//! Basic stateful firewall with priority-ordered match/action rules.
//!
//! # Features
//!
//! - **Match criteria**: src/dst IP (CIDR), src/dst port ranges, protocol, conntrack state
//! - **Actions**: ACCEPT, DROP, REJECT (with ICMP error)
//! - **Priority ordering**: Higher priority rules evaluated first (tie-break by rule ID)
//! - **Conntrack integration**: Stateful filtering based on connection tracking decisions
//! - **Logging**: Per-rule optional logging for debugging and audit
//!
//! # Default Policy
//!
//! The default rule set implements a stateful firewall:
//! 1. DROP packets with Invalid conntrack state (priority 1000)
//! 2. ACCEPT packets with Established/Related state (priority 900)
//! 3. ACCEPT all other traffic (priority -1, can be overridden)
//!
//! # Security Design
//!
//! - Rules are evaluated in priority order (descending), first match wins
//! - Rule table replacement is atomic via RwLock
//! - No dynamic rule addition - table must be replaced atomically
//!
//! # References
//! - Linux netfilter/iptables conceptual model
//! - RFC 5765: Security threats and solutions for connections states

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use spin::{Once, RwLock};

use crate::conntrack::CtDecision;
use crate::ipv4::{Ipv4Addr, Ipv4Proto};

// ============================================================================
// Firewall Statistics
// ============================================================================

/// Global firewall statistics.
pub struct FirewallStats {
    /// Packets accepted by firewall rules
    pub packets_accepted: AtomicU64,
    /// Packets dropped by firewall rules
    pub packets_dropped: AtomicU64,
    /// Packets rejected (with ICMP response) by firewall rules
    pub packets_rejected: AtomicU64,
    /// Rule evaluations performed
    pub rule_evaluations: AtomicU64,
    /// Default policy hits (no rule matched)
    pub default_hits: AtomicU64,
}

impl FirewallStats {
    pub const fn new() -> Self {
        Self {
            packets_accepted: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_rejected: AtomicU64::new(0),
            rule_evaluations: AtomicU64::new(0),
            default_hits: AtomicU64::new(0),
        }
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> FirewallStatsSnapshot {
        FirewallStatsSnapshot {
            packets_accepted: self.packets_accepted.load(AtomicOrdering::Relaxed),
            packets_dropped: self.packets_dropped.load(AtomicOrdering::Relaxed),
            packets_rejected: self.packets_rejected.load(AtomicOrdering::Relaxed),
            rule_evaluations: self.rule_evaluations.load(AtomicOrdering::Relaxed),
            default_hits: self.default_hits.load(AtomicOrdering::Relaxed),
        }
    }
}

/// Snapshot of firewall statistics.
#[derive(Debug, Clone, Copy)]
pub struct FirewallStatsSnapshot {
    pub packets_accepted: u64,
    pub packets_dropped: u64,
    pub packets_rejected: u64,
    pub rule_evaluations: u64,
    pub default_hits: u64,
}

// ============================================================================
// Action Types
// ============================================================================

/// Action taken when a firewall rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// Allow the packet to proceed
    Accept,
    /// Silently discard the packet
    Drop,
    /// Discard the packet and send an ICMP error response
    Reject {
        /// ICMP destination unreachable code to send
        icmp_code: u8,
    },
}

impl Default for FirewallAction {
    fn default() -> Self {
        Self::Accept
    }
}

// ============================================================================
// Match Criteria Types
// ============================================================================

/// Inclusive port range matcher.
///
/// Matches ports in the range [start, end] inclusive.
#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Create a new port range.
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Create a range matching a single port.
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Create a range matching all ports.
    pub const fn any() -> Self {
        Self {
            start: 0,
            end: 65535,
        }
    }

    /// Check if a port falls within this range.
    #[inline]
    pub fn matches(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl From<u16> for PortRange {
    fn from(port: u16) -> Self {
        Self::single(port)
    }
}

/// CIDR-style IPv4 address matcher.
///
/// Matches addresses that share the same prefix bits.
#[derive(Debug, Clone, Copy)]
pub struct IpCidrMatch {
    /// Network address
    pub addr: Ipv4Addr,
    /// Prefix length (0-32)
    pub prefix_len: u8,
}

impl IpCidrMatch {
    /// Create a new CIDR matcher.
    pub const fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }

    /// Create a matcher for a single host (/32).
    pub const fn host(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            prefix_len: 32,
        }
    }

    /// Create a matcher that matches any address (/0).
    pub const fn any() -> Self {
        Self {
            addr: Ipv4Addr([0, 0, 0, 0]),
            prefix_len: 0,
        }
    }

    /// Check if an IP address matches this CIDR.
    #[inline]
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        let prefix = self.prefix_len.min(32);
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - prefix);
        (ipv4_to_u32(self.addr) & mask) == (ipv4_to_u32(ip) & mask)
    }
}

/// Bitmask for conntrack state matching.
///
/// Multiple states can be combined to match any of them.
#[derive(Debug, Clone, Copy)]
pub struct CtStateMask(u8);

impl CtStateMask {
    /// Match any connection state
    pub const ANY: Self = Self(0x0f);
    /// Match only NEW connections
    pub const NEW: Self = Self(0x01);
    /// Match only ESTABLISHED connections
    pub const ESTABLISHED: Self = Self(0x02);
    /// Match only RELATED connections
    pub const RELATED: Self = Self(0x04);
    /// Match only INVALID packets
    pub const INVALID: Self = Self(0x08);

    /// Create a state mask from a slice of states.
    pub fn from_states(states: &[CtDecision]) -> Self {
        let mut bits = 0u8;
        for state in states {
            bits |= Self::bit_for_state(*state);
        }
        Self(bits)
    }

    /// Combine two state masks (OR operation).
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    fn bit_for_state(state: CtDecision) -> u8 {
        match state {
            CtDecision::New => Self::NEW.0,
            CtDecision::Established => Self::ESTABLISHED.0,
            CtDecision::Related => Self::RELATED.0,
            CtDecision::Invalid => Self::INVALID.0,
        }
    }

    /// Check if a conntrack decision matches this mask.
    #[inline]
    pub fn matches(self, state: Option<CtDecision>) -> bool {
        match state {
            Some(s) => self.0 & Self::bit_for_state(s) != 0,
            // If no conntrack state, only match if mask is ANY
            None => self.0 == Self::ANY.0,
        }
    }
}

// ============================================================================
// Firewall Rule
// ============================================================================

/// A firewall rule with match criteria and action.
///
/// Rules are evaluated in priority order (descending). The first matching
/// rule determines the packet's fate. If no rule matches, the default
/// action is applied.
#[derive(Debug, Clone)]
pub struct FirewallRule {
    /// Unique rule identifier for logging
    pub id: u32,
    /// Rule priority (higher = evaluated first)
    pub priority: i32,
    /// Source IP CIDR (None = any)
    pub src_ip: Option<IpCidrMatch>,
    /// Destination IP CIDR (None = any)
    pub dst_ip: Option<IpCidrMatch>,
    /// Source port range (None = any, only for TCP/UDP)
    pub src_port: Option<PortRange>,
    /// Destination port range (None = any, only for TCP/UDP)
    pub dst_port: Option<PortRange>,
    /// IP protocol (None = any)
    pub proto: Option<Ipv4Proto>,
    /// Conntrack state mask
    pub ct_state: CtStateMask,
    /// Action to take on match
    pub action: FirewallAction,
    /// Whether to log when this rule matches
    pub log: bool,
}

impl FirewallRule {
    /// Create a builder for constructing rules.
    pub fn builder(id: u32) -> FirewallRuleBuilder {
        FirewallRuleBuilder::new(id)
    }

    /// Check if this rule matches a packet.
    #[inline]
    fn matches(&self, packet: &FirewallPacket) -> bool {
        match_field_ip(self.src_ip, packet.src_ip)
            && match_field_ip(self.dst_ip, packet.dst_ip)
            && match_field_port(self.src_port, packet.src_port)
            && match_field_port(self.dst_port, packet.dst_port)
            && match_field_proto(self.proto, packet.proto)
            && self.ct_state.matches(packet.ct_state)
    }
}

/// Builder for constructing firewall rules.
pub struct FirewallRuleBuilder {
    rule: FirewallRule,
}

impl FirewallRuleBuilder {
    pub fn new(id: u32) -> Self {
        Self {
            rule: FirewallRule {
                id,
                priority: 0,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                proto: None,
                ct_state: CtStateMask::ANY,
                action: FirewallAction::Accept,
                log: false,
            },
        }
    }

    pub fn priority(mut self, priority: i32) -> Self {
        self.rule.priority = priority;
        self
    }

    pub fn src_ip(mut self, cidr: IpCidrMatch) -> Self {
        self.rule.src_ip = Some(cidr);
        self
    }

    pub fn dst_ip(mut self, cidr: IpCidrMatch) -> Self {
        self.rule.dst_ip = Some(cidr);
        self
    }

    pub fn src_port(mut self, range: PortRange) -> Self {
        self.rule.src_port = Some(range);
        self
    }

    pub fn dst_port(mut self, range: PortRange) -> Self {
        self.rule.dst_port = Some(range);
        self
    }

    pub fn proto(mut self, proto: Ipv4Proto) -> Self {
        self.rule.proto = Some(proto);
        self
    }

    pub fn ct_state(mut self, mask: CtStateMask) -> Self {
        self.rule.ct_state = mask;
        self
    }

    pub fn action(mut self, action: FirewallAction) -> Self {
        self.rule.action = action;
        self
    }

    pub fn log(mut self, log: bool) -> Self {
        self.rule.log = log;
        self
    }

    pub fn build(self) -> FirewallRule {
        self.rule
    }
}

// ============================================================================
// Packet Metadata
// ============================================================================

/// Packet metadata presented to the firewall for evaluation.
#[derive(Debug, Clone, Copy)]
pub struct FirewallPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub proto: Ipv4Proto,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ct_state: Option<CtDecision>,
}

// ============================================================================
// Firewall Verdict
// ============================================================================

/// Result of firewall rule evaluation.
#[derive(Debug, Clone, Copy)]
pub struct FirewallVerdict {
    /// Action to take
    pub action: FirewallAction,
    /// ID of the matching rule (None if default policy)
    pub rule_id: Option<u32>,
    /// Whether to log this verdict
    pub log: bool,
}

// ============================================================================
// Firewall Table
// ============================================================================

/// The firewall rule table.
///
/// Thread-safe container for firewall rules with atomic replacement support.
pub struct FirewallTable {
    rules: RwLock<Vec<FirewallRule>>,
    default_action: FirewallAction,
    stats: FirewallStats,
}

impl FirewallTable {
    /// Create a new firewall table with default action and initial rules.
    pub fn new_with_rules(default_action: FirewallAction, mut rules: Vec<FirewallRule>) -> Self {
        Self::sort_rules(&mut rules);
        Self {
            rules: RwLock::new(rules),
            default_action,
            stats: FirewallStats::new(),
        }
    }

    /// Atomically replace all rules.
    pub fn replace_rules(&self, mut rules: Vec<FirewallRule>) {
        Self::sort_rules(&mut rules);
        let mut guard = self.rules.write();
        *guard = rules;
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// Get firewall statistics.
    pub fn stats(&self) -> FirewallStatsSnapshot {
        self.stats.snapshot()
    }

    /// Evaluate a packet against the rule table.
    pub fn evaluate(&self, packet: &FirewallPacket) -> FirewallVerdict {
        let rules = self.rules.read();
        // R64-6 FIX: Batch rule evaluation counter to reduce atomic operations
        // Instead of one atomic per rule, we count locally and do one atomic per packet
        let mut evals: u64 = 0;

        for rule in rules.iter() {
            evals += 1;
            if rule.matches(packet) {
                // Update stats atomically (once per packet)
                self.stats
                    .rule_evaluations
                    .fetch_add(evals, AtomicOrdering::Relaxed);
                match rule.action {
                    FirewallAction::Accept => {
                        self.stats
                            .packets_accepted
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    FirewallAction::Drop => {
                        self.stats
                            .packets_dropped
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    FirewallAction::Reject { .. } => {
                        self.stats
                            .packets_rejected
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }

                return FirewallVerdict {
                    action: rule.action,
                    rule_id: Some(rule.id),
                    log: rule.log,
                };
            }
        }

        // No rule matched, use default action
        // R64-6 FIX: Update rule evaluations count for default path
        self.stats
            .rule_evaluations
            .fetch_add(evals, AtomicOrdering::Relaxed);
        self.stats
            .default_hits
            .fetch_add(1, AtomicOrdering::Relaxed);
        match self.default_action {
            FirewallAction::Accept => {
                self.stats
                    .packets_accepted
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            FirewallAction::Drop => {
                self.stats
                    .packets_dropped
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            FirewallAction::Reject { .. } => {
                self.stats
                    .packets_rejected
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        FirewallVerdict {
            action: self.default_action,
            rule_id: None,
            log: false,
        }
    }

    /// Sort rules by priority (descending), then by ID (ascending).
    fn sort_rules(rules: &mut Vec<FirewallRule>) {
        rules.sort_by(|a, b| match b.priority.cmp(&a.priority) {
            Ordering::Equal => a.id.cmp(&b.id),
            other => other,
        });
    }
}

// ============================================================================
// Match Helper Functions
// ============================================================================

#[inline]
fn match_field_ip(rule: Option<IpCidrMatch>, value: Ipv4Addr) -> bool {
    match rule {
        Some(cidr) => cidr.matches(value),
        None => true,
    }
}

#[inline]
fn match_field_port(rule: Option<PortRange>, value: Option<u16>) -> bool {
    match (rule, value) {
        (Some(range), Some(port)) => range.matches(port),
        (Some(_), None) => false, // Rule requires port but packet has none
        (None, _) => true,        // No port requirement
    }
}

#[inline]
fn match_field_proto(rule: Option<Ipv4Proto>, value: Ipv4Proto) -> bool {
    match rule {
        Some(p) => p == value,
        None => true,
    }
}

#[inline]
fn ipv4_to_u32(addr: Ipv4Addr) -> u32 {
    u32::from_be_bytes(addr.0)
}

// ============================================================================
// Default Rules
// ============================================================================

/// Create the default stateful firewall rule set.
///
/// # R94-12 FIX: Default Deny Policy
///
/// The firewall now uses a "default deny" (DROP) policy. Only traffic matching
/// explicit ACCEPT rules will be permitted. This is the security-first approach:
/// - INVALID packets are dropped (conntrack detected invalid state)
/// - ESTABLISHED/RELATED packets are accepted (replies to existing connections)
/// - All other traffic is dropped by default
///
/// To permit new inbound/outbound connections, explicit rules must be added.
fn default_rules() -> Vec<FirewallRule> {
    vec![
        // Rule 1: Drop INVALID packets (high priority)
        FirewallRule::builder(1)
            .priority(1000)
            .ct_state(CtStateMask::INVALID)
            .action(FirewallAction::Drop)
            .log(true)
            .build(),
        // Rule 2: Accept ESTABLISHED and RELATED packets
        FirewallRule::builder(2)
            .priority(900)
            .ct_state(CtStateMask::ESTABLISHED.or(CtStateMask::RELATED))
            .action(FirewallAction::Accept)
            .log(false)
            .build(),
        // R94-12 FIX: Removed catch-all Accept rule.
        // New connections require explicit ACCEPT rules.
        // Default policy (DROP) applies to unmatched traffic.
    ]
}

// ============================================================================
// Global Instance
// ============================================================================

static FIREWALL_TABLE: Once<FirewallTable> = Once::new();

/// Get the global firewall table.
///
/// # R94-12 FIX: Default Deny Policy
///
/// Uses `FirewallAction::Drop` as the default policy. All traffic not matching
/// an explicit ACCEPT rule will be dropped. This is fail-closed security design.
pub fn firewall_table() -> &'static FirewallTable {
    FIREWALL_TABLE
        .call_once(|| FirewallTable::new_with_rules(FirewallAction::Drop, default_rules()))
}

// ============================================================================
// Logging
// ============================================================================

/// Simple log rate limiter for firewall (100 logs/sec burst).
///
/// R64-4 FIX: Rate limit firewall logs to prevent console flooding
/// from invalid traffic or DoS attempts.
///
/// R65-1 FIX: Use CAS loop for atomic token decrement to prevent race condition
/// where multiple threads can simultaneously pass the `current > 0` check and
/// underflow the counter to u64::MAX, effectively disabling rate limiting.
static FW_LOG_TOKENS: AtomicU64 = AtomicU64::new(100);
static FW_LOG_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if we can log (simple token bucket, 100/sec).
///
/// R65-1 FIX: Uses atomic compare-and-swap to safely decrement tokens.
/// This prevents race conditions where multiple threads could consume
/// the "last" token simultaneously, causing counter underflow.
fn can_log(now_ms: u64) -> bool {
    const LOG_RATE_LIMIT: u64 = 100;
    const LOG_RATE_WINDOW_MS: u64 = 1000;

    let window_start = FW_LOG_WINDOW_START.load(AtomicOrdering::Relaxed);
    if now_ms.saturating_sub(window_start) >= LOG_RATE_WINDOW_MS {
        FW_LOG_WINDOW_START.store(now_ms, AtomicOrdering::Relaxed);
        FW_LOG_TOKENS.store(LOG_RATE_LIMIT, AtomicOrdering::Relaxed);
    }

    // R65-1 FIX: Use fetch_update with CAS loop to atomically check and decrement.
    // This ensures only one thread can consume each token, preventing underflow.
    // If current is 0, the closure returns None and fetch_update returns Err,
    // indicating no token was available.
    FW_LOG_TOKENS
        .fetch_update(
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
            |current| {
                if current > 0 {
                    Some(current - 1)
                } else {
                    None
                }
            },
        )
        .is_ok()
}

/// Log a firewall match (only if verdict.log is true and not rate limited).
///
/// # Arguments
/// * `verdict` - Firewall verdict containing log flag
/// * `packet` - Packet metadata
/// * `now_ms` - Current timestamp for rate limiting
pub fn log_match(verdict: &FirewallVerdict, packet: &FirewallPacket, now_ms: u64) {
    if !verdict.log {
        return;
    }

    // R64-4 FIX: Rate limit firewall logs
    if !can_log(now_ms) {
        return;
    }

    kprintln!(
        "[fw] rule={:?} action={:?} proto={:?} {:?}:{:?} -> {:?}:{:?} ct_state={:?}",
        verdict.rule_id,
        verdict.action,
        packet.proto,
        packet.src_ip,
        packet.src_port,
        packet.dst_ip,
        packet.dst_port,
        packet.ct_state
    );
}

// ============================================================================
// Tests (compile-time only)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_match() {
        let cidr = IpCidrMatch::new(Ipv4Addr([192, 168, 1, 0]), 24);
        assert!(cidr.matches(Ipv4Addr([192, 168, 1, 1])));
        assert!(cidr.matches(Ipv4Addr([192, 168, 1, 255])));
        assert!(!cidr.matches(Ipv4Addr([192, 168, 2, 1])));
    }

    #[test]
    fn test_port_range() {
        let range = PortRange::new(80, 443);
        assert!(range.matches(80));
        assert!(range.matches(443));
        assert!(range.matches(200));
        assert!(!range.matches(79));
        assert!(!range.matches(444));
    }

    #[test]
    fn test_ct_state_mask() {
        let mask = CtStateMask::ESTABLISHED.or(CtStateMask::RELATED);
        assert!(mask.matches(Some(CtDecision::Established)));
        assert!(mask.matches(Some(CtDecision::Related)));
        assert!(!mask.matches(Some(CtDecision::New)));
        assert!(!mask.matches(Some(CtDecision::Invalid)));
    }
}
