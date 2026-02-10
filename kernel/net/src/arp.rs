//! ARP (Address Resolution Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 826 compliant ARP implementation with security-first design.
//!
//! # Packet Format (RFC 826)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Hardware Type         |         Protocol Type         |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |  HLen |  PLen |            Operation (1=Req, 2=Reply)         |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Sender Hardware Address (6 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Sender Protocol Address (4 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Target Hardware Address (6 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Target Protocol Address (4 bytes)          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - Rate limiting for both RX processing and TX replies (anti-flooding)
//! - Cache conflict detection (anti-poisoning)
//! - Static entry protection (never overwritten by dynamic)
//! - Source validation (reject broadcast/multicast/zero MACs)
//! - Reflection attack prevention
//! - Bounded cache with LRU eviction
//!
//! # References
//!
//! - RFC 826: Ethernet Address Resolution Protocol
//! - RFC 5227: IPv4 Address Conflict Detection

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ethernet::{build_ethernet_frame, EthAddr, ETHERTYPE_ARP};
use crate::icmp::TokenBucket;
use crate::ipv4::Ipv4Addr;

// ============================================================================
// ARP Constants (RFC 826)
// ============================================================================

/// Hardware type: Ethernet
pub const HTYPE_ETHERNET: u16 = 1;

/// Protocol type: IPv4
pub const PTYPE_IPV4: u16 = 0x0800;

/// Hardware address length: Ethernet MAC (6 bytes)
pub const HLEN_ETHERNET: u8 = 6;

/// Protocol address length: IPv4 (4 bytes)
pub const PLEN_IPV4: u8 = 4;

/// ARP operation: Request
pub const OPCODE_REQUEST: u16 = 1;

/// ARP operation: Reply
pub const OPCODE_REPLY: u16 = 2;

/// ARP packet size for Ethernet/IPv4
pub const ARP_PACKET_LEN: usize = 28;

/// Default ARP cache TTL (5 minutes)
pub const DEFAULT_CACHE_TTL_MS: u64 = 5 * 60 * 1000;

/// Default maximum ARP cache entries
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 256;

/// Default ARP RX rate limit (packets per second)
pub const DEFAULT_RX_RATE_PPS: u64 = 50;

/// Default ARP RX burst capacity
pub const DEFAULT_RX_BURST: u64 = 100;

/// Default ARP TX rate limit (packets per second)
pub const DEFAULT_TX_RATE_PPS: u64 = 20;

/// Default ARP TX burst capacity
pub const DEFAULT_TX_BURST: u64 = 40;

// ============================================================================
// ARP Operation Code
// ============================================================================

/// ARP operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    /// ARP Request (who-has)
    Request,
    /// ARP Reply (is-at)
    Reply,
}

impl ArpOp {
    /// Convert from raw opcode
    pub fn from_raw(op: u16) -> Option<Self> {
        match op {
            OPCODE_REQUEST => Some(ArpOp::Request),
            OPCODE_REPLY => Some(ArpOp::Reply),
            _ => None,
        }
    }

    /// Convert to raw opcode
    pub fn to_raw(self) -> u16 {
        match self {
            ArpOp::Request => OPCODE_REQUEST,
            ArpOp::Reply => OPCODE_REPLY,
        }
    }
}

// ============================================================================
// ARP Packet
// ============================================================================

/// Parsed ARP packet for Ethernet/IPv4
#[derive(Debug, Clone, Copy)]
pub struct ArpPacket {
    /// Sender hardware (MAC) address
    pub sender_hw: EthAddr,
    /// Sender protocol (IP) address
    pub sender_ip: Ipv4Addr,
    /// Target hardware (MAC) address
    pub target_hw: EthAddr,
    /// Target protocol (IP) address
    pub target_ip: Ipv4Addr,
    /// ARP operation
    pub op: ArpOp,
}

// ============================================================================
// ARP Errors
// ============================================================================

/// Errors that can occur during ARP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpError {
    /// Packet is too short
    Truncated,
    /// Invalid hardware type (not Ethernet)
    InvalidHardwareType,
    /// Invalid protocol type (not IPv4)
    InvalidProtocolType,
    /// Invalid address lengths
    InvalidAddressLength,
    /// Invalid operation code
    InvalidOpcode,
    /// Invalid sender address (broadcast/multicast/zero MAC)
    InvalidSender,
    /// Rate limited (flood protection)
    RateLimited,
    /// Conflicting cache entry (anti-spoofing)
    CacheConflict,
}

// ============================================================================
// ARP Cache Entry
// ============================================================================

/// Type of ARP cache entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryKind {
    /// Statically configured (never expires, never overwritten)
    Static,
    /// Dynamically learned from network
    Dynamic,
}

/// An entry in the ARP cache
#[derive(Debug, Clone, Copy)]
pub struct ArpEntry {
    /// IP address
    pub ip: Ipv4Addr,
    /// MAC address
    pub mac: EthAddr,
    /// Entry type
    pub kind: ArpEntryKind,
    /// Last update timestamp (milliseconds)
    pub updated_at: u64,
}

// ============================================================================
// ARP Cache
// ============================================================================

/// ARP cache with anti-spoofing protection
///
/// # Security Features
///
/// - Bounded size with LRU eviction
/// - TTL-based expiration for dynamic entries
/// - Conflict detection (rejects updates that change existing MAC)
/// - Static entry protection (never overwritten)
pub struct ArpCache {
    /// Cache entries (LRU order: oldest first)
    entries: VecDeque<ArpEntry>,
    /// TTL for dynamic entries in milliseconds
    ttl_ms: u64,
    /// Maximum number of entries
    max_entries: usize,
    /// R102-12 FIX: Per-interface RX rate limiter.
    /// Prevents a single malicious host on one interface from exhausting the
    /// global token bucket and starving ARP processing on all other interfaces.
    pub rx_rate_limiter: TokenBucket,
    /// R102-12 FIX: Per-interface TX rate limiter.
    pub tx_rate_limiter: TokenBucket,
}

impl ArpCache {
    /// Create a new ARP cache with specified TTL and capacity.
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        ArpCache {
            entries: VecDeque::with_capacity(max_entries.min(64)),
            ttl_ms,
            max_entries,
            // R102-12 FIX: Per-interface rate limiters with same defaults as global.
            rx_rate_limiter: TokenBucket::new(DEFAULT_RX_RATE_PPS, DEFAULT_RX_BURST),
            tx_rate_limiter: TokenBucket::new(DEFAULT_TX_RATE_PPS, DEFAULT_TX_BURST),
        }
    }

    /// Create a cache with default settings (5 min TTL, 256 entries).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CACHE_TTL_MS, DEFAULT_CACHE_MAX_ENTRIES)
    }

    /// Look up a MAC address for the given IP.
    ///
    /// Returns `None` if not found or expired.
    pub fn lookup(&self, ip: Ipv4Addr, now_ms: u64) -> Option<EthAddr> {
        self.entries
            .iter()
            .find(|e| e.ip == ip && !self.is_expired(e, now_ms))
            .map(|e| e.mac)
    }

    /// Insert or update an entry in the cache.
    ///
    /// # Security: Anti-Spoofing
    ///
    /// - Never overwrites static entries
    /// - Rejects dynamic updates that change an existing MAC (conflict)
    /// - Purges expired entries before checking conflicts (R45 FIX)
    /// - This prevents ARP cache poisoning attacks
    ///
    /// # Returns
    ///
    /// `Ok(())` if inserted/updated, `Err(ArpError::CacheConflict)` if rejected.
    pub fn insert(
        &mut self,
        ip: Ipv4Addr,
        mac: EthAddr,
        kind: ArpEntryKind,
        now_ms: u64,
    ) -> Result<(), ArpError> {
        // R45 FIX: Purge expired entries first so they cannot block fresh mappings
        self.purge_expired(now_ms);

        // Check for existing entry
        if let Some(pos) = self.entries.iter().position(|e| e.ip == ip) {
            let existing = &self.entries[pos];

            // Never overwrite static entries
            if existing.kind == ArpEntryKind::Static {
                if kind == ArpEntryKind::Static && existing.mac == mac {
                    // Same static entry, just update timestamp
                    let entry = &mut self.entries[pos];
                    entry.updated_at = now_ms;
                    return Ok(());
                }
                return Err(ArpError::CacheConflict);
            }

            // For dynamic entries, reject if MAC changes (anti-poisoning)
            // Only allow refresh with same MAC
            if existing.mac != mac {
                return Err(ArpError::CacheConflict);
            }

            // Remove and re-add at end (update LRU position)
            self.entries.remove(pos);
        }

        // R62-5 FIX: Evict oldest *dynamic* entry if at capacity; never evict static.
        // Static entries represent trusted bindings (e.g., gateway) and must be protected
        // from cache-filling attacks that could enable ARP poisoning.
        if self.entries.len() >= self.max_entries {
            // Find first dynamic entry to evict (oldest dynamic)
            if let Some(pos) = self
                .entries
                .iter()
                .position(|e| e.kind == ArpEntryKind::Dynamic)
            {
                self.entries.remove(pos);
            } else {
                // Cache is full of static entries; refuse new insertion
                // This prevents attackers from forcing eviction of static entries
                return Err(ArpError::CacheConflict);
            }
        }

        // Add new entry at end (most recently used)
        self.entries.push_back(ArpEntry {
            ip,
            mac,
            kind,
            updated_at: now_ms,
        });

        Ok(())
    }

    /// Add a static entry that never expires and cannot be overwritten.
    pub fn add_static(&mut self, ip: Ipv4Addr, mac: EthAddr, now_ms: u64) -> Result<(), ArpError> {
        self.insert(ip, mac, ArpEntryKind::Static, now_ms)
    }

    /// Remove expired dynamic entries.
    pub fn purge_expired(&mut self, now_ms: u64) {
        let ttl_ms = self.ttl_ms;
        self.entries.retain(|e| {
            // Static entries never expire
            if e.kind == ArpEntryKind::Static {
                return true;
            }
            // Dynamic entries expire after ttl_ms
            now_ms.saturating_sub(e.updated_at) <= ttl_ms
        });
    }

    /// Check if an entry is expired.
    fn is_expired(&self, entry: &ArpEntry, now_ms: u64) -> bool {
        // Static entries never expire
        if entry.kind == ArpEntryKind::Static {
            return false;
        }
        now_ms.saturating_sub(entry.updated_at) > self.ttl_ms
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all dynamic entries.
    pub fn clear_dynamic(&mut self) {
        self.entries.retain(|e| e.kind == ArpEntryKind::Static);
    }

    /// R101-11 FIX: Check if a static entry exists for the given IP.
    ///
    /// Used by gratuitous ARP processing to protect static entries (e.g., gateway)
    /// from being updated via gratuitous ARP packets, even with matching MACs.
    pub fn has_static_entry(&self, ip: Ipv4Addr) -> bool {
        self.entries
            .iter()
            .any(|e| e.ip == ip && e.kind == ArpEntryKind::Static)
    }
}

// ============================================================================
// ARP Statistics
// ============================================================================

/// ARP protocol statistics
#[derive(Debug, Default)]
pub struct ArpStats {
    /// ARP packets received
    pub rx_packets: AtomicU64,
    /// ARP requests received
    pub rx_requests: AtomicU64,
    /// ARP replies received
    pub rx_replies: AtomicU64,
    /// ARP replies sent
    pub tx_replies: AtomicU64,
    /// Packets dropped due to parse errors
    pub rx_errors: AtomicU64,
    /// Packets dropped due to rate limiting
    pub rx_rate_limited: AtomicU64,
    /// Packets dropped due to cache conflicts
    pub cache_conflicts: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
}

impl ArpStats {
    pub const fn new() -> Self {
        ArpStats {
            rx_packets: AtomicU64::new(0),
            rx_requests: AtomicU64::new(0),
            rx_replies: AtomicU64::new(0),
            tx_replies: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            rx_rate_limited: AtomicU64::new(0),
            cache_conflicts: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_requests(&self) {
        self.rx_requests.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_replies(&self) {
        self.rx_replies.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_tx_replies(&self) {
        self.tx_replies.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_rate_limited(&self) {
        self.rx_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_conflicts(&self) {
        self.cache_conflicts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// ARP Parsing
// ============================================================================

/// Parse an ARP packet from raw bytes.
///
/// # Security
///
/// - Validates hardware type (Ethernet), protocol type (IPv4)
/// - Validates address lengths
/// - Validates operation code
/// - Rejects packets with broadcast/multicast/zero sender MAC
///
/// # Arguments
///
/// * `buf` - Raw ARP packet bytes (Ethernet payload)
///
/// # Returns
///
/// Parsed `ArpPacket` or error describing the validation failure.
pub fn parse_arp(buf: &[u8]) -> Result<ArpPacket, ArpError> {
    // Minimum length check
    if buf.len() < ARP_PACKET_LEN {
        return Err(ArpError::Truncated);
    }

    // Parse and validate fixed fields
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    if htype != HTYPE_ETHERNET {
        return Err(ArpError::InvalidHardwareType);
    }

    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    if ptype != PTYPE_IPV4 {
        return Err(ArpError::InvalidProtocolType);
    }

    let hlen = buf[4];
    let plen = buf[5];
    if hlen != HLEN_ETHERNET || plen != PLEN_IPV4 {
        return Err(ArpError::InvalidAddressLength);
    }

    let opcode = u16::from_be_bytes([buf[6], buf[7]]);
    let op = ArpOp::from_raw(opcode).ok_or(ArpError::InvalidOpcode)?;

    // Parse addresses
    let mut sender_hw_bytes = [0u8; 6];
    sender_hw_bytes.copy_from_slice(&buf[8..14]);
    let sender_hw = EthAddr(sender_hw_bytes);

    let sender_ip = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);

    let mut target_hw_bytes = [0u8; 6];
    target_hw_bytes.copy_from_slice(&buf[18..24]);
    let target_hw = EthAddr(target_hw_bytes);

    let target_ip = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);

    // Security: Validate sender address
    // Reject broadcast/multicast source MACs (potential spoofing)
    if sender_hw.is_broadcast() || sender_hw.is_multicast() {
        return Err(ArpError::InvalidSender);
    }

    // Reject zero MAC (invalid sender)
    if sender_hw == EthAddr::ZERO {
        return Err(ArpError::InvalidSender);
    }

    // Reject zero sender IP (unless it's ARP probe, but we don't support that yet)
    if sender_ip.is_unspecified() {
        return Err(ArpError::InvalidSender);
    }

    Ok(ArpPacket {
        sender_hw,
        sender_ip,
        target_hw,
        target_ip,
        op,
    })
}

// ============================================================================
// ARP Serialization
// ============================================================================

/// Serialize an ARP packet to bytes.
///
/// # Arguments
///
/// * `pkt` - ARP packet to serialize
///
/// # Returns
///
/// 28-byte ARP packet suitable for Ethernet payload.
pub fn serialize_arp(pkt: &ArpPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ARP_PACKET_LEN);

    // Hardware type (Ethernet)
    buf.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    // Protocol type (IPv4)
    buf.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    // Hardware address length
    buf.push(HLEN_ETHERNET);
    // Protocol address length
    buf.push(PLEN_IPV4);
    // Operation
    buf.extend_from_slice(&pkt.op.to_raw().to_be_bytes());
    // Sender hardware address
    buf.extend_from_slice(&pkt.sender_hw.0);
    // Sender protocol address
    buf.extend_from_slice(&pkt.sender_ip.octets());
    // Target hardware address
    buf.extend_from_slice(&pkt.target_hw.0);
    // Target protocol address
    buf.extend_from_slice(&pkt.target_ip.octets());

    buf
}

/// Build an ARP reply packet.
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `target_mac` - Target MAC address (original sender)
/// * `target_ip` - Target IP address (original sender)
///
/// # Returns
///
/// Complete Ethernet frame containing ARP reply.
pub fn build_arp_reply(
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    target_mac: EthAddr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: target_mac,
        target_ip: target_ip,
        op: ArpOp::Reply,
    };

    let arp_payload = serialize_arp(&arp_pkt);
    build_ethernet_frame(target_mac, our_mac, ETHERTYPE_ARP, &arp_payload)
}

/// Build an ARP request packet.
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `target_ip` - IP address we're looking for
///
/// # Returns
///
/// Complete Ethernet frame containing ARP request (broadcast).
pub fn build_arp_request(our_mac: EthAddr, our_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: EthAddr::ZERO, // Unknown, set to zero for request
        target_ip: target_ip,
        op: ArpOp::Request,
    };

    let arp_payload = serialize_arp(&arp_pkt);
    // Broadcast the request
    build_ethernet_frame(EthAddr::BROADCAST, our_mac, ETHERTYPE_ARP, &arp_payload)
}

/// Build a gratuitous ARP packet (announce our presence).
///
/// Gratuitous ARP has sender IP == target IP, used for:
/// - Announcing presence on network
/// - Updating stale ARP caches
/// - Detecting IP conflicts
///
/// # Arguments
///
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
///
/// # Returns
///
/// Complete Ethernet frame containing gratuitous ARP (broadcast).
pub fn build_gratuitous_arp(our_mac: EthAddr, our_ip: Ipv4Addr) -> Vec<u8> {
    let arp_pkt = ArpPacket {
        sender_hw: our_mac,
        sender_ip: our_ip,
        target_hw: EthAddr::ZERO,
        target_ip: our_ip, // Same as sender IP for gratuitous ARP
        op: ArpOp::Request,
    };

    let arp_payload = serialize_arp(&arp_pkt);
    build_ethernet_frame(EthAddr::BROADCAST, our_mac, ETHERTYPE_ARP, &arp_payload)
}

// ============================================================================
// ARP Rate Limiter
// ============================================================================

/// Global ARP rate limiter for RX processing.
pub static ARP_RX_RATE_LIMITER: TokenBucket =
    TokenBucket::new(DEFAULT_RX_RATE_PPS, DEFAULT_RX_BURST);

/// Global ARP rate limiter for TX replies.
pub static ARP_TX_RATE_LIMITER: TokenBucket =
    TokenBucket::new(DEFAULT_TX_RATE_PPS, DEFAULT_TX_BURST);

// ============================================================================
// ARP Processing Result
// ============================================================================

/// Result of processing an ARP packet
#[derive(Debug)]
pub enum ArpResult {
    /// ARP was handled, no response needed
    Handled,
    /// ARP requires a reply to be sent
    Reply(Vec<u8>),
    /// ARP was dropped with reason
    Dropped(ArpError),
}

// ============================================================================
// ARP Packet Handler
// ============================================================================

/// Process an incoming ARP packet.
///
/// This function handles:
/// 1. Rate limiting (flood protection)
/// 2. Packet parsing and validation
/// 3. Cache update (with anti-spoofing)
/// 4. ARP reply generation for requests targeting our IP
///
/// # Security
///
/// - Rate limits both RX processing and TX replies
/// - Validates sender addresses (rejects broadcast/multicast/zero)
/// - Detects cache conflicts (anti-poisoning)
/// - Prevents reflection attacks (won't reply to conflicting sender)
///
/// # Arguments
///
/// * `payload` - ARP packet bytes (Ethernet payload)
/// * `our_mac` - Our MAC address
/// * `our_ip` - Our IP address
/// * `cache` - ARP cache for address resolution
/// * `stats` - Statistics counters
/// * `now_ms` - Current time in milliseconds
///
/// # Returns
///
/// `ArpResult` indicating what action to take.
pub fn process_arp(
    payload: &[u8],
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    cache: &mut ArpCache,
    stats: &ArpStats,
    now_ms: u64,
) -> ArpResult {
    stats.inc_rx_packets();

    // R102-12 FIX: Check per-interface rate limiter first, then global as backstop.
    // This prevents a single malicious host on one interface from starving all others.
    if !cache.rx_rate_limiter.allow(now_ms) || !ARP_RX_RATE_LIMITER.allow(now_ms) {
        stats.inc_rx_rate_limited();
        return ArpResult::Dropped(ArpError::RateLimited);
    }

    // Parse ARP packet
    let pkt = match parse_arp(payload) {
        Ok(p) => p,
        Err(e) => {
            stats.inc_rx_errors();
            return ArpResult::Dropped(e);
        }
    };

    // Track request/reply stats
    match pkt.op {
        ArpOp::Request => stats.inc_rx_requests(),
        ArpOp::Reply => stats.inc_rx_replies(),
    }

    // R45 FIX: Determine if packet involves us or is gratuitous
    let is_gratuitous = pkt.sender_ip == pkt.target_ip;
    let for_us = pkt.target_ip == our_ip;

    // R101-11 FIX: Strengthened gratuitous ARP anti-spoofing.
    //
    // R48-2 restricted gratuitous ARP to same-MAC refreshes. R101-11 adds an
    // additional check: if a static entry exists for the sender IP, gratuitous
    // ARP is NEVER used to update the cache (static entries are authoritative).
    // This protects critical entries like the default gateway from gratuitous ARP
    // cache poisoning attacks even if the attacker can spoof the legitimate MAC.
    //
    // Acceptance rules for gratuitous ARP:
    // 1. It's for our own IP (legitimate self-announcement), OR
    // 2. It's a same-MAC refresh of an existing DYNAMIC cache entry
    //    (static entries are never updated via gratuitous ARP)
    let existing_mac = cache.lookup(pkt.sender_ip, now_ms);

    // Check if a static entry exists for this IP
    let has_static_entry = cache.has_static_entry(pkt.sender_ip);

    let allow_gratuitous = is_gratuitous
        && !has_static_entry  // R101-11: Never allow gratuitous ARP to affect static entries
        && (
            pkt.sender_ip == our_ip ||                        // Our own announcement
        existing_mac == Some(pkt.sender_hw)
            // Same-MAC refresh only (dynamic entries)
        );

    // Security: Detect reflection attack attempt
    // If sender claims our IP but has different MAC, ignore completely
    if pkt.sender_ip == our_ip && pkt.sender_hw != our_mac {
        stats.inc_cache_conflicts();
        return ArpResult::Dropped(ArpError::CacheConflict);
    }

    // R45 FIX: Drop ARP replies not directed at us to reduce poisoning surface
    // Only accept replies that are:
    // 1. Targeted at our IP and MAC, or
    // 2. Gratuitous announcements that pass the R48-2 check
    if pkt.op == ArpOp::Reply {
        // Reject replies with invalid target MAC (broadcast/multicast/zero)
        if pkt.target_hw.is_broadcast()
            || pkt.target_hw.is_multicast()
            || pkt.target_hw == EthAddr::ZERO
        {
            stats.inc_rx_errors();
            return ArpResult::Dropped(ArpError::InvalidSender);
        }
        // Drop replies not for us (check allow_gratuitous instead of is_gratuitous)
        if !allow_gratuitous && (!for_us || pkt.target_hw != our_mac) {
            return ArpResult::Handled;
        }
    }

    // R65-7 FIX: Only learn from ARP replies (or allowed gratuitous/self-refresh requests).
    // This blocks attackers from poisoning the cache via forged ARP requests targeted at us.
    // Previously, any packet with target_ip == our_ip would learn the sender's mapping,
    // allowing an attacker to send a request claiming sender_ip = gateway_ip to hijack traffic.
    match pkt.op {
        ArpOp::Reply => {
            // Learn from replies addressed to us or allowed gratuitous
            if for_us || allow_gratuitous {
                if let Err(e) =
                    cache.insert(pkt.sender_ip, pkt.sender_hw, ArpEntryKind::Dynamic, now_ms)
                {
                    stats.inc_cache_conflicts();
                    return ArpResult::Dropped(e);
                }
            }
        }
        ArpOp::Request => {
            // Only allow gratuitous/self-refresh to update cache; ignore other requests.
            // Normal requests should only trigger a reply, not learn the sender's mapping.
            if allow_gratuitous {
                if let Err(e) =
                    cache.insert(pkt.sender_ip, pkt.sender_hw, ArpEntryKind::Dynamic, now_ms)
                {
                    stats.inc_cache_conflicts();
                    return ArpResult::Dropped(e);
                }
            }
        }
    }

    // Handle based on operation type
    match pkt.op {
        ArpOp::Request => {
            // Only respond if the request is for our IP
            if !for_us {
                return ArpResult::Handled;
            }

            // Ignore gratuitous ARP (target IP == sender IP, request for self)
            if is_gratuitous {
                return ArpResult::Handled;
            }

            // R102-12 FIX: Per-interface TX rate limiter + global backstop.
            if !cache.tx_rate_limiter.allow(now_ms) || !ARP_TX_RATE_LIMITER.allow(now_ms) {
                stats.inc_rx_rate_limited();
                return ArpResult::Dropped(ArpError::RateLimited);
            }

            // Build and return reply
            let reply = build_arp_reply(our_mac, our_ip, pkt.sender_hw, pkt.sender_ip);
            stats.inc_tx_replies();
            ArpResult::Reply(reply)
        }
        ArpOp::Reply => {
            // Reply processing: mapping was already learned above (if applicable)
            ArpResult::Handled
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_arp_request() -> Vec<u8> {
        let pkt = ArpPacket {
            sender_hw: EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Request,
        };
        serialize_arp(&pkt)
    }

    #[test]
    fn test_parse_valid_arp() {
        let data = make_test_arp_request();
        let pkt = parse_arp(&data).expect("should parse");
        assert_eq!(pkt.op, ArpOp::Request);
        assert_eq!(pkt.sender_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(pkt.target_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0u8; 10];
        assert_eq!(parse_arp(&data), Err(ArpError::Truncated));
    }

    #[test]
    fn test_parse_invalid_htype() {
        let mut data = make_test_arp_request();
        data[0] = 0x00; // Invalid hardware type
        data[1] = 0x02;
        assert_eq!(parse_arp(&data), Err(ArpError::InvalidHardwareType));
    }

    #[test]
    fn test_parse_broadcast_sender() {
        let pkt = ArpPacket {
            sender_hw: EthAddr::BROADCAST,
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::ZERO,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Request,
        };
        let data = serialize_arp(&pkt);
        assert_eq!(parse_arp(&data), Err(ArpError::InvalidSender));
    }

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        cache.insert(ip, mac, ArpEntryKind::Dynamic, 1000).unwrap();
        assert_eq!(cache.lookup(ip, 1000), Some(mac));
    }

    #[test]
    fn test_cache_conflict_rejection() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac1 = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac2 = EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        cache.insert(ip, mac1, ArpEntryKind::Dynamic, 1000).unwrap();
        // Attempt to update with different MAC should be rejected (anti-poisoning)
        assert_eq!(
            cache.insert(ip, mac2, ArpEntryKind::Dynamic, 2000),
            Err(ArpError::CacheConflict)
        );
        // Original mapping should still be there
        assert_eq!(cache.lookup(ip, 2000), Some(mac1));
    }

    #[test]
    fn test_cache_static_protection() {
        let mut cache = ArpCache::new(60_000, 10);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let static_mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let spoofed_mac = EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        cache.add_static(ip, static_mac, 1000).unwrap();
        // Attempt to overwrite static with dynamic should be rejected
        assert_eq!(
            cache.insert(ip, spoofed_mac, ArpEntryKind::Dynamic, 2000),
            Err(ArpError::CacheConflict)
        );
        assert_eq!(cache.lookup(ip, 2000), Some(static_mac));
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = ArpCache::new(1000, 10); // 1 second TTL
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mac = EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        cache.insert(ip, mac, ArpEntryKind::Dynamic, 0).unwrap();
        assert_eq!(cache.lookup(ip, 500), Some(mac)); // Not expired
        assert_eq!(cache.lookup(ip, 1500), None); // Expired
    }

    #[test]
    fn test_serialize_roundtrip() {
        let pkt = ArpPacket {
            sender_hw: EthAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_hw: EthAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            op: ArpOp::Reply,
        };
        let data = serialize_arp(&pkt);
        let parsed = parse_arp(&data).expect("should parse");
        assert_eq!(parsed.sender_hw, pkt.sender_hw);
        assert_eq!(parsed.sender_ip, pkt.sender_ip);
        assert_eq!(parsed.target_hw, pkt.target_hw);
        assert_eq!(parsed.target_ip, pkt.target_ip);
        assert_eq!(parsed.op, pkt.op);
    }
}
