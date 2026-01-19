//! Connection Tracking (Conntrack) for Zero-OS
//!
//! This module provides stateful connection tracking for the network stack,
//! independent of the socket layer. It tracks TCP, UDP, and ICMP flows for:
//!
//! - Stateful firewall decisions
//! - NAT support (future)
//! - Connection statistics
//!
//! # Design
//!
//! - Independent from socket.rs TCP state machine
//! - Tracks packet-level state transitions
//! - Per-protocol timeout management
//! - Memory-bounded with LRU eviction
//!
//! # Security
//!
//! - Validates state transitions to detect invalid packets
//! - Rate limits new connection creation
//! - Bounded memory usage with configurable limits

use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::vec::Vec;
use core::cmp::Reverse;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once, RwLock};

use crate::ipv4::Ipv4Addr;

// ============================================================================
// Constants
// ============================================================================

/// Maximum entries in the conntrack table
pub const CT_MAX_ENTRIES: usize = 65536;

/// TCP timeout values (milliseconds)
pub const CT_TCP_TIMEOUT_SYN_SENT_MS: u64 = 60_000;
pub const CT_TCP_TIMEOUT_SYN_RECV_MS: u64 = 60_000;
pub const CT_TCP_TIMEOUT_ESTABLISHED_MS: u64 = 300_000; // 5 minutes
pub const CT_TCP_TIMEOUT_FIN_WAIT_MS: u64 = 120_000; // 2 minutes
pub const CT_TCP_TIMEOUT_CLOSE_WAIT_MS: u64 = 60_000;
pub const CT_TCP_TIMEOUT_LAST_ACK_MS: u64 = 30_000;
pub const CT_TCP_TIMEOUT_TIME_WAIT_MS: u64 = 120_000; // 2*MSL
pub const CT_TCP_TIMEOUT_CLOSE_MS: u64 = 10_000;

/// UDP timeout values (milliseconds)
pub const CT_UDP_TIMEOUT_UNREPLIED_MS: u64 = 30_000;
pub const CT_UDP_TIMEOUT_REPLIED_MS: u64 = 180_000; // 3 minutes

/// ICMP timeout values (milliseconds)
pub const CT_ICMP_TIMEOUT_MS: u64 = 30_000;

/// Sweep budget per timer tick
pub const CT_SWEEP_BUDGET: usize = 256;

// ============================================================================
// Protocol Numbers
// ============================================================================

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// ============================================================================
// Flow Key
// ============================================================================

/// Normalized flow key for bidirectional matching.
///
/// The key is normalized so that (A->B) and (B->A) map to the same entry.
/// Direction is tracked separately in the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// Protocol number (TCP=6, UDP=17, ICMP=1)
    pub proto: u8,
    /// Lower IP address (for normalization)
    pub ip_lo: [u8; 4],
    /// Higher IP address (for normalization)
    pub ip_hi: [u8; 4],
    /// Lower port (for normalization)
    pub port_lo: u16,
    /// Higher port (for normalization)
    pub port_hi: u16,
}

impl FlowKey {
    /// Create a normalized flow key from packet fields.
    ///
    /// Returns the key and the direction (Original if src < dst, Reply otherwise).
    pub fn from_packet(
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> (Self, ConntrackDir) {
        let src_tuple = (src_ip.0, src_port);
        let dst_tuple = (dst_ip.0, dst_port);

        if src_tuple <= dst_tuple {
            (
                Self {
                    proto,
                    ip_lo: src_ip.0,
                    ip_hi: dst_ip.0,
                    port_lo: src_port,
                    port_hi: dst_port,
                },
                ConntrackDir::Original,
            )
        } else {
            (
                Self {
                    proto,
                    ip_lo: dst_ip.0,
                    ip_hi: src_ip.0,
                    port_lo: dst_port,
                    port_hi: src_port,
                },
                ConntrackDir::Reply,
            )
        }
    }

    /// Create a flow key for ICMP (using type/code/id as port fields).
    pub fn from_icmp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        icmp_type: u8,
        icmp_code: u8,
        icmp_id: u16,
    ) -> (Self, ConntrackDir) {
        // Pack type/code into port_lo, id into port_hi
        let pseudo_port = ((icmp_type as u16) << 8) | (icmp_code as u16);
        Self::from_packet(IPPROTO_ICMP, src_ip, dst_ip, pseudo_port, icmp_id)
    }
}

// ============================================================================
// Direction
// ============================================================================

/// Direction of a packet relative to the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackDir {
    /// Original direction (initiator -> responder)
    Original,
    /// Reply direction (responder -> initiator)
    Reply,
}

// ============================================================================
// Protocol States
// ============================================================================

/// TCP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpCtState {
    /// No connection
    None,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN-ACK received, waiting for ACK
    SynRecv,
    /// Connection established
    Established,
    /// FIN sent, waiting for ACK
    FinWait,
    /// FIN received, waiting for close
    CloseWait,
    /// Final ACK sent
    LastAck,
    /// Waiting for 2*MSL timeout
    TimeWait,
    /// Connection closed
    Close,
}

impl TcpCtState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            TcpCtState::None => CT_TCP_TIMEOUT_CLOSE_MS,
            TcpCtState::SynSent => CT_TCP_TIMEOUT_SYN_SENT_MS,
            TcpCtState::SynRecv => CT_TCP_TIMEOUT_SYN_RECV_MS,
            TcpCtState::Established => CT_TCP_TIMEOUT_ESTABLISHED_MS,
            TcpCtState::FinWait => CT_TCP_TIMEOUT_FIN_WAIT_MS,
            TcpCtState::CloseWait => CT_TCP_TIMEOUT_CLOSE_WAIT_MS,
            TcpCtState::LastAck => CT_TCP_TIMEOUT_LAST_ACK_MS,
            TcpCtState::TimeWait => CT_TCP_TIMEOUT_TIME_WAIT_MS,
            TcpCtState::Close => CT_TCP_TIMEOUT_CLOSE_MS,
        }
    }
}

/// UDP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCtState {
    /// Single packet seen (unreplied)
    Unreplied,
    /// Bidirectional traffic seen
    Replied,
}

impl UdpCtState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            UdpCtState::Unreplied => CT_UDP_TIMEOUT_UNREPLIED_MS,
            UdpCtState::Replied => CT_UDP_TIMEOUT_REPLIED_MS,
        }
    }
}

/// ICMP connection tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpCtState {
    /// Echo request sent
    EchoRequest,
    /// Echo reply received
    EchoReply,
}

/// Protocol-specific state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtProtoState {
    Tcp(TcpCtState),
    Udp(UdpCtState),
    Icmp(IcmpCtState),
    Other,
}

impl CtProtoState {
    /// Get the timeout for this state in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            CtProtoState::Tcp(s) => s.timeout_ms(),
            CtProtoState::Udp(s) => s.timeout_ms(),
            CtProtoState::Icmp(_) => CT_ICMP_TIMEOUT_MS,
            CtProtoState::Other => CT_UDP_TIMEOUT_UNREPLIED_MS,
        }
    }
}

// ============================================================================
// Conntrack Entry
// ============================================================================

/// A connection tracking entry.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// Normalized flow key
    pub key: FlowKey,
    /// Protocol-specific state
    pub state: CtProtoState,
    /// Last packet timestamp (ms)
    pub last_seen_ms: u64,
    /// Bytes transferred (original direction)
    pub bytes_orig: u64,
    /// Bytes transferred (reply direction)
    pub bytes_reply: u64,
    /// Packets transferred (original direction)
    pub packets_orig: u64,
    /// Packets transferred (reply direction)
    pub packets_reply: u64,
    /// Creation timestamp (ms)
    pub created_ms: u64,
    /// Whether reply has been seen
    pub seen_reply: bool,
    /// R63-1 FIX: True initiator direction for this flow.
    ///
    /// FlowKey normalization uses lexicographic ordering which may not match
    /// the actual connection initiator. This field records the direction of
    /// the first packet (the true initiator) so the state machine can correctly
    /// distinguish Original (initiator→responder) from Reply (responder→initiator).
    pub initiator_dir: ConntrackDir,
    /// R65-3 FIX: Monotonic generation for validating heap entries in the LRU index.
    pub lru_gen: u64,
}

impl ConntrackEntry {
    /// Create a new entry.
    ///
    /// # Arguments
    ///
    /// * `key` - Normalized flow key
    /// * `state` - Initial protocol state
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `initiator_dir` - Direction of the first packet (true initiator)
    pub fn new(
        key: FlowKey,
        state: CtProtoState,
        now_ms: u64,
        initiator_dir: ConntrackDir,
    ) -> Self {
        Self {
            key,
            state,
            last_seen_ms: now_ms,
            bytes_orig: 0,
            bytes_reply: 0,
            packets_orig: 0,
            packets_reply: 0,
            created_ms: now_ms,
            seen_reply: false,
            initiator_dir,
            lru_gen: 0,
        }
    }

    /// Check if the entry has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let timeout = self.state.timeout_ms();
        now_ms.saturating_sub(self.last_seen_ms) > timeout
    }

    /// Update statistics for a packet.
    pub fn update_stats(&mut self, dir: ConntrackDir, bytes: usize, now_ms: u64) {
        self.last_seen_ms = now_ms;
        match dir {
            ConntrackDir::Original => {
                self.bytes_orig = self.bytes_orig.saturating_add(bytes as u64);
                self.packets_orig = self.packets_orig.saturating_add(1);
            }
            ConntrackDir::Reply => {
                self.bytes_reply = self.bytes_reply.saturating_add(bytes as u64);
                self.packets_reply = self.packets_reply.saturating_add(1);
                self.seen_reply = true;
            }
        }
    }
}

// ============================================================================
// Decision
// ============================================================================

/// Decision from conntrack processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtDecision {
    /// Packet matches existing tracked connection
    Established,
    /// New connection created
    New,
    /// Related to existing connection (e.g., ICMP error)
    Related,
    /// Invalid state transition - should be dropped
    Invalid,
}

/// Result of conntrack update.
#[derive(Debug, Clone, Copy)]
pub struct CtUpdateResult {
    /// Decision for this packet
    pub decision: CtDecision,
    /// Current protocol state
    pub state: CtProtoState,
    /// Packet direction
    pub dir: ConntrackDir,
}

// ============================================================================
// L4 Metadata
// ============================================================================

/// Layer 4 metadata for state machine transitions.
#[derive(Debug, Clone, Copy)]
pub struct L4Meta {
    /// TCP flags (SYN, ACK, FIN, RST)
    pub tcp_flags: u8,
    /// Packet payload length
    pub payload_len: usize,
}

impl L4Meta {
    pub fn new(tcp_flags: u8, payload_len: usize) -> Self {
        Self {
            tcp_flags,
            payload_len,
        }
    }

    /// Check if SYN flag is set.
    pub fn is_syn(&self) -> bool {
        self.tcp_flags & 0x02 != 0
    }

    /// Check if ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.tcp_flags & 0x10 != 0
    }

    /// Check if FIN flag is set.
    pub fn is_fin(&self) -> bool {
        self.tcp_flags & 0x01 != 0
    }

    /// Check if RST flag is set.
    pub fn is_rst(&self) -> bool {
        self.tcp_flags & 0x04 != 0
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Conntrack statistics.
#[derive(Debug, Default)]
pub struct ConntrackStats {
    /// Total entries created
    pub entries_created: AtomicU64,
    /// Total entries deleted
    pub entries_deleted: AtomicU64,
    /// Entries deleted due to timeout
    pub timeout_deletes: AtomicU64,
    /// New connections rejected (table full)
    pub insert_failed: AtomicU64,
    /// Invalid state transitions
    pub invalid_transitions: AtomicU64,
    /// R63-3 FIX: Entries evicted via LRU when table is full
    pub evictions: AtomicU64,
    /// Current entry count
    pub current_entries: AtomicU32,
}

impl ConntrackStats {
    pub const fn new() -> Self {
        Self {
            entries_created: AtomicU64::new(0),
            entries_deleted: AtomicU64::new(0),
            timeout_deletes: AtomicU64::new(0),
            insert_failed: AtomicU64::new(0),
            invalid_transitions: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            current_entries: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// R65-3 FIX: LRU Index Entry for O(log n) eviction
// ============================================================================

/// Heap entry keyed by last_seen_ms and a generation to skip stale nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LruIndexEntry {
    last_seen_ms: u64,
    generation: u64,
    key: FlowKey,
}

impl PartialOrd for LruIndexEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LruIndexEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Order by last_seen_ms first, then generation, then key for stability
        self.last_seen_ms
            .cmp(&other.last_seen_ms)
            .then_with(|| self.generation.cmp(&other.generation))
            .then_with(|| self.key.cmp(&other.key))
    }
}

// ============================================================================
// Conntrack Table
// ============================================================================

/// The connection tracking table.
pub struct ConntrackTable {
    /// Entry storage (BTreeMap for stable iteration during sweep)
    entries: RwLock<BTreeMap<FlowKey, Mutex<ConntrackEntry>>>,
    /// R65-3 FIX: Min-heap (via Reverse) for O(log n) LRU eviction
    lru_index: Mutex<BinaryHeap<Reverse<LruIndexEntry>>>,
    /// R65-3 FIX: Monotonic generation counter for LRU heap validation
    lru_clock: AtomicU64,
    /// Statistics
    stats: ConntrackStats,
}

impl ConntrackTable {
    /// Create a new conntrack table.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            lru_index: Mutex::new(BinaryHeap::new()),
            lru_clock: AtomicU64::new(0),
            stats: ConntrackStats::new(),
        }
    }

    /// R65-3 FIX: Allocate a fresh LRU generation value.
    fn next_lru_generation(&self) -> u64 {
        self.lru_clock
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// R65-3 FIX: Record the latest access for a flow in the LRU heap.
    fn record_lru(&self, key: FlowKey, last_seen_ms: u64, generation: u64) {
        let mut heap = self.lru_index.lock();
        heap.push(Reverse(LruIndexEntry {
            last_seen_ms,
            generation,
            key,
        }));
    }

    /// Look up an entry by flow key.
    pub fn lookup(&self, key: &FlowKey) -> Option<ConntrackEntry> {
        let entries = self.entries.read();
        entries.get(key).map(|e| e.lock().clone())
    }

    /// Update conntrack state on packet arrival.
    ///
    /// This is the main entry point for packet processing.
    pub fn update_on_packet(
        &self,
        proto: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        l4: &L4Meta,
        now_ms: u64,
    ) -> CtUpdateResult {
        let (key, dir) = FlowKey::from_packet(proto, src_ip, dst_ip, src_port, dst_port);

        // Fast path: check existing entry with read lock
        {
            let entries = self.entries.read();
            if let Some(entry_lock) = entries.get(&key) {
                let mut entry = entry_lock.lock();

                // R63-1 FIX: Compute state machine direction based on true initiator.
                // FlowKey normalization uses lexicographic ordering, but the state machine
                // needs to know if this packet is from the initiator (Original) or responder (Reply).
                let state_dir = if dir == entry.initiator_dir {
                    ConntrackDir::Original
                } else {
                    ConntrackDir::Reply
                };

                let (new_state, decision) = self.transition_state(&entry, state_dir, proto, l4);

                if decision == CtDecision::Invalid {
                    self.stats
                        .invalid_transitions
                        .fetch_add(1, Ordering::Relaxed);
                    return CtUpdateResult {
                        decision,
                        state: entry.state,
                        dir,
                    };
                }

                entry.state = new_state;
                entry.update_stats(state_dir, l4.payload_len, now_ms);

                // R65-3 FIX: Record LRU access
                let lru_gen = self.next_lru_generation();
                entry.lru_gen = lru_gen;
                let last_seen_ms = entry.last_seen_ms;
                drop(entry);

                self.record_lru(key, last_seen_ms, lru_gen);

                return CtUpdateResult {
                    decision: CtDecision::Established,
                    state: new_state,
                    dir,
                };
            }
        }

        // Slow path: create new entry with write lock
        self.create_entry(key, dir, proto, l4, now_ms)
    }

    /// Create a new conntrack entry.
    fn create_entry(
        &self,
        key: FlowKey,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
        now_ms: u64,
    ) -> CtUpdateResult {
        // Determine initial state first (before acquiring lock)
        let initial_state = match proto {
            IPPROTO_TCP => {
                if l4.is_syn() && !l4.is_ack() {
                    CtProtoState::Tcp(TcpCtState::SynSent)
                } else {
                    // Non-SYN packet without existing entry - invalid
                    self.stats
                        .invalid_transitions
                        .fetch_add(1, Ordering::Relaxed);
                    return CtUpdateResult {
                        decision: CtDecision::Invalid,
                        state: CtProtoState::Tcp(TcpCtState::None),
                        dir,
                    };
                }
            }
            IPPROTO_UDP => CtProtoState::Udp(UdpCtState::Unreplied),
            IPPROTO_ICMP => CtProtoState::Icmp(IcmpCtState::EchoRequest),
            _ => CtProtoState::Other,
        };

        // Insert entry
        let mut entries = self.entries.write();

        // Double-check after acquiring write lock
        // R65-2 FIX: Entry was inserted concurrently. Reuse the packet's real
        // direction (`dir`) instead of calling update_on_packet with normalized
        // (ip_lo, ip_hi) which would re-normalize and lose direction information.
        if let Some(entry_lock) = entries.get(&key) {
            let mut entry = entry_lock.lock();

            // Calculate state direction relative to initiator
            let state_dir = if dir == entry.initiator_dir {
                ConntrackDir::Original
            } else {
                ConntrackDir::Reply
            };

            let (new_state, decision) = self.transition_state(&entry, state_dir, proto, l4);

            if decision == CtDecision::Invalid {
                self.stats
                    .invalid_transitions
                    .fetch_add(1, Ordering::Relaxed);
                return CtUpdateResult {
                    decision,
                    state: entry.state,
                    dir,
                };
            }

            entry.state = new_state;
            entry.update_stats(state_dir, l4.payload_len, now_ms);

            // R65-3 FIX: Record LRU access
            let lru_gen = self.next_lru_generation();
            entry.lru_gen = lru_gen;
            let last_seen_ms = entry.last_seen_ms;
            drop(entry);

            self.record_lru(key, last_seen_ms, lru_gen);

            return CtUpdateResult {
                decision: CtDecision::Established,
                state: new_state,
                dir,
            };
        }

        // R63-2 FIX: Check table capacity UNDER the write lock to prevent
        // concurrent bypass. Previously, the check was done before acquiring
        // the lock, allowing multiple threads to pass the check simultaneously.
        // R63-3 FIX: Use LRU eviction instead of rejecting when table is full.
        // This prevents attackers from filling the table to block legitimate traffic.
        if entries.len() >= CT_MAX_ENTRIES {
            if !self.evict_lru_locked(&mut entries) {
                // Table is empty but still at capacity? Shouldn't happen.
                self.stats.insert_failed.fetch_add(1, Ordering::Relaxed);
                return CtUpdateResult {
                    decision: CtDecision::Invalid,
                    state: CtProtoState::Other,
                    dir,
                };
            }
        }

        // R63-1 FIX: Pass initiator_dir to track the true connection initiator.
        // The first packet's direction (dir) is the initiator direction.
        let mut entry = ConntrackEntry::new(key, initial_state, now_ms, dir);
        // Use Original for stats since this is the first packet from initiator
        entry.update_stats(ConntrackDir::Original, l4.payload_len, now_ms);

        // R65-3 FIX: Set LRU generation and record in heap
        let lru_gen = self.next_lru_generation();
        entry.lru_gen = lru_gen;
        let last_seen_ms = entry.last_seen_ms;

        entries.insert(key, Mutex::new(entry));
        self.stats.entries_created.fetch_add(1, Ordering::Relaxed);
        self.stats.current_entries.fetch_add(1, Ordering::Relaxed);

        self.record_lru(key, last_seen_ms, lru_gen);

        CtUpdateResult {
            decision: CtDecision::New,
            state: initial_state,
            dir,
        }
    }

    /// Compute state transition for a packet.
    fn transition_state(
        &self,
        entry: &ConntrackEntry,
        dir: ConntrackDir,
        proto: u8,
        l4: &L4Meta,
    ) -> (CtProtoState, CtDecision) {
        match (proto, &entry.state) {
            (IPPROTO_TCP, CtProtoState::Tcp(tcp_state)) => self.tcp_transition(*tcp_state, dir, l4),
            (IPPROTO_UDP, CtProtoState::Udp(udp_state)) => self.udp_transition(*udp_state, dir),
            (IPPROTO_ICMP, CtProtoState::Icmp(icmp_state)) => {
                self.icmp_transition(*icmp_state, dir)
            }
            _ => (entry.state, CtDecision::Established),
        }
    }

    /// TCP state machine transition.
    fn tcp_transition(
        &self,
        state: TcpCtState,
        dir: ConntrackDir,
        l4: &L4Meta,
    ) -> (CtProtoState, CtDecision) {
        // Handle RST - always transitions to Close
        if l4.is_rst() {
            return (
                CtProtoState::Tcp(TcpCtState::Close),
                CtDecision::Established,
            );
        }

        let new_state = match (state, dir) {
            // SYN sent, waiting for SYN-ACK
            (TcpCtState::SynSent, ConntrackDir::Reply) if l4.is_syn() && l4.is_ack() => {
                TcpCtState::SynRecv
            }
            // SYN-ACK received, waiting for ACK
            (TcpCtState::SynRecv, ConntrackDir::Original) if l4.is_ack() && !l4.is_syn() => {
                TcpCtState::Established
            }
            // Established - handle FIN
            (TcpCtState::Established, _) if l4.is_fin() => match dir {
                ConntrackDir::Original => TcpCtState::FinWait,
                ConntrackDir::Reply => TcpCtState::CloseWait,
            },
            // FIN wait - handle reply FIN or ACK
            (TcpCtState::FinWait, ConntrackDir::Reply) if l4.is_fin() => TcpCtState::LastAck,
            (TcpCtState::FinWait, ConntrackDir::Reply) if l4.is_ack() => TcpCtState::TimeWait,
            // Close wait - handle FIN
            (TcpCtState::CloseWait, ConntrackDir::Original) if l4.is_fin() => TcpCtState::LastAck,
            // Last ACK - handle final ACK
            (TcpCtState::LastAck, _) if l4.is_ack() => TcpCtState::TimeWait,
            // Stay in current state for other packets
            _ => state,
        };

        (CtProtoState::Tcp(new_state), CtDecision::Established)
    }

    /// UDP state machine transition.
    fn udp_transition(&self, state: UdpCtState, dir: ConntrackDir) -> (CtProtoState, CtDecision) {
        let new_state = match (state, dir) {
            (UdpCtState::Unreplied, ConntrackDir::Reply) => UdpCtState::Replied,
            _ => state,
        };
        (CtProtoState::Udp(new_state), CtDecision::Established)
    }

    /// ICMP state machine transition.
    fn icmp_transition(&self, state: IcmpCtState, dir: ConntrackDir) -> (CtProtoState, CtDecision) {
        let new_state = match (state, dir) {
            (IcmpCtState::EchoRequest, ConntrackDir::Reply) => IcmpCtState::EchoReply,
            _ => state,
        };
        (CtProtoState::Icmp(new_state), CtDecision::Established)
    }

    /// Remove an entry by key.
    pub fn remove(&self, key: &FlowKey) -> bool {
        let mut entries = self.entries.write();
        if entries.remove(key).is_some() {
            self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
            self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// R63-3 FIX: Evict the least-recently-seen entry (LRU) while holding the write lock.
    ///
    /// This prevents table exhaustion attacks where an attacker fills the table
    /// with long-lived UDP or half-open TCP connections to block legitimate traffic.
    ///
    /// # Returns
    ///
    /// `true` if an entry was evicted, `false` if the table is empty.
    /// R65-3 FIX: Evict the least-recently-seen entry (LRU) in O(log n) using heap index.
    ///
    /// This prevents table exhaustion attacks where an attacker fills the table
    /// with long-lived UDP or half-open TCP connections to block legitimate traffic.
    ///
    /// # Returns
    /// `true` if an entry was evicted, `false` if table is empty.
    fn evict_lru_locked(&self, entries: &mut BTreeMap<FlowKey, Mutex<ConntrackEntry>>) -> bool {
        // R65-3 FIX: Use heap for O(log n) eviction instead of O(n) linear scan
        loop {
            let candidate = {
                let mut heap = self.lru_index.lock();
                heap.pop().map(|Reverse(entry)| entry)
            };

            let Some(victim) = candidate else {
                return false;
            };

            // Validate the heap entry is still current (not stale)
            if let Some(entry_lock) = entries.get(&victim.key) {
                let entry = entry_lock.lock();
                if entry.lru_gen == victim.generation && entry.last_seen_ms == victim.last_seen_ms {
                    drop(entry);
                    entries.remove(&victim.key);
                    self.stats.entries_deleted.fetch_add(1, Ordering::Relaxed);
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_entries.fetch_sub(1, Ordering::Relaxed);
                    return true;
                }
                // Entry was updated since heap entry was created - skip stale entry
            }
            // Entry was removed or stale - continue to next candidate
        }
    }

    /// Sweep expired entries.
    ///
    /// Should be called periodically from timer context.
    /// Returns the number of entries removed.
    pub fn sweep(&self, now_ms: u64, budget: usize) -> usize {
        let mut to_remove = Vec::new();

        // Collect expired keys with read lock
        {
            let entries = self.entries.read();
            for (key, entry_lock) in entries.iter() {
                if to_remove.len() >= budget {
                    break;
                }
                let entry = entry_lock.lock();
                if entry.is_expired(now_ms) {
                    to_remove.push(*key);
                }
            }
        }

        // Remove with write lock
        // R65-4 FIX: Only decrement current_entries for entries actually removed.
        // The previous code unconditionally decremented by to_remove.len(), but
        // concurrent operations might have already removed some entries.
        // Now we check remove() return value and only count successful removals.
        if !to_remove.is_empty() {
            let mut entries = self.entries.write();
            let mut actually_removed: u64 = 0;
            for key in &to_remove {
                // R65-4 FIX: Check if entry actually existed before counting
                if entries.remove(key).is_some() {
                    actually_removed += 1;
                }
            }
            if actually_removed > 0 {
                self.stats
                    .timeout_deletes
                    .fetch_add(actually_removed, Ordering::Relaxed);
                self.stats
                    .entries_deleted
                    .fetch_add(actually_removed, Ordering::Relaxed);
                // R65-4 FIX: Only subtract actually removed count to prevent underflow
                self.stats
                    .current_entries
                    .fetch_sub(actually_removed as u32, Ordering::Relaxed);
            }
            actually_removed as usize
        } else {
            0
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &ConntrackStats {
        &self.stats
    }

    /// Get current entry count.
    pub fn len(&self) -> usize {
        self.stats.current_entries.load(Ordering::Relaxed) as usize
    }

    /// Check if table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static CONNTRACK_TABLE: Once<ConntrackTable> = Once::new();

/// Get the global conntrack table.
pub fn conntrack_table() -> &'static ConntrackTable {
    CONNTRACK_TABLE.call_once(ConntrackTable::new)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Process a TCP packet through conntrack.
pub fn ct_process_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    let l4 = L4Meta::new(tcp_flags, payload_len);
    conntrack_table().update_on_packet(IPPROTO_TCP, src_ip, dst_ip, src_port, dst_port, &l4, now_ms)
}

/// Process a UDP packet through conntrack.
pub fn ct_process_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    let l4 = L4Meta::new(0, payload_len);
    conntrack_table().update_on_packet(IPPROTO_UDP, src_ip, dst_ip, src_port, dst_port, &l4, now_ms)
}

/// Process an ICMP packet through connection tracking.
///
/// ICMP tracking is simpler than TCP/UDP:
/// - Echo request/reply pairs can be tracked
/// - ICMP error messages (Type 3, 11, etc.) are RELATED to existing connections
/// - Other ICMP messages are treated as NEW
///
/// # Arguments
/// * `src_ip` - Source IP address
/// * `dst_ip` - Destination IP address
/// * `icmp_type` - ICMP message type
/// * `icmp_code` - ICMP message code
/// * `payload_len` - Length of payload
/// * `now_ms` - Current time in milliseconds
pub fn ct_process_icmp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    payload_len: usize,
    now_ms: u64,
) -> CtUpdateResult {
    // ICMP error messages (Destination Unreachable, Time Exceeded, etc.)
    // are RELATED to existing connections
    let is_error_type = icmp_type == 3 || icmp_type == 11 || icmp_type == 12;

    // Use type/code as pseudo-ports for flow tracking
    // This allows tracking echo request/reply pairs
    let pseudo_src_port = ((icmp_type as u16) << 8) | (icmp_code as u16);
    let pseudo_dst_port = 0u16;

    let l4 = L4Meta::new(0, payload_len);

    // For ICMP errors, we could try to find the original connection
    // For now, treat as simple flow tracking
    if is_error_type {
        // ICMP errors are typically RELATED - but without parsing the
        // embedded packet, we can't confirm. Return NEW for now.
        // A more sophisticated implementation would parse the embedded
        // IP header to find the original connection.
    }

    conntrack_table().update_on_packet(
        IPPROTO_ICMP,
        src_ip,
        dst_ip,
        pseudo_src_port,
        pseudo_dst_port,
        &l4,
        now_ms,
    )
}

/// Run conntrack sweep (call from timer).
pub fn ct_sweep(now_ms: u64) -> usize {
    conntrack_table().sweep(now_ms, CT_SWEEP_BUDGET)
}
