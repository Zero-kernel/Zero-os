//! TCP (Transmission Control Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 793 compliant TCP implementation with security-first design.
//!
//! # TCP Header Format (RFC 793)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Source Port           |       Destination Port        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                        Sequence Number                        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                     Acknowledgment Number                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Data  |       |U|A|P|R|S|F|                                   |
//! | Offs  | Resv  |R|C|S|S|Y|I|            Window                 |
//! |       |       |G|K|H|T|N|N|                                   |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |           Checksum            |         Urgent Pointer        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                    Options (if data offset > 5)               |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                             Data                              |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - ISN randomization per RFC 6528 (keyed hash over 4-tuple + time)
//! - Strict sequence number validation (prevents off-path attacks)
//! - SYN flood protection with backlog limits (SYN cookies placeholder)
//! - Connection resource limits
//! - Checksum verification with IPv4 pseudo-header
//! - RST rate limiting
//! - Invalid flag combination rejection
//!
//! # State Machine
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   \
//!                              +---------+            CLOSE    |    \
//!                              |  LISTEN |          ---------- |     |
//!                              +---------+          delete TCB |     |
//!                   rcv SYN      |     |     SEND              |     |
//!                  -----------   |     |    -------            |     V
//! +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//! |         |<-----------------           ------------------>|         |
//! |   SYN   |                    rcv SYN                     |   SYN   |
//! |   RCVD  |<-----------------------------------------------|   SENT  |
//! |         |                    snd ACK                     |         |
//! |         |------------------           -------------------|         |
//! +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//!   |           --------------   |     |   -----------
//!   |                  x         |     |     snd ACK
//!   |                            V     V
//!   |  CLOSE                   +---------+
//!   | -------                  |  ESTAB  |
//!   | snd FIN                  +---------+
//!   |                   ...continued states...
//! ```
//!
//! # References
//!
//! - RFC 793: Transmission Control Protocol
//! - RFC 1122: Requirements for Internet Hosts
//! - RFC 6528: Defending Against Sequence Number Attacks
//! - RFC 5961: Improving TCP's Robustness to Blind In-Window Attacks

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once, RwLock};

use crate::ipv4::{compute_checksum, Ipv4Addr};

// ============================================================================
// TCP Constants
// ============================================================================

/// TCP header minimum length in bytes (without options)
pub const TCP_HEADER_MIN_LEN: usize = 20;

/// TCP header maximum length in bytes (with max options)
pub const TCP_HEADER_MAX_LEN: usize = 60;

/// TCP protocol number (for IPv4)
pub const TCP_PROTO: u8 = 6;

/// Maximum Segment Size default (RFC 879)
pub const TCP_DEFAULT_MSS: u16 = 536;

/// Maximum Segment Size for Ethernet (1500 - 20 IP - 20 TCP)
pub const TCP_ETHERNET_MSS: u16 = 1460;

/// Default receive window size (unscaled, for compatibility)
pub const TCP_DEFAULT_WINDOW: u16 = 65535;

// ============================================================================
// SYN Cookie Constants (RFC 4987)
// ============================================================================

/// Supported MSS values encoded in SYN cookies (3 bits => 8 slots).
///
/// These are sorted in ascending order. When generating a cookie, we select
/// the largest value that doesn't exceed the peer's offered MSS.
///
/// # Security Consideration
///
/// SYN cookies lose MSS precision (only 8 values supported). The table covers
/// common network paths from small MTU links to Ethernet. Window scaling
/// information is not preserved in cookies (limitation of the protocol).
pub const TCP_SYN_COOKIE_MSS_TABLE: [u16; 8] = [
    256,              // Minimum practical MSS
    TCP_DEFAULT_MSS,  // 536 - RFC 879 default
    576,              // Common older networks
    1024,             // Intermediate networks
    1200,             // Conservative Ethernet estimate
    1360,             // PPPoE/VPN overhead adjustment
    1400,             // Common datacenter setting
    TCP_ETHERNET_MSS, // 1460 - Full Ethernet
];

/// Time granularity for SYN cookie timestamps (milliseconds).
///
/// Coarser granularity (4 seconds) allows more time slots in fewer bits
/// while still providing reasonable protection against replay attacks.
pub const TCP_SYN_COOKIE_TIME_GRANULARITY_MS: u64 = 4_000;

/// Maximum age for a valid SYN cookie (milliseconds).
///
/// Cookies older than this are rejected to prevent replay attacks.
/// 120 seconds allows for slow networks with high packet loss while
/// limiting the attack window.
pub const TCP_SYN_COOKIE_MAX_AGE_MS: u64 = 120_000;

/// Secret rotation period for SYN cookie MAC (milliseconds).
///
/// The secret is rotated every 5 minutes. During rotation, both the
/// current and previous secrets are accepted to handle in-flight packets.
const TCP_SYN_COOKIE_SECRET_ROTATE_MS: u64 = 300_000;

/// Bit width for time slot in SYN cookie (6 bits = 64 slots × 4 sec = 256 sec range).
const TCP_SYN_COOKIE_TIME_BITS: u32 = 6;

/// Bit width for MSS index in SYN cookie (3 bits = 8 MSS options).
const TCP_SYN_COOKIE_MSS_BITS: u32 = 3;

/// Bit width for MAC in SYN cookie (remaining 23 bits).
const TCP_SYN_COOKIE_MAC_BITS: u32 = 32 - TCP_SYN_COOKIE_TIME_BITS - TCP_SYN_COOKIE_MSS_BITS;

/// Bitmask for time slot extraction.
const TCP_SYN_COOKIE_TIME_MASK: u32 = (1 << TCP_SYN_COOKIE_TIME_BITS) - 1;

/// Bitmask for MSS index extraction.
const TCP_SYN_COOKIE_MSS_MASK: u32 = (1 << TCP_SYN_COOKIE_MSS_BITS) - 1;

/// Bitmask for MAC extraction.
const TCP_SYN_COOKIE_MAC_MASK: u32 = (1 << TCP_SYN_COOKIE_MAC_BITS) - 1;

/// Maximum valid age in time slots for SYN cookie validation.
const TCP_SYN_COOKIE_MAX_AGE_SLOTS: u32 =
    (TCP_SYN_COOKIE_MAX_AGE_MS / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32;

// ============================================================================
// Window Scaling Constants (RFC 7323)
// ============================================================================

/// Maximum window scale shift factor per RFC 7323.
/// Scale factor of 14 allows windows up to 1GB (65535 << 14).
pub const TCP_MAX_WINDOW_SCALE: u8 = 14;

/// Maximum scaled window size in bytes.
/// This is the largest receive window we can advertise (65535 << 14).
pub const TCP_MAX_SCALED_WINDOW: u32 = (u16::MAX as u32) << TCP_MAX_WINDOW_SCALE;

/// Default receive buffer size in bytes (256 KB).
/// This is larger than 64KB to make window scaling worthwhile.
/// Provides good throughput on typical networks.
pub const TCP_DEFAULT_RCV_WINDOW_BYTES: u32 = 256 * 1024;

/// Maximum retransmission attempts before giving up
pub const TCP_MAX_RETRIES: u8 = 15;

/// Initial retransmission timeout in milliseconds
pub const TCP_INITIAL_RTO_MS: u64 = 1000;

/// Minimum retransmission timeout in milliseconds
///
/// RFC 6298 Section 2.4 recommends a minimum RTO of 1 second to avoid
/// spurious retransmissions due to delayed ACKs. While some implementations
/// use lower values (Linux uses 200ms with tcp_rto_min), we follow the RFC
/// for correctness and to account for our coarser timer granularity.
pub const TCP_MIN_RTO_MS: u64 = 1000;

/// Maximum retransmission timeout in milliseconds
pub const TCP_MAX_RTO_MS: u64 = 120_000;

/// TIME-WAIT duration (2*MSL = 2*60 seconds per RFC 793)
pub const TCP_TIME_WAIT_MS: u64 = 120_000;

/// R65-5 FIX: FIN_WAIT_2 idle timeout (60 seconds).
///
/// RFC 793 does not specify a timeout for FIN_WAIT_2, but without one, connections
/// can remain in this state indefinitely if the peer never sends FIN. This creates
/// a resource exhaustion vulnerability where an attacker can:
/// 1. Establish many connections
/// 2. Send FIN and receive our FIN-ACK (we move to FIN_WAIT_2)
/// 3. Never send their FIN, leaking our TCB resources forever
///
/// Linux uses tcp_fin_timeout sysctl (default 60 seconds) to bound this state.
/// We follow the same approach for consistency and security.
pub const TCP_FIN_WAIT_2_TIMEOUT_MS: u64 = 60_000;

/// R52-1 FIX: SYN timeout for half-open connections in SYN queue.
///
/// Half-open connections (SYN received, SYN-ACK sent, awaiting final ACK) are
/// evicted from the SYN queue after this timeout to prevent SYN flood attacks
/// from exhausting listener resources.
///
/// 30 seconds is a reasonable balance:
/// - Long enough for legitimate slow connections (high-latency, packet loss)
/// - Short enough to recover from SYN flood attacks within minutes
///
/// Reference: Linux uses tcp_synack_retries (default 5) * exponential backoff,
/// resulting in ~63 seconds total. We use a simpler fixed timeout.
pub const TCP_SYN_TIMEOUT_MS: u64 = 30_000;

/// FIN retransmission timeout floor (RFC 6298 style, reuse RTO baseline)
pub const TCP_FIN_TIMEOUT_MS: u64 = TCP_INITIAL_RTO_MS;

/// Maximum FIN retransmission attempts before giving up
pub const TCP_MAX_FIN_RETRIES: u8 = 5;

/// Maximum SYN backlog per listening socket
pub const TCP_MAX_SYN_BACKLOG: usize = 128;

/// Maximum pending connections per listening socket
pub const TCP_MAX_ACCEPT_BACKLOG: usize = 128;

/// R50-5 FIX: Maximum active TCP connections (all states) to prevent resource exhaustion
pub const TCP_MAX_ACTIVE_CONNECTIONS: usize = 4096;

/// R51-2 FIX: Maximum TCP send size (bounds kernel allocations).
/// Limits per-send payload to 64KB to align with default receive window.
/// Enforced in tcp_send() to protect all send paths from OOM DoS.
pub const TCP_MAX_SEND_SIZE: usize = 64 * 1024;

// ============================================================================
// Congestion Control Constants (RFC 5681)
// ============================================================================

/// Initial slow-start threshold.
///
/// Set to a large value initially; will be reduced on congestion events.
/// 64KB aligns with the default receive window.
pub const TCP_INITIAL_SSTHRESH: u32 = 64 * 1024;

/// Compute the initial congestion window per RFC 5681 Section 3.1.
///
/// IW = min(4*SMSS, max(2*SMSS, 4380 bytes))
///
/// This formula allows:
/// - At least 2 segments for small MSS
/// - Up to 4 segments for larger MSS
/// - Maximum of ~3 full-size Ethernet segments
#[inline]
pub fn initial_cwnd(smss: u16) -> u32 {
    let smss = smss as u32;
    let four_smss = smss.saturating_mul(4);
    let two_smss = smss.saturating_mul(2);
    core::cmp::min(four_smss, core::cmp::max(two_smss, 4380))
}

// ============================================================================
// TCP Flags
// ============================================================================

/// FIN flag - sender has finished sending
pub const TCP_FLAG_FIN: u8 = 0x01;
/// SYN flag - synchronize sequence numbers
pub const TCP_FLAG_SYN: u8 = 0x02;
/// RST flag - reset the connection
pub const TCP_FLAG_RST: u8 = 0x04;
/// PSH flag - push function
pub const TCP_FLAG_PSH: u8 = 0x08;
/// ACK flag - acknowledgment field is significant
pub const TCP_FLAG_ACK: u8 = 0x10;
/// URG flag - urgent pointer field is significant
pub const TCP_FLAG_URG: u8 = 0x20;
/// ECE flag - ECN-Echo (RFC 3168)
pub const TCP_FLAG_ECE: u8 = 0x40;
/// CWR flag - Congestion Window Reduced (RFC 3168)
pub const TCP_FLAG_CWR: u8 = 0x80;

// ============================================================================
// TCP State Machine
// ============================================================================

/// TCP connection state per RFC 793
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection state at all
    Closed,
    /// Waiting for a connection request from any remote TCP
    Listen,
    /// Waiting for a matching connection request after having sent one
    SynSent,
    /// Waiting for confirming connection request acknowledgment
    SynReceived,
    /// Open connection, data can be exchanged
    Established,
    /// Waiting for a connection termination request from remote TCP
    /// (after local close)
    FinWait1,
    /// Waiting for a connection termination request from remote TCP
    FinWait2,
    /// Waiting for a connection termination request from local user
    CloseWait,
    /// Waiting for connection termination request acknowledgment from remote TCP
    Closing,
    /// Waiting for acknowledgment of connection termination request
    LastAck,
    /// Waiting for enough time to pass to be sure remote TCP received
    /// acknowledgment of its connection termination request
    TimeWait,
}

impl TcpState {
    /// Check if the connection is in an established or semi-established state
    pub fn can_send(&self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }

    /// Check if the connection can receive data
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        )
    }

    /// Check if the connection is closed or closing
    pub fn is_closed(&self) -> bool {
        matches!(self, TcpState::Closed | TcpState::TimeWait)
    }

    /// Check if the connection is synchronized (after handshake)
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
        )
    }
}

// ============================================================================
// Congestion Control State Machine (RFC 5681)
// ============================================================================

/// Congestion control state per RFC 5681.
///
/// TCP congestion control operates in one of three phases:
/// - Slow Start: Exponential growth of cwnd until ssthresh is reached
/// - Congestion Avoidance: Linear growth after ssthresh
/// - Fast Recovery: Entered after triple duplicate ACK
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpCongestionState {
    /// Exponential cwnd growth (cwnd < ssthresh).
    ///
    /// On each ACK: cwnd += min(N, SMSS) where N is newly acked bytes.
    SlowStart,

    /// Linear cwnd growth (cwnd >= ssthresh).
    ///
    /// On each ACK: cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT).
    CongestionAvoidance,

    /// Fast recovery after triple duplicate ACK (RFC 5681 Section 3.2).
    ///
    /// ssthresh = max(FlightSize/2, 2*SMSS)
    /// cwnd = ssthresh + 3*SMSS (inflate for segments in flight)
    /// Retransmit the first unacked segment.
    FastRecovery,
}

impl Default for TcpCongestionState {
    fn default() -> Self {
        Self::SlowStart
    }
}

/// Result of ACK processing for congestion control decisions.
#[derive(Debug, Default, Clone, Copy)]
pub struct AckUpdate {
    /// Number of newly acknowledged bytes (0 for duplicate ACK).
    pub newly_acked: u32,
    /// True if this ACK did not advance snd_una (duplicate ACK).
    pub duplicate: bool,
}

/// Actions that congestion control may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAction {
    /// No immediate transmission change needed.
    None,
    /// Trigger fast retransmit of the first unacknowledged segment.
    FastRetransmit,
    /// R56-1: RFC 3042 Limited Transmit - request sending new data on early dup ACKs.
    ///
    /// On the first or second duplicate ACK (before fast retransmit threshold),
    /// if FlightSize + SMSS <= cwnd + 2*SMSS, send one new segment to help
    /// drive fast retransmit on small-window connections.
    LimitedTransmit,
    /// Retransmit next unacknowledged segment after partial ACK (NewReno).
    ///
    /// R55-1: NewReno partial ACK handling - stay in fast recovery and
    /// retransmit the next unacked segment instead of exiting FR.
    RetransmitNext,
}

// ============================================================================
// TCP Header
// ============================================================================

/// Parsed TCP header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number (valid if ACK flag set)
    pub ack_num: u32,
    /// Data offset in 32-bit words (5-15)
    pub data_offset: u8,
    /// Reserved bits (must be zero)
    pub reserved: u8,
    /// Control flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
    pub flags: u8,
    /// Receive window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer (valid if URG flag set)
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Create a new TCP header with the given parameters
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        window: u16,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset: 5, // No options, 20 bytes
            reserved: 0,
            flags,
            window,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Get the header length in bytes
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_FLAG_SYN != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & TCP_FLAG_ACK != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FLAG_FIN != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & TCP_FLAG_RST != 0
    }

    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        self.flags & TCP_FLAG_PSH != 0
    }

    /// Serialize header to bytes (without checksum)
    pub fn to_bytes(&self) -> [u8; TCP_HEADER_MIN_LEN] {
        let mut bytes = [0u8; TCP_HEADER_MIN_LEN];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        // Data offset (4 bits) + reserved (4 bits)
        bytes[12] = (self.data_offset << 4) | (self.reserved & 0x0F);
        bytes[13] = self.flags;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes
    }
}

// ============================================================================
// TCP Options
// ============================================================================

/// TCP option kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOptionKind {
    /// End of option list
    EndOfList,
    /// No-operation (padding)
    Nop,
    /// Maximum Segment Size
    Mss(u16),
    /// Window Scale (RFC 7323)
    WindowScale(u8),
    /// Selective Acknowledgment Permitted (RFC 2018)
    SackPermitted,
    /// Timestamps (RFC 7323)
    Timestamps { ts_val: u32, ts_ecr: u32 },
    /// Unknown option
    Unknown { kind: u8, len: u8 },
}

/// Parsed TCP options
#[derive(Debug, Clone, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size
    pub mss: Option<u16>,
    /// Window Scale factor
    pub window_scale: Option<u8>,
    /// SACK permitted
    pub sack_permitted: bool,
    /// Timestamps
    pub timestamps: Option<(u32, u32)>,
}

// ============================================================================
// TCP Option Serialization
// ============================================================================

/// Serialize a single TCP option to bytes.
///
/// Returns the raw bytes for the option, including kind and length fields
/// where applicable. Single-byte options (End, NOP) return just the kind byte.
pub fn serialize_tcp_option(option: &TcpOptionKind) -> Vec<u8> {
    match *option {
        TcpOptionKind::EndOfList => vec![0],
        TcpOptionKind::Nop => vec![1],
        TcpOptionKind::Mss(mss) => {
            let mut bytes = Vec::with_capacity(4);
            bytes.extend_from_slice(&[2, 4]); // kind=2, len=4
            bytes.extend_from_slice(&mss.to_be_bytes());
            bytes
        }
        TcpOptionKind::WindowScale(scale) => vec![3, 3, scale], // kind=3, len=3, shift
        TcpOptionKind::SackPermitted => vec![4, 2],             // kind=4, len=2
        TcpOptionKind::Timestamps { ts_val, ts_ecr } => {
            let mut bytes = Vec::with_capacity(10);
            bytes.extend_from_slice(&[8, 10]); // kind=8, len=10
            bytes.extend_from_slice(&ts_val.to_be_bytes());
            bytes.extend_from_slice(&ts_ecr.to_be_bytes());
            bytes
        }
        TcpOptionKind::Unknown { kind, len } => {
            // Ensure minimum length of 2 (kind + length bytes)
            let effective_len = len.max(2);
            let mut bytes = Vec::with_capacity(effective_len as usize);
            bytes.push(kind);
            bytes.push(effective_len);
            bytes.resize(effective_len as usize, 0);
            bytes
        }
    }
}

/// Serialize a slice of TCP options with padding to 32-bit boundary.
///
/// This function:
/// 1. Serializes each option in order
/// 2. Appends End-of-List marker if not already present
/// 3. Pads with NOP (0x00) bytes to ensure 32-bit alignment
///
/// Returns empty Vec if no options provided (no padding needed for minimal header).
pub fn serialize_tcp_options(options: &[TcpOptionKind]) -> Vec<u8> {
    if options.is_empty() {
        return Vec::new();
    }

    let mut bytes = Vec::new();
    let mut has_end = false;

    for opt in options {
        let opt_bytes = serialize_tcp_option(opt);
        bytes.extend_from_slice(&opt_bytes);

        if matches!(opt, TcpOptionKind::EndOfList) {
            has_end = true;
            break;
        }
    }

    // Append End-of-List if not present
    if !has_end {
        bytes.push(0);
    }

    // Pad to 32-bit boundary with zeroes (same as NOP bytes after End)
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }

    bytes
}

// ============================================================================
// TCP Control Block (TCB)
// ============================================================================

/// 4-tuple connection key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnKey {
    /// Local IP address
    pub local_ip: Ipv4Addr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_ip: Ipv4Addr,
    /// Remote port
    pub remote_port: u16,
}

impl TcpConnKey {
    /// Create a new connection key
    pub fn new(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }

    /// Create the reverse key (for matching incoming packets)
    pub fn reverse(&self) -> Self {
        Self {
            local_ip: self.remote_ip,
            local_port: self.remote_port,
            remote_ip: self.local_ip,
            remote_port: self.local_port,
        }
    }
}

/// TCP Control Block - per-connection state
pub struct TcpControlBlock {
    /// Connection state
    pub state: TcpState,

    /// Connection key (4-tuple)
    pub key: TcpConnKey,

    // === Send Sequence Space (RFC 793 Section 3.2) ===
    /// Initial Send Sequence Number
    pub iss: u32,
    /// Send Unacknowledged - oldest unacknowledged sequence number
    pub snd_una: u32,
    /// Send Next - next sequence number to send
    pub snd_nxt: u32,
    /// Send Window - send window size
    pub snd_wnd: u32,
    /// Segment sequence number used for last window update
    pub snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    pub snd_wl2: u32,

    // === Congestion Control (RFC 5681) ===
    /// Congestion window in bytes.
    ///
    /// Limits the amount of data that can be in flight (unacknowledged).
    /// Initialized to IW = min(4*MSS, max(2*MSS, 4380)).
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    ///
    /// When cwnd < ssthresh: slow start (exponential growth).
    /// When cwnd >= ssthresh: congestion avoidance (linear growth).
    pub ssthresh: u32,
    /// Duplicate ACK counter for fast retransmit detection.
    ///
    /// Incremented on each duplicate ACK; reset on new data ACK.
    /// Fast retransmit triggered when dup_ack_count reaches 3.
    pub dup_ack_count: u8,
    /// Current congestion control state.
    pub congestion_state: TcpCongestionState,
    /// R55-1: Recovery point for NewReno partial ACK handling.
    ///
    /// Set to snd_nxt when entering fast recovery. A full ACK (ack >= recover)
    /// exits fast recovery; a partial ACK (ack < recover) triggers retransmit
    /// of the next unacked segment while staying in fast recovery.
    pub recover: u32,

    // === Receive Sequence Space ===
    /// Initial Receive Sequence Number
    pub irs: u32,
    /// Receive Next - next sequence number expected
    pub rcv_nxt: u32,
    /// Receive Window - receive window size
    pub rcv_wnd: u32,

    // === Segment Size ===
    /// Maximum Segment Size for sending
    pub snd_mss: u16,
    /// Maximum Segment Size for receiving
    pub rcv_mss: u16,

    // === Window Scaling (RFC 7323) ===
    /// Send window scale factor (shift count for peer's advertised window).
    /// Applied when decoding peer's window advertisements.
    pub snd_wscale: u8,
    /// Receive window scale factor (shift count for our advertised window).
    /// Applied when encoding our window advertisements.
    pub rcv_wscale: u8,
    /// True if we sent Window Scale option in our SYN/SYN-ACK.
    pub wscale_requested: bool,
    /// True if peer sent Window Scale option in their SYN/SYN-ACK.
    pub wscale_received: bool,

    // === Retransmission State ===
    /// Current retransmission timeout in milliseconds
    pub rto_ms: u64,
    /// Smoothed Round-Trip Time (SRTT) in microseconds
    pub srtt_us: u64,
    /// RTT variance (RTTVAR) in microseconds
    pub rttvar_us: u64,
    /// Number of consecutive retransmissions
    pub retries: u8,

    // === Buffers ===
    /// Send buffer (unacknowledged segments)
    pub send_buffer: VecDeque<TcpSegment>,
    /// Receive buffer (in-order data)
    pub recv_buffer: VecDeque<u8>,
    /// Out-of-order segments
    pub ooo_queue: VecDeque<TcpSegment>,

    // === Flags ===
    /// FIN has been sent
    pub fin_sent: bool,
    /// Timestamp when FIN was last sent (for retransmission timer)
    pub fin_sent_time: u64,
    /// FIN retransmission counter
    pub fin_retries: u8,
    /// FIN has been received
    pub fin_received: bool,
    /// ACK is pending (delayed ACK)
    pub ack_pending: bool,

    // === Timestamps ===
    /// Connection established timestamp (for TIME-WAIT)
    pub established_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// TIME_WAIT start timestamp (for 2MSL timer)
    pub time_wait_start: u64,
    /// R65-5 FIX: FIN_WAIT_2 start timestamp (for idle timeout)
    pub fin_wait2_start: u64,
}

/// A TCP segment for buffering
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// Sequence number of first byte
    pub seq: u32,
    /// Segment data
    pub data: Vec<u8>,
    /// Timestamp when segment was sent (for RTT)
    pub sent_at: u64,
    /// Number of times retransmitted
    pub retrans_count: u8,
}

impl TcpControlBlock {
    /// Create a new TCB for an outgoing connection (client)
    pub fn new_client(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
    ) -> Self {
        Self {
            state: TcpState::Closed,
            key: TcpConnKey::new(local_ip, local_port, remote_ip, remote_port),
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            cwnd: initial_cwnd(TCP_DEFAULT_MSS),
            ssthresh: TCP_INITIAL_SSTHRESH,
            dup_ack_count: 0,
            congestion_state: TcpCongestionState::SlowStart,
            recover: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: TCP_DEFAULT_RCV_WINDOW_BYTES,
            snd_mss: TCP_DEFAULT_MSS,
            rcv_mss: TCP_ETHERNET_MSS,
            snd_wscale: 0,
            rcv_wscale: 0,
            wscale_requested: false,
            wscale_received: false,
            rto_ms: TCP_INITIAL_RTO_MS,
            srtt_us: 0,
            rttvar_us: 0,
            retries: 0,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            ooo_queue: VecDeque::new(),
            fin_sent: false,
            fin_sent_time: 0,
            fin_retries: 0,
            fin_received: false,
            ack_pending: false,
            established_at: 0,
            last_activity: 0,
            time_wait_start: 0,
            fin_wait2_start: 0,
        }
    }

    /// Create a new TCB for an incoming connection (server)
    pub fn new_server(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        iss: u32,
        irs: u32,
    ) -> Self {
        let mut tcb = Self::new_client(local_ip, local_port, remote_ip, remote_port, iss);
        tcb.irs = irs;
        tcb.rcv_nxt = irs.wrapping_add(1);
        tcb.state = TcpState::SynReceived;
        tcb
    }

    /// Create a TCB for a listening socket without a peer.
    ///
    /// R51-1: Used for TCP passive open (listen/accept).
    pub fn new_listen(local_ip: Ipv4Addr, local_port: u16) -> Self {
        let mut tcb = Self::new_client(local_ip, local_port, Ipv4Addr([0, 0, 0, 0]), 0, 0);
        tcb.state = TcpState::Listen;
        tcb
    }

    /// Check if there is unsent or unacknowledged data
    pub fn has_pending_data(&self) -> bool {
        !self.send_buffer.is_empty() || self.snd_una != self.snd_nxt
    }

    /// Bytes currently in flight (unacknowledged data).
    ///
    /// FlightSize = snd_nxt - snd_una
    #[inline]
    pub fn bytes_in_flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// Get the amount of data available to read
    pub fn available_data(&self) -> usize {
        self.recv_buffer.len()
    }

    /// Calculate available send window respecting both peer window and cwnd.
    ///
    /// The effective send window is min(snd_wnd, cwnd) - bytes_in_flight.
    /// This ensures congestion control limits sending even when the peer
    /// advertises a large window.
    pub fn send_window_available(&self) -> u32 {
        let bytes_in_flight = self.bytes_in_flight();
        // Effective window is minimum of peer's advertised window and cwnd
        // Ensure cwnd is at least 1 MSS to allow progress
        let effective_wnd = core::cmp::min(self.snd_wnd, self.cwnd.max(self.snd_mss as u32));
        effective_wnd.saturating_sub(bytes_in_flight)
    }

    /// Check if window scaling is enabled for this connection.
    ///
    /// Window scaling is only active if both sides exchanged WSopt during handshake.
    #[inline]
    pub fn wscale_enabled(&self) -> bool {
        self.wscale_requested && self.wscale_received
    }

    /// Get effective send window scale (0 if scaling not enabled).
    #[inline]
    pub fn effective_snd_wscale(&self) -> u8 {
        if self.wscale_enabled() {
            self.snd_wscale
        } else {
            0
        }
    }

    /// Get effective receive window scale (0 if scaling not enabled).
    #[inline]
    pub fn effective_rcv_wscale(&self) -> u8 {
        if self.wscale_enabled() {
            self.rcv_wscale
        } else {
            0
        }
    }
}

// ============================================================================
// Window Scaling Functions (RFC 7323)
// ============================================================================

/// Calculate the window scale factor needed for a desired window size.
///
/// Returns the minimum shift count (0-14) that allows advertising the desired
/// window within the 16-bit window field.
///
/// # Arguments
///
/// * `desired_wnd` - Desired receive window size in bytes
///
/// # Returns
///
/// Window scale shift count (0-14)
pub fn calc_wscale(desired_wnd: u32) -> u8 {
    if desired_wnd <= u16::MAX as u32 {
        return 0;
    }
    // Find minimum shift to fit desired_wnd in 16 bits
    // desired_wnd >> shift <= 65535
    for shift in 1..=TCP_MAX_WINDOW_SCALE {
        if desired_wnd >> shift <= u16::MAX as u32 {
            return shift;
        }
    }
    TCP_MAX_WINDOW_SCALE
}

/// Decode a received window value using the peer's window scale.
///
/// Applies the scale factor and caps at TCP_MAX_SCALED_WINDOW to prevent
/// overflow and unreasonable window sizes.
///
/// # Arguments
///
/// * `raw` - Raw window value from TCP header (16-bit)
/// * `scale` - Window scale shift count (0-14)
///
/// # Returns
///
/// Scaled window size in bytes
#[inline]
pub fn decode_window(raw: u16, scale: u8) -> u32 {
    let shift = scale.min(TCP_MAX_WINDOW_SCALE);
    // Shift is clamped to 14, raw is 16-bit, so max result is 65535 << 14 = ~1GB
    // which fits in u32 without overflow
    let scaled = (raw as u32) << shift;
    scaled.min(TCP_MAX_SCALED_WINDOW)
}

/// Encode a window value for transmission using our window scale.
///
/// Divides the available window by the scale factor for transmission in
/// the 16-bit window field. If avoid_zero is true and the result would be
/// zero but we have some window available, returns 1 to avoid advertising
/// a zero window incorrectly.
///
/// # Arguments
///
/// * `avail` - Available receive window in bytes
/// * `scale` - Window scale shift count (0-14)
/// * `avoid_zero` - If true, return at least 1 when avail > 0
///
/// # Returns
///
/// Encoded window value for TCP header (16-bit)
#[inline]
pub fn encode_window(avail: u32, scale: u8, avoid_zero: bool) -> u16 {
    let shift = scale.min(TCP_MAX_WINDOW_SCALE);
    let mut w = avail >> shift;
    // Avoid advertising zero window when we have some space
    if avoid_zero && w == 0 && avail > 0 {
        w = 1;
    }
    w.min(u16::MAX as u32) as u16
}

// ============================================================================
// RTT Estimation and Retransmission (RFC 6298)
// ============================================================================

/// Clock granularity (G) in microseconds for RTO calculation.
/// RFC 6298 recommends 100ms or finer; we use 100ms.
const RTO_CLOCK_GRANULARITY_US: u64 = 100_000;

/// Smoothing factor alpha = 1/8 for SRTT calculation.
const RTT_ALPHA_NUM: u64 = 1;
const RTT_ALPHA_DEN: u64 = 8;

/// Variance factor beta = 1/4 for RTTVAR calculation.
const RTT_BETA_NUM: u64 = 1;
const RTT_BETA_DEN: u64 = 4;

/// Multiplier K = 4 for RTO variance term.
const RTT_K: u64 = 4;

/// Update RTT estimates and compute RTO per RFC 6298.
///
/// This function implements the standard TCP RTT estimation algorithm:
/// - First sample: SRTT = R, RTTVAR = R/2
/// - Subsequent:   RTTVAR = (1-β)×RTTVAR + β×|SRTT - R|
///                 SRTT = (1-α)×SRTT + α×R
/// - RTO = SRTT + max(G, K×RTTVAR)
///
/// Where α = 1/8, β = 1/4, K = 4, G = 100ms
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `sample_us` - RTT sample in microseconds
///
/// # Security
///
/// - RTO is clamped to [TCP_MIN_RTO_MS, TCP_MAX_RTO_MS] to prevent
///   both too-aggressive retransmission and unbounded delays.
pub fn update_rtt(tcb: &mut TcpControlBlock, sample_us: u64) {
    // Reject zero or unreasonably large samples (> 10 minutes)
    if sample_us == 0 || sample_us > 600_000_000 {
        return;
    }

    if tcb.srtt_us == 0 {
        // First RTT measurement (RFC 6298 Section 2.2)
        tcb.srtt_us = sample_us;
        tcb.rttvar_us = sample_us / 2;
    } else {
        // Subsequent measurements (RFC 6298 Section 2.3)
        let srtt = tcb.srtt_us;
        let rttvar = tcb.rttvar_us;

        // Compute absolute RTT error: |SRTT - R|
        let rtt_err = if srtt > sample_us {
            srtt - sample_us
        } else {
            sample_us - srtt
        };

        // RTTVAR = (1 - β)×RTTVAR + β×|SRTT - R|
        // Using integer arithmetic: (3×RTTVAR + error) / 4
        tcb.rttvar_us =
            ((RTT_BETA_DEN - RTT_BETA_NUM) * rttvar + RTT_BETA_NUM * rtt_err) / RTT_BETA_DEN;

        // SRTT = (1 - α)×SRTT + α×R
        // Using integer arithmetic: (7×SRTT + sample) / 8
        tcb.srtt_us =
            ((RTT_ALPHA_DEN - RTT_ALPHA_NUM) * srtt + RTT_ALPHA_NUM * sample_us) / RTT_ALPHA_DEN;
    }

    // RTO = SRTT + max(G, K×RTTVAR)
    let variance_term = RTT_K.saturating_mul(tcb.rttvar_us);
    let rto_us = tcb
        .srtt_us
        .saturating_add(core::cmp::max(RTO_CLOCK_GRANULARITY_US, variance_term));

    // Convert to milliseconds and clamp to valid range
    let rto_ms = (rto_us / 1000).clamp(TCP_MIN_RTO_MS, TCP_MAX_RTO_MS);
    tcb.rto_ms = rto_ms;
}

/// Process incoming ACK: advance snd_una, clean send buffer, sample RTT.
///
/// This function implements ACK processing per RFC 793 with RFC 6298
/// RTT sampling (Karn's algorithm - don't sample retransmitted segments).
///
/// Returns `AckUpdate` for congestion control decisions.
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `ack_num` - ACK number from incoming segment
/// * `now_ms` - Current monotonic time in milliseconds
///
/// # Effects
///
/// - Removes fully acknowledged segments from send_buffer
/// - Samples RTT from first non-retransmitted acknowledged segment
/// - Updates snd_una to new acknowledgment point
/// - Resets retries counter on progress (new ACK)
///
/// # Security
///
/// - Uses seq_gt() for wraparound-safe sequence comparison
/// - Karn's algorithm prevents RTT corruption from retransmissions
pub fn handle_ack(tcb: &mut TcpControlBlock, ack_num: u32, now_ms: u64) -> AckUpdate {
    let mut update = AckUpdate::default();

    if seq_gt(ack_num, tcb.snd_una) {
        // New ACK - advances the acknowledgment point
        update.newly_acked = ack_num.wrapping_sub(tcb.snd_una);

        let mut rtt_sampled = false;

        // Remove fully acknowledged segments from send buffer
        while let Some(seg) = tcb.send_buffer.front() {
            // Segment end sequence = seq + data.len()
            let end_seq = seg.seq.wrapping_add(seg.data.len() as u32);

            // Check if entire segment is acknowledged (ack_num >= end_seq)
            if !seq_ge(ack_num, end_seq) {
                // This segment is not fully acknowledged yet
                break;
            }

            // Pop the acknowledged segment
            let seg = tcb.send_buffer.pop_front().unwrap();

            // Karn's algorithm: only sample RTT from non-retransmitted segments
            // This prevents RTT estimate corruption from ambiguous RTT samples
            if !rtt_sampled && seg.retrans_count == 0 {
                let rtt_ms = now_ms.saturating_sub(seg.sent_at);
                // Convert to microseconds (cap to prevent overflow)
                let rtt_us = rtt_ms.saturating_mul(1000);
                update_rtt(tcb, rtt_us);
                rtt_sampled = true;
            }
        }

        // Update send unacknowledged pointer
        tcb.snd_una = ack_num;

        // Reset consecutive retransmission counter on progress
        tcb.retries = 0;
    } else if ack_num == tcb.snd_una {
        // Duplicate ACK - same ACK number as before
        update.duplicate = true;
    }

    update
}

// ============================================================================
// Congestion Control (RFC 5681)
// ============================================================================

/// Update congestion control state per RFC 5681.
///
/// Called after ACK processing to adjust cwnd and detect fast retransmit.
///
/// # Arguments
///
/// * `tcb` - TCP control block to update
/// * `acked_bytes` - Number of newly acknowledged bytes (0 for duplicate ACK)
/// * `duplicate_ack` - True if this was a duplicate ACK
///
/// # Returns
///
/// `CongestionAction::FastRetransmit` if 3 duplicate ACKs detected,
/// otherwise `CongestionAction::None`.
///
/// # Algorithm
///
/// **Slow Start** (cwnd < ssthresh):
/// - cwnd += min(N, SMSS) where N is newly acked bytes
///
/// **Congestion Avoidance** (cwnd >= ssthresh):
/// - cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT)
///
/// **Fast Recovery** (RFC 5681 Section 3.2 + NewReno):
/// - On 3rd duplicate ACK: ssthresh = max(FlightSize/2, 2*SMSS)
/// - cwnd = ssthresh + 3*SMSS, trigger fast retransmit
/// - On each additional duplicate ACK: cwnd += SMSS
/// - R55-1: On partial ACK (ack < recover): stay in FR, retransmit next
/// - On full ACK (ack >= recover): exit fast recovery, cwnd = ssthresh
pub fn update_congestion_control(
    tcb: &mut TcpControlBlock,
    acked_bytes: u32,
    duplicate_ack: bool,
    ack_num: u32,
) -> CongestionAction {
    if acked_bytes > 0 {
        // New data acknowledged - reset duplicate ACK counter
        tcb.dup_ack_count = 0;

        let mss = tcb.snd_mss as u32;

        match tcb.congestion_state {
            TcpCongestionState::SlowStart => {
                // Slow start: exponential growth
                // cwnd += min(N, SMSS) for each ACK
                let growth = core::cmp::min(acked_bytes, mss).max(1);
                tcb.cwnd = tcb.cwnd.saturating_add(growth);

                // Transition to congestion avoidance when cwnd >= ssthresh
                if tcb.cwnd >= tcb.ssthresh {
                    tcb.congestion_state = TcpCongestionState::CongestionAvoidance;
                }
            }
            TcpCongestionState::CongestionAvoidance => {
                // RFC 5681: Congestion avoidance - linear growth
                // cwnd += SMSS * SMSS / cwnd (approximately 1 MSS per RTT)
                let increment = mss.saturating_mul(mss).saturating_div(tcb.cwnd.max(1));
                tcb.cwnd = tcb.cwnd.saturating_add(increment.max(1));
            }
            TcpCongestionState::FastRecovery => {
                // R55-1: NewReno partial ACK handling
                if seq_ge(ack_num, tcb.recover) {
                    // Full ACK: all data sent before entering FR is acknowledged
                    // Exit fast recovery and deflate cwnd
                    tcb.cwnd = tcb.ssthresh.max(mss);
                    tcb.congestion_state = TcpCongestionState::CongestionAvoidance;
                    return CongestionAction::None;
                } else {
                    // Partial ACK: some but not all FR data acknowledged
                    // Stay in fast recovery, deflate cwnd, retransmit next
                    // cwnd = ssthresh + 3*MSS - acked_bytes (deflate for acked data)
                    tcb.cwnd = tcb
                        .ssthresh
                        .saturating_add(3 * mss)
                        .saturating_sub(acked_bytes)
                        .max(mss);
                    return CongestionAction::RetransmitNext;
                }
            }
        }

        return CongestionAction::None;
    }

    // Handle duplicate ACKs
    if duplicate_ack {
        tcb.dup_ack_count = tcb.dup_ack_count.saturating_add(1);
        let mss = tcb.snd_mss as u32;

        // R55-2 FIX: Only enter fast recovery if not already in it (RFC 6582).
        // After a partial ACK, dup_ack_count resets to 0, so subsequent dup ACKs
        // would hit this branch again. The state check prevents re-cutting ssthresh.
        if tcb.congestion_state != TcpCongestionState::FastRecovery {
            // R56-1: RFC 3042 Limited Transmit on first/second duplicate ACK.
            //
            // For small-window connections that may never accumulate 3 dup ACKs,
            // send new data on the first two dup ACKs if:
            //   FlightSize + SMSS <= cwnd + 2*SMSS
            //
            // This helps generate additional ACKs to reach the fast retransmit
            // threshold without waiting for RTO.
            if tcb.dup_ack_count <= 2 {
                let flight = tcb.bytes_in_flight();
                // Check: can we send one more MSS under RFC 3042 allowance?
                if flight.saturating_add(mss) <= tcb.cwnd.saturating_add(2 * mss) {
                    return CongestionAction::LimitedTransmit;
                }
            }

            if tcb.dup_ack_count == 3 {
                // Triple duplicate ACK - enter fast retransmit/recovery
                // RFC 5681 Section 3.2: ssthresh = max(FlightSize/2, 2*SMSS)
                let flight = tcb.bytes_in_flight().max(mss);
                tcb.ssthresh = core::cmp::max(flight / 2, 2 * mss);

                // cwnd = ssthresh + 3*SMSS (account for segments that triggered dup ACKs)
                tcb.cwnd = tcb.ssthresh.saturating_add(3 * mss);
                tcb.congestion_state = TcpCongestionState::FastRecovery;

                // R55-1: Set recovery point for NewReno partial ACK detection
                tcb.recover = tcb.snd_nxt;

                return CongestionAction::FastRetransmit;
            }
        }

        // R55-3 FIX: Window inflation on any dup ACK during fast recovery (RFC 6582).
        // Changed from dup_ack_count > 3 to > 0 so dup ACKs after partial ACK
        // (when dup_ack_count restarts from 0) still inflate cwnd to keep pipe full.
        if tcb.congestion_state == TcpCongestionState::FastRecovery && tcb.dup_ack_count > 0 {
            tcb.cwnd = tcb.cwnd.saturating_add(mss);
        }
    }

    CongestionAction::None
}

/// Handle retransmission timeout - enter loss recovery (RFC 5681 Section 3.1).
///
/// Called when RTO expires and a segment is retransmitted.
///
/// # Effects
///
/// - ssthresh = max(FlightSize/2, 2*SMSS)
/// - cwnd = 1*SMSS (back to slow start)
/// - congestion_state = SlowStart
/// - dup_ack_count = 0
/// - recover = snd_nxt (R55-1: reset recovery point)
pub fn handle_retransmission_timeout(tcb: &mut TcpControlBlock) {
    let flight = tcb.bytes_in_flight().max(tcb.snd_mss as u32);
    tcb.ssthresh = core::cmp::max(flight / 2, 2 * tcb.snd_mss as u32);
    tcb.cwnd = tcb.snd_mss as u32; // Back to 1 SMSS
    tcb.congestion_state = TcpCongestionState::SlowStart;
    tcb.recover = tcb.snd_nxt; // R55-1: Reset recovery point
    tcb.dup_ack_count = 0;
}

/// R57-1: RFC 2861 idle cwnd validation to prevent stale bursts.
///
/// A TCP connection is considered "idle" when no data is in flight and no
/// data has been sent for at least one RTO period. After idle periods, cwnd
/// may no longer reflect current network conditions, so we reduce it to avoid
/// congestion bursts.
///
/// # Algorithm
///
/// - After first idle RTO: cap cwnd at initial window (IW)
/// - For each additional idle RTO: halve cwnd until ssthresh floor
/// - If cwnd falls to or below ssthresh, re-enter slow start
///
/// # Arguments
///
/// * `tcb` - TCP control block to validate
/// * `now_ms` - Current monotonic time in milliseconds
///
/// # Security
///
/// Prevents connections from bursting with a stale (potentially large) cwnd
/// after being idle, which could cause network congestion or self-induced
/// packet loss.
#[inline]
pub fn validate_cwnd_after_idle(tcb: &mut TcpControlBlock, now_ms: u64) {
    // Skip if no activity recorded yet or invalid RTO
    if tcb.last_activity == 0 || tcb.rto_ms == 0 {
        return;
    }

    // RFC 2861: Not idle if there is still outstanding data in flight
    if tcb.bytes_in_flight() > 0 {
        return;
    }

    let idle_ms = now_ms.saturating_sub(tcb.last_activity);
    if idle_ms < tcb.rto_ms {
        // Not idle yet - no adjustment needed
        return;
    }

    let iw = initial_cwnd(tcb.snd_mss);
    let idle_rtos = idle_ms / tcb.rto_ms;

    // First idle RTO: collapse inflated cwnd to initial window
    let mut new_cwnd = core::cmp::min(tcb.cwnd, iw);

    // Additional RTOs: exponential decay toward ssthresh floor
    if idle_rtos > 1 && new_cwnd > tcb.ssthresh {
        let floor = core::cmp::max(tcb.ssthresh, tcb.snd_mss as u32).max(1);
        for _ in 1..idle_rtos {
            if new_cwnd <= floor {
                break;
            }
            new_cwnd = new_cwnd.saturating_div(2).max(floor);
        }
    }

    // Apply reduction if cwnd decreased
    if new_cwnd < tcb.cwnd {
        tcb.cwnd = new_cwnd;
        // Re-enter slow start if cwnd fell to or below ssthresh
        if tcb.cwnd <= tcb.ssthresh {
            tcb.congestion_state = TcpCongestionState::SlowStart;
        }
    }
}

// ============================================================================
// TCP Errors
// ============================================================================

/// Errors that can occur during TCP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// Packet is too short
    Truncated,
    /// Invalid header length (data offset)
    InvalidHeaderLen,
    /// Invalid flags combination
    InvalidFlags,
    /// Checksum verification failed
    BadChecksum,
    /// Connection refused (RST received)
    ConnectionRefused,
    /// Connection reset by peer
    ConnectionReset,
    /// Connection timed out
    Timeout,
    /// Invalid state for operation
    InvalidState,
    /// No route to host
    NoRoute,
    /// Address already in use
    AddressInUse,
    /// Connection already exists
    ConnectionExists,
    /// Not connected
    NotConnected,
    /// Resource temporarily unavailable
    WouldBlock,
    /// Invalid sequence number
    InvalidSeq,
}

/// Result type for TCP operations
pub type TcpResult<T> = Result<T, TcpError>;

// ============================================================================
// TCP Statistics
// ============================================================================

/// TCP stack statistics
#[derive(Debug, Default)]
pub struct TcpStats {
    /// Total segments received
    pub rx_segments: AtomicU64,
    /// Total segments sent
    pub tx_segments: AtomicU64,
    /// Segments dropped (invalid)
    pub rx_dropped: AtomicU64,
    /// Checksum errors
    pub checksum_errors: AtomicU64,
    /// Connections established
    pub connections_established: AtomicU64,
    /// Connections reset
    pub connections_reset: AtomicU64,
    /// Retransmissions
    pub retransmissions: AtomicU64,
    /// Segments received out of order
    pub out_of_order: AtomicU64,
}

impl TcpStats {
    /// Create new statistics
    pub const fn new() -> Self {
        Self {
            rx_segments: AtomicU64::new(0),
            tx_segments: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            checksum_errors: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_reset: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            out_of_order: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// TCP Parsing Functions
// ============================================================================

/// Parse TCP header from raw bytes
///
/// # Security
///
/// - Validates minimum header length
/// - Validates data offset field
/// - Does NOT verify checksum (caller must do this)
///
/// # Arguments
///
/// * `data` - Raw TCP segment bytes
///
/// # Returns
///
/// Parsed header on success
pub fn parse_tcp_header(data: &[u8]) -> TcpResult<TcpHeader> {
    // Check minimum length
    if data.len() < TCP_HEADER_MIN_LEN {
        return Err(TcpError::Truncated);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) & 0x0F;
    let reserved = data[12] & 0x0F;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    // Validate data offset (must be at least 5 = 20 bytes)
    if data_offset < 5 {
        return Err(TcpError::InvalidHeaderLen);
    }

    // Validate data offset doesn't exceed packet
    let header_len = (data_offset as usize) * 4;
    if data.len() < header_len {
        return Err(TcpError::Truncated);
    }

    // Validate reserved bits are zero (RFC 793)
    // Note: Modern TCP uses some reserved bits for ECN, so we're lenient here
    if reserved & 0x0E != 0 {
        // Only check bits 1-3, bit 0 is NS flag
        // For strict compliance, could reject here
    }

    Ok(TcpHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_ptr,
    })
}

/// Parse TCP options from header
///
/// # Arguments
///
/// * `data` - TCP segment bytes (starting from byte 0)
/// * `header` - Parsed TCP header
///
/// # Returns
///
/// Parsed options
pub fn parse_tcp_options(data: &[u8], header: &TcpHeader) -> TcpOptions {
    let mut options = TcpOptions::default();
    let header_len = header.header_len();

    if header_len <= TCP_HEADER_MIN_LEN || data.len() < header_len {
        return options;
    }

    let opts_data = &data[TCP_HEADER_MIN_LEN..header_len];
    let mut i = 0;

    while i < opts_data.len() {
        match opts_data[i] {
            0 => break,  // End of Option List
            1 => i += 1, // NOP
            2 => {
                // MSS
                if i + 4 <= opts_data.len() && opts_data[i + 1] == 4 {
                    let raw_mss = u16::from_be_bytes([opts_data[i + 2], opts_data[i + 3]]);
                    // R66-1 FIX: Clamp to RFC 879 minimum of 536 bytes to prevent
                    // tiny-MSS DoS attacks (CPU/memory amplification via micro-segments)
                    options.mss = Some(raw_mss.max(TCP_DEFAULT_MSS));
                    i += 4;
                } else {
                    break;
                }
            }
            3 => {
                // Window Scale
                if i + 3 <= opts_data.len() && opts_data[i + 1] == 3 {
                    // R66-2 FIX: RFC 7323 mandates maximum shift count of 14.
                    // Values > 14 are treated as 14 to prevent overflow in window calculations.
                    options.window_scale = Some(opts_data[i + 2].min(TCP_MAX_WINDOW_SCALE));
                    i += 3;
                } else {
                    break;
                }
            }
            4 => {
                // SACK Permitted
                if i + 2 <= opts_data.len() && opts_data[i + 1] == 2 {
                    options.sack_permitted = true;
                    i += 2;
                } else {
                    break;
                }
            }
            8 => {
                // Timestamps
                if i + 10 <= opts_data.len() && opts_data[i + 1] == 10 {
                    let ts_val = u32::from_be_bytes([
                        opts_data[i + 2],
                        opts_data[i + 3],
                        opts_data[i + 4],
                        opts_data[i + 5],
                    ]);
                    let ts_ecr = u32::from_be_bytes([
                        opts_data[i + 6],
                        opts_data[i + 7],
                        opts_data[i + 8],
                        opts_data[i + 9],
                    ]);
                    options.timestamps = Some((ts_val, ts_ecr));
                    i += 10;
                } else {
                    break;
                }
            }
            _ => {
                // R50-6 FIX: Unknown option - skip based on length field with overflow-safe math
                if i + 1 < opts_data.len() {
                    let len = opts_data[i + 1] as usize;
                    // Minimum option length is 2 (kind + length bytes)
                    if len < 2 {
                        break;
                    }
                    // Use checked_add to prevent integer overflow attacks
                    if let Some(next) = i.checked_add(len) {
                        if next <= opts_data.len() {
                            i = next;
                            continue;
                        }
                    }
                    // Overflow or out-of-bounds - stop parsing
                    break;
                } else {
                    break;
                }
            }
        }
    }

    options
}

/// Compute TCP checksum using IPv4 pseudo-header
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// TCP checksum value
pub fn compute_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    // Build pseudo-header
    let tcp_len = tcp_data.len() as u16;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.0);
    pseudo[4..8].copy_from_slice(&dst_ip.0);
    pseudo[8] = 0; // Zero
    pseudo[9] = TCP_PROTO;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    // Compute checksum over pseudo-header + TCP segment
    let mut sum: u32 = compute_checksum(&pseudo, pseudo.len()) as u32;

    // Add TCP segment
    let tcp_sum = compute_checksum(tcp_data, tcp_data.len()) as u32;
    sum = sum.wrapping_add(tcp_sum);

    // Fold and complement
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Verify TCP checksum
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// true if checksum is valid
pub fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> bool {
    compute_tcp_checksum(src_ip, dst_ip, tcp_data) == 0
}

/// Build a TCP segment with the given parameters
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq_num` - Sequence number
/// * `ack_num` - Acknowledgment number
/// * `flags` - TCP flags
/// * `window` - Window size
/// * `payload` - Segment payload
///
/// # Returns
///
/// Complete TCP segment with checksum
pub fn build_tcp_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header = TcpHeader::new(src_port, dst_port, seq_num, ack_num, flags, window);
    let mut segment = Vec::with_capacity(TCP_HEADER_MIN_LEN + payload.len());
    segment.extend_from_slice(&header.to_bytes());
    segment.extend_from_slice(payload);

    // Compute and set checksum
    let checksum = compute_tcp_checksum(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    segment
}

/// Build a TCP segment with options and correct data offset.
///
/// This function serializes TCP options, pads them to 32-bit boundary,
/// and includes them in the header. The data_offset field is set correctly
/// to reflect the actual header length (base header + options).
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq_num` - Sequence number
/// * `ack_num` - Acknowledgment number
/// * `flags` - TCP flags
/// * `window` - Window size (already scaled by caller if applicable)
/// * `options` - TCP options to include (e.g., MSS, Window Scale)
/// * `payload` - Segment payload
///
/// # Returns
///
/// Complete TCP segment with options and checksum
///
/// # Panics
///
/// Debug-asserts if options exceed maximum header length (40 bytes of options).
pub fn build_tcp_segment_with_options(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    options: &[TcpOptionKind],
    payload: &[u8],
) -> Vec<u8> {
    let options_bytes = serialize_tcp_options(options);
    let header_len = TCP_HEADER_MIN_LEN + options_bytes.len();

    // Validate header length doesn't exceed maximum (60 bytes = 15 * 4)
    debug_assert!(
        header_len <= TCP_HEADER_MAX_LEN,
        "TCP options exceed maximum header length: {} > {}",
        header_len,
        TCP_HEADER_MAX_LEN
    );

    // Create header with correct data offset
    let mut header = TcpHeader::new(src_port, dst_port, seq_num, ack_num, flags, window);
    header.data_offset = (header_len / 4) as u8;

    // Build segment: header + options + payload
    let mut segment = Vec::with_capacity(header_len + payload.len());
    segment.extend_from_slice(&header.to_bytes());
    segment.extend_from_slice(&options_bytes);
    segment.extend_from_slice(payload);

    // Compute and set checksum
    let checksum = compute_tcp_checksum(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    segment
}

// ============================================================================
// ISN Generation (RFC 6528)
// ============================================================================

/// Global ISN generator state
static ISN_COUNTER: AtomicU32 = AtomicU32::new(0);

/// R54-1 FIX: ISN secret key with auto-upgrade capability.
///
/// Initially may use a weak RDTSC-based fallback during early boot before
/// CSPRNG is seeded. Once CSPRNG is ready, the secret is transparently
/// upgraded to strong entropy on next use.
///
/// Uses AtomicU64 instead of Once<u64> to enable runtime upgrade.
static ISN_SECRET: AtomicU64 = AtomicU64::new(0);

/// R54-1 FIX: Tracks whether current ISN_SECRET is from weak entropy source.
///
/// When true, subsequent calls to isn_secret() will attempt to upgrade
/// to strong entropy from CSPRNG.
static ISN_SECRET_WEAK: AtomicBool = AtomicBool::new(true);

/// R62-3 FIX: Counter for connections established with weak ISN entropy.
/// Used for monitoring/auditing purposes.
static ISN_WEAK_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

/// Get or initialize the ISN secret key from CSPRNG.
///
/// R54-1 IMPROVEMENT: Auto-upgrades weak secret to strong once CSPRNG is ready.
///
/// # Security Design
///
/// 1. **Fast path**: If strong secret is already installed, return immediately
/// 2. **Upgrade path**: If CSPRNG is now available and current secret is weak,
///    atomically upgrade to strong entropy
/// 3. **Fallback path**: For early boot, use RDTSC-based weak secret that
///    will be upgraded later
///
/// The upgrade is transparent to callers and maintains ISN monotonicity
/// (the counter is never reset, only the secret key changes).
#[inline]
fn isn_secret() -> u64 {
    // Fast path: strong secret already installed
    let current = ISN_SECRET.load(Ordering::Acquire);
    if current != 0 && !ISN_SECRET_WEAK.load(Ordering::Relaxed) {
        return current;
    }

    // Try to install or upgrade to strong entropy from CSPRNG
    if let Ok(strong) = security::rng::random_u64() {
        let prev = ISN_SECRET.load(Ordering::Acquire);
        let is_weak = ISN_SECRET_WEAK.load(Ordering::Relaxed);

        // Upgrade if: no secret yet OR current secret is weak
        if prev == 0 || is_weak {
            if ISN_SECRET
                .compare_exchange(prev, strong, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Successfully installed strong secret
                ISN_SECRET_WEAK.store(false, Ordering::Release);
                return strong;
            }
        }

        // Another thread may have upgraded - check if strong now
        let upgraded = ISN_SECRET.load(Ordering::Acquire);
        if upgraded != 0 && !ISN_SECRET_WEAK.load(Ordering::Relaxed) {
            return upgraded;
        }
    }

    // Fallback: weak secret for early boot (will be upgraded later)
    #[cfg(target_arch = "x86_64")]
    let weak = {
        let lo: u64;
        let hi: u64;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        }
        // Mix with prime constant for better distribution of weak entropy
        let tsc = (hi << 32) | lo;
        tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let weak = 0xa5a5_5a5a_d3e4_c7d2_u64;

    // Install weak secret only if none exists; keep marked as upgradeable
    if ISN_SECRET
        .compare_exchange(0, weak, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        ISN_SECRET_WEAK.store(true, Ordering::Release);
        return weak;
    }

    // Another thread installed something - use that
    ISN_SECRET.load(Ordering::Acquire)
}

/// Generate an Initial Sequence Number (ISN) per RFC 6528
///
/// R50-1 FIX: Uses keyed hash over 4-tuple + counter for security.
/// The secret key is initialized at boot from CSPRNG entropy.
///
/// # Security
///
/// - Secret key prevents off-path ISN prediction
/// - Counter prevents ISN reuse within connection lifetime
/// - Multiple mixing rounds provide diffusion
///
/// # Arguments
///
/// * `local_ip` - Local IP address
/// * `local_port` - Local port
/// * `remote_ip` - Remote IP address
/// * `remote_port` - Remote port
///
/// # Returns
///
/// Cryptographically unpredictable ISN for the connection
pub fn generate_isn(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> u32 {
    // RFC 6528-style keyed ISN generation: ISN = F(secret, 4-tuple, counter)
    // Increment counter by 1 (not 64000) since mixing provides enough diffusion
    let counter = ISN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let secret = isn_secret();

    // R62-3 FIX: Track connections established with weak entropy for auditing
    // This allows monitoring of security posture during early boot
    if ISN_SECRET_WEAK.load(Ordering::Relaxed) {
        ISN_WEAK_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    }

    // Pack 4-tuple into 64-bit values for mixing
    let tuple_ip = u64::from_be_bytes([
        local_ip.0[0],
        local_ip.0[1],
        local_ip.0[2],
        local_ip.0[3],
        remote_ip.0[0],
        remote_ip.0[1],
        remote_ip.0[2],
        remote_ip.0[3],
    ]);
    let tuple_port = ((local_port as u64) << 48) | ((remote_port as u64) << 32) | (counter as u64);

    // SipHash-like mixing for unpredictable output
    // Multiple rounds of multiply-rotate-xor for avalanche effect
    let mut v0 = secret;
    let mut v1 = tuple_ip;

    // Round 1: Mix secret with IP tuple
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);

    // Round 2: Mix with port tuple
    v0 = v0.wrapping_add(tuple_port);
    v1 = v1.rotate_left(17);
    v0 ^= v1;
    v1 = v1.rotate_left(21);

    // Round 3: Final diffusion with golden ratio prime
    let mixed = v0.wrapping_add(v1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let final_mix = mixed.rotate_left(23);

    // Fold 64-bit result to 32-bit
    (final_mix >> 32) as u32 ^ final_mix as u32
}

// ============================================================================
// SYN Cookies (RFC 4987)
// ============================================================================
//
// SYN cookies provide SYN flood protection without allocating per-connection
// state for half-open connections. When the SYN backlog is full, we encode
// connection parameters into the ISN of the SYN-ACK:
//
// ISN Format (32 bits):
// +------------------------+-----------+------------+
// |     MAC (23 bits)      | Time (6b) | MSS (3b)   |
// +------------------------+-----------+------------+
//
// On receiving the final ACK, we validate the cookie by recomputing the MAC
// and checking the time slot hasn't expired.
//
// Limitations:
// - Window scaling information is lost (reverts to no scaling)
// - Only 8 MSS values supported (reduced precision)
// - SACK/Timestamps cannot be negotiated
//
// Security Properties:
// - CSPRNG-seeded secret rotated every 5 minutes
// - 23-bit MAC provides ~8 million possible values (brute force resistant)
// - 2-minute validity window limits replay attacks
// - Dual-secret system handles rotation gracefully

/// Decoded data from a validated SYN cookie.
///
/// Contains the recovered connection parameters for establishing the TCB.
#[derive(Debug, Clone, Copy)]
pub struct SynCookieData {
    /// Initial Sequence Number (the cookie value)
    pub iss: u32,
    /// MSS table index (0-7)
    pub mss_index: u8,
    /// Recovered MSS value from table
    pub mss: u16,
}

/// SYN cookie secret state with rotation support.
///
/// Maintains current and previous secrets for graceful rotation.
/// In-flight SYN-ACKs using the previous secret remain valid during
/// the transition period.
struct SynCookieSecrets {
    /// Current active secret for new cookies
    current: u64,
    /// Previous secret accepted during rotation grace period
    previous: u64,
    /// Timestamp of last rotation (milliseconds)
    last_rotated_ms: u64,
}

impl SynCookieSecrets {
    /// Create new secrets initialized from CSPRNG or fallback.
    fn new(now_ms: u64) -> Self {
        let key = syn_cookie_get_key();
        Self {
            current: key,
            // Initialize previous as derived from current (different value)
            previous: key.rotate_left(17) ^ 0xA5A5_A5A5_A5A5_A5A5,
            last_rotated_ms: now_ms,
        }
    }

    /// Get current and previous secrets, rotating if necessary.
    ///
    /// Rotation occurs when the secret age exceeds TCP_SYN_COOKIE_SECRET_ROTATE_MS.
    /// Both secrets are returned to allow validation of cookies generated with
    /// either the current or previous secret.
    fn get_secrets(&mut self, now_ms: u64) -> (u64, u64) {
        let elapsed = now_ms.saturating_sub(self.last_rotated_ms);
        if elapsed > TCP_SYN_COOKIE_SECRET_ROTATE_MS {
            // Rotate: current becomes previous, generate new current
            self.previous = self.current;
            self.current = syn_cookie_get_key();
            self.last_rotated_ms = now_ms;
        }
        (self.current, self.previous)
    }
}

/// Global SYN cookie secrets storage.
static SYN_COOKIE_SECRETS: Once<Mutex<SynCookieSecrets>> = Once::new();

/// Get the SYN cookie secrets state, initializing if necessary.
#[inline]
fn syn_cookie_state(now_ms: u64) -> &'static Mutex<SynCookieSecrets> {
    SYN_COOKIE_SECRETS.call_once(|| Mutex::new(SynCookieSecrets::new(now_ms)));
    SYN_COOKIE_SECRETS
        .get()
        .expect("SYN cookie secrets must be initialized")
}

/// Get a random key for SYN cookie generation.
///
/// Attempts to use CSPRNG; falls back to ISN secret if unavailable.
#[inline]
fn syn_cookie_get_key() -> u64 {
    security::rng::random_u64().unwrap_or_else(|_| isn_secret())
}

/// Parameters for SYN cookie MAC computation.
///
/// Packs the 4-tuple and encoded values for hashing.
#[derive(Clone, Copy)]
struct SynCookieMacParams {
    /// Packed local and remote IP addresses
    tuple_ip: u64,
    /// Packed local and remote ports
    tuple_ports: u64,
    /// Time slot (6 bits)
    time_slot: u8,
    /// MSS table index (3 bits)
    mss_index: u8,
}

impl SynCookieMacParams {
    /// Create MAC parameters from connection 4-tuple and encoded values.
    fn new(
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        time_slot: u8,
        mss_index: u8,
    ) -> Self {
        let tuple_ip = u64::from_be_bytes([
            local_ip.0[0],
            local_ip.0[1],
            local_ip.0[2],
            local_ip.0[3],
            remote_ip.0[0],
            remote_ip.0[1],
            remote_ip.0[2],
            remote_ip.0[3],
        ]);
        let tuple_ports = ((local_port as u64) << 48) | ((remote_port as u64) << 32);
        Self {
            tuple_ip,
            tuple_ports,
            time_slot,
            mss_index,
        }
    }
}

/// Compute SYN cookie MAC using SipHash-like mixing.
///
/// Returns a 23-bit MAC value for cookie verification.
///
/// # Security
///
/// Uses multiple rounds of multiply-rotate-xor mixing for avalanche effect.
/// The secret provides keying; the parameters provide domain separation.
#[inline]
fn syn_cookie_compute_mac(secret: u64, params: &SynCookieMacParams) -> u32 {
    // Mix secret with parameters using SipHash-like rounds
    let mut v0 = secret.rotate_left(7) ^ params.tuple_ip ^ ((params.time_slot as u64) << 24);
    let mut v1 = secret.rotate_right(11) ^ params.tuple_ports ^ ((params.mss_index as u64) << 8);

    // Round 1
    v0 = v0.wrapping_add(v1 ^ 0x9E37_79B9_7F4A_7C15).rotate_left(17);
    v1 ^= v0.rotate_right(19);

    // Round 2
    let mix = v0.wrapping_add(v1).rotate_left(23) ^ v1;

    // Fold to 23 bits
    ((mix as u32) ^ ((mix >> 32) as u32)) & TCP_SYN_COOKIE_MAC_MASK
}

/// Select the best MSS index for SYN cookie encoding.
///
/// Given a peer's offered MSS (or None for default), returns the index into
/// TCP_SYN_COOKIE_MSS_TABLE and the corresponding MSS value to advertise.
///
/// # Algorithm
///
/// Selects the largest table entry that doesn't exceed the offered MSS.
/// This ensures we don't send segments larger than the peer can handle.
///
/// # Arguments
///
/// * `offered` - The MSS value from the peer's SYN, or None if not specified
///
/// # Returns
///
/// A tuple of (table_index, mss_value) where table_index can be encoded
/// in 3 bits and mss_value is the actual MSS to use.
pub fn syn_cookie_select_mss(offered: Option<u16>) -> (u8, u16) {
    let target = offered.unwrap_or(TCP_ETHERNET_MSS);
    let mut best_index = 0usize;

    // Find the largest MSS that doesn't exceed the offered value
    for (i, &candidate) in TCP_SYN_COOKIE_MSS_TABLE.iter().enumerate() {
        if candidate <= target {
            best_index = i;
        } else {
            // Table is sorted, no need to check further
            break;
        }
    }

    (best_index as u8, TCP_SYN_COOKIE_MSS_TABLE[best_index])
}

/// Generate a SYN cookie ISN for stateless SYN-ACK.
///
/// When the SYN backlog is full, this function generates an ISN that encodes:
/// - 23 bits: MAC over (4-tuple, time_slot, mss_index, secret)
/// - 6 bits: Current time slot (4-second granularity)
/// - 3 bits: MSS index into TCP_SYN_COOKIE_MSS_TABLE
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
/// * `local_ip` - Local (server) IP address
/// * `local_port` - Local (server) port
/// * `remote_ip` - Remote (client) IP address
/// * `remote_port` - Remote (client) port
/// * `mss_index` - Index into MSS table (from syn_cookie_select_mss)
///
/// # Returns
///
/// The 32-bit ISN to use in the SYN-ACK segment.
///
/// # Security
///
/// The MAC provides authentication - only the server with the secret can
/// generate valid cookies. The time slot prevents replay attacks beyond
/// the validity window.
pub fn generate_syn_cookie_isn(
    now_ms: u64,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    mss_index: u8,
) -> u32 {
    // Compute current time slot (wrapping within 6-bit range)
    let time_slot =
        ((now_ms / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32) & TCP_SYN_COOKIE_TIME_MASK;

    // Build MAC parameters
    let params = SynCookieMacParams::new(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        time_slot as u8,
        mss_index,
    );

    // Get current secret (with rotation check)
    let (current_secret, _) = {
        let mut guard = syn_cookie_state(now_ms).lock();
        guard.get_secrets(now_ms)
    };

    // Compute MAC
    let mac = syn_cookie_compute_mac(current_secret, &params);

    // Pack into ISN: [MAC (23 bits)][Time (6 bits)][MSS (3 bits)]
    let data_bits = ((time_slot & TCP_SYN_COOKIE_TIME_MASK) << TCP_SYN_COOKIE_MSS_BITS)
        | (mss_index as u32 & TCP_SYN_COOKIE_MSS_MASK);
    (mac << (TCP_SYN_COOKIE_TIME_BITS + TCP_SYN_COOKIE_MSS_BITS)) | data_bits
}

/// Validate a SYN cookie from an incoming ACK and recover connection parameters.
///
/// When we receive an ACK completing the handshake but have no half-open
/// connection state, we attempt to validate it as a SYN cookie response.
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
/// * `cookie_isn` - The ISN we sent in the SYN-ACK (ACK number - 1)
/// * `local_ip` - Local (server) IP address
/// * `local_port` - Local (server) port
/// * `remote_ip` - Remote (client) IP address
/// * `remote_port` - Remote (client) port
///
/// # Returns
///
/// * `Some(SynCookieData)` if the cookie is valid and not expired
/// * `None` if the cookie is invalid, expired, or malformed
///
/// # Security
///
/// Validates the cookie against both current and previous secrets to handle
/// rotation gracefully. The time slot is checked against the maximum age
/// to prevent replay attacks. The MSS index is bounds-checked.
pub fn validate_syn_cookie(
    now_ms: u64,
    cookie_isn: u32,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Option<SynCookieData> {
    // Extract encoded fields from cookie
    let mss_index = (cookie_isn & TCP_SYN_COOKIE_MSS_MASK) as usize;
    if mss_index >= TCP_SYN_COOKIE_MSS_TABLE.len() {
        return None;
    }

    let time_slot = (cookie_isn >> TCP_SYN_COOKIE_MSS_BITS) & TCP_SYN_COOKIE_TIME_MASK;
    let received_mac = cookie_isn >> (TCP_SYN_COOKIE_TIME_BITS + TCP_SYN_COOKIE_MSS_BITS);

    // R62-1 FIX: Check age with wraparound protection.
    // The 6-bit time field wraps after 64 slots (256 seconds). Without this fix,
    // a cookie from slot 63 validated at slot 1 would compute age_slots = 2 after
    // masking, incorrectly passing the age check despite being ~252 seconds old.
    // We reject any age >= half the range (32 slots = 128s) to detect wrap-around.
    let now_slot =
        ((now_ms / TCP_SYN_COOKIE_TIME_GRANULARITY_MS) as u32) & TCP_SYN_COOKIE_TIME_MASK;
    let age_slots = now_slot.wrapping_sub(time_slot) & TCP_SYN_COOKIE_TIME_MASK;
    let half_range = 1u32 << (TCP_SYN_COOKIE_TIME_BITS - 1); // 32 slots = 128 seconds
    if age_slots > TCP_SYN_COOKIE_MAX_AGE_SLOTS || age_slots >= half_range {
        return None;
    }

    // Build MAC parameters
    let params = SynCookieMacParams::new(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        time_slot as u8,
        mss_index as u8,
    );

    // Get both secrets for rotation grace period
    let (current_secret, previous_secret) = {
        let mut guard = syn_cookie_state(now_ms).lock();
        guard.get_secrets(now_ms)
    };

    // Verify MAC against current secret
    let expected_mac = syn_cookie_compute_mac(current_secret, &params);
    if received_mac == expected_mac {
        return Some(SynCookieData {
            iss: cookie_isn,
            mss_index: mss_index as u8,
            mss: TCP_SYN_COOKIE_MSS_TABLE[mss_index],
        });
    }

    // Try previous secret (for rotation grace period)
    let expected_mac_prev = syn_cookie_compute_mac(previous_secret, &params);
    if received_mac == expected_mac_prev {
        return Some(SynCookieData {
            iss: cookie_isn,
            mss_index: mss_index as u8,
            mss: TCP_SYN_COOKIE_MSS_TABLE[mss_index],
        });
    }

    // Invalid cookie
    None
}

// ============================================================================
// Sequence Number Arithmetic (RFC 793 Section 3.3)
// ============================================================================

/// Check if sequence number a is less than b (with wraparound)
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Check if sequence number a is less than or equal to b (with wraparound)
#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

/// Check if sequence number a is greater than b (with wraparound)
#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Check if sequence number a is greater than or equal to b (with wraparound)
#[inline]
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Check if sequence number seq is within window [left, left+size)
#[inline]
pub fn seq_in_window(seq: u32, left: u32, size: u32) -> bool {
    let right = left.wrapping_add(size);
    if size == 0 {
        false
    } else if seq_le(left, right) {
        // No wraparound
        seq_ge(seq, left) && seq_lt(seq, right)
    } else {
        // Window wraps around
        seq_ge(seq, left) || seq_lt(seq, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_header_parsing() {
        // SYN packet
        let syn = [
            0x00, 0x50, // src port 80
            0x1F, 0x90, // dst port 8080
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, // data offset 5 (20 bytes)
            0x02, // SYN flag
            0xFF, 0xFF, // window 65535
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent ptr
        ];

        let header = parse_tcp_header(&syn).unwrap();
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 8080);
        assert_eq!(header.seq_num, 1);
        assert_eq!(header.ack_num, 0);
        assert!(header.is_syn());
        assert!(!header.is_ack());
    }

    #[test]
    fn test_seq_arithmetic() {
        // Normal case
        assert!(seq_lt(100, 200));
        assert!(seq_le(100, 100));
        assert!(seq_gt(200, 100));

        // Wraparound case
        assert!(seq_lt(0xFFFFFFFF, 0));
        assert!(seq_gt(0, 0xFFFFFFFF));
    }

    #[test]
    fn test_tcp_state() {
        assert!(!TcpState::Closed.can_send());
        assert!(TcpState::Established.can_send());
        assert!(TcpState::Established.can_receive());
        assert!(!TcpState::TimeWait.can_receive());
    }
}
