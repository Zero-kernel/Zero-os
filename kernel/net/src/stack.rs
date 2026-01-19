//! Network protocol stack for Zero-OS (Phase D.2)
//!
//! This module provides the main packet processing loop that integrates
//! all protocol layers (Ethernet, IPv4, ICMP).
//!
//! # Architecture
//!
//! ```text
//!                     +------------------+
//!                     |   NetDevice      |
//!                     | (virtio-net)     |
//!                     +--------+---------+
//!                              |
//!                     +--------v---------+
//!                     |   Ethernet       |
//!                     |   (parse/build)  |
//!                     +--------+---------+
//!                              |
//!              +---------------+---------------+
//!              |                               |
//!     +--------v---------+           +---------v--------+
//!     |     IPv4         |           |      ARP         |
//!     | (validate/route) |           |  (cache/reply)   |
//!     +--------+---------+           +------------------+
//!              |
//!     +--------v---------+
//!     |     ICMP         |
//!     |  (echo reply)    |
//!     +------------------+
//! ```
//!
//! # Security
//!
//! - All packet parsing uses strict validation
//! - ICMP responses are rate-limited
//! - Source routing is rejected
//! - Broadcast/multicast sources are rejected

use alloc::vec::Vec;
use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::arp::{process_arp, ArpCache, ArpEntryKind, ArpError, ArpResult, ArpStats};
use crate::buffer::NetBuf;
use crate::device::TxError;
use crate::ethernet::{
    build_ethernet_frame, parse_ethernet, EthAddr, EthHeader, ETHERTYPE_ARP, ETHERTYPE_IPV4,
};
use crate::firewall::{firewall_table, FirewallAction, FirewallPacket, FirewallVerdict};
use crate::fragment::{
    cleanup_expired_fragments, process_fragment as reassemble_fragment, FragmentDropReason,
};
use crate::get_device;
use crate::icmp::{
    build_dest_unreachable, build_echo_reply, parse_icmp, IcmpError, ICMP_CODE_PORT_UNREACHABLE,
    ICMP_RATE_LIMITER, ICMP_TYPE_ECHO_REQUEST,
};
use crate::ipv4::{
    build_ipv4_header, compute_checksum, parse_ipv4, Ipv4Addr, Ipv4Error, Ipv4Header, Ipv4Proto,
    IPV4_HEADER_MIN_LEN,
};
use crate::socket::socket_table;
use crate::tcp::{
    build_tcp_segment, parse_tcp_header, parse_tcp_options, verify_tcp_checksum, TcpError,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_HEADER_MIN_LEN,
};
use crate::udp::{parse_udp, UdpError, UdpResult, UdpStats};
use crate::DEFAULT_MTU;

// ============================================================================
// Statistics
// ============================================================================

/// Network stack statistics
#[derive(Debug, Default)]
pub struct NetStats {
    /// Total packets received
    pub rx_packets: AtomicU64,
    /// Packets dropped due to parsing errors
    pub rx_errors: AtomicU64,
    /// IPv4 packets received
    pub ipv4_rx: AtomicU64,
    /// ICMP packets received
    pub icmp_rx: AtomicU64,
    /// ICMP echo requests received
    pub icmp_echo_rx: AtomicU64,
    /// ICMP echo replies sent
    pub icmp_echo_tx: AtomicU64,
    /// Packets dropped by rate limiter
    pub rate_limited: AtomicU64,
    /// Packets dropped due to unsupported protocol
    pub unsupported_proto: AtomicU64,
    /// IP fragments received
    pub fragments_rx: AtomicU64,
    /// Successfully reassembled datagrams
    pub fragments_reassembled: AtomicU64,
    /// Fragments dropped (security limits, overlap, etc.)
    pub fragments_dropped: AtomicU64,
    /// ARP statistics
    pub arp_stats: ArpStats,
    /// UDP statistics
    pub udp_stats: UdpStats,
}

impl NetStats {
    /// Create new stats counter
    pub const fn new() -> Self {
        NetStats {
            rx_packets: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            ipv4_rx: AtomicU64::new(0),
            icmp_rx: AtomicU64::new(0),
            icmp_echo_rx: AtomicU64::new(0),
            icmp_echo_tx: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            unsupported_proto: AtomicU64::new(0),
            fragments_rx: AtomicU64::new(0),
            fragments_reassembled: AtomicU64::new(0),
            fragments_dropped: AtomicU64::new(0),
            arp_stats: ArpStats::new(),
            udp_stats: UdpStats::new(),
        }
    }

    #[inline]
    fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_ipv4_rx(&self) {
        self.ipv4_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_rx(&self) {
        self.icmp_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_rx(&self) {
        self.icmp_echo_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_icmp_echo_tx(&self) {
        self.icmp_echo_tx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_unsupported_proto(&self) {
        self.unsupported_proto.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_rx(&self) {
        self.fragments_rx.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_reassembled(&self) {
        self.fragments_reassembled.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragments_dropped(&self) {
        self.fragments_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Packet Processing Result
// ============================================================================

/// Result of processing an incoming packet
#[derive(Debug)]
pub enum ProcessResult {
    /// Packet was handled, no response needed
    Handled,
    /// Packet requires a response to be sent
    Reply(Vec<u8>),
    /// Packet was dropped with reason
    Dropped(DropReason),
}

/// Reason for dropping a packet
#[derive(Debug, Clone, Copy)]
pub enum DropReason {
    /// Ethernet frame parsing failed
    EthParseError,
    /// IPv4 parsing/validation failed
    Ipv4Error(Ipv4Error),
    /// ICMP parsing failed
    IcmpError(IcmpError),
    /// ARP processing error
    ArpError(ArpError),
    /// UDP processing error
    UdpError(UdpError),
    /// TCP processing error
    TcpError(TcpError),
    /// Fragment reassembly error
    FragmentError(FragmentDropReason),
    /// Unsupported EtherType
    UnsupportedEtherType,
    /// Unsupported IP protocol
    UnsupportedProtocol,
    /// Rate limited
    RateLimited,
    /// Dropped by firewall
    Firewall {
        rule_id: Option<u32>,
        rejected: bool,
    },
}

// ============================================================================
// Packet Handler
// ============================================================================

/// Process an incoming Ethernet frame.
///
/// This is the main entry point for packet processing. It:
/// 1. Parses the Ethernet header
/// 2. Validates the frame is addressed to us (unicast or broadcast)
/// 3. Routes to the appropriate protocol handler (IPv4, ARP, etc.)
/// 4. Returns any response packet that should be sent
///
/// # Security
///
/// - Only processes frames addressed to our MAC or broadcast
/// - Silently drops frames to other destinations (no error logged)
///
/// # Arguments
/// * `frame` - Raw Ethernet frame bytes
/// * `our_mac` - Our MAC address (for filtering and responses)
/// * `our_ip` - Our IP address (for filtering and responses)
/// * `arp_cache` - ARP cache for address resolution
/// * `stats` - Statistics counters
/// * `now_ms` - Current time in milliseconds (for rate limiting)
///
/// # Returns
/// `ProcessResult` indicating what action to take
pub fn process_frame(
    frame: &[u8],
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    arp_cache: &mut ArpCache,
    stats: &NetStats,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_rx_packets();

    // Parse Ethernet header
    let (eth_hdr, eth_payload) = match parse_ethernet(frame) {
        Ok(result) => result,
        Err(_) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::EthParseError);
        }
    };

    // MAC filtering: only accept frames addressed to us or broadcast
    // This prevents processing stray traffic and reflection attacks
    if eth_hdr.dst != our_mac && !eth_hdr.dst.is_broadcast() {
        // Not for us - silently drop without incrementing error counter
        return ProcessResult::Handled;
    }

    // Route to protocol handler
    match eth_hdr.ethertype {
        ETHERTYPE_IPV4 => process_ipv4(eth_payload, &eth_hdr, our_mac, our_ip, stats, now_ms),
        ETHERTYPE_ARP => {
            // Process ARP packet
            match process_arp(
                eth_payload,
                our_mac,
                our_ip,
                arp_cache,
                &stats.arp_stats,
                now_ms,
            ) {
                ArpResult::Handled => ProcessResult::Handled,
                ArpResult::Reply(frame) => ProcessResult::Reply(frame),
                ArpResult::Dropped(e) => ProcessResult::Dropped(DropReason::ArpError(e)),
            }
        }
        _ => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedEtherType)
        }
    }
}

/// Process an IPv4 packet.
fn process_ipv4(
    packet: &[u8],
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    now_ms: u64,
) -> ProcessResult {
    stats.inc_ipv4_rx();

    // Parse and validate IPv4 header first
    let (ip_hdr, _options, payload) = match parse_ipv4(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::Ipv4Error(e));
        }
    };

    // Check if packet is destined for us (unicast only for responses)
    // Security: We accept broadcast for informational purposes but will NOT
    // generate responses to broadcast destinations (Smurf attack prevention)
    let is_broadcast_dst = ip_hdr.dst.is_broadcast();
    if ip_hdr.dst != our_ip && !is_broadcast_dst {
        // Not for us, silently drop (no error)
        return ProcessResult::Handled;
    }

    // Fragment handling with secure reassembly
    // R48-6 + R60: Process fragments through reassembly cache with anti-DoS limits
    let final_payload = if ip_hdr.is_fragment() {
        stats.inc_fragments_rx();
        match reassemble_fragment(&ip_hdr, payload, now_ms) {
            Ok(Some(reassembled)) => {
                // Reassembly complete - use the reassembled payload
                stats.inc_fragments_reassembled();
                reassembled
            }
            Ok(None) => {
                // More fragments needed - handled, no response
                return ProcessResult::Handled;
            }
            Err(reason) => {
                // Fragment dropped due to security limit or error
                stats.inc_fragments_dropped();
                return ProcessResult::Dropped(DropReason::FragmentError(reason));
            }
        }
    } else {
        // Non-fragment: use payload directly
        payload.to_vec()
    };

    // Route to protocol handler
    match ip_hdr.proto() {
        Some(Ipv4Proto::Icmp) => {
            // Pass broadcast flag to ICMP handler for response suppression
            process_icmp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                our_mac,
                our_ip,
                stats,
                now_ms,
                is_broadcast_dst,
            )
        }
        Some(Ipv4Proto::Udp) => {
            // Process UDP packet
            process_udp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                stats,
                is_broadcast_dst,
                now_ms,
            )
        }
        Some(Ipv4Proto::Tcp) => {
            // Process TCP packet
            process_tcp(
                &final_payload,
                &ip_hdr,
                eth_hdr,
                stats,
                is_broadcast_dst,
                now_ms,
            )
        }
        None => {
            stats.inc_unsupported_proto();
            ProcessResult::Dropped(DropReason::UnsupportedProtocol)
        }
    }
}

/// Process a UDP datagram.
///
/// # Security
///
/// - Does NOT process datagrams sent to broadcast/multicast addresses
///   (prevents amplification attacks)
/// - Validates checksum strictly (zero checksums rejected)
/// - Validates length fields
/// - Delivers to bound sockets via socket_table()
fn process_udp(
    payload: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    stats: &NetStats,
    is_broadcast_dst: bool,
    now_ms: u64,
) -> ProcessResult {
    stats.udp_stats.inc_rx_packets();

    // Security: Reject UDP to broadcast/multicast destinations
    // This prevents amplification attacks
    if is_broadcast_dst || ip_hdr.dst.is_multicast() {
        stats.udp_stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::UdpError(UdpError::BroadcastDest));
    }

    // Parse and validate UDP datagram
    let (header, data) = match parse_udp(payload, ip_hdr.src, ip_hdr.dst) {
        Ok(result) => result,
        Err(e) => {
            match e {
                UdpError::ChecksumInvalid | UdpError::ZeroChecksum => {
                    stats.udp_stats.inc_checksum_errors();
                }
                _ => {
                    stats.udp_stats.inc_rx_errors();
                }
            }
            return ProcessResult::Dropped(DropReason::UdpError(e));
        }
    };

    // Record bytes received
    stats.udp_stats.add_rx_bytes(data.len() as u64);

    // Conntrack: Update connection tracking state (used by firewall)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_udp;
        Some(ct_process_udp(
            ip_hdr.src,
            ip_hdr.dst,
            header.src_port,
            header.dst_port,
            payload.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // Firewall: Evaluate packet against rule table
    let fw_packet = FirewallPacket {
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Udp,
        src_port: Some(header.src_port),
        dst_port: Some(header.dst_port),
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_verdict = firewall_table().evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, payload, now_ms)
    {
        return result;
    }

    // Deliver to socket layer
    if socket_table().deliver_udp(header.dst_port, ip_hdr.src, header.src_port, data, now_ms) {
        return ProcessResult::Handled;
    }

    // No listener - silently drop to avoid port scanning feedback
    // Note: We could send ICMP Port Unreachable, but that requires:
    // 1. Rate limiting (to prevent reflection attacks)
    // 2. Building the ICMP response
    // For now, silent drop is the safer default
    stats.udp_stats.inc_no_listener();
    ProcessResult::Handled
}

/// Process an ICMP packet.
///
/// # Security
///
/// - Does NOT respond to echo requests sent to broadcast/multicast IP addresses
///   (Smurf attack prevention per RFC 1122 section 3.2.2.6)
/// - Rate limits all ICMP responses
fn process_icmp(
    packet: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    our_mac: EthAddr,
    our_ip: Ipv4Addr,
    stats: &NetStats,
    now_ms: u64,
    is_broadcast_dst: bool,
) -> ProcessResult {
    stats.inc_icmp_rx();

    // Parse ICMP header
    let (icmp_hdr, _payload) = match parse_icmp(packet) {
        Ok(result) => result,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::IcmpError(e));
        }
    };

    // R64-2 FIX: Add firewall evaluation for ICMP traffic
    // ICMP uses conntrack for RELATED state (e.g., ICMP errors for tracked connections)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_icmp;
        Some(ct_process_icmp(
            ip_hdr.src,
            ip_hdr.dst,
            icmp_hdr.icmp_type,
            icmp_hdr.code,
            packet.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // Firewall: Evaluate ICMP packet against rule table
    let fw_packet = FirewallPacket {
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Icmp,
        src_port: None, // ICMP has no ports
        dst_port: None,
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_verdict = firewall_table().evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, packet, now_ms)
    {
        return result;
    }

    // Handle echo request (ping)
    if icmp_hdr.icmp_type == ICMP_TYPE_ECHO_REQUEST {
        stats.inc_icmp_echo_rx();

        // SECURITY: Never respond to echo requests sent to broadcast/multicast
        // This prevents Smurf attacks (RFC 1122 section 3.2.2.6)
        if is_broadcast_dst {
            return ProcessResult::Handled;
        }

        // Also check if destination MAC was broadcast (belt and suspenders)
        if eth_hdr.dst.is_broadcast() || eth_hdr.dst.is_multicast() {
            return ProcessResult::Handled;
        }

        // Rate limit ICMP responses
        if !ICMP_RATE_LIMITER.allow(now_ms) {
            stats.inc_rate_limited();
            return ProcessResult::Dropped(DropReason::RateLimited);
        }

        // Build ICMP echo reply
        let icmp_reply = match build_echo_reply(packet) {
            Ok(reply) => reply,
            Err(e) => {
                stats.inc_rx_errors();
                return ProcessResult::Dropped(DropReason::IcmpError(e));
            }
        };

        // Build IPv4 header (swap src/dst)
        let ip_reply = build_ipv4_header(
            our_ip,     // Our IP as source
            ip_hdr.src, // Original source as destination
            Ipv4Proto::Icmp,
            icmp_reply.len() as u16,
            64, // Default TTL
        );

        // Combine IP header and ICMP reply
        let mut ip_packet = Vec::with_capacity(ip_reply.len() + icmp_reply.len());
        ip_packet.extend_from_slice(&ip_reply);
        ip_packet.extend_from_slice(&icmp_reply);

        // Build Ethernet frame (swap src/dst MACs)
        let frame = build_ethernet_frame(
            eth_hdr.src, // Original source as destination
            our_mac,     // Our MAC as source
            ETHERTYPE_IPV4,
            &ip_packet,
        );

        stats.inc_icmp_echo_tx();
        return ProcessResult::Reply(frame);
    }

    // Other ICMP types are just handled (logged but no response)
    ProcessResult::Handled
}

/// Process a TCP segment.
///
/// # Security
///
/// - Does NOT process segments sent to broadcast/multicast addresses
///   (prevents amplification attacks)
/// - Validates checksum before processing
/// - Sends RST for unknown connections
fn process_tcp(
    payload: &[u8],
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    stats: &NetStats,
    is_broadcast_dst: bool,
    now_ms: u64,
) -> ProcessResult {
    // Security: ignore TCP to broadcast/multicast destinations
    if is_broadcast_dst || ip_hdr.dst.is_multicast() {
        stats.inc_unsupported_proto();
        return ProcessResult::Handled;
    }

    // Parse TCP header
    let tcp_hdr = match parse_tcp_header(payload) {
        Ok(h) => h,
        Err(e) => {
            stats.inc_rx_errors();
            return ProcessResult::Dropped(DropReason::TcpError(e));
        }
    };

    // Validate header length
    let hdr_len = tcp_hdr.header_len();
    if payload.len() < hdr_len || hdr_len < TCP_HEADER_MIN_LEN {
        stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::TcpError(TcpError::Truncated));
    }

    // Verify checksum
    if !verify_tcp_checksum(ip_hdr.src, ip_hdr.dst, payload) {
        stats.inc_rx_errors();
        return ProcessResult::Dropped(DropReason::TcpError(TcpError::BadChecksum));
    }

    // Extract payload (data after TCP header)
    let tcp_payload = &payload[hdr_len..];

    // Conntrack: Update connection tracking state (used by firewall)
    #[cfg(feature = "conntrack")]
    let ct_result = {
        use crate::conntrack::ct_process_tcp;
        Some(ct_process_tcp(
            ip_hdr.src,
            ip_hdr.dst,
            tcp_hdr.src_port,
            tcp_hdr.dst_port,
            tcp_hdr.flags,
            tcp_payload.len(),
            now_ms,
        ))
    };
    #[cfg(not(feature = "conntrack"))]
    let ct_result: Option<crate::conntrack::CtUpdateResult> = None;

    // Firewall: Evaluate packet against rule table
    let fw_packet = FirewallPacket {
        src_ip: ip_hdr.src,
        dst_ip: ip_hdr.dst,
        proto: Ipv4Proto::Tcp,
        src_port: Some(tcp_hdr.src_port),
        dst_port: Some(tcp_hdr.dst_port),
        ct_state: ct_result.as_ref().map(|r| r.decision),
    };
    let fw_verdict = firewall_table().evaluate(&fw_packet);
    if let Some(result) =
        apply_firewall_verdict(&fw_verdict, &fw_packet, ip_hdr, eth_hdr, payload, now_ms)
    {
        return result;
    }

    // R58: Parse TCP options for window scaling support
    // Use the full segment so parse_tcp_options can validate header_len
    let tcp_options = parse_tcp_options(payload, &tcp_hdr);

    // Delegate to socket layer for stateful TCP processing
    if let Some(resp_seg) = socket_table().process_tcp_segment(
        ip_hdr.src,
        ip_hdr.dst,
        &tcp_hdr,
        tcp_payload,
        &tcp_options,
    ) {
        // Build IPv4 header (swap src/dst)
        let ip_reply = build_ipv4_header(
            ip_hdr.dst, // Our IP as source
            ip_hdr.src, // Original source as destination
            Ipv4Proto::Tcp,
            resp_seg.len() as u16,
            64, // Default TTL
        );

        // Combine IP header and TCP segment
        let mut ip_packet = Vec::with_capacity(ip_reply.len() + resp_seg.len());
        ip_packet.extend_from_slice(&ip_reply);
        ip_packet.extend_from_slice(&resp_seg);

        // Build Ethernet frame (swap MACs)
        let frame = build_ethernet_frame(
            eth_hdr.src, // Original source as destination
            eth_hdr.dst, // Our MAC as source
            ETHERTYPE_IPV4,
            &ip_packet,
        );

        return ProcessResult::Reply(frame);
    }

    ProcessResult::Handled
}

// ============================================================================
// Outbound Transmission (TX path)
// ============================================================================

/// Default IP address for Zero-OS in QEMU user-mode networking.
const DEFAULT_OUR_IP: Ipv4Addr = Ipv4Addr([10, 0, 2, 15]);

/// Default gateway IP in QEMU user-mode networking.
const DEFAULT_GATEWAY_IP: Ipv4Addr = Ipv4Addr([10, 0, 2, 2]);

/// Default gateway MAC (QEMU's virtual router).
/// This is the standard MAC QEMU assigns to its SLIRP gateway.
const DEFAULT_GATEWAY_MAC: EthAddr = EthAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// Network configuration for TX path.
#[derive(Clone, Copy)]
struct NetConfig {
    our_ip: Ipv4Addr,
    our_mac: EthAddr,
    gateway_ip: Ipv4Addr,
    gateway_mac: EthAddr,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            our_ip: DEFAULT_OUR_IP,
            our_mac: EthAddr::ZERO,
            gateway_ip: DEFAULT_GATEWAY_IP,
            gateway_mac: DEFAULT_GATEWAY_MAC,
        }
    }
}

/// Public snapshot of network configuration.
#[derive(Clone, Copy)]
pub struct NetConfigSnapshot {
    pub our_ip: Ipv4Addr,
    pub our_mac: EthAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: EthAddr,
}

/// Global network state for TX path.
struct NetState {
    config: Mutex<NetConfig>,
    arp: Mutex<ArpCache>,
}

static NET_STATE: Once<NetState> = Once::new();

#[inline]
fn net_state() -> &'static NetState {
    NET_STATE.call_once(|| NetState {
        config: Mutex::new(NetConfig::default()),
        arp: Mutex::new(ArpCache::with_defaults()),
    })
}

/// Resolve MAC address from network device if not yet set.
fn resolve_mac_from_device(cfg: &mut NetConfig) {
    if cfg.our_mac != EthAddr::ZERO {
        return;
    }
    if let Some(dev) = get_device("eth0") {
        let mac_bytes = dev.lock().mac_address();
        cfg.our_mac = EthAddr(mac_bytes);
    }
}

/// Get a snapshot of the current network configuration.
///
/// Lazily initializes our MAC address from the network device.
pub fn network_config() -> NetConfigSnapshot {
    let state = net_state();
    let mut cfg = state.config.lock();
    resolve_mac_from_device(&mut cfg);
    NetConfigSnapshot {
        our_ip: cfg.our_ip,
        our_mac: cfg.our_mac,
        gateway_ip: cfg.gateway_ip,
        gateway_mac: cfg.gateway_mac,
    }
}

/// Resolve destination MAC address.
///
/// For now, we use the gateway MAC for all destinations.
/// A proper implementation would check if dst_ip is on the local subnet
/// and use ARP for local destinations.
fn resolve_dst_mac(dst_ip: Ipv4Addr, cfg: &NetConfigSnapshot) -> EthAddr {
    let state = net_state();
    let mut cache = state.arp.lock();

    // Static timestamp (proper implementation would use kernel time)
    let now_ms = 0;

    // Ensure gateway is always in cache
    let _ = cache.insert(
        cfg.gateway_ip,
        cfg.gateway_mac,
        ArpEntryKind::Static,
        now_ms,
    );

    // Try direct lookup first
    if let Some(mac) = cache.lookup(dst_ip, now_ms) {
        return mac;
    }

    // Fall back to gateway MAC for off-link destinations
    cfg.gateway_mac
}

/// Build complete Ethernet frame and transmit via network device.
fn build_frame_and_transmit(
    proto: Ipv4Proto,
    dst_ip: Ipv4Addr,
    payload: &[u8],
) -> Result<(), TxError> {
    if payload.is_empty() || payload.len() > DEFAULT_MTU {
        return Err(TxError::InvalidBuffer);
    }

    let cfg = network_config();
    if cfg.our_mac == EthAddr::ZERO {
        // No network device available
        return Err(TxError::LinkDown);
    }

    let dst_mac = resolve_dst_mac(dst_ip, &cfg);

    // Build IPv4 header
    let ip_hdr = build_ipv4_header(cfg.our_ip, dst_ip, proto, payload.len() as u16, 64);

    // Construct complete IP packet
    let mut ip_packet = Vec::with_capacity(ip_hdr.len() + payload.len());
    ip_packet.extend_from_slice(&ip_hdr);
    ip_packet.extend_from_slice(payload);

    // Build Ethernet frame
    let frame = build_ethernet_frame(dst_mac, cfg.our_mac, ETHERTYPE_IPV4, &ip_packet);

    // Allocate NetBuf and copy frame data
    let frame_phys = mm::buddy_allocator::alloc_physical_pages(1).ok_or(TxError::InvalidBuffer)?;

    let mut buf = match NetBuf::with_defaults(frame_phys) {
        Some(b) => b,
        None => {
            mm::buddy_allocator::free_physical_pages(frame_phys, 1);
            return Err(TxError::InvalidBuffer);
        }
    };

    let data = match buf.push_tail(frame.len()) {
        Some(d) => d,
        None => {
            // NetBuf Drop will free the frame
            return Err(TxError::InvalidBuffer);
        }
    };
    data.copy_from_slice(&frame);

    // Transmit via network device
    let dev = match get_device("eth0") {
        Some(d) => d,
        None => {
            return Err(TxError::LinkDown);
        }
    };

    let result = match dev.lock().transmit(buf) {
        Ok(()) => Ok(()),
        Err((err, _returned)) => Err(err),
    };
    result
}

/// Transmit a serialized TCP segment (without IP/Ethernet headers).
///
/// The segment should be a complete TCP header + payload as built by
/// the socket layer's tcp_send() or connect().
///
/// # Arguments
/// * `dst_ip` - Destination IP address
/// * `segment` - Complete TCP segment (header + payload)
///
/// # Returns
/// * `Ok(())` on successful transmission
/// * `Err(TxError)` on failure
pub fn transmit_tcp_segment(dst_ip: Ipv4Addr, segment: &[u8]) -> Result<(), TxError> {
    build_frame_and_transmit(Ipv4Proto::Tcp, dst_ip, segment)
}

/// Transmit a serialized UDP datagram (without IP/Ethernet headers).
///
/// The datagram should be a complete UDP header + payload as built by
/// the socket layer's send_to_udp().
///
/// # Arguments
/// * `dst_ip` - Destination IP address
/// * `datagram` - Complete UDP datagram (header + payload)
///
/// # Returns
/// * `Ok(())` on successful transmission
/// * `Err(TxError)` on failure
pub fn transmit_udp_datagram(dst_ip: Ipv4Addr, datagram: &[u8]) -> Result<(), TxError> {
    build_frame_and_transmit(Ipv4Proto::Udp, dst_ip, datagram)
}

// ============================================================================
// Firewall Helpers
// ============================================================================

/// Build original IP header snapshot for ICMP reject response.
///
/// Per RFC 792, ICMP error messages include the original IP header + first 8 bytes
/// of the original payload (L4 header).
///
/// # R64-3 NOTE: Current implementation reconstructs the IP header from parsed fields
/// rather than copying the original bytes. This means:
/// - IP options are not included (assumes IHL=5)
/// - Checksum is recalculated
///
/// A more RFC-compliant implementation would pass through the original packet slice.
/// This is acceptable for most cases but may cause issues with packets containing
/// IP options. Future improvement: pass original IP header bytes through the call chain.
fn build_original_ip_for_reject(ip_hdr: &Ipv4Header, l4_bytes: &[u8]) -> Vec<u8> {
    let quoted_len = cmp::min(l4_bytes.len(), 8);
    let mut hdr = [0u8; IPV4_HEADER_MIN_LEN];

    // Build minimal header snapshot from the parsed fields
    hdr[0] = 0x45; // Version + IHL (no options)
    hdr[1] = ip_hdr.dscp_ecn;
    let total_len = (IPV4_HEADER_MIN_LEN + quoted_len) as u16;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&ip_hdr.identification.to_be_bytes());
    hdr[6..8].copy_from_slice(&ip_hdr.flags_fragment.to_be_bytes());
    hdr[8] = ip_hdr.ttl;
    hdr[9] = ip_hdr.protocol;
    hdr[12..16].copy_from_slice(&ip_hdr.src.0);
    hdr[16..20].copy_from_slice(&ip_hdr.dst.0);
    let checksum = compute_checksum(&hdr, IPV4_HEADER_MIN_LEN);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut snapshot = Vec::with_capacity(IPV4_HEADER_MIN_LEN + quoted_len);
    snapshot.extend_from_slice(&hdr);
    if quoted_len > 0 {
        snapshot.extend_from_slice(&l4_bytes[..quoted_len]);
    }
    snapshot
}

/// Apply firewall verdict, generating response if needed.
///
/// Returns `Some(ProcessResult)` if the packet should be dropped/rejected,
/// or `None` if the packet should be accepted and processing should continue.
fn apply_firewall_verdict(
    verdict: &FirewallVerdict,
    packet: &FirewallPacket,
    ip_hdr: &Ipv4Header,
    eth_hdr: &EthHeader,
    l4_bytes: &[u8],
    now_ms: u64,
) -> Option<ProcessResult> {
    crate::firewall::log_match(verdict, packet, now_ms);

    match verdict.action {
        FirewallAction::Accept => None,
        FirewallAction::Drop => Some(ProcessResult::Dropped(DropReason::Firewall {
            rule_id: verdict.rule_id,
            rejected: false,
        })),
        FirewallAction::Reject { icmp_code } => {
            // Don't send ICMP errors to broadcast/multicast
            if ip_hdr.dst.is_broadcast() || ip_hdr.dst.is_multicast() {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }

            // R64-1 FIX: Rate limit firewall REJECT ICMP responses
            // Prevents reflection/amplification attacks
            if !ICMP_RATE_LIMITER.allow(now_ms) {
                return Some(ProcessResult::Dropped(DropReason::Firewall {
                    rule_id: verdict.rule_id,
                    rejected: true,
                }));
            }

            // R64-5 FIX: For TCP rejections, send a TCP RST per RFC 793 instead of ICMP
            // This is more appropriate for TCP as RST immediately terminates the connection
            // and is the standard response for rejected TCP traffic.
            if packet.proto == Ipv4Proto::Tcp {
                if let Ok(tcp_hdr) = parse_tcp_header(l4_bytes) {
                    let hdr_len = tcp_hdr.header_len();
                    if l4_bytes.len() >= hdr_len && hdr_len >= TCP_HEADER_MIN_LEN {
                        let tcp_payload = &l4_bytes[hdr_len..];

                        let is_ack = tcp_hdr.flags & TCP_FLAG_ACK != 0;
                        let is_syn = tcp_hdr.flags & TCP_FLAG_SYN != 0;
                        let is_fin = tcp_hdr.flags & TCP_FLAG_FIN != 0;

                        // RFC 793: If ACK was set, RST seq = incoming ACK number, no ACK flag
                        // If ACK was not set, RST seq = 0, ACK = incoming SEQ + segment length
                        let (seq_num, ack_num, flags) = if is_ack {
                            (tcp_hdr.ack_num, 0, TCP_FLAG_RST)
                        } else {
                            let mut seg_len = tcp_payload.len() as u32;
                            if is_syn {
                                seg_len = seg_len.wrapping_add(1);
                            }
                            if is_fin {
                                seg_len = seg_len.wrapping_add(1);
                            }
                            let computed_ack = tcp_hdr.seq_num.wrapping_add(seg_len);
                            (0, computed_ack, TCP_FLAG_RST | TCP_FLAG_ACK)
                        };

                        let rst_segment = build_tcp_segment(
                            ip_hdr.dst, // Our IP as source
                            ip_hdr.src, // Original source as destination
                            tcp_hdr.dst_port,
                            tcp_hdr.src_port,
                            seq_num,
                            ack_num,
                            flags,
                            0,   // Window size
                            &[], // No payload
                        );

                        let ip_reply = build_ipv4_header(
                            ip_hdr.dst,
                            ip_hdr.src,
                            Ipv4Proto::Tcp,
                            rst_segment.len() as u16,
                            64,
                        );

                        let mut ip_packet = Vec::with_capacity(ip_reply.len() + rst_segment.len());
                        ip_packet.extend_from_slice(&ip_reply);
                        ip_packet.extend_from_slice(&rst_segment);

                        let frame = build_ethernet_frame(
                            eth_hdr.src,
                            eth_hdr.dst,
                            ETHERTYPE_IPV4,
                            &ip_packet,
                        );

                        return Some(ProcessResult::Reply(frame));
                    }
                }
                // If TCP header parsing fails, fall through to ICMP response
            }

            // Build ICMP destination unreachable for non-TCP protocols
            let quoted = build_original_ip_for_reject(ip_hdr, l4_bytes);
            let icmp = build_dest_unreachable(icmp_code, &quoted);
            let ip_reply = build_ipv4_header(
                ip_hdr.dst,
                ip_hdr.src,
                Ipv4Proto::Icmp,
                icmp.len() as u16,
                64,
            );

            let mut ip_packet = Vec::with_capacity(ip_reply.len() + icmp.len());
            ip_packet.extend_from_slice(&ip_reply);
            ip_packet.extend_from_slice(&icmp);

            let frame = build_ethernet_frame(eth_hdr.src, eth_hdr.dst, ETHERTYPE_IPV4, &ip_packet);

            Some(ProcessResult::Reply(frame))
        }
    }
}

// ============================================================================
// Timer Maintenance
// ============================================================================

/// Handle periodic timer tick for network stack maintenance.
///
/// This should be called from the system timer interrupt handler (e.g., every 1 second).
/// Performs cleanup of expired fragment reassembly queues.
///
/// # Arguments
/// * `now_ms` - Current time in milliseconds
///
/// # Returns
/// Number of expired fragment queues cleaned up
pub fn handle_timer_tick(now_ms: u64) -> usize {
    cleanup_expired_fragments(now_ms)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_atomic() {
        let stats = NetStats::new();
        stats.inc_rx_packets();
        stats.inc_rx_packets();
        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 2);
    }
}
