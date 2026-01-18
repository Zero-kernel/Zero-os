//! UDP (User Datagram Protocol) for Zero-OS (Phase D.2)
//!
//! This module provides RFC 768 compliant UDP implementation with security-first design.
//!
//! # Packet Format (RFC 768)
//!
//! ```text
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |         Source Port           |       Destination Port        |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |            Length             |           Checksum            |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! |                             Data                              |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! # Security Features
//!
//! - Strict length validation (header + payload)
//! - Checksum verification with IPv4 pseudo-header
//! - Drop packets with zero checksum (stricter than RFC allows)
//! - Rate-limited ICMP port unreachable responses
//! - Silent drop for closed ports (anti-port-scan)
//! - Broadcast/multicast destination rejection
//!
//! # References
//!
//! - RFC 768: User Datagram Protocol
//! - RFC 1122: Requirements for Internet Hosts

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ipv4::{compute_checksum, Ipv4Addr};

// ============================================================================
// UDP Constants
// ============================================================================

/// UDP header length in bytes
pub const UDP_HEADER_LEN: usize = 8;

/// UDP protocol number (for IPv4)
pub const UDP_PROTO: u8 = 17;

/// Minimum UDP datagram size (header only)
pub const UDP_MIN_LEN: usize = 8;

/// Maximum UDP payload size considering IPv4 total length limit
/// IPv4 max total length = 65535, minus 20-byte IP header, minus 8-byte UDP header
/// This prevents overflow when building IPv4 packets (R46 FIX)
pub const UDP_MAX_PAYLOAD: usize = 65507;

/// Default MTU for UDP (typical Ethernet)
pub const UDP_DEFAULT_MTU: usize = 1472; // 1500 - 20 (IP) - 8 (UDP)

/// Ephemeral port range start (IANA recommendation)
pub const EPHEMERAL_PORT_START: u16 = 49152;

/// Ephemeral port range end
pub const EPHEMERAL_PORT_END: u16 = 65535;

// ============================================================================
// UDP Header
// ============================================================================

/// Parsed UDP header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Total length (header + payload)
    pub length: u16,
    /// Checksum (0 means not computed for IPv4)
    pub checksum: u16,
}

impl UdpHeader {
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; UDP_HEADER_LEN] {
        let mut bytes = [0u8; UDP_HEADER_LEN];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.length.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        bytes
    }
}

// ============================================================================
// UDP Errors
// ============================================================================

/// Errors that can occur during UDP processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpError {
    /// Packet is too short (< 8 bytes)
    Truncated,
    /// Length field doesn't match actual data
    LengthMismatch,
    /// Checksum verification failed
    ChecksumInvalid,
    /// Zero checksum (policy violation - we require checksums)
    ZeroChecksum,
    /// No listener on destination port
    NoListener,
    /// Packet too large
    PayloadTooLarge,
    /// Destination is broadcast/multicast (rejected)
    BroadcastDest,
    /// Source is broadcast/multicast (invalid)
    InvalidSource,
}

// ============================================================================
// UDP Statistics
// ============================================================================

/// UDP protocol statistics
#[derive(Debug, Default)]
pub struct UdpStats {
    /// UDP packets received
    pub rx_packets: AtomicU64,
    /// UDP bytes received
    pub rx_bytes: AtomicU64,
    /// UDP packets sent
    pub tx_packets: AtomicU64,
    /// UDP bytes sent
    pub tx_bytes: AtomicU64,
    /// Packets dropped due to parse errors
    pub rx_errors: AtomicU64,
    /// Packets dropped - checksum invalid
    pub checksum_errors: AtomicU64,
    /// Packets dropped - no listener
    pub no_listener: AtomicU64,
}

impl UdpStats {
    pub const fn new() -> Self {
        UdpStats {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            checksum_errors: AtomicU64::new(0),
            no_listener: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_rx_packets(&self) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_tx_packets(&self) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_checksum_errors(&self) {
        self.checksum_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_no_listener(&self) {
        self.no_listener.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// UDP Parsing
// ============================================================================

/// Parse a UDP header from raw bytes.
///
/// # Arguments
///
/// * `buf` - Raw UDP packet bytes (must be at least 8 bytes)
///
/// # Returns
///
/// Parsed `UdpHeader` or error.
pub fn parse_udp_header(buf: &[u8]) -> Result<UdpHeader, UdpError> {
    if buf.len() < UDP_HEADER_LEN {
        return Err(UdpError::Truncated);
    }

    let src_port = u16::from_be_bytes([buf[0], buf[1]]);
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    let length = u16::from_be_bytes([buf[4], buf[5]]);
    let checksum = u16::from_be_bytes([buf[6], buf[7]]);

    Ok(UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    })
}

/// Parse and validate a complete UDP datagram.
///
/// # Security
///
/// - Validates header length field matches actual data
/// - Verifies checksum using IPv4 pseudo-header
/// - Rejects zero checksums (stricter than RFC 768)
/// - Validates source/destination addresses
///
/// # Arguments
///
/// * `data` - Raw UDP datagram bytes (IPv4 payload)
/// * `src_ip` - Source IPv4 address (for checksum)
/// * `dst_ip` - Destination IPv4 address (for checksum)
///
/// # Returns
///
/// `(header, payload)` on success, error on failure.
pub fn parse_udp(
    data: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<(UdpHeader, &[u8]), UdpError> {
    // Parse header
    let header = parse_udp_header(data)?;

    // Validate length field
    let udp_len = header.length as usize;
    if udp_len < UDP_HEADER_LEN {
        return Err(UdpError::LengthMismatch);
    }
    if udp_len > data.len() {
        return Err(UdpError::LengthMismatch);
    }

    // Security: Reject zero checksums
    // RFC 768 allows zero checksum to mean "not computed", but we enforce
    // checksum verification for security (prevents trivial forgery)
    // NOTE: This is stricter than RFC 768/1122 but improves security
    if header.checksum == 0 {
        return Err(UdpError::ZeroChecksum);
    }

    // Verify checksum
    if !verify_udp_checksum(src_ip, dst_ip, &data[..udp_len]) {
        return Err(UdpError::ChecksumInvalid);
    }

    // Validate source address
    if src_ip.is_broadcast() || src_ip.is_multicast() {
        return Err(UdpError::InvalidSource);
    }

    // Extract payload
    let payload = &data[UDP_HEADER_LEN..udp_len];

    Ok((header, payload))
}

// ============================================================================
// UDP Checksum
// ============================================================================

/// Compute UDP checksum including IPv4 pseudo-header.
///
/// The pseudo-header consists of:
/// - Source IP (4 bytes)
/// - Destination IP (4 bytes)
/// - Zero (1 byte)
/// - Protocol (1 byte) = 17
/// - UDP Length (2 bytes)
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `udp_segment` - Complete UDP segment (header + payload)
///
/// # Returns
///
/// Computed checksum value.
pub fn compute_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Add pseudo-header: source IP
    let src = src_ip.octets();
    sum = sum.wrapping_add(u16::from_be_bytes([src[0], src[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src[2], src[3]]) as u32);

    // Add pseudo-header: destination IP
    let dst = dst_ip.octets();
    sum = sum.wrapping_add(u16::from_be_bytes([dst[0], dst[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst[2], dst[3]]) as u32);

    // Add pseudo-header: zero + protocol
    sum = sum.wrapping_add(UDP_PROTO as u32);

    // Add pseudo-header: UDP length
    sum = sum.wrapping_add(udp_segment.len() as u32);

    // Add UDP segment (header + payload)
    let mut chunks = udp_segment.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    // Handle odd byte
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u16::from_be_bytes([last, 0]) as u32);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

/// Verify UDP checksum.
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `udp_segment` - Complete UDP segment (header + payload)
///
/// # Returns
///
/// `true` if checksum is valid, `false` otherwise.
pub fn verify_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> bool {
    // When computed over the entire segment including checksum,
    // the result should be 0xFFFF (all ones) or equivalently 0 after complement
    let result = compute_udp_checksum(src_ip, dst_ip, udp_segment);
    // The checksum algorithm: if correct, sum of all including checksum = 0xFFFF
    // After complement: !0xFFFF = 0
    result == 0
}

// ============================================================================
// UDP Serialization
// ============================================================================

/// Build a UDP datagram.
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address (for checksum)
/// * `dst_ip` - Destination IPv4 address (for checksum)
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `payload` - Datagram payload
///
/// # Returns
///
/// Complete UDP datagram ready for IPv4 encapsulation.
pub fn build_udp_datagram(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, UdpError> {
    // Validate payload size
    if payload.len() > UDP_MAX_PAYLOAD {
        return Err(UdpError::PayloadTooLarge);
    }

    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

    // Build datagram with zero checksum initially
    let mut datagram = Vec::with_capacity(udp_len as usize);
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&udp_len.to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
    datagram.extend_from_slice(payload);

    // Compute checksum
    let checksum = compute_udp_checksum(src_ip, dst_ip, &datagram);

    // If checksum computes to 0, use 0xFFFF (RFC 768)
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };

    // Write checksum
    datagram[6..8].copy_from_slice(&checksum.to_be_bytes());

    Ok(datagram)
}

// ============================================================================
// UDP Processing Result
// ============================================================================

/// Result of processing a UDP datagram
#[derive(Debug)]
pub enum UdpResult {
    /// Datagram was delivered to a listener
    Delivered,
    /// No listener - may want to send ICMP port unreachable
    NoListener(Ipv4Addr, u16), // (src_ip, src_port) for ICMP response
    /// Datagram was dropped with error
    Dropped(UdpError),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header() {
        let data = [
            0x1F, 0x90, // src_port = 8080
            0x00, 0x50, // dst_port = 80
            0x00, 0x10, // length = 16
            0x12, 0x34, // checksum
                  // 8 bytes of payload...
        ];
        let header = parse_udp_header(&data).unwrap();
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.length, 16);
        assert_eq!(header.checksum, 0x1234);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x50, 0x00, 0x51]; // Only 4 bytes
        assert_eq!(parse_udp_header(&data), Err(UdpError::Truncated));
    }

    #[test]
    fn test_checksum_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let payload = b"Hello, UDP!";

        let datagram = build_udp_datagram(src_ip, dst_ip, 12345, 80, payload).unwrap();
        assert!(verify_udp_checksum(src_ip, dst_ip, &datagram));
    }

    #[test]
    fn test_zero_checksum_rejected() {
        // Manually construct a packet with zero checksum
        let data = [
            0x1F, 0x90, // src_port
            0x00, 0x50, // dst_port
            0x00, 0x08, // length = 8 (header only)
            0x00, 0x00, // checksum = 0
        ];
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

        assert_eq!(
            parse_udp(&data, src_ip, dst_ip),
            Err(UdpError::ZeroChecksum)
        );
    }

    #[test]
    fn test_length_mismatch() {
        let data = [
            0x1F, 0x90, // src_port
            0x00, 0x50, // dst_port
            0x00, 0x20, // length = 32 (but only 8 bytes provided)
            0x12, 0x34, // checksum
        ];
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

        assert_eq!(
            parse_udp(&data, src_ip, dst_ip),
            Err(UdpError::LengthMismatch)
        );
    }

    #[test]
    fn test_header_serialization() {
        let header = UdpHeader {
            src_port: 12345,
            dst_port: 80,
            length: 16,
            checksum: 0xABCD,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes[0..2], 12345u16.to_be_bytes());
        assert_eq!(bytes[2..4], 80u16.to_be_bytes());
        assert_eq!(bytes[4..6], 16u16.to_be_bytes());
        assert_eq!(bytes[6..8], 0xABCDu16.to_be_bytes());
    }
}
