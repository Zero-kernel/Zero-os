//! IPv4 protocol layer for Zero-OS (Phase D.2)
//!
//! This module provides IPv4 packet parsing and validation with a security-first design.
//!
//! # Security Features
//! - Strict header validation (version, IHL, length)
//! - Checksum verification
//! - Source routing option rejection (LSRR, SSRR)
//! - Invalid source address rejection (broadcast, multicast)
//! - TTL validation
//!
//! # References
//! - RFC 791: Internet Protocol

/// Minimum IPv4 header length in bytes (IHL == 5)
pub const IPV4_HEADER_MIN_LEN: usize = 20;

/// Maximum IPv4 header length in bytes (IHL == 15)
pub const IPV4_HEADER_MAX_LEN: usize = 60;

// ============================================================================
// IPv4 Protocol Numbers
// ============================================================================

/// IPv4 protocol numbers (subset used by Zero-OS)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Proto {
    /// ICMP (Internet Control Message Protocol)
    Icmp = 1,
    /// TCP (Transmission Control Protocol)
    Tcp = 6,
    /// UDP (User Datagram Protocol)
    Udp = 17,
}

impl Ipv4Proto {
    /// Try to convert from raw protocol number
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            1 => Some(Ipv4Proto::Icmp),
            6 => Some(Ipv4Proto::Tcp),
            17 => Some(Ipv4Proto::Udp),
            _ => None,
        }
    }

    /// Get raw protocol number
    pub fn to_raw(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// IPv4 Address
// ============================================================================

/// IPv4 address (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    /// Create from 4 octets
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }

    /// All zeros (0.0.0.0)
    pub const UNSPECIFIED: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    /// Loopback (127.0.0.1)
    pub const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    /// Broadcast (255.255.255.255)
    pub const BROADCAST: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

    /// Check if this is a multicast address (224.0.0.0/4)
    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 0xe0
    }

    /// Check if this is the broadcast address (255.255.255.255)
    #[inline]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    /// Check if this is the unspecified address (0.0.0.0)
    #[inline]
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Check if this is a loopback address (127.0.0.0/8)
    #[inline]
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Check if this address is valid as a source address
    ///
    /// # R44-3 FIX: Strengthened source validation
    /// Invalid sources now include:
    /// - Broadcast (255.255.255.255 and directed broadcast patterns)
    /// - Multicast (224.0.0.0/4)
    /// - Unspecified (0.0.0.0)
    /// - Loopback (127.0.0.0/8) - can be spoofed from external networks
    /// - Reserved 0/8 network (except 0.0.0.0 which is handled above)
    /// - Addresses ending in .255 (potential directed broadcast)
    #[inline]
    pub fn is_valid_source(&self) -> bool {
        // Basic checks
        if self.is_broadcast() || self.is_multicast() || self.is_unspecified() {
            return false;
        }

        // R44-3 FIX: Reject loopback from external sources
        // Loopback addresses should never appear on the wire
        if self.is_loopback() {
            return false;
        }

        // R44-3 FIX: Reject 0/8 network (reserved)
        if self.0[0] == 0 {
            return false;
        }

        // R44-3 FIX: Heuristic - reject sources ending in .255
        // These are likely directed broadcast addresses. While some legitimate
        // hosts may use .255, the risk of reflection attacks outweighs this.
        // TODO: Make this subnet-aware when we have netmask configuration
        if self.0[3] == 255 {
            return false;
        }

        true
    }

    /// Get the raw bytes
    #[inline]
    pub fn octets(&self) -> [u8; 4] {
        self.0
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(bytes: [u8; 4]) -> Self {
        Ipv4Addr(bytes)
    }
}

impl From<u32> for Ipv4Addr {
    fn from(ip: u32) -> Self {
        Ipv4Addr(ip.to_be_bytes())
    }
}

// ============================================================================
// IPv4 Header
// ============================================================================

/// Parsed IPv4 header
///
/// This structure contains all parsed header fields.
/// Options are not stored directly; use the returned slice from `parse()`.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// IP version (should always be 4)
    pub version: u8,
    /// Internet Header Length (in 32-bit words, minimum 5)
    pub ihl: u8,
    /// Type of Service / DSCP + ECN
    pub dscp_ecn: u8,
    /// Total length of the IP packet (header + payload)
    pub total_len: u16,
    /// Identification for fragmentation
    pub identification: u16,
    /// Flags (3 bits) + Fragment offset (13 bits)
    pub flags_fragment: u16,
    /// Time to Live
    pub ttl: u8,
    /// Protocol number
    pub protocol: u8,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src: Ipv4Addr,
    /// Destination address
    pub dst: Ipv4Addr,
    /// Options length in bytes (header_len - 20)
    pub options_len: usize,
}

impl Ipv4Header {
    /// Get the header length in bytes
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Get the payload length in bytes
    #[inline]
    pub fn payload_len(&self) -> usize {
        (self.total_len as usize).saturating_sub(self.header_len())
    }

    /// Check if this packet has the "Don't Fragment" flag set
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.flags_fragment & 0x4000 != 0
    }

    /// Check if this packet has the "More Fragments" flag set
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.flags_fragment & 0x2000 != 0
    }

    /// Get the fragment offset (in 8-byte units)
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment & 0x1fff
    }

    /// Check if this is a fragment
    #[inline]
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.fragment_offset() != 0
    }

    /// Get the protocol as enum if known
    #[inline]
    pub fn proto(&self) -> Option<Ipv4Proto> {
        Ipv4Proto::from_raw(self.protocol)
    }
}

// ============================================================================
// IPv4 Errors
// ============================================================================

/// Errors that can occur during IPv4 parsing/validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Error {
    /// Packet is too short
    Truncated,
    /// IP version is not 4
    BadVersion,
    /// Internet Header Length is less than 5
    BadIhl,
    /// Total length field doesn't match packet size
    BadTotalLen,
    /// Header checksum is incorrect
    ChecksumMismatch,
    /// Packet contains source routing options (LSRR or SSRR)
    SourceRoutingForbidden,
    /// Source address is invalid (broadcast, multicast, etc.)
    InvalidSource,
    /// TTL is zero
    InvalidTtl,
}

// ============================================================================
// Checksum Calculation
// ============================================================================

/// Compute IPv4 header checksum.
///
/// This uses the standard Internet checksum algorithm (one's complement sum).
/// When computing over a header that includes the checksum field, the result
/// should be 0 if the checksum is valid.
///
/// # Arguments
/// * `data` - The data to checksum
/// * `len` - Number of bytes to include (will be capped to data.len())
///
/// # Returns
/// The 16-bit checksum value
pub fn compute_checksum(data: &[u8], len: usize) -> u16 {
    let capped = core::cmp::min(data.len(), len);
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < capped {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }

    // Handle odd byte
    if capped % 2 == 1 {
        sum = sum.wrapping_add((data[capped - 1] as u32) << 8);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return one's complement
    !(sum as u16)
}

/// Calculate checksum for data where checksum field is at offset
pub fn calculate_checksum_with_pseudo(pseudo_header: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum pseudo header
    for chunk in pseudo_header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Sum data
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    // Fold
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

// ============================================================================
// IPv4 Parsing
// ============================================================================

/// Parse and validate an IPv4 packet.
///
/// This function performs comprehensive validation including:
/// - Version check (must be 4)
/// - Header length validation
/// - Total length validation
/// - Checksum verification
/// - TTL check (must be > 0)
/// - Source address validation
/// - Source routing option rejection
///
/// # Arguments
/// * `packet` - Raw packet bytes
///
/// # Returns
/// On success: (header, options_slice, payload_slice)
/// On failure: Ipv4Error describing the problem
pub fn parse_ipv4(packet: &[u8]) -> Result<(Ipv4Header, &[u8], &[u8]), Ipv4Error> {
    // Check minimum length
    if packet.len() < IPV4_HEADER_MIN_LEN {
        return Err(Ipv4Error::Truncated);
    }

    // Parse version and IHL
    let version_ihl = packet[0];
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0f;

    // Version must be 4
    if version != 4 {
        return Err(Ipv4Error::BadVersion);
    }

    // IHL must be at least 5 (20 bytes)
    if ihl < 5 {
        return Err(Ipv4Error::BadIhl);
    }

    let header_len = (ihl as usize) * 4;

    // Check we have the full header
    if header_len > packet.len() {
        return Err(Ipv4Error::Truncated);
    }

    // Parse total length
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);

    // Total length should match packet (or be less for padding)
    if (total_len as usize) > packet.len() {
        return Err(Ipv4Error::Truncated);
    }
    if (total_len as usize) < header_len {
        return Err(Ipv4Error::BadTotalLen);
    }

    // Verify checksum
    let checksum = u16::from_be_bytes([packet[10], packet[11]]);
    if compute_checksum(&packet[..header_len], header_len) != 0 {
        return Err(Ipv4Error::ChecksumMismatch);
    }

    // TTL must be non-zero
    let ttl = packet[8];
    if ttl == 0 {
        return Err(Ipv4Error::InvalidTtl);
    }

    // Parse addresses
    let src = Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]);
    let dst = Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]);

    // Validate source address
    if !src.is_valid_source() {
        return Err(Ipv4Error::InvalidSource);
    }

    // Check for forbidden options
    let options_len = header_len - IPV4_HEADER_MIN_LEN;
    let options = &packet[IPV4_HEADER_MIN_LEN..header_len];
    if contains_source_routing(options) {
        return Err(Ipv4Error::SourceRoutingForbidden);
    }

    // Extract payload
    let payload = &packet[header_len..total_len as usize];

    let hdr = Ipv4Header {
        version,
        ihl,
        dscp_ecn: packet[1],
        total_len,
        identification: u16::from_be_bytes([packet[4], packet[5]]),
        flags_fragment: u16::from_be_bytes([packet[6], packet[7]]),
        ttl,
        protocol: packet[9],
        checksum,
        src,
        dst,
        options_len,
    };

    Ok((hdr, options, payload))
}

/// Check if options contain source routing (LSRR or SSRR).
///
/// Source routing options are a security risk and should be rejected.
/// - LSRR (Loose Source Route): 0x83
/// - SSRR (Strict Source Route): 0x89
fn contains_source_routing(options: &[u8]) -> bool {
    let mut i = 0;
    while i < options.len() {
        let opt = options[i];
        match opt {
            0 => break,                 // End of options list
            1 => i += 1,                // NOP (No Operation)
            0x83 | 0x89 => return true, // LSRR or SSRR - FORBIDDEN
            _ => {
                // Variable-length option
                if i + 1 >= options.len() {
                    break;
                }
                let len = options[i + 1] as usize;
                if len < 2 || i + len > options.len() {
                    break; // Malformed option
                }
                i += len;
            }
        }
    }
    false
}

// ============================================================================
// IPv4 Packet Building
// ============================================================================

/// Build an IPv4 header for transmission.
///
/// # Arguments
/// * `src` - Source address
/// * `dst` - Destination address
/// * `proto` - Protocol number
/// * `payload_len` - Length of the payload
/// * `ttl` - Time to live (default: 64)
///
/// # Returns
/// A 20-byte header with checksum calculated
pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: Ipv4Proto,
    payload_len: u16,
    ttl: u8,
) -> [u8; IPV4_HEADER_MIN_LEN] {
    let total_len = (IPV4_HEADER_MIN_LEN as u16) + payload_len;
    let mut hdr = [0u8; IPV4_HEADER_MIN_LEN];

    // Version (4) + IHL (5)
    hdr[0] = 0x45;
    // DSCP/ECN
    hdr[1] = 0;
    // Total length
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    // Identification (use 0 for now)
    hdr[4..6].copy_from_slice(&0u16.to_be_bytes());
    // Flags + Fragment offset (Don't Fragment)
    hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    // TTL
    hdr[8] = ttl;
    // Protocol
    hdr[9] = proto.to_raw();
    // Checksum placeholder
    hdr[10] = 0;
    hdr[11] = 0;
    // Source address
    hdr[12..16].copy_from_slice(&src.0);
    // Destination address
    hdr[16..20].copy_from_slice(&dst.0);

    // Calculate and fill checksum
    let checksum = compute_checksum(&hdr, IPV4_HEADER_MIN_LEN);
    hdr[10] = (checksum >> 8) as u8;
    hdr[11] = (checksum & 0xff) as u8;

    hdr
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_addr_properties() {
        assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
        assert!(Ipv4Addr::new(255, 255, 255, 255).is_broadcast());
        assert!(Ipv4Addr::new(127, 0, 0, 1).is_loopback());
        assert!(Ipv4Addr::new(0, 0, 0, 0).is_unspecified());

        assert!(!Ipv4Addr::new(192, 168, 1, 1).is_valid_source() == false);
        assert!(!Ipv4Addr::new(255, 255, 255, 255).is_valid_source());
    }

    #[test]
    fn test_checksum() {
        // Example from RFC 791
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let csum = compute_checksum(&hdr, 20);
        // With zero checksum field, this gives the correct checksum
        assert_ne!(csum, 0);
    }
}
