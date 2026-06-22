//! ICMPv4 protocol layer for Zero-OS (Phase D.2)
//!
//! This module provides ICMP packet parsing, validation, and echo reply
//! construction with a security-first design.
//!
//! # Security Features
//! - Strict length validation
//! - Checksum verification
//! - Rate limiting via token bucket algorithm
//! - Supported message type whitelist
//!
//! # Rate Limiting
//!
//! ICMP responses are rate-limited to prevent amplification attacks.
//! The default configuration allows 10 packets/second with a burst of 20.
//!
//! # References
//! - RFC 792: Internet Control Message Protocol

use alloc::vec::Vec;
use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ipv4::compute_checksum;

// ============================================================================
// ICMP Message Types
// ============================================================================

/// ICMP Echo Reply (ping response)
pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;

/// ICMP Destination Unreachable
pub const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;

/// ICMP Source Quench (deprecated, RFC 6633)
pub const ICMP_TYPE_SOURCE_QUENCH: u8 = 4;

/// ICMP Redirect
pub const ICMP_TYPE_REDIRECT: u8 = 5;

/// ICMP Echo Request (ping request)
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

/// ICMP Time Exceeded
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;

/// ICMP Parameter Problem
pub const ICMP_TYPE_PARAMETER_PROBLEM: u8 = 12;

// ============================================================================
// ICMP Destination Unreachable Codes
// ============================================================================

/// Network unreachable
pub const ICMP_CODE_NET_UNREACHABLE: u8 = 0;

/// Host unreachable
pub const ICMP_CODE_HOST_UNREACHABLE: u8 = 1;

/// Protocol unreachable
pub const ICMP_CODE_PROTO_UNREACHABLE: u8 = 2;

/// Port unreachable
pub const ICMP_CODE_PORT_UNREACHABLE: u8 = 3;

/// Fragmentation needed but DF set
pub const ICMP_CODE_FRAG_NEEDED: u8 = 4;

// ============================================================================
// ICMP Time Exceeded Codes
// ============================================================================

/// TTL exceeded in transit
pub const ICMP_CODE_TTL_EXCEEDED: u8 = 0;

/// Fragment reassembly time exceeded
pub const ICMP_CODE_FRAG_TIME_EXCEEDED: u8 = 1;

// ============================================================================
// Constants
// ============================================================================

/// Minimum ICMP header length (type + code + checksum + rest_of_header)
pub const ICMP_HEADER_LEN: usize = 8;

/// Maximum ICMP echo payload size (to prevent oversized packets)
/// Standard allows up to 64KB, but we limit for DoS protection
pub const ICMP_MAX_ECHO_PAYLOAD: usize = 1472; // 1500 MTU - 20 IP - 8 ICMP

// ============================================================================
// ICMP Header
// ============================================================================

/// Parsed ICMP header.
///
/// The header is 8 bytes total:
/// ```text
/// +--------+--------+----------------+
/// |  Type  |  Code  |   Checksum     |
/// +--------+--------+----------------+
/// |      Rest of Header (4 bytes)    |
/// +----------------------------------+
/// ```
///
/// The "rest of header" varies by type:
/// - Echo Request/Reply: Identifier (2 bytes) + Sequence Number (2 bytes)
/// - Dest Unreachable: Unused (4 bytes, should be 0)
/// - Time Exceeded: Unused (4 bytes, should be 0)
#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    /// Message type (see ICMP_TYPE_* constants)
    pub icmp_type: u8,
    /// Message code (meaning depends on type)
    pub code: u8,
    /// ICMP checksum over entire message
    pub checksum: u16,
    /// Rest of header (interpretation varies by type)
    pub rest_of_header: [u8; 4],
}

impl IcmpHeader {
    /// Get echo identifier (valid for echo request/reply)
    #[inline]
    pub fn echo_id(&self) -> u16 {
        u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]])
    }

    /// Get echo sequence number (valid for echo request/reply)
    #[inline]
    pub fn echo_seq(&self) -> u16 {
        u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]])
    }

    /// Check if this is an echo request
    #[inline]
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == ICMP_TYPE_ECHO_REQUEST
    }

    /// Check if this is an echo reply
    #[inline]
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == ICMP_TYPE_ECHO_REPLY
    }

    /// Check if this is an error message
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(
            self.icmp_type,
            ICMP_TYPE_DEST_UNREACHABLE | ICMP_TYPE_TIME_EXCEEDED | ICMP_TYPE_PARAMETER_PROBLEM
        )
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; ICMP_HEADER_LEN] {
        let mut bytes = [0u8; ICMP_HEADER_LEN];
        bytes[0] = self.icmp_type;
        bytes[1] = self.code;
        bytes[2] = (self.checksum >> 8) as u8;
        bytes[3] = (self.checksum & 0xff) as u8;
        bytes[4..8].copy_from_slice(&self.rest_of_header);
        bytes
    }
}

// ============================================================================
// ICMP Errors
// ============================================================================

/// Errors that can occur during ICMP parsing/building
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// Packet is too short
    Truncated,
    /// Checksum verification failed
    InvalidChecksum,
    /// Unsupported or invalid ICMP type
    InvalidType,
    /// Invalid code for the given type
    InvalidCode,
    /// Packet was dropped due to rate limiting
    RateLimited,
    /// Payload exceeds maximum allowed size
    PayloadTooLarge,
    /// Not an echo request (for reply building)
    NotEchoRequest,
}

// ============================================================================
// ICMP Parsing
// ============================================================================

/// Check if an ICMP type is supported for processing.
///
/// We only process a limited set of ICMP types for security.
#[inline]
fn is_supported_type(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_TYPE_ECHO_REQUEST
            | ICMP_TYPE_ECHO_REPLY
            | ICMP_TYPE_DEST_UNREACHABLE
            | ICMP_TYPE_TIME_EXCEEDED
            | ICMP_TYPE_PARAMETER_PROBLEM
    )
}

/// Parse and validate an ICMPv4 packet.
///
/// This function performs validation including:
/// - Minimum length check
/// - Supported type verification
/// - Checksum verification
///
/// # Arguments
/// * `packet` - Raw ICMP packet bytes (excluding IP header)
///
/// # Returns
/// On success: (header, payload_slice)
/// On failure: IcmpError describing the problem
pub fn parse_icmp(packet: &[u8]) -> Result<(IcmpHeader, &[u8]), IcmpError> {
    // Check minimum length
    if packet.len() < ICMP_HEADER_LEN {
        return Err(IcmpError::Truncated);
    }

    let icmp_type = packet[0];
    let code = packet[1];

    // Check supported type
    if !is_supported_type(icmp_type) {
        return Err(IcmpError::InvalidType);
    }

    // Verify checksum
    // When computing checksum over the entire packet including the checksum field,
    // the result should be 0 if the checksum is valid
    if compute_checksum(packet, packet.len()) != 0 {
        return Err(IcmpError::InvalidChecksum);
    }

    let checksum = u16::from_be_bytes([packet[2], packet[3]]);

    let mut rest_of_header = [0u8; 4];
    rest_of_header.copy_from_slice(&packet[4..8]);

    let header = IcmpHeader {
        icmp_type,
        code,
        checksum,
        rest_of_header,
    };

    let payload = &packet[ICMP_HEADER_LEN..];

    Ok((header, payload))
}

/// Parse ICMP without checksum validation.
///
/// Useful when you've already validated the checksum or for debugging.
pub fn parse_icmp_unchecked(packet: &[u8]) -> Result<(IcmpHeader, &[u8]), IcmpError> {
    if packet.len() < ICMP_HEADER_LEN {
        return Err(IcmpError::Truncated);
    }

    let icmp_type = packet[0];
    let code = packet[1];
    let checksum = u16::from_be_bytes([packet[2], packet[3]]);

    let mut rest_of_header = [0u8; 4];
    rest_of_header.copy_from_slice(&packet[4..8]);

    let header = IcmpHeader {
        icmp_type,
        code,
        checksum,
        rest_of_header,
    };

    let payload = &packet[ICMP_HEADER_LEN..];

    Ok((header, payload))
}

// ============================================================================
// ICMP Packet Building
// ============================================================================

/// Build an ICMP echo reply from a validated echo request packet.
///
/// This function:
/// 1. Validates the request is an echo request with code 0
/// 2. Copies the entire packet
/// 3. Changes type from 8 (request) to 0 (reply)
/// 4. Recalculates the checksum
///
/// # Security Note
///
/// **IMPORTANT**: The caller MUST validate that the source IP address is NOT:
/// - Broadcast (255.255.255.255 or subnet broadcast)
/// - Multicast (224.0.0.0/4)
/// - Unspecified (0.0.0.0)
///
/// Responding to such addresses enables Smurf attacks and ICMP amplification.
/// Use `Ipv4Addr::is_valid_source()` from the ipv4 module for validation.
///
/// # Arguments
/// * `request` - Raw ICMP echo request packet
///
/// # Returns
/// The complete ICMP echo reply packet, or error if validation fails
pub fn build_echo_reply(request: &[u8]) -> Result<Vec<u8>, IcmpError> {
    // Parse and validate the request
    let (hdr, _payload) = parse_icmp(request)?;

    // Must be an echo request
    if hdr.icmp_type != ICMP_TYPE_ECHO_REQUEST {
        return Err(IcmpError::NotEchoRequest);
    }

    // RFC 792: Echo request code MUST be 0
    // Reject requests with non-zero code to avoid propagating malformed packets
    if hdr.code != 0 {
        return Err(IcmpError::InvalidCode);
    }

    // Check payload size
    if request.len() - ICMP_HEADER_LEN > ICMP_MAX_ECHO_PAYLOAD {
        return Err(IcmpError::PayloadTooLarge);
    }

    // R164-6 FIX: Fallible allocation for echo reply copy.
    let mut reply = Vec::new();
    if reply.try_reserve_exact(request.len()).is_err() {
        return Err(IcmpError::PayloadTooLarge);
    }
    reply.extend_from_slice(request);

    // Change type to echo reply
    reply[0] = ICMP_TYPE_ECHO_REPLY;

    // Clear checksum field before recalculating
    reply[2] = 0;
    reply[3] = 0;

    // Calculate new checksum
    let checksum = compute_checksum(&reply, reply.len());
    reply[2] = (checksum >> 8) as u8;
    reply[3] = (checksum & 0xff) as u8;

    Ok(reply)
}

/// Build an ICMP destination unreachable message.
///
/// # Arguments
/// * `code` - Destination unreachable code (see ICMP_CODE_* constants)
/// * `original_ip_header` - The IP header + first 8 bytes of payload that triggered the error
///
/// # Returns
/// Complete ICMP destination unreachable packet
pub fn build_dest_unreachable(code: u8, original_ip_header: &[u8]) -> Vec<u8> {
    build_error_message(ICMP_TYPE_DEST_UNREACHABLE, code, original_ip_header)
}

/// Build an ICMP time exceeded message.
///
/// # Arguments
/// * `code` - Time exceeded code (TTL or fragment)
/// * `original_ip_header` - The IP header + first 8 bytes of payload that triggered the error
///
/// # Returns
/// Complete ICMP time exceeded packet
pub fn build_time_exceeded(code: u8, original_ip_header: &[u8]) -> Vec<u8> {
    build_error_message(ICMP_TYPE_TIME_EXCEEDED, code, original_ip_header)
}

/// Internal: build an ICMP error message.
///
/// Error messages contain:
/// - 8 byte ICMP header (type, code, checksum, unused)
/// - Original IP header + first 8 bytes of original payload
// R164-6 FIX: Fallible allocation — returns empty Vec on OOM.
fn build_error_message(icmp_type: u8, code: u8, original_data: &[u8]) -> Vec<u8> {
    let data_len = cmp::min(original_data.len(), 28);
    let mut packet = Vec::new();
    if packet
        .try_reserve_exact(ICMP_HEADER_LEN + data_len)
        .is_err()
    {
        return packet;
    }

    // Type
    packet.push(icmp_type);
    // Code
    packet.push(code);
    // Checksum placeholder
    packet.push(0);
    packet.push(0);
    // Rest of header (unused, must be 0)
    packet.extend_from_slice(&[0, 0, 0, 0]);
    // Original IP header + data
    packet.extend_from_slice(&original_data[..data_len]);

    // Calculate checksum
    let checksum = compute_checksum(&packet, packet.len());
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Token bucket rate limiter for ICMP responses.
///
/// This implements a token bucket algorithm to prevent ICMP amplification attacks.
/// Tokens are replenished at a steady rate, and each outgoing packet consumes
/// one token. When tokens are exhausted, packets are dropped.
///
/// # Thread Safety
///
/// This implementation uses atomics for thread-safe operation without locking.
/// The token consumption uses compare-exchange to ensure correctness under
/// concurrent access. The refill calculation has a benign race: if two threads
/// refill simultaneously, slightly more or fewer tokens may be added than
/// strictly necessary, but this does not compromise security (errs on the side
/// of rate limiting rather than allowing extra packets).
///
/// # Security Note
///
/// **IMPORTANT**: The caller must provide a trusted, monotonic timestamp.
/// Using untrusted or user-controllable timestamps allows attackers to:
/// - Jump time forward to instantly refill the bucket
/// - Reset rate limiting by providing timestamp 0
///
/// Always use a kernel-internal monotonic clock (e.g., TSC-based timer).
///
/// # Example
///
/// ```ignore
/// static ICMP_LIMITER: TokenBucket = TokenBucket::new_default();
///
/// fn send_icmp_reply(packet: &[u8]) -> Result<(), IcmpError> {
///     // Use trusted kernel monotonic time
///     let now = arch::tsc_to_ms(arch::rdtsc());
///     if !ICMP_LIMITER.allow(now) {
///         return Err(IcmpError::RateLimited);
///     }
///     // ... send packet
/// }
/// ```
#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u64,
    /// Current token count (atomic for thread safety)
    tokens: AtomicU64,
    /// Token replenishment rate per second
    rate_per_sec: u64,
    /// Last refill timestamp in milliseconds (atomic)
    last_refill_ms: AtomicU64,
}

/// Maximum refill window to prevent extreme time jumps (60 seconds)
const MAX_REFILL_WINDOW_MS: u64 = 60_000;

impl TokenBucket {
    /// Default steady-state rate: 10 packets per second
    pub const DEFAULT_RATE_PER_SEC: u64 = 10;

    /// Default burst allowance: 20 packets
    pub const DEFAULT_BURST: u64 = 20;

    /// Create a token bucket with custom rate and burst capacity.
    ///
    /// # Arguments
    /// * `rate_per_sec` - Token replenishment rate (packets per second)
    /// * `burst` - Maximum token capacity (burst size)
    pub const fn new(rate_per_sec: u64, burst: u64) -> Self {
        TokenBucket {
            capacity: burst,
            tokens: AtomicU64::new(burst),
            rate_per_sec,
            last_refill_ms: AtomicU64::new(0),
        }
    }

    /// Create a token bucket with default limits (10 pps, burst 20).
    pub const fn new_default() -> Self {
        Self::new(Self::DEFAULT_RATE_PER_SEC, Self::DEFAULT_BURST)
    }

    /// Try to consume one token.
    ///
    /// This should be called before sending an ICMP response.
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds (MUST be from trusted monotonic source)
    ///
    /// # Returns
    /// `true` if a token was consumed and the packet can be sent,
    /// `false` if rate limited (or if time went backwards).
    ///
    /// # R44-6 FIX: Added monotonic time enforcement and refill window capping
    pub fn allow(&self, now_ms: u64) -> bool {
        // Refill tokens based on elapsed time
        let last = self.last_refill_ms.load(Ordering::Relaxed);

        // R44-6 FIX: Enforce monotonic time - reject if time went backwards
        // This prevents manipulation via non-monotonic timestamps
        if last != 0 && now_ms < last {
            return false;
        }

        let elapsed = if last == 0 {
            // First call - initialize timestamp
            self.last_refill_ms.store(now_ms, Ordering::Relaxed);
            0
        } else {
            // R44-6 FIX: Cap the refill window to prevent extreme time jumps
            // from instantly refilling the bucket
            cmp::min(now_ms.saturating_sub(last), MAX_REFILL_WINDOW_MS)
        };

        if elapsed > 0 {
            // Calculate tokens to add (rate_per_sec * elapsed_sec)
            let added = elapsed.saturating_mul(self.rate_per_sec) / 1000;

            if added > 0 {
                // Refill tokens (capped at capacity)
                let current = self.tokens.load(Ordering::Relaxed);
                let new_tokens = cmp::min(self.capacity, current.saturating_add(added));
                self.tokens.store(new_tokens, Ordering::Relaxed);
                self.last_refill_ms.store(now_ms, Ordering::Relaxed);
            }
        }

        // Try to consume a token
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }

            // Attempt to decrement atomically
            match self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // Retry if another thread modified tokens
            }
        }
    }

    /// Get current token count (for debugging/monitoring).
    pub fn available_tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }

    /// Reset the bucket to full capacity.
    pub fn reset(&self) {
        self.tokens.store(self.capacity, Ordering::Relaxed);
        self.last_refill_ms.store(0, Ordering::Relaxed);
    }
}

// Implement Clone manually since AtomicU64 doesn't implement Clone
impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        TokenBucket {
            capacity: self.capacity,
            tokens: AtomicU64::new(self.tokens.load(Ordering::Relaxed)),
            rate_per_sec: self.rate_per_sec,
            last_refill_ms: AtomicU64::new(self.last_refill_ms.load(Ordering::Relaxed)),
        }
    }
}

// ============================================================================
// Global ICMP Rate Limiter
// ============================================================================

/// Global ICMP response rate limiter.
///
/// This should be used for all outgoing ICMP responses to prevent
/// amplification attacks.
pub static ICMP_RATE_LIMITER: TokenBucket = TokenBucket::new_default();

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_echo_request() {
        // Valid ICMP echo request
        let packet = [
            0x08, 0x00, // Type 8, Code 0
            0xf7, 0xff, // Checksum (calculated for this minimal packet)
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
        ];

        // Note: This test would need proper checksum calculation
        // Actual test should use a packet with valid checksum
    }

    #[test]
    fn test_is_supported_type() {
        assert!(is_supported_type(ICMP_TYPE_ECHO_REQUEST));
        assert!(is_supported_type(ICMP_TYPE_ECHO_REPLY));
        assert!(is_supported_type(ICMP_TYPE_DEST_UNREACHABLE));
        assert!(is_supported_type(ICMP_TYPE_TIME_EXCEEDED));
        assert!(!is_supported_type(99)); // Unknown type
    }

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10, 5);

        // Should allow up to burst capacity
        assert!(bucket.allow(0));
        assert!(bucket.allow(0));
        assert!(bucket.allow(0));
        assert!(bucket.allow(0));
        assert!(bucket.allow(0));

        // Should be rate limited now
        assert!(!bucket.allow(0));

        // After 1 second, should have 10 more tokens (capped at 5)
        assert!(bucket.allow(1000));
    }
}
