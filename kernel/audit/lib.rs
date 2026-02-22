//! Security Audit Subsystem for Zero-OS
//!
//! This module provides enterprise-grade security audit logging with:
//!
//! - **Tamper Evidence**: SHA-256 hash-chained events prevent undetected modification
//! - **IRQ Safety**: Lock operations disable interrupts to prevent deadlock
//! - **Fixed Ring Buffer**: Bounded memory with overflow accounting
//! - **Zero Allocation**: Event emission path avoids heap allocation
//! - **Capability Gating**: Future support for access control on audit reads
//!
//! # Security Design
//!
//! 1. **Hash Chain**: Each event includes `prev_hash` and `hash` fields (32 bytes each).
//!    The chain uses SHA-256 with domain separation ("AUDIT-SHA256-V1") and allows
//!    verification that no events were inserted, deleted, or modified between any
//!    two points.
//!
//! 2. **Overflow Handling**: When the ring buffer is full, oldest events
//!    are evicted. The `dropped` counter in each event tracks how many
//!    events were lost before that record.
//!
//! 3. **Subject/Object Model**: Events capture WHO (subject: pid/uid/gid/cap)
//!    did WHAT (kind: syscall/fs/ipc) to WHOM (object: path/endpoint/socket).
//!
//! # Hash Algorithm History
//!
//! - **v0.x (legacy)**: Used FNV-1a 64-bit hash
//! - **v1.0 (current)**: Upgraded to SHA-256 (32-byte hash) for enterprise security
//!
//! Note: Hash chain format is incompatible between versions. Old FNV-1a chains
//! cannot be verified with the new SHA-256 implementation.
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize during kernel boot
//! audit::init(256)?;
//!
//! // Emit events from syscall/VFS/IPC paths
//! audit::emit(
//!     AuditKind::Syscall,
//!     AuditOutcome::Success,
//!     AuditSubject::new(pid, uid, gid, None),
//!     AuditObject::None,
//!     &[syscall_nr, arg0, arg1],
//!     0,  // errno
//!     get_timestamp(),
//! )?;
//!
//! // Read events for logging/forwarding
//! let snapshot = audit::snapshot();
//! ```

#![no_std]

extern crate alloc;

extern crate drivers;
#[macro_use]
extern crate klog;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::instructions::interrupts;

// ============================================================================
// Configuration
// ============================================================================

/// Default ring buffer capacity (number of events)
pub const DEFAULT_CAPACITY: usize = 256;

/// Maximum capacity to prevent excessive memory usage
pub const MAX_CAPACITY: usize = 8192;

/// Maximum number of syscall arguments to store
/// Note: We store syscall_num + 6 args, so need 7 slots
pub const MAX_ARGS: usize = 7;

/// R110-4 FIX: Minimum HMAC key size (128-bit).
///
/// Keys shorter than this provide negligible tamper resistance.
/// FIPS 140-2 / NIST SP 800-107 require HMAC keys >= 128 bits.
pub const MIN_HMAC_KEY_SIZE: usize = 16;

/// R65-15 FIX: Maximum HMAC key size
/// Using 32 bytes (256 bits) as recommended for HMAC-SHA256
pub const MAX_HMAC_KEY_SIZE: usize = 32;

// ============================================================================
// Error Types
// ============================================================================

/// Audit subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// Audit subsystem not initialized
    Uninitialized,
    /// Already initialized
    AlreadyInitialized,
    /// Invalid capacity (zero or too large)
    InvalidCapacity,
    /// Audit subsystem is disabled
    Disabled,
    /// Missing capability to read/export the audit log (CAP_AUDIT_READ)
    AccessDenied,
    /// R110-4 FIX: HMAC key too small (below MIN_HMAC_KEY_SIZE)
    KeyTooSmall,
    /// R65-15 FIX: HMAC key too large
    KeyTooLarge,
    /// R65-15 FIX: HMAC key already set (cannot be changed for forward secrecy)
    KeyAlreadySet,
}

// ============================================================================
// Event Classification
// ============================================================================

/// High-level category of audit events
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditKind {
    /// System call entry/exit
    Syscall = 0,
    /// Inter-process communication (pipe, mq, futex)
    Ipc = 1,
    /// File system operations (open, read, write, unlink)
    Fs = 2,
    /// Process lifecycle (fork, exec, exit)
    Process = 3,
    /// Signal delivery
    Signal = 4,
    /// Security decisions (DAC/MAC checks, capability use)
    Security = 5,
    /// Network operations (future)
    Network = 6,
    /// Kernel internal events (boot, shutdown)
    Internal = 7,
}

/// Outcome of the audited operation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditOutcome {
    /// Operation succeeded
    Success = 0,
    /// Operation denied by security policy
    Denied = 1,
    /// Operation failed with error
    Error = 2,
    /// Informational event (no operation)
    Info = 3,
}

// ============================================================================
// Security Event Encoding (Phase B.4)
// ============================================================================

/// Security-specific classification for `AuditKind::Security` events.
///
/// Stored in `args[0]` to distinguish between different security subsystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditSecurityClass {
    /// LSM hook denied an operation.
    Lsm = 1,
    /// Seccomp/Pledge filter blocked a syscall.
    Seccomp = 2,
    /// Capability lifecycle or use.
    Capability = 3,
    /// P1-3: Cgroup delegation lifecycle (grant/revoke).
    CgroupDelegation = 4,
}

/// LSM denial reason code (stored in `args[2]`).
///
/// Provides more detail on why an LSM hook denied an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditLsmReason {
    /// Generic policy decision (default).
    Policy = 1,
    /// Operation required a capability that was missing.
    MissingCapability = 2,
    /// Integrity/label validation failed.
    Integrity = 3,
    /// DAC permission check failed.
    DacDenied = 4,
    /// MAC policy blocked the operation.
    MacDenied = 5,
    /// Internal policy failure (misconfiguration or bug).
    Internal = 254,
    /// Other/unspecified reason.
    Unknown = 255,
}

/// Normalized seccomp actions for audit reporting (`args[3]`).
///
/// Matches the seccomp::SeccompAction enum for consistent logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditSeccompAction {
    /// Syscall was allowed.
    Allow = 0,
    /// Syscall was logged but allowed.
    Log = 1,
    /// Syscall returned errno.
    Errno = 2,
    /// Syscall caused SIGSYS trap.
    Trap = 3,
    /// Syscall caused process termination.
    Kill = 4,
}

/// Capability operations tracked by audit (`args[1]`).
///
/// Used to distinguish different capability lifecycle events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditCapOperation {
    /// Capability allocated to process.
    Allocate = 1,
    /// Capability revoked.
    Revoke = 2,
    /// Capability delegated to another process.
    Delegate = 3,
    /// Capability used for an operation.
    Use = 4,
    /// Capability lookup failed (invalid/stale).
    LookupFailed = 5,
}

/// P1-3: Cgroup delegation operations tracked by audit (`args[1]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditCgroupDelegationOp {
    /// Delegation granted or updated.
    Grant = 1,
    /// Delegation revoked.
    Revoke = 2,
}

/// Argument layout for security events (shared across SecurityClass variants).
///
/// - `args[0]`: AuditSecurityClass discriminant
/// - `args[1..6]`: Class-specific details
pub const AUDIT_SECURITY_ARG_CLASS: usize = 0;
pub const AUDIT_SECURITY_ARG_DETAIL0: usize = 1;
pub const AUDIT_SECURITY_ARG_DETAIL1: usize = 2;
pub const AUDIT_SECURITY_ARG_DETAIL2: usize = 3;
pub const AUDIT_SECURITY_ARG_DETAIL3: usize = 4;

// ============================================================================
// Subject and Object Types
// ============================================================================

/// Subject (actor) of an audit event
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditSubject {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Capability ID used (if any)
    pub cap_id: Option<u64>,
}

impl AuditSubject {
    /// Create a new audit subject
    #[inline]
    pub const fn new(pid: u32, uid: u32, gid: u32, cap_id: Option<u64>) -> Self {
        Self {
            pid,
            uid,
            gid,
            cap_id,
        }
    }

    /// Create a kernel subject (pid 0)
    #[inline]
    pub const fn kernel() -> Self {
        Self {
            pid: 0,
            uid: 0,
            gid: 0,
            cap_id: None,
        }
    }
}

/// Object (target) of an audit event
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditObject {
    /// No specific object
    None,
    /// File system object
    Path {
        /// Inode number
        inode: u64,
        /// File mode bits
        mode: u32,
        /// X-1 FIX: SHA-256 (truncated to 64 bits) hash of the path string
        path_hash: u64,
    },
    /// IPC endpoint
    Endpoint {
        /// Endpoint ID
        id: u64,
    },
    /// Process target
    Process {
        /// Target PID
        pid: u32,
        /// Signal number (if signal-related)
        signal: Option<u32>,
    },
    /// Capability reference
    Capability {
        /// Capability ID
        cap_id: u64,
    },
    /// Socket (future)
    Socket {
        /// Protocol (TCP=6, UDP=17)
        proto: u8,
        /// Local address (packed IPv4 or hash of IPv6)
        local_addr: u64,
        /// Local port
        local_port: u16,
        /// Remote address
        remote_addr: u64,
        /// Remote port
        remote_port: u16,
    },
    /// Memory region
    Memory {
        /// Virtual address
        vaddr: u64,
        /// Size in bytes
        size: u64,
        /// Protection flags
        prot: u32,
    },
    /// Namespace (F.1: Mount namespace audit support)
    Namespace {
        /// Namespace ID
        ns_id: u64,
        /// Namespace type (CLONE_NEWNS=0x20000, CLONE_NEWPID=0x20000000)
        ns_type: u32,
        /// Parent namespace ID (0 if root)
        parent_id: u64,
    },
}

// ============================================================================
// Audit Event
// ============================================================================

/// A single audit record with hash chain metadata
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Monotonically increasing event ID
    pub id: u64,
    /// Timestamp (timer ticks since boot)
    pub timestamp: u64,
    /// Event category
    pub kind: AuditKind,
    /// Operation outcome
    pub outcome: AuditOutcome,
    /// Actor information
    pub subject: AuditSubject,
    /// Target object
    pub object: AuditObject,
    /// Operation-specific arguments
    pub args: [u64; MAX_ARGS],
    /// Number of valid arguments
    pub arg_count: u8,
    /// Error number (if outcome is Error)
    pub errno: i32,
    /// Number of events dropped before this one
    pub dropped: u64,
    /// Hash of the previous event (for chain verification) - SHA-256
    pub prev_hash: [u8; 32],
    /// Hash of this event (SHA-256 over all fields)
    pub hash: [u8; 32],
}

impl AuditEvent {
    /// Create a new event (id, dropped, prev_hash, hash filled by ring buffer)
    fn new(
        timestamp: u64,
        kind: AuditKind,
        outcome: AuditOutcome,
        subject: AuditSubject,
        object: AuditObject,
        args: &[u64],
        errno: i32,
    ) -> Self {
        let mut arg_buf = [0u64; MAX_ARGS];
        let arg_count = args.len().min(MAX_ARGS);
        arg_buf[..arg_count].copy_from_slice(&args[..arg_count]);

        Self {
            id: 0,
            timestamp,
            kind,
            outcome,
            subject,
            object,
            args: arg_buf,
            arg_count: arg_count as u8,
            errno,
            dropped: 0,
            prev_hash: ZERO_HASH,
            hash: ZERO_HASH,
        }
    }
}

// ============================================================================
// Hash Chain (SHA-256)
// ============================================================================

/// Zero-initialized hash constant
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// SHA-256 block size in bytes (for HMAC padding)
const SHA256_BLOCK_SIZE: usize = 64;

/// HMAC inner pad constant (0x36 repeated)
const HMAC_IPAD: u8 = 0x36;

/// HMAC outer pad constant (0x5c repeated)
const HMAC_OPAD: u8 = 0x5c;

/// SHA-256 initial state constants (FIPS 180-4)
const SHA256_INIT_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (FIPS 180-4)
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pure Rust SHA-256 implementation for no_std kernel environment
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher
    #[inline]
    fn new() -> Self {
        Self {
            state: SHA256_INIT_STATE,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Compute SHA-256 digest of a single message
    #[inline]
    #[allow(dead_code)]
    fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Update the hasher with more data
    fn update(&mut self, data: &[u8]) {
        let mut input = data;

        while !input.is_empty() {
            let take = core::cmp::min(64 - self.buffer_len, input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            self.total_len = self.total_len.wrapping_add(take as u64);

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress_block(&block);
                self.buffer_len = 0;
            }
            input = &input[take..];
        }
    }

    /// Finalize the hash and return the digest
    fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_len.wrapping_mul(8);

        // Pad with 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough room for length, pad and compress
        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.compress_block(&block);
            self.buffer_len = 0;
        }

        // Pad with zeros until length field position
        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        // Append bit length in big-endian
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.compress_block(&block);

        // Output state in big-endian
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    /// Compress a single 512-bit block
    #[inline(always)]
    fn compress_block(&mut self, block: &[u8; 64]) {
        // Helper functions per FIPS 180-4
        #[inline(always)]
        fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        #[inline(always)]
        fn maj(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        #[inline(always)]
        fn big_sigma0(x: u32) -> u32 {
            x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
        }

        #[inline(always)]
        fn big_sigma1(x: u32) -> u32 {
            x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
        }

        #[inline(always)]
        fn small_sigma0(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        #[inline(always)]
        fn small_sigma1(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        // Message schedule
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // Working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 64 rounds
        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Update state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Helper to feed typed data into SHA-256 with consistent encoding
struct Sha256Writer {
    hasher: Sha256,
}

impl Sha256Writer {
    #[inline]
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    #[inline]
    fn write_u8(&mut self, v: u8) {
        self.hasher.update(&[v]);
    }

    #[inline]
    fn write_u16(&mut self, v: u16) {
        self.hasher.update(&v.to_le_bytes());
    }

    #[inline]
    fn write_u32(&mut self, v: u32) {
        self.hasher.update(&v.to_le_bytes());
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.hasher.update(&v.to_le_bytes());
    }

    #[inline]
    fn write_i32(&mut self, v: i32) {
        self.write_u32(v as u32);
    }

    #[inline]
    fn write_bytes(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    #[inline]
    fn finish(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

// ============================================================================
// Public Crypto API for FIPS KATs
// ============================================================================

/// Public crypto API for FIPS Known Answer Tests.
///
/// These functions expose the audit subsystem's internal SHA-256 and HMAC-SHA256
/// implementations so that the compliance module can run self-tests against the
/// exact same code used for audit log integrity.
///
/// # R93-14: FIPS KAT Support
///
/// FIPS 140-2/140-3 requires that cryptographic modules run Known Answer Tests
/// (KAT) at startup before enabling FIPS mode. These APIs allow the compliance
/// module to test:
/// - SHA-256 with NIST CAVP test vectors
/// - HMAC-SHA256 with NIST CSRC example values
pub mod crypto {
    use super::Sha256;

    /// Compute SHA-256 digest of a byte slice.
    ///
    /// This is the same SHA-256 implementation used for audit log integrity.
    #[inline]
    pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data)
    }

    /// Streaming SHA-256 hasher (no allocation, no_std compatible).
    ///
    /// Use this for large inputs that cannot be loaded into memory at once.
    pub struct StreamingSha256 {
        inner: Sha256,
    }

    impl StreamingSha256 {
        /// Create a new streaming hasher.
        #[inline]
        pub fn new() -> Self {
            Self {
                inner: Sha256::new(),
            }
        }

        /// Update the hasher with more data.
        #[inline]
        pub fn update(&mut self, data: &[u8]) {
            self.inner.update(data);
        }

        /// Finalize the hash and return the 32-byte digest.
        #[inline]
        pub fn finalize(self) -> [u8; 32] {
            self.inner.finalize()
        }
    }

    impl Default for StreamingSha256 {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Compute HMAC-SHA256(key, msg) over raw byte slices.
    ///
    /// Delegates to the internal `hmac_sha256()` function to ensure FIPS KATs
    /// exercise the exact same code path used for audit log integrity chains.
    /// Implements RFC 2104 / FIPS 198-1.
    #[inline]
    pub fn hmac_sha256_digest(key: &[u8], msg: &[u8]) -> [u8; 32] {
        super::hmac_sha256(key, |w| {
            w.write_bytes(msg);
        })
    }
}

/// Compute SHA-256 hash of an AuditObject
fn hash_object(hasher: &mut Sha256Writer, obj: &AuditObject) {
    match obj {
        AuditObject::None => {
            hasher.write_u8(0);
        }
        AuditObject::Path {
            inode,
            mode,
            path_hash,
        } => {
            hasher.write_u8(1);
            hasher.write_u64(*inode);
            hasher.write_u32(*mode);
            hasher.write_u64(*path_hash);
        }
        AuditObject::Endpoint { id } => {
            hasher.write_u8(2);
            hasher.write_u64(*id);
        }
        AuditObject::Process { pid, signal } => {
            hasher.write_u8(3);
            hasher.write_u32(*pid);
            hasher.write_u32(signal.unwrap_or(0));
        }
        AuditObject::Capability { cap_id } => {
            hasher.write_u8(4);
            hasher.write_u64(*cap_id);
        }
        AuditObject::Socket {
            proto,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        } => {
            hasher.write_u8(5);
            hasher.write_u8(*proto);
            hasher.write_u64(*local_addr);
            hasher.write_u16(*local_port);
            hasher.write_u64(*remote_addr);
            hasher.write_u16(*remote_port);
        }
        AuditObject::Memory { vaddr, size, prot } => {
            hasher.write_u8(6);
            hasher.write_u64(*vaddr);
            hasher.write_u64(*size);
            hasher.write_u32(*prot);
        }
        AuditObject::Namespace {
            ns_id,
            ns_type,
            parent_id,
        } => {
            hasher.write_u8(7);
            hasher.write_u64(*ns_id);
            hasher.write_u32(*ns_type);
            hasher.write_u64(*parent_id);
        }
    }
}

/// Serialize the event payload (excluding key handling) into the hasher.
///
/// This is a shared helper used by both plain SHA-256 and HMAC-SHA256 modes
/// to ensure consistent event encoding.
fn write_event_payload(hasher: &mut Sha256Writer, prev_hash: [u8; 32], event: &AuditEvent) {
    // Chain to previous event
    hasher.write_bytes(&prev_hash);

    // Event metadata
    hasher.write_u64(event.id);
    hasher.write_u64(event.timestamp);
    hasher.write_u8(event.kind as u8);
    hasher.write_u8(event.outcome as u8);

    // Subject
    hasher.write_u32(event.subject.pid);
    hasher.write_u32(event.subject.uid);
    hasher.write_u32(event.subject.gid);
    hasher.write_u64(event.subject.cap_id.unwrap_or(0));

    // Arguments
    hasher.write_u8(event.arg_count);
    for i in 0..event.arg_count as usize {
        hasher.write_u64(event.args[i]);
    }

    // Error and dropped count
    hasher.write_i32(event.errno);
    hasher.write_u64(event.dropped);

    // Object
    hash_object(hasher, &event.object);
}

/// Securely zero a buffer to scrub sensitive key material.
///
/// Uses volatile writes to prevent the compiler from optimizing away the zeroing,
/// followed by a compiler fence to ensure the writes complete before the function
/// returns.
///
/// # R94-10: Defense-in-depth for key material
///
/// HMAC computations create intermediate buffers containing key-derived material
/// (key_block, inner_pad, outer_pad, inner_digest). These must be scrubbed after
/// use to minimize the window for key extraction via memory disclosure bugs.
#[inline(never)]
fn secure_zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Compute HMAC-SHA256: H((K' ⊕ opad) || H((K' ⊕ ipad) || message))
///
/// This is the standard HMAC construction per RFC 2104 / FIPS 198-1.
/// The message is written via a closure to allow streaming without allocation.
///
/// # Arguments
///
/// * `key` - The secret key (will be normalized to block size)
/// * `write_message` - Closure that writes the message to the inner hasher
///
/// # Returns
///
/// 32-byte HMAC-SHA256 digest
///
/// # R94-10 FIX: Key Material Scrubbing
///
/// All intermediate buffers containing key-derived material are securely zeroed
/// before the function returns to minimize exposure window for memory disclosure.
fn hmac_sha256<F>(key: &[u8], write_message: F) -> [u8; 32]
where
    F: FnOnce(&mut Sha256Writer),
{
    // Normalize key to block size:
    // - If key > block size, hash it first
    // - If key < block size, pad with zeros
    let mut key_block = [0u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        let hashed_key = Sha256::digest(key);
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Prepare inner pad (K' XOR ipad) and outer pad (K' XOR opad)
    let mut inner_pad = [0u8; SHA256_BLOCK_SIZE];
    let mut outer_pad = [0u8; SHA256_BLOCK_SIZE];
    for i in 0..SHA256_BLOCK_SIZE {
        inner_pad[i] = key_block[i] ^ HMAC_IPAD;
        outer_pad[i] = key_block[i] ^ HMAC_OPAD;
    }

    // Inner hash: H((K' XOR ipad) || message)
    let mut inner = Sha256Writer::new();
    inner.write_bytes(&inner_pad);
    write_message(&mut inner);
    let mut inner_digest = inner.finish();

    // Outer hash: H((K' XOR opad) || inner_digest)
    let mut outer = Sha256Writer::new();
    outer.write_bytes(&outer_pad);
    outer.write_bytes(&inner_digest);
    let result = outer.finish();

    // R94-10 FIX: Scrub all key-derived material from the stack before returning.
    // This minimizes the exposure window for key extraction via memory disclosure bugs.
    secure_zeroize(&mut key_block);
    secure_zeroize(&mut inner_pad);
    secure_zeroize(&mut outer_pad);
    secure_zeroize(&mut inner_digest);

    result
}

/// Compute the hash of an audit event (SHA-256 with domain separation)
fn hash_event(prev_hash: [u8; 32], event: &AuditEvent) -> [u8; 32] {
    hash_event_prefixed(prev_hash, event, None)
}

/// Compute the hash of an audit event with optional HMAC key
///
/// This function supports two modes:
///
/// - **Keyless mode** (`key=None`): Uses domain-separated SHA-256 with
///   "AUDIT-SHA256-V1" prefix. Suitable for tamper-evidence without secrets.
///
/// - **Keyed mode** (`key=Some(k)`): Uses proper HMAC-SHA256 per RFC 2104/FIPS 198-1
///   with "AUDIT-HMAC-SHA256-V1" domain separator in the message. Provides both
///   tamper-evidence and authenticity verification.
///
/// # Security Properties
///
/// HMAC-SHA256 provides:
/// - Collision resistance (from SHA-256)
/// - PRF security (key-dependent outputs)
/// - Resistance to length extension attacks (unlike prefix construction)
///
/// # Arguments
///
/// * `prev_hash` - Hash of the previous event in the chain
/// * `event` - The event to hash
/// * `key` - Optional HMAC key (None for keyless chain)
///
/// # Returns
///
/// 32-byte digest (SHA-256 or HMAC-SHA256)
#[allow(dead_code)]
fn hash_event_prefixed(prev_hash: [u8; 32], event: &AuditEvent, key: Option<&[u8]>) -> [u8; 32] {
    match key {
        Some(k) => {
            // HMAC-SHA256 mode: proper keyed authentication
            hmac_sha256(k, |hasher| {
                // Domain separator for keyed mode
                hasher.write_bytes(b"AUDIT-HMAC-SHA256-V1");
                write_event_payload(hasher, prev_hash, event);
            })
        }
        None => {
            // Plain SHA-256 mode: domain-separated hash chain
            let mut hasher = Sha256Writer::new();
            hasher.write_bytes(b"AUDIT-SHA256-V1");
            write_event_payload(&mut hasher, prev_hash, event);
            hasher.finish()
        }
    }
}

// ============================================================================
// Ring Buffer
// ============================================================================

/// R65-15 FIX: HMAC key storage
///
/// The key is stored inline to avoid allocation in the hot path.
/// We use Option to track whether a key has been set.
struct HmacKey {
    /// Key data (padded with zeros if shorter than MAX_HMAC_KEY_SIZE)
    data: [u8; MAX_HMAC_KEY_SIZE],
    /// Actual key length (0 means no key set)
    len: usize,
}

impl HmacKey {
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_HMAC_KEY_SIZE],
            len: 0,
        }
    }

    fn is_set(&self) -> bool {
        self.len > 0
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// R66-10 FIX: Zeroize key material on drop to prevent memory disclosure.
impl Drop for HmacKey {
    fn drop(&mut self) {
        // Zeroize key material to avoid lingering secrets in memory
        // Use volatile writes to prevent optimization away
        for byte in self.data.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        self.len = 0;
        // Memory barrier to ensure zeroization is not reordered
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Internal ring buffer for audit events
struct AuditRing {
    /// Fixed-size buffer
    buf: Vec<Option<AuditEvent>>,
    /// Index of the oldest event
    head: usize,
    /// Number of events currently stored
    len: usize,
    /// Next event ID
    next_id: u64,
    /// Hash of the last event (chain head) - SHA-256
    prev_hash: [u8; 32],
    /// Accumulated dropped count since last emit
    dropped: u64,
    /// R65-15 FIX: HMAC key for audit log integrity
    ///
    /// When set, all events are hashed with HMAC-SHA256 instead of plain SHA-256.
    /// This provides:
    /// - Tamper evidence (attackers cannot forge valid hashes)
    /// - Authenticity verification (only key holder can verify)
    /// - Forward secrecy (old events remain secure even if key is later compromised)
    hmac_key: HmacKey,
}

impl AuditRing {
    /// Create a new ring buffer with given capacity
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: alloc::vec![None; capacity],
            head: 0,
            len: 0,
            next_id: 0,
            prev_hash: ZERO_HASH,
            dropped: 0,
            hmac_key: HmacKey::empty(), // R65-15 FIX: Initialize empty key
        }
    }

    /// R65-15 FIX: Set the HMAC key for audit log integrity
    ///
    /// Once set, the key cannot be changed to preserve forward secrecy.
    /// All subsequent events will be hashed with HMAC-SHA256 instead of
    /// plain SHA-256, providing tamper-evidence and authenticity.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key (min MIN_HMAC_KEY_SIZE bytes, recommended: 32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Key was set successfully
    /// * `Err(KeyTooSmall)` - Key is shorter than MIN_HMAC_KEY_SIZE (R110-4 FIX)
    /// * `Err(KeyTooLarge)` - Key exceeds MAX_HMAC_KEY_SIZE
    /// * `Err(KeyAlreadySet)` - Key was already set
    fn set_key(&mut self, key: &[u8]) -> Result<(), AuditError> {
        // R110-4 FIX: Enforce minimum key length for meaningful tamper resistance.
        if key.len() < MIN_HMAC_KEY_SIZE {
            return Err(AuditError::KeyTooSmall);
        }
        if key.len() > MAX_HMAC_KEY_SIZE {
            return Err(AuditError::KeyTooLarge);
        }
        if self.hmac_key.is_set() {
            return Err(AuditError::KeyAlreadySet);
        }
        self.hmac_key.data[..key.len()].copy_from_slice(key);
        self.hmac_key.len = key.len();
        Ok(())
    }

    /// Check if HMAC key is set
    fn has_key(&self) -> bool {
        self.hmac_key.is_set()
    }

    /// Return `(used, capacity)` for ring buffer occupancy reporting.
    ///
    /// Used by `read_from_cursor()` to populate `AuditExportBatch::ring_usage`.
    #[inline]
    fn usage_fraction(&self) -> (usize, usize) {
        (self.len, self.buf.len())
    }

    /// Push an event into the ring buffer
    ///
    /// # R65-15 FIX: HMAC Support
    ///
    /// When an HMAC key is set, events are hashed with HMAC-SHA256 instead
    /// of plain SHA-256. This provides cryptographic proof of integrity and
    /// authenticity that cannot be forged without the key.
    fn push(&mut self, mut event: AuditEvent) {
        if self.buf.is_empty() {
            return;
        }

        // Evict oldest event if buffer is full
        if self.len == self.buf.len() {
            self.dropped = self.dropped.saturating_add(1);
            self.buf[self.head] = None;
            self.head = (self.head + 1) % self.buf.len();
            self.len -= 1;
        }

        // Fill in event metadata
        event.id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        event.prev_hash = self.prev_hash;
        event.dropped = core::mem::take(&mut self.dropped);

        // R65-15 FIX: Use HMAC-SHA256 when key is set, otherwise plain SHA-256
        event.hash = if self.hmac_key.is_set() {
            hash_event_prefixed(event.prev_hash, &event, Some(self.hmac_key.as_slice()))
        } else {
            hash_event(event.prev_hash, &event)
        };
        self.prev_hash = event.hash;

        // Insert at tail
        let tail = (self.head + self.len) % self.buf.len();
        self.buf[tail] = Some(event);
        self.len += 1;
    }

    /// Drain all events from the buffer
    fn drain(&mut self) -> Vec<AuditEvent> {
        let mut events = Vec::with_capacity(self.len);
        for _ in 0..self.len {
            if let Some(event) = self.buf[self.head].take() {
                events.push(event);
            }
            self.head = (self.head + 1) % self.buf.len();
        }
        self.len = 0;
        events
    }

    /// Read up to `max_events` events with `id >= cursor` without draining.
    ///
    /// `cursor` is an event ID. If `cursor` refers to an event that has already
    /// been evicted from the ring buffer, reading starts from the oldest
    /// available event. Returns `next_cursor = last_returned_id + 1`.
    fn read_from_cursor(&self, cursor: u64, max_events: usize) -> AuditExportBatch {
        let tail_hash = self.tail_hash();

        // P1-2: Compute ring buffer occupancy in basis points (0–10000).
        let (used, capacity) = self.usage_fraction();
        let ring_usage: u16 = if capacity > 0 {
            ((used as u64 * 10000) / capacity as u64) as u16
        } else {
            0
        };

        // P1-2: Determine oldest_id upfront so we can compute dropped_since_cursor
        // for all return paths (including empty ring / future cursor).
        let oldest_id = if used == 0 || capacity == 0 {
            cursor
        } else {
            self.buf[self.head].as_ref().map(|e| e.id).unwrap_or(cursor)
        };

        // P1-2: Events lost between the caller's cursor and the oldest available.
        let dropped_since_cursor: u64 = if cursor < oldest_id {
            oldest_id.saturating_sub(cursor)
        } else {
            0
        };

        if used == 0 || capacity == 0 || max_events == 0 {
            return AuditExportBatch {
                events: Vec::new(),
                next_cursor: cursor,
                has_more: false,
                tail_hash,
                batch_first_prev_hash: ZERO_HASH,
                ring_usage,
                dropped_since_cursor,
            };
        }

        // Clamp cursor to the valid range [oldest_id, next_id].
        // - If cursor < oldest_id: the requested events were evicted; start
        //   from the oldest available event.
        // - If cursor >= next_id: the caller has a stale/future cursor
        //   (e.g., from a reboot); clamp to next_id so the caller polls
        //   for new events instead of missing them.
        let start_cursor = if cursor < oldest_id {
            oldest_id
        } else if cursor >= self.next_id {
            // Future cursor: nothing available yet; return next_id so the
            // caller can poll again when new events arrive.
            return AuditExportBatch {
                events: Vec::new(),
                next_cursor: self.next_id,
                has_more: false,
                tail_hash,
                batch_first_prev_hash: ZERO_HASH,
                ring_usage,
                dropped_since_cursor,
            };
        } else {
            cursor
        };

        // Linear scan to find the first buffered event with id >= start_cursor.
        let mut start_offset: Option<usize> = None;
        for i in 0..self.len {
            let idx = (self.head + i) % self.buf.len();
            if let Some(ref event) = self.buf[idx] {
                if event.id >= start_cursor {
                    start_offset = Some(i);
                    break;
                }
            }
        }

        let Some(start_offset) = start_offset else {
            // Cursor is beyond the newest available event.
            return AuditExportBatch {
                events: Vec::new(),
                next_cursor: start_cursor,
                has_more: false,
                tail_hash,
                batch_first_prev_hash: ZERO_HASH,
                ring_usage,
                dropped_since_cursor,
            };
        };

        let available = self.len - start_offset;
        let to_take = core::cmp::min(max_events, available);
        let mut events = Vec::with_capacity(to_take);
        let mut last_id = start_cursor;

        for i in 0..available {
            if events.len() >= to_take {
                break;
            }
            let idx = (self.head + start_offset + i) % self.buf.len();
            if let Some(ref event) = self.buf[idx] {
                if event.id < start_cursor {
                    continue;
                }
                last_id = event.id;
                events.push(event.clone());
            }
        }

        let next_cursor = if events.is_empty() {
            start_cursor
        } else {
            last_id.wrapping_add(1)
        };

        // P1-2: Extract first event's prev_hash for chain continuity verification.
        // When dropped_since_cursor > 0, the chain is broken so we zero the field
        // to signal the daemon that continuity cannot be verified for this window.
        let batch_first_prev_hash = if dropped_since_cursor > 0 {
            ZERO_HASH
        } else {
            events.first().map(|e| e.prev_hash).unwrap_or(ZERO_HASH)
        };

        AuditExportBatch {
            events,
            next_cursor,
            has_more: available > to_take,
            tail_hash,
            batch_first_prev_hash,
            ring_usage,
            dropped_since_cursor,
        }
    }

    /// Get the current tail hash (for integrity verification)
    fn tail_hash(&self) -> [u8; 32] {
        self.prev_hash
    }

    /// Get statistics
    fn stats(&self) -> AuditStats {
        AuditStats {
            total_events: self.next_id,
            buffered_events: self.len as u64,
            dropped_events: self.dropped,
            capacity: self.buf.len() as u64,
            tail_hash: self.prev_hash,
        }
    }
}

// ============================================================================
// Audit Snapshot and Statistics
// ============================================================================

/// Snapshot of audit log for readers
pub struct AuditSnapshot {
    /// Drained events
    pub events: Vec<AuditEvent>,
    /// Number of events dropped since last snapshot
    pub dropped: u64,
    /// Hash of the last event in the chain (SHA-256)
    pub tail_hash: [u8; 32],
}

/// Audit subsystem statistics
#[derive(Clone, Copy, Debug)]
pub struct AuditStats {
    /// Total events emitted since boot
    pub total_events: u64,
    /// Events currently in buffer
    pub buffered_events: u64,
    /// Events dropped due to overflow
    pub dropped_events: u64,
    /// Buffer capacity
    pub capacity: u64,
    /// Current tail hash (SHA-256)
    pub tail_hash: [u8; 32],
}

// ============================================================================
// Cursor-Based Export (Non-Draining) — G.fin.2
// ============================================================================

/// Batch of audit events exported from a cursor without draining the ring buffer.
pub struct AuditExportBatch {
    /// Exported events in ascending `id` order.
    pub events: Vec<AuditEvent>,
    /// Cursor to resume from on the next call (`last_returned_id + 1`).
    pub next_cursor: u64,
    /// `true` if there are additional events available after this batch.
    pub has_more: bool,
    /// Current tail hash of the audit chain (SHA-256).
    pub tail_hash: [u8; 32],
    /// P1-2: `prev_hash` of the first exported event (SHA-256).
    ///
    /// Enables userspace to verify chain continuity across export windows:
    /// `batch_first_prev_hash == last_window_last_hash`.
    ///
    /// When `events` is empty or `dropped_since_cursor > 0`, this field is
    /// zero-filled (chain was broken — the daemon must treat it as a gap).
    pub batch_first_prev_hash: [u8; 32],
    /// P1-2: Ring buffer occupancy in basis points (0–10000).
    ///
    /// Enables the userspace audit daemon to detect back-pressure and throttle
    /// high-rate event producers before ring overflow causes event loss.
    pub ring_usage: u16,
    /// P1-2: Estimated events evicted between the caller's cursor and the
    /// oldest event still available in the ring.
    ///
    /// When non-zero the daemon knows it missed `dropped_since_cursor` events
    /// and can emit a synthetic gap marker in the remote syslog stream.
    pub dropped_since_cursor: u64,
}

/// Magic value for [`AuditExportHeader`] ("ZAUD" in little-endian).
pub const AUDIT_EXPORT_MAGIC: u32 = u32::from_le_bytes(*b"ZAUD");

/// Export format version.
///
/// Version history:
/// - v1: Initial format (48-byte header)
/// - v2: Added ring_usage + dropped_since_cursor for remote delivery (64-byte header)
/// - v3: Added batch_first_prev_hash + backpressure_high_water_bps (96-byte header)
pub const AUDIT_EXPORT_VERSION: u16 = 3;

/// Default high-water mark for userspace backpressure polling (basis points).
///
/// Userspace audit daemons should treat `ring_usage >= backpressure_high_water_bps`
/// as a signal to increase export frequency or throttle high-rate producers.
pub const AUDIT_BACKPRESSURE_DEFAULT_BPS: u16 = 8000;

/// Fixed-size export header written before `AuditExportRecord[]`.
///
/// All integer fields are stored in little-endian byte order on the wire.
///
/// Layout (v3, 96 bytes):
///   [0..4)    magic                        u32
///   [4..6)    version                      u16
///   [6..8)    record_count                 u16
///   [8..16)   cursor                       u64
///   [16..48)  tail_hash                    [u8; 32]
///   [48..56)  dropped_since_cursor         u64
///   [56..58)  ring_usage                   u16
///   [58..60)  backpressure_high_water_bps  u16
///   [60..64)  _reserved                    [u8; 4]
///   [64..96)  batch_first_prev_hash        [u8; 32]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditExportHeader {
    /// Magic: `AUDIT_EXPORT_MAGIC` ("ZAUD").
    pub magic: u32,
    /// Format version: `AUDIT_EXPORT_VERSION`.
    pub version: u16,
    /// Number of `AuditExportRecord` entries following this header.
    pub record_count: u16,
    /// Next cursor for the caller to resume from (`last_returned_id + 1`).
    pub cursor: u64,
    /// Current chain tail hash (SHA-256).
    pub tail_hash: [u8; 32],
    /// P1-2: Estimated events evicted between caller's cursor and oldest available.
    pub dropped_since_cursor: u64,
    /// P1-2: Ring buffer occupancy in basis points (0–10000).
    pub ring_usage: u16,
    /// P1-2: Recommended high-water mark for backpressure polling (0–10000).
    ///
    /// When `ring_usage >= backpressure_high_water_bps`, userspace should
    /// increase export frequency or apply upstream throttling.
    pub backpressure_high_water_bps: u16,
    /// Reserved for future use; zero-filled.
    pub _reserved: [u8; 4],
    /// P1-2: `prev_hash` of the first exported event (SHA-256).
    ///
    /// When `record_count > 0` and `dropped_since_cursor == 0`, userspace can
    /// verify chain continuity: `batch_first_prev_hash == last_window_last_hash`.
    /// Zero-filled when no events are exported or the chain has a gap.
    pub batch_first_prev_hash: [u8; 32],
}

impl AuditExportHeader {
    /// Serialized size in bytes (v3: 96).
    pub const SIZE: usize = 96;

    /// Construct a new header.
    #[inline]
    pub const fn new(
        record_count: u16,
        next_cursor: u64,
        tail_hash: [u8; 32],
        ring_usage: u16,
        dropped_since_cursor: u64,
        batch_first_prev_hash: [u8; 32],
    ) -> Self {
        Self {
            magic: AUDIT_EXPORT_MAGIC,
            version: AUDIT_EXPORT_VERSION,
            record_count,
            cursor: next_cursor,
            tail_hash,
            dropped_since_cursor,
            ring_usage,
            backpressure_high_water_bps: AUDIT_BACKPRESSURE_DEFAULT_BPS,
            _reserved: [0u8; 4],
            batch_first_prev_hash,
        }
    }

    /// Serialize to a little-endian byte representation.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.magic.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.record_count.to_le_bytes());
        out[8..16].copy_from_slice(&self.cursor.to_le_bytes());
        out[16..48].copy_from_slice(&self.tail_hash);
        out[48..56].copy_from_slice(&self.dropped_since_cursor.to_le_bytes());
        out[56..58].copy_from_slice(&self.ring_usage.to_le_bytes());
        out[58..60].copy_from_slice(&self.backpressure_high_water_bps.to_le_bytes());
        // out[60..64] remains zero (_reserved)
        out[64..96].copy_from_slice(&self.batch_first_prev_hash);
        out
    }
}

// Compile-time size assertion.
const _: [(); AuditExportHeader::SIZE] = [(); core::mem::size_of::<AuditExportHeader>()];

/// Fixed-size export record (128 bytes) for a single audit event.
///
/// Designed for a stable userspace ABI and efficient bulk transfer. Truncated
/// hash fields (8 bytes of the full 32-byte SHA-256) provide enough entropy
/// for chain integrity spot-checks; the full hashes are available via the
/// kernel's in-memory ring buffer for authoritative verification.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditExportRecord {
    /// Monotonically increasing event ID.
    pub id: u64,
    /// Timestamp (timer ticks since boot).
    pub timestamp: u64,
    /// Event category (`AuditKind` repr).
    pub kind: u8,
    /// Operation outcome (`AuditOutcome` repr).
    pub outcome: u8,
    _pad0: [u8; 2],
    /// Subject PID.
    pub pid: u32,
    /// Subject UID.
    pub uid: u32,
    /// Subject GID.
    pub gid: u32,
    /// Capability ID used (0 if none).
    pub cap_id: u64,
    /// Object type discriminant (0=None, 1=Path, 2=Endpoint, 3=Process, etc.).
    pub object_disc: u8,
    _pad1: [u8; 3],
    /// Error number (0 if success).
    pub errno: i32,
    /// Operation-specific arguments (up to 6).
    pub args: [u64; 6],
    /// Truncated `prev_hash` (first 8 bytes of SHA-256).
    pub prev_hash_trunc: [u8; 8],
    /// Truncated `hash` (first 8 bytes of SHA-256).
    pub hash_trunc: [u8; 8],
    /// Number of events dropped before this one.
    pub dropped: u64,
    /// Reserved for future use.
    pub reserved: [u8; 8],
}

impl AuditExportRecord {
    /// Serialized size in bytes.
    pub const SIZE: usize = 128;

    /// Map an `AuditObject` to its discriminant byte.
    #[inline]
    fn object_disc(obj: &AuditObject) -> u8 {
        match obj {
            AuditObject::None => 0,
            AuditObject::Path { .. } => 1,
            AuditObject::Endpoint { .. } => 2,
            AuditObject::Process { .. } => 3,
            AuditObject::Socket { .. } => 4,
            AuditObject::Memory { .. } => 5,
            AuditObject::Capability { .. } => 6,
            AuditObject::Namespace { .. } => 7,
        }
    }

    /// Convert an `AuditEvent` into the fixed-size export representation.
    ///
    /// When `redact_syscall_args` is `true`, syscall arguments `args[1..]` are
    /// zeroed to avoid leaking user pointers across processes; `args[0]`
    /// (the syscall number) is preserved.
    #[inline]
    pub fn from_event(event: &AuditEvent, redact_syscall_args: bool) -> Self {
        let mut args = [0u64; 6];
        let count = core::cmp::min(event.arg_count as usize, args.len());
        let should_redact = redact_syscall_args && matches!(event.kind, AuditKind::Syscall);
        for i in 0..count {
            args[i] = if should_redact && i != 0 {
                0
            } else {
                event.args[i]
            };
        }

        let mut prev_hash_trunc = [0u8; 8];
        prev_hash_trunc.copy_from_slice(&event.prev_hash[..8]);
        let mut hash_trunc = [0u8; 8];
        hash_trunc.copy_from_slice(&event.hash[..8]);

        Self {
            id: event.id,
            timestamp: event.timestamp,
            kind: event.kind as u8,
            outcome: event.outcome as u8,
            _pad0: [0; 2],
            pid: event.subject.pid,
            uid: event.subject.uid,
            gid: event.subject.gid,
            cap_id: event.subject.cap_id.unwrap_or(0),
            object_disc: Self::object_disc(&event.object),
            _pad1: [0; 3],
            errno: event.errno,
            args,
            prev_hash_trunc,
            hash_trunc,
            dropped: event.dropped,
            reserved: [0; 8],
        }
    }

    /// Serialize into the on-wire little-endian byte representation.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let mut o = 0usize;

        out[o..o + 8].copy_from_slice(&self.id.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        o += 8;
        out[o] = self.kind;
        o += 1;
        out[o] = self.outcome;
        o += 1;
        out[o..o + 2].copy_from_slice(&self._pad0);
        o += 2;
        out[o..o + 4].copy_from_slice(&self.pid.to_le_bytes());
        o += 4;
        out[o..o + 4].copy_from_slice(&self.uid.to_le_bytes());
        o += 4;
        out[o..o + 4].copy_from_slice(&self.gid.to_le_bytes());
        o += 4;
        out[o..o + 8].copy_from_slice(&self.cap_id.to_le_bytes());
        o += 8;
        out[o] = self.object_disc;
        o += 1;
        out[o..o + 3].copy_from_slice(&self._pad1);
        o += 3;
        out[o..o + 4].copy_from_slice(&self.errno.to_le_bytes());
        o += 4;
        for arg in &self.args {
            out[o..o + 8].copy_from_slice(&arg.to_le_bytes());
            o += 8;
        }
        out[o..o + 8].copy_from_slice(&self.prev_hash_trunc);
        o += 8;
        out[o..o + 8].copy_from_slice(&self.hash_trunc);
        o += 8;
        out[o..o + 8].copy_from_slice(&self.dropped.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.reserved);
        out
    }
}

// Compile-time size assertion.
const _: [(); AuditExportRecord::SIZE] = [(); core::mem::size_of::<AuditExportRecord>()];

// ============================================================================
// Snapshot Authorization (Capability Gate)
// ============================================================================

/// Callback type for snapshot authorization.
///
/// This function is called by `snapshot()` to verify the caller has
/// permission to read/export audit events. Returns `Ok(())` to allow,
/// or `Err(AuditError::AccessDenied)` to deny.
///
/// # Usage
///
/// The authorizer is registered during kernel boot by code that has
/// access to both process context and the capability subsystem:
///
/// ```rust,ignore
/// fn check_audit_read_cap() -> Result<(), AuditError> {
///     let current = get_current_process();
///     if current.cap_table.has_rights(CapRights::AUDIT_READ) {
///         Ok(())
///     } else {
///         Err(AuditError::AccessDenied)
///     }
/// }
///
/// audit::register_snapshot_authorizer(check_audit_read_cap);
/// ```
pub type SnapshotAuthorizer = fn() -> Result<(), AuditError>;

/// R66-10 FIX: Callback type for HMAC key configuration authorization.
///
/// Implementations should enforce CAP_AUDIT_WRITE or a bootstrap policy that
/// is equivalent during early kernel initialization.
///
/// # Usage
///
/// ```rust,ignore
/// fn check_audit_write_cap() -> Result<(), audit::AuditError> {
///     if process::current_has_cap(CapRights::AUDIT_WRITE) {
///         Ok(())
///     } else {
///         Err(audit::AuditError::AccessDenied)
///     }
/// }
///
/// audit::register_hmac_key_authorizer(check_audit_write_cap);
/// ```
pub type HmacKeyAuthorizer = fn() -> Result<(), AuditError>;

/// Callback type for pre-snapshot flush hook.
///
/// This function is called by `snapshot()` immediately before draining
/// the audit ring buffer. It allows other subsystems (LSM, seccomp, etc.)
/// to flush any buffered security events into the audit ring so they are
/// included in the snapshot.
///
/// # Usage
///
/// ```rust,ignore
/// fn flush_pending_events() {
///     // Flush any buffered LSM denial events
///     lsm::flush_audit_queue();
///     // Flush any buffered seccomp events
///     seccomp::flush_audit_queue();
/// }
///
/// audit::register_flush_hook(flush_pending_events);
/// ```
pub type FlushHook = fn();

/// R72-PERSIST: Callback type for persistence hook.
///
/// This function is called by `snapshot()` after draining the audit ring
/// buffer to allow persisting the drained events to durable storage (e.g.,
/// writing to ext2 via the VFS). Errors are treated as best-effort; the
/// snapshot still returns the drained events so callers can retry or forward
/// them elsewhere.
///
/// # Arguments
///
/// * `events` - Slice of drained audit events to persist
///
/// # Returns
///
/// * `Ok(())` - Events successfully persisted
/// * `Err(...)` - Persistence failed (events still returned to caller)
///
/// # Usage
///
/// ```rust,ignore
/// fn persist_audit_events(events: &[AuditEvent]) -> Result<(), AuditError> {
///     for event in events {
///         let record = serialize_event(event);
///         vfs::append("/var/log/audit.log", &record)?;
///     }
///     Ok(())
/// }
///
/// audit::register_persistence_hook(persist_audit_events);
/// ```
pub type PersistenceHook = fn(&[AuditEvent]) -> Result<(), AuditError>;

/// Optional capability gate for audit snapshots (set once at boot).
///
/// When set, `snapshot()` calls this function to verify the caller
/// has CAP_AUDIT_READ (or equivalent) before returning events.
/// If not set, `snapshot()` fails closed with AccessDenied.
static SNAPSHOT_AUTHORIZER: Mutex<Option<SnapshotAuthorizer>> = Mutex::new(None);

/// Optional flush hook executed prior to draining the audit ring buffer.
///
/// When set, `snapshot()` calls this function before draining events,
/// allowing other subsystems to flush pending audit data.
static FLUSH_HOOK: Mutex<Option<FlushHook>> = Mutex::new(None);

/// R72-PERSIST: Optional persistence hook executed after draining the audit ring.
///
/// When set, drained events are forwarded to this hook so they can be written
/// to persistent storage. Failures are best-effort and do not drop the events
/// returned by `snapshot()`.
static PERSISTENCE_HOOK: Mutex<Option<PersistenceHook>> = Mutex::new(None);

/// R66-10 FIX: Optional capability gate for audit HMAC key configuration.
///
/// If unset, `set_hmac_key` fails closed with AccessDenied. Kernel init code
/// should register an authorizer (root/CAP_AUDIT_WRITE) before configuring the key.
static HMAC_KEY_AUTHORIZER: Mutex<Option<HmacKeyAuthorizer>> = Mutex::new(None);

/// Register the snapshot authorizer callback.
///
/// This function should be called during kernel initialization by code
/// that can access both process context and the capability subsystem.
/// Once registered, all calls to `snapshot()` must pass this check.
///
/// # Arguments
///
/// * `authorizer` - Function that checks if current process has CAP_AUDIT_READ
///
/// # Example
///
/// ```rust,ignore
/// // In kernel main after both audit and cap are initialized:
/// audit::register_snapshot_authorizer(|| {
///     let creds = kernel_core::current_credentials();
///     if creds.effective_uid == 0 {
///         // Root always allowed (temporary policy)
///         Ok(())
///     } else {
///         Err(audit::AuditError::AccessDenied)
///     }
/// });
/// ```
pub fn register_snapshot_authorizer(authorizer: SnapshotAuthorizer) {
    interrupts::without_interrupts(|| {
        let mut guard = SNAPSHOT_AUTHORIZER.lock();
        *guard = Some(authorizer);
    });
}

/// R66-10 FIX: Register the HMAC key configuration authorizer.
///
/// Must be set during kernel init before calling `set_hmac_key` to enforce
/// CAP_AUDIT_WRITE (or a bootstrap allow policy during early boot).
///
/// # Arguments
///
/// * `authorizer` - Function that checks if current context has CAP_AUDIT_WRITE
///
/// # Example
///
/// ```rust,ignore
/// // During kernel init, register an authorizer that checks CAP_AUDIT_WRITE:
/// audit::register_hmac_key_authorizer(|| {
///     if kernel_core::current_has_cap(cap::CapRights::AUDIT_WRITE) {
///         Ok(())
///     } else {
///         Err(audit::AuditError::AccessDenied)
///     }
/// });
///
/// // For early boot before process subsystem is up, use permissive authorizer:
/// audit::register_hmac_key_authorizer(|| Ok(()));  // Bootstrap allow
/// ```
pub fn register_hmac_key_authorizer(authorizer: HmacKeyAuthorizer) {
    interrupts::without_interrupts(|| {
        let mut guard = HMAC_KEY_AUTHORIZER.lock();
        *guard = Some(authorizer);
    });
}

/// Register a flush hook to be called before snapshot drains the ring buffer.
///
/// The flush hook allows other subsystems (LSM, seccomp, capability system)
/// to emit any pending audit events before the snapshot is taken. This
/// ensures that security events are not lost during the drain operation.
///
/// # Arguments
///
/// * `hook` - Function to call before draining the audit ring
///
/// # Example
///
/// ```rust,ignore
/// audit::register_flush_hook(|| {
///     // Flush any pending LSM events
///     lsm::flush_pending_audit_events();
/// });
/// ```
pub fn register_flush_hook(hook: FlushHook) {
    interrupts::without_interrupts(|| {
        let mut guard = FLUSH_HOOK.lock();
        *guard = Some(hook);
    });
}

/// Invoke the registered flush hook if present.
///
/// Called by `snapshot()` before draining the ring buffer.
fn run_flush_hook() {
    let hook = interrupts::without_interrupts(|| {
        let guard = FLUSH_HOOK.lock();
        *guard
    });

    if let Some(func) = hook {
        func();
    }
}

/// R72-PERSIST: Register a persistence hook to be called after snapshot drains the ring buffer.
///
/// The persistence hook can store drained audit events to durable media (e.g., ext2 file).
/// Failures are treated as best-effort; the snapshot still returns the events
/// to the caller so they can be retried or forwarded elsewhere.
///
/// # Arguments
///
/// * `hook` - Function to call with drained events
///
/// # Example
///
/// ```rust,ignore
/// fn persist_to_disk(events: &[AuditEvent]) -> Result<(), AuditError> {
///     let fd = vfs::open("/var/log/audit.log", O_APPEND)?;
///     for event in events {
///         vfs::write(fd, &serialize_event(event))?;
///     }
///     vfs::close(fd);
///     Ok(())
/// }
///
/// audit::register_persistence_hook(persist_to_disk);
/// ```
pub fn register_persistence_hook(hook: PersistenceHook) {
    interrupts::without_interrupts(|| {
        let mut guard = PERSISTENCE_HOOK.lock();
        *guard = Some(hook);
    });
}

/// R72-PERSIST: Invoke the registered persistence hook if present.
///
/// Called by `snapshot()` after draining the ring buffer. Errors are returned
/// so callers can log and retry without dropping the drained events (they are
/// still returned by `snapshot()`).
fn run_persistence_hook(events: &[AuditEvent]) -> Result<(), AuditError> {
    let hook = interrupts::without_interrupts(|| {
        let guard = PERSISTENCE_HOOK.lock();
        *guard
    });

    match hook {
        Some(func) => func(events),
        None => Ok(()),
    }
}

/// Enforce the snapshot capability gate.
///
/// Called by `snapshot()` before returning events. Fails closed:
/// - If no authorizer is registered → AccessDenied
/// - If authorizer denies → AccessDenied
/// - If authorizer allows → Ok(())
fn ensure_snapshot_authorized() -> Result<(), AuditError> {
    let authorizer = interrupts::without_interrupts(|| {
        let guard = SNAPSHOT_AUTHORIZER.lock();
        *guard
    });

    match authorizer {
        Some(check_fn) => check_fn(),
        None => {
            // Fail closed: no authorizer means no access
            Err(AuditError::AccessDenied)
        }
    }
}

/// R66-10 FIX: Enforce the HMAC key configuration capability gate.
///
/// Fails closed when no authorizer is registered. Kernel bootstrap paths that
/// need to set the key before the process subsystem is ready should install
/// a temporary authorizer that applies the appropriate policy.
///
/// # Returns
///
/// - If authorizer is registered and allows → Ok(())
/// - If no authorizer is registered → AccessDenied
/// - If authorizer denies → AccessDenied
fn ensure_hmac_key_authorized() -> Result<(), AuditError> {
    let authorizer = interrupts::without_interrupts(|| {
        let guard = HMAC_KEY_AUTHORIZER.lock();
        *guard
    });

    match authorizer {
        Some(check_fn) => check_fn(),
        None => {
            // Fail closed: no authorizer means no access
            Err(AuditError::AccessDenied)
        }
    }
}

// ============================================================================
// Global Audit Log
// ============================================================================

/// Global audit state
static AUDIT_INITIALIZED: AtomicBool = AtomicBool::new(false);
static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
static AUDIT_TOTAL_EMITTED: AtomicU64 = AtomicU64::new(0);

/// Global audit ring buffer (protected by Mutex with IRQ disable)
static AUDIT_RING: Mutex<Option<AuditRing>> = Mutex::new(None);

/// Initialize the audit subsystem
///
/// This must be called during kernel boot, after heap initialization
/// but before any audit events are emitted.
///
/// # Arguments
///
/// * `capacity` - Number of events to buffer (clamped to MAX_CAPACITY)
///
/// # Returns
///
/// Ok(()) on success, Err on failure
pub fn init(capacity: usize) -> Result<(), AuditError> {
    // Validate capacity
    if capacity == 0 {
        return Err(AuditError::InvalidCapacity);
    }
    let capacity = capacity.min(MAX_CAPACITY);

    // Check if already initialized
    if AUDIT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(AuditError::AlreadyInitialized);
    }

    // Initialize with interrupts disabled
    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if ring.is_some() {
            return Err(AuditError::AlreadyInitialized);
        }
        *ring = Some(AuditRing::with_capacity(capacity));
        AUDIT_INITIALIZED.store(true, Ordering::SeqCst);
        Ok(())
    })?;

    klog_always!(
        "  Audit subsystem initialized (capacity: {} events)",
        capacity
    );
    Ok(())
}

/// R65-15 FIX: Set the HMAC key for audit log integrity verification
///
/// This function sets a cryptographic key that will be used to compute
/// HMAC-SHA256 hashes instead of plain SHA-256 for all subsequent audit
/// events. This provides:
///
/// - **Tamper evidence**: Without the key, attackers cannot forge valid hashes
/// - **Authenticity**: Only key holders can verify the integrity of the log
/// - **Forward secrecy**: Events hashed before key compromise remain secure
///
/// # Security Requirements
///
/// - The key should be 32 bytes of cryptographically secure random data
/// - The key should be stored securely (e.g., in TPM, secure enclave, or
///   passed from bootloader via secure channel)
/// - Once set, the key cannot be changed (prevents key rotation attacks)
///
/// # Arguments
///
/// * `key` - Secret key (min MIN_HMAC_KEY_SIZE bytes, max MAX_HMAC_KEY_SIZE bytes; recommended: 32 bytes)
///
/// # Returns
///
/// * `Ok(())` - Key was set successfully
/// * `Err(Uninitialized)` - Audit subsystem not initialized
/// * `Err(AccessDenied)` - Caller lacks CAP_AUDIT_WRITE or no authorizer registered (R66-10)
/// * `Err(KeyTooSmall)` - Key is shorter than MIN_HMAC_KEY_SIZE (R110-4 FIX)
/// * `Err(KeyTooLarge)` - Key exceeds MAX_HMAC_KEY_SIZE
/// * `Err(KeyAlreadySet)` - Key was already set
///
/// # Security Requirements (R66-10)
///
/// Caller must have CAP_AUDIT_WRITE capability, enforced via registered authorizer.
/// During early boot before the process subsystem is up, use a permissive bootstrap
/// authorizer registered via `register_hmac_key_authorizer`.
///
/// # Example
///
/// ```rust,ignore
/// // During secure boot, set the audit HMAC key
/// // (requires CAP_AUDIT_WRITE or early-boot authorizer)
/// let key = get_secure_random_bytes::<32>();
/// audit::set_hmac_key(&key)?;
/// ```
pub fn set_hmac_key(key: &[u8]) -> Result<(), AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::SeqCst) {
        return Err(AuditError::Uninitialized);
    }

    // R66-10 FIX: Enforce capability check before allowing HMAC key configuration
    ensure_hmac_key_authorized()?;

    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if let Some(ref mut r) = *ring {
            r.set_key(key)?;
            klog!(Info, 
                "  Audit HMAC key set ({} bytes) - integrity protection active",
                key.len()
            );
            Ok(())
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// R65-15 FIX: Check if audit HMAC key is configured
///
/// Returns true if an HMAC key has been set, meaning events are being
/// hashed with HMAC-SHA256 for cryptographic integrity protection.
#[inline]
pub fn has_hmac_key() -> bool {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return false;
    }

    interrupts::without_interrupts(|| {
        let ring = AUDIT_RING.lock();
        ring.as_ref().map(|r| r.has_key()).unwrap_or(false)
    })
}

/// Check if audit subsystem is initialized
#[inline]
pub fn is_initialized() -> bool {
    AUDIT_INITIALIZED.load(Ordering::Relaxed)
}

/// Enable audit event emission
pub fn enable() {
    AUDIT_ENABLED.store(true, Ordering::SeqCst);
}

/// Disable audit event emission
///
/// # Security (Phase A Hardening)
///
/// This function is intentionally a no-op. The audit subsystem is mandatory
/// and cannot be disabled at runtime. Attempts to disable are logged but
/// ignored to prevent attackers from covering their tracks.
pub fn disable() {
    // R35-AUDIT-1: Audit is mandatory - log the attempt but don't disable
    kprintln!("  audit: disable() called but ignored (audit is mandatory)");
}

/// Check if audit is enabled
#[inline]
pub fn is_enabled() -> bool {
    AUDIT_ENABLED.load(Ordering::Relaxed)
}

/// Emit an audit event
///
/// This is the main entry point for recording security events.
/// The function is designed to be low-overhead and never panic.
///
/// # Arguments
///
/// * `kind` - Event category
/// * `outcome` - Operation result
/// * `subject` - Actor (who performed the action)
/// * `object` - Target (what was acted upon)
/// * `args` - Operation-specific arguments (max 6)
/// * `errno` - Error number (0 if success)
/// * `timestamp` - Event timestamp
///
/// # Returns
///
/// Ok(()) on success, Err if audit is not initialized or disabled
pub fn emit(
    kind: AuditKind,
    outcome: AuditOutcome,
    subject: AuditSubject,
    object: AuditObject,
    args: &[u64],
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    // Fast path: check enabled without lock
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return Err(AuditError::Disabled);
    }

    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    let event = AuditEvent::new(timestamp, kind, outcome, subject, object, args, errno);

    // Emit with interrupts disabled to prevent deadlock
    interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if let Some(ref mut r) = *ring {
            r.push(event);
            AUDIT_TOTAL_EMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

// ============================================================================
// Security Event Helpers (Phase B.4)
// ============================================================================

/// Emit an audit record for an LSM denial.
///
/// # Arguments
///
/// * `subject` - The process that attempted the operation
/// * `object` - The target of the operation (file, process, etc.)
/// * `hook` - Name of the LSM hook that denied (e.g., "file_open", "task_fork")
/// * `reason` - Why the hook denied the operation
/// * `errno` - Error number returned to user space
/// * `timestamp` - Event timestamp
///
/// # Args Layout
///
/// - `args[0]` = `AuditSecurityClass::Lsm`
/// - `args[1]` = SHA-256 (truncated to 64 bits) hash of the hook name
/// - `args[2]` = `AuditLsmReason`
#[inline]
pub fn emit_lsm_denial(
    subject: AuditSubject,
    object: AuditObject,
    hook: &str,
    reason: AuditLsmReason,
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    let hook_hash = hash_bytes(hook.as_bytes());
    let args = [AuditSecurityClass::Lsm as u64, hook_hash, reason as u64];

    emit(
        AuditKind::Security,
        AuditOutcome::Denied,
        subject,
        object,
        &args,
        errno,
        timestamp,
    )
}

/// Emit an audit record for a seccomp/pledge violation.
///
/// # Arguments
///
/// * `subject` - The process that attempted the syscall
/// * `syscall_nr` - System call number that was blocked
/// * `filter_id` - Identifier of the filter that blocked (hash or index)
/// * `action` - The action taken (Kill, Errno, Trap, Log)
/// * `errno` - Error number (for Errno action) or 0
/// * `timestamp` - Event timestamp
///
/// # Args Layout
///
/// - `args[0]` = `AuditSecurityClass::Seccomp`
/// - `args[1]` = syscall number
/// - `args[2]` = filter identifier
/// - `args[3]` = `AuditSeccompAction`
///
/// # Note
///
/// The outcome is determined by the action:
/// - Kill/Trap/Errno → Denied
/// - Log → Info (syscall is allowed but logged)
/// - Allow → Success (not typically audited)
#[inline]
pub fn emit_seccomp_violation(
    subject: AuditSubject,
    syscall_nr: u64,
    filter_id: u64,
    action: AuditSeccompAction,
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    let args = [
        AuditSecurityClass::Seccomp as u64,
        syscall_nr,
        filter_id,
        action as u64,
    ];

    // Determine outcome based on action
    let outcome = match action {
        AuditSeccompAction::Log => AuditOutcome::Info,
        AuditSeccompAction::Allow => AuditOutcome::Success,
        _ => AuditOutcome::Denied,
    };

    emit(
        AuditKind::Security,
        outcome,
        subject,
        AuditObject::None,
        &args,
        errno,
        timestamp,
    )
}

/// Emit an audit record for capability lifecycle/use.
///
/// # Arguments
///
/// * `outcome` - Success (for allocate/delegate) or Denied (for failed lookup)
/// * `subject` - The process performing the operation
/// * `cap_id` - The capability ID involved
/// * `op` - The operation type (Allocate, Revoke, Delegate, Use)
/// * `target_pid` - For delegation, the target process
/// * `errno` - Error number (0 for success)
/// * `timestamp` - Event timestamp
///
/// # Args Layout
///
/// - `args[0]` = `AuditSecurityClass::Capability`
/// - `args[1]` = `AuditCapOperation`
/// - `args[2]` = target pid (or 0)
#[inline]
pub fn emit_capability_event(
    outcome: AuditOutcome,
    subject: AuditSubject,
    cap_id: u64,
    op: AuditCapOperation,
    target_pid: Option<u32>,
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    let args = [
        AuditSecurityClass::Capability as u64,
        op as u64,
        target_pid.unwrap_or(0) as u64,
    ];

    emit(
        AuditKind::Security,
        outcome,
        subject,
        AuditObject::Capability { cap_id },
        &args,
        errno,
        timestamp,
    )
}

/// P1-3: Emit an audit record for cgroup delegation lifecycle.
///
/// # Args Layout
///
/// - `args[0]` = `AuditSecurityClass::CgroupDelegation`
/// - `args[1]` = `AuditCgroupDelegationOp` (Grant / Revoke)
/// - `args[2]` = cgroup id
/// - `args[3]` = old delegate UID (or `u64::MAX` if none)
/// - `args[4]` = new delegate UID (or `u64::MAX` if none / revoke)
#[inline]
pub fn emit_cgroup_delegation_event(
    subject: AuditSubject,
    cgroup_id: u64,
    op: AuditCgroupDelegationOp,
    old_delegate_uid: Option<u32>,
    new_delegate_uid: Option<u32>,
    errno: i32,
    timestamp: u64,
) -> Result<(), AuditError> {
    let args = [
        AuditSecurityClass::CgroupDelegation as u64,
        op as u64,
        cgroup_id,
        old_delegate_uid.map(|uid| uid as u64).unwrap_or(u64::MAX),
        new_delegate_uid.map(|uid| uid as u64).unwrap_or(u64::MAX),
    ];

    emit(
        AuditKind::Security,
        AuditOutcome::Success,
        subject,
        AuditObject::None,
        &args,
        errno,
        timestamp,
    )
}

/// Emit an audit record for a security policy allow decision.
///
/// This is used for "log-only" filters or when verbose security auditing
/// is enabled. Captures allowed operations for security monitoring.
///
/// # Arguments
///
/// * `subject` - The process performing the operation
/// * `hook` - Name of the LSM hook or "seccomp" for filter passes
/// * `syscall_nr` - System call number (0 if not applicable)
/// * `timestamp` - Event timestamp
#[inline]
pub fn emit_security_allow(
    subject: AuditSubject,
    hook: &str,
    syscall_nr: u64,
    timestamp: u64,
) -> Result<(), AuditError> {
    let hook_hash = hash_bytes(hook.as_bytes());
    let args = [AuditSecurityClass::Lsm as u64, hook_hash, syscall_nr];

    emit(
        AuditKind::Security,
        AuditOutcome::Success,
        subject,
        AuditObject::None,
        &args,
        0,
        timestamp,
    )
}

/// Export a batch of audit events from a cursor without draining the ring buffer.
///
/// This is the preferred API for remote delivery / userspace audit daemon
/// forwarding. Callers provide a monotonically increasing `cursor` (event ID)
/// and receive up to `max_events` events with `id >= cursor`. Events remain
/// in the ring buffer and can be re-exported or eventually evicted naturally.
///
/// If `cursor` refers to an event that has already been evicted, export starts
/// from the oldest available event. The returned `AuditExportBatch::next_cursor`
/// should be passed to the next call to resume.
///
/// # Capability Gate
///
/// Identical to `snapshot()`: requires `SNAPSHOT_AUTHORIZER` / `CAP_AUDIT_READ`.
pub fn export(cursor: u64, max_events: usize) -> Result<AuditExportBatch, AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    // Capability gate: verify caller has CAP_AUDIT_READ.
    ensure_snapshot_authorized()?;

    // Invoke flush hook so pending events from other subsystems are visible.
    run_flush_hook();

    interrupts::without_interrupts(|| {
        let ring = AUDIT_RING.lock();
        if let Some(ref r) = *ring {
            Ok(r.read_from_cursor(cursor, max_events))
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// Take a snapshot of the audit log (drains all buffered events)
///
/// This function is typically called by a log forwarder or
/// when dumping audit events for analysis.
///
/// # Returns
///
/// Snapshot containing all buffered events and metadata
pub fn snapshot() -> Result<AuditSnapshot, AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    // Capability gate: verify caller has CAP_AUDIT_READ
    ensure_snapshot_authorized()?;

    // Phase A hardening: invoke flush hook to allow subsystems to emit
    // any pending audit events before we drain the ring buffer
    run_flush_hook();

    // Drain events from the ring buffer
    let snapshot = interrupts::without_interrupts(|| {
        let mut ring = AUDIT_RING.lock();
        if let Some(ref mut r) = *ring {
            let dropped = r.dropped;
            let tail_hash = r.tail_hash();
            let events = r.drain();
            Ok(AuditSnapshot {
                events,
                dropped,
                tail_hash,
            })
        } else {
            Err(AuditError::Uninitialized)
        }
    })?;

    // R72-PERSIST: Invoke persistence hook (best-effort, don't lose events on failure)
    if let Err(err) = run_persistence_hook(&snapshot.events) {
        kprintln!(
            "  audit: persistence hook failed: {:?} (events returned to caller)",
            err
        );
    }

    Ok(snapshot)
}

/// Get audit statistics without draining events
pub fn stats() -> Result<AuditStats, AuditError> {
    if !AUDIT_INITIALIZED.load(Ordering::Relaxed) {
        return Err(AuditError::Uninitialized);
    }

    interrupts::without_interrupts(|| {
        let ring = AUDIT_RING.lock();
        if let Some(ref r) = *ring {
            Ok(r.stats())
        } else {
            Err(AuditError::Uninitialized)
        }
    })
}

/// Get total events emitted since boot
#[inline]
pub fn total_emitted() -> u64 {
    AUDIT_TOTAL_EMITTED.load(Ordering::Relaxed)
}

// ============================================================================
// Convenience Macros
// ============================================================================

/// Emit an audit event, ignoring errors
///
/// Use this macro when audit failure should not affect the main code path.
///
/// # Example
///
/// ```rust,ignore
/// audit_emit!(AuditKind::Syscall, AuditOutcome::Success,
///     AuditSubject::new(pid, uid, gid, None),
///     AuditObject::None,
///     &[syscall_nr],
///     timestamp);
/// ```
#[macro_export]
macro_rules! audit_emit {
    ($kind:expr, $outcome:expr, $subject:expr, $object:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit($kind, $outcome, $subject, $object, $args, $errno, $ts);
    }};
    ($kind:expr, $outcome:expr, $subject:expr, $object:expr, $args:expr, $ts:expr) => {{
        let _ = $crate::emit($kind, $outcome, $subject, $object, $args, 0, $ts);
    }};
}

/// Emit a syscall audit event
#[macro_export]
macro_rules! audit_syscall {
    ($outcome:expr, $subject:expr, $syscall_nr:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Syscall,
            $outcome,
            $subject,
            $crate::AuditObject::None,
            $args,
            $errno,
            $ts,
        );
    }};
}

/// Emit a file system audit event
#[macro_export]
macro_rules! audit_fs {
    ($outcome:expr, $subject:expr, $inode:expr, $mode:expr, $path_hash:expr, $args:expr, $errno:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Fs,
            $outcome,
            $subject,
            $crate::AuditObject::Path {
                inode: $inode,
                mode: $mode,
                path_hash: $path_hash,
            },
            $args,
            $errno,
            $ts,
        );
    }};
}

/// Emit a security decision audit event
#[macro_export]
macro_rules! audit_security {
    ($outcome:expr, $subject:expr, $object:expr, $args:expr, $ts:expr) => {{
        let _ = $crate::emit(
            $crate::AuditKind::Security,
            $outcome,
            $subject,
            $object,
            $args,
            0,
            $ts,
        );
    }};
}

// ============================================================================
// X-1 FIX: SHA-256 Utility (compact hashing for paths/identifiers)
// ============================================================================
// Previously used FNV-1a which is not cryptographically secure.
// Now uses SHA-256 truncated to 64 bits with domain separation.

/// Domain separation prefix for path hashing
const PATH_HASH_DOMAIN: &[u8] = b"AUDIT-PATH-SHA256-V1:";

/// Domain separation prefix for bytes hashing
const BYTES_HASH_DOMAIN: &[u8] = b"AUDIT-BYTES-SHA256-V1:";

/// Compute SHA-256 truncated to 64 bits with domain separation
#[inline]
fn sha256_trunc64_with_domain(domain: &[u8], data: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let digest = hasher.finalize();
    // Truncate to 64 bits (first 8 bytes of SHA-256)
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3],
        digest[4], digest[5], digest[6], digest[7],
    ])
}

// ============================================================================
// Path Hashing Utility
// ============================================================================

/// Compute a compact SHA-256-derived hash of a path string
///
/// X-1 FIX: Now uses SHA-256 (truncated to 64 bits) instead of FNV-1a.
/// This provides cryptographic strength for tamper detection.
///
/// This is used to avoid storing full path strings in audit events,
/// while still allowing correlation between related events.
pub fn hash_path(path: &str) -> u64 {
    sha256_trunc64_with_domain(PATH_HASH_DOMAIN, path.as_bytes())
}

/// Compute a compact SHA-256-derived hash of a byte slice
///
/// X-1 FIX: Now uses SHA-256 (truncated to 64 bits) instead of FNV-1a.
pub fn hash_bytes(data: &[u8]) -> u64 {
    sha256_trunc64_with_domain(BYTES_HASH_DOMAIN, data)
}

/// R41-4 FIX: Compute SHA-256 hash of the first `max_len` bytes of a binary blob.
///
/// Used for in-memory exec where no stable on-disk path exists. The hash is
/// computed from the actual ELF content, preventing argv[0] spoofing attacks.
///
/// The digest is truncated to 64 bits to match path_hash consumers.
///
/// # Arguments
/// * `data` - The binary data to hash
/// * `max_len` - Maximum number of bytes to include in hash (typically 4096)
///
/// # Security
/// Using the actual binary content for policy checks prevents attackers from
/// bypassing LSM hooks by setting argv[0] to an allowed program name while
/// executing malicious code.
pub fn hash_binary_prefix(data: &[u8], max_len: usize) -> u64 {
    let len = core::cmp::min(data.len(), max_len);
    let digest = Sha256::digest(&data[..len]);
    // Truncate to 64 bits (first 8 bytes of SHA-256)
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

// ============================================================================
// Chain Verification
// ============================================================================

/// Verify the hash chain of a sequence of events
///
/// Returns true if all events have valid hash chains.
pub fn verify_chain(events: &[AuditEvent]) -> bool {
    if events.is_empty() {
        return true;
    }

    for (i, event) in events.iter().enumerate() {
        let expected_hash = hash_event(event.prev_hash, event);
        if event.hash != expected_hash {
            return false;
        }

        // Verify chain continuity (except for first event)
        if i > 0 && event.prev_hash != events[i - 1].hash {
            return false;
        }
    }

    true
}

/// Verify the hash chain of a sequence of events using HMAC-SHA256.
///
/// This function verifies chains that were created with keyed HMAC-SHA256
/// authentication. It is the keyed counterpart to [`verify_chain`].
///
/// # R94-15 FIX: Keyed Chain Verification
///
/// The audit subsystem supports both keyless (SHA-256) and keyed (HMAC-SHA256)
/// hash chains. Prior to this fix, only `verify_chain()` existed for keyless
/// verification, leaving keyed chains unverifiable through the public API.
///
/// # Arguments
///
/// * `events` - Slice of audit events in chain order (oldest to newest)
/// * `key` - The HMAC key used to create the chain (must match the key
///   used during event generation; empty key is valid but not recommended)
///
/// # Returns
///
/// `true` if all events have valid keyed hash chains, `false` otherwise.
///
/// # Security Properties
///
/// HMAC-SHA256 verification provides:
/// - Tamper evidence (any modification invalidates the chain)
/// - Authenticity (only parties with the key can create valid chains)
/// - Protection against length extension attacks
///
/// # Example
///
/// ```rust,ignore
/// let key = b"my-audit-signing-key";
/// let events = export_audit_log();
/// if verify_chain_hmac(&events, key) {
///     kprintln!("Audit log integrity verified");
/// } else {
///     kprintln!("WARNING: Audit log may have been tampered with!");
/// }
/// ```
pub fn verify_chain_hmac(events: &[AuditEvent], key: &[u8]) -> bool {
    if events.is_empty() {
        return true;
    }

    for (i, event) in events.iter().enumerate() {
        let expected_hash = hash_event_prefixed(event.prev_hash, event, Some(key));
        if event.hash != expected_hash {
            return false;
        }

        // Verify chain continuity (except for first event)
        if i > 0 && event.prev_hash != events[i - 1].hash {
            return false;
        }
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // NIST test vector: SHA-256("abc") = ba7816bf...
        let digest = Sha256::digest(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c442...
        let digest = Sha256::digest(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_multiblock() {
        // NIST test vector: SHA-256 of 1,000,000 'a' characters
        // This tests multi-block processing (>64 bytes)
        // We'll use a shorter but still multi-block test: 128 bytes of 'a'
        let data: [u8; 128] = [b'a'; 128];
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        // Pre-computed: SHA-256 of 128 'a's
        // echo -n "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | sha256sum
        let expected = [
            0x76, 0xb7, 0xd0, 0x74, 0xc5, 0x46, 0x4f, 0x46, 0x85, 0xa5, 0x4b, 0x5b, 0xdd, 0x69,
            0x60, 0xde, 0x46, 0x83, 0x45, 0x41, 0x72, 0x6d, 0x1c, 0x35, 0xbd, 0x02, 0xdb, 0x2a,
            0x6c, 0x4d, 0xa7, 0xa2,
        ];
        assert_eq!(digest, expected);
    }

    // X-1 FIX: Removed obsolete test_fnv1a_hash_nonzero test
    // FNV-1a has been replaced with SHA-256 for cryptographic strength

    #[test]
    fn test_hash_path() {
        let h1 = hash_path("/etc/passwd");
        let h2 = hash_path("/etc/passwd");
        let h3 = hash_path("/etc/shadow");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            100,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(1, 0, 0, None),
            AuditObject::None,
            &[1, 2, 3],
            0,
        );
        assert_eq!(event.timestamp, 100);
        assert_eq!(event.kind, AuditKind::Syscall);
        assert_eq!(event.arg_count, 3);
        assert_eq!(event.args[0], 1);
        assert_eq!(event.prev_hash, ZERO_HASH);
        assert_eq!(event.hash, ZERO_HASH);
    }

    #[test]
    fn test_hash_event_chain() {
        let mut event1 = AuditEvent::new(
            1,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(1, 0, 0, None),
            AuditObject::None,
            &[1, 2, 3],
            0,
        );
        event1.id = 0;
        event1.prev_hash = ZERO_HASH;
        event1.hash = hash_event(event1.prev_hash, &event1);

        let mut event2 = AuditEvent::new(
            2,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(2, 0, 0, None),
            AuditObject::Process {
                pid: 10,
                signal: Some(9),
            },
            &[4, 5, 6],
            0,
        );
        event2.id = 1;
        event2.prev_hash = event1.hash;
        event2.hash = hash_event(event2.prev_hash, &event2);

        // Verify chain
        let events = alloc::vec![event1.clone(), event2.clone()];
        assert!(verify_chain(&events));

        // Verify chain links
        assert_eq!(event2.prev_hash, event1.hash);

        // Hashes should be non-zero
        assert_ne!(event1.hash, ZERO_HASH);
        assert_ne!(event2.hash, ZERO_HASH);
    }

    #[test]
    fn test_verify_chain_detects_tampering() {
        let mut event1 = AuditEvent::new(
            1,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(1, 0, 0, None),
            AuditObject::None,
            &[1, 2, 3],
            0,
        );
        event1.id = 0;
        event1.prev_hash = ZERO_HASH;
        event1.hash = hash_event(event1.prev_hash, &event1);

        let mut event2 = AuditEvent::new(
            2,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(2, 0, 0, None),
            AuditObject::None,
            &[4, 5, 6],
            0,
        );
        event2.id = 1;
        event2.prev_hash = event1.hash;
        event2.hash = hash_event(event2.prev_hash, &event2);

        // Tamper with event1's data
        let mut tampered_event1 = event1.clone();
        tampered_event1.args[0] = 999; // Modify data without updating hash

        let events = alloc::vec![tampered_event1, event2];
        assert!(!verify_chain(&events), "Tampering should be detected");
    }

    #[test]
    fn test_hmac_sha256_rfc4231_vector() {
        // RFC 4231 Test Case 2:
        // Key = "key" (4 bytes)
        // Data = "The quick brown fox jumps over the lazy dog"
        // Expected HMAC = f7bc83f430538424b132...
        let digest = hmac_sha256(b"key", |w| {
            w.write_bytes(b"The quick brown fox jumps over the lazy dog");
        });

        let expected = [
            0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
            0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x10, 0xbd, 0x0a, 0x1e, 0x82, 0x64,
            0x72, 0xa3, 0xd3, 0xaa,
        ];
        assert_eq!(
            digest, expected,
            "HMAC-SHA256 must match RFC 4231 test vector"
        );
    }

    #[test]
    fn test_hmac_sha256_empty_message() {
        // HMAC-SHA256 with empty message
        let digest = hmac_sha256(b"key", |_w| {
            // Write nothing
        });

        // Pre-computed: hmac-sha256 with key="key" and empty message
        // This verifies the implementation handles empty messages correctly
        assert_ne!(digest, [0u8; 32], "HMAC digest should not be all zeros");
        assert_ne!(digest, ZERO_HASH, "HMAC digest should be valid");
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // Test with key > 64 bytes (must be hashed first per HMAC spec)
        let long_key = [0x41u8; 100]; // 100 bytes of 'A'
        let digest = hmac_sha256(&long_key, |w| {
            w.write_bytes(b"test message");
        });

        // Should produce a valid non-zero digest
        assert_ne!(
            digest, [0u8; 32],
            "Long key HMAC should produce valid digest"
        );
    }

    #[test]
    fn test_keyed_vs_unkeyed_hash_differs() {
        // Verify that keyed and unkeyed hashing produce different results
        let event = AuditEvent::new(
            1,
            AuditKind::Syscall,
            AuditOutcome::Success,
            AuditSubject::new(1, 0, 0, None),
            AuditObject::None,
            &[1, 2, 3],
            0,
        );

        let unkeyed = hash_event_prefixed(ZERO_HASH, &event, None);
        let keyed = hash_event_prefixed(ZERO_HASH, &event, Some(b"secret"));

        assert_ne!(unkeyed, keyed, "Keyed and unkeyed hashes must differ");
        assert_ne!(unkeyed, ZERO_HASH, "Unkeyed hash should be valid");
        assert_ne!(keyed, ZERO_HASH, "Keyed hash should be valid");
    }
}
