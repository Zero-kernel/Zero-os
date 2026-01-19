//! Core capability types for Zero-OS.
//!
//! Provides CapId encoding, rights/flags bitmasks, capability objects, and
//! table entry metadata. Generation counters are encoded in the high 32 bits
//! of CapId to defend against use-after-free on slot reuse.
//!
//! # Design Rationale
//!
//! 1. **Generation Counter**: Prevents use-after-free when CapId slots are reused.
//!    Each time a capability is revoked, the generation counter increments,
//!    invalidating any stale CapId references.
//!
//! 2. **Rights Model**: Capabilities carry explicit rights that can only be
//!    reduced (never expanded) during delegation.
//!
//! 3. **Flags**: Control fork/exec behavior (CLOEXEC, CLOFORK) for secure
//!    process inheritance semantics.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt;

// ============================================================================
// Local Type Definitions (to avoid cyclic dependency with kernel_core)
// ============================================================================

/// Process identifier type (matches kernel_core::ProcessId)
pub type ProcessId = usize;

/// File operations trait (matches kernel_core::FileOps)
///
/// This is a local definition to avoid cyclic dependency with kernel_core.
/// The trait must be implemented identically in kernel_core for interop.
pub trait FileOps: Send + Sync {
    /// Clone this file descriptor (for fork)
    fn clone_box(&self) -> Box<dyn FileOps>;

    /// Get Any reference for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Get type name (for debugging)
    fn type_name(&self) -> &'static str;
}

impl fmt::Debug for dyn FileOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileOps({})", self.type_name())
    }
}

// ============================================================================
// Namespace Identifier
// ============================================================================

/// Namespace identifier (mount/ipc/net/user/pid/etc.)
///
/// Used to reference isolated namespaces for containerization support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct NamespaceId(pub u64);

impl NamespaceId {
    /// Create a new namespace identifier.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw u64 value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

// ============================================================================
// Capability Identifier
// ============================================================================

/// Capability identifier: high 48 bits = generation, low 16 bits = slot index.
///
/// # Encoding (R29-4 FIX: Extended from 32-bit to 48-bit generation)
///
/// ```text
/// 63              16 15              0
/// +------------------+----------------+
/// |    Generation    |     Index      |
/// |     (48 bits)    |   (16 bits)    |
/// +------------------+----------------+
/// ```
///
/// - **Index**: Slot in per-process CapTable (max 65536 = MAX_CAP_SLOTS)
/// - **Generation**: Incremented on revocation, prevents use-after-free
///
/// With 48-bit generation (~281 trillion allocations before exhaustion),
/// this provides sufficient headroom for long-running systems.
///
/// # Invalid CapId
///
/// A CapId with value 0 (index=0, generation=0) is considered invalid.
/// Valid generations start from 1.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CapId(pub u64);

impl CapId {
    /// Sentinel invalid capability (generation=0 is never used for valid caps).
    pub const INVALID: CapId = CapId(0);

    /// R29-4 FIX: Construct from (index, generation) parts with extended generation.
    ///
    /// # Arguments
    /// * `index` - Slot index (16 bits, max 65535)
    /// * `generation` - Generation counter (48 bits, will be masked)
    ///
    /// # Safety Note
    ///
    /// Caller must ensure generation >= 1 for valid capabilities.
    #[inline]
    pub const fn from_parts(index: u16, generation: u64) -> Self {
        // Mask generation to 48 bits and combine with 16-bit index
        let gen_masked = generation & 0x0000_FFFF_FFFF_FFFF;
        Self((gen_masked << 16) | (index as u64))
    }

    /// R29-4 FIX: Legacy constructor for 32-bit generation (backward compatibility).
    /// Deprecated: Use from_parts with u64 generation instead.
    #[inline]
    pub const fn from_parts_u32(index: u32, generation: u32) -> Self {
        Self::from_parts(index as u16, generation as u64)
    }

    /// Extract slot index (low 16 bits).
    #[inline]
    pub const fn index(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// R29-4 FIX: Extract generation counter (high 48 bits).
    #[inline]
    pub const fn generation(self) -> u64 {
        self.0 >> 16
    }

    /// Get raw u64 backing value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Check if this CapId is valid (non-zero generation).
    #[inline]
    pub const fn is_valid(self) -> bool {
        // Generation 0 is reserved for INVALID
        self.generation() > 0
    }
}

impl fmt::Debug for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapId(gen={}, idx={})", self.generation(), self.index())
    }
}

impl fmt::Display for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.generation(), self.index())
    }
}

// ============================================================================
// Capability Rights
// ============================================================================

bitflags::bitflags! {
    /// Capability rights mask.
    ///
    /// Rights control what operations a capability holder can perform
    /// on the referenced object. Rights can only be reduced during
    /// delegation (monotonic restriction).
    ///
    /// # Standard Rights
    ///
    /// - `READ`: Read data from the object
    /// - `WRITE`: Write data to the object
    /// - `EXEC`: Execute/map as executable
    /// - `IOCTL`: Perform device control operations
    /// - `ADMIN`: Administrative operations (e.g., chmod, chown)
    ///
    /// # Memory Rights
    ///
    /// - `MAP`: mmap the object
    /// - `MAP_EXEC`: mmap with PROT_EXEC (requires EXEC too)
    ///
    /// # Network Rights
    ///
    /// - `BIND`: Bind socket to address
    /// - `CONNECT`: Connect to remote address
    /// - `LISTEN`: Listen for connections
    /// - `ACCEPT`: Accept connections
    ///
    /// # Process Rights
    ///
    /// - `SIGNAL`: Send signals to the process
    /// - `WAIT`: Wait for process termination
    /// - `PTRACE`: Debug/trace the process
    ///
    /// # Special Rights
    ///
    /// - `BYPASS_DAC`: Bypass discretionary access control (root only)
    /// - `BYPASS_MAC`: Bypass mandatory access control (root only)
    #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CapRights: u64 {
        // Generic rights (bits 0-4)
        const READ        = 1 << 0;
        const WRITE       = 1 << 1;
        const EXEC        = 1 << 2;
        const IOCTL       = 1 << 3;
        const ADMIN       = 1 << 4;

        // Memory rights (bits 5-6)
        const MAP         = 1 << 5;
        const MAP_EXEC    = 1 << 6;

        // Network rights (bits 7-10, 14)
        const BIND        = 1 << 7;
        const CONNECT     = 1 << 8;
        const LISTEN      = 1 << 9;
        const ACCEPT      = 1 << 10;
        /// Bind to privileged ports (< 1024). Equivalent to Linux CAP_NET_BIND_SERVICE.
        /// This is an ambient authority checked via has_rights(), not per-socket.
        const NET_BIND_SERVICE = 1 << 14;

        // Process rights (bits 11-13)
        const SIGNAL      = 1 << 11;
        const WAIT        = 1 << 12;
        const PTRACE      = 1 << 13;

        // Special rights (bits 30-31)
        const BYPASS_DAC  = 1 << 30;
        const BYPASS_MAC  = 1 << 31;

        // Audit/logging rights (bits 40-41)
        /// Permission to read/export audit logs via audit::snapshot()
        const AUDIT_READ  = 1 << 40;
        /// R66-10 FIX: Permission to configure audit subsystem (e.g., set HMAC keys)
        const AUDIT_WRITE = 1 << 41;

        // Convenience combinations
        const RW          = Self::READ.bits() | Self::WRITE.bits();
        const RWX         = Self::RW.bits() | Self::EXEC.bits();
        const ALL_SOCKET  = Self::BIND.bits() | Self::CONNECT.bits() | Self::LISTEN.bits() | Self::ACCEPT.bits();
        const ALL_PROCESS = Self::SIGNAL.bits() | Self::WAIT.bits() | Self::PTRACE.bits();
    }
}

impl CapRights {
    /// Check if self contains all `required` rights.
    #[inline]
    pub fn allows(self, required: CapRights) -> bool {
        self.contains(required)
    }

    /// Restrict rights by masking (AND operation).
    ///
    /// Returns a new CapRights that is the intersection of self and mask.
    /// Used for delegation: `delegated_rights = original_rights.restrict(mask)`
    #[inline]
    pub fn restrict(self, mask: CapRights) -> CapRights {
        self & mask
    }
}

impl fmt::Debug for CapRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show as hex with flag names
        write!(f, "CapRights({:#x})", self.bits())
    }
}

// ============================================================================
// Capability Flags
// ============================================================================

bitflags::bitflags! {
    /// Per-capability metadata flags controlling fork/exec behavior.
    ///
    /// These flags determine how capabilities are inherited across
    /// fork() and exec() system calls.
    ///
    /// # Default Behavior
    ///
    /// - **Fork**: Capabilities are inherited (copied to child) by default.
    ///   Set `CLOFORK` to prevent inheritance.
    /// - **Exec**: Capabilities are inherited by default.
    ///   Set `CLOEXEC` to revoke on exec.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CapFlags: u32 {
        /// Close on exec (like FD_CLOEXEC).
        ///
        /// Capability is revoked when the process calls exec().
        /// Default: capability survives exec.
        const CLOEXEC = 1 << 0;

        /// Do NOT inherit on fork.
        ///
        /// When set, capability is NOT copied to child process after fork().
        /// Default (flag absent): capability IS copied to child.
        ///
        /// # Naming Rationale
        ///
        /// The name "CLOFORK" follows CLOEXEC convention: "close on fork".
        /// This is the opposite of typical UNIX fd behavior where fds
        /// are always inherited unless CLOEXEC is set.
        const CLOFORK = 1 << 1;

        /// Path-only capability (like O_PATH).
        ///
        /// Capability can only be used for path operations,
        /// not for read/write. Useful for directory traversal.
        const O_PATH  = 1 << 2;

        /// Capability cannot be delegated.
        ///
        /// Holder cannot transfer this capability to other processes.
        const NOXFER  = 1 << 3;
    }
}

impl fmt::Debug for CapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapFlags({:#x})", self.bits())
    }
}

// ============================================================================
// Capability Object Types
// ============================================================================

/// IPC endpoint identifier (from ipc crate).
pub type EndpointId = u64;

/// Objects referenced by capabilities.
///
/// Each variant represents a different kernel object type that can be
/// protected by capability-based access control.
#[derive(Clone)]
pub enum CapObject {
    /// VFS/fd-backed objects (wraps FileOps for fd_table interop).
    ///
    /// Includes regular files, pipes, sockets, device files, etc.
    File(Arc<dyn FileOps>),

    /// IPC endpoint (message queue endpoint from ipc subsystem).
    Endpoint(EndpointId),

    /// Network socket handle (placeholder until net stack lands).
    Socket(Arc<Socket>),

    /// Shared memory region handle.
    Shm(Arc<Shm>),

    /// Timer handle (for timerfd-like functionality).
    Timer(Arc<Timer>),

    /// Process handle (for process control operations).
    Process(ProcessId),

    /// Namespace handle (mount/net/ipc/pid/user namespaces).
    Namespace(NamespaceId),
}

impl fmt::Debug for CapObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapObject::File(fo) => write!(f, "File({})", fo.type_name()),
            CapObject::Endpoint(id) => write!(f, "Endpoint({})", id),
            CapObject::Socket(_) => write!(f, "Socket"),
            CapObject::Shm(_) => write!(f, "Shm"),
            CapObject::Timer(_) => write!(f, "Timer"),
            CapObject::Process(pid) => write!(f, "Process({})", pid),
            CapObject::Namespace(ns) => write!(f, "Namespace({})", ns.raw()),
        }
    }
}

// ============================================================================
// Capability Entry
// ============================================================================

/// Capability table entry pairing object, rights, and flags.
///
/// This is the internal representation stored in per-process CapTables.
#[derive(Debug, Clone)]
pub struct CapEntry {
    /// The kernel object this capability references.
    pub object: CapObject,

    /// Rights held by this capability.
    pub rights: CapRights,

    /// Behavioral flags (CLOEXEC, CLOFORK, etc.).
    pub flags: CapFlags,
}

impl CapEntry {
    /// Create a new capability entry with empty flags.
    #[inline]
    pub fn new(object: CapObject, rights: CapRights) -> Self {
        Self {
            object,
            rights,
            flags: CapFlags::empty(),
        }
    }

    /// Create a new capability entry with explicit flags.
    #[inline]
    pub fn with_flags(object: CapObject, rights: CapRights, flags: CapFlags) -> Self {
        Self {
            object,
            rights,
            flags,
        }
    }

    /// Check if this capability should be inherited across exec().
    #[inline]
    pub fn inherits_on_exec(&self) -> bool {
        !self.flags.contains(CapFlags::CLOEXEC)
    }

    /// Check if this capability should be inherited across fork().
    #[inline]
    pub fn inherits_on_fork(&self) -> bool {
        !self.flags.contains(CapFlags::CLOFORK)
    }

    /// Check if this capability allows the given rights.
    #[inline]
    pub fn allows(&self, required: CapRights) -> bool {
        self.rights.allows(required)
    }
}

// ============================================================================
// Placeholder Object Handles
// ============================================================================

/// Socket capability handle referencing a socket_table() entry by ID.
///
/// This struct links the capability system to the network socket table.
/// The socket_id corresponds to the `SocketState.id` field in `socket_table()`.
#[derive(Debug, Clone)]
pub struct Socket {
    /// Global socket identifier managed by socket_table()
    pub socket_id: u64,
}

impl Socket {
    /// Create a socket capability handle for a specific socket ID.
    #[inline]
    pub fn new(socket_id: u64) -> Self {
        Self { socket_id }
    }

    /// Create a placeholder socket (socket_id = 0, invalid).
    /// Used for legacy compatibility; new code should use `new()`.
    #[inline]
    pub fn placeholder() -> Self {
        Self { socket_id: 0 }
    }
}

/// Placeholder shared memory handle.
#[derive(Debug, Clone)]
pub struct Shm {
    /// Virtual address of the shared mapping.
    pub vaddr: u64,
    /// Size in bytes.
    pub size: usize,
    // Will contain: physical frames, permissions, etc.
}

impl Shm {
    /// Create a placeholder shared memory region.
    pub fn placeholder() -> Self {
        Self { vaddr: 0, size: 0 }
    }
}

/// Placeholder timer handle (for timerfd-like functionality).
#[derive(Debug, Clone)]
pub struct Timer {
    /// Timer ID.
    pub id: u64,
    // Will contain: interval, expiration, callback, etc.
}

impl Timer {
    /// Create a placeholder timer.
    pub fn placeholder() -> Self {
        Self { id: 0 }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Capability-related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// Invalid capability ID (generation mismatch or never existed).
    InvalidCapId,

    /// Capability lacks required rights for the operation.
    InsufficientRights,

    /// Capability table is full, cannot allocate new slot.
    TableFull,

    /// No current process context (called from kernel thread).
    NoCurrentProcess,

    /// Capability cannot be delegated (NOXFER flag set).
    DelegationDenied,

    /// Invalid operation for this object type.
    InvalidOperation,

    /// Generation counter exhausted after 2^32 allocations (R25-2 fix).
    /// This is a fatal condition - the capability table can no longer be used safely.
    GenerationExhausted,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapError::InvalidCapId => write!(f, "invalid capability ID"),
            CapError::InsufficientRights => write!(f, "insufficient capability rights"),
            CapError::TableFull => write!(f, "capability table full"),
            CapError::NoCurrentProcess => write!(f, "no current process context"),
            CapError::DelegationDenied => write!(f, "capability delegation denied"),
            CapError::InvalidOperation => write!(f, "invalid operation for object type"),
            CapError::GenerationExhausted => write!(f, "capability generation counter exhausted"),
        }
    }
}
