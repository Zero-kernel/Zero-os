//! Mount Namespace Support
//!
//! Implements Linux-compatible mount namespaces for filesystem isolation.
//!
//! # Overview
//!
//! Mount namespaces provide isolated filesystem views. Each namespace has:
//! - Its own mount table (independent of parent after CLONE_NEWNS)
//! - A hierarchical relationship with parent namespaces (for depth limiting)
//! - Copy-on-write semantics: CLONE_NEWNS copies the entire mount table
//!
//! # Architecture
//!
//! The MountNamespace structure is defined here in kernel_core to avoid
//! circular dependencies. The actual mount table with FileSystem references
//! is managed by the VFS layer, which uses the namespace ID as a key.
//!
//! # Key Differences from PID Namespace
//!
//! Unlike PID namespaces:
//! - No cross-namespace visibility (parent cannot see child's mounts)
//! - No PID translation (paths are always resolved in current namespace)
//! - No init/cascade-kill semantics
//! - Full copy of mount table on CLONE_NEWNS (not shared references)

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use alloc::boxed::Box;
use cap::NamespaceId;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::process::FileOps;

// ============================================================================
// Constants
// ============================================================================

/// Maximum mount namespace nesting depth (Linux default is 32)
pub const MAX_MNT_NS_LEVEL: u8 = 32;

// ============================================================================
// Mount Flags
// ============================================================================

bitflags::bitflags! {
    /// Mount flags controlling filesystem behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MountFlags: u64 {
        /// Mount read-only (MS_RDONLY)
        const RDONLY  = 1 << 0;
        /// Ignore setuid/setgid bits (MS_NOSUID)
        const NOSUID  = 1 << 1;
        /// Disallow access to device special files (MS_NODEV)
        const NODEV   = 1 << 2;
        /// Disallow program execution (MS_NOEXEC)
        const NOEXEC  = 1 << 3;
        /// Do not update access times (MS_NOATIME)
        const NOATIME = 1 << 4;
        /// Update atime only if mtime/ctime changed (MS_RELATIME)
        const RELATIME = 1 << 5;
        /// Perform a bind mount (MS_BIND)
        const BIND    = 1 << 12;
        /// Recursively apply to submounts (MS_REC)
        const REC     = 1 << 14;
        /// Make mount private (MS_PRIVATE)
        const PRIVATE = 1 << 18;
        /// Make mount shared (MS_SHARED)
        const SHARED  = 1 << 20;
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during mount namespace operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountNsError {
    /// Maximum namespace nesting depth exceeded
    MaxDepthExceeded,
    /// Namespace is shutting down
    NamespaceShuttingDown,
    /// Mount point already exists at the specified path
    MountExists,
    /// Mount point not found at the specified path
    MountNotFound,
    /// Mount is busy (open files or submounts)
    MountBusy,
    /// Invalid mount path (must be absolute)
    InvalidPath,
    /// Operation requires elevated privileges
    PermissionDenied,
    /// Filesystem type not supported
    FsTypeNotSupported,
    /// Out of memory
    NoMemory,
}

// ============================================================================
// Mount Namespace
// ============================================================================

/// A mount namespace providing isolated filesystem views.
///
/// This structure contains only the namespace identity and hierarchy.
/// The actual mount table is managed by the VFS layer using the namespace ID.
///
/// # Lifecycle
///
/// Lifecycle management is handled by `Arc` reference counting.
/// No manual refcount is needed — `Arc::strong_count()` serves this role.
pub struct MountNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<MountNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Root mount path for this namespace (usually "/")
    root_path: RwLock<String>,
}

impl MountNamespace {
    /// Create the root mount namespace.
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            root_path: RwLock::new("/".to_string()),
        }
    }

    /// Create a new child namespace.
    pub fn new_child(parent: Arc<MountNamespace>) -> Result<Arc<Self>, MountNsError> {
        if parent.level >= MAX_MNT_NS_LEVEL {
            return Err(MountNsError::MaxDepthExceeded);
        }

        let id = NEXT_MNT_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| MountNsError::NoMemory)?;

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            root_path: RwLock::new(parent.root_path.read().clone()),
        });

        Ok(child)
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<MountNamespace>> {
        self.parent.as_ref().map(Arc::clone)
    }

    /// Get the nesting level (0 = root).
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.level == 0
    }

    /// Get the namespace root path.
    #[inline]
    pub fn root_path(&self) -> String {
        self.root_path.read().clone()
    }

    /// Set the namespace root path (for pivot_root/chroot).
    pub fn set_root_path(&self, path: String) {
        *self.root_path.write() = path;
    }

}

impl core::fmt::Debug for MountNamespace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .finish()
    }
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// The root mount namespace (level 0, no parent).
    pub static ref ROOT_MNT_NAMESPACE: Arc<MountNamespace> = Arc::new(MountNamespace::new_root());

    /// Counter for generating unique namespace IDs.
    static ref NEXT_MNT_NS_ID: AtomicU64 = AtomicU64::new(1);
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize and return the root mount namespace.
pub fn init() -> Arc<MountNamespace> {
    ROOT_MNT_NAMESPACE.clone()
}

/// Create a new child namespace (for CLONE_NEWNS).
pub fn clone_namespace(parent: Arc<MountNamespace>) -> Result<Arc<MountNamespace>, MountNsError> {
    MountNamespace::new_child(parent)
}

/// Print namespace information for debugging.
pub fn print_namespace_info(ns: &Arc<MountNamespace>) {
    kprintln!(
        "[MNT NS] id={}, level={}, arc_refs={}",
        ns.id().raw(),
        ns.level(),
        Arc::strong_count(ns)
    );
}

// ============================================================================
// Mount Namespace File Descriptor
// ============================================================================

/// File descriptor wrapper for a mount namespace (used by setns).
///
/// This allows a mount namespace to be referenced via a file descriptor,
/// enabling sys_setns to switch to a different mount namespace.
pub struct MountNamespaceFd {
    ns: Arc<MountNamespace>,
}

impl MountNamespaceFd {
    /// Create a new file descriptor wrapper for a mount namespace.
    pub fn new(ns: Arc<MountNamespace>) -> Self {
        Self { ns }
    }

    /// Get the underlying mount namespace.
    pub fn namespace(&self) -> Arc<MountNamespace> {
        self.ns.clone()
    }
}

impl FileOps for MountNamespaceFd {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(Self {
            ns: self.ns.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "mount_namespace_fd"
    }
}
