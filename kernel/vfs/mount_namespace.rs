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
//! # Linux Compatibility
//!
//! - CLONE_NEWNS creates a new mount namespace with a copy of parent's mounts
//! - unshare(CLONE_NEWNS) moves the calling process to a new mount namespace
//! - setns() can switch to an existing mount namespace (via fd)
//! - Mounts in child namespaces are invisible to parent namespaces
//!
//! # Key Differences from PID Namespace
//!
//! Unlike PID namespaces:
//! - No cross-namespace visibility (parent cannot see child's mounts)
//! - No PID translation (paths are always resolved in current namespace)
//! - No init/cascade-kill semantics
//! - Full copy of mount table on CLONE_NEWNS (not shared references)
//!
//! # Security
//!
//! - All mount operations require CAP_SYS_ADMIN (or CapRights::ADMIN)
//! - Namespace depth is limited to prevent resource exhaustion
//! - Path resolution is confined to namespace root
//!
//! # Usage
//!
//! ```rust,ignore
//! // Get root namespace
//! let root_ns = mount_namespace::init();
//!
//! // Create a child namespace (CLONE_NEWNS)
//! let child_ns = MountNamespace::new_child(root_ns.clone())?;
//! copy_mounts(&root_ns, &child_ns);
//!
//! // Add a mount to the child namespace
//! add_mount(&child_ns, "/mnt/data".to_string(), mount)?;
//!
//! // Parent cannot see /mnt/data, child can
//! ```

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use cap::NamespaceId;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::traits::FileSystem;

// ============================================================================
// Constants
// ============================================================================

/// Maximum mount namespace nesting depth (Linux default is 32)
///
/// This prevents resource exhaustion attacks via deeply nested namespaces.
pub const MAX_MNT_NS_LEVEL: u8 = 32;

// ============================================================================
// Mount Flags
// ============================================================================

bitflags::bitflags! {
    /// Mount flags controlling filesystem behavior.
    ///
    /// These flags are applied to individual mount points and control
    /// security-relevant behaviors like setuid execution and device access.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Default for MountFlags {
    fn default() -> Self {
        Self::empty()
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
    /// Namespace is shutting down (unused, for future compatibility)
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
// Mount Entry
// ============================================================================

/// A single mount entry in a namespace's mount table.
///
/// Each mount represents a filesystem mounted at a specific path.
/// Mounts are cloned (not shared) when creating child namespaces.
#[derive(Clone)]
pub struct Mount {
    /// Absolute path where this filesystem is mounted
    pub path: String,
    /// The mounted filesystem
    pub fs: Arc<dyn FileSystem>,
    /// Mount flags (read-only, nosuid, etc.)
    pub flags: MountFlags,
    /// Device/source path (e.g., "/dev/sda1", "none" for virtual fs)
    pub source: String,
    /// Filesystem type name (e.g., "ext2", "ramfs", "proc")
    pub fstype: String,
}

impl Mount {
    /// Create a new mount entry.
    pub fn new(
        path: String,
        fs: Arc<dyn FileSystem>,
        flags: MountFlags,
        source: String,
        fstype: String,
    ) -> Self {
        Self {
            path,
            fs,
            flags,
            source,
            fstype,
        }
    }

    /// Check if mount is read-only.
    #[inline]
    pub fn is_readonly(&self) -> bool {
        self.flags.contains(MountFlags::RDONLY)
    }

    /// Check if setuid is disabled on this mount.
    #[inline]
    pub fn is_nosuid(&self) -> bool {
        self.flags.contains(MountFlags::NOSUID)
    }

    /// Check if device access is disabled on this mount.
    #[inline]
    pub fn is_nodev(&self) -> bool {
        self.flags.contains(MountFlags::NODEV)
    }

    /// Check if execution is disabled on this mount.
    #[inline]
    pub fn is_noexec(&self) -> bool {
        self.flags.contains(MountFlags::NOEXEC)
    }
}

impl core::fmt::Debug for Mount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mount")
            .field("path", &self.path)
            .field("source", &self.source)
            .field("fstype", &self.fstype)
            .field("flags", &self.flags)
            .finish()
    }
}

// ============================================================================
// Mount Namespace
// ============================================================================

/// A mount namespace providing isolated filesystem views.
///
/// # Hierarchy
///
/// Mount namespaces form a tree structure:
/// - Root namespace (level 0) has no parent
/// - Child namespaces start with a copy of parent's mount table
/// - Changes in child are invisible to parent
///
/// # Copy-on-Write Semantics
///
/// When CLONE_NEWNS is used, the child receives a complete copy of the
/// parent's mount table. Subsequent mount/umount operations in either
/// namespace do not affect the other.
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

    /// Mount table: path -> Mount
    ///
    /// Key is the absolute mount path (e.g., "/", "/dev", "/proc")
    mounts: RwLock<BTreeMap<String, Mount>>,

    /// Root mount path for this namespace (usually "/")
    ///
    /// Used for pivot_root and chroot operations within the namespace.
    root_path: RwLock<String>,
}

impl MountNamespace {
    /// Create the root mount namespace.
    ///
    /// The root namespace:
    /// - Has level 0
    /// - Has no parent
    /// - Is the default namespace for all processes
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            mounts: RwLock::new(BTreeMap::new()),
            root_path: RwLock::new("/".to_string()),
        }
    }

    /// Create a new child namespace.
    ///
    /// The child namespace:
    /// - Starts with an empty mount table (caller must copy_mounts)
    /// - Has level = parent.level + 1
    /// - Can be nested up to MAX_MNT_NS_LEVEL deep
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent namespace
    ///
    /// # Returns
    ///
    /// New namespace or error if max depth exceeded
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let child = MountNamespace::new_child(parent.clone())?;
    /// copy_mounts(&parent, &child);  // Don't forget to copy mounts!
    /// ```
    pub fn new_child(parent: Arc<MountNamespace>) -> Result<Arc<Self>, MountNsError> {
        // Check nesting depth
        if parent.level >= MAX_MNT_NS_LEVEL {
            return Err(MountNsError::MaxDepthExceeded);
        }

        // Generate unique namespace ID (R112-2: overflow-safe allocation)
        let id = NEXT_MNT_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| MountNsError::NoMemory)?;

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            mounts: RwLock::new(BTreeMap::new()),
            root_path: RwLock::new(parent.root_path.read().clone()),
        });

        // Emit audit event for namespace creation (use Internal kind)
        #[cfg(feature = "audit")]
        {
            use audit::{emit, AuditKind};
            emit(AuditKind::Internal, child.id.raw(), parent.id.raw(), child.level as u64);
        }

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

    /// Get the number of mounts in this namespace.
    #[inline]
    pub fn mount_count(&self) -> usize {
        self.mounts.read().len()
    }

    /// Get all mount paths in this namespace.
    pub fn mount_paths(&self) -> Vec<String> {
        self.mounts.read().keys().cloned().collect()
    }

    /// Find the mount point for a given path.
    ///
    /// Returns the longest matching mount path and its Mount entry.
    /// This is used by VFS for path resolution.
    ///
    /// # Arguments
    ///
    /// * `path` - Absolute path to resolve
    ///
    /// # Returns
    ///
    /// (mount_path, Mount, relative_path) or None if no mount found
    pub fn find_mount(&self, path: &str) -> Option<(String, Mount, String)> {
        let mounts = self.mounts.read();

        // Helper to check if path matches mount point with proper boundaries
        let mount_matches = |target: &str, mount_path: &str| -> bool {
            if mount_path == "/" {
                true
            } else if target == mount_path {
                true
            } else {
                target.starts_with(mount_path)
                    && target.as_bytes().get(mount_path.len()) == Some(&b'/')
            }
        };

        // Find longest matching mount point
        let mut best_match: Option<(&String, &Mount)> = None;

        for (mount_path, mount) in mounts.iter() {
            if mount_matches(path, mount_path) {
                match best_match {
                    None => best_match = Some((mount_path, mount)),
                    Some((current_path, _)) => {
                        if mount_path.len() > current_path.len() {
                            best_match = Some((mount_path, mount));
                        }
                    }
                }
            }
        }

        best_match.map(|(mount_path, mount)| {
            let relative = if path.len() > mount_path.len() {
                path[mount_path.len()..].to_string()
            } else {
                "/".to_string()
            };
            (mount_path.clone(), mount.clone(), relative)
        })
    }

    /// Check if a path has any submounts.
    ///
    /// Used to prevent unmounting a directory with active submounts.
    pub fn has_submounts(&self, path: &str) -> bool {
        let mounts = self.mounts.read();

        // Special handling for root
        if path == "/" {
            // Root has submounts if there's any mount besides itself
            return mounts.len() > 1 || !mounts.contains_key("/");
        }

        // For non-root paths, ensure trailing slash for prefix check
        let path_with_slash = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };

        mounts.keys().any(|k| k != path && k.starts_with(&path_with_slash))
    }
}

impl core::fmt::Debug for MountNamespace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("mount_count", &self.mount_count())
            .finish()
    }
}

// ============================================================================
// Path Utilities
// ============================================================================

/// Normalize a mount path.
///
/// - Removes trailing slashes (except for root "/")
/// - Removes duplicate slashes
/// - Rejects paths that don't start with "/"
/// - Rejects paths with ".." components (security)
///
/// # Security
///
/// This function prevents path confusion attacks by ensuring consistent
/// path representation in the mount table.
fn normalize_mount_path(path: &str) -> Result<String, MountNsError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(MountNsError::InvalidPath);
    }

    // Special case for root
    if path == "/" {
        return Ok("/".to_string());
    }

    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {} // Skip empty and current dir
            ".." => {
                // Reject ".." to prevent escape attacks
                return Err(MountNsError::InvalidPath);
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        Ok("/".to_string())
    } else {
        let mut result = String::new();
        for c in components {
            result.push('/');
            result.push_str(c);
        }
        Ok(result)
    }
}

/// Simple FNV-1a 64-bit hash for path hashing (used in audit events).
#[inline]
fn hash_path(path: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// The root mount namespace (level 0, no parent).
    ///
    /// All processes start in the root namespace unless CLONE_NEWNS is used.
    /// This is initialized on first access and contains the initial mount table.
    pub static ref ROOT_MNT_NAMESPACE: Arc<MountNamespace> = Arc::new(MountNamespace::new_root());

    /// Counter for generating unique namespace IDs.
    ///
    /// ID 0 is reserved for the root namespace.
    static ref NEXT_MNT_NS_ID: AtomicU64 = AtomicU64::new(1);
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize and return the root mount namespace.
///
/// This function should be called during VFS initialization.
/// The returned namespace will be used as the default for all processes.
pub fn init() -> Arc<MountNamespace> {
    ROOT_MNT_NAMESPACE.clone()
}

/// Copy mount table from one namespace to another.
///
/// This implements Copy-on-Write semantics for CLONE_NEWNS.
/// The destination namespace receives a complete, independent copy
/// of the source namespace's mount table.
///
/// # Arguments
///
/// * `from` - Source namespace to copy from
/// * `to` - Destination namespace to copy to
///
/// # Note
///
/// The destination's existing mount table is cleared before copying.
/// This should typically only be called on a freshly created namespace.
pub fn copy_mounts(from: &MountNamespace, to: &MountNamespace) {
    let src = from.mounts.read();
    let mut dst = to.mounts.write();

    // Clear destination (should already be empty for new namespace)
    dst.clear();

    // Deep copy each mount entry
    for (path, mount) in src.iter() {
        dst.insert(
            path.clone(),
            Mount {
                path: mount.path.clone(),
                fs: mount.fs.clone(),
                flags: mount.flags,
                source: mount.source.clone(),
                fstype: mount.fstype.clone(),
            },
        );
    }

    // Copy root path
    *to.root_path.write() = from.root_path.read().clone();
}

/// Get a mount entry by path.
///
/// # Arguments
///
/// * `ns` - Namespace to search in
/// * `path` - Exact mount path to look up
///
/// # Returns
///
/// The mount entry if found, or None
pub fn get_mount(ns: &Arc<MountNamespace>, path: &str) -> Option<Mount> {
    ns.mounts.read().get(path).cloned()
}

/// Add a mount entry to a namespace.
///
/// # Arguments
///
/// * `ns` - Namespace to add mount to
/// * `path` - Absolute path for mount point
/// * `mount` - Mount entry to add
///
/// # Returns
///
/// Ok(()) on success, or error if path is invalid or mount already exists
///
/// # Security
///
/// Caller must have already verified CAP_SYS_ADMIN or equivalent capability.
/// Path is normalized before insertion to prevent duplicate/malformed entries.
pub fn add_mount(
    ns: &Arc<MountNamespace>,
    path: String,
    mut mount: Mount,
) -> Result<(), MountNsError> {
    // Normalize path to prevent duplicates like "/mnt" vs "/mnt/"
    let normalized_path = normalize_mount_path(&path)?;

    // Ensure mount.path matches the normalized key
    mount.path = normalized_path.clone();

    let mut table = ns.mounts.write();

    // Check for existing mount at this path
    if table.contains_key(&normalized_path) {
        return Err(MountNsError::MountExists);
    }

    table.insert(normalized_path.clone(), mount);

    // Emit audit event (use Fs kind for mount operations)
    #[cfg(feature = "audit")]
    {
        use audit::{emit, AuditKind};
        // Use path hash as identifier
        let path_hash = hash_path(&normalized_path);
        emit(AuditKind::Fs, ns.id.raw(), path_hash, 0);
    }

    Ok(())
}

/// Remove a mount entry from a namespace.
///
/// # Arguments
///
/// * `ns` - Namespace to remove mount from
/// * `path` - Mount path to remove
///
/// # Returns
///
/// Ok(()) on success, or error if mount not found or busy
///
/// # Security
///
/// Caller must have already verified CAP_SYS_ADMIN or equivalent capability.
pub fn remove_mount(ns: &Arc<MountNamespace>, path: &str) -> Result<(), MountNsError> {
    // Check for submounts
    if ns.has_submounts(path) {
        return Err(MountNsError::MountBusy);
    }

    let mut table = ns.mounts.write();

    if table.remove(path).is_some() {
        // Emit audit event (use Fs kind for umount operations)
        #[cfg(feature = "audit")]
        {
            use audit::{emit, AuditKind};
            let path_hash = hash_path(path);
            emit(AuditKind::Fs, ns.id.raw(), path_hash, 1);  // 1 = umount operation
        }

        Ok(())
    } else {
        Err(MountNsError::MountNotFound)
    }
}

/// Create a new child namespace with parent's mounts copied.
///
/// This is a convenience function that combines new_child() and copy_mounts().
/// Used by CLONE_NEWNS implementation.
///
/// # Arguments
///
/// * `parent` - Parent namespace to clone from
///
/// # Returns
///
/// New namespace with a copy of parent's mount table
pub fn clone_namespace(parent: Arc<MountNamespace>) -> Result<Arc<MountNamespace>, MountNsError> {
    let child = MountNamespace::new_child(parent.clone())?;
    copy_mounts(&parent, &child);
    Ok(child)
}

// ============================================================================
// Debug Helpers
// ============================================================================

/// Print namespace information for debugging.
pub fn print_namespace_info(ns: &Arc<MountNamespace>) {
    kprintln!(
        "[MNT NS] id={}, level={}, mounts={}, arc_refs={}",
        ns.id().raw(),
        ns.level(),
        ns.mount_count(),
        Arc::strong_count(ns)
    );

    let mounts = ns.mounts.read();
    for (path, mount) in mounts.iter() {
        kprintln!(
            "  {} -> {} ({:?})",
            path, mount.fstype, mount.flags
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let root = init();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
    }

    #[test]
    fn test_child_namespace() {
        let root = init();
        let child = MountNamespace::new_child(root.clone()).unwrap();
        assert!(!child.is_root());
        assert_eq!(child.level(), 1);
    }

    #[test]
    fn test_max_depth() {
        let mut current = init();
        for _ in 0..MAX_MNT_NS_LEVEL {
            current = MountNamespace::new_child(current).unwrap();
        }
        // Next one should fail
        assert_eq!(
            MountNamespace::new_child(current).err(),
            Some(MountNsError::MaxDepthExceeded)
        );
    }
}
