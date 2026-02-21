//! Network Namespace Implementation for Zero-OS
//!
//! Provides isolated network stack for containerization support. Each network
//! namespace maintains its own:
//! - Network interfaces (devices)
//! - IP addresses and routing tables
//! - Socket bindings
//! - Firewall rules
//!
//! # Design
//!
//! Follows the same hierarchical model as other namespaces:
//! - Root namespace at level 0 (contains physical devices by default)
//! - Child namespaces created via CLONE_NEWNET or unshare(CLONE_NEWNET)
//! - Maximum nesting depth of 32 levels
//!
//! # Security
//!
//! - All network namespace operations require CAP_NET_ADMIN or CAP_SYS_ADMIN
//! - Namespace switching (setns) requires single-threaded process
//! - Network resources are isolated: sockets in different namespaces can bind same ports
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create child namespace
//! let child_ns = clone_net_namespace(parent_ns)?;
//!
//! // Check socket visibility
//! let visible = is_socket_in_namespace(socket_id, &ns);
//! ```

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cap::NamespaceId;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum network namespace nesting depth
pub const MAX_NET_NS_LEVEL: u8 = 32;

/// CLONE_NEWNET flag for clone/unshare
pub const CLONE_NEWNET: u64 = 0x4000_0000;

/// R76-2 FIX: Maximum number of network namespaces allowed system-wide.
/// Prevents DoS via namespace exhaustion.
pub const MAX_NET_NS_COUNT: u32 = 1024;

/// R76-2 FIX: Current network namespace count (root starts at 1).
static NET_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Error Types
// ============================================================================

/// Network namespace operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetNsError {
    /// Maximum namespace depth exceeded
    MaxDepthExceeded,
    /// R76-2 FIX: Maximum system-wide namespace count exceeded
    MaxNamespaces,
    /// Namespace not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Device already exists in namespace
    DeviceExists,
    /// Device not found
    DeviceNotFound,
    /// Invalid namespace state
    InvalidState,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
}

// ============================================================================
// R77-5 FIX: Namespace Count Guard
// ============================================================================

/// Guard for atomic namespace count management.
///
/// # R77-5 FIX
///
/// This guard ensures that the global namespace count is correctly maintained
/// even if `Arc::new()` fails (OOM) after the count has been incremented.
/// The guard automatically decrements the count on drop unless `commit()` is called.
///
/// ## Problem
///
/// Previously, the count was incremented before `Arc::new()`:
/// ```ignore
/// let prev = NET_NS_COUNT.fetch_add(1, ...);  // Count incremented
/// let child = Arc::new(Self { ... });          // If OOM here, count leaks!
/// ```
///
/// ## Solution
///
/// Use RAII pattern to ensure automatic rollback:
/// ```ignore
/// let guard = NsCountGuard::new(&NET_NS_COUNT)?;  // Count incremented
/// let child = Arc::new(Self { ... });              // If OOM, guard drops and rolls back
/// guard.commit();                                  // Success - prevent rollback
/// ```
struct NsCountGuard {
    counter: &'static AtomicU32,
    committed: bool,
}

impl NsCountGuard {
    /// Create a new guard, incrementing the counter.
    ///
    /// Returns error if the count would exceed the limit.
    fn new(counter: &'static AtomicU32, max_count: u32) -> Result<Self, NetNsError> {
        let prev = counter.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (count guard with immediate rollback)
        if prev >= max_count {
            counter.fetch_sub(1, Ordering::SeqCst);
            return Err(NetNsError::MaxNamespaces);
        }
        Ok(Self {
            counter,
            committed: false,
        })
    }

    /// Commit the count increment, preventing rollback on drop.
    ///
    /// Call this after the namespace has been successfully created.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for NsCountGuard {
    fn drop(&mut self) {
        if !self.committed {
            // Allocation failed - roll back the count increment
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// Root network namespace - contains physical devices by default
    pub static ref ROOT_NET_NAMESPACE: Arc<NetNamespace> = Arc::new(NetNamespace::new_root());
}

/// Next available namespace ID (starts at 1, 0 is reserved for root)
static NEXT_NET_NS_ID: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// Network Namespace
// ============================================================================

/// A network namespace providing isolated network stack.
///
/// Each namespace has its own:
/// - Set of network devices (interfaces)
/// - IP address assignments
/// - Routing table
/// - Socket bindings (same port can be used in different namespaces)
/// - Firewall rules
pub struct NetNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<NetNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Reference count of processes using this namespace
    refcount: AtomicU32,

    /// Network devices assigned to this namespace (by device index)
    devices: RwLock<BTreeSet<u32>>,

    /// Loopback interface is always present (127.0.0.1)
    has_loopback: bool,
}

impl fmt::Debug for NetNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .field("has_loopback", &self.has_loopback)
            .finish()
    }
}

impl NetNamespace {
    /// Create the root network namespace.
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()),
            has_loopback: true,
        }
    }

    /// Create a new child namespace.
    ///
    /// Child namespaces start with only a loopback interface.
    /// Physical devices must be explicitly moved into child namespaces.
    ///
    /// # R77-5 FIX
    ///
    /// Uses `NsCountGuard` to ensure the global namespace count is correctly
    /// maintained even if `Arc::new()` fails (OOM). The guard automatically
    /// rolls back the count increment on failure.
    pub fn new_child(parent: Arc<NetNamespace>) -> Result<Arc<Self>, NetNsError> {
        if parent.level >= MAX_NET_NS_LEVEL {
            return Err(NetNsError::MaxDepthExceeded);
        }

        // R77-5 FIX: Use guard pattern to ensure count rollback on allocation failure.
        // The guard increments the count and will auto-decrement on drop unless committed.
        let count_guard = NsCountGuard::new(&NET_NS_COUNT, MAX_NET_NS_COUNT)?;

        // R112-2: overflow-safe namespace ID allocation
        let id = NEXT_NET_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| {
                // count_guard will auto-rollback on drop (R77-5 pattern)
                NetNsError::NamespaceIdOverflow
            })?;

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()), // Empty - only loopback
            has_loopback: true,
        });

        // R77-5 FIX: Arc allocation succeeded - commit the guard to prevent rollback.
        count_guard.commit();

        Ok(child)
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<NetNamespace>> {
        self.parent.clone()
    }

    /// Get the nesting level.
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get current reference count.
    #[inline]
    pub fn ref_count(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count (R112-2: overflow-safe).
    #[inline]
    pub fn inc_ref(&self) {
        self.refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .expect("NetNamespace refcount overflow");
    }

    /// Decrement reference count.
    #[inline]
    pub fn dec_ref(&self) {
        self.refcount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if namespace has loopback interface.
    #[inline]
    pub fn has_loopback(&self) -> bool {
        self.has_loopback
    }

    /// Add a device to this namespace.
    ///
    /// Note: Device must be removed from its current namespace first.
    pub fn add_device(&self, device_idx: u32) -> Result<(), NetNsError> {
        let mut devices = self.devices.write();
        if devices.contains(&device_idx) {
            return Err(NetNsError::DeviceExists);
        }
        devices.insert(device_idx);
        Ok(())
    }

    /// Remove a device from this namespace.
    pub fn remove_device(&self, device_idx: u32) -> Result<(), NetNsError> {
        let mut devices = self.devices.write();
        if devices.remove(&device_idx) {
            Ok(())
        } else {
            Err(NetNsError::DeviceNotFound)
        }
    }

    /// Check if device is in this namespace.
    pub fn has_device(&self, device_idx: u32) -> bool {
        self.devices.read().contains(&device_idx)
    }

    /// Get list of devices in this namespace.
    pub fn devices(&self) -> Vec<u32> {
        self.devices.read().iter().copied().collect()
    }

    /// Get number of devices in this namespace.
    pub fn device_count(&self) -> usize {
        self.devices.read().len()
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the network namespace subsystem.
///
/// Called during kernel initialization to set up the root namespace.
pub fn init() -> Arc<NetNamespace> {
    ROOT_NET_NAMESPACE.clone()
}

/// Create a new child network namespace (for CLONE_NEWNET).
///
/// # Arguments
///
/// * `parent` - Parent namespace to derive from
///
/// # Returns
///
/// New child namespace with isolated network stack (only loopback)
///
/// # Errors
///
/// * `MaxDepthExceeded` - Maximum nesting depth reached
pub fn clone_net_namespace(parent: Arc<NetNamespace>) -> Result<Arc<NetNamespace>, NetNsError> {
    NetNamespace::new_child(parent)
}

/// Print namespace information for debugging.
pub fn print_net_namespace_info(ns: &Arc<NetNamespace>) {
    kprintln!(
        "[NET NS] id={}, level={}, refcount={}, devices={}",
        ns.id().raw(),
        ns.level(),
        ns.ref_count(),
        ns.device_count()
    );
}

/// Get the root network namespace.
#[inline]
pub fn root_net_namespace() -> Arc<NetNamespace> {
    ROOT_NET_NAMESPACE.clone()
}

/// Move a device from one namespace to another.
///
/// # Security
///
/// This operation requires CAP_NET_ADMIN in both the source and
/// destination namespaces.
///
/// # R75-3 FIX
///
/// Added permission check: requires CAP_ADMIN (CAP_NET_ADMIN equivalent)
/// or root (euid == 0) to move devices between namespaces. Without this
/// check, unprivileged processes could hijack network devices from the
/// host namespace or inject devices into other namespaces.
pub fn move_device(
    device_idx: u32,
    from: &Arc<NetNamespace>,
    to: &Arc<NetNamespace>,
) -> Result<(), NetNsError> {
    // R75-3 FIX: Security check - require CAP_NET_ADMIN (mapped to ADMIN) or root
    let has_cap_admin =
        crate::process::with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN))
            .unwrap_or(false);
    // CODEX REVIEW FIX: Use unwrap_or(false) instead of unwrap_or(true) to prevent
    // permission bypass when current_euid() fails (e.g., no process context).
    // Fail-closed: if we can't determine euid, assume non-root.
    let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(false);
    if !is_root && !has_cap_admin {
        return Err(NetNsError::PermissionDenied);
    }

    // Remove from source namespace
    from.remove_device(device_idx)?;

    // Add to destination namespace
    match to.add_device(device_idx) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Rollback: put device back in source
            let _ = from.add_device(device_idx);
            Err(e)
        }
    }
}

// ============================================================================
// R76-2 FIX: Namespace Resource Cleanup
// ============================================================================

/// R76-2 FIX: Decrement global namespace counter when namespace is destroyed.
impl Drop for NetNamespace {
    fn drop(&mut self) {
        if self.level > 0 {
            NET_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Network Namespace File Descriptor (for sys_setns)
// ============================================================================

use crate::{FileDescriptor, FileOps, SyscallError};

/// File descriptor wrapper for network namespace (used by sys_setns).
///
/// When a process opens /proc/[pid]/ns/net, it gets this file descriptor
/// that references the target process's network namespace.
pub struct NetNamespaceFd {
    ns: Arc<NetNamespace>,
}

impl NetNamespaceFd {
    /// Create a new network namespace file descriptor.
    pub fn new(ns: Arc<NetNamespace>) -> Self {
        ns.inc_ref();
        Self { ns }
    }

    /// Get the underlying namespace.
    pub fn namespace(&self) -> Arc<NetNamespace> {
        self.ns.clone()
    }
}

impl Drop for NetNamespaceFd {
    fn drop(&mut self) {
        self.ns.dec_ref();
    }
}

impl FileOps for NetNamespaceFd {
    fn clone_box(&self) -> alloc::boxed::Box<dyn FileOps> {
        // R75-4 FIX: Increment manual refcount when cloning FD.
        //
        // Without this, dup()/fork() creates a new FD that shares the same
        // Arc but doesn't increment the manual refcount. When each copy is
        // dropped, dec_ref() is called multiple times, causing underflow
        // (wrapping from 1 to u32::MAX) and breaking reference tracking.
        self.ns.inc_ref();
        alloc::boxed::Box::new(Self {
            ns: self.ns.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "net_namespace_fd"
    }

    fn stat(&self) -> Result<crate::VfsStat, SyscallError> {
        Ok(crate::VfsStat {
            dev: 0,
            ino: self.ns.id().raw(),
            mode: 0o444,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        })
    }
}

// ============================================================================
// Test Support
// ============================================================================

/// Test helper: Check if network namespace subsystem is initialized.
pub fn test_is_net_ns_initialized() -> bool {
    ROOT_NET_NAMESPACE.id().raw() == 0 && ROOT_NET_NAMESPACE.is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_namespace() {
        let root = ROOT_NET_NAMESPACE.clone();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
        assert_eq!(root.id().raw(), 0);
        assert!(root.has_loopback());
    }

    #[test]
    fn test_child_namespace() {
        let root = ROOT_NET_NAMESPACE.clone();
        let child = clone_net_namespace(root.clone()).unwrap();

        assert!(!child.is_root());
        assert_eq!(child.level(), 1);
        assert!(child.parent().is_some());
        assert_eq!(child.parent().unwrap().id(), root.id());
        assert!(child.has_loopback());
        assert_eq!(child.device_count(), 0); // Only loopback, no physical devices
    }

    #[test]
    fn test_device_management() {
        let ns = clone_net_namespace(ROOT_NET_NAMESPACE.clone()).unwrap();

        // Add device
        assert!(ns.add_device(1).is_ok());
        assert!(ns.has_device(1));
        assert_eq!(ns.device_count(), 1);

        // Duplicate add fails
        assert!(matches!(ns.add_device(1), Err(NetNsError::DeviceExists)));

        // Remove device
        assert!(ns.remove_device(1).is_ok());
        assert!(!ns.has_device(1));
        assert_eq!(ns.device_count(), 0);

        // Remove non-existent fails
        assert!(matches!(ns.remove_device(1), Err(NetNsError::DeviceNotFound)));
    }

    #[test]
    fn test_max_depth() {
        let mut current = ROOT_NET_NAMESPACE.clone();

        for level in 1..=MAX_NET_NS_LEVEL {
            match clone_net_namespace(current.clone()) {
                Ok(child) => {
                    assert_eq!(child.level(), level);
                    current = child;
                }
                Err(NetNsError::MaxDepthExceeded) => {
                    assert_eq!(level, MAX_NET_NS_LEVEL + 1);
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
    }
}
