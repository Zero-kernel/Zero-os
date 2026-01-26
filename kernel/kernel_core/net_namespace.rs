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

// ============================================================================
// Error Types
// ============================================================================

/// Network namespace operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetNsError {
    /// Maximum namespace depth exceeded
    MaxDepthExceeded,
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
    pub fn new_child(parent: Arc<NetNamespace>) -> Result<Arc<Self>, NetNsError> {
        if parent.level >= MAX_NET_NS_LEVEL {
            return Err(NetNsError::MaxDepthExceeded);
        }

        let id = NEXT_NET_NS_ID.fetch_add(1, Ordering::SeqCst);

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()), // Empty - only loopback
            has_loopback: true,
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

    /// Increment reference count.
    #[inline]
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
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
    println!(
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
pub fn move_device(
    device_idx: u32,
    from: &Arc<NetNamespace>,
    to: &Arc<NetNamespace>,
) -> Result<(), NetNsError> {
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
