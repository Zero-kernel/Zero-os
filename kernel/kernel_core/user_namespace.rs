//! User Namespace Implementation for Zero-OS
//!
//! Provides Linux-compatible user namespaces (CLONE_NEWUSER) with UID/GID
//! mapping support. User namespaces virtualize user/group identities so that
//! processes can appear as root (uid/gid 0) inside the namespace while still
//! retaining their host credentials for security isolation.
//!
//! # Design
//!
//! Follows the same hierarchical model as other namespaces (PID, Mount, IPC, Net):
//! - Root namespace at level 0 (shared by default, identity mapping)
//! - Child namespaces created via CLONE_NEWUSER or unshare(CLONE_NEWUSER)
//! - Maximum nesting depth of 32 levels (MAX_USER_NS_LEVEL)
//!
//! # UID/GID Mapping
//!
//! Each user namespace maintains separate UID and GID mapping tables:
//! - Up to MAX_MAPPINGS (5) mapping extents per table
//! - Single-write semantics (mirrors Linux /proc/[pid]/uid_map behavior)
//! - Mappings translate between host IDs and namespace-local IDs
//!
//! ```text
//! Host System:        User Namespace:
//! uid=1000 --------> uid=0 (root in namespace)
//! gid=1000 --------> gid=0 (root in namespace)
//! ```
//!
//! # Security
//!
//! Unlike other namespace types, CLONE_NEWUSER does NOT require CAP_SYS_ADMIN
//! or root privileges. This is by design - user namespaces enable unprivileged
//! container creation. However:
//!
//! - Namespace depth is limited to prevent resource exhaustion
//! - Total namespace count is limited (MAX_USER_NS_COUNT)
//! - Mapping must be valid (no overlaps, no overflow, non-zero count)
//! - Mappings can only be written once (single-write semantics)
//!
//! # References
//!
//! - Linux user_namespaces(7) man page
//! - Phase F.1 in roadmap.md

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cap::NamespaceId;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Lazy, RwLock};

use crate::{current_egid, current_euid, FileDescriptor, FileOps, SyscallError, VfsStat};

// ============================================================================
// Constants
// ============================================================================

/// Maximum nesting depth for user namespaces.
///
/// This matches the Linux default of 32 levels. Prevents stack overflow
/// during recursive operations and limits resource consumption.
pub const MAX_USER_NS_LEVEL: u8 = 32;

/// Maximum UID/GID mapping extents per namespace.
///
/// Linux uses 5 mapping lines per uid_map/gid_map file.
/// This is sufficient for most container use cases:
/// - Map single user to root (1 extent)
/// - Map user range + nobody (2-3 extents)
/// - Complex multi-tenant scenarios (up to 5 extents)
pub const MAX_MAPPINGS: usize = 5;

/// Maximum number of user namespaces system-wide.
///
/// Prevents DoS via unbounded namespace creation.
pub const MAX_USER_NS_COUNT: u32 = 1024;

/// CLONE_NEWUSER flag value (Linux x86_64 ABI).
///
/// This flag is used with clone(2) or unshare(2) to create a new user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;

// ============================================================================
// Global State
// ============================================================================

/// Root user namespace (level 0, identity mapping).
///
/// All processes start in this namespace unless CLONE_NEWUSER is used.
/// The root namespace provides identity mapping: uid/gid values are unchanged.
pub static ROOT_USER_NAMESPACE: Lazy<Arc<UserNamespace>> =
    Lazy::new(|| Arc::new(UserNamespace::new_root()));

/// Next available namespace ID (0 reserved for root).
static NEXT_USER_NS_ID: AtomicU64 = AtomicU64::new(1);

/// Current user namespace count (root counts as 1).
static USER_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Types
// ============================================================================

/// UID/GID mapping extent.
///
/// Represents a contiguous range of IDs mapped between namespace and host.
///
/// # Example
///
/// A mapping of `{ ns_id: 0, host_id: 1000, count: 1 }` means:
/// - namespace UID 0 maps to host UID 1000
/// - Only one ID is covered by this extent
///
/// For a range: `{ ns_id: 1000, host_id: 100000, count: 65536 }` means:
/// - namespace UIDs 1000-66535 map to host UIDs 100000-165535
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidGidMapping {
    /// UID/GID inside the namespace (start of range).
    pub ns_id: u32,
    /// Corresponding host UID/GID (start of range).
    pub host_id: u32,
    /// Number of contiguous IDs covered by this extent.
    pub count: u32,
}

/// User namespace operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserNsError {
    /// Maximum namespace depth exceeded (MAX_USER_NS_LEVEL).
    MaxDepthExceeded,
    /// Maximum system-wide namespace count exceeded (MAX_USER_NS_COUNT).
    MaxNamespaces,
    /// Too many mapping extents (exceeds MAX_MAPPINGS).
    TooManyMappings,
    /// Invalid mapping (overlap, overflow, or empty count).
    InvalidMapping,
    /// Mapping already set (single-write semantics).
    MappingAlreadySet,
    /// Permission denied for mapping operation.
    PermissionDenied,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
}

impl fmt::Display for UserNsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserNsError::MaxDepthExceeded => {
                write!(f, "user namespace depth exceeds MAX_USER_NS_LEVEL ({})", MAX_USER_NS_LEVEL)
            }
            UserNsError::MaxNamespaces => {
                write!(f, "user namespace count exceeds MAX_USER_NS_COUNT ({})", MAX_USER_NS_COUNT)
            }
            UserNsError::TooManyMappings => {
                write!(f, "too many mapping extents (max {})", MAX_MAPPINGS)
            }
            UserNsError::InvalidMapping => write!(f, "invalid mapping (overlap/overflow/empty)"),
            UserNsError::MappingAlreadySet => write!(f, "mapping already set (single-write)"),
            UserNsError::PermissionDenied => write!(f, "permission denied"),
            UserNsError::NamespaceIdOverflow => write!(f, "namespace ID counter overflow"),
        }
    }
}

/// Mapping kind for permission checks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MappingKind {
    Uid,
    Gid,
}

/// RAII guard for atomic namespace count management.
///
/// Ensures the namespace count is decremented if creation fails,
/// preventing count leaks on error paths.
///
/// Uses CAS loop to avoid race conditions where multiple concurrent
/// creators could exceed MAX_USER_NS_COUNT.
struct NsCountGuard {
    committed: bool,
}

impl NsCountGuard {
    /// Try to increment the namespace count, returning an error if at limit.
    ///
    /// Uses compare_exchange loop to atomically check and increment,
    /// preventing TOCTOU race conditions that could exceed the limit.
    fn try_new() -> Result<Self, UserNsError> {
        loop {
            let current = USER_NS_COUNT.load(Ordering::SeqCst);
            if current >= MAX_USER_NS_COUNT {
                return Err(UserNsError::MaxNamespaces);
            }
            // Try to atomically increment from current to current+1
            match USER_NS_COUNT.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(Self { committed: false }),
                Err(_) => continue, // Another thread modified count, retry
            }
        }
    }

    /// Mark the guard as committed (namespace successfully created).
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for NsCountGuard {
    fn drop(&mut self) {
        if !self.committed {
            USER_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// User Namespace
// ============================================================================

/// A user namespace providing UID/GID isolation with mapping tables.
///
/// User namespaces allow processes to have different privilege levels
/// inside and outside the namespace. A process can be UID 0 (root) inside
/// its user namespace while being an unprivileged user on the host.
pub struct UserNamespace {
    /// Unique namespace identifier.
    id: NamespaceId,

    /// Parent namespace (None for root).
    parent: Option<Arc<UserNamespace>>,

    /// Nesting level (0 = root).
    level: u8,

    /// Manual reference count (for namespace file descriptors).
    refcount: AtomicU32,

    /// UID mapping table (namespace ID -> host ID).
    uid_map: RwLock<Vec<UidGidMapping>>,

    /// GID mapping table (namespace ID -> host ID).
    gid_map: RwLock<Vec<UidGidMapping>>,

    /// Flag indicating UID map has been written (single-write semantics).
    uid_map_set: AtomicBool,

    /// Flag indicating GID map has been written (single-write semantics).
    gid_map_set: AtomicBool,
}

impl fmt::Debug for UserNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .field("uid_map_set", &self.uid_map_set.load(Ordering::Relaxed))
            .field("gid_map_set", &self.gid_map_set.load(Ordering::Relaxed))
            .finish()
    }
}

impl UserNamespace {
    /// Create the root user namespace (identity mapping).
    ///
    /// The root namespace has no mapping tables - all UIDs/GIDs pass through
    /// unchanged (identity mapping).
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            refcount: AtomicU32::new(1),
            uid_map: RwLock::new(Vec::new()),
            gid_map: RwLock::new(Vec::new()),
            // Root mapping is implicitly fixed (identity)
            uid_map_set: AtomicBool::new(true),
            gid_map_set: AtomicBool::new(true),
        }
    }

    /// Create a new child user namespace.
    ///
    /// # Arguments
    ///
    /// * `parent` - Parent namespace to derive from
    ///
    /// # Returns
    ///
    /// New child namespace with empty mapping tables (to be configured later)
    ///
    /// # Errors
    ///
    /// * `MaxDepthExceeded` - Maximum nesting depth reached
    /// * `MaxNamespaces` - System-wide namespace limit reached
    pub fn new_child(parent: Arc<UserNamespace>) -> Result<Arc<Self>, UserNsError> {
        // Check depth limit
        if parent.level >= MAX_USER_NS_LEVEL {
            return Err(UserNsError::MaxDepthExceeded);
        }

        // Check and increment namespace count atomically
        let guard = NsCountGuard::try_new()?;

        // Allocate unique ID (R112-2: overflow-safe allocation)
        let id = NEXT_USER_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| {
                // guard will auto-rollback on drop (R77-5 pattern)
                UserNsError::NamespaceIdOverflow
            })?;

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            uid_map: RwLock::new(Vec::new()),
            gid_map: RwLock::new(Vec::new()),
            // Child starts with unset mappings
            uid_map_set: AtomicBool::new(false),
            gid_map_set: AtomicBool::new(false),
        });

        // Commit the count increment (won't be rolled back)
        guard.commit();

        Ok(child)
    }

    /// Get namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<UserNamespace>> {
        self.parent.clone()
    }

    /// Get nesting level.
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get reference count.
    #[inline]
    pub fn ref_count(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count (R112-2: overflow-safe).
    #[inline]
    pub fn inc_ref(&self) {
        self.refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .expect("UserNamespace refcount overflow");
    }

    /// Decrement reference count.
    #[inline]
    pub fn dec_ref(&self) {
        self.refcount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if UID mapping has been configured.
    #[inline]
    pub fn uid_map_is_set(&self) -> bool {
        self.uid_map_set.load(Ordering::Acquire)
    }

    /// Check if GID mapping has been configured.
    #[inline]
    pub fn gid_map_is_set(&self) -> bool {
        self.gid_map_set.load(Ordering::Acquire)
    }

    /// Translate a host UID into this namespace's UID.
    ///
    /// # Arguments
    ///
    /// * `host_uid` - UID on the host system
    ///
    /// # Returns
    ///
    /// The corresponding UID in this namespace, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_uid_to_ns(&self, host_uid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(host_uid);
        }

        let map = self.uid_map.read();
        for m in map.iter() {
            let end = m.host_id.checked_add(m.count)?;
            if host_uid >= m.host_id && host_uid < end {
                return Some(m.ns_id.saturating_add(host_uid.saturating_sub(m.host_id)));
            }
        }
        None
    }

    /// Translate a namespace UID back to host UID.
    ///
    /// # Arguments
    ///
    /// * `ns_uid` - UID inside this namespace
    ///
    /// # Returns
    ///
    /// The corresponding host UID, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_uid_from_ns(&self, ns_uid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(ns_uid);
        }

        let map = self.uid_map.read();
        for m in map.iter() {
            let end = m.ns_id.checked_add(m.count)?;
            if ns_uid >= m.ns_id && ns_uid < end {
                return Some(m.host_id.saturating_add(ns_uid.saturating_sub(m.ns_id)));
            }
        }
        None
    }

    /// Translate a host GID into this namespace's GID.
    ///
    /// # Arguments
    ///
    /// * `host_gid` - GID on the host system
    ///
    /// # Returns
    ///
    /// The corresponding GID in this namespace, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_gid_to_ns(&self, host_gid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(host_gid);
        }

        let map = self.gid_map.read();
        for m in map.iter() {
            let end = m.host_id.checked_add(m.count)?;
            if host_gid >= m.host_id && host_gid < end {
                return Some(m.ns_id.saturating_add(host_gid.saturating_sub(m.host_id)));
            }
        }
        None
    }

    /// Translate a namespace GID back to host GID.
    ///
    /// # Arguments
    ///
    /// * `ns_gid` - GID inside this namespace
    ///
    /// # Returns
    ///
    /// The corresponding host GID, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_gid_from_ns(&self, ns_gid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(ns_gid);
        }

        let map = self.gid_map.read();
        for m in map.iter() {
            let end = m.ns_id.checked_add(m.count)?;
            if ns_gid >= m.ns_id && ns_gid < end {
                return Some(m.host_id.saturating_add(ns_gid.saturating_sub(m.ns_id)));
            }
        }
        None
    }

    /// Set UID mapping table.
    ///
    /// This can only be called once (single-write semantics, matching Linux).
    ///
    /// # Arguments
    ///
    /// * `mappings` - Vector of UID mapping extents
    ///
    /// # Errors
    ///
    /// * `MappingAlreadySet` - UID mapping was already written
    /// * `InvalidMapping` - Mapping has overlaps, overflow, or empty count
    /// * `TooManyMappings` - More than MAX_MAPPINGS extents
    /// * `PermissionDenied` - Caller lacks permission to set this mapping
    pub fn set_uid_map(&self, mappings: Vec<UidGidMapping>) -> Result<(), UserNsError> {
        // Check permission before attempting to set mapping
        self.ensure_mapping_allowed(&mappings, MappingKind::Uid)?;
        set_mapping(&self.uid_map, &self.uid_map_set, mappings)
    }

    /// Set GID mapping table.
    ///
    /// This can only be called once (single-write semantics, matching Linux).
    ///
    /// # Arguments
    ///
    /// * `mappings` - Vector of GID mapping extents
    ///
    /// # Errors
    ///
    /// * `MappingAlreadySet` - GID mapping was already written
    /// * `InvalidMapping` - Mapping has overlaps, overflow, or empty count
    /// * `TooManyMappings` - More than MAX_MAPPINGS extents
    /// * `PermissionDenied` - Caller lacks permission to set this mapping
    pub fn set_gid_map(&self, mappings: Vec<UidGidMapping>) -> Result<(), UserNsError> {
        // Check permission before attempting to set mapping
        self.ensure_mapping_allowed(&mappings, MappingKind::Gid)?;
        set_mapping(&self.gid_map, &self.gid_map_set, mappings)
    }

    /// Get current UID mappings (for procfs display).
    pub fn uid_mappings(&self) -> Vec<UidGidMapping> {
        self.uid_map.read().clone()
    }

    /// Get current GID mappings (for procfs display).
    pub fn gid_mappings(&self) -> Vec<UidGidMapping> {
        self.gid_map.read().clone()
    }

    /// Ensure the caller has permission to set mappings in this namespace.
    ///
    /// Linux permission model (user_namespaces(7)):
    /// - Process must have CAP_SETUID/CAP_SETGID in parent namespace, OR
    /// - Process can only map its own UID/GID (single-extent mapping to self)
    /// - Mapped host IDs must be within parent namespace's mapped range
    ///
    /// # Arguments
    ///
    /// * `mappings` - The proposed mapping extents
    /// * `kind` - Whether this is a UID or GID mapping
    ///
    /// # Returns
    ///
    /// Ok(()) if the caller has permission, Err(PermissionDenied) otherwise
    fn ensure_mapping_allowed(
        &self,
        mappings: &[UidGidMapping],
        kind: MappingKind,
    ) -> Result<(), UserNsError> {
        // Root namespace doesn't allow mapping changes
        if self.is_root() {
            return Err(UserNsError::PermissionDenied);
        }

        // Get caller's effective ID
        let caller_id = match kind {
            MappingKind::Uid => current_euid().unwrap_or(u32::MAX),
            MappingKind::Gid => current_egid().unwrap_or(u32::MAX),
        };

        // Root (euid/egid 0) can set arbitrary mappings
        if caller_id == 0 {
            // Still need to validate parent mapping containment
            return self.validate_parent_containment(mappings, kind);
        }

        // Non-root: only allow single-extent mapping of own ID
        if mappings.len() != 1 {
            return Err(UserNsError::PermissionDenied);
        }

        let m = &mappings[0];

        // Must map exactly one ID
        if m.count != 1 {
            return Err(UserNsError::PermissionDenied);
        }

        // Must map caller's own host ID
        if m.host_id != caller_id {
            return Err(UserNsError::PermissionDenied);
        }

        // Validate parent containment
        self.validate_parent_containment(mappings, kind)
    }

    /// Validate that all host IDs in mappings fall within parent's mapped range.
    ///
    /// This prevents privilege escalation by ensuring a child namespace cannot
    /// grant access to host IDs that the parent namespace cannot access.
    fn validate_parent_containment(
        &self,
        mappings: &[UidGidMapping],
        kind: MappingKind,
    ) -> Result<(), UserNsError> {
        let parent = match &self.parent {
            Some(p) => p,
            None => return Ok(()), // Root has no restrictions
        };

        // Root parent has identity mapping - all IDs are valid
        if parent.is_root() {
            return Ok(());
        }

        // Get parent's mapping table
        let parent_mappings = match kind {
            MappingKind::Uid => parent.uid_mappings(),
            MappingKind::Gid => parent.gid_mappings(),
        };

        // Each extent's host range must be fully contained in parent's host ranges
        for m in mappings {
            if !range_within_parent(&parent_mappings, m.host_id, m.count) {
                return Err(UserNsError::PermissionDenied);
            }
        }

        Ok(())
    }
}

/// Validate and store UID/GID mappings with overlap/overflow checks.
fn set_mapping(
    table: &RwLock<Vec<UidGidMapping>>,
    flag: &AtomicBool,
    mappings: Vec<UidGidMapping>,
) -> Result<(), UserNsError> {
    // Single-write semantics: fail if already set
    if flag.swap(true, Ordering::SeqCst) {
        return Err(UserNsError::MappingAlreadySet);
    }

    // Validate mapping
    if mappings.is_empty() {
        flag.store(false, Ordering::SeqCst);
        return Err(UserNsError::InvalidMapping);
    }

    if mappings.len() > MAX_MAPPINGS {
        flag.store(false, Ordering::SeqCst);
        return Err(UserNsError::TooManyMappings);
    }

    if let Err(e) = validate_mappings(&mappings) {
        flag.store(false, Ordering::SeqCst);
        return Err(e);
    }

    // Store validated mappings
    let mut guard = table.write();
    *guard = mappings;
    Ok(())
}

/// Validate mapping extents for correctness.
fn validate_mappings(mappings: &[UidGidMapping]) -> Result<(), UserNsError> {
    for m in mappings {
        // Count must be non-zero
        if m.count == 0 {
            return Err(UserNsError::InvalidMapping);
        }

        // Check for overflow in namespace range
        m.ns_id
            .checked_add(m.count)
            .ok_or(UserNsError::InvalidMapping)?;

        // Check for overflow in host range
        m.host_id
            .checked_add(m.count)
            .ok_or(UserNsError::InvalidMapping)?;
    }

    // Check for overlapping extents
    for i in 0..mappings.len() {
        for j in (i + 1)..mappings.len() {
            let a = &mappings[i];
            let b = &mappings[j];

            // Check namespace ID range overlap
            if ranges_overlap(a.ns_id, a.count, b.ns_id, b.count) {
                return Err(UserNsError::InvalidMapping);
            }

            // Check host ID range overlap
            if ranges_overlap(a.host_id, a.count, b.host_id, b.count) {
                return Err(UserNsError::InvalidMapping);
            }
        }
    }

    Ok(())
}

/// Check if two ranges overlap.
#[inline]
fn ranges_overlap(start_a: u32, count_a: u32, start_b: u32, count_b: u32) -> bool {
    let end_a = start_a.saturating_add(count_a);
    let end_b = start_b.saturating_add(count_b);
    start_a < end_b && start_b < end_a
}

/// Check if a host ID range is fully contained within any of the parent's mapped ranges.
///
/// For a child namespace to map [host_start, host_start + count), the entire range
/// must fall within one of the parent's host ID ranges. This prevents privilege
/// escalation through nested namespaces.
///
/// # Arguments
///
/// * `parent_mappings` - Parent namespace's mapping table
/// * `host_start` - Start of the host ID range to check
/// * `count` - Number of IDs in the range
///
/// # Returns
///
/// true if the range is fully contained in some parent extent, false otherwise
fn range_within_parent(parent_mappings: &[UidGidMapping], host_start: u32, count: u32) -> bool {
    let host_end = match host_start.checked_add(count) {
        Some(e) => e,
        None => return false, // Overflow means invalid range
    };

    // Check if any parent extent fully contains this range
    for pm in parent_mappings {
        let pm_end = pm.host_id.saturating_add(pm.count);
        if host_start >= pm.host_id && host_end <= pm_end {
            return true;
        }
    }

    false
}

impl Drop for UserNamespace {
    fn drop(&mut self) {
        // Decrement global count for non-root namespaces
        if self.level > 0 {
            USER_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the user namespace subsystem.
///
/// Returns the root user namespace. Should be called during kernel initialization.
#[inline]
pub fn init() -> Arc<UserNamespace> {
    ROOT_USER_NAMESPACE.clone()
}

/// Create a new child user namespace (for CLONE_NEWUSER).
///
/// # Arguments
///
/// * `parent` - Parent namespace to clone from
///
/// # Returns
///
/// New child namespace with isolated user/group ID space
///
/// # Errors
///
/// * `MaxDepthExceeded` - Maximum nesting depth reached
/// * `MaxNamespaces` - System-wide namespace limit reached
pub fn clone_user_namespace(parent: Arc<UserNamespace>) -> Result<Arc<UserNamespace>, UserNsError> {
    UserNamespace::new_child(parent)
}

/// Get the root user namespace.
#[inline]
pub fn root_user_namespace() -> Arc<UserNamespace> {
    ROOT_USER_NAMESPACE.clone()
}

/// Print namespace information for debugging.
pub fn print_user_namespace_info(ns: &Arc<UserNamespace>) {
    kprintln!(
        "[USER NS] id={}, level={}, refcount={}, uid_map_set={}, gid_map_set={}",
        ns.id().raw(),
        ns.level(),
        ns.ref_count(),
        ns.uid_map_is_set(),
        ns.gid_map_is_set()
    );
}

/// Get the current user namespace count.
#[inline]
pub fn user_ns_count() -> u32 {
    USER_NS_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// User Namespace File Descriptor
// ============================================================================

/// File descriptor wrapper for user namespace.
///
/// Used by setns(2) to switch a process's user namespace by holding
/// an open file descriptor to a namespace.
pub struct UserNamespaceFd {
    ns: Arc<UserNamespace>,
}

impl UserNamespaceFd {
    /// Create a new user namespace file descriptor.
    pub fn new(ns: Arc<UserNamespace>) -> Self {
        ns.inc_ref();
        Self { ns }
    }

    /// Access the underlying namespace.
    pub fn namespace(&self) -> Arc<UserNamespace> {
        self.ns.clone()
    }
}

impl Drop for UserNamespaceFd {
    fn drop(&mut self) {
        self.ns.dec_ref();
    }
}

impl FileOps for UserNamespaceFd {
    fn clone_box(&self) -> FileDescriptor {
        self.ns.inc_ref();
        Box::new(Self { ns: self.ns.clone() })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "user_namespace_fd"
    }

    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_namespace_identity() {
        let root = ROOT_USER_NAMESPACE.clone();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
        assert_eq!(root.map_uid_to_ns(1000), Some(1000));
        assert_eq!(root.map_uid_from_ns(0), Some(0));
    }

    #[test]
    fn test_mapping_validation() {
        let mappings = vec![
            UidGidMapping { ns_id: 0, host_id: 1000, count: 1 },
            UidGidMapping { ns_id: 1, host_id: 1001, count: 1 },
        ];
        assert!(validate_mappings(&mappings).is_ok());

        // Overlapping ns_id
        let bad_mappings = vec![
            UidGidMapping { ns_id: 0, host_id: 1000, count: 2 },
            UidGidMapping { ns_id: 1, host_id: 2000, count: 1 },
        ];
        assert!(validate_mappings(&bad_mappings).is_err());
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(0, 10, 5, 10));
        assert!(!ranges_overlap(0, 5, 5, 5));
        assert!(!ranges_overlap(10, 5, 0, 5));
    }
}
