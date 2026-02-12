//! CPU Set (cpuset) Implementation for CPU Isolation
//!
//! Provides CPU isolation by allowing processes to be restricted to a subset of CPUs.
//! This is the foundation for cgroup CPU controller and container CPU isolation.
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |   Root Cpuset    |  <- All online CPUs (ID 0)
//! |   cpus_allowed   |
//! +--------+---------+
//!          |
//!     +----+----+
//!     |         |
//!  +--v--+   +--v--+
//!  |Set A|   |Set B|  <- User-created cpusets (subsets of parent)
//!  +-----+   +-----+
//! ```
//!
//! # Effective Affinity
//!
//! The effective CPU mask for a task is:
//! `online_mask ∩ cpuset_mask ∩ task_affinity`
//!
//! This ensures tasks only run on CPUs that are:
//! 1. Currently online
//! 2. In the task's cpuset
//! 3. In the task's personal affinity mask
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create a cpuset limited to CPUs 0-3
//! let id = cpuset_create(0b1111)?;
//!
//! // Attach a process to this cpuset
//! cpuset_attach(pid, id)?;
//!
//! // The process is now restricted to CPUs 0-3
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use cpu_local::max_cpus;
use spin::{Mutex, RwLock};

/// Unique identifier for a cpuset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpusetId(pub u32);

impl CpusetId {
    /// Root cpuset ID (contains all CPUs)
    pub const ROOT: CpusetId = CpusetId(0);

    /// Invalid cpuset ID (used for error returns)
    pub const INVALID: CpusetId = CpusetId(u32::MAX);
}

/// A cpuset node representing a set of CPUs.
///
/// Tasks attached to a cpuset can only run on CPUs in its `cpus_allowed` mask.
/// Cpusets form a hierarchy where children are subsets of their parent.
pub struct CpusetNode {
    /// Unique identifier for this cpuset
    pub id: CpusetId,
    /// Bitmask of CPUs allowed (bit N = CPU N)
    cpus_allowed: AtomicU64,
    /// Parent cpuset (None for root)
    parent: Option<Weak<CpusetNode>>,
    /// Number of tasks attached to this cpuset
    task_count: AtomicU32,
}

impl CpusetNode {
    /// Create a new cpuset node.
    fn new(id: CpusetId, cpus: u64, parent: Option<Weak<CpusetNode>>) -> Self {
        Self {
            id,
            cpus_allowed: AtomicU64::new(cpus),
            parent,
            task_count: AtomicU32::new(0),
        }
    }

    /// Get the CPU mask for this cpuset.
    #[inline]
    pub fn cpus(&self) -> u64 {
        self.cpus_allowed.load(Ordering::Acquire)
    }

    /// Set the CPU mask for this cpuset.
    ///
    /// Note: Caller must ensure the new mask is a subset of the parent's mask.
    pub fn set_cpus(&self, cpus: u64) {
        self.cpus_allowed.store(cpus, Ordering::Release);
    }

    /// Get the number of tasks in this cpuset.
    #[inline]
    pub fn task_count(&self) -> u32 {
        self.task_count.load(Ordering::Relaxed)
    }

    /// Increment task count when a task joins.
    fn task_joined(&self) {
        self.task_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement task count when a task leaves.
    fn task_left(&self) {
        self.task_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Check if a CPU is allowed by this cpuset.
    #[inline]
    pub fn cpu_allowed(&self, cpu_id: usize) -> bool {
        if cpu_id >= 64 {
            return false;
        }
        let mask = self.cpus_allowed.load(Ordering::Relaxed);
        (mask & (1u64 << cpu_id)) != 0
    }

    /// Get the effective CPU mask considering parent hierarchy.
    ///
    /// Returns the intersection of this cpuset's mask with all ancestors.
    pub fn effective_cpus(&self) -> u64 {
        let mut mask = self.cpus_allowed.load(Ordering::Acquire);
        if let Some(ref parent_weak) = self.parent {
            if let Some(parent) = parent_weak.upgrade() {
                mask &= parent.effective_cpus();
            }
        }
        mask
    }
}

/// Global cpuset registry.
struct CpusetRegistry {
    /// Map from cpuset ID to cpuset node
    sets: BTreeMap<CpusetId, Arc<CpusetNode>>,
    /// Next available cpuset ID
    next_id: u32,
}

impl CpusetRegistry {
    fn new() -> Self {
        Self {
            sets: BTreeMap::new(),
            next_id: 1, // 0 is reserved for root
        }
    }
}

/// Global cpuset registry protected by RwLock.
static CPUSET_REGISTRY: RwLock<Option<CpusetRegistry>> = RwLock::new(None);

/// Root cpuset (contains all online CPUs).
static ROOT_CPUSET: Mutex<Option<Arc<CpusetNode>>> = Mutex::new(None);

/// Initialize the cpuset subsystem.
///
/// Creates the root cpuset containing all online CPUs.
/// Must be called after CPU enumeration is complete.
pub fn init() {
    let online_mask = online_cpu_mask();

    // Create root cpuset
    let root = Arc::new(CpusetNode::new(CpusetId::ROOT, online_mask, None));

    // Store root cpuset
    *ROOT_CPUSET.lock() = Some(Arc::clone(&root));

    // Initialize registry with root
    let mut registry = CpusetRegistry::new();
    registry.sets.insert(CpusetId::ROOT, root);
    *CPUSET_REGISTRY.write() = Some(registry);

    // E.5: Register cpuset callbacks with kernel_core for fork/exit notifications
    kernel_core::register_cpuset_task_joined(cpuset_task_joined_callback);
    kernel_core::register_cpuset_task_left(cpuset_task_left_callback);

    klog_always!("[CPUSET] Initialized with root mask 0x{:016x}", online_mask);
}

/// Get the current online CPU mask.
///
/// This returns a mask where bit N is set if CPU N is online.
#[inline]
pub fn online_cpu_mask() -> u64 {
    let cpu_count = max_cpus();
    if cpu_count >= 64 {
        u64::MAX
    } else {
        (1u64 << cpu_count) - 1
    }
}

/// Get the root cpuset.
pub fn root_cpuset() -> Option<Arc<CpusetNode>> {
    ROOT_CPUSET.lock().clone()
}

/// Get a cpuset by ID.
pub fn get_cpuset(id: CpusetId) -> Option<Arc<CpusetNode>> {
    CPUSET_REGISTRY.read().as_ref()?.sets.get(&id).cloned()
}

/// Create a new cpuset with the specified CPU mask.
///
/// # Arguments
/// * `cpus` - Bitmask of CPUs to allow (must be subset of root)
/// * `parent_id` - Parent cpuset ID (or ROOT for top-level)
///
/// # Returns
/// * `Ok(CpusetId)` - ID of the new cpuset
/// * `Err(CpusetError)` - If creation fails
pub fn cpuset_create(cpus: u64, parent_id: CpusetId) -> Result<CpusetId, CpusetError> {
    let mut registry_guard = CPUSET_REGISTRY.write();
    let registry = registry_guard.as_mut().ok_or(CpusetError::NotInitialized)?;

    // Get parent cpuset
    let parent = registry.sets.get(&parent_id).ok_or(CpusetError::InvalidParent)?;

    // Validate mask is subset of parent
    let parent_mask = parent.cpus();
    if (cpus & !parent_mask) != 0 {
        return Err(CpusetError::InvalidMask);
    }

    // Validate mask is not empty
    if cpus == 0 {
        return Err(CpusetError::EmptyMask);
    }

    // Allocate new ID
    let id = CpusetId(registry.next_id);
    registry.next_id = registry.next_id.checked_add(1).ok_or(CpusetError::TooManySets)?;

    // Create cpuset node
    let node = Arc::new(CpusetNode::new(id, cpus, Some(Arc::downgrade(parent))));
    registry.sets.insert(id, node);

    Ok(id)
}

/// Destroy a cpuset.
///
/// The cpuset must have no attached tasks and no child cpusets.
pub fn cpuset_destroy(id: CpusetId) -> Result<(), CpusetError> {
    if id == CpusetId::ROOT {
        return Err(CpusetError::CannotDestroyRoot);
    }

    let mut registry_guard = CPUSET_REGISTRY.write();
    let registry = registry_guard.as_mut().ok_or(CpusetError::NotInitialized)?;

    // Get cpuset and check task count
    let cpuset = registry.sets.get(&id).ok_or(CpusetError::NotFound)?;
    if cpuset.task_count() > 0 {
        return Err(CpusetError::NotEmpty);
    }

    // R73-3 FIX: Prevent destroying cpusets that still have children
    // This would leave orphaned cpusets that bypass parent mask constraints
    let has_children = registry
        .sets
        .values()
        .any(|child| {
            child
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.id == cpuset.id)
                .unwrap_or(false)
        });
    if has_children {
        return Err(CpusetError::NotEmpty); // Reuse NotEmpty - has child cpusets
    }

    registry.sets.remove(&id);
    Ok(())
}

/// Update the CPU mask of a cpuset.
///
/// # Arguments
/// * `id` - Cpuset ID
/// * `cpus` - New CPU mask (must be subset of parent)
pub fn cpuset_set_cpus(id: CpusetId, cpus: u64) -> Result<(), CpusetError> {
    let registry_guard = CPUSET_REGISTRY.read();
    let registry = registry_guard.as_ref().ok_or(CpusetError::NotInitialized)?;

    let cpuset = registry.sets.get(&id).ok_or(CpusetError::NotFound)?;

    // For root, validate against online CPUs
    if id == CpusetId::ROOT {
        let online = online_cpu_mask();
        if (cpus & !online) != 0 {
            return Err(CpusetError::InvalidMask);
        }
    } else {
        // For non-root, validate against parent
        // R73-3 FIX: Return error if parent is missing or dropped
        // This prevents bypassing parent mask constraints after orphaning
        match &cpuset.parent {
            Some(parent_weak) => {
                match parent_weak.upgrade() {
                    Some(parent) => {
                        let parent_mask = parent.cpus();
                        if (cpus & !parent_mask) != 0 {
                            return Err(CpusetError::InvalidMask);
                        }
                    }
                    None => {
                        // Parent has been destroyed - hierarchy integrity violated
                        return Err(CpusetError::InvalidParent);
                    }
                }
            }
            None => {
                // Non-root cpuset without parent reference - should not happen
                return Err(CpusetError::InvalidParent);
            }
        }
    }

    if cpus == 0 {
        return Err(CpusetError::EmptyMask);
    }

    cpuset.set_cpus(cpus);
    Ok(())
}

/// Get the effective CPU mask for a task.
///
/// This computes: `online_mask ∩ cpuset_mask ∩ task_affinity`
///
/// # Arguments
/// * `cpuset_id` - Task's cpuset ID
/// * `task_affinity` - Task's personal affinity mask (0 = all CPUs)
#[inline]
pub fn effective_cpus(cpuset_id: CpusetId, task_affinity: u64) -> u64 {
    let online = online_cpu_mask();

    let cpuset_mask = get_cpuset(cpuset_id)
        .map(|cs| cs.effective_cpus())
        .unwrap_or(online);

    // task_affinity == 0 means "no restriction"
    let affinity = if task_affinity == 0 { online } else { task_affinity };

    online & cpuset_mask & affinity
}

/// Check if a CPU is allowed for a task given its cpuset and affinity.
///
/// # Arguments
/// * `cpu_id` - CPU to check
/// * `cpuset_id` - Task's cpuset ID
/// * `task_affinity` - Task's personal affinity mask (0 = all CPUs)
#[inline]
pub fn is_cpu_allowed(cpu_id: usize, cpuset_id: CpusetId, task_affinity: u64) -> bool {
    if cpu_id >= 64 {
        return false;
    }
    let mask = effective_cpus(cpuset_id, task_affinity);
    (mask & (1u64 << cpu_id)) != 0
}

/// Called when a task joins a cpuset.
pub fn task_joined(cpuset_id: CpusetId) {
    if let Some(cpuset) = get_cpuset(cpuset_id) {
        cpuset.task_joined();
    }
}

/// Called when a task leaves a cpuset.
pub fn task_left(cpuset_id: CpusetId) {
    if let Some(cpuset) = get_cpuset(cpuset_id) {
        cpuset.task_left();
    }
}

/// E.5: Callback wrapper for task_joined (used by kernel_core callback system)
///
/// This function matches the CpusetTaskJoinedCallback signature (fn(u32))
/// and is registered during cpuset initialization.
fn cpuset_task_joined_callback(cpuset_id: u32) {
    task_joined(CpusetId(cpuset_id));
}

/// E.5: Callback wrapper for task_left (used by kernel_core callback system)
///
/// This function matches the CpusetTaskLeftCallback signature (fn(u32))
/// and is registered during cpuset initialization.
fn cpuset_task_left_callback(cpuset_id: u32) {
    task_left(CpusetId(cpuset_id));
}

/// Errors that can occur during cpuset operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpusetError {
    /// Cpuset subsystem not initialized
    NotInitialized,
    /// Cpuset not found
    NotFound,
    /// Invalid parent cpuset
    InvalidParent,
    /// CPU mask is not a subset of parent
    InvalidMask,
    /// CPU mask is empty
    EmptyMask,
    /// Cannot destroy root cpuset
    CannotDestroyRoot,
    /// Cpuset has attached tasks
    NotEmpty,
    /// Too many cpusets created
    TooManySets,
    /// Permission denied
    PermissionDenied,
}

impl CpusetError {
    /// Convert to errno-style error code.
    pub fn to_errno(&self) -> i32 {
        match self {
            CpusetError::NotInitialized => -22,  // EINVAL
            CpusetError::NotFound => -2,         // ENOENT
            CpusetError::InvalidParent => -22,   // EINVAL
            CpusetError::InvalidMask => -22,     // EINVAL
            CpusetError::EmptyMask => -22,       // EINVAL
            CpusetError::CannotDestroyRoot => -1, // EPERM
            CpusetError::NotEmpty => -16,        // EBUSY
            CpusetError::TooManySets => -12,     // ENOMEM
            CpusetError::PermissionDenied => -1, // EPERM
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_cpus() {
        // Test with 8 CPUs online
        let online = 0xFF; // CPUs 0-7
        let cpuset = 0x0F; // CPUs 0-3
        let affinity = 0x03; // CPUs 0-1

        // Effective should be intersection
        let eff = online & cpuset & affinity;
        assert_eq!(eff, 0x03); // CPUs 0-1
    }

    #[test]
    fn test_cpu_allowed() {
        let mask = 0b1010u64; // CPUs 1 and 3

        assert!(!is_bit_set(mask, 0));
        assert!(is_bit_set(mask, 1));
        assert!(!is_bit_set(mask, 2));
        assert!(is_bit_set(mask, 3));
    }

    fn is_bit_set(mask: u64, bit: usize) -> bool {
        bit < 64 && (mask & (1u64 << bit)) != 0
    }
}
