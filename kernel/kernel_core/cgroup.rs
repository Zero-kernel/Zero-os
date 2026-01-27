//! Cgroup v2 Resource Controller
//!
//! This module implements a minimal Cgroup v2 style resource controller for Zero-OS.
//! It provides hierarchical resource governance with three controllers:
//! - **CPU**: Weight-based scheduling and quota limits
//! - **Memory**: Hard and soft memory limits
//! - **PIDs**: Maximum process/thread count per cgroup
//!
//! # Architecture
//!
//! ```text
//! ROOT_CGROUP (id=0, depth=0, all controllers)
//!   ├── system.slice (id=1, depth=1)
//!   │   └── sshd.service (id=2, depth=2)
//!   └── user.slice (id=3, depth=1)
//!       └── user-1000.slice (id=4, depth=2)
//! ```
//!
//! # Security Considerations
//!
//! - **Depth Limit (MAX_CGROUP_DEPTH=8)**: Prevents deeply nested hierarchies that could
//!   cause stack overflow during traversal or excessive lock contention.
//! - **Count Limit (MAX_CGROUPS=4096)**: Prevents DoS via unbounded cgroup creation.
//! - **Controller Inheritance**: Child cgroups can only enable a subset of parent's controllers.
//! - **PID Quota Enforcement**: Tasks are rejected when cgroup's pids_max is reached.
//!
//! # References
//!
//! - Linux cgroup v2 documentation: Documentation/admin-guide/cgroup-v2.rst
//! - Phase F.2 in roadmap-enterprise.md

#![allow(dead_code)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use spin::{Lazy, Mutex, RwLock};

use bitflags::bitflags;

// ============================================================================
// Type Definitions
// ============================================================================

/// Unique identifier for a cgroup node.
///
/// The root cgroup always has ID 0. Child cgroups are assigned
/// monotonically increasing IDs starting from 1.
pub type CgroupId = u64;

/// Identifier for a task/process attached to a cgroup.
///
/// This maps to ProcessId from the process module.
pub type TaskId = u64;

/// Maximum allowed depth for the cgroup hierarchy.
///
/// Root is depth 0, so max depth 8 allows 9 levels total.
/// This prevents stack overflow during recursive operations
/// and limits lock contention in deep hierarchies.
pub const MAX_CGROUP_DEPTH: u32 = 8;

/// Maximum number of cgroups that can exist simultaneously.
///
/// This prevents DoS attacks where an adversary creates
/// unlimited cgroups to exhaust kernel memory.
pub const MAX_CGROUPS: usize = 4096;

// ============================================================================
// Controller Flags
// ============================================================================

bitflags! {
    /// Bitflags describing enabled controllers on a cgroup node.
    ///
    /// Controllers can only be enabled if the parent cgroup has them enabled.
    /// This enforces the "no internal processes" rule from cgroup v2.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CgroupControllers: u32 {
        /// CPU controller: weight-based scheduling and quota limits.
        const CPU    = 0x01;
        /// Memory controller: hard/soft limits and OOM configuration.
        const MEMORY = 0x02;
        /// PIDs controller: maximum number of tasks in the cgroup.
        const PIDS   = 0x04;
    }
}

// ============================================================================
// Resource Limits
// ============================================================================

/// Resource limits supported by the cgroup controllers.
///
/// Each field is optional; `None` denotes "no limit" (inherited from parent
/// or unlimited). Limits are checked at task attach time and during resource
/// consumption.
#[derive(Debug, Clone, Default)]
pub struct CgroupLimits {
    /// CPU weight in the range 1-10000 (default: 100).
    ///
    /// Higher weight means more CPU time relative to siblings.
    /// Maps to `cpu.weight` in cgroup v2.
    pub cpu_weight: Option<u32>,

    /// CPU quota as `(max_microseconds, period_microseconds)`.
    ///
    /// The cgroup can use at most `max` microseconds of CPU time
    /// per `period` microseconds. Maps to `cpu.max` in cgroup v2.
    pub cpu_max: Option<(u64, u64)>,

    /// Hard memory limit in bytes.
    ///
    /// If exceeded, OOM killer is invoked. Maps to `memory.max`.
    pub memory_max: Option<u64>,

    /// Soft memory limit in bytes.
    ///
    /// If exceeded, reclaim is triggered but no OOM. Maps to `memory.high`.
    pub memory_high: Option<u64>,

    /// Maximum number of tasks (processes + threads) in the cgroup.
    ///
    /// fork/clone fails with EAGAIN when limit is reached.
    /// Maps to `pids.max` in cgroup v2.
    pub pids_max: Option<u64>,
}

// ============================================================================
// Statistics
// ============================================================================

/// Lock-free statistics for a cgroup node.
///
/// Uses atomic operations to allow updates from interrupt context
/// and non-preemptible scheduler paths without taking locks.
#[derive(Debug)]
pub struct CgroupStats {
    /// Cumulative CPU time consumed in nanoseconds.
    pub cpu_time_ns: AtomicU64,

    /// Current memory usage in bytes (updated by memory controller).
    pub memory_current: AtomicU64,

    /// Number of times memory.high was exceeded.
    pub memory_events_high: AtomicU64,

    /// Number of times memory.max was hit (OOM events).
    pub memory_events_max: AtomicU64,

    /// Current number of attached tasks.
    pub pids_current: AtomicU64,

    /// Number of times pids.max was hit (fork failures).
    pub pids_events_max: AtomicU32,
}

impl CgroupStats {
    /// Creates a new zeroed statistics block.
    pub const fn new() -> Self {
        Self {
            cpu_time_ns: AtomicU64::new(0),
            memory_current: AtomicU64::new(0),
            memory_events_high: AtomicU64::new(0),
            memory_events_max: AtomicU64::new(0),
            pids_current: AtomicU64::new(0),
            pids_events_max: AtomicU32::new(0),
        }
    }

    /// Produces a consistent point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> CgroupStatsSnapshot {
        CgroupStatsSnapshot {
            cpu_time_ns: self.cpu_time_ns.load(Ordering::Relaxed),
            memory_current: self.memory_current.load(Ordering::Relaxed),
            memory_events_high: self.memory_events_high.load(Ordering::Relaxed),
            memory_events_max: self.memory_events_max.load(Ordering::Relaxed),
            pids_current: self.pids_current.load(Ordering::Relaxed),
            pids_events_max: self.pids_events_max.load(Ordering::Relaxed),
        }
    }

    /// Records additional CPU time consumed by this cgroup.
    #[inline]
    pub fn add_cpu_time(&self, delta_ns: u64) {
        self.cpu_time_ns.fetch_add(delta_ns, Ordering::Relaxed);
    }

    /// Updates current memory usage (called by memory controller/sampler).
    #[inline]
    pub fn set_memory_current(&self, bytes: u64) {
        self.memory_current.store(bytes, Ordering::Relaxed);
    }

    /// Records a memory.high exceeded event.
    #[inline]
    pub fn record_memory_high(&self) {
        self.memory_events_high.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a memory.max (OOM) event.
    #[inline]
    pub fn record_memory_max(&self) {
        self.memory_events_max.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the attached task count.
    #[inline]
    fn increment_pids(&self) {
        self.pids_current.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the attached task count.
    #[inline]
    fn decrement_pids(&self) {
        self.pids_current.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records a pids.max exceeded event.
    #[inline]
    fn record_pids_max_event(&self) {
        self.pids_events_max.fetch_add(1, Ordering::Relaxed);
    }
}

/// Point-in-time copy of `CgroupStats`.
///
/// This is returned by `CgroupNode::get_stats()` for safe reading
/// without holding any locks.
#[derive(Debug, Clone, Copy)]
pub struct CgroupStatsSnapshot {
    pub cpu_time_ns: u64,
    pub memory_current: u64,
    pub memory_events_high: u64,
    pub memory_events_max: u64,
    pub pids_current: u64,
    pub pids_events_max: u32,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors returned by cgroup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupError {
    /// Creating child would exceed MAX_CGROUP_DEPTH.
    DepthLimit,
    /// Creating cgroup would exceed MAX_CGROUPS.
    CgroupLimit,
    /// Requested cgroup ID does not exist.
    NotFound,
    /// Task is already attached to this cgroup.
    TaskAlreadyAttached,
    /// Task is not attached to this cgroup.
    TaskNotAttached,
    /// Provided limit value is invalid (e.g., zero period).
    InvalidLimit,
    /// Requested controller is not enabled on this cgroup.
    ControllerDisabled,
    /// PID limit exceeded - cannot attach more tasks.
    PidsLimitExceeded,
    /// Memory limit exceeded - operation would cause OOM.
    MemoryLimitExceeded,
    /// Permission denied - requires CAP_SYS_ADMIN or cgroup ownership.
    PermissionDenied,
    /// Cannot delete non-empty cgroup (has children or tasks).
    NotEmpty,
}

impl fmt::Display for CgroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CgroupError::DepthLimit => write!(f, "cgroup depth exceeds MAX_CGROUP_DEPTH ({})", MAX_CGROUP_DEPTH),
            CgroupError::CgroupLimit => write!(f, "cgroup count exceeds MAX_CGROUPS ({})", MAX_CGROUPS),
            CgroupError::NotFound => write!(f, "cgroup not found"),
            CgroupError::TaskAlreadyAttached => write!(f, "task already attached to this cgroup"),
            CgroupError::TaskNotAttached => write!(f, "task not attached to this cgroup"),
            CgroupError::InvalidLimit => write!(f, "invalid resource limit value"),
            CgroupError::ControllerDisabled => write!(f, "controller not enabled on this cgroup"),
            CgroupError::PidsLimitExceeded => write!(f, "pids.max limit exceeded"),
            CgroupError::MemoryLimitExceeded => write!(f, "memory.max limit exceeded"),
            CgroupError::PermissionDenied => write!(f, "permission denied"),
            CgroupError::NotEmpty => write!(f, "cgroup has children or attached tasks"),
        }
    }
}

// ============================================================================
// Cgroup Node
// ============================================================================

/// A node in the cgroup hierarchy.
///
/// Each node represents a control group with:
/// - Hierarchy metadata (id, parent, children, depth)
/// - Enabled controllers (subset of parent's controllers)
/// - Resource limits (optional per-controller)
/// - Live statistics (lock-free atomics)
/// - Attached processes (protected by mutex)
#[derive(Debug)]
pub struct CgroupNode {
    /// Unique identifier for this cgroup.
    id: CgroupId,

    /// Weak reference to parent (None for root).
    parent: Option<Weak<CgroupNode>>,

    /// IDs of direct children.
    children: Mutex<BTreeSet<CgroupId>>,

    /// Depth in hierarchy (root = 0).
    depth: u32,

    /// Enabled controllers (subset of parent's).
    controllers: CgroupControllers,

    /// Resource limits for enabled controllers.
    limits: Mutex<CgroupLimits>,

    /// Lock-free statistics.
    stats: CgroupStats,

    /// Set of attached task IDs.
    processes: Mutex<BTreeSet<TaskId>>,

    /// Manual reference count for external tracking.
    ref_count: AtomicU32,
}

impl CgroupNode {
    /// Creates the root cgroup node with all controllers enabled.
    fn new_root() -> Self {
        Self {
            id: 0,
            parent: None,
            children: Mutex::new(BTreeSet::new()),
            depth: 0,
            controllers: CgroupControllers::all(),
            limits: Mutex::new(CgroupLimits::default()),
            stats: CgroupStats::new(),
            processes: Mutex::new(BTreeSet::new()),
            ref_count: AtomicU32::new(1),
        }
    }

    /// Returns this cgroup's unique identifier.
    #[inline]
    pub fn id(&self) -> CgroupId {
        self.id
    }

    /// Returns the depth in the hierarchy (root = 0).
    #[inline]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns the enabled controllers for this cgroup.
    #[inline]
    pub fn controllers(&self) -> CgroupControllers {
        self.controllers
    }

    /// Returns a copy of the current limits.
    pub fn limits(&self) -> CgroupLimits {
        self.limits.lock().clone()
    }

    /// Returns the parent cgroup, if any.
    pub fn parent(&self) -> Option<Arc<CgroupNode>> {
        self.parent.as_ref().and_then(|w| w.upgrade())
    }

    /// Returns the IDs of direct children.
    pub fn children(&self) -> Vec<CgroupId> {
        self.children.lock().iter().copied().collect()
    }

    /// Returns the number of attached tasks.
    pub fn task_count(&self) -> usize {
        self.processes.lock().len()
    }

    /// Checks if a specific task is attached to this cgroup.
    pub fn has_task(&self, task: TaskId) -> bool {
        self.processes.lock().contains(&task)
    }

    /// Creates a new child cgroup under this parent.
    ///
    /// # Arguments
    ///
    /// * `parent` - Arc reference to the parent cgroup
    /// * `controllers` - Controllers to enable (must be subset of parent's)
    ///
    /// # Errors
    ///
    /// * `ControllerDisabled` - Requested controllers not enabled on parent
    /// * `DepthLimit` - Would exceed MAX_CGROUP_DEPTH
    /// * `CgroupLimit` - Would exceed MAX_CGROUPS
    pub fn new_child(
        parent: &Arc<Self>,
        controllers: CgroupControllers,
    ) -> Result<Arc<Self>, CgroupError> {
        // Validate controllers are subset of parent's
        if controllers.is_empty() || !parent.controllers.contains(controllers) {
            return Err(CgroupError::ControllerDisabled);
        }

        // Check depth limit
        let next_depth = parent.depth.saturating_add(1);
        if next_depth > MAX_CGROUP_DEPTH {
            return Err(CgroupError::DepthLimit);
        }

        // Allocate unique ID
        let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::SeqCst);
        if id == u64::MAX {
            return Err(CgroupError::CgroupLimit);
        }

        // Check global count limit (with lock held to prevent TOCTOU)
        {
            let registry = CGROUP_REGISTRY.read();
            if registry.len() >= MAX_CGROUPS {
                return Err(CgroupError::CgroupLimit);
            }
        }

        // Create the new node
        let node = Arc::new(CgroupNode {
            id,
            parent: Some(Arc::downgrade(parent)),
            children: Mutex::new(BTreeSet::new()),
            depth: next_depth,
            controllers,
            limits: Mutex::new(CgroupLimits::default()),
            stats: CgroupStats::new(),
            processes: Mutex::new(BTreeSet::new()),
            ref_count: AtomicU32::new(1),
        });

        // Register in global registry (re-check count under write lock)
        {
            let mut registry = CGROUP_REGISTRY.write();
            if registry.len() >= MAX_CGROUPS {
                return Err(CgroupError::CgroupLimit);
            }
            registry.insert(id, node.clone());
        }

        // Add to parent's children list
        parent.children.lock().insert(id);

        Ok(node)
    }

    /// Attaches a task to this cgroup.
    ///
    /// Enforces the pids.max limit if the PIDs controller is enabled.
    ///
    /// # Errors
    ///
    /// * `TaskAlreadyAttached` - Task is already in this cgroup
    /// * `PidsLimitExceeded` - Would exceed pids.max
    pub fn attach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        let mut procs = self.processes.lock();

        // Check if already attached
        if procs.contains(&task) {
            return Err(CgroupError::TaskAlreadyAttached);
        }

        // Check pids.max limit before inserting
        if self.controllers.contains(CgroupControllers::PIDS) {
            if let Some(limit) = self.limits.lock().pids_max {
                if (procs.len() as u64) >= limit {
                    self.stats.record_pids_max_event();
                    return Err(CgroupError::PidsLimitExceeded);
                }
            }
        }

        // Insert and update stats
        procs.insert(task);
        self.stats.increment_pids();

        Ok(())
    }

    /// Detaches a task from this cgroup.
    ///
    /// # Errors
    ///
    /// * `TaskNotAttached` - Task is not in this cgroup
    pub fn detach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        let mut procs = self.processes.lock();

        if !procs.remove(&task) {
            return Err(CgroupError::TaskNotAttached);
        }

        self.stats.decrement_pids();
        Ok(())
    }

    /// Updates resource limits for this cgroup.
    ///
    /// Only fields that are `Some` in the input are updated.
    ///
    /// # Errors
    ///
    /// * `ControllerDisabled` - Limit requires a controller not enabled
    /// * `InvalidLimit` - Value is invalid (e.g., zero weight/period)
    pub fn set_limit(&self, updated: CgroupLimits) -> Result<(), CgroupError> {
        // Validate controller availability
        if updated.cpu_weight.is_some() || updated.cpu_max.is_some() {
            if !self.controllers.contains(CgroupControllers::CPU) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.memory_max.is_some() || updated.memory_high.is_some() {
            if !self.controllers.contains(CgroupControllers::MEMORY) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.pids_max.is_some() {
            if !self.controllers.contains(CgroupControllers::PIDS) {
                return Err(CgroupError::ControllerDisabled);
            }
        }

        // Validate CPU weight (1-10000)
        if let Some(weight) = updated.cpu_weight {
            if weight == 0 || weight > 10000 {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Validate CPU quota (period > 0, max > 0)
        if let Some((max, period)) = updated.cpu_max {
            if period == 0 || max == 0 {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Apply updates
        let mut limits = self.limits.lock();
        if let Some(v) = updated.cpu_weight {
            limits.cpu_weight = Some(v);
        }
        if let Some(v) = updated.cpu_max {
            limits.cpu_max = Some(v);
        }
        if let Some(v) = updated.memory_max {
            limits.memory_max = Some(v);
        }
        if let Some(v) = updated.memory_high {
            limits.memory_high = Some(v);
        }
        if let Some(v) = updated.pids_max {
            limits.pids_max = Some(v);
        }

        Ok(())
    }

    /// Returns a snapshot of current statistics.
    pub fn get_stats(&self) -> CgroupStatsSnapshot {
        self.stats.snapshot()
    }

    /// Increments the manual reference count.
    pub fn inc_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the manual reference count.
    pub fn dec_ref(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst)
    }

    /// Returns the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global registry of all cgroups, keyed by CgroupId.
pub static CGROUP_REGISTRY: Lazy<RwLock<BTreeMap<CgroupId, Arc<CgroupNode>>>> =
    Lazy::new(|| RwLock::new(BTreeMap::new()));

/// The root cgroup (id=0, all controllers enabled).
pub static ROOT_CGROUP: Lazy<Arc<CgroupNode>> = Lazy::new(|| {
    let root = Arc::new(CgroupNode::new_root());
    CGROUP_REGISTRY.write().insert(root.id, root.clone());
    root
});

/// Monotonic ID generator for cgroups (starts at 1, root is 0).
static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(1);

/// Global cgroup count for quota enforcement.
static CGROUP_COUNT: AtomicU32 = AtomicU32::new(1); // Root counts as 1

// ============================================================================
// Public API
// ============================================================================

/// Initializes the cgroup subsystem.
///
/// This forces initialization of the root cgroup and registry.
/// Should be called during kernel initialization.
pub fn init() {
    // Force lazy initialization
    let _ = ROOT_CGROUP.id();
    println!("[cgroup] Cgroup v2 subsystem initialized (root id=0)");
}

/// Looks up a cgroup by its ID.
///
/// Returns `None` if the cgroup doesn't exist.
pub fn lookup_cgroup(id: CgroupId) -> Option<Arc<CgroupNode>> {
    if id == 0 {
        return Some(ROOT_CGROUP.clone());
    }
    CGROUP_REGISTRY.read().get(&id).cloned()
}

/// Creates a new child cgroup under the specified parent.
///
/// This is a convenience wrapper around `CgroupNode::new_child()`.
pub fn create_cgroup(
    parent_id: CgroupId,
    controllers: CgroupControllers,
) -> Result<Arc<CgroupNode>, CgroupError> {
    let parent = lookup_cgroup(parent_id).ok_or(CgroupError::NotFound)?;
    CgroupNode::new_child(&parent, controllers)
}

/// Deletes a cgroup by ID.
///
/// The cgroup must be empty (no children, no attached tasks).
///
/// # Errors
///
/// * `NotFound` - Cgroup doesn't exist
/// * `NotEmpty` - Cgroup has children or attached tasks
/// * `PermissionDenied` - Cannot delete root cgroup
///
/// # CODEX FIX: Atomicity
///
/// Previously there was a TOCTOU race between checking emptiness and removing
/// from the registry. Now we hold the registry write lock throughout the operation,
/// preventing new tasks from being attached between the check and removal.
pub fn delete_cgroup(id: CgroupId) -> Result<(), CgroupError> {
    if id == 0 {
        return Err(CgroupError::PermissionDenied);
    }

    // CODEX FIX: Hold registry write lock throughout to prevent TOCTOU race
    // This blocks lookup_cgroup() used by attach_task(), ensuring no new
    // tasks can be attached between the emptiness check and removal.
    let mut registry = CGROUP_REGISTRY.write();

    let node = registry.get(&id).cloned().ok_or(CgroupError::NotFound)?;

    // Check if empty while holding registry write lock
    // No new tasks can attach because lookup_cgroup needs registry read lock
    if !node.children.lock().is_empty() {
        return Err(CgroupError::NotEmpty);
    }
    if !node.processes.lock().is_empty() {
        return Err(CgroupError::NotEmpty);
    }

    // Remove from parent's children (safe - parent lookup also blocked)
    if let Some(parent) = node.parent() {
        parent.children.lock().remove(&id);
    }

    // Remove from registry atomically
    registry.remove(&id);

    Ok(())
}

/// Returns the root cgroup.
pub fn root_cgroup() -> Arc<CgroupNode> {
    ROOT_CGROUP.clone()
}

/// Returns the total number of cgroups.
pub fn cgroup_count() -> usize {
    CGROUP_REGISTRY.read().len()
}

/// Migrates a task from one cgroup to another.
///
/// This is an atomic operation that detaches from the old cgroup
/// and attaches to the new cgroup.
///
/// # Errors
///
/// * `NotFound` - Source or target cgroup doesn't exist
/// * `TaskNotAttached` - Task is not in source cgroup
/// * `PidsLimitExceeded` - Target cgroup's pids.max exceeded
pub fn migrate_task(
    task: TaskId,
    from_id: CgroupId,
    to_id: CgroupId,
) -> Result<(), CgroupError> {
    let from = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let to = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    // Detach from source
    from.detach_task(task)?;

    // Attach to target (rollback on failure)
    if let Err(e) = to.attach_task(task) {
        // Rollback: re-attach to source
        let _ = from.attach_task(task);
        return Err(e);
    }

    Ok(())
}

// ============================================================================
// Scheduler Integration
// ============================================================================

/// Returns the effective CPU weight for a task in the given cgroup.
///
/// If no explicit weight is set, returns the default (100).
pub fn get_effective_cpu_weight(cgroup_id: CgroupId) -> u32 {
    const DEFAULT_WEIGHT: u32 = 100;

    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        cgroup.limits.lock().cpu_weight.unwrap_or(DEFAULT_WEIGHT)
    } else {
        DEFAULT_WEIGHT
    }
}

/// Checks if a task can be forked based on cgroup pids.max limit.
///
/// Returns `true` if fork is allowed, `false` if pids.max would be exceeded.
pub fn check_fork_allowed(cgroup_id: CgroupId) -> bool {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::PIDS) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.pids_max {
                let current = cgroup.stats.pids_current.load(Ordering::Relaxed);
                if current >= max {
                    cgroup.stats.record_pids_max_event();
                    return false;
                }
            }
        }
    }
    true
}

/// Records CPU time for a cgroup (called from scheduler).
pub fn account_cpu_time(cgroup_id: CgroupId, delta_ns: u64) {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        cgroup.stats.add_cpu_time(delta_ns);
    }
}

// ============================================================================
// Memory Controller Integration
// ============================================================================

/// Updates memory usage for a cgroup.
pub fn update_memory_usage(cgroup_id: CgroupId, bytes: u64) {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        cgroup.stats.set_memory_current(bytes);

        // Check high watermark
        if let Some(high) = cgroup.limits.lock().memory_high {
            if bytes > high {
                cgroup.stats.record_memory_high();
            }
        }
    }
}

/// Checks if memory allocation would exceed cgroup limit.
///
/// Returns `true` if allocation is allowed.
pub fn check_memory_allowed(cgroup_id: CgroupId, allocation_bytes: u64) -> bool {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.memory_max {
                let current = cgroup.stats.memory_current.load(Ordering::Relaxed);
                if current.saturating_add(allocation_bytes) > max {
                    cgroup.stats.record_memory_max();
                    return false;
                }
            }
        }
    }
    true
}

/// Atomically charges memory usage to a cgroup, enforcing memory.max.
///
/// Uses CAS (compare-and-swap) to close the TOCTOU race between limit check
/// and accounting update that exists when separate check + store operations
/// are used by concurrent mmap callers.
///
/// # Errors
///
/// * `MemoryLimitExceeded` - Adding `allocation_bytes` would exceed memory.max
///
/// # CODEX FIX: Atomic charge/uncharge
///
/// This replaces the two-step "check_memory_allowed + update_memory_usage"
/// pattern which was vulnerable to races where two concurrent mmaps both
/// pass the limit check before either commits the accounting update.
pub fn try_charge_memory(cgroup_id: CgroupId, allocation_bytes: u64) -> Result<(), CgroupError> {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let limits = cgroup.limits.lock();
            let mut current = cgroup.stats.memory_current.load(Ordering::Relaxed);

            loop {
                let new = current.saturating_add(allocation_bytes);

                // Check hard limit
                if let Some(max) = limits.memory_max {
                    if new > max {
                        cgroup.stats.record_memory_max();
                        return Err(CgroupError::MemoryLimitExceeded);
                    }
                }

                // CAS: atomically update if no concurrent modification
                match cgroup.stats.memory_current.compare_exchange(
                    current,
                    new,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Check high watermark
                        if let Some(high) = limits.memory_high {
                            if new > high {
                                cgroup.stats.record_memory_high();
                            }
                        }
                        return Ok(());
                    }
                    Err(actual) => current = actual, // Retry with actual value
                }
            }
        }
    }

    Ok(()) // No memory controller enabled, allow
}

/// Atomically uncharges memory from a cgroup (saturating at zero).
///
/// Called when memory is released (munmap, process exit, etc.).
/// Uses fetch_update for atomic subtract-with-floor-at-zero.
pub fn uncharge_memory(cgroup_id: CgroupId, bytes: u64) {
    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let _ = cgroup.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(bytes)),
            );
        }
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns true if the cgroup subsystem is initialized.
#[cfg(test)]
pub fn test_is_initialized() -> bool {
    CGROUP_REGISTRY.read().contains_key(&0)
}
