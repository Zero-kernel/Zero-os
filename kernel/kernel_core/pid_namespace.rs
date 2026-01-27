//! PID Namespace Support
//!
//! Implements Linux-compatible PID namespaces for process isolation.
//!
//! # Overview
//!
//! PID namespaces provide isolated PID number spaces. Each namespace has:
//! - Its own PID numbering starting from 1
//! - A hierarchical relationship with parent namespaces
//! - An "init" process (PID 1) that owns the namespace
//!
//! # Linux Compatibility
//!
//! - Processes have a PID in each ancestor namespace (root has global PID)
//! - Parent namespaces can see child namespace processes (with parent's PID)
//! - Child namespaces cannot see parent namespace processes
//! - When namespace init (PID 1) dies, all processes in namespace are killed
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create a new child namespace
//! let child_ns = PidNamespace::new_child(parent_ns);
//!
//! // Allocate PID chain for a new process
//! let chain = assign_pid_chain(child_ns, global_pid)?;
//!
//! // Translate PID between namespaces
//! let ns_pid = pid_in_namespace(&ns, global_pid);
//! let global = resolve_pid_in_namespace(&ns, ns_pid);
//! ```

use alloc::{collections::BTreeMap, sync::{Arc, Weak}, vec, vec::Vec};
use cap::NamespaceId;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use crate::process::{ProcessId, MAX_PID};

// ============================================================================
// Constants
// ============================================================================

/// Maximum PID namespace nesting depth (Linux default is 32)
pub const MAX_PID_NS_LEVEL: u8 = 32;

/// R76-2 FIX: Maximum number of PID namespaces allowed system-wide (including root).
/// Prevents DoS via namespace exhaustion. Value chosen to allow reasonable containerization
/// while preventing memory exhaustion attacks.
pub const MAX_PID_NS_COUNT: u32 = 1024;

/// R76-2 FIX: Current PID namespace count (root starts at 1).
/// Atomic counter to enforce MAX_PID_NS_COUNT limit.
static PID_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during PID namespace operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidNamespaceError {
    /// PID space exhausted in namespace
    PidExhausted,
    /// Init process already set for namespace
    InitAlreadySet,
    /// Maximum namespace nesting depth exceeded
    MaxDepthExceeded,
    /// R76-2 FIX: Maximum system-wide namespace count exceeded
    MaxNamespaces,
    /// Namespace is shutting down
    NamespaceShuttingDown,
    /// Invalid operation on root namespace
    InvalidOnRoot,
}

// ============================================================================
// PID Namespace Membership
// ============================================================================

/// Represents a process's membership in a PID namespace.
///
/// Each process has a membership entry for every namespace in its hierarchy,
/// from the root namespace down to its owning namespace.
#[derive(Clone)]
pub struct PidNamespaceMembership {
    /// The namespace this membership is in
    pub ns: Arc<PidNamespace>,
    /// The PID as seen from this namespace
    pub pid: ProcessId,
}

impl core::fmt::Debug for PidNamespaceMembership {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PidNamespaceMembership")
            .field("ns_id", &self.ns.id().raw())
            .field("pid", &self.pid)
            .finish()
    }
}

// ============================================================================
// PID Namespace
// ============================================================================

/// A PID namespace providing isolated process ID numbering.
///
/// # Hierarchy
///
/// PID namespaces form a tree structure:
/// - Root namespace (level 0) has no parent and uses global PIDs
/// - Child namespaces have their own PID counters starting from 1
/// - Processes are visible to all ancestor namespaces with different PIDs
///
/// # Init Process
///
/// The first process in a namespace becomes its init (PID 1).
/// When init exits, all processes in the namespace are killed.
#[derive(Debug)]
pub struct PidNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<PidNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Next PID to allocate in this namespace
    next_pid: Mutex<ProcessId>,

    /// Namespace PID -> Global PID mapping
    pid_by_ns: Mutex<BTreeMap<ProcessId, ProcessId>>,

    /// Global PID -> Namespace PID mapping
    pid_by_global: Mutex<BTreeMap<ProcessId, ProcessId>>,

    /// Init process global PID (PID 1 in this namespace)
    init_global_pid: Mutex<Option<ProcessId>>,

    /// Whether namespace is shutting down (init died)
    shutting_down: AtomicBool,

    /// R73-2 FIX: Child namespaces for cascade kill traversal
    children: Mutex<Vec<Weak<PidNamespace>>>,
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// The root PID namespace (level 0, no parent)
    ///
    /// All processes start in the root namespace unless CLONE_NEWPID is used.
    /// The root namespace uses global PIDs directly (no translation needed).
    pub static ref ROOT_PID_NAMESPACE: Arc<PidNamespace> = Arc::new(PidNamespace::new_root());

    /// Counter for generating unique namespace IDs
    static ref NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);
}

// ============================================================================
// PidNamespace Implementation
// ============================================================================

impl PidNamespace {
    /// Create the root PID namespace.
    ///
    /// The root namespace:
    /// - Has level 0
    /// - Has no parent
    /// - Uses global PIDs directly (no translation)
    fn new_root() -> Self {
        PidNamespace {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            next_pid: Mutex::new(1),
            pid_by_ns: Mutex::new(BTreeMap::new()),
            pid_by_global: Mutex::new(BTreeMap::new()),
            init_global_pid: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            children: Mutex::new(Vec::new()),
        }
    }

    /// Create a new child namespace.
    ///
    /// The child namespace:
    /// - Has its own PID numbering starting from 1
    /// - Can be nested up to MAX_PID_NS_LEVEL deep
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent namespace
    ///
    /// # Returns
    ///
    /// New namespace or error if max depth exceeded
    pub fn new_child(parent: Arc<PidNamespace>) -> Result<Arc<Self>, PidNamespaceError> {
        // Check nesting depth
        if parent.level >= MAX_PID_NS_LEVEL {
            return Err(PidNamespaceError::MaxDepthExceeded);
        }

        // R76-2 FIX: Enforce global namespace count limit to prevent DoS.
        // This prevents an attacker from creating unbounded namespaces and
        // exhausting kernel memory. We use compare-exchange loop to avoid
        // TOCTOU race condition between check and increment.
        let prev = PID_NS_COUNT.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_PID_NS_COUNT {
            // Restore count and fail
            PID_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
            return Err(PidNamespaceError::MaxNamespaces);
        }

        // Generate unique namespace ID
        let id = NEXT_NS_ID.fetch_add(1, Ordering::SeqCst);

        let child = Arc::new(PidNamespace {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            next_pid: Mutex::new(1),
            pid_by_ns: Mutex::new(BTreeMap::new()),
            pid_by_global: Mutex::new(BTreeMap::new()),
            init_global_pid: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            children: Mutex::new(Vec::new()),
        });

        // R73-2 FIX: Register child in parent's children list for cascade kill traversal
        parent.children.lock().push(Arc::downgrade(&child));

        Ok(child)
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<PidNamespace>> {
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

    /// Allocate a namespace-local PID for the given global PID.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    ///
    /// # Returns
    ///
    /// The namespace-local PID or error if exhausted
    pub fn alloc_pid(&self, global_pid: ProcessId) -> Result<ProcessId, PidNamespaceError> {
        // Check if shutting down
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(PidNamespaceError::NamespaceShuttingDown);
        }

        let mut next = self.next_pid.lock();
        if *next > MAX_PID {
            return Err(PidNamespaceError::PidExhausted);
        }

        let ns_pid = *next;
        *next += 1;

        // Update mappings - ALWAYS lock pid_by_global first to avoid deadlock with remove_pid
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        by_global.insert(global_pid, ns_pid);
        by_ns.insert(ns_pid, global_pid);

        Ok(ns_pid)
    }

    /// Attach a global PID to the root namespace.
    ///
    /// In the root namespace, global PID == namespace PID (identity mapping).
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    pub fn attach_root_pid(&self, global_pid: ProcessId) {
        debug_assert!(self.is_root(), "attach_root_pid called on non-root namespace");
        // Lock in same order as alloc_pid to avoid deadlock
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        by_global.insert(global_pid, global_pid);
        by_ns.insert(global_pid, global_pid);
    }

    /// Remove a process from this namespace.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    pub fn remove_pid(&self, global_pid: ProcessId) {
        // Lock in same order as alloc_pid to avoid deadlock
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if let Some(ns_pid) = by_global.remove(&global_pid) {
            by_ns.remove(&ns_pid);
        }
    }

    /// Lookup global PID from namespace-local PID.
    ///
    /// # Arguments
    ///
    /// * `ns_pid` - The namespace-local PID
    ///
    /// # Returns
    ///
    /// The global PID if found
    pub fn lookup_global(&self, ns_pid: ProcessId) -> Option<ProcessId> {
        self.pid_by_ns.lock().get(&ns_pid).copied()
    }

    /// Lookup namespace-local PID from global PID.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The global PID
    ///
    /// # Returns
    ///
    /// The namespace-local PID if the process is visible in this namespace
    pub fn lookup_ns_pid(&self, global_pid: ProcessId) -> Option<ProcessId> {
        self.pid_by_global.lock().get(&global_pid).copied()
    }

    /// Set the init process for this namespace.
    ///
    /// The first process (PID 1) in a namespace becomes its init.
    /// This can only be set once.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The init process's global PID
    pub fn set_init(&self, global_pid: ProcessId) -> Result<(), PidNamespaceError> {
        let mut init = self.init_global_pid.lock();
        if init.is_some() {
            return Err(PidNamespaceError::InitAlreadySet);
        }
        *init = Some(global_pid);
        Ok(())
    }

    /// Get the init process's global PID.
    #[inline]
    pub fn init_global_pid(&self) -> Option<ProcessId> {
        *self.init_global_pid.lock()
    }

    /// Check if the given global PID is the init process of this namespace.
    #[inline]
    pub fn is_init(&self, global_pid: ProcessId) -> bool {
        *self.init_global_pid.lock() == Some(global_pid)
    }

    /// Mark the namespace as shutting down.
    ///
    /// Called when init exits. Returns true if this call triggered the transition.
    pub fn mark_shutting_down(&self) -> bool {
        !self.shutting_down.swap(true, Ordering::SeqCst)
    }

    /// Check if namespace is shutting down.
    #[inline]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Get all global PIDs of processes in this namespace.
    ///
    /// Used for cascade killing when init exits.
    pub fn members(&self) -> Vec<ProcessId> {
        self.pid_by_ns.lock().values().copied().collect()
    }

    /// Get the number of processes in this namespace.
    pub fn member_count(&self) -> usize {
        self.pid_by_ns.lock().len()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Assign PID chain for a new process.
///
/// Creates membership entries for every namespace from root to the target,
/// allocating namespace-local PIDs in each.
///
/// # Arguments
///
/// * `leaf` - The owning namespace (deepest in hierarchy)
/// * `global_pid` - The process's global PID
///
/// # Returns
///
/// Vec of memberships from root to leaf, or error if PID allocation fails
///
/// # Linux Semantics
///
/// A process is visible in all ancestor namespaces with different PIDs.
/// Example: Process in level-2 namespace has 3 PIDs (root, level-1, level-2).
pub fn assign_pid_chain(
    leaf: Arc<PidNamespace>,
    global_pid: ProcessId,
) -> Result<Vec<PidNamespaceMembership>, PidNamespaceError> {
    // Build path from leaf to root
    let mut path: Vec<Arc<PidNamespace>> = Vec::new();
    let mut cursor = Some(leaf.clone());
    while let Some(ns) = cursor {
        path.push(ns.clone());
        cursor = ns.parent();
    }

    // Reverse to allocate from root downward
    path.reverse();

    // Allocate PIDs in each namespace
    let mut chain: Vec<PidNamespaceMembership> = Vec::with_capacity(path.len());
    for ns in path {
        let ns_pid = if ns.is_root() {
            // Root namespace uses global PID directly
            ns.attach_root_pid(global_pid);
            global_pid
        } else {
            // Child namespaces allocate their own PIDs
            match ns.alloc_pid(global_pid) {
                Ok(pid) => pid,
                Err(e) => {
                    // Roll back any mappings created so far to avoid ghost PIDs
                    for allocated in &chain {
                        allocated.ns.remove_pid(global_pid);
                    }
                    return Err(e);
                }
            }
        };

        // NOTE: Do NOT set init here - defer until chain is fully allocated.
        // If we set init and a later alloc_pid fails, we'd have an orphaned init.

        chain.push(PidNamespaceMembership { ns, pid: ns_pid });
    }

    // Now that the full chain succeeded, set init for any namespace where this is PID 1.
    //
    // This ensures we don't leave init_global_pid set for a namespace whose process
    // failed to allocate PIDs further down the chain.
    for membership in &chain {
        if !membership.ns.is_root() && membership.pid == 1 {
            // Ignore error if init already set (shouldn't happen for fresh namespace)
            let _ = membership.ns.set_init(global_pid);
        }
    }

    Ok(chain)
}

/// Remove a process from all namespaces it belongs to.
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
/// * `global_pid` - The process's global PID
pub fn detach_pid_chain(chain: &[PidNamespaceMembership], global_pid: ProcessId) {
    for membership in chain {
        membership.ns.remove_pid(global_pid);
    }
}

/// Translate a namespace-local PID to global PID.
///
/// # Arguments
///
/// * `ns` - The namespace to resolve in
/// * `ns_pid` - The namespace-local PID
///
/// # Returns
///
/// The global PID if the process is visible in the namespace
pub fn resolve_pid_in_namespace(ns: &Arc<PidNamespace>, ns_pid: ProcessId) -> Option<ProcessId> {
    ns.lookup_global(ns_pid)
}

/// Translate a global PID to namespace-local PID.
///
/// # Arguments
///
/// * `ns` - The namespace to translate for
/// * `global_pid` - The global PID
///
/// # Returns
///
/// The namespace-local PID if the process is visible
pub fn pid_in_namespace(ns: &Arc<PidNamespace>, global_pid: ProcessId) -> Option<ProcessId> {
    ns.lookup_ns_pid(global_pid)
}

/// Get the owning namespace for a process (deepest/leaf namespace).
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
///
/// # Returns
///
/// The owning namespace (last in chain)
pub fn owning_namespace(chain: &[PidNamespaceMembership]) -> Option<Arc<PidNamespace>> {
    chain.last().map(|m| m.ns.clone())
}

/// Get the PID as seen from the process's owning namespace.
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
///
/// # Returns
///
/// The namespace-local PID in the owning namespace
pub fn pid_in_owning_namespace(chain: &[PidNamespaceMembership]) -> Option<ProcessId> {
    chain.last().map(|m| m.pid)
}

/// Check if a process is visible from a namespace.
///
/// Processes are visible in their owning namespace and all ancestors.
///
/// # Arguments
///
/// * `target_ns` - The namespace to check visibility from
/// * `chain` - The process's namespace membership chain
pub fn is_visible_in_namespace(
    target_ns: &Arc<PidNamespace>,
    chain: &[PidNamespaceMembership],
) -> bool {
    chain.iter().any(|m| Arc::ptr_eq(&m.ns, target_ns))
}

/// Get all namespaces that need cascade kill when init exits.
///
/// When init of a namespace exits, all processes in that namespace
/// and its descendants must be killed.
///
/// # Arguments
///
/// * `ns` - The namespace whose init is exiting
///
/// # Returns
///
/// Global PIDs of all processes to kill
pub fn get_cascade_kill_pids(ns: &Arc<PidNamespace>) -> Vec<ProcessId> {
    // R73-2 FIX: Traverse the entire namespace subtree, including descendants
    let mut pids = Vec::new();
    let mut stack: Vec<Arc<PidNamespace>> = vec![ns.clone()];

    while let Some(cur) = stack.pop() {
        // Get all members of this namespace (except init itself)
        let init_pid = cur.init_global_pid();
        for pid in cur.members() {
            if init_pid != Some(pid) {
                pids.push(pid);
            }
        }

        // Traverse child namespaces
        let mut children = cur.children.lock();
        // Clean up released children (strong_count == 0)
        children.retain(|w: &Weak<PidNamespace>| w.strong_count() > 0);
        // Add live children to the traversal stack
        stack.extend(children.iter().filter_map(|w: &Weak<PidNamespace>| w.upgrade()));
    }

    pids
}

// ============================================================================
// Debug Helpers
// ============================================================================

/// Print namespace hierarchy for debugging.
pub fn print_namespace_info(ns: &Arc<PidNamespace>) {
    println!(
        "[PID NS] id={}, level={}, members={}, init={:?}, shutting_down={}",
        ns.id().raw(),
        ns.level(),
        ns.member_count(),
        ns.init_global_pid(),
        ns.is_shutting_down()
    );
}

/// Print a process's namespace chain for debugging.
pub fn print_pid_chain(chain: &[PidNamespaceMembership]) {
    print!("[PID chain] ");
    for (i, m) in chain.iter().enumerate() {
        if i > 0 {
            print!(" -> ");
        }
        print!("ns{}:pid{}", m.ns.id().raw(), m.pid);
    }
    println!();
}

// ============================================================================
// R76-2 FIX: Namespace Resource Cleanup
// ============================================================================

/// R76-2 FIX: Decrement global namespace counter when namespace is destroyed.
/// This ensures that the global namespace count is properly maintained and
/// prevents counter leaks that could lead to spurious MaxNamespaces errors.
impl Drop for PidNamespace {
    fn drop(&mut self) {
        // Only decrement for non-root namespaces (root is never dropped)
        if self.level > 0 {
            PID_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
