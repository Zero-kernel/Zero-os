//! Lock Ordering and Synchronization Documentation
//!
//! This module documents the global lock ordering for Zero-OS to prevent deadlocks
//! in SMP environments. All locks must be acquired in the order specified below.
//!
//! # E.4 Lockdep Implementation
//!
//! This module provides runtime deadlock detection (lockdep) with:
//! - Per-CPU lock stack tracking via `CpuLocal<LockStack>`
//! - Lock class identification via `LockClassKey`
//! - `LockdepMutex<T>` wrapper around `spin::Mutex` with ordering validation
//! - Optional dependency graph cycle detection (`lockdep_graph` feature)
//!
//! # Lock Ordering (Acquire in this order, release in reverse)
//!
//! ```text
//! Level 1 (Highest - Interrupt Control)
//! ├── IRQ disable
//! │
//! Level 2 (Per-CPU Data)
//! ├── Per-CPU locks (via CpuLocal)
//! │
//! Level 3 (Scheduler)
//! ├── READY_QUEUE
//! ├── CURRENT_PROCESS
//! ├── SCHEDULER_STATS
//! │
//! Level 4 (Memory Management)
//! ├── COW_FAULT_LOCK (fork.rs:412) - serialize COW page fault handling
//! ├── PT_LOCK (page_table.rs:39) - global page table operations
//! ├── PAGE_TABLE_MANAGER
//! ├── BUDDY_ALLOCATOR / FRAME_ALLOCATOR
//! ├── HEAP_ALLOCATOR (global_alloc)
//! │
//! Level 5 (Process/Thread)
//! ├── PROCESS_TABLE
//! ├── Process::inner (per-process mutex)
//! │
//! Level 6 (VFS)
//! ├── VFS root lock
//! ├── Inode locks (per-inode)
//! ├── File table locks (per-process)
//! │
//! Level 7 (IPC)
//! ├── ENDPOINT_REGISTRY
//! ├── Pipe locks (per-pipe)
//! ├── Futex locks (per-futex)
//! │
//! Level 8 (Device/Driver)
//! ├── VGA_BUFFER / FRAMEBUFFER
//! ├── SERIAL_PORT
//! ├── Keyboard buffer
//! │
//! Level 9 (Audit/Security)
//! ├── AUDIT_RING
//! ├── RNG_STATE
//! └── KPTR_KEY
//! ```
//!
//! # Lock Ordering Rules
//!
//! 1. **Never acquire a higher-level lock while holding a lower-level lock**
//!    - If you hold PROCESS_TABLE (Level 5), you cannot acquire READY_QUEUE (Level 3)
//!
//! 2. **Interrupt handling restrictions**
//!    - IRQ handlers can only acquire Level 8+ locks
//!    - Never acquire scheduler or memory locks in IRQ context
//!
//! 3. **Per-process locks are independent**
//!    - Two different Process::inner locks can be held simultaneously
//!    - But avoid if possible (fork/clone edge cases)
//!
//! 4. **Spinlock vs Mutex**
//!    - Use spin::Mutex for short critical sections
//!    - Spin locks must not be held across yield/sleep
//!
//! # Current Lock Inventory
//!
//! | Lock | Module | Level | Type | Notes |
//! |------|--------|-------|------|-------|
//! | READY_QUEUE | sched/enhanced_scheduler.rs | 3 | Mutex<BTreeMap> | Per-CPU in SMP |
//! | CURRENT_PROCESS | sched/enhanced_scheduler.rs | 3 | Mutex<Option<Pid>> | Per-CPU in SMP |
//! | COW_FAULT_LOCK | kernel_core/fork.rs | 4a | Mutex<()> | Static, serialize COW faults |
//! | PT_LOCK | mm/page_table.rs | 4b | Mutex<()> | Global page table ops |
//! | PAGE_TABLE_MANAGER | mm/page_table.rs | 4 | Once<Mutex> | Global |
//! | BUDDY_ALLOCATOR | mm/buddy_allocator.rs | 4 | Mutex | Global |
//! | ALLOCATOR | mm/memory.rs | 4 | LockedHeap | Global |
//! | PROCESS_TABLE | kernel_core/process.rs | 5 | Array<Option<Arc<Mutex>>> | Global |
//! | VFS_ROOT | vfs/lib.rs | 6 | Arc<dyn Fs> | Global |
//! | ENDPOINT_REGISTRY | ipc/ipc.rs | 7 | Mutex<HashMap> | Global |
//! | VGA_BUFFER | drivers/vga_buffer.rs | 8 | Mutex | Global |
//! | SERIAL_PORT | drivers/serial.rs | 8 | Mutex | Global |
//! | AUDIT_RING | audit/lib.rs | 9 | Mutex | Global |
//! | RNG_STATE | security/rng.rs | 9 | Mutex | Global |
//!
//! # R69-5: COW_FAULT_LOCK and PT_LOCK Ordering
//!
//! **Critical Lock Ordering**: COW_FAULT_LOCK < PT_LOCK
//!
//! These two locks serialize page table operations during fork and COW fault handling:
//!
//! ```text
//! COW_FAULT_LOCK (fork.rs:412)
//!     └── PT_LOCK (page_table.rs:39, acquired via with_current_manager/with_pt_lock)
//! ```
//!
//! ## Call Paths Analysis
//!
//! 1. **handle_cow_page_fault()** (fork.rs:404-495):
//!    - Acquires COW_FAULT_LOCK first
//!    - Then calls with_current_manager() which acquires PT_LOCK
//!    - Order: COW_FAULT_LOCK → PT_LOCK ✓
//!
//! 2. **copy_page_table_cow()** (fork.rs:319-377):
//!    - Calls with_pt_lock() which acquires PT_LOCK only
//!    - Does NOT hold COW_FAULT_LOCK
//!    - Order: PT_LOCK only ✓
//!
//! ## Why This Ordering Matters
//!
//! - If any code path acquired PT_LOCK then COW_FAULT_LOCK, it would deadlock
//!   with handle_cow_page_fault() on SMP systems
//! - Current code is safe because:
//!   - fork() path uses PT_LOCK only (no nested COW fault possible during fork)
//!   - COW fault path always acquires COW_FAULT_LOCK first
//!
//! ## Safety Rules
//!
//! 1. **Never acquire COW_FAULT_LOCK while holding PT_LOCK**
//! 2. **Always acquire COW_FAULT_LOCK before PT_LOCK if both needed**
//! 3. **COW_FAULT_LOCK is only needed in handle_cow_page_fault()**
//!
//! # SMP Migration Notes
//!
//! When enabling SMP, the following changes are required:
//!
//! 1. **Scheduler locks** become per-CPU run queues
//!    - Each CPU has its own READY_QUEUE and CURRENT_PROCESS
//!    - Load balancing requires cross-CPU lock acquisition
//!
//! 2. **Memory allocator** needs lock-free or partitioned design
//!    - BUDDY_ALLOCATOR should use per-CPU free lists
//!    - Consider lock-free allocator for hot paths
//!
//! 3. **Process table** remains global but with RCU-like access
//!    - Read mostly, write rarely pattern
//!
//! 4. **IRQ-safe locks** use IRQ disable + spin
//!    - `spin::Mutex` is NOT IRQ-safe by default
//!    - Wrap with `interrupts::without_interrupts(|| ...)`
//!
//! # Deadlock Prevention Checklist
//!
//! - [ ] Never hold locks across blocking operations (sleep, wait)
//! - [ ] Always acquire locks in documented order
//! - [ ] Use try_lock() with fallback for out-of-order cases
//! - [ ] Per-CPU data doesn't need locks (single owner)
//! - [ ] Disable IRQs when holding scheduler locks
//! - [ ] Document any lock order exceptions with justification
//!
//! # Example: Safe Lock Acquisition
//!
//! ```rust,ignore
//! // CORRECT: Acquire in order (Level 3 before Level 5)
//! fn schedule_process(pid: ProcessId) {
//!     let queue = READY_QUEUE.lock();  // Level 3
//!     let proc = PROCESS_TABLE.get(pid).lock();  // Level 5
//!     // ... use both ...
//!     drop(proc);  // Release Level 5
//!     drop(queue); // Release Level 3
//! }
//!
//! // INCORRECT: Would cause deadlock in SMP
//! fn bad_pattern(pid: ProcessId) {
//!     let proc = PROCESS_TABLE.get(pid).lock();  // Level 5
//!     let queue = READY_QUEUE.lock();  // Level 3 - WRONG ORDER!
//! }
//! ```

#![allow(dead_code)]

#[cfg(all(debug_assertions, feature = "lockdep_graph"))]
extern crate alloc;

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use spin::Mutex as RawMutex;
use spin::MutexGuard as RawMutexGuard;

/// Lock level enumeration for documentation and debugging
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockLevel {
    /// Level 1: Interrupt control (highest priority)
    IrqControl = 1,
    /// Level 2: Per-CPU data structures
    PerCpu = 2,
    /// Level 3: Scheduler locks
    Scheduler = 3,
    /// Level 4: Memory management locks
    Memory = 4,
    /// Level 5: Process/thread locks
    Process = 5,
    /// Level 6: VFS locks
    Vfs = 6,
    /// Level 7: IPC locks
    Ipc = 7,
    /// Level 8: Device/driver locks
    Device = 8,
    /// Level 9: Audit/security locks (lowest priority)
    Audit = 9,
}

impl LockLevel {
    /// Check if acquiring `target` lock is valid when holding `current`
    pub fn can_acquire_from(current: LockLevel, target: LockLevel) -> bool {
        // Can only acquire lower-priority (higher number) locks
        target > current
    }

    /// Get the name of this lock level
    pub fn name(self) -> &'static str {
        match self {
            LockLevel::IrqControl => "IRQ_CONTROL",
            LockLevel::PerCpu => "PER_CPU",
            LockLevel::Scheduler => "SCHEDULER",
            LockLevel::Memory => "MEMORY",
            LockLevel::Process => "PROCESS",
            LockLevel::Vfs => "VFS",
            LockLevel::Ipc => "IPC",
            LockLevel::Device => "DEVICE",
            LockLevel::Audit => "AUDIT",
        }
    }
}

// ============================================================================
// E.4 Lockdep: Lock Class Key
// ============================================================================

/// Identifier for a lock class (per lock type/site).
///
/// Lock classes are identified by a static string (typically the lock name).
/// Using classes instead of individual instances keeps the dependency graph small
/// and matches the documented lock ordering levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockClassKey(pub &'static str);

impl LockClassKey {
    /// Create a new lock class key with the given name.
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Get the name of this lock class.
    pub const fn name(self) -> &'static str {
        self.0
    }
}

/// Maximum depth of nested locks tracked in debug builds.
///
/// This is a reasonable limit - if you're holding more than 32 locks
/// simultaneously, something is likely wrong with the design.
pub const MAX_LOCK_DEPTH: usize = 32;

// ============================================================================
// E.4 Lockdep: LockdepMutex Wrapper
// ============================================================================

/// Lockdep-aware mutex wrapper around `spin::Mutex`.
///
/// In debug builds, this wrapper tracks lock acquisitions and validates
/// that lock ordering rules are followed. In release builds, it compiles
/// down to a plain `spin::Mutex` with no overhead.
///
/// # Example
///
/// ```rust,ignore
/// use sched::lock_ordering::{LockdepMutex, LockClassKey, LockLevel};
///
/// static MY_LOCK: LockdepMutex<u32> = LockdepMutex::new(
///     0,
///     LockClassKey::new("MY_LOCK"),
///     LockLevel::Scheduler,
/// );
///
/// fn example() {
///     let guard = MY_LOCK.lock();
///     // Use guard...
/// }
/// ```
pub struct LockdepMutex<T> {
    class: LockClassKey,
    level: LockLevel,
    inner: RawMutex<T>,
}

impl<T> LockdepMutex<T> {
    /// Create a new lockdep-tracked mutex.
    ///
    /// # Arguments
    ///
    /// * `value` - Initial value to store in the mutex
    /// * `class` - Lock class key for this mutex
    /// * `level` - Lock ordering level
    pub const fn new(value: T, class: LockClassKey, level: LockLevel) -> Self {
        Self {
            class,
            level,
            inner: RawMutex::new(value),
        }
    }

    /// Acquire the lock, checking for ordering violations.
    ///
    /// In debug builds, this validates that acquiring this lock doesn't
    /// violate the lock ordering hierarchy. In release builds, this is
    /// equivalent to `spin::Mutex::lock()`.
    ///
    /// # R71-3 FIX: IRQ Safety
    ///
    /// In debug builds, the entire check-lock-record sequence is wrapped in
    /// `without_interrupts()` to prevent IRQ handlers from acquiring locks
    /// in the window between check and record, which could cause ordering
    /// violations to go undetected.
    #[inline]
    pub fn lock(&self) -> LockdepMutexGuard<'_, T> {
        #[cfg(debug_assertions)]
        let guard = x86_64::instructions::interrupts::without_interrupts(|| {
            lock_tracking::check_acquire(self.class, self.level);
            let g = self.inner.lock();
            lock_tracking::record_acquire(self.class, self.level);
            g
        });
        #[cfg(not(debug_assertions))]
        let guard = self.inner.lock();

        LockdepMutexGuard {
            lock: self,
            guard: ManuallyDrop::new(guard),
        }
    }

    /// Try to acquire the lock without blocking.
    ///
    /// Returns `None` if the lock is already held.
    ///
    /// Note: In debug builds, ordering validation happens BEFORE the lock
    /// attempt to avoid the case where we've already acquired the lock
    /// before detecting a violation.
    ///
    /// # R71-3 FIX: IRQ Safety
    ///
    /// Same IRQ protection as `lock()` to ensure consistent lockdep tracking.
    #[inline]
    pub fn try_lock(&self) -> Option<LockdepMutexGuard<'_, T>> {
        #[cfg(debug_assertions)]
        {
            x86_64::instructions::interrupts::without_interrupts(|| {
                lock_tracking::check_acquire(self.class, self.level);
                self.inner.try_lock().map(|guard| {
                    lock_tracking::record_acquire(self.class, self.level);
                    LockdepMutexGuard {
                        lock: self,
                        guard: ManuallyDrop::new(guard),
                    }
                })
            })
        }
        #[cfg(not(debug_assertions))]
        {
            self.inner.try_lock().map(|guard| {
                LockdepMutexGuard {
                    lock: self,
                    guard: ManuallyDrop::new(guard),
                }
            })
        }
    }

    /// Get a mutable reference to the underlying data.
    ///
    /// This requires exclusive access to the mutex, which is guaranteed
    /// by the `&mut self` reference.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Get the lock class key.
    #[inline]
    pub fn class(&self) -> LockClassKey {
        self.class
    }

    /// Get the lock level.
    #[inline]
    pub fn level(&self) -> LockLevel {
        self.level
    }
}

// Safety: LockdepMutex is Send+Sync if T is Send
unsafe impl<T: Send> Send for LockdepMutex<T> {}
unsafe impl<T: Send> Sync for LockdepMutex<T> {}

/// Guard returned by `LockdepMutex::lock()`.
///
/// When dropped, this guard releases the lock and updates the lockdep
/// tracking state. Uses `ManuallyDrop` to ensure proper ordering:
/// the lock is released first, then the tracking is updated.
pub struct LockdepMutexGuard<'a, T> {
    lock: &'a LockdepMutex<T>,
    guard: ManuallyDrop<RawMutexGuard<'a, T>>,
}

impl<'a, T> Drop for LockdepMutexGuard<'a, T> {
    fn drop(&mut self) {
        // Codex E.4 Fix: Release lock and update tracking with interrupts
        // disabled to prevent IRQ reentrancy from corrupting the lock stack.
        //
        // The correct order is:
        // 1. Disable interrupts
        // 2. Drop the underlying lock guard (releases the lock)
        // 3. Update the tracking stack
        // 4. Re-enable interrupts
        //
        // This ensures the tracking stack accurately reflects held locks
        // even if an IRQ fires during the drop sequence.
        #[cfg(debug_assertions)]
        {
            let class = self.lock.class;
            let level = self.lock.level;
            x86_64::instructions::interrupts::without_interrupts(|| {
                // Drop the underlying guard first (releases the lock)
                // Safety: We own the ManuallyDrop and will not use it again
                unsafe { ManuallyDrop::drop(&mut self.guard) };
                // Then update tracking
                lock_tracking::record_release(class, level);
            });
        }
        #[cfg(not(debug_assertions))]
        {
            // In release mode, just drop the guard normally
            // Safety: We own the ManuallyDrop and will not use it again
            unsafe { ManuallyDrop::drop(&mut self.guard) };
        }
    }
}

impl<'a, T> Deref for LockdepMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<'a, T> DerefMut for LockdepMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

// ============================================================================
// E.4 Lockdep: Per-CPU Lock Tracking (Debug Builds)
// ============================================================================

#[cfg(debug_assertions)]
pub mod lock_tracking {
    use super::{LockClassKey, LockLevel, MAX_LOCK_DEPTH};
    use core::cell::{Cell, UnsafeCell};
    use cpu_local::CpuLocal;

    /// Entry in the per-CPU lock stack.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LockEntry {
        class: LockClassKey,
        level: LockLevel,
    }

    /// Per-CPU stack of currently held locks.
    ///
    /// This tracks the order in which locks are acquired on each CPU,
    /// enabling detection of lock ordering violations.
    struct LockStack {
        depth: Cell<usize>,
        entries: UnsafeCell<[Option<LockEntry>; MAX_LOCK_DEPTH]>,
    }

    // Safety: LockStack is per-CPU, only accessed with interrupts disabled
    unsafe impl Send for LockStack {}
    unsafe impl Sync for LockStack {}

    impl LockStack {
        const fn new() -> Self {
            Self {
                depth: Cell::new(0),
                entries: UnsafeCell::new([None; MAX_LOCK_DEPTH]),
            }
        }

        /// Get the topmost lock entry on the stack.
        fn top(&self) -> Option<LockEntry> {
            let depth = self.depth.get();
            if depth == 0 {
                None
            } else {
                // Safety: depth > 0, so entries[depth-1] was written
                unsafe { (*self.entries.get())[depth - 1] }
            }
        }

        /// Validate that acquiring the given lock doesn't violate ordering.
        fn validate(&self, class: LockClassKey, level: LockLevel) {
            if let Some(top) = self.top() {
                // Allow re-acquiring the same lock class (recursive locks)
                if top.class == class {
                    return;
                }
                // Check ordering: can only acquire lower-priority (higher number) locks
                if !LockLevel::can_acquire_from(top.level, level) {
                    panic!(
                        "Lockdep: ordering violation - holding {} ({:?}), trying to acquire {} ({:?})",
                        top.class.name(),
                        top.level,
                        class.name(),
                        level
                    );
                }
            }
        }

        /// Push a lock entry onto the stack.
        fn push(&self, entry: LockEntry) {
            let depth = self.depth.get();
            if depth >= MAX_LOCK_DEPTH {
                panic!("Lockdep: exceeded max lock depth {}", MAX_LOCK_DEPTH);
            }
            // Safety: depth < MAX_LOCK_DEPTH, so entries[depth] is valid
            unsafe {
                (*self.entries.get())[depth] = Some(entry);
            }
            self.depth.set(depth + 1);
        }

        /// Pop a lock entry from the stack.
        ///
        /// Validates that the released lock matches what was expected (LIFO order).
        fn pop(&self, expected: LockEntry) {
            let depth = self.depth.get();
            if depth == 0 {
                panic!(
                    "Lockdep: release {} ({:?}) with empty stack",
                    expected.class.name(),
                    expected.level
                );
            }
            let idx = depth - 1;
            // Safety: depth > 0, so entries[idx] was written
            let found = unsafe { (*self.entries.get())[idx] };
            if found != Some(expected) {
                panic!(
                    "Lockdep: release order mismatch - expected {} ({:?}), found {:?}",
                    expected.class.name(),
                    expected.level,
                    found.map(|e| (e.class.name(), e.level))
                );
            }
            // Safety: idx is valid
            unsafe {
                (*self.entries.get())[idx] = None;
            }
            self.depth.set(idx);
        }

        /// Get current stack depth (for testing).
        #[allow(dead_code)]
        fn len(&self) -> usize {
            self.depth.get()
        }

        /// Iterate over held locks in acquisition order.
        ///
        /// This is used by the dependency graph feature to record edges
        /// from all currently held locks to a newly acquired lock.
        #[cfg(feature = "lockdep_graph")]
        fn for_each_held<F: FnMut(LockEntry)>(&self, mut f: F) {
            let depth = self.depth.get();
            if depth == 0 {
                return;
            }
            // Safety: entries below depth are initialized when depth is increased
            let entries = unsafe { &*self.entries.get() };
            for idx in 0..depth {
                if let Some(entry) = entries[idx] {
                    f(entry);
                }
            }
        }
    }

    /// Per-CPU lock stack for tracking held locks.
    static HELD: CpuLocal<LockStack> = CpuLocal::new(LockStack::new);

    // ========================================================================
    // R72: Optional Dependency Graph Tracking (debug builds + feature flag)
    // ========================================================================

    /// Lock dependency graph for cycle detection.
    ///
    /// This module implements directed graph tracking of lock acquisitions.
    /// An edge A → B means "lock A was held when lock B was acquired".
    /// If a cycle is detected (B already has a path to A), acquiring B while
    /// holding A would create a potential deadlock.
    #[cfg(feature = "lockdep_graph")]
    mod dep_graph {
        use super::{LockClassKey, LockEntry, LockStack};
        use alloc::collections::{BTreeMap, BTreeSet};
        use alloc::vec::Vec;
        use spin::{Mutex, MutexGuard, Once};

        /// The dependency graph storing edges between lock classes.
        struct DependencyGraph {
            /// Map from lock class to set of classes acquired while holding it
            edges: BTreeMap<LockClassKey, BTreeSet<LockClassKey>>,
        }

        impl DependencyGraph {
            fn new() -> Self {
                Self {
                    edges: BTreeMap::new(),
                }
            }

            /// Add a dependency edge: `from` was held when `to` was acquired.
            fn add_edge(&mut self, from: LockClassKey, to: LockClassKey) {
                self.edges.entry(from).or_default().insert(to);
            }

            /// Check if there's a path from `start` to `target` in the graph.
            ///
            /// Uses iterative DFS to avoid stack overflow on deep graphs.
            fn has_path(&self, start: LockClassKey, target: LockClassKey) -> bool {
                let mut stack = Vec::new();
                let mut visited = BTreeSet::new();
                stack.push(start);

                while let Some(node) = stack.pop() {
                    if !visited.insert(node) {
                        continue;
                    }

                    if node == target {
                        return true;
                    }

                    if let Some(children) = self.edges.get(&node) {
                        for &next in children {
                            if !visited.contains(&next) {
                                stack.push(next);
                            }
                        }
                    }
                }

                false
            }

            /// Check if adding edge `from` → `to` would create a cycle.
            ///
            /// A cycle would be created if `to` already has a path back to `from`.
            fn would_create_cycle(&self, from: LockClassKey, to: LockClassKey) -> bool {
                // If to → from already exists (directly or transitively), adding
                // from → to would create a cycle
                self.has_path(to, from)
            }
        }

        /// Global dependency graph protected by a spinlock.
        static GRAPH: Once<Mutex<DependencyGraph>> = Once::new();

        fn graph() -> MutexGuard<'static, DependencyGraph> {
            GRAPH.call_once(|| Mutex::new(DependencyGraph::new())).lock()
        }

        /// Validate that acquiring `new_class` won't create a cycle with held locks.
        ///
        /// For each currently held lock, check if adding the dependency edge
        /// held_lock → new_class would create a cycle in the dependency graph.
        pub(super) fn validate_edges(stack: &LockStack, new_class: LockClassKey) {
            let graph = graph();
            stack.for_each_held(|entry| {
                if entry.class == new_class {
                    return; // recursive lock of same class is allowed
                }

                if graph.would_create_cycle(entry.class, new_class) {
                    panic!(
                        "Lockdep: dependency cycle detected! \
                         Acquiring '{}' while holding '{}' would create a deadlock path",
                        new_class.name(),
                        entry.class.name()
                    );
                }
            });
        }

        /// Record dependency edges from all held locks to the newly acquired lock.
        ///
        /// This builds the dependency graph over time as locks are acquired.
        pub(super) fn record_edges(stack: &LockStack, new_class: LockClassKey) {
            let mut graph = graph();
            stack.for_each_held(|entry| {
                if entry.class != new_class {
                    graph.add_edge(entry.class, new_class);
                }
            });
        }
    }

    /// Check lock ordering before acquiring.
    ///
    /// Called before actually acquiring the lock to detect potential violations.
    ///
    /// # Safety
    ///
    /// Uses `without_interrupts` to prevent IRQ handlers from corrupting
    /// the per-CPU lock stack during validation.
    ///
    /// # R72: Dependency Graph Integration
    ///
    /// When the `lockdep_graph` feature is enabled, this also validates that
    /// acquiring this lock won't create a cycle in the dependency graph.
    #[inline]
    pub fn check_acquire(class: LockClassKey, level: LockLevel) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            HELD.with(|stack| {
                stack.validate(class, level);
                #[cfg(feature = "lockdep_graph")]
                dep_graph::validate_edges(stack, class);
            })
        });
    }

    /// Record that a lock was acquired.
    ///
    /// Called after successfully acquiring the lock.
    ///
    /// # Safety
    ///
    /// Uses `without_interrupts` to prevent IRQ handlers from corrupting
    /// the per-CPU lock stack during the push operation.
    ///
    /// # R72: Dependency Graph Integration
    ///
    /// When the `lockdep_graph` feature is enabled, this also records
    /// dependency edges from all currently held locks to the new lock.
    #[inline]
    pub fn record_acquire(class: LockClassKey, level: LockLevel) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            HELD.with(|stack| {
                #[cfg(feature = "lockdep_graph")]
                dep_graph::record_edges(stack, class);
                stack.push(LockEntry { class, level })
            })
        });
    }

    /// Record that a lock was released.
    ///
    /// Called when the lock guard is dropped.
    ///
    /// # Safety
    ///
    /// Uses `without_interrupts` to prevent IRQ handlers from corrupting
    /// the per-CPU lock stack during the pop operation.
    #[inline]
    pub fn record_release(class: LockClassKey, level: LockLevel) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            HELD.with(|stack| stack.pop(LockEntry { class, level }))
        });
    }

    /// Get the current lock stack depth (for testing/debugging).
    #[allow(dead_code)]
    pub fn current_depth() -> usize {
        x86_64::instructions::interrupts::without_interrupts(|| HELD.with(|stack| stack.len()))
    }
}

// ============================================================================
// E.4 Lockdep: No-op Implementation (Release Builds)
// ============================================================================

#[cfg(not(debug_assertions))]
pub mod lock_tracking {
    use super::{LockClassKey, LockLevel};

    #[inline(always)]
    pub fn check_acquire(_class: LockClassKey, _level: LockLevel) {}

    #[inline(always)]
    pub fn record_acquire(_class: LockClassKey, _level: LockLevel) {}

    #[inline(always)]
    pub fn record_release(_class: LockClassKey, _level: LockLevel) {}

    #[inline(always)]
    pub fn current_depth() -> usize {
        0
    }
}

// ============================================================================
// Convenience Macros
// ============================================================================

/// Macro to declare a lockdep-tracked static mutex.
///
/// # Example
///
/// ```rust,ignore
/// declare_lockdep_mutex!(MY_LOCK: u32 = 0, Scheduler);
/// ```
#[macro_export]
macro_rules! declare_lockdep_mutex {
    ($name:ident: $ty:ty = $init:expr, $level:ident) => {
        static $name: $crate::lock_ordering::LockdepMutex<$ty> =
            $crate::lock_ordering::LockdepMutex::new(
                $init,
                $crate::lock_ordering::LockClassKey::new(stringify!($name)),
                $crate::lock_ordering::LockLevel::$level,
            );
    };
}
