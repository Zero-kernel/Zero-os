//! Lock Ordering and Synchronization Documentation
//!
//! This module documents the global lock ordering for Zero-OS to prevent deadlocks
//! in SMP environments. All locks must be acquired in the order specified below.
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

/// Lock ordering verification helper (debug builds only)
///
/// In debug builds, this can be used to track lock acquisition order
/// and panic on violations. In release builds, this is a no-op.
#[cfg(debug_assertions)]
pub mod lock_tracking {
    use super::LockLevel;
    use core::cell::Cell;

    /// Thread-local tracking of current lock level
    /// Note: This needs to be per-CPU in SMP mode
    #[thread_local]
    static CURRENT_LEVEL: Cell<Option<LockLevel>> = Cell::new(None);

    /// Check lock ordering before acquiring
    pub fn check_acquire(target: LockLevel) {
        if let Some(current) = CURRENT_LEVEL.get() {
            if !LockLevel::can_acquire_from(current, target) {
                panic!(
                    "Lock ordering violation: holding {} (level {}), trying to acquire {} (level {})",
                    current.name(),
                    current as u8,
                    target.name(),
                    target as u8
                );
            }
        }
        CURRENT_LEVEL.set(Some(target));
    }

    /// Record lock release
    pub fn record_release(_level: LockLevel) {
        CURRENT_LEVEL.set(None);
    }
}

#[cfg(not(debug_assertions))]
pub mod lock_tracking {
    use super::LockLevel;

    #[inline(always)]
    pub fn check_acquire(_target: LockLevel) {}

    #[inline(always)]
    pub fn record_release(_level: LockLevel) {}
}
