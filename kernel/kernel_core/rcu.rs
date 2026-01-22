//! Read-Copy-Update (RCU) Synchronization Primitive
//!
//! RCU provides a synchronization mechanism optimized for read-mostly data
//! structures. Readers can access shared data without taking any locks,
//! while writers defer destruction until all pre-existing readers are done.
//!
//! # Architecture
//!
//! This implementation uses:
//! - Global epoch counter for grace period tracking
//! - Per-CPU reader nesting counters
//! - Per-CPU quiescent state tracking via `rcu_epoch`
//!
//! # Grace Period Detection
//!
//! A grace period is a duration during which all CPUs have passed through
//! at least one quiescent state (a point where no RCU read-side critical
//! sections are active). When `synchronize_rcu()` returns, all pre-existing
//! readers have completed.
//!
//! # API
//!
//! ```rust,ignore
//! use kernel_core::rcu;
//!
//! // Read-side critical section
//! rcu::rcu_read_lock();
//! // Access RCU-protected data...
//! rcu::rcu_read_unlock();
//!
//! // Writer side
//! // Update RCU-protected pointer
//! // old_value = swap_pointer(...)
//! rcu::synchronize_rcu();  // Wait for all readers
//! // Safe to free old_value
//!
//! // Or use callback-based deferred free
//! rcu::call_rcu(|| drop(old_value));
//! ```
//!
//! # Integration Points
//!
//! - `rcu_quiescent_state()` is called from scheduler tick and context switch
//! - `poll()` drains callbacks in process context (syscall return path)

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use cpu_local::{current_cpu, num_online_cpus, CpuLocal, PER_CPU_DATA};
use spin::Mutex;

/// Global epoch counter (monotonically increasing).
///
/// Incremented by `synchronize_rcu()` to begin a new grace period.
/// Writers waiting for readers use this to track when it's safe to proceed.
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Highest grace period that has fully completed.
///
/// Updated only after all CPUs report quiescence so callbacks never run
/// ahead of an in-flight grace period. This prevents `poll()` from running
/// callbacks before `synchronize_rcu()` has verified all readers are done.
static COMPLETED_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Per-CPU reader nesting counter.
///
/// Non-zero means the CPU is in an RCU read-side critical section.
/// Nested calls are supported via reference counting.
static RCU_READERS: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));

/// Deferred callback entry with target epoch.
struct Callback {
    /// The grace period epoch after which this callback can run.
    target_epoch: u64,
    /// The callback function to invoke.
    func: Box<dyn FnMut() + Send>,
}

/// Queue of deferred callbacks waiting for their grace periods.
static CALLBACKS: Mutex<Vec<Callback>> = Mutex::new(Vec::new());

/// Maximum number of callbacks to drain per `poll()` invocation.
///
/// This prevents a single callback batch from monopolizing the CPU.
const MAX_CALLBACKS_PER_POLL: usize = 16;

// ============================================================================
// Read-Side API
// ============================================================================

/// Enter an RCU read-side critical section.
///
/// This must be paired with a call to `rcu_read_unlock()`. Nested calls
/// are allowed (reference counted).
///
/// # Performance
///
/// This is very cheap: just an atomic increment. No locks, no memory barriers
/// that would stall the pipeline.
///
/// # Note
///
/// Read-side critical sections should be short. Don't sleep, block, or
/// do anything that could cause a context switch while in an RCU read-side
/// critical section.
#[inline]
pub fn rcu_read_lock() {
    // Prevent preemption during the reader accounting.
    // This ensures the CPU that incremented the counter is the same one
    // that will decrement it.
    current_cpu().preempt_disable();
    RCU_READERS.with(|counter| {
        counter.fetch_add(1, Ordering::Acquire);
    });
}

/// Exit an RCU read-side critical section.
///
/// Must be called once for each call to `rcu_read_lock()`.
///
/// When the reader count drops to zero, this CPU's quiescent state is
/// updated to allow pending grace periods to complete.
#[inline]
pub fn rcu_read_unlock() {
    let remaining = RCU_READERS.with(|counter| {
        let old = counter.fetch_sub(1, Ordering::Release);
        if old == 0 {
            // Underflow - caller bug
            panic!("RCU: rcu_read_unlock called without matching rcu_read_lock");
        }
        old - 1
    });

    // If all readers on this CPU are done, mark quiescent state
    if remaining == 0 {
        let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
        current_cpu().rcu_epoch.store(epoch, Ordering::Release);
    }

    current_cpu().preempt_enable();
}

/// Check if the current CPU is in an RCU read-side critical section.
#[inline]
pub fn rcu_read_lock_held() -> bool {
    RCU_READERS.with(|counter| counter.load(Ordering::Relaxed) > 0)
}

// ============================================================================
// Quiescent State API
// ============================================================================

/// Mark that this CPU has passed through a quiescent state.
///
/// A quiescent state is a point where no RCU read-side critical sections
/// are active on this CPU. This should be called from:
/// - Scheduler tick (when not in an RCU read-side section)
/// - Context switch
/// - Idle loop
///
/// This function is cheap when already quiescent (just a store).
#[inline]
pub fn rcu_quiescent_state() {
    // Only update if not currently in a read-side critical section
    let readers = RCU_READERS.with(|counter| counter.load(Ordering::Relaxed));
    if readers == 0 {
        let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
        current_cpu().rcu_epoch.store(epoch, Ordering::Release);
    }
}

/// Force a quiescent state on this CPU.
///
/// This is used when we know we're not in an RCU read-side critical section
/// and want to expedite grace period completion. Unlike `rcu_quiescent_state()`,
/// this doesn't check the reader count - caller must ensure it's zero.
///
/// # Safety
///
/// Caller must ensure no RCU read-side critical section is active on this CPU.
#[inline]
pub unsafe fn rcu_quiescent_state_force() {
    let epoch = GLOBAL_EPOCH.load(Ordering::Relaxed);
    current_cpu().rcu_epoch.store(epoch, Ordering::Release);
}

// ============================================================================
// Writer-Side API
// ============================================================================

/// Wait until all pre-existing RCU readers have completed.
///
/// This function blocks (busy-waits) until a full grace period has elapsed.
/// After it returns, any reader that was in an RCU read-side critical section
/// when this function was called has now exited that section.
///
/// # Usage
///
/// Typically used after updating an RCU-protected pointer to wait before
/// freeing the old data:
///
/// ```rust,ignore
/// // Swap in the new data
/// let old = RCU_DATA.swap(new, Ordering::Release);
///
/// // Wait for all readers of old data to finish
/// synchronize_rcu();
///
/// // Now safe to free old data
/// drop(old);
/// ```
///
/// # Note
///
/// This function busy-waits and should not be called from interrupt context.
/// For non-blocking operation, use `call_rcu()` instead.
pub fn synchronize_rcu() {
    // Advance global epoch to start a new grace period
    let target = GLOBAL_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;

    // Mark our own CPU as quiescent (we're not in a read-side section here)
    rcu_quiescent_state();

    // Wait until all CPUs have passed through a quiescent state
    // at or after the target epoch
    while !all_cpus_quiescent(target) {
        core::hint::spin_loop();
    }

    // Publish completion BEFORE running callbacks so concurrent pollers
    // cannot race ahead and see callbacks as ready before grace period ends.
    COMPLETED_EPOCH.store(target, Ordering::Release);

    // Drain any callbacks that are now safe to run
    drain_callbacks(target);
}

/// Queue a callback to run after the next grace period.
///
/// The callback will be invoked in process context after all pre-existing
/// RCU readers have completed. This is the preferred way to defer freeing
/// RCU-protected data when you don't want to block.
///
/// # Example
///
/// ```rust,ignore
/// // Replace old data
/// let old = RCU_DATA.swap(new, Ordering::Release);
///
/// // Schedule deferred free (non-blocking)
/// call_rcu(move || drop(old));
/// ```
///
/// # Note
///
/// The callback runs in process context from `reschedule_if_needed()`.
/// It must not sleep or take locks that could cause deadlock.
pub fn call_rcu<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    // Callbacks need to wait for readers that existed at call time,
    // which means waiting for the NEXT epoch to complete.
    let target = GLOBAL_EPOCH.load(Ordering::Relaxed) + 1;

    // Wrap the FnOnce in a FnMut-compatible closure
    let mut opt = Some(f);
    let cb: Box<dyn FnMut() + Send> = Box::new(move || {
        if let Some(f) = opt.take() {
            f();
        }
    });

    CALLBACKS.lock().push(Callback {
        target_epoch: target,
        func: cb,
    });
}

/// Poll for and run any callbacks whose grace period has completed.
///
/// This should be called from process context (e.g., syscall return path)
/// to drain pending callbacks. It's non-blocking and runs at most
/// `MAX_CALLBACKS_PER_POLL` callbacks per invocation.
///
/// # Safety
///
/// Only drains callbacks whose target epoch is <= COMPLETED_EPOCH,
/// ensuring we never run callbacks before their grace period has
/// actually finished (which would cause use-after-free).
///
/// # Returns
///
/// The number of callbacks that were executed.
pub fn poll() -> usize {
    // Only drain callbacks whose grace period has actually finished.
    // Using COMPLETED_EPOCH (not GLOBAL_EPOCH) prevents racing ahead
    // of an in-progress synchronize_rcu().
    let completed_epoch = COMPLETED_EPOCH.load(Ordering::Acquire);
    drain_callbacks(completed_epoch)
}

/// Get the current global RCU epoch (for debugging).
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Relaxed)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if all CPUs have reached a quiescent state at or after the target epoch.
///
/// # Important
///
/// Only checks online CPUs (via `num_online_cpus()`), not all `max_cpus()` slots.
/// Uninitialized CPU slots have `rcu_epoch == 0` which would cause deadlock
/// if we waited for them. We must use `.max(1)` to handle the BSP-only case
/// before any APs have come online.
fn all_cpus_quiescent(target: u64) -> bool {
    // Only online CPUs can hold readers or update rcu_epoch.
    // Use .max(1) to ensure we check at least the BSP even if counter is 0.
    let num_cpus = num_online_cpus().max(1);

    for cpu_id in 0..num_cpus {
        // Check if this CPU has any active readers
        let readers = RCU_READERS
            .with_cpu(cpu_id, |counter| counter.load(Ordering::Acquire))
            .unwrap_or(0);

        if readers != 0 {
            // This CPU is in a read-side critical section
            return false;
        }

        // Check if this CPU's epoch has reached the target
        if let Some(per_cpu) = PER_CPU_DATA.get_cpu(cpu_id) {
            let cpu_epoch = per_cpu.rcu_epoch.load(Ordering::Acquire);
            if cpu_epoch < target {
                return false;
            }
        }
    }

    true
}

/// Drain callbacks whose grace period has completed.
///
/// Returns the number of callbacks executed.
fn drain_callbacks(done_epoch: u64) -> usize {
    let mut count = 0;

    // Take up to MAX_CALLBACKS_PER_POLL callbacks that are ready
    loop {
        if count >= MAX_CALLBACKS_PER_POLL {
            break;
        }

        // Find and remove one ready callback
        let callback = {
            let mut queue = CALLBACKS.lock();
            let mut found_idx = None;

            for (i, cb) in queue.iter().enumerate() {
                if cb.target_epoch <= done_epoch {
                    found_idx = Some(i);
                    break;
                }
            }

            found_idx.map(|i| queue.swap_remove(i))
        };

        match callback {
            Some(mut cb) => {
                // Run the callback outside the lock
                (cb.func)();
                count += 1;
            }
            None => break, // No more ready callbacks
        }
    }

    count
}

/// Get the number of pending callbacks (for debugging/monitoring).
pub fn pending_callbacks() -> usize {
    CALLBACKS.lock().len()
}

// ============================================================================
// RAII Guard for Read-Side Critical Sections
// ============================================================================

/// RAII guard for RCU read-side critical sections.
///
/// Automatically calls `rcu_read_unlock()` when dropped.
///
/// # Example
///
/// ```rust,ignore
/// fn read_data() -> Data {
///     let _guard = RcuReadGuard::new();
///     // Data is protected while guard is held
///     RCU_DATA.load(Ordering::Acquire).clone()
/// }
/// ```
pub struct RcuReadGuard(());

impl RcuReadGuard {
    /// Enter an RCU read-side critical section.
    #[inline]
    pub fn new() -> Self {
        rcu_read_lock();
        Self(())
    }
}

impl Default for RcuReadGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RcuReadGuard {
    #[inline]
    fn drop(&mut self) {
        rcu_read_unlock();
    }
}

// Safety: RcuReadGuard is !Send because dropping it on a different CPU than
// where it was created would corrupt the per-CPU reader count.
impl !Send for RcuReadGuard {}
