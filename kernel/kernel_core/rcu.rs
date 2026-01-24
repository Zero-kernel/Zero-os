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
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

/// R72: Batch of callbacks that all target the same epoch.
///
/// Batching callbacks by epoch reduces lock contention on the global
/// CALLBACKS queue, as we only need to match/remove entire batches
/// instead of scanning individual callbacks.
struct CallbackBatch {
    target_epoch: u64,
    callbacks: VecDeque<Callback>,
}

/// R72: Queue of deferred callbacks batched by target epoch.
///
/// Callbacks for the same epoch are grouped into a single batch.
/// This improves drain_callbacks() efficiency:
/// - Can pop entire batch at once instead of scanning
/// - Reduced lock hold time
/// - Better cache locality
static CALLBACKS: Mutex<VecDeque<CallbackBatch>> = Mutex::new(VecDeque::new());

/// Maximum number of callbacks to drain per `poll()` invocation.
///
/// This prevents a single callback batch from monopolizing the CPU.
const MAX_CALLBACKS_PER_POLL: usize = 16;

/// R72: One-time guard for timer registration.
///
/// Ensures the RCU timer callback is only registered once even if
/// init_rcu_timer() is called multiple times.
static RCU_TIMER_REGISTERED: AtomicBool = AtomicBool::new(false);

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
        // R71-2 FIX: Use Acquire to synchronize with SeqCst increment in synchronize_rcu().
        // This ensures we see the latest epoch value and don't store a stale epoch
        // that could cause synchronize_rcu() to block indefinitely.
        let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
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
        // R71-2 FIX: Use Acquire ordering to synchronize with SeqCst increment
        // in synchronize_rcu(). This prevents storing a stale epoch value that
        // could cause grace period detection to fail.
        let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
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
///
/// # R72-3 FIX: Memory Ordering
///
/// Uses `Ordering::Acquire` to synchronize with the `Ordering::SeqCst` increment
/// in `synchronize_rcu()`. This ensures we never store a stale epoch value that
/// would cause grace period detection to stall indefinitely. A CPU that stores
/// an old epoch and then halts (e.g., during shutdown) would otherwise block
/// all future grace periods since `all_cpus_quiescent()` would never see it
/// reach the target epoch.
#[inline]
pub unsafe fn rcu_quiescent_state_force() {
    // R72-3 FIX: Use Acquire ordering to pair with SeqCst increment in synchronize_rcu().
    // This prevents storing a stale epoch that would stall grace periods.
    let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
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
///
/// # R71-1 FIX: Grace Period Advancement
///
/// This function ensures callbacks make forward progress:
/// 1. If no grace period is in-flight, start one by advancing GLOBAL_EPOCH
/// 2. Target is always set to a valid epoch that will eventually complete
///
/// The `poll()` function in `try_advance_completed_epoch()` completes grace
/// periods when all CPUs have passed through quiescent states.
pub fn call_rcu<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    // R71-1 FIX: Ensure grace period advancement for callback progress.
    // Use a loop to handle concurrent callers correctly.
    //
    // The key insight: we want to ensure that the target epoch we assign
    // will eventually be completed. This means we must either:
    // - Piggyback on an existing in-flight grace period (current + 1), OR
    // - Start a new grace period by advancing GLOBAL_EPOCH
    //
    // We use CAS to avoid the race where multiple callers all try to start
    // grace periods and end up with targets beyond GLOBAL_EPOCH.
    let target = loop {
        let current = GLOBAL_EPOCH.load(Ordering::Acquire);
        let completed = COMPLETED_EPOCH.load(Ordering::Acquire);

        if completed >= current {
            // No grace period in-flight. Try to start one.
            // Use CAS to ensure only one caller advances the epoch.
            match GLOBAL_EPOCH.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::Acquire,
            ) {
                Ok(_) => break current + 1, // We started the GP, target it
                Err(_) => continue,         // Another caller beat us, retry
            }
        } else {
            // Grace period in-flight (current > completed).
            // Our callback will complete when this GP finishes.
            // Target = current (the in-flight GP), not current + 1.
            break current;
        }
    };

    // Wrap the FnOnce in a FnMut-compatible closure
    let mut opt = Some(f);
    let cb: Box<dyn FnMut() + Send> = Box::new(move || {
        if let Some(f) = opt.take() {
            f();
        }
    });

    // R72: Add callback to batched queue (grouped by target epoch)
    let mut batches = CALLBACKS.lock();

    // Check if the last batch has the same target epoch
    if let Some(back) = batches.back_mut() {
        if back.target_epoch == target {
            // Append to existing batch
            back.callbacks.push_back(Callback {
                target_epoch: target,
                func: cb,
            });
            return;
        }
    }

    // Create new batch for this epoch
    let mut batch = CallbackBatch {
        target_epoch: target,
        callbacks: VecDeque::new(),
    };
    batch.callbacks.push_back(Callback {
        target_epoch: target,
        func: cb,
    });
    batches.push_back(batch);
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
/// # R71-1 FIX (Part 2): Grace Period Completion
///
/// Before draining callbacks, this function checks if any pending grace
/// periods can be completed. If `GLOBAL_EPOCH > COMPLETED_EPOCH` and all
/// CPUs have passed through a quiescent state, we advance `COMPLETED_EPOCH`.
/// This ensures `call_rcu()` callbacks make forward progress even without
/// explicit `synchronize_rcu()` calls.
///
/// # Returns
///
/// The number of callbacks that were executed.
pub fn poll() -> usize {
    // R71-1 FIX (Part 2): Try to complete any pending grace periods.
    // This is the key addition that makes call_rcu() actually work without
    // synchronize_rcu() - we check if grace periods can complete on each poll.
    try_advance_completed_epoch();

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

/// R71-1 FIX (Part 2): Try to advance COMPLETED_EPOCH if grace period is done.
///
/// Checks if all CPUs have passed through a quiescent state for all pending
/// epochs up to GLOBAL_EPOCH. For each epoch where all CPUs are quiescent,
/// advances COMPLETED_EPOCH to that epoch.
///
/// This is a non-blocking check that makes `call_rcu()` work without requiring
/// explicit `synchronize_rcu()` calls.
fn try_advance_completed_epoch() {
    let global = GLOBAL_EPOCH.load(Ordering::Acquire);
    let mut completed = COMPLETED_EPOCH.load(Ordering::Acquire);

    // Try to advance COMPLETED_EPOCH toward GLOBAL_EPOCH
    while completed < global {
        let next = completed + 1;
        if all_cpus_quiescent(next) {
            // All CPUs have passed through quiescent state for this epoch.
            // Try to advance COMPLETED_EPOCH (CAS to handle concurrent advances).
            match COMPLETED_EPOCH.compare_exchange(
                completed,
                next,
                Ordering::SeqCst,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    completed = next;
                    // Continue to try advancing further epochs
                }
                Err(actual) => {
                    // Another thread advanced it, use their value
                    completed = actual;
                }
            }
        } else {
            // Not all CPUs quiescent yet, can't advance further
            break;
        }
    }
}

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
/// R72: Batched callback draining for improved efficiency.
///
/// Callbacks are now grouped by epoch. We pop entire batches (or partial
/// batches) to reduce lock contention and improve cache locality.
///
/// Returns the number of callbacks executed.
fn drain_callbacks(done_epoch: u64) -> usize {
    let mut count = 0;

    // Process batches up to MAX_CALLBACKS_PER_POLL total callbacks
    loop {
        if count >= MAX_CALLBACKS_PER_POLL {
            break;
        }

        // Pop the front batch if it's ready (target_epoch <= done_epoch)
        let mut batch = {
            let mut queue = CALLBACKS.lock();
            match queue.front() {
                Some(front) if front.target_epoch <= done_epoch => queue.pop_front(),
                _ => None,
            }
        };

        match batch.as_mut() {
            Some(b) => {
                // Process callbacks from this batch until we hit the limit
                while count < MAX_CALLBACKS_PER_POLL {
                    if let Some(mut cb) = b.callbacks.pop_front() {
                        // Run the callback outside the lock
                        (cb.func)();
                        count += 1;
                    } else {
                        break; // Batch exhausted
                    }
                }

                // If batch still has remaining callbacks, push it back to front
                // to maintain FIFO order across poll() calls
                if !b.callbacks.is_empty() {
                    let mut queue = CALLBACKS.lock();
                    // Re-add remaining batch at the front
                    if let Some(remaining) = batch.take() {
                        queue.push_front(remaining);
                    }
                }
            }
            None => break, // No more ready batches
        }
    }

    count
}

/// Get the number of pending callbacks (for debugging/monitoring).
///
/// R72: Updated to count callbacks across all batches.
pub fn pending_callbacks() -> usize {
    CALLBACKS
        .lock()
        .iter()
        .map(|batch| batch.callbacks.len())
        .sum()
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

// ============================================================================
// R72: Timer-Driven Grace Period Advancement
// ============================================================================

/// Initialize RCU timer integration.
///
/// Registers a timer callback to periodically advance grace periods on idle
/// CPUs. This ensures callbacks make forward progress even when no explicit
/// `synchronize_rcu()` calls are made.
///
/// # Safety
///
/// Safe to call multiple times; registration only happens once.
///
/// # Note
///
/// This is already integrated via scheduler_hook::on_scheduler_tick() which
/// calls rcu_quiescent_state(). This function provides an additional explicit
/// registration point if needed.
pub fn init_rcu_timer() {
    if RCU_TIMER_REGISTERED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        // The timer callback is already registered in scheduler_hook::on_scheduler_tick()
        // which calls rcu_quiescent_state(). No additional registration needed.
        // This function serves as an explicit initialization point if needed.
    }
}

/// R72: Timer-driven hook to keep grace periods moving.
///
/// Called from timer interrupt context to:
/// 1. Mark quiescent state (if not in RCU read section)
/// 2. Attempt to advance COMPLETED_EPOCH if all CPUs are quiescent
///
/// This ensures callbacks make forward progress even on idle CPUs that
/// aren't actively calling poll().
///
/// # Note
///
/// This is already called via scheduler_hook::on_scheduler_tick() which
/// invokes rcu_quiescent_state(). For additional timer-driven epoch
/// advancement, this function can be called from other timer contexts.
#[inline]
pub fn rcu_timer_tick() {
    // Mark quiescent state (if not in RCU read section)
    rcu_quiescent_state();

    // Try to advance COMPLETED_EPOCH toward GLOBAL_EPOCH
    // This allows callbacks to make progress without explicit poll() calls
    try_advance_completed_epoch();
}
