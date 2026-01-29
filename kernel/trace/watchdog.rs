//! Hung-Task Watchdog with Per-Task Heartbeats
//!
//! Monitors task activity and fires tracepoints when tasks become unresponsive.
//! Designed for detecting deadlocks, infinite loops, and stuck tasks.
//!
//! # Design
//!
//! - **Registration**: Tasks register a watchdog slot with a timeout. The slot
//!   stores the task ID, timeout, and last-seen timestamp.
//!
//! - **Heartbeats**: Tasks refresh their timestamp via [`heartbeat`] during
//!   context switches or periodic activity. This is a single atomic store.
//!
//! - **Polling**: The [`poll_watchdogs`] function is called from the timer tick
//!   handler. It iterates all active slots, checking if any have exceeded their
//!   timeout. Overdue tasks trigger the `watchdog.hung_task` tracepoint.
//!
//! # IRQ Safety
//!
//! - Registration/unregistration uses a mutex for slot allocation but is
//!   expected to be rare (task creation/exit).
//! - Heartbeats are lock-free (single atomic store).
//! - Polling is lock-free and safe from IRQ context.
//!
//! # One-Shot Firing
//!
//! To avoid flooding logs, each slot has a `tripped` flag that is set when the
//! task exceeds its timeout. The tracepoint only fires on the transition from
//! OK to overdue. When a heartbeat arrives after a trip, the `tripped` flag is
//! cleared and a recovery is counted.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::counters::{increment_counter, TraceCounter};
use crate::{ensure_metrics_read_allowed, TraceCategory, TraceError, TraceId, Tracepoint};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of watchdog slots.
///
/// Limits memory usage and ensures bounded polling time. Increase if more
/// concurrent monitored tasks are expected.
pub const MAX_WATCHDOG_SLOTS: usize = 512;

/// Minimum timeout in milliseconds to prevent misconfiguration.
const MIN_TIMEOUT_MS: u64 = 10;

// ============================================================================
// Built-in Tracepoint
// ============================================================================

/// Built-in tracepoint fired when a task exceeds its watchdog timeout.
///
/// Fields:
/// - `task_id`: Process/thread ID of the hung task
/// - `overdue_ms`: How long past the deadline (milliseconds)
/// - `timeout_ms`: Configured timeout
/// - `cpu`: CPU where the task was last seen
pub static TRACE_WATCHDOG_HANG: Tracepoint = Tracepoint::new(
    TraceId::new(0x1000),
    "watchdog.hung_task",
    TraceCategory::Watchdog,
    &["task_id", "overdue_ms", "timeout_ms", "cpu"],
);

// ============================================================================
// Types
// ============================================================================

/// Configuration for registering a watchdog slot.
#[derive(Clone, Copy, Debug)]
pub struct WatchdogConfig {
    /// Task identifier (typically PID or thread ID).
    pub task_id: u64,
    /// Timeout in milliseconds. If no heartbeat arrives within this window,
    /// the task is considered hung.
    pub timeout_ms: u64,
}

/// Opaque handle returned by [`register_watchdog`].
///
/// Used for [`heartbeat`] and [`unregister_watchdog`] calls. The generation
/// field detects stale handles after slot reuse.
#[derive(Clone, Copy, Debug)]
pub struct WatchdogHandle {
    /// Slot index in the watchdog table.
    pub slot: usize,
    /// Generation at registration time (for ABA detection, 64-bit R89-2).
    pub generation: u64,
}

/// Snapshot of a single watchdog slot for diagnostics.
#[derive(Clone, Copy, Debug)]
pub struct WatchdogEvent {
    /// Task identifier.
    pub task_id: u64,
    /// Last heartbeat timestamp (ms since boot).
    pub last_seen_ms: u64,
    /// Configured timeout in milliseconds.
    pub timeout_ms: u64,
    /// How long past deadline (0 if not overdue).
    pub overdue_ms: u64,
    /// CPU where the task was last seen.
    pub cpu: u32,
    /// Slot index.
    pub slot: usize,
    /// Whether currently tripped (waiting for heartbeat).
    pub tripped: bool,
}

/// Errors from watchdog operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// All watchdog slots are in use.
    TableFull,
    /// Timeout is below minimum allowed ([`MIN_TIMEOUT_MS`]).
    InvalidTimeout,
    /// Handle refers to a slot that has been reused or freed.
    StaleHandle,
}

// ============================================================================
// Watchdog Slot
// ============================================================================

/// Single watchdog slot storing task heartbeat state.
///
/// All fields are atomic to allow lock-free heartbeats and polling.
#[derive(Debug)]
struct WatchdogSlot {
    /// Task identifier (0 when inactive).
    task_id: AtomicU64,
    /// Timeout in milliseconds.
    timeout_ms: AtomicU64,
    /// Last heartbeat timestamp (ms since boot).
    last_seen_ms: AtomicU64,
    /// CPU where last heartbeat occurred.
    last_cpu: AtomicU32,
    /// Generation counter for ABA detection (64-bit to prevent wrap attacks).
    generation: AtomicU64,
    /// Whether slot is actively monitoring a task.
    active: AtomicBool,
    /// Whether task has exceeded timeout (one-shot trip).
    tripped: AtomicBool,
}

impl WatchdogSlot {
    /// Create an empty slot.
    const fn new() -> Self {
        Self {
            task_id: AtomicU64::new(0),
            timeout_ms: AtomicU64::new(0),
            last_seen_ms: AtomicU64::new(0),
            last_cpu: AtomicU32::new(0),
            generation: AtomicU64::new(0),
            active: AtomicBool::new(false),
            tripped: AtomicBool::new(false),
        }
    }

    /// Clear slot for reuse.
    /// R89-1 FIX: Clear data BEFORE marking inactive to prevent races.
    /// Caller must hold alloc_guard to serialize with registration.
    fn clear(&self) {
        // Clear data fields first (while slot is still considered "ours")
        self.task_id.store(0, Ordering::Relaxed);
        self.timeout_ms.store(0, Ordering::Relaxed);
        self.last_seen_ms.store(0, Ordering::Relaxed);
        self.last_cpu.store(0, Ordering::Relaxed);
        self.tripped.store(false, Ordering::Relaxed);
        // Mark inactive LAST to publish cleared state atomically
        self.active.store(false, Ordering::Release);
        // Note: generation is NOT cleared - it monotonically increases
    }
}

// Safety: WatchdogSlot only contains atomics
unsafe impl Send for WatchdogSlot {}
unsafe impl Sync for WatchdogSlot {}

// ============================================================================
// Watchdog State
// ============================================================================

/// Global watchdog state containing all slots and allocation metadata.
struct WatchdogState {
    /// Fixed-size slot array.
    slots: [WatchdogSlot; MAX_WATCHDOG_SLOTS],
    /// Mutex for slot allocation (registration/unregistration serialization).
    alloc_guard: Mutex<()>,
    /// Global generation counter for unique handle generation (64-bit, R89-2).
    next_generation: AtomicU64,
}

impl WatchdogState {
    /// Create initialized state.
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| WatchdogSlot::new()),
            alloc_guard: Mutex::new(()),
            next_generation: AtomicU64::new(1), // Start at 1 so 0 is never valid
        }
    }
}

// Lazy initialization of global state
static WATCHDOG_STATE: Once<WatchdogState> = Once::new();

/// Get or initialize global watchdog state.
fn state() -> &'static WatchdogState {
    WATCHDOG_STATE.call_once(WatchdogState::new)
}

// ============================================================================
// Public API
// ============================================================================

/// Register a watchdog heartbeat for a task.
///
/// Allocates a slot and initializes it with the provided configuration.
/// The returned handle must be used for [`heartbeat`] calls and must be
/// passed to [`unregister_watchdog`] when the task exits.
///
/// # Arguments
///
/// * `cfg` - Configuration including task ID and timeout
/// * `now_ms` - Current monotonic timestamp (ms since boot)
///
/// # Errors
///
/// - [`WatchdogError::InvalidTimeout`] if `timeout_ms < MIN_TIMEOUT_MS`
/// - [`WatchdogError::TableFull`] if all slots are in use
///
/// # Example
///
/// ```rust,ignore
/// let handle = register_watchdog(WatchdogConfig {
///     task_id: current_pid() as u64,
///     timeout_ms: 5000, // 5 second timeout
/// }, current_timestamp_ms())?;
/// ```
pub fn register_watchdog(
    cfg: WatchdogConfig,
    now_ms: u64,
) -> Result<WatchdogHandle, WatchdogError> {
    if cfg.timeout_ms < MIN_TIMEOUT_MS {
        return Err(WatchdogError::InvalidTimeout);
    }

    let st = state();
    let _guard = st.alloc_guard.lock();

    // Find first inactive slot
    for (idx, slot) in st.slots.iter().enumerate() {
        if !slot.active.load(Ordering::Acquire) {
            // R89-2 FIX: Allocate generation atomically, preventing wrap to zero
            let gen = st
                .next_generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |g| {
                    let next = g.wrapping_add(1);
                    // Skip zero on wrap to ensure 0 is never a valid generation
                    Some(if next == 0 { 1 } else { next })
                })
                .unwrap_or(1); // fetch_update only fails if closure returns None

            // Initialize slot atomically
            slot.task_id.store(cfg.task_id, Ordering::Relaxed);
            slot.timeout_ms.store(cfg.timeout_ms, Ordering::Relaxed);
            slot.last_seen_ms.store(now_ms, Ordering::Release);
            slot.last_cpu
                .store(cpu_local::current_cpu_id() as u32, Ordering::Relaxed);
            slot.generation.store(gen, Ordering::Release);
            slot.tripped.store(false, Ordering::Relaxed);

            // Publish slot as active (must be last)
            slot.active.store(true, Ordering::Release);

            return Ok(WatchdogHandle {
                slot: idx,
                generation: gen,
            });
        }
    }

    Err(WatchdogError::TableFull)
}

/// Unregister a watchdog heartbeat.
///
/// Frees the slot for reuse. Should be called when the monitored task exits.
///
/// # Arguments
///
/// * `handle` - Handle returned by [`register_watchdog`]
///
/// # Errors
///
/// Returns [`WatchdogError::StaleHandle`] if the handle is invalid (slot
/// reused or generation mismatch).
pub fn unregister_watchdog(handle: &WatchdogHandle) -> Result<(), WatchdogError> {
    let st = state();

    if handle.slot >= st.slots.len() {
        return Err(WatchdogError::StaleHandle);
    }

    // R89-1 FIX: Hold alloc_guard to serialize clear() with registration
    let _guard = st.alloc_guard.lock();

    let slot = &st.slots[handle.slot];

    // R89-1 FIX: Verify both generation AND active flag to detect ABA
    if slot.generation.load(Ordering::Acquire) != handle.generation
        || !slot.active.load(Ordering::Acquire)
    {
        return Err(WatchdogError::StaleHandle);
    }

    // Now safe to clear (we hold alloc_guard, serializing with registration)
    slot.clear();
    Ok(())
}

/// Refresh the heartbeat timestamp for a monitored task.
///
/// This is the hot-path operation, called on context switches or periodic
/// task activity. It's a single atomic store with no locks.
///
/// If the task was previously tripped (overdue), this clears the trip flag
/// and counts a recovery.
///
/// # Arguments
///
/// * `handle` - Handle returned by [`register_watchdog`]
/// * `now_ms` - Current monotonic timestamp (ms since boot)
///
/// # Errors
///
/// Returns [`WatchdogError::StaleHandle`] if the handle is invalid.
///
/// # Example
///
/// ```rust,ignore
/// // In context switch path:
/// if let Some(ref handle) = task.watchdog_handle {
///     let _ = heartbeat(handle, current_timestamp_ms());
/// }
/// ```
#[inline]
pub fn heartbeat(handle: &WatchdogHandle, now_ms: u64) -> Result<(), WatchdogError> {
    let st = state();

    if handle.slot >= st.slots.len() {
        return Err(WatchdogError::StaleHandle);
    }

    let slot = &st.slots[handle.slot];

    // Verify slot is still valid for this handle
    if slot.generation.load(Ordering::Acquire) != handle.generation
        || !slot.active.load(Ordering::Acquire)
    {
        return Err(WatchdogError::StaleHandle);
    }

    // Clear trip flag if set (task recovered)
    let was_tripped = slot.tripped.swap(false, Ordering::AcqRel);
    if was_tripped {
        increment_counter(TraceCounter::WatchdogRecoveries, 1);
    }

    // Update timestamp and CPU
    slot.last_seen_ms.store(now_ms, Ordering::Release);
    slot.last_cpu
        .store(cpu_local::current_cpu_id() as u32, Ordering::Relaxed);

    Ok(())
}

/// Poll all active watchdogs and fire tracepoints for overdue tasks.
///
/// This function should be called periodically from the timer tick handler.
/// It iterates all active slots and checks if any have exceeded their timeout.
/// Overdue tasks trigger the `watchdog.hung_task` tracepoint.
///
/// # Arguments
///
/// * `now_ms` - Current monotonic timestamp (ms since boot)
///
/// # Returns
///
/// Number of newly tripped watchdogs (excluding already-tripped ones).
///
/// # IRQ Safety
///
/// This function is lock-free and safe to call from IRQ context.
///
/// # Example
///
/// ```rust,ignore
/// // In timer interrupt handler:
/// trace::poll_watchdogs(kernel_core::time::current_timestamp_ms());
/// ```
#[inline]
pub fn poll_watchdogs(now_ms: u64) -> usize {
    let st = state();
    let mut tripped_count = 0;

    for slot in st.slots.iter() {
        // Skip inactive slots (lock-free check)
        if !slot.active.load(Ordering::Acquire) {
            continue;
        }

        let last = slot.last_seen_ms.load(Ordering::Acquire);
        let timeout = slot.timeout_ms.load(Ordering::Relaxed);

        // Skip slots with zero timeout (defensive)
        if timeout == 0 {
            continue;
        }

        let overdue = now_ms.saturating_sub(last);

        if overdue >= timeout {
            // Check if already tripped (one-shot firing)
            if slot.tripped.swap(true, Ordering::AcqRel) {
                // Already tripped, skip to avoid log flooding
                continue;
            }

            tripped_count += 1;
            increment_counter(TraceCounter::WatchdogTrips, 1);

            // Fire the hung_task tracepoint
            let _ = TRACE_WATCHDOG_HANG.emit(
                now_ms,
                &[
                    slot.task_id.load(Ordering::Relaxed),
                    overdue,
                    timeout,
                    slot.last_cpu.load(Ordering::Relaxed) as u64,
                ],
            );
        }
    }

    tripped_count
}

/// Take a guarded snapshot of all active watchdog slots.
///
/// This function is guarded by the read guard installed via
/// [`install_read_guard`](crate::install_read_guard).
///
/// # Arguments
///
/// * `now_ms` - Current timestamp for calculating overdue_ms
///
/// # Returns
///
/// Vector of [`WatchdogEvent`] for all active slots.
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
pub fn snapshot_watchdogs(now_ms: u64) -> Result<Vec<WatchdogEvent>, TraceError> {
    ensure_metrics_read_allowed()?;

    let st = state();
    let mut out = Vec::new();

    for (slot_id, slot) in st.slots.iter().enumerate() {
        if !slot.active.load(Ordering::Acquire) {
            continue;
        }

        let last = slot.last_seen_ms.load(Ordering::Acquire);
        let timeout = slot.timeout_ms.load(Ordering::Relaxed);
        let task_id = slot.task_id.load(Ordering::Relaxed);
        let cpu = slot.last_cpu.load(Ordering::Relaxed);
        let tripped = slot.tripped.load(Ordering::Relaxed);

        let overdue = if now_ms > last {
            let diff = now_ms - last;
            if diff >= timeout {
                diff
            } else {
                0
            }
        } else {
            0
        };

        out.push(WatchdogEvent {
            task_id,
            last_seen_ms: last,
            timeout_ms: timeout,
            overdue_ms: overdue,
            cpu,
            slot: slot_id,
            tripped,
        });
    }

    Ok(out)
}

/// Get the number of currently active watchdog slots.
///
/// This is a quick check that doesn't require the read guard.
pub fn active_count() -> usize {
    let st = state();
    st.slots
        .iter()
        .filter(|s| s.active.load(Ordering::Relaxed))
        .count()
}
