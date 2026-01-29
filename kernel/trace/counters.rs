//! Per-CPU Kernel Counters
//!
//! Provides low-overhead atomic counters for kernel hot paths. Counters are
//! maintained per-CPU to avoid cache line contention on multi-core systems.
//!
//! # Design
//!
//! - **Lock-free increments**: Each CPU has its own counter array accessed via
//!   `CpuLocal`. Increments are single atomic fetch-add operations with
//!   `Relaxed` ordering (no inter-CPU synchronization needed for incrementing).
//!
//! - **Aggregated snapshots**: The [`snapshot_counters`] function iterates all
//!   CPU slots and sums the values. This is slower but provides a consistent
//!   global view. Snapshots are guarded by the read guard from the parent module.
//!
//! # IRQ Safety
//!
//! All operations are safe to call from IRQ context. The per-CPU design means
//! there's no lock contention with other CPUs, and atomics don't require
//! disabling interrupts.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use cpu_local::CpuLocal;

use crate::{ensure_metrics_read_allowed, TraceError};

// ============================================================================
// Constants
// ============================================================================

/// Number of defined trace counters. Matches [`TraceCounter`] variants.
pub const TRACE_COUNTER_COUNT: usize = 14;

// ============================================================================
// Counter Enumeration
// ============================================================================

/// Predefined kernel counters for hot paths.
///
/// Each counter is tracked per-CPU and aggregated on demand via
/// [`snapshot_counters`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceCounter {
    /// Total system call entries.
    SyscallEntry = 0,
    /// System calls denied by seccomp/LSM.
    SyscallDenied = 1,
    /// Page fault exceptions handled.
    PageFaults = 2,
    /// IPC messages sent/received.
    IpcMessages = 3,
    /// Context switches performed.
    ContextSwitches = 4,
    /// Timer ticks processed by scheduler.
    SchedulerTicks = 5,
    /// Total hardware interrupts handled.
    Interrupts = 6,
    /// Tracepoints successfully emitted.
    TracepointsEmitted = 7,
    /// Tracepoints dropped (too many args, etc.).
    TracepointsDropped = 8,
    /// Watchdog timeout trips detected.
    WatchdogTrips = 9,
    /// Watchdog recoveries (heartbeat after trip).
    WatchdogRecoveries = 10,
    /// Copy-on-write page faults.
    CowFaults = 11,
    /// Memory allocation failures.
    AllocFailures = 12,
    /// Custom counter for module use.
    Custom0 = 13,
}

/// Human-readable counter names for diagnostics/procfs export.
const COUNTER_NAMES: [&str; TRACE_COUNTER_COUNT] = [
    "syscall.entry",
    "syscall.denied",
    "mm.page_faults",
    "ipc.messages",
    "sched.context_switches",
    "sched.ticks",
    "interrupts",
    "tracepoints.emitted",
    "tracepoints.dropped",
    "watchdog.trips",
    "watchdog.recoveries",
    "mm.cow_faults",
    "mm.alloc_failures",
    "custom0",
];

/// Get the human-readable name for a counter.
#[inline]
pub fn counter_name(counter: TraceCounter) -> &'static str {
    COUNTER_NAMES[counter as usize]
}

// ============================================================================
// Per-CPU Counter Storage
// ============================================================================

/// Per-CPU counter array. Each CPU has its own instance.
struct PerCpuCounters {
    counts: [AtomicU64; TRACE_COUNTER_COUNT],
}

impl PerCpuCounters {
    /// Create a zeroed counter array.
    fn new() -> Self {
        Self {
            counts: core::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Increment a counter by delta (lock-free, IRQ-safe).
    ///
    /// R89-4 NOTE: Uses wrapping add for performance. 64-bit counters would
    /// require 2^64 increments to wrap (~18 quintillion events), which is
    /// impractical at any realistic event rate. If saturating semantics
    /// are ever needed, use fetch_update with saturating_add at cost of CAS loop.
    #[inline]
    fn add(&self, counter: TraceCounter, delta: u64) {
        self.counts[counter as usize].fetch_add(delta, Ordering::Relaxed);
    }

    /// Reset a single counter to zero.
    fn reset_single(&self, counter: TraceCounter) {
        self.counts[counter as usize].store(0, Ordering::Relaxed);
    }

    /// Reset all counters to zero.
    fn reset_all(&self) {
        for c in &self.counts {
            c.store(0, Ordering::Relaxed);
        }
    }

    /// Snapshot all counters with Acquire ordering for cross-CPU visibility.
    fn snapshot(&self) -> [u64; TRACE_COUNTER_COUNT] {
        let mut out = [0u64; TRACE_COUNTER_COUNT];
        for (idx, c) in self.counts.iter().enumerate() {
            out[idx] = c.load(Ordering::Acquire);
        }
        out
    }
}

// Safety: PerCpuCounters only contains atomics, which are Send+Sync
unsafe impl Send for PerCpuCounters {}
unsafe impl Sync for PerCpuCounters {}

/// Global per-CPU counter storage.
static PER_CPU_COUNTERS: CpuLocal<PerCpuCounters> = CpuLocal::new(PerCpuCounters::new);

// ============================================================================
// Public API
// ============================================================================

/// Increment a kernel counter on the current CPU.
///
/// This is the hot-path entry point. It's a single atomic fetch-add with
/// no lock contention, safe to call from any context including IRQ handlers.
///
/// # Arguments
///
/// * `counter` - Which counter to increment
/// * `delta` - Amount to add (typically 1)
///
/// # Example
///
/// ```rust,ignore
/// // In syscall entry handler:
/// increment_counter(TraceCounter::SyscallEntry, 1);
/// ```
#[inline]
pub fn increment_counter(counter: TraceCounter, delta: u64) {
    PER_CPU_COUNTERS.with(|slot| slot.add(counter, delta));
}

/// Reset a specific counter across all CPUs, or reset all counters.
///
/// This is NOT lock-free (iterates CPUs) and should only be used for
/// administrative purposes, not in hot paths.
///
/// # Arguments
///
/// * `counter` - Specific counter to reset, or `None` to reset all
pub fn reset_counter(counter: Option<TraceCounter>) {
    let max = cpu_local::max_cpus();
    match counter {
        Some(c) => {
            for cpu in 0..max {
                let _ = PER_CPU_COUNTERS.with_cpu(cpu, |slot| slot.reset_single(c));
            }
        }
        None => {
            for cpu in 0..max {
                let _ = PER_CPU_COUNTERS.with_cpu(cpu, |slot| slot.reset_all());
            }
        }
    }
}

// ============================================================================
// Snapshot Types
// ============================================================================

/// Counter values for a single CPU.
#[derive(Clone, Debug)]
pub struct CpuCounterSnapshot {
    /// CPU index (0-based).
    pub cpu: usize,
    /// Counter values indexed by [`TraceCounter`].
    pub counts: [u64; TRACE_COUNTER_COUNT],
}

/// Aggregated counter snapshot across all CPUs.
#[derive(Clone, Debug)]
pub struct TraceCounterSnapshot {
    /// Sum of each counter across all CPUs.
    pub total: [u64; TRACE_COUNTER_COUNT],
    /// Per-CPU breakdown for debugging/monitoring.
    pub per_cpu: Vec<CpuCounterSnapshot>,
}

impl TraceCounterSnapshot {
    /// Get total count for a specific counter.
    #[inline]
    pub fn get(&self, counter: TraceCounter) -> u64 {
        self.total[counter as usize]
    }

    /// Iterate over all counters with names.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        COUNTER_NAMES
            .iter()
            .copied()
            .zip(self.total.iter().copied())
    }
}

/// Aggregate counters across all CPUs.
///
/// This function is guarded by the read guard installed via
/// [`install_read_guard`](crate::install_read_guard).
///
/// # Returns
///
/// A snapshot containing both the aggregate totals and per-CPU breakdown.
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
///
/// # Example
///
/// ```rust,ignore
/// if let Ok(snapshot) = trace::snapshot_counters() {
///     println!("Total syscalls: {}", snapshot.get(TraceCounter::SyscallEntry));
///     for (name, value) in snapshot.iter() {
///         println!("  {}: {}", name, value);
///     }
/// }
/// ```
pub fn snapshot_counters() -> Result<TraceCounterSnapshot, TraceError> {
    ensure_metrics_read_allowed()?;

    let mut total = [0u64; TRACE_COUNTER_COUNT];
    let mut per_cpu = Vec::new();

    let max = cpu_local::max_cpus();
    for cpu in 0..max {
        if let Some(counts) = PER_CPU_COUNTERS.with_cpu(cpu, |slot| slot.snapshot()) {
            for (idx, val) in counts.iter().enumerate() {
                total[idx] = total[idx].saturating_add(*val);
            }
            per_cpu.push(CpuCounterSnapshot { cpu, counts });
        }
    }

    Ok(TraceCounterSnapshot { total, per_cpu })
}
