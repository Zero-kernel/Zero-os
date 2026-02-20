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
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
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
        /// IO controller: bandwidth and IOPS limits.
        const IO     = 0x08;
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

    /// Aggregate I/O bandwidth limit in bytes per second (read + write).
    ///
    /// When exceeded, I/O operations are throttled until tokens refill.
    /// Uses token bucket algorithm with 4-second burst window.
    /// Maps to `io.max` (bps) in cgroup v2.
    pub io_max_bytes_per_sec: Option<u64>,

    /// Aggregate I/O operations per second limit (read + write).
    ///
    /// When exceeded, I/O operations are throttled until tokens refill.
    /// Uses token bucket algorithm with 4-second burst window.
    /// Maps to `io.max` (iops) in cgroup v2.
    pub io_max_iops_per_sec: Option<u64>,
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

    // IO controller statistics
    /// Total bytes read via block I/O.
    pub io_read_bytes: AtomicU64,
    /// Total bytes written via block I/O.
    pub io_write_bytes: AtomicU64,
    /// Total read I/O operations completed.
    pub io_read_ios: AtomicU64,
    /// Total write I/O operations completed.
    pub io_write_ios: AtomicU64,
    /// Number of times I/O was throttled due to io.max limit.
    pub io_throttle_events: AtomicU64,
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
            io_read_bytes: AtomicU64::new(0),
            io_write_bytes: AtomicU64::new(0),
            io_read_ios: AtomicU64::new(0),
            io_write_ios: AtomicU64::new(0),
            io_throttle_events: AtomicU64::new(0),
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
            io_read_bytes: self.io_read_bytes.load(Ordering::Relaxed),
            io_write_bytes: self.io_write_bytes.load(Ordering::Relaxed),
            io_read_ios: self.io_read_ios.load(Ordering::Relaxed),
            io_write_ios: self.io_write_ios.load(Ordering::Relaxed),
            io_throttle_events: self.io_throttle_events.load(Ordering::Relaxed),
        }
    }

    /// Records additional CPU time consumed by this cgroup.
    #[inline]
    pub fn add_cpu_time(&self, delta_ns: u64) {
        self.cpu_time_ns.fetch_add(delta_ns, Ordering::Relaxed);
    }

    // R77-2 FIX: Removed set_memory_current() which used bare store().
    // Memory accounting is now exclusively through try_charge_memory()/uncharge_memory()
    // to prevent CAS overwrites. Use get_memory_current() for read-only access.

    /// Returns current memory usage (read-only snapshot).
    ///
    /// # R77-2 FIX
    ///
    /// This replaces the old `set_memory_current()` which used bare `store()`
    /// and could overwrite in-flight CAS updates from `try_charge_memory()`.
    /// Memory accounting should only be modified through:
    /// - `try_charge_memory()` for allocations (atomic CAS)
    /// - `uncharge_memory()` for deallocations (atomic fetch_update)
    #[inline]
    pub fn get_memory_current(&self) -> u64 {
        self.memory_current.load(Ordering::Relaxed)
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

    /// Decrements the attached task count (saturating at zero).
    ///
    /// # R110-1 FIX: Saturating decrement via `fetch_update`
    ///
    /// Bare `fetch_sub(1)` could wrap `pids_current` to `u64::MAX` if called
    /// when the counter is already 0 (double-exit race, cgroup migration during
    /// exit).  This matches the `uncharge_memory` pattern used elsewhere.
    #[inline]
    fn decrement_pids(&self) {
        let _ = self.pids_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
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
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub io_read_ios: u64,
    pub io_write_ios: u64,
    pub io_throttle_events: u64,
}

// ============================================================================
// F.2: CPU Quota Tracking (cpu.max enforcement)
// ============================================================================

/// Per-cgroup CPU quota state for cpu.max enforcement.
///
/// Tracks per-period CPU usage and throttle state using lock-free atomics.
/// The quota is enforced by the scheduler: when usage exceeds max within a
/// period, the cgroup is throttled until the next period.
///
/// # Fields
///
/// * `period_start_ns` - Start time of the current accounting period
/// * `period_usage_ns` - Accumulated CPU time used in the current period
/// * `throttled_until_ns` - End of throttle window (0 = not throttled)
/// * `throttle_events` - Counter of throttle events for statistics
/// * `refreshing` - R110-2 FIX: Lock that serializes window refresh with charging
#[derive(Debug)]
struct CpuQuotaState {
    /// Start of the current quota period in nanoseconds since boot
    period_start_ns: AtomicU64,
    /// CPU time consumed in the current period
    period_usage_ns: AtomicU64,
    /// If non-zero, the cgroup is throttled until this time
    throttled_until_ns: AtomicU64,
    /// Number of times this cgroup has been throttled
    throttle_events: AtomicU64,
    /// R110-2 FIX: True while the CAS winner is resetting per-period counters.
    /// Chargers that observe `refreshing == true` skip charging for this tick
    /// (fail-closed: the tick is lost, which is the same behavior as lock
    /// contention on the limits mutex — documented as safe in charge_cpu_quota).
    refreshing: AtomicBool,
}

impl CpuQuotaState {
    /// Creates a new quota state with all fields zeroed.
    const fn new() -> Self {
        Self {
            period_start_ns: AtomicU64::new(0),
            period_usage_ns: AtomicU64::new(0),
            throttled_until_ns: AtomicU64::new(0),
            throttle_events: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Refresh the quota window if the period has elapsed.
    ///
    /// Called before charging or checking throttle state to ensure
    /// we're accounting against the correct period.
    ///
    /// # R110-2 FIX: SMP-safe window refresh via refresh lock + CAS
    ///
    /// The refresh lock (`refreshing: AtomicBool`) is acquired **before** the
    /// CAS on `period_start_ns`.  This ensures that:
    ///
    /// 1. Only one CPU can enter the refresh critical section at a time.
    /// 2. `period_start_ns` is only updated **after** `period_usage_ns` and
    ///    `throttled_until_ns` have been reset to 0.
    /// 3. Concurrent chargers that observe `refreshing == true` skip the tick
    ///    (fail-closed, same as limits-lock contention — documented as safe).
    ///
    /// The new period start is published last, so any CPU that observes the
    /// fresh `period_start_ns` is guaranteed to see zeroed usage counters.
    #[inline]
    fn refresh_window(&self, now_ns: u64, period_ns: u64) {
        let start = self.period_start_ns.load(Ordering::Acquire);

        // Fast-path: still within the current accounting window.
        if start != 0 && now_ns.saturating_sub(start) < period_ns {
            return;
        }

        // Try to acquire the refresh lock (non-blocking, single-winner).
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            // Another CPU is already refreshing — this tick is skipped
            // (fail-closed: chargers also check `is_refreshing()`).
            return;
        }

        // We hold the refresh lock.  Re-check the window under the lock
        // (another CPU may have completed a refresh between our initial
        // check and the lock acquisition).
        let start = self.period_start_ns.load(Ordering::Acquire);
        if start != 0 && now_ns.saturating_sub(start) < period_ns {
            self.refreshing.store(false, Ordering::Release);
            return;
        }

        // Reset per-period counters BEFORE publishing the new start time.
        // Any concurrent charger will see `refreshing == true` and skip.
        self.period_usage_ns.store(0, Ordering::Release);
        self.throttled_until_ns.store(0, Ordering::Release);

        // Publish the new window start — chargers that observe this value
        // are guaranteed to see zeroed usage/throttle counters above.
        self.period_start_ns.store(now_ns, Ordering::Release);

        // Release the refresh lock — chargers may resume.
        self.refreshing.store(false, Ordering::Release);
    }

    /// Returns true if a window refresh is currently in progress.
    ///
    /// Callers (charge_cpu_quota) should skip charging when this is true
    /// to avoid racing with the usage counter reset.
    #[inline]
    fn is_refreshing(&self) -> bool {
        self.refreshing.load(Ordering::Acquire)
    }

    /// Returns the number of throttle events.
    #[inline]
    fn throttle_count(&self) -> u64 {
        self.throttle_events.load(Ordering::Relaxed)
    }
}

/// Result of charging CPU quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaStatus {
    /// No CPU controller or cpu.max is unlimited.
    Unlimited,
    /// Quota available, time has been charged.
    Allowed,
    /// Quota exceeded; cgroup is throttled until the specified time (ns).
    Throttled(u64),
}

// ============================================================================
// F.2: IO Throttling (io.max enforcement)
// ============================================================================

/// I/O direction for bandwidth and IOPS accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// Block read operation.
    Read,
    /// Block write operation.
    Write,
}

/// Result of charging I/O bandwidth tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoThrottleStatus {
    /// No IO controller or limits configured.
    Unlimited,
    /// Tokens available, I/O request permitted.
    Allowed,
    /// Tokens exhausted; caller should wait until `until_ns` before retrying.
    Throttled(u64),
}

/// Maximum burst window for IO token bucket (seconds).
///
/// Allows short bursts of up to 4 seconds worth of tokens, smoothing
/// out bursty workloads while still enforcing long-term average limits.
const IO_BURST_SECS: u64 = 4;

/// Nanoseconds per second constant.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Internal token bucket state for IO bandwidth and IOPS throttling.
///
/// Each cgroup has one of these, tracking both bytes/sec and IOPS tokens.
/// Protected by a mutex in `IoThrottleState`.
#[derive(Debug)]
struct IoBucketState {
    /// Last time tokens were refilled (nanoseconds since boot).
    last_refill_ns: u64,
    /// Current available byte tokens (decremented on IO, refilled over time).
    byte_tokens: u64,
    /// Current available IOPS tokens (decremented on IO, refilled over time).
    iops_tokens: u64,
    /// If non-zero, throttled until this time (nanoseconds since boot).
    throttle_until_ns: u64,
}

impl IoBucketState {
    /// Refill tokens based on elapsed time since last refill.
    ///
    /// Token bucket algorithm: tokens accumulate at the configured rate,
    /// normally capped at `rate * IO_BURST_SECS` to allow bounded bursts.
    ///
    /// # CODEX FIX: Stale Token Clamping
    ///
    /// When limits change from unlimited to limited, tokens may be at u64::MAX.
    /// This function now clamps tokens to the cap to prevent limit bypass.
    ///
    /// # CODEX FIX: Oversized I/O Support
    ///
    /// A single I/O larger than the burst capacity would deadlock because refill
    /// caps at `rate * burst`. To prevent this, `requested_bytes` extends the
    /// effective cap so large I/Os can eventually accumulate enough tokens.
    fn refill(&mut self, limits: &CgroupLimits, now_ns: u64, requested_bytes: u64) {
        let elapsed = if self.last_refill_ns == 0 {
            0
        } else {
            now_ns.saturating_sub(self.last_refill_ns)
        };

        // Refill byte tokens
        if let Some(bps) = limits.io_max_bytes_per_sec {
            let burst_cap = bps.saturating_mul(IO_BURST_SECS);
            // Allow cap to grow to requested_bytes to prevent deadlock on large I/O
            let effective_cap = burst_cap.max(requested_bytes);

            if self.last_refill_ns == 0 {
                // First refill: grant full burst capacity (not request-extended)
                self.byte_tokens = burst_cap;
            } else {
                // CODEX FIX: Clamp stale tokens when limit tightened or toggled on
                if self.byte_tokens > effective_cap {
                    self.byte_tokens = effective_cap;
                }
                if elapsed > 0 && self.byte_tokens < effective_cap {
                    // Proportional refill: tokens = elapsed_secs * rate
                    let add = ((elapsed as u128 * bps as u128) / NS_PER_SEC as u128) as u64;
                    self.byte_tokens = core::cmp::min(effective_cap, self.byte_tokens.saturating_add(add));
                }
            }
        } else {
            self.byte_tokens = u64::MAX;
        }

        // Refill IOPS tokens
        if let Some(iops) = limits.io_max_iops_per_sec {
            let cap = iops.saturating_mul(IO_BURST_SECS);
            if self.last_refill_ns == 0 {
                self.iops_tokens = cap;
            } else {
                // CODEX FIX: Clamp stale tokens when limit tightened or toggled on
                if self.iops_tokens > cap {
                    self.iops_tokens = cap;
                }
                if elapsed > 0 && self.iops_tokens < cap {
                    let add = ((elapsed as u128 * iops as u128) / NS_PER_SEC as u128) as u64;
                    self.iops_tokens = core::cmp::min(cap, self.iops_tokens.saturating_add(add));
                }
            }
        } else {
            self.iops_tokens = u64::MAX;
        }

        // Clear expired throttle
        if self.throttle_until_ns != 0 && now_ns >= self.throttle_until_ns {
            self.throttle_until_ns = 0;
        }

        self.last_refill_ns = now_ns;
    }
}

/// Per-cgroup IO throttle state.
///
/// Wraps `IoBucketState` in a mutex for thread-safe access.
/// The mutex is only held during token accounting (microsecond-scale),
/// never while waiting for IO or rescheduling, avoiding deadlock with
/// the block layer's device locks.
#[derive(Debug)]
struct IoThrottleState {
    state: Mutex<IoBucketState>,
}

impl IoThrottleState {
    const fn new() -> Self {
        Self {
            state: Mutex::new(IoBucketState {
                last_refill_ns: 0,
                byte_tokens: 0,
                iops_tokens: 0,
                throttle_until_ns: 0,
            }),
        }
    }

    /// Charge IO tokens for a single operation.
    ///
    /// Refills tokens based on elapsed time, then attempts to consume tokens
    /// for the given operation. If insufficient tokens are available, computes
    /// the time until enough tokens will have accumulated and returns
    /// `Throttled(until_ns)`.
    ///
    /// # Arguments
    ///
    /// * `limits` - Current cgroup limits (must be locked by caller)
    /// * `bytes` - Number of bytes in this I/O operation
    /// * `now_ns` - Current time in nanoseconds since boot
    /// * `stats` - Cgroup stats for recording throttle events
    fn charge(
        &self,
        limits: &CgroupLimits,
        bytes: u64,
        now_ns: u64,
        stats: &CgroupStats,
    ) -> IoThrottleStatus {
        let mut bucket = self.state.lock();
        bucket.refill(limits, now_ns, bytes);

        // If still in a throttle window, return immediately
        if bucket.throttle_until_ns != 0 && now_ns < bucket.throttle_until_ns {
            return IoThrottleStatus::Throttled(bucket.throttle_until_ns);
        }

        let mut throttle_until = 0u64;

        // Check byte budget
        if let Some(bps) = limits.io_max_bytes_per_sec {
            if bucket.byte_tokens < bytes {
                // Not enough tokens: compute wait time for deficit to refill
                let deficit = bytes - bucket.byte_tokens;
                let wait_ns =
                    ((deficit as u128 * NS_PER_SEC as u128) + (bps as u128 - 1)) / bps as u128;
                throttle_until = now_ns.saturating_add(wait_ns as u64);
            } else {
                bucket.byte_tokens = bucket.byte_tokens.saturating_sub(bytes);
            }
        }

        // Check IOPS budget
        if let Some(iops) = limits.io_max_iops_per_sec {
            if bucket.iops_tokens == 0 {
                // No IOPS tokens: wait for one token to refill
                let nanos_per_io = NS_PER_SEC
                    .checked_div(iops.max(1))
                    .unwrap_or(NS_PER_SEC);
                throttle_until = throttle_until.max(now_ns.saturating_add(nanos_per_io));
            } else {
                bucket.iops_tokens = bucket.iops_tokens.saturating_sub(1);
            }
        }

        if throttle_until != 0 {
            bucket.throttle_until_ns = throttle_until;
            stats.io_throttle_events.fetch_add(1, Ordering::Relaxed);
            return IoThrottleStatus::Throttled(throttle_until);
        }

        IoThrottleStatus::Allowed
    }
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

    /// R77-1 FIX: Deletion flag to block late attaches after removal is initiated.
    ///
    /// This prevents the race where a thread holds an old Arc<CgroupNode> and
    /// attempts to attach_task() after delete_cgroup() has verified emptiness
    /// but before removing from the registry. Without this flag, such late
    /// attaches could create orphaned tasks in an unregistered cgroup.
    deleted: AtomicBool,

    /// P1-3: Delegated owner UID for this cgroup subtree.
    ///
    /// When set, the specified UID may manage this cgroup and all its
    /// descendants (create/delete children, set limits, migrate tasks)
    /// without requiring root.  Delegation is set by root via
    /// `delegate_cgroup()` and inherits downward: `is_delegated_to(uid)`
    /// walks the ancestor chain.
    delegate_uid: Mutex<Option<u32>>,

    /// F.2: CPU quota tracking state for cpu.max enforcement.
    ///
    /// Tracks per-period CPU usage and throttle state for the CPU controller.
    cpu_quota: CpuQuotaState,

    /// F.2: IO throttle state for io.max enforcement.
    ///
    /// Tracks IO bandwidth and IOPS tokens for the IO controller.
    io_throttle: IoThrottleState,
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
            deleted: AtomicBool::new(false), // R77-1 FIX
            delegate_uid: Mutex::new(None), // P1-3
            cpu_quota: CpuQuotaState::new(), // F.2: CPU quota tracking
            io_throttle: IoThrottleState::new(), // F.2: IO throttle state
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

    // ==================================================================
    // P1-3: Cgroup Delegation
    // ==================================================================

    /// Returns the delegate UID for this cgroup, if any.
    pub fn delegate_uid(&self) -> Option<u32> {
        *self.delegate_uid.lock()
    }

    /// Returns `true` if this cgroup (or any ancestor) is delegated to `uid`.
    ///
    /// Walks the ancestor chain upward; stops at the first match.
    pub fn is_delegated_to(&self, uid: u32) -> bool {
        if self.delegate_uid() == Some(uid) {
            return true;
        }
        let mut cursor = self.parent();
        while let Some(node) = cursor {
            if node.delegate_uid() == Some(uid) {
                return true;
            }
            cursor = node.parent();
        }
        false
    }

    /// P1-3: Validate that `updated` limits do not exceed the effective ancestor limits.
    ///
    /// Called when a delegated (non-root) user sets limits.  Walks the full
    /// ancestor chain and finds the tightest (most restrictive) configured
    /// limit for each resource.  The delegated user's requested limits must
    /// not exceed those boundaries, preventing privilege escalation through
    /// the delegation mechanism.
    ///
    /// For resources where no ancestor has a configured limit, the check is
    /// skipped (unlimited parent means no boundary constraint).
    pub fn check_limit_boundary(&self, updated: &CgroupLimits) -> Result<(), CgroupError> {
        // Collect effective (tightest) ancestor limits by walking up the chain.
        let mut eff_cpu_max: Option<(u64, u64)> = None;
        let mut eff_memory_max: Option<u64> = None;
        let mut eff_memory_high: Option<u64> = None;
        let mut eff_pids_max: Option<u64> = None;
        let mut eff_io_bps: Option<u64> = None;
        let mut eff_io_iops: Option<u64> = None;

        let mut cursor = self.parent();
        while let Some(ancestor) = cursor {
            let al = ancestor.limits();

            // cpu.max: keep the tightest ratio (lowest max/period)
            if let Some((amax, aperiod)) = al.cpu_max {
                if amax != u64::MAX && aperiod != 0 {
                    eff_cpu_max = Some(match eff_cpu_max {
                        None => (amax, aperiod),
                        Some((emax, eperiod)) => {
                            // Compare ratios: amax/aperiod vs emax/eperiod
                            // via cross-multiplication to avoid floating point.
                            let a_val = (amax as u128) * (eperiod as u128);
                            let e_val = (emax as u128) * (aperiod as u128);
                            if a_val < e_val {
                                (amax, aperiod) // ancestor is tighter
                            } else {
                                (emax, eperiod) // existing is tighter
                            }
                        }
                    });
                }
            }

            // Scalar limits: take the minimum non-MAX value
            if let Some(v) = al.memory_max {
                if v != u64::MAX {
                    eff_memory_max = Some(eff_memory_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.memory_high {
                if v != u64::MAX {
                    eff_memory_high = Some(eff_memory_high.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.pids_max {
                if v != u64::MAX {
                    eff_pids_max = Some(eff_pids_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.io_max_bytes_per_sec {
                eff_io_bps = Some(eff_io_bps.map_or(v, |e: u64| e.min(v)));
            }
            if let Some(v) = al.io_max_iops_per_sec {
                eff_io_iops = Some(eff_io_iops.map_or(v, |e: u64| e.min(v)));
            }

            cursor = ancestor.parent();
        }

        // --- Validate updated limits against effective boundaries ---

        // cpu.max: compare bandwidth ratio
        if let Some((max, period)) = updated.cpu_max {
            if max == 0 || period == 0 {
                return Err(CgroupError::InvalidLimit);
            }
            if let Some((emax, eperiod)) = eff_cpu_max {
                // Child cannot be unlimited if any ancestor is finite.
                if max == u64::MAX {
                    return Err(CgroupError::PermissionDenied);
                }
                // child_ratio = max/period ≤ eff_ratio = emax/eperiod
                let lhs = (max as u128) * (eperiod as u128);
                let rhs = (emax as u128) * (period as u128);
                if lhs > rhs {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // memory.max
        if let Some(max) = updated.memory_max {
            if let Some(emax) = eff_memory_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // memory.high
        if let Some(high) = updated.memory_high {
            if let Some(ehigh) = eff_memory_high {
                if high == u64::MAX || high > ehigh {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // pids.max
        if let Some(max) = updated.pids_max {
            if let Some(emax) = eff_pids_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // io.max bytes per sec
        if let Some(bps) = updated.io_max_bytes_per_sec {
            if let Some(ebps) = eff_io_bps {
                if bps > ebps {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // io.max IOPS
        if let Some(iops) = updated.io_max_iops_per_sec {
            if let Some(eiops) = eff_io_iops {
                if iops > eiops {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        Ok(())
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

        // R111-1 FIX: Use fetch_update + checked_add to prevent wrapping to 0
        // on u64 overflow.  A bare fetch_add wraps the counter past 0 (root cgroup
        // ID), which would shadow the root cgroup in the registry.  This follows the
        // R105-5 pattern established for IPC endpoint IDs and socket IDs.
        let id = NEXT_CGROUP_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| CgroupError::CgroupLimit)?;

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
            deleted: AtomicBool::new(false), // R77-1 FIX
            delegate_uid: Mutex::new(None), // P1-3
            cpu_quota: CpuQuotaState::new(), // F.2: CPU quota tracking
            io_throttle: IoThrottleState::new(), // F.2: IO throttle state
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
    /// * `NotFound` - Cgroup is being deleted (R77-1 FIX)
    /// * `TaskAlreadyAttached` - Task is already in this cgroup
    /// * `PidsLimitExceeded` - Would exceed pids.max
    ///
    /// # R90-3 FIX: Atomic pids.max enforcement
    ///
    /// Uses fetch_update CAS to atomically check-and-increment pids counters,
    /// preventing concurrent attach bypassing pids.max limits.
    pub fn attach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        // R77-1 FIX: Block attaches once deletion has started.
        // This prevents the race where a thread holds an old Arc<CgroupNode>
        // and attempts to attach after delete_cgroup() has checked emptiness
        // but before removing from registry.
        if self.deleted.load(Ordering::Acquire) {
            return Err(CgroupError::NotFound);
        }

        let mut procs = self.processes.lock();

        // Check if already attached
        if procs.contains(&task) {
            return Err(CgroupError::TaskAlreadyAttached);
        }

        // R83-3 + R90-3 FIX: Hierarchical PIDs enforcement with atomic charging
        //
        // In cgroups v2, a cgroup's pids.max limit applies to the total number
        // of processes in that cgroup *and all its descendants*. R90-3 fixes
        // the race where concurrent attachers could all pass relaxed checks
        // and then all increment, exceeding pids.max.
        //
        // Solution: Use fetch_update CAS to atomically check-and-increment.
        // On any failure, rollback previously charged ancestors.
        let mut ancestors: alloc::vec::Vec<Arc<CgroupNode>> = alloc::vec::Vec::new();
        let mut cursor = self.parent();
        while let Some(p) = cursor {
            ancestors.push(p.clone());
            cursor = p.parent();
        }

        // Snapshot limits (only if PIDs controller enabled)
        let self_limit = if self.controllers.contains(CgroupControllers::PIDS) {
            self.limits.lock().pids_max
        } else {
            None
        };
        let ancestor_limits: alloc::vec::Vec<Option<u64>> = ancestors
            .iter()
            .map(|a| {
                if a.controllers.contains(CgroupControllers::PIDS) {
                    a.limits.lock().pids_max
                } else {
                    None
                }
            })
            .collect();

        // R90-3 FIX: Atomic charge helper using CAS
        // Returns Ok(()) if charge succeeded, Err(()) if limit would be exceeded
        let charge = |stats: &CgroupStats, limit: Option<u64>| -> Result<(), ()> {
            if let Some(limit) = limit {
                stats
                    .pids_current
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                        if cur >= limit {
                            None // Reject: would exceed limit
                        } else {
                            Some(cur + 1)
                        }
                    })
                    .map(|_| ())
                    .map_err(|_| ())
            } else {
                // No limit set, always allow
                stats.pids_current.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };

        // Track which stats have been charged for rollback on failure
        let mut charged: alloc::vec::Vec<&CgroupStats> = alloc::vec::Vec::new();

        // Charge self first
        if charge(&self.stats, self_limit).is_err() {
            self.stats.record_pids_max_event();
            return Err(CgroupError::PidsLimitExceeded);
        }
        charged.push(&self.stats);

        // Charge all ancestors, rolling back on failure
        for (ancestor, limit) in ancestors.iter().zip(ancestor_limits.iter()) {
            if charge(&ancestor.stats, *limit).is_err() {
                ancestor.stats.record_pids_max_event();
                // R110-1 FIX: Rollback with saturating decrement to prevent
                // underflow if a concurrent exit already decremented.
                for stats in charged.into_iter() {
                    let _ = stats.pids_current.fetch_update(
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                        |current| Some(current.saturating_sub(1)),
                    );
                }
                return Err(CgroupError::PidsLimitExceeded);
            }
            charged.push(&ancestor.stats);
        }

        // All charges succeeded, commit membership
        procs.insert(task);
        // Counters already incremented during charging, no additional increment needed

        Ok(())
    }

    /// Detaches a task from this cgroup.
    ///
    /// # Errors
    ///
    /// * `TaskNotAttached` - Task is not in this cgroup
    pub fn detach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        // R83-3 FIX: Collect ancestors before detaching for hierarchical count update
        let mut ancestors: alloc::vec::Vec<Arc<CgroupNode>> = alloc::vec::Vec::new();
        let mut cursor = self.parent();
        while let Some(p) = cursor {
            ancestors.push(p.clone());
            cursor = p.parent();
        }

        let mut procs = self.processes.lock();

        if !procs.remove(&task) {
            return Err(CgroupError::TaskNotAttached);
        }

        self.stats.decrement_pids();

        // R83-3 FIX: Decrement ancestor counts for hierarchical tracking
        for ancestor in ancestors {
            ancestor.stats.decrement_pids();
        }

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
        if updated.io_max_bytes_per_sec.is_some() || updated.io_max_iops_per_sec.is_some() {
            if !self.controllers.contains(CgroupControllers::IO) {
                return Err(CgroupError::ControllerDisabled);
            }
        }

        // Validate CPU weight (1-10000)
        if let Some(weight) = updated.cpu_weight {
            if weight == 0 || weight > 10000 {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Validate CPU quota (period > 0, max > 0, no overflow when converting to ns)
        if let Some((max, period)) = updated.cpu_max {
            if period == 0 || max == 0 {
                return Err(CgroupError::InvalidLimit);
            }
            // P1-3 FIX: Cap values to prevent saturating_mul(1_000) overflow
            // in the enforcement path (charge_cpu_quota). u64::MAX is exempt
            // as it means "unlimited".  1_000_000_000_000 µs ≈ 11.5 days.
            const MAX_CPU_US: u64 = 1_000_000_000_000;
            if max != u64::MAX && max > MAX_CPU_US {
                return Err(CgroupError::InvalidLimit);
            }
            if period > MAX_CPU_US {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Validate IO limits (must be non-zero if provided)
        if let Some(bps) = updated.io_max_bytes_per_sec {
            if bps == 0 {
                return Err(CgroupError::InvalidLimit);
            }
        }
        if let Some(iops) = updated.io_max_iops_per_sec {
            if iops == 0 {
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
        if let Some(v) = updated.io_max_bytes_per_sec {
            limits.io_max_bytes_per_sec = Some(v);
        }
        if let Some(v) = updated.io_max_iops_per_sec {
            limits.io_max_iops_per_sec = Some(v);
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
    klog_always!("[cgroup] Cgroup v2 subsystem initialized (root id=0)");
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

/// P1-3: Delegate management of a cgroup subtree to `uid`.
///
/// Root (euid 0), holders of CAP_SYS_ADMIN, or existing delegated managers
/// of this cgroup's subtree may call this.  Delegated managers may sub-delegate
/// within their delegated scope.
///
/// Once delegated, the specified UID may create/delete children, set limits
/// (bounded by the parent), and migrate tasks within this cgroup and all its
/// descendants.
///
/// Pass `uid = None` to revoke delegation.
///
/// # Returns
///
/// On success, returns the previous `delegate_uid` value for audit trail.
///
/// # Errors
///
/// * `PermissionDenied` - Caller lacks root, CAP_SYS_ADMIN, or delegation
/// * `NotFound` - Cgroup ID does not exist
pub fn delegate_cgroup(
    id: CgroupId,
    uid: Option<u32>,
    caller_authorized: bool,
) -> Result<Option<u32>, CgroupError> {
    if !caller_authorized {
        return Err(CgroupError::PermissionDenied);
    }
    let node = lookup_cgroup(id).ok_or(CgroupError::NotFound)?;
    let old_uid = core::mem::replace(&mut *node.delegate_uid.lock(), uid);
    Ok(old_uid)
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
///
/// # R77-1 FIX: Deletion Flag
///
/// Additionally, we set the `deleted` flag before checking emptiness to block
/// any late attaches from threads holding old Arc<CgroupNode> references.
/// The attach_task() method checks this flag and rejects attaches to deleted cgroups.
pub fn delete_cgroup(id: CgroupId) -> Result<(), CgroupError> {
    if id == 0 {
        return Err(CgroupError::PermissionDenied);
    }

    // CODEX FIX: Hold registry write lock throughout to prevent TOCTOU race
    // This blocks lookup_cgroup() used by attach_task(), ensuring no new
    // tasks can be attached between the emptiness check and removal.
    let mut registry = CGROUP_REGISTRY.write();

    let node = registry.get(&id).cloned().ok_or(CgroupError::NotFound)?;

    // R77-1 FIX: Mark as deleting BEFORE checking emptiness to block any racing
    // attach_task() callers who hold old Arc<CgroupNode> references.
    // The deleted flag uses Acquire/Release ordering to ensure proper visibility.
    node.deleted.store(true, Ordering::Release);

    // Check if empty while holding registry write lock
    // No new tasks can attach because:
    // 1. lookup_cgroup needs registry read lock (which we hold as write)
    // 2. attach_task() checks deleted flag (which we just set)
    if !node.children.lock().is_empty() {
        // Rollback deleted flag since deletion failed
        node.deleted.store(false, Ordering::Release);
        return Err(CgroupError::NotEmpty);
    }
    if !node.processes.lock().is_empty() {
        // Rollback deleted flag since deletion failed
        node.deleted.store(false, Ordering::Release);
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
/// # R90-4 FIX: Migration/Deletion Race
///
/// Holds `CGROUP_REGISTRY` read lock throughout the migration to prevent
/// concurrent `delete_cgroup()` from removing source or target cgroups
/// between detach and attach, which could leave the task orphaned.
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
    // R90-4 FIX: Hold registry read lock to block concurrent delete_cgroup.
    // delete_cgroup requires a write lock, so this prevents both source
    // and target from being deleted during the migration window.
    let _reg_guard = CGROUP_REGISTRY.read();

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
/// R111-2 FIX: Walks the ancestor chain (up to MAX_CGROUP_DEPTH levels) so that
/// a parent or grandparent `pids.max` limit is also checked.  This is a best-effort
/// pre-check — the authoritative hierarchical CAS-based check remains in `attach_task()`.
/// Using `Ordering::Acquire` ensures visibility of concurrent PID counter increments.
///
/// Returns `true` if fork is allowed, `false` if pids.max would be exceeded.
pub fn check_fork_allowed(cgroup_id: CgroupId) -> bool {
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::PIDS) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.pids_max {
                let current = cgroup.stats.pids_current.load(Ordering::Acquire);
                if current >= max {
                    cgroup.stats.record_pids_max_event();
                    return false;
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
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

/// Returns current memory usage for a cgroup (read-only snapshot).
///
/// # R77-2 FIX
///
/// This replaces the old `update_memory_usage()` which used bare `store()` and
/// could overwrite in-flight `try_charge_memory()` CAS operations. The memory
/// accounting model is now exclusively charge/uncharge based:
///
/// - **Allocations** (mmap, etc.): Use `try_charge_memory()` with atomic CAS
/// - **Deallocations** (munmap, etc.): Use `uncharge_memory()` with fetch_update
/// - **Monitoring**: Use this function for read-only snapshots
///
/// This eliminates the race where a background sampler's `store()` would
/// overwrite concurrent CAS updates, potentially bypassing memory limits.
pub fn get_memory_usage(cgroup_id: CgroupId) -> Option<u64> {
    lookup_cgroup(cgroup_id).map(|cgroup| cgroup.stats.get_memory_current())
}

/// Checks if memory allocation would exceed cgroup limit.
///
/// P2-9 FIX: Walks the ancestor chain (up to MAX_CGROUP_DEPTH levels) so that
/// a parent or grandparent `memory.max` limit is also checked.  This is a
/// best-effort pre-check — the authoritative hierarchical CAS-based enforcement
/// is in `try_charge_memory()`.  Uses `Ordering::Acquire` to ensure visibility
/// of concurrent memory counter increments.
///
/// Returns `true` if allocation is allowed.
pub fn check_memory_allowed(cgroup_id: CgroupId, allocation_bytes: u64) -> bool {
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.memory_max {
                let current = cgroup.stats.memory_current.load(Ordering::Acquire);
                if current.saturating_add(allocation_bytes) > max {
                    cgroup.stats.record_memory_max();
                    return false;
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
    true
}

/// Atomically charges memory usage to a cgroup, enforcing memory.max.
///
/// P2-9 FIX: Hierarchical memory.max enforcement.
///
/// In cgroups v2, ancestor `memory.max` limits apply to all descendants.
/// This function charges `memory_current` on the target cgroup **and** every
/// ancestor with the MEMORY controller enabled.  On failure at any level,
/// all previously charged ancestors are rolled back (saturating subtract).
///
/// This follows the same charge-then-rollback pattern as hierarchical
/// `pids.max` enforcement in `attach_task()` (R83-3 + R90-3).
///
/// Uses CAS (`fetch_update`) for each cgroup to atomically check the limit
/// and increment the counter, closing the TOCTOU race between concurrent
/// mmap callers (CODEX FIX).
///
/// # Errors
///
/// * `MemoryLimitExceeded` - Adding `allocation_bytes` would exceed memory.max
///   at this cgroup or any ancestor.
pub fn try_charge_memory(cgroup_id: CgroupId, allocation_bytes: u64) -> Result<(), CgroupError> {
    if allocation_bytes == 0 {
        return Ok(());
    }

    // Collect the chain: target cgroup + ancestors with MEMORY controller.
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    let mut chain: Vec<Arc<CgroupNode>> = Vec::new();
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            chain.push(cgroup.clone());
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if chain.is_empty() {
        return Ok(()); // No memory controller anywhere in the chain
    }

    // Snapshot limits to avoid holding multiple locks during CAS charging.
    let limits_snapshot: Vec<(Option<u64>, Option<u64>)> = chain
        .iter()
        .map(|c| {
            let l = c.limits.lock();
            (l.memory_max, l.memory_high)
        })
        .collect();

    // Track indices of charged cgroups for rollback on failure.
    let mut charged: Vec<usize> = Vec::new();

    for (idx, cgroup) in chain.iter().enumerate() {
        let (max, high) = limits_snapshot[idx];

        match cgroup.stats.memory_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(allocation_bytes);
                if let Some(max) = max {
                    if new > max {
                        return None; // Reject: would exceed limit
                    }
                }
                Some(new)
            },
        ) {
            Ok(old) => {
                // Check high watermark event
                let new = old.saturating_add(allocation_bytes);
                if let Some(high) = high {
                    if new > high {
                        cgroup.stats.record_memory_high();
                    }
                }
                charged.push(idx);
            }
            Err(_) => {
                // Limit exceeded at this level — record event and rollback.
                cgroup.stats.record_memory_max();

                // R110-1 pattern: Rollback with saturating decrement to
                // prevent underflow if a concurrent uncharge raced.
                for &j in &charged {
                    let _ = chain[j].stats.memory_current.fetch_update(
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                        |current| Some(current.saturating_sub(allocation_bytes)),
                    );
                }

                return Err(CgroupError::MemoryLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges memory from a cgroup (saturating at zero).
///
/// P2-9 FIX: Walks the same ancestor chain as `try_charge_memory()` to
/// uncharge `memory_current` at each level.  Without this, ancestor counters
/// would permanently leak, eventually DoS-ing the subtree by "stuck" usage.
///
/// Called when memory is released (munmap, process exit, etc.).
/// Uses fetch_update for atomic subtract-with-floor-at-zero.
pub fn uncharge_memory(cgroup_id: CgroupId, bytes: u64) {
    if bytes == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let _ = cgroup.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(bytes)),
            );
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

// ============================================================================
// F.2: IO Controller Integration (io.max enforcement)
// ============================================================================

/// Charge IO tokens for a cgroup and return throttle status.
///
/// Called before issuing a block I/O operation. If the cgroup has io.max
/// configured and is out of tokens, returns `Throttled(until_ns)` indicating
/// when the caller should retry.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to charge
/// * `bytes` - Number of bytes in this I/O operation
/// * `op` - Read or Write direction
/// * `now_ns` - Current time in nanoseconds since boot
///
/// # Returns
///
/// * `Unlimited` - No IO controller or io.max not configured
/// * `Allowed` - Tokens available, operation permitted
/// * `Throttled(until_ns)` - Tokens exhausted, retry after specified time
pub fn charge_io(
    cgroup_id: CgroupId,
    bytes: u64,
    _op: IoDirection,
    now_ns: u64,
) -> IoThrottleStatus {
    if bytes == 0 {
        return IoThrottleStatus::Allowed;
    }

    // P2-9 FIX: Hierarchical io.max enforcement.
    //
    // In cgroups v2, ancestor io.max limits apply to all descendants.
    // Walk the ancestor chain and charge each level's IO token bucket.
    // If any level is throttled, return the most restrictive deadline.
    //
    // Two-phase approach to avoid partial token consumption:
    //   Phase 1: Query all ancestors to determine if any are throttled,
    //            WITHOUT consuming tokens.
    //   Phase 2: If none are throttled, commit token consumption at
    //            every level.
    //
    // This prevents "token leakage" where a child's tokens are consumed
    // but the IO is not issued because an ancestor is throttled.
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    let mut chain: Vec<Arc<CgroupNode>> = Vec::new();

    // Collect ancestors with IO controller and configured io.max limits.
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::IO) {
            let limits = cgroup.limits.lock();
            if limits.io_max_bytes_per_sec.is_some() || limits.io_max_iops_per_sec.is_some() {
                chain.push(cgroup.clone());
            }
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if chain.is_empty() {
        return IoThrottleStatus::Unlimited;
    }

    // Phase 1: Check all levels for throttle status WITHOUT consuming tokens.
    // We use the IoThrottleState's existing throttle_until_ns window to detect
    // active throttling, and check token availability without decrementing.
    let mut overall_throttle_until: u64 = 0;

    for cgroup in &chain {
        let limits = cgroup.limits.lock();
        let bucket = cgroup.io_throttle.state.lock();

        // Check if currently in a throttle window.
        if bucket.throttle_until_ns != 0 && now_ns < bucket.throttle_until_ns {
            overall_throttle_until = overall_throttle_until.max(bucket.throttle_until_ns);
            continue;
        }

        // Check byte budget (without consuming).
        if let Some(bps) = limits.io_max_bytes_per_sec {
            if bucket.byte_tokens < bytes {
                let deficit = bytes - bucket.byte_tokens;
                let wait_ns =
                    ((deficit as u128 * 1_000_000_000u128) + (bps as u128 - 1)) / bps as u128;
                let until = now_ns.saturating_add(wait_ns as u64);
                overall_throttle_until = overall_throttle_until.max(until);
            }
        }

        // Check IOPS budget (without consuming).
        if let Some(iops) = limits.io_max_iops_per_sec {
            if bucket.iops_tokens == 0 {
                let nanos_per_io = 1_000_000_000u64
                    .checked_div(iops.max(1))
                    .unwrap_or(1_000_000_000);
                let until = now_ns.saturating_add(nanos_per_io);
                overall_throttle_until = overall_throttle_until.max(until);
            }
        }
    }

    // If any level would throttle, return the most restrictive deadline
    // WITHOUT consuming any tokens.
    if overall_throttle_until != 0 {
        return IoThrottleStatus::Throttled(overall_throttle_until);
    }

    // Phase 2: All levels have sufficient tokens.  Commit consumption at
    // every level by calling the existing charge() method.
    for cgroup in &chain {
        let limits = cgroup.limits.lock();
        let _ = cgroup
            .io_throttle
            .charge(&limits, bytes, now_ns, &cgroup.stats);
    }

    IoThrottleStatus::Allowed
}

/// Block until IO tokens are available (process context only).
///
/// Called by the block layer before issuing I/O. This function will yield
/// the CPU and retry until tokens become available. **Must not be called
/// from IRQ context** as it may reschedule.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to throttle against
/// * `bytes` - Number of bytes in this I/O operation
/// * `op` - Read or Write direction
///
/// # Returns
///
/// Always returns `Allowed` once tokens are available.
pub fn wait_for_io_window(
    cgroup_id: CgroupId,
    bytes: u64,
    op: IoDirection,
) -> IoThrottleStatus {
    let mut now_ns = crate::current_timestamp_ms().saturating_mul(1_000_000);

    loop {
        match charge_io(cgroup_id, bytes, op, now_ns) {
            IoThrottleStatus::Allowed | IoThrottleStatus::Unlimited => {
                return IoThrottleStatus::Allowed
            }
            IoThrottleStatus::Throttled(until) => {
                // Yield CPU to allow other tasks to run while we wait for tokens.
                // SAFETY: This is only called from process context (block layer)
                // where rescheduling is safe.
                crate::scheduler_hook::force_reschedule();

                // Update timestamp for next check
                let next = crate::current_timestamp_ms().saturating_mul(1_000_000);
                now_ns = core::cmp::max(next, now_ns.saturating_add(1_000_000));

                if now_ns < until {
                    continue;
                }
            }
        }
    }
}

/// Record IO completion statistics after a successful transfer.
///
/// Called by the block layer after an I/O operation completes successfully.
/// Updates the read/write byte counters for the cgroup.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup that performed the I/O
/// * `bytes` - Number of bytes transferred
/// * `op` - Read or Write direction
pub fn record_io_completion(cgroup_id: CgroupId, bytes: u64, op: IoDirection) {
    if bytes == 0 {
        return;
    }

    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::IO) {
            match op {
                IoDirection::Read => {
                    cgroup.stats.io_read_bytes.fetch_add(bytes, Ordering::Relaxed);
                    cgroup.stats.io_read_ios.fetch_add(1, Ordering::Relaxed);
                }
                IoDirection::Write => {
                    cgroup.stats.io_write_bytes.fetch_add(bytes, Ordering::Relaxed);
                    cgroup.stats.io_write_ios.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ============================================================================
// F.2: CPU Controller Integration (cpu.max enforcement)
// ============================================================================

/// Charge CPU time and enforce cpu.max quota.
///
/// Called from the scheduler's tick handler to account CPU usage against
/// the cgroup's quota and check for throttling.
///
/// # Safety Note
///
/// This function is called in IRQ context (timer interrupt handler).
/// It uses `try_lock()` on the limits mutex to avoid deadlock: if
/// a process-context thread holds the lock (e.g., setting limits),
/// the charge is skipped for this tick. This is safe because:
/// - Missing one tick of enforcement doesn't breach isolation
/// - The quota will be enforced on subsequent ticks
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to charge
/// * `delta_ns` - CPU time consumed (nanoseconds)
/// * `now_ns` - Current time (nanoseconds since boot)
///
/// # Returns
///
/// * `Unlimited` - No CPU controller or cpu.max configured
/// * `Allowed` - Quota available, time has been charged
/// * `Throttled(until_ns)` - Quota exceeded, cgroup is throttled until specified time
pub fn charge_cpu_quota(
    cgroup_id: CgroupId,
    delta_ns: u64,
    now_ns: u64,
) -> CpuQuotaStatus {
    if delta_ns == 0 {
        return CpuQuotaStatus::Allowed;
    }

    // P2-9 FIX: Hierarchical cpu.max enforcement.
    //
    // In cgroups v2, ancestor cpu.max quotas apply to all descendants.
    // We charge CPU time at each level of the hierarchy and return the
    // most restrictive throttle deadline.
    //
    // Design: walk from leaf to root.  At each node with a CPU controller
    // and cpu.max configured, charge time and record throttle status.  The
    // overall result is the latest (most restrictive) throttle deadline
    // among all ancestors, or Allowed if none are throttled.
    const LOCK_CONTENTION_THROTTLE_NS: u64 = 10_000_000; // 10ms

    let mut any_quota = false;
    let mut overall_throttle_until: u64 = 0;

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::CPU) {
            // IRQ-safe: Use try_lock() to avoid deadlock when process-context
            // code holds the limits lock (e.g., sys_cgroup_set_limit).
            //
            // R83-5 FIX: Fail-closed when lock is contended (prevents bypass).
            let cpu_max = match cgroup.limits.try_lock() {
                Some(limits) => limits.cpu_max,
                None => {
                    return CpuQuotaStatus::Throttled(
                        now_ns.saturating_add(LOCK_CONTENTION_THROTTLE_NS),
                    );
                }
            };

            if let Some((max_us, period_us)) = cpu_max {
                // u64::MAX means "max" (no quota) - mirrors Linux semantics
                if max_us != u64::MAX {
                    any_quota = true;

                    let period_ns = period_us.saturating_mul(1_000);
                    let max_ns = max_us.saturating_mul(1_000);
                    let quota = &cgroup.cpu_quota;

                    // Refresh the window if the period has elapsed
                    quota.refresh_window(now_ns, period_ns);

                    // Check if currently throttled
                    let throttle_until = quota.throttled_until_ns.load(Ordering::Acquire);
                    let mut should_charge = true;
                    if throttle_until != 0 {
                        if now_ns < throttle_until {
                            // Still in throttle window
                            overall_throttle_until =
                                overall_throttle_until.max(throttle_until);
                            should_charge = false;
                        } else {
                            // R110-2 FIX: Throttle expired — delegate to
                            // CAS-serialized refresh_window().
                            quota.refresh_window(now_ns, period_ns);
                        }
                    }

                    // R110-2 FIX: Skip charging while a refresh is in progress.
                    if should_charge && !quota.is_refreshing() {
                        let used = quota
                            .period_usage_ns
                            .fetch_add(delta_ns, Ordering::SeqCst)
                            .saturating_add(delta_ns);

                        if used > max_ns {
                            // Quota exceeded — throttle until end of current period
                            let until = quota
                                .period_start_ns
                                .load(Ordering::Relaxed)
                                .saturating_add(period_ns);
                            quota.throttled_until_ns.store(until, Ordering::SeqCst);
                            quota.throttle_events.fetch_add(1, Ordering::Relaxed);
                            overall_throttle_until =
                                overall_throttle_until.max(until);
                        }
                    }
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if overall_throttle_until != 0 {
        CpuQuotaStatus::Throttled(overall_throttle_until)
    } else if any_quota {
        CpuQuotaStatus::Allowed
    } else {
        CpuQuotaStatus::Unlimited
    }
}

/// Fast-path check if a cgroup is currently throttled.
///
/// Used by the scheduler before selecting a task to avoid scheduling
/// tasks from throttled cgroups.
///
/// # Safety Note
///
/// This function may be called with interrupts disabled (scheduler context).
/// Uses `try_lock()` on the limits mutex to avoid deadlock.
/// If the lock is contended, returns `None` (not throttled) - this is
/// conservative but safe, as the throttle will be detected on the next check.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to check
/// * `now_ns` - Current time (nanoseconds since boot)
///
/// # Returns
///
/// * `Some(until_ns)` - Cgroup is throttled until the specified time
/// * `None` - Cgroup is not throttled (or no CPU controller/quota)
pub fn cpu_quota_is_throttled(cgroup_id: CgroupId, now_ns: u64) -> Option<u64> {
    // P2-9 FIX: Walk ancestors so parent throttling also blocks descendants.
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    let mut overall_until: u64 = 0;

    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::CPU) {
            // IRQ-safe: Use try_lock() to avoid deadlock in scheduler context.
            // If contended, return None (existing conservative behavior).
            let cpu_max = match cgroup.limits.try_lock() {
                Some(limits) => limits.cpu_max,
                None => return None,
            };

            if let Some((max_us, period_us)) = cpu_max {
                if max_us != u64::MAX {
                    let period_ns = period_us.saturating_mul(1_000);
                    let quota = &cgroup.cpu_quota;

                    // Refresh window first to check if throttle has expired
                    quota.refresh_window(now_ns, period_ns);

                    let until = quota.throttled_until_ns.load(Ordering::Acquire);
                    if until != 0 {
                        if now_ns < until {
                            // Still throttled at this level
                            overall_until = overall_until.max(until);
                        } else {
                            // R110-2 FIX: Throttle expired — delegate to
                            // CAS-serialized refresh_window().
                            quota.refresh_window(now_ns, period_ns);
                        }
                    }
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if overall_until != 0 { Some(overall_until) } else { None }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns true if the cgroup subsystem is initialized.
#[cfg(test)]
pub fn test_is_initialized() -> bool {
    CGROUP_REGISTRY.read().contains_key(&0)
}
