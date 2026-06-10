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
        /// J2-7: FILES controller — per-cgroup open file-descriptor count limit.
        const FILES  = 0x10;
        /// J2-8: NET controller — per-cgroup ephemeral-port count limit.
        /// (Bit reserved here so FILES/NET never alias; wired in J.2 item 8.)
        const NET    = 0x20;
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

    /// J2-7: Maximum number of open file descriptors in the cgroup (FILES controller).
    /// Hierarchical, in addition to per-process `RLIMIT_NOFILE`. `None` = unlimited.
    pub fds_max: Option<u64>,

    /// J2-8: Maximum number of ephemeral ports reserved in the cgroup (NET controller).
    /// `None` = unlimited. (Field reserved here; charge wiring lands in J.2 item 8.)
    pub ports_max: Option<u64>,

    /// J2-10: Maximum bytes of kernel memory for per-tenant VFS directory enumeration
    /// (MEMORY controller). `None` = unlimited. (Field reserved here; charge wiring
    /// lands in J.2 item 10.)
    pub vfs_dir_max: Option<u64>,
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

    /// J2-7: Current number of open file descriptors charged to this cgroup.
    pub fds_current: AtomicU64,
    /// J2-7: Number of times fds.max was hit (EMFILE / fork-EAGAIN events).
    pub fds_events_max: AtomicU32,
    /// J2-8: Current number of ephemeral ports charged to this cgroup.
    pub ports_current: AtomicU64,
    /// J2-8: Number of times ports.max was hit.
    pub ports_events_max: AtomicU32,
    /// J2-10: Current bytes of VFS directory-enumeration memory charged to this cgroup.
    pub vfs_dir_current: AtomicU64,
    /// J2-9: Current bytes of kernel memory charged to this cgroup (observability;
    /// hard enforcement remains via `memory_current`).
    pub kmem_current: AtomicU64,
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
            // J2-7/8/9/10: per-cgroup FD / port / VFS-dir / kmem counters.
            fds_current: AtomicU64::new(0),
            fds_events_max: AtomicU32::new(0),
            ports_current: AtomicU64::new(0),
            ports_events_max: AtomicU32::new(0),
            vfs_dir_current: AtomicU64::new(0),
            kmem_current: AtomicU64::new(0),
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
            fds_current: self.fds_current.load(Ordering::Relaxed),
            fds_events_max: self.fds_events_max.load(Ordering::Relaxed),
            ports_current: self.ports_current.load(Ordering::Relaxed),
            ports_events_max: self.ports_events_max.load(Ordering::Relaxed),
            vfs_dir_current: self.vfs_dir_current.load(Ordering::Relaxed),
            kmem_current: self.kmem_current.load(Ordering::Relaxed),
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
        self.memory_events_high.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// Records a memory.max (OOM) event.
    #[inline]
    pub fn record_memory_max(&self) {
        self.memory_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// Increments the attached task count.
    #[inline]
    fn increment_pids(&self) {
        self.pids_current.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
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
        self.pids_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// J2-7: Decrements the FD count (saturating at zero), mirroring
    /// `decrement_pids` (R110-1) so a double-uncharge / migration race can never
    /// wrap `fds_current` to `u64::MAX`.
    #[inline]
    fn decrement_fds(&self, n: u64) {
        let _ = self.fds_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(n)),
        );
    }

    /// J2-7: Records an fds.max exceeded event.
    #[inline]
    fn record_fds_max_event(&self) {
        self.fds_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// J2-8: Decrements the ephemeral-port count (saturating at zero), mirroring
    /// `decrement_fds` so a double-uncharge / teardown race (the deferred-uncharge
    /// queue can fold the same charge twice if a remove and a reaper both observe
    /// the entry) can never wrap `ports_current` to `u64::MAX`.
    #[inline]
    fn decrement_ports(&self, n: u64) {
        let _ = self.ports_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(n)),
        );
    }

    /// J2-8: Records a ports.max exceeded event.
    #[inline]
    fn record_ports_max_event(&self) {
        self.ports_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
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
    pub fds_current: u64,
    pub fds_events_max: u32,
    pub ports_current: u64,
    pub ports_events_max: u32,
    pub vfs_dir_current: u64,
    pub kmem_current: u64,
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
            stats.io_throttle_events.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
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
    /// J2-7: FD limit exceeded - cannot open/install more file descriptors.
    FdsLimitExceeded,
    /// J2-8: Ephemeral-port limit exceeded - cannot reserve more ports.
    PortsLimitExceeded,
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
            CgroupError::FdsLimitExceeded => write!(f, "files.max limit exceeded"),
            CgroupError::PortsLimitExceeded => write!(f, "ports.max limit exceeded"),
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
        // R169-L4 FIX: Bound the ancestor walk by MAX_CGROUP_DEPTH — the backstop
        // every other cgroup ancestor walk uses — so a corrupted/cyclic parent
        // chain cannot spin forever. The hierarchy is depth-capped at create time
        // (MAX_CGROUP_DEPTH), so this never truncates a legitimate chain.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(node) = cursor {
            if node.delegate_uid() == Some(uid) {
                return true;
            }
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
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
        let mut eff_fds_max: Option<u64> = None;
        let mut eff_ports_max: Option<u64> = None;
        let mut eff_vfs_dir_max: Option<u64> = None;

        // R169-L4 FIX: bound the ancestor walk by MAX_CGROUP_DEPTH (mirrors the
        // other cgroup ancestor walks) so a corrupted/cyclic parent chain cannot
        // spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
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
            if let Some(v) = al.fds_max {
                if v != u64::MAX {
                    eff_fds_max = Some(eff_fds_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.ports_max {
                if v != u64::MAX {
                    eff_ports_max = Some(eff_ports_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.vfs_dir_max {
                if v != u64::MAX {
                    eff_vfs_dir_max = Some(eff_vfs_dir_max.map_or(v, |e: u64| e.min(v)));
                }
            }

            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
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

        // J2-7 files.max / J2-8 net.ports.max / J2-10 vfs_dir.max: a delegated
        // child cannot exceed (or be unlimited beyond) the tightest ancestor cap.
        if let Some(max) = updated.fds_max {
            if let Some(emax) = eff_fds_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }
        if let Some(max) = updated.ports_max {
            if let Some(emax) = eff_ports_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }
        if let Some(max) = updated.vfs_dir_max {
            if let Some(emax) = eff_vfs_dir_max {
                if max == u64::MAX || max > emax {
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
        self.attach_task_impl(task, true)
    }

    /// Attaches a task to this cgroup, bypassing pids.max enforcement.
    ///
    /// R123-4 FIX: Used exclusively for rollback paths (e.g. `migrate_task`)
    /// where a failed migration must re-attach the task to its source cgroup.
    /// Without this, a concurrent attach filling pids.max between detach and
    /// rollback would leave the task permanently unattached (INV-CG-03 violation).
    fn force_attach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        self.attach_task_impl(task, false)
    }

    fn attach_task_impl(&self, task: TaskId, enforce_pids_max: bool) -> Result<(), CgroupError> {
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
        // R169-L4 FIX: bound the ancestor collection by MAX_CGROUP_DEPTH (mirrors
        // the other cgroup ancestor walks) so a corrupted/cyclic parent chain
        // cannot spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(p) = cursor {
            ancestors.push(p.clone());
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = p.parent();
        }

        // Snapshot limits (only if PIDs controller enabled AND enforcement requested)
        let self_limit = if enforce_pids_max && self.controllers.contains(CgroupControllers::PIDS) {
            self.limits.lock().pids_max
        } else {
            None
        };
        let ancestor_limits: alloc::vec::Vec<Option<u64>> = ancestors
            .iter()
            .map(|a| {
                if enforce_pids_max && a.controllers.contains(CgroupControllers::PIDS) {
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
                stats.pids_current.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (statistics counter)
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
        // R169-L4 FIX: bound the ancestor collection by MAX_CGROUP_DEPTH (mirrors
        // the other cgroup ancestor walks) so a corrupted/cyclic parent chain
        // cannot spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(p) = cursor {
            ancestors.push(p.clone());
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
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
        // J2-7/8/10: new resource limits require their controllers to be enabled.
        if updated.fds_max.is_some() {
            if !self.controllers.contains(CgroupControllers::FILES) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.ports_max.is_some() {
            if !self.controllers.contains(CgroupControllers::NET) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.vfs_dir_max.is_some() {
            if !self.controllers.contains(CgroupControllers::MEMORY) {
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
        if let Some(v) = updated.fds_max {
            limits.fds_max = Some(v);
        }
        if let Some(v) = updated.ports_max {
            limits.ports_max = Some(v);
        }
        if let Some(v) = updated.vfs_dir_max {
            limits.vfs_dir_max = Some(v);
        }

        Ok(())
    }

    /// Returns a snapshot of current statistics.
    pub fn get_stats(&self) -> CgroupStatsSnapshot {
        self.stats.snapshot()
    }

    /// Increments the manual reference count (R112-2: overflow-safe).
    pub fn inc_ref(&self) {
        self.ref_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("CgroupNode refcount overflow");
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

/// R169-2 FIX (D1-CGROUP-IRQ-L5): Non-blocking sibling of `lookup_cgroup` for
/// IRQ / IRQ-disabled contexts (the timer-tick CPU accounting at
/// `on_clock_tick`, and the scheduler pick path via `cpu_quota_is_throttled`).
///
/// `lookup_cgroup` takes a BLOCKING `CGROUP_REGISTRY.read()` on a non-reentrant
/// `spin::RwLock`. If a same-CPU process-context writer (`create_cgroup` 1202 /
/// `delete_cgroup` 1639 / `migrate_task` 1708, all IRQs-enabled) is interrupted
/// mid-hold by the timer, the IRQ's blocking read spins forever on the lock the
/// suspended writer can never release → deterministic self-deadlock.
///
/// `try_read()` returns `None` immediately (never spins) on writer contention,
/// so this CANNOT block in an IRQ-off context regardless of writer discipline —
/// eliminating the deadlock class at the single chokepoint every IRQ-unsafe
/// registry read flows through. Mirrors the existing `cgroup.limits.try_lock()`
/// IRQ-safety pattern (2589). Root (id 0) short-circuits to `ROOT_CGROUP` and
/// never touches the registry, so it always resolves even in IRQ context.
pub fn try_lookup_cgroup(id: CgroupId) -> Option<Arc<CgroupNode>> {
    if id == 0 {
        return Some(ROOT_CGROUP.clone());
    }
    CGROUP_REGISTRY.try_read().and_then(|g| g.get(&id).cloned())
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

    // R169-3 / R169-L9/L10/L11 FIX (D2-J2-CHARGE-LIFETIME): BEFORE taking the
    // registry write lock, FIRST sweep dead-`Weak` bindings across ALL namespaces,
    // THEN flush the deferred per-cgroup port-uncharge queue in process context.
    // The sweep reclaims a charge stranded by a socket dropped without close() /
    // in a quiescent sibling netns (which the rate-gated reschedule sweep may not
    // have visited yet) so it stops inflating `ports_current` at the emptiness
    // gate below; the drain then applies every enqueued (swept + just-exited)
    // uncharge so the gate samples the true live count. A genuinely LIVE charge
    // (its `Weak` still upgrades) is left intact and correctly fails the delete
    // closed (the R169-3 loud-strand guarantee). BOTH steps MUST run before
    // `CGROUP_REGISTRY.write()` is held: the sweep takes the L8 binding locks and
    // only enqueues (no L5), but the drain acquires the L5 read path
    // (`uncharge_ports` -> `lookup_cgroup`) and the non-reentrant spin::RwLock
    // would self-deadlock under a held write guard. `delete_cgroup` runs in
    // process context (cgroupfs rmdir / sys path) with IRQs enabled, so the
    // blocking sweep+drain is safe here.
    net::socket_table().sweep_stranded_port_charges();
    net::socket_table().drain_deferred_port_uncharges();

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

    // R169-3 FIX (D2-J2-CHARGE-LIFETIME): Reject deletion while the cgroup still
    // carries LIVE per-cgroup resource charges. These charges are keyed by a
    // bare `cgid` (e.g. `PortBinding.charged_cgroup`, and the memory/fd ancestor
    // walks); if the node leaves the registry while a charge still references
    // its id, the later `uncharge_*()` -> `lookup_cgroup(id) == None` becomes a
    // SILENT no-op and the `+N` applied to every ancestor at charge time is
    // NEVER reversed → permanent ancestor over-count → eventual
    // ports.max / files.max / memory.max self-DoS of the surviving subtree (the
    // R169-3 leak; ids are monotonic and never recycled, 1537, so there is no
    // misapply — only the leak). Gating the delete on the live counters (read
    // under the held write lock, `Acquire` to pair with the `SeqCst` charge
    // stores) keeps the id registry-resident until every charge is reconciled,
    // so each uncharge is guaranteed to find the node and actually decrement.
    // The `deleted` flag is already set (blocking new attach_task), and the
    // lifecycle guarantees no NEW charge lands after this gate samples zero:
    // migration is serialized under the Process lock and exit detaches the task
    // before its deferred uncharges, so the only post-gate counter motion is
    // DECREMENTS (the charge helpers themselves do not consult `deleted` — the
    // safety here is lifecycle-based, not flag-enforced).
    //
    // EXCLUDED from the gate: `kmem_current` (a currently-unwired/dead stat
    // field, always 0; J2-9 page-table kmem rides `memory_current`) and
    // `vfs_dir_current` (RAII `VfsDirBudgetGuard` Arc-pins the node, so its
    // uncharge always reaches the same node it charged and self-reconciles).
    // Only the bare-cgid PORT / FD / MEMORY charges can outlive the id.
    //
    // Fail-CLOSED: a transient `NotEmpty`/EBUSY (the CAP_SYS_ADMIN / delegated
    // owner retries once in-flight teardown + uncharge settles — promptly,
    // because the deferred port queue was force-drained above and exit-path
    // uncharges run on every syscall-return/idle drain) is strictly safer than
    // a silent, unrecoverable over-count. ids are never recycled, so a deferred
    // delete can never misapply to a different cgroup.
    let live_ports = node.stats.ports_current.load(Ordering::Acquire);
    let live_fds = node.stats.fds_current.load(Ordering::Acquire);
    let live_mem = node.stats.memory_current.load(Ordering::Acquire);
    if live_ports != 0 || live_fds != 0 || live_mem != 0 {
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
///
/// # Caller obligations (R169-L12)
///
/// This migrates ONLY the task's cgroup MEMBERSHIP and the hierarchical **pids**
/// accounting (`detach_task`/`attach_task`). It does NOT transfer the per-cgroup
/// **FD** or **memory** charges — a caller that re-homes a task between cgroups
/// MUST migrate those separately (see `sys_cgroup_attach`, which moves fd +
/// memory charges under the Process lock); omitting that strands them on the
/// source ancestor chain. Ephemeral-**port** charges are NOT task-migratable by
/// design: each is bound at allocation to the socket's owning cgroup via
/// `PortBinding.charged_cgroup` (and uncharged against that stored id), and
/// deliberately does NOT move on cgroup attach (the J2-8 self-test asserts this).
/// Re-homing the task therefore leaves the port charge with the original cgroup —
/// whether that SHOULD change is the open D2-J2-CHARGE-LIFETIME / R169-7 question,
/// not a caller obligation of this function.
///
/// Lock discipline: `migrate_task` holds the **non-reentrant** `CGROUP_REGISTRY`
/// read lock for the whole window (R90-4). Callers MUST therefore run any
/// charge/uncharge primitive (each does `lookup_cgroup` → a registry read) AFTER
/// `migrate_task` returns, never inside a callback under this guard. Callers MUST
/// NOT fold `address_space_share_count()` (which takes PROCESS_TABLE then foreign
/// Process locks) into a "hold the target Process lock across `migrate_task`"
/// obligation — that is the R156-1 child→parent ABBA / self-deadlock footgun.
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
        // R123-4 FIX: Rollback must not fail due to pids.max. force_attach_task()
        // bypasses pids.max enforcement so a failed migration never orphans the
        // task (INV-CG-03). The pids counter may temporarily exceed pids.max, but
        // this is bounded and self-correcting (next task exit decrements it).
        if let Err(rollback_err) = from.force_attach_task(task) {
            klog_always!(
                "SECURITY: cgroup migrate rollback failed for task {}: source={} target={} err={:?}",
                task, from_id, to_id, rollback_err
            );
        }
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
///
/// R169-2 FIX (D1-CGROUP-IRQ-L5): Invoked from `on_clock_tick` in true timer-IRQ
/// context (IRQs disabled), so it MUST NOT take the blocking registry lock. Uses
/// `try_lookup_cgroup` and FAILS OPEN on registry contention: a dropped tick is
/// harmless because CPU-time accounting is monotonic-add-only (no paired
/// uncharge), so it can never underflow, orphan a charge, or breach a limit —
/// the missing tick self-corrects on the next one.
pub fn account_cpu_time(cgroup_id: CgroupId, delta_ns: u64) {
    if let Some(cgroup) = try_lookup_cgroup(cgroup_id) {
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

/// J2-9: Force-charges `bytes` of kernel memory to a cgroup + every
/// MEMORY-controller ancestor WITHOUT rejecting on `memory.max` (saturating add
/// over the same chain `uncharge_memory` walks). This is the SOFT-cap charge for
/// the page-table-frame kmem allocated by `map_to`: that frame count is knowable
/// only AFTER the mapping is built (IM-14 "delta known only after the mutation ⇒
/// soft cap"), and the frames physically exist by then — so accounting must
/// record them even if they push `memory_current` transiently past `memory.max`.
/// The overshoot is bounded by ONE mmap's page-table delta (~1/512 of the data,
/// itself already capped by the HARD Phase-1 DATA gate) and the HARD gate on the
/// NEXT allocation re-enforces the limit. Thus this is the over-count-safe /
/// never-under-count direction — it cannot create a `memory.max` bypass (unlike a
/// reject-then-rollback, which would orphan the already-allocated PT frames
/// uncharged). Root cgroup (id 0) is NOT exempt: page-table memory is real kernel
/// memory and rides `memory.current` exactly like the DATA charge.
pub fn charge_memory_forced(cgroup_id: CgroupId, bytes: u64) {
    if bytes == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            // fetch_update (never fetch_add — lint-fetch-add) with a closure that
            // always returns Some never fails: an unconditional saturating add.
            let _ = cgroup.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| Some(current.saturating_add(bytes)),
            );
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// Atomically transfers cgroup memory charges from one cgroup to another.
///
/// R143-1 FIX: When a process is migrated between cgroups, its existing memory
/// charges must be transferred so that exit-time uncharge targets the correct
/// cgroup. Without this transfer, the source cgroup permanently leaks
/// `memory_current` and the destination under-counts, enabling `memory.max`
/// bypass.
///
/// R148-1 FIX: Charge-destination-first protocol. The previous uncharge-first
/// protocol could permanently lose charges when the destination charge failed
/// and the rollback re-charge also failed under contention (source cgroup's
/// freed budget consumed by concurrent allocators). The new protocol:
///
/// 1. Try to charge `bytes` to destination hierarchy
/// 2. Uncharge `bytes` from source hierarchy (saturating, cannot fail)
///
/// Shared ancestors are transiently over-counted (both source and destination
/// charged) but never under-counted. Over-count is safe (conservative); under-
/// count enables `memory.max` bypass.
///
/// # Errors
///
/// * `NotFound` - Source or target cgroup doesn't exist
/// * `MemoryLimitExceeded` - Destination cgroup (or ancestor) would exceed `memory.max`
pub fn migrate_memory_charges(
    bytes: u64,
    from_id: CgroupId,
    to_id: CgroupId,
) -> Result<(), CgroupError> {
    if bytes == 0 || from_id == to_id {
        return Ok(());
    }

    // Validate both cgroups exist. The returned Arc keeps them alive for the
    // duration of this function even without holding CGROUP_REGISTRY — the Arc
    // prevents deallocation even if a concurrent delete_cgroup removes them
    // from the registry. We intentionally do NOT hold the registry read lock
    // because uncharge_memory/try_charge_memory internally call lookup_cgroup
    // which acquires the same spin::RwLock, and spin::RwLock does not support
    // re-entrant readers on the same CPU (would deadlock on uniprocessor).
    let _from_arc = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let _to_arc = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    // Phase 1: Charge destination hierarchy first. If this fails (memory.max
    // exceeded), return error — source is unchanged, no rollback needed.
    try_charge_memory(to_id, bytes)?;

    // Phase 2: Uncharge source hierarchy (saturating, cannot fail).
    uncharge_memory(from_id, bytes);

    Ok(())
}

// ============================================================================
// J2-7: FILES Controller Integration (files.max enforcement)
// ============================================================================

/// Atomically charges `count` open file descriptors to a cgroup, enforcing
/// `files.max` hierarchically (target cgroup + every ancestor with the FILES
/// controller), mirroring `try_charge_memory` (CAS + ancestor rollback).
///
/// Root cgroup (id 0) is EXEMPT via the canonical id-based rule: root is created
/// with `CgroupControllers::all()`, so a controller-based exemption would NOT
/// skip it; the `cgroup_id == 0` short-circuit keeps root counters at 0
/// uniformly across all per-cgroup quota controllers.
///
/// # Errors
/// * `FdsLimitExceeded` - charging `count` would exceed `files.max` at this
///   cgroup or any ancestor. Nothing is charged: every partial charge is rolled
///   back before returning (fail-closed).
pub fn try_charge_fds(cgroup_id: CgroupId, count: u64) -> Result<(), CgroupError> {
    if count == 0 || cgroup_id == 0 {
        return Ok(());
    }

    // Collect the chain: target cgroup + ancestors with the FILES controller.
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    let mut chain: Vec<Arc<CgroupNode>> = Vec::new();
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::FILES) {
            chain.push(cgroup.clone());
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if chain.is_empty() {
        return Ok(()); // No FILES controller anywhere in the chain.
    }

    // Snapshot per-node limits (lock each briefly; never hold two at once).
    let limits_snapshot: Vec<Option<u64>> =
        chain.iter().map(|c| c.limits.lock().fds_max).collect();

    // Track charged indices for rollback on rejection at a deeper level.
    let mut charged: Vec<usize> = Vec::new();
    for (idx, cgroup) in chain.iter().enumerate() {
        let max = limits_snapshot[idx];
        match cgroup.stats.fds_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(count);
                if let Some(max) = max {
                    if new > max {
                        return None; // would exceed files.max
                    }
                }
                Some(new)
            },
        ) {
            Ok(_) => charged.push(idx),
            Err(_) => {
                cgroup.stats.record_fds_max_event();
                // R110-1 pattern: rollback previously charged levels (saturating).
                for &j in &charged {
                    chain[j].stats.decrement_fds(count);
                }
                return Err(CgroupError::FdsLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges `count` file descriptors from a cgroup (saturating at
/// zero), walking the same ancestor chain as `try_charge_fds`. Root (id 0) is
/// exempt. Called on fd close / cloexec / exec / process exit / migration.
pub fn uncharge_fds(cgroup_id: CgroupId, count: u64) {
    if count == 0 || cgroup_id == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::FILES) {
            cgroup.stats.decrement_fds(count);
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// Transfers `count` FD charges from one cgroup to another on task migration.
///
/// Charge-destination-first protocol (mirrors `migrate_memory_charges`, R148-1):
/// a failed destination charge leaves the source intact, so no charge is ever
/// lost. Shared ancestors are transiently over-counted but never under-counted
/// (over-count is safe; under-count would enable a `files.max` bypass).
///
/// The returned `Arc`s keep both nodes alive without holding `CGROUP_REGISTRY`
/// across the inner `try_charge_fds`/`uncharge_fds` calls (which re-`lookup`),
/// since `spin::RwLock` is not re-entrant on the same CPU.
///
/// # Errors
/// * `NotFound` - source or destination cgroup doesn't exist.
/// * `FdsLimitExceeded` - destination (or ancestor) would exceed `files.max`.
pub fn migrate_fd_charges(
    count: u64,
    from_id: CgroupId,
    to_id: CgroupId,
) -> Result<(), CgroupError> {
    if count == 0 || from_id == to_id {
        return Ok(());
    }
    let _from_arc = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let _to_arc = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    try_charge_fds(to_id, count)?; // destination first
    uncharge_fds(from_id, count); // source (saturating, cannot fail)
    Ok(())
}

// ============================================================================
// J2-8: NET controller — per-cgroup ephemeral-port budget (ports.max)
// ============================================================================

/// Atomically charges `count` ephemeral ports against a cgroup and its NET
/// ancestors, hierarchically enforcing `ports.max`. Root (id 0) is exempt.
///
/// This is the verbatim structural twin of `try_charge_fds` (FILES -> NET=0x20,
/// fds_* -> ports_*): it walks the target + ancestors carrying the NET
/// controller, snapshots each node's `ports_max`, then does a saturating
/// `fetch_update` per level and ROLLS BACK every already-charged level on the
/// first rejection (so a deep-ancestor cap never strands a charge at a shallower
/// level). Hierarchical by design: an ancestor's `ports_current` aggregates all
/// descendants' charges, so the leaf invariant "ports_current(leaf) == count of
/// live PortBinding entries charged to leaf" holds per-leaf and the uncharge
/// walks the SAME chain (symmetry).
///
/// # Lock context (J2-SHARED-CORE invariant, lock_ordering.rs)
/// Acquires CGROUP_REGISTRY (L5, via `lookup_cgroup`) + per-node `limits` (L5).
/// MUST NOT be called while any net-binding lock (L8) is held or from IRQ
/// context — the net layer resolves the cgroup and charges BEFORE taking a
/// binding lock, and routes every teardown uncharge through the process-context
/// deferred-uncharge drain.
///
/// # Errors
/// * `PortsLimitExceeded` - the target or an ancestor would exceed `ports.max`.
pub fn try_charge_ports(cgroup_id: CgroupId, count: u64) -> Result<(), CgroupError> {
    if count == 0 || cgroup_id == 0 {
        return Ok(());
    }

    // Collect the chain: target cgroup + ancestors with the NET controller.
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    let mut chain: Vec<Arc<CgroupNode>> = Vec::new();
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::NET) {
            chain.push(cgroup.clone());
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if chain.is_empty() {
        return Ok(()); // No NET controller anywhere in the chain.
    }

    // Snapshot per-node limits (lock each briefly; never hold two at once).
    let limits_snapshot: Vec<Option<u64>> =
        chain.iter().map(|c| c.limits.lock().ports_max).collect();

    // Track charged indices for rollback on rejection at a deeper level.
    let mut charged: Vec<usize> = Vec::new();
    for (idx, cgroup) in chain.iter().enumerate() {
        let max = limits_snapshot[idx];
        match cgroup.stats.ports_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(count);
                if let Some(max) = max {
                    if new > max {
                        return None; // would exceed ports.max
                    }
                }
                Some(new)
            },
        ) {
            Ok(_) => charged.push(idx),
            Err(_) => {
                cgroup.stats.record_ports_max_event();
                // Rollback previously charged levels (saturating, cannot fail).
                for &j in &charged {
                    chain[j].stats.decrement_ports(count);
                }
                return Err(CgroupError::PortsLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges `count` ephemeral ports from a cgroup (saturating at
/// zero), walking the same NET ancestor chain as `try_charge_ports`. Root (id 0)
/// is exempt. Called from the process-context deferred-uncharge drain and the
/// direct (close / connect-rollback) teardown sites — NEVER under a net-binding
/// lock or from IRQ.
///
/// "Uncharge what you charged": the net layer passes the STORED `charged_cgroup`
/// recorded in the `PortBinding` value at allocation time, never the current
/// task's cgroup (which may have migrated, or whose lookup would re-enter
/// PROCESS_TABLE on the exec/cloexec teardown path).
pub fn uncharge_ports(cgroup_id: CgroupId, count: u64) {
    if count == 0 || cgroup_id == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::NET) {
            cgroup.stats.decrement_ports(count);
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
    //
    // R143-4 NOTE: The return value from charge() is intentionally discarded.
    // A narrow TOCTOU race exists: an ancestor could transition to Throttled
    // between Phase 1 check and Phase 2 commit (due to a concurrent IO charge
    // on another CPU). If this occurs, one IO operation exceeds the throttle
    // deadline. This is self-correcting: the next charge_io() call will see
    // the throttle state and wait. The performance cost of full rollback +
    // retry outweighs the impact of a single leaked IO in this microsecond
    // race window.
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
                    cgroup.stats.io_read_bytes.fetch_add(bytes, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                    cgroup.stats.io_read_ios.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                }
                IoDirection::Write => {
                    cgroup.stats.io_write_bytes.fetch_add(bytes, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                    cgroup.stats.io_write_ios.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
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
    // R169-2 FIX (D1-CGROUP-IRQ-L5): on_clock_tick calls this in timer-IRQ
    // context (IRQs disabled), so the leaf lookup must be NON-blocking. Fail
    // CLOSED on registry contention — return a bounded throttle, identical to
    // the existing limits.try_lock() contention branch below (2589). This
    // preserves isolation (cpu.max can never be bypassed by inducing registry
    // contention) and self-corrects on the next tick. The ancestor walk uses
    // cgroup.parent() (Weak::upgrade, no registry), so only the entry lookup
    // changes.
    let mut cursor = match try_lookup_cgroup(cgroup_id) {
        Some(c) => Some(c),
        None => {
            return CpuQuotaStatus::Throttled(
                now_ns.saturating_add(LOCK_CONTENTION_THROTTLE_NS),
            );
        }
    };
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
                            quota.throttle_events.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
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
    // R169-2 FIX (D1-CGROUP-IRQ-L5): This is reached from select_next_locked
    // (the scheduler pick path) inside without_interrupts — a THIRD IRQ-off
    // registry reader the original finding missed. Use the non-blocking
    // try_lookup_cgroup; on registry contention it yields None, the walk is
    // skipped, and we return None (not throttled) — exactly this function's
    // already-documented conservative contended-limits behavior (the throttle
    // is detected on the next check). The ancestor walk uses parent()
    // (Weak::upgrade, no registry), so only the entry lookup changes.
    let mut cursor = try_lookup_cgroup(cgroup_id);
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
// J2-7: FILES Controller Self-Test (wired into the boot integration suite)
// ============================================================================

/// In-kernel assertions for the per-cgroup FD budget (`files.max`). Panics on any
/// failure, which `make test` / `make boot-check` detect via the serial log.
///
/// Covers: hierarchical cap enforcement (fail-closed) + ancestor rollback on a
/// deep-level rejection, ancestor propagation, the root `id==0` short-circuit
/// (a root-TARGETED charge is a no-op — note descendant charges still aggregate
/// at root per cgroup-v2 semantics), `migrate_fd_charges` balance across chains,
/// and saturating uncharge. Exercises `try_charge_fds`/`uncharge_fds` directly
/// (no real fd_table) so the engine is validated independently of syscall wiring.
pub fn run_cgroup_fd_budget_self_test() {
    let fds = |n: &Arc<CgroupNode>| n.stats.fds_current.load(Ordering::SeqCst);

    // Fresh, empty, task-less cgroups under root: A(fds_max=10) ⊃ B(fds_max=4),
    // plus sibling C(fds_max=20). Their counters start at 0 (isolated from any
    // real boot processes in root).
    let a = create_cgroup(0, CgroupControllers::FILES).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits { fds_max: Some(10), ..Default::default() })
        .expect("set A.files.max");
    let b = create_cgroup(a_id, CgroupControllers::FILES).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits { fds_max: Some(4), ..Default::default() })
        .expect("set B.files.max");
    let c = create_cgroup(0, CgroupControllers::FILES).expect("create C");
    let c_id = c.id();
    c.set_limit(CgroupLimits { fds_max: Some(20), ..Default::default() })
        .expect("set C.files.max");

    // 1) Charge 3 under B (within B's cap): B and ancestor A both increment.
    try_charge_fds(b_id, 3).expect("charge 3 under B");
    assert_eq!(fds(&b), 3, "B after charge 3");
    assert_eq!(fds(&a), 3, "A (ancestor) after charge 3 under B");

    // 2) Over B's cap (3+2 > 4) → FdsLimitExceeded, and A is NOT left over-charged
    //    (deep-level rejection rolls back the already-charged ancestor).
    assert_eq!(
        try_charge_fds(b_id, 2),
        Err(CgroupError::FdsLimitExceeded),
        "B over-cap must fail-closed"
    );
    assert_eq!(fds(&b), 3, "B unchanged after rejected charge");
    assert_eq!(fds(&a), 3, "A rolled back after B rejection");

    // 3) Charge exactly to B's cap.
    try_charge_fds(b_id, 1).expect("charge 1 to B's cap");
    assert_eq!(fds(&b), 4, "B at cap");
    assert_eq!(fds(&a), 4, "A after B at cap");

    // 4) Root id==0 short-circuit: a root-TARGETED charge changes nothing.
    let root = lookup_cgroup(0).expect("root");
    let root_before = root.stats.fds_current.load(Ordering::SeqCst);
    try_charge_fds(0, 100).expect("root-targeted charge is Ok");
    uncharge_fds(0, 100);
    assert_eq!(
        root.stats.fds_current.load(Ordering::SeqCst),
        root_before,
        "root id=0 charge/uncharge are no-ops"
    );

    // 5) migrate_fd_charges B -> C: move the 4 fds. B's chain (B, A) drops by 4;
    //    C's chain (C) gains 4. (Both chains share root, so root nets 0.)
    migrate_fd_charges(4, b_id, c_id).expect("migrate B->C");
    assert_eq!(fds(&b), 0, "B drained after migrate");
    assert_eq!(fds(&a), 0, "A (B's ancestor) drained after migrate");
    assert_eq!(fds(&c), 4, "C charged after migrate");

    // 6) Saturating uncharge: uncharging more than charged floors at 0.
    uncharge_fds(c_id, 999);
    assert_eq!(fds(&c), 0, "C saturates at 0");

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(a_id);
    let _ = delete_cgroup(c_id);
}

/// J2-8: in-kernel self-test for the per-cgroup ephemeral-port budget ARITHMETIC
/// (NET controller, ports.max): hierarchical charge, deep-rejection rollback of
/// the already-charged ancestor, root id==0 exemption, and saturating uncharge.
/// Mirrors the FILES test minus migration — port charges deliberately do NOT
/// migrate on cgroup_attach (they stick to the alloc-time cgroup via
/// "uncharge what you charged"; the net-side MECHANISM is tested in
/// `net::SocketTable::run_per_cgroup_port_budget_self_test`).
pub fn run_cgroup_ports_budget_self_test() {
    let ports = |n: &Arc<CgroupNode>| n.stats.ports_current.load(Ordering::SeqCst);

    // Fresh, task-less NET cgroups under root: A(ports_max=10) ⊃ B(ports_max=4).
    let a = create_cgroup(0, CgroupControllers::NET).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits { ports_max: Some(10), ..Default::default() })
        .expect("set A.ports.max");
    let b = create_cgroup(a_id, CgroupControllers::NET).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits { ports_max: Some(4), ..Default::default() })
        .expect("set B.ports.max");

    // 1) Charge 3 under B (within cap): B and ancestor A both increment.
    try_charge_ports(b_id, 3).expect("charge 3 under B");
    assert_eq!(ports(&b), 3, "B after charge 3");
    assert_eq!(ports(&a), 3, "A (ancestor) after charge 3 under B");

    // 2) Over B's cap (3+2 > 4) -> PortsLimitExceeded; A is NOT left over-charged
    //    (deep-level rejection rolls back the already-charged ancestor).
    assert_eq!(
        try_charge_ports(b_id, 2),
        Err(CgroupError::PortsLimitExceeded),
        "B over-cap must fail-closed"
    );
    assert_eq!(ports(&b), 3, "B unchanged after rejected charge");
    assert_eq!(ports(&a), 3, "A rolled back after B rejection");

    // 3) Charge exactly to B's cap.
    try_charge_ports(b_id, 1).expect("charge 1 to B's cap");
    assert_eq!(ports(&b), 4, "B at cap");
    assert_eq!(ports(&a), 4, "A after B at cap");

    // 4) Root id==0 short-circuit: a root-TARGETED charge/uncharge is a no-op.
    let root = lookup_cgroup(0).expect("root");
    let root_before = root.stats.ports_current.load(Ordering::SeqCst);
    try_charge_ports(0, 100).expect("root-targeted charge is Ok");
    uncharge_ports(0, 100);
    assert_eq!(
        root.stats.ports_current.load(Ordering::SeqCst),
        root_before,
        "root id=0 port charge/uncharge are no-ops"
    );

    // 5) Uncharge what you charged: drop B's 4 — B and ancestor A both decrement.
    uncharge_ports(b_id, 4);
    assert_eq!(ports(&b), 0, "B drained");
    assert_eq!(ports(&a), 0, "A (B's ancestor) drained");

    // 6) Saturating uncharge: over-uncharge floors at 0 (never wraps).
    uncharge_ports(b_id, 999);
    assert_eq!(ports(&b), 0, "B saturates at 0");

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(a_id);
}

/// J2-9: in-kernel self-test for the page-table-frame kmem accounting. The pt
/// charge rides the MEMORY controller (try_charge_memory / uncharge_memory /
/// migrate_memory_charges) EXACTLY like the mmap DATA charge, so this exercises
/// those primitives over the same hierarchy / migration / exit / fork balance
/// points that sys_mmap's pt charge, compute_cgroup_charged_bytes (migration),
/// free_process_resources (exit), and fork_inner (fork) depend on — including the
/// INV-5 trap that the MEMORY controller (unlike files/ports/vfs_dir) does NOT
/// exempt the root cgroup. Root counters carry live boot charges, so root
/// assertions use DELTAS; fresh task-less children start at 0 (absolute).
pub fn run_cgroup_pt_kmem_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &Arc<CgroupNode>| n.stats.memory_current.load(Ordering::SeqCst);

    // Fresh, empty, task-less MEMORY cgroups under root:
    // A(memory.max=64 pages) ⊃ B(memory.max=8 pages), sibling C(memory.max=64 pages).
    let a = create_cgroup(0, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits { memory_max: Some(64 * PAGE), ..Default::default() })
        .expect("set A.memory.max");
    let b = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits { memory_max: Some(8 * PAGE), ..Default::default() })
        .expect("set B.memory.max");
    let c = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create C");
    let c_id = c.id();
    c.set_limit(CgroupLimits { memory_max: Some(64 * PAGE), ..Default::default() })
        .expect("set C.memory.max");

    // 1) FORCED PT charge + ANCESTOR propagation. charge_memory_forced is how
    //    sys_mmap records the page-table-frame kmem (the frame count is known only
    //    AFTER map_to runs ⇒ soft cap per IM-14). Charge 6 PT pages under B.
    charge_memory_forced(b_id, 6 * PAGE);
    assert_eq!(mem(&b), 6 * PAGE, "B after forced PT charge");
    assert_eq!(mem(&a), 6 * PAGE, "A (ancestor) after forced PT charge under B");

    // 2) SOFT overshoot: a forced PT charge NEVER rejects, even past memory.max.
    //    6 + 4 = 10 > B.max(8) is ALLOWED — the frames physically exist, and
    //    over-count is the safe direction (bounded by one mmap's tiny pt delta in
    //    practice). Both B and the ancestor A rise.
    charge_memory_forced(b_id, 4 * PAGE);
    assert_eq!(mem(&b), 10 * PAGE, "B forced past memory.max (soft, over-count-safe)");
    assert_eq!(mem(&a), 10 * PAGE, "A after forced overshoot under B");

    // 3) The HARD gate RE-ENFORCES on the NEXT data-style allocation: now that B is
    //    over its max, try_charge_memory (the Phase-1 DATA gate) rejects — so the
    //    soft pt overshoot cannot be parlayed into an unbounded bypass.
    assert_eq!(
        try_charge_memory(b_id, PAGE),
        Err(CgroupError::MemoryLimitExceeded),
        "hard DATA gate re-enforces memory.max after pt overshoot",
    );
    assert_eq!(mem(&b), 10 * PAGE, "B unchanged after rejected hard charge");

    // 4) ROOT NOT EXEMPT (INV-5 trap): unlike files/ports/vfs_dir, the MEMORY
    //    controller charges the root cgroup. A root-targeted forced charge MUST
    //    move root.memory_current — asserted via delta (root carries live charges).
    let root = lookup_cgroup(0).expect("root");
    let root_before = mem(&root);
    charge_memory_forced(0, 5 * PAGE);
    assert_eq!(mem(&root), root_before + 5 * PAGE, "root IS charged (no exemption)");
    uncharge_memory(0, 5 * PAGE);
    assert_eq!(mem(&root), root_before, "root PT uncharge restores baseline");

    // 5) MIGRATION TRANSFER (compute_cgroup_charged_bytes path): move B's 10 PT
    //    pages B → C. B's chain (B, A) drops by 10; C's chain (C, A) gains 10. The
    //    shared ancestor A nets 0; B ends at 0, C ends at 10.
    migrate_memory_charges(10 * PAGE, b_id, c_id).expect("migrate PT B→C");
    assert_eq!(mem(&b), 0, "B drained after PT migrate");
    assert_eq!(mem(&c), 10 * PAGE, "C charged after PT migrate");
    assert_eq!(mem(&a), 10 * PAGE, "A (shared ancestor) net unchanged by sibling migrate");

    // 6) EXIT BALANCE: last-exit uncharge of C's PT returns the chain to baseline.
    uncharge_memory(c_id, 10 * PAGE);
    assert_eq!(mem(&c), 0, "C drained after exit uncharge");
    assert_eq!(mem(&a), 0, "A drained after C exit uncharge");

    // 7) FORK == EXIT balance (per-process +X / -X): fork charges the inherited
    //    child PT to the PARENT cgroup with the HARD gate (the value is known
    //    pre-fork ⇒ hard per IM-14); the child's last-exit uncharge cancels it.
    try_charge_memory(a_id, 6 * PAGE).expect("fork: charge inherited child PT to parent cgroup");
    assert_eq!(mem(&a), 6 * PAGE, "A after fork PT charge");
    uncharge_memory(a_id, 6 * PAGE); // child last-exit
    assert_eq!(mem(&a), 0, "A back to baseline: fork PT charge cancelled by child exit");

    // 8) SATURATING uncharge: over-uncharge floors at 0 (never drives memory_current
    //    below true usage → never a downstream memory.max bypass).
    uncharge_memory(a_id, 999 * PAGE);
    assert_eq!(mem(&a), 0, "A saturates at 0 on over-uncharge");

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(c_id);
    let _ = delete_cgroup(a_id);
}

// ============================================================================
// J2-10: VFS Directory-Enumeration Budget (vfs_dir.max, MEMORY controller)
// ============================================================================

/// Minimum bytes a single directory-enumeration syscall is granted even when the
/// cgroup's `vfs_dir.max` headroom is below it, so enumeration always makes
/// forward progress (never a false end-of-directory). The resulting over-count
/// is bounded by (concurrent getdents in the cgroup) × this value — safe, since
/// over-count restricts further, it never bypasses (Safety > Efficiency).
pub const MIN_VFS_DIR_BUDGET: usize = 4096;

/// RAII budget for ONE directory-enumeration syscall (`getdents64`). Charges
/// `vfs_dir_current` on the target cgroup + every MEMORY-controller ancestor at
/// construction, and uncharges the SAME held `Arc<CgroupNode>` set on drop —
/// NEVER re-resolving the registry. Because the held Arcs keep each charged node
/// alive past `delete_cgroup` (which only removes the node from the registry and
/// its parent's child list — the object survives while an Arc exists, see
/// `migrate_memory_charges`), the uncharge-set == charge-set BY CONSTRUCTION:
/// migration- AND deletion-safe with no transfer needed (J2-10 mustFix A). The
/// cap is HARD (per-node CAS reservation, not a read-then-add soft cap, so
/// concurrent chargers cannot overshoot `vfs_dir.max`); it still degrades
/// gracefully by GRANTING the largest amount that fits (a getdents64 short read)
/// instead of failing the syscall. The only bounded over-count is a small
/// progress `floor` granted when the cgroup is already at its cap, so enumeration
/// never deadlocks — over-count restricts further, it never bypasses.
///
/// SCOPE: this bounds the per-tenant ACCUMULATED getdents64 kernel buffer (the
/// `entries` Vec + per-entry serialization, held across the syscall) — the
/// dominant, sustained, tenant-controllable allocation. A backend's TRANSIENT
/// per-`readdir(offset)` internal scratch (e.g. procfs rebuilding a PID listing)
/// is freed each call, is pre-existing, and is a separate cross-filesystem
/// concern not addressed here.
#[must_use = "the guard must outlive the directory enumeration it bounds"]
pub struct VfsDirBudgetGuard {
    chain: Vec<Arc<CgroupNode>>,
    bytes: u64,
    granted: usize,
}

impl VfsDirBudgetGuard {
    /// Charge up to `want` bytes, clamped to the tightest `vfs_dir.max` headroom
    /// in the chain but never below `min(MIN_VFS_DIR_BUDGET, want)` (bounded
    /// over-count for forward progress) and never above `want`. Root cgroup
    /// (id 0) is EXEMPT: no charge, full `want` granted. MUST be called with NO
    /// Process lock held — it acquires CGROUP_REGISTRY (Level 5).
    pub fn charge(cgroup_id: CgroupId, want: usize) -> Self {
        if cgroup_id == 0 || want == 0 {
            return Self { chain: Vec::new(), bytes: 0, granted: want };
        }
        // Collect target + ancestors with the MEMORY controller.
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
            return Self { chain, bytes: 0, granted: want };
        }
        let want_u = want as u64;
        let floor = (MIN_VFS_DIR_BUDGET as u64).min(want_u);
        // Snapshot each node's vfs_dir.max once (None = unlimited).
        let caps: Vec<Option<u64>> = chain.iter().map(|n| n.limits.lock().vfs_dir_max).collect();

        // HARD reservation (NOT a soft read-then-add): grant the largest amount in
        // [floor, want] that fits EVERY node's vfs_dir.max right now, charged
        // atomically per node via CAS so concurrent chargers cannot all observe the
        // same headroom and overshoot (that would make the cap advisory, defeating
        // the memory bound). On a per-node CAS rejection (a concurrent charger
        // shrank the headroom between read and commit) roll back and retry a bounded
        // number of times. Fallback: when not even `floor` fits, force `floor` so
        // enumeration still makes forward progress — a BOUNDED over-count (≤ floor
        // per concurrent call) that restricts further, never bypasses.
        for _attempt in 0..4 {
            let mut headroom: u64 = u64::MAX;
            for (i, node) in chain.iter().enumerate() {
                if let Some(max) = caps[i] {
                    let cur = node.stats.vfs_dir_current.load(Ordering::Acquire);
                    headroom = headroom.min(max.saturating_sub(cur));
                }
            }
            if headroom < floor {
                for node in &chain {
                    node.stats.vfs_dir_current.fetch_add(floor, Ordering::SeqCst); // lint-fetch-add: allow (statistics counter)
                }
                return Self { chain, bytes: floor, granted: floor as usize };
            }
            let grant = want_u.min(headroom); // in [floor, want]
            let mut charged: Vec<usize> = Vec::new();
            let mut committed = true;
            for (i, node) in chain.iter().enumerate() {
                let max = caps[i];
                let res = node.stats.vfs_dir_current.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |cur| {
                        let new = cur.saturating_add(grant);
                        if let Some(m) = max {
                            if new > m {
                                return None; // would exceed vfs_dir.max
                            }
                        }
                        Some(new)
                    },
                );
                if res.is_ok() {
                    charged.push(i);
                } else {
                    committed = false;
                    break;
                }
            }
            if committed {
                return Self { chain, bytes: grant, granted: grant as usize };
            }
            // Roll back the partial reservation (saturating) and retry.
            for &i in &charged {
                let _ = chain[i].stats.vfs_dir_current.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(grant)),
                );
            }
        }
        // Retries exhausted under pathological contention. One FINAL attempt to
        // reserve exactly `floor` honoring the cap (CAS) — so the forced path
        // below is taken ONLY when not even `floor` fits, matching the design.
        let mut charged: Vec<usize> = Vec::new();
        let mut committed = true;
        for (i, node) in chain.iter().enumerate() {
            let max = caps[i];
            let res = node.stats.vfs_dir_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |cur| {
                    let new = cur.saturating_add(floor);
                    if let Some(m) = max {
                        if new > m {
                            return None;
                        }
                    }
                    Some(new)
                },
            );
            if res.is_ok() {
                charged.push(i);
            } else {
                committed = false;
                break;
            }
        }
        if committed {
            return Self { chain, bytes: floor, granted: floor as usize };
        }
        for &i in &charged {
            let _ = chain[i].stats.vfs_dir_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |c| Some(c.saturating_sub(floor)),
            );
        }
        // Even `floor` does not fit under the cap → force it (bounded over-count
        // ≤ floor per concurrent call) so enumeration still makes forward progress.
        for node in &chain {
            node.stats.vfs_dir_current.fetch_add(floor, Ordering::SeqCst); // lint-fetch-add: allow (statistics counter)
        }
        Self { chain, bytes: floor, granted: floor as usize }
    }

    /// The byte budget granted to the caller (use as the readdir allocation cap).
    #[inline]
    pub fn granted(&self) -> usize {
        self.granted
    }

    /// Idempotently uncharge the held chain (saturating). Safe to call repeatedly
    /// — a second call (or Drop after an explicit release) uncharges nothing.
    pub fn release(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let bytes = self.bytes;
        self.bytes = 0;
        for node in &self.chain {
            let _ = node.stats.vfs_dir_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |cur| Some(cur.saturating_sub(bytes)),
            );
        }
    }
}

impl Drop for VfsDirBudgetGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// In-kernel assertions for the per-cgroup VFS dir-enumeration budget. Panics on
/// failure; detected by `make test` / `make boot-check` via the serial log.
///
/// Covers: cap clamping (granted reduced to headroom, short read), ancestor
/// propagation, the headline DELETION-SAFETY property (charge under a leaf, then
/// delete the leaf, then drop the guard → the ancestor counter still returns to
/// 0 because the guard uncharges the held Arcs, not a re-resolved id), root
/// id==0 exemption, and release idempotency.
pub fn run_cgroup_vfs_dir_budget_self_test() {
    let vdir = |n: &Arc<CgroupNode>| n.stats.vfs_dir_current.load(Ordering::SeqCst);

    // P(vfs_dir_max=10000) ⊃ A(vfs_dir_max unlimited): fresh, task-less.
    let p = create_cgroup(0, CgroupControllers::MEMORY).expect("create P");
    let p_id = p.id();
    p.set_limit(CgroupLimits { vfs_dir_max: Some(10_000), ..Default::default() })
        .expect("set P.vfs_dir_max");
    let a = create_cgroup(p_id, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();

    // 1) Charge 3000 under A: A and ancestor P both reflect it; granted == want.
    {
        let g = VfsDirBudgetGuard::charge(a_id, 3000);
        assert_eq!(g.granted(), 3000, "full grant within headroom");
        assert_eq!(vdir(&a), 3000, "A vfs_dir_current");
        assert_eq!(vdir(&p), 3000, "P (ancestor) vfs_dir_current");
    } // guard drops → uncharge
    assert_eq!(vdir(&a), 0, "A uncharged on drop");
    assert_eq!(vdir(&p), 0, "P uncharged on drop");

    // 2) Cap clamping: want 50000 but P.headroom is 10000 → granted 10000 (short read).
    {
        let g = VfsDirBudgetGuard::charge(a_id, 50_000);
        assert_eq!(g.granted(), 10_000, "granted clamped to P's headroom");
        assert_eq!(vdir(&p), 10_000, "P at cap");
    }
    assert_eq!(vdir(&p), 0, "P back to 0 after clamped guard drop");

    // 3) DELETION SAFETY: charge under A, delete A, then drop the guard — the
    //    ancestor P counter MUST still return to 0 (guard uncharges held Arcs).
    {
        let g = VfsDirBudgetGuard::charge(a_id, 2000);
        assert_eq!(vdir(&p), 2000, "P charged via A");
        // Delete A out from under the live guard (no tasks/children on A).
        let _ = delete_cgroup(a_id);
        assert!(lookup_cgroup(a_id).is_none(), "A removed from registry");
        // g drops here → uncharges the HELD [A_arc, P_arc], not lookup(a_id).
    }
    assert_eq!(vdir(&p), 0, "P uncharged despite A deletion (Arc-pinned uncharge)");

    // 4) Root id==0 exemption: no charge, full grant.
    {
        let root = lookup_cgroup(0).expect("root");
        let before = root.stats.vfs_dir_current.load(Ordering::SeqCst);
        let g = VfsDirBudgetGuard::charge(0, 1234);
        assert_eq!(g.granted(), 1234, "root grants full want");
        assert_eq!(
            root.stats.vfs_dir_current.load(Ordering::SeqCst),
            before,
            "root id=0 not charged"
        );
    }

    // 5) Release idempotency: explicit release then Drop uncharges only once.
    {
        let mut g = VfsDirBudgetGuard::charge(p_id, 1000);
        assert_eq!(vdir(&p), 1000);
        g.release();
        assert_eq!(vdir(&p), 0, "released");
        g.release(); // no-op
        assert_eq!(vdir(&p), 0, "double release is a no-op");
    } // Drop after release → also a no-op
    assert_eq!(vdir(&p), 0, "no underflow after release+drop");

    let _ = delete_cgroup(p_id);
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Returns true if the cgroup subsystem is initialized.
#[cfg(test)]
pub fn test_is_initialized() -> bool {
    CGROUP_REGISTRY.read().contains_key(&0)
}
