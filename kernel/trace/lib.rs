//! Kernel Observability Infrastructure for Zero-OS
//!
//! Phase G.1 observability subsystem providing:
//!
//! - **Static Tracepoints**: Compile-time registered probe points that can be
//!   enabled/disabled at runtime with zero cost when disabled (single atomic load).
//! - **Per-CPU Counters**: Lock-free, IRQ-safe kernel metrics aggregated on demand.
//! - **Hung-Task Watchdog**: Per-task heartbeat monitoring with configurable timeouts
//!   and automatic tracepoint emission on overdue tasks.
//!
//! # Security Model
//!
//! - **Read Guard**: A pluggable capability/LSM check gates all metric export paths
//!   (counter snapshots, tracepoint listings, watchdog status). Install via
//!   [`install_read_guard`] during boot to enforce `CAP_TRACE_READ` or equivalent.
//! - **No Info Leaks**: Trace arguments are bounded ([`TRACE_ARGS_MAX`]) and must
//!   be explicitly provided by the emitter; no kernel pointers are automatically
//!   included. Consumers (e.g., procfs) decide formatting and redaction policy.
//! - **IRQ Safety**: Counter increments and watchdog heartbeats are lock-free
//!   atomics safe to call from any context including IRQ handlers.
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                    Tracepoint Registry                            |
//! |  +------------------+  +------------------+  +------------------+ |
//! |  | sched.switch     |  | syscall.entry    |  | watchdog.hung    | |
//! |  | enabled: false   |  | enabled: false   |  | enabled: true    | |
//! |  | sink: None       |  | sink: None       |  | sink: log_fn     | |
//! |  +------------------+  +------------------+  +------------------+ |
//! +------------------------------------------------------------------+
//!
//! +------------------------------------------------------------------+
//! |                    Per-CPU Counters                               |
//! |  CPU 0: [syscall=142, faults=3, ipc=50, switches=88, ...]        |
//! |  CPU 1: [syscall=97,  faults=1, ipc=33, switches=72, ...]        |
//! |  CPU 2: [syscall=120, faults=0, ipc=41, switches=95, ...]        |
//! +------------------------------------------------------------------+
//!
//! +------------------------------------------------------------------+
//! |                    Watchdog Table                                 |
//! |  Slot 0: task=1  timeout=5000ms  last_seen=12340ms  ok           |
//! |  Slot 1: task=5  timeout=3000ms  last_seen=9200ms   OVERDUE      |
//! |  Slot 2: (empty)                                                  |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // During kernel boot:
//! trace::init();
//!
//! // Hot path (lock-free):
//! trace::increment_counter(TraceCounter::SyscallEntry, 1);
//!
//! // Watchdog registration:
//! let handle = trace::register_watchdog(WatchdogConfig {
//!     task_id: pid as u64,
//!     timeout_ms: 5000,
//! }, now_ms)?;
//!
//! // Periodic poll from timer tick:
//! trace::poll_watchdogs(now_ms);
//!
//! // Guarded export:
//! let snapshot = trace::snapshot_counters()?;
//! ```

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

pub mod counters;
pub mod profiler;
pub mod watchdog;

// Re-export public API
pub use counters::{
    counter_name, increment_counter, reset_counter, snapshot_counters, CpuCounterSnapshot,
    TraceCounter, TraceCounterSnapshot, TRACE_COUNTER_COUNT,
};
pub use profiler::{
    profiler_enabled, record_pc_sample, snapshot_profiler, start_profiler, stop_profiler,
    ProfilerSample, ProfilerSnapshot, PROFILER_RING_CAPACITY,
};
pub use watchdog::{
    heartbeat, poll_watchdogs, register_watchdog, snapshot_watchdogs, unregister_watchdog,
    WatchdogConfig, WatchdogError, WatchdogEvent, WatchdogHandle, TRACE_WATCHDOG_HANG,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of arguments carried by a single trace record.
///
/// Bounded to prevent unbounded stack usage in the emit path and to
/// limit the information surface available through tracepoints.
pub const TRACE_ARGS_MAX: usize = 6;

/// Maximum number of statically registered tracepoints.
///
/// This is a compile-time limit to avoid heap allocation in the registry.
/// Increase if more subsystems need tracepoints.
pub const MAX_TRACEPOINTS: usize = 64;

// ============================================================================
// Types
// ============================================================================

/// Fixed-size argument array for trace records.
pub type TraceArgs = [u64; TRACE_ARGS_MAX];

/// Callback invoked when an enabled tracepoint fires.
///
/// Sinks must be safe to call from any context (including IRQ).
/// The sink receives an immutable reference to the fully materialized record.
pub type TraceSink = fn(&TraceRecord);

/// Guard function for gating metric/tracepoint reads.
///
/// Returns `true` if the caller is authorized (e.g., has `CAP_TRACE_READ`).
/// Returns `false` to deny access (results in [`TraceError::AccessDenied`]).
pub type TraceGuardFn = fn() -> bool;

/// Tracepoint identifier.
///
/// Opaque 32-bit value. Ranges:
/// - `0x0000..0x0FFF`: Reserved for built-in kernel tracepoints
/// - `0x1000..0x1FFF`: Watchdog subsystem
/// - `0x2000..0xFFFF`: Available for subsystem/module use
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TraceId(pub u32);

impl TraceId {
    /// Construct a new trace ID.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }
}

/// Coarse category for filtering and routing trace records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceCategory {
    /// Scheduler events (context switch, migration, load balance).
    Sched = 0,
    /// System call entry/exit/denial.
    Syscall = 1,
    /// Memory management (page fault, mmap, OOM).
    Memory = 2,
    /// Inter-process communication (pipe, futex, signal).
    Ipc = 3,
    /// Network stack events (TCP, UDP, ICMP).
    Net = 4,
    /// Watchdog/health monitoring events.
    Watchdog = 5,
    /// Storage/VFS events.
    Storage = 6,
    /// Security events (LSM denial, capability check).
    Security = 7,
    /// Module-defined custom events.
    Custom = 255,
}

/// Fully materialized trace record delivered to sink callbacks.
///
/// Records are constructed on the stack in the emit path and passed
/// by reference to sinks. They are not heap-allocated.
#[derive(Clone, Debug)]
pub struct TraceRecord {
    /// Tracepoint that fired.
    pub id: TraceId,
    /// Category for filtering.
    pub category: TraceCategory,
    /// Human-readable tracepoint name.
    pub name: &'static str,
    /// Monotonic timestamp (milliseconds since boot).
    pub timestamp: u64,
    /// CPU on which the event occurred.
    pub cpu: usize,
    /// Argument values (first `arg_count` entries are valid).
    pub args: TraceArgs,
    /// Number of valid arguments in `args`.
    pub arg_count: u8,
    /// Field names corresponding to argument positions.
    pub fields: &'static [&'static str],
}

/// Public metadata for listing registered tracepoints.
#[derive(Clone, Debug)]
pub struct TracepointInfo {
    /// Tracepoint identifier.
    pub id: TraceId,
    /// Human-readable name.
    pub name: &'static str,
    /// Event category.
    pub category: TraceCategory,
    /// Field name descriptors.
    pub fields: &'static [&'static str],
    /// Whether currently enabled.
    pub enabled: bool,
}

/// Errors from trace infrastructure control paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceError {
    /// Tracepoint registry is full ([`MAX_TRACEPOINTS`] reached).
    RegistryFull,
    /// A tracepoint with the same ID is already registered.
    DuplicateId,
    /// More than [`TRACE_ARGS_MAX`] arguments provided to emit.
    TooManyArgs,
    /// Tracepoint ID not found in registry.
    NotFound,
    /// A sink callback is already installed for this tracepoint.
    CallbackAlreadySet,
    /// The read guard denied access.
    AccessDenied,
    /// A read guard has already been installed.
    GuardAlreadyInstalled,
}

// ============================================================================
// Tracepoint
// ============================================================================

/// Static tracepoint descriptor.
///
/// Tracepoints are created at compile time via [`declare_tracepoint!`] and
/// registered during boot via [`register_tracepoint`]. They start disabled
/// and can be toggled at runtime.
///
/// # Performance
///
/// When disabled, [`emit`](Tracepoint::emit) performs a single `Acquire` load
/// and returns immediately. When enabled but no sink is installed, the counter
/// is incremented but no callback overhead is incurred.
pub struct Tracepoint {
    /// Unique identifier.
    pub id: TraceId,
    /// Human-readable name (e.g., "sched.context_switch").
    pub name: &'static str,
    /// Category for downstream filtering.
    pub category: TraceCategory,
    /// Field name metadata for argument positions.
    pub fields: &'static [&'static str],
    /// Runtime enable/disable flag.
    enabled: core::sync::atomic::AtomicBool,
    /// Optional sink callback (stored as raw bits, R89-3 CHERI/MPK-safe).
    callback: AtomicUsize,
}

// Safety: Tracepoint fields are all atomics or static references
unsafe impl Send for Tracepoint {}
unsafe impl Sync for Tracepoint {}

impl Tracepoint {
    /// Create a new static tracepoint descriptor.
    ///
    /// Tracepoints start disabled with no sink callback.
    pub const fn new(
        id: TraceId,
        name: &'static str,
        category: TraceCategory,
        fields: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            name,
            category,
            fields,
            enabled: core::sync::atomic::AtomicBool::new(false),
            callback: AtomicUsize::new(0), // R89-3: Use usize bits, not pointer
        }
    }

    /// Enable this tracepoint.
    #[inline]
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable this tracepoint.
    #[inline]
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Check if this tracepoint is currently enabled.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Install a sink callback for this tracepoint.
    ///
    /// Only one sink per tracepoint is supported. Use CAS to prevent races
    /// between concurrent installers.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::CallbackAlreadySet`] if a callback is already installed.
    pub fn install_callback(&self, cb: TraceSink) -> Result<(), TraceError> {
        // R89-3 FIX: Store function pointer as raw bits (usize), not data pointer
        let raw = cb as usize;
        // CAS: only install if currently zero (no existing callback)
        match self.callback.compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(_) => Err(TraceError::CallbackAlreadySet),
        }
    }

    /// Remove the sink callback. The tracepoint remains enabled/disabled as-is.
    pub fn clear_callback(&self) {
        self.callback.store(0, Ordering::Release);
    }

    /// Load the current callback, if any.
    #[inline]
    fn callback(&self) -> Option<TraceSink> {
        let raw = self.callback.load(Ordering::Acquire);
        if raw == 0 {
            None
        } else {
            // R89-3 FIX: Transmute from usize (not data pointer) to fn pointer
            // Safety: value originated from a valid `TraceSink` fn pointer
            Some(unsafe { core::mem::transmute::<usize, TraceSink>(raw) })
        }
    }

    /// Emit a trace record if this tracepoint is enabled.
    ///
    /// This is the hot-path entry point. When disabled, this performs a single
    /// atomic load and returns immediately with `Ok(())`.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Monotonic timestamp (typically from `time::current_timestamp_ms()`)
    /// * `args` - Slice of argument values (max [`TRACE_ARGS_MAX`])
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::TooManyArgs`] if `args.len() > TRACE_ARGS_MAX`.
    /// The record is dropped and the dropped counter is incremented.
    pub fn emit(&self, timestamp: u64, args: &[u64]) -> Result<(), TraceError> {
        // Fast path: single atomic load when disabled
        if !self.is_enabled() {
            return Ok(());
        }

        if args.len() > TRACE_ARGS_MAX {
            counters::increment_counter(counters::TraceCounter::TracepointsDropped, 1);
            return Err(TraceError::TooManyArgs);
        }

        // Build record on stack (no heap allocation)
        let mut buf = [0u64; TRACE_ARGS_MAX];
        buf[..args.len()].copy_from_slice(args);

        let record = TraceRecord {
            id: self.id,
            category: self.category,
            name: self.name,
            timestamp,
            cpu: cpu_local::current_cpu_id(),
            args: buf,
            arg_count: args.len() as u8,
            fields: self.fields,
        };

        // Invoke sink if installed
        if let Some(cb) = self.callback() {
            cb(&record);
        }

        counters::increment_counter(counters::TraceCounter::TracepointsEmitted, 1);
        Ok(())
    }
}

// ============================================================================
// Tracepoint Registry
// ============================================================================

/// Internal registry of statically registered tracepoints.
struct TraceRegistry {
    slots: [Option<&'static Tracepoint>; MAX_TRACEPOINTS],
}

impl TraceRegistry {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_TRACEPOINTS],
        }
    }

    fn insert(&mut self, tp: &'static Tracepoint) -> Result<(), TraceError> {
        // Check for duplicate ID
        if self
            .slots
            .iter()
            .flatten()
            .any(|existing| existing.id == tp.id)
        {
            return Err(TraceError::DuplicateId);
        }

        // Find first empty slot
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(tp);
                return Ok(());
            }
        }
        Err(TraceError::RegistryFull)
    }

    fn find(&self, id: TraceId) -> Option<&'static Tracepoint> {
        self.slots.iter().flatten().find(|tp| tp.id == id).copied()
    }

    fn list(&self) -> Vec<TracepointInfo> {
        let mut out = Vec::new();
        for tp in self.slots.iter().flatten() {
            out.push(TracepointInfo {
                id: tp.id,
                name: tp.name,
                category: tp.category,
                fields: tp.fields,
                enabled: tp.is_enabled(),
            });
        }
        out
    }
}

static TRACE_REGISTRY: Mutex<TraceRegistry> = Mutex::new(TraceRegistry::new());

/// Read guard for gating metric export paths.
///
/// When installed, all snapshot/listing functions call the guard before
/// returning data. If the guard returns false, [`TraceError::AccessDenied`]
/// is returned.
/// R89-3: Store as usize (raw bits) for CHERI/MPK compatibility.
static READ_GUARD: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Install a read guard for metric export paths.
///
/// The guard function is called before returning counter snapshots,
/// tracepoint listings, or watchdog status. If it returns `false`,
/// the caller receives [`TraceError::AccessDenied`].
///
/// Typically installed during boot to enforce `CAP_TRACE_READ`:
///
/// ```rust,ignore
/// trace::install_read_guard(|| {
///     current_credentials().map_or(false, |c| c.euid == 0)
/// });
/// ```
///
/// # Errors
///
/// Returns [`TraceError::GuardAlreadyInstalled`] if a guard is already set.
pub fn install_read_guard(guard: TraceGuardFn) -> Result<(), TraceError> {
    // R89-3 FIX: Store function pointer as raw bits (usize), not data pointer
    let raw = guard as usize;
    match READ_GUARD.compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(_) => Err(TraceError::GuardAlreadyInstalled),
    }
}

/// Check the read guard allows access. Returns Ok if no guard is installed
/// or the guard returns true.
pub(crate) fn ensure_metrics_read_allowed() -> Result<(), TraceError> {
    let raw = READ_GUARD.load(Ordering::Acquire);
    if raw == 0 {
        return Ok(());
    }
    // R89-3 FIX: Transmute from usize (not data pointer) to fn pointer
    // Safety: value originated from a valid `TraceGuardFn` fn pointer
    let guard: TraceGuardFn = unsafe { core::mem::transmute::<usize, TraceGuardFn>(raw) };
    if guard() {
        Ok(())
    } else {
        Err(TraceError::AccessDenied)
    }
}

/// Register a tracepoint with the global registry.
///
/// Tracepoints must have unique IDs. Registration is typically done during
/// subsystem initialization or via the [`declare_tracepoint!`] macro.
///
/// # Errors
///
/// - [`TraceError::DuplicateId`] if a tracepoint with the same ID exists
/// - [`TraceError::RegistryFull`] if the registry is at capacity
pub fn register_tracepoint(tp: &'static Tracepoint) -> Result<(), TraceError> {
    TRACE_REGISTRY.lock().insert(tp)
}

/// Look up a registered tracepoint by ID.
///
/// Returns `None` if no tracepoint with the given ID is registered.
pub fn lookup_tracepoint(id: TraceId) -> Option<&'static Tracepoint> {
    TRACE_REGISTRY.lock().find(id)
}

/// List all registered tracepoints with current status.
///
/// This function is guarded by [`install_read_guard`].
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
pub fn tracepoints() -> Result<Vec<TracepointInfo>, TraceError> {
    ensure_metrics_read_allowed()?;
    Ok(TRACE_REGISTRY.lock().list())
}

/// Enable a registered tracepoint by ID.
///
/// # Errors
///
/// Returns [`TraceError::NotFound`] if the ID is not registered.
pub fn enable_tracepoint(id: TraceId) -> Result<(), TraceError> {
    match lookup_tracepoint(id) {
        Some(tp) => {
            tp.enable();
            Ok(())
        }
        None => Err(TraceError::NotFound),
    }
}

/// Disable a registered tracepoint by ID.
///
/// # Errors
///
/// Returns [`TraceError::NotFound`] if the ID is not registered.
pub fn disable_tracepoint(id: TraceId) -> Result<(), TraceError> {
    match lookup_tracepoint(id) {
        Some(tp) => {
            tp.disable();
            Ok(())
        }
        None => Err(TraceError::NotFound),
    }
}

/// Initialize the trace subsystem.
///
/// Registers built-in tracepoints and initializes internal state.
/// Must be called during kernel boot before subsystems begin emitting events.
pub fn init() {
    // Register built-in tracepoints
    let _ = register_tracepoint(&watchdog::TRACE_WATCHDOG_HANG);

    println!("[trace] Observability subsystem initialized");
    println!(
        "      Max tracepoints: {}, counters: {}, watchdog slots: {}",
        MAX_TRACEPOINTS,
        counters::TRACE_COUNTER_COUNT,
        watchdog::MAX_WATCHDOG_SLOTS,
    );
}

/// Convenience macro for declaring static tracepoints with field metadata.
///
/// # Example
///
/// ```rust,ignore
/// declare_tracepoint!(
///     pub SCHED_SWITCH, 0x0001, TraceCategory::Sched,
///     ["prev_pid", "next_pid", "prev_state"]
/// );
/// ```
#[macro_export]
macro_rules! declare_tracepoint {
    ($vis:vis $name:ident, $id:expr, $category:expr, [$($field:expr),* $(,)?]) => {
        $vis static $name: $crate::Tracepoint = $crate::Tracepoint::new(
            $crate::TraceId::new($id),
            stringify!($name),
            $category,
            &[$($field),*],
        );
    };
}
