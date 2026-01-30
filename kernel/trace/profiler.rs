//! Timer-driven PC (Program Counter) Sampling Profiler
//!
//! Provides hardware-assisted profiling by sampling the instruction pointer (RIP)
//! at regular timer intervals. Samples are stored in per-CPU ring buffers to avoid
//! cache line contention.
//!
//! # Design
//!
//! - **Lock-free write path**: Each CPU has its own ring buffer accessed via
//!   `CpuLocal`. Writes are single-producer (only the timer ISR on that CPU),
//!   using seqlock publishing for safe concurrent reads.
//!
//! - **Drop-oldest semantics**: When a ring is full, the oldest sample is
//!   overwritten. This ensures bounded memory usage regardless of sampling rate.
//!
//! - **Guarded export**: Snapshot/control APIs are protected by the read guard
//!   from the parent module, requiring `CAP_TRACE_READ` or equivalent.
//!
//! # IRQ Safety
//!
//! The [`record_pc_sample`] function is safe to call from IRQ context. It performs
//! no locking and uses only atomic operations with relaxed/release ordering.
//!
//! # Usage
//!
//! ```rust,ignore
//! // Start profiling (clears buffers)
//! trace::start_profiler()?;
//!
//! // ... workload runs, timer samples are collected ...
//!
//! // Retrieve samples (drains buffers)
//! let snapshot = trace::snapshot_profiler()?;
//! for sample in &snapshot.samples {
//!     println!("CPU{}: pid={} rip=0x{:x}", sample.cpu, sample.pid, sample.rip);
//! }
//!
//! // Stop profiling
//! trace::stop_profiler()?;
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cpu_local::CpuLocal;

use crate::{ensure_metrics_read_allowed, TraceError};

// ============================================================================
// Constants
// ============================================================================

/// Number of samples per CPU ring buffer before overwriting oldest.
///
/// 1024 samples at 1ms tick rate = ~1 second of history per CPU.
/// Adjust based on memory constraints and desired capture window.
pub const PROFILER_RING_CAPACITY: usize = 1024;

// ============================================================================
// Sample Types
// ============================================================================

/// Single PC sample captured from the timer tick.
///
/// Kept small (32 bytes) to minimize cache impact during high-frequency sampling.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ProfilerSample {
    /// Monotonic time in nanoseconds (derived from ms * 1_000_000).
    pub timestamp_ns: u64,
    /// Current PID (0 if idle or no current process).
    pub pid: u64,
    /// Instruction pointer at sample time.
    pub rip: u64,
    /// CPU that captured the sample.
    pub cpu: u32,
    /// Reserved for future use (alignment padding).
    _reserved: u32,
}

/// Aggregated snapshot of samples across all CPUs.
///
/// Samples are ordered per-CPU (oldest to newest within each CPU),
/// but interleaving between CPUs is not guaranteed.
#[derive(Clone, Debug)]
pub struct ProfilerSnapshot {
    /// All collected samples across all CPUs.
    pub samples: Vec<ProfilerSample>,
}

impl ProfilerSnapshot {
    /// Total number of samples in this snapshot.
    #[inline]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if snapshot is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Iterate over samples.
    pub fn iter(&self) -> impl Iterator<Item = &ProfilerSample> {
        self.samples.iter()
    }
}

// ============================================================================
// Ring Buffer Implementation
// ============================================================================

/// Single ring slot with seqlock-style publishing.
///
/// The seqlock ensures readers don't observe partial writes during IRQ.
/// Writers increment seq to odd (write in progress), write data, then
/// increment to even (published). Readers spin until seq is stable and even.
struct SampleSlot {
    /// Sequence number: even = stable, odd = write in progress.
    seq: AtomicU64,
    /// The sample data (interior mutability for IRQ writer).
    data: UnsafeCell<ProfilerSample>,
}

impl SampleSlot {
    /// Create a new empty slot.
    const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            data: UnsafeCell::new(ProfilerSample {
                timestamp_ns: 0,
                pid: 0,
                rip: 0,
                cpu: 0,
                _reserved: 0,
            }),
        }
    }

    /// Store a sample with seqlock publishing.
    ///
    /// # Safety
    ///
    /// Must only be called from single-producer context (one CPU's timer ISR).
    #[inline]
    fn store(&self, sample: ProfilerSample) {
        let seq = self.seq.load(Ordering::Relaxed);
        // Mark write in progress (odd) - Release ordering ensures prior reads complete
        self.seq.store(seq.wrapping_add(1), Ordering::Release);
        // Write the sample data
        unsafe {
            *self.data.get() = sample;
        }
        // Publish (even) with Release to make data visible to readers
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// Load a sample, spinning until stable (not mid-write).
    ///
    /// Returns when a consistent sample is read.
    #[inline]
    fn load_stable(&self) -> ProfilerSample {
        loop {
            let start = self.seq.load(Ordering::Acquire);
            // If odd, write in progress - spin
            if start % 2 != 0 {
                core::hint::spin_loop();
                continue;
            }
            // Read the data
            let sample = unsafe { *self.data.get() };
            // Verify seq didn't change during read
            let end = self.seq.load(Ordering::Acquire);
            if start == end {
                return sample;
            }
            // Changed during read - retry
            core::hint::spin_loop();
        }
    }
}

// Safety: seqlock guards access to the interior data.
// Only one writer (per-CPU timer ISR) and multiple readers (snapshot).
unsafe impl Send for SampleSlot {}
unsafe impl Sync for SampleSlot {}

/// Per-CPU ring buffer for PC samples.
///
/// Uses monotonic head/tail counters that wrap via modulo indexing.
/// This avoids complex wrap-around logic in the hot path.
struct SampleRing {
    /// Next write position (monotonically increasing).
    head: AtomicUsize,
    /// Next read position (monotonically increasing).
    tail: AtomicUsize,
    /// Fixed-size array of sample slots.
    slots: [SampleSlot; PROFILER_RING_CAPACITY],
}

impl SampleRing {
    /// Create a new empty ring buffer.
    fn new() -> Self {
        // Use from_fn for runtime initialization (SampleSlot contains UnsafeCell, not Copy)
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            slots: core::array::from_fn(|_| SampleSlot::new()),
        }
    }

    /// Push a sample, overwriting oldest on overflow.
    ///
    /// # IRQ Safety
    ///
    /// Lock-free, single-producer safe. Only the timer ISR on this CPU calls push.
    #[inline]
    fn push(&self, sample: ProfilerSample) {
        let head = self.head.load(Ordering::Relaxed);
        let idx = head % PROFILER_RING_CAPACITY;

        // Write the sample to the slot
        self.slots[idx].store(sample);

        // Advance head
        let new_head = head.wrapping_add(1);
        self.head.store(new_head, Ordering::Release);

        // If buffer is now over capacity, advance tail to drop oldest
        let tail = self.tail.load(Ordering::Relaxed);
        let span = new_head.wrapping_sub(tail);
        if span > PROFILER_RING_CAPACITY {
            // Advance tail to maintain capacity invariant
            let new_tail = new_head.wrapping_sub(PROFILER_RING_CAPACITY);
            self.tail.store(new_tail, Ordering::Relaxed);
        }
    }

    /// Drain all buffered samples into the output vector.
    ///
    /// Samples are returned in oldest-to-newest order for this CPU.
    /// After draining, the buffer is empty (tail catches up to head).
    fn drain_into(&self, out: &mut Vec<ProfilerSample>) {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);

        // Calculate how many samples are available
        let available = head.wrapping_sub(tail).min(PROFILER_RING_CAPACITY);
        if available == 0 {
            return;
        }

        out.reserve(available);

        // Read samples from oldest (tail) to newest (head-1)
        for offset in 0..available {
            let idx = tail.wrapping_add(offset) % PROFILER_RING_CAPACITY;
            out.push(self.slots[idx].load_stable());
        }

        // Advance tail to head (buffer now empty)
        self.tail.store(head, Ordering::Release);
    }

    /// Reset the ring buffer (clear all samples).
    fn reset(&self) {
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Relaxed);
    }
}

// Safety: ring uses atomics and seqlock for interior mutability.
unsafe impl Send for SampleRing {}
unsafe impl Sync for SampleRing {}

// ============================================================================
// Global State
// ============================================================================

/// Global profiler enable flag.
///
/// When false, [`record_pc_sample`] returns immediately without recording.
static PROFILER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Per-CPU ring buffers for samples.
static PROFILER_RINGS: CpuLocal<SampleRing> = CpuLocal::new(SampleRing::new);

// ============================================================================
// Public API
// ============================================================================

/// Record a PC sample from the timer interrupt.
///
/// This is the hot-path entry point called from the timer ISR. When profiling
/// is disabled, this function performs a single atomic load and returns.
///
/// # Arguments
///
/// * `timestamp_ns` - Monotonic timestamp in nanoseconds
/// * `pid` - Current process ID (0 if idle/unknown)
/// * `rip` - Instruction pointer at sample time
///
/// # IRQ Safety
///
/// This function is lock-free and safe to call from any context including IRQ.
#[inline]
pub fn record_pc_sample(timestamp_ns: u64, pid: u64, rip: u64) {
    // Fast path: single atomic load when disabled
    if !PROFILER_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let cpu_idx = cpu_local::current_cpu_id();
    let sample = ProfilerSample {
        timestamp_ns,
        pid,
        rip,
        cpu: cpu_idx as u32,
        _reserved: 0,
    };

    // Push to this CPU's ring buffer
    PROFILER_RINGS.with(|ring| ring.push(sample));
}

/// Check if the profiler is currently enabled.
#[inline]
pub fn profiler_enabled() -> bool {
    PROFILER_ENABLED.load(Ordering::Acquire)
}

/// Start the profiler and clear all per-CPU buffers.
///
/// Samples will be recorded at each timer tick until [`stop_profiler`] is called.
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
pub fn start_profiler() -> Result<(), TraceError> {
    ensure_metrics_read_allowed()?;

    // Clear all per-CPU ring buffers before starting
    let max = cpu_local::max_cpus();
    for cpu in 0..max {
        let _ = PROFILER_RINGS.with_cpu(cpu, |ring| ring.reset());
    }

    // Enable sampling
    PROFILER_ENABLED.store(true, Ordering::Release);

    Ok(())
}

/// Stop the profiler.
///
/// Sampling stops immediately. Buffered samples remain available for
/// [`snapshot_profiler`] until the profiler is restarted.
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
pub fn stop_profiler() -> Result<(), TraceError> {
    ensure_metrics_read_allowed()?;
    PROFILER_ENABLED.store(false, Ordering::Release);
    Ok(())
}

/// Drain all per-CPU ring buffers into a single snapshot.
///
/// Temporarily pauses sampling during the drain to ensure consistency,
/// then restores the previous enable state.
///
/// # Returns
///
/// A snapshot containing all buffered samples across all CPUs.
/// Samples are grouped by CPU (oldest to newest within each CPU).
///
/// # Errors
///
/// Returns [`TraceError::AccessDenied`] if the read guard denies access.
pub fn snapshot_profiler() -> Result<ProfilerSnapshot, TraceError> {
    ensure_metrics_read_allowed()?;

    // Temporarily disable to avoid concurrent writes during drain
    let was_enabled = PROFILER_ENABLED.swap(false, Ordering::AcqRel);

    let mut samples = Vec::new();

    // Drain all CPUs
    let max = cpu_local::max_cpus();
    for cpu in 0..max {
        let _ = PROFILER_RINGS.with_cpu(cpu, |ring| ring.drain_into(&mut samples));
    }

    // Restore previous enable state
    if was_enabled {
        PROFILER_ENABLED.store(true, Ordering::Release);
    }

    Ok(ProfilerSnapshot { samples })
}
