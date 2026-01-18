//! TLB Shootdown Infrastructure
//!
//! Provides cross-CPU TLB invalidation for SMP systems.
//!
//! # R23-1/R23-3 Fix
//!
//! This module addresses the TLB coherency issues identified in Round 23 audit:
//! - R23-1: COW page table modifications need TLB shootdown on all CPUs
//! - R23-3: munmap needs TLB shootdown before frame deallocation
//!
//! # Current Implementation (Single-Core)
//!
//! Currently, Zero-OS runs in single-core mode (`current_cpu_id()` always returns 0).
//! All functions perform local TLB flushes only. This is safe because:
//! - Only one CPU exists, so no stale TLB entries can exist on other CPUs
//! - The local flush ensures the current CPU sees updated mappings
//!
//! # SMP Upgrade Path
//!
//! When SMP support is enabled, these functions must be updated to:
//! 1. Send IPI (Inter-Processor Interrupt) to all CPUs running the affected address space
//! 2. Wait for acknowledgment from all target CPUs
//! 3. Only then return (and allow frame deallocation in munmap case)
//!
//! The interface is designed to support this transition:
//! - `flush_current_as_all()`: Flush entire address space on all CPUs
//! - `flush_current_as_range()`: Flush specific range on all CPUs (future optimization)
//!
//! # Safety Guard
//!
//! A compile-time or runtime guard should be added before enabling SMP to ensure
//! the IPI-based implementation is in place. See `assert_single_core_mode()`.

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::tlb;
use x86_64::VirtAddr;

/// Statistics for TLB shootdown operations (for debugging/profiling)
/// Uses atomics for SMP-safety (relaxed ordering is sufficient for stats)
#[derive(Debug)]
pub struct TlbShootdownStats {
    /// Number of full address space flushes
    pub full_flushes: u64,
    /// Number of range flushes
    pub range_flushes: u64,
    /// Number of pages flushed in range operations
    pub pages_flushed: u64,
}

// Atomic statistics for SMP-safe updates
static STATS_FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_RANGE_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_PAGES_FLUSHED: AtomicU64 = AtomicU64::new(0);

/// SMP support flag - set to true when real IPI-based shootdown is implemented
/// CRITICAL: This must remain false until IPI mechanism is complete
static SMP_SHOOTDOWN_IMPLEMENTED: bool = false;

/// R24-7 fix: Track number of online CPUs
/// This counter must be incremented by the SMP bring-up code when each CPU comes online.
/// Starts at 1 (BSP is always online).
static ONLINE_CPU_COUNT: AtomicU64 = AtomicU64::new(1);

/// Register a CPU as online.
///
/// This function MUST be called by the SMP bring-up code when each AP (Application Processor)
/// is initialized. The BSP (Boot Strap Processor) is already counted (initial value is 1).
///
/// # Safety
///
/// This function is safe to call from any context, but should only be called once per CPU
/// during SMP initialization.
pub fn register_cpu_online() {
    ONLINE_CPU_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Get the number of online CPUs.
///
/// Returns the current count of online CPUs. Useful for debugging and SMP validation.
pub fn online_cpu_count() -> u64 {
    ONLINE_CPU_COUNT.load(Ordering::SeqCst)
}

/// Assert that we're in single-core mode.
///
/// This function should be called at boot time or before any TLB shootdown
/// operation to ensure we don't silently run with broken SMP support.
///
/// # Panics
///
/// Panics if multiple CPUs are online but SMP shootdown is not implemented.
///
/// # R24-7 Fix
///
/// Now checks both `ONLINE_CPU_COUNT` and current CPU ID. This prevents the case where
/// SMP is enabled but the guard only checks cpu_id (which would pass on BSP even with
/// multiple CPUs online).
#[inline]
fn assert_single_core_mode() {
    // R24-7 fix: Check online CPU count first
    // This catches the case where we're on BSP but APs have been brought online
    let cpu_count = ONLINE_CPU_COUNT.load(Ordering::SeqCst);
    if cpu_count > 1 && !SMP_SHOOTDOWN_IMPLEMENTED {
        panic!(
            "TLB shootdown called with {} CPUs online but SMP support not implemented! \
             This is a critical bug - stale TLB entries may cause memory corruption. \
             Implement IPI-based shootdown or disable SMP.",
            cpu_count
        );
    }

    // Also check current CPU ID as a secondary guard
    // cpu_local::current_cpu_id() returns 0 in single-core mode
    // When SMP is enabled, this will return non-zero for secondary CPUs
    let cpu_id = cpu_local::current_cpu_id();

    // Guard: If we're on a non-boot CPU but SMP shootdown isn't implemented, panic
    if cpu_id != 0 && !SMP_SHOOTDOWN_IMPLEMENTED {
        panic!(
            "TLB shootdown called on CPU {} but SMP support not implemented! \
             This is a critical bug - stale TLB entries may cause memory corruption.",
            cpu_id
        );
    }
}

/// Flush the entire TLB for the current address space on all CPUs.
///
/// This function should be called after modifying page table entries that
/// affect multiple pages or when the specific pages are not known.
///
/// # R23-1 Fix
///
/// Used in `copy_page_table_cow()` after marking parent PTEs as read-only.
/// Ensures all CPUs (in SMP) see the updated COW mappings.
///
/// # Current Behavior (Single-Core)
///
/// Performs local `flush_all()` only. Safe because only one CPU exists.
///
/// # SMP Behavior (Future)
///
/// Will send IPI to all CPUs running this address space (same CR3) and wait
/// for acknowledgment before returning.
///
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
#[inline]
pub fn flush_current_as_all() {
    // Safety guard: panic if SMP is enabled but shootdown not implemented
    assert_single_core_mode();

    // R23-1/R23-3 fix: TLB shootdown placeholder
    //
    // CURRENT: Single-core mode - only local flush needed
    // FUTURE (SMP): Replace with IPI-based shootdown:
    //   1. Get set of CPUs running this address space (same CR3)
    //   2. Send FLUSH_ALL IPI to all target CPUs
    //   3. Wait for ACK from all targets
    //   4. Return

    tlb::flush_all();

    // Update statistics (atomic for SMP-safety)
    STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
}

/// Flush a range of pages from the TLB on all CPUs.
///
/// This function should be called after unmapping a range of pages,
/// before deallocating the underlying physical frames.
///
/// # Arguments
///
/// * `start` - Starting virtual address (will be page-aligned down)
/// * `len` - Length in bytes (will be rounded up to page boundary)
///
/// # R23-3 Fix
///
/// Used in `sys_munmap()` after unmapping pages but before freeing frames.
/// Ensures no CPU (in SMP) retains stale TLB entries pointing to freed frames.
///
/// # Current Behavior (Single-Core)
///
/// Performs local `invlpg` for each page in the range. For large ranges,
/// falls back to `flush_all()` for efficiency.
///
/// # SMP Behavior (Future)
///
/// Will send IPI with the address range to all CPUs running this address space
/// and wait for acknowledgment before returning. This is CRITICAL for safety:
/// frames must NOT be freed until all CPUs have flushed their TLB entries.
///
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
pub fn flush_current_as_range(start: VirtAddr, len: usize) {
    // Safety guard: panic if SMP is enabled but shootdown not implemented
    assert_single_core_mode();

    // R23-1/R23-3 fix: TLB shootdown placeholder
    //
    // CURRENT: Single-core mode - only local flush needed
    // FUTURE (SMP): Replace with IPI-based shootdown:
    //   1. Get set of CPUs running this address space (same CR3)
    //   2. Send FLUSH_RANGE IPI with (start, len) to all target CPUs
    //   3. Wait for ACK from all targets
    //   4. Return

    const PAGE_SIZE: u64 = 4096;
    // Threshold: if flushing more than 16 pages, do full flush instead
    const FULL_FLUSH_THRESHOLD: u64 = 16;

    let start_aligned = start.align_down(PAGE_SIZE);

    // Safe end calculation: use checked_add to prevent overflow
    // If overflow occurs, fall back to full flush
    let end = match start.as_u64().checked_add(len as u64) {
        Some(e) => e,
        None => {
            // Overflow: fall back to full flush for safety
            tlb::flush_all();
            STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Align end up to page boundary (safe, already checked for overflow)
    let end_aligned = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = (end_aligned - start_aligned.as_u64()) / PAGE_SIZE;

    if num_pages > FULL_FLUSH_THRESHOLD || num_pages == 0 {
        // Large range or invalid: full flush is more efficient/safer
        tlb::flush_all();
        STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
    } else {
        // Small range: flush individual pages
        for i in 0..num_pages {
            let addr = VirtAddr::new(start_aligned.as_u64() + (i * PAGE_SIZE));
            tlb::flush(addr);
        }
        STATS_RANGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
        STATS_PAGES_FLUSHED.fetch_add(num_pages, Ordering::Relaxed);
    }
}

/// Flush a single page from the TLB on all CPUs.
///
/// Convenience wrapper around `flush_current_as_range` for single pages.
///
/// # Arguments
///
/// * `addr` - Virtual address of the page to flush
#[inline]
pub fn flush_current_as_page(addr: VirtAddr) {
    flush_current_as_range(addr, 4096);
}

/// Get TLB shootdown statistics.
///
/// Returns a snapshot of the current statistics. Thread-safe due to atomic loads.
pub fn get_stats() -> TlbShootdownStats {
    TlbShootdownStats {
        full_flushes: STATS_FULL_FLUSHES.load(Ordering::Relaxed),
        range_flushes: STATS_RANGE_FLUSHES.load(Ordering::Relaxed),
        pages_flushed: STATS_PAGES_FLUSHED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// SMP Support Stubs (Future Implementation)
// ============================================================================

/// Marker for SMP-required functionality.
///
/// When SMP is enabled, these will be replaced with real implementations.
#[allow(dead_code)]
mod smp_stubs {
    /// IPI vector for TLB shootdown
    pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xFE;

    /// Maximum time to wait for IPI acknowledgment (in microseconds)
    pub const IPI_ACK_TIMEOUT_US: u64 = 1000;

    /// Pending TLB shootdown request (per-CPU in SMP)
    pub struct TlbShootdownRequest {
        /// Requesting CPU ID
        pub from_cpu: usize,
        /// Target address space (CR3)
        pub target_cr3: u64,
        /// Start address (0 for full flush)
        pub start: u64,
        /// Length in bytes (0 for full flush)
        pub len: usize,
    }

    /// Send TLB shootdown IPI to target CPUs
    ///
    /// # Future Implementation
    ///
    /// 1. For each target CPU (those with matching CR3):
    ///    a. Set pending request in target's per-CPU area
    ///    b. Send IPI using APIC
    /// 2. Wait for all targets to acknowledge
    /// 3. Clear pending requests
    /// 4. Return
    pub fn send_tlb_shootdown_ipi(_target_cr3: u64, _start: u64, _len: usize) {
        // TODO: Implement when SMP support is added
        // For now, this is never called (single-core mode)
    }
}
