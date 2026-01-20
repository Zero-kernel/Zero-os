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
//! # IPI-Based Implementation (SMP)
//!
//! When multiple CPUs are online, TLB shootdown works as follows:
//! 1. Requesting CPU writes request to each target CPU's per-CPU mailbox
//! 2. Requesting CPU sends TLB shootdown IPI (vector 0xFE) to all targets
//! 3. Requesting CPU flushes its own TLB locally
//! 4. Each target CPU's IPI handler reads mailbox, flushes TLB, writes ACK
//! 5. Requesting CPU waits for all ACKs with bounded timeout
//!
//! # Memory Ordering
//!
//! - Requester: writes fields Relaxed, then `request_gen` Release
//! - Handler: loads `request_gen` Acquire, reads fields Relaxed, writes `ack_gen` Release
//! - Waiter: loads `ack_gen` Acquire to ensure flush completion is visible
//!
//! # Safety Guard
//!
//! The `assert_single_core_mode()` function panics if multiple CPUs are online
//! but the IPI sender is not registered, ensuring we never silently skip shootdown.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::hint::spin_loop;
use core::mem;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use cpu_local::{
    current_cpu, current_cpu_id, lapic_id_for_cpu, max_cpus, CpuLocal, TlbShootdownMailbox,
    PER_CPU_DATA,
};
use spin::RwLock;
use x86_64::instructions::tlb;
use x86_64::registers::control::Cr3;
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

/// SMP support flag - now true since IPI-based shootdown is implemented
static SMP_SHOOTDOWN_IMPLEMENTED: bool = true;

/// R24-7 fix: Track number of online CPUs
/// This counter must be incremented by the SMP bring-up code when each CPU comes online.
/// Starts at 1 (BSP is always online).
static ONLINE_CPU_COUNT: AtomicU64 = AtomicU64::new(1);

/// Codex review fix: Per-CPU online bitmask for safe target selection.
///
/// Bit N is set when CPU N has fully initialized and can handle IPIs.
/// This prevents sending IPIs to CPUs that have LAPIC IDs registered but
/// haven't completed their initialization yet.
///
/// BSP (CPU 0) is marked online at init time. APs set their bit via
/// `register_cpu_online_with_id()` after completing initialization.
static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(1); // BSP (bit 0) is always online

/// Next generation number for TLB shootdown requests (monotonic, starts at 1)
static NEXT_SHOOTDOWN_GEN: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// Per-Address-Space TLB Tracking (R68 Architecture Improvement)
// ============================================================================

/// Per-CPU record of last loaded CR3 (0 = unknown/kernel shared).
///
/// Each CPU tracks its current CR3 so we can update ASID_CPU_MASKS on context switch.
static CPU_ACTIVE_CR3: CpuLocal<AtomicU64> = CpuLocal::new(|| AtomicU64::new(0));

/// CR3 -> CPU bitmask mapping for address spaces currently running.
///
/// Key: CR3 physical address (address space identifier)
/// Value: Bitmask of CPUs currently running this address space
///
/// When a CPU switches CR3, it updates this map:
/// - Removes itself from the old CR3's bitmask
/// - Adds itself to the new CR3's bitmask
///
/// TLB shootdown uses this to target only CPUs with potentially cached TLB entries.
/// If a CR3 is not in the map, we fall back to broadcast (safe but less efficient).
static ASID_CPU_MASKS: RwLock<BTreeMap<u64, u64>> = RwLock::new(BTreeMap::new());

/// Statistics for optimized TLB shootdowns
static STATS_TARGETED_SHOOTDOWNS: AtomicU64 = AtomicU64::new(0);
static STATS_BROADCAST_FALLBACK: AtomicU64 = AtomicU64::new(0);

/// Convert CPU ID to bitmask bit, if within range.
#[inline]
fn cpu_bit(cpu_id: usize) -> Option<u64> {
    if cpu_id < 64 {
        Some(1u64 << cpu_id)
    } else {
        None
    }
}

/// Registered function used to send the TLB shootdown IPI
/// Stored as usize to avoid function pointer in static
static TLB_IPI_SENDER: AtomicUsize = AtomicUsize::new(0);

/// Spin iterations to wait for ACKs before timing out
/// At ~2GHz, 1M iterations is roughly 0.5-1ms
const IPI_ACK_TIMEOUT_SPINS: usize = 1_000_000;

/// Page size used for alignment
const PAGE_SIZE: u64 = 4096;

/// If more than this many pages are affected, fall back to full flush
const FULL_FLUSH_THRESHOLD: u64 = 16;

/// Type alias for IPI sender function
type TlbIpiSender = fn(usize);

/// Register a CPU as online (legacy interface, uses current CPU ID).
///
/// This function MUST be called by the SMP bring-up code when each AP (Application Processor)
/// is initialized. The BSP (Boot Strap Processor) is already counted (initial value is 1).
///
/// # Safety
///
/// This function is safe to call from any context, but should only be called once per CPU
/// during SMP initialization.
pub fn register_cpu_online() {
    let cpu_id = current_cpu_id();
    register_cpu_online_with_id(cpu_id);
}

/// Register a specific CPU as online by its ID.
///
/// This is the preferred interface when the CPU ID is known (e.g., from AP trampoline data).
/// Sets the corresponding bit in ONLINE_CPU_MASK with Release ordering.
///
/// # Arguments
///
/// * `cpu_id` - The logical CPU index (0 = BSP, 1+ = APs)
pub fn register_cpu_online_with_id(cpu_id: usize) {
    if cpu_id >= 64 {
        return; // Can't represent in bitmask, ignore
    }
    let mask = 1u64 << cpu_id;
    ONLINE_CPU_MASK.fetch_or(mask, Ordering::Release);
    ONLINE_CPU_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Check if a specific CPU is marked as online.
///
/// Uses Acquire ordering to synchronize with the Release in `register_cpu_online_with_id`.
///
/// # R68-6 FIX: Made public for IPI layer
///
/// The IPI layer needs to check online status before sending IPIs to avoid targeting
/// CPUs that have LAPIC IDs registered but haven't completed initialization yet.
#[inline]
pub fn is_cpu_online(cpu_id: usize) -> bool {
    if cpu_id >= 64 {
        return false;
    }
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    (mask & (1u64 << cpu_id)) != 0
}

/// Get the number of online CPUs.
///
/// Returns the current count of online CPUs. Useful for debugging and SMP validation.
pub fn online_cpu_count() -> u64 {
    ONLINE_CPU_COUNT.load(Ordering::SeqCst)
}

// ============================================================================
// CR3 Tracking for Optimized TLB Shootdown
// ============================================================================

/// Update CR3 -> CPU ownership tracking after a CR3 change on this CPU.
///
/// Called by `activate_memory_space()` whenever a context switch changes CR3.
/// This allows TLB shootdown to target only CPUs that might have TLB entries
/// for the affected address space, rather than broadcasting to all CPUs.
///
/// # Arguments
///
/// * `new_cr3` - The new CR3 value (physical address of PML4)
///
/// # Implementation
///
/// 1. Swap the current CPU's tracked CR3 with the new value
/// 2. Remove this CPU's bit from the old CR3's mask (if tracked)
/// 3. Add this CPU's bit to the new CR3's mask
///
/// # Thread Safety
///
/// Uses a RwLock for the global map. The per-CPU CR3 tracking uses atomics.
/// CPUs with ID >= 64 fall back to broadcast shootdown (cannot be tracked in u64 mask).
pub fn track_cr3_switch(new_cr3: u64) {
    let cpu_id = current_cpu_id();
    let bit = match cpu_bit(cpu_id) {
        Some(b) => b,
        None => {
            // CPU ID >= 64: can't track in bitmask, just update local state
            CPU_ACTIVE_CR3.with(|c| c.store(new_cr3, Ordering::SeqCst));
            return;
        }
    };

    // Atomically swap the CPU's tracked CR3
    let prev = CPU_ACTIVE_CR3.with(|c| c.swap(new_cr3, Ordering::SeqCst));

    // Update the global CR3 -> CPU mask mapping
    let mut map = ASID_CPU_MASKS.write();

    // Remove this CPU from the previous CR3's mask
    if prev != 0 && prev != new_cr3 {
        if let Some(mask) = map.get_mut(&prev) {
            *mask &= !bit;
            if *mask == 0 {
                map.remove(&prev);
            }
        }
    }

    // Add this CPU to the new CR3's mask
    if new_cr3 != 0 {
        let entry = map.entry(new_cr3).or_insert(0);
        *entry |= bit;
    }
}

/// Get the current CPU's tracked CR3 value.
///
/// Returns 0 if no CR3 has been tracked for this CPU yet.
#[inline]
pub fn current_cpu_cr3() -> u64 {
    CPU_ACTIVE_CR3.with(|c| c.load(Ordering::SeqCst))
}

/// Register the function used to send the TLB shootdown IPI.
///
/// This is called by the arch IPI layer to avoid a circular dependency from `mm` to `arch`.
/// Must be called during early boot before any TLB shootdown operations with SMP.
pub fn register_ipi_sender(sender: TlbIpiSender) {
    TLB_IPI_SENDER.store(sender as usize, Ordering::Release);
}

/// Get the registered IPI sender function, if any.
fn tlb_ipi_sender() -> Option<TlbIpiSender> {
    let ptr = TLB_IPI_SENDER.load(Ordering::Acquire);
    if ptr == 0 {
        None
    } else {
        // Safety: pointer was written from a real function in register_ipi_sender()
        Some(unsafe { mem::transmute(ptr) })
    }
}

/// Assert that we're in single-core mode or have IPI sender registered.
///
/// This function should be called at boot time or before any TLB shootdown
/// operation to ensure we don't silently run with broken SMP support.
///
/// # Panics
///
/// Panics if multiple CPUs are online but IPI sender is not registered.
#[inline]
fn assert_single_core_mode() {
    let cpu_count = ONLINE_CPU_COUNT.load(Ordering::SeqCst);
    if cpu_count > 1 && tlb_ipi_sender().is_none() {
        panic!(
            "TLB shootdown called with {} CPUs online but IPI sender not registered! \
             This is a critical bug - stale TLB entries may cause memory corruption. \
             Register the TLB IPI sender before enabling SMP.",
            cpu_count
        );
    }

    // Also check current CPU ID as a secondary guard
    let cpu_id = current_cpu_id();
    if cpu_id != 0 && tlb_ipi_sender().is_none() {
        panic!(
            "TLB shootdown called on CPU {} but IPI sender not registered! \
             This is a critical bug - stale TLB entries may cause memory corruption.",
            cpu_id
        );
    }
}

/// Get the current CR3 value (page table base)
#[inline]
fn current_cr3_value() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

/// Get a reference to a specific CPU's TLB shootdown mailbox
fn mailbox_for_cpu(cpu_id: usize) -> Option<&'static TlbShootdownMailbox> {
    PER_CPU_DATA.get_cpu(cpu_id).map(|data| data.tlb_mailbox())
}

/// Collect target CPUs for TLB shootdown based on address space tracking.
///
/// R68 Architecture Improvement: Uses per-address-space tracking to target only
/// CPUs that might have TLB entries for the affected address space.
///
/// # Arguments
///
/// * `target_cr3` - The CR3 of the address space being modified (0 = broadcast to all)
///
/// # Returns
///
/// Vector of CPU IDs that need to receive the TLB shootdown IPI.
///
/// # Fallback Behavior
///
/// If the CR3 is not in the tracking map, or if tracking indicates no CPUs,
/// we fall back to broadcasting to all online CPUs (except self). This ensures
/// correctness even if tracking becomes out of sync.
fn collect_target_cpus(target_cr3: u64) -> Vec<usize> {
    let mut targets = Vec::new();
    let self_id = current_cpu_id();

    // Try to use per-address-space tracking if CR3 is valid
    if target_cr3 != 0 {
        if let Some(mask) = ASID_CPU_MASKS.read().get(&target_cr3).copied() {
            if mask != 0 {
                // We found tracked CPUs for this address space
                let online = ONLINE_CPU_MASK.load(Ordering::Acquire);
                let tracked = mask & online; // Only consider online CPUs

                // Convert bitmask to CPU list
                let max_tracked = core::cmp::min(max_cpus(), 64);
                for cpu in 0..max_tracked {
                    if cpu == self_id {
                        continue;
                    }
                    if let Some(bit) = cpu_bit(cpu) {
                        if (tracked & bit) != 0 && lapic_id_for_cpu(cpu).is_some() {
                            targets.push(cpu);
                        }
                    }
                }

                if !targets.is_empty() {
                    // Successful targeted shootdown
                    STATS_TARGETED_SHOOTDOWNS.fetch_add(1, Ordering::Relaxed);
                    return targets;
                }
            }
        }
    }

    // Fallback: broadcast to all online CPUs except self
    // This handles: CR3=0, CR3 not tracked, or empty tracked mask
    STATS_BROADCAST_FALLBACK.fetch_add(1, Ordering::Relaxed);

    for cpu in 0..max_cpus() {
        if cpu == self_id {
            continue;
        }
        // Check both: LAPIC ID is registered AND CPU is marked online
        if lapic_id_for_cpu(cpu).is_some() && is_cpu_online(cpu) {
            targets.push(cpu);
        }
    }
    targets
}

/// Post shootdown requests to all target CPUs' mailboxes
fn post_requests(targets: &[usize], cr3: u64, start: u64, len: u64, generation: u64) {
    for &cpu in targets {
        if let Some(mailbox) = mailbox_for_cpu(cpu) {
            // Write request fields with Relaxed ordering
            mailbox.target_cr3.store(cr3, Ordering::Relaxed);
            mailbox.start.store(start, Ordering::Relaxed);
            mailbox.len.store(len, Ordering::Relaxed);
            // Write generation with Release to synchronize with handler's Acquire
            mailbox.request_gen.store(generation, Ordering::Release);
        }
    }
}

/// Send TLB shootdown IPIs to all target CPUs
fn send_ipis(targets: &[usize], sender: TlbIpiSender) {
    for &cpu in targets {
        sender(cpu);
    }
}

/// Number of retry attempts for ACK timeout before panicking
const ACK_TIMEOUT_RETRIES: usize = 3;

/// Wait for all target CPUs to acknowledge the shootdown request
///
/// Returns true if all ACKs received, false on timeout.
fn wait_for_acks(targets: &[usize], generation: u64) -> bool {
    for _ in 0..IPI_ACK_TIMEOUT_SPINS {
        let all_acked = targets.iter().all(|&cpu| {
            mailbox_for_cpu(cpu)
                .map(|m| m.ack_gen.load(Ordering::Acquire) >= generation)
                .unwrap_or(true) // Missing CPU counts as acked
        });
        if all_acked {
            return true;
        }
        spin_loop();
    }
    false
}

/// Get list of CPUs that haven't ACKed yet
fn get_unacked_cpus(targets: &[usize], generation: u64) -> Vec<usize> {
    targets
        .iter()
        .filter(|&&cpu| {
            mailbox_for_cpu(cpu)
                .map(|m| m.ack_gen.load(Ordering::Relaxed) < generation)
                .unwrap_or(false)
        })
        .copied()
        .collect()
}

/// Wait for ACKs with retry support
///
/// Codex review fix: On timeout, resends IPIs and retries before failing.
/// After ACK_TIMEOUT_RETRIES attempts, panics in debug builds or warns in release.
fn wait_for_acks_with_retry(
    targets: &[usize],
    generation: u64,
    sender: TlbIpiSender,
) -> bool {
    for attempt in 0..=ACK_TIMEOUT_RETRIES {
        if wait_for_acks(targets, generation) {
            return true;
        }

        // Get unacked CPUs for retry/logging
        let unacked = get_unacked_cpus(targets, generation);
        if unacked.is_empty() {
            return true; // All acked now
        }

        if attempt < ACK_TIMEOUT_RETRIES {
            // Resend IPIs to unacked CPUs
            for &cpu in &unacked {
                sender(cpu);
            }
        } else {
            // Final timeout - this is a critical error
            drivers::println!(
                "[CRITICAL] TLB shootdown gen {} failed after {} retries. CPUs not responding: {:?}",
                generation,
                ACK_TIMEOUT_RETRIES,
                unacked
            );

            // In debug builds, panic to catch the issue early
            #[cfg(debug_assertions)]
            panic!(
                "TLB shootdown timeout: CPUs {:?} not responding. \
                 This is a critical SMP bug - stale TLB entries may cause memory corruption.",
                unacked
            );

            // In release builds, continue with warning (safer than hard panic)
            // The TLB may be stale on some CPUs, but panicking could cause worse issues
            return false;
        }
    }
    false
}

/// Warn about timeout waiting for ACKs (non-fatal, for debugging)
fn warn_timeout(targets: &[usize], generation: u64) {
    // Find which CPUs didn't ACK
    let missing: Vec<usize> = targets
        .iter()
        .filter(|&&cpu| {
            mailbox_for_cpu(cpu)
                .map(|m| m.ack_gen.load(Ordering::Relaxed) < generation)
                .unwrap_or(false)
        })
        .copied()
        .collect();

    drivers::println!(
        "[WARN] TLB shootdown gen {} timed out waiting for ACK from CPUs {:?}",
        generation,
        missing
    );
}

/// Dispatch a TLB shootdown to remote CPUs
///
/// Returns (targets, generation) if there are remote CPUs to notify,
/// None if this is the only CPU.
///
/// # R68 Architecture Improvement
///
/// Now uses per-address-space tracking to target only CPUs that might have
/// TLB entries for the current CR3, reducing unnecessary IPI traffic.
fn dispatch_shootdown(start: u64, len: u64) -> Option<(Vec<usize>, u64)> {
    let cr3 = current_cr3_value();

    // R68 optimization: Use per-address-space tracking to target only relevant CPUs
    let targets = collect_target_cpus(cr3);
    if targets.is_empty() {
        return None;
    }

    let sender = tlb_ipi_sender().unwrap_or_else(|| {
        panic!(
            "TLB shootdown requested for CPUs {:?} but no IPI sender registered",
            targets
        )
    });

    let generation = NEXT_SHOOTDOWN_GEN.fetch_add(1, Ordering::SeqCst);

    // Post requests to all target mailboxes
    post_requests(&targets, cr3, start, len, generation);

    // Send IPIs to wake up targets
    send_ipis(&targets, sender);

    Some((targets, generation))
}

/// Range operation type for flush optimization
enum RangeOp {
    /// Full TLB flush
    Full,
    /// Range flush with specific pages
    Pages { start: u64, len: u64, pages: u64 },
}

/// Normalize a virtual address range for TLB flushing
fn normalize_range(start: VirtAddr, len: usize) -> RangeOp {
    let start_aligned = start.align_down(PAGE_SIZE);
    let end = match start.as_u64().checked_add(len as u64) {
        Some(e) => e,
        None => return RangeOp::Full, // Overflow: full flush
    };

    let end_aligned = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let bytes = end_aligned.saturating_sub(start_aligned.as_u64());
    let pages = bytes / PAGE_SIZE;

    if pages == 0 || pages > FULL_FLUSH_THRESHOLD {
        RangeOp::Full
    } else {
        RangeOp::Pages {
            start: start_aligned.as_u64(),
            len: bytes,
            pages,
        }
    }
}

/// Flush a range of pages locally
fn flush_range_local(start: u64, len: u64) {
    debug_assert!(len % PAGE_SIZE == 0);
    let mut offset = 0;
    while offset < len {
        let addr = VirtAddr::new(start + offset);
        tlb::flush(addr);
        offset += PAGE_SIZE;
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
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
#[inline]
pub fn flush_current_as_all() {
    assert_single_core_mode();

    // Dispatch to remote CPUs (if any)
    let shoot = dispatch_shootdown(0, 0);

    // Flush local TLB immediately
    tlb::flush_all();

    // Wait for remote ACKs with retry support
    if let Some((targets, generation)) = shoot {
        // Mark our own mailbox as processed (for symmetry)
        current_cpu()
            .tlb_mailbox()
            .ack_gen
            .store(generation, Ordering::Release);

        // Get sender for retry
        if let Some(sender) = tlb_ipi_sender() {
            // R68-5 FIX: TLB shootdown failure is FATAL - stale TLB entries are unacceptable.
            //
            // If any CPU fails to ACK, it may have stale TLB entries that point to:
            // - Freed frames (use-after-free)
            // - Wrong permissions (W^X bypass)
            // - Other process's pages (isolation breach)
            //
            // We cannot safely continue. Previous behavior (warn + continue) allowed
            // silent memory corruption in release builds.
            if !wait_for_acks_with_retry(&targets, generation, sender) {
                let unacked = get_unacked_cpus(&targets, generation);
                panic!(
                    "CRITICAL: TLB shootdown gen {} failed! CPUs {:?} did not ACK. \
                     Cannot continue - stale TLB entries would cause memory corruption.",
                    generation, unacked
                );
            }
        }
    }

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
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
pub fn flush_current_as_range(start: VirtAddr, len: usize) {
    assert_single_core_mode();

    match normalize_range(start, len) {
        RangeOp::Full => {
            flush_current_as_all();
        }
        RangeOp::Pages {
            start: aligned_start,
            len: aligned_len,
            pages,
        } => {
            // Dispatch to remote CPUs
            let shoot = dispatch_shootdown(aligned_start, aligned_len);

            // Flush local TLB
            flush_range_local(aligned_start, aligned_len);

            // Wait for remote ACKs with retry support
            if let Some((targets, generation)) = shoot {
                current_cpu()
                    .tlb_mailbox()
                    .ack_gen
                    .store(generation, Ordering::Release);

                // Get sender for retry
                if let Some(sender) = tlb_ipi_sender() {
                    // R68-5 FIX: Range flush ACK failure is also fatal.
                    // Same reasoning as flush_current_as_all - cannot allow stale TLB.
                    if !wait_for_acks_with_retry(&targets, generation, sender) {
                        let unacked = get_unacked_cpus(&targets, generation);
                        panic!(
                            "CRITICAL: TLB shootdown gen {} (range 0x{:x}+0x{:x}) failed! \
                             CPUs {:?} did not ACK. Cannot continue.",
                            generation, aligned_start, aligned_len, unacked
                        );
                    }
                }
            }

            STATS_RANGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
            STATS_PAGES_FLUSHED.fetch_add(pages, Ordering::Relaxed);
        }
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

/// Handle an incoming TLB shootdown IPI on the current CPU.
///
/// This is called from the IPI handler (vector 0xFE) after receiving a
/// TLB shootdown request. It:
/// 1. Reads the request from this CPU's mailbox using seqlock-style protocol
/// 2. Checks if the request targets this CPU's address space (CR3 match)
/// 3. Performs the appropriate TLB flush
/// 4. Writes ACK to allow the requester to proceed
///
/// # Seqlock Protocol (Codex review fix)
///
/// To prevent torn reads when a new request arrives while we're reading fields:
/// 1. Load request_gen with Acquire
/// 2. Read all fields with Relaxed
/// 3. Re-read request_gen with Acquire
/// 4. If it changed, retry from step 1
/// 5. If stable, process the request and ACK
///
/// # Safety
///
/// Must be called from interrupt context with interrupts disabled.
pub fn handle_shootdown_ipi() {
    let mailbox = current_cpu().tlb_mailbox();

    // Maximum retries to prevent infinite loop if constantly being overwritten
    const MAX_RETRIES: usize = 10;

    for _ in 0..MAX_RETRIES {
        // Step 1: Load generation with Acquire to synchronize with requester's Release
        let generation = mailbox.request_gen.load(Ordering::Acquire);
        if generation == 0 {
            return; // No request pending
        }

        let last_ack = mailbox.ack_gen.load(Ordering::Relaxed);
        if last_ack >= generation {
            return; // Already processed this request
        }

        // Step 2: Read request details (Relaxed is fine, synchronized by request_gen Acquire)
        let target_cr3 = mailbox.target_cr3.load(Ordering::Relaxed);
        let len = mailbox.len.load(Ordering::Relaxed);
        let start = mailbox.start.load(Ordering::Relaxed);

        // Step 3: Re-read generation to detect torn reads
        let generation2 = mailbox.request_gen.load(Ordering::Acquire);
        if generation != generation2 {
            // Request was overwritten while reading, retry
            continue;
        }

        // Step 4: Fields are consistent, process the request
        let this_cr3 = current_cr3_value();

        // Only flush if the CR3 matches (0 means unconditional flush)
        if target_cr3 == 0 || target_cr3 == this_cr3 {
            if len == 0 {
                // Full TLB flush
                tlb::flush_all();
            } else {
                // Range flush
                flush_range_local(start, len);
            }
        }

        // Step 5: Write ACK with Release to allow requester to proceed
        mailbox.ack_gen.store(generation, Ordering::Release);
        return;
    }

    // If we exhausted retries, ACK the latest generation anyway to avoid deadlock
    // This is a best-effort fallback - the requester will see the ACK and proceed
    let final_gen = mailbox.request_gen.load(Ordering::Acquire);
    if final_gen > 0 {
        // Do a full flush to be safe since we couldn't read consistent parameters
        tlb::flush_all();
        mailbox.ack_gen.store(final_gen, Ordering::Release);
    }
}
