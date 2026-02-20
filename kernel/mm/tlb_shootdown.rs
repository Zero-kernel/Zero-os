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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cpu_local::{
    current_cpu, current_cpu_id, lapic_id_for_cpu, max_cpus, CpuLocal, TlbShootdownMailbox,
    PER_CPU_DATA, TLB_SHOOTDOWN_QUEUE_LEN,
};
use spin::RwLock;
use x86_64::instructions::tlb;
use x86_64::registers::control::{Cr3, Cr3Flags, Cr4, Cr4Flags};
use x86_64::VirtAddr;

// INVPCID support for efficient TLB invalidation
use tlb_ops::{invpcid_all_nonglobal, invpcid_supported};

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
    /// R106-5: Number of times mailbox saturation forced a full-flush fallback
    pub coalesced_fallbacks: u64,
}

// Atomic statistics for SMP-safe updates
static STATS_FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_RANGE_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_PAGES_FLUSHED: AtomicU64 = AtomicU64::new(0);
/// R106-5: Counter for mailbox saturation fallbacks
static STATS_COALESCED_FALLBACKS: AtomicU64 = AtomicU64::new(0);

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

/// R69-4 FIX: Writer-priority flag to prevent starvation.
///
/// When a writer (track_cr3_switch) needs the lock, it sets this flag.
/// Readers (collect_target_cpus) check this flag and briefly yield to writers.
/// This prevents heavy TLB shootdown traffic from starving context switches.
static ASID_WRITER_PENDING: AtomicBool = AtomicBool::new(false);

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

/// Cached INVPCID support flag (initialized once, never changes)
///
/// Using a static to cache the CPUID result avoids repeated CPUID calls
/// in the hot path.
static INVPCID_SUPPORTED: AtomicBool = AtomicBool::new(false);

/// Initialize INVPCID support flag.
///
/// Must be called once during boot before any TLB shootdown operations.
/// After initialization, `is_invpcid_available()` returns the cached value.
pub fn init_invpcid_support() {
    let supported = invpcid_supported();
    INVPCID_SUPPORTED.store(supported, Ordering::Release);
    if supported {
        kprintln!("[TLB] INVPCID instruction available - using efficient flushes");
    }
}

/// Check if INVPCID instruction is available (cached).
///
/// Uses Acquire ordering to pair with the Release store in init_invpcid_support().
#[inline]
fn is_invpcid_available() -> bool {
    INVPCID_SUPPORTED.load(Ordering::Acquire)
}

/// Check if CR4.PCIDE is enabled on the current CPU (CR4 bit 17).
///
/// R74-1 Enhancement: The `mm` crate cannot depend on the `security` crate's
/// `is_pcid_enabled()` helper (would create cyclic dependency), so we read
/// CR4 directly. This is a CPU-local check and doesn't require synchronization.
#[inline]
fn is_pcid_enabled() -> bool {
    Cr4::read().contains(Cr4Flags::PCID)
}

/// Flush all PCID-tagged TLB translations on CPUs without INVPCID.
///
/// # R74-1 Enhancement: Non-INVPCID PCID-Wide Flush
///
/// When PCID is enabled but INVPCID is not available, a standard CR3 reload
/// only flushes TLB entries for the *current* PCID. Stale entries for other
/// PCIDs may remain, creating a security vulnerability where:
///
/// 1. CPU1 runs process A (PCID=5), caches TLB entry for 0x1000
/// 2. CPU1 switches to process B (PCID=3), TLB entry for PCID=5 retained
/// 3. Process A unmaps 0x1000, sends TLB shootdown to CPU1
/// 4. CPU1 does CR3 reload, but only flushes PCID=3 (current), not PCID=5
/// 5. CPU1 switches back to process A (PCID=5), stale TLB entry active
/// 6. Process A can access freed memory → Use-after-free
///
/// # Intel SDM Vol. 3A Section 4.10.4.1 Fix
///
/// Clearing CR4.PCIDE invalidates ALL TLB entries for ALL PCIDs. The sequence:
/// 1. Save original CR3 (with PCID in bits [11:0]) and CR4
/// 2. Write CR3 with [11:0]=0 (required before toggling PCIDE)
/// 3. Clear CR4.PCIDE → invalidates all TLB entries for all PCIDs
/// 4. Reload CR3 to serialize the flush
/// 5. Restore CR4.PCIDE (safe now: CR3[11:0]=0)
/// 6. Restore CR3 with original PCID
///
/// # Safety
///
/// - Must be called with interrupts disabled (IPI handler context)
/// - Modifies CR3/CR4 which affects page translation
/// - All kernel mappings must remain valid throughout
/// - Intel SDM requirement: CR3[11:0] must be 0 when toggling CR4.PCIDE
#[inline]
unsafe fn flush_all_pcid_without_invpcid() {
    // Read current CR3 with PCID bits preserved (u16 contains PCID value 0-4095)
    let (frame, raw_pcid) = Cr3::read_raw();

    // Read current CR4
    let cr4 = Cr4::read();

    // Step 1: Ensure CR3[11:0]=0 before touching PCIDE (Intel SDM requirement)
    // Using empty() flags - no cache flags when PCID is in use
    Cr3::write(frame, Cr3Flags::empty());

    // Step 2: Clear CR4.PCIDE
    // Intel SDM: "If CR4.PCIDE was 1 before the MOV to CR4, any TLB entries
    // established with any PCID are invalidated."
    let mut cr4_no_pcid = cr4;
    cr4_no_pcid.remove(Cr4Flags::PCID);
    Cr4::write(cr4_no_pcid);

    // Step 3: Reload CR3 to serialize the invalidation (PCIDE=0, low bits=0)
    Cr3::write(frame, Cr3Flags::empty());

    // Step 4: Restore CR4.PCIDE
    // Intel SDM: "Software can set CR4.PCIDE to 1 only if CR3[11:0] = 000H"
    // CR3[11:0] is 0 from the write above, so this is safe
    Cr4::write(cr4);

    // Step 5: Restore original CR3 with PCID
    // This sets up the correct PCID for the current execution context
    Cr3::write_raw(frame, raw_pcid);
}

/// Flush all non-global TLB entries locally, using INVPCID if available.
///
/// This is more efficient than CR3 reload when INVPCID type 2 is available,
/// as it doesn't require reading/writing CR3.
///
/// # R74-1 Enhancement: PCID-Aware Flush
///
/// Three code paths:
/// 1. **INVPCID available**: Use INVPCID type 2 (most efficient, flushes all PCIDs)
/// 2. **PCID enabled, no INVPCID**: Toggle CR4.PCIDE to flush all PCIDs
/// 3. **No PCID**: Standard CR3 reload (fastest, no PCID tracking overhead)
#[inline]
fn flush_all_local() {
    if is_invpcid_available() {
        // INVPCID type 2: flush all non-global entries for all PCIDs
        // Most efficient path - single instruction
        unsafe { invpcid_all_nonglobal() };
    } else if is_pcid_enabled() {
        // R74-1 Enhancement: PCID without INVPCID
        // Toggle CR4.PCIDE to invalidate all PCID-tagged translations
        // More expensive (4 control register writes) but necessary for correctness
        unsafe { flush_all_pcid_without_invpcid() };
    } else {
        // No PCID: standard CR3 reload flushes all non-global TLB entries
        // This is the legacy path for older CPUs
        tlb::flush_all();
    }
}

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
///
/// # R69-4 FIX: Write Priority
///
/// To prevent writer starvation under heavy TLB shootdown traffic, this function
/// sets ASID_WRITER_PENDING before acquiring the write lock. Readers check this
/// flag and briefly spin-wait, giving priority to context switches.
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

    // R69-4 FIX: Signal that a writer is waiting
    ASID_WRITER_PENDING.store(true, Ordering::Release);

    // Update the global CR3 -> CPU mask mapping
    let mut map = ASID_CPU_MASKS.write();

    // R69-4 FIX: Clear writer-pending flag once we have the lock
    ASID_WRITER_PENDING.store(false, Ordering::Release);

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
///
/// # R69-4 FIX: Writer Priority
///
/// Before acquiring the read lock, this function checks if a writer (context switch)
/// is pending. If so, it briefly spin-waits to give priority to the writer.
/// This prevents heavy TLB shootdown traffic from starving context switches.
fn collect_target_cpus(target_cr3: u64) -> Vec<usize> {
    let mut targets = Vec::new();
    let self_id = current_cpu_id();

    // R69-4 FIX: Yield to pending writers before acquiring read lock.
    // Writers (context switches) are time-critical and should not be starved
    // by heavy TLB shootdown traffic. We spin-wait briefly if a writer is pending.
    const WRITER_YIELD_SPINS: usize = 100;
    for _ in 0..WRITER_YIELD_SPINS {
        if !ASID_WRITER_PENDING.load(Ordering::Acquire) {
            break;
        }
        spin_loop();
    }

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

/// Enqueue a TLB shootdown request into a CPU's mailbox queue.
///
/// # R72: Queue-Based Mailbox
///
/// Instead of spin-waiting for the previous request to be ACKed before posting,
/// this enqueues the request into a bounded ring buffer. The queue allows multiple
/// requests to be batched, reducing serialization and IPI overhead.
///
/// # R106-5 FIX: Graceful Fallback on Saturation
///
/// Previously panicked when the queue was full after MAILBOX_WAIT_SPINS.
/// Now returns `false` to signal the caller to fall back to a full TLB flush,
/// which is safe (though less efficient). Panicking on runtime queue pressure
/// was a user-triggerable DoS vector via rapid mmap/munmap churn.
///
/// Returns `true` if the request was successfully enqueued, `false` if the
/// queue is saturated and the caller should use a full-flush fallback.
fn enqueue_mailbox(
    mailbox: &TlbShootdownMailbox,
    cr3: u64,
    start: u64,
    len: u64,
    generation: u64,
) -> bool {
    const MAILBOX_WAIT_SPINS: usize = 500_000;
    let mut spins = 0usize;

    loop {
        let head = mailbox.head.load(Ordering::Acquire);
        let tail = mailbox.tail.load(Ordering::Acquire);

        // Check if queue has space: tail - head < queue_len
        if tail.wrapping_sub(head) < TLB_SHOOTDOWN_QUEUE_LEN as u64 {
            // Try to claim a slot with CAS on tail
            if mailbox
                .tail
                .compare_exchange_weak(tail, tail + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Successfully claimed slot, write entry
                let slot = (tail as usize) % TLB_SHOOTDOWN_QUEUE_LEN;
                let entry = &mailbox.entries[slot];

                // Write entry fields with Relaxed ordering
                entry.cr3.store(cr3, Ordering::Relaxed);
                entry.start.store(start, Ordering::Relaxed);
                entry.len.store(len, Ordering::Relaxed);

                // Publish entry by storing generation with Release
                entry.generation.store(generation, Ordering::Release);

                // Also update request_gen for compatibility with ACK waiting.
                // Use fetch_max to keep it monotonic under concurrent posters.
                mailbox
                    .request_gen
                    .fetch_max(generation, Ordering::Release);
                return true;
            }
            // CAS failed, retry
        } else {
            // Queue is full, need to wait
            spins += 1;
            if spins % 100_000 == 0 {
                kprintln!(
                    "[TLB] CPU shootdown queue full, waiting (head={}, tail={}, spins={})",
                    head,
                    tail,
                    spins
                );
            }
            if spins >= MAILBOX_WAIT_SPINS {
                // R106-5 FIX: Graceful fallback instead of panic.
                // Under runtime pressure (rapid mmap/munmap), signal the caller
                // to perform a full TLB flush rather than crashing the kernel.
                klog_always!(
                    "[TLB][R106-5] shootdown mailbox saturated (head={}, tail={}) after {} spins; falling back to full flush",
                    head,
                    tail,
                    MAILBOX_WAIT_SPINS
                );
                return false;
            }
        }

        spin_loop();
    }
}

/// Post shootdown requests to all target CPUs' mailboxes
///
/// # R72: Queue-Based Approach
///
/// Uses `enqueue_mailbox` to add requests to each CPU's queue, allowing
/// multiple requests to be batched without full serialization.
///
/// # R94-8 FIX: Fail-Fast on Missing Mailbox
///
/// Previously silently skipped CPUs with missing mailboxes. This created an
/// inconsistent security gap: no request was posted, so no ACK was expected,
/// making the shootdown appear to succeed without actually flushing that CPU's
/// TLB. Stale TLB entries could then point to freed memory → use-after-free.
///
/// Now panics if a target CPU's mailbox is missing, since:
/// 1. Target CPUs are collected from per-address-space tracking (only active CPUs)
/// 2. Every active CPU must have been initialized with a mailbox
/// 3. A missing mailbox for an active CPU indicates a critical initialization bug
///
/// # R106-5 FIX: Returns list of CPUs whose mailboxes were saturated
///
/// CPUs returned in this list need a full-flush fallback via the IPI handler.
/// For these CPUs, request_gen is advanced without a queue entry so the IPI
/// handler performs an implicit full flush when it sees request_gen > ack_gen.
fn post_requests(targets: &[usize], cr3: u64, start: u64, len: u64, generation: u64) -> Vec<usize> {
    let mut fallback_cpus = Vec::new();
    for &cpu in targets {
        // R94-8 FIX: A target CPU MUST have an initialized mailbox. If it doesn't,
        // this is a critical per-CPU initialization failure that would silently skip
        // TLB flushes, risking use-after-free from stale TLB entries.
        let mailbox = mailbox_for_cpu(cpu).unwrap_or_else(|| {
            panic!(
                "TLB shootdown: CPU {} is in target set but has no mailbox. \
                 This indicates a critical per-CPU initialization failure.",
                cpu
            )
        });
        if !enqueue_mailbox(mailbox, cr3, start, len, generation) {
            // R106-5 FIX: Queue saturated for this CPU. Advance request_gen so
            // the IPI handler performs a full flush when it sees the generation gap.
            mailbox
                .request_gen
                .fetch_max(generation, Ordering::Release);
            STATS_COALESCED_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            fallback_cpus.push(cpu);
        }
    }
    fallback_cpus
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
///
/// # R93-9 FIX: Fail-Closed ACK Handling
///
/// Previously used `.unwrap_or(true)` which treated missing CPU mailboxes as ACKed.
/// This was a security vulnerability: if a CPU's per-CPU data was not properly
/// initialized (race condition, memory corruption, etc.), the TLB shootdown would
/// consider it "done" without actually flushing that CPU's TLB. This could leave
/// stale TLB entries pointing to freed memory → use-after-free.
///
/// Now uses `.unwrap_or(false)` (fail-closed): if we cannot verify a CPU's ACK,
/// we assume it has NOT acked. Combined with the retry/panic logic in callers,
/// this ensures we never silently skip a CPU's TLB flush.
fn wait_for_acks(targets: &[usize], generation: u64) -> bool {
    for _ in 0..IPI_ACK_TIMEOUT_SPINS {
        let all_acked = targets.iter().all(|&cpu| {
            mailbox_for_cpu(cpu)
                .map(|m| m.ack_gen.load(Ordering::Acquire) >= generation)
                // R93-9 FIX: Fail-closed - missing mailbox means NOT acked
                .unwrap_or(false)
        });
        if all_acked {
            return true;
        }
        spin_loop();
    }
    false
}

/// Get list of CPUs that haven't ACKed yet
///
/// # R93-9 FIX: Fail-Closed Missing Mailbox
///
/// Previously used `.unwrap_or(false)` which excluded CPUs with missing mailboxes
/// from the unacked list. This was a security bug that complemented the fail-open
/// bug in `wait_for_acks`:
///
/// 1. wait_for_acks treats missing mailbox as acked (returns early "success")
/// 2. get_unacked_cpus excludes missing CPUs from unacked list (no retry/warning)
/// 3. Result: CPU with missing mailbox silently skipped, stale TLB remains
///
/// Now uses `.unwrap_or(true)` (fail-closed): if we cannot verify a CPU's ACK
/// status, we assume it has NOT acked and include it in the unacked list.
/// This ensures the retry logic and panic path catch the problem.
fn get_unacked_cpus(targets: &[usize], generation: u64) -> Vec<usize> {
    targets
        .iter()
        .filter(|&&cpu| {
            mailbox_for_cpu(cpu)
                .map(|m| m.ack_gen.load(Ordering::Relaxed) < generation)
                // R93-9 FIX: Fail-closed - missing mailbox means NOT acked
                .unwrap_or(true)
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
            kprintln!(
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

    kprintln!(
        "[WARN] TLB shootdown gen {} timed out waiting for ACK from CPUs {:?}",
        generation,
        missing
    );
}

/// Dispatch a TLB shootdown to remote CPUs
///
/// Returns dispatch metadata if there are remote CPUs to notify,
/// None if this is the only CPU.
///
/// # R68 Architecture Improvement
///
/// Now uses per-address-space tracking to target only CPUs that might have
/// TLB entries for the current CR3, reducing unnecessary IPI traffic.
///
/// # R106-5 FIX: Propagates mailbox saturation info
///
/// The returned `ShootdownDispatch` includes a list of CPUs whose mailboxes
/// were saturated. Callers should perform a full local flush when this list
/// is non-empty to ensure correctness.
struct ShootdownDispatch {
    targets: Vec<usize>,
    generation: u64,
    /// R106-5: CPUs that couldn't be enqueued (mailbox full); need full-flush fallback
    fallback_cpus: Vec<usize>,
}

fn dispatch_shootdown(start: u64, len: u64) -> Option<ShootdownDispatch> {
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

    // Post requests to all target mailboxes. Under mailbox saturation this may
    // return a list of CPUs that need a full-flush fallback (R106-5).
    let fallback_cpus = post_requests(&targets, cr3, start, len, generation);

    // Send IPIs to wake up targets
    send_ipis(&targets, sender);

    Some(ShootdownDispatch {
        targets,
        generation,
        fallback_cpus,
    })
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

/// P2-7 FIX: Pin execution to a stable CPU for TLB shootdown operations.
///
/// Under eventual preemption/migration support, a task performing a TLB
/// shootdown could migrate between dispatching IPIs and ACKing its own
/// mailbox. This would cause:
/// - Target set computed on CPU A but self-ACK on CPU B (wrong mailbox)
/// - Missed local TLB flush if range partially completed before migration
/// - Stale per-CPU mailbox reference pointing to wrong CPU's data
///
/// The pin guard disables preemption after verifying the CPU ID is stable,
/// using a retry loop to handle the race window between LAPIC ID read and
/// preempt_disable(). Preemption is re-enabled on drop.
struct ShootdownCpuPin {
    cpu_id: usize,
    /// PhantomData<*const ()> makes this type !Send + !Sync, preventing
    /// accidental cross-thread/cross-CPU movement or drop.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl ShootdownCpuPin {
    #[inline]
    fn new() -> Self {
        loop {
            let cpu_id = current_cpu_id();

            // Narrow the race window: if we were already migrated after
            // sampling cpu_id, retry without touching the stale CPU's
            // preemption counter.
            if current_cpu_id() != cpu_id {
                spin_loop();
                continue;
            }

            let per_cpu = PER_CPU_DATA
                .get_cpu(cpu_id)
                .unwrap_or_else(|| {
                    panic!("TLB shootdown: missing per-CPU slot for CPU {}", cpu_id)
                });

            per_cpu.preempt_disable();
            core::sync::atomic::compiler_fence(Ordering::SeqCst);

            if current_cpu_id() == cpu_id {
                return Self {
                    cpu_id,
                    _not_send: core::marker::PhantomData,
                };
            }

            // Migration detected — undo and retry on the correct CPU.
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            per_cpu.preempt_enable();
            spin_loop();
        }
    }

    #[inline]
    fn cpu_id(&self) -> usize {
        self.cpu_id
    }
}

impl Drop for ShootdownCpuPin {
    #[inline]
    fn drop(&mut self) {
        let per_cpu = PER_CPU_DATA.get_cpu(self.cpu_id).unwrap_or_else(|| {
            panic!(
                "TLB shootdown: missing per-CPU slot for CPU {}",
                self.cpu_id
            )
        });
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        per_cpu.preempt_enable();
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
    // P2-7 FIX: Pin to a stable CPU for the entire shootdown operation.
    let _pin = ShootdownCpuPin::new();

    assert_single_core_mode();

    // Dispatch to remote CPUs (if any)
    let shoot = dispatch_shootdown(0, 0);

    // Flush local TLB immediately using INVPCID if available
    flush_all_local();

    // Wait for remote ACKs with retry support
    if let Some(ShootdownDispatch { targets, generation, .. }) = shoot {
        // P2-7 FIX: Use mailbox_for_cpu() with pinned CPU ID instead of
        // current_cpu().tlb_mailbox() to prevent stale reference on migration.
        let local_mailbox = mailbox_for_cpu(_pin.cpu_id()).unwrap_or_else(|| {
            panic!(
                "TLB shootdown: missing local mailbox for CPU {}",
                _pin.cpu_id()
            )
        });
        if local_mailbox.request_gen.load(Ordering::Acquire) == generation {
            local_mailbox.ack_gen.store(generation, Ordering::Release);
        }

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
            // P2-7 FIX: Pin to a stable CPU for the entire range shootdown.
            let _pin = ShootdownCpuPin::new();

            // Dispatch to remote CPUs
            let shoot = dispatch_shootdown(aligned_start, aligned_len);

            // R106-5: Check if any target CPU's mailbox was saturated
            let needs_full_flush_fallback = shoot
                .as_ref()
                .map(|s| !s.fallback_cpus.is_empty())
                .unwrap_or(false);

            // Flush local TLB — use full flush if any mailbox was saturated
            if needs_full_flush_fallback {
                flush_all_local();
            } else {
                flush_range_local(aligned_start, aligned_len);
            }

            // Wait for remote ACKs with retry support
            if let Some(ShootdownDispatch { targets, generation, .. }) = shoot {
                // R71-4 FIX: Same self-ACK protection as flush_current_as_all.
                // Only ACK if the request_gen matches to avoid accidentally
                // acknowledging a foreign request.
                // P2-7 FIX: Use mailbox_for_cpu() with pinned CPU ID.
                let local_mailbox = mailbox_for_cpu(_pin.cpu_id()).unwrap_or_else(|| {
                    panic!(
                        "TLB shootdown: missing local mailbox for CPU {}",
                        _pin.cpu_id()
                    )
                });
                if local_mailbox.request_gen.load(Ordering::Acquire) == generation {
                    local_mailbox.ack_gen.store(generation, Ordering::Release);
                }

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

            // R106-5: Track stats based on whether fallback was used
            if needs_full_flush_fallback {
                STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
            } else {
                STATS_RANGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
                STATS_PAGES_FLUSHED.fetch_add(pages, Ordering::Relaxed);
            }
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
        coalesced_fallbacks: STATS_COALESCED_FALLBACKS.load(Ordering::Relaxed),
    }
}

/// Handle an incoming TLB shootdown IPI on the current CPU.
///
/// # R72: Queue-Based Draining
///
/// Drains the per-CPU mailbox queue in FIFO order. For each entry:
/// 1. Loads the entry generation with Acquire
/// 2. Reads flush parameters (CR3, start, len)
/// 3. Performs the appropriate TLB flush if CR3 matches
/// 4. ACKs the generation and clears the entry
/// 5. Advances the queue head
///
/// This processes all pending requests, not just the latest, ensuring
/// no flush is dropped.
///
/// # Safety
///
/// Must be called from interrupt context with interrupts disabled.
pub fn handle_shootdown_ipi() {
    let mailbox = current_cpu().tlb_mailbox();
    let this_cr3 = current_cr3_value();

    // Drain all pending requests from the queue
    loop {
        let head = mailbox.head.load(Ordering::Acquire);
        let tail = mailbox.tail.load(Ordering::Acquire);

        // Check if queue is empty
        if head >= tail {
            break; // Queue drained — fall through to the request_gen gap check
        }

        let slot = (head as usize) % TLB_SHOOTDOWN_QUEUE_LEN;
        let entry = &mailbox.entries[slot];

        // Load generation with Acquire to synchronize with producer's Release
        let generation = entry.generation.load(Ordering::Acquire);
        if generation == 0 {
            // Entry not yet published, spin briefly and retry
            spin_loop();
            continue;
        }

        // Read flush parameters (Relaxed is fine, synchronized by generation Acquire)
        let target_cr3 = entry.cr3.load(Ordering::Relaxed);
        let len = entry.len.load(Ordering::Relaxed);
        let start = entry.start.load(Ordering::Relaxed);

        // R74-1 FIX: Always invalidate TLB before ACKing.
        //
        // With PCID enabled, a CPU may have stale TLB entries for an address space
        // it previously ran but is not currently running. If we only flush when
        // target_cr3 == this_cr3, we leave stale entries intact that become active
        // on context switch back to that CR3, enabling use-after-free and W^X bypass.
        //
        // Security fix: Always perform a flush. When the target address space is not
        // currently active, fall back to flushing all non-global entries to ensure
        // any cached entries for target_cr3 are invalidated.
        if len == 0 || target_cr3 == 0 {
            // Full TLB flush requested or unconditional flush
            flush_all_local();
        } else if target_cr3 == this_cr3 {
            // Target address space is currently active - range flush is safe
            flush_range_local(start, len);
        } else {
            // R74-1 FIX: Target address space not currently running here.
            // We may have stale entries from a previous execution of this CR3.
            // Flush all non-global entries (all PCIDs) to ensure no stale
            // translations survive. This is more expensive but necessary for
            // security when PCID is enabled.
            flush_all_local();
        }

        // ACK this generation (only if it advances ack_gen - ensures monotonicity)
        // This prevents race where out-of-order processing could cause ack_gen
        // to decrease, confusing waiters.
        let current_ack = mailbox.ack_gen.load(Ordering::Acquire);
        if generation > current_ack {
            mailbox.ack_gen.store(generation, Ordering::Release);
        }

        // Clear entry and advance head
        entry.generation.store(0, Ordering::Release);
        mailbox.head.store(head + 1, Ordering::Release);
    }

    // R106-5 FIX: Implicit full-flush fallback for saturated mailbox.
    // When a requester couldn't enqueue (queue full), it advanced request_gen
    // without a queue entry. Detect this case and perform a full flush.
    let requested = mailbox.request_gen.load(Ordering::Acquire);
    let acked = mailbox.ack_gen.load(Ordering::Acquire);
    if requested > acked {
        flush_all_local();
        mailbox.ack_gen.store(requested, Ordering::Release);
    }
}
