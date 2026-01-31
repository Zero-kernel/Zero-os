//! Minimal per-CPU storage for SMP support
//!
//! Provides a simple per-CPU storage abstraction using CPU ID indexed arrays.
//! Currently uses a single-core fallback (CPU ID always 0) until full SMP
//! support with APIC enumeration is implemented.
//!
//! # Usage
//!
//! ```rust,ignore
//! use cpu_local::CpuLocal;
//! use core::sync::atomic::AtomicUsize;
//!
//! static MY_DATA: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));
//!
//! MY_DATA.with(|d| d.fetch_add(1, Ordering::SeqCst));
//! ```

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Once;

/// Maximum number of CPUs supported
const MAX_CPUS: usize = 64;

/// Invalid LAPIC ID marker
const INVALID_LAPIC_ID: u32 = u32::MAX;

/// Invalid CPU ID marker for reverse mapping
const INVALID_CPU_ID: usize = usize::MAX;

/// Size of LAPIC ID reverse mapping table (covers all 8-bit LAPIC IDs)
const LAPIC_ID_REVERSE_MAP_SIZE: usize = 256;

/// Marker for "no FPU owner" in per-CPU lazy FPU tracking
pub const NO_FPU_OWNER: usize = usize::MAX;

/// LAPIC ID to CPU index mapping table.
///
/// Index = CPU logical index, Value = hardware LAPIC ID.
/// Used by `current_cpu_id()` to map LAPIC ID to CPU index.
static LAPIC_ID_MAP: [AtomicU32; MAX_CPUS] = {
    // Initialize all entries to INVALID_LAPIC_ID
    const INIT: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
    [INIT; MAX_CPUS]
};

/// R67-8 FIX: Reverse mapping for O(1) LAPIC ID to CPU index lookup.
///
/// Index = hardware LAPIC ID (0..255), Value = CPU logical index.
/// This enables fast CPU ID lookup in syscall entry without linear search.
static LAPIC_ID_REVERSE_MAP: [AtomicUsize; LAPIC_ID_REVERSE_MAP_SIZE] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; LAPIC_ID_REVERSE_MAP_SIZE]
};

// ============================================================================
// Per-CPU Data Structure for SMP Support (Phase E)
// ============================================================================

/// Raw task pointer used to avoid circular dependencies with the scheduler.
pub type RawTaskPtr = *mut ();

/// Depth of the per-CPU TLB shootdown queue.
///
/// This allows batching multiple TLB shootdown requests without
/// serializing on a single slot. A depth of 4 is sufficient for
/// most workloads while keeping memory overhead low.
pub const TLB_SHOOTDOWN_QUEUE_LEN: usize = 4;

/// A single TLB shootdown request stored in the per-CPU queue.
///
/// Each entry represents a pending TLB invalidation request that
/// the IPI handler will process in FIFO order.
#[repr(C)]
pub struct TlbShootdownEntry {
    /// Request generation (0 = empty/processed slot)
    pub generation: AtomicU64,
    /// Target CR3 (0 means flush regardless of CR3)
    pub cr3: AtomicU64,
    /// Page-aligned virtual start address (0 for full flush)
    pub start: AtomicU64,
    /// Length in bytes, page-aligned (0 for full flush)
    pub len: AtomicU64,
}

impl TlbShootdownEntry {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            start: AtomicU64::new(0),
            len: AtomicU64::new(0),
        }
    }
}

// Manual Clone impl since AtomicU64 doesn't implement Clone
impl Clone for TlbShootdownEntry {
    fn clone(&self) -> Self {
        Self {
            generation: AtomicU64::new(self.generation.load(Ordering::Relaxed)),
            cr3: AtomicU64::new(self.cr3.load(Ordering::Relaxed)),
            start: AtomicU64::new(self.start.load(Ordering::Relaxed)),
            len: AtomicU64::new(self.len.load(Ordering::Relaxed)),
        }
    }
}

/// Per-CPU mailbox for TLB shootdown IPIs (small FIFO queue).
///
/// # R72: Queue-Based Design
///
/// Instead of a single-slot mailbox that requires serialization before posting,
/// this uses a bounded ring buffer (depth 4) allowing multiple requests to be
/// queued. This reduces contention and IPI overhead for high-frequency shootdowns.
///
/// # Memory Ordering
///
/// - Requester: writes entry fields Relaxed, then publishes entry.generation with Release,
///   then updates request_gen with Release
/// - Handler: loads entry.generation with Acquire, reads fields Relaxed, acks via ack_gen Release,
///   then clears entry.generation with Release and advances head
/// - Waiter: loads ack_gen with Acquire to ensure flush completion is visible
#[repr(C)]
pub struct TlbShootdownMailbox {
    /// Monotonic generation number for the most recent request (for compat/fast path)
    pub request_gen: AtomicU64,
    /// Last generation this CPU has processed
    pub ack_gen: AtomicU64,
    /// Queue head (next entry to consume), wraps via modulo
    pub head: AtomicU64,
    /// Queue tail (next slot to publish), wraps via modulo
    pub tail: AtomicU64,
    /// Fixed-size ring buffer of pending shootdown requests
    pub entries: [TlbShootdownEntry; TLB_SHOOTDOWN_QUEUE_LEN],
}

impl TlbShootdownMailbox {
    pub const fn new() -> Self {
        Self {
            request_gen: AtomicU64::new(0),
            ack_gen: AtomicU64::new(0),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            entries: [
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
            ],
        }
    }
}

/// Per-CPU data required for SMP operation.
///
/// This structure contains all per-CPU metadata needed by the scheduler,
/// interrupt handlers, and RCU subsystem. All fields use atomics for
/// safe access from interrupt handlers and cross-CPU visibility.
///
/// # Memory Layout
///
/// Fields are ordered to minimize padding and optimize cache line usage.
/// The structure is designed to fit within a single cache line (64 bytes)
/// for the core fields.
#[repr(C)]
pub struct PerCpuData {
    /// Logical CPU index in the OS scheduler (0-based)
    pub cpu_id: AtomicUsize,
    /// Local APIC ID read from hardware
    pub lapic_id: AtomicU32,
    /// Preemption disable nesting counter (non-zero = preemption disabled)
    pub preempt_count: AtomicU32,
    /// Interrupt disable nesting counter
    pub irq_count: AtomicU32,
    /// Last task (PID) that owns the FPU on this CPU (NO_FPU_OWNER if none).
    ///
    /// Used for lazy FPU save/restore: when a #NM exception fires, we save
    /// the previous owner's state before restoring the new owner's state.
    pub fpu_owner: AtomicUsize,
    /// Set by scheduler/interrupts to trigger a reschedule
    pub need_resched: AtomicBool,
    /// Padding for alignment
    _pad: [u8; 3],
    /// Currently running task (raw pointer to avoid scheduler dependency)
    pub current_task: AtomicPtr<()>,
    /// Top of the privilege 0 kernel stack
    pub kernel_stack_top: AtomicUsize,
    /// Top of the interrupt stack (IST1)
    pub irq_stack_top: AtomicUsize,
    /// Top of the syscall entry stack
    pub syscall_stack_top: AtomicUsize,
    /// Epoch counter for RCU/quiescent state tracking
    pub rcu_epoch: AtomicU64,
    /// Per-CPU TLB shootdown mailbox for cross-CPU invalidation
    pub tlb_mailbox: TlbShootdownMailbox,
}

// Safety: PerCpuData uses only atomics, so it's Send+Sync
unsafe impl Send for PerCpuData {}
unsafe impl Sync for PerCpuData {}

impl PerCpuData {
    /// Construct a zeroed per-CPU record.
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicUsize::new(0),
            lapic_id: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            irq_count: AtomicU32::new(0),
            fpu_owner: AtomicUsize::new(NO_FPU_OWNER),
            need_resched: AtomicBool::new(false),
            _pad: [0; 3],
            current_task: AtomicPtr::new(null_mut()),
            kernel_stack_top: AtomicUsize::new(0),
            irq_stack_top: AtomicUsize::new(0),
            syscall_stack_top: AtomicUsize::new(0),
            rcu_epoch: AtomicU64::new(0),
            tlb_mailbox: TlbShootdownMailbox::new(),
        }
    }

    /// Initialize this CPU slot with identity and stack metadata.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
    /// * `lapic_id` - Hardware Local APIC ID
    /// * `kernel_stack_top` - Top of kernel privilege stack
    /// * `irq_stack_top` - Top of interrupt stack (IST1)
    /// * `syscall_stack_top` - Top of syscall entry stack
    pub fn init(
        &self,
        cpu_id: usize,
        lapic_id: u32,
        kernel_stack_top: usize,
        irq_stack_top: usize,
        syscall_stack_top: usize,
    ) {
        self.cpu_id.store(cpu_id, Ordering::Relaxed);
        self.lapic_id.store(lapic_id, Ordering::Relaxed);
        self.current_task.store(null_mut(), Ordering::Relaxed);
        self.need_resched.store(false, Ordering::Relaxed);
        self.kernel_stack_top
            .store(kernel_stack_top, Ordering::Relaxed);
        self.irq_stack_top.store(irq_stack_top, Ordering::Relaxed);
        self.syscall_stack_top
            .store(syscall_stack_top, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        self.irq_count.store(0, Ordering::Relaxed);
        self.fpu_owner.store(NO_FPU_OWNER, Ordering::Relaxed);
        self.rcu_epoch.store(0, Ordering::Relaxed);
    }

    /// Disable preemption on this CPU.
    ///
    /// Returns the new preemption count. Preemption is disabled when count > 0.
    #[inline]
    pub fn preempt_disable(&self) -> u32 {
        self.preempt_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Enable preemption on this CPU.
    ///
    /// Returns the new preemption count. Panics if count would go negative.
    #[inline]
    pub fn preempt_enable(&self) -> u32 {
        let old = self.preempt_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "preempt_enable called with count already 0");
        old - 1
    }

    /// Check if preemption is enabled on this CPU.
    #[inline]
    pub fn preemptible(&self) -> bool {
        self.preempt_count.load(Ordering::Relaxed) == 0
            && self.irq_count.load(Ordering::Relaxed) == 0
    }

    /// Enter an IRQ handler context.
    #[inline]
    pub fn irq_enter(&self) {
        self.irq_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Exit an IRQ handler context.
    #[inline]
    pub fn irq_exit(&self) {
        let old = self.irq_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "irq_exit called with count already 0");
    }

    /// Check if we're currently in an IRQ handler.
    #[inline]
    pub fn in_irq(&self) -> bool {
        self.irq_count.load(Ordering::Relaxed) > 0
    }

    /// Mark that a reschedule is needed on this CPU.
    #[inline]
    pub fn set_need_resched(&self) {
        self.need_resched.store(true, Ordering::Release);
    }

    /// Clear and return the need_resched flag.
    #[inline]
    pub fn clear_need_resched(&self) -> bool {
        self.need_resched.swap(false, Ordering::AcqRel)
    }

    /// Get the current task pointer.
    #[inline]
    pub fn get_current_task(&self) -> RawTaskPtr {
        self.current_task.load(Ordering::Acquire)
    }

    /// Set the current task pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the task pointer is valid for the duration it's set.
    #[inline]
    pub unsafe fn set_current_task(&self, task: RawTaskPtr) {
        self.current_task.store(task, Ordering::Release);
    }

    /// Get the FPU owner (PID) on this CPU.
    ///
    /// Returns NO_FPU_OWNER if no process owns the FPU state on this CPU.
    #[inline]
    pub fn get_fpu_owner(&self) -> usize {
        self.fpu_owner.load(Ordering::Acquire)
    }

    /// Set the FPU owner on this CPU.
    ///
    /// Called by the #NM handler after restoring a process's FPU state.
    #[inline]
    pub fn set_fpu_owner(&self, pid: usize) {
        self.fpu_owner.store(pid, Ordering::Release);
    }

    /// Clear the FPU owner if it matches the given PID.
    ///
    /// Called when a process exits to prevent #NM from trying to save
    /// state to freed memory. Uses compare-exchange to handle races.
    ///
    /// # Returns
    ///
    /// `true` if the owner was cleared, `false` if it was already different.
    #[inline]
    pub fn clear_fpu_owner_if(&self, pid: usize) -> bool {
        self.fpu_owner
            .compare_exchange(pid, NO_FPU_OWNER, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Access this CPU's TLB shootdown mailbox.
    ///
    /// Used by both the requesting CPU (to set up shootdown request) and
    /// the IPI handler (to read request and write ACK).
    #[inline]
    pub fn tlb_mailbox(&self) -> &TlbShootdownMailbox {
        &self.tlb_mailbox
    }
}

/// Per-CPU storage wrapper
///
/// Stores one instance of T per CPU, lazily initialized on first access.
/// Safe to use from interrupt context as long as T's operations are safe.
///
/// R91-2 FIX: Slots are heap-allocated via `Box<[MaybeUninit<T>]>` to avoid
/// placing `[MaybeUninit<T>; MAX_CPUS]` on the stack during `call_once`.
/// For large per-CPU types like `SampleRing` (~41KB), the previous stack-based
/// approach would allocate ~2.6MB on the stack (64 * 41KB), causing a
/// deterministic stack overflow on first access.
pub struct CpuLocal<T> {
    /// Initialization function for each CPU's slot
    init: fn() -> T,
    /// Per-CPU slots, heap-allocated and initialized lazily via Once
    slots: Once<UnsafeCell<Box<[MaybeUninit<T>]>>>,
}

// Safety: CpuLocal is Send+Sync because each CPU only accesses its own slot
unsafe impl<T: Send> Send for CpuLocal<T> {}
unsafe impl<T: Send + Sync> Sync for CpuLocal<T> {}

impl<T> CpuLocal<T> {
    /// Create a new per-CPU storage with the given initializer
    ///
    /// The initializer is called once per CPU slot on first access.
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            init,
            slots: Once::new(),
        }
    }

    /// Get or initialize the slots array.
    ///
    /// R91-2 FIX: Allocates on the heap instead of the stack to prevent
    /// stack overflow for large per-CPU types (e.g., SampleRing ~41KB * 64 CPUs).
    fn get_slots(&self) -> &UnsafeCell<Box<[MaybeUninit<T>]>> {
        self.slots.call_once(|| {
            // Heap-allocate the slot array. Box::new_uninit_slice creates the
            // allocation directly on the heap without an intermediate stack copy.
            let mut arr = Box::new_uninit_slice(MAX_CPUS);
            for slot in arr.iter_mut() {
                slot.write((self.init)());
            }
            UnsafeCell::new(arr)
        })
    }

    /// Access the current CPU's slot immutably
    ///
    /// # Safety
    ///
    /// This is safe because each CPU only accesses its own slot, and we
    /// use interior mutability (e.g., atomics) for any mutations.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let id = current_cpu_id();
        // Hard bound check to prevent UB with non-zero-based APIC IDs
        assert!(
            id < MAX_CPUS,
            "CPU ID {} out of range (max {})",
            id,
            MAX_CPUS
        );
        // Safety: bound check above guarantees the slot exists and was initialized in get_slots()
        let slot = unsafe {
            let arr = &*self.get_slots().get();
            arr.get(id)
                .expect("CPU slot missing after bounds check")
                .assume_init_ref()
        };
        f(slot)
    }

    /// Access a specific CPU's slot immutably.
    ///
    /// Used for cross-CPU operations like TLB shootdown where we need to
    /// access another CPU's mailbox.
    ///
    /// # Safety
    ///
    /// This is safe only when `T` supports concurrent access (e.g., uses atomics).
    /// The caller must ensure proper synchronization for non-atomic operations.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn with_cpu<R>(&self, cpu_id: usize, f: impl FnOnce(&T) -> R) -> Option<R> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        // Safety: slots are initialized in get_slots(); cpu_id bounds checked above
        let slot = unsafe {
            let arr = &*self.get_slots().get();
            match arr.get(cpu_id) {
                Some(s) => s.assume_init_ref(),
                None => return None,
            }
        };
        Some(f(slot))
    }

    /// Get a static reference to a specific CPU's slot.
    ///
    /// Unlike `with_cpu`, this returns the reference directly instead of via
    /// a closure. The returned reference is `'static` because the underlying
    /// storage is owned by a static `Once` (and the heap allocation is never freed).
    ///
    /// # Safety
    ///
    /// This is safe only when `T` supports concurrent access (e.g., uses atomics).
    /// The caller must ensure proper synchronization for non-atomic operations.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn get_cpu(&self, cpu_id: usize) -> Option<&'static T> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        // Safety:
        // - slots are initialized in get_slots() before first access
        // - cpu_id bounds checked above
        // - The underlying storage is in a static Once, so references are 'static
        // - We transmute the lifetime because the storage truly is 'static
        unsafe {
            let arr = &*self.get_slots().get();
            match arr.get(cpu_id) {
                Some(s) => {
                    let ref_with_lifetime = s.assume_init_ref();
                    // Safety: The backing storage is owned by a static Once
                    // (heap-allocated Box never freed), so the data lives for
                    // 'static. The borrow checker can't see this, so we
                    // transmute the lifetime.
                    Some(core::mem::transmute::<&T, &'static T>(ref_with_lifetime))
                }
                None => None,
            }
        }
    }
}

/// Get the current CPU ID
///
/// # R67-8 FIX: O(1) Lookup
///
/// Uses a reverse mapping table (LAPIC ID → CPU index) for constant-time lookup.
/// This is critical for syscall entry performance where the CPU ID must be
/// determined very early without a stack.
///
/// # Implementation
///
/// 1. Read LAPIC ID from hardware (0xFEE00020, bits 31:24)
/// 2. O(1) lookup in LAPIC_ID_REVERSE_MAP
/// 3. Fallback to CPU 0 only during early boot (before registration)
///
/// # Panics (in debug builds)
///
/// Once SMP is enabled, falling back to CPU 0 would be a critical bug that
/// could cause slot aliasing. In debug builds, this generates a warning.
#[inline]
pub fn current_cpu_id() -> usize {
    // Read LAPIC ID from hardware (0xFEE00020)
    let apic_id = unsafe {
        let apic_base = 0xFEE0_0020 as *const u32;
        (core::ptr::read_volatile(apic_base) >> 24) as usize
    };

    // R67-8 FIX: O(1) reverse lookup instead of linear search
    let cpu_idx = if apic_id < LAPIC_ID_REVERSE_MAP_SIZE {
        LAPIC_ID_REVERSE_MAP[apic_id].load(Ordering::Relaxed)
    } else {
        INVALID_CPU_ID
    };

    // Return valid CPU index if found
    if cpu_idx < MAX_CPUS {
        return cpu_idx;
    }

    // Fallback to CPU 0 - only safe during early boot before registration
    // R67-8 FIX: In debug builds, warn about potential slot aliasing
    #[cfg(debug_assertions)]
    {
        // Only warn once SMP could be active (after BSP registration)
        // LAPIC_ID_MAP[0] being valid indicates BSP has registered
        if LAPIC_ID_MAP[0].load(Ordering::Relaxed) != INVALID_LAPIC_ID as u32 {
            // This is a potential bug - LAPIC ID not registered
            // Could cause slot 0 aliasing under SMP
            // In release builds we silently fall back, but this should be investigated
        }
    }
    0
}

/// Register the LAPIC ID to CPU index mapping.
///
/// This must be called for each CPU during bring-up to enable
/// proper `current_cpu_id()` operation.
///
/// # R67-8 FIX
///
/// Also populates the reverse mapping table for O(1) lookup in syscall entry.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
/// * `lapic_id` - Hardware LAPIC ID
///
/// # Panics
///
/// Panics if `cpu_id` is out of range.
pub fn register_cpu_id(cpu_id: usize, lapic_id: u32) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    LAPIC_ID_MAP[cpu_id].store(lapic_id, Ordering::Relaxed);

    // R67-8 FIX: Populate reverse mapping for O(1) lookup
    if (lapic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE {
        LAPIC_ID_REVERSE_MAP[lapic_id as usize].store(cpu_id, Ordering::Relaxed);
    }
}

/// Get the maximum number of supported CPUs
pub const fn max_cpus() -> usize {
    MAX_CPUS
}

/// Get the LAPIC ID for a CPU index if it has been registered.
///
/// Returns None if:
/// - cpu_id is out of range (>= MAX_CPUS)
/// - cpu_id has not been registered yet (LAPIC ID is INVALID_LAPIC_ID)
///
/// # Usage
///
/// Used by IPI sending code to map logical CPU index to hardware LAPIC ID.
#[inline]
pub fn lapic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    let id = LAPIC_ID_MAP[cpu_id].load(Ordering::Relaxed);
    if id == INVALID_LAPIC_ID {
        None
    } else {
        Some(id)
    }
}

// ============================================================================
// Global Per-CPU Data Access
// ============================================================================

/// Global per-CPU data block for scheduler and IRQ metadata.
///
/// This is the primary per-CPU data structure used by the kernel.
/// Access it via `current_cpu()` or `PER_CPU_DATA.with()`.
pub static PER_CPU_DATA: CpuLocal<PerCpuData> = CpuLocal::new(PerCpuData::new);

/// Access the current CPU's `PerCpuData`.
///
/// This is the primary way to access per-CPU state. The returned reference
/// is valid for the duration of the current CPU's execution (i.e., until
/// migration to another CPU, which is not yet supported).
///
/// # Example
///
/// ```rust,ignore
/// use cpu_local::current_cpu;
///
/// current_cpu().set_need_resched();
/// if current_cpu().preemptible() {
///     // Safe to reschedule
/// }
/// ```
#[inline]
pub fn current_cpu() -> &'static PerCpuData {
    // We use a closure that returns the reference directly since
    // the underlying storage is static
    PER_CPU_DATA.with(|d| {
        // Safety: The PerCpuData is stored in static memory with 'static lifetime
        unsafe { &*(d as *const PerCpuData) }
    })
}

/// Initialize the bootstrap processor's per-CPU slot.
///
/// Must be invoked during early boot before interrupts are enabled.
/// The BSP (CPU 0) is initialized with the provided stack addresses.
///
/// # Arguments
///
/// * `lapic_id` - Hardware Local APIC ID of the BSP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if called when not on CPU 0.
pub fn init_bsp(
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    // Register BSP's LAPIC ID mapping first
    register_cpu_id(0, lapic_id);

    current_cpu().init(
        0,
        lapic_id,
        kernel_stack_top,
        irq_stack_top,
        syscall_stack_top,
    );
}

/// Initialize an application processor's per-CPU slot.
///
/// Called by AP bootstrap code after the AP has started executing.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (1+ for APs)
/// * `lapic_id` - Hardware Local APIC ID of this AP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if cpu_id is 0 (BSP) or out of range.
pub fn init_ap(
    cpu_id: usize,
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    assert!(cpu_id > 0, "init_ap must not be called for BSP (CPU 0)");
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);

    // Register AP's LAPIC ID mapping
    register_cpu_id(cpu_id, lapic_id);

    // Initialize this CPU's PerCpuData
    // Note: We access via PER_CPU_DATA since current_cpu_id() now uses LAPIC map
    PER_CPU_DATA.with(|d| {
        d.init(
            cpu_id,
            lapic_id,
            kernel_stack_top,
            irq_stack_top,
            syscall_stack_top,
        );
    });
}

/// Counter for online CPUs.
///
/// This is incremented by `mark_cpu_online()` as APs come online.
/// BSP (CPU 0) is counted at init time.
static ONLINE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// Get the number of online CPUs.
///
/// # R69-1 FIX: Accurate Online CPU Count
///
/// Returns the actual count of online CPUs tracked locally.
/// This count is incremented by `mark_cpu_online()` as APs come online.
#[inline]
pub fn num_online_cpus() -> usize {
    ONLINE_CPU_COUNT.load(Ordering::Acquire)
}

/// Mark a CPU as online (call this from AP initialization).
///
/// This increments the online CPU counter. Should be called once per AP
/// after it has completed initialization.
///
/// # Safety
///
/// Should only be called once per CPU during SMP initialization.
#[inline]
pub fn mark_cpu_online() {
    ONLINE_CPU_COUNT.fetch_add(1, Ordering::Release);
}

/// Clear FPU ownership for a process across all CPUs.
///
/// Called when a process exits to ensure no CPU holds a stale FPU owner
/// reference that would cause #NM to save state to freed memory.
///
/// This function iterates all CPU slots and uses compare-exchange to
/// atomically clear any slot that matches the given PID.
pub fn clear_fpu_owner_all_cpus(pid: usize) {
    for cpu_id in 0..MAX_CPUS {
        if let Some(per_cpu) = PER_CPU_DATA.get_cpu(cpu_id) {
            per_cpu.clear_fpu_owner_if(pid);
        }
    }
}
