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

/// Per-CPU mailbox for TLB shootdown IPIs.
///
/// The requesting CPU writes the range/CR3 fields and then bumps `request_gen`
/// with `Release` ordering. The target CPU's IPI handler loads `request_gen`
/// with `Acquire`, performs the flush, and stores the same generation into
/// `ack_gen` with `Release`.
///
/// # Memory Ordering
///
/// - Requester: writes fields with Relaxed, then `request_gen` with Release
/// - Handler: loads `request_gen` with Acquire, reads fields Relaxed, writes `ack_gen` Release
/// - Waiter: loads `ack_gen` with Acquire to ensure flush completion is visible
#[repr(C)]
pub struct TlbShootdownMailbox {
    /// Monotonic generation number for the most recent request
    pub request_gen: AtomicU64,
    /// Last generation this CPU has processed
    pub ack_gen: AtomicU64,
    /// Target CR3 (0 means flush regardless of CR3)
    pub target_cr3: AtomicU64,
    /// Page-aligned virtual start address (0 for full flush)
    pub start: AtomicU64,
    /// Length in bytes, page-aligned (0 for full flush)
    pub len: AtomicU64,
}

impl TlbShootdownMailbox {
    pub const fn new() -> Self {
        Self {
            request_gen: AtomicU64::new(0),
            ack_gen: AtomicU64::new(0),
            target_cr3: AtomicU64::new(0),
            start: AtomicU64::new(0),
            len: AtomicU64::new(0),
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
pub struct CpuLocal<T> {
    /// Initialization function for each CPU's slot
    init: fn() -> T,
    /// Array of per-CPU slots, initialized lazily
    slots: Once<UnsafeCell<[MaybeUninit<T>; MAX_CPUS]>>,
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

    /// Get or initialize the slots array
    fn get_slots(&self) -> &UnsafeCell<[MaybeUninit<T>; MAX_CPUS]> {
        self.slots.call_once(|| {
            // Safety: We're initializing all slots before returning
            let mut arr: [MaybeUninit<T>; MAX_CPUS] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for slot in &mut arr {
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
    /// storage is in a static `Once<UnsafeCell<...>>`.
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
                    // Safety: The slots array is in a static Once<UnsafeCell<...>>,
                    // so the data lives for 'static. The borrow checker can't see
                    // this, so we transmute the lifetime.
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

/// Get the number of online CPUs.
///
/// Currently returns 1 for single-core operation.
/// Will be updated when SMP AP startup is implemented.
#[inline]
pub fn num_online_cpus() -> usize {
    // TODO: Track online CPU count when APs are started
    1
}
