//! 全局描述符表 (GDT) 和任务状态段 (TSS) 初始化
//!
//! 提供用户态到内核态的安全切换，包括双重错误的 IST 栈支持。
//!
//! ## 功能
//! - GDT 包含内核/用户代码和数据段
//! - TSS 提供特权级栈切换 (Ring 3 -> Ring 0)
//! - IST (中断栈表) 为双重错误提供独立栈
//!
//! ## SMP Support (R70-3)
//! - Each CPU has its own TSS (required because TSS is marked "busy" after LTR)
//! - Each CPU has its own GDT (because TSS descriptor points to per-CPU TSS)
//! - Segment selectors are identical across all CPUs

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;
use x86_64::{
    instructions::tables::load_tss,
    registers::segmentation::{Segment, CS, DS, SS},
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

/// Maximum supported CPUs
const MAX_CPUS: usize = 64;

/// IST 索引：双重错误处理程序使用的栈
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// R148-I5 FIX: IST index for NMI handler.
/// NMI can fire at any point (including inside other exception handlers).
/// Without a dedicated stack, an NMI during a near-full kernel stack path
/// (e.g., page fault handler) could overflow and corrupt the interrupted
/// handler's stack frame.
pub const NMI_IST_INDEX: u16 = 1;

/// 特权级栈索引 (用于 Ring 3 -> Ring 0 切换)
const KERNEL_PRIVILEGE_STACK_INDEX: usize = 0;

/// 内核栈大小 (64 KB)
pub const KERNEL_STACK_SIZE: usize = 16 * 4096;

/// 双重错误 IST 栈大小 (32 KB)
pub const DOUBLE_FAULT_STACK_SIZE: usize = 8 * 4096;

/// R148-I5 FIX: NMI IST stack size (32 KB, matches double-fault for consistency)
pub const NMI_STACK_SIZE: usize = 8 * 4096;

/// Page-aligned kernel stack structure.
///
/// R148-4 FIX: Changed from 16-byte to 4096-byte alignment so that the
/// bottom page of AP IST stacks can be unmapped as a guard page without
/// affecting adjacent .bss data.
#[repr(C, align(4096))]
struct AlignedStack<const SIZE: usize>([u8; SIZE]);

/// BSP 内核特权栈 (用于 syscall/中断时的栈切换)
static mut BSP_KERNEL_STACK: AlignedStack<KERNEL_STACK_SIZE> = AlignedStack([0; KERNEL_STACK_SIZE]);

/// BSP 双重错误独立栈 (防止栈溢出导致三重错误)
static mut BSP_DOUBLE_FAULT_STACK: AlignedStack<DOUBLE_FAULT_STACK_SIZE> =
    AlignedStack([0; DOUBLE_FAULT_STACK_SIZE]);

/// R148-I5 FIX: BSP NMI IST stack
static mut BSP_NMI_STACK: AlignedStack<NMI_STACK_SIZE> = AlignedStack([0; NMI_STACK_SIZE]);

/// R145-6 FIX: Per-AP dedicated double-fault IST stacks.  Without these,
/// APs reuse their kernel stack for #DF handling, so a stack overflow
/// triggers #PF → #DF on the same corrupted stack → triple fault.
/// Uses AlignedStack to guarantee 16-byte alignment for x86-interrupt ABI.
static mut AP_DOUBLE_FAULT_STACKS: [AlignedStack<DOUBLE_FAULT_STACK_SIZE>; MAX_CPUS] = {
    const INIT: AlignedStack<DOUBLE_FAULT_STACK_SIZE> = AlignedStack([0; DOUBLE_FAULT_STACK_SIZE]);
    [INIT; MAX_CPUS]
};

/// R148-I5 FIX: Per-AP dedicated NMI IST stacks.
static mut AP_NMI_STACKS: [AlignedStack<NMI_STACK_SIZE>; MAX_CPUS] = {
    const INIT: AlignedStack<NMI_STACK_SIZE> = AlignedStack([0; NMI_STACK_SIZE]);
    [INIT; MAX_CPUS]
};

/// 段选择子集合
#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    /// 内核代码段选择子 (Ring 0)
    pub kernel_code: SegmentSelector,
    /// 内核数据段选择子 (Ring 0)
    pub kernel_data: SegmentSelector,
    /// 用户代码段选择子 (Ring 3)
    pub user_code: SegmentSelector,
    /// 用户数据段选择子 (Ring 3)
    pub user_data: SegmentSelector,
    /// TSS 段选择子
    pub tss: SegmentSelector,
}

// ============================================================================
// Per-CPU TSS and GDT Storage (R70-3 FIX)
// ============================================================================

/// Per-CPU TSS storage.
///
/// Each CPU must have its own TSS because:
/// 1. TSS is marked "busy" after LTR instruction
/// 2. Each CPU needs its own RSP0 for privilege level transitions
/// 3. Each CPU needs its own IST stacks for exception handling
static mut PER_CPU_TSS: [TaskStateSegment; MAX_CPUS] = {
    const INIT: TaskStateSegment = TaskStateSegment::new();
    [INIT; MAX_CPUS]
};

/// Per-CPU GDT storage.
///
/// Each CPU needs its own GDT because the TSS descriptor points to
/// that CPU's specific TSS. All other segment descriptors are identical.
static mut PER_CPU_GDT: [Option<(GlobalDescriptorTable, Selectors)>; MAX_CPUS] = {
    const INIT: Option<(GlobalDescriptorTable, Selectors)> = None;
    [INIT; MAX_CPUS]
};

/// Initialization flags for per-CPU GDT
static PER_CPU_INIT: [AtomicBool; MAX_CPUS] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; MAX_CPUS]
};

/// Global selectors cache (all CPUs use same selector values)
static SELECTORS_CACHE: Once<Selectors> = Once::new();

/// Initialize per-CPU TSS and GDT for a specific CPU.
///
/// # Safety
///
/// Must be called exactly once per CPU during initialization.
/// The `kernel_stack_top` must be a valid stack address.
unsafe fn init_per_cpu_gdt(cpu_id: usize, kernel_stack_top: u64, df_stack_top: u64, nmi_stack_top: u64) {
    if cpu_id >= MAX_CPUS {
        panic!("CPU ID {} exceeds MAX_CPUS {}", cpu_id, MAX_CPUS);
    }

    // Initialize this CPU's TSS
    let tss = &mut PER_CPU_TSS[cpu_id];
    tss.privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] = VirtAddr::new(kernel_stack_top);
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = VirtAddr::new(df_stack_top);
    // R148-I5 FIX: Configure dedicated NMI IST stack
    tss.interrupt_stack_table[NMI_IST_INDEX as usize] = VirtAddr::new(nmi_stack_top);

    // Create this CPU's GDT with its TSS
    let mut gdt = GlobalDescriptorTable::new();

    // Add kernel segments (identical across all CPUs)
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());

    // Add user segments (identical across all CPUs)
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());

    // Add this CPU's TSS descriptor (points to per-CPU TSS)
    let tss_selector = gdt.append(Descriptor::tss_segment(tss));

    let selectors = Selectors {
        kernel_code,
        kernel_data,
        user_code,
        user_data,
        tss: tss_selector,
    };

    // Store in per-CPU array
    PER_CPU_GDT[cpu_id] = Some((gdt, selectors));

    // Cache selectors on first init (all CPUs have same selector values)
    SELECTORS_CACHE.call_once(|| selectors);

    // Mark as initialized
    PER_CPU_INIT[cpu_id].store(true, Ordering::Release);
}

/// Load per-CPU GDT and TSS for the current CPU.
///
/// # Safety
///
/// Must be called after `init_per_cpu_gdt` for this CPU.
unsafe fn load_per_cpu_gdt(cpu_id: usize) {
    if !PER_CPU_INIT[cpu_id].load(Ordering::Acquire) {
        panic!("Per-CPU GDT not initialized for CPU {}", cpu_id);
    }

    let (gdt, selectors) = PER_CPU_GDT[cpu_id].as_ref().unwrap();

    // Load GDT
    gdt.load();

    // Set segment registers
    CS::set_reg(selectors.kernel_code);
    DS::set_reg(selectors.kernel_data);
    SS::set_reg(selectors.kernel_data);

    // Load TSS
    load_tss(selectors.tss);
}

// ============================================================================
// Public API
// ============================================================================

/// 初始化 GDT 和 TSS (BSP)
///
/// 必须在启用中断前调用。加载 GDT、设置段寄存器、加载 TSS。
pub fn init() {
    // BSP uses CPU ID 0
    let kernel_stack_top = {
        let stack_start = VirtAddr::from_ptr(unsafe { &raw const BSP_KERNEL_STACK.0 });
        (stack_start + KERNEL_STACK_SIZE as u64).as_u64()
    };
    let df_stack_top = {
        let stack_start = VirtAddr::from_ptr(unsafe { &raw const BSP_DOUBLE_FAULT_STACK.0 });
        (stack_start + DOUBLE_FAULT_STACK_SIZE as u64).as_u64()
    };
    // R148-I5 FIX: BSP NMI IST stack
    let nmi_stack_top = {
        let stack_start = VirtAddr::from_ptr(unsafe { &raw const BSP_NMI_STACK.0 });
        (stack_start + NMI_STACK_SIZE as u64).as_u64()
    };

    unsafe {
        init_per_cpu_gdt(0, kernel_stack_top, df_stack_top, nmi_stack_top);
        load_per_cpu_gdt(0);
    }

    let selectors = selectors();
    klog_always!("GDT initialized with per-CPU TSS support (R70-3)");
    klog_always!("  Kernel CS: {:?}", selectors.kernel_code);
    klog_always!("  Kernel DS: {:?}", selectors.kernel_data);
    klog_always!("  User CS:   {:?}", selectors.user_code);
    klog_always!("  User DS:   {:?}", selectors.user_data);
    klog_always!("  TSS:       {:?}", selectors.tss);
}

/// 获取段选择子
///
/// Returns cached selectors (identical across all CPUs).
pub fn selectors() -> &'static Selectors {
    SELECTORS_CACHE.get().expect("GDT not initialized")
}

/// 更新当前 CPU 的 TSS RSP0 (内核栈指针)
///
/// 在切换到用户态进程前调用，设置从用户态返回内核态时使用的栈。
///
/// # Safety
///
/// 调用者必须确保 `stack_top` 是有效的栈顶地址且正确对齐。
pub unsafe fn set_kernel_stack(stack_top: u64) {
    let cpu_id = cpu_local::current_cpu_id();
    if cpu_id < MAX_CPUS {
        PER_CPU_TSS[cpu_id].privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] =
            VirtAddr::new(stack_top);
    }
}

/// 获取当前 CPU 的内核栈指针 (RSP0)
pub fn get_kernel_stack() -> VirtAddr {
    let cpu_id = cpu_local::current_cpu_id();
    if cpu_id < MAX_CPUS {
        unsafe { PER_CPU_TSS[cpu_id].privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] }
    } else {
        VirtAddr::new(0)
    }
}

/// R149-I5 FIX: Unmap the bottom page of the BSP IST double-fault stack as
/// a guard page.  R148-4 added this for AP stacks; BSP was left unguarded
/// because gdt::init() runs before mm::page_table::init().
///
/// Must be called after mm::page_table::init() completes (e.g. from
/// stack_guard::install or a post-init hook in main.rs).
pub fn install_bsp_ist_guard_page() {
    use x86_64::structures::paging::{Page, Size4KiB};
    let guard_addr = VirtAddr::from_ptr(unsafe { &raw const BSP_DOUBLE_FAULT_STACK.0 });
    let guard_page = Page::<Size4KiB>::containing_address(guard_addr);
    unsafe {
        mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
            let _ = manager.unmap_page(guard_page);
        });
    }
}

/// R148-I5 FIX: Unmap the bottom page of the BSP NMI IST stack as a guard page.
/// Must be called after mm::page_table::init() completes (same as install_bsp_ist_guard_page).
pub fn install_bsp_nmi_guard_page() {
    use x86_64::structures::paging::{Page, Size4KiB};
    let guard_addr = VirtAddr::from_ptr(unsafe { &raw const BSP_NMI_STACK.0 });
    let guard_page = Page::<Size4KiB>::containing_address(guard_addr);
    unsafe {
        mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
            let _ = manager.unmap_page(guard_page);
        });
    }
}

/// 更新当前 CPU 指定 IST 栈顶
///
/// # Safety
///
/// 调用者必须确保 `stack_top` 是有效的栈顶地址且正确对齐。
pub unsafe fn set_ist_stack(index: usize, stack_top: VirtAddr) {
    let cpu_id = cpu_local::current_cpu_id();
    if cpu_id < MAX_CPUS && index < 7 {
        PER_CPU_TSS[cpu_id].interrupt_stack_table[index] = stack_top;
    }
}

/// 获取当前 CPU 的默认内核栈顶地址
///
/// R70-3 FIX: Returns the current CPU's kernel stack, not just BSP's.
/// Each CPU has its own kernel stack set during initialization.
/// When a process doesn't have a dedicated kernel stack, use the
/// current CPU's default stack.
pub fn default_kernel_stack_top() -> u64 {
    let cpu_id = cpu_local::current_cpu_id();
    if cpu_id < MAX_CPUS && PER_CPU_INIT[cpu_id].load(Ordering::Acquire) {
        // Return this CPU's TSS RSP0 (set during init)
        unsafe { PER_CPU_TSS[cpu_id].privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX].as_u64() }
    } else {
        // Fallback for early boot (before per-CPU init)
        let stack_start = VirtAddr::from_ptr(unsafe { &raw const BSP_KERNEL_STACK.0 });
        (stack_start + KERNEL_STACK_SIZE as u64).as_u64()
    }
}

/// Initialize GDT and TSS for an Application Processor (AP).
///
/// R70-3 FIX: Each AP gets its own TSS and GDT to enable proper
/// privilege level transitions and interrupt handling.
///
/// # Arguments
///
/// * `cpu_id` - The logical CPU ID for this AP
/// * `kernel_stack_top` - The kernel stack top address for this AP
///
/// # Safety
///
/// Must only be called once per AP during SMP bring-up, after the AP
/// has switched to 64-bit mode but before any interrupt handling.
pub unsafe fn init_for_ap(cpu_id: usize, kernel_stack_top: u64) {
    if cpu_id == 0 {
        panic!("init_for_ap called for BSP (CPU 0)");
    }
    if cpu_id >= MAX_CPUS {
        panic!("CPU ID {} exceeds MAX_CPUS {}", cpu_id, MAX_CPUS);
    }

    // R145-6 FIX: APs use a dedicated per-CPU IST stack for double-fault
    // handling so that a kernel stack overflow does not corrupt the #DF
    // handler's stack (which would escalate to a triple fault).
    let df_stack_start = x86_64::VirtAddr::from_ptr(unsafe {
        &raw const AP_DOUBLE_FAULT_STACKS[cpu_id].0
    });
    let df_stack_top = (df_stack_start + DOUBLE_FAULT_STACK_SIZE as u64).as_u64();

    // R148-4 FIX: Unmap the bottom page of the AP IST stack as a guard page.
    // With the AlignedStack now page-aligned, the bottom page can be safely
    // unmapped without affecting adjacent data. Overflow past the guard page
    // triggers a page fault instead of silently corrupting .bss.
    {
        use x86_64::structures::paging::{Page, Size4KiB};
        let guard_page = Page::<Size4KiB>::containing_address(df_stack_start);
        unsafe {
            mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
                let _ = manager.unmap_page(guard_page);
            });
        }
    }

    // R148-I5 FIX: Per-AP dedicated NMI IST stack + guard page
    let nmi_stack_start = x86_64::VirtAddr::from_ptr(unsafe {
        &raw const AP_NMI_STACKS[cpu_id].0
    });
    let nmi_stack_top = (nmi_stack_start + NMI_STACK_SIZE as u64).as_u64();
    {
        use x86_64::structures::paging::{Page, Size4KiB};
        let guard_page = Page::<Size4KiB>::containing_address(nmi_stack_start);
        unsafe {
            mm::page_table::with_current_manager(VirtAddr::new(0), |manager| {
                let _ = manager.unmap_page(guard_page);
            });
        }
    }

    init_per_cpu_gdt(cpu_id, kernel_stack_top, df_stack_top, nmi_stack_top);
    load_per_cpu_gdt(cpu_id);
}

/// Legacy init_for_ap without parameters (for backward compatibility).
///
/// # Safety
///
/// This function is deprecated. Use `init_for_ap(cpu_id, kernel_stack_top)` instead.
#[deprecated(note = "Use init_for_ap(cpu_id, kernel_stack_top) instead")]
pub unsafe fn init_for_ap_legacy() {
    // This should not be called - panic to catch usage
    panic!("init_for_ap_legacy is deprecated, use init_for_ap(cpu_id, kernel_stack_top)");
}
