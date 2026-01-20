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

/// 特权级栈索引 (用于 Ring 3 -> Ring 0 切换)
const KERNEL_PRIVILEGE_STACK_INDEX: usize = 0;

/// 内核栈大小 (64 KB)
pub const KERNEL_STACK_SIZE: usize = 16 * 4096;

/// 双重错误 IST 栈大小 (32 KB)
pub const DOUBLE_FAULT_STACK_SIZE: usize = 8 * 4096;

/// 16 字节对齐的内核栈结构
#[repr(C, align(16))]
struct AlignedStack<const SIZE: usize>([u8; SIZE]);

/// BSP 内核特权栈 (用于 syscall/中断时的栈切换)
static mut BSP_KERNEL_STACK: AlignedStack<KERNEL_STACK_SIZE> = AlignedStack([0; KERNEL_STACK_SIZE]);

/// BSP 双重错误独立栈 (防止栈溢出导致三重错误)
static mut BSP_DOUBLE_FAULT_STACK: AlignedStack<DOUBLE_FAULT_STACK_SIZE> =
    AlignedStack([0; DOUBLE_FAULT_STACK_SIZE]);

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
unsafe fn init_per_cpu_gdt(cpu_id: usize, kernel_stack_top: u64, df_stack_top: u64) {
    if cpu_id >= MAX_CPUS {
        panic!("CPU ID {} exceeds MAX_CPUS {}", cpu_id, MAX_CPUS);
    }

    // Initialize this CPU's TSS
    let tss = &mut PER_CPU_TSS[cpu_id];
    tss.privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] = VirtAddr::new(kernel_stack_top);
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = VirtAddr::new(df_stack_top);

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

    unsafe {
        init_per_cpu_gdt(0, kernel_stack_top, df_stack_top);
        load_per_cpu_gdt(0);
    }

    let selectors = selectors();
    println!("GDT initialized with per-CPU TSS support (R70-3)");
    println!("  Kernel CS: {:?}", selectors.kernel_code);
    println!("  Kernel DS: {:?}", selectors.kernel_data);
    println!("  User CS:   {:?}", selectors.user_code);
    println!("  User DS:   {:?}", selectors.user_data);
    println!("  TSS:       {:?}", selectors.tss);
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

    // APs use their kernel stack for double fault handling too
    // (In production, each AP should have a dedicated DF stack)
    let df_stack_top = kernel_stack_top;

    init_per_cpu_gdt(cpu_id, kernel_stack_top, df_stack_top);
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
