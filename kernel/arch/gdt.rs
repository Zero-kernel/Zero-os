//! 全局描述符表 (GDT) 和任务状态段 (TSS) 初始化
//!
//! 提供用户态到内核态的安全切换，包括双重错误的 IST 栈支持。
//!
//! ## 功能
//! - GDT 包含内核/用户代码和数据段
//! - TSS 提供特权级栈切换 (Ring 3 -> Ring 0)
//! - IST (中断栈表) 为双重错误提供独立栈

use lazy_static::lazy_static;
use x86_64::{
    instructions::tables::load_tss,
    registers::segmentation::{Segment, CS, DS, SS},
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

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

/// 内核特权栈 (用于 syscall/中断时的栈切换)
static mut KERNEL_STACK: AlignedStack<KERNEL_STACK_SIZE> = AlignedStack([0; KERNEL_STACK_SIZE]);

/// 双重错误独立栈 (防止栈溢出导致三重错误)
static mut DOUBLE_FAULT_STACK: AlignedStack<DOUBLE_FAULT_STACK_SIZE> =
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

lazy_static! {
    /// 任务状态段
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        // 设置特权级栈 0 (Ring 3 -> Ring 0 时使用)
        tss.privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] = {
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const KERNEL_STACK.0 });
            stack_start + KERNEL_STACK_SIZE as u64
        };

        // 设置 IST 栈 0 (双重错误使用)
        // 使用独立栈防止栈溢出导致的三重错误
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(unsafe { &raw const DOUBLE_FAULT_STACK.0 });
            stack_start + DOUBLE_FAULT_STACK_SIZE as u64
        };

        tss
    };

    /// 全局描述符表和选择子
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        // 添加内核段描述符
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());

        // 添加用户段描述符
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());

        // 添加 TSS 描述符
        let tss = gdt.append(Descriptor::tss_segment(&TSS));

        (
            gdt,
            Selectors {
                kernel_code,
                kernel_data,
                user_code,
                user_data,
                tss,
            },
        )
    };
}

/// 初始化 GDT 和 TSS
///
/// 必须在启用中断前调用。加载 GDT、设置段寄存器、加载 TSS。
pub fn init() {
    // 加载 GDT
    GDT.0.load();

    // 设置段寄存器指向内核段
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        DS::set_reg(GDT.1.kernel_data);
        SS::set_reg(GDT.1.kernel_data);
    }

    // 加载 TSS
    unsafe {
        load_tss(GDT.1.tss);
    }

    println!("GDT initialized with TSS support");
    println!("  Kernel CS: {:?}", GDT.1.kernel_code);
    println!("  Kernel DS: {:?}", GDT.1.kernel_data);
    println!("  User CS:   {:?}", GDT.1.user_code);
    println!("  User DS:   {:?}", GDT.1.user_data);
    println!("  TSS:       {:?}", GDT.1.tss);
}

/// 获取段选择子
pub fn selectors() -> &'static Selectors {
    &GDT.1
}

/// 更新 TSS 的 RSP0 (内核栈指针)
///
/// 在切换到用户态进程前调用，设置从用户态返回内核态时使用的栈。
///
/// # Safety
///
/// 调用者必须确保 `stack_top` 是有效的栈顶地址且正确对齐。
pub unsafe fn set_kernel_stack(stack_top: u64) {
    // 直接修改 TSS 的特权级栈表
    // 注意：这里使用裸指针绕过 lazy_static 的不可变性
    let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
    (*tss_ptr).privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX] = VirtAddr::new(stack_top);
}

/// 获取当前内核栈指针 (RSP0)
pub fn get_kernel_stack() -> VirtAddr {
    TSS.privilege_stack_table[KERNEL_PRIVILEGE_STACK_INDEX]
}

/// 更新指定 IST 栈顶
///
/// # Safety
///
/// 调用者必须确保 `stack_top` 是有效的栈顶地址且正确对齐。
pub unsafe fn set_ist_stack(index: usize, stack_top: VirtAddr) {
    let tss_ptr = &*TSS as *const TaskStateSegment as *mut TaskStateSegment;
    (*tss_ptr).interrupt_stack_table[index] = stack_top;
}

/// 获取默认内核栈顶地址
///
/// 当进程没有分配专用内核栈时，可使用此默认栈。
/// 返回 GDT 初始化时配置的 TSS.rsp0 默认值。
pub fn default_kernel_stack_top() -> u64 {
    let stack_start = VirtAddr::from_ptr(unsafe { &raw const KERNEL_STACK.0 });
    (stack_start + KERNEL_STACK_SIZE as u64).as_u64()
}

/// Initialize GDT for an Application Processor (AP).
///
/// APs share the same GDT with the BSP, but each AP needs to:
/// 1. Load the GDT into GDTR
/// 2. Set segment registers to point to kernel segments
/// 3. Load the TSS (currently skipped - see note below)
///
/// # Safety
///
/// Must only be called once per AP during SMP bring-up, after the AP
/// has switched to 64-bit mode but before any interrupt handling.
pub unsafe fn init_for_ap() {
    // Load the shared GDT
    GDT.0.load();

    // Set segment registers to kernel segments
    // This is critical: the AP was using trampoline's GDT with different selectors
    CS::set_reg(GDT.1.kernel_code);
    DS::set_reg(GDT.1.kernel_data);
    SS::set_reg(GDT.1.kernel_data);

    // NOTE: TSS loading is skipped on APs
    // Each CPU needs its own TSS for proper interrupt handling (RSP0/IST stacks).
    // The BSP's TSS is marked "busy" and cannot be shared via LTR.
    // TODO: Implement per-CPU TSS allocation for production SMP support.
    // For now, APs run without a TSS - interrupts on APs will not work correctly.
}
