//! SYSCALL/SYSRET 系统调用入口配置
//!
//! 配置 x86_64 的快速系统调用机制，包括：
//! - IA32_STAR: 内核/用户代码段选择子
//! - IA32_LSTAR: 系统调用入口点地址
//! - IA32_SFMASK: RFLAGS 掩码
//! - IA32_EFER: 启用 SYSCALL/SYSRET 扩展
//!
//! # Phase 6: User Space Support
//!
//! 这是实现 Ring 3 用户态支持的关键组件。
//!
//! ## SYSCALL 寄存器约定
//!
//! 用户态调用 SYSCALL 时：
//! - RAX: 系统调用号
//! - RDI: arg0, RSI: arg1, RDX: arg2
//! - R10: arg3 (不是 RCX，因为 SYSCALL 会覆盖它)
//! - R8: arg4, R9: arg5
//!
//! SYSCALL 指令执行后：
//! - RCX = 用户态 RIP (返回地址)
//! - R11 = 用户态 RFLAGS
//! - CS/SS 根据 STAR MSR 切换

use crate::gdt;
use core::arch::asm;

/// IA32_STAR MSR 地址
const IA32_STAR: u32 = 0xC000_0081;

/// IA32_LSTAR MSR 地址 (64-bit SYSCALL 入口点)
const IA32_LSTAR: u32 = 0xC000_0082;

/// IA32_CSTAR MSR 地址 (32-bit 兼容模式，暂不使用)
#[allow(dead_code)]
const IA32_CSTAR: u32 = 0xC000_0083;

/// IA32_SFMASK MSR 地址 (SYSCALL RFLAGS 掩码)
const IA32_SFMASK: u32 = 0xC000_0084;

/// IA32_EFER MSR 地址
const IA32_EFER: u32 = 0xC000_0080;

/// IA32_GS_BASE MSR 地址 (用户态 GS 基址)
///
/// Used with SWAPGS instruction to swap between user and kernel GS base.
/// User-space programs can set this via arch_prctl(ARCH_SET_GS).
const IA32_GS_BASE: u32 = 0xC000_0101;

/// IA32_KERNEL_GS_BASE MSR 地址 (内核态 GS 基址)
///
/// Contains the kernel's GS base address. The SWAPGS instruction atomically
/// swaps IA32_GS_BASE and IA32_KERNEL_GS_BASE. In single-core mode, this is
/// set to 0. In SMP mode, this would point to per-CPU data structures.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// EFER.SCE 位 (System Call Extensions)
const EFER_SCE: u64 = 1 << 0;

/// RFLAGS 中断标志位
const RFLAGS_IF: u64 = 1 << 9;
/// RFLAGS 单步标志位
const RFLAGS_TF: u64 = 1 << 8;
/// RFLAGS 方向标志位
const RFLAGS_DF: u64 = 1 << 10;
/// RFLAGS AC 标志位 (SMAP)
const RFLAGS_AC: u64 = 1 << 18;
/// RFLAGS IOPL 位 (I/O 特权级)
const RFLAGS_IOPL: u64 = 0b11 << 12;
/// RFLAGS NT 位 (嵌套任务)
const RFLAGS_NT: u64 = 1 << 14;
/// RFLAGS RF 位 (恢复标志)
const RFLAGS_RF: u64 = 1 << 16;

/// 用户代码段选择子 (SYSRET/IRET 回退用)
const USER_CODE_SELECTOR: u64 = 0x23;
/// 用户数据段选择子
const USER_DATA_SELECTOR: u64 = 0x1B;

// ============================================================================
// 系统调用帧定义
// ============================================================================

/// 系统调用保存帧中的寄存器数量
const SYSCALL_FRAME_QWORDS: usize = 16;

/// 系统调用帧大小（字节）
const SYSCALL_FRAME_SIZE: usize = SYSCALL_FRAME_QWORDS * 8;

/// 临时栈大小（4KB，仅用于单核）
const SYSCALL_SCRATCH_SIZE: usize = 4096;

/// FPU/SIMD 保存区大小（FXSAVE/FXRSTOR 需要 512 字节且 16 字节对齐）
/// Z-1 fix: 用于在 syscall 路径中保存/恢复用户态 FPU 状态
const FPU_SAVE_AREA_SIZE: usize = 512;

// 帧内各寄存器的偏移量
const OFF_RAX: usize = 0; // 系统调用号 / 返回值
const OFF_RCX: usize = 8; // 用户 RIP
const OFF_RDX: usize = 16; // arg2
const OFF_RBX: usize = 24; // callee-saved
const OFF_RSP: usize = 32; // 用户 RSP
const OFF_RBP: usize = 40; // callee-saved
const OFF_RSI: usize = 48; // arg1
const OFF_RDI: usize = 56; // arg0
const OFF_R8: usize = 64; // arg4
const OFF_R9: usize = 72; // arg5
const OFF_R10: usize = 80; // arg3
const OFF_R11: usize = 88; // 用户 RFLAGS
const OFF_R12: usize = 96; // callee-saved
const OFF_R13: usize = 104; // callee-saved
const OFF_R14: usize = 112; // callee-saved
const OFF_R15: usize = 120; // callee-saved

/// 对齐的栈存储（确保 16 字节对齐满足 ABI 要求）
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct AlignedStack<const N: usize>([u8; N]);

// ============================================================================
// R23-2 fix: Per-CPU syscall 临时数据
// ============================================================================
// 将原来的全局变量改为 per-CPU 数组，为 SMP 支持做准备。
// 当前 current_cpu_id() 总是返回 0，所以实际行为与单核相同。
// 未来启用 SMP 时，只需实现真正的 CPU ID 获取逻辑即可。
//
// **SMP 升级路径**：
// 1. 实现 current_cpu_id() 读取 APIC ID
// 2. 在汇编中通过 GS 段或 APIC ID 计算 per-CPU 偏移
// 3. 将 `lea rsp, [{scratch_stacks}]` 改为 `lea rsp, [{scratch_stacks} + cpu_id * SCRATCH_SIZE]`

/// 最大支持的 CPU 数量（必须与 cpu_local crate 保持一致）
const SYSCALL_MAX_CPUS: usize = 64;

// 编译时断言：确保 SYSCALL_MAX_CPUS 与 cpu_local::max_cpus() 一致
const _: () = {
    assert!(
        SYSCALL_MAX_CPUS == 64,
        "SYSCALL_MAX_CPUS must match cpu_local::max_cpus()"
    );
    // 注意：cpu_local::max_cpus() 是 const fn，但由于跨 crate 常量引用限制，
    // 这里硬编码为 64。如果 cpu_local 修改了 MAX_CPUS，需要同步更新此处。
};

/// Per-CPU scratch 栈数组
///
/// 每个 CPU 有独立的 4KB 临时栈，用于 syscall 入口时保存用户寄存器。
/// 使用 `#[no_mangle]` 以便汇编代码可以直接引用符号地址。
///
/// # Safety
///
/// - 在中断禁用状态下使用（SFMASK 清除 IF），不会重入
/// - 每个 CPU 只访问自己的 slot，通过 CPU ID 索引
/// - 数组元素继承 AlignedStack 的 16 字节对齐属性
#[no_mangle]
static mut SYSCALL_SCRATCH_STACKS: [AlignedStack<SYSCALL_SCRATCH_SIZE>; SYSCALL_MAX_CPUS] =
    [AlignedStack([0; SYSCALL_SCRATCH_SIZE]); SYSCALL_MAX_CPUS];

// ============================================================================
// R67-8 FIX: GS-based per-CPU syscall metadata
// ============================================================================
// Instead of using slot 0 for all CPUs, we use GS-relative addressing.
// After SWAPGS, GS points to this CPU's SyscallPerCpu structure.
// This avoids the race condition where multiple CPUs clobber slot 0.

/// R67-8 FIX: Per-CPU syscall metadata accessible via GS segment.
///
/// After SWAPGS in syscall entry, GS base points to this structure.
/// The assembly uses `gs:[offset]` to access per-CPU data without
/// needing to compute CPU ID.
///
/// R67-11 FIX: Added `syscall_active` field to detect nested syscalls.
/// This prevents stack corruption when an interrupt handler attempts
/// to execute a syscall while one is already in progress.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct SyscallPerCpu {
    /// Top of this CPU's scratch stack (pre-computed for fast access)
    pub scratch_top: u64,
    /// User RSP shadow - saved on syscall entry, restored on exit
    pub user_rsp_shadow: u64,
    /// Pointer to current syscall frame on kernel stack
    pub frame_ptr: u64,
    /// R67-11 FIX: Per-CPU syscall active flag (0 = idle, 1 = active).
    /// Accessed atomically via `lock cmpxchg` in assembly. Plain u64
    /// (not AtomicU64) to maintain Copy trait for array initialization.
    pub syscall_active: u64,
}

impl SyscallPerCpu {
    const fn new() -> Self {
        Self {
            scratch_top: 0,
            user_rsp_shadow: 0,
            frame_ptr: 0,
            syscall_active: 0,
        }
    }
}

/// Per-CPU syscall metadata array, indexed by CPU ID.
/// Each entry is 64-byte aligned for cache line isolation.
#[no_mangle]
static mut SYSCALL_PERCPU: [SyscallPerCpu; SYSCALL_MAX_CPUS] =
    [SyscallPerCpu::new(); SYSCALL_MAX_CPUS];

/// Offset of scratch_top in SyscallPerCpu (for GS-relative addressing)
const PERCPU_SCRATCH_TOP_OFFSET: usize = 0;
/// Offset of user_rsp_shadow in SyscallPerCpu
const PERCPU_USER_RSP_OFFSET: usize = 8;
/// Offset of frame_ptr in SyscallPerCpu
const PERCPU_FRAME_PTR_OFFSET: usize = 16;
/// R67-11 FIX: Offset of syscall_active flag in SyscallPerCpu
const PERCPU_SYSCALL_ACTIVE_OFFSET: usize = 24;

/// R67-11 FIX: Error code for nested syscall rejection.
/// Using -EBUSY (16) to indicate the syscall layer is busy.
const SYSCALL_NESTED_ERROR: i64 = -16;

// ============================================================================
// MSR 操作
// ============================================================================

/// 读取 MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// 写入 MSR
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// 系统调用入口是否已初始化
static mut SYSCALL_INITIALIZED: bool = false;

/// 初始化 SYSCALL/SYSRET MSR
///
/// 配置快速系统调用机制，使用户态程序可以通过 SYSCALL 指令进入内核。
///
/// # Arguments
///
/// * `syscall_entry` - 系统调用入口函数地址（汇编存根）
///
/// # Safety
///
/// - 必须在 GDT 初始化后调用
/// - syscall_entry 必须是有效的系统调用处理程序地址
/// - 只能调用一次
///
/// # STAR MSR 布局 (64-bit 模式)
///
/// ```text
/// bits 63:48 = 用户代码段选择子基址（SYSRET 加载 CS = 此值 + 16, SS = 此值 + 8）
/// bits 47:32 = 内核代码段选择子（SYSCALL 加载 CS = 此值, SS = 此值 + 8）
/// bits 31:0  = 保留（32-bit 模式使用）
/// ```
pub unsafe fn init_syscall_msr(syscall_entry: u64) {
    if SYSCALL_INITIALIZED {
        println!("Warning: SYSCALL MSR already initialized");
        return;
    }

    let sel = gdt::selectors();

    // 获取选择子的原始值（不含 RPL）
    let kernel_cs = sel.kernel_code.0 as u64;
    let user_data = sel.user_data.0 as u64;

    // STAR 布局计算：
    // SYSRET (64-bit): CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
    // 目标：CS = 0x23 (user_code | RPL=3), SS = 0x1b (user_data | RPL=3)
    // 计算：STAR[63:48] = 0x23 - 16 = 0x13 = (user_data - 8) | 3
    let sysret_base = (user_data - 8) | 3;

    let star_value = (sysret_base << 48) | (kernel_cs << 32);

    // 写入 STAR
    wrmsr(IA32_STAR, star_value);

    // 写入 LSTAR (系统调用入口点)
    wrmsr(IA32_LSTAR, syscall_entry);

    // 写入 SFMASK (SYSCALL 时清除的 RFLAGS 位)
    // 清除 IF/TF/DF/AC 以及 IOPL/NT/RF，防止特权/调试位带入内核
    let sfmask =
        RFLAGS_IF | RFLAGS_TF | RFLAGS_DF | RFLAGS_AC | RFLAGS_IOPL | RFLAGS_NT | RFLAGS_RF;
    wrmsr(IA32_SFMASK, sfmask);

    // R67-8 FIX: GS base initialization moved to init_syscall_percpu()
    // which is called per-CPU after stack allocation. The kernel GS base
    // will point to each CPU's SyscallPerCpu structure for GS-relative
    // addressing in syscall entry/exit.
    // Note: For BSP, init_syscall_percpu(0) must be called after this function.

    // 启用 EFER.SCE (System Call Extensions)
    let efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    SYSCALL_INITIALIZED = true;

    println!("SYSCALL MSR initialized:");
    println!("  STAR:   0x{:016x}", star_value);
    println!("  LSTAR:  0x{:016x}", syscall_entry);
    println!("  SFMASK: 0x{:016x}", sfmask);
    println!(
        "  Kernel CS: 0x{:x}, SYSRET base: 0x{:x}",
        kernel_cs, sysret_base
    );
}

/// 检查 SYSCALL/SYSRET 是否已初始化
pub fn is_initialized() -> bool {
    unsafe { SYSCALL_INITIALIZED }
}

/// 获取当前 STAR MSR 值（调试用）
pub fn get_star() -> u64 {
    unsafe { rdmsr(IA32_STAR) }
}

/// 获取当前 LSTAR MSR 值（调试用）
pub fn get_lstar() -> u64 {
    unsafe { rdmsr(IA32_LSTAR) }
}

// ============================================================================
// Syscall 帧访问（供 clone/fork 使用）
// ============================================================================

/// Syscall 帧结构（与汇编保存布局一致）
///
/// 这个结构体表示 syscall_entry_stub 保存到内核栈上的寄存器帧。
/// 布局必须与汇编中的偏移量完全匹配。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub rax: u64, // 0x00: 系统调用号 / 返回值
    pub rcx: u64, // 0x08: 用户 RIP (syscall 保存)
    pub rdx: u64, // 0x10: arg2
    pub rbx: u64, // 0x18: callee-saved
    pub rsp: u64, // 0x20: 用户 RSP
    pub rbp: u64, // 0x28: callee-saved
    pub rsi: u64, // 0x30: arg1
    pub rdi: u64, // 0x38: arg0
    pub r8: u64,  // 0x40: arg4
    pub r9: u64,  // 0x48: arg5
    pub r10: u64, // 0x50: arg3
    pub r11: u64, // 0x58: 用户 RFLAGS (syscall 保存)
    pub r12: u64, // 0x60: callee-saved
    pub r13: u64, // 0x68: callee-saved
    pub r14: u64, // 0x70: callee-saved
    pub r15: u64, // 0x78: callee-saved
}

/// 获取当前 CPU 的 syscall 帧指针
///
/// 在 syscall 处理期间调用，返回指向当前 syscall 帧的指针。
/// 用于 clone/fork 读取调用者的寄存器状态。
///
/// # Safety
///
/// 只能在 syscall 处理器内部调用（即 syscall_dispatcher 执行期间）。
/// 在 syscall 处理结束后，返回的指针将无效。
///
/// # Returns
///
/// 返回 Some(&SyscallFrame) 如果在 syscall 上下文中，否则返回 None
pub fn get_current_syscall_frame() -> Option<&'static kernel_core::SyscallFrame> {
    // R67-8 FIX: Use current_cpu_id() instead of hardcoded slot 0
    let cpu_id = cpu_local::current_cpu_id();
    if cpu_id >= SYSCALL_MAX_CPUS {
        return None;
    }
    unsafe {
        let ptr = SYSCALL_PERCPU[cpu_id].frame_ptr;
        if ptr == 0 {
            None
        } else {
            // 类型转换安全：arch::SyscallFrame 和 kernel_core::SyscallFrame 布局完全相同
            Some(&*(ptr as *const kernel_core::SyscallFrame))
        }
    }
}

/// 注册 syscall 帧回调到 kernel_core
///
/// 在 syscall 初始化时调用，让 kernel_core 能访问当前 syscall 帧
pub fn register_frame_callback() {
    kernel_core::register_syscall_frame_callback(get_current_syscall_frame);
}

/// R67-8 FIX: Initialize per-CPU syscall metadata and kernel GS base.
///
/// Must be called once per CPU after its scratch stacks are allocated.
/// This sets up the GS-based per-CPU addressing used in syscall entry.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
///
/// # Safety
///
/// - Must be called with interrupts disabled
/// - Must be called only once per CPU
/// - Must be called after SYSCALL_SCRATCH_STACKS is initialized
pub unsafe fn init_syscall_percpu(cpu_id: usize) {
    assert!(
        cpu_id < SYSCALL_MAX_CPUS,
        "CPU ID {} out of range for syscall per-CPU init",
        cpu_id
    );

    // Pre-compute scratch stack top for this CPU
    let scratch_base = SYSCALL_SCRATCH_STACKS[cpu_id].0.as_ptr() as usize;
    SYSCALL_PERCPU[cpu_id].scratch_top = (scratch_base + SYSCALL_SCRATCH_SIZE) as u64;
    SYSCALL_PERCPU[cpu_id].user_rsp_shadow = 0;
    SYSCALL_PERCPU[cpu_id].frame_ptr = 0;
    // R67-11 FIX: Initialize syscall active flag to 0 (idle)
    SYSCALL_PERCPU[cpu_id].syscall_active = 0;

    // Program kernel GS base to point to this CPU's SyscallPerCpu
    // After SWAPGS, GS:0 will point to SYSCALL_PERCPU[cpu_id]
    let percpu_addr = &SYSCALL_PERCPU[cpu_id] as *const SyscallPerCpu as u64;
    wrmsr(IA32_KERNEL_GS_BASE, percpu_addr);

    // User GS base starts at 0 (user can set it via arch_prctl)
    wrmsr(IA32_GS_BASE, 0);
}

// ============================================================================
// C ABI 辅助函数
// ============================================================================

/// 获取内核栈顶（TSS RSP0）
///
/// # Safety
///
/// 仅由 syscall_entry_stub 汇编代码调用
#[no_mangle]
extern "C" fn syscall_get_kernel_rsp0() -> u64 {
    gdt::get_kernel_stack().as_u64()
}

/// 系统调用分发器桥接
///
/// 将 C ABI 调用转发到 Rust 的 syscall_dispatcher
///
/// # Safety
///
/// 仅由 syscall_entry_stub 汇编代码调用
#[no_mangle]
extern "C" fn syscall_dispatcher_bridge(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    kernel_core::syscall::syscall_dispatcher(syscall_num, arg0, arg1, arg2, arg3, arg4, arg5)
}

// ============================================================================
// 系统调用入口点
// ============================================================================

/// 系统调用入口点
///
/// 处理从用户态通过 SYSCALL 指令进入内核的情况。
///
/// ## 执行流程
///
/// 1. 保存用户 RSP 到暂存区
/// 2. 切换到临时栈
/// 3. 保存所有用户寄存器
/// 4. 获取内核栈并复制帧
/// 5. 启用中断，调用 syscall_dispatcher
/// 6. 禁用中断，恢复寄存器
/// 7. 执行 SYSRETQ 返回用户态
///
/// ## 寄存器约定
///
/// 进入时（来自 SYSCALL）：
/// - RAX = 系统调用号
/// - RDI/RSI/RDX/R10/R8/R9 = arg0-arg5
/// - RCX = 用户 RIP
/// - R11 = 用户 RFLAGS
/// - RSP = 用户栈（需要保存）
///
/// 退出时（SYSRETQ 前）：
/// - RAX = 返回值
/// - RCX = 用户 RIP
/// - R11 = 用户 RFLAGS
/// - 其他寄存器已恢复
///
/// ## 已知限制
///
/// 1. **R67-8 FIX: Per-CPU 数据**：使用 GS-relative 寻址访问 per-CPU 数据。
///    SWAPGS 后 GS 指向当前 CPU 的 SyscallPerCpu 结构，包含 scratch_top、
///    user_rsp_shadow 和 frame_ptr。每个 CPU 必须调用 init_syscall_percpu()
///    初始化其 GS base。
///
/// 2. **FPU/SIMD 状态**：在分发器调用前后使用 FXSAVE64/FXRSTOR64 保存并
///    恢复用户态 FPU/SIMD 状态。当前在内核栈上分配保存区。（Z-1 fix）
///
/// # Safety
///
/// 此函数不应被直接调用，仅作为 LSTAR 的目标。
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry_stub() -> ! {
    core::arch::naked_asm!(
        // ========================================
        // 阶段 1: SMAP 安全 & SWAPGS & 保存用户 RSP
        // ========================================
        // NOTE: CLAC requires SMAP support (CR4.SMAP). If CPU doesn't support SMAP,
        // CLAC is undefined and causes #UD. Using NOP instead for compatibility.
        // TODO: Check SMAP support at runtime and conditionally use CLAC.
        "nop", "nop", "nop",                        // 替代 clac (需要 SMAP 支持)

        // CVE-2019-1125 SWAPGS 防护：
        // 立即执行 SWAPGS 切换到内核 GS 基址，然后使用 LFENCE 序列化
        // 以关闭推测执行窗口，防止攻击者利用 SWAPGS 推测泄露内核数据
        // R67-8 FIX: After SWAPGS, GS points to this CPU's SyscallPerCpu structure
        "swapgs",
        "lfence",

        // R67-8 FIX: Use GS-relative addressing instead of hardcoded slot 0
        // GS:PERCPU_USER_RSP_OFFSET points to this CPU's user_rsp_shadow field
        "mov qword ptr gs:[{percpu_user_rsp}], rsp",   // 保存用户 RSP 到 per-CPU 暂存区

        // ========================================
        // 阶段 2: 切换到临时栈
        // ========================================
        // R67-8 FIX: Load this CPU's pre-computed scratch stack top via GS
        "mov rsp, qword ptr gs:[{percpu_scratch_top}]", // 使用 per-CPU 临时栈
        "cld",                                      // 清除方向标志

        // ========================================
        // 阶段 3: 保存用户寄存器到临时栈
        // ========================================
        "sub rsp, {frame_size}",                    // 分配帧空间

        "mov [rsp + {off_rax}], rax",               // 系统调用号
        "mov [rsp + {off_rcx}], rcx",               // 用户 RIP
        "mov [rsp + {off_rdx}], rdx",               // arg2
        "mov [rsp + {off_rbx}], rbx",               // callee-saved

        // R67-8 FIX: 从 per-CPU GS 区读取保存的用户 RSP
        "mov rax, qword ptr gs:[{percpu_user_rsp}]",
        "mov [rsp + {off_rsp}], rax",               // 用户 RSP

        "mov [rsp + {off_rbp}], rbp",               // callee-saved
        "mov [rsp + {off_rsi}], rsi",               // arg1
        "mov [rsp + {off_rdi}], rdi",               // arg0
        "mov [rsp + {off_r8}], r8",                 // arg4
        "mov [rsp + {off_r9}], r9",                 // arg5
        "mov [rsp + {off_r10}], r10",               // arg3
        "mov [rsp + {off_r11}], r11",               // 用户 RFLAGS
        "mov [rsp + {off_r12}], r12",               // callee-saved
        "mov [rsp + {off_r13}], r13",               // callee-saved
        "mov [rsp + {off_r14}], r14",               // callee-saved
        "mov [rsp + {off_r15}], r15",               // callee-saved

        // 清除用户设置的调试寄存器，防止硬件断点打进内核
        "xor rax, rax",
        "mov dr7, rax",
        "mov dr6, rax",

        // ========================================
        // R67-11 FIX: 嵌套 syscall 检测
        // ========================================
        // 使用 lock cmpxchg 原子地检测并设置 syscall_active 标志。
        // 如果标志已经是 1（说明已有 syscall 正在处理），则设置 r15 = 1 标记为嵌套。
        // 后续会根据 r15 决定是否跳过 dispatcher 并返回错误。
        "xor r15d, r15d",                           // r15 = 0（假设是首次进入）
        "xor eax, eax",                             // 期望值 = 0（空闲状态）
        "mov edx, 1",                               // 新值 = 1（占用状态）
        "lock cmpxchg qword ptr gs:[{percpu_syscall_active}], rdx",
        "setnz r15b",                               // 如果 cmpxchg 失败（已被占用），r15 = 1

        // ========================================
        // 阶段 4: 切换到内核栈
        // ========================================
        "mov r12, rsp",                             // r12 = 临时栈上的帧指针

        // 获取内核栈顶（TSS RSP0）- 栈已 16B 对齐无需额外调整
        "call {get_rsp0}",                          // 返回值在 rax
        "mov rsp, rax",                             // 切换到内核栈

        // Z-1 fix: 在内核栈上分配 FPU 保存区与通用寄存器帧
        // 内存布局（从高到低）：
        //   [TSS RSP0]        <- 内核栈顶（16B 对齐）
        //   [FPU save area]   <- 512 字节，16B 对齐
        //   [syscall frame]   <- 128 字节，通用寄存器
        "sub rsp, {fpu_save_size}",                 // 512B FPU 保存区
        "sub rsp, {frame_size}",                    // 128B 通用寄存器帧
        "mov rdi, rsp",                             // dst = 内核栈帧
        "mov rsi, r12",                             // src = 临时栈帧
        "mov rcx, {frame_qwords}",                  // count
        "rep movsq",                                // 复制帧

        "mov r12, rsp",                             // r12 = 内核栈帧指针（保留用于恢复）
        "lea r13, [rsp + {frame_size}]",            // r13 = FPU 保存区指针（位于帧上方）

        // Z-1 fix: 保存用户 FPU/SIMD 状态
        "fxsave64 [r13]",

        // ========================================
        // R67-11 FIX: 嵌套 syscall 快速失败
        // ========================================
        // 如果 r15 != 0，说明这是嵌套 syscall（之前的 cmpxchg 失败）。
        // 跳过 dispatcher，直接返回 -EBUSY 错误。
        "test r15b, r15b",
        "jnz 3f",                                   // 嵌套 syscall -> 跳转到错误返回

        // R67-8 FIX: 保存 syscall 帧指针供 clone/fork 使用 (via GS)
        "mov qword ptr gs:[{percpu_frame_ptr}], r12",

        // ========================================
        // 阶段 5: 调用系统调用分发器
        // ========================================
        // System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9, [stack]
        // syscall_dispatcher(num, arg0, arg1, arg2, arg3, arg4, arg5)

        "sti",                                      // 启用中断

        "mov rdi, [r12 + {off_rax}]",               // syscall_num (原 RAX)
        "mov rsi, [r12 + {off_rdi}]",               // arg0 (原 RDI)
        "mov rdx, [r12 + {off_rsi}]",               // arg1 (原 RSI)
        "mov rcx, [r12 + {off_rdx}]",               // arg2 (原 RDX)
        "mov r8,  [r12 + {off_r10}]",               // arg3 (原 R10，不是 RCX)
        "mov r9,  [r12 + {off_r8}]",                // arg4 (原 R8)

        // Z-2 fix: 栈对齐修复
        // 当前 RSP 是 16B 对齐（frame 和 FPU 区都是 16 的倍数）
        // System V ABI: call 前 RSP 必须 16B 对齐（call 后入口 RSP+8 是 16B 对齐）
        // 需要 sub 8 + push = 16B，保持对齐
        "sub rsp, 8",                               // 对齐填充
        "push qword ptr [r12 + {off_r9}]",          // arg5 (原 R9)

        "call {dispatcher}",                        // 调用分发器

        "add rsp, 16",                              // 清理栈参数 + 对齐填充

        // R67-8 FIX: 清除 syscall 帧指针（syscall 处理完成）(via GS)
        "mov qword ptr gs:[{percpu_frame_ptr}], 0",

        // R67-11 FIX: 正常路径跳转到公共退出
        "jmp 4f",

        // ========================================
        // R67-11 FIX: 嵌套 syscall 错误返回
        // ========================================
        "3:",
        "mov rax, {nested_err}",                    // 返回 -EBUSY 表示嵌套 syscall

        // ========================================
        // R67-11 FIX: 公共退出路径
        // ========================================
        "4:",

        // ========================================
        // 阶段 6: 恢复寄存器
        // ========================================
        "cli",                                      // 禁用中断

        // Z-1 fix: 恢复用户 FPU/SIMD 状态
        "fxrstor64 [r13]",

        // ========================================
        // R67-11 FIX: 释放 syscall_active 标志
        // ========================================
        // 只有在这次进入成功获取标志（r15 == 0）时才释放。
        // 如果是嵌套 syscall（r15 == 1），不需要释放。
        "test r15b, r15b",
        "jnz 5f",                                   // 嵌套 syscall，跳过释放
        "mov qword ptr gs:[{percpu_syscall_active}], 0",  // 释放标志
        "5:",

        // SYSRET 安全检查：用户 RIP/RSP 必须是规范地址且在低半区
        // 这是防御 CVE-2014-4699/CVE-2014-9322 类漏洞的关键
        "mov rdx, [r12 + {off_rcx}]",               // 用户 RIP
        "mov rbx, rdx",
        "shl rbx, 16",
        "sar rbx, 16",
        "cmp rbx, rdx",
        "jne 2f",                                   // 非规范地址，跳转到 IRETQ 回退
        "bt rdx, 47",
        "jc 2f",                                    // 高半区地址，跳转到 IRETQ 回退

        "mov rdx, [r12 + {off_rsp}]",               // 用户 RSP
        "mov rbx, rdx",
        "shl rbx, 16",
        "sar rbx, 16",
        "cmp rbx, rdx",
        "jne 2f",                                   // 非规范地址，跳转到 IRETQ 回退
        "bt rdx, 47",
        "jc 2f",                                    // 高半区地址，跳转到 IRETQ 回退

        // 地址检查通过，执行正常 SYSRET 路径
        // RAX 已经是返回值，不需要恢复
        "mov rcx, [r12 + {off_rcx}]",               // 用户 RIP
        "mov rdx, [r12 + {off_rdx}]",
        "mov rbx, [r12 + {off_rbx}]",
        "mov rbp, [r12 + {off_rbp}]",
        "mov rsi, [r12 + {off_rsi}]",
        "mov rdi, [r12 + {off_rdi}]",
        "mov r8,  [r12 + {off_r8}]",
        "mov r9,  [r12 + {off_r9}]",
        "mov r10, [r12 + {off_r10}]",

        // R67-9 FIX: Mask RFLAGS to remove privileged bits before SYSRET
        // Clear: IOPL(12-13), NT(14), RF(16), VM(17), VIF(19), VIP(20)
        // Set: IF(9) to enable interrupts in user mode
        // Mask value: ~0x1D3000 = 0xFFFFFFFFFFE2CFFF
        // Note: x86-64 AND r64,imm only accepts 32-bit sign-extended immediates,
        // so we must load the mask into a register first (use r13 as scratch)
        "mov r11, [r12 + {off_r11}]",               // 用户 RFLAGS
        "movabs r13, {rflags_user_mask}",           // R67-9: Load mask into scratch
        "and r11, r13",                             // R67-9: Clear privileged bits
        "or  r11, {rflags_if}",                     // R67-9: Ensure IF is set
        "mov r13, [r12 + {off_r13}]",
        "mov r14, [r12 + {off_r14}]",
        "mov r15, [r12 + {off_r15}]",

        // 恢复用户 RSP（必须在 r12 恢复前完成）
        "mov rsp, [r12 + {off_rsp}]",

        // 最后恢复 r12
        "mov r12, [r12 + {off_r12}]",

        // ========================================
        // 阶段 7: 返回用户态 (SYSRET 快速路径)
        // ========================================
        // CVE-2019-1125 SWAPGS 防护：
        // 返回用户态前执行 SWAPGS 恢复用户 GS 基址
        // LFENCE 序列化以关闭推测窗口
        "swapgs",
        "lfence",
        "sysretq",                                  // 返回用户态

        // ========================================
        // R35-SYSRET-1 FIX: 回退路径 - 终止进程而非尝试返回
        // ========================================
        // 当检测到非规范或高半区 RIP/RSP 时，不执行 swapgs/iretq，
        // 因为使用攻击者提供的无效地址会导致 #GP 并在错误的 GS 状态下处理。
        // 相反，调用 syscall_bad_return() 终止当前进程并调度其他任务。
        "2:",
        // 设置 System V ABI 调用参数
        "mov rdi, [r12 + {off_rcx}]",               // arg0 = 用户 RIP (用于日志)
        "mov rsi, [r12 + {off_rsp}]",               // arg1 = 用户 RSP (用于日志)
        "mov r12, [r12 + {off_r12}]",               // 恢复 r12 保持 ABI 整洁
        // 对齐栈：call 后 RSP+8 应为 16B 对齐
        "sub rsp, 8",                               // 对齐填充
        "call {bad_return}",                        // syscall_bad_return() 不返回

        // 符号绑定
        // R67-8 FIX: Use GS-relative offsets instead of hardcoded slot 0
        percpu_user_rsp = const PERCPU_USER_RSP_OFFSET,
        percpu_scratch_top = const PERCPU_SCRATCH_TOP_OFFSET,
        percpu_frame_ptr = const PERCPU_FRAME_PTR_OFFSET,
        // R67-11 FIX: Offset for nested syscall detection flag
        percpu_syscall_active = const PERCPU_SYSCALL_ACTIVE_OFFSET,
        // R67-11 FIX: Error code for nested syscall rejection (-EBUSY = -16)
        nested_err = const SYSCALL_NESTED_ERROR,
        frame_size = const SYSCALL_FRAME_SIZE,
        frame_qwords = const SYSCALL_FRAME_QWORDS,
        fpu_save_size = const FPU_SAVE_AREA_SIZE,
        // R67-9 FIX: RFLAGS mask to clear privileged bits
        // Clear: IOPL(12-13), NT(14), RF(16), VM(17), VIF(19), VIP(20)
        // Bit positions: 12,13,14,16,17,19,20 = 0x1D3000
        // Full 64-bit mask: ~0x1D3000 = 0xFFFFFFFFFFE2CFFF
        rflags_user_mask = const 0xFFFF_FFFF_FFE2_CFFFu64,
        // Ensure IF is set for user mode
        rflags_if = const 0x200u64,
        off_rax = const OFF_RAX,
        off_rcx = const OFF_RCX,
        off_rdx = const OFF_RDX,
        off_rbx = const OFF_RBX,
        off_rsp = const OFF_RSP,
        off_rbp = const OFF_RBP,
        off_rsi = const OFF_RSI,
        off_rdi = const OFF_RDI,
        off_r8 = const OFF_R8,
        off_r9 = const OFF_R9,
        off_r10 = const OFF_R10,
        off_r11 = const OFF_R11,
        off_r12 = const OFF_R12,
        off_r13 = const OFF_R13,
        off_r14 = const OFF_R14,
        off_r15 = const OFF_R15,
        get_rsp0 = sym syscall_get_kernel_rsp0,
        dispatcher = sym syscall_dispatcher_bridge,
        bad_return = sym syscall_bad_return,
    );
}

// ============================================================================
// R35-SYSRET-1 FIX: Fatal handler for invalid SYSRET targets
// ============================================================================

/// Fatal handler for invalid SYSRET targets (non-canonical or high-half RIP/RSP).
///
/// This function is called when syscall_entry_stub detects that the user's RIP or RSP
/// is non-canonical or points to kernel space. Instead of attempting IRETQ with invalid
/// addresses (which would cause #GP with corrupted GS state), we terminate the process.
///
/// # Safety
///
/// This function must only be called from the syscall path on a valid kernel stack.
/// It never returns - it either reschedules to another task or halts.
///
/// # Arguments
///
/// * `user_rip` - The invalid user RIP that triggered the fallback
/// * `user_rsp` - The invalid user RSP that triggered the fallback
#[no_mangle]
extern "C" fn syscall_bad_return(user_rip: u64, user_rsp: u64) -> ! {
    println!(
        "syscall: SECURITY - rejecting invalid return RIP=0x{:x} RSP=0x{:x}",
        user_rip, user_rsp
    );

    // Terminate the current process with SIGSEGV-style exit code
    if let Some(pid) = kernel_core::process::current_pid() {
        // Exit code 128 + 11 = 139 (SIGSEGV)
        kernel_core::process::terminate_process(pid, 139);
        kernel_core::process::cleanup_zombie(pid);
    }

    // Never resume to user; let scheduler pick a new task.
    // We're on the kernel stack in interrupt-disabled state (cli was executed in asm).
    // The scheduler will handle finding the next runnable task.
    kernel_core::scheduler_hook::force_reschedule();

    // If schedule() somehow returns (e.g., no other tasks), halt the CPU
    loop {
        x86_64::instructions::hlt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msr_helpers() {
        assert_eq!(IA32_STAR, 0xC000_0081);
        assert_eq!(IA32_LSTAR, 0xC000_0082);
    }

    #[test]
    fn test_frame_layout() {
        // 验证帧大小正确
        assert_eq!(SYSCALL_FRAME_SIZE, 128);
        // 验证所有偏移量都在帧范围内
        assert!(OFF_R15 + 8 <= SYSCALL_FRAME_SIZE);
        // Z-1 fix: 验证 FPU 保存区大小和对齐要求
        assert_eq!(FPU_SAVE_AREA_SIZE, 512);
        assert_eq!(FPU_SAVE_AREA_SIZE % 16, 0); // FXSAVE 需要 16B 对齐
    }
}
