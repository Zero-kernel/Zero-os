//! 进程上下文切换
//!
//! 提供进程上下文的保存、恢复和切换功能

use core::arch::asm;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// FPU 保存区在 Context 中的偏移量
/// 原有寄存器占用 0xA0 字节，向上取 64 字节对齐得到 0xC0
const FXSAVE_OFFSET: usize = 0xC0;

/// 512 字节的 FXSAVE/FXRSTOR 区域
/// 按 64 字节对齐以兼容 XSAVE 路径
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub data: [u8; FXSAVE_SIZE],
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxSaveArea")
            .field("fcw", &u16::from_le_bytes([self.data[0], self.data[1]]))
            .field("fsw", &u16::from_le_bytes([self.data[2], self.data[3]]))
            .field(
                "mxcsr",
                &u32::from_le_bytes([self.data[24], self.data[25], self.data[26], self.data[27]]),
            )
            .finish_non_exhaustive()
    }
}

impl Default for FxSaveArea {
    fn default() -> Self {
        let mut area = FxSaveArea {
            data: [0; FXSAVE_SIZE],
        };
        // 设置默认的 FCW（FPU Control Word）：双精度、所有异常屏蔽
        area.data[0] = 0x7F;
        area.data[1] = 0x03;
        // 设置默认的 MXCSR（SSE Control/Status）：所有异常屏蔽
        area.data[24] = 0x80;
        area.data[25] = 0x1F;
        area
    }
}

/// 进程上下文结构
///
/// 保存进程执行时的CPU寄存器状态，包括通用寄存器和 FPU/SIMD 状态
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    // 通用寄存器 (偏移 0x00 - 0x7F)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // 指令指针和标志寄存器 (偏移 0x80 - 0x8F)
    pub rip: u64,
    pub rflags: u64,

    // 段寄存器 (偏移 0x90 - 0x9F)
    pub cs: u64,
    pub ss: u64,

    // 填充以对齐 FxSaveArea 到 64 字节边界 (偏移 0xA0 - 0xBF)
    _padding: [u64; 4],

    /// FPU/SIMD 保存区 (偏移 0xC0)
    /// 用于 FXSAVE/FXRSTOR 指令
    pub fx: FxSaveArea,
}

impl Context {
    /// 创建一个新的空上下文
    pub const fn new() -> Self {
        Context {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202, // IF (中断使能) 位设置
            cs: 0x08,      // 内核代码段
            ss: 0x10,      // 内核数据段
            _padding: [0; 4],
            fx: FxSaveArea {
                data: [0; FXSAVE_SIZE],
            },
        }
    }

    /// 为新进程初始化上下文
    ///
    /// # Arguments
    ///
    /// * `entry_point` - 进程入口点地址
    /// * `stack_top` - 栈顶地址
    pub fn init_for_process(entry_point: u64, stack_top: u64) -> Self {
        let mut ctx = Self::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.rbp = stack_top;
        ctx.rflags = 0x202; // IF位使能
        ctx.fx = FxSaveArea::default(); // 使用默认的 FPU 状态
        ctx
    }

    /// 为用户态进程初始化上下文
    ///
    /// 设置正确的用户态段选择子：
    /// - CS = 0x23 (user_code selector with RPL=3)
    /// - SS = 0x1B (user_data selector with RPL=3)
    pub fn init_for_user_process(entry_point: u64, stack_top: u64) -> Self {
        let mut ctx = Self::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.rbp = stack_top;
        ctx.rflags = 0x202; // IF位使能
        ctx.cs = 0x23; // 用户代码段 (GDT索引4, RPL=3): 0x20 | 3
        ctx.ss = 0x1B; // 用户数据段 (GDT索引3, RPL=3): 0x18 | 3
        ctx.fx = FxSaveArea::default(); // 使用默认的 FPU 状态
        ctx
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// R65-16 FIX: Validate that a context has kernel-mode segments.
///
/// This function should be called before switch_context to prevent
/// a critical privilege escalation vulnerability where user-mode code
/// could be executed at Ring 0 privilege level.
///
/// # Returns
///
/// `true` if the context has kernel-mode segments (cs/ss RPL=0),
/// `false` if it has user-mode segments.
///
/// # Safety
///
/// The ctx pointer must be valid and point to a properly initialized Context.
#[inline]
pub unsafe fn validate_kernel_context(ctx: *const Context) -> bool {
    let cs = (*ctx).cs;
    let ss = (*ctx).ss;
    // Check Ring Privilege Level (RPL) - bits 0-1 of segment selector
    // RPL=0 means kernel mode, RPL=3 means user mode
    (cs & 0x3) == 0 && (ss & 0x3) == 0
}

/// R65-16 FIX: Assert that a context has kernel-mode segments.
///
/// Panics if the context has user-mode segments, preventing privilege escalation.
/// This should be called before switch_context in debug builds or when
/// extra validation is desired.
///
/// # Safety
///
/// The ctx pointer must be valid and point to a properly initialized Context.
#[inline]
pub unsafe fn assert_kernel_context(ctx: *const Context) {
    let cs = (*ctx).cs;
    let ss = (*ctx).ss;
    let cs_rpl = cs & 0x3;
    let ss_rpl = ss & 0x3;

    if cs_rpl != 0 || ss_rpl != 0 {
        panic!(
            "R65-16 SECURITY: Attempted to switch to non-kernel context! \
             cs={:#x} (RPL={}), ss={:#x} (RPL={}). \
             Use enter_usermode for user-mode transitions.",
            cs, cs_rpl, ss, ss_rpl
        );
    }
}

/// 保存当前上下文并切换到新上下文
///
/// # R65-16 Security Note
///
/// This function must ONLY be called with kernel-mode contexts (cs/ss RPL=0).
/// Calling with user-mode contexts would be a critical privilege escalation
/// vulnerability. Use `assert_kernel_context` or `validate_kernel_context`
/// before calling in debug builds or sensitive code paths.
///
/// For user-mode transitions, use the enter_usermode path with proper IRETQ.
///
/// # Z-5 fix: rdi/rsi 按 SysV AMD64 caller-saved 处理
///
/// 按 SysV AMD64 约定，内核线程的 rdi/rsi 视为 caller-saved，
/// 切换后不保证保留，默认被清零以避免误用函数参数指针。
/// 用户态进程使用 save_context/enter_usermode 路径，不受影响。
///
/// # Safety
///
/// 此函数直接操作CPU寄存器，必须确保：
/// - old_ctx 和 new_ctx 指向有效的Context结构
/// - 调用者了解上下文切换的影响
/// - FPU 已通过 init_fpu() 初始化
/// - 目标上下文必须是内核上下文（cs/ss RPL=0）- 使用 validate_kernel_context 验证
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old_ctx: *mut Context, _new_ctx: *const Context) {
    core::arch::naked_asm!(
        // R67-10 FIX: Save RFLAGS and disable interrupts FIRST to protect FPU state
        // during the entire context switch. This prevents IRQ handlers from clobbering
        // FPU state between fxsave64 and fxrstor64.
        "pushfq",
        "pop qword ptr [rdi + 0x88]",  // Save RFLAGS to old_ctx before cli
        "cli",                          // Disable interrupts during FPU operations

        // 保存当前 FPU/SIMD 状态到 old_ctx
        "fxsave64 [rdi + {fxoff}]",

        // 先保存 rcx/rdx（在覆盖前使用 rdi 作为基址）
        "mov [rdi + 0x10], rcx",   // 保存rcx
        "mov [rdi + 0x18], rdx",   // 保存rdx

        // Z-5 fix: 将 rdi/rsi 移至 rdx/rcx 作为上下文指针
        // 入口 rdi/rsi 是函数参数（old_ctx/new_ctx），按 SysV 属于 caller-saved
        "mov rdx, rdi",            // rdx = old_ctx 指针
        "mov rcx, rsi",            // rcx = new_ctx 指针

        // 保存当前上下文到 old_ctx (rdx)
        "mov [rdx + 0x00], rax",   // 保存rax
        "mov [rdx + 0x08], rbx",   // 保存rbx
        // Z-5 fix: rdi/rsi 按 caller-saved 处理，不跨调度保留，设为 0
        "xor rax, rax",
        "mov [rdx + 0x20], rax",   // rsi = 0 (caller-saved)
        "mov [rdx + 0x28], rax",   // rdi = 0 (caller-saved)
        "mov [rdx + 0x30], rbp",   // 保存rbp
        "mov [rdx + 0x38], rsp",   // 保存rsp
        "mov [rdx + 0x40], r8",    // 保存r8
        "mov [rdx + 0x48], r9",    // 保存r9
        "mov [rdx + 0x50], r10",   // 保存r10
        "mov [rdx + 0x58], r11",   // 保存r11
        "mov [rdx + 0x60], r12",   // 保存r12
        "mov [rdx + 0x68], r13",   // 保存r13
        "mov [rdx + 0x70], r14",   // 保存r14
        "mov [rdx + 0x78], r15",   // 保存r15

        // 保存rip (返回地址在栈顶)
        "mov rax, [rsp]",
        "mov [rdx + 0x80], rax",

        // R67-10 FIX: RFLAGS already saved at function entry (before cli)
        // No need to save again here

        // 保存段寄存器
        "mov ax, cs",
        "mov [rdx + 0x90], rax",
        "mov ax, ss",
        "mov [rdx + 0x98], rax",

        // 恢复新进程的 FPU/SIMD 状态
        "fxrstor64 [rcx + {fxoff}]",

        // 加载新上下文从 new_ctx (rcx)
        "mov rax, [rcx + 0x00]",   // 恢复rax
        "mov rbx, [rcx + 0x08]",   // 恢复rbx
        "mov rdx, [rcx + 0x18]",   // 恢复rdx
        "mov rbp, [rcx + 0x30]",   // 恢复rbp
        "mov rsp, [rcx + 0x38]",   // 恢复rsp
        "mov r8,  [rcx + 0x40]",   // 恢复r8
        "mov r9,  [rcx + 0x48]",   // 恢复r9
        "mov r10, [rcx + 0x50]",   // 恢复r10
        "mov r11, [rcx + 0x58]",   // 恢复r11
        "mov r12, [rcx + 0x60]",   // 恢复r12
        "mov r13, [rcx + 0x68]",   // 恢复r13
        "mov r14, [rcx + 0x70]",   // 恢复r14
        "mov r15, [rcx + 0x78]",   // 恢复r15

        // 恢复rip (跳转地址)
        "push qword ptr [rcx + 0x80]",

        // Z-5 fix: 恢复 rdi/rsi（caller-saved，内核线程为 0）
        // R67-10 FIX: 在 popfq 之前恢复这些寄存器，避免 IF=1 时的中断窗口
        "mov rdi, [rcx + 0x28]",   // 恢复rdi (内核线程: 0)
        "mov rsi, [rcx + 0x20]",   // 恢复rsi (内核线程: 0)

        // 将 RFLAGS 压栈（在恢复 rcx 之前）
        "push qword ptr [rcx + 0x88]",

        // 最后恢复 rcx（必须最后，因为 rcx 是基址）
        "mov rcx, [rcx + 0x10]",

        // R67-10 FIX: 恢复 rflags 紧接着 ret，最小化 IF=1 后的中断窗口
        "popfq",

        // 返回到新进程
        "ret",
        fxoff = const FXSAVE_OFFSET,
    )
}

/// 保存当前上下文
///
/// 保存当前 CPU 状态到指定的 Context 结构，包括：
/// - 所有通用寄存器 (rax-r15)
/// - 栈指针 (rsp) 和帧指针 (rbp)
/// - 段寄存器 (cs, ss) - 用于判断当前执行模式
/// - FPU/SIMD 状态
///
/// 注意：RIP 和 RFLAGS 不在此保存，它们由调用者或上下文切换机制处理。
///
/// # Safety
///
/// 调用者必须确保ctx指向有效的Context结构，且 FPU 已初始化
#[inline]
pub unsafe fn save_context(ctx: *mut Context) {
    asm!(
        // R67-10 FIX: Protect FXSAVE from interrupt corruption
        // Save RFLAGS to stack, disable interrupts, do FXSAVE, restore RFLAGS
        "pushfq",
        "cli",
        "fxsave64 [{ctx} + {fxoff}]",
        "popfq",                        // Restore original IF state
        "mov [{ctx} + 0x00], rax",
        "mov [{ctx} + 0x08], rbx",
        "mov [{ctx} + 0x10], rcx",
        "mov [{ctx} + 0x18], rdx",
        "mov [{ctx} + 0x20], rsi",
        "mov [{ctx} + 0x28], rdi",
        "mov [{ctx} + 0x30], rbp",
        "mov [{ctx} + 0x38], rsp",
        "mov [{ctx} + 0x40], r8",
        "mov [{ctx} + 0x48], r9",
        "mov [{ctx} + 0x50], r10",
        "mov [{ctx} + 0x58], r11",
        "mov [{ctx} + 0x60], r12",
        "mov [{ctx} + 0x68], r13",
        "mov [{ctx} + 0x70], r14",
        "mov [{ctx} + 0x78], r15",
        // 保存 CS/SS 以便调度器判断当前执行模式
        // 当用户进程在系统调用中被抢占时，CS=0x08（内核）
        // 这使得调度器能正确使用 switch_context 而非 enter_usermode
        "mov rax, cs",
        "mov [{ctx} + 0x90], rax",
        "mov rax, ss",
        "mov [{ctx} + 0x98], rax",
        ctx = in(reg) ctx,
        fxoff = const FXSAVE_OFFSET,
    );
}

/// 恢复上下文
///
/// # Safety
///
/// 调用者必须确保ctx指向有效的Context结构，且 FPU 已初始化
#[inline]
pub unsafe fn restore_context(ctx: *const Context) {
    asm!(
        // R67-10 FIX: Protect FXRSTOR from interrupt corruption
        // Save RFLAGS to stack, disable interrupts, do FXRSTOR, restore RFLAGS
        "pushfq",
        "cli",
        "fxrstor64 [{ctx} + {fxoff}]",
        "popfq",                        // Restore original IF state
        "mov rax, [{ctx} + 0x00]",
        "mov rbx, [{ctx} + 0x08]",
        "mov rcx, [{ctx} + 0x10]",
        "mov rdx, [{ctx} + 0x18]",
        "mov rsi, [{ctx} + 0x20]",
        "mov rdi, [{ctx} + 0x28]",
        "mov rbp, [{ctx} + 0x30]",
        "mov rsp, [{ctx} + 0x38]",
        "mov r8,  [{ctx} + 0x40]",
        "mov r9,  [{ctx} + 0x48]",
        "mov r10, [{ctx} + 0x50]",
        "mov r11, [{ctx} + 0x58]",
        "mov r12, [{ctx} + 0x60]",
        "mov r13, [{ctx} + 0x68]",
        "mov r14, [{ctx} + 0x70]",
        "mov r15, [{ctx} + 0x78]",
        ctx = in(reg) ctx,
        fxoff = const FXSAVE_OFFSET,
    );
}

/// 初始化 FPU/SIMD 支持
///
/// 必须在使用 FXSAVE/FXRSTOR 之前调用一次。
/// 设置 CR0 和 CR4 中的相关位以启用 SSE 和 FPU 支持。
pub fn init_fpu() {
    unsafe {
        // CR0: 关闭 EM（协处理器仿真），开启 MP（监控协处理器），清除 TS（任务切换）
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
        cr0.remove(Cr0Flags::TASK_SWITCHED); // 清除 TS 防止 #NM
        cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        unsafe { Cr0::write(cr0) };

        // CR4: 启用 OSFXSR（允许 FXSAVE/FXRSTOR）和 OSXMMEXCPT（SSE 异常处理）
        let mut cr4 = Cr4::read();
        cr4.insert(Cr4Flags::OSFXSR);
        cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        unsafe { Cr4::write(cr4) };
    }
}

// ============================================================================
// 用户态入口
// ============================================================================

/// 用户态段选择子
pub const USER_CODE_SELECTOR: u64 = 0x23; // GDT index 4 with RPL=3
pub const USER_DATA_SELECTOR: u64 = 0x1B; // GDT index 3 with RPL=3

/// RFLAGS 安全掩码常量
const RFLAGS_IF: u64 = 1 << 9; // 中断使能位
const RFLAGS_IOPL: u64 = 0b11 << 12; // I/O 特权级
const RFLAGS_NT: u64 = 1 << 14; // 嵌套任务标志
const RFLAGS_RF: u64 = 1 << 16; // 恢复标志

/// 用户态 RFLAGS 安全掩码
/// 清除 IOPL/NT/RF 等特权位，只保留用户可控位
const RFLAGS_USER_MASK: u64 = !(RFLAGS_IOPL | RFLAGS_NT | RFLAGS_RF);

/// 进入用户态（首次）
///
/// 使用 IRETQ 从内核态（Ring 0）切换到用户态（Ring 3）。
/// 这是进程首次进入用户态的唯一方式，因为 SYSRET 只能用于从 SYSCALL 返回。
///
/// ## IRETQ 栈帧布局
///
/// IRETQ 期望栈上有以下数据（从低地址到高地址）：
/// - RIP    (8 bytes) - 用户态入口点
/// - CS     (8 bytes) - 用户代码段选择子
/// - RFLAGS (8 bytes) - 用户态标志寄存器
/// - RSP    (8 bytes) - 用户态栈指针
/// - SS     (8 bytes) - 用户数据段选择子
///
/// ## 安全注意事项
///
/// 1. 此函数不会返回 - 它跳转到用户态代码
/// 2. 在调用前必须设置好 TSS 的 RSP0 以便系统调用返回
/// 3. 中断必须在 IRETQ 后由 RFLAGS.IF 控制
/// 4. RIP/RSP 必须是规范地址且在用户空间（bit 47 == 0）
/// 5. RFLAGS 中的特权位（IOPL/NT/RF）会被清除
/// 6. 段选择子强制使用用户态值，忽略上下文中的值
///
/// # Arguments
///
/// * `ctx` - 包含用户态入口点和栈信息的上下文
///
/// # Safety
///
/// - ctx 必须指向有效的 Context 结构
/// - ctx.rip 必须是有效的用户态代码地址（规范且 bit 47 == 0）
/// - ctx.rsp 必须是有效的用户态栈地址（规范且 bit 47 == 0）
/// - 调用前必须设置 TSS RSP0
#[unsafe(naked)]
pub unsafe extern "C" fn enter_usermode(ctx: *const Context) -> ! {
    core::arch::naked_asm!(
        // ========================================
        // Y-6 安全修复：规范地址验证
        // ========================================
        // 验证 RIP 是规范地址且在用户空间 (bit 47 == 0)
        "mov rax, [rdi + 0x80]",      // 加载用户 RIP
        "mov rcx, rax",
        "shl rcx, 16",
        "sar rcx, 16",
        "cmp rcx, rax",
        "jne 3f",                      // 非规范地址，跳转到 UD2
        "bt rax, 47",
        "jc 3f",                       // 内核空间地址，跳转到 UD2

        // 验证 RSP 是规范地址且在用户空间 (bit 47 == 0)
        "mov rcx, [rdi + 0x38]",      // 加载用户 RSP
        "mov rbx, rcx",
        "shl rbx, 16",
        "sar rbx, 16",
        "cmp rbx, rcx",
        "jne 3f",                      // 非规范地址，跳转到 UD2
        "bt rcx, 47",
        "jc 3f",                       // 内核空间地址，跳转到 UD2

        // ========================================
        // Y-6 安全修复：RFLAGS 清理
        // ========================================
        // 清除 IOPL/NT/RF 等特权位，确保 IF 置位
        "mov rax, [rdi + 0x88]",      // 加载用户 RFLAGS
        "and rax, {rflags_user_mask}", // 清除特权位
        "or  rax, {rflags_if}",        // 确保中断使能
        "mov r15, rax",                // 暂存到 r15

        // 恢复 FPU/SIMD 状态
        "fxrstor64 [rdi + {fxoff}]",

        // 恢复通用寄存器（除了 RSP，它由 IRETQ 恢复）
        "mov rax, [rdi + 0x00]",
        "mov rbx, [rdi + 0x08]",
        "mov rcx, [rdi + 0x10]",
        "mov rdx, [rdi + 0x18]",
        "mov rsi, [rdi + 0x20]",
        // rdi 最后恢复
        "mov rbp, [rdi + 0x30]",
        "mov r8,  [rdi + 0x40]",
        "mov r9,  [rdi + 0x48]",
        "mov r10, [rdi + 0x50]",
        "mov r11, [rdi + 0x58]",
        "mov r12, [rdi + 0x60]",
        "mov r13, [rdi + 0x68]",
        "mov r14, [rdi + 0x70]",
        // r15 稍后恢复（当前保存着清理后的 RFLAGS）

        // ========================================
        // 构建 IRETQ 栈帧
        // ========================================
        // 注意：IRETQ 期望从低地址到高地址依次为 RIP, CS, RFLAGS, RSP, SS
        // 我们需要先 push SS，最后 push RIP
        // Y-6 安全修复：强制使用用户态段选择子，不信任上下文值

        // SS (强制用户数据段)
        "push {user_ss}",
        // RSP (用户栈)
        "push qword ptr [rdi + 0x38]",
        // RFLAGS (已清理，从 r15 获取)
        "push r15",
        // CS (强制用户代码段)
        "push {user_cs}",
        // RIP (入口点)
        "push qword ptr [rdi + 0x80]",

        // 恢复 r15（原上下文值）
        "mov r15, [rdi + 0x78]",

        // 最后恢复 rdi
        "mov rdi, [rdi + 0x28]",

        // 执行 IRETQ 进入用户态
        "iretq",

        // ========================================
        // 非法地址回退：触发 #UD
        // ========================================
        // 如果 RIP 或 RSP 是非规范地址或内核地址，
        // 则触发未定义指令异常，防止非法的用户态转换
        "3:",
        "ud2",

        fxoff = const FXSAVE_OFFSET,
        rflags_if = const RFLAGS_IF,
        rflags_user_mask = const RFLAGS_USER_MASK,
        user_cs = const USER_CODE_SELECTOR,
        user_ss = const USER_DATA_SELECTOR,
    );
}

/// 使用指定的入口点和栈进入用户态
///
/// 这是一个更简便的接口，直接指定入口点和栈地址。
///
/// # Arguments
///
/// * `entry_point` - 用户态代码入口地址
/// * `user_stack` - 用户态栈顶地址
///
/// # Safety
///
/// - entry_point 必须是有效的用户态代码地址
/// - user_stack 必须是有效的用户态栈地址（向下增长）
/// - 调用前必须设置 TSS RSP0
pub unsafe fn jump_to_usermode(entry_point: u64, user_stack: u64) -> ! {
    let ctx = Context::init_for_user_process(entry_point, user_stack);
    enter_usermode(&ctx)
}
