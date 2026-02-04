//! 中断和异常处理
//!
//! 实现完整的x86_64中断描述符表（IDT）和异常处理器
//!
//! # SMAP 安全 (S-6 fix + V-4 SMP fix)
//!
//! 当中断发生在 STAC 区域（SMAP 临时禁用）时，中断处理器必须立即执行 CLAC
//! 以恢复 SMAP 保护。这防止了攻击者利用中断窗口绕过 SMAP。
//!
//! V-4 fix: 直接读取CR4而非使用全局缓存，确保SMP环境下每个CPU正确检测SMAP状态。
//!
//! # FPU/SSE 安全 (R65-18 fix + R66-7 SMP fix)
//!
//! 硬件中断处理器必须保存/恢复 FPU/SSE 状态，因为：
//! 1. x86-interrupt 调用约定不保存 FPU 寄存器
//! 2. 中断处理器内的代码（如 println!, memcpy）可能使用 SSE 指令
//! 3. 不保存会破坏被中断进程的 FPU 状态
//!
//! R66-7 fix: FPU save area is now per-CPU to support SMP. Each CPU has its
//! own 512-byte aligned buffer, preventing FPU state corruption when multiple
//! CPUs handle interrupts concurrently.

use crate::apic;
use crate::context_switch;
use crate::gdt;
use crate::ipi;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cpu_local::{current_cpu, CpuLocal, NO_FPU_OWNER};
use kernel_core::on_scheduler_tick;
use kernel_core::process::{current_pid, get_process};
use lazy_static::lazy_static;
use mm::tlb_shootdown;
use x86_64::instructions::interrupts as x86_interrupts;
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

// G.1 Observability: Per-CPU counter integration
use trace::counters::{increment_counter, TraceCounter};
// G.1 Observability: Watchdog polling for hung-task detection
use trace::watchdog::poll_watchdogs;
// G.1 Observability: PC sampling profiler
use trace::profiler::record_pc_sample;

// Serial port for debug output (0x3F8)
const SERIAL_PORT: u16 = 0x3F8;

// ============================================================================
// R65-18 FIX + R66-7 SMP FIX: Per-CPU FPU/SSE State Save for Interrupt Handlers
// ============================================================================

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// R66-7 FIX: Per-CPU FPU save area for interrupt handlers.
///
/// Each CPU has its own 64-byte aligned buffer for FXSAVE/FXRSTOR.
/// This prevents FPU state corruption when multiple CPUs handle
/// interrupts concurrently.
#[repr(C, align(64))]
struct IrqFpuSaveArea {
    data: [u8; FXSAVE_SIZE],
}

/// R66-7 FIX: Per-CPU FPU save areas using CpuLocal.
///
/// # Safety
///
/// Each CPU exclusively accesses its own FPU save area. The 64-byte
/// alignment satisfies FXSAVE64/FXRSTOR64 requirements.
static IRQ_FPU_AREAS: CpuLocal<IrqFpuSaveArea> = CpuLocal::new(|| IrqFpuSaveArea {
    data: [0; FXSAVE_SIZE],
});

/// R67-7 FIX: Per-CPU nesting depth for IRQ FPU saves.
///
/// Tracks nesting to handle nested NMIs/double-faults correctly.
/// Only the outermost save/restore pair actually performs FXSAVE/FXRSTOR.
/// Uses AtomicU32 for thread-safety (required by CpuLocal).
static IRQ_FPU_DEPTH: CpuLocal<core::sync::atomic::AtomicU32> =
    CpuLocal::new(|| core::sync::atomic::AtomicU32::new(0));

/// R69-2: Track CR0.TS state for lazy FPU.
///
/// When entering an IRQ, if CR0.TS was set (lazy FPU mode), we must temporarily
/// clear it so FXSAVE/FXRSTOR don't trigger #NM. After IRQ handling, we restore
/// the original TS state so lazy FPU semantics continue for the user process.
static IRQ_FPU_TS_WAS_SET: CpuLocal<AtomicBool> = CpuLocal::new(|| AtomicBool::new(false));

/// R65-18 FIX + R66-7 FIX + R67-7 FIX: Save FPU/SSE state before IRQ handler work.
///
/// Uses per-CPU storage to support SMP. Must be called at the beginning
/// of IRQ handlers that may use FPU/SSE. Pairs with `irq_restore_fpu()`.
///
/// R67-7: Now handles nested interrupts (NMI/double-fault during IRQ).
/// Only the first (outermost) save actually performs FXSAVE64.
///
/// # Safety
///
/// - Must be called with interrupts disabled (which they are in IRQ handlers)
/// - Each CPU uses its own save area, so no cross-CPU corruption
///
/// # R68-7 FIX: Checked Arithmetic
///
/// Uses `fetch_update` with `checked_add` to detect overflow. In release builds,
/// unchecked `fetch_add` would silently wrap around, causing the nesting depth to
/// reset and permanently skip FPU saves on subsequent interrupts. This could be
/// exploited via interrupt storms to corrupt or leak FPU state between processes.
#[inline]
unsafe fn irq_save_fpu() {
    use core::sync::atomic::Ordering;
    // R68-7 FIX: Use checked arithmetic to catch overflow
    let depth = IRQ_FPU_DEPTH.with(|d| {
        d.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .unwrap_or_else(|prev| {
                panic!(
                    "irq_save_fpu: nesting depth overflow! prev={} - interrupt storm attack?",
                    prev
                )
            })
    });
    if depth > 0 {
        // Already saved on this CPU - nested interrupt
        return;
    }

    // R69-2: Preserve and clear CR0.TS before FXSAVE to avoid #NM recursion.
    // Under lazy FPU, TS may be set - executing FXSAVE with TS set would trigger #NM.
    let ts_was_set = Cr0::read().contains(Cr0Flags::TASK_SWITCHED);
    IRQ_FPU_TS_WAS_SET.with(|flag| flag.store(ts_was_set, Ordering::Relaxed));
    if ts_was_set {
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::TASK_SWITCHED);
        unsafe { Cr0::write(cr0) };
    }

    // Outermost save - actually perform FXSAVE
    IRQ_FPU_AREAS.with(|area| {
        let ptr = area.data.as_ptr() as *mut u8;
        core::arch::asm!(
            "fxsave64 [{}]",
            in(reg) ptr,
            options(nostack)
        );
    });
}

/// R65-18 FIX + R66-7 FIX + R67-7 FIX: Restore FPU/SSE state after IRQ handler work.
///
/// Uses per-CPU storage to support SMP. Must be called before returning
/// from IRQ handlers that called `irq_save_fpu()`.
///
/// R67-7: Only the last (outermost) restore actually performs FXRSTOR64.
///
/// # R68-7 FIX: Checked Arithmetic
///
/// Uses `fetch_update` with `checked_sub` to detect underflow. Underflow would
/// indicate a mismatched save/restore pair - the depth would wrap to u32::MAX,
/// permanently disabling FPU restoration on this CPU. This is a critical bug
/// that must be caught immediately, not silently via debug_assert.
#[inline]
unsafe fn irq_restore_fpu() {
    use core::sync::atomic::Ordering;
    // R68-7 FIX: Use checked arithmetic to catch underflow
    let prev_depth = IRQ_FPU_DEPTH.with(|d| {
        d.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .unwrap_or_else(|prev| {
                panic!(
                    "irq_restore_fpu: depth underflow! prev={} - mismatched save/restore pair",
                    prev
                )
            })
    });

    // prev_depth is the value BEFORE decrement, so:
    // prev_depth == 1 means we just decremented to 0 (outermost restore)
    // prev_depth > 1 means we're still nested
    // prev_depth == 0 would have triggered the panic above

    if prev_depth != 1 {
        // Not the outermost - don't restore yet
        return;
    }
    // Outermost restore - actually perform FXRSTOR
    IRQ_FPU_AREAS.with(|area| {
        let ptr = area.data.as_ptr();
        core::arch::asm!(
            "fxrstor64 [{}]",
            in(reg) ptr,
            options(nostack)
        );
    });

    // R69-2: Restore CR0.TS if it was set before IRQ entry (lazy FPU).
    // This ensures lazy FPU semantics continue for the user process.
    IRQ_FPU_TS_WAS_SET.with(|flag| {
        if flag.swap(false, Ordering::Relaxed) {
            let mut cr0 = Cr0::read();
            cr0.insert(Cr0Flags::TASK_SWITCHED);
            unsafe { Cr0::write(cr0) };
        }
    });
}

/// Clear Direction Flag and AC flag if SMAP is enabled (S-6 fix + V-4 SMP fix + R65-17 fix)
///
/// Called at the entry of interrupt handlers to:
/// 1. R65-17 FIX: Clear DF to prevent backwards string operations if user entered
///    kernel with DF=1. This is critical for memory safety.
/// 2. Restore SMAP protection in case the interrupt occurred during a STAC region.
///
/// V-4 fix: Reads CR4 directly instead of using a cached value. This ensures
/// correct SMAP detection on each CPU in SMP environments where different
/// cores might enable SMAP at different times.
///
/// # Performance Note
///
/// Reading CR4 is a privileged instruction but is fast on modern CPUs.
/// The overhead is minimal compared to the security benefit of correct
/// SMAP enforcement across all CPUs.
///
/// # Safety
///
/// Safe to call from any context. CLD and CLAC are no-ops if already in the
/// expected state.
#[inline(always)]
fn clac_if_smap() {
    use x86_64::registers::control::{Cr4, Cr4Flags};

    // R65-17 FIX: Always clear Direction Flag to prevent backwards string operations.
    // A user process can enter the kernel with DF=1 (e.g., via interrupt or syscall),
    // which would cause all subsequent string ops (rep movsb, rep stosb, etc.) to run
    // backwards, potentially corrupting memory or leaking data.
    // This is a critical security fix - CLD must be executed before any string operations.
    // Note: CLD modifies EFLAGS.DF, so we cannot use preserves_flags here.
    unsafe {
        core::arch::asm!("cld", options(nostack, nomem));
    }

    if Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION) {
        unsafe {
            core::arch::asm!("clac", options(nostack, nomem));
        }
    }
}

#[inline(always)]
unsafe fn serial_outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack)
    );
}

/// Write string to serial port (for early debug)
#[allow(dead_code)]
unsafe fn serial_write_str(s: &str) {
    for byte in s.bytes() {
        serial_outb(SERIAL_PORT, byte);
    }
}

/// Write hex value to serial port
#[allow(dead_code)]
unsafe fn serial_write_hex(val: u64) {
    serial_write_str("0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        serial_outb(SERIAL_PORT, c);
    }
}

/// 中断统计信息快照（用于外部查询）
#[derive(Debug, Default, Clone, Copy)]
pub struct InterruptStatsSnapshot {
    pub breakpoint: u64,
    pub page_fault: u64,
    pub double_fault: u64,
    pub general_protection_fault: u64,
    pub invalid_opcode: u64,
    pub divide_error: u64,
    pub overflow: u64,
    pub bound_range_exceeded: u64,
    pub invalid_tss: u64,
    pub segment_not_present: u64,
    pub stack_segment_fault: u64,
    pub alignment_check: u64,
    pub machine_check: u64,
    pub simd_floating_point: u64,
    pub virtualization: u64,
    pub timer: u64,
    pub keyboard: u64,
}

impl InterruptStatsSnapshot {
    pub fn print(&self) {
        println!("=== Interrupt Statistics ===");
        println!("Exceptions:");
        println!("  Breakpoint:       {}", self.breakpoint);
        println!("  Page Fault:       {}", self.page_fault);
        println!("  Double Fault:     {}", self.double_fault);
        println!("  GP Fault:         {}", self.general_protection_fault);
        println!("  Invalid Opcode:   {}", self.invalid_opcode);
        println!("  Divide Error:     {}", self.divide_error);
        println!("Hardware Interrupts:");
        println!("  Timer:            {}", self.timer);
        println!("  Keyboard:         {}", self.keyboard);
    }
}

/// 原子中断统计计数器（用于中断处理程序内部，避免死锁）
struct AtomicInterruptStats {
    breakpoint: AtomicU64,
    page_fault: AtomicU64,
    double_fault: AtomicU64,
    general_protection_fault: AtomicU64,
    invalid_opcode: AtomicU64,
    divide_error: AtomicU64,
    overflow: AtomicU64,
    bound_range_exceeded: AtomicU64,
    invalid_tss: AtomicU64,
    segment_not_present: AtomicU64,
    stack_segment_fault: AtomicU64,
    alignment_check: AtomicU64,
    machine_check: AtomicU64,
    simd_floating_point: AtomicU64,
    virtualization: AtomicU64,
    timer: AtomicU64,
    keyboard: AtomicU64,
}

impl AtomicInterruptStats {
    const fn new() -> Self {
        Self {
            breakpoint: AtomicU64::new(0),
            page_fault: AtomicU64::new(0),
            double_fault: AtomicU64::new(0),
            general_protection_fault: AtomicU64::new(0),
            invalid_opcode: AtomicU64::new(0),
            divide_error: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            bound_range_exceeded: AtomicU64::new(0),
            invalid_tss: AtomicU64::new(0),
            segment_not_present: AtomicU64::new(0),
            stack_segment_fault: AtomicU64::new(0),
            alignment_check: AtomicU64::new(0),
            machine_check: AtomicU64::new(0),
            simd_floating_point: AtomicU64::new(0),
            virtualization: AtomicU64::new(0),
            timer: AtomicU64::new(0),
            keyboard: AtomicU64::new(0),
        }
    }

    /// 获取当前统计的快照
    fn snapshot(&self) -> InterruptStatsSnapshot {
        InterruptStatsSnapshot {
            breakpoint: self.breakpoint.load(Ordering::Relaxed),
            page_fault: self.page_fault.load(Ordering::Relaxed),
            double_fault: self.double_fault.load(Ordering::Relaxed),
            general_protection_fault: self.general_protection_fault.load(Ordering::Relaxed),
            invalid_opcode: self.invalid_opcode.load(Ordering::Relaxed),
            divide_error: self.divide_error.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            bound_range_exceeded: self.bound_range_exceeded.load(Ordering::Relaxed),
            invalid_tss: self.invalid_tss.load(Ordering::Relaxed),
            segment_not_present: self.segment_not_present.load(Ordering::Relaxed),
            stack_segment_fault: self.stack_segment_fault.load(Ordering::Relaxed),
            alignment_check: self.alignment_check.load(Ordering::Relaxed),
            machine_check: self.machine_check.load(Ordering::Relaxed),
            simd_floating_point: self.simd_floating_point.load(Ordering::Relaxed),
            virtualization: self.virtualization.load(Ordering::Relaxed),
            timer: self.timer.load(Ordering::Relaxed),
            keyboard: self.keyboard.load(Ordering::Relaxed),
        }
    }
}

/// 全局原子中断统计（避免中断处理程序中的锁争用）
static INTERRUPT_STATS: AtomicInterruptStats = AtomicInterruptStats::new();

/// Per-CPU flags to track first timer interrupt (for debug output)
/// MAX_CPUS = 64 to match cpu_local
static AP_TIMER_SEEN: [AtomicBool; 64] = {
    const INIT: AtomicBool = AtomicBool::new(false);
    [INIT; 64]
};

lazy_static! {
    /// 全局中断描述符表
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU异常处理器 (0-31)
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_exceeded_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);

        // 双重错误使用 IST 栈，防止栈溢出导致三重错误
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }

        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        idt.alignment_check.set_handler_fn(alignment_check_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
        idt.virtualization.set_handler_fn(virtualization_handler);

        // 硬件中断处理器 (32-255)
        idt[32].set_handler_fn(timer_interrupt_handler);      // IRQ 0: Timer
        idt[33].set_handler_fn(keyboard_interrupt_handler);   // IRQ 1: Keyboard
        idt[36].set_handler_fn(serial_interrupt_handler);     // IRQ 4: Serial COM1

        // IPI handlers (high vectors)
        idt[ipi::IPI_VECTOR_RESCHEDULE].set_handler_fn(reschedule_ipi_handler);
        idt[ipi::IPI_VECTOR_TLB_SHOOTDOWN].set_handler_fn(tlb_shootdown_ipi_handler);

        idt
    };
}

/// 初始化中断处理
pub fn init() {
    // 首先初始化 GDT 和 TSS（IDT 的 IST 依赖 TSS）
    gdt::init();

    // 初始化 FPU/SIMD 支持（必须在使用 FXSAVE/FXRSTOR 前）
    context_switch::init_fpu();

    // 初始化 IPI 子系统（注册 TLB shootdown IPI 发送器）
    // 必须在 SMP 启动前调用，以便 TLB shootdown 可以正常工作
    ipi::init();

    // 初始化 8259 PIC，重映射 IRQ 向量避免与 CPU 异常冲突
    unsafe {
        pic_init();
    }

    // 加载中断描述符表（必须在初始化硬件中断之前）
    IDT.load();

    // 初始化串口接收中断（用于 -nographic 模式输入）
    // 注意：必须在 IDT 加载后调用，确保中断处理器已就绪
    unsafe {
        serial_init_interrupt();
    }

    println!("Interrupt Descriptor Table (IDT) loaded");
    println!("  Exception handlers: 20 (double fault uses IST)");
    println!("  Hardware interrupt handlers: 3 (Timer, Keyboard, Serial)");
    println!("  FPU/SIMD support enabled (FXSAVE/FXRSTOR ready)");
}

/// Load IDT on an Application Processor.
///
/// Called during AP bring-up to load the pre-built IDT.
/// Does not reinitialize PIC or GDT - these are already set up by BSP.
///
/// # Safety
///
/// - Must only be called on APs during SMP bring-up
/// - BSP must have already initialized the IDT
pub unsafe fn load_idt_for_ap() {
    IDT.load();
}

/// 初始化串口接收中断
///
/// 配置 COM1 (0x3F8) 以触发接收数据中断
///
/// 关键：必须配置 MCR 的 OUT2 位 (bit 3)，否则 UART 中断信号
/// 无法传递到 8259 PIC，导致中断永远不会触发。
unsafe fn serial_init_interrupt() {
    let ier: u16 = SERIAL_PORT + 1; // Interrupt Enable Register
    let fcr: u16 = SERIAL_PORT + 2; // FIFO Control Register
    let lcr: u16 = SERIAL_PORT + 3; // Line Control Register
    let mcr: u16 = SERIAL_PORT + 4; // Modem Control Register

    // 1. 先禁用所有串口中断
    core::arch::asm!("out dx, al", in("dx") ier, in("al") 0x00u8, options(nostack, nomem));

    // 2. 配置 LCR: 8N1 格式 (8 data bits, no parity, 1 stop bit)
    //    确保 DLAB (bit 7) 为 0，这样访问的是 RBR/THR 而非 divisor
    core::arch::asm!("out dx, al", in("dx") lcr, in("al") 0x03u8, options(nostack, nomem));

    // 3. 配置 FCR: 启用 FIFO 并清空 RX/TX 缓冲区
    //    0xC7 = 启用FIFO(1) + 清空RX FIFO(2) + 清空TX FIFO(4) + 14字节触发阈值(0xC0)
    core::arch::asm!("out dx, al", in("dx") fcr, in("al") 0xC7u8, options(nostack, nomem));

    // 4. 配置 MCR: 关键！OUT2 必须设置才能让中断信号到达 PIC
    //    0x0B = DTR(1) + RTS(2) + OUT2(8)
    //    OUT2 是 8250/16550 的中断使能位，控制 IRQ 线是否连接到 PIC
    core::arch::asm!("out dx, al", in("dx") mcr, in("al") 0x0Bu8, options(nostack, nomem));

    // 5. 清空可能残留的接收数据，确保 FIFO 为空
    loop {
        let lsr: u8;
        core::arch::asm!("in al, dx", out("al") lsr, in("dx") (SERIAL_PORT + 5), options(nostack, nomem));
        if lsr & 0x01 == 0 {
            break;
        }
        // 读取并丢弃数据
        let mut dummy: u8;
        core::arch::asm!("in al, dx", out("al") dummy, in("dx") SERIAL_PORT, options(nostack, nomem));
        let _ = dummy; // Suppress unused warning
    }

    // 6. 读取 IIR 清除可能挂起的中断标识
    let mut iir: u8;
    core::arch::asm!("in al, dx", out("al") iir, in("dx") (SERIAL_PORT + 2), options(nostack, nomem));
    let _ = iir; // Suppress unused warning

    // 注意：不在此处开启 IER，避免在全局中断未启用时积压数据
    // 串口接收中断将由 enable_serial_interrupts() 在 sti 前启用
}

/// 启用串口接收中断
///
/// 应在 IDT 已加载、即将开启全局中断时调用。
/// 这样可以最小化在禁用中断期间积压串口数据的窗口。
pub fn enable_serial_interrupts() {
    let ier: u16 = SERIAL_PORT + 1;
    unsafe {
        // 启用接收数据中断 (IER bit 0)
        core::arch::asm!("out dx, al", in("dx") ier, in("al") 0x01u8, options(nostack, nomem));
    }
}

/// 获取中断统计信息
pub fn get_stats() -> InterruptStatsSnapshot {
    INTERRUPT_STATS.snapshot()
}

// ============================================================================
// CPU异常处理器 (0-31)
// ============================================================================

/// #DE - Divide Error (除法错误)
extern "x86-interrupt" fn divide_error_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS.divide_error.fetch_add(1, Ordering::Relaxed);
    // 注意：中断处理程序中不使用 println! 以避免死锁
    panic!("Divide by zero or division overflow");
}

/// #DB - Debug Exception (调试异常)
extern "x86-interrupt" fn debug_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    // 调试异常：静默处理
}

/// #NMI - Non-Maskable Interrupt (不可屏蔽中断)
extern "x86-interrupt" fn nmi_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    // NMI：可能是硬件错误，静默处理
}

/// #BP - Breakpoint (断点)
extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS.breakpoint.fetch_add(1, Ordering::Relaxed);
    // 断点异常：通常用于调试，静默处理
}

/// #OF - Overflow (溢出)
extern "x86-interrupt" fn overflow_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS.overflow.fetch_add(1, Ordering::Relaxed);
    panic!("Arithmetic overflow");
}

/// #BR - Bound Range Exceeded (边界范围超出)
extern "x86-interrupt" fn bound_range_exceeded_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS
        .bound_range_exceeded
        .fetch_add(1, Ordering::Relaxed);
    panic!("Bound range exceeded");
}

/// #UD - Invalid Opcode (无效操作码)
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS
        .invalid_opcode
        .fetch_add(1, Ordering::Relaxed);
    // Debug output for Ring 3 issues
    unsafe {
        serial_write_str("\n[#UD] Invalid opcode at RIP=");
        serial_write_hex(stack_frame.instruction_pointer.as_u64());
        serial_write_str(" RSP=");
        serial_write_hex(stack_frame.stack_pointer.as_u64());
        serial_write_str("\n");
    }
    panic!("Invalid or undefined opcode");
}

/// #NM - Device Not Available (设备不可用)
///
/// R69-2: Lazy FPU save/restore implementation.
///
/// This handler is triggered when:
/// 1. CR0.TS is set (by context switch) AND
/// 2. An FPU/SSE/AVX instruction is executed
///
/// The handler:
/// 1. Clears CR0.TS to allow FPU access
/// 2. Saves previous owner's FPU state (if any) to their PCB
/// 3. Restores current process's FPU state (or initializes if never used)
/// 4. Marks current process as FPU owner on this CPU
///
/// This is more efficient than eager save/restore because many processes
/// never use FPU between context switches.
extern "x86-interrupt" fn device_not_available_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();

    // Clear CR0.TS to allow FPU instructions in the handler
    let cr0 = Cr0::read();
    if cr0.contains(Cr0Flags::TASK_SWITCHED) {
        let mut new_cr0 = cr0;
        new_cr0.remove(Cr0Flags::TASK_SWITCHED);
        unsafe { Cr0::write(new_cr0) };
    }

    // Get current process PID
    let current = match current_pid() {
        Some(pid) => pid,
        None => {
            // No current process (early boot or kernel thread).
            // TS is cleared, so FPU will work. No state tracking needed.
            return;
        }
    };

    // Disable interrupts during FPU owner transition to prevent races
    x86_interrupts::without_interrupts(|| {
        let per_cpu = current_cpu();
        let prev_owner = per_cpu.get_fpu_owner();

        // Fast path: same process re-accessing FPU
        if prev_owner == current {
            // Already own the FPU, just ensure ownership is tracked
            per_cpu.set_fpu_owner(current);
            return;
        }

        // Save previous owner's FPU state if needed
        if prev_owner != NO_FPU_OWNER {
            if let Some(prev_proc) = get_process(prev_owner) {
                let mut pcb = prev_proc.lock();
                let fx_ptr = pcb.context.fx.data.as_mut_ptr();
                unsafe {
                    core::arch::asm!("fxsave64 [{}]", in(reg) fx_ptr, options(nostack));
                }
                pcb.fpu_used = true;
            } else {
                // Previous owner no longer exists, just clear ownership
                per_cpu.clear_fpu_owner_if(prev_owner);
            }
        }

        // Restore or initialize current process's FPU state
        if let Some(cur_proc) = get_process(current) {
            let mut pcb = cur_proc.lock();
            let fx_ptr = pcb.context.fx.data.as_ptr();
            unsafe {
                core::arch::asm!("fxrstor64 [{}]", in(reg) fx_ptr, options(nostack));
            }
            pcb.fpu_used = true;
            per_cpu.set_fpu_owner(current);
        } else {
            // Current process doesn't exist (shouldn't happen in normal operation)
            per_cpu.set_fpu_owner(NO_FPU_OWNER);
        }
    });
}

/// #DF - Double Fault (双重错误)
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    // S-6 fix: Immediately restore SMAP protection
    clac_if_smap();

    // L-7 fix: Only output detailed state in debug builds to avoid
    // leaking kernel addresses (KASLR bypass prevention)
    #[cfg(debug_assertions)]
    unsafe {
        serial_write_str("\n[DOUBLE FAULT] RIP=");
        serial_write_hex(stack_frame.instruction_pointer.as_u64());
        serial_write_str(" RSP=");
        serial_write_hex(stack_frame.stack_pointer.as_u64());
        serial_write_str("\n");
    }
    #[cfg(not(debug_assertions))]
    unsafe {
        // Suppress unused warning in release builds
        let _ = &stack_frame;
        serial_write_str("\n[DOUBLE FAULT]\n");
    }

    INTERRUPT_STATS.double_fault.fetch_add(1, Ordering::Relaxed);
    panic!("Double fault - system halted");
}

/// #TS - Invalid TSS (无效TSS)
extern "x86-interrupt" fn invalid_tss_handler(_stack_frame: InterruptStackFrame, _error_code: u64) {
    clac_if_smap();
    INTERRUPT_STATS.invalid_tss.fetch_add(1, Ordering::Relaxed);
    panic!("Invalid Task State Segment");
}

/// #NP - Segment Not Present (段不存在)
extern "x86-interrupt" fn segment_not_present_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    clac_if_smap();
    INTERRUPT_STATS
        .segment_not_present
        .fetch_add(1, Ordering::Relaxed);
    panic!("Segment not present");
}

/// #SS - Stack Segment Fault (栈段错误)
extern "x86-interrupt" fn stack_segment_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    clac_if_smap();
    INTERRUPT_STATS
        .stack_segment_fault
        .fetch_add(1, Ordering::Relaxed);
    panic!("Stack segment fault");
}

/// #GP - General Protection Fault (一般保护错误)
extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    // S-6 fix: Immediately restore SMAP protection
    clac_if_smap();

    // Output to serial immediately - no heap/VGA
    unsafe {
        serial_write_str("\n[GPF] error=");
        serial_write_hex(error_code);
        serial_write_str(" RIP=");
        serial_write_hex(stack_frame.instruction_pointer.as_u64());
        serial_write_str("\n");
    }
    INTERRUPT_STATS
        .general_protection_fault
        .fetch_add(1, Ordering::Relaxed);
    panic!("General protection fault");
}

/// #PF - Page Fault (页错误)
///
/// 处理缺页异常：
/// 1. COW 缺页：复制页面并恢复执行
/// 2. 容错用户拷贝中的缺页：终止进程（无法恢复 RIP）
/// 3. 用户空间缺页（用户态触发）：终止进程
/// 4. 内核空间缺页或内核态触发的用户空间缺页：内核 bug，panic
///
/// # Safety Note
///
/// 区分用户态触发和内核态触发的缺页：
/// - USER_MODE 标志表示 CPU 在 Ring 3 时触发
/// - 内核态访问用户内存的缺页如果在 usercopy 中会被优雅处理
/// - 其他内核态缺页仍会 panic（内核 bug）
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    // S-6 fix: Immediately restore SMAP protection
    // If this interrupt occurred during a STAC region, AC is set and SMAP is bypassed.
    // We must clear AC before doing anything else to prevent SMAP bypass attacks.
    clac_if_smap();

    use kernel_core::usercopy;

    // X-8 FIX: Suppress unused warnings in release builds
    // stack_frame is only used in debug_assertions for detailed panic messages
    #[cfg(not(debug_assertions))]
    let _ = &stack_frame;

    /// 用户空间地址上界
    const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

    // Immediate serial output - before anything else
    let fault_addr_raw = unsafe {
        let mut addr: u64;
        core::arch::asm!("mov {}, cr2", out(reg) addr, options(nomem, nostack));
        addr
    };

    // X-8 FIX: In release builds, avoid leaking kernel pointers over serial
    #[cfg(debug_assertions)]
    unsafe {
        serial_write_str("\n[PF ENTRY] CR2=");
        serial_write_hex(fault_addr_raw);
        serial_write_str(" err=");
        serial_write_hex(error_code.bits());
        serial_write_str("\n");
    }
    #[cfg(not(debug_assertions))]
    unsafe {
        // X-8: Only show error code in release builds, not CR2 (pointer leak)
        serial_write_str("\n[PF ENTRY] err=");
        serial_write_hex(error_code.bits());
        serial_write_str("\n");
    }

    INTERRUPT_STATS.page_fault.fetch_add(1, Ordering::Relaxed);
    // G.1: Track page faults in per-CPU observability counters
    increment_counter(TraceCounter::PageFaults, 1);

    // 获取导致缺页的地址
    let fault_addr = fault_addr_raw as usize;

    // 检查是否为写入导致的保护违规缺页（可能是 COW）
    // PROTECTION_VIOLATION 表示页面存在但权限不足，区别于页面不存在的情况
    // 必须先处理 COW，因为 usercopy 写入 COW 页面是合法操作
    if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
        && error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
    {
        if let Some(pid) = kernel_core::process::current_pid() {
            // 尝试处理 COW 缺页
            if unsafe { kernel_core::fork::handle_cow_page_fault(pid, fault_addr).is_ok() } {
                // G.1: Track successful COW page fault handling
                increment_counter(TraceCounter::CowFaults, 1);
                return; // COW 已修复，返回继续执行
            }
        }
    }

    // 【H-26 修复】检查是否为容错用户拷贝中的缺页
    // 由于 x86 指令长度可变，无法简单地推进 RIP 跳过故障指令
    // 采用"标记进程终止 + 请求重调度"的方式优雅处理，避免整个内核 panic
    //
    // 已知限制：完整解决方案需要异常表（exception table）将故障地址映射到恢复地址
    if usercopy::try_handle_usercopy_fault(fault_addr) {
        // 标记进程终止并请求重调度
        if let Some(pid) = kernel_core::process::current_pid() {
            // SIGSEGV 的退出码为 128 + 11 = 139
            kernel_core::process::terminate_process(pid, 139);
            // 设置重调度标志，让调度器在安全点切换进程
            kernel_core::request_resched_from_irq();
            // 返回让中断框架执行 iret，调度器会选择其他进程
            return;
        }

        // 无法识别当前进程时仍保持 panic 以避免静默失败
        // X-8 FIX: Redact kernel pointers in release builds
        #[cfg(debug_assertions)]
        panic!(
            "Usercopy page fault at 0x{:x} - TOCTOU detected (no current PID)\n\
             (User memory unmapped during syscall copy)\n{:#?}",
            fault_addr, stack_frame
        );
        #[cfg(not(debug_assertions))]
        panic!(
            "Usercopy page fault (details redacted) - TOCTOU detected (no current PID)"
        );
    }

    // 【安全修复 S-3】检查是否为用户态触发的用户空间缺页
    // USER_MODE 标志表示 CPU 在 Ring 3（用户态）时触发了缺页
    // 只有在用户态触发且地址在用户空间时才终止进程
    // 内核态访问用户内存的缺页仍然 panic（这是内核bug，如TOCTOU）
    let is_user_mode = error_code.contains(PageFaultErrorCode::USER_MODE);

    if is_user_mode && fault_addr < USER_SPACE_TOP {
        if let Some(pid) = kernel_core::process::current_pid() {
            // 标记进程为待终止状态并设置重调度标志
            // 实际终止在返回用户态前的安全路径中执行
            // SIGSEGV 的退出码为 128 + 11 = 139
            kernel_core::process::terminate_process(pid, 139);

            // 设置重调度标志，让调度器在安全点切换进程
            kernel_core::request_resched_from_irq();

            // 返回让中断框架执行 iret
            // 由于进程已被标记为 Zombie，调度器不会再选择它
            return;
        }
    }

    // 内核空间缺页或内核态触发的用户空间缺页是严重的内核 bug
    // 先通过串口输出关键信息（避免VGA/堆访问）
    // X-8 FIX: In release builds, avoid leaking kernel pointers
    #[cfg(debug_assertions)]
    unsafe {
        serial_write_str("\n[PAGE FAULT] addr=");
        serial_write_hex(fault_addr as u64);
        serial_write_str(" error=");
        serial_write_hex(error_code.bits());
        serial_write_str(" RIP=");
        serial_write_hex(stack_frame.instruction_pointer.as_u64());
        serial_write_str("\n");
    }
    #[cfg(not(debug_assertions))]
    unsafe {
        serial_write_str("\n[PAGE FAULT] error=");
        serial_write_hex(error_code.bits());
        serial_write_str("\n");
    }

    // X-8 FIX: Redact kernel pointers in release builds
    #[cfg(debug_assertions)]
    panic!(
        "Page fault at 0x{:x} (error={:?}, user_mode={})\n{:#?}",
        fault_addr, error_code, is_user_mode, stack_frame
    );
    #[cfg(not(debug_assertions))]
    panic!(
        "Page fault (details redacted) (error={:?}, user_mode={})",
        error_code, is_user_mode
    );
}

/// #MF - x87 Floating-Point Exception (x87浮点异常)
extern "x86-interrupt" fn x87_floating_point_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    panic!("x87 floating-point exception");
}

/// #AC - Alignment Check (对齐检查)
extern "x86-interrupt" fn alignment_check_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    clac_if_smap();
    INTERRUPT_STATS
        .alignment_check
        .fetch_add(1, Ordering::Relaxed);
    panic!("Alignment check failed");
}

/// #MC - Machine Check (机器检查)
extern "x86-interrupt" fn machine_check_handler(_stack_frame: InterruptStackFrame) -> ! {
    clac_if_smap();
    INTERRUPT_STATS
        .machine_check
        .fetch_add(1, Ordering::Relaxed);
    panic!("Machine check - hardware error");
}

/// #XM - SIMD Floating-Point Exception (SIMD浮点异常)
extern "x86-interrupt" fn simd_floating_point_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS
        .simd_floating_point
        .fetch_add(1, Ordering::Relaxed);
    panic!("SIMD floating-point exception");
}

/// #VE - Virtualization Exception (虚拟化异常)
extern "x86-interrupt" fn virtualization_handler(_stack_frame: InterruptStackFrame) {
    clac_if_smap();
    INTERRUPT_STATS
        .virtualization
        .fetch_add(1, Ordering::Relaxed);
    panic!("Virtualization exception");
}

// ============================================================================
// 硬件中断处理器 (32-255)
// ============================================================================

/// IRQ 0 - Timer Interrupt (定时器中断)
///
/// 每次定时器中断时执行：
/// 1. 更新中断统计
/// 2. 更新系统时钟
/// 3. 通过钩子调用调度器处理时间片
/// 4. 发送 EOI
/// 5. 如果从用户态返回且需要重调度，执行抢占
///
/// R65-18 FIX: Saves/restores FPU state to prevent corruption when IRQ code uses SSE.
/// R69-3 FIX: Uses irq_enter/irq_exit for proper IRQ context tracking on SMP.
///
/// 注意：必须先发送 EOI 再执行抢占，避免上下文切换后 IRQ0 被屏蔽。
/// 内核态中断不抢占，以避免持锁时发生调度。
extern "x86-interrupt" fn timer_interrupt_handler(stack_frame: InterruptStackFrame) {
    // S-6 fix: Immediately restore SMAP protection
    clac_if_smap();

    // R69-3 FIX: Mark entering IRQ context for preemption tracking
    current_cpu().irq_enter();

    // R65-18 FIX: Save FPU state before any code that might use SSE
    // This prevents corruption of user/kernel FPU state by IRQ handler code
    unsafe {
        irq_save_fpu();
    }

    INTERRUPT_STATS.timer.fetch_add(1, Ordering::Relaxed);
    // G.1: Track scheduler ticks and interrupts in per-CPU observability counters
    increment_counter(TraceCounter::SchedulerTicks, 1);
    increment_counter(TraceCounter::Interrupts, 1);

    // Check if this is BSP (CPU 0) or an AP
    // BSP receives PIT IRQ0 via 8259 PIC, APs receive LAPIC timer interrupts
    let cpu_id = cpu_local::current_cpu_id();
    let is_bsp = cpu_id == 0;

    // Debug: Mark first timer interrupt on each AP via direct serial output (lock-free)
    // This avoids console lock contention in IRQ context
    if !is_bsp && cpu_id < 64 {
        if !AP_TIMER_SEEN[cpu_id].swap(true, Ordering::Relaxed) {
            // Write directly to serial port 0x3F8 without locking
            // Format: "[T:X]" where X is CPU ID
            unsafe {
                let port = 0x3F8u16;
                // Wait for transmit buffer empty
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b'[');
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b'T');
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b':');
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b'0' + (cpu_id as u8));
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b']');
                while (x86_64::instructions::port::PortReadOnly::<u8>::new(port + 5).read() & 0x20) == 0 {}
                x86_64::instructions::port::PortWriteOnly::<u8>::new(port).write(b'\n');
            }
        }
    }

    // Only BSP should increment global tick count to avoid time advancing N× faster
    // APs get their own LAPIC timer interrupts but don't maintain wall-clock time
    let timestamp_ms = if is_bsp {
        kernel_core::on_timer_tick();

        // G.1 Observability: Poll watchdogs for hung-task detection.
        // Only BSP polls to avoid duplicate detections. The poll function
        // internally fires the hung_task tracepoint for any timed-out tasks
        // and increments the WatchdogTrips counter.
        let now_ms = kernel_core::time::current_timestamp_ms();
        let _tripped = poll_watchdogs(now_ms);
        now_ms
    } else {
        // APs also need a timestamp for profiling
        kernel_core::time::current_timestamp_ms()
    };

    // G.1 Observability: Sample RIP for PC profiler on all CPUs.
    // This captures the instruction pointer where the timer interrupted execution.
    // Convert timestamp from ms to ns for higher precision in analysis tools.
    // Note: Use unwrap_or(0) for PID - current_pid() is already called from
    // IRQ context elsewhere (page fault handler) and the per-CPU mutex is
    // extremely short-lived, but profiler samples are best-effort anyway.
    let timestamp_ns = timestamp_ms.saturating_mul(1_000_000);
    let pid = current_pid().unwrap_or(0) as u64;
    record_pc_sample(timestamp_ns, pid, stack_frame.instruction_pointer.as_u64());

    // 通过钩子调用调度器的时钟 tick 处理
    // 调度器会更新时间片并设置 NEED_RESCHED 标志（如需要）
    // All CPUs need scheduler ticks for time slice management
    on_scheduler_tick();

    // EOI handling: BSP sends to both PIC and LAPIC, AP only to LAPIC
    // Sending PIC EOI from AP could clear in-service bit while BSP handles real PIC IRQ
    unsafe {
        if is_bsp {
            // BSP: Send EOI to 8259 PIC (IRQ0 comes from PIT)
            core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
        }
        // All CPUs: Send EOI to LAPIC
        apic::lapic_eoi();
    }

    // 检查是否即将返回用户态（RPL == 3）
    // CS 的低 2 位是请求特权级 (RPL)
    let returning_to_user = (stack_frame.code_segment.0 & 0x3) == 3;

    // 【关键修复】返回用户态前仅标记需要调度，避免在中断栈上直接 switch_context
    // 在中断上下文中调用 switch_context 会导致：
    // 1. 使用中断栈而非进程内核栈
    // 2. 没有正确的 iret 降权路径
    // 实际调度延迟到安全路径（syscall 返回）执行
    if returning_to_user {
        kernel_core::request_resched_from_irq();
    }

    // R65-18 FIX: Restore FPU state before returning from IRQ
    unsafe {
        irq_restore_fpu();
    }

    // R69-3 FIX: Mark leaving IRQ context
    current_cpu().irq_exit();
}

/// IRQ 1 - Keyboard Interrupt (键盘中断)
///
/// R65-18 FIX: Saves/restores FPU state to prevent corruption.
/// R69-3 FIX: Uses irq_enter/irq_exit for proper IRQ context tracking on SMP.
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // S-6 fix: Immediately restore SMAP protection
    clac_if_smap();

    // R69-3 FIX: Mark entering IRQ context
    current_cpu().irq_enter();

    // R65-18 FIX: Save FPU state
    unsafe {
        irq_save_fpu();
    }

    INTERRUPT_STATS.keyboard.fetch_add(1, Ordering::Relaxed);
    // G.1: Track hardware interrupts in per-CPU observability counters
    increment_counter(TraceCounter::Interrupts, 1);

    // 读取键盘扫描码
    let scancode: u8;
    unsafe {
        core::arch::asm!("in al, 0x60", out("al") scancode, options(nostack, nomem));
    }

    // 将扫描码传递给键盘驱动进行处理
    // 键盘驱动会解码扫描码并将字符放入输入缓冲区
    drivers::push_scancode(scancode);

    // R23-5 fix: 唤醒等待 stdin 输入的进程
    kernel_core::wake_stdin_waiters();

    // 输入到来后请求调度器检查待运行进程，确保shell能及时响应键盘输入
    kernel_core::request_resched_from_irq();

    // 发送 EOI 到 PIC
    unsafe {
        core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
        // Also ack LAPIC for ExtINT mode
        apic::lapic_eoi();
    }

    // R65-18 FIX: Restore FPU state
    unsafe {
        irq_restore_fpu();
    }

    // R69-3 FIX: Mark leaving IRQ context
    current_cpu().irq_exit();
}

/// IRQ 4 - Serial COM1 Interrupt (串口中断)
///
/// 处理串口接收数据，用于 `-nographic` 模式下的键盘输入
///
/// 注意：16550 UART 有16字节的 FIFO 缓冲区，必须循环读取所有可用数据，
/// 否则如果 FIFO 未清空，可能不会触发新的中断。
///
/// R65-18 FIX: Saves/restores FPU state to prevent corruption.
/// R69-3 FIX: Uses irq_enter/irq_exit for proper IRQ context tracking on SMP.
extern "x86-interrupt" fn serial_interrupt_handler(_stack_frame: InterruptStackFrame) {
    // S-6 fix: Immediately restore SMAP protection
    clac_if_smap();

    // R69-3 FIX: Mark entering IRQ context
    current_cpu().irq_enter();

    // R65-18 FIX: Save FPU state
    unsafe {
        irq_save_fpu();
    }

    let mut received_any = false;

    // 循环读取所有可用数据（清空 FIFO）
    loop {
        // 检查是否有数据可读 (LSR bit 0 = Data Ready)
        let lsr: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") lsr, in("dx") (SERIAL_PORT + 5), options(nostack, nomem));
        }

        // 如果没有数据可读，退出循环
        if lsr & 0x01 == 0 {
            break;
        }

        // 读取数据
        let data: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") data, in("dx") SERIAL_PORT, options(nostack, nomem));
        }

        // 将串口数据放入键盘缓冲区（模拟键盘输入）
        // 串口数据已经是 ASCII，不需要扫描码转换
        if drivers::keyboard::push_char(data) {
            received_any = true;
        }
    }

    // 如果收到了输入，唤醒等待输入的进程并请求重调度
    if received_any {
        // R23-5 fix: 唤醒等待 stdin 输入的进程
        kernel_core::wake_stdin_waiters();
        kernel_core::request_resched_from_irq();
    }

    // 发送 EOI 到 PIC
    unsafe {
        core::arch::asm!("mov al, 0x20; out 0x20, al", options(nostack, nomem));
        // Also ack LAPIC for ExtINT mode
        apic::lapic_eoi();
    }

    // R65-18 FIX: Restore FPU state
    unsafe {
        irq_restore_fpu();
    }

    // R69-3 FIX: Mark leaving IRQ context
    current_cpu().irq_exit();
}

/// 触发断点异常（用于测试）
pub fn trigger_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// 触发页错误（用于测试）
pub fn trigger_page_fault() {
    unsafe {
        let ptr = 0xdeadbeef as *mut u8;
        *ptr = 42;
    }
}

// ============================================================================
// 8259 PIC (Programmable Interrupt Controller) 支持
// ============================================================================

/// PIC 端口定义
const PIC1_CMD: u16 = 0x20; // 主 PIC 命令端口
const PIC1_DATA: u16 = 0x21; // 主 PIC 数据端口
const PIC2_CMD: u16 = 0xA0; // 从 PIC 命令端口
const PIC2_DATA: u16 = 0xA1; // 从 PIC 数据端口

/// PIC 中断向量偏移
pub const PIC1_OFFSET: u8 = 0x20; // 主 PIC: IRQ 0-7 -> 向量 32-39
pub const PIC2_OFFSET: u8 = 0x28; // 从 PIC: IRQ 8-15 -> 向量 40-47

/// 等待 I/O 完成（用于 PIC 初始化时的延迟）
#[inline]
unsafe fn io_wait() {
    // 向未使用的端口 0x80 写入任意值，产生足够的延迟
    core::arch::asm!("out 0x80, al", in("al") 0u8, options(nostack, nomem));
}

/// 初始化并重映射 8259 PIC
///
/// 将主 PIC (IRQ 0-7) 映射到向量 offset1 开始
/// 将从 PIC (IRQ 8-15) 映射到向量 offset2 开始
///
/// # Safety
///
/// 必须在启用中断前调用。offset1 和 offset2 不得与 CPU 异常向量 (0-31) 重叠。
pub unsafe fn pic_init() {
    // 保存当前中断掩码
    let mask1: u8;
    let mask2: u8;
    core::arch::asm!("in al, dx", out("al") mask1, in("dx") PIC1_DATA, options(nostack, nomem));
    core::arch::asm!("in al, dx", out("al") mask2, in("dx") PIC2_DATA, options(nostack, nomem));

    // ICW1: 开始初始化序列（边沿触发，级联模式，需要 ICW4）
    core::arch::asm!("out dx, al", in("dx") PIC1_CMD, in("al") 0x11u8, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_CMD, in("al") 0x11u8, options(nostack, nomem));
    io_wait();

    // ICW2: 设置中断向量偏移
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") PIC1_OFFSET, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") PIC2_OFFSET, options(nostack, nomem));
    io_wait();

    // ICW3: 配置级联
    // 主 PIC: IR2 连接从 PIC (位掩码 0x04)
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") 4u8, options(nostack, nomem));
    io_wait();
    // 从 PIC: 级联标识为 2
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") 2u8, options(nostack, nomem));
    io_wait();

    // ICW4: 设置 8086/88 模式
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") 0x01u8, options(nostack, nomem));
    io_wait();
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") 0x01u8, options(nostack, nomem));
    io_wait();

    // 恢复中断掩码（或设置新掩码）
    // 启用 IRQ0 (定时器), IRQ1 (键盘), IRQ4 (串口 COM1)
    let new_mask1: u8 = 0xEC; // 11101100 - 启用 IRQ0, IRQ1, IRQ4
    let new_mask2: u8 = 0xFF; // 11111111 - 禁用所有从 PIC 中断
    core::arch::asm!("out dx, al", in("dx") PIC1_DATA, in("al") new_mask1, options(nostack, nomem));
    core::arch::asm!("out dx, al", in("dx") PIC2_DATA, in("al") new_mask2, options(nostack, nomem));

    println!(
        "PIC initialized: IRQ0-7 -> vectors {}-{}, IRQ8-15 -> vectors {}-{}",
        PIC1_OFFSET,
        PIC1_OFFSET + 7,
        PIC2_OFFSET,
        PIC2_OFFSET + 7
    );
}

/// 发送 EOI (End of Interrupt) 到 PIC
///
/// # Arguments
/// * `irq` - 中断请求号 (0-15)
#[inline]
pub unsafe fn pic_send_eoi(irq: u8) {
    if irq >= 8 {
        // 从 PIC 的中断，需要同时发送 EOI 到从 PIC 和主 PIC
        core::arch::asm!("out dx, al", in("dx") PIC2_CMD, in("al") 0x20u8, options(nostack, nomem));
    }
    core::arch::asm!("out dx, al", in("dx") PIC1_CMD, in("al") 0x20u8, options(nostack, nomem));
}

// ============================================================================
// IPI Handlers (Inter-Processor Interrupts for SMP)
// ============================================================================

/// Reschedule IPI Handler (vector 0xFB)
///
/// Called when this CPU receives a reschedule request from another CPU.
/// This handler:
/// 1. Clears SMAP if active (CLAC)
/// 2. Sets the need_resched flag on this CPU
/// 3. Requests a reschedule from IRQ context
/// 4. Sends LAPIC EOI to acknowledge the interrupt
///
/// The actual context switch will occur at the next safe scheduling point
/// (e.g., syscall return or timer interrupt).
///
/// R69-3 FIX: Uses irq_enter/irq_exit for proper IRQ context tracking on SMP.
///
/// # Safety
///
/// - Must be called with interrupts disabled (x86-interrupt calling convention)
/// - Uses LAPIC EOI (not PIC) since this is an IPI
extern "x86-interrupt" fn reschedule_ipi_handler(_stack_frame: InterruptStackFrame) {
    // S-6 fix: Clear SMAP to prevent user-page access during handler
    clac_if_smap();

    // R69-3 FIX: Mark entering IRQ context
    current_cpu().irq_enter();

    // Mark this CPU as needing a reschedule
    current_cpu().set_need_resched();

    // Request reschedule from IRQ context (sets IRQ_RESCHED_PENDING)
    kernel_core::request_resched_from_irq();

    // Send LAPIC EOI (not PIC - this is an IPI)
    unsafe {
        apic::lapic_eoi();
    }

    // R69-3 FIX: Mark leaving IRQ context
    current_cpu().irq_exit();
}

/// TLB Shootdown IPI Handler (vector 0xFE)
///
/// Called when this CPU receives a TLB shootdown request from another CPU.
/// This handler:
/// 1. Clears SMAP if active (CLAC)
/// 2. Delegates to mm::tlb_shootdown::handle_shootdown_ipi()
/// 3. Sends LAPIC EOI to acknowledge the interrupt
///
/// R69-3 FIX: Uses irq_enter/irq_exit for proper IRQ context tracking on SMP.
///
/// # Safety
///
/// - Must be called with interrupts disabled (x86-interrupt calling convention)
/// - Uses LAPIC EOI (not PIC) since this is an IPI
extern "x86-interrupt" fn tlb_shootdown_ipi_handler(_stack_frame: InterruptStackFrame) {
    // S-6 fix: Clear SMAP to prevent user-page access during handler
    clac_if_smap();

    // R69-3 FIX: Mark entering IRQ context
    current_cpu().irq_enter();

    // Delegate to the TLB shootdown module
    tlb_shootdown::handle_shootdown_ipi();

    // Send LAPIC EOI (not PIC - this is an IPI)
    unsafe {
        apic::lapic_eoi();
    }

    // R69-3 FIX: Mark leaving IRQ context
    current_cpu().irq_exit();
}
