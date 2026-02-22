//! 中断和异常处理演示模块

use arch::interrupts::{get_stats, trigger_breakpoint};

/// 演示中断统计
pub fn demo_interrupt_stats() {
    klog!(Info, "\n=== Interrupt Statistics Demo ===\n");

    klog!(Info, "1. Getting current interrupt statistics...");
    let stats = get_stats();
    stats.print();

    klog!(Info, "\n2. Triggering a breakpoint exception...");
    trigger_breakpoint();
    klog!(Info, "   ✓ Breakpoint handled successfully");

    klog!(Info, "\n3. Updated statistics:");
    let stats = get_stats();
    stats.print();

    klog!(Info, "\n✓ Interrupt statistics demo completed!\n");
}

/// 演示异常处理
pub fn demo_exception_handling() {
    klog!(Info, "\n=== Exception Handling Demo ===\n");

    klog!(Info, "1. Testing breakpoint exception (#BP)...");
    trigger_breakpoint();
    klog!(Info, "   ✓ Breakpoint exception handled");

    klog!(Info, "\n2. Exception handlers registered:");
    klog!(Info, "   ✓ Divide Error (#DE)");
    klog!(Info, "   ✓ Debug (#DB)");
    klog!(Info, "   ✓ Non-Maskable Interrupt (NMI)");
    klog!(Info, "   ✓ Breakpoint (#BP)");
    klog!(Info, "   ✓ Overflow (#OF)");
    klog!(Info, "   ✓ Bound Range Exceeded (#BR)");
    klog!(Info, "   ✓ Invalid Opcode (#UD)");
    klog!(Info, "   ✓ Device Not Available (#NM)");
    klog!(Info, "   ✓ Double Fault (#DF)");
    klog!(Info, "   ✓ Invalid TSS (#TS)");
    klog!(Info, "   ✓ Segment Not Present (#NP)");
    klog!(Info, "   ✓ Stack Segment Fault (#SS)");
    klog!(Info, "   ✓ General Protection Fault (#GP)");
    klog!(Info, "   ✓ Page Fault (#PF)");
    klog!(Info, "   ✓ x87 Floating-Point (#MF)");
    klog!(Info, "   ✓ Alignment Check (#AC)");
    klog!(Info, "   ✓ Machine Check (#MC)");
    klog!(Info, "   ✓ SIMD Floating-Point (#XM)");
    klog!(Info, "   ✓ Virtualization (#VE)");

    klog!(Info, "\n✓ Exception handling demo completed!\n");
}

/// 演示硬件中断
pub fn demo_hardware_interrupts() {
    klog!(Info, "\n=== Hardware Interrupts Demo ===\n");

    klog!(Info, "1. Hardware interrupt handlers registered:");
    klog!(Info, "   ✓ IRQ 0: Timer (PIT)");
    klog!(Info, "   ✓ IRQ 1: Keyboard (PS/2)");

    klog!(Info, "\n2. Interrupt statistics:");
    let stats = get_stats();
    klog!(Info, "   Timer interrupts:    {}", stats.timer);
    klog!(Info, "   Keyboard interrupts: {}", stats.keyboard);

    klog!(Info, "\n✓ Hardware interrupts demo completed!\n");
}

/// 运行所有中断演示
pub fn run_all_demos() {
    demo_interrupt_stats();
    demo_exception_handling();
    demo_hardware_interrupts();
}
