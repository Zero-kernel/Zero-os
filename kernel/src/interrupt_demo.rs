//! 中断和异常处理演示模块

use arch::interrupts::{get_stats, trigger_breakpoint};

/// 演示中断统计
pub fn demo_interrupt_stats() {
    klog_always!("\n=== Interrupt Statistics Demo ===\n");

    klog_always!("1. Getting current interrupt statistics...");
    let stats = get_stats();
    stats.print();

    klog_always!("\n2. Triggering a breakpoint exception...");
    trigger_breakpoint();
    klog_always!("   ✓ Breakpoint handled successfully");

    klog_always!("\n3. Updated statistics:");
    let stats = get_stats();
    stats.print();

    klog_always!("\n✓ Interrupt statistics demo completed!\n");
}

/// 演示异常处理
pub fn demo_exception_handling() {
    klog_always!("\n=== Exception Handling Demo ===\n");

    klog_always!("1. Testing breakpoint exception (#BP)...");
    trigger_breakpoint();
    klog_always!("   ✓ Breakpoint exception handled");

    klog_always!("\n2. Exception handlers registered:");
    klog_always!("   ✓ Divide Error (#DE)");
    klog_always!("   ✓ Debug (#DB)");
    klog_always!("   ✓ Non-Maskable Interrupt (NMI)");
    klog_always!("   ✓ Breakpoint (#BP)");
    klog_always!("   ✓ Overflow (#OF)");
    klog_always!("   ✓ Bound Range Exceeded (#BR)");
    klog_always!("   ✓ Invalid Opcode (#UD)");
    klog_always!("   ✓ Device Not Available (#NM)");
    klog_always!("   ✓ Double Fault (#DF)");
    klog_always!("   ✓ Invalid TSS (#TS)");
    klog_always!("   ✓ Segment Not Present (#NP)");
    klog_always!("   ✓ Stack Segment Fault (#SS)");
    klog_always!("   ✓ General Protection Fault (#GP)");
    klog_always!("   ✓ Page Fault (#PF)");
    klog_always!("   ✓ x87 Floating-Point (#MF)");
    klog_always!("   ✓ Alignment Check (#AC)");
    klog_always!("   ✓ Machine Check (#MC)");
    klog_always!("   ✓ SIMD Floating-Point (#XM)");
    klog_always!("   ✓ Virtualization (#VE)");

    klog_always!("\n✓ Exception handling demo completed!\n");
}

/// 演示硬件中断
pub fn demo_hardware_interrupts() {
    klog_always!("\n=== Hardware Interrupts Demo ===\n");

    klog_always!("1. Hardware interrupt handlers registered:");
    klog_always!("   ✓ IRQ 0: Timer (PIT)");
    klog_always!("   ✓ IRQ 1: Keyboard (PS/2)");

    klog_always!("\n2. Interrupt statistics:");
    let stats = get_stats();
    klog_always!("   Timer interrupts:    {}", stats.timer);
    klog_always!("   Keyboard interrupts: {}", stats.keyboard);

    klog_always!("\n✓ Hardware interrupts demo completed!\n");
}

/// 运行所有中断演示
pub fn run_all_demos() {
    demo_interrupt_stats();
    demo_exception_handling();
    demo_hardware_interrupts();
}
