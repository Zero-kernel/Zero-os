//! 调度器回调钩子
//!
//! 提供调度器与其他模块之间的解耦接口，避免循环依赖。
//! - arch 模块通过此钩子调用调度器的定时器处理
//! - syscall 模块通过此钩子触发重调度检查

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use cpu_local::CpuLocal;
use spin::Mutex;

/// 定时器回调类型：在定时器中断时调用
pub type TimerCallback = fn();

/// 重调度回调类型：force=true 强制调度，false 仅在需要时调度
pub type ReschedCallback = fn(force: bool);

/// R39-6 FIX: 全局定时器回调列表（支持多个回调，按注册顺序依次调用）
static TIMER_CBS: Mutex<Vec<TimerCallback>> = Mutex::new(Vec::new());

/// 全局重调度回调
static RESCHED_CB: Mutex<Option<ReschedCallback>> = Mutex::new(None);

/// 【关键修复】从中断上下文延迟的抢占请求标志
///
/// 在中断上下文中不能直接调用 switch_context（会导致栈和特权级问题），
/// 只设置此标志，由安全路径（syscall 返回）消费
///
/// R67-4 FIX: Now per-CPU to avoid cross-CPU races where one CPU
/// sets the flag and another clears it.
static IRQ_RESCHED_PENDING: CpuLocal<AtomicBool> = CpuLocal::new(|| AtomicBool::new(false));

/// 注册定时器回调
///
/// R39-6 FIX: 支持多个回调注册，调度器和超时处理可以同时注册
/// 调度器在初始化时调用此函数注册 on_clock_tick 处理器
pub fn register_timer_callback(cb: TimerCallback) {
    TIMER_CBS.lock().push(cb);
}

/// 注册重调度回调
///
/// 调度器在初始化时调用此函数注册 reschedule_now 处理器
pub fn register_resched_callback(cb: ReschedCallback) {
    *RESCHED_CB.lock() = Some(cb);
}

/// Maximum number of timer callbacks (prevents allocation in IRQ context)
const MAX_TIMER_CALLBACKS: usize = 4;

/// 调用定时器回调
///
/// R39-6 FIX: 遍历所有注册的回调并依次调用
/// 由 arch 模块的定时器中断处理器调用
///
/// # Codex Review Fix
///
/// Use fixed-size stack array instead of Vec::clone() to avoid heap
/// allocation in IRQ context. MAX_TIMER_CALLBACKS limits the number
/// of callbacks (typically just scheduler tick + waitqueue timeout).
///
/// # E.4 RCU Integration
///
/// Marks a quiescent state after processing callbacks. The timer tick
/// is a natural quiescent point since no RCU readers should be active
/// in IRQ context.
#[inline]
pub fn on_scheduler_tick() {
    // Copy callbacks to fixed stack array (no heap allocation in IRQ context)
    let mut callbacks: [Option<TimerCallback>; MAX_TIMER_CALLBACKS] = [None; MAX_TIMER_CALLBACKS];
    let count = {
        let guard = TIMER_CBS.lock();
        let n = guard.len().min(MAX_TIMER_CALLBACKS);
        for (i, cb) in guard.iter().take(n).enumerate() {
            callbacks[i] = Some(*cb);
        }
        n
    }; // Lock released here

    // Call callbacks outside of lock
    for cb in callbacks.iter().take(count) {
        if let Some(f) = cb {
            f();
        }
    }

    // R72: Use rcu_timer_tick() instead of just rcu_quiescent_state().
    // This not only marks quiescent state but also tries to advance
    // COMPLETED_EPOCH, enabling callback progress on idle CPUs.
    crate::rcu::rcu_timer_tick();
}

/// 检查并执行重调度（如果需要）
///
/// 由系统调用返回路径调用，仅在 NEED_RESCHED 或 IRQ_RESCHED_PENDING 标志置位时执行调度
///
/// R65-6 FIX: Also drains any deferred TCP timer work that couldn't complete
/// in IRQ context due to lock contention.
///
/// R67-4 FIX: Uses per-CPU IRQ_RESCHED_PENDING flag.
///
/// # E.4 RCU Integration
///
/// Drains RCU callbacks whose grace period has completed. This is the main
/// process-context path where deferred destruction work gets done.
#[inline]
pub fn reschedule_if_needed() {
    // R65-6 FIX: Drain deferred TCP timer work before scheduling check
    // This ensures timer work is completed in safe (non-IRQ) context when
    // IRQ-time processing was blocked by lock contention.
    crate::time::drain_deferred_tcp_timers();

    // E.4 RCU: Drain callbacks in process context.
    // This runs deferred destruction work for RCU-protected data.
    crate::rcu::poll();

    // R67-4 FIX: Consume this CPU's IRQ-triggered reschedule request
    let irq_pending = IRQ_RESCHED_PENDING.with(|flag| flag.swap(false, Ordering::SeqCst));

    if let Some(cb) = *RESCHED_CB.lock() {
        // 如果有中断请求，强制调度；否则由调度器检查 NEED_RESCHED
        cb(irq_pending);
    }
}

/// 强制执行重调度
///
/// 由 sys_yield 调用，无论 NEED_RESCHED 标志如何都执行调度
#[inline]
pub fn force_reschedule() {
    if let Some(cb) = *RESCHED_CB.lock() {
        cb(true);
    }
}

/// 【新增】从中断上下文请求抢占
///
/// 仅设置标志，不执行实际的上下文切换。
/// 实际切换在安全路径（syscall 返回或下一个调度点）执行。
///
/// R67-4 FIX: Sets this CPU's IRQ_RESCHED_PENDING flag.
///
/// # Safety
///
/// 此函数可从中断上下文安全调用
#[inline]
pub fn request_resched_from_irq() {
    IRQ_RESCHED_PENDING.with(|flag| flag.store(true, Ordering::SeqCst));
}
