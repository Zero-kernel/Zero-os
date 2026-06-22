//! 调度器回调钩子
//!
//! 提供调度器与其他模块之间的解耦接口，避免循环依赖。
//! - arch 模块通过此钩子调用调度器的定时器处理
//! - syscall 模块通过此钩子触发重调度检查

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

/// R169-L9/L10/L11: cadence of the global stranded-port-charge sweep. One
/// `sweep_stranded_port_charges()` pass runs every `PORT_CHARGE_SWEEP_INTERVAL`
/// full process-context deferred-work drains, amortizing its full-map scan. A
/// global counter (a coarse rate gate; exact per-CPU accuracy is unnecessary)
/// drives it. The sweep is enqueue-only and the correctness backstop for dead-
/// `Weak` port-charge reclamation, so the interval only affects RECLAIM LATENCY,
/// never correctness (`delete_cgroup` sweeps synchronously before its gate).
const PORT_CHARGE_SWEEP_INTERVAL: u32 = 256;
static PORT_CHARGE_SWEEP_TICK: AtomicU32 = AtomicU32::new(0);

/// R151-5 FIX: Force-initialize the per-CPU resched flag before IRQs are enabled.
///
/// `IRQ_RESCHED_PENDING` is accessed from `request_resched_from_irq()` in timer
/// and keyboard interrupt handlers. Without pre-initialization, the first IRQ on
/// a CPU can deadlock inside `Once::call_once()` heap allocation.
pub fn force_init_resched_locals() {
    IRQ_RESCHED_PENDING.force_init();
}

/// 注册定时器回调
///
/// R39-6 FIX: 支持多个回调注册，调度器和超时处理可以同时注册
/// 调度器在初始化时调用此函数注册 on_clock_tick 处理器
///
/// R148-I6 FIX: Disable interrupts while holding TIMER_CBS lock to prevent
/// deadlock if a timer IRQ fires during registration and on_scheduler_tick()
/// tries to acquire the same lock.
pub fn register_timer_callback(cb: TimerCallback) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut cbs = TIMER_CBS.lock();
        // R161-I2 FIX: Bounds check before push to prevent unbounded growth.
        if cbs.len() < MAX_TIMER_CALLBACKS {
            cbs.push(cb);
        }
    });
}

/// 注册重调度回调
///
/// 调度器在初始化时调用此函数注册 reschedule_now 处理器
pub fn register_resched_callback(cb: ReschedCallback) {
    // R152-11 FIX: Disable IRQs while holding RESCHED_CB lock.
    // force_reschedule() also acquires this lock and is reachable from signal paths
    // that may run in interrupt-adjacent context. Matches register_timer_callback().
    x86_64::instructions::interrupts::without_interrupts(|| {
        *RESCHED_CB.lock() = Some(cb);
    });
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
    // R148-I6 FIX: Blocking lock() is safe here because register_timer_callback()
    // now wraps its lock acquisition in without_interrupts(), preventing timer IRQ
    // from firing while the registration lock is held.  Using try_lock() here would
    // skip ticks and break per-CPU scheduler time-slice accounting and timeout progress.
    let count = {
        let guard = TIMER_CBS.lock();
        let n = guard.len().min(MAX_TIMER_CALLBACKS);
        for (i, cb) in guard.iter().take(n).enumerate() {
            callbacks[i] = Some(*cb);
        }
        n
    };

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
    // R169-5 FIX (D1-CGROUP-IRQ-L5): This is the full process-context
    // deferred-work drain — it performs BLOCKING Level-8 (sockets/tcp_conns
    // teardown) and non-IRQ-safe Level-5 (CGROUP_REGISTRY port-uncharge,
    // Process) acquisitions plus a context-switch callback, so it MUST be
    // entered with interrupts ENABLED. An idle loop that needs a race-free arm
    // window must disable IRQs ONLY across the need_resched check + sti;hlt,
    // NEVER across this drain (see arch/smp.rs `ap_idle_loop`). `force_reschedule()`
    // is the deliberately drain-free, IRQ-adjacent-safe variant. This converts
    // the previously comment-only contract into a machine-checked invariant.
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "reschedule_if_needed() (full L8 + L5 deferred-work drain) must run with \
         interrupts ENABLED — never from an IRQ-off context (R169-5)"
    );

    // R65-6 FIX: Drain deferred TCP timer work before scheduling check
    crate::time::drain_deferred_tcp_timers();

    // R169-L9/L10/L11: rate-gated ns-agnostic stranded-port-charge sweep. The
    // alloc-time `reap_dead_bindings` only visits the namespace of an active
    // ephemeral allocation, so a socket dropped without close(), a charge stranded
    // in a quiescent sibling netns, or a binding pinned by a zombie process would
    // never be revisited and its port charge would leak toward ports.max. This
    // sweep generalizes the proven dead-`Weak` reap across both binding maps and
    // ALL namespaces (the maps are the single source of truth — no per-socket
    // mirror, hence no ABA-prone side state). It only ENQUEUES to the deferred
    // queue drained just below (so reclaimed charges apply this same pass) and
    // never crosses L8 -> L5 under a lock. Rate-gated (1 pass per
    // PORT_CHARGE_SWEEP_INTERVAL drains) to amortize the full-map scan.
    {
        // Coarse wrapping rate-gate tick, not an ID/refcount — wraparound is benign.
        let prev = PORT_CHARGE_SWEEP_TICK.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow
        if prev % PORT_CHARGE_SWEEP_INTERVAL == 0 {
            net::socket_table().sweep_stranded_port_charges();
        }
    }

    // J2-8: Drain deferred per-cgroup port uncharges in process context. Placed
    // AFTER the TCP-timer drain and the rate-gated sweep because both can tear
    // down ESTABLISHED connections / reap dead bindings, which ENQUEUE port
    // uncharges in this same pass. The cgroup uncharge takes CGROUP_REGISTRY
    // (Level 5) and so must run here (process context, IRQs ENABLED, no
    // net-binding lock held), never under the binding lock or in IRQ. NOT wired
    // into force_reschedule(): that hook is reachable from IRQ-adjacent paths
    // where a Level-5 acquire is illegal. R169-5: every caller of this function
    // (syscall return, nanosleep, BSP idle, and now the AP idle loop after its
    // restructure) runs with IRQs enabled, so this drain is genuinely
    // process-context on all paths — the debug_assert above enforces it. The
    // fold-by-cgid queue bounds any transient overshoot until this drain runs.
    net::socket_table().drain_deferred_port_uncharges();

    // R149-1 FIX: Drain deferred stdin wakes from keyboard/serial IRQ.
    crate::syscall::drain_deferred_stdin_wakes();

    // M4-1c: reap empty socket wait-queue BTreeMap nodes that the timer IRQ
    // (check_timeouts) deferred out of IRQ context (R151-5 dealloc class). Lock-free
    // fast-path + try_lock, so this is cheap when nothing emptied and never blocks.
    crate::syscall::drain_socket_waiter_cleanup();

    // R155-6 FIX: Drain deferred IRQ terminations in process context.
    crate::process::drain_deferred_irq_terminates();

    // E.4 RCU: Drain callbacks in process context.
    crate::rcu::poll();

    // R67-4 FIX: Consume this CPU's IRQ-triggered reschedule request
    let irq_pending = IRQ_RESCHED_PENDING.with(|flag| flag.swap(false, Ordering::SeqCst));

    // R160-3 FIX: Copy callback out of lock before invoking. The previous
    // `if let Some(cb) = *RESCHED_CB.lock() { cb(...); }` pattern held the
    // MutexGuard across the callback (Rust 2021 temporary lifetime rules).
    // The callback triggers context switches — holding a global spinlock
    // across switch_context corrupts the lock when the resumed task drops
    // its own stale MutexGuard. Same copy-then-call pattern as on_scheduler_tick().
    let cb = x86_64::instructions::interrupts::without_interrupts(|| *RESCHED_CB.lock());
    if let Some(cb) = cb {
        cb(irq_pending);
    }
}

/// 强制执行重调度
///
/// 由 sys_yield 调用，无论 NEED_RESCHED 标志如何都执行调度
#[inline]
pub fn force_reschedule() {
    // R160-3 FIX: Copy callback out of lock before invoking (same fix as reschedule_if_needed).
    let cb = x86_64::instructions::interrupts::without_interrupts(|| *RESCHED_CB.lock());
    if let Some(cb) = cb {
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
