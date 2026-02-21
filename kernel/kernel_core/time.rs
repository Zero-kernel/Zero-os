//! 简单时间管理模块
//!
//! 提供基于时钟中断的时间戳支持

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 全局时钟计数器（每次时钟中断递增）
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// 系统启动时间的 TSC 值（用于更精确的时间测量）
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Last TIME_WAIT sweep timestamp (ms)
static LAST_TIME_WAIT_SWEEP: AtomicU64 = AtomicU64::new(0);

/// Last TCP timer sweep timestamp (ms) for retransmission/FIN timers.
static LAST_TCP_TIMER_SWEEP: AtomicU64 = AtomicU64::new(0);

/// R65-6 FIX: Deferred TCP timer work pending flag.
///
/// Set when IRQ-time timer processing is incomplete (lock contention or
/// exceeded socket budget). Cleared when work is drained in safe context.
static TCP_TIMER_DEFERRED: AtomicBool = AtomicBool::new(false);

/// R65-6 FIX: Deferred timestamp for retry.
static TCP_TIMER_DEFERRED_TS: AtomicU64 = AtomicU64::new(0);

/// R65-6 FIX: Whether TIME_WAIT sweep is deferred.
static TCP_TIMER_DEFERRED_TW: AtomicBool = AtomicBool::new(false);

/// TCP timer sweep interval in milliseconds (data/FIN retransmission).
///
/// R53-3 FIX: Reduced from 5s to 200ms to support RFC 6298 retransmission.
/// With TCP_MIN_RTO_MS = 1000ms, a 200ms sweep interval means retransmissions
/// fire within 200ms of RTO expiry (worst case 1200ms from segment send).
///
/// 200ms balances:
/// - Responsiveness: 5x faster than previous 1s minimum
/// - CPU overhead: 25x less frequent than Codex-suggested 100ms
/// - Alignment: Matches RTO_CLOCK_GRANULARITY_US (100ms) reasonably well
const TCP_TIMER_SWEEP_INTERVAL_MS: u64 = 200;

/// TIME_WAIT sweep interval in milliseconds (coarse cleanup).
///
/// TIME_WAIT expiry is 120s (2MSL), so a 1s cadence is sufficient
/// while reducing load compared to the fast retransmission timer.
const TIME_WAIT_SWEEP_INTERVAL_MS: u64 = 1000;

/// 初始化时间子系统
pub fn init() {
    // 记录启动时的 TSC 值
    let tsc = read_tsc();
    BOOT_TSC.store(tsc, Ordering::SeqCst);
}

/// 时钟中断处理 - 递增时钟计数器
///
/// 应由定时器中断处理程序调用
#[inline]
pub fn on_timer_tick() {
    let current = TICK_COUNT.fetch_add(1, Ordering::SeqCst) + 1; // lint-fetch-add: allow (monotonic counter)

    // R53-3 FIX: Drive TCP timers at two frequencies:
    // - Fast timer (200ms): Data/FIN retransmission checks
    // - Slow timer (1s): TIME_WAIT cleanup
    //
    // This enables responsive retransmission (within 200ms of RTO expiry)
    // while avoiding excessive TIME_WAIT iteration overhead.

    let last_rto = LAST_TCP_TIMER_SWEEP.load(Ordering::Relaxed);
    let last_tw = LAST_TIME_WAIT_SWEEP.load(Ordering::Relaxed);

    let need_rto = current.saturating_sub(last_rto) >= TCP_TIMER_SWEEP_INTERVAL_MS;
    let need_tw = current.saturating_sub(last_tw) >= TIME_WAIT_SWEEP_INTERVAL_MS;

    // R65-6 FIX: Check if deferred work is pending from previous tick
    let had_deferred = TCP_TIMER_DEFERRED.load(Ordering::Acquire);

    // Early exit if neither timer has fired and no deferred work
    if !need_rto && !need_tw && !had_deferred {
        return;
    }

    let mut run_rto = false;
    let mut run_tw = false;

    // Claim the RTO timer (CAS to avoid concurrent sweeps)
    if need_rto
        && LAST_TCP_TIMER_SWEEP
            .compare_exchange(last_rto, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        run_rto = true;
    }

    // Claim the TIME_WAIT timer
    if need_tw
        && LAST_TIME_WAIT_SWEEP
            .compare_exchange(last_tw, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        run_tw = true;
    }

    // R65-6 FIX: Include deferred TIME_WAIT sweep
    if had_deferred && TCP_TIMER_DEFERRED_TW.load(Ordering::Relaxed) {
        run_tw = true;
    }

    // Run TCP timers if either was claimed or we have deferred work
    if run_rto || run_tw || had_deferred {
        let completed = net::socket_table().run_tcp_timers(current, run_tw);

        // R65-6 FIX: If timer processing was incomplete, defer to safe context
        if !completed {
            TCP_TIMER_DEFERRED.store(true, Ordering::Release);
            TCP_TIMER_DEFERRED_TS.store(current, Ordering::Relaxed);
            if run_tw {
                TCP_TIMER_DEFERRED_TW.store(true, Ordering::Relaxed);
            }
            // Request reschedule to drain in safe context
            crate::request_resched_from_irq();
        } else {
            // Clear deferred flags on successful completion
            TCP_TIMER_DEFERRED.store(false, Ordering::Release);
            TCP_TIMER_DEFERRED_TW.store(false, Ordering::Relaxed);
        }
    }
}

/// 获取当前时钟计数（自启动以来的时钟周期数）
#[inline]
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::SeqCst)
}

/// 获取当前时间戳（毫秒）
///
/// 假设时钟中断频率为 1000Hz（每毫秒一次）
/// 如果实际频率不同，需要相应调整
#[inline]
pub fn current_timestamp_ms() -> u64 {
    get_ticks()
}

/// 读取 CPU 的时间戳计数器 (TSC)
#[inline]
pub fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, nomem)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 获取自启动以来的 TSC 差值
pub fn tsc_since_boot() -> u64 {
    let current = read_tsc();
    let boot = BOOT_TSC.load(Ordering::SeqCst);
    current.saturating_sub(boot)
}

/// R65-6 FIX: Drain deferred TCP timer work in safe (non-IRQ) context.
///
/// Called from syscall return path to ensure timer work is not starved when
/// IRQ-time processing was incomplete due to lock contention or exceeded
/// socket budget.
///
/// This provides a safety net: even if IRQ-time timer processing is repeatedly
/// blocked, the work will eventually complete when a process makes a syscall.
pub fn drain_deferred_tcp_timers() {
    // Fast path: nothing deferred
    if !TCP_TIMER_DEFERRED.load(Ordering::Acquire) {
        return;
    }

    // Get deferred parameters
    let ts = TCP_TIMER_DEFERRED_TS.load(Ordering::Relaxed);
    let sweep_tw = TCP_TIMER_DEFERRED_TW.load(Ordering::Relaxed);
    let current = if ts == 0 { current_timestamp_ms() } else { ts };

    // Use blocking variant which will wait for locks
    let completed = net::socket_table().run_tcp_timers_blocking(current, sweep_tw);

    if completed {
        TCP_TIMER_DEFERRED.store(false, Ordering::Release);
        TCP_TIMER_DEFERRED_TW.store(false, Ordering::Relaxed);
        TCP_TIMER_DEFERRED_TS.store(0, Ordering::Relaxed);
    }
    // If still incomplete, leave deferred flag set for next opportunity
}
