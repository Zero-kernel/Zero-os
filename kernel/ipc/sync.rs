//! 同步原语
//!
//! 提供内核空间的同步机制，包括：
//! - 等待队列（WaitQueue）：用于进程阻塞/唤醒
//! - 互斥锁（KMutex）：内核互斥锁（可阻塞）
//! - 信号量（Semaphore）：计数信号量
//!
//! 这些原语是管道、消息队列阻塞操作的基础

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kernel_core::process::{self, ProcessId, ProcessState};
use spin::Mutex;
use x86_64::instructions::interrupts;

/// R39-6 FIX: 纳秒到毫秒 Tick 的转换常量（时钟频率 1kHz）
const NS_PER_MS: u64 = 1_000_000;

/// R39-6 FIX: 等待结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// 被正常唤醒
    Woken,
    /// 等待超时
    TimedOut,
    /// 队列已关闭
    Closed,
    /// 无当前进程
    NoProcess,
}

/// R39-6 FIX: 定时等待者记录
#[derive(Debug, Clone, Copy)]
struct TimedWaiter {
    /// 等待队列指针（用于匹配）
    queue: usize,
    /// 等待的进程ID
    pid: ProcessId,
    /// 超时截止时间（tick）
    deadline_tick: u64,
}

/// R39-6 FIX: 全局定时等待者列表
static TIMED_WAITERS: Mutex<Vec<TimedWaiter>> = Mutex::new(Vec::new());

/// R39-6 FIX: 定时器回调是否已注册
static WAITQUEUE_TIMER_INIT: AtomicBool = AtomicBool::new(false);

/// 等待队列
///
/// 用于进程阻塞和唤醒。当资源不可用时，进程加入等待队列；
/// 当资源可用时，唤醒等待队列中的进程。
///
/// # X-6 安全增强
///
/// 添加 `closed` 标志防止在端点销毁后新的等待者加入，
/// 避免永久阻塞和资源泄漏。
///
/// # R39-6 FIX: 超时支持
///
/// 添加 `timed_out` 集合记录因超时被唤醒的进程，
/// 用于区分正常唤醒与超时唤醒。
pub struct WaitQueue {
    /// 等待的进程ID列表
    waiters: Mutex<VecDeque<ProcessId>>,
    /// 当为 true 时不再接受新的等待者（用于端点销毁时取消阻塞）
    closed: AtomicBool,
    /// R39-6 FIX: 标记因超时被唤醒的进程
    timed_out: Mutex<BTreeSet<ProcessId>>,
}

impl WaitQueue {
    /// 创建新的等待队列
    pub fn new() -> Self {
        WaitQueue {
            waiters: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            timed_out: Mutex::new(BTreeSet::new()),
        }
    }

    /// 将当前进程加入等待队列并阻塞
    ///
    /// 返回true表示成功阻塞后被唤醒，false表示无当前进程或队列已关闭
    ///
    /// # X-6 安全增强
    ///
    /// 如果队列已关闭（如端点被销毁），立即返回 false 而不阻塞，
    /// 防止进程在已销毁的端点上永久阻塞。
    pub fn wait(&self) -> bool {
        matches!(self.wait_with_timeout(None), WaitOutcome::Woken)
    }

    /// R39-6 FIX: 将当前进程加入等待队列并阻塞（可选超时）
    ///
    /// # Arguments
    ///
    /// * `timeout_ns` - 超时时间（纳秒），None 表示无限等待
    ///
    /// # Returns
    ///
    /// 返回等待结果，用于区分正常唤醒与超时唤醒。
    pub fn wait_with_timeout(&self, timeout_ns: Option<u64>) -> WaitOutcome {
        let pid = match process::current_pid() {
            Some(p) => p,
            None => return WaitOutcome::NoProcess,
        };

        // X-6: 快速检查 - 如果已关闭则不阻塞
        if self.closed.load(Ordering::Acquire) {
            return WaitOutcome::Closed;
        }

        // 零超时：直接返回超时
        if matches!(timeout_ns, Some(0)) {
            return WaitOutcome::TimedOut;
        }

        // 计算超时截止时间（tick）
        let deadline_tick = timeout_ns.map(|ns| {
            let ticks = (ns + NS_PER_MS - 1) / NS_PER_MS;
            let ticks = if ticks == 0 { 1 } else { ticks };
            kernel_core::get_ticks().saturating_add(ticks)
        });

        let mut enqueued = false;

        // 在关中断状态下操作，防止竞态条件
        interrupts::without_interrupts(|| {
            // X-6: 二次检查 - 在临界区内再次确认未关闭
            if self.closed.load(Ordering::Relaxed) {
                return;
            }

            // 将当前进程加入等待队列
            self.waiters.lock().push_back(pid);

            // 将进程状态设为阻塞
            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                proc.state = ProcessState::Blocked;
            }

            enqueued = true;
        });

        // X-6: 如果未能入队（队列已关闭），直接返回
        if !enqueued {
            return WaitOutcome::Closed;
        }

        // 注册超时
        if let Some(deadline) = deadline_tick {
            ensure_waitqueue_timer_registered();
            register_timed_wait(self as *const _ as usize, pid, deadline);
        }

        // 触发调度，让出CPU
        kernel_core::force_reschedule();

        // 唤醒后清理超时登记
        if deadline_tick.is_some() {
            cancel_timed_wait(self as *const _ as usize, pid);
        }

        // 检查是否因超时唤醒
        if self.consume_timeout_flag(pid) {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Woken
        }
    }

    /// R39-6 FIX: 标记指定进程因超时唤醒（从队列移除并设置为 Ready）
    fn timeout_wake(&self, pid: ProcessId) {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            if let Some(pos) = waiters.iter().position(|&p| p == pid) {
                waiters.remove(pos);
            }
            drop(waiters);

            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                }
            }

            self.timed_out.lock().insert(pid);
        });
    }

    /// R39-6 FIX: 消费超时标记
    fn consume_timeout_flag(&self, pid: ProcessId) -> bool {
        self.timed_out.lock().remove(&pid)
    }

    /// 唤醒等待队列中的一个进程
    ///
    /// 返回被唤醒的进程ID，如果队列为空返回None
    pub fn wake_one(&self) -> Option<ProcessId> {
        interrupts::without_interrupts(|| {
            let pid = self.waiters.lock().pop_front()?;
            // R39-6 FIX: 取消该进程的定时等待
            cancel_timed_wait(self as *const _ as usize, pid);

            // 将进程状态设为就绪
            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                }
            }

            Some(pid)
        })
    }

    /// 唤醒等待队列中的所有进程
    ///
    /// 返回被唤醒的进程数量
    pub fn wake_all(&self) -> usize {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let count = waiters.len();

            while let Some(pid) = waiters.pop_front() {
                // R39-6 FIX: 取消该进程的定时等待
                cancel_timed_wait(self as *const _ as usize, pid);
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.state = ProcessState::Ready;
                    }
                }
            }

            count
        })
    }

    /// 唤醒等待队列中的最多 n 个进程
    ///
    /// 用于 futex FUTEX_WAKE 操作，只唤醒指定数量的等待者
    ///
    /// # Arguments
    ///
    /// * `n` - 最多唤醒的进程数量
    ///
    /// # Returns
    ///
    /// 实际唤醒的进程数量
    pub fn wake_n(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let mut woken = 0;

            while woken < n {
                if let Some(pid) = waiters.pop_front() {
                    // R39-6 FIX: 取消该进程的定时等待
                    cancel_timed_wait(self as *const _ as usize, pid);
                    if let Some(proc_arc) = process::get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.state = ProcessState::Ready;
                            woken += 1;
                        }
                    }
                } else {
                    break;
                }
            }

            woken
        })
    }

    /// E.4 PI: 唤醒指定的等待者（如果存在）
    ///
    /// 用于需要精确唤醒特定进程的场景（例如 FUTEX_LOCK_PI 选择最高优先级等待者）。
    ///
    /// # Arguments
    ///
    /// * `pid` - 要唤醒的进程 ID
    ///
    /// # Returns
    ///
    /// 如果成功唤醒该进程返回 true，否则返回 false
    pub fn wake_specific(&self, pid: ProcessId) -> bool {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            if let Some(pos) = waiters.iter().position(|&p| p == pid) {
                waiters.remove(pos);
                // 取消该进程的定时等待
                cancel_timed_wait(self as *const _ as usize, pid);
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.state = ProcessState::Ready;
                    }
                }
                true
            } else {
                false
            }
        })
    }

    /// 检查等待队列是否为空
    pub fn is_empty(&self) -> bool {
        self.waiters.lock().is_empty()
    }

    /// 获取等待队列中的进程数量
    pub fn len(&self) -> usize {
        self.waiters.lock().len()
    }

    /// Z-11 fix: 准备等待（添加到队列但不立即阻塞）
    ///
    /// 用于实现条件变量语义，避免 lost-wakeup 竞态条件。
    /// 调用者应在持有相关锁的情况下调用此函数，然后释放锁，
    /// 最后调用 `finish_wait()` 来实际阻塞。
    ///
    /// # Returns
    ///
    /// 如果成功加入队列返回 true，如果无当前进程或队列已关闭返回 false
    pub fn prepare_to_wait(&self) -> bool {
        let pid = match process::current_pid() {
            Some(p) => p,
            None => return false,
        };

        // 如果已关闭则不阻塞
        if self.closed.load(Ordering::Acquire) {
            return false;
        }

        interrupts::without_interrupts(|| {
            // 再次检查未关闭
            if self.closed.load(Ordering::Relaxed) {
                return false;
            }

            // 将当前进程加入等待队列
            self.waiters.lock().push_back(pid);

            // 将进程状态设为阻塞
            if let Some(proc_arc) = process::get_process(pid) {
                let mut proc = proc_arc.lock();
                proc.state = ProcessState::Blocked;
            }

            true
        })
    }

    /// Z-11 fix: 完成等待（实际阻塞）
    ///
    /// 必须在 `prepare_to_wait()` 返回 true 之后调用。
    /// 在调用此函数之前应释放相关锁。
    pub fn finish_wait(&self) {
        // 触发调度，让出CPU
        kernel_core::force_reschedule();
    }

    /// Z-11 fix: 取消等待（从队列移除）
    ///
    /// 如果在 `prepare_to_wait()` 后发现条件已满足，
    /// 调用此函数取消等待而不阻塞。
    ///
    /// # Returns
    ///
    /// 如果成功从队列移除返回 true
    pub fn cancel_wait(&self) -> bool {
        let pid = match process::current_pid() {
            Some(p) => p,
            None => return false,
        };

        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();

            // 从队列中移除当前进程
            if let Some(pos) = waiters.iter().position(|&p| p == pid) {
                waiters.remove(pos);
                // R39-6 FIX: 取消定时等待
                cancel_timed_wait(self as *const _ as usize, pid);

                // 恢复进程状态为就绪
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    proc.state = ProcessState::Ready;
                }

                true
            } else {
                false
            }
        })
    }

    /// 检查队列是否已关闭（例如端点被销毁）
    ///
    /// # X-6 安全增强
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 关闭队列并唤醒所有等待者
    ///
    /// 用于端点销毁时，确保所有等待者被唤醒并得到错误返回。
    /// 关闭后的队列不再接受新的等待者。
    ///
    /// # X-6 安全增强
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake_all();
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// 内核互斥锁
///
/// 可阻塞的互斥锁，当锁不可用时进程会被阻塞。
/// 适用于需要长时间持有锁的场景。
pub struct KMutex {
    /// 锁状态：true表示已锁定
    locked: AtomicBool,
    /// 等待队列
    wait_queue: WaitQueue,
    /// 当前持有锁的进程ID（调试用）
    owner: Mutex<Option<ProcessId>>,
}

impl KMutex {
    /// 创建新的互斥锁
    pub fn new() -> Self {
        KMutex {
            locked: AtomicBool::new(false),
            wait_queue: WaitQueue::new(),
            owner: Mutex::new(None),
        }
    }

    /// 获取锁
    ///
    /// 如果锁已被持有，当前进程会被阻塞直到锁可用
    pub fn lock(&self) {
        loop {
            // 尝试获取锁
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // 成功获取锁
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return;
            }

            // 锁被占用，加入等待队列并阻塞
            self.wait_queue.wait();
        }
    }

    /// 尝试获取锁（非阻塞）
    ///
    /// 如果锁可用，获取锁并返回true；否则返回false
    pub fn try_lock(&self) -> bool {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            if let Some(pid) = process::current_pid() {
                *self.owner.lock() = Some(pid);
            }
            true
        } else {
            false
        }
    }

    /// 释放锁
    pub fn unlock(&self) {
        *self.owner.lock() = None;
        self.locked.store(false, Ordering::Release);

        // 唤醒一个等待者
        self.wait_queue.wake_one();
    }

    /// 检查锁是否被持有
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl Default for KMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// 计数信号量
///
/// 用于控制对有限资源的并发访问
pub struct Semaphore {
    /// 当前计数
    count: AtomicU32,
    /// 等待队列
    wait_queue: WaitQueue,
}

impl Semaphore {
    /// 创建新的信号量
    ///
    /// # Arguments
    ///
    /// * `initial` - 初始计数值
    pub fn new(initial: u32) -> Self {
        Semaphore {
            count: AtomicU32::new(initial),
            wait_queue: WaitQueue::new(),
        }
    }

    /// P操作（等待/获取）
    ///
    /// 如果计数大于0，减1并继续；否则阻塞直到计数大于0
    pub fn wait(&self) {
        loop {
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                // 尝试减少计数
                if self
                    .count
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return;
                }
                // CAS失败，重试
                continue;
            }

            // 计数为0，阻塞
            self.wait_queue.wait();
        }
    }

    /// P操作（非阻塞）
    ///
    /// 如果计数大于0，减1并返回true；否则返回false
    pub fn try_wait(&self) -> bool {
        loop {
            let current = self.count.load(Ordering::SeqCst);
            if current == 0 {
                return false;
            }
            if self
                .count
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// V操作（发布/释放）
    ///
    /// 增加计数并唤醒一个等待者
    pub fn signal(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.wait_queue.wake_one();
    }

    /// 获取当前计数
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

/// 条件变量
///
/// 用于等待特定条件成立
pub struct CondVar {
    /// 等待队列
    wait_queue: WaitQueue,
}

impl CondVar {
    /// 创建新的条件变量
    pub fn new() -> Self {
        CondVar {
            wait_queue: WaitQueue::new(),
        }
    }

    /// 等待条件成立
    ///
    /// 调用者必须在持有相关锁的情况下调用此函数。
    /// 此函数会释放锁、等待唤醒、然后重新获取锁。
    ///
    /// # Arguments
    ///
    /// * `mutex` - 保护条件的互斥锁
    pub fn wait(&self, mutex: &KMutex) {
        // 释放锁
        mutex.unlock();

        // 等待唤醒
        self.wait_queue.wait();

        // 重新获取锁
        mutex.lock();
    }

    /// 唤醒一个等待者
    pub fn notify_one(&self) {
        self.wait_queue.wake_one();
    }

    /// 唤醒所有等待者
    pub fn notify_all(&self) {
        self.wait_queue.wake_all();
    }
}

impl Default for CondVar {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// R39-6 FIX: WaitQueue 超时支持辅助函数
// =============================================================================

/// R39-6 FIX: 初始化 WaitQueue 定时器回调
///
/// 在 IPC 模块初始化时调用，注册定时器回调以处理超时唤醒。
pub fn init_waitqueue_timers() {
    ensure_waitqueue_timer_registered();
}

/// 确保定时器回调已注册（只注册一次）
fn ensure_waitqueue_timer_registered() {
    if WAITQUEUE_TIMER_INIT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        kernel_core::register_timer_callback(waitqueue_timer_tick);
    }
}

/// 注册定时等待
fn register_timed_wait(queue: usize, pid: ProcessId, deadline_tick: u64) {
    TIMED_WAITERS.lock().push(TimedWaiter {
        queue,
        pid,
        deadline_tick,
    });
}

/// 取消定时等待
fn cancel_timed_wait(queue: usize, pid: ProcessId) {
    let mut waits = TIMED_WAITERS.lock();
    waits.retain(|w| !(w.queue == queue && w.pid == pid));
}

/// Maximum number of timeouts to process per tick (prevents allocation in IRQ context)
const MAX_TIMEOUTS_PER_TICK: usize = 16;

/// 处理超时的等待者
///
/// # Codex Review Fix
///
/// Use fixed-size stack array instead of Vec to avoid heap allocation
/// in IRQ context. MAX_TIMEOUTS_PER_TICK limits how many timeouts
/// are processed per tick; excess will be caught in next tick.
fn process_waitqueue_timeouts(now_ticks: u64) {
    let mut expired: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let count = {
        let mut waits = TIMED_WAITERS.lock();
        let mut expired_count = 0;
        let mut i = 0;
        while i < waits.len() && expired_count < MAX_TIMEOUTS_PER_TICK {
            if waits[i].deadline_tick <= now_ticks {
                expired[expired_count] = Some(waits.remove(i));
                expired_count += 1;
            } else {
                i += 1;
            }
        }
        expired_count
    };

    for waiter in expired.iter().take(count).flatten() {
        // 安全性：waiter.queue 来源于 &WaitQueue 的地址，
        // 调用者需确保 WaitQueue 在超时期间仍然有效
        unsafe {
            if let Some(queue) = (waiter.queue as *const WaitQueue).as_ref() {
                queue.timeout_wake(waiter.pid);
            }
        }
    }
}

/// 定时器回调：每个 tick 检查超时
fn waitqueue_timer_tick() {
    let now = kernel_core::get_ticks();
    process_waitqueue_timeouts(now);
}
