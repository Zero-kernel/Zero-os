//! 同步原语
//!
//! 提供内核空间的同步机制，包括：
//! - 等待队列（WaitQueue）：用于进程阻塞/唤醒
//! - 互斥锁（KMutex）：内核互斥锁（可阻塞）
//! - 信号量（Semaphore）：计数信号量
//!
//! 这些原语是管道、消息队列阻塞操作的基础

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
    /// R165-4 FIX: The exact `wait_with_timeout` generation this timer belongs to.
    /// Carried through to `timeout_wake` so the recorded timeout flag is tagged
    /// with the waiter's OWN generation (not a global snapshot), letting
    /// `consume_timeout_flag` match it exactly and reject stale flags.
    generation: u64,
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
    /// R165-4 FIX: Each waiter is tagged with the `wait_with_timeout` generation
    /// that enqueued it (or a fresh generation for the condvar prepare_to_wait
    /// path). `timeout_wake` only acts on an exact (pid, generation) match, so a
    /// stale/re-inserted timer cannot wake a different, later wait by the same
    /// PID — including one blocked on a *different* queue.
    waiters: Mutex<VecDeque<(ProcessId, u64)>>,
    /// 当为 true 时不再接受新的等待者（用于端点销毁时取消阻塞）
    closed: AtomicBool,
    /// R164-10 FIX: Timeout entries tagged with (PID, generation) to prevent
    /// PID reuse misclassification. A stale entry from a dead process whose
    /// PID was recycled cannot match the new process's generation.
    timed_out: Mutex<BTreeMap<ProcessId, u64>>,
    /// Monotonic generation counter, incremented on each wait_with_timeout call.
    wait_generation: AtomicU64,
}

impl WaitQueue {
    /// 创建新的等待队列
    pub fn new() -> Self {
        WaitQueue {
            waiters: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            timed_out: Mutex::new(BTreeMap::new()),
            wait_generation: AtomicU64::new(0),
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

        // R164-10 FIX: Snapshot a unique generation for this wait call.
        let my_gen = self.wait_generation.fetch_add(1, Ordering::Relaxed);

        // X-6: 快速检查 - 如果已关闭则不阻塞
        if self.closed.load(Ordering::Acquire) {
            return WaitOutcome::Closed;
        }

        // 零超时：直接返回超时
        if matches!(timeout_ns, Some(0)) {
            return WaitOutcome::TimedOut;
        }

        // 计算超时截止时间（tick）
        // R154-10 FIX: Use checked_add to prevent overflow when user supplies
        // huge timeout values (e.g. u64::MAX). The previous (ns + NS_PER_MS - 1)
        // expression wraps around for ns > u64::MAX - NS_PER_MS + 1, producing a
        // near-zero tick count and effectively no timeout.
        let deadline_tick = timeout_ns.map(|ns| {
            let ticks = ns.checked_add(NS_PER_MS - 1).unwrap_or(u64::MAX) / NS_PER_MS;
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

            // R153-1 FIX: Check for duplicate before enqueue. A spurious
            // reschedule can re-enter wait_with_timeout() for the same PID,
            // causing multiple copies that consume wake signals meant for
            // other waiters (Semaphore/CondVar/socket recv all affected).
            {
                let mut waiters = self.waiters.lock();
                // R165-4 FIX: The queued membership and the timer record must
                // advance together. If this PID is already queued (a prior wait
                // whose entry lingered after a non-WaitQueue wake — e.g. a signal
                // setting the task Ready directly), REFRESH its generation to this
                // wait's my_gen. Otherwise register_timed_wait would make the new
                // generation authoritative while the deque still held the old one,
                // and timeout_wake's exact (pid, generation) check would drop this
                // wait's timer — a missed legitimate timeout.
                let mut refreshed = false;
                for entry in waiters.iter_mut() {
                    if entry.0 == pid {
                        entry.1 = my_gen;
                        refreshed = true;
                        break;
                    }
                }
                if !refreshed {
                    waiters.push_back((pid, my_gen));
                }
            }

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

        // R158-1 FIX: register under IRQ-disable to prevent deadlock with
        // process_waitqueue_timeouts() acquiring TIMED_WAITERS from timer IRQ.
        if let Some(deadline) = deadline_tick {
            ensure_waitqueue_timer_registered();
            interrupts::without_interrupts(|| {
                // R165-4 FIX: Record this wait's own generation in the timer so a
                // fired timeout is attributed to this exact wait instance.
                register_timed_wait(self as *const _ as usize, pid, deadline, my_gen);
            });
        }

        // 触发调度，让出CPU
        kernel_core::force_reschedule();

        // R158-1 FIX: cancel under IRQ-disable (same lock ordering as register).
        if deadline_tick.is_some() {
            interrupts::without_interrupts(|| {
                cancel_timed_wait(self as *const _ as usize, pid);
            });
        }

        // R164-10 FIX: Pass generation to consume — only accept if the
        // timed_out entry's generation matches our wait call's generation.
        if self.consume_timeout_flag(pid, my_gen) {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Woken
        }
    }

    /// R39-6 FIX: 标记指定进程因超时唤醒（从队列移除并设置为 Ready）
    ///
    /// Returns true if the wake completed, false if Process lock was contended
    /// (caller should retry on next tick).
    fn timeout_wake(&self, pid: ProcessId, generation: u64) -> bool {
        interrupts::without_interrupts(|| {
            // R165-4 FIX: Act only if THIS exact (pid, generation) is still queued
            // on THIS WaitQueue. A stale timer — re-inserted by a retry that raced
            // a normal wake, or left over from a finished wait — will not match and
            // must not wake an unrelated later wait by the same PID (possibly even
            // one blocked on a different queue). Hold the waiters lock across the
            // try_lock(proc): try_lock can never deadlock, and waiters->proc is the
            // same order wake_all uses.
            let mut waiters = self.waiters.lock();
            let pos = match waiters
                .iter()
                .position(|&(p, g)| p == pid && g == generation)
            {
                Some(pos) => pos,
                None => return true, // not our waiter — let the timer be dropped
            };

            // R155-2 FIX: try_lock() to avoid deadlock in IRQ context.
            if let Some(proc_arc) = process::get_process(pid) {
                if let Some(mut proc) = proc_arc.try_lock() {
                    // R165-4 FIX: Record the timeout only when THIS call performs
                    // the Blocked->Ready transition. If the task was already Ready
                    // (a normal wake beat us), recording a timeout flag would be a
                    // stale entry.
                    let was_blocked = proc.state == ProcessState::Blocked;
                    if was_blocked {
                        proc.state = ProcessState::Ready;
                    }
                    drop(proc);
                    waiters.remove(pos);
                    drop(waiters);
                    if was_blocked {
                        // Tag with the waiter's OWN generation (from the timer
                        // record); consume_timeout_flag requires an exact match.
                        self.timed_out.lock().insert(pid, generation);
                    }
                    true
                } else {
                    // Contended (e.g. a concurrent wake holds the process lock).
                    // Keep membership and retry on the next tick.
                    false
                }
            } else {
                // R155-12 FIX: Process no longer exists (killed). Drop membership;
                // do NOT insert a timeout flag (no one would consume it).
                waiters.remove(pos);
                true
            }
        })
    }

    // R165-4 FIX: Consume the timeout flag only on an EXACT generation match.
    // A stored generation strictly less than `expected_gen` is a stale leftover
    // from an earlier wait by this PID (its consumer raced a normal wake); drop
    // it without reporting a timeout. A stored generation greater than expected
    // is impossible (a single PID cannot have two concurrent waits). Tightening
    // R164-10's `>=` to `==` closes the spurious-ETIMEDOUT path.
    fn consume_timeout_flag(&self, pid: ProcessId, expected_gen: u64) -> bool {
        let mut set = self.timed_out.lock();
        if let Some(&stored_gen) = set.get(&pid) {
            if stored_gen <= expected_gen {
                set.remove(&pid);
                return stored_gen == expected_gen;
            }
        }
        false
    }

    /// R156-6 FIX: Remove stale entries for an exiting process.
    pub fn cleanup_for_pid(&self, pid: ProcessId) {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            waiters.retain(|&(p, _)| p != pid);
            drop(waiters);
            self.timed_out.lock().remove(&pid);
        });
    }

    /// 唤醒等待队列中的一个进程
    ///
    /// 返回被唤醒的进程ID，如果队列为空返回None
    pub fn wake_one(&self) -> Option<ProcessId> {
        interrupts::without_interrupts(|| {
            let pid = self.waiters.lock().pop_front()?.0;
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

            while let Some((pid, _gen)) = waiters.pop_front() {
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
                if let Some((pid, _gen)) = waiters.pop_front() {
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
            if let Some(pos) = waiters.iter().position(|&(p, _)| p == pid) {
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

            // R152-8 FIX: Check for duplicate enqueue before pushing.
            // Without this, spurious reschedule returns cause the same PID
            // to accumulate in the deque, consuming wake signals meant for
            // other waiters.
            let mut waiters = self.waiters.lock();
            if waiters.iter().any(|&(p, _)| p == pid) {
                return true; // Already enqueued — no duplicate
            }

            // 将当前进程加入等待队列
            // R165-4 FIX: the condvar prepare_to_wait path never registers a
            // timer, so its generation only needs to be unique; snapshot one so
            // the entry shape matches the timed path and wake/cancel stay uniform.
            let gen = self.wait_generation.fetch_add(1, Ordering::Relaxed);
            waiters.push_back((pid, gen));

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
            if let Some(pos) = waiters.iter().position(|&(p, _)| p == pid) {
                waiters.remove(pos);
                // R39-6 FIX: 取消定时等待
                cancel_timed_wait(self as *const _ as usize, pid);

                // 恢复进程状态为就绪
                //
                // R170-4 FIX: restore Ready ONLY when the state is still the
                // `Blocked` our own prepare_to_wait() wrote (the exact undo).
                // cancel_wait is also reached from paths where the caller has
                // already RESUMED and is Running (the futex_lock_pi success /
                // EAGAIN exits after a non-dequeuing wake): tasks stay in the
                // ready queue while Running, and `state == Ready` is the
                // scheduler's claim gate, so an unconditional Ready re-stamp
                // would let another CPU's pick/steal claim a task that is
                // still executing here (same-task-on-two-CPUs). The guard
                // also stops resurrecting a Zombie/Terminated task to Ready.
                // Every legacy caller cancels immediately after
                // prepare_to_wait (state IS Blocked), so their behavior is
                // byte-identical.
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

    /// R155-7 FIX: Use prepare_to_wait/cancel_wait pattern (same as R154-6 Semaphore)
    /// to prevent lost-wakeup race where unlock() calls wake_one() between our
    /// CAS failure and enqueue, seeing an empty queue.
    pub fn lock(&self) {
        loop {
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return;
            }

            if !self.wait_queue.prepare_to_wait() {
                return;
            }

            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.wait_queue.cancel_wait();
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return;
            }

            self.wait_queue.finish_wait();
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
    ///
    /// R154-16 FIX: Debug assertion verifying caller owns the lock.
    pub fn unlock(&self) {
        debug_assert!(
            {
                let owner = self.owner.lock();
                owner.is_none() || *owner == process::current_pid()
            },
            "KMutex::unlock() called by non-owner"
        );
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
    ///
    /// # R154-6 FIX: Use prepare_to_wait/cancel_wait pattern to prevent lost wakeup.
    ///
    /// The old sequence had a classic lost-wakeup race: (1) load count=0,
    /// (2) signal() fires — count becomes 1, wake_one() sees empty queue,
    /// (3) process enters wait_queue.wait() and blocks forever.
    /// Now we register in the wait queue BEFORE checking count, so any
    /// signal() between check and block will find us in the queue.
    pub fn wait(&self) {
        loop {
            // Fast path: try to decrement without blocking
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                if self
                    .count
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return;
                }
                continue;
            }

            // R154-6 FIX: Register in wait queue BEFORE re-checking count.
            if !self.wait_queue.prepare_to_wait() {
                return; // No current process or queue closed
            }

            // Re-check count after registration: a signal() between our
            // initial load and prepare_to_wait would have incremented count
            // AND called wake_one (which now sees us in the queue).
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                if self
                    .count
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    // Got the permit — cancel the wait, don't block.
                    self.wait_queue.cancel_wait();
                    return;
                }
                // CAS failed — someone else grabbed it. Stay in queue and block.
            }

            // Block until woken by signal()
            self.wait_queue.finish_wait();
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
    ///
    /// R154-17 FIX: Use saturating increment to prevent u32 wrap-around
    /// that would clear all permits (count wraps from MAX to 0).
    pub fn signal(&self) {
        let _ = self.count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            Some(v.saturating_add(1))
        });
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
    /// # R153-7 FIX: Use prepare_to_wait/finish_wait pattern.
    ///
    /// The old sequence (unlock → wait) had a lost-wakeup window: if
    /// notify_one() fires between mutex.unlock() and wait_queue enqueue,
    /// the wake signal is lost because the waiter is not yet registered.
    /// Now we register BEFORE releasing the mutex, so the wake cannot
    /// be missed.
    ///
    /// # Arguments
    ///
    /// * `mutex` - 保护条件的互斥锁
    pub fn wait(&self, mutex: &KMutex) {
        // R153-7 FIX: Register in wait queue BEFORE releasing mutex.
        // If notify_one() fires after mutex release, our PID is already
        // in the queue and the wake signal will be delivered.
        if !self.wait_queue.prepare_to_wait() {
            return; // No current process or queue closed
        }

        // 释放锁 — notifiers can now run
        mutex.unlock();

        // 实际阻塞
        self.wait_queue.finish_wait();

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
fn register_timed_wait(queue: usize, pid: ProcessId, deadline_tick: u64, generation: u64) {
    // R143-5 FIX: All WaitQueue instances must be 'static (kernel BSS/data).
    // If a heap/stack WaitQueue were used with timed waits, the raw `usize`
    // address could dangle after the WaitQueue is dropped. This assert catches
    // accidental non-static usage in debug builds. Kernel static data lives
    // in the high-half address space (>= 0xFFFF_FFFF_8000_0000).
    debug_assert!(
        queue >= 0xFFFF_FFFF_8000_0000,
        "R143-5: WaitQueue address 0x{:x} is not in kernel static range — \
         timed waits require 'static WaitQueue instances",
        queue
    );
    // R154-10 FIX: Deduplicate before pushing. A spurious reschedule or
    // re-entrant wait path can call register_timed_wait() for the same
    // (queue, pid) pair, creating duplicate entries that consume extra
    // timeout slots and may cause double-wakeup.
    // R165-4 FIX: REPLACE any pre-existing (queue, pid) entry rather than skip.
    // A given (queue, pid) can have at most one active wait, so any prior entry
    // is a stale leftover (e.g. a timer-retry that raced a normal wake). Skipping
    // it (the old behavior) could leave the *new* wait with the *old* generation
    // — or no timer at all. Replacing makes this wait's generation authoritative;
    // any still-pending stale timer is harmless because timeout_wake now requires
    // an exact (pid, generation) membership match.
    let mut waiters = TIMED_WAITERS.lock();
    waiters.retain(|w| !(w.queue == queue && w.pid == pid));
    waiters.push(TimedWaiter {
        queue,
        pid,
        deadline_tick,
        generation,
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

    // R155-2 FIX: Track failed wakes for re-insertion
    let mut retry: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let mut retry_count = 0;

    for waiter in expired.iter().take(count).flatten() {
        unsafe {
            if let Some(queue) = (waiter.queue as *const WaitQueue).as_ref() {
                if !queue.timeout_wake(waiter.pid, waiter.generation) {
                    if retry_count < MAX_TIMEOUTS_PER_TICK {
                        retry[retry_count] = Some(*waiter);
                        retry_count += 1;
                    }
                }
            }
        }
    }

    // Re-insert failed wakes so the next tick retries
    if retry_count > 0 {
        let mut waits = TIMED_WAITERS.lock();
        for w in retry.iter().take(retry_count).flatten() {
            waits.push(*w);
        }
    }
}

/// 定时器回调：每个 tick 检查超时
fn waitqueue_timer_tick() {
    let now = kernel_core::get_ticks();
    process_waitqueue_timeouts(now);
}
