//! 同步原语
//!
//! 提供内核空间的同步机制，包括：
//! - 等待队列（WaitQueue）：用于进程阻塞/唤醒
//! - 互斥锁（KMutex）：内核互斥锁（可阻塞）
//! - 信号量（Semaphore）：计数信号量
//!
//! 这些原语是管道、消息队列阻塞操作的基础

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
    /// R171 (F3): 等待期间检测到挂起的 kill —— 以 EINTR 中断阻塞，而非重新挂起。
    Interrupted,
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
/// 超时唤醒与正常唤醒的区分通过每-PCB 的 `Process.wq_timeout_marker`
/// 标记完成（M4-1b：取代了原先在定时器 IRQ 中分配堆节点的 `timed_out`
/// 集合）。标记在 `timeout_wake` 的 Blocked->Ready 过程中、持有 proc 锁时
/// 写入，由等待者自身的 epilogue 经 `process::consume_wq_timeout` 消费。
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
    // M4-1b: the former `timed_out: Mutex<BTreeMap<ProcessId, u64>>` was removed —
    // its `insert` allocated a node in TIMER-IRQ context (`timeout_wake`, the
    // R151-5 deadlock class). The timeout marker now lives per-PCB in
    // `Process.wq_timeout_marker`, set under the proc lock at the Blocked->Ready
    // transition and consumed by the waiter's epilogue via
    // `process::consume_wq_timeout`. The marker dies with the PCB, so no per-queue
    // map and no exit-time prune are needed.
    /// Monotonic generation counter, incremented on each wait_with_timeout call.
    wait_generation: AtomicU64,
}

impl WaitQueue {
    /// 创建新的等待队列
    pub fn new() -> Self {
        WaitQueue {
            waiters: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
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
                // M4-1b: entry-clear (born-clean). The prior wait's epilogue swap
                // should already have zeroed this; the debug_assert is the tripwire
                // and the store is the belt so a future exit path that forgets to
                // consume can never leak a stale incomparable generation (the wq
                // marker is one field shared across ALL WaitQueues, each with its own
                // gen counter) into THIS wait. Must precede Blocked (the IRQ
                // timeout-set only fires on a Blocked, still-queued entry); the whole
                // enqueue+block runs under IRQs-off, so no marker can be set between
                // the enqueue above and this clear.
                debug_assert!(
                    proc.wq_timeout_marker.load(Ordering::Relaxed) == 0,
                    "M4-1b: wq_timeout_marker not born-clean at wait entry"
                );
                proc.wq_timeout_marker.store(0, Ordering::Relaxed);
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

        // R171-F3 FIX: if a pending kill woke us, interrupt the wait (EINTR)
        // instead of reporting a spurious Woken/TimedOut. A kill flips
        // Blocked->Ready WITHOUT dequeuing us from this WaitQueue, so removing
        // our own membership here is load-bearing (no stale waiter lingers).
        if process::wait_should_abort(pid) {
            interrupts::without_interrupts(|| {
                self.waiters.lock().retain(|&(p, _)| p != pid);
            });
            // R171-F3: consume any timeout marker this wait may have stranded (a
            // timer that fired just before/at the cancel above) so an exact
            // (pid, generation) match can never surface it as a later spurious
            // TimedOut. consume_timeout_flag is exact-gen, so it only clears OURS.
            self.consume_timeout_flag(pid, my_gen);
            return WaitOutcome::Interrupted;
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
            // R171-G5-1 FIX: try_get_process() so the PROCESS_TABLE lookup itself
            // also never blocks on the table in this IRQ-reachable scan.
            match process::try_get_process(pid) {
                // Contended table: keep membership and retry on the next tick
                // (same defer-not-drop contract as the proc.try_lock() arm below).
                None => false,
                // R155-12 FIX: Process no longer exists (killed). Drop membership;
                // do NOT insert a timeout flag (no one would consume it).
                Some(None) => {
                    waiters.remove(pos);
                    true
                }
                Some(Some(proc_arc)) => {
                    if let Some(mut proc) = proc_arc.try_lock() {
                        // R165-4 FIX: Record the timeout only when THIS call performs
                        // the Blocked->Ready transition. If the task was already Ready
                        // (a normal wake beat us), recording a timeout flag would be a
                        // stale entry.
                        let was_blocked = proc.state == ProcessState::Blocked;
                        if was_blocked {
                            // M4-1b: SET the per-PCB wq marker (Release) STRICTLY
                            // BEFORE state=Ready, both inside THIS held proc-lock
                            // critical section — the proc-lock release/acquire hand-off
                            // (NOT the Release on the atomic) is the marker-before-wake
                            // edge every `state` reader honors. Replaces the
                            // IRQ-allocating `self.timed_out.lock().insert` (R151-5
                            // heap-alloc-in-IRQ class) that previously ran AFTER
                            // drop(proc), which ALSO closes the old Ready-before-marker
                            // visibility gap. Tagged with the waiter's OWN generation
                            // (from the timer record); the epilogue consume requires an
                            // exact match.
                            proc.wq_timeout_marker.store(
                                process::pack_timeout_marker(generation),
                                Ordering::Release,
                            );
                            proc.state = ProcessState::Ready;
                        }
                        drop(proc);
                        waiters.remove(pos);
                        drop(waiters);
                        true
                    } else {
                        // Contended (e.g. a concurrent wake holds the process lock).
                        // Keep membership and retry on the next tick.
                        false
                    }
                }
            }
        })
    }

    // R165-4 FIX: Consume the timeout flag only on an EXACT generation match.
    // A stored generation strictly less than `expected_gen` is a stale leftover
    // from an earlier wait by this PID (its consumer raced a normal wake); drop
    // it without reporting a timeout. A stored generation greater than expected
    // is impossible (a single PID cannot have two concurrent waits). Tightening
    // R164-10's `>=` to `==` closes the spurious-ETIMEDOUT path.
    //
    // M4-1b: the marker now lives per-PCB in `Process.wq_timeout_marker`;
    // `process::consume_wq_timeout` does the swap-to-clear with the SAME exact-gen
    // semantics (stored != expected => false + cleared; == => true). It is
    // process-context-only (blocking PROCESS_TABLE); all callers below are wait
    // epilogues. The proc lock it takes is the synchronizing edge that pairs with
    // the IRQ-side store-under-proc-lock.
    fn consume_timeout_flag(&self, pid: ProcessId, expected_gen: u64) -> bool {
        process::consume_wq_timeout(pid, expected_gen)
    }

    /// R156-6 FIX: Remove stale entries for an exiting process.
    pub fn cleanup_for_pid(&self, pid: ProcessId) {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            waiters.retain(|&(p, _)| p != pid);
            // M4-1b: no `timed_out` map to prune — the per-PCB `wq_timeout_marker`
            // dies with the PCB. The `waiters` membership retain stays (a stale
            // deque entry for a dead PID is still reachable by wake_one/timeout_wake).
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

            // R171-F2 FIX: a pending kill must NOT enqueue / re-block — bail like
            // the closed case so the caller's loop observes the kill and returns
            // EINTR (e.g. a pipe read/write loop re-checks wait_should_abort at
            // its top; without this gate the task would re-block under the kill).
            if process::wait_should_abort(pid) {
                return false;
            }

            // R152-8 FIX: Check for duplicate enqueue before pushing.
            // Without this, spurious reschedule returns cause the same PID
            // to accumulate in the deque, consuming wake signals meant for
            // other waiters.
            let mut waiters = self.waiters.lock();
            if waiters.iter().any(|&(p, _)| p == pid) {
                // R171-F2 FIX: already enqueued (a spurious-reschedule re-entry).
                // RE-STAMP Blocked so the task genuinely blocks again instead of
                // spinning Ready forever (the unkillable busy-spin): the prior
                // code returned true WITHOUT re-Blocking, so finish_wait()'s
                // reschedule immediately re-ran the still-Ready task at 100% CPU.
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        proc.state = ProcessState::Blocked;
                    }
                }
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

/// M4-1c: rotating scan cursor for `drain_expired_timeouts`.
///
/// Round-robin starting offset so that under sustained `timeout_wake` contention
/// the same front-of-`TIMED_WAITERS` entries are not re-tried every tick while
/// later expired waiters starve. This preserves the fairness the old
/// remove-then-repush-to-tail had (Codex requirement-align A2), without the
/// IRQ-context `Vec::push`. Accessed ONLY under the `TIMED_WAITERS` lock (Phase 1),
/// so plain `Relaxed` is sound (the lock orders it). Kept bounded < 2*len by the
/// `% len` on load and the `start + examined` store (both < len each).
static WQ_TIMEOUT_SCAN_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// M4-1c: pure, testable core of the WaitQueue timeout drain (copy-don't-remove).
///
/// # Codex Review Fix (M4-1b) + M4-1c CLOSURE
///
/// Uses fixed-size stack arrays (`expired` / `woke`) instead of a per-tick Vec to
/// bound IRQ work; `MAX_TIMEOUTS_PER_TICK` caps timeouts per tick (excess is caught
/// the next tick). M4-1c closes the last IRQ heap residual: the former Phase-3
/// retry `waits.push(*w)` could grow-REALLOC `TIMED_WAITERS: Vec` under the global
/// heap lock in the timer IRQ (R151-5 alloc-in-IRQ). The drain now COPIES expired
/// entries (no removal) in Phase 1, wakes them in Phase 2, and removes ONLY the
/// completed ones by exact `(queue, pid, generation)` via `Vec::retain` in Phase 3.
/// The timer-IRQ path therefore performs NO `Vec::push` and NO dealloc —
/// `Vec::retain`/`Vec::remove` never shrink capacity (std guarantee) and
/// `TimedWaiter` is `Copy`. The only Vec growth is the process-context
/// `register_timed_wait` push.
///
/// `wake(tw) -> true` means the waiter completed (woken / stale / process-gone) and
/// must be removed; `false` means defer (proc-lock / PROCESS_TABLE contention) — the
/// entry is left in place and re-evaluated next tick (deadline still <= now).
///
/// # Lock order (LOAD-BEARING)
///
/// `TIMED_WAITERS` MUST be DROPPED across the `wake` call. The wake path nests
/// `WaitQueue.waiters -> TIMED_WAITERS` (`wake_all`/`wake_n`/`cancel_wait` hold
/// `self.waiters` across `cancel_timed_wait`, which takes `TIMED_WAITERS`); holding
/// `TIMED_WAITERS` across `wake` (which itself takes `WaitQueue.waiters` inside
/// `timeout_wake`) would invert that to ABBA on SMP. Phase 1 scopes the lock to the
/// copy block and releases BEFORE Phase 2; Phase 3 re-acquires ALONE and its
/// `retain` closure touches ONLY the Vec — never `WaitQueue.waiters` / `proc`.
fn drain_expired_timeouts(
    waits: &Mutex<Vec<TimedWaiter>>,
    cursor: &AtomicUsize,
    now_ticks: u64,
    mut wake: impl FnMut(&TimedWaiter) -> bool,
) {
    // Phase 1: COPY up to MAX expired entries (rotating start), no removal.
    let mut expired: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let count = {
        let waits = waits.lock();
        let len = waits.len();
        if len == 0 {
            return;
        }
        let start = cursor.load(Ordering::Relaxed) % len;
        let mut n = 0;
        let mut examined = 0;
        while examined < len && n < MAX_TIMEOUTS_PER_TICK {
            let waiter = waits[(start + examined) % len];
            examined += 1;
            if waiter.deadline_tick <= now_ticks {
                expired[n] = Some(waiter);
                n += 1;
            }
        }
        // Advance the cursor past the examined window so the next tick continues the
        // round-robin sweep (bounded latency for every waiter even under contention).
        cursor.store(start + examined, Ordering::Relaxed);
        n
    };

    // Phase 2: wake each expired waiter WITHOUT holding TIMED_WAITERS; record the
    // completed ones (woke_count <= count <= MAX, so the stack array never overflows).
    let mut woke: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let mut woke_count = 0;
    for waiter in expired.iter().take(count).flatten() {
        if wake(waiter) {
            woke[woke_count] = Some(*waiter);
            woke_count += 1;
        }
    }

    // Phase 3: remove the completed waiters by EXACT (queue, pid, generation). A
    // concurrent process-context `register_timed_wait` replaces (queue, pid) with a
    // NEW generation (replace-semantics), so matching the full triple never drops a
    // fresh re-registered wait. `Vec::retain` never reallocs/deallocs (capacity
    // untouched), so this stays alloc-free in IRQ.
    if woke_count > 0 {
        let done = &woke[..woke_count];
        let mut waits = waits.lock();
        waits.retain(|tw| {
            !done.iter().flatten().any(|d| {
                d.queue == tw.queue && d.pid == tw.pid && d.generation == tw.generation
            })
        });
    }
}

fn process_waitqueue_timeouts(now_ticks: u64) {
    drain_expired_timeouts(&TIMED_WAITERS, &WQ_TIMEOUT_SCAN_CURSOR, now_ticks, |waiter| {
        // SAFETY: timed WaitQueue addresses are 'static kernel high-half data
        // (register_timed_wait debug-asserts addr >= 0xFFFF_FFFF_8000_0000), so the
        // raw pointer is valid for the program lifetime. `<*const T>::as_ref()`
        // returns None ONLY for a NULL pointer (defensive; unreachable given the
        // invariant — NOT a dangling-pointer guard) — treat it as completed so the
        // stale entry is removed.
        unsafe {
            match (waiter.queue as *const WaitQueue).as_ref() {
                Some(queue) => queue.timeout_wake(waiter.pid, waiter.generation),
                None => true,
            }
        }
    });
}

/// M4-1c self-test: the WaitQueue timeout drain core (copy-don't-remove + rotating
/// cursor + exact-(queue,pid,generation) retain). Drives a LOCAL `Vec` + cursor with
/// a test-controlled fake `wake` — NEVER the global `TIMED_WAITERS` static. Catches
/// the mis-wires a green build/boot cannot: an IRQ `Vec` realloc, a dropped fresh
/// re-registered wait, a missed/over-cap timeout, and lost round-robin fairness.
pub fn run_wq_timeout_drain_self_test() {
    use core::cell::Cell;
    let q1: usize = 0xFFFF_FFFF_8000_1000;
    let q2: usize = 0xFFFF_FFFF_8000_2000;
    let mk = |queue: usize, pid: ProcessId, generation: u64, deadline_tick: u64| TimedWaiter {
        queue,
        pid,
        deadline_tick,
        generation,
    };

    // (1) NO-REALLOC AT IRQ HIGH-WATER: fill to MAX live entries, force every wake to
    // FAIL (full retry path), assert capacity unchanged. The ONLY assertion that
    // proves the former IRQ Vec::push realloc is gone.
    {
        let waits = Mutex::new(Vec::with_capacity(MAX_TIMEOUTS_PER_TICK));
        for i in 0..MAX_TIMEOUTS_PER_TICK {
            waits.lock().push(mk(q1, i, i as u64, 1));
        }
        let cap0 = waits.lock().capacity();
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |_| false); // all contended
        assert!(
            waits.lock().capacity() == cap0,
            "M4-1c: TIMED_WAITERS realloc'd in the IRQ drain path"
        );
        assert!(
            waits.lock().len() == MAX_TIMEOUTS_PER_TICK,
            "M4-1c: contended waiters must be retained (defer-not-drop)"
        );
    }

    // (2) RETRY-PRESERVES-MEMBERSHIP: a failed wake leaves the entry with its
    // ORIGINAL generation + deadline.
    {
        let waits = Mutex::new(Vec::new());
        waits.lock().push(mk(q1, 7, 5, 10));
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |_| false);
        let v = waits.lock();
        assert!(
            v.len() == 1 && v[0].generation == 5 && v[0].deadline_tick == 10,
            "M4-1c: contended retry must preserve the original entry"
        );
    }

    // (3) EXACT-GENERATION RETRY (headline): a concurrent re-register during the wake
    // replaces (queue, pid) with a NEW generation; Phase 3 must NOT drop it.
    {
        let waits = Mutex::new(Vec::new());
        waits.lock().push(mk(q1, 7, 5, 10));
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |w| {
            // Simulate register_timed_wait replace-semantics (retain-by-(queue,pid) +
            // push a new generation) racing between the Phase-1 copy and Phase-3 retain.
            let mut v = waits.lock();
            v.retain(|t| !(t.queue == w.queue && t.pid == w.pid));
            v.push(TimedWaiter {
                queue: w.queue,
                pid: w.pid,
                deadline_tick: 999,
                generation: 7,
            });
            true // the gen-5 wake completes
        });
        let v = waits.lock();
        assert!(
            v.iter().any(|t| t.queue == q1 && t.pid == 7 && t.generation == 7),
            "M4-1c: fresh re-registered (gen 7) wait must survive the drain"
        );
        assert!(
            !v.iter().any(|t| t.generation == 5),
            "M4-1c: the completed gen-5 entry must be removed"
        );
    }

    // (4) CAP HONORED + REMAINDER SURVIVES: MAX+3 expired, all wake succeed; one tick
    // removes exactly MAX, 3 remain (caught next tick).
    {
        let waits = Mutex::new(Vec::new());
        for i in 0..(MAX_TIMEOUTS_PER_TICK + 3) {
            waits.lock().push(mk(q1, i, i as u64, 1));
        }
        let cur = AtomicUsize::new(0);
        let woke = Cell::new(0usize);
        drain_expired_timeouts(&waits, &cur, 100, |_| {
            woke.set(woke.get() + 1);
            true
        });
        assert!(
            woke.get() == MAX_TIMEOUTS_PER_TICK,
            "M4-1c: must cap wakes per tick at MAX_TIMEOUTS_PER_TICK"
        );
        assert!(
            waits.lock().len() == 3,
            "M4-1c: the over-cap expired remainder must survive for the next tick"
        );
    }

    // (5) NON-EXPIRED UNTOUCHED: a future-deadline entry is neither woken nor removed.
    {
        let waits = Mutex::new(Vec::new());
        waits.lock().push(mk(q1, 1, 1, 1)); // expired
        waits.lock().push(mk(q2, 2, 2, 1_000)); // future
        let cur = AtomicUsize::new(0);
        let woke = Cell::new(0usize);
        drain_expired_timeouts(&waits, &cur, 100, |_| {
            woke.set(woke.get() + 1);
            true
        });
        let v = waits.lock();
        assert!(woke.get() == 1, "M4-1c: only the expired entry should wake");
        assert!(
            v.len() == 1 && v[0].pid == 2,
            "M4-1c: the future-deadline entry must remain"
        );
    }

    // (6) ROUND-ROBIN FAIRNESS: MAX+4 expired, all-contended; over ceil(n/MAX) ticks
    // the rotating cursor examines EVERY entry (no permanent front starvation).
    {
        let total = MAX_TIMEOUTS_PER_TICK + 4;
        let waits = Mutex::new(Vec::new());
        for i in 0..total {
            waits.lock().push(mk(q1, i, i as u64, 1));
        }
        let cur = AtomicUsize::new(0);
        let seen = Cell::new(0u64); // bitmask of examined pids (total < 64)
        for _ in 0..2 {
            drain_expired_timeouts(&waits, &cur, 100, |w| {
                seen.set(seen.get() | (1u64 << w.pid));
                false // all contended -> nothing removed, Vec stable across ticks
            });
        }
        let full = (1u64 << total) - 1;
        assert!(
            seen.get() == full,
            "M4-1c: the rotating cursor must examine every waiter within ceil(n/MAX) ticks"
        );
    }
}

/// 定时器回调：每个 tick 检查超时
fn waitqueue_timer_tick() {
    let now = kernel_core::get_ticks();
    process_waitqueue_timeouts(now);
}
