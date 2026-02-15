//! Futex (Fast Userspace Mutex) 实现
//!
//! 提供用户空间快速互斥锁的内核支持，包括：
//! - FUTEX_WAIT: 如果 *uaddr == val，阻塞当前进程；否则返回 EAGAIN
//! - FUTEX_WAIT_TIMEOUT: 同上，但支持超时（R39-6 FIX）
//! - FUTEX_WAKE: 唤醒最多 n 个在 uaddr 上等待的进程
//! - FUTEX_LOCK_PI: 互斥锁加锁（带优先级继承）- E.4 PI
//! - FUTEX_UNLOCK_PI: 互斥锁解锁（带优先级继承）- E.4 PI
//!
//! 使用全局 FutexTable，以 (pid, vaddr) 为键索引等待队列。
//! 进程退出时自动清理其所有 futex 等待队列。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use kernel_core::process::{self, FutexKey, Priority, ProcessId};
use kernel_core::request_resched_from_irq;
use spin::Mutex;

use crate::sync::{WaitOutcome, WaitQueue};

/// Futex 操作码
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
/// R39-6 FIX: 带超时的等待
pub const FUTEX_WAIT_TIMEOUT: i32 = 2;
/// E.4 PI: 互斥锁加锁（带优先级继承）
pub const FUTEX_LOCK_PI: i32 = 3;
/// E.4 PI: 互斥锁解锁（带优先级继承）
pub const FUTEX_UNLOCK_PI: i32 = 4;

/// Futex 错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexError {
    /// 值不匹配（FUTEX_WAIT 时 *uaddr != val）
    WouldBlock,
    /// 无效的操作码
    InvalidOperation,
    /// 内存访问错误
    Fault,
    /// 无当前进程
    NoProcess,
    /// R39-6 FIX: 等待超时
    TimedOut,
    /// E.4 PI: Robust futex - 锁持有者已退出
    OwnerDied,
}

/// 单个 futex 地址的等待状态
struct FutexBucket {
    /// 等待队列（Arc 包装，避免持有桶锁时阻塞导致死锁）
    queue: Arc<WaitQueue>,
    /// 活跃等待者计数（用于判断是否可以清理）
    waiter_count: usize,
    /// E.4 PI: 当前持有者（线程ID），FUTEX_LOCK_PI 使用
    owner: Option<ProcessId>,
    /// E.4 PI: 持有者已经死亡（robust futex 语义）
    owner_dead: bool,
    /// E.4 PI: PI 等待者列表 (pid -> priority)，用于找出最高优先级的等待者
    pi_waiters: BTreeMap<ProcessId, Priority>,
}

impl FutexBucket {
    fn new() -> Self {
        FutexBucket {
            queue: Arc::new(WaitQueue::new()),
            waiter_count: 0,
            owner: None,
            owner_dead: false,
            pi_waiters: BTreeMap::new(),
        }
    }
}

lazy_static::lazy_static! {
    /// 全局 Futex 表
    ///
    /// 以 (pid, vaddr) 为键，管理该地址上的等待队列。
    /// 空队列会在唤醒后被清理，避免内存泄漏。
    static ref FUTEX_TABLE: Mutex<BTreeMap<FutexKey, Arc<Mutex<FutexBucket>>>> =
        Mutex::new(BTreeMap::new());
}

/// 从用户空间读取 u32 值
///
/// 用于 futex_wait 在入队前二次检查值，防止 lost-wake 竞态
/// R24-5 fix: 验证跨页、使用 SMAP 保护和容错 usercopy
fn read_user_u32(uaddr: usize) -> Result<u32, FutexError> {
    use kernel_core::usercopy::copy_from_user_safe;
    use mm::page_table::PageTableManager;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    // 验证并读取跨页安全
    unsafe {
        mm::page_table::with_current_manager(
            VirtAddr::new(0),
            |manager: &mut PageTableManager| -> Result<u32, FutexError> {
                let end = uaddr
                    .checked_add(core::mem::size_of::<u32>())
                    .ok_or(FutexError::Fault)?;

                // 验证起止两页（处理跨页读取）
                for addr in [uaddr, end - 1] {
                    let page_addr = addr & !0xfff;
                    if let Some((_, flags)) =
                        manager.translate_with_flags(VirtAddr::new(page_addr as u64))
                    {
                        if !flags.contains(PageTableFlags::PRESENT)
                            || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                        {
                            return Err(FutexError::Fault);
                        }
                    } else {
                        return Err(FutexError::Fault);
                    }
                }

                // 使用 SMAP 安全的容错复制
                // P1-6 FIX: Removed redundant outer UserAccessGuard —
                // copy_from_user_safe creates its own guard internally.
                let mut buf = [0u8; 4];
                copy_from_user_safe(&mut buf, uaddr as *const u8).map_err(|_| FutexError::Fault)?;
                Ok(u32::from_ne_bytes(buf))
            },
        )
    }
}

/// FUTEX_WAIT / FUTEX_WAIT_TIMEOUT 操作
///
/// 如果 *uaddr == expected，则阻塞当前进程；否则返回 WouldBlock。
///
/// # Arguments
///
/// * `tgid` - 线程组 ID (R37-2 FIX: 使用 TGID 而非 PID)
/// * `uaddr` - 用户空间 futex 地址（已验证）
/// * `expected` - 期望的值
/// * `current_value` - 当前从用户空间读取的值（调用者负责验证和读取）
/// * `timeout_ns` - R39-6 FIX: 可选超时时间（纳秒），None 表示无限等待
///
/// # Returns
///
/// 成功阻塞并被唤醒后返回 Ok(0)，值不匹配返回 WouldBlock，超时返回 TimedOut
pub fn futex_wait(
    tgid: ProcessId,
    uaddr: usize,
    expected: u32,
    current_value: u32,
    timeout_ns: Option<u64>,
) -> Result<usize, FutexError> {
    // 值不匹配，立即返回
    if current_value != expected {
        return Err(FutexError::WouldBlock);
    }

    // R37-2 FIX: Futex key is scoped by TGID so CLONE_THREAD siblings can wake each other
    let key = (tgid, uaddr);

    // 获取或创建此地址的等待桶
    let bucket = get_or_create_bucket(key);

    // 【关键修复】增加等待者计数并获取队列 Arc，然后立即释放桶锁
    // 避免持有桶锁时调用 WaitQueue::wait() 导致死锁
    let queue = {
        let mut b = bucket.lock();
        b.waiter_count += 1;
        b.queue.clone()
    }; // 桶锁在此释放

    // 【关键修复】在入队前二次读取 futex 值，防止 lost-wake 竞态
    // 如果值已变化，说明唤醒者已经完成操作，我们不应该阻塞
    match read_user_u32(uaddr) {
        Ok(cur) if cur == expected => {
            // 值仍然匹配，继续阻塞
        }
        Ok(_) => {
            // 值已变化，回滚等待者计数并返回
            let mut b = bucket.lock();
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(FutexError::WouldBlock);
        }
        Err(e) => {
            // 内存访问错误，回滚并返回
            let mut b = bucket.lock();
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            cleanup_empty_bucket(key, &bucket);
            return Err(e);
        }
    }

    // R39-6 FIX: 阻塞等待（支持可选超时）
    // WaitQueue::wait_with_timeout 会设置进程状态并触发调度
    // 此时不持有桶锁，唤醒者可以安全地获取锁并调用 wake_n
    let outcome = queue.wait_with_timeout(timeout_ns);

    // 被唤醒后减少等待者计数
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
    }

    // 尝试清理空桶
    cleanup_empty_bucket(key, &bucket);

    // R39-6 FIX: 根据等待结果返回
    match outcome {
        WaitOutcome::Woken => Ok(0),
        WaitOutcome::TimedOut => Err(FutexError::TimedOut),
        WaitOutcome::Closed | WaitOutcome::NoProcess => Err(FutexError::NoProcess),
    }
}

/// FUTEX_WAKE 操作
///
/// 唤醒最多 n 个在 uaddr 上等待的进程。
///
/// # Arguments
///
/// * `tgid` - 线程组 ID (R37-2 FIX: 使用 TGID 而非 PID)
/// * `uaddr` - 用户空间 futex 地址
/// * `n` - 最多唤醒的进程数量
///
/// # Returns
///
/// 实际唤醒的进程数量
pub fn futex_wake(tgid: ProcessId, uaddr: usize, n: usize) -> usize {
    // R37-2 FIX: Futex key is scoped by TGID
    let key = (tgid, uaddr);

    // 查找此地址的等待桶
    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    };

    let woken = if let Some(ref bucket) = bucket {
        // 获取队列 Arc 后释放桶锁，避免在唤醒时持有锁
        let queue = {
            let b = bucket.lock();
            b.queue.clone()
        };
        queue.wake_n(n)
    } else {
        0
    };

    // 尝试清理空桶
    if let Some(ref bucket) = bucket {
        cleanup_empty_bucket(key, bucket);
    }

    woken
}

/// E.4 PI: FUTEX_LOCK_PI 操作（带优先级继承的互斥锁加锁）
///
/// # 语义
///
/// - 如果未被持有，当前线程成为 owner，返回 Ok(0)
/// - 如果被其他线程持有，当前线程加入等待队列，并将自身优先级捐赠给 owner（链式传播）
/// - 如果 owner 已经死亡（robust futex），新的持有者获得锁并返回 OwnerDied
/// - 如果自己已经持有该锁，返回 InvalidOperation（防止死锁）
///
/// # Arguments
///
/// * `tgid` - 线程组 ID
/// * `uaddr` - 用户空间 futex 地址
/// * `_current_value` - 当前从用户空间读取的值（用于验证）
///
/// # Returns
///
/// 成功获取锁返回 Ok(0)，锁持有者死亡返回 Err(OwnerDied)
pub fn futex_lock_pi(
    tgid: ProcessId,
    uaddr: usize,
    _current_value: u32,
) -> Result<usize, FutexError> {
    let pid = process::current_pid().ok_or(FutexError::NoProcess)?;
    let key: FutexKey = (tgid, uaddr);

    // 获取当前等待者的优先级
    let waiter_priority = {
        let proc_arc = process::get_process(pid).ok_or(FutexError::NoProcess)?;
        let proc = proc_arc.lock();
        proc.dynamic_priority
    };

    let bucket = get_or_create_bucket(key);

    // 快路径：尝试直接获取所有权
    {
        let mut b = bucket.lock();

        // 清理已死亡的 owner（robust futex）
        if let Some(owner) = b.owner {
            if process::get_process(owner).is_none() {
                b.owner = None;
                b.owner_dead = true;
            }
        }

        if b.owner.is_none() {
            // 锁空闲，直接获取
            let owner_died = b.owner_dead;
            b.owner = Some(pid);
            b.owner_dead = false;
            b.pi_waiters.remove(&pid);
            return if owner_died {
                Err(FutexError::OwnerDied)
            } else {
                Ok(0)
            };
        }

        if b.owner == Some(pid) {
            // 自己已经持有，防止死锁
            return Err(FutexError::InvalidOperation);
        }

        // 需要等待：增加计数但暂不记录 pi_waiters（避免 race）
        b.waiter_count += 1;
    }

    // 记录阻塞的 futex key（用于链式 PI）
    if let Some(proc) = process::get_process(pid) {
        proc.lock().set_waiting_on_futex(Some(key));
    }

    // CRITICAL FIX: 先加入 WaitQueue，再记录 pi_waiters
    // 这避免了 unlock_pi 在 waiter 入队前就尝试 wake_specific 的 race
    let queue = { bucket.lock().queue.clone() };
    if !queue.prepare_to_wait() {
        // 入队失败（队列已关闭或无当前进程），回滚
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
        if let Some(proc) = process::get_process(pid) {
            proc.lock().set_waiting_on_futex(None);
        }
        return Err(FutexError::NoProcess);
    }

    // 现在 waiter 已在队列中，安全地记录 pi_waiters
    {
        let mut b = bucket.lock();
        b.pi_waiters.insert(pid, waiter_priority);
    }

    // R73-1 FIX: 窗口修复——在 pi_waiters.insert 后再次检查 owner 状态
    // 如果在 prepare_to_wait() 和 pi_waiters.insert() 之间 owner 已经 unlock,
    // 此时 owner 会是 None，我们需要直接获取锁而不是阻塞
    {
        let mut b = bucket.lock();
        if b.owner.is_none() {
            let owner_died = b.owner_dead;
            b.owner = Some(pid);
            b.owner_dead = false;
            b.pi_waiters.remove(&pid);
            if b.waiter_count > 0 {
                b.waiter_count -= 1;
            }
            drop(b);
            // 取消排队的等待，防止永久阻塞
            queue.cancel_wait();
            if let Some(proc) = process::get_process(pid) {
                proc.lock().set_waiting_on_futex(None);
            }
            recompute_pi_state(key, &bucket);
            cleanup_empty_bucket(key, &bucket);
            return if owner_died {
                Err(FutexError::OwnerDied)
            } else {
                Ok(0)
            };
        }
    }

    // 触发 PI 传播到当前 owner
    recompute_pi_state(key, &bucket);

    // 完成等待（实际阻塞）
    queue.finish_wait();

    // 检查是否因超时或关闭被唤醒（此处没有超时，所以只处理正常唤醒和关闭）
    // Note: finish_wait 不返回 outcome，需要通过其他方式判断
    // 我们使用 Woken 作为默认，因为 PI futex 不支持超时（目前）

    // 出队并更新 PI 状态
    let mut owner_died = false;
    {
        let mut b = bucket.lock();
        if b.waiter_count > 0 {
            b.waiter_count -= 1;
        }
        b.pi_waiters.remove(&pid);
        owner_died = b.owner_dead;

        // CRITICAL FIX: 检查是否已被 unlock_pi 设置为 owner
        // 如果已经是 owner，就不需要再竞争
        if b.owner == Some(pid) {
            // 已经被 unlock_pi 转移了所有权
            drop(b);
            if let Some(proc) = process::get_process(pid) {
                proc.lock().set_waiting_on_futex(None);
            }
            recompute_pi_state(key, &bucket);
            cleanup_empty_bucket(key, &bucket);
            return if owner_died {
                Err(FutexError::OwnerDied)
            } else {
                Ok(0)
            };
        }

        // 如果 owner 已经被清空（owner 死亡且未被 unlock_pi 处理），尝试接管锁
        if b.owner.is_none() {
            b.owner = Some(pid);
            b.owner_dead = false;
        }
    }

    // 清除等待标记
    if let Some(proc) = process::get_process(pid) {
        proc.lock().set_waiting_on_futex(None);
    }

    // 等待者离开后重新计算 PI
    recompute_pi_state(key, &bucket);
    cleanup_empty_bucket(key, &bucket);

    if owner_died {
        Err(FutexError::OwnerDied)
    } else {
        Ok(0)
    }
}

/// E.4 PI: FUTEX_UNLOCK_PI 操作（带优先级继承的互斥锁解锁）
///
/// # 语义
///
/// - 仅持有者可以解锁
/// - 将锁直接转移给最高优先级的等待者
/// - 根据剩余等待者更新 PI 状态
///
/// # Arguments
///
/// * `tgid` - 线程组 ID
/// * `uaddr` - 用户空间 futex 地址
///
/// # Returns
///
/// 成功解锁返回 Ok(0)，不是持有者返回 Err(InvalidOperation)
pub fn futex_unlock_pi(tgid: ProcessId, uaddr: usize) -> Result<usize, FutexError> {
    let pid = process::current_pid().ok_or(FutexError::NoProcess)?;
    let key: FutexKey = (tgid, uaddr);

    let bucket = {
        let table = FUTEX_TABLE.lock();
        table.get(&key).cloned()
    }
    .ok_or(FutexError::InvalidOperation)?;

    let (queue, next_owner, remaining_boost) = {
        let mut b = bucket.lock();
        if b.owner != Some(pid) {
            return Err(FutexError::InvalidOperation);
        }

        // 移除已退出的等待者，避免唤醒僵尸
        b.pi_waiters
            .retain(|waiter, _| process::get_process(*waiter).is_some());

        let queue = b.queue.clone();
        let next = select_highest_waiter(&b.pi_waiters);

        if let Some((next_pid, _prio)) = next {
            // 直接移除并转移所有权
            b.pi_waiters.remove(&next_pid);
            b.owner = Some(next_pid);
            b.owner_dead = false;
        } else {
            b.owner = None;
            b.owner_dead = false;
        }

        let donation = highest_waiter_priority(&b);
        (queue, next.map(|(p, _)| p), donation)
    };

    // 当前持有者清除自己的 PI 提升
    if let Some(proc) = process::get_process(pid) {
        let changed = proc.lock().clear_pi_boost(&key);
        if changed {
            request_resched_from_irq();
        }
    }

    if let Some(new_owner) = next_owner {
        // 传递剩余等待者的捐赠到新的 owner，并链式传播
        {
            let mut visited = BTreeSet::new();
            visited.insert(key);
            apply_pi_and_propagate(key, new_owner, remaining_boost, &mut visited);
        }

        // 清理等待标记并唤醒新的 owner
        if let Some(proc) = process::get_process(new_owner) {
            proc.lock().set_waiting_on_futex(None);
        }
        queue.wake_specific(new_owner);
    } else {
        // 无等待者，尝试清理桶
        cleanup_empty_bucket(key, &bucket);
    }

    Ok(0)
}

/// 清理进程的所有 futex 等待队列
///
/// 进程/线程退出时调用，唤醒所有等待者并移除该进程的所有 futex 条目。
///
/// R37-2 FIX: 如果退出的线程还有 CLONE_THREAD 兄弟线程存活，则保留 TGID 的
/// futex 桶，避免清除正在使用的 futex。这保持了 pthread 语义。
///
/// E.4 PI: 如果退出的线程持有 PI futex，标记为 owner_dead 并选择
/// 最高优先级等待者作为继任者（robust futex 语义）。只唤醒继任者以保持互斥。
///
/// R37-2 FIX (Codex review): Accept TGID directly from caller to avoid deadlock.
/// The caller (free_process_resources) already holds the process lock, so we must
/// not try to lock the process again.
///
/// # R72-1 FIX: Waiter Cleanup
///
/// Previously, this function only handled the exiting thread when it was the futex
/// owner. If the thread was a waiter (in pi_waiters and/or WaitQueue), its entry
/// was left behind. This is dangerous because:
///
/// 1. The PID may be reused by a new process
/// 2. When the owner unlocks, `select_highest_waiter()` may return the stale PID
/// 3. `wake_specific()` would try to wake the new (unrelated) process
/// 4. The real waiters would never be woken, causing deadlock
///
/// Now we clean up waiter entries first, before handling owner cleanup.
pub fn cleanup_process_futexes(pid: ProcessId, tgid: ProcessId) {
    // R37-2 FIX (Codex review): Use TGID provided by caller, not from process lock.
    // Check thread group size without locking the current process.
    let group_size = process::thread_group_size(tgid);

    // R72-1 FIX: Clean up this PID from ALL waiter lists (even if not owner).
    // This prevents stale PID references from poisoning futex state after PID reuse.
    {
        let table = FUTEX_TABLE.lock();
        let buckets: alloc::vec::Vec<(FutexKey, Arc<Mutex<FutexBucket>>)> = table
            .iter()
            .filter(|(k, _)| k.0 == tgid)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        drop(table);

        for (key, bucket) in buckets {
            let mut needs_pi_recompute = false;
            let (queue, removed_from_pi) = {
                let mut b = bucket.lock();

                // Skip if this PID is the owner (handled in next phase)
                if b.owner == Some(pid) {
                    continue;
                }

                // Remove from pi_waiters if present
                let removed_from_pi = b.pi_waiters.remove(&pid).is_some();

                if removed_from_pi {
                    needs_pi_recompute = true;
                }

                (b.queue.clone(), removed_from_pi)
            };

            // Remove from WaitQueue (this handles non-PI waiters too)
            // wake_specific returns true if the PID was found and removed
            let was_in_queue = queue.wake_specific(pid);

            // R72-1 FIX (Codex review): Only decrement waiter_count once.
            // A process waiting on a PI futex is counted once in waiter_count,
            // even though it appears in both pi_waiters and WaitQueue.
            // Decrement only if we found it in either location.
            if removed_from_pi || was_in_queue {
                let mut b = bucket.lock();
                if b.waiter_count > 0 {
                    b.waiter_count -= 1;
                }
            }

            // Recompute PI state if we removed a PI waiter
            // This ensures the owner's priority boost is correctly updated
            if needs_pi_recompute {
                recompute_pi_state(key, &bucket);
            }

            // Try to clean up empty bucket
            cleanup_empty_bucket(key, &bucket);
        }
    }

    // E.4 PI: 先标记由退出线程持有的 futex（robust 语义）
    {
        let table = FUTEX_TABLE.lock();
        let owned: alloc::vec::Vec<(FutexKey, Arc<Mutex<FutexBucket>>)> = table
            .iter()
            .filter(|(k, _)| k.0 == tgid)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        drop(table);

        for (key, bucket) in owned {
            let (queue, next_owner) = {
                let mut b = bucket.lock();
                if b.owner != Some(pid) {
                    continue;
                }

                // 标记 owner 死亡
                b.owner_dead = true;

                // CRITICAL FIX: 选择最高优先级等待者作为继任者，而非唤醒全部
                // 这保持了互斥语义
                let queue = b.queue.clone();
                let next = select_highest_waiter(&b.pi_waiters);

                if let Some((next_pid, _prio)) = next {
                    // 转移所有权给继任者
                    b.pi_waiters.remove(&next_pid);
                    b.owner = Some(next_pid);
                    // 保持 owner_dead = true 以便继任者知道前任已死亡
                } else {
                    // 无等待者，清除所有权
                    b.owner = None;
                }

                (queue, next.map(|(p, _)| p))
            };

            if let Some(new_owner) = next_owner {
                // 清除继任者的等待标记并唤醒
                if let Some(proc) = process::get_process(new_owner) {
                    proc.lock().set_waiting_on_futex(None);
                }
                queue.wake_specific(new_owner);
            }

            // 重新计算 PI（owner 已变更）
            recompute_pi_state(key, &bucket);
        }
    }

    // 如果线程组还有其他活跃线程，只做 owner_dead 标记，不移除桶
    if group_size > 1 {
        return;
    }

    let mut table = FUTEX_TABLE.lock();

    // 收集要移除的键 (使用 TGID 而非 PID)
    let keys_to_remove: alloc::vec::Vec<FutexKey> =
        table.keys().filter(|(p, _)| *p == tgid).cloned().collect();

    // 唤醒所有等待者并移除条目
    for key in keys_to_remove {
        if let Some(bucket) = table.remove(&key) {
            let queue = {
                let b = bucket.lock();
                b.queue.clone()
            };
            queue.wake_all();
        }
    }
}

/// 获取或创建指定键的等待桶
fn get_or_create_bucket(key: FutexKey) -> Arc<Mutex<FutexBucket>> {
    let mut table = FUTEX_TABLE.lock();
    table
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(FutexBucket::new())))
        .clone()
}

/// 清理空的等待桶（无等待者时移除）
///
/// E.4 PI: 额外检查 owner 和 pi_waiters 是否为空
fn cleanup_empty_bucket(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) {
    let b = bucket.lock();
    // E.4 PI: 只有当 owner、等待者、队列都为空时才清理
    if b.waiter_count == 0 && b.queue.is_empty() && b.owner.is_none() && b.pi_waiters.is_empty() {
        drop(b);

        // 重新获取 table 锁进行移除
        let mut table = FUTEX_TABLE.lock();
        if let Some(existing) = table.get(&key) {
            // 确保是同一个桶（防止竞态条件下移除新创建的桶）
            if Arc::ptr_eq(existing, bucket) {
                // 再次检查是否为空
                let b = existing.lock();
                if b.waiter_count == 0
                    && b.queue.is_empty()
                    && b.owner.is_none()
                    && b.pi_waiters.is_empty()
                {
                    drop(b);
                    table.remove(&key);
                }
            }
        }
    }
}

/// 获取活跃的 futex 地址数量（调试用）
pub fn active_futex_count() -> usize {
    FUTEX_TABLE.lock().len()
}

/// FutexTable 类型别名（向后兼容）
pub type FutexTable = ();

// ============================================================================
// E.4 PI: 内部辅助函数（优先级继承支持）
// ============================================================================

/// E.4 PI: 选择最高优先级（数值最小）的等待者
fn select_highest_waiter(waiters: &BTreeMap<ProcessId, Priority>) -> Option<(ProcessId, Priority)> {
    waiters
        .iter()
        .min_by_key(|(_, prio)| *prio)
        .map(|(pid, prio)| (*pid, *prio))
}

/// E.4 PI: 获取当前最高优先级等待者的优先级（仅优先级值）
fn highest_waiter_priority(bucket: &FutexBucket) -> Option<Priority> {
    bucket.pi_waiters.values().min().copied()
}

/// E.4 PI: Maximum PI chain propagation depth
///
/// Limits the depth of PI chain traversal to prevent stack overflow from
/// maliciously constructed long wait chains. 64 is a reasonable limit -
/// real-world systems rarely have chains deeper than 5-10 levels.
const MAX_PI_CHAIN_DEPTH: usize = 64;

/// E.4 PI: 将优先级捐赠应用于 owner 并沿等待链路传播（A -> B -> C）
///
/// 支持链式优先级继承：如果 owner 也在等待其他 futex，则继续向上传播
///
/// # R72-2 FIX: Iterative Implementation
///
/// This function now uses an iterative approach with a work stack instead of
/// recursive calls to prevent stack overflow when traversing long PI chains.
/// A malicious user could construct a chain of N processes where each waits
/// on the next's futex (A → B → C → ... → N). With recursive propagation,
/// unlock_pi() would cause O(N) stack frames, overflowing the 16KB kernel
/// stack for N > ~100. The iterative version uses O(1) stack space.
///
/// Additionally, a depth limit of MAX_PI_CHAIN_DEPTH prevents unbounded
/// traversal even with a Vec work stack, limiting worst-case to O(MAX_PI_CHAIN_DEPTH).
fn apply_pi_and_propagate(
    key: FutexKey,
    owner: ProcessId,
    donated: Option<Priority>,
    visited: &mut BTreeSet<FutexKey>,
) {
    // R72-2 FIX: Use work stack instead of recursion
    // Stack entry: (futex_key, owner_pid, donated_priority)
    let mut work_stack: alloc::vec::Vec<(FutexKey, ProcessId, Option<Priority>)> =
        alloc::vec::Vec::with_capacity(8);
    work_stack.push((key, owner, donated));

    let mut depth = 0;

    while let Some((cur_key, cur_owner, donation)) = work_stack.pop() {
        // R72-2 FIX: Depth limit to prevent unbounded traversal
        depth += 1;
        if depth > MAX_PI_CHAIN_DEPTH {
            // Log warning but don't panic - gracefully stop propagation
            kprintln!(
                "[FUTEX] PI chain depth exceeded {} at key {:?}, truncating",
                MAX_PI_CHAIN_DEPTH,
                cur_key
            );
            break;
        }

        if let Some(proc) = process::get_process(cur_owner) {
            let (changed, next_wait, effective_prio) = {
                let mut p = proc.lock();
                let changed = match donation {
                    Some(prio) => p.apply_pi_boost(cur_key, prio),
                    None => p.clear_pi_boost(&cur_key),
                };
                let next = p.get_waiting_on_futex();
                let eff = p.dynamic_priority;
                (changed, next, eff)
            };

            if changed {
                // 通知调度器重新评估优先级
                request_resched_from_irq();
            }

            // 链式传播（如果 owner 也在等待其他 futex）
            if let Some(next_key) = next_wait {
                if visited.insert(next_key) {
                    // Look up next owner and push to work stack
                    let next_owner = {
                        let table = FUTEX_TABLE.lock();
                        table.get(&next_key).and_then(|b| b.lock().owner)
                    };

                    if let Some(next_owner_pid) = next_owner {
                        work_stack.push((next_key, next_owner_pid, Some(effective_prio)));
                    }
                }
            }
        }
    }
}

/// E.4 PI: 根据当前等待者重新计算 owner 的 PI，并处理链式传播/清除
fn recompute_pi_state(key: FutexKey, bucket: &Arc<Mutex<FutexBucket>>) {
    let (owner, donation) = {
        let mut b = bucket.lock();
        // 清理已退出的 owner
        if let Some(owner_pid) = b.owner {
            if process::get_process(owner_pid).is_none() {
                b.owner = None;
                b.owner_dead = true;
            }
        }
        (b.owner, highest_waiter_priority(&b))
    };

    if let Some(owner_pid) = owner {
        let mut visited = BTreeSet::new();
        visited.insert(key);
        apply_pi_and_propagate(key, owner_pid, donation, &mut visited);
    }
}
