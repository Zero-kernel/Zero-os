//! 增强型调度器
//!
//! 实现多级反馈队列调度和时钟中断集成
//!
//! 使用 Arc<Mutex<Process>> 共享引用与 PROCESS_TABLE 同步状态
//!
//! 就绪队列使用优先级分桶：BTreeMap<Priority, BTreeMap<Pid, PCB>>
//! - 外层按优先级排序（数值越小优先级越高）
//! - 内层按 PID 排序实现同优先级的 FIFO
//!
//! # R67-4 FIX: Per-CPU Scheduler State
//!
//! CURRENT_PROCESS and need_resched are now per-CPU to prevent cross-CPU races:
//! - Each CPU tracks its own current process via CpuLocal
//! - Reschedule flag uses cpu_local::current_cpu().need_resched
//! - Ready queue remains global (per-CPU run queues are future work)

use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::Ordering;
use cpu_local::{current_cpu, CpuLocal};
use kernel_core::process::{self, Priority, Process, ProcessId, ProcessState};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::interrupts;

// 导入arch模块的上下文切换功能
use arch::Context as ArchContext;
use arch::{assert_kernel_context, enter_usermode, save_context, switch_context};
use arch::{default_kernel_stack_top, set_kernel_stack};

/// 调度器调试输出开关
///
/// 设置为 true 启用详细调度日志，设置为 false 禁用
/// 在生产环境或使用 shell 时应设置为 false
const SCHED_DEBUG: bool = false;

/// 调度器调试输出宏
macro_rules! sched_debug {
    ($($arg:tt)*) => {
        if SCHED_DEBUG {
            println!($($arg)*);
        }
    };
}

// 类型别名以保持兼容性
pub type Pid = ProcessId;
pub type ProcessControlBlock = Arc<Mutex<Process>>;

/// 优先级分桶的就绪队列类型
///
/// 结构: Priority -> (Pid -> ProcessControlBlock)
/// - 按优先级从低到高排序（优先级数值越小越优先）
/// - 同优先级内按 PID 先入先出
type ReadyQueues = BTreeMap<Priority, BTreeMap<Pid, ProcessControlBlock>>;

/// 用于首次调度的哑上下文（内核启动上下文的保存位置，无需恢复）
static BOOTSTRAP_CONTEXT: Mutex<ArchContext> = Mutex::new(ArchContext::new());

/// R67-4 FIX: Per-CPU current process tracking.
///
/// Each CPU tracks its own current process. This prevents races where
/// multiple CPUs could believe they own the same process.
static CURRENT_PROCESS: CpuLocal<Mutex<Option<Pid>>> = CpuLocal::new(|| Mutex::new(None));

/// 全局就绪队列 - 按优先级分桶维护就绪进程
///
/// R67-4 NOTE: Ready queue remains global for now. Per-CPU run queues
/// with load balancing is future work for Phase F.
lazy_static! {
    pub static ref READY_QUEUE: Mutex<ReadyQueues> = Mutex::new(BTreeMap::new());
    pub static ref SCHEDULER_STATS: Mutex<SchedulerStats> = Mutex::new(SchedulerStats::new());
}

/// 调度器统计信息
pub struct SchedulerStats {
    pub total_switches: u64,
    pub total_ticks: u64,
    pub processes_created: u64,
    pub processes_terminated: u64,
}

impl SchedulerStats {
    pub fn new() -> Self {
        SchedulerStats {
            total_switches: 0,
            total_ticks: 0,
            processes_created: 0,
            processes_terminated: 0,
        }
    }

    pub fn print(&self) {
        println!("=== Scheduler Statistics ===");
        println!("Context switches: {}", self.total_switches);
        println!("Total ticks:      {}", self.total_ticks);
        println!("Processes created: {}", self.processes_created);
        println!("Processes terminated: {}", self.processes_terminated);
    }
}

/// 调度器
pub struct Scheduler;

impl Scheduler {
    // ========================================================================
    // 内部辅助函数
    // ========================================================================

    /// 在优先级分桶中查找指定 PID 的进程
    fn find_pcb(queue: &ReadyQueues, pid: Pid) -> Option<ProcessControlBlock> {
        for bucket in queue.values() {
            if let Some(pcb) = bucket.get(&pid) {
                return Some(pcb.clone());
            }
        }
        None
    }

    /// 选择优先级最高的就绪进程（内部实现，需要队列锁）
    ///
    /// # Arguments
    /// * `queue` - 就绪队列引用
    /// * `skip_pid` - 要跳过的进程 PID（用于 yield 时避免选中自己）
    fn select_next_locked(queue: &ReadyQueues, skip_pid: Option<Pid>) -> Option<Pid> {
        // Debug: print all processes in queue
        for (priority, bucket) in queue.iter() {
            for (&pid, pcb) in bucket.iter() {
                let state = pcb.lock().state;
                sched_debug!(
                    "[SCHED] queue: pid={}, priority={}, state={:?}",
                    pid,
                    priority,
                    state
                );
            }
        }

        // BTreeMap 按 key 升序排列，所以优先级数值最小（最高优先级）的在前面
        for (_priority, bucket) in queue.iter() {
            for (&pid, pcb) in bucket.iter() {
                // 跳过指定的进程（用于 yield 场景）
                if Some(pid) == skip_pid {
                    continue;
                }
                if pcb.lock().state == ProcessState::Ready {
                    sched_debug!("[SCHED] selected pid={}", pid);
                    return Some(pid);
                }
            }
        }

        // 如果没有其他就绪进程，回退到被跳过的进程（如果它是就绪的）
        if let Some(skip) = skip_pid {
            if let Some(pcb) = Self::find_pcb(queue, skip) {
                if pcb.lock().state == ProcessState::Ready {
                    sched_debug!("[SCHED] fallback to skipped pid={}", skip);
                    return Some(skip);
                }
            }
        }

        sched_debug!("[SCHED] no ready process found");
        None
    }

    // ========================================================================
    // 公开 API
    // ========================================================================

    /// 添加进程到就绪队列
    ///
    /// 将进程插入到其动态优先级对应的桶中
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn add_process(pcb: ProcessControlBlock) {
        interrupts::without_interrupts(|| {
            let (pid, priority) = {
                let mut proc = pcb.lock();
                proc.state = ProcessState::Ready;
                (proc.pid, proc.dynamic_priority)
            };
            sched_debug!("[SCHED] add_process: pid={}, priority={}", pid, priority);
            {
                let mut queue = READY_QUEUE.lock();
                // 先从所有桶中移除（防止重复）
                for bucket in queue.values_mut() {
                    bucket.remove(&pid);
                }
                // 插入到正确的优先级桶
                queue.entry(priority).or_default().insert(pid, pcb);
            }

            let mut stats = SCHEDULER_STATS.lock();
            stats.processes_created += 1;
        });
    }

    /// 移除进程
    ///
    /// 从所有优先级桶中移除指定 PID
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid) {
        interrupts::without_interrupts(|| {
            {
                let mut queue = READY_QUEUE.lock();
                for bucket in queue.values_mut() {
                    bucket.remove(&pid);
                }
                // 清理空桶
                queue.retain(|_, bucket| !bucket.is_empty());
            }

            let mut stats = SCHEDULER_STATS.lock();
            stats.processes_terminated += 1;
        });
    }

    /// 恢复被暂停的进程（用于 SIGCONT）
    ///
    /// 如果进程处于 Stopped 状态，将其设置为 Ready 并添加到就绪队列。
    ///
    /// # Arguments
    ///
    /// * `pid` - 要恢复的进程 ID
    ///
    /// # Returns
    ///
    /// 如果进程被成功恢复则返回 true
    pub fn resume_stopped(pid: Pid) -> bool {
        use process::get_process;

        interrupts::without_interrupts(|| {
            if let Some(pcb) = get_process(pid) {
                let (should_add, priority) = {
                    let mut proc = pcb.lock();
                    if proc.state == ProcessState::Stopped {
                        proc.state = ProcessState::Ready;
                        (true, proc.dynamic_priority)
                    } else {
                        (false, 0)
                    }
                };

                if should_add {
                    // 先从队列中移除（防止重复）
                    {
                        let mut queue = READY_QUEUE.lock();
                        for bucket in queue.values_mut() {
                            bucket.remove(&pid);
                        }
                    }

                    // 添加到正确的优先级桶
                    {
                        let mut queue = READY_QUEUE.lock();
                        queue.entry(priority).or_default().insert(pid, pcb);
                    }

                    return true;
                }
            }
            false
        })
    }

    /// 选择下一个要运行的进程
    ///
    /// 按优先级从高到低（数值从小到大）遍历，返回第一个就绪进程
    pub fn select_next() -> Option<Pid> {
        interrupts::without_interrupts(|| {
            let queue = READY_QUEUE.lock();
            Self::select_next_locked(&queue, None)
        })
    }

    /// 更新当前运行的进程
    ///
    /// R67-4 FIX: Uses per-CPU storage.
    pub fn set_current(pid: Option<Pid>) {
        CURRENT_PROCESS.with(|current: &Mutex<Option<Pid>>| {
            *current.lock() = pid;
        });
    }

    /// 获取当前运行的进程
    ///
    /// R67-4 FIX: Reads from per-CPU storage.
    pub fn get_current() -> Option<Pid> {
        CURRENT_PROCESS.with(|current: &Mutex<Option<Pid>>| *current.lock())
    }

    /// 处理时钟中断 - 更新时间片并设置重调度标志
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    /// 所有调度器函数必须遵循此顺序以避免死锁
    ///
    /// **重要**: 此函数在中断上下文中运行，只设置当前 CPU 的 need_resched 标志，
    /// 不执行实际的调度/CR3切换。这避免了在中断返回时运行在错误地址空间的问题。
    ///
    /// # R65-19 FIX: 饥饿防止
    ///
    /// 每次tick时，遍历所有就绪进程，增加等待计数器，并在超过阈值时
    /// 提升其优先级。这确保了即使低优先级进程被高优先级进程持续抢占，
    /// 也能在合理时间内获得CPU时间。
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU CURRENT_PROCESS and need_resched to avoid cross-CPU races.
    pub fn on_clock_tick() {
        // 使用 without_interrupts 确保在持有锁期间不会被嵌套中断打断
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Use per-CPU current process
            let current_pid = Self::get_current();

            // 获取当前进程的 Arc 引用并更新时间片
            if let Some(pcb) = {
                let queue = READY_QUEUE.lock();
                current_pid.and_then(|pid| Self::find_pcb(&queue, pid))
            } {
                let mut proc = pcb.lock();

                // 减少时间片
                if proc.time_slice > 0 {
                    proc.time_slice -= 1;
                }

                // 时间片已用完，标记为就绪态并降低优先级
                if proc.time_slice == 0 {
                    proc.state = ProcessState::Ready;
                    proc.decrease_dynamic_priority(); // 惩罚 CPU 密集型进程
                    proc.reset_time_slice();
                    // R67-4 FIX: Set this CPU's reschedule flag
                    current_cpu().set_need_resched();
                }
            }

            // R65-19 FIX: 饥饿防止 - 增加等待进程的等待计数并检查饥饿
            {
                let queue = READY_QUEUE.lock();
                for (_priority, bucket) in queue.iter() {
                    for (&pid, pcb) in bucket.iter() {
                        // 跳过当前运行的进程
                        if Some(pid) == current_pid {
                            continue;
                        }
                        let mut proc = pcb.lock();
                        if proc.state == ProcessState::Ready {
                            // 增加等待时间
                            proc.increment_wait_ticks();
                            // 检查并提升饥饿进程的优先级
                            proc.check_and_boost_starved();
                        }
                    }
                }
            }

            // 最后更新 SCHEDULER_STATS
            {
                let mut stats = SCHEDULER_STATS.lock();
                stats.total_ticks += 1;
            }
        });
        // 注意：不再在中断上下文中调用 schedule()
        // 真正的上下文切换需要在受控路径中执行（如系统调用返回或显式调度点）
    }

    /// 查询是否需要重新调度
    ///
    /// R67-4 FIX: Reads from per-CPU need_resched flag.
    pub fn need_resched() -> bool {
        current_cpu().need_resched.load(Ordering::SeqCst)
    }

    /// 清除重调度标志
    ///
    /// R67-4 FIX: Clears this CPU's need_resched flag.
    pub fn clear_resched() {
        current_cpu().need_resched.store(false, Ordering::SeqCst);
    }

    /// 执行调度 - 选择下一个进程并更新状态
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    ///
    /// **重要**: 此函数只更新进程状态和当前进程标识，不切换CR3。
    /// CR3切换必须与完整的寄存器上下文切换（switch_context）配合执行。
    /// 当前内核尚未实现真正的进程切换，所有"进程"共享内核地址空间。
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU CURRENT_PROCESS and need_resched to avoid cross-CPU races.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn schedule() -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Clear this CPU's reschedule flag
            current_cpu().need_resched.store(false, Ordering::SeqCst);

            // R67-4 FIX: Use per-CPU current process
            let current_pid = Self::get_current();
            sched_debug!("[SCHED] schedule: current_pid={:?}", current_pid);

            // 在单次锁定中获取所需的所有引用
            // 注意：传递 current_pid 给 select_next_locked，使其优先选择其他进程
            // 这确保 yield 后不会立即再次选中自己，给其他进程运行机会
            let (next_pid, current_proc, next_proc) = {
                let queue = READY_QUEUE.lock();
                let next = Self::select_next_locked(&queue, current_pid);
                let current_proc = current_pid.and_then(|pid| Self::find_pcb(&queue, pid));
                let next_proc = next.and_then(|pid| Self::find_pcb(&queue, pid));
                (next, current_proc, next_proc)
            };

            sched_debug!("[SCHED] schedule: next_pid={:?}", next_pid);

            // 选择下一个要运行的进程
            if let Some(next_pid) = next_pid {
                if Some(next_pid) != current_pid {
                    sched_debug!("[SCHED] switching from {:?} to {}", current_pid, next_pid);
                    // 保存当前进程状态
                    if let Some(proc) = current_proc {
                        let mut pcb = proc.lock();
                        if pcb.state == ProcessState::Running {
                            pcb.state = ProcessState::Ready;
                        }
                    }

                    // 设置新进程为运行态并获取其地址空间
                    let next_memory_space = if let Some(proc) = next_proc {
                        let mut pcb = proc.lock();
                        pcb.state = ProcessState::Running;
                        pcb.reset_time_slice();
                        pcb.reset_wait_ticks(); // R65-19 FIX: Reset wait counter when scheduled
                        pcb.memory_space
                    } else {
                        0 // 默认使用引导页表
                    };

                    // 注意：不在此处切换 CR3
                    // CR3 切换必须与 switch_context 配合执行，否则会导致：
                    // 1. 中断返回后运行在错误的地址空间
                    // 2. 被中断的代码访问错误的内存映射
                    //
                    // TODO: 实现完整的上下文切换路径后，在此处或调用方处理 CR3
                    // process::activate_memory_space(next_memory_space);

                    // 更新当前进程 (both scheduler and kernel_core trackers)
                    Self::set_current(Some(next_pid));
                    process::set_current_pid(Some(next_pid));

                    let mut stats = SCHEDULER_STATS.lock();
                    stats.total_switches += 1;

                    return Some((next_pid, next_memory_space));
                }
            }
            None
        })
    }

    /// 主动让出CPU
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn yield_cpu() -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            if let Some(pid) = Self::get_current() {
                if let Some(pcb) = {
                    let queue = READY_QUEUE.lock();
                    Self::find_pcb(&queue, pid)
                } {
                    let mut proc = pcb.lock();
                    proc.state = ProcessState::Ready;
                    proc.update_dynamic_priority(); // 奖励主动让出的进程
                }
            }
        });

        Self::schedule()
    }

    /// 获取进程数量
    pub fn process_count() -> usize {
        interrupts::without_interrupts(|| {
            READY_QUEUE.lock().values().map(|bucket| bucket.len()).sum()
        })
    }

    /// 打印调度统计信息
    pub fn print_stats() {
        interrupts::without_interrupts(|| {
            SCHEDULER_STATS.lock().print();
        });
    }

    /// 在安全上下文中执行完整上下文切换（含 CR3）
    ///
    /// # Arguments
    /// * `force` - true 无视 need_resched 立即尝试切换（用于 sys_yield）
    ///           - false 只有 need_resched 置位时才切换（用于系统调用返回点）
    ///
    /// 此函数是调度器的核心入口点，负责：
    /// 1. 检查是否需要调度
    /// 2. 选择下一个进程
    /// 3. 保存旧进程上下文（在旧地址空间中）
    /// 4. 切换地址空间（CR3）
    /// 5. 根据目标进程特权级选择切换方式：
    ///    - Ring 0：使用 switch_context 直接切换
    ///    - Ring 3：使用 save_context + enter_usermode (IRETQ)
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU need_resched and CURRENT_PROCESS to avoid cross-CPU races.
    ///
    /// **警告**: 此函数可能不会返回（如果发生上下文切换）
    pub fn reschedule_now(force: bool) {
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Check and clear this CPU's need_resched flag
            if !force && !current_cpu().clear_need_resched() {
                return;
            }

            // R67-4 FIX: Use per-CPU current process
            let old_pid = Self::get_current();

            // 执行调度决策
            let sched_decision = Self::schedule();
            let (next_pid, next_space) = match sched_decision {
                Some(v) => v,
                None => return, // 没有可调度的进程
            };

            // 如果新旧进程相同，无需切换
            if old_pid == Some(next_pid) {
                return;
            }

            // 获取新进程的 PCB（必须存在）
            let next_pcb = match process::get_process(next_pid) {
                Some(p) => p,
                None => return,
            };

            // 获取旧进程的上下文指针
            // 首次调度时 old_pid 为 None，使用哑上下文保存内核启动状态
            let old_ctx_ptr: *mut ArchContext = match old_pid.and_then(process::get_process) {
                Some(old_pcb) => {
                    let mut guard = old_pcb.lock();

                    // R24-6 fix: 保存当前硬件 FS/GS base 到 PCB
                    // 用户态可能通过 wrfsbase/wrgsbase 指令修改了 TLS 基址，
                    // 必须在切换前读取 MSR 并保存，否则下次恢复时会使用旧值
                    #[cfg(target_arch = "x86_64")]
                    {
                        use x86_64::registers::model_specific::Msr;
                        const MSR_FS_BASE: u32 = 0xC000_0100;
                        const MSR_GS_BASE: u32 = 0xC000_0101;

                        unsafe {
                            let fs_msr = Msr::new(MSR_FS_BASE);
                            let gs_msr = Msr::new(MSR_GS_BASE);
                            guard.fs_base = fs_msr.read();
                            guard.gs_base = gs_msr.read();
                        }
                    }

                    &mut guard.context as *mut _ as *mut ArchContext
                }
                None => {
                    // 首次调度：保存到哑上下文（不会被恢复）
                    let mut bootstrap = BOOTSTRAP_CONTEXT.lock();
                    &mut *bootstrap as *mut ArchContext
                }
            };

            // 获取新进程的上下文指针、内核栈顶、CS（用于判断 Ring 3）和 FS/GS base（TLS）
            let (new_ctx_ptr, next_kstack_top, next_cs, next_fs_base, next_gs_base): (
                *const ArchContext,
                u64,
                u64,
                u64,
                u64,
            ) = {
                let guard = next_pcb.lock();
                let ctx = &guard.context as *const _ as *const ArchContext;
                let kstack_top = guard.kernel_stack_top.as_u64();
                let cs = guard.context.cs;
                let fs_base = guard.fs_base;
                let gs_base = guard.gs_base;
                (ctx, kstack_top, cs, fs_base, gs_base)
            };

            // 判断下一个进程是否为用户态进程（Ring 3）
            // CS 的低 2 位是 RPL（Request Privilege Level）
            // RPL == 3 表示用户态（Ring 3）
            let next_is_user = (next_cs & 0x3) == 0x3;

            // 执行上下文切换
            // switch_context 内部流程：
            // 1. 保存当前寄存器到 old_ctx（在当前/旧地址空间中完成）
            // 2. 恢复新进程寄存器（包括 rsp）
            // 3. 跳转到新进程的 rip
            //
            // 注意：CR3 切换在 switch_context 之后执行会有问题，因为跳转后
            // 已在新进程的执行路径中。因此我们在切换前激活新地址空间。
            //
            // 安全性说明：当前内核使用共享内核地址空间模型，所有进程的
            // 内核映射（高地址半区）相同，因此 CR3 切换后仍能访问所有 PCB。

            // 更新 TSS.rsp0 为新进程的内核栈顶
            // 这确保从用户态中断/异常返回时使用正确的内核栈
            // 如果进程没有专用内核栈，回退到默认内核栈以避免使用旧进程的栈
            let effective_kstack_top = if next_kstack_top != 0 {
                next_kstack_top
            } else {
                default_kernel_stack_top()
            };
            unsafe {
                set_kernel_stack(effective_kstack_top);
            }

            // Debug output for Ring 3 transition (minimal)
            // Uncomment for debugging: println!("[SCHED] -> PID {} (Ring {})", next_pid, if next_is_user { 3 } else { 0 });

            process::activate_memory_space(next_space);

            // 执行上下文切换
            // 根据目标进程的特权级选择不同的切换方式：
            //
            // - Ring 0（内核进程）：使用 switch_context 直接切换寄存器和栈
            // - Ring 3（用户进程）：需要使用 IRETQ 进行特权级切换
            //
            // 对于 Ring 3 进程，enter_usermode 永不返回（执行 IRETQ 跳转到用户态），
            // 因此必须先用 save_context 保存当前内核上下文，以便下次被调度时恢复。
            unsafe {
                if next_is_user {
                    // 用户态进程：先保存当前上下文，再通过 IRETQ 进入用户态
                    // enter_usermode 会验证 RIP/RSP 的规范性和用户空间边界，
                    // 清理 RFLAGS 中的特权位（IOPL/NT/RF），强制使用用户段选择子
                    save_context(old_ctx_ptr);

                    // Debug: 打印进入用户态前的上下文（必须在 MSR 写入之前）
                    {
                        let ctx = &*new_ctx_ptr;
                        sched_debug!(
                            "[SCHED] enter_usermode PID={}: rax=0x{:x}, rip=0x{:x}, rsp=0x{:x}, fs_base=0x{:x}",
                            next_pid, ctx.rax, ctx.rip, ctx.rsp, next_fs_base
                        );
                    }

                    // 恢复用户进程的 FS/GS base (TLS 支持)
                    // 必须在 enter_usermode 之前的最后一步写入 MSR
                    // 因为 println! 等内核代码可能会覆盖 FS_BASE MSR
                    {
                        use x86_64::registers::model_specific::Msr;
                        const MSR_FS_BASE: u32 = 0xC000_0100;
                        const MSR_GS_BASE: u32 = 0xC000_0101;

                        let mut fs_msr = Msr::new(MSR_FS_BASE);
                        fs_msr.write(next_fs_base);

                        let mut gs_msr = Msr::new(MSR_GS_BASE);
                        gs_msr.write(next_gs_base);
                    }

                    enter_usermode(new_ctx_ptr);
                    // 不会到达这里
                } else {
                    // 内核态进程：使用标准的 switch_context
                    // 对于旧进程，函数会在下次被调度时从这里"返回"
                    // R65-16 FIX: Validate target context has kernel-mode segments before switching.
                    // This prevents a critical privilege escalation vulnerability.
                    assert_kernel_context(new_ctx_ptr);
                    switch_context(old_ctx_ptr, new_ctx_ptr);
                }
            }
        });
    }
}

/// 初始化调度器
pub fn init() {
    // 注册进程清理回调，确保进程终止时调度器同步更新
    process::register_cleanup_notifier(Scheduler::remove_process);

    // 注册调度器添加进程回调，用于 clone/fork 时添加新进程
    process::register_scheduler_add(Scheduler::add_process);

    // 注册定时器回调，让 arch 模块的定时器中断能调用调度器
    kernel_core::register_timer_callback(Scheduler::on_clock_tick);

    // 注册重调度回调，让系统调用返回时能触发调度
    kernel_core::register_resched_callback(Scheduler::reschedule_now);

    // 注册信号恢复回调，让 SIGCONT 能正确恢复暂停的进程
    kernel_core::register_resume_callback(Scheduler::resume_stopped);

    println!("Enhanced scheduler initialized");
    println!("  Ready queue capacity: unlimited");
    println!("  Scheduling algorithm: Priority-based with time slice");
    println!("  Context switch: Enabled with CR3 switching + Ring 3 IRETQ support");
}
