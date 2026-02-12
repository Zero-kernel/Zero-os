use crate::process::{
    current_pid, get_process, set_current_pid, Priority, ProcessId, ProcessState,
};
use alloc::collections::BTreeMap;
use spin::Mutex;

/// 优先级调度器
/// 使用多级反馈队列实现，支持优先级和时间片
pub struct PriorityScheduler {
    /// 就绪队列，按优先级组织（优先级 -> 进程ID列表）
    ready_queues: BTreeMap<Priority, alloc::vec::Vec<ProcessId>>,

    /// 当前运行的进程ID
    current_process: Option<ProcessId>,

    /// 调度统计
    stats: SchedulerStats,
}

impl PriorityScheduler {
    pub fn new() -> Self {
        PriorityScheduler {
            ready_queues: BTreeMap::new(),
            current_process: None,
            stats: SchedulerStats::default(),
        }
    }

    /// 添加进程到就绪队列
    pub fn add_process(&mut self, pid: ProcessId) {
        if let Some(process) = get_process(pid) {
            let mut proc = process.lock();
            let priority = proc.dynamic_priority;
            proc.state = ProcessState::Ready;
            drop(proc);

            self.ready_queues
                .entry(priority)
                .or_insert_with(alloc::vec::Vec::new)
                .push(pid);

            self.stats.enqueued += 1;
        }
    }

    /// 从就绪队列移除进程
    pub fn remove_process(&mut self, pid: ProcessId) -> bool {
        for (_priority, queue) in self.ready_queues.iter_mut() {
            if let Some(pos) = queue.iter().position(|&p| p == pid) {
                queue.remove(pos);
                return true;
            }
        }
        false
    }

    /// 选择下一个要运行的进程
    pub fn schedule(&mut self) -> Option<ProcessId> {
        // 如果有当前进程，先处理它
        if let Some(current_pid) = self.current_process {
            if let Some(process) = get_process(current_pid) {
                let mut proc = process.lock();

                // 检查进程状态
                // R98-1 FIX: Also check orthogonal stopped flag
                match proc.state {
                    ProcessState::Running => {
                        // R98-1 FIX: Check job-control stop flag first
                        if proc.stopped {
                            // Put the task back into the ready queues as Ready-but-stopped
                            proc.reset_time_slice();
                            proc.state = ProcessState::Ready;
                            let priority = proc.dynamic_priority;
                            drop(proc);

                            self.ready_queues
                                .entry(priority)
                                .or_insert_with(alloc::vec::Vec::new)
                                .push(current_pid);
                        } else if proc.time_slice > 0 {
                            // 还有时间片，继续运行
                            return Some(current_pid);
                        } else {
                            // 时间片用完，重新加入就绪队列
                            proc.reset_time_slice();
                            proc.decrease_dynamic_priority(); // 惩罚CPU密集型进程
                            proc.state = ProcessState::Ready;
                            let priority = proc.dynamic_priority;
                            drop(proc);

                            self.ready_queues
                                .entry(priority)
                                .or_insert_with(alloc::vec::Vec::new)
                                .push(current_pid);
                        }
                    }
                    ProcessState::Blocked | ProcessState::Sleeping | ProcessState::Stopped => {
                        // 进程被阻塞/睡眠/暂停，不再运行
                        drop(proc);
                    }
                    ProcessState::Zombie | ProcessState::Terminated => {
                        // 进程已终止
                        drop(proc);
                    }
                    _ => {
                        drop(proc);
                    }
                }
            }

            self.current_process = None;
        }

        // 从最高优先级队列中选择进程
        while let Some((&priority, queue)) = self.ready_queues.iter_mut().next() {
            if queue.is_empty() {
                self.ready_queues.remove(&priority);
                continue;
            }

            // 从队列头部取出进程（FIFO）
            let pid = queue.remove(0);

            if let Some(process) = get_process(pid) {
                let mut proc = process.lock();

                // 确保进程仍然是就绪状态
                // R98-1 FIX: Also check orthogonal stopped flag
                if proc.state == ProcessState::Ready && !proc.stopped {
                    proc.state = ProcessState::Running;
                    proc.reset_time_slice();
                    drop(proc);

                    self.current_process = Some(pid);
                    self.stats.scheduled += 1;
                    set_current_pid(Some(pid));

                    return Some(pid);
                }
            }
        }

        // 没有可运行的进程
        set_current_pid(None);
        None
    }

    /// 时钟中断处理（每个时钟滴答调用）
    pub fn tick(&mut self) {
        if let Some(current_pid) = self.current_process {
            if let Some(process) = get_process(current_pid) {
                let mut proc = process.lock();

                if proc.state == ProcessState::Running {
                    // 减少时间片
                    if proc.time_slice > 0 {
                        proc.time_slice -= 1;
                    }

                    // 增加CPU时间
                    proc.cpu_time += 1;

                    // 定期提升优先级（防止饥饿）
                    if proc.cpu_time % 100 == 0 {
                        proc.update_dynamic_priority();
                    }
                }
            }
        }

        self.stats.ticks += 1;
    }

    /// 阻塞当前进程
    pub fn block_current(&mut self) {
        if let Some(current_pid) = self.current_process {
            if let Some(process) = get_process(current_pid) {
                let mut proc = process.lock();
                proc.state = ProcessState::Blocked;
                drop(proc);
            }
            self.current_process = None;
        }
    }

    /// 唤醒进程
    pub fn wake_up(&mut self, pid: ProcessId) {
        if let Some(process) = get_process(pid) {
            let mut proc = process.lock();
            if proc.state == ProcessState::Blocked || proc.state == ProcessState::Sleeping {
                proc.state = ProcessState::Ready;
                let priority = proc.dynamic_priority;
                drop(proc);

                self.ready_queues
                    .entry(priority)
                    .or_insert_with(alloc::vec::Vec::new)
                    .push(pid);

                self.stats.woken += 1;
            }
        }
    }

    /// 获取调度器统计信息
    pub fn get_stats(&self) -> SchedulerStats {
        self.stats
    }

    /// 获取就绪队列中的进程数
    pub fn ready_count(&self) -> usize {
        self.ready_queues.values().map(|q| q.len()).sum()
    }
}

/// 调度器统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedulerStats {
    pub scheduled: u64, // 调度次数
    pub enqueued: u64,  // 入队次数
    pub woken: u64,     // 唤醒次数
    pub ticks: u64,     // 时钟滴答数
}

impl SchedulerStats {
    pub fn print(&self) {
        klog_always!("=== Scheduler Statistics ===");
        klog_always!("Scheduled:  {}", self.scheduled);
        klog_always!("Enqueued:   {}", self.enqueued);
        klog_always!("Woken:      {}", self.woken);
        klog_always!("Ticks:      {}", self.ticks);
    }
}

/// 全局调度器实例
lazy_static::lazy_static! {
    static ref SCHEDULER: Mutex<PriorityScheduler> = Mutex::new(PriorityScheduler::new());
}

/// 初始化调度器
pub fn init() {
    klog_always!("Priority scheduler initialized");

    // 创建init进程（PID 0，最高优先级）
    // Init 进程必须成功创建，失败则 panic
    let init_pid = crate::process::create_process("init".into(), 0, 0)
        .expect("FATAL: Failed to create init process - kernel stack allocation failed");
    SCHEDULER.lock().add_process(init_pid);

    klog_always!("Init process created with PID {}", init_pid);
}

/// 执行调度
pub fn schedule() -> Option<ProcessId> {
    SCHEDULER.lock().schedule()
}

/// 添加进程到调度器
pub fn add_process(pid: ProcessId) {
    SCHEDULER.lock().add_process(pid);
}

/// 从调度器移除进程
pub fn remove_process(pid: ProcessId) {
    SCHEDULER.lock().remove_process(pid);
}

/// 时钟中断处理
pub fn tick() {
    SCHEDULER.lock().tick();
}

/// 阻塞当前进程
pub fn block_current() {
    SCHEDULER.lock().block_current();
}

/// 唤醒进程
pub fn wake_up(pid: ProcessId) {
    SCHEDULER.lock().wake_up(pid);
}

/// 获取调度器统计信息
pub fn get_scheduler_stats() -> SchedulerStats {
    SCHEDULER.lock().get_stats()
}

/// 获取就绪队列中的进程数
pub fn ready_count() -> usize {
    SCHEDULER.lock().ready_count()
}

/// 主调度循环（用于测试）
pub fn run() -> ! {
    loop {
        if let Some(pid) = schedule() {
            // 在实际实现中，这里应该切换到进程上下文
            // 现在只是简单地打印信息
            if let Some(process) = get_process(pid) {
                let proc = process.lock();
                kprintln!(
                    "Running process: PID={}, Name={}, Priority={}, TimeSlice={}ms",
                    pid, proc.name, proc.dynamic_priority, proc.time_slice
                );
            }

            // 模拟进程执行
            x86_64::instructions::hlt();
        } else {
            // 没有进程可运行，进入空闲状态
            kprintln!("No process to run, entering idle state");
            x86_64::instructions::hlt();
        }
    }
}
