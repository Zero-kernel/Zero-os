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
//!
//! # R69-1 FIX: Per-CPU Run Queues
//!
//! Ready queues are now per-CPU (CpuLocal<Mutex<...>>) with work stealing and
//! periodic load balancing to avoid global lock contention. This improves SMP
//! scalability by eliminating the global queue lock as a bottleneck.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};
use cpu_local::{current_cpu, current_cpu_id, max_cpus, num_online_cpus, CpuLocal, NO_FPU_OWNER};
use kernel_core::process::{self, Priority, Process, ProcessId, ProcessState};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::interrupts;

// 导入arch模块的上下文切换功能
use arch::ipi::{send_ipi, IpiType};
use arch::Context as ArchContext;
use arch::{assert_kernel_context, enter_usermode, save_context, switch_context};
use arch::{default_kernel_stack_top, set_kernel_stack};

/// 调度器调试输出开关
///
/// 设置为 true 启用详细调度日志，设置为 false 禁用
/// 在生产环境或使用 shell 时应设置为 false
const SCHED_DEBUG: bool = false;

/// Work-stealing and load balancing tunables
///
/// LOAD_BALANCE_INTERVAL_TICKS: How often (in timer ticks) to run the load balancer.
/// LOAD_IMBALANCE_THRESHOLD: Minimum difference in queue lengths before migrating.
const LOAD_BALANCE_INTERVAL_TICKS: u64 = 64;
const LOAD_IMBALANCE_THRESHOLD: usize = 1;

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

/// R70-4 FIX: Shadow buffer for the next task's context.
///
/// Per-CPU storage to hold a copy of the target task's Context while the PCB
/// lock is released. This prevents use-after-unlock when calling enter_usermode
/// or switch_context, fixing the root cause of kick IPI double-fault.
///
/// Safety: Each CPU only mutates its own slot in reschedule_now() with
/// interrupts disabled, so cross-CPU aliasing cannot occur.
///
/// Note: Uses kernel_core::process::Context which is ABI-compatible with
/// arch::Context (same #[repr(C, align(64))] layout). Cast to ArchContext
/// pointer when passing to context switch functions.
struct ContextShadow {
    buf: UnsafeCell<process::Context>,
}

unsafe impl Send for ContextShadow {}
unsafe impl Sync for ContextShadow {}

impl ContextShadow {
    fn new() -> Self {
        Self {
            buf: UnsafeCell::new(process::Context::default()),
        }
    }

    /// Copy the context into the shadow buffer and return a stable pointer.
    ///
    /// Must be called with interrupts disabled to prevent preemption.
    /// Returns pointer cast to ArchContext for use with context switch functions.
    #[inline]
    fn store(&self, ctx: &process::Context) -> *const ArchContext {
        // Safety: We have exclusive access (per-CPU, interrupts disabled)
        // process::Context and arch::Context have identical ABI layout
        unsafe {
            *self.buf.get() = *ctx;
            self.buf.get() as *const ArchContext
        }
    }
}

/// Per-CPU scratch space for staging the next task's Context before the PCB
/// lock is released. Prevents use-after-unlock when calling enter_usermode.
static NEXT_CONTEXT_SHADOW: CpuLocal<ContextShadow> = CpuLocal::new(ContextShadow::new);

// Static assert: ensure process::Context and arch::Context have identical size/align
// This guards against future drift between the two types which would cause UB.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<process::Context>() == size_of::<ArchContext>());
    assert!(align_of::<process::Context>() == align_of::<ArchContext>());
};

/// 用于首次调度的哑上下文（内核启动上下文的保存位置，无需恢复）
static BOOTSTRAP_CONTEXT: Mutex<ArchContext> = Mutex::new(ArchContext::new());

/// R67-4 FIX: Per-CPU current process tracking.
///
/// Each CPU tracks its own current process. This prevents races where
/// multiple CPUs could believe they own the same process.
static CURRENT_PROCESS: CpuLocal<Mutex<Option<Pid>>> = CpuLocal::new(|| Mutex::new(None));

/// R69-1 FIX: Per-CPU ready queues - each CPU has its own priority-bucketed queue.
///
/// Using CpuLocal splits the lock across CPUs, reducing cross-CPU contention and
/// enabling work stealing for load balancing.
pub static READY_QUEUE: CpuLocal<Mutex<ReadyQueues>> =
    CpuLocal::new(|| Mutex::new(BTreeMap::new()));

lazy_static! {
    pub static ref SCHEDULER_STATS: Mutex<SchedulerStats> = Mutex::new(SchedulerStats::new());
}

/// Load balancing tick counter (only driven on CPU0 to reduce contention)
static BALANCE_TICKER: AtomicU64 = AtomicU64::new(0);

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
        // Get current CPU ID for affinity check
        let cpu_id = current_cpu_id();
        let cpu_mask = 1u64 << cpu_id;

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
                let proc = pcb.lock();
                // Check both state AND CPU affinity
                if proc.state == ProcessState::Ready && (proc.allowed_cpus & cpu_mask) != 0 {
                    sched_debug!("[SCHED] selected pid={}", pid);
                    return Some(pid);
                }
            }
        }

        // 如果没有其他就绪进程，回退到被跳过的进程（如果它是就绪的且允许在此CPU运行）
        if let Some(skip) = skip_pid {
            if let Some(pcb) = Self::find_pcb(queue, skip) {
                let proc = pcb.lock();
                if proc.state == ProcessState::Ready && (proc.allowed_cpus & cpu_mask) != 0 {
                    sched_debug!("[SCHED] fallback to skipped pid={}", skip);
                    return Some(skip);
                }
            }
        }

        sched_debug!("[SCHED] no ready process found");
        None
    }

    // ========================================================================
    // R69-1 FIX: Per-CPU Queue Helper Functions
    // ========================================================================

    /// Get the current CPU's ready queue
    #[inline]
    fn current_ready_queue() -> &'static Mutex<ReadyQueues> {
        READY_QUEUE.with(|q: &Mutex<ReadyQueues>| unsafe { &*(q as *const Mutex<ReadyQueues>) })
    }

    /// Get a specific CPU's ready queue
    #[inline]
    fn ready_queue_for_cpu(cpu_id: usize) -> Option<&'static Mutex<ReadyQueues>> {
        READY_QUEUE.get_cpu(cpu_id)
    }

    /// Calculate the length of a ready queue
    #[inline]
    fn queue_len(queue: &ReadyQueues) -> usize {
        queue.values().map(|bucket| bucket.len()).sum()
    }

    /// Get queue length for a specific CPU
    #[inline]
    fn queue_len_for_cpu(cpu_id: usize) -> usize {
        Self::ready_queue_for_cpu(cpu_id)
            .map(|q| Self::queue_len(&q.lock()))
            .unwrap_or(0)
    }

    // ========================================================================
    // R70-2 FIX: SMP Kick Mechanism
    //
    // When new work becomes runnable, wake idle CPUs so they can pick it up
    // immediately rather than waiting for the next timer tick.
    // ========================================================================

    /// Check whether a CPU is permitted by the affinity mask (bit N = CPU N).
    ///
    /// Guards against CPU IDs >= 64 to avoid undefined behavior from shift overflow.
    #[inline]
    fn cpu_allowed(cpu_id: usize, allowed_cpus: u64) -> bool {
        cpu_id < 64 && (allowed_cpus & (1u64 << cpu_id)) != 0
    }

    /// Send a reschedule IPI to the target CPU.
    ///
    /// This wakes the CPU from its idle HLT loop, causing it to check for
    /// runnable work in its ready queue.
    ///
    /// R70-7: Re-enabled after R70-4 (context shadow buffer) and R70-5 (AP stack
    /// allocation fix) resolved the double fault issue.
    #[inline]
    fn kick_cpu(cpu_id: usize) {
        send_ipi(cpu_id, IpiType::Reschedule);
    }

    /// Wake idle CPUs that are allowed to run the given work.
    ///
    /// Iterates through online CPUs (excluding self) and sends a reschedule IPI
    /// to any CPU that:
    /// 1. Is allowed by the process's CPU affinity mask
    /// 2. Has an empty ready queue (likely idle in HLT)
    ///
    /// This enables rapid work distribution when multiple idle CPUs exist.
    ///
    /// R70-4: Re-enabled after fixing use-after-unlock race in reschedule_now()
    /// via per-CPU context shadow buffer.
    fn kick_idle_cpus(allowed_cpus: u64) {
        let self_cpu = current_cpu_id();
        let total = Self::cpu_pool_size();
        for cpu_id in 0..total {
            if cpu_id == self_cpu {
                continue;
            }
            // Skip CPUs not in affinity mask (0 means all allowed)
            if allowed_cpus != 0 && !Self::cpu_allowed(cpu_id, allowed_cpus) {
                continue;
            }
            // Only kick if queue is empty (CPU likely idle in HLT)
            let queue_empty = Self::ready_queue_for_cpu(cpu_id)
                .map(|q| q.lock().is_empty())
                .unwrap_or(false);
            if queue_empty {
                Self::kick_cpu(cpu_id);
            }
        }
    }

    /// Send a reschedule IPI to a specific CPU.
    #[allow(dead_code)]
    fn kick_cpu_impl(cpu_id: usize) {
        send_ipi(cpu_id, IpiType::Reschedule);
    }

    /// Number of CPUs to consider for load balancing (at least 1)
    #[inline]
    fn cpu_pool_size() -> usize {
        cmp::min(max_cpus(), cmp::max(num_online_cpus(), 1))
    }

    /// Find the least loaded CPU and its queue length
    ///
    /// # Arguments
    /// * `exclude` - Optional CPU to exclude from search
    /// * `allowed_cpus` - Affinity mask (bit N = CPU N allowed). If 0, all CPUs are considered.
    fn least_loaded_cpu(exclude: Option<usize>, allowed_cpus: u64) -> (usize, usize) {
        let mut best_cpu = current_cpu_id();
        let mut best_len = usize::MAX;
        let total = Self::cpu_pool_size();
        for cpu_id in 0..total {
            if Some(cpu_id) == exclude {
                continue;
            }
            // R70-2 FIX: Filter by affinity mask (0 means no restriction)
            if allowed_cpus != 0 && !Self::cpu_allowed(cpu_id, allowed_cpus) {
                continue;
            }
            if let Some(q) = Self::ready_queue_for_cpu(cpu_id) {
                let len = Self::queue_len(&q.lock());
                if len < best_len {
                    best_len = len;
                    best_cpu = cpu_id;
                }
            }
        }
        (best_cpu, best_len)
    }

    /// Select target CPU for new/resumed work (load-aware placement)
    ///
    /// # Arguments
    /// * `preferred_cpu` - Default CPU (usually current CPU)
    /// * `allowed_cpus` - Affinity mask (bit N = CPU N allowed). If 0, all CPUs are considered.
    fn target_cpu_for_new_work(preferred_cpu: usize, allowed_cpus: u64) -> usize {
        // R70-2 FIX: Pass affinity mask to least_loaded_cpu
        let (least_cpu, least_len) = Self::least_loaded_cpu(None, allowed_cpus);
        let preferred_len = Self::queue_len_for_cpu(preferred_cpu);

        // If preferred CPU is not allowed, always use least_cpu
        if allowed_cpus != 0 && !Self::cpu_allowed(preferred_cpu, allowed_cpus) {
            return least_cpu;
        }

        if least_len != usize::MAX
            && least_cpu != preferred_cpu
            && least_len + LOAD_IMBALANCE_THRESHOLD < preferred_len
        {
            least_cpu
        } else {
            preferred_cpu
        }
    }

    /// Remove a PID from all CPU queues
    fn remove_from_all_queues(pid: Pid) {
        let cpu_count = Self::cpu_pool_size();
        for cpu_id in 0..cpu_count {
            if let Some(queue) = Self::ready_queue_for_cpu(cpu_id) {
                let mut guard = queue.lock();
                for bucket in guard.values_mut() {
                    bucket.remove(&pid);
                }
                guard.retain(|_, bucket| !bucket.is_empty());
            }
        }
    }

    /// Enqueue a process on a specific CPU's queue
    fn enqueue_on_cpu(pcb: ProcessControlBlock, priority: Priority, cpu_id: usize) {
        let queue =
            Self::ready_queue_for_cpu(cpu_id).unwrap_or_else(|| Self::current_ready_queue());
        let pid = {
            let mut proc = pcb.lock();
            proc.state = ProcessState::Ready;
            proc.pid
        };
        let mut guard = queue.lock();
        guard.entry(priority).or_default().insert(pid, pcb);
    }

    /// Pop a ready process from a queue (for migration)
    fn pop_ready_process(queue: &mut ReadyQueues) -> Option<(Pid, ProcessControlBlock, Priority)> {
        let mut target: Option<(Priority, Pid)> = None;
        for (&priority, bucket) in queue.iter() {
            for (&pid, pcb) in bucket.iter() {
                if pcb.lock().state == ProcessState::Ready {
                    target = Some((priority, pid));
                    break;
                }
            }
            if target.is_some() {
                break;
            }
        }

        if let Some((priority, pid)) = target {
            if let Some(bucket) = queue.get_mut(&priority) {
                if let Some(pcb) = bucket.remove(&pid) {
                    if bucket.is_empty() {
                        queue.remove(&priority);
                    }
                    return Some((pid, pcb, priority));
                }
            }
        }
        None
    }

    /// Try to steal a ready process from another CPU
    fn steal_one(
        current_pid: Option<Pid>,
    ) -> Option<(Pid, ProcessControlBlock, usize, Priority)> {
        let local_cpu = current_cpu_id();
        let cpu_count = Self::cpu_pool_size();
        if cpu_count < 2 {
            return None;
        }

        // Find the most loaded CPU (potential victim)
        let mut source_cpu = None;
        let mut source_len = 0usize;
        for cpu_id in 0..cpu_count {
            if cpu_id == local_cpu {
                continue;
            }
            let len = Self::queue_len_for_cpu(cpu_id);
            if len > source_len {
                source_len = len;
                source_cpu = Some(cpu_id);
            }
        }

        let source_cpu = source_cpu?;
        if source_len == 0 {
            return None;
        }

        let queue = Self::ready_queue_for_cpu(source_cpu)?;
        let mut guard = queue.lock();
        let mut candidate = Self::select_next_locked(&guard, None);
        while let Some(pid) = candidate {
            // Skip if this is the current process
            if Some(pid) == current_pid {
                candidate = Self::select_next_locked(&guard, Some(pid));
                continue;
            }
            if let Some(proc_arc) = Self::find_pcb(&guard, pid) {
                let mut pcb = proc_arc.lock();
                if pcb.state != ProcessState::Ready {
                    drop(pcb);
                    candidate = Self::select_next_locked(&guard, Some(pid));
                    continue;
                }
                let priority = pcb.dynamic_priority;
                pcb.state = ProcessState::Running;
                pcb.reset_time_slice();
                pcb.reset_wait_ticks();
                let mem_space = pcb.memory_space;
                drop(pcb);
                // Remove from source queue
                if let Some(bucket) = guard.get_mut(&priority) {
                    bucket.remove(&pid);
                    if bucket.is_empty() {
                        guard.remove(&priority);
                    }
                }
                drop(guard);
                return Some((pid, proc_arc.clone(), mem_space, priority));
            } else {
                candidate = Self::select_next_locked(&guard, Some(pid));
            }
        }
        None
    }

    /// Periodic load balancing (only run on CPU0 to reduce contention)
    fn maybe_balance() {
        if current_cpu_id() != 0 {
            return;
        }
        let tick = BALANCE_TICKER.fetch_add(1, Ordering::Relaxed) + 1;
        if tick % LOAD_BALANCE_INTERVAL_TICKS != 0 {
            return;
        }
        Self::balance_queues();
    }

    /// Migrate a ready task from the busiest CPU to the idlest CPU
    fn balance_queues() {
        let cpu_count = Self::cpu_pool_size();
        if cpu_count < 2 {
            return;
        }

        let mut lengths = Vec::with_capacity(cpu_count);
        for cpu_id in 0..cpu_count {
            lengths.push(Self::queue_len_for_cpu(cpu_id));
        }

        let mut busiest = None;
        let mut busiest_len = 0usize;
        let mut idlest = None;
        let mut idlest_len = usize::MAX;
        for (cpu_id, len) in lengths.into_iter().enumerate() {
            if len > busiest_len {
                busiest_len = len;
                busiest = Some(cpu_id);
            }
            if len < idlest_len {
                idlest_len = len;
                idlest = Some(cpu_id);
            }
        }

        if let (Some(src), Some(dst)) = (busiest, idlest) {
            if src != dst && busiest_len > idlest_len + LOAD_IMBALANCE_THRESHOLD {
                Self::migrate_one_ready(src, dst);
            }
        }
    }

    /// Migrate one ready process from source to destination CPU
    ///
    /// # R69-3 FIX: Respect CPU Affinity Mask
    ///
    /// Before migrating, checks if the destination CPU is in the task's allowed_cpus
    /// mask. If not permitted, the task is put back in the source queue and migration
    /// is skipped. This prevents violating user-configured CPU placement constraints.
    fn migrate_one_ready(src_cpu: usize, dst_cpu: usize) {
        let Some(src_queue) = Self::ready_queue_for_cpu(src_cpu) else {
            return;
        };

        let candidate = {
            let mut guard = src_queue.lock();
            Self::pop_ready_process(&mut guard)
        };

        if let Some((pid, pcb, priority)) = candidate {
            // R69-3 FIX: Check CPU affinity before migration
            let allowed_cpus = {
                let mut proc = pcb.lock();
                proc.state = ProcessState::Ready;
                proc.reset_wait_ticks();
                proc.allowed_cpus
            };

            // Check if destination CPU is allowed
            // allowed_cpus == 0 means "use default" (all CPUs allowed)
            // allowed_cpus != 0 is a bitmask where bit N means CPU N is allowed
            if allowed_cpus != 0 && (dst_cpu >= 64 || (allowed_cpus & (1u64 << dst_cpu)) == 0) {
                // Destination CPU not in affinity mask, put task back
                let mut src_guard = src_queue.lock();
                src_guard.entry(priority).or_default().insert(pid, pcb);
                return;
            }

            let target =
                Self::ready_queue_for_cpu(dst_cpu).unwrap_or_else(|| Self::current_ready_queue());
            let mut dst_guard = target.lock();
            dst_guard.entry(priority).or_default().insert(pid, pcb);
        }
    }

    /// Select next process from local queue or via work stealing
    fn select_next_process(
        current_pid: Option<Pid>,
    ) -> (
        Option<Pid>,
        Option<ProcessControlBlock>,
        Option<ProcessControlBlock>,
        usize,
    ) {
        let queue_ref = Self::current_ready_queue();
        let queue = queue_ref.lock();
        let current_proc = current_pid.and_then(|pid| Self::find_pcb(&queue, pid));

        let mut candidate = Self::select_next_locked(&queue, current_pid);
        let mut claimed_proc = None;
        let mut claimed_memory_space = 0usize;

        if let Some(pid) = candidate {
            if Some(pid) != current_pid {
                if let Some(proc_arc) = Self::find_pcb(&queue, pid) {
                    let mut pcb = proc_arc.lock();
                    if pcb.state == ProcessState::Ready {
                        pcb.state = ProcessState::Running;
                        pcb.reset_time_slice();
                        pcb.reset_wait_ticks();
                        claimed_memory_space = pcb.memory_space;
                        drop(pcb);
                        claimed_proc = Some(proc_arc.clone());
                    } else {
                        candidate = None;
                    }
                } else {
                    candidate = None;
                }
            }
        }

        drop(queue);

        // If local queue had nothing, try work stealing
        if candidate.is_none() {
            if let Some((pid, proc_arc, mem_space, priority)) = Self::steal_one(current_pid) {
                // Add stolen process to local queue
                let mut queue = queue_ref.lock();
                queue.entry(priority).or_default().insert(pid, proc_arc.clone());
                return (Some(pid), current_proc, Some(proc_arc), mem_space);
            }
        }

        (candidate, current_proc, claimed_proc, claimed_memory_space)
    }

    // ========================================================================
    // 公开 API
    // ========================================================================

    /// 添加进程到就绪队列
    ///
    /// R69-1 FIX: Uses load-aware CPU placement. The process is added to the
    /// least-loaded CPU's queue to balance work across cores.
    ///
    /// R70-2 FIX: Kicks idle CPUs when new work is added so they can pick it up
    /// immediately rather than waiting for the next timer tick.
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn add_process(pcb: ProcessControlBlock) {
        interrupts::without_interrupts(|| {
            let (pid, priority, allowed_cpus) = {
                let mut proc = pcb.lock();
                proc.state = ProcessState::Ready;
                (proc.pid, proc.dynamic_priority, proc.allowed_cpus)
            };
            // R70-2 FIX: Pass affinity mask to target selection
            let target_cpu = Self::target_cpu_for_new_work(current_cpu_id(), allowed_cpus);
            sched_debug!(
                "[SCHED] add_process: pid={}, priority={}, target_cpu={}",
                pid,
                priority,
                target_cpu
            );

            // Remove from all queues first (prevent duplicates across CPUs)
            Self::remove_from_all_queues(pid);

            // R70-2 FIX: Check if target CPU's queue was empty before enqueue
            let target_was_idle = Self::ready_queue_for_cpu(target_cpu)
                .map(|q| q.lock().is_empty())
                .unwrap_or(false);

            // Add to target CPU's queue
            Self::enqueue_on_cpu(pcb, priority, target_cpu);

            {
                let mut stats = SCHEDULER_STATS.lock();
                stats.processes_created += 1;
            }

            // R70-7: Kick target CPU to pick up new work immediately.
            // Fixed: R70-4 (context shadow buffer) + R70-5 (AP stack allocation)
            // resolved the double fault issue.
            if target_was_idle
                && target_cpu != current_cpu_id()
                && Self::cpu_allowed(target_cpu, allowed_cpus)
            {
                Self::kick_cpu(target_cpu);
            }
        });
    }

    /// 移除进程
    ///
    /// R69-1 FIX: Removes process from all per-CPU queues.
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid) {
        interrupts::without_interrupts(|| {
            Self::remove_from_all_queues(pid);

            let mut stats = SCHEDULER_STATS.lock();
            stats.processes_terminated += 1;
        });
    }

    /// 恢复被暂停的进程（用于 SIGCONT）
    ///
    /// R69-1 FIX: Uses load-aware CPU placement for resumed processes.
    ///
    /// R70-2 FIX: Kicks idle CPUs when a process resumes so they can pick it up
    /// immediately rather than waiting for the next timer tick.
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
                let (should_add, priority, allowed_cpus) = {
                    let mut proc = pcb.lock();
                    if proc.state == ProcessState::Stopped {
                        proc.state = ProcessState::Ready;
                        (true, proc.dynamic_priority, proc.allowed_cpus)
                    } else {
                        (false, 0, 0)
                    }
                };

                if should_add {
                    // R70-2 FIX: Pass affinity mask to target selection
                    let target_cpu = Self::target_cpu_for_new_work(current_cpu_id(), allowed_cpus);
                    Self::remove_from_all_queues(pid);

                    // R70-2 FIX: Check if target CPU's queue was empty before enqueue
                    let target_was_idle = Self::ready_queue_for_cpu(target_cpu)
                        .map(|q| q.lock().is_empty())
                        .unwrap_or(false);

                    Self::enqueue_on_cpu(pcb, priority, target_cpu);

                    // R70-7: Kick target CPU to pick up resumed work immediately.
                    // Fixed: R70-4 (context shadow buffer) + R70-5 (AP stack allocation)
                    // resolved the double fault issue.
                    if target_was_idle
                        && target_cpu != current_cpu_id()
                        && Self::cpu_allowed(target_cpu, allowed_cpus)
                    {
                        Self::kick_cpu(target_cpu);
                    }

                    return true;
                }
            }
            false
        })
    }

    /// 选择下一个要运行的进程
    ///
    /// R69-1 FIX: Uses current CPU's queue.
    pub fn select_next() -> Option<Pid> {
        interrupts::without_interrupts(|| {
            let queue = Self::current_ready_queue();
            let queue = queue.lock();
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
    ///
    /// # R69-1 FIX: Per-CPU Queues
    ///
    /// Uses current CPU's ready queue for time slice management.
    pub fn on_clock_tick() {
        // 使用 without_interrupts 确保在持有锁期间不会被嵌套中断打断
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Use per-CPU current process
            let current_pid = Self::get_current();
            // R69-1 FIX: Use current CPU's ready queue
            let ready_queue = Self::current_ready_queue();

            // 获取当前进程的 Arc 引用并更新时间片
            if let Some(pcb) = {
                let queue = ready_queue.lock();
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
                let queue = ready_queue.lock();
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

            // R69-1 FIX: Periodic load balancing (only on CPU0)
            Self::maybe_balance();
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
    /// # R68-3 FIX: Atomic State Transition
    ///
    /// State transition from Ready to Running is now done atomically within the
    /// queue lock to prevent two CPUs from selecting the same process. If another
    /// CPU has already claimed the selected process (state != Ready), we re-select.
    ///
    /// # R69-1 FIX: Per-CPU Run Queues with Work Stealing
    ///
    /// Uses per-CPU ready queues to reduce lock contention. If the local queue is
    /// empty, attempts to steal a ready process from another CPU's queue.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn schedule() -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Clear this CPU's reschedule flag
            current_cpu().need_resched.store(false, Ordering::SeqCst);

            // R67-4 FIX: Use per-CPU current process
            let current_pid = Self::get_current();
            sched_debug!("[SCHED] schedule: current_pid={:?}", current_pid);

            // R69-1 FIX: Use select_next_process which handles per-CPU queues and work stealing
            let (next_pid, current_proc, _next_proc, next_memory_space) =
                Self::select_next_process(current_pid);

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

                    // R68-3: State transition already done inside the lock above
                    // next_proc and next_memory_space are already set

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
    /// R69-1 FIX: Uses current CPU's ready queue.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn yield_cpu() -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            if let Some(pid) = Self::get_current() {
                if let Some(pcb) = {
                    let queue = Self::current_ready_queue();
                    let queue = queue.lock();
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
    ///
    /// R69-1 FIX: Sums across all per-CPU queues.
    pub fn process_count() -> usize {
        interrupts::without_interrupts(|| {
            let mut total = 0;
            let cpu_count = Self::cpu_pool_size();
            for cpu_id in 0..cpu_count {
                if let Some(queue) = Self::ready_queue_for_cpu(cpu_id) {
                    total += Self::queue_len(&queue.lock());
                }
            }
            total
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
    /// # R69-3 FIX: Preemptibility Check
    ///
    /// Checks if preemption is allowed (irq_count and preempt_count must be zero).
    /// If not preemptible, defers the reschedule by setting need_resched flag.
    ///
    /// **警告**: 此函数可能不会返回（如果发生上下文切换）
    pub fn reschedule_now(force: bool) {
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Check and clear this CPU's need_resched flag
            if !force && !current_cpu().clear_need_resched() {
                return;
            }

            // R69-3 FIX: Check if we can preempt (not in IRQ context, preemption enabled)
            // If not preemptible, set need_resched and defer until a safe point
            if !current_cpu().preemptible() {
                current_cpu().set_need_resched();
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

            // R69-2 FIX: Save lazy FPU state before context switch.
            //
            // The lazy FPU implementation tracks FPU owner per-CPU. When a task is
            // switched out, we must save its FPU state and clear ownership to prevent:
            // 1. Cross-CPU stale state: If task migrates to CPU1, CPU0 still thinks
            //    it owns the task's FPU. New task on CPU0 would overwrite migrated
            //    task's FPU state in its PCB.
            // 2. State corruption: Migrated task's current FPU work on CPU1 would
            //    be clobbered when next #NM occurs on CPU0.
            //
            // By saving and clearing before switch, each CPU starts fresh and
            // migrations always restore from saved PCB state via #NM handler.
            if let Some(opid) = old_pid {
                let per_cpu = current_cpu();
                let owner = per_cpu.get_fpu_owner();
                if owner != NO_FPU_OWNER && owner == opid {
                    if let Some(proc_arc) = process::get_process(opid) {
                        let mut pcb = proc_arc.lock();
                        // R69-2 FIX (codex review): Clear CR0.TS before fxsave64.
                        //
                        // Under lazy FPU, CR0.TS may be set if the task never touched
                        // FPU since its last switch-in. Executing fxsave64 with TS=1
                        // would trigger #NM fault inside reschedule_now (with IF=0),
                        // causing re-entry into lazy-FPU handler and potential panic.
                        //
                        // By clearing TS first, we ensure fxsave64 can safely execute.
                        // After the context switch, the next task will have TS set by
                        // switch_context() to enable lazy FPU for the new task.
                        unsafe {
                            use x86_64::registers::control::{Cr0, Cr0Flags};
                            let cr0 = Cr0::read();
                            if cr0.contains(Cr0Flags::TASK_SWITCHED) {
                                let mut new_cr0 = cr0;
                                new_cr0.remove(Cr0Flags::TASK_SWITCHED);
                                Cr0::write(new_cr0);
                            }
                        }
                        // Save current FPU hardware state to PCB
                        let fx_ptr = pcb.context.fx.data.as_mut_ptr();
                        unsafe {
                            core::arch::asm!("fxsave64 [{}]", in(reg) fx_ptr, options(nostack));
                        }
                        pcb.fpu_used = true;
                    }
                    // Clear ownership so this CPU doesn't claim stale state
                    per_cpu.set_fpu_owner(NO_FPU_OWNER);
                }
            }

            // 获取新进程的上下文指针、内核栈顶、CS（用于判断 Ring 3）和 FS/GS base（TLS）
            // R70-4 FIX: Copy context to per-CPU shadow buffer to prevent use-after-unlock.
            // The PCB lock is released at the end of the closure, but we use the shadow
            // buffer's stable pointer for enter_usermode/switch_context.
            let (new_ctx_ptr, next_kstack_top, next_cs, next_fs_base, next_gs_base): (
                *const ArchContext,
                u64,
                u64,
                u64,
                u64,
            ) = NEXT_CONTEXT_SHADOW.with(|shadow| {
                let guard = next_pcb.lock();
                // Copy full context (176 bytes + FPU) to per-CPU shadow while holding lock
                let ctx_ptr = shadow.store(&guard.context);
                let kstack_top = guard.kernel_stack_top.as_u64();
                let cs = guard.context.cs;
                let fs_base = guard.fs_base;
                let gs_base = guard.gs_base;
                (ctx_ptr, kstack_top, cs, fs_base, gs_base)
            });

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
    println!("  Ready queue: per-CPU with work stealing (R69-1)");
    println!("  Scheduling algorithm: Priority-based with time slice");
    println!("  SMP kick: IPI wake on new work (R70-2)");
    println!("  Context switch: Enabled with CR3 switching + Ring 3 IRETQ support");
}
