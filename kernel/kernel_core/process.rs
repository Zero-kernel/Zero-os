use crate::fork::PAGE_REF_COUNT;
use crate::signal::PendingSignals;
use crate::syscall::{SyscallError, VfsStat};
use crate::time;
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use cap::CapTable;
use core::any::Any;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use lsm::ProcessCtx as LsmProcessCtx; // R25-7 FIX: Import LSM for task_exit hook
use mm::memory::FrameAllocator;
use mm::page_table;
use seccomp::{PledgeState, SeccompState};
use spin::{Mutex, RwLock};
// G.1 Observability: Watchdog integration for hung-task detection
use trace::watchdog::{register_watchdog, unregister_watchdog, WatchdogConfig, WatchdogHandle};
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

/// 进程ID类型
pub type ProcessId = usize;

/// 进程优先级（0-139，数值越小优先级越高）
pub type Priority = u8;

/// E.4 Priority Inheritance: Futex 键 (tgid, uaddr)
///
/// Used for tracking which futex a task is waiting on (for transitive PI)
/// and as keys in the PI boost map.
pub type FutexKey = (ProcessId, usize);

/// mmap 默认起始地址
const DEFAULT_MMAP_BASE: usize = 0x4000_0000;

/// 页大小
const PAGE_SIZE: u64 = 0x1000;

/// 每进程内核栈基址（PML4[511]/PDPT[508]，在共享内核空间内）
pub const KSTACK_BASE: u64 = 0xFFFF_FFFF_0000_0000;

/// 每进程内核栈步长（16KB 栈 + 4KB 守护页 = 20KB）
pub const KSTACK_STRIDE: u64 = 0x5000;

/// 内核栈页数（16KB = 4 页）
const KSTACK_PAGES: usize = 4;

/// 守护页数
const KSTACK_GUARD_PAGES: usize = 1;

/// G.1: Default watchdog timeout for hung-task detection (10 seconds).
///
/// If a task hasn't been scheduled (heartbeat) for this duration, it will
/// trigger the hung_task tracepoint. 10s is a reasonable default that catches
/// true hangs while allowing normal blocking operations.
const WATCHDOG_TIMEOUT_MS: u64 = 10_000;

/// 调度器清理回调类型
type SchedulerCleanupCallback = fn(ProcessId);

/// IPC清理回调类型
/// R37-2 FIX (Codex review): Pass both PID and TGID to avoid deadlock.
/// The callback is called from free_process_resources which already holds the process lock,
/// so the callback must not try to lock the process again.
/// R75-2 FIX: Also pass IPC namespace ID for per-namespace endpoint cleanup.
type IpcCleanupCallback = fn(ProcessId, ProcessId, cap::NamespaceId); // (pid, tgid, ipc_ns_id)

/// 调度器添加进程回调类型
///
/// clone/fork 创建新进程后调用，将进程添加到调度队列
pub type SchedulerAddCallback = fn(Arc<Mutex<Process>>);

/// Futex 唤醒回调类型
///
/// 线程退出时调用，唤醒等待在 clear_child_tid 地址上的进程
/// 参数: (tgid, uaddr, max_wake_count) -> 实际唤醒数量
pub type FutexWakeCallback = fn(ProcessId, usize, usize) -> usize;

/// E.5 Cpuset: Callback for task joining a cpuset
///
/// Called when a new process is created (fork/clone) to update cpuset task count.
/// Parameter: cpuset_id (u32)
pub type CpusetTaskJoinedCallback = fn(u32);

/// E.5 Cpuset: Callback for task leaving a cpuset
///
/// Called when a process exits to update cpuset task count.
/// Parameter: cpuset_id (u32)
pub type CpusetTaskLeftCallback = fn(u32);

/// 最大文件描述符数量（每进程）
pub const MAX_FD: i32 = 256;

/// 文件操作 trait
///
/// 定义文件描述符必须实现的操作，支持：
/// - 克隆（用于 fork）
/// - 向下转型（用于类型特定操作）
/// - 调试输出
///
/// 由于循环依赖限制，kernel_core 定义此 trait，具体类型（如 PipeHandle）
/// 在各自的 crate（如 ipc）中实现。
pub trait FileOps: Send + Sync {
    /// 克隆此文件描述符（用于 fork）
    fn clone_box(&self) -> Box<dyn FileOps>;

    /// 获取 Any 引用用于向下转型
    fn as_any(&self) -> &dyn Any;

    /// 获取类型名称（用于调试）
    fn type_name(&self) -> &'static str;

    /// R41-1 FIX: 获取文件状态信息（用于 fstat）
    ///
    /// 默认返回 EBADF，子类型应覆盖此方法返回正确的元数据。
    /// FileHandle、Ext2File 应返回 inode 元数据，
    /// PipeHandle 应返回 S_IFIFO 模式。
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Err(SyscallError::EBADF)
    }
}

impl core::fmt::Debug for dyn FileOps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileOps({})", self.type_name())
    }
}

/// 文件描述符类型
pub type FileDescriptor = Box<dyn FileOps>;

/// 内核栈分配错误
#[derive(Debug, Clone, Copy)]
pub enum KernelStackError {
    /// 栈地址已被映射（PID 复用时可能发生）
    AlreadyMapped,
    /// 物理内存分配失败
    AllocationFailed,
    /// 页表映射失败
    MapFailed,
    /// R103-I2 FIX: 地址计算溢出（PID 超出内核栈地址空间范围）
    AddressOverflow,
}

/// 进程创建错误
///
/// SECURITY FIX Z-7: 进程创建失败时必须正确报告错误，而非静默回退
#[derive(Debug, Clone, Copy)]
pub enum ProcessCreateError {
    /// 内核栈分配失败
    KernelStackAllocFailed(KernelStackError),
    /// R29-5 FIX: PID 空间耗尽（内核栈地址空间溢出）
    PidExhausted,
    /// F.1: PID namespace chain assignment failed
    NamespaceError,
}

/// R29-5 FIX: Maximum PID before kernel stack address overflow
///
/// Each process gets a kernel stack at KSTACK_BASE + pid * KSTACK_STRIDE.
/// After this many PIDs, new stacks would overflow into other kernel memory.
/// Calculation: (u64::MAX - KSTACK_BASE) / KSTACK_STRIDE ≈ 209,715
pub const MAX_PID: ProcessId = ((u64::MAX - KSTACK_BASE) / KSTACK_STRIDE) as ProcessId;

/// R106-11 (P0-4): User-visible PID upper bound (Linux default: 32768).
///
/// Bounded separately from `MAX_PID` (kernel stack address space limit) so PID
/// recycling keeps the process table bounded and prevents PID exhaustion under
/// fork/exit churn. Valid PIDs are in [1, PID_MAX].
pub const PID_MAX: ProcessId = 32_768;

/// 计算指定 PID 的内核栈虚拟地址范围
///
/// 返回 Ok((栈底, 栈顶))，栈向下生长，栈顶用于 TSS.rsp0
///
/// # R103-I2 FIX
///
/// Returns `Err(KernelStackError::AddressOverflow)` instead of panicking
/// when the PID causes address arithmetic to overflow.  Although current
/// callers validate `pid <= MAX_PID`, this function is `pub` and future
/// call sites might not enforce the bound.  Returning `Result` makes the
/// contract explicit and prevents kernel panics from propagating.
#[inline]
pub fn kernel_stack_slot(pid: ProcessId) -> Result<(VirtAddr, VirtAddr), KernelStackError> {
    // R102-8 FIX: Use checked arithmetic to prevent silent wrapping on invalid PID.
    // R103-I2 FIX: Propagate overflow as error instead of panicking.
    let slot_offset = (pid as u64)
        .checked_mul(KSTACK_STRIDE)
        .ok_or(KernelStackError::AddressOverflow)?;
    let guard_base_addr = KSTACK_BASE
        .checked_add(slot_offset)
        .ok_or(KernelStackError::AddressOverflow)?;

    let guard_bytes = KSTACK_GUARD_PAGES as u64 * PAGE_SIZE; // compile-time constant, safe
    let stack_base_addr = guard_base_addr
        .checked_add(guard_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;

    let stack_bytes = KSTACK_PAGES as u64 * PAGE_SIZE; // compile-time constant, safe
    let stack_top_addr = stack_base_addr
        .checked_add(stack_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;

    Ok((VirtAddr::new(stack_base_addr), VirtAddr::new(stack_top_addr)))
}

/// 为指定 PID 分配并映射带守护页的内核栈
///
/// 在共享的内核页表上映射，所有进程地址空间均可见。
/// 守护页不映射物理帧，访问时会触发页错误。
///
/// # Returns
///
/// 成功返回 (栈底, 栈顶)，失败返回错误
pub fn allocate_kernel_stack(pid: ProcessId) -> Result<(VirtAddr, VirtAddr), KernelStackError> {
    let (stack_base, stack_top) = kernel_stack_slot(pid)?;
    // R103-I2 FIX: Derive guard_base from stack_base using checked arithmetic
    // instead of the previous unchecked `KSTACK_BASE + pid as u64 * KSTACK_STRIDE`.
    let guard_bytes = KSTACK_GUARD_PAGES as u64 * PAGE_SIZE;
    let guard_base_addr = stack_base
        .as_u64()
        .checked_sub(guard_bytes)
        .ok_or(KernelStackError::AddressOverflow)?;
    let guard_base = VirtAddr::new(guard_base_addr);

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            // 检查整个 slot（守护页 + 栈页）是否已被映射
            let total_pages = KSTACK_PAGES + KSTACK_GUARD_PAGES;
            for i in 0..total_pages {
                let addr = guard_base + (i as u64 * PAGE_SIZE);
                if mgr.translate_addr(addr).is_some() {
                    return Err(KernelStackError::AlreadyMapped);
                }
            }

            // 分配连续物理帧
            let phys_start = frame_alloc
                .allocate_contiguous_frames(KSTACK_PAGES)
                .ok_or(KernelStackError::AllocationFailed)?
                .start_address();

            // 内核栈页标志：可写、不可执行、全局（跨 CR3 有效）
            let flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::GLOBAL;

            // 映射栈页（守护页不映射，自动触发页错误）
            let stack_size = (KSTACK_PAGES as u64 * PAGE_SIZE) as usize;
            mgr.map_range(stack_base, phys_start, stack_size, flags, &mut frame_alloc)
                .map_err(|_| KernelStackError::MapFailed)?;

            // 清零栈区域
            core::ptr::write_bytes(stack_base.as_mut_ptr::<u8>(), 0, stack_size);

            Ok((stack_base, stack_top))
        })
    }
}

/// 进程状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 就绪状态，等待被调度
    Ready,
    /// 运行状态
    Running,
    /// 阻塞状态（等待I/O或其他事件）
    Blocked,
    /// 暂停状态（如 SIGSTOP）
    Stopped,
    /// 睡眠状态
    Sleeping,
    /// 僵尸状态（已终止但未被父进程回收）
    Zombie,
    /// 已终止
    Terminated,
}

/// FXSAVE 区域大小（512 字节）
const FXSAVE_SIZE: usize = 512;

/// 512 字节的 FXSAVE/FXRSTOR 区域
/// 按 64 字节对齐以兼容 XSAVE 路径
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub data: [u8; FXSAVE_SIZE],
}

impl core::fmt::Debug for FxSaveArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FxSaveArea").finish_non_exhaustive()
    }
}

impl Default for FxSaveArea {
    fn default() -> Self {
        let mut area = FxSaveArea {
            data: [0; FXSAVE_SIZE],
        };
        // 设置默认的 FCW（FPU Control Word）：双精度、所有异常屏蔽
        area.data[0] = 0x7F;
        area.data[1] = 0x03;
        // 设置默认的 MXCSR（SSE Control/Status）：所有异常屏蔽
        area.data[24] = 0x80;
        area.data[25] = 0x1F;
        area
    }
}

/// CPU上下文（用于进程切换）
///
/// 包含通用寄存器和 FPU/SIMD 状态，与 arch::Context 布局一致
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct Context {
    // 通用寄存器 (偏移 0x00 - 0x7F)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // 指令指针和标志 (偏移 0x80 - 0x8F)
    pub rip: u64,
    pub rflags: u64,

    // 段寄存器 (偏移 0x90 - 0x9F)
    pub cs: u64,
    pub ss: u64,

    // 填充以对齐 FxSaveArea 到 64 字节边界 (偏移 0xA0 - 0xBF)
    _padding: [u64; 4],

    /// FPU/SIMD 保存区 (偏移 0xC0)
    pub fx: FxSaveArea,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202, // IF (中断使能) 位设置
            cs: 0x08,      // 内核代码段
            ss: 0x10,      // 内核数据段
            _padding: [0; 4],
            fx: FxSaveArea::default(),
        }
    }
}

/// 进程控制块（PCB）
///
/// 注意：Process 不实现 Clone，因为 fd_table 包含不可克隆的 Box<dyn FileOps>。
/// 进程复制（fork）通过手动字段复制和 clone_box() 实现。
///
/// # 线程模型
///
/// 在 CLONE_THREAD 模式下，多个 Process 结构体共享同一个 tgid（线程组ID）。
/// - pid: 唯一标识符（Linux 中称为 task）
/// - tid: 等于 pid（Linux 语义）
/// - tgid: 线程组ID（主线程的 pid，所有线程共享）
/// - is_thread: true 表示由 CLONE_THREAD 创建
#[derive(Debug)]
pub struct Process {
    /// 进程ID（唯一标识，也是 Linux 语义中的 tid）
    pub pid: ProcessId,

    /// R106-1 FIX: 进程代际（monotonic generation counter）。
    ///
    /// 每个进程实例获得一个全局唯一、单调递增的 generation 值。
    /// 当 PID 被回收并分配给新进程时，新进程的 generation 不同于旧进程，
    /// 从而防止 IPC allowed_senders 等基于 PID 的授权被新进程继承。
    pub generation: u64,

    /// 线程ID（等于 pid，保持 Linux 兼容性）
    pub tid: ProcessId,

    /// 线程组ID（主线程时等于 pid，子线程时等于主线程的 pid）
    pub tgid: ProcessId,

    /// 父进程ID
    pub ppid: ProcessId,

    /// 是否为线程（由 CLONE_THREAD 创建）
    pub is_thread: bool,

    /// 进程名称
    pub name: String,

    /// 进程状态
    pub state: ProcessState,

    /// R98-1 FIX: 作业控制停止标志（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）。
    ///
    /// 与 `state` 正交：进程可以同时处于 Blocked/Sleeping 且被 job-control 停止。
    /// 当 `stopped == true` 时，调度器不会选择该进程运行，但其等待队列位置不变，
    /// 避免 SIGSTOP 覆盖 Blocked 状态导致丢失唤醒（H-34）。
    pub stopped: bool,

    /// 挂起的信号位图（1-64）
    pub pending_signals: PendingSignals,

    /// 进程优先级（静态优先级）
    pub priority: Priority,

    /// 动态优先级（用于调度）
    pub dynamic_priority: Priority,

    /// E.4 Priority Inheritance: 未应用 PI 的动态优先级基线
    ///
    /// When priority inheritance is active, `dynamic_priority` becomes the effective
    /// priority (min of base and all PI boosts). This field stores the original
    /// priority before any PI modifications were applied.
    pub base_dynamic_priority: Priority,

    /// E.4 Priority Inheritance: 当前的 futex PI 捐赠 (key -> 最高等待者优先级)
    ///
    /// When this task holds a futex and high-priority waiters are blocked on it,
    /// those waiters' priorities are recorded here. The effective priority is
    /// computed as min(base_dynamic_priority, min(all pi_boosts values)).
    pub pi_boosts: BTreeMap<FutexKey, Priority>,

    /// E.4 Priority Inheritance: 如果阻塞在 futex 上，记录等待的 futex key
    ///
    /// Used for transitive priority inheritance: if A waits on B, and B waits on C,
    /// then A's priority should propagate through to C.
    pub waiting_on_futex: Option<FutexKey>,

    /// 时间片（剩余时间片，单位：毫秒）
    pub time_slice: u32,

    /// CPU上下文
    pub context: Context,

    /// Has this process ever used FPU/SIMD (lazy FPU tracking).
    ///
    /// When false, the FPU state in `context.fx` is default-initialized and
    /// has never been saved from hardware. When true, the state was saved by
    /// the #NM handler and should be restored on next FPU use.
    /// This enables lazy FPU save/restore to skip processes that never use FPU.
    pub fpu_used: bool,

    /// 内核栈指针（栈底）
    pub kernel_stack: VirtAddr,

    /// 内核栈顶（用于 TSS.rsp0）
    pub kernel_stack_top: VirtAddr,

    /// 用户栈指针（如果是用户进程）
    pub user_stack: Option<VirtAddr>,

    /// 内存空间（页表基址）
    pub memory_space: usize,

    /// mmap 区域跟踪 (起始地址 -> 长度)
    pub mmap_regions: BTreeMap<usize, usize>,

    /// 下一个自动分配的 mmap 起始地址
    pub next_mmap_addr: usize,

    /// 文件描述符表（fd -> 描述符）
    ///
    /// fd 0/1/2 分别保留给 stdin/stdout/stderr，新分配从 3 开始
    pub fd_table: BTreeMap<i32, FileDescriptor>,

    /// R39-4 FIX: 带 FD_CLOEXEC 标记的文件描述符集合
    ///
    /// exec 时会关闭这些 fd，防止敏感句柄泄漏到新程序
    pub cloexec_fds: BTreeSet<i32>,

    /// 能力表（Capability Table，管理进程持有的能力）
    ///
    /// 每个进程拥有独立的能力表。能力表中的条目（CapEntry）包含：
    /// - 对内核对象（文件、端点、Socket 等）的引用
    /// - 权限掩码（只读、读写、执行等）
    /// - 标志（CLOEXEC、CLOFORK 等）
    ///
    /// 使用 Arc 包装以支持 fork 时的高效克隆。
    pub cap_table: Arc<CapTable>,

    /// 退出码
    pub exit_code: Option<i32>,

    /// 等待的子进程（Some(0) 表示等待任意子进程，Some(pid) 表示等待特定子进程）
    pub waiting_child: Option<ProcessId>,

    /// 子进程列表
    pub children: Vec<ProcessId>,

    /// CPU时间统计（毫秒）
    pub cpu_time: u64,

    /// R65-19 FIX: 等待时间计数器（调度器tick数）
    ///
    /// 跟踪进程在就绪队列中等待的时间。当等待时间超过阈值时，
    /// 调度器会提升进程的动态优先级，防止低优先级进程饥饿。
    /// 每次进程被调度运行时重置为0。
    pub wait_ticks: u64,

    /// CPU亲和性位掩码（bit N = 允许在CPU N上运行）
    ///
    /// 用于SMP调度，限制进程可以运行的CPU集合。
    /// 默认值：0xFFFFFFFFFFFFFFFF（允许在所有CPU上运行）
    /// 位0对应CPU 0，位1对应CPU 1，以此类推。
    pub allowed_cpus: u64,

    /// Cpuset ID for CPU isolation.
    ///
    /// Tasks are restricted to CPUs in their cpuset's mask.
    /// Effective affinity = online_mask ∩ cpuset_mask ∩ allowed_cpus.
    /// Default: CpusetId(0) = root cpuset (all CPUs).
    pub cpuset_id: u32,

    /// 创建时间戳
    pub created_at: u64,

    // ========== 进程凭证 (DAC支持) ==========
    /// R39-3 FIX: 共享凭证结构
    ///
    /// 使用 Arc<RwLock<Credentials>> 实现线程间共享凭证。
    /// CLONE_THREAD 创建的线程共享同一个 Arc，因此 setuid/setgid
    /// 等操作会影响所有同进程的线程（符合 POSIX 语义）。
    /// 普通 fork 会 clone 凭证到新的 Arc。
    pub credentials: Arc<RwLock<Credentials>>,

    /// 文件创建掩码 (umask)
    /// 新建文件的权限 = mode & !umask
    pub umask: u16,

    // ========== OOM Killer 支持 ==========
    /// Nice 值 (-20 到 19)
    /// 负值表示更高优先级，正值表示更低优先级
    /// 对于 OOM killer：nice 值越高越容易被杀
    pub nice: i32,

    /// OOM 分数调整值 (-1000 到 1000)
    /// -1000 表示完全免疫 OOM killer
    /// 正值增加被杀概率，负值降低被杀概率
    pub oom_score_adj: i32,

    // ========== 堆管理 (brk) ==========
    /// 堆起始地址（ELF bss 段末尾，页对齐）
    pub brk_start: usize,

    /// 当前 program break（可能未页对齐）
    pub brk: usize,

    // ========== TLS 支持 ==========
    /// FS segment base (用于 TLS)
    pub fs_base: u64,

    /// GS segment base (保留)
    pub gs_base: u64,

    // ========== 线程支持 (musl 初始化需要) ==========
    /// clear_child_tid 指针 (set_tid_address / CLONE_CHILD_CLEARTID)
    /// 进程退出时内核会将此地址处的值设为 0 并执行 futex_wake
    pub clear_child_tid: u64,

    /// set_child_tid 指针 (CLONE_CHILD_SETTID)
    /// clone 时内核会将子线程 tid 写入此地址
    pub set_child_tid: u64,

    /// robust_list 头指针 (set_robust_list)
    /// 用于 robust futex 机制，进程退出时内核会清理持有的 robust mutex
    pub robust_list_head: u64,

    /// robust_list 长度
    pub robust_list_len: usize,

    // ========== F.1: PID Namespace Support ==========
    /// PID namespace membership chain (root -> owning namespace)
    ///
    /// Each entry contains the namespace and the PID as seen from that namespace.
    /// The last entry is the owning (leaf) namespace where the process was created.
    /// Root namespace (level 0) uses global PID directly.
    pub pid_ns_chain: Vec<crate::pid_namespace::PidNamespaceMembership>,

    /// PID namespace for children
    ///
    /// When CLONE_NEWPID is used, children are created in a new child namespace.
    /// Otherwise, children inherit this namespace (same as parent's owning namespace).
    pub pid_ns_for_children: Arc<crate::pid_namespace::PidNamespace>,

    // ========== F.1: Mount Namespace Support ==========
    /// Mount namespace of this process
    ///
    /// All path resolution and mount operations are confined to this namespace.
    /// CLONE_THREAD keeps the same mount namespace; CLONE_NEWNS creates a copy.
    pub mount_ns: Arc<crate::mount_namespace::MountNamespace>,

    /// Mount namespace for children (set by CLONE_NEWNS)
    ///
    /// Children inherit this namespace unless CLONE_NEWNS is requested,
    /// in which case a new namespace copy is created for them.
    pub mount_ns_for_children: Arc<crate::mount_namespace::MountNamespace>,

    // ========== F.1: IPC Namespace Support ==========
    /// IPC namespace of this process
    ///
    /// All IPC resources (message queues, semaphores, shared memory) are
    /// confined to this namespace. CLONE_NEWIPC creates an isolated namespace.
    pub ipc_ns: Arc<crate::ipc_namespace::IpcNamespace>,

    /// IPC namespace for children (set by CLONE_NEWIPC)
    pub ipc_ns_for_children: Arc<crate::ipc_namespace::IpcNamespace>,

    // ========== F.1: Network Namespace Support ==========
    /// Network namespace of this process
    ///
    /// All network operations (sockets, interfaces, routing) are confined
    /// to this namespace. CLONE_NEWNET creates an isolated namespace.
    pub net_ns: Arc<crate::net_namespace::NetNamespace>,

    /// Network namespace for children (set by CLONE_NEWNET)
    pub net_ns_for_children: Arc<crate::net_namespace::NetNamespace>,

    // ========== F.1: User Namespace Support ==========
    /// User namespace of this process
    ///
    /// Provides UID/GID virtualization. Inside a user namespace, a process
    /// can appear as root (uid=0) while being unprivileged on the host.
    /// CLONE_NEWUSER creates an isolated namespace with its own UID/GID mappings.
    pub user_ns: Arc<crate::user_namespace::UserNamespace>,

    /// User namespace for children (set by CLONE_NEWUSER)
    pub user_ns_for_children: Arc<crate::user_namespace::UserNamespace>,

    // ========== F.2: Cgroup v2 Support ==========
    /// Cgroup ID this process belongs to.
    ///
    /// Every process is attached to exactly one cgroup. The root cgroup (id=0)
    /// is the default. Cgroup controllers (CPU/Memory/PIDs) enforce resource
    /// limits based on this membership.
    pub cgroup_id: crate::cgroup::CgroupId,

    // ========== Seccomp/Pledge 沙箱 ==========
    /// Seccomp 过滤器状态
    /// 包含 BPF 过滤器栈和 no_new_privs 标志
    pub seccomp_state: SeccompState,

    /// Pledge 状态（可选）
    /// 如果设置，表示进程使用 OpenBSD 风格的 pledge 沙箱
    pub pledge_state: Option<PledgeState>,

    /// R26-3: 标记当前是否正在安装 seccomp 过滤器
    /// 在安装期间拒绝创建新线程，防止 TSYNC 竞态绕过
    pub seccomp_installing: bool,

    // ========== G.1: Observability ==========
    /// Watchdog handle for hung-task detection.
    ///
    /// If set, the scheduler sends heartbeats during context switches.
    /// Unregistered on process termination.
    pub watchdog_handle: Option<WatchdogHandle>,
}

impl Process {
    /// 创建新进程
    ///
    /// 默认以root权限运行（uid=0, gid=0），umask为标准0o022
    pub fn new(pid: ProcessId, ppid: ProcessId, name: String, priority: Priority) -> Self {
        Process {
            pid,
            generation: NEXT_GENERATION.fetch_add(1, Ordering::SeqCst), // lint-fetch-add: allow (generation counter)
            tid: pid,  // tid == pid (Linux 语义)
            tgid: pid, // 主线程时 tgid == pid
            ppid,
            is_thread: false,
            name,
            state: ProcessState::Ready,
            stopped: false, // R98-1 FIX: Job-control stop flag starts cleared
            pending_signals: PendingSignals::new(),
            priority,
            dynamic_priority: priority,
            base_dynamic_priority: priority, // E.4 PI: starts same as dynamic_priority
            pi_boosts: BTreeMap::new(),       // E.4 PI: no boosts initially
            waiting_on_futex: None,           // E.4 PI: not waiting on any futex
            time_slice: calculate_time_slice(priority),
            context: Context::default(),
            fpu_used: false, // Lazy FPU: process hasn't used FPU yet
            kernel_stack: VirtAddr::new(0),
            kernel_stack_top: VirtAddr::new(0),
            user_stack: None,
            memory_space: 0,
            mmap_regions: BTreeMap::new(),
            next_mmap_addr: DEFAULT_MMAP_BASE,
            fd_table: BTreeMap::new(),
            cloexec_fds: BTreeSet::new(),
            cap_table: Arc::new(CapTable::new()),
            exit_code: None,
            waiting_child: None,
            children: Vec::new(),
            cpu_time: 0,
            wait_ticks: 0, // R65-19 FIX: Initialize starvation counter
            allowed_cpus: 0xFFFFFFFFFFFFFFFF, // SMP: Allow on all CPUs by default
            cpuset_id: 0, // Root cpuset (all CPUs)
            created_at: time::current_timestamp_ms(),
            // R101-1 FIX: Default to unprivileged nobody (uid=65534) credentials.
            //
            // Previously all processes started with uid=0 (root), creating a flat
            // privilege model with no defense-in-depth. Now Process::new() uses
            // restricted defaults. Kernel-internal processes (ppid=0) are promoted
            // to root explicitly by create_process(), and fork()/clone() inherit
            // credentials from the parent process via independent clone.
            credentials: Arc::new(RwLock::new(Credentials {
                uid: 65534,
                gid: 65534,
                euid: 65534,
                egid: 65534,
                supplementary_groups: Vec::new(),
            })),
            umask: 0o022,
            // OOM killer 支持 - 默认中立设置
            nice: 0,
            oom_score_adj: 0,
            // 堆管理 - ELF 加载时设置实际值
            brk_start: 0,
            brk: 0,
            // TLS 支持
            fs_base: 0,
            gs_base: 0,
            // 线程支持 (musl 初始化)
            clear_child_tid: 0,
            set_child_tid: 0,
            robust_list_head: 0,
            robust_list_len: 0,
            // F.1: PID namespace - default to root namespace
            // The actual chain will be assigned by create_process after PID allocation
            pid_ns_chain: Vec::new(),
            pid_ns_for_children: crate::pid_namespace::ROOT_PID_NAMESPACE.clone(),
            // F.1: Mount namespace - default to root mount namespace
            // The actual namespace will be assigned by create_process from parent
            mount_ns: crate::mount_namespace::ROOT_MNT_NAMESPACE.clone(),
            mount_ns_for_children: crate::mount_namespace::ROOT_MNT_NAMESPACE.clone(),
            // F.1: IPC namespace - default to root IPC namespace
            ipc_ns: crate::ipc_namespace::ROOT_IPC_NAMESPACE.clone(),
            ipc_ns_for_children: crate::ipc_namespace::ROOT_IPC_NAMESPACE.clone(),
            // F.1: Network namespace - default to root network namespace
            net_ns: crate::net_namespace::ROOT_NET_NAMESPACE.clone(),
            net_ns_for_children: crate::net_namespace::ROOT_NET_NAMESPACE.clone(),
            // F.1: User namespace - default to root user namespace
            // Unlike other namespaces, CLONE_NEWUSER does not require root/CAP_SYS_ADMIN
            user_ns: crate::user_namespace::ROOT_USER_NAMESPACE.clone(),
            user_ns_for_children: crate::user_namespace::ROOT_USER_NAMESPACE.clone(),
            // F.2: Cgroup v2 - default to root cgroup
            cgroup_id: 0,
            // Seccomp/Pledge 沙箱 (默认无限制)
            seccomp_state: SeccompState::new(),
            pledge_state: None,
            // R26-3: seccomp 安装状态标志
            seccomp_installing: false,
            // G.1: Watchdog not registered until process starts running
            watchdog_handle: None,
        }
    }

    /// 分配新的文件描述符
    ///
    /// fd 0/1/2 保留给标准输入/输出/错误，新分配从 3 开始
    ///
    /// # Returns
    ///
    /// 成功返回分配的 fd，失败（达到上限）返回 None
    pub fn allocate_fd(&mut self, desc: FileDescriptor) -> Option<i32> {
        let fd = self.next_available_fd()?;
        self.fd_table.insert(fd, desc);
        Some(fd)
    }

    /// 获取指定 fd 对应的描述符引用
    pub fn get_fd(&self, fd: i32) -> Option<&FileDescriptor> {
        if fd < 0 {
            return None;
        }
        self.fd_table.get(&fd)
    }

    /// 移除并返回指定 fd 的描述符
    ///
    /// 关闭文件描述符时使用，描述符的 Drop 会自动处理资源清理
    /// R39-4 FIX: 同时清除 CLOEXEC 标记
    pub fn remove_fd(&mut self, fd: i32) -> Option<FileDescriptor> {
        if fd < 0 {
            return None;
        }
        self.cloexec_fds.remove(&fd);
        self.fd_table.remove(&fd)
    }

    /// R39-4 FIX: 设置或清除指定 fd 的 FD_CLOEXEC 标记
    ///
    /// # Arguments
    /// * `fd` - 文件描述符
    /// * `cloexec` - true 设置 CLOEXEC，false 清除
    pub fn set_fd_cloexec(&mut self, fd: i32, cloexec: bool) {
        if cloexec {
            self.cloexec_fds.insert(fd);
        } else {
            self.cloexec_fds.remove(&fd);
        }
    }

    /// R39-4 FIX: 在 exec 期间关闭所有带 FD_CLOEXEC 的文件描述符
    ///
    /// SECURITY: 防止敏感句柄（如设备、管道）泄漏到 exec 后的新程序。
    /// 这是 POSIX close-on-exec 语义的实现。
    pub fn apply_fd_cloexec(&mut self) {
        let to_close: Vec<i32> = self.cloexec_fds.iter().copied().collect();
        for fd in to_close {
            self.fd_table.remove(&fd);
        }
        self.cloexec_fds.clear();
    }

    /// 查找下一个可用的 fd（从 3 开始）
    fn next_available_fd(&self) -> Option<i32> {
        // 从 3 开始，因为 0/1/2 保留给标准流
        let mut fd: i32 = 3;
        while fd < MAX_FD {
            if !self.fd_table.contains_key(&fd) {
                return Some(fd);
            }
            fd = fd.checked_add(1)?;
        }
        None // 已达到 fd 上限
    }

    /// 重置时间片
    ///
    /// F.2: Now factors in cgroup cpu_weight for resource governance.
    pub fn reset_time_slice(&mut self) {
        self.time_slice = calculate_time_slice_with_cgroup(self.dynamic_priority, self.cgroup_id);
    }

    // ========================================================================
    // E.4 Priority Inheritance (PI) Methods
    // ========================================================================

    /// E.4 PI: 重新计算包含 PI 的有效优先级
    ///
    /// `dynamic_priority` = min(base_dynamic_priority, min(all pi_boosts))
    /// Returns true if the effective priority changed.
    ///
    /// F.2: Now factors in cgroup cpu_weight when recalculating time slice.
    pub fn recompute_effective_priority(&mut self) -> bool {
        let inherited = self.pi_boosts.values().min().copied();
        let base = self.base_dynamic_priority;
        let effective = inherited.map_or(base, |p| core::cmp::min(p, base));
        if effective != self.dynamic_priority {
            self.dynamic_priority = effective;
            self.time_slice = calculate_time_slice_with_cgroup(self.dynamic_priority, self.cgroup_id);
            true
        } else {
            false
        }
    }

    /// E.4 PI: 应用一次 PI 提升（如果提升更高则更新）
    ///
    /// Called when a high-priority waiter blocks on a futex held by this task.
    /// Returns true if the effective priority changed.
    pub fn apply_pi_boost(&mut self, key: FutexKey, donated: Priority) -> bool {
        let should_update = match self.pi_boosts.get(&key) {
            Some(&existing) => donated < existing, // Lower priority number = higher priority
            None => true,
        };
        if should_update {
            self.pi_boosts.insert(key, donated);
            return self.recompute_effective_priority();
        }
        false
    }

    /// E.4 PI: 清除指定 futex 的 PI 提升
    ///
    /// Called when the futex is released or all waiters leave.
    /// Returns true if the effective priority changed.
    pub fn clear_pi_boost(&mut self, key: &FutexKey) -> bool {
        if self.pi_boosts.remove(key).is_some() {
            return self.recompute_effective_priority();
        }
        false
    }

    /// E.4 PI: 记录 / 清除当前等待的 futex（用于链式 PI）
    pub fn set_waiting_on_futex(&mut self, key: Option<FutexKey>) {
        self.waiting_on_futex = key;
    }

    /// E.4 PI: 获取当前等待的 futex key（用于链式 PI）
    pub fn get_waiting_on_futex(&self) -> Option<FutexKey> {
        self.waiting_on_futex
    }

    // ========================================================================
    // Standard Priority Methods (updated for PI awareness)
    // ========================================================================

    /// 更新动态优先级（用于公平调度）
    ///
    /// E.4 PI: Now operates on base_dynamic_priority and recomputes effective.
    pub fn update_dynamic_priority(&mut self) {
        // 简单的优先级提升策略
        if self.base_dynamic_priority > 0 {
            self.base_dynamic_priority -= 1;
            self.recompute_effective_priority();
        }
    }

    /// 降低动态优先级（惩罚CPU密集型进程）
    ///
    /// E.4 PI: Now operates on base_dynamic_priority and recomputes effective.
    pub fn decrease_dynamic_priority(&mut self) {
        if self.base_dynamic_priority < 139 {
            self.base_dynamic_priority += 1;
            self.recompute_effective_priority();
        }
    }

    /// R65-19 FIX: 饥饿防止 - 提升长时间等待进程的优先级
    ///
    /// 每次调度器tick时，对所有就绪但未运行的进程增加wait_ticks。
    /// 当wait_ticks超过阈值(STARVATION_THRESHOLD)时，提升动态优先级。
    ///
    /// # 算法
    ///
    /// - 每STARVATION_THRESHOLD个tick提升1级优先级
    /// - 最多提升到静态优先级（不会超过原始优先级）
    /// - 提升后重置wait_ticks，开始新的等待周期
    ///
    /// # 防饥饿保证
    ///
    /// 即使低优先级进程被高优先级进程持续抢占，经过足够长的等待时间后，
    /// 其优先级会被逐渐提升直到获得运行机会。
    ///
    /// # R66-4 FIX: Priority Boost Cap
    ///
    /// Previously, dynamic_priority could be boosted below static priority,
    /// allowing low-priority processes to gain higher priority than intended.
    /// Now capped at static priority to prevent priority inversion abuse.
    ///
    /// # E.4 PI: Updated for priority inheritance
    ///
    /// Now operates on base_dynamic_priority and recomputes effective priority.
    pub fn check_and_boost_starved(&mut self) {
        // 饥饿阈值：100个tick（约100ms，假设1ms/tick）
        const STARVATION_THRESHOLD: u64 = 100;

        if self.wait_ticks >= STARVATION_THRESHOLD {
            // R66-4 FIX: Only boost if base > static (never boost beyond static)
            // This prevents low-priority processes from gaining realtime priority
            // E.4 PI: Now operates on base_dynamic_priority
            if self.base_dynamic_priority > self.priority {
                self.base_dynamic_priority -= 1;
                self.recompute_effective_priority();
            }
            // 重置等待计数器
            self.wait_ticks = 0;
        }
    }

    /// R65-19 FIX: 重置等待时间（进程被调度运行时调用）
    #[inline]
    pub fn reset_wait_ticks(&mut self) {
        self.wait_ticks = 0;
    }

    /// R65-19 FIX: 增加等待时间（调度器tick时调用）
    #[inline]
    pub fn increment_wait_ticks(&mut self) {
        self.wait_ticks = self.wait_ticks.saturating_add(1);
    }

    /// 恢复静态优先级
    ///
    /// E.4 PI: Now resets base_dynamic_priority and recomputes effective priority.
    pub fn restore_static_priority(&mut self) {
        self.base_dynamic_priority = self.priority;
        self.recompute_effective_priority();
    }
}

/// 根据优先级计算时间片（毫秒）
fn calculate_time_slice(priority: Priority) -> u32 {
    // 优先级越高，时间片越长
    // 优先级0-99: 100-200ms
    // 优先级100-139: 10-100ms
    if priority < 100 {
        200 - priority as u32
    } else {
        140 - priority as u32
    }
}

/// F.2: 根据优先级和 cgroup cpu_weight 计算时间片
///
/// Scales base time slice by cgroup weight:
/// - weight=100 (default): no change
/// - weight=200: 2x time slice (more CPU time)
/// - weight=50: 0.5x time slice (less CPU time)
///
/// Clamps result to [1, 300]ms to prevent starvation of peer cgroups.
fn calculate_time_slice_with_cgroup(priority: Priority, cgroup_id: crate::cgroup::CgroupId) -> u32 {
    let base = calculate_time_slice(priority);
    let weight = crate::cgroup::get_effective_cpu_weight(cgroup_id);

    // Scale: new_slice = base * weight / 100
    // Use u64 to avoid overflow during multiplication
    let scaled = (base as u64 * weight as u64) / 100;

    // Clamp to reasonable range [1, 300]
    // Upper bound reduced from 1000ms to 300ms to prevent excessive starvation
    // of peer cgroups when high weights (e.g., 10000) are configured.
    scaled.clamp(1, 300) as u32
}

/// 全局进程表
///
/// 使用 Option<Arc<Mutex<Process>>> 以支持 PID 作为直接索引。
/// 索引 0 保留为空（PID 从 1 开始），实际进程存储在其 PID 对应的索引位置。
lazy_static::lazy_static! {
    pub static ref PROCESS_TABLE: Mutex<Vec<Option<Arc<Mutex<Process>>>>> = Mutex::new(vec![None]); // 索引0预留
    static ref SCHEDULER_CLEANUP: Mutex<Option<SchedulerCleanupCallback>> = Mutex::new(None);
    static ref IPC_CLEANUP: Mutex<Option<IpcCleanupCallback>> = Mutex::new(None);
    /// 调度器添加进程回调
    static ref SCHEDULER_ADD: Mutex<Option<SchedulerAddCallback>> = Mutex::new(None);
    /// Futex 唤醒回调（用于 clear_child_tid）
    static ref FUTEX_WAKE: Mutex<Option<FutexWakeCallback>> = Mutex::new(None);
    /// E.5 Cpuset: Task joined callback (for fork/clone)
    static ref CPUSET_TASK_JOINED: Mutex<Option<CpusetTaskJoinedCallback>> = Mutex::new(None);
    /// E.5 Cpuset: Task left callback (for process exit)
    static ref CPUSET_TASK_LEFT: Mutex<Option<CpusetTaskLeftCallback>> = Mutex::new(None);
    /// 缓存引导时的 CR3 值，用于内核进程或 memory_space == 0 的情况
    static ref BOOT_CR3: (PhysFrame<Size4KiB>, Cr3Flags) = Cr3::read();
}

/// R67-4 FIX: Per-CPU storage for current process ID.
///
/// Each CPU tracks its own currently running process. This prevents race
/// conditions where multiple CPUs could interfere with each other's
/// current process state.
///
/// R91-1 FIX: Uses AtomicUsize instead of Mutex<Option<ProcessId>> to eliminate
/// IRQ deadlock. Timer ISR calls current_pid() from interrupt context while
/// syscall path enables interrupts (sti) before dispatcher. If timer fires
/// while syscall code holds the per-CPU Mutex, the ISR would deadlock trying
/// to acquire the same non-reentrant spinlock on the same CPU.
///
/// Encoding: 0 = no current process, N > 0 = ProcessId N.
/// PID 0 is never assigned, so 0 is a safe sentinel.
static CURRENT_PID: cpu_local::CpuLocal<AtomicUsize> =
    cpu_local::CpuLocal::new(|| AtomicUsize::new(0));

/// R106-11 (P0-4): Next PID allocation hint for circular scan.
///
/// PID 0 is never allocated; valid PIDs are in [1, PID_MAX].
/// On each allocation, the scan starts from this hint and wraps around.
static NEXT_PID_HINT: Mutex<ProcessId> = Mutex::new(1);

/// R106-1 FIX: 下一个可用的进程 generation（单调递增，永不复用）。
///
/// 每个新进程实例（包括 PID 复用场景）获得唯一的 generation 值，
/// 用于 IPC 授权等需要区分进程身份的场景。u64 空间在实际中不可耗尽。
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// 初始化进程子系统
///
/// 必须在任何进程创建或调度之前调用，以确保 BOOT_CR3 捕获正确的引导页表值。
pub fn init() {
    // 强制 BOOT_CR3 lazy_static 初始化，确保捕获当前（引导）CR3
    let _ = *BOOT_CR3;
    klog_always!("  Process subsystem initialized (boot CR3 cached)");
}

/// R106-11 (P0-4): Allocate a free global PID with recycling.
///
/// Uses a circular scan starting from `hint`. On wrap-around, scans from PID 1
/// up to the previous hint. PID 0 is never allocated.
///
/// # Lock ordering
///
/// The caller must hold `NEXT_PID_HINT` and pass the already-locked
/// `PROCESS_TABLE` to avoid double-locking.
fn allocate_global_pid(
    hint: &mut ProcessId,
    table: &Vec<Option<Arc<Mutex<Process>>>>,
) -> Result<ProcessId, ProcessCreateError> {
    let pid_max = PID_MAX.min(MAX_PID);

    let start = match *hint {
        0 => 1,
        n if n > pid_max => 1,
        n => n,
    };

    // Forward scan: [start, pid_max]
    for pid in start..=pid_max {
        let is_free = table.get(pid).map(|slot| slot.is_none()).unwrap_or(true);
        if is_free {
            *hint = if pid == pid_max { 1 } else { pid + 1 };
            return Ok(pid);
        }
    }

    // Wrap-around scan: [1, start)
    for pid in 1..start {
        let is_free = table.get(pid).map(|slot| slot.is_none()).unwrap_or(true);
        if is_free {
            *hint = if pid == pid_max { 1 } else { pid + 1 };
            return Ok(pid);
        }
    }

    Err(ProcessCreateError::PidExhausted)
}

/// 创建新进程
///
/// # Arguments
/// * `name` - 进程名称
/// * `ppid` - 父进程 ID（0 表示无父进程）
/// * `priority` - 进程优先级
///
/// # Returns
/// 成功返回新创建进程的 PID，失败返回错误
///
/// # Security Fix Z-7
/// 内核栈分配失败时必须返回错误终止进程创建，绝不能共享内核栈
pub fn create_process(
    name: String,
    ppid: ProcessId,
    priority: Priority,
) -> Result<ProcessId, ProcessCreateError> {
    // R106-11 (P0-4): Allocate PID via recycling scan.
    // Lock ordering: NEXT_PID_HINT → PROCESS_TABLE (consistent with all paths).
    //
    // Kernel stack deallocation is deferred via call_rcu(), so a recycled PID's
    // stack slot may still be mapped. If allocate_kernel_stack returns AlreadyMapped,
    // advance the hint past that PID and retry with the next candidate.
    let mut hint_guard = NEXT_PID_HINT.lock();

    // Maximum retries bounded by practical RCU backlog; in a healthy system only
    // a handful of PIDs can be in the grace-period window simultaneously.
    const MAX_STACK_RETRIES: usize = 32;
    let mut stack_retries = 0;
    let (pid, stack_base, stack_top) = loop {
        let pid = {
            let table = PROCESS_TABLE.lock();
            allocate_global_pid(&mut hint_guard, &table)?
        };

        match allocate_kernel_stack(pid) {
            Ok((base, top)) => break (pid, base, top),
            Err(KernelStackError::AlreadyMapped) => {
                // Stack slot still mapped from RCU-deferred free; skip this PID.
                stack_retries += 1;
                if stack_retries >= MAX_STACK_RETRIES {
                    kprintln!(
                        "Error: {} consecutive PIDs have stale kernel stacks (RCU backlog)",
                        stack_retries
                    );
                    return Err(ProcessCreateError::KernelStackAllocFailed(
                        KernelStackError::AlreadyMapped,
                    ));
                }
                // Advance hint past the stale PID so the next scan starts beyond it.
                // The slot is None in PROCESS_TABLE, so the allocator will normally
                // return it again on wrap-around. However, with forward-scanning and
                // a large PID space (32768), the RCU grace period will almost certainly
                // complete before the allocator wraps back to this PID.
                let pid_max = PID_MAX.min(MAX_PID);
                *hint_guard = if pid >= pid_max { 1 } else { pid + 1 };
                continue;
            }
            Err(e) => {
                kprintln!(
                    "Error: Failed to allocate kernel stack for PID {}: {:?}",
                    pid, e
                );
                return Err(ProcessCreateError::KernelStackAllocFailed(e));
            }
        }
    };

    let process = Arc::new(Mutex::new(Process::new(pid, ppid, name.clone(), priority)));

    // 设置已分配的内核栈
    {
        let mut proc = process.lock();
        proc.kernel_stack = stack_base;
        proc.kernel_stack_top = stack_top;
    }

    // R101-1 FIX: Kernel-internal processes (ppid == 0) need explicit root credentials.
    //
    // Process::new() now defaults to nobody (uid=65534). Kernel threads and init
    // processes must be explicitly promoted to root. User-spawned processes will
    // inherit credentials from the parent via fork()/clone().
    if ppid == 0 {
        let mut proc = process.lock();
        *proc.credentials.write() = Credentials {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            supplementary_groups: Vec::new(),
        };
    }

    // F.1 PID Namespace: Assign namespace chain for the new process
    //
    // For kernel-created processes (ppid == 0), use root namespace.
    // For forked/cloned processes, the caller (fork.rs/sys_clone) will handle
    // namespace inheritance from the parent.
    {
        let target_ns = if ppid == 0 {
            // Kernel thread: use root namespace
            crate::pid_namespace::ROOT_PID_NAMESPACE.clone()
        } else {
            // Child process: inherit from parent's pid_ns_for_children
            // Note: For now, default to root. Fork/clone will override this.
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().pid_ns_for_children.clone()
            } else {
                crate::pid_namespace::ROOT_PID_NAMESPACE.clone()
            }
        };

        // Assign PID chain from root namespace down to target
        match crate::pid_namespace::assign_pid_chain(target_ns.clone(), pid) {
            Ok(chain) => {
                let mut proc = process.lock();
                proc.pid_ns_chain = chain;
                proc.pid_ns_for_children = target_ns;
            }
            Err(e) => {
                // Namespace chain assignment failed, clean up
                // R104-2 FIX: Gate diagnostic println behind debug_assertions.
                kprintln!("Error: Failed to assign PID namespace chain: {:?}", e);
                let _ = e; // suppress unused warning in release
                free_kernel_stack(pid, stack_base);
                // R106-11: PID reclaim is automatic — the slot is still None,
                // so the next allocate_global_pid() scan will find it.
                return Err(ProcessCreateError::NamespaceError);
            }
        }
    }

    // Mount namespace: inherit from parent's mount_ns_for_children (or root for kernel threads)
    {
        let target_mnt_ns = if ppid == 0 {
            crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
        } else {
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().mount_ns_for_children.clone()
            } else {
                crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
            }
        };

        let mut proc = process.lock();
        proc.mount_ns = target_mnt_ns.clone();
        proc.mount_ns_for_children = target_mnt_ns;
    }

    // R106-11 (P0-4): Insert into PROCESS_TABLE, then release hint_guard.
    // The hint_guard was held throughout to prevent concurrent allocators from
    // reusing this PID slot before insertion.
    {
        let mut table = PROCESS_TABLE.lock();

        // 确保进程表有足够的空间存储新进程
        // PID 直接作为索引使用，因此表长度需要 >= pid + 1
        while table.len() <= pid {
            table.push(None);
        }

        // 将新进程存储在其 PID 对应的索引位置
        table[pid] = Some(process.clone());

        // 如果有父进程，将此进程添加到父进程的子进程列表
        if ppid > 0 {
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().children.push(pid);
            }
        }
    }

    // Safe to release now — the PID slot is occupied in PROCESS_TABLE
    drop(hint_guard);

    // E.5 Cpuset: count kernel-created tasks (ppid == 0) so root cpuset reflects live tasks.
    // Fork path handles task counting separately via fork.rs which also copies cpuset_id.
    if ppid == 0 {
        let cpuset_id = process.lock().cpuset_id;
        notify_cpuset_task_joined(cpuset_id);
    }

    // G.1 Observability: Register watchdog for hung-task detection.
    // Best-effort registration - failure is logged but doesn't fail process creation.
    // The 10-second timeout catches true hangs while allowing normal blocking operations.
    let now_ms = time::current_timestamp_ms();
    let cfg = WatchdogConfig {
        task_id: pid as u64,
        timeout_ms: WATCHDOG_TIMEOUT_MS,
    };
    match register_watchdog(cfg, now_ms) {
        Ok(handle) => {
            process.lock().watchdog_handle = Some(handle);
        }
        Err(_) => {
            // Watchdog slots full - system under heavy load but not fatal
            // R104-2 FIX: Gate diagnostic println behind debug_assertions.
            kprintln!(
                "  Warning: Failed to register watchdog for PID {} (slots full)",
                pid
            );
        }
    }

    // R104-2 FIX: Gate diagnostic println behind debug_assertions.
    klog!(Info, 
        "Created process: PID={}, Name={}, Priority={}",
        pid, name, priority
    );

    Ok(pid)
}

/// F.1 PID Namespace: Create a process in a specific namespace.
///
/// This is used by sys_clone with CLONE_NEWPID to create processes
/// in a new namespace instead of inheriting from parent.
///
/// # Arguments
///
/// * `name` - Process name
/// * `ppid` - Parent process ID
/// * `priority` - Process priority
/// * `target_ns` - The PID namespace to create the process in
///
/// # Returns
///
/// The new process's global PID on success
pub fn create_process_in_namespace(
    name: String,
    ppid: ProcessId,
    priority: Priority,
    target_ns: Arc<crate::pid_namespace::PidNamespace>,
) -> Result<ProcessId, ProcessCreateError> {
    // Allocate PID and kernel stack (same as create_process)
    // R106-11 (P0-4): Allocate PID via recycling scan with AlreadyMapped retry.
    let mut hint_guard = NEXT_PID_HINT.lock();

    const MAX_STACK_RETRIES: usize = 32;
    let mut stack_retries = 0;
    let (pid, stack_base, stack_top) = loop {
        let pid = {
            let table = PROCESS_TABLE.lock();
            allocate_global_pid(&mut hint_guard, &table)?
        };

        match allocate_kernel_stack(pid) {
            Ok((base, top)) => break (pid, base, top),
            Err(KernelStackError::AlreadyMapped) => {
                stack_retries += 1;
                if stack_retries >= MAX_STACK_RETRIES {
                    kprintln!(
                        "Error: {} consecutive PIDs have stale kernel stacks (RCU backlog)",
                        stack_retries
                    );
                    return Err(ProcessCreateError::KernelStackAllocFailed(
                        KernelStackError::AlreadyMapped,
                    ));
                }
                let pid_max = PID_MAX.min(MAX_PID);
                *hint_guard = if pid >= pid_max { 1 } else { pid + 1 };
                continue;
            }
            Err(e) => {
                kprintln!(
                    "Error: Failed to allocate kernel stack for PID {}: {:?}",
                    pid, e
                );
                return Err(ProcessCreateError::KernelStackAllocFailed(e));
            }
        }
    };

    let process = Arc::new(Mutex::new(Process::new(pid, ppid, name.clone(), priority)));

    // Set up kernel stack
    {
        let mut proc = process.lock();
        proc.kernel_stack = stack_base;
        proc.kernel_stack_top = stack_top;
    }

    // R101-1 FIX: Kernel-internal processes (ppid == 0) need explicit root credentials.
    if ppid == 0 {
        let mut proc = process.lock();
        *proc.credentials.write() = Credentials {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            supplementary_groups: Vec::new(),
        };
    }

    // Assign PID namespace chain using the specified target namespace
    match crate::pid_namespace::assign_pid_chain(target_ns.clone(), pid) {
        Ok(chain) => {
            let mut proc = process.lock();
            proc.pid_ns_chain = chain;
            proc.pid_ns_for_children = target_ns;
        }
        Err(e) => {
            // R104-2 FIX: Gate diagnostic println behind debug_assertions.
            kprintln!("Error: Failed to assign PID namespace chain: {:?}", e);
            let _ = e; // suppress unused warning in release
            free_kernel_stack(pid, stack_base);
            // R106-11: PID reclaim is automatic — the slot is still None,
            // so the next allocate_global_pid() scan will find it.
            return Err(ProcessCreateError::NamespaceError);
        }
    }

    // Mount namespace: inherit from parent's mount_ns_for_children (or root for kernel threads)
    {
        let target_mnt_ns = if ppid == 0 {
            crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
        } else {
            let table = PROCESS_TABLE.lock();
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().mount_ns_for_children.clone()
            } else {
                crate::mount_namespace::ROOT_MNT_NAMESPACE.clone()
            }
        };

        let mut proc = process.lock();
        proc.mount_ns = target_mnt_ns.clone();
        proc.mount_ns_for_children = target_mnt_ns;
    }

    // R106-11 (P0-4): Insert into PROCESS_TABLE, then release hint_guard.
    {
        let mut table = PROCESS_TABLE.lock();

        while table.len() <= pid {
            table.push(None);
        }

        table[pid] = Some(process.clone());

        if ppid > 0 {
            if let Some(Some(parent)) = table.get(ppid) {
                parent.lock().children.push(pid);
            }
        }
    }

    // Safe to release now — the PID slot is occupied in PROCESS_TABLE
    drop(hint_guard);

    if ppid == 0 {
        let cpuset_id = process.lock().cpuset_id;
        notify_cpuset_task_joined(cpuset_id);
    }

    // G.1 Observability: Register watchdog for hung-task detection.
    // Best-effort registration - failure is logged but doesn't fail process creation.
    let now_ms = time::current_timestamp_ms();
    let cfg = WatchdogConfig {
        task_id: pid as u64,
        timeout_ms: WATCHDOG_TIMEOUT_MS,
    };
    match register_watchdog(cfg, now_ms) {
        Ok(handle) => {
            process.lock().watchdog_handle = Some(handle);
        }
        Err(_) => {
            // R104-2 FIX: Gate diagnostic println behind debug_assertions.
            kprintln!(
                "  Warning: Failed to register watchdog for PID {} (slots full)",
                pid
            );
        }
    }

    // R104-2 FIX: Gate diagnostic println behind debug_assertions.
    klog!(Info, 
        "Created process in namespace: PID={}, Name={}, Priority={}, NS={}",
        pid, name, priority, process.lock().pid_ns_for_children.id().raw()
    );

    Ok(pid)
}

/// 获取当前进程ID
///
/// R67-4 FIX: Reads from per-CPU storage to avoid cross-CPU races.
///
/// R91-1 FIX: Lock-free atomic load. Safe to call from any context including
/// IRQ handlers (timer ISR profiler sampling) without deadlock risk.
pub fn current_pid() -> Option<ProcessId> {
    let raw = CURRENT_PID.with(|pid| pid.load(Ordering::Relaxed));
    if raw == 0 { None } else { Some(raw) }
}

/// R106-1 FIX: 获取当前进程的 generation 值。
///
/// 与 `current_pid()` 配合使用，提供 (pid, generation) 二元组
/// 作为不可伪造的进程身份标识，防止 PID 复用后的授权继承。
pub fn current_generation() -> Option<u64> {
    let pid = current_pid()?;
    let process = get_process(pid)?;
    let proc = process.lock();
    Some(proc.generation)
}

/// R25-6 FIX: Get the size of a thread group (number of tasks sharing the same tgid).
///
/// Returns the count of active threads in the thread group identified by tgid.
/// Used to detect multi-threaded processes for seccomp TSYNC enforcement.
pub fn thread_group_size(tgid: ProcessId) -> usize {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.tgid == tgid
                    && p.state != ProcessState::Zombie
                    && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

/// R37-1 FIX: Count live tasks sharing the same address space (CLONE_VM siblings).
///
/// Returns 0 if no valid memory_space is set.
/// Used to detect CLONE_VM processes for seccomp TSYNC enforcement.
pub fn address_space_share_count(memory_space: usize) -> usize {
    if memory_space == 0 {
        return 0;
    }
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.memory_space == memory_space
                    && p.state != ProcessState::Zombie
                    && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

/// R37-1 FIX (Codex review): Count CLONE_VM siblings that are NOT in the same thread group.
///
/// CLONE_THREAD siblings share memory_space AND have the same tgid - these can be TSYNC'd.
/// Pure CLONE_VM siblings share memory_space but have DIFFERENT tgid - these cannot be TSYNC'd.
///
/// This function returns the count of processes that share the same memory_space but have
/// a different tgid than the caller. If count > 0, TSYNC must be rejected.
pub fn non_thread_group_vm_share_count(memory_space: usize, caller_tgid: ProcessId) -> usize {
    if memory_space == 0 {
        return 0;
    }
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter(|slot| {
            if let Some(p) = slot {
                let p = p.lock();
                p.memory_space == memory_space
                    && p.tgid != caller_tgid // Different thread group = pure CLONE_VM sibling
                    && p.state != ProcessState::Zombie
                    && p.state != ProcessState::Terminated
            } else {
                false
            }
        })
        .count()
}

/// R101-9 FIX: Get a snapshot of all active PIDs from the process table.
///
/// Returns a Vec of all PIDs that have live process entries. Used by
/// exit_group to find sibling threads in the same thread group.
pub fn process_table_snapshot() -> alloc::vec::Vec<ProcessId> {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| {
            if slot.is_some() {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}

/// 设置当前进程ID
///
/// R67-4 FIX: Writes to per-CPU storage to avoid cross-CPU races.
///
/// R91-1 FIX: Lock-free atomic store. Uses Relaxed ordering because this is
/// per-CPU data only written by the owning CPU's scheduler and read by the
/// same CPU's IRQ handler. No cross-CPU visibility is needed.
pub fn set_current_pid(pid: Option<ProcessId>) {
    let raw = pid.unwrap_or(0);
    CURRENT_PID.with(|current| current.store(raw, Ordering::Relaxed));
}

// ========== 进程凭证访问 (DAC支持) ==========

/// 进程凭证结构
#[derive(Debug, Clone)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub supplementary_groups: Vec<u32>,
}

/// 获取当前进程的凭证
///
/// R39-3 FIX: 从共享凭证结构读取，线程间共享
/// 返回 None 如果没有当前进程
pub fn current_credentials() -> Option<Credentials> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    let creds = proc.credentials.read().clone();
    Some(creds)
}

/// 获取当前进程的有效用户ID
pub fn current_euid() -> Option<u32> {
    current_credentials().map(|c| c.euid)
}

/// 获取当前进程的有效组ID
pub fn current_egid() -> Option<u32> {
    current_credentials().map(|c| c.egid)
}

/// F.1: 获取当前进程的挂载命名空间
///
/// Returns the current process's mount namespace, used by VFS for
/// namespace-aware path resolution.
pub fn current_mount_ns() -> Option<Arc<crate::mount_namespace::MountNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.mount_ns.clone())
}

/// F.1: 获取当前进程的IPC命名空间
///
/// Returns the current process's IPC namespace, used for isolating
/// System V IPC resources (message queues, semaphores, shared memory).
pub fn current_ipc_ns() -> Option<Arc<crate::ipc_namespace::IpcNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.ipc_ns.clone())
}

/// F.1: 获取当前进程的网络命名空间
///
/// Returns the current process's network namespace, used for isolating
/// network devices, sockets, and routing tables.
pub fn current_net_ns() -> Option<Arc<crate::net_namespace::NetNamespace>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.net_ns.clone())
}

/// R75-2 FIX: 获取当前进程的 IPC 命名空间 ID
///
/// Returns the current process's IPC namespace identifier, used for
/// partitioning IPC endpoint tables by namespace.
#[inline]
pub fn current_ipc_ns_id() -> Option<cap::NamespaceId> {
    current_ipc_ns().map(|ns| ns.id())
}

/// R75-1 FIX: 获取当前进程的网络命名空间 ID
///
/// Returns the current process's network namespace identifier, used for
/// partitioning socket tables and port bindings by namespace.
#[inline]
pub fn current_net_ns_id() -> Option<cap::NamespaceId> {
    current_net_ns().map(|ns| ns.id())
}

/// F.2: 获取当前进程的 Cgroup ID
///
/// Returns the current process's cgroup identifier, used for resource
/// accounting and limit enforcement by cgroup controllers.
#[inline]
pub fn current_cgroup_id() -> Option<crate::cgroup::CgroupId> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.cgroup_id)
}

/// 获取当前进程的附属组列表
///
/// R39-3 FIX: 从共享凭证结构读取
/// 返回附属组ID的克隆列表，如果没有当前进程则返回 None
pub fn current_supplementary_groups() -> Option<Vec<u32>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    let groups = proc.credentials.read().supplementary_groups.clone();
    Some(groups)
}

/// Maximum number of supplementary groups per process
///
/// This limit prevents memory exhaustion and keeps permission check performance reasonable.
/// Linux uses NGROUPS_MAX (typically 65536), but we use a smaller value for kernel simplicity.
pub const NGROUPS_MAX: usize = 256;

/// 设置当前进程的附属组列表
///
/// 会自动去重并排序，方便后续查找。
/// 最多保留 NGROUPS_MAX 个组以防止资源耗尽。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以修改附属组列表。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `groups` - 新的附属组列表
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn set_current_supplementary_groups(groups: &[u32]) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();

    // R39-3 FIX: 使用共享凭证结构
    let mut creds = proc.credentials.write();

    // Security: Only root can modify supplementary groups
    if creds.euid != 0 {
        return None;
    }

    creds.supplementary_groups.clear();
    // Take only up to NGROUPS_MAX groups to prevent DoS
    let limit = groups.len().min(NGROUPS_MAX);
    creds
        .supplementary_groups
        .extend(groups[..limit].iter().copied());
    creds.supplementary_groups.sort_unstable();
    creds.supplementary_groups.dedup();
    Some(())
}

/// 向当前进程添加一个附属组
///
/// 如果该组已存在则不会重复添加。
/// 如果已达到 NGROUPS_MAX 上限，添加操作被忽略。
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以添加附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要添加的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn add_supplementary_group(gid: u32) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();

    // R39-3 FIX: 使用共享凭证结构
    let mut creds = proc.credentials.write();

    // Security: Only root can modify supplementary groups
    if creds.euid != 0 {
        return None;
    }

    if !creds.supplementary_groups.contains(&gid) {
        // Enforce NGROUPS_MAX limit
        if creds.supplementary_groups.len() < NGROUPS_MAX {
            creds.supplementary_groups.push(gid);
        }
    }
    Some(())
}

/// 从当前进程移除一个附属组
///
/// 如果该组不存在则无操作
///
/// # Security
///
/// 只有 root 进程 (euid == 0) 可以移除附属组。
/// 非特权进程调用此函数将静默失败（返回 None）。
///
/// # Arguments
/// * `gid` - 要移除的组ID
///
/// # Returns
/// 成功返回 Some(())，没有当前进程或权限不足返回 None
pub fn remove_supplementary_group(gid: u32) -> Option<()> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();

    // R39-3 FIX: 使用共享凭证结构
    let mut creds = proc.credentials.write();

    // Security: Only root can modify supplementary groups
    if creds.euid != 0 {
        return None;
    }

    creds.supplementary_groups.retain(|&g| g != gid);
    Some(())
}

/// 获取当前进程的umask
pub fn current_umask() -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.umask)
}

/// 设置当前进程的umask，返回旧的umask
pub fn set_current_umask(new_mask: u16) -> Option<u16> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let mut proc = slot.as_ref()?.lock();
    let old = proc.umask;
    proc.umask = new_mask & 0o777; // 只保留权限位
    Some(old)
}

// ========== 能力表访问 ==========

/// 获取当前进程的能力表（CapTable）
///
/// 返回能力表的 Arc 克隆，调用者可以直接使用 CapTable 的方法
/// （如 allocate、lookup、revoke、delegate 等）进行操作。
///
/// # Returns
///
/// 如果当前有运行中的进程，返回 Some(Arc<CapTable>)；
/// 如果在内核线程中调用（无当前进程），返回 None。
pub fn current_cap_table() -> Option<Arc<CapTable>> {
    let pid = current_pid()?;
    let table = PROCESS_TABLE.lock();
    let slot = table.get(pid)?;
    let proc = slot.as_ref()?.lock();
    Some(proc.cap_table.clone())
}

/// 对当前进程的能力表执行操作
///
/// 提供一个便捷的方式来对能力表执行操作，而无需手动获取 Arc。
///
/// # Arguments
///
/// * `f` - 接受 &CapTable 引用的闭包
///
/// # Returns
///
/// 如果当前有运行中的进程，返回闭包的返回值；否则返回 None。
///
/// # Example
///
/// ```rust,ignore
/// let can_write = with_current_cap_table(|table| {
///     table.check_rights(cap_id, CapRights::WRITE).unwrap_or(false)
/// });
/// ```
pub fn with_current_cap_table<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&CapTable) -> R,
{
    current_cap_table().map(|table| f(&table))
}

// ========== Seccomp/Pledge 沙箱访问 ==========

use seccomp::SeccompVerdict;

/// 评估当前进程的 seccomp 过滤器
///
/// 在系统调用分发前调用此函数检查 seccomp 过滤器和 pledge 限制。
///
/// # Arguments
/// * `syscall_nr` - 系统调用号
/// * `args` - 系统调用参数数组 (6 个参数)
///
/// # Returns
/// 返回 seccomp 评估结果:
/// - `SeccompAction::Allow` - 允许执行
/// - `SeccompAction::Kill` - 终止进程
/// - `SeccompAction::Errno(e)` - 返回错误码
/// - `SeccompAction::Trap` - 触发 SIGSYS
/// - `SeccompAction::Log` - 记录日志但允许执行
pub fn evaluate_seccomp(syscall_nr: u64, args: &[u64; 6]) -> SeccompVerdict {
    let pid = match current_pid() {
        Some(p) => p,
        None => return SeccompVerdict::allow(),
    };

    let table = PROCESS_TABLE.lock();
    let slot = match table.get(pid) {
        Some(s) => s,
        None => return SeccompVerdict::allow(),
    };
    let proc = match slot.as_ref() {
        Some(p) => p.lock(),
        None => return SeccompVerdict::allow(),
    };

    // First check pledge if set
    if let Some(ref pledge) = proc.pledge_state {
        if !pledge.allows(syscall_nr, args) {
            return SeccompVerdict::kill(0);
        }
    }

    // Then evaluate seccomp filters
    if proc.seccomp_state.has_filters() {
        let mut verdict = proc.seccomp_state.evaluate(syscall_nr, args);

        // R25-5 FIX: Honor log_violations flag
        // When log_violations is set, convert Allow to Log for auditing
        if proc.seccomp_state.log_violations {
            if matches!(verdict.action, seccomp::SeccompAction::Allow) {
                verdict.action = seccomp::SeccompAction::Log;
            }
        }

        verdict
    } else {
        SeccompVerdict::allow()
    }
}

/// 检查当前进程是否启用了 seccomp
pub fn has_seccomp_enabled() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    let table = PROCESS_TABLE.lock();
    let slot = match table.get(pid) {
        Some(s) => s,
        None => return false,
    };
    let proc = match slot.as_ref() {
        Some(p) => p.lock(),
        None => return false,
    };

    proc.seccomp_state.has_filters() || proc.pledge_state.is_some()
}

/// 检查当前进程是否设置了 no_new_privs
pub fn has_no_new_privs() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    let table = PROCESS_TABLE.lock();
    let slot = match table.get(pid) {
        Some(s) => s,
        None => return false,
    };
    let proc = match slot.as_ref() {
        Some(p) => p.lock(),
        None => return false,
    };

    proc.seccomp_state.no_new_privs
}

/// 激活指定的地址空间
///
/// 切换到进程的页表。memory_space 为 0 时使用引导时的页表（内核共享页表）。
/// 调用 Cr3::write 会刷新 TLB，确保新地址空间立即生效。
///
/// # Arguments
/// * `memory_space` - 进程的 PML4 物理地址，0 表示使用引导页表
///
/// # Safety
/// 这个函数会修改 CR3 寄存器，调用者必须确保：
/// - memory_space 指向有效的 PML4 页表
/// - 内核代码和数据在新旧页表中都有正确映射
pub fn activate_memory_space(memory_space: usize) {
    let (boot_frame, boot_flags) = *BOOT_CR3;
    let (current_frame, _) = Cr3::read();

    let (target_frame, target_flags) = if memory_space == 0 {
        // 使用引导页表（内核进程或尚未分配独立页表的进程）
        (boot_frame, boot_flags)
    } else {
        // 使用进程的独立页表
        (
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64)),
            boot_flags, // 使用相同的 CR3 标志
        )
    };

    // 只有当目标页表与当前不同时才切换（避免不必要的 TLB 刷新）
    if target_frame != current_frame {
        unsafe { Cr3::write(target_frame, target_flags) };

        // R68 Architecture Improvement: Update per-address-space TLB tracking.
        //
        // This allows TLB shootdown to target only CPUs that might have TLB entries
        // for the affected address space, rather than broadcasting to all CPUs.
        // The tracking is used by collect_target_cpus() in tlb_shootdown.rs.
        //
        // # Race Condition Safety
        //
        // There's a window between the CR3 write and map update where another CPU's
        // shootdown for this CR3 could miss us. This is SAFE because:
        // - Writing CR3 flushes all non-global TLB entries on this CPU
        // - We have no stale entries to flush since our TLB is fresh
        // - Any subsequent TLB entries will be populated after the shootdown
        mm::tlb_shootdown::track_cr3_switch(target_frame.start_address().as_u64());
    }
}

/// 获取进程
///
/// # Arguments
/// * `pid` - 进程 ID
///
/// # Returns
/// 如果进程存在，返回进程的 Arc 引用；否则返回 None
pub fn get_process(pid: ProcessId) -> Option<Arc<Mutex<Process>>> {
    let table = PROCESS_TABLE.lock();
    table.get(pid).and_then(|slot| slot.clone())
}

/// 注册调度器的清理回调，用于在 PCB 删除时同步调度器状态
pub fn register_cleanup_notifier(callback: SchedulerCleanupCallback) {
    *SCHEDULER_CLEANUP.lock() = Some(callback);
}

/// 注册IPC清理回调，用于在进程退出时清理其端点
pub fn register_ipc_cleanup(callback: IpcCleanupCallback) {
    *IPC_CLEANUP.lock() = Some(callback);
}

/// 注册调度器添加进程回调，用于 clone/fork 时将新进程添加到调度队列
pub fn register_scheduler_add(callback: SchedulerAddCallback) {
    *SCHEDULER_ADD.lock() = Some(callback);
}

/// 注册 futex 唤醒回调，用于线程退出时唤醒等待者
pub fn register_futex_wake(callback: FutexWakeCallback) {
    *FUTEX_WAKE.lock() = Some(callback);
}

/// 通知调度器进程已被移除
fn notify_scheduler_process_removed(pid: ProcessId) {
    let callback = *SCHEDULER_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid);
    }
}

/// 通知IPC子系统清理进程端点
/// R37-2 FIX (Codex review): Pass TGID to avoid re-locking the process in callback.
/// R75-2 FIX: Pass IPC namespace ID for per-namespace endpoint cleanup.
fn notify_ipc_process_cleanup(pid: ProcessId, tgid: ProcessId, ipc_ns_id: cap::NamespaceId) {
    let callback = *IPC_CLEANUP.lock();
    if let Some(cb) = callback {
        cb(pid, tgid, ipc_ns_id);
    }
}

/// 通知调度器添加新进程到调度队列
///
/// 由 clone/fork 在创建新进程后调用
pub fn notify_scheduler_add_process(process: Arc<Mutex<Process>>) {
    let callback = *SCHEDULER_ADD.lock();
    if let Some(cb) = callback {
        cb(process);
    }
}

/// 通知 futex 唤醒等待者
///
/// 由线程退出时调用，用于 clear_child_tid 机制
fn notify_futex_wake(tgid: ProcessId, uaddr: usize, max_wake: usize) -> usize {
    let callback = *FUTEX_WAKE.lock();
    if let Some(cb) = callback {
        cb(tgid, uaddr, max_wake)
    } else {
        0
    }
}

/// E.5 Cpuset: Register callback for task joining a cpuset
///
/// Called by sched::cpuset during initialization to register its task_joined function.
pub fn register_cpuset_task_joined(callback: CpusetTaskJoinedCallback) {
    *CPUSET_TASK_JOINED.lock() = Some(callback);
}

/// E.5 Cpuset: Register callback for task leaving a cpuset
///
/// Called by sched::cpuset during initialization to register its task_left function.
pub fn register_cpuset_task_left(callback: CpusetTaskLeftCallback) {
    *CPUSET_TASK_LEFT.lock() = Some(callback);
}

/// E.5 Cpuset: Notify that a task joined a cpuset
///
/// Called when a new process is created via fork/clone.
pub fn notify_cpuset_task_joined(cpuset_id: u32) {
    let callback = *CPUSET_TASK_JOINED.lock();
    if let Some(cb) = callback {
        cb(cpuset_id);
    }
}

/// E.5 Cpuset: Notify that a task left a cpuset
///
/// Called when a process exits.
pub fn notify_cpuset_task_left(cpuset_id: u32) {
    let callback = *CPUSET_TASK_LEFT.lock();
    if let Some(cb) = callback {
        cb(cpuset_id);
    }
}

/// 终止进程
pub fn terminate_process(pid: ProcessId, exit_code: i32) {
    if let Some(process) = get_process(pid) {
        let children_to_reparent: Vec<ProcessId>;
        let parent_pid: ProcessId;
        let clear_child_tid: u64;
        let tgid: ProcessId;
        let memory_space: usize;
        // R25-7 FIX: Save credentials for LSM exit hook
        let lsm_uid: u32;
        let lsm_gid: u32;
        let lsm_euid: u32;
        let lsm_egid: u32;
        // F.1: Save namespace info for cleanup
        let pid_ns_chain: Vec<crate::pid_namespace::PidNamespaceMembership>;
        // F.2: Save cgroup_id for task detachment
        let cgroup_id: crate::cgroup::CgroupId;
        // G.1: Save watchdog handle for unregistration
        let watchdog_handle: Option<WatchdogHandle>;

        {
            let mut proc = process.lock();
            proc.state = ProcessState::Zombie;
            proc.exit_code = Some(exit_code);
            parent_pid = proc.ppid;
            children_to_reparent = proc.children.clone();
            proc.children.clear();
            // 获取 clear_child_tid 信息用于线程退出通知
            clear_child_tid = proc.clear_child_tid;
            tgid = proc.tgid;
            memory_space = proc.memory_space;
            // 清除 clear_child_tid 避免重复处理
            proc.clear_child_tid = 0;
            // R25-7 + R39-3 FIX: Capture credentials from shared structure
            {
                let creds = proc.credentials.read();
                lsm_uid = creds.uid;
                lsm_gid = creds.gid;
                lsm_euid = creds.euid;
                lsm_egid = creds.egid;
            } // Drop creds read guard before mutable access below
            // F.1: Copy namespace chain for cleanup
            pid_ns_chain = proc.pid_ns_chain.clone();
            // F.2: Copy cgroup_id for detachment
            cgroup_id = proc.cgroup_id;
            // G.1: Take watchdog handle (process no longer needs it)
            watchdog_handle = proc.watchdog_handle.take();
        }

        // G.1 Observability: Unregister watchdog before any other cleanup.
        // This must happen early to prevent false hung-task alerts during teardown.
        if let Some(handle) = watchdog_handle {
            unregister_watchdog(&handle);
        }

        // R25-7 FIX: Call LSM task_exit hook for forced terminations (kill/seccomp paths)
        // This ensures policy can track ALL process exits, not just normal sys_exit
        let lsm_ctx = LsmProcessCtx::new(pid, tgid, lsm_uid, lsm_gid, lsm_euid, lsm_egid);
        let _ = lsm::hook_task_exit(&lsm_ctx, exit_code);

        // F.2: Detach from cgroup (decrement task count)
        // This must happen before other cleanup to maintain correct stats
        if let Some(cgroup) = crate::cgroup::lookup_cgroup(cgroup_id) {
            let _ = cgroup.detach_task(pid as u64);
        }

        // R69-2 FIX: Clear FPU ownership on all CPUs to prevent use-after-free.
        // If this process was the FPU owner on any CPU, its FPU state would be saved
        // to the PCB which is about to be deallocated. Clear ownership now.
        cpu_local::clear_fpu_owner_all_cpus(pid);

        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        klog_always!("Process {} terminated with exit code {}", pid, exit_code);

        // F.1 PID Namespace: Handle init death cascade
        //
        // If this process is the init (PID 1) of any namespace, all other processes
        // in that namespace must be killed (SIGKILL). This is Linux semantics.
        handle_namespace_init_death(pid, &pid_ns_chain);

        // F.1: Detach from all namespaces
        crate::pid_namespace::detach_pid_chain(&pid_ns_chain, pid);

        // 处理 clear_child_tid (CLONE_CHILD_CLEARTID)
        // 线程退出时将 clear_child_tid 地址处的值设为 0 并唤醒 futex
        if clear_child_tid != 0 && memory_space != 0 {
            // R24-3 fix: 写入 0 到 clear_child_tid 地址（SMAP + fault-tolerant）
            // 注意：需要在正确的地址空间中执行
            unsafe {
                use crate::usercopy::copy_to_user_safe;
                use x86_64::registers::control::Cr3;
                use x86_64::structures::paging::PhysFrame;
                use x86_64::PhysAddr;

                // R102-4 FIX: Disable interrupts around CR3 switch to prevent:
                // 1. Interrupt handlers running with the wrong page tables
                // 2. Timer interrupts triggering rescheduling in foreign address space
                // 3. KPTI context mismatch if interrupts load incorrect CR3
                x86_64::instructions::interrupts::without_interrupts(|| {
                    // 切换到目标进程的地址空间
                    let current_cr3 = Cr3::read();
                    let target_frame =
                        PhysFrame::containing_address(PhysAddr::new(memory_space as u64));
                    Cr3::write(target_frame, current_cr3.1);

                    // 将 0 写入 clear_child_tid 地址（带 SMAP 保护和容错处理）
                    // P1-6 FIX: Removed redundant outer UserAccessGuard —
                    // copy_to_user_safe creates its own guard internally.
                    let tid_ptr = clear_child_tid as *mut u8;
                    if (tid_ptr as usize) >= 0x1000 && (tid_ptr as usize) < 0x8000_0000_0000 {
                        let zero = 0i32.to_ne_bytes();
                        // 忽略写入错误（用户可能已 unmap 该地址）
                        let _ = copy_to_user_safe(tid_ptr, &zero);
                    }

                    // 恢复原来的地址空间
                    Cr3::write(current_cr3.0, current_cr3.1);
                });
            }

            // 唤醒等待在 clear_child_tid 地址上的 futex
            let woken = notify_futex_wake(tgid, clear_child_tid as usize, 1);
            if woken > 0 {
                // R102-L6 FIX: Gate address-revealing log behind debug_assertions
                kprintln!(
                    "  Woke {} waiters on clear_child_tid=0x{:x}",
                    woken, clear_child_tid
                );
                let _ = woken; // suppress unused warning in release
            }
        }

        // 将孤儿进程重新分配给 init 进程 (PID 1)
        if !children_to_reparent.is_empty() {
            reparent_orphans(&children_to_reparent);
        }

        // 唤醒等待此进程的父进程
        let mut wake_parent = false;

        if parent_pid > 0 {
            if let Some(parent) = get_process(parent_pid) {
                let mut parent_proc = parent.lock();
                let waiting = parent_proc.waiting_child;
                // 父进程正在等待，且等待的是任意子进程(0)或此特定子进程
                if parent_proc.state == ProcessState::Blocked
                    && (waiting == Some(0) || waiting == Some(pid))
                {
                    parent_proc.state = ProcessState::Ready;
                    parent_proc.waiting_child = None;
                    wake_parent = true;
                }
            }
        }

        // 在释放锁后触发调度，让被唤醒的父进程有机会运行
        if wake_parent {
            crate::force_reschedule();
        }
    }
}

/// F.1 PID Namespace: 将孤儿进程重新分配给正确的 init 进程
///
/// Orphans are reparented to the init process of their owning PID namespace,
/// not necessarily global PID 1. This ensures getppid() returns a valid PID
/// that is visible within the process's namespace.
fn reparent_orphans(orphans: &[ProcessId]) {
    const ROOT_INIT_PID: ProcessId = 1;

    for &child_pid in orphans {
        // Determine the init process of the child's owning PID namespace
        let adopt_pid = if let Some(child_proc) = get_process(child_pid) {
            let ns_init = {
                let child = child_proc.lock();
                crate::pid_namespace::owning_namespace(&child.pid_ns_chain)
                    .and_then(|ns| ns.init_global_pid())
            };
            // If namespace has an init, use it; otherwise fall back to root init
            ns_init.unwrap_or(ROOT_INIT_PID)
        } else {
            ROOT_INIT_PID
        };

        // Update child's recorded parent
        if let Some(child_process) = get_process(child_pid) {
            let mut child = child_process.lock();
            child.ppid = adopt_pid;
        }

        // Add to adopter's children list if the adopter exists
        if let Some(adopter) = get_process(adopt_pid) {
            let mut adopter_proc = adopter.lock();
            if !adopter_proc.children.contains(&child_pid) {
                adopter_proc.children.push(child_pid);
            }
        }
    }

    if !orphans.is_empty() {
        klog!(Info, "Reparented {} orphan process(es)", orphans.len());
    }
}

/// F.1 PID Namespace: Handle cascade killing when a namespace init dies
///
/// When the init process (PID 1) of a namespace exits, all other processes
/// in that namespace receive SIGKILL. This is Linux semantics to ensure
/// proper namespace teardown.
///
/// # Arguments
///
/// * `dying_pid` - The global PID of the exiting process
/// * `pid_ns_chain` - The namespace membership chain of the exiting process
fn handle_namespace_init_death(
    dying_pid: ProcessId,
    pid_ns_chain: &[crate::pid_namespace::PidNamespaceMembership],
) {
    use crate::signal::{send_signal, Signal};

    // Check each namespace in the chain (except root, which has no cascade)
    for membership in pid_ns_chain.iter() {
        // Skip root namespace - global PID 1 death is handled elsewhere
        if membership.ns.is_root() {
            continue;
        }

        // Check if this process is the init of this namespace
        if membership.ns.is_init(dying_pid) {
            // Mark namespace as shutting down
            if membership.ns.mark_shutting_down() {
                // R104-2 FIX: Gate to prevent leaking namespace IDs + PIDs.
                kprintln!(
                    "[PID NS] Init death cascade: namespace {} is shutting down (init pid={})",
                    membership.ns.id().raw(),
                    dying_pid
                );

                // Get all processes to kill (excluding the dying init itself)
                let victims = crate::pid_namespace::get_cascade_kill_pids(&membership.ns);

                if !victims.is_empty() {
                    // R104-2 FIX: Gate namespace cascade logging.
                    kprintln!(
                        "[PID NS] Sending SIGKILL to {} processes in namespace {}",
                        victims.len(),
                        membership.ns.id().raw()
                    );

                    for victim_pid in victims {
                        // Skip if victim is the dying process itself
                        if victim_pid == dying_pid {
                            continue;
                        }

                        // Send SIGKILL (uncatchable) to each process
                        match send_signal(victim_pid, Signal::SIGKILL) {
                            Ok(_) => {
                                // R104-2 FIX: Gate victim PID logging.
                                kprintln!(
                                    "[PID NS]   SIGKILL sent to PID {} (namespace cascade)",
                                    victim_pid
                                );
                            }
                            Err(e) => {
                                // Process may have already exited, ignore errors
                                // R104-2 FIX: Gate victim PID + error logging.
                                kprintln!(
                                    "[PID NS]   Failed to send SIGKILL to PID {}: {:?}",
                                    victim_pid, e
                                );
                                let _ = e; // suppress unused warning in release
                            }
                        }
                    }
                }
            }
            // Only one namespace can have this process as init
            // (processes are init only in their owning namespace)
            break;
        }
    }
}

/// 等待子进程
pub fn wait_process(pid: ProcessId) -> Option<i32> {
    if let Some(process) = get_process(pid) {
        let proc = process.lock();
        if proc.state == ProcessState::Zombie {
            return proc.exit_code;
        }
    }
    None
}

/// 清理僵尸进程
///
/// 完全移除进程：
/// 1. 释放进程持有的内存资源（mmap 区域）
/// 2. 从 PROCESS_TABLE 中移除
/// 3. 通知调度器移除该进程
pub fn cleanup_zombie(pid: ProcessId) {
    let removed = {
        let mut table = PROCESS_TABLE.lock();

        // R24-1 fix: 分两阶段处理，避免借用冲突
        // 阶段1：检查进程状态和共享情况
        let (memory_space, is_zombie) = {
            if let Some(slot) = table.get(pid) {
                if let Some(process) = slot {
                    let proc = process.lock();
                    if proc.state == ProcessState::Zombie {
                        (proc.memory_space, true)
                    } else {
                        (0, false)
                    }
                } else {
                    (0, false)
                }
            } else {
                (0, false)
            }
        };

        if !is_zombie {
            false
        } else {
            // 阶段2：检查是否有其他进程共享地址空间
            let keep_address_space = if memory_space == 0 {
                false
            } else {
                table.iter().enumerate().any(|(idx, other_slot)| {
                    if idx == pid {
                        return false;
                    }
                    if let Some(other_proc_arc) = other_slot {
                        let other = other_proc_arc.lock();
                        other.memory_space == memory_space
                            && other.state != ProcessState::Terminated
                    } else {
                        false
                    }
                })
            };

            // 阶段3：现在可以安全地获取可变引用并清理
            if let Some(slot) = table.get_mut(pid) {
                if let Some(process) = slot {
                    let mut proc = process.lock();
                    // 再次验证状态（防止并发修改）
                    if proc.state == ProcessState::Zombie {
                        free_process_resources(&mut proc, keep_address_space);
                        proc.state = ProcessState::Terminated;
                        drop(proc);
                        *slot = None;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        }
    };

    if removed {
        notify_scheduler_process_removed(pid);
        klog!(Info, "Cleaned up zombie process {}", pid);
    }
}

/// 释放进程持有的内核资源
///
/// - 释放 per-process 内核栈（取消映射并归还物理帧）
/// - 清理 mmap 区域跟踪信息
/// - 如果进程拥有独立页表（memory_space != 0），直接遍历该页表：
///   * 仅处理用户空间 PML4 条目 0-255
///   * 对叶子页减少 COW 引用计数并在归零时释放物理帧
///   * 递归释放中间页表帧，最后释放 PML4 帧本身
///
/// 恒等映射 0-4GB 允许将物理地址当作虚拟地址解引用。
///
/// # 当前限制
///
/// - **HUGE_PAGE**: 用户空间应仅使用 4KB 页面。若存在 2MB/1GB 大页映射，
///   当前实现会跳过以避免 buddy allocator 损坏。
///
/// # Arguments
///
/// * `proc` - 进程引用
/// * `keep_address_space` - R24-1 fix: 如果为 true，不释放地址空间（其他线程仍在使用）
fn free_process_resources(proc: &mut Process, keep_address_space: bool) {
    let region_count = proc.mmap_regions.len();
    let total_size: usize = proc.mmap_regions.values().sum();

    // 释放 per-process 内核栈
    if proc.kernel_stack.as_u64() != 0 {
        free_kernel_stack(proc.pid, proc.kernel_stack);
        proc.kernel_stack = VirtAddr::new(0);
        proc.kernel_stack_top = VirtAddr::new(0);
    }

    // 清理 mmap 区域跟踪
    proc.mmap_regions.clear();

    // 关闭并清理所有文件描述符
    // 通过 clear() 触发每个 FileDescriptor 的 Drop，自动释放管道等资源
    let fd_count = proc.fd_table.len();
    proc.fd_table.clear();
    // R104-2 FIX: Gate all resource-cleanup diagnostics behind debug_assertions
    // to prevent leaking fd count, page table root addresses, and PID in release.
    if fd_count > 0 {
        kprintln!(
            "  Closed {} file descriptors for process {}",
            fd_count, proc.pid
        );
    }

    // 如果进程拥有独立的页表（memory_space != 0），释放页表及其管理的物理帧
    // R24-1 fix: 检查是否有其他线程共享地址空间，只有在无共享引用时才释放
    // 如果该线程是最后持有者（keep_address_space 为 false），也要释放地址空间避免泄漏
    if proc.memory_space != 0 {
        if keep_address_space {
            // 线程或被共享的地址空间不释放，只清零引用
            if !proc.is_thread {
                kprintln!(
                    "  Deferred address space release for process {} (shared by other threads)",
                    proc.pid
                );
            }
            proc.memory_space = 0;
        } else {
            // R104-2 FIX: Capture root before free for debug print, but gate the
            // print behind debug_assertions to avoid leaking PT root addresses.
            #[cfg(debug_assertions)]
            let _saved_root = proc.memory_space;
            free_address_space(proc.memory_space);
            kprintln!(
                "  Released page table hierarchy for process {} (root=0x{:x})",
                proc.pid, _saved_root
            );
            proc.memory_space = 0;
        }
    }

    // 通知 IPC 子系统清理进程端点（通过回调避免循环依赖）
    // R37-2 FIX (Codex review): Pass TGID to avoid deadlock from re-locking this process
    // R75-2 FIX: Pass IPC namespace ID for per-namespace endpoint cleanup
    let ipc_ns_id = proc.ipc_ns.id();
    notify_ipc_process_cleanup(proc.pid, proc.tgid, ipc_ns_id);

    // E.5 Cpuset: decrement task count when process exits
    notify_cpuset_task_left(proc.cpuset_id);

    if region_count > 0 {
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
            "  Cleared {} mmap regions ({} KB) for process {}",
            region_count,
            total_size / 1024,
            proc.pid
        );
    }
}

/// 释放指定进程的内核栈
///
/// 取消内核栈页面的映射并归还物理帧。守护页从未映射故无需处理。
///
/// # Arguments
///
/// * `pid` - 进程 ID（用于日志）
/// * `stack_base` - 内核栈底地址
///
/// # Safety Notes
///
/// SMP 下可能存在其他 CPU 仍在引用该栈（例如其正在进行上下文切换）。
/// 因此，实际的取消映射与物理帧归还通过 `call_rcu()` 延迟到 RCU grace period
/// 之后执行，以确保所有 CPU 都已进入过 quiescent state。
///
/// 如果当前 CPU 正在使用该栈，则仍跳过释放以避免自踩栈导致崩溃。
pub fn free_kernel_stack(pid: ProcessId, stack_base: VirtAddr) {
    use core::arch::asm;
    use x86_64::structures::paging::Page;

    // H-25 FIX: call_rcu requires a 'static closure; capture the raw address
    // and reconstruct VirtAddr inside the deferred callback.
    let stack_base_u64 = stack_base.as_u64();

    // 【关键修复】检查当前 CPU 是否正在使用该栈
    let current_rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags));
    }

    let stack_bottom = stack_base_u64;
    let stack_top = stack_bottom + (KSTACK_PAGES as u64 * PAGE_SIZE);

    if current_rsp >= stack_bottom && current_rsp < stack_top {
        // 当前 CPU 正在使用此栈，不能释放（会导致自踩栈崩溃）
        // 这种情况不应该发生（进程应在不同栈上清理自己的栈），但防御性编程
        // R104-2 FIX: Gate to prevent leaking kernel RSP in release builds.
        kprintln!(
            "  WARNING: Skip releasing kernel stack for PID {} (in use by current CPU, RSP=0x{:x})",
            pid, current_rsp
        );
        return;
    }

    // H-25 FIX: Defer unmap + frame reclamation until after a grace period so
    // all CPUs (including ones that might still be switching away) have passed
    // a quiescent state.
    crate::rcu::call_rcu(move || {
        let stack_base = VirtAddr::new(stack_base_u64);
        let mut frame_alloc = FrameAllocator::new();

        unsafe {
            page_table::with_current_manager(VirtAddr::new(0), |mgr| {
                for i in 0..KSTACK_PAGES {
                    let addr = stack_base + (i as u64 * PAGE_SIZE);
                    let page = Page::containing_address(addr);

                    if let Ok(frame) = mgr.unmap_page(page) {
                        frame_alloc.deallocate_frame(frame);
                    }
                }
            });
        }

        // R104-2 FIX: Gate to prevent leaking kernel stack address in release builds.
        kprintln!(
            "  Released kernel stack for PID {} at 0x{:x}",
            pid, stack_base_u64
        );
    });
}

/// 释放独立用户地址空间（PML4 物理地址）
///
/// - 仅遍历用户空间映射 (PML4[0..255])
/// - 使用 COW 引用计数安全地释放叶子页
/// - 最后释放 PML4 帧本身
///
/// 调用者必须确保该地址空间不再被任何 CPU 使用。
pub fn free_address_space(memory_space: usize) {
    if memory_space == 0 {
        return;
    }

    unsafe {
        let mut frame_alloc = FrameAllocator::new();
        let root_frame: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(memory_space as u64));
        let root_table = phys_to_virt_table(root_frame.start_address());

        // 只遍历用户空间映射 (PML4 index 0-255)，内核高半区 (256-511) 共享无需处理
        free_page_table_level(root_table, 4, &mut frame_alloc);

        // 释放 PML4 帧本身
        frame_alloc.deallocate_frame(root_frame);
    }
}

/// 递归释放页表层级
///
/// level: 4=PML4, 3=PDPT, 2=PD, 1=PT
///
/// 直接使用 memory_space 的物理地址，通过恒等映射访问页表，避免依赖当前 CR3。
///
/// # Safety
///
/// 调用者必须确保 `table` 指向有效的页表，且页表不再被任何进程使用。
unsafe fn free_page_table_level(
    table: &mut PageTable,
    level: u8,
    frame_alloc: &mut FrameAllocator,
) {
    // PML4 只处理用户空间条目 (0-255)，其他层级处理全部 512 条目
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut table[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        let entry_phys = entry.addr();

        // 检查是否是大页 (2MB 或 1GB)
        //
        // R49-2 FIX: Previously this code skipped huge pages entirely, causing
        // memory leaks if user-space ever used huge pages. While user-space
        // typically doesn't use huge pages currently, we should:
        // 1. Clear the page table entry (defense-in-depth)
        // 2. Attempt to free the physical memory
        //
        // Note: Buddy allocator only tracks 4KB frames. For huge pages, we
        // release the base frame which may not fully reclaim the memory.
        // Future improvement: Extend buddy allocator for multi-page frees.
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // Release the huge page physical memory to prevent leak
            let huge_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(entry_phys);
            frame_alloc.deallocate_frame(huge_frame);

            // Clear the page table entry for defense-in-depth
            entry.set_unused();
            continue;
        }

        if level == 1 {
            // PT 层级的叶子节点：释放 4KB 物理帧
            free_leaf_frame(entry_phys, frame_alloc);
        } else {
            // 中间节点：递归处理子页表
            let next_table = phys_to_virt_table(entry_phys);
            free_page_table_level(next_table, level - 1, frame_alloc);

            // 释放子页表帧本身
            let next_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(entry_phys);
            frame_alloc.deallocate_frame(next_frame);
        }
    }
}

/// 释放叶子页物理帧
///
/// 使用 COW 引用计数管理：减少引用计数，当计数归零时释放物理帧。
/// 对于未被 COW 跟踪的页面（refcount=0），直接释放。
fn free_leaf_frame(phys: PhysAddr, frame_alloc: &mut FrameAllocator) {
    let phys_usize = phys.as_u64() as usize;

    // 检查是否在 COW 跟踪中
    let current_count = PAGE_REF_COUNT.get(phys_usize);

    if current_count > 0 {
        // COW 页面：减少引用计数
        let remaining = PAGE_REF_COUNT.decrement(phys_usize);
        if remaining == 0 {
            // 最后一个引用，释放物理帧
            let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(phys);
            frame_alloc.deallocate_frame(frame);
        }
    } else {
        // 未被 COW 跟踪的独占页面，直接释放
        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(phys);
        frame_alloc.deallocate_frame(frame);
    }
}

/// 将物理地址转换为页表引用（使用高半区直映）
///
/// # Safety
///
/// 调用者必须确保：
/// - 物理地址指向有效的页表
/// - 物理地址在 0-1GB 范围内（高半区直映覆盖的范围）
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 获取进程统计信息
pub fn get_process_stats() -> ProcessStats {
    let table = PROCESS_TABLE.lock();
    let mut stats = ProcessStats::default();

    // 遍历进程表，跳过 None 值
    for slot in table.iter() {
        if let Some(process) = slot {
            stats.total += 1;
            let proc = process.lock();
            // R98-1 FIX: Check orthogonal stopped flag before state.
            // Zombie/Terminated take priority, then stopped flag, then scheduler state.
            match proc.state {
                ProcessState::Zombie => stats.zombie += 1,
                ProcessState::Terminated => stats.terminated += 1,
                ProcessState::Stopped => stats.stopped += 1,
                _ if proc.stopped => stats.stopped += 1,
                ProcessState::Ready => stats.ready += 1,
                ProcessState::Running => stats.running += 1,
                ProcessState::Blocked => stats.blocked += 1,
                ProcessState::Sleeping => stats.sleeping += 1,
            }
        }
    }

    stats
}

/// 进程统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessStats {
    pub total: usize,
    pub ready: usize,
    pub running: usize,
    pub stopped: usize,
    pub blocked: usize,
    pub sleeping: usize,
    pub zombie: usize,
    pub terminated: usize,
}

impl ProcessStats {
    pub fn print(&self) {
        klog!(Info, "=== Process Statistics ===");
        klog!(Info, "Total:      {}", self.total);
        klog!(Info, "Ready:      {}", self.ready);
        klog!(Info, "Running:    {}", self.running);
        klog!(Info, "Stopped:    {}", self.stopped);
        klog!(Info, "Blocked:    {}", self.blocked);
        klog!(Info, "Sleeping:   {}", self.sleeping);
        klog!(Info, "Zombie:     {}", self.zombie);
        klog!(Info, "Terminated: {}", self.terminated);
    }
}

// ========== OOM Killer 回调实现 ==========

/// 为 OOM killer 生成进程快照
///
/// 返回所有可杀进程的信息，用于 OOM 评分和选择
pub fn oom_snapshot() -> Vec<mm::OomProcessInfo> {
    let table = PROCESS_TABLE.lock();
    let mut result = Vec::new();

    for slot in table.iter() {
        if let Some(process) = slot {
            let proc = process.lock();

            // 跳过僵尸和已终止的进程
            if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
                continue;
            }

            // 跳过 init 进程 (PID 1) - 永不杀死
            if proc.pid == 1 {
                continue;
            }

            // 计算 RSS（简化实现：使用 mmap 区域大小估算）
            let rss_pages = (proc.mmap_regions.values().sum::<usize>() / 4096) as u64;

            // R39-3 FIX: 使用共享凭证获取 uid/gid
            let creds = proc.credentials.read();
            result.push(mm::OomProcessInfo {
                pid: proc.pid,
                tgid: proc.tgid,
                uid: creds.uid,
                gid: creds.gid,
                rss_pages,
                nice: proc.nice,
                oom_score_adj: proc.oom_score_adj,
                has_mm: proc.memory_space != 0,
                is_kernel_thread: proc.memory_space == 0,
            });
        }
    }

    result
}

/// OOM killer 调用的进程终止函数
///
/// 使用指定的退出码终止进程
pub fn oom_kill(pid: ProcessId, exit_code: i32) {
    terminate_process(pid, exit_code);
}

/// OOM killer 调用的进程清理函数
///
/// 清理僵尸进程并释放资源
pub fn oom_cleanup(pid: ProcessId) {
    cleanup_zombie(pid);
}

/// OOM killer 调用的时间戳函数
///
/// 返回当前时间戳（毫秒）
pub fn oom_timestamp() -> u64 {
    time::current_timestamp_ms()
}

/// 注册 OOM killer 回调
///
/// 在内核初始化时调用，将进程管理函数注册到 OOM killer
pub fn register_oom_callbacks() {
    mm::register_oom_callbacks(oom_snapshot, oom_kill, oom_cleanup, oom_timestamp);
    klog!(Info, "  OOM killer callbacks registered");
}
