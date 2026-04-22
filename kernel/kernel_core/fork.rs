//! Fork系统调用实现
//!
//! 实现完整的进程复制功能，包含写时复制(COW)机制

use crate::process::{
    create_process, current_pid, free_address_space, free_kernel_stack, get_process, ProcessId,
    ProcessState,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use mm::memory::FrameAllocator;
use mm::page_table::with_pt_lock;
use spin::RwLock;
// G.1 Observability: Watchdog handle type for cleanup_partial_child
use trace::watchdog::{unregister_watchdog, WatchdogHandle};
use x86_64::{
    instructions::interrupts,
    registers::control::Cr3,
    structures::paging::{
        page_table::PageTableEntry, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

/// Fork系统调用的结果
pub enum ForkResult {
    /// 父进程返回值：子进程的PID
    Parent(ProcessId),
    /// 子进程返回值：0
    Child,
    /// 错误
    Error(ForkError),
}

/// Fork错误类型
#[derive(Debug, Clone, Copy)]
pub enum ForkError {
    /// 没有当前进程
    NoCurrentProcess,
    /// 无法获取进程信息
    ProcessNotFound,
    /// 内存分配失败
    MemoryAllocationFailed,
    /// 页表复制失败
    PageTableCopyFailed,
    /// 子进程创建失败（内核栈分配等）
    ProcessCreationFailed,
    /// F.2: Cgroup pids.max limit exceeded
    CgroupPidsLimitExceeded,
    /// R122-1 FIX: mmap_regions contains in-flight PENDING_MAP/PENDING_UNMAP entries;
    /// fork must be retried after the concurrent mmap/munmap completes.
    MmapTransientState,
}

/// 执行fork系统调用
///
/// 创建当前进程的完整副本，包括：
/// - 进程控制块（PCB）
/// - CPU上下文
/// - 内存空间（使用写时复制COW）
/// - 文件描述符表
///
/// # 返回值
///
/// - 父进程：返回子进程的PID
/// - 子进程：返回0
/// - 错误：返回错误码
pub fn sys_fork() -> Result<ProcessId, ForkError> {
    let current = current_pid().ok_or(ForkError::NoCurrentProcess)?;
    let parent_process = get_process(current).ok_or(ForkError::ProcessNotFound)?;

    // F.2: Check cgroup pids.max limit BEFORE creating any resources
    // This prevents fork bombs and ensures cgroup limits are enforced
    {
        let parent = parent_process.lock();
        if !crate::cgroup::check_fork_allowed(parent.cgroup_id) {
            return Err(ForkError::CgroupPidsLimitExceeded);
        }
    }

    // 捕获父进程信息后释放锁，避免 create_process 再次获取锁导致潜在问题
    let (parent_root, parent_pid, parent_prio, child_name) = {
        let parent = parent_process.lock();
        let root = if parent.memory_space == 0 {
            let (cr3, _) = Cr3::read();
            cr3.start_address().as_u64() as usize
        } else {
            parent.memory_space
        };
        (
            root,
            parent.pid,
            parent.priority,
            alloc::format!("{}-child", parent.name),
        )
    };

    // 创建子进程（此时未持有父进程锁，避免死锁）
    // Z-7: create_process 现在返回 Result，失败时正确传播错误
    let child_pid = create_process(child_name, parent_pid, parent_prio)
        .map_err(|_| ForkError::ProcessCreationFailed)?;

    // 重新获取父进程锁执行真正的 fork
    let mut parent = parent_process.lock();

    // F.2: Get parent's cgroup_id for child attachment
    let parent_cgroup_id = parent.cgroup_id;
    // R77-3 FIX: Also capture cpuset_id for rollback on cgroup attach failure.
    // notify_cpuset_task_joined is called inside fork_inner after critical
    // allocations succeed, so we need to roll back if cgroup attach fails.
    let parent_cpuset_id = parent.cpuset_id;

    // R152-5 FIX: Attach child to cgroup BEFORE the expensive fork_inner() PT copy.
    // This eliminates the pids.max TOCTOU window where multiple concurrent forks
    // all pass check_fork_allowed but waste kernel resources (kernel stack, PID,
    // page table copy) before attach_task() serially rejects them.
    let mut cgroup_attached = false;
    if let Some(cgroup) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
        if let Err(_) = cgroup.attach_task(child_pid as u64) {
            parent.children.retain(|&pid| pid != child_pid);
            drop(parent);
            cleanup_partial_child(child_pid);
            return Err(ForkError::CgroupPidsLimitExceeded);
        }
        cgroup_attached = true;
    }

    let result = fork_inner(&mut parent, child_pid, parent_root);

    if result.is_err() {
        // 从父进程子列表移除失败的占位 PID，防止悬挂
        parent.children.retain(|&pid| pid != child_pid);
        // R152-5: Detach from cgroup if we attached before fork_inner
        if cgroup_attached {
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
        }
        // H.0.9 FIX: Do NOT roll back cpuset task count on fork_inner failure.
        // (see original comment — cpuset join happens inside fork_inner after
        // frame allocation, so it was never incremented on this error path)
        drop(parent);
        cleanup_partial_child(child_pid);
    } else {

        // R138-1 FIX: Worst-case COW cgroup memory charging.
        //
        // COW fork shares physical frames but gives the child a full copy of
        // mmap_regions, brk, and elf_charged_bytes.  On child exit (or exec),
        // free_process_resources() / sys_exec() uncharges ALL of those bytes.
        // If the child was never charged for them, the parent's charges get
        // uncharged twice — driving memory_current below true physical usage
        // and allowing subsequent allocations to bypass memory.max.
        //
        // Fix: charge the child's cgroup for the full inherited virtual
        // footprint at fork time.  This is conservative (counts COW-shared
        // pages for both parent and child) but is fail-closed: the uncharge
        // on exit exactly cancels the charge here, keeping memory_current
        // accurate for every process independently.
        //
        // Locking note: fork_inner() copies mmap_regions, brk, and
        // elf_charged_bytes verbatim from parent to child.  Rather than
        // re-locking the child (which would nest parent→child locks and
        // widen the critical section), we compute the inherited footprint
        // directly from the already-held parent snapshot.
        let fork_charge_bytes: u64 = {
            let mut bytes: u64 = 0;

            // Sum non-PROT_NONE mmap regions (inherited verbatim from parent)
            for (&_base, &len_with_flags) in parent.mmap_regions.iter() {
                if (len_with_flags & crate::syscall::MMAP_REGION_FLAG_PROT_NONE) != 0 {
                    continue;
                }
                let len = crate::syscall::mmap_region_len(len_with_flags) as u64;
                bytes = bytes.saturating_add(len);
            }

            // Brk heap (inherited verbatim from parent)
            let heap_bytes = {
                const PAGE_SIZE: usize = 0x1000;
                let brk_aligned = (parent.brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let brk_start_aligned =
                    (parent.brk_start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                brk_aligned.saturating_sub(brk_start_aligned) as u64
            };
            bytes = bytes.saturating_add(heap_bytes);

            // ELF loader charges (inherited verbatim from parent)
            bytes = bytes.saturating_add(parent.elf_charged_bytes);

            bytes
        };

        if fork_charge_bytes > 0
            && crate::cgroup::try_charge_memory(parent_cgroup_id, fork_charge_bytes).is_err()
        {
            // Cgroup memory.max would be exceeded — roll back the entire fork.
            parent.children.retain(|&pid| pid != child_pid);
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            drop(parent);
            cleanup_partial_child(child_pid);
            return Err(ForkError::MemoryAllocationFailed);
        }
    }

    result
}

/// Fork 的内部实现，便于错误处理和回滚
fn fork_inner(
    parent: &mut crate::process::Process,
    child_pid: ProcessId,
    parent_root: usize,
) -> Result<ProcessId, ForkError> {
    // R122-1 FIX: Reject fork() while any mmap/munmap operation is in-flight.
    //
    // The three-phase mmap/munmap protocol (R121-4) encodes transient state in
    // the low 12 bits of each mmap_regions entry (PENDING_MAP / PENDING_UNMAP).
    // Committed entries always store page-aligned lengths (low 12 bits = 0).
    //
    // If a sibling thread (CLONE_VM) is between Phase 1 (reserve with PENDING
    // flag) and Phase 3 (commit by clearing flag), copying the entry into the
    // child — even after stripping the flag — produces an inconsistent child
    // address space: the region record says "mapped" but the page table may be
    // partially populated (PENDING_MAP) or partially torn down (PENDING_UNMAP).
    //
    // Returning MmapTransientState (mapped to EAGAIN) lets userspace retry.
    // This is fail-closed: any non-zero low bits block fork, covering future
    // transient flags as well.
    if parent
        .mmap_regions
        .values()
        .any(|&len_with_flags| len_with_flags & crate::syscall::MMAP_REGION_FLAG_TRANSIENT_MASK != 0)
    {
        return Err(ForkError::MmapTransientState);
    }

    if let Some(child_process) = get_process(child_pid) {
        let mut child = child_process.lock();

        // 分配子进程页表根
        let mut frame_alloc = FrameAllocator::new();
        let child_root_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        unsafe {
            zero_table(child_root_frame);
        }

        // 复制页表并设置 COW
        unsafe {
            if let Err(e) = copy_page_table_cow(
                parent_root,
                child_root_frame.start_address().as_u64() as usize,
            ) {
                // 页表复制失败，释放已分配的页表树
                // 注意：copy_page_table_cow 可能已经分配了部分子页表
                free_address_space(child_root_frame.start_address().as_u64() as usize);
                return Err(e);
            }
        }

        child.memory_space = child_root_frame.start_address().as_u64() as usize;

        // H.3 KPTI: Create a user-mode PML4 root for the child's COW-copied kernel PML4.
        //
        // The COW fork path allocates an independent kernel PML4 for the child, so the
        // KPTI user CR3 shadow must be built against that new root — it cannot share
        // the parent's user PML4 (which points into the parent's kernel PML4 sub-tables).
        if security::is_kpti_enabled() {
            match create_kpti_user_pml4(child.memory_space) {
                Ok((_user_frame, user_phys)) => {
                    child.user_memory_space = user_phys;
                }
                Err(e) => {
                    // User PML4 creation failed — roll back the child's kernel PML4.
                    free_address_space(child.memory_space);
                    child.memory_space = 0;
                    child.user_memory_space = 0;
                    return Err(e);
                }
            }
        } else {
            child.user_memory_space = 0;
        }

        // 复制 CPU 上下文（RAX 在下方置 0）
        child.context = parent.context;
        // Lazy FPU: inherit parent's FPU usage flag
        // If parent used FPU, the state in context.fx is valid and child inherits it
        child.fpu_used = parent.fpu_used;
        child.user_stack = parent.user_stack;
        // SMP: inherit CPU affinity from parent
        child.allowed_cpus = parent.allowed_cpus;

        // E.5 Cpuset: inherit cpuset from parent and update task count
        child.cpuset_id = parent.cpuset_id;
        crate::process::notify_cpuset_task_joined(parent.cpuset_id);

        // 子进程使用自己的内核栈（由 create_process -> allocate_kernel_stack 分配）
        // 复制父进程内核栈内容以保持返回路径一致
        let parent_top = parent.kernel_stack_top.as_u64();
        let parent_rsp = parent.context.rsp;
        let child_top = child.kernel_stack_top.as_u64();

        // 计算父进程已使用的栈空间
        let used = parent_top.saturating_sub(parent_rsp);
        let parent_stack_size = parent_top.saturating_sub(parent.kernel_stack.as_u64());

        if child_top != 0 && used > 0 && used <= parent_stack_size {
            // 子进程栈顶减去相同使用量 = 子进程 RSP
            let child_rsp = child_top - used;

            // 复制父栈内容到子栈
            unsafe {
                core::ptr::copy_nonoverlapping(
                    parent_rsp as *const u8,
                    child_rsp as *mut u8,
                    used as usize,
                );
            }

            child.context.rsp = child_rsp;

            // 调整 RBP（如果它指向父栈范围内）
            if parent.context.rbp >= parent_rsp && parent.context.rbp <= parent_top {
                // RBP 相对偏移保持不变
                let rbp_offset = parent.context.rbp - parent_rsp;
                child.context.rbp = child_rsp + rbp_offset;
            } else {
                // RBP 不在栈范围内，直接使用子栈顶
                child.context.rbp = child_rsp;
            }
        } else if child_top != 0 {
            // 无法复制栈，使用子栈顶作为起点
            child.context.rsp = child_top;
            child.context.rbp = child_top;
        }
        // 如果 child_top == 0，保持父进程的 rsp/rbp（回退到共享栈）

        // 克隆文件描述符表（每个 fd 调用 clone_box）
        for (&fd, desc) in parent.fd_table.iter() {
            child.fd_table.insert(fd, desc.clone_box());
        }

        // R39-4 FIX: 克隆 close-on-exec 标记集合
        //
        // fork 时子进程继承父进程的 CLOEXEC 标记，
        // 这些 fd 会在子进程 exec 时自动关闭
        child.cloexec_fds = parent.cloexec_fds.clone();

        // 克隆能力表（尊重 CLOFORK 标志）
        //
        // clone_for_fork() 会过滤掉带有 CLOFORK 标志的能力条目，
        // 并保持生成计数器的单调性以防止 wrap 攻击。
        child.cap_table = Arc::new(parent.cap_table.clone_for_fork());

        child.time_slice = parent.time_slice;
        child.cpu_time = 0;

        // E.4 Priority Inheritance: 继承基础动态优先级
        //
        // 子进程继承父进程的 base_dynamic_priority（未应用 PI 的优先级基线）。
        // 但不继承 pi_boosts（父进程持有的 futex 相关），子进程从空开始。
        // waiting_on_futex 也不继承（子进程未阻塞在任何 futex 上）。
        child.base_dynamic_priority = parent.base_dynamic_priority;
        // pi_boosts 和 waiting_on_futex 在 Process::new() 中已初始化为空

        // R39-3 FIX: 继承父进程的凭证（fork 创建独立副本）
        //
        // fork() 创建的子进程获得父进程凭证的克隆副本（独立 Arc）。
        // 这意味着子进程后续的 setuid/setgid 不会影响父进程。
        // 对于 CLONE_THREAD，sys_clone 中会处理共享凭证。
        let parent_creds = parent.credentials.read().clone();
        child.credentials = Arc::new(RwLock::new(parent_creds));
        child.umask = parent.umask;

        // 复制堆管理状态
        child.brk_start = parent.brk_start;
        child.brk = parent.brk;

        // R138-1 FIX: Inherit parent's ELF loader charges so the child's cgroup
        // accounting is complete under worst-case COW semantics.  The actual
        // cgroup charge for the child's full inherited footprint (mmap_regions +
        // brk + elf_charged_bytes) happens in sys_fork() after fork_inner returns.
        child.elf_charged_bytes = parent.elf_charged_bytes;

        // 复制 TLS 状态（FS/GS base）
        child.fs_base = parent.fs_base;
        child.gs_base = parent.gs_base;

        // F.2: 继承 Cgroup 成员关系
        // 子进程继承父进程的 cgroup，并注册到 cgroup 的任务列表
        child.cgroup_id = parent.cgroup_id;
        // Note: cgroup task tracking is done after process is fully created

        // R93-1 FIX: 继承 IPC/Network/User 命名空间（以及 for_children 默认值）
        // 防止 fork() 产生的子进程意外回落到 root namespace 造成隔离逃逸
        // 注：PID namespace 和 Mount namespace 已在 create_process() 中继承
        child.ipc_ns = parent.ipc_ns.clone();
        child.ipc_ns_for_children = parent.ipc_ns_for_children.clone();
        child.net_ns = parent.net_ns.clone();
        child.net_ns_for_children = parent.net_ns_for_children.clone();
        child.user_ns = parent.user_ns.clone();
        child.user_ns_for_children = parent.user_ns_for_children.clone();

        // 继承 Seccomp/Pledge 沙箱状态
        // - SeccompState.filters: Vec<Arc<SeccompFilter>> 通过 Arc 共享，避免深拷贝
        // - no_new_privs: 粘滞标志，一旦设置不可清除，必须继承
        // - pledge_state: 包含 promises 和 exec_promises（exec 后生效）
        child.seccomp_state = parent.seccomp_state.clone();
        child.pledge_state = parent.pledge_state.clone();

        // 复制线程支持状态
        // 【注意】fork 创建的是新进程，不是线程
        // - tid/tgid 设为子进程 pid（Process::new 已处理）
        // - is_thread = false（Process::new 已处理）
        // - clear_child_tid/set_child_tid 清零（子进程需要自己设置）
        child.clear_child_tid = 0;
        child.set_child_tid = 0;
        child.robust_list_head = 0;
        child.robust_list_len = 0;

        // R122-1 FIX: Transient PENDING_* entries are rejected at fork_inner()
        // entry above. Strip only transient in-flight flags when cloning committed
        // regions into the child, preserving persistent per-region flags (e.g.
        // PROT_NONE) so the child inherits correct region metadata.
        child.mmap_regions = parent
            .mmap_regions
            .iter()
            .map(|(&base, &len_with_flags)| {
                (base, len_with_flags & !crate::syscall::MMAP_REGION_FLAG_TRANSIENT_MASK)
            })
            .collect();
        child.next_mmap_addr = parent.next_mmap_addr;

        child.context.rax = 0; // 子进程返回值 0
        child.state = ProcessState::Ready;

        kprintln!(
            "Fork: parent={}, child={}, COW enabled",
            parent.pid, child.pid
        );
        Ok(child_pid)
    } else {
        Err(ForkError::ProcessNotFound)
    }
}

/// 清理失败的 fork 创建的部分子进程
fn cleanup_partial_child(child_pid: ProcessId) {
    use crate::process::PROCESS_TABLE;

    // 预先收集需要释放的资源，避免长时间持有 PROCESS_TABLE 锁
    // G.1: Also extract watchdog handle for unregistration
    // H.0.9: Also extract PID namespace chain for detachment outside lock
    let (kstack, addr_space, user_addr_space, watchdog_handle, pid_ns_chain): (
        Option<VirtAddr>,
        usize,
        usize,
        Option<WatchdogHandle>,
        Vec<crate::pid_namespace::PidNamespaceMembership>,
    ) = {
        let mut table = PROCESS_TABLE.lock();
        if let Some(slot) = table.get_mut(child_pid) {
            if let Some(process) = slot.take() {
                let mut proc = process.lock();
                (
                    if proc.kernel_stack.as_u64() != 0 {
                        Some(proc.kernel_stack)
                    } else {
                        None
                    },
                    proc.memory_space,
                    proc.user_memory_space, // H.3 KPTI: capture for cleanup
                    // G.1: Take watchdog handle to unregister outside lock
                    proc.watchdog_handle.take(),
                    // H.0.9: Capture PID namespace chain for detachment outside lock.
                    // create_process() calls assign_pid_chain(), so the chain is populated
                    // even for partially-constructed children. Without detachment, the
                    // namespace PID slots leak and are never reclaimed.
                    proc.pid_ns_chain.clone(),
                )
            } else {
                (None, 0, 0, None, Vec::new())
            }
        } else {
            (None, 0, 0, None, Vec::new())
        }
    };

    // G.1 Observability: Unregister watchdog before releasing other resources
    // This prevents false hung-task alerts for the partially-created process
    if let Some(handle) = watchdog_handle {
        unregister_watchdog(&handle);
    }

    // H.0.9: Detach PID namespace chain to reclaim namespace PID slots.
    // Must be done outside PROCESS_TABLE lock to avoid lock ordering violation.
    if !pid_ns_chain.is_empty() {
        crate::pid_namespace::detach_pid_chain(&pid_ns_chain, child_pid);
    }

    // 在 PROCESS_TABLE 锁外释放资源
    if let Some(stack_base) = kstack {
        free_kernel_stack(child_pid, stack_base);
    }
    // H.3 KPTI: Free user PML4 root BEFORE kernel PML4.
    // User-half entries are shared pointers into the kernel PML4's sub-tables,
    // so the root must be deallocated before those sub-tables are freed.
    if user_addr_space != 0 {
        free_kpti_user_pml4(user_addr_space);
    }
    if addr_space != 0 {
        free_address_space(addr_space);
    }

    kprintln!("Fork failed: cleaned up partial child PID {}", child_pid);
}

/// 实现写时复制(Copy-On-Write)的页表复制
///
/// 这是fork的关键优化：
/// 1. 将父进程的所有可写页标记为只读
/// 2. 子进程共享这些页
/// 3. 当任一进程尝试写入时，触发页错误
/// 4. 页错误处理程序复制该页并更新页表
///
/// # Z-8 fix: 两阶段 COW 实现
///
/// 为防止内存分配失败时父进程 PTE 残留 COW 修改，采用两阶段处理：
/// 1. **规划阶段**：遍历页表收集叶子修改计划和所需中间页表帧数量
/// 2. **预分配阶段**：预分配所有中间页表帧（若失败，父进程未被修改）
/// 3. **应用阶段**：使用预分配帧应用所有 COW 修改（保证不会失败）
///
/// # R67-6 FIX: Cross-CPU Serialization
///
/// Acquires the global page table lock (PT_LOCK) to prevent concurrent
/// mmap/munmap/pagefault operations from racing with COW setup. This ensures
/// no parent thread can modify the address space while fork is flipping flags.
///
/// # Safety
///
/// 此函数直接操作页表，必须确保：
/// - 页表结构有效
/// - 有足够的物理内存
pub unsafe fn copy_page_table_cow(
    parent_page_table: usize,
    child_page_table: usize,
) -> Result<(), ForkError> {
    // R67-6 FIX: Hold PT_LOCK during entire COW setup to prevent concurrent
    // mmap/munmap/pagefault from racing with parent PTE modifications.
    with_pt_lock(|| {
        let mut frame_alloc = FrameAllocator::new();
        let parent_root: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(parent_page_table as u64));
        let child_root: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(child_page_table as u64));

        let parent_pml4 = phys_to_virt_table(parent_root.start_address());
        let child_pml4 = phys_to_virt_table(child_root.start_address());

        // 复制内核高半区映射（索引 256-511）
        for i in 256..512 {
            child_pml4[i] = parent_pml4[i].clone();
        }

        // Z-8 fix: 两阶段 COW
        // 阶段 1: 规划 - 收集叶子修改计划和所需中间页表帧数量
        let mut plan = CowClonePlan::new();
        plan_clone_level(parent_pml4, 4, &mut plan)?;

        // 阶段 2: 预分配所有中间页表帧
        // 若分配失败，此时父进程未被修改，直接返回错误即可
        let table_frames = preallocate_table_frames(plan.tables_needed, &mut frame_alloc)?;

        // 阶段 3: 应用所有 COW 修改（使用预分配帧，保证不会失败）
        let mut leaf_cursor = 0usize;
        let mut frame_iter = table_frames.into_iter();
        apply_clone_level(
            parent_pml4,
            child_pml4,
            &mut frame_iter,
            &plan,
            &mut leaf_cursor,
            4,
        )?;
        debug_assert_eq!(leaf_cursor, plan.leaf_updates.len());

        // R23-1 fix: 父进程页表被改成只读+BIT_9，需要刷新 TLB 才能生效
        // 使用 TLB shootdown 机制，为 SMP 支持做准备
        // 当前单核模式下，只做本地 flush
        mm::flush_current_as_all();

        kprintln!(
            "COW page table copy: parent=0x{:x}, child=0x{:x}, leaves={}, tables={}",
            parent_page_table,
            child_page_table,
            plan.leaf_updates.len(),
            plan.tables_needed
        );

        Ok(())
    })
}

/// 处理写时复制的页错误
///
/// 当进程尝试写入COW页时调用
///
/// # R65-21 FIX: Race Condition Prevention
///
/// This function now uses a global lock to serialize COW page fault handling.
/// Without synchronization, two threads writing to the same COW page simultaneously
/// could cause:
/// - Both threads unmapping/mapping independently
/// - Double-decrementing the old page's reference count (use-after-free)
/// - One thread's new mapping being overwritten by the other
///
/// The lock ensures only one COW resolution happens at a time. After acquiring
/// the lock, we re-check if the page is still COW (another thread may have
/// resolved it while we were waiting).
///
/// # Arguments
///
/// * `pid` - 触发页错误的进程ID
/// * `fault_addr` - 导致错误的虚拟地址
///
/// # Safety
///
/// 此函数分配新的物理页并更新页表
pub unsafe fn handle_cow_page_fault(pid: ProcessId, fault_addr: usize) -> Result<(), ForkError> {
    use mm::page_table::with_current_manager;
    use spin::Mutex;

    // R65-21 FIX: Global lock to serialize COW page fault handling.
    // This prevents race conditions when multiple threads fault on the same COW page.
    // Using a static Mutex ensures all COW faults are serialized.
    // Note: In SMP future, this could be made per-page or per-address-space for better scalability.
    static COW_FAULT_LOCK: Mutex<()> = Mutex::new(());
    let _cow_guard = COW_FAULT_LOCK.lock();

    let virt = VirtAddr::new(fault_addr as u64);
    let page = Page::containing_address(virt);

    // R114-3 FIX: ALL PTE flag reads are now performed under PT_LOCK inside
    // `with_current_manager()`. Previously, `find_pte()` read flags outside the lock,
    // creating a TOCTOU race on SMP with CLONE_THREAD|CLONE_VM: another thread
    // could `munmap`/`mprotect` the page between the unlocked `find_pte()` read and
    // the locked `with_current_manager()` use, leading to stale-flags decisions
    // and potential use-after-free or wrong-frame deallocation.

    // 使用基于当前 CR3 的页表管理器，确保操作正确的地址空间
    let mut frame_alloc = FrameAllocator::new();

    with_current_manager(VirtAddr::new(0), |manager| -> Result<(), ForkError> {
        // R114-3 FIX: Read PTE flags UNDER PT_LOCK via translate_with_flags().
        // This eliminates the TOCTOU window that existed when find_pte() was called
        // outside the lock scope.
        let (old_phys, flags) = manager
            .translate_with_flags(virt)
            .ok_or(ForkError::PageTableCopyFailed)?;

        // R65-21 FIX: After acquiring the lock, re-check if the page is still COW.
        // Another thread may have resolved this COW fault while we were waiting for the lock.
        // If COW flag is no longer set, check if the page is now writable:
        // - If writable: another thread resolved it, flush TLB and return Ok
        // - If not writable: this was never a COW page, return error to let caller handle it
        if !flags.contains(cow_flag()) {
            if flags.contains(PageTableFlags::WRITABLE) {
                // COW already resolved by another thread, just ensure TLB is consistent
                // R68-4 FIX: Use cross-CPU shootdown to ensure all CPUs see the resolution.
                // On SMP, other CPUs sharing this address space may have stale TLB entries.
                mm::flush_current_as_page(virt);
                return Ok(());
            } else {
                // Page is not COW and not writable - this is NOT a COW fault
                // Return error so caller can handle it appropriately (e.g., SIGSEGV)
                return Err(ForkError::PageTableCopyFailed);
            }
        }

        let old_frame = PhysFrame::containing_address(old_phys);

        // 分配新物理页
        let new_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;

        // 复制页内容（使用高半区直映访问物理内存）
        let old_virt = mm::phys_to_virt(old_frame.start_address());
        let new_virt = mm::phys_to_virt(new_frame.start_address());
        core::ptr::copy_nonoverlapping(old_virt.as_ptr::<u8>(), new_virt.as_mut_ptr::<u8>(), 4096);

        // H-35 fix: Check unmap result - if it fails, deallocate the new frame and return error
        if manager.unmap_page(page).is_err() {
            frame_alloc.deallocate_frame(new_frame);
            return Err(ForkError::PageTableCopyFailed);
        }

        // 设置新标志：移除 COW，添加 WRITABLE
        // R114-3 FIX: `flags` is guaranteed fresh — read under PT_LOCK above.
        let mut new_flags = flags;
        new_flags.remove(cow_flag());
        new_flags.insert(PageTableFlags::WRITABLE);

        // H-35 fix: If map fails, try to restore the old mapping to avoid page loss
        if let Err(_) = manager.map_page(page, new_frame, new_flags, &mut frame_alloc) {
            // Attempt to restore the old mapping
            let _ = manager.map_page(page, old_frame, flags, &mut frame_alloc);
            // R68-4 FIX: Flush TLB on all CPUs sharing this address space.
            // Use cross-CPU shootdown to ensure the restored mapping is visible.
            mm::flush_current_as_page(virt);
            // Deallocate the new frame we allocated
            frame_alloc.deallocate_frame(new_frame);
            return Err(ForkError::PageTableCopyFailed);
        }

        // H-35 & R68-4 FIX: Flush TLB on ALL CPUs to ensure the new writable mapping is effective.
        //
        // On SMP, other CPUs in the same address space may have the old COW (read-only) TLB
        // entry cached. Without cross-CPU shootdown, they would continue to trigger COW faults
        // or write to the old frame, causing memory corruption or use-after-free.
        mm::flush_current_as_page(virt);

        // 减少原页引用计数
        // R114-3 FIX (Codex review): Use page-aligned frame address for refcount key,
        // not the offset-adjusted `old_phys`. `translate_with_flags()` returns
        // `frame.start_address() + offset`, but refcount keys are page-aligned
        // (set by `PAGE_REF_COUNT.increment(entry.addr().as_u64() as usize)` in fork).
        // Using unaligned `old_phys` would miss the entry and return 0, causing
        // premature frame deallocation.
        let remaining = PAGE_REF_COUNT.decrement(old_frame.start_address().as_u64() as usize);
        if remaining == 0 {
            frame_alloc.deallocate_frame(old_frame);
        }

        kprintln!(
            "COW page fault: pid={}, addr=0x{:x} resolved",
            pid, fault_addr
        );
        Ok(())
    })
}

/// 物理页引用计数管理
///
/// 使用 RwLock + AtomicU64 实现中断安全的引用计数：
/// - 读取操作只需 RwLock 读锁，高并发友好
/// - 原子操作确保增减引用不需要等待写锁
/// - 新增条目时禁用中断获取写锁，避免死锁
pub struct PhysicalPageRefCount {
    /// 物理页地址 -> 原子引用计数
    /// 使用 AtomicU64 避免在中断上下文中获取锁
    ref_counts: Arc<RwLock<alloc::collections::BTreeMap<usize, AtomicU64>>>,
}

impl PhysicalPageRefCount {
    pub fn new() -> Self {
        PhysicalPageRefCount {
            ref_counts: Arc::new(RwLock::new(alloc::collections::BTreeMap::new())),
        }
    }

    /// 增加页的引用计数
    ///
    /// 快速路径：如果条目已存在，只需原子增加
    /// 慢速路径：禁用中断并获取写锁创建新条目
    pub fn increment(&self, phys_addr: usize) -> u64 {
        // 快速路径：尝试读锁查找已存在的条目
        if let Some(count) = self.ref_counts.read().get(&phys_addr) {
            return count.fetch_add(1, Ordering::SeqCst) + 1; // lint-fetch-add: allow (statistics counter)
        }

        // 慢速路径：禁用中断以安全获取写锁
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            // Double-check：可能在等待写锁期间被其他 CPU 创建
            let entry = counts.entry(phys_addr).or_insert_with(|| AtomicU64::new(0));
            entry.fetch_add(1, Ordering::SeqCst) + 1 // lint-fetch-add: allow (statistics counter)
        })
    }

    /// 减少页的引用计数
    ///
    /// 返回更新后的引用计数。如果为 0 则调用者可以释放该页。
    /// 使用 CAS 循环确保原子性。
    /// 【M-15 修复】当引用计数归零时，自动从映射中移除条目以防止内存泄漏
    ///
    /// # R69-1 FIX: Atomic Decrement + Removal
    ///
    /// Previous two-phase approach (read-lock CAS, then write-lock removal) had a TOCTOU
    /// vulnerability: between releasing read lock and calling remove_entry(), a concurrent
    /// increment() could resurrect the entry, causing use-after-free when caller frees
    /// the frame based on the returned 0.
    ///
    /// Now uses a single write-lock section with interrupts disabled to ensure atomicity
    /// of decrement + removal. This eliminates the ABA window at the cost of slightly
    /// higher contention (all decrements now need write lock instead of read lock).
    pub fn decrement(&self, phys_addr: usize) -> u64 {
        // R69-1 FIX: Single atomic section eliminates ABA race condition.
        // By holding the write lock throughout decrement + removal, no concurrent
        // increment can resurrect the entry after we observe count == 0.
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            if let Some(count) = counts.get(&phys_addr) {
                let mut prev = count.load(Ordering::SeqCst);
                while prev > 0 {
                    match count.compare_exchange(prev, prev - 1, Ordering::SeqCst, Ordering::SeqCst)
                    {
                        Ok(_) => {
                            let new_val = prev - 1;
                            if new_val == 0 {
                                // Remove entry immediately while still holding the lock
                                counts.remove(&phys_addr);
                            }
                            return new_val;
                        }
                        Err(actual) => prev = actual,
                    }
                }
            }
            0
        })
    }

    /// 移除指定地址的引用计数条目（引用计数归零时调用）
    fn remove_entry(&self, phys_addr: usize) {
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            // 二次检查确保确实归零（防止并发increment竞态）
            if let Some(entry) = counts.get(&phys_addr) {
                if entry.load(Ordering::SeqCst) == 0 {
                    counts.remove(&phys_addr);
                }
            }
        });
    }

    /// 获取页的引用计数
    pub fn get(&self, phys_addr: usize) -> u64 {
        self.ref_counts
            .read()
            .get(&phys_addr)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 移除引用计数为 0 的条目（可选清理）
    pub fn cleanup_zero_entries(&self) {
        interrupts::without_interrupts(|| {
            let mut counts = self.ref_counts.write();
            counts.retain(|_, v| v.load(Ordering::Relaxed) > 0);
        });
    }
}

/// 全局物理页引用计数器
lazy_static::lazy_static! {
    pub static ref PAGE_REF_COUNT: PhysicalPageRefCount = PhysicalPageRefCount::new();
}

// ============================================================================
// COW 辅助函数
// ============================================================================

/// COW 标志位（使用 BIT_9，这是 x86_64 页表中可供软件使用的位）
#[inline]
const fn cow_flag() -> PageTableFlags {
    PageTableFlags::BIT_9
}

// ============================================================================
// Z-8 fix: 两阶段 COW 实现
// ============================================================================

/// 记录叶子节点需要应用的 COW 修改
///
/// 存储父 PTE 指针、原始标志和物理地址，用于应用阶段
struct LeafUpdate {
    /// 父进程页表项指针
    entry_ptr: *mut PageTableEntry,
    /// 原始标志
    original_flags: PageTableFlags,
    /// 物理地址
    phys_addr: PhysAddr,
}

/// 记录 COW 复制计划
///
/// 包含所有叶子修改和需要的中间页表帧数量
struct CowClonePlan {
    /// 叶子节点修改列表
    leaf_updates: Vec<LeafUpdate>,
    /// 需要的中间页表帧数量
    tables_needed: usize,
}

impl CowClonePlan {
    fn new() -> Self {
        CowClonePlan {
            leaf_updates: Vec::new(),
            tables_needed: 0,
        }
    }

    fn record_leaf(&mut self, entry: &mut PageTableEntry) {
        self.leaf_updates.push(LeafUpdate {
            entry_ptr: entry as *mut PageTableEntry,
            original_flags: entry.flags(),
            phys_addr: entry.addr(),
        });
    }
}

/// 第一阶段：规划 - 遍历收集叶子修改计划并统计需要的新页表帧数量
///
/// 此阶段不修改任何页表项，仅收集信息
fn plan_clone_level(
    parent: &mut PageTable,
    level: u8,
    plan: &mut CowClonePlan,
) -> Result<(), ForkError> {
    // 只处理用户空间（PML4 的索引 0-255）
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut parent[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 叶子节点：记录到计划中
            plan.record_leaf(entry);
        } else {
            // 中间节点：计数并递归
            plan.tables_needed += 1;
            let parent_next = unsafe { phys_to_virt_table(entry.addr()) };
            plan_clone_level(parent_next, level - 1, plan)?;
        }
    }
    Ok(())
}

/// 第二阶段：预分配所有需要的中间页表帧
///
/// 若分配失败，此时父进程未被修改，直接返回错误即可
///
/// # Z-8b fix: 部分分配失败时回收已分配的帧
///
/// 当分配第 N 个帧失败时，回收已分配的 0..N-1 个帧，
/// 避免物理帧泄漏导致内存 DoS。
fn preallocate_table_frames(
    count: usize,
    frame_alloc: &mut FrameAllocator,
) -> Result<Vec<PhysFrame<Size4KiB>>, ForkError> {
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        match frame_alloc.allocate_frame() {
            Some(frame) => frames.push(frame),
            None => {
                // Z-8b fix: 回收已分配的帧，避免部分失败导致物理帧泄漏
                for frame in frames.drain(..) {
                    frame_alloc.deallocate_frame(frame);
                }
                return Err(ForkError::MemoryAllocationFailed);
            }
        }
    }
    Ok(frames)
}

/// 第三阶段：应用 - 使用预分配帧克隆页表并按计划应用 COW 修改
///
/// 此阶段使用预分配帧，保证不会因为内存分配失败而中途退出
fn apply_clone_level(
    parent: &mut PageTable,
    child: &mut PageTable,
    frames: &mut impl Iterator<Item = PhysFrame<Size4KiB>>,
    plan: &CowClonePlan,
    leaf_cursor: &mut usize,
    level: u8,
) -> Result<(), ForkError> {
    // 只处理用户空间（PML4 的索引 0-255）
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut parent[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 叶子节点：应用 COW 修改
            let planned = plan
                .leaf_updates
                .get(*leaf_cursor)
                .ok_or(ForkError::PageTableCopyFailed)?;
            *leaf_cursor += 1;
            apply_leaf(entry, &mut child[idx], planned)?;
        } else {
            // 中间节点：使用预分配帧
            let frame = frames.next().ok_or(ForkError::MemoryAllocationFailed)?;
            unsafe {
                zero_table(frame);
            }

            child[idx].set_addr(frame.start_address(), entry.flags());

            let parent_next = unsafe { phys_to_virt_table(entry.addr()) };
            let child_next = unsafe { phys_to_virt_table(frame.start_address()) };
            apply_clone_level(
                parent_next,
                child_next,
                frames,
                plan,
                leaf_cursor,
                level - 1,
            )?;
        }
    }
    Ok(())
}

/// 应用单个叶子的 COW 修改
///
/// 使用第一阶段记录的原始状态进行修改
fn apply_leaf(
    parent_entry: &mut PageTableEntry,
    child_entry: &mut PageTableEntry,
    planned: &LeafUpdate,
) -> Result<(), ForkError> {
    // 验证计划匹配（调试断言）
    debug_assert_eq!(
        planned.entry_ptr, parent_entry as *mut PageTableEntry,
        "COW plan mismatch: entry pointer doesn't match"
    );

    let addr = planned.phys_addr;
    let mut flags = planned.original_flags;
    let addr_usize = addr.as_u64() as usize;

    // 处理已经是 COW 的页面（来自之前的 fork）
    if flags.contains(cow_flag()) {
        // 已经是 COW，给新子进程增加一份引用
        PAGE_REF_COUNT.increment(addr_usize);
    } else if flags.contains(PageTableFlags::WRITABLE) {
        // 如果页面可写，则标记为 COW
        flags.remove(PageTableFlags::WRITABLE);
        flags.insert(cow_flag());

        // 更新父进程页表项
        parent_entry.set_addr(addr, flags);

        // 增加引用计数（父进程和子进程各一次）
        PAGE_REF_COUNT.increment(addr_usize);
        PAGE_REF_COUNT.increment(addr_usize);
    } else if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        // 【关键修复】只读用户页面（如代码段）也在进程间共享
        // 缺少引用计数会导致父进程退出时页面被释放，而子进程仍在使用
        //
        // 【TOCTOU 修复】使用一次原子加返回旧值的方式避免 get()+increment 竞态：
        // - increment() 返回更新后的值，减 1 得到旧值
        // - 如果旧值为 0，说明是首次跟踪此页面，需要补记父进程的引用
        // - 如果旧值 > 0，说明已有其他进程在跟踪，只需为子进程增加引用
        let new_count = PAGE_REF_COUNT.increment(addr_usize); // 子进程持有引用
        let prev = new_count.saturating_sub(1); // 计算旧值
        if prev == 0 {
            // 首次跟踪此页面时，补记父进程的持有
            PAGE_REF_COUNT.increment(addr_usize);
        }
    }

    // 子进程使用相同的映射
    child_entry.set_addr(addr, flags);
    Ok(())
}

/// 查找虚拟地址对应的页表项
///
/// R114-3 FIX: DEPRECATED — This function reads PTE flags without holding PT_LOCK, creating
/// TOCTOU races on SMP. Use `PageTableManager::translate_with_flags()` under PT_LOCK instead.
/// Retained only for potential future diagnostic use; all production callers must use the
/// lock-held API.
#[allow(dead_code)]
fn find_pte(addr: VirtAddr) -> Option<&'static mut PageTableEntry> {
    let (root, _) = Cr3::read();
    let mut table = unsafe { phys_to_virt_table(root.start_address()) };

    let idxs: [usize; 4] = [
        usize::from(addr.p4_index()),
        usize::from(addr.p3_index()),
        usize::from(addr.p2_index()),
        usize::from(addr.p1_index()),
    ];

    for (depth, idx) in idxs.iter().copied().enumerate() {
        let entry = unsafe { &mut *(&mut table[idx] as *mut PageTableEntry) };
        if entry.is_unused() {
            return None;
        }
        if depth == 3 {
            return Some(entry);
        }
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None; // 大页不支持 COW
        }
        table = unsafe { phys_to_virt_table(entry.addr()) };
    }
    None
}

/// 将物理地址转换为页表引用
///
/// # Safety
///
/// 调用者必须确保物理地址指向有效的页表
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    // 使用高半区直映访问物理内存
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 将物理帧清零
unsafe fn zero_table(frame: PhysFrame) {
    let virt = mm::phys_to_virt(frame.start_address());
    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
}

/// 创建新的用户地址空间
///
/// 分配新的 PML4 页表并复制内核高半区映射（索引 256-511）。
/// 用户空间（索引 0-255）为空，供后续 ELF 加载使用。
///
/// # Returns
///
/// 成功返回新 PML4 的物理帧和物理地址，失败返回 ForkError
///
/// # Safety
///
/// 返回的页表必须在使用完毕后释放，否则会内存泄漏。
pub fn create_fresh_address_space() -> Result<(PhysFrame<Size4KiB>, usize), ForkError> {
    let mut frame_alloc = FrameAllocator::new();

    // 分配新的 PML4 帧
    let new_pml4_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;

    // 清零新页表
    unsafe {
        zero_table(new_pml4_frame);
    }

    // 获取当前页表根（复制内核映射）
    let (current_frame, _) = Cr3::read();

    // 递归页表槽索引 (PML4[510] 指向 PML4 自身)
    const RECURSIVE_INDEX: usize = 510;

    unsafe {
        let current_pml4 = phys_to_virt_table(current_frame.start_address());
        let new_pml4 = phys_to_virt_table(new_pml4_frame.start_address());

        // 【关键修复】深拷贝 PML4[0] 并为用户空间准备 4KB 页映射
        //
        // PML4[0] 包含恒等映射（0-4GB），使用 2MB 大页。
        // 用户空间需要 4KB 页映射，所以我们需要：
        // 1. 深拷贝 PML4[0] 路径上的页表（避免影响内核的恒等映射）
        // 2. 将用户空间区域（0x400000 附近）的 2MB 大页拆分为 4KB 页
        if !current_pml4[0].is_unused() {
            deep_copy_identity_for_user(current_pml4, new_pml4, &mut frame_alloc)?;
        }

        // 复制内核高半区映射（索引 256-511）
        // 这些映射在所有进程间共享
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on kernel high-half entries.
        // Defense-in-depth: even if parent entries are corrupted with U/S bit,
        // child address space must not inherit user-accessibility to kernel space.
        for i in 256..512 {
            new_pml4[i] = current_pml4[i].clone();
            if !new_pml4[i].is_unused() {
                let addr = new_pml4[i].addr();
                let mut flags = new_pml4[i].flags();
                flags.remove(PageTableFlags::USER_ACCESSIBLE);
                new_pml4[i].set_addr(addr, flags);
            }
        }

        // 【关键修复】设置新页表的递归映射
        // PML4[510] 必须指向新的 PML4 帧自身，而不是从 boot 页表复制的旧值
        // 这样 recursive_pml4() 等函数才能正确访问新页表的条目
        let recursive_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        new_pml4[RECURSIVE_INDEX].set_frame(new_pml4_frame, recursive_flags);
    }

    let phys_addr = new_pml4_frame.start_address().as_u64() as usize;
    Ok((new_pml4_frame, phys_addr))
}

/// H.3 KPTI: Create a user-mode PML4 root for KPTI dual page tables.
///
/// The user PML4 provides the address space visible under the user CR3:
/// - **User half (PML4[0..255])**: Shares the same sub-table pointers as the
///   kernel PML4. Both roots see identical user-space mappings without duplicating
///   page table frames below PML4 level.
/// - **Kernel half (PML4[256..510])**: Empty — kernel text/data/heap is NOT mapped.
///   This is the core KPTI isolation property.
/// - **Entry island (PML4[511])**: Copied from the kernel PML4 to ensure the
///   syscall/interrupt entry stubs, GS-based per-CPU data, IDT, GDT, and TSS
///   remain accessible before the CR3 switch to kernel mode. Mapped as
///   supervisor-only (USER_ACCESSIBLE cleared).
/// - **Recursive slot (PML4[510])**: Explicitly empty — user CR3 must not have
///   self-referencing page table access.
///
/// # Bring-Up Note
///
/// The current PML4[511] copy is a coarse mapping that exposes more kernel pages
/// than strictly necessary (the entire high-half direct-map region covered by that
/// single PML4 entry). A production KPTI implementation should replace this with a
/// page-granular trampoline island. However, all entries remain supervisor-only,
/// so user-mode code cannot access them — the exposure is only to Meltdown-class
/// speculative reads, which KPTI is designed to mitigate.
///
/// # Lifetime
///
/// The user PML4 root frame is privately owned. User-half entries are shared
/// pointers into the kernel PML4's sub-tables and MUST NOT be recursively freed.
/// Call `free_kpti_user_pml4()` to release only the root frame.
///
/// # Arguments
///
/// * `kernel_pml4_phys` - Physical address of the kernel PML4 root
///
/// # Returns
///
/// `(PhysFrame, usize)` — the user PML4 frame and its physical address
pub fn create_kpti_user_pml4(
    kernel_pml4_phys: usize,
) -> Result<(PhysFrame<Size4KiB>, usize), ForkError> {
    let mut frame_alloc = FrameAllocator::new();

    // Mask low 12 bits defensively (PCID bits may be present in raw CR3 values)
    let kernel_pml4_phys = kernel_pml4_phys & !0xFFF;
    if kernel_pml4_phys == 0 {
        return Err(ForkError::PageTableCopyFailed);
    }

    // Allocate user PML4 root
    let user_pml4_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    unsafe {
        zero_table(user_pml4_frame);
    }

    // R118-5 FIX: Allocate a dedicated PDPT for the entry island (PML4[511]).
    //
    // Instead of copying the kernel's full PML4[511] (which maps 512 GiB),
    // we create a fresh PDPT and copy only the top 4 GiB (PDPT[508..=511]).
    // This limits speculative Meltdown-style exposure from 512 GiB to 4 GiB,
    // covering only the regions actually needed by the trampoline:
    //   - Kernel text/data (.text at 0xffffffff80100000)
    //   - Per-CPU syscall metadata (SyscallPerCpu)
    //   - IDT/GDT/TSS and scratch stacks
    let entry_island_pdpt_frame = match frame_alloc.allocate_frame() {
        Some(f) => f,
        None => {
            // Roll back: free the PML4 frame that was already allocated above.
            frame_alloc.deallocate_frame(user_pml4_frame);
            return Err(ForkError::MemoryAllocationFailed);
        }
    };
    unsafe {
        zero_table(entry_island_pdpt_frame);
    }

    let kernel_pml4_frame: PhysFrame<Size4KiB> =
        PhysFrame::containing_address(PhysAddr::new(kernel_pml4_phys as u64));

    /// User-half boundary: PML4 indices 0..255
    const USER_HALF_END: usize = 256;
    /// Recursive page table slot — must be empty in user PML4
    const RECURSIVE_INDEX: usize = 510;
    /// Entry island slot — contains kernel text/entry stubs/IDT/GDT/TSS
    const ENTRY_ISLAND_INDEX: usize = 511;

    unsafe {
        let kernel_pml4 = phys_to_virt_table(kernel_pml4_frame.start_address());
        let user_pml4 = phys_to_virt_table(user_pml4_frame.start_address());

        // ── Share user-half entries (PML4[0..255]) ──
        //
        // These are raw pointer copies — the user PML4 shares the same PDPT/PD/PT
        // frames as the kernel PML4. Any PML4-level change to user mappings must
        // update both roots (currently only create_fresh_address_space modifies
        // PML4[0], and we mirror it here).
        for i in 0..USER_HALF_END {
            user_pml4[i] = kernel_pml4[i].clone();
        }

        // ── Ensure no recursive mapping ──
        user_pml4[RECURSIVE_INDEX].set_unused();

        // ── Map entry island (PML4[511]) ──
        //
        // R118-5 FIX: Instead of copying the kernel's PML4[511] verbatim (512 GiB),
        // point to a dedicated PDPT that only maps the top 4 GiB (PDPT[508..=511]).
        //
        // R121-2 NOTE: All four PDPT entries are currently required:
        //   - PDPT[508]: Per-process kernel stacks (KSTACK_BASE = 0xffff_ffff_0000_0000)
        //                TSS.RSP0 points here; must be mapped during Ring 3→0 transitions.
        //   - PDPT[509]: stack_guard guarded RSP0/IST stacks mapped during boot.
        //   - PDPT[510]: Kernel .text/.rodata/.data/.bss + statics (GDT, TSS,
        //                SYSCALL_PERCPU, scratch stacks).
        //   - PDPT[511]: Heap allocations (IDT via lazy_static, etc.)
        //
        // A tighter island (R121-2 final) requires relocating kernel stacks
        // into PDPT[510..=511] or using a dedicated entry stack in the island,
        // plus moving IDT/GDT/TSS into dedicated linker sections at known
        // page-aligned addresses — deferred to dedicated KPTI hardening cycle.
        //
        // All entries are supervisor-only (USER_ACCESSIBLE removed at both PML4
        // and PDPT levels) to prevent normal Ring 3 access and limit Meltdown-style
        // speculative exposure to 4 GiB instead of 512 GiB.
        if !kernel_pml4[ENTRY_ISLAND_INDEX].is_unused() {
            let mut island_flags = kernel_pml4[ENTRY_ISLAND_INDEX].flags();
            island_flags.remove(PageTableFlags::USER_ACCESSIBLE);
            user_pml4[ENTRY_ISLAND_INDEX].set_frame(entry_island_pdpt_frame, island_flags);

            let kernel_pdpt = phys_to_virt_table(kernel_pml4[ENTRY_ISLAND_INDEX].addr());
            let island_pdpt = phys_to_virt_table(entry_island_pdpt_frame.start_address());

            // Copy only PDPT[508..=511] (top 4 GiB) from kernel's PDPT.
            // PDPT[0..508] remain absent (not present) in the user PDPT.
            for i in 508..512 {
                island_pdpt[i] = kernel_pdpt[i].clone();
                if !island_pdpt[i].is_unused() {
                    let addr = island_pdpt[i].addr();
                    let mut flags = island_pdpt[i].flags();
                    flags.remove(PageTableFlags::USER_ACCESSIBLE);
                    island_pdpt[i].set_addr(addr, flags);
                }
            }
        }
    }

    let phys_addr = user_pml4_frame.start_address().as_u64() as usize;
    Ok((user_pml4_frame, phys_addr))
}

/// H.3 KPTI: Free a user PML4 root created by `create_kpti_user_pml4()`.
///
/// Deallocates the root PML4 frame and its dedicated entry-island PDPT frame.
/// User-half entries (PML4[0..255]) are shared pointers into the kernel PML4's
/// sub-tables and MUST NOT be freed here (they are freed when
/// `free_address_space()` is called on the kernel PML4).
///
/// # Safety
///
/// The caller must ensure the user PML4 is not loaded in any CPU's CR3.
pub fn free_kpti_user_pml4(user_memory_space: usize) {
    if user_memory_space == 0 {
        return;
    }

    let mut frame_alloc = FrameAllocator::new();
    let root_frame: PhysFrame<Size4KiB> =
        PhysFrame::containing_address(PhysAddr::new(user_memory_space as u64));

    // R118-5 FIX: Free the privately-owned entry-island PDPT frame (PML4[511]).
    unsafe {
        const ENTRY_ISLAND_INDEX: usize = 511;
        let user_pml4 = phys_to_virt_table(root_frame.start_address());
        if !user_pml4[ENTRY_ISLAND_INDEX].is_unused() {
            let pdpt_phys = user_pml4[ENTRY_ISLAND_INDEX].addr();
            user_pml4[ENTRY_ISLAND_INDEX].set_unused();
            let pdpt_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(pdpt_phys);
            frame_alloc.deallocate_frame(pdpt_frame);
        }
    }

    frame_alloc.deallocate_frame(root_frame);
}

/// 深拷贝恒等映射 PML4[0]，并为用户空间准备 4KB 页映射
///
/// 用户空间起始地址 0x400000 (4MB) 落在：
/// - PML4[0] (0-512GB)
/// - PDPT[0] (0-1GB)
/// - PD[2] (4MB-6MB，因为每个 PD entry 覆盖 2MB)
///
/// 我们需要：
/// 1. 为新页表分配独立的 PDPT（深拷贝）
/// 2. 为 PDPT[0] 分配独立的 PD（深拷贝）
/// 3. 将 PD[2] 的 2MB 大页拆分为 4KB PT（如果需要）
///
/// 这样用户空间可以使用 4KB 页，而内核的恒等映射不受影响。
///
/// # R93-7 FIX: USER_ACCESSIBLE Propagation
///
/// When copying page table entries, we must ensure USER_ACCESSIBLE is set on
/// all entries in the path from PML4 down to the leaf page tables that user
/// space might traverse. Previously, only specific indices were modified,
/// leaving other entries as supervisor-only which caused spurious #PF.
unsafe fn deep_copy_identity_for_user(
    current_pml4: &mut PageTable,
    new_pml4: &mut PageTable,
    frame_alloc: &mut FrameAllocator,
) -> Result<(), ForkError> {
    // 用户空间起始地址对应的页表索引
    const USER_BASE: usize = 0x400000; // 4MB
    const PDPT_IDX: usize = 0; // 0-1GB 在 PDPT[0]
    const PD_IDX: usize = 2; // 4MB-6MB 在 PD[2] (4MB / 2MB = 2)

    let current_pml4_0 = &current_pml4[0];
    if current_pml4_0.is_unused() {
        return Ok(()); // 没有恒等映射，无需处理
    }

    // Step 1: 分配新的 PDPT
    let new_pdpt_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    zero_table(new_pdpt_frame);

    // 复制 PDPT 条目
    // R93-7 FIX (revised): Only PDPT[0] needs USER_ACCESSIBLE for user space.
    // Other PDPT entries (1-511) are identity map for physical memory beyond 1GB.
    // Setting USER_ACCESSIBLE on those would expose kernel memory and break SMAP.
    // We copy them as supervisor-only to maintain isolation.
    // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on all non-PDPT_IDX entries.
    // Defense-in-depth: prevent propagation even if parent has corrupted flags.
    let current_pdpt = phys_to_virt_table(current_pml4_0.addr());
    let new_pdpt = phys_to_virt_table(new_pdpt_frame.start_address());
    for i in 0..512 {
        new_pdpt[i] = current_pdpt[i].clone();
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE except for PDPT_IDX
        if i != PDPT_IDX && !new_pdpt[i].is_unused() {
            let addr = new_pdpt[i].addr();
            let mut flags = new_pdpt[i].flags();
            flags.remove(PageTableFlags::USER_ACCESSIBLE);
            new_pdpt[i].set_addr(addr, flags);
        }
    }

    // 更新新 PML4[0] 指向新 PDPT
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pml4_flags = current_pml4_0.flags();
    pml4_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pml4[0].set_addr(new_pdpt_frame.start_address(), pml4_flags);

    // Step 2: 检查 PDPT[0]（0-1GB 区域）
    let current_pdpt_0 = &current_pdpt[PDPT_IDX];
    if current_pdpt_0.is_unused() {
        return Ok(()); // 0-1GB 未映射
    }

    // 如果 PDPT[0] 是 1GB 大页，我们不支持拆分（太复杂）
    if current_pdpt_0.flags().contains(PageTableFlags::HUGE_PAGE) {
        kprintln!("WARNING: 1GB huge page at PDPT[0], cannot split for user space");
        return Err(ForkError::PageTableCopyFailed);
    }

    // Step 3: 分配新的 PD
    let new_pd_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    zero_table(new_pd_frame);

    // 复制 PD 条目
    // R93-7 FIX (revised): Only PD[2] (4MB-6MB region) needs USER_ACCESSIBLE.
    // Other PD entries are identity-mapped kernel memory (0-4MB, 6MB-1GB).
    // Setting USER_ACCESSIBLE on those would:
    // 1. Break SMAP - kernel can't access "user" pages without STAC
    // 2. Expose kernel memory to user space
    // We copy them as supervisor-only; USER_ACCESSIBLE is set on PD[2] below.
    // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on all non-PD_IDX entries.
    // Defense-in-depth: prevent propagation even if parent has corrupted flags.
    let current_pd = phys_to_virt_table(current_pdpt_0.addr());
    let new_pd = phys_to_virt_table(new_pd_frame.start_address());
    for i in 0..512 {
        new_pd[i] = current_pd[i].clone();
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE except for PD_IDX
        if i != PD_IDX && !new_pd[i].is_unused() {
            let addr = new_pd[i].addr();
            let mut flags = new_pd[i].flags();
            flags.remove(PageTableFlags::USER_ACCESSIBLE);
            new_pd[i].set_addr(addr, flags);
        }
    }

    // 更新新 PDPT[0] 指向新 PD
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pdpt_flags = current_pdpt_0.flags();
    pdpt_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pdpt[PDPT_IDX].set_addr(new_pd_frame.start_address(), pdpt_flags);

    // Step 4: 检查并拆分 PD[2]（4MB-6MB 区域）的 2MB 大页
    let current_pd_entry = &new_pd[PD_IDX];
    if current_pd_entry.is_unused() {
        return Ok(()); // 4MB-6MB 未映射
    }

    if current_pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // 这是 2MB 大页，需要拆分为 4KB PT
        // 但我们不填充 PT 条目，而是留空让 ELF loader 创建新映射
        // 用户进程不需要 identity mapping，它会有自己的物理帧

        // 分配新的 PT
        let new_pt_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        zero_table(new_pt_frame); // PT 保持为空，不填充 identity mapping

        // 更新 PD[2] 指向新的空 PT（不再是大页）
        // 【关键修复】添加 USER_ACCESSIBLE，移除 NO_EXECUTE 以允许用户代码执行
        // NX 位会被 ELF loader 在 PT 级别按需设置
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::HUGE_PAGE);
        pd_flags.remove(PageTableFlags::DIRTY); // DIRTY 是叶子页专有
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(new_pt_frame.start_address(), pd_flags);
    } else {
        // R94-5 FIX: Always allocate a fresh empty PT for the user base region.
        //
        // Even if the boot mapping already uses a 4KB PT at PD[2], reusing it risks
        // sharing page-table pages with the kernel identity map (cross-process corruption
        // and potential USER_ACCESSIBLE flag escalation).
        //
        // Previous code: reused pd_addr from current_pd_entry, which shared the PT
        // page with the kernel. Now we allocate a fresh empty PT instead.
        //
        // Leave the PT empty: ELF loader will populate user mappings.
        let new_pt_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        zero_table(new_pt_frame); // PT 保持为空，不填充 identity mapping

        // 【关键修复】添加 USER_ACCESSIBLE，移除 NO_EXECUTE 以允许用户代码执行
        // NX 位会被 ELF loader 在 PT 级别按需设置
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(new_pt_frame.start_address(), pd_flags);
    }

    Ok(())
}
