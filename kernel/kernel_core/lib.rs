#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(negative_impls)]
extern crate alloc;

// 导入 drivers crate，这会自动导入其导出的宏
#[macro_use]
extern crate drivers;

// 导出 vga_buffer 模块中的其他公共函数
pub use drivers::vga_buffer;

pub mod cgroup;
pub mod elf_loader;
pub mod exception_table;
pub mod fork;
pub mod ipc_namespace;
pub mod mount_namespace;
pub mod net_namespace;
pub mod pid_namespace;
pub mod process;
pub mod rcu;
pub mod user_namespace;
pub mod scheduler_hook;
pub mod signal;
pub mod syscall;
pub mod time;
pub mod usercopy;

pub use elf_loader::{load_elf, ElfLoadError, ElfLoadResult, USER_STACK_SIZE, USER_STACK_TOP};
pub use fork::{create_fresh_address_space, sys_fork, ForkError, ForkResult, PAGE_REF_COUNT};
pub use process::{
    add_supplementary_group,
    // CLONE_VM sibling detection (R37-1 fix)
    address_space_share_count,
    allocate_kernel_stack,
    // F.1 PID Namespace: create process in specific namespace
    create_process_in_namespace,
    current_cap_table,
    current_credentials,
    current_egid,
    current_euid,
    current_ipc_ns,      // F.1: IPC namespace
    current_ipc_ns_id,   // R75-2: IPC namespace ID for partitioning
    current_mount_ns,    // F.1: Mount namespace
    current_net_ns,      // F.1: Network namespace
    current_net_ns_id,   // R75-1: Network namespace ID for partitioning
    current_cgroup_id,   // F.2: Cgroup ID for resource accounting
    current_pid,
    current_supplementary_groups,
    current_umask,
    // Seccomp/Pledge support
    evaluate_seccomp,
    free_address_space,
    free_kernel_stack,
    get_process,
    has_no_new_privs,
    has_seccomp_enabled,
    kernel_stack_slot,
    non_thread_group_vm_share_count,
    register_ipc_cleanup,
    // OOM killer support
    register_oom_callbacks,
    remove_supplementary_group,
    set_current_supplementary_groups,
    set_current_umask,
    // Thread group support (R33-1 fix)
    thread_group_size,
    with_current_cap_table,
    // E.5 Cpuset callback registration
    register_cpuset_task_joined,
    register_cpuset_task_left,
    CpusetTaskJoinedCallback,
    CpusetTaskLeftCallback,
    // DAC support
    Credentials,
    FileDescriptor,
    FileOps,
    KernelStackError,
    KSTACK_BASE,
    KSTACK_STRIDE,
    MAX_FD,
    NGROUPS_MAX,
    // E.4 Priority Inheritance support
    FutexKey,
    Priority,
    // Process ID type
    ProcessId,
};
// Re-export capability types for convenience
pub use cap::{
    CapEntry, CapError, CapFlags, CapId, CapObject, CapRights, CapTable, EndpointId, NamespaceId,
    Shm, Socket, Timer,
};
pub use scheduler_hook::{
    force_reschedule, on_scheduler_tick, register_resched_callback, register_timer_callback,
    request_resched_from_irq, reschedule_if_needed,
};
pub use signal::{
    default_action, register_resume_callback, send_signal, signal_name, PendingSignals, Signal,
    SignalAction, SignalError,
};
pub use syscall::{
    register_fd_close_callback, register_fd_read_callback, register_fd_write_callback,
    register_futex_callback, register_mount_ns_materialize_callback, register_pipe_callback,
    register_syscall_frame_callback, register_vfs_create_callback, register_vfs_lseek_callback,
    register_vfs_open_callback, register_vfs_open_with_resolve_callback,
    register_vfs_readdir_callback, register_vfs_stat_callback, register_vfs_truncate_callback,
    register_vfs_unlink_callback, wake_stdin_waiters, DirEntry, FileType, SyscallError,
    SyscallFrame, VfsStat,
    // R74-2 test helper
    test_is_mount_ns_callback_registered,
};
pub use time::{current_timestamp_ms, get_ticks, on_timer_tick};
pub use usercopy::{
    // Type-safe user pointer API (A.1 Security Hardening)
    copy_from_user,
    // Legacy API (for backward compatibility)
    copy_from_user_safe,
    copy_from_user_slice,
    copy_to_user,
    copy_to_user_safe,
    copy_to_user_slice,
    copy_user_cstring,
    is_in_usercopy,
    strncpy_from_user,
    try_handle_usercopy_fault,
    UserAccessGuard,
    UserPtr,
    UserSlice,
    UsercopyError,
    MAX_CSTRING_LEN,
    USER_SPACE_TOP,
};
// E.4: RCU (Read-Copy-Update) synchronization primitive
pub use rcu::{
    call_rcu, rcu_quiescent_state, rcu_read_lock, rcu_read_lock_held, rcu_read_unlock,
    synchronize_rcu, RcuReadGuard,
};
// F.1: PID namespace support
pub use pid_namespace::{
    assign_pid_chain, detach_pid_chain, get_cascade_kill_pids, is_visible_in_namespace,
    owning_namespace, pid_in_namespace, pid_in_owning_namespace, resolve_pid_in_namespace,
    PidNamespace, PidNamespaceError, PidNamespaceMembership, ROOT_PID_NAMESPACE,
    MAX_PID_NS_LEVEL,
};
// F.1: Mount namespace support
pub use mount_namespace::{
    clone_namespace as clone_mount_namespace, init as init_mount_namespace,
    print_namespace_info as print_mount_namespace_info, MountFlags, MountNamespace,
    MountNamespaceFd, MountNsError, ROOT_MNT_NAMESPACE, MAX_MNT_NS_LEVEL,
};
// F.1: IPC namespace support
pub use ipc_namespace::{
    clone_ipc_namespace, init as init_ipc_namespace,
    print_ipc_namespace_info, IpcNamespace, IpcNamespaceFd, IpcNsError,
    ROOT_IPC_NAMESPACE, MAX_IPC_NS_LEVEL, CLONE_NEWIPC,
    test_is_ipc_ns_initialized,
};
// F.1: Network namespace support
pub use net_namespace::{
    clone_net_namespace, init as init_net_namespace,
    print_net_namespace_info, move_device as move_net_device, NetNamespace,
    NetNamespaceFd, NetNsError, ROOT_NET_NAMESPACE, MAX_NET_NS_LEVEL, CLONE_NEWNET,
    test_is_net_ns_initialized,
};
// F.1: User namespace support
pub use user_namespace::{
    clone_user_namespace, init as init_user_namespace, root_user_namespace,
    print_user_namespace_info, user_ns_count, UserNamespace, UserNamespaceFd,
    UserNsError, UidGidMapping, ROOT_USER_NAMESPACE, MAX_USER_NS_LEVEL,
    MAX_MAPPINGS, CLONE_NEWUSER,
};

// F.2: Cgroup v2 support
pub use cgroup::{
    init as init_cgroup, lookup_cgroup, create_cgroup, delete_cgroup,
    root_cgroup, cgroup_count, migrate_task,
    get_effective_cpu_weight, check_fork_allowed, account_cpu_time,
    // R77-2 FIX: Replaced update_memory_usage with read-only get_memory_usage
    get_memory_usage, check_memory_allowed, try_charge_memory, uncharge_memory,
    // F.2: CPU quota (cpu.max) enforcement
    charge_cpu_quota, cpu_quota_is_throttled, CpuQuotaStatus,
    // F.2: IO throttling (io.max) enforcement
    charge_io, wait_for_io_window, record_io_completion, IoDirection, IoThrottleStatus,
    CgroupNode, CgroupId, CgroupControllers, CgroupLimits,
    CgroupStats, CgroupStatsSnapshot, CgroupError,
    MAX_CGROUP_DEPTH, MAX_CGROUPS, ROOT_CGROUP, CGROUP_REGISTRY,
};

// ============================================================================
// LSM Context Provider Adapters
// ============================================================================

/// Adapter: Get current PID for LSM
fn lsm_get_pid() -> Option<lsm::ProcessId> {
    current_pid()
}

/// Adapter: Get current credentials for LSM
fn lsm_get_credentials() -> Option<lsm::Credentials> {
    current_credentials().map(|c| lsm::Credentials {
        uid: c.uid,
        gid: c.gid,
        euid: c.euid,
        egid: c.egid,
    })
}

/// Adapter: Get current ticks for LSM
fn lsm_get_ticks() -> u64 {
    get_ticks()
}

pub fn init() {
    process::init(); // 必须最先初始化，确保 BOOT_CR3 被缓存
    time::init();

    // Register LSM context providers (must be after process::init)
    lsm::register_context_provider(lsm_get_pid, lsm_get_credentials, lsm_get_ticks);

    // R29-2 FIX: Register seccomp current-process evaluation callbacks
    // This bridges the seccomp module to the process module for filter evaluation
    seccomp::register_current_hooks(evaluate_seccomp, has_seccomp_enabled);

    // Register socket wait hooks for blocking recv support
    // Must be after process::init since it needs process management
    syscall::register_socket_hooks();

    // Register socket timeout checker as timer callback
    scheduler_hook::register_timer_callback(syscall::check_socket_timeouts);

    // R26-4 FIX: Register audit snapshot authorizer
    // Allow root (euid == 0) or processes with CAP_AUDIT_READ capability
    audit::register_snapshot_authorizer(|| {
        // First check: root always allowed
        if let Some(creds) = current_credentials() {
            if creds.euid == 0 {
                return Ok(());
            }
        }

        // Second check: CAP_AUDIT_READ capability
        if let Some(has_cap) =
            with_current_cap_table(|table| table.has_rights(cap::CapRights::AUDIT_READ))
        {
            if has_cap {
                return Ok(());
            }
        }

        Err(audit::AuditError::AccessDenied)
    });

    // Register OOM killer callbacks (must be after mm initialization)
    process::register_oom_callbacks();

    // F.2: Initialize cgroup v2 subsystem
    cgroup::init();

    println!("Kernel core module initialized");
}
