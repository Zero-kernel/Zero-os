#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

use alloc::boxed::Box;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

pub use kernel_core::process;
use kernel_core::{FileOps, SyscallError};

pub mod futex;
pub mod ipc;
pub mod pipe;
pub mod sync;

pub use ipc::{
    cleanup_process_endpoints, destroy_endpoint, get_queue_length, grant_access, receive_message,
    receive_message_blocking, receive_message_with_retries, register_endpoint, revoke_access,
    send_message, send_message_notify, EndpointId, IpcError, Message, ReceivedMessage,
};

pub use sync::{init_waitqueue_timers, CondVar, KMutex, Semaphore, WaitOutcome, WaitQueue};

pub use pipe::{
    create_pipe, create_pipe_with_capacity, PipeEndType, PipeError, PipeFlags, PipeHandle, PipeId,
    PipeStatus, DEFAULT_PIPE_CAPACITY,
};

pub use futex::{
    active_futex_count, cleanup_process_futexes, futex_lock_pi, futex_unlock_pi, futex_wait,
    futex_wake, FutexError, FutexTable, FUTEX_LOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT,
    FUTEX_WAIT_TIMEOUT, FUTEX_WAKE,
};

// ============================================================================
// 系统调用回调实现
// ============================================================================

/// 创建管道的系统调用回调
///
/// 创建一个管道，分配两个文件描述符给当前进程
fn pipe_create_callback() -> Result<(i32, i32), SyscallError> {
    use process::{current_pid, get_process};

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 创建管道
    let (read_handle, write_handle) = create_pipe(PipeFlags::default());

    // 分配文件描述符
    let (read_fd, write_fd) = {
        let mut proc = process.lock();

        // 分配读端 fd
        let rfd = proc
            .allocate_fd(Box::new(read_handle) as Box<dyn FileOps>)
            .ok_or(SyscallError::EMFILE)?;

        // 分配写端 fd，失败时回滚
        let wfd = match proc.allocate_fd(Box::new(write_handle) as Box<dyn FileOps>) {
            Some(fd) => fd,
            None => {
                // 回滚：移除已分配的读端 fd
                proc.remove_fd(rfd);
                return Err(SyscallError::EMFILE);
            }
        };

        (rfd, wfd)
    };

    println!(
        "sys_pipe: created pipe (read_fd={}, write_fd={})",
        read_fd, write_fd
    );
    Ok((read_fd, write_fd))
}

/// 文件描述符读取回调
///
/// 从指定的文件描述符读取数据（管道 + VFS 文件）
///
/// R32-IPC-1 FIX: Single lookup to avoid TOCTOU - determine fd type and
/// get handle in one lock acquisition.
///
/// R41-3 FIX: Clone file handle and drop process lock before I/O.
/// This prevents holding the lock during potentially blocking device I/O,
/// avoiding DoS vectors and deadlock risks.
fn fd_read_callback(fd: i32, buf: &mut [u8]) -> Result<usize, SyscallError> {
    use process::{current_pid, get_process};
    use vfs::traits::FileHandle;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Single lock acquisition for both type checks
    let proc = process.lock();
    let fd_obj = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

    // Check for pipe first (needs clone for out-of-lock I/O to avoid deadlock)
    if let Some(pipe_handle) = fd_obj.as_any().downcast_ref::<PipeHandle>() {
        let pipe_clone = pipe_handle.clone();
        drop(proc); // Release lock before potentially blocking pipe I/O
        return pipe_clone.read(buf).map_err(pipe_error_to_syscall);
    }

    // R41-3 FIX: Clone FileHandle and drop lock before I/O
    if let Some(file) = fd_obj.as_any().downcast_ref::<FileHandle>() {
        if file.inode.is_dir() {
            return Err(SyscallError::EISDIR);
        }
        let file_clone = file.clone();
        drop(proc); // Release lock before VFS I/O
        return file_clone.read(buf).map_err(fs_error_to_syscall);
    }

    Err(SyscallError::EBADF)
}

/// 文件描述符写入回调
///
/// 向指定的文件描述符写入数据（管道 + VFS 文件）
///
/// R32-IPC-1 FIX: Single lookup to avoid TOCTOU - determine fd type and
/// get handle in one lock acquisition.
///
/// R41-3 FIX: Clone file handle and drop process lock before I/O.
/// This prevents holding the lock during potentially blocking device I/O,
/// avoiding DoS vectors and deadlock risks.
fn fd_write_callback(fd: i32, buf: &[u8]) -> Result<usize, SyscallError> {
    use process::{current_pid, get_process};
    use vfs::traits::FileHandle;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Single lock acquisition for both type checks
    let proc = process.lock();
    let fd_obj = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

    // Check for pipe first (needs clone for out-of-lock I/O to avoid deadlock)
    if let Some(pipe_handle) = fd_obj.as_any().downcast_ref::<PipeHandle>() {
        let pipe_clone = pipe_handle.clone();
        drop(proc); // Release lock before potentially blocking pipe I/O
        return pipe_clone.write(buf).map_err(pipe_error_to_syscall);
    }

    // R41-3 FIX: Clone FileHandle and drop lock before I/O
    if let Some(file) = fd_obj.as_any().downcast_ref::<FileHandle>() {
        if file.inode.is_dir() {
            return Err(SyscallError::EISDIR);
        }
        let file_clone = file.clone();
        drop(proc); // Release lock before VFS I/O
        return file_clone.write(buf).map_err(fs_error_to_syscall);
    }

    Err(SyscallError::EBADF)
}

/// 文件描述符关闭回调
///
/// 关闭指定的文件描述符（触发 Drop 清理资源）
fn fd_close_callback(fd: i32) -> Result<(), SyscallError> {
    use process::{current_pid, get_process};

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 移除文件描述符（Drop 会自动清理管道资源）
    let mut proc = process.lock();
    proc.remove_fd(fd).ok_or(SyscallError::EBADF)?;

    Ok(())
}

/// PipeError 到 SyscallError 的转换
fn pipe_error_to_syscall(err: PipeError) -> SyscallError {
    match err {
        PipeError::WouldBlock => SyscallError::EAGAIN,
        PipeError::BrokenPipe => SyscallError::EPIPE,
        PipeError::Closed => SyscallError::EPIPE,
        PipeError::InvalidPipe | PipeError::InvalidOperation => SyscallError::EBADF,
        PipeError::NoCurrentProcess => SyscallError::ESRCH,
    }
}

/// FsError 到 SyscallError 的转换（用于 VFS FileHandle）
fn fs_error_to_syscall(err: vfs::types::FsError) -> SyscallError {
    use vfs::types::FsError;
    match err {
        FsError::NotFound => SyscallError::ENOENT,
        FsError::NotDir => SyscallError::ENOTDIR,
        FsError::IsDir => SyscallError::EISDIR,
        FsError::Exists => SyscallError::EEXIST,
        FsError::PermDenied => SyscallError::EACCES,
        FsError::BadFd => SyscallError::EBADF,
        FsError::ReadOnly => SyscallError::EACCES,
        FsError::NoSpace | FsError::NoMem => SyscallError::ENOMEM,
        FsError::Io => SyscallError::EIO,
        FsError::Invalid | FsError::NameTooLong | FsError::Seek => SyscallError::EINVAL,
        FsError::CrossDev => SyscallError::EXDEV,
        FsError::SymlinkLoop => SyscallError::ELOOP,
        FsError::NotSupported => SyscallError::ENOSYS,
        FsError::Pipe => SyscallError::EPIPE,
        FsError::NotEmpty => SyscallError::EBUSY,
    }
}

/// Futex 操作回调
///
/// 根据操作码执行 FUTEX_WAIT / FUTEX_WAIT_TIMEOUT / FUTEX_WAKE
///
/// # Arguments
///
/// * `uaddr` - 用户空间 futex 地址
/// * `op` - 操作码 (FUTEX_WAIT=0, FUTEX_WAKE=1, FUTEX_WAIT_TIMEOUT=2)
/// * `val` - FUTEX_WAIT 时为期望值，FUTEX_WAKE 时为唤醒数量
/// * `current_value` - 调用者从用户空间读取的当前值（仅 FUTEX_WAIT 使用）
/// * `timeout_ns` - R39-6 FIX: 可选超时时间（纳秒），仅 FUTEX_WAIT_TIMEOUT 使用
///
/// # Returns
///
/// FUTEX_WAIT/FUTEX_WAIT_TIMEOUT: 成功返回 0，值不匹配返回 EAGAIN，超时返回 ETIMEDOUT
/// FUTEX_WAKE: 返回实际唤醒的进程数量
///
/// # Security (R32-IPC-2 fix)
///
/// Validates that uaddr is properly aligned and points to a user-accessible page.
/// This prevents using kernel addresses or unmapped memory as futex keys.
fn futex_callback(
    uaddr: usize,
    op: i32,
    val: u32,
    current_value: u32,
    timeout_ns: Option<u64>,
) -> Result<usize, SyscallError> {
    use mm::page_table::{with_current_manager, PHYSICAL_MEMORY_OFFSET};
    use process::current_pid;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    // R32-IPC-2 FIX: Validate alignment (u32 must be 4-byte aligned)
    if uaddr & 0x3 != 0 {
        return Err(SyscallError::EINVAL);
    }

    // R32-IPC-2 FIX: Validate user-space address range
    // Reject kernel addresses (addresses >= PHYSICAL_MEMORY_OFFSET are kernel space)
    if uaddr as u64 >= PHYSICAL_MEMORY_OFFSET {
        return Err(SyscallError::EFAULT);
    }

    // R32-IPC-2 FIX: Verify page is mapped with USER_ACCESSIBLE flag
    unsafe {
        with_current_manager(VirtAddr::new(0), |mgr| {
            // Check start and end of u32 value
            let end_addr = uaddr
                .checked_add(core::mem::size_of::<u32>() - 1)
                .ok_or(SyscallError::EFAULT)?;

            for addr in [uaddr, end_addr] {
                if let Some((_, flags)) = mgr.translate_with_flags(VirtAddr::new(addr as u64)) {
                    if !flags.contains(PageTableFlags::PRESENT)
                        || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                    {
                        return Err(SyscallError::EFAULT);
                    }
                } else {
                    return Err(SyscallError::EFAULT);
                }
            }
            Ok(())
        })?;
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;

    // R37-2 FIX: Use TGID so futex keys are shared across CLONE_THREAD siblings.
    // This ensures pthread mutexes/condvars work correctly in multi-threaded programs.
    let tgid = {
        let proc_arc = process::get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        proc.tgid
    };

    match op {
        // R39-6 FIX: FUTEX_WAIT 和 FUTEX_WAIT_TIMEOUT 统一处理
        futex::FUTEX_WAIT | futex::FUTEX_WAIT_TIMEOUT => {
            // FUTEX_WAIT 使用 None（无限等待），FUTEX_WAIT_TIMEOUT 使用传入的超时
            let effective_timeout = if op == futex::FUTEX_WAIT_TIMEOUT {
                timeout_ns
            } else {
                None
            };
            futex_wait(tgid, uaddr, val, current_value, effective_timeout).map_err(|e| match e {
                FutexError::WouldBlock => SyscallError::EAGAIN,
                FutexError::Fault => SyscallError::EFAULT,
                FutexError::NoProcess => SyscallError::ESRCH,
                FutexError::InvalidOperation => SyscallError::EINVAL,
                FutexError::TimedOut => SyscallError::ETIMEDOUT,
                FutexError::OwnerDied => SyscallError::EOWNERDEAD,
            })
        }
        futex::FUTEX_WAKE => Ok(futex_wake(tgid, uaddr, val as usize)),
        // E.4 PI: FUTEX_LOCK_PI - 带优先级继承的互斥锁加锁
        futex::FUTEX_LOCK_PI => {
            futex_lock_pi(tgid, uaddr, current_value).map_err(|e| match e {
                FutexError::WouldBlock => SyscallError::EAGAIN,
                FutexError::Fault => SyscallError::EFAULT,
                FutexError::NoProcess => SyscallError::ESRCH,
                FutexError::InvalidOperation => SyscallError::EINVAL,
                FutexError::TimedOut => SyscallError::ETIMEDOUT,
                FutexError::OwnerDied => SyscallError::EOWNERDEAD,
            })
        }
        // E.4 PI: FUTEX_UNLOCK_PI - 带优先级继承的互斥锁解锁
        futex::FUTEX_UNLOCK_PI => futex_unlock_pi(tgid, uaddr).map_err(|e| match e {
            FutexError::WouldBlock => SyscallError::EAGAIN,
            FutexError::Fault => SyscallError::EFAULT,
            FutexError::NoProcess => SyscallError::ESRCH,
            FutexError::InvalidOperation => SyscallError::EINVAL,
            FutexError::TimedOut => SyscallError::ETIMEDOUT,
            FutexError::OwnerDied => SyscallError::EOWNERDEAD,
        }),
        _ => Err(SyscallError::EINVAL),
    }
}

/// 进程退出时的 IPC 清理（端点 + futex 表）
///
/// 注册到 kernel_core 的进程清理回调，确保进程退出时自动清理所有 IPC 资源
///
/// R37-2 FIX (Codex review): Accept TGID directly to avoid re-locking the process.
/// The caller (free_process_resources) already holds the process lock.
fn ipc_cleanup(pid: process::ProcessId, tgid: process::ProcessId) {
    cleanup_process_endpoints(pid);
    cleanup_process_futexes(pid, tgid);
}

/// Futex 唤醒回调（用于线程退出时的 clear_child_tid 机制）
///
/// 唤醒等待在指定地址上的进程。使用 TGID 作为键，以便线程组内的
/// 线程能够互相唤醒，保持 pthread 语义。
///
/// # Arguments
///
/// * `tgid` - 线程组ID（R37-2 FIX: 用于定位 futex 表，确保线程间互操作）
/// * `uaddr` - 用户空间 futex 地址
/// * `max_wake` - 最大唤醒数量
///
/// # Returns
///
/// 实际唤醒的进程数量
fn futex_wake_callback(tgid: process::ProcessId, uaddr: usize, max_wake: usize) -> usize {
    // R37-2: 使用 tgid 作为键唤醒等待者，确保 CLONE_THREAD 兄弟可以互相唤醒
    futex_wake(tgid, uaddr, max_wake)
}

/// 初始化IPC子系统
///
/// 注册进程清理回调，确保进程退出时自动清理其IPC端点。
/// 同时注册系统调用回调，使 kernel_core 的 sys_pipe/sys_read/sys_write/sys_close
/// 能够操作管道。
pub fn init() {
    // R39-6 FIX: 初始化 WaitQueue 超时定时器
    sync::init_waitqueue_timers();

    // 注册IPC清理回调到进程管理子系统（包括端点和 futex 清理）
    kernel_core::register_ipc_cleanup(ipc_cleanup);

    // 注册 futex 唤醒回调，用于线程退出时的 clear_child_tid 机制
    process::register_futex_wake(futex_wake_callback);

    // 注册系统调用回调
    kernel_core::register_pipe_callback(pipe_create_callback);
    kernel_core::register_fd_read_callback(fd_read_callback);
    kernel_core::register_fd_write_callback(fd_write_callback);
    kernel_core::register_fd_close_callback(fd_close_callback);
    kernel_core::register_futex_callback(futex_callback);

    ipc::init();
    println!("  Synchronization primitives loaded (WaitQueue, KMutex, Semaphore, CondVar)");
    println!("  Pipe support loaded (anonymous pipes with blocking I/O)");
    println!("  Futex support loaded (user-space fast mutex with timeout)");
    println!("  Syscall callbacks registered (pipe, read, write, close, futex)");
}
