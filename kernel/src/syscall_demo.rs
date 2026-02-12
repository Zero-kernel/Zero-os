//! 系统调用演示模块

use kernel_core::syscall::{syscall_dispatcher, SyscallNumber};

/// 演示基础系统调用
pub fn demo_basic_syscalls() {
    klog_always!("\n=== Basic Syscalls Demo ===\n");

    // 演示1: getpid系统调用
    klog_always!("1. Testing sys_getpid...");
    let pid = syscall_dispatcher(SyscallNumber::GetPid as u64, 0, 0, 0, 0, 0, 0);
    if pid >= 0 {
        klog_always!("   ✓ Current PID: {}", pid);
    } else {
        klog_always!("   ✗ Failed with error code: {}", pid);
    }

    // 演示2: getppid系统调用
    klog_always!("\n2. Testing sys_getppid...");
    let ppid = syscall_dispatcher(SyscallNumber::GetPPid as u64, 0, 0, 0, 0, 0, 0);
    if ppid >= 0 {
        klog_always!("   ✓ Parent PID: {}", ppid);
    } else {
        klog_always!("   ✗ Failed with error code: {}", ppid);
    }

    // 演示3: write系统调用
    klog_always!("\n3. Testing sys_write...");
    let msg = b"Hello from syscall!\n";
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        1, // stdout
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
        0,
        0,
    );
    if result >= 0 {
        klog_always!("   ✓ Wrote {} bytes", result);
    } else {
        klog_always!("   ✗ Failed with error code: {}", result);
    }

    klog_always!("\n✓ Basic syscalls demo completed!\n");
}

/// 演示进程管理系统调用
pub fn demo_process_syscalls() {
    klog_always!("\n=== Process Management Syscalls Demo ===\n");

    // 演示1: fork系统调用
    klog_always!("1. Testing sys_fork...");
    let child_pid = syscall_dispatcher(SyscallNumber::Fork as u64, 0, 0, 0, 0, 0, 0);
    if child_pid >= 0 {
        klog_always!("   ✓ Forked child process with PID: {}", child_pid);
    } else {
        klog_always!("   ✗ Fork failed with error code: {}", child_pid);
    }

    // 演示2: yield系统调用
    klog_always!("\n2. Testing sys_yield...");
    let result = syscall_dispatcher(SyscallNumber::Yield as u64, 0, 0, 0, 0, 0, 0);
    if result >= 0 {
        klog_always!("   ✓ Yielded CPU successfully");
    } else {
        klog_always!("   ✗ Yield failed with error code: {}", result);
    }

    klog_always!("\n✓ Process management syscalls demo completed!\n");
}

/// 演示错误处理
pub fn demo_error_handling() {
    klog_always!("\n=== Error Handling Demo ===\n");

    // 演示1: 无效的文件描述符
    klog_always!("1. Testing invalid file descriptor...");
    let msg = b"test";
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        999, // 无效的fd
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
        0,
        0,
    );
    if result < 0 {
        klog_always!("   ✓ Correctly returned error code: {} (EBADF)", result);
    } else {
        klog_always!("   ✗ Should have failed but returned: {}", result);
    }

    // 演示2: 空指针
    klog_always!("\n2. Testing null pointer...");
    let result = syscall_dispatcher(
        SyscallNumber::Write as u64,
        1,
        0, // null pointer
        10,
        0,
        0,
        0,
    );
    if result < 0 {
        klog_always!("   ✓ Correctly returned error code: {} (EFAULT)", result);
    } else {
        klog_always!("   ✗ Should have failed but returned: {}", result);
    }

    // 演示3: 未实现的系统调用
    klog_always!("\n3. Testing unimplemented syscall...");
    let result = syscall_dispatcher(SyscallNumber::Exec as u64, 0, 0, 0, 0, 0, 0);
    if result < 0 {
        klog_always!("   ✓ Correctly returned error code: {} (ENOSYS)", result);
    } else {
        klog_always!("   ✗ Should have failed but returned: {}", result);
    }

    klog_always!("\n✓ Error handling demo completed!\n");
}

/// 演示系统调用性能
pub fn demo_syscall_performance() {
    klog_always!("\n=== Syscall Performance Demo ===\n");

    klog_always!("1. Benchmarking getpid (lightweight syscall)...");
    let iterations = 1000;

    for i in 0..iterations {
        let _pid = syscall_dispatcher(SyscallNumber::GetPid as u64, 0, 0, 0, 0, 0, 0);

        if i % 100 == 0 {
            print!(".");
        }
    }
    klog_always!("\n   ✓ Completed {} getpid calls", iterations);

    klog_always!("\n2. Benchmarking write (I/O syscall)...");
    let msg = b"x";
    for i in 0..100 {
        let _result = syscall_dispatcher(
            SyscallNumber::Write as u64,
            1,
            msg.as_ptr() as u64,
            msg.len() as u64,
            0,
            0,
            0,
        );

        if i % 10 == 0 {
            print!(".");
        }
    }
    klog_always!("\n   ✓ Completed 100 write calls");

    klog_always!("\n✓ Performance demo completed!\n");
}

/// 运行所有系统调用演示
pub fn run_all_demos() {
    demo_basic_syscalls();
    demo_process_syscalls();
    demo_error_handling();
    demo_syscall_performance();
}
