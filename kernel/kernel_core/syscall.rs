//! 系统调用接口
//!
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口
//!
//! # Audit Integration
//!
//! All syscalls are audited with entry and exit events for security monitoring.
//! Events include: syscall number, arguments, result, and process context.

use crate::cgroup;
use crate::fork::PAGE_REF_COUNT;
use crate::process::{
    cleanup_zombie, create_process, create_process_in_namespace, current_net_ns_id, current_pid,
    get_process, terminate_process, with_current_cap_table, ProcessId, ProcessState,
};
use cpu_local::{current_cpu, current_cpu_id, max_cpus};
use crate::usercopy::UserAccessGuard;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

// Audit integration for syscall security monitoring
use audit::{AuditKind, AuditObject, AuditOutcome, AuditSubject};

// Seccomp/Pledge syscall filtering
extern crate seccomp;

// LSM hook infrastructure
extern crate lsm;

// Network socket layer
extern crate net;

// Capability system
extern crate cap;

// Security RNG for cryptographically secure random number generation
use security::rng;

/// 最大参数数量（防止恶意用户传递过多参数）
const MAX_ARG_COUNT: usize = 256;

// ============================================================================
// Seccomp/Prctl Constants (Linux x86_64 ABI)
// ============================================================================

/// Seccomp operation modes
const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// Seccomp mode return values for prctl(PR_GET_SECCOMP)
const SECCOMP_MODE_DISABLED: usize = 0;
const SECCOMP_MODE_STRICT: usize = 1;
const SECCOMP_MODE_FILTER: usize = 2;

/// prctl option codes for seccomp operations
const PR_GET_SECCOMP: i32 = 21;
const PR_SET_SECCOMP: i32 = 22;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// User-space BPF instruction opcodes (simplified encoding)
/// These define the wire format for filters passed from userspace
const SECCOMP_USER_OP_LD_NR: u8 = 0;
const SECCOMP_USER_OP_LD_ARG: u8 = 1;
const SECCOMP_USER_OP_LD_CONST: u8 = 2;
const SECCOMP_USER_OP_AND: u8 = 3;
const SECCOMP_USER_OP_OR: u8 = 4;
const SECCOMP_USER_OP_SHR: u8 = 5;
const SECCOMP_USER_OP_JMP_EQ: u8 = 6;
const SECCOMP_USER_OP_JMP_NE: u8 = 7;
const SECCOMP_USER_OP_JMP_LT: u8 = 8;
const SECCOMP_USER_OP_JMP_LE: u8 = 9;
const SECCOMP_USER_OP_JMP_GT: u8 = 10;
const SECCOMP_USER_OP_JMP_GE: u8 = 11;
const SECCOMP_USER_OP_JMP: u8 = 12;
const SECCOMP_USER_OP_RET: u8 = 13;

/// Seccomp action codes for RET instruction
const SECCOMP_USER_ACTION_ALLOW: u32 = 0;
const SECCOMP_USER_ACTION_LOG: u32 = 1;
const SECCOMP_USER_ACTION_ERRNO: u32 = 2;
const SECCOMP_USER_ACTION_TRAP: u32 = 3;
const SECCOMP_USER_ACTION_KILL: u32 = 4;

/// User-space seccomp instruction structure
/// Matches the format passed from userspace via sys_seccomp(FILTER)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserSeccompInsn {
    /// Opcode (SECCOMP_USER_OP_*)
    op: u8,
    _padding: [u8; 7],
    /// First operand (varies by opcode)
    arg0: u64,
    /// Second operand (jump targets for conditional jumps)
    arg1: u64,
    /// Third operand (false branch offset for conditional jumps)
    arg2: u64,
}

/// User-space seccomp program header
/// Describes the filter to be installed
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserSeccompProg {
    /// Number of instructions
    len: u32,
    /// Default action (applied when no instruction returns)
    default_action: u32,
    /// Pointer to instruction array
    filter: u64, // Using u64 instead of *const for safe Copy
}

// ============================================================================
// Linux ABI struct definitions for new syscalls
// ============================================================================

/// AT_FDCWD sentinel for *at() syscalls (openat, fstatat, etc.)
const AT_FDCWD: i32 = -100;

/// struct open_how (Linux openat2 ABI)
///
/// Used by the openat2(2) syscall to specify open flags, mode, and resolve flags.
/// Compatible with Linux 5.6+ ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct OpenHow {
    /// Open flags (O_RDONLY, O_WRONLY, O_CREAT, O_NOFOLLOW, etc.)
    flags: u64,
    /// File creation mode (only used with O_CREAT)
    mode: u64,
    /// Path resolution flags (RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH, etc.)
    resolve: u64,
}

/// struct timeval (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

/// struct timespec (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// struct utsname (Linux ABI, fixed-size strings)
#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
        }
    }
}

/// Linux dirent64 layout for getdents64 syscall
#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // followed by name bytes + '\0'
}

// ============================================================================
// Socket ABI (Linux x86_64)
// ============================================================================

/// Socket type flags (Linux ABI)
const SOCK_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
const SOCK_CLOEXEC: u32 = 0o2000000; // O_CLOEXEC

/// sendto/recvfrom flags we support
const MSG_DONTWAIT: u32 = 0x40;

/// Maximum UDP payload size
const UDP_MAX_PAYLOAD: usize = 65507;

/// struct sockaddr_in (Linux x86_64 ABI compatible)
///
/// Used by socket syscalls for IPv4 address specification.
/// All multi-byte fields are in network byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SockAddrIn {
    /// Address family (AF_INET = 2)
    sin_family: u16,
    /// Port number (network byte order)
    sin_port: u16,
    /// IPv4 address (network byte order)
    sin_addr: u32,
    /// Padding to 16 bytes (Linux ABI)
    sin_zero: [u8; 8],
}

impl SockAddrIn {
    /// Create from Ipv4Addr and port (host byte order).
    fn from_addr(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: u32::from_be_bytes(ip),
            sin_zero: [0; 8],
        }
    }

    /// Extract IP address as [u8; 4] in network byte order.
    fn ip_bytes(&self) -> [u8; 4] {
        self.sin_addr.to_be_bytes()
    }

    /// Extract port in host byte order.
    fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }
}

/// AF_INET constant (IPv4)
const AF_INET: u32 = 2;

/// Socket file descriptor wrapper for fd_table.
///
/// Stores the CapId and socket_id together for efficient lookup.
#[derive(Clone)]
struct SocketFile {
    /// Capability ID referencing this socket in cap_table
    cap_id: cap::CapId,
    /// Socket ID in socket_table()
    socket_id: u64,
    /// Non-blocking flag (SOCK_NONBLOCK)
    nonblocking: bool,
}

impl SocketFile {
    fn new(cap_id: cap::CapId, socket_id: u64, nonblocking: bool) -> Self {
        Self {
            cap_id,
            socket_id,
            nonblocking,
        }
    }
}

/// S_IFSOCK constant - socket file type marker
const S_IFSOCK: u32 = 0o140000;

impl crate::process::FileOps for SocketFile {
    fn clone_box(&self) -> alloc::boxed::Box<dyn crate::process::FileOps> {
        // Increment refcount on clone (for dup/fork POSIX semantics).
        //
        // NOTE: If the socket was already closed/removed from the table,
        // get() returns None and we create a SocketFile pointing to a dead
        // socket. This is acceptable because:
        // 1. Any operation on the dead socket will fail gracefully (EBADF)
        // 2. Drop will do nothing (get() returns None again)
        // 3. The FileOps trait doesn't allow returning errors from clone_box
        //
        // This edge case can occur if the socket is closed between dup/fork
        // initiation and completion - a valid race condition in concurrent
        // environments.
        if let Some(sock) = net::socket_table().get(self.socket_id) {
            sock.increment_refcount();
        }
        alloc::boxed::Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "SocketFile"
    }

    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
            dev: 0,
            ino: self.socket_id,
            mode: S_IFSOCK | 0o666, // Socket with rw-rw-rw- permissions
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        })
    }
}

/// Socket cleanup on Drop with reference counting.
///
/// When a SocketFile is dropped (via sys_close or process exit), we decrement
/// the socket's reference count. Only when the refcount reaches 0 do we fully
/// close the socket, releasing the port binding and waking any waiters.
///
/// This preserves POSIX semantics for:
/// - dup()/dup2()/dup3(): Multiple FDs can share one socket
/// - fork(): Child inherits socket FDs with proper refcounting
///
/// The reference count is:
/// - Initialized to 1 at socket creation
/// - Incremented in clone_box() (called by dup/fork)
/// - Decremented here on drop
impl Drop for SocketFile {
    fn drop(&mut self) {
        // Decrement refcount; only close when reaching 0
        if let Some(sock) = net::socket_table().get(self.socket_id) {
            if sock.decrement_refcount() == 0 {
                net::socket_table().close(self.socket_id);
            }
        }
    }
}

// ============================================================================
// R23-5 fix: stdin 阻塞等待支持
// ============================================================================

use alloc::collections::VecDeque;

/// stdin 等待队列
///
/// 当 sys_read(fd=0) 没有数据时，进程会被加入此队列并阻塞。
/// 键盘/串口中断通过 wake_stdin_waiters() 唤醒等待者。
static STDIN_WAITERS: spin::Mutex<VecDeque<ProcessId>> = spin::Mutex::new(VecDeque::new());

/// 准备等待 stdin 输入（第一阶段）
///
/// 在检查缓冲区为空后调用此函数，将当前进程加入等待队列。
/// 必须在持有键盘缓冲区检查的同一临界区内调用，以避免丢失唤醒。
///
/// # Returns
///
/// 成功入队返回 true，无当前进程返回 false
fn stdin_prepare_to_wait() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };

    // 在关中断状态下操作
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut waiters = STDIN_WAITERS.lock();

        // 避免重复添加：检查是否已经在等待队列中
        // 这防止了当 force_reschedule 返回（因没有其他进程）时
        // 进程在循环中反复将自己添加到队列导致内存耗尽
        if !waiters.iter().any(|&p| p == pid) {
            waiters.push_back(pid);
        }

        // 将进程状态设为阻塞
        if let Some(proc_arc) = get_process(pid) {
            let mut proc = proc_arc.lock();
            proc.state = ProcessState::Blocked;
        }
    });

    true
}

/// 完成等待（第二阶段）
///
/// 在 prepare_to_wait 后调用，实际让出 CPU。
/// 如果没有其他进程可调度，会进入 HLT 循环等待中断唤醒。
fn stdin_finish_wait() {
    // 尝试切换到其他进程
    crate::force_reschedule();

    // 如果 force_reschedule 返回，说明没有其他进程可运行
    // 当前进程已被标记为 Blocked，需要等待中断（键盘/串口）唤醒
    // 进入 HLT 循环，避免忙等消耗 CPU
    loop {
        // 必须在关中断状态下检查进程状态，避免与中断处理程序竞争
        // enable_and_hlt 后中断是开启的，需要先关闭再检查
        let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
            if let Some(pid) = current_pid() {
                if let Some(proc_arc) = get_process(pid) {
                    let proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        // 已被唤醒（可能是键盘中断），退出等待
                        return false;
                    }
                }
            }
            true // 继续等待
        });

        if !should_continue {
            break;
        }

        // 启用中断并等待（HLT 会在下一个中断时唤醒）
        // 键盘/串口中断会调用 wake_stdin_waiters() 将进程设为 Ready
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}

/// 唤醒一个等待 stdin 的进程
///
/// 由键盘/串口中断处理器调用。
/// 使用 wake_one 语义以避免惊群效应。
pub fn wake_stdin_waiters() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut waiters = STDIN_WAITERS.lock();
        // 清理已退出的进程并唤醒第一个有效等待者
        while let Some(pid) = waiters.pop_front() {
            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                    return; // 只唤醒一个
                }
            }
            // 进程不存在或不在阻塞状态，继续检查下一个
        }
    });
}

// ============================================================================
// Socket Wait Hooks Implementation (scheduler integration for net crate)
// ============================================================================

use alloc::collections::{BTreeMap, BTreeSet};

/// Per-queue waiter tracking for socket blocking operations.
///
/// Uses the WaitQueue address as a unique identifier. Each queue maintains
/// a FIFO list of waiting process IDs with optional timeout deadlines.
struct SocketWaiters {
    /// Map from queue address to list of (ProcessId, deadline_ticks)
    /// Deadline is None for indefinite wait, Some(ticks) for timeout
    waiters: BTreeMap<usize, VecDeque<(ProcessId, Option<u64>)>>,
    /// Track timed-out waiters to report correct WaitOutcome.
    ///
    /// When a waiter times out (via check_timeouts or inline check), we add
    /// their PID here. When wait() returns, it consumes this marker to
    /// distinguish TimedOut from Woken (fixes race between timer and wake).
    timed_out: BTreeSet<ProcessId>,
}

impl SocketWaiters {
    const fn new() -> Self {
        SocketWaiters {
            waiters: BTreeMap::new(),
            timed_out: BTreeSet::new(),
        }
    }

    /// Add current process to wait queue.
    fn add_waiter(&mut self, queue_addr: usize, pid: ProcessId, deadline: Option<u64>) {
        self.waiters
            .entry(queue_addr)
            .or_insert_with(VecDeque::new)
            .push_back((pid, deadline));
    }

    /// Remove a specific process from a queue (on wakeup or timeout).
    fn remove_waiter(&mut self, queue_addr: usize, pid: ProcessId) -> bool {
        if let Some(queue) = self.waiters.get_mut(&queue_addr) {
            if let Some(pos) = queue.iter().position(|(p, _)| *p == pid) {
                queue.remove(pos);
                // Clean up empty queue entries
                if queue.is_empty() {
                    self.waiters.remove(&queue_addr);
                }
                return true;
            }
        }
        false
    }

    /// Mark a process as timed out (for correct WaitOutcome reporting).
    fn mark_timed_out(&mut self, pid: ProcessId) {
        self.timed_out.insert(pid);
    }

    /// Consume the timeout marker for a process.
    ///
    /// Returns true if the process was marked as timed out (and removes the mark).
    fn consume_timeout(&mut self, pid: ProcessId) -> bool {
        self.timed_out.remove(&pid)
    }

    /// Wake one waiter from a queue (FIFO order).
    fn wake_one(&mut self, queue_addr: usize) -> Option<ProcessId> {
        if let Some(queue) = self.waiters.get_mut(&queue_addr) {
            while let Some((pid, _)) = queue.pop_front() {
                // Verify process still exists and is blocked
                if let Some(proc_arc) = get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.state = ProcessState::Ready;
                        // Clean up empty queue
                        if queue.is_empty() {
                            self.waiters.remove(&queue_addr);
                        }
                        return Some(pid);
                    }
                }
                // Process gone or not blocked, try next
            }
            // All waiters invalid, clean up
            self.waiters.remove(&queue_addr);
        }
        None
    }

    /// Wake all waiters from a queue.
    fn wake_all(&mut self, queue_addr: usize) -> usize {
        let mut woken = 0;
        if let Some(mut queue) = self.waiters.remove(&queue_addr) {
            while let Some((pid, _)) = queue.pop_front() {
                if let Some(proc_arc) = get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.state = ProcessState::Ready;
                        woken += 1;
                    }
                }
            }
        }
        woken
    }

    /// Check and wake timed-out waiters. Called from timer interrupt.
    ///
    /// Also cleans up waiters for processes that have exited, preventing
    /// memory leaks and stale entries in the waiter queues.
    ///
    /// Uses fixed-size stack buffer to avoid heap allocation in IRQ context.
    fn check_timeouts(&mut self, current_ticks: u64) {
        // Maximum timeouts processed per tick to avoid spending too long in IRQ
        const MAX_TIMEOUTS_PER_TICK: usize = 16;

        // Use stack array instead of Vec to avoid IRQ-context allocation
        // Each entry: (queue_addr, pid, is_timeout vs is_exited)
        let mut expired: [Option<(usize, ProcessId, bool)>; MAX_TIMEOUTS_PER_TICK] =
            [None; MAX_TIMEOUTS_PER_TICK];
        let mut count = 0;

        // Collect expired or exited waiters
        for (&queue_addr, queue) in self.waiters.iter() {
            for &(pid, deadline) in queue.iter() {
                if count >= MAX_TIMEOUTS_PER_TICK {
                    break; // Will catch remaining on next tick
                }
                let is_timeout = deadline.map(|dl| current_ticks >= dl).unwrap_or(false);
                let is_exited = get_process(pid).is_none();
                if is_timeout || is_exited {
                    expired[count] = Some((queue_addr, pid, is_timeout));
                    count += 1;
                }
            }
        }

        // Wake expired waiters and drop entries for dead processes
        let mut queues_to_clean: [Option<usize>; MAX_TIMEOUTS_PER_TICK] =
            [None; MAX_TIMEOUTS_PER_TICK];
        let mut clean_count = 0;

        for entry in expired.iter().take(count).flatten() {
            let (queue_addr, pid, is_timeout) = *entry;

            if let Some(queue) = self.waiters.get_mut(&queue_addr) {
                if let Some(pos) = queue.iter().position(|(p, _)| *p == pid) {
                    queue.remove(pos);

                    // Mark as timed out for correct WaitOutcome (only if timeout, not exit)
                    if is_timeout {
                        self.timed_out.insert(pid);
                    }

                    // Wake the process if it still exists
                    if let Some(proc_arc) = get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.state = ProcessState::Ready;
                        }
                    }

                    // Track queues that may need cleanup
                    if queue.is_empty() && clean_count < MAX_TIMEOUTS_PER_TICK {
                        queues_to_clean[clean_count] = Some(queue_addr);
                        clean_count += 1;
                    }
                }
            }
        }

        // Clean up empty queues (separate pass to avoid borrow issues)
        for addr in queues_to_clean.iter().take(clean_count).flatten() {
            if let Some(queue) = self.waiters.get(addr) {
                if queue.is_empty() {
                    self.waiters.remove(addr);
                }
            }
        }

        // Clean up stale timeout markers for exited processes (prevents PID reuse issues)
        // Only do this periodically to avoid overhead on every tick
        if current_ticks % 100 == 0 {
            self.timed_out.retain(|pid| get_process(*pid).is_some());
        }
    }
}

/// Global socket waiter tracking.
static SOCKET_WAITERS: spin::Mutex<SocketWaiters> = spin::Mutex::new(SocketWaiters::new());

/// Kernel implementation of SocketWaitHooks trait.
///
/// Provides true blocking waits with scheduler integration and timeout support.
pub struct KernelSocketWaitHooks;

impl net::SocketWaitHooks for KernelSocketWaitHooks {
    fn wait(&self, queue: &net::WaitQueue, timeout_ns: Option<u64>) -> net::WaitOutcome {
        // Get current process
        let pid = match current_pid() {
            Some(p) => p,
            None => return net::WaitOutcome::NoProcess,
        };

        // Calculate deadline in ticks (if timeout specified)
        // Timer tick is 1ms (time::on_timer_tick increments every millisecond)
        const NS_PER_TICK: u64 = 1_000_000;
        let deadline = timeout_ns.map(|ns| {
            let current = crate::get_ticks();
            let ticks = (ns + NS_PER_TICK - 1) / NS_PER_TICK; // Round up
            current.saturating_add(ticks)
        });

        // Queue address as unique identifier
        let queue_addr = queue as *const _ as usize;

        // Phase 1: Add to wait queue and mark blocked (with interrupts disabled)
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut waiters = SOCKET_WAITERS.lock();

            // Avoid duplicate entries
            if let Some(q) = waiters.waiters.get(&queue_addr) {
                if q.iter().any(|(p, _)| *p == pid) {
                    return; // Already waiting
                }
            }

            waiters.add_waiter(queue_addr, pid, deadline);

            // Mark process as blocked
            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                proc.state = ProcessState::Blocked;
            }
        });

        // Phase 2: Yield CPU and wait for wakeup
        crate::force_reschedule();

        // Phase 3: HLT loop waiting for interrupt (if no other process to run)
        loop {
            let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
                if let Some(proc_arc) = get_process(pid) {
                    let proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        return false; // Woken up
                    }
                } else {
                    return false; // Process gone
                }

                // Check if closed
                if queue.is_closed() {
                    // Remove from wait queue
                    SOCKET_WAITERS.lock().remove_waiter(queue_addr, pid);
                    // Mark ready so we can return
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().state = ProcessState::Ready;
                    }
                    return false;
                }

                // Check timeout
                if let Some(dl) = deadline {
                    if crate::get_ticks() >= dl {
                        // Timeout expired - mark and remove
                        let mut waiters = SOCKET_WAITERS.lock();
                        waiters.remove_waiter(queue_addr, pid);
                        waiters.mark_timed_out(pid);
                        if let Some(proc_arc) = get_process(pid) {
                            proc_arc.lock().state = ProcessState::Ready;
                        }
                        return false;
                    }
                }

                true // Continue waiting
            });

            if !should_continue {
                break;
            }

            // Wait for interrupt (timer or network)
            x86_64::instructions::interrupts::enable_and_hlt();
        }

        // Determine outcome using timeout marker (fixes race between timer and wake)
        if queue.is_closed() {
            // Consume any stale timeout marker
            SOCKET_WAITERS.lock().consume_timeout(pid);
            return net::WaitOutcome::Closed;
        }

        // Check if we were marked as timed out (by timer callback or inline check)
        if SOCKET_WAITERS.lock().consume_timeout(pid) {
            return net::WaitOutcome::TimedOut;
        }

        net::WaitOutcome::Woken
    }

    fn wake_one(&self, queue: &net::WaitQueue) {
        let queue_addr = queue as *const _ as usize;
        x86_64::instructions::interrupts::without_interrupts(|| {
            SOCKET_WAITERS.lock().wake_one(queue_addr);
        });
    }

    fn wake_all(&self, queue: &net::WaitQueue) {
        let queue_addr = queue as *const _ as usize;
        x86_64::instructions::interrupts::without_interrupts(|| {
            SOCKET_WAITERS.lock().wake_all(queue_addr);
        });
    }

    fn get_ticks(&self) -> u64 {
        crate::get_ticks()
    }
}

/// Static instance of KernelSocketWaitHooks for registration.
static KERNEL_SOCKET_WAIT_HOOKS: KernelSocketWaitHooks = KernelSocketWaitHooks;

/// Register socket wait hooks with the net crate.
///
/// Called during kernel initialization after process module is ready.
pub fn register_socket_hooks() {
    net::register_socket_wait_hooks(&KERNEL_SOCKET_WAIT_HOOKS);
}

/// Timer callback to check socket wait timeouts.
///
/// Called from scheduler tick to wake processes whose timeouts have expired.
pub fn check_socket_timeouts() {
    let current_ticks = crate::get_ticks();
    // Use try_lock to avoid blocking in IRQ context
    if let Some(mut waiters) = SOCKET_WAITERS.try_lock() {
        waiters.check_timeouts(current_ticks);
    }
}

/// 最大参数总字节数（argv + envp 字符串总大小上限）
const MAX_ARG_TOTAL: usize = 128 * 1024;

/// 单个参数最大长度
const MAX_ARG_STRLEN: usize = 4096;

/// 最大单次读写长度（X-2 安全修复：防止内核堆耗尽 DoS）
///
/// 用户可请求任意大小的 count，如果不限制会导致：
/// - 内核尝试分配 GB 级别的 Vec
/// - OOM panic 或堆耗尽
/// - 任意用户进程可 DoS 整个系统
///
/// Linux 通常允许单次最大 2GB，但考虑到 Zero-OS 是微内核，
/// 1MB 上限足够大多数场景，同时保护内核免受资源耗尽攻击。
const MAX_RW_SIZE: usize = 1 * 1024 * 1024;

/// 系统调用号定义（参考Linux系统调用表）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // 进程管理
    Exit = 60,           // 退出进程
    ExitGroup = 231,     // 退出进程组
    Fork = 57,           // 创建子进程
    Exec = 59,           // 执行程序
    Wait = 61,           // 等待子进程
    GetPid = 39,         // 获取进程ID
    GetTid = 186,        // 获取线程ID
    GetPPid = 110,       // 获取父进程ID
    SetTidAddress = 218, // 设置 clear_child_tid
    SetRobustList = 273, // 设置 robust_list
    Kill = 62,           // 发送信号

    // 文件I/O
    Read = 0,   // 读取文件
    Write = 1,  // 写入文件
    Open = 2,   // 打开文件
    Close = 3,  // 关闭文件
    Stat = 4,   // 获取文件状态
    Fstat = 5,  // 获取文件描述符状态
    Lseek = 8,  // 移动文件指针
    Ioctl = 16, // I/O 控制

    // 内存管理
    Brk = 12,      // 改变数据段大小
    Mmap = 9,      // 内存映射
    Munmap = 11,   // 取消内存映射
    Mprotect = 10, // 设置内存保护

    // 进程间通信
    Pipe = 22, // 创建管道
    Dup = 32,  // 复制文件描述符
    Dup2 = 33, // 复制文件描述符到指定位置

    // 时间相关
    Time = 201,  // 获取时间
    Sleep = 35,  // 睡眠
    Futex = 202, // 快速用户空间互斥锁

    // 其他
    Yield = 24,      // 主动让出CPU
    GetCwd = 79,     // 获取当前工作目录
    Chdir = 80,      // 改变当前工作目录
    GetRandom = 318, // 获取随机字节
}

/// 系统调用错误码
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Success = 0,     // 成功
    EPERM = -1,      // 操作不允许
    ENOENT = -2,     // 文件或目录不存在
    ESRCH = -3,      // 进程不存在
    EINTR = -4,      // 系统调用被中断
    EIO = -5,        // I/O错误
    ENXIO = -6,      // 设备不存在
    E2BIG = -7,      // 参数列表过长
    ENOEXEC = -8,    // 执行格式错误
    EBADF = -9,      // 文件描述符错误
    ECHILD = -10,    // 没有子进程
    EAGAIN = -11,    // 资源暂时不可用
    ENOMEM = -12,    // 内存不足
    EACCES = -13,    // 权限不足
    EFAULT = -14,    // 地址错误
    EBUSY = -16,     // 设备或资源忙
    EEXIST = -17,    // 文件已存在
    EXDEV = -18,     // 跨设备链接 (cross-device link)
    ENOTDIR = -20,   // 不是目录
    EISDIR = -21,    // 是目录
    EINVAL = -22,    // 无效参数
    ENFILE = -23,    // 系统打开文件过多
    EMFILE = -24,    // 进程打开文件过多
    ENOTTY = -25,    // 不是终端设备
    EPIPE = -32,     // 管道破裂
    ERANGE = -34,    // 结果超出范围
    ENOSYS = -38,    // 功能未实现
    ENOTEMPTY = -39, // 目录非空
    ELOOP = -40,     // 符号链接过多或禁止符号链接
    ENOSPC = -28,    // 设备无空间 (no space left on device)
    // Socket-related errors (Linux ABI)
    ENOTSOCK = -88,        // 套接字操作目标不是套接字
    EDESTADDRREQ = -89,    // 需要目标地址
    EMSGSIZE = -90,        // 消息太长
    EPROTOTYPE = -91,      // 协议类型错误
    EPROTONOSUPPORT = -93, // 协议不支持
    EAFNOSUPPORT = -97,    // 地址族不支持
    EADDRINUSE = -98,      // 地址已被使用
    EADDRNOTAVAIL = -99,   // 无法分配请求的地址
    ENETDOWN = -100,       // 网络不可用
    ECONNREFUSED = -111,   // 连接被拒绝
    EISCONN = -106,        // 套接字已连接
    ENOTCONN = -107,       // 传输端点未连接
    ETIMEDOUT = -110,      // R39-6 FIX: 操作超时
    EALREADY = -114,       // 操作已经在进行
    EINPROGRESS = -115,    // 操作正在进行
    EOPNOTSUPP = -95,      // 操作不支持
    ECONNABORTED = -103,   // R51-1: 连接被中止 (accept on closed listener)
    // E.4 PI: Robust futex error
    EOWNERDEAD = -130,     // E.4 PI: Robust futex - 锁持有者已退出
}

impl SyscallError {
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// 系统调用结果类型
pub type SyscallResult = Result<usize, SyscallError>;

// ============================================================================
// Syscall 帧访问（供 clone/fork 使用）
// ============================================================================

/// Syscall 帧结构（与 arch::syscall 中的布局一致）
///
/// 表示 syscall_entry_stub 保存到内核栈上的寄存器帧。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub rax: u64, // 0x00: 系统调用号 / 返回值
    pub rcx: u64, // 0x08: 用户 RIP (syscall 保存)
    pub rdx: u64, // 0x10: arg2
    pub rbx: u64, // 0x18: callee-saved
    pub rsp: u64, // 0x20: 用户 RSP
    pub rbp: u64, // 0x28: callee-saved
    pub rsi: u64, // 0x30: arg1
    pub rdi: u64, // 0x38: arg0
    pub r8: u64,  // 0x40: arg4
    pub r9: u64,  // 0x48: arg5
    pub r10: u64, // 0x50: arg3
    pub r11: u64, // 0x58: 用户 RFLAGS (syscall 保存)
    pub r12: u64, // 0x60: callee-saved
    pub r13: u64, // 0x68: callee-saved
    pub r14: u64, // 0x70: callee-saved
    pub r15: u64, // 0x78: callee-saved
}

/// 获取当前 syscall 帧的回调类型
///
/// 由 arch 模块注册，用于 clone/fork 读取调用者的寄存器状态
pub type GetSyscallFrameCallback = fn() -> Option<&'static SyscallFrame>;

/// 全局 syscall 帧回调
static SYSCALL_FRAME_CALLBACK: spin::Mutex<Option<GetSyscallFrameCallback>> =
    spin::Mutex::new(None);

/// 注册获取 syscall 帧的回调
///
/// 由 arch 模块在初始化时调用
pub fn register_syscall_frame_callback(cb: GetSyscallFrameCallback) {
    *SYSCALL_FRAME_CALLBACK.lock() = Some(cb);
}

/// 获取当前 syscall 帧
///
/// 仅在 syscall 处理期间有效，用于 clone/fork
fn get_current_syscall_frame() -> Option<&'static SyscallFrame> {
    if let Some(cb) = *SYSCALL_FRAME_CALLBACK.lock() {
        cb()
    } else {
        None
    }
}

/// 管道创建回调类型
///
/// 由 ipc 模块注册，返回 (read_fd, write_fd) 或错误
pub type PipeCreateCallback = fn() -> Result<(i32, i32), SyscallError>;

/// 文件描述符读取回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的读取
/// 参数: (fd, buf, count) -> bytes_read 或错误
pub type FdReadCallback = fn(i32, &mut [u8]) -> Result<usize, SyscallError>;

/// 文件描述符写入回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的写入
/// 参数: (fd, buf) -> bytes_written 或错误
pub type FdWriteCallback = fn(i32, &[u8]) -> Result<usize, SyscallError>;

/// 文件描述符关闭回调类型
///
/// 由 ipc 模块注册，处理文件描述符的关闭
pub type FdCloseCallback = fn(i32) -> Result<(), SyscallError>;

/// Futex 操作回调类型
///
/// 由 ipc 模块注册，处理 FUTEX_WAIT 和 FUTEX_WAKE 操作
/// 参数: (uaddr, op, val, current_value) -> result 或错误
/// R39-6 FIX: 增加 timeout_ns 参数支持 FUTEX_WAIT_TIMEOUT
pub type FutexCallback = fn(usize, i32, u32, u32, Option<u64>) -> Result<usize, SyscallError>;

/// VFS 打开文件回调类型
///
/// 由 vfs 模块注册，处理文件打开
/// 参数: (path, flags, mode) -> FileOps box 或错误
/// 返回的 FileOps 由 syscall 模块存入 fd_table
pub type VfsOpenCallback =
    fn(&str, u32, u32) -> Result<crate::process::FileDescriptor, SyscallError>;

/// VFS 打开文件回调类型（带 resolve 标志，用于 openat2）
///
/// 由 vfs 模块注册，处理带 resolve 标志的文件打开
/// 参数: (path, flags, mode, resolve_flags) -> FileOps box 或错误
pub type VfsOpenWithResolveCallback =
    fn(&str, u32, u32, u64) -> Result<crate::process::FileDescriptor, SyscallError>;

/// VFS 获取文件状态回调类型
///
/// 由 vfs 模块注册，处理 stat 系统调用
/// 参数: (path) -> (size, mode, ino, dev, nlink, uid, gid, rdev, atime, mtime, ctime) 或错误
pub type VfsStatCallback = fn(&str) -> Result<VfsStat, SyscallError>;

/// VFS lseek 回调类型
///
/// 由 vfs 模块注册，处理文件 seek 操作
/// 参数: (file_ops_ref, offset, whence) -> 新偏移位置 或错误
/// file_ops_ref 是通过 as_any 获取的引用
pub type VfsLseekCallback = fn(&dyn core::any::Any, i64, i32) -> Result<u64, SyscallError>;

/// VFS 创建文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录创建
/// 参数: (path, mode, is_dir) -> () 或错误
pub type VfsCreateCallback = fn(&str, u32, bool) -> Result<(), SyscallError>;

/// VFS 删除文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录删除
/// 参数: (path) -> () 或错误
pub type VfsUnlinkCallback = fn(&str) -> Result<(), SyscallError>;

/// VFS 读取目录项回调类型
///
/// 由 vfs 模块注册，处理目录内容读取
/// 参数: (fd, buf) -> 返回实际读取的目录项列表
pub type VfsReaddirCallback = fn(i32) -> Result<alloc::vec::Vec<DirEntry>, SyscallError>;

/// VFS 截断文件回调类型
///
/// 由 vfs 模块注册，处理文件截断操作
/// 参数: (fd, length) -> () 或错误
pub type VfsTruncateCallback = fn(i32, u64) -> Result<(), SyscallError>;

/// R74-2 FIX: Mount namespace materialization callback type.
///
/// Registered by vfs module to force eager materialization of mount tables.
/// This prevents security vulnerabilities where lazy materialization allows
/// parent namespace mounts to leak into child namespaces.
///
/// Parameter: Arc<MountNamespace> to materialize
pub type MountNsMaterializeCallback = fn(&alloc::sync::Arc<crate::mount_namespace::MountNamespace>);

/// 文件类型枚举(本地定义避免循环依赖)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Symlink,
    Fifo,
    Socket,
}

/// 目录项结构(本地定义避免循环依赖)
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub ino: u64,
    pub file_type: FileType,
}

/// VFS 文件状态信息
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VfsStat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

lazy_static::lazy_static! {
    /// 管道创建回调
    static ref PIPE_CREATE_CALLBACK: spin::Mutex<Option<PipeCreateCallback>> = spin::Mutex::new(None);
    /// 文件描述符读取回调
    static ref FD_READ_CALLBACK: spin::Mutex<Option<FdReadCallback>> = spin::Mutex::new(None);
    /// 文件描述符写入回调
    static ref FD_WRITE_CALLBACK: spin::Mutex<Option<FdWriteCallback>> = spin::Mutex::new(None);
    /// 文件描述符关闭回调
    static ref FD_CLOSE_CALLBACK: spin::Mutex<Option<FdCloseCallback>> = spin::Mutex::new(None);
    /// Futex 操作回调
    static ref FUTEX_CALLBACK: spin::Mutex<Option<FutexCallback>> = spin::Mutex::new(None);
    /// VFS 打开文件回调
    static ref VFS_OPEN_CALLBACK: spin::Mutex<Option<VfsOpenCallback>> = spin::Mutex::new(None);
    /// VFS 带 resolve 标志的打开文件回调 (openat2)
    static ref VFS_OPEN_WITH_RESOLVE_CALLBACK: spin::Mutex<Option<VfsOpenWithResolveCallback>> = spin::Mutex::new(None);
    /// VFS stat 回调
    static ref VFS_STAT_CALLBACK: spin::Mutex<Option<VfsStatCallback>> = spin::Mutex::new(None);
    /// VFS lseek 回调
    static ref VFS_LSEEK_CALLBACK: spin::Mutex<Option<VfsLseekCallback>> = spin::Mutex::new(None);
    /// VFS 创建回调
    static ref VFS_CREATE_CALLBACK: spin::Mutex<Option<VfsCreateCallback>> = spin::Mutex::new(None);
    /// VFS 删除回调
    static ref VFS_UNLINK_CALLBACK: spin::Mutex<Option<VfsUnlinkCallback>> = spin::Mutex::new(None);
    /// VFS 读取目录回调
    static ref VFS_READDIR_CALLBACK: spin::Mutex<Option<VfsReaddirCallback>> = spin::Mutex::new(None);
    /// VFS 截断回调
    static ref VFS_TRUNCATE_CALLBACK: spin::Mutex<Option<VfsTruncateCallback>> = spin::Mutex::new(None);
    /// R74-2 FIX: Mount namespace materialization callback
    static ref MOUNT_NS_MATERIALIZE_CALLBACK: spin::Mutex<Option<MountNsMaterializeCallback>> = spin::Mutex::new(None);
}

/// 注册管道创建回调
pub fn register_pipe_callback(cb: PipeCreateCallback) {
    *PIPE_CREATE_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符读取回调
pub fn register_fd_read_callback(cb: FdReadCallback) {
    *FD_READ_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符写入回调
pub fn register_fd_write_callback(cb: FdWriteCallback) {
    *FD_WRITE_CALLBACK.lock() = Some(cb);
}

/// 注册文件描述符关闭回调
pub fn register_fd_close_callback(cb: FdCloseCallback) {
    *FD_CLOSE_CALLBACK.lock() = Some(cb);
}

/// 注册 Futex 操作回调
pub fn register_futex_callback(cb: FutexCallback) {
    *FUTEX_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 打开文件回调
pub fn register_vfs_open_callback(cb: VfsOpenCallback) {
    *VFS_OPEN_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 带 resolve 标志的打开文件回调 (openat2)
pub fn register_vfs_open_with_resolve_callback(cb: VfsOpenWithResolveCallback) {
    *VFS_OPEN_WITH_RESOLVE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS stat 回调
pub fn register_vfs_stat_callback(cb: VfsStatCallback) {
    *VFS_STAT_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS lseek 回调
pub fn register_vfs_lseek_callback(cb: VfsLseekCallback) {
    *VFS_LSEEK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 创建回调
pub fn register_vfs_create_callback(cb: VfsCreateCallback) {
    *VFS_CREATE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 删除回调
pub fn register_vfs_unlink_callback(cb: VfsUnlinkCallback) {
    *VFS_UNLINK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 读取目录回调
pub fn register_vfs_readdir_callback(cb: VfsReaddirCallback) {
    *VFS_READDIR_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 截断回调
pub fn register_vfs_truncate_callback(cb: VfsTruncateCallback) {
    *VFS_TRUNCATE_CALLBACK.lock() = Some(cb);
}

/// R74-2 FIX: Register mount namespace materialization callback.
///
/// The VFS module **must** call this at initialization to register the function
/// that materializes mount namespace tables. This forces eager table creation
/// to prevent parent namespace mounts from leaking into child namespaces.
///
/// # R74-2 Enhancement
///
/// Missing registration will panic during namespace creation to avoid silent
/// isolation bypasses. This enforces proper initialization order: VFS callbacks
/// must be registered before any namespace operations (clone/unshare with CLONE_NEWNS).
pub fn register_mount_ns_materialize_callback(cb: MountNsMaterializeCallback) {
    *MOUNT_NS_MATERIALIZE_CALLBACK.lock() = Some(cb);
}

/// R74-2 Test Helper: Check if mount namespace materialization callback is registered.
///
/// Used by runtime tests to verify the R74-2 fix is properly initialized.
/// Returns true if the callback is registered, false otherwise.
pub fn test_is_mount_ns_callback_registered() -> bool {
    MOUNT_NS_MATERIALIZE_CALLBACK.lock().is_some()
}

/// R74-2 FIX: Mandatory mount namespace materialization.
///
/// Private helper used by sys_clone and sys_unshare to ensure mount tables are
/// eagerly materialized when namespaces are created.
///
/// # R74-2 Enhancement: Panic if Callback Absent
///
/// This function will panic if the VFS has not registered the materialization
/// callback. This prevents silent isolation bypasses where namespace operations
/// could proceed without proper mount table snapshots, potentially leaking
/// parent namespace mounts to child namespaces.
///
/// # Panics
///
/// Panics with a critical error if `register_mount_ns_materialize_callback()`
/// was not called before this function is invoked.
fn materialize_namespace(ns: &Arc<crate::mount_namespace::MountNamespace>) {
    // R74-2 Enhancement: Mandatory callback - panic if not registered.
    // Copy the fn pointer out immediately to avoid holding lock during callback.
    // MountNsMaterializeCallback is `fn(...)` which is Copy, so we dereference
    // to copy the pointer and release the mutex before invoking.
    let cb = *MOUNT_NS_MATERIALIZE_CALLBACK.lock().as_ref().expect(
        "CRITICAL: Mount namespace materialization callback not registered! \
         VFS must call register_mount_ns_materialize_callback() before any \
         namespace operations (clone/unshare with CLONE_NEWNS). This is a \
         kernel initialization bug."
    );
    cb(ns);
}

// ============================================================================
// VFS 辅助函数
// ============================================================================

/// S_IFDIR 常量 - 目录类型标识
const S_IFDIR: u32 = 0o040000;
/// S_IFMT 常量 - 文件类型掩码
const S_IFMT: u32 = 0o170000;

/// 检查 mode 是否表示目录
#[inline]
fn is_directory_mode(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// 用户空间地址上界
///
/// x86_64 规范地址空间中，用户空间使用低半区（0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF）
/// 内核空间使用高半区（0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF）
const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// sys_exec 允许的最大 ELF 映像大小（16 MB）
///
/// 防止恶意用户请求过大的内存分配导致内核资源耗尽
const MAX_EXEC_IMAGE_SIZE: usize = 16 * 1024 * 1024;

/// R41-4 FIX: 用于 LSM 策略检查的 ELF 前缀哈希长度
///
/// 对 ELF 二进制内容的前 4KB 计算 SHA-256 哈希，替代使用 argv[0] 路径。
/// 这防止了攻击者通过伪造 argv[0] 绕过 LSM 策略。
const EXEC_HASH_WINDOW: usize = 4096;

// mmap 跟踪已移至 Process 结构体的 mmap_regions 和 next_mmap_addr 字段

/// 验证用户空间指针
///
/// 检查指针是否：
/// 1. 非空
/// 2. 长度有效（非零）
/// 3. 地址范围在用户空间内（不会访问内核内存）
/// 4. 不会发生地址回绕
///
/// # Arguments
/// * `ptr` - 用户提供的指针
/// * `len` - 要访问的字节数
///
/// # Returns
/// 如果指针有效返回 Ok(()), 否则返回 EFAULT 错误
fn validate_user_ptr(ptr: *const u8, len: usize) -> Result<(), SyscallError> {
    // 空指针检查
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 零长度检查
    if len == 0 {
        return Err(SyscallError::EFAULT);
    }

    let start = ptr as usize;

    // 地址回绕检查
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::EFAULT),
    };

    // 用户空间边界检查：确保整个缓冲区都在用户空间内
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    Ok(())
}

/// 验证用户空间可写指针
///
/// 与 validate_user_ptr 相同的检查，用于写入操作
#[inline]
fn validate_user_ptr_mut(ptr: *mut u8, len: usize) -> Result<(), SyscallError> {
    validate_user_ptr(ptr as *const u8, len)
}

/// 验证用户空间地址是否已映射且具备所需权限
///
/// 通过页表遍历验证地址范围内的每一页都已映射且具有正确的权限标志。
/// 这比 validate_user_ptr 更严格，可以防止访问未映射内存导致的内核崩溃。
///
/// # Arguments
/// * `ptr` - 用户空间缓冲区起始地址
/// * `len` - 缓冲区长度
/// * `require_write` - 是否需要写入权限
///
/// # Returns
/// 如果所有页都已正确映射返回 Ok(()), 否则返回 EFAULT
fn verify_user_memory(ptr: *const u8, len: usize, require_write: bool) -> Result<(), SyscallError> {
    // 先进行基本的边界检查
    validate_user_ptr(ptr, len)?;

    if len == 0 {
        return Ok(());
    }

    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(SyscallError::EFAULT)?;

    // 遍历页表验证映射
    unsafe {
        mm::page_table::with_current_manager(
            VirtAddr::new(0),
            |manager| -> Result<(), SyscallError> {
                let mut page_addr = start & !0xfff; // 对齐到页边界
                while page_addr < end {
                    // 查询页表获取映射信息和标志
                    let (_, flags) = manager
                        .translate_with_flags(VirtAddr::new(page_addr as u64))
                        .ok_or(SyscallError::EFAULT)?;

                    // 检查页是否存在且用户可访问
                    if !flags.contains(PageTableFlags::PRESENT)
                        || !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                    {
                        return Err(SyscallError::EFAULT);
                    }

                    // 如果需要写入权限，检查 WRITABLE 或 BIT_9 (COW) 标志
                    // COW 页面标记为只读但有 BIT_9，写入时会触发 #PF 并由 COW 处理器创建可写副本
                    // 真正的只读页面（如代码段）没有这两个标志，应该拒绝写入
                    if require_write
                        && !flags.contains(PageTableFlags::WRITABLE)
                        && !flags.contains(PageTableFlags::BIT_9)
                    {
                        return Err(SyscallError::EFAULT);
                    }

                    page_addr = page_addr.checked_add(0x1000).ok_or(SyscallError::EFAULT)?;
                }
                Ok(())
            },
        )
    }
}

/// 从用户态缓冲区安全复制数据到内核缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// # Arguments
/// * `dest` - 内核缓冲区（目标）
/// * `user_src` - 用户空间缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射返回 EFAULT
fn copy_from_user(dest: &mut [u8], user_src: *const u8) -> Result<(), SyscallError> {
    if dest.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_src, dest.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    crate::usercopy::copy_from_user_safe(dest, user_src).map_err(|_| SyscallError::EFAULT)
}

/// 将内核缓冲区的数据安全复制到用户态缓冲区
///
/// 使用容错拷贝机制：如果在拷贝过程中发生页错误，
/// 会返回 EFAULT 而非导致内核 panic（解决 TOCTOU 竞态条件）。
///
/// 注意：COW 页面会在写入时触发页错误，由 COW 处理器创建可写副本。
///
/// # Arguments
/// * `user_dst` - 用户空间缓冲区（目标）
/// * `src` - 内核缓冲区（源）
///
/// # Returns
/// 复制成功返回 Ok(()), 如果用户内存未映射或不可写返回 EFAULT
fn copy_to_user(user_dst: *mut u8, src: &[u8]) -> Result<(), SyscallError> {
    if src.is_empty() {
        return Ok(());
    }

    // 先进行基本的边界检查（地址范围验证）
    validate_user_ptr(user_dst as *const u8, src.len())?;

    // 使用容错拷贝：逐字节复制，页错误时返回 EFAULT
    // COW 页面会在 usercopy 过程中触发 #PF，由 COW 处理器处理
    crate::usercopy::copy_to_user_safe(user_dst, src).map_err(|_| SyscallError::EFAULT)
}

/// 从用户空间复制以 '\0' 结尾的 C 字符串到内核缓冲区
///
/// V-2 fix: 使用 usercopy 容错拷贝机制，防止 TOCTOU 攻击。
/// 如果用户在验证后取消映射内存，copy_from_user_safe 会安全返回错误
/// 而不是导致内核 panic。
///
/// 逐字节读取直到遇到 NUL 终止符，限制最大长度防止恶意无限字符串。
fn copy_user_cstring(ptr: *const u8) -> Result<Vec<u8>, SyscallError> {
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut buf = Vec::new();

    for i in 0..=MAX_ARG_STRLEN {
        // V-2 fix: 使用容错单字节拷贝
        // copy_from_user_safe 内部会：
        // 1. 创建 UserAccessGuard 处理 SMAP
        // 2. 创建 UserCopyGuard 登记 usercopy 状态
        // 3. 页错误时安全返回 Err 而非 panic
        let mut byte = [0u8; 1];
        crate::usercopy::copy_from_user_safe(&mut byte, unsafe { ptr.add(i) })
            .map_err(|_| SyscallError::EFAULT)?;

        if byte[0] == 0 {
            return Ok(buf);
        }
        buf.push(byte[0]);
    }

    // 字符串超过最大长度限制
    Err(SyscallError::E2BIG)
}

/// 将用户空间的字符串指针数组（以 NULL 结尾）复制到内核
///
/// V-2 fix: 使用 usercopy 容错拷贝机制读取指针数组，防止 TOCTOU 攻击。
///
/// 用于 exec 的 argv 和 envp 参数
fn copy_user_str_array(list_ptr: *const *const u8) -> Result<Vec<Vec<u8>>, SyscallError> {
    // NULL 指针表示空数组
    if list_ptr.is_null() {
        return Ok(Vec::new());
    }

    let word = mem::size_of::<usize>();
    let base = list_ptr as usize;
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;

    for idx in 0..MAX_ARG_COUNT {
        // 计算当前条目地址
        let entry_addr = base.checked_add(idx * word).ok_or(SyscallError::EFAULT)?;

        // V-2 fix: 使用容错拷贝读取指针值
        // 这确保了即使用户在我们读取时取消映射，也不会导致内核 panic
        let mut raw_ptr = [0u8; core::mem::size_of::<usize>()];
        crate::usercopy::copy_from_user_safe(&mut raw_ptr, entry_addr as *const u8)
            .map_err(|_| SyscallError::EFAULT)?;
        let entry = usize::from_ne_bytes(raw_ptr) as *const u8;

        if entry.is_null() {
            break; // NULL 终止
        }

        // 复制字符串内容（copy_user_cstring 现在也使用容错拷贝）
        let s = copy_user_cstring(entry)?;
        total = total
            .checked_add(s.len() + 1) // +1 for trailing '\0'
            .ok_or(SyscallError::E2BIG)?;
        if total > MAX_ARG_TOTAL {
            return Err(SyscallError::E2BIG);
        }

        items.push(s);
    }

    // 检查是否超过最大参数数量（没有遇到 NULL 终止）
    if items.len() == MAX_ARG_COUNT {
        return Err(SyscallError::E2BIG);
    }

    Ok(items)
}

/// 初始化系统调用处理器
pub fn init() {
    println!("Syscall handler initialized");
    println!("  Supported syscalls: exit, fork, getpid, read, write, yield");
}

/// Get audit subject from current process context
///
/// Returns AuditSubject with pid, uid, gid from current process credentials.
/// Falls back to kernel subject (pid 0) if no current process.
#[inline]
fn get_audit_subject() -> AuditSubject {
    if let Some(pid) = current_pid() {
        if let Some(creds) = crate::process::current_credentials() {
            AuditSubject::new(pid as u32, creds.euid, creds.egid, None)
        } else {
            // Process exists but credentials unavailable
            AuditSubject::new(pid as u32, 0, 0, None)
        }
    } else {
        AuditSubject::kernel()
    }
}

// ============================================================================
// LSM Integration Helpers
// ============================================================================

/// Map LSM errors to syscall errno values.
#[inline]
fn lsm_error_to_syscall(err: lsm::LsmError) -> SyscallError {
    match err {
        lsm::LsmError::Denied => SyscallError::EPERM,
        lsm::LsmError::Internal => SyscallError::EPERM,
    }
}

/// R26-6 FIX: Map capability errors to syscall errno values.
///
/// This ensures proper error reporting when capability operations fail,
/// rather than silently swallowing errors.
#[inline]
#[allow(dead_code)] // Will be used when capability syscalls are added
fn cap_error_to_syscall(err: cap::CapError) -> SyscallError {
    match err {
        cap::CapError::TableFull => SyscallError::EMFILE,
        cap::CapError::GenerationExhausted => SyscallError::ERANGE, // No EOVERFLOW, use ERANGE
        cap::CapError::InvalidCapId => SyscallError::EBADF,
        cap::CapError::DelegationDenied => SyscallError::EPERM,
        cap::CapError::InsufficientRights => SyscallError::EPERM,
        cap::CapError::InvalidOperation => SyscallError::EINVAL,
        cap::CapError::NoCurrentProcess => SyscallError::ESRCH,
    }
}

/// Map socket layer errors to syscall errno values.
///
/// Used by sys_socket/sys_bind/sys_sendto/sys_recvfrom to convert
/// SocketError into appropriate Linux errno codes.
#[inline]
fn socket_error_to_syscall(err: net::SocketError) -> SyscallError {
    match err {
        net::SocketError::InvalidDomain => SyscallError::EAFNOSUPPORT,
        net::SocketError::InvalidType => SyscallError::EPROTOTYPE,
        net::SocketError::InvalidProtocol => SyscallError::EPROTONOSUPPORT,
        net::SocketError::PermissionDenied | net::SocketError::PrivilegedPort => {
            SyscallError::EACCES
        }
        net::SocketError::PortInUse => SyscallError::EADDRINUSE,
        net::SocketError::NoPorts => SyscallError::EAGAIN,
        net::SocketError::NotBound => SyscallError::EDESTADDRREQ,
        net::SocketError::Closed | net::SocketError::NotFound => SyscallError::EBADF,
        net::SocketError::Timeout => SyscallError::ETIMEDOUT,
        net::SocketError::MessageTooLarge => SyscallError::EMSGSIZE,
        net::SocketError::NoProcess => SyscallError::ESRCH,
        net::SocketError::AlreadyConnected => SyscallError::EISCONN,
        net::SocketError::InProgress => SyscallError::EINPROGRESS,
        net::SocketError::WouldBlock => SyscallError::EAGAIN,
        net::SocketError::InvalidState => SyscallError::ENOTCONN,
        // R76-3 FIX: Per-namespace socket quota exceeded maps to EAGAIN (retriable)
        net::SocketError::QuotaExceeded => SyscallError::EAGAIN,
        net::SocketError::Udp(net::UdpError::PayloadTooLarge) => SyscallError::EMSGSIZE,
        net::SocketError::Udp(_) => SyscallError::EINVAL,
        net::SocketError::Lsm(e) => lsm_error_to_syscall(e),
    }
}

/// Map network TX errors to syscall errno values.
///
/// Used when transmitting TCP segments or UDP datagrams via the network device.
#[inline]
fn tx_error_to_syscall(err: net::TxError) -> SyscallError {
    match err {
        net::TxError::QueueFull => SyscallError::EAGAIN,
        net::TxError::LinkDown => SyscallError::ENETDOWN,
        net::TxError::InvalidBuffer => SyscallError::EINVAL,
        net::TxError::IoError => SyscallError::EIO,
    }
}

/// Build an LSM ProcessCtx from current process state.
/// Returns None if no current process is available.
#[inline]
fn lsm_current_process_ctx() -> Option<lsm::ProcessCtx> {
    lsm::ProcessCtx::from_current()
}

/// Build an LSM ProcessCtx from a locked Process struct.
#[inline]
fn lsm_process_ctx_from(proc: &crate::process::Process) -> lsm::ProcessCtx {
    // R39-3 FIX: 使用共享凭证读取 uid/gid/euid/egid
    let creds = proc.credentials.read();
    lsm::ProcessCtx::new(
        proc.pid, proc.tgid, creds.uid, creds.gid, creds.euid, creds.egid,
    )
}

/// Enforce task_fork LSM hook after fork/clone succeeds.
/// On denial, cleans up the child process and returns EPERM.
fn enforce_lsm_task_fork(parent_pid: ProcessId, child_pid: ProcessId) -> Result<(), SyscallError> {
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;
    let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;

    let (parent_ctx, child_ctx) = {
        let parent = parent_arc.lock();
        let child = child_arc.lock();
        (lsm_process_ctx_from(&parent), lsm_process_ctx_from(&child))
    };

    if let Err(err) = lsm::hook_task_fork(&parent_ctx, &child_ctx) {
        // Rollback: remove child from parent's children list and terminate
        if let Some(parent) = get_process(parent_pid) {
            let mut parent = parent.lock();
            parent.children.retain(|&pid| pid != child_pid);
        }
        // Use exit code 128 + signal (SIGSYS=31) to indicate security termination
        terminate_process(child_pid, 128 + 31);
        cleanup_zombie(child_pid);
        return Err(lsm_error_to_syscall(err));
    }

    Ok(())
}

// ============================================================================
// R65-13 FIX: Capability Operation Wrappers with LSM/Audit Integration
// ============================================================================

/// Allocate a capability with LSM check and audit logging.
///
/// # Security
///
/// 1. Calls LSM hook_task_cap_modify before allocation
/// 2. If LSM denies, returns EPERM without allocating
/// 3. On success, emits audit event for tracking
///
/// # Arguments
///
/// * `cap_table` - The capability table to allocate in
/// * `entry` - The capability entry to allocate
/// * `proc_ctx` - Process context for LSM check
///
/// # Returns
///
/// * `Ok(CapId)` - The allocated capability ID
/// * `Err(SyscallError)` - LSM denied or allocation failed
fn cap_allocate_with_lsm(
    cap_table: &cap::CapTable,
    entry: cap::CapEntry,
    proc_ctx: Option<&lsm::ProcessCtx>,
) -> Result<cap::CapId, SyscallError> {
    // Create a placeholder CapId for LSM check (will be replaced by actual ID)
    let placeholder_id = cap::CapId::INVALID;

    // LSM hook: check permission before allocation
    if let Some(ctx) = proc_ctx {
        if let Err(err) = lsm::hook_task_cap_modify(ctx, placeholder_id, lsm::cap_op::ALLOCATE) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // Perform the allocation
    let cap_id = cap_table.allocate(entry).map_err(cap_error_to_syscall)?;

    // Emit audit event on success
    if let Some(ctx) = proc_ctx {
        let subject =
            audit::AuditSubject::new(ctx.pid as u32, ctx.uid, ctx.gid, ctx.cap.map(|c| c.raw()));
        let timestamp = crate::time::get_ticks();
        let _ = audit::emit_capability_event(
            audit::AuditOutcome::Success,
            subject,
            cap_id.raw(),
            audit::AuditCapOperation::Allocate,
            None,
            0,
            timestamp,
        );
    }

    Ok(cap_id)
}

/// Revoke a capability with LSM check and audit logging.
///
/// # Security
///
/// 1. Calls LSM hook_task_cap_modify before revocation
/// 2. If LSM denies, returns EPERM without revoking
/// 3. On success, emits audit event for tracking
///
/// # Arguments
///
/// * `cap_table` - The capability table to revoke from
/// * `cap_id` - The capability ID to revoke
/// * `proc_ctx` - Process context for LSM check
///
/// # Returns
///
/// * `Ok(CapEntry)` - The revoked capability entry
/// * `Err(SyscallError)` - LSM denied or revocation failed
fn cap_revoke_with_lsm(
    cap_table: &cap::CapTable,
    cap_id: cap::CapId,
    proc_ctx: Option<&lsm::ProcessCtx>,
) -> Result<cap::CapEntry, SyscallError> {
    // LSM hook: check permission before revocation
    if let Some(ctx) = proc_ctx {
        if let Err(err) = lsm::hook_task_cap_modify(ctx, cap_id, lsm::cap_op::REVOKE) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // Perform the revocation
    let entry = cap_table.revoke(cap_id).map_err(cap_error_to_syscall)?;

    // Emit audit event on success
    if let Some(ctx) = proc_ctx {
        let subject =
            audit::AuditSubject::new(ctx.pid as u32, ctx.uid, ctx.gid, ctx.cap.map(|c| c.raw()));
        let timestamp = crate::time::get_ticks();
        let _ = audit::emit_capability_event(
            audit::AuditOutcome::Success,
            subject,
            cap_id.raw(),
            audit::AuditCapOperation::Revoke,
            None,
            0,
            timestamp,
        );
    }

    Ok(entry)
}

/// 系统调用分发器
///
/// 根据系统调用号和参数执行相应的系统调用
///
/// # Audit Trail
///
/// All syscalls emit an audit event after completion with:
/// - Syscall number and up to 6 arguments
/// - Success/Error outcome
/// - Process context (pid, uid, gid)
///
/// 在返回前检查 NEED_RESCHED 标志，如果需要则执行调度。
/// 这是 NEED_RESCHED 的主要消费点，确保时间片到期后能在返回用户态前触发调度。
pub fn syscall_dispatcher(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    // Capture timestamp at syscall entry
    let timestamp = crate::time::get_ticks();

    // Evaluate seccomp/pledge filters before dispatch
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    let verdict = crate::process::evaluate_seccomp(syscall_num, &args);

    match verdict.action {
        seccomp::SeccompAction::Kill => {
            // R25-4 + R39-2 FIX: Kill process with SIGSYS semantics and NEVER return
            //
            // SECURITY: After terminating the process, we must not return to userspace.
            // The process state is now invalid (PCB cleaned up, memory potentially freed).
            // Returning would cause UAF and complete seccomp bypass.
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                    // Terminate with SIGSYS exit code (128 + 31 = 159)
                    crate::process::terminate_process(pid, 128 + 31);
                    crate::process::cleanup_zombie(pid);
                }
            }
            // R39-2 FIX: Never return to userspace after fatal seccomp action.
            // Force scheduler to pick another task. If no tasks exist, CPU halts.
            crate::scheduler_hook::force_reschedule();
            // Safety: If reschedule returns (no other tasks), spin forever.
            // This path should not be reached in normal operation.
            loop {
                core::hint::spin_loop();
            }
        }
        seccomp::SeccompAction::Trap => {
            // R25-4 + R39-2 FIX: Trap treated as fatal until SIGSYS delivery exists
            //
            // SECURITY: Same rationale as Kill - process is terminated, never return.
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                    // Terminate with SIGSYS semantics until proper signal delivery exists
                    crate::process::terminate_process(pid, 128 + 31);
                    crate::process::cleanup_zombie(pid);
                }
            }
            // R39-2 FIX: Never return to userspace after fatal seccomp action.
            crate::scheduler_hook::force_reschedule();
            loop {
                core::hint::spin_loop();
            }
        }
        seccomp::SeccompAction::Errno(e) => {
            // Return the error code - audit the violation
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            return -(e as i64);
        }
        seccomp::SeccompAction::Log => {
            // Log the violation but continue
            if let Some(creds) = crate::current_credentials() {
                if let Some(pid) = crate::process::current_pid() {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            // Fall through to dispatch
        }
        seccomp::SeccompAction::Allow => {
            // Continue to dispatch
        }
    }

    // LSM hook: check syscall entry with security policy
    // Build context before dispatch; on denial, return EPERM
    let lsm_ctx = lsm::SyscallCtx::from_current(syscall_num, &args);
    if let Some(ref ctx) = lsm_ctx {
        if let Err(err) = lsm::hook_syscall_enter(ctx) {
            // LSM denied the syscall - call exit hook and return error
            let errno = lsm_error_to_syscall(err);
            let ret = errno.as_i64();
            let _ = lsm::hook_syscall_exit(ctx, ret as isize);
            return ret;
        }
    }

    let result = match syscall_num {
        // 进程管理
        56 => sys_clone(
            arg0,
            arg1 as *mut u8,
            arg2 as *mut i32,
            arg3 as *mut i32,
            arg4,
        ),
        60 => sys_exit(arg0 as i32),
        231 => sys_exit_group(arg0 as i32),
        57 => sys_fork(),
        59 => sys_exec(
            arg0 as *const u8,
            arg1 as usize,
            arg2 as *const *const u8,
            arg3 as *const *const u8,
        ),
        61 => sys_wait(arg0 as *mut i32),
        39 => sys_getpid(),
        186 => sys_gettid(),
        110 => sys_getppid(),
        102 => sys_getuid(),
        107 => sys_geteuid(),
        104 => sys_getgid(),
        108 => sys_getegid(),
        218 => sys_set_tid_address(arg0 as *mut i32),
        273 => sys_set_robust_list(arg0 as *const u8, arg1 as usize),
        62 => sys_kill(arg0 as ProcessId, arg1 as i32),
        // F.1: Namespace unshare
        272 => sys_unshare(arg0 as u64),
        // F.1: setns for mount namespace
        308 => sys_setns(arg0 as i32, arg1 as i32),

        // 文件I/O
        0 => sys_read(arg0 as i32, arg1 as *mut u8, arg2 as usize),
        1 => sys_write(arg0 as i32, arg1 as *const u8, arg2 as usize),
        2 => sys_open(arg0 as *const u8, arg1 as i32, arg2 as u32),
        257 => sys_openat(arg0 as i32, arg1 as *const u8, arg2 as i32, arg3 as u32),
        437 => sys_openat2(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *const OpenHow,
            arg3 as usize,
        ),
        3 => sys_close(arg0 as i32),
        4 => sys_stat(arg0 as *const u8, arg1 as *mut VfsStat),
        5 => sys_fstat(arg0 as i32, arg1 as *mut VfsStat),
        6 => sys_lstat(arg0 as *const u8, arg1 as *mut VfsStat),
        262 => sys_fstatat(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *mut VfsStat,
            arg3 as i32,
        ),
        8 => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32),
        16 => sys_ioctl(arg0 as i32, arg1, arg2),
        20 => sys_writev(arg0 as i32, arg1 as *const Iovec, arg2 as usize),
        22 => sys_pipe(arg0 as *mut i32),
        32 => sys_dup(arg0 as i32),
        33 => sys_dup2(arg0 as i32, arg1 as i32),
        292 => sys_dup3(arg0 as i32, arg1 as i32, arg2 as i32),
        77 => sys_ftruncate(arg0 as i32, arg1 as i64),
        217 => sys_getdents64(arg0 as i32, arg1 as *mut u8, arg2 as usize),

        // 文件系统操作
        21 => sys_access(arg0 as *const u8, arg1 as i32),
        79 => sys_getcwd(arg0 as *mut u8, arg1 as usize),
        80 => sys_chdir(arg0 as *const u8),
        83 => sys_mkdir(arg0 as *const u8, arg1 as u32),
        84 => sys_rmdir(arg0 as *const u8),
        87 => sys_unlink(arg0 as *const u8),
        90 => sys_chmod(arg0 as *const u8, arg1 as u32),
        91 => sys_fchmod(arg0 as i32, arg1 as u32),
        95 => sys_umask(arg0 as u32),

        // 内存管理
        12 => sys_brk(arg0 as usize),
        9 => sys_mmap(
            arg0 as usize,
            arg1 as usize,
            arg2 as i32,
            arg3 as i32,
            arg4 as i32,
            arg5 as i64,
        ),
        10 => sys_mprotect(arg0 as usize, arg1 as usize, arg2 as i32),
        11 => sys_munmap(arg0 as usize, arg1 as usize),

        // 架构相关
        158 => sys_arch_prctl(arg0 as i32, arg1 as u64),

        // Futex
        // R39-6 FIX: 传递第4个参数用于超时
        202 => sys_futex(arg0 as usize, arg1 as i32, arg2 as u32, arg3 as usize),

        // 安全/沙箱 (Seccomp/Prctl)
        157 => sys_prctl(arg0 as i32, arg1, arg2, arg3, arg4),
        317 => sys_seccomp(arg0 as u32, arg1 as u32, arg2),

        // 时间相关
        35 => sys_nanosleep(arg0 as *const TimeSpec, arg1 as *mut TimeSpec),
        96 => sys_gettimeofday(arg0 as *mut TimeVal, arg1 as usize),

        // 系统信息
        63 => sys_uname(arg0 as *mut UtsName),

        // 其他
        24 => sys_yield(),
        318 => sys_getrandom(arg0 as *mut u8, arg1 as usize, arg2 as u32),

        // CPU Affinity (E.5 SMP Scheduler - syscalls 203/204)
        203 => sys_sched_setaffinity(arg0 as i32, arg1 as usize, arg2 as *const u8),
        204 => sys_sched_getaffinity(arg0 as i32, arg1 as usize, arg2 as *mut u8),

        // 套接字 (Socket syscalls - Linux x86_64 ABI)
        41 => sys_socket(arg0 as i32, arg1 as i32, arg2 as i32),
        42 => sys_connect(arg0 as i32, arg1 as *const SockAddrIn, arg2 as u32),
        43 => sys_accept(arg0 as i32, arg1 as *mut SockAddrIn, arg2 as *mut u32),
        49 => sys_bind(arg0 as i32, arg1 as *const SockAddrIn, arg2 as u32),
        50 => sys_listen(arg0 as i32, arg1 as i32),
        44 => sys_sendto(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as usize,
            arg3 as i32,
            arg4 as *const SockAddrIn,
            arg5 as u32,
        ),
        45 => sys_recvfrom(
            arg0 as i32,
            arg1 as *mut u8,
            arg2 as usize,
            arg3 as i32,
            arg4 as *mut SockAddrIn,
            arg5 as *mut u32,
        ),
        48 => sys_shutdown(arg0 as i32, arg1 as i32),

        // F.2 Cgroup v2 syscalls (Zero-OS specific, 500-504)
        500 => sys_cgroup_create(arg0 as u64, arg1 as u32),
        501 => sys_cgroup_destroy(arg0 as u64),
        502 => sys_cgroup_attach(arg0 as u64),
        503 => sys_cgroup_set_limit(arg0 as u64, arg1 as u32, arg2),
        504 => sys_cgroup_get_stats(arg0 as u64, arg1 as *mut CgroupStatsBuf),

        _ => Err(SyscallError::ENOSYS),
    };

    // Emit audit event for syscall completion
    // Note: This is after the syscall so we capture the outcome
    let (outcome, errno) = match &result {
        Ok(_) => (AuditOutcome::Success, 0),
        Err(e) => (AuditOutcome::Error, e.as_i64() as i32),
    };

    // Emit audit event (ignore errors - audit should never block syscalls)
    // Include all 6 arguments for syscalls like mmap that use all of them
    let _ = audit::emit(
        AuditKind::Syscall,
        outcome,
        get_audit_subject(),
        AuditObject::None,
        &[syscall_num, arg0, arg1, arg2, arg3, arg4, arg5],
        errno,
        timestamp,
    );

    // LSM hook: notify security policy of syscall exit
    if let Some(ref ctx) = lsm_ctx {
        let ret = match &result {
            Ok(val) => *val as isize,
            Err(e) => e.as_i64() as isize,
        };
        let _ = lsm::hook_syscall_exit(ctx, ret);
    }

    // 在返回用户态前检查是否需要调度
    // 这是定时器中断设置的 NEED_RESCHED 标志的主要消费点
    crate::reschedule_if_needed();

    match result {
        Ok(val) => val as i64,
        Err(err) => err.as_i64(),
    }
}

// ============================================================================
// 进程管理系统调用
// ============================================================================

/// sys_exit - 终止当前进程
fn sys_exit(exit_code: i32) -> SyscallResult {
    if let Some(pid) = current_pid() {
        // LSM hook: notify policy of process exit (informational, doesn't block)
        if let Some(exit_ctx) = lsm_current_process_ctx() {
            let _ = lsm::hook_task_exit(&exit_ctx, exit_code);
        }

        terminate_process(pid, exit_code);
        println!("Process {} exited with code {}", pid, exit_code);

        // 退出的进程不应继续运行，立即让出 CPU
        // 这也会触发等待中的父进程被调度
        crate::force_reschedule();

        // 如果调度器选择了其他进程，这里不会返回
        // 如果没有其他进程，系统会回到这里（但进程已是 Zombie 状态）
        // 在这种情况下，我们必须阻止返回到用户空间
        // 进入无限循环等待中断（其他进程可能会在定时器中断中被创建）
        println!("[sys_exit] No other process to run, entering idle loop");
        loop {
            x86_64::instructions::hlt();
        }
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_exit_group - 终止进程组
///
/// 在当前单进程实现中，语义等同于 sys_exit。
/// 完整实现应终止同一进程组内的所有线程。
fn sys_exit_group(exit_code: i32) -> SyscallResult {
    // 当前为单进程模型，直接委托给 sys_exit
    sys_exit(exit_code)
}

/// sys_fork - 创建子进程
fn sys_fork() -> SyscallResult {
    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;

    // 调用真正的 fork 实现（包含 COW 支持）
    match crate::fork::sys_fork() {
        Ok(child_pid) => {
            // LSM hook: check if policy allows this fork
            enforce_lsm_task_fork(parent_pid, child_pid)?;

            // F.1 PID Namespace: Translate child's global PID to parent's namespace view
            //
            // Linux semantics: fork() returns the child's PID as seen from the parent's
            // namespace. This is the same PID used by wait(), kill(), etc.
            let parent_view_pid = {
                let parent = parent_arc.lock();
                let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
                if let Some(ns) = owning_ns {
                    crate::pid_namespace::pid_in_namespace(&ns, child_pid).unwrap_or(child_pid)
                } else {
                    child_pid
                }
            };

            Ok(parent_view_pid)
        }
        Err(e) => {
            // F.2: Map ForkError to appropriate syscall error
            use crate::fork::ForkError;
            match e {
                ForkError::CgroupPidsLimitExceeded => Err(SyscallError::EAGAIN),
                _ => Err(SyscallError::ENOMEM),
            }
        }
    }
}

// ============================================================================
// Clone Flags (Linux x86_64 ABI)
// ============================================================================

/// 共享虚拟内存空间
const CLONE_VM: u64 = 0x0000_0100;
/// 共享文件系统信息
const CLONE_FS: u64 = 0x0000_0200;
/// 共享文件描述符表
const CLONE_FILES: u64 = 0x0000_0400;
/// 共享信号处理器
const CLONE_SIGHAND: u64 = 0x0000_0800;
/// 加入同一线程组
const CLONE_THREAD: u64 = 0x0001_0000;
/// 设置 TLS
const CLONE_SETTLS: u64 = 0x0008_0000;
/// 在父进程写入子 TID
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// 子进程退出时清除 TID 并唤醒 futex
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// 在子进程写入 TID
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// F.1: Create a new PID namespace for the child
const CLONE_NEWPID: u64 = 0x2000_0000;
/// F.1: Create a new mount namespace for the child
const CLONE_NEWNS: u64 = 0x0002_0000;
/// F.1: Create a new IPC namespace for the child
const CLONE_NEWIPC: u64 = crate::CLONE_NEWIPC;
/// F.1: Create a new network namespace for the child
const CLONE_NEWNET: u64 = crate::CLONE_NEWNET;
/// F.1: Create a new user namespace for the child
/// NOTE: Unlike other namespaces, CLONE_NEWUSER does NOT require CAP_SYS_ADMIN or root.
/// This is intentional to enable unprivileged container creation.
const CLONE_NEWUSER: u64 = crate::CLONE_NEWUSER;

/// sys_clone - 创建线程/轻量级进程
///
/// 根据 flags 创建新的执行上下文，支持共享地址空间（线程）或独立地址空间（进程）。
///
/// # Arguments (Linux x86_64 ABI)
///
/// * `flags` - clone 标志位组合
/// * `stack` - 子进程/线程的用户栈指针（可为 NULL 使用父栈）
/// * `parent_tid` - CLONE_PARENT_SETTID 时写入子 TID 的地址
/// * `child_tid` - CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID 时使用的地址
/// * `tls` - CLONE_SETTLS 时设置的 TLS base 地址
///
/// # Returns
///
/// * 父进程：返回子进程/线程的 TID
/// * 子进程/线程：返回 0（通过设置 context.rax = 0）
fn sys_clone(
    flags: u64,
    stack: *mut u8,
    parent_tid: *mut i32,
    child_tid: *mut i32,
    tls: u64,
) -> SyscallResult {
    println!(
        "[sys_clone] entry: flags=0x{:x}, stack=0x{:x}, tls=0x{:x}",
        flags, stack as u64, tls
    );

    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;

    // 支持的 flags
    let supported_flags = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID
        | CLONE_NEWPID   // F.1: PID namespace support
        | CLONE_NEWNS    // F.1: Mount namespace support
        | CLONE_NEWIPC   // F.1: IPC namespace support
        | CLONE_NEWNET   // F.1: Network namespace support
        | CLONE_NEWUSER; // F.1: User namespace support

    // 检查不支持的 flags
    // 返回 EINVAL 而不是 ENOSYS，因为这是参数验证失败而非功能未实现
    if flags & !supported_flags != 0 {
        println!(
            "sys_clone: unsupported flags 0x{:x}",
            flags & !supported_flags
        );
        return Err(SyscallError::EINVAL);
    }

    // CLONE_THREAD 要求必须同时设置 CLONE_VM 和 CLONE_SIGHAND
    if flags & CLONE_THREAD != 0 {
        if flags & CLONE_VM == 0 || flags & CLONE_SIGHAND == 0 {
            return Err(SyscallError::EINVAL);
        }
        // R37-7 FIX: CLONE_THREAD requires a separate stack for the new thread.
        // Sharing the parent's stack leads to data races and corruption.
        if stack.is_null() {
            println!(
                "[sys_clone] CLONE_THREAD rejected: NULL stack would share parent's user stack"
            );
            return Err(SyscallError::EINVAL);
        }
    }

    // F.1: CLONE_NEWPID cannot be combined with CLONE_THREAD
    // Creating a thread in a new PID namespace makes no sense - threads share PID space
    if flags & CLONE_NEWPID != 0 && flags & CLONE_THREAD != 0 {
        println!("[sys_clone] CLONE_NEWPID cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1: CLONE_NEWNS cannot be combined with CLONE_THREAD
    // Mount namespace is per-process; threads must share the same mount namespace
    if flags & CLONE_NEWNS != 0 && flags & CLONE_THREAD != 0 {
        println!("[sys_clone] CLONE_NEWNS cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNS requires CAP_SYS_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNS != 0 {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(true);
        if !is_root && !has_cap_admin {
            println!("[sys_clone] CLONE_NEWNS denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWIPC cannot be combined with CLONE_THREAD
    // IPC namespace is per-process; threads must share the same IPC namespace
    if flags & CLONE_NEWIPC != 0 && flags & CLONE_THREAD != 0 {
        println!("[sys_clone] CLONE_NEWIPC cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWIPC requires CAP_SYS_ADMIN or root
    if flags & CLONE_NEWIPC != 0 {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(true);
        if !is_root && !has_cap_admin {
            println!("[sys_clone] CLONE_NEWIPC denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWNET cannot be combined with CLONE_THREAD
    // Network namespace is per-process; threads must share the same network namespace
    if flags & CLONE_NEWNET != 0 && flags & CLONE_THREAD != 0 {
        println!("[sys_clone] CLONE_NEWNET cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNET requires CAP_NET_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNET != 0 {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(true);
        if !is_root && !has_cap_admin {
            println!("[sys_clone] CLONE_NEWNET denied: requires CAP_NET_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWUSER cannot be combined with CLONE_THREAD
    // User namespace is per-process; threads must share the same user namespace
    if flags & CLONE_NEWUSER != 0 && flags & CLONE_THREAD != 0 {
        println!("[sys_clone] CLONE_NEWUSER cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWUSER does NOT require CAP_SYS_ADMIN or root.
    // This is intentional - user namespaces enable unprivileged container creation.
    // The only restriction is the system-wide namespace count limit.
    // Namespace depth is enforced by user_namespace::new_child().

    // 验证 parent_tid 指针
    if flags & CLONE_PARENT_SETTID != 0 {
        if parent_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(parent_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(parent_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证 child_tid 指针
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 {
        if child_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(child_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(child_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证栈指针（如果提供）
    if !stack.is_null() {
        validate_user_ptr(stack as *const u8, 1)?;
    }

    // 从 MSR 读取当前 FS_BASE（TLS 基址）
    // musl 可能通过 wrfsbase 指令直接设置 FS base，绕过 arch_prctl
    // 因此 PCB 中的 fs_base 可能是 0，需要从硬件同步
    let current_fs_base = {
        use x86_64::registers::model_specific::Msr;
        const MSR_FS_BASE: u32 = 0xC000_0100;
        unsafe { Msr::new(MSR_FS_BASE).read() }
    };

    // 从父进程收集必要信息
    let (
        parent_space,
        parent_tgid,
        parent_mmap,
        parent_next_mmap,
        parent_brk_start,
        parent_brk,
        parent_name,
        parent_priority,
        parent_context,
        parent_user_stack,
        parent_fs_base,
        parent_gs_base,
        parent_credentials_arc, // R39-3 FIX: 共享凭证 Arc
        parent_umask,
        parent_seccomp_state,
        parent_pledge_state,
        parent_seccomp_installing,
        parent_pid_ns_for_children, // F.1: PID namespace for children
        parent_mount_ns,             // F.1: Mount namespace
        parent_mount_ns_for_children, // F.1: Mount namespace for children
        parent_ipc_ns,               // F.1: IPC namespace
        parent_ipc_ns_for_children,  // F.1: IPC namespace for children
        parent_net_ns,               // F.1: Network namespace
        parent_net_ns_for_children,  // F.1: Network namespace for children
        parent_user_ns,              // F.1: User namespace
        parent_user_ns_for_children, // F.1: User namespace for children
    ) = {
        let mut parent = parent_arc.lock();
        // 始终从 MSR 同步 fs_base 到 PCB
        // 这确保即使进程通过 wrfsbase 指令修改了 TLS（绕过 arch_prctl），
        // 子进程也能继承正确的 TLS 基址
        if current_fs_base != 0 {
            parent.fs_base = current_fs_base;
        }
        (
            parent.memory_space,
            parent.tgid,
            parent.mmap_regions.clone(),
            parent.next_mmap_addr,
            parent.brk_start,
            parent.brk,
            parent.name.clone(),
            parent.priority,
            parent.context,
            parent.user_stack,
            parent.fs_base,
            parent.gs_base,
            parent.credentials.clone(), // R39-3 FIX: 获取凭证 Arc
            parent.umask,
            parent.seccomp_state.clone(),
            parent.pledge_state.clone(),
            parent.seccomp_installing,
            parent.pid_ns_for_children.clone(), // F.1: PID namespace
            parent.mount_ns.clone(),             // F.1: Mount namespace
            parent.mount_ns_for_children.clone(), // F.1: Mount namespace for children
            parent.ipc_ns.clone(),               // F.1: IPC namespace
            parent.ipc_ns_for_children.clone(),  // F.1: IPC namespace for children
            parent.net_ns.clone(),               // F.1: Network namespace
            parent.net_ns_for_children.clone(),  // F.1: Network namespace for children
            parent.user_ns.clone(),              // F.1: User namespace
            parent.user_ns_for_children.clone(), // F.1: User namespace for children
        )
    };

    // 决定使用的地址空间
    let (child_space, is_shared_space) = if flags & CLONE_VM != 0 {
        // CLONE_VM: 共享父进程的地址空间
        (parent_space, true)
    } else {
        // 不共享地址空间：使用 COW fork
        match crate::fork::sys_fork() {
            Ok(child_pid) => {
                // fork 成功，执行 LSM 检查
                // 这种情况很少见（clone 不带 CLONE_VM 通常就是 fork）
                enforce_lsm_task_fork(parent_pid, child_pid)?;

                // F.1: Translate to parent's namespace view before returning
                let parent_view_pid = {
                    let parent = parent_arc.lock();
                    let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
                    if let Some(ns) = owning_ns {
                        crate::pid_namespace::pid_in_namespace(&ns, child_pid).unwrap_or(child_pid)
                    } else {
                        child_pid
                    }
                };
                return Ok(parent_view_pid);
            }
            Err(_) => return Err(SyscallError::ENOMEM),
        }
    };

    // 创建子任务名称
    let child_name = if flags & CLONE_THREAD != 0 {
        alloc::format!("{}-thread", parent_name)
    } else {
        alloc::format!("{}-clone", parent_name)
    };

    // F.1: Handle CLONE_NEWNS - create new mount namespace
    let new_mount_ns = if flags & CLONE_NEWNS != 0 {
        match crate::mount_namespace::clone_namespace(parent_mount_ns.clone()) {
            Ok(ns) => {
                // R74-2 FIX: Eagerly materialize mount namespace tables.
                //
                // Without eager materialization, the child namespace's mount table
                // is created lazily on first VFS access. This creates a race where
                // mounts added to the parent AFTER clone() but BEFORE the child's
                // first VFS access would leak into the child, bypassing namespace
                // isolation.
                //
                // Fix: Materialize both parent and child mount tables NOW to
                // snapshot the parent's mount state at clone time.
                materialize_namespace(&parent_mount_ns);
                materialize_namespace(&ns);

                println!(
                    "[sys_clone] Created new mount namespace: id={}, level={} (eagerly materialized)",
                    ns.id().raw(),
                    ns.level()
                );

                // F.1 Audit: Emit namespace creation event
                let parent_id = ns.parent().map(|p| p.id().raw()).unwrap_or(0);
                let _ = audit::emit(
                    AuditKind::Process,
                    AuditOutcome::Success,
                    get_audit_subject(),
                    AuditObject::Namespace {
                        ns_id: ns.id().raw(),
                        ns_type: CLONE_NEWNS as u32,
                        parent_id,
                    },
                    &[56, flags, CLONE_NEWNS], // syscall 56 = clone, flags, CLONE_NEWNS
                    0,
                    crate::time::current_timestamp_ms(),
                );

                Some(ns)
            }
            Err(crate::mount_namespace::MountNsError::MaxDepthExceeded) => {
                println!("[sys_clone] Failed to create mount namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                println!("[sys_clone] Failed to create mount namespace: {:?}", e);
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWIPC - create new IPC namespace
    let new_ipc_ns = if flags & CLONE_NEWIPC != 0 {
        match crate::ipc_namespace::clone_ipc_namespace(parent_ipc_ns_for_children.clone()) {
            Ok(ns) => {
                println!(
                    "[sys_clone] Created new IPC namespace: id={}, level={}",
                    ns.id().raw(),
                    ns.level()
                );

                // F.1 Audit: Emit namespace creation event
                let parent_id = ns.parent().map(|p| p.id().raw()).unwrap_or(0);
                let _ = audit::emit(
                    AuditKind::Process,
                    AuditOutcome::Success,
                    get_audit_subject(),
                    AuditObject::Namespace {
                        ns_id: ns.id().raw(),
                        ns_type: CLONE_NEWIPC as u32,
                        parent_id,
                    },
                    &[56, flags, CLONE_NEWIPC], // syscall 56 = clone
                    0,
                    crate::time::current_timestamp_ms(),
                );

                Some(ns)
            }
            Err(crate::ipc_namespace::IpcNsError::MaxDepthExceeded) => {
                println!("[sys_clone] Failed to create IPC namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::ipc_namespace::IpcNsError::MaxNamespaces) => {
                println!("[sys_clone] Failed to create IPC namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                println!("[sys_clone] Failed to create IPC namespace: {:?}", e);
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWNET - create new network namespace
    let new_net_ns = if flags & CLONE_NEWNET != 0 {
        match crate::net_namespace::clone_net_namespace(parent_net_ns_for_children.clone()) {
            Ok(ns) => {
                println!(
                    "[sys_clone] Created new network namespace: id={}, level={}, has_loopback={}",
                    ns.id().raw(),
                    ns.level(),
                    ns.has_loopback()
                );

                // F.1 Audit: Emit namespace creation event
                let parent_id = ns.parent().map(|p| p.id().raw()).unwrap_or(0);
                let _ = audit::emit(
                    AuditKind::Process,
                    AuditOutcome::Success,
                    get_audit_subject(),
                    AuditObject::Namespace {
                        ns_id: ns.id().raw(),
                        ns_type: CLONE_NEWNET as u32,
                        parent_id,
                    },
                    &[56, flags, CLONE_NEWNET], // syscall 56 = clone
                    0,
                    crate::time::current_timestamp_ms(),
                );

                Some(ns)
            }
            Err(crate::net_namespace::NetNsError::MaxDepthExceeded) => {
                println!("[sys_clone] Failed to create network namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::net_namespace::NetNsError::MaxNamespaces) => {
                println!("[sys_clone] Failed to create network namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                println!("[sys_clone] Failed to create network namespace: {:?}", e);
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWUSER - create new user namespace
    let new_user_ns = if flags & CLONE_NEWUSER != 0 {
        match crate::user_namespace::clone_user_namespace(parent_user_ns_for_children.clone()) {
            Ok(ns) => {
                println!(
                    "[sys_clone] Created new user namespace: id={}, level={}",
                    ns.id().raw(),
                    ns.level()
                );

                // Emit audit event for user namespace creation
                let parent_id = ns.parent().map(|p| p.id().raw()).unwrap_or(0);
                let _ = audit::emit(
                    AuditKind::Process,
                    AuditOutcome::Success,
                    get_audit_subject(),
                    AuditObject::Namespace {
                        ns_id: ns.id().raw(),
                        ns_type: CLONE_NEWUSER as u32,
                        parent_id,
                    },
                    &[56, flags, CLONE_NEWUSER], // syscall 56 = clone
                    0,
                    crate::time::current_timestamp_ms(),
                );

                Some(ns)
            }
            Err(crate::user_namespace::UserNsError::MaxDepthExceeded) => {
                println!("[sys_clone] Failed to create user namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(crate::user_namespace::UserNsError::MaxNamespaces) => {
                println!("[sys_clone] Failed to create user namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                println!("[sys_clone] Failed to create user namespace: {:?}", e);
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWPID - create child in new PID namespace
    let child_pid = if flags & CLONE_NEWPID != 0 {
        // Create a new child PID namespace
        let new_ns = crate::pid_namespace::PidNamespace::new_child(parent_pid_ns_for_children)
            .map_err(|e| {
                println!("[sys_clone] Failed to create PID namespace: {:?}", e);
                match e {
                    crate::pid_namespace::PidNamespaceError::MaxDepthExceeded => SyscallError::EAGAIN,
                    // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
                    crate::pid_namespace::PidNamespaceError::MaxNamespaces => SyscallError::EAGAIN,
                    _ => SyscallError::ENOMEM,
                }
            })?;
        println!(
            "[sys_clone] Created new PID namespace: id={}, level={}",
            new_ns.id().raw(),
            new_ns.level()
        );
        // Create process in the new namespace
        create_process_in_namespace(child_name, parent_pid, parent_priority, new_ns)
            .map_err(|_| SyscallError::ENOMEM)?
    } else {
        // Regular process creation - inherits parent's pid_ns_for_children
        create_process(child_name, parent_pid, parent_priority)
            .map_err(|_| SyscallError::ENOMEM)?
    };

    let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;

    {
        let mut child = child_arc.lock();

        // R33-2 FIX: When parent is installing seccomp, block any shared-VM clone
        // (CLONE_VM with or without CLONE_THREAD) to prevent sandbox escape.
        // An attacker could race seccomp installation by spawning a CLONE_VM child
        // that shares the address space but escapes the pending filter.
        if is_shared_space && parent_seccomp_installing {
            child.state = ProcessState::Terminated;
            drop(child);
            crate::process::terminate_process(child_pid, -1);
            println!(
                "sys_clone: rejecting CLONE_VM during seccomp installation (pid={})",
                parent_pid
            );
            return Err(SyscallError::EBUSY);
        }

        // 设置线程标识
        child.tid = child_pid; // tid == pid (Linux 语义)
        if flags & CLONE_THREAD != 0 {
            // R26-3 FIX: Reject thread creation if parent is installing seccomp filter
            // This prevents TOCTOU race where new thread escapes sandbox
            if parent_seccomp_installing {
                // Clean up: terminate the child process we just created
                child.state = ProcessState::Terminated;
                drop(child);
                crate::process::terminate_process(child_pid, -1);
                return Err(SyscallError::EBUSY);
            }
            child.tgid = parent_tgid; // 加入父进程的线程组
            child.is_thread = true;
        } else {
            child.tgid = child_pid; // 新线程组
            child.is_thread = false;
        }

        // 设置地址空间
        child.memory_space = child_space;
        if is_shared_space {
            // 共享地址空间时复制相关元数据
            child.mmap_regions = parent_mmap;
            child.next_mmap_addr = parent_next_mmap;
            child.brk_start = parent_brk_start;
            child.brk = parent_brk;
        }

        // 从当前 syscall 帧构建子进程上下文
        // 使用 syscall 帧而非 parent.context，因为后者是上次调度时的状态
        if let Some(frame) = get_current_syscall_frame() {
            // Debug: 打印 SyscallFrame 原始值
            println!(
                "[sys_clone] SyscallFrame: rcx(rip)=0x{:x}, rsp=0x{:x}, r9=0x{:x}",
                frame.rcx, frame.rsp, frame.r9
            );

            // 从 syscall 帧复制寄存器状态
            child.context.rax = 0; // 子进程 clone 返回值 = 0
            child.context.rbx = frame.rbx;
            child.context.rcx = frame.rcx; // 用户 RIP (SYSCALL 保存)
            child.context.rdx = frame.rdx;
            child.context.rsi = frame.rsi;
            child.context.rdi = frame.rdi;
            child.context.rbp = frame.rbp;
            child.context.r8 = frame.r8;
            child.context.r9 = frame.r9;
            child.context.r10 = frame.r10;
            child.context.r11 = frame.r11; // 用户 RFLAGS
            child.context.r12 = frame.r12;
            child.context.r13 = frame.r13;
            child.context.r14 = frame.r14;
            child.context.r15 = frame.r15;
            // RIP = RCX (syscall 保存的用户返回地址)
            child.context.rip = frame.rcx;
            // RFLAGS = R11 (syscall 保存的用户 RFLAGS)
            child.context.rflags = frame.r11;
            // 用户态段选择子
            child.context.cs = 0x23; // USER_CODE_SELECTOR
            child.context.ss = 0x1b; // USER_DATA_SELECTOR

            // 设置栈指针
            if !stack.is_null() {
                let sp = stack as u64;
                child.context.rsp = sp;
                child.context.rbp = sp; // 子线程清空 frame pointer
                child.user_stack = Some(VirtAddr::new(sp));
            } else {
                child.context.rsp = frame.rsp;
                child.user_stack = parent_user_stack;
            }
        } else {
            // 回退：使用 parent.context（不应该发生）
            println!("sys_clone: WARNING - syscall frame not available, using stale context");
            child.context = parent_context;
            child.context.rax = 0;
            if !stack.is_null() {
                let sp = stack as u64;
                child.context.rsp = sp;
                child.context.rbp = sp;
                child.user_stack = Some(VirtAddr::new(sp));
            } else {
                child.user_stack = parent_user_stack;
            }
        }

        // Debug: 打印子进程上下文关键寄存器
        println!(
            "[sys_clone] Child {} ctx: rax=0x{:x}, rip=0x{:x}, rsp=0x{:x}, r9=0x{:x}, rcx=0x{:x}",
            child_pid,
            child.context.rax,
            child.context.rip,
            child.context.rsp,
            child.context.r9,
            child.context.rcx
        );

        // 设置 TLS
        // R24-2 fix: 验证 TLS 基址是 canonical 且在用户空间范围内
        // 避免非法地址导致后续 WRMSR 时 #GP 内核崩溃
        if flags & CLONE_SETTLS != 0 {
            if !is_canonical(tls) || tls >= USER_SPACE_TOP as u64 {
                // 非法 TLS 地址：先释放child锁再清理，避免死锁
                // 标记进程为终止状态并清零共享地址空间引用
                child.state = ProcessState::Terminated;
                child.memory_space = 0; // 不释放共享地址空间
                drop(child);
                // 通过cleanup_zombie安全地从进程表移除
                // 但由于子进程还未设置为Zombie状态，我们直接使用terminate
                // 注意：此时子进程未被调度，terminate_process安全
                crate::process::terminate_process(child_pid, -1);
                return Err(SyscallError::EINVAL);
            }
            child.fs_base = tls;
        } else {
            child.fs_base = parent_fs_base;
        }
        child.gs_base = parent_gs_base;

        // Debug: 打印 TLS 信息
        println!(
            "[sys_clone] TLS: msr_fs=0x{:x}, parent_fs=0x{:x}, child_fs=0x{:x}",
            current_fs_base, parent_fs_base, child.fs_base
        );

        // 设置 tid 指针
        if flags & CLONE_CHILD_SETTID != 0 {
            child.set_child_tid = child_tid as u64;
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            child.clear_child_tid = child_tid as u64;
        }

        // R39-3 FIX: 复制/共享凭证
        //
        // CLONE_THREAD: 共享父进程的凭证 Arc（符合 POSIX 线程语义）
        // 非 CLONE_THREAD: 克隆凭证到新的 Arc（进程隔离）
        //
        // 这确保同一进程的线程共享 setuid/setgid 变更，
        // 而不同进程保持凭证独立。
        if flags & CLONE_THREAD != 0 {
            child.credentials = parent_credentials_arc.clone();
        } else {
            let creds_copy = parent_credentials_arc.read().clone();
            child.credentials = Arc::new(spin::RwLock::new(creds_copy));
        }
        child.umask = parent_umask;

        // 继承 Seccomp/Pledge 沙箱状态
        // - 过滤器栈通过 Arc 共享，父子进程共享同一过滤器对象
        // - no_new_privs 是粘滞标志，一旦设置无法清除
        // - pledge 状态包括当前 promises 和 exec_promises（exec 后生效）
        child.seccomp_state = parent_seccomp_state;
        child.pledge_state = parent_pledge_state;

        // 复制文件描述符表（CLONE_FILES 时理论上应共享，但当前架构暂用克隆）
        if flags & CLONE_FILES != 0 {
            let parent = parent_arc.lock();
            for (&fd, desc) in parent.fd_table.iter() {
                child.fd_table.insert(fd, desc.clone_box());
            }
        }

        // 克隆能力表（CLONE_THREAD 时共享，否则克隆并过滤 CLOFORK）
        //
        // 对于线程（CLONE_THREAD），共享父进程的能力表（通过 Arc）
        // 对于进程（无 CLONE_THREAD），使用 clone_for_fork() 过滤 CLOFORK 条目
        //
        // 注意：与 fd_table 不同，cap_table 使用 Arc 包装，天然支持共享
        if flags & CLONE_THREAD != 0 {
            // 线程：共享父进程的能力表
            let parent = parent_arc.lock();
            child.cap_table = parent.cap_table.clone();
        } else {
            // R25-8 FIX: 非线程情况（包括CLONE_FILES和默认进程语义）
            // 都必须继承能力表并过滤 CLOFORK 条目
            let parent = parent_arc.lock();
            child.cap_table = Arc::new(parent.cap_table.clone_for_fork());
        }

        // F.1 Mount Namespace: Assign mount namespace to child
        //
        // CLONE_NEWNS: Use the new mount namespace created earlier
        // Without CLONE_NEWNS: Inherit parent's mount_ns_for_children
        let child_mount_ns = new_mount_ns
            .clone()
            .unwrap_or_else(|| parent_mount_ns_for_children.clone());
        child.mount_ns = child_mount_ns.clone();
        child.mount_ns_for_children = child_mount_ns;

        // F.1 IPC Namespace: Assign IPC namespace to child
        //
        // CLONE_NEWIPC: Use the new IPC namespace created earlier
        // Without CLONE_NEWIPC: Inherit parent's ipc_ns_for_children
        let child_ipc_ns = new_ipc_ns
            .clone()
            .unwrap_or_else(|| parent_ipc_ns_for_children.clone());
        child.ipc_ns = child_ipc_ns.clone();
        child.ipc_ns_for_children = child_ipc_ns;

        // F.1 Network Namespace: Assign network namespace to child
        //
        // CLONE_NEWNET: Use the new network namespace created earlier
        // Without CLONE_NEWNET: Inherit parent's net_ns_for_children
        let child_net_ns = new_net_ns
            .clone()
            .unwrap_or_else(|| parent_net_ns_for_children.clone());
        child.net_ns = child_net_ns.clone();
        child.net_ns_for_children = child_net_ns;

        // F.1 User Namespace: Assign user namespace to child
        //
        // CLONE_NEWUSER: Use the new user namespace created earlier
        // Without CLONE_NEWUSER: Inherit parent's user_ns_for_children
        //
        // Note: User namespace does not require root/CAP_SYS_ADMIN, enabling
        // unprivileged container creation. UID/GID mappings can be set later
        // via /proc/[pid]/uid_map and /proc/[pid]/gid_map.
        let child_user_ns = new_user_ns
            .clone()
            .unwrap_or_else(|| parent_user_ns_for_children.clone());
        child.user_ns = child_user_ns.clone();
        child.user_ns_for_children = child_user_ns;

        // 设置进程状态为就绪
        child.state = ProcessState::Ready;
    }

    // F.1 PID Namespace: Translate child's global PID to parent's namespace view
    //
    // Linux semantics: clone() returns the child's PID as seen from the parent's
    // namespace. This is the same PID the parent will use for kill(), waitpid(), etc.
    //
    // For processes in the root namespace, this is the same as the global PID.
    // For processes in child namespaces, the parent sees a different PID.
    let parent_view_pid = {
        let parent = parent_arc.lock();
        let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
        if let Some(ns) = owning_ns {
            crate::pid_namespace::pid_in_namespace(&ns, child_pid).unwrap_or(child_pid)
        } else {
            // No namespace chain (shouldn't happen), fall back to global PID
            child_pid
        }
    };

    // F.1 PID Namespace: Get child's own namespace-local PID for CLONE_CHILD_SETTID
    //
    // CLONE_CHILD_SETTID writes the TID the child sees for itself.
    // This is the child's PID in its owning namespace (the deepest namespace).
    // With CLONE_NEWPID, the child's owning namespace is a new child namespace,
    // where it is PID 1 (the init process of that namespace).
    let child_view_pid = {
        let child = child_arc.lock();
        crate::pid_namespace::pid_in_owning_namespace(&child.pid_ns_chain).unwrap_or(child_pid)
    };

    // 写入 parent_tid (F.1: use parent's view of child's PID)
    if flags & CLONE_PARENT_SETTID != 0 {
        let tid_bytes = (parent_view_pid as i32).to_ne_bytes();
        copy_to_user(parent_tid as *mut u8, &tid_bytes)?;
    }

    // 写入 child_tid（在共享地址空间中，子进程会看到此值）
    // F.1: use child's own namespace-local PID (not parent's view)
    //
    // With CLONE_NEWPID, parent sees child as e.g. PID 5, but child sees itself as PID 1.
    // The child uses this value for futex operations, robust_list, etc., so it must match
    // what gettid() returns to the child.
    if flags & CLONE_CHILD_SETTID != 0 {
        let tid_bytes = (child_view_pid as i32).to_ne_bytes();
        copy_to_user(child_tid as *mut u8, &tid_bytes)?;
    }

    // LSM hook: check if policy allows this fork/clone
    // Must be BEFORE scheduler notification to prevent denied child from running
    enforce_lsm_task_fork(parent_pid, child_pid)?;

    // 将子进程添加到调度器（通过回调，避免循环依赖）
    if let Some(child_arc) = get_process(child_pid) {
        crate::process::notify_scheduler_add_process(child_arc);
    }

    println!(
        "sys_clone: parent={}, child={} (parent_view={}, child_view={}), flags=0x{:x}, is_thread={}",
        parent_pid,
        child_pid,
        parent_view_pid,
        child_view_pid,
        flags,
        flags & CLONE_THREAD != 0
    );

    // F.1: Return namespace-local PID to parent (Linux semantics)
    Ok(parent_view_pid)
}

/// sys_exec - 执行新程序
///
/// 将当前进程的地址空间替换为新的 ELF 可执行映像
///
/// # Arguments
///
/// * `image` - 指向用户态 ELF 映像的指针
/// * `image_len` - ELF 映像长度（字节数）
/// * `argv` - 命令行参数数组（NULL 结尾）
/// * `envp` - 环境变量数组（NULL 结尾）
///
/// # Safety
///
/// 用户指针在切换 CR3 前必须先复制到内核堆，否则地址失效
fn sys_exec(
    image: *const u8,
    image_len: usize,
    argv: *const *const u8,
    envp: *const *const u8,
) -> SyscallResult {
    use crate::elf_loader::{load_elf, USER_STACK_SIZE};
    use crate::fork::create_fresh_address_space;
    use crate::process::{
        activate_memory_space, current_pid, free_address_space, get_process, thread_group_size,
        ProcessState,
    };

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R33-1 FIX: Refuse exec while other threads share this address space.
    // Calling exec in a multithreaded process would free the page tables while
    // sibling threads are still executing, causing UAF/memory corruption.
    // Linux behavior: exec in multithreaded process kills other threads first,
    // but that requires complex thread group handling. For now, reject with EBUSY.
    let tgid = {
        let proc = process.lock();
        proc.tgid
    };
    if thread_group_size(tgid) > 1 {
        println!(
            "sys_exec: refusing exec in multithreaded process (tgid={}, threads={})",
            tgid,
            thread_group_size(tgid)
        );
        return Err(SyscallError::EBUSY);
    }

    // 验证参数：非空、合理大小
    if image.is_null() || image_len == 0 {
        return Err(SyscallError::EINVAL);
    }
    if image_len > MAX_EXEC_IMAGE_SIZE {
        println!(
            "sys_exec: ELF size {} exceeds limit {}",
            image_len, MAX_EXEC_IMAGE_SIZE
        );
        return Err(SyscallError::E2BIG);
    }

    // 【关键】在切换 CR3 前将用户数据复制到内核堆
    // 切换地址空间后原用户指针将失效
    let mut elf_data = vec![0u8; image_len];
    copy_from_user(&mut elf_data, image)?;

    // 复制 argv 和 envp 到内核
    let argv_vec = copy_user_str_array(argv)?;
    let envp_vec = copy_user_str_array(envp)?;

    // R41-4 FIX: LSM hook uses SHA-256 of ELF content instead of argv[0]
    //
    // SECURITY: Previously used argv[0] (user-controlled) for policy checks,
    // allowing attackers to bypass MAC by setting argv[0] to an allowed program.
    // Now we hash the actual binary content to ensure policy is checked against
    // what will actually be executed.
    let bin_hash = audit::hash_binary_prefix(&elf_data, EXEC_HASH_WINDOW);

    if let Some(exec_ctx) = lsm_current_process_ctx() {
        if let Err(err) = lsm::hook_task_exec(&exec_ctx, bin_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 创建新的地址空间
    let (_new_pml4_frame, new_memory_space) =
        create_fresh_address_space().map_err(|_| SyscallError::ENOMEM)?;

    // 保存旧地址空间以便失败时恢复或成功时释放
    let old_memory_space = {
        let proc = process.lock();
        proc.memory_space
    };

    // S-7 fix: RAII guard to rollback address space on error
    //
    // After switching CR3, any error must restore the old address space
    // and free the new one. This guard ensures automatic rollback.
    struct ExecSpaceGuard {
        old_space: usize,
        new_space: usize,
        committed: bool,
    }

    impl ExecSpaceGuard {
        fn new(old_space: usize, new_space: usize) -> Self {
            Self {
                old_space,
                new_space,
                committed: false,
            }
        }

        /// Mark the exec as successful, preventing rollback on drop
        fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for ExecSpaceGuard {
        fn drop(&mut self) {
            if !self.committed {
                // Rollback: restore old address space and free new one
                crate::process::activate_memory_space(self.old_space);
                crate::process::free_address_space(self.new_space);
            }
        }
    }

    // Create the guard before switching CR3
    let mut space_guard = ExecSpaceGuard::new(old_memory_space, new_memory_space);

    // 切换到新地址空间
    activate_memory_space(new_memory_space);

    // 加载 ELF 映像
    // S-7 fix: Let the guard handle rollback on error
    let load_result = load_elf(&elf_data).map_err(|e| {
        println!("sys_exec: ELF load failed: {:?}", e);
        SyscallError::ENOEXEC
    })?;

    // =========================================================================
    // 构建符合 System V AMD64 ABI 的用户栈布局：
    //
    // 高地址 (栈顶方向)
    //   +------------------+
    //   | 字符串数据区      |  <- argv[0] 字符串, argv[1] 字符串, ..., envp[0], ...
    //   +------------------+
    //   | 16字节对齐填充    |
    //   +------------------+
    //   | NULL (envp终止)   |
    //   | envp[n-1] 指针    |
    //   | ...              |
    //   | envp[0] 指针      |
    //   | NULL (argv终止)   |
    //   | argv[n-1] 指针    |
    //   | ...              |
    //   | argv[0] 指针      |
    //   | argc             |  <- RSP 指向这里
    //   +------------------+
    // 低地址 (栈底方向)
    // =========================================================================

    let argc = argv_vec.len();
    let envc = envp_vec.len();
    let word = mem::size_of::<usize>();

    // 计算字符串总大小
    let string_bytes: usize = argv_vec
        .iter()
        .chain(envp_vec.iter())
        .map(|s| s.len() + 1) // +1 for '\0'
        .sum();

    // 指针区大小: argc + argv_ptrs + NULL + envp_ptrs + NULL
    let pointer_count = 1 + argc + 1 + envc + 1;
    let pointer_bytes = pointer_count * word;

    // 检查栈空间是否足够
    let stack_top = load_result.user_stack_top as usize;
    let stack_base = stack_top
        .checked_sub(USER_STACK_SIZE)
        .ok_or(SyscallError::EFAULT)?;

    // Allow supervisor access to user pages for stack construction when SMAP is enabled
    let _user_access = UserAccessGuard::new();

    let total_needed = string_bytes + pointer_bytes + 16; // +16 for alignment
    if total_needed > USER_STACK_SIZE {
        return Err(SyscallError::E2BIG);
    }

    let mut sp = stack_top;
    let mut argv_ptrs: Vec<usize> = Vec::with_capacity(argc);
    let mut envp_ptrs: Vec<usize> = Vec::with_capacity(envc);

    // 1. 复制 argv 字符串（从高地址向低地址生长）
    for s in argv_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sp as *mut u8, len);
            *((sp + len) as *mut u8) = 0; // NUL 终止
        }
        argv_ptrs.push(sp);
    }
    argv_ptrs.reverse(); // 恢复正序

    // 2. 复制 envp 字符串
    for s in envp_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sp as *mut u8, len);
            *((sp + len) as *mut u8) = 0;
        }
        envp_ptrs.push(sp);
    }
    envp_ptrs.reverse();

    // 3. 16 字节对齐
    sp &= !0xF;

    // 4. 检查指针区空间是否足够
    if sp < stack_base + pointer_bytes {
        return Err(SyscallError::E2BIG);
    }

    // 5. 确保最终 RSP 满足 SysV AMD64 ABI 要求
    // 进程入口点要求 (RSP % 16) == 8，这样第一个 PUSH 后 RSP 才是 16 字节对齐
    // 注意：直接跳转到 _start 不经过 CALL，所以 RSP 需要预留 8 字节偏移
    let final_sp = sp - pointer_bytes;
    if (final_sp & 0xF) == 0 {
        // 当前是 16 对齐，需要调整为 16+8
        sp -= word; // 添加填充使最终 RSP % 16 == 8
        unsafe {
            *(sp as *mut usize) = 0;
        }
    }

    // 6. 压入指针区（从高地址向低地址）
    unsafe {
        // envp NULL 终止
        sp -= word;
        *(sp as *mut usize) = 0;

        // envp 指针数组（逆序压入）
        for ptr in envp_ptrs.iter().rev() {
            sp -= word;
            *(sp as *mut usize) = *ptr;
        }

        // argv NULL 终止
        sp -= word;
        *(sp as *mut usize) = 0;

        // argv 指针数组（逆序压入）
        for ptr in argv_ptrs.iter().rev() {
            sp -= word;
            *(sp as *mut usize) = *ptr;
        }

        // argc
        sp -= word;
        *(sp as *mut usize) = argc;
    }

    let final_rsp = sp as u64;
    let argv_base = (sp + word) as u64; // argv[0] 的地址

    // 更新进程 PCB
    let old_space = {
        let mut proc = process.lock();

        let old_space = proc.memory_space;
        proc.memory_space = new_memory_space;
        proc.user_stack = Some(VirtAddr::new(load_result.user_stack_top));

        // 设置上下文
        proc.context.rip = load_result.entry;
        proc.context.rsp = final_rsp;
        proc.context.rbp = final_rsp;

        // 用户态段选择子（Ring 3）
        proc.context.cs = 0x1B;
        proc.context.ss = 0x23;
        proc.context.rflags = 0x202;

        // System V AMD64 调用约定：RDI = argc, RSI = argv
        proc.context.rdi = argc as u64;
        proc.context.rsi = argv_base;

        // 清零其他寄存器
        proc.context.rax = 0;
        proc.context.rbx = 0;
        proc.context.rcx = 0;
        proc.context.rdx = 0;
        proc.context.r8 = 0;
        proc.context.r9 = 0;
        proc.context.r10 = 0;
        proc.context.r11 = 0;
        proc.context.r12 = 0;
        proc.context.r13 = 0;
        proc.context.r14 = 0;
        proc.context.r15 = 0;

        proc.mmap_regions.clear();
        proc.next_mmap_addr = 0x4000_0000;

        // 初始化堆管理（brk）
        // brk_start 和 brk 初始化为 ELF 最高段末尾（页对齐）
        // 这确保 brk(0) 返回正确的初始值，malloc 才能正常工作
        proc.brk_start = load_result.brk_start;
        proc.brk = load_result.brk_start;

        // 重置 TLS 状态（新程序需要重新设置）
        proc.fs_base = 0;
        proc.gs_base = 0;

        // OpenBSD Pledge 语义：exec 后应用 exec_promises
        // 如果进程设置了 exec_promises，则在 exec 成功后将其替换为当前 promises
        // 这允许进程在 exec 前声明一组更宽松的权限（用于加载程序），
        // exec 后自动收紧到更严格的权限集
        if let Some(ref mut pledge) = proc.pledge_state {
            if let Some(exec_promises) = pledge.exec_promises.take() {
                pledge.promises = exec_promises;
            }
        }

        // Seccomp 过滤器在 exec 后保持不变（Linux 语义）
        // no_new_privs 仍然有效，防止特权提升

        // 应用 CLOEXEC 能力：撤销带有 CLOEXEC 标志的能力条目
        //
        // 新加载的程序不应继承标记为 CLOEXEC 的能力，这与文件描述符
        // 的 CLOEXEC 语义一致。apply_cloexec() 会将这些条目撤销并
        // 返回到空闲列表，同时递增生成计数器防止旧 CapId 被复用。
        proc.cap_table.apply_cloexec();

        // R39-4 FIX: 应用 FD_CLOEXEC：关闭带有 close-on-exec 标志的文件描述符
        //
        // POSIX 语义：exec 成功后，所有标记为 O_CLOEXEC/FD_CLOEXEC 的文件描述符
        // 必须被关闭。这防止敏感句柄（如特权设备、安全令牌）泄漏到新程序。
        //
        // 典型攻击场景：
        // 1. 父进程以 root 权限打开 /dev/vda 但忘记设置 CLOEXEC
        // 2. exec 不可信程序后，该程序意外获得块设备访问权限
        //
        // 注意：此操作必须在 commit 之前执行，确保 exec 回滚时 fd 不变
        proc.apply_fd_cloexec();

        proc.state = ProcessState::Ready;

        old_space
    };

    // S-7 fix: Commit the exec - prevent guard from rolling back
    // This must be called after all error-prone operations are complete.
    space_guard.commit();

    // 释放旧地址空间
    if old_space != 0 {
        free_address_space(old_space);
    }

    println!(
        "sys_exec: entry=0x{:x}, rsp=0x{:x}, argc={}",
        load_result.entry, final_rsp, argc
    );

    Ok(0)
}

/// sys_wait - 等待子进程
///
/// 阻塞当前进程直到一个子进程终止，然后收割该僵尸进程并返回其 PID 和退出码。
///
/// # Arguments
///
/// * `status` - 指向用户态 i32 的指针，用于存储子进程的退出码。可为 NULL。
///
/// # Returns
///
/// * 成功：返回已终止子进程的 PID
/// * ECHILD：当前进程没有子进程
/// * EFAULT：status 指针无效
fn sys_wait(status: *mut i32) -> SyscallResult {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent = get_process(pid).ok_or(SyscallError::ESRCH)?;

    loop {
        // 【关键修复】先标记为等待状态，再扫描子进程，避免 lost wake-up
        // 如果子进程在我们标记之后、扫描之前退出，terminate_process 会看到我们的等待状态
        // 如果子进程在我们扫描时/之后退出，我们会在扫描中发现它的 Zombie 状态
        let child_list = {
            let mut proc = parent.lock();
            if proc.children.is_empty() {
                return Err(SyscallError::ECHILD);
            }
            // 先标记为等待状态
            proc.state = ProcessState::Blocked;
            proc.waiting_child = Some(0); // 0 表示等待任意子进程
            proc.children.clone()
        };

        // 查找已终止的僵尸子进程
        // F.1 PID Namespace: Also capture the child's namespace chain to derive ns-local PID
        let mut zombie_child: Option<(ProcessId, i32, Vec<crate::pid_namespace::PidNamespaceMembership>)> = None;
        let mut stale_pids: vec::Vec<ProcessId> = vec::Vec::new();

        for child_pid in child_list.iter() {
            match get_process(*child_pid) {
                Some(child_proc) => {
                    let child = child_proc.lock();
                    if child.state == ProcessState::Zombie {
                        zombie_child = Some((
                            *child_pid,
                            child.exit_code.unwrap_or(0),
                            child.pid_ns_chain.clone(), // Capture ns chain before cleanup
                        ));
                        break;
                    }
                }
                None => {
                    // 子进程已被清理但仍在父进程列表中，标记为过期
                    stale_pids.push(*child_pid);
                }
            }
        }

        // 如果找到僵尸子进程，收割并返回
        if let Some((child_pid, exit_code, child_ns_chain)) = zombie_child {
            // 将退出码写入用户空间（如果提供了 status 指针）
            if !status.is_null() {
                let bytes = exit_code.to_ne_bytes();
                copy_to_user(status as *mut u8, &bytes)?;
            }

            // F.1 PID Namespace: Translate child's global PID to parent's namespace view
            //
            // Linux semantics: wait() returns the PID as seen from the caller's namespace.
            //
            // CRITICAL: We CANNOT use pid_in_namespace() here because terminate_process()
            // already called detach_pid_chain() which removed the child from namespace maps.
            // Instead, we derive the ns-local PID from the child's stored pid_ns_chain.
            //
            // The child's pid_ns_chain contains entries for all namespaces from root to
            // its owning namespace. We find the entry that matches the parent's owning
            // namespace to get the PID as the parent sees it.
            let parent_view_pid = {
                let proc = parent.lock();
                let parent_owning_ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain);
                if let Some(ref parent_ns) = parent_owning_ns {
                    // Find the child's PID in the parent's owning namespace
                    child_ns_chain
                        .iter()
                        .find(|m| Arc::ptr_eq(&m.ns, parent_ns))
                        .map(|m| m.pid)
                        .unwrap_or(child_pid) // Fallback if not visible (shouldn't happen)
                } else {
                    child_pid // Root namespace: use global PID
                }
            };

            // 从父进程的子进程列表中移除，并恢复 Ready 状态
            {
                let mut proc = parent.lock();
                proc.children.retain(|&c| c != child_pid);
                proc.waiting_child = None;
                proc.state = ProcessState::Ready;
            }

            // 清理僵尸进程资源
            cleanup_zombie(child_pid);

            println!(
                "sys_wait: reaped child {} (ns_pid={}) with exit code {}",
                child_pid, parent_view_pid, exit_code
            );
            // F.1: Return namespace-local PID to parent (Linux semantics)
            return Ok(parent_view_pid);
        }

        // 清理过期的子进程 PID
        if !stale_pids.is_empty() {
            let mut proc = parent.lock();
            proc.children.retain(|pid| !stale_pids.contains(pid));
            // 如果清理后没有子进程了，恢复状态并返回 ECHILD
            if proc.children.is_empty() {
                proc.state = ProcessState::Ready;
                proc.waiting_child = None;
                return Err(SyscallError::ECHILD);
            }
        }

        // 没有找到僵尸子进程，让出 CPU 等待被唤醒
        // 状态已在循环开始时设为 Blocked，子进程退出时会将其设为 Ready
        crate::force_reschedule();

        // 被唤醒后继续循环，检查是否有僵尸子进程
        // 如果是被子进程退出唤醒的，循环会找到 zombie 并返回
        // 如果是误唤醒，循环会重新设置 Blocked 状态并继续等待
    }
}

/// sys_getpid - 获取当前进程ID
///
/// F.1 PID Namespace: Returns the PID as seen from the process's owning namespace,
/// not the global (kernel internal) PID. For processes in the root namespace,
/// these are the same.
fn sys_getpid() -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    let ns_pid = {
        let proc = proc_arc.lock();
        // F.1: Return the PID from the owning (leaf) namespace
        // The last entry in pid_ns_chain is the owning namespace
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain).unwrap_or(global_pid)
    };

    Ok(ns_pid)
}

/// sys_getppid - 获取父进程ID
///
/// F.1 PID Namespace: Returns the parent's PID as seen from the current process's
/// owning namespace. If the parent is not visible in the namespace (e.g., parent
/// is in an ancestor namespace), returns 0 (orphan/adopted by namespace init).
fn sys_getppid() -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    let proc = proc_arc.lock();
    let parent_global_pid = proc.ppid;

    // F.1: Get owning namespace for translation
    let owning_ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain);
    drop(proc); // Release lock before looking up parent

    // If parent_pid is 0, the process has no parent (init)
    if parent_global_pid == 0 {
        return Ok(0);
    }

    // Try to translate parent's global PID to namespace-local PID
    if let Some(ns) = owning_ns {
        // Look up parent's PID in our namespace
        if let Some(ns_ppid) = ns.lookup_ns_pid(parent_global_pid) {
            return Ok(ns_ppid);
        }
        // Parent not visible in our namespace - return 0 (orphan semantics)
        // This happens when parent is in an ancestor namespace
        Ok(0)
    } else {
        // No namespace chain - return global PID (root namespace)
        Ok(parent_global_pid)
    }
}

/// sys_gettid - 获取当前线程ID
///
/// 返回当前线程的 TID。对于主线程，TID == PID == TGID。
/// 对于子线程，TID 是线程的唯一标识，TGID 是所属进程组。
///
/// F.1 PID Namespace: Returns the TID as seen from the thread's owning namespace.
fn sys_gettid() -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(global_pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();

    // F.1: Return the TID from the owning namespace (TID == namespace-local PID)
    let ns_tid =
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain).unwrap_or(proc.tid);
    Ok(ns_tid)
}

/// sys_set_tid_address - 设置 clear_child_tid 指针
///
/// musl libc 在启动时调用此函数来注册 TID 清理指针。
/// 当线程退出时，内核应将 0 写入此地址并执行 futex_wake。
///
/// # Arguments
///
/// * `tidptr` - 指向用户空间 i32 的指针，可为 NULL
///
/// # Returns
///
/// 返回调用进程的 TID（当前等于 PID）
///
/// F.1 PID Namespace: Returns the namespace-local TID.
fn sys_set_tid_address(tidptr: *mut i32) -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    // 验证用户指针（如果非空）
    if !tidptr.is_null() {
        validate_user_ptr_mut(tidptr as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(tidptr as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 保存指针到进程控制块
    let ns_tid = {
        let mut proc = process.lock();
        proc.clear_child_tid = tidptr as u64;
        // F.1: Return the TID from the owning namespace
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain).unwrap_or(proc.tid)
    };

    // 返回当前 TID (namespace-local)
    Ok(ns_tid)
}

/// sys_set_robust_list - 注册 robust_list 头指针
///
/// robust_list 用于跟踪进程持有的 robust futex，以便在进程异常退出时
/// 内核能够自动释放这些锁，防止死锁。
///
/// # Arguments
///
/// * `head` - 指向 robust_list_head 结构的用户空间指针
/// * `len` - robust_list_head 结构的大小（必须为 24）
///
/// # Returns
///
/// 成功返回 0
fn sys_set_robust_list(head: *const u8, len: usize) -> SyscallResult {
    /// Linux robust_list_head 结构大小
    /// struct robust_list_head {
    ///     struct robust_list *list;         // 8 bytes
    ///     long futex_offset;                // 8 bytes
    ///     struct robust_list *list_op_pending; // 8 bytes
    /// }
    const ROBUST_LIST_HEAD_SIZE: usize = 24;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 允许 NULL 指针（用于清除）
    if head.is_null() {
        let mut proc = process.lock();
        proc.robust_list_head = 0;
        proc.robust_list_len = 0;
        return Ok(0);
    }

    // Linux 要求 len 必须等于 sizeof(struct robust_list_head) == 24
    if len != ROBUST_LIST_HEAD_SIZE {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存
    validate_user_ptr(head, len)?;
    verify_user_memory(head, len, false)?;

    // 保存到进程控制块
    let mut proc = process.lock();
    proc.robust_list_head = head as u64;
    proc.robust_list_len = len;

    Ok(0)
}

/// sys_kill - 发送信号给进程
///
/// # Arguments
///
/// * `pid` - 目标进程 ID (namespace-local PID as seen by caller)
/// * `sig` - 信号编号（1-64）
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
///
/// # Permission Model (Z-9 fix: POSIX-compliant UID/EUID checks)
///
/// POSIX permission rules for kill():
/// - Root (euid == 0) 可以发信号给任何进程
/// - 进程可以向自己发送任意信号
/// - sender.uid == target.uid
/// - sender.euid == target.uid
/// - PID 1 (init) 受保护，只有自己能向自己发信号
///
/// F.1 PID Namespace: The pid parameter is interpreted as a namespace-local PID.
/// It is translated to a global PID using the caller's owning namespace.
fn sys_kill(pid: ProcessId, sig: i32) -> SyscallResult {
    use crate::signal::{send_signal, signal_name, Signal};

    let self_global_pid = current_pid().ok_or(SyscallError::ESRCH)?;

    // F.1: Translate namespace-local PID to global PID
    let target_global_pid = {
        let self_proc = get_process(self_global_pid).ok_or(SyscallError::ESRCH)?;
        let owning_ns = {
            let proc = self_proc.lock();
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
        };
        if let Some(ns) = owning_ns {
            // Translate using caller's namespace
            crate::pid_namespace::resolve_pid_in_namespace(&ns, pid).ok_or(SyscallError::ESRCH)?
        } else {
            // No namespace (root or early boot) - use PID directly
            pid
        }
    };

    // 【安全修复 Z-9】POSIX 权限检查（防御深度）
    // send_signal 也会进行相同检查，这里提前拒绝以提供更清晰的错误

    // PID 1 保护：只有 init 自己能向自己发信号
    // Note: This checks the target's global PID, so namespace PID 1 is protected
    // within that namespace, but global PID 1 is specially protected.
    if target_global_pid == 1 && self_global_pid != 1 {
        return Err(SyscallError::EPERM);
    }

    // 非自己的进程需要进行 POSIX 权限检查
    if self_global_pid != target_global_pid {
        // 获取发送者凭证
        let sender_creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;

        // 获取目标进程凭证
        // R39-3 FIX: 使用共享凭证读取目标进程 uid
        let target = get_process(target_global_pid).ok_or(SyscallError::ESRCH)?;
        let target_uid = target.lock().credentials.read().uid;

        // POSIX 权限检查：
        // 1. Root (euid == 0) 可以发信号给任何进程
        // 2. sender.uid == target.uid
        // 3. sender.euid == target.uid
        let has_permission = sender_creds.euid == 0
            || sender_creds.uid == target_uid
            || sender_creds.euid == target_uid;

        if !has_permission {
            return Err(SyscallError::EPERM);
        }
    }

    // 验证信号编号
    let signal = Signal::from_raw(sig)?;

    // 发送信号 (using global PID)
    let action = send_signal(target_global_pid, signal)?;

    println!(
        "sys_kill: sent {} to PID {} (global={}, action: {:?})",
        signal_name(signal),
        pid,
        target_global_pid,
        action
    );

    Ok(0)
}

/// sys_unshare - Unshare namespaces for the current process
///
/// F.1 PID Namespace: When CLONE_NEWPID is specified, the calling process's
/// pid_ns_for_children is set to a new child namespace. The process itself
/// remains in its original namespace, but its future children will be created
/// in the new namespace.
///
/// # Arguments
///
/// * `flags` - Namespace flags to unshare (CLONE_NEWPID, etc.)
///
/// # Returns
///
/// 0 on success, -EINVAL for unsupported flags, -ENOMEM on allocation failure
///
/// # Linux Semantics
///
/// Unlike clone(), unshare() affects only the namespace for children, not the
/// caller's own namespace membership (for PID namespace).
fn sys_unshare(flags: u64) -> SyscallResult {
    // F.1: Currently CLONE_NEWPID and CLONE_NEWNS are supported
    let supported = CLONE_NEWPID | CLONE_NEWNS;
    let unsupported = flags & !supported;

    if unsupported != 0 {
        println!(
            "[sys_unshare] Unsupported flags: 0x{:x} (supported: CLONE_NEWPID | CLONE_NEWNS)",
            unsupported
        );
        return Err(SyscallError::EINVAL);
    }

    if flags == 0 {
        // No flags specified - nothing to do
        return Ok(0);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    if flags & CLONE_NEWPID != 0 {
        // Create a new child PID namespace
        let current_ns_for_children = {
            let proc = proc_arc.lock();
            proc.pid_ns_for_children.clone()
        };

        let new_ns =
            crate::pid_namespace::PidNamespace::new_child(current_ns_for_children).map_err(
                |e| {
                    println!("[sys_unshare] Failed to create PID namespace: {:?}", e);
                    match e {
                        crate::pid_namespace::PidNamespaceError::MaxDepthExceeded => {
                            SyscallError::EAGAIN
                        }
                        // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
                        crate::pid_namespace::PidNamespaceError::MaxNamespaces => {
                            SyscallError::EAGAIN
                        }
                        _ => SyscallError::ENOMEM,
                    }
                },
            )?;

        // Update the process's pid_ns_for_children
        {
            let mut proc = proc_arc.lock();
            proc.pid_ns_for_children = new_ns.clone();
        }

        println!(
            "[sys_unshare] Process {} unshared PID namespace, children will use ns_id={}, level={}",
            pid,
            new_ns.id().raw(),
            new_ns.level()
        );
    }

    // F.1: Handle CLONE_NEWNS - unshare mount namespace
    //
    // Unlike PID namespace, mount namespace unshare immediately affects the
    // current process's view of the filesystem. The process moves to a new
    // mount namespace with a copy of the parent's mount table.
    if flags & CLONE_NEWNS != 0 {
        // F.1 Security: require CAP_SYS_ADMIN or root
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(true);
        if !is_root && !has_cap_admin {
            println!("[sys_unshare] CLONE_NEWNS denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }

        // R74-3 FIX: Prevent mount namespace divergence in multi-threaded processes.
        //
        // CLONE_NEWNS can only be used by single-threaded processes. If multiple
        // threads share the same tgid, allowing one thread to unshare its mount
        // namespace would cause thread-local divergence, violating the assumption
        // that all threads in a thread group share the same mount namespace.
        //
        // This matches Linux behavior (EINVAL if CLONE_NEWNS with CLONE_THREAD).
        let tgid = {
            let proc = proc_arc.lock();
            proc.tgid
        };
        let thread_count = crate::thread_group_size(tgid);
        if thread_count > 1 {
            println!(
                "[sys_unshare] CLONE_NEWNS denied: thread group has {} threads (must be 1)",
                thread_count
            );
            return Err(SyscallError::EINVAL);
        }

        let current_ns = {
            let proc = proc_arc.lock();
            proc.mount_ns.clone()
        };

        let new_ns = crate::mount_namespace::clone_namespace(current_ns.clone()).map_err(|e| {
            println!("[sys_unshare] Failed to create mount namespace: {:?}", e);
            match e {
                crate::mount_namespace::MountNsError::MaxDepthExceeded => SyscallError::EAGAIN,
                _ => SyscallError::ENOMEM,
            }
        })?;

        // R74-2 FIX: Eagerly materialize mount namespace tables at unshare time.
        //
        // Same security fix as sys_clone: snapshot the parent's mount table NOW
        // to prevent post-unshare parent mounts from leaking into the child.
        materialize_namespace(&current_ns);
        materialize_namespace(&new_ns);

        // Update process's mount namespace (immediately takes effect)
        {
            let mut proc = proc_arc.lock();
            proc.mount_ns = new_ns.clone();
            proc.mount_ns_for_children = new_ns.clone();
        }

        println!(
            "[sys_unshare] Process {} unshared mount namespace, now using ns_id={}, level={} (eagerly materialized)",
            pid,
            new_ns.id().raw(),
            new_ns.level()
        );

        // F.1 Audit: Emit namespace unshare event
        let parent_id = new_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_ns.id().raw(),
                ns_type: CLONE_NEWNS as u32,
                parent_id,
            },
            &[272, flags, CLONE_NEWNS], // syscall 272 = unshare, flags, CLONE_NEWNS
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    Ok(0)
}

/// sys_setns - Switch to an existing mount namespace.
///
/// Allows a process to join an existing mount namespace referenced by
/// a file descriptor. This is used by container runtimes to enter
/// namespaces created by other processes.
///
/// # Arguments
///
/// * `fd` - File descriptor referencing a MountNamespaceFd
/// * `nstype` - Namespace type (must be 0 or CLONE_NEWNS for mount ns)
///
/// # Returns
///
/// 0 on success, -EINVAL for invalid namespace type, -EPERM if not root,
/// -EBADF for invalid fd, -EINVAL if fd is not a mount namespace fd
///
/// # Security
///
/// Requires root (euid == 0) or CAP_SYS_ADMIN equivalent.
fn sys_setns(fd: i32, nstype: i32) -> SyscallResult {
    // Validate namespace type
    if nstype != 0 && (nstype as u64) != CLONE_NEWNS {
        println!("[sys_setns] Invalid nstype: {}", nstype);
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: Require CAP_SYS_ADMIN (CapRights::ADMIN) or root
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
    let is_root = crate::current_euid().map(|e| e == 0).unwrap_or(true);
    if !is_root && !has_cap_admin {
        println!("[sys_setns] Permission denied: requires CAP_SYS_ADMIN or root");
        return Err(SyscallError::EPERM);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R74-3 FIX: Prevent mount namespace divergence in multi-threaded processes.
    //
    // setns(CLONE_NEWNS) cannot be used by multi-threaded processes because
    // it would cause thread-local namespace divergence. All threads in a
    // thread group must share the same mount namespace.
    //
    // This matches Linux behavior.
    let tgid = {
        let proc = proc_arc.lock();
        proc.tgid
    };
    let thread_count = crate::thread_group_size(tgid);
    if thread_count > 1 {
        println!(
            "[sys_setns] CLONE_NEWNS denied: thread group has {} threads (must be 1)",
            thread_count
        );
        return Err(SyscallError::EINVAL);
    }

    // Extract target mount namespace from fd
    let target_ns = {
        let proc = proc_arc.lock();
        let fd_entry = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
        if let Some(ns_fd) = fd_entry
            .as_any()
            .downcast_ref::<crate::mount_namespace::MountNamespaceFd>()
        {
            ns_fd.namespace()
        } else {
            println!("[sys_setns] fd {} is not a mount namespace fd", fd);
            return Err(SyscallError::EINVAL);
        }
    };

    println!(
        "[sys_setns] Process {} switching to mount namespace id={}, level={}",
        pid,
        target_ns.id().raw(),
        target_ns.level()
    );

    // Get old namespace for audit before switching
    let old_ns_id = {
        let proc = proc_arc.lock();
        proc.mount_ns.id().raw()
    };

    // Switch current process mount namespace (and future children)
    {
        let mut proc = proc_arc.lock();
        proc.mount_ns = target_ns.clone();
        proc.mount_ns_for_children = target_ns.clone();
    }

    // F.1 Audit: Emit namespace switch event
    let parent_id = target_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
    let _ = audit::emit(
        AuditKind::Process,
        AuditOutcome::Success,
        get_audit_subject(),
        AuditObject::Namespace {
            ns_id: target_ns.id().raw(),
            ns_type: CLONE_NEWNS as u32,
            parent_id,
        },
        &[308, fd as u64, old_ns_id], // syscall 308 = setns, fd, old_ns_id
        0,
        crate::time::current_timestamp_ms(),
    );

    Ok(0)
}

// ============================================================================
// 文件I/O系统调用
// ============================================================================

/// sys_pipe - 创建匿名管道
///
/// 创建一个管道，返回两个文件描述符：
/// - fds[0]: 读端
/// - fds[1]: 写端
///
/// # Arguments
///
/// * `fds` - 指向用户空间的 i32[2] 数组，用于返回文件描述符
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
fn sys_pipe(fds: *mut i32) -> SyscallResult {
    // 验证用户指针
    if fds.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 预先验证用户缓冲区可写
    // 这避免了创建管道后因 copy_to_user 失败导致的 fd 泄漏
    validate_user_ptr(fds as *const u8, core::mem::size_of::<[i32; 2]>())?;
    verify_user_memory(fds as *const u8, core::mem::size_of::<[i32; 2]>(), true)?;

    // 获取回调函数指针并立即释放锁
    // 避免在持有锁时执行可能耗时的回调
    let create_fn = {
        let callback = PIPE_CREATE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用管道创建回调
    let (read_fd, write_fd) = create_fn()?;

    // 将文件描述符写回用户空间
    let fd_array = [read_fd, write_fd];
    let bytes = unsafe {
        core::slice::from_raw_parts(
            fd_array.as_ptr() as *const u8,
            core::mem::size_of::<[i32; 2]>(),
        )
    };

    // copy_to_user 失败时回滚：关闭已创建的文件描述符
    if let Err(e) = copy_to_user(fds as *mut u8, bytes) {
        // 尝试关闭已分配的 fd（通过关闭回调）
        let close_fn = {
            let callback = FD_CLOSE_CALLBACK.lock();
            callback.as_ref().copied()
        };
        if let Some(close) = close_fn {
            let _ = close(read_fd);
            let _ = close(write_fd);
        }
        return Err(e);
    }

    Ok(0)
}

/// sys_read - 从文件描述符读取数据
///
/// # Security (X-2 fix)
///
/// 限制单次读取大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_read 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值导致切片越界 panic。
fn sys_read(fd: i32, buf: *mut u8, count: usize) -> SyscallResult {
    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr_mut(buf, count)?;

    // stdin (fd 0): 从键盘缓冲区读取字符
    // R23-5 fix: 阻塞模式 - 如果没有输入则等待
    // 使用 prepare-check-finish 模式避免丢失唤醒竞态
    if fd == 0 {
        // Debug: print heap stats before allocation
        #[cfg(debug_assertions)]
        println!("[sys_read] fd=0 count={}", count);

        let mut tmp = vec![0u8; count];
        loop {
            // 先尝试读取
            let bytes_read = drivers::keyboard_read(&mut tmp);
            if bytes_read > 0 {
                copy_to_user(buf, &tmp[..bytes_read])?;
                return Ok(bytes_read);
            }

            // 无数据：先入队再检查（避免丢失唤醒）
            if !stdin_prepare_to_wait() {
                // 无当前进程，返回 0 (EOF)
                return Ok(0);
            }

            // 二次检查：入队后可能有新数据到达
            let bytes_read = drivers::keyboard_read(&mut tmp);
            if bytes_read > 0 {
                // 有数据了，取消等待并返回
                // 注意：我们已经在等待队列中，但进程已被标记为 Blocked
                // 下次唤醒会将我们设为 Ready，但我们不会真正睡眠
                // 这是安全的：最坏情况是多一次调度
                copy_to_user(buf, &tmp[..bytes_read])?;
                return Ok(bytes_read);
            }

            // 确实没有数据，完成等待（让出 CPU）
            stdin_finish_wait();
            // 被唤醒后继续循环尝试读取
        }
    }

    // stdout/stderr 不支持读取
    if fd == 1 || fd == 2 {
        return Err(SyscallError::EBADF);
    }

    // 获取回调函数指针并立即释放锁
    let read_fn = {
        let callback = FD_READ_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EBADF)?
    };

    // 分配临时缓冲区并执行读取（在锁外）
    let mut tmp = vec![0u8; count];
    let bytes_read = read_fn(fd, &mut tmp)?;

    // Z-4 安全修复：将回调返回值 clamp 到请求的大小
    // 防止恶意/错误回调返回超大值导致切片越界 panic
    let bytes_read = bytes_read.min(count);

    // 复制到用户空间
    copy_to_user(buf, &tmp[..bytes_read])?;
    Ok(bytes_read)
}

/// sys_write - 向文件描述符写入数据
///
/// # Security (X-2 fix)
///
/// 限制单次写入大小为 MAX_RW_SIZE (1MB)，防止用户请求超大 count
/// 导致内核堆耗尽。在分配缓冲区前先验证用户指针有效性。
///
/// # Security (Z-4 fix)
///
/// 回调返回的 bytes_written 必须 clamp 到请求的 count，防止恶意/错误回调
/// 返回超大值。
fn sys_write(fd: i32, buf: *const u8, count: usize) -> SyscallResult {
    // X-2 安全修复：限制大小并提前验证
    let count = match count {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 预先验证用户缓冲区，避免在分配后发现指针无效
    validate_user_ptr(buf, count)?;

    // 先复制到内核缓冲区，避免直接解引用用户指针
    let mut tmp = vec![0u8; count];
    copy_from_user(&mut tmp, buf)?;

    // stdout(1)/stderr(2): 直接打印
    if fd == 1 || fd == 2 {
        if let Ok(s) = core::str::from_utf8(&tmp) {
            print!("{}", s);
            Ok(tmp.len())
        } else {
            Err(SyscallError::EINVAL)
        }
    } else if fd == 0 {
        // stdin 不支持写入
        Err(SyscallError::EBADF)
    } else {
        // 获取回调函数指针并立即释放锁
        let write_fn = {
            let callback = FD_WRITE_CALLBACK.lock();
            *callback.as_ref().ok_or(SyscallError::EBADF)?
        };

        // 在锁外执行写入
        let bytes_written = write_fn(fd, &tmp)?;

        // Z-4 安全修复：将回调返回值 clamp 到请求的大小
        Ok(bytes_written.min(count))
    }
}

/// iovec 结构，用于 writev/readv 分散-聚集 I/O
#[repr(C)]
struct Iovec {
    /// 缓冲区起始地址
    iov_base: *const u8,
    /// 缓冲区长度
    iov_len: usize,
}

/// writev 最大 iovec 数量
const IOV_MAX: usize = 1024;

/// sys_writev - 分散写入多个缓冲区
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `iov` - iovec 数组指针
/// * `iovcnt` - iovec 数组元素个数
///
/// # Returns
/// 成功返回写入的总字节数，失败返回错误码
fn sys_writev(fd: i32, iov: *const Iovec, iovcnt: usize) -> SyscallResult {
    use crate::usercopy::{copy_from_user_safe, UserAccessGuard};

    // 验证 iovcnt
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > IOV_MAX {
        return Err(SyscallError::EINVAL);
    }

    // 验证 iov 指针
    if iov.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let iov_size = iovcnt * mem::size_of::<Iovec>();
    validate_user_ptr(iov as *const u8, iov_size)?;

    // R24-11 fix: Copy iovec array using fault-tolerant usercopy
    // This prevents kernel panic if user unmaps iovec during copy
    let mut iov_array: Vec<Iovec> = Vec::with_capacity(iovcnt);
    {
        let _guard = UserAccessGuard::new();
        for i in 0..iovcnt {
            // Calculate offset for this iovec entry
            let entry_offset = i * mem::size_of::<Iovec>();
            let entry_ptr = (iov as usize + entry_offset) as *const u8;

            // Use fault-tolerant copy for each iovec entry
            let mut entry_bytes = [0u8; mem::size_of::<Iovec>()];
            if copy_from_user_safe(&mut entry_bytes, entry_ptr).is_err() {
                return Err(SyscallError::EFAULT);
            }

            // Safely transmute bytes to Iovec
            // SAFETY: Iovec is repr(C) and all byte patterns are valid
            let iov_entry: Iovec = unsafe { core::ptr::read(entry_bytes.as_ptr() as *const Iovec) };
            iov_array.push(iov_entry);
        }
    }

    // 逐个写入每个缓冲区
    let mut total_written: usize = 0;
    for entry in iov_array.iter() {
        if entry.iov_len == 0 {
            continue;
        }

        // 验证并写入单个缓冲区
        match sys_write(fd, entry.iov_base, entry.iov_len) {
            Ok(written) => {
                total_written += written;
            }
            Err(e) => {
                // 如果已写入部分数据，返回已写入的字节数
                if total_written > 0 {
                    return Ok(total_written);
                }
                return Err(e);
            }
        }
    }

    Ok(total_written)
}

/// sys_open - 打开文件
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `flags` - 打开标志 (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - 创建文件时的权限模式
///
/// # Returns
/// 成功返回文件描述符，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
fn sys_open(path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        core::str::from_utf8(&path_bytes)
            .map_err(|_| SyscallError::EINVAL)?
            .to_string()
    };

    // LSM hook: check file create permission if O_CREAT is set
    let open_flags = flags as u32;
    let path_hash = audit::hash_path(&path_str);

    if let Some(proc_ctx) = lsm_current_process_ctx() {
        // Check create permission first (if O_CREAT)
        if open_flags & lsm::OpenFlags::O_CREAT != 0 {
            // Get parent directory inode and name hash
            let (parent_hash, name_hash) = match path_str.rfind('/') {
                Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
                Some(idx) => (
                    audit::hash_path(&path_str[..idx]),
                    audit::hash_path(&path_str[idx + 1..]),
                ),
                None => (audit::hash_path("."), path_hash),
            };

            if let Err(err) =
                lsm::hook_file_create(&proc_ctx, parent_hash, name_hash, mode & 0o7777)
            {
                return Err(lsm_error_to_syscall(err));
            }
        }
    }

    // 获取 VFS 回调
    let open_fn = {
        let callback = VFS_OPEN_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS 打开文件
    let file_ops = open_fn(&path_str, flags as u32, mode)?;

    // LSM hook: check file open permission
    // This is after VFS open to have file metadata, but before fd allocation
    // If denied, file_ops will be dropped (closed) automatically
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let file_ctx = lsm::FileCtx::new(path_hash, mode, path_hash);
        if let Err(err) =
            lsm::hook_file_open(&proc_ctx, path_hash, lsm::OpenFlags(open_flags), &file_ctx)
        {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // R39-4 FIX: O_CLOEXEC 常量定义
    const O_CLOEXEC: u32 = 0x80000;

    // 分配文件描述符并存入 fd_table
    let fd = {
        let mut proc = process.lock();
        let fd = proc.allocate_fd(file_ops).ok_or(SyscallError::EMFILE)?;

        // R39-4 FIX: 如果 flags 包含 O_CLOEXEC，标记 fd 为 close-on-exec
        //
        // 这样 exec 时会自动关闭此 fd，防止敏感句柄泄漏到子进程
        if open_flags & O_CLOEXEC != 0 {
            proc.set_fd_cloexec(fd, true);
        }

        fd
    };

    Ok(fd as usize)
}

/// sys_stat - 获取文件状态
///
/// # Arguments
/// * `path` - 文件路径（用户空间指针）
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
///
/// # Security (Z-3 fix)
/// 使用 fault-tolerant copy_user_cstring 复制用户路径，防止 TOCTOU 和内核 panic
fn sys_stat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    // 验证路径指针
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        core::str::from_utf8(&path_bytes)
            .map_err(|_| SyscallError::EINVAL)?
            .to_string()
    };

    // 获取 VFS stat 回调
    let stat_fn = {
        let callback = VFS_STAT_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS stat
    let stat = stat_fn(&path_str)?;

    // 将结果写入用户空间
    let stat_bytes = unsafe {
        core::slice::from_raw_parts(
            &stat as *const VfsStat as *const u8,
            core::mem::size_of::<VfsStat>(),
        )
    };
    copy_to_user(statbuf as *mut u8, stat_bytes)?;

    Ok(0)
}

/// sys_fstat - 获取文件描述符状态
///
/// R41-1 FIX: 现在返回真实的 inode 元数据，而非虚假数据。
/// - 标准流 (0/1/2) 返回字符设备模式 (S_IFCHR | 0666)
/// - FileHandle: 查询底层 inode.stat() 获取真实元数据
/// - PipeHandle: 返回 S_IFIFO | 0666 模式
/// - 其他类型: 返回 EBADF
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `statbuf` - 指向用户空间 VfsStat 结构体的指针
///
/// # Returns
/// 成功返回 0，失败返回错误码
///
/// # Security
/// 此修复解决了 R41-1 安全漏洞：之前的实现返回虚假的 S_IFREG|0644
/// 给所有 fd>2，导致类型混淆和安全策略绕过。现在正确返回文件
/// 类型（普通文件、FIFO 等），使安全检查能够正确判断 fd 类型。
fn sys_fstat(fd: i32, statbuf: *mut VfsStat) -> SyscallResult {
    // 验证 statbuf 指针
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    validate_user_ptr(statbuf as *const u8, mem::size_of::<VfsStat>())?;
    verify_user_memory(statbuf as *const u8, mem::size_of::<VfsStat>(), true)?;

    // 负数 fd 无效
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }

    // 获取 stat 数据
    let stat = if fd <= 2 {
        // 标准流返回字符设备模式 (S_IFCHR | 0666)
        VfsStat {
            dev: 0,
            ino: fd as u64,
            mode: 0o020000 | 0o666, // S_IFCHR | rw-rw-rw-
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        }
    } else {
        // R41-1 FIX: 查询 fd 对象获取真实元数据
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = process.lock();
        let fd_obj = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
        fd_obj.stat()?
    };

    // 将结果写入用户空间
    let stat_bytes = unsafe {
        core::slice::from_raw_parts(
            &stat as *const VfsStat as *const u8,
            mem::size_of::<VfsStat>(),
        )
    };
    copy_to_user(statbuf as *mut u8, stat_bytes)?;

    Ok(0)
}

/// sys_lseek - 移动文件读写偏移
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `offset` - 偏移量
/// * `whence` - 偏移起点：
///   - 0 (SEEK_SET): 从文件开头
///   - 1 (SEEK_CUR): 从当前位置
///   - 2 (SEEK_END): 从文件结尾
///
/// # Returns
/// 成功返回新的偏移位置，失败返回错误码
fn sys_lseek(fd: i32, offset: i64, whence: i32) -> SyscallResult {
    // 标准流不支持 seek
    if fd < 3 {
        return Err(SyscallError::EINVAL);
    }

    // 验证 whence 参数
    if whence < 0 || whence > 2 {
        return Err(SyscallError::EINVAL);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 从 fd_table 获取文件描述符
    let proc = process.lock();
    let file_ops = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

    // 获取 lseek 回调函数
    let lseek_fn = {
        let callback = VFS_LSEEK_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EINVAL)?
    };

    // 通过回调执行 seek 操作
    // 回调函数会尝试将 file_ops 向下转型到 FileHandle 并执行 seek
    match lseek_fn(file_ops.as_any(), offset, whence) {
        Ok(new_offset) => Ok(new_offset as usize),
        Err(e) => Err(e),
    }
}

/// sys_close - 关闭文件描述符
fn sys_close(fd: i32) -> SyscallResult {
    // 标准流不能关闭（简化实现）
    if fd <= 2 {
        return Err(SyscallError::EBADF);
    }

    // 获取回调函数指针并立即释放锁
    let close_fn = {
        let callback = FD_CLOSE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::EBADF)?
    };

    // 在锁外执行关闭
    close_fn(fd)?;
    Ok(0)
}

/// sys_ioctl - I/O 控制
///
/// 为 musl libc 提供最小化 stub 实现。
/// musl 会在终端检测时调用 TCGETS 等 ioctl，返回 ENOTTY 表明不是终端。
///
/// # Arguments
/// * `fd` - 文件描述符
/// * `cmd` - ioctl 命令码
/// * `arg` - 命令参数
///
/// # Returns
/// 当前始终返回 ENOTTY（不是终端设备）
fn sys_ioctl(fd: i32, cmd: u64, arg: u64) -> SyscallResult {
    // 标记参数为已使用，避免编译器警告
    let _ = (cmd, arg);

    // 验证 fd 有效性
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }

    // 标准流始终有效，其他 fd 需要检查
    if fd > 2 {
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = process.lock();
        if proc.get_fd(fd).is_none() {
            return Err(SyscallError::EBADF);
        }
    }

    // 当前不实现任何 ioctl 命令
    // 常见命令：
    // - TCGETS (0x5401): 获取终端属性
    // - TIOCGWINSZ (0x5413): 获取终端窗口大小
    // 返回 ENOTTY 告知 musl 这不是终端设备
    Err(SyscallError::ENOTTY)
}

// ============================================================================
// 内存管理系统调用
// ============================================================================

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// 页对齐向上取整
#[inline]
fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// sys_brk - 改变数据段大小（堆管理）
///
/// # Arguments
///
/// * `addr` - 新的 program break 地址，0 表示查询当前值
///
/// # Returns
///
/// 成功返回新的 brk 值，失败返回旧的 brk 值（符合 Linux 语义）
///
/// # Behavior
///
/// - brk(0) 返回当前 program break
/// - brk(addr < brk_start) 返回当前 brk（拒绝缩小到起始点以下）
/// - brk(addr > current) 扩展堆，分配匿名页
/// - brk(addr < current) 收缩堆，释放页面
fn sys_brk(addr: usize) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    let mut proc = process.lock();

    // 查询模式：返回当前 brk
    if addr == 0 {
        return Ok(proc.brk);
    }

    // F.2 Cgroup: Cache cgroup_id for memory accounting
    let cgroup_id = proc.cgroup_id;

    // R29-3 FIX: Call LSM hook for brk operations
    if let Some(ctx) = lsm::ProcessCtx::from_current() {
        if lsm::hook_memory_brk(&ctx, addr as u64).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    // 拒绝缩小到 brk_start 以下
    if addr < proc.brk_start {
        return Ok(proc.brk);
    }

    // 检查用户空间边界
    if addr >= USER_SPACE_TOP {
        return Ok(proc.brk);
    }

    let old_brk = proc.brk;
    let old_top = page_align_up(old_brk);
    let new_top = page_align_up(addr);

    // 堆扩展
    if new_top > old_top {
        let grow_size = new_top - old_top;

        // 检查与 mmap 区域冲突
        for (&region_base, &region_len) in proc.mmap_regions.iter() {
            let region_end = region_base.saturating_add(region_len);
            if old_top < region_end && new_top > region_base {
                // 有重叠，返回旧值
                return Ok(old_brk);
            }
        }

        // F.2 Cgroup: Charge memory before heap expansion.
        // Uses CAS-based try_charge_memory() to atomically check limit and update usage.
        if cgroup::try_charge_memory(cgroup_id, grow_size as u64).is_err() {
            return Ok(old_brk); // Quota exceeded, return current brk
        }

        // 释放锁后进行映射操作
        drop(proc);

        // R37-5 FIX: Track mapped pages for rollback on partial allocation failure.
        // If allocation fails partway, we must unmap+free pages already mapped in this call.
        let map_result: Result<(), SyscallError> = unsafe {
            with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
                let mut frame_alloc = FrameAllocator::new();
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::NO_EXECUTE;
                let mut mapped_pages: Vec<Page<x86_64::structures::paging::Size4KiB>> = Vec::new();

                for offset in (0..grow_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((old_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // 检查页面是否已映射
                    if manager.translate_addr(vaddr).is_some() {
                        continue;
                    }

                    // 分配物理帧 - with rollback on failure
                    let frame = match frame_alloc.allocate_frame() {
                        Some(f) => f,
                        None => {
                            // Rollback: unmap all pages we mapped in this call
                            for &rollback_page in mapped_pages.iter().rev() {
                                if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
                                    frame_alloc.deallocate_frame(freed_frame);
                                }
                            }
                            return Err(SyscallError::ENOMEM);
                        }
                    };

                    // 清零新分配的帧
                    let virt = mm::phys_to_virt(frame.start_address());
                    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, PAGE_SIZE);

                    // 映射页 - with rollback on failure
                    if manager
                        .map_page(page, frame, flags, &mut frame_alloc)
                        .is_err()
                    {
                        // Free the frame we just allocated
                        frame_alloc.deallocate_frame(frame);
                        // Rollback: unmap all pages we mapped in this call
                        for &rollback_page in mapped_pages.iter().rev() {
                            if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
                                frame_alloc.deallocate_frame(freed_frame);
                            }
                        }
                        return Err(SyscallError::ENOMEM);
                    }

                    mapped_pages.push(page);
                }
                Ok(())
            })
        };

        if map_result.is_err() {
            // 分配失败，返回旧值并回滚内存计费
            // F.2 Cgroup: Rollback memory charge on mapping failure
            cgroup::uncharge_memory(cgroup_id, grow_size as u64);
            return Ok(old_brk);
        }

        // 更新进程 brk
        let mut proc = process.lock();
        proc.brk = addr;
        Ok(addr)
    }
    // 堆收缩
    else if new_top < old_top {
        let shrink_size = old_top - new_top;

        // 释放锁后进行解映射操作
        drop(proc);

        // 解映射页面
        unsafe {
            with_current_manager(VirtAddr::new(0), |manager| {
                let mut frame_alloc = FrameAllocator::new();

                for offset in (0..shrink_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((new_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // 解映射并释放帧
                    if let Ok(frame) = manager.unmap_page(page) {
                        frame_alloc.deallocate_frame(frame);
                    }
                }
            });
        }

        // 更新进程 brk 并释放内存计费
        let mut proc = process.lock();
        proc.brk = addr;
        drop(proc);

        // F.2 Cgroup: Uncharge memory after successful heap shrink
        cgroup::uncharge_memory(cgroup_id, shrink_size as u64);

        Ok(addr)
    }
    // 同一页内调整，只更新 brk 值
    else {
        proc.brk = addr;
        Ok(addr)
    }
}

/// sys_mmap - 内存映射
///
/// 使用当前进程的地址空间进行映射，确保进程隔离
fn sys_mmap(
    addr: usize,
    length: usize,
    prot: i32,
    _flags: i32,
    fd: i32,
    _offset: i64,
) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::{Page, PageTableFlags};
    use x86_64::VirtAddr;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 验证参数
    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    // R30-2 FIX: Enforce W^X policy - reject PROT_WRITE | PROT_EXEC
    // PROT_WRITE = 0x2, PROT_EXEC = 0x4
    // Mirrors the check in sys_mprotect for consistency
    if (prot & 0x2 != 0) && (prot & 0x4 != 0) {
        return Err(SyscallError::EPERM);
    }

    // 文件映射暂不支持
    // R72-ENOSYS FIX: Return EOPNOTSUPP instead of ENOSYS. The syscall IS
    // implemented (for anonymous mappings), but file-backed mappings are not
    // yet supported.
    if fd >= 0 {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R29-3 FIX: Call LSM hook for anonymous mmap operations
    if let Some(ctx) = lsm::ProcessCtx::from_current() {
        if lsm::hook_memory_mmap(&ctx, addr as u64, length as u64, prot as u32, _flags as u32)
            .is_err()
        {
            return Err(SyscallError::EPERM);
        }
    }

    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // R32-SC-1 FIX: PROT_NONE (prot=0) should create non-present mapping
    // that faults on access (guard page behavior). Mirror sys_mprotect.
    let mut page_flags = if prot == 0 {
        PageTableFlags::empty()
    } else {
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
    };

    // PROT_WRITE
    if prot & 0x2 != 0 {
        page_flags |= PageTableFlags::WRITABLE;
    }

    // PROT_EXEC (x86_64使用NX位表示不可执行)
    if prot & 0x4 == 0 {
        page_flags |= PageTableFlags::NO_EXECUTE;
    }

    // R65-9 FIX: Hold process lock across address selection, page ops, and PCB commit
    // This prevents race conditions where concurrent mmap calls select overlapping addresses
    // or concurrent mmap/munmap calls corrupt page table state.
    let mut proc = process.lock();

    // 选择起始虚拟地址（使用 checked_add 防止溢出）
    // R65-11 FIX: Ensure auto-selected address is at least MMAP_MIN_ADDR
    let base = if addr == 0 {
        let candidate = proc
            .next_mmap_addr
            .checked_add(0xfff)
            .ok_or(SyscallError::EINVAL)?
            & !0xfff;
        // Ensure we don't auto-select addresses below MMAP_MIN_ADDR
        if candidate < crate::usercopy::MMAP_MIN_ADDR {
            crate::usercopy::MMAP_MIN_ADDR
        } else {
            candidate
        }
    } else {
        addr
    };

    // 检查地址对齐
    if base & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    // R65-11 FIX: Reject mappings below MMAP_MIN_ADDR to prevent NULL dereference exploitation
    // A kernel NULL pointer bug could be exploited if user space can map page 0 with controlled content.
    // 64KB is the Linux default (vm.mmap_min_addr).
    if base < crate::usercopy::MMAP_MIN_ADDR {
        return Err(SyscallError::EPERM);
    }

    // 计算结束地址并检查用户空间边界
    let end = base
        .checked_add(length_aligned)
        .ok_or(SyscallError::EFAULT)?;

    if end > USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    // 检查与现有映射的重叠
    for (&region_base, &region_len) in proc.mmap_regions.iter() {
        let region_end = region_base
            .checked_add(region_len)
            .ok_or(SyscallError::EFAULT)?;
        if base < region_end && end > region_base {
            return Err(SyscallError::EINVAL);
        }
    }

    let update_next = addr == 0;

    // F.2 Cgroup: Atomically charge memory AFTER all validation passes.
    // Uses CAS-based try_charge_memory() to close the TOCTOU race between limit
    // check and usage update. By charging only after validation, early errors
    // (unaligned address, below MMAP_MIN_ADDR, user-space overflow, overlap)
    // don't leak phantom usage that could exhaust memory quota.
    let cgroup_id = proc.cgroup_id;
    cgroup::try_charge_memory(cgroup_id, length_aligned as u64)
        .map_err(|_| SyscallError::ENOMEM)?;

    // 使用基于当前 CR3 的页表管理器进行映射
    // 使用 tracked vector 记录已映射的页，确保失败时完整回滚，避免帧泄漏
    let map_result: Result<(), SyscallError> = unsafe {
        use x86_64::structures::paging::PhysFrame;

        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            let mut frame_alloc = FrameAllocator::new();
            // 跟踪已成功映射的 (page, frame) 对，用于失败时回滚
            let mut mapped: vec::Vec<(Page, PhysFrame)> = vec::Vec::new();

            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((base + offset) as u64));

                // 分配物理帧，失败时回滚所有已映射的页
                let frame = match frame_alloc.allocate_frame() {
                    Some(f) => f,
                    None => {
                        // 回滚：释放所有已映射的页和帧
                        // 只有在 unmap 成功时才释放帧，避免 UAF
                        for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                            if manager.unmap_page(cleanup_page).is_ok() {
                                frame_alloc.deallocate_frame(cleanup_frame);
                            }
                            // unmap 失败时不释放帧，因为映射可能仍然存在
                            // 这会导致帧泄漏，但比 UAF 更安全
                        }
                        return Err(SyscallError::ENOMEM);
                    }
                };

                // 安全：清零新分配的帧，防止泄漏其他进程的数据
                // 使用高半区直映访问物理内存
                let virt = mm::phys_to_virt(frame.start_address());
                core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 0x1000);

                // 映射页，失败时回滚
                if let Err(_) = manager.map_page(page, frame, page_flags, &mut frame_alloc) {
                    // 释放当前分配但未映射的帧
                    frame_alloc.deallocate_frame(frame);
                    // 回滚：释放所有已映射的页和帧
                    // 只有在 unmap 成功时才释放帧，避免 UAF
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if manager.unmap_page(cleanup_page).is_ok() {
                            frame_alloc.deallocate_frame(cleanup_frame);
                        }
                        // unmap 失败时不释放帧，因为映射可能仍然存在
                    }
                    return Err(SyscallError::ENOMEM);
                }

                // 记录成功映射的页
                mapped.push((page, frame));
            }

            Ok(())
        })
    };

    // F.2 Cgroup: If mapping fails, rollback the memory charge to maintain
    // correct accounting. Without this, a failed mmap would leave phantom
    // usage that blocks future allocations.
    if let Err(e) = map_result {
        cgroup::uncharge_memory(cgroup_id, length_aligned as u64);
        return Err(e);
    }

    // 记录映射到进程 PCB（锁仍持有，R65-9 FIX）
    proc.mmap_regions.insert(base, length_aligned);
    if update_next {
        proc.next_mmap_addr = end;
    } else if proc.next_mmap_addr < end {
        proc.next_mmap_addr = end;
    }

    // Note: Memory is already atomically charged via try_charge_memory() above.
    // R77-2 FIX: No separate accounting call needed - charge/uncharge model is complete.
    drop(proc); // Explicitly drop the lock

    println!(
        "sys_mmap: pid={}, mapped {} bytes at 0x{:x}",
        pid, length_aligned, base
    );

    Ok(base)
}

/// sys_munmap - 取消内存映射
///
/// 使用当前进程的地址空间进行取消映射，确保进程隔离
fn sys_munmap(addr: usize, length: usize) -> SyscallResult {
    use mm::memory::FrameAllocator;
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::Page;
    use x86_64::VirtAddr;

    // 验证参数
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    if length == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    // 对齐到页边界（使用 checked_add 防止整数溢出）
    let length_aligned = length.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // R65-9 FIX: Hold process lock across validation, unmapping, and PCB update
    // This prevents race conditions where concurrent munmap calls double-free pages
    let mut proc = process.lock();

    // 检查该区域是否在进程的 mmap 记录中
    let recorded_length = *proc.mmap_regions.get(&addr).ok_or(SyscallError::EINVAL)?;

    // 验证长度匹配
    if recorded_length != length_aligned {
        return Err(SyscallError::EINVAL);
    }

    // R30-3 FIX: Call LSM hook for munmap operations
    // This ensures memory unmapping is subject to policy and audit
    if let Some(ctx) = lsm::ProcessCtx::from_current() {
        if lsm::hook_memory_munmap(&ctx, addr as u64, length_aligned as u64).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    // 使用基于当前 CR3 的页表管理器进行取消映射
    // R23-3 fix: 使用两阶段方法 - 先收集帧、做 TLB shootdown、再释放
    let unmap_result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            use alloc::vec::Vec;
            use x86_64::structures::paging::PhysFrame;

            let mut frame_alloc = FrameAllocator::new();
            let mut frames_to_free: Vec<PhysFrame> = Vec::new();

            // 阶段 1: 取消映射并收集需要释放的帧
            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((addr + offset) as u64));
                if let Ok(frame) = manager.unmap_page(page) {
                    let phys_addr = frame.start_address().as_u64() as usize;

                    // 检查是否为 COW 共享页
                    // 如果有引用计数，递减；只有当引用计数为 0 时才释放
                    let should_free = if PAGE_REF_COUNT.get(phys_addr) > 0 {
                        PAGE_REF_COUNT.decrement(phys_addr) == 0
                    } else {
                        // 没有引用计数记录，说明不是 COW 页，可以直接释放
                        true
                    };

                    if should_free {
                        frames_to_free.push(frame);
                    }
                }
            }

            // 阶段 2: R23-3 fix - TLB shootdown
            // 在释放物理帧之前，确保所有 CPU 都已清除 stale TLB 条目
            // 当前单核模式下，只做本地 flush；SMP 时需要 IPI
            mm::flush_current_as_range(VirtAddr::new(addr as u64), length_aligned);

            // 阶段 3: 释放物理帧（此时 TLB 已清除，安全释放）
            for frame in frames_to_free {
                frame_alloc.deallocate_frame(frame);
            }

            Ok(())
        })
    };

    unmap_result?;

    // 从进程 PCB 中移除映射记录（锁仍持有，R65-9 FIX）
    proc.mmap_regions.remove(&addr);

    // F.2 Cgroup: Atomically uncharge memory after successful munmap.
    // Uses the specific region size for accurate accounting rather than
    // recalculating total usage from scratch.
    let cgroup_id = proc.cgroup_id;
    drop(proc); // Explicitly drop the lock
    cgroup::uncharge_memory(cgroup_id, length_aligned as u64);

    println!(
        "sys_munmap: pid={}, unmapped {} bytes at 0x{:x}",
        pid, length_aligned, addr
    );

    Ok(0)
}

/// mprotect 保护标志
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const PROT_NONE: i32 = 0x0;

/// sys_mprotect - 设置内存区域保护属性
///
/// # Arguments
/// * `addr` - 起始地址（必须页对齐）
/// * `len` - 区域长度
/// * `prot` - 保护标志 (PROT_READ, PROT_WRITE, PROT_EXEC)
///
/// # Returns
/// 成功返回 0，失败返回错误码
fn sys_mprotect(addr: usize, len: usize, prot: i32) -> SyscallResult {
    use mm::page_table::with_current_manager;
    use x86_64::structures::paging::Page;
    use x86_64::VirtAddr;

    // 验证地址页对齐
    if addr & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 长度为 0 时直接返回成功
    if len == 0 {
        return Ok(0);
    }

    // 对齐长度到页边界
    let len_aligned = len.checked_add(0xfff).ok_or(SyscallError::EINVAL)? & !0xfff;

    // R28-7 Fix: Validate that addr + len_aligned doesn't overflow or exceed user space
    let end = addr.checked_add(len_aligned).ok_or(SyscallError::EINVAL)?;
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EINVAL);
    }

    // W^X 安全检查：禁止同时可写可执行
    if (prot & PROT_WRITE != 0) && (prot & PROT_EXEC != 0) {
        return Err(SyscallError::EPERM);
    }

    // R29-3 FIX: Call LSM hook for mprotect operations
    if let Some(ctx) = lsm::ProcessCtx::from_current() {
        if lsm::hook_memory_mprotect(&ctx, addr as u64, len_aligned as u64, prot as u32).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    // 构建页表标志
    // R24-4 fix: PROT_NONE 需要清除 PRESENT 标志，使页面不可访问
    let flags = if prot == PROT_NONE {
        // 不可访问：清除 PRESENT，页存在但任何访问都会触发 #PF
        PageTableFlags::empty()
    } else {
        let mut f = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if prot & PROT_WRITE != 0 {
            f |= PageTableFlags::WRITABLE;
        }
        if prot & PROT_EXEC == 0 {
            // 如果没有 EXEC 权限，设置 NX 位
            f |= PageTableFlags::NO_EXECUTE;
        }
        f
    };

    // 更新页表项
    let result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            for offset in (0..len_aligned).step_by(0x1000) {
                let page_addr = addr + offset;
                let page = Page::containing_address(VirtAddr::new(page_addr as u64));

                // 尝试更新页的保护属性
                // 如果页不存在，跳过（mprotect 只修改已存在的映射）
                if let Err(e) = manager.update_flags(page, flags) {
                    // 忽略页不存在的错误，这是正常的
                    // 其他错误则返回
                    if !matches!(e, mm::page_table::UpdateFlagsError::PageNotMapped) {
                        return Err(SyscallError::EFAULT);
                    }
                }
            }
            Ok(())
        })
    };

    result?;

    // 刷新 TLB
    mm::flush_current_as_range(VirtAddr::new(addr as u64), len_aligned);

    Ok(0)
}

// ============================================================================
// Seccomp/Prctl 系统调用
// ============================================================================

// R26-3: Helper functions to manage seccomp installation state
//
// These functions set/clear the `seccomp_installing` flag to prevent TOCTOU
// race conditions between seccomp filter installation and thread creation.
// The flag must be manually cleared after installation completes or on error.

/// Convert seccomp error to syscall error
fn seccomp_error_to_syscall(err: seccomp::SeccompError) -> SyscallError {
    match err {
        seccomp::SeccompError::Fault => SyscallError::EFAULT,
        seccomp::SeccompError::NotPermitted => SyscallError::EPERM,
        seccomp::SeccompError::ProgramTooLong => SyscallError::E2BIG,
        _ => SyscallError::EINVAL,
    }
}

/// Decode user-space action code to SeccompAction
fn decode_user_action(code: u32, aux: u64) -> Result<seccomp::SeccompAction, SyscallError> {
    match code {
        SECCOMP_USER_ACTION_ALLOW => Ok(seccomp::SeccompAction::Allow),
        SECCOMP_USER_ACTION_LOG => Ok(seccomp::SeccompAction::Log),
        SECCOMP_USER_ACTION_ERRNO => {
            if aux > i32::MAX as u64 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompAction::Errno(aux as i32))
        }
        SECCOMP_USER_ACTION_TRAP => Ok(seccomp::SeccompAction::Trap),
        SECCOMP_USER_ACTION_KILL => Ok(seccomp::SeccompAction::Kill),
        _ => Err(SyscallError::EINVAL),
    }
}

/// Convert u64 to u8 with bounds check
#[inline]
fn to_u8_checked(val: u64) -> Result<u8, SyscallError> {
    if val > u8::MAX as u64 {
        return Err(SyscallError::EINVAL);
    }
    Ok(val as u8)
}

/// Translate user-space instruction to kernel SeccompInsn
fn translate_user_insn(insn: &UserSeccompInsn) -> Result<seccomp::SeccompInsn, SyscallError> {
    match insn.op {
        SECCOMP_USER_OP_LD_NR => Ok(seccomp::SeccompInsn::LdSyscallNr),
        SECCOMP_USER_OP_LD_ARG => {
            let idx = to_u8_checked(insn.arg0)?;
            if idx >= 6 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompInsn::LdArg(idx))
        }
        SECCOMP_USER_OP_LD_CONST => Ok(seccomp::SeccompInsn::LdConst(insn.arg0)),
        SECCOMP_USER_OP_AND => Ok(seccomp::SeccompInsn::And(insn.arg0)),
        SECCOMP_USER_OP_OR => Ok(seccomp::SeccompInsn::Or(insn.arg0)),
        SECCOMP_USER_OP_SHR => Ok(seccomp::SeccompInsn::Shr(to_u8_checked(insn.arg0)?)),
        SECCOMP_USER_OP_JMP_EQ => Ok(seccomp::SeccompInsn::JmpEq(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_NE => Ok(seccomp::SeccompInsn::JmpNe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LT => Ok(seccomp::SeccompInsn::JmpLt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LE => Ok(seccomp::SeccompInsn::JmpLe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GT => Ok(seccomp::SeccompInsn::JmpGt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GE => Ok(seccomp::SeccompInsn::JmpGe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP => Ok(seccomp::SeccompInsn::Jmp(to_u8_checked(insn.arg0)?)),
        SECCOMP_USER_OP_RET => {
            let action = decode_user_action(insn.arg0 as u32, insn.arg1)?;
            Ok(seccomp::SeccompInsn::Ret(action))
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// Load and validate a seccomp filter from userspace
fn load_user_seccomp_filter(flags: u32, args: u64) -> Result<seccomp::SeccompFilter, SyscallError> {
    // Validate flags - reject TSYNC since we don't implement thread synchronization
    // Silently accepting TSYNC would leave sibling threads unsandboxed (security gap)
    if flags & seccomp::SeccompFlags::TSYNC.bits() != 0 {
        println!("[sys_seccomp] TSYNC not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    // R28-8 Fix: Reject NEW_THREADS flag since we don't implement per-new-thread filtering
    // Accepting this flag would make callers believe new threads are sandboxed when they're not.
    if flags & seccomp::SeccompFlags::NEW_THREADS.bits() != 0 {
        println!("[sys_seccomp] NEW_THREADS not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    let filter_flags = seccomp::SeccompFlags::from_bits(flags).ok_or(SyscallError::EINVAL)?;

    // Read program header from userspace
    let mut prog = UserSeccompProg::default();
    let prog_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut prog as *mut _ as *mut u8,
            mem::size_of::<UserSeccompProg>(),
        )
    };
    copy_from_user(prog_bytes, args as *const u8)?;

    // Validate program length
    let len = prog.len as usize;
    if len == 0 || len > seccomp::MAX_INSNS {
        return Err(SyscallError::EINVAL);
    }

    // Validate filter pointer
    let insn_ptr = prog.filter as *const UserSeccompInsn;
    if insn_ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Calculate total size and validate
    let insn_size = mem::size_of::<UserSeccompInsn>();
    let total = insn_size.checked_mul(len).ok_or(SyscallError::EFAULT)?;
    validate_user_ptr(insn_ptr as *const u8, total)?;

    // Read instructions from userspace
    let mut raw_insns = vec![UserSeccompInsn::default(); len];
    let raw_bytes =
        unsafe { core::slice::from_raw_parts_mut(raw_insns.as_mut_ptr() as *mut u8, total) };
    copy_from_user(raw_bytes, insn_ptr as *const u8)?;

    // Decode default action
    let default_action = decode_user_action(prog.default_action, 0)?;

    // Translate all instructions
    let mut program = Vec::with_capacity(len);
    for insn in raw_insns.iter() {
        program.push(translate_user_insn(insn)?);
    }

    // Create and validate filter
    seccomp::SeccompFilter::new(program, default_action, filter_flags)
        .map_err(seccomp_error_to_syscall)
}

/// Get current seccomp mode for PR_GET_SECCOMP
fn current_seccomp_mode(state: &seccomp::SeccompState) -> usize {
    if state.filters.is_empty() {
        return SECCOMP_MODE_DISABLED;
    }

    // Check if it's strict mode (only the strict filter installed)
    let strict_id = seccomp::strict_filter().id;
    if state.filters.len() == 1 {
        if let Some(filter) = state.filters.first() {
            if filter.id == strict_id {
                return SECCOMP_MODE_STRICT;
            }
        }
    }

    SECCOMP_MODE_FILTER
}

/// sys_seccomp - Install seccomp filter or strict mode
///
/// # Arguments
/// * `op` - Operation (SECCOMP_SET_MODE_STRICT or SECCOMP_SET_MODE_FILTER)
/// * `flags` - Filter flags (SeccompFlags bits)
/// * `args` - For FILTER mode, pointer to UserSeccompProg
///
/// # Security
/// - Filters can only be added, never removed (one-way sandboxing)
/// - Installing a filter automatically sets no_new_privs
/// - Filters are inherited across fork/clone
fn sys_seccomp(op: u32, flags: u32, args: u64) -> SyscallResult {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            // Strict mode requires no flags or args
            if flags != 0 || args != 0 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let filter = seccomp::strict_filter();

            let mut proc = proc_arc.lock();

            // R26-3 FIX: Check if another thread is already installing
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // Installing any filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;
            proc.seccomp_state.add_filter(filter);

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            println!("[sys_seccomp] PID={} installed STRICT mode", pid);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            // Load and validate the filter from userspace
            let filter = load_user_seccomp_filter(flags, args)?;

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = proc_arc.lock();

            // R26-3 FIX: Check if another thread is already installing
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R25-6 FIX: Reject seccomp in multi-threaded processes without TSYNC
            // R37-1 FIX (Codex review): Correctly distinguish CLONE_THREAD vs pure CLONE_VM siblings.
            // - CLONE_THREAD siblings (same tgid) can be synchronized with TSYNC
            // - Pure CLONE_VM siblings (different tgid) cannot be synchronized with TSYNC
            let thread_count = crate::process::thread_group_size(proc.tgid);
            let pure_vm_siblings =
                crate::process::non_thread_group_vm_share_count(proc.memory_space, proc.tgid);
            let tsync_requested = flags & seccomp::SeccompFlags::TSYNC.bits() != 0;

            // Reject if multi-threaded without TSYNC (partial sandboxing)
            if thread_count > 1 && !tsync_requested {
                println!(
                    "[sys_seccomp] PID={} REJECTED: threads={} without TSYNC",
                    pid, thread_count
                );
                return Err(SyscallError::EPERM);
            }

            // R37-1 FIX: If pure CLONE_VM siblings exist, reject regardless of TSYNC.
            // TSYNC only synchronizes CLONE_THREAD siblings (same tgid), not CLONE_VM processes.
            if pure_vm_siblings > 0 {
                println!(
                    "[sys_seccomp] PID={} REJECTED: {} CLONE_VM siblings (different tgid) present; \
                    seccomp cannot secure shared address space",
                    pid, pure_vm_siblings
                );
                return Err(SyscallError::EBUSY);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // Installing filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;

            // If LOG flag is set, enable violation logging
            if filter.flags.contains(seccomp::SeccompFlags::LOG) {
                proc.seccomp_state.log_violations = true;
            }

            proc.seccomp_state.add_filter(filter);

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            println!(
                "[sys_seccomp] PID={} installed FILTER mode (total filters: {})",
                pid,
                proc.seccomp_state.filters.len()
            );
            Ok(0)
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// sys_prctl - Process control operations
///
/// Implements seccomp and no_new_privs related prctl operations:
/// - PR_SET_NO_NEW_PRIVS: Set the sticky no_new_privs flag
/// - PR_GET_NO_NEW_PRIVS: Check if no_new_privs is set
/// - PR_GET_SECCOMP: Get current seccomp mode
/// - PR_SET_SECCOMP: Set seccomp mode (alternative to sys_seccomp)
///
/// # Arguments
/// * `option` - prctl operation code
/// * `arg2-arg5` - Operation-specific arguments
fn sys_prctl(option: i32, arg2: u64, arg3: u64, _arg4: u64, _arg5: u64) -> SyscallResult {
    match option {
        PR_SET_NO_NEW_PRIVS => {
            // arg2 must be 1 to set, 0 is invalid (can't unset)
            if arg2 != 1 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = proc_arc.lock();
            proc.seccomp_state.no_new_privs = true;

            println!("[sys_prctl] PID={} set NO_NEW_PRIVS", pid);
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(proc.seccomp_state.no_new_privs as usize)
        }
        PR_GET_SECCOMP => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(current_seccomp_mode(&proc.seccomp_state))
        }
        PR_SET_SECCOMP => {
            // prctl(PR_SET_SECCOMP, mode, filter_ptr, 0, 0)
            // Extra args (arg4/arg5) must be zero
            if _arg4 != 0 || _arg5 != 0 {
                return Err(SyscallError::EINVAL);
            }

            // Delegate to sys_seccomp based on mode
            // Note: prctl doesn't support flags, so we always pass 0
            let mode = arg2 as u32;
            match mode {
                SECCOMP_SET_MODE_STRICT => {
                    // Strict mode requires arg3=0
                    if arg3 != 0 {
                        return Err(SyscallError::EINVAL);
                    }
                    sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0)
                }
                SECCOMP_SET_MODE_FILTER => {
                    // arg3 is pointer to filter prog
                    // prctl interface doesn't support flags (use sys_seccomp directly for flags)
                    sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, arg3)
                }
                _ => Err(SyscallError::EINVAL),
            }
        }
        _ => {
            // Other prctl options not implemented
            Err(SyscallError::EINVAL)
        }
    }
}

// ============================================================================
// 架构相关系统调用
// ============================================================================

/// arch_prctl 操作码
const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;

/// 检查地址是否为 canonical 形式（x86_64）
///
/// 在 x86_64 中，虚拟地址必须是 48 位有效，高 16 位必须等于第 47 位的符号扩展。
/// 即：地址的高 17 位要么全为 0，要么全为 1。
#[inline]
fn is_canonical(addr: u64) -> bool {
    // 有效用户空间：0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF
    // 有效内核空间：0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
    // 非 canonical 区域：0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF
    let sign_extended = ((addr as i64) >> 47) as u64;
    sign_extended == 0 || sign_extended == 0x1FFFF
}

/// sys_arch_prctl - 设置/获取架构相关的线程状态
///
/// 主要用于 TLS (Thread Local Storage) 支持，设置 FS/GS segment base。
///
/// # Arguments
///
/// * `code` - 操作码 (ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS)
/// * `addr` - SET: 要设置的 base 地址；GET: 存储结果的用户空间指针
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
fn sys_arch_prctl(code: i32, addr: u64) -> SyscallResult {
    use x86_64::registers::model_specific::Msr;

    // MSR 寄存器常量
    const MSR_FS_BASE: u32 = 0xC000_0100;
    const MSR_GS_BASE: u32 = 0xC000_0101;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    match code {
        ARCH_SET_FS => {
            // 验证地址是 canonical
            if !is_canonical(addr) {
                return Err(SyscallError::EINVAL);
            }

            // Debug: 打印 ARCH_SET_FS 调用
            println!("[arch_prctl] PID={} ARCH_SET_FS addr=0x{:x}", pid, addr);

            // 更新进程 PCB 中的 fs_base
            {
                let mut proc = process.lock();
                proc.fs_base = addr;
            }

            // 立即更新 MSR（当前进程正在运行）
            unsafe {
                let mut msr = Msr::new(MSR_FS_BASE);
                msr.write(addr);
            }

            Ok(0)
        }

        ARCH_GET_FS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // 从 PCB 获取 fs_base
            let fs_base = {
                let proc = process.lock();
                proc.fs_base
            };

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &fs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        ARCH_SET_GS => {
            // 验证地址是 canonical
            if !is_canonical(addr) {
                return Err(SyscallError::EINVAL);
            }

            // 更新进程 PCB 中的 gs_base
            {
                let mut proc = process.lock();
                proc.gs_base = addr;
            }

            // 立即更新 MSR
            unsafe {
                let mut msr = Msr::new(MSR_GS_BASE);
                msr.write(addr);
            }

            Ok(0)
        }

        ARCH_GET_GS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // 从 PCB 获取 gs_base
            let gs_base = {
                let proc = process.lock();
                proc.gs_base
            };

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &gs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        _ => Err(SyscallError::EINVAL),
    }
}

// ============================================================================
// Futex 系统调用
// ============================================================================

/// sys_futex - 快速用户空间互斥锁操作
///
/// 实现 FUTEX_WAIT 和 FUTEX_WAKE 操作，用于用户空间高效同步。
///
/// # Arguments
///
/// * `uaddr` - 用户空间 futex 地址（指向 u32）
/// * `op` - 操作码：0=FUTEX_WAIT, 1=FUTEX_WAKE, 2=FUTEX_WAIT_TIMEOUT
/// * `val` - FUTEX_WAIT: 期望值；FUTEX_WAKE: 最大唤醒数量
/// * `timeout_ptr` - R39-6 FIX: 超时结构指针（仅 FUTEX_WAIT_TIMEOUT 使用）
///
/// # Returns
///
/// * FUTEX_WAIT: 成功阻塞并被唤醒返回 0，值不匹配返回 EAGAIN
/// * FUTEX_WAIT_TIMEOUT: 同上，超时返回 ETIMEDOUT
/// * FUTEX_WAKE: 返回实际唤醒的进程数量
/// * FUTEX_LOCK_PI: E.4 PI - 带优先级继承的互斥锁加锁
/// * FUTEX_UNLOCK_PI: E.4 PI - 带优先级继承的互斥锁解锁
fn sys_futex(uaddr: usize, op: i32, val: u32, timeout_ptr: usize) -> SyscallResult {
    const FUTEX_WAIT: i32 = 0;
    const FUTEX_WAKE: i32 = 1;
    const FUTEX_WAIT_TIMEOUT: i32 = 2;
    const FUTEX_LOCK_PI: i32 = 3;
    const FUTEX_UNLOCK_PI: i32 = 4;

    // 验证用户指针
    if uaddr == 0 {
        return Err(SyscallError::EFAULT);
    }

    // 检查地址对齐（u32 需要 4 字节对齐）
    if uaddr % 4 != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存可访问
    // E.4 PI: FUTEX_LOCK_PI 也需要读取用户内存
    verify_user_memory(
        uaddr as *const u8,
        core::mem::size_of::<u32>(),
        op == FUTEX_WAIT || op == FUTEX_WAIT_TIMEOUT || op == FUTEX_LOCK_PI,
    )?;

    // 获取回调函数
    let futex_fn = {
        let callback = FUTEX_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 对于 FUTEX_WAIT/FUTEX_WAIT_TIMEOUT/FUTEX_LOCK_PI，需要先读取当前值
    let current_value = if op == FUTEX_WAIT || op == FUTEX_WAIT_TIMEOUT || op == FUTEX_LOCK_PI {
        // 读取 futex 字（安全：已验证用户内存）
        let mut value_bytes = [0u8; 4];
        copy_from_user(&mut value_bytes, uaddr as *const u8)?;
        u32::from_ne_bytes(value_bytes)
    } else {
        0 // FUTEX_WAKE/FUTEX_UNLOCK_PI 不需要当前值
    };

    // R39-6 FIX: 解析可选超时（纳秒）
    let timeout_ns = if op == FUTEX_WAIT_TIMEOUT && timeout_ptr != 0 {
        // 验证 timespec 结构可读
        verify_user_memory(
            timeout_ptr as *const u8,
            core::mem::size_of::<TimeSpec>(),
            false,
        )?;

        // 读取 timespec
        let mut ts_bytes = [0u8; 16]; // sizeof(TimeSpec) = 16
        copy_from_user(&mut ts_bytes, timeout_ptr as *const u8)?;

        // 解析 timespec (tv_sec: i64, tv_nsec: i64)
        let tv_sec = i64::from_ne_bytes(ts_bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_ne_bytes(ts_bytes[8..16].try_into().unwrap());

        // 验证 timespec 有效性
        if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(SyscallError::EINVAL);
        }

        // 转换为纳秒
        Some(
            (tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(tv_nsec as u64),
        )
    } else {
        None
    };

    // 调用 IPC 模块的 futex 实现
    futex_fn(uaddr, op, val, current_value, timeout_ns)
}

// ============================================================================
// 其他系统调用
// ============================================================================

/// sys_yield - 主动让出CPU
fn sys_yield() -> SyscallResult {
    // 将当前进程状态设置为Ready
    if let Some(pid) = current_pid() {
        if let Some(process) = get_process(pid) {
            let mut proc = process.lock();
            proc.state = crate::process::ProcessState::Ready;
        }
    }

    // 强制触发重调度，立即执行上下文切换
    // 注意：force_reschedule() 可能不会返回（如果切换到其他进程）
    // 当本进程再次被调度时，会从这里继续执行
    crate::force_reschedule();

    Ok(0)
}

// ============================================================================
// CPU Affinity Syscalls (E.5 SMP Scheduler)
// ============================================================================

/// Debug macro for scheduler-related syscalls (defined early for use in functions below)
macro_rules! sched_affinity_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "sched_debug")]
        {
            drivers::println!($($arg)*);
        }
    };
}

/// Check whether the calling task may SET another task's CPU affinity.
///
/// Per Linux semantics, sched_setaffinity requires:
/// - Target is self (always allowed)
/// - OR caller has CAP_SYS_NICE (using ADMIN as closest equivalent)
/// - OR caller is root (euid == 0)
///
/// # Returns
/// - Ok(true) if allowed
/// - Ok(false) if not allowed (caller should return EPERM)
/// - Err if process lookup fails
#[inline]
fn can_set_affinity(target_pid: ProcessId) -> Result<bool, SyscallError> {
    let caller = current_pid().ok_or(SyscallError::ESRCH)?;
    if caller == target_pid {
        return Ok(true);
    }

    // Check for CAP_SYS_NICE (using ADMIN capability as closest match)
    let has_cap = with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
    if has_cap {
        return Ok(true);
    }

    // Check if caller is root
    if let Some(proc_arc) = get_process(caller) {
        let proc = proc_arc.lock();
        let creds = proc.credentials.read();
        if creds.euid == 0 {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Check whether the calling task may GET another task's CPU affinity.
///
/// Per Linux semantics, sched_getaffinity is more permissive:
/// - Target is self (always allowed)
/// - Target is in same thread group (same tgid)
/// - OR caller has CAP_SYS_NICE/root
///
/// For now, we allow reading affinity of any process for simplicity,
/// matching older Linux behavior. Stricter checks can be added later.
#[inline]
fn can_get_affinity(target_pid: ProcessId) -> Result<bool, SyscallError> {
    // Linux is permissive about reading affinity - allow for all processes
    // This matches common Linux distributions' behavior
    if get_process(target_pid).is_none() {
        return Err(SyscallError::ESRCH);
    }
    Ok(true)
}

/// Get the mask of usable CPUs (online CPUs capped at max_cpus).
///
/// This returns a bitmask where bit N is set if CPU N is available.
/// Used for normalizing affinity masks and for returning "all CPUs"
/// when allowed_cpus == 0.
#[inline]
fn usable_cpu_mask() -> u64 {
    let cpu_count = max_cpus();
    if cpu_count >= 64 {
        u64::MAX
    } else {
        (1u64 << cpu_count).saturating_sub(1)
    }
}

/// Normalize affinity mask: mask off CPUs beyond max_cpus and reject empty masks.
///
/// # Returns
/// - Ok(mask) - Normalized mask with only valid CPU bits set
/// - Err(EINVAL) - If the normalized mask is empty (no valid CPUs)
#[inline]
fn normalize_affinity_mask(mask: u64) -> Result<u64, SyscallError> {
    let normalized = mask & usable_cpu_mask();
    if normalized == 0 {
        return Err(SyscallError::EINVAL);
    }
    Ok(normalized)
}

/// sys_sched_setaffinity - Set CPU affinity mask for a process
///
/// # Arguments
/// * `pid` - Target process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU mask in bytes (must be >= 8)
/// * `mask` - User pointer to the affinity mask (u64 bitmask, bit N = CPU N)
///
/// # Returns
/// * `Ok(0)` - Success
/// * `Err(ESRCH)` - No process with the given PID
/// * `Err(EPERM)` - Caller lacks permission to modify target's affinity
/// * `Err(EINVAL)` - Invalid cpusetsize or empty mask after normalization
/// * `Err(EFAULT)` - Invalid user pointer
///
/// # E.5 Implementation Notes
/// If the target process is currently running on a CPU not in the new mask,
/// a reschedule is triggered to migrate it to an allowed CPU.
fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> SyscallResult {
    use core::mem::size_of;

    // Validate parameters
    if mask.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if cpusetsize < size_of::<u64>() {
        return Err(SyscallError::EINVAL);
    }

    // Resolve target PID
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 { caller_pid } else { pid as ProcessId };

    // Permission check (uses can_set_affinity which requires privilege for other processes)
    if !can_set_affinity(target_pid)? {
        return Err(SyscallError::EPERM);
    }

    // Copy mask from userspace
    let _guard = UserAccessGuard::new();
    let mut mask_bytes = [0u8; 8];
    crate::usercopy::copy_from_user_safe(&mut mask_bytes, mask).map_err(|_| SyscallError::EFAULT)?;
    let new_mask = normalize_affinity_mask(u64::from_ne_bytes(mask_bytes))?;

    // Update PCB and get info needed for reschedule decision
    let proc_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();
    let old_mask = proc.allowed_cpus;
    proc.allowed_cpus = new_mask;
    let is_running = proc.state == ProcessState::Running;
    // Note: We don't track which CPU a process is running on in the PCB currently,
    // so for cross-CPU migration we rely on the scheduler's periodic load balancing.
    // For self-migration, we can check current_cpu_id().
    drop(proc);

    // If the caller changed its own affinity and current CPU is now disallowed,
    // trigger immediate reschedule
    if target_pid == caller_pid && is_running {
        let cpu_id = current_cpu_id();
        // new_mask is never 0 here (normalize_affinity_mask rejects it)
        let cpu_still_allowed = cpu_id < 64 && (new_mask & (1u64 << cpu_id)) != 0;
        if !cpu_still_allowed {
            current_cpu().set_need_resched();
        }
    }

    // Log if mask changed (for debugging)
    if old_mask != new_mask {
        sched_affinity_debug!(
            "[AFFINITY] pid={} mask changed: 0x{:016x} -> 0x{:016x}",
            target_pid, old_mask, new_mask
        );
    }

    Ok(0)
}

/// sys_sched_getaffinity - Get CPU affinity mask for a process
///
/// # Arguments
/// * `pid` - Target process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU mask buffer in bytes (must be >= 8)
/// * `mask` - User pointer to receive the affinity mask
///
/// # Returns
/// * `Ok(8)` - Success, returns number of bytes written
/// * `Err(ESRCH)` - No process with the given PID
/// * `Err(EINVAL)` - Invalid cpusetsize
/// * `Err(EFAULT)` - Invalid user pointer
///
/// # Notes
/// - If allowed_cpus == 0 in the PCB, this means "no restriction" (all CPUs).
///   In that case, we return a mask with all usable CPUs set.
/// - The returned mask is always normalized to the system's CPU count.
/// - Linux is permissive about reading affinity (no EPERM for other processes).
fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> SyscallResult {
    use core::mem::size_of;

    // Validate parameters
    if mask.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if cpusetsize < size_of::<u64>() {
        return Err(SyscallError::EINVAL);
    }

    // Resolve target PID
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 { caller_pid } else { pid as ProcessId };

    // Permission check (permissive - just verify process exists)
    can_get_affinity(target_pid)?;

    // Get the affinity mask from PCB
    let proc_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;
    let proc = proc_arc.lock();
    let mut affinity = proc.allowed_cpus;
    drop(proc);

    // Normalize the mask to the system's usable CPUs
    let usable = usable_cpu_mask();

    // If allowed_cpus == 0, it means "all CPUs allowed"
    // Return a mask with all usable CPUs set
    if affinity == 0 {
        affinity = usable;
    } else {
        // Normalize: mask off any bits beyond max_cpus
        affinity &= usable;
    }

    // Copy mask to userspace
    let mask_bytes = affinity.to_ne_bytes();
    let _guard = UserAccessGuard::new();
    crate::usercopy::copy_to_user_safe(mask, &mask_bytes).map_err(|_| SyscallError::EFAULT)?;

    // Return number of bytes written (Linux returns the cpumask size)
    Ok(size_of::<u64>())
}

/// sys_getrandom - 获取随机字节
///
/// 为 musl libc 提供随机数生成支持。
/// 使用 RDRAND 指令（如果 CPU 支持）混合时间戳生成随机数。
///
/// # Arguments
/// * `buf` - 用户空间缓冲区指针
/// * `len` - 请求的字节数
/// * `flags` - 标志位 (GRND_NONBLOCK=0x1, GRND_RANDOM=0x2)
///
/// # Returns
/// 成功返回写入的字节数，失败返回错误码
fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> SyscallResult {
    /// GRND_NONBLOCK - 非阻塞模式
    const GRND_NONBLOCK: u32 = 0x1;
    /// GRND_RANDOM - 使用 /dev/random 语义（当前忽略）
    const GRND_RANDOM: u32 = 0x2;

    // 验证 flags 有效性
    if flags & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 处理边界情况
    let count = match len {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // 验证用户缓冲区
    validate_user_ptr_mut(buf, count)?;
    verify_user_memory(buf as *const u8, count, true)?;

    // R40-1 FIX: 使用 CSPRNG (ChaCha20) 生成随机数据
    //
    // 之前的实现使用时间戳混合 RDRAND，在启动早期可能是可预测的。
    // 现在使用 security::rng 模块的 ChaCha20 CSPRNG，它：
    // - 由 RDRAND/RDSEED 播种
    // - 定期重新播种
    // - 提供密码学安全的随机数
    let mut tmp = vec![0u8; count];
    match rng::fill_random(&mut tmp) {
        Ok(()) => {}
        Err(rng::RngError::NotInitialized) => {
            // 懒初始化 CSPRNG；非阻塞模式遵循 Linux 语义返回 EAGAIN
            if flags & GRND_NONBLOCK != 0 {
                return Err(SyscallError::EAGAIN);
            }
            // 尝试初始化 CSPRNG
            rng::init_global().map_err(|_| SyscallError::EAGAIN)?;
            rng::fill_random(&mut tmp).map_err(|_| SyscallError::EIO)?
        }
        Err(_) if flags & GRND_NONBLOCK != 0 => return Err(SyscallError::EAGAIN),
        Err(_) => return Err(SyscallError::EIO),
    }

    // 复制到用户空间
    copy_to_user(buf, &tmp)?;

    Ok(count)
}

// ============================================================================
// 用户/组ID系统调用
// ============================================================================

/// sys_getuid - 获取真实用户ID
fn sys_getuid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.uid as usize)
}

/// sys_geteuid - 获取有效用户ID
fn sys_geteuid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.euid as usize)
}

/// sys_getgid - 获取真实组ID
fn sys_getgid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.gid as usize)
}

/// sys_getegid - 获取有效组ID
fn sys_getegid() -> SyscallResult {
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.egid as usize)
}

// ============================================================================
// 文件系统附加系统调用
// ============================================================================

/// sys_getcwd - 获取当前工作目录
///
/// 当前实现返回固定值"/"，因为PCB未跟踪工作目录。
fn sys_getcwd(buf: *mut u8, size: usize) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if size < 2 {
        return Err(SyscallError::ERANGE);
    }

    // 当前工作目录固定为根目录
    let cwd = b"/\0";
    copy_to_user(buf, cwd)?;
    Ok(cwd.len())
}

/// sys_chdir - 更改当前工作目录
///
/// 当前实现仅验证路径存在，但不真正更改工作目录。
fn sys_chdir(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 复制路径
    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 通过回调获取stat并验证路径存在且是目录
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;
    if !is_directory_mode(stat.mode) {
        return Err(SyscallError::ENOTDIR);
    }

    // TODO: 将cwd存储在PCB中
    Ok(0)
}

/// sys_mkdir - 创建目录
fn sys_mkdir(path: *const u8, mode: u32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // LSM hook: check mkdir permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_mkdir(&proc_ctx, parent_hash, name_hash, mode & 0o7777) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调创建目录
    let create_fn = VFS_CREATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    create_fn(path_str, mode & 0o7777, true)?;
    Ok(0)
}

/// sys_rmdir - 删除空目录
fn sys_rmdir(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 通过回调检查是否为目录
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;
    if !is_directory_mode(stat.mode) {
        return Err(SyscallError::ENOTDIR);
    }

    // LSM hook: check rmdir permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_rmdir(&proc_ctx, parent_hash, name_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调删除目录
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str)?;
    Ok(0)
}

/// sys_unlink - 删除文件
fn sys_unlink(path: *const u8) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 不允许删除目录 (应使用rmdir)
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    if let Ok(stat) = stat_fn(path_str) {
        if is_directory_mode(stat.mode) {
            return Err(SyscallError::EISDIR);
        }
    }

    // LSM hook: check unlink permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let (parent_hash, name_hash) = match path_str.rfind('/') {
            Some(0) => (audit::hash_path("/"), audit::hash_path(&path_str[1..])),
            Some(idx) => (
                audit::hash_path(&path_str[..idx]),
                audit::hash_path(&path_str[idx + 1..]),
            ),
            None => (audit::hash_path("."), audit::hash_path(path_str)),
        };
        if let Err(err) = lsm::hook_file_unlink(&proc_ctx, parent_hash, name_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // 通过回调删除文件
    let unlink_fn = VFS_UNLINK_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    unlink_fn(path_str)?;
    Ok(0)
}

/// sys_access - 检查文件访问权限
///
/// mode: R_OK(4) | W_OK(2) | X_OK(1) | F_OK(0)
fn sys_access(path: *const u8, mode: i32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let path_bytes = crate::usercopy::copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    let path_str = core::str::from_utf8(&path_bytes).map_err(|_| SyscallError::EINVAL)?;

    // 通过回调获取文件状态
    let stat_fn = VFS_STAT_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let stat = stat_fn(path_str)?;

    // F_OK(0) - 仅检查文件是否存在
    if mode == 0 {
        return Ok(0);
    }

    // 获取当前进程凭证
    let euid = crate::current_euid().unwrap_or(0);
    let egid = crate::current_egid().unwrap_or(0);
    let sup_groups = crate::current_supplementary_groups().unwrap_or_default();

    // root用户拥有所有权限
    if euid == 0 {
        return Ok(0);
    }

    // 计算权限位
    let perm_bits = if euid == stat.uid {
        (stat.mode >> 6) & 0o7
    } else if egid == stat.gid || sup_groups.iter().any(|&g| g == stat.gid) {
        (stat.mode >> 3) & 0o7
    } else {
        stat.mode & 0o7
    };

    let need_read = (mode & 4) != 0;
    let need_write = (mode & 2) != 0;
    let need_exec = (mode & 1) != 0;

    let ok = (!need_read || (perm_bits & 0o4) != 0)
        && (!need_write || (perm_bits & 0o2) != 0)
        && (!need_exec || (perm_bits & 0o1) != 0);

    if ok {
        Ok(0)
    } else {
        Err(SyscallError::EACCES)
    }
}

/// sys_lstat - 获取符号链接状态
///
/// 当前VFS不支持符号链接，等同于stat。
fn sys_lstat(path: *const u8, statbuf: *mut VfsStat) -> SyscallResult {
    sys_stat(path, statbuf)
}

/// sys_fstatat - 相对路径stat
///
/// 当前仅支持AT_FDCWD或绝对路径。
fn sys_fstatat(dirfd: i32, path: *const u8, statbuf: *mut VfsStat, _flags: i32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 检查路径是否为绝对路径
    let first_byte = unsafe { *path };

    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        // R72-ENOSYS FIX: Return EOPNOTSUPP (operation not supported) instead of
        // ENOSYS. The syscall exists but relative path resolution from dirfd is
        // not yet implemented.
        return Err(SyscallError::EOPNOTSUPP);
    }

    sys_stat(path, statbuf)
}

/// sys_openat - 相对路径打开文件
///
/// 当前仅支持AT_FDCWD或绝对路径。
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let first_byte = unsafe { *path };

    if dirfd != AT_FDCWD && first_byte != b'/' {
        // R72-ENOSYS FIX: Return EOPNOTSUPP (operation not supported) instead of
        // ENOSYS. The syscall exists but relative path resolution from dirfd is
        // not yet implemented.
        return Err(SyscallError::EOPNOTSUPP);
    }

    sys_open(path, flags, mode)
}

/// sys_openat2 - open with extended flags and resolve options (Linux 5.6+)
///
/// # Arguments
/// * `dirfd` - Base directory fd (AT_FDCWD for current directory)
/// * `path` - File path (user space pointer)
/// * `how` - Pointer to struct open_how (flags, mode, resolve)
/// * `size` - Size of the open_how structure
///
/// # Returns
/// File descriptor on success, error code on failure
///
/// # Security
/// - RESOLVE_NO_SYMLINKS: Reject any symlink in path (ELOOP)
/// - RESOLVE_BENEATH: Reject paths escaping starting point (EXDEV)
/// - RESOLVE_NO_MAGICLINKS: Block /proc magic symlinks (ELOOP)
/// - RESOLVE_NO_XDEV: Don't cross mount boundaries (EXDEV)
fn sys_openat2(dirfd: i32, path: *const u8, how: *const OpenHow, size: usize) -> SyscallResult {
    use crate::usercopy::{copy_from_user, copy_user_cstring, UserPtr};

    // Validate pointers
    if path.is_null() || how.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Validate size (must be at least as large as our struct)
    if size < core::mem::size_of::<OpenHow>() {
        return Err(SyscallError::EINVAL);
    }

    // Copy open_how from user space
    let mut how_local = OpenHow::default();
    let how_ptr = UserPtr::<OpenHow>::new(how as *mut OpenHow).map_err(|_| SyscallError::EFAULT)?;
    copy_from_user(&mut how_local, how_ptr).map_err(|_| SyscallError::EFAULT)?;

    // Copy path from user space
    let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
    if path_bytes.is_empty() {
        return Err(SyscallError::EINVAL);
    }
    let path_str = core::str::from_utf8(&path_bytes)
        .map_err(|_| SyscallError::EINVAL)?
        .to_string();

    // Get current process
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R65-22 FIX: Handle dirfd for relative paths
    // Resolve relative paths against the directory referenced by dirfd
    let resolved_path = if path_str.starts_with('/') {
        // Absolute path: dirfd is ignored
        path_str.clone()
    } else if dirfd == AT_FDCWD {
        // AT_FDCWD: resolve relative to current working directory
        // For now, treat as relative to root (cwd support is limited)
        if path_str.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", path_str)
        }
    } else {
        // R65-22 FIX: Resolve relative path against dirfd
        // Get the directory fd and resolve path relative to it
        let dir_path = {
            let proc_guard = process.lock();
            let dir_fd = proc_guard.get_fd(dirfd).ok_or(SyscallError::EBADF)?;

            // The fd must be a directory for relative path resolution
            // Check via file type if available, or defer to VFS for directory check
            // For now, we require the fd to represent a directory inode
            if let Some(path_info) = proc_guard.fd_table.get(&dirfd) {
                // Use the path from the fd if we can extract it
                // Fall back to requiring explicit directory support
            }
            drop(proc_guard);

            // Since we don't have full fd_path tracking yet, return EOPNOTSUPP for
            // non-AT_FDCWD dirfd with relative paths. This is safer than incorrectly
            // resolving paths, as it prevents potential sandbox escapes.
            //
            // R72-ENOSYS FIX: Return EOPNOTSUPP (operation not supported) instead of
            // ENOSYS. The syscall exists but relative path resolution from dirfd is
            // not yet implemented.
            //
            // TODO: Implement full fd_paths tracking for complete openat2 support
            return Err(SyscallError::EOPNOTSUPP);
        };
    };

    // R65-22 FIX: Validate RESOLVE_BENEATH/RESOLVE_IN_ROOT constraints
    // These flags should confine path resolution to the anchor directory.
    // Without proper dirfd tracking, we cannot fully enforce these flags for
    // non-AT_FDCWD dirfd, so we reject such combinations.
    //
    // R72-ENOSYS FIX: Return EINVAL instead of ENOSYS. The syscall exists but
    // this specific flag combination is invalid for our current implementation.
    let resolve = how_local.resolve;
    if dirfd != AT_FDCWD && (resolve & 0x08 != 0 || resolve & 0x10 != 0) {
        // RESOLVE_BENEATH (0x08) or RESOLVE_IN_ROOT (0x10) with non-AT_FDCWD dirfd
        // Cannot properly enforce without fd_path tracking
        return Err(SyscallError::EINVAL);
    }

    // Validate flags: reject unknown flags
    let known_flags: u64 = 0o17777777; // All valid O_* flags
    if how_local.flags & !known_flags != 0 {
        return Err(SyscallError::EINVAL);
    }

    // Validate resolve: reject unknown resolve flags
    let known_resolve: u64 = 0x3F; // RESOLVE_NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH | IN_ROOT | CACHED
    if how_local.resolve & !known_resolve != 0 {
        return Err(SyscallError::EINVAL);
    }

    let open_flags = how_local.flags as u32;
    let mode = how_local.mode as u32;
    // Note: `resolve` already defined above for R65-22 validation

    // LSM hook: check file create permission if O_CREAT is set
    let path_hash = audit::hash_path(&resolved_path);

    if let Some(proc_ctx) = lsm_current_process_ctx() {
        if open_flags & lsm::OpenFlags::O_CREAT != 0 {
            let (parent_hash, name_hash) = match resolved_path.rfind('/') {
                Some(0) => (audit::hash_path("/"), audit::hash_path(&resolved_path[1..])),
                Some(idx) => (
                    audit::hash_path(&resolved_path[..idx]),
                    audit::hash_path(&resolved_path[idx + 1..]),
                ),
                None => (audit::hash_path("."), path_hash),
            };

            if let Err(err) =
                lsm::hook_file_create(&proc_ctx, parent_hash, name_hash, mode & 0o7777)
            {
                return Err(lsm_error_to_syscall(err));
            }
        }
    }

    // Get VFS callback with resolve support
    let open_fn = {
        let callback = VFS_OPEN_WITH_RESOLVE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // Call VFS with resolve flags
    let file_ops = open_fn(&resolved_path, open_flags, mode, resolve)?;

    // LSM hook: check file open permission
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let file_ctx = lsm::FileCtx::new(path_hash, mode, path_hash);
        if let Err(err) =
            lsm::hook_file_open(&proc_ctx, path_hash, lsm::OpenFlags(open_flags), &file_ctx)
        {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // O_CLOEXEC flag
    const O_CLOEXEC: u32 = 0x80000;

    // Allocate fd
    let fd = {
        let mut proc = process.lock();
        let fd = proc.allocate_fd(file_ops).ok_or(SyscallError::EMFILE)?;

        if open_flags & O_CLOEXEC != 0 {
            proc.set_fd_cloexec(fd, true);
        }

        fd
    };

    Ok(fd as usize)
}

// ============================================================================
// 文件描述符操作系统调用
// ============================================================================

/// sys_dup - 复制文件描述符
fn sys_dup(oldfd: i32) -> SyscallResult {
    if oldfd < 0 {
        return Err(SyscallError::EBADF);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    let newfd = proc.allocate_fd(cloned).ok_or(SyscallError::EMFILE)?;
    Ok(newfd as usize)
}

/// sys_dup2 - 复制文件描述符到指定位置
fn sys_dup2(oldfd: i32, newfd: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        // 验证oldfd有效
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
        return Ok(newfd as usize);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    // R39-4 FIX: 使用 remove_fd 代替直接操作 fd_table
    // 这样会同时清除 newfd 的 CLOEXEC 标记
    //
    // POSIX: dup2 创建的新 fd 不继承 CLOEXEC 标志
    proc.remove_fd(newfd);
    proc.fd_table.insert(newfd, cloned);
    // newfd 不设置 CLOEXEC（这是 dup2 的标准行为）

    Ok(newfd as usize)
}

/// sys_dup3 - 复制文件描述符(带flags)
///
/// flags: O_CLOEXEC(0x80000)
fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    if oldfd == newfd {
        return Err(SyscallError::EINVAL);
    }

    // 仅接受O_CLOEXEC标志
    const O_CLOEXEC: i32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        return Err(SyscallError::EINVAL);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();

    let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
    let cloned = src.clone_box();

    // R39-4 FIX: 使用 remove_fd 清除旧 fd 的 CLOEXEC 标记
    proc.remove_fd(newfd);
    proc.fd_table.insert(newfd, cloned);

    // R39-4 FIX: 如果 flags 包含 O_CLOEXEC，标记 fd 为 close-on-exec
    //
    // dup3 相比 dup2 的唯一区别就是可以原子地设置 CLOEXEC
    if flags & O_CLOEXEC != 0 {
        proc.set_fd_cloexec(newfd, true);
    }

    Ok(newfd as usize)
}

/// sys_ftruncate - 截断文件
fn sys_ftruncate(fd: i32, length: i64) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if length < 0 {
        return Err(SyscallError::EINVAL);
    }

    // 通过回调执行截断
    let truncate_fn = VFS_TRUNCATE_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    truncate_fn(fd, length as u64)?;
    Ok(0)
}

/// sys_chmod - 修改文件权限
///
/// 当前VFS不支持chmod操作。
///
/// # R72-ENOSYS FIX
/// Returns EOPNOTSUPP instead of ENOSYS since the syscall IS implemented,
/// but the operation is not supported by the current VFS backend.
fn sys_chmod(_path: *const u8, _mode: u32) -> SyscallResult {
    // VFS trait未提供chmod方法
    Err(SyscallError::EOPNOTSUPP)
}

/// sys_fchmod - 修改文件权限(通过fd)
///
/// 当前VFS不支持chmod操作。
///
/// # R72-ENOSYS FIX
/// Returns EOPNOTSUPP instead of ENOSYS since the syscall IS implemented,
/// but the operation is not supported by the current VFS backend.
fn sys_fchmod(_fd: i32, _mode: u32) -> SyscallResult {
    Err(SyscallError::EOPNOTSUPP)
}

/// sys_umask - 设置文件创建掩码
fn sys_umask(mask: u32) -> SyscallResult {
    let old = crate::set_current_umask((mask & 0o777) as u16).ok_or(SyscallError::ESRCH)?;
    Ok(old as usize)
}

/// sys_getdents64 - 读取目录项
fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> SyscallResult {
    if fd < 0 {
        return Err(SyscallError::EBADF);
    }
    if dirp.is_null() || count == 0 {
        return Err(SyscallError::EINVAL);
    }

    // 通过回调读取目录项
    let readdir_fn = VFS_READDIR_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let entries = readdir_fn(fd)?;

    // 构建dirent64结构
    let mut written = 0usize;
    let header_size = core::mem::size_of::<LinuxDirent64>();

    for entry in entries {
        let name_bytes = entry.name.as_bytes();

        // R42-2 FIX: Use checked arithmetic to prevent integer overflow.
        // An extremely long filename could cause the addition to wrap around,
        // resulting in an undersized buffer and subsequent memory corruption.
        let reclen = header_size
            .checked_add(name_bytes.len())
            .and_then(|v| v.checked_add(1)) // +1 for NUL terminator
            .and_then(|v| v.checked_add(7)) // +7 for alignment
            .map(|v| v & !7) // 8-byte alignment (round down)
            .ok_or(SyscallError::EINVAL)?;

        // R42-2 FIX: Validate reclen fits in u16 (d_reclen field type)
        if reclen > u16::MAX as usize {
            return Err(SyscallError::EINVAL);
        }

        // R42-2 FIX: Use checked arithmetic for buffer position
        let next_written = written.checked_add(reclen).ok_or(SyscallError::EINVAL)?;
        if next_written > count {
            break;
        }

        let d_type = match entry.file_type {
            FileType::Regular => 8,     // DT_REG
            FileType::Directory => 4,   // DT_DIR
            FileType::CharDevice => 2,  // DT_CHR
            FileType::BlockDevice => 6, // DT_BLK
            FileType::Symlink => 10,    // DT_LNK
            FileType::Fifo => 1,        // DT_FIFO
            FileType::Socket => 12,     // DT_SOCK
        };

        // 构建dirent结构到临时缓冲区
        let mut buf = vec![0u8; reclen];
        let dirent = LinuxDirent64 {
            d_ino: entry.ino,
            d_off: (written + reclen) as i64,
            d_reclen: reclen as u16,
            d_type,
        };

        // 复制header
        unsafe {
            core::ptr::copy_nonoverlapping(
                &dirent as *const _ as *const u8,
                buf.as_mut_ptr(),
                header_size,
            );
        }

        // 复制文件名
        buf[header_size..header_size + name_bytes.len()].copy_from_slice(name_bytes);
        buf[header_size + name_bytes.len()] = 0; // NUL terminator

        // 复制到用户空间
        copy_to_user(unsafe { dirp.add(written) }, &buf)?;
        written = next_written; // R42-2 FIX: Use pre-computed checked value
    }

    Ok(written)
}

// ============================================================================
// 时间系统调用
// ============================================================================

/// sys_nanosleep - 高精度睡眠
///
/// 当前使用忙等待实现，未来应使用定时器。
fn sys_nanosleep(req: *const TimeSpec, rem: *mut TimeSpec) -> SyscallResult {
    if req.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut ts = TimeSpec::default();
    let ts_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut ts as *mut TimeSpec as *mut u8,
            core::mem::size_of::<TimeSpec>(),
        )
    };
    crate::usercopy::copy_from_user_safe(ts_bytes, req as *const u8)
        .map_err(|_| SyscallError::EFAULT)?;

    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::EINVAL);
    }

    // 计算睡眠时间(毫秒)
    let total_ms = (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((ts.tv_nsec / 1_000_000) as u64);

    // R42-3 FIX: Yield CPU during sleep to prevent busy-wait DoS.
    // Instead of spinning in kernel context monopolizing the CPU,
    // we allow the scheduler to run other processes and use HLT
    // to reduce power consumption while waiting for the timer.
    let start = crate::time::get_ticks();
    while crate::time::get_ticks().saturating_sub(start) < total_ms {
        // Allow other processes to run
        crate::reschedule_if_needed();
        // Halt until next timer interrupt (reduces CPU usage)
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    // 如果提供了rem，设置为0
    if !rem.is_null() {
        let zero = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let zero_bytes = unsafe {
            core::slice::from_raw_parts(
                &zero as *const TimeSpec as *const u8,
                core::mem::size_of::<TimeSpec>(),
            )
        };
        crate::usercopy::copy_to_user_safe(rem as *mut u8, zero_bytes)
            .map_err(|_| SyscallError::EFAULT)?;
    }

    Ok(0)
}

/// sys_gettimeofday - 获取当前时间
fn sys_gettimeofday(tv: *mut TimeVal, _tz: usize) -> SyscallResult {
    if tv.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let ms = crate::time::current_timestamp_ms();
    let timeval = TimeVal {
        tv_sec: (ms / 1000) as i64,
        tv_usec: ((ms % 1000) * 1000) as i64,
    };

    let tv_bytes = unsafe {
        core::slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    crate::usercopy::copy_to_user_safe(tv as *mut u8, tv_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}

// ============================================================================
// 系统信息系统调用
// ============================================================================

/// sys_uname - 获取系统信息
fn sys_uname(buf: *mut UtsName) -> SyscallResult {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    fn fill_field(target: &mut [u8; 65], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(64);
        target[..len].copy_from_slice(&bytes[..len]);
        target[len] = 0;
    }

    let mut uts = UtsName::default();
    fill_field(&mut uts.sysname, "Zero-OS");
    fill_field(&mut uts.nodename, "zero-node");
    fill_field(&mut uts.release, "0.6.5");
    fill_field(&mut uts.version, "Security Foundation Phase A");
    fill_field(&mut uts.machine, "x86_64");

    let uts_bytes = unsafe {
        core::slice::from_raw_parts(
            &uts as *const UtsName as *const u8,
            core::mem::size_of::<UtsName>(),
        )
    };
    crate::usercopy::copy_to_user_safe(buf as *mut u8, uts_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}

// ============================================================================
// Socket 系统调用 (Linux x86_64 ABI: 41/49/44/45)
// ============================================================================

/// Helper: Read sockaddr_in from user space with length validation.
fn read_sockaddr_in(user: *const SockAddrIn, len: u32) -> Result<SockAddrIn, SyscallError> {
    if user.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let need = core::mem::size_of::<SockAddrIn>() as u32;
    if len < need {
        return Err(SyscallError::EINVAL);
    }

    validate_user_ptr(user as *const u8, need as usize)?;

    let mut addr = SockAddrIn::default();
    let addr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut addr as *mut SockAddrIn as *mut u8,
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    copy_from_user(addr_bytes, user as *const u8)?;
    Ok(addr)
}

/// Helper: Write sockaddr_in to user space with length tracking.
fn write_sockaddr_in(
    addr: &SockAddrIn,
    user_addr: *mut SockAddrIn,
    user_len: *mut u32,
) -> Result<(), SyscallError> {
    if user_addr.is_null() {
        return Ok(()); // Nothing to write
    }

    // Get user-provided buffer length
    let provided_len = if user_len.is_null() {
        core::mem::size_of::<SockAddrIn>() as u32
    } else {
        validate_user_ptr(user_len as *const u8, core::mem::size_of::<u32>())?;
        let mut len_bytes = [0u8; 4];
        copy_from_user(&mut len_bytes, user_len as *const u8)?;
        u32::from_ne_bytes(len_bytes)
    };

    let addr_bytes = unsafe {
        core::slice::from_raw_parts(
            addr as *const SockAddrIn as *const u8,
            core::mem::size_of::<SockAddrIn>(),
        )
    };

    let write_len = core::cmp::min(provided_len as usize, addr_bytes.len());
    if write_len > 0 {
        validate_user_ptr_mut(user_addr as *mut u8, write_len)?;
        copy_to_user(user_addr as *mut u8, &addr_bytes[..write_len])?;
    }

    // Write actual length back
    if !user_len.is_null() {
        let actual = (core::mem::size_of::<SockAddrIn>() as u32).to_ne_bytes();
        copy_to_user(user_len as *mut u8, &actual)?;
    }

    Ok(())
}

/// Helper: Get socket handle from fd_table.
fn socket_handle_from_fd(fd: i32) -> Result<(cap::CapId, u64, bool), SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();
    let fd_obj = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
    let socket = fd_obj
        .as_any()
        .downcast_ref::<SocketFile>()
        .ok_or(SyscallError::ENOTSOCK)?;
    Ok((socket.cap_id, socket.socket_id, socket.nonblocking))
}

/// Helper: Resolve socket state from handle.
///
/// # Security (R76-1 FIX)
/// Enforces network namespace isolation: a process can only access sockets
/// that belong to its current network namespace. This prevents a process
/// from using sockets inherited from a parent namespace after calling
/// clone(CLONE_NEWNET) or setns().
fn resolve_socket(
    cap_id: cap::CapId,
    socket_id: u64,
) -> Result<(cap::CapEntry, alloc::sync::Arc<net::SocketState>), SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();

    // Lookup capability entry
    let entry = proc
        .cap_table
        .lookup(cap_id)
        .map_err(cap_error_to_syscall)?;

    // Verify it's a socket with matching ID
    match &entry.object {
        cap::CapObject::Socket(ref h) if h.socket_id == socket_id => {}
        _ => return Err(SyscallError::ENOTSOCK),
    }

    // Get socket state from socket_table
    let sock = net::socket_table()
        .get(socket_id)
        .ok_or(SyscallError::EBADF)?;

    // R76-1 FIX: Enforce network namespace isolation.
    // A process that has entered a different network namespace (via clone/setns)
    // must not be able to use sockets from its previous namespace.
    // This prevents container escape via inherited socket capabilities.
    let caller_ns_id = current_net_ns_id().ok_or(SyscallError::ESRCH)?;
    if sock.net_ns_id != caller_ns_id {
        // Socket belongs to a different namespace - deny access
        return Err(SyscallError::EACCES);
    }

    Ok((entry, sock))
}

/// sys_socket - Create a UDP socket (syscall 41).
///
/// # Arguments
/// * `domain` - Address family (AF_INET = 2)
/// * `type_` - Socket type (SOCK_DGRAM = 2, may have SOCK_CLOEXEC/SOCK_NONBLOCK)
/// * `protocol` - Protocol (IPPROTO_UDP = 17, or 0 for default)
///
/// # Returns
/// File descriptor on success, negative errno on failure.
///
/// # Security
/// - Invokes LSM hook_net_socket for policy check
/// - Creates CapEntry with READ|WRITE|BIND rights
/// - Stores CapId in fd_table via SocketFile wrapper
fn sys_socket(domain: i32, type_: i32, protocol: i32) -> SyscallResult {
    // Parse domain
    let domain_val =
        net::SocketDomain::from_raw(domain as u32).ok_or(SyscallError::EAFNOSUPPORT)?;

    // Parse type (handle SOCK_CLOEXEC/SOCK_NONBLOCK flags)
    let raw_ty = type_ as u32;
    let cloexec = raw_ty & SOCK_CLOEXEC != 0;
    let nonblock = raw_ty & SOCK_NONBLOCK != 0;
    let clean_ty = raw_ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let ty = net::SocketType::from_raw(clean_ty).ok_or(SyscallError::EPROTOTYPE)?;

    // Parse protocol (infers default from socket type)
    let proto =
        net::SocketProtocol::from_raw(protocol as u32, ty).ok_or(SyscallError::EPROTONOSUPPORT)?;

    // Currently only support AF_INET
    if domain_val != net::SocketDomain::Inet4 {
        return Err(SyscallError::EAFNOSUPPORT);
    }

    // Validate socket type and protocol combinations
    match (ty, proto) {
        (net::SocketType::Dgram, net::SocketProtocol::Udp) => {}
        (net::SocketType::Stream, net::SocketProtocol::Tcp) => {}
        _ => return Err(SyscallError::EPROTONOSUPPORT),
    }

    // Get security label from current process
    let label = net::SocketLabel::from_current(0).ok_or(SyscallError::ESRCH)?;

    // R75-1 FIX: Get current process's network namespace for socket isolation.
    // Fail-closed: if we can't determine the namespace, refuse to create socket.
    let net_ns_id = current_net_ns_id().ok_or(SyscallError::ESRCH)?;

    // Create socket via socket_table (includes LSM hook_net_socket check)
    let socket = match (ty, proto) {
        (net::SocketType::Dgram, net::SocketProtocol::Udp) => net::socket_table()
            .create_udp_socket(label, net_ns_id)
            .map_err(socket_error_to_syscall)?,
        (net::SocketType::Stream, net::SocketProtocol::Tcp) => net::socket_table()
            .create_tcp_socket(label, net_ns_id)
            .map_err(socket_error_to_syscall)?,
        _ => return Err(SyscallError::EPROTONOSUPPORT),
    };

    // Create capability entry
    let cap_flags = if cloexec {
        cap::CapFlags::CLOEXEC
    } else {
        cap::CapFlags::empty()
    };
    let cap_entry = cap::CapEntry::with_flags(
        // R75-1 FIX: Pass network namespace ID to Socket capability for isolation tracking
        cap::CapObject::Socket(alloc::sync::Arc::new(cap::Socket::new(socket.id, socket.net_ns_id.raw()))),
        cap::CapRights::READ | cap::CapRights::WRITE | cap::CapRights::BIND,
        cap_flags,
    );

    // Allocate CapId + fd
    // R65-13 FIX: Add LSM/audit integration for capability allocation
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let fd = {
        let mut proc = process.lock();
        let proc_ctx = lsm_process_ctx_from(&proc);

        // R65-13 FIX: LSM hook before capability allocation
        if let Err(err) =
            lsm::hook_task_cap_modify(&proc_ctx, cap::CapId::INVALID, lsm::cap_op::ALLOCATE)
        {
            drop(proc);
            net::socket_table().close(socket.id);
            return Err(lsm_error_to_syscall(err));
        }

        // Allocate capability for the socket
        let cap_id = match proc.cap_table.allocate(cap_entry) {
            Ok(id) => id,
            Err(e) => {
                drop(proc);
                net::socket_table().close(socket.id);
                return Err(cap_error_to_syscall(e));
            }
        };

        // R65-13 FIX: Audit event for capability allocation
        {
            let subject = audit::AuditSubject::new(
                proc_ctx.pid as u32,
                proc_ctx.uid,
                proc_ctx.gid,
                proc_ctx.cap.map(|c| c.raw()),
            );
            let timestamp = crate::time::get_ticks();
            let _ = audit::emit_capability_event(
                audit::AuditOutcome::Success,
                subject,
                cap_id.raw(),
                audit::AuditCapOperation::Allocate,
                None,
                0,
                timestamp,
            );
        }

        let sock_file = SocketFile::new(cap_id, socket.id, nonblock);
        // R51-4 FIX: Roll back allocations if fd table is full
        let fd = match proc.allocate_fd(alloc::boxed::Box::new(sock_file)) {
            Some(fd) => fd,
            None => {
                // Release capability and close socket to prevent resource leak
                // R65-13 FIX: Audit event for capability revocation (rollback)
                {
                    let subject = audit::AuditSubject::new(
                        proc_ctx.pid as u32,
                        proc_ctx.uid,
                        proc_ctx.gid,
                        proc_ctx.cap.map(|c| c.raw()),
                    );
                    let timestamp = crate::time::get_ticks();
                    let _ = audit::emit_capability_event(
                        audit::AuditOutcome::Success,
                        subject,
                        cap_id.raw(),
                        audit::AuditCapOperation::Revoke,
                        None,
                        0,
                        timestamp,
                    );
                }
                let _ = proc.cap_table.revoke(cap_id);
                drop(proc);
                net::socket_table().close(socket.id);
                return Err(SyscallError::EMFILE);
            }
        };
        if cloexec {
            proc.cloexec_fds.insert(fd);
        }
        fd
    };

    Ok(fd as usize)
}

/// sys_bind - Bind socket to local address (syscall 49).
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `addr` - Pointer to sockaddr_in
/// * `addrlen` - Length of address structure
///
/// # Security
/// - Verifies CapRights::BIND
/// - Invokes LSM hook_net_bind for policy check
/// - Ports < 1024 require euid == 0 or NET_BIND_SERVICE capability
fn sys_bind(fd: i32, addr: *const SockAddrIn, addrlen: u32) -> SyscallResult {
    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check BIND right
    if !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    // Read address from user space
    let user_addr = read_sockaddr_in(addr, addrlen)?;
    if user_addr.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }

    let port = user_addr.port();
    let ip = net::Ipv4Addr(user_addr.ip_bytes());

    // Get current process context for LSM check
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // R49-3 FIX: Compute privileged port binding permission
    // Can bind to privileged ports if: root (euid == 0) OR has NET_BIND_SERVICE capability
    let has_net_bind_cap =
        with_current_cap_table(|table| table.has_rights(cap::CapRights::NET_BIND_SERVICE))
            .unwrap_or(false);
    let can_bind_privileged = ctx.euid == 0 || has_net_bind_cap;

    // Early check for privileged port access
    const PRIVILEGED_PORT_LIMIT: u16 = 1024;
    if port != 0 && port < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
        return Err(SyscallError::EACCES);
    }

    // Bind via socket_table (includes LSM hook_net_bind check)
    // R51-1: Support both UDP and TCP binding
    let port_opt = if port == 0 { None } else { Some(port) };
    if socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp {
        net::socket_table()
            .bind_udp(&socket, &ctx, cap_id, ip, port_opt, can_bind_privileged)
            .map_err(socket_error_to_syscall)?;
    } else if socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp {
        net::socket_table()
            .bind_tcp(&socket, &ctx, cap_id, ip, port_opt, can_bind_privileged)
            .map_err(socket_error_to_syscall)?;
    } else {
        return Err(SyscallError::EOPNOTSUPP);
    }

    Ok(0)
}

/// sys_listen - Mark a TCP socket as listening (syscall 50, R51-1).
///
/// Transitions a bound TCP socket to LISTEN state, enabling it to accept
/// incoming connections.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `backlog` - Maximum pending connections (clamped to system limits)
///
/// # Security
/// - Verifies CapRights::BIND (required for listen)
/// - Invokes LSM hook_net_listen for policy check
/// - Auto-binds to ephemeral port if not already bound
fn sys_listen(fd: i32, backlog: i32) -> SyscallResult {
    if backlog < 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets can listen
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // BIND right required for listen
    if !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Compute privileged-port permission for auto-bind
    let has_net_bind_cap =
        with_current_cap_table(|table| table.has_rights(cap::CapRights::NET_BIND_SERVICE))
            .unwrap_or(false);
    let can_bind_privileged = ctx.euid == 0 || has_net_bind_cap;

    net::socket_table()
        .listen(&socket, &ctx, cap_id, backlog as u32, can_bind_privileged)
        .map_err(socket_error_to_syscall)?;

    Ok(0)
}

/// sys_accept - Accept a pending TCP connection (syscall 43, R51-1).
///
/// Extracts the first connection from the listen queue, creates a new
/// socket for it, and returns its file descriptor.
///
/// # Arguments
/// * `fd` - Listening socket file descriptor
/// * `addr` - Optional pointer to receive peer address
/// * `addrlen` - Optional pointer to address length
///
/// # Security
/// - Verifies CapRights::READ (required for accept)
/// - Invokes LSM hook_net_accept for policy check
/// - Returns EAGAIN for non-blocking if no connections pending
fn sys_accept(fd: i32, addr: *mut SockAddrIn, addrlen: *mut u32) -> SyscallResult {
    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets can accept
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // READ right required for accept
    if !entry.rights.allows(cap::CapRights::READ) {
        return Err(SyscallError::EACCES);
    }

    // Must be in LISTEN state
    if !socket.is_listening() {
        return Err(SyscallError::EINVAL);
    }

    let current = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Blocking loop until a connection is ready
    let child = loop {
        match net::socket_table().poll_accept_ready(&socket) {
            Ok(Some(conn)) => break conn,
            Ok(None) => {
                if nonblock {
                    return Err(SyscallError::EAGAIN);
                }
                // Block on accept wait queue
                if let Some(waiters) = socket.listen_waiters() {
                    match waiters.wait_with_timeout(None) {
                        net::WaitOutcome::Woken => continue,
                        net::WaitOutcome::Closed => return Err(SyscallError::ECONNABORTED),
                        net::WaitOutcome::NoProcess => return Err(SyscallError::ESRCH),
                        net::WaitOutcome::TimedOut => continue,
                    }
                } else {
                    return Err(SyscallError::EINVAL);
                }
            }
            Err(e) => return Err(socket_error_to_syscall(e)),
        }
    };

    // Helper to clean up child socket on error after it's been popped from accept queue
    let cleanup_child = |c: &alloc::sync::Arc<net::SocketState>| {
        c.mark_closed();
        net::socket_table().close(c.id);
    };

    // LSM accept hook (using child's context for peer info)
    let mut ctx = net::socket_table().ctx_from_socket(&child);
    ctx.cap = Some(cap_id);
    if let Err(e) = lsm::hook_net_accept(&current, &ctx) {
        cleanup_child(&child);
        return Err(lsm_error_to_syscall(e));
    }

    // Fill optional peer address
    if !addr.is_null() && !addrlen.is_null() {
        if let (Some(rip), Some(rport)) = (child.remote_ip(), child.remote_port()) {
            let mut out = SockAddrIn::default();
            out.sin_family = AF_INET as u16;
            out.sin_port = rport.to_be();
            out.sin_addr = u32::from_le_bytes(rip).swap_bytes();

            if let Err(e) = validate_user_ptr(addr as *const u8, core::mem::size_of::<SockAddrIn>())
            {
                cleanup_child(&child);
                return Err(e);
            }
            if let Err(e) = validate_user_ptr(addrlen as *const u8, core::mem::size_of::<u32>()) {
                cleanup_child(&child);
                return Err(e);
            }

            // Convert struct to bytes for copy_to_user
            let out_bytes = unsafe {
                core::slice::from_raw_parts(
                    &out as *const SockAddrIn as *const u8,
                    core::mem::size_of::<SockAddrIn>(),
                )
            };
            if let Err(e) = copy_to_user(addr as *mut u8, out_bytes) {
                cleanup_child(&child);
                return Err(e);
            }

            let len_val = core::mem::size_of::<SockAddrIn>() as u32;
            if let Err(e) = copy_to_user(addrlen as *mut u8, &len_val.to_ne_bytes()) {
                cleanup_child(&child);
                return Err(e);
            }
        }
    }

    // Allocate capability + fd for child socket
    // R75-1 FIX: Pass network namespace ID to Socket capability (inherited from listener)
    let cap_entry = cap::CapEntry::with_flags(
        cap::CapObject::Socket(alloc::sync::Arc::new(cap::Socket::new(child.id, child.net_ns_id.raw()))),
        cap::CapRights::READ | cap::CapRights::WRITE | cap::CapRights::BIND,
        cap::CapFlags::empty(),
    );

    let pid = match current_pid() {
        Some(p) => p,
        None => {
            cleanup_child(&child);
            return Err(SyscallError::ESRCH);
        }
    };
    let process = match get_process(pid) {
        Some(p) => p,
        None => {
            cleanup_child(&child);
            return Err(SyscallError::ESRCH);
        }
    };
    let new_fd = {
        let mut proc = process.lock();
        let proc_ctx = lsm_process_ctx_from(&proc);

        // R65-13 FIX: LSM hook before capability allocation
        if let Err(err) =
            lsm::hook_task_cap_modify(&proc_ctx, cap::CapId::INVALID, lsm::cap_op::ALLOCATE)
        {
            drop(proc);
            cleanup_child(&child);
            return Err(lsm_error_to_syscall(err));
        }

        let new_cap = match proc.cap_table.allocate(cap_entry) {
            Ok(c) => c,
            Err(e) => {
                drop(proc);
                cleanup_child(&child);
                return Err(cap_error_to_syscall(e));
            }
        };

        // R65-13 FIX: Audit event for capability allocation
        {
            let subject = audit::AuditSubject::new(
                proc_ctx.pid as u32,
                proc_ctx.uid,
                proc_ctx.gid,
                proc_ctx.cap.map(|c| c.raw()),
            );
            let timestamp = crate::time::get_ticks();
            let _ = audit::emit_capability_event(
                audit::AuditOutcome::Success,
                subject,
                new_cap.raw(),
                audit::AuditCapOperation::Allocate,
                None,
                0,
                timestamp,
            );
        }

        let sock_file = SocketFile::new(new_cap, child.id, nonblock);
        match proc.allocate_fd(alloc::boxed::Box::new(sock_file)) {
            Some(fd) => fd,
            None => {
                // Rollback capability allocation
                // R65-13 FIX: Audit event for capability revocation (rollback)
                {
                    let subject = audit::AuditSubject::new(
                        proc_ctx.pid as u32,
                        proc_ctx.uid,
                        proc_ctx.gid,
                        proc_ctx.cap.map(|c| c.raw()),
                    );
                    let timestamp = crate::time::get_ticks();
                    let _ = audit::emit_capability_event(
                        audit::AuditOutcome::Success,
                        subject,
                        new_cap.raw(),
                        audit::AuditCapOperation::Revoke,
                        None,
                        0,
                        timestamp,
                    );
                }
                let _ = proc.cap_table.revoke(new_cap);
                drop(proc);
                cleanup_child(&child);
                return Err(SyscallError::EMFILE);
            }
        }
    };

    Ok(new_fd as usize)
}

/// sys_connect - Connect a TCP socket (syscall 42).
///
/// Initiates a TCP three-way handshake for stream sockets.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `addr` - Pointer to sockaddr_in with destination address
/// * `addrlen` - Length of address structure
///
/// # Security
/// - Verifies CapRights::WRITE for sending SYN
/// - Verifies CapRights::BIND if socket not yet bound (auto-bind)
/// - Invokes LSM hook_net_send for policy check
///
/// # Returns
/// - 0 on success (connection established or in progress)
/// - EINPROGRESS for non-blocking sockets when handshake is in progress
/// - EISCONN if already connected
fn sys_connect(fd: i32, addr: *const SockAddrIn, addrlen: u32) -> SyscallResult {
    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only stream sockets are supported for connect()
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // WRITE right required to transmit SYN
    if !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // BIND right required if auto-bind is needed
    if socket.local_port().is_none() && !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    // Read destination address
    let dest = read_sockaddr_in(addr, addrlen)?;
    if dest.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }
    let dst_port = dest.port();
    if dst_port == 0 {
        return Err(SyscallError::EINVAL);
    }
    let dst_ip = net::Ipv4Addr(dest.ip_bytes());

    // Current process context for LSM
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Source IP: use bound value if present, else 0.0.0.0 placeholder
    // The actual source IP will be determined by routing (future enhancement)
    let src_ip = socket
        .local_ip()
        .map(net::Ipv4Addr)
        .unwrap_or(net::Ipv4Addr([0, 0, 0, 0]));

    // Non-blocking connect uses zero timeout to get EINPROGRESS
    // Blocking connect uses a reasonable timeout to avoid indefinite blocks
    const TCP_CONNECT_TIMEOUT_NS: u64 = 5_000_000_000; // 5 seconds (for testing)

    // Phase 1: Build SYN segment and install TCB (always non-blocking first)
    // We use timeout=Some(0) to just build the segment without waiting
    let syn_result = net::socket_table()
        .connect(&socket, &ctx, cap_id, src_ip, dst_ip, dst_port, Some(0))
        .map_err(socket_error_to_syscall)?;

    // Phase 2: Transmit the SYN segment via network device
    // R51-5 FIX: Abort connection if TX fails to prevent TCB/binding leak
    if let Err(e) = net::transmit_tcp_segment(syn_result.dst_ip, &syn_result.segment) {
        net::socket_table().abort_tcp_connect(&socket);
        return Err(tx_error_to_syscall(e));
    }

    // Non-blocking connect returns EINPROGRESS after sending SYN
    if nonblock {
        return Err(SyscallError::EINPROGRESS);
    }

    // Phase 3: Blocking connect - wait for connection to complete
    // Poll the TCP state with the specified timeout
    let start_ticks = crate::time::get_ticks();
    let timeout_ticks = TCP_CONNECT_TIMEOUT_NS / 1_000_000; // Convert ns to ms (1 tick = ~1ms)

    loop {
        // Check if connection established or failed
        match socket.tcp_state() {
            Some(net::TcpState::Established) => return Ok(0),
            Some(net::TcpState::Closed) => {
                // R50-3 FIX: Clean up resources on connection refused
                net::socket_table().abort_tcp_connect(&socket);
                return Err(SyscallError::ECONNREFUSED);
            }
            None => {
                // R50-3 FIX (codex review): TCB was cleaned up by RST or error
                // Return connection refused since the connection attempt failed
                return Err(SyscallError::ECONNREFUSED);
            }
            _ => {} // Still connecting (SYN_SENT)
        }

        // Check timeout
        let elapsed = crate::time::get_ticks() - start_ticks;
        if elapsed > timeout_ticks {
            // R50-3 FIX: Clean up TCB, port binding, and 4-tuple on timeout
            // This prevents resource exhaustion from abandoned connection attempts
            net::socket_table().abort_tcp_connect(&socket);
            return Err(SyscallError::ETIMEDOUT);
        }

        // Yield to allow RX processing
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
        crate::force_reschedule();
    }
}

/// sys_sendto - Send UDP datagram (syscall 44).
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `buf` - Data buffer
/// * `len` - Data length
/// * `flags` - Send flags (MSG_DONTWAIT supported)
/// * `dest_addr` - Destination address
/// * `addrlen` - Length of destination address
///
/// # Security
/// - Verifies CapRights::WRITE
/// - Invokes LSM hook_net_send for policy check
/// - Auto-binds to ephemeral port if not bound
fn sys_sendto(
    fd: i32,
    buf: *const u8,
    len: usize,
    flags: i32,
    dest_addr: *const SockAddrIn,
    addrlen: u32,
) -> SyscallResult {
    if len == 0 {
        return Ok(0);
    }

    // Check flags
    let flag_bits = flags as u32;
    if flag_bits & !MSG_DONTWAIT != 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check WRITE right
    if !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // Determine socket type
    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;

    // Get current process context early
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // TCP: send() semantics when dest_addr is NULL (connected socket)
    if dest_addr.is_null() {
        if !is_tcp {
            return Err(SyscallError::EDESTADDRREQ);
        }

        // R51-2 FIX: Cap TCP send size pre-copy to avoid large allocations.
        // tcp_send() also enforces this limit as the canonical check point.
        if len > net::tcp::TCP_MAX_SEND_SIZE {
            return Err(SyscallError::EMSGSIZE);
        }

        // Copy payload from user space
        validate_user_ptr(buf, len)?;
        let mut data = vec![0u8; len];
        copy_from_user(&mut data, buf)?;

        // Get remote IP for transmission
        let remote_ip = socket
            .remote_ip()
            .map(net::Ipv4Addr)
            .ok_or(SyscallError::ENOTCONN)?;

        // Send via TCP (segments split at MSS boundary)
        let (bytes_sent, segments) = net::socket_table()
            .tcp_send(&socket, &ctx, cap_id, &data)
            .map_err(socket_error_to_syscall)?;

        // Transmit all TCP segments via network device
        for segment in segments {
            net::transmit_tcp_segment(remote_ip, &segment).map_err(tx_error_to_syscall)?;
        }

        return Ok(bytes_sent);
    }

    // Non-TCP with dest_addr: must be UDP
    if !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // UDP size check
    if len > UDP_MAX_PAYLOAD {
        return Err(SyscallError::EMSGSIZE);
    }

    // R48-REVIEW FIX: Check BIND right if socket is not already bound.
    // Auto-bind in sendto requires BIND capability to prevent capability bypass.
    let is_bound = socket.local_port().is_some();
    if !is_bound && !entry.rights.allows(cap::CapRights::BIND) {
        // Socket not bound and no BIND right - cannot auto-bind
        return Err(SyscallError::EACCES);
    }

    // Read destination address
    let dest = read_sockaddr_in(dest_addr, addrlen)?;
    if dest.sin_family != AF_INET as u16 {
        return Err(SyscallError::EAFNOSUPPORT);
    }
    let dst_port = dest.port();
    if dst_port == 0 {
        return Err(SyscallError::EINVAL);
    }
    let dst_ip = net::Ipv4Addr(dest.ip_bytes());

    // Copy payload from user space
    validate_user_ptr(buf, len)?;
    let mut data = vec![0u8; len];
    copy_from_user(&mut data, buf)?;

    // R48-REVIEW FIX: Source IP - use actual bound address if available.
    // If not bound, use INADDR_ANY (0.0.0.0) which send_to_udp will use
    // when auto-binding to an ephemeral port.
    let src_ip = socket
        .local_ip()
        .map(net::Ipv4Addr)
        .unwrap_or(net::Ipv4Addr([0, 0, 0, 0]));

    // Send via socket_table (includes LSM hook_net_send check)
    let datagram = net::socket_table()
        .send_to_udp(&socket, &ctx, cap_id, src_ip, dst_ip, dst_port, &data)
        .map_err(socket_error_to_syscall)?;

    // Transmit the UDP datagram via network device
    net::transmit_udp_datagram(dst_ip, &datagram).map_err(tx_error_to_syscall)?;

    Ok(len)
}

/// sys_recvfrom - Receive data from socket (syscall 45).
///
/// Supports both UDP (connectionless) and TCP (connection-oriented) sockets.
/// For TCP: use with NULL src_addr for recv() semantics.
/// For UDP: use with non-NULL src_addr to get sender info.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `buf` - Buffer for received data
/// * `len` - Buffer length
/// * `flags` - Receive flags (MSG_DONTWAIT supported)
/// * `src_addr` - Buffer for source address (optional, NULL for TCP recv)
/// * `addrlen` - Pointer to address length (in/out)
///
/// # Security
/// - Verifies CapRights::READ
/// - Invokes LSM hook_net_recv for policy check
fn sys_recvfrom(
    fd: i32,
    buf: *mut u8,
    len: usize,
    flags: i32,
    src_addr: *mut SockAddrIn,
    addrlen: *mut u32,
) -> SyscallResult {
    if len == 0 {
        return Ok(0);
    }

    // Check flags
    let flag_bits = flags as u32;
    if flag_bits & !MSG_DONTWAIT != 0 {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Check READ right
    if !entry.rights.allows(cap::CapRights::READ) {
        return Err(SyscallError::EACCES);
    }

    // Determine socket type
    let is_tcp = socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp;
    let is_udp = socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp;

    // Get current process context
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Determine timeout (0 for non-blocking, None for blocking)
    let timeout = if nonblock || (flag_bits & MSG_DONTWAIT != 0) {
        Some(0)
    } else {
        None
    };

    // TCP: recv() semantics when src_addr is NULL (connected socket)
    if is_tcp && src_addr.is_null() {
        let data = net::socket_table()
            .tcp_recv(&socket, &ctx, cap_id, len, timeout)
            .map_err(socket_error_to_syscall)?;

        let copy_len = core::cmp::min(len, data.len());
        validate_user_ptr_mut(buf, copy_len)?;
        copy_to_user(buf, &data[..copy_len])?;
        return Ok(copy_len);
    }

    // Must be UDP for recvfrom with address
    if !is_udp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // Receive via socket_table (includes LSM hook_net_recv check)
    let pkt = net::socket_table()
        .recv_from_udp(&socket, &ctx, cap_id, timeout)
        .map_err(socket_error_to_syscall)?;

    // Copy data to user space
    let copy_len = core::cmp::min(len, pkt.data.len());
    validate_user_ptr_mut(buf, copy_len)?;
    copy_to_user(buf, &pkt.data[..copy_len])?;

    // Write source address if requested
    if !src_addr.is_null() {
        let sockaddr = SockAddrIn::from_addr(pkt.src_ip.0, pkt.src_port);
        write_sockaddr_in(&sockaddr, src_addr, addrlen)?;
    }

    Ok(copy_len)
}

/// sys_shutdown - Shutdown TCP connection (syscall 48).
///
/// Implements graceful connection shutdown per RFC 793.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `how` - Shutdown mode: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
///
/// # State Transitions
/// - ESTABLISHED + SHUT_WR → FIN_WAIT_1 (sends FIN)
/// - CLOSE_WAIT + SHUT_WR → LAST_ACK (sends FIN)
///
/// # Security
/// - Verifies CapRights::WRITE for SHUT_WR/SHUT_RDWR
/// - Invokes LSM hook_net_shutdown for policy check
fn sys_shutdown(fd: i32, how: i32) -> SyscallResult {
    // Validate how parameter
    const SHUT_RD: i32 = 0;
    const SHUT_WR: i32 = 1;
    const SHUT_RDWR: i32 = 2;

    if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
        return Err(SyscallError::EINVAL);
    }

    let (cap_id, socket_id, _nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets support shutdown
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // WRITE right required for SHUT_WR or SHUT_RDWR
    if how != SHUT_RD && !entry.rights.allows(cap::CapRights::WRITE) {
        return Err(SyscallError::EACCES);
    }

    // Get current process context
    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Call tcp_shutdown
    match net::socket_table().tcp_shutdown(&socket, &ctx, cap_id, how) {
        Ok(Some(fin_segment)) => {
            // Transmit the FIN segment
            if let Some(dst_ip) = socket.remote_ip() {
                let _ = net::transmit_tcp_segment(net::Ipv4Addr(dst_ip), &fin_segment);
            }
            Ok(0)
        }
        Ok(None) => Ok(0), // SHUT_RD or FIN already sent
        Err(e) => Err(socket_error_to_syscall(e)),
    }
}

// ============================================================================
// F.2 Cgroup v2 Syscalls
// ============================================================================

/// Buffer for returning cgroup statistics to userspace.
///
/// Must match the layout expected by userspace cgroup tools.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CgroupStatsBuf {
    /// Cgroup ID
    pub id: u64,
    /// Depth in hierarchy (root = 0)
    pub depth: u32,
    /// Enabled controllers bitmap (CPU=1, MEMORY=2, PIDS=4, IO=8)
    pub controllers: u32,
    /// Current number of attached tasks
    pub nr_tasks: u64,
    /// Cumulative CPU time in nanoseconds
    pub cpu_time_ns: u64,
    /// Current memory usage in bytes
    pub memory_current: u64,
    /// Number of memory.high exceeded events
    pub memory_events_high: u64,
    /// Number of memory.max (OOM) events
    pub memory_events_max: u64,
    /// Number of pids.max exceeded events
    pub pids_events_max: u32,
    /// Padding for alignment
    _padding: u32,
    // F.2: IO controller statistics
    /// Total bytes read via block I/O
    pub io_read_bytes: u64,
    /// Total bytes written via block I/O
    pub io_write_bytes: u64,
    /// Total read I/O operations completed
    pub io_read_ios: u64,
    /// Total write I/O operations completed
    pub io_write_ios: u64,
    /// Number of times I/O was throttled due to io.max limit
    pub io_throttle_events: u64,
}

/// sys_cgroup_create - Create a child cgroup
///
/// # Arguments
/// * `parent_id` - ID of parent cgroup (0 for root)
/// * `controllers` - Bitmask of controllers to enable (CPU=1, MEMORY=2, PIDS=4)
///
/// # Returns
/// * On success: New cgroup ID (positive)
/// * On error: Negative errno
///
/// # Security
/// Requires CAP_SYS_ADMIN (or root) to create cgroups.
fn sys_cgroup_create(parent_id: u64, controllers: u32) -> Result<usize, SyscallError> {
    // Security: Only root can create cgroups
    let creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    if creds.euid != 0 {
        return Err(SyscallError::EPERM);
    }

    // Convert u32 controllers to CgroupControllers flags
    let ctrl_flags = cgroup::CgroupControllers::from_bits_truncate(controllers);
    if ctrl_flags.is_empty() {
        return Err(SyscallError::EINVAL);
    }

    match cgroup::create_cgroup(parent_id, ctrl_flags) {
        Ok(node) => Ok(node.id() as usize),
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::DepthLimit) => Err(SyscallError::ENOSPC),
        Err(cgroup::CgroupError::CgroupLimit) => Err(SyscallError::ENOSPC),
        Err(cgroup::CgroupError::ControllerDisabled) => Err(SyscallError::EINVAL),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_destroy - Delete a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of cgroup to delete
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
/// Requires CAP_SYS_ADMIN (or root). Cgroup must be empty.
fn sys_cgroup_destroy(cgroup_id: u64) -> Result<usize, SyscallError> {
    // Security: Only root can destroy cgroups
    let creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    if creds.euid != 0 {
        return Err(SyscallError::EPERM);
    }

    match cgroup::delete_cgroup(cgroup_id) {
        Ok(()) => Ok(0),
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::NotEmpty) => Err(SyscallError::EBUSY),
        Err(cgroup::CgroupError::PermissionDenied) => Err(SyscallError::EPERM),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_attach - Attach current process to a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
/// Process can migrate itself. Root can migrate any process (future extension).
fn sys_cgroup_attach(cgroup_id: u64) -> Result<usize, SyscallError> {
    let pid = crate::process::current_pid().ok_or(SyscallError::ESRCH)?;
    let process = crate::process::get_process(pid).ok_or(SyscallError::ESRCH)?;

    let old_cgroup_id = {
        let proc = process.lock();
        proc.cgroup_id
    };

    // Migrate task between cgroups
    match cgroup::migrate_task(pid as u64, old_cgroup_id, cgroup_id) {
        Ok(()) => {
            // Update PCB with new cgroup
            let mut proc = process.lock();
            proc.cgroup_id = cgroup_id;
            Ok(0)
        }
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::PidsLimitExceeded) => Err(SyscallError::EAGAIN),
        Err(cgroup::CgroupError::TaskNotAttached) => {
            // Process not in old cgroup - try direct attach to new cgroup
            if let Some(target) = cgroup::lookup_cgroup(cgroup_id) {
                match target.attach_task(pid as u64) {
                    Ok(()) => {
                        let mut proc = process.lock();
                        proc.cgroup_id = cgroup_id;
                        Ok(0)
                    }
                    Err(cgroup::CgroupError::PidsLimitExceeded) => Err(SyscallError::EAGAIN),
                    Err(_) => Err(SyscallError::EINVAL),
                }
            } else {
                Err(SyscallError::ENOENT)
            }
        }
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// Limit types for sys_cgroup_set_limit
const CGROUP_LIMIT_CPU_WEIGHT: u32 = 1;
const CGROUP_LIMIT_CPU_MAX: u32 = 2;
const CGROUP_LIMIT_MEMORY_MAX: u32 = 3;
const CGROUP_LIMIT_MEMORY_HIGH: u32 = 4;
const CGROUP_LIMIT_PIDS_MAX: u32 = 5;
const CGROUP_LIMIT_IO_MAX_BPS: u32 = 6;
const CGROUP_LIMIT_IO_MAX_IOPS: u32 = 7;

/// sys_cgroup_set_limit - Set a resource limit on a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `limit_type` - Type of limit (1=cpu_weight, 2=cpu_max, 3=memory_max, etc.)
/// * `value` - Limit value (interpretation depends on limit_type)
///
/// For cpu_max: value encodes (max_us << 32) | period_us
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
/// Requires CAP_SYS_ADMIN (or root) to set limits.
fn sys_cgroup_set_limit(cgroup_id: u64, limit_type: u32, value: u64) -> Result<usize, SyscallError> {
    // Security: Only root can set cgroup limits
    let creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    if creds.euid != 0 {
        return Err(SyscallError::EPERM);
    }

    let cgroup_node = cgroup::lookup_cgroup(cgroup_id).ok_or(SyscallError::ENOENT)?;

    let mut limits = cgroup::CgroupLimits::default();

    match limit_type {
        CGROUP_LIMIT_CPU_WEIGHT => {
            // value is the weight (1-10000)
            if value == 0 || value > 10000 {
                return Err(SyscallError::EINVAL);
            }
            limits.cpu_weight = Some(value as u32);
        }
        CGROUP_LIMIT_CPU_MAX => {
            // value encodes (max_us << 32) | period_us
            let max_us = (value >> 32) as u64;
            let period_us = (value & 0xFFFFFFFF) as u64;
            if max_us == 0 || period_us == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.cpu_max = Some((max_us, period_us));
        }
        CGROUP_LIMIT_MEMORY_MAX => {
            limits.memory_max = Some(value);
        }
        CGROUP_LIMIT_MEMORY_HIGH => {
            limits.memory_high = Some(value);
        }
        CGROUP_LIMIT_PIDS_MAX => {
            limits.pids_max = Some(value);
        }
        CGROUP_LIMIT_IO_MAX_BPS => {
            // value is bytes per second limit (0 means unlimited)
            if value == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.io_max_bytes_per_sec = Some(value);
        }
        CGROUP_LIMIT_IO_MAX_IOPS => {
            // value is IOPS limit (0 means unlimited)
            if value == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.io_max_iops_per_sec = Some(value);
        }
        _ => return Err(SyscallError::EINVAL),
    }

    match cgroup_node.set_limit(limits) {
        Ok(()) => Ok(0),
        Err(cgroup::CgroupError::ControllerDisabled) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::InvalidLimit) => Err(SyscallError::EINVAL),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_get_stats - Get cgroup statistics
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `buf` - Pointer to CgroupStatsBuf to fill
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
fn sys_cgroup_get_stats(cgroup_id: u64, buf: *mut CgroupStatsBuf) -> Result<usize, SyscallError> {
    use crate::usercopy::{copy_to_user_safe, UserAccessGuard};

    // Validate user pointer
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let buf_addr = buf as usize;
    if buf_addr < crate::usercopy::MMAP_MIN_ADDR || buf_addr >= USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    let cgroup_node = cgroup::lookup_cgroup(cgroup_id).ok_or(SyscallError::ENOENT)?;
    let stats = cgroup_node.get_stats();

    let result = CgroupStatsBuf {
        id: cgroup_node.id(),
        depth: cgroup_node.depth(),
        controllers: cgroup_node.controllers().bits(),
        nr_tasks: stats.pids_current,
        cpu_time_ns: stats.cpu_time_ns,
        memory_current: stats.memory_current,
        memory_events_high: stats.memory_events_high,
        memory_events_max: stats.memory_events_max,
        pids_events_max: stats.pids_events_max,
        _padding: 0,
        // F.2: IO controller statistics
        io_read_bytes: stats.io_read_bytes,
        io_write_bytes: stats.io_write_bytes,
        io_read_ios: stats.io_read_ios,
        io_write_ios: stats.io_write_ios,
        io_throttle_events: stats.io_throttle_events,
    };

    // Copy to userspace with SMAP protection
    unsafe {
        let _guard = UserAccessGuard::new();
        let result_bytes: [u8; core::mem::size_of::<CgroupStatsBuf>()] =
            core::mem::transmute(result);
        if copy_to_user_safe(buf as *mut u8, &result_bytes).is_err() {
            return Err(SyscallError::EFAULT);
        }
    }

    Ok(0)
}

/// 系统调用统计
pub struct SyscallStats {
    pub total_calls: u64,
    pub exit_calls: u64,
    pub fork_calls: u64,
    pub read_calls: u64,
    pub write_calls: u64,
    pub failed_calls: u64,
}

impl SyscallStats {
    pub fn new() -> Self {
        SyscallStats {
            total_calls: 0,
            exit_calls: 0,
            fork_calls: 0,
            read_calls: 0,
            write_calls: 0,
            failed_calls: 0,
        }
    }

    pub fn print(&self) {
        println!("=== Syscall Statistics ===");
        println!("Total calls:  {}", self.total_calls);
        println!("Exit calls:   {}", self.exit_calls);
        println!("Fork calls:   {}", self.fork_calls);
        println!("Read calls:   {}", self.read_calls);
        println!("Write calls:  {}", self.write_calls);
        println!("Failed calls: {}", self.failed_calls);
    }
}
