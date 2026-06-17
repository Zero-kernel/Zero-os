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
    cleanup_unscheduled_process, cleanup_zombie, create_process, create_process_in_namespace,
    current_net_ns_id, current_pid, get_process, terminate_process, terminate_self_and_halt,
    try_get_process, wait_should_abort, with_current_cap_table, ProcessId, ProcessState,
};
use cpu_local::{current_cpu, current_cpu_id, max_cpus};
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

// G.1 Observability: Per-CPU counter integration
use trace::counters::{increment_counter, TraceCounter};

// G.3 Compliance: Hardening profiles and FIPS mode
extern crate compliance;
extern crate livepatch;

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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 32] = [(); core::mem::size_of::<UserSeccompInsn>()];

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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<UserSeccompProg>()];

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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 24] = [(); core::mem::size_of::<OpenHow>()];

/// struct timeval (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<TimeVal>()];

/// struct timespec (Linux ABI)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<TimeSpec>()];

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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 325] = [(); core::mem::size_of::<UtsName>()];

/// Linux dirent64 layout for getdents64 syscall
#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // followed by name bytes + '\0'
}

// H.0.1-3: Compile-time ABI size assertion (includes 5 bytes tail padding).
const _: [(); 24] = [(); core::mem::size_of::<LinuxDirent64>()];

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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<SockAddrIn>()];

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
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

/// stdin 等待队列
///
/// 当 sys_read(fd=0) 没有数据时，进程会被加入此队列并阻塞。
/// 键盘/串口中断通过 wake_stdin_waiters() 唤醒等待者。
static STDIN_WAITERS: spin::Mutex<VecDeque<ProcessId>> = spin::Mutex::new(VecDeque::new());

/// R149-1 FIX: Deferred stdin wake flag for IRQ handlers.
///
/// Keyboard/serial IRQ handlers must NOT acquire PROCESS_TABLE or Process
/// locks (deterministic deadlock if the interrupted context holds them).
/// Instead, the IRQ handler sets this global flag and the actual wake is
/// drained in process context by `drain_deferred_stdin_wakes()`.
///
/// Global (not per-CPU) because: (a) keyboard IRQ may fire on any CPU,
/// (b) the blocked process may call stdin_finish_wait() on a different CPU,
/// (c) any CPU's reschedule_if_needed() should be able to drain the wake.
static STDIN_WAKE_PENDING: AtomicBool = AtomicBool::new(false);

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

/// R158-8 FIX: Cancel a prepared wait when data arrives on the double-check path.
/// Removes PID from STDIN_WAITERS and resets state to Ready.
fn stdin_cancel_wait() {
    if let Some(pid) = current_pid() {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut waiters = STDIN_WAITERS.lock();
            waiters.retain(|&p| p != pid);

            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                }
            }
        });
    }
}

/// 完成等待（第二阶段）
///
/// 在 prepare_to_wait 后调用，实际让出 CPU。
/// 如果没有其他进程可调度，会进入 HLT 循环等待中断唤醒。
fn stdin_finish_wait() -> bool {
    // 尝试切换到其他进程
    crate::force_reschedule();

    // R171-F3: true if a pending kill ended the wait (the caller returns EINTR).
    let mut aborted = false;

    // 如果 force_reschedule 返回，说明没有其他进程可运行
    // 当前进程已被标记为 Blocked，需要等待中断（键盘/串口）唤醒
    // 进入 HLT 循环，避免忙等消耗 CPU
    loop {
        // R149-1 FIX: Drain deferred stdin wakes before checking state.
        // This handles the case where the system is idle (no other runnable
        // processes) and force_reschedule returned without switching — the
        // only progress path is draining the flag here after HLT returns.
        drain_deferred_stdin_wakes();

        // 必须在关中断状态下检查进程状态，避免与中断处理程序竞争
        // enable_and_hlt 后中断是开启的，需要先关闭再检查
        let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
            // R171-F3 FIX: a pending kill interrupts the blocking stdin read.
            // Dequeue from STDIN_WAITERS + mark Ready, flag aborted, and break so
            // the caller returns EINTR instead of HLT-looping unkillably.
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) {
                    STDIN_WAITERS.lock().retain(|&p| p != pid);
                    if let Some(proc_arc) = get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.state = ProcessState::Ready;
                        }
                    }
                    aborted = true;
                    return false;
                }
            }
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

    aborted
}

/// 唤醒一个等待 stdin 的进程 (IRQ-safe fast path).
///
/// 由键盘/串口中断处理器调用。
/// R149-1 FIX: No locks acquired — just sets a deferred flag. The actual
/// wake (which requires PROCESS_TABLE + Process locks) is performed by
/// `drain_deferred_stdin_wakes()` in process context.
pub fn wake_stdin_waiters() {
    STDIN_WAKE_PENDING.store(true, AtomicOrdering::Release);
}

/// R149-1 FIX: Drain deferred stdin wakeups in safe (non-IRQ) process context.
///
/// Called from:
/// - `scheduler_hook::reschedule_if_needed()` on syscall return
/// - `stdin_finish_wait()` HLT loop (handles idle-system case)
///
/// Uses wake_one semantics to avoid thundering herd.
pub fn drain_deferred_stdin_wakes() {
    // Fast path: no wake pending
    if !STDIN_WAKE_PENDING.swap(false, AtomicOrdering::Acquire) {
        return;
    }

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

use alloc::collections::BTreeMap;

/// Per-queue waiter tracking for socket blocking operations.
///
/// Uses the WaitQueue address as a unique identifier. Each queue maintains
/// a FIFO list of waiting process IDs with optional timeout deadlines.
struct SocketWaiters {
    /// Map from queue address to list of `(ProcessId, generation, deadline_ticks)`.
    /// Deadline is None for indefinite wait, Some(ticks) for timeout.
    ///
    /// R165-9 FIX: each waiter carries the monotonic `generation` of the
    /// `wait()` call that enqueued it (mirrors the IPC WaitQueue R165-4 fix).
    waiters: BTreeMap<usize, VecDeque<(ProcessId, u64, Option<u64>)>>,
    /// Track timed-out waiters to report correct WaitOutcome.
    ///
    /// When a waiter times out (via check_timeouts or inline check), we record
    /// `(pid -> generation)` here. When wait() returns, it consumes this marker
    /// to distinguish TimedOut from Woken.
    ///
    /// R165-9 FIX: keyed by `(pid, generation)` rather than PID alone. A PID
    /// recycled to a different process within the ~tick window cannot consume a
    /// stale timeout marker, because its `wait()` runs with a fresh generation
    /// that will not match the old marker.
    timed_out: BTreeMap<ProcessId, u64>,
    /// Monotonic generation counter, advanced on each `wait()` registration.
    /// All access is under the `SOCKET_WAITERS` lock, so a plain counter
    /// suffices (no atomics needed).
    next_generation: u64,
}

impl SocketWaiters {
    const fn new() -> Self {
        SocketWaiters {
            waiters: BTreeMap::new(),
            timed_out: BTreeMap::new(),
            next_generation: 1,
        }
    }

    /// R165-9 FIX: Allocate a fresh, unique generation for a `wait()` call.
    fn alloc_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        generation
    }

    /// Add the current process to a wait queue, or refresh its generation and
    /// deadline if it is already queued.
    ///
    /// R165-9 FIX: on a duplicate (spurious re-entry of `wait()` for the same
    /// PID) we REFRESH the existing entry's generation/deadline to this wait's
    /// values, so a subsequent timeout is attributed to the current wait and a
    /// legitimate timeout is never dropped (mirrors sync.rs R165-4).
    fn add_or_refresh_waiter(
        &mut self,
        queue_addr: usize,
        pid: ProcessId,
        generation: u64,
        deadline: Option<u64>,
    ) {
        let queue = self.waiters.entry(queue_addr).or_insert_with(VecDeque::new);
        if let Some(entry) = queue.iter_mut().find(|(p, _, _)| *p == pid) {
            entry.1 = generation;
            entry.2 = deadline;
        } else {
            queue.push_back((pid, generation, deadline));
        }
    }

    /// Remove a specific process from a queue (on wakeup or timeout).
    ///
    /// R165-9 FIX: when `expected` is `Some(gen)`, only the entry whose
    /// generation matches is removed — a newer wait by the same PID is left
    /// intact. Returns true iff an entry was removed.
    fn remove_waiter(&mut self, queue_addr: usize, pid: ProcessId, expected: Option<u64>) -> bool {
        if let Some(queue) = self.waiters.get_mut(&queue_addr) {
            if let Some(pos) = queue
                .iter()
                .position(|(p, g, _)| *p == pid && expected.map_or(true, |e| *g == e))
            {
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
    fn mark_timed_out(&mut self, pid: ProcessId, generation: u64) {
        self.timed_out.insert(pid, generation);
    }

    /// Consume the timeout marker for a process on an EXACT generation match.
    ///
    /// R165-9 FIX: a stored generation strictly less than `expected` is a stale
    /// leftover from an earlier wait by this PID — drop it without reporting a
    /// timeout. A greater stored generation is impossible (one PID cannot have
    /// two concurrent waits). Returns true only on an exact `(pid, gen)` match.
    fn consume_timeout(&mut self, pid: ProcessId, expected: u64) -> bool {
        if let Some(&stored) = self.timed_out.get(&pid) {
            if stored <= expected {
                self.timed_out.remove(&pid);
                return stored == expected;
            }
        }
        false
    }

    /// Wake one waiter from a queue (FIFO order).
    fn wake_one(&mut self, queue_addr: usize) -> Option<ProcessId> {
        if let Some(queue) = self.waiters.get_mut(&queue_addr) {
            while let Some((pid, _, _)) = queue.pop_front() {
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
            while let Some((pid, _, _)) = queue.pop_front() {
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
        // Each entry: (queue_addr, pid, generation, is_timeout vs is_exited)
        let mut expired: [Option<(usize, ProcessId, u64, bool)>; MAX_TIMEOUTS_PER_TICK] =
            [None; MAX_TIMEOUTS_PER_TICK];
        let mut count = 0;

        // Collect expired or exited waiters
        for (&queue_addr, queue) in self.waiters.iter() {
            for &(pid, generation, deadline) in queue.iter() {
                if count >= MAX_TIMEOUTS_PER_TICK {
                    break; // Will catch remaining on next tick
                }
                let is_timeout = deadline.map(|dl| current_ticks >= dl).unwrap_or(false);
                // R171-G5-1 FIX: never block PROCESS_TABLE in this IRQ tick scan.
                // A contended table (try_get_process == None) is NOT "exited" — it
                // defers: the entry is left untouched and re-evaluated next tick.
                let is_exited = matches!(try_get_process(pid), Some(None));
                if is_timeout || is_exited {
                    expired[count] = Some((queue_addr, pid, generation, is_timeout));
                    count += 1;
                }
            }
        }

        // Wake expired waiters and drop entries for dead processes
        let mut queues_to_clean: [Option<usize>; MAX_TIMEOUTS_PER_TICK] =
            [None; MAX_TIMEOUTS_PER_TICK];
        let mut clean_count = 0;

        for entry in expired.iter().take(count).flatten() {
            let (queue_addr, pid, generation, is_timeout) = *entry;

            if let Some(queue) = self.waiters.get_mut(&queue_addr) {
                // R165-9 FIX: act only on the EXACT (pid, generation) we recorded
                // above, so a newer wait by the same PID is left undisturbed.
                if queue.iter().any(|(p, g, _)| *p == pid && *g == generation) {
                    // R155-2 FIX: try_lock BEFORE removing from queue.
                    // If contended, skip — the entry stays with its original
                    // deadline and will be retried on the next tick.
                    //
                    // R165-9 FIX: only record a timeout when THIS call performs the
                    // Blocked->Ready transition. If the process exited, its lock is
                    // contended, or a normal wake already readied it, we must not
                    // leave a stale timeout marker (mirrors sync.rs timeout_wake).
                    let mut record_timeout = false;
                    // R171-G5-1 FIX: tri-state try_get_process — never block
                    // PROCESS_TABLE in IRQ context.
                    match try_get_process(pid) {
                        // Contended table: defer this waiter (leave it queued with
                        // its original deadline; retried next tick). Do NOT remove.
                        None => continue,
                        // Process gone — fall through to remove membership with
                        // record_timeout == false (R155-12: no stale timeout flag).
                        Some(None) => {}
                        Some(Some(proc_arc)) => {
                            if let Some(mut proc) = proc_arc.try_lock() {
                                if proc.state == ProcessState::Blocked {
                                    proc.state = ProcessState::Ready;
                                    record_timeout = is_timeout;
                                }
                            } else {
                                continue;
                            }
                        }
                    }

                    // Lock succeeded (or process gone) — now remove our exact entry
                    if let Some(pos) = queue
                        .iter()
                        .position(|(p, g, _)| *p == pid && *g == generation)
                    {
                        queue.remove(pos);
                    }

                    if record_timeout {
                        self.timed_out.insert(pid, generation);
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
            // R171-G5-1 FIX: prune only entries we can DEFINITIVELY confirm gone
            // (Some(None)); a contended table (None) is kept and reconsidered at
            // the next prune — never block PROCESS_TABLE in this IRQ scan.
            self.timed_out
                .retain(|pid, _| !matches!(try_get_process(*pid), Some(None)));
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
        // R154-10 FIX: Use checked_add to prevent overflow when user supplies
        // huge timeout values (e.g. u64::MAX). The previous (ns + NS_PER_TICK - 1)
        // expression wraps around for ns > u64::MAX - NS_PER_TICK + 1.
        const NS_PER_TICK: u64 = 1_000_000;
        let deadline = timeout_ns.map(|ns| {
            let current = crate::get_ticks();
            let ticks = ns.checked_add(NS_PER_TICK - 1).unwrap_or(u64::MAX) / NS_PER_TICK; // Round up (overflow-safe)
            current.saturating_add(ticks)
        });

        // Queue address as unique identifier
        let queue_addr = queue as *const _ as usize;

        // Phase 1: Add to wait queue and mark blocked (with interrupts disabled)
        // R152-2 FIX: Consume wake token *after* registering the waiter,
        // while interrupts are disabled and SOCKET_WAITERS is locked.
        // This closes the missed-wakeup race where wake_one() can run between
        // a pre-check and waiter registration.
        let (my_gen, immediate) = x86_64::instructions::interrupts::without_interrupts(|| {
            let mut waiters = SOCKET_WAITERS.lock();

            // R165-9 FIX: allocate this wait's unique generation under the lock,
            // then register (or, on spurious re-entry for the same PID, refresh
            // the existing entry's generation + deadline to this wait's values).
            let my_gen = waiters.alloc_generation();
            waiters.add_or_refresh_waiter(queue_addr, pid, my_gen, deadline);

            // R152-2 FIX: Check for pending wake AFTER registration.
            // If a wake arrived before we registered, consume the token and
            // remove ourselves — no need to block.
            if queue.try_consume_wakeup() {
                waiters.remove_waiter(queue_addr, pid, Some(my_gen));
                return (my_gen, Some(net::WaitOutcome::Woken));
            }

            // Mark process as blocked
            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                proc.state = ProcessState::Blocked;
            }
            (my_gen, None)
        });

        if let Some(outcome) = immediate {
            return outcome;
        }

        // Phase 2: Yield CPU and wait for wakeup
        crate::force_reschedule();

        // Phase 3: HLT loop waiting for interrupt (if no other process to run)
        // R171-F3: track whether a pending kill (not a normal wake/timeout/close)
        // ended the wait, so we can report Interrupted (EINTR) below.
        let mut aborted = false;
        loop {
            let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
                // R171-F3 FIX: a pending kill must interrupt the blocking
                // accept/recv FIRST. A kill flips Blocked->Ready, so the
                // `state != Blocked` check below would otherwise return a spurious
                // "Woken" and the caller (sys_accept / recv) would re-park forever.
                // Dequeue our exact (pid, generation), mark Ready, flag aborted.
                if wait_should_abort(pid) {
                    SOCKET_WAITERS.lock().remove_waiter(queue_addr, pid, Some(my_gen));
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().state = ProcessState::Ready;
                    }
                    aborted = true;
                    return false;
                }
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
                    // Remove from wait queue (R165-9: our exact generation)
                    SOCKET_WAITERS.lock().remove_waiter(queue_addr, pid, Some(my_gen));
                    // Mark ready so we can return
                    if let Some(proc_arc) = get_process(pid) {
                        proc_arc.lock().state = ProcessState::Ready;
                    }
                    return false;
                }

                // Check timeout
                if let Some(dl) = deadline {
                    if crate::get_ticks() >= dl {
                        // Timeout expired - mark and remove.
                        // R165-9 FIX: only record the timeout if we actually
                        // removed OUR (pid, generation) entry, so we never stamp a
                        // timeout over a concurrent wake/refresh of a newer wait.
                        let mut waiters = SOCKET_WAITERS.lock();
                        if waiters.remove_waiter(queue_addr, pid, Some(my_gen)) {
                            waiters.mark_timed_out(pid, my_gen);
                        }
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

        // R171-F3 FIX: a pending-kill abort takes precedence over a coincident
        // close/timeout/wake — consume any stale timeout marker for THIS wait and
        // report Interrupted so the caller returns EINTR instead of re-parking.
        if aborted {
            SOCKET_WAITERS.lock().consume_timeout(pid, my_gen);
            return net::WaitOutcome::Interrupted;
        }

        // Determine outcome using timeout marker (fixes race between timer and wake)
        if queue.is_closed() {
            // Consume any stale timeout marker for THIS wait (R165-9: exact gen)
            SOCKET_WAITERS.lock().consume_timeout(pid, my_gen);
            return net::WaitOutcome::Closed;
        }

        // Check if we were marked as timed out (by timer callback or inline check)
        if SOCKET_WAITERS.lock().consume_timeout(pid, my_gen) {
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

/// J2-8: Kernel implementation of the per-cgroup ephemeral-port budget hooks.
///
/// Bridges the `net` crate (which cannot depend on `kernel_core::cgroup` — that
/// would be a dependency cycle) to `process::current_cgroup_id` +
/// `cgroup::try_charge_ports` / `cgroup::uncharge_ports`.
struct KernelCgroupPortHooks;

impl net::CgroupPortHooks for KernelCgroupPortHooks {
    fn current_cgroup_id(&self) -> Option<u64> {
        // Returns None for non-process (kernel-thread / RX) callers; the net
        // side then treats the charge as cgid 0 (root / exempt).
        crate::process::current_cgroup_id()
    }

    fn try_charge_ports(&self, cgid: u64, n: u64) -> Result<(), ()> {
        crate::cgroup::try_charge_ports(cgid, n).map_err(|_| ())
    }

    fn uncharge_ports(&self, cgid: u64, n: u64) {
        crate::cgroup::uncharge_ports(cgid, n);
    }
}

/// Static instance of KernelCgroupPortHooks for registration.
static KERNEL_CGROUP_PORT_HOOKS: KernelCgroupPortHooks = KernelCgroupPortHooks;

/// J2-8: Register the per-cgroup ephemeral-port budget hooks with the net crate.
///
/// Called during kernel initialization alongside `register_socket_hooks`, after
/// the process module and cgroup registry are ready.
pub fn register_cgroup_port_hooks() {
    net::register_cgroup_port_hooks(&KERNEL_CGROUP_PORT_HOOKS);
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

/// R130-1 FIX: Maximum number of mmap regions per process.
///
/// Bounds the per-process `mmap_regions` BTreeMap to prevent unbounded kernel
/// heap growth from unprivileged syscalls (e.g., millions of PROT_NONE mmaps).
/// Matches Linux's default `/proc/sys/vm/max_map_count` (65536).
///
/// R165-14: `pub(crate)` so fork.rs can re-assert the bound before cloning the
/// parent's region map into the child (see fork::fork_inner).
pub(crate) const MAX_MAP_COUNT: usize = 65536;

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
    // R104-4: Arithmetic overflow (POSIX value 75)
    EOVERFLOW = -75,       // 值溢出 (value too large for data type)
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

/// R102-6 FIX: Execute a closure with the current syscall frame.
///
/// Prevents the frame reference from escaping the active syscall window.
/// The internal callback still returns `&'static SyscallFrame` for ABI
/// compatibility, but this wrapper ensures callers cannot store the reference.
///
/// # Arguments
///
/// * `f` - Closure receiving `&SyscallFrame`, executed only if a frame is active.
///
/// # Returns
///
/// `Some(R)` with the closure's return value, or `None` if no frame is active.
pub fn with_current_syscall_frame<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&SyscallFrame) -> R,
{
    get_current_syscall_frame().map(f)
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
/// R114-2 FIX: Added `max_bytes` parameter to enforce kernel-side memory budget.
/// The callback MUST stop collecting entries once the estimated serialized size
/// (header + name + NUL + alignment) exceeds `max_bytes`. This prevents unbounded
/// kernel heap allocation from large directories, which could trigger OOM panic.
/// 参数: (fd, max_bytes) -> 返回实际读取的目录项列表
pub type VfsReaddirCallback = fn(i32, usize) -> Result<alloc::vec::Vec<DirEntry>, SyscallError>;

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

// H.0.1-3: Compile-time ABI size assertion (112 = 2 implicit 4-byte padding gaps).
const _: [(); 112] = [(); core::mem::size_of::<VfsStat>()];

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

/// sys_exec 允许的最大 ELF 映像大小（512 KiB）
///
/// R151-1 FIX: Reduced from 16 MiB to 512 KiB. The kernel heap is only 1 MiB
/// (HEAP_SIZE); the previous 16 MiB limit allowed infallible vec! allocation to
/// exhaust the heap and trigger the alloc_error_handler panic — a deterministic
/// kernel crash from unprivileged userspace.
const MAX_EXEC_IMAGE_SIZE: usize = 512 * 1024;

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

    // R101-7 FIX: Reject pointers below MMAP_MIN_ADDR to prevent NULL dereference
    // exploitation. If a kernel NULL pointer dereference bug exists and a user can
    // map page 0 through a path that bypasses sys_mmap(), validate_user_ptr() would
    // otherwise accept the low address. This provides defense-in-depth matching the
    // MMAP_MIN_ADDR enforcement already in sys_mmap() and usercopy::is_user_range().
    if start < crate::usercopy::MMAP_MIN_ADDR {
        return Err(SyscallError::EFAULT);
    }

    // 地址回绕检查
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::EFAULT),
    };

    // 用户空间边界检查：确保整个缓冲区都在用户空间内
    // R154-I5 FIX: This uses `>` (end > USER_SPACE_TOP) while usercopy::validate_user_range()
    // uses `<` (end < USER_SPACE_TOP). The difference is intentional:
    //   - validate_user_ptr: `end > USER_SPACE_TOP` rejects end == TOP+1 but allows end == TOP.
    //     Since len >= 1 is enforced above, end == TOP means the last byte is at TOP-1 (valid).
    //   - validate_user_range: `end < USER_SPACE_TOP` is stricter, rejecting end == TOP.
    //     This is conservative for usercopy where USER_SPACE_TOP itself is never a valid byte.
    // Both are safe: the canonical hole starts at USER_SPACE_TOP, so the strictest correct
    // bound is `end <= USER_SPACE_TOP` (which `end > TOP` implements via negation).
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
// R164-3 FIX: Fallible String construction from &str. The infallible
// .to_string() panics under OOM via alloc_error_handler. All path
// syscalls (open, stat, openat, fstatat) use this instead.
#[inline]
fn try_str_to_string(s: &str) -> Result<String, SyscallError> {
    let mut owned = String::new();
    owned.try_reserve_exact(s.len()).map_err(|_| SyscallError::ENOMEM)?;
    owned.push_str(s);
    Ok(owned)
}

/// 逐字节读取直到遇到 NUL 终止符，限制最大长度防止恶意无限字符串。
fn copy_user_cstring(ptr: *const u8) -> Result<Vec<u8>, SyscallError> {
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R160-2 FIX: Pre-reserve capacity for the cstring buffer. The old code
    // used infallible push() per byte, up to MAX_ARG_STRLEN (4096) iterations.
    // Under OOM, any push could trigger alloc_error_handler → kernel panic.
    let mut buf = Vec::new();
    buf.try_reserve(256).map_err(|_| SyscallError::ENOMEM)?;

    for i in 0..=MAX_ARG_STRLEN {
        let mut byte = [0u8; 1];
        let src_addr = (ptr as usize).wrapping_add(i) as *const u8;
        crate::usercopy::copy_from_user_safe(&mut byte, src_addr)
            .map_err(|_| SyscallError::EFAULT)?;

        if byte[0] == 0 {
            return Ok(buf);
        }
        if buf.try_reserve(1).is_err() {
            return Err(SyscallError::ENOMEM);
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
    // R160-2 FIX: Fallible allocation for argument list. The old infallible
    // push could panic under OOM with up to MAX_ARG_COUNT (256) entries.
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;

    for idx in 0..MAX_ARG_COUNT {
        let entry_addr = base.checked_add(idx * word).ok_or(SyscallError::EFAULT)?;

        let mut raw_ptr = [0u8; core::mem::size_of::<usize>()];
        crate::usercopy::copy_from_user_safe(&mut raw_ptr, entry_addr as *const u8)
            .map_err(|_| SyscallError::EFAULT)?;
        let entry = usize::from_ne_bytes(raw_ptr) as *const u8;

        if entry.is_null() {
            break;
        }

        let s = copy_user_cstring(entry)?;
        total = total
            .checked_add(s.len() + 1)
            .ok_or(SyscallError::E2BIG)?;
        if total > MAX_ARG_TOTAL {
            return Err(SyscallError::E2BIG);
        }

        items.try_reserve(1).map_err(|_| SyscallError::ENOMEM)?;
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
    klog_always!("Syscall handler initialized");
    klog_always!("  Supported syscalls: exit, fork, getpid, read, write, yield");
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
        // R107-5 FIX: Socket ID counter overflow (u64 exhaustion) maps to ENOSPC
        net::SocketError::IdExhausted => SyscallError::ENOSPC,
        net::SocketError::Lsm(e) => lsm_error_to_syscall(e),
        net::SocketError::NoMemory => SyscallError::ENOMEM,
        // R171-F3: a blocking socket op interrupted by a pending kill -> EINTR.
        net::SocketError::Interrupted => SyscallError::EINTR,
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
///
/// # H.0.9 Restriction
///
/// This function uses `cleanup_unscheduled_process()` which skips cpuset/cgroup
/// teardown. It is ONLY safe to call on children created via `create_process()`
/// that were never passed through `fork_inner()` (i.e., the CLONE_VM main path
/// in sys_clone). For fork-based children where fork_inner ran (cpuset joined,
/// cgroup attached), callers must inline the LSM check and use
/// `request_process_exit()` + scheduler enqueue instead.
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
        // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process to
        // avoid cgroup/cpuset/IPC detach on never-joined subsystems.
        cleanup_unscheduled_process(child_pid);
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

    // G.1: Count every syscall entry (per-CPU, lock-free, IRQ-safe)
    increment_counter(TraceCounter::SyscallEntry, 1);

    // R154-I1 FIX: Early-exit if this thread is marked for death by exit_group().
    // Without this, a pending_kill thread can execute one full syscall before the
    // flag is consumed at the normal syscall-return check point.
    // We use take_pending_process_exit() (which atomically clears the flag) and
    // terminate_self_and_halt() so the thread actually dies rather than looping
    // on EINTR indefinitely.
    if let Some(pid) = crate::process::current_pid() {
        if let Some(exit_code) = crate::process::take_pending_process_exit(pid) {
            increment_counter(TraceCounter::SyscallExit, 1);
            terminate_self_and_halt(pid, exit_code);
        }
    }

    // Evaluate seccomp/pledge filters before dispatch
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    let verdict = crate::process::evaluate_seccomp(syscall_num, &args);

    match verdict.action {
        seccomp::SeccompAction::Kill => {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // R25-4 + R39-2 FIX: Kill process with SIGSYS semantics and NEVER return
            //
            // SECURITY: After terminating the process, we must not return to userspace.
            // The process state is now invalid (PCB cleaned up, memory potentially freed).
            // Returning would cause UAF and complete seccomp bypass.
            let pid = match crate::process::current_pid() {
                Some(pid) => pid,
                None => {
                    // No current PID — should not happen. Force halt as fallback.
                    crate::scheduler_hook::force_reschedule();
                    loop {
                        core::hint::spin_loop();
                    }
                }
            };

            if let Some(creds) = crate::current_credentials() {
                seccomp::notify_violation(
                    pid as u32,
                    creds.uid,
                    creds.gid,
                    syscall_num,
                    &verdict,
                    timestamp,
                );
            }

            // R117-1 FIX: Use centralized terminate_self_and_halt() which disables
            // interrupts and switches to boot CR3 before halting, preventing timer
            // IRQ UAF on the zombie's stack/CR3.
            terminate_self_and_halt(pid, 128 + 31);
        }
        seccomp::SeccompAction::Trap => {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // R25-4 + R39-2 FIX: Trap treated as fatal until SIGSYS delivery exists
            //
            // SECURITY: Same rationale as Kill - process is terminated, never return.
            let pid = match crate::process::current_pid() {
                Some(pid) => pid,
                None => {
                    crate::scheduler_hook::force_reschedule();
                    loop {
                        core::hint::spin_loop();
                    }
                }
            };

            if let Some(creds) = crate::current_credentials() {
                seccomp::notify_violation(
                    pid as u32,
                    creds.uid,
                    creds.gid,
                    syscall_num,
                    &verdict,
                    timestamp,
                );
            }

            // R117-1 FIX: Use centralized terminate_self_and_halt().
            terminate_self_and_halt(pid, 128 + 31);
        }
        seccomp::SeccompAction::Errno(e) => {
            increment_counter(TraceCounter::SyscallDenied, 1);
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
            increment_counter(TraceCounter::SyscallExit, 1);
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
    // R142-4 FIX: Defense-in-depth assertion — a user syscall without LSM context
    // means current_pid() or current_credentials() returned None, which is a kernel
    // bug (SYSCALL requires Ring 3 → requires a running process with valid PID).
    debug_assert!(
        lsm_ctx.is_some(),
        "R142-4: LSM context missing for user syscall — kernel bug"
    );
    if let Some(ref ctx) = lsm_ctx {
        if let Err(err) = lsm::hook_syscall_enter(ctx) {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // LSM denied the syscall - call exit hook and return error
            let errno = lsm_error_to_syscall(err);
            let ret = errno.as_i64();
            let _ = lsm::hook_syscall_exit(ctx, ret as isize);
            increment_counter(TraceCounter::SyscallExit, 1);
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
        // M2-1 SLICE-2 INVARIANT (vfork / syscall 58 scope boundary):
        // There is intentionally NO `58 =>` arm here. vfork is in the default
        // seccomp allowlist (seccomp/lib.rs:279, seccomp/types.rs:1131 under
        // PledgePromises::PROC) but has no dispatch, so syscall 58 falls through
        // to `_ => Err(ENOSYS)` (line ~2491). vfork is therefore ENOSYS and
        // CHARGE-NEUTRAL today: it creates no process and no address space, so
        // it can never pin/charge cgroup memory and cannot strand a mem_pinned
        // residual (no path exists). If a FUTURE slice wires vfork to real Linux
        // semantics (child borrows the parent's MmState until exec/exit), the
        // handler MUST route memory accounting through exactly ONE of:
        //   (a) fork_inner / sys_fork  -> independent MmState, so the aggregated
        //       fork charge at fork.rs:240 (try_charge_memory(parent_cgroup_id,
        //       fork_charge_bytes)) applies and telescopes via the child's exit
        //       uncharge; OR
        //   (b) the CLONE_VM shared-MmState path (see line ~3151:
        //       `if flags & CLONE_VM != 0 { (parent_space, true) }`) which shares
        //       the parent AS and performs NO independent fork charge.
        // A vfork handler MUST NOT introduce a THIRD, uncharged AS-creating path:
        // a shared-MmState process that independently fork-charges would double
        // the charge (the FA-09 over-count / permanent-undeletability direction),
        // and an independent-MmState process that skips the fork charge would
        // strand the child's exit uncharge into a saturating under-count.
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

        // F.2 Cgroup v2 syscalls (Zero-OS specific, 500-504, 513, 516)
        500 => sys_cgroup_create(arg0 as u64, arg1 as u32),
        501 => sys_cgroup_destroy(arg0 as u64),
        502 => sys_cgroup_attach(arg0 as u64),
        503 => sys_cgroup_set_limit(arg0 as u64, arg1 as u32, arg2),
        // 504 is the FROZEN v1 stats ABI (2-arg, writes the 104-byte v1 prefix, returns 0).
        504 => sys_cgroup_get_stats(arg0 as u64, arg1 as *mut CgroupStatsBuf),
        513 => sys_cgroup_delegate(arg0 as u64, arg1 as u64),
        // J.2: v2 stats with statx-style size negotiation (writes min(buf_len, sizeof)).
        516 => sys_cgroup_get_stats2(arg0 as u64, arg1 as *mut CgroupStatsBuf, arg2 as usize),

        // G.3 Compliance syscalls (Zero-OS specific, 505-508)
        505 => sys_compliance_status(arg0 as *mut ComplianceStatusBuf),
        506 => sys_fips_enable(),
        507 => sys_compliance_query_algo(arg0 as u32),
        508 => sys_audit_export(arg0 as *mut u8, arg1 as usize, arg2 as u64, arg3 as usize),

        // G.2 Live Patching syscalls (Zero-OS specific, 509-512, 514-515)
        509 => sys_kpatch_load(arg0 as usize, arg1 as usize),
        510 => sys_kpatch_enable(arg0 as u64),
        511 => sys_kpatch_disable(arg0 as u64),
        // R104-5 FIX: Wire kpatch_unload to complete the livepatch syscall family
        512 => sys_kpatch_unload(arg0 as u64),
        // P1-4: Batch enable/disable with topological dependency ordering
        514 => sys_kpatch_enable_all(),
        515 => sys_kpatch_disable_all(),

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

    // R115-1 FIX: Honor cross-CPU exit requests at syscall return.
    //
    // exit_group() may request sibling threads to exit while they are running on
    // other CPUs. Those threads cannot be terminated remotely (UAF risk), so they
    // check the pending-kill flag here — the earliest safe point where the thread
    // is guaranteed to not be in the middle of a kernel operation.
    if let Some(pid) = current_pid() {
        if let Some(exit_code) = crate::process::take_pending_process_exit(pid) {
            // R117-1 FIX: Use centralized terminate_self_and_halt().
            terminate_self_and_halt(pid, exit_code);
        }
    }

    // 在返回用户态前检查是否需要调度
    // 这是定时器中断设置的 NEED_RESCHED 标志的主要消费点
    crate::reschedule_if_needed();

    // G.1: Count successful syscall exit (after all processing complete)
    increment_counter(TraceCounter::SyscallExit, 1);

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
        // R115-1 FIX: Removed duplicate hook_task_exit() call.
        // terminate_process() is the sole call site for the LSM exit hook,
        // preventing double-fire in audit logs.
        // R104-2 FIX: Gate to prevent leaking PID in release builds.
        klog_always!("Process {} exited with code {}", pid, exit_code);

        // R117-1 FIX: Use centralized terminate_self_and_halt() which disables
        // interrupts and switches to boot CR3 before halting.
        terminate_self_and_halt(pid, exit_code);
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_exit_group - 终止进程组
///
/// R101-9 FIX: Properly terminates all threads sharing the same tgid.
///
/// R115-1 FIX: Cross-CPU safe termination. Sibling threads that may be running
/// on other CPUs are NOT terminated directly (which would cause UAF on their
/// kernel stack, FPU state, and cgroup accounting). Instead, a pending-kill
/// flag is set and the sibling self-terminates at the next syscall return.
/// The calling thread terminates itself directly (same-CPU, always safe).
fn sys_exit_group(exit_code: i32) -> SyscallResult {
    if let Some(pid) = current_pid() {
        // Determine our thread group ID and publish the group-exiting flag.
        let tgid = {
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            // R153-3 FIX: Publish thread-group "exiting" flag before marking
            // siblings. This prevents concurrent sys_clone(CLONE_THREAD) from
            // slipping in between this point and the atomic marking scan below.
            proc.thread_group_exiting.store(true, core::sync::atomic::Ordering::Release);
            proc.tgid
        };

        // R152-10 FIX: Atomically mark all siblings under PROCESS_TABLE lock.
        // This prevents a concurrent sys_clone(CLONE_THREAD) from creating a
        // new thread that escapes the exit_group scan. The old snapshot-then-mark
        // pattern had a TOCTOU window where new threads could be created between
        // the snapshot and the marking loop.
        let marked = crate::process::request_exit_group_atomic(pid, tgid, exit_code);

        // R115-1 FIX: Removed duplicate hook_task_exit() call.
        // terminate_process() is the sole call site for the LSM exit hook.
        // Now terminate ourselves directly (same CPU, always safe).
        kprintln!(
            "Process {} (tgid={}) exit_group with code {} ({} sibling task(s) marked for exit)",
            pid, tgid, exit_code, marked
        );

        // R117-1 FIX: Use centralized terminate_self_and_halt().
        terminate_self_and_halt(pid, exit_code);
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_fork - 创建子进程
///
/// R101-10 FIX: Warns (debug) when fork is called from a multi-threaded process.
/// POSIX specifies that fork() in a multi-threaded process only duplicates the
/// calling thread, but shared resources (mutexes, file locks) may be in
/// inconsistent states in the child.
fn sys_fork() -> SyscallResult {
    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;

    // R101-10 FIX: Check if the calling process has active sibling threads.
    // If so, the forked child will inherit the address space with potentially
    // locked mutexes that will never be unlocked (the other threads don't exist
    // in the child). Warn in debug mode; in the future, consider returning ENOSYS.
    {
        let parent = parent_arc.lock();
        let parent_tgid = parent.tgid;
        let parent_is_thread_leader = parent.pid == parent.tgid;
        drop(parent);

        // Only check if process is part of a thread group (tgid matches a leader)
        if parent_is_thread_leader {
            // R165-15 FIX: process_table_snapshot() is now fallible (returns None
            // on OOM instead of aborting). This is a best-effort diagnostic, so on
            // allocation failure we simply skip the warning (sibling_count = 0).
            let sibling_count = crate::process::process_table_snapshot()
                .map(|table| {
                    table
                        .iter()
                        .filter(|&&p| p != parent_pid)
                        .filter(|&&p| {
                            if let Some(proc_arc) = get_process(p) {
                                let proc = proc_arc.lock();
                                proc.tgid == parent_tgid
                                    && proc.is_thread
                                    && proc.state != crate::process::ProcessState::Terminated
                            } else {
                                false
                            }
                        })
                        .count()
                })
                .unwrap_or(0);

            if sibling_count > 0 {
                kprintln!(
                    "WARNING: fork() called from multi-threaded process (pid={}, {} active threads). \
                     Child may deadlock on inherited locked mutexes.",
                    parent_pid, sibling_count
                );
            }
        }
    }

    // 调用真正的 fork 实现（包含 COW 支持）
    match crate::fork::sys_fork() {
        Ok(child_pid) => {
            // LSM hook: check if policy allows this fork
            //
            // H.0.9 FIX: Cannot use enforce_lsm_task_fork() here because it calls
            // cleanup_unscheduled_process() which skips cpuset/cgroup teardown.
            // fork::sys_fork() ran fork_inner which joined cpuset and attached cgroup.
            // On LSM denial, use terminate_process() + cleanup_zombie() for full teardown.
            // This is safe because the child was never scheduled (no SMP race).
            {
                let parent_arc_lsm = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;
                let child_arc_lsm = get_process(child_pid).ok_or(SyscallError::ESRCH)?;
                let (parent_ctx, child_ctx) = {
                    let parent = parent_arc_lsm.lock();
                    let child = child_arc_lsm.lock();
                    (lsm_process_ctx_from(&parent), lsm_process_ctx_from(&child))
                };
                if let Err(err) = lsm::hook_task_fork(&parent_ctx, &child_ctx) {
                    if let Some(parent) = get_process(parent_pid) {
                        parent.lock().children.retain(|&pid| pid != child_pid);
                    }
                    // H.0.9: Child was fully forked (cpuset/cgroup joined) but never
                    // scheduled. terminate_process + cleanup_zombie gives full teardown
                    // including cpuset task_left and cgroup detach. Safe because no CPU
                    // has ever run this process (no SMP race on PCB).
                    terminate_process(child_pid, 128 + crate::signal::Signal::SIGKILL.as_i32());
                    cleanup_zombie(child_pid);
                    return Err(lsm_error_to_syscall(err));
                }
            }

            // F.1 PID Namespace: Translate child's global PID to parent's namespace view
            //
            // Linux semantics: fork() returns the child's PID as seen from the parent's
            // namespace. This is the same PID used by wait(), kill(), etc.
            //
            // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
            // Falling back to global PID would break PID namespace isolation, allowing
            // processes to observe kernel-internal PIDs across namespace boundaries.
            //
            // H.0.9 FIX: PID translation is performed BEFORE scheduler enqueue. On
            // translation failure, the child is still unscheduled, so we can safely
            // use terminate_process() + cleanup_zombie() for synchronous full teardown
            // (no zombie accumulation, no cpuset/cgroup leak).
            let parent_view_pid = {
                let parent = parent_arc.lock();
                let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
                if let Some(ns) = owning_ns {
                    crate::pid_namespace::pid_in_namespace(&ns, child_pid)
                } else {
                    Some(child_pid)
                }
            };

            let parent_view_pid = match parent_view_pid {
                Some(pid) => pid,
                None => {
                    // H.0.9: Child is fully forked (cpuset/cgroup joined) but never
                    // scheduled. terminate_process + cleanup_zombie gives full teardown.
                    if let Some(parent) = get_process(parent_pid) {
                        parent.lock().children.retain(|&p| p != child_pid);
                    }
                    terminate_process(child_pid, 128 + crate::signal::Signal::SIGKILL.as_i32());
                    cleanup_zombie(child_pid);
                    return Err(SyscallError::EFAULT);
                }
            };

            // R101-3 FIX: Notify scheduler about the new child process.
            //
            // Previously, sys_fork() did not call notify_scheduler_add_process(),
            // causing forked children to exist in the process table but never be
            // added to the scheduler's run queue. This made fork() a resource leak
            // DoS vector — each call consumed a PID, kernel stack, and page tables
            // that were never reclaimed because the child never ran to completion.
            //
            // H.0.9: Moved AFTER PID translation so translation failure can use
            // synchronous terminate_process + cleanup_zombie (child not yet enqueued).
            if let Some(child_arc) = get_process(child_pid) {
                crate::process::notify_scheduler_add_process(child_arc);
            }

            Ok(parent_view_pid)
        }
        Err(e) => {
            // F.2: Map ForkError to appropriate syscall error
            use crate::fork::ForkError;
            match e {
                ForkError::CgroupPidsLimitExceeded
                | ForkError::CgroupFilesLimitExceeded
                | ForkError::MmapTransientState => Err(SyscallError::EAGAIN),
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
    // R101-2 FIX: Gate clone debug prints behind debug_assertions to prevent
    // leaking user stack/instruction pointers and TLS base addresses.
    kprintln!(
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
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
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
            kprintln!(
                "[sys_clone] CLONE_THREAD rejected: NULL stack would share parent's user stack"
            );
            return Err(SyscallError::EINVAL);
        }

        // R153-3 FIX: Reject CLONE_THREAD if the thread group is exiting.
        // The shared thread_group_exiting flag is set by exit_group() BEFORE
        // the per-thread pending_kill scan, closing the TOCTOU window where
        // the caller hasn't been marked yet. Also check pending_kill as a
        // fallback for single-thread exit paths.
        {
            let parent = parent_arc.lock();
            if parent.thread_group_exiting.load(core::sync::atomic::Ordering::Acquire)
                || parent.pending_kill.load(core::sync::atomic::Ordering::Acquire)
            {
                return Err(SyscallError::EINVAL);
            }
        }
    }

    // F.1: CLONE_NEWPID cannot be combined with CLONE_THREAD
    // Creating a thread in a new PID namespace makes no sense - threads share PID space
    if flags & CLONE_NEWPID != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWPID cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // R161-16 FIX: When CLONE_NEWUSER is present alongside other namespace flags,
    // skip privilege checks for those flags. Linux processes CLONE_NEWUSER first,
    // granting capabilities within the new user namespace. We match this behavior
    // by deferring the check — the new user namespace grants CAP_SYS_ADMIN within it.
    let creating_user_ns = flags & CLONE_NEWUSER != 0;

    // R156-2 FIX: CLONE_NEWPID requires CAP_SYS_ADMIN or root, matching
    // the gates on CLONE_NEWNS/NEWIPC/NEWNET. Previously ungated, allowing
    // unprivileged PID namespace creation and quota exhaustion.
    if flags & CLONE_NEWPID != 0 && !creating_user_ns {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWPID denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWNS cannot be combined with CLONE_THREAD
    // Mount namespace is per-process; threads must share the same mount namespace
    if flags & CLONE_NEWNS != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWNS cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNS requires CAP_SYS_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNS != 0 && !creating_user_ns {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() instead of namespace-local euid==0
        // for consistency with sys_setns and cgroup governance gates.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWNS denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWIPC cannot be combined with CLONE_THREAD
    // IPC namespace is per-process; threads must share the same IPC namespace
    if flags & CLONE_NEWIPC != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWIPC cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWIPC requires CAP_SYS_ADMIN or root
    if flags & CLONE_NEWIPC != 0 && !creating_user_ns {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() for consistency with sys_setns.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWIPC denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWNET cannot be combined with CLONE_THREAD
    // Network namespace is per-process; threads must share the same network namespace
    if flags & CLONE_NEWNET != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWNET cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNET requires CAP_NET_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNET != 0 && !creating_user_ns {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() for consistency with sys_setns.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWNET denied: requires CAP_NET_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWUSER cannot be combined with CLONE_THREAD
    // User namespace is per-process; threads must share the same user namespace
    if flags & CLONE_NEWUSER != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWUSER cannot be combined with CLONE_THREAD");
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
        parent_user_memory_space, // H.3 KPTI: user CR3 root for CLONE_VM sharing
        parent_tgid,
        parent_thread_group_exiting, // R153-3 FIX: shared exiting flag
        parent_mm_arc,  // D3-ARC-MM-SHARED: shared mm Arc for CLONE_VM
        parent_name,
        parent_priority,
        parent_cgroup_id,     // R123-2 FIX: for cgroup attachment after create_process
        parent_cpuset_id,     // R123-2 FIX: for cpuset inheritance
        parent_allowed_cpus,  // R123-2 FIX: for cpuset CPU mask inheritance
        _parent_context,
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
        parent_fd_table_snapshot,    // R133-5 FIX: fd_table snapshot under parent lock
        parent_cloexec_snapshot,     // R169-L1 FIX: cloexec_fds snapshot under parent lock
        parent_cap_table_clone,      // R133-5 FIX: cap_table clone under parent lock
    ) = {
        let mut parent = parent_arc.lock();
        // 始终从 MSR 同步 fs_base 到 PCB
        // 这确保即使进程通过 wrfsbase 指令修改了 TLS（绕过 arch_prctl），
        // 子进程也能继承正确的 TLS 基址
        if current_fs_base != 0 {
            parent.fs_base = current_fs_base;
        }

        // R133-5 FIX: Snapshot fd_table and cap_table under the parent lock
        // to avoid child→parent lock order inversion later. Previously,
        // the child lock block re-acquired parent.lock() for CLONE_FILES
        // and cap_table cloning, violating the parent→child lock order
        // used in enforce_lsm_task_fork().
        // R158-7 FIX (LOW): Fallible fd_table snapshot (bounded by MAX_FD).
        let fd_snapshot: Vec<(i32, crate::process::FileDescriptor)> =
            if flags & CLONE_FILES != 0 {
                let mut snap = Vec::new();
                if snap.try_reserve_exact(parent.fd_table.len()).is_err() {
                    return Err(SyscallError::ENOMEM);
                }
                for (&fd, desc) in parent.fd_table.iter() {
                    snap.push((fd, desc.clone_box()));
                }
                snap
            } else {
                Vec::new()
            };

        // R169-L1 FIX: Snapshot cloexec_fds under the parent lock too (fallibly,
        // matching fd_snapshot), so a CLONE_FILES child inherits the parent's
        // close-on-exec marks instead of silently losing them (a latent CLOEXEC
        // bypass that diverges from fork.rs). Reading parent.cloexec_fds at the
        // child-setup site would re-acquire the parent lock = R133-5 child->parent
        // inversion; the bounded set is rebuilt into the child OUTSIDE the lock.
        let cloexec_snapshot: Vec<i32> = if flags & CLONE_FILES != 0 {
            let mut snap = Vec::new();
            if snap.try_reserve_exact(parent.cloexec_fds.len()).is_err() {
                return Err(SyscallError::ENOMEM);
            }
            snap.extend(parent.cloexec_fds.iter().copied());
            snap
        } else {
            Vec::new()
        };

        let cap_clone = if flags & CLONE_THREAD != 0 {
            // Thread: share parent's cap_table (via Arc)
            parent.cap_table.clone()
        } else {
            // R25-8 FIX: Non-thread cases must inherit and filter CLOFORK entries
            // R161-4 FIX: Fallible clone + Arc wrapping
            Arc::new(parent.cap_table.try_clone_for_fork().map_err(|_| SyscallError::ENOMEM)?)
        };

        // D3-ARC-MM-SHARED: Clone mm Arc for CLONE_VM sharing.
        // R162-5 FIX: Removed dead mmap_snapshot code. Under D3-ARC-MM-SHARED,
        // CLONE_VM shares the Arc directly and fork returns early from sys_clone.
        // The mmap_snapshot BTreeMap was never used but performed up to 65536
        // infallible BTreeMap node allocations under the parent lock.
        let parent_mm_arc_clone = Arc::clone(&parent.mm);

        (
            parent.memory_space,
            parent.user_memory_space, // H.3 KPTI
            parent.tgid,
            parent.thread_group_exiting.clone(), // R153-3 FIX
            parent_mm_arc_clone, // D3-ARC-MM-SHARED
            parent.name.clone(),
            parent.priority,
            parent.cgroup_id,     // R123-2 FIX
            parent.cpuset_id,     // R123-2 FIX
            parent.allowed_cpus,  // R123-2 FIX
            parent.context,
            parent.user_stack,
            parent.fs_base,
            parent.gs_base,
            parent.credentials.clone(), // R39-3 FIX: 获取凭证 Arc
            parent.umask,
            parent.seccomp_state.try_clone().map_err(|_| SyscallError::ENOMEM)?,
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
            fd_snapshot,                         // R133-5 FIX: fd_table snapshot
            cloexec_snapshot,                    // R169-L1 FIX: cloexec_fds snapshot
            cap_clone,                           // R133-5 FIX: cap_table clone
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
                //
                // H.0.9 FIX: Cannot use enforce_lsm_task_fork() here because it calls
                // cleanup_unscheduled_process() which skips cpuset/cgroup teardown.
                // fork::sys_fork() ran fork_inner (cpuset joined, cgroup attached).
                // On LSM denial, use terminate_process + cleanup_zombie for full
                // teardown. Safe because the child was never scheduled (no SMP race).
                {
                    let parent_arc_lsm = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;
                    let child_arc_lsm = get_process(child_pid).ok_or(SyscallError::ESRCH)?;
                    let (parent_ctx, child_ctx) = {
                        let p = parent_arc_lsm.lock();
                        let c = child_arc_lsm.lock();
                        (lsm_process_ctx_from(&p), lsm_process_ctx_from(&c))
                    };
                    if let Err(err) = lsm::hook_task_fork(&parent_ctx, &child_ctx) {
                        if let Some(parent) = get_process(parent_pid) {
                            parent.lock().children.retain(|&pid| pid != child_pid);
                        }
                        // H.0.9: Child was fully forked (cpuset/cgroup joined) but never
                        // scheduled. terminate_process + cleanup_zombie gives full teardown.
                        terminate_process(child_pid, 128 + crate::signal::Signal::SIGKILL.as_i32());
                        cleanup_zombie(child_pid);
                        return Err(lsm_error_to_syscall(err));
                    }
                }

                // F.1: Translate to parent's namespace view before returning
                //
                // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
                //
                // H.0.9 FIX: Translation failure must not leak the child. fork::sys_fork()
                // ran fork_inner (cpuset joined, cgroup attached) but did NOT add to
                // scheduler. Use terminate_process + cleanup_zombie for synchronous
                // full teardown (no zombie, no cpuset/cgroup leak).
                let parent_view_pid = {
                    let parent = parent_arc.lock();
                    let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
                    if let Some(ns) = owning_ns {
                        crate::pid_namespace::pid_in_namespace(&ns, child_pid)
                    } else {
                        Some(child_pid)
                    }
                };
                match parent_view_pid {
                    Some(pid) => {
                        // H.0.9: fork::sys_fork() does not add to scheduler; enqueue now.
                        if let Some(child_arc) = get_process(child_pid) {
                            crate::process::notify_scheduler_add_process(child_arc);
                        }
                        return Ok(pid);
                    }
                    None => {
                        // Child was fully forked (cpuset/cgroup joined) but never scheduled.
                        // H.0.9: Use terminate_process + cleanup_zombie for full teardown.
                        if let Some(parent) = get_process(parent_pid) {
                            parent.lock().children.retain(|&pid| pid != child_pid);
                        }
                        terminate_process(child_pid, 128 + crate::signal::Signal::SIGKILL.as_i32());
                        cleanup_zombie(child_pid);
                        return Err(SyscallError::EFAULT);
                    }
                }
            }
            Err(e) => {
                // R122-1 FIX: Map MmapTransientState to EAGAIN (retriable)
                // to keep behavior consistent with the sys_fork() path.
                use crate::fork::ForkError;
                return Err(match e {
                    ForkError::CgroupPidsLimitExceeded
                    | ForkError::CgroupFilesLimitExceeded
                    | ForkError::MmapTransientState => SyscallError::EAGAIN,
                    _ => SyscallError::ENOMEM,
                });
            }
        }
    };

    // R160-14 FIX: Truncate child name to prevent unbounded growth from
    // deeply nested clone chains. The old infallible format!() could
    // accumulate ~230KB names and panic under OOM.
    let suffix = if flags & CLONE_THREAD != 0 { "-thread" } else { "-clone" };
    let max_name = 256;
    let child_name = if parent_name.len() + suffix.len() > max_name {
        let mut name = String::new();
        if name.try_reserve(max_name).is_ok() {
            let truncated = &parent_name[..max_name.saturating_sub(suffix.len())];
            name.push_str(truncated);
            name.push_str(suffix);
        }
        name
    } else {
        let mut name = String::new();
        if name.try_reserve(parent_name.len() + suffix.len()).is_err() {
            return Err(SyscallError::ENOMEM);
        }
        name.push_str(&parent_name);
        name.push_str(suffix);
        name
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

                klog!(Info,
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
                klog!(Error, "[sys_clone] Failed to create mount namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(Error, "[sys_clone] Failed to create mount namespace: {:?}", e);
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
                klog!(Info,
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
                klog!(Error, "[sys_clone] Failed to create IPC namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::ipc_namespace::IpcNsError::MaxNamespaces) => {
                klog!(Error, "[sys_clone] Failed to create IPC namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(Error, "[sys_clone] Failed to create IPC namespace: {:?}", e);
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
                klog!(Info,
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
                klog!(Error, "[sys_clone] Failed to create network namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::net_namespace::NetNsError::MaxNamespaces) => {
                klog!(Error, "[sys_clone] Failed to create network namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(Error, "[sys_clone] Failed to create network namespace: {:?}", e);
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
                klog!(Info,
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
                klog!(Error, "[sys_clone] Failed to create user namespace: max depth exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(crate::user_namespace::UserNsError::MaxNamespaces) => {
                klog!(Error, "[sys_clone] Failed to create user namespace: max namespaces exceeded");
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(Error, "[sys_clone] Failed to create user namespace: {:?}", e);
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
                // R104-2 FIX: Gate diagnostic println behind debug_assertions.
                kprintln!("[sys_clone] Failed to create PID namespace: {:?}", e);
                match e {
                    crate::pid_namespace::PidNamespaceError::MaxDepthExceeded => SyscallError::EAGAIN,
                    // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
                    crate::pid_namespace::PidNamespaceError::MaxNamespaces => SyscallError::EAGAIN,
                    _ => SyscallError::ENOMEM,
                }
            })?;
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
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
            // R152-12 FIX: Drop child_arc before cleanup so namespace Arc refcount
            // reaches zero promptly, allowing PidNamespace::drop to decrement PID_NS_COUNT.
            drop(child_arc);
            // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
            // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            // R103-L2 FIX: Gate diagnostic println behind debug_assertions.
            // In release builds this leaks internal PID and seccomp race state.
            kprintln!(
                "sys_clone: rejecting CLONE_VM during seccomp installation (pid={})",
                parent_pid
            );
            return Err(SyscallError::EBUSY);
        }

        // 设置线程标识
        child.tid = child_pid; // tid == pid (Linux 语义)
        if flags & CLONE_THREAD != 0 {
            // R26-3 FIX: Reject thread creation if parent is installing seccomp filter
            // R163-13 FIX: Re-check the live flag (not just snapshot) after
            // create_process, closing the TOCTOU window where sys_seccomp
            // sets the flag between snapshot and this check.
            let live_seccomp_installing = get_process(parent_pid)
                .map(|p| p.lock().seccomp_installing)
                .unwrap_or(false);
            if parent_seccomp_installing || live_seccomp_installing {
                // Clean up: terminate the child process we just created
                child.state = ProcessState::Terminated;
                drop(child);
                // R152-12 FIX: Drop child_arc before cleanup for prompt namespace counter release
                drop(child_arc);
                // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
                // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::EBUSY);
            }
            child.tgid = parent_tgid; // 加入父进程的线程组
            child.is_thread = true;
            child.thread_group_exiting = parent_thread_group_exiting.clone(); // R153-3 FIX

            // R153-3 FIX: After setting child.tgid, re-check the shared
            // thread_group_exiting flag. exit_group() may have started while
            // sys_clone was in progress, and the atomic scan may have missed
            // this child (it had default tgid at insert time). The shared flag
            // is set BEFORE the scan, so checking it here is race-free.
            //
            // R154-13 FIX: Return EINTR instead of marking pending_exit_code=0.
            // The previous code set exit code to 0 regardless of the actual
            // exit_group code, which is incorrect. Since the group is already
            // exiting, the cleanest approach is to abort the clone entirely —
            // the child never needs to run.
            if parent_thread_group_exiting.load(core::sync::atomic::Ordering::Acquire) {
                child.state = ProcessState::Terminated;
                drop(child);
                drop(child_arc);
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::EINTR);
            }
        } else {
            child.tgid = child_pid; // 新线程组
            child.is_thread = false;
        }

        // 设置地址空间
        child.memory_space = child_space;
        if is_shared_space {
            // H.3 KPTI: CLONE_VM shares both kernel and user CR3 roots.
            // Threads in the same address space use the same KPTI shadow PML4.
            child.user_memory_space = parent_user_memory_space;

            // D3-ARC-MM-SHARED: CLONE_VM shares the same MmState via Arc.
            // All CLONE_VM siblings point to the same Arc<Mutex<MmState>>,
            // eliminating the need for sync_vm_siblings_* functions and
            // reconcile_clone_vm_mmap_regions(). The child's default MmState
            // (created by create_process) is dropped and replaced.
            child.mm = Arc::clone(&parent_mm_arc);
        }

        // 从当前 syscall 帧构建子进程上下文
        // 使用 syscall 帧而非 parent.context，因为后者是上次调度时的状态
        // R102-6 FIX: Use closure-based API to prevent syscall frame reference escape.
        let frame_applied = with_current_syscall_frame(|frame| {
            // R101-2 FIX: Gate SyscallFrame debug print behind debug_assertions
            kprintln!(
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
        });

        // R103-1 FIX (fail-closed): If the syscall frame is unavailable (cleared by
        // a preemptive context switch racing switch_context's gs:[frame_ptr]=0 reset),
        // we MUST NOT fall back to `parent.context`.  That snapshot may contain ring-0
        // CS/SS, a stale kernel RSP, or state from a different scheduling epoch — any
        // of which would crash or escalate privilege once the child is scheduled.
        //
        // Instead, terminate the child and return EBUSY so the caller can retry.
        if frame_applied.is_none() {
            kprintln!(
                "sys_clone: ABORT - syscall frame not available, refusing stale context (pid={})",
                child_pid
            );
            child.state = ProcessState::Terminated;
            child.memory_space = 0; // Do not free shared address space
            drop(child);
            // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
            // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EBUSY);
        }

        // R102-10 FIX: Gate register/address dump behind debug_assertions.
        // Leaks child RIP/RSP which defeats userspace ASLR.
        kprintln!(
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
                // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
                // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::EINVAL);
            }
            child.fs_base = tls;
        } else {
            child.fs_base = parent_fs_base;
        }
        child.gs_base = parent_gs_base;

        // R101-2 FIX: Gate TLS debug print behind debug_assertions
        kprintln!(
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

        // R133-5 FIX: Use pre-captured fd_table snapshot instead of re-acquiring
        // parent lock (which would create child→parent lock order inversion).
        if flags & CLONE_FILES != 0 {
            for (fd, desc) in parent_fd_table_snapshot {
                child.fd_table.insert(fd, desc);
            }
            // R169-L1 FIX: Inherit the close-on-exec marks captured under the
            // parent lock. The rebuild is bounded by MAX_FD and runs OUTSIDE the
            // parent lock, so the infallible BTreeSet insert cannot panic while a
            // foreign lock is held. Matches fork.rs, closing the CLOEXEC-bypass
            // parity gap (VD-03) where a CLONE_FILES child silently lost CLOEXEC.
            for fd in parent_cloexec_snapshot {
                child.cloexec_fds.insert(fd);
            }
        }

        // R133-5 FIX: Use pre-captured cap_table clone instead of re-acquiring
        // parent lock. See snapshot above (under parent lock block).
        child.cap_table = parent_cap_table_clone;

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

    // D3-ARC-MM-SHARED: reconcile_clone_vm_mmap_regions is no longer needed.
    // CLONE_VM children share the same Arc<Mutex<MmState>> as the parent,
    // so all updates are automatically visible to all siblings.

    // F.1 PID Namespace: Translate child's global PID to parent's namespace view
    //
    // Linux semantics: clone() returns the child's PID as seen from the parent's
    // namespace. This is the same PID the parent will use for kill(), waitpid(), etc.
    //
    // For processes in the root namespace, this is the same as the global PID.
    // For processes in child namespaces, the parent sees a different PID.
    //
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
    // H.0.9 FIX: Translation failure must clean up the unscheduled child.
    let parent_view_pid = {
        let parent = parent_arc.lock();
        let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
        if let Some(ns) = owning_ns {
            crate::pid_namespace::pid_in_namespace(&ns, child_pid)
        } else {
            // No namespace chain (shouldn't happen), fall back to global PID
            Some(child_pid)
        }
    };
    let parent_view_pid = match parent_view_pid {
        Some(pid) => pid,
        None => {
            // Child was created via create_process() and never scheduled.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EFAULT);
        }
    };

    // F.1 PID Namespace: Get child's own namespace-local PID for CLONE_CHILD_SETTID
    //
    // CLONE_CHILD_SETTID writes the TID the child sees for itself.
    // This is the child's PID in its owning namespace (the deepest namespace).
    // With CLONE_NEWPID, the child's owning namespace is a new child namespace,
    // where it is PID 1 (the init process of that namespace).
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
    // H.0.9 FIX: Translation failure must clean up the unscheduled child.
    let child_view_pid = {
        let child = child_arc.lock();
        crate::pid_namespace::pid_in_owning_namespace(&child.pid_ns_chain)
    };
    let child_view_pid = match child_view_pid {
        Some(pid) => pid,
        None => {
            // Child was created via create_process() and never scheduled.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EFAULT);
        }
    };

    // R104-3 FIX: Move LSM check BEFORE user memory writes to prevent observable
    // side effects when policy denies the clone. Previously, copy_to_user wrote the
    // child TID to user memory before the LSM gate, creating a side channel. Also,
    // copy_to_user failure (EFAULT) returned immediately without cleaning up the
    // fully-constructed child process, leaking PID/kernel-stack/address-space.
    //
    // LSM hook: check if policy allows this fork/clone
    // Must be BEFORE user memory writes and scheduler notification
    enforce_lsm_task_fork(parent_pid, child_pid)?;

    // R123-2 FIX: Propagate cgroup + cpuset membership for sys_clone tasks.
    //
    // create_process() initializes cgroup_id=0 (root). Without explicit
    // attachment, CLONE_THREAD tasks bypass pids.max, memory.max, and cpu.max
    // — a container escape via resource exhaustion. The fork path (fork.rs:73-148)
    // handles this correctly; this brings sys_clone to parity.
    //
    // Must be AFTER enforce_lsm_task_fork() because that helper uses
    // cleanup_unscheduled_process() which skips cgroup/cpuset teardown.
    // We attach here so rollback paths below can detach symmetrically.
    //
    // R149-4 FIX: For CLONE_VM, the early parent_cgroup_id snapshot (captured
    // under parent lock at line ~2802) may be stale — cgroup migration could
    // have changed the parent's cgroup_id between snapshot and here.  By this
    // point, child.memory_space is set (line ~3195), making share_count > 1,
    // which blocks further migration via R148-5.  Re-read the parent's
    // cgroup_id now to get the stable, post-migration value.
    let parent_cgroup_id = if is_shared_space {
        get_process(parent_pid)
            .map(|p| p.lock().cgroup_id)
            .unwrap_or(parent_cgroup_id)
    } else {
        parent_cgroup_id
    };
    if !crate::cgroup::check_fork_allowed(parent_cgroup_id) {
        if let Some(parent) = get_process(parent_pid) {
            parent.lock().children.retain(|&p| p != child_pid);
        }
        cleanup_unscheduled_process(child_pid);
        return Err(SyscallError::EAGAIN);
    }

    {
        let mut child = child_arc.lock();
        child.cgroup_id = parent_cgroup_id;
        child.cpuset_id = parent_cpuset_id;
        child.allowed_cpus = parent_allowed_cpus;
    }

    if let Some(cgroup) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
        if cgroup.attach_task(child_pid as u64).is_err() {
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
    }

    // E.5 Cpuset: update task count after successful cgroup attach.
    crate::process::notify_cpuset_task_joined(parent_cpuset_id);

    // J2-7: per-cgroup FD budget — batch-charge the child's copied fds. Only
    // CLONE_FILES populates the child fd_table (deep copy); otherwise it is empty
    // (count 0, a no-op). Charge to the child's now-attached cgroup. On failure,
    // mirror the cgroup-attach rollback exactly (detach cgroup + cpuset, drop the
    // child); later copy_to_user arms route through cleanup_unscheduled_process →
    // free_process_resources, which uncharges fds_charged_count (set below).
    let child_fd_count = {
        let child = child_arc.lock();
        child.fd_table.len() as u64
    };
    if child_fd_count > 0 {
        if crate::cgroup::try_charge_fds(parent_cgroup_id, child_fd_count).is_err() {
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
        child_arc.lock().fds_charged_count = child_fd_count;
    }

    // 写入 parent_tid (F.1: use parent's view of child's PID)
    if flags & CLONE_PARENT_SETTID != 0 {
        let tid_bytes = (parent_view_pid as i32).to_ne_bytes();
        if let Err(e) = copy_to_user(parent_tid as *mut u8, &tid_bytes) {
            // R104-3 FIX: Clean up child process on copy_to_user failure to prevent
            // PID / kernel-stack / address-space leak.
            // R123-2 FIX: Child is now attached to cgroup + cpuset; roll back
            // those subsystems before cleanup_unscheduled_process().
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(e);
        }
    }

    // 写入 child_tid（在共享地址空间中，子进程会看到此值）
    // F.1: use child's own namespace-local PID (not parent's view)
    //
    // With CLONE_NEWPID, parent sees child as e.g. PID 5, but child sees itself as PID 1.
    // The child uses this value for futex operations, robust_list, etc., so it must match
    // what gettid() returns to the child.
    if flags & CLONE_CHILD_SETTID != 0 {
        let tid_bytes = (child_view_pid as i32).to_ne_bytes();
        if let Err(e) = copy_to_user(child_tid as *mut u8, &tid_bytes) {
            // R104-3 FIX: Clean up child process on copy_to_user failure.
            // R123-2 FIX: Child is now attached to cgroup + cpuset; roll back
            // those subsystems before cleanup_unscheduled_process().
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(e);
        }
    }

    // 将子进程添加到调度器（通过回调，避免循环依赖）
    if let Some(child_arc) = get_process(child_pid) {
        crate::process::notify_scheduler_add_process(child_arc);
    }

    // R101-2 FIX: Gate clone completion debug print behind debug_assertions.
    // Leaks global child PID and clone flags.
    kprintln!(
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
        activate_memory_space, address_space_share_count, current_pid, free_address_space,
        get_process, thread_group_size, ProcessState,
    };

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R33-1 FIX: Refuse exec while other threads share this address space.
    // Calling exec in a multithreaded process would free the page tables while
    // sibling threads are still executing, causing UAF/memory corruption.
    // Linux behavior: exec in multithreaded process kills other threads first,
    // but that requires complex thread group handling. For now, reject with EBUSY.
    let (tgid, current_memory_space) = {
        let proc = process.lock();
        (proc.tgid, proc.memory_space)
    };
    let thread_count = thread_group_size(tgid);
    if thread_count > 1 {
        kprintln!(
            "sys_exec: refusing exec in multithreaded process (tgid={}, threads={})",
            tgid,
            thread_count
        );
        return Err(SyscallError::EBUSY);
    }

    // R118-1 FIX: Refuse exec when other tasks share this address space (CLONE_VM).
    //
    // thread_group_size(tgid) only counts CLONE_THREAD siblings (same tgid).
    // A process created via CLONE_VM without CLONE_THREAD has a different tgid
    // but shares the same memory_space.  If exec freed the old page tables,
    // that CLONE_VM sibling would still reference the freed CR3 → UAF.
    //
    // R136-1 FIX: address_space_share_count() now counts ALL non-Terminated
    // processes (including Zombies) that share the same memory_space. A Zombie
    // retains its memory_space reference until reaped by cleanup_zombie(), so
    // it must be counted to prevent double-free of CR3 page tables.
    let share_count = address_space_share_count(current_memory_space);
    if share_count > 1 {
        kprintln!(
            "sys_exec: refusing exec with {} CLONE_VM sibling(s) sharing address space (cr3=0x{:x})",
            share_count - 1,
            current_memory_space
        );
        return Err(SyscallError::EBUSY);
    }

    // 验证参数：非空、合理大小
    if image.is_null() || image_len == 0 {
        return Err(SyscallError::EINVAL);
    }
    if image_len > MAX_EXEC_IMAGE_SIZE {
        kprintln!(
            "sys_exec: ELF size {} exceeds limit {}",
            image_len, MAX_EXEC_IMAGE_SIZE
        );
        return Err(SyscallError::E2BIG);
    }

    // 【关键】在切换 CR3 前将用户数据复制到内核堆
    // 切换地址空间后原用户指针将失效
    // R151-1 FIX: Use fallible allocation to prevent kernel panic on OOM.
    // The global alloc_error_handler panics; try_reserve_exact returns Err instead.
    let mut elf_data: Vec<u8> = Vec::new();
    elf_data
        .try_reserve_exact(image_len)
        .map_err(|_| SyscallError::ENOMEM)?;
    elf_data.resize(image_len, 0);
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

    // H.3 KPTI: User PML4 creation is deferred until AFTER load_elf() and stack
    // setup populate user-space page table entries. create_kpti_user_pml4() snapshots
    // PML4[0..255], so it must run after all user mappings (code, data, BSS, stack
    // at PML4[255]) are established. See the "Phase 4: KPTI" block below.

    // 保存旧地址空间以便失败时恢复或成功时释放
    // R149-3 FIX: Capture cgroup_id under process lock once. This single
    // snapshot is used for both load_elf() charging and ExecSpaceGuard
    // rollback, eliminating the TOCTOU where concurrent cgroup migration
    // could cause the guard to uncharge a different cgroup than was charged.
    // R171 M2-1 SLICE-1 FIX: a RAII guard that clears `exec_in_progress` on EVERY
    // exit from sys_exec after the snapshot below (success commit OR any rollback).
    // Declared BEFORE `ExecSpaceGuard` so it drops AFTER the guard's rollback
    // uncharge — i.e. migration stays blocked through the entire exec window
    // including the rollback path. Clears under the Process lock (the only mutator).
    struct ExecInProgressGuard {
        process: Arc<spin::Mutex<crate::process::Process>>,
    }
    impl Drop for ExecInProgressGuard {
        fn drop(&mut self) {
            self.process.lock().exec_in_progress = false;
        }
    }

    let (old_memory_space, old_user_memory_space, exec_cgroup_id) = {
        let mut proc = process.lock();
        // R171 M2-1 SLICE-1 FIX: arm the migration block under the Process lock,
        // BEFORE the lock is dropped for load_elf's lock-dropped charge window. A
        // concurrent cgroup migration now sees this set and retries (EAGAIN/EBUSY)
        // instead of snapshotting compute_cgroup_charged_bytes mid-charge and
        // stranding the in-flight exec charge on `exec_cgroup_id`.
        proc.exec_in_progress = true;
        proc.mm.lock().exec_pending_bytes = 0; // Clear any stale value
        (proc.memory_space, proc.user_memory_space, proc.cgroup_id)
    };
    // Armed: from here every sys_exec exit clears the flag (no gap — the next
    // statements cannot early-return before this guard exists).
    let _exec_progress_guard = ExecInProgressGuard {
        process: process.clone(),
    };

    // S-7 fix: RAII guard to rollback address space on error
    //
    // After switching CR3, any error must restore the old address space
    // and free the new one. This guard ensures automatic rollback.
    // R118-I1 FIX: ExecSpaceGuard now tracks new_user_space so that KPTI user
    // PML4 frames are freed on rollback (previously leaked on exec failure).
    struct ExecSpaceGuard {
        /// R149-3 FIX: Process handle for clearing exec_pending_bytes and
        /// re-reading cgroup_id on rollback (migration may have moved the
        /// charge to a different cgroup).
        process: Arc<spin::Mutex<crate::process::Process>>,
        old_space: usize,
        old_user_space: usize,
        new_space: usize,
        new_user_space: usize,
        /// R125-1 FIX: Cgroup to uncharge on rollback (may be overridden by
        /// re-read in Drop if migration occurred).
        cgroup_id: cgroup::CgroupId,
        /// R125-1 FIX: Total bytes charged by load_elf() (segments + stack).
        charged_bytes: u64,
        committed: bool,
    }

    impl ExecSpaceGuard {
        fn new(
            process: Arc<spin::Mutex<crate::process::Process>>,
            old_space: usize,
            old_user_space: usize,
            new_space: usize,
        ) -> Self {
            Self {
                process,
                old_space,
                old_user_space,
                new_space,
                new_user_space: 0,
                cgroup_id: 0,
                charged_bytes: 0,
                committed: false,
            }
        }

        /// R118-I1 FIX: Track KPTI user PML4 for rollback cleanup.
        fn set_new_user_space(&mut self, user_space: usize) {
            self.new_user_space = user_space;
        }

        /// R125-1 FIX: Record cgroup charges made by load_elf() so that
        /// drop() can uncharge them if exec fails after load_elf() succeeds.
        fn set_cgroup_charge(&mut self, cgroup_id: cgroup::CgroupId, charged_bytes: u64) {
            self.cgroup_id = cgroup_id;
            self.charged_bytes = charged_bytes;
        }

        /// Mark the exec as successful, preventing rollback on drop
        fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for ExecSpaceGuard {
        fn drop(&mut self) {
            if !self.committed {
                // R149-3 FIX: Clear exec_pending_bytes and re-read cgroup_id
                // under lock. If cgroup migration occurred after load_elf()
                // charged exec_cgroup_id, the charge was transferred to the
                // new cgroup by migrate_memory_charges(). We must uncharge
                // the current (post-migration) cgroup_id, not the stale one.
                if self.charged_bytes > 0 {
                    let rollback_cgroup_id = {
                        let proc = self.process.lock();
                        proc.mm.lock().exec_pending_bytes = 0;
                        proc.cgroup_id
                    };
                    // Use fresh cgroup_id from process (post-migration safe).
                    self.cgroup_id = rollback_cgroup_id;
                }

                // Rollback: restore old address space and free new one
                crate::process::activate_memory_space(self.old_space, Some(self.old_user_space));
                // R118-I1 FIX: Free KPTI user PML4 before kernel PML4
                // (user PML4 contains shared sub-table pointers)
                if self.new_user_space != 0 {
                    crate::fork::free_kpti_user_pml4(self.new_user_space);
                }
                crate::process::free_address_space(self.new_space);
                // R125-1 FIX: Uncharge cgroup memory that load_elf() charged
                if self.charged_bytes > 0 {
                    cgroup::uncharge_memory(self.cgroup_id, self.charged_bytes);
                }
            }
        }
    }

    // Create the guard before switching CR3
    let mut space_guard = ExecSpaceGuard::new(
        process.clone(),
        old_memory_space,
        old_user_memory_space,
        new_memory_space,
    );

    // 切换到新地址空间 (KPTI user PML4 not yet created — pass 0)
    activate_memory_space(new_memory_space, Some(0));

    // 加载 ELF 映像
    // S-7 fix: Let the guard handle rollback on error
    // R149-3 FIX: Pass exec_cgroup_id captured under lock, not re-read.
    let load_result = load_elf(&elf_data, exec_cgroup_id).map_err(|e| {
        klog!(Error, "sys_exec: ELF load failed: {:?}", e);
        SyscallError::ENOEXEC
    })?;

    // R125-1 FIX: Record cgroup charges from load_elf() in the guard.  If
    // any subsequent step (copy_to_user, KPTI PML4 creation, etc.) fails,
    // ExecSpaceGuard::drop() will uncharge these bytes, preventing permanent
    // inflation of cgroup memory_current on exec rollback.
    // R149-3 FIX: Use the same exec_cgroup_id for guard (not re-read).
    // Also set exec_pending_bytes so compute_cgroup_charged_bytes() includes
    // these in-flight charges during any concurrent migration.
    {
        let proc = process.lock();
        proc.mm.lock().exec_pending_bytes = load_result.charged_bytes;
    }
    space_guard.set_cgroup_charge(exec_cgroup_id, load_result.charged_bytes);

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

    // R106-4 FIX: Build the entire initial user stack in a kernel buffer first,
    // then copy to user space via a single `copy_to_user()` call.  This eliminates
    // the wide `UserAccessGuard` that previously covered ~90 lines of direct
    // user-pointer writes, minimizing the SMAP-disabled window.
    // `copy_to_user` internally handles SMAP per-chunk (R65-10 chunked copy).

    let total_needed = string_bytes + pointer_bytes + 16; // +16 for alignment
    if total_needed > USER_STACK_SIZE {
        return Err(SyscallError::E2BIG);
    }

    // ── Phase 1: Compute user-space addresses without touching user memory ──

    let mut sp = stack_top;
    // R160-15 FIX: Fallible allocation (with_capacity is infallible).
    let mut argv_ptrs: Vec<usize> = Vec::new();
    argv_ptrs.try_reserve_exact(argc).map_err(|_| SyscallError::ENOMEM)?;
    let mut envp_ptrs: Vec<usize> = Vec::new();
    envp_ptrs.try_reserve_exact(envc).map_err(|_| SyscallError::ENOMEM)?;

    // 1. 计算 argv 字符串位置（从高地址向低地址生长）
    for s in argv_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        argv_ptrs.push(sp);
    }
    argv_ptrs.reverse(); // 恢复正序

    // 2. 计算 envp 字符串位置
    for s in envp_vec.iter().rev() {
        let len = s.len();
        sp = sp.checked_sub(len + 1).ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
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
    let tentative_rsp = sp.checked_sub(pointer_bytes).ok_or(SyscallError::EFAULT)?;
    let needs_abi_pad = (tentative_rsp & 0xF) == 0;
    // If padding is needed, insert one extra word between pointer area and string area
    if needs_abi_pad {
        sp = sp.checked_sub(word).ok_or(SyscallError::EFAULT)?;
    }

    // Final buf_base is where argc will live (lowest address of the buffer)
    let buf_base = sp.checked_sub(pointer_bytes).ok_or(SyscallError::EFAULT)?;
    if buf_base < stack_base {
        return Err(SyscallError::E2BIG);
    }

    // ── Phase 2: Assemble stack content in a kernel-side buffer ──

    let buf_len = stack_top.checked_sub(buf_base).ok_or(SyscallError::EFAULT)?;
    // R156-3 FIX: Fallible allocation for exec stack buffer.
    let mut stack_buf = Vec::new();
    stack_buf.try_reserve_exact(buf_len).map_err(|_| SyscallError::ENOMEM)?;
    stack_buf.resize(buf_len, 0);

    // Helper: write bytes into stack_buf at the position corresponding to `user_addr`
    let buf_write = |buf: &mut Vec<u8>, user_addr: usize, data: &[u8]| -> Result<(), SyscallError> {
        let off = user_addr.checked_sub(buf_base).ok_or(SyscallError::EFAULT)?;
        let end = off.checked_add(data.len()).ok_or(SyscallError::EFAULT)?;
        if end > buf.len() {
            return Err(SyscallError::EFAULT);
        }
        buf[off..end].copy_from_slice(data);
        Ok(())
    };

    // Helper: write a native-endian usize value
    let buf_write_usize = |buf: &mut Vec<u8>, user_addr: usize, val: usize| -> Result<(), SyscallError> {
        let off = user_addr.checked_sub(buf_base).ok_or(SyscallError::EFAULT)?;
        let end = off.checked_add(word).ok_or(SyscallError::EFAULT)?;
        if end > buf.len() {
            return Err(SyscallError::EFAULT);
        }
        buf[off..end].copy_from_slice(&val.to_ne_bytes());
        Ok(())
    };

    // 6. 写入 argv 字符串 + NUL 终止符
    for (s, &addr) in argv_vec.iter().zip(argv_ptrs.iter()) {
        buf_write(&mut stack_buf, addr, s)?;
        // NUL terminator (buffer is zero-initialized, but be explicit)
        let nul_addr = addr.checked_add(s.len()).ok_or(SyscallError::EFAULT)?;
        buf_write(&mut stack_buf, nul_addr, &[0u8])?;
    }

    // 7. 写入 envp 字符串 + NUL 终止符
    for (s, &addr) in envp_vec.iter().zip(envp_ptrs.iter()) {
        buf_write(&mut stack_buf, addr, s)?;
        let nul_addr = addr.checked_add(s.len()).ok_or(SyscallError::EFAULT)?;
        buf_write(&mut stack_buf, nul_addr, &[0u8])?;
    }

    // 8. 写入指针区: argc | argv[0..n] | NULL | envp[0..m] | NULL
    let mut cursor = buf_base;

    // argc
    buf_write_usize(&mut stack_buf, cursor, argc)?;
    cursor = cursor.checked_add(word).ok_or(SyscallError::EFAULT)?;

    // argv pointers
    for &ptr in &argv_ptrs {
        buf_write_usize(&mut stack_buf, cursor, ptr)?;
        cursor = cursor.checked_add(word).ok_or(SyscallError::EFAULT)?;
    }
    // argv NULL terminator
    buf_write_usize(&mut stack_buf, cursor, 0)?;
    cursor = cursor.checked_add(word).ok_or(SyscallError::EFAULT)?;

    // envp pointers
    for &ptr in &envp_ptrs {
        buf_write_usize(&mut stack_buf, cursor, ptr)?;
        cursor = cursor.checked_add(word).ok_or(SyscallError::EFAULT)?;
    }
    // envp NULL terminator
    buf_write_usize(&mut stack_buf, cursor, 0)?;

    // ABI padding word (already zero-initialized in stack_buf, but explicit)
    if needs_abi_pad {
        let pad_addr = buf_base.checked_add(pointer_bytes).ok_or(SyscallError::EFAULT)?;
        buf_write_usize(&mut stack_buf, pad_addr, 0)?;
    }

    // ── Phase 3: Single copy to user space (SMAP handled internally per chunk) ──

    copy_to_user(buf_base as *mut u8, &stack_buf)?;

    // ── Phase 4: KPTI user PML4 creation ──
    //
    // Now that load_elf() and stack setup have populated all user-space page table
    // entries (code/data at PML4[0], stack at PML4[255], etc.), snapshot the kernel
    // PML4's user half into the KPTI user PML4.  This must happen AFTER all user
    // mappings are established, because create_kpti_user_pml4() copies PML4[0..255]
    // entries by value — any entries created later would be invisible under user CR3.
    let new_user_memory_space = if security::is_kpti_enabled() {
        let (_user_frame, user_phys) =
            crate::fork::create_kpti_user_pml4(new_memory_space)
                .map_err(|_| SyscallError::ENOMEM)?;
        user_phys
    } else {
        0
    };
    // R118-I1 FIX: Register user PML4 with guard so rollback frees it.
    space_guard.set_new_user_space(new_user_memory_space);

    // Final RSP points to argc (lowest address in the buffer)
    let final_rsp = buf_base as u64;
    let argv_base = (buf_base + word) as u64; // argv[0] 的地址

    // 更新进程 PCB
    let (old_space, old_user_space, cloexec_removed, cloexec_cgroup_id, cloexec_closed) = {
        let mut proc = process.lock();

        // R169-4 FIX: Reserve the close-on-exec drop buffer to the CURRENT
        // cloexec-fd count BEFORE any irreversible exec mutation (capability
        // revocation at cap_table.apply_cloexec(), fd close). On allocation
        // failure we return ENOMEM here — nothing has been mutated yet, so the
        // exec rolls back cleanly via space_guard. FD state is per-process
        // (never Arc-shared, even under CLONE_FILES) and nothing in this lock
        // hold adds cloexec marks, so this capacity is EXACTLY sufficient for
        // take_cloexec_fds_into() below: every push fits without realloc,
        // guaranteeing no FileDescriptor ever drops inline under the Process
        // lock (the R169-4 lock-inversion class) — with no fatal-OOM residual.
        let mut cloexec_removed: Vec<crate::process::FileDescriptor> = Vec::new();
        if cloexec_removed.try_reserve(proc.cloexec_fds.len()).is_err() {
            return Err(SyscallError::ENOMEM);
        }

        let old_space = proc.memory_space;
        let old_user_space = proc.user_memory_space;
        proc.memory_space = new_memory_space;
        // H.3 KPTI: Set user PML4 root (0 if KPTI disabled)
        proc.user_memory_space = new_user_memory_space;
        proc.user_stack = Some(VirtAddr::new(load_result.user_stack_top));

        // 设置上下文
        proc.context.rip = load_result.entry;
        proc.context.rsp = final_rsp;
        proc.context.rbp = final_rsp;

        // R133-6 FIX: Correct user CS/SS selectors (Ring 3)
        // USER_CS = 0x23, USER_SS = 0x1B (previously swapped)
        proc.context.cs = 0x23;
        proc.context.ss = 0x1B;
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

        // R124-1 FIX: Uncharge the old image's cgroup memory before clearing
        // mmap_regions. exec() replaces the entire userspace image; the old
        // regions' cgroup charges must be released or memory_current leaks
        // monotonically across every execve(), eventually blocking all
        // allocations in the cgroup (container DoS).
        //
        // Skip PROT_NONE reservations: never allocated frames or charged
        // memory (R123-1 invariant INV-MM-PROT-NONE).
        //
        // D3-ARC-MM-SHARED: Lock MmState once for all mm field accesses in
        // this block. The mm lock is held inside the proc lock scope.
        {
            let cgroup_id = proc.cgroup_id;
            let mut mm = proc.mm.lock();
            for (&_base, &len_with_flags) in mm.mmap_regions.iter() {
                if len_with_flags.is_prot_none() {
                    continue;
                }
                let len = mmap_region_len(len_with_flags) as u64;
                if len > 0 {
                    cgroup::uncharge_memory(cgroup_id, len);
                }
            }

            // R127-3 FIX: Uncharge brk heap from the old image before resetting
            // brk_start/brk. Without this, the old image's heap charges remain
            // permanently in the cgroup, leaking memory_current across every exec.
            let heap_bytes =
                page_align_up(mm.brk).saturating_sub(page_align_up(mm.brk_start)) as u64;
            if heap_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, heap_bytes);
            }

            // R137-1 FIX: Uncharge the old image's ELF loader charges (PT_LOAD
            // segments + user stack). These bytes were charged by load_elf() and
            // are not represented in mmap_regions or brk bookkeeping.
            let elf_bytes = mm.elf_charged_bytes;
            if elf_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, elf_bytes);
            }

            // J2-9 FIX: Uncharge the old image's page-table-frame kmem. exec()
            // replaces the whole address space; free_address_space(old_space)
            // below (~line 4518) SYNCHRONOUSLY frees the old AS's entire
            // page-table hierarchy, so a stale pt_charged_bytes would leak
            // memory_current monotonically across every execve() (container DoS)
            // AND propagate phantom bytes cross-cgroup on a later migration. exec
            // already rejected shared/CLONE_VM address spaces, so this runs
            // ungated (the last and only holder).
            let pt_bytes = mm.pt_charged_bytes;
            if pt_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, pt_bytes);
            }
            mm.pt_charged_bytes = 0;
            // R171-CG1x0 FIX (M2-1 SLICE-0): the wholesale uncharge above drained
            // both lanes (INVARIANT I'); clear the frame-identity ledger and reset
            // the basis so the fresh image starts authoritative with no stale frame
            // keys (a reused physical frame in the new AS cannot collide).
            mm.pt_charged_frames.clear();
            mm.pt_inherited_bytes = 0;
            mm.pt_ledger_authoritative = true;
            // M2-1 SLICE-4d: charge + ledger the NEW image's page-table-frame kmem — the
            // intermediate PT/PD/PDPT frames load_elf built for this fresh AS (recorded by
            // RecordingFrameAllocator). SOFT/forced charge: the count is knowable only
            // after load_elf ran (a hard reject would orphan already-built tables uncharged
            // = a worse bypass). Folded HERE, right after the old image's ledger is cleared,
            // onto the now-fresh authoritative ledger, under this same Process+MmState
            // commit (exec_in_progress also blocks migration across the whole exec window).
            // PT is charged ONLY on this success commit; any earlier exec failure tears down
            // the new AS via ExecSpaceGuard with PT never charged. record_pt_charge bumps
            // pt_charged_bytes and preserves INVARIANT I'.
            let new_pt_bytes = (load_result.pt_frames.len() as u64).saturating_mul(0x1000);
            if new_pt_bytes > 0 {
                cgroup::charge_memory_forced(cgroup_id, new_pt_bytes);
                mm.record_pt_charge(&load_result.pt_frames);
            }

            // R131-6 FIX: Reset per-task charge counter — the old image's charges
            // were fully uncharged above; new ELF image starts with a clean slate.
            mm.vm_charged_bytes = 0;
            mm.brk_pending_growth = 0; // R144-1 FIX: Clear pending brk growth on exec
            // R165-1 FIX: clear any brk reservation on exec image replacement.
            // exec already rejects multithreaded/shared-VM callers, so no sibling
            // brk can be in flight here; reset defensively for a clean slate.
            mm.brk_in_progress = false;
            mm.mprotect_pending_bytes = 0; // R147-1 FIX: Clear pending mprotect charges on exec
            mm.exec_pending_bytes = 0; // R149-3 FIX: Charge now reflected in elf_charged_bytes
            // R137-1 FIX: Record the new ELF image's cgroup charges (segments + stack)
            // so that process exit and subsequent exec can uncharge them. The old
            // image's elf_charged_bytes were already uncharged above alongside
            // mmap_regions and brk. Safe to set before space_guard.commit() because
            // no fallible operations remain between lock release and commit(); if the
            // guard were to roll back, it uncharges via its own charged_bytes field.
            mm.elf_charged_bytes = load_result.charged_bytes;
            mm.mmap_regions.clear();
            // H.2 Partial KASLR: Re-randomize mmap base on exec for ASLR
            mm.next_mmap_addr = security::randomized_mmap_base(0x4000_0000);

            // 初始化堆管理（brk）
            // brk_start 和 brk 初始化为 ELF 最高段末尾（页对齐）
            // 这确保 brk(0) 返回正确的初始值，malloc 才能正常工作
            mm.brk_start = load_result.brk_start;
            mm.brk = load_result.brk_start;
        }

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
        // R163-12 FIX: Clear stale seccomp_installing flag on exec.
        proc.seccomp_installing = false;

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
        //
        // R169-4 FIX: Drain the removed CLOEXEC descriptors into the
        // pre-reserved buffer (no inline drop) and capture the closed count +
        // owning cgroup, but DEFER the actual FileDescriptor drops and the L5
        // per-cgroup FD-budget uncharge to OUTSIDE this block (below the `};`).
        let cloexec_cgroup_id = proc.cgroup_id;
        let cloexec_closed = proc.take_cloexec_fds_into(&mut cloexec_removed);

        proc.state = ProcessState::Ready;

        (
            old_space,
            old_user_space,
            cloexec_removed,
            cloexec_cgroup_id,
            cloexec_closed,
        )
    };

    // R169-4 FIX (HIGH, lock inversion): Drop the closed CLOEXEC
    // FileDescriptors and uncharge the per-cgroup FD budget OUTSIDE the Process
    // lock. SocketFile::Drop → socket close → wake_all (re-locks PROCESS_TABLE +
    // a foreign Process::inner) and uncharge_fds → CGROUP_REGISTRY (L5); running
    // either under the Process lock is a lock inversion (R154-3/R155-3) and an
    // L5-under-Process-lock acquire (D1-CGROUP-IRQ-L5).
    if cloexec_closed > 0 {
        crate::cgroup::uncharge_fds(cloexec_cgroup_id, cloexec_closed);
    }
    drop(cloexec_removed);

    // S-7 fix: Commit the exec - prevent guard from rolling back
    // This must be called after all error-prone operations are complete.
    space_guard.commit();

    // R118-6 FIX: Update per-CPU KPTI CR3 pair now that the user PML4 exists.
    //
    // The initial activate_memory_space() ran before Phase 4 and installed a
    // single-root context (user PML4 wasn't created yet).  Now that the user
    // PML4 is committed to the PCB, re-invoke with the correct user_memory_space
    // to install the dual-root KPTI context.  This replaces the previous
    // sync_kpti_cr3() call that scanned PROCESS_TABLE.
    activate_memory_space(new_memory_space, Some(new_user_memory_space));

    // 释放旧地址空间
    // H.3 KPTI: Free old user PML4 before old kernel PML4 (shared sub-tables).
    // R162-4 FIX: Re-verify that no CLONE_VM sibling was created during the
    // lock-free exec window (ELF loading, CR3 switch). If a concurrent
    // sys_clone(CLONE_VM) created a new sibling referencing old_space after
    // the initial share_count check at line ~3848, freeing old_space here
    // would cause UAF of the sibling's page tables.
    if old_space != 0 && address_space_share_count(old_space) == 0 {
        if old_user_space != 0 {
            crate::fork::free_kpti_user_pml4(old_user_space);
        }
        free_address_space(old_space);
    }

    // R101-2 FIX: Gate exec entry/rsp/argc debug print behind debug_assertions.
    // These leak user entry point and stack pointer addresses.
    kprintln!(
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
        // R171-F3 FIX: a pending kill interrupts wait() with EINTR instead of
        // re-blocking on children. Restore Ready + clear the waiting_child marker
        // so the scheduler/teardown sees a runnable task (not a stuck Blocked one).
        if wait_should_abort(pid) {
            let mut proc = parent.lock();
            proc.state = ProcessState::Ready;
            proc.waiting_child = None;
            return Err(SyscallError::EINTR);
        }
        // 【关键修复】先标记为等待状态，再扫描子进程，避免 lost wake-up
        // 如果子进程在我们标记之后、扫描之前退出，terminate_process 会看到我们的等待状态
        // 如果子进程在我们扫描时/之后退出，我们会在扫描中发现它的 Zombie 状态
        let child_list = {
            let mut proc = parent.lock();
            if proc.children.is_empty() {
                if !proc.children_incomplete {
                    return Err(SyscallError::ECHILD);
                }
                // R158-4 Phase 2: children_incomplete is set — do PROCESS_TABLE fallback scan.
                drop(proc);
                let mut found = Vec::new();
                {
                    let table = crate::process::PROCESS_TABLE.lock();
                    for (idx, slot) in table.iter().enumerate() {
                        if let Some(proc_arc) = slot {
                            let p = proc_arc.lock();
                            if p.ppid == pid && idx != pid {
                                if found.try_reserve(1).is_ok() {
                                    found.push(idx);
                                }
                            }
                        }
                    }
                }
                if found.is_empty() {
                    // No orphan children found — clear stale flag and return ECHILD.
                    let mut proc = parent.lock();
                    proc.children_incomplete = false;
                    return Err(SyscallError::ECHILD);
                }
                // Re-acquire and set wait state.
                let mut proc = parent.lock();
                proc.state = ProcessState::Blocked;
                proc.waiting_child = Some(0);
                found
            } else {
                // Normal fast path: use children list.
                proc.state = ProcessState::Blocked;
                proc.waiting_child = Some(0);
                let mut snapshot = Vec::new();
                if snapshot.try_reserve_exact(proc.children.len()).is_err() {
                    proc.state = ProcessState::Ready;
                    proc.waiting_child = None;
                    return Err(SyscallError::ENOMEM);
                }
                snapshot.extend_from_slice(&proc.children);
                snapshot
            }
        };

        // 查找已终止的僵尸子进程
        // F.1 PID Namespace: Also capture the child's namespace chain to derive ns-local PID
        let mut zombie_child: Option<(ProcessId, i32, Vec<crate::pid_namespace::PidNamespaceMembership>)> = None;
        let mut stale_pids: vec::Vec<ProcessId> = vec::Vec::new();

        for child_pid in child_list.iter() {
            match get_process(*child_pid) {
                Some(child_proc) => {
                    let child = child_proc.lock();
                    // R169-9: only reap a Zombie whose teardown has been published
                    // (teardown_done) — never before its cgroup/ns/futex teardown ran.
                    if child.state == ProcessState::Zombie
                        && child
                            .teardown_done
                            .load(core::sync::atomic::Ordering::Acquire)
                    {
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
                    // R157-6 FIX: Fallible push — skip stale entry on OOM
                    // (it will be cleaned up on the next wait call).
                    if stale_pids.try_reserve(1).is_ok() {
                        stale_pids.push(*child_pid);
                    }
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

            kprintln!(
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
        // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
            .ok_or(SyscallError::EFAULT)?
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
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global TID.
    let ns_tid =
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
            .ok_or(SyscallError::EFAULT)?;
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
        // R94-6 FIX: Translation failure returns EFAULT instead of leaking global TID.
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
            .ok_or(SyscallError::EFAULT)?
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

        // R101-5/R101-13 FIX: User namespace-aware permission check.
        //
        // Previously, a process with euid=0 inside a user namespace could send
        // signals to ANY process in the system, breaking container isolation.
        // Now we translate UIDs through the user namespace hierarchy:
        // - Both sender and target UIDs are mapped to their host-level equivalents
        // - Root inside a user namespace maps to OVERFLOW_UID (65534) in the parent
        // - Only processes whose UIDs match at the host level can signal each other
        //
        // For root namespace processes, map_uid_from_ns returns identity.
        // R163-14 FIX: Single lookup — prevents TOCTOU on user_ns if setns
        // runs between two separate lookups.
        let sender_ns = {
            let self_proc = get_process(self_global_pid).ok_or(SyscallError::ESRCH)?;
            let guard = self_proc.lock();
            guard.user_ns.clone()
        };
        let target_ns = {
            let ns = target.lock().user_ns.clone();
            ns
        };

        // Map sender's UIDs to host-level equivalents
        const OVERFLOW_UID: u32 = 65534;
        let sender_host_euid = sender_ns.map_uid_from_ns(sender_creds.euid)
            .unwrap_or(OVERFLOW_UID);
        let sender_host_uid = sender_ns.map_uid_from_ns(sender_creds.uid)
            .unwrap_or(OVERFLOW_UID);
        // Map target's UID to host-level equivalent
        let target_host_uid = target_ns.map_uid_from_ns(target_uid)
            .unwrap_or(OVERFLOW_UID);

        // POSIX 权限检查 (namespace-aware):
        // 1. Root at HOST level (host_euid == 0) 可以发信号给任何进程
        // 2. sender host_uid == target host_uid
        // 3. sender host_euid == target host_uid
        let has_permission = sender_host_euid == 0
            || sender_host_uid == target_host_uid
            || sender_host_euid == target_host_uid;

        if !has_permission {
            return Err(SyscallError::EPERM);
        }
    }

    // R161-2 FIX + R162-1-1 FIX: Invoke LSM hook_signal_send BEFORE sig==0
    // check so MAC policy can deny process existence probes across security
    // domains (matching Linux SELinux/AppArmor behavior).
    if let Some(task_ctx) = lsm_current_process_ctx() {
        let sig_ctx = lsm::SignalCtx {
            target_pid: target_global_pid,
            sig,
            cap: None,
        };
        if let Err(err) = lsm::hook_signal_send(&task_ctx, &sig_ctx) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // R161-I6 FIX: POSIX kill(pid, 0) — permission check without delivery.
    // Signal 0 is used to test if a process exists and the caller has permission.
    // Placed after LSM check so MAC policy can deny existence probes.
    if sig == 0 {
        return Ok(0);
    }

    // 验证信号编号
    let signal = Signal::from_raw(sig)?;

    // 发送信号 (using global PID)
    let _action = send_signal(target_global_pid, signal)?;

    // R101-2 FIX: Gate signal dispatch debug print behind debug_assertions.
    // R111-4 FIX: Remove target_global_pid from output to preserve PID namespace
    // isolation even in debug builds.
    kprintln!(
        "sys_kill: sent {} to PID {} (action: {:?})",
        signal_name(signal),
        pid,
        _action
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
        kprintln!(
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

    // R165-17 FIX: Invoke the dedicated task-level LSM hook for namespace
    // creation. Previously sys_unshare had only DAC cap/root gates and no MAC
    // mediation point. Evaluate after flag validation, before any cap check or
    // namespace mutation; deny => EPERM. Build ctx from the locked proc and drop
    // the lock before calling the hook (Process-mutex re-entrancy, R131-1 pattern).
    {
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)
        };
        if lsm::hook_task_unshare(&ctx, flags).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    // R156-2 FIX: CLONE_NEWPID in unshare requires CAP_ADMIN or root,
    // matching clone() and the gates on CLONE_NEWNS/NEWIPC/NEWNET.
    if flags & CLONE_NEWPID != 0 {
        let has_cap_admin =
            with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_unshare] CLONE_NEWPID denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    if flags & CLONE_NEWPID != 0 {
        // Create a new child PID namespace
        let current_ns_for_children = {
            let proc = proc_arc.lock();
            proc.pid_ns_for_children.clone()
        };

        let new_ns =
            crate::pid_namespace::PidNamespace::new_child(current_ns_for_children).map_err(
                |e| {
                    klog!(Error, "[sys_unshare] Failed to create PID namespace: {:?}", e);
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

        klog!(Info,
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
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() for consistency with sys_setns.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_unshare] CLONE_NEWNS denied: requires CAP_SYS_ADMIN or root");
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
            kprintln!(
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
            klog!(Error, "[sys_unshare] Failed to create mount namespace: {:?}", e);
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

        klog!(Info,
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
        kprintln!("[sys_setns] Invalid nstype: {}", nstype);
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: Require CAP_SYS_ADMIN (CapRights::ADMIN) or root
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
    // R83-2 FIX: Fail-closed - if euid cannot be determined, deny access
    // Previously used unwrap_or(true) which would grant root access on None
    // R135-3 FIX: Use host-mapped root check. Namespace root must NOT be
    // able to join arbitrary mount namespaces.
    let is_root = crate::current_is_host_root();
    if !is_root && !has_cap_admin {
        kprintln!("[sys_setns] Permission denied: requires CAP_SYS_ADMIN or root");
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
        kprintln!(
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
            kprintln!("[sys_setns] fd {} is not a mount namespace fd", fd);
            return Err(SyscallError::EINVAL);
        }
    };

    // R165-17 FIX: Invoke the dedicated task-level LSM hook for joining a
    // namespace. Previously sys_setns had only DAC cap/root gates and no MAC
    // mediation point. Evaluate after the cap + thread-group checks and target
    // resolution, before the namespace switch; deny => EPERM. Build ctx from the
    // locked proc and drop the lock before the hook (R131-1 re-entrancy pattern).
    {
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)
        };
        if lsm::hook_task_setns(&ctx, CLONE_NEWNS as u64, target_ns.id().raw()).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    klog!(Info,
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

    // R163-I1 FIX: Removed redundant validate_user_ptr — verify_user_memory
    // already calls validate_user_ptr internally as its first step.
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
    // lint-repr-c-copy: allow (no-padding: [i32; 2] = 8 bytes, primitive array)
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
        // R158-I8 FIX: removed unconditional debug kprintln (log spam + info disclosure).

        // R156-3 FIX: Fallible allocation — infallible vec! panics on OOM.
        let mut tmp = Vec::new();
        tmp.try_reserve_exact(count).map_err(|_| SyscallError::ENOMEM)?;
        tmp.resize(count, 0);
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
                // R158-8 FIX: cancel wait (dequeue + Blocked→Ready) before return.
                stdin_cancel_wait();
                copy_to_user(buf, &tmp[..bytes_read])?;
                return Ok(bytes_read);
            }

            // 确实没有数据，完成等待（让出 CPU）
            // R171-F3: a pending kill interrupts the blocking stdin read (EINTR);
            // stdin_finish_wait() already dequeued us + restored Ready.
            if stdin_finish_wait() {
                return Err(SyscallError::EINTR);
            }
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

    // R156-3 FIX: Fallible allocation for read buffer.
    let mut tmp = Vec::new();
    tmp.try_reserve_exact(count).map_err(|_| SyscallError::ENOMEM)?;
    tmp.resize(count, 0);
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

    // R156-3 FIX: Fallible allocation for write buffer.
    let mut tmp = Vec::new();
    tmp.try_reserve_exact(count).map_err(|_| SyscallError::ENOMEM)?;
    tmp.resize(count, 0);
    copy_from_user(&mut tmp, buf)?;

    // stdout(1)/stderr(2): 直接打印
    // R158-I9 FIX: Accept non-UTF-8 bytes (POSIX write(2) is byte-oriented).
    // Display valid UTF-8 as text; replace invalid sequences with U+FFFD.
    if fd == 1 || fd == 2 {
        // R162-17 FIX: Avoid infallible from_utf8_lossy which can allocate ~3x
        // input size on all-invalid bytes. Print in chunks using from_utf8
        // on valid spans and individual replacement chars for invalid bytes.
        match core::str::from_utf8(&tmp) {
            Ok(s) => print!("{}", s),
            Err(_) => {
                let mut i = 0;
                while i < tmp.len() {
                    match core::str::from_utf8(&tmp[i..]) {
                        Ok(s) => { print!("{}", s); break; }
                        Err(e) => {
                            let valid_end = e.valid_up_to();
                            if valid_end > 0 {
                                if let Ok(valid) = core::str::from_utf8(&tmp[i..i + valid_end]) {
                                    print!("{}", valid);
                                }
                            }
                            print!("\u{FFFD}");
                            i += valid_end + e.error_len().unwrap_or(1);
                        }
                    }
                }
            }
        }
        Ok(tmp.len())
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

// H.0.1-3: Compile-time ABI size assertion.
const _: [(); 16] = [(); core::mem::size_of::<Iovec>()];

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
    use crate::usercopy::copy_from_user_safe;

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
    // R97-1 FIX: Use checked_mul to prevent integer overflow
    let iov_size = iovcnt
        .checked_mul(mem::size_of::<Iovec>())
        .ok_or(SyscallError::EFAULT)?;
    validate_user_ptr(iov as *const u8, iov_size)?;

    // R24-11 fix: Copy iovec array using fault-tolerant usercopy
    // This prevents kernel panic if user unmaps iovec during copy
    //
    // P1-6 FIX: Removed outer UserAccessGuard — copy_from_user_safe creates
    // its own per-chunk guard internally.  An outer guard prevents the
    // inter-chunk interrupt-restore window, widening the SMAP-bypass.
    // R158-9 FIX: Fallible allocation (bounded by IOV_MAX but policy requires try_reserve).
    let mut iov_array: Vec<Iovec> = Vec::new();
    iov_array.try_reserve_exact(iovcnt).map_err(|_| SyscallError::ENOMEM)?;
    for i in 0..iovcnt {
        // R97-1 FIX: Use checked_mul/checked_add to prevent integer overflow
        let entry_offset = i
            .checked_mul(mem::size_of::<Iovec>())
            .ok_or(SyscallError::EFAULT)?;
        let entry_ptr = (iov as usize)
            .checked_add(entry_offset)
            .ok_or(SyscallError::EFAULT)? as *const u8;

        // Use fault-tolerant copy for each iovec entry
        let mut entry_bytes = [0u8; mem::size_of::<Iovec>()];
        if copy_from_user_safe(&mut entry_bytes, entry_ptr).is_err() {
            return Err(SyscallError::EFAULT);
        }

        // Safely transmute bytes to Iovec
        // SAFETY: Iovec is repr(C) and all byte patterns are valid.
        // R97-1 FIX: Use read_unaligned since entry_bytes has only 1-byte alignment.
        let iov_entry: Iovec =
            unsafe { core::ptr::read_unaligned(entry_bytes.as_ptr() as *const Iovec) };
        iov_array.push(iov_entry);
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
                // R104-4 FIX: Use checked_add to prevent silent usize wrap-around
                // when a malicious/buggy iov list accumulates > usize::MAX bytes.
                total_written = total_written
                    .checked_add(written)
                    .ok_or(SyscallError::EOVERFLOW)?;
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

    // 安全复制路径字符串 (Z-3 fix: fault-tolerant usercopy)
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(
            core::str::from_utf8(&path_bytes)
                .map_err(|_| SyscallError::EINVAL)?
        )?
    };

    // R96-5 FIX: Delegate to internal helper to avoid TOCTOU in openat
    sys_open_internal(&path_str, flags, mode)
}

/// R96-5 FIX: Internal helper for sys_open that works on already-copied path.
///
/// This eliminates TOCTOU window in sys_openat where the path could be modified
/// between checking the first byte and calling sys_open.
fn sys_open_internal(path_str: &str, flags: i32, mode: u32) -> SyscallResult {
    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R105-1 FIX: Removed duplicate LSM hook_file_create / hook_file_open from
    // the syscall layer.  The VFS layer (manager.rs open_file / create_file)
    // already invokes both hooks with the authoritative inode metadata.
    // Keeping the hooks here caused:
    //   1. Double hook invocation per open, with inconsistent object identity
    //      (path_hash here vs real inode in VFS).
    //   2. Risk of policy desync if one layer is bypassed.
    let open_flags = flags as u32;

    // 获取 VFS 回调
    let open_fn = {
        let callback = VFS_OPEN_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS 打开文件 — VFS enforces LSM hooks with real inode context
    let file_ops = open_fn(&path_str, flags as u32, mode)?;

    // R39-4 FIX: O_CLOEXEC 常量定义
    const O_CLOEXEC: u32 = 0x80000;

    // 分配文件描述符并存入 fd_table
    let fd = {
        let mut proc = process.lock();
        // D2-FD-DROP-UNDER-LOCK: pre-existing inline drop of the rejected
        // object on the EMFILE arm (byte-equivalent to the old
        // allocate_fd-internal drop); conversion to drop-outside tracked.
        let fd = proc
            .allocate_fd(file_ops)
            .map_err(|rejected| {
                drop(rejected);
                SyscallError::EMFILE
            })?;

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
        try_str_to_string(
            core::str::from_utf8(&path_bytes)
                .map_err(|_| SyscallError::EINVAL)?
        )?
    };

    // R96-5 FIX: Delegate to internal helper to avoid TOCTOU in fstatat
    sys_stat_internal(&path_str, statbuf)
}

/// R113-1 FIX: Copy VfsStat to userspace via a zeroed byte buffer so that
/// implicit `#[repr(C)]` padding bytes (after `rdev` and after `blksize`) are
/// guaranteed to be zero, preventing kernel memory disclosure.
#[inline]
fn copy_vfs_stat_to_user(user_dst: *mut VfsStat, stat: &VfsStat) -> Result<(), SyscallError> {
    let mut buf = [0u8; mem::size_of::<VfsStat>()];

    macro_rules! put {
        ($field:ident) => {
            let off = mem::offset_of!(VfsStat, $field);
            let bytes = stat.$field.to_ne_bytes();
            buf[off..off + bytes.len()].copy_from_slice(&bytes);
        };
    }

    put!(dev);
    put!(ino);
    put!(mode);
    put!(nlink);
    put!(uid);
    put!(gid);
    put!(rdev);
    put!(size);
    put!(blksize);
    put!(blocks);
    put!(atime_sec);
    put!(atime_nsec);
    put!(mtime_sec);
    put!(mtime_nsec);
    put!(ctime_sec);
    put!(ctime_nsec);

    copy_to_user(user_dst as *mut u8, &buf)
}

/// R96-5 FIX: Internal helper for sys_stat that works on already-copied path.
///
/// This eliminates TOCTOU window in sys_fstatat where the path could be modified
/// between checking the first byte and calling sys_stat.
fn sys_stat_internal(path_str: &str, statbuf: *mut VfsStat) -> SyscallResult {
    // 获取 VFS stat 回调
    let stat_fn = {
        let callback = VFS_STAT_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // 调用 VFS stat
    let stat = stat_fn(path_str)?;

    // R113-1 FIX: Copy via zeroed buffer to avoid padding info leak
    copy_vfs_stat_to_user(statbuf, &stat)?;

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
        // R131-4 FIX: Release process lock before calling VFS stat() callback.
        // Holding the process lock across inode.stat() creates a lock ordering
        // inversion risk: process lock → procfs → PROCESS_TABLE (reverse of
        // normal signal delivery path: PROCESS_TABLE → process lock).
        // Same clone_box() pattern as R130-2 sys_lseek fix.
        let fd_obj = {
            let proc = process.lock();
            proc.get_fd(fd).ok_or(SyscallError::EBADF)?.clone_box()
        };
        // Process lock released here — safe for VFS/procfs operations
        fd_obj.stat()?
    };

    // R113-1 FIX: Copy via zeroed buffer to avoid padding info leak
    copy_vfs_stat_to_user(statbuf, &stat)?;

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

    // R130-2 FIX: Extract file descriptor and release process lock before
    // calling VFS callback. Holding the process lock across the VFS callback
    // creates a lock ordering inversion risk (process lock -> procfs ->
    // PROCESS_TABLE vs. signal delivery PROCESS_TABLE -> process lock).
    // Follows the same pattern as vfs_readdir_callback and vfs_truncate_callback.
    let file_ops = {
        let proc = process.lock();
        proc.get_fd(fd).ok_or(SyscallError::EBADF)?.clone_box()
    };
    // Process lock released here — safe for VFS operations

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

// R121-4 FIX: mmap_regions encodes transient state in the low bits of the
// stored length. All committed lengths are page-aligned (4 KiB), so the
// low 12 bits are available for flags.
//
// Transient (in-flight) flags — cleared when operation completes:
//   PENDING_MAP   — address range reserved, page table mapping in progress
//   PENDING_UNMAP — region marked for removal, page table unmap in progress
//
// Persistent (committed) flags — survive into committed entry:
//   PROT_NONE — pure address reservation, no physical frames allocated/charged
//
// R122-1: Made pub(crate) so fork.rs can check for transient state.
pub(crate) const MMAP_REGION_FLAG_MASK: usize = 0xfff;
const MMAP_REGION_FLAG_PENDING_MAP: usize = 1 << 0;
const MMAP_REGION_FLAG_PENDING_UNMAP: usize = 1 << 1;
// R123-1 FIX: Committed flag indicating PROT_NONE reservation (no frames/charge).
// R124-1 FIX: Made pub(crate) so process exit/exec cleanup can skip uncharge for PROT_NONE.
pub(crate) const MMAP_REGION_FLAG_PROT_NONE: usize = 1 << 2;

// R144-2 FIX: Protection bit flags stored in mmap_regions entries so that
// /proc/[pid]/maps can display accurate permissions instead of hardcoded "rw-p".
// Public so that VFS procfs can decode permission strings via mmap_flags_to_perms().
pub const MMAP_REGION_FLAG_PROT_READ: usize = 1 << 3;
pub const MMAP_REGION_FLAG_PROT_WRITE: usize = 1 << 4;
pub const MMAP_REGION_FLAG_PROT_EXEC: usize = 1 << 5;
/// R149-6 / R168-1 FIX: Transient ownership token for an mprotect operation
/// that drops the MmState lock for page-table work. Path A (PROT_NONE → real)
/// holds it while allocating + mapping frames; Path B (real → PROT_NONE) holds
/// it while unmapping + freeing frames. Set under the lock before the PT ops
/// and cleared on commit/rollback. Concurrent munmap / mprotect / fork observe
/// it via the transient mask and fail closed (EBUSY / skip / EAGAIN) instead of
/// racing cgroup bookkeeping against the in-flight page-table side effects —
/// preventing both the permanent charge leak (Path A) and the double-uncharge
/// isolation bypass (Path B).
const MMAP_REGION_FLAG_PENDING_MPROTECT: usize = 1 << 6;

/// Mask of transient in-flight flags. Only these are stripped on fork/clone;
/// persistent committed flags (e.g. PROT_NONE) are preserved.
pub(crate) const MMAP_REGION_FLAG_TRANSIENT_MASK: usize =
    MMAP_REGION_FLAG_PENDING_MAP | MMAP_REGION_FLAG_PENDING_UNMAP | MMAP_REGION_FLAG_PENDING_MPROTECT;

/// D2-MMAP-LIFECYCLE Phase 2: typed newtype for `mmap_regions` VALUES.
///
/// A `#[repr(transparent)]` newtype over the packed `usize` (bits [63:12] =
/// page-aligned length, bits [11:0] = flags — see the encoding contract on
/// `MmState::mmap_regions`). `Copy` + `repr(transparent)` guarantees that the
/// `FallibleOrderedMap<usize, MmapEntry>` backing store (next-phase #11) holds
/// values VERBATIM — bit-identical to the previous packed `usize`. Every
/// method body is written in terms of the existing `MMAP_REGION_FLAG_*`
/// constants, so it is provably bit-equivalent to the prior inline bit-ops.
///
/// This formalizes the transient-state encoding contract (Phase 2): the magic
/// low-bit arithmetic is replaced by named, intention-revealing accessors and
/// constructors, while the on-the-wire representation is unchanged.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::len_without_is_empty)]
pub struct MmapEntry(usize);

#[allow(clippy::len_without_is_empty)]
impl MmapEntry {
    /// Wrap a raw packed word (migration / escape hatch). Identity, bit-identical.
    #[inline]
    pub const fn from_raw(raw: usize) -> Self {
        MmapEntry(raw)
    }

    /// Pack a page-aligned length with a precomputed flag word.
    /// Precondition (same as the prior code): `len` is page-aligned (low 12 bits
    /// zero) and `flags` ⊆ `MMAP_REGION_FLAG_MASK`, so the OR is non-overlapping.
    #[inline]
    pub const fn from_len_flags(len: usize, flags: usize) -> Self {
        MmapEntry(len | flags)
    }

    /// Pure PROT_NONE reservation — `len | PROT_NONE`, NO other flags retained.
    /// Caller MUST pass an already-extracted length (`entry.len()` / `region_len`),
    /// never a raw packed word, or stale flag/length bits would leak in.
    #[inline]
    pub const fn prot_none(len: usize) -> Self {
        MmapEntry(len | MMAP_REGION_FLAG_PROT_NONE)
    }

    /// The raw packed word.
    #[inline]
    pub const fn raw(self) -> usize {
        self.0
    }

    /// Page-aligned length (all flag bits stripped). Equals the old `mmap_region_len`.
    #[inline]
    pub const fn len(self) -> usize {
        self.0 & !MMAP_REGION_FLAG_MASK
    }

    /// Low-12 flag bits — the FULL `& 0xfff` committed-flags capture (NOT a
    /// transient-stripped or persistent-only subset).
    #[inline]
    pub const fn flags(self) -> usize {
        self.0 & MMAP_REGION_FLAG_MASK
    }

    /// PROT_NONE (bit 2): pure reservation, no physical frames charged.
    #[inline]
    pub const fn is_prot_none(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_NONE != 0
    }

    /// Individual POSIX prot-bit accessors (bits 3/4/5).
    #[inline]
    pub const fn prot_read(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_READ != 0
    }
    #[inline]
    pub const fn prot_write(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_WRITE != 0
    }
    #[inline]
    pub const fn prot_exec(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PROT_EXEC != 0
    }

    /// 4-char Linux-style "rwxp" permission string for /proc/[pid]/maps.
    /// All Zero-OS mappings are private, so the 4th char is always 'p'.
    #[inline]
    pub fn perms(self) -> [u8; 4] {
        [
            if self.prot_read() { b'r' } else { b'-' },
            if self.prot_write() { b'w' } else { b'-' },
            if self.prot_exec() { b'x' } else { b'-' },
            b'p',
        ]
    }

    /// Any transient in-flight flag (PENDING_MAP|PENDING_UNMAP|PENDING_MPROTECT) set.
    #[inline]
    pub const fn has_transient(self) -> bool {
        self.0 & MMAP_REGION_FLAG_TRANSIENT_MASK != 0
    }

    /// Raw transient subset (for debug validation).
    #[inline]
    pub const fn transient_flags(self) -> usize {
        self.0 & MMAP_REGION_FLAG_TRANSIENT_MASK
    }

    /// PENDING_MPROTECT (bit 6) ownership-token test (R149-6 / R164-2 race guard).
    #[inline]
    pub const fn is_pending_mprotect(self) -> bool {
        self.0 & MMAP_REGION_FLAG_PENDING_MPROTECT != 0
    }

    /// Set PENDING_MPROTECT in place. FAITHFUL to the prior bare
    /// `*entry |= MMAP_REGION_FLAG_PENDING_MPROTECT` (no pre-clear of other
    /// transient bits) — bit-identical regardless of preconditions.
    #[inline]
    pub fn set_pending_mprotect(&mut self) {
        self.0 |= MMAP_REGION_FLAG_PENDING_MPROTECT;
    }

    /// Clear PENDING_MPROTECT in place, preserving every other bit.
    #[inline]
    pub fn clear_pending_mprotect(&mut self) {
        self.0 &= !MMAP_REGION_FLAG_PENDING_MPROTECT;
    }

    /// Arm PENDING_UNMAP (munmap Phase-1 marker). FAITHFUL literal OR — matches
    /// `recorded_length | committed_flags | PENDING_UNMAP` (committed_flags is
    /// transient-free at the only call site, guarded by `has_transient`).
    #[inline]
    pub const fn with_pending_unmap(self) -> Self {
        MmapEntry(self.0 | MMAP_REGION_FLAG_PENDING_UNMAP)
    }

    /// mprotect Path A "preserved" flags: committed flags minus
    /// PROT_NONE | PROT_RWX | PENDING_MPROTECT (mask `!0x7c`).
    #[inline]
    pub const fn committed_flags_excluding_prot(self) -> usize {
        (self.0 & MMAP_REGION_FLAG_MASK)
            & !(MMAP_REGION_FLAG_PROT_NONE
                | MMAP_REGION_FLAG_PROT_READ
                | MMAP_REGION_FLAG_PROT_WRITE
                | MMAP_REGION_FLAG_PROT_EXEC
                | MMAP_REGION_FLAG_PENDING_MPROTECT)
    }

    /// mprotect Path D in-place display-bit sync: clear exactly R|W|X (0x38),
    /// OR the new prot bits, leaving length + PROT_NONE + transient bits untouched.
    #[inline]
    pub fn rewrite_prot_bits(&mut self, new_prot_flags: usize) {
        let prot_mask = MMAP_REGION_FLAG_PROT_READ
            | MMAP_REGION_FLAG_PROT_WRITE
            | MMAP_REGION_FLAG_PROT_EXEC;
        self.0 = (self.0 & !prot_mask) | new_prot_flags;
    }

    /// Fork transient-strip: clear PENDING_* (bits 0,1,6), preserve PROT_* + length.
    /// PRESERVING PROT_NONE (bit 2) is load-bearing for the child's cgroup-charge skip.
    #[inline]
    pub const fn fork_stripped(self) -> Self {
        MmapEntry(self.0 & !MMAP_REGION_FLAG_TRANSIENT_MASK)
    }

    /// Debug invariant check: page-aligned length + at most one transient flag.
    #[inline]
    pub fn debug_validate(self) {
        if cfg!(debug_assertions) {
            let length = self.len();
            debug_assert!(
                length & (PAGE_SIZE - 1) == 0,
                "mmap_regions: length {:#x} is not page-aligned",
                length,
            );
            let transient = self.transient_flags();
            debug_assert!(
                transient == 0
                    || transient == MMAP_REGION_FLAG_PENDING_MAP
                    || transient == MMAP_REGION_FLAG_PENDING_UNMAP
                    || transient == MMAP_REGION_FLAG_PENDING_MPROTECT,
                "mmap_regions: multiple transient flags set: {:#x}",
                transient,
            );
        }
    }
}

/// Extract the actual page-aligned length from an mmap_regions entry.
/// Thin shim over [`MmapEntry::len`] (retained so existing call sites that pass
/// the entry value compile unchanged after the newtype migration).
#[inline]
pub(crate) fn mmap_region_len(entry: MmapEntry) -> usize {
    entry.len()
}

// D2-MMAP-LIFECYCLE: Validation helper for mmap_regions entries (debug builds).
// Thin shim over [`MmapEntry::debug_validate`].
#[inline]
pub(crate) fn debug_validate_mmap_entry(entry: MmapEntry) {
    entry.debug_validate();
}

/// R144-2 FIX: Encode POSIX prot bits (PROT_READ/WRITE/EXEC) into mmap region
/// flags for storage in `mmap_regions`.  Used by `generate_maps()` in procfs
/// to display accurate permission strings.
#[inline]
fn mmap_prot_to_flags(prot: i32) -> usize {
    let mut flags = 0usize;
    if prot & PROT_READ != 0 {
        flags |= MMAP_REGION_FLAG_PROT_READ;
    }
    if prot & PROT_WRITE != 0 {
        flags |= MMAP_REGION_FLAG_PROT_WRITE;
    }
    if prot & PROT_EXEC != 0 {
        flags |= MMAP_REGION_FLAG_PROT_EXEC;
    }
    flags
}

/// R144-2 FIX: Decode mmap region flags back to a 4-char Linux-style permission
/// string ("rwxp"/"r--p"/etc.).  All Zero-OS mmap regions are private (no shared
/// mappings), so the 4th character is always 'p'.
pub fn mmap_flags_to_perms(flags: usize) -> [u8; 4] {
    [
        if flags & MMAP_REGION_FLAG_PROT_READ != 0 { b'r' } else { b'-' },
        if flags & MMAP_REGION_FLAG_PROT_WRITE != 0 { b'w' } else { b'-' },
        if flags & MMAP_REGION_FLAG_PROT_EXEC != 0 { b'x' } else { b'-' },
        b'p', // always private
    ]
}

/// R165-1/R165-2 FIX (D2-MM-BRK-RESV): RAII reservation that serializes
/// concurrent `brk()` operations on a shared `MmState`.
///
/// `sys_brk` drops the `MmState` lock across irreversible page-table work
/// (frame alloc/free, map/unmap) because that work acquires the page-table
/// manager and frame-allocator locks — never `MmState` — so holding `MmState`
/// across it would invert the established lock order. The previous post-hoc
/// `mm.brk == old_brk` re-check could only *detect* a racing sibling `brk()`,
/// not undo the page-table side effects already committed. This guard instead
/// *prevents* the race: while held, `brk_in_progress` is set and every other
/// `brk()` on the shared address space returns the current break unchanged, so
/// `mm.brk` cannot move and the lock-dropped PT work stays consistent with the
/// eventual commit.
///
/// The flag is cleared on `Drop`, which covers every early-return / error path.
/// The normal commit path clears it under the same `MmState` lock it already
/// holds and then disarms the guard. `Drop` only ever runs at `sys_brk` scope
/// exit — after every inner `mm_arc.lock()` scope has ended — so re-locking
/// `MmState` here cannot self-deadlock.
struct BrkReservation {
    mm: Arc<spin::Mutex<crate::process::MmState>>,
    armed: bool,
}

impl Drop for BrkReservation {
    fn drop(&mut self) {
        if self.armed {
            self.mm.lock().brk_in_progress = false;
        }
    }
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
    // D3-ARC-MM-SHARED: Clone mm Arc before dropping process lock for PT ops.
    let mm_arc = Arc::clone(&proc.mm);

    // 查询模式：返回当前 brk
    if addr == 0 {
        return Ok(mm_arc.lock().brk);
    }

    // F.2 Cgroup: Cache cgroup_id for memory accounting
    let cgroup_id = proc.cgroup_id;

    // R131-1 FIX: Use lsm_process_ctx_from() instead of ProcessCtx::from_current()
    // to avoid deadlock. from_current() calls current_credentials() which re-acquires
    // the same Process mutex we already hold → deterministic self-deadlock.
    let ctx = lsm_process_ctx_from(&proc);
    if lsm::hook_memory_brk(&ctx, addr as u64).is_err() {
        return Err(SyscallError::EPERM);
    }

    // D3-ARC-MM-SHARED: Lock mm once for validation + setup phase.
    // R165-1/R165-2 FIX: Read old_brk AND acquire the brk reservation under the
    // SAME lock acquisition, so no sibling brk() can change mm.brk between the
    // read and the reservation. While `brk_resv` is held (brk_in_progress=true),
    // mm.brk is pinned to old_brk until this call commits, making the existing
    // post-PT re-checks provably true rather than best-effort recovery.
    let (old_brk, old_top, new_top, mut brk_resv) = {
        let mut mm = mm_arc.lock();
        // 拒绝缩小到 brk_start 以下
        if addr < mm.brk_start {
            return Ok(mm.brk);
        }
        // 检查用户空间边界
        if addr >= USER_SPACE_TOP {
            return Ok(mm.brk);
        }
        // A sibling brk() on this shared MmState is mid-flight. Linux brk()
        // returns the current break on failure, so report it unchanged and let
        // the caller retry instead of racing the page tables.
        if mm.brk_in_progress {
            return Ok(mm.brk);
        }
        mm.brk_in_progress = true;
        (
            mm.brk,
            page_align_up(mm.brk),
            page_align_up(addr),
            BrkReservation {
                mm: Arc::clone(&mm_arc),
                armed: true,
            },
        )
    };

    // 堆扩展
    if new_top > old_top {
        let grow_size = new_top - old_top;

        // 检查与 mmap 区域冲突
        {
            let mm = mm_arc.lock();
            for (&region_base, &region_len_with_flags) in mm.mmap_regions.iter() {
                let region_end = region_base.saturating_add(mmap_region_len(region_len_with_flags));
                if old_top < region_end && new_top > region_base {
                    // 有重叠，返回旧值
                    return Ok(old_brk);
                }
            }
        }

        // F.2 Cgroup: Charge memory before heap expansion.
        // R169-1 FIX (CRITICAL self-deadlock): Reuse the `cgroup_id` cached at
        // the top of sys_brk instead of re-locking the Process mutex here. The
        // `proc` guard acquired at function entry is held CONTINUOUSLY until
        // `drop(proc)` below (only the separate `mm` lock is taken/released in
        // between — never the Process lock), and every cgroup-migration path
        // (sys_cgroup_attach and the cgroupfs task-move) takes that same Process
        // lock before it writes `proc.cgroup_id`. No migration can therefore
        // occur in this window, so the cached value is provably
        // current. The prior R162-12 `process.lock()` re-acquired the
        // already-held, non-reentrant `spin::Mutex` on the SAME CPU →
        // deterministic self-deadlock on every paging brk() growth (the common
        // glibc-malloc path). Any genuinely-fresh post-PT read must happen only
        // AFTER `drop(proc)`, mirroring the shrink (6791) and rollback (6682)
        // paths which re-read only once the guard is released.
        if cgroup::try_charge_memory(cgroup_id, grow_size as u64).is_err() {
            return Ok(old_brk); // Quota exceeded, return current brk
        }

        // R144-1 FIX: Record the pending brk growth so that
        // compute_cgroup_charged_bytes() includes it even though brk
        // hasn't been updated yet. This closes the TOCTOU window where
        // cgroup migration could read stale brk during the lock drop.
        // R163-9 FIX: Use saturating_add instead of overwrite to prevent
        // concurrent CLONE_VM sys_brk calls from clobbering each other's
        // pending growth (same pattern as R162-3 for mprotect_pending_bytes).
        {
            let mut mm = mm_arc.lock();
            mm.brk_pending_growth = mm.brk_pending_growth.saturating_add(grow_size as u64);
        }

        // 释放 Process 锁后进行映射操作
        drop(proc);

        // R37-5 FIX: Track mapped pages for rollback on partial allocation failure.
        // If allocation fails partway, we must unmap+free pages already mapped in this call.
        let map_result: Result<vec::Vec<x86_64::structures::paging::PhysFrame>, SyscallError> = unsafe {
            use x86_64::structures::paging::PhysFrame;
            with_current_manager(VirtAddr::new(0), |manager| -> Result<vec::Vec<PhysFrame>, SyscallError> {
                // M2-1 SLICE-4b: record the intermediate PT/PD/PDPT frames map_page
                // builds for this heap growth so they are charged + ledgered at the
                // commit fold (mirrors sys_mmap Phase-2/3). The per-page DATA frame
                // below goes through the inherent allocate_data_frame (UNrecorded);
                // only map_page's trait allocate_frame records page-table frames.
                let mut frame_alloc = RecordingFrameAllocator::new();
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
                    // M2-1 SLICE-4b: DATA frame via the inherent allocate_data_frame
                    // (NOT recorded into the PT ledger). LOAD-BEARING split — the
                    // map_page call below KEEPS `&mut frame_alloc`, so only the
                    // intermediate tables it pulls are recorded.
                    let frame = match frame_alloc.allocate_data_frame() {
                        Some(f) => f,
                        None => {
                            // R127-2 FIX: 3-phase rollback pattern —
                            // 1) unmap pages and collect frames
                            // 2) cross-CPU TLB shootdown
                            // 3) deallocate frames after TLB is flushed
                            // R158-12 + R158-6 FIX: Fallible rollback Vec; immediate free on OOM.
                            let mut frames_to_free = Vec::new();
                            let _ = frames_to_free.try_reserve(mapped_pages.len());
                            for &rollback_page in mapped_pages.iter().rev() {
                                if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
                                    if frames_to_free.try_reserve(1).is_ok() {
                                        frames_to_free.push(freed_frame);
                                    } else {
                                        mm::flush_current_as_page(rollback_page.start_address());
                                        frame_alloc.deallocate_frame(freed_frame);
                                    }
                                }
                            }
                            // M2-1 SLICE-4b: reclaim the now-empty intermediate PT/PD
                            // tables this rolled-back growth left behind (mirrors
                            // sys_mmap R169-L2; also fixes the pre-existing brk-grow
                            // rollback table leak). old_top/grow_size spans the whole
                            // request — mapped_pages is SPARSE (translate_addr skip at
                            // the top of the loop), and table_empty() leaves a table
                            // still pinned by a skipped sibling leaf untouched.
                            manager.prune_empty_tables_in_range(
                                VirtAddr::new(old_top as u64),
                                grow_size,
                                &mut frames_to_free,
                            );
                            if !frames_to_free.is_empty() {
                                mm::flush_current_as_range(
                                    VirtAddr::new(old_top as u64),
                                    grow_size,
                                );
                                for frame in frames_to_free {
                                    frame_alloc.deallocate_frame(frame);
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
                        // R127-2 + R158-6 FIX: 3-phase rollback; immediate free on OOM.
                        let mut frames_to_free = Vec::new();
                        let _ = frames_to_free.try_reserve(mapped_pages.len());
                        for &rollback_page in mapped_pages.iter().rev() {
                            if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
                                if frames_to_free.try_reserve(1).is_ok() {
                                    frames_to_free.push(freed_frame);
                                } else {
                                    mm::flush_current_as_page(rollback_page.start_address());
                                    frame_alloc.deallocate_frame(freed_frame);
                                }
                            }
                        }
                        // M2-1 SLICE-4b: reclaim now-empty intermediate PT/PD tables
                        // (mirrors sys_mmap R169-L2; fixes the pre-existing brk-grow
                        // rollback table leak). old_top/grow_size spans the sparse
                        // request; table_empty() guards still-pinned tables.
                        manager.prune_empty_tables_in_range(
                            VirtAddr::new(old_top as u64),
                            grow_size,
                            &mut frames_to_free,
                        );
                        if !frames_to_free.is_empty() {
                            mm::flush_current_as_range(
                                VirtAddr::new(old_top as u64),
                                grow_size,
                            );
                            for frame in frames_to_free {
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                        return Err(SyscallError::ENOMEM);
                    }

                    // R158-6 FIX: fallible push — unmap+free on OOM.
                    if mapped_pages.try_reserve(1).is_err() {
                        if let Ok(freed) = manager.unmap_page(page) {
                            mm::flush_current_as_page(page.start_address());
                            frame_alloc.deallocate_frame(freed);
                        }
                        let mut frames_to_free = Vec::new();
                        let _ = frames_to_free.try_reserve(mapped_pages.len());
                        for &rollback_page in mapped_pages.iter().rev() {
                            if let Ok(freed_frame) = manager.unmap_page(rollback_page) {
                                if frames_to_free.try_reserve(1).is_ok() {
                                    frames_to_free.push(freed_frame);
                                } else {
                                    mm::flush_current_as_page(rollback_page.start_address());
                                    frame_alloc.deallocate_frame(freed_frame);
                                }
                            }
                        }
                        // M2-1 SLICE-4b: reclaim now-empty intermediate PT/PD tables
                        // (mirrors sys_mmap R169-L2; fixes the pre-existing brk-grow
                        // rollback table leak). old_top/grow_size spans the sparse
                        // request; table_empty() guards still-pinned tables.
                        manager.prune_empty_tables_in_range(
                            VirtAddr::new(old_top as u64),
                            grow_size,
                            &mut frames_to_free,
                        );
                        if !frames_to_free.is_empty() {
                            mm::flush_current_as_range(
                                VirtAddr::new(old_top as u64),
                                grow_size,
                            );
                            for f in frames_to_free {
                                frame_alloc.deallocate_frame(f);
                            }
                        }
                        return Err(SyscallError::ENOMEM);
                    }
                    mapped_pages.push(page);
                }
                // M2-1 SLICE-4b: yield the recorded PT-frame identities (NOT a count)
                // for the Step-3 charge + ledger fold. Every Err path above freed its
                // own DATA leaves AND pruned+freed its own intermediate tables, so this
                // Vec is meaningful only on this Ok path.
                Ok(frame_alloc.pt_frames)
            })
        };

        // M2-1 SLICE-4b: bind the recorded PT-frame identities on success. The Err arm
        // is the pre-existing DATA-charge rollback (the Step-2 closure already freed its
        // own DATA leaves AND pruned+freed its own intermediate tables on every error
        // path, so no PT uncharge is owed here).
        let pt_frames = match map_result {
            Err(_) => {
                // 分配失败，返回旧值并回滚内存计费
                // R144-1 FIX: Clear brk_pending_growth under lock BEFORE
                // uncharging, and use the *current* cgroup_id (migration may
                // have changed it while we held no lock).  Clearing pending
                // first prevents a concurrent sys_cgroup_attach from migrating
                // a charge that is about to be rolled back.
                let rollback_cgroup_id = {
                    let proc = process.lock();
                    // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
                    let mut mm = mm_arc.lock();
                    mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
                    proc.cgroup_id
                };
                cgroup::uncharge_memory(rollback_cgroup_id, grow_size as u64);
                return Ok(old_brk);
            }
            Ok(frames) => frames,
        };
        // M2-1 SLICE-4b: the PT-frame charge is exactly the recorded PT/PD/PDPT frame
        // count (DATA frames went through allocate_data_frame, unrecorded).
        let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

        // D3-ARC-MM-SHARED: Update brk and charge counters in shared MmState.
        // R162-2 FIX: Re-verify mm.brk == old_brk at commit.
        // M2-1 SLICE-4b: hold BOTH the Process and MmState locks across the PT-frame
        // charge fold (canonical Process -> MmState order, exactly like sys_mmap Phase-3
        // and mprotect Path-A Step-3). cgroup migration snapshots
        // compute_cgroup_charged_bytes — which folds pt_charged_bytes — under the Process
        // lock (R155-5), so charging under mm-only would race sys_cgroup_attach and
        // strand the PT charge on a stale cgroup. `proc` (the entry guard) was dropped
        // before the lock-free PT work; this re-acquires a fresh Process lock — no
        // self-deadlock (the PT work ran with no Process lock held).
        {
            let proc = process.lock();
            let mut mm = mm_arc.lock();
            if mm.brk != old_brk {
                // DEAD under the brk reservation: brk_in_progress pins mm.brk to old_brk
                // for the whole lock-dropped window (a sibling brk early-returns on the
                // brk_in_progress guard; exec rejects shared-VM; fork is EAGAIN mid-brk).
                // Retained as R162-2 defense-in-depth — charge NOTHING for PT (Template-C
                // ride-to-teardown, over-count-safe) and uncharge only the stale DATA
                // growth. Capture brk + cgroup_id BEFORE drop(mm) (no second MmState
                // lock); do NOT disarm brk_resv (let BrkReservation::Drop clear the flag).
                debug_assert!(
                    false,
                    "brk moved under reservation — impossible (brk_in_progress pins it)"
                );
                // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
                mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
                let current_brk = mm.brk;
                let rollback_cgroup_id = proc.cgroup_id;
                drop(mm);
                cgroup::uncharge_memory(rollback_cgroup_id, grow_size as u64);
                return Ok(current_brk);
            }
            mm.brk = addr;
            // R163-9 FIX: saturating_sub to preserve concurrent brk pending.
            mm.brk_pending_growth = mm.brk_pending_growth.saturating_sub(grow_size as u64);
            mm.vm_charged_bytes = mm
                .vm_charged_bytes
                .saturating_add(grow_size as u64);
            // M2-1 SLICE-4b: SOFT/forced PT-frame kmem charge, after-the-fact (the PT
            // count is knowable only after map_page ran — IM-15), migration-atomic under
            // this Process+MmState hold. record_pt_charge does the per-AS frame-identity
            // ledger insert + INVARIANT-I' bookkeeping (with OOM fallback to
            // pt_inherited_bytes). charge_memory_forced/uncharge_memory take only
            // CGROUP_REGISTRY + atomics (never Process/MmState), so this is deadlock-free
            // under the held locks (same as sys_mmap Phase-3). The live tables reclaim via
            // the 4c shrink prune+reconcile or last-exit teardown.
            if pt_bytes > 0 {
                cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
                mm.record_pt_charge(&pt_frames);
            }
            // R165-1/R165-2 FIX: release the brk reservation under the commit lock.
            mm.brk_in_progress = false;
            brk_resv.armed = false;
        }

        // D3-ARC-MM-SHARED: sync_vm_siblings_brk is no longer needed — all
        // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

        Ok(addr)
    }
    // 堆收缩
    else if new_top < old_top {
        let shrink_size = old_top - new_top;

        // 释放锁后进行解映射操作
        drop(proc);

        // R126-1 FIX: 3-phase unmap matching sys_munmap() pattern for COW safety
        // M2-1 SLICE-4c: the closure now ALSO yields the reclaimed empty PT/PD TABLE
        // frames (NOT freed here) so the folded commit below can remove them from the
        // per-AS ledger BEFORE they are published to the buddy (free-after-remove),
        // mirroring sys_munmap Phase-2/3. This pairs with SLICE-4b: a brk-grown ledgered
        // PT frame is now debited here on shrink instead of riding to teardown.
        let table_frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame> = unsafe {
            use x86_64::structures::paging::PhysFrame;
            with_current_manager(VirtAddr::new(0), |manager| -> alloc::vec::Vec<PhysFrame> {
                let mut frame_alloc = FrameAllocator::new();
                // R159-2 FIX: Fallible frames_to_free (same pattern as R159-1/R158-7).
                let mut frames_to_free = Vec::new();
                let _ = frames_to_free.try_reserve(shrink_size / PAGE_SIZE);

                for offset in (0..shrink_size).step_by(PAGE_SIZE) {
                    let vaddr = VirtAddr::new((new_top + offset) as u64);
                    let page = Page::containing_address(vaddr);

                    // R142-2 FIX: Mirror sys_munmap() fallback for non-present PTEs.
                    let frame_opt = match manager.unmap_page(page) {
                        Ok(frame) => Some(frame),
                        Err(mm::page_table::UnmapError::PageNotMapped) => {
                            manager.take_nonpresent_leaf_frame(page)
                        }
                        Err(_) => None,
                    };

                    if let Some(frame) = frame_opt {
                        let phys_addr = frame.start_address().as_u64() as usize;

                        let should_free = if PAGE_REF_COUNT.get(phys_addr) > 0 {
                            PAGE_REF_COUNT.decrement(phys_addr) == 0
                        } else {
                            true
                        };

                        if should_free {
                            if frames_to_free.try_reserve(1).is_ok() {
                                frames_to_free.push(frame);
                            } else {
                                mm::flush_current_as_page(page.start_address());
                                frame_alloc.deallocate_frame(frame);
                            }
                        }
                    }
                }

                if !frames_to_free.is_empty() {
                    mm::flush_current_as_range(VirtAddr::new(new_top as u64), shrink_size);
                    for frame in frames_to_free {
                        frame_alloc.deallocate_frame(frame);
                    }
                }

                // M2-1 SLICE-4c: reclaim the now-empty intermediate PT/PD tables this
                // shrink emptied — but DO NOT free them here. prune clears the parent
                // entries + issues the all-CPU paging-structure shootdown under PT_LOCK
                // (clear -> flush stays in this phase); the carried frames are published
                // to the buddy strictly AFTER the folded commit removes them from the
                // per-AS ledger (free-after-remove).
                let mut table_frames: alloc::vec::Vec<PhysFrame> = alloc::vec::Vec::new();
                let _ = table_frames.try_reserve((shrink_size / 0x20_0000) + 2);
                manager.prune_empty_tables_in_range(
                    VirtAddr::new(new_top as u64),
                    shrink_size,
                    &mut table_frames,
                );
                table_frames
            })
        };

        // M2-1 SLICE-4c: a leak-safe carrier for the reclaimed PT/PD table frames. They
        // are published to the buddy ONLY after the folded commit removes them from the
        // per-AS ledger (free-after-remove); on any early-return/panic before the explicit
        // drain, Drop frees them so a carried frame can never leak (mirrors sys_munmap).
        struct TableFrameReclaim {
            frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
            drained: bool,
        }
        impl Drop for TableFrameReclaim {
            fn drop(&mut self) {
                if !self.drained && !self.frames.is_empty() {
                    let mut fa = mm::memory::FrameAllocator::new();
                    for f in self.frames.drain(..) {
                        fa.deallocate_frame(f);
                    }
                }
            }
        }
        let mut reclaim = TableFrameReclaim {
            frames: table_frames,
            drained: false,
        };

        // R164-1 FIX: Re-verify mm.brk == old_brk at shrink commit, matching
        // the grow path (R162-2).
        // M2-1 SLICE-4c: fold the DATA uncharge AND the per-AS PT-ledger reconcile into
        // ONE Process+MmState critical section (canonical Process -> MmState order, exactly
        // like sys_munmap Phase-3) so both land atomically w.r.t. cgroup migration (which
        // snapshots compute_cgroup_charged_bytes — including pt_charged_bytes — under the
        // Process lock, R155-5). The prior code uncharged DATA in a SEPARATE process.lock()
        // AFTER the mm-only commit, leaving a migration split; folding both closes it.
        // cgroup uncharge runs with PT_LOCK already dropped (sanctioned under the Process
        // lock; never under PT_LOCK).
        {
            let proc = process.lock();
            let mut mm = mm_arc.lock();
            let cgroup_id = proc.cgroup_id;
            // PT leg (computed once, applied in whichever arm runs): reconcile the ledger
            // with the frames prune reclaimed — debit a reclaimed frame IFF this AS charged
            // it (frame-identity provenance; an UNCHARGED inherited frame is correctly NOT
            // debited). Skipped while the ledger is non-authoritative (a forked child's
            // inherited basis rides to teardown). The ledger removal happens HERE, strictly
            // before the frames are published to the buddy below (free-after-remove).
            let pt_freed = if mm.pt_ledger_authoritative {
                let freed = crate::process::pt_ledger_reconcile(
                    &mut mm.pt_charged_frames,
                    reclaim.frames.iter().map(|f| f.start_address().as_u64()),
                );
                if freed > 0 {
                    mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(freed);
                }
                freed
            } else {
                0
            };
            if mm.brk != old_brk {
                // Concurrent brk changed mm.brk while we were unmapping. Our unmapped pages
                // were in [new_top, old_top) below old_brk, so they don't overlap concurrent
                // growth. The DATA charge for these freed pages must still be released (the
                // frames were already deallocated). reclaim stays armed; its Drop publishes
                // the table frames to the buddy AFTER this ledger removal (free-after-remove).
                mm.vm_charged_bytes = mm
                    .vm_charged_bytes
                    .saturating_sub(shrink_size as u64);
                let current_brk = mm.brk;
                cgroup::uncharge_memory(cgroup_id, shrink_size as u64);
                if pt_freed > 0 {
                    cgroup::uncharge_memory(cgroup_id, pt_freed);
                }
                return Ok(current_brk);
            }
            mm.brk = addr;
            mm.vm_charged_bytes = mm
                .vm_charged_bytes
                .saturating_sub(shrink_size as u64);
            cgroup::uncharge_memory(cgroup_id, shrink_size as u64);
            if pt_freed > 0 {
                cgroup::uncharge_memory(cgroup_id, pt_freed);
            }
            // R165-1 FIX: release the brk reservation under the commit lock.
            mm.brk_in_progress = false;
            brk_resv.armed = false;
        }

        // M2-1 SLICE-4c: NOW publish the reclaimed table frames to the buddy — strictly
        // AFTER the ledger removal above (free-after-remove). In the window a frame becomes
        // buddy-reusable it is already gone from the ledger and pt_charged_bytes, so a
        // concurrent re-allocator that obtains it re-records it fresh.
        {
            let mut fa = FrameAllocator::new();
            for f in reclaim.frames.drain(..) {
                fa.deallocate_frame(f);
            }
            reclaim.drained = true;
        }

        Ok(addr)
    }
    // 同一页内调整，只更新 brk 值
    else {
        let mut mm = mm_arc.lock();
        mm.brk = addr;
        // R165-1 FIX: release the brk reservation under the same lock.
        mm.brk_in_progress = false;
        brk_resv.armed = false;
        Ok(addr)
    }
}

/// R171-CG1x0 FIX (M2-1 SLICE-0; hoisted to module scope by M2-1 SLICE-4a): a
/// frame-allocator shim that RECORDS THE IDENTITY of every intermediate
/// PT/PD/PDPT frame `map_to`/`map_page` pulls via `create_next_table`, so the
/// per-AS provenance ledger (`MmState.pt_charged_frames`) can later uncharge a
/// reclaimed page-table frame IFF the AS charged it (defeating the cross-origin
/// `memory.max` bypass).
///
/// Hoisted from a `sys_mmap`-local definition so every EAGER PT-building syscall
/// path (mmap; mprotect Path-A; later brk/exec) shares ONE audited shim. The
/// DATA/PT split is by CALL PATH, not a counter: the explicit per-page DATA frame
/// the caller pulls goes through the INHERENT `allocate_data_frame` (never
/// recorded — it is not page-table memory); the PT/PD/PDPT frames `map_to` pulls
/// go through the TRAIT `allocate_frame` (recorded by physical address). `map_to`
/// allocates an intermediate frame ONLY for an `is_unused()` level (the
/// `create_next_table` guard), so `pt_frames` is EXACTLY the newly-built
/// page-table frames — frame identity, not a fungible count. The trait body
/// RESERVES the ledger slot BEFORE pulling from the buddy: on `try_reserve`
/// failure it returns None WITHOUT allocating, so `map_to` fails and the caller's
/// existing rollback fires — there is never an unrecorded LIVE PT frame
/// (fail-closed). `deallocate_frame` never touches `pt_frames` (rollback frees
/// must not perturb the recorded set; `pt_frames` is consumed only on the Ok
/// path). Both allocate bodies delegate to `self.inner` (never
/// `Self::allocate_frame`) to avoid inherent/trait recursion. `inner` is spelled
/// fully-qualified `mm::memory::FrameAllocator` so it cannot silently resolve to
/// a different ambient type after the hoist.
pub(crate) struct RecordingFrameAllocator {
    inner: mm::memory::FrameAllocator,
    pt_frames: vec::Vec<x86_64::structures::paging::PhysFrame>,
}
impl RecordingFrameAllocator {
    /// Construct over a fresh buddy frame allocator with an empty PT-frame record.
    pub(crate) fn new() -> Self {
        Self {
            inner: mm::memory::FrameAllocator::new(),
            pt_frames: vec::Vec::new(),
        }
    }
    /// Explicit DATA-frame allocation (per-page in a map loop): NOT recorded —
    /// data frames are not page-table kmem and must not enter the ledger.
    /// M2-1 SLICE-4d: pub(crate) so the ELF loader (a sibling module) can pull DATA
    /// frames through the SAME audited shim and keep the DATA/PT split intact.
    pub(crate) fn allocate_data_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame> {
        self.inner.allocate_frame()
    }
    /// M2-1 SLICE-4d: pub(crate) so the ELF loader's map-fail rollback can free a DATA
    /// frame through the shim (never perturbs the recorded `pt_frames`).
    pub(crate) fn deallocate_frame(&mut self, frame: x86_64::structures::paging::PhysFrame) {
        self.inner.deallocate_frame(frame);
    }
    /// M2-1 SLICE-4d: consume the recorder and return the recorded PT/PD/PDPT frame
    /// identities. A cross-module accessor (the `pt_frames` field stays private) so the
    /// ELF loader can fold the recorded frames into ElfLoadResult without touching the
    /// field directly. Call ONLY on the Ok path — every helper frees its own DATA frames
    /// on error and, on exec failure, the whole new AS (incl. these tables) is torn down
    /// by free_address_space, so the dropped recorder leaks nothing.
    pub(crate) fn take_pt_frames(self) -> vec::Vec<x86_64::structures::paging::PhysFrame> {
        self.pt_frames
    }
}
unsafe impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>
    for RecordingFrameAllocator
{
    fn allocate_frame(
        &mut self,
    ) -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>>
    {
        // Reserve the ledger slot BEFORE pulling a frame from the buddy. On OOM
        // return None without allocating: `map_to` then fails and the caller's
        // existing rollback runs — no unrecorded live PT frame can exist (fail-closed).
        if self.pt_frames.try_reserve(1).is_err() {
            return None;
        }
        let f = self.inner.allocate_frame();
        if let Some(frame) = f {
            self.pt_frames.push(frame); // cannot fail: capacity reserved above
        }
        f
    }
}

/// M2-1 SLICE-4b: regression guard for the LOAD-BEARING DATA/PT split in
/// `RecordingFrameAllocator`. The inherent `allocate_data_frame` must NOT record (heap /
/// ELF-segment / stack DATA pages are not page-table kmem), while the trait
/// `allocate_frame` (the path `map_page` pulls for intermediate tables) MUST record by
/// frame identity. A mis-wire routing a DATA pull through the trait would record every
/// data page as a PT frame (~512x over-charge + a corrupt ledger whose data-frame keys a
/// later `pt_ledger_reconcile` would debit as PT). This guards the brk-grow / exec
/// DATA/PT swap — the single most error-prone seam of M2-1 SLICE-4. Lives in `syscall.rs`
/// because it touches the module-private `allocate_data_frame` / `pt_frames`.
pub fn run_recording_frame_allocator_split_self_test() {
    let mut fa = RecordingFrameAllocator::new();
    // DATA frame via the inherent method: must NOT be recorded.
    let d = fa
        .allocate_data_frame()
        .expect("buddy frame for DATA self-test");
    assert_eq!(fa.pt_frames.len(), 0, "DATA frame must NOT enter the PT ledger");
    // PT frame via the trait method `map_page` uses: must be recorded by identity.
    let p = <RecordingFrameAllocator as x86_64::structures::paging::FrameAllocator<
        x86_64::structures::paging::Size4KiB,
    >>::allocate_frame(&mut fa)
    .expect("buddy frame for PT self-test");
    assert_eq!(fa.pt_frames.len(), 1, "trait allocate_frame MUST record the PT frame");
    assert_eq!(
        fa.pt_frames[0], p,
        "recorded PT frame identity must match the allocation"
    );
    // Cleanup: return both frames to the buddy (deallocate_frame never perturbs pt_frames).
    fa.deallocate_frame(d);
    fa.deallocate_frame(p);
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

    let is_prot_none = prot == PROT_NONE;

    // R32-SC-1 FIX: PROT_NONE (prot=0) should create non-present mapping
    // that faults on access (guard page behavior). Mirror sys_mprotect.
    let mut page_flags = if is_prot_none {
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

    // R121-4 FIX (was R65-9): Three-phase mmap to respect documented lock
    // ordering (PT_LOCK before Process::inner in lock_ordering.rs) while still
    // preventing address-space races.
    //
    // Phase 1 (Process lock): select/validate address, reserve in mmap_regions
    //   with a PENDING_MAP flag so concurrent mmap/munmap see it as occupied.
    // Phase 2 (no Process lock): charge cgroup, then perform PT operations via
    //   with_current_manager() which acquires PT_LOCK.
    // Phase 3 (Process lock): commit (clear pending flag), or rollback on failure.
    let update_next = addr == 0;

    // D3-ARC-MM-SHARED: Phase 1 operates on shared MmState via mm Arc.
    let (base, end, cgroup_id, old_next_mmap_addr, mm_arc) = {
        let mut proc = process.lock();
        let mm_arc = Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        // 选择起始虚拟地址（使用 checked_add 防止溢出）
        // R65-11 FIX: Ensure auto-selected address is at least MMAP_MIN_ADDR
        let base = if addr == 0 {
            let candidate = mm
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

        // R130-1 FIX: Bound mmap_regions to prevent kernel heap exhaustion DoS.
        // Without this check, unlimited PROT_NONE (or normal) mmaps can grow
        // the BTreeMap until alloc_error_handler panics the kernel.
        if mm.mmap_regions.len() >= MAX_MAP_COUNT {
            return Err(SyscallError::ENOMEM);
        }

        // 检查与现有映射的重叠（pending entries also count as occupied）
        for (&region_base, &region_len_with_flags) in mm.mmap_regions.iter() {
            let region_len = mmap_region_len(region_len_with_flags);
            let region_end = region_base
                .checked_add(region_len)
                .ok_or(SyscallError::EFAULT)?;
            if base < region_end && end > region_base {
                return Err(SyscallError::EINVAL);
            }
        }

        // R147-I1 FIX: Charge cgroup memory BEFORE inserting PENDING_MAP entry.
        if !is_prot_none {
            if cgroup::try_charge_memory(proc.cgroup_id, length_aligned as u64).is_err() {
                return Err(SyscallError::ENOMEM);
            }
        }

        // Reserve the region with PENDING_MAP flag before dropping locks.
        let phase1_flags = MMAP_REGION_FLAG_PENDING_MAP
            | if is_prot_none { MMAP_REGION_FLAG_PROT_NONE } else { 0 };
        // next-phase #11: fallible insert. `base` is a new key (overlap-checked
        // above), so this allocates a slot. On OOM, roll back the cgroup charge
        // made for the non-PROT_NONE case before returning ENOMEM — otherwise the
        // charge would leak with no region to account for it.
        if mm
            .mmap_regions
            .try_insert(base, MmapEntry::from_len_flags(length_aligned, phase1_flags))
            .is_err()
        {
            if !is_prot_none {
                cgroup::uncharge_memory(proc.cgroup_id, length_aligned as u64);
            }
            return Err(SyscallError::ENOMEM);
        }

        // Advance next_mmap_addr early so concurrent auto-mmaps don't collide.
        let old_next_mmap_addr = mm.next_mmap_addr;
        if update_next && mm.next_mmap_addr < end {
            mm.next_mmap_addr = end;
        }

        let cgroup_id = proc.cgroup_id;
        drop(mm);
        (base, end, cgroup_id, old_next_mmap_addr, mm_arc)
    }; // Process lock + MmState lock dropped here — Phase 1 complete

    // R123-1 FIX: PROT_NONE is a pure address reservation per POSIX semantics.
    // No physical frames are allocated and no cgroup memory is charged until
    // protections are elevated (e.g. via mprotect) and a page fault triggers
    // demand allocation. The mmap_regions entry is committed with the
    // PROT_NONE flag so munmap/exit know not to uncharge or free frames.
    if is_prot_none {
        let len_with_flags = MmapEntry::prot_none(length_aligned);
        {
            let mut mm = mm_arc.lock();
            debug_validate_mmap_entry(len_with_flags);
            // next-phase #11: `base` is still present from Phase 1 (its
            // PENDING_MAP marker makes concurrent munmap/mprotect/fork bail), so
            // this is an in-place replace that never allocates; map_err keeps the
            // path total even in the impossible-realloc case.
            mm.mmap_regions
                .try_insert(base, len_with_flags)
                .map_err(|_| SyscallError::ENOMEM)?;
            if mm.next_mmap_addr < end {
                mm.next_mmap_addr = end;
            }
        }

        // D3-ARC-MM-SHARED: sync_vm_siblings_add_mmap is no longer needed — all
        // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

        // R159-17 FIX: Gate address-revealing log behind debug_assertions.
        #[cfg(debug_assertions)]
        kprintln!(
            "sys_mmap: pid={}, reserved {} bytes at 0x{:x} (PROT_NONE, no frames)",
            pid, length_aligned, base
        );

        return Ok(base);
    }

    // R147-I1 FIX: Cgroup charge moved into Phase 1 (under process lock, before
    // PENDING_MAP insert). This eliminates the window where migration could
    // snapshot an uncharged PENDING_MAP entry. The old standalone charge call
    // and its rollback are no longer needed.

    // M2-1 SLICE-0 / SLICE-4a: the PT-recording frame allocator is now the
    // module-level `RecordingFrameAllocator` (hoisted above `fn sys_mmap` so
    // mprotect Path-A — and later brk/exec — share one audited shim).

    // 使用基于当前 CR3 的页表管理器进行映射
    // 使用 tracked vector 记录已映射的页，确保失败时完整回滚，避免帧泄漏
    // J2-9: the closure returns the TOTAL frames allocated (data + page-table) so
    // Phase 3 can charge the page-table-frame kmem AFTER PT_LOCK is dropped (the
    // cgroup charge must never run under PT_LOCK — lock_ordering invariant).
    let map_result: Result<vec::Vec<x86_64::structures::paging::PhysFrame>, SyscallError> = unsafe {
        use x86_64::structures::paging::PhysFrame;

        with_current_manager(VirtAddr::new(0), |manager| -> Result<vec::Vec<PhysFrame>, SyscallError> {
            let mut frame_alloc = RecordingFrameAllocator {
                inner: FrameAllocator::new(),
                pt_frames: vec::Vec::new(),
            };
            // 跟踪已成功映射的 (page, frame) 对，用于失败时回滚
            let mut mapped: vec::Vec<(Page, PhysFrame)> = vec::Vec::new();

            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((base + offset) as u64));

                // 分配物理帧，失败时回滚所有已映射的页
                // R171-CG1x0 FIX (M2-1 SLICE-0): the DATA frame uses the inherent
                // `allocate_data_frame` (NOT recorded into the PT ledger); only the
                // intermediate tables `map_page`/`map_to` pull below are recorded.
                let frame = match frame_alloc.allocate_data_frame() {
                    Some(f) => f,
                    None => {
                        // R127-2 + R158-12 FIX: 3-phase rollback; immediate free on OOM.
                        let flush_len = mapped.len() * 0x1000;
                        let mut frames_to_free = vec::Vec::new();
                        let _ = frames_to_free.try_reserve(mapped.len());
                        for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                            if manager.unmap_page(cleanup_page).is_ok() {
                                if frames_to_free.try_reserve(1).is_ok() {
                                    frames_to_free.push(cleanup_frame);
                                } else {
                                    mm::flush_current_as_page(cleanup_page.start_address());
                                    frame_alloc.deallocate_frame(cleanup_frame);
                                }
                            }
                        }
                        // R169-L2 FIX: reclaim the intermediate PT/PD tables the
                        // rolled-back leaves left empty; the frames ride the same
                        // flush+free below (3-phase: clear entry, flush, free).
                        manager.prune_empty_tables_in_range(
                            VirtAddr::new(base as u64),
                            flush_len,
                            &mut frames_to_free,
                        );
                        if !frames_to_free.is_empty() {
                            mm::flush_current_as_range(VirtAddr::new(base as u64), flush_len);
                            for frame in frames_to_free {
                                frame_alloc.deallocate_frame(frame);
                            }
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
                    frame_alloc.deallocate_frame(frame);
                    // R127-2 + R158-12 FIX: 3-phase rollback with fallible Vec.
                    // R169-L2: +1 page so the prune covers the CURRENT page, whose
                    // intermediate tables map_to may have created before failing.
                    let flush_len = (mapped.len() + 1) * 0x1000;
                    let mut frames_to_free = vec::Vec::new();
                    let _ = frames_to_free.try_reserve(mapped.len());
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if manager.unmap_page(cleanup_page).is_ok() {
                            if frames_to_free.try_reserve(1).is_ok() {
                                frames_to_free.push(cleanup_frame);
                            } else {
                                mm::flush_current_as_page(cleanup_page.start_address());
                                frame_alloc.deallocate_frame(cleanup_frame);
                            }
                        }
                    }
                    // R169-L2 FIX: reclaim now-empty intermediate PT/PD tables.
                    manager.prune_empty_tables_in_range(
                        VirtAddr::new(base as u64),
                        flush_len,
                        &mut frames_to_free,
                    );
                    if !frames_to_free.is_empty() {
                        mm::flush_current_as_range(VirtAddr::new(base as u64), flush_len);
                        for frame in frames_to_free {
                            frame_alloc.deallocate_frame(frame);
                        }
                    }
                    return Err(SyscallError::ENOMEM);
                }

                // R156-3 + R158-12 FIX: Fallible push for mmap page tracking.
                if mapped.try_reserve(1).is_err() {
                    if manager.unmap_page(page).is_ok() {
                        mm::flush_current_as_page(page.start_address());
                        frame_alloc.deallocate_frame(frame);
                    }
                    // R169-L2: +1 page — the current page was mapped then locally
                    // unmapped above, so its intermediate tables may now be prunable.
                    let flush_len = (mapped.len() + 1) * 0x1000;
                    let mut frames_to_free = vec::Vec::new();
                    let _ = frames_to_free.try_reserve(mapped.len());
                    for (cleanup_page, cleanup_frame) in mapped.drain(..) {
                        if manager.unmap_page(cleanup_page).is_ok() {
                            if frames_to_free.try_reserve(1).is_ok() {
                                frames_to_free.push(cleanup_frame);
                            } else {
                                mm::flush_current_as_page(cleanup_page.start_address());
                                frame_alloc.deallocate_frame(cleanup_frame);
                            }
                        }
                    }
                    // R169-L2 FIX: reclaim now-empty intermediate PT/PD tables.
                    manager.prune_empty_tables_in_range(
                        VirtAddr::new(base as u64),
                        flush_len,
                        &mut frames_to_free,
                    );
                    if !frames_to_free.is_empty() {
                        mm::flush_current_as_range(VirtAddr::new(base as u64), flush_len);
                        for frame in frames_to_free {
                            frame_alloc.deallocate_frame(frame);
                        }
                    }
                    return Err(SyscallError::ENOMEM);
                }
                mapped.push((page, frame));
            }

            // R171-CG1x0 FIX (M2-1 SLICE-0): yield the recorded PT-frame identities
            // (NOT a count). On every Err path above the closure freed its own
            // frames, so this Vec is meaningful only on the Ok path.
            Ok(frame_alloc.pt_frames)
        })
    };

    // F.2 Cgroup: If mapping fails, rollback the memory charge and Phase 1
    // reservation to maintain correct accounting.
    // R148-2 FIX: Remove reservation under process lock AND capture current
    // cgroup_id, then uncharge with the fresh id. The cached cgroup_id from
    // Phase 1 may be stale if cgroup migration occurred during PT operations.
    // R171-CG1x0 FIX (M2-1 SLICE-0): the closure now yields the IDENTITIES of the
    // page-table frames built on success (the closure freed its own frames on every
    // Err path, so the Vec is meaningful only on Ok).
    let pt_frames = match map_result {
        Err(e) => {
            let rollback_cgroup_id = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                mm.mmap_regions.remove(&base);
                if update_next && mm.next_mmap_addr == end {
                    mm.next_mmap_addr = old_next_mmap_addr;
                }
                proc.cgroup_id
            };
            cgroup::uncharge_memory(rollback_cgroup_id, length_aligned as u64);
            return Err(e);
        }
        Ok(frames) => frames,
    };

    // R171-CG1x0 FIX (M2-1 SLICE-0): the page-table-frame charge is exactly the
    // number of recorded PT/PD/PDPT frame identities — `RecordingFrameAllocator`
    // records only the frames `map_to` pulled for intermediate tables; the leaf
    // DATA frame went through `allocate_data_frame` (unrecorded). No data-page
    // subtraction is needed (the count is already PT-only, by identity).
    let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);

    // Phase 3: Commit the reservation (clear PENDING_MAP) AND record the
    // page-table-frame kmem in the SAME Process-lock critical section. Doing both
    // under the Process lock — the sanctioned Process → MmState → cgroup order,
    // exactly like the Phase-1 DATA charge at the top of this fn — makes this
    // mutually exclusive with cgroup migration, which holds the Process lock
    // across compute_cgroup_charged_bytes + the cgroup_id update (R155-5). So the
    // forced pt charge and the pt_charged_bytes mirror land atomically w.r.t.
    // migration, and no transient mirror field is needed.
    //
    // J2-9: the pt charge is a SOFT / forced charge (charge_memory_forced), NOT a
    // hard try_charge_memory. The page-table-frame count is knowable only AFTER
    // map_to has run (IM-14: "delta known only after the mutation ⇒ soft cap"),
    // and by then the frames physically exist. A hard reject here would have to
    // free the already-built intermediate PT tables (a leak-prone rollback that
    // would ORPHAN them uncharged → a partial memory.max bypass); instead we KEEP
    // and CHARGE them, accepting a bounded overshoot (≤ this one mapping's pt
    // delta, ~1/512 of the data that already passed the Phase-1 HARD gate). The
    // HARD gate on the NEXT allocation re-enforces memory.max, so this is the
    // over-count-safe / never-under-count direction — it cannot bypass memory.max.
    // R144-2 FIX: Store protection bits so procfs /proc/[pid]/maps shows accurate perms.
    let prot_flags = mmap_prot_to_flags(prot);
    let committed_len_with_flags = MmapEntry::from_len_flags(length_aligned, prot_flags);
    {
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        // next-phase #11: `base` is still present from Phase 1 (PENDING_MAP), so
        // this is an in-place replace clearing the flag — no allocation.
        mm.mmap_regions
            .try_insert(base, committed_len_with_flags)
            .map_err(|_| SyscallError::ENOMEM)?;
        // R131-6 FIX: Track per-address-space cgroup DATA charge.
        mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_add(length_aligned as u64);
        if mm.next_mmap_addr < end {
            mm.next_mmap_addr = end;
        }
        // J2-9: record the page-table-frame kmem (forced soft charge) under this
        // same Process lock so the cgroup counter and the per-AS mirror move
        // together and stay consistent with proc.cgroup_id (migration-atomic).
        //
        // R171-CG1x0 FIX (M2-1 SLICE-0): BEFORE charging, record each PT frame's
        // physical identity in the per-AS provenance ledger so a later munmap-prune
        // uncharges a reclaimed frame IFF this mmap charged it — defeating the
        // cross-origin memory.max bypass. The ledger insert runs under THIS same
        // MmState lock that any concurrent munmap of this shared AS must also take,
        // so a sibling cannot remove an entry mid-install. Reserve up front; on a
        // reserve OOM (or the never-firing aliasing safety net) fall back to the
        // untracked `pt_inherited_bytes` basis: those frames then reclaim only at
        // teardown (over-count-safe — restricts the tenant further, never a bypass),
        // and INVARIANT I' (pt_charged_bytes == pt_inherited_bytes +
        // pt_charged_frames.len()*0x1000) is preserved on every branch.
        if pt_bytes > 0 {
            let ledgered = if mm.pt_charged_frames.try_reserve(pt_frames.len()).is_ok() {
                let mut all_fresh = true;
                for f in &pt_frames {
                    match mm.pt_charged_frames.try_insert(f.start_address().as_u64(), ()) {
                        Ok(None) => {}
                        Ok(Some(_)) => {
                            // A frame the allocator just handed out as is_unused()
                            // CANNOT already be ledgered unless free-after-remove
                            // (munmap step) were violated — a never-firing safety
                            // net, NEVER a silent in-place replace.
                            debug_assert!(
                                false,
                                "pt ledger frame aliased — free-after-remove invariant violated"
                            );
                            all_fresh = false;
                        }
                        // Unreachable after a successful try_reserve(len); defensive.
                        Err(_) => {
                            all_fresh = false;
                            break;
                        }
                    }
                }
                all_fresh
            } else {
                false
            };
            cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
            mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_add(pt_bytes);
            if ledgered {
                // This AS now authoritatively tracks its own PT charges by frame.
                if !mm.pt_ledger_authoritative {
                    mm.pt_ledger_authoritative = true;
                }
            } else {
                // OOM / aliasing fallback: drop any partial inserts and carry the
                // bytes in the untracked basis so the ledger stays consistent with
                // INVARIANT I' (these frames reclaim wholesale at teardown).
                for f in &pt_frames {
                    mm.pt_charged_frames.remove(&f.start_address().as_u64());
                }
                mm.pt_inherited_bytes = mm.pt_inherited_bytes.saturating_add(pt_bytes);
            }
        }
    }

    // D3-ARC-MM-SHARED: sync_vm_siblings_add_mmap is no longer needed — all
    // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

    // Note: Memory is already atomically charged via try_charge_memory() above.
    // R77-2 FIX: No separate accounting call needed - charge/uncharge model is complete.

    // R102-10 + R159-17 FIX: Gate address-revealing log behind debug_assertions.
    #[cfg(debug_assertions)]
    kprintln!(
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

    // R121-4 FIX (was R65-9): Three-phase munmap to respect documented lock
    // ordering while preventing concurrent munmap double-free.
    //
    // Phase 1 (Process lock): validate region, mark as PENDING_UNMAP so
    //   concurrent mmap/munmap can't race the PT operations.
    // Phase 2 (no Process lock): perform PT unmap via with_current_manager().
    // Phase 3 (Process lock): remove PCB record and uncharge cgroup.
    // D3-ARC-MM-SHARED: Phase 1 operates on shared MmState via mm Arc.
    let (recorded_length, committed_flags, mm_arc) = {
        let mut proc = process.lock();
        let mm_arc = Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        // 检查该区域是否在 mmap 记录中
        let recorded_len_with_flags = *mm.mmap_regions.get(&addr).ok_or(SyscallError::EINVAL)?;

        // Reject if another operation is already in progress on this region.
        if recorded_len_with_flags.has_transient() {
            return Err(SyscallError::EBUSY);
        }

        let recorded_length = mmap_region_len(recorded_len_with_flags);
        // R123-1 FIX: Capture committed per-region flags (e.g. PROT_NONE) so
        // we can skip cgroup uncharge for regions that were never charged.
        let committed_flags = recorded_len_with_flags.flags();

        // 验证长度匹配
        if recorded_length != length_aligned {
            return Err(SyscallError::EINVAL);
        }

        // R131-2 FIX: Use lsm_process_ctx_from() instead of ProcessCtx::from_current()
        // to avoid deadlock.
        let ctx = lsm_process_ctx_from(&proc);
        if lsm::hook_memory_munmap(&ctx, addr as u64, length_aligned as u64).is_err() {
            return Err(SyscallError::EPERM);
        }

        // Mark as pending-unmap so concurrent mmap/munmap can't race the PT ops.
        // Preserve committed per-region flags (e.g. PROT_NONE) through the operation.
        // next-phase #11: `addr` is the region being unmapped (already present),
        // so setting its PENDING_UNMAP flag is an in-place replace — no alloc.
        mm.mmap_regions
            .try_insert(
                addr,
                MmapEntry::from_len_flags(recorded_length, committed_flags).with_pending_unmap(),
            )
            .map_err(|_| SyscallError::ENOMEM)?;

        // R145-1 FIX: Do NOT capture cgroup_id here — it may change during
        // the lock-drop window (migration).  Re-read under lock in Phase 3.
        drop(mm);
        (recorded_length, committed_flags, mm_arc)
    }; // Process lock + MmState lock dropped here — Phase 1 complete

    // 使用基于当前 CR3 的页表管理器进行取消映射
    // R23-3 fix: 使用两阶段方法 - 先收集帧、做 TLB shootdown、再释放
    // 使用基于当前 CR3 的页表管理器进行取消映射
    // R23-3 fix: 使用两阶段方法 - 先收集帧、做 TLB shootdown、再释放
    // R171-CG1x0 FIX (M2-1 SLICE-0): the closure now yields the reclaimed empty
    // PT/PD TABLE frames (NOT freed here) so Phase 3 can remove them from the per-AS
    // ledger BEFORE they are published to the buddy (free-after-remove).
    let unmap_result: Result<alloc::vec::Vec<x86_64::structures::paging::PhysFrame>, SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<alloc::vec::Vec<x86_64::structures::paging::PhysFrame>, SyscallError> {
            use alloc::vec::Vec;
            use x86_64::structures::paging::PhysFrame;

            let mut frame_alloc = FrameAllocator::new();
            // R159-1 FIX: Fallible frames_to_free with per-page inline-free fallback.
            // Same pattern as R158-7 (mprotect Path B). Prevents kernel panic
            // when munmap runs under OOM — the paradox of needing memory to free memory.
            let mut frames_to_free: Vec<PhysFrame> = Vec::new();
            let _ = frames_to_free.try_reserve(length_aligned / 0x1000);

            for offset in (0..length_aligned).step_by(0x1000) {
                let page = Page::containing_address(VirtAddr::new((addr + offset) as u64));

                // R141-9 FIX: Try normal unmap first. If the page is non-present
                // (e.g. after mprotect(PROT_NONE)), fall back to reclaiming the
                // frame from the raw PTE.
                let frame_opt = match manager.unmap_page(page) {
                    Ok(frame) => Some(frame),
                    Err(mm::page_table::UnmapError::PageNotMapped) => {
                        manager.take_nonpresent_leaf_frame(page)
                    }
                    Err(_) => None,
                };

                if let Some(frame) = frame_opt {
                    let phys_addr = frame.start_address().as_u64() as usize;

                    let should_free = if PAGE_REF_COUNT.get(phys_addr) > 0 {
                        PAGE_REF_COUNT.decrement(phys_addr) == 0
                    } else {
                        true
                    };

                    if should_free {
                        if frames_to_free.try_reserve(1).is_ok() {
                            frames_to_free.push(frame);
                        } else {
                            mm::flush_current_as_page(page.start_address());
                            frame_alloc.deallocate_frame(frame);
                        }
                    }
                }
            }

            // Batch TLB shootdown then deallocate deferred frames
            if !frames_to_free.is_empty() {
                mm::flush_current_as_range(VirtAddr::new(addr as u64), length_aligned);
                for frame in frames_to_free {
                    frame_alloc.deallocate_frame(frame);
                }
            }

            // R171-CG1x0 FIX (M2-1 SLICE-0): reclaim the now-empty intermediate
            // PT/PD tables this unmap left behind — but DO NOT free them to the buddy
            // here. prune clears the parent PDE/PDPTE entries and issues the
            // all-CPU paging-structure shootdown UNDER PT_LOCK (clear→flush stays in
            // Phase 2); the carried frames are published to the buddy strictly AFTER
            // Phase 3 removes them from the per-AS ledger (free-after-remove). Note:
            // this fires prune on the COMMON munmap-empties-a-table path (previously
            // only on the rare OOM-rollback paths) — accepted per Safety > Speed.
            let mut table_frames: Vec<PhysFrame> = Vec::new();
            let _ = table_frames.try_reserve((length_aligned / 0x20_0000) + 2);
            manager.prune_empty_tables_in_range(
                VirtAddr::new(addr as u64),
                length_aligned,
                &mut table_frames,
            );

            Ok(table_frames)
        })
    };

    let table_frames = match unmap_result {
        Ok(tf) => tf,
        Err(e) => {
            // Roll back the PENDING_UNMAP marker so the region remains usable.
            // Preserve committed per-region flags (e.g. PROT_NONE).
            // next-phase #11: `addr` still carries its PENDING_UNMAP marker here, so
            // this is an in-place replace that cannot allocate; ignore the result so
            // the original unmap error `e` is the one returned.
            let _ = mm_arc
                .lock()
                .mmap_regions
                .try_insert(addr, MmapEntry::from_len_flags(recorded_length, committed_flags));
            return Err(e);
        }
    };

    // R171-CG1x0 FIX (M2-1 SLICE-0): a leak-safe carrier for the reclaimed PT/PD
    // table frames. The frames are published to the buddy ONLY after Phase 3 removes
    // them from the per-AS ledger (free-after-remove). On any early-return/panic
    // before the explicit drain, Drop frees them so a carried frame can never leak.
    struct TableFrameReclaim {
        frames: alloc::vec::Vec<x86_64::structures::paging::PhysFrame>,
        drained: bool,
    }
    impl Drop for TableFrameReclaim {
        fn drop(&mut self) {
            if !self.drained && !self.frames.is_empty() {
                let mut fa = mm::memory::FrameAllocator::new();
                for f in self.frames.drain(..) {
                    fa.deallocate_frame(f);
                }
            }
        }
    }
    let mut reclaim = TableFrameReclaim {
        frames: table_frames,
        drained: false,
    };

    // D3-ARC-MM-SHARED + R145-1 + R171-CG1x0 FIX (M2-1 SLICE-0): folded Phase 3 —
    // ONE Process→MmState critical section (canonical order, matching sys_mmap
    // Phase 3) so the region removal, the DATA uncharge, AND the per-AS PT-ledger
    // reconcile all land atomically w.r.t. cgroup migration (which snapshots
    // compute_cgroup_charged_bytes under the Process lock, R155-5). The cgroup
    // uncharges run here with PT_LOCK already dropped — lock_ordering sanctions
    // cgroup helpers under the Process lock; never under PT_LOCK.
    {
        let proc = process.lock();
        let mut mm = mm_arc.lock();
        // Re-read cgroup_id under the lock — migration may have moved us during the
        // lock-free Phase 2 PT work.
        let cgroup_id = proc.cgroup_id;

        // Under shared MmState the first remover wins; a racing CLONE_VM sibling
        // sees the entry gone (the shared Mutex serializes; no double-remove).
        let was_present = mm.mmap_regions.remove(&addr).is_some();

        // DATA leg: uncharge the region bytes only on the first remove and only for
        // a charged (non-PROT_NONE) region.
        if was_present && (committed_flags & MMAP_REGION_FLAG_PROT_NONE) == 0 {
            mm.vm_charged_bytes = mm.vm_charged_bytes.saturating_sub(recorded_length as u64);
            cgroup::uncharge_memory(cgroup_id, length_aligned as u64);
        }

        // PT leg: reconcile the ledger with the frames prune reclaimed. Uncharge a
        // reclaimed frame IFF this AS charged it (on mmap or mprotect Path-A;
        // frame-identity provenance) — never a guessed constant, so an UNCHARGED
        // brk/ELF frame that prune happened to reclaim is correctly NOT debited (defeats the
        // cross-origin memory.max bypass). Skipped while the ledger is
        // non-authoritative (a forked child's inherited basis: empty ledger →
        // nothing to remove; the basis rides to teardown, over-count-safe).
        if mm.pt_ledger_authoritative {
            let pt_freed = crate::process::pt_ledger_reconcile(
                &mut mm.pt_charged_frames,
                reclaim.frames.iter().map(|f| f.start_address().as_u64()),
            );
            if pt_freed > 0 {
                mm.pt_charged_bytes = mm.pt_charged_bytes.saturating_sub(pt_freed);
                cgroup::uncharge_memory(cgroup_id, pt_freed);
            }
        }
    } // Process + MmState locks dropped here.

    // R171-CG1x0 FIX (M2-1 SLICE-0): NOW publish the reclaimed table frames to the
    // buddy — STRICTLY AFTER the ledger removal above. In the window a frame becomes
    // buddy-reusable it is already gone from the ledger and from pt_charged_bytes, so
    // a concurrent re-allocator that obtains it re-records it fresh (mmap Phase-3
    // try_insert ⇒ Ok(None)); there is no window where a live table is
    // buddy-free-and-charged or live-and-uncharged. The free runs lock-free (buddy
    // internal lock only) — zero new lock-ordering edge.
    {
        let mut fa = FrameAllocator::new();
        for f in reclaim.frames.drain(..) {
            fa.deallocate_frame(f);
        }
        reclaim.drained = true;
    }

    // R102-10 + R159-17 FIX: Gate address-revealing log behind debug_assertions.
    #[cfg(debug_assertions)]
    kprintln!(
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

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let is_target_prot_none = prot == PROT_NONE;

    // Phase 0: Under process lock, classify each mmap_regions entry in
    // [addr, end) by its current PROT_NONE status.  This determines whether
    // we need frame allocation (PROT_NONE → real) or frame deallocation
    // (real → PROT_NONE).
    // D3-ARC-MM-SHARED: Phase 0 operates on shared MmState via mm Arc.
    let (prot_none_regions, real_regions, mm_arc) = {
        let proc = process.lock();
        let mm_arc = Arc::clone(&proc.mm);
        let mut mm = mm_arc.lock();

        // R161-10 FIX: Split regions that partially overlap [addr, end) at the
        // boundary points. This ensures the classification loop below only sees
        // entries fully contained within the mprotect range, so Path A/B process
        // exactly the correct pages and bookkeeping updates find entries by key.
        // R162-2-1 FIX: Check MAX_MAP_COUNT before splitting to prevent unbounded
        // region growth via repeated partial-range mprotect calls.
        if mm.mmap_regions.len() + 2 >= MAX_MAP_COUNT {
            return Err(SyscallError::ENOMEM);
        }

        // next-phase #11: the two split blocks below add at most two new boundary
        // keys (`addr`, `end`) — every other insert is an in-place replace of an
        // existing region base. Pre-reserve that capacity so the subsequent
        // try_insert calls cannot fail mid-sequence and leave a half-split map.
        // (Matches the `+ 2` headroom asserted by the MAX_MAP_COUNT check above.)
        mm.mmap_regions
            .try_reserve(2)
            .map_err(|_| SyscallError::ENOMEM)?;

        // Split preceding region whose tail extends into [addr, end).
        // next-phase #11: copy the boundary entry out of the range iterator into
        // an owned Option FIRST so the immutable `range(..)` borrow of
        // `mmap_regions` is released before the `try_insert` mutations below.
        // (`BTreeMap::range` had no drop glue and the borrow ended early; the
        // `FallibleOrderedMap` range iterator must be dropped explicitly via this
        // `let` boundary, else it conflicts with the mutable borrow in the body.)
        let preceding = mm
            .mmap_regions
            .range(..addr)
            .next_back()
            .map(|(&base, &lf)| (base, lf));
        if let Some((prev_base, prev_lf)) = preceding {
            let prev_len = mmap_region_len(prev_lf);
            let prev_end = prev_base.saturating_add(prev_len);
            if prev_end > addr && prev_len > 0 {
                if prev_lf.has_transient() {
                    return Err(SyscallError::EBUSY);
                }
                let prev_flags = prev_lf.flags();
                let left_len = addr - prev_base;
                mm.mmap_regions
                    .try_insert(prev_base, MmapEntry::from_len_flags(left_len, prev_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
                let tail_end = prev_end.min(end);
                let tail_len = tail_end - addr;
                mm.mmap_regions
                    .try_insert(addr, MmapEntry::from_len_flags(tail_len, prev_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
                if prev_end > end {
                    let right_len = prev_end - end;
                    mm.mmap_regions
                        .try_insert(end, MmapEntry::from_len_flags(right_len, prev_flags))
                        .map_err(|_| SyscallError::ENOMEM)?;
                }
            }
        }

        // Split trailing region that starts in [addr, end) but extends past end.
        // next-phase #11: same as above — hoist the range lookup into an owned
        // Option so the immutable borrow ends before the try_insert mutations.
        let trailing = mm
            .mmap_regions
            .range(addr..end)
            .next_back()
            .map(|(&base, &lf)| (base, lf));
        if let Some((last_base, last_lf)) = trailing {
            let last_len = mmap_region_len(last_lf);
            let last_end = last_base.saturating_add(last_len);
            if last_end > end && last_len > 0 {
                if last_lf.has_transient() {
                    return Err(SyscallError::EBUSY);
                }
                let last_flags = last_lf.flags();
                let in_range_len = end - last_base;
                let right_len = last_end - end;
                mm.mmap_regions
                    .try_insert(last_base, MmapEntry::from_len_flags(in_range_len, last_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
                mm.mmap_regions
                    .try_insert(end, MmapEntry::from_len_flags(right_len, last_flags))
                    .map_err(|_| SyscallError::ENOMEM)?;
            }
        }

        let mut prot_none_regions: Vec<(usize, usize)> = Vec::new();
        let mut real_regions: Vec<(usize, usize)> = Vec::new();
        let region_count = mm.mmap_regions.range(addr..end).count();
        if prot_none_regions.try_reserve(region_count).is_err()
            || real_regions.try_reserve(region_count).is_err()
        {
            return Err(SyscallError::ENOMEM);
        }

        // R158-17 FIX: Track coverage to detect unmapped gaps in [addr, end).
        let mut coverage = addr;

        for (&region_base, &len_with_flags) in mm.mmap_regions.range(addr..end) {
            let region_len = mmap_region_len(len_with_flags);

            if region_len > 0 && region_base > coverage {
                return Err(SyscallError::ENOMEM);
            }

            if len_with_flags.has_transient() {
                return Err(SyscallError::EBUSY);
            }

            if region_len == 0 {
                continue;
            }

            let region_end = region_base.saturating_add(region_len);
            if region_end > coverage {
                coverage = region_end;
            }

            if len_with_flags.is_prot_none() {
                prot_none_regions.push((region_base, region_len));
            } else {
                real_regions.push((region_base, region_len));
            }
        }

        // R158-17: Verify full coverage of [addr, end).
        if coverage < end {
            return Err(SyscallError::ENOMEM);
        }

        drop(mm);
        (prot_none_regions, real_regions, mm_arc)
    };

    // D3-ARC-MM-SHARED: sync_vm_siblings_split_region is no longer needed — all
    // CLONE_VM siblings share the same MmState via Arc<Mutex<MmState>>.

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

    let new_prot_flags = mmap_prot_to_flags(prot);

    // ---------------------------------------------------------------
    // Path A — PROT_NONE → real permissions:
    // Allocate frames, charge cgroup, clear PROT_NONE flag.
    //
    // R146-3 NOTE: If mprotect spans multiple PROT_NONE regions and a later
    // region fails (cgroup charge exhaustion or frame allocation failure),
    // earlier regions that were successfully committed are NOT rolled back.
    // POSIX mprotect(2) allows indeterminate state on error ("if the call
    // fails, some of the address space may have been changed"), so this is
    // not a spec violation. Callers MUST NOT assume all-or-nothing atomicity
    // for multi-region mprotect operations.
    // ---------------------------------------------------------------
    if !is_target_prot_none && !prot_none_regions.is_empty() {
        for &(region_base, region_len) in &prot_none_regions {
            // Step 1: Charge cgroup for the reservation being materialized.
            //
            // R147-1 FIX: Record the in-flight charge under the process lock so
            // compute_cgroup_charged_bytes() includes it during cgroup migration.
            // Read cgroup_id fresh (not from Phase 0) in case migration occurred.
            {
                let proc = process.lock();
                let cgroup_id = proc.cgroup_id;
                if cgroup::try_charge_memory(cgroup_id, region_len as u64).is_err() {
                    return Err(SyscallError::ENOMEM);
                }
                let mut mm = mm_arc.lock();
                // R162-3 FIX: Accumulate instead of overwrite to prevent concurrent
                // mprotect operations from clobbering each other's pending charge.
                mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                    .saturating_add(region_len as u64);
                // R149-6 FIX: Set transient flag so concurrent munmap sees
                // the in-flight mprotect and returns EBUSY.
                // R164-2 FIX: Check if PENDING_MPROTECT is already set by a
                // concurrent mprotect on the same region. Without this, two
                // CLONE_VM threads can both charge cgroup and proceed to PT
                // ops, then one's rollback clears the flag, causing the
                // other's commit check to fail — leaking frames.
                if let Some(entry) = mm.mmap_regions.get_mut(&region_base) {
                    if entry.is_pending_mprotect() {
                        mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                            .saturating_sub(region_len as u64);
                        drop(mm);
                        let cgroup_id = proc.cgroup_id;
                        drop(proc);
                        cgroup::uncharge_memory(cgroup_id, region_len as u64);
                        return Err(SyscallError::EBUSY);
                    }
                    // next-phase #11 (symmetric with R168 Path B / IM-12): the
                    // MmState lock was FREE between Phase-0 classification and this
                    // claim, so a concurrent op on a CLONE_VM sibling may have
                    // (a) demoted this region away from PROT_NONE, (b) marked it
                    // transient — a racing munmap's PENDING_UNMAP or mmap's
                    // PENDING_MAP — or (c) split/resized it so the live length no
                    // longer matches the stale Phase-0 `region_len`. Committing
                    // Path A with that stale length would rewrite a wrong-length
                    // entry (overlapping a neighbour) AND over-charge the cgroup.
                    // Re-validate the live entry against the snapshot exactly as
                    // Path B does; on any mismatch roll back THIS region's charge
                    // and skip it (POSIX mprotect permits partial application).
                    // After we set PENDING_MPROTECT, concurrent split/munmap both
                    // bail on has_transient() for the entire Step 2 window, so
                    // `region_len` is guaranteed to remain the live length through
                    // the Step 3 commit below.
                    if !entry.is_prot_none()
                        || entry.has_transient()
                        || entry.len() != region_len
                    {
                        mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                            .saturating_sub(region_len as u64);
                        drop(mm);
                        drop(proc);
                        cgroup::uncharge_memory(cgroup_id, region_len as u64);
                        continue;
                    }
                    entry.set_pending_mprotect();
                } else {
                    // Region vanished between Phase 0 classification and here;
                    // roll back the charge and fail.
                    // R162-3 FIX: Decrement instead of zeroing to preserve
                    // other concurrent mprotect operations' pending charges.
                    mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                        .saturating_sub(region_len as u64);
                    drop(mm);
                    drop(proc);
                    cgroup::uncharge_memory(cgroup_id, region_len as u64);
                    return Err(SyscallError::EFAULT);
                }
            }

            // Step 2: Allocate zeroed frames + map pages.
            // Uses same pattern as sys_mmap with 3-phase rollback on failure.
            let map_result: Result<vec::Vec<x86_64::structures::paging::PhysFrame>, SyscallError> = unsafe {
                use x86_64::structures::paging::PhysFrame;

                // M2-1 SLICE-4a: use the PT-recording allocator (lifted module-level
                // shim) so the intermediate PT/PD frames map_to builds for this
                // PROT_NONE -> real materialization are charged + ledgered at the
                // Step-3 commit, mirroring sys_mmap. The DATA frame uses the inherent
                // allocate_data_frame (NOT recorded); only map_page's trait
                // allocate_frame records PT/PD frames.
                with_current_manager(VirtAddr::new(0), |manager| -> Result<vec::Vec<PhysFrame>, SyscallError> {
                    let mut frame_alloc = RecordingFrameAllocator::new();
                    let mut mapped: vec::Vec<(Page, PhysFrame)> = vec::Vec::new();

                    for offset in (0..region_len).step_by(0x1000) {
                        let page = Page::containing_address(
                            VirtAddr::new((region_base + offset) as u64),
                        );

                        let frame = match frame_alloc.allocate_data_frame() {
                            Some(f) => f,
                            None => {
                                // R159-4 FIX: Fallible rollback (same pattern as R158-7).
                                let flush_len = mapped.len() * 0x1000;
                                let mut frames_to_free = vec::Vec::new();
                                let _ = frames_to_free.try_reserve(mapped.len());
                                for (cp, cf) in mapped.drain(..) {
                                    if manager.unmap_page(cp).is_ok() {
                                        if frames_to_free.try_reserve(1).is_ok() {
                                            frames_to_free.push(cf);
                                        } else {
                                            mm::flush_current_as_page(cp.start_address());
                                            frame_alloc.deallocate_frame(cf);
                                        }
                                    }
                                }
                                // R169-L2 FIX: reclaim now-empty intermediate PT/PD tables.
                                manager.prune_empty_tables_in_range(
                                    VirtAddr::new(region_base as u64),
                                    flush_len,
                                    &mut frames_to_free,
                                );
                                if !frames_to_free.is_empty() {
                                    mm::flush_current_as_range(
                                        VirtAddr::new(region_base as u64),
                                        flush_len,
                                    );
                                    for f in frames_to_free {
                                        frame_alloc.deallocate_frame(f);
                                    }
                                }
                                return Err(SyscallError::ENOMEM);
                            }
                        };

                        // Security: zero new frame to prevent data leakage.
                        let virt = mm::phys_to_virt(frame.start_address());
                        core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 0x1000);

                        if let Err(_) = manager.map_page(page, frame, flags, &mut frame_alloc) {
                            frame_alloc.deallocate_frame(frame);
                            // R159-4 FIX: Fallible rollback.
                            // R169-L2: +1 page so the prune covers the CURRENT page,
                            // whose tables map_to may have created before failing.
                            let flush_len = (mapped.len() + 1) * 0x1000;
                            let mut frames_to_free = vec::Vec::new();
                            let _ = frames_to_free.try_reserve(mapped.len());
                            for (cp, cf) in mapped.drain(..) {
                                if manager.unmap_page(cp).is_ok() {
                                    if frames_to_free.try_reserve(1).is_ok() {
                                        frames_to_free.push(cf);
                                    } else {
                                        mm::flush_current_as_page(cp.start_address());
                                        frame_alloc.deallocate_frame(cf);
                                    }
                                }
                            }
                            // R169-L2 FIX: reclaim now-empty intermediate PT/PD tables.
                            manager.prune_empty_tables_in_range(
                                VirtAddr::new(region_base as u64),
                                flush_len,
                                &mut frames_to_free,
                            );
                            if !frames_to_free.is_empty() {
                                mm::flush_current_as_range(
                                    VirtAddr::new(region_base as u64),
                                    flush_len,
                                );
                                for f in frames_to_free {
                                    frame_alloc.deallocate_frame(f);
                                }
                            }
                            return Err(SyscallError::ENOMEM);
                        }

                        // R157-5 FIX: Fallible push (same pattern as R157-1/R156-3).
                        if mapped.try_reserve(1).is_err() {
                            if manager.unmap_page(page).is_ok() {
                                mm::flush_current_as_page(page.start_address());
                                frame_alloc.deallocate_frame(frame);
                            }
                            // R159-4 FIX: Fallible rollback.
                            // R169-L2: +1 page — the current page was mapped then
                            // locally unmapped; its tables may now be prunable.
                            let flush_len = (mapped.len() + 1) * 0x1000;
                            let mut frames_to_free = vec::Vec::new();
                            let _ = frames_to_free.try_reserve(mapped.len());
                            for (cp, cf) in mapped.drain(..) {
                                if manager.unmap_page(cp).is_ok() {
                                    if frames_to_free.try_reserve(1).is_ok() {
                                        frames_to_free.push(cf);
                                    } else {
                                        mm::flush_current_as_page(cp.start_address());
                                        frame_alloc.deallocate_frame(cf);
                                    }
                                }
                            }
                            // R169-L2 FIX: reclaim now-empty intermediate PT/PD tables.
                            manager.prune_empty_tables_in_range(
                                VirtAddr::new(region_base as u64),
                                flush_len,
                                &mut frames_to_free,
                            );
                            if !frames_to_free.is_empty() {
                                mm::flush_current_as_range(
                                    VirtAddr::new(region_base as u64),
                                    flush_len,
                                );
                                for f in frames_to_free {
                                    frame_alloc.deallocate_frame(f);
                                }
                            }
                            return Err(SyscallError::ENOMEM);
                        }
                        mapped.push((page, frame));
                    }

                    // M2-1 SLICE-4a: yield the recorded PT-frame identities (NOT a
                    // count) for the Step-3 charge + ledger fold. On every Err path
                    // above the closure freed its own frames, so this Vec is
                    // meaningful only on the Ok path.
                    Ok(frame_alloc.pt_frames)
                })
            };

            // M2-1 SLICE-4a: capture the recorded PT-frame identities on success
            // (consumed by the Step-3 commit fold). The Err arm is the pre-existing
            // rollback, unchanged: the Step-2 closure already freed its PT frames on
            // every error path, so there is nothing to uncharge here.
            let pt_frames = match map_result {
                Err(e) => {
                    // R146-2 FIX: Re-read cgroup_id under lock before rollback uncharge.
                    // R147-1 FIX: Clear mprotect_pending_bytes before uncharge.
                    let rollback_cgroup_id = {
                        let proc = process.lock();
                        let mut mm = mm_arc.lock();
                        mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                            .saturating_sub(region_len as u64);
                        // R149-6 FIX: Clear the transient mprotect flag on rollback.
                        if let Some(entry) = mm.mmap_regions.get_mut(&region_base) {
                            entry.clear_pending_mprotect();
                        }
                        proc.cgroup_id
                    };
                    cgroup::uncharge_memory(rollback_cgroup_id, region_len as u64);
                    return Err(e);
                }
                Ok(frames) => frames,
            };

            // Step 3: Commit bookkeeping — clear PROT_NONE, set prot bits,
            // track charge.
            //
            // R149-6 FIX: Verify the entry still exists and has our transient
            // PENDING_MPROTECT flag. If the entry was removed (e.g., by a
            // concurrent munmap that raced before we set the flag — should be
            // impossible with the flag, but defensive), roll back the charge
            // instead of silently re-inserting a ghost entry.
            // M2-1 SLICE-4a: the PT-frame kmem charge for the frames map_to built
            // for this region (frame identity, recorded above by
            // RecordingFrameAllocator). The fold runs in the committing arm below,
            // under BOTH the Process and MmState locks (canonical Process -> MmState
            // order). The PRE-SLICE-4a commit took ONLY mm_arc.lock(); folding a
            // cgroup charge there would race a concurrent sys_cgroup_attach (which
            // snapshots compute_cgroup_charged_bytes — INCLUDING pt_charged_bytes —
            // under the Process lock) and strand the PT charge + its mem_pinned pin
            // on a stale cgroup. Holding the Process lock across the fold closes that
            // window — exactly as sys_mmap Phase-3 does.
            let pt_bytes = (pt_frames.len() as u64).saturating_mul(0x1000);
            let commit_result: Result<MmapEntry, ()> = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                match mm.mmap_regions.get(&region_base).copied() {
                    Some(old) if old.is_pending_mprotect() => {
                        // Entry present with our transient flag — commit.
                        // Clear PROT_NONE + old prot bits + transient mprotect flag.
                        let preserved = old.committed_flags_excluding_prot();
                        let new_entry = MmapEntry::from_len_flags(region_len, preserved | new_prot_flags);
                        // next-phase #11: `region_base` is present (matched just
                        // above under this same lock hold), so replace in place —
                        // get_mut cannot allocate, keeping this commit infallible.
                        if let Some(slot) = mm.mmap_regions.get_mut(&region_base) {
                            *slot = new_entry;
                        }
                        mm.vm_charged_bytes = mm
                            .vm_charged_bytes
                            .saturating_add(region_len as u64);
                        // R147-1 FIX: Charge is now reflected in mmap_regions.
                        mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                            .saturating_sub(region_len as u64);
                        // M2-1 SLICE-4a: charge + ledger the PT-frame kmem this
                        // PROT_NONE -> real materialization built, under the SAME
                        // Process + MmState hold (migration-atomic). charge_memory_forced
                        // is the SOFT/forced charge (the PT delta is knowable only after
                        // map_to ran; a hard reject would orphan already-built tables
                        // uncharged = a worse bypass). record_pt_charge does the per-AS
                        // ledger + INVARIANT-I' bookkeeping (the unit-tested mirror of
                        // the sys_mmap Phase-3 fold). Reclaim rides this region's
                        // eventual munmap Phase-3 fold (pt_ledger_reconcile, frame
                        // identity) or last-exit teardown.
                        if pt_bytes > 0 {
                            cgroup::charge_memory_forced(proc.cgroup_id, pt_bytes);
                            mm.record_pt_charge(&pt_frames);
                        }
                        Ok(new_entry)
                    }
                    _ => {
                        // Entry gone or flag cleared — concurrent munmap removed it
                        // (defensive: PENDING_MPROTECT blocks that). Roll back the DATA
                        // charge below. M2-1 SLICE-4a: charge + ledger NOTHING for PT
                        // here — the map_to-built frames were never ledgered, so a
                        // concurrent munmap's reconcile debits 0 (no bypass) and they
                        // ride to teardown (over-count-safe). `pt_frames` is dropped.
                        mm.mprotect_pending_bytes = mm.mprotect_pending_bytes
                            .saturating_sub(region_len as u64);
                        Err(())
                    }
                }
            };

            let committed = match commit_result {
                Ok(entry) => entry,
                Err(()) => {
                    // R149-6 FIX: Rollback charge — entry was removed during PT ops.
                    let rollback_cgroup_id = process.lock().cgroup_id;
                    cgroup::uncharge_memory(rollback_cgroup_id, region_len as u64);
                    // Continue with remaining regions (POSIX allows partial success).
                    continue;
                }
            };

            // D3-ARC-MM-SHARED: sync_vm_siblings_mprotect_flags is no longer
            // needed — all CLONE_VM siblings share the same MmState.
            let _ = committed; // suppress unused variable warning
        }
    }

    // ---------------------------------------------------------------
    // Path B — real permissions → PROT_NONE:
    // Unmap/free frames, uncharge cgroup, set PROT_NONE flag.
    // ---------------------------------------------------------------
    if is_target_prot_none && !real_regions.is_empty() {
        for &(region_base, region_len) in &real_regions {
            // R168-1 FIX (found during the D2-MMAP-LIFECYCLE Phase 2 re-land
            // audit): Path B demotes a real region to PROT_NONE by unmapping its
            // frames with the shared MmState lock DROPPED for the page-table
            // work. The previous code set NO transient marker over that window,
            // so a concurrent munmap (or mprotect) on the same MmState (a
            // CLONE_VM sibling) could interleave: capture the region as still
            // real+charged, mark PENDING_UNMAP, drop its lock — and this path's
            // commit would then transition to PROT_NONE and uncharge the cgroup,
            // after which the racing munmap's Phase 3 would uncharge the SAME
            // bytes a SECOND time (cgroup memory_current driven below true usage
            // → memory.max isolation bypass / container DoS). Mirror Path A's
            // proven protocol: claim the entry with PENDING_MPROTECT under the
            // lock BEFORE the unmap, so concurrent munmap / mprotect / fork fail
            // closed on has_transient() for the whole window. The claim is
            // released by the prot_none() commit in Step 3.
            //
            // Path B does NOT touch mprotect_pending_bytes: unlike Path A it does
            // not pre-charge — the region stays charged across the claim window
            // (still non-PROT_NONE, so compute_cgroup_charged_bytes() keeps
            // counting it) and the charge is removed exactly once, at commit.
            //
            // Step 1: Claim the live entry under the lock, re-validating against
            // the Phase-0 snapshot (the lock was free since classification, so a
            // racing op may have demoted / removed / split it in between).
            let claimed = {
                let mut mm = mm_arc.lock();
                match mm.mmap_regions.get_mut(&region_base) {
                    Some(entry) => {
                        if entry.is_prot_none() {
                            // A concurrent mprotect already demoted + uncharged it.
                            false
                        } else if entry.has_transient() {
                            // Another in-flight op (munmap / mprotect) owns it and
                            // will account for it. POSIX permits partial success.
                            false
                        } else if entry.len() != region_len {
                            // R168-2 FIX: region was split/resized in the window;
                            // the stale Phase-0 length no longer matches the live
                            // entry. Skip rather than rewrite a mismatched length.
                            false
                        } else {
                            entry.set_pending_mprotect();
                            true
                        }
                    }
                    None => false, // a concurrent munmap removed + uncharged it.
                }
            };
            if !claimed {
                continue;
            }

            // ---------------------------------------------------------------
            // M2-1 SLICE-4e (DEFERRED — intentional, NOT an oversight): this
            // real -> PROT_NONE demotion deliberately does NOT prune the now-empty
            // intermediate PT/PD tables. The region stays in mmap_regions as
            // PROT_NONE and its tables stay charged in the per-AS ledger; they are
            // reclaimed + frame-identity-reconciled later by sys_munmap Phase-3 (the
            // common path) or wholesale at last-exit / exec teardown
            // (process::free_process_resources). Pruning here would only churn tables a
            // later Path-A re-materialization rebuilds. This is OVER-COUNT-SAFE
            // (charged-but-reserved): never a memory.max bypass and never a leak —
            // reclamation is by page-table-STRUCTURE walk (prune_empty_tables_in_range)
            // + frame-identity reconcile (pt_ledger_reconcile), NOT by mmap_regions
            // membership. See docs/next-phase-plan.md (M2-1 SLICE-4e) for the full
            // 5-path reclamation proof, incl. the forked-child non-authoritative case
            // (pt_ledger_authoritative=false skips the munmap-time debit; the inherited
            // basis rides to wholesale teardown, process.rs free_process_resources).
            // The DEFER adds zero code under PT_LOCK and zero ledger writes under the
            // Step-3 Process+MmState hold — migration-atomicity is untouched.
            // ---------------------------------------------------------------
            // Step 2: Unmap pages and free frames (COW-aware).
            // R158-7 FIX: fallible frames_to_free with immediate free on OOM.
            unsafe {
                use mm::memory::FrameAllocator;

                with_current_manager(VirtAddr::new(0), |manager| {
                    use alloc::vec::Vec;
                    use x86_64::structures::paging::PhysFrame;

                    let mut frame_alloc = FrameAllocator::new();
                    let mut frames_to_free: Vec<PhysFrame> = Vec::new();
                    let _ = frames_to_free.try_reserve(region_len / 0x1000);

                    for offset in (0..region_len).step_by(0x1000) {
                        let page = Page::containing_address(
                            VirtAddr::new((region_base + offset) as u64),
                        );

                        let frame_opt = match manager.unmap_page(page) {
                            Ok(frame) => Some(frame),
                            Err(mm::page_table::UnmapError::PageNotMapped) => {
                                manager.take_nonpresent_leaf_frame(page)
                            }
                            Err(_) => None,
                        };

                        if let Some(frame) = frame_opt {
                            let phys_addr = frame.start_address().as_u64() as usize;
                            let should_free = if PAGE_REF_COUNT.get(phys_addr) > 0 {
                                PAGE_REF_COUNT.decrement(phys_addr) == 0
                            } else {
                                true
                            };
                            if should_free {
                                if frames_to_free.try_reserve(1).is_ok() {
                                    frames_to_free.push(frame);
                                } else {
                                    mm::flush_current_as_page(page.start_address());
                                    frame_alloc.deallocate_frame(frame);
                                }
                            }
                        }
                    }

                    // Batch TLB shootdown then deallocate deferred frames
                    if !frames_to_free.is_empty() {
                        mm::flush_current_as_range(
                            VirtAddr::new(region_base as u64),
                            region_len,
                        );
                        for frame in frames_to_free {
                            frame_alloc.deallocate_frame(frame);
                        }
                    }
                })
            };

            // Step 3: Commit real→PROT_NONE in the shared MmState, releasing the
            // PENDING_MPROTECT claim (prot_none() clears every flag but
            // PROT_NONE). Because we held the claim across the unmap window, the
            // entry is guaranteed present, still our claim, and unchanged in
            // length. Read cgroup_id under the SAME Process→MmState critical
            // section as the vm_charged_bytes decrement (R146-2 pattern) so a
            // concurrent cgroup migration can never split the decrement from its
            // uncharge target. Write the LIVE entry length (R168-2), not the
            // stale Phase-0 region_len.
            let transition = {
                let proc = process.lock();
                let mut mm = mm_arc.lock();
                match mm.mmap_regions.get(&region_base).copied() {
                    Some(old) if old.is_pending_mprotect() => {
                        let live_len = old.len();
                        // next-phase #11: `region_base` is present (matched just
                        // above under this same lock hold), so replace in place —
                        // get_mut cannot allocate, keeping this commit infallible.
                        if let Some(slot) = mm.mmap_regions.get_mut(&region_base) {
                            *slot = MmapEntry::prot_none(live_len);
                        }
                        mm.vm_charged_bytes =
                            mm.vm_charged_bytes.saturating_sub(live_len as u64);
                        Some((proc.cgroup_id, live_len))
                    }
                    _ => {
                        // Unreachable while we hold the claim (munmap / mprotect /
                        // fork all fail closed on has_transient). If the claim
                        // were somehow lost, fail toward OVER-counting (skip the
                        // uncharge) rather than risk the double-uncharge isolation
                        // bypass this fix exists to prevent — the frames were
                        // already freed in Step 2.
                        debug_assert!(
                            false,
                            "mprotect Path B: lost PENDING_MPROTECT claim at {:#x}",
                            region_base
                        );
                        None
                    }
                }
            };

            if let Some((uncharge_cgroup_id, uncharge_len)) = transition {
                cgroup::uncharge_memory(uncharge_cgroup_id, uncharge_len as u64);
            }
        }
    }

    // 更新页表项 (Path C: normal PTE flag update for all pages in range)
    let result: Result<(), SyscallError> = unsafe {
        with_current_manager(VirtAddr::new(0), |manager| -> Result<(), SyscallError> {
            for offset in (0..len_aligned).step_by(0x1000) {
                let page_addr = addr + offset;
                let vaddr = VirtAddr::new(page_addr as u64);
                let page = Page::containing_address(vaddr);

                // R127-1 FIX: Preserve COW semantics. If the page is COW-shared
                // (BIT_9 set by fork), we must NOT make it WRITABLE via mprotect.
                // Instead, preserve the COW marker and keep the page read-only so
                // that the first write triggers the COW fault handler for proper
                // resolution (new frame allocation + copy).
                // Without this check, mprotect(PROT_WRITE) on a COW page would
                // strip BIT_9 and set WRITABLE, allowing direct writes to the
                // shared physical frame — a COW isolation break.
                let mut new_flags = flags;
                if let Some((_phys, current_flags)) = manager.translate_with_flags(vaddr) {
                    if current_flags.contains(PageTableFlags::BIT_9) {
                        new_flags.insert(PageTableFlags::BIT_9);
                        new_flags.remove(PageTableFlags::WRITABLE);
                    }
                }

                // 尝试更新页的保护属性
                // 如果页不存在，跳过（mprotect 只修改已存在的映射）
                if let Err(e) = manager.update_flags(page, new_flags) {
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

    // R145-2 FIX: Update mmap_regions protection display bits to match the
    // new PTE flags.  Path A/B already handled PROT_NONE transitions above;
    // this block updates the prot display bits (READ/WRITE/EXEC) for all
    // regions in [addr, end) so /proc/[pid]/maps shows accurate permissions.
    // For Path A/B regions this is a harmless no-op (bits already correct).
    //
    // R146-8 FIX: Also propagate display-bit updates to CLONE_VM siblings
    // so their /proc/[pid]/maps shows consistent permissions. Collect
    // updated entries and sync after releasing the process lock.
    // D3-ARC-MM-SHARED: Update display bits directly in shared MmState.
    // sync_vm_siblings_mprotect_flags is no longer needed — all CLONE_VM
    // siblings share the same MmState via Arc<Mutex<MmState>>.
    {
        let mut mm = mm_arc.lock();
        for (&_region_base, len_with_flags) in mm.mmap_regions.range_mut(addr..end) {
            len_with_flags.rewrite_prot_bits(new_prot_flags);
        }
    }

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
        kprintln!("[sys_seccomp] TSYNC not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    // R28-8 Fix: Reject NEW_THREADS flag since we don't implement per-new-thread filtering
    // Accepting this flag would make callers believe new threads are sandboxed when they're not.
    if flags & seccomp::SeccompFlags::NEW_THREADS.bits() != 0 {
        kprintln!("[sys_seccomp] NEW_THREADS not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    let filter_flags = seccomp::SeccompFlags::from_bits(flags).ok_or(SyscallError::EINVAL)?;

    // Read program header from userspace
    let mut prog = UserSeccompProg::default();
    // lint-repr-c-copy: allow (no-padding: UserSeccompProg {u32,u32,u64} = 16 bytes; user→kernel)
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

    // R158-3 FIX: Fallible allocation — user-controlled len can exhaust kernel heap.
    let mut raw_insns = Vec::new();
    raw_insns.try_reserve_exact(len).map_err(|_| SyscallError::ENOMEM)?;
    raw_insns.resize(len, UserSeccompInsn::default());
    let raw_bytes =
        unsafe { core::slice::from_raw_parts_mut(raw_insns.as_mut_ptr() as *mut u8, total) };
    copy_from_user(raw_bytes, insn_ptr as *const u8)?;

    // Decode default action
    let default_action = decode_user_action(prog.default_action, 0)?;

    // R158-3 FIX: Fallible allocation for translated program.
    let mut program = Vec::new();
    program.try_reserve_exact(len).map_err(|_| SyscallError::ENOMEM)?;
    for insn in raw_insns.iter() {
        program.push(translate_user_insn(insn)?);
    }

    // Create and validate filter
    seccomp::SeccompFilter::new(program, default_action, filter_flags)
        .map_err(seccomp_error_to_syscall)
}

/// Get current seccomp mode for PR_GET_SECCOMP
// R159-I3 FIX: Cache strict_filter ID to avoid heap allocation on every
// PR_GET_SECCOMP call. Computed once on first use.
static STRICT_FILTER_ID: spin::Once<u64> = spin::Once::new();

fn current_seccomp_mode(state: &seccomp::SeccompState) -> usize {
    if state.filters().is_empty() {
        return SECCOMP_MODE_DISABLED;
    }

    let strict_id = *STRICT_FILTER_ID.call_once(|| seccomp::strict_filter().id());
    if state.filters().len() == 1 {
        if let Some(filter) = state.filters().first() {
            if filter.id() == strict_id {
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

            // R142-8 FIX: Reject STRICT mode in multi-threaded processes or when
            // CLONE_VM siblings exist. Without this, only the calling thread is
            // sandboxed while other threads sharing the address space retain full
            // syscall access — defeating the purpose of strict sandboxing.
            //
            // Lock ordering: read tgid/memory_space under process lock, drop it,
            // then call thread_group_size/non_thread_group_vm_share_count (which
            // acquire PROCESS_TABLE lock). PROCESS_TABLE → Process ordering preserved.
            let (tgid, memory_space) = {
                let proc = proc_arc.lock();
                // R26-3 FIX: Check if another thread is already installing
                if proc.seccomp_installing {
                    return Err(SyscallError::EBUSY);
                }
                (proc.tgid, proc.memory_space)
            }; // Process lock dropped

            let thread_count = crate::process::thread_group_size(tgid);
            if thread_count > 1 {
                klog!(Warn,
                    "[sys_seccomp] PID={} STRICT mode REJECTED: threads={} (multi-threaded)",
                    pid, thread_count
                );
                return Err(SyscallError::EPERM);
            }

            let pure_vm_siblings =
                crate::process::non_thread_group_vm_share_count(memory_space, tgid);
            if pure_vm_siblings > 0 {
                klog!(Warn,
                    "[sys_seccomp] PID={} STRICT mode REJECTED: {} CLONE_VM siblings",
                    pid, pure_vm_siblings
                );
                return Err(SyscallError::EPERM);
            }

            let filter = seccomp::strict_filter();
            let mut proc = proc_arc.lock();

            // R26-3 FIX: Re-check after reacquiring lock (race window between
            // the initial check above and the re-acquire here).
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // R171-CG2x1 FIX: failure-atomic install — run the now-cap-fallible
            // add_filter FIRST; commit the sticky no_new_privs only on success so
            // a reject leaves no seccomp state drift.
            // R159-6 FIX: Fallible add_filter.
            if proc.seccomp_state.add_filter(filter).is_err() {
                proc.seccomp_installing = false;
                return Err(SyscallError::ENOMEM);
            }

            // Installing any filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            klog!(Info, "[sys_seccomp] PID={} installed STRICT mode", pid);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            // Load and validate the filter from userspace
            let filter = load_user_seccomp_filter(flags, args)?;

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

            // R142-8 FIX: Read tgid/memory_space under process lock, then drop
            // before calling thread_group_size/non_thread_group_vm_share_count
            // (which acquire PROCESS_TABLE lock). Holding process lock while
            // calling those helpers is a latent self-deadlock: the helpers
            // iterate PROCESS_TABLE and lock each Process entry, including
            // the caller's own entry → spin forever.
            let (tgid, memory_space) = {
                let proc = proc_arc.lock();
                // R26-3 FIX: Check if another thread is already installing
                if proc.seccomp_installing {
                    return Err(SyscallError::EBUSY);
                }
                (proc.tgid, proc.memory_space)
            }; // Process lock dropped

            // R25-6 FIX: Reject seccomp in multi-threaded processes without TSYNC
            // R37-1 FIX (Codex review): Correctly distinguish CLONE_THREAD vs pure CLONE_VM siblings.
            // - CLONE_THREAD siblings (same tgid) can be synchronized with TSYNC
            // - Pure CLONE_VM siblings (different tgid) cannot be synchronized with TSYNC
            let thread_count = crate::process::thread_group_size(tgid);
            let pure_vm_siblings =
                crate::process::non_thread_group_vm_share_count(memory_space, tgid);
            let tsync_requested = flags & seccomp::SeccompFlags::TSYNC.bits() != 0;

            // Reject if multi-threaded without TSYNC (partial sandboxing)
            if thread_count > 1 && !tsync_requested {
                klog!(Warn,
                    "[sys_seccomp] PID={} REJECTED: threads={} without TSYNC",
                    pid, thread_count
                );
                return Err(SyscallError::EPERM);
            }

            // R37-1 FIX: If pure CLONE_VM siblings exist, reject regardless of TSYNC.
            // TSYNC only synchronizes CLONE_THREAD siblings (same tgid), not CLONE_VM processes.
            if pure_vm_siblings > 0 {
                klog!(Warn,
                    "[sys_seccomp] PID={} REJECTED: {} CLONE_VM siblings (different tgid) present; \
                    seccomp cannot secure shared address space",
                    pid, pure_vm_siblings
                );
                return Err(SyscallError::EBUSY);
            }

            let mut proc = proc_arc.lock();

            // R26-3 FIX: Re-check after reacquiring lock
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // R171-CG2x1 FIX: make the install failure-atomic. Capture the LOG
            // intent, run the now-cap-fallible add_filter FIRST, and commit the
            // sticky no_new_privs / log_violations state ONLY on success — so a
            // chain-cap reject (ENOMEM) leaves no observable seccomp state drift
            // (previously log_violations/no_new_privs were flipped before the
            // fallible add_filter, persisting on a now attacker-reachable reject).
            let wants_log = filter.flags().contains(seccomp::SeccompFlags::LOG);
            // R159-6 FIX: Fallible add_filter.
            if proc.seccomp_state.add_filter(filter).is_err() {
                proc.seccomp_installing = false;
                return Err(SyscallError::ENOMEM);
            }

            // Installing a filter sets no_new_privs (sticky, one-way).
            proc.seccomp_state.no_new_privs = true;
            if wants_log {
                proc.seccomp_state.log_violations = true;
            }

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            klog!(Info,
                "[sys_seccomp] PID={} installed FILTER mode (total filters: {})",
                pid,
                proc.seccomp_state.filters().len()
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
    // R165-16 FIX: Invoke the dedicated task-level LSM hook for prctl. It was
    // defined (lsm::hook_task_prctl) but never called from this syscall, so an
    // LSM policy could not mediate security-relevant prctl options (NO_NEW_PRIVS,
    // SET_SECCOMP, …). Evaluate up front, before any state change; deny -> EPERM.
    // R131-1 FIX pattern: build the ctx from the locked proc and drop it before
    // calling the hook to avoid Process-mutex re-entrancy.
    {
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)
        };
        if lsm::hook_task_prctl(&ctx, option, arg2).is_err() {
            return Err(SyscallError::EPERM);
        }
    }
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

            klog!(Info, "[sys_prctl] PID={} set NO_NEW_PRIVS", pid);
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
    // R100-1 FIX: 系统调用入口已执行 SWAPGS，此时：
    //   IA32_GS_BASE (0xC0000101) = 内核 per-CPU 指针（不可触碰）
    //   IA32_KERNEL_GS_BASE (0xC0000102) = 用户态 GS 基址
    // 因此 ARCH_SET_GS / ARCH_GET_GS 必须操作 0xC0000102
    const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    match code {
        ARCH_SET_FS => {
            // 验证地址是 canonical
            if !is_canonical(addr) {
                return Err(SyscallError::EINVAL);
            }

            // R102-10 FIX: Gate TLS base address log behind debug_assertions.
            // Leaks userspace TLS base which aids exploitation.
            kprintln!("[arch_prctl] PID={} ARCH_SET_FS addr=0x{:x}", pid, addr);

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
                let mut msr = Msr::new(MSR_KERNEL_GS_BASE);
                msr.write(addr);
            }

            Ok(0)
        }

        ARCH_GET_GS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // R100-1 FIX: 直接从 IA32_KERNEL_GS_BASE 读取用户态 GS 基址。
            // 用户态可能通过 wrgsbase 指令修改了 GS，PCB 中的缓存值可能过期。
            let gs_base = unsafe { Msr::new(MSR_KERNEL_GS_BASE).read() };

            // 同步到 PCB 以保持一致性
            {
                let mut proc = process.lock();
                proc.gs_base = gs_base;
            }

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
            kprintln!($($arg)*);
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

    // R134-4 FIX: Use host-mapped root check instead of namespace euid==0.
    // Namespace root must not be able to modify CPU affinity of host processes.
    if crate::current_is_host_root() {
        return Ok(true);
    }

    Ok(false)
}

/// Check whether the calling task may GET another task's CPU affinity.
///
/// Per Linux semantics, sched_getaffinity is permissive (no EPERM for
/// cross-UID reads). However, PID namespace isolation MUST be enforced:
/// a container process must not be able to probe host processes by global PID.
///
/// R141-4 FIX: Added PID namespace visibility check. Processes not visible
/// from the caller's namespace are treated as ESRCH.
#[inline]
fn can_get_affinity(target_pid: ProcessId) -> Result<bool, SyscallError> {
    let target_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;

    // R141-4 FIX: Enforce PID namespace visibility.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let caller_ns = {
        let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
    };
    if let Some(ns) = caller_ns {
        let visible = {
            let proc = target_arc.lock();
            crate::pid_namespace::is_visible_in_namespace(&ns, &proc.pid_ns_chain)
        };
        if !visible {
            return Err(SyscallError::ESRCH);
        }
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

    // R141-4 FIX: Resolve target PID through namespace translation.
    // The user-provided pid is namespace-local; translate to global.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 {
        caller_pid
    } else {
        let caller_ns = {
            let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
        };
        if let Some(ns) = caller_ns {
            crate::pid_namespace::resolve_pid_in_namespace(&ns, pid as ProcessId)
                .ok_or(SyscallError::ESRCH)?
        } else {
            pid as ProcessId
        }
    };

    // Permission check (uses can_set_affinity which requires privilege for other processes)
    if !can_set_affinity(target_pid)? {
        return Err(SyscallError::EPERM);
    }

    // Copy mask from userspace
    // P1-6 FIX: Removed redundant outer UserAccessGuard — copy_from_user_safe
    // creates its own guard internally.
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

    // R141-4 FIX: Resolve target PID through namespace translation.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 {
        caller_pid
    } else {
        let caller_ns = {
            let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
        };
        if let Some(ns) = caller_ns {
            crate::pid_namespace::resolve_pid_in_namespace(&ns, pid as ProcessId)
                .ok_or(SyscallError::ESRCH)?
        } else {
            pid as ProcessId
        }
    };

    // Permission check (permissive - just verify process exists + namespace visibility)
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
    // P1-6 FIX: Removed redundant outer UserAccessGuard — copy_to_user_safe
    // creates its own guard internally.
    let mask_bytes = affinity.to_ne_bytes();
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

    // R163-I1 FIX: Removed redundant validate_user_ptr_mut — verify_user_memory
    // already calls validate_user_ptr internally.
    verify_user_memory(buf as *const u8, count, true)?;

    // R40-1 FIX: 使用 CSPRNG (ChaCha20) 生成随机数据
    //
    // 之前的实现使用时间戳混合 RDRAND，在启动早期可能是可预测的。
    // 现在使用 security::rng 模块的 ChaCha20 CSPRNG，它：
    // - 由 RDRAND/RDSEED 播种
    // - 定期重新播种
    // - 提供密码学安全的随机数
    // R156-3 FIX: Fallible allocation for getrandom buffer.
    let mut tmp = Vec::new();
    tmp.try_reserve_exact(count).map_err(|_| SyscallError::ENOMEM)?;
    tmp.resize(count, 0);
    match rng::fill_random(&mut tmp) {
        Ok(()) => {}
        // R140-6 FIX: FIPS state failed/corrupted — deny all crypto.
        Err(rng::RngError::FipsBlocked) => return Err(SyscallError::EPERM),
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

    // R130-7 FIX: Invoke LSM MAC hook before DAC permission check.
    // Without this, a MAC-denied file that is DAC-accessible can be probed
    // via access() without MAC intervention — inconsistent with enforcement
    // at real operations (open, read, write, unlink).
    // R131-7 FIX: LSM hook is now checked for ALL modes including F_OK (mode==0).
    // Previously, F_OK returned early before reaching this hook, allowing
    // file existence probes to bypass MAC policy.
    if let Some(proc_ctx) = lsm_current_process_ctx() {
        let access_mask = (mode as u32) & 0x7; // R_OK=4, W_OK=2, X_OK=1
        if let Err(err) = lsm::hook_file_permission(&proc_ctx, stat.ino, access_mask) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // F_OK(0) - 仅检查文件是否存在 (after LSM check)
    if mode == 0 {
        return Ok(0);
    }

    // 获取当前进程凭证
    // R93-4 FIX: Fail-closed - return ESRCH if credentials unavailable (was unwrap_or(0))
    // R135-1 FIX: Use host-mapped credentials for DAC checks in sys_access.
    // Namespace euid/egid must NOT be compared against host inode UIDs/GIDs.
    let euid = crate::current_host_euid().ok_or(SyscallError::ESRCH)?;
    let egid = crate::current_host_egid().ok_or(SyscallError::ESRCH)?;
    let sup_groups = crate::current_host_supplementary_groups().unwrap_or_default();

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
///
/// # R154-8 FIX: AT_SYMLINK_NOFOLLOW documentation
/// The `flags` parameter (including AT_SYMLINK_NOFOLLOW = 0x100) is currently
/// ignored because the VFS does not implement symbolic links. When symlink
/// support is added, this function must inspect `flags` and branch on
/// AT_SYMLINK_NOFOLLOW to lstat() the link itself rather than its target.
///
/// # R96-5 FIX: TOCTOU Protection
/// Copies the entire path once and uses the kernel copy for both the
/// check and the actual operation, eliminating the window where an
/// attacker could modify the path between check and use.
fn sys_fstatat(dirfd: i32, path: *const u8, statbuf: *mut VfsStat, _flags: i32) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if statbuf.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R96-5 FIX: Copy the entire path once to eliminate TOCTOU window.
    // Previously we copied only the first byte, then called sys_stat which
    // would copy the path again. An attacker could modify the path between
    // the two copies.
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(
            core::str::from_utf8(&path_bytes)
                .map_err(|_| SyscallError::EINVAL)?
        )?
    };

    // Check from kernel copy - no TOCTOU possible
    let first_byte = path_str.as_bytes().first().copied().unwrap_or(0);
    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        return Err(SyscallError::EOPNOTSUPP);
    }

    // Use internal helper with already-copied path
    sys_stat_internal(&path_str, statbuf)
}

/// sys_openat - 相对路径打开文件
///
/// 当前仅支持AT_FDCWD或绝对路径。
///
/// # R96-5 FIX: TOCTOU Protection
/// Copies the entire path once and uses the kernel copy for both the
/// check and the actual operation, eliminating the window where an
/// attacker could modify the path between check and use.
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> SyscallResult {
    use crate::usercopy::copy_user_cstring;

    if path.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // R96-5 FIX: Copy the entire path once to eliminate TOCTOU window.
    // Previously we copied only the first byte, then called sys_open which
    // would copy the path again. An attacker could modify the path between
    // the two copies.
    let path_str = {
        let path_bytes = copy_user_cstring(path).map_err(|_| SyscallError::EFAULT)?;
        if path_bytes.is_empty() {
            return Err(SyscallError::EINVAL);
        }
        try_str_to_string(
            core::str::from_utf8(&path_bytes)
                .map_err(|_| SyscallError::EINVAL)?
        )?
    };

    // Check from kernel copy - no TOCTOU possible
    let first_byte = path_str.as_bytes().first().copied().unwrap_or(0);
    if dirfd != AT_FDCWD && first_byte != b'/' {
        // 相对路径 + 非AT_FDCWD: 暂不支持
        return Err(SyscallError::EOPNOTSUPP);
    }

    // Use internal helper with already-copied path
    sys_open_internal(&path_str, flags, mode)
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
    let path_str = try_str_to_string(
        core::str::from_utf8(&path_bytes)
            .map_err(|_| SyscallError::EINVAL)?
    )?;

    // Get current process
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R65-22 FIX: Handle dirfd for relative paths
    // Resolve relative paths against the directory referenced by dirfd
    // R164-3 FIX: Use fallible allocation for resolved path construction.
    // R165-5 FIX: Move (not clone) path_str on the absolute-path arm. The prior
    // `path_str.clone()` was an infallible String allocation of up to
    // MAX_ARG_STRLEN+1 = 4097 user-controlled bytes — an OOM-time kernel panic.
    // path_str is not used after this if/else, so the move is sound.
    let resolved_path = if path_str.starts_with('/') {
        path_str
    } else if dirfd == AT_FDCWD {
        if path_str.is_empty() {
            try_str_to_string("/")?
        } else {
            let mut s = String::new();
            s.try_reserve_exact(1 + path_str.len()).map_err(|_| SyscallError::ENOMEM)?;
            s.push('/');
            s.push_str(&path_str);
            s
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

    // R105-1 FIX: Removed duplicate LSM hooks — VFS layer enforces
    // hook_file_create and hook_file_open with real inode context.
    // See sys_open_internal R105-1 comment for rationale.

    // Get VFS callback with resolve support
    let open_fn = {
        let callback = VFS_OPEN_WITH_RESOLVE_CALLBACK.lock();
        *callback.as_ref().ok_or(SyscallError::ENOSYS)?
    };

    // Call VFS with resolve flags — VFS enforces LSM hooks
    let file_ops = open_fn(&resolved_path, open_flags, mode, resolve)?;

    // O_CLOEXEC flag
    const O_CLOEXEC: u32 = 0x80000;

    // Allocate fd
    let fd = {
        let mut proc = process.lock();
        // D2-FD-DROP-UNDER-LOCK: pre-existing inline drop of the rejected
        // object on the EMFILE arm (byte-equivalent to the old
        // allocate_fd-internal drop); conversion to drop-outside tracked.
        let fd = proc
            .allocate_fd(file_ops)
            .map_err(|rejected| {
                drop(rejected);
                SyscallError::EMFILE
            })?;

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

    // D2-FD-DROP-UNDER-LOCK: pre-existing inline drop of the rejected clone on
    // the EMFILE arm (byte-equivalent to the old allocate_fd-internal drop);
    // conversion to drop-outside tracked.
    let newfd = proc
        .allocate_fd(cloned)
        .map_err(|rejected| {
            drop(rejected);
            SyscallError::EMFILE
        })?;
    Ok(newfd as usize)
}

/// sys_dup2 - 复制文件描述符到指定位置
fn sys_dup2(oldfd: i32, newfd: i32) -> SyscallResult {
    if oldfd < 0 || newfd < 0 {
        return Err(SyscallError::EBADF);
    }

    // R141-3 FIX: Reject newfd >= MAX_FD to prevent unbounded fd_table growth.
    // allocate_fd() enforces MAX_FD for sys_dup/sys_open, but dup2 accepts an
    // arbitrary newfd — without this gate a user can dup2(fd, 1_000_000) and
    // grow the per-process BTreeMap in kernel heap without limit (local OOM DoS).
    if newfd >= crate::process::MAX_FD {
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

    // R155-3 FIX: Extract old fd under lock, drop OUTSIDE to prevent
    // lock inversion (Process → SocketFile::drop → waiters → Process).
    let old_fd_entry = {
        let mut proc = proc_arc.lock();
        let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
        let cloned = src.clone_box();
        // J2-7: net-aware, fail-closed FD accounting (replaces remove_fd+insert):
        // empty newfd → charge +1 (EMFILE on over-budget, table untouched);
        // occupied newfd → net 0, reuses the replaced entry's charge.
        proc.replace_fd_charged(newfd, cloned)
            .map_err(|_| SyscallError::EMFILE)?
    };
    drop(old_fd_entry);

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

    // R141-3 FIX: Reject newfd >= MAX_FD (same gate as sys_dup2 above).
    if newfd >= crate::process::MAX_FD {
        return Err(SyscallError::EBADF);
    }

    // 仅接受O_CLOEXEC标志
    const O_CLOEXEC: i32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        return Err(SyscallError::EINVAL);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R155-3 FIX: Extract old fd under lock, drop OUTSIDE to prevent
    // lock inversion (Process → SocketFile::drop → waiters → Process).
    let old_fd_entry = {
        let mut proc = proc_arc.lock();
        let src = proc.get_fd(oldfd).ok_or(SyscallError::EBADF)?;
        let cloned = src.clone_box();
        // J2-7: net-aware, fail-closed FD accounting (replaces remove_fd+insert).
        // replace_fd_charged clears CLOEXEC on newfd; re-set it below if requested.
        let removed = proc
            .replace_fd_charged(newfd, cloned)
            .map_err(|_| SyscallError::EMFILE)?;

        if flags & O_CLOEXEC != 0 {
            proc.set_fd_cloexec(newfd, true);
        }

        removed
    };
    drop(old_fd_entry);

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

    // R114-2 FIX: Cap `count` to MAX_RW_SIZE (1 MB) to prevent extreme kernel allocations
    // even with large user buffers. This matches Linux's practical limit for readdir.
    const MAX_RW_SIZE: usize = 1024 * 1024; // 1 MB
    let budget = count.min(MAX_RW_SIZE);

    // J2-10: per-cgroup VFS dir-enumeration budget (vfs_dir.max). Resolve the
    // cgroup id FIRST (current_cgroup_id releases the Process lock before we
    // charge — INV-2: cgroup charges never run under the Process lock). The RAII
    // guard charges at construction and uncharges on Ok and every early `?` Err
    // return through Drop, covering the lifetime of both the `entries` Vec and the
    // per-entry serialization buffers below. (The kernel is built panic=abort, so
    // Drop does not run on panic — but a panic halts the kernel, making the
    // transient charge moot.) When the
    // tenant's budget is tight it grants a SMALLER amount → a graceful getdents64
    // short read (the next call resumes from the advanced offset); it never fails
    // the syscall or returns a false EOD. Root id==0 is exempt (full budget).
    let vfs_cg = crate::process::current_cgroup_id().unwrap_or(0);
    let vfs_guard = crate::cgroup::VfsDirBudgetGuard::charge(vfs_cg, budget);
    let budget = vfs_guard.granted();

    // 通过回调读取目录项，passing byte budget to limit kernel-side allocation
    let readdir_fn = VFS_READDIR_CALLBACK.lock().ok_or(SyscallError::ENOSYS)?;
    let entries = readdir_fn(fd, budget)?;

    // 构建dirent64结构
    let mut written = 0usize;
    let header_size = core::mem::size_of::<LinuxDirent64>();
    // R114-2 FIX: Validate ABI assumption — vfs_readdir_callback uses DIRENT64_HEADER_SIZE=24
    // for budget estimation. If repr(C) padding changes, this catches the mismatch.
    debug_assert_eq!(header_size, 24, "LinuxDirent64 size mismatch: budget estimation assumes 24");

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

        // R156-3 FIX: Fallible allocation for dirent buffer.
        let mut buf = Vec::new();
        buf.try_reserve_exact(reclen).map_err(|_| SyscallError::ENOMEM)?;
        buf.resize(reclen, 0);

        // R113-1 FIX: Write header fields individually into the zeroed buffer
        // instead of copy_nonoverlapping from a stack LinuxDirent64, which would
        // copy 5 bytes of uninitialized tail padding (offsets 19-23).
        buf[0..8].copy_from_slice(&entry.ino.to_ne_bytes());
        buf[8..16].copy_from_slice(&(next_written as i64).to_ne_bytes());
        buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        buf[18] = d_type;

        // 复制文件名
        buf[header_size..header_size + name_bytes.len()].copy_from_slice(name_bytes);
        buf[header_size + name_bytes.len()] = 0; // NUL terminator

        // 复制到用户空间
        // R102-I4 FIX: Use integer arithmetic for user pointer offset (provenance-safe).
        let dst = (dirp as usize).wrapping_add(written) as *mut u8;
        copy_to_user(dst, &buf)?;
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
    // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes; user→kernel)
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
        // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes; all-zero)
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

    // lint-repr-c-copy: allow (no-padding: TimeVal {i64,i64} = 16 bytes)
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

    // lint-repr-c-copy: allow (no-padding: UtsName {[u8;65]×5} = 325 bytes, alignment=1)
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
    // lint-repr-c-copy: allow (no-padding: SockAddrIn {u16,u16,u32,[u8;8]} = 16 bytes; user→kernel)
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

    // lint-repr-c-copy: allow (no-padding: SockAddrIn {u16,u16,u32,[u8;8]} = 16 bytes)
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

    // R132-1 FIX: Extract capability entry and net namespace ID under the process lock,
    // then drop the lock before any external lookups. Previously, current_net_ns_id()
    // was called while holding process.lock(), which re-acquired the same non-reentrant
    // Process mutex via PROCESS_TABLE → slot.lock() → deterministic self-deadlock on
    // every socket operation (bind, listen, accept, connect, sendto, recvfrom, shutdown).
    let (entry, caller_ns_id) = {
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

        // Read net_ns ID directly from the locked Process struct instead of calling
        // current_net_ns_id() which would re-enter PROCESS_TABLE and deadlock.
        let ns_id = proc.net_ns.id();

        (entry, ns_id)
    };
    // Process lock released — safe for external lookups

    // Get socket state from socket_table
    let sock = net::socket_table()
        .get(socket_id)
        .ok_or(SyscallError::EBADF)?;

    // R76-1 FIX: Enforce network namespace isolation.
    // A process that has entered a different network namespace (via clone/setns)
    // must not be able to use sockets from its previous namespace.
    // This prevents container escape via inherited socket capabilities.
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
/// - Creates CapEntry with READ|WRITE|BIND rights (TCP also gets CONNECT|LISTEN|ACCEPT)
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
    // R152-1 FIX: TCP sockets get CONNECT/LISTEN/ACCEPT rights at creation.
    // These rights enable least-privilege delegation (e.g., connect-only cap).
    let mut rights = cap::CapRights::READ | cap::CapRights::WRITE | cap::CapRights::BIND;
    if ty == net::SocketType::Stream && proto == net::SocketProtocol::Tcp {
        rights |= cap::CapRights::CONNECT | cap::CapRights::LISTEN | cap::CapRights::ACCEPT;
    }
    let cap_entry = cap::CapEntry::with_flags(
        // R75-1 FIX: Pass network namespace ID to Socket capability for isolation tracking
        cap::CapObject::Socket(alloc::sync::Arc::new(cap::Socket::new(socket.id, socket.net_ns_id.raw()))),
        rights,
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
            Ok(fd) => fd,
            Err(rejected) => {
                // D2-FD-DROP-UNDER-LOCK: pre-existing inline drop of the
                // rejected SocketFile (byte-equivalent to the old
                // allocate_fd-internal drop — keeps the audited teardown
                // ORDER: box-drop, then cap revoke, then explicit close);
                // conversion to drop-outside tracked.
                drop(rejected);
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
    // R134-3 FIX: Use host-mapped root check instead of namespace euid==0.
    // Namespace root must NOT be able to bind privileged ports on the host network.
    let has_net_bind_cap =
        with_current_cap_table(|table| table.has_rights(cap::CapRights::NET_BIND_SERVICE))
            .unwrap_or(false);
    let can_bind_privileged = crate::current_is_host_root() || has_net_bind_cap;

    // Early check for privileged port access
    const PRIVILEGED_PORT_LIMIT: u16 = 1024;
    if port != 0 && port < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
        return Err(SyscallError::EACCES);
    }

    // Bind via socket_table (includes LSM hook_net_bind check)
    // R51-1: Support both UDP and TCP binding
    // R169-6 FIX (D2-J2-PORT-COVERAGE): EVERY bind now charges the per-cgroup
    // `ports.max` budget (root cgroup id 0 exempt at the charge layer).
    // - `bind(0)` charges a kernel-chosen port as BindCharge::Ephemeral
    //   (ghost-bind teardown; POSIX-deviation note: its port does NOT persist
    //   across a failed connect — unchanged shipped semantics; the
    //   bind(0)+connect self-replace undercount stays closed on the connect
    //   side via the reuse-live-binding gate).
    // - R169-6 slice 2: an explicit NON-zero bind charges as
    //   BindCharge::Explicit with HOLD-UNTIL-CLOSE teardown (the while-alive
    //   teardown arms pure-skip it, so the port + charge persist until
    //   close()/exit) — closing the last ports.max bypass: `socket();
    //   bind(fd,p); ...` repeated no longer consumes uncharged ports.
    // A tenant at ports.max gets QuotaExceeded -> EAGAIN (definitively EAGAIN
    // via socket_error_to_syscall — NOT EADDRINUSE, so a quota failure is
    // never confused with a real port collision; note quota is checked before
    // the in-use probe, so a busy-port bind at the cap also reports EAGAIN).
    let (port_opt, policy) = if port == 0 {
        (None, net::BindCharge::Ephemeral)
    } else {
        (Some(port), net::BindCharge::Explicit)
    };
    if socket.ty == net::SocketType::Dgram && socket.proto == net::SocketProtocol::Udp {
        net::socket_table()
            .bind_udp(&socket, &ctx, cap_id, ip, port_opt, can_bind_privileged, policy)
            .map_err(socket_error_to_syscall)?;
    } else if socket.ty == net::SocketType::Stream && socket.proto == net::SocketProtocol::Tcp {
        net::socket_table()
            .bind_tcp(&socket, &ctx, cap_id, ip, port_opt, can_bind_privileged, policy)
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
/// - Verifies CapRights::LISTEN (required for listen)
/// - Verifies CapRights::BIND if auto-bind is needed
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

    // R152-1 FIX: LISTEN right required for listen()
    if !entry.rights.allows(cap::CapRights::LISTEN) {
        return Err(SyscallError::EACCES);
    }

    // R152-1 FIX: BIND right required only if listen() must auto-bind
    if socket.local_port().is_none() && !entry.rights.allows(cap::CapRights::BIND) {
        return Err(SyscallError::EACCES);
    }

    let ctx = lsm_current_process_ctx().ok_or(SyscallError::ESRCH)?;

    // Compute privileged-port permission for auto-bind
    // R134-3 FIX: Use host-mapped root check instead of namespace euid==0.
    let has_net_bind_cap =
        with_current_cap_table(|table| table.has_rights(cap::CapRights::NET_BIND_SERVICE))
            .unwrap_or(false);
    let can_bind_privileged = crate::current_is_host_root() || has_net_bind_cap;

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
/// - Verifies CapRights::ACCEPT (required for accept)
/// - Invokes LSM hook_net_accept for policy check
/// - Returns EAGAIN for non-blocking if no connections pending
fn sys_accept(fd: i32, addr: *mut SockAddrIn, addrlen: *mut u32) -> SyscallResult {
    let (cap_id, socket_id, nonblock) = socket_handle_from_fd(fd)?;
    let (entry, socket) = resolve_socket(cap_id, socket_id)?;

    // Only TCP sockets can accept
    if socket.ty != net::SocketType::Stream || socket.proto != net::SocketProtocol::Tcp {
        return Err(SyscallError::EOPNOTSUPP);
    }

    // R152-1 FIX: ACCEPT right required for accept()
    if !entry.rights.allows(cap::CapRights::ACCEPT) {
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
                        // R171-F3: pending kill — interrupt the blocking accept.
                        net::WaitOutcome::Interrupted => return Err(SyscallError::EINTR),
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
    // R162-11 FIX: addr copy failure is non-fatal — the connection is already
    // established and the child fd is valid. Destroying the child socket on
    // EFAULT during addr copy allows a malicious process to silently kill
    // incoming connections by providing invalid addr pointers. Instead, skip
    // the addr copy on validation failure (Linux behavior).
    if !addr.is_null() && !addrlen.is_null() {
        if let (Some(rip), Some(rport)) = (child.remote_ip(), child.remote_port()) {
            let mut out = SockAddrIn::default();
            out.sin_family = AF_INET as u16;
            out.sin_port = rport.to_be();
            out.sin_addr = u32::from_be_bytes(rip);

            let addr_valid = validate_user_ptr(addr as *const u8, core::mem::size_of::<SockAddrIn>()).is_ok()
                && validate_user_ptr(addrlen as *const u8, core::mem::size_of::<u32>()).is_ok();
            if !addr_valid {
                // Skip addr copy but don't destroy the child — proceed to return fd.
            } else {

            // Convert struct to bytes for copy_to_user
            // lint-repr-c-copy: allow (no-padding: SockAddrIn {u16,u16,u32,[u8;8]} = 16 bytes)
            let out_bytes = unsafe {
                core::slice::from_raw_parts(
                    &out as *const SockAddrIn as *const u8,
                    core::mem::size_of::<SockAddrIn>(),
                )
            };
            // R162-11 FIX: copy_to_user failure is also non-fatal for addr fill.
            let _ = copy_to_user(addr as *mut u8, out_bytes);
            let len_val = core::mem::size_of::<SockAddrIn>() as u32;
            let _ = copy_to_user(addrlen as *mut u8, &len_val.to_ne_bytes());
            }
        }
    }

    // Allocate capability + fd for child socket
    // R75-1 FIX: Pass network namespace ID to Socket capability (inherited from listener)
    // R152-1 FIX: Child socket rights are limited to (READ|WRITE) & listener_rights.
    // This enforces capability monotonicity: a restricted listener cannot mint
    // broader child capabilities via accept().
    let child_rights = (cap::CapRights::READ | cap::CapRights::WRITE) & entry.rights;
    let cap_entry = cap::CapEntry::with_flags(
        cap::CapObject::Socket(alloc::sync::Arc::new(cap::Socket::new(child.id, child.net_ns_id.raw()))),
        child_rights,
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
            Ok(fd) => fd,
            Err(rejected) => {
                // D2-FD-DROP-UNDER-LOCK: pre-existing inline drop of the
                // rejected SocketFile (byte-equivalent to the old
                // allocate_fd-internal drop — keeps the audited teardown
                // ORDER: box-drop, then cap revoke, then cleanup_child);
                // conversion to drop-outside tracked.
                drop(rejected);
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
/// - Verifies CapRights::CONNECT for initiating connect()
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

    // R152-1 FIX: CONNECT right required for connect()
    if !entry.rights.allows(cap::CapRights::CONNECT) {
        return Err(SyscallError::EACCES);
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

    // R155-8 FIX: Seed conntrack entry for the outbound SYN before transmitting.
    // Without this, the inbound SYN-ACK is classified Invalid (no existing entry,
    // and SYN-ACK is not a pure SYN). Same pattern as the SYN cookie path.
    // R156-9 FIX: Gate behind conntrack feature to match all other call sites.
    #[cfg(feature = "conntrack")]
    {
        let now_ms = crate::time::get_ticks();
        let _ = net::conntrack::ct_process_tcp(
            socket.net_ns_id.0,
            syn_result.src_ip,
            syn_result.dst_ip,
            syn_result.local_port,
            syn_result.dst_port,
            net::TCP_FLAG_SYN,
            0,
            now_ms,
        );
    }

    // Phase 2: Transmit the SYN segment via network device
    // R51-5 FIX: Abort connection if TX fails to prevent TCB/binding leak
    if let Err(e) = net::transmit_tcp_segment(syn_result.dst_ip, &syn_result.segment, socket.net_ns_id.0) {
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
        // R156-3 FIX: Fallible allocation for TCP send buffer.
        let mut data = Vec::new();
        data.try_reserve_exact(len).map_err(|_| SyscallError::ENOMEM)?;
        data.resize(len, 0);
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

        // Transmit all TCP segments via network device.
        // R162-10 FIX: Ignore transmit failures — data is already committed
        // to the TCP send buffer with snd_nxt advanced. The retransmission
        // timer will re-send on failure. Returning an error here would cause
        // the caller to re-send, creating duplicate data in the TCP stream.
        for segment in segments {
            let _ = net::transmit_tcp_segment(remote_ip, &segment, socket.net_ns_id.0);
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
    // R156-3 FIX: Fallible allocation for UDP send buffer.
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|_| SyscallError::ENOMEM)?;
    data.resize(len, 0);
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
    // R162-7-2 FIX: Pass socket's namespace for per-NS egress firewall evaluation.
    net::transmit_udp_datagram(dst_ip, &datagram, socket.net_ns_id.0).map_err(tx_error_to_syscall)?;

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
    // R159-12 FIX: Clamp to MAX_RW_SIZE, matching sys_read/sys_write.
    if len > MAX_RW_SIZE {
        return Err(SyscallError::EINVAL);
    }

    // R160-1 FIX: Validate user buffer BEFORE any socket operation. The
    // previous code called tcp_recv/recv_from_udp (which dequeues data)
    // before checking the buffer pointer. On EFAULT, the dequeued data was
    // irretrievably lost — violating TCP's reliable delivery at the syscall
    // boundary. This matches the pattern in sys_read (line 5255).
    validate_user_ptr_mut(buf, len)?;

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

        // R161-1 FIX: Remove redundant validate_user_ptr_mut(buf, copy_len).
        // The buffer was already validated at line 10273 with the full `len`.
        // When tcp_recv returns empty Vec (TCP EOF / FIN), copy_len == 0,
        // and validate_user_ptr rejects len==0 → EFAULT, breaking EOF detection.
        // Guard copy with copy_len > 0; return 0 for EOF (POSIX recv semantics).
        let copy_len = core::cmp::min(len, data.len());
        if copy_len > 0 {
            copy_to_user(buf, &data[..copy_len])?;
        }
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

    // R161-1 FIX: Same fix as TCP path — remove redundant validation.
    // A 0-length UDP datagram is protocol-legal (RFC 768); returning EFAULT is wrong.
    let copy_len = core::cmp::min(len, pkt.data.len());
    if copy_len > 0 {
        copy_to_user(buf, &pkt.data[..copy_len])?;
    }

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
                let _ = net::transmit_tcp_segment(net::Ipv4Addr(dst_ip), &fin_segment, socket.net_ns_id.0);
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
    /// Enabled controllers bitmap (CPU=1, MEMORY=2, PIDS=4, IO=8, FILES=0x10, NET=0x20)
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
    // J.2 items 7/8/10: per-cgroup FD / ephemeral-port / VFS-dir accounting.
    // APPENDED (offset-stable) so a caller declaring the old 104-byte length via
    // `buf_len` still receives the exact v1 prefix (statx-style negotiation in
    // sys_cgroup_get_stats). Order chosen for zero implicit padding: three u64
    // (8-aligned) then two u32. kmem (item 9) is intentionally OMITTED — its
    // counter is not yet wired (page-table frames charge `memory_current`, not
    // `kmem_current`), so exposing it would publish a permanent zero.
    /// J2-7: current open file-descriptor count (FILES controller)
    pub fds_current: u64,
    /// J2-8: current ephemeral-port count (NET controller)
    pub ports_current: u64,
    /// J2-10: current in-flight VFS dir-enumeration bytes (MEMORY controller)
    pub vfs_dir_current: u64,
    /// J2-7: number of files.max exceeded events
    pub fds_events_max: u32,
    /// J2-8: number of ports.max exceeded events
    pub ports_events_max: u32,
}

// H.0.1-3: Compile-time ABI size assertion (136 bytes, no implicit padding).
// J.2: grown from 104 → 136 (3×u64 + 2×u32 appended). The v2 entry point
// (sys_cgroup_get_stats2) negotiates the length via its `buf_len` argument; the
// kernel never writes past the declared buffer.
const _: [(); 136] = [(); core::mem::size_of::<CgroupStatsBuf>()];

/// J.2: Frozen v1 ABI size for syscall 504. CgroupStatsBuf may grow over time
/// (new fields are APPENDED), but syscall 504 ALWAYS writes exactly this many
/// bytes — the offset-stable v1 prefix — so its ABI is permanently stable. New
/// appended fields are read only via the negotiated v2 entry point (syscall 516).
const CGROUP_STATS_V1_SIZE: usize = 104;

// Pin the first appended field to the v1 boundary: this guarantees the bytes
// syscall 504 writes (the [0, CGROUP_STATS_V1_SIZE) prefix) are EXACTLY the v1
// fields (id … io_throttle_events). If a future edit inserts a field before
// `fds_current`, this assertion fails — forcing a deliberate ABI decision.
const _: [(); CGROUP_STATS_V1_SIZE] = [(); core::mem::offset_of!(CgroupStatsBuf, fds_current)];

/// H.0.1-3: Copy CgroupStatsBuf to userspace via a zeroed byte buffer so that
/// any padding bytes (explicit `_padding` field) are guaranteed zero, preventing
/// kernel memory disclosure. Mirrors the VfsStat pattern (R113-1).
///
/// J.2: `copy_len` is the statx-style negotiated length (== min(caller buf_len,
/// sizeof)). The full struct is serialized into the zeroed buffer, then ONLY the
/// first `copy_len` bytes are written to userspace — the kernel never writes past
/// the caller's declared buffer. Appended fields are offset-stable, so a caller
/// declaring the old 104-byte length receives exactly the v1 prefix.
#[inline]
fn copy_cgroup_stats_to_user(
    user_dst: *mut CgroupStatsBuf,
    stats: &CgroupStatsBuf,
    copy_len: usize,
) -> Result<(), SyscallError> {
    let mut buf = [0u8; mem::size_of::<CgroupStatsBuf>()];

    macro_rules! put {
        ($field:ident) => {
            let off = mem::offset_of!(CgroupStatsBuf, $field);
            let bytes = stats.$field.to_ne_bytes();
            buf[off..off + bytes.len()].copy_from_slice(&bytes);
        };
    }

    put!(id);
    put!(depth);
    put!(controllers);
    put!(nr_tasks);
    put!(cpu_time_ns);
    put!(memory_current);
    put!(memory_events_high);
    put!(memory_events_max);
    put!(pids_events_max);
    // `_padding` intentionally left as zeroes in the buffer.
    put!(io_read_bytes);
    put!(io_write_bytes);
    put!(io_read_ios);
    put!(io_write_ios);
    put!(io_throttle_events);
    // J.2 appended fields.
    put!(fds_current);
    put!(ports_current);
    put!(vfs_dir_current);
    put!(fds_events_max);
    put!(ports_events_max);

    // Negotiated length: never write past the caller's declared buffer.
    let n = copy_len.min(buf.len());
    copy_to_user(user_dst as *mut u8, &buf[..n])
}

/// P1-3: Returns `true` if the current process's host-mapped euid is a
/// delegated owner of `cgroup_id` (or any ancestor in the delegation chain).
///
/// R134-2 FIX: Use host-mapped euid for delegation identity matching.
/// Namespace-relative euid can collide across user namespaces, allowing
/// an attacker to assume another namespace's delegation identity.
fn is_cgroup_delegated_to_caller(cgroup_id: u64) -> bool {
    let euid = match crate::process::current_host_euid() {
        Some(uid) => uid,
        None => return false,
    };
    cgroup::lookup_cgroup(cgroup_id)
        .map(|cg| cg.is_delegated_to(euid))
        .unwrap_or(false)
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
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability to create cgroups. Previously only
/// checked euid==0 which bypassed the capability model and didn't support
/// future namespace-aware delegation.
fn sys_cgroup_create(parent_id: u64, controllers: u32) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for cgroup creation
    // P1-3: Also allow delegated owners of the parent cgroup
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);

    if !has_cap_admin && !crate::current_is_host_root() && !is_cgroup_delegated_to_caller(parent_id) {
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
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability. Cgroup must be empty.
fn sys_cgroup_destroy(cgroup_id: u64) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for cgroup destruction
    // P1-3: Also allow delegated owners (delegation checked on the cgroup itself,
    // since delegation inherits from ancestors)
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);

    if !has_cap_admin && !crate::current_is_host_root() && !is_cgroup_delegated_to_caller(cgroup_id) {
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

/// sys_cgroup_delegate (513) — Delegate management of a cgroup subtree to a UID.
///
/// # Arguments
/// * `cgroup_id` - ID of cgroup to delegate
/// * `uid` - Target UID, or `u64::MAX` to revoke delegation
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno (EPERM, ENOENT, EINVAL)
///
/// # Security
///
/// Requires root (euid == 0), CAP_SYS_ADMIN, or delegated subtree ownership
/// (sub-delegation). Delegation allows the specified UID to create/delete
/// children, set limits (bounded by ancestor ceilings), and migrate owned tasks
/// within the cgroup and its descendants. Pass `uid = u64::MAX` to revoke.
fn sys_cgroup_delegate(cgroup_id: u64, uid: u64) -> Result<usize, SyscallError> {
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);

    // P1-3: Allow host root, CAP_SYS_ADMIN, or delegated subtree managers.
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let authorized = crate::current_is_host_root()
        || has_cap_admin
        || is_cgroup_delegated_to_caller(cgroup_id);

    let delegate_uid = if uid == u64::MAX {
        None
    } else {
        if uid > u32::MAX as u64 {
            return Err(SyscallError::EINVAL);
        }
        Some(uid as u32)
    };

    // Determine audit operation type.
    let op = if delegate_uid.is_some() {
        audit::AuditCgroupDelegationOp::Grant
    } else {
        audit::AuditCgroupDelegationOp::Revoke
    };

    match cgroup::delegate_cgroup(cgroup_id, delegate_uid, authorized) {
        Ok(old_uid) => {
            // P1-3: Emit audit event for delegation lifecycle.
            let timestamp = crate::time::get_ticks();
            let _ = audit::emit_cgroup_delegation_event(
                get_audit_subject(),
                cgroup_id,
                op,
                old_uid,
                delegate_uid,
                0,
                timestamp,
            );
            Ok(0)
        }
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::PermissionDenied) => Err(SyscallError::EPERM),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// R93-5 FIX: Check if target cgroup is a descendant of ancestor cgroup.
///
/// Returns true if `target_id` is the same as `ancestor_id` or is a descendant
/// (child, grandchild, etc.) of `ancestor_id`. This is used to enforce that
/// non-root processes can only move to more restricted (deeper) cgroups.
fn cgroup_is_descendant_of(target_id: u64, ancestor_id: u64) -> bool {
    // Same cgroup is allowed (no movement)
    if target_id == ancestor_id {
        return true;
    }

    // Walk up from target to see if we reach ancestor
    let target = match cgroup::lookup_cgroup(target_id) {
        Some(cg) => cg,
        None => return false,
    };

    let mut cursor = target.parent();
    while let Some(parent) = cursor {
        if parent.id() == ancestor_id {
            return true;
        }
        cursor = parent.parent();
    }

    false
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
///
/// R93-5 FIX: Require privilege to migrate between cgroups.
///
/// To prevent unprivileged cgroup escape (moving to a less restricted parent):
/// 1. Require CAP_SYS_ADMIN or root (euid == 0) to attach
/// 2. Target cgroup must be a descendant of current cgroup (can only move deeper)
///
/// Root users can still move anywhere; non-root with CAP_SYS_ADMIN is restricted
/// to descendants to prevent accidental privilege escalation.
fn sys_cgroup_attach(cgroup_id: u64) -> Result<usize, SyscallError> {
    let pid = crate::process::current_pid().ok_or(SyscallError::ESRCH)?;
    let process = crate::process::get_process(pid).ok_or(SyscallError::ESRCH)?;

    let old_cgroup_id = {
        let proc = process.lock();
        proc.cgroup_id
    };

    // R93-5 FIX: Require CAP_SYS_ADMIN or root to attach to cgroups
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let is_root = crate::current_is_host_root();

    if !is_root {
        // P1-3: Delegated owners of the target cgroup may attach without
        // CAP_SYS_ADMIN, but are still subject to the descendant-or-delegated
        // check to prevent cgroup escape.
        if is_cgroup_delegated_to_caller(cgroup_id) {
            // Delegated user: verify target is within the delegated subtree.
            // is_delegated_to() already walks ancestors, so if the target cgroup
            // is delegated to us, attaching is safe.
        } else {
            // Non-delegated, non-root: need CAP_SYS_ADMIN + descendant check
            let has_cap_admin =
                with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN))
                    .unwrap_or(false);
            if !has_cap_admin {
                return Err(SyscallError::EPERM);
            }

            // R93-5 FIX: Non-root can only move to descendant cgroups to prevent escape
            // This prevents moving from a restricted child to a less-restricted parent
            if !cgroup_is_descendant_of(cgroup_id, old_cgroup_id) {
                return Err(SyscallError::EPERM);
            }
        }
    }

    // R156-1 FIX: Read memory_space under brief lock, then call
    // address_space_share_count() OUTSIDE Process lock to avoid ABBA
    // deadlock. address_space_share_count() acquires PROCESS_TABLE then
    // iterates locking Process::inner — holding our Process::inner first
    // inverts the documented Level 5 ordering with create_process().
    let memory_space = { process.lock().memory_space };
    if memory_space != 0
        && crate::process::address_space_share_count(memory_space) > 1
    {
        return Err(SyscallError::EBUSY);
    }

    // R155-5 FIX: Hold Process lock across the ENTIRE migration window
    // (migrate_task + charge transfer + cgroup_id update).
    let mut proc = process.lock();

    // R156-1 FIX: Re-verify memory_space after re-acquiring lock.
    // Between the share_count check and here, exec/clone could have
    // changed memory_space. Return EAGAIN so caller can retry.
    if proc.memory_space != memory_space {
        return Err(SyscallError::EAGAIN);
    }

    // R171 M2-1 SLICE-1 FIX: refuse to re-home a task that is mid-`sys_exec`.
    // exec HARD-charges the new image to its snapshot cgroup inside load_elf with
    // the Process lock DROPPED; migrating the task in that window would snapshot
    // compute_cgroup_charged_bytes WITHOUT the in-flight charge and strand it on the
    // snapshot cgroup. Checked here UNDER the held Process lock, BEFORE migrate_task,
    // so the membership move and the exec charge are mutually exclusive. The exec
    // window is bounded and self-clears → EAGAIN (retry) is the correct response.
    if proc.exec_in_progress {
        return Err(SyscallError::EAGAIN);
    }

    match cgroup::migrate_task(pid as u64, old_cgroup_id, cgroup_id) {
        Ok(()) => {
            let total_charged_bytes =
                crate::process::compute_cgroup_charged_bytes(&proc);

            // J2-7: combined cgroup migration with a HOLE-FREE rollback. The two
            // MOVABLE controllers (memory + FDs) are migrated so that EVERY rollback
            // is a saturating uncharge (can never fail) or the pre-existing
            // best-effort migrate_task reverse — there is no fallible reverse-charge
            // that could strand a charge in the destination.
            //
            // R169-7 (D2-J2-CHARGE-LIFETIME): per-cgroup ephemeral-PORT charges are
            // intentionally NOT re-homed here. Unlike fds/memory (per-process
            // tallies owned by this PID), a port charge is anchored in the
            // `PortBinding.charged_cgroup` of an `Arc<SocketState>` that may be
            // SHARED by N file descriptors across fork/CLONE_FILES/dup — there is no
            // per-process port tally to move, and re-keying by PID would
            // mis-attribute a sibling's still-live charge. The charge therefore
            // stays anchored to the cgroup that allocated the port until the binding
            // is torn down (uncharge uses the STORED cgid) or dead-`Weak` reaped by
            // the global sweep (`sweep_stranded_port_charges`). The residual is made
            // LOUD by the R169-3 `delete_cgroup` gate (the source cgroup cannot be
            // deleted while a live port charge references it) and self-heals on
            // socket teardown. Full Arc-shared port migration is a separate
            // from-scratch design (needs a designated-owner socket set), DEFERRED.
            //
            // Protocol: (1) charge the FD count
            // to the DESTINATION first; (2) migrate memory (charge-dest-first,
            // R148-1); (3) complete the FD move by uncharging the SOURCE. The
            // reverse of step 1 is uncharge_fds (never fails); a step-2 failure
            // leaves memory at the source (R148-1), so we just undo step 1.
            // fds_charged_count is read under the held Process lock.
            let fd_count = proc.fds_charged_count;
            if let Err(_e) = cgroup::try_charge_fds(cgroup_id, fd_count) {
                let _ = cgroup::migrate_task(pid as u64, cgroup_id, old_cgroup_id);
                return Err(SyscallError::EAGAIN);
            }
            if let Err(_e) = cgroup::migrate_memory_charges(
                total_charged_bytes,
                old_cgroup_id,
                cgroup_id,
            ) {
                // Memory dest-charge failed → source memory untouched (R148-1).
                // Undo the FD dest-charge (saturating, never fails) and revert.
                // R156-5 FIX: keep the Process lock held throughout the rollback.
                cgroup::uncharge_fds(cgroup_id, fd_count);
                let _ = cgroup::migrate_task(pid as u64, cgroup_id, old_cgroup_id);
                return Err(SyscallError::ENOMEM);
            }
            // Both destinations charged and memory source uncharged. Complete the
            // FD migration: uncharge the source (never fails). FDs + memory now
            // both reside at the destination, consistent with proc.cgroup_id.
            cgroup::uncharge_fds(old_cgroup_id, fd_count);

            // R170-3 FIX: land any contention-deferred CPU-quota debt on the
            // OLD cgroup BEFORE re-pointing (take under the held Process
            // lock, then flush — the blocking walk is process-context-legal
            // under the established Process → cgroup order). Without this,
            // the next tick's tag-mismatch branch would silently discard the
            // source cgroup's deferred charge.
            let quota_debt = (proc.cpu_quota_debt_cgid, proc.cpu_quota_debt_ns);
            proc.cpu_quota_debt_ns = 0;
            cgroup::flush_cpu_quota_debt(
                quota_debt.0,
                quota_debt.1,
                crate::current_timestamp_ms().saturating_mul(1_000_000),
            );

            proc.cgroup_id = cgroup_id;
            Ok(0)
        }
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::PidsLimitExceeded) => Err(SyscallError::EAGAIN),
        Err(cgroup::CgroupError::TaskNotAttached) => {
            // R94-11 FIX: TaskNotAttached indicates an inconsistent state between
            // the PCB's recorded cgroup_id and the actual cgroup membership.
            // This should not happen in normal operation and may indicate:
            // - A race condition during cgroup migration
            // - Memory corruption
            // - A bug in cgroup bookkeeping
            //
            // Previous behavior: Try direct attach to new cgroup as fallback.
            // This was a security risk because it could bypass cgroup hierarchy
            // restrictions - a task might escape from a restricted child cgroup
            // to a less-restricted parent by exploiting this fallback path.
            //
            // New behavior: Return EIO to indicate internal inconsistency.
            // The caller should not retry without understanding the root cause.
            // This is fail-closed security: we refuse to proceed when state is
            // indeterminate rather than potentially violating isolation.
            Err(SyscallError::EIO)
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
/// J2-7: per-cgroup open-FD count limit (`files.max`). value = max fds (u64::MAX = unlimited).
const CGROUP_LIMIT_FILES_MAX: u32 = 8;
/// J2-8: per-cgroup ephemeral-port count limit (`ports.max`). value = max ports (u64::MAX = unlimited).
const CGROUP_LIMIT_PORTS_MAX: u32 = 9;
/// J2-10: per-cgroup VFS dir-enumeration byte limit (`vfs_dir.max`). value = max bytes (u64::MAX = unlimited).
const CGROUP_LIMIT_VFS_DIR_MAX: u32 = 10;

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
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability to set limits.
fn sys_cgroup_set_limit(cgroup_id: u64, limit_type: u32, value: u64) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for setting limits
    // P1-3: Delegated owners may set limits bounded by parent ceilings
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
    let is_host_root = crate::current_is_host_root();

    let is_delegated = !has_cap_admin && !is_host_root && is_cgroup_delegated_to_caller(cgroup_id);
    if !has_cap_admin && !is_host_root && !is_delegated {
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
        CGROUP_LIMIT_FILES_MAX => {
            // J2-7: per-cgroup open-FD budget (value = max fds; u64::MAX = unlimited).
            // 0 is a valid limit (no fds allowed), mirroring pids.max semantics.
            limits.fds_max = Some(value);
        }
        CGROUP_LIMIT_PORTS_MAX => {
            // J2-8: stored now; enforced when the NET-port charge wiring lands.
            limits.ports_max = Some(value);
        }
        CGROUP_LIMIT_VFS_DIR_MAX => {
            // J2-10: stored now; enforced when the VFS dir-budget wiring lands.
            limits.vfs_dir_max = Some(value);
        }
        _ => return Err(SyscallError::EINVAL),
    }

    // P1-3: Delegated (non-root, non-admin) users must satisfy hierarchical
    // boundary checks — they cannot set limits that exceed their ancestors'
    // effective limits, preventing privilege escalation via delegation.
    if is_delegated {
        if let Err(_) = cgroup_node.check_limit_boundary(&limits) {
            return Err(SyscallError::EPERM);
        }
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
/// * `buf` - Pointer to a userspace CgroupStatsBuf to fill
///
/// # Returns
/// * On success: 0 (writes exactly the frozen `CGROUP_STATS_V1_SIZE` v1 prefix)
/// * On error: Negative errno
///
/// J.2 ABI NOTE: syscall 504 is FROZEN at the v1 layout. It always writes
/// `CGROUP_STATS_V1_SIZE` bytes (the offset-stable v1 prefix) and returns 0,
/// regardless of how CgroupStatsBuf grows. The appended fields (fds/ports/vfs_dir
/// current + events) are read via the negotiated v2 entry point
/// `sys_cgroup_get_stats2` (syscall 516) — 504's ABI never changes.
fn sys_cgroup_get_stats(cgroup_id: u64, buf: *mut CgroupStatsBuf) -> Result<usize, SyscallError> {
    cgroup_stats_collect_and_copy(cgroup_id, buf, CGROUP_STATS_V1_SIZE)?;
    Ok(0)
}

/// sys_cgroup_get_stats2 - Get cgroup statistics with statx-style size negotiation.
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `buf` - Pointer to a userspace CgroupStatsBuf to fill
/// * `buf_len` - Caller-declared size of `buf` in bytes. The kernel writes EXACTLY
///   `min(buf_len, size_of::<CgroupStatsBuf>())` bytes and NEVER past the declared
///   length. Appended fields are offset-stable, so a caller declaring a smaller
///   buffer receives the matching prefix; a larger buffer is filled up to sizeof.
///
/// # Returns
/// * On success: number of bytes written (== `min(buf_len, sizeof)`; 0 when buf_len==0)
/// * On error: Negative errno
fn sys_cgroup_get_stats2(
    cgroup_id: u64,
    buf: *mut CgroupStatsBuf,
    buf_len: usize,
) -> Result<usize, SyscallError> {
    let copy_len = buf_len.min(core::mem::size_of::<CgroupStatsBuf>());
    cgroup_stats_collect_and_copy(cgroup_id, buf, copy_len)?;
    Ok(copy_len)
}

/// J.2: Shared collector for the cgroup-stats syscalls (v1 504 + v2 516).
///
/// Validates the caller, builds the full CgroupStatsBuf, and writes EXACTLY
/// `copy_len` bytes — the offset-stable prefix — never more. `copy_len == 0` is a
/// valid no-op (writes nothing): it must NOT call `validate_user_ptr_mut`, which
/// rejects a zero-length range (defense against NULL/zero-size confusion).
fn cgroup_stats_collect_and_copy(
    cgroup_id: u64,
    buf: *mut CgroupStatsBuf,
    copy_len: usize,
) -> Result<(), SyscallError> {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    // R162-13 FIX: full range check (start + size) — but only over the bytes we
    // will actually write. Skip for the zero-length no-op (validate rejects len 0).
    if copy_len > 0 {
        validate_user_ptr_mut(buf as *mut u8, copy_len)?;
    }

    // P1-3: Stats access should respect delegation boundaries.
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin =
        with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN)).unwrap_or(false);
    if !crate::current_is_host_root() && !has_cap_admin && !is_cgroup_delegated_to_caller(cgroup_id) {
        return Err(SyscallError::EPERM);
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
        // J.2 items 7/8/10: FD / ephemeral-port / VFS-dir accounting.
        fds_current: stats.fds_current,
        ports_current: stats.ports_current,
        vfs_dir_current: stats.vfs_dir_current,
        fds_events_max: stats.fds_events_max,
        ports_events_max: stats.ports_events_max,
    };

    // H.0.1-3: Copy via zeroed byte buffer so padding bytes are guaranteed zero.
    if copy_len > 0 {
        copy_cgroup_stats_to_user(buf, &result, copy_len)?;
    }
    Ok(())
}

// ============================================================================
// G.3 Compliance Syscalls
// ============================================================================

/// Buffer for returning compliance status to userspace.
///
/// Must match the layout expected by userspace compliance tools.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ComplianceStatusBuf {
    /// Hardening profile: 0=Secure, 1=Balanced, 2=Performance
    pub profile: u8,
    /// Whether the profile is locked (cannot be changed until reboot)
    pub profile_locked: u8,
    /// FIPS state: 0=Disabled, 1=Enabled, 2=Failed
    pub fips_state: u8,
    /// Padding for alignment
    _padding: [u8; 5],
}

// H.0.1-3: Compile-time ABI size assertion (8 bytes, alignment 1, no implicit padding).
const _: [(); 8] = [(); core::mem::size_of::<ComplianceStatusBuf>()];

/// H.0.1-3: Copy ComplianceStatusBuf to userspace via a zeroed byte buffer.
/// All fields are u8 (alignment 1, no implicit gaps), but explicit _padding
/// is guaranteed zero by the zeroed buffer pattern for defense-in-depth.
#[inline]
fn copy_compliance_status_to_user(
    user_dst: *mut ComplianceStatusBuf,
    status: &ComplianceStatusBuf,
) -> Result<(), SyscallError> {
    let mut buf = [0u8; mem::size_of::<ComplianceStatusBuf>()];
    buf[mem::offset_of!(ComplianceStatusBuf, profile)] = status.profile;
    buf[mem::offset_of!(ComplianceStatusBuf, profile_locked)] = status.profile_locked;
    buf[mem::offset_of!(ComplianceStatusBuf, fips_state)] = status.fips_state;
    // `_padding` intentionally left as zeroes in the buffer.
    copy_to_user(user_dst as *mut u8, &buf)
}

/// sys_compliance_status - Get current compliance status
///
/// # Arguments
/// * `buf` - Pointer to ComplianceStatusBuf in userspace
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno (EFAULT if pointer invalid)
fn sys_compliance_status(buf: *mut ComplianceStatusBuf) -> Result<usize, SyscallError> {
    // Validate user pointer
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let buf_addr = buf as usize;
    if buf_addr < crate::usercopy::MMAP_MIN_ADDR || buf_addr >= USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    // Get compliance status from the compliance module
    let status = compliance::status();

    let result = ComplianceStatusBuf {
        profile: status.profile as u8,
        profile_locked: if status.profile_locked { 1 } else { 0 },
        fips_state: status.fips_state as u8,
        _padding: [0; 5],
    };

    // H.0.1-3: Copy via zeroed byte buffer so padding bytes are guaranteed zero.
    copy_compliance_status_to_user(buf, &result)?;

    Ok(0)
}

/// sys_fips_enable - Enable FIPS mode (sticky until reboot)
///
/// Requires CAP_SYS_ADMIN capability. Once enabled, FIPS mode cannot be
/// disabled until the next reboot.
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///   - EPERM: Not privileged (requires CAP_SYS_ADMIN)
///   - EALREADY: FIPS mode already enabled
///   - EIO: FIPS self-test failed
fn sys_fips_enable() -> Result<usize, SyscallError> {
    // Check privilege: require root or CAP_ADMIN capability
    // R133-1 FIX: Use host-mapped root check for host-global FIPS gate.
    let _creds = crate::current_credentials().ok_or(SyscallError::ESRCH)?;
    if !crate::current_is_host_root() {
        // Check for CAP_ADMIN capability (system administration rights)
        let has_cap = with_current_cap_table(|table| table.has_rights(cap::CapRights::ADMIN));
        if has_cap != Some(true) {
            return Err(SyscallError::EPERM);
        }
    }

    // Attempt to enable FIPS mode
    match compliance::enable_fips_mode() {
        Ok(()) => Ok(0),
        Err(compliance::FipsError::AlreadyEnabled) => Err(SyscallError::EALREADY),
        Err(compliance::FipsError::EnableFailed) => Err(SyscallError::EIO), // R93-1 FIX
        Err(compliance::FipsError::SelfTestFailed) => Err(SyscallError::EIO),
        Err(_) => Err(SyscallError::EPERM),
    }
}

/// sys_compliance_query_algo - Check if a cryptographic algorithm is permitted
///
/// # Arguments
/// * `algo_id` - Algorithm identifier (matches compliance::CryptoAlgorithm repr)
///
/// # Returns
/// * 1: Algorithm is permitted under current policy
/// * 0: Algorithm is not permitted (blocked by FIPS)
/// * Negative errno on error
fn sys_compliance_query_algo(algo_id: u32) -> Result<usize, SyscallError> {
    // Convert algo_id to CryptoAlgorithm
    let algo = match algo_id {
        0 => compliance::CryptoAlgorithm::Sha256,
        1 => compliance::CryptoAlgorithm::Sha384,
        2 => compliance::CryptoAlgorithm::Sha512,
        3 => compliance::CryptoAlgorithm::Blake2b,
        4 => compliance::CryptoAlgorithm::HmacSha256,
        5 => compliance::CryptoAlgorithm::EcdsaP256,
        6 => compliance::CryptoAlgorithm::EcdsaP384,
        7 => compliance::CryptoAlgorithm::Ed25519,
        8 => compliance::CryptoAlgorithm::Aes128Gcm,
        9 => compliance::CryptoAlgorithm::Aes256Gcm,
        10 => compliance::CryptoAlgorithm::ChaCha20,
        11 => compliance::CryptoAlgorithm::ChaCha20Poly1305,
        _ => return Err(SyscallError::EINVAL),
    };

    if compliance::is_algorithm_permitted(algo) {
        Ok(1)
    } else {
        Ok(0)
    }
}

// ============================================================================
// Audit Export — G.fin.2 (cursor-based, non-draining)
// ============================================================================

/// Token-bucket rate limiter for `sys_audit_export`.
///
/// Prevents audit export from becoming a DoS vector: each exported event
/// consumes one token. Tokens refill at a fixed rate per timer tick.
///
/// - Capacity (burst): 1000 records
/// - Refill: 10 records per tick
struct AuditExportTokenBucket {
    tokens: u64,
    last_tick: u64,
}

impl AuditExportTokenBucket {
    const CAPACITY: u64 = 1000;
    const REFILL_PER_TICK: u64 = 10;

    const fn new() -> Self {
        Self {
            tokens: Self::CAPACITY,
            last_tick: 0,
        }
    }

    fn refill(&mut self, now_tick: u64) {
        if self.last_tick == 0 {
            self.last_tick = now_tick;
            return;
        }
        // Monotonic time expected; if time goes backwards, skip refill (fail-closed).
        if now_tick <= self.last_tick {
            self.last_tick = now_tick;
            return;
        }
        let elapsed = now_tick - self.last_tick;
        let added = elapsed.saturating_mul(Self::REFILL_PER_TICK);
        self.tokens = core::cmp::min(Self::CAPACITY, self.tokens.saturating_add(added));
        self.last_tick = now_tick;
    }

    fn take(&mut self, now_tick: u64, want: u64) -> u64 {
        self.refill(now_tick);
        let grant = core::cmp::min(self.tokens, want);
        self.tokens -= grant;
        grant
    }

    fn refund(&mut self, n: u64) {
        self.tokens = core::cmp::min(Self::CAPACITY, self.tokens.saturating_add(n));
    }
}

static AUDIT_EXPORT_LIMITER: spin::Mutex<AuditExportTokenBucket> =
    spin::Mutex::new(AuditExportTokenBucket::new());

/// sys_audit_export — Export audit events to userspace buffer (cursor-based, non-draining)
///
/// Requires CAP_AUDIT_READ capability or root privilege.
///
/// # Arguments
/// * `buf`        — Pointer to destination buffer in userspace
/// * `buf_len`    — Size of the buffer in bytes
/// * `cursor`     — Starting event ID (inclusive); pass 0 to start from the oldest
/// * `max_events` — Maximum number of records to export
///
/// # ABI
///
/// The buffer is filled with:
/// - [`audit::AuditExportHeader`] (96 bytes): magic `"ZAUD"`, version 3, record_count, next cursor,
///   tail_hash, dropped_since_cursor, ring_usage, backpressure_high_water_bps, batch_first_prev_hash
/// - [`audit::AuditExportRecord`] array (128 bytes each): fixed-size per-event records
///
/// The header's `cursor` field is the next cursor to use (`last_id + 1`).
///
/// # Returns
/// * On success: number of events exported (≥ 0)
/// * On error: Negative errno
///   - EPERM: Not privileged
///   - EFAULT: Invalid pointer
///   - ENOSPC: Buffer too small for header + ≥1 record
///   - EINVAL: `max_events == 0`
///   - EAGAIN: Rate limited
fn sys_audit_export(
    buf: *mut u8,
    buf_len: usize,
    cursor: u64,
    max_events: usize,
) -> Result<usize, SyscallError> {
    use crate::usercopy::copy_to_user_safe;

    // Check privilege: require root or CAP_AUDIT_READ.
    // R133-1 FIX: Use host-mapped root check for host-global audit gate.
    let creds = crate::current_credentials().ok_or(SyscallError::ESRCH)?;
    let caller_is_root = crate::current_is_host_root();
    if !caller_is_root {
        let has_cap = with_current_cap_table(|table| table.has_rights(cap::CapRights::AUDIT_READ));
        if has_cap != Some(true) {
            return Err(SyscallError::EPERM);
        }
    }

    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if max_events == 0 {
        return Err(SyscallError::EINVAL);
    }

    let buf_addr = buf as usize;
    // R107-6 FIX: Validate both buffer start AND end against user-space boundaries.
    // Without end-of-buffer check, a malicious caller could pass buf near USER_SPACE_TOP
    // with a large buf_len, causing wrapping_add to produce kernel-space addresses.
    if buf_addr < crate::usercopy::MMAP_MIN_ADDR || buf_addr >= USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }
    if buf_len > USER_SPACE_TOP - buf_addr {
        return Err(SyscallError::EFAULT);
    }

    const HEADER_SIZE: usize = audit::AuditExportHeader::SIZE;
    const RECORD_SIZE: usize = audit::AuditExportRecord::SIZE;

    // Require space for at least the header + one record.
    if buf_len < HEADER_SIZE + RECORD_SIZE {
        return Err(SyscallError::ENOSPC);
    }

    // How many records physically fit in the buffer?
    let max_fit = (buf_len - HEADER_SIZE) / RECORD_SIZE;
    let requested = core::cmp::min(max_events, core::cmp::min(max_fit, u16::MAX as usize));
    if requested == 0 {
        return Err(SyscallError::ENOSPC);
    }

    // Token-bucket rate limiting: reserve up to `requested` event exports.
    let now_tick = crate::time::get_ticks();
    let reserved = {
        let mut limiter = AUDIT_EXPORT_LIMITER.lock();
        limiter.take(now_tick, requested as u64)
    };
    if reserved == 0 {
        return Err(SyscallError::EAGAIN);
    }

    // Perform the non-draining export.
    let batch = match audit::export(cursor, reserved as usize) {
        Ok(b) => b,
        Err(audit::AuditError::AccessDenied) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EPERM);
        }
        Err(audit::AuditError::Uninitialized) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::ENOSYS);
        }
        Err(_) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EIO);
        }
    };

    let exported = batch.events.len();
    let record_count = core::cmp::min(exported, u16::MAX as usize) as u16;

    // Write header.
    let header = audit::AuditExportHeader::new(
        record_count,
        batch.next_cursor,
        batch.tail_hash,
        batch.ring_usage,
        batch.dropped_since_cursor,
        batch.batch_first_prev_hash,
    );
    let header_bytes = header.to_bytes();
    if copy_to_user_safe(buf, &header_bytes).is_err() {
        AUDIT_EXPORT_LIMITER.lock().refund(reserved);
        return Err(SyscallError::EFAULT);
    }

    // Write records. Non-root callers get redacted syscall args.
    let redact_syscall_args = !caller_is_root;
    for (i, event) in batch.events.iter().enumerate() {
        let record = audit::AuditExportRecord::from_event(event, redact_syscall_args);
        let record_bytes = record.to_bytes();

        let offset = HEADER_SIZE + i * RECORD_SIZE;
        // R107-6 FIX: Use checked_add for defense-in-depth. The upfront buf_len boundary
        // check guarantees this cannot overflow, but checked_add makes the intent explicit.
        let dst_addr = match (buf as usize).checked_add(offset) {
            Some(addr) => addr,
            None => {
                AUDIT_EXPORT_LIMITER.lock().refund(reserved);
                return Err(SyscallError::EFAULT);
            }
        };
        let dst = dst_addr as *mut u8;
        if copy_to_user_safe(dst, &record_bytes).is_err() {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EFAULT);
        }
    }

    // Refund any unused tokens (reserved > exported if ring had fewer events).
    let unused = reserved.saturating_sub(exported as u64);
    if unused > 0 {
        AUDIT_EXPORT_LIMITER.lock().refund(unused);
    }

    Ok(exported)
}

// ============================================================================
// G.2 Live Patching syscalls (509-511)
// ============================================================================

/// sys_kpatch_load (509): Load a patch image from userspace.
///
/// Arguments:
/// - user_ptr: Pointer to patch image buffer in userspace
/// - len: Length of patch image in bytes
///
/// Returns:
/// - Positive patch_id on success (as usize)
/// - Negative errno on failure (EPERM, EFAULT, E2BIG, EINVAL, EACCES, etc.)
fn sys_kpatch_load(user_ptr: usize, len: usize) -> Result<usize, SyscallError> {
    // Delegate to livepatch crate which handles privilege check via KernelOps
    let result = livepatch::sys_kpatch_load(user_ptr, len);
    if result < 0 {
        // Convert livepatch errno to SyscallError
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -7 => Err(SyscallError::E2BIG),
            -12 => Err(SyscallError::ENOMEM),
            -13 => Err(SyscallError::EACCES),
            -14 => Err(SyscallError::EFAULT),
            -16 => Err(SyscallError::EBUSY),
            -17 => Err(SyscallError::EEXIST),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(result as usize)
    }
}

/// sys_kpatch_enable (510): Enable a previously loaded patch.
///
/// Arguments:
/// - patch_id: Patch identifier returned by sys_kpatch_load
///
/// Returns:
/// - 0 on success
/// - Negative errno on failure
fn sys_kpatch_enable(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_enable(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// sys_kpatch_disable (511): Disable (rollback) a previously enabled patch.
///
/// Arguments:
/// - patch_id: Patch identifier returned by sys_kpatch_load
///
/// Returns:
/// - 0 on success
/// - Negative errno on failure
fn sys_kpatch_disable(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_disable(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// sys_kpatch_unload — Unload a disabled livepatch module and free its memory.
///
/// R104-5 FIX: This wrapper was missing from the syscall layer, leaving
/// syscall 512 dispatching to the default ENOSYS path.
///
/// # Arguments
/// * `patch_id` - The patch identifier returned by `sys_kpatch_load`.
///
/// # Errors
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — no patch with the given id
/// - `EBUSY`   — patch is still enabled
/// - `EINVAL`  — invalid patch_id or internal error
/// - `ENOSYS`  — livepatch subsystem not available
fn sys_kpatch_unload(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_unload(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// P1-4: sys_kpatch_enable_all (514) — Enable all loaded patches in topological
/// dependency order.
///
/// Patches already in `Enabled` state are skipped. On failure, all patches
/// enabled by this batch are rolled back (disabled) in reverse order.
///
/// # Arguments
///
/// Takes no arguments (operates on all loaded patches).
///
/// # Errors
///
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — a dependency UID is not loaded, or a patch disappeared
/// - `EBUSY`   — a patch is in a transitional state
/// - `EINVAL`  — dependency cycle detected
/// - `ENOSYS`  — livepatch subsystem not available
fn sys_kpatch_enable_all() -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_enable_all();
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// P1-4: sys_kpatch_disable_all (515) — Disable all enabled patches in reverse
/// topological dependency order.
///
/// Patches not in `Enabled` state are skipped. On failure, all patches
/// disabled by this batch are re-enabled in reverse order.
///
/// # Arguments
///
/// Takes no arguments (operates on all enabled patches).
///
/// # Errors
///
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — a patch disappeared during iteration
/// - `EBUSY`   — a patch is in a transitional state
/// - `EINVAL`  — dependency cycle detected
/// - `ENOSYS`  — livepatch subsystem not available
fn sys_kpatch_disable_all() -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_disable_all();
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
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
        klog!(Info, "=== Syscall Statistics ===");
        klog!(Info, "Total calls:  {}", self.total_calls);
        klog!(Info, "Exit calls:   {}", self.exit_calls);
        klog!(Info, "Fork calls:   {}", self.fork_calls);
        klog!(Info, "Read calls:   {}", self.read_calls);
        klog!(Info, "Write calls:  {}", self.write_calls);
        klog!(Info, "Failed calls: {}", self.failed_calls);
    }
}
