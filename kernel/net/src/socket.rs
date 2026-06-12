//! Socket capability layer for Zero-OS (Phase D.2)
//!
//! This module provides a capability-based socket API with security-first design:
//!
//! - **Capability-Based Access**: Sockets are accessed via CapId handles
//! - **LSM Integration**: All operations pass through security hooks
//! - **Rate Limiting**: Per-socket and global limits prevent DoS
//! - **Security Labels**: Sockets carry creator context for MAC enforcement
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |  User Syscall    | --> |  SocketTable     | --> |  SocketState     |
//! |  (via CapId)     |     |  (global lookup) |     |  (per-socket)    |
//! +------------------+     +------------------+     +------------------+
//!                                  |                        |
//!                                  v                        v
//!                          +------------------+     +------------------+
//!                          |  Port Bindings   |     |  RX Queue        |
//!                          |  (UDP port map)  |     |  (datagrams)     |
//!                          +------------------+     +------------------+
//! ```
//!
//! # Security Features
//!
//! 1. **Capability Checks**: Each syscall validates CapId and rights
//! 2. **LSM Hooks**: create/bind/send/recv pass through hook_net_*
//! 3. **Socket Labels**: Creator credentials captured for MAC decisions
//! 4. **Queue Limits**: MAX_RX_QUEUE prevents memory exhaustion
//! 5. **Port Validation**: Privileged ports require root or capability
//!
//! # Example Flow
//!
//! ```text
//! 1. sys_socket() -> LSM hook_net_socket -> create SocketState -> CapId
//! 2. sys_bind()   -> LSM hook_net_bind   -> allocate port
//! 3. sys_sendto() -> LSM hook_net_send   -> build UDP datagram
//! 4. sys_recvfrom() -> wait on RX queue  -> LSM hook_net_recv -> return data
//! ```
//!
//! # References
//!
//! - POSIX.1-2017 Socket Interface
//! - RFC 768: UDP Protocol

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once, RwLock};

use cap::{CapId, NamespaceId};
use lsm::{
    hook_net_bind, hook_net_connect, hook_net_listen, hook_net_recv, hook_net_send,
    hook_net_shutdown, hook_net_socket, LsmError, NetCtx, ProcessCtx,
};

use crate::ipv4::Ipv4Addr;
use crate::stack::transmit_tcp_segment;
use crate::tcp::{
    build_tcp_segment, build_tcp_segment_with_options, calc_wscale, decode_window, encode_window,
    generate_isn, generate_syn_cookie_isn, handle_ack, handle_retransmission_timeout, initial_cwnd,
    seq_ge, seq_gt, seq_in_window, syn_cookie_select_mss,
    update_congestion_control, validate_cwnd_after_idle, validate_syn_cookie, CongestionAction,
    SackBlock, TcpConnKey, TcpControlBlock, TcpHeader, TcpOptionKind, TcpOptions, TcpSegment,
    TcpState, TCP_DEFAULT_WINDOW, TCP_ETHERNET_MSS, TCP_FIN_TIMEOUT_MS, TCP_FIN_WAIT_2_TIMEOUT_MS,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
    TCP_MAX_ACCEPT_BACKLOG, TCP_MAX_ACTIVE_CONNECTIONS, TCP_MAX_FIN_RETRIES, TCP_MAX_RETRIES,
    TCP_MAX_RTO_MS, TCP_MAX_SEND_BUFFER_BYTES, TCP_MAX_SEND_SIZE, TCP_MAX_SYN_BACKLOG, TCP_MAX_WINDOW_SCALE, TCP_PROTO,
    TCP_SYN_TIMEOUT_MS, TCP_TIME_WAIT_MS,
};
use crate::udp::{
    build_udp_datagram, UdpError, EPHEMERAL_PORT_END, EPHEMERAL_PORT_START, UDP_PROTO,
};

// ============================================================================
// Simple Wait Primitives (local to net crate to avoid ipc dependency)
// ============================================================================

/// Wait operation outcome.
///
/// Represents the result of a blocking wait operation.
/// Used by both socket waits and futex operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Resource became available (waiter was explicitly woken)
    Woken,
    /// Operation timed out
    TimedOut,
    /// Resource closed (socket/queue closed while waiting)
    Closed,
    /// No process context available (called from kernel context)
    NoProcess,
}

// ============================================================================
// Socket Wait Hooks (Scheduler Integration)
// ============================================================================

/// Scheduler integration hooks for socket blocking waits.
///
/// This trait allows the net crate to perform true blocking waits without
/// depending on kernel_core's process/scheduler implementation directly.
/// kernel_core registers an implementation at initialization time.
///
/// # Design
///
/// The trait design follows the same pattern as stdin blocking in syscall.rs:
/// 1. Mark process as Blocked
/// 2. Add to waiter queue
/// 3. Call force_reschedule to yield CPU
/// 4. On wakeup, check condition and return outcome
///
/// # Safety
///
/// Implementations must:
/// - Properly handle interrupt disabling during state transitions
/// - Not hold locks across reschedule calls to avoid deadlock
/// - Clean up waiter entries on timeout or close
pub trait SocketWaitHooks: Send + Sync {
    /// Block the current task until woken, timed out, or the queue is closed.
    ///
    /// # Arguments
    /// * `queue` - The wait queue to block on
    /// * `timeout_ns` - Optional timeout in nanoseconds:
    ///   - `None`: Block indefinitely
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///
    /// # Returns
    /// * `Woken` - Explicitly woken by wake_one/wake_all
    /// * `TimedOut` - Timeout expired before wakeup
    /// * `Closed` - Queue was closed while waiting
    /// * `NoProcess` - No current process context (kernel thread)
    fn wait(&self, queue: &WaitQueue, timeout_ns: Option<u64>) -> WaitOutcome;

    /// Wake one waiter blocked on this queue.
    ///
    /// If multiple waiters are blocked, wakes the one that blocked first (FIFO).
    fn wake_one(&self, queue: &WaitQueue);

    /// Wake all waiters blocked on this queue.
    fn wake_all(&self, queue: &WaitQueue);

    /// Get the current kernel tick count (monotonic milliseconds since boot).
    ///
    /// Used for TIME_WAIT timer initialization when the periodic sweep hasn't
    /// yet primed the cached clock. This provides accurate timing instead of
    /// relying on TSC assumptions.
    ///
    /// # R51-6 Enhancement
    ///
    /// Replaces the RDTSC-based fallback which assumed a 2GHz TSC frequency.
    /// The kernel tick counter is calibrated and reliable.
    fn get_ticks(&self) -> u64;
}

/// Static storage for the registered wait hooks.
///
/// Uses spin::Once to ensure thread-safe one-time initialization.
/// After initialization, the reference is valid for the lifetime of the kernel.
static SOCKET_WAIT_HOOKS: spin::Once<&'static dyn SocketWaitHooks> = spin::Once::new();

/// Register kernel scheduler hooks for socket waits.
///
/// This should be called once during kernel initialization from kernel_core::init().
/// Multiple calls are safe - only the first registration takes effect.
///
/// # Arguments
/// * `hooks` - Static reference to a SocketWaitHooks implementation
pub fn register_socket_wait_hooks(hooks: &'static dyn SocketWaitHooks) {
    SOCKET_WAIT_HOOKS.call_once(|| hooks);
}

/// Read CPU timestamp counter for low-quality entropy fallback.
///
/// Used when CSPRNG is unavailable to provide unpredictable port selection.
/// Not cryptographically secure but better than a monotonic counter.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn rdtsc() -> u64 {
    // Fallback for non-x86_64: use a constant that will be mixed with counter
    0xa5a5_5a5a_d3e4_c7d2_u64
}

/// Get the registered wait hooks, if any.
#[inline]
fn socket_wait_hooks() -> Option<&'static dyn SocketWaitHooks> {
    SOCKET_WAIT_HOOKS.get().copied()
}

/// R162-20 FIX: Public helper for stack.rs to get kernel ticks via hooks.
pub fn socket_wait_hooks_get_ticks() -> Option<u64> {
    socket_wait_hooks().map(|h| h.get_ticks())
}

// ============================================================================
// J2-8: Per-cgroup ephemeral-port budget upcall (CgroupPortHooks)
// ============================================================================
//
// The `net` crate cannot depend on `kernel_core::cgroup` (kernel_core depends on
// net -> a direct call would be a dependency cycle). So per-cgroup port charging
// is injected via a trait object registered by kernel_core at boot, exactly like
// `SocketWaitHooks`. kernel_core's impl forwards to `cgroup::try_charge_ports` /
// `cgroup::uncharge_ports` and `process::current_cgroup_id`.

/// Hooks for charging a per-cgroup ephemeral-port budget (J.2 item 8).
///
/// All three methods run in the contexts the lock-ordering invariant allows:
/// `current_cgroup_id` and `try_charge_ports` only from process (syscall)
/// context BEFORE any net-binding lock is taken; `uncharge_ports` only from the
/// process-context deferred-uncharge drain or the direct teardown sites AFTER
/// every binding lock is dropped (never under an L8 binding lock, never in IRQ).
pub trait CgroupPortHooks: Send + Sync {
    /// Current task's cgroup id, or `None` for non-process (kernel-thread / RX)
    /// callers. `None` and root both resolve to 0 (exempt) at the call site.
    fn current_cgroup_id(&self) -> Option<u64>;
    /// Hierarchically charge one ephemeral port against `cgid` and its NET
    /// ancestors. `Err(())` on `ports.max` exceeded (mapped to EAGAIN by net).
    fn try_charge_ports(&self, cgid: u64, n: u64) -> Result<(), ()>;
    /// Hierarchically uncharge `n` ephemeral ports from `cgid` (saturating).
    fn uncharge_ports(&self, cgid: u64, n: u64);
}

static CGROUP_PORT_HOOKS: spin::Once<&'static dyn CgroupPortHooks> = spin::Once::new();

/// Register the per-cgroup port-budget hooks (called once from kernel_core init).
pub fn register_cgroup_port_hooks(hooks: &'static dyn CgroupPortHooks) {
    CGROUP_PORT_HOOKS.call_once(|| hooks);
}

#[inline]
fn cgroup_port_hooks() -> Option<&'static dyn CgroupPortHooks> {
    CGROUP_PORT_HOOKS.get().copied()
}

/// Resolve the current task's cgroup id for a port charge, or 0 (root / exempt)
/// when there is no process context or no hook is registered yet.
///
/// Fail-open is SAFE here: a non-zero cgid is only ever produced by a real
/// userspace process attached to a non-root cgroup, which cannot exist before
/// the hook is registered at boot (the registration precedes userspace), so the
/// charge/uncharge helpers below are never reached with `cgid != 0` while
/// unregistered. This mirrors how the other controllers short-circuit cgid 0.
#[inline]
fn resolve_port_cgroup() -> u64 {
    cgroup_port_hooks()
        .and_then(|h| h.current_cgroup_id())
        .unwrap_or(0)
}

/// Charge one ephemeral port against `cgid` (process context, before any binding
/// lock). Returns `QuotaExceeded` (-> EAGAIN) when `ports.max` is hit. A 0 cgid
/// (root / no process / pre-registration) is a no-op success.
#[inline]
fn try_charge_port_cgroup(cgid: u64) -> Result<(), SocketError> {
    if cgid == 0 {
        return Ok(());
    }
    match cgroup_port_hooks() {
        Some(h) => h.try_charge_ports(cgid, 1).map_err(|_| SocketError::QuotaExceeded),
        None => Ok(()), // unreachable with cgid != 0 (see resolve_port_cgroup)
    }
}

/// Uncharge `n` ephemeral ports from `cgid`. Process context only (drain / direct
/// teardown after all binding locks are dropped). A 0 cgid is a no-op.
#[inline]
fn uncharge_port_cgroup(cgid: u64, n: u64) {
    if cgid == 0 || n == 0 {
        return;
    }
    if let Some(h) = cgroup_port_hooks() {
        h.uncharge_ports(cgid, n);
    }
}

/// Simple wait queue with optional scheduler integration.
///
/// When SocketWaitHooks are registered, this queue supports true blocking
/// with timeout. Without hooks, only non-blocking polling is supported.
///
/// # Architecture
///
/// The queue maintains:
/// - A closed flag to signal permanent closure
/// - A wakeup counter for detecting spurious wakeups
///
/// Actual waiter tracking is delegated to the SocketWaitHooks implementation
/// in kernel_core, which has access to the process table and scheduler.
pub struct WaitQueue {
    /// Flag indicating if the queue is closed
    closed: AtomicBool,
    /// Wakeup counter (incremented on wake, read on wait to detect wakeup).
    ///
    /// R153-I3 NOTE: Under sustained traffic, wake_one()/wake_all() accumulate
    /// tokens faster than waiters consume them. This is benign — the 2^64
    /// wraparound is non-exploitable, and try_consume_wakeup() returns early
    /// `Woken` (not a spin loop). If this becomes a performance concern under
    /// heavy load, consider a generation counter or 0/1 pending-wake flag.
    wakeup_count: AtomicU64,
}

impl WaitQueue {
    /// Create a new wait queue.
    pub fn new() -> Self {
        WaitQueue {
            closed: AtomicBool::new(false),
            wakeup_count: AtomicU64::new(0),
        }
    }

    /// Try to consume one pending wake token.
    ///
    /// Returns `true` if a token was consumed.
    ///
    /// R152-2 FIX: SocketWaitHooks implementations must consume wake tokens
    /// *after* waiter registration to avoid missed-wakeup races.
    pub fn try_consume_wakeup(&self) -> bool {
        self.wakeup_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current > 0).then(|| current - 1)
            })
            .is_ok()
    }

    /// Wait with optional timeout.
    ///
    /// # Arguments
    /// * `timeout_ns` - Timeout in nanoseconds.
    ///   - `Some(0)`: Non-blocking poll (return immediately)
    ///   - `Some(n)`: Block for up to n nanoseconds
    ///   - `None`: Block indefinitely
    ///
    /// # Returns
    /// - `WaitOutcome::Woken` if wakeup was signaled
    /// - `WaitOutcome::TimedOut` if timeout expired or non-blocking poll
    /// - `WaitOutcome::Closed` if the queue is closed
    /// - `WaitOutcome::NoProcess` if no process context (kernel thread)
    pub fn wait_with_timeout(&self, timeout_ns: Option<u64>) -> WaitOutcome {
        // Check if closed
        if self.closed.load(Ordering::Acquire) {
            return WaitOutcome::Closed;
        }

        // Non-blocking poll returns immediately
        if timeout_ns == Some(0) {
            return WaitOutcome::TimedOut;
        }

        // R152-2 FIX: Delegate to scheduler hooks for true blocking.
        // Wake token consumption must happen *after* waiter registration inside
        // the hooks implementation, otherwise a wake that arrives between the
        // pre-check and registration is missed.
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wait(self, timeout_ns)
        } else if self.try_consume_wakeup() {
            WaitOutcome::Woken
        } else {
            // No scheduler hooks registered - fall back to non-blocking.
            // This happens early in boot or in kernel threads.
            WaitOutcome::TimedOut
        }
    }

    /// Signal one waiter.
    ///
    /// Wakes the first blocked waiter (FIFO order). If no waiters are blocked,
    /// increments the wakeup counter so the next wait() sees it.
    pub fn wake_one(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_one(self);
        }
    }

    /// Signal all waiters.
    ///
    /// Wakes all blocked waiters. If no waiters are blocked, increments the
    /// wakeup counter.
    pub fn wake_all(&self) {
        self.wakeup_count.fetch_add(1, Ordering::Release);
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wake_all(self);
        }
    }

    /// Close the queue and prevent further waits.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Check if closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum queued datagrams per socket.
///
/// This limit prevents memory exhaustion attacks. When the queue is full,
/// new datagrams are dropped (not an error - normal network behavior).
const MAX_RX_QUEUE: usize = 64;

/// R132-4 FIX: Maximum aggregate UDP payload bytes queued across all sockets.
///
/// Prevents memory exhaustion when many UDP sockets each buffer large datagrams.
/// 16 MiB is a conservative cap: enough for normal traffic (~250 full-size
/// datagrams) but prevents unbounded kernel heap growth from UDP flooding.
const MAX_GLOBAL_UDP_QUEUED_BYTES: usize = 16 * 1024 * 1024;

/// R132-4 FIX: Global accounting of UDP payload bytes currently queued.
///
/// Incremented atomically in `enqueue_rx()`, decremented in `pop_rx()` and
/// `SocketState::drop()` (for unread datagrams still queued at socket close).
static GLOBAL_UDP_QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Privileged port boundary (ports below this require special permissions).
const PRIVILEGED_PORT_LIMIT: u16 = 1024;

// ============================================================================
// Challenge ACK Rate Limiting (R54-2 FIX)
// ============================================================================

/// Maximum challenge ACKs per window period (RFC 5961 rate limiting).
///
/// R54-2 FIX: Prevents amplification attacks via spoofed RST packets.
/// Linux default: 100/sec (tcp_challenge_ack_limit sysctl).
const CHALLENGE_ACK_LIMIT: u32 = 100;

/// Challenge ACK rate limiting window in milliseconds.
const CHALLENGE_ACK_WINDOW_MS: u64 = 1000;

/// Token bucket for challenge ACK rate limiting.
static CHALLENGE_ACK_TOKENS: AtomicU32 = AtomicU32::new(CHALLENGE_ACK_LIMIT);

/// Window start time for challenge ACK rate limiter.
static CHALLENGE_ACK_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if a challenge ACK can be sent (rate limiter).
///
/// R54-2 FIX: Implements token bucket rate limiting for challenge ACKs
/// to prevent amplification attacks via spoofed RST packets.
///
/// # Arguments
///
/// * `now_ms` - Current timestamp in milliseconds
///
/// # Returns
///
/// `true` if a challenge ACK can be sent, `false` if rate limit exceeded.
///
/// # Security
///
/// Without this check, an attacker could send high-rate spoofed RST packets
/// with invalid sequence numbers, causing the victim to generate unlimited
/// challenge ACKs. This consumes CPU and bandwidth, and can be used as a
/// reflection/amplification attack vector.
fn allow_challenge_ack(now_ms: u64) -> bool {
    // R121-6 FIX: Use compare_exchange on window start so only one CPU
    // wins the reset race. Without CAS, multiple CPUs can simultaneously
    // observe the window as expired and all refill tokens to the full limit.
    //
    // R155-13 FIX: Refill tokens only on CAS success to prevent a losing CPU
    // from overwriting tokens the winner already spent.
    // Release on CAS pairs with Acquire on window_start load to ensure
    // the token store is visible to any CPU that sees the new window.
    let window_start = CHALLENGE_ACK_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= CHALLENGE_ACK_WINDOW_MS {
        if CHALLENGE_ACK_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            CHALLENGE_ACK_TOKENS.store(CHALLENGE_ACK_LIMIT, Ordering::Release);
        }
    }

    // Try to consume a token using CAS loop
    let mut tokens = CHALLENGE_ACK_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match CHALLENGE_ACK_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }

    // Rate limit exceeded - drop the challenge ACK
    false
}

// ============================================================================
// RST Rate Limiting (R63-4 FIX)
// ============================================================================

/// Maximum RST packets per window period.
///
/// R63-4 FIX: Prevents amplification attacks via spoofed packets that trigger
/// RST responses. Without this limit, attackers can send invalid packets to
/// cause unlimited RST generation, consuming CPU and bandwidth.
const RST_RATE_LIMIT: u32 = 100;

/// RST rate limiting window in milliseconds.
const RST_RATE_WINDOW_MS: u64 = 1000;

/// Token bucket for RST rate limiting.
static RST_TOKENS: AtomicU32 = AtomicU32::new(RST_RATE_LIMIT);

/// Window start time for RST rate limiter.
static RST_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if an RST can be sent (rate limiter).
///
/// R63-4 FIX: Implements token bucket rate limiting for RST packets
/// to prevent amplification attacks.
fn allow_rst(now_ms: u64) -> bool {
    // R121-6 FIX: Use compare_exchange on window start so only one CPU
    // wins the reset race, preventing concurrent token refill on SMP.
    // R154-15 FIX: Use AcqRel/Release ordering (same rationale as
    // allow_challenge_ack) to prevent a second CPU from seeing the new
    // window but stale zero tokens.
    let window_start = RST_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= RST_RATE_WINDOW_MS {
        if RST_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            RST_TOKENS.store(RST_RATE_LIMIT, Ordering::Release);
        }
    }

    let mut tokens = RST_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match RST_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }
    false
}

// ============================================================================
// SYN Cookie SYN-ACK Rate Limiting (R137-2 FIX)
// ============================================================================

/// Maximum SYN-cookie SYN-ACK packets per window period.
///
/// R137-2 FIX: SYN cookies generate stateless SYN-ACK responses. Without a
/// global rate limit, spoofed SYN floods cause the server to reflect SYN-ACKs
/// to victims (low amplification ~1.2x but still undesirable). 200/sec is
/// generous enough for legitimate handshakes under load while capping
/// reflection bandwidth.
const SYNACK_COOKIE_RATE_LIMIT: u32 = 200;

/// SYN-cookie SYN-ACK rate limiting window in milliseconds.
const SYNACK_COOKIE_RATE_WINDOW_MS: u64 = 1000;

/// Token bucket for SYN-cookie SYN-ACK rate limiting.
static SYNACK_COOKIE_TOKENS: AtomicU32 = AtomicU32::new(SYNACK_COOKIE_RATE_LIMIT);

/// Window start time for SYN-cookie SYN-ACK rate limiter.
static SYNACK_COOKIE_WINDOW_START: AtomicU64 = AtomicU64::new(0);

/// Check if a SYN-cookie SYN-ACK can be sent (rate limiter).
///
/// R137-2 FIX: Token bucket rate limiting for stateless SYN-cookie SYN-ACK
/// responses to reduce spoofed-source reflection amplification.
fn allow_syn_cookie_ack(now_ms: u64) -> bool {
    // Use compare_exchange on window start so only one CPU wins the reset
    // race, preventing concurrent token refill on SMP (same as allow_rst).
    // R154-15 FIX: Use AcqRel/Release ordering (same rationale as
    // allow_challenge_ack) to prevent a second CPU from seeing the new
    // window but stale zero tokens.
    let window_start = SYNACK_COOKIE_WINDOW_START.load(Ordering::Acquire);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= SYNACK_COOKIE_RATE_WINDOW_MS {
        if SYNACK_COOKIE_WINDOW_START
            .compare_exchange(window_start, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            SYNACK_COOKIE_TOKENS.store(SYNACK_COOKIE_RATE_LIMIT, Ordering::Release);
        }
    }

    let mut tokens = SYNACK_COOKIE_TOKENS.load(Ordering::Acquire);
    while tokens > 0 {
        match SYNACK_COOKIE_TOKENS.compare_exchange_weak(
            tokens,
            tokens - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => tokens = current,
        }
    }
    false
}

// ============================================================================
// R74-5 FIX: Global TCP Connection Counters
// ============================================================================


/// Global counter for half-open (SYN_RECEIVED) TCP connections.
///
/// R74-5 FIX: Tracks connections in the SYN queue across all listeners to enforce
/// a global limit. Without this, an attacker could open unlimited half-open
/// connections across many listening sockets, exhausting kernel memory.
///
/// Incremented when a SYN is queued, decremented when:
/// - Connection completes handshake (moves to ESTABLISHED)
/// - SYN times out and is removed from queue
/// - Connection is rejected/dropped
static GLOBAL_HALF_OPEN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Global counter for active (ESTABLISHED, CLOSE_WAIT, etc.) TCP connections.
///
/// R74-5 FIX: Tracks all active connections to prevent resource exhaustion.
/// This is already partially enforced via tcp_conns.len() checks, but we
/// add this counter for O(1) limit checking without holding the lock.
///
/// R154-I6 FIX: Scope clarification -- this counter tracks passive-open (accepted)
/// connections only. Client-initiated (active-open / connect()) sockets are NOT
/// counted here. The counter is incremented in `queue_accept()` and decremented
/// on connection teardown. For observability, note that the public accessor
/// returns the passive-open count, not total TCP connections.
static GLOBAL_ACTIVE_CONN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Global maximum for half-open connections (SYN flood protection).
///
/// When this limit is reached, new SYNs should use SYN cookies instead of
/// queueing state. This provides stateless protection against SYN floods.
const GLOBAL_MAX_HALF_OPEN: u32 = 1024;

/// Atomically try to increment half-open counter if below limit.
///
/// # R74-5 Enhancement: TOCTOU Fix
///
/// The original implementation had a race condition:
/// ```
/// if !can_queue_half_open() { return false; }  // Check
/// // RACE: Other thread can increment here
/// inc_half_open();  // Increment
/// ```
///
/// This atomic version uses `fetch_update` to check and increment in one
/// operation, preventing bursts from exceeding the limit.
///
/// # Returns
/// - `true`: Counter incremented, caller can queue the SYN
/// - `false`: Limit reached, caller should use SYN cookie fallback
#[inline]
fn try_inc_half_open() -> bool {
    GLOBAL_HALF_OPEN_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if current < GLOBAL_MAX_HALF_OPEN {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

/// Decrement half-open connection count.
///
/// R74-5 FIX: Called when a half-open connection is removed (timeout, handshake, reject).
#[inline]
fn dec_half_open() {
    // Use saturating_sub to avoid underflow in case of accounting bugs
    let _ = GLOBAL_HALF_OPEN_COUNT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

/// Atomically try to increment active connection counter if below limit.
///
/// # R74-5 Enhancement: Active Connection Limit Enforcement
///
/// The original implementation incremented without checking the limit.
/// This atomic version enforces `TCP_MAX_ACTIVE_CONNECTIONS` to prevent
/// connection flood DoS attacks.
///
/// # Returns
/// - `true`: Counter incremented, connection can be established
/// - `false`: Limit reached, connection should be rejected (send RST)
#[inline]
fn try_inc_active_conn() -> bool {
    GLOBAL_ACTIVE_CONN_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            if (current as usize) < TCP_MAX_ACTIVE_CONNECTIONS {
                Some(current + 1)
            } else {
                None
            }
        })
        .is_ok()
}

/// Decrement active connection count.
///
/// R74-5 FIX: Called when a connection is closed/removed from tcp_conns.
#[inline]
fn dec_active_conn() {
    let _ = GLOBAL_ACTIVE_CONN_COUNT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

// ============================================================================
// R132-5 FIX: SYN Cookie Observability Counters
// ============================================================================

/// Total SYN cookies generated (SYN-ACKs sent with stateless cookie ISN).
static SYN_COOKIES_GENERATED: AtomicU64 = AtomicU64::new(0);

/// Total SYN cookies validated successfully (completed handshakes).
static SYN_COOKIES_VALIDATED: AtomicU64 = AtomicU64::new(0);

/// Total SYN cookies rejected (invalid MAC, expired, or malformed).
static SYN_COOKIES_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Snapshot of SYN cookie observability counters.
#[derive(Debug, Clone, Copy)]
pub struct SynCookieCounters {
    pub generated: u64,
    pub validated: u64,
    pub rejected: u64,
}

/// Get current SYN cookie observability counters (for procfs/stats export).
pub fn syn_cookie_counters() -> SynCookieCounters {
    SynCookieCounters {
        generated: SYN_COOKIES_GENERATED.load(Ordering::Relaxed),
        validated: SYN_COOKIES_VALIDATED.load(Ordering::Relaxed),
        rejected: SYN_COOKIES_REJECTED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Socket Types
// ============================================================================

/// Socket address domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDomain {
    /// IPv4 Internet domain (AF_INET)
    Inet4,
}

impl SocketDomain {
    /// Linux AF_INET value
    pub const AF_INET: u32 = 2;

    /// Parse from Linux domain constant
    pub fn from_raw(domain: u32) -> Option<Self> {
        match domain {
            Self::AF_INET => Some(SocketDomain::Inet4),
            _ => None,
        }
    }
}

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Stream socket (SOCK_STREAM) - TCP
    Stream,
    /// Datagram socket (SOCK_DGRAM) - UDP
    Dgram,
}

impl SocketType {
    /// Linux SOCK_STREAM value
    pub const SOCK_STREAM: u32 = 1;
    /// Linux SOCK_DGRAM value
    pub const SOCK_DGRAM: u32 = 2;

    /// Parse from Linux type constant
    pub fn from_raw(ty: u32) -> Option<Self> {
        match ty {
            Self::SOCK_STREAM => Some(SocketType::Stream),
            Self::SOCK_DGRAM => Some(SocketType::Dgram),
            _ => None,
        }
    }
}

/// Socket protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    /// TCP protocol (IPPROTO_TCP = 6)
    Tcp,
    /// UDP protocol (IPPROTO_UDP = 17)
    Udp,
}

impl SocketProtocol {
    /// Linux IPPROTO_TCP value
    pub const IPPROTO_TCP: u32 = 6;
    /// Linux IPPROTO_UDP value
    pub const IPPROTO_UDP: u32 = 17;

    /// Parse from Linux protocol constant with socket type inference
    pub fn from_raw(proto: u32, sock_type: SocketType) -> Option<Self> {
        match proto {
            0 => {
                // Default protocol based on socket type
                match sock_type {
                    SocketType::Stream => Some(SocketProtocol::Tcp),
                    SocketType::Dgram => Some(SocketProtocol::Udp),
                }
            }
            Self::IPPROTO_TCP => Some(SocketProtocol::Tcp),
            Self::IPPROTO_UDP => Some(SocketProtocol::Udp),
            _ => None,
        }
    }
}

// ============================================================================
// Security Label
// ============================================================================

/// Security label captured at socket creation.
///
/// This label is stored with the socket and used for:
/// 1. LSM hook invocations (passing original creator context)
/// 2. MAC policy decisions (e.g., SELinux domain transitions)
/// 3. Audit logging (who created this socket)
#[derive(Debug, Clone, Copy)]
pub struct SocketLabel {
    /// Process context at creation time
    pub creator: ProcessCtx,
    /// Optional security marking (SELinux/SMACK/AppArmor)
    /// Value 0 means no marking set
    pub secmark: u64,
}

impl SocketLabel {
    /// Create a label from the current process context.
    ///
    /// Returns `None` if there is no current process (kernel context).
    pub fn from_current(secmark: u64) -> Option<Self> {
        ProcessCtx::from_current().map(|creator| SocketLabel { creator, secmark })
    }
}

// ============================================================================
// Pending Datagram
// ============================================================================

/// A received UDP datagram queued for userspace delivery.
#[derive(Debug, Clone)]
pub struct PendingDatagram {
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Source port
    pub src_port: u16,
    /// Datagram payload (UDP data only, no headers)
    pub data: Vec<u8>,
    /// Receive timestamp (ticks)
    pub received_at: u64,
}

// ============================================================================
// TCP Socket State
// ============================================================================

/// TCP socket-specific state for stream sockets.
///
/// This structure holds the TCP control block and dedicated wait queues for
/// TCP state transitions (connect completion, close) and data availability.
struct TcpSocketState {
    /// TCP control block for this stream socket
    control: TcpControlBlock,
    /// Waiters interested in TCP state transitions (connect/close)
    state_waiters: Arc<WaitQueue>,
    /// Waiters for data availability (recv)
    data_waiters: Arc<WaitQueue>,
}

impl TcpSocketState {
    fn new(control: TcpControlBlock) -> Self {
        TcpSocketState {
            control,
            state_waiters: Arc::new(WaitQueue::new()),
            data_waiters: Arc::new(WaitQueue::new()),
        }
    }
}

// ============================================================================
// TCP Listen State (R51-1: Passive Open)
// ============================================================================

/// R106-10 FIX: TCP connection lookup key type (net_ns_id, local_ip, local_port, remote_ip, remote_port)
///
/// Used for both active and passive TCP connection tracking.
/// The namespace ID ensures that connections in different network namespaces
/// cannot collide on the same 4-tuple.
type TcpLookupKey = (NamespaceId, u32, u16, u32, u16);

/// Half-open connection (SYN received, SYN-ACK sent, awaiting final ACK).
struct PendingSyn {
    /// Connection lookup key (4-tuple)
    key: TcpLookupKey,
    /// Child socket in SynReceived state
    sock: Arc<SocketState>,
    /// Cached SYN-ACK segment for retransmission
    syn_ack: Vec<u8>,
    /// Timestamp when SYN-ACK was sent (for SYN timeout)
    syn_sent_at: u64,
}

/// Passive-open bookkeeping for a listening TCP socket.
///
/// A listening socket maintains two bounded queues:
/// - SYN queue: Half-open connections (SYN received, SYN-ACK sent)
/// - Accept queue: Fully established connections ready for accept()
///
/// Both queues are bounded to prevent resource exhaustion from SYN floods.
struct TcpListenState {
    /// Maximum half-open connections (SYN queue size)
    syn_backlog: usize,
    /// Maximum pending accept connections (accept queue size)
    accept_backlog: usize,
    /// Half-open connections indexed by 4-tuple
    syn_queue: BTreeMap<TcpLookupKey, PendingSyn>,
    /// Fully established connections awaiting accept()
    accept_queue: VecDeque<Arc<SocketState>>,
    /// Wait queue for blocking accept()
    accept_waiters: Arc<WaitQueue>,
}

impl TcpListenState {
    /// Create new listen state with bounded backlogs.
    fn new(backlog: usize) -> Self {
        // Clamp backlog to valid range
        let effective = backlog.clamp(1, TCP_MAX_ACCEPT_BACKLOG);
        TcpListenState {
            syn_backlog: TCP_MAX_SYN_BACKLOG.min(effective),
            accept_backlog: effective,
            syn_queue: BTreeMap::new(),
            accept_queue: VecDeque::new(),
            accept_waiters: Arc::new(WaitQueue::new()),
        }
    }

    /// Enqueue a half-open connection.
    ///
    /// Returns false if SYN queue is full (silent drop for SYN flood mitigation).
    ///
    /// J2-2: `table` is threaded in so the per-namespace half-open budget can be
    /// charged in the same funnel as the global reservation (lock order
    /// `listen.lock` > `per_ns_syn_counts`; the caller holds `listen.lock`).
    fn queue_syn(&mut self, entry: PendingSyn, table: &SocketTable) -> bool {
        // Check local queue limit first (fast path)
        if self.syn_queue.len() >= self.syn_backlog {
            return false;
        }

        // R74-5 Enhancement: Atomically reserve global half-open slot.
        // This prevents the TOCTOU race where multiple threads could all pass
        // a non-atomic check before any increment, exceeding the global limit.
        //
        // If this returns false, caller falls back to SYN cookies for
        // stateless flood protection (R106-2 FIX: implemented in SYN handler).
        if !try_inc_half_open() {
            return false;
        }

        // J2-2: per-namespace half-open budget (a subset of the global limit). On
        // over-quota, roll back the global reservation we just took and signal the
        // caller to fall back to stateless SYN cookies (same as the global path).
        if !table.try_inc_ns_syn(entry.key.0) {
            dec_half_open();
            return false;
        }

        self.syn_queue.insert(entry.key, entry);
        true
    }

    /// Remove and return a half-open connection by key.
    ///
    /// J2-2: `table` is threaded in so the per-namespace half-open uncharge stays
    /// in the same single funnel as the global decrement.
    fn take_syn(&mut self, key: &TcpLookupKey, table: &SocketTable) -> Option<PendingSyn> {
        let result = self.syn_queue.remove(key);

        // R74-5 FIX: Decrement global half-open counter when removing
        if result.is_some() {
            dec_half_open();
            // J2-2: uncharge the per-namespace half-open slot in the same funnel.
            table.dec_ns_syn(key.0);
        }

        result
    }

    /// Get a reference to a half-open connection.
    fn get_syn(&self, key: &TcpLookupKey) -> Option<&PendingSyn> {
        self.syn_queue.get(key)
    }

    /// Enqueue a fully established connection for accept().
    ///
    /// Returns false if accept queue is full.
    fn queue_accept(&mut self, sock: Arc<SocketState>) -> bool {
        if self.accept_queue.len() >= self.accept_backlog {
            return false;
        }

        // R74-5 Enhancement: Atomically reserve global active connection slot.
        // This enforces TCP_MAX_ACTIVE_CONNECTIONS to prevent connection floods.
        if !try_inc_active_conn() {
            return false;
        }

        // R121-3 FIX: Mark this socket as counted so cleanup_tcp_connection()
        // only decrements for sockets that actually incremented the counter.
        sock.counted_in_active.store(true, Ordering::Release);

        self.accept_queue.push_back(sock);
        true
    }

    /// Dequeue an established connection for accept().
    fn pop_accept(&mut self) -> Option<Arc<SocketState>> {
        self.accept_queue.pop_front()
    }

    /// Check if accept queue has pending connections.
    fn has_pending(&self) -> bool {
        !self.accept_queue.is_empty()
    }

    /// Get the accept wait queue for blocking.
    fn waiters(&self) -> Arc<WaitQueue> {
        self.accept_waiters.clone()
    }
}

/// Result of initiating a TCP connect (SYN sent).
#[derive(Debug, Clone)]
pub struct TcpConnectResult {
    /// Serialized TCP segment (header + payload) ready for IPv4 encapsulation.
    pub segment: Vec<u8>,
    /// Local port used for the connection.
    pub local_port: u16,
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dst_ip: Ipv4Addr,
    /// Destination port.
    pub dst_port: u16,
}

// ============================================================================
// Socket Metadata
// ============================================================================

/// Socket binding and connection state.
#[derive(Debug, Clone, Copy, Default)]
struct SocketMeta {
    /// Local IP address (if bound)
    local_ip: Option<[u8; 4]>,
    /// Local port (if bound)
    local_port: Option<u16>,
    /// Remote IP address (if connected)
    remote_ip: Option<[u8; 4]>,
    /// Remote port (if connected)
    remote_port: Option<u16>,
}

impl SocketMeta {
    fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Socket State
// ============================================================================

/// Per-socket state backing a capability handle.
///
/// This structure is wrapped in `Arc` and stored in the capability table.
/// Multiple CapId entries can reference the same socket (via dup()).
pub struct SocketState {
    /// Unique socket identifier (monotonically increasing)
    pub id: u64,
    /// Socket domain
    pub domain: SocketDomain,
    /// Socket type
    pub ty: SocketType,
    /// Socket protocol
    pub proto: SocketProtocol,
    /// Security label from creation
    pub label: SocketLabel,
    /// R75-1 FIX: Network namespace identifier (for CLONE_NEWNET isolation)
    ///
    /// Sockets are isolated by network namespace. Port bindings and lookups
    /// are partitioned by this ID, ensuring that different namespaces can
    /// bind to the same port independently.
    pub net_ns_id: NamespaceId,
    /// Reference count for file descriptors referencing this socket.
    ///
    /// Initialized to 1 at creation. Incremented on dup()/fork(), decremented
    /// on close(). Socket is only fully closed when refcount reaches 0.
    refcount: AtomicU64,
    /// Binding/connection metadata
    meta: Mutex<SocketMeta>,
    /// Received datagram queue
    rx_queue: Mutex<VecDeque<PendingDatagram>>,
    /// Wait queue for blocking recv
    waiters: WaitQueue,
    /// Socket closed flag
    closed: AtomicBool,
    /// R121-3 FIX: Whether this socket was counted in GLOBAL_ACTIVE_CONN_COUNT.
    ///
    /// Set to `true` when `try_inc_active_conn()` succeeds in `queue_accept()`.
    /// Checked in `cleanup_tcp_connection()` to avoid decrementing the counter
    /// for client-initiated connections that were never counted.
    counted_in_active: AtomicBool,
    /// Bytes received counter
    rx_bytes: AtomicU64,
    /// Bytes sent counter
    tx_bytes: AtomicU64,
    /// Datagrams received counter
    rx_datagrams: AtomicU64,
    /// Datagrams sent counter
    tx_datagrams: AtomicU64,
    /// Datagrams dropped due to queue full
    rx_dropped: AtomicU64,
    /// TCP state (only populated for stream sockets)
    tcp: Mutex<Option<TcpSocketState>>,
    /// Listen state (only for listening TCP sockets)
    listen: Mutex<Option<TcpListenState>>,
}

impl core::fmt::Debug for SocketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketState")
            .field("id", &self.id)
            .field("domain", &self.domain)
            .field("ty", &self.ty)
            .field("proto", &self.proto)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SocketState {
    /// Create a new socket state.
    ///
    /// R75-1 FIX: Now requires net_ns_id parameter for namespace isolation.
    pub fn new(
        id: u64,
        domain: SocketDomain,
        ty: SocketType,
        proto: SocketProtocol,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Self {
        SocketState {
            id,
            domain,
            ty,
            proto,
            label,
            net_ns_id,
            refcount: AtomicU64::new(1),
            meta: Mutex::new(SocketMeta::new()),
            rx_queue: Mutex::new(VecDeque::new()),
            waiters: WaitQueue::new(),
            closed: AtomicBool::new(false),
            counted_in_active: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_datagrams: AtomicU64::new(0),
            tx_datagrams: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            tcp: Mutex::new(None),
            listen: Mutex::new(None),
        }
    }

    /// Check if the socket is closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Increment the socket reference count.
    ///
    /// Called when a file descriptor is duplicated (dup/dup2/dup3) or when
    /// forking a process that has socket file descriptors.
    ///
    /// Uses AcqRel ordering for symmetry with decrement_refcount() and to
    /// ensure visibility of all modifications before the increment.
    #[inline]
    pub fn increment_refcount(&self) {
        self.refcount.fetch_add(1, Ordering::AcqRel);
    }

    /// Decrement the socket reference count and return the new count.
    ///
    /// Called when a file descriptor is closed. The socket should only be
    /// fully closed (port released, waiters woken) when this returns 0.
    ///
    /// Uses `fetch_update` to prevent underflow: if the refcount is already 0
    /// (which indicates a double-drop bug), we return 0 without modifying the
    /// counter, avoiding wrap to `u64::MAX` which would leak the socket.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if called with refcount == 0 (double-drop).
    #[inline]
    pub fn decrement_refcount(&self) -> u64 {
        match self
            .refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current == 0 {
                    // Debug: catch double-drop bugs early
                    debug_assert!(false, "socket refcount underflow: double-drop detected");
                    None // Don't modify - already at 0
                } else {
                    Some(current - 1)
                }
            }) {
            Ok(old) => old - 1, // Return new value (old - 1)
            Err(_) => 0,        // Was already 0, return 0
        }
    }

    /// Mark the socket as closed and wake all waiters.
    pub fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return; // Already closed
        }
        // Wake UDP/datagram waiters
        self.waiters.wake_all();
        // Wake TCP state waiters
        if let Some(waiters) = self.tcp_waiters() {
            waiters.close();
            waiters.wake_all();
        }
        // Wake TCP data waiters
        if let Some(waiters) = self.tcp_data_waiters() {
            waiters.close();
            waiters.wake_all();
        }
        // Wake accept waiters (for listening sockets)
        if let Some(waiters) = self.listen_waiters() {
            waiters.close();
            waiters.wake_all();
        }
    }

    /// Bind the socket to a local address.
    pub fn bind_local(&self, ip: Ipv4Addr, port: u16) {
        let mut meta = self.meta.lock();
        meta.local_ip = Some(ip.0);
        meta.local_port = Some(port);
    }

    /// Get the local port if bound.
    pub fn local_port(&self) -> Option<u16> {
        self.meta.lock().local_port
    }

    /// Get the local IP address if bound.
    ///
    /// R48-REVIEW FIX: Expose bound local IP for correct source address in sendto.
    pub fn local_ip(&self) -> Option<[u8; 4]> {
        self.meta.lock().local_ip
    }

    /// Set the remote endpoint (for connect).
    pub fn set_remote(&self, ip: Ipv4Addr, port: u16) {
        let mut meta = self.meta.lock();
        meta.remote_ip = Some(ip.0);
        meta.remote_port = Some(port);
    }

    /// Get the remote port if connected.
    pub fn remote_port(&self) -> Option<u16> {
        self.meta.lock().remote_port
    }

    /// Get the remote IP address if connected.
    pub fn remote_ip(&self) -> Option<[u8; 4]> {
        self.meta.lock().remote_ip
    }

    /// Install a TCP control block for this socket.
    fn attach_tcp(&self, control: TcpControlBlock) {
        *self.tcp.lock() = Some(TcpSocketState::new(control));
    }

    /// Get the current TCP state (if any).
    pub fn tcp_state(&self) -> Option<TcpState> {
        self.tcp.lock().as_ref().map(|tcp| tcp.control.state)
    }

    /// Get a clone of the TCP state waiters (for blocking connect/wakeups).
    fn tcp_waiters(&self) -> Option<Arc<WaitQueue>> {
        self.tcp
            .lock()
            .as_ref()
            .map(|tcp| tcp.state_waiters.clone())
    }

    /// Wake TCP state waiters (called when state transitions occur).
    pub fn wake_tcp_waiters(&self) {
        if let Some(waiters) = self.tcp_waiters() {
            waiters.wake_all();
        }
    }

    /// Get a clone of the TCP data waiters (for blocking recv).
    fn tcp_data_waiters(&self) -> Option<Arc<WaitQueue>> {
        self.tcp.lock().as_ref().map(|tcp| tcp.data_waiters.clone())
    }

    /// Wake TCP data waiters (called when data arrives).
    pub fn wake_tcp_data_waiters(&self) {
        if let Some(waiters) = self.tcp_data_waiters() {
            waiters.wake_all();
        }
    }

    // -----------------------------------------------------------------------
    // Listen State Helpers (R51-1)
    // -----------------------------------------------------------------------

    /// Install listen state for a listening socket.
    fn install_listen_state(&self, state: TcpListenState) {
        *self.listen.lock() = Some(state);
    }

    /// Clear listen state when socket is closed.
    fn clear_listen_state(&self) {
        self.listen.lock().take();
    }

    /// Get the accept wait queue for blocking accept().
    pub fn listen_waiters(&self) -> Option<Arc<WaitQueue>> {
        self.listen.lock().as_ref().map(|l| l.waiters())
    }

    /// Pop the next established connection from the accept queue.
    pub fn pop_accept_ready(&self) -> Option<Arc<SocketState>> {
        self.listen.lock().as_mut().and_then(|l| l.pop_accept())
    }

    /// Push an established connection to the accept queue.
    ///
    /// Returns false if the accept queue is full.
    fn push_accept_ready(&self, child: Arc<SocketState>) -> bool {
        let mut guard = self.listen.lock();
        if let Some(state) = guard.as_mut() {
            let queued = state.queue_accept(child);
            if queued {
                state.waiters().wake_one();
            }
            queued
        } else {
            false
        }
    }

    /// Check if this socket is in Listen state.
    pub fn is_listening(&self) -> bool {
        matches!(self.tcp_state(), Some(TcpState::Listen))
    }

    /// Get a snapshot of socket metadata.
    fn meta_snapshot(&self) -> SocketMeta {
        *self.meta.lock()
    }

    /// Enqueue a received datagram.
    ///
    /// Returns `true` if the datagram was queued, `false` if dropped
    /// (queue full, global byte cap exceeded, or socket closed).
    ///
    /// R133-2 FIX: Accept raw parameters instead of pre-allocated PendingDatagram.
    /// The payload is only copied (to_vec) after per-socket queue depth and
    /// global byte cap checks pass, preventing allocation/copy churn DoS under
    /// UDP flood conditions when the cap is saturated.
    fn enqueue_rx(&self, src_ip: Ipv4Addr, src_port: u16, data: &[u8], received_at: u64) -> bool {
        if self.is_closed() {
            return false;
        }

        let pkt_len = data.len();

        let mut queue = self.rx_queue.lock();
        if queue.len() >= MAX_RX_QUEUE {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // R132-4 FIX: Enforce global UDP queued bytes cap via atomic CAS loop.
        // Prevents aggregate memory exhaustion across all UDP sockets.
        if GLOBAL_UDP_QUEUED_BYTES
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let new_total = current.saturating_add(pkt_len);
                if new_total <= MAX_GLOBAL_UDP_QUEUED_BYTES {
                    Some(new_total)
                } else {
                    None
                }
            })
            .is_err()
        {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // R133-2 FIX: Only allocate/copy the payload after all cap checks pass.
        // R164-6 FIX: Fallible copy of UDP payload. On OOM, roll back the
        // global byte counter and reject the datagram.
        let mut data_copy = Vec::new();
        if data_copy.try_reserve_exact(data.len()).is_err() {
            GLOBAL_UDP_QUEUED_BYTES.fetch_sub(pkt_len, Ordering::Relaxed);
            return false;
        }
        data_copy.extend_from_slice(data);
        let pkt = PendingDatagram {
            src_ip,
            src_port,
            data: data_copy,
            received_at,
        };

        self.rx_bytes
            .fetch_add(pkt_len as u64, Ordering::Relaxed);
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        queue.push_back(pkt);
        drop(queue);

        self.waiters.wake_one();
        true
    }

    /// Pop the next received datagram from the queue.
    ///
    /// R132-4 FIX: Decrements GLOBAL_UDP_QUEUED_BYTES on dequeue.
    fn pop_rx(&self) -> Option<PendingDatagram> {
        let pkt = self.rx_queue.lock().pop_front();
        if let Some(ref pkt) = pkt {
            // R146-NET-4 FIX: Saturating decrement prevents underflow wrap
            // in case of hypothetical double-dequeue, which would permanently
            // block all UDP receive queueing.
            let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(pkt.data.len())),
            );
        }
        pkt
    }

    /// Get socket statistics.
    pub fn stats(&self) -> SocketStats {
        SocketStats {
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            tx_datagrams: self.tx_datagrams.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            rx_queue_len: self.rx_queue.lock().len(),
        }
    }
}

/// R132-4 FIX: Release global UDP queued byte accounting when a socket is
/// dropped with unread datagrams still in its rx_queue.
impl Drop for SocketState {
    fn drop(&mut self) {
        let queued_bytes: usize = self
            .rx_queue
            .get_mut()
            .iter()
            .map(|pkt| pkt.data.len())
            .sum();
        if queued_bytes > 0 {
            // R146-NET-4 FIX: Saturating decrement prevents underflow wrap.
            let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(queued_bytes)),
            );
        }

        // J2-6: uncharge any residual per-namespace TCP send bytes for a connection
        // whose TCB rode this Arc to its grave WITHOUT being nulled — the
        // close-non-keep path (close() removes the socket from `sockets` without
        // nulling the TCB). The strong Arc<SocketState> owners are `sockets` AND a
        // listener's `accept_queue` (udp/tcp_bindings/tcp_conns hold only Weak);
        // accept-queue children carry NO charged send bytes (not yet accept()ed, so
        // never tcp_send'd: ns_charged_send_bytes == 0) and are uncharged via
        // cleanup_tcp_connection at listener teardown — so for every charge-bearing
        // socket `sockets` is the last strong ref and this Drop is the catch-all.
        // get_mut() is exclusive purely from `&mut self` in drop (independent of
        // strong_count). Paths that null the TCB first (detach_tcp_uncharged /
        // cleanup_tcp_connection) zero the mirror, so Drop then reads None and
        // uncharges 0 — each residual is uncharged EXACTLY once.
        if self.net_ns_id != NamespaceId(0) {
            if let Some(ts) = self.tcp.get_mut().as_mut() {
                let charged = ts.control.ns_charged_send_bytes;
                if charged > 0 {
                    socket_table().uncharge_ns_send_residual(self.net_ns_id, charged);
                    ts.control.ns_charged_send_bytes = 0;
                }
                // J2-4: symmetric recv-byte residual uncharge. NOTE (unlike send,
                // where accept-queue children carry ns_charged_send_bytes == 0 since
                // never tcp_send'd): an accept-queue child CAN carry
                // ns_charged_recv_bytes > 0 from piggybacked SynReceived data — those
                // children are torn down via cleanup_tcp_connection (which nulls the
                // TCB first), so this Drop catch-all covers the normal-accept()
                // ->sockets-owned path.
                let rcharged = ts.control.ns_charged_recv_bytes;
                if rcharged > 0 {
                    socket_table().uncharge_ns_recv_residual(self.net_ns_id, rcharged);
                    ts.control.ns_charged_recv_bytes = 0;
                }
            }
        }
    }
}

/// Socket statistics.
#[derive(Debug, Clone, Copy)]
pub struct SocketStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    pub rx_dropped: u64,
    pub rx_queue_len: usize,
}

// ============================================================================
// Socket Errors
// ============================================================================

/// Socket operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// Invalid socket domain
    InvalidDomain,
    /// Invalid socket type
    InvalidType,
    /// Invalid protocol
    InvalidProtocol,
    /// Permission denied (LSM or DAC)
    PermissionDenied,
    /// Port already in use
    PortInUse,
    /// No ephemeral ports available
    NoPorts,
    /// R107-5: Socket ID space exhausted (u64 counter wrapped around)
    IdExhausted,
    /// Socket not bound (sendto without prior bind)
    NotBound,
    /// Socket is closed
    Closed,
    /// Operation timed out
    Timeout,
    /// Payload exceeds TCP/UDP size limits (R51-2)
    MessageTooLarge,
    /// No current process context
    NoProcess,
    /// Socket not found
    NotFound,
    /// Privileged port requires root
    PrivilegedPort,
    /// Connection already established or in progress
    AlreadyConnected,
    /// Operation would block while connect is in progress (non-blocking)
    InProgress,
    /// Operation would block on non-blocking socket (R51-1)
    WouldBlock,
    /// Invalid socket state for the requested operation
    InvalidState,
    /// R76-3 FIX: Per-namespace socket quota exceeded
    QuotaExceeded,
    /// UDP layer error
    Udp(UdpError),
    /// LSM policy denial
    Lsm(LsmError),
    /// R162-9 FIX: Allocation failed
    NoMemory,
}

impl From<UdpError> for SocketError {
    fn from(e: UdpError) -> Self {
        SocketError::Udp(e)
    }
}

impl From<LsmError> for SocketError {
    fn from(e: LsmError) -> Self {
        SocketError::Lsm(e)
    }
}

// ============================================================================
// Socket Table
// ============================================================================

// TcpLookupKey is defined earlier in this file, near TcpListenState.

/// R169-6 slice 2: lifetime contract of a port binding (see `PortBinding.kind`).
/// `Explicit` = user-requested specific port via `bind(non-zero)`; a CHARGED
/// entry of this kind is HOLD-UNTIL-CLOSE. `Ephemeral` = kernel-chosen
/// (connect auto-alloc, send_to_udp/listener auto-bind, and `bind(0)` — which
/// keeps its already-shipped charged-Ephemeral ghost-bind teardown this slice)
/// plus every uncharged/repair insert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BindKind {
    Ephemeral,
    Explicit,
}

/// J2-8: Value stored in `udp_bindings` / `tcp_bindings`.
///
/// The map is keyed by `(NamespaceId, port)` — the cgroup that allocated an
/// ephemeral port is NOT derivable from the key (many cgroups per netns) and is
/// NOT recoverable from a dead `Weak`. So the charged cgroup travels INSIDE the
/// map value: this is the single source of truth for the per-cgroup port budget
/// (`ports_current(g)` == count of live entries with `charged_cgroup == g`, by
/// construction). `charged_cgroup == 0` means "not charged" (passive-open
/// child, root cgroup, or pre-hook-registration) — a no-op at uncharge.
/// R169-6 slice 1: the listener auto-bind is CHARGED (kernel-chosen ephemeral
/// port). R169-6 slice 2: an explicit `bind(non-zero)` is now ALSO charged,
/// stamped `BindKind::Explicit`.
///
/// `kind` records the bind's LIFETIME contract, not how the port number was
/// chosen. It is load-bearing ONLY for CHARGED entries: a charged `Explicit`
/// binding is HOLD-UNTIL-CLOSE — the five while-alive teardown arms PURE-SKIP
/// it via `resolve_while_alive_teardown` (POSIX: an explicitly bound socket
/// keeps its port across failed connects until close), while a charged
/// `Ephemeral` binding gets the ghost-bind teardown (remove + refund + clear
/// `local_*` so a retry re-allocates and re-charges). An UNcharged entry's
/// kind is never CONSULTED (the `cgid != 0` qualifier in
/// `resolve_while_alive_teardown` is load-bearing): a root/pre-hook explicit
/// bind stamps `Explicit` with cgid 0 and keeps today's remove-while-alive +
/// connect-repair semantics. For UDP the kind is INERT — UDP has no
/// while-alive teardown arm (see the UDP-EXPLICIT INVARIANT in `bind_udp`).
///
/// Changing the value type from a bare `Weak<SocketState>` is deliberate: it is
/// the single source of truth, evicted atomically with the entry by
/// `BTreeMap::remove`/`insert`. Every mutation MUST go through
/// `insert_binding_charged` / `remove_binding_charged` /
/// `resolve_while_alive_teardown`; every read projects `.sock`.
struct PortBinding {
    sock: Weak<SocketState>,
    charged_cgroup: u64,
    kind: BindKind,
}

impl PortBinding {
    #[inline]
    fn sock_ptr(&self) -> *const SocketState {
        self.sock.as_ptr()
    }
}

/// J2-8: Outcome of `insert_binding_charged`. The new entry always carries the
/// new charge; the caller's only obligation is to REFUND any displaced non-zero
/// charge. This single rule is correct for every case — fresh insert, replacing
/// a dead stale-Weak (reclaim its leaked charge), or re-registering the same
/// socket (the old charge is refunded and the new one takes its place, so the
/// owning cgroup's count is net-unchanged and exactly one charge sits in the
/// map for that port).
enum InsertOutcome {
    /// No prior entry (or the prior entry carried no charge): nothing to refund.
    FreshGrowth,
    /// The replaced entry carried this non-zero charge — refund it (enqueue,
    /// since the caller holds the binding lock). The new charge is kept.
    DisplacedCharge(u64),
}

/// R169-6 slice 2: charge policy a caller passes to `bind_udp` / `bind_tcp`
/// (replaces the old `charge_ephemeral: bool`). `Ephemeral` REQUIRES
/// `port == None` (kernel-chosen; charged, ghost-bind teardown); `Explicit`
/// REQUIRES `port == Some(p)` (user-chosen; charged, hold-until-close); `None`
/// is the kept-total no-charge arm (no live caller today — every current bind
/// path charges; root resolves to cgid 0 and is exempted at the charge layer
/// instead).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindCharge {
    None,
    Ephemeral,
    Explicit,
}

impl BindCharge {
    #[inline]
    fn should_charge(self) -> bool {
        !matches!(self, BindCharge::None)
    }
    #[inline]
    fn kind(self) -> BindKind {
        match self {
            BindCharge::Explicit => BindKind::Explicit,
            _ => BindKind::Ephemeral,
        }
    }
}

/// R169-6 slice 2: outcome of `resolve_while_alive_teardown` — the single
/// choke-point decision for the five while-alive teardown arms.
/// `SkipExplicit` = the entry is this socket's own CHARGED `Explicit` binding:
/// HOLD-UNTIL-CLOSE — the caller must do NOTHING (no remove, no refund, no
/// `local_*` clear). `Removed(Some(cgid))` = an own CHARGED `Ephemeral`
/// binding was removed — the caller refunds it (direct in process ctx /
/// enqueue under L8) AND clears `local_ip`/`local_port` (the ghost-bind fix;
/// lexically unreachable for a charged Explicit entry by the match in
/// `resolve_while_alive_teardown`). `Removed(None)` = uncharged own entry
/// removed, foreign ptr-miss (entry restored), or absent — nothing to refund,
/// nothing to clear.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TeardownAction {
    SkipExplicit,
    Removed(Option<u64>),
}

/// Global socket table: tracks all sockets and port bindings.
///
/// Thread-safe via RwLock (read-heavy) and Mutex (write operations).
///
/// # R75-1 FIX: Network Namespace Isolation
///
/// Port bindings (udp_bindings, tcp_bindings) are partitioned by NamespaceId.
/// Different network namespaces can bind to the same port independently,
/// providing true CLONE_NEWNET isolation.
///
/// # R76-3 FIX: Per-Namespace Socket Quota
///
/// Each namespace is limited to MAX_SOCKETS_PER_NS sockets to prevent DoS
/// attacks where a container exhausts global socket resources.
pub struct SocketTable {
    /// Next socket ID (monotonically increasing)
    next_socket_id: AtomicU64,
    /// Next ephemeral port seed
    next_ephemeral: AtomicU16,
    /// All active sockets (socket_id -> SocketState)
    sockets: RwLock<BTreeMap<u64, Arc<SocketState>>>,
    /// R75-1 FIX: UDP port bindings partitioned by network namespace.
    /// J2-8: value carries the charged cgroup (see `PortBinding`).
    udp_bindings: Mutex<BTreeMap<(NamespaceId, u16), PortBinding>>,
    /// R75-1 FIX: TCP local port bindings partitioned by network namespace.
    /// J2-8: value carries the charged cgroup (see `PortBinding`).
    tcp_bindings: Mutex<BTreeMap<(NamespaceId, u16), PortBinding>>,
    /// Active TCP connections keyed by 4-tuple
    tcp_conns: Mutex<BTreeMap<TcpLookupKey, Weak<SocketState>>>,
    /// R76-3 FIX: Per-namespace socket count for quota enforcement
    per_ns_counts: Mutex<BTreeMap<NamespaceId, u64>>,
    /// J2-1 FIX (Phase J.2 per-tenant quotas): Per-namespace live TCP connection
    /// count. Bound to `tcp_conns` 4-tuple MEMBERSHIP (key.0 == net_ns_id), NOT a
    /// per-socket flag, so the six stale-Weak reapers cannot leak it. A strict
    /// subset of the global `TCP_MAX_ACTIVE_CONNECTIONS` cap; root (ns 0) is exempt.
    /// Lock order: `tcp_conns` > `per_ns_conn_counts` (pure leaf, takes no further lock).
    per_ns_conn_counts: Mutex<BTreeMap<NamespaceId, u32>>,
    /// J2-2 FIX (Phase J.2 per-tenant quotas): Per-namespace half-open (SYN-queue)
    /// count, summed across all listeners in the namespace. A strict subset of the
    /// global half-open cap; root (ns 0) is exempt. Charged/uncharged through
    /// `queue_syn`/`take_syn`. Lock order: `listen.lock` > `per_ns_syn_counts`.
    per_ns_syn_counts: Mutex<BTreeMap<NamespaceId, u64>>,
    /// J2-6 FIX (Phase J.2 per-tenant quotas): Per-namespace aggregate TCP send
    /// buffer bytes, summed across all live connections in the namespace. A strict
    /// additional layer over the per-connection `TCP_MAX_SEND_BUFFER_BYTES` (4 MiB)
    /// cap; root (ns 0) is exempt. Charged at `tcp_send`, uncharged via the
    /// `handle_ack` reconcile and at teardown (the per-TCB `ns_charged_send_bytes`
    /// mirror records each connection's contribution). Lock order:
    /// `sock.tcp` > `per_ns_send_bytes` (pure leaf, takes no further lock).
    per_ns_send_bytes: Mutex<BTreeMap<NamespaceId, usize>>,
    /// J2-4 FIX (Phase J.2 per-tenant quotas): Per-namespace aggregate TCP RECV
    /// footprint F = recv_buffer.len() + ooo_bytes, summed across all live
    /// connections in the namespace. A strict additional layer over the per-conn
    /// `TCP_MAX_RECV_BUFFER_BYTES` cap; root (ns 0) is exempt. Charged via a
    /// decide-only gate + reconciled to live F under `sock.tcp`
    /// (`try_charge_ns_recv_gate` / `reconcile_ns_recv`). SOFT cap (bounded,
    /// self-correcting overshoot — never under-counts, no isolation bypass). Lock
    /// order: `sock.tcp` > `per_ns_recv_bytes` (pure leaf, takes no further lock).
    per_ns_recv_bytes: Mutex<BTreeMap<NamespaceId, usize>>,
    /// J2-8 FIX (Phase J.2 per-tenant quotas): Deferred per-cgroup port-uncharge
    /// queue, folded by cgroup id (so its size is bounded by the number of
    /// distinct charged cgroups, never by event count). The cgroup uncharge
    /// primitive takes CGROUP_REGISTRY (Level 5) and so MUST NOT run under a
    /// net-binding lock (Level 8) or in IRQ; teardown sites that remove a binding
    /// in those contexts (cleanup_tcp_connection, deliver_udp/lookup stale prune,
    /// stale-replace, the new bindings reaper, netns Drop) ENQUEUE here instead.
    /// `drain_deferred_port_uncharges` flushes it in process context (the
    /// scheduler reschedule hook). Pure Level-8 leaf: only appended while a
    /// binding lock is already held, or alone during the process-ctx drain.
    port_uncharge_pending: Mutex<BTreeMap<u64, u64>>,
    /// Last observed timestamp (ms) used for TIME_WAIT bookkeeping.
    /// Updated by sweep_time_wait() and used by RX path when transitioning to TIME_WAIT.
    time_wait_clock: AtomicU64,
    /// R63-5 FIX: Timer sweeps skipped due to lock contention
    timer_sweeps_skipped: AtomicU64,
    /// Statistics
    created: AtomicU64,
    closed_count: AtomicU64,
    bind_count: AtomicU64,
    /// P0-2 FIX: Forced TIME_WAIT evictions to admit SYN cookie completions
    forced_tw_evictions: AtomicU64,
}

impl SocketTable {
    /// Encode advertised receive window for TCP header using window scaling.
    ///
    /// RFC 7323: If window scaling is enabled, the advertised window in the
    /// TCP header is the actual available window divided by 2^scale.
    /// Uses `avoid_zero=true` to prevent advertising zero window when space exists.
    #[inline]
    fn encode_adv_window(tcb: &TcpControlBlock, available: u32) -> u16 {
        encode_window(available, tcb.effective_rcv_wscale(), true)
    }

    /// Compute current advertised receive window (scaled if negotiated).
    ///
    /// Accounts for both in-order receive buffer and out-of-order queue bytes
    /// to accurately reflect available space.
    #[inline]
    fn current_adv_window(tcb: &TcpControlBlock) -> u16 {
        let consumed = (tcb.recv_buffer.len() as u32).saturating_add(tcb.ooo_bytes);
        let available = tcb.rcv_wnd.saturating_sub(consumed);
        Self::encode_adv_window(tcb, available)
    }

    /// Build an ACK segment carrying SACK blocks (RFC 2018).
    ///
    /// If SACK is negotiated and the OOO queue is non-empty, SACK blocks are
    /// serialized into TCP options. Otherwise a plain ACK is emitted.
    ///
    /// The most recently received OOO range is placed first in the SACK block
    /// list per RFC 2018 Section 3 recommendation.
    fn build_sack_ack(
        tcb: &TcpControlBlock,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        window: u16,
    ) -> Vec<u8> {
        let sack_blocks = if tcb.sack_enabled() {
            tcb.generate_sack_blocks()
        } else {
            Vec::new()
        };

        if sack_blocks.is_empty() {
            // Plain ACK — no SACK blocks to report
            return build_tcp_segment(
                src_ip, dst_ip, src_port, dst_port,
                tcb.snd_nxt, tcb.rcv_nxt, TCP_FLAG_ACK, window, &[],
            );
        }

        // Build ACK with SACK option (kind=5).
        // NOP padding before SACK aligns to 32-bit boundary:
        //   NOP, NOP, SACK(blocks...)
        // R163-10 FIX: There are always exactly 3 options (NOP, NOP, SACK).
        // Use a stack array to eliminate the heap allocation for the opts Vec,
        // making ACK generation OOM-free for the options list itself.
        let opts = [
            TcpOptionKind::Nop,
            TcpOptionKind::Nop,
            TcpOptionKind::Sack(sack_blocks),
        ];

        build_tcp_segment_with_options(
            src_ip, dst_ip, src_port, dst_port,
            tcb.snd_nxt, tcb.rcv_nxt, TCP_FLAG_ACK, window, &opts[..], &[],
        )
    }

    /// Create a new socket table.
    pub const fn new() -> Self {
        SocketTable {
            next_socket_id: AtomicU64::new(1),
            next_ephemeral: AtomicU16::new(EPHEMERAL_PORT_START),
            sockets: RwLock::new(BTreeMap::new()),
            udp_bindings: Mutex::new(BTreeMap::new()),
            tcp_bindings: Mutex::new(BTreeMap::new()),
            tcp_conns: Mutex::new(BTreeMap::new()),
            per_ns_counts: Mutex::new(BTreeMap::new()), // R76-3 FIX
            per_ns_conn_counts: Mutex::new(BTreeMap::new()), // J2-1 FIX
            per_ns_syn_counts: Mutex::new(BTreeMap::new()), // J2-2 FIX
            per_ns_send_bytes: Mutex::new(BTreeMap::new()), // J2-6 FIX
            per_ns_recv_bytes: Mutex::new(BTreeMap::new()), // J2-4 FIX
            port_uncharge_pending: Mutex::new(BTreeMap::new()), // J2-8 FIX
            time_wait_clock: AtomicU64::new(0),
            timer_sweeps_skipped: AtomicU64::new(0),
            created: AtomicU64::new(0),
            closed_count: AtomicU64::new(0),
            bind_count: AtomicU64::new(0),
            forced_tw_evictions: AtomicU64::new(0),
        }
    }

    /// R76-3 FIX: Maximum sockets allowed per network namespace.
    /// Prevents DoS via socket exhaustion within a single namespace.
    /// Value allows reasonable server workloads while preventing abuse.
    pub const MAX_SOCKETS_PER_NS: u64 = 8192;

    /// R76-3 FIX: Try to increment namespace socket count, failing if quota exceeded.
    fn try_inc_ns_count(&self, ns_id: NamespaceId) -> Result<(), SocketError> {
        let mut counts = self.per_ns_counts.lock();
        let count = counts.entry(ns_id).or_insert(0);
        if *count >= Self::MAX_SOCKETS_PER_NS {
            return Err(SocketError::QuotaExceeded); // Maps to EAGAIN in syscall layer
        }
        *count += 1;
        Ok(())
    }

    /// R76-3 FIX: Decrement namespace socket count.
    ///
    /// R170-7 FIX: remove the row at zero (mirrors the other four per-ns
    /// counter maps' prune-at-zero discipline). Without this, EVERY namespace
    /// that ever created a socket left a permanent `(ns_id, 0)` row behind —
    /// `NamespaceId`s are monotonic and never reused, so the map grew
    /// unboundedly across short-lived namespaces even when fully drained.
    fn dec_ns_count(&self, ns_id: NamespaceId) {
        let mut counts = self.per_ns_counts.lock();
        if let Some(count) = counts.get_mut(&ns_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ns_id);
            }
        }
    }

    // ========================================================================
    // Phase J.2: Per-Tenant (Per-Network-Namespace) TCP Resource Budgets
    // ========================================================================
    //
    // J2-1 (connection budget) and J2-2 (SYN-backlog budget) bound, per network
    // namespace, the two count-class TCP resources that a single tenant could
    // otherwise use to monopolize the GLOBAL pools (`TCP_MAX_ACTIVE_CONNECTIONS`
    // and the global half-open limit). Both per-ns caps are strict SUBSETS of the
    // corresponding global caps, so both gates must pass (fail-closed) — the
    // per-ns budget never weakens the existing global protection, only refines it.
    //
    // The ROOT namespace (`NamespaceId(0)`, the host) is EXEMPT: it is bounded
    // only by the global caps. This is deliberate — quotas isolate untrusted
    // tenants (CLONE_NEWNET, ns >= 1) without regressing host connection capacity
    // (a per-ns cap below the global 4096 would otherwise cap a host-only system).
    //
    // `NamespaceId` is monotonic and never reused (net_namespace.rs: NEXT_NET_NS_ID
    // is allocated via `fetch_update` + `checked_add`; Drop does not recycle), so a
    // dead namespace's stale TCP state cannot bleed accounting into a new tenant.

    /// J2-1: maximum live TCP connections per NON-root namespace (subset of the
    /// global `TCP_MAX_ACTIVE_CONNECTIONS`).
    pub const MAX_CONNS_PER_NS: u32 = 1024;
    /// J2-2: maximum half-open (SYN-queue) entries per NON-root namespace, summed
    /// across all listeners (subset of the global half-open limit).
    pub const MAX_HALF_OPEN_PER_NS: u64 = 256;
    /// J2-6: maximum aggregate buffered TCP send bytes per NON-root namespace,
    /// summed across all live connections. A strict ADDITIONAL layer on top of the
    /// per-connection `TCP_MAX_SEND_BUFFER_BYTES` (4 MiB) cap — and necessarily
    /// `>=` it so a single connection can still fill its own send buffer. 64 MiB
    /// caps a tenant at ~16 fully-buffered connections' worth of TX backlog,
    /// bounding the aggregate kernel-heap DoS a single CLONE_NEWNET tenant can
    /// inflict while leaving generous headroom for real multi-connection workloads.
    pub const MAX_SEND_BYTES_PER_NS: usize = 64 * 1024 * 1024;
    /// J2-4: maximum aggregate TCP recv footprint (recv_buffer.len() + ooo_bytes)
    /// per NON-root namespace, summed across all live connections. 64x the per-conn
    /// `TCP_MAX_RECV_BUFFER_BYTES` (256 KiB) = 16 MiB — and necessarily `>=` it so a
    /// single connection can still fill its own recv buffer. 1/4 of the 64 MiB send
    /// cap, matching the 4:1 per-conn send:recv buffer ratio. SOFT cap: the
    /// decide-only `try_charge_ns_recv_gate` releases its leaf before the buffer
    /// mutation + `reconcile_ns_recv`, so concurrent same-ns siblings may transiently
    /// overshoot by at most (concurrent admissions) x one segment payload
    /// (<= num_cpus x snd_mss), bounded overall by MAX_CONNS_PER_NS x
    /// TCP_MAX_RECV_BUFFER_BYTES; it self-corrects on the next gate and NEVER
    /// under-counts (no isolation bypass). A hard reserve-at-gate is deliberately
    /// avoided — it would reintroduce the OOO pre-charge-refund leak class.
    pub const MAX_RECV_BYTES_PER_NS: usize = 16 * 1024 * 1024;

    /// J2-1: charge one per-namespace TCP connection. Fails closed
    /// (`QuotaExceeded` -> EAGAIN) when the tenant is at its cap. Root (ns 0) is
    /// never charged. The count is bound to `tcp_conns` MEMBERSHIP — every charge
    /// here is matched by an uncharge at the corresponding `tcp_conns` removal
    /// (`dec_ns_conn`) or stale-Weak prune (`conns_retain_accounted`), so it is
    /// exactly the live key count per namespace by construction (no flag to leak).
    /// Caller holds the `tcp_conns` guard; this nests `per_ns_conn_counts` under it.
    fn try_inc_ns_conn(&self, ns_id: NamespaceId) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) {
            return Ok(());
        }
        let mut counts = self.per_ns_conn_counts.lock();
        let count = counts.entry(ns_id).or_insert(0);
        if *count >= Self::MAX_CONNS_PER_NS {
            return Err(SocketError::QuotaExceeded);
        }
        *count += 1;
        Ok(())
    }

    /// J2-1: uncharge one per-namespace TCP connection. `saturating_sub` +
    /// remove-at-0 keeps the map bounded (mirrors conntrack `dec_ns_entry_count`).
    /// No-op for root and for any namespace without a live charge.
    fn dec_ns_conn(&self, ns_id: NamespaceId) {
        if ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_conn_counts.lock();
        let now_zero = match counts.get_mut(&ns_id) {
            Some(c) => {
                *c = c.saturating_sub(1);
                *c == 0
            }
            None => false,
        };
        if now_zero {
            counts.remove(&ns_id);
        }
    }

    /// J2-1: prune dead-Weak `tcp_conns` entries AND uncharge their per-namespace
    /// connection count in a single pass, under the caller's held `tcp_conns`
    /// guard. This is the load-bearing leak fix: the dominant `tcp_conns` teardown
    /// is the six stale-Weak reapers (a freed `Arc` can never run
    /// `cleanup_tcp_connection`), so binding the count to map membership HERE is
    /// the only way to keep it leak-free. Replaces the bare
    /// `conns.retain(|_, w| w.strong_count() > 0)`.
    fn conns_retain_accounted(
        &self,
        conns: &mut BTreeMap<TcpLookupKey, Weak<SocketState>>,
    ) {
        let mut counts = self.per_ns_conn_counts.lock();
        conns.retain(|key, weak| {
            let keep = weak.strong_count() > 0;
            if !keep && key.0 != NamespaceId(0) {
                if let Some(c) = counts.get_mut(&key.0) {
                    *c = c.saturating_sub(1);
                }
            }
            keep
        });
        // Drop any namespace entries that reached zero (keep the map bounded).
        counts.retain(|_, v| *v != 0);
    }

    // ========================================================================
    // J2-8: per-cgroup ephemeral-port budget — binding choke-points, deferred
    // uncharge queue, reapers, and the netns teardown backstop.
    // ========================================================================

    /// J2-8: fold one deferred port-uncharge (`cgid` += `n`) into the pending
    /// queue. Pure Level-8 leaf — safe to call while a binding lock is held
    /// (lock order: binding-lock > `port_uncharge_pending`). The actual Level-5
    /// cgroup uncharge happens later in `drain_deferred_port_uncharges`.
    fn enqueue_port_uncharge(&self, cgid: u64, n: u64) {
        if cgid == 0 || n == 0 {
            return;
        }
        let mut pending = self.port_uncharge_pending.lock();
        let slot = pending.entry(cgid).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    /// J2-8: flush the deferred port-uncharge queue in PROCESS context. Snapshot
    /// then clear under the leaf lock, DROP that guard, then perform the Level-5
    /// cgroup uncharges (never under a binding lock, never in IRQ). Idempotent:
    /// a second drain finds the queue empty. Called from the scheduler reschedule
    /// hook after the deferred TCP-timer drain (a producer in the same pass).
    pub fn drain_deferred_port_uncharges(&self) {
        let drained: Vec<(u64, u64)> = {
            let mut pending = self.port_uncharge_pending.lock();
            if pending.is_empty() {
                return;
            }
            let out = pending.iter().map(|(&c, &n)| (c, n)).collect();
            pending.clear();
            out
        };
        for (cgid, n) in drained {
            uncharge_port_cgroup(cgid, n);
        }
    }

    /// J2-8: single choke-point for REMOVING a binding entry. Returns the charged
    /// cgroup id to uncharge (non-zero only), or `None`. `expect_ptr` (`Some`)
    /// gates the removal on the entry pointing at THAT socket: a foreign entry —
    /// a recycled `(ns,port)` now owned by another socket, or a passive-open
    /// child carrying the listener's port — is restored untouched and `None`
    /// returned, so a stale-meta teardown can never uncharge/unbind someone
    /// else's binding. Operates on the caller's held guard; the caller chooses
    /// direct uncharge (process ctx, after dropping the guard) vs `enqueue`.
    fn remove_binding_charged(
        bindings: &mut BTreeMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: Option<*const SocketState>,
    ) -> Option<u64> {
        match bindings.remove(&key) {
            Some(pb) => {
                if let Some(p) = expect_ptr {
                    if pb.sock_ptr() != p {
                        bindings.insert(key, pb); // foreign — put it back
                        return None;
                    }
                }
                if pb.charged_cgroup != 0 {
                    Some(pb.charged_cgroup)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// R169-6 slice 2: pure ptr-eq-gated read of an entry's (kind, charge).
    /// Operates on the caller's already-held guard and takes NO lock internally
    /// (the RX-context cleanup arm would self-deadlock otherwise — doc-pinned).
    /// Compares `Weak::as_ptr` WITHOUT upgrading: every caller passes the ptr
    /// of an `Arc` it itself holds, so a ptr match is live by construction; a
    /// foreign / passive-child / recycled-key entry returns `None`. (The
    /// connect registration gate deliberately does NOT use this — it must
    /// distinguish a live foreign owner from a dead stale entry, which needs
    /// `upgrade()`.)
    fn peek_binding_kind(
        bindings: &BTreeMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: *const SocketState,
    ) -> Option<(BindKind, u64)> {
        bindings.get(&key).and_then(|pb| {
            if pb.sock_ptr() == expect_ptr {
                Some((pb.kind, pb.charged_cgroup))
            } else {
                None
            }
        })
    }

    /// R169-6 slice 2: the while-alive teardown decision for the five
    /// remove-first arms (the four connect cleanup arms + the
    /// `cleanup_tcp_connection` survivor branch). The connect registration
    /// ROLLBACK is deliberately NOT one of them — it is gated by its local
    /// `binding_registered` flag and must never adopt this helper (see the
    /// comment there). Fuses the kind peek and the ptr-eq remove under the
    /// caller's SINGLE guard hold (no TOCTOU). The `cgid != 0` qualifier is
    /// load-bearing: an uncharged (root / pre-hook) Explicit entry keeps
    /// today's remove-while-alive + connect-repair semantics.
    fn resolve_while_alive_teardown(
        bindings: &mut BTreeMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        expect_ptr: *const SocketState,
    ) -> TeardownAction {
        match Self::peek_binding_kind(bindings, key, expect_ptr) {
            Some((BindKind::Explicit, cgid)) if cgid != 0 => TeardownAction::SkipExplicit,
            _ => TeardownAction::Removed(Self::remove_binding_charged(
                bindings,
                key,
                Some(expect_ptr),
            )),
        }
    }

    /// J2-8: single choke-point for INSERTING/replacing a binding entry carrying
    /// `new_cgid`. The exhaustive `InsertOutcome` tells the caller whether the
    /// new charge is genuine growth (keep), a self-replace (undo the speculative
    /// charge), or evicted a stale charged entry (enqueue the old charge). Any
    /// displaced UNcharged entry is a plain `FreshGrowth` (nothing to uncharge).
    fn insert_binding_charged(
        bindings: &mut BTreeMap<(NamespaceId, u16), PortBinding>,
        key: (NamespaceId, u16),
        sock: &Arc<SocketState>,
        new_cgid: u64,
        kind: BindKind,
    ) -> InsertOutcome {
        let prev = bindings.insert(
            key,
            PortBinding {
                sock: Arc::downgrade(sock),
                charged_cgroup: new_cgid,
                kind,
            },
        );
        // Always refund the displaced charge; ptr identity is irrelevant.
        match prev {
            Some(old) if old.charged_cgroup != 0 => InsertOutcome::DisplacedCharge(old.charged_cgroup),
            _ => InsertOutcome::FreshGrowth,
        }
    }

    /// J2-8: prune dead-`Weak` entries for namespace `ns` from a binding map,
    /// ENQUEUEing each charged cgroup for deferred uncharge (cgroup uncharge is
    /// not a pure leaf, so — unlike J2-1's inline `conns_retain_accounted` — it
    /// cannot run under this binding lock). Also prunes UNcharged dead Weaks so a
    /// stale entry never makes a port look in-use to the ephemeral allocator
    /// (the pre-existing `contains_key`-counts-dead-Weak port-availability bug).
    /// Runs under the caller's held binding guard.
    fn reap_dead_bindings(
        &self,
        bindings: &mut BTreeMap<(NamespaceId, u16), PortBinding>,
        ns: NamespaceId,
    ) {
        let mut to_enqueue: Vec<u64> = Vec::new();
        Self::collect_dead_binding_charges(bindings, Some(ns), &mut to_enqueue);
        for cgid in to_enqueue {
            self.enqueue_port_uncharge(cgid, 1);
        }
    }

    /// R169-L9/L10/L11: the shared dead-`Weak` collector behind both the
    /// alloc-time namespace-local reaper (`reap_dead_bindings`) and the global
    /// stranded-charge sweep (`sweep_stranded_port_charges`). Drops EVERY dead
    /// entry (so a stale `Weak` never makes a port look in-use to the ephemeral
    /// allocator — the pre-existing port-availability fix) and pushes the
    /// `charged_cgroup` of each dead CHARGED entry onto `to_enqueue`. When `ns`
    /// is `Some`, only that namespace is scanned (leaving others untouched);
    /// `None` scans all namespaces. Runs under the caller's held binding guard;
    /// it never charges/uncharges (the L5 cgroup uncharge is deferred to the
    /// process-context drain), so it is a pure Level-8-leaf operation.
    /// R169-6 slice 2: dead-Weak reclaim is KIND-AGNOSTIC — it reads
    /// `charged_cgroup`, never `kind` (a held Explicit charge is reclaimed
    /// identically once its socket is gone).
    fn collect_dead_binding_charges(
        bindings: &mut BTreeMap<(NamespaceId, u16), PortBinding>,
        ns: Option<NamespaceId>,
        to_enqueue: &mut Vec<u64>,
    ) {
        bindings.retain(|key, pb| {
            if let Some(target_ns) = ns {
                if key.0 != target_ns {
                    return true; // leave other namespaces untouched
                }
            }
            let alive = pb.sock.strong_count() > 0;
            if !alive && pb.charged_cgroup != 0 {
                to_enqueue.push(pb.charged_cgroup);
            }
            alive
        });
    }

    /// R169-L9/L10/L11: ns-AGNOSTIC sweep of stranded per-cgroup port charges.
    ///
    /// `reap_dead_bindings` only runs for the namespace of an *active* ephemeral
    /// allocation, so a socket dropped without `close()` (L9), a charge stranded
    /// in a quiescent sibling namespace (L10), or a binding whose owning netns is
    /// pinned alive by a zombie process (L11) would never be revisited and its
    /// charge would leak toward `ports.max` indefinitely. This sweep generalizes
    /// the proven dead-`Weak` reap across BOTH binding maps and ALL namespaces:
    /// the binding maps are the single source of truth, and a dead `Weak` is
    /// sufficient proof that the stored charge is reclaimable — no per-socket
    /// mirror (and therefore no ABA-prone side state) is required.
    ///
    /// Enqueue-only: each reclaimed charge is folded into the deferred
    /// port-uncharge queue (pure Level-8 leaf push under the binding lock); the
    /// Level-5 cgroup uncharge runs later in `drain_deferred_port_uncharges`
    /// (process context, IRQs enabled, no binding lock held). Locks the two maps
    /// one at a time and never crosses L8 -> L5 under a lock. Driven rate-gated
    /// from the reschedule deferred-work drain and synchronously before the
    /// `delete_cgroup` emptiness gate.
    pub fn sweep_stranded_port_charges(&self) {
        let mut to_enqueue: Vec<u64> = Vec::new();
        {
            let mut bindings = self.udp_bindings.lock();
            Self::collect_dead_binding_charges(&mut bindings, None, &mut to_enqueue);
        }
        {
            let mut bindings = self.tcp_bindings.lock();
            Self::collect_dead_binding_charges(&mut bindings, None, &mut to_enqueue);
        }
        for cgid in to_enqueue {
            self.enqueue_port_uncharge(cgid, 1);
        }
    }

    /// J2-8: remove ALL bindings (alive or dead) for namespace `ns`, enqueuing
    /// each charged cgroup. The netns-teardown backstop: once a netns is
    /// destroyed nothing ever allocates an ephemeral port in it again, so the
    /// alloc-time reaper would never run and a still-charged binding would leak
    /// forever. Wired from `NetNamespace::Drop`. Enqueue-only (Drop runs in
    /// arbitrary context; the Level-5 uncharge is deferred to the drain).
    pub fn drain_ns_port_bindings(&self, ns: NamespaceId) {
        let mut to_enqueue: Vec<u64> = Vec::new();
        {
            let mut bindings = self.udp_bindings.lock();
            bindings.retain(|key, pb| {
                if key.0 != ns {
                    return true;
                }
                if pb.charged_cgroup != 0 {
                    to_enqueue.push(pb.charged_cgroup);
                }
                false
            });
        }
        {
            let mut bindings = self.tcp_bindings.lock();
            bindings.retain(|key, pb| {
                if key.0 != ns {
                    return true;
                }
                if pb.charged_cgroup != 0 {
                    to_enqueue.push(pb.charged_cgroup);
                }
                false
            });
        }
        for cgid in to_enqueue {
            self.enqueue_port_uncharge(cgid, 1);
        }
    }

    /// R170-7 FIX: netns-death backstop for the FIVE per-ns COUNTER maps
    /// (`per_ns_counts` / `per_ns_conn_counts` / `per_ns_syn_counts` /
    /// `per_ns_send_bytes` / `per_ns_recv_bytes`). Every decrement path
    /// self-prunes its row at zero, but a namespace destroyed while a counter
    /// is still non-zero (draining TCB, half-open SYN, residual buffered
    /// bytes) would leak that row forever — `NamespaceId`s are monotonic and
    /// never reused, so nothing would ever decrement it again (unbounded
    /// zombie-row growth across short-lived namespaces). Wired from
    /// `NetNamespace::Drop` next to `drain_ns_port_bindings`.
    ///
    /// # Lock context (proof pinned HERE, not inherited from the Drop comment)
    ///
    /// Each of the five maps is a documented pure-leaf `Mutex` (lock_ordering
    /// J2 table: takes no further lock while held), locked ONE AT A TIME in
    /// its own statement scope. `drain_ns_port_bindings`'s "Drop runs in
    /// arbitrary context" note is about the LEVEL-5 cgroup uncharge (which
    /// must be enqueue-only) — NOT about leaf locks. The last
    /// `Arc<NetNamespace>` drop is process-context today (a PCB's namespace
    /// ref drops at reap / syscall return; `NetNamespaceFd` drops at fd
    /// close; no IRQ path holds an owning Arc), so these leaf-mutex
    /// acquisitions cannot self-deadlock against an IRQ holder. If a future
    /// change introduces an IRQ-context owning-Arc drop, this drain (and the
    /// binding-lock acquisition in `drain_ns_port_bindings`) must be
    /// re-audited.
    ///
    /// # Residual (documented, accepted)
    ///
    /// A socket mid-teardown on another CPU can hold a transient strong
    /// `Arc<SocketState>` and reconcile AFTER this drain, re-`or_insert`ing a
    /// row — but every straggler pairs its charge with an uncharge and all
    /// five decrement paths now remove-at-zero, so a re-inserted row
    /// self-heals. This drain is the backstop for rows non-zero AT namespace
    /// death, not a hard "no row after Drop" invariant (that would need
    /// ns-liveness gating of every `or_insert` — deferred; CLONE_NEWNET is
    /// implemented so namespaces ARE created/destroyed today, but sockets
    /// carry only `net_ns_id` by value and the residual self-heals via the
    /// remove-at-zero decrement paths).
    pub fn drain_ns_counters(&self, ns: NamespaceId) {
        {
            self.per_ns_counts.lock().remove(&ns);
        }
        {
            self.per_ns_conn_counts.lock().remove(&ns);
        }
        {
            self.per_ns_syn_counts.lock().remove(&ns);
        }
        {
            self.per_ns_send_bytes.lock().remove(&ns);
        }
        {
            self.per_ns_recv_bytes.lock().remove(&ns);
        }
    }

    /// J2-2: charge one per-namespace half-open (SYN-queue) slot. Returns false
    /// (caller falls back to stateless SYN cookies) when the tenant is at its cap.
    /// Root (ns 0) is never charged. Charged in `queue_syn`, uncharged in
    /// `take_syn` / the listener-close drain.
    fn try_inc_ns_syn(&self, ns_id: NamespaceId) -> bool {
        if ns_id == NamespaceId(0) {
            return true;
        }
        let mut counts = self.per_ns_syn_counts.lock();
        let count = counts.entry(ns_id).or_insert(0);
        if *count >= Self::MAX_HALF_OPEN_PER_NS {
            return false;
        }
        *count += 1;
        true
    }

    /// J2-2: uncharge one per-namespace half-open slot.
    fn dec_ns_syn(&self, ns_id: NamespaceId) {
        self.dec_ns_syn_by(ns_id, 1);
    }

    /// J2-2: uncharge `n` per-namespace half-open slots at once. Used by the
    /// listener-close drain, which removes the whole SYN queue under `listen.lock`
    /// and defers the per-ns decrement to the proven `dec_ns_count` safe context.
    fn dec_ns_syn_by(&self, ns_id: NamespaceId, n: u64) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_syn_counts.lock();
        let now_zero = match counts.get_mut(&ns_id) {
            Some(c) => {
                *c = c.saturating_sub(n);
                *c == 0
            }
            None => false,
        };
        if now_zero {
            counts.remove(&ns_id);
        }
    }

    /// J2-6: charge `additional` aggregate send bytes to the namespace's TX-memory
    /// budget, RESERVING headroom atomically under the leaf lock so the cap is HARD
    /// even across sibling sockets in the same namespace (no read-then-commit
    /// TOCTOU). On success the per-TCB mirror is advanced by the SAME amount so the
    /// invariant `per_ns_send_bytes[ns] == Σ live tcb.ns_charged_send_bytes` holds.
    /// Fails closed (`WouldBlock` -> caller retries after ACKs drain) at the cap;
    /// the reservation is all-or-nothing (never partially applied on failure).
    /// Root (ns 0) / zero are no-ops. Caller holds `sock.tcp.lock()`; nests
    /// `per_ns_send_bytes` as a pure leaf.
    fn try_charge_ns_send(
        &self,
        ns_id: NamespaceId,
        tcb: &mut TcpControlBlock,
        additional: usize,
    ) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) || additional == 0 {
            return Ok(());
        }
        let mut counts = self.per_ns_send_bytes.lock();
        let e = counts.entry(ns_id).or_insert(0);
        let projected = match e.checked_add(additional) {
            Some(p) if p <= Self::MAX_SEND_BYTES_PER_NS => p,
            _ => {
                // Reservation rejected: leave the counter untouched. Drop a freshly
                // inserted zero entry so a denied charge cannot pin a stale key.
                if *e == 0 {
                    counts.remove(&ns_id);
                }
                return Err(SocketError::WouldBlock);
            }
        };
        *e = projected;
        tcb.ns_charged_send_bytes = tcb.ns_charged_send_bytes.saturating_add(additional);
        Ok(())
    }

    /// J2-6: reconcile the namespace TX-memory counter toward this TCB's LIVE
    /// `send_buffer_bytes`, applying the signed delta vs the per-TCB mirror
    /// (`ns_charged_send_bytes`). REFUNDS an over-reservation after partial
    /// buffering and UNCHARGES bytes freed by `handle_ack`. Never enforces the cap
    /// (the charge path already did) — it only trues the counter toward the real
    /// footprint, so it can never reject. Saturating + remove-at-0. Root (ns 0):
    /// just keep the mirror in lockstep. Caller holds `sock.tcp.lock()`; pure leaf.
    fn reconcile_ns_send(&self, ns_id: NamespaceId, tcb: &mut TcpControlBlock) {
        if ns_id == NamespaceId(0) {
            tcb.ns_charged_send_bytes = tcb.send_buffer_bytes;
            return;
        }
        let live = tcb.send_buffer_bytes;
        let charged = tcb.ns_charged_send_bytes;
        if live == charged {
            return;
        }
        let mut counts = self.per_ns_send_bytes.lock();
        if live > charged {
            let e = counts.entry(ns_id).or_insert(0);
            *e = e.saturating_add(live - charged);
        } else if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(charged - live);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
        tcb.ns_charged_send_bytes = live;
    }

    /// J2-6: uncharge `n` residual send bytes at connection teardown (the caller
    /// reads the per-TCB mirror and zeroes it). Saturating + remove-at-0; mirrors
    /// `dec_ns_conn`. Root (ns 0) / zero are no-ops.
    fn uncharge_ns_send_residual(&self, ns_id: NamespaceId, n: usize) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_send_bytes.lock();
        if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(n);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
    }

    /// J2-6: run `handle_ack` then reconcile the per-namespace send-byte counter
    /// down by the bytes the ACK freed from `send_buffer`. The thin wrapper exists
    /// because `handle_ack` (tcp.rs) has no `net_ns_id` in scope; the socket-layer
    /// caller holds `sock` and the `sock.tcp` guard. Applied at the 7
    /// ESTABLISHED/FIN-state ACK sites; the SYN-cookie path (detached TCB,
    /// `send_buffer_bytes == 0`) and the `apply_ack_and_cc` hot path reconcile
    /// separately. `handle_ack`'s `AckUpdate` is discarded at these sites, as
    /// before.
    fn handle_ack_reconciled(
        &self,
        sock: &Arc<SocketState>,
        tcb: &mut TcpControlBlock,
        ack_num: u32,
        now_ms: u64,
    ) {
        handle_ack(tcb, ack_num, now_ms);
        self.reconcile_ns_send(sock.net_ns_id, tcb);
    }

    /// J2-6: the SOLE helper allowed to null a connection's TCB (`*sock.tcp = None`)
    /// from a context that does not already hold the guard. It first uncharges the
    /// residual per-namespace send bytes and zeroes the mirror, closing the leak
    /// class (a TCB dropped with bytes still charged) STRUCTURALLY. Used at the
    /// SYN-SENT connect-timeout site; `cleanup_tcp_connection` inlines the same
    /// sequence under its already-held guard. The last-ref `impl Drop for
    /// SocketState` is the catch-all for the close-non-keep path that nulls nothing.
    fn detach_tcp_uncharged(&self, sock: &Arc<SocketState>) {
        let mut g = sock.tcp.lock();
        if let Some(ts) = g.as_mut() {
            let charged = ts.control.ns_charged_send_bytes;
            if charged > 0 {
                self.uncharge_ns_send_residual(sock.net_ns_id, charged);
                ts.control.ns_charged_send_bytes = 0;
            }
            // J2-4: symmetric recv-byte residual uncharge.
            let rcharged = ts.control.ns_charged_recv_bytes;
            if rcharged > 0 {
                self.uncharge_ns_recv_residual(sock.net_ns_id, rcharged);
                ts.control.ns_charged_recv_bytes = 0;
            }
        }
        *g = None;
    }

    /// J2-4: per-namespace RECV-memory budget PRE-GATE. DECIDE-only — takes NO
    /// charge and mutates nothing (counter or mirror); it only decides whether
    /// admitting `grow_by` more recv bytes for this connection would push the
    /// namespace aggregate past the cap. Root (ns 0) / zero are admitted. The actual
    /// counter move happens later in `reconcile_ns_recv` AFTER the buffer mutation,
    /// because recv's true F-delta is unknown pre-mutation (ooo_insert returns a
    /// merge-adjusted delta; ooo_drain is net-neutral-except-FIN-clear). `grow_by`
    /// is the UPPER bound on F-growth (payload.len()/useful.len()), so the gate is
    /// conservative-strict and never under-counts. SOFT cap — see MAX_RECV_BYTES_PER_NS.
    /// Caller holds `sock.tcp.lock()`; nests `per_ns_recv_bytes` as a pure leaf.
    fn try_charge_ns_recv_gate(
        &self,
        ns_id: NamespaceId,
        tcb: &TcpControlBlock,
        grow_by: usize,
    ) -> Result<(), SocketError> {
        if ns_id == NamespaceId(0) || grow_by == 0 {
            return Ok(());
        }
        let counts = self.per_ns_recv_bytes.lock();
        let live = counts.get(&ns_id).copied().unwrap_or(0);
        let charged = tcb.ns_charged_recv_bytes;
        // The namespace footprint EXCLUDING this connection's current contribution,
        // plus this connection's projected footprint after the growth.
        let other_conns = live.saturating_sub(charged);
        let conn_after = charged.saturating_add(grow_by);
        match other_conns.checked_add(conn_after) {
            Some(projected) if projected <= Self::MAX_RECV_BYTES_PER_NS => Ok(()),
            _ => Err(SocketError::WouldBlock),
        }
    }

    /// J2-4: reconcile the namespace RECV counter toward this TCB's LIVE footprint
    /// F = recv_buffer.len() + ooo_bytes, applying the signed delta vs the per-TCB
    /// mirror (`ns_charged_recv_bytes`). This single primitive absorbs ooo_drain
    /// neutrality, ooo_insert merge-absorption, and FIN-clear shrink. Saturating +
    /// remove-at-0. NEVER rejects (the gate already enforced). Idempotent — a second
    /// call with unchanged F is a no-op (safe to over-place). Root (ns 0): just keep
    /// the mirror in lockstep. Caller holds `sock.tcp.lock()`; pure leaf.
    fn reconcile_ns_recv(&self, ns_id: NamespaceId, tcb: &mut TcpControlBlock) {
        let live = tcb.recv_buffer.len().saturating_add(tcb.ooo_bytes as usize);
        if ns_id == NamespaceId(0) {
            tcb.ns_charged_recv_bytes = live;
            return;
        }
        let charged = tcb.ns_charged_recv_bytes;
        if live == charged {
            return;
        }
        let mut counts = self.per_ns_recv_bytes.lock();
        if live > charged {
            let e = counts.entry(ns_id).or_insert(0);
            *e = e.saturating_add(live - charged);
        } else if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(charged - live);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
        tcb.ns_charged_recv_bytes = live;
    }

    /// J2-4: uncharge `n` residual recv bytes at connection teardown (the caller
    /// reads the per-TCB mirror and zeroes it). Saturating + remove-at-0; mirrors
    /// `uncharge_ns_send_residual`. Root (ns 0) / zero are no-ops.
    fn uncharge_ns_recv_residual(&self, ns_id: NamespaceId, n: usize) {
        if n == 0 || ns_id == NamespaceId(0) {
            return;
        }
        let mut counts = self.per_ns_recv_bytes.lock();
        if let Some(c) = counts.get_mut(&ns_id) {
            let now = c.saturating_sub(n);
            if now == 0 {
                counts.remove(&ns_id);
            } else {
                *c = now;
            }
        }
    }

    /// Remove a socket from the `sockets` map, returning the owned Arc with the
    /// write guard ALREADY dropped (the guard is a temporary confined to this fn).
    /// Callers can then run teardown — e.g. cleanup_tcp_connection(), which
    /// re-acquires `sockets.write()` (R129-2) — WITHOUT self-deadlocking. In
    /// edition 2021 a temporary in an `if let` scrutinee lives to the END of the
    /// block, so `if let Some(s) = self.sockets.write().remove(..) { .. }` would
    /// hold the write lock across the body; routing the removal through this helper
    /// confines the guard to the call.
    fn remove_socket(&self, socket_id: u64) -> Option<Arc<SocketState>> {
        self.sockets.write().remove(&socket_id)
    }

    /// J2-1/J2-2 self-test (Phase J.2 per-tenant TCP budgets). Exercises the
    /// per-namespace connection + half-open counters directly on a fresh
    /// `SocketTable`: cap enforcement (fail-closed), namespace isolation, root
    /// exemption, remove-at-0 bookkeeping, and — critically — that the stale-Weak
    /// reaper (`conns_retain_accounted`) UNCHARGES pruned entries (the leak fix a
    /// per-socket flag could not provide). Any failure panics; `make boot-check`
    /// surfaces it via the serial log. Wired into the boot integration suite.
    pub fn run_per_ns_budget_self_test() {
        let table = SocketTable::new();
        let ns_a = NamespaceId(1);
        let ns_b = NamespaceId(2);
        let root = NamespaceId(0);

        // --- J2-1 connection budget: cap (fail-closed), isolation, root exemption ---
        for _ in 0..SocketTable::MAX_CONNS_PER_NS {
            table
                .try_inc_ns_conn(ns_a)
                .expect("J2-1: ns_a under cap should succeed");
        }
        assert!(
            table.try_inc_ns_conn(ns_a).is_err(),
            "J2-1: ns_a connection budget must fail closed at the cap"
        );
        table
            .try_inc_ns_conn(ns_b)
            .expect("J2-1: ns_b must be independent of ns_a");
        table.dec_ns_conn(ns_b);
        for _ in 0..(SocketTable::MAX_CONNS_PER_NS + 16) {
            table
                .try_inc_ns_conn(root)
                .expect("J2-1: root namespace must be exempt");
        }
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&root),
            "J2-1: root must never be tracked in per_ns_conn_counts"
        );
        for _ in 0..SocketTable::MAX_CONNS_PER_NS {
            table.dec_ns_conn(ns_a);
        }
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&ns_a),
            "J2-1: per_ns_conn_counts key must be removed at zero"
        );
        table.dec_ns_conn(ns_a); // saturating underflow guard (no panic, no underflow)

        // --- J2-1 leak-via-retain regression (the load-bearing fix) ---
        // A dead-Weak prune MUST uncharge the per-namespace count, else a tenant
        // wedges at its cap forever (self-DoS). Build a tcp_conns map of dead Weaks
        // and confirm conns_retain_accounted prunes AND uncharges exactly them,
        // leaving an unrelated namespace's count untouched.
        let ns_dead = NamespaceId(3);
        let ns_other = NamespaceId(4);
        const N_DEAD: u32 = 5;
        for _ in 0..N_DEAD {
            table.try_inc_ns_conn(ns_dead).unwrap();
        }
        table.try_inc_ns_conn(ns_other).unwrap(); // unrelated tenant, no map entry
        let mut conns: BTreeMap<TcpLookupKey, Weak<SocketState>> = BTreeMap::new();
        for i in 0..N_DEAD {
            // Weak::new() never upgrades (strong_count() == 0) -> pruned.
            conns.insert((ns_dead, i, 0u16, 0u32, 0u16), Weak::new());
        }
        table.conns_retain_accounted(&mut conns);
        assert!(conns.is_empty(), "J2-1: all dead-Weak entries must be pruned");
        assert!(
            !table.per_ns_conn_counts.lock().contains_key(&ns_dead),
            "J2-1 LEAK REGRESSION: pruned dead-Weak entries must uncharge to zero"
        );
        assert_eq!(
            table.per_ns_conn_counts.lock().get(&ns_other).copied(),
            Some(1u32),
            "J2-1: an unrelated namespace must be untouched by the reaper"
        );
        table.dec_ns_conn(ns_other);

        // --- J2-2 half-open (SYN) budget: cap, isolation, root exemption, batch drain ---
        for _ in 0..SocketTable::MAX_HALF_OPEN_PER_NS {
            assert!(
                table.try_inc_ns_syn(ns_a),
                "J2-2: ns_a under cap should succeed"
            );
        }
        assert!(
            !table.try_inc_ns_syn(ns_a),
            "J2-2: ns_a half-open budget must fail closed at the cap"
        );
        assert!(
            table.try_inc_ns_syn(ns_b),
            "J2-2: ns_b must be independent of ns_a"
        );
        table.dec_ns_syn(ns_b);
        for _ in 0..(SocketTable::MAX_HALF_OPEN_PER_NS + 8) {
            assert!(
                table.try_inc_ns_syn(root),
                "J2-2: root namespace must be exempt"
            );
        }
        assert!(
            !table.per_ns_syn_counts.lock().contains_key(&root),
            "J2-2: root must never be tracked in per_ns_syn_counts"
        );
        // Batch drain mirrors the listener-close path; key removed at zero.
        table.dec_ns_syn_by(ns_a, SocketTable::MAX_HALF_OPEN_PER_NS);
        assert!(
            !table.per_ns_syn_counts.lock().contains_key(&ns_a),
            "J2-2: per_ns_syn_counts key must be removed at zero after batch drain"
        );
        table.dec_ns_syn_by(ns_a, 100); // saturating underflow guard

        // --- J2-6 send-byte budget: hard cap, isolation, root exemption,
        //     reserve->refund reconcile, remove-at-0, and the load-bearing
        //     Drop/detach residual regressions ---
        let ns_s = NamespaceId(10);
        let ns_t = NamespaceId(11);
        let ns_u = NamespaceId(12);

        // (1) HARD cap, fail-closed, atomic reservation (no partial-apply on reject).
        let mut tcb_a =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 1]), 1, Ipv4Addr([10, 0, 0, 2]), 2, 0);
        assert!(
            table
                .try_charge_ns_send(ns_s, &mut tcb_a, SocketTable::MAX_SEND_BYTES_PER_NS)
                .is_ok(),
            "J2-6: charge up to the cap must succeed"
        );
        assert_eq!(
            tcb_a.ns_charged_send_bytes,
            SocketTable::MAX_SEND_BYTES_PER_NS,
            "J2-6: the per-TCB mirror must track the charged amount"
        );
        let mut tcb_b =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 3]), 3, Ipv4Addr([10, 0, 0, 4]), 4, 0);
        assert!(
            table.try_charge_ns_send(ns_s, &mut tcb_b, 1).is_err(),
            "J2-6: one byte over the cap must fail closed"
        );
        assert_eq!(
            tcb_b.ns_charged_send_bytes, 0,
            "J2-6: a rejected reservation must not advance the mirror"
        );
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_s).copied(),
            Some(SocketTable::MAX_SEND_BYTES_PER_NS),
            "J2-6: a rejected reservation must not partially apply to the counter"
        );

        // (2) Namespace isolation: ns_t independent of ns_s.
        let mut tcb_c =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 5]), 5, Ipv4Addr([10, 0, 0, 6]), 6, 0);
        assert!(
            table.try_charge_ns_send(ns_t, &mut tcb_c, 4096).is_ok(),
            "J2-6: ns_t must be independent of ns_s"
        );

        // (3) Root exemption: never charged, never tracked.
        let mut tcb_root =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 7]), 7, Ipv4Addr([10, 0, 0, 8]), 8, 0);
        assert!(
            table
                .try_charge_ns_send(root, &mut tcb_root, SocketTable::MAX_SEND_BYTES_PER_NS * 4)
                .is_ok(),
            "J2-6: root is exempt from the send-byte cap"
        );
        assert_eq!(
            tcb_root.ns_charged_send_bytes, 0,
            "J2-6: a root charge must not advance the mirror"
        );
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&root),
            "J2-6: root must never be tracked in per_ns_send_bytes"
        );

        // (4) Reserve->refund reconcile (the double-count fix): reserve a payload,
        //     buffer fewer bytes (OOM truncation), reconcile -> counter trues DOWN.
        let mut tcb_r =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 9]), 9, Ipv4Addr([10, 0, 0, 10]), 10, 0);
        assert!(table.try_charge_ns_send(ns_u, &mut tcb_r, 8192).is_ok());
        assert_eq!(table.per_ns_send_bytes.lock().get(&ns_u).copied(), Some(8192));
        tcb_r.send_buffer_bytes = 5000; // only 5000 of the 8192 reserved were buffered
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert_eq!(
            tcb_r.ns_charged_send_bytes, 5000,
            "J2-6: reconcile must true the mirror to the live send_buffer_bytes"
        );
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_u).copied(),
            Some(5000),
            "J2-6: reconcile must refund the (reserved - buffered) shortfall (no double-count)"
        );
        tcb_r.send_buffer_bytes = 1000; // ACK drains 5000 -> 1000
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert_eq!(table.per_ns_send_bytes.lock().get(&ns_u).copied(), Some(1000));
        tcb_r.send_buffer_bytes = 0; // fully drained -> remove-at-0
        table.reconcile_ns_send(ns_u, &mut tcb_r);
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&ns_u),
            "J2-6: per_ns_send_bytes key must be removed at zero"
        );
        assert_eq!(tcb_r.ns_charged_send_bytes, 0);

        // (5) Saturating-underflow guard on residual uncharge (absent key).
        table.uncharge_ns_send_residual(ns_u, 999);
        assert!(!table.per_ns_send_bytes.lock().contains_key(&ns_u));

        // (6) DROP-RESIDUAL regression — the load-bearing Channel-A anchor. Build a
        //     real Arc<SocketState> with an attached TCB, charge the GLOBAL table
        //     (impl Drop uncharges via socket_table()), then drop the Arc and assert
        //     the residual is gone. Unique high namespace ids avoid colliding with
        //     any live boot socket.
        let gtable = socket_table();
        let drop_ns = NamespaceId(0x7000_0001);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = Arc::new(SocketState::new(
                u64::MAX,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                drop_ns,
            ));
            let tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 0, 0, 11]),
                11,
                Ipv4Addr([10, 0, 0, 12]),
                12,
                0,
            );
            sock.attach_tcp(tcb);
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable
                    .try_charge_ns_send(drop_ns, &mut ts.control, 256 * 1024)
                    .expect("charge under cap");
            }
            assert_eq!(
                gtable.per_ns_send_bytes.lock().get(&drop_ns).copied(),
                Some(256 * 1024),
                "J2-6: global per-ns send bytes charged before drop"
            );
            // `sock` dropped here -> impl Drop uncharges the residual via the mirror.
        }
        assert!(
            !gtable.per_ns_send_bytes.lock().contains_key(&drop_ns),
            "J2-6: Drop must uncharge the residual per-ns send bytes (leak-class regression)"
        );

        // (7) detach_tcp_uncharged regression: nulling the TCB uncharges + zeroes the
        //     mirror, and a subsequent Drop is a 0 no-op (no double-subtract).
        let detach_ns = NamespaceId(0x7000_0002);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = Arc::new(SocketState::new(
                u64::MAX - 1,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                detach_ns,
            ));
            let tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 0, 0, 13]),
                13,
                Ipv4Addr([10, 0, 0, 14]),
                14,
                0,
            );
            sock.attach_tcp(tcb);
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable
                    .try_charge_ns_send(detach_ns, &mut ts.control, 128 * 1024)
                    .expect("charge under cap");
            }
            gtable.detach_tcp_uncharged(&sock);
            assert!(
                !gtable.per_ns_send_bytes.lock().contains_key(&detach_ns),
                "J2-6: detach_tcp_uncharged must uncharge the residual"
            );
            // `sock` dropped here -> Drop finds the TCB nulled -> uncharges 0.
        }
        assert!(
            !gtable.per_ns_send_bytes.lock().contains_key(&detach_ns),
            "J2-6: a post-detach Drop must not double-subtract"
        );

        // (8) AGGREGATION invariant: per_ns_send_bytes[ns] == sum over MULTIPLE live
        //     conns in the SAME ns. Charge TWO TCBs into one namespace, assert the
        //     sum, tear ONE down, assert the counter drops to exactly the other's
        //     mirror (not 0, not the sum). This is the only test that proves the
        //     cross-sibling accumulation the whole budget exists to enforce.
        let ns_agg = NamespaceId(13);
        let mut tcb_x =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 15]), 15, Ipv4Addr([10, 0, 0, 16]), 16, 0);
        let mut tcb_y =
            TcpControlBlock::new_client(Ipv4Addr([10, 0, 0, 17]), 17, Ipv4Addr([10, 0, 0, 18]), 18, 0);
        assert!(table.try_charge_ns_send(ns_agg, &mut tcb_x, 3000).is_ok());
        assert!(table.try_charge_ns_send(ns_agg, &mut tcb_y, 5000).is_ok());
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_agg).copied(),
            Some(8000),
            "J2-6: the per-ns counter must be the SUM of sibling conns' charges"
        );
        // Tear down conn x (simulate its full drain): the counter must drop to
        // exactly y's mirror, proving per-conn attribution within the sum.
        tcb_x.send_buffer_bytes = 0;
        table.reconcile_ns_send(ns_agg, &mut tcb_x);
        assert_eq!(
            table.per_ns_send_bytes.lock().get(&ns_agg).copied(),
            Some(5000),
            "J2-6: tearing down one sibling must leave exactly the other's charge"
        );
        assert_eq!(tcb_y.ns_charged_send_bytes, 5000);
        tcb_y.send_buffer_bytes = 0;
        table.reconcile_ns_send(ns_agg, &mut tcb_y);
        assert!(
            !table.per_ns_send_bytes.lock().contains_key(&ns_agg),
            "J2-6: counter removed at zero after all siblings drain"
        );

        // ================= J2-4 recv-byte budget (10 cases) =================
        // Drive the counter via a TCB's ooo_bytes (a plain field — no multi-MiB
        // allocation) + reconcile_ns_recv; the gate is decide-only so it is tested
        // separately. recv_buffer is exercised directly only in the FIN-clear case.
        let ns_rs = NamespaceId(20);
        let ns_rt = NamespaceId(21);
        let ns_ru = NamespaceId(22);
        let ns_ragg = NamespaceId(23);
        let ns_rx = NamespaceId(24);

        // (1) Aggregate cap (decide-only gate): drive ns_rs to the cap, assert a
        //     sibling (charged==0) is rejected — proving it is an aggregate, not
        //     per-conn, cap.
        let mut rtcb_a =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 1]), 1, Ipv4Addr([10, 1, 0, 2]), 2, 0);
        rtcb_a.ooo_bytes = SocketTable::MAX_RECV_BYTES_PER_NS as u32;
        table.reconcile_ns_recv(ns_rs, &mut rtcb_a);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_rs).copied(),
            Some(SocketTable::MAX_RECV_BYTES_PER_NS),
            "J2-recv: reconcile must charge the full footprint"
        );
        let rtcb_b =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 3]), 3, Ipv4Addr([10, 1, 0, 4]), 4, 0);
        assert!(
            table.try_charge_ns_recv_gate(ns_rs, &rtcb_b, 1).is_err(),
            "J2-recv: one byte over the aggregate cap must be rejected (sibling)"
        );

        // (2) Namespace isolation.
        let rtcb_c =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 5]), 5, Ipv4Addr([10, 1, 0, 6]), 6, 0);
        assert!(
            table.try_charge_ns_recv_gate(ns_rt, &rtcb_c, 4096).is_ok(),
            "J2-recv: ns_rt must be independent of ns_rs"
        );

        // (3) Root exemption: gate always Ok; reconcile sets the mirror but no key.
        let mut rtcb_root =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 7]), 7, Ipv4Addr([10, 1, 0, 8]), 8, 0);
        assert!(
            table
                .try_charge_ns_recv_gate(root, &rtcb_root, SocketTable::MAX_RECV_BYTES_PER_NS * 4)
                .is_ok(),
            "J2-recv: root is exempt from the recv cap"
        );
        rtcb_root.ooo_bytes = 9999;
        table.reconcile_ns_recv(root, &mut rtcb_root);
        assert!(
            !table.per_ns_recv_bytes.lock().contains_key(&root),
            "J2-recv: root must never be tracked in per_ns_recv_bytes"
        );

        // (4) Reconcile down-true + remove-at-0.
        let mut rtcb_u =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 9]), 9, Ipv4Addr([10, 1, 0, 10]), 10, 0);
        rtcb_u.ooo_bytes = 8192;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert_eq!(table.per_ns_recv_bytes.lock().get(&ns_ru).copied(), Some(8192));
        rtcb_u.ooo_bytes = 5000;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert_eq!(table.per_ns_recv_bytes.lock().get(&ns_ru).copied(), Some(5000));
        rtcb_u.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_u);
        assert!(
            !table.per_ns_recv_bytes.lock().contains_key(&ns_ru),
            "J2-recv: counter removed at zero"
        );

        // (5) Saturating-underflow guard on residual uncharge (absent key).
        table.uncharge_ns_recv_residual(ns_ru, 999);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ru));

        // (9) FIN-CLEAR-NO-OVERCOUNT (headline recv hazard): F = recv_buffer.len() +
        //     ooo_bytes; clearing OOO must drop the counter to recv_buffer.len() only.
        let mut rtcb_fin =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 11]), 11, Ipv4Addr([10, 1, 0, 12]), 12, 0);
        for _ in 0..1000 {
            rtcb_fin.recv_buffer.push_back(0u8);
        }
        rtcb_fin.ooo_bytes = 4000;
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert_eq!(table.per_ns_recv_bytes.lock().get(&ns_ru).copied(), Some(5000));
        rtcb_fin.ooo_bytes = 0; // simulate the FIN-clear OOO purge
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ru).copied(),
            Some(1000),
            "J2-recv: FIN-clear must drop the counter to recv_buffer.len() (no over-count)"
        );
        rtcb_fin.recv_buffer.clear();
        table.reconcile_ns_recv(ns_ru, &mut rtcb_fin);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ru));

        // (8) AGGREGATION across two live siblings in one namespace.
        let mut rtcb_x =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 13]), 13, Ipv4Addr([10, 1, 0, 14]), 14, 0);
        let mut rtcb_y =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 15]), 15, Ipv4Addr([10, 1, 0, 16]), 16, 0);
        rtcb_x.ooo_bytes = 3000;
        rtcb_y.ooo_bytes = 5000;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_x);
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_y);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ragg).copied(),
            Some(8000),
            "J2-recv: per-ns counter must be the SUM of sibling footprints"
        );
        rtcb_x.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_x);
        assert_eq!(
            table.per_ns_recv_bytes.lock().get(&ns_ragg).copied(),
            Some(5000),
            "J2-recv: tearing down one sibling leaves exactly the other's footprint"
        );
        rtcb_y.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_ragg, &mut rtcb_y);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_ragg));

        // (10) GATE-REARM + OOO-non-bypass: the post-mutation reconcile (not the
        //      gate) is what re-arms enforcement; the gate is grow_by-agnostic, so an
        //      OOO grow_by is admitted/rejected identically to an in-order one.
        let mut rtcb_near =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 17]), 17, Ipv4Addr([10, 1, 0, 18]), 18, 0);
        rtcb_near.ooo_bytes = (SocketTable::MAX_RECV_BYTES_PER_NS - 1000) as u32;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_near);
        let rtcb_probe =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 19]), 19, Ipv4Addr([10, 1, 0, 20]), 20, 0);
        assert!(
            table.try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 500).is_ok(),
            "J2-recv: gate admits below the cap"
        );
        assert!(
            table.try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 2000).is_err(),
            "J2-recv: gate rejects above the cap (same logic for OOO and in-order)"
        );
        let mut rtcb_push =
            TcpControlBlock::new_client(Ipv4Addr([10, 1, 0, 21]), 21, Ipv4Addr([10, 1, 0, 22]), 22, 0);
        rtcb_push.ooo_bytes = 1500;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_push);
        assert!(
            table.try_charge_ns_recv_gate(ns_rx, &rtcb_probe, 1).is_err(),
            "J2-recv: a reconcile that pushes the ns past the cap re-arms the gate"
        );
        rtcb_near.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_near);
        rtcb_push.ooo_bytes = 0;
        table.reconcile_ns_recv(ns_rx, &mut rtcb_push);
        assert!(!table.per_ns_recv_bytes.lock().contains_key(&ns_rx));

        // (6) DROP-RESIDUAL + (7) detach regressions on a real Arc<SocketState>,
        //     charging the GLOBAL socket_table() (impl Drop / detach uncharge it).
        let rdrop_ns = NamespaceId(0x7000_0011);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = Arc::new(SocketState::new(
                u64::MAX - 2,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                rdrop_ns,
            ));
            let mut tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 1, 0, 23]),
                23,
                Ipv4Addr([10, 1, 0, 24]),
                24,
                0,
            );
            tcb.ooo_bytes = 256 * 1024;
            sock.attach_tcp(tcb);
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable.reconcile_ns_recv(rdrop_ns, &mut ts.control);
            }
            assert_eq!(
                gtable.per_ns_recv_bytes.lock().get(&rdrop_ns).copied(),
                Some(256 * 1024),
                "J2-recv: global per-ns recv bytes charged before drop"
            );
        }
        assert!(
            !gtable.per_ns_recv_bytes.lock().contains_key(&rdrop_ns),
            "J2-recv: Drop must uncharge the residual recv bytes (leak-class regression)"
        );

        let rdetach_ns = NamespaceId(0x7000_0012);
        {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            let sock = Arc::new(SocketState::new(
                u64::MAX - 3,
                SocketDomain::Inet4,
                SocketType::Stream,
                SocketProtocol::Tcp,
                label,
                rdetach_ns,
            ));
            let mut tcb = TcpControlBlock::new_client(
                Ipv4Addr([10, 1, 0, 25]),
                25,
                Ipv4Addr([10, 1, 0, 26]),
                26,
                0,
            );
            tcb.ooo_bytes = 128 * 1024;
            sock.attach_tcp(tcb);
            {
                let mut g = sock.tcp.lock();
                let ts = g.as_mut().expect("tcb attached");
                gtable.reconcile_ns_recv(rdetach_ns, &mut ts.control);
            }
            gtable.detach_tcp_uncharged(&sock);
            assert!(
                !gtable.per_ns_recv_bytes.lock().contains_key(&rdetach_ns),
                "J2-recv: detach_tcp_uncharged must uncharge the residual recv bytes"
            );
        }
        assert!(
            !gtable.per_ns_recv_bytes.lock().contains_key(&rdetach_ns),
            "J2-recv: a post-detach Drop must not double-subtract"
        );
    }

    /// J2-8: in-kernel self-test for the per-cgroup ephemeral-port budget
    /// MECHANISM — the membership/leak-class logic the budget's correctness rests
    /// on (the cgroup arithmetic itself is tested in `cgroup::run_ports_budget_self_test`).
    ///
    /// Runs against a LOCAL `SocketTable`, manipulating `PortBinding` values
    /// directly and asserting the `port_uncharge_pending` bookkeeping. The boot
    /// process is in the root cgroup (id 0, exempt) so a behavioural charge would
    /// be a no-op; instead this proves the dangerous classes — uncharge-once via
    /// the ptr-eq remove choke-point, refund-the-displaced-charge, dead-Weak
    /// reaping (incl. the port-availability prune), the netns-teardown backstop,
    /// and fold-by-cgid drain idempotency.
    pub fn run_per_cgroup_port_budget_self_test() {
        let mk = |id: u64, ns: NamespaceId| -> Arc<SocketState> {
            let label = SocketLabel {
                creator: ProcessCtx::new(1, 1, 0, 0, 0, 0),
                secmark: 0,
            };
            Arc::new(SocketState::new(
                id,
                SocketDomain::Inet4,
                SocketType::Dgram,
                SocketProtocol::Udp,
                label,
                ns,
            ))
        };
        let table = SocketTable::new();
        let ns = NamespaceId(9);

        // (1) Fresh insert is FreshGrowth (nothing displaced to refund).
        let s1 = mk(101, ns);
        {
            let mut b = table.udp_bindings.lock();
            match SocketTable::insert_binding_charged(&mut b, (ns, 5000), &s1, 42, BindKind::Ephemeral) {
                InsertOutcome::FreshGrowth => {}
                InsertOutcome::DisplacedCharge(_) => panic!("J2-8: fresh insert must be FreshGrowth"),
            }
            assert_eq!(b.get(&(ns, 5000)).map(|pb| pb.charged_cgroup), Some(42));
        }

        // (2) Ptr-eq guard: a FOREIGN socket cannot remove/uncharge this binding,
        //     and the entry is restored untouched (recycled-key / passive-child
        //     cross-cgroup-clobber protection). The OWNING socket gets the charge.
        let s_other = mk(102, ns);
        {
            let mut b = table.udp_bindings.lock();
            assert!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5000), Some(Arc::as_ptr(&s_other)))
                    .is_none(),
                "J2-8: a foreign ptr must NOT remove/uncharge the binding"
            );
            assert!(b.contains_key(&(ns, 5000)), "J2-8: foreign-rejected entry restored");
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5000), Some(Arc::as_ptr(&s1))),
                Some(42),
                "J2-8: the owning socket's remove returns its stored charge exactly once"
            );
            assert!(b.contains_key(&(ns, 5000)) == false);
        }

        // (3) Removing an UNcharged (cgid 0) entry yields no uncharge.
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5001), &s1, 0, BindKind::Ephemeral);
            assert!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5001), None).is_none(),
                "J2-8: an uncharged binding must not produce an uncharge"
            );
        }

        // (4) Replacing a charged entry reports DisplacedCharge(old) and keeps the
        //     new charge — the single rule that keeps one-port==one-charge across
        //     stale-Weak overwrite and same-socket re-registration.
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5002), &s1, 7, BindKind::Ephemeral);
            match SocketTable::insert_binding_charged(&mut b, (ns, 5002), &s1, 8, BindKind::Ephemeral) {
                InsertOutcome::DisplacedCharge(old) => {
                    assert_eq!(old, 7, "J2-8: must report the displaced charge for refund")
                }
                InsertOutcome::FreshGrowth => panic!("J2-8: replacing a charged entry must displace"),
            }
            assert_eq!(
                b.get(&(ns, 5002)).map(|pb| pb.charged_cgroup),
                Some(8),
                "J2-8: the new charge is what remains in the map"
            );
            b.clear();
        }

        // (5) Deferred-uncharge queue: fold-by-cgid + drain clears + idempotent.
        table.enqueue_port_uncharge(3, 1);
        table.enqueue_port_uncharge(3, 2); // folds 3 -> 3
        table.enqueue_port_uncharge(4, 1);
        table.enqueue_port_uncharge(0, 5); // cgid 0 is a no-op
        assert_eq!(table.port_uncharge_pending.lock().get(&3).copied(), Some(3), "J2-8: fold-by-cgid");
        assert_eq!(table.port_uncharge_pending.lock().get(&4).copied(), Some(1));
        assert!(table.port_uncharge_pending.lock().get(&0).is_none(), "J2-8: cgid 0 never enqueued");
        table.drain_deferred_port_uncharges();
        assert!(
            table.port_uncharge_pending.lock().is_empty(),
            "J2-8: drain must clear the pending queue"
        );
        table.drain_deferred_port_uncharges(); // idempotent: no panic/underflow

        // (6) Dead-Weak reaper: a dead charged binding is pruned AND its charge
        //     enqueued; a dead UNcharged binding is pruned (port-availability fix)
        //     with NO enqueue; a live binding is kept.
        let live = mk(200, ns);
        {
            let dead1 = mk(201, ns);
            let dead2 = mk(202, ns);
            {
                let mut b = table.udp_bindings.lock();
                SocketTable::insert_binding_charged(&mut b, (ns, 6000), &live, 0, BindKind::Ephemeral);
                SocketTable::insert_binding_charged(&mut b, (ns, 6001), &dead1, 55, BindKind::Ephemeral);
                SocketTable::insert_binding_charged(&mut b, (ns, 6002), &dead2, 0, BindKind::Ephemeral);
            }
            // dead1 / dead2 dropped here -> their Weaks become un-upgradeable.
        }
        {
            let mut b = table.udp_bindings.lock();
            table.reap_dead_bindings(&mut b, ns);
            assert!(b.contains_key(&(ns, 6000)), "J2-8: live binding kept");
            assert!(!b.contains_key(&(ns, 6001)), "J2-8: dead charged binding reaped");
            assert!(
                !b.contains_key(&(ns, 6002)),
                "J2-8: dead UNcharged binding reaped too (port-availability fix)"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&55).copied(),
            Some(1),
            "J2-8: the reaper enqueued exactly the dead binding's charge"
        );
        table.drain_deferred_port_uncharges();

        // (7) Netns-teardown backstop: remove ALL (ns,*) bindings (alive or dead),
        //     enqueue the charged ones, and leave other namespaces untouched.
        let other_ns = NamespaceId(10);
        let s_a = mk(300, ns);
        let s_b = mk(301, ns);
        let s_c = mk(302, other_ns);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 7000), &s_a, 71, BindKind::Ephemeral);
            SocketTable::insert_binding_charged(&mut b, (ns, 7001), &s_b, 0, BindKind::Ephemeral);
            SocketTable::insert_binding_charged(&mut b, (other_ns, 7000), &s_c, 99, BindKind::Ephemeral);
        }
        table.drain_ns_port_bindings(ns);
        {
            let b = table.tcp_bindings.lock();
            assert!(!b.contains_key(&(ns, 7000)), "J2-8: backstop removed the ns binding");
            assert!(!b.contains_key(&(ns, 7001)));
            assert!(
                b.contains_key(&(other_ns, 7000)),
                "J2-8: backstop must leave OTHER namespaces untouched"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&71).copied(),
            Some(1),
            "J2-8: backstop enqueued the charged ns binding"
        );
        assert!(
            table.port_uncharge_pending.lock().get(&99).is_none(),
            "J2-8: backstop must not enqueue another namespace's charge"
        );
        table.drain_deferred_port_uncharges();

        // (8) R169-L9/L10/L11 global sweep: reaps dead charged bindings across
        //     ALL namespaces and BOTH maps, even when no allocator ever revisits
        //     that namespace — the idle/cross-netns/zombie-pinned reclamation
        //     class. A live binding in any ns is left intact.
        let live_keep = mk(402, other_ns);
        {
            let dead_udp = mk(400, ns);
            let dead_tcp = mk(401, other_ns);
            {
                let mut b = table.udp_bindings.lock();
                SocketTable::insert_binding_charged(&mut b, (ns, 7100), &dead_udp, 81, BindKind::Ephemeral);
            }
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(&mut b, (other_ns, 7101), &dead_tcp, 91, BindKind::Ephemeral);
                SocketTable::insert_binding_charged(&mut b, (other_ns, 7102), &live_keep, 17, BindKind::Ephemeral);
            }
            // dead_udp / dead_tcp dropped here -> their Weaks become dead.
        }
        table.sweep_stranded_port_charges();
        {
            let bu = table.udp_bindings.lock();
            assert!(
                !bu.contains_key(&(ns, 7100)),
                "R169-L10: global sweep reaps a dead UDP binding with no ns-local allocator"
            );
        }
        {
            let bt = table.tcp_bindings.lock();
            assert!(
                !bt.contains_key(&(other_ns, 7101)),
                "R169-L10: global sweep reaps a dead TCP binding in another namespace"
            );
            assert!(
                bt.contains_key(&(other_ns, 7102)),
                "R169-L10: global sweep must keep a LIVE binding"
            );
        }
        assert_eq!(
            table.port_uncharge_pending.lock().get(&81).copied(),
            Some(1),
            "R169-L10: sweep enqueued the dead UDP binding charge"
        );
        assert_eq!(
            table.port_uncharge_pending.lock().get(&91).copied(),
            Some(1),
            "R169-L10: sweep enqueued the dead TCP binding charge"
        );
        assert!(
            table.port_uncharge_pending.lock().get(&17).is_none(),
            "R169-L10: sweep must NOT enqueue a live binding's charge"
        );
        table.drain_deferred_port_uncharges();

        // (9) R169-6 slice-1 (listener charging) invariant. A listener now carries
        //     a real charge in its single (ns,port) PortBinding. Assert the two
        //     properties that make charging it through the existing Ephemeral path
        //     safe: (a) a passive-open CHILD (a distinct Arc sharing the listener's
        //     (ns,port)) can NEVER uncharge the listener — ptr-eq miss — and the
        //     listener's charge survives intact; (b) the listener's OWN close
        //     refunds the stored charge exactly once; (c) a no-close listener drop
        //     is reclaimed by the global sweep. This regression-guards the widening
        //     of charged bindings to listeners.
        let listener = mk(500, ns);
        let child = mk(501, ns); // passive-open child: distinct Arc, same (ns,port)
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 7200), &listener, 123, BindKind::Ephemeral);
            // (a) child cannot uncharge the listener (ptr-eq miss); entry restored.
            assert!(
                SocketTable::remove_binding_charged(&mut b, (ns, 7200), Some(Arc::as_ptr(&child)))
                    .is_none(),
                "R169-6: a passive-open child must NOT uncharge the listener's port"
            );
            assert_eq!(
                b.get(&(ns, 7200)).map(|pb| pb.charged_cgroup),
                Some(123),
                "R169-6: the listener's charge survives a child's removal attempt"
            );
            // (b) the listener's own close refunds exactly once.
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 7200), Some(Arc::as_ptr(&listener))),
                Some(123),
                "R169-6: the listener's own close refunds its stored charge once"
            );
        }
        // (c) a no-close listener drop is reclaimed by the global sweep.
        {
            let dropped_listener = mk(502, ns);
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(&mut b, (ns, 7201), &dropped_listener, 124, BindKind::Ephemeral);
            }
            // dropped_listener dropped here -> its Weak is dead.
        }
        table.sweep_stranded_port_charges();
        assert!(
            !table.tcp_bindings.lock().contains_key(&(ns, 7201)),
            "R169-6: a no-close listener drop is reaped by the global sweep"
        );
        assert_eq!(
            table.port_uncharge_pending.lock().get(&124).copied(),
            Some(1),
            "R169-6: the dropped listener's charge is reclaimed exactly once"
        );
        table.drain_deferred_port_uncharges();

        // ---- R169-6 slice 2: BindKind / hold-until-close mechanism ----

        // (10) REGRESSION TRIPWIRE for the slice-2 kill class: an own CHARGED
        //      Explicit binding is PURE-SKIPPED by the while-alive choke-point
        //      (NOT removed, NOT refunded). Reverting any arm to an
        //      unconditional remove flips this to Removed(Some) and fails boot.
        let s_x = mk(600, ns);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5100), &s_x, 222, BindKind::Explicit);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&s_x)),
                TeardownAction::SkipExplicit,
                "R169-6 s2: own charged Explicit must be PURE-SKIPPED while alive"
            );
            assert_eq!(
                b.get(&(ns, 5100)).map(|pb| pb.charged_cgroup),
                Some(222),
                "R169-6 s2: the skipped Explicit binding keeps its charge"
            );

            // (11) own CHARGED Ephemeral -> Removed(Some): the ghost-bind arm.
            SocketTable::insert_binding_charged(&mut b, (ns, 5101), &s_x, 223, BindKind::Ephemeral);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5101), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(Some(223)),
                "R169-6 s2: own charged Ephemeral is removed + refunded while alive"
            );
            assert!(!b.contains_key(&(ns, 5101)));

            // (12) own UNcharged Ephemeral -> Removed(None): removed, no refund.
            SocketTable::insert_binding_charged(&mut b, (ns, 5102), &s_x, 0, BindKind::Ephemeral);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5102), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(None)
            );
            assert!(!b.contains_key(&(ns, 5102)));

            // (12b) own UNcharged EXPLICIT (root / pre-hook) -> Removed(None):
            //      the `cgid != 0` qualifier is load-bearing — an uncharged
            //      Explicit keeps today's remove-while-alive + connect-repair
            //      semantics (no hold, no refund, no clear).
            SocketTable::insert_binding_charged(&mut b, (ns, 5105), &s_x, 0, BindKind::Explicit);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5105), Arc::as_ptr(&s_x)),
                TeardownAction::Removed(None),
                "R169-6 s2: an UNcharged Explicit (cgid 0) is NOT held"
            );
            assert!(!b.contains_key(&(ns, 5105)));

            // (13) FOREIGN ptr-miss: a passive-open child can neither hold-skip
            //      nor remove the owner's Explicit binding; entry restored.
            let child2 = mk(601, ns);
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&child2)),
                TeardownAction::Removed(None),
                "R169-6 s2: foreign ptr-miss must not skip-hold or uncharge"
            );
            assert_eq!(
                b.get(&(ns, 5100)).map(|pb| pb.charged_cgroup),
                Some(222),
                "R169-6 s2: entry restored untouched after a foreign attempt"
            );
            assert!(
                SocketTable::peek_binding_kind(&b, (ns, 5100), Arc::as_ptr(&child2)).is_none(),
                "R169-6 s2: peek is ptr-eq gated (the discriminant that replaces a liveness bool)"
            );

            // (14) explicit-bind-then-listen single charge: the held Explicit
            //      binding survives arbitrary while-alive attempts, then the
            //      OWNER's kind-agnostic terminal remove refunds exactly once.
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 5100), Arc::as_ptr(&s_x)),
                TeardownAction::SkipExplicit
            );
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5100), Some(Arc::as_ptr(&s_x))),
                Some(222),
                "R169-6 s2: terminal close refunds the held Explicit exactly once"
            );
            assert!(!b.contains_key(&(ns, 5100)));

            // (15) PRIVILEGED (port < 1024) Explicit: identical accounting —
            //      no port-magnitude branch exists in teardown (hoarding closed).
            let priv_sock = mk(602, ns);
            SocketTable::insert_binding_charged(&mut b, (ns, 80), &priv_sock, 224, BindKind::Explicit);
            assert_eq!(
                SocketTable::peek_binding_kind(&b, (ns, 80), Arc::as_ptr(&priv_sock)),
                Some((BindKind::Explicit, 224))
            );
            assert_eq!(
                SocketTable::resolve_while_alive_teardown(&mut b, (ns, 80), Arc::as_ptr(&priv_sock)),
                TeardownAction::SkipExplicit,
                "R169-6 s2: privileged Explicit is held identically"
            );
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 80), Some(Arc::as_ptr(&priv_sock))),
                Some(224)
            );

            // (16) TERMINAL teardown (the cleanup is_closed()==true branch and
            //      close()) removes a held Explicit KIND-AGNOSTICALLY —
            //      hold-until-close is NOT hold-forever.
            SocketTable::insert_binding_charged(&mut b, (ns, 5106), &s_x, 225, BindKind::Explicit);
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5106), Some(Arc::as_ptr(&s_x))),
                Some(225),
                "R169-6 s2: terminal (is_closed) teardown removes a held Explicit"
            );
            b.clear();
        }

        // (19) dead-Explicit displaced by a live Explicit bind on the SAME
        //      port: the kind-agnostic displacement refund reclaims the dead
        //      socket's stranded charge exactly once while the new charge is
        //      stamped (reachable now that explicit binds are charged).
        {
            let dead_explicit = mk(603, ns);
            {
                let mut b = table.tcp_bindings.lock();
                SocketTable::insert_binding_charged(
                    &mut b,
                    (ns, 5107),
                    &dead_explicit,
                    226,
                    BindKind::Explicit,
                );
            }
            // dead_explicit drops here -> its Weak is dead, charge stranded.
        }
        {
            let mut b = table.tcp_bindings.lock();
            let s_y = mk(604, ns);
            match SocketTable::insert_binding_charged(&mut b, (ns, 5107), &s_y, 227, BindKind::Explicit)
            {
                InsertOutcome::DisplacedCharge(old) => assert_eq!(
                    old, 226,
                    "R169-6 s2: dead Explicit displaced by a live Explicit refunds once"
                ),
                InsertOutcome::FreshGrowth => {
                    panic!("R169-6 s2: displacing a dead charged Explicit must refund")
                }
            }
            assert_eq!(b.get(&(ns, 5107)).map(|pb| pb.charged_cgroup), Some(227));
            let _ = &s_y; // alive through the assertions above
            b.clear();
        }

        // (17) UDP Explicit inert hold-until-close: no UDP while-alive arm
        //      exists; the only remover (the close-equivalent kind-agnostic
        //      remove) refunds exactly once.
        let s_udp = mk(605, ns);
        {
            let mut b = table.udp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (ns, 5108), &s_udp, 228, BindKind::Explicit);
            assert_eq!(
                SocketTable::remove_binding_charged(&mut b, (ns, 5108), Some(Arc::as_ptr(&s_udp))),
                Some(228),
                "R169-6 s2: UDP explicit bind+close refunds exactly once"
            );
        }

        // (18) netns-drain-then-repair accounting: the drain enqueues the held
        //      Explicit charge (netns finality removes live bindings, non-ptr-
        //      gated); a subsequent connect-style repair stamps charge-0
        //      Ephemeral — net effect exactly one uncharge, no double-refund,
        //      no new undercount.
        let drain_ns2 = NamespaceId(11);
        let s_drain = mk(606, drain_ns2);
        {
            let mut b = table.tcp_bindings.lock();
            SocketTable::insert_binding_charged(&mut b, (drain_ns2, 5109), &s_drain, 229, BindKind::Explicit);
        }
        table.drain_ns_port_bindings(drain_ns2);
        assert_eq!(
            table.port_uncharge_pending.lock().get(&229).copied(),
            Some(1),
            "R169-6 s2: netns drain enqueues the held Explicit charge once"
        );
        {
            let mut b = table.tcp_bindings.lock();
            // The connect-repair stamps speculative 0 / Ephemeral (see connect()).
            match SocketTable::insert_binding_charged(&mut b, (drain_ns2, 5109), &s_drain, 0, BindKind::Ephemeral)
            {
                InsertOutcome::FreshGrowth => {}
                InsertOutcome::DisplacedCharge(_) => {
                    panic!("R169-6 s2: a post-drain repair must not displace a charge")
                }
            }
            b.clear();
        }
        table.drain_deferred_port_uncharges();

        // Keep every live socket alive through all assertions above.
        let _ = (
            &s1, &s_other, &live, &s_a, &s_b, &s_c, &live_keep, &listener, &child, &s_x, &s_udp,
            &s_drain,
        );
    }

    /// Create a UDP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// The socket is bound to the caller's network namespace via `net_ns_id`.
    /// Port bindings will be isolated within this namespace.
    ///
    /// # R76-3 FIX: Per-Namespace Socket Quota
    ///
    /// Enforces MAX_SOCKETS_PER_NS limit to prevent namespace DoS.
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_udp_socket(
        &self,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Result<Arc<SocketState>, SocketError> {
        // R76-3 FIX: Check and increment namespace quota before creating socket
        self.try_inc_ns_count(net_ns_id)?;

        // Build LSM context
        let mut ctx = NetCtx::new(0, UDP_PROTO as u16);
        ctx.cap = Some(CapId::INVALID);

        // Check LSM policy
        if let Err(_e) = hook_net_socket(&label.creator, &ctx) {
            self.dec_ns_count(net_ns_id); // Rollback quota
            return Err(SocketError::PermissionDenied);
        }

        // R107-5 FIX: Allocate socket ID with overflow protection.
        // Uses fetch_update + checked_add to prevent u64 wrap-around and ID collision,
        // matching the R105-5 pattern applied to IPC endpoint IDs.
        let id = match self.next_socket_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(prev) => prev,
            Err(_) => {
                self.dec_ns_count(net_ns_id); // Rollback quota
                return Err(SocketError::IdExhausted);
            }
        };

        // Create socket state with namespace binding
        let sock = Arc::new(SocketState::new(
            id,
            SocketDomain::Inet4,
            SocketType::Dgram,
            SocketProtocol::Udp,
            label,
            net_ns_id,
        ));

        // Register in table
        self.sockets.write().insert(id, sock.clone());
        self.created.fetch_add(1, Ordering::Relaxed);

        Ok(sock)
    }

    /// Create a TCP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// The socket is bound to the caller's network namespace via `net_ns_id`.
    /// Port bindings will be isolated within this namespace.
    ///
    /// # R76-3 FIX: Per-Namespace Socket Quota
    ///
    /// Enforces MAX_SOCKETS_PER_NS limit to prevent namespace DoS.
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_tcp_socket(
        &self,
        label: SocketLabel,
        net_ns_id: NamespaceId,
    ) -> Result<Arc<SocketState>, SocketError> {
        // R76-3 FIX: Check and increment namespace quota before creating socket
        self.try_inc_ns_count(net_ns_id)?;

        // Build LSM context
        let mut ctx = NetCtx::new(0, TCP_PROTO as u16);
        ctx.cap = Some(CapId::INVALID);

        // Check LSM policy
        if let Err(_e) = hook_net_socket(&label.creator, &ctx) {
            self.dec_ns_count(net_ns_id); // Rollback quota
            return Err(SocketError::PermissionDenied);
        }

        // R107-5 FIX: Allocate socket ID with overflow protection.
        // Uses fetch_update + checked_add to prevent u64 wrap-around and ID collision,
        // matching the R105-5 pattern applied to IPC endpoint IDs.
        let id = match self.next_socket_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(prev) => prev,
            Err(_) => {
                self.dec_ns_count(net_ns_id); // Rollback quota
                return Err(SocketError::IdExhausted);
            }
        };

        // Create socket state with namespace binding
        let sock = Arc::new(SocketState::new(
            id,
            SocketDomain::Inet4,
            SocketType::Stream,
            SocketProtocol::Tcp,
            label,
            net_ns_id,
        ));

        // Register in table
        self.sockets.write().insert(id, sock.clone());
        self.created.fetch_add(1, Ordering::Relaxed);

        Ok(sock)
    }

    /// Bind a UDP socket to an address and port.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to bind
    /// * `current` - Current process context (for privilege check)
    /// * `cap_id` - Capability used for this operation
    /// * `ip` - Local IP address
    /// * `port` - Port number (None for ephemeral)
    /// * `can_bind_privileged` - Whether caller can bind to privileged ports
    ///                           (euid == 0 or NET_BIND_SERVICE capability)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_bind` for LSM policy check
    /// - Ports < 1024 require can_bind_privileged == true
    /// - R47-1 FIX: Uses current creds, not creation creds
    /// - R49-3 FIX: Respects NET_BIND_SERVICE capability via flag
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port bindings are partitioned by the socket's network namespace.
    /// Different namespaces can bind to the same port independently.
    ///
    /// # Returns
    ///
    /// The bound port number on success.
    ///
    /// # J2-8 / R169-6: Per-cgroup port budget
    ///
    /// `policy` selects the charge + teardown contract (replaces the old
    /// `charge_ephemeral: bool`): `BindCharge::Ephemeral` for a kernel-chosen
    /// port (`port == None` — send_to_udp auto-bind, explicit `bind(0)`),
    /// `BindCharge::Explicit` for a user-chosen port (`port == Some(p)` —
    /// sys_bind non-zero; charged AND hold-until-close, R169-6 slice 2). One
    /// port is charged to the current cgroup's NET `ports.max` after LSM
    /// admits and before the binding lock; the charge is rolled back if the
    /// port turns out to be in use.
    ///
    /// NOTE (errno precedence, accepted): a tenant at ports.max binding a BUSY
    /// port gets EAGAIN (quota, checked first) rather than EADDRINUSE —
    /// reordering would add an extra L8 probe before the charge.
    /// NOTE (capability persistence): a privileged explicit bind that passed
    /// NET_BIND_SERVICE keeps its port + charge after a later capability drop
    /// (POSIX: bind permission is checked at bind time) — do not "fix" this by
    /// refunding on cap-drop.
    pub fn bind_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // R169-6 slice 2: the charge policy must match the port-argument shape.
        debug_assert!(
            matches!(policy, BindCharge::None)
                || (matches!(policy, BindCharge::Explicit) == port.is_some()),
            "BindCharge::Explicit <=> explicit port; Ephemeral <=> port == None"
        );

        // Determine port
        // R75-1 FIX: Pass namespace ID for ephemeral port allocation
        let chosen_port = if let Some(p) = port {
            // R49-3 FIX: Privileged port check uses flag from syscall layer
            // This ensures NET_BIND_SERVICE capability is properly honored
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_port(sock.net_ns_id)?
        };

        // Build LSM context with actual CapId and current context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_bind(current, &ctx)?;

        // J2-8 / R169-6 slice 2: resolve + charge the per-cgroup port budget
        // AFTER LSM admits and BEFORE taking the binding lock (lock-ordering:
        // cgroup L5 must precede the L8 binding lock). Soft pre-insert charge —
        // rolled back below if the port races to PortInUse. cgid 0 (root / no
        // proc) is a no-op. Charging is kind-blind; the stamped kind only
        // selects the TEARDOWN contract.
        //
        // UDP-EXPLICIT INVARIANT: a charged Explicit UDP binding is
        // hold-until-close BY CONSTRUCTION — UDP has NO while-alive teardown
        // arm (connect() is TCP-gated; send_to_udp auto-binds only when
        // unbound; every UDP remover — close(), deliver_udp dead-Weak cleanup,
        // reap/sweep, drain_ns — is kind-agnostic and fires only at
        // close()/dead-Weak/netns-finality). The BindKind::Explicit stamp is
        // INERT for UDP. A FUTURE UDP connect()/rebind that removes a LIVE
        // binding MUST add the same peek_binding_kind PURE-SKIP guard or it
        // reintroduces the TCP undercount class.
        let charged_cgroup = if policy.should_charge() {
            if matches!(policy, BindCharge::Explicit) {
                // Self-heal for the explicit path: the ephemeral allocator
                // reaps this namespace's dead bindings before its availability
                // scan, but an explicit Some(p) bind never runs the allocator —
                // reap here so a tenant wedged at ports.max by dead bindings is
                // unwedged before the gate. Own block: the L8 guard MUST drop
                // before the drain/charge below (L5 under L8 is forbidden).
                let mut bindings = self.udp_bindings.lock();
                self.reap_dead_bindings(&mut bindings, sock.net_ns_id);
            }
            // Drain reclaimed charges (incl. the reap's, and the allocator's
            // for the port==None path) so the gate reads a healed
            // ports_current.
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // R75-1 FIX: Use (namespace, port) key for binding
        let binding_key = (sock.net_ns_id, chosen_port);

        // Register port binding. Compute the outcome WITHOUT returning from inside
        // the L8 critical section, so the speculative charge can be rolled back
        // after the guard drops (cgroup uncharge under the binding lock is
        // forbidden by the lock-ordering invariant).
        let mut port_in_use = false;
        let mut evicted: Option<u64> = None;
        {
            let mut bindings = self.udp_bindings.lock();
            if bindings
                .get(&binding_key)
                .map_or(false, |pb| pb.sock.upgrade().is_some())
            {
                port_in_use = true;
            } else if let InsertOutcome::DisplacedCharge(old) = Self::insert_binding_charged(
                &mut bindings,
                binding_key,
                sock,
                charged_cgroup,
                policy.kind(),
            ) {
                evicted = Some(old);
            }
        }
        // J2-8: enqueue any evicted stale charge (deferred; drained in process
        // ctx). Done after dropping the guard.
        if let Some(old) = evicted {
            self.enqueue_port_uncharge(old, 1);
        }
        if port_in_use {
            // Roll back the speculative charge (guard dropped above) —
            // kind-agnostic: a failed explicit bind costs zero.
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(SocketError::PortInUse);
        }

        // Update socket state
        sock.bind_local(ip, chosen_port);
        self.bind_count.fetch_add(1, Ordering::Relaxed);

        Ok(chosen_port)
    }

    // NOTE: alloc_ephemeral_tcp_port is defined later in this impl block.

    /// Bind a TCP socket (stream) to a local address/port (R51-1).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to bind
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `ip` - Local IP address to bind to
    /// * `port` - Port to bind (None for ephemeral)
    /// * `can_bind_privileged` - Whether privileged ports are allowed
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_bind` for LSM policy check
    /// - Privileged ports require root or NET_BIND_SERVICE
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port bindings are partitioned by the socket's network namespace.
    ///
    /// # J2-8 / R169-6
    ///
    /// `policy` mirrors `bind_udp` (see there, incl. the errno-precedence and
    /// capability-persistence notes): `BindCharge::Ephemeral` for `bind(0)` /
    /// `listen()` auto-bind (kernel-chosen, charged, ghost-bind teardown),
    /// `BindCharge::Explicit` for sys_bind non-zero (charged AND
    /// hold-until-close — the five while-alive teardown arms PURE-SKIP it,
    /// R169-6 slice 2). The active-open TCP path (`connect`) allocates inline
    /// and charges at its own site rather than through `bind_tcp`; its
    /// `did_alloc==false` reconnect over an own charged `bind(0)`/explicit
    /// binding preserves that charge (reuse-live-binding) rather than
    /// displacing it.
    pub fn bind_tcp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
        policy: BindCharge,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // R169-6 slice 2: the charge policy must match the port-argument shape.
        debug_assert!(
            matches!(policy, BindCharge::None)
                || (matches!(policy, BindCharge::Explicit) == port.is_some()),
            "BindCharge::Explicit <=> explicit port; Ephemeral <=> port == None"
        );

        // Determine port
        // R75-1 FIX: Pass namespace ID for ephemeral port allocation
        let chosen_port = if let Some(p) = port {
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_tcp_port(sock.net_ns_id)?
        };

        // Build LSM context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id);

        // Check LSM policy
        hook_net_bind(current, &ctx)?;

        // J2-8 / R169-6 slice 2: charge AFTER LSM, BEFORE the binding lock
        // (see bind_udp for the full ordering + UDP-EXPLICIT INVARIANT notes;
        // here the TCP while-alive arms enforce hold-until-close via
        // resolve_while_alive_teardown).
        let charged_cgroup = if policy.should_charge() {
            if matches!(policy, BindCharge::Explicit) {
                // Self-heal for the explicit path (see bind_udp): reap this
                // namespace's dead bindings — the explicit Some(p) bind never
                // runs the allocator's reaper. Own block: the L8 guard MUST
                // drop before the drain/charge below.
                let mut bindings = self.tcp_bindings.lock();
                self.reap_dead_bindings(&mut bindings, sock.net_ns_id);
            }
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // R75-1 FIX: Use (namespace, port) key for binding
        let binding_key = (sock.net_ns_id, chosen_port);

        // Register port binding (never return from inside the L8 section).
        let mut port_in_use = false;
        let mut evicted: Option<u64> = None;
        {
            let mut bindings = self.tcp_bindings.lock();
            if bindings
                .get(&binding_key)
                .map_or(false, |pb| pb.sock.upgrade().is_some())
            {
                port_in_use = true;
            } else if let InsertOutcome::DisplacedCharge(old) = Self::insert_binding_charged(
                &mut bindings,
                binding_key,
                sock,
                charged_cgroup,
                policy.kind(),
            ) {
                evicted = Some(old);
            }
        }
        if let Some(old) = evicted {
            self.enqueue_port_uncharge(old, 1);
        }
        if port_in_use {
            // Kind-agnostic rollback — a failed explicit bind costs zero.
            uncharge_port_cgroup(charged_cgroup, 1);
            return Err(SocketError::PortInUse);
        }

        // Update socket state
        sock.bind_local(ip, chosen_port);
        self.bind_count.fetch_add(1, Ordering::Relaxed);

        Ok(chosen_port)
    }

    /// Transition a TCP socket into LISTEN state (R51-1).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to put into listen mode
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `backlog` - Maximum pending connections (clamped to limits)
    /// * `can_bind_privileged` - Whether privileged ports are allowed (for auto-bind)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_listen` for LSM policy check
    /// - Auto-binds to ephemeral port if not already bound
    pub fn listen(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        backlog: u32,
        can_bind_privileged: bool,
    ) -> Result<(), SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }

        // Cannot listen on connected socket
        if sock.remote_port().is_some() {
            return Err(SocketError::AlreadyConnected);
        }

        // Already listening?
        if sock.is_listening() {
            return Ok(());
        }

        let backlog = backlog.max(1) as usize;

        // Auto-bind if not bound
        if sock.local_port().is_none() {
            let local_ip = sock
                .local_ip()
                .map(Ipv4Addr)
                .unwrap_or(Ipv4Addr([0, 0, 0, 0]));
            // R169-6 FIX (slice 1): the listener auto-bind IS charged to the
            // current cgroup's `ports.max`. The port is KERNEL-CHOSEN (port==None
            // → BindCharge::Ephemeral, charged by bind_tcp exactly like an
            // active-open auto-bind),
            // it stamps `charged_cgroup` into the single (ns,port) PortBinding, and
            // it tears down through the EXISTING class-agnostic sites with Ephemeral
            // semantics: close() (5121) reads the STORED cgid and uncharges (ptr-eq
            // gated, so a passive-open child sharing this (ns,port) can never
            // uncharge it), and the dead-Weak triad (lookup cleanup / reap /
            // sweep / netns-Drop backstop) reclaims a no-close drop. A listener is
            // charged exactly ONCE: passive-open children share this entry and
            // never re-insert. Closes the listener-port exhaustion bypass where a
            // server forking thousands of listeners escaped ports.max entirely.
            // (R169-6 slice 2 LANDED: explicit bind(non-zero) is now charged as
            // BindCharge::Explicit with hold-until-close teardown; a listener on
            // an EXPLICITLY-bound socket skips this auto-bind entirely — its
            // binding was already charged once at sys_bind.)
            let _ = self.bind_tcp(
                sock,
                current,
                cap_id,
                local_ip,
                None,
                can_bind_privileged,
                BindCharge::Ephemeral,
            )?;
        }

        // LSM listen hook
        let mut ctx = self.ctx_from_socket(sock);
        ctx.cap = Some(cap_id);
        hook_net_listen(current, &ctx, backlog as u32)?;

        // Install listen TCB + queues
        let meta = sock.meta_snapshot();
        let lip = meta
            .local_ip
            .map(Ipv4Addr)
            .unwrap_or(Ipv4Addr([0, 0, 0, 0]));
        let lport = meta.local_port.ok_or(SocketError::InvalidState)?;

        sock.attach_tcp(TcpControlBlock::new_listen(lip, lport));
        sock.install_listen_state(TcpListenState::new(backlog));

        Ok(())
    }

    /// Lookup a listening socket by local port (R51-1).
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Listener lookup is scoped to the specified network namespace.
    fn lookup_tcp_listener(
        &self,
        net_ns_id: NamespaceId,
        local_port: u16,
    ) -> Option<Arc<SocketState>> {
        // R75-1 FIX: Use namespace-scoped binding key
        let binding_key = (net_ns_id, local_port);
        let mut bindings = self.tcp_bindings.lock();
        match bindings.get(&binding_key).and_then(|pb| pb.sock.upgrade()) {
            Some(sock) if sock.is_listening() => Some(sock),
            Some(_) => None, // Bound but not listening
            None => {
                // J2-8: clean up the stale Weak AND enqueue its charge (this runs
                // in RX/lookup context under the binding lock — DEFERRED uncharge).
                // R169-6: listener entries are now CHARGED (Ephemeral semantics), so
                // reading the STORED cgid here correctly reclaims a dead listener's
                // port charge. No expect_ptr: the entry is already known dead.
                if let Some(cgid) = Self::remove_binding_charged(&mut bindings, binding_key, None) {
                    self.enqueue_port_uncharge(cgid, 1);
                }
                None
            }
        }
    }

    /// Poll the accept queue of a listening socket (non-blocking) (R51-1).
    pub fn poll_accept_ready(
        &self,
        listener: &Arc<SocketState>,
    ) -> Result<Option<Arc<SocketState>>, SocketError> {
        if !listener.is_listening() {
            return Err(SocketError::InvalidState);
        }
        Ok(listener.pop_accept_ready())
    }

    /// Build a UDP datagram for transmission.
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to send from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `src_ip` - Source IP address (our IP)
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `payload` - Data to send
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_send` for LSM policy check
    /// - Automatically binds to ephemeral port if not bound
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Complete UDP datagram ready for IPv4 encapsulation.
    pub fn send_to_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if closed
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Get or allocate local port
        let local_port = match sock.local_port() {
            Some(p) => p,
            None => {
                // Auto-bind to ephemeral port - no privilege needed for ephemeral ports
                // (ephemeral range is 49152-65535, well above privileged port limit)
                // J2-8: ACTIVE-OPEN ephemeral auto-bind -> charge the per-cgroup
                // ports.max budget (BindCharge::Ephemeral).
                self.bind_udp(sock, current, cap_id, src_ip, None, false, BindCharge::Ephemeral)?
            }
        };

        // Build LSM context with actual CapId
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(src_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(dst_ip.0);
        ctx.remote_port = dst_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_send(current, &ctx, payload.len())?;

        // Build UDP datagram
        let datagram = build_udp_datagram(src_ip, dst_ip, local_port, dst_port, payload)?;

        // R158-2 FIX: Seed conntrack so reply packets are classified as ESTABLISHED.
        // Use the IP that will appear in the outgoing IP header (network_config().our_ip)
        // rather than the socket-layer src_ip, which may be 0.0.0.0 for unbound sockets.
        #[cfg(feature = "conntrack")]
        {
            use crate::conntrack::ct_process_udp;
            let ct_src = if src_ip == crate::Ipv4Addr([0, 0, 0, 0]) {
                crate::stack::network_config().our_ip
            } else {
                src_ip
            };
            let now_ms = self.time_wait_now();
            let _ = ct_process_udp(
                sock.net_ns_id.0,
                ct_src,
                dst_ip,
                local_port,
                dst_port,
                payload.len(),
                now_ms,
            );
        }

        // Update statistics
        sock.tx_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        sock.tx_datagrams.fetch_add(1, Ordering::Relaxed);

        Ok(datagram)
    }

    /// Initiate a TCP connect (client-side SYN).
    ///
    /// Builds and returns the SYN segment and records the TCB.
    /// The handshake completes asynchronously via the RX path (Phase 2).
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket to connect
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `src_ip` - Source IP address (0.0.0.0 for auto-select)
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `timeout_ns` - Timeout for blocking connect (None = blocking indefinitely)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_connect` for LSM policy check on active open
    /// - Auto-binds to ephemeral port if not already bound
    ///
    /// # Returns
    ///
    /// - `Ok(TcpConnectResult)` with SYN segment on successful initiation
    /// - `Err(InProgress)` for non-blocking connect (timeout_ns == Some(0))
    /// - `Err(Timeout)` if blocking connect times out before ESTABLISHED
    ///
    /// # Note
    ///
    /// Phase 1 implementation only initiates the handshake (SYN). Full 3-way
    /// handshake completion (SYN-ACK handling, ACK transmission) requires the
    /// RX path integration in Phase 2.
    pub fn connect(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        timeout_ns: Option<u64>,
    ) -> Result<TcpConnectResult, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }
        if dst_port == 0 {
            return Err(SocketError::InvalidProtocol);
        }

        // Check if already connected or connecting
        if sock.remote_port().is_some() {
            return Err(SocketError::AlreadyConnected);
        }
        if let Some(state) = sock.tcp_state() {
            if state != TcpState::Closed {
                return Err(SocketError::AlreadyConnected);
            }
        }

        // Determine local endpoint (bind if needed)
        // R75-1 FIX: Allocate port within socket's network namespace
        // J2-8: `did_alloc` marks an ACTIVE-OPEN ephemeral allocation — the only
        // per-cgroup port-budget charge candidate (an already-bound socket
        // re-uses its port and is not charged here).
        let (local_port, did_alloc) = match sock.local_port() {
            Some(p) => (p, false),
            None => (self.alloc_ephemeral_tcp_port(sock.net_ns_id)?, true),
        };
        let local_ip = sock.local_ip().map(Ipv4Addr).unwrap_or(src_ip);

        // Build the connection key for uniqueness check
        let conn_key = tcp_map_key_from_parts(sock.net_ns_id, local_ip, local_port, dst_ip, dst_port);

        // Check for duplicate connection (but don't register yet - defer until after LSM)
        {
            let conns = self.tcp_conns.lock();
            if conns.get(&conn_key).and_then(|w| w.upgrade()).is_some() {
                return Err(SocketError::PortInUse);
            }
        }

        // LSM policy check BEFORE registering connection
        // Use hook_net_connect for active open (per LSM API)
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(dst_ip.0);
        ctx.remote_port = dst_port;
        ctx.cap = Some(cap_id);
        hook_net_connect(current, &ctx)?;

        // J2-8: charge the per-cgroup ephemeral-port budget for an ACTIVE-OPEN
        // allocation, AFTER LSM admits and BEFORE any binding lock (lock-ordering
        // forbids the L5 cgroup charge under the L8 binding lock). Soft pre-charge
        // — refunded by the rollback below if registration fails. cgid 0 (root /
        // no process ctx) is a no-op.
        let charged_cgroup = if did_alloc {
            // Drain reclaimed charges first (the allocator just reaped this ns's
            // dead bindings) so a wedged tenant is unwedged before the gate.
            self.drain_deferred_port_uncharges();
            let cgid = resolve_port_cgroup();
            try_charge_port_cgroup(cgid)?;
            cgid
        } else {
            0
        };

        // Track what we've registered for cleanup on failure
        let mut binding_registered = false;
        let mut conn_registered = false;

        // Register local port binding and connection 4-tuple
        // This is done AFTER LSM check to prevent resource leaks on denial
        // R75-1 FIX: Use namespace-scoped port binding keys
        let binding_key = (sock.net_ns_id, local_port);
        let registration_result: Result<(), SocketError> = (|| {
            // Register local port in tcp_bindings
            {
                let mut bindings = self.tcp_bindings.lock();
                // R169-6: skip the re-insert ONLY when a LIVE binding for this
                // (ns,port) owned by THIS socket already exists. That entry
                // already carries the correct stored charge AND kind (bind(0)
                // Ephemeral, explicit bind Explicit), so overwriting it with
                // the `did_alloc == false` speculative charge (0) would
                // displace + refund the live charge while the port stays held —
                // the R169-6 self-replace undercount. It is NOT safe to gate
                // purely on `did_alloc`: an UNcharged teardown can remove the
                // entry while leaving `local_port` set.
                //
                // REPAIR PROOF (R169-6 slice 2): a CHARGED Ephemeral
                // while-alive removal clears `local_port` (ghost-bind fix, so
                // the retry takes `did_alloc == true`); a CHARGED Explicit
                // binding is NEVER removed by a while-alive arm
                // (hold-until-close — removed only by close()/terminal
                // cleanup/dead-Weak reap/netns drain). So an own binding ABSENT
                // here with `local_port == Some` is always UNcharged (an
                // uncharged-teardown survivor, or post-netns-drain where the
                // drain already enqueued any charge) — repairing it with the
                // speculative 0 / BindKind::Ephemeral never undercounts.
                //
                // This gate deliberately uses get()+upgrade()+ptr_eq, NOT
                // peek_binding_kind: it must distinguish a live FOREIGN owner
                // (PortInUse) from a dead stale entry (repairable), which
                // requires upgrade().
                let mut reuse_live_binding = false;
                // Reject only a LIVE binding owned by a DIFFERENT socket (a live
                // binding owned by THIS socket — re-connect — proceeds).
                if let Some(existing) = bindings.get(&binding_key) {
                    if let Some(existing_sock) = existing.sock.upgrade() {
                        if !Arc::ptr_eq(&existing_sock, sock) {
                            return Err(SocketError::PortInUse);
                        }
                        reuse_live_binding = !did_alloc;
                    }
                }
                if !reuse_live_binding {
                    // J2-8: stamp the (possibly 0) charge into a newly-created or
                    // repaired binding value, and refund any displaced stale charge
                    // (enqueue — we hold the L8 binding lock). From here the BINDING
                    // owns `charged_cgroup`; the failure rollback below removes it
                    // (returning the charge to uncharge), so `binding_registered`
                    // gates direct-vs-via-binding refund of the speculative charge.
                    // R169-6 slice 2: a connect-created/repaired binding is always
                    // BindKind::Ephemeral (fresh auto-alloc, or an uncharged repair
                    // — see the REPAIR PROOF above; a non-zero charge here implies
                    // did_alloc).
                    debug_assert!(
                        charged_cgroup == 0 || did_alloc,
                        "connect: non-zero speculative charge implies did_alloc"
                    );
                    if let InsertOutcome::DisplacedCharge(old) = Self::insert_binding_charged(
                        &mut bindings,
                        binding_key,
                        sock,
                        charged_cgroup,
                        BindKind::Ephemeral,
                    ) {
                        self.enqueue_port_uncharge(old, 1);
                    }
                    binding_registered = true;
                }
            }

            // Register connection 4-tuple
            {
                let mut conns = self.tcp_conns.lock();

                // R50-5 IMPROVEMENT: Prune stale Weak entries before counting
                // This prevents false exhaustion when connections have been dropped
                // but their Weak references haven't been cleaned up yet
                self.conns_retain_accounted(&mut conns);

                // R50-5 FIX: Enforce global TCP connection limit to prevent resource exhaustion
                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                    return Err(SocketError::NoPorts);
                }
                // Re-check after lock acquisition (race-safe)
                if conns.get(&conn_key).and_then(|w| w.upgrade()).is_some() {
                    return Err(SocketError::PortInUse);
                }
                // J2-1: per-namespace connection budget (composes with the global
                // cap checked above; both must pass). On over-quota this `?` exits
                // the registration closure with QuotaExceeded -> EAGAIN, dropping
                // the `conns` guard before the binding rollback below.
                self.try_inc_ns_conn(conn_key.0)?;
                conns.insert(conn_key, Arc::downgrade(sock));
                conn_registered = true;
            }

            Ok(())
        })();

        // On registration failure, clean up any partial registrations
        if let Err(e) = registration_result {
            if conn_registered {
                // J2-1: uncharge the per-namespace connection charged at insert.
                if self.tcp_conns.lock().remove(&conn_key).is_some() {
                    self.dec_ns_conn(conn_key.0);
                }
            }
            if binding_registered {
                // R75-1 FIX: Remove using namespace-scoped key.
                // J2-8: removing the binding returns its STORED charge to
                // uncharge (process ctx — block-scoped so the L8 guard drops
                // before the L5 uncharge, avoiding the Rust-2021 temporary trap).
                // R169-6 slice 2 (ARM-1): deliberately NOT routed through
                // resolve_while_alive_teardown — this rollback is gated by the
                // LOCAL `binding_registered` flag, so it can only ever remove
                // the own EPHEMERAL binding THIS connect just inserted. A
                // pre-existing own Explicit/bind(0) binding took the
                // reuse_live_binding path (binding_registered == false) and is
                // structurally unreachable here; converting this arm to
                // peek-then-remove would remove a binding this call never
                // inserted -> spurious uncharge -> undercount.
                let cgid = {
                    let mut bindings = self.tcp_bindings.lock();
                    Self::remove_binding_charged(&mut bindings, binding_key, Some(Arc::as_ptr(sock)))
                };
                if let Some(c) = cgid {
                    uncharge_port_cgroup(c, 1);
                }
            } else {
                // J2-8: the binding was never inserted (e.g. PortInUse on a live
                // foreign binding) — refund the orphaned speculative charge.
                uncharge_port_cgroup(charged_cgroup, 1);
            }
            return Err(e);
        }

        // Update socket metadata (connection is now registered)
        sock.bind_local(local_ip, local_port);
        sock.set_remote(dst_ip, dst_port);

        // Generate Initial Sequence Number (ISN) per RFC 6528
        let iss = generate_isn(local_ip, local_port, dst_ip, dst_port);

        // Build TCB in SYN_SENT state
        let mut tcb = TcpControlBlock::new_client(local_ip, local_port, dst_ip, dst_port, iss);
        tcb.state = TcpState::SynSent;
        tcb.snd_una = iss;
        tcb.snd_nxt = iss.wrapping_add(1); // SYN consumes one sequence number
        tcb.snd_wnd = TCP_DEFAULT_WINDOW as u32;

        // R58: RFC 7323 Window Scaling - calculate and set our scale factor
        // WSopt MUST only appear in SYN segments
        tcb.rcv_wscale = calc_wscale(tcb.rcv_wnd);
        tcb.wscale_requested = true;

        // SACK-Permitted (RFC 2018): advertise SACK capability in SYN
        tcb.sack_requested = true;

        // Calculate scaled window for SYN
        let syn_wnd = Self::encode_adv_window(&tcb, tcb.rcv_wnd);
        sock.attach_tcp(tcb);

        // Build the SYN segment with Window Scale + SACK-Permitted options
        let tcp_guard = sock.tcp.lock();
        let tcb_ref = tcp_guard.as_ref().unwrap();
        let syn_options = [
            TcpOptionKind::WindowScale(tcb_ref.control.rcv_wscale),
            TcpOptionKind::SackPermitted,
        ];
        drop(tcp_guard);
        let segment = build_tcp_segment_with_options(
            local_ip,
            dst_ip,
            local_port,
            dst_port,
            iss,
            0,
            TCP_FLAG_SYN,
            syn_wnd,
            &syn_options,
            &[],
        );

        let result = TcpConnectResult {
            segment,
            local_port,
            src_ip: local_ip,
            dst_ip,
            dst_port,
        };

        // Non-blocking connect: return result immediately with InProgress
        // The caller should transmit the SYN and poll for state transition
        if timeout_ns == Some(0) {
            // For non-blocking, we still return the result so the SYN can be transmitted
            // The socket is in SYN_SENT state; completion happens via RX path
            return Ok(result);
        }

        // Blocking connect: wait for state transition signaled via TCP waiters
        // Note: Full handshake completion requires RX path integration (Phase 2)
        // For now, we wait but the RX path to process SYN-ACK is not yet implemented
        if let Some(waiters) = sock.tcp_waiters() {
            match waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => {
                    if matches!(sock.tcp_state(), Some(TcpState::Established)) {
                        return Ok(result);
                    }
                    // Connection was reset or failed
                    if matches!(sock.tcp_state(), Some(TcpState::Closed)) {
                        // Clean up on failed connection
                        // R75-1 FIX: Use namespace-scoped binding key
                        let binding_key = (sock.net_ns_id, local_port);
                        // J2-8 / R169-6 slice 2: while-alive teardown via the
                        // kind-gated choke-point — an own charged Explicit
                        // binding is PURE-SKIPPED (hold-until-close), an own
                        // charged Ephemeral is removed + refunded +
                        // local-cleared (ghost-bind fix). Block-scoped so the
                        // L8 guard drops before the L5 uncharge / meta lock.
                        let action = {
                            let mut bindings = self.tcp_bindings.lock();
                            Self::resolve_while_alive_teardown(
                                &mut bindings,
                                binding_key,
                                Arc::as_ptr(sock),
                            )
                        };
                        if let TeardownAction::Removed(Some(c)) = action {
                            uncharge_port_cgroup(c, 1);
                            // Ghost-bind clear — lexically Ephemeral-only (a
                            // charged Explicit took SkipExplicit above).
                            let mut m = sock.meta.lock();
                            m.local_ip = None;
                            m.local_port = None;
                        }
                        // J2-1: uncharge the per-namespace connection.
                        if self.tcp_conns.lock().remove(&conn_key).is_some() {
                            self.dec_ns_conn(conn_key.0);
                        }
                        return Err(SocketError::Closed);
                    }
                    // Still in SYN_SENT or other intermediate state
                    return Err(SocketError::InProgress);
                }
                WaitOutcome::TimedOut => {
                    // Timeout - the SYN was sent but no response
                    // Clean up resources to allow retry or close
                    // R75-1 FIX: Use namespace-scoped binding key
                    let binding_key = (sock.net_ns_id, local_port);
                    // J2-8 / R169-6 slice 2: kind-gated while-alive teardown
                    // (see the Woken->Closed arm). Belt-and-suspenders with the
                    // deferred cleanup_tcp_connection path — BTreeMap::remove
                    // is the single arbiter, so only one of them gets the
                    // charge; an own charged Explicit binding is PURE-SKIPPED
                    // on BOTH (hold-until-close).
                    let action = {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::resolve_while_alive_teardown(
                            &mut bindings,
                            binding_key,
                            Arc::as_ptr(sock),
                        )
                    };
                    if let TeardownAction::Removed(Some(c)) = action {
                        uncharge_port_cgroup(c, 1);
                        // Ghost-bind clear — lexically Ephemeral-only (a
                        // charged Explicit took SkipExplicit above).
                        let mut m = sock.meta.lock();
                        m.local_ip = None;
                        m.local_port = None;
                    }
                    // J2-1: uncharge the per-namespace connection.
                    if self.tcp_conns.lock().remove(&conn_key).is_some() {
                        self.dec_ns_conn(conn_key.0);
                    }
                    // Reset socket metadata to allow retry after close
                    {
                        let mut meta = sock.meta.lock();
                        meta.remote_ip = None;
                        meta.remote_port = None;
                    }
                    // J2-6: clear the TCB through the unified helper, which first
                    // uncharges any residual per-namespace send bytes (today 0 in
                    // SYN-SENT since the socket can't send pre-ESTABLISHED, but
                    // leak-proof for any future pre-ESTABLISHED data buffering).
                    self.detach_tcp_uncharged(sock);
                    return Err(SocketError::Timeout);
                }
                WaitOutcome::Closed => {
                    // R75-1 FIX: Use namespace-scoped binding key
                    let binding_key = (sock.net_ns_id, local_port);
                    // J2-8 / R169-6 slice 2: kind-gated while-alive teardown
                    // (see the Woken->Closed arm). Belt-and-suspenders with the
                    // deferred cleanup_tcp_connection path — BTreeMap::remove
                    // is the single arbiter, so only one of them gets the
                    // charge; an own charged Explicit binding is PURE-SKIPPED
                    // on BOTH (hold-until-close).
                    let action = {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::resolve_while_alive_teardown(
                            &mut bindings,
                            binding_key,
                            Arc::as_ptr(sock),
                        )
                    };
                    if let TeardownAction::Removed(Some(c)) = action {
                        uncharge_port_cgroup(c, 1);
                        // Ghost-bind clear — lexically Ephemeral-only (a
                        // charged Explicit took SkipExplicit above).
                        let mut m = sock.meta.lock();
                        m.local_ip = None;
                        m.local_port = None;
                    }
                    // J2-1: uncharge the per-namespace connection.
                    if self.tcp_conns.lock().remove(&conn_key).is_some() {
                        self.dec_ns_conn(conn_key.0);
                    }
                    return Err(SocketError::Closed);
                }
                WaitOutcome::NoProcess => return Err(SocketError::NoProcess),
            }
        }

        // No waiters registered (early boot) - return result for async processing
        // The SYN segment is ready to be transmitted by the caller
        Ok(result)
    }

    /// Receive a UDP datagram (blocking with optional timeout).
    ///
    /// # Arguments
    ///
    /// * `sock` - Socket to receive from
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `timeout_ns` - Timeout in nanoseconds (None for blocking)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_recv` for LSM policy check
    /// - R47-2 FIX: Uses current creds and actual CapId
    ///
    /// # Returns
    ///
    /// Received datagram on success.
    pub fn recv_from_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        timeout_ns: Option<u64>,
    ) -> Result<PendingDatagram, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        loop {
            // Check if closed
            if sock.is_closed() {
                return Err(SocketError::Closed);
            }

            // R152-13 FIX: Peek at front datagram and perform LSM check BEFORE popping.
            // This prevents data loss when LSM denies the recv operation.
            // Codex review: pop must happen under the SAME lock to avoid checked-A-popped-B race.
            {
                let mut queue = sock.rx_queue.lock();
                if let Some(pkt) = queue.front() {
                    let mut ctx = self.ctx_from_socket(sock);
                    ctx.remote = ipv4_to_u64(pkt.src_ip.0);
                    ctx.remote_port = pkt.src_port;
                    ctx.cap = Some(cap_id);

                    hook_net_recv(current, &ctx, pkt.data.len())?;

                    // LSM approved — pop the exact datagram we checked (same lock held)
                    let pkt = queue.pop_front().unwrap();
                    // Account for global UDP bytes
                    let _ = GLOBAL_UDP_QUEUED_BYTES.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |current| Some(current.saturating_sub(pkt.data.len())),
                    );
                    return Ok(pkt);
                } else {
                    drop(queue);
                    // Block on wait queue
                    match sock.waiters.wait_with_timeout(timeout_ns) {
                        WaitOutcome::Woken => continue,
                        WaitOutcome::TimedOut => return Err(SocketError::Timeout),
                        WaitOutcome::Closed => return Err(SocketError::Closed),
                        WaitOutcome::NoProcess => return Err(SocketError::NoProcess),
                    }
                }
            }
        }
    }

    // ========================================================================
    // TCP Data Transfer (Phase 3)
    // ========================================================================

    /// Send TCP data (PSH+ACK segment).
    ///
    /// Builds MSS-sized TCP segments for transmission.
    /// Large payloads are split into multiple segments to fit within MTU.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket (must be in ESTABLISHED state)
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `payload` - Data to send
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_send` for LSM policy check
    /// - Validates socket is in ESTABLISHED state
    /// - Enforces TCP_MAX_SEND_SIZE limit
    ///
    /// # Returns
    ///
    /// Tuple of (bytes_queued, segments) on success.
    /// Caller is responsible for transmitting each segment.
    pub fn tcp_send(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        payload: &[u8],
    ) -> Result<(usize, Vec<Vec<u8>>), SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // R51-2 FIX: Enforce send size limit to prevent OOM DoS
        // This is the canonical enforcement point for all TCP send paths.
        if payload.len() > TCP_MAX_SEND_SIZE {
            return Err(SocketError::MessageTooLarge);
        }

        // Get connection endpoints from metadata
        let meta = sock.meta_snapshot();
        let (local_ip, local_port, remote_ip, remote_port) = match (
            meta.local_ip.map(Ipv4Addr),
            meta.local_port,
            meta.remote_ip.map(Ipv4Addr),
            meta.remote_port,
        ) {
            (Some(li), Some(lp), Some(ri), Some(rp)) => (li, lp, ri, rp),
            _ => return Err(SocketError::InvalidState),
        };

        // LSM policy check
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(remote_ip.0);
        ctx.remote_port = remote_port;
        ctx.cap = Some(cap_id);
        hook_net_send(current, &ctx, payload.len())?;

        // Build segment under TCP lock
        let mut guard = sock.tcp.lock();
        let tcp_state = guard.as_mut().ok_or(SocketError::InvalidState)?;

        // Must be in a send-capable state (ESTABLISHED or CLOSE_WAIT)
        if !tcp_state.control.state.can_send() {
            return Err(SocketError::InvalidState);
        }

        // Get current timestamp for idle validation and retransmission tracking
        let now_ms = self.time_wait_now();

        // R57-1: RFC 2861 idle cwnd validation - reduce cwnd if connection was idle
        // This prevents bursting with a stale (potentially large) cwnd after idle periods
        crate::tcp::validate_cwnd_after_idle(&mut tcp_state.control, now_ms);

        // Respect the peer-advertised send window; refuse to emit data that would overflow it
        let window_avail = tcp_state.control.send_window_available() as usize;
        if !payload.is_empty() && payload.len() > window_avail {
            // Window too small - caller should retry later
            return Err(SocketError::Timeout);
        }

        // R115-3 FIX: Bound total buffered TX bytes per connection to prevent OOM.
        // The send_buffer_bytes counter tracks cumulative data in the send_buffer.
        // If adding this payload would exceed the per-socket cap, reject with
        // WouldBlock so the caller retries after ACKs drain the buffer.
        let new_total = tcp_state
            .control
            .send_buffer_bytes
            .checked_add(payload.len())
            .ok_or(SocketError::WouldBlock)?;
        if new_total > TCP_MAX_SEND_BUFFER_BYTES {
            return Err(SocketError::WouldBlock);
        }

        // J2-6: per-namespace TX-memory budget — reserve `payload.len()` headroom
        // atomically (HARD cap, fail-closed). The per-conn cap above is checked
        // first (cheapest). On over-quota the caller retries after ACKs drain. The
        // reservation advances the per-TCB mirror; the post-buffering reconcile
        // below refunds the (payload.len() - offset) shortfall if OOM truncates the
        // segmentation loop. Root (ns 0) is exempt.
        self.try_charge_ns_send(sock.net_ns_id, &mut tcp_state.control, payload.len())?;

        // Get current sequence numbers
        let base_seq = tcp_state.control.snd_nxt;
        let ack = tcp_state.control.rcv_nxt;

        // R58: Advertise our scaled receive window
        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

        // TCP segmentation: split payload into MSS-sized chunks
        let mss = TCP_ETHERNET_MSS as usize;
        // R163-10 FIX: Start with Vec::new() instead of Vec::with_capacity so
        // the segments list itself has no infallible reservation. Each slot is
        // reserved fallibly inside the loop via try_reserve(1) before push.
        let mut segments: Vec<Vec<u8>> = Vec::new();
        let mut offset = 0usize;

        while offset < payload.len() {
            let end = core::cmp::min(offset + mss, payload.len());
            let seg_payload = &payload[offset..end];
            let seq = base_seq.wrapping_add(offset as u32);

            // PSH flag on non-empty data (typically set on last segment)
            let is_last = end == payload.len();
            let flags = TCP_FLAG_ACK
                | if !seg_payload.is_empty() && is_last {
                    TCP_FLAG_PSH
                } else {
                    0
                };

            // R163-10 FIX: Reserve space in the output segments Vec before
            // building the segment. If we cannot even reserve the slot, break
            // now — no data was buffered for retransmission for this chunk.
            if segments.try_reserve(1).is_err() {
                break;
            }

            let segment = build_tcp_segment(
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                seq,
                ack,
                flags,
                advertised_wnd,
                seg_payload,
            );

            // R163-10 FIX: build_tcp_segment returns empty Vec on OOM; do not
            // queue an empty (malformed) packet or advance accounting.
            if segment.is_empty() {
                break;
            }

            // Buffer segment for potential retransmission
            // This enables reliable delivery: segments are kept until ACKed
            // R162-9 FIX: Fallible allocation for retransmission buffer copy.
            let mut retrans_data = Vec::new();
            if retrans_data.try_reserve_exact(seg_payload.len()).is_err() {
                break; // Stop sending more segments; already-buffered ones will be retransmitted
            }
            retrans_data.extend_from_slice(seg_payload);

            // R163-10 FIX: Reserve a slot in the send_buffer VecDeque fallibly
            // before push_back. If send_buffer is full or OOM, break and leave
            // already-queued segments for transmission.
            if tcp_state.control.send_buffer.try_reserve(1).is_err() {
                break;
            }
            tcp_state.control.send_buffer.push_back(TcpSegment {
                seq,
                data: retrans_data,
                sent_at: now_ms,
                retrans_count: 0,
                sacked: false,
                lost: false,
            });

            segments.push(segment);
            offset = end;
        }

        // R163-1 FIX: Use `offset` (actual bytes buffered) not `payload.len()`.
        // When try_reserve_exact fails mid-loop, only `offset` bytes have
        // retransmission buffers. Advancing snd_nxt past unbuffered data
        // causes irrecoverable sequence number corruption on packet loss.
        if offset == 0 {
            // J2-6: nothing was buffered — refund the full per-ns reservation
            // (reconcile sees live == old send_buffer_bytes < mirror) before exit.
            self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);
            drop(guard);
            return Err(SocketError::NoMemory);
        }

        tcp_state.control.send_buffer_bytes = tcp_state
            .control
            .send_buffer_bytes
            .saturating_add(offset);

        // J2-6: true the per-ns counter to the bytes actually buffered, refunding
        // the (payload.len() - offset) over-reservation when OOM truncated the loop.
        self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);

        tcp_state.control.snd_nxt = base_seq.wrapping_add(offset as u32);

        // R57-1: Record activity timestamp for idle detection (RFC 2861)
        tcp_state.control.last_activity = now_ms;

        drop(guard);

        // Update statistics
        sock.tx_bytes
            .fetch_add(offset as u64, Ordering::Relaxed);

        Ok((offset, segments))
    }

    /// Shutdown TCP connection (half-close).
    ///
    /// Implements graceful shutdown per RFC 793. SHUT_RD is a no-op (we continue
    /// receiving data until FIN). SHUT_WR sends FIN and transitions state.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `how` - Shutdown mode: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
    ///
    /// # State Transitions
    ///
    /// - ESTABLISHED + SHUT_WR → FIN_WAIT_1 (send FIN)
    /// - CLOSE_WAIT + SHUT_WR → LAST_ACK (send FIN)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_shutdown` for LSM policy check
    ///
    /// # Returns
    ///
    /// Serialized FIN segment for transmission (if needed), or None.
    pub fn tcp_shutdown(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        how: i32,
    ) -> Result<Option<Vec<u8>>, SocketError> {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;

        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        // Validate how parameter
        if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
            return Err(SocketError::InvalidState);
        }

        // SHUT_RD is a no-op for TCP (we continue receiving until FIN)
        if how == SHUT_RD {
            return Ok(None);
        }

        // Get connection endpoints from metadata
        let meta = sock.meta_snapshot();
        let (local_ip, local_port, remote_ip, remote_port) = match (
            meta.local_ip.map(Ipv4Addr),
            meta.local_port,
            meta.remote_ip.map(Ipv4Addr),
            meta.remote_port,
        ) {
            (Some(li), Some(lp), Some(ri), Some(rp)) => (li, lp, ri, rp),
            _ => return Err(SocketError::InvalidState),
        };

        // LSM policy check
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(local_ip.0);
        ctx.local_port = local_port;
        ctx.remote = ipv4_to_u64(remote_ip.0);
        ctx.remote_port = remote_port;
        ctx.cap = Some(cap_id);
        hook_net_shutdown(current, &ctx, how).map_err(|_| SocketError::PermissionDenied)?;

        let mut guard = sock.tcp.lock();
        let tcp_state = guard.as_mut().ok_or(SocketError::InvalidState)?;

        // Check if FIN already sent
        if tcp_state.control.fin_sent {
            return Ok(None);
        }

        // Can only send FIN from states that allow sending
        if !tcp_state.control.state.can_send() {
            return Err(SocketError::InvalidState);
        }

        // Build FIN segment
        let seq = tcp_state.control.snd_nxt;
        let ack = tcp_state.control.rcv_nxt;
        // R58: Use scaled window advertisement
        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

        // FIN consumes 1 sequence number
        tcp_state.control.snd_nxt = tcp_state.control.snd_nxt.wrapping_add(1);
        tcp_state.control.fin_sent = true;
        tcp_state.control.fin_sent_time = self.time_wait_now();
        tcp_state.control.fin_retries = 0;

        // State transition
        tcp_state.control.state = match tcp_state.control.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            other => other, // Should not happen due to can_send() check
        };

        let fin_segment = build_tcp_segment(
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            seq,
            ack,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            advertised_wnd,
            &[],
        );

        drop(guard);
        sock.wake_tcp_waiters();

        Ok(Some(fin_segment))
    }

    /// Receive TCP data (blocking with optional timeout).
    ///
    /// Returns data from the receive buffer, blocking if empty.
    ///
    /// # Arguments
    ///
    /// * `sock` - TCP socket (must be in ESTABLISHED state)
    /// * `current` - Current process context
    /// * `cap_id` - Capability used for this operation
    /// * `max_len` - Maximum bytes to return
    /// * `timeout_ns` - Timeout in nanoseconds (None for blocking indefinitely)
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_recv` for LSM policy check
    ///
    /// # Returns
    ///
    /// Vector of received bytes (may be less than max_len).
    pub fn tcp_recv(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        max_len: usize,
        timeout_ns: Option<u64>,
    ) -> Result<Vec<u8>, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }
        if sock.is_closed() {
            return Err(SocketError::Closed);
        }

        loop {
            // Get data waiters for blocking
            let waiters = sock.tcp_data_waiters().ok_or(SocketError::Closed)?;

            // Try to get data from buffer
            {
                let mut guard = sock.tcp.lock();
                let tcp_state = guard.as_mut().ok_or(SocketError::Closed)?;

                // Check connection state for receive capability
                if tcp_state.control.state.is_closed() {
                    return Err(SocketError::Closed);
                }
                if !tcp_state.control.state.can_receive() {
                    return Err(SocketError::InvalidState);
                }

                // Check if we have data in the buffer
                if !tcp_state.control.recv_buffer.is_empty() {
                    let take = core::cmp::min(max_len, tcp_state.control.recv_buffer.len());

                    // R152-14 FIX: Perform LSM check BEFORE draining recv_buffer.
                    // This prevents permanent data loss when LSM denies the recv.
                    drop(guard);
                    let mut ctx = self.ctx_from_socket(sock);
                    ctx.cap = Some(cap_id);
                    hook_net_recv(current, &ctx, take)?;

                    // Re-acquire TCP lock and drain buffer after LSM approval
                    // Codex review: if another reader drained the buffer during LSM check,
                    // actual_take can be 0 — loop again instead of returning spurious EOF.
                    let mut guard = sock.tcp.lock();
                    let tcp_state = guard.as_mut().ok_or(SocketError::Closed)?;
                    let actual_take = core::cmp::min(take, tcp_state.control.recv_buffer.len());
                    if actual_take == 0 {
                        // Buffer was drained by another reader — retry the loop
                        drop(guard);
                        continue;
                    }
                    // R162-9 FIX: Fallible allocation for tcp_recv drain buffer.
                    let mut data = Vec::new();
                    if data.try_reserve_exact(actual_take).is_err() {
                        drop(guard);
                        return Err(SocketError::NoMemory);
                    }
                    for _ in 0..actual_take {
                        if let Some(b) = tcp_state.control.recv_buffer.pop_front() {
                            data.push(b);
                        }
                    }

                    // R158-10 FIX: Retry OOO drain after freeing recv_buffer space.
                    // Without this, contiguous OOO data could sit undelivered until
                    // the next packet arrival, causing unnecessary read stalls.
                    tcp_state.control.ooo_drain_contiguous();

                    // J2-4: the consumer drained recv_buffer (and ooo_drain may have
                    // FIN-cleared OOO) — reconcile the per-ns recv counter DOWN to the
                    // now-smaller true F (returns budget to the tenant as the app reads).
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    // R161-11 FIX: OOO drain in recv path may deliver buffered FIN,
                    // triggering FinWait2→TimeWait. Initialize time_wait_start.
                    if tcp_state.control.state == TcpState::TimeWait
                        && tcp_state.control.time_wait_start == 0
                    {
                        tcp_state.control.time_wait_start = self.time_wait_now();
                    }

                    drop(guard);

                    // Update statistics
                    sock.rx_bytes
                        .fetch_add(data.len() as u64, Ordering::Relaxed);

                    return Ok(data);
                }

                // R145-3 FIX: EOF — FIN received and recv buffer fully drained.
                // Return empty Vec (0 bytes) per POSIX instead of blocking
                // forever or returning InvalidState.
                if tcp_state.control.fin_received {
                    return Ok(Vec::new());
                }
            }

            // No data available, block on wait queue
            match waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => continue,
                WaitOutcome::TimedOut => return Err(SocketError::Timeout),
                WaitOutcome::Closed => return Err(SocketError::Closed),
                WaitOutcome::NoProcess => return Err(SocketError::NoProcess),
            }
        }
    }

    /// Deliver an inbound UDP datagram to a bound socket.
    ///
    /// Called from the network stack's packet processing path.
    ///
    /// # Arguments
    ///
    /// * `dst_port` - Destination port
    /// * `src_ip` - Source IP address
    /// * `src_port` - Source port
    /// * `data` - Datagram payload
    /// * `now_ticks` - Current time in ticks
    ///
    /// # Security
    ///
    /// - R47-3 FIX: Cleans up stale port bindings
    /// - R47-4 FIX: Checks queue capacity before copying to prevent DoS
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Packet delivery is scoped to the caller's network namespace.
    /// Only sockets bound to the same namespace can receive the packet.
    ///
    /// # Returns
    ///
    /// `true` if delivered to a socket, `false` if no listener.
    pub fn deliver_udp(
        &self,
        net_ns_id: NamespaceId,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        data: &[u8],
        now_ticks: u64,
    ) -> bool {
        // R75-1 FIX: Look up bound socket within the specified namespace
        let binding_key = (net_ns_id, dst_port);
        let target = {
            let mut bindings = self.udp_bindings.lock();
            match bindings.get(&binding_key).and_then(|pb| pb.sock.upgrade()) {
                Some(sock) => Some(sock),
                None => {
                    // R47-3 FIX: Clean up stale binding if upgrade failed.
                    // J2-8: this is the UDP RX path (IRQ/softirq-reachable by
                    // contract) and removes under the binding lock — so the
                    // stored charge is ENQUEUED for deferred uncharge, never
                    // uncharged inline (L5 under L8 / in IRQ is forbidden). No
                    // expect_ptr: the entry is already known dead.
                    if let Some(cgid) =
                        Self::remove_binding_charged(&mut bindings, binding_key, None)
                    {
                        self.enqueue_port_uncharge(cgid, 1);
                    }
                    None
                }
            }
        };

        let Some(sock) = target else {
            return false;
        };

        // R48-3 FIX: Invoke LSM policy check BEFORE allocating/copying
        // attacker-controlled payload. This prevents unauthorized peers from
        // filling MAX_RX_QUEUE of MAC-protected sockets, causing legitimate
        // traffic to be dropped despite policy denial at recv_from_udp time.
        //
        // We use the socket creator's context for the policy decision, since
        // this is packet delivery (not a specific syscall caller context).
        {
            let mut ctx = self.ctx_from_socket(&sock);
            ctx.remote = ipv4_to_u64(src_ip.0);
            ctx.remote_port = src_port;
            // Note: No CapId available in delivery path (not a syscall)

            if hook_net_recv(&sock.label.creator, &ctx, data.len()).is_err() {
                // LSM policy denied - drop packet without consuming queue space
                sock.rx_dropped.fetch_add(1, Ordering::Relaxed);
                return true; // Socket exists but policy denied
            }
        }

        // R133-2 FIX: Removed pre-allocation of data.to_vec() before cap checks.
        // enqueue_rx now performs queue depth and global byte cap checks BEFORE
        // allocating/copying the attacker-controlled payload.
        // Regardless of the enqueue outcome, a bound socket exists so report
        // "listener found".
        let _ = sock.enqueue_rx(src_ip, src_port, data, now_ticks);
        true
    }

    /// Close a socket, initiating TCP graceful shutdown if needed.
    ///
    /// Called when the capability is revoked or file descriptor is closed.
    ///
    /// # TCP Graceful Shutdown
    ///
    /// For TCP sockets in ESTABLISHED or CLOSE_WAIT state, this function:
    /// 1. Sends a FIN segment to initiate graceful shutdown
    /// 2. Transitions state to FIN_WAIT_1 or LAST_ACK
    /// 3. Keeps the socket registered for FIN retransmission and TIME_WAIT handling
    ///
    /// The sweep_time_wait function will clean up the socket after:
    /// - TIME_WAIT expires (120 seconds per RFC 793)
    /// - FIN retransmission limit exceeded (peer unresponsive)
    ///
    /// For UDP sockets or TCP sockets already closing, immediate cleanup occurs.
    pub fn close(&self, socket_id: u64) {
        // Fetch the socket without removing it; TCP may need graceful FIN shutdown.
        let sock = {
            let sockets = self.sockets.read();
            sockets.get(&socket_id).cloned()
        };

        let Some(sock) = sock else {
            return;
        };

        let mut keep_registered = false;
        let mut fin_to_send: Option<(Ipv4Addr, Vec<u8>, u64)> = None;

        // TCP sockets may need to send FIN and stay registered for TIME_WAIT/ACK handling.
        if sock.proto == SocketProtocol::Tcp {
            let meta = sock.meta_snapshot();
            if let (Some(local_ip), Some(local_port), Some(remote_ip), Some(remote_port)) = (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    match tcp_state.control.state {
                        TcpState::Established => {
                            keep_registered = true;

                            if !tcp_state.control.fin_sent {
                                let seq = tcp_state.control.snd_nxt;
                                let ack = tcp_state.control.rcv_nxt;
                                // R58: Use scaled window
                                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                                // FIN consumes one sequence number
                                tcp_state.control.snd_nxt =
                                    tcp_state.control.snd_nxt.wrapping_add(1);
                                tcp_state.control.fin_sent = true;
                                tcp_state.control.fin_sent_time = self.time_wait_now();
                                tcp_state.control.fin_retries = 0;
                                tcp_state.control.state = TcpState::FinWait1;

                                let fin_segment = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    advertised_wnd,
                                    &[],
                                );
                                fin_to_send = Some((remote_ip, fin_segment, sock.net_ns_id.0));
                            }
                        }
                        TcpState::CloseWait => {
                            keep_registered = true;

                            if !tcp_state.control.fin_sent {
                                let seq = tcp_state.control.snd_nxt;
                                let ack = tcp_state.control.rcv_nxt;
                                // R58: Use scaled window
                                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                                tcp_state.control.snd_nxt =
                                    tcp_state.control.snd_nxt.wrapping_add(1);
                                tcp_state.control.fin_sent = true;
                                tcp_state.control.fin_sent_time = self.time_wait_now();
                                tcp_state.control.fin_retries = 0;
                                tcp_state.control.state = TcpState::LastAck;

                                let fin_segment = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    advertised_wnd,
                                    &[],
                                );
                                fin_to_send = Some((remote_ip, fin_segment, sock.net_ns_id.0));
                            }
                        }
                        TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::Closing
                        | TcpState::LastAck
                        | TcpState::TimeWait => {
                            // Already in closing states; leave registered for sweep_time_wait.
                            keep_registered = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        if keep_registered {
            // Mark closed but leave in the tables so FIN/ACK/TIME_WAIT can complete.
            // The sweep_time_wait timer will clean up after TIME_WAIT expires or
            // FIN retransmission gives up.
            sock.mark_closed();
            sock.wake_tcp_waiters();
            self.closed_count.fetch_add(1, Ordering::Relaxed);

            // R169-6 slice 2 BACKSTOP (Codex convergence round-1 UNSAFE fix):
            // an RX-side cleanup_tcp_connection can race this close() — it read
            // is_closed()==false (so it PURE-SKIPPED a charged Explicit binding)
            // and its FINAL is_closed() gate also missed our mark_closed().
            // Without this backstop the socket would linger in `sockets`
            // forever: its TCB is already None so sweep_time_wait never
            // revisits it, and the map's strong Arc keeps the binding's Weak
            // alive, so the dead-Weak triad never reclaims the held charge
            // (pre-existing socket/ns-count linger, now also a permanent
            // ports.max strand for a charged Explicit bind).
            //
            // ORDERING PROOF that exactly one side always finishes the
            // teardown: we mark_closed() (A1) THEN re-check the TCB (A2);
            // cleanup nulls the TCB (B1) THEN reads is_closed() (B2).
            // - B1 < A2: we observe TCB == None here and run the terminal
            //   teardown below.
            // - A2 < B1: then A1 < A2 < B1 < B2, so B2 observes mark_closed and
            //   cleanup removes the socket itself (its now-dead Weak is swept).
            // Overlap may fire BOTH; every step below is exactly-once gated
            // (sockets-map remove is_some / BTreeMap single arbiter / ptr-eq).
            let tcb_gone = sock.tcp.lock().is_none();
            if tcb_gone {
                if self.sockets.write().remove(&socket_id).is_some() {
                    self.dec_ns_count(sock.net_ns_id);
                }
                let meta = sock.meta_snapshot();
                if let Some(port) = meta.local_port {
                    let binding_key = (sock.net_ns_id, port);
                    // Terminal teardown: KIND-AGNOSTIC ptr-eq-gated remove
                    // (hold-until-close ends at close). Block-scoped so the L8
                    // guard drops before the L5 uncharge; STORED cgid only —
                    // close() may run under the Process lock (exec/cloexec).
                    let port_cgid = {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::remove_binding_charged(
                            &mut bindings,
                            binding_key,
                            Some(Arc::as_ptr(&sock)),
                        )
                    };
                    if let Some(c) = port_cgid {
                        uncharge_port_cgroup(c, 1);
                    }
                }
            }
        } else if let Some(sock) = self.remove_socket(socket_id) {
            // DEADLOCK FIX (found in J2-6 convergence audit, PE-06): the removal now
            // goes through remove_socket() so the `sockets` write guard is dropped
            // BEFORE this body. In edition 2021 a temporary in an `if let` scrutinee
            // lives to the end of the block, so the prior inline
            // `self.sockets.write().remove(..)` held the write lock across the child
            // cleanup loop below — and cleanup_tcp_connection() re-acquires
            // `sockets.write()` (R129-2), self-deadlocking on listener close with
            // queued children. This makes the R52-2 "cleanup after releasing locks"
            // intent actually hold.
            // R52-2 FIX: Clean up pending SYN/accept queues for listening sockets
            //
            // When a listening socket is closed, we must tear down all pending
            // connections to prevent resource leaks. This includes:
            // - Half-open connections in the SYN queue (awaiting final ACK)
            // - Fully established connections in the accept queue (awaiting accept())
            //
            // DEADLOCK FIX (Codex review): Collect children first while holding
            // listen lock, then release it before calling cleanup_tcp_connection,
            // which may acquire sockets.write() lock internally.
            let mut children_to_cleanup: Vec<Arc<SocketState>> = Vec::new();
            // J2-2: count the half-open SYNs drained below; the per-namespace
            // half-open uncharge is deferred to the proven dec_ns_count safe
            // context (all drained SYNs share this listener's namespace).
            let mut drained_syn_count: u64 = 0;
            if sock.is_listening() {
                let mut listen_guard = sock.listen.lock();
                if let Some(mut listen_state) = listen_guard.take() {
                    // Collect half-open SYN queue children
                    let syn_keys: Vec<TcpLookupKey> =
                        listen_state.syn_queue.keys().cloned().collect();
                    for key in syn_keys {
                        if let Some(pending) = listen_state.syn_queue.remove(&key) {
                            pending.sock.mark_closed();
                            children_to_cleanup.push(pending.sock);

                            // R74-5 FIX: Decrement half-open counter when cleaning up SYN queue
                            dec_half_open();
                            // J2-2: account the per-namespace half-open drain (deferred).
                            drained_syn_count += 1;
                        }
                    }
                    // Collect established-but-not-accepted queue children.
                    // R121-3 FIX (Codex review): Do NOT decrement the active connection
                    // counter here. These children will be processed by
                    // cleanup_tcp_connection() below, which decrements iff
                    // counted_in_active is true. Decrementing here as well would
                    // cause a double-decrement for accept-queue sockets.
                    while let Some(child) = listen_state.accept_queue.pop_front() {
                        child.mark_closed();
                        children_to_cleanup.push(child);
                    }
                    // Wake any blocked accept() to return ECONNABORTED
                    listen_state.accept_waiters.close();
                    listen_state.accept_waiters.wake_all();
                }
                // listen_guard is dropped here, releasing the listen lock
            }

            let meta = sock.meta_snapshot();

            // R75-1 FIX: Remove port bindings using namespace-scoped keys.
            // J2-8: route through remove_binding_charged — ptr-eq gated, so a
            // child socket carrying the listener's port (passive open) can NEVER
            // unbind/uncharge the listener's binding — and refund the STORED port
            // charge. Block-scoped so the L8 binding guard drops BEFORE the L5
            // uncharge (Rust-2021 temporary-lifetime trap). Read the STORED cgid,
            // never current_cgroup_id(): close() also runs UNDER the Process lock
            // on exec/cloexec teardown, where re-locking PROCESS_TABLE would
            // self-deadlock. DOMINANT teardown for UDP + non-ESTABLISHED TCP.
            if let Some(port) = meta.local_port {
                let binding_key = (sock.net_ns_id, port);
                let sock_ptr = Some(Arc::as_ptr(&sock));
                let port_cgid = match sock.proto {
                    SocketProtocol::Udp => {
                        let mut bindings = self.udp_bindings.lock();
                        Self::remove_binding_charged(&mut bindings, binding_key, sock_ptr)
                    }
                    SocketProtocol::Tcp => {
                        let mut bindings = self.tcp_bindings.lock();
                        Self::remove_binding_charged(&mut bindings, binding_key, sock_ptr)
                    }
                };
                if let Some(c) = port_cgid {
                    uncharge_port_cgroup(c, 1);
                }
            }

            // Remove TCP connection from 4-tuple map
            if sock.proto == SocketProtocol::Tcp {
                if let (Some(lip), Some(lport), Some(rip), Some(rport)) = (
                    meta.local_ip,
                    meta.local_port,
                    meta.remote_ip,
                    meta.remote_port,
                ) {
                    let key = tcp_map_key_from_parts(sock.net_ns_id, Ipv4Addr(lip), lport, Ipv4Addr(rip), rport);
                    if self.tcp_conns.lock().remove(&key).is_some() {
                        // J2-1: uncharge the per-namespace connection (bound to
                        // tcp_conns membership, independent of counted_in_active).
                        self.dec_ns_conn(key.0);
                        // R121-3 FIX (Codex review): Only decrement if this socket
                        // was counted via try_inc_active_conn() in queue_accept().
                        // Client-initiated connections (sys_connect) are never
                        // counted, so decrementing them would drift the counter low.
                        if sock.counted_in_active.load(Ordering::Acquire) {
                            dec_active_conn();
                        }
                    }
                }
            }

            // Mark closed and wake waiters
            sock.mark_closed();
            self.closed_count.fetch_add(1, Ordering::Relaxed);

            // R52-2 FIX: Cleanup children AFTER releasing all locks above
            // This prevents deadlock with cleanup_tcp_connection() which may
            // acquire sockets.write() lock.
            for child in children_to_cleanup {
                self.cleanup_tcp_connection(&child);
            }

            // R76-3 FIX: Decrement per-namespace socket count AFTER releasing sockets lock
            // to avoid deadlock (Codex review fix: lock ordering with per_ns_counts)
            self.dec_ns_count(sock.net_ns_id);
            // J2-2: uncharge the per-namespace half-open SYNs drained above, in the
            // SAME safe context as dec_ns_count (mirrors that proven lock ordering).
            self.dec_ns_syn_by(sock.net_ns_id, drained_syn_count);
        }

        // Transmit FIN after releasing locks to avoid blocking critical sections.
        if let Some((dst_ip, segment, ns_id)) = fin_to_send {
            let _ = transmit_tcp_segment(dst_ip, &segment, ns_id);
        }
    }

    /// Get a socket by ID.
    pub fn get(&self, socket_id: u64) -> Option<Arc<SocketState>> {
        self.sockets.read().get(&socket_id).cloned()
    }

    /// Get table statistics.
    pub fn stats(&self) -> TableStats {
        TableStats {
            created: self.created.load(Ordering::Relaxed),
            closed: self.closed_count.load(Ordering::Relaxed),
            active: self.sockets.read().len(),
            bound_ports: self.udp_bindings.lock().len(),
            timer_sweeps_skipped: self.timer_sweeps_skipped.load(Ordering::Relaxed),
            forced_tw_evictions: self.forced_tw_evictions.load(Ordering::Relaxed),
        }
    }

    /// R59-2 FIX: Fallback seed when CSPRNG is unavailable.
    ///
    /// Uses RDTSC mixed with monotonic counter via multiply-rotate-xor.
    /// Not cryptographically secure but unpredictable enough to prevent
    /// trivial port guessing when hardware RNG is unavailable.
    #[inline]
    fn fallback_port_seed(&self) -> u16 {
        let tsc = rdtsc();
        let counter = self.next_ephemeral.fetch_add(1, Ordering::Relaxed) as u64;

        // SipHash-like mixing for unpredictable output
        let mut v0 = tsc.wrapping_add(counter);
        let mut v1 = (tsc ^ counter).rotate_left(17);

        v0 = v0.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        v1 ^= v0.rotate_left(23);
        v1 = v1.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        v0 ^= v1.rotate_left(41);

        let mixed = v0 ^ v1;
        (mixed ^ (mixed >> 32)) as u16
    }

    /// Allocate an ephemeral port.
    ///
    /// R59-1 FIX: Use CSPRNG for port randomization to prevent off-path attacks.
    /// Attackers who can predict ephemeral ports can more easily hijack connections.
    ///
    /// Algorithm:
    /// 1. Try random ports from CSPRNG (2x range attempts for good coverage)
    /// 2. Fall back to deterministic sweep if CSPRNG fails or all random ports taken
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port availability is checked within the given namespace. Different namespaces
    /// can independently use the same ephemeral port without conflict.
    fn alloc_ephemeral_port(&self, net_ns_id: NamespaceId) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let mut bindings = self.udp_bindings.lock();
        // J2-8: prune this namespace's dead-Weak bindings (enqueuing their charges)
        // so a stale entry never makes a port look in-use below, and the leaked
        // charge is reclaimed.
        self.reap_dead_bindings(&mut bindings, net_ns_id);

        // Phase 1: Random selection using CSPRNG (preferred)
        // Try 2x range to give good coverage while limiting iterations
        for _ in 0..(range.saturating_mul(2)) {
            // Try CSPRNG first, fall back to RDTSC-based hash if RNG unavailable
            // R149-5 FIX: Use fill_random (FIPS boundary pub API).
            let seed = {
                let mut buf = [0u8; 4];
                if security::fill_random(&mut buf).is_ok() {
                    u32::from_le_bytes(buf) as u16
                } else {
                    self.fallback_port_seed()
                }
            };
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            // R75-1 FIX: Check namespace-scoped port binding
            if !bindings.contains_key(&(net_ns_id, candidate)) {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback (guarantees finding free port if one exists)
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            // R75-1 FIX: Check namespace-scoped port binding
            if !bindings.contains_key(&(net_ns_id, candidate)) {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Allocate an ephemeral port for TCP (ensures no existing TCP socket uses it).
    ///
    /// R59-1 FIX: Use CSPRNG for port randomization to prevent off-path attacks.
    /// Predictable ephemeral ports enable connection hijacking and blind injection.
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// Port availability is checked within the given namespace. Different namespaces
    /// can independently use the same ephemeral port without conflict.
    fn alloc_ephemeral_tcp_port(&self, net_ns_id: NamespaceId) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let mut tcp_bindings = self.tcp_bindings.lock();
        // J2-8: prune dead-Weak bindings (enqueue their charges) so a stale entry
        // is not counted as in-use. Done while only tcp_bindings is held, so the
        // pending leaf is never taken under tcp_conns.
        self.reap_dead_bindings(&mut tcp_bindings, net_ns_id);
        let mut tcp_conns = self.tcp_conns.lock();
        // J2-8 (Codex review): a stale `tcp_conns` Weak ALSO makes a port look
        // in-use via the `keys().any(...)` scan below, so prune those too —
        // completing the dead-Weak port-availability fix for TCP (J2-1's
        // per-namespace conn count is uncharged here as a side effect).
        self.conns_retain_accounted(&mut tcp_conns);

        // Phase 1: Random selection using CSPRNG (preferred)
        for _ in 0..(range.saturating_mul(2)) {
            // R59-2 FIX: Use RDTSC-based fallback instead of predictable counter
            // R149-5 FIX: Use fill_random (FIPS boundary pub API).
            let seed = {
                let mut buf = [0u8; 4];
                if security::fill_random(&mut buf).is_ok() {
                    u32::from_le_bytes(buf) as u16
                } else {
                    self.fallback_port_seed()
                }
            };
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            // R75-1 FIX: Check namespace-scoped TCP port binding
            if tcp_bindings.contains_key(&(net_ns_id, candidate)) {
                continue;
            }
            // R106-10 FIX: Check if any connection uses this port within this namespace
            let in_use = tcp_conns
                .keys()
                .any(|(ns_id, _, port, _, _)| *ns_id == net_ns_id && *port == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            // R75-1 FIX: Check namespace-scoped TCP port binding
            if tcp_bindings.contains_key(&(net_ns_id, candidate)) {
                continue;
            }
            let in_use = tcp_conns
                .keys()
                .any(|(ns_id, _, port, _, _)| *ns_id == net_ns_id && *port == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Build LSM NetCtx from socket state.
    ///
    /// # R51-1: Made public for sys_accept to build context for LSM hook.
    pub fn ctx_from_socket(&self, sock: &SocketState) -> NetCtx {
        let meta = sock.meta_snapshot();
        // Use correct protocol based on socket type
        let proto = match sock.proto {
            SocketProtocol::Udp => UDP_PROTO as u16,
            SocketProtocol::Tcp => TCP_PROTO as u16,
        };
        let mut ctx = NetCtx::new(sock.id, proto);

        if let Some(ip) = meta.local_ip {
            ctx.local = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.local_port {
            ctx.local_port = port;
        }
        if let Some(ip) = meta.remote_ip {
            ctx.remote = ipv4_to_u64(ip);
        }
        if let Some(port) = meta.remote_port {
            ctx.remote_port = port;
        }
        ctx.cap = Some(CapId::INVALID);

        ctx
    }

    // ========================================================================
    // TCP RX Path (Phase 2)
    // ========================================================================

    /// R106-10 FIX: Look up a TCP connection by namespace + 4-tuple, removing stale entries.
    ///
    /// # Arguments
    /// * `net_ns_id` - Network namespace for scoped lookup
    /// * `local_ip` - Our IP (destination in incoming packet)
    /// * `local_port` - Our port (destination port in incoming packet)
    /// * `remote_ip` - Peer IP (source in incoming packet)
    /// * `remote_port` - Peer port (source port in incoming packet)
    pub fn lookup_tcp_conn(
        &self,
        net_ns_id: NamespaceId,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Arc<SocketState>> {
        let key = tcp_map_key_from_parts(net_ns_id, local_ip, local_port, remote_ip, remote_port);
        let mut conns = self.tcp_conns.lock();
        match conns.get(&key).and_then(|w| w.upgrade()) {
            Some(sock) => Some(sock),
            None => {
                // Clean up stale weak reference.
                // J2-1: uncharge the per-namespace connection on lazy stale-Weak removal.
                if conns.remove(&key).is_some() {
                    self.dec_ns_conn(key.0);
                }
                None
            }
        }
    }

    /// P0-2 FIX: Attempt to reclaim one TCP connection slot by evicting the
    /// oldest TIME_WAIT entry from `tcp_conns`.
    ///
    /// Called exclusively from the SYN cookie ACK validation path when the
    /// global connection limit is reached.  Under sustained overload the
    /// normal periodic `sweep_time_wait` may not have run yet, so we do a
    /// targeted eviction of the single oldest TIME_WAIT socket.
    ///
    /// # Lock ordering
    ///
    /// `tcp_conns` is locked briefly to collect candidate sockets, then
    /// released before calling `cleanup_tcp_connection` (which re-locks
    /// `tcp_conns` internally).  `sock.tcp` is acquired via `try_lock()` to
    /// avoid deadlock if another core is already processing that socket.
    ///
    /// # Returns
    ///
    /// `true` if `tcp_conns.len()` is below `TCP_MAX_ACTIVE_CONNECTIONS`
    /// after cleanup/eviction (i.e. the caller may proceed to create a
    /// connection).
    fn try_evict_time_wait_for_cookie(&self, now_ms: u64) -> bool {
        // Phase 1: collect live socket Arcs while holding tcp_conns briefly.
        let candidates: Vec<Arc<SocketState>> = {
            let mut conns = self.tcp_conns.lock();
            self.conns_retain_accounted(&mut conns);
            if conns.len() < TCP_MAX_ACTIVE_CONNECTIONS {
                return true; // stale-Weak pruning alone freed capacity
            }
            conns.values().filter_map(|w| w.upgrade()).collect()
        };

        // Phase 2: scan for the oldest closed TIME_WAIT socket.
        // Only consider sockets that are both in TIME_WAIT state AND already
        // marked closed (user-space FD released).  try_lock avoids deadlock
        // if another core is mid-operation on a socket.
        let mut oldest_start: u64 = u64::MAX;
        let mut victim: Option<Arc<SocketState>> = None;

        for sock in &candidates {
            if !sock.is_closed() {
                continue; // still has user-space reference
            }
            let guard = match sock.tcp.try_lock() {
                Some(g) => g,
                None => continue,
            };
            let tcp_state = match guard.as_ref() {
                Some(s) => s,
                None => continue,
            };
            if tcp_state.control.state != TcpState::TimeWait {
                continue;
            }
            // time_wait_start == 0 means just entered — treat as "now".
            let start = if tcp_state.control.time_wait_start == 0 {
                now_ms
            } else {
                tcp_state.control.time_wait_start
            };
            if start < oldest_start {
                oldest_start = start;
                victim = Some(sock.clone());
            }
        }
        // Drop candidate list before cleanup (releases Arc refs).
        drop(candidates);

        let victim = match victim {
            Some(v) => v,
            None => return false, // no eligible TIME_WAIT entries to evict
        };
        if let Some(mut guard) = victim.tcp.try_lock() {
            if let Some(tcp_state) = guard.as_mut() {
                if tcp_state.control.state == TcpState::TimeWait {
                    tcp_state.control.state = TcpState::Closed;
                }
            }
        }
        // cleanup_tcp_connection: removes from tcp_conns + dec_active_conn.
        // R129-2: If the victim was mark_closed(), cleanup_tcp_connection now also
        // removes from sockets map and calls dec_ns_count. The is_some() guard below
        // ensures we only decrement if cleanup_tcp_connection didn't already do it.
        self.cleanup_tcp_connection(&victim);
        // Remove from sockets map + decrement namespace quota (fallback for
        // victims not yet mark_closed when cleanup_tcp_connection ran).
        if self.sockets.write().remove(&victim.id).is_some() {
            self.dec_ns_count(victim.net_ns_id);
        }
        self.forced_tw_evictions.fetch_add(1, Ordering::Relaxed);

        // Phase 4: re-check capacity.
        let mut conns = self.tcp_conns.lock();
        self.conns_retain_accounted(&mut conns);
        conns.len() < TCP_MAX_ACTIVE_CONNECTIONS
    }

    /// Process an inbound TCP segment for handshake completion.
    ///
    /// This implements Phase 2 of the TCP state machine:
    /// - SYN_SENT + SYN-ACK → ESTABLISHED (send ACK)
    /// - Unknown connection → RST
    ///
    /// # Arguments
    /// * `src_ip` - Source IP (remote peer)
    /// * `dst_ip` - Destination IP (our IP)
    /// * `header` - Parsed TCP header
    /// * `payload` - TCP payload (after header)
    /// * `options` - Parsed TCP options (for window scaling, etc.)
    ///
    /// # R75-1 FIX: Network Namespace Isolation
    ///
    /// TCP segment processing is scoped to the specified network namespace.
    /// Listener lookup and connection matching respect namespace boundaries.
    ///
    /// # Returns
    /// TCP segment to transmit (ACK or RST) if a response is required.
    pub fn process_tcp_segment(
        &self,
        net_ns_id: NamespaceId,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
        options: &TcpOptions,
    ) -> Option<Vec<u8>> {
        // R160-9 FIX: Reject invalid TCP flag combinations per RFC 793 §3.4.
        // SYN+RST is always invalid (connection-setup contradicts abort).
        // SYN+FIN is suspicious and rejected by modern stacks. These malformed
        // segments are typically from port scanners or exploit attempts.
        let flags = header.flags;
        if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_RST != 0 {
            return None;
        }
        if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_FIN != 0 {
            return None;
        }

        // RFC 793/5961: Handle RST segments with sequence validation
        if header.flags & TCP_FLAG_RST != 0 {
            // If we have a connection, validate RST before accepting
            if let Some(sock) =
                self.lookup_tcp_conn(net_ns_id, dst_ip, header.dst_port, src_ip, header.src_port)
            {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    let old_state = tcp_state.control.state;

                    // R151-7 FIX: Validate RST per RFC 5961 Section 3.2.
                    // In synchronized states, accept RST ONLY if SEG.SEQ == RCV.NXT (exact match).
                    // In-window but non-exact RSTs trigger a rate-limited challenge ACK.
                    // Out-of-window RSTs are silently dropped.
                    let (accept_rst, send_challenge) = match old_state {
                        TcpState::SynSent => {
                            // R152-6 FIX: In SYN_SENT, require ACK flag on RST per RFC 793 §3.4.
                            // Never send challenge ACK — RFC 5961 challenge ACKs are for
                            // synchronized states only. Bare RST (no ACK) is silently dropped.
                            let has_ack = header.flags & TCP_FLAG_ACK != 0;
                            (has_ack && header.ack_num == tcp_state.control.snd_nxt, false)
                        }
                        // R146-NET-3 FIX: Accept RST in SynReceived so
                        // half-open connections can be aborted and SYN queue
                        // slots freed. Per RFC 793 Section 3.4, a valid RST
                        // in SYN_RECEIVED returns the connection to CLOSED.
                        TcpState::SynReceived
                        | TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::CloseWait
                        | TcpState::Closing
                        | TcpState::LastAck => {
                            // R151-7 FIX: RFC 5961 strict RST validation.
                            // Only exact seq match accepts RST; in-window triggers challenge ACK.
                            let wnd = tcp_state.control.rcv_wnd.max(1);
                            if header.seq_num == tcp_state.control.rcv_nxt {
                                (true, false)
                            } else if seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, wnd) {
                                (false, true)
                            } else {
                                (false, false)
                            }
                        }
                        _ => (false, false), // Silently drop RST in other states
                    };

                    if !accept_rst {
                        // R151-7 FIX: Out-of-window RSTs are silently dropped (no challenge ACK).
                        if !send_challenge {
                            drop(guard);
                            return None;
                        }
                        // R54-2 FIX: Rate limit challenge ACKs to prevent amplification attacks
                        // An attacker could send spoofed RST packets at high rate to exhaust
                        // CPU and bandwidth via unlimited challenge ACK responses.
                        if !allow_challenge_ack(self.time_wait_now()) {
                            drop(guard);
                            return None;
                        }

                        // R50-4 IMPROVEMENT: Send challenge ACK per RFC 5961 Section 3.2
                        // This allows legitimate endpoints to prove their connection state
                        // while preventing blind RST injection attacks
                        // R58: Use scaled window advertisement
                        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                        let challenge_ack = build_tcp_segment(
                            dst_ip,                    // Our IP
                            src_ip,                    // Peer IP
                            header.dst_port,           // Our port
                            header.src_port,           // Peer port
                            tcp_state.control.snd_nxt, // Our next seq
                            tcp_state.control.rcv_nxt, // Expected peer seq
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        drop(guard);
                        return Some(challenge_ack);
                    }

                    // R130-4 FIX: Extend RST cleanup to all synchronized states.
                    // RFC 793 §3.4 requires a valid RST in any synchronized state
                    // to immediately close the connection. Previously only SynSent
                    // and Established triggered cleanup; closing-state RSTs were
                    // silently ignored, leaving sockets until timer sweep.
                    if matches!(
                        old_state,
                        TcpState::SynSent
                            | TcpState::SynReceived
                            | TcpState::Established
                            | TcpState::FinWait1
                            | TcpState::FinWait2
                            | TcpState::CloseWait
                            | TcpState::Closing
                            | TcpState::LastAck
                    ) {
                        tcp_state.control.state = TcpState::Closed;
                        drop(guard);

                        // R164-5 FIX: When RST aborts a SynReceived connection,
                        // remove the PendingSyn entry from the listener's SYN
                        // queue and decrement GLOBAL_HALF_OPEN_COUNT. Without
                        // this, the slot leaks until SYN timeout (30s), allowing
                        // an attacker to exhaust the half-open limit.
                        if old_state == TcpState::SynReceived {
                            if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                                let mut listen_guard = listener.listen.lock();
                                if let Some(listen_state) = listen_guard.as_mut() {
                                    let syn_key = tcp_map_key_from_parts(
                                        net_ns_id, dst_ip, header.dst_port,
                                        src_ip, header.src_port,
                                    );
                                    listen_state.take_syn(&syn_key, self);
                                }
                            }
                        }

                        self.cleanup_tcp_connection(&sock);
                        sock.wake_tcp_waiters();
                    }
                }
            }
            return None;
        }

        // Look up existing connection by namespace + 4-tuple
        let sock = match self.lookup_tcp_conn(net_ns_id, dst_ip, header.dst_port, src_ip, header.src_port) {
            Some(s) => s,
            None => {
                // R51-1: Passive open handling for inbound SYN
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                // Pure SYN (without ACK) indicates new connection request
                if is_syn && !is_ack {
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let mut listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_mut() {
                            let syn_key = tcp_map_key_from_parts(
                                listener.net_ns_id,
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                            );

                            // Handle retransmitted SYN: resend cached SYN-ACK
                            if let Some(existing) = listen_state.get_syn(&syn_key) {
                                return Some(existing.syn_ack.clone());
                            }

                            // Get current timestamp for SYN cookie timing
                            let now_ms = self.time_wait_now();

                            // Select MSS for SYN cookie (used in both paths)
                            let (mss_index, cookie_mss) = syn_cookie_select_mss(options.mss);

                            // R106-2 FIX: Determine if we should fall back to SYN cookies.
                            // When the global connection limit is reached, use stateless
                            // SYN-ACK instead of silently dropping.  This ensures legitimate
                            // clients can still complete handshakes once connection slots
                            // free up, while attackers gain no DoS advantage.
                            let mut force_syn_cookie = false;
                            {
                                let mut conns = self.tcp_conns.lock();
                                self.conns_retain_accounted(&mut conns);
                                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                    // R106-2 FIX: Global active connection limit reached —
                                    // fall back to SYN cookies instead of dropping the SYN.
                                    force_syn_cookie = true;
                                }
                                // Check if 4-tuple already exists (race condition guard)
                                if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                    return None;
                                }
                            }

                            // R106-2 FIX: SYN Cookie Path — use stateless SYN-ACK when:
                            // 1. Per-listener SYN backlog is full (original condition), OR
                            // 2. Global active connection limit is reached (new condition)
                            // SYN cookies require zero per-connection state, providing
                            // graceful degradation instead of silent SYN drops.
                            if force_syn_cookie
                                || listen_state.syn_queue.len() >= listen_state.syn_backlog
                            {
                                // R137-2 FIX: Rate limit stateless SYN-cookie SYN-ACK
                                // generation to reduce spoofed-source reflection.
                                if !allow_syn_cookie_ack(now_ms) {
                                    return None;
                                }

                                // Generate SYN cookie ISN (encodes 4-tuple, time, MSS)
                                SYN_COOKIES_GENERATED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX
                                let cookie_iss = generate_syn_cookie_isn(
                                    now_ms,
                                    dst_ip,
                                    header.dst_port,
                                    src_ip,
                                    header.src_port,
                                    mss_index,
                                );

                                // Build SYN-ACK with cookie ISN and MSS option
                                // Note: Window scaling is NOT preserved in SYN cookies
                                let syn_ack_options = [TcpOptionKind::Mss(cookie_mss)];
                                let syn_ack = build_tcp_segment_with_options(
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    cookie_iss,
                                    header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                                    TCP_DEFAULT_WINDOW, // Unscaled window
                                    &syn_ack_options,
                                    &[],
                                );

                                // No state allocated - SYN cookie is stateless
                                // R107-3 FIX: Seed synthetic conntrack state so the
                                // returning ACK is not classified as invalid mid-stream.
                                // Step 1: Register the incoming SYN (creates SynSent entry)
                                // Step 2: Register the outgoing SYN-ACK (advances to SynRecv)
                                #[cfg(feature = "conntrack")]
                                {
                                    use crate::conntrack::ct_process_tcp;
                                    let _ = ct_process_tcp(
                                        listener.net_ns_id.0,
                                        src_ip,
                                        dst_ip,
                                        header.src_port,
                                        header.dst_port,
                                        header.flags,
                                        payload.len(),
                                        now_ms,
                                    );
                                    let _ = ct_process_tcp(
                                        listener.net_ns_id.0,
                                        dst_ip,
                                        src_ip,
                                        header.dst_port,
                                        header.src_port,
                                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                                        0,
                                        now_ms,
                                    );
                                }
                                return Some(syn_ack);
                            }

                            // R77-4 FIX: Enforce per-namespace socket quota before creating child socket.
                            // Without this check, TCP listeners could create unlimited child sockets
                            // bypassing the MAX_SOCKETS_PER_NS quota, leading to DoS via connection
                            // floods and potential count underflow when sockets are later closed.
                            if let Err(_) = self.try_inc_ns_count(listener.net_ns_id) {
                                // Quota exceeded: silently drop SYN like backlog-full scenario.
                                // This prevents attackers from exhausting socket resources via
                                // connection floods while appearing as normal packet loss.
                                return None;
                            }

                            // Create child socket inheriting listener properties
                            // R75-1 FIX: Child socket inherits parent listener's network namespace
                            // R107-5 FIX: Overflow-safe socket ID allocation
                            let child_id = match self.next_socket_id.fetch_update(
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                                |current| current.checked_add(1),
                            ) {
                                Ok(prev) => prev,
                                Err(_) => {
                                    self.dec_ns_count(listener.net_ns_id); // Rollback quota
                                    return None; // ID space exhausted, drop like backlog-full
                                }
                            };
                            let child = Arc::new(SocketState::new(
                                child_id,
                                listener.domain,
                                listener.ty,
                                listener.proto,
                                listener.label,
                                listener.net_ns_id,
                            ));

                            // Register in socket table
                            self.sockets.write().insert(child_id, child.clone());
                            self.created.fetch_add(1, Ordering::Relaxed);

                            // Set local and remote addresses
                            child.bind_local(dst_ip, header.dst_port);
                            child.set_remote(src_ip, header.src_port);

                            // Generate server ISN using the secure ISN generator
                            let iss =
                                generate_isn(dst_ip, header.dst_port, src_ip, header.src_port);

                            // Create server-side TCB in SynReceived state
                            let mut tcb = TcpControlBlock::new_server(
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                                iss,
                                header.seq_num,
                            );

                            // Set MSS from negotiated value
                            tcb.snd_mss = cookie_mss;
                            tcb.rcv_mss = cookie_mss;
                            tcb.cwnd = initial_cwnd(cookie_mss);

                            // R58: RFC 7323 Window Scaling - process WSopt from incoming SYN
                            // If client sent WSopt, we should respond with our own WSopt
                            if let Some(peer_scale) = options.window_scale {
                                tcb.snd_wscale = peer_scale.min(TCP_MAX_WINDOW_SCALE);
                                tcb.wscale_received = true;
                                // Calculate our scale factor for outgoing window advertisements
                                tcb.rcv_wscale = calc_wscale(tcb.rcv_wnd);
                                tcb.wscale_requested = true;
                            }

                            // RFC 2018: SACK negotiation — record peer's SACK-Permitted
                            // and advertise our own capability in the SYN-ACK.
                            if options.sack_permitted {
                                tcb.sack_received = true;
                            }
                            tcb.sack_requested = true;

                            child.attach_tcp(tcb);

                            // R58: Calculate window for SYN-ACK (unscaled per RFC 7323)
                            // RFC 7323 Section 2.2: The window field in SYN and SYN-ACK
                            // segments is never scaled; scaling takes effect only after
                            // the SYN exchange is complete.
                            let syn_ack_wnd = {
                                let guard = child.tcp.lock();
                                if let Some(ts) = guard.as_ref() {
                                    encode_window(ts.control.rcv_wnd, 0, true)
                                } else {
                                    TCP_DEFAULT_WINDOW
                                }
                            };

                            // Build SYN-ACK segment with MSS, SACK-Permitted, and optional WSopt
                            // RFC 793: SYN consumes 1 sequence number
                            let syn_ack = if options.window_scale.is_some() {
                                // Include MSS, WSopt, and SACK-Permitted in response
                                let our_scale = {
                                    let guard = child.tcp.lock();
                                    guard.as_ref().map(|ts| ts.control.rcv_wscale).unwrap_or(0)
                                };
                                let syn_ack_options = [
                                    TcpOptionKind::Mss(cookie_mss),
                                    TcpOptionKind::WindowScale(our_scale),
                                    TcpOptionKind::SackPermitted,
                                ];
                                build_tcp_segment_with_options(
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    iss,
                                    header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                                    syn_ack_wnd,
                                    &syn_ack_options,
                                    &[],
                                )
                            } else {
                                // Include MSS and SACK-Permitted
                                let syn_ack_options = [
                                    TcpOptionKind::Mss(cookie_mss),
                                    TcpOptionKind::SackPermitted,
                                ];
                                build_tcp_segment_with_options(
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    iss,
                                    header.seq_num.wrapping_add(1), // ACK = IRS + 1
                                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                                    syn_ack_wnd,
                                    &syn_ack_options,
                                    &[],
                                )
                            };

                            // Register connection for demux.
                            // J2-1: charge the per-namespace connection budget bound
                            // to this tcp_conns insertion. If the tenant is already at
                            // its connection cap, skip the insert + SYN queue and fall
                            // back to stateless SYN cookies (handled below), exactly
                            // like the global half-open / queue_syn failure path.
                            let ns_conn_charged = {
                                let mut conns = self.tcp_conns.lock();
                                if self.try_inc_ns_conn(syn_key.0).is_ok() {
                                    // Bind the charge to a genuine membership growth: the
                                    // dup-check for this path ran under an earlier, separate
                                    // tcp_conns lock (TOCTOU), so if the key raced in, insert
                                    // would REPLACE without growing the map — undo the extra
                                    // charge to keep count == live tcp_conns key count.
                                    if conns.insert(syn_key, Arc::downgrade(&child)).is_some() {
                                        self.dec_ns_conn(syn_key.0);
                                    }
                                    true
                                } else {
                                    false
                                }
                            };

                            // Queue half-open connection in SYN queue (only if it was
                            // charged + registered above).
                            if ns_conn_charged {
                                let pending = PendingSyn {
                                    key: syn_key,
                                    sock: child.clone(),
                                    syn_ack: syn_ack.clone(),
                                    syn_sent_at: now_ms,
                                };

                                // SYN cookie path handles the backlog-full case above,
                                // but queue_syn can still fail due to the global/per-ns
                                // half-open limit.
                                if listen_state.queue_syn(pending, self) {
                                    // R155-9 FIX: Seed conntrack for the inbound SYN +
                                    // outbound SYN-ACK so the final ACK transitions to
                                    // Established. Same pattern as the SYN cookie path.
                                    #[cfg(feature = "conntrack")]
                                    {
                                        use crate::conntrack::ct_process_tcp;
                                        let _ = ct_process_tcp(
                                            listener.net_ns_id.0,
                                            src_ip,
                                            dst_ip,
                                            header.src_port,
                                            header.dst_port,
                                            header.flags,
                                            payload.len(),
                                            now_ms,
                                        );
                                        let _ = ct_process_tcp(
                                            listener.net_ns_id.0,
                                            dst_ip,
                                            src_ip,
                                            header.dst_port,
                                            header.src_port,
                                            TCP_FLAG_SYN | TCP_FLAG_ACK,
                                            0,
                                            now_ms,
                                        );
                                    }
                                    return Some(syn_ack);
                                }

                                // R106-2 FIX: queue_syn failed. J2-1: uncharge the
                                // per-namespace connection charged above and remove the
                                // tcp_conns entry before falling back to SYN cookies.
                                if self.tcp_conns.lock().remove(&syn_key).is_some() {
                                    self.dec_ns_conn(syn_key.0);
                                }
                            }

                            // Clean up the child socket + fall back to SYN cookies.
                            // Reached when queue_syn failed OR the per-namespace
                            // connection budget was exceeded (ns_conn_charged == false,
                            // in which case the child was never inserted into tcp_conns).
                            self.sockets.write().remove(&child_id);
                            // R77-4 FIX: Rollback quota on failure path
                            self.dec_ns_count(listener.net_ns_id);

                            // Fall back to stateless SYN cookie SYN-ACK
                            // R137-2 FIX: Rate limit fallback SYN-cookie path as well.
                            if !allow_syn_cookie_ack(now_ms) {
                                return None;
                            }
                            SYN_COOKIES_GENERATED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX
                            let cookie_iss = generate_syn_cookie_isn(
                                now_ms,
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                                mss_index,
                            );
                            let syn_ack_options = [TcpOptionKind::Mss(cookie_mss)];
                            let cookie_syn_ack = build_tcp_segment_with_options(
                                dst_ip,
                                src_ip,
                                header.dst_port,
                                header.src_port,
                                cookie_iss,
                                header.seq_num.wrapping_add(1),
                                TCP_FLAG_SYN | TCP_FLAG_ACK,
                                TCP_DEFAULT_WINDOW,
                                &syn_ack_options,
                                &[],
                            );
                            // R107-3 FIX: Seed synthetic conntrack state for this
                            // SYN-cookie handshake (SYN-ACK retry path).
                            #[cfg(feature = "conntrack")]
                            {
                                use crate::conntrack::ct_process_tcp;
                                let _ = ct_process_tcp(
                                    listener.net_ns_id.0,
                                    src_ip,
                                    dst_ip,
                                    header.src_port,
                                    header.dst_port,
                                    header.flags,
                                    payload.len(),
                                    now_ms,
                                );
                                let _ = ct_process_tcp(
                                    listener.net_ns_id.0,
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                                    0,
                                    now_ms,
                                );
                            }
                            return Some(cookie_syn_ack);
                        }
                    }
                }

                // SYN Cookie Validation Path: If this is an ACK with no half-open
                // connection, it might be completing a SYN cookie handshake
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_syn = header.flags & TCP_FLAG_SYN != 0;

                if is_ack && !is_syn {
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let now_ms = self.time_wait_now();

                        // The cookie ISN is (ACK number - 1) since we sent SYN-ACK with ISN,
                        // and client ACK should acknowledge ISN+1
                        let cookie_isn = header.ack_num.wrapping_sub(1);

                        if let Some(cookie_data) = validate_syn_cookie(
                            now_ms,
                            cookie_isn,
                            dst_ip,
                            header.dst_port,
                            src_ip,
                            header.src_port,
                        ) {
                            SYN_COOKIES_VALIDATED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX
                            // Security: Final ACK must exactly acknowledge our SYN (ISS + 1)
                            // This prevents attacks with forged ACK numbers that could
                            // corrupt send-window accounting
                            if header.ack_num != cookie_data.iss.wrapping_add(1) {
                                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                            }

                            // Security: SYN-cookie completion must be a pure ACK (no data)
                            // Accepting data here would silently drop or misorder it
                            // and increase attack surface for injection attacks
                            if !payload.is_empty() {
                                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                            }

                            // Valid SYN cookie - create connection
                            let syn_key = tcp_map_key_from_parts(
                                listener.net_ns_id,
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                            );

                            // P0-2 FIX: Check limits before creating connection.
                            // When at capacity, attempt TIME_WAIT eviction so that
                            // validated SYN cookie completions are not silently
                            // dropped under sustained load.
                            {
                                let mut conns = self.tcp_conns.lock();
                                self.conns_retain_accounted(&mut conns);
                                // Check for duplicate first (race condition guard)
                                if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                    return None;
                                }
                                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                    // Release lock — try_evict needs it internally.
                                    drop(conns);
                                    if !self.try_evict_time_wait_for_cookie(now_ms) {
                                        // Genuinely no capacity even after eviction.
                                        return None;
                                    }
                                    // Re-check under fresh lock: another core may have
                                    // consumed the freed slot or inserted a duplicate.
                                    let mut conns = self.tcp_conns.lock();
                                    self.conns_retain_accounted(&mut conns);
                                    if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                        return None;
                                    }
                                    if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                        return None;
                                    }
                                }
                            }

                            // Check accept queue capacity
                            {
                                let listen_guard = listener.listen.lock();
                                if let Some(listen_state) = listen_guard.as_ref() {
                                    if listen_state.accept_queue.len()
                                        >= listen_state.accept_backlog
                                    {
                                        // Accept queue full - send RST
                                        return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                    }
                                }
                            }

                            // R77-4 FIX: Enforce per-namespace socket quota before creating child socket.
                            // This is the SYN cookie completion path - without this check, validated
                            // cookies could create unlimited sockets bypassing namespace quotas.
                            if let Err(_) = self.try_inc_ns_count(listener.net_ns_id) {
                                // Quota exceeded: behave like accept queue full and send RST
                                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                            }

                            // Create child socket for the connection
                            // R75-1 FIX: Child socket inherits parent listener's network namespace
                            // R107-5 FIX: Overflow-safe socket ID allocation
                            let child_id = match self.next_socket_id.fetch_update(
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                                |current| current.checked_add(1),
                            ) {
                                Ok(prev) => prev,
                                Err(_) => {
                                    self.dec_ns_count(listener.net_ns_id); // Rollback quota
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload); // ID exhausted
                                }
                            };
                            let child = Arc::new(SocketState::new(
                                child_id,
                                listener.domain,
                                listener.ty,
                                listener.proto,
                                listener.label,
                                listener.net_ns_id,
                            ));

                            self.sockets.write().insert(child_id, child.clone());
                            self.created.fetch_add(1, Ordering::Relaxed);

                            child.bind_local(dst_ip, header.dst_port);
                            child.set_remote(src_ip, header.src_port);

                            // Create TCB in Established state (handshake completed via cookie)
                            // The IRS (Initial Receive Sequence) was header.seq_num in the original SYN
                            // which is now header.seq_num - 1 (they sent +1 in their ACK)
                            let irs = header.seq_num.wrapping_sub(1);
                            let mut tcb = TcpControlBlock::new_server(
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                                cookie_data.iss,
                                irs,
                            );

                            // R151-8 FIX: SYN cookie connections do not negotiate window
                            // scaling. Cap rcv_wnd to what can be advertised in the 16-bit
                            // TCP window field without WSopt. Without this cap, the stack
                            // accepts up to 256 KiB per connection while only advertising
                            // 64 KiB, enabling 4x memory amplification under SYN flood.
                            if !tcb.wscale_enabled() {
                                tcb.rcv_wnd = tcb.rcv_wnd.min(u16::MAX as u32);
                            }

                            // Set MSS from cookie
                            tcb.snd_mss = cookie_data.mss;
                            tcb.rcv_mss = cookie_data.mss;
                            tcb.cwnd = initial_cwnd(cookie_data.mss);

                            // Update sequence numbers: our SYN consumed 1 byte
                            tcb.snd_nxt = cookie_data.iss.wrapping_add(1);
                            tcb.snd_una = cookie_data.iss;

                            // Initialize send window from their ACK
                            // Note: No window scaling for SYN cookie connections
                            tcb.snd_wnd = decode_window(header.window, 0);
                            tcb.snd_wl1 = header.seq_num;
                            tcb.snd_wl2 = header.ack_num;

                            // Transition directly to Established (cookie validated)
                            tcb.state = TcpState::Established;
                            tcb.established_at = now_ms;
                            tcb.last_activity = now_ms;

                            // Process the ACK to update snd_una
                            handle_ack(&mut tcb, header.ack_num, now_ms);

                            child.attach_tcp(tcb);

                            // Register connection.
                            // J2-1: charge the per-namespace connection budget bound
                            // to this insertion. On over-quota, tear down the child
                            // (cleanup_tcp_connection removes it from the sockets map +
                            // dec_ns_count) and send RST — mirrors accept-queue-full.
                            // The conns guard is dropped before cleanup_tcp_connection,
                            // which re-locks tcp_conns (non-reentrant).
                            {
                                let mut conns = self.tcp_conns.lock();
                                if self.try_inc_ns_conn(syn_key.0).is_err() {
                                    drop(conns);
                                    child.mark_closed();
                                    self.cleanup_tcp_connection(&child);
                                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                                }
                                // Bind the charge to a genuine membership growth (TOCTOU:
                                // the dup-check ran under an earlier, separate tcp_conns
                                // lock; a raced-in key would make insert REPLACE).
                                if conns.insert(syn_key, Arc::downgrade(&child)).is_some() {
                                    self.dec_ns_conn(syn_key.0);
                                }
                            }

                            // Add to accept queue
                            if !listener.push_accept_ready(child.clone()) {
                                // Accept queue became full between check and push
                                child.mark_closed();
                                // R129-2 FIX: cleanup_tcp_connection now handles dec_ns_count
                                // when removing from sockets map. The explicit dec_ns_count
                                // (R77-4) that was here is no longer needed and would cause
                                // a double-decrement.
                                self.cleanup_tcp_connection(&child);
                                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                            }

                            // Wake waiting accept()
                            child.wake_tcp_waiters();

                            // No response needed - connection is established
                            return None;
                        } else {
                            SYN_COOKIES_REJECTED.fetch_add(1, Ordering::Relaxed); // R132-5 FIX
                        }
                    }
                }

                // No connection found - send RST per RFC 793
                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
            }
        };

        // Process based on current TCP state
        let mut guard = sock.tcp.lock();
        let tcp_state = match guard.as_mut() {
            Some(s) => s,
            None => {
                // Socket has no TCP state (shouldn't happen for TCP sockets)
                drop(guard);
                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
            }
        };

        match tcp_state.control.state {
            TcpState::SynSent => {
                // Expecting SYN-ACK to complete active open
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                // RFC 793: In SYN-SENT, must receive SYN+ACK (normal 3-way handshake)
                // or SYN without ACK (simultaneous open).
                if !is_ack {
                    if is_syn {
                        // R148-I2 FIX: RFC 793 simultaneous open.
                        // Both endpoints independently sent SYN to each other.
                        // Accept the remote's SYN, transition to SYN-RECEIVED,
                        // and respond with SYN+ACK (our original ISS + ACK their SYN).
                        tcp_state.control.irs = header.seq_num;
                        tcp_state.control.rcv_nxt = header.seq_num.wrapping_add(1);

                        // Process peer's TCP options (MSS, window scale, SACK)
                        if tcp_state.control.wscale_requested {
                            if let Some(peer_scale) = options.window_scale {
                                tcp_state.control.snd_wscale =
                                    peer_scale.min(TCP_MAX_WINDOW_SCALE);
                                tcp_state.control.wscale_received = true;
                            }
                        }
                        if tcp_state.control.sack_requested && options.sack_permitted {
                            tcp_state.control.sack_received = true;
                        }
                        // R150-2 FIX: Process peer MSS from bare SYN (simultaneous open).
                        // Without this, snd_mss stays at TCP_DEFAULT_MSS (536) →
                        // initial_cwnd = 536 × 10 = 5360 instead of 1460 × 10 = 14600.
                        if let Some(mss) = options.mss {
                            let clamped = mss.max(64).min(TCP_ETHERNET_MSS);
                            tcp_state.control.snd_mss = clamped;
                            tcp_state.control.cwnd =
                                initial_cwnd(tcp_state.control.snd_mss);
                        }

                        // Initialize send window (unscaled per RFC 7323 §2.2)
                        tcp_state.control.snd_wnd = decode_window(header.window, 0);
                        tcp_state.control.snd_wl1 = header.seq_num;

                        tcp_state.control.state = TcpState::SynReceived;

                        // Build SYN+ACK: retransmit our SYN (snd_una = ISS) + ACK their SYN
                        // R163-10 FIX: Replace infallible alloc::vec![...] + push() opts
                        // construction with a bounded stack array. There are at most 3
                        // options (MSS, WindowScale, SackPermitted); we populate a
                        // fixed-size array and slice it to the actual count used.
                        let wscale_opt = tcp_state.control.wscale_requested.then(||
                            TcpOptionKind::WindowScale(tcp_state.control.rcv_wscale)
                        );
                        let sack_opt = tcp_state.control.sack_requested.then(||
                            TcpOptionKind::SackPermitted
                        );
                        let syn_ack = match (wscale_opt, sack_opt) {
                            (Some(ws), Some(_sack)) => build_tcp_segment_with_options(
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                tcp_state.control.snd_una, tcp_state.control.rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS), ws, TcpOptionKind::SackPermitted],
                                &[],
                            ),
                            (Some(ws), None) => build_tcp_segment_with_options(
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                tcp_state.control.snd_una, tcp_state.control.rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS), ws],
                                &[],
                            ),
                            (None, Some(_sack)) => build_tcp_segment_with_options(
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                tcp_state.control.snd_una, tcp_state.control.rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS), TcpOptionKind::SackPermitted],
                                &[],
                            ),
                            (None, None) => build_tcp_segment_with_options(
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                tcp_state.control.snd_una, tcp_state.control.rcv_nxt,
                                TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_DEFAULT_WINDOW,
                                &[TcpOptionKind::Mss(TCP_ETHERNET_MSS)],
                                &[],
                            ),
                        };

                        drop(guard);
                        return Some(syn_ack);
                    }
                    // Non-SYN without ACK in SYN-SENT — ignore
                    return None;
                }

                if !is_syn {
                    // ACK without SYN in SYN-SENT is invalid per RFC 793
                    // Send RST and abort connection
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    sock.wake_tcp_waiters();
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Validate ACK number: must acknowledge our SYN (ISS + 1)
                let expected_ack = tcp_state.control.snd_nxt;
                if header.ack_num != expected_ack {
                    // Invalid ACK - send RST and abort connection
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    sock.wake_tcp_waiters();
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Accept the remote's ISN and transition to ESTABLISHED
                tcp_state.control.irs = header.seq_num;
                // R51-3 FIX: Ignore SYN-ACK payload (not buffered, breaks integrity)
                // RFC 793: SYN consumes 1 sequence number only.
                // TCP Fast Open (RFC 7413) would require explicit negotiation and
                // buffering of early data before ACKing, which we don't support.
                let syn_len = 1u32;
                tcp_state.control.rcv_nxt = header.seq_num.wrapping_add(syn_len);
                // Update snd_una and refresh RTT estimates from ACK
                self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                // R58: RFC 7323 Window Scaling - process WSopt from SYN-ACK
                // Window scaling is ONLY negotiated if we sent WSopt in our SYN
                // AND the peer includes WSopt in their SYN-ACK.
                if tcp_state.control.wscale_requested {
                    if let Some(peer_scale) = options.window_scale {
                        // Clamp to maximum allowed scale factor
                        tcp_state.control.snd_wscale = peer_scale.min(TCP_MAX_WINDOW_SCALE);
                        tcp_state.control.wscale_received = true;
                    }
                    // If peer didn't send WSopt, window scaling is disabled
                    // (snd_wscale remains 0, wscale_received remains false)
                }

                // RFC 2018: SACK negotiation — record peer's SACK capability.
                // SACK is active only when both sides exchanged SACK-Permitted
                // during the SYN/SYN-ACK handshake.
                if tcp_state.control.sack_requested && options.sack_permitted {
                    tcp_state.control.sack_received = true;
                }
                // R150-2 FIX: Process peer MSS from SYN-ACK. Without this,
                // snd_mss stays at TCP_DEFAULT_MSS (536) for ALL connect()-initiated
                // connections → initial_cwnd = 536 × 10 = 5360 bytes instead of
                // 1460 × 10 = 14600 bytes, throttling throughput ~60% in slow-start.
                if let Some(mss) = options.mss {
                    let clamped = mss.max(64).min(TCP_ETHERNET_MSS);
                    tcp_state.control.snd_mss = clamped;
                    tcp_state.control.cwnd = initial_cwnd(tcp_state.control.snd_mss);
                }

                // Initialize send window from SYN-ACK (window field is never scaled on SYNs)
                // RFC 7323 Section 2.2: Scaling takes effect only after SYN exchange completes
                tcp_state.control.snd_wnd = decode_window(
                    header.window,
                    0, // RFC 7323: SYN/SYN-ACK window is unscaled
                );
                tcp_state.control.snd_wl1 = header.seq_num;
                tcp_state.control.snd_wl2 = header.ack_num;
                tcp_state.control.state = TcpState::Established;

                // R58 FIX: RFC 793 semantics - if window scaling was not negotiated,
                // cap receive window to 16 bits to avoid accepting more data than
                // we can advertise without scaling. This ensures sequence/window
                // checks remain consistent with advertised window.
                if !tcp_state.control.wscale_enabled()
                    && tcp_state.control.rcv_wnd > u16::MAX as u32
                {
                    tcp_state.control.rcv_wnd = u16::MAX as u32;
                }

                // R58: Compute scaled window for final handshake ACK
                let handshake_adv_wnd = Self::current_adv_window(&tcp_state.control);

                // Build ACK segment to complete 3-way handshake
                let ack_segment = build_tcp_segment(
                    dst_ip,                    // src (our IP)
                    src_ip,                    // dst (peer IP)
                    header.dst_port,           // src port (our port)
                    header.src_port,           // dst port (peer port)
                    tcp_state.control.snd_nxt, // seq = our next seq
                    tcp_state.control.rcv_nxt, // ack = their ISN + 1 + data
                    TCP_FLAG_ACK,
                    handshake_adv_wnd,
                    &[],
                );

                // Wake any threads blocked in connect()
                drop(guard);
                sock.wake_tcp_waiters();

                Some(ack_segment)
            }

            TcpState::Established => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                // RFC 793: in synchronized states, segments must carry ACK
                if !is_ack {
                    return None;
                }

                // R58: Calculate scaled advertised receive window
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                // R50-2 FIX: Validate ACK with wraparound-safe sequence comparisons
                // ACK must be: snd_una <= ack_num <= snd_nxt
                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                // R50-2 FIX: Validate segment sequence number is within receive window
                // This prevents blind data injection attacks
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                // If sequence is outside receive window, send challenge ACK
                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                // Track whether fast retransmit was triggered
                let mut fast_retransmit_seg: Option<Vec<u8>> = None;

                if ack_in_range {
                    // RFC 2018 / RFC 6675: Extract SACK blocks from incoming segment
                    // for sender scoreboard processing and loss-based retransmission.
                    let sack_blocks = if tcp_state.control.sack_enabled() {
                        options.sack_blocks.as_slice()
                    } else {
                        &[]
                    };

                    // Combined ACK processing + SACK scoreboard + congestion control.
                    // apply_ack_and_cc returns (Some(segment), _) if fast retransmit was triggered,
                    // and (_, true) if RFC 3042 Limited Transmit requests new data.
                    let (retransmit_seg, limited_transmit) = self.apply_ack_and_cc(
                        &mut tcp_state.control,
                        header.ack_num,
                        advertised_wnd,
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        self.time_wait_now(),
                        sack_blocks,
                        !payload.is_empty(),
                        header.window,
                    );
                    fast_retransmit_seg = retransmit_seg;

                    // J2-6: apply_ack_and_cc ran handle_ack internally (freeing acked
                    // send bytes); reconcile the per-namespace send counter here at
                    // the caller, which holds `sock` — keeping apply_ack_and_cc's
                    // signature free of net_ns_id (no change to the hot CC path).
                    self.reconcile_ns_send(sock.net_ns_id, &mut tcp_state.control);

                    // R56-1: RFC 3042 Limited Transmit — wake sender to push new data
                    if limited_transmit {
                        sock.wake_tcp_waiters();
                    }

                    // R58: Decode peer's advertised window and update send window
                    let peer_adv_wnd =
                        decode_window(header.window, tcp_state.control.effective_snd_wscale());

                    // R50-2 FIX: Use seq_gt/seq_ge for wraparound-safe window update (RFC 793)
                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        tcp_state.control.snd_wnd = peer_adv_wnd;
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    // Unacceptable ACK: send duplicate ACK without aborting (RFC 793)
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                let mut data_received = false;
                // R155-15 FIX: Track whether OOO drain delivered a buffered FIN,
                // so that state waiters are also woken (not just data waiters).
                let mut ooo_fin_delivered = false;
                let mut response: Option<Vec<u8>> = None;
                // R144-1 FIX: Save rcv_nxt AFTER in-order data but BEFORE OOO drain.
                //
                // When a segment carries both data and FIN, rcv_nxt advances by
                // payload.len() for the data, then ooo_drain_contiguous() may
                // advance it further for contiguous OOO segments.  The FIN check
                // below compares header.seq_num + payload.len() against rcv_nxt,
                // which must reflect the position immediately after the in-order
                // data (the FIN position) -- not the post-drain position.
                // Without this fix, the FIN is silently lost and the connection
                // stays in Established state indefinitely (TCB leak).
                let mut fin_expected_seq: Option<u32> = None;

                // Process incoming data if present
                if !payload.is_empty() {
                    // Recalculate window after ACK processing (includes OOO bytes)
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    // LSM check before buffering data
                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        // LSM denied - silently drop
                        return None;
                    }

                    // Check if segment is in-order (seq == rcv_nxt)
                    if header.seq_num == tcp_state.control.rcv_nxt {
                        // In-order: buffer directly into receive buffer
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            // Would overrun advertised window — send ACK with current window
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R162-9 FIX: Fallible recv_buffer growth
                        if tcp_state.control.recv_buffer.try_reserve(payload.len()).is_err() {
                            return None;
                        }
                        tcp_state.control.recv_buffer.extend(payload.iter().copied());
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);

                        // R144-1 FIX: Snapshot rcv_nxt before OOO drain so the FIN
                        // check uses the correct expected sequence.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);

                        // R144-1 FIX: Skip OOO drain when the current segment carries
                        // FIN.  The FIN handler below will clear the OOO queue (no data
                        // is valid after FIN).  If we drained here, OOO data starting at
                        // the FIN position would be appended to recv_buffer before FIN
                        // acceptance, enabling post-FIN data injection.
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();

                            // R155-15 FIX: OOO drain may deliver a buffered FIN,
                            // triggering state transitions inside tcp.rs (e.g.
                            // Established→CloseWait) without socket-layer side
                            // effects.  If fin_received became true, ensure recv
                            // waiters are woken for EOF delivery.
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                            }
                        }

                        // Build ACK (plain — no SACK blocks needed for in-order data
                        // with empty OOO queue; includes SACK if OOO queue is non-empty)
                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // Out-of-order: buffer in OOO queue and send SACK-bearing ACK
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state.control.ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Per RFC 793, accept in-window portion of partial
                        // retransmission overlaps (seq < rcv_nxt, seq+len > rcv_nxt).
                        // R162-6-1/6-2 FIX: Pass FIN flag when FIN position is at seg_end,
                        // and handle OOO-drain state transitions (wake waiters, set timers).
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip = tcp_state.control.rcv_nxt
                                .wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, useful.len())
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt, useful, pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let dup_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(dup_ack);
                    }
                }

                // RFC 793: Handle FIN flag - peer wants to close
                if is_fin {
                    // R144-1 FIX: Use the pre-OOO-drain rcv_nxt (if available) so that
                    // contiguous OOO segments drained after the in-order data do not
                    // push rcv_nxt past the FIN position, silently losing FIN.
                    let expected_fin_pos = fin_expected_seq
                        .unwrap_or(tcp_state.control.rcv_nxt);
                    // FIN must be in-order (seq_num + payload_len == expected position)
                    if header.seq_num.wrapping_add(payload.len() as u32)
                        != expected_fin_pos
                    {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: FIN consumes 1 sequence number.
                    // Set rcv_nxt to expected_fin_pos + 1, since the OOO drain may
                    // have already advanced rcv_nxt past the FIN position.  Data
                    // delivered by OOO drain that was beyond the FIN is invalid
                    // (no legitimate data can follow FIN in the same direction);
                    // clearing the OOO queue below prevents further delivery.
                    tcp_state.control.rcv_nxt = expected_fin_pos.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: No data is valid after FIN.  Drop any buffered
                    // OOO segments to prevent delivering data past FIN and to free
                    // memory sooner.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    // Transition to CLOSE_WAIT (passive close)
                    tcp_state.control.state = TcpState::CloseWait;

                    drop(guard);
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(data_ack) = response {
                    drop(guard);

                    if data_received {
                        // Wake any threads blocked in tcp_recv()
                        sock.wake_tcp_data_waiters();
                    }

                    // R155-15 FIX: OOO drain delivered a buffered FIN, which
                    // transitioned the state (e.g. Established→CloseWait)
                    // inside tcp.rs.  Wake state waiters so close/shutdown
                    // paths see the transition, and ensure data waiters are
                    // woken for EOF even if data_received was not set.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }

                    // RFC 5681: If fast retransmit was triggered, transmit it now
                    // Priority: data ACK first (we already have one), fast retransmit happens via timer
                    // However, if the peer's ACK was a dup ACK, the data_ack response handles it
                    if let Some(fr_seg) = fast_retransmit_seg {
                        // Transmit fast retransmit segment asynchronously
                        let meta = sock.meta_snapshot();
                        if let Some(remote_ip) = meta.remote_ip.map(Ipv4Addr) {
                            let _ = transmit_tcp_segment(remote_ip, &fr_seg, sock.net_ns_id.0);
                        }
                    }

                    return Some(data_ack);
                }

                // RFC 5681: Handle fast retransmit even for pure ACK (no data response)
                if let Some(fr_seg) = fast_retransmit_seg {
                    drop(guard);
                    let meta = sock.meta_snapshot();
                    if let Some(remote_ip) = meta.remote_ip.map(Ipv4Addr) {
                        let _ = transmit_tcp_segment(remote_ip, &fr_seg, sock.net_ns_id.0);
                    }
                    return None; // Fast retransmit sent via transmit_tcp_segment
                }

                // Pure ACK with no data - nothing more to do
                None
            }

            // ================================================================
            // FIN-WAIT-1: We sent FIN, waiting for ACK and/or peer's FIN
            // ================================================================
            TcpState::FinWait1 => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in closing states,
                // so retransmit timer selects the right segment if data remains.
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                // Check if our FIN was ACKed
                let acked_fin = seq_ge(header.ack_num, tcp_state.control.snd_nxt);
                if acked_fin {
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::FinWait2;
                    // R65-5 FIX: Start FIN_WAIT_2 idle timeout timer
                    tcp_state.control.fin_wait2_start = self.time_wait_now();
                }

                let mut data_received = false;
                // R155-15 FIX: Track OOO-drain-delivered FIN for wake side effects.
                let mut ooo_fin_delivered = false;
                let mut response: Option<Vec<u8>> = None;
                // R144-1 FIX: See Established-state comment for rationale.
                let mut fin_expected_seq: Option<u32> = None;

                // Process incoming data (we can still receive in FIN_WAIT_1)
                if !payload.is_empty() {
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    if header.seq_num == tcp_state.control.rcv_nxt {
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R162-9 FIX: Fallible recv_buffer growth
                        if tcp_state.control.recv_buffer.try_reserve(payload.len()).is_err() {
                            return None;
                        }
                        tcp_state.control.recv_buffer.extend(payload.iter().copied());
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);
                        // R144-1 FIX: Snapshot before OOO drain; skip drain if FIN.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();
                            // R155-15 FIX: OOO drain may deliver buffered FIN.
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                                // R161-11 FIX: OOO drain may transition FinWait2→TimeWait
                                // (when FIN ACK above moved us to FinWait2 first).
                                // Set time_wait_start immediately.
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                            }
                        }

                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state.control.ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Accept in-window portion of partial overlap.
                        // R162-6-1/6-2 FIX: Pass FIN and handle OOO-drain transitions.
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip = tcp_state.control.rcv_nxt
                                .wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, useful.len())
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt, useful, pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let dup_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(dup_ack);
                    }
                }

                // Handle peer's FIN
                if is_fin {
                    // R144-1 FIX: Use pre-OOO-drain rcv_nxt.
                    let expected_fin_seq = fin_expected_seq
                        .unwrap_or(tcp_state.control.rcv_nxt);
                    if header.seq_num.wrapping_add(payload.len() as u32) != expected_fin_seq {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: Set rcv_nxt to the FIN position + 1.
                    tcp_state.control.rcv_nxt = expected_fin_seq.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: Clear OOO queue — no data valid past FIN.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // If our FIN was ACKed: FIN_WAIT_1 + FIN → TIME_WAIT
                    // If not ACKed: FIN_WAIT_1 + FIN → CLOSING (simultaneous close)
                    if acked_fin {
                        // Record TIME_WAIT start for 2MSL timer
                        tcp_state.control.time_wait_start = self.time_wait_now();
                        // FIN ACKed - clear retransmission timer
                        tcp_state.control.fin_sent_time = 0;
                        tcp_state.control.fin_retries = 0;
                    }
                    tcp_state.control.state = if acked_fin {
                        TcpState::TimeWait
                    } else {
                        TcpState::Closing
                    };

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);

                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(resp) = response {
                    drop(guard);
                    if data_received {
                        sock.wake_tcp_data_waiters();
                    }
                    // R155-15 FIX: OOO drain delivered buffered FIN — wake
                    // both data and state waiters for EOF and state transition.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }
                    if acked_fin {
                        sock.wake_tcp_waiters();
                    }
                    return Some(resp);
                }

                if acked_fin {
                    drop(guard);
                    sock.wake_tcp_waiters();
                }

                None
            }

            // ================================================================
            // FIN-WAIT-2: Our FIN was ACKed, waiting for peer's FIN
            // ================================================================
            TcpState::FinWait2 => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in FIN_WAIT_2.
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                let mut data_received = false;
                // R155-15 FIX: Track OOO-drain-delivered FIN for wake side effects.
                let mut ooo_fin_delivered = false;
                let mut response: Option<Vec<u8>> = None;
                // R144-1 FIX: See Established-state comment for rationale.
                let mut fin_expected_seq: Option<u32> = None;

                // We can still receive data in FIN_WAIT_2
                if !payload.is_empty() {
                    let window_after_ack = Self::current_adv_window(&tcp_state.control);

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    if header.seq_num == tcp_state.control.rcv_nxt {
                        let consumed = (tcp_state.control.recv_buffer.len() as u32)
                            .saturating_add(tcp_state.control.ooo_bytes);
                        let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);

                        if (payload.len() as u32) > available {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // J2-4: per-namespace recv-memory gate (decide-only, fail-closed;
                        // identical drop+window-ACK shape as the per-conn overrun above).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let win_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                window_after_ack,
                            );
                            return Some(win_ack);
                        }

                        // R162-9 FIX: Fallible recv_buffer growth
                        if tcp_state.control.recv_buffer.try_reserve(payload.len()).is_err() {
                            return None;
                        }
                        tcp_state.control.recv_buffer.extend(payload.iter().copied());
                        tcp_state.control.rcv_nxt =
                            tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);
                        // R144-1 FIX: Snapshot before OOO drain; skip drain if FIN.
                        fin_expected_seq = Some(tcp_state.control.rcv_nxt);
                        if !is_fin {
                            tcp_state.control.ooo_drain_contiguous();
                            // R155-15 FIX: OOO drain may deliver buffered FIN
                            // (FinWait2→TimeWait transition inside tcp.rs).
                            if tcp_state.control.fin_received {
                                ooo_fin_delivered = true;
                                // R161-11 FIX: Set time_wait_start immediately on
                                // OOO-drain-triggered FinWait2→TimeWait transition.
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                            }
                        }

                        // J2-4: reconcile to true F after the in-order extend + drain,
                        // GATED on !is_fin — the is_fin case is reconciled post-OOO-purge
                        // in the FIN handler, avoiding a transiently-inflated publish to
                        // concurrent same-ns siblings.
                        if !is_fin {
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        response = Some(Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        ));
                        data_received = true;
                    } else if seq_gt(header.seq_num, tcp_state.control.rcv_nxt) {
                        // R133-3 FIX: Pass FIN flag to preserve it during OOO buffering.
                        // J2-4: gate before buffering OOO (so OOO is not a budget bypass);
                        // on reject drop the segment + SACK-ACK (peer/SACK retransmits).
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            let sack_ack = Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                ack_wnd,
                            );
                            return Some(sack_ack);
                        }
                        tcp_state.control.ooo_insert(header.seq_num, payload, is_fin);
                        self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let sack_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(sack_ack);
                    } else {
                        // R161-12 FIX: Accept in-window portion of partial overlap.
                        // R162-6-1/6-2 FIX: Pass FIN and handle OOO-drain transitions.
                        let seg_end = header.seq_num.wrapping_add(payload.len() as u32);
                        if seq_gt(seg_end, tcp_state.control.rcv_nxt) {
                            let skip = tcp_state.control.rcv_nxt
                                .wrapping_sub(header.seq_num) as usize;
                            let useful = &payload[skip..];
                            let pass_fin = is_fin;
                            // J2-4: gate the in-window overlap tail before buffering; on
                            // reject drop it and dup-ACK (peer/SACK retransmits).
                            if self
                                .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, useful.len())
                                .is_err()
                            {
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let dup_ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                return Some(dup_ack);
                            }
                            tcp_state.control.ooo_insert(
                                tcp_state.control.rcv_nxt, useful, pass_fin,
                            );
                            tcp_state.control.ooo_drain_contiguous();
                            // J2-4: reconcile to true F after the drain — covers BOTH the
                            // FIN early-return and the dup_ack fall-through.
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            data_received = true;
                            if tcp_state.control.fin_received {
                                if tcp_state.control.state == TcpState::TimeWait
                                    && tcp_state.control.time_wait_start == 0
                                {
                                    tcp_state.control.time_wait_start = self.time_wait_now();
                                }
                                let ack_wnd = Self::current_adv_window(&tcp_state.control);
                                let ack = Self::build_sack_ack(
                                    &tcp_state.control,
                                    dst_ip, src_ip, header.dst_port, header.src_port,
                                    ack_wnd,
                                );
                                drop(guard);
                                sock.wake_tcp_waiters();
                                sock.wake_tcp_data_waiters();
                                return Some(ack);
                            }
                        }
                        let ack_wnd = Self::current_adv_window(&tcp_state.control);
                        let dup_ack = Self::build_sack_ack(
                            &tcp_state.control,
                            dst_ip, src_ip, header.dst_port, header.src_port,
                            ack_wnd,
                        );
                        return Some(dup_ack);
                    }
                }

                // Handle peer's FIN
                if is_fin {
                    // R144-1 FIX: Use pre-OOO-drain rcv_nxt.
                    let expected_fin_seq = fin_expected_seq
                        .unwrap_or(tcp_state.control.rcv_nxt);
                    if header.seq_num.wrapping_add(payload.len() as u32) != expected_fin_seq {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            advertised_wnd,
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // R144-1 FIX: Set rcv_nxt to FIN position + 1.
                    tcp_state.control.rcv_nxt = expected_fin_seq.wrapping_add(1);
                    tcp_state.control.fin_received = true;

                    // R144-1 FIX: Clear OOO queue — no data valid past FIN.
                    while let Some(stale) = tcp_state.control.ooo_queue.pop_front() {
                        tcp_state.control.ooo_bytes = tcp_state
                            .control
                            .ooo_bytes
                            .saturating_sub(stale.data.len() as u32);
                    }
                    // J2-4: reconcile to post-purge true F (the FIN cleared the OOO queue,
                    // shrinking F). Dominates the fin-ack return. The combined in-order
                    // data+FIN case reaches here with the in-order reconcile skipped
                    // (is_fin), so this is its sole reconcile — no over-count of cleared OOO.
                    self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let fin_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    // FIN_WAIT_2 + FIN → TIME_WAIT
                    tcp_state.control.time_wait_start = self.time_wait_now();
                    tcp_state.control.state = TcpState::TimeWait;

                    drop(guard);
                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();

                    return Some(fin_ack);
                }

                if let Some(resp) = response {
                    drop(guard);
                    if data_received {
                        sock.wake_tcp_data_waiters();
                    }
                    // R155-15 FIX: OOO drain delivered buffered FIN
                    // (FinWait2→TimeWait) — wake both waiters for EOF
                    // and state-transition side effects.
                    if ooo_fin_delivered {
                        sock.wake_tcp_waiters();
                        sock.wake_tcp_data_waiters();
                    }
                    return Some(resp);
                }

                None
            }

            // ================================================================
            // CLOSE-WAIT: Peer sent FIN, waiting for local close
            // ================================================================
            TcpState::CloseWait => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // RFC 6675: Update sender SACK scoreboard in CLOSE_WAIT.
                // Data may still be sent in this state (application has not closed yet).
                if tcp_state.control.sack_enabled() && !options.sack_blocks.is_empty() {
                    tcp_state.control.process_sack_blocks(&options.sack_blocks);
                    tcp_state.control.sack_mark_lost();
                }

                // In CLOSE_WAIT, we don't expect more data but still ACK segments
                if !payload.is_empty() || (header.flags & TCP_FLAG_FIN != 0) {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let ack_seg = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);
                    return Some(ack_seg);
                }

                None
            }

            // ================================================================
            // CLOSING: Simultaneous close, waiting for ACK of our FIN
            // ================================================================
            TcpState::Closing => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // Handle retransmitted FIN from peer
                let mut fin_ack = None;
                if header.flags & TCP_FLAG_FIN != 0 {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Re-ACK the FIN
                    fin_ack = Some(build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    ));
                }

                // Check if our FIN was ACKed
                if seq_ge(header.ack_num, tcp_state.control.snd_nxt) {
                    // CLOSING + ACK of FIN → TIME_WAIT
                    tcp_state.control.time_wait_start = self.time_wait_now();
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::TimeWait;
                    drop(guard);
                    // Wake waiters (cleanup will be done by sweep_time_wait after 2MSL)
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();
                    return fin_ack;
                }

                if let Some(seg) = fin_ack {
                    drop(guard);
                    return Some(seg);
                }

                None
            }

            // ================================================================
            // LAST-ACK: Waiting for ACK of our FIN (passive close)
            // ================================================================
            TcpState::LastAck => {
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                if !is_ack {
                    return None;
                }

                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window {
                    let win_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(win_ack);
                }

                let ack_in_range = seq_ge(header.ack_num, tcp_state.control.snd_una)
                    && seq_ge(tcp_state.control.snd_nxt, header.ack_num);

                if ack_in_range {
                    self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());

                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Apply window scaling when updating send window
                        tcp_state.control.snd_wnd =
                            decode_window(header.window, tcp_state.control.effective_snd_wscale());
                        tcp_state.control.snd_wl1 = header.seq_num;
                        tcp_state.control.snd_wl2 = header.ack_num;
                    }
                } else {
                    let dup_ack = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        advertised_wnd,
                        &[],
                    );
                    drop(guard);
                    return Some(dup_ack);
                }

                // Check if our FIN was ACKed
                if seq_ge(header.ack_num, tcp_state.control.snd_nxt) {
                    // LAST_ACK + ACK of FIN → CLOSED
                    // FIN ACKed - clear retransmission timer
                    tcp_state.control.fin_sent_time = 0;
                    tcp_state.control.fin_retries = 0;
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);
                    self.cleanup_tcp_connection(&sock);
                    return None;
                }

                // Handle retransmitted FIN from peer
                if header.flags & TCP_FLAG_FIN != 0 {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    let ack_seg = build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    );

                    drop(guard);
                    return Some(ack_seg);
                }

                None
            }

            // ================================================================
            // TIME-WAIT: Wait for 2MSL before final cleanup
            // ================================================================
            TcpState::TimeWait => {
                // R58: Use scaled window advertisement
                let advertised_wnd = Self::current_adv_window(&tcp_state.control);
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);

                // R164-4 FIX: Check for retransmitted FIN BEFORE the window check.
                // A retransmitted FIN has seq == rcv_nxt - 1 (FIN consumed one
                // sequence number). This falls outside [rcv_nxt, rcv_nxt + wnd),
                // so the old window check silently dropped it. Per RFC 793, the
                // TIME_WAIT state must re-ACK retransmitted FINs and restart 2MSL.
                let is_retransmitted_fin = header.flags & TCP_FLAG_FIN != 0
                    && header.seq_num == tcp_state.control.rcv_nxt.wrapping_sub(1);

                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !seq_in_recv_window && !is_retransmitted_fin {
                    drop(guard);
                    return None;
                }

                // Handle retransmitted FIN from peer
                // R159-9 FIX: Only accept FIN at the exact expected sequence position.
                let mut fin_ack = None;
                if is_retransmitted_fin {
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Re-ACK the FIN and restart 2MSL timer
                    fin_ack = Some(build_tcp_segment(
                        dst_ip,
                        src_ip,
                        header.dst_port,
                        header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window_after),
                        &[],
                    ));

                    // Restart 2MSL timer on retransmitted FIN
                    tcp_state.control.time_wait_start = self.time_wait_now();
                }

                drop(guard);

                // No immediate cleanup - sweep_time_wait() will handle it after 2MSL
                if fin_ack.is_some() {
                    sock.wake_tcp_waiters();
                    sock.wake_tcp_data_waiters();
                }

                fin_ack
            }

            TcpState::SynReceived => {
                // R51-1: Handle final ACK to complete passive open handshake
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let syn_key =
                    tcp_map_key_from_parts(net_ns_id, dst_ip, header.dst_port, src_ip, header.src_port);

                // Handle retransmitted SYN: resend cached SYN-ACK
                if is_syn && !is_ack {
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_ref() {
                            if let Some(pending) = listen_state.get_syn(&syn_key) {
                                drop(guard);
                                return Some(pending.syn_ack.clone());
                            }
                        }
                    }
                    return None;
                }

                // Must have ACK to complete handshake
                if !is_ack {
                    return None;
                }

                // Validate ACK acknowledges our SYN (ISS + 1)
                let ack_valid = header.ack_num == tcp_state.control.snd_nxt;
                let recv_wnd = tcp_state.control.rcv_wnd.max(1);
                // R148-I2 FIX: During RFC 793 simultaneous open, the peer's SYN+ACK
                // carries seq = their ISS (already received, below rcv_nxt). The SYN
                // portion is a known retransmission — relax seq_in_window only for the
                // exact expected simultaneous-open pattern: SYN+ACK with seq == rcv_nxt-1
                // (the retransmitted SYN) and no payload.
                let simultaneous_open_synack = is_syn
                    && is_ack
                    && header.seq_num == tcp_state.control.rcv_nxt.wrapping_sub(1)
                    && payload.is_empty();
                let seq_ok = simultaneous_open_synack
                    || seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !ack_valid || !seq_ok {
                    // Invalid ACK - abort handshake, send RST
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);

                    // R51-1 FIX: Remove stale PendingSyn from listener's SYN queue
                    // before cleanup to prevent cached SYN-ACK responses to dead socket
                    // R75-1 FIX: Look up listener within the specified namespace
                    if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                        let mut listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_mut() {
                            listen_state.take_syn(&syn_key, self);
                        }
                    }

                    // R51-1 FIX (Codex): Mark socket closed before cleanup to ensure
                    // it's removed from sockets map (cleanup checks is_closed())
                    sock.mark_closed();
                    self.cleanup_tcp_connection(&sock);
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Handshake complete - transition to Established
                self.handle_ack_reconciled(&sock, &mut tcp_state.control, header.ack_num, self.time_wait_now());
                // R58: Apply window scaling when updating send window
                tcp_state.control.snd_wnd =
                    decode_window(header.window, tcp_state.control.effective_snd_wscale());
                tcp_state.control.snd_wl1 = header.seq_num;
                tcp_state.control.snd_wl2 = header.ack_num;
                tcp_state.control.state = TcpState::Established;

                // R58 FIX: RFC 793 semantics - if window scaling was not negotiated,
                // cap receive window to 16 bits to avoid accepting more data than
                // we can advertise without scaling. This ensures sequence/window
                // checks remain consistent with advertised window.
                if !tcp_state.control.wscale_enabled()
                    && tcp_state.control.rcv_wnd > u16::MAX as u32
                {
                    tcp_state.control.rcv_wnd = u16::MAX as u32;
                }

                // R152-4 FIX: Process any payload piggybacked on the completing ACK.
                // RFC 793 §3.4 permits data on the third handshake segment.
                // Without this, the payload is silently discarded and the peer
                // must retransmit, adding an unnecessary RTT of latency.
                let mut ack_response: Option<Vec<u8>> = None;
                let is_fin = header.flags & TCP_FLAG_FIN != 0;

                // R154-7 FIX: Apply LSM recv hook BEFORE buffering piggybacked data.
                // Established/FinWait1/FinWait2 all call hook_net_recv; SynReceived
                // was missing this check, allowing one segment of unauthorized data.
                let payload_allowed = if !payload.is_empty() {
                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_ok()
                } else {
                    true
                };

                if payload_allowed && !payload.is_empty()
                    && header.seq_num == tcp_state.control.rcv_nxt
                {
                    // R154-I2 FIX: Window calculation uses recv_buffer.len() without ooo_bytes.
                    // Invariant: SynReceived state cannot have out-of-order data because OOO
                    // buffering only occurs in Established/FinWait1/FinWait2 paths. This is
                    // the first data segment accepted after handshake completion, so ooo_bytes
                    // is guaranteed to be zero here.
                    debug_assert_eq!(tcp_state.control.ooo_bytes, 0,
                        "R154-I2: OOO bytes non-zero in SynReceived→Established transition");
                    let consumed = tcp_state.control.recv_buffer.len() as u32;
                    let available = tcp_state.control.rcv_wnd.saturating_sub(consumed);
                    if (payload.len() as u32) <= available {
                        // J2-4: per-namespace recv gate. On reject send a window ACK and
                        // do NOT extend / advance rcv_nxt (fail-closed; peer retransmits).
                        // rcv_nxt is advanced ONLY in the else-branch extend, so a
                        // data+FIN segment whose data is budget-rejected also fails the
                        // FIN check at the piggyback block below -> no half-accept.
                        if self
                            .try_charge_ns_recv_gate(sock.net_ns_id, &tcp_state.control, payload.len())
                            .is_err()
                        {
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            ack_response = Some(Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                ack_wnd,
                            ));
                        } else {
                            // R162-9 FIX: Fallible recv_buffer growth
                            if tcp_state.control.recv_buffer.try_reserve(payload.len()).is_err() {
                                return None;
                            }
                            tcp_state.control.recv_buffer.extend(payload.iter().copied());
                            tcp_state.control.rcv_nxt = tcp_state
                                .control
                                .rcv_nxt
                                .wrapping_add(payload.len() as u32);
                            // J2-4: reconcile to true F (== recv_buffer.len(); ooo_bytes==0
                            // here per the debug_assert above). Runs before drop(guard).
                            self.reconcile_ns_recv(sock.net_ns_id, &mut tcp_state.control);
                            let ack_wnd = Self::current_adv_window(&tcp_state.control);
                            ack_response = Some(Self::build_sack_ack(
                                &tcp_state.control,
                                dst_ip, src_ip, header.dst_port, header.src_port,
                                ack_wnd,
                            ));
                        }
                    }
                }

                // Handle FIN piggybacked on completing ACK (passive close)
                if is_fin
                    && header.seq_num.wrapping_add(payload.len() as u32)
                        == tcp_state.control.rcv_nxt
                {
                    tcp_state.control.rcv_nxt = tcp_state.control.rcv_nxt.wrapping_add(1);
                    tcp_state.control.fin_received = true;
                    tcp_state.control.state = TcpState::CloseWait;
                    let window = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                    ack_response = Some(build_tcp_segment(
                        dst_ip, src_ip,
                        header.dst_port, header.src_port,
                        tcp_state.control.snd_nxt,
                        tcp_state.control.rcv_nxt,
                        TCP_FLAG_ACK,
                        Self::encode_adv_window(&tcp_state.control, window),
                        &[],
                    ));
                }

                // Codex review: only wake data waiters if we actually buffered something
                let has_data = ack_response.is_some();

                drop(guard);

                // Remove from SYN queue and add to accept queue
                // R75-1 FIX: Look up listener within the specified namespace
                if let Some(listener) = self.lookup_tcp_listener(net_ns_id, header.dst_port) {
                    let mut listen_guard = listener.listen.lock();
                    if let Some(listen_state) = listen_guard.as_mut() {
                        // Remove from SYN queue
                        listen_state.take_syn(&syn_key, self);
                    }
                    drop(listen_guard);

                    // Push to accept queue and wake accept() waiters
                    // R154-9 FIX: Defense-in-depth note — completed child sockets are
                    // pushed here without a per-socket LSM accept check. Currently
                    // sys_accept() performs hook_net_accept() before returning the fd
                    // to userspace, so security is maintained. If a future code path
                    // hands out accepted sockets without going through sys_accept(),
                    // an LSM gate should be added here as well.
                    if !listener.push_accept_ready(sock.clone()) {
                        // Accept queue full - abort connection
                        // R51-1 FIX (Codex): Mark socket closed before cleanup
                        sock.mark_closed();
                        self.cleanup_tcp_connection(&sock);
                        return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                    }
                }

                // Wake any waiters (accept queue changed)
                // R152-4 FIX: Also wake data waiters if payload was buffered
                if has_data {
                    sock.wake_tcp_data_waiters();
                }
                sock.wake_tcp_waiters();
                ack_response
            }

            TcpState::Listen => {
                // Listen state should not receive segments here - handled above
                // This is an internal error / unexpected state
                None
            }

            _ => {
                // Other states not yet implemented
                None
            }
        }
    }

    /// Get the current timestamp for TCP timing operations.
    ///
    /// # R53-2 FIX (Timestamp Precision)
    ///
    /// This function now ALWAYS fetches the real-time kernel tick counter
    /// instead of using the cached sweep timestamp. This is critical for:
    ///
    /// 1. **RTT Sampling**: Accurate RTT measurements require precise
    ///    timestamps when segments are sent and when ACKs arrive. Using a
    ///    5-second cached timestamp would produce RTT samples of either 0
    ///    (if both occur in same sweep period) or ~5s (if they span periods),
    ///    completely corrupting SRTT/RTTVAR/RTO calculations.
    ///
    /// 2. **Retransmission Timing**: Segments sent just after a sweep would
    ///    have `sent_at` equal to the sweep time, making them appear older
    ///    than they are and triggering immediate spurious retransmissions.
    ///
    /// The cached `time_wait_clock` is still used as a fallback only when:
    /// - SocketWaitHooks are not yet registered (very early boot)
    /// - As a fallback for TIME_WAIT timer initialization
    ///
    /// Performance: get_ticks() is a simple atomic load from kernel_core's
    /// TICKS counter, not an expensive RDTSC or syscall.
    #[inline]
    fn time_wait_now(&self) -> u64 {
        // Always prefer real-time ticks for accurate RTT/retransmission timing
        if let Some(hooks) = socket_wait_hooks() {
            return hooks.get_ticks().max(1);
        }
        // Fallback to cached time or minimal non-zero value during early boot
        let cached = self.time_wait_clock.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        1 // Minimal non-zero value before any time source is available
    }

    /// Apply ACK processing with RFC 5681 congestion control and RFC 6675 SACK recovery.
    ///
    /// Combines `handle_ack()`, SACK scoreboard updates, and `update_congestion_control()`.
    ///
    /// # Arguments
    ///
    /// * `tcb` - TCP control block to update
    /// * `ack_num` - ACK number from incoming segment
    /// * `advertised_wnd` - Our current scaled advertised window for response segments
    /// * `local_ip`, `remote_ip` - IP addresses for segment construction
    /// * `local_port`, `remote_port` - Ports for segment construction
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `sack_blocks` - SACK blocks from incoming segment (empty if SACK disabled)
    /// * `has_payload` - True if the incoming segment carries data (not a pure ACK)
    /// * `peer_raw_window` - Raw window field from incoming TCP header (pre-decode)
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `Option<Vec<u8>>`: Retransmit segment if fast retransmit or partial-ACK was triggered
    /// - `bool`: True if RFC 3042 Limited Transmit was signaled (caller should wake sender)
    fn apply_ack_and_cc(
        &self,
        tcb: &mut TcpControlBlock,
        ack_num: u32,
        advertised_wnd: u16,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        now_ms: u64,
        sack_blocks: &[SackBlock],
        has_payload: bool,
        peer_raw_window: u16,
    ) -> (Option<Vec<u8>>, bool) {
        // Process ACK and get update info
        let ack_update = handle_ack(tcb, ack_num, now_ms);

        // RFC 2018 / RFC 6675: Process incoming SACK blocks on the sender scoreboard.
        // Mark segments as SACKed, update highest_sacked, then detect lost segments.
        if tcb.sack_enabled() && !sack_blocks.is_empty() {
            tcb.process_sack_blocks(sack_blocks);
            tcb.sack_mark_lost();
        }

        // RFC 5681 §3.2: Duplicate ACK definition — a pure duplicate ACK must:
        // 1. Have the same acknowledgment number as a previous ACK (ack_update.duplicate)
        // 2. Carry no data (payload empty)
        // 3. NOT be a pure window update (window must match current snd_wnd)
        // Segments with data or window changes are NOT duplicate ACKs.
        let peer_adv_wnd = decode_window(peer_raw_window, tcb.effective_snd_wscale());
        let is_window_update = peer_adv_wnd != tcb.snd_wnd;
        let is_pure_dup_ack = ack_update.duplicate && !has_payload && !is_window_update;

        // Update congestion control and check for fast retransmit
        // R55-1: Pass ack_num for NewReno partial ACK detection
        let action =
            update_congestion_control(tcb, ack_update.newly_acked, is_pure_dup_ack, ack_num);

        // Handle congestion control actions
        match action {
            // R55-1: Both FastRetransmit and RetransmitNext trigger segment retransmission
            CongestionAction::FastRetransmit | CongestionAction::RetransmitNext => {
                // RFC 6675: When SACK is enabled, prefer retransmitting the earliest
                // segment marked as lost rather than blindly retransmitting the front.
                let retransmit_idx = if tcb.sack_enabled() {
                    tcb.sack_find_lost_segment().or(Some(0))
                } else {
                    Some(0)
                };

                if let Some(idx) = retransmit_idx {
                    if let Some(seg) = tcb.send_buffer.get_mut(idx) {
                        let flags = TCP_FLAG_ACK
                            | if !seg.data.is_empty() {
                                TCP_FLAG_PSH
                            } else {
                                0
                            };
                        seg.retrans_count = seg.retrans_count.saturating_add(1);
                        seg.sent_at = now_ms;
                        tcb.last_activity = now_ms;

                        return (
                            Some(build_tcp_segment(
                                local_ip,
                                remote_ip,
                                local_port,
                                remote_port,
                                seg.seq,
                                tcb.rcv_nxt,
                                flags,
                                advertised_wnd,
                                &seg.data,
                            )),
                            false,
                        );
                    }
                }
            }
            // R56-1: RFC 3042 Limited Transmit — signal caller to wake sender
            CongestionAction::LimitedTransmit => return (None, true),
            CongestionAction::None => {}
        }

        (None, false)
    }

    /// Sweep TIME_WAIT connections and clean up those that exceeded 2MSL.
    ///
    /// This is a backward-compatible wrapper for `run_tcp_timers` that always
    /// performs TIME_WAIT cleanup. Use `run_tcp_timers` directly when you need
    /// to control whether TIME_WAIT cleanup runs.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Monotonic timestamp in milliseconds
    pub fn sweep_time_wait(&self, current_time_ms: u64) {
        self.run_tcp_timers(current_time_ms, true);
    }

    /// Run TCP timers for retransmission and optional TIME_WAIT cleanup.
    ///
    /// R53-3 FIX: Split TCP timer processing into two frequencies:
    /// - Fast timer (every 200ms): Data/FIN retransmission checks
    /// - Slow timer (every 1s): TIME_WAIT and SYN queue cleanup
    ///
    /// This enables responsive retransmission (within 200ms of RTO expiry)
    /// while avoiding excessive TIME_WAIT iteration overhead.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Monotonic timestamp in milliseconds
    /// * `sweep_time_wait` - If true, also check TIME_WAIT expiry and SYN queue timeouts
    ///
    /// # Design
    ///
    /// The function performs:
    /// 1. Updates the cached time_wait_clock for new TIME_WAIT transitions
    /// 2. Data segment retransmission (always, for responsive RTO)
    /// 3. FIN retransmission (always, needed for graceful close)
    /// 4. TIME_WAIT expiry cleanup (only when sweep_time_wait=true)
    /// 5. SYN queue timeout cleanup (only when sweep_time_wait=true)
    ///
    /// The two-phase approach (collect then cleanup) avoids holding locks
    /// across cleanup operations which may wake blocked processes.
    ///
    /// # Safety
    ///
    /// R150-1 FIX: This function must NOT be called from hard IRQ context.
    /// It allocates heap memory (Vec, build_tcp_segment → Vec<u8>) and may
    /// transmit packets (transmit_tcp_segment → device spinlock + DMA alloc).
    ///
    /// Uses try_lock on the sockets lock to avoid blocking. If the lock is
    /// held, the sweep is skipped and returns `false`.
    /// R65-6 FIX: Returns `true` if timer sweep completed successfully, `false` if
    /// skipped due to lock contention (caller should defer work to safe context).
    pub fn run_tcp_timers(&self, current_time_ms: u64, sweep_time_wait: bool) -> bool {
        // Update cached time so RX path can stamp new TIME_WAIT transitions
        self.time_wait_clock
            .store(current_time_ms, Ordering::Relaxed);

        // Collect sockets for cleanup and FIN retransmissions
        let mut to_cleanup: Vec<Arc<SocketState>> = Vec::new();
        let mut fin_retransmit: Vec<(Ipv4Addr, Vec<u8>, u64)> = Vec::new();
        // Data segment retransmissions (TCP retransmission RFC 6298)
        let mut data_retransmit: Vec<(Ipv4Addr, Vec<u8>, u64)> = Vec::new();
        // R149-2 FIX: Track whether any expired SYN entries were detected
        // (non-destructive; actual removal deferred to blocking path).
        let mut has_expired_syn = false;

        // R62-4 FIX: Avoid timer starvation under lock contention.
        // Previously, try_read failure would skip the entire sweep, allowing
        // TIME_WAIT and SYN queue entries to accumulate indefinitely under flood.
        // Now we retry with spin hints to increase chance of success.
        // Note: We avoid blocking read since this may be called from timer context.
        // If still contended after retries, we skip but increment a counter for monitoring.
        let sockets_guard = {
            let mut guard_opt = None;
            // Try non-blocking read up to 5 times with spin hint
            for _ in 0..5 {
                if let Some(g) = self.sockets.try_read() {
                    guard_opt = Some(g);
                    break;
                }
                // Yield to allow writer to complete
                core::hint::spin_loop();
            }
            match guard_opt {
                Some(g) => g,
                None => {
                    // Still contended - skip this sweep but don't starve indefinitely
                    // The next timer tick will retry. Under sustained flood, some sweeps
                    // will succeed between write bursts.
                    // R63-5 FIX: Track skipped sweeps for monitoring/alerting
                    self.timer_sweeps_skipped.fetch_add(1, Ordering::Relaxed);
                    // R65-6 FIX: Return false to signal incomplete - caller should defer
                    return false;
                }
            }
        };

        for sock in sockets_guard.values() {
            // Get socket metadata for FIN retransmission
            let meta = sock.meta_snapshot();
            let key_parts = match (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                (Some(li), Some(lp), Some(ri), Some(rp)) => Some((li, lp, ri, rp)),
                _ => None,
            };

            // Use try_lock to avoid blocking on per-socket lock
            let mut tcp_guard = match sock.tcp.try_lock() {
                Some(guard) => guard,
                None => continue, // Skip this socket, try next
            };

            let mut should_cleanup = false;
            let mut need_init_timestamp = false;
            let mut need_init_fin_time = false;
            let mut need_fin_retransmit = false;
            let mut mark_timeout_close = false;

            if let Some(tcp_state) = tcp_guard.as_mut() {
                // TIME_WAIT handling
                // R53-3: TIME_WAIT expiry check only runs on slow timer (1s cadence)
                // to reduce iteration overhead. Timestamp init always runs.
                if tcp_state.control.state == TcpState::TimeWait {
                    let start = tcp_state.control.time_wait_start;
                    if start == 0 {
                        need_init_timestamp = true;
                    } else if sweep_time_wait
                        && current_time_ms.saturating_sub(start) >= TCP_TIME_WAIT_MS
                    {
                        should_cleanup = true;
                    }
                }

                // R65-5 FIX: FIN_WAIT_2 idle timeout handling
                //
                // Without this timeout, connections can remain in FIN_WAIT_2 indefinitely
                // if the peer never sends their FIN. This creates a resource exhaustion
                // vulnerability: an attacker can establish many connections, send FIN,
                // and never complete the close sequence.
                //
                // Linux uses tcp_fin_timeout sysctl (default 60 seconds). We implement
                // the same approach: if no FIN is received within the timeout, clean up
                // the connection to reclaim resources.
                if tcp_state.control.state == TcpState::FinWait2 && sweep_time_wait {
                    let start = tcp_state.control.fin_wait2_start;
                    if start != 0
                        && current_time_ms.saturating_sub(start) >= TCP_FIN_WAIT_2_TIMEOUT_MS
                    {
                        // Timeout expired - peer never sent FIN, cleanup connection
                        should_cleanup = true;
                        mark_timeout_close = true;
                    }
                }

                // FIN retransmission handling for FIN_WAIT_1 / CLOSING / LAST_ACK
                if matches!(
                    tcp_state.control.state,
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                ) && tcp_state.control.fin_sent
                {
                    let fin_start = tcp_state.control.fin_sent_time;
                    if fin_start == 0 {
                        need_init_fin_time = true;
                    } else {
                        let fin_timeout =
                            core::cmp::max(tcp_state.control.rto_ms, TCP_FIN_TIMEOUT_MS);
                        if current_time_ms.saturating_sub(fin_start) >= fin_timeout {
                            if tcp_state.control.fin_retries >= TCP_MAX_FIN_RETRIES {
                                // Max retries exceeded - cleanup connection
                                should_cleanup = true;
                            } else {
                                // Need to retransmit FIN
                                need_fin_retransmit = true;
                            }
                        }
                    }
                }

                // Data retransmission: check send_buffer for segments past RTO
                // This handles reliable delivery for established connections
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if !tcp_state.control.send_buffer.is_empty()
                        && matches!(
                            tcp_state.control.state,
                            TcpState::Established
                                | TcpState::CloseWait
                                | TcpState::FinWait1
                                | TcpState::FinWait2
                                | TcpState::Closing
                                | TcpState::LastAck
                        )
                    {
                        let rto = tcp_state.control.rto_ms;
                        let ack = tcp_state.control.rcv_nxt;
                        // R58: Use scaled window advertisement
                        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                        // RFC 5681 §3.1: On RTO, check if FIRST unacked segment has timed out
                        // If so, enter loss recovery FIRST (cwnd = 1*SMSS), then retransmit
                        // only the first segment. Do NOT retransmit entire send buffer.
                        //
                        // Use two-phase approach to avoid borrow conflict:
                        // 1. Check timeout with immutable borrow
                        // 2. Enter loss recovery
                        // 3. Build retransmit segment with mutable borrow
                        let needs_retransmit = tcp_state
                            .control
                            .send_buffer
                            .front()
                            .map(|seg| current_time_ms.saturating_sub(seg.sent_at) >= rto)
                            .unwrap_or(false);

                        if needs_retransmit {
                            // RFC 5681: Enter loss recovery BEFORE retransmitting
                            // This sets ssthresh = max(FlightSize/2, 2*SMSS) and cwnd = 1*SMSS
                            handle_retransmission_timeout(&mut tcp_state.control);

                            // RFC 6675: Clear SACK scoreboard on RTO — all SACKed/lost flags
                            // become stale after timeout-based recovery resets the send state.
                            tcp_state.control.sack_clear_scoreboard();

                            // RFC 5681 §3.1: Retransmit ONLY the first unacked segment
                            if let Some(first_seg) = tcp_state.control.send_buffer.front_mut() {
                                let flags = TCP_FLAG_ACK
                                    | if !first_seg.data.is_empty() {
                                        TCP_FLAG_PSH
                                    } else {
                                        0
                                    };
                                let seg_bytes = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    first_seg.seq,
                                    ack,
                                    flags,
                                    advertised_wnd,
                                    &first_seg.data,
                                );

                                // Update segment tracking
                                first_seg.retrans_count = first_seg.retrans_count.saturating_add(1);
                                first_seg.sent_at = current_time_ms;

                                // R57-1: Update activity timestamp for idle detection
                                tcp_state.control.last_activity = current_time_ms;

                                data_retransmit.push((remote_ip, seg_bytes, sock.net_ns_id.0));
                            }

                            // Exponential backoff: double RTO on each retransmission
                            tcp_state.control.retries = tcp_state.control.retries.saturating_add(1);
                            tcp_state.control.rto_ms = tcp_state
                                .control
                                .rto_ms
                                .saturating_mul(2)
                                .min(TCP_MAX_RTO_MS);

                            // Connection timeout: too many retries
                            if tcp_state.control.retries >= TCP_MAX_RETRIES {
                                tcp_state.control.state = TcpState::Closed;
                                should_cleanup = true;
                                mark_timeout_close = true;
                            }
                        }
                    }
                }
            }
            drop(tcp_guard);

            // Mark socket closed if connection timed out
            if mark_timeout_close {
                sock.mark_closed();
            }

            // Initialize TIME_WAIT timestamp if needed
            if need_init_timestamp {
                if let Some(mut guard) = sock.tcp.try_lock() {
                    if let Some(tcp_state) = guard.as_mut() {
                        if tcp_state.control.state == TcpState::TimeWait
                            && tcp_state.control.time_wait_start == 0
                        {
                            tcp_state.control.time_wait_start = current_time_ms;
                        }
                    }
                }
            }

            // Initialize FIN timestamp if needed
            if need_init_fin_time {
                if let Some(mut guard) = sock.tcp.try_lock() {
                    if let Some(tcp_state) = guard.as_mut() {
                        if matches!(
                            tcp_state.control.state,
                            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                        ) && tcp_state.control.fin_sent
                            && tcp_state.control.fin_sent_time == 0
                        {
                            tcp_state.control.fin_sent_time = current_time_ms;
                        }
                    }
                }
            }

            // Build FIN retransmission segment
            if need_fin_retransmit {
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if let Some(mut guard) = sock.tcp.try_lock() {
                        if let Some(tcp_state) = guard.as_mut() {
                            if matches!(
                                tcp_state.control.state,
                                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                            ) && tcp_state.control.fin_sent
                                && tcp_state.control.fin_retries < TCP_MAX_FIN_RETRIES
                            {
                                let window_after = tcp_state
                                    .control
                                    .rcv_wnd
                                    .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                                // FIN sequence is snd_nxt - 1 (since FIN consumed one seq number)
                                let seq = tcp_state.control.snd_nxt.wrapping_sub(1);
                                let ack = tcp_state.control.rcv_nxt;

                                let seg = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    seq,
                                    ack,
                                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                                    Self::encode_adv_window(&tcp_state.control, window_after),
                                    &[],
                                );

                                // Update retransmission bookkeeping
                                tcp_state.control.fin_retries =
                                    tcp_state.control.fin_retries.saturating_add(1);
                                tcp_state.control.fin_sent_time = current_time_ms;

                                fin_retransmit.push((remote_ip, seg, sock.net_ns_id.0));
                            }
                        }
                    }
                }
            }

            // Handle cleanup
            //
            // R53-1 FIX: Cleanup must handle both graceful shutdown states
            // (TimeWait, FinWait1, Closing, LastAck) AND connections closed
            // due to retransmission timeout (already in Closed state with
            // mark_timeout_close flag set).
            if should_cleanup {
                // Retransmission timeout case: socket already marked closed and
                // state set to Closed in the retransmission loop above
                if mark_timeout_close {
                    to_cleanup.push(sock.clone());
                } else if let Some(mut guard) = sock.tcp.try_lock() {
                    if let Some(tcp_state) = guard.as_mut() {
                        if tcp_state.control.state == TcpState::TimeWait
                            || matches!(
                                tcp_state.control.state,
                                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                            )
                        {
                            tcp_state.control.state = TcpState::Closed;
                            to_cleanup.push(sock.clone());
                        }
                    }
                }
            }

            // R52-1 FIX: Sweep half-open SYN queue for listening sockets
            //
            // Half-open connections (SYN received, SYN-ACK sent) that exceed
            // TCP_SYN_TIMEOUT_MS are cleaned up to prevent SYN flood resource
            // exhaustion. This ensures listeners can accept new connections
            // even under attack.
            //
            // R53-3: SYN queue cleanup only runs on slow timer (1s cadence)
            // to reduce iteration overhead for listening sockets.
            //
            // R149-2 FIX: In IRQ context, do NOT call take_syn() or perform
            // any destructive SYN queue operations. Only detect whether any
            // expired entries exist. All removal + cleanup is deferred to
            // run_tcp_timers_blocking() in process context. Without this,
            // take_syn() removes entries that are then dropped on the floor
            // when we return false, leaking half-open counter slots.
            if sweep_time_wait {
                if let Some(listen_guard) = sock.listen.try_lock() {
                    if let Some(listen_state) = listen_guard.as_ref() {
                        for (_key, pending) in listen_state.syn_queue.iter() {
                            if current_time_ms.saturating_sub(pending.syn_sent_at)
                                >= TCP_SYN_TIMEOUT_MS
                            {
                                // At least one expired SYN entry exists —
                                // mark for deferred blocking cleanup.
                                has_expired_syn = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        drop(sockets_guard);

        // R149-2 FIX: In IRQ context, NEVER perform blocking cleanup that
        // requires `sockets.write()`, `sock.tcp.lock()`, or `cleanup_tcp_connection()`.
        // If the timer IRQ interrupted a code path holding `sockets.read()`,
        // blocking `sockets.write()` would spin forever (reader can never release).
        //
        // All blocking cleanup is deferred to `run_tcp_timers_blocking()` in
        // process context (called from `drain_deferred_tcp_timers()`).
        // Only non-blocking network transmits (FIN/data retransmissions) proceed here.
        let needs_blocking_cleanup = !to_cleanup.is_empty() || has_expired_syn;

        // Transmit any pending FIN retransmissions (best-effort, no locks needed)
        for (dst_ip, seg, ns_id) in fin_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg, ns_id);
        }

        // Transmit data segment retransmissions (RFC 6298, no locks needed)
        for (dst_ip, seg, ns_id) in data_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg, ns_id);
        }

        // If any sockets need blocking cleanup, signal incomplete to caller
        // so work is deferred to safe (non-IRQ) context.
        if needs_blocking_cleanup {
            return false;
        }

        // R65-6 FIX: Signal successful completion to caller
        true
    }

    /// R65-6 FIX: Blocking variant of run_tcp_timers for safe (non-IRQ) context.
    ///
    /// Called from syscall return path to drain deferred timer work when IRQ-time
    /// processing was incomplete due to lock contention.
    ///
    /// Unlike run_tcp_timers(), this function uses blocking locks and is guaranteed
    /// to complete (unless the kernel is severely broken). This ensures timer work
    /// is not starved indefinitely under sustained lock contention.
    ///
    /// # Returns
    ///
    /// Always `true` since blocking locks guarantee completion.
    pub fn run_tcp_timers_blocking(&self, current_time_ms: u64, sweep_time_wait: bool) -> bool {
        // Update cached time so RX path can stamp new TIME_WAIT transitions
        self.time_wait_clock
            .store(current_time_ms, Ordering::Relaxed);

        // Collect sockets for cleanup and FIN retransmissions
        let mut to_cleanup: Vec<Arc<SocketState>> = Vec::new();
        let mut fin_retransmit: Vec<(Ipv4Addr, Vec<u8>, u64)> = Vec::new();
        let mut data_retransmit: Vec<(Ipv4Addr, Vec<u8>, u64)> = Vec::new();
        let mut syn_timeouts: Vec<(Arc<SocketState>, Ipv4Addr, Option<Vec<u8>>)> = Vec::new();
        // R148-I3 FIX: Collect keepalive probes to send after releasing locks.
        // R160-8 FIX: Extended tuple includes conntrack seeding metadata.
        let mut keepalive_probes: Vec<(Ipv4Addr, Vec<u8>, u64, Ipv4Addr, u16, u16)> = Vec::new();
        // R148-3 FIX: Collect listeners for deferred SYN queue sweep outside
        // sockets lock. Sweeping under sockets.read() creates AB-BA deadlock
        // with the SYN handler path: sockets.read()->listen.lock() vs
        // listen.lock()->sockets.write().
        let mut listeners_to_sweep: Vec<Arc<SocketState>> = Vec::new();

        // R65-6 FIX: Use blocking read lock - safe in non-IRQ context
        let sockets_guard = self.sockets.read();

        for sock in sockets_guard.values() {
            let meta = sock.meta_snapshot();
            let key_parts = match (
                meta.local_ip.map(Ipv4Addr),
                meta.local_port,
                meta.remote_ip.map(Ipv4Addr),
                meta.remote_port,
            ) {
                (Some(li), Some(lp), Some(ri), Some(rp)) => Some((li, lp, ri, rp)),
                _ => None,
            };

            // R65-6 FIX: Use blocking lock for per-socket state
            let mut tcp_guard = sock.tcp.lock();

            let mut should_cleanup = false;
            let mut need_init_timestamp = false;
            let mut need_init_fin_time = false;
            let mut need_fin_retransmit = false;
            let mut mark_timeout_close = false;

            if let Some(tcp_state) = tcp_guard.as_mut() {
                // TIME_WAIT handling
                if tcp_state.control.state == TcpState::TimeWait {
                    let start = tcp_state.control.time_wait_start;
                    if start == 0 {
                        need_init_timestamp = true;
                    } else if sweep_time_wait
                        && current_time_ms.saturating_sub(start) >= TCP_TIME_WAIT_MS
                    {
                        should_cleanup = true;
                    }
                }

                // R65-5 FIX: FIN_WAIT_2 idle timeout handling
                if tcp_state.control.state == TcpState::FinWait2 && sweep_time_wait {
                    let start = tcp_state.control.fin_wait2_start;
                    if start != 0
                        && current_time_ms.saturating_sub(start) >= TCP_FIN_WAIT_2_TIMEOUT_MS
                    {
                        should_cleanup = true;
                        mark_timeout_close = true;
                    }
                }

                // FIN retransmission handling
                if matches!(
                    tcp_state.control.state,
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                ) && tcp_state.control.fin_sent
                {
                    let fin_start = tcp_state.control.fin_sent_time;
                    if fin_start == 0 {
                        need_init_fin_time = true;
                    } else {
                        let fin_timeout =
                            core::cmp::max(tcp_state.control.rto_ms, TCP_FIN_TIMEOUT_MS);
                        if current_time_ms.saturating_sub(fin_start) >= fin_timeout {
                            if tcp_state.control.fin_retries >= TCP_MAX_FIN_RETRIES {
                                should_cleanup = true;
                            } else {
                                need_fin_retransmit = true;
                            }
                        }
                    }
                }

                // Data retransmission
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if !tcp_state.control.send_buffer.is_empty()
                        && matches!(
                            tcp_state.control.state,
                            TcpState::Established
                                | TcpState::CloseWait
                                | TcpState::FinWait1
                                | TcpState::FinWait2
                                | TcpState::Closing
                                | TcpState::LastAck
                        )
                    {
                        let rto = tcp_state.control.rto_ms;
                        let ack = tcp_state.control.rcv_nxt;
                        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

                        let needs_retransmit = tcp_state
                            .control
                            .send_buffer
                            .front()
                            .map(|seg| current_time_ms.saturating_sub(seg.sent_at) >= rto)
                            .unwrap_or(false);

                        if needs_retransmit {
                            handle_retransmission_timeout(&mut tcp_state.control);

                            if let Some(first_seg) = tcp_state.control.send_buffer.front_mut() {
                                let flags = TCP_FLAG_ACK
                                    | if !first_seg.data.is_empty() {
                                        TCP_FLAG_PSH
                                    } else {
                                        0
                                    };
                                let seg_bytes = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    first_seg.seq,
                                    ack,
                                    flags,
                                    advertised_wnd,
                                    &first_seg.data,
                                );

                                first_seg.retrans_count = first_seg.retrans_count.saturating_add(1);
                                first_seg.sent_at = current_time_ms;
                                tcp_state.control.last_activity = current_time_ms;

                                data_retransmit.push((remote_ip, seg_bytes, sock.net_ns_id.0));
                            }

                            tcp_state.control.retries = tcp_state.control.retries.saturating_add(1);
                            tcp_state.control.rto_ms = tcp_state
                                .control
                                .rto_ms
                                .saturating_mul(2)
                                .min(TCP_MAX_RTO_MS);

                            if tcp_state.control.retries >= TCP_MAX_RETRIES {
                                tcp_state.control.state = TcpState::Closed;
                                should_cleanup = true;
                                mark_timeout_close = true;
                            }
                        }
                    }
                }

                // R148-I3 FIX: TCP keepalive probes per RFC 1122 §4.2.3.6.
                // Send probes only when idle (no outstanding data) in a state
                // where the connection should remain alive.
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    if tcp_state.control.keepalive_enabled
                        && tcp_state.control.send_buffer.is_empty()
                        && matches!(
                            tcp_state.control.state,
                            TcpState::Established | TcpState::CloseWait
                        )
                        && tcp_state.control.last_activity != 0
                    {
                        let idle_ms =
                            current_time_ms.saturating_sub(tcp_state.control.last_activity);
                        let probes_sent = tcp_state.control.keepalive_probes_sent as u64;
                        let threshold = tcp_state.control.keepalive_idle_ms
                            + probes_sent * tcp_state.control.keepalive_interval_ms;

                        if idle_ms >= threshold {
                            if tcp_state.control.keepalive_probes_sent
                                >= tcp_state.control.keepalive_probes_max
                            {
                                // Connection dead — too many unanswered probes
                                tcp_state.control.state = TcpState::Closed;
                                should_cleanup = true;
                                mark_timeout_close = true;
                            } else {
                                // Send keepalive probe: seq = snd_una - 1 to elicit ACK
                                let advertised_wnd =
                                    Self::current_adv_window(&tcp_state.control);
                                let probe = build_tcp_segment(
                                    local_ip,
                                    remote_ip,
                                    local_port,
                                    remote_port,
                                    tcp_state.control.snd_una.wrapping_sub(1),
                                    tcp_state.control.rcv_nxt,
                                    TCP_FLAG_ACK,
                                    advertised_wnd,
                                    &[],
                                );
                                tcp_state.control.keepalive_probes_sent =
                                    tcp_state.control.keepalive_probes_sent.saturating_add(1);
                                keepalive_probes.push((remote_ip, probe, sock.net_ns_id.0, local_ip, local_port, remote_port));
                            }
                        }
                    }
                }
            }
            drop(tcp_guard);

            if mark_timeout_close {
                sock.mark_closed();
            }

            // Initialize TIME_WAIT timestamp if needed
            if need_init_timestamp {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    if tcp_state.control.state == TcpState::TimeWait
                        && tcp_state.control.time_wait_start == 0
                    {
                        tcp_state.control.time_wait_start = current_time_ms;
                    }
                }
            }

            // Initialize FIN timestamp if needed
            if need_init_fin_time {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    if matches!(
                        tcp_state.control.state,
                        TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                    ) && tcp_state.control.fin_sent
                        && tcp_state.control.fin_sent_time == 0
                    {
                        tcp_state.control.fin_sent_time = current_time_ms;
                    }
                }
            }

            // Build FIN retransmission segment
            if need_fin_retransmit {
                if let Some((local_ip, local_port, remote_ip, remote_port)) = key_parts {
                    let mut guard = sock.tcp.lock();
                    if let Some(tcp_state) = guard.as_mut() {
                        if matches!(
                            tcp_state.control.state,
                            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                        ) && tcp_state.control.fin_sent
                            && tcp_state.control.fin_retries < TCP_MAX_FIN_RETRIES
                        {
                            let window_after = tcp_state
                                .control
                                .rcv_wnd
                                .saturating_sub(tcp_state.control.recv_buffer.len() as u32);
                            let seq = tcp_state.control.snd_nxt.wrapping_sub(1);
                            let ack = tcp_state.control.rcv_nxt;

                            let seg = build_tcp_segment(
                                local_ip,
                                remote_ip,
                                local_port,
                                remote_port,
                                seq,
                                ack,
                                TCP_FLAG_FIN | TCP_FLAG_ACK,
                                Self::encode_adv_window(&tcp_state.control, window_after),
                                &[],
                            );

                            tcp_state.control.fin_retries =
                                tcp_state.control.fin_retries.saturating_add(1);
                            tcp_state.control.fin_sent_time = current_time_ms;

                            fin_retransmit.push((remote_ip, seg, sock.net_ns_id.0));
                        }
                    }
                }
            }

            // Handle cleanup
            if should_cleanup {
                if mark_timeout_close {
                    to_cleanup.push(sock.clone());
                } else {
                    let mut guard = sock.tcp.lock();
                    if let Some(tcp_state) = guard.as_mut() {
                        if tcp_state.control.state == TcpState::TimeWait
                            || matches!(
                                tcp_state.control.state,
                                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                            )
                        {
                            tcp_state.control.state = TcpState::Closed;
                            to_cleanup.push(sock.clone());
                        }
                    }
                }
            }

            // R148-3 FIX: Defer SYN queue sweep outside sockets lock to avoid
            // AB-BA deadlock with the RX SYN handler path.
            if sweep_time_wait && sock.is_listening() {
                listeners_to_sweep.push(sock.clone());
            }
        }

        drop(sockets_guard);

        // R148-3 FIX: Sweep SYN queues after releasing sockets lock. The RX
        // SYN handler acquires listen.lock() then sockets.write(); sweeping
        // under sockets.read() then listen.lock() would create AB-BA deadlock.
        if sweep_time_wait {
            for listener in &listeners_to_sweep {
                let mut listen_guard = listener.listen.lock();
                if let Some(listen_state) = listen_guard.as_mut() {
                    let mut expired_keys: Vec<TcpLookupKey> = Vec::new();
                    for (key, pending) in listen_state.syn_queue.iter() {
                        if current_time_ms.saturating_sub(pending.syn_sent_at) >= TCP_SYN_TIMEOUT_MS
                        {
                            expired_keys.push(*key);
                        }
                    }

                    for key in expired_keys {
                        if let Some(pending) = listen_state.take_syn(&key, self) {
                            let rst_seg = {
                                let mut tcb_guard = pending.sock.tcp.lock();
                                if let Some(tcb) = tcb_guard.as_mut() {
                                    // R106-10 FIX: key.0 is now NamespaceId; IPs/ports shifted by 1
                                    let local_ip = Ipv4Addr(key.1.to_be_bytes());
                                    let remote_ip = Ipv4Addr(key.3.to_be_bytes());
                                    let seq = tcb.control.snd_nxt;
                                    let ack = tcb.control.rcv_nxt;

                                    Some(build_tcp_segment(
                                        local_ip,
                                        remote_ip,
                                        key.2,
                                        key.4,
                                        seq,
                                        ack,
                                        TCP_FLAG_RST | TCP_FLAG_ACK,
                                        0,
                                        &[],
                                    ))
                                } else {
                                    None
                                }
                            };

                            syn_timeouts.push((
                                pending.sock.clone(),
                                Ipv4Addr(key.3.to_be_bytes()),
                                rst_seg,
                            ));
                        }
                    }
                }
            }
        }

        // Cleanup phase (outside sockets lock)
        let mut ids_to_remove: Vec<u64> = Vec::new();
        for sock in &to_cleanup {
            self.cleanup_tcp_connection(sock);
            if sock.is_closed() {
                ids_to_remove.push(sock.id);
            }
        }

        for (child, dst_ip, rst_seg) in syn_timeouts {
            let child_ns = child.net_ns_id.0;
            child.mark_closed();
            self.cleanup_tcp_connection(&child);
            if let Some(seg) = rst_seg {
                let _ = transmit_tcp_segment(dst_ip, &seg, child_ns);
            }
            ids_to_remove.push(child.id);
        }

        // R129-2 FIX: Mirror the non-blocking sweep path (run_tcp_timers) and
        // decrement per-namespace socket count when actually removing sockets.
        // For sockets already removed by cleanup_tcp_connection (mark_closed path),
        // remove() returns None and dec_ns_count is not called (no double-decrement).
        let mut ns_ids_to_decrement: Vec<NamespaceId> = Vec::new();
        if !ids_to_remove.is_empty() {
            let mut sockets = self.sockets.write();
            for id in ids_to_remove {
                if let Some(sock) = sockets.remove(&id) {
                    ns_ids_to_decrement.push(sock.net_ns_id);
                }
            }
        }
        for ns_id in ns_ids_to_decrement {
            self.dec_ns_count(ns_id);
        }

        for (dst_ip, seg, ns_id) in fin_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg, ns_id);
        }

        for (dst_ip, seg, ns_id) in data_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg, ns_id);
        }

        // R148-I3 + R160-8 FIX: Send keepalive probes with conntrack seeding.
        // Without conntrack refresh, idle connections could see their conntrack
        // entry expire while the socket layer still considers the connection alive.
        for (dst_ip, seg, ns_id, local_ip, local_port, remote_port) in keepalive_probes {
            #[cfg(feature = "conntrack")]
            {
                use crate::conntrack::ct_process_tcp;
                let _ = ct_process_tcp(
                    ns_id, local_ip, dst_ip, local_port, remote_port,
                    TCP_FLAG_ACK, 0, current_time_ms,
                );
            }
            let _ = transmit_tcp_segment(dst_ip, &seg, ns_id);
        }

        // Blocking variant always succeeds
        true
    }

    /// Clean up TCP connection resources (bindings and 4-tuple registration).
    ///
    /// Called when a connection is aborted (RST received, timeout, error) or
    /// when graceful shutdown completes (LAST_ACK→CLOSED, TIME_WAIT expiry).
    ///
    /// If the socket was marked closed by close() (indicating graceful shutdown
    /// initiated by the local side), this function also removes the socket from
    /// the sockets map to prevent memory leaks.
    fn cleanup_tcp_connection(&self, sock: &Arc<SocketState>) {
        let meta = sock.meta_snapshot();

        // R51-1 FIX: Only remove local port binding if this socket owns it.
        // Child sockets from passive open share the listener's port binding,
        // so we must not unbind the port when cleaning up a child socket.
        // R75-1 FIX: Use namespace-scoped binding key.
        if let Some(port) = meta.local_port {
            let binding_key = (sock.net_ns_id, port);
            // J2-8 / R169-6 slice 2: ptr-eq-gated, KIND-GATED teardown (the
            // R51-1 ownership check is folded into the expect_ptr — a
            // passive-open child sharing the listener's port leaves the
            // listener binding intact). This is the funnel for RX-RST / sweep /
            // abort / TIME_WAIT-evict and runs under the L8 binding lock in
            // RX-reachable context, so a reclaimed charge is ENQUEUED for
            // deferred uncharge — never uncharged inline.
            //
            // is_closed() gate (load-bearing): is_closed() is set ONLY by
            // close()/mark_closed — the TCB-Closed transitions (abort_tcp_connect,
            // forced TIME_WAIT evict) do NOT set it.
            // - is_closed() == true: TERMINAL teardown (the graceful-close
            //   funnel — the socket is removed from `sockets` below). Remove
            //   the binding KIND-AGNOSTICALLY: hold-until-close ends HERE for
            //   an Explicit binding; deferring to the dead-Weak sweep would
            //   only add reclaim latency.
            // - is_closed() == false: the socket SURVIVES (RST-on-Established,
            //   abort-for-retry, forced TIME_WAIT eviction of a never-closed
            //   socket). Kind-gated: an own charged Explicit binding is
            //   PURE-SKIPPED (POSIX hold-until-close — the still-open FD owns
            //   the port; a retry connect() reuses it with the charge intact;
            //   if the owner is later dropped without close(), the
            //   kind-agnostic dead-Weak triad reclaims the charge exactly
            //   once); an own charged Ephemeral is removed + enqueued +
            //   local-cleared (ghost-bind fix below).
            let action = {
                let mut bindings = self.tcp_bindings.lock();
                if sock.is_closed() {
                    TeardownAction::Removed(Self::remove_binding_charged(
                        &mut bindings,
                        binding_key,
                        Some(Arc::as_ptr(sock)),
                    ))
                } else {
                    Self::resolve_while_alive_teardown(
                        &mut bindings,
                        binding_key,
                        Arc::as_ptr(sock),
                    )
                }
            };
            if let TeardownAction::Removed(Some(cgid)) = action {
                self.enqueue_port_uncharge(cgid, 1);
                // Ghost-bind clear: without this, local_port survives as a
                // charge-less "ghost bind" — the retry sees local_port == Some
                // -> did_alloc == false -> re-inserts the binding UNCHARGED,
                // undercounting live ports and bypassing ports.max. Reachable
                // for a charged-EPHEMERAL removal and for the TERMINAL
                // (is_closed) removal only (a surviving charged Explicit took
                // SkipExplicit; uncharged/foreign yield Removed(None)), so a
                // live user's explicit bind is never silently cleared. (For a
                // fully-closed socket the clear is a harmless no-op — it is
                // removed from `sockets` below anyway.)
                let mut m = sock.meta.lock();
                m.local_ip = None;
                m.local_port = None;
            }
        }

        // Remove namespace + 4-tuple from connection map
        if let (Some(lip), Some(lport), Some(rip), Some(rport)) = (
            meta.local_ip,
            meta.local_port,
            meta.remote_ip,
            meta.remote_port,
        ) {
            let key = tcp_map_key_from_parts(sock.net_ns_id, Ipv4Addr(lip), lport, Ipv4Addr(rip), rport);
            if self.tcp_conns.lock().remove(&key).is_some() {
                // J2-1: uncharge the per-namespace connection (bound to tcp_conns
                // membership, independent of counted_in_active).
                self.dec_ns_conn(key.0);
                // R121-3 FIX: Only decrement the global active connection counter
                // if this socket was previously counted via try_inc_active_conn()
                // in queue_accept(). Client-initiated connections (sys_connect)
                // are never counted, so decrementing them would artificially lower
                // the counter and weaken connection-flood DoS protection.
                if sock.counted_in_active.load(Ordering::Acquire) {
                    dec_active_conn();
                }
            }
        }

        // Clear remote metadata to allow retry
        {
            let mut meta = sock.meta.lock();
            meta.remote_ip = None;
            meta.remote_port = None;
        }

        // Close and wake TCP waiters before dropping the TCB
        let mut tcp_guard = sock.tcp.lock();
        if let Some(tcp_state) = tcp_guard.as_mut() {
            tcp_state.state_waiters.close();
            tcp_state.state_waiters.wake_all();
            tcp_state.data_waiters.close();
            tcp_state.data_waiters.wake_all();
            // J2-6: uncharge the residual per-namespace send bytes before the TCB is
            // dropped. LOAD-BEARING for the path where is_closed() is false below
            // (the Arc lives on with the TCB nulled, so impl Drop would find None
            // and uncharge 0 — this is then the only uncharge that runs). Mirrors
            // detach_tcp_uncharged under the already-held guard (no re-lock). Only
            // sock.tcp is held here (tcp_bindings/tcp_conns released above), so
            // per_ns_send_bytes stays a pure leaf.
            let charged = tcp_state.control.ns_charged_send_bytes;
            if charged > 0 {
                self.uncharge_ns_send_residual(sock.net_ns_id, charged);
                tcp_state.control.ns_charged_send_bytes = 0;
            }
            // J2-4: symmetric recv-byte residual uncharge (LOAD-BEARING on the
            // is_closed()==false path: the Arc lives on with the TCB nulled, so Drop
            // later finds None and this is the only recv uncharge that runs).
            let rcharged = tcp_state.control.ns_charged_recv_bytes;
            if rcharged > 0 {
                self.uncharge_ns_recv_residual(sock.net_ns_id, rcharged);
                tcp_state.control.ns_charged_recv_bytes = 0;
            }
        }
        *tcp_guard = None;
        drop(tcp_guard);

        // If socket was marked closed by close() (graceful shutdown path),
        // remove it from the sockets map to complete cleanup and prevent leak.
        // This handles the case where close() kept the socket registered for
        // FIN/ACK handling and the TCP state machine has now completed.
        // R129-2 FIX: When removing from sockets map, also decrement per-namespace
        // socket count. This fixes a leak where SynReceived sockets aborted via
        // invalid ACK or accept-queue-full had try_inc_ns_count() called at
        // creation but dec_ns_count() was never called on abort. The is_some()
        // guard prevents double-decrement when close_socket() or sweep_time_wait
        // already removed the socket from the map.
        if sock.is_closed() {
            if self.sockets.write().remove(&sock.id).is_some() {
                self.dec_ns_count(sock.net_ns_id);
            }
        }
    }

    /// R50-3 FIX: Abort an in-flight outbound TCP connection (timeout/reset path).
    ///
    /// Called from sys_connect when a blocking connect times out to ensure
    /// TCB and port bindings are properly released.
    ///
    /// # Arguments
    ///
    /// * `sock` - The socket with a connection attempt to abort
    pub fn abort_tcp_connect(&self, sock: &Arc<SocketState>) {
        // Transition TCB to Closed state
        {
            let mut guard = sock.tcp.lock();
            if let Some(tcp_state) = guard.as_mut() {
                tcp_state.control.state = TcpState::Closed;
            }
        }
        // Clean up all connection resources
        self.cleanup_tcp_connection(sock);
    }

    /// Build a TCP RST segment for invalid/unknown connections.
    ///
    /// R63-4 FIX: Returns `None` if RST rate limit is exceeded.
    ///
    /// Per RFC 793:
    /// - If ACK was set: RST seq = incoming ACK number, no ACK flag
    /// - If ACK was not set: RST seq = 0, ACK = incoming SEQ + segment length
    fn build_tcp_rst(
        &self,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // R63-4 FIX: Rate limit RST responses to prevent amplification attacks
        if !allow_rst(self.time_wait_now()) {
            return None;
        }

        let is_ack = header.flags & TCP_FLAG_ACK != 0;
        let is_syn = header.flags & TCP_FLAG_SYN != 0;
        let is_fin = header.flags & 0x01 != 0; // FIN flag

        if is_ack {
            // RFC 793: <SEQ=SEG.ACK><CTL=RST>
            Some(build_tcp_segment(
                local_ip,
                remote_ip,
                header.dst_port,
                header.src_port,
                header.ack_num,
                0,
                TCP_FLAG_RST,
                0,
                &[],
            ))
        } else {
            // RFC 793: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            let mut seg_len = payload.len() as u32;
            if is_syn {
                seg_len = seg_len.wrapping_add(1);
            }
            if is_fin {
                seg_len = seg_len.wrapping_add(1);
            }
            let ack_num = header.seq_num.wrapping_add(seg_len);

            Some(build_tcp_segment(
                local_ip,
                remote_ip,
                header.dst_port,
                header.src_port,
                0,
                ack_num,
                TCP_FLAG_RST | TCP_FLAG_ACK,
                0,
                &[],
            ))
        }
    }
}

/// Socket table statistics.
#[derive(Debug, Clone, Copy)]
pub struct TableStats {
    pub created: u64,
    pub closed: u64,
    pub active: usize,
    pub bound_ports: usize,
    /// R63-5 FIX: Timer sweeps skipped due to lock contention
    pub timer_sweeps_skipped: u64,
    /// P0-2 FIX: Forced TIME_WAIT evictions to admit SYN cookie completions
    pub forced_tw_evictions: u64,
}

// ============================================================================
// Global Singleton
// ============================================================================

static SOCKET_TABLE: Once<SocketTable> = Once::new();

/// Get the global socket table.
pub fn socket_table() -> &'static SocketTable {
    SOCKET_TABLE.call_once(SocketTable::new)
}

// ============================================================================
// Helpers
// ============================================================================

/// Convert IPv4 bytes to u64 for LSM context.
#[inline]
fn ipv4_to_u64(bytes: [u8; 4]) -> u64 {
    u32::from_be_bytes(bytes) as u64
}

/// R106-10 FIX: Build TCP lookup key from namespace + connection parts.
#[inline]
fn tcp_map_key_from_parts(
    net_ns_id: NamespaceId,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> TcpLookupKey {
    (
        net_ns_id,
        u32::from_be_bytes(local_ip.0),
        local_port,
        u32::from_be_bytes(remote_ip.0),
        remote_port,
    )
}

/// R106-10 FIX: Build TCP lookup key from namespace + TcpConnKey.
#[inline]
#[allow(dead_code)]
fn tcp_map_key_from_conn_key(net_ns_id: NamespaceId, key: &TcpConnKey) -> TcpLookupKey {
    (
        net_ns_id,
        u32::from_be_bytes(key.local_ip.0),
        key.local_port,
        u32::from_be_bytes(key.remote_ip.0),
        key.remote_port,
    )
}

// ============================================================================
// R74-5 Test Helpers: Expose counter state for runtime testing
// ============================================================================

/// Get current half-open connection count for testing.
///
/// R74-5 Enhancement: Used by runtime tests to verify atomic counter behavior.
pub fn test_get_half_open_count() -> u32 {
    GLOBAL_HALF_OPEN_COUNT.load(Ordering::Relaxed)
}

/// Get current active connection count for testing.
///
/// R74-5 Enhancement: Used by runtime tests to verify atomic counter behavior.
pub fn test_get_active_conn_count() -> u32 {
    GLOBAL_ACTIVE_CONN_COUNT.load(Ordering::Relaxed)
}

/// Get the maximum half-open connection limit for testing.
pub fn test_get_max_half_open() -> u32 {
    GLOBAL_MAX_HALF_OPEN
}

/// Test atomic increment of half-open counter (public wrapper for testing).
///
/// R74-5 Enhancement: Verifies atomic `fetch_update` behavior.
/// Returns true if increment succeeded (under limit), false if at limit.
pub fn test_try_inc_half_open() -> bool {
    try_inc_half_open()
}

/// Test decrement of half-open counter (public wrapper for testing).
pub fn test_dec_half_open() {
    dec_half_open()
}

/// Test atomic increment of active connection counter (public wrapper for testing).
///
/// R74-5 Enhancement: Verifies atomic `fetch_update` behavior.
/// Returns true if increment succeeded (under limit), false if at limit.
pub fn test_try_inc_active_conn() -> bool {
    try_inc_active_conn()
}

/// Test decrement of active connection counter (public wrapper for testing).
pub fn test_dec_active_conn() {
    dec_active_conn()
}

/// Reset counters to zero for test isolation.
///
/// # Safety
/// Only call from test code when no real network activity is happening.
pub fn test_reset_counters() {
    GLOBAL_HALF_OPEN_COUNT.store(0, Ordering::Relaxed);
    GLOBAL_ACTIVE_CONN_COUNT.store(0, Ordering::Relaxed);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_domain_from_raw() {
        assert_eq!(SocketDomain::from_raw(2), Some(SocketDomain::Inet4));
        assert_eq!(SocketDomain::from_raw(0), None);
        assert_eq!(SocketDomain::from_raw(10), None); // AF_INET6
    }

    #[test]
    fn test_socket_type_from_raw() {
        assert_eq!(SocketType::from_raw(2), Some(SocketType::Dgram));
        assert_eq!(SocketType::from_raw(1), Some(SocketType::Stream)); // SOCK_STREAM
    }

    #[test]
    fn test_socket_protocol_from_raw() {
        // UDP tests
        assert_eq!(
            SocketProtocol::from_raw(17, SocketType::Dgram),
            Some(SocketProtocol::Udp)
        );
        assert_eq!(
            SocketProtocol::from_raw(0, SocketType::Dgram),
            Some(SocketProtocol::Udp)
        );
        // TCP tests
        assert_eq!(
            SocketProtocol::from_raw(6, SocketType::Stream),
            Some(SocketProtocol::Tcp)
        );
        assert_eq!(
            SocketProtocol::from_raw(0, SocketType::Stream),
            Some(SocketProtocol::Tcp)
        );
        // Invalid
        assert_eq!(SocketProtocol::from_raw(99, SocketType::Dgram), None);
    }

    #[test]
    fn test_ipv4_to_u64() {
        assert_eq!(ipv4_to_u64([192, 168, 1, 1]), 0xC0A80101);
        assert_eq!(ipv4_to_u64([0, 0, 0, 0]), 0);
        assert_eq!(ipv4_to_u64([255, 255, 255, 255]), 0xFFFFFFFF);
    }
}
