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
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once, RwLock};

use cap::CapId;
use lsm::{
    hook_net_bind, hook_net_connect, hook_net_listen, hook_net_recv, hook_net_send,
    hook_net_shutdown, hook_net_socket, LsmError, NetCtx, ProcessCtx,
};

use crate::ipv4::Ipv4Addr;
use crate::stack::transmit_tcp_segment;
use crate::tcp::{
    build_tcp_segment, build_tcp_segment_with_options, calc_wscale, decode_window, encode_window,
    generate_isn, generate_syn_cookie_isn, handle_ack, handle_retransmission_timeout, initial_cwnd,
    seq_ge, seq_gt, seq_in_window, syn_cookie_select_mss, update_congestion_control,
    validate_cwnd_after_idle, validate_syn_cookie, CongestionAction, TcpConnKey, TcpControlBlock,
    TcpHeader, TcpOptionKind, TcpOptions, TcpSegment, TcpState, TCP_DEFAULT_WINDOW,
    TCP_ETHERNET_MSS, TCP_FIN_TIMEOUT_MS, TCP_FIN_WAIT_2_TIMEOUT_MS, TCP_FLAG_ACK, TCP_FLAG_FIN,
    TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_MAX_ACCEPT_BACKLOG, TCP_MAX_ACTIVE_CONNECTIONS,
    TCP_MAX_FIN_RETRIES, TCP_MAX_RETRIES, TCP_MAX_RTO_MS, TCP_MAX_SEND_SIZE, TCP_MAX_SYN_BACKLOG,
    TCP_MAX_WINDOW_SCALE, TCP_PROTO, TCP_SYN_TIMEOUT_MS, TCP_TIME_WAIT_MS,
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
    /// Wakeup counter (incremented on wake, read on wait to detect wakeup)
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

        // Consume any pending wake signal that arrived before we registered
        // to avoid sleeping despite a ready datagram.
        if self
            .wakeup_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current > 0).then(|| current - 1)
            })
            .is_ok()
        {
            return WaitOutcome::Woken;
        }

        // Delegate to scheduler hooks for true blocking
        if let Some(hooks) = socket_wait_hooks() {
            hooks.wait(self, timeout_ns)
        } else {
            // No scheduler hooks registered - fall back to non-blocking
            // This happens early in boot or in kernel threads
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
    // Check if we need to reset the window
    let window_start = CHALLENGE_ACK_WINDOW_START.load(Ordering::Relaxed);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= CHALLENGE_ACK_WINDOW_MS {
        // New window - reset tokens and update start time
        CHALLENGE_ACK_WINDOW_START.store(now_ms, Ordering::Relaxed);
        CHALLENGE_ACK_TOKENS.store(CHALLENGE_ACK_LIMIT, Ordering::Relaxed);
    }

    // Try to consume a token using CAS loop
    let mut tokens = CHALLENGE_ACK_TOKENS.load(Ordering::Relaxed);
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
    let window_start = RST_WINDOW_START.load(Ordering::Relaxed);
    if window_start == 0 || now_ms.saturating_sub(window_start) >= RST_RATE_WINDOW_MS {
        RST_WINDOW_START.store(now_ms, Ordering::Relaxed);
        RST_TOKENS.store(RST_RATE_LIMIT, Ordering::Relaxed);
    }

    let mut tokens = RST_TOKENS.load(Ordering::Relaxed);
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

/// TCP connection lookup key type (local_ip, local_port, remote_ip, remote_port)
///
/// Used for both active and passive TCP connection tracking.
type TcpLookupKey = (u32, u16, u32, u16);

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
    fn queue_syn(&mut self, entry: PendingSyn) -> bool {
        if self.syn_queue.len() >= self.syn_backlog {
            return false;
        }
        self.syn_queue.insert(entry.key, entry);
        true
    }

    /// Remove and return a half-open connection by key.
    fn take_syn(&mut self, key: &TcpLookupKey) -> Option<PendingSyn> {
        self.syn_queue.remove(key)
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
    pub fn new(
        id: u64,
        domain: SocketDomain,
        ty: SocketType,
        proto: SocketProtocol,
        label: SocketLabel,
    ) -> Self {
        SocketState {
            id,
            domain,
            ty,
            proto,
            label,
            refcount: AtomicU64::new(1),
            meta: Mutex::new(SocketMeta::new()),
            rx_queue: Mutex::new(VecDeque::new()),
            waiters: WaitQueue::new(),
            closed: AtomicBool::new(false),
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
    /// (queue full or socket closed).
    fn enqueue_rx(&self, pkt: PendingDatagram) -> bool {
        if self.is_closed() {
            return false;
        }

        let mut queue = self.rx_queue.lock();
        if queue.len() >= MAX_RX_QUEUE {
            self.rx_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.rx_bytes
            .fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        queue.push_back(pkt);
        drop(queue);

        self.waiters.wake_one();
        true
    }

    /// Pop the next received datagram from the queue.
    fn pop_rx(&self) -> Option<PendingDatagram> {
        self.rx_queue.lock().pop_front()
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
    /// UDP layer error
    Udp(UdpError),
    /// LSM policy denial
    Lsm(LsmError),
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

/// Global socket table: tracks all sockets and port bindings.
///
/// Thread-safe via RwLock (read-heavy) and Mutex (write operations).
pub struct SocketTable {
    /// Next socket ID (monotonically increasing)
    next_socket_id: AtomicU64,
    /// Next ephemeral port seed
    next_ephemeral: AtomicU16,
    /// All active sockets (socket_id -> SocketState)
    sockets: RwLock<BTreeMap<u64, Arc<SocketState>>>,
    /// UDP port bindings (port -> weak ref to socket)
    udp_bindings: Mutex<BTreeMap<u16, Weak<SocketState>>>,
    /// TCP local port bindings
    tcp_bindings: Mutex<BTreeMap<u16, Weak<SocketState>>>,
    /// Active TCP connections keyed by 4-tuple
    tcp_conns: Mutex<BTreeMap<TcpLookupKey, Weak<SocketState>>>,
    /// Last observed timestamp (ms) used for TIME_WAIT bookkeeping.
    /// Updated by sweep_time_wait() and used by RX path when transitioning to TIME_WAIT.
    time_wait_clock: AtomicU64,
    /// R63-5 FIX: Timer sweeps skipped due to lock contention
    timer_sweeps_skipped: AtomicU64,
    /// Statistics
    created: AtomicU64,
    closed_count: AtomicU64,
    bind_count: AtomicU64,
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
    /// This is a convenience method for computing the window advertisement
    /// when buffer state is already available in the TCB.
    #[inline]
    fn current_adv_window(tcb: &TcpControlBlock) -> u16 {
        let available = tcb.rcv_wnd.saturating_sub(tcb.recv_buffer.len() as u32);
        Self::encode_adv_window(tcb, available)
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
            time_wait_clock: AtomicU64::new(0),
            timer_sweeps_skipped: AtomicU64::new(0),
            created: AtomicU64::new(0),
            closed_count: AtomicU64::new(0),
            bind_count: AtomicU64::new(0),
        }
    }

    /// Create a UDP socket.
    ///
    /// # Security
    ///
    /// - Invokes `hook_net_socket` for LSM policy check
    /// - Captures creator context in socket label
    ///
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_udp_socket(&self, label: SocketLabel) -> Result<Arc<SocketState>, SocketError> {
        // Build LSM context
        let mut ctx = NetCtx::new(0, UDP_PROTO as u16);
        ctx.cap = Some(CapId::INVALID);

        // Check LSM policy
        hook_net_socket(&label.creator, &ctx)?;

        // Allocate socket ID
        let id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);

        // Create socket state
        let sock = Arc::new(SocketState::new(
            id,
            SocketDomain::Inet4,
            SocketType::Dgram,
            SocketProtocol::Udp,
            label,
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
    /// # Returns
    ///
    /// Arc to the new socket state, ready to be wrapped in a CapEntry.
    pub fn create_tcp_socket(&self, label: SocketLabel) -> Result<Arc<SocketState>, SocketError> {
        // Build LSM context
        let mut ctx = NetCtx::new(0, TCP_PROTO as u16);
        ctx.cap = Some(CapId::INVALID);

        // Check LSM policy
        hook_net_socket(&label.creator, &ctx)?;

        // Allocate socket ID
        let id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);

        // Create socket state
        let sock = Arc::new(SocketState::new(
            id,
            SocketDomain::Inet4,
            SocketType::Stream,
            SocketProtocol::Tcp,
            label,
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
    /// # Returns
    ///
    /// The bound port number on success.
    pub fn bind_udp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Dgram || sock.proto != SocketProtocol::Udp {
            return Err(SocketError::InvalidType);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // Determine port
        let chosen_port = if let Some(p) = port {
            // R49-3 FIX: Privileged port check uses flag from syscall layer
            // This ensures NET_BIND_SERVICE capability is properly honored
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_port()?
        };

        // Build LSM context with actual CapId and current context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

        // Check LSM policy using CURRENT process context
        hook_net_bind(current, &ctx)?;

        // Register port binding
        {
            let mut bindings = self.udp_bindings.lock();

            // Check for existing binding (race condition prevention)
            if let Some(existing) = bindings.get(&chosen_port) {
                if existing.upgrade().is_some() {
                    return Err(SocketError::PortInUse);
                }
                // R47-3 FIX: Remove stale weak reference
                bindings.remove(&chosen_port);
            }

            bindings.insert(chosen_port, Arc::downgrade(sock));
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
    pub fn bind_tcp(
        &self,
        sock: &Arc<SocketState>,
        current: &ProcessCtx,
        cap_id: CapId,
        ip: Ipv4Addr,
        port: Option<u16>,
        can_bind_privileged: bool,
    ) -> Result<u16, SocketError> {
        // Validate socket type
        if sock.ty != SocketType::Stream || sock.proto != SocketProtocol::Tcp {
            return Err(SocketError::InvalidType);
        }

        // Check if already bound
        if sock.local_port().is_some() {
            return Err(SocketError::PortInUse);
        }

        // Determine port
        let chosen_port = if let Some(p) = port {
            if p < PRIVILEGED_PORT_LIMIT && !can_bind_privileged {
                return Err(SocketError::PrivilegedPort);
            }
            p
        } else {
            self.alloc_ephemeral_tcp_port()?
        };

        // Build LSM context
        let mut ctx = self.ctx_from_socket(sock);
        ctx.local = ipv4_to_u64(ip.0);
        ctx.local_port = chosen_port;
        ctx.cap = Some(cap_id);

        // Check LSM policy
        hook_net_bind(current, &ctx)?;

        // Register port binding
        {
            let mut bindings = self.tcp_bindings.lock();

            // Check for existing binding
            if let Some(existing) = bindings.get(&chosen_port) {
                if existing.upgrade().is_some() {
                    return Err(SocketError::PortInUse);
                }
                bindings.remove(&chosen_port);
            }

            bindings.insert(chosen_port, Arc::downgrade(sock));
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
            let _ = self.bind_tcp(sock, current, cap_id, local_ip, None, can_bind_privileged)?;
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
    fn lookup_tcp_listener(&self, local_port: u16) -> Option<Arc<SocketState>> {
        let mut bindings = self.tcp_bindings.lock();
        match bindings.get(&local_port).and_then(|w| w.upgrade()) {
            Some(sock) if sock.is_listening() => Some(sock),
            Some(_) => None, // Bound but not listening
            None => {
                bindings.remove(&local_port); // Clean up stale weak ref
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
                self.bind_udp(sock, current, cap_id, src_ip, None, false)?
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
        let local_port = match sock.local_port() {
            Some(p) => p,
            None => self.alloc_ephemeral_tcp_port()?,
        };
        let local_ip = sock.local_ip().map(Ipv4Addr).unwrap_or(src_ip);

        // Build the connection key for uniqueness check
        let conn_key = tcp_map_key_from_parts(local_ip, local_port, dst_ip, dst_port);

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

        // Track what we've registered for cleanup on failure
        let mut binding_registered = false;
        let mut conn_registered = false;

        // Register local port binding and connection 4-tuple
        // This is done AFTER LSM check to prevent resource leaks on denial
        let registration_result: Result<(), SocketError> = (|| {
            // Register local port in tcp_bindings
            {
                let mut bindings = self.tcp_bindings.lock();
                if let Some(existing) = bindings.get(&local_port) {
                    if let Some(existing_sock) = existing.upgrade() {
                        if !Arc::ptr_eq(&existing_sock, sock) {
                            return Err(SocketError::PortInUse);
                        }
                    }
                }
                bindings.insert(local_port, Arc::downgrade(sock));
                binding_registered = true;
            }

            // Register connection 4-tuple
            {
                let mut conns = self.tcp_conns.lock();

                // R50-5 IMPROVEMENT: Prune stale Weak entries before counting
                // This prevents false exhaustion when connections have been dropped
                // but their Weak references haven't been cleaned up yet
                conns.retain(|_, weak| weak.strong_count() > 0);

                // R50-5 FIX: Enforce global TCP connection limit to prevent resource exhaustion
                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                    return Err(SocketError::NoPorts);
                }
                // Re-check after lock acquisition (race-safe)
                if conns.get(&conn_key).and_then(|w| w.upgrade()).is_some() {
                    return Err(SocketError::PortInUse);
                }
                conns.insert(conn_key, Arc::downgrade(sock));
                conn_registered = true;
            }

            Ok(())
        })();

        // On registration failure, clean up any partial registrations
        if let Err(e) = registration_result {
            if conn_registered {
                self.tcp_conns.lock().remove(&conn_key);
            }
            if binding_registered {
                self.tcp_bindings.lock().remove(&local_port);
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

        // Calculate scaled window for SYN
        let syn_wnd = Self::encode_adv_window(&tcb, tcb.rcv_wnd);
        sock.attach_tcp(tcb);

        // Build the SYN segment with Window Scale option
        let syn_options = [TcpOptionKind::WindowScale(
            sock.tcp.lock().as_ref().unwrap().control.rcv_wscale,
        )];
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
                        self.tcp_bindings.lock().remove(&local_port);
                        self.tcp_conns.lock().remove(&conn_key);
                        return Err(SocketError::Closed);
                    }
                    // Still in SYN_SENT or other intermediate state
                    return Err(SocketError::InProgress);
                }
                WaitOutcome::TimedOut => {
                    // Timeout - the SYN was sent but no response
                    // Clean up resources to allow retry or close
                    self.tcp_bindings.lock().remove(&local_port);
                    self.tcp_conns.lock().remove(&conn_key);
                    // Reset socket metadata to allow retry after close
                    {
                        let mut meta = sock.meta.lock();
                        meta.remote_ip = None;
                        meta.remote_port = None;
                    }
                    // Clear TCB
                    *sock.tcp.lock() = None;
                    return Err(SocketError::Timeout);
                }
                WaitOutcome::Closed => {
                    self.tcp_bindings.lock().remove(&local_port);
                    self.tcp_conns.lock().remove(&conn_key);
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

            // Try to get a datagram
            if let Some(pkt) = sock.pop_rx() {
                // Build LSM context with actual CapId
                let mut ctx = self.ctx_from_socket(sock);
                ctx.remote = ipv4_to_u64(pkt.src_ip.0);
                ctx.remote_port = pkt.src_port;
                ctx.cap = Some(cap_id); // R47-2 FIX: Pass actual CapId

                // Check LSM policy using CURRENT process context
                hook_net_recv(current, &ctx, pkt.data.len())?;

                return Ok(pkt);
            }

            // Block on wait queue
            match sock.waiters.wait_with_timeout(timeout_ns) {
                WaitOutcome::Woken => continue,
                WaitOutcome::TimedOut => return Err(SocketError::Timeout),
                WaitOutcome::Closed => return Err(SocketError::Closed),
                WaitOutcome::NoProcess => return Err(SocketError::NoProcess),
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

        // Get current sequence numbers
        let base_seq = tcp_state.control.snd_nxt;
        let ack = tcp_state.control.rcv_nxt;

        // R58: Advertise our scaled receive window
        let advertised_wnd = Self::current_adv_window(&tcp_state.control);

        // TCP segmentation: split payload into MSS-sized chunks
        let mss = TCP_ETHERNET_MSS as usize;
        let mut segments = Vec::with_capacity((payload.len() + mss - 1) / mss.max(1));
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

            // Buffer segment for potential retransmission
            // This enables reliable delivery: segments are kept until ACKed
            tcp_state.control.send_buffer.push_back(TcpSegment {
                seq,
                data: seg_payload.to_vec(),
                sent_at: now_ms,
                retrans_count: 0,
            });

            segments.push(segment);
            offset = end;
        }

        // Update send next sequence number
        tcp_state.control.snd_nxt = base_seq.wrapping_add(payload.len() as u32);

        // R57-1: Record activity timestamp for idle detection (RFC 2861)
        tcp_state.control.last_activity = now_ms;

        drop(guard);

        // Update statistics
        sock.tx_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        Ok((payload.len(), segments))
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
                    let mut data = Vec::new();
                    let take = core::cmp::min(max_len, tcp_state.control.recv_buffer.len());

                    for _ in 0..take {
                        if let Some(b) = tcp_state.control.recv_buffer.pop_front() {
                            data.push(b);
                        }
                    }

                    drop(guard);

                    // LSM check for recv delivery
                    let mut ctx = self.ctx_from_socket(sock);
                    ctx.cap = Some(cap_id);
                    hook_net_recv(current, &ctx, data.len())?;

                    // Update statistics
                    sock.rx_bytes
                        .fetch_add(data.len() as u64, Ordering::Relaxed);

                    return Ok(data);
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
    /// # Returns
    ///
    /// `true` if delivered to a socket, `false` if no listener.
    pub fn deliver_udp(
        &self,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        data: &[u8],
        now_ticks: u64,
    ) -> bool {
        // Look up bound socket
        let target = {
            let mut bindings = self.udp_bindings.lock();
            match bindings.get(&dst_port).and_then(|w| w.upgrade()) {
                Some(sock) => Some(sock),
                None => {
                    // R47-3 FIX: Clean up stale binding if upgrade failed
                    bindings.remove(&dst_port);
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

        // R47-4 FIX: Check queue capacity BEFORE copying
        // This prevents memory exhaustion from large datagrams
        {
            let queue = sock.rx_queue.lock();
            if queue.len() >= MAX_RX_QUEUE {
                sock.rx_dropped.fetch_add(1, Ordering::Relaxed);
                return true; // Socket exists but queue full - don't report no listener
            }
        }

        // Now safe to allocate memory for the datagram (LSM approved, queue has space)
        let pkt = PendingDatagram {
            src_ip,
            src_port,
            data: data.to_vec(),
            received_at: now_ticks,
        };

        // Enqueue (enqueue_rx may still drop if race condition)
        sock.enqueue_rx(pkt)
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
        let mut fin_to_send: Option<(Ipv4Addr, Vec<u8>)> = None;

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
                                fin_to_send = Some((remote_ip, fin_segment));
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
                                fin_to_send = Some((remote_ip, fin_segment));
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
        } else if let Some(sock) = self.sockets.write().remove(&socket_id) {
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
                        }
                    }
                    // Collect established-but-not-accepted queue children
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

            // Remove port bindings based on protocol
            if let Some(port) = meta.local_port {
                match sock.proto {
                    SocketProtocol::Udp => {
                        self.udp_bindings.lock().remove(&port);
                    }
                    SocketProtocol::Tcp => {
                        self.tcp_bindings.lock().remove(&port);
                    }
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
                    let key = tcp_map_key_from_parts(Ipv4Addr(lip), lport, Ipv4Addr(rip), rport);
                    self.tcp_conns.lock().remove(&key);
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
        }

        // Transmit FIN after releasing locks to avoid blocking critical sections.
        if let Some((dst_ip, segment)) = fin_to_send {
            let _ = transmit_tcp_segment(dst_ip, &segment);
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
    fn alloc_ephemeral_port(&self) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let bindings = self.udp_bindings.lock();

        // Phase 1: Random selection using CSPRNG (preferred)
        // Try 2x range to give good coverage while limiting iterations
        for _ in 0..(range.saturating_mul(2)) {
            // Try CSPRNG first, fall back to RDTSC-based hash if RNG unavailable
            let seed = security::rng::random_u32()
                .map(|r| r as u16)
                .unwrap_or_else(|_| self.fallback_port_seed());
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            if !bindings.contains_key(&candidate) {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback (guarantees finding free port if one exists)
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            if !bindings.contains_key(&candidate) {
                return Ok(candidate);
            }
        }

        Err(SocketError::NoPorts)
    }

    /// Allocate an ephemeral port for TCP (ensures no existing TCP socket uses it).
    ///
    /// R59-1 FIX: Use CSPRNG for port randomization to prevent off-path attacks.
    /// Predictable ephemeral ports enable connection hijacking and blind injection.
    fn alloc_ephemeral_tcp_port(&self) -> Result<u16, SocketError> {
        let range = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let tcp_bindings = self.tcp_bindings.lock();
        let tcp_conns = self.tcp_conns.lock();

        // Phase 1: Random selection using CSPRNG (preferred)
        for _ in 0..(range.saturating_mul(2)) {
            // R59-2 FIX: Use RDTSC-based fallback instead of predictable counter
            let seed = security::rng::random_u32()
                .map(|r| r as u16)
                .unwrap_or_else(|_| self.fallback_port_seed());
            let candidate = EPHEMERAL_PORT_START + (seed % range);

            // Check if port is in use by TCP bindings or connections
            if tcp_bindings.contains_key(&candidate) {
                continue;
            }
            // Also check if any connection uses this as local port
            let in_use = tcp_conns.keys().any(|(_, port, _, _)| *port == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }

        // Phase 2: Deterministic sweep fallback
        for offset in 0..range {
            let candidate = EPHEMERAL_PORT_START + offset;
            if tcp_bindings.contains_key(&candidate) {
                continue;
            }
            let in_use = tcp_conns.keys().any(|(_, port, _, _)| *port == candidate);
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

    /// Look up a TCP connection by 4-tuple, removing stale entries.
    ///
    /// # Arguments
    /// * `local_ip` - Our IP (destination in incoming packet)
    /// * `local_port` - Our port (destination port in incoming packet)
    /// * `remote_ip` - Peer IP (source in incoming packet)
    /// * `remote_port` - Peer port (source port in incoming packet)
    pub fn lookup_tcp_conn(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<Arc<SocketState>> {
        let key = tcp_map_key_from_parts(local_ip, local_port, remote_ip, remote_port);
        let mut conns = self.tcp_conns.lock();
        match conns.get(&key).and_then(|w| w.upgrade()) {
            Some(sock) => Some(sock),
            None => {
                // Clean up stale weak reference
                conns.remove(&key);
                None
            }
        }
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
    /// # Returns
    /// TCP segment to transmit (ACK or RST) if a response is required.
    pub fn process_tcp_segment(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        header: &TcpHeader,
        payload: &[u8],
        options: &TcpOptions,
    ) -> Option<Vec<u8>> {
        // RFC 793/5961: Handle RST segments with sequence validation
        if header.flags & TCP_FLAG_RST != 0 {
            // If we have a connection, validate RST before accepting
            if let Some(sock) =
                self.lookup_tcp_conn(dst_ip, header.dst_port, src_ip, header.src_port)
            {
                let mut guard = sock.tcp.lock();
                if let Some(tcp_state) = guard.as_mut() {
                    let old_state = tcp_state.control.state;

                    // R50-4 FIX: Validate RST sequence/ack per RFC 5961 before honoring
                    // This prevents off-path RST injection attacks
                    let accept_rst = match old_state {
                        TcpState::SynSent => {
                            // In SYN_SENT: RST is valid if ACK acknowledges our SYN
                            header.ack_num == tcp_state.control.snd_nxt
                        }
                        TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::CloseWait
                        | TcpState::Closing
                        | TcpState::LastAck => {
                            // In synchronized states: RST must be in receive window
                            let wnd = tcp_state.control.rcv_wnd.max(1);
                            seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, wnd)
                        }
                        _ => false, // Ignore RST in other states
                    };

                    if !accept_rst {
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

                    if old_state == TcpState::SynSent || old_state == TcpState::Established {
                        tcp_state.control.state = TcpState::Closed;
                        drop(guard);

                        // Clean up connection resources
                        self.cleanup_tcp_connection(&sock);
                        sock.wake_tcp_waiters();
                    }
                }
            }
            return None;
        }

        // Look up existing connection by 4-tuple
        let sock = match self.lookup_tcp_conn(dst_ip, header.dst_port, src_ip, header.src_port) {
            Some(s) => s,
            None => {
                // R51-1: Passive open handling for inbound SYN
                let is_syn = header.flags & TCP_FLAG_SYN != 0;
                let is_ack = header.flags & TCP_FLAG_ACK != 0;

                // Pure SYN (without ACK) indicates new connection request
                if is_syn && !is_ack {
                    if let Some(listener) = self.lookup_tcp_listener(header.dst_port) {
                        let mut listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_mut() {
                            let syn_key = tcp_map_key_from_parts(
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

                            // Enforce global connection limit before allocating resources
                            {
                                let mut conns = self.tcp_conns.lock();
                                conns.retain(|_, weak| weak.strong_count() > 0);
                                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                    // Connection limit reached - silently drop SYN
                                    return None;
                                }
                                // Check if 4-tuple already exists (race condition guard)
                                if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                    return None;
                                }
                            }

                            // SYN Cookie Path: If SYN queue is full, use stateless SYN-ACK
                            // This prevents SYN flood attacks from exhausting resources
                            if listen_state.syn_queue.len() >= listen_state.syn_backlog {
                                // Generate SYN cookie ISN (encodes 4-tuple, time, MSS)
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
                                return Some(syn_ack);
                            }

                            // Create child socket inheriting listener properties
                            let child_id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
                            let child = Arc::new(SocketState::new(
                                child_id,
                                listener.domain,
                                listener.ty,
                                listener.proto,
                                listener.label,
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

                            // Build SYN-ACK segment with MSS and optional WSopt
                            // RFC 793: SYN consumes 1 sequence number
                            let syn_ack = if options.window_scale.is_some() {
                                // Include MSS and WSopt in response
                                let our_scale = {
                                    let guard = child.tcp.lock();
                                    guard.as_ref().map(|ts| ts.control.rcv_wscale).unwrap_or(0)
                                };
                                let syn_ack_options = [
                                    TcpOptionKind::Mss(cookie_mss),
                                    TcpOptionKind::WindowScale(our_scale),
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
                                // Include MSS only
                                let syn_ack_options = [TcpOptionKind::Mss(cookie_mss)];
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

                            // Register connection for demux
                            {
                                let mut conns = self.tcp_conns.lock();
                                conns.insert(syn_key, Arc::downgrade(&child));
                            }

                            // Queue half-open connection in SYN queue
                            let pending = PendingSyn {
                                key: syn_key,
                                sock: child.clone(),
                                syn_ack: syn_ack.clone(),
                                syn_sent_at: now_ms,
                            };

                            // SYN cookie path handles the backlog-full case above,
                            // so queue_syn should always succeed here
                            if listen_state.queue_syn(pending) {
                                return Some(syn_ack);
                            }

                            // Cleanup (shouldn't happen given the check above)
                            self.tcp_conns.lock().remove(&syn_key);
                            self.sockets.write().remove(&child_id);
                            return None;
                        }
                    }
                }

                // SYN Cookie Validation Path: If this is an ACK with no half-open
                // connection, it might be completing a SYN cookie handshake
                let is_ack = header.flags & TCP_FLAG_ACK != 0;
                let is_syn = header.flags & TCP_FLAG_SYN != 0;

                if is_ack && !is_syn {
                    if let Some(listener) = self.lookup_tcp_listener(header.dst_port) {
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
                                dst_ip,
                                header.dst_port,
                                src_ip,
                                header.src_port,
                            );

                            // Check limits before creating connection
                            {
                                let mut conns = self.tcp_conns.lock();
                                conns.retain(|_, weak| weak.strong_count() > 0);
                                if conns.len() >= TCP_MAX_ACTIVE_CONNECTIONS {
                                    // Connection limit reached
                                    return None;
                                }
                                // Check for duplicate (race condition guard)
                                if conns.get(&syn_key).and_then(|w| w.upgrade()).is_some() {
                                    return None;
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

                            // Create child socket for the connection
                            let child_id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
                            let child = Arc::new(SocketState::new(
                                child_id,
                                listener.domain,
                                listener.ty,
                                listener.proto,
                                listener.label,
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

                            // Register connection
                            {
                                let mut conns = self.tcp_conns.lock();
                                conns.insert(syn_key, Arc::downgrade(&child));
                            }

                            // Add to accept queue
                            if !listener.push_accept_ready(child.clone()) {
                                // Accept queue became full between check and push
                                child.mark_closed();
                                self.cleanup_tcp_connection(&child);
                                return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                            }

                            // Wake waiting accept()
                            child.wake_tcp_waiters();

                            // No response needed - connection is established
                            return None;
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

                // RFC 793: In SYN-SENT, must receive SYN+ACK
                // A pure ACK or other segment should elicit RST
                if !is_ack {
                    // No ACK flag - ignore (could be simultaneous open SYN)
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
                handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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
                    // Update snd_una to acknowledge sent data and refresh RTT/RTO
                    let ack_update =
                        handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

                    // R58: Decode peer's advertised window once for both dup-ACK check and update
                    let peer_adv_wnd =
                        decode_window(header.window, tcp_state.control.effective_snd_wscale());

                    // RFC 5681 §3.2: Duplicate ACK definition
                    // A duplicate ACK must:
                    // - Have the same acknowledgment number as a previous ACK
                    // - Carry no data (payload empty)
                    // - NOT be a pure window update (window must be same as before)
                    // Segments with data or window changes are NOT duplicate ACKs
                    let is_window_update = peer_adv_wnd != tcp_state.control.snd_wnd;
                    let is_pure_dup_ack =
                        ack_update.duplicate && payload.is_empty() && !is_window_update;

                    // RFC 5681: Update congestion control and check for fast retransmit
                    // R55-1: Pass ack_num for NewReno partial ACK detection
                    let action = update_congestion_control(
                        &mut tcp_state.control,
                        ack_update.newly_acked,
                        is_pure_dup_ack,
                        header.ack_num,
                    );

                    // Handle congestion control actions
                    match action {
                        // Fast retransmit or partial ACK retransmit: resend first unacked segment
                        // R55-1: RetransmitNext handles NewReno partial ACK in fast recovery
                        CongestionAction::FastRetransmit | CongestionAction::RetransmitNext => {
                            if let Some(seg) = tcp_state.control.send_buffer.front_mut() {
                                let flags = TCP_FLAG_ACK
                                    | if !seg.data.is_empty() {
                                        TCP_FLAG_PSH
                                    } else {
                                        0
                                    };
                                seg.retrans_count = seg.retrans_count.saturating_add(1);
                                let now = self.time_wait_now();
                                seg.sent_at = now;
                                tcp_state.control.last_activity = now;

                                fast_retransmit_seg = Some(build_tcp_segment(
                                    dst_ip,
                                    src_ip,
                                    header.dst_port,
                                    header.src_port,
                                    seg.seq,
                                    tcp_state.control.rcv_nxt,
                                    flags,
                                    advertised_wnd,
                                    &seg.data,
                                ));
                            }
                        }
                        // R56-1: RFC 3042 Limited Transmit - signal that new data can be sent.
                        // The congestion control has determined conditions permit sending new data
                        // beyond the normal cwnd limit. Wake any blocked senders to utilize this.
                        CongestionAction::LimitedTransmit => {
                            // Wake blocked tcp_send() callers to send more data if available.
                            // Uses state_waiters as send window opening is similar to state change.
                            sock.wake_tcp_waiters();
                        }
                        CongestionAction::None => {}
                    }

                    // R50-2 FIX: Use seq_gt/seq_ge for wraparound-safe window update (RFC 793)
                    if seq_gt(header.seq_num, tcp_state.control.snd_wl1)
                        || (header.seq_num == tcp_state.control.snd_wl1
                            && seq_ge(header.ack_num, tcp_state.control.snd_wl2))
                    {
                        // R58: Use pre-decoded peer window for update
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
                let mut response: Option<Vec<u8>> = None;

                // Process incoming data if present
                if !payload.is_empty() {
                    // Recalculate window after ACK processing
                    let window_after_ack = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Check if segment is in-order (seq == rcv_nxt)
                    if header.seq_num != tcp_state.control.rcv_nxt {
                        // Out-of-order segment: send ACK with expected seq
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    // Drop data that would overrun the advertised receive window
                    if (payload.len() as u32) > window_after_ack {
                        let win_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(win_ack);
                    }

                    // LSM check before buffering data
                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        // LSM denied - silently drop
                        return None;
                    }

                    // Buffer the in-order data
                    tcp_state
                        .control
                        .recv_buffer
                        .extend(payload.iter().copied());

                    // Update rcv_nxt
                    tcp_state.control.rcv_nxt =
                        tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);

                    // Recalculate window after buffering
                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    // Build ACK for the received data
                    response = Some(build_tcp_segment(
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
                    data_received = true;
                }

                // RFC 793: Handle FIN flag - peer wants to close
                if is_fin {
                    // FIN must be in-order (seq_num == rcv_nxt after any data)
                    if header.seq_num.wrapping_add(payload.len() as u32)
                        != tcp_state.control.rcv_nxt
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

                    // FIN consumes 1 sequence number
                    tcp_state.control.rcv_nxt = tcp_state.control.rcv_nxt.wrapping_add(1);
                    tcp_state.control.fin_received = true;

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

                    // RFC 5681: If fast retransmit was triggered, transmit it now
                    // Priority: data ACK first (we already have one), fast retransmit happens via timer
                    // However, if the peer's ACK was a dup ACK, the data_ack response handles it
                    if let Some(fr_seg) = fast_retransmit_seg {
                        // Transmit fast retransmit segment asynchronously
                        let meta = sock.meta_snapshot();
                        if let Some(remote_ip) = meta.remote_ip.map(Ipv4Addr) {
                            let _ = transmit_tcp_segment(remote_ip, &fr_seg);
                        }
                    }

                    return Some(data_ack);
                }

                // RFC 5681: Handle fast retransmit even for pure ACK (no data response)
                if let Some(fr_seg) = fast_retransmit_seg {
                    drop(guard);
                    let meta = sock.meta_snapshot();
                    if let Some(remote_ip) = meta.remote_ip.map(Ipv4Addr) {
                        let _ = transmit_tcp_segment(remote_ip, &fr_seg);
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
                    handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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
                let mut response: Option<Vec<u8>> = None;

                // Process incoming data (we can still receive in FIN_WAIT_1)
                if !payload.is_empty() {
                    let window_after_ack = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    if header.seq_num != tcp_state.control.rcv_nxt {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    if (payload.len() as u32) > window_after_ack {
                        let win_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(win_ack);
                    }

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    tcp_state
                        .control
                        .recv_buffer
                        .extend(payload.iter().copied());
                    tcp_state.control.rcv_nxt =
                        tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    response = Some(build_tcp_segment(
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
                    data_received = true;
                }

                // Handle peer's FIN
                if is_fin {
                    let expected_fin_seq = tcp_state.control.rcv_nxt;
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

                    tcp_state.control.rcv_nxt = tcp_state.control.rcv_nxt.wrapping_add(1);
                    tcp_state.control.fin_received = true;

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
                    handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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

                let mut data_received = false;
                let mut response: Option<Vec<u8>> = None;

                // We can still receive data in FIN_WAIT_2
                if !payload.is_empty() {
                    let window_after_ack = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    if header.seq_num != tcp_state.control.rcv_nxt {
                        let dup_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(dup_ack);
                    }

                    if (payload.len() as u32) > window_after_ack {
                        let win_ack = build_tcp_segment(
                            dst_ip,
                            src_ip,
                            header.dst_port,
                            header.src_port,
                            tcp_state.control.snd_nxt,
                            tcp_state.control.rcv_nxt,
                            TCP_FLAG_ACK,
                            Self::encode_adv_window(&tcp_state.control, window_after_ack),
                            &[],
                        );
                        return Some(win_ack);
                    }

                    let mut ctx = self.ctx_from_socket(&sock);
                    ctx.remote = ipv4_to_u64(src_ip.0);
                    ctx.remote_port = header.src_port;
                    if hook_net_recv(&sock.label.creator, &ctx, payload.len()).is_err() {
                        return None;
                    }

                    tcp_state
                        .control
                        .recv_buffer
                        .extend(payload.iter().copied());
                    tcp_state.control.rcv_nxt =
                        tcp_state.control.rcv_nxt.wrapping_add(payload.len() as u32);

                    let window_after = tcp_state
                        .control
                        .rcv_wnd
                        .saturating_sub(tcp_state.control.recv_buffer.len() as u32);

                    response = Some(build_tcp_segment(
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
                    data_received = true;
                }

                // Handle peer's FIN
                if is_fin {
                    let expected_fin_seq = tcp_state.control.rcv_nxt;
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

                    tcp_state.control.rcv_nxt = tcp_state.control.rcv_nxt.wrapping_add(1);
                    tcp_state.control.fin_received = true;

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
                    handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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
                    handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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
                    handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());

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
                let seq_in_recv_window =
                    seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                // Do not collapse TIME_WAIT on out-of-window traffic; prevents spoofed
                // segments from forcing premature cleanup and RSTs on legitimate retransmits.
                if !seq_in_recv_window {
                    drop(guard);
                    return None;
                }

                // Handle retransmitted FIN from peer
                let mut fin_ack = None;
                if header.flags & TCP_FLAG_FIN != 0 {
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
                    tcp_map_key_from_parts(dst_ip, header.dst_port, src_ip, header.src_port);

                // Handle retransmitted SYN: resend cached SYN-ACK
                if is_syn && !is_ack {
                    if let Some(listener) = self.lookup_tcp_listener(header.dst_port) {
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
                let seq_ok = seq_in_window(header.seq_num, tcp_state.control.rcv_nxt, recv_wnd);

                if !ack_valid || !seq_ok {
                    // Invalid ACK - abort handshake, send RST
                    tcp_state.control.state = TcpState::Closed;
                    drop(guard);

                    // R51-1 FIX: Remove stale PendingSyn from listener's SYN queue
                    // before cleanup to prevent cached SYN-ACK responses to dead socket
                    if let Some(listener) = self.lookup_tcp_listener(header.dst_port) {
                        let mut listen_guard = listener.listen.lock();
                        if let Some(listen_state) = listen_guard.as_mut() {
                            listen_state.take_syn(&syn_key);
                        }
                    }

                    // R51-1 FIX (Codex): Mark socket closed before cleanup to ensure
                    // it's removed from sockets map (cleanup checks is_closed())
                    sock.mark_closed();
                    self.cleanup_tcp_connection(&sock);
                    return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                }

                // Handshake complete - transition to Established
                handle_ack(&mut tcp_state.control, header.ack_num, self.time_wait_now());
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

                drop(guard);

                // Remove from SYN queue and add to accept queue
                if let Some(listener) = self.lookup_tcp_listener(header.dst_port) {
                    let mut listen_guard = listener.listen.lock();
                    if let Some(listen_state) = listen_guard.as_mut() {
                        // Remove from SYN queue
                        listen_state.take_syn(&syn_key);
                    }
                    drop(listen_guard);

                    // Push to accept queue and wake accept() waiters
                    if !listener.push_accept_ready(sock.clone()) {
                        // Accept queue full - abort connection
                        // R51-1 FIX (Codex): Mark socket closed before cleanup
                        sock.mark_closed();
                        self.cleanup_tcp_connection(&sock);
                        return self.build_tcp_rst(dst_ip, src_ip, header, payload);
                    }
                }

                // Wake any waiters (accept queue changed)
                sock.wake_tcp_waiters();
                None
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

    /// Apply ACK processing with RFC 5681 congestion control.
    ///
    /// Combines `handle_ack()` and `update_congestion_control()` and returns
    /// a fast retransmit segment if triggered by triple duplicate ACK.
    ///
    /// # Arguments
    ///
    /// * `tcb` - TCP control block to update
    /// * `ack_num` - ACK number from incoming segment
    /// * `advertised_wnd` - Our current advertised window for response
    /// * `local_ip`, `remote_ip` - IP addresses for segment construction
    /// * `local_port`, `remote_port` - Ports for segment construction
    /// * `now_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// `Some(segment)` if fast retransmit was triggered, `None` otherwise.
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
    ) -> Option<Vec<u8>> {
        // Process ACK and get update info
        let ack_update = handle_ack(tcb, ack_num, now_ms);

        // Update congestion control and check for fast retransmit
        // R55-1: Pass ack_num for NewReno partial ACK detection
        let action =
            update_congestion_control(tcb, ack_update.newly_acked, ack_update.duplicate, ack_num);

        // Handle congestion control actions
        match action {
            // R55-1: Both FastRetransmit and RetransmitNext trigger segment retransmission
            CongestionAction::FastRetransmit | CongestionAction::RetransmitNext => {
                // Fast retransmit: resend first unacked segment
                if let Some(seg) = tcb.send_buffer.front_mut() {
                    let flags = TCP_FLAG_ACK
                        | if !seg.data.is_empty() {
                            TCP_FLAG_PSH
                        } else {
                            0
                        };
                    seg.retrans_count = seg.retrans_count.saturating_add(1);
                    seg.sent_at = now_ms;
                    tcb.last_activity = now_ms;

                    return Some(build_tcp_segment(
                        local_ip,
                        remote_ip,
                        local_port,
                        remote_port,
                        seg.seq,
                        tcb.rcv_nxt,
                        flags,
                        advertised_wnd,
                        &seg.data,
                    ));
                }
            }
            // R56-1: Limited Transmit - no segment to build here, caller handles wake
            CongestionAction::LimitedTransmit | CongestionAction::None => {}
        }

        None
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
    /// This function uses try_lock to avoid deadlock when called from timer
    /// interrupt context. If the sockets lock is held, the sweep is skipped
    /// and will be retried on the next timer tick.
    /// R65-6 FIX: Returns `true` if timer sweep completed successfully, `false` if
    /// skipped due to lock contention (caller should defer work to safe context).
    pub fn run_tcp_timers(&self, current_time_ms: u64, sweep_time_wait: bool) -> bool {
        // Update cached time so RX path can stamp new TIME_WAIT transitions
        self.time_wait_clock
            .store(current_time_ms, Ordering::Relaxed);

        // Collect sockets for cleanup and FIN retransmissions
        let mut to_cleanup: Vec<Arc<SocketState>> = Vec::new();
        let mut fin_retransmit: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();
        // Data segment retransmissions (TCP retransmission RFC 6298)
        let mut data_retransmit: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();
        // R52-1 FIX: Collect expired SYN queue entries for cleanup
        let mut syn_timeouts: Vec<(Arc<SocketState>, Ipv4Addr, Option<Vec<u8>>)> = Vec::new();

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

                                data_retransmit.push((remote_ip, seg_bytes));
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

                                fin_retransmit.push((remote_ip, seg));
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
            if sweep_time_wait {
                if let Some(mut listen_guard) = sock.listen.try_lock() {
                    if let Some(listen_state) = listen_guard.as_mut() {
                        // Collect expired keys first to avoid borrow issues
                        let mut expired_keys: Vec<TcpLookupKey> = Vec::new();
                        for (key, pending) in listen_state.syn_queue.iter() {
                            if current_time_ms.saturating_sub(pending.syn_sent_at)
                                >= TCP_SYN_TIMEOUT_MS
                            {
                                expired_keys.push(*key);
                            }
                        }

                        // Remove expired entries and queue for cleanup
                        for key in expired_keys {
                            if let Some(pending) = listen_state.take_syn(&key) {
                                // Build best-effort RST+ACK for the peer
                                let rst_seg =
                                    if let Some(mut tcb_guard) = pending.sock.tcp.try_lock() {
                                        if let Some(tcb) = tcb_guard.as_mut() {
                                            // Extract IP addresses from the key
                                            let local_ip = Ipv4Addr(key.0.to_be_bytes());
                                            let remote_ip = Ipv4Addr(key.2.to_be_bytes());
                                            let seq = tcb.control.snd_nxt;
                                            let ack = tcb.control.rcv_nxt;

                                            Some(build_tcp_segment(
                                                local_ip,
                                                remote_ip,
                                                key.1, // local_port
                                                key.3, // remote_port
                                                seq,
                                                ack,
                                                TCP_FLAG_RST | TCP_FLAG_ACK,
                                                0,
                                                &[],
                                            ))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                // Queue for cleanup outside locks
                                syn_timeouts.push((
                                    pending.sock.clone(),
                                    Ipv4Addr(key.2.to_be_bytes()),
                                    rst_seg,
                                ));
                            }
                        }
                    }
                }
            }
        }

        drop(sockets_guard);

        // Cleanup phase (outside sockets lock to avoid deadlock)
        // First, collect socket IDs to remove (those marked closed by close())
        let mut ids_to_remove: Vec<u64> = Vec::new();
        for sock in &to_cleanup {
            self.cleanup_tcp_connection(sock);
            // Remove from sockets map if socket was marked closed by close()
            // This handles the case where close() initiated graceful shutdown
            // and sweep_time_wait is completing the cleanup after TIME_WAIT
            if sock.is_closed() {
                ids_to_remove.push(sock.id);
            }
        }

        // R52-1 FIX: Cleanup expired SYN queue entries and send best-effort RSTs
        //
        // These child sockets were in SYN_RECEIVED state awaiting the final ACK
        // but timed out. We clean up their resources and optionally send RST to
        // notify the peer that the connection attempt failed.
        for (child, dst_ip, rst_seg) in syn_timeouts {
            child.mark_closed();
            self.cleanup_tcp_connection(&child);
            if let Some(seg) = rst_seg {
                let _ = transmit_tcp_segment(dst_ip, &seg);
            }
            ids_to_remove.push(child.id);
        }

        // Remove closed sockets from the sockets map
        if !ids_to_remove.is_empty() {
            let mut sockets = self.sockets.write();
            for id in ids_to_remove {
                sockets.remove(&id);
            }
        }

        // Transmit any pending FIN retransmissions (best-effort)
        for (dst_ip, seg) in fin_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg);
        }

        // Transmit data segment retransmissions (RFC 6298 TCP retransmission)
        for (dst_ip, seg) in data_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg);
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
        let mut fin_retransmit: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();
        let mut data_retransmit: Vec<(Ipv4Addr, Vec<u8>)> = Vec::new();
        let mut syn_timeouts: Vec<(Arc<SocketState>, Ipv4Addr, Option<Vec<u8>>)> = Vec::new();

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

                                data_retransmit.push((remote_ip, seg_bytes));
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

                            fin_retransmit.push((remote_ip, seg));
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

            // Sweep SYN queue for listening sockets
            if sweep_time_wait {
                let mut listen_guard = sock.listen.lock();
                if let Some(listen_state) = listen_guard.as_mut() {
                    let mut expired_keys: Vec<TcpLookupKey> = Vec::new();
                    for (key, pending) in listen_state.syn_queue.iter() {
                        if current_time_ms.saturating_sub(pending.syn_sent_at) >= TCP_SYN_TIMEOUT_MS
                        {
                            expired_keys.push(*key);
                        }
                    }

                    for key in expired_keys {
                        if let Some(pending) = listen_state.take_syn(&key) {
                            let rst_seg = {
                                let mut tcb_guard = pending.sock.tcp.lock();
                                if let Some(tcb) = tcb_guard.as_mut() {
                                    let local_ip = Ipv4Addr(key.0.to_be_bytes());
                                    let remote_ip = Ipv4Addr(key.2.to_be_bytes());
                                    let seq = tcb.control.snd_nxt;
                                    let ack = tcb.control.rcv_nxt;

                                    Some(build_tcp_segment(
                                        local_ip,
                                        remote_ip,
                                        key.1,
                                        key.3,
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
                                Ipv4Addr(key.2.to_be_bytes()),
                                rst_seg,
                            ));
                        }
                    }
                }
            }
        }

        drop(sockets_guard);

        // Cleanup phase (outside sockets lock)
        let mut ids_to_remove: Vec<u64> = Vec::new();
        for sock in &to_cleanup {
            self.cleanup_tcp_connection(sock);
            if sock.is_closed() {
                ids_to_remove.push(sock.id);
            }
        }

        for (child, dst_ip, rst_seg) in syn_timeouts {
            child.mark_closed();
            self.cleanup_tcp_connection(&child);
            if let Some(seg) = rst_seg {
                let _ = transmit_tcp_segment(dst_ip, &seg);
            }
            ids_to_remove.push(child.id);
        }

        if !ids_to_remove.is_empty() {
            let mut sockets = self.sockets.write();
            for id in ids_to_remove {
                sockets.remove(&id);
            }
        }

        for (dst_ip, seg) in fin_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg);
        }

        for (dst_ip, seg) in data_retransmit {
            let _ = transmit_tcp_segment(dst_ip, &seg);
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
        if let Some(port) = meta.local_port {
            let mut bindings = self.tcp_bindings.lock();
            if let Some(weak) = bindings.get(&port) {
                // Only remove if this binding points to us (not a listener)
                if weak.as_ptr() == Arc::as_ptr(sock) {
                    bindings.remove(&port);
                }
            }
        }

        // Remove 4-tuple from connection map
        if let (Some(lip), Some(lport), Some(rip), Some(rport)) = (
            meta.local_ip,
            meta.local_port,
            meta.remote_ip,
            meta.remote_port,
        ) {
            let key = tcp_map_key_from_parts(Ipv4Addr(lip), lport, Ipv4Addr(rip), rport);
            self.tcp_conns.lock().remove(&key);
        }

        // Clear remote metadata to allow retry
        {
            let mut meta = sock.meta.lock();
            meta.remote_ip = None;
            meta.remote_port = None;
        }

        // Close and wake TCP waiters before dropping the TCB
        let mut tcp_guard = sock.tcp.lock();
        if let Some(tcp_state) = tcp_guard.as_ref() {
            tcp_state.state_waiters.close();
            tcp_state.state_waiters.wake_all();
            tcp_state.data_waiters.close();
            tcp_state.data_waiters.wake_all();
        }
        *tcp_guard = None;
        drop(tcp_guard);

        // If socket was marked closed by close() (graceful shutdown path),
        // remove it from the sockets map to complete cleanup and prevent leak.
        // This handles the case where close() kept the socket registered for
        // FIN/ACK handling and the TCP state machine has now completed.
        if sock.is_closed() {
            self.sockets.write().remove(&sock.id);
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

/// Build TCP lookup key from connection parts.
#[inline]
fn tcp_map_key_from_parts(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> TcpLookupKey {
    (
        u32::from_be_bytes(local_ip.0),
        local_port,
        u32::from_be_bytes(remote_ip.0),
        remote_port,
    )
}

/// Build TCP lookup key from TcpConnKey.
#[inline]
#[allow(dead_code)]
fn tcp_map_key_from_conn_key(key: &TcpConnKey) -> TcpLookupKey {
    (
        u32::from_be_bytes(key.local_ip.0),
        key.local_port,
        u32::from_be_bytes(key.remote_ip.0),
        key.remote_port,
    )
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
