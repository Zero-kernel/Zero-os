//! Signal handling for Zero-OS
//!
//! Provides POSIX-like signal support including:
//! - Signal definitions (SIGKILL, SIGTERM, SIGSTOP, etc.)
//! - Pending signals bitmap per process
//! - Default signal actions
//! - Signal delivery mechanism

use crate::process::{self, ProcessId, ProcessState};
use crate::syscall::SyscallError;
use spin::Mutex;

/// Maximum signal number supported (1-64)
const MAX_SIGNAL: u8 = 64;

// ============================================================================
// 调度器集成回调
// ============================================================================

/// 恢复被暂停进程的回调类型
type ResumeCallback = fn(ProcessId) -> bool;

/// 全局恢复回调（由调度器注册）
static RESUME_CALLBACK: Mutex<Option<ResumeCallback>> = Mutex::new(None);

/// 注册恢复回调
///
/// 由调度器在初始化时调用，注册 resume_stopped 函数
pub fn register_resume_callback(callback: ResumeCallback) {
    *RESUME_CALLBACK.lock() = Some(callback);
}

/// 获取恢复回调
fn get_resume_callback() -> Option<ResumeCallback> {
    *RESUME_CALLBACK.lock()
}

/// Signal identifier (1-64, 0 is invalid)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(u8);

impl Signal {
    // Standard POSIX signals
    pub const SIGHUP: Signal = Signal(1); // Hangup
    pub const SIGINT: Signal = Signal(2); // Interrupt (Ctrl+C)
    pub const SIGQUIT: Signal = Signal(3); // Quit (Ctrl+\)
    pub const SIGILL: Signal = Signal(4); // Illegal instruction
    pub const SIGTRAP: Signal = Signal(5); // Trace/breakpoint trap
    pub const SIGABRT: Signal = Signal(6); // Abort
    pub const SIGBUS: Signal = Signal(7); // Bus error
    pub const SIGFPE: Signal = Signal(8); // Floating-point exception
    pub const SIGKILL: Signal = Signal(9); // Kill (cannot be caught/ignored)
    pub const SIGUSR1: Signal = Signal(10); // User-defined signal 1
    pub const SIGSEGV: Signal = Signal(11); // Segmentation fault
    pub const SIGUSR2: Signal = Signal(12); // User-defined signal 2
    pub const SIGPIPE: Signal = Signal(13); // Broken pipe
    pub const SIGALRM: Signal = Signal(14); // Alarm clock
    pub const SIGTERM: Signal = Signal(15); // Termination
    pub const SIGCHLD: Signal = Signal(17); // Child status changed
    pub const SIGCONT: Signal = Signal(18); // Continue if stopped
    pub const SIGSTOP: Signal = Signal(19); // Stop (cannot be caught/ignored)
    pub const SIGTSTP: Signal = Signal(20); // Stop typed at terminal
    pub const SIGTTIN: Signal = Signal(21); // Background read from tty
    pub const SIGTTOU: Signal = Signal(22); // Background write to tty

    /// Create signal from raw signal number
    pub fn from_raw(raw: i32) -> Result<Self, SignalError> {
        if raw <= 0 || raw > MAX_SIGNAL as i32 {
            return Err(SignalError::InvalidSignal);
        }
        Ok(Signal(raw as u8))
    }

    /// Create signal from 1-based index
    pub fn from_index(idx: u8) -> Option<Self> {
        if idx == 0 || idx > MAX_SIGNAL {
            None
        } else {
            Some(Signal(idx))
        }
    }

    /// Get raw signal number
    #[inline]
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Get signal number as i32 (for syscall compatibility)
    #[inline]
    pub fn as_i32(self) -> i32 {
        self.0 as i32
    }

    /// Get bit mask for this signal in pending signals bitmap
    #[inline]
    pub fn bit(self) -> u64 {
        1u64 << (self.0 - 1)
    }

    /// Check if this is a stop signal (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU)
    #[inline]
    pub fn is_stop(self) -> bool {
        matches!(self.0, 19 | 20 | 21 | 22)
    }

    /// Check if this is SIGCONT
    #[inline]
    pub fn is_continue(self) -> bool {
        self == Signal::SIGCONT
    }

    /// Check if this signal cannot be caught or ignored (SIGKILL, SIGSTOP)
    #[inline]
    pub fn is_uncatchable(self) -> bool {
        self == Signal::SIGKILL || self == Signal::SIGSTOP
    }
}

/// Pending signals bitmap (supports signals 1-64)
#[derive(Debug, Clone, Copy)]
pub struct PendingSignals {
    bits: u64,
}

impl PendingSignals {
    /// Create empty pending signals set
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Set a signal as pending
    #[inline]
    pub fn set(&mut self, signal: Signal) {
        self.bits |= signal.bit();
    }

    /// Clear a pending signal
    #[inline]
    pub fn clear(&mut self, signal: Signal) {
        self.bits &= !signal.bit();
    }

    /// Check if a specific signal is pending
    #[inline]
    pub fn is_pending(&self, signal: Signal) -> bool {
        (self.bits & signal.bit()) != 0
    }

    /// Check if any signal is pending
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.bits != 0
    }

    /// Take the next pending signal (lowest numbered first)
    pub fn take_next(&mut self) -> Option<Signal> {
        if self.bits == 0 {
            return None;
        }
        let idx = self.bits.trailing_zeros() as u8;
        self.bits &= !(1u64 << idx);
        Signal::from_index(idx + 1)
    }

    /// Get raw bits (for debugging)
    #[inline]
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// Clear all pending signals
    #[inline]
    pub fn clear_all(&mut self) {
        self.bits = 0;
    }
}

impl Default for PendingSignals {
    fn default() -> Self {
        Self::new()
    }
}

/// Default signal action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Ignore the signal
    Ignore,
    /// Terminate the process
    Terminate,
    /// Stop the process
    Stop,
    /// Continue if stopped
    Continue,
}

/// Signal-related errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// Invalid signal number
    InvalidSignal,
    /// Target process does not exist
    NoSuchProcess,
    /// Permission denied
    PermissionDenied,
}

impl From<SignalError> for SyscallError {
    fn from(err: SignalError) -> Self {
        match err {
            SignalError::InvalidSignal => SyscallError::EINVAL,
            SignalError::NoSuchProcess => SyscallError::ESRCH,
            SignalError::PermissionDenied => SyscallError::EPERM,
        }
    }
}

/// Calculate exit code for signal termination (128 + signal number)
#[inline]
fn signal_exit_code(signal: Signal) -> i32 {
    128 + signal.as_u8() as i32
}

/// Get default action for a signal
///
/// SIGKILL and SIGSTOP always execute their default action.
pub fn default_action(signal: Signal) -> SignalAction {
    if signal.is_continue() {
        SignalAction::Continue
    } else if signal.is_stop() {
        SignalAction::Stop
    } else if signal == Signal::SIGCHLD {
        SignalAction::Ignore
    } else {
        SignalAction::Terminate
    }
}

/// Send a signal to a process
///
/// Executes the default action immediately for SIGKILL/SIGSTOP.
/// Other signals are queued for later delivery.
///
/// # Arguments
///
/// * `pid` - Target process ID
/// * `signal` - Signal to send
///
/// # Returns
///
/// The action taken on success, or error
///
/// # Permission Model (Z-9 fix: POSIX-compliant UID/EUID checks)
///
/// POSIX permission rules for kill():
/// - Root (euid == 0) can signal any process
/// - Process can signal itself
/// - sender.uid == target.uid
/// - sender.euid == target.uid
/// - PID 1 (init) is additionally protected: only self can signal
pub fn send_signal(pid: ProcessId, signal: Signal) -> Result<SignalAction, SignalError> {
    // 注意：我们需要调用调度器的 resume_stopped，它在 sched crate 中
    // 由于循环依赖的限制，我们通过回调机制实现

    // R65-26 FIX: Get target process Arc ONCE and hold it throughout the operation.
    // This prevents TOCTOU where PID is reused between permission check and signal delivery.
    // Previously, we fetched the process twice: once for permission check, once for signal.
    let process_arc = process::get_process(pid).ok_or(SignalError::NoSuchProcess)?;

    // 【安全修复 Z-9】POSIX 权限检查（深度防御）
    // 使用 UID/EUID 而非仅父子关系
    if let Some(sender_pid) = process::current_pid() {
        // PID 1 (init) 保护：只有 init 自己可以向自己发信号
        if pid == 1 && sender_pid != 1 {
            return Err(SignalError::PermissionDenied);
        }

        // 非自己的进程需要进行 POSIX 权限检查
        if sender_pid != pid {
            // 获取发送者凭证
            let sender_creds = process::current_credentials().ok_or(SignalError::NoSuchProcess)?;

            // R65-26 FIX: Read target UID from the same Arc we'll use for signal delivery
            // This closes the TOCTOU window where PID could be reused between check and delivery
            let target_uid = process_arc.lock().credentials.read().uid;

            // POSIX 权限检查：
            // 1. Root (euid == 0) 可以发信号给任何进程
            // 2. sender.uid == target.uid
            // 3. sender.euid == target.uid
            let has_permission = sender_creds.euid == 0
                || sender_creds.uid == target_uid
                || sender_creds.euid == target_uid;

            if !has_permission {
                return Err(SignalError::PermissionDenied);
            }
        }
    }

    // process_arc already obtained above (R65-26 FIX)
    let action = default_action(signal);
    let mut needs_reschedule = false;
    let mut terminate_code: Option<i32> = None;
    let mut needs_resume = false;

    {
        let mut proc = process_arc.lock();

        // Cannot send signals to zombie or terminated processes
        if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
            return Err(SignalError::NoSuchProcess);
        }

        // Queue the signal
        proc.pending_signals.set(signal);

        // Execute default action
        match action {
            SignalAction::Terminate => {
                terminate_code = Some(signal_exit_code(signal));
                // Need to reschedule if terminating current process
                if process::current_pid() == Some(pid) {
                    needs_reschedule = true;
                }
            }
            SignalAction::Stop => {
                // R98-1 FIX: Job-control stop is orthogonal to scheduler state.
                // Do NOT overwrite Blocked/Sleeping, or we lose the wait condition
                // and break wait queue invariants (H-34 lost wakeup fix).
                let was_running = proc.state == ProcessState::Running;
                proc.stopped = true;
                // Need to reschedule if stopping current process
                if was_running && process::current_pid() == Some(pid) {
                    needs_reschedule = true;
                }
            }
            SignalAction::Continue => {
                // R98-1 FIX: Handle SIGCONT via scheduler resume callback.
                // We check if the process is stopped but DO NOT clear the flag here.
                // The scheduler's resume_stopped() will clear `stopped` and handle
                // the state transition atomically. This avoids a race where we
                // clear `stopped` but resume_stopped() sees it already false.
                //
                // Note: We check BOTH `stopped` (orthogonal flag) AND `ProcessState::Stopped`
                // (legacy state) to handle both code paths consistently.
                if proc.stopped || proc.state == ProcessState::Stopped {
                    needs_resume = true;
                }
                // Clear the SIGCONT from pending since we handle it immediately
                proc.pending_signals.clear(signal);
            }
            SignalAction::Ignore => {
                // Clear the ignored signal from pending
                proc.pending_signals.clear(signal);
            }
        }
    } // Release process lock before calling scheduler functions

    // Terminate process if needed
    if let Some(code) = terminate_code {
        process::terminate_process(pid, code);
    }

    // Resume stopped process - calls into scheduler to add to ready queue
    if needs_resume {
        // 通过回调调用调度器的 resume_stopped 函数
        if let Some(resume_fn) = get_resume_callback() {
            resume_fn(pid);
        }
    }

    // Trigger reschedule if needed
    if needs_reschedule {
        crate::scheduler_hook::force_reschedule();
    }

    Ok(action)
}

/// Check if process has any pending signals
pub fn has_pending_signals(pid: ProcessId) -> bool {
    if let Some(process_arc) = process::get_process(pid) {
        let proc = process_arc.lock();
        proc.pending_signals.has_pending()
    } else {
        false
    }
}

/// Get signal name for debugging
pub fn signal_name(signal: Signal) -> &'static str {
    match signal.as_u8() {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        _ => "SIG???",
    }
}
