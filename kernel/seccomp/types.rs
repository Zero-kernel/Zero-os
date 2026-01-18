//! Seccomp/Pledge types and data structures.
//!
//! This module defines the core types for syscall filtering:
//! - BPF-like instruction set for flexible filtering
//! - Pledge promises for OpenBSD-style sandboxing
//! - Filter state management

#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::fmt;

// ============================================================================
// Seccomp Actions
// ============================================================================

/// Action to take when a seccomp filter matches.
///
/// Actions have a severity ordering: Kill > Trap > Errno > Log > Allow.
/// When multiple filters are stacked, the most restrictive action wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Allow the syscall to proceed.
    Allow,
    /// Log the syscall but allow it.
    Log,
    /// Return an error without executing the syscall.
    Errno(i32),
    /// Trigger a trap (SIGSYS with handler).
    Trap,
    /// Kill the process with SIGSYS.
    Kill,
}

impl SeccompAction {
    /// Get the severity level of this action (higher = more restrictive).
    #[inline]
    pub const fn severity(&self) -> u8 {
        match self {
            SeccompAction::Allow => 0,
            SeccompAction::Log => 1,
            SeccompAction::Errno(_) => 2,
            SeccompAction::Trap => 3,
            SeccompAction::Kill => 4,
        }
    }

    /// Check if this action is more restrictive than another.
    #[inline]
    pub fn more_restrictive_than(&self, other: &SeccompAction) -> bool {
        self.severity() > other.severity()
    }
}

impl Default for SeccompAction {
    fn default() -> Self {
        SeccompAction::Allow
    }
}

/// Result of evaluating a seccomp filter.
#[derive(Debug, Clone, Copy)]
pub struct SeccompVerdict {
    /// The action to take.
    pub action: SeccompAction,
    /// Filter ID that produced this verdict (for logging).
    pub filter_id: u64,
}

impl SeccompVerdict {
    /// Create an allow verdict.
    #[inline]
    pub const fn allow() -> Self {
        Self {
            action: SeccompAction::Allow,
            filter_id: 0,
        }
    }

    /// Create a kill verdict.
    #[inline]
    pub const fn kill(filter_id: u64) -> Self {
        Self {
            action: SeccompAction::Kill,
            filter_id,
        }
    }

    /// Create an errno verdict.
    #[inline]
    pub const fn errno(errno: i32, filter_id: u64) -> Self {
        Self {
            action: SeccompAction::Errno(errno),
            filter_id,
        }
    }
}

// ============================================================================
// BPF-like Instructions
// ============================================================================

/// BPF-like instruction for seccomp filters.
///
/// This is a simplified instruction set that provides:
/// - Load syscall arguments (read-only)
/// - Arithmetic and logical operations
/// - Comparisons with conditional jumps
/// - Return actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompInsn {
    /// Load syscall number into accumulator.
    LdSyscallNr,
    /// Load syscall argument (index 0-5) into accumulator.
    LdArg(u8),
    /// Load constant into accumulator.
    LdConst(u64),
    /// Bitwise AND accumulator with constant.
    And(u64),
    /// Bitwise OR accumulator with constant.
    Or(u64),
    /// Right shift accumulator by constant.
    Shr(u8),
    /// Jump if accumulator equals constant.
    JmpEq(u64, u8, u8), // (value, true_offset, false_offset)
    /// Jump if accumulator not equals constant.
    JmpNe(u64, u8, u8),
    /// Jump if accumulator less than constant.
    JmpLt(u64, u8, u8),
    /// Jump if accumulator less than or equal to constant.
    JmpLe(u64, u8, u8),
    /// Jump if accumulator greater than constant.
    JmpGt(u64, u8, u8),
    /// Jump if accumulator greater than or equal to constant.
    JmpGe(u64, u8, u8),
    /// Unconditional jump (relative offset).
    Jmp(u8),
    /// Return with action.
    Ret(SeccompAction),
}

/// Maximum program length to prevent DoS.
pub const MAX_INSNS: usize = 64;

// ============================================================================
// Seccomp Filter
// ============================================================================

bitflags! {
    /// Seccomp filter flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SeccompFlags: u32 {
        /// Log violations but don't enforce.
        const LOG = 1 << 0;
        /// Synchronize with all threads in thread group.
        const TSYNC = 1 << 1;
        /// Apply filter only to new threads.
        const NEW_THREADS = 1 << 2;
    }
}

/// A compiled seccomp filter.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    /// Default action when no rule matches.
    pub default_action: SeccompAction,
    /// BPF-like program.
    pub prog: Arc<[SeccompInsn]>,
    /// Fast allow bitmap for common syscalls (syscall_nr < 512).
    /// If bit N is set, syscall N is unconditionally allowed.
    pub fast_allow: FastAllowSet,
    /// Unique filter ID (hash) for logging/dedup.
    pub id: u64,
    /// Filter flags.
    pub flags: SeccompFlags,
}

impl SeccompFilter {
    /// Create a new filter from a program.
    pub fn new(
        prog: Vec<SeccompInsn>,
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        // Validate the program
        validate_program(&prog)?;

        // Compute fast_allow bitmap
        let fast_allow = compute_fast_allow(&prog);

        // Compute filter ID (simple hash of program)
        let id = compute_filter_id(&prog);

        Ok(Self {
            default_action,
            prog: prog.into(),
            fast_allow,
            id,
            flags,
        })
    }

    /// Evaluate this filter against a syscall.
    pub fn evaluate(&self, syscall_nr: u64, args: &[u64; 6]) -> SeccompAction {
        // Fast path: check fast_allow bitmap
        if syscall_nr < 512 && self.fast_allow.get(syscall_nr as usize) {
            return SeccompAction::Allow;
        }

        // Interpret the BPF program
        let mut acc: u64 = 0;
        let mut pc: usize = 0;

        while pc < self.prog.len() {
            match self.prog[pc] {
                SeccompInsn::LdSyscallNr => {
                    acc = syscall_nr;
                    pc += 1;
                }
                SeccompInsn::LdArg(idx) => {
                    acc = if (idx as usize) < 6 {
                        args[idx as usize]
                    } else {
                        0
                    };
                    pc += 1;
                }
                SeccompInsn::LdConst(val) => {
                    acc = val;
                    pc += 1;
                }
                SeccompInsn::And(val) => {
                    acc &= val;
                    pc += 1;
                }
                SeccompInsn::Or(val) => {
                    acc |= val;
                    pc += 1;
                }
                SeccompInsn::Shr(shift) => {
                    acc >>= shift;
                    pc += 1;
                }
                // R32-SECCOMP-2 FIX: All jump instructions must validate pc bounds
                // after increment. If pc escapes program bounds, fail-closed with Trap.
                SeccompInsn::JmpEq(val, t, f) => {
                    pc += 1 + if acc == val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::JmpNe(val, t, f) => {
                    pc += 1 + if acc != val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::JmpLt(val, t, f) => {
                    pc += 1 + if acc < val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::JmpLe(val, t, f) => {
                    pc += 1 + if acc <= val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::JmpGt(val, t, f) => {
                    pc += 1 + if acc > val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::JmpGe(val, t, f) => {
                    pc += 1 + if acc >= val { t as usize } else { f as usize };
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::Jmp(offset) => {
                    pc += 1 + offset as usize;
                    if pc >= self.prog.len() {
                        return SeccompAction::Trap;
                    }
                }
                SeccompInsn::Ret(action) => {
                    return action;
                }
            }
        }

        // If we fall through, use default action
        self.default_action
    }
}

// ============================================================================
// Fast Allow Bitmap
// ============================================================================

/// Bitmap for fast syscall allow checks.
#[derive(Debug, Clone)]
pub struct FastAllowSet {
    /// 512 bits = 8 u64s
    bits: [u64; 8],
}

impl FastAllowSet {
    /// Create an empty set.
    pub const fn empty() -> Self {
        Self { bits: [0; 8] }
    }

    /// Set bit at index.
    pub fn set(&mut self, idx: usize) {
        if idx < 512 {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// Get bit at index.
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        if idx < 512 {
            (self.bits[idx / 64] >> (idx % 64)) & 1 != 0
        } else {
            false
        }
    }
}

impl Default for FastAllowSet {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Pledge Promises
// ============================================================================

bitflags! {
    /// Pledge promise set (OpenBSD-style).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PledgePromises: u32 {
        /// Basic I/O: read, write, close, fstat, lseek, getpid, etc.
        const STDIO = 1 << 0;
        /// Read-only filesystem access: open(RD), stat, readdir.
        const RPATH = 1 << 1;
        /// Write filesystem access: open(WR|CREAT), write, rename, unlink.
        const WPATH = 1 << 2;
        /// Create files: open(O_CREAT), mkdir, mknod.
        const CPATH = 1 << 3;
        /// Temp files: tmpfile, unlink of temp.
        const TMPPATH = 1 << 4;
        /// Process operations: fork, clone, exec, wait, kill.
        const PROC = 1 << 5;
        /// Thread operations: clone(THREAD), futex.
        const THREAD = 1 << 6;
        /// Execute programs: exec*.
        const EXEC = 1 << 7;
        /// Unix sockets.
        const UNIX = 1 << 8;
        /// Internet sockets.
        const INET = 1 << 9;
        /// DNS resolution.
        const DNS = 1 << 10;
        /// Change file attributes: chmod, chown, utime.
        const FATTR = 1 << 11;
        /// Get/set resource limits: getrlimit, setrlimit.
        const RLIMIT = 1 << 12;
        /// Get current time.
        const TIME = 1 << 13;
        /// Send signals to own process group.
        const SENDSIG = 1 << 14;
        /// Ptrace (for debuggers).
        const PTRACE = 1 << 15;
        /// Memory mapping with EXEC.
        const PROT_EXEC = 1 << 16;
        /// Virtual memory: mmap, mprotect, munmap.
        const VM = 1 << 17;
    }
}

impl PledgePromises {
    /// Parse promise string (space-separated).
    pub fn parse(s: &str) -> Result<Self, SeccompError> {
        let mut promises = PledgePromises::empty();
        for word in s.split_whitespace() {
            match word {
                "stdio" => promises |= PledgePromises::STDIO,
                "rpath" => promises |= PledgePromises::RPATH,
                "wpath" => promises |= PledgePromises::WPATH,
                "cpath" => promises |= PledgePromises::CPATH,
                "tmppath" => promises |= PledgePromises::TMPPATH,
                "proc" => promises |= PledgePromises::PROC,
                "thread" => promises |= PledgePromises::THREAD,
                "exec" => promises |= PledgePromises::EXEC,
                "unix" => promises |= PledgePromises::UNIX,
                "inet" => promises |= PledgePromises::INET,
                "dns" => promises |= PledgePromises::DNS,
                "fattr" => promises |= PledgePromises::FATTR,
                "rlimit" => promises |= PledgePromises::RLIMIT,
                "time" => promises |= PledgePromises::TIME,
                "sendsig" => promises |= PledgePromises::SENDSIG,
                "ptrace" => promises |= PledgePromises::PTRACE,
                "prot_exec" => promises |= PledgePromises::PROT_EXEC,
                "vm" => promises |= PledgePromises::VM,
                _ => return Err(SeccompError::InvalidPromise),
            }
        }
        Ok(promises)
    }
}

/// Pledge state for a process.
#[derive(Debug, Clone)]
pub struct PledgeState {
    /// Current active promises.
    pub promises: PledgePromises,
    /// Promises to apply after exec (if Some).
    pub exec_promises: Option<PledgePromises>,
}

impl PledgeState {
    /// Create a new pledge state with given promises.
    pub fn new(promises: PledgePromises) -> Self {
        Self {
            promises,
            exec_promises: None,
        }
    }

    /// Check if a syscall is allowed by current promises.
    pub fn allows(&self, syscall_nr: u64, args: &[u64; 6]) -> bool {
        promise_allows_syscall(self.promises, syscall_nr, args)
    }
}

// ============================================================================
// Seccomp State
// ============================================================================

/// Per-process seccomp state.
#[derive(Debug, Clone)]
pub struct SeccompState {
    /// Stack of filters (evaluated in order, most restrictive wins).
    pub filters: Vec<Arc<SeccompFilter>>,
    /// PR_SET_NO_NEW_PRIVS flag.
    pub no_new_privs: bool,
    /// Log all violations.
    pub log_violations: bool,
}

impl SeccompState {
    /// Create empty seccomp state.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            no_new_privs: false,
            log_violations: false,
        }
    }

    /// Evaluate all filters against a syscall.
    ///
    /// Returns the most restrictive verdict across all filters.
    /// Severity ordering: Kill > Trap > Errno > Log > Allow.
    pub fn evaluate(&self, syscall_nr: u64, args: &[u64; 6]) -> SeccompVerdict {
        let mut result = SeccompVerdict::allow();

        for filter in &self.filters {
            let action = filter.evaluate(syscall_nr, args);

            // Track the most restrictive action seen
            if action.more_restrictive_than(&result.action) {
                result = SeccompVerdict {
                    action,
                    filter_id: filter.id,
                };
            }

            // Early exit on Kill (can't be more restrictive)
            if matches!(result.action, SeccompAction::Kill) {
                break;
            }
        }

        result
    }

    /// Add a filter to the stack.
    pub fn add_filter(&mut self, filter: SeccompFilter) {
        self.filters.push(Arc::new(filter));
    }

    /// Check if any filters are active.
    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
    }
}

impl Default for SeccompState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Seccomp errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompError {
    /// Program is too long.
    ProgramTooLong,
    /// Program has invalid instruction.
    InvalidInstruction,
    /// Program has out-of-bounds jump.
    InvalidJump,
    /// Program doesn't terminate with RET.
    NoTerminator,
    /// Program accesses invalid argument index.
    InvalidArgIndex,
    /// Invalid pledge promise string.
    InvalidPromise,
    /// Operation not permitted (no_new_privs).
    NotPermitted,
    /// Memory fault copying from user.
    Fault,
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeccompError::ProgramTooLong => write!(f, "seccomp: program too long"),
            SeccompError::InvalidInstruction => write!(f, "seccomp: invalid instruction"),
            SeccompError::InvalidJump => write!(f, "seccomp: invalid jump"),
            SeccompError::NoTerminator => write!(f, "seccomp: program doesn't terminate"),
            SeccompError::InvalidArgIndex => write!(f, "seccomp: invalid argument index"),
            SeccompError::InvalidPromise => write!(f, "seccomp: invalid pledge promise"),
            SeccompError::NotPermitted => write!(f, "seccomp: operation not permitted"),
            SeccompError::Fault => write!(f, "seccomp: memory fault"),
        }
    }
}

// ============================================================================
// Validation and Helpers
// ============================================================================

/// Validate a seccomp program.
///
/// # Security (R32-SECCOMP-1 fix)
///
/// Jump targets must be strictly less than prog.len() to ensure they
/// land on a valid instruction. Allowing target == prog.len() enables
/// policy bypass by falling through to the default action.
fn validate_program(prog: &[SeccompInsn]) -> Result<(), SeccompError> {
    if prog.is_empty() {
        return Err(SeccompError::NoTerminator);
    }
    if prog.len() > MAX_INSNS {
        return Err(SeccompError::ProgramTooLong);
    }

    // Check for valid argument indices and jump targets
    for (i, insn) in prog.iter().enumerate() {
        match insn {
            SeccompInsn::LdArg(idx) if *idx >= 6 => {
                return Err(SeccompError::InvalidArgIndex);
            }
            SeccompInsn::JmpEq(_, t, f)
            | SeccompInsn::JmpNe(_, t, f)
            | SeccompInsn::JmpLt(_, t, f)
            | SeccompInsn::JmpLe(_, t, f)
            | SeccompInsn::JmpGt(_, t, f)
            | SeccompInsn::JmpGe(_, t, f) => {
                let true_target = i + 1 + *t as usize;
                let false_target = i + 1 + *f as usize;
                // R32-SECCOMP-1 FIX: Use >= instead of > to prevent jumping past program end
                if true_target >= prog.len() || false_target >= prog.len() {
                    return Err(SeccompError::InvalidJump);
                }
            }
            SeccompInsn::Jmp(offset) => {
                let target = i + 1 + *offset as usize;
                // R32-SECCOMP-1 FIX: Use >= instead of > to prevent jumping past program end
                if target >= prog.len() {
                    return Err(SeccompError::InvalidJump);
                }
            }
            _ => {}
        }
    }

    // Check that program ends with a RET
    let has_terminator = prog.iter().any(|insn| matches!(insn, SeccompInsn::Ret(_)));
    if !has_terminator {
        return Err(SeccompError::NoTerminator);
    }

    Ok(())
}

/// Compute fast_allow bitmap from program.
///
/// Scans for patterns where a syscall number check leads directly to Allow.
/// Only sets the fast-allow bit if we can verify the path leads to Ret(Allow).
///
/// Pattern detected:
///   LD syscall_nr
///   JMP_EQ N, offset, ...
///   ... (at offset) Ret(Allow)
fn compute_fast_allow(prog: &[SeccompInsn]) -> FastAllowSet {
    let mut set = FastAllowSet::empty();

    // For each instruction, check if it's a pattern we can optimize
    for (i, insn) in prog.iter().enumerate() {
        // Look for: LdSyscallNr followed by JmpEq
        if i + 1 >= prog.len() {
            continue;
        }

        if !matches!(insn, SeccompInsn::LdSyscallNr) {
            continue;
        }

        // Check if next instruction is JmpEq
        if let SeccompInsn::JmpEq(nr, true_offset, _) = prog[i + 1] {
            // Calculate the target of the true branch
            let true_target = i + 2 + true_offset as usize;

            // Verify the target is within bounds and is Ret(Allow)
            if true_target < prog.len() {
                if let SeccompInsn::Ret(SeccompAction::Allow) = prog[true_target] {
                    // This syscall number unconditionally leads to Allow
                    if nr < 512 {
                        set.set(nr as usize);
                    }
                }
            }
        }
    }

    set
}

/// Compute filter ID from program.
fn compute_filter_id(prog: &[SeccompInsn]) -> u64 {
    // Simple FNV-1a hash
    let mut hash: u64 = 0xcbf29ce484222325;
    for insn in prog {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                insn as *const SeccompInsn as *const u8,
                core::mem::size_of::<SeccompInsn>(),
            )
        };
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// Check if a pledge promise set allows a syscall.
///
/// This is a simplified mapping; real implementation would be more comprehensive.
fn promise_allows_syscall(promises: PledgePromises, syscall_nr: u64, args: &[u64; 6]) -> bool {
    // Define syscall numbers (these should match kernel_core/syscall.rs)
    const SYS_READ: u64 = 0;
    const SYS_WRITE: u64 = 1;
    const SYS_OPEN: u64 = 2;
    const SYS_CLOSE: u64 = 3;
    const SYS_STAT: u64 = 4;
    const SYS_FSTAT: u64 = 5;
    const SYS_LSEEK: u64 = 8;
    const SYS_MMAP: u64 = 9;
    const SYS_MPROTECT: u64 = 10;
    const SYS_MUNMAP: u64 = 11;
    const SYS_BRK: u64 = 12;
    const SYS_GETPID: u64 = 39;
    const SYS_FORK: u64 = 57;
    const SYS_CLONE: u64 = 56;
    const SYS_EXECVE: u64 = 59;
    const SYS_EXIT: u64 = 60;
    const SYS_WAIT4: u64 = 61;
    const SYS_KILL: u64 = 62;
    const SYS_FUTEX: u64 = 202;
    const SYS_GETRANDOM: u64 = 318;
    const SYS_OPENAT: u64 = 257;

    // File open flag bits (must match VFS)
    const O_ACCMODE: u64 = 0x3;
    const O_WRONLY: u64 = 0x1;
    const O_RDWR: u64 = 0x2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;

    // Memory protection flags
    const PROT_EXEC: i32 = 0x4;

    // Always allow exit
    if syscall_nr == SYS_EXIT {
        return true;
    }

    // Handle path syscalls with flag-aware checks
    if matches!(syscall_nr, SYS_OPEN | SYS_OPENAT) {
        let flags = if syscall_nr == SYS_OPEN {
            args[1]
        } else {
            args[2]
        };
        let accmode = flags & O_ACCMODE;
        let wants_write = accmode == O_WRONLY || accmode == O_RDWR;
        let wants_create = (flags & (O_CREAT | O_TRUNC)) != 0;
        let wants_append = (flags & O_APPEND) != 0;

        // Require at least one path capability
        let has_path = promises.intersects(
            PledgePromises::RPATH
                | PledgePromises::WPATH
                | PledgePromises::CPATH
                | PledgePromises::TMPPATH,
        );
        if !has_path {
            return false;
        }

        // Writing (including append/truncate) requires WPATH/CPATH/TMPPATH
        if (wants_write || wants_append)
            && !(promises.contains(PledgePromises::WPATH)
                || promises.contains(PledgePromises::CPATH)
                || promises.contains(PledgePromises::TMPPATH))
        {
            return false;
        }

        // Creation/truncate requires CPATH or TMPPATH
        if wants_create
            && !(promises.contains(PledgePromises::CPATH)
                || promises.contains(PledgePromises::TMPPATH))
        {
            return false;
        }

        // Read-only open is permitted with RPATH
        if !wants_write && !wants_create {
            return promises.contains(PledgePromises::RPATH)
                || promises.contains(PledgePromises::WPATH)
                || promises.contains(PledgePromises::CPATH)
                || promises.contains(PledgePromises::TMPPATH);
        }

        return true;
    }

    // Memory management with PROT_EXEC gating
    if matches!(syscall_nr, SYS_MMAP | SYS_MPROTECT) {
        if !promises.contains(PledgePromises::VM) {
            return false;
        }
        let prot = args[2] as i32;
        if (prot & PROT_EXEC) != 0 && !promises.contains(PledgePromises::PROT_EXEC) {
            return false;
        }
        return true;
    }

    // Check each promise category
    if promises.contains(PledgePromises::STDIO) {
        if matches!(
            syscall_nr,
            SYS_READ | SYS_WRITE | SYS_CLOSE | SYS_FSTAT | SYS_LSEEK | SYS_GETPID
        ) {
            return true;
        }
    }

    if promises.contains(PledgePromises::RPATH) {
        if syscall_nr == SYS_STAT {
            return true;
        }
    }

    if promises.contains(PledgePromises::WPATH) {
        if syscall_nr == SYS_WRITE {
            return true;
        }
    }

    if promises.contains(PledgePromises::VM) {
        if matches!(syscall_nr, SYS_MUNMAP | SYS_BRK) {
            return true;
        }
    }

    if promises.contains(PledgePromises::PROC) {
        if matches!(syscall_nr, SYS_FORK | SYS_CLONE | SYS_WAIT4 | SYS_KILL) {
            return true;
        }
    }

    if promises.contains(PledgePromises::EXEC) {
        if syscall_nr == SYS_EXECVE {
            return true;
        }
    }

    if promises.contains(PledgePromises::THREAD) {
        if matches!(syscall_nr, SYS_CLONE | SYS_FUTEX) {
            return true;
        }
    }

    if promises.contains(PledgePromises::TIME) {
        if syscall_nr == SYS_GETRANDOM {
            return true;
        }
    }

    false
}
