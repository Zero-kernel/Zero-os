//! Zero-OS kernel logging (`klog`).
//!
//! This crate provides profile-aware, security-conscious logging macros that
//! replace ungated `println!` usage throughout the kernel.  It is designed to
//! be a lightweight dependency that every kernel sub-crate can import without
//! pulling in heavyweight subsystems.
//!
//! # Macro Overview
//!
//! | Macro | Release build | Profile-aware | Use case |
//! |-------|--------------|---------------|----------|
//! | [`kprintln!`] | Compiled out | No | Debug diagnostics (replaces `println!`) |
//! | [`klog!`] | Active | Yes | Operational logging with level filter |
//! | [`klog_always!`] | Active | Secure-gated | Boot banners, status messages |
//! | [`klog_force!`] | Active | No | Pre-panic diagnostics, critical errors |
//!
//! # Hardening Profile Integration
//!
//! Log filtering is **runtime** and derived from the active hardening profile.
//! The kernel boot path must call [`set_profile`] once the compliance subsystem
//! is initialised:
//!
//! - **Secure** : no output (zero information leak surface)
//! - **Balanced**: `Error` + `Warn` only
//! - **Performance**: all levels
//!
//! The hot path is a single `Relaxed` atomic load + integer compare.
//!
//! # Pointer Safety
//!
//! This crate intentionally does **not** depend on `security` (kptr_guard) to
//! avoid circular dependencies.  Callers MUST wrap kernel addresses with
//! `security::KptrGuard` before formatting:
//!
//! ```ignore
//! use security::KptrGuard;
//! klog!(Info, "page table root: {}", KptrGuard::from_addr(root));
//! ```
//!
//! Passing raw kernel addresses to any klog macro in production code is a
//! security policy violation.

#![no_std]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// ============================================================================
// Log Levels
// ============================================================================

/// Severity level for [`klog!`] messages.
///
/// Ordered from least severe ([`Trace`]) to most severe ([`Error`]).
/// The runtime filter allows messages at or above the configured minimum level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Extremely verbose tracing (compiled out in release).
    Trace = 0,
    /// Developer-oriented debug information (compiled out in release).
    Debug = 1,
    /// Normal operational information.
    Info = 2,
    /// Potential problems that merit attention.
    Warn = 3,
    /// Errors that affect correctness or security.
    Error = 4,
}

// ============================================================================
// Profile Filter
// ============================================================================

/// Sentinel: all output suppressed.
const LEVEL_DISABLED: u8 = u8::MAX;

/// Runtime minimum level.  Messages with `level >= LOG_MIN_LEVEL` are emitted.
/// Initialised to DISABLED; the boot path must call [`set_profile`].
static LOG_MIN_LEVEL: AtomicU8 = AtomicU8::new(LEVEL_DISABLED);

/// P1-1: Runtime gate for [`klog_always!`].
///
/// Defaults to `false` (fail-closed) until [`set_profile`] is called.
/// In `Secure` profile this remains `false`, suppressing all `klog_always!`
/// output to minimize information leakage.  Use [`klog_force!`] for
/// output that must appear regardless of profile (e.g., pre-panic diagnostics).
static LOG_ALWAYS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Hardening profile identifiers mirroring `compliance::HardeningProfile`.
///
/// Duplicated here to avoid a compile-time dependency on `compliance`.
/// Values MUST stay in sync with `compliance::HardeningProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KlogProfile {
    /// Maximum security, no klog output.
    Secure = 0,
    /// Balanced: errors and warnings only.
    Balanced = 1,
    /// Performance/debug: all levels.
    Performance = 2,
}

/// Set the klog filter from a profile.
///
/// Called once during early boot after the compliance subsystem selects a
/// profile.  Safe to call again if the profile changes at runtime.
///
/// P1-1: Also gates [`klog_always!`] — Secure profile suppresses all
/// `klog_always!` output.  Use [`klog_force!`] for output that must
/// appear regardless of profile.
#[inline]
pub fn set_profile(profile: KlogProfile) {
    let min = match profile {
        KlogProfile::Secure => LEVEL_DISABLED,
        KlogProfile::Balanced => Level::Warn as u8,
        KlogProfile::Performance => Level::Trace as u8,
    };
    LOG_MIN_LEVEL.store(min, Ordering::Release);
    // P1-1: Secure profile suppresses klog_always! to minimize info leakage.
    LOG_ALWAYS_ENABLED.store(profile != KlogProfile::Secure, Ordering::Release);
}

/// Disable all klog output.  Does **not** affect [`klog_always!`].
#[inline]
pub fn disable() {
    LOG_MIN_LEVEL.store(LEVEL_DISABLED, Ordering::Release);
}

/// Returns `true` if a message at `level` would currently be emitted.
///
/// Hot path: single `Relaxed` atomic load + integer compare.
#[inline(always)]
pub fn enabled(level: Level) -> bool {
    level as u8 >= LOG_MIN_LEVEL.load(Ordering::Relaxed)
}

/// P1-1: Returns `true` if [`klog_always!`] output is currently enabled.
///
/// Hot path: single `Relaxed` atomic load.  `klog_always!` output is
/// suppressed in `Secure` profile to minimize information leakage.
#[doc(hidden)]
#[inline(always)]
pub fn _klog_always_enabled() -> bool {
    LOG_ALWAYS_ENABLED.load(Ordering::Relaxed)
}

// ============================================================================
// Output Helpers (not public API — used by macros)
// ============================================================================

#[doc(hidden)]
#[inline(always)]
pub fn _klog_print(args: core::fmt::Arguments) {
    drivers::vga_buffer::_print(args);
}

// ============================================================================
// Macros
// ============================================================================

/// Profile-gated kernel output (boot banners, status messages).
///
/// P1-1: Suppressed in [`KlogProfile::Secure`] to minimize information
/// leakage.  For output that must appear regardless of profile (e.g.,
/// pre-panic diagnostics, security policy enforcement messages), use
/// [`klog_force!`] instead.
#[macro_export]
macro_rules! klog_always {
    () => {{
        if $crate::_klog_always_enabled() {
            $crate::_klog_print(format_args!("\n"));
        }
    }};
    ($($arg:tt)+) => {{
        if $crate::_klog_always_enabled() {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
}

/// Truly unconditional kernel output — never suppressed by any profile.
///
/// Use sparingly: only for output that **must** appear regardless of
/// hardening profile.  Examples:
/// - Security policy enforcement messages immediately before `panic!()`
/// - Critical hardware errors that prevent boot
/// - Livepatch ECDSA key placeholder warnings
///
/// All other boot/status output should use [`klog_always!`] (profile-gated).
#[macro_export]
macro_rules! klog_force {
    () => {{
        $crate::_klog_print(format_args!("\n"));
    }};
    ($($arg:tt)+) => {{
        $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
    }};
}

/// Debug-only kernel print — drop-in replacement for `println!`.
///
/// **Fully compiled out** in release builds (zero cost, zero binary impact).
/// Use this for developer diagnostics that should never appear in production.
#[macro_export]
macro_rules! kprintln {
    () => {{
        #[cfg(debug_assertions)]
        $crate::klog_always!();
    }};
    ($($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        $crate::klog_always!($($arg)+);
    }};
}

/// Profile-aware kernel logging.
///
/// `Debug` and `Trace` levels are additionally compiled out in release builds,
/// so they incur zero cost in production even if the profile would allow them.
///
/// # Examples
///
/// ```ignore
/// klog!(Error, "buddy allocator: OOM at order {}", order);
/// klog!(Warn,  "timer sweep took {}us", elapsed);
/// klog!(Info,  "SMP: {} CPUs online", count);
/// klog!(Debug, "sys_clone flags=0x{:x}", flags);
/// ```
#[macro_export]
macro_rules! klog {
    // ---- Error (always compiled in, runtime-filtered) ----
    (Error, $($arg:tt)+) => {{
        if $crate::enabled($crate::Level::Error) {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
    // ---- Warn (always compiled in, runtime-filtered) ----
    (Warn, $($arg:tt)+) => {{
        if $crate::enabled($crate::Level::Warn) {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
    // ---- Info (always compiled in, runtime-filtered) ----
    (Info, $($arg:tt)+) => {{
        if $crate::enabled($crate::Level::Info) {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
    // ---- Debug (compiled out in release) ----
    (Debug, $($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        if $crate::enabled($crate::Level::Debug) {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
    // ---- Trace (compiled out in release) ----
    (Trace, $($arg:tt)+) => {{
        #[cfg(debug_assertions)]
        if $crate::enabled($crate::Level::Trace) {
            $crate::_klog_print(format_args!("{}\n", format_args!($($arg)+)));
        }
    }};
}
