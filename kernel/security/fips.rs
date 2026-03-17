//! R140-6 FIX: FIPS Mode State for the Security Crate
//!
//! Stores the canonical FIPS mode flag so that cryptographic primitives in the
//! `security` crate (e.g., `rng::fill_random`) can enforce FIPS policy without
//! introducing a circular dependency on the `compliance` crate.
//!
//! The `compliance` crate sets the state via `set_fips_state()` after running
//! self-tests.  Consumers in both `security` and `compliance` read the state via
//! `fips_state()`.

use core::sync::atomic::{AtomicU8, Ordering};

/// FIPS mode states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FipsState {
    /// FIPS mode not enabled.
    Disabled = 0,
    /// FIPS mode enabled (sticky until reboot).
    Enabled = 1,
    /// FIPS mode enable failed (e.g., self-test failure) or state corrupted.
    Failed = 2,
}

/// Global FIPS mode flag (sticky once enabled).
static FIPS_MODE: AtomicU8 = AtomicU8::new(FipsState::Disabled as u8);

/// Get the current FIPS state.
///
/// R94-3 FIX: Fail-closed on corruption — unknown/corrupted atomic values
/// return `Failed` instead of `Disabled`.
#[inline]
pub fn fips_state() -> FipsState {
    match FIPS_MODE.load(Ordering::Acquire) {
        0 => FipsState::Disabled,
        1 => FipsState::Enabled,
        2 => FipsState::Failed,
        _ => FipsState::Failed,
    }
}

/// Set the global FIPS state.
///
/// Called by the `compliance` subsystem after running self-tests.
///
/// Enforces monotonic transitions: once Enabled or Failed, the state cannot
/// be reverted to Disabled (Codex review: prevents accidental/malicious downgrade).
///
/// R141-6 FIX: Uses compare_exchange instead of separate load+store to
/// eliminate a theoretical race where two concurrent callers both read
/// Disabled and store different values. In practice, the compliance crate's
/// FIPS_ENABLING spinlock serializes callers, but CAS is defense-in-depth.
///
/// Reject no-op Disabled→Disabled transitions (caller should only call this
/// with Enabled or Failed).
#[inline]
pub fn set_fips_state(state: FipsState) {
    let desired = state as u8;
    // Refuse Disabled → Disabled (no-op that could mask a bug).
    if desired == FipsState::Disabled as u8 {
        return;
    }
    // CAS: only succeeds if current state is Disabled.
    let _ = FIPS_MODE.compare_exchange(
        FipsState::Disabled as u8,
        desired,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}
