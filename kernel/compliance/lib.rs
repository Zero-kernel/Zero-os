//! G.3 Compliance: Hardening Profiles and FIPS Mode
//!
//! This module provides:
//! - **Hardening profiles**: Secure/Balanced/Performance security configurations
//! - **FIPS mode**: Sticky flag for FIPS 140-2/140-3 compliance preparation
//! - **Policy enforcement**: Centralized crypto policy decisions
//!
//! # Hardening Profiles
//!
//! | Profile | W^X | Spectre | kptr | Audit | Use Case |
//! |---------|-----|---------|------|-------|----------|
//! | Secure | strict | full | yes | 256 | Production, high-security |
//! | Balanced | warn | full | yes | 128 | Development, general use |
//! | Performance | off | partial | no | 64 | Benchmarking, low-latency |
//!
//! # FIPS Mode
//!
//! Once enabled, FIPS mode is **sticky** and cannot be disabled until reboot.
//! In FIPS mode:
//! - Non-FIPS algorithms (ChaCha20) are blocked or replaced
//! - Cryptographic operations are logged to audit
//! - Self-tests may be required before crypto use

#![no_std]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use security::SecurityConfig;

// ============================================================================
// Hardening Profiles
// ============================================================================

/// System hardening profile levels.
///
/// Profiles are boot-time selected and affect security vs performance tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HardeningProfile {
    /// Maximum security - strict W^X, all mitigations, large audit buffer.
    ///
    /// Recommended for production deployments handling sensitive data.
    Secure = 0,

    /// Balanced security and performance - W^X warnings, full mitigations.
    ///
    /// Suitable for general-purpose use and development.
    Balanced = 1,

    /// Performance-optimized - minimal security overhead.
    ///
    /// Only for controlled environments (benchmarking, testing).
    /// **NOT recommended for production.**
    Performance = 2,
}

impl HardeningProfile {
    /// Parse profile from string (case-insensitive).
    ///
    /// Accepts various aliases for each profile level.
    pub fn from_str(s: &str) -> Option<Self> {
        Self::from_str_internal(s.as_bytes())
    }

    /// Get profile name for display.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Secure => "Secure",
            Self::Balanced => "Balanced",
            Self::Performance => "Performance",
        }
    }

    /// Get recommended audit ring capacity for this profile.
    pub const fn audit_capacity(&self) -> usize {
        match self {
            Self::Secure => 256,
            Self::Balanced => 128,
            Self::Performance => 64,
        }
    }

    /// Generate SecurityConfig for this profile.
    ///
    /// The `phys_offset` must be provided from the memory subsystem.
    pub fn security_config(&self, phys_offset: x86_64::VirtAddr) -> SecurityConfig {
        match self {
            Self::Secure => SecurityConfig {
                phys_offset,
                cleanup_strategy: security::IdentityCleanupStrategy::RemoveWritable,
                enforce_nx: true,
                validate_wxorx: true,
                initialize_rng: true,
                strict_wxorx: true,  // Panic on W^X violation
                enable_kptr_guard: true,
                enable_spectre_mitigations: true,
                run_security_tests: true,
            },
            Self::Balanced => SecurityConfig {
                phys_offset,
                cleanup_strategy: security::IdentityCleanupStrategy::RemoveWritable,
                enforce_nx: true,
                validate_wxorx: true,
                initialize_rng: true,
                strict_wxorx: false, // Warn but don't panic
                enable_kptr_guard: true,
                enable_spectre_mitigations: true,
                run_security_tests: false,
            },
            Self::Performance => SecurityConfig {
                phys_offset,
                cleanup_strategy: security::IdentityCleanupStrategy::RemoveWritable,
                enforce_nx: true,  // Always keep NX for basic safety
                validate_wxorx: false,
                initialize_rng: true,
                strict_wxorx: false,
                enable_kptr_guard: false,
                enable_spectre_mitigations: false, // Disable for max performance
                run_security_tests: false,
            },
        }
    }

    /// Check if this profile enables Spectre mitigations.
    pub const fn spectre_mitigations_enabled(&self) -> bool {
        match self {
            Self::Secure | Self::Balanced => true,
            Self::Performance => false,
        }
    }

    /// Check if this profile enables kernel pointer obfuscation.
    pub const fn kptr_guard_enabled(&self) -> bool {
        match self {
            Self::Secure | Self::Balanced => true,
            Self::Performance => false,
        }
    }
}

impl Default for HardeningProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

// ============================================================================
// Global Profile State
// ============================================================================

/// Currently active hardening profile (set at boot, read-only afterward).
static ACTIVE_PROFILE: AtomicU8 = AtomicU8::new(HardeningProfile::Balanced as u8);

/// Flag indicating profile has been locked (cannot be changed after boot).
static PROFILE_LOCKED: AtomicBool = AtomicBool::new(false);

/// Set the active hardening profile.
///
/// This can only be called once during early boot before `lock_profile()`.
/// Returns `false` if the profile is already locked.
pub fn set_profile(profile: HardeningProfile) -> bool {
    if PROFILE_LOCKED.load(Ordering::Acquire) {
        return false;
    }
    ACTIVE_PROFILE.store(profile as u8, Ordering::Release);
    true
}

/// Lock the profile, preventing further changes.
///
/// Should be called after kernel initialization is complete.
pub fn lock_profile() {
    PROFILE_LOCKED.store(true, Ordering::Release);
}

/// Get the currently active hardening profile.
pub fn current_profile() -> HardeningProfile {
    match ACTIVE_PROFILE.load(Ordering::Acquire) {
        0 => HardeningProfile::Secure,
        1 => HardeningProfile::Balanced,
        2 => HardeningProfile::Performance,
        _ => HardeningProfile::Balanced, // Fallback
    }
}

/// Check if the profile has been locked.
pub fn is_profile_locked() -> bool {
    PROFILE_LOCKED.load(Ordering::Acquire)
}

// ============================================================================
// FIPS Mode
// ============================================================================

/// FIPS mode states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FipsState {
    /// FIPS mode not enabled.
    Disabled = 0,
    /// FIPS mode enabled (sticky until reboot).
    Enabled = 1,
    /// FIPS mode enable failed (e.g., self-test failure).
    Failed = 2,
}

/// Global FIPS mode flag (sticky once enabled).
static FIPS_MODE: AtomicU8 = AtomicU8::new(FipsState::Disabled as u8);

/// R93-1 FIX: Serialize FIPS enable attempts to avoid races between callers.
static FIPS_ENABLING: AtomicBool = AtomicBool::new(false);

/// Error type for FIPS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsError {
    /// FIPS mode is already enabled.
    AlreadyEnabled,
    /// FIPS mode enable failed.
    EnableFailed,
    /// Operation not permitted in FIPS mode.
    NotPermitted,
    /// Self-test failed.
    SelfTestFailed,
    /// Access denied (requires privilege).
    AccessDenied,
}

/// Enable FIPS mode.
///
/// Once enabled, FIPS mode is **sticky** and cannot be disabled until reboot.
/// This function:
/// 1. Runs required cryptographic self-tests
/// 2. Sets the global FIPS flag
/// 3. Emits an audit event
///
/// # Errors
///
/// Returns `FipsError::AlreadyEnabled` if FIPS mode is already active.
/// Returns `FipsError::SelfTestFailed` if cryptographic self-tests fail.
/// Returns `FipsError::EnableFailed` if FIPS mode previously failed.
pub fn enable_fips_mode() -> Result<(), FipsError> {
    // R93-1 FIX: Fast-path: already enabled or permanently failed.
    match fips_state() {
        FipsState::Enabled => return Err(FipsError::AlreadyEnabled),
        FipsState::Failed => return Err(FipsError::EnableFailed),
        FipsState::Disabled => {}
    }

    // R93-1 FIX: Serialize enable attempts (prevents races between self-tests and state updates).
    while FIPS_ENABLING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        core::hint::spin_loop();
    }

    // Guard to ensure FIPS_ENABLING is released on all exit paths.
    struct EnableGuard;
    impl Drop for EnableGuard {
        fn drop(&mut self) {
            FIPS_ENABLING.store(false, Ordering::Release);
        }
    }
    let _guard = EnableGuard;

    // R93-1 FIX: Re-check after acquiring the enable lock to avoid TOCTOU races.
    match fips_state() {
        FipsState::Enabled => return Err(FipsError::AlreadyEnabled),
        FipsState::Failed => return Err(FipsError::EnableFailed),
        FipsState::Disabled => {}
    }

    // Run self-tests (placeholder - real implementation would test crypto)
    if !run_fips_self_tests() {
        FIPS_MODE.store(FipsState::Failed as u8, Ordering::Release);
        emit_fips_audit_event(false, "self-test failed");
        return Err(FipsError::SelfTestFailed);
    }

    // Enable FIPS mode (sticky)
    FIPS_MODE.store(FipsState::Enabled as u8, Ordering::Release);
    emit_fips_audit_event(true, "enabled");

    Ok(())
}

/// Check if FIPS mode is currently enabled.
#[inline]
pub fn is_fips_enabled() -> bool {
    FIPS_MODE.load(Ordering::Acquire) == FipsState::Enabled as u8
}

/// Get the current FIPS state.
pub fn fips_state() -> FipsState {
    match FIPS_MODE.load(Ordering::Acquire) {
        0 => FipsState::Disabled,
        1 => FipsState::Enabled,
        2 => FipsState::Failed,
        _ => FipsState::Disabled,
    }
}

/// Check if an algorithm is permitted under current FIPS policy.
///
/// In FIPS mode, only FIPS-approved algorithms are allowed.
/// R93-1 FIX: Fail closed if FIPS self-tests failed.
pub fn is_algorithm_permitted(algorithm: CryptoAlgorithm) -> bool {
    match fips_state() {
        FipsState::Disabled => return true, // All algorithms permitted when FIPS is off
        FipsState::Enabled => {}
        // R93-1 FIX: Fail closed if FIPS self-tests failed.
        FipsState::Failed => return false,
    }

    match algorithm {
        // FIPS-approved algorithms
        CryptoAlgorithm::Sha256 => true,
        CryptoAlgorithm::Sha384 => true,
        CryptoAlgorithm::Sha512 => true,
        CryptoAlgorithm::HmacSha256 => true,
        CryptoAlgorithm::EcdsaP256 => true,
        CryptoAlgorithm::EcdsaP384 => true,
        CryptoAlgorithm::Aes128Gcm => true,
        CryptoAlgorithm::Aes256Gcm => true,

        // Non-FIPS algorithms
        CryptoAlgorithm::ChaCha20 => false,
        CryptoAlgorithm::ChaCha20Poly1305 => false,
        CryptoAlgorithm::Ed25519 => false,
        CryptoAlgorithm::Blake2b => false,
    }
}

/// Cryptographic algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    // Hash functions
    Sha256,
    Sha384,
    Sha512,
    Blake2b,

    // MACs
    HmacSha256,

    // Signatures
    EcdsaP256,
    EcdsaP384,
    Ed25519,

    // Encryption
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20,
    ChaCha20Poly1305,
}

// ============================================================================
// FIPS Self-Tests (Placeholder)
// ============================================================================

/// Run FIPS cryptographic self-tests.
///
/// In a real implementation, this would:
/// - Test SHA-256 with known-answer vectors
/// - Test HMAC-SHA256 with known-answer vectors
/// - Test ECDSA signature verification
/// - Test any other approved algorithms
fn run_fips_self_tests() -> bool {
    // Placeholder: always pass for MVP
    // TODO: Implement actual known-answer tests
    true
}

// ============================================================================
// Audit Integration
// ============================================================================

/// Emit FIPS-related audit event.
fn emit_fips_audit_event(success: bool, _message: &str) {
    // Use audit subsystem to log FIPS state changes
    let outcome = if success {
        audit::AuditOutcome::Success
    } else {
        audit::AuditOutcome::Error
    };

    // Encode FIPS event type in args:
    // args[0] = event type: 1 = enable attempt, 2 = self-test
    // args[1] = success flag: 1 = success, 0 = failure
    let event_args: [u64; 2] = [
        1, // FIPS enable event
        if success { 1 } else { 0 },
    ];

    let _ = audit::emit(
        audit::AuditKind::Security,
        outcome,
        audit::AuditSubject::kernel(),
        audit::AuditObject::None,
        &event_args,
        0, // No errno
        0, // Timestamp will be filled by audit subsystem
    );
}

// ============================================================================
// Compliance Status
// ============================================================================

/// Compliance status summary.
#[derive(Debug, Clone, Copy)]
pub struct ComplianceStatus {
    /// Active hardening profile.
    pub profile: HardeningProfile,
    /// Whether profile is locked.
    pub profile_locked: bool,
    /// Current FIPS state.
    pub fips_state: FipsState,
}

/// Get current compliance status.
pub fn status() -> ComplianceStatus {
    ComplianceStatus {
        profile: current_profile(),
        profile_locked: is_profile_locked(),
        fips_state: fips_state(),
    }
}

// ============================================================================
// Internal Helper: Case-insensitive string matching (no_std compatible)
// ============================================================================

impl HardeningProfile {
    /// Internal case-insensitive byte slice matching.
    fn from_str_internal(s: &[u8]) -> Option<Self> {
        // Convert to lowercase in fixed-size buffer
        let lower: [u8; 16] = {
            let mut buf = [0u8; 16];
            for (i, &b) in s.iter().take(16).enumerate() {
                buf[i] = if b >= b'A' && b <= b'Z' {
                    b + 32
                } else {
                    b
                };
            }
            buf
        };
        let len = s.len().min(16);
        let lower_slice = &lower[..len];

        if lower_slice == b"secure" || lower_slice == b"strict" || lower_slice == b"hardened" {
            Some(Self::Secure)
        } else if lower_slice == b"balanced" || lower_slice == b"default" || lower_slice == b"normal" {
            Some(Self::Balanced)
        } else if lower_slice == b"performance" || lower_slice == b"perf" || lower_slice == b"fast" {
            Some(Self::Performance)
        } else {
            None
        }
    }
}
