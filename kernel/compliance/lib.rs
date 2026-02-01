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
/// # R93-14 FIX: Real FIPS 140-2/140-3 Known Answer Tests
///
/// This function runs NIST-specified Known Answer Tests (KAT) to verify
/// correct implementation of cryptographic algorithms before enabling FIPS mode.
///
/// Tests include:
/// - SHA-256: NIST FIPS 180-4 / CAVP test vectors
/// - HMAC-SHA256: NIST CSRC example values
///
/// # Returns
///
/// `true` if all self-tests pass, `false` if any test fails.
/// A failure means FIPS mode cannot be enabled.
fn run_fips_self_tests() -> bool {
    fips_kat::run_all()
}

// ============================================================================
// R93-14: FIPS Known Answer Tests (KAT)
// ============================================================================

mod fips_kat {
    use audit::crypto;

    // Architectural note:
    // - We avoid duplicating cryptographic implementations in `compliance`.
    // - Instead, `compliance` orchestrates KATs implemented by the owning subsystem.
    //   This keeps a single source of truth (and avoids drift) at the cost of a
    //   cross-crate dependency.
    // - If ECDSA becomes broadly used outside `livepatch`, consider extracting the
    //   verifier/KAT into a shared kernel crypto crate (to decouple from livepatch).

    /// Constant-time byte slice comparison to prevent timing attacks.
    ///
    /// Always compares all bytes regardless of early mismatch.
    #[inline]
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    /// Run all FIPS KAT tests.
    ///
    /// Returns `true` only if ALL tests pass. Fail-closed design.
    pub(super) fn run_all() -> bool {
        // Add additional KATs here as crypto primitives are added:
        // - AES-GCM: When kernel AES implementation exists
        // - ECDSA P-256: via livepatch::ecdsa_p256 (RFC 6979 A.2.5 KAT)
        kat_sha256() && kat_hmac_sha256() && kat_ecdsa_p256()
    }

    // ------------------------------------------------------------------------
    // SHA-256 KAT (NIST FIPS 180-4 / CAVP)
    // ------------------------------------------------------------------------

    /// SHA-256 Known Answer Tests using NIST test vectors.
    ///
    /// Test vectors from FIPS 180-4 and NIST CAVP:
    /// - Empty message
    /// - "abc"
    /// - 1,000,000 repetitions of 'a' (streaming test)
    fn kat_sha256() -> bool {
        // NIST SHA-256 test vector: SHA-256("")
        const EXPECT_EMPTY: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];

        // NIST SHA-256 test vector: SHA-256("abc")
        const EXPECT_ABC: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        // NIST FIPS 180-4 example: SHA-256("a" x 1,000,000)
        const EXPECT_1M_A: [u8; 32] = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];

        // Test 1: Empty message
        if !ct_eq(&crypto::sha256_digest(b""), &EXPECT_EMPTY) {
            return false;
        }

        // Test 2: Short message "abc"
        if !ct_eq(&crypto::sha256_digest(b"abc"), &EXPECT_ABC) {
            return false;
        }

        // Test 3: Long message (streaming, no heap allocation)
        // Uses 64-byte blocks to match SHA-256 block size
        let mut hasher = crypto::StreamingSha256::new();
        let block = [b'a'; 64];
        let mut remaining = 1_000_000usize;
        while remaining >= block.len() {
            hasher.update(&block);
            remaining -= block.len();
        }
        if remaining != 0 {
            hasher.update(&block[..remaining]);
        }
        if !ct_eq(&hasher.finalize(), &EXPECT_1M_A) {
            return false;
        }

        true
    }

    // ------------------------------------------------------------------------
    // HMAC-SHA256 KAT (NIST CSRC / RFC 4231)
    // ------------------------------------------------------------------------

    /// HMAC-SHA256 Known Answer Tests using NIST CSRC example values.
    ///
    /// Test vectors from NIST CSRC HMAC_SHA256.pdf:
    /// - Key length = block length (64 bytes)
    /// - Key length < block length (32 bytes)
    /// - Key length > block length (100 bytes, triggers key hashing)
    fn kat_hmac_sha256() -> bool {
        // NIST CSRC Test Vector 1:
        // Key = 0x00..0x3f (64 bytes), Msg = "Sample message for keylen=blocklen"
        const EXPECT_V1: [u8; 32] = [
            0x8b, 0xb9, 0xa1, 0xdb, 0x98, 0x06, 0xf2, 0x0d, 0xf7, 0xf7, 0x7b, 0x82, 0x13, 0x8c,
            0x79, 0x14, 0xd1, 0x74, 0xd5, 0x9e, 0x13, 0xdc, 0x4d, 0x01, 0x69, 0xc9, 0x05, 0x7b,
            0x13, 0x3e, 0x1d, 0x62,
        ];

        // NIST CSRC Test Vector 2:
        // Key = 0x00..0x1f (32 bytes), Msg = "Sample message for keylen<blocklen"
        const EXPECT_V2: [u8; 32] = [
            0xa2, 0x8c, 0xf4, 0x31, 0x30, 0xee, 0x69, 0x6a, 0x98, 0xf1, 0x4a, 0x37, 0x67, 0x8b,
            0x56, 0xbc, 0xfc, 0xbd, 0xd9, 0xe5, 0xcf, 0x69, 0x71, 0x7f, 0xec, 0xf5, 0x48, 0x0f,
            0x0e, 0xbd, 0xf7, 0x90,
        ];

        // NIST CSRC Test Vector 3:
        // Key = 0x00..0x63 (100 bytes), Msg = "Sample message for keylen=blocklen"
        // This tests the HMAC key > blocksize path (key gets hashed first)
        const EXPECT_V3: [u8; 32] = [
            0xbd, 0xcc, 0xb6, 0xc7, 0x2d, 0xde, 0xad, 0xb5, 0x00, 0xae, 0x76, 0x83, 0x86, 0xcb,
            0x38, 0xcc, 0x41, 0xc6, 0x3d, 0xbb, 0x08, 0x78, 0xdd, 0xb9, 0xc7, 0xa3, 0x8a, 0x43,
            0x1b, 0x78, 0x37, 0x8d,
        ];

        // Test 1: Key length = block length (64 bytes)
        let mut key_64 = [0u8; 64];
        for (i, b) in key_64.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mac = crypto::hmac_sha256_digest(&key_64, b"Sample message for keylen=blocklen");
        if !ct_eq(&mac, &EXPECT_V1) {
            return false;
        }

        // Test 2: Key length < block length (32 bytes)
        let mut key_32 = [0u8; 32];
        for (i, b) in key_32.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mac = crypto::hmac_sha256_digest(&key_32, b"Sample message for keylen<blocklen");
        if !ct_eq(&mac, &EXPECT_V2) {
            return false;
        }

        // Test 3: Key length > block length (100 bytes)
        // This exercises the HMAC key hashing path
        let mut key_100 = [0u8; 100];
        for (i, b) in key_100.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mac = crypto::hmac_sha256_digest(&key_100, b"Sample message for keylen=blocklen");
        if !ct_eq(&mac, &EXPECT_V3) {
            return false;
        }

        true
    }

    // ------------------------------------------------------------------------
    // ECDSA P-256 KAT (RFC 6979 Appendix A.2.5)
    // ------------------------------------------------------------------------

    /// ECDSA P-256 Known Answer Test.
    ///
    /// Delegates to the kernel's existing ECDSA P-256 verifier KAT in
    /// `livepatch::ecdsa_p256` (RFC 6979 Appendix A.2.5).
    ///
    /// The livepatch module uses a deterministic ECDSA test vector:
    /// - Private key d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    /// - Message: "sample"
    /// - Prehash: SHA-256("sample")
    /// - The signature (r||s) is verified against the public key derived from d.
    fn kat_ecdsa_p256() -> bool {
        livepatch::ecdsa_p256::run_kat_if_needed()
    }
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
