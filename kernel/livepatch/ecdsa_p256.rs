//! ECDSA P-256 verification helper (no_std).
//!
//! Implements ECDSA P-256 signature verification for the livepatch subsystem with:
//! - Public key: SEC1 uncompressed (65 bytes): `0x04 || X || Y`
//! - Signature: IEEE P1363 fixed-size (64 bytes): `r || s` (big-endian, 32 bytes each)
//! - Verification input: SHA-256 digest (prehash), NOT raw message
//! - FIPS-style KAT gate: verification disabled until Known Answer Test passes
//!
//! # Security Properties
//!
//! - Constant-time field arithmetic (via `p256` crate's `arithmetic` feature)
//! - No heap allocation during verification
//! - KAT must pass before any production signature can be verified
//! - Multiple trusted keys supported for key rotation
//!
//! # Implementation Notes
//!
//! This module uses `ecdsa::hazmat::verify_prehashed` directly instead of the higher-level
//! `PrehashVerifier` trait. This avoids pulling in `sha2` (which has LLVM issues on
//! bare-metal targets) while still providing cryptographically secure verification.
//!
//! # References
//!
//! - NIST FIPS 186-4 (Digital Signature Standard)
//! - NIST CAVP ECDSA test vectors (186-4ecdsatestvectors.zip)
//! - RFC 6979 (Deterministic ECDSA - for test vector generation)

use core::sync::atomic::{AtomicU8, Ordering};

// Low-level ECDSA verification API (no sha2 dependency).
use ecdsa::hazmat::verify_prehashed;
use ecdsa::Signature;
use p256::{FieldBytes, NistP256, PublicKey};

// ============================================================================
// Error types
// ============================================================================

/// Errors from ECDSA P-256 verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// FIPS Known Answer Test failed; all cryptographic operations are disabled.
    KatFailed,
    /// No trusted public keys are configured (all placeholders are all-zero).
    NoTrustedPublicKeys,
    /// Public key is not a valid SEC1 uncompressed P-256 point.
    InvalidPublicKey,
    /// Signature is not a valid IEEE P1363 fixed-size (r||s) 64-byte blob.
    InvalidSignature,
    /// Signature did not verify under any trusted key (cryptographic failure).
    SignatureInvalid,
}

// ============================================================================
// KAT state machine
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KatState {
    /// Not yet initialized.
    Uninit = 0,
    /// KAT is currently running (one-shot, taken by first caller).
    Running = 1,
    /// KAT passed; cryptographic operations are enabled.
    Pass = 2,
    /// KAT failed; all cryptographic operations are disabled.
    Fail = 3,
}

impl KatState {
    #[inline]
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => KatState::Uninit,
            1 => KatState::Running,
            2 => KatState::Pass,
            _ => KatState::Fail,
        }
    }
}

/// Global KAT state. Verification is disabled until this transitions to `Pass`.
static KAT_STATE: AtomicU8 = AtomicU8::new(KatState::Uninit as u8);

// ============================================================================
// Utility functions
// ============================================================================

/// Constant-time check if a byte slice is all zeros.
///
/// Uses XOR accumulator to avoid early-exit leaking information about key content.
/// The volatile read prevents the compiler from optimizing away the loop.
#[inline]
fn ct_is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    // Volatile read prevents compiler from short-circuiting the loop.
    // This is a defense-in-depth measure for constant-time behavior.
    unsafe { core::ptr::read_volatile(&acc) == 0 }
}

// ============================================================================
// KAT implementation
// ============================================================================

/// Ensure the FIPS Known Answer Test has passed.
///
/// This function is idempotent and thread-safe. On first call, it runs the KAT.
/// Subsequent calls observe the cached result. Returns `true` if KAT passed.
///
/// # R94-1 FIX: Deadlock-Free KAT Execution
///
/// Previous implementation used `spin_loop()` to wait for a concurrent KAT runner.
/// On single-core CPUs or with strict priority scheduling, this caused permanent
/// deadlock: the waiting thread would starve the runner thread, preventing KAT
/// completion and blocking all livepatch verification indefinitely.
///
/// New design: each caller independently runs the KAT and attempts to publish the
/// result. This is safe because:
/// - `run_kat()` is a pure computation over constant test vectors (idempotent, no side effects)
/// - `Fail` is sticky: once any caller observes a KAT failure, it is permanent
/// - `Pass` is only published if no concurrent caller has already set `Fail`
/// - No thread ever blocks waiting for another thread
///
/// # Behavior
///
/// - If KAT is `Pass`, returns `true` immediately.
/// - If KAT is `Fail`, returns `false` immediately.
/// - If KAT is `Uninit` or `Running`, the caller runs KAT locally and publishes results.
#[inline]
fn ensure_kat() -> bool {
    // Fast path: check if KAT already completed.
    match KatState::from_u8(KAT_STATE.load(Ordering::Acquire)) {
        KatState::Pass => return true,
        KatState::Fail => return false,
        _ => {}
    }

    // Slow path: KAT not yet complete.
    //
    // R94-1 FIX: Never spin_loop() waiting for another thread. On single-core or
    // with strict priority scheduling, spinning deadlocks the system. Instead, each
    // caller runs KAT independently and attempts to publish the result.

    // Best-effort: mark KAT as Running for diagnostics. This is not required for
    // correctness — it merely reduces redundant KAT executions in the common case.
    let _claimed = KAT_STATE
        .compare_exchange(
            KatState::Uninit as u8,
            KatState::Running as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok();

    // Re-check: a concurrent caller may have published a terminal state while we
    // attempted the CAS above.
    match KatState::from_u8(KAT_STATE.load(Ordering::Acquire)) {
        KatState::Pass => return true,
        KatState::Fail => return false,
        _ => {} // Uninit or Running — proceed with local KAT execution
    }

    // Run KAT locally. This is pure computation over constant test vectors:
    // safe to run concurrently from multiple threads without side effects.
    let ok = run_kat();

    if !ok {
        // Fail-closed: immediately publish failure. This is sticky — once Fail is
        // set, no subsequent Pass can override it, ensuring fail-closed semantics.
        KAT_STATE.store(KatState::Fail as u8, Ordering::Release);
        return false;
    }

    // Publish Pass, but only if no concurrent caller has already set Fail.
    // Uses a CAS loop to avoid overwriting a Fail state with Pass.
    let mut cur = KAT_STATE.load(Ordering::Acquire);
    loop {
        match KatState::from_u8(cur) {
            KatState::Pass => return true,
            KatState::Fail => return false, // Respect sticky failure from another caller
            KatState::Uninit | KatState::Running => {
                match KAT_STATE.compare_exchange(
                    cur,
                    KatState::Pass as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(next) => cur = next, // Retry with updated state
                }
            }
        }
    }
}

/// Run the FIPS Known Answer Test for ECDSA P-256.
///
/// Uses the RFC 6979 Appendix A.2.5 test vector (ECDSA P-256 with SHA-256).
/// This is a well-known, reproducible test case for deterministic ECDSA.
///
/// # Test Vector Details
///
/// - Curve: P-256 (secp256r1)
/// - Hash: SHA-256
/// - Private key d: C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
/// - Message: "sample" (ASCII)
/// - Digest: SHA-256("sample") = AF2B...D1BF (32 bytes)
/// - Public key: Uncompressed SEC1 format (65 bytes)
/// - Signature: r||s fixed-size format (64 bytes, deterministic per RFC 6979)
fn run_kat() -> bool {
    // RFC 6979 Appendix A.2.5 P-256/SHA-256 test vector.
    //
    // This is a well-known test vector for deterministic ECDSA.
    // Using RFC 6979 deterministic ECDSA with:
    //   - Private key d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    //   - Message: "sample"
    //
    // Public key (uncompressed SEC1):
    const PUBKEY_UNCOMPRESSED: [u8; 65] = [
        0x04,
        // X coordinate (32 bytes)
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        // Y coordinate (32 bytes)
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
    ];

    // SHA-256("sample") - the prehash digest.
    const DIGEST: [u8; 32] = [
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
    ];

    // RFC 6979 deterministic ECDSA signature for the above.
    // Signature (r || s), 64 bytes total.
    const SIG_RS: [u8; 64] = [
        // r (32 bytes)
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
        // s (32 bytes)
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
    ];

    // Positive KAT: Valid signature must verify.
    if verify_prehash_unchecked(&PUBKEY_UNCOMPRESSED, &DIGEST, &SIG_RS).is_err() {
        return false;
    }

    // R94-2 FIX: Negative KATs to ensure verifier is not fail-open.
    //
    // If verify_prehash_unchecked regresses to always return Ok(), these tests catch it.
    // Both must fail for the KAT to pass.

    // Negative KAT 1: Corrupted signature must fail.
    // Flip one bit in the signature - this must invalidate it.
    let mut corrupted_sig = SIG_RS;
    corrupted_sig[0] ^= 0x01;
    if verify_prehash_unchecked(&PUBKEY_UNCOMPRESSED, &DIGEST, &corrupted_sig).is_ok() {
        return false; // Fail-open detected: corrupted sig should NOT verify
    }

    // Negative KAT 2: Wrong digest must fail.
    // Flip one bit in the digest - the signature is for the original digest.
    let mut wrong_digest = DIGEST;
    wrong_digest[0] ^= 0x01;
    if verify_prehash_unchecked(&PUBKEY_UNCOMPRESSED, &wrong_digest, &SIG_RS).is_ok() {
        return false; // Fail-open detected: wrong digest should NOT verify
    }

    true
}

// ============================================================================
// Core verification (unchecked - no KAT gate)
// ============================================================================

/// Verify an ECDSA P-256 signature over a SHA-256 prehash (digest).
///
/// This is the raw verification function WITHOUT KAT gate. Use `verify_prehash()`
/// for production code, which enforces the KAT gate.
fn verify_prehash_unchecked(
    pubkey_uncompressed: &[u8; 65],
    digest: &[u8; 32],
    sig_rs: &[u8; 64],
) -> Result<(), VerifyError> {
    // Parse the fixed-size signature (r || s, 64 bytes).
    let signature = Signature::<NistP256>::from_slice(sig_rs)
        .map_err(|_| VerifyError::InvalidSignature)?;

    // Parse the uncompressed SEC1 public key (0x04 || X || Y, 65 bytes).
    let public_key = PublicKey::from_sec1_bytes(pubkey_uncompressed)
        .map_err(|_| VerifyError::InvalidPublicKey)?;

    // Convert digest to FieldBytes for the hazmat API.
    // For P-256 + SHA-256, the digest is exactly 32 bytes (same as field size).
    let mut z = FieldBytes::default();
    z.copy_from_slice(digest);

    // Convert public key to projective point for verification.
    let q = public_key.to_projective();

    // Verify the signature using the low-level hazmat API.
    verify_prehashed::<NistP256>(&q, &z, &signature)
        .map_err(|_| VerifyError::SignatureInvalid)
}

// ============================================================================
// Public API
// ============================================================================

/// Verify an ECDSA P-256 signature over a SHA-256 prehash (digest).
///
/// This function is KAT-gated: it returns `Err(KatFailed)` until the FIPS
/// Known Answer Test passes. After KAT passes, verification is performed.
///
/// # Arguments
///
/// * `pubkey_uncompressed` - SEC1 uncompressed public key (65 bytes, 0x04 prefix)
/// * `digest` - SHA-256 digest of the message (32 bytes)
/// * `sig_rs` - IEEE P1363 fixed-size signature (64 bytes, r||s big-endian)
///
/// # Returns
///
/// * `Ok(())` - Signature is valid.
/// * `Err(VerifyError)` - Signature verification failed for the specified reason.
#[allow(dead_code)]
pub fn verify_prehash(
    pubkey_uncompressed: &[u8; 65],
    digest: &[u8; 32],
    sig_rs: &[u8; 64],
) -> Result<(), VerifyError> {
    if !ensure_kat() {
        return Err(VerifyError::KatFailed);
    }
    verify_prehash_unchecked(pubkey_uncompressed, digest, sig_rs)
}

/// Verify an ECDSA P-256 signature against multiple trusted public keys.
///
/// This function supports key rotation by checking the signature against all
/// non-zero trusted keys. Returns `Ok(())` if ANY trusted key validates the signature.
///
/// # Arguments
///
/// * `trusted_pubkeys_uncompressed` - Array of SEC1 uncompressed public keys (65 bytes each)
/// * `digest` - SHA-256 digest of the message (32 bytes)
/// * `sig_rs` - IEEE P1363 fixed-size signature (64 bytes, r||s big-endian)
///
/// # Security
///
/// - All-zero public keys are treated as empty slots and skipped.
/// - Constant-time comparison is used to detect all-zero keys.
/// - KAT gate is enforced before any cryptographic operation.
///
/// # Returns
///
/// * `Ok(())` - Signature is valid under at least one trusted key.
/// * `Err(NoTrustedPublicKeys)` - All trusted keys are all-zero placeholders.
/// * `Err(SignatureInvalid)` - Signature did not verify under any trusted key.
pub fn verify_prehash_any(
    trusted_pubkeys_uncompressed: &[[u8; 65]],
    digest: &[u8; 32],
    sig_rs: &[u8; 64],
) -> Result<(), VerifyError> {
    // Enforce KAT gate.
    if !ensure_kat() {
        return Err(VerifyError::KatFailed);
    }

    // Reject if all trusted keys are all-zero placeholders.
    if trusted_pubkeys_uncompressed
        .iter()
        .all(|k| ct_is_all_zero(k))
    {
        return Err(VerifyError::NoTrustedPublicKeys);
    }

    // Parse the signature once (shared across all key attempts).
    let signature = Signature::<NistP256>::from_slice(sig_rs)
        .map_err(|_| VerifyError::InvalidSignature)?;

    // Convert digest to FieldBytes once (shared across all key attempts).
    let mut z = FieldBytes::default();
    z.copy_from_slice(digest);

    let mut saw_parseable_key = false;

    for pubkey in trusted_pubkeys_uncompressed.iter() {
        // Skip all-zero placeholders (staged key rollout support).
        if ct_is_all_zero(pubkey) {
            continue;
        }

        // Attempt to parse the public key.
        let public_key = match PublicKey::from_sec1_bytes(pubkey) {
            Ok(k) => {
                saw_parseable_key = true;
                k
            }
            Err(_) => continue, // Skip malformed keys.
        };

        // Convert to projective point for verification.
        let q = public_key.to_projective();

        // Verify the signature (accept if ANY trusted key succeeds).
        if verify_prehashed::<NistP256>(&q, &z, &signature).is_ok() {
            return Ok(());
        }
    }

    if saw_parseable_key {
        Err(VerifyError::SignatureInvalid)
    } else {
        Err(VerifyError::InvalidPublicKey)
    }
}

/// Returns `true` if the KAT has passed.
///
/// This can be used for diagnostic purposes to check if the ECDSA
/// subsystem is operational without performing a verification.
#[allow(dead_code)]
pub fn is_kat_passed() -> bool {
    KatState::from_u8(KAT_STATE.load(Ordering::Acquire)) == KatState::Pass
}

/// Force the KAT to run if it hasn't been run yet.
///
/// Returns `true` if the KAT passed.
#[allow(dead_code)]
pub fn run_kat_if_needed() -> bool {
    ensure_kat()
}
