//! Kernel Pointer Guard for Zero-OS
//!
//! This module provides kernel pointer obfuscation to prevent information
//! leakage through kernel logs. Similar to Linux's `%pK` format specifier.
//!
//! # Security Goals
//!
//! 1. **Prevent KASLR Bypass**: Obfuscate kernel addresses in logs
//! 2. **Defense in Depth**: Even if logs are leaked, addresses are masked
//! 3. **Runtime Toggle**: Can be disabled for debugging
//!
//! # Usage
//!
//! ```rust,ignore
//! use security::KptrGuard;
//!
//! let ptr: *const u8 = some_kernel_address();
//! println!("Address: {}", KptrGuard::new(ptr));  // Shows obfuscated address
//! ```

use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Global switch for pointer obfuscation.
/// When enabled, all KptrGuard displays show obfuscated addresses.
static KPTR_GUARD_ENABLED: AtomicBool = AtomicBool::new(true);

/// Secret material mixed into addresses for obfuscation.
/// Initialized from hardware entropy or TSC at boot.
static KPTR_SECRET: AtomicU64 = AtomicU64::new(0);

/// Counter for additional entropy mixing (prevents replay attacks).
static KPTR_COUNTER: AtomicU64 = AtomicU64::new(0);
// R163-35 FIX: Track whether kptr has been seeded with strong entropy.
// Before reseed_from_entropy() is called, the TSC-based secret is weak.
static KPTR_STRONG_SEEDED: AtomicBool = AtomicBool::new(false);

/// Wrapper for kernel pointers that renders an obfuscated address.
///
/// When displayed via `Display` or `Debug`, the address is obfuscated
/// if the global kptr guard is enabled. The raw address can still be
/// retrieved via `raw()` for internal kernel use.
#[derive(Clone, Copy)]
pub struct KptrGuard {
    addr: u64,
}

impl KptrGuard {
    /// Create a guard from a raw pointer.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let guard = KptrGuard::new(&some_variable as *const _);
    /// ```
    #[inline]
    pub fn new<T>(ptr: *const T) -> Self {
        KptrGuard { addr: ptr as u64 }
    }

    /// Create a guard from a mutable pointer.
    #[inline]
    pub fn from_mut<T>(ptr: *mut T) -> Self {
        KptrGuard { addr: ptr as u64 }
    }

    /// Create a guard from a known address (for tests or diagnostics).
    #[inline]
    pub fn from_addr(addr: u64) -> Self {
        KptrGuard { addr }
    }

    /// Get the raw underlying address.
    ///
    /// # Security Note
    ///
    /// This returns the actual address. Only use internally in the kernel;
    /// never expose this value to user space or logs.
    #[inline]
    pub fn raw(&self) -> u64 {
        self.addr
    }

    /// Get the value that will be displayed given the current global toggle.
    ///
    /// If kptr guard is enabled, returns the obfuscated value.
    /// If disabled, returns the raw address.
    #[inline]
    pub fn guarded_value(&self) -> u64 {
        if is_enabled() {
            obfuscate(self.addr)
        } else {
            self.addr
        }
    }

    /// Get the obfuscated value regardless of global toggle.
    ///
    /// Useful for testing or when you always want obfuscation.
    #[inline]
    pub fn obfuscated_value(&self) -> u64 {
        obfuscate(self.addr)
    }

    /// Check if this appears to be a kernel address (high half).
    #[inline]
    pub fn is_kernel_address(&self) -> bool {
        self.addr >= 0xFFFF_8000_0000_0000
    }
}

impl fmt::Display for KptrGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.guarded_value())
    }
}

impl fmt::Debug for KptrGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_enabled() {
            write!(f, "KptrGuard(0x{:016x})", self.guarded_value())
        } else {
            write!(f, "KptrGuard(0x{:016x} [raw])", self.addr)
        }
    }
}

impl fmt::Pointer for KptrGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.guarded_value())
    }
}

// ============================================================================
// Global Control Functions
// ============================================================================

/// Enable kernel pointer masking (default state).
///
/// When enabled, all `KptrGuard` displays show obfuscated addresses.
#[inline]
pub fn enable() {
    KPTR_GUARD_ENABLED.store(true, Ordering::Release);
}

/// Disable kernel pointer masking.
///
/// # Security Warning
///
/// Only disable for debugging. Production systems should always have
/// kptr guard enabled to prevent information leakage.
#[inline]
pub fn disable() {
    KPTR_GUARD_ENABLED.store(false, Ordering::Release);
}

/// Check whether pointer masking is enabled.
#[inline]
pub fn is_enabled() -> bool {
    KPTR_GUARD_ENABLED.load(Ordering::Acquire)
}

/// Reseed the guard secret with caller-provided entropy.
///
/// Returns the mixed secret value (useful for verification).
pub fn reseed_with(secret: u64) -> u64 {
    let counter = KPTR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = mix64(secret ^ counter);
    KPTR_SECRET.store(mixed, Ordering::SeqCst);
    // R165-11 FIX: Any reseed installs a NEW secret of unknown strength, so the
    // strong-seeded flag must not stay sticky-true from a prior strong reseed
    // (e.g. a later TSC-fallback or arbitrary reseed would otherwise leave
    // kptr_strongly_seeded() reporting true for a now-weak secret). Default to
    // weak here; reseed_from_entropy re-asserts strong only on the RNG path.
    KPTR_STRONG_SEEDED.store(false, Ordering::SeqCst);
    mixed
}

/// Reseed using hardware RNG if available, otherwise TSC.
///
/// This should be called after the RNG subsystem is initialized
/// to get cryptographically strong entropy.
pub fn reseed_from_entropy() -> u64 {
    // R165-11 FIX: Only mark KPTR_STRONG_SEEDED on the actual hardware-RNG path.
    // The previous code set it true unconditionally — including the TSC fallback,
    // which is NOT cryptographically strong — so the flag did not reflect reality.
    // Setting it only on the RNG branch makes the flag truthful for any future
    // consumer (e.g. a strength assertion before exposing hashed kernel pointers).
    if let Ok(val) = super::rng::random_u64() {
        let result = reseed_with(val);
        KPTR_STRONG_SEEDED.store(true, Ordering::SeqCst);
        result
    } else {
        // TSC fallback: reseed, but leave KPTR_STRONG_SEEDED false.
        reseed_with(tsc_entropy())
    }
}

/// R165-11 FIX: Query whether the kptr secret has been seeded from the hardware
/// CSPRNG (strong) rather than the TSC fallback (weak). Turns KPTR_STRONG_SEEDED
/// from a write-only flag into a readable property so a caller that must not
/// expose hashed kernel pointers under weak seeding can gate on it.
#[allow(dead_code)] // Public query API; consumers wired as KASLR-leak gating lands.
pub fn kptr_strongly_seeded() -> bool {
    KPTR_STRONG_SEEDED.load(Ordering::SeqCst)
}

/// Initialize kptr guard with TSC-based entropy.
///
/// Called during early boot before RNG is available.
pub fn init() {
    // Use TSC for initial seeding
    let initial = tsc_entropy();
    KPTR_SECRET.store(mix64(initial), Ordering::SeqCst);
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Obfuscate an address using the active secret.
#[inline]
fn obfuscate(addr: u64) -> u64 {
    let secret = ensure_secret();
    // Use a different mixing strategy for the output
    // This makes it harder to reverse the obfuscation
    let mixed = addr ^ secret;
    mix64(mixed) ^ (addr.rotate_right(17) & 0xFFFF_0000_0000_0000)
}

/// Ensure the secret is initialized, initializing from TSC if needed.
#[inline]
fn ensure_secret() -> u64 {
    let current = KPTR_SECRET.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }

    // Race-safe initialization
    let new_secret = mix64(tsc_entropy());
    match KPTR_SECRET.compare_exchange(0, new_secret, Ordering::SeqCst, Ordering::Acquire) {
        Ok(_) => new_secret,
        Err(existing) => existing,
    }
}

/// SplitMix64-based mixing function for good bit diffusion.
///
/// Based on the splitmix64 PRNG, provides excellent avalanche properties.
#[inline]
fn mix64(mut x: u64) -> u64 {
    // Constants derived from splitmix64
    x ^= 0x9e37_79b9_7f4a_7c15;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

/// Get coarse entropy from the timestamp counter.
///
/// Not cryptographically secure, but provides reasonable initial entropy
/// for pointer obfuscation until the RNG subsystem is initialized.
#[inline]
fn tsc_entropy() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    // R169-L5 FIX (operator-precedence / KASLR-in-logs entropy, VD-08):
    // Assemble the full 64-bit TSC FIRST, then XOR the mixing constant across
    // ALL bits. The prior one-liner
    //   ((high as u64) << 32) | (low as u64) ^ 0x5bf0_a8a5_5a5a_f00d
    // parses (Rust: `^` binds tighter than `|`) as
    //   ((high as u64) << 32) | ((low as u64) ^ 0x5bf0_a8a5_5a5a_f00d)
    // so the constant's HIGH half (0x5bf0_a8a5) was OR-ed into the high TSC
    // bits — forcing those bits permanently to 1 (constant, predictable) and
    // leaving only the low 32 bits actually mixed. The two-statement form makes
    // the precedence unambiguous and mixes the constant into the whole value.
    let tsc = ((high as u64) << 32) | (low as u64);
    tsc ^ 0x5bf0_a8a5_5a5a_f00d
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Format a raw pointer for safe logging.
///
/// This is a convenience function that creates a `KptrGuard` and formats it.
///
/// # Example
///
/// ```rust,ignore
/// println!("Address: {}", kptr::format_ptr(&some_value as *const _));
/// ```
#[inline]
pub fn format_ptr<T>(ptr: *const T) -> KptrGuard {
    KptrGuard::new(ptr)
}

/// Format a raw address for safe logging.
#[inline]
pub fn format_addr(addr: u64) -> KptrGuard {
    KptrGuard::from_addr(addr)
}
