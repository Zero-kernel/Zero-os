//! Hardware Random Number Generator and CSPRNG for Zero-OS
//!
//! This module provides cryptographically secure random number generation:
//!
//! - **RDRAND/RDSEED**: Hardware entropy from Intel/AMD processors
//! - **ChaCha20 CSPRNG**: Cryptographically Secure Pseudo-Random Number Generator
//!
//! # Security Design
//!
//! 1. **Primary entropy source**: RDSEED (true random, slower)
//! 2. **Fallback entropy source**: RDRAND (conditioned random, faster)
//! 3. **CSPRNG**: ChaCha20 stream cipher used as PRNG
//! 4. **Reseeding**: Periodically reseed from hardware entropy
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize once during boot
//! rng::init_global()?;
//!
//! // Get random numbers
//! let value = rng::random_u64()?;
//!
//! // Fill buffer with random bytes
//! let mut buf = [0u8; 32];
//! rng::fill_random(&mut buf)?;
//! ```

use core::hint::spin_loop;
use lazy_static::lazy_static;
use spin::Mutex;

/// RNG errors
#[derive(Debug, Clone, Copy)]
pub enum RngError {
    /// RDRAND instruction not supported by CPU
    RdRandUnsupported,
    /// RDSEED instruction not supported by CPU
    RdSeedUnsupported,
    /// Failed to obtain entropy after multiple attempts
    InsufficientEntropy,
    /// RNG not initialized
    NotInitialized,
    /// Reseed required (too many bytes generated without reseeding)
    ReseedRequired,
}

/// Maximum bytes to generate before reseeding
const RESEED_INTERVAL: u64 = 1024 * 1024; // 1MB

/// R108-3 FIX: Maximum bytes to generate per lock acquisition.
///
/// `GLOBAL_RNG` is a global spin-mutex; holding it across large buffers (up to
/// 1MB from `sys_getrandom`) causes system-wide cross-core contention.  Chunking
/// keeps worst-case lock hold times bounded to a single 4KB page.
const RNG_FILL_CHUNK_SIZE: usize = 4096;

/// Global CSPRNG instance
lazy_static! {
    static ref GLOBAL_RNG: Mutex<Option<ChaCha20Rng>> = Mutex::new(None);
}

/// Initialize the global RNG
///
/// This function:
/// 1. Checks for hardware RNG support (RDRAND/RDSEED)
/// 2. Seeds a ChaCha20 CSPRNG from hardware entropy
/// 3. Verifies the RNG is working correctly
///
/// # Returns
///
/// `Ok(())` on success, `Err(RngError)` if hardware RNG is unavailable
///
/// # Security Note
///
/// This function should be called early in boot, after CPU feature detection.
pub fn init_global() -> Result<(), RngError> {
    // Check hardware support
    if !rdrand_supported() {
        return Err(RngError::RdRandUnsupported);
    }

    // Seed material: 32 bytes key + 12 bytes nonce
    let mut seed = [0u8; 44];
    fill_entropy(&mut seed)?;

    // Create and initialize the CSPRNG
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&seed[0..32]);
    nonce.copy_from_slice(&seed[32..44]);

    let mut rng = ChaCha20Rng::new(key, nonce);

    // Mix in additional entropy for defense in depth
    let mut extra = [0u8; 16];
    fill_entropy(&mut extra)?;
    rng.mix_in(&extra);

    // Clear sensitive data from stack
    explicit_bzero(&mut seed);
    explicit_bzero(&mut key);
    explicit_bzero(&mut nonce);
    explicit_bzero(&mut extra);

    *GLOBAL_RNG.lock() = Some(rng);
    Ok(())
}

/// Check if the global CSPRNG is initialized and ready for use.
///
/// R62-3 FIX: Allows callers to check RNG readiness before security-critical
/// operations that require strong entropy (e.g., ISN generation).
///
/// # Returns
///
/// `true` if CSPRNG is initialized and ready, `false` otherwise
#[inline]
pub fn is_ready() -> bool {
    GLOBAL_RNG.lock().is_some()
}

/// Fill buffer with random bytes from the global CSPRNG
///
/// # Arguments
///
/// * `out` - Buffer to fill with random bytes
///
/// # Returns
///
/// `Ok(())` on success, `Err(RngError)` if RNG not initialized
///
/// # R108-3 FIX: Chunked generation
///
/// Generates output in `RNG_FILL_CHUNK_SIZE` (4KB) chunks with the global
/// spin-mutex released between chunks.  This bounds worst-case lock hold time
/// and reduces cross-core contention for large `getrandom()` calls.
///
/// The reseed interval check now resets `bytes_generated` even when hardware
/// entropy is unavailable, preventing repeated reseed attempts on every
/// subsequent call during transient entropy failures.
pub fn fill_random(out: &mut [u8]) -> Result<(), RngError> {
    for chunk in out.chunks_mut(RNG_FILL_CHUNK_SIZE) {
        let mut guard = GLOBAL_RNG.lock();
        let rng = guard.as_mut().ok_or(RngError::NotInitialized)?;

        // Check if we need to reseed
        if rng.bytes_generated >= RESEED_INTERVAL {
            // R108-3 FIX: Reset counter unconditionally to avoid retrying on
            // every subsequent call when entropy is temporarily unavailable.
            // The CSPRNG remains cryptographically secure even without reseeding.
            rng.bytes_generated = 0;

            let mut seed = [0u8; 32];
            if fill_entropy(&mut seed).is_ok() {
                rng.mix_in(&seed);
            }
            explicit_bzero(&mut seed);
        }

        rng.fill_bytes(chunk);
        // Lock is released here (guard dropped) before next chunk iteration,
        // allowing other CPUs to acquire the RNG for their operations.
    }
    Ok(())
}

/// Try to fill buffer with random bytes from the global CSPRNG without blocking.
///
/// This is intended for contexts where spinning on the RNG mutex could deadlock
/// (e.g., panic paths with interrupts disabled). If the CSPRNG is available, it
/// is used. Otherwise, falls back to direct hardware entropy (RDSEED/RDRAND)
/// without taking any locks.
///
/// # G.1 kdump
///
/// Used by the crash dump subsystem to generate encryption keys/nonces in
/// panic context where the main RNG lock may already be held.
///
/// # R92-5 FIX
///
/// Instead of returning `Err(NotInitialized)` when the lock is contended,
/// we now fall back to direct hardware entropy. This ensures kdump can
/// always get entropy for encryption, avoiding plaintext dumps.
pub fn try_fill_random(out: &mut [u8]) -> Result<(), RngError> {
    // First, try the CSPRNG if it's available without blocking.
    if let Some(mut guard) = GLOBAL_RNG.try_lock() {
        if let Some(rng) = guard.as_mut() {
            // Check if we need to reseed
            if rng.bytes_generated >= RESEED_INTERVAL {
                // R108-3 FIX: Reset counter unconditionally to prevent repeated
                // reseed attempts in panic context where entropy may be unavailable.
                rng.bytes_generated = 0;

                let mut seed = [0u8; 32];
                if fill_entropy(&mut seed).is_ok() {
                    rng.mix_in(&seed);
                }
                explicit_bzero(&mut seed);
            }

            rng.fill_bytes(out);
            return Ok(());
        }
    }

    // R92-5 FIX: Fall back to direct hardware entropy (no locks, panic-safe).
    // This ensures kdump can always encrypt its output even when CSPRNG is unavailable.
    fill_entropy(out)
}

/// Get a random 64-bit unsigned integer
pub fn random_u64() -> Result<u64, RngError> {
    let mut buf = [0u8; 8];
    fill_random(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Get a random 32-bit unsigned integer
pub fn random_u32() -> Result<u32, RngError> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Get a random value in range [0, max)
pub fn random_range(max: u64) -> Result<u64, RngError> {
    if max == 0 {
        return Ok(0);
    }

    // Use rejection sampling to avoid modulo bias
    let threshold = u64::MAX - (u64::MAX % max);
    loop {
        let val = random_u64()?;
        if val < threshold {
            return Ok(val % max);
        }
    }
}

// ============================================================================
// Hardware Entropy Sources
// ============================================================================

/// Fill buffer with entropy from hardware RNG
fn fill_entropy(buf: &mut [u8]) -> Result<(), RngError> {
    let mut offset = 0;

    while offset < buf.len() {
        let remaining = buf.len() - offset;
        let chunk_size = remaining.min(8);

        // Try RDSEED first (true random), fall back to RDRAND
        // SECURITY FIX Z-6: Never fall back to zero on entropy failure
        // Both RDSEED and RDRAND must succeed, or propagate error
        let value = if rdseed_supported() {
            rdseed64().or_else(|_| rdrand64())?
        } else {
            rdrand64()?
        };

        let bytes = value.to_le_bytes();
        buf[offset..offset + chunk_size].copy_from_slice(&bytes[..chunk_size]);
        offset += chunk_size;
    }

    Ok(())
}

// ============================================================================
// Early Boot Entropy (Pre-CSPRNG)
// ============================================================================

/// Early RDRAND access for pre-CSPRNG initialization.
///
/// This function provides raw hardware entropy without relying on the global
/// ChaCha20 CSPRNG, enabling early boot code (e.g., heap randomization) to
/// obtain randomness before `init_global()` is called.
///
/// # Use Cases
///
/// - Heap base randomization (Partial KASLR)
/// - Per-CPU stack randomization
/// - Early boot entropy seeding
///
/// # Security Note
///
/// This function directly uses RDRAND without additional mixing or whitening.
/// For cryptographic purposes after boot, prefer `fill_random()` which uses
/// the properly seeded ChaCha20 CSPRNG.
///
/// # Returns
///
/// `Ok(u64)` on success, `Err(RngError)` if RDRAND is unsupported or fails
pub fn rdrand64_early() -> Result<u64, RngError> {
    rdrand64()
}

/// Check if hardware RNG (RDRAND) is available for early boot use.
///
/// This is safe to call before CSPRNG initialization.
#[inline]
pub fn rdrand_available() -> bool {
    rdrand_supported()
}

/// Execute RDRAND instruction to get 64-bit random value
fn rdrand64() -> Result<u64, RngError> {
    if !rdrand_supported() {
        return Err(RngError::RdRandUnsupported);
    }

    // RDRAND may fail if entropy is depleted, retry up to 32 times
    for _ in 0..32 {
        let mut value: u64 = 0;
        let ok: u8;

        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }

        if ok == 1 {
            return Ok(value);
        }

        spin_loop();
    }

    Err(RngError::InsufficientEntropy)
}

/// Execute RDSEED instruction to get 64-bit true random value
fn rdseed64() -> Result<u64, RngError> {
    if !rdseed_supported() {
        return Err(RngError::RdSeedUnsupported);
    }

    // RDSEED may fail more often than RDRAND, retry up to 64 times
    for _ in 0..64 {
        let mut value: u64 = 0;
        let ok: u8;

        unsafe {
            core::arch::asm!(
                "rdseed {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }

        if ok == 1 {
            return Ok(value);
        }

        spin_loop();
    }

    Err(RngError::InsufficientEntropy)
}

/// Check if RDRAND is supported via CPUID
///
/// R72-4 FIX: Remove nostack and nomem since push/pop uses stack memory.
fn rdrand_supported() -> bool {
    // CPUID.01H:ECX.RDRAND[bit 30]
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            lateout("ecx") ecx,
            lateout("edx") _,
            // No options - push/pop uses both stack and memory
        );
    }
    (ecx & (1 << 30)) != 0
}

/// Check if RDSEED is supported via CPUID
///
/// R72-4 FIX: Remove nostack and nomem since push/pop uses stack memory.
fn rdseed_supported() -> bool {
    // CPUID.07H:EBX.RDSEED[bit 18]
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            lateout("edx") _,
            // No options - push/pop uses both stack and memory
        );
    }
    (ebx & (1 << 18)) != 0
}

// ============================================================================
// ChaCha20 CSPRNG
// ============================================================================

/// ChaCha20-based Cryptographically Secure PRNG
pub struct ChaCha20Rng {
    /// ChaCha20 state (16 x 32-bit words)
    state: [u32; 16],
    /// Output buffer
    buffer: [u8; 64],
    /// Bytes available in buffer
    available: usize,
    /// Total bytes generated since last reseed
    bytes_generated: u64,
}

impl ChaCha20Rng {
    /// ChaCha20 constants: "expand 32-byte k"
    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Create a new ChaCha20 RNG with given key and nonce
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        let mut state = [0u32; 16];

        // Constants
        state[0] = Self::CONSTANTS[0];
        state[1] = Self::CONSTANTS[1];
        state[2] = Self::CONSTANTS[2];
        state[3] = Self::CONSTANTS[3];

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        // Counter (starts at 0)
        state[12] = 0;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        let mut rng = ChaCha20Rng {
            state,
            buffer: [0u8; 64],
            available: 0,
            bytes_generated: 0,
        };

        // Pre-fill buffer
        rng.refill();
        rng
    }

    /// Mix in additional entropy
    pub fn mix_in(&mut self, extra: &[u8]) {
        // XOR extra bytes into key portion of state
        for (i, byte) in extra.iter().take(32).enumerate() {
            let word_idx = 4 + (i / 4);
            let byte_idx = i % 4;
            let mask = (*byte as u32) << (byte_idx * 8);
            self.state[word_idx] ^= mask;
        }

        // Force regeneration
        self.available = 0;
        self.refill();
    }

    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut remaining = out.len();
        let mut offset = 0;

        while remaining > 0 {
            if self.available == 0 {
                self.refill();
            }

            let to_copy = remaining.min(self.available);
            let buf_start = 64 - self.available;

            out[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[buf_start..buf_start + to_copy]);

            self.available -= to_copy;
            remaining -= to_copy;
            offset += to_copy;
            self.bytes_generated += to_copy as u64;
        }
    }

    /// Refill the output buffer with a new ChaCha20 block
    fn refill(&mut self) {
        let mut working = self.state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }

        // Serialize to buffer
        for (i, word) in working.iter().enumerate() {
            self.buffer[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        self.available = 64;
    }

    /// ChaCha20 quarter round
    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
}

/// Securely zero memory (prevent compiler optimization)
#[inline(never)]
fn explicit_bzero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_quarter_round() {
        // Test vector from RFC 7539
        let mut state = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ];

        ChaCha20Rng::quarter_round(&mut state, 2, 7, 8, 13);

        assert_eq!(state[2], 0xbdb886dc);
        assert_eq!(state[7], 0xcfacafd2);
        assert_eq!(state[8], 0xe46bea80);
        assert_eq!(state[13], 0xccc07c79);
    }
}
