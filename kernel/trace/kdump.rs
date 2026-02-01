//! G.1 kdump: Encrypted, Redacted Kernel Crash Dump
//!
//! Provides crash dump functionality for post-mortem analysis with:
//! - **Encryption**: ChaCha20 stream cipher protects dump contents
//! - **Pointer redaction**: KptrGuard obfuscates kernel addresses (KASLR protection)
//! - **Size-bounded**: ~4KB max dump to avoid hanging during panic
//! - **No heap allocation**: Safe to call in panic context
//!
//! # Output Format
//!
//! ```text
//! --BEGIN ZOS-KDUMP--
//! v=1 enc=chacha20 nonce=<hex> len=<bytes>
//! <base64-encoded encrypted dump>
//! --END ZOS-KDUMP--
//! ```
//!
//! # Usage
//!
//! Called automatically from the panic handler:
//! ```rust,ignore
//! #[panic_handler]
//! fn panic(info: &PanicInfo) -> ! {
//!     let dump = trace::kdump::capture_crash_context(info);
//!     // ... print panic message ...
//!     trace::kdump::emit_encrypted_dump(dump);
//!     loop { hlt(); }
//! }
//! ```

use core::{
    arch::asm,
    fmt,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use compliance::is_fips_enabled;
use security::{try_fill_random, ChaCha20Rng, KptrGuard};

// ============================================================================
// Constants
// ============================================================================

/// Magic header for kdump format validation
const KDUMP_MAGIC: [u8; 4] = *b"ZKD1";

/// Kdump format version
const KDUMP_VERSION: u16 = 1;

/// Maximum plaintext dump size before encryption (~3KB)
const KDUMP_MAX_PLAINTEXT: usize = 3072;

/// Maximum panic file path length
const PANIC_FILE_MAX: usize = 128;

/// Maximum panic message length
const PANIC_MSG_MAX: usize = 384;

/// Stack dump size in bytes (~1.5KB)
const STACK_DUMP_BYTES: usize = 1536;

/// Serial port for dump output
const SERIAL_PORT: u16 = 0x3F8;

/// Base64 line length for readability
const BASE64_LINE: usize = 64;

// Flag bits for dump metadata
const FLAG_PANIC_MSG_TRUNC: u16 = 1 << 0;
const FLAG_PANIC_FILE_TRUNC: u16 = 1 << 1;
const FLAG_STACK_SKIPPED: u16 = 1 << 2;
const FLAG_REDACTED_PTRS: u16 = 1 << 3;
const FLAG_ENCRYPTED: u16 = 1 << 4;

// ============================================================================
// CPU Register State
// ============================================================================

/// CPU register snapshot at crash time.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CpuRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr3: u64,
}

impl CpuRegs {
    /// Create a zeroed register set.
    pub const fn zeroed() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rsp: 0, rflags: 0, cr3: 0,
        }
    }
}

// ============================================================================
// Crash Dump Structure
// ============================================================================

/// Complete crash dump structure.
///
/// All fields are fixed-size to avoid heap allocation in panic context.
pub struct CrashDump {
    /// Format version
    pub version: u16,
    /// Metadata flags
    pub flags: u16,
    /// TSC timestamp at crash
    pub tsc: u64,
    /// CPU register state (redacted)
    pub regs: CpuRegs,

    /// Panic file path length
    pub panic_file_len: u16,
    /// Panic file path (truncated)
    pub panic_file: [u8; PANIC_FILE_MAX],
    /// Panic line number
    pub panic_line: u32,
    /// Panic column number
    pub panic_col: u32,

    /// Panic message length
    pub panic_msg_len: u16,
    /// Panic message (truncated)
    pub panic_msg: [u8; PANIC_MSG_MAX],

    /// Stack dump start address (redacted)
    pub stack_addr: u64,
    /// Stack dump length
    pub stack_len: u16,
    /// Stack dump bytes (with redacted pointers)
    pub stack: [u8; STACK_DUMP_BYTES],
}

impl CrashDump {
    /// Create an empty crash dump.
    pub const fn empty() -> Self {
        Self {
            version: KDUMP_VERSION,
            flags: 0,
            tsc: 0,
            regs: CpuRegs::zeroed(),
            panic_file_len: 0,
            panic_file: [0u8; PANIC_FILE_MAX],
            panic_line: 0,
            panic_col: 0,
            panic_msg_len: 0,
            panic_msg: [0u8; PANIC_MSG_MAX],
            stack_addr: 0,
            stack_len: 0,
            stack: [0u8; STACK_DUMP_BYTES],
        }
    }

    /// Capture crash context from panic info.
    fn capture(&mut self, info: &PanicInfo) {
        *self = Self::empty();
        self.tsc = read_tsc();

        // Read current CPU registers
        let raw_regs = read_regs();

        // Capture stack (may fail if RSP is invalid)
        let stack_len = capture_stack_bytes(&mut self.stack, raw_regs.rsp);
        self.stack_len = stack_len as u16;
        if stack_len == 0 {
            self.flags |= FLAG_STACK_SKIPPED;
        }

        // Redact kernel pointers in stack
        redact_stack_words(&mut self.stack[..stack_len]);

        // Redact registers and store
        self.regs = redact_regs(raw_regs);
        self.stack_addr = redact_if_kernel_ptr(raw_regs.rsp);
        self.flags |= FLAG_REDACTED_PTRS;

        // Capture panic location
        if let Some(location) = info.location() {
            self.panic_line = location.line();
            self.panic_col = location.column();

            let file_bytes = location.file().as_bytes();
            let to_copy = file_bytes.len().min(self.panic_file.len());
            self.panic_file[..to_copy].copy_from_slice(&file_bytes[..to_copy]);
            self.panic_file_len = to_copy as u16;
            if to_copy != file_bytes.len() {
                self.flags |= FLAG_PANIC_FILE_TRUNC;
            }
        }

        // Capture panic message
        let mut msg = FixedBuf::new(&mut self.panic_msg);
        // PanicInfo::message() returns PanicMessage which implements Display
        let _ = fmt::write(&mut msg, format_args!("{}", info.message()));
        self.panic_msg_len = msg.len as u16;
        if msg.truncated {
            self.flags |= FLAG_PANIC_MSG_TRUNC;
        }

        // R92-3 FIX: Redact kernel pointers that may have been formatted into the message.
        redact_ascii_hex_kernel_ptrs(&mut self.panic_msg[..self.panic_msg_len as usize]);
    }

    /// Serialize dump into a byte buffer.
    ///
    /// Returns the number of bytes written.
    fn serialize_into(&self, out: &mut [u8]) -> usize {
        let mut w = Writer::new(out);

        // Header
        w.bytes(&KDUMP_MAGIC);
        w.u16(self.version);
        w.u16(self.flags);
        w.u64(self.tsc);

        // Registers (19 x u64 = 152 bytes)
        w.u64(self.regs.rax);
        w.u64(self.regs.rbx);
        w.u64(self.regs.rcx);
        w.u64(self.regs.rdx);
        w.u64(self.regs.rsi);
        w.u64(self.regs.rdi);
        w.u64(self.regs.rbp);
        w.u64(self.regs.r8);
        w.u64(self.regs.r9);
        w.u64(self.regs.r10);
        w.u64(self.regs.r11);
        w.u64(self.regs.r12);
        w.u64(self.regs.r13);
        w.u64(self.regs.r14);
        w.u64(self.regs.r15);
        w.u64(self.regs.rip);
        w.u64(self.regs.rsp);
        w.u64(self.regs.rflags);
        w.u64(self.regs.cr3);

        // Panic location
        w.u16(self.panic_file_len);
        w.bytes(&self.panic_file[..self.panic_file_len as usize]);
        w.u32(self.panic_line);
        w.u32(self.panic_col);

        // Panic message
        w.u16(self.panic_msg_len);
        w.bytes(&self.panic_msg[..self.panic_msg_len as usize]);

        // Stack dump
        w.u64(self.stack_addr);
        w.u16(self.stack_len);
        w.bytes(&self.stack[..self.stack_len as usize]);

        w.pos
    }
}

// ============================================================================
// Global State (static, no heap)
// ============================================================================

/// Kdump capture state machine: 0=idle, 1=capturing, 2=captured
static KDUMP_STATE: AtomicU8 = AtomicU8::new(0);

/// Guard against double emission
static KDUMP_EMITTED: AtomicBool = AtomicBool::new(false);

/// Static storage for crash dump (no heap allocation)
static mut KDUMP_STORAGE: CrashDump = CrashDump::empty();

/// Immutable empty dump used as a safe fallback on cross-CPU contention.
/// R92-1 FIX: Return this instead of KDUMP_STORAGE on timeout to avoid data race.
static KDUMP_EMPTY: CrashDump = CrashDump::empty();

/// Static buffer for serialized dump
static mut KDUMP_BUF: [u8; KDUMP_MAX_PLAINTEXT] = [0u8; KDUMP_MAX_PLAINTEXT];

// ============================================================================
// Public API
// ============================================================================

/// Capture crash context from a panic.
///
/// This function is safe to call multiple times (from different CPUs);
/// only the first caller actually captures the dump.
///
/// # Safety
///
/// Must be called with interrupts disabled (cli).
pub fn capture_crash_context(info: &PanicInfo) -> &'static CrashDump {
    let state = KDUMP_STATE.load(Ordering::Acquire);
    if state == 2 {
        // Already captured - return existing dump
        return unsafe { &KDUMP_STORAGE };
    }

    // Try to be the capturing CPU
    if KDUMP_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // We are the capturing CPU
        unsafe {
            KDUMP_STORAGE.capture(info);
        }
        KDUMP_STATE.store(2, Ordering::Release);
        unsafe { &KDUMP_STORAGE }
    } else {
        // Another CPU is capturing - spin briefly until capture completes.
        for _ in 0..10_000 {
            if KDUMP_STATE.load(Ordering::Acquire) == 2 {
                // R92-1 FIX: Only return KDUMP_STORAGE after confirmed complete.
                return unsafe { &KDUMP_STORAGE };
            }
            core::hint::spin_loop();
        }
        // R92-1 FIX: Timed out - return immutable empty dump to avoid racing KDUMP_STORAGE.
        &KDUMP_EMPTY
    }
}

/// Emit the encrypted crash dump over serial.
///
/// Only emits once per boot. Subsequent calls are no-ops.
///
/// # Output
///
/// Writes to serial port 0x3F8 in the format:
/// ```text
/// --BEGIN ZOS-KDUMP--
/// v=1 enc=chacha20 nonce=<hex> len=<bytes>
/// <base64-encoded encrypted dump>
/// --END ZOS-KDUMP--
/// ```
///
/// # R93-8 FIX: No Plaintext Fallback
///
/// If encryption fails (RNG unavailable), the dump is NOT emitted at all.
/// This prevents sensitive crash data from being leaked in plaintext.
/// Previous behavior emitted `enc=none` which exposed kernel pointers,
/// stack contents, and register state in cleartext over serial.
///
/// # R93-15 FIX: FIPS Compliance
///
/// ChaCha20 is NOT a FIPS 140-2/140-3 approved algorithm. In FIPS mode:
/// - The dump is suppressed entirely (fail-closed security design)
/// - A warning is emitted indicating FIPS-compliant kdump is not yet supported
/// - Future implementation should add AES-256-GCM for FIPS-compliant encryption
pub fn emit_encrypted_dump(dump: &CrashDump) {
    // Only emit once
    if KDUMP_EMITTED.swap(true, Ordering::AcqRel) {
        return;
    }

    // R93-15 FIX: Suppress dump in FIPS mode (ChaCha20 is not FIPS-approved).
    // In FIPS mode, crash dumps must use FIPS-approved algorithms (AES-GCM).
    // Until an AES implementation is added, we fail closed to maintain compliance.
    if is_fips_enabled() {
        serial_write_str("\n[kdump] FIPS mode active - ChaCha20 not permitted\n");
        serial_write_str("[kdump] Crash dump suppressed for FIPS compliance\n");
        // Securely zero the dump in memory before returning
        let out = unsafe { &mut KDUMP_BUF };
        secure_bzero(out);
        return;
    }

    let out = unsafe { &mut KDUMP_BUF };
    let len = dump.serialize_into(out);
    if len == 0 {
        return;
    }

    // R92-4 FIX: Generate key and nonce in a single RNG call to minimize
    // lock contention in panic context.
    let mut seed = [0u8; 44]; // 32 bytes key + 12 bytes nonce
    let rng_ok = try_fill_random(&mut seed).is_ok();

    // R93-8 FIX: If RNG fails, do NOT emit plaintext dump.
    // Emitting unencrypted crash data leaks sensitive kernel state.
    if !rng_ok {
        secure_bzero(&mut seed);
        secure_bzero(&mut out[..len]);
        serial_write_str("\n[kdump] Encryption failed - dump suppressed for security\n");
        return;
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&seed[..32]);
    nonce.copy_from_slice(&seed[32..]);
    secure_bzero(&mut seed);

    // Encrypt in place using ChaCha20
    // R92-4 FIX: Clear key_for_cipher after creating the cipher to minimize exposure.
    let mut key_for_cipher = key;
    secure_bzero(&mut key);

    let mut cipher = ChaCha20Rng::new(key_for_cipher, nonce);
    secure_bzero(&mut key_for_cipher);
    xor_chacha20(&mut cipher, &mut out[..len]);
    // Note: ChaCha20Rng internal state remains in memory until panic completes.
    // This is acceptable in panic context where memory may already be compromised.

    // Emit header
    serial_write_str("\n--BEGIN ZOS-KDUMP--\n");
    serial_write_str("v=1 enc=chacha20 nonce=");
    serial_write_hex_bytes(&nonce);
    serial_write_str(" len=");
    serial_write_dec_u32(len as u32);
    serial_write_str("\n");

    // Emit base64-encoded dump
    emit_base64(&out[..len]);

    serial_write_str("--END ZOS-KDUMP--\n");

    // Cleanup
    secure_bzero(&mut nonce);
    secure_bzero(&mut out[..len]);
}

// ============================================================================
// Fixed-size Write Buffer (no heap)
// ============================================================================

struct FixedBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
    truncated: bool,
}

impl<'a> FixedBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0, truncated: false }
    }
}

impl fmt::Write for FixedBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.len);
        let to_copy = remaining.min(bytes.len());
        if to_copy < bytes.len() {
            self.truncated = true;
        }
        if to_copy != 0 {
            self.buf[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.len += to_copy;
        }
        Ok(())
    }
}

// ============================================================================
// Binary Serialization Writer
// ============================================================================

struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        let remaining = self.out.len().saturating_sub(self.pos);
        let to_copy = remaining.min(bytes.len());
        if to_copy != 0 {
            self.out[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
        }
    }

    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
}

// ============================================================================
// CPU State Reading (x86_64)
// ============================================================================

#[cfg(target_arch = "x86_64")]
fn read_regs() -> CpuRegs {
    let mut regs = CpuRegs::zeroed();
    unsafe {
        asm!("mov {0}, rax", out(reg) regs.rax, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rbx", out(reg) regs.rbx, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rcx", out(reg) regs.rcx, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rdx", out(reg) regs.rdx, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rsi", out(reg) regs.rsi, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rdi", out(reg) regs.rdi, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rbp", out(reg) regs.rbp, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r8", out(reg) regs.r8, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r9", out(reg) regs.r9, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r10", out(reg) regs.r10, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r11", out(reg) regs.r11, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r12", out(reg) regs.r12, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r13", out(reg) regs.r13, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r14", out(reg) regs.r14, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, r15", out(reg) regs.r15, options(nomem, nostack, preserves_flags));

        asm!("lea {0}, [rip]", out(reg) regs.rip, options(nomem, nostack, preserves_flags));
        asm!("mov {0}, rsp", out(reg) regs.rsp, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {0}", out(reg) regs.rflags);
        asm!("mov {0}, cr3", out(reg) regs.cr3, options(nomem, nostack, preserves_flags));
    }
    regs
}

#[cfg(not(target_arch = "x86_64"))]
fn read_regs() -> CpuRegs {
    CpuRegs::zeroed()
}

/// Read TSC (Time Stamp Counter) for precise timing.
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
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
    { 0 }
}

// ============================================================================
// Stack Capture
// ============================================================================

/// Capture stack bytes from the given RSP.
///
/// Returns the number of bytes captured, or 0 if RSP is invalid.
/// R92-2 FIX: Avoids crossing page boundary to reduce risk of faulting
/// near unmapped stack top/guard pages.
fn capture_stack_bytes(dst: &mut [u8], rsp: u64) -> usize {
    if rsp == 0 || !is_canonical_address(rsp) {
        return 0;
    }

    // R92-2 FIX: Best-effort page boundary check to avoid faulting if RSP
    // is near an unmapped guard page. Only read within the current page.
    const PAGE_SIZE: usize = 4096;
    let page_off = (rsp as usize) & (PAGE_SIZE - 1);
    let to_read = dst.len().min(PAGE_SIZE - page_off);

    let src = rsp as *const u8;
    for (i, b) in dst.iter_mut().take(to_read).enumerate() {
        // Use volatile read to prevent optimization
        *b = unsafe { core::ptr::read_volatile(src.add(i)) };
    }
    to_read
}

// ============================================================================
// Pointer Redaction
// ============================================================================

/// Redact all kernel pointers in registers.
fn redact_regs(mut regs: CpuRegs) -> CpuRegs {
    regs.rax = redact_if_kernel_ptr(regs.rax);
    regs.rbx = redact_if_kernel_ptr(regs.rbx);
    regs.rcx = redact_if_kernel_ptr(regs.rcx);
    regs.rdx = redact_if_kernel_ptr(regs.rdx);
    regs.rsi = redact_if_kernel_ptr(regs.rsi);
    regs.rdi = redact_if_kernel_ptr(regs.rdi);
    regs.rbp = redact_if_kernel_ptr(regs.rbp);
    regs.r8 = redact_if_kernel_ptr(regs.r8);
    regs.r9 = redact_if_kernel_ptr(regs.r9);
    regs.r10 = redact_if_kernel_ptr(regs.r10);
    regs.r11 = redact_if_kernel_ptr(regs.r11);
    regs.r12 = redact_if_kernel_ptr(regs.r12);
    regs.r13 = redact_if_kernel_ptr(regs.r13);
    regs.r14 = redact_if_kernel_ptr(regs.r14);
    regs.r15 = redact_if_kernel_ptr(regs.r15);
    regs.rip = redact_if_kernel_ptr(regs.rip);
    regs.rsp = redact_if_kernel_ptr(regs.rsp);

    // CR3 is always sensitive - always redact
    regs.cr3 = KptrGuard::from_addr(regs.cr3).obfuscated_value();
    regs
}

/// Redact kernel pointer words in stack dump.
fn redact_stack_words(stack: &mut [u8]) {
    for chunk in stack.chunks_exact_mut(8) {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(chunk);
        let word = u64::from_le_bytes(word_bytes);
        if is_kernel_address(word) {
            let redacted = KptrGuard::from_addr(word).obfuscated_value();
            chunk.copy_from_slice(&redacted.to_le_bytes());
        }
    }
}

/// Redact kernel pointers that appear as ASCII hex literals in a buffer.
///
/// R92-3 FIX: Best-effort heuristic to redact pointers that may have been
/// formatted into panic messages. Scans for `0x`/`0X` followed by 16 hex
/// digits and obfuscates values that look like kernel virtual addresses.
fn redact_ascii_hex_kernel_ptrs(buf: &mut [u8]) {
    let mut i = 0usize;
    while i + 18 <= buf.len() {
        if buf[i] == b'0' && (buf[i + 1] == b'x' || buf[i + 1] == b'X') {
            if let Some(val) = parse_hex_u64_16(&buf[i + 2..i + 18]) {
                if is_kernel_address(val) {
                    let redacted = KptrGuard::from_addr(val).obfuscated_value();
                    write_hex_u64_16(&mut buf[i + 2..i + 18], redacted);
                    i += 18;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// Parse 16 hex digits into a u64.
fn parse_hex_u64_16(hex: &[u8]) -> Option<u64> {
    if hex.len() != 16 {
        return None;
    }

    let mut v: u64 = 0;
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        v = (v << 4) | digit;
    }
    Some(v)
}

/// Write a u64 as 16 lowercase hex digits.
fn write_hex_u64_16(out: &mut [u8], v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if out.len() < 16 {
        return;
    }
    for i in 0..16 {
        let shift = 60 - (i * 4);
        out[i] = HEX[((v >> shift) & 0xF) as usize];
    }
}

#[inline]
fn is_kernel_address(addr: u64) -> bool {
    addr >= 0xFFFF_8000_0000_0000
}

#[inline]
fn is_canonical_address(addr: u64) -> bool {
    let sign = (addr >> 47) & 1;
    let top = addr >> 48;
    if sign == 0 { top == 0 } else { top == 0xFFFF }
}

#[inline]
fn redact_if_kernel_ptr(val: u64) -> u64 {
    if is_kernel_address(val) {
        KptrGuard::from_addr(val).obfuscated_value()
    } else {
        val
    }
}

// ============================================================================
// Encryption
// ============================================================================

/// XOR buffer with ChaCha20 keystream.
fn xor_chacha20(cipher: &mut ChaCha20Rng, buf: &mut [u8]) {
    let mut keystream = [0u8; 64];
    let mut offset = 0;
    while offset < buf.len() {
        let chunk = (buf.len() - offset).min(keystream.len());
        cipher.fill_bytes(&mut keystream[..chunk]);
        for i in 0..chunk {
            buf[offset + i] ^= keystream[i];
        }
        offset += chunk;
    }
    secure_bzero(&mut keystream);
}

// ============================================================================
// Base64 Output
// ============================================================================

/// Emit data as base64 over serial.
fn emit_base64(data: &[u8]) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut col = 0usize;

    let mut i = 0usize;
    while i + 3 <= data.len() {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        i += 3;

        let out0 = TABLE[(b0 >> 2) as usize];
        let out1 = TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        let out2 = TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize];
        let out3 = TABLE[(b2 & 0x3f) as usize];

        for ch in [out0, out1, out2, out3] {
            serial_write_byte(ch);
            col += 1;
            if col == BASE64_LINE {
                serial_write_byte(b'\n');
                col = 0;
            }
        }
    }

    // Handle remaining bytes
    let rem = data.len() - i;
    if rem == 1 {
        let b0 = data[i];
        let out0 = TABLE[(b0 >> 2) as usize];
        let out1 = TABLE[((b0 & 0x03) << 4) as usize];
        for ch in [out0, out1, b'=', b'='] {
            serial_write_byte(ch);
            col += 1;
            if col == BASE64_LINE {
                serial_write_byte(b'\n');
                col = 0;
            }
        }
    } else if rem == 2 {
        let b0 = data[i];
        let b1 = data[i + 1];
        let out0 = TABLE[(b0 >> 2) as usize];
        let out1 = TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        let out2 = TABLE[((b1 & 0x0f) << 2) as usize];
        for ch in [out0, out1, out2, b'='] {
            serial_write_byte(ch);
            col += 1;
            if col == BASE64_LINE {
                serial_write_byte(b'\n');
                col = 0;
            }
        }
    }

    if col != 0 {
        serial_write_byte(b'\n');
    }
}

// ============================================================================
// Serial I/O (low-level, no locks)
// ============================================================================

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
fn serial_write_byte(byte: u8) {
    unsafe { outb(SERIAL_PORT, byte); }
}

fn serial_write_str(s: &str) {
    for b in s.bytes() {
        serial_write_byte(b);
    }
}

fn serial_write_dec_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    loop {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
        if n == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        serial_write_byte(buf[i]);
    }
}

fn serial_write_hex_bytes(bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        serial_write_byte(HEX[(b >> 4) as usize]);
        serial_write_byte(HEX[(b & 0x0f) as usize]);
    }
}

// ============================================================================
// Secure Memory Clearing
// ============================================================================

/// Securely zero a buffer (prevents compiler from optimizing away).
fn secure_bzero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
