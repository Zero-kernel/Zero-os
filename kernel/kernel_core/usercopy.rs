//! Fault-tolerant user-space memory copy
//!
//! This module provides safe copy operations between kernel and user space
//! that can recover from page faults (TOCTOU protection).
//!
//! # Design (H-26 FIX: Exception Table EFAULT Semantics)
//!
//! Uses a per-CPU state to track when a user copy is in progress.
//! If a page fault occurs during a user copy:
//! 1. User memory accesses go through small x86_64 assembly helpers
//! 2. Each faulting instruction has an exception-table entry mapping to a fixup label
//! 3. The page_fault_handler consults the exception table; on match, rewrites RIP to fixup
//! 4. The helper returns an error code, and the copy routine returns `Err(())` (EFAULT)
//!
//! This allows syscalls to return EFAULT instead of terminating the process.
//!
//! # Type-Safe API (A.1 Security Hardening)
//!
//! This module provides type-safe user pointer wrappers:
//! - `UserPtr<T>`: Single object pointer with alignment validation
//! - `UserSlice<T>`: Slice pointer with bounds and alignment validation
//!
//! These wrappers enforce:
//! - Non-null pointers
//! - User-space address range validation
//! - Type alignment requirements
//! - Overflow-safe arithmetic
//!
//! # SMAP Guard Nesting (S-5 fix)
//!
//! UserAccessGuard supports nesting via a depth counter. Only the outermost
//! guard executes STAC/CLAC, preventing premature SMAP re-enablement when
//! guards are nested (e.g., copy_user_str_array calling copy_user_cstring).
//!
//! # PID Binding (H-36 fix)
//!
//! Usercopy state is bound to the owning process PID to prevent cross-process
//! false positive fault detection in future SMP scenarios.
//!
//! # Per-CPU State (V-5 fix)
//!
//! Both usercopy state and SMAP guard depth are now per-CPU via CpuLocal<T>.
//! This ensures correct behavior in SMP environments where multiple CPUs may
//! be performing user copies concurrently.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use cpu_local::{current_cpu_id, CpuLocal};
use x86_64::registers::control::{Cr4, Cr4Flags};

// ============================================================================
// H-26 FIX: Exception-table assisted user accesses (x86_64)
// ============================================================================
//
// x86 has variable-length instructions, so on a fault we can't reliably advance RIP.
// Instead, we emit a Linux-style exception table that maps the faulting instruction
// address to a fixup address inside the same helper. The page fault handler rewrites
// RIP to the fixup, and the helper returns an error to the caller.
//
// Assembly helpers use the System V AMD64 ABI:
// - rdi = first argument (dst for get_u8, dst for put_u8)
// - rsi = second argument (src for get_u8, val for put_u8)
// - rax = return value (0 = success, 1 = fault)
//
// NOTE: Uses Intel syntax (default for Rust inline assembly on x86_64)
core::arch::global_asm!(
    r#"
    .text

    // Copy one byte from user space [rsi] to kernel space [rdi]
    // Returns 0 on success, 1 on fault
    .global __zero_os_usercopy_get_u8
    .type __zero_os_usercopy_get_u8, @function
__zero_os_usercopy_get_u8:
.Lget_u8_access:
    mov al, [rsi]           // Read byte from user space - may fault here
    mov [rdi], al           // Write to kernel buffer
    xor eax, eax            // Return 0 (success)
    ret
.Lget_u8_fixup:
    mov eax, 1              // Return 1 (fault)
    ret
    .size __zero_os_usercopy_get_u8, .-__zero_os_usercopy_get_u8

    // Exception table entry for get_u8
    .pushsection .ex_table,"a"
    .balign 16
    .quad .Lget_u8_access, .Lget_u8_fixup
    .popsection

    // Write one byte (sil) to user space [rdi]
    // Returns 0 on success, 1 on fault
    .global __zero_os_usercopy_put_u8
    .type __zero_os_usercopy_put_u8, @function
__zero_os_usercopy_put_u8:
.Lput_u8_access:
    mov [rdi], sil          // Write byte to user space - may fault here
    xor eax, eax            // Return 0 (success)
    ret
.Lput_u8_fixup:
    mov eax, 1              // Return 1 (fault)
    ret
    .size __zero_os_usercopy_put_u8, .-__zero_os_usercopy_put_u8

    // Exception table entry for put_u8
    .pushsection .ex_table,"a"
    .balign 16
    .quad .Lput_u8_access, .Lput_u8_fixup
    .popsection
"#
);

extern "C" {
    /// Copy one byte from user space to kernel buffer.
    /// Returns 0 on success, 1 on fault.
    fn __zero_os_usercopy_get_u8(dst: *mut u8, src: *const u8) -> u32;

    /// Write one byte to user space.
    /// Returns 0 on success, 1 on fault.
    fn __zero_os_usercopy_put_u8(dst: *mut u8, val: u8) -> u32;
}

/// H-26 FIX: Exception-safe byte read from user space
#[inline(always)]
unsafe fn copy_byte_from_user(dst: *mut u8, src: *const u8) -> Result<(), ()> {
    if __zero_os_usercopy_get_u8(dst, src) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// H-26 FIX: Exception-safe byte write to user space
#[inline(always)]
unsafe fn write_byte_to_user(dst: *mut u8, val: u8) -> Result<(), ()> {
    if __zero_os_usercopy_put_u8(dst, val) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// User-copy state with PID binding for SMP safety (V-5 fix)
///
/// Each CPU maintains its own copy state via CpuLocal<T>, ensuring that
/// concurrent user copies on different CPUs do not interfere with each other.
///
/// H-26 FIX: Removed the `faulted` flag. Exception table fixups now handle
/// fault recovery directly in the assembly helpers.
struct UserCopyState {
    /// True if currently executing a user copy operation
    active: AtomicBool,
    /// PID that owns the active user copy (0 = none/kernel)
    pid: AtomicUsize,
    /// Number of bytes remaining to copy (for progress tracking)
    remaining: AtomicUsize,
    /// Inclusive start address of the current user buffer
    start: AtomicUsize,
    /// Exclusive end address of the current user buffer
    end: AtomicUsize,
}

impl UserCopyState {
    /// Create a new zeroed UserCopyState
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            pid: AtomicUsize::new(0),
            remaining: AtomicUsize::new(0),
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
        }
    }
}

/// Per-CPU user copy state (V-5 fix)
///
/// Each CPU has its own UserCopyState, ensuring SMP-safe operation.
static USER_COPY_STATE: CpuLocal<UserCopyState> = CpuLocal::new(UserCopyState::new);

/// Per-CPU SMAP guard nesting depth counter (S-5 + V-5 fix)
///
/// Tracks how many UserAccessGuard instances are currently active on this CPU.
/// STAC is only executed when depth transitions 0→1.
/// CLAC is only executed when depth transitions 1→0.
///
/// Per-CPU storage ensures correct nesting behavior in SMP environments.
static SMAP_GUARD_DEPTH: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));

/// Helper to get current process PID (0 if none)
#[inline]
fn current_pid_raw() -> usize {
    crate::process::current_pid().unwrap_or(0)
}

/// RAII guard to temporarily lift SMAP for intentional user memory access
///
/// When SMAP (Supervisor Mode Access Prevention) is enabled, the kernel cannot
/// directly read/write user memory. This guard uses STAC (Set AC flag) to
/// temporarily allow kernel access to user pages, and CLAC (Clear AC flag)
/// on drop to restore protection.
///
/// # Nesting Support (S-5 fix)
///
/// This guard supports nesting: only the outermost guard executes STAC/CLAC.
/// Nested guards simply increment/decrement a depth counter without affecting
/// the AC flag. This prevents the bug where nested guard drops would clear AC
/// prematurely (e.g., when `copy_user_str_array` calls `copy_user_cstring`).
///
/// # Interrupt Safety (R25-10 fix)
///
/// The outermost guard disables interrupts before executing STAC and restores
/// them after CLAC. This prevents interrupt handlers from running with the AC
/// flag set, which could allow unintended access to user memory.
///
/// # Safety
///
/// This guard should only be used around intentional user memory accesses
/// in controlled contexts (e.g., copy_from_user, copy_to_user).
#[must_use]
pub struct UserAccessGuard {
    /// Whether SMAP was active when the guard was created
    smap_active: bool,
    /// CPU this guard was created on (per-CPU depth must be balanced on same CPU)
    cpu_id: usize,
    /// Whether interrupts were enabled when the guard was created (R25-10 fix)
    /// Only meaningful for the outermost guard (when smap_active && is_outermost)
    interrupts_were_enabled: bool,
}

impl UserAccessGuard {
    /// Create a new guard that temporarily disables SMAP if active
    ///
    /// # Nesting Behavior
    ///
    /// - First guard (depth 0→1): Disables interrupts, executes STAC to disable SMAP
    /// - Nested guards (depth >1): Only increments counter, no STAC/interrupt change
    ///
    /// # R25-10 Fix
    ///
    /// Interrupts are disabled before STAC to prevent interrupt handlers from
    /// running with AC=1 (user access allowed).
    #[inline]
    pub fn new() -> Self {
        let cpu_id = current_cpu_id();
        let smap_active = Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
        let mut interrupts_were_enabled = false;

        if smap_active {
            // Only execute STAC when this is the outermost guard (depth 0→1)
            // V-5 fix: Use per-CPU depth counter
            let prev_depth = SMAP_GUARD_DEPTH.with(|d| d.fetch_add(1, Ordering::SeqCst));
            if prev_depth == 0 {
                // R25-10 FIX: Disable interrupts before setting AC flag
                // This prevents interrupt handlers from running with user access allowed
                interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
                if interrupts_were_enabled {
                    x86_64::instructions::interrupts::disable();
                }
                // Set AC flag to allow supervisor access to user pages
                unsafe {
                    core::arch::asm!("stac", options(nostack, nomem));
                }
            }
        }

        UserAccessGuard {
            smap_active,
            cpu_id,
            interrupts_were_enabled,
        }
    }
}

impl Default for UserAccessGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UserAccessGuard {
    /// Drop the guard, restoring SMAP protection if this is the outermost guard
    ///
    /// # Nesting Behavior
    ///
    /// - Outermost guard (depth 1→0): Executes CLAC to re-enable SMAP, restores interrupts
    /// - Inner guards (depth >1): Only decrements counter, no CLAC/interrupt change
    ///
    /// # R25-10 Fix
    ///
    /// Interrupts are restored after CLAC to maintain the interrupt-disabled window
    /// around the AC=1 period.
    #[inline]
    fn drop(&mut self) {
        // Detect CPU migration which would cause per-CPU depth imbalance
        // Use assert (not debug_assert) to catch this in release builds
        assert_eq!(
            current_cpu_id(),
            self.cpu_id,
            "UserAccessGuard dropped on different CPU; per-CPU SMAP depth would be imbalanced"
        );

        if self.smap_active {
            // Only execute CLAC when this is the outermost guard (depth 1→0)
            // V-5 fix: Use per-CPU depth counter
            let prev_depth = SMAP_GUARD_DEPTH.with(|d| d.fetch_sub(1, Ordering::SeqCst));
            // Check for underflow (should never happen with correct nesting)
            assert!(prev_depth > 0, "SMAP guard depth underflow");
            if prev_depth == 1 {
                // Clear AC flag to restore SMAP protection
                unsafe {
                    core::arch::asm!("clac", options(nostack, nomem));
                }
                // R25-10 FIX: Restore interrupts after clearing AC flag
                // Only if they were enabled when we started
                if self.interrupts_were_enabled {
                    x86_64::instructions::interrupts::enable();
                }
            }
        }
    }
}

/// Check if a user copy is currently in progress for the current process
///
/// # PID Binding (H-36 fix)
///
/// Returns true only if:
/// 1. A usercopy is active, AND
/// 2. The active usercopy belongs to the current process
///
/// This prevents false positive fault detection in SMP scenarios where
/// one CPU might fault while another CPU is doing a usercopy.
///
/// # V-5 fix
///
/// Now uses per-CPU state, so each CPU only checks its own usercopy status.
#[inline]
pub fn is_in_usercopy() -> bool {
    let pid = current_pid_raw();
    USER_COPY_STATE.with(|s| s.active.load(Ordering::SeqCst) && s.pid.load(Ordering::SeqCst) == pid)
}

// H-26 FIX: Removed set_usercopy_fault() and check_and_clear_fault()
// Exception table fixups now handle fault recovery directly in assembly helpers.

/// RAII guard for user copy state with PID binding
struct UserCopyGuard {
    /// CPU this guard was created on (per-CPU state must be cleared on same CPU)
    cpu_id: usize,
}

impl UserCopyGuard {
    /// Create a new UserCopyGuard, registering the current copy operation
    ///
    /// # PID Binding
    ///
    /// Stores the current process PID to associate the copy with its owner.
    ///
    /// # V-5 fix
    ///
    /// Uses per-CPU state for SMP safety.
    ///
    /// # H-26 FIX
    ///
    /// Removed faulted flag initialization - exception table handles faults.
    #[inline]
    fn new(buffer_start: usize, len: usize) -> Self {
        let cpu_id = current_cpu_id();
        USER_COPY_STATE.with(|s| {
            s.pid.store(current_pid_raw(), Ordering::SeqCst);
            s.start.store(buffer_start, Ordering::SeqCst);
            s.end
                .store(buffer_start.saturating_add(len), Ordering::SeqCst);
            s.active.store(true, Ordering::SeqCst);
        });
        UserCopyGuard { cpu_id }
    }
}

impl Drop for UserCopyGuard {
    #[inline]
    fn drop(&mut self) {
        // Detect CPU migration which would leave stale state on old CPU
        // Use assert (not debug_assert) to catch this in release builds
        assert_eq!(
            current_cpu_id(),
            self.cpu_id,
            "UserCopyGuard dropped on different CPU; per-CPU usercopy state would be stale"
        );

        USER_COPY_STATE.with(|s| {
            s.active.store(false, Ordering::SeqCst);
            s.pid.store(0, Ordering::SeqCst);
            s.start.store(0, Ordering::SeqCst);
            s.end.store(0, Ordering::SeqCst);
        });
    }
}

/// User space address boundary (canonical lower half on x86_64)
pub const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// R65-11 FIX: Minimum user-space mapping address.
///
/// Prevents NULL pointer dereference exploitation by disallowing mappings
/// at low addresses. A kernel NULL pointer bug can be exploited if user
/// space can map page 0 with controlled content.
///
/// 64KB is the Linux default (vm.mmap_min_addr). This prevents:
/// - Direct NULL dereference exploitation
/// - Near-NULL dereference exploitation (struct member access)
/// - Integer overflow to near-zero addresses
///
/// This should be enforced in both mmap and pointer validation.
pub const MMAP_MIN_ADDR: usize = 0x10000; // 64KB

/// R65-10 FIX: Maximum bytes to copy before yielding to interrupts.
///
/// When copying large buffers with interrupts disabled (SMAP mode), we risk
/// starving timer interrupts and causing scheduler/watchdog timeouts.
/// Copy in chunks and briefly re-enable interrupts between chunks.
///
/// 4KB (page size) is a good balance:
/// - Small enough to not noticeably delay timer interrupts (~1ms @ 1GHz)
/// - Large enough to amortize the interrupt enable/disable overhead
const USERCOPY_CHUNK_SIZE: usize = 4096;

/// Check if a pointer is properly aligned for type T
#[inline]
fn is_aligned(ptr: usize, align: usize) -> bool {
    // Alignment must be power of 2; 0 or 1 means no alignment requirement
    if align <= 1 {
        return true;
    }
    debug_assert!(align.is_power_of_two(), "alignment must be power of two");
    ptr & (align - 1) == 0
}

/// Validate that an address range is in user space
///
/// # Arguments
/// * `ptr` - Starting address
/// * `len` - Length in bytes
///
/// # Returns
/// * `true` if the range [ptr, ptr+len) is entirely in valid user space
/// * `false` if null, below MMAP_MIN_ADDR, in kernel space, or would overflow
///
/// # Zero Length Handling
///
/// When `len == 0`, returns `true` if `ptr` is a valid non-null user-space
/// address. This allows validation of pointer-only operations where no
/// actual memory access will occur.
///
/// # R65-11 FIX: Minimum Address Check
///
/// Rejects pointers below MMAP_MIN_ADDR to prevent NULL dereference
/// exploitation attacks.
#[inline]
fn validate_user_range(ptr: usize, len: usize) -> bool {
    // Null pointer is always invalid
    if ptr == 0 {
        return false;
    }
    // R65-11 FIX: Reject pointers below MMAP_MIN_ADDR
    // This prevents NULL dereference exploitation
    if ptr < MMAP_MIN_ADDR {
        return false;
    }
    // Pointer must be in user space (below canonical hole)
    if ptr >= USER_SPACE_TOP {
        return false;
    }
    // Zero-length is valid if pointer itself is in user space
    // This enables pointer validation without actual access
    if len == 0 {
        return true;
    }
    // Check for overflow and ensure end is within user space
    // Note: end is exclusive, and USER_SPACE_TOP marks the start of
    // the canonical hole, so end must be strictly less than USER_SPACE_TOP
    match ptr.checked_add(len) {
        Some(end) => end < USER_SPACE_TOP, // Strict less-than (exclusive end)
        None => false,
    }
}

/// Validate that an address range is in user space with alignment check
///
/// Like `validate_user_range` but also checks alignment requirements.
#[inline]
fn validate_user_range_aligned(ptr: usize, len: usize, align: usize) -> bool {
    validate_user_range(ptr, len) && is_aligned(ptr, align)
}

/// Fault-tolerant copy from user space to kernel buffer
///
/// This function handles page faults gracefully by returning EFAULT
/// instead of panicking. It copies one byte at a time to ensure
/// we can detect faults at any point.
///
/// # R65-10 FIX: Chunked Copy
///
/// For large buffers, copy in USERCOPY_CHUNK_SIZE chunks and briefly
/// re-enable interrupts between chunks. This prevents timer starvation
/// and scheduler delays during large copies.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// Uses exception-safe assembly helpers that return error on fault instead
/// of terminating the process. The page fault handler rewrites RIP to the
/// fixup label when a fault occurs in the helper.
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
///
/// # Safety
/// The caller must ensure `dst` is a valid kernel buffer.
pub fn copy_from_user_safe(dst: &mut [u8], src: *const u8) -> Result<(), ()> {
    let len = dst.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    if !validate_user_range(src as usize, len) {
        return Err(());
    }

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(src as usize, len);
    USER_COPY_STATE.with(|s| s.remaining.store(len, Ordering::SeqCst));
    let dst_ptr = dst.as_mut_ptr();

    // R65-10 FIX: Copy in chunks to allow interrupt servicing
    let mut offset = 0usize;
    while offset < len {
        let chunk_end = (offset + USERCOPY_CHUNK_SIZE).min(len);

        // Allow supervisor access to user pages for this chunk
        let _smap_guard = UserAccessGuard::new();

        // H-26 FIX: Copy using exception-safe helpers
        for i in offset..chunk_end {
            // SAFETY: user range validated; dst is a kernel slice
            unsafe { copy_byte_from_user(dst_ptr.add(i), src.add(i)) }?;
            USER_COPY_STATE.with(|s| s.remaining.store(len - i - 1, Ordering::SeqCst));
        }

        offset = chunk_end;

        // R65-10 FIX: SMAP guard dropped here, interrupts re-enabled briefly
        // This allows pending timer/scheduler interrupts to be serviced
    }

    Ok(())
}

/// Fault-tolerant copy from kernel buffer to user space
///
/// # R65-10 FIX: Chunked Copy
///
/// For large buffers, copy in USERCOPY_CHUNK_SIZE chunks and briefly
/// re-enable interrupts between chunks. This prevents timer starvation
/// and scheduler delays during large copies.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// Uses exception-safe assembly helpers that return error on fault instead
/// of terminating the process.
///
/// # Arguments
/// * `dst` - Destination user space pointer
/// * `src` - Source kernel buffer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
pub fn copy_to_user_safe(dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    let len = src.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    if !validate_user_range(dst as usize, len) {
        return Err(());
    }

    // Set up the copy state with buffer range tracking
    let _guard = UserCopyGuard::new(dst as usize, len);
    USER_COPY_STATE.with(|s| s.remaining.store(len, Ordering::SeqCst));

    // R65-10 FIX: Copy in chunks to allow interrupt servicing
    let mut offset = 0usize;
    while offset < len {
        let chunk_end = (offset + USERCOPY_CHUNK_SIZE).min(len);

        // Allow supervisor access to user pages for this chunk
        let _smap_guard = UserAccessGuard::new();

        // H-26 FIX: Copy using exception-safe helpers
        for i in offset..chunk_end {
            unsafe { write_byte_to_user(dst.add(i), src[i]) }?;
            USER_COPY_STATE.with(|s| s.remaining.store(len - i - 1, Ordering::SeqCst));
        }

        offset = chunk_end;

        // R65-10 FIX: SMAP guard dropped here, interrupts re-enabled briefly
        // This allows pending timer/scheduler interrupts to be serviced
    }

    Ok(())
}

/// Try to handle a page fault that occurred during user copy
///
/// This should be called AFTER COW handling in the page_fault_handler.
///
/// # Arguments
/// * `fault_addr` - The address that caused the fault
///
/// # Returns
/// * `true` - Fault was in usercopy range; page_fault_handler may apply exception-table fixup
/// * `false` - Not a user copy fault, handle normally
///
/// # PID Binding (H-36 fix)
///
/// Only returns true if the faulting process owns the active usercopy.
/// This prevents incorrect fault attribution in SMP scenarios.
///
/// # V-5 fix
///
/// Uses per-CPU state, ensuring each CPU checks only its own usercopy status.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// When this returns true, the page fault handler should consult the exception table
/// using the faulting RIP. If a fixup entry is found, rewrite RIP to the fixup and
/// return so the usercopy helper can return `Err(())` to the syscall layer (EFAULT).
pub fn try_handle_usercopy_fault(fault_addr: usize) -> bool {
    // Only handle if we're in a user copy for the current process
    // is_in_usercopy() already checks PID binding (H-36 fix)
    if !is_in_usercopy() {
        return false;
    }

    // Double-check PID for defense-in-depth (SMP safety)
    let current = current_pid_raw();
    let owner = USER_COPY_STATE.with(|s| s.pid.load(Ordering::SeqCst));
    if current != owner {
        return false;
    }

    // Only handle user-space addresses
    if fault_addr >= USER_SPACE_TOP {
        return false;
    }

    // Ensure the fault belongs to the active buffer range to avoid
    // swallowing unrelated user faults
    let (start, end) =
        USER_COPY_STATE.with(|s| (s.start.load(Ordering::SeqCst), s.end.load(Ordering::SeqCst)));
    if start == 0 || fault_addr < start || fault_addr >= end {
        return false;
    }

    // H-26 FIX: No longer set a fault flag.
    // Exception table fixup in page_fault_handler will rewrite RIP.
    true
}

/// Maximum length for user-space C strings (paths, arguments)
pub const MAX_CSTRING_LEN: usize = 4096;

/// Fault-tolerant copy of a NUL-terminated string from user space
///
/// Copies bytes from user space until a NUL terminator is found or
/// MAX_CSTRING_LEN is reached. Returns the string bytes WITHOUT the NUL.
///
/// # Arguments
/// * `src` - Source user space pointer to NUL-terminated string
///
/// # Returns
/// * `Ok(Vec<u8>)` - String bytes (not including NUL terminator)
/// * `Err(())` - Page fault occurred, null pointer, or string too long
///
/// # Security (Z-3 fix)
///
/// This function uses fault-tolerant byte-by-byte copy to safely handle:
/// - Unmapped user memory (returns EFAULT instead of kernel panic)
/// - TOCTOU attacks where memory is unmapped during copy
/// - Overly long strings (bounded by MAX_CSTRING_LEN)
pub fn copy_user_cstring(src: *const u8) -> Result<alloc::vec::Vec<u8>, ()> {
    use alloc::vec::Vec;

    if src.is_null() {
        return Err(());
    }

    // Validate that starting address is in user space
    let start_addr = src as usize;
    if start_addr >= USER_SPACE_TOP {
        return Err(());
    }

    // Allow supervisor access to user pages when SMAP is enabled
    let _smap_guard = UserAccessGuard::new();

    // Set up the copy state - we don't know exact length, use max
    let _guard = UserCopyGuard::new(start_addr, MAX_CSTRING_LEN);

    let mut result = Vec::with_capacity(256); // Typical path length

    for i in 0..MAX_CSTRING_LEN {
        // Validate each byte address is still in user space
        let byte_addr = match start_addr.checked_add(i) {
            Some(addr) if addr < USER_SPACE_TOP => addr,
            _ => return Err(()),
        };

        // H-26 FIX: Read using exception-safe helper
        let mut byte = 0u8;
        unsafe { copy_byte_from_user(&mut byte as *mut u8, byte_addr as *const u8) }?;

        // NUL terminator found - done
        if byte == 0 {
            return Ok(result);
        }

        result.push(byte);
    }

    // String too long (no NUL found within MAX_CSTRING_LEN)
    Err(())
}

// ============================================================================
// Type-Safe User Pointer API (A.1 Security Hardening)
// ============================================================================

/// Error type for usercopy operations
///
/// This is a simple unit error type. Callers should convert to appropriate
/// syscall error codes (typically EFAULT) at the syscall boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsercopyError;

/// Type-safe wrapper for a single user-space object pointer
///
/// `UserPtr<T>` enforces:
/// - Non-null pointer
/// - Address within user space bounds
/// - Proper alignment for type T
/// - T must be Copy (safe to bitwise copy)
///
/// # Example
///
/// ```ignore
/// // In syscall handler:
/// let user_ptr = UserPtr::<u64>::new(arg as *mut u64)?;
/// let mut value: u64 = 0;
/// copy_from_user(&mut value, user_ptr)?;
/// ```
///
/// # Security
///
/// This type prevents common user pointer bugs:
/// - Null pointer dereference (validated at construction)
/// - Kernel pointer confusion (must be below USER_SPACE_TOP)
/// - Alignment violations (checked against align_of::<T>())
/// - Type confusion (enforced by generic parameter)
#[derive(Debug)]
pub struct UserPtr<T: Copy> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

// SAFETY: UserPtr only holds a user-space address, not actual data.
// The pointer is validated to be in user space at construction.
// Sending the address between threads is safe; actual access requires
// proper synchronization through the copy functions.
unsafe impl<T: Copy> Send for UserPtr<T> {}
unsafe impl<T: Copy> Sync for UserPtr<T> {}

impl<T: Copy> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Copy> Copy for UserPtr<T> {}

impl<T: Copy> UserPtr<T> {
    /// Create a new UserPtr from a mutable raw pointer
    ///
    /// Validates that the pointer is:
    /// - Non-null
    /// - Within user space address range
    /// - Properly aligned for type T
    /// - Has room for size_of::<T>() bytes
    ///
    /// # Errors
    ///
    /// Returns `UsercopyError` if validation fails.
    pub fn new(ptr: *mut T) -> Result<Self, UsercopyError> {
        if ptr.is_null() {
            return Err(UsercopyError);
        }

        let addr = ptr as usize;
        let size = size_of::<T>();
        let align = align_of::<T>();

        // Validate address range and alignment
        // For ZSTs (size == 0), we still validate the pointer is in user space
        if !validate_user_range_aligned(addr, size, align) {
            return Err(UsercopyError);
        }

        Ok(Self {
            ptr,
            _marker: PhantomData,
        })
    }

    /// Create a UserPtr from a const raw pointer (read-only access)
    ///
    /// This is useful when you only need to read from user space.
    /// The internal representation is mutable for API uniformity,
    /// but the source being const signals read-only intent.
    pub fn from_const(ptr: *const T) -> Result<Self, UsercopyError> {
        Self::new(ptr as *mut T)
    }

    /// Get the underlying pointer as const
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr as *const T
    }

    /// Get the underlying pointer as mutable
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Get the address as usize
    #[inline]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }

    /// Offset the pointer by a given number of elements
    ///
    /// Returns `UsercopyError` if the result would overflow or
    /// exceed user space bounds.
    pub fn offset(&self, count: isize) -> Result<Self, UsercopyError> {
        let elem_size = size_of::<T>();
        let offset_bytes = (count as isize)
            .checked_mul(elem_size as isize)
            .ok_or(UsercopyError)?;

        let new_addr = if offset_bytes >= 0 {
            self.addr().checked_add(offset_bytes as usize)
        } else {
            self.addr().checked_sub((-offset_bytes) as usize)
        }
        .ok_or(UsercopyError)?;

        Self::new(new_addr as *mut T)
    }
}

/// Type-safe wrapper for a user-space slice pointer
///
/// `UserSlice<T>` enforces:
/// - Non-null base pointer
/// - Base address within user space bounds
/// - Proper alignment for type T
/// - Total byte count doesn't overflow
/// - Entire range is within user space
///
/// # Example
///
/// ```ignore
/// // In syscall handler:
/// let user_buf = UserSlice::<u8>::new(buf as *mut u8, len)?;
/// let mut kernel_buf = vec![0u8; len];
/// let copied = copy_from_user_slice(&mut kernel_buf, user_buf)?;
/// ```
#[derive(Debug)]
pub struct UserSlice<T: Copy> {
    ptr: *mut T,
    len: usize,
    _marker: PhantomData<T>,
}

unsafe impl<T: Copy> Send for UserSlice<T> {}
unsafe impl<T: Copy> Sync for UserSlice<T> {}

impl<T: Copy> Clone for UserSlice<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Copy> Copy for UserSlice<T> {}

impl<T: Copy> UserSlice<T> {
    /// Create a new UserSlice from a raw pointer and element count
    ///
    /// Validates that:
    /// - Base pointer is non-null
    /// - Base is within user space and properly aligned
    /// - Total byte size (len * size_of::<T>()) doesn't overflow
    /// - Entire range [ptr, ptr + len*sizeof(T)) is in user space
    ///
    /// # Arguments
    /// * `ptr` - Base pointer to the slice
    /// * `len` - Number of elements (not bytes)
    ///
    /// # Errors
    ///
    /// Returns `UsercopyError` if validation fails.
    pub fn new(ptr: *mut T, len: usize) -> Result<Self, UsercopyError> {
        if ptr.is_null() {
            return Err(UsercopyError);
        }

        let addr = ptr as usize;
        let elem_size = size_of::<T>();
        let align = align_of::<T>();

        // Calculate total byte size, checking for overflow
        let byte_len = elem_size.checked_mul(len).ok_or(UsercopyError)?;

        // Validate the entire range
        if !validate_user_range_aligned(addr, byte_len, align) {
            return Err(UsercopyError);
        }

        Ok(Self {
            ptr,
            len,
            _marker: PhantomData,
        })
    }

    /// Create a UserSlice from const pointers (read-only access)
    pub fn from_const(ptr: *const T, len: usize) -> Result<Self, UsercopyError> {
        Self::new(ptr as *mut T, len)
    }

    /// Get the number of elements
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the slice is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the total byte size
    ///
    /// This is guaranteed not to overflow because the constructor validates
    /// that `len * size_of::<T>()` fits within user space bounds.
    #[inline]
    pub fn byte_len(&self) -> usize {
        // Use saturating_mul as defense-in-depth, though the constructor
        // already validated this won't overflow
        self.len.saturating_mul(size_of::<T>())
    }

    /// Get the base pointer as const
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr as *const T
    }

    /// Get the base pointer as mutable
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Get the base address as usize
    #[inline]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }
}

// ============================================================================
// Generic Copy Functions
// ============================================================================

/// Copy a single typed value from user space
///
/// # Type Safety
///
/// The `UserPtr<T>` wrapper ensures:
/// - The pointer is properly aligned for T
/// - The pointer is in user space
/// - There is room for size_of::<T>() bytes
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer (validated)
///
/// # Errors
///
/// Returns `UsercopyError` if:
/// - A page fault occurs during the copy
/// - The user memory is not mapped or readable
pub fn copy_from_user<T: Copy>(dst: &mut T, src: UserPtr<T>) -> Result<(), UsercopyError> {
    let size = size_of::<T>();
    if size == 0 {
        // ZST: nothing to copy
        return Ok(());
    }

    // SAFETY: dst is a valid kernel reference, size matches T
    let dst_bytes = unsafe { core::slice::from_raw_parts_mut(dst as *mut T as *mut u8, size) };

    copy_from_user_safe(dst_bytes, src.as_ptr() as *const u8).map_err(|_| UsercopyError)
}

/// Copy a single typed value to user space
///
/// # Type Safety
///
/// The `UserPtr<T>` wrapper ensures:
/// - The pointer is properly aligned for T
/// - The pointer is in user space
/// - There is room for size_of::<T>() bytes
///
/// # Arguments
/// * `dst` - Destination user space pointer (validated)
/// * `src` - Source kernel value
///
/// # Errors
///
/// Returns `UsercopyError` if:
/// - A page fault occurs during the copy
/// - The user memory is not mapped or writable
/// - COW page could not be resolved
pub fn copy_to_user<T: Copy>(dst: UserPtr<T>, src: &T) -> Result<(), UsercopyError> {
    let size = size_of::<T>();
    if size == 0 {
        // ZST: nothing to copy
        return Ok(());
    }

    // SAFETY: src is a valid kernel reference, size matches T
    let src_bytes = unsafe { core::slice::from_raw_parts(src as *const T as *const u8, size) };

    copy_to_user_safe(dst.as_mut_ptr() as *mut u8, src_bytes).map_err(|_| UsercopyError)
}

/// Copy bytes from user space slice to kernel buffer
///
/// Copies up to `min(dst.len(), src.len())` bytes.
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space slice (validated)
///
/// # Returns
/// * `Ok(n)` - Number of bytes successfully copied
/// * `Err(UsercopyError)` - Copy failed (page fault, unmapped, etc.)
pub fn copy_from_user_slice(dst: &mut [u8], src: UserSlice<u8>) -> Result<usize, UsercopyError> {
    if dst.is_empty() || src.is_empty() {
        return Ok(0);
    }

    let to_copy = dst.len().min(src.len());

    copy_from_user_safe(&mut dst[..to_copy], src.as_ptr() as *const u8)
        .map(|_| to_copy)
        .map_err(|_| UsercopyError)
}

/// Copy bytes from kernel buffer to user space slice
///
/// Copies up to `min(dst.len(), src.len())` bytes.
///
/// # Arguments
/// * `dst` - Destination user space slice (validated)
/// * `src` - Source kernel buffer
///
/// # Returns
/// * `Ok(n)` - Number of bytes successfully copied
/// * `Err(UsercopyError)` - Copy failed (page fault, unmapped, etc.)
pub fn copy_to_user_slice(dst: UserSlice<u8>, src: &[u8]) -> Result<usize, UsercopyError> {
    if dst.is_empty() || src.is_empty() {
        return Ok(0);
    }

    let to_copy = dst.len().min(src.len());

    copy_to_user_safe(dst.as_mut_ptr() as *mut u8, &src[..to_copy])
        .map(|_| to_copy)
        .map_err(|_| UsercopyError)
}

/// Copy a NUL-terminated string from user space into a fixed-size kernel buffer
///
/// Unlike `copy_user_cstring`, this function:
/// - Copies into a caller-provided buffer (no heap allocation)
/// - Returns the number of bytes copied (excluding NUL)
/// - Writes NUL terminator to dst if found within bounds
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer to start of string
///
/// # Returns
/// * `Ok(n)` - `n` bytes copied (excluding NUL); dst[n] == 0 if NUL was found
/// * `Err(UsercopyError)` - Page fault or other error
///
/// # Behavior
///
/// - Copies at most `min(dst.len() - 1, MAX_CSTRING_LEN)` bytes (DoS protection)
/// - If NUL is found within the limit, dst is NUL-terminated
/// - If NUL is not found, all copied bytes are in dst without NUL
///   (caller should check if result == max_copy)
///
/// # Security
///
/// This function is safe against:
/// - TOCTOU attacks (fault-tolerant byte-by-byte copy)
/// - Buffer overflow (bounded by dst.len())
/// - DoS attacks (bounded by MAX_CSTRING_LEN)
/// - Kernel pointer confusion (UserPtr validation)
pub fn strncpy_from_user(dst: &mut [u8], src: UserPtr<u8>) -> Result<usize, UsercopyError> {
    if dst.is_empty() {
        return Ok(0);
    }

    // Reserve space for NUL and cap at MAX_CSTRING_LEN to prevent DoS
    let max_copy = dst.len().saturating_sub(1).min(MAX_CSTRING_LEN);
    if max_copy == 0 {
        dst[0] = 0;
        return Ok(0);
    }

    let start_addr = src.addr();

    // Allow supervisor access to user pages when SMAP is enabled
    let _smap_guard = UserAccessGuard::new();

    // Set up copy state for fault tracking
    let _guard = UserCopyGuard::new(start_addr, max_copy);
    USER_COPY_STATE.with(|s| s.remaining.store(max_copy, Ordering::SeqCst));

    let mut copied = 0usize;
    let dst_ptr = dst.as_mut_ptr();

    for i in 0..max_copy {
        // Calculate byte address with overflow check
        let byte_addr = match start_addr.checked_add(i) {
            Some(addr) if addr < USER_SPACE_TOP => addr,
            _ => return Err(UsercopyError),
        };

        // H-26 FIX: Read using exception-safe helper
        unsafe { copy_byte_from_user(dst_ptr.add(i), byte_addr as *const u8) }
            .map_err(|_| UsercopyError)?;

        // NUL terminator found
        if dst[i] == 0 {
            return Ok(copied);
        }

        copied += 1;

        USER_COPY_STATE.with(|s| {
            s.remaining
                .store(max_copy.saturating_sub(i + 1), Ordering::SeqCst)
        });
    }

    // Reached max_copy without finding NUL
    // Do NOT write NUL - caller should check if returned == max_copy
    Ok(copied)
}
