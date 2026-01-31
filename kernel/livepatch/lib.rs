//! Zero-OS G.2 Live Patching (no_std)
//!
//! This crate implements a minimal livepatch mechanism:
//! - Patch authenticity check: **ECDSA P-256 + SHA-256** (ECDSA verify is stubbed)
//! - Detour: overwrite first byte of a target function with **INT3 (0xCC)**
//! - Redirect: a **#BP** handler rewrites `RIP` to the patch handler address
//! - Lifecycle: register / enable / disable with an explicit state machine
//!
//! # Patch image format
//!
//! All integers are little-endian. Signature is a fixed 64-byte `(r||s)` blob.
//!
//! ```text
//! 0x00 4  magic              = "ZLP2"
//! 0x04 2  version            = 1
//! 0x06 2  header_len         = 72
//! 0x08 4  flags              (reserved)
//! 0x0C 4  reserved0          = 0
//! 0x10 8  target_addr        (kernel VA of function entry)
//! 0x18 8  handler_addr       (kernel VA; 0 means handler is in patch_data)
//! 0x20 4  patch_data_len     (bytes)
//! 0x24 4  reserved1          = 0
//! 0x28 32 patch_data_sha256  (SHA-256 of patch_data)
//! 0x48 64 signature          (ECDSA P-256, r||s; covers header||patch_data)
//! 0x88 .. patch_data         (optional handler code blob)
//! ```
//!
//! # SMP safety
//!
//! - The detour write is a **single-byte atomic store**.
//! - The handler lookup is lock-free (fixed patch table; atomics only).
//! - Cross-core instruction stream synchronization is delegated to `KernelOps::sync_cores()`.

#![no_std]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use spin::{Mutex, Once};
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::VirtAddr;

// ============================================================================
// Public constants / syscall numbers
// ============================================================================

pub const SYS_KPATCH_LOAD: u64 = 509;
pub const SYS_KPATCH_ENABLE: u64 = 510;
pub const SYS_KPATCH_DISABLE: u64 = 511;

// ============================================================================
// Error model (minimal errno subset)
// ============================================================================

#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    EPERM = -1,
    ENOENT = -2,
    E2BIG = -7,
    ENOMEM = -12,
    EACCES = -13,
    EFAULT = -14,
    EBUSY = -16,
    EEXIST = -17,
    EINVAL = -22,
    ENOSYS = -38,
    EALREADY = -114,
}

impl Errno {
    #[inline]
    pub const fn as_i64(self) -> i64 {
        self as i64
    }
}

// ============================================================================
// Kernel hooks
// ============================================================================

/// Kernel-provided operations required by the livepatch module.
pub trait KernelOps: Sync {
    /// Returns true if the calling task is privileged (CAP_ADMIN or equivalent).
    fn is_privileged(&self) -> bool;

    /// Copy from user memory into a kernel buffer.
    ///
    /// # Safety
    /// Implementations must validate that `user_src..user_src+len` is readable user memory.
    unsafe fn copy_from_user(&self, dst: *mut u8, user_src: usize, len: usize)
        -> Result<(), Errno>;

    /// Allocate an executable region and return its kernel VA.
    ///
    /// SECURITY: The returned mapping must be kernel-only (not user-accessible).
    /// Prefer W^X: allocate RW, copy bytes, then transition to RX via `seal_exec`.
    unsafe fn alloc_exec(&self, len: usize) -> Result<usize, Errno>;

    /// Tighten permissions on an exec region after initialization (e.g., RW->RX).
    ///
    /// Default implementation is a no-op for kernels that don't support it yet.
    unsafe fn seal_exec(&self, _addr: usize, _len: usize) -> Result<(), Errno> {
        Ok(())
    }

    /// Free an executable region previously allocated with `alloc_exec`.
    unsafe fn free_exec(&self, addr: usize, len: usize);

    /// Temporarily make kernel text writable for patching.
    ///
    /// SECURITY: Must only permit kernel text pages, and must be safe against
    /// concurrent calls (or callers must serialize externally).
    unsafe fn make_text_writable(&self, addr: usize, len: usize) -> Result<(), Errno>;

    /// Restore kernel text protections after patching.
    unsafe fn make_text_readonly(&self, addr: usize, len: usize);

    /// Ensure instruction stream synchronization across all CPUs after text modification.
    ///
    /// SECURITY: After this returns, no CPU may execute stale instruction bytes from
    /// the modified region. Implementations must use IPI + serializing instructions.
    fn sync_cores(&self);

    /// Flush/serialize instruction fetch for the given region.
    fn flush_icache(&self, addr: usize, len: usize);
}

static KERNEL_OPS: Once<&'static dyn KernelOps> = Once::new();

/// Initialize the livepatch module and install kernel hooks.
pub fn init(ops: &'static dyn KernelOps) {
    let _ = KERNEL_OPS.call_once(|| ops);
    let _ = PATCH_TABLE.call_once(init_patch_table);
}

#[inline]
fn ops() -> Result<&'static dyn KernelOps, Errno> {
    KERNEL_OPS.get().copied().ok_or(Errno::ENOSYS)
}

// ============================================================================
// Patch format constants
// ============================================================================

const PATCH_MAGIC: [u8; 4] = *b"ZLP2";
const PATCH_VERSION: u16 = 1;
const PATCH_HEADER_LEN: usize = 72;
const PATCH_SIGNATURE_LEN: usize = 64;
const INT3: u8 = 0xCC;

/// Limit patch image size copied from userspace.
pub const MAX_PATCH_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct PatchHeader {
    #[allow(dead_code)]
    flags: u32,
    target_addr: u64,
    handler_addr: u64,
    patch_data_len: u32,
    patch_data_sha256: [u8; 32],
}

#[derive(Debug)]
struct PatchImage<'a> {
    raw_header: &'a [u8],
    header: PatchHeader,
    signature: &'a [u8; 64],
    patch_data: &'a [u8],
}

impl<'a> PatchImage<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self, Errno> {
        if buf.len() < PATCH_HEADER_LEN + PATCH_SIGNATURE_LEN {
            return Err(Errno::EINVAL);
        }

        let raw_header = &buf[..PATCH_HEADER_LEN];

        // magic
        if raw_header[0..4] != PATCH_MAGIC {
            return Err(Errno::EINVAL);
        }

        let version = read_le_u16(raw_header, 0x04)?;
        if version != PATCH_VERSION {
            return Err(Errno::EINVAL);
        }

        let header_len = read_le_u16(raw_header, 0x06)? as usize;
        if header_len != PATCH_HEADER_LEN {
            return Err(Errno::EINVAL);
        }

        let flags = read_le_u32(raw_header, 0x08)?;
        let target_addr = read_le_u64(raw_header, 0x10)?;
        let handler_addr = read_le_u64(raw_header, 0x18)?;
        let patch_data_len = read_le_u32(raw_header, 0x20)?;

        let mut patch_data_sha256 = [0u8; 32];
        patch_data_sha256.copy_from_slice(&raw_header[0x28..0x48]);

        let total_len = PATCH_HEADER_LEN
            .checked_add(PATCH_SIGNATURE_LEN)
            .and_then(|v| v.checked_add(patch_data_len as usize))
            .ok_or(Errno::EINVAL)?;

        // Require exact length to avoid hidden bytes not covered by signature.
        if buf.len() != total_len {
            return Err(Errno::EINVAL);
        }

        let sig_off = PATCH_HEADER_LEN;
        let data_off = PATCH_HEADER_LEN + PATCH_SIGNATURE_LEN;

        let signature: &'a [u8; 64] = buf[sig_off..sig_off + PATCH_SIGNATURE_LEN]
            .try_into()
            .map_err(|_| Errno::EINVAL)?;

        let patch_data = &buf[data_off..data_off + patch_data_len as usize];

        let header = PatchHeader {
            flags,
            target_addr,
            handler_addr,
            patch_data_len,
            patch_data_sha256,
        };

        Ok(Self {
            raw_header,
            header,
            signature,
            patch_data,
        })
    }
}

// ============================================================================
// Patch state machine + fixed patch table
// ============================================================================

const MAX_PATCHES: usize = 64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchState {
    Empty = 0,
    Loading = 1,
    Registered = 2,
    Enabling = 3,
    Enabled = 4,
    Disabling = 5,
    Disabled = 6,
    Failed = 7,
}

impl PatchState {
    #[inline]
    fn from_u8(v: u8) -> PatchState {
        match v {
            0 => PatchState::Empty,
            1 => PatchState::Loading,
            2 => PatchState::Registered,
            3 => PatchState::Enabling,
            4 => PatchState::Enabled,
            5 => PatchState::Disabling,
            6 => PatchState::Disabled,
            _ => PatchState::Failed,
        }
    }

    #[inline]
    fn is_bp_active(self) -> bool {
        matches!(self, PatchState::Enabling | PatchState::Enabled | PatchState::Disabling)
    }
}

struct PatchSlot {
    state: AtomicU8,
    id: AtomicU64,
    target: AtomicUsize,
    handler: AtomicUsize,

    // Saved original first byte for rollback.
    orig_valid: AtomicU8,
    orig_byte: AtomicU8,

    // Optional allocated handler blob region.
    exec_addr: AtomicUsize,
    exec_len: AtomicUsize,
}

impl PatchSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PatchState::Empty as u8),
            id: AtomicU64::new(0),
            target: AtomicUsize::new(0),
            handler: AtomicUsize::new(0),
            orig_valid: AtomicU8::new(0),
            orig_byte: AtomicU8::new(0),
            exec_addr: AtomicUsize::new(0),
            exec_len: AtomicUsize::new(0),
        }
    }
}

static PATCH_TABLE: Once<&'static [PatchSlot]> = Once::new();
static NEXT_PATCH_ID: AtomicU64 = AtomicU64::new(1);

/// R94-3 FIX: Serialize patch registration to prevent duplicate-target races.
static PATCH_REG_LOCK: Mutex<()> = Mutex::new(());
/// R94-5 FIX: Serialize text patching to prevent concurrent page-permission conflicts.
static TEXT_PATCH_LOCK: Mutex<()> = Mutex::new(());

fn init_patch_table() -> &'static [PatchSlot] {
    let mut v = Vec::with_capacity(MAX_PATCHES);
    for _ in 0..MAX_PATCHES {
        v.push(PatchSlot::new());
    }
    Box::leak(v.into_boxed_slice())
}

#[inline]
fn patch_table() -> &'static [PatchSlot] {
    PATCH_TABLE.call_once(init_patch_table);
    PATCH_TABLE.get().copied().unwrap_or(&[])
}

#[inline]
fn patch_table_get() -> Option<&'static [PatchSlot]> {
    PATCH_TABLE.get().copied()
}

fn find_slot_by_id(id: u64) -> Option<&'static PatchSlot> {
    for slot in patch_table().iter() {
        let st = PatchState::from_u8(slot.state.load(Ordering::Acquire));
        if st != PatchState::Empty && slot.id.load(Ordering::Acquire) == id {
            return Some(slot);
        }
    }
    None
}

/// Query current state for a loaded patch id.
pub fn patch_state(id: u64) -> Option<PatchState> {
    find_slot_by_id(id).map(|s| PatchState::from_u8(s.state.load(Ordering::Acquire)))
}

// ============================================================================
// Signature verification (SHA-256 + stubbed ECDSA P-256)
// ============================================================================

// Placeholder: kernel should embed/derive a real trusted public key.
#[allow(dead_code)]
const TRUSTED_P256_PUBKEY_UNCOMPRESSED: [u8; 65] = [0u8; 65];

/// R94-1 FIX: Default fail-closed — no real ECDSA verifier wired in yet.
/// To use the development stub, compile with `--features insecure-ecdsa-stub`.
#[cfg(not(feature = "insecure-ecdsa-stub"))]
fn verify_patch_authenticity(_img: &PatchImage<'_>) -> Result<(), Errno> {
    // SECURITY: Fail-closed until a real ECDSA P-256 verifier is integrated.
    Err(Errno::ENOSYS)
}

/// Insecure development-only verifier. Never enable in production.
#[cfg(feature = "insecure-ecdsa-stub")]
fn verify_patch_authenticity(img: &PatchImage<'_>) -> Result<(), Errno> {
    // R94-2 FIX: Refuse to run with an unconfigured (all-zero) public key.
    if TRUSTED_P256_PUBKEY_UNCOMPRESSED.iter().all(|&b| b == 0) {
        return Err(Errno::ENOSYS);
    }

    // 1) Integrity check: header carries patch_data sha256.
    let data_hash = sha256::sha256(img.patch_data);
    if !ct_eq(&data_hash, &img.header.patch_data_sha256) {
        return Err(Errno::EACCES);
    }

    // 2) Authenticity check: signature over header||patch_data.
    let mut h = sha256::Sha256::new();
    h.update(img.raw_header);
    h.update(img.patch_data);
    let digest = h.finalize();

    #[allow(deprecated)]
    if !verify_ecdsa_p256_sha256_stub(
        &TRUSTED_P256_PUBKEY_UNCOMPRESSED,
        &digest,
        img.signature,
    ) {
        return Err(Errno::EACCES);
    }

    Ok(())
}

/// STUB verifier for ECDSA-P256(SHA-256).
///
/// SECURITY: This is NOT real ECDSA verification and is **not secure**.
/// Replace with a constant-time big-int P-256 verifier before production use.
#[cfg(feature = "insecure-ecdsa-stub")]
#[deprecated(note = "SECURITY: insecure signature stub; do not enable in production")]
fn verify_ecdsa_p256_sha256_stub(
    _pubkey_uncompressed: &[u8; 65],
    digest: &[u8; 32],
    sig_rs: &[u8; 64],
) -> bool {
    // Accept only if r == digest and s == digest (placeholder check).
    ct_eq(&sig_rs[0..32], digest) && ct_eq(&sig_rs[32..64], digest)
}

// ============================================================================
// Public API: register / enable / disable
// ============================================================================

#[derive(Debug)]
struct LoadedPatch {
    target: usize,
    handler: usize,
    exec_addr: usize,
    exec_len: usize,
}

fn load_patch_from_bytes(patch_bytes: &[u8]) -> Result<LoadedPatch, Errno> {
    // R94-8 FIX: Enforce MAX_PATCH_BYTES for all callers (not just syscall path).
    if patch_bytes.len() > MAX_PATCH_BYTES {
        return Err(Errno::E2BIG);
    }

    let img = PatchImage::parse(patch_bytes)?;
    verify_patch_authenticity(&img)?;

    // R94-4 FIX: Require kernel high-half address for target.
    if img.header.target_addr == 0 || !is_kernel_canonical_u64(img.header.target_addr) {
        return Err(Errno::EINVAL);
    }
    let target = img.header.target_addr as usize;

    let mut exec_addr = 0usize;
    let mut exec_len = 0usize;

    let handler = if img.header.handler_addr != 0 {
        // R94-4 FIX: Require kernel high-half address for handler.
        if !is_kernel_canonical_u64(img.header.handler_addr) {
            return Err(Errno::EINVAL);
        }
        img.header.handler_addr as usize
    } else {
        // Handler code is provided by patch_data.
        if img.header.patch_data_len == 0 {
            return Err(Errno::EINVAL);
        }
        let ops = ops()?;
        let len = img.patch_data.len();
        let addr = unsafe { ops.alloc_exec(len)? };
        // R94-4 FIX: Validate allocated address is in kernel space.
        if addr == 0 || !is_kernel_canonical_u64(addr as u64) {
            if addr != 0 {
                unsafe { ops.free_exec(addr, len) };
            }
            return Err(Errno::ENOMEM);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(img.patch_data.as_ptr(), addr as *mut u8, len);
            // R94-4: Seal executable region (W^X transition).
            if let Err(e) = ops.seal_exec(addr, len) {
                ops.free_exec(addr, len);
                return Err(e);
            }
        }
        ops.flush_icache(addr, len);
        exec_addr = addr;
        exec_len = len;
        addr
    };

    // R94-4 FIX: Final handler address validation.
    if handler == 0 || !is_kernel_canonical_u64(handler as u64) {
        if exec_len != 0 {
            let ops = ops()?;
            unsafe { ops.free_exec(exec_addr, exec_len) };
        }
        return Err(Errno::EINVAL);
    }

    Ok(LoadedPatch {
        target,
        handler,
        exec_addr,
        exec_len,
    })
}

fn register_loaded_patch(p: &LoadedPatch) -> Result<u64, Errno> {
    let _ = ops()?;
    let table = patch_table();

    // R94-3 FIX: Serialize registration to prevent duplicate-target races.
    let _guard = PATCH_REG_LOCK.lock();

    // Reject multiple patches to the same target (now race-free under lock).
    for slot in table.iter() {
        let st = PatchState::from_u8(slot.state.load(Ordering::Acquire));
        if st != PatchState::Empty {
            if slot.target.load(Ordering::Acquire) == p.target {
                return Err(Errno::EBUSY);
            }
        }
    }

    for slot in table.iter() {
        if slot
            .state
            .compare_exchange(
                PatchState::Empty as u8,
                PatchState::Loading as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let id = NEXT_PATCH_ID.fetch_add(1, Ordering::Relaxed);
            slot.id.store(id, Ordering::Release);
            slot.target.store(p.target, Ordering::Release);
            slot.handler.store(p.handler, Ordering::Release);
            slot.exec_addr.store(p.exec_addr, Ordering::Release);
            slot.exec_len.store(p.exec_len, Ordering::Release);
            slot.orig_valid.store(0, Ordering::Release);
            slot.orig_byte.store(0, Ordering::Release);
            slot.state.store(PatchState::Registered as u8, Ordering::Release);
            return Ok(id);
        }
    }

    Err(Errno::ENOMEM)
}

/// Register a patch image already present in kernel memory.
pub fn kpatch_register(patch_bytes: &[u8]) -> Result<u64, Errno> {
    let ops = ops()?;
    let loaded = load_patch_from_bytes(patch_bytes)?;
    match register_loaded_patch(&loaded) {
        Ok(id) => Ok(id),
        Err(e) => {
            if loaded.exec_len != 0 {
                unsafe { ops.free_exec(loaded.exec_addr, loaded.exec_len) };
            }
            Err(e)
        }
    }
}

/// Enable a previously loaded patch by id (installs INT3 at target entry).
pub fn kpatch_enable(id: u64) -> Result<(), Errno> {
    let slot = find_slot_by_id(id).ok_or(Errno::ENOENT)?;

    let prev = loop {
        let st = PatchState::from_u8(slot.state.load(Ordering::Acquire));
        match st {
            PatchState::Registered | PatchState::Disabled => {
                if slot
                    .state
                    .compare_exchange(
                        st as u8,
                        PatchState::Enabling as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break st;
                }
            }
            PatchState::Enabled => return Ok(()),
            PatchState::Enabling | PatchState::Disabling | PatchState::Loading => {
                return Err(Errno::EBUSY);
            }
            PatchState::Empty => return Err(Errno::ENOENT),
            PatchState::Failed => return Err(Errno::EINVAL),
        }
    };

    let res = unsafe { install_int3_detour(slot) };
    match res {
        Ok(()) => {
            slot.state.store(PatchState::Enabled as u8, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            slot.state.store(prev as u8, Ordering::Release);
            Err(e)
        }
    }
}

/// Disable a previously enabled patch by id (restores original first byte).
pub fn kpatch_disable(id: u64) -> Result<(), Errno> {
    let slot = find_slot_by_id(id).ok_or(Errno::ENOENT)?;

    let prev = loop {
        let st = PatchState::from_u8(slot.state.load(Ordering::Acquire));
        match st {
            PatchState::Enabled => {
                if slot
                    .state
                    .compare_exchange(
                        PatchState::Enabled as u8,
                        PatchState::Disabling as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    break st;
                }
            }
            PatchState::Disabled | PatchState::Registered => return Ok(()),
            PatchState::Enabling | PatchState::Disabling | PatchState::Loading => {
                return Err(Errno::EBUSY);
            }
            PatchState::Empty => return Err(Errno::ENOENT),
            PatchState::Failed => return Err(Errno::EINVAL),
        }
    };

    let res = unsafe { restore_original_byte(slot) };
    match res {
        Ok(()) => {
            slot.state.store(PatchState::Disabled as u8, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            slot.state.store(prev as u8, Ordering::Release);
            Err(e)
        }
    }
}

// ============================================================================
// INT3 detour plumbing
// ============================================================================

unsafe fn install_int3_detour(slot: &PatchSlot) -> Result<(), Errno> {
    let ops = ops()?;
    // R94-5 FIX: Serialize text patching to avoid concurrent page-permission conflicts.
    let _guard = TEXT_PATCH_LOCK.lock();
    let target = slot.target.load(Ordering::Acquire);
    if target == 0 {
        return Err(Errno::EINVAL);
    }

    unsafe { ops.make_text_writable(target, 1)? };

    // Read current byte at target address.
    let current = unsafe { core::ptr::read_volatile(target as *const u8) };
    if current == INT3 {
        unsafe { ops.make_text_readonly(target, 1) };
        return Err(Errno::EBUSY);
    }

    // Capture original byte once; on re-enable, verify text hasn't changed unexpectedly.
    if slot.orig_valid.load(Ordering::Acquire) == 0 {
        slot.orig_byte.store(current, Ordering::Release);
        slot.orig_valid.store(1, Ordering::Release);
    } else {
        let orig = slot.orig_byte.load(Ordering::Acquire);
        if current != orig {
            unsafe { ops.make_text_readonly(target, 1) };
            return Err(Errno::EBUSY);
        }
    }

    // Atomic single-byte write for SMP safety.
    unsafe { atomic_write_u8(target, INT3) };

    ops.flush_icache(target, 1);
    ops.sync_cores();

    unsafe { ops.make_text_readonly(target, 1) };
    Ok(())
}

unsafe fn restore_original_byte(slot: &PatchSlot) -> Result<(), Errno> {
    let ops = ops()?;
    // R94-5 FIX: Serialize text patching.
    let _guard = TEXT_PATCH_LOCK.lock();
    let target = slot.target.load(Ordering::Acquire);
    if target == 0 {
        return Err(Errno::EINVAL);
    }

    if slot.orig_valid.load(Ordering::Acquire) == 0 {
        return Err(Errno::EINVAL);
    }
    let orig = slot.orig_byte.load(Ordering::Acquire);

    unsafe { ops.make_text_writable(target, 1)? };

    // R94-5: Verify current byte is still INT3 before restoring
    // (defends against double-disable or external text modification).
    let current = unsafe { core::ptr::read_volatile(target as *const u8) };
    if current != INT3 {
        unsafe { ops.make_text_readonly(target, 1) };
        return Err(Errno::EINVAL);
    }

    unsafe { atomic_write_u8(target, orig) };

    ops.flush_icache(target, 1);
    ops.sync_cores();

    unsafe { ops.make_text_readonly(target, 1) };
    Ok(())
}

#[inline]
unsafe fn atomic_write_u8(addr: usize, value: u8) {
    let p = addr as *mut AtomicU8;
    (*p).store(value, Ordering::SeqCst);
}

// ============================================================================
// #BP handler / dispatch
// ============================================================================

/// Fast-path dispatch for breakpoint exceptions.
///
/// Returns `true` if the breakpoint was a livepatch INT3 and `RIP` was rewritten.
///
/// # Safety
/// This function modifies the stack frame's instruction pointer through raw pointer
/// manipulation. It must only be called from a breakpoint exception handler context.
pub fn breakpoint_dispatch(stack_frame: &mut InterruptStackFrame) -> bool {
    let table = match patch_table_get() {
        Some(t) => t,
        None => return false,
    };

    // For INT3, the CPU-pushed RIP points to the next instruction,
    // so the actual INT3 address is RIP-1.
    let rip = stack_frame.instruction_pointer.as_u64() as usize;
    if rip == 0 {
        return false;
    }
    let hit = rip.wrapping_sub(1);

    for slot in table.iter() {
        let st = PatchState::from_u8(slot.state.load(Ordering::Acquire));
        if !st.is_bp_active() {
            continue;
        }
        if slot.target.load(Ordering::Acquire) != hit {
            continue;
        }

        let handler = slot.handler.load(Ordering::Acquire);
        if handler == 0 {
            return false;
        }

        // Rewrite RIP to patch handler using Volatile::update().
        // The x86_64 crate's InterruptStackFrame wraps the value in Volatile
        // to prevent optimizations that could break exception handling.
        unsafe {
            stack_frame.as_mut().update(|frame| {
                frame.instruction_pointer = VirtAddr::new(handler as u64);
            });
        }
        return true;
    }
    false
}

/// A ready-to-install #BP handler for livepatch.
pub extern "x86-interrupt" fn kpatch_breakpoint_handler(mut stack_frame: InterruptStackFrame) {
    let _ = breakpoint_dispatch(&mut stack_frame);
}

// ============================================================================
// Syscall entry points (CAP_ADMIN required)
// ============================================================================

/// sys_kpatch_load (509): Load patch from userspace buffer.
pub fn sys_kpatch_load(user_ptr: usize, len: usize) -> i64 {
    match do_sys_kpatch_load(user_ptr, len) {
        Ok(id) => id as i64,
        Err(e) => e.as_i64(),
    }
}

fn do_sys_kpatch_load(user_ptr: usize, len: usize) -> Result<u64, Errno> {
    let ops = ops()?;
    let _ = patch_table();

    if !ops.is_privileged() {
        return Err(Errno::EPERM);
    }

    if user_ptr == 0 {
        return Err(Errno::EFAULT);
    }

    if len > MAX_PATCH_BYTES {
        return Err(Errno::E2BIG);
    }
    if len < PATCH_HEADER_LEN + PATCH_SIGNATURE_LEN {
        return Err(Errno::EINVAL);
    }

    // R94-7 FIX: Defense-in-depth — reject user_ptr+len overflow.
    if user_ptr.checked_add(len).is_none() {
        return Err(Errno::EFAULT);
    }

    let mut buf = vec![0u8; len];
    unsafe { ops.copy_from_user(buf.as_mut_ptr(), user_ptr, len)? };

    let loaded = load_patch_from_bytes(&buf)?;
    match register_loaded_patch(&loaded) {
        Ok(id) => Ok(id),
        Err(e) => {
            if loaded.exec_len != 0 {
                unsafe { ops.free_exec(loaded.exec_addr, loaded.exec_len) };
            }
            Err(e)
        }
    }
}

/// sys_kpatch_enable (510): Activate a loaded patch.
pub fn sys_kpatch_enable(patch_id: u64) -> i64 {
    match do_sys_kpatch_enable(patch_id) {
        Ok(()) => 0,
        Err(e) => e.as_i64(),
    }
}

fn do_sys_kpatch_enable(patch_id: u64) -> Result<(), Errno> {
    let ops = ops()?;
    let _ = patch_table();

    if !ops.is_privileged() {
        return Err(Errno::EPERM);
    }
    kpatch_enable(patch_id)
}

/// sys_kpatch_disable (511): Deactivate a patch (rollback).
pub fn sys_kpatch_disable(patch_id: u64) -> i64 {
    match do_sys_kpatch_disable(patch_id) {
        Ok(()) => 0,
        Err(e) => e.as_i64(),
    }
}

fn do_sys_kpatch_disable(patch_id: u64) -> Result<(), Errno> {
    let ops = ops()?;
    let _ = patch_table();

    if !ops.is_privileged() {
        return Err(Errno::EPERM);
    }
    kpatch_disable(patch_id)
}

// ============================================================================
// Helpers
// ============================================================================

#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> Result<u16, Errno> {
    let b: [u8; 2] = read_bytes(buf, off)?;
    Ok(u16::from_le_bytes(b))
}

#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> Result<u32, Errno> {
    let b: [u8; 4] = read_bytes(buf, off)?;
    Ok(u32::from_le_bytes(b))
}

#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> Result<u64, Errno> {
    let b: [u8; 8] = read_bytes(buf, off)?;
    Ok(u64::from_le_bytes(b))
}

#[inline]
fn read_bytes<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N], Errno> {
    let end = off.checked_add(N).ok_or(Errno::EINVAL)?;
    if end > buf.len() {
        return Err(Errno::EINVAL);
    }
    let out: [u8; N] = buf[off..end].try_into().map_err(|_| Errno::EINVAL)?;
    Ok(out)
}

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

#[inline]
fn is_canonical_u64(addr: u64) -> bool {
    let sign = (addr >> 47) & 1;
    let upper = addr >> 48;
    if sign == 0 {
        upper == 0
    } else {
        upper == 0xFFFF
    }
}

/// R94-4 FIX: Require address to be in kernel high-half (bit 63 set + canonical).
#[inline]
fn is_kernel_canonical_u64(addr: u64) -> bool {
    is_canonical_u64(addr) && ((addr >> 63) != 0)
}

// ============================================================================
// Minimal SHA-256 (no_std)
// ============================================================================

mod sha256 {
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        bit_len: u64,
    }

    impl Sha256 {
        pub const fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                ],
                buffer: [0u8; 64],
                buffer_len: 0,
                bit_len: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            if data.is_empty() {
                return;
            }

            self.bit_len = self.bit_len.wrapping_add((data.len() as u64).wrapping_mul(8));

            if self.buffer_len != 0 {
                let need = 64 - self.buffer_len;
                let take = core::cmp::min(need, data.len());
                self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
                self.buffer_len += take;
                data = &data[take..];

                if self.buffer_len == 64 {
                    let block = self.buffer;
                    self.compress(&block);
                    self.buffer_len = 0;
                }
            }

            while data.len() >= 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[..64]);
                self.compress(&block);
                data = &data[64..];
            }

            if !data.is_empty() {
                self.buffer[..data.len()].copy_from_slice(data);
                self.buffer_len = data.len();
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let mut block = [0u8; 64];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 0x80;

            if self.buffer_len >= 56 {
                self.compress(&block);
                block = [0u8; 64];
            }

            let bit_len_be = self.bit_len.to_be_bytes();
            block[56..64].copy_from_slice(&bit_len_be);
            self.compress(&block);

            let mut out = [0u8; 32];
            for (i, word) in self.state.iter().copied().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }

        fn compress(&mut self, block: &[u8; 64]) {
            const K: [u32; 64] = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            ];

            let mut w = [0u32; 64];
            for i in 0..16 {
                let j = i * 4;
                w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7)
                    ^ w[i - 15].rotate_right(18)
                    ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17)
                    ^ w[i - 2].rotate_right(19)
                    ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    }
}
