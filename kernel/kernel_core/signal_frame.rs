//! M0 item 5 (sub-slice 1a) — Linux x86-64 `rt_sigframe` builder + SROP-defended
//! sigreturn-context validator. **Pure logic**: no user-memory access, no PCB/lock
//! touch — every function operates on plain values / kernel buffers so the layout
//! math and the SROP validators are unit-testable (the self-tests at the bottom
//! drive them directly, the way `user_stack.rs` self-tests drive `compute_layout`).
//!
//! Design hierarchy: **Safety > Efficiency > Speed.**
//!
//! # Frame shape (low → high addresses, fully contiguous)
//!
//! The frame is built top-down from `(interrupted_rsp - 128)` (the 128-byte SysV red
//! zone is skipped so a leaf handler's red-zone use does not clobber the frame):
//!
//! ```text
//!   frame_base + 0    : pretcode (8)   = SA_RESTORER VA (the handler returns here)
//!   frame_base + 8    : ucontext (304) = uc_flags/uc_link/uc_stack + sigcontext + uc_sigmask
//!   frame_base + 312  : siginfo  (128) = si_signo/si_errno/si_code(SI_USER) + zero
//!   frame_base + 440  : fpstate  (512) = FXSAVE image (16-aligned)
//!   frame_base + 952  : end
//! ```
//!
//! `frame_base % 16 == 8` (handler entry RSP, as-if just after a `CALL`); the fully
//! contiguous layout makes `fpstate` a FIXED offset (`+432`) from `uc` so
//! `rt_sigreturn` re-derives it from RSP **without trusting** the user `fpstate`
//! pointer (an SROP info-leak gate).

use crate::syscall::SyscallError;
use alloc::vec::Vec;

// ── Component sizes (bytes) ──
const PRETCODE_SIZE: u64 = 8;
/// ucontext = uc_flags(8) + uc_link(8) + uc_stack(24) + sigcontext(256) + uc_sigmask(8).
const UC_SIZE: u64 = 304;
const SIGINFO_SIZE: u64 = 128;
/// FXSAVE legacy area (no XSAVE/AVX in this kernel — `fxsave64` only).
pub const FXSAVE_SIZE: usize = 512;
/// Total frame size (pretcode + ucontext + siginfo + fpstate).
const FRAME_SIZE: u64 = PRETCODE_SIZE + UC_SIZE + SIGINFO_SIZE + FXSAVE_SIZE as u64; // 952

// ── Offsets from `frame_base` ──
const OFF_PRETCODE: u64 = 0;
const OFF_UC: u64 = 8;
const OFF_UC_FLAGS: u64 = OFF_UC; // +0
const OFF_UC_STACK_FLAGS: u64 = OFF_UC + 24; // ss_flags within uc_stack (SS_DISABLE)
/// sigcontext (uc_mcontext) starts 40 bytes into the ucontext.
const OFF_MCONTEXT: u64 = OFF_UC + 40; // 48
const OFF_SIGINFO: u64 = OFF_UC + UC_SIZE; // 312
const OFF_FPSTATE: u64 = OFF_SIGINFO + SIGINFO_SIZE; // 440

// ── sigcontext greg offsets (absolute from frame_base = OFF_MCONTEXT + field) ──
// Linux x86-64 `struct sigcontext` field order.
const MC_R8: u64 = OFF_MCONTEXT;
const MC_R9: u64 = OFF_MCONTEXT + 8;
const MC_R10: u64 = OFF_MCONTEXT + 16;
const MC_R11: u64 = OFF_MCONTEXT + 24;
const MC_R12: u64 = OFF_MCONTEXT + 32;
const MC_R13: u64 = OFF_MCONTEXT + 40;
const MC_R14: u64 = OFF_MCONTEXT + 48;
const MC_R15: u64 = OFF_MCONTEXT + 56;
const MC_RDI: u64 = OFF_MCONTEXT + 64;
const MC_RSI: u64 = OFF_MCONTEXT + 72;
const MC_RBP: u64 = OFF_MCONTEXT + 80;
const MC_RBX: u64 = OFF_MCONTEXT + 88;
const MC_RDX: u64 = OFF_MCONTEXT + 96;
const MC_RAX: u64 = OFF_MCONTEXT + 104;
const MC_RCX: u64 = OFF_MCONTEXT + 112;
const MC_RSP: u64 = OFF_MCONTEXT + 120;
const MC_RIP: u64 = OFF_MCONTEXT + 128;
const MC_EFLAGS: u64 = OFF_MCONTEXT + 136;
const MC_FPSTATE_PTR: u64 = OFF_MCONTEXT + 184;
// reserved1[8] follows at +192..+256; left zero.

// ── siginfo field offsets (from frame_base) ──
const SI_SIGNO: u64 = OFF_SIGINFO; // +0
const SI_ERRNO: u64 = OFF_SIGINFO + 4;
const SI_CODE: u64 = OFF_SIGINFO + 8;
/// SI_USER — a user `kill()`/`raise()` source. The minimal slice-1 siginfo carries
/// no sender pid/uid/addr (the `PendingSignals` u64 bitmap holds none); a documented
/// M0 divergence (real `siginfo` is SLICE 4).
const SI_USER: u32 = 0;

/// The red zone skipped below the interrupted RSP (SysV AMD64 §3.2.2).
const RED_ZONE: u64 = 128;

/// RFLAGS sanitize mask: identical to the SYSRET path's `rflags_user_mask`
/// (`arch/syscall.rs`), ADDITIONALLY clearing TF (0x100) and DF (0x400). The SYSRET
/// mask keeps DF/TF; a freshly-entered SysV handler requires DF=0, and TF must never
/// be force-set into a handler. IF (0x200) is always forced on.
const RFLAGS_SANITIZE_AND: u64 = 0xFFFF_FFFF_FFE2_CFFF & !0x100 & !0x400;
const RFLAGS_IF: u64 = 0x200;

/// The architectural FXSAVE MXCSR mask fallback if `CPUID`/the live mask reports 0
/// (Intel SDM: the default usable MXCSR mask is `0x0000_FFBF`). Masking the user
/// MXCSR with the real mask is what guarantees the exit-path `fxrstor64` cannot #GP
/// on reserved MXCSR bits.
pub const MXCSR_DEFAULT_MASK: u32 = 0x0000_FFBF;
/// Byte offset of MXCSR within the 512-byte FXSAVE area.
const FXSAVE_MXCSR_OFF: usize = 24;

/// The POD snapshot of the interrupted user register state (read from the kernel-stack
/// `SyscallFrame` by the caller). `rax` is the FINAL syscall result that the
/// interrupted context must resume with (see the EINTR/short-count contract).
#[derive(Clone, Copy, Default)]
pub struct SavedUserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Interrupted user RIP (the syscall return address, `frame.rcx`).
    pub rip: u64,
    /// Interrupted user RFLAGS (`frame.r11`).
    pub rflags: u64,
}

/// Where the assembled frame must be copied, plus the redirected handler-entry
/// register values the caller writes into the live `SyscallFrame`.
#[derive(Debug, Clone, Copy)]
pub struct SigframeLayout {
    /// Handler-entry RSP (= `frame_base`, points at the pretcode; `% 16 == 8`).
    pub frame_base: u64,
    /// VA of the `ucontext` (handler arg3; also where `rt_sigreturn` finds RSP).
    pub uc_va: u64,
    /// VA of the `siginfo` (handler arg2).
    pub siginfo_va: u64,
    /// VA of the 512-byte FXSAVE image (a FIXED `uc_va + 432`).
    pub fpstate_va: u64,
    /// Total frame byte length (always `FRAME_SIZE`).
    pub len: usize,
}

/// `rt_sigreturn` re-derives the fpstate VA from the user RSP at a FIXED offset,
/// NEVER trusting the in-frame `fpstate` pointer (SROP info-leak gate). At
/// `rt_sigreturn`, RSP == `uc_va`, and the contiguous layout puts fpstate at
/// `uc_va + (OFF_FPSTATE - OFF_UC)`.
pub const SIGRETURN_FPSTATE_FROM_UC: u64 = OFF_FPSTATE - OFF_UC; // 432
/// `rt_sigreturn` reads the sigcontext at `uc_va + (OFF_MCONTEXT - OFF_UC)`.
pub const SIGRETURN_MCONTEXT_FROM_UC: u64 = OFF_MCONTEXT - OFF_UC; // 40

/// Compute the frame placement (addresses only — pure, no user-memory access).
///
/// `interrupted_rsp` is the user RSP at the syscall return; `stack_floor` is the
/// lowest mapped user-stack VA (`USER_STACK_TOP - USER_STACK_SIZE`). Returns `E2BIG`
/// (treated by the caller as a fatal SIGSEGV) if the frame would underflow the stack.
pub fn compute_sigframe_layout(
    interrupted_rsp: u64,
    stack_floor: u64,
) -> Result<SigframeLayout, SyscallError> {
    // Skip the 128-byte red zone below the interrupted RSP.
    let top = interrupted_rsp
        .checked_sub(RED_ZONE)
        .ok_or(SyscallError::EFAULT)?;
    // Place the frame so frame_base ≡ 8 (mod 16): align the candidate down to 16
    // then drop 8. fpstate (frame_base + 440) is then 16-aligned for fxrstor64.
    let candidate = top.checked_sub(FRAME_SIZE).ok_or(SyscallError::E2BIG)?;
    let frame_base = (candidate & !0xF)
        .checked_sub(8)
        .ok_or(SyscallError::E2BIG)?;
    if frame_base < stack_floor {
        return Err(SyscallError::E2BIG);
    }
    // Structural invariants (defense-in-depth; a corrupt layout must NEVER reach Ring 3).
    debug_assert_eq!(frame_base & 0xF, 8, "handler-entry RSP must be %16==8");
    debug_assert_eq!((frame_base + OFF_FPSTATE) & 0xF, 0, "fpstate must be 16-aligned");
    if frame_base & 0xF != 8 {
        return Err(SyscallError::EFAULT);
    }
    Ok(SigframeLayout {
        frame_base,
        uc_va: frame_base + OFF_UC,
        siginfo_va: frame_base + OFF_SIGINFO,
        fpstate_va: frame_base + OFF_FPSTATE,
        len: FRAME_SIZE as usize,
    })
}

#[inline]
fn put_u64(buf: &mut [u8], off: u64, val: u64) {
    let o = off as usize;
    buf[o..o + 8].copy_from_slice(&val.to_ne_bytes());
}

#[inline]
fn put_u32(buf: &mut [u8], off: u64, val: u32) {
    let o = off as usize;
    buf[o..o + 4].copy_from_slice(&val.to_ne_bytes());
}

/// Assemble the full `rt_sigframe` into a ZERO-FILLED kernel buffer (pure; the zero
/// fill is load-bearing — it provides the siginfo/ucontext padding, the FXSAVE
/// reserved-tail zeroing, and prevents any kernel-stack residue from leaking to
/// userspace). `fpstate` must be the 512-byte live FXSAVE image (already sanitized of
/// the kernel-stack residue tail by the caller via `sanitize_fxsave_for_export`).
#[allow(clippy::too_many_arguments)]
pub fn assemble_sigframe(
    layout: &SigframeLayout,
    ctx: &SavedUserContext,
    fpstate: &[u8; FXSAVE_SIZE],
    signum: u32,
    handler: u64,
    restorer: u64,
) -> Result<Vec<u8>, SyscallError> {
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(layout.len)
        .map_err(|_| SyscallError::ENOMEM)?;
    buf.resize(layout.len, 0); // zero-fill is LOAD-BEARING (padding + no residue leak).

    // pretcode = SA_RESTORER (the handler `ret`s here, which issues rt_sigreturn).
    put_u64(&mut buf, OFF_PRETCODE, restorer);

    // ucontext: uc_flags = 0, uc_link = 0, uc_stack = {0, SS_DISABLE(2), 0}.
    put_u64(&mut buf, OFF_UC_FLAGS, 0);
    put_u32(&mut buf, OFF_UC_STACK_FLAGS, 2 /* SS_DISABLE */);

    // sigcontext (uc_mcontext): the interrupted user register state.
    put_u64(&mut buf, MC_R8, ctx.r8);
    put_u64(&mut buf, MC_R9, ctx.r9);
    put_u64(&mut buf, MC_R10, ctx.r10);
    put_u64(&mut buf, MC_R11, ctx.r11);
    put_u64(&mut buf, MC_R12, ctx.r12);
    put_u64(&mut buf, MC_R13, ctx.r13);
    put_u64(&mut buf, MC_R14, ctx.r14);
    put_u64(&mut buf, MC_R15, ctx.r15);
    put_u64(&mut buf, MC_RDI, ctx.rdi);
    put_u64(&mut buf, MC_RSI, ctx.rsi);
    put_u64(&mut buf, MC_RBP, ctx.rbp);
    put_u64(&mut buf, MC_RBX, ctx.rbx);
    put_u64(&mut buf, MC_RDX, ctx.rdx);
    put_u64(&mut buf, MC_RAX, ctx.rax); // the FINAL syscall result — restored on return.
    put_u64(&mut buf, MC_RCX, ctx.rcx);
    put_u64(&mut buf, MC_RSP, ctx.rsp);
    put_u64(&mut buf, MC_RIP, ctx.rip);
    put_u64(&mut buf, MC_EFLAGS, ctx.rflags);
    // uc_mcontext.fpstate pointer is ABI shape only; rt_sigreturn re-derives the VA.
    put_u64(&mut buf, MC_FPSTATE_PTR, layout.fpstate_va);

    // siginfo: minimal (si_signo, si_errno=0, si_code=SI_USER); rest zero.
    put_u32(&mut buf, SI_SIGNO, signum);
    put_u32(&mut buf, SI_ERRNO, 0);
    put_u32(&mut buf, SI_CODE, SI_USER as u32);

    // fpstate: the 512-byte FXSAVE image.
    let o = OFF_FPSTATE as usize;
    buf[o..o + FXSAVE_SIZE].copy_from_slice(&fpstate[..]);

    // `handler` is recorded by the caller into the live frame's RIP — not stored here.
    let _ = handler;
    Ok(buf)
}

/// First byte of the NON-architectural FXSAVE tail. The legacy `fxsave64` area lays
/// out the control/status words (0..32), the x87/MMX registers (32..160) and
/// XMM0..XMM15 (160..416); everything from byte 416 onward is reserved /
/// software-available and is NOT written by every CPU, so it can carry kernel-stack
/// residue from before the `fxsave64`.
const FXSAVE_RESERVED_TAIL: usize = 416;

/// Sanitize a live kernel FXSAVE image for export to the user sigframe: zero the
/// ENTIRE non-architectural reserved tail (bytes 416..512) so no kernel-stack residue
/// leaks through the frame. The architectural fields (0..416 — control/status, x87
/// regs, XMM0..XMM15) are preserved. `fxrstor64` ignores the reserved tail, so
/// zeroing it is behavior-neutral for the handler.
pub fn sanitize_fxsave_for_export(fx: &mut [u8; FXSAVE_SIZE]) {
    for b in fx.iter_mut().skip(FXSAVE_RESERVED_TAIL) {
        *b = 0;
    }
}

/// Mask the user-supplied MXCSR in an inbound FXSAVE image so `fxrstor64` on the
/// kernel exit path cannot #GP on reserved MXCSR bits. `cpu_mask` is the live
/// `MXCSR_MASK` (falls back to `MXCSR_DEFAULT_MASK` when reported as 0).
pub fn sanitize_inbound_fxsave(fx: &mut [u8; FXSAVE_SIZE], cpu_mask: u32) {
    let mask = if cpu_mask == 0 { MXCSR_DEFAULT_MASK } else { cpu_mask };
    let mut mxcsr = u32::from_ne_bytes([
        fx[FXSAVE_MXCSR_OFF],
        fx[FXSAVE_MXCSR_OFF + 1],
        fx[FXSAVE_MXCSR_OFF + 2],
        fx[FXSAVE_MXCSR_OFF + 3],
    ]);
    mxcsr &= mask;
    let bytes = mxcsr.to_ne_bytes();
    fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4].copy_from_slice(&bytes);
}

/// SROP gate: a restored user RIP/RSP must be a canonical, low-half (Ring-3) address —
/// identical to the SYSRET-path check (`arch/syscall.rs`: bits 63..47 must all equal
/// bit 47, AND bit 47 must be 0). Used for BOTH the handler/restorer VAs at install
/// AND the restored context at `rt_sigreturn`.
#[inline]
pub fn is_canonical_user_addr(addr: u64) -> bool {
    // Sign-extend bit 47 and require equality (canonical), then require bit 47 == 0
    // (low half / user space).
    let sext = ((addr << 16) as i64 >> 16) as u64;
    sext == addr && (addr & (1u64 << 47)) == 0
}

/// Sanitize a user-provided RFLAGS for resumption: clear all privileged/dangerous
/// bits (IOPL/NT/RF/VM/VIF/VIP via the SYSRET mask, plus TF and DF) and force IF on.
#[inline]
pub fn sanitize_user_rflags(raw: u64) -> u64 {
    (raw & RFLAGS_SANITIZE_AND) | RFLAGS_IF
}

/// The sigcontext (uc_mcontext) byte length copied back at `rt_sigreturn`.
pub const MCONTEXT_SIZE: usize = 256;

// Within-mcontext field offsets (= the absolute MC_* offsets minus OFF_MCONTEXT).
const MCI_R8: usize = 0;
const MCI_R9: usize = 8;
const MCI_R10: usize = 16;
const MCI_R11: usize = 24;
const MCI_R12: usize = 32;
const MCI_R13: usize = 40;
const MCI_R14: usize = 48;
const MCI_R15: usize = 56;
const MCI_RDI: usize = 64;
const MCI_RSI: usize = 72;
const MCI_RBP: usize = 80;
const MCI_RBX: usize = 88;
const MCI_RDX: usize = 96;
const MCI_RAX: usize = 104;
const MCI_RCX: usize = 112;
const MCI_RSP: usize = 120;
const MCI_RIP: usize = 128;
const MCI_EFLAGS: usize = 136;

#[inline]
fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(a)
}

/// Parse + SROP-VALIDATE a user-supplied sigcontext (copied from the user stack at
/// `rt_sigreturn`). The restored RIP and RSP MUST be canonical, low-half (Ring-3)
/// addresses (rejecting a forged high-half/kernel target — the SROP class); RFLAGS is
/// sanitized (IF forced, IOPL/TF/DF/NT/RF/VM cleared). CS/SS in the user context are
/// IGNORED entirely (SYSRET re-loads the fixed user selectors). Returns the
/// to-be-restored register state, or `Err(())` if the context is unsafe (the caller
/// then force-terminates with SIGSEGV — never resumes a forged context).
pub fn parse_and_validate_mcontext(mc: &[u8; MCONTEXT_SIZE]) -> Result<SavedUserContext, ()> {
    let rip = rd_u64(mc, MCI_RIP);
    let rsp = rd_u64(mc, MCI_RSP);
    if !is_canonical_user_addr(rip) || !is_canonical_user_addr(rsp) {
        return Err(());
    }
    Ok(SavedUserContext {
        rax: rd_u64(mc, MCI_RAX),
        rbx: rd_u64(mc, MCI_RBX),
        rcx: rd_u64(mc, MCI_RCX),
        rdx: rd_u64(mc, MCI_RDX),
        rsi: rd_u64(mc, MCI_RSI),
        rdi: rd_u64(mc, MCI_RDI),
        rbp: rd_u64(mc, MCI_RBP),
        rsp,
        r8: rd_u64(mc, MCI_R8),
        r9: rd_u64(mc, MCI_R9),
        r10: rd_u64(mc, MCI_R10),
        r11: rd_u64(mc, MCI_R11),
        r12: rd_u64(mc, MCI_R12),
        r13: rd_u64(mc, MCI_R13),
        r14: rd_u64(mc, MCI_R14),
        r15: rd_u64(mc, MCI_R15),
        rip,
        // Sanitized here: the resumed RFLAGS can never carry IOPL/TF/DF/etc.
        rflags: sanitize_user_rflags(rd_u64(mc, MCI_EFLAGS)),
    })
}

// ====================================================================================
// In-kernel self-tests (registered in kernel/src/integration_test.rs). Pure — no user
// memory / no CR3. Cover the mis-wires a green boot cannot catch: the %16==8 alignment
// flip, the contiguous-offset contract, the FXSAVE-tail info-leak zeroing, the MXCSR
// mask, and the SROP RIP/RSP/RFLAGS sanitizers.
// ====================================================================================

fn selftest_layout_alignment() {
    // Sweep a range of interrupted RSPs (all 16-aligned and mis-aligned) and assert
    // frame_base %16 == 8 (handler entry) and fpstate 16-aligned, for every parity.
    let floor = 0x10_0000u64;
    for delta in 0..32u64 {
        let rsp = 0x40_0000u64 + delta;
        let layout = compute_sigframe_layout(rsp, floor).expect("layout");
        assert_eq!(layout.frame_base & 0xF, 8, "frame_base must be %16==8 (rsp+{delta})");
        assert_eq!(layout.fpstate_va & 0xF, 0, "fpstate must be 16-aligned (rsp+{delta})");
        // Contiguous-offset contract the rt_sigreturn re-derivation depends on.
        assert_eq!(layout.uc_va, layout.frame_base + OFF_UC);
        assert_eq!(layout.siginfo_va, layout.frame_base + OFF_SIGINFO);
        assert_eq!(layout.fpstate_va, layout.uc_va + SIGRETURN_FPSTATE_FROM_UC);
        assert_eq!(layout.frame_base + OFF_MCONTEXT, layout.uc_va + SIGRETURN_MCONTEXT_FROM_UC);
        assert_eq!(layout.len, FRAME_SIZE as usize);
    }
    // Underflow → E2BIG (never a wild write).
    assert_eq!(
        compute_sigframe_layout(floor + 16, floor).unwrap_err(),
        SyscallError::E2BIG
    );
}

fn selftest_assemble_roundtrip() {
    let floor = 0x10_0000u64;
    let layout = compute_sigframe_layout(0x40_0000, floor).expect("layout");
    let mut ctx = SavedUserContext::default();
    ctx.rip = 0x12_3456;
    ctx.rsp = 0x40_0000;
    ctx.rax = 0xFFFF_FFFF_FFFF_FFFC; // -4 (EINTR) — must round-trip into mcontext.RAX.
    ctx.rdi = 0xAABB;
    ctx.rflags = 0x202;
    let mut fx = [0u8; FXSAVE_SIZE];
    fx[FXSAVE_MXCSR_OFF] = 0x80; // a benign MXCSR low byte (architectural, preserved)
    // Plant kernel-stack residue ACROSS the whole non-architectural tail (416..512),
    // including the early reserved region 416..463 that the old 464-cutoff missed.
    fx[416] = 0xAA;
    fx[448] = 0xBB;
    fx[FXSAVE_SIZE - 1] = 0xCC;
    sanitize_fxsave_for_export(&mut fx);
    assert_eq!(fx[FXSAVE_MXCSR_OFF], 0x80, "architectural MXCSR byte must survive");
    for (i, b) in fx.iter().enumerate().skip(FXSAVE_RESERVED_TAIL) {
        assert_eq!(*b, 0, "FXSAVE reserved tail byte {i} must be zeroed (info-leak gate)");
    }
    let buf = assemble_sigframe(&layout, &ctx, &fx, 10, 0xCAFE, 0xBEEF).expect("assemble");
    assert_eq!(buf.len(), FRAME_SIZE as usize);
    // pretcode == restorer.
    assert_eq!(read_u64(&buf, OFF_PRETCODE), 0xBEEF);
    // mcontext RIP/RSP/RAX/RDI round-trip.
    assert_eq!(read_u64(&buf, MC_RIP), 0x12_3456);
    assert_eq!(read_u64(&buf, MC_RSP), 0x40_0000);
    assert_eq!(read_u64(&buf, MC_RAX), 0xFFFF_FFFF_FFFF_FFFC);
    assert_eq!(read_u64(&buf, MC_RDI), 0xAABB);
    // siginfo si_signo == signum, si_code == SI_USER.
    assert_eq!(read_u32(&buf, SI_SIGNO), 10);
    assert_eq!(read_u32(&buf, SI_CODE), SI_USER);
    // fpstate pointer (ABI shape) and the FIXED re-derivation must agree.
    assert_eq!(read_u64(&buf, MC_FPSTATE_PTR), layout.fpstate_va);
    assert_eq!(layout.uc_va + SIGRETURN_FPSTATE_FROM_UC, layout.fpstate_va);
}

fn selftest_mxcsr_and_rflags() {
    // MXCSR masking: reserved bits cleared; zero cpu mask falls back to default.
    let mut fx = [0u8; FXSAVE_SIZE];
    fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4].copy_from_slice(&0xFFFF_FFFFu32.to_ne_bytes());
    sanitize_inbound_fxsave(&mut fx, 0); // zero -> default 0xFFBF
    let m = read_u32_at(&fx, FXSAVE_MXCSR_OFF);
    assert_eq!(m, MXCSR_DEFAULT_MASK, "MXCSR must be masked to the default usable bits");
    // RFLAGS sanitize: IF forced on, TF/DF/IOPL cleared.
    let dirty = 0x3000 /*IOPL*/ | 0x100 /*TF*/ | 0x400 /*DF*/ | 0x1 /*CF*/;
    let clean = sanitize_user_rflags(dirty);
    assert_eq!(clean & 0x200, 0x200, "IF must be forced");
    assert_eq!(clean & 0x100, 0, "TF must be cleared");
    assert_eq!(clean & 0x400, 0, "DF must be cleared");
    assert_eq!(clean & 0x3000, 0, "IOPL must be cleared");
    assert_eq!(clean & 0x1, 0x1, "user CF preserved");
}

fn selftest_srop_canonical() {
    // Low-half canonical user addresses accepted.
    assert!(is_canonical_user_addr(0x40_0000));
    assert!(is_canonical_user_addr(0x0000_7FFF_FFFF_F000));
    // High-half (kernel) rejected.
    assert!(!is_canonical_user_addr(0xFFFF_FFFF_8010_0000));
    // Non-canonical rejected.
    assert!(!is_canonical_user_addr(0x0001_0000_0000_0000 | (1u64 << 47)));
    assert!(!is_canonical_user_addr(0x8000_0000_0000_0000));
    // The boundary bit-47-set value is high-half → rejected.
    assert!(!is_canonical_user_addr(1u64 << 47));
}

fn read_u64(buf: &[u8], off: u64) -> u64 {
    let o = off as usize;
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[o..o + 8]);
    u64::from_ne_bytes(b)
}
fn read_u32(buf: &[u8], off: u64) -> u32 {
    read_u32_at(buf, off as usize)
}
fn read_u32_at(buf: &[u8], o: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[o..o + 4]);
    u32::from_ne_bytes(b)
}

/// Test 5 — deliver→rt_sigreturn mcontext round-trip identity + SROP rejection. The
/// single test that proves the save/restore symmetry the FPU-corruption and SROP
/// hazards hinge on: assemble a frame, extract the sigcontext, parse+validate it, and
/// assert the restored register state matches the saved interrupted context; then a
/// forged high-half RIP must be REJECTED.
fn selftest_mcontext_roundtrip() {
    let floor = 0x10_0000u64;
    let layout = compute_sigframe_layout(0x40_0000, floor).expect("layout");
    let mut ctx = SavedUserContext::default();
    ctx.rip = 0x12_3456;
    ctx.rsp = 0x3F_F000;
    ctx.rax = 0xFFFF_FFFF_FFFF_FFFC; // -4
    ctx.rdi = 0xAABB;
    ctx.r15 = 0xDEAD_BEEF;
    ctx.rflags = 0x3 | 0x3000 /*IOPL*/ | 0x100 /*TF*/; // dirty: must be sanitized on parse.
    let fx = [0u8; FXSAVE_SIZE];
    let buf = assemble_sigframe(&layout, &ctx, &fx, 11, 0xCAFE, 0xBEEF).expect("assemble");

    // Extract the 256-byte sigcontext at the mcontext offset (uc + 40).
    let mc_off = (SIGRETURN_MCONTEXT_FROM_UC + OFF_UC) as usize; // = OFF_MCONTEXT
    let mut mc = [0u8; MCONTEXT_SIZE];
    mc.copy_from_slice(&buf[mc_off..mc_off + MCONTEXT_SIZE]);
    let restored = parse_and_validate_mcontext(&mc).expect("valid mcontext");
    assert_eq!(restored.rip, 0x12_3456, "RIP round-trip");
    assert_eq!(restored.rsp, 0x3F_F000, "RSP round-trip");
    assert_eq!(restored.rax, 0xFFFF_FFFF_FFFF_FFFC, "RAX (EINTR) round-trip");
    assert_eq!(restored.rdi, 0xAABB, "RDI round-trip");
    assert_eq!(restored.r15, 0xDEAD_BEEF, "R15 round-trip");
    // RFLAGS must be sanitized on the way back (IF forced, IOPL/TF cleared).
    assert_eq!(restored.rflags & 0x200, 0x200, "IF forced on restore");
    assert_eq!(restored.rflags & 0x100, 0, "TF cleared on restore");
    assert_eq!(restored.rflags & 0x3000, 0, "IOPL cleared on restore");

    // Forged high-half (kernel) RIP must be rejected (SROP gate).
    let mut bad = mc;
    bad[MCI_RIP..MCI_RIP + 8].copy_from_slice(&0xFFFF_FFFF_8010_0000u64.to_ne_bytes());
    assert!(parse_and_validate_mcontext(&bad).is_err(), "forged kernel RIP must be rejected");
    // Forged high-half RSP must be rejected too.
    let mut bad2 = mc;
    bad2[MCI_RSP..MCI_RSP + 8].copy_from_slice(&0xFFFF_8000_0000_0000u64.to_ne_bytes());
    assert!(parse_and_validate_mcontext(&bad2).is_err(), "forged kernel RSP must be rejected");
}

/// Run all rt_sigframe builder/validator self-tests. Any failure panics (surfaced by
/// the serial Test Summary).
pub fn run_signal_frame_self_test() {
    selftest_layout_alignment();
    selftest_assemble_roundtrip();
    selftest_mxcsr_and_rflags();
    selftest_srop_canonical();
    selftest_mcontext_roundtrip();
}
