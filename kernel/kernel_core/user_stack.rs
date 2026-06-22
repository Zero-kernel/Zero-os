//! M0 #1 — Initial user-stack + System V AMD64 auxiliary vector (auxv) builder.
//!
//! Builds the SysV AMD64 initial process stack (`argc` / `argv` / `envp` + a full
//! auxv) that a Linux/musl C runtime expects at `_start`, and copies it into the
//! already-mapped, already-charged user stack with a single `copy_to_user`.
//!
//! Shared by BOTH user-image bring-up paths so the layout/auxv math lives in ONE
//! place:
//!   - `kernel_core::syscall::sys_exec`  — the real `execve`.
//!   - `usermode_test` (kernel crate)    — the boot Ring-3 diagnostic that runs the
//!     M0 musl gate. The gate runs through usermode_test, NOT sys_exec, so this
//!     builder MUST be reachable from both.
//!
//! Design hierarchy: **Safety > Efficiency > Speed.**
//!
//! # Caller contract (preconditions — enforced by construction at both call sites)
//!
//! 1. The caller is ALREADY on the target process CR3: `copy_to_user` writes into
//!    the freshly-mapped user-stack pages of that address space.
//! 2. The caller holds NO Process lock and NO page-table / COW lock. This builder
//!    performs `copy_to_user` (faultable) and `security::fill_random` (RNG lock);
//!    a page fault while holding the Process lock would drive the page-fault handler
//!    into the PT/COW lock = reverse lock order. Both consumers call this OUTSIDE
//!    those locks by construction. (A runtime lock-depth assertion would require a
//!    `kernel_core -> sched` dependency — a reverse cycle — so the guarantee is
//!    structural + documented rather than asserted.)
//!
//! # Side effects
//!
//! Exactly one `copy_to_user` into already-mapped / already-charged stack pages,
//! plus one `security::fill_random` (16 bytes). NO cgroup charge, NO PCB write, NO
//! new page allocation — the auxv/strings live inside the 2 MiB user stack that
//! `elf_loader::load_elf` already mapped and charged.

use crate::elf_loader::{ElfLoadResult, USER_STACK_SIZE, USER_STACK_TOP};
use crate::syscall::SyscallError;
use alloc::vec::Vec;

// ── SysV AMD64 / Linux auxiliary-vector tags (a_type). Static-musl-first subset. ──
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

/// AT_PAGESZ value — matches `elf_loader`'s `PAGE_SIZE` (0x1000).
const AUXV_PAGE_SIZE: u64 = 4096;
/// AT_CLKTCK value. The kernel scheduler tick is 1 ms (`TICK_NS = 1_000_000 ns` =>
/// 1000 Hz). Do NOT regress to the "100 = Linux HZ" assumption — that is not this
/// kernel's tick rate.
const AUXV_CLK_TCK: u64 = 1000;
/// AT_RANDOM payload size in bytes — musl/glibc consume exactly 16 (stack canary +
/// pointer-guard seed).
const AT_RANDOM_LEN: usize = 16;

/// Machine word size (8 on x86-64).
const WORD: u64 = core::mem::size_of::<u64>() as u64;

/// Exclusive upper bound of canonical lower-half user virtual addresses. Used by the
/// self-test's auxv-value whitelist to catch a future entry that embeds a kernel or
/// physical address.
const USER_SPACE_TOP: u64 = 0x0000_8000_0000_0000;

/// POD credential snapshot for the identity auxv entries
/// (AT_UID / AT_EUID / AT_GID / AT_EGID / AT_SECURE).
///
/// The CALLER takes this under a scoped `proc.credentials.read()` that is dropped
/// BEFORE [`build_initial_user_stack`] is called — the builder never touches the PCB
/// or any lock.
#[derive(Clone, Copy)]
pub struct StackCreds {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    /// AT_SECURE: set when the process runs with a privilege delta
    /// (`euid != uid || egid != gid`).
    pub at_secure: bool,
}

/// Result of building the initial user stack.
pub struct UserStackLayout {
    /// Entry RSP — points at `argc`, 16-byte aligned (SysV AMD64: `RSP % 16 == 0`
    /// at `_start`, since the kernel enters user mode via `IRETQ` with no synthetic
    /// return address pushed).
    pub rsp: u64,
    /// `argc` (diagnostic only — it is delivered on the stack at `[RSP]`, NOT in a
    /// register).
    pub argc: u64,
    /// VA of the `argv[0]` pointer slot (diagnostic only).
    pub argv_base: u64,
}

/// Pure-arithmetic layout plan — computed WITHOUT touching user memory so it is
/// unit-testable (the alignment-sweep / contiguity self-tests drive it directly).
struct LayoutPlan {
    /// = entry RSP (`argc`'s address), 16-byte aligned.
    buf_base: u64,
    /// Bytes from `buf_base` up to (exclusive) `user_stack_top`.
    buf_len: usize,
    /// User VAs of each `argv` string (ascending order, parallel to `argv`).
    argv_ptrs: Vec<u64>,
    /// User VAs of each `envp` string (ascending order, parallel to `envp`).
    envp_ptrs: Vec<u64>,
    /// User VA of the 16-byte AT_RANDOM blob.
    rand_va: u64,
    /// User VA of the NUL-terminated AT_EXECFN string.
    execfn_va: u64,
    /// `(a_type, a_val)` pairs INCLUDING the trailing AT_NULL terminator.
    auxv: Vec<(u64, u64)>,
}

/// Compute the full stack layout (addresses only — no user-memory access).
///
/// Validates every bound with checked arithmetic and the true mapped-stack floor,
/// returning `E2BIG`/`EFAULT`/`ENOMEM` before any byte is written. The unconditional
/// 16-byte mask-down on `buf_base` guarantees `RSP % 16 == 0` for ALL `(argc, envc,
/// auxv_count)` parities — eliminating the alignment-parity bug class rather than
/// patching one case.
#[allow(clippy::too_many_arguments)]
fn compute_layout(
    entry: u64,
    user_stack_top: u64,
    phdr: u64,
    phent: u16,
    phnum: u16,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    creds: &StackCreds,
    execfn: &[u8],
) -> Result<LayoutPlan, SyscallError> {
    // True mapped stack floor: load_elf maps [USER_STACK_TOP - USER_STACK_SIZE,
    // USER_STACK_TOP + PAGE). Derive the floor from the architectural constant, NOT
    // from `user_stack_top` (which is pre-biased by -16) — the latter would be 16
    // bytes too low and let a string underflow into unmapped memory.
    let stack_base = USER_STACK_TOP
        .checked_sub(USER_STACK_SIZE as u64)
        .ok_or(SyscallError::EFAULT)?;

    // The writable ceiling for the string area is `user_stack_top` (= USER_STACK_TOP
    // - 16). All writes land in [buf_base, user_stack_top); the highest written byte
    // is at user_stack_top - 1.
    let mut sp = user_stack_top;

    // --- argv strings (high -> low) ---
    let mut argv_ptrs: Vec<u64> = Vec::new();
    argv_ptrs
        .try_reserve_exact(argv.len())
        .map_err(|_| SyscallError::ENOMEM)?;
    for s in argv.iter().rev() {
        sp = sp
            .checked_sub(s.len() as u64 + 1)
            .ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        argv_ptrs.push(sp);
    }
    argv_ptrs.reverse();

    // --- envp strings (high -> low) ---
    let mut envp_ptrs: Vec<u64> = Vec::new();
    envp_ptrs
        .try_reserve_exact(envp.len())
        .map_err(|_| SyscallError::ENOMEM)?;
    for s in envp.iter().rev() {
        sp = sp
            .checked_sub(s.len() as u64 + 1)
            .ok_or(SyscallError::EFAULT)?;
        if sp < stack_base {
            return Err(SyscallError::E2BIG);
        }
        envp_ptrs.push(sp);
    }
    envp_ptrs.reverse();

    // --- AT_RANDOM 16-byte blob ---
    sp = sp
        .checked_sub(AT_RANDOM_LEN as u64)
        .ok_or(SyscallError::EFAULT)?;
    if sp < stack_base {
        return Err(SyscallError::E2BIG);
    }
    let rand_va = sp;

    // --- AT_EXECFN string ---
    sp = sp
        .checked_sub(execfn.len() as u64 + 1)
        .ok_or(SyscallError::EFAULT)?;
    if sp < stack_base {
        return Err(SyscallError::E2BIG);
    }
    let execfn_va = sp;

    // 16-align the string-area floor (defensive; `user_stack_top` is already
    // 16-aligned, so this is normally a no-op).
    sp &= !0xF;

    // --- build the auxv (a_type, a_val) pairs, INCLUDING the trailing AT_NULL ---
    let mut auxv: Vec<(u64, u64)> = Vec::new();
    // Upper bound: PHDR triple (3) + 13 fixed + AT_NULL (1) = 17.
    auxv.try_reserve_exact(17)
        .map_err(|_| SyscallError::ENOMEM)?;
    // AT_PHDR/PHENT/PHNUM are conditional — omitted wholesale when phdr == 0.
    if phdr != 0 {
        auxv.push((AT_PHDR, phdr));
        auxv.push((AT_PHENT, phent as u64));
        auxv.push((AT_PHNUM, phnum as u64));
    }
    auxv.push((AT_PAGESZ, AUXV_PAGE_SIZE));
    auxv.push((AT_BASE, 0)); // static ET_EXEC has no interpreter base; MUST be 0.
    auxv.push((AT_FLAGS, 0));
    auxv.push((AT_ENTRY, entry));
    auxv.push((AT_UID, creds.uid as u64));
    auxv.push((AT_EUID, creds.euid as u64));
    auxv.push((AT_GID, creds.gid as u64));
    auxv.push((AT_EGID, creds.egid as u64));
    auxv.push((AT_HWCAP, 0)); // deferred (not fabricated); avoids leaking CPUID detail.
    auxv.push((AT_CLKTCK, AUXV_CLK_TCK));
    auxv.push((AT_SECURE, if creds.at_secure { 1 } else { 0 }));
    auxv.push((AT_RANDOM, rand_va)); // POINTER to 16 CSPRNG bytes (filled at assembly).
    auxv.push((AT_EXECFN, execfn_va));
    auxv.push((AT_NULL, 0)); // terminator pair — ALWAYS last.

    // Pointer/aux area word count:
    //   argc + argv ptrs + argv NULL + envp ptrs + envp NULL + 2 * auxv-pairs
    // (`auxv` already includes the AT_NULL pair, so `2 * auxv.len()` counts it once).
    let pointer_words = 1u64
        .checked_add(argv.len() as u64)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(envp.len() as u64))
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(2u64.checked_mul(auxv.len() as u64)?))
        .ok_or(SyscallError::EFAULT)?;
    let pointer_bytes = pointer_words
        .checked_mul(WORD)
        .ok_or(SyscallError::EFAULT)?;

    // Unconditional 16-byte mask-down => RSP % 16 == 0 for EVERY parity. The discarded
    // 0..15 low bytes become a zero-filled gap between AT_NULL and the strings.
    let buf_base = sp.checked_sub(pointer_bytes).ok_or(SyscallError::E2BIG)? & !0xF;
    if buf_base < stack_base {
        return Err(SyscallError::E2BIG);
    }
    // Defense-in-depth: a corrupted alignment must NEVER reach Ring 3.
    debug_assert_eq!(buf_base & 0xF, 0, "entry RSP must be 16-byte aligned");
    if buf_base & 0xF != 0 {
        return Err(SyscallError::EFAULT);
    }

    let buf_len = user_stack_top
        .checked_sub(buf_base)
        .ok_or(SyscallError::EFAULT)? as usize;

    Ok(LayoutPlan {
        buf_base,
        buf_len,
        argv_ptrs,
        envp_ptrs,
        rand_va,
        execfn_va,
        auxv,
    })
}

/// Write `data` into the kernel buffer at the offset of user VA `va` (= `va - base`).
fn put(buf: &mut [u8], base: u64, va: u64, data: &[u8]) -> Result<(), SyscallError> {
    let off = va.checked_sub(base).ok_or(SyscallError::EFAULT)? as usize;
    let end = off.checked_add(data.len()).ok_or(SyscallError::EFAULT)?;
    if end > buf.len() {
        return Err(SyscallError::EFAULT);
    }
    buf[off..end].copy_from_slice(data);
    Ok(())
}

/// Write a native-endian `u64` word into the kernel buffer at user VA `va`.
fn put_word(buf: &mut [u8], base: u64, va: u64, val: u64) -> Result<(), SyscallError> {
    put(buf, base, va, &val.to_ne_bytes())
}

/// Assemble the full stack image into a zero-filled kernel buffer (pure;
/// unit-testable). The buffer maps 1:1 onto `[buf_base, user_stack_top)` — the byte
/// at user VA `v` lives at `buf[v - buf_base]`. String NUL terminators and the
/// 0..15-byte alignment gap come from the zero fill (load-bearing: prevents any
/// heap-residue leak through unwritten slack).
fn assemble_buffer(
    plan: &LayoutPlan,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    execfn: &[u8],
    rand_bytes: &[u8; AT_RANDOM_LEN],
) -> Result<Vec<u8>, SyscallError> {
    let base = plan.buf_base;
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(plan.buf_len)
        .map_err(|_| SyscallError::ENOMEM)?;
    buf.resize(plan.buf_len, 0); // zero-fill is LOAD-BEARING (NUL terminators + gap).

    // --- string area: argv strings, envp strings, AT_RANDOM blob, execfn string ---
    for (s, &va) in argv.iter().zip(plan.argv_ptrs.iter()) {
        put(&mut buf, base, va, s)?; // trailing NUL already zero from the fill.
    }
    for (s, &va) in envp.iter().zip(plan.envp_ptrs.iter()) {
        put(&mut buf, base, va, s)?;
    }
    put(&mut buf, base, plan.rand_va, rand_bytes)?;
    put(&mut buf, base, plan.execfn_va, execfn)?;

    // --- control block, low -> high from buf_base ---
    let mut cursor = base;
    // argc
    put_word(&mut buf, base, cursor, argv.len() as u64)?;
    cursor += WORD;
    // argv pointers
    for &p in &plan.argv_ptrs {
        put_word(&mut buf, base, cursor, p)?;
        cursor += WORD;
    }
    // argv NULL terminator
    put_word(&mut buf, base, cursor, 0)?;
    cursor += WORD;
    // envp pointers
    for &p in &plan.envp_ptrs {
        put_word(&mut buf, base, cursor, p)?;
        cursor += WORD;
    }
    // envp NULL terminator
    put_word(&mut buf, base, cursor, 0)?;
    cursor += WORD;
    // auxv pairs (the trailing AT_NULL pair is the last element of plan.auxv)
    for &(t, v) in &plan.auxv {
        put_word(&mut buf, base, cursor, t)?;
        cursor += WORD;
        put_word(&mut buf, base, cursor, v)?;
        cursor += WORD;
    }
    // Bytes from `cursor` up to user_stack_top stay zero (alignment gap + any slack).

    Ok(buf)
}

/// Build the SysV AMD64 initial user stack and copy it into the (already-mapped,
/// already-charged) user stack. See the module docs for the caller contract.
///
/// `argv`/`envp` are the NUL-free kernel-side copies (e.g. from `copy_user_str_array`,
/// already length-capped). `execfn` is the NUL-free program path for AT_EXECFN.
pub fn build_initial_user_stack(
    load_result: &ElfLoadResult,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    creds: &StackCreds,
    execfn: &[u8],
) -> Result<UserStackLayout, SyscallError> {
    let plan = compute_layout(
        load_result.entry,
        load_result.user_stack_top,
        load_result.phdr,
        load_result.phent,
        load_result.phnum,
        argv,
        envp,
        creds,
        execfn,
    )?;

    // AT_RANDOM: 16 CSPRNG bytes. HARD-FAIL on RNG error — never a zero/weak canary
    // (a deterministic seed would defeat musl's stack-protector + pointer guard).
    let mut rand_bytes = [0u8; AT_RANDOM_LEN];
    security::fill_random(&mut rand_bytes).map_err(|_| SyscallError::EAGAIN)?;

    let buf = assemble_buffer(&plan, argv, envp, execfn, &rand_bytes)?;

    // Single bulk copy into the target AS (preserves the R106-4 narrow per-chunk
    // SMAP window; copy_to_user validates the destination range).
    crate::syscall::copy_to_user(plan.buf_base as *mut u8, &buf)?;

    Ok(UserStackLayout {
        rsp: plan.buf_base,
        argc: argv.len() as u64,
        argv_base: plan.buf_base + WORD, // argv[0] pointer slot.
    })
}

// ====================================================================================
// In-kernel self-test (registered in kernel/src/integration_test.rs). Panics on any
// failure — surfaced by `make test` / `make boot-check` via the serial Test Summary.
// These cover the mis-wires a green build/boot cannot catch: the alignment-parity
// flip, an auxv value accidentally carrying a kernel address, and a broken layout
// contract. All are pure (no mapped user memory / no CR3 needed).
// ====================================================================================

/// Synthetic `Vec<u8>` argument list of `n` short distinct strings.
fn synth_args(n: usize) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for i in 0..n {
        // Vary lengths so the sweep exercises odd/even string-byte totals.
        let mut s = Vec::new();
        for _ in 0..=i {
            s.push(b'a' + (i as u8 & 0x0F));
        }
        v.push(s);
    }
    v
}

/// Test 1 — entry-RSP alignment sweep. The decisive mis-wire (the parity flip):
/// `RSP % 16` must be 0 for EVERY `(argc, envc, phdr-present)` combination.
fn selftest_alignment_sweep() {
    let entry = crate::elf_loader::USER_BASE as u64 + 0x1000;
    let ust = USER_STACK_TOP - 16;
    let creds = StackCreds {
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        at_secure: false,
    };
    for argc in 0..=3usize {
        for envc in 0..=2usize {
            for &phdr in &[0u64, entry + 0x2000] {
                let argv = synth_args(argc);
                let envp = synth_args(envc);
                let plan =
                    compute_layout(entry, ust, phdr, 56, 10, &argv, &envp, &creds, b"/selftest")
                        .expect("compute_layout must succeed for small inputs");
                assert_eq!(
                    plan.buf_base & 0xF,
                    0,
                    "entry RSP not 16-aligned: argc={argc} envc={envc} phdr={phdr:#x}"
                );
                assert_eq!(
                    plan.argv_ptrs.len(),
                    argc,
                    "argv_ptrs count must equal argc"
                );
                // auxv must always be AT_NULL-terminated.
                assert_eq!(
                    *plan.auxv.last().expect("auxv non-empty"),
                    (AT_NULL, 0),
                    "auxv must end with AT_NULL"
                );
                // The PHDR triple is present iff phdr != 0.
                let has_phdr = plan.auxv.iter().any(|&(t, _)| t == AT_PHDR);
                assert_eq!(has_phdr, phdr != 0, "AT_PHDR presence must track phdr!=0");
            }
        }
    }
}

/// Test 2 — auxv value whitelist. Every auxv VALUE must be either a known constant or
/// a user VA strictly below `USER_SPACE_TOP` (and at/above the mapped stack floor):
/// catches a future entry that embeds a kernel VA / KASLR slide / CR3 / phys frame
/// (`copy_to_user` only validates the destination range, never the embedded values).
fn selftest_auxv_value_whitelist() {
    let entry = crate::elf_loader::USER_BASE as u64 + 0x1000;
    let ust = USER_STACK_TOP - 16;
    let stack_base = USER_STACK_TOP - USER_STACK_SIZE as u64;
    let creds = StackCreds {
        uid: 7,
        euid: 7,
        gid: 9,
        egid: 9,
        at_secure: true,
    };
    let argv = synth_args(2);
    let envp = synth_args(1);
    let plan = compute_layout(
        entry,
        ust,
        entry + 0x2000,
        56,
        10,
        &argv,
        &envp,
        &creds,
        b"/whoami",
    )
    .expect("compute_layout");
    for &(t, v) in &plan.auxv {
        let ok = match t {
            AT_PAGESZ => v == AUXV_PAGE_SIZE,
            AT_BASE | AT_FLAGS | AT_HWCAP | AT_NULL => v == 0,
            AT_CLKTCK => v == AUXV_CLK_TCK,
            AT_SECURE => v <= 1,
            AT_UID | AT_EUID | AT_GID | AT_EGID => v <= u32::MAX as u64,
            AT_PHENT | AT_PHNUM => v <= u16::MAX as u64,
            // Pointer/VA-valued tags: must be a canonical lower-half user VA inside
            // the mapped stack (AT_RANDOM/AT_EXECFN) or a validated user entry/phdr.
            AT_RANDOM | AT_EXECFN => v >= stack_base && v < ust,
            AT_ENTRY | AT_PHDR => v > 0 && v < USER_SPACE_TOP,
            _ => false, // an unexpected tag is itself a failure.
        };
        assert!(ok, "auxv value out of whitelist: tag={t} val={v:#x}");
    }
}

/// Test 3 — layout contiguity. Assemble a concrete (argc=1, envc=1, phdr-present)
/// image and verify the on-stack control block musl walks: argc at `[RSP]`, the argv
/// and envp NULL terminators in place, the auxv block AT_NULL-terminated, and
/// AT_RANDOM/AT_EXECFN values pointing into the (non-zero) string area.
fn selftest_layout_contiguity() {
    let entry = crate::elf_loader::USER_BASE as u64 + 0x1000;
    let ust = USER_STACK_TOP - 16;
    let creds = StackCreds {
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        at_secure: false,
    };
    let argv = synth_args(1); // ["a"]
    let envp = synth_args(1); // ["a"]
    let plan = compute_layout(
        entry,
        ust,
        entry + 0x2000,
        56,
        10,
        &argv,
        &envp,
        &creds,
        b"/exe",
    )
    .expect("compute_layout");
    let rand = [0xABu8; AT_RANDOM_LEN];
    let buf = assemble_buffer(&plan, &argv, &envp, b"/exe", &rand).expect("assemble");

    let read_word = |va: u64| -> u64 {
        let off = (va - plan.buf_base) as usize;
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[off..off + 8]);
        u64::from_ne_bytes(b)
    };

    // [RSP] == argc == 1.
    assert_eq!(read_word(plan.buf_base), 1, "argc must be at [RSP]");
    // argc | argv[0] | argv NULL | envp[0] | envp NULL | auxv...
    let argv0 = read_word(plan.buf_base + WORD);
    assert_eq!(
        argv0, plan.argv_ptrs[0],
        "argv[0] slot must hold argv[0] VA"
    );
    assert_eq!(
        read_word(plan.buf_base + 2 * WORD),
        0,
        "argv NULL terminator"
    );
    let envp0 = read_word(plan.buf_base + 3 * WORD);
    assert_eq!(
        envp0, plan.envp_ptrs[0],
        "envp[0] slot must hold envp[0] VA"
    );
    assert_eq!(
        read_word(plan.buf_base + 4 * WORD),
        0,
        "envp NULL terminator"
    );

    // auxv begins at buf_base + 5 words and ends with AT_NULL(0,0).
    let mut cur = plan.buf_base + 5 * WORD;
    let mut saw_random = false;
    let mut saw_execfn = false;
    let mut saw_null = false;
    for _ in 0..plan.auxv.len() {
        let t = read_word(cur);
        let v = read_word(cur + WORD);
        cur += 2 * WORD;
        if t == AT_RANDOM {
            assert_eq!(v, plan.rand_va, "AT_RANDOM must point at the blob");
            // The blob must be the non-zero CSPRNG bytes we wrote.
            let off = (v - plan.buf_base) as usize;
            assert_eq!(&buf[off..off + AT_RANDOM_LEN], &rand[..], "AT_RANDOM bytes");
            saw_random = true;
        } else if t == AT_EXECFN {
            assert_eq!(v, plan.execfn_va, "AT_EXECFN must point at the string");
            saw_execfn = true;
        } else if t == AT_NULL {
            assert_eq!(v, 0, "AT_NULL value");
            saw_null = true;
            break;
        }
    }
    assert!(
        saw_random && saw_execfn && saw_null,
        "auxv must contain RANDOM/EXECFN/NULL"
    );

    // The 0..15-byte alignment gap (between AT_NULL and the string area) must be zero.
    let gap_start = (cur - plan.buf_base) as usize;
    let gap_end = (plan.argv_ptrs[0]
        .min(plan.envp_ptrs[0])
        .min(plan.rand_va)
        .min(plan.execfn_va)
        - plan.buf_base) as usize;
    for b in &buf[gap_start..gap_end] {
        assert_eq!(*b, 0, "alignment gap / slack must be zero-filled");
    }
}

/// Run all initial-user-stack-builder self-tests. Any failure panics.
pub fn run_user_stack_builder_self_test() {
    selftest_alignment_sweep();
    selftest_auxv_value_whitelist();
    selftest_layout_contiguity();
}
