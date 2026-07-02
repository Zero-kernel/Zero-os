//! ELF 装载器
//!
//! 负责解析并加载 ELF64 可执行文件到用户地址空间
//!
//! 功能：
//! - 验证 ELF64 格式（x86_64, Executable）
//! - 按 PT_LOAD 段映射用户地址空间
//! - 处理 BSS（memsz > filesz 部分清零）
//! - 返回入口点和用户栈顶

use alloc::vec::Vec;
use core::{cmp, ptr};
use mm::memory::FrameAllocator;
use mm::{page_table, phys_to_virt};
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};
use xmas_elf::{
    header::{Class, Machine, Type as ElfType},
    program::Type as PhType,
    ElfFile,
};

// R93-6 FIX: Import cgroup module for memory accounting
use crate::cgroup;

/// 用户地址空间起始（4MB）
///
/// 用户程序加载在 4MB 处，这是经典的 Linux 用户空间起始地址。
/// 注意：bootloader 建立的恒等映射使用 2MB 大页，在映射用户空间前
/// 需要将冲突的大页拆分为 4KB 页（通过 ensure_pte_level）。
pub const USER_BASE: usize = 0x0040_0000;

/// 用户栈顶地址：用户栈区间的固定（非随机化）独占上界。M0 无栈 ASLR，该 VA 是
/// 确定的——正因可被预测，才需要低端守护页。真正的 4 KiB 守护页由
/// `allocate_user_stack_tracked` 在窗口低端 [stack_base, stack_base+USER_STACK_GUARD_SIZE)
/// 划出，永不映射。
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// 用户栈保留窗口大小（默认 2MB，含低端 1 页守护）
pub const USER_STACK_SIZE: usize = 0x20_0000;

/// M0-7 SLICE 5: Eager-mapped top region size (16 KB = 4 pages).
///
/// The top of the user stack is eagerly mapped to back initial stack usage
/// (argc/argv/envp/auxv in build_initial_user_stack, signal frames in
/// maybe_deliver_signal, IRQ signal delivery). The rest of the stack window
/// grows on-demand via #PF.
///
/// Rationale for 16KB:
/// - Enough for typical initial stack usage (few KB)
/// - Small enough to make lazy region useful
/// - Page-aligned for clean geometry
pub const USER_STACK_EAGER_SIZE: usize = 16 * 1024; // 16 KB = 4 pages

/// M0-7: 用户栈低端永久未映射的守护页大小（1×4 KiB）。
///
/// 栈向下溢出落入该页 → not-present 的用户态写缺页 → 经 `interrupts.rs` 既有的
/// 用户 SIGSEGV 路径终止进程，而非静默破坏其下的 brk/堆。守护页必须是「完全
/// 未使用」的 PTE（加载循环从不访问它，addr=0），绝不能是显式的 non-present
/// PTE——否则 `free_address_space` 的 R123-1 叶子回收会对幻象帧二次释放。
pub const USER_STACK_GUARD_SIZE: usize = 0x1000;

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// R151-2 FIX: Maximum pages per single ELF PT_LOAD segment.
///
/// Caps attacker-controlled `p_memsz` to bound kernel heap usage when tracking
/// mapped pages. 256 pages × 4 KiB = 1 MiB maximum per segment. Each
/// MappedEntry is 16 bytes, so 256 entries = 4 KiB — well within heap budget.
const MAX_ELF_SEGMENT_PAGES: usize = 256;

/// Z-10 fix: 页映射记录类型，用于失败时统一回滚
type MappedEntry = (Page<Size4KiB>, PhysFrame<Size4KiB>);

/// ELF 加载错误
#[derive(Debug, Clone, Copy)]
pub enum ElfLoadError {
    /// ELF 魔数无效
    InvalidMagic,
    /// 不支持的 ELF 类型（非 64 位）
    UnsupportedClass,
    /// 不支持的机器架构（非 x86_64）
    UnsupportedMachine,
    /// 不支持的文件类型（非可执行文件）
    UnsupportedType,
    /// 非小端格式
    NotLittleEndian,
    /// 段地址超出允许范围
    SegmentOutOfRange,
    /// 同时可写可执行的段被拒绝（W^X 安全策略）
    WritableExecutableSegment,
    /// 段与栈区域重叠
    OverlapWithStack,
    /// 页映射失败
    MapFailed,
    /// 段数据越界
    OutOfBounds,
    /// 物理内存不足
    OutOfMemory,
    /// R93-6 FIX: Cgroup memory limit exceeded
    CgroupLimitExceeded,
    /// R154-5 FIX: Too many PT_LOAD segments (DoS prevention)
    TooManySegments,
    /// R154-12 FIX: PT_LOAD segments have overlapping virtual address ranges
    OverlappingSegments,
    /// R155-16 FIX: Segment vaddr+memsz arithmetic overflow
    InvalidSegment,
}

/// ELF 加载结果
pub struct ElfLoadResult {
    /// 程序入口点地址
    pub entry: u64,
    /// 用户栈顶地址
    pub user_stack_top: u64,
    /// 堆起始地址（BSS 末尾，页对齐）
    ///
    /// 这是 brk(0) 的初始返回值，也是 brk_start 的初始值。
    /// 计算为所有 PT_LOAD 段中 (vaddr + memsz) 的最大值，向上对齐到页边界。
    pub brk_start: usize,
    /// R125-1 FIX: Total bytes charged to the process's cgroup during ELF
    /// loading (segments + stack, page-aligned).  The caller uses this to
    /// roll back cgroup accounting if exec fails after load_elf() succeeds.
    pub charged_bytes: u64,
    /// M2-1 SLICE-4d: the intermediate PT/PD/PDPT frame identities the ELF loader built
    /// for this fresh address space (segments + stack), recorded by
    /// `RecordingFrameAllocator`. sys_exec folds these into the new AS's
    /// `pt_charged_frames` ledger + a forced cgroup PT-kmem charge AT THE SUCCESS COMMIT
    /// (after the old image's ledger is cleared). On any pre-commit failure the whole new
    /// AS is torn down by free_address_space and this Vec is simply dropped (the frames
    /// were never charged). The OTHER load_elf consumer (kernel/src/usermode_test.rs, a
    /// root-cgroup boot diagnostic) ignores this field — it field-accesses entry/stack.
    pub pt_frames: Vec<PhysFrame<Size4KiB>>,
    /// M0 #1 (auxv): user-space virtual address of the `Elf64_Phdr` array (AT_PHDR).
    ///
    /// `0` is a sentinel meaning "no usable program-header table" — the auxv builder
    /// then OMITS the entire AT_PHDR/AT_PHENT/AT_PHNUM triple (musl static tolerates
    /// its absence; only TLS-via-phdr is skipped). Computed by [`compute_phdr_va`].
    pub phdr: u64,
    /// M0 #1 (auxv): `e_phentsize` (AT_PHENT) — size of one program-header entry
    /// (56 for ELF64). Read directly from the ELF header.
    pub phent: u16,
    /// M0 #1 (auxv): `e_phnum` (AT_PHNUM) — number of program-header entries.
    pub phnum: u16,
}

/// 为当前进程地址空间加载 ELF 映像
///
/// # 前置条件
///
/// - 调用方已切换到目标进程的地址空间（当前 CR3 是目标进程的页表）
/// - 用户空间未被映射（除内核高半区外）
///
/// # Arguments
///
/// * `image` - ELF 文件的原始字节
/// * `cgroup_id` - R149-3 FIX: Cgroup ID for memory accounting, captured by
///   the caller under process lock to avoid TOCTOU with concurrent migration.
///
/// # Returns
///
/// 成功返回入口点和用户栈顶，失败返回错误码
pub fn load_elf(image: &[u8], cgroup_id: cgroup::CgroupId) -> Result<ElfLoadResult, ElfLoadError> {
    let elf = ElfFile::new(image).map_err(|_| ElfLoadError::InvalidMagic)?;

    // 验证 ELF 头
    validate_elf_header(&elf)?;

    // R149-3 FIX: Use caller-provided cgroup_id instead of re-reading via
    // current_cgroup_id(). sys_exec captures this under the process lock and
    // passes it here, eliminating the TOCTOU gap where concurrent cgroup
    // migration could cause the ExecSpaceGuard to uncharge the wrong cgroup.

    // Z-10 fix: 追踪所有已映射的页，用于失败时统一回滚
    // 这确保如果段 N 失败，段 0..N-1 的映射也会被清理
    //
    // 【性能优化】预分配容量避免动态扩容导致的堆分配
    // 估算：典型 ELF 约 10 个 LOAD 段 + 512 页用户栈
    // 每段平均 10 页 = 100 页 + 512 = ~612 页
    // 使用 1024 作为合理上限，避免堆碎片化
    // R154-14 FIX: Use fallible allocation to avoid panic on heap exhaustion.
    // Start with empty Vec; load_segment_tracked uses try_reserve internally.
    let mut all_mappings: Vec<MappedEntry> = Vec::new();

    // 追踪所有段的最高地址，用于计算 brk_start
    let mut highest_segment_end: usize = 0;

    // R125-1 FIX: Accumulate total cgroup-charged bytes across all segments
    // and the user stack.  Returned in ElfLoadResult so the caller can
    // uncharge on exec rollback (ExecSpaceGuard::drop).
    let mut charged_bytes: u64 = 0;

    // M2-1 SLICE-4d: accumulate the intermediate PT/PD/PDPT frame identities each helper
    // records for this fresh AS (segments + stack). sys_exec folds them into the new AS
    // ledger + a forced PT-kmem charge at the success commit. Bounded by
    // MAX_ELF_LOAD_SEGMENTS x MAX_ELF_SEGMENT_PAGES; grown fallibly (try_reserve) below.
    let mut pt_frames_acc: Vec<PhysFrame<Size4KiB>> = Vec::new();

    // R154-5 FIX: Limit PT_LOAD segment count to prevent DoS via crafted ELF
    // with thousands of tiny segments (e_phnum allows up to 65535). Each segment
    // triggers cgroup charge, heap growth, PT mapping, and TLB flush.
    const MAX_ELF_LOAD_SEGMENTS: usize = 32;
    let mut load_segment_count: usize = 0;

    // R154-12 FIX: Track loaded segment vaddr ranges to detect overlaps.
    // A malicious ELF with overlapping PT_LOAD segments could cause double-map
    // of the same virtual pages, leading to cgroup charge confusion, stale TLB
    // entries, or data corruption from a later segment overwriting an earlier one.
    let mut loaded_ranges: Vec<(usize, usize)> = Vec::new(); // (start, end) pairs

    // 加载所有 PT_LOAD 段
    for ph in elf.program_iter() {
        if ph.get_type() == Ok(PhType::Load) {
            load_segment_count += 1;
            if load_segment_count > MAX_ELF_LOAD_SEGMENTS {
                klog!(
                    Error,
                    "ELF loader: too many PT_LOAD segments ({} > {})",
                    load_segment_count,
                    MAX_ELF_LOAD_SEGMENTS
                );
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(ElfLoadError::TooManySegments);
            }

            // 计算段结束地址
            let vaddr = ph.virtual_addr() as usize;
            let memsz = ph.mem_size() as usize;
            if memsz > 0 {
                // R155-16 FIX: Use checked_add instead of saturating_add.
                // saturating_add silently clamps to usize::MAX on overflow,
                // producing a bogus segment_end that passes overlap checks
                // and causes incorrect page mappings. Return an error instead.
                let segment_end = match vaddr.checked_add(memsz) {
                    Some(end) => end,
                    None => {
                        // R165-12 FIX: Debug, not Error — these messages echo
                        // attacker-controlled ELF virtual addresses; emitting them
                        // at Error level leaks address-layout info (and lets an
                        // unprivileged user flood the log) in Balanced/Performance
                        // profiles. The syscall still returns the error to userspace.
                        klog!(
                            Debug,
                            "ELF loader: PT_LOAD segment vaddr {:#x} + memsz {:#x} overflows",
                            vaddr,
                            memsz
                        );
                        rollback_all_mappings(&mut all_mappings, cgroup_id);
                        return Err(ElfLoadError::InvalidSegment);
                    }
                };

                // R154-12 + R160-I1 FIX: Check overlap using page-aligned ranges.
                // Two segments with non-overlapping byte ranges may share the same
                // page, causing map_page to fail with PageAlreadyMapped. Aligning
                // to page boundaries catches this at validation time.
                let page_mask: usize = 0xFFF;
                let page_start = vaddr & !page_mask;
                // R165-13 FIX: saturating_add for the page-align-up. segment_end
                // (= vaddr + memsz) is already overflow-checked above, but a VA at
                // the very top of the address space could still overflow when
                // adding page_mask, panicking in debug builds on a crafted ELF.
                let page_end = segment_end.saturating_add(page_mask) & !page_mask;
                for &(prev_start, prev_end) in loaded_ranges.iter() {
                    let prev_page_start = prev_start & !page_mask;
                    let prev_page_end = prev_end.saturating_add(page_mask) & !page_mask;
                    if page_start < prev_page_end && prev_page_start < page_end {
                        // R165-12 FIX: Debug, not Error — attacker-controlled VAs.
                        klog!(Debug,
                            "ELF loader: PT_LOAD segment [{:#x}, {:#x}) overlaps with [{:#x}, {:#x}) at page level",
                            vaddr, segment_end, prev_start, prev_end
                        );
                        rollback_all_mappings(&mut all_mappings, cgroup_id);
                        return Err(ElfLoadError::OverlappingSegments);
                    }
                }
                // R156-13 FIX: Fallible push for consistency with tracked.try_reserve.
                if loaded_ranges.try_reserve(1).is_err() {
                    rollback_all_mappings(&mut all_mappings, cgroup_id);
                    return Err(ElfLoadError::OutOfMemory);
                }
                loaded_ranges.push((vaddr, segment_end));

                if segment_end > highest_segment_end {
                    highest_segment_end = segment_end;
                }
            }

            let (seg_charged, seg_pt) =
                match load_segment_tracked(&elf, &ph, &mut all_mappings, cgroup_id) {
                    Ok(v) => v,
                    Err(e) => {
                        rollback_all_mappings(&mut all_mappings, cgroup_id);
                        return Err(e);
                    }
                };
            charged_bytes = charged_bytes.saturating_add(seg_charged);
            // M2-1 SLICE-4d: fold this segment's recorded PT frames into the accumulator
            // (fallible — on OOM tear down the partial AS and fail, mirroring load_elf's
            // other try_reserve sites).
            if pt_frames_acc.try_reserve(seg_pt.len()).is_err() {
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(ElfLoadError::OutOfMemory);
            }
            pt_frames_acc.extend(seg_pt);
        }
    }

    // 分配用户栈
    let (stack_charged, stack_pt) = match allocate_user_stack_tracked(&mut all_mappings, cgroup_id)
    {
        Ok(v) => v,
        Err(e) => {
            rollback_all_mappings(&mut all_mappings, cgroup_id);
            return Err(e);
        }
    };
    charged_bytes = charged_bytes.saturating_add(stack_charged);
    // M2-1 SLICE-4d: fold the user stack's recorded PT frames into the accumulator.
    if pt_frames_acc.try_reserve(stack_pt.len()).is_err() {
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::OutOfMemory);
    }
    pt_frames_acc.extend(stack_pt);

    // 计算 brk_start：段末尾向上对齐到页边界
    let brk_start = (highest_segment_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // 验证 brk_start 不与栈区域重叠
    // 栈区域：[USER_STACK_TOP - USER_STACK_SIZE, USER_STACK_TOP)
    // NOTE: this is the ARCHITECTURAL window base (incl. the M0-7 low guard page); brk
    // must stay below the WHOLE window, so the guard is brk-safe by this very check.
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    // R172-26 FIX: strict `>` (half-open window), single-sourced via user_stack_window(). The
    // old `>=` was one page over-conservative: brk_start == stack_base is an EMPTY heap abutting
    // the window (zero overlap), and the first non-empty grow is independently rejected at
    // runtime by the strict `>` brk gate (syscall.rs). Aligning here removes the load-time vs
    // runtime boundary disagreement. `stack_base` (== user_stack_window().0) is kept for the log.
    if brk_start > user_stack_window().0 {
        // R165-12 FIX: Debug, not Error — keep this user VA out of production logs.
        // (USER_STACK_TOP is a FIXED constant; there is NO user-stack ASLR in M0, so
        // `stack_base` is deterministic — Debug here is log hygiene, not ASLR.)
        klog!(
            Debug,
            "ELF loader: brk_start 0x{:x} overlaps with stack at 0x{:x}",
            brk_start,
            stack_base
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::OverlapWithStack);
    }

    // R105-2 FIX: Diagnostic address log moved to debug-gated kprintln!.
    // These are user-space VAs (not kernel), but still should not appear in
    // production logs to avoid aiding ROP/JOP gadget searches.
    kprintln!(
        "ELF loaded: entry=0x{:x}, brk_start=0x{:x}",
        elf.header.pt2.entry_point(),
        brk_start
    );

    // R24-9 fix: 验证入口点地址是 canonical 且在用户空间范围内
    // 防止恶意 ELF 设置内核地址或非法地址导致 #GP 或代码执行到错误位置
    let entry = elf.header.pt2.entry_point();
    if entry < USER_BASE as u64 || entry >= USER_STACK_TOP {
        // R165-12 FIX: Debug, not Error — echoes an attacker-controlled VA.
        klog!(
            Debug,
            "ELF loader: invalid entry point 0x{:x} (valid range: 0x{:x}-0x{:x})",
            entry,
            USER_BASE,
            USER_STACK_TOP
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    // 验证 canonical（虽然上面的范围检查已经隐含了这一点，但显式检查更安全）
    let sign_extended = ((entry as i64) >> 47) as u64;
    if sign_extended != 0 && sign_extended != 0x1FFFF {
        // R163-22 FIX: Use Debug level — Error would expose attacker-controlled
        // values in production logs (PO-8 / INV-11 compliance).
        klog!(Debug, "ELF loader: non-canonical entry point");
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    // R162-23 FIX: Verify entry point falls within a loaded PT_LOAD segment.
    // A crafted ELF could set e_entry to an unmapped gap between segments,
    // causing the process to fault immediately on execution.
    let entry_in_segment = loaded_ranges
        .iter()
        .any(|&(start, end)| (entry as usize) >= start && (entry as usize) < end);
    if !entry_in_segment {
        // R165-12 FIX: Debug, not Error — echoes an attacker-controlled VA.
        klog!(
            Debug,
            "ELF loader: entry point 0x{:x} not within any loaded segment",
            entry
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    // 【修复】初始 RSP 必须在已映射的栈页内
    // 栈分配从 (USER_STACK_TOP - USER_STACK_SIZE) 到 USER_STACK_TOP
    // 但 USER_STACK_TOP 所在的页边界不在映射范围内
    // 设置 RSP 为最后一个映射页的顶部，减去 16 字节确保 ABI 16字节对齐
    let initial_rsp = USER_STACK_TOP - 16;

    // M0 #1 (auxv): capture program-header info for the SysV auxiliary vector.
    // `phent`/`phnum` are unconditional header reads; `phdr` (AT_PHDR) uses the
    // two-tier PT_PHDR / covering-PT_LOAD computation (0 = "omit the triple").
    // `elf` is borrowed for the whole function, so reading it here is safe.
    let phdr = compute_phdr_va(&elf);
    let phent = elf.header.pt2.ph_entry_size();
    let phnum = elf.header.pt2.ph_count();

    Ok(ElfLoadResult {
        entry,
        user_stack_top: initial_rsp,
        brk_start,
        charged_bytes,
        // M2-1 SLICE-4d: the recorded PT/PD/PDPT frames sys_exec folds into the fresh AS
        // ledger + a forced PT-kmem charge at the success commit.
        pt_frames: pt_frames_acc,
        phdr,
        phent,
        phnum,
    })
}

/// M0 #1 (auxv): compute the user-space VA of the program-header table (AT_PHDR).
///
/// Returns `0` (the "omit AT_PHDR/AT_PHENT/AT_PHNUM" sentinel) whenever no *validated*
/// user-space mapping exists. The returned VA is ALWAYS a canonical user address whose
/// whole `[va, va + e_phentsize*e_phnum)` range is file-backed by a mapped `PT_LOAD`.
///
/// Step 1 — derive a candidate VA:
/// - **Tier 1** — an explicit `PT_PHDR` program header (its `p_vaddr`). `musl-gcc
///   -static` always emits `PT_PHDR`, so the M0 gate takes this path.
/// - **Tier 2** — the `PT_LOAD` whose FILE range *fully* contains the table
///   `[e_phoff, e_phoff + e_phnum*e_phentsize)`; then `va = p_vaddr + (e_phoff -
///   p_offset)`. The full-table coverage check (not just the start) avoids pointing at
///   unmapped/zero-filled bytes.
///
/// Step 2 — VALIDATE (Codex `019ee8d1` finding 2): a `PT_PHDR` `p_vaddr` is
/// attacker-controlled, so the candidate is accepted ONLY if its whole VA range lies
/// inside the file-backed VA range of some mapped `PT_LOAD` AND inside the user image
/// window `[USER_BASE, USER_STACK_TOP - USER_STACK_SIZE)`. Otherwise the triple is
/// omitted (return `0`) — a crafted ELF can never push a non-user/unmapped VA into
/// AT_PHDR. A well-formed static binary keeps its phdrs in the first `PT_LOAD`, so this
/// rejects only malformed images (musl then merely skips TLS-via-phdr).
///
/// `ET_DYN` is rejected by [`validate_elf_header`], so the load bias is always `0` for
/// accepted images; if PIE support is added, this is the single site that needs
/// `+ load_bias`.
fn compute_phdr_va(elf: &ElfFile) -> u64 {
    // Program-header table size in bytes (e_phentsize * e_phnum).
    let e_phoff = elf.header.pt2.ph_offset();
    let table_bytes = match (elf.header.pt2.ph_entry_size() as u64)
        .checked_mul(elf.header.pt2.ph_count() as u64)
    {
        Some(b) if b != 0 => b,
        _ => return 0, // no program headers (or overflow): omit the triple.
    };

    // --- Step 1: derive a CANDIDATE user VA for the phdr table. ---
    let mut candidate: u64 = 0;
    // Tier 1: explicit PT_PHDR.
    for ph in elf.program_iter() {
        if ph.get_type() == Ok(PhType::Phdr) {
            candidate = ph.virtual_addr();
            break;
        }
    }
    // Tier 2: the PT_LOAD that file-backs the ENTIRE table.
    if candidate == 0 {
        if let Some(table_end) = e_phoff.checked_add(table_bytes) {
            for ph in elf.program_iter() {
                if ph.get_type() != Ok(PhType::Load) {
                    continue;
                }
                let seg_off = ph.offset();
                let seg_file_end = match seg_off.checked_add(ph.file_size()) {
                    Some(e) => e,
                    None => continue,
                };
                // [e_phoff, table_end) ⊆ [seg_off, seg_file_end).
                if seg_off <= e_phoff && table_end <= seg_file_end {
                    candidate = ph
                        .virtual_addr()
                        .checked_add(e_phoff - seg_off)
                        .unwrap_or(0);
                    break;
                }
            }
        }
    }
    if candidate == 0 {
        return 0;
    }

    // --- Step 2: VALIDATE the candidate against file-backed PT_LOAD coverage + user
    // bounds. Reject (return 0) anything outside, so AT_PHDR is always a real user VA. ---
    let cand_end = match candidate.checked_add(table_bytes) {
        Some(e) => e,
        None => return 0,
    };
    let user_floor = USER_BASE as u64;
    // R172-X-F2: route the last guard-INCLUSIVE re-derivation through the single source
    // (algebraically identical to USER_STACK_TOP - USER_STACK_SIZE).
    let user_ceiling = user_stack_window().0 as u64; // strictly below the stack.
    if candidate < user_floor || cand_end > user_ceiling {
        return 0;
    }
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(PhType::Load) {
            continue;
        }
        let seg_va = ph.virtual_addr();
        let seg_va_file_end = match seg_va.checked_add(ph.file_size()) {
            Some(e) => e,
            None => continue,
        };
        // Whole table VA range must be inside this segment's FILE-backed VA range.
        if seg_va <= candidate && cand_end <= seg_va_file_end {
            return candidate;
        }
    }

    // Candidate not covered by any file-backed PT_LOAD VA range: omit.
    0
}

/// 验证 ELF 头
fn validate_elf_header(elf: &ElfFile) -> Result<(), ElfLoadError> {
    let hdr = &elf.header;

    // 验证魔数
    if hdr.pt1.magic != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfLoadError::InvalidMagic);
    }

    // 验证 64 位
    match hdr.pt1.class() {
        Class::SixtyFour => {}
        _ => return Err(ElfLoadError::UnsupportedClass),
    }

    // 验证小端
    match hdr.pt1.data() {
        xmas_elf::header::Data::LittleEndian => {}
        _ => return Err(ElfLoadError::NotLittleEndian),
    }

    // 验证 x86_64
    if hdr.pt2.machine().as_machine() != Machine::X86_64 {
        return Err(ElfLoadError::UnsupportedMachine);
    }

    // 验证可执行文件
    if hdr.pt2.type_().as_type() != ElfType::Executable {
        return Err(ElfLoadError::UnsupportedType);
    }

    // R172-02 FIX (untrusted-input panic=abort DoS): bound + align the program-header table
    // BEFORE any `program_iter()` is reached on attacker bytes. xmas-elf's
    // `parse_program_header` slices `&input[off..off+entsize]` with NO bounds check, and
    // `zero::read::<ProgramHeader64>` then asserts BOTH (a) the slice is large enough AND
    // (b) the slice base is `align_of::<ProgramHeader64>()`-aligned (8). Either assert
    // failing is `panic=abort` -> permanent CPU halt: a ~100-byte crafted ELF with a bad
    // `e_phoff`/`e_phnum`/`e_phentsize` (or an unaligned `e_phoff`) is an unauthenticated
    // full-system DoS via execve(59)/spawn_image(517). `validate_elf_header` dominates every
    // `program_iter()` call (load loop, AT_PHDR derivation), so one fail-closed check here
    // closes the class. `header::sanity_check` does NOT exist in xmas-elf-0.9.1 (do not call).
    const PH64_ENTSIZE: u64 = 56; // size_of::<xmas_elf::program::ProgramHeader64>() (fixed ELF64 ABI)
    const PH64_ALIGN: usize = 8; // align_of::<ProgramHeader64>() — zero::read asserts this
    let e_phnum = hdr.pt2.ph_count();
    if e_phnum != 0 {
        let e_phoff = hdr.pt2.ph_offset();
        let e_phentsize = hdr.pt2.ph_entry_size() as u64;
        // Exact ELF64 entry size: a smaller entsize makes the crate slice/read overlap or
        // run short; a larger one over-reads. Reject both (readable-but-bad => reject, FX-18).
        if e_phentsize != PH64_ENTSIZE {
            return Err(ElfLoadError::OutOfBounds);
        }
        // [e_phoff, e_phoff + e_phnum*e_phentsize) must lie within the image (checked math).
        let table_bytes = (e_phnum as u64)
            .checked_mul(e_phentsize)
            .ok_or(ElfLoadError::OutOfBounds)?;
        let table_end = e_phoff
            .checked_add(table_bytes)
            .ok_or(ElfLoadError::OutOfBounds)?;
        if table_end > elf.input.len() as u64 {
            return Err(ElfLoadError::OutOfBounds);
        }
        // Alignment: each entry is at `input.as_ptr() + e_phoff + i*56`; since 56 % 8 == 0,
        // every entry shares the alignment of `(input base + e_phoff)`. If that is not
        // 8-aligned, the first `program_iter()` read panics — reject fail-closed instead.
        let table_base = (elf.input.as_ptr() as usize).wrapping_add(e_phoff as usize);
        if table_base & (PH64_ALIGN - 1) != 0 {
            return Err(ElfLoadError::OutOfBounds);
        }
    }

    Ok(())
}

/// Z-10 fix: 加载单个程序段并追踪映射，便于失败时全局回滚
///
/// # Arguments
///
/// * `elf` - ELF 文件引用
/// * `ph` - 程序头
/// * `tracked` - 全局映射追踪向量，成功映射的页会被追加到此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory accounting
///
/// # Returns
///
/// 成功返回 Ok(charged_bytes)，失败时调用方负责使用 tracked 进行全局回滚。
/// R125-1 FIX: Returns the number of bytes charged to the cgroup for this
/// segment so the caller can accumulate the total for exec rollback.
fn load_segment_tracked(
    elf: &ElfFile,
    ph: &xmas_elf::program::ProgramHeader,
    tracked: &mut Vec<MappedEntry>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(u64, Vec<PhysFrame<Size4KiB>>), ElfLoadError> {
    let vaddr = ph.virtual_addr() as usize;
    let memsz = ph.mem_size() as usize;
    let filesz = ph.file_size() as usize;
    let offset = ph.offset() as usize;

    // 跳过大小为 0 的段
    if memsz == 0 {
        return Ok((0, Vec::new()));
    }

    // R93-18 FIX: Reject malformed ELF with p_filesz > p_memsz.
    // In valid ELF, filesz <= memsz (the extra memsz - filesz bytes are BSS, zeroed).
    // If filesz > memsz, the segment is malformed and could cause truncated loads
    // or buffer overflows when copying file data.
    if filesz > memsz {
        return Err(ElfLoadError::OutOfBounds);
    }

    // 边界检查
    let end = vaddr.checked_add(memsz).ok_or(ElfLoadError::OutOfBounds)?;

    if vaddr < USER_BASE {
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    // R172-26 FIX: `end` is the EXCLUSIVE segment end; it intrudes the half-open stack window
    // [stack_base, USER_STACK_TOP) iff `end > stack_base`, NOT `>=` (end == stack_base means
    // the segment is [.., stack_base), disjoint). The old `>=` was one page over-conservative.
    // Single-sourced through user_stack_window().0 (usize; drops the as-u64 casts) so all the
    // load-time guards share the runtime SoT and cannot drift apart.
    if end > user_stack_window().0 {
        return Err(ElfLoadError::OverlapWithStack);
    }

    // 验证文件数据边界
    if offset.saturating_add(filesz) > elf.input.len() {
        return Err(ElfLoadError::OutOfBounds);
    }

    // 【W-1 安全修复】W^X (Write XOR Execute) 检查
    // 拒绝同时可写可执行的段，防止代码注入攻击
    // 恶意程序可能利用 RWX 段在运行时注入并执行任意代码
    let writable = ph.flags().is_write();
    let executable = ph.flags().is_execute();
    if writable && executable {
        return Err(ElfLoadError::WritableExecutableSegment);
    }

    // 计算需要映射的页
    let page_base = vaddr & !(PAGE_SIZE - 1);
    let page_offset = vaddr - page_base;
    let map_len = page_offset + memsz;
    let page_count = (map_len + PAGE_SIZE - 1) / PAGE_SIZE;

    // R151-2 FIX: Reject segments whose page_count exceeds the heap-safe limit.
    // The VA-range check above permits memsz up to ~140 TB but does not bound
    // page_count. A crafted ELF with small p_filesz but huge p_memsz exhausts
    // the 1 MiB heap via Vec::with_capacity(page_count).
    if page_count > MAX_ELF_SEGMENT_PAGES {
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    // R93-6 FIX: Pre-charge memory for this segment.
    // This enforces cgroup memory limits during ELF loading, preventing bypass
    // by loading large binaries that exceed memory.max.
    let charge_bytes = (page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        klog!(
            Error,
            "ELF loader: cgroup memory limit exceeded for segment (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    // R100-7 FIX: Record how many pages are already tracked before this segment.
    // If mapping fails mid-way, we must uncharge bytes for pages that were
    // pre-charged but never mapped (and thus won't be counted in rollback).
    let tracked_before = tracked.len();

    // 确定页权限
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if ph.flags().is_write() {
        flags |= PageTableFlags::WRITABLE;
    }
    if !ph.flags().is_execute() {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    // Z-10 fix: 本段成功映射的页（用于数据复制）
    // 【性能优化】预分配精确容量，避免 push 时重新分配
    // R151-2 FIX: Use fallible allocation instead of infallible with_capacity.
    let mut segment_mapped: Vec<MappedEntry> = Vec::new();
    if segment_mapped.try_reserve_exact(page_count).is_err() {
        // Cgroup was already charged; uncharge since no pages were mapped.
        cgroup::uncharge_memory(cgroup_id, charge_bytes);
        return Err(ElfLoadError::OutOfMemory);
    }
    // M2-1 SLICE-4d: the PT-recording shim so the intermediate PT/PD/PDPT frames map_page
    // builds for this segment are recorded (charged + ledgered by sys_exec at the success
    // commit). DATA frames below use allocate_data_frame (unrecorded); only map_page's
    // trait allocate_frame records page-table frames.
    let mut frame_alloc = crate::syscall::RecordingFrameAllocator::new();

    // R105-2 FIX: Segment layout diagnostics moved to debug-gated kprintln!.
    kprintln!(
        "  load_segment: vaddr=0x{:x}, memsz={}, filesz={}, pages={}",
        vaddr,
        memsz,
        filesz,
        page_count
    );
    kprintln!(
        "    flags: R={} W={} X={} => PTFlags: 0x{:x}",
        true,
        ph.flags().is_write(),
        ph.flags().is_execute(),
        flags.bits()
    );

    // 注意：用户地址空间的 4MB-6MB 区域已准备好 4KB 页表
    // ELF 加载器直接创建新的 4KB 页映射

    let map_result = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((page_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                // M2-1 SLICE-4d: DATA frame via the inherent allocate_data_frame (NOT
                // recorded); the map_page below records only the intermediate tables.
                let frame = frame_alloc
                    .allocate_data_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                // R172-24 FIX: reserve BOTH tracking vectors BEFORE map_page (mirror the
                // stack path allocate_user_stack_tracked / R158-9). The old order mapped
                // FIRST then `tracked.try_reserve(1)?`, so a reserve-OOM left a mapped-but-
                // UNTRACKED frame: reclaimed only by the whole-AS free_address_space backstop
                // and mis-uncharged by the post-loop `tracked.len()` delta (transient cgroup
                // skew + a latent leak if a future refactor made this failure recoverable).
                // Reserve-before-map makes "no frame is mapped unless its rollback slot
                // exists" hold by construction; the reserve-fail branch never maps, so no
                // prune/unmap is needed (strictly simpler than the map-then-reserve sites).
                if tracked.try_reserve(1).is_err() || segment_mapped.try_reserve(1).is_err() {
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::OutOfMemory);
                }

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    // R165-12 FIX: Debug, not Error — leaks the loaded segment VA.
                    klog!(
                        Debug,
                        "ELF loader: map_page FAILED for va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    // Z-10 fix: 释放刚分配但未映射成功的帧
                    // 调用方会使用 tracked 回滚所有已成功映射的页
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                // Z-10 fix: 追加到本段和全局追踪向量 (capacity reserved above -> infallible).
                segment_mapped.push((page, frame));
                tracked.push((page, frame));
            }
            Ok(())
        })
    };

    if let Err(e) = map_result {
        // R100-7 FIX: Uncharge cgroup bytes for pages that were pre-charged
        // but never mapped. rollback_all_mappings will handle the tracked pages.
        let mapped_in_segment = tracked.len().saturating_sub(tracked_before);
        let unmapped_bytes = charge_bytes.saturating_sub((mapped_in_segment * PAGE_SIZE) as u64);
        if unmapped_bytes > 0 {
            cgroup::uncharge_memory(cgroup_id, unmapped_bytes);
        }
        return Err(e);
    }

    // 【修复】使用直映物理地址访问内存，避免依赖当前 CR3
    // 首先清零所有映射的页面（防止信息泄漏）
    for (_, frame) in segment_mapped.iter() {
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        unsafe {
            ptr::write_bytes(base, 0, PAGE_SIZE);
        }
    }

    // 复制文件内容到正确的偏移位置
    let mut remaining_copy = filesz;
    let mut src_off = offset;
    for (idx, (_, frame)) in segment_mapped.iter().enumerate() {
        if remaining_copy == 0 {
            break;
        }
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        let start = if idx == 0 { page_offset } else { 0 };
        let len = cmp::min(PAGE_SIZE - start, remaining_copy);
        unsafe {
            ptr::copy_nonoverlapping(elf.input.as_ptr().add(src_off), base.add(start), len);
        }
        remaining_copy -= len;
        src_off += len;
    }

    // M2-1 SLICE-4d: yield the recorded PT/PD/PDPT frame identities alongside the charged
    // DATA bytes. On every Err path above the frames ride in the new AS and are reclaimed
    // wholesale by free_address_space on exec rollback (the recorder is dropped, never
    // charged); this Ok path hands them to load_elf -> sys_exec's success-commit fold.
    Ok((charge_bytes, frame_alloc.take_pt_frames()))
}

/// M0-7 SLICE 5: the user-stack map geometry — SINGLE source of truth for BOTH the
/// loader (`allocate_user_stack_tracked`) and tests.
///
/// Returns `(stack_base, usable_base, eager_floor, eager_page_count)`:
/// * `stack_base`        — architectural low boundary of the reserved window
///   (`USER_STACK_TOP - USER_STACK_SIZE`); brk/segments are barred below it.
/// * `usable_base`       — `stack_base + USER_STACK_GUARD_SIZE`, the lowest VA that
///   COULD be mapped (guard is unmapped); the lazy region base.
/// * `eager_floor`       — `USER_STACK_TOP - USER_STACK_EAGER_SIZE`, the lowest
///   EAGERLY-mapped VA; the eager region base.
/// * `eager_page_count`  — `USER_STACK_EAGER_SIZE / PAGE_SIZE` (4 pages = 16KB)
///   eagerly mapped downward from `USER_STACK_TOP`.
///
/// Geometry:
/// ```
/// [stack_base, usable_base)         — UNMAPPED guard page (4KB)
/// [usable_base, eager_floor)        — LAZY region (demand-grow on #PF)
/// [eager_floor, USER_STACK_TOP)     — EAGER region (mapped at exec)
/// ```
pub(crate) const fn user_stack_layout() -> (usize, usize, usize, usize) {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    let usable_base = stack_base + USER_STACK_GUARD_SIZE;
    let eager_floor = USER_STACK_TOP as usize - USER_STACK_EAGER_SIZE;
    let eager_page_count = USER_STACK_EAGER_SIZE / PAGE_SIZE;
    (stack_base, usable_base, eager_floor, eager_page_count)
}

/// M0-7 slice 2 (SLICE 1+2): the SINGLE SOURCE of the architectural user-stack window
/// `[stack_base, USER_STACK_TOP)` — **guard-INCLUSIVE** (`stack_base = USER_STACK_TOP -
/// USER_STACK_SIZE`, the SAME ceiling the `OverlapWithStack` segment guards at
/// `:323`/`:495`/`:597` already enforce, NOT the `guard_top`/`usable_base` floor).
///
/// Returned as the half-open `(window_start, window_end)`. Consumed by the runtime
/// stack-window exclusion in `sys_mmap` and `sys_brk` (the "third door": today both bound
/// only on `USER_SPACE_TOP`, which is `0x1FFFE000` ABOVE the window, so a hinted/MAP_FIXED
/// mmap or a brk grow can land INSIDE the reserved stack region and alias it). Routing both
/// through this one const fn keeps the exclusion bound from drifting to `guard_top` (which
/// would re-open `[stack_base, guard_top)` and the guard page itself to aliasing).
pub(crate) const fn user_stack_window() -> (usize, usize) {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    (stack_base, USER_STACK_TOP as usize)
}

/// M0-7 / R172-X-F2: the lowest MAPPED user-stack VA (guard-EXCLUSIVE) — the reserved
/// window's low edge plus the one permanently-UNMAPPED low guard page. Equals BOTH
/// `user_stack_layout().1` (usable_base) and `user_stack_window().0 + USER_STACK_GUARD_SIZE`.
/// This is the SINGLE source for the sigframe floor (`maybe_deliver_signal`), the
/// auxv/argv builder floor (`user_stack::compute_layout`), and the RLIMIT_STACK
/// magnitude — so a future guard-size change moves ALL of them together.
///
/// Derived from `user_stack_window().0` (NOT a fresh `USER_STACK_TOP - (SIZE - GUARD)`)
/// so the guard-INCLUSIVE window base (quantity A) and this guard-EXCLUSIVE floor
/// (quantity B) share ONE origin expression; the cross-geometry self-test then pins
/// `floor == window_start + GUARD == usable_base` as a near-tautology. Returned as `u64`
/// (the type every consumer needs); the architectural extent fits `u64` and the addition
/// of two compile-time constants cannot overflow.
///
/// `pub` (not `pub(crate)`) so the boot `usermode_test` AS-install path (in the binary
/// crate) can seed `MmState.stack_floor_committed` to the same mapped floor the exec
/// image-install commit uses — M0-7 item7 SLICE 4.
pub const fn user_stack_mapped_floor() -> u64 {
    user_stack_window().0 as u64 + USER_STACK_GUARD_SIZE as u64
}

/// M0-7 item7 SLICE 4: the lowest VA a user main-stack demand-grow may descend to,
/// derived from the soft `RLIMIT_STACK` `rlim_cur` (bytes). Used by
/// `try_grow_user_stack` to bound a grow request.
///
/// The growable extent is `min(rlim_cur, USER_STACK_SIZE - USER_STACK_GUARD_SIZE)`:
/// the `min()` clamp is LOAD-BEARING because `RLIMIT_STACK.rlim_max` is infinite, so a
/// process can `setrlimit` `rlim_cur` arbitrarily high — but the architectural window
/// only backs `SIZE - GUARD` bytes above the unmapped guard page, and a grow must NEVER
/// descend below `user_stack_mapped_floor()` (that would alias the guard or the brk
/// heap below the window). The extent is page-aligned DOWN, which makes the returned
/// floor `== page_align_up(USER_STACK_TOP - min(...))` (the conservative direction: a
/// partial-page limit yields a SMALLER growable region) and page-aligned because
/// `USER_STACK_TOP` and the aligned extent are both page multiples.
///
/// Returned floor is in `[user_stack_mapped_floor(), USER_STACK_TOP]`. With the default
/// `rlim_cur == SIZE - GUARD` it equals `user_stack_mapped_floor()` exactly — i.e. on a
/// default process the whole window-minus-guard is already eager-mapped, so there is no
/// lazy region to grow into (SLICE 5 splits the geometry to create one).
pub(crate) fn stack_grow_floor(rlim_cur: u64) -> usize {
    let max_extent = (USER_STACK_SIZE - USER_STACK_GUARD_SIZE) as u64;
    let extent = if rlim_cur < max_extent {
        rlim_cur
    } else {
        max_extent
    };
    let extent_pages = extent & !((PAGE_SIZE as u64) - 1);
    (USER_STACK_TOP - extent_pages) as usize
}

/// M0-7 self-test: pin the eager user-stack map geometry so a regression to the `+1`
/// "anti-guard" (a page above `USER_STACK_TOP`) or a forgotten guard carve fails
/// `make test`. Pure — exercises the loader's own `user_stack_layout` helper.
pub fn run_user_stack_guard_range_self_test() {
    let (stack_base, usable_base, eager_floor, eager_page_count) = user_stack_layout();
    // The guard is exactly ONE page at the window's low end.
    assert_eq!(
        usable_base - stack_base,
        USER_STACK_GUARD_SIZE,
        "guard page must be exactly USER_STACK_GUARD_SIZE at the window low end"
    );
    // M0-7 SLICE 5: Exactly USER_STACK_EAGER_SIZE / PAGE_SIZE pages are eagerly mapped (4 pages = 16KB).
    assert_eq!(
        eager_page_count,
        USER_STACK_EAGER_SIZE / PAGE_SIZE,
        "eager page_count must be USER_STACK_EAGER_SIZE / PAGE_SIZE"
    );
    // M0-7 SLICE 5: The topmost eager page ends EXACTLY at USER_STACK_TOP.
    // The eager region is [eager_floor, USER_STACK_TOP).
    assert_eq!(
        eager_floor + eager_page_count * PAGE_SIZE,
        USER_STACK_TOP as usize,
        "top eager page must end exactly at USER_STACK_TOP (no page above the window)"
    );
    // M0-7 SLICE 5: The eager map stays strictly inside the reserved window.
    // The eager region [eager_floor, USER_STACK_TOP) is above the guard and below USER_STACK_TOP.
    assert!(
        usable_base == stack_base + USER_STACK_GUARD_SIZE
            && eager_floor >= usable_base
            && eager_floor + eager_page_count * PAGE_SIZE <= USER_STACK_TOP as usize,
        "eager stack map must lie within (stack_base+guard .. USER_STACK_TOP]"
    );
}

/// Z-10 fix: 分配用户栈并追踪映射，便于失败时全局回滚
///
/// # Arguments
///
/// * `tracked` - 全局映射追踪向量，成功映射的页会被追加到此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory accounting
///
/// # Returns
///
/// 成功返回 Ok(charged_bytes)，失败时调用方负责使用 tracked 进行全局回滚。
/// R125-1 FIX: Returns the number of bytes charged to the cgroup for the
/// stack so the caller can accumulate the total for exec rollback.
fn allocate_user_stack_tracked(
    tracked: &mut Vec<MappedEntry>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(u64, Vec<PhysFrame<Size4KiB>>), ElfLoadError> {
    // M0-7 SLICE 5: Map only the EAGER top region (16KB = 4 pages). The rest of the
    // stack window grows on-demand via #PF handler. The guard page remains unmapped.
    let (_, usable_base, eager_floor, eager_page_count) = user_stack_layout();

    // R93-6 FIX: Pre-charge memory for eager stack region only.
    let charge_bytes = (eager_page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        klog!(
            Error,
            "ELF loader: cgroup memory limit exceeded for stack (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    // R100-7 FIX: Record tracked count before stack mapping for accurate
    // partial-failure uncharge (same pattern as load_segment_tracked).
    let tracked_before = tracked.len();

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    // Z-10 fix: 本段成功映射的页（用于数据清零）
    // R154-14 FIX: Use fallible allocation to avoid panic on heap exhaustion.
    let mut stack_mapped: Vec<MappedEntry> = Vec::new();
    // M2-1 SLICE-4d: PT-recording shim (see load_segment_tracked) — DATA via
    // allocate_data_frame (unrecorded), intermediate tables recorded by the trait.
    let mut frame_alloc = crate::syscall::RecordingFrameAllocator::new();

    let map_result = unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            // M0-7 SLICE 5: Map eager_page_count pages starting at eager_floor
            // (the top of the stack, growing downward toward usable_base)
            for i in 0..eager_page_count {
                let va = VirtAddr::new((eager_floor + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                // M2-1 SLICE-4d: DATA frame via allocate_data_frame (NOT recorded).
                let frame = frame_alloc
                    .allocate_data_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                // R158-9 FIX: Reserve tracking space BEFORE map_page so a failed
                // reservation cannot leave a mapped-but-untracked page.
                if tracked.try_reserve(1).is_err() || stack_mapped.try_reserve(1).is_err() {
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::OutOfMemory);
                }

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    // R165-12 FIX: Debug, not Error — keep this user VA out of
                    // production logs (the stack VA is a FIXED constant, NOT KASLR-
                    // randomized; Debug here is log hygiene).
                    klog!(
                        Debug,
                        "ELF loader: map_page FAILED for stack va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                stack_mapped.push((page, frame));
                tracked.push((page, frame));
            }
            // M0-7 SLICE 5: the low guard page + lazy region MUST stay unmapped.
            // The loop maps only [eager_floor, USER_STACK_TOP), so
            // [stack_base, usable_base) remains the unmapped guard and
            // [usable_base, eager_floor) is the lazy region (unmapped until #PF).
            // reclaim would double-free — is caught at boot (debug builds).
            debug_assert!(
                mgr.translate_addr(VirtAddr::new((usable_base - USER_STACK_GUARD_SIZE) as u64))
                    .is_none(),
                "user-stack guard page must be unmapped"
            );
            Ok(())
        })
    };

    if let Err(e) = map_result {
        // R100-7 FIX: Uncharge cgroup bytes for stack pages that were pre-charged
        // but never mapped.
        let mapped_stack = tracked.len().saturating_sub(tracked_before);
        let unmapped_bytes = charge_bytes.saturating_sub((mapped_stack * PAGE_SIZE) as u64);
        if unmapped_bytes > 0 {
            cgroup::uncharge_memory(cgroup_id, unmapped_bytes);
        }
        return Err(e);
    }

    // 【修复】使用直映物理地址清零栈区域
    // R100-5 FIX: 清零所有已映射的栈页（eager_page_count 页）以防信息泄漏。
    // M0-7 SLICE 5: eager_page_count、charge_bytes 与下面的 remaining 都源自同一
    // user_stack_layout() 的 eager_page_count，三者恒一致；故 remaining 恰在覆盖
    // 最后一页后归零。下方两个断言把这一 lockstep 钉死：半改 eager_page_count 会导致
    // 少清零（信息泄漏）或多扣费（cgroup 泄漏）。
    let mut remaining = eager_page_count * PAGE_SIZE;
    for (_, frame) in stack_mapped.iter() {
        let base = unsafe { phys_to_virt(frame.start_address()).as_mut_ptr::<u8>() };
        let len = cmp::min(PAGE_SIZE, remaining);
        unsafe {
            ptr::write_bytes(base, 0, len);
        }
        remaining -= len;
        if remaining == 0 {
            break;
        }
    }
    debug_assert_eq!(
        stack_mapped.len(),
        eager_page_count,
        "stack mapped-page count must equal page_count (charge/zero lockstep)"
    );
    debug_assert_eq!(
        remaining, 0,
        "stack zeroing must cover exactly page_count pages"
    );

    // M2-1 SLICE-4d: yield the recorded PT-frame identities alongside the charged bytes.
    Ok((charge_bytes, frame_alloc.take_pt_frames()))
}

/// Z-10 fix: 回滚所有已追踪的映射（段 + 栈）
///
/// 当 ELF 加载过程中任何步骤失败时，调用此函数清理所有已成功建立的映射，
/// 防止物理帧泄漏和半成品地址空间。
///
/// # Arguments
///
/// * `tracked` - 已追踪的映射向量，函数会清空此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory uncharging
///
/// # Safety
///
/// 必须在当前进程的地址空间上下文中调用（CR3 指向目标页表）
fn rollback_all_mappings(tracked: &mut Vec<MappedEntry>, cgroup_id: cgroup::CgroupId) {
    if tracked.is_empty() {
        return;
    }

    let page_count = tracked.len();
    klog!(Warn, "ELF loader: rolling back {} mapped pages", page_count);

    // R93-6 FIX: Uncharge memory for all pages being rolled back.
    // This ensures cgroup memory accounting remains accurate on failure.
    let uncharge_bytes = (page_count * PAGE_SIZE) as u64;
    cgroup::uncharge_memory(cgroup_id, uncharge_bytes);

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            while let Some((page, _expected_frame)) = tracked.pop() {
                // 尝试取消映射并释放物理帧
                match mgr.unmap_page(page) {
                    Ok(unmapped_frame) => {
                        frame_alloc.deallocate_frame(unmapped_frame);
                    }
                    Err(e) => {
                        klog!(
                            Warn,
                            "ELF rollback: unmap_page failed for va=0x{:x}: {:?}",
                            page.start_address().as_u64(),
                            e
                        );
                        // 继续尝试回滚其他页，不要因为一个失败就停止
                    }
                }
            }
        });
    }
}

/// 打印 ELF 文件信息（调试用）
// R163-21 FIX: Use Debug level — Info-level VA disclosure aids ASLR bypass.
pub fn print_elf_info(image: &[u8]) {
    if let Ok(elf) = ElfFile::new(image) {
        let hdr = &elf.header;
        klog!(Debug, "=== ELF Info ===");
        klog!(Debug, "Entry point: 0x{:x}", hdr.pt2.entry_point());
        klog!(Debug, "Program headers: {}", hdr.pt2.ph_count());

        // R172-02 FIX: this debug helper is the OTHER program_iter() site (besides load_elf);
        // gate it on validate_elf_header too so a crafted ELF can never panic=abort here
        // either (closes the panic CLASS module-wide, not just the exec path). No-op return
        // on a malformed table — it is only diagnostics.
        if validate_elf_header(&elf).is_err() {
            klog!(
                Debug,
                "  (program-header table failed validation; not iterating)"
            );
            return;
        }

        for (i, ph) in elf.program_iter().enumerate() {
            if ph.get_type() == Ok(PhType::Load) {
                klog!(
                    Debug,
                    "  Segment {}: vaddr=0x{:x}, memsz=0x{:x}, filesz=0x{:x}",
                    i,
                    ph.virtual_addr(),
                    ph.mem_size(),
                    ph.file_size()
                );
            }
        }
    }
}
