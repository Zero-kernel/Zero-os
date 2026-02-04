//! Memory Hardening for Zero-OS
//!
//! This module provides memory protection hardening:
//!
//! - **Identity Map Cleanup**: Remove or restrict the bootloader's identity mapping
//! - **NX Enforcement**: Set the No-Execute bit on data pages
//! - **Section Protection**: Apply appropriate permissions to kernel sections
//!
//! # Security Goals
//!
//! 1. **Prevent Code Injection**: Data regions should not be executable
//! 2. **Prevent Code Modification**: Code regions should be read-only
//! 3. **Minimize Attack Surface**: Remove unnecessary memory mappings

use mm::memory::FrameAllocator;
use mm::page_table::{
    self, ensure_pte_range, map_mmio, mmio_flags, recursive_pd, recursive_pdpt, recursive_pt,
    split_2m_entry, MapError, APIC_MMIO_SIZE, APIC_PHYS_ADDR, VGA_PHYS_ADDR,
};
use x86_64::{
    instructions::tlb,
    structures::paging::page_table::PageTableEntry,
    structures::paging::{PageTable, PageTableFlags},
    PhysAddr, VirtAddr,
};

/// Strategy for handling the identity mapping after boot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCleanupStrategy {
    /// Completely remove the identity mapping
    Unmap,
    /// Keep mapping but remove WRITABLE flag and add NO_EXECUTE
    RemoveWritable,
    /// Skip identity map cleanup (for debugging only)
    Skip,
}

/// Outcome of identity map cleanup
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// Identity mapping was completely removed
    Unmapped,
    /// Identity mapping was made read-only with NX
    ReadOnlyUpdated { updated_entries: usize },
    /// Identity mapping was already absent
    AlreadyAbsent,
    /// Cleanup was skipped
    Skipped,
}

/// Memory hardening errors
#[derive(Debug)]
pub enum HardeningError {
    /// Required page table level is missing
    PageTableMissing(&'static str),
    /// Failed to allocate a frame for page table splitting
    FrameAllocFailed,
    /// Page table structure is inconsistent
    InconsistentTopology,
    /// Invalid virtual or physical address
    InvalidAddress,
    /// Operation would break kernel functionality
    UnsafeOperation(&'static str),
}

/// Summary of NX enforcement
#[derive(Debug, Clone, Copy)]
pub struct NxEnforcementSummary {
    /// Pages marked as R-X (text/code)
    pub text_rx_pages: usize,
    /// Pages marked as R-- (rodata)
    pub ro_pages: usize,
    /// Pages marked as RW- with NX (data/bss)
    pub data_nx_pages: usize,
}

// External linker symbols for section boundaries
#[allow(dead_code)]
extern "C" {
    static kernel_start: u8;
    static kernel_end: u8;
    static text_start: u8;
    static text_end: u8;
    static rodata_start: u8;
    static rodata_end: u8;
    static data_start: u8;
    static data_end: u8;
    static bss_start: u8;
    static bss_end: u8;
}

/// VGA MMIO region size (4 KiB)
const VGA_MMIO_SIZE: usize = 0x1000;

/// SMP trampoline physical address (must match arch/smp.rs TRAMPOLINE_PHYS)
/// This page needs to remain executable for AP startup.
const SMP_TRAMPOLINE_PHYS: u64 = 0x8000;

/// SMP trampoline size (covers the code + data area)
const SMP_TRAMPOLINE_SIZE: usize = 0x1000; // 4KB page

/// Clean up the identity mapping created by the bootloader
///
/// The bootloader creates an identity mapping (physical == virtual) for the
/// first 4GB. After initialization, this mapping should be restricted.
///
/// # Arguments
///
/// * `phys_offset` - Physical memory offset for page table access
/// * `strategy` - How to handle the identity mapping
///
/// # Returns
///
/// Cleanup outcome on success, error if the operation fails
pub fn cleanup_identity_map(
    _phys_offset: VirtAddr,
    strategy: IdentityCleanupStrategy,
) -> Result<CleanupOutcome, HardeningError> {
    if strategy == IdentityCleanupStrategy::Skip {
        return Ok(CleanupOutcome::Skipped);
    }

    // Ensure MMIO windows stay reachable before altering identity mappings
    let mut frame_allocator = FrameAllocator::new();
    protect_mmio_regions(&mut frame_allocator)?;

    // Get current RSP - we must preserve this region as writable
    // The bootloader sets up a stack in identity-mapped memory
    let current_rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }

    unsafe {
        page_table::with_active_level_4_table(|pml4| {
            // PML4[0] covers virtual addresses 0x0 to 0x7FFFFFFFFFFF (low half)
            let entry = &mut pml4[0];

            if entry.is_unused() {
                return Ok(CleanupOutcome::AlreadyAbsent);
            }

            match strategy {
                IdentityCleanupStrategy::Unmap => {
                    // Completely remove the identity mapping
                    // WARNING: May break hardware access (VGA at 0xB8000, etc.)
                    entry.set_unused();
                    tlb::flush_all();
                    Ok(CleanupOutcome::Unmapped)
                }

                IdentityCleanupStrategy::RemoveWritable => {
                    // Make the identity mapping read-only with NX
                    // Use recursive page table access to reach page table frames
                    // at any physical address (not limited by high-half mapping)

                    // Verify PML4[510] recursive entry is set
                    let pml4_510 = &pml4[510];
                    if pml4_510.is_unused() {
                        return Err(HardeningError::PageTableMissing(
                            "PML4[510] recursive entry missing",
                        ));
                    }

                    let pdpt = recursive_pdpt(0);
                    let mut updated = 0usize;

                    // Walk PDPT entries (each covers 1GB)
                    for (pdpt_idx, pdpt_entry) in pdpt.iter_mut().enumerate() {
                        if pdpt_entry.is_unused() {
                            continue;
                        }

                        let pdpt_flags = pdpt_entry.flags();

                        // Handle 1GB huge pages - cannot split, error out
                        if pdpt_flags.contains(PageTableFlags::HUGE_PAGE) {
                            return Err(HardeningError::UnsafeOperation(
                                "Cannot harden 1GB identity mapping without splitting",
                            ));
                        }

                        // Walk PD entries (each covers 2MB)
                        let pd = recursive_pd(0, pdpt_idx);

                        for (pd_idx, pd_entry) in pd.iter_mut().enumerate() {
                            if pd_entry.is_unused() {
                                continue;
                            }

                            let pd_base = identity_pd_base(pdpt_idx, pd_idx);
                            updated += harden_identity_pd_entry_recursive(
                                pd_entry,
                                pd_base,
                                pdpt_idx,
                                pd_idx,
                                current_rsp,
                                &mut frame_allocator,
                            )?;
                        }
                    }

                    tlb::flush_all();
                    Ok(CleanupOutcome::ReadOnlyUpdated {
                        updated_entries: updated,
                    })
                }

                IdentityCleanupStrategy::Skip => Ok(CleanupOutcome::Skipped),
            }
        })
    }
}

// Silence unused warning for phys_offset parameter (kept for API compatibility)
#[allow(unused_variables)]

/// Enforce NX bit on kernel data sections
///
/// This function walks the high-half kernel mappings and applies proper
/// W^X permissions based on section type:
/// - text: R-X (executable, read-only)
/// - rodata: R-- (read-only, non-executable)
/// - data/bss: RW-NX (read-write, non-executable)
///
/// # Arguments
///
/// * `phys_offset` - Physical memory offset for page table access
/// * `frame_allocator` - Frame allocator for page table splitting
///
/// # Returns
///
/// Summary of pages protected on success
pub fn enforce_nx_for_kernel(
    phys_offset: VirtAddr,
    frame_allocator: &mut FrameAllocator,
) -> Result<NxEnforcementSummary, HardeningError> {
    let mut summary = NxEnforcementSummary {
        text_rx_pages: 0,
        ro_pages: 0,
        data_nx_pages: 0,
    };

    // Get kernel section boundaries from linker symbols
    let text = SectionRange::new(unsafe { &text_start as *const u8 as u64 }, unsafe {
        &text_end as *const u8 as u64
    });
    let rodata = SectionRange::new(unsafe { &rodata_start as *const u8 as u64 }, unsafe {
        &rodata_end as *const u8 as u64
    });
    let data = SectionRange::new(unsafe { &data_start as *const u8 as u64 }, unsafe {
        &data_end as *const u8 as u64
    });
    let bss = SectionRange::new(unsafe { &bss_start as *const u8 as u64 }, unsafe {
        &bss_end as *const u8 as u64
    });

    // Demote huge pages to 4KB granularity across all sections
    unsafe {
        ensure_pte_range(VirtAddr::new(text.start), text.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(rodata.start), rodata.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(data.start), data.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
        ensure_pte_range(VirtAddr::new(bss.start), bss.size(), frame_allocator)
            .map_err(map_error_to_hardening)?;
    }

    unsafe {
        page_table::with_active_level_4_table(|pml4| {
            // PML4[511] covers the high half (kernel space)
            let pml4_entry = &mut pml4[511];
            if pml4_entry.is_unused() {
                return Err(HardeningError::PageTableMissing("PML4[511] missing"));
            }

            let pdpt = get_table_from_entry(pml4_entry, phys_offset)?;

            // PDPT[510] covers 0xFFFFFFFF80000000 - 0xFFFFFFFFBFFFFFFF
            let pdpt_entry = &mut pdpt[510];
            if pdpt_entry.is_unused() {
                return Err(HardeningError::PageTableMissing("PDPT[510] missing"));
            }

            // Check if this is a huge page
            if pdpt_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(HardeningError::UnsafeOperation(
                    "Cannot split 1GB huge page for kernel",
                ));
            }

            let pd = get_table_from_entry(pdpt_entry, phys_offset)?;

            // 【W^X 修复】基线处理：先将内核 PD 下所有页面标记为 NX
            //
            // 当 ensure_pte_range 将 2MB 内核 huge page 拆分为 4KB 页面时，
            // 新创建的 PTE 会继承原始的 RWX 标志。apply_section 只修改落在
            // text/rodata/data/bss 范围内的 ~74 个页面，剩余 512-74 ≈ 438 个
            // 页面仍保持 RWX，导致 W^X 违规。
            //
            // 解决方案：先对所有内核映射页面添加 NX，然后由 text 段处理器
            // 仅对需要执行的代码页清除 NX。这确保所有非代码页都是 NX 的。
            mark_all_nx(pd, phys_offset)?;

            // Apply text section: R-X (executable, read-only)
            apply_section(
                pd,
                phys_offset,
                &text,
                |mut flags| {
                    flags.remove(PageTableFlags::WRITABLE);
                    flags.remove(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.text_rx_pages,
            )?;

            // Apply rodata section: R-- (read-only, non-executable)
            apply_section(
                pd,
                phys_offset,
                &rodata,
                |mut flags| {
                    flags.remove(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.ro_pages,
            )?;

            // Apply data section: RW-NX (read-write, non-executable)
            apply_section(
                pd,
                phys_offset,
                &data,
                |mut flags| {
                    flags.insert(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.data_nx_pages,
            )?;

            // Apply bss section: RW-NX (read-write, non-executable)
            apply_section(
                pd,
                phys_offset,
                &bss,
                |mut flags| {
                    flags.insert(PageTableFlags::WRITABLE);
                    flags.insert(PageTableFlags::NO_EXECUTE);
                    flags
                },
                &mut summary.data_nx_pages,
            )?;

            tlb::flush_all();
            Ok(summary)
        })
    }
}

/// Get child page table from a page table entry
unsafe fn get_table_from_entry(
    entry: &mut PageTableEntry,
    phys_offset: VirtAddr,
) -> Result<&'static mut PageTable, HardeningError> {
    if entry.is_unused() {
        return Err(HardeningError::PageTableMissing("entry is unused"));
    }

    let phys = entry.addr();
    let virt = phys_offset + phys.as_u64();
    Ok(&mut *(virt.as_u64() as *mut PageTable))
}

/// 为 PD 下的所有叶子页面添加 NX 位
///
/// 处理 2MB huge page（PD 级叶子）和 4KB 页面（PT 级叶子）。
/// 这是 W^X 策略的基线保护：默认所有页面不可执行，
/// 然后由各段处理器仅对代码页（.text）清除 NX。
///
/// # Safety
///
/// 调用者必须确保 `pd` 指向有效的 Page Directory，
/// 且 `phys_offset` 是正确的物理内存偏移量。
fn mark_all_nx(pd: &mut PageTable, phys_offset: VirtAddr) -> Result<(), HardeningError> {
    for pd_entry in pd.iter_mut() {
        if pd_entry.is_unused() {
            continue;
        }

        let flags = pd_entry.flags();

        // 处理 2MB huge page（PD 级别的叶子节点）
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            if !flags.contains(PageTableFlags::NO_EXECUTE) {
                let mut new_flags = flags;
                new_flags.insert(PageTableFlags::NO_EXECUTE);
                pd_entry.set_addr(pd_entry.addr(), new_flags);
            }
            continue;
        }

        // 4KB 页面：遍历 PT 条目
        let pt = unsafe { get_table_from_entry(pd_entry, phys_offset)? };
        for pt_entry in pt.iter_mut() {
            if pt_entry.is_unused() {
                continue;
            }

            let mut new_flags = pt_entry.flags();
            if !new_flags.contains(PageTableFlags::NO_EXECUTE) {
                new_flags.insert(PageTableFlags::NO_EXECUTE);
                pt_entry.set_addr(pt_entry.addr(), new_flags);
            }
        }
    }

    Ok(())
}

/// Calculate PD index for a virtual address
#[inline]
fn pd_index(vaddr: u64) -> usize {
    ((vaddr >> 21) & 0x1FF) as usize
}

/// Calculate base virtual address for a PD index (in high half)
#[inline]
fn pd_base_vaddr(pd_idx: usize) -> u64 {
    0xFFFF_FFFF_8000_0000u64 + (pd_idx as u64 * 0x200000)
}

// ============================================================================
// Helper types and functions for per-section W^X enforcement
// ============================================================================

/// Represents a kernel section address range (page-aligned)
#[derive(Clone, Copy)]
struct SectionRange {
    start: u64,
    end: u64,
}

impl SectionRange {
    fn new(start: u64, end: u64) -> Self {
        SectionRange {
            start: align_down(start),
            end: align_up(end),
        }
    }

    fn size(&self) -> usize {
        self.end.saturating_sub(self.start) as usize
    }
}

/// Apply protection flags to a kernel section
fn apply_section<F>(
    pd: &mut PageTable,
    phys_offset: VirtAddr,
    range: &SectionRange,
    mut adjust: F,
    counter: &mut usize,
) -> Result<(), HardeningError>
where
    F: FnMut(PageTableFlags) -> PageTableFlags,
{
    if range.size() == 0 {
        return Ok(());
    }

    let pd_start = pd_index(range.start);
    let pd_end = pd_index(range.end.saturating_sub(1));

    for pd_idx in pd_start..=pd_end {
        let pd_entry = &mut pd[pd_idx];
        if pd_entry.is_unused() {
            continue;
        }

        let flags = pd_entry.flags();
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(HardeningError::UnsafeOperation(
                "Expected 4KB pages after demotion",
            ));
        }

        let pt = unsafe { get_table_from_entry(pd_entry, phys_offset)? };
        let pd_base = pd_base_vaddr(pd_idx);

        for (pt_idx, pt_entry) in pt.iter_mut().enumerate() {
            if pt_entry.is_unused() {
                continue;
            }

            let page_vaddr = pd_base + (pt_idx as u64 * 4096);
            if page_vaddr < range.start || page_vaddr >= range.end {
                continue;
            }

            let new_flags = adjust(pt_entry.flags());
            pt_entry.set_addr(pt_entry.addr(), new_flags);
            *counter += 1;
        }
    }

    Ok(())
}

// ============================================================================
// Identity map hardening helpers
// ============================================================================

/// Harden a single PD entry in the identity mapping
///
/// Note: We do NOT split 2MB huge pages because the frame allocator returns
/// frames that may not be accessible via the high-half mapping (bootloader
/// only maps a limited range). Instead, we mark entire 2MB regions as RO+NX.
///
/// This means MMIO regions in the identity map become read-only (breaking
/// direct identity-map device access), but:
/// - VGA is accessible via high-half: PHYSICAL_MEMORY_OFFSET + 0xB8000
/// - APIC will need dedicated high-half mapping when SMP is implemented
///
/// Note: This function is superseded by `harden_identity_pd_entry_recursive` which
/// properly splits MMIO huge pages. Kept for potential fallback use.
#[allow(dead_code)]
fn harden_identity_pd_entry(
    pd_entry: &mut PageTableEntry,
    pd_base: u64,
    phys_offset: VirtAddr,
    _frame_allocator: &mut FrameAllocator,
) -> Result<usize, HardeningError> {
    if pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // Mark entire 2MB huge page as RO+NX
        // We don't split because allocated frames may not be accessible
        let mut flags = pd_entry.flags();
        flags.remove(PageTableFlags::WRITABLE);
        flags.insert(PageTableFlags::NO_EXECUTE);
        pd_entry.set_addr(pd_entry.addr(), flags);
        return Ok(1);
    }

    // Already 4KB pages, harden each entry preserving MMIO access
    // Note: This dead code path doesn't have access to RSP, so stack preservation
    // is not supported. Use harden_identity_pd_entry_recursive instead.
    let pt = unsafe { get_table_from_entry(pd_entry, phys_offset)? };
    Ok(harden_identity_pt(pt, pd_base, 0)) // 0 = no stack preservation
}

/// Harden a page table in the identity mapping, preserving MMIO and stack pages
///
/// # L-5 FIX Addendum: SMP Trampoline Handling
///
/// The SMP trampoline at 0x8000 must remain executable for AP startup.
/// We mark it read-only (no write) but keep it executable (no NX).
///
/// # L-5 FIX Addendum: Stack Preservation
///
/// The bootloader stack must remain writable. When we split MMIO-containing
/// 2MB regions, we must not accidentally mark stack pages read-only.
/// We preserve pages containing the current RSP and a few pages below (stack grows down).
fn harden_identity_pt(pt: &mut PageTable, pd_base: u64, current_rsp: u64) -> usize {
    let mut updated = 0usize;

    for (pt_idx, pt_entry) in pt.iter_mut().enumerate() {
        if pt_entry.is_unused() {
            continue;
        }

        let page_vaddr = pd_base + (pt_idx as u64 * 4096);
        let mut flags = pt_entry.flags();

        if is_mmio_page(page_vaddr) {
            // MMIO pages: keep writable, add NX, add uncached flags
            let mut mmio = mmio_flags();
            if flags.contains(PageTableFlags::GLOBAL) {
                mmio.insert(PageTableFlags::GLOBAL);
            }
            flags = mmio;
        } else if is_smp_trampoline_page(page_vaddr) {
            // SMP trampoline: read-only but MUST remain executable for AP startup
            // Do NOT add NO_EXECUTE here - APs need to run code from this page
            flags.remove(PageTableFlags::WRITABLE);
            // Explicitly do NOT insert NO_EXECUTE
        } else if is_stack_page(page_vaddr, current_rsp) {
            // Stack pages: keep writable but add NX (code shouldn't run from stack)
            flags.insert(PageTableFlags::NO_EXECUTE);
            // Explicitly do NOT remove WRITABLE
        } else {
            // Normal pages: make read-only, add NX
            flags.remove(PageTableFlags::WRITABLE);
            flags.insert(PageTableFlags::NO_EXECUTE);
        }

        pt_entry.set_addr(pt_entry.addr(), flags);
        updated += 1;
    }

    updated
}

/// Check if a page is part of the bootloader stack region
///
/// We conservatively mark pages containing RSP and up to STACK_GUARD_PAGES below
/// as stack pages. The stack grows downward, so these pages may be used.
///
/// # Arguments
///
/// * `page_vaddr` - Virtual address of the 4KB page to check
/// * `current_rsp` - Current RSP value (0 disables stack preservation)
#[inline]
fn is_stack_page(page_vaddr: u64, current_rsp: u64) -> bool {
    // RSP of 0 means "no stack preservation" (e.g., dead code fallback path)
    if current_rsp == 0 {
        return false;
    }

    // Stack guard: preserve the page containing RSP plus 8 pages (32KB) below
    // This should cover typical bootloader stack usage
    const STACK_GUARD_PAGES: u64 = 8;
    const PAGE_SIZE: u64 = 4096;

    let rsp_page = current_rsp & !0xFFF; // Page containing RSP
    let stack_bottom = rsp_page.saturating_sub(STACK_GUARD_PAGES * PAGE_SIZE);

    // Stack region: from stack_bottom to rsp_page (inclusive)
    page_vaddr >= stack_bottom && page_vaddr <= rsp_page
}

/// Harden a single PD entry using recursive page table access
///
/// This version uses the recursive page table mapping (PML4[510]) to access
/// page table frames at any physical address, bypassing the high-half mapping
/// limitation.
///
/// # L-5 FIX: Split MMIO Huge Pages
///
/// When a 2MB huge page contains MMIO regions (VGA, APIC, framebuffer), we
/// now split it into 512 4KB PTEs instead of marking the entire region writable.
/// This ensures only actual MMIO pages remain writable, while other pages
/// (including kernel pages at 0x100000) are marked read-only.
fn harden_identity_pd_entry_recursive(
    pd_entry: &mut PageTableEntry,
    pd_base: u64,
    pdpt_idx: usize,
    pd_idx: usize,
    current_rsp: u64,
    frame_allocator: &mut FrameAllocator,
) -> Result<usize, HardeningError> {
    // Calculate the 2MB-aligned base for stack region comparison
    let stack_pd_base = current_rsp & !0x1FFFFF;

    let flags = pd_entry.flags();
    if flags.contains(PageTableFlags::HUGE_PAGE) {
        // L-5 FIX: If this 2MB huge page overlaps MMIO, demote to 4KB PTEs
        // so only the actual MMIO pages remain writable (mmio_flags()).
        // Previously, the entire 2MB was marked writable, leaving kernel
        // pages (e.g., at 0x100000) also writable - a security violation.
        if is_mmio_2mb_region(pd_base) {
            // Split the 2MB huge page into 512 4KB PTEs
            let pt = unsafe { split_2m_entry(pd_entry, frame_allocator) }
                .map_err(map_error_to_hardening)?;
            // Now harden each 4KB page individually: MMIO pages get mmio_flags(),
            // stack pages stay writable, all other pages get RO + NX
            return Ok(harden_identity_pt(pt, pd_base, current_rsp));
        }

        // Check if this 2MB region contains the bootloader stack - preserve writability
        if pd_base == stack_pd_base {
            // Stack region: keep writable but add NX (code shouldn't run from stack)
            let mut new_flags = flags;
            new_flags.insert(PageTableFlags::NO_EXECUTE);
            pd_entry.set_addr(pd_entry.addr(), new_flags);
            return Ok(1);
        }

        // Normal region: make read-only + NX
        let mut new_flags = flags;
        new_flags.remove(PageTableFlags::WRITABLE);
        new_flags.insert(PageTableFlags::NO_EXECUTE);
        pd_entry.set_addr(pd_entry.addr(), new_flags);
        return Ok(1);
    }

    // 4KB pages - need to access PT via recursive mapping
    let pt = unsafe { recursive_pt(0, pdpt_idx, pd_idx) };
    Ok(harden_identity_pt(pt, pd_base, current_rsp))
}

// ============================================================================
// MMIO protection
// ============================================================================

/// Ensure MMIO regions are properly mapped before identity map cleanup
///
/// Note: This function is currently a no-op. MMIO protection in the identity
/// map is handled by harden_identity_pd_entry when it detects MMIO ranges.
/// The high-half VGA access uses PHYSICAL_MEMORY_OFFSET which is already
/// set up by the bootloader.
///
/// TODO: Implement proper high-half APIC mapping when needed for SMP.
fn protect_mmio_regions(_frame_allocator: &mut FrameAllocator) -> Result<(), HardeningError> {
    // MMIO in identity map is preserved by harden_identity_pd_entry
    // VGA high-half access works via PHYSICAL_MEMORY_OFFSET
    // APIC mapping deferred until SMP implementation
    Ok(())
}

/// Map a single MMIO region with proper flags
#[allow(dead_code)]
unsafe fn map_mmio_region(
    virt: VirtAddr,
    phys: PhysAddr,
    size: usize,
    frame_allocator: &mut FrameAllocator,
) -> Result<(), HardeningError> {
    map_mmio(virt, phys, size, frame_allocator).map_err(map_error_to_hardening)
}

// ============================================================================
// Utility functions
// ============================================================================

/// Calculate base address for identity map PD entry
#[inline]
fn identity_pd_base(pdpt_idx: usize, pd_idx: usize) -> u64 {
    (pdpt_idx as u64 * 0x4000_0000) + (pd_idx as u64 * 0x200000)
}

/// Check if two ranges overlap
#[inline]
fn overlaps(start_a: u64, end_a: u64, start_b: u64, end_b: u64) -> bool {
    start_a < end_b && start_b < end_a
}

/// Check if a page address is within an MMIO region
#[inline]
fn is_mmio_page(vaddr: u64) -> bool {
    // Check VGA region
    if overlaps(
        vaddr,
        vaddr.saturating_add(0x1000),
        VGA_PHYS_ADDR,
        VGA_PHYS_ADDR + VGA_MMIO_SIZE as u64,
    ) {
        return true;
    }

    // Check APIC region
    if overlaps(
        vaddr,
        vaddr.saturating_add(0x1000),
        APIC_PHYS_ADDR,
        APIC_PHYS_ADDR + APIC_MMIO_SIZE as u64,
    ) {
        return true;
    }

    // Check GOP framebuffer region (dynamically determined)
    if let Some((fb_base, fb_size)) = drivers::framebuffer::get_framebuffer_region() {
        if overlaps(
            vaddr,
            vaddr.saturating_add(0x1000),
            fb_base,
            fb_base + fb_size as u64,
        ) {
            return true;
        }
    }

    false
}

/// Check if a page address is the SMP trampoline page
///
/// The SMP trampoline is used to boot Application Processors (APs) and must
/// remain executable. It's located at a fixed low address (0x8000) because
/// APs start in real mode and can only address the first 1MB.
#[inline]
fn is_smp_trampoline_page(vaddr: u64) -> bool {
    overlaps(
        vaddr,
        vaddr.saturating_add(0x1000),
        SMP_TRAMPOLINE_PHYS,
        SMP_TRAMPOLINE_PHYS + SMP_TRAMPOLINE_SIZE as u64,
    )
}

/// Check if a 2MB region contains any MMIO address
#[inline]
fn is_mmio_2mb_region(pd_base: u64) -> bool {
    let pd_end = pd_base + 0x200000;

    // Check VGA region
    if overlaps(
        pd_base,
        pd_end,
        VGA_PHYS_ADDR,
        VGA_PHYS_ADDR + VGA_MMIO_SIZE as u64,
    ) {
        return true;
    }

    // Check APIC region
    if overlaps(
        pd_base,
        pd_end,
        APIC_PHYS_ADDR,
        APIC_PHYS_ADDR + APIC_MMIO_SIZE as u64,
    ) {
        return true;
    }

    // Check GOP framebuffer region (dynamically determined)
    if let Some((fb_base, fb_size)) = drivers::framebuffer::get_framebuffer_region() {
        if overlaps(pd_base, pd_end, fb_base, fb_base + fb_size as u64) {
            return true;
        }
    }

    false
}

/// Align address down to page boundary
#[inline]
fn align_down(addr: u64) -> u64 {
    addr & !0xfffu64
}

/// Align address up to page boundary
#[inline]
fn align_up(addr: u64) -> u64 {
    (addr + 0xfffu64) & !0xfffu64
}

/// Convert MapError to HardeningError
fn map_error_to_hardening(err: MapError) -> HardeningError {
    match err {
        MapError::FrameAllocationFailed => HardeningError::FrameAllocFailed,
        MapError::ParentEntryHugePage => {
            HardeningError::UnsafeOperation("Cannot demote huge page at requested granularity")
        }
        MapError::PageAlreadyMapped => HardeningError::InconsistentTopology,
        // R32-MM-2 FIX: Handle InvalidRange error from overflow-checked page table operations
        MapError::InvalidRange => HardeningError::InvalidAddress,
    }
}
