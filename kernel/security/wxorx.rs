//! W^X (Write XOR Execute) Policy Enforcement
//!
//! This module validates that no memory pages are simultaneously writable and executable,
//! which is a fundamental security principle to prevent code injection attacks.
//!
//! # Security Rationale
//!
//! The W^X (also written W⊕X or "Write XOR Execute") policy ensures:
//! - Code pages are read-only and executable (R-X)
//! - Data pages are writable but not executable (RW-)
//! - No page can be both writable AND executable (RWX)
//!
//! This prevents attackers from:
//! 1. Injecting code into writable buffers and executing it
//! 2. Modifying existing code pages
//!
//! # Implementation
//!
//! The validator walks the 4-level x86_64 page table hierarchy:
//! - PML4 (Page Map Level 4) - 512 GB regions
//! - PDPT (Page Directory Pointer Table) - 1 GB regions (can be huge pages)
//! - PD (Page Directory) - 2 MB regions (can be huge pages)
//! - PT (Page Table) - 4 KB pages

use mm::page_table::{self, RECURSIVE_INDEX};
use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageTable, PageTableFlags},
    PhysAddr, VirtAddr,
};

/// Summary of W^X validation
#[derive(Debug, Clone, Copy)]
pub struct ValidationSummary {
    /// Total page table entries scanned
    pub scanned_entries: usize,
    /// Number of W^X violations found
    pub violations: usize,
}

/// Details about a W^X violation
#[derive(Debug, Clone, Copy)]
pub struct Violation {
    /// Virtual base address of the violating region
    pub virt_base: VirtAddr,
    /// Physical address of the page
    pub phys: PhysAddr,
    /// Page table level where violation was found
    pub level: PageLevel,
    /// Page flags that caused the violation
    pub flags: PageTableFlags,
}

/// Page table hierarchy level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLevel {
    /// PML4 - 512 GB per entry
    P4,
    /// PDPT - 1 GB per entry
    P3,
    /// PD - 2 MB per entry
    P2,
    /// PT - 4 KB per entry
    P1,
    /// 1 GB huge page (PDPT level)
    Huge1G,
    /// 2 MB huge page (PD level)
    Huge2M,
}

/// W^X validation errors
#[derive(Debug)]
pub enum WxorxError {
    /// A W^X violation was detected
    Violation(Violation),
    /// X-3 FIX: One or more violations detected (includes full scan summary)
    PolicyViolation(ValidationSummary),
    /// Page table walk failed
    IncompleteWalk(&'static str),
    /// Invalid page table structure
    InvalidStructure,
}

/// Validate W^X policy on the currently active page tables
///
/// This function walks the entire page table hierarchy starting from CR3
/// and checks that no leaf page has both WRITABLE and !NO_EXECUTE flags.
///
/// # Arguments
///
/// * `phys_offset` - Virtual address offset for physical memory access
///
/// # Returns
///
/// X-3 FIX: API semantic clarification:
/// - `Ok(summary)` if no W^X violations are present.
/// - `Err(WxorxError::PolicyViolation(summary))` if any violations are found.
///
/// # Security Note
///
/// This function reads from CR3 directly, so it validates the actual
/// active page tables, not any cached or stale references.
pub fn validate_active(phys_offset: VirtAddr) -> Result<ValidationSummary, WxorxError> {
    // Read current CR3 to get the root page table
    let (cr3, _) = Cr3::read();
    let root_phys = cr3.start_address();
    let root_virt = phys_offset + root_phys.as_u64();

    let pml4: &PageTable = unsafe { &*(root_virt.as_u64() as *const PageTable) };

    let mut summary = ValidationSummary {
        scanned_entries: 0,
        violations: 0,
    };

    // Walk all PML4 entries
    for (pml4_idx, pml4_entry) in pml4.iter().enumerate() {
        // 【W^X 修复】跳过递归页表槽 (PML4[510])
        //
        // 递归映射允许通过特殊虚拟地址访问任意页表帧。当验证器遍历递归槽时，
        // 会将中间页表条目（PML4/PDPT/PD）误认为是叶子 PTE，从而报告假阳性。
        // 这些条目本身是 writable + !NO_EXECUTE，但它们不是实际的内存映射。
        // NX 位只在叶子页表条目上强制执行。
        if pml4_idx == RECURSIVE_INDEX {
            continue;
        }

        if pml4_entry.is_unused() {
            continue;
        }

        summary.scanned_entries += 1;

        // Calculate the virtual address base for this PML4 entry
        let virt_base = canonicalize(pml4_idx as u64 * (512 * 1024 * 1024 * 1024));

        // Get PDPT
        let pdpt_phys = pml4_entry.addr();
        let pdpt_virt = phys_offset + pdpt_phys.as_u64();
        let pdpt: &PageTable = unsafe { &*(pdpt_virt.as_u64() as *const PageTable) };

        // Walk PDPT entries
        walk_pdpt(pdpt, virt_base, phys_offset, &mut summary)?;
    }

    // X-3 FIX: Return Err if violations found, not Ok with violations
    // This prevents callers from misinterpreting "Ok" as "no violations"
    if summary.violations > 0 {
        return Err(WxorxError::PolicyViolation(summary));
    }

    Ok(summary)
}

/// Walk PDPT level
fn walk_pdpt(
    pdpt: &PageTable,
    base: u64,
    phys_offset: VirtAddr,
    summary: &mut ValidationSummary,
) -> Result<(), WxorxError> {
    for (pdpt_idx, pdpt_entry) in pdpt.iter().enumerate() {
        if pdpt_entry.is_unused() {
            continue;
        }

        summary.scanned_entries += 1;
        let flags = pdpt_entry.flags();
        let virt_base = base + (pdpt_idx as u64 * 1024 * 1024 * 1024);

        // Check for 1GB huge page
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            if is_wxorx_violation(flags) {
                summary.violations += 1;
                // Continue checking to count all violations
            }
            continue;
        }

        // Get PD
        let pd_phys = pdpt_entry.addr();
        let pd_virt = phys_offset + pd_phys.as_u64();
        let pd: &PageTable = unsafe { &*(pd_virt.as_u64() as *const PageTable) };

        walk_pd(pd, virt_base, phys_offset, summary)?;
    }

    Ok(())
}

/// Walk PD (Page Directory) level
fn walk_pd(
    pd: &PageTable,
    base: u64,
    phys_offset: VirtAddr,
    summary: &mut ValidationSummary,
) -> Result<(), WxorxError> {
    for (pd_idx, pd_entry) in pd.iter().enumerate() {
        if pd_entry.is_unused() {
            continue;
        }

        summary.scanned_entries += 1;
        let flags = pd_entry.flags();
        let virt_base = base + (pd_idx as u64 * 2 * 1024 * 1024);

        // Check for 2MB huge page
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            if is_wxorx_violation(flags) {
                summary.violations += 1;
            }
            continue;
        }

        // Get PT
        let pt_phys = pd_entry.addr();
        let pt_virt = phys_offset + pt_phys.as_u64();
        let pt: &PageTable = unsafe { &*(pt_virt.as_u64() as *const PageTable) };

        walk_pt(pt, virt_base, summary)?;
    }

    Ok(())
}

/// Walk PT (Page Table) level - 4KB pages
fn walk_pt(pt: &PageTable, base: u64, summary: &mut ValidationSummary) -> Result<(), WxorxError> {
    for (pt_idx, pt_entry) in pt.iter().enumerate() {
        if pt_entry.is_unused() {
            continue;
        }

        summary.scanned_entries += 1;
        let flags = pt_entry.flags();
        let _virt_addr = base + (pt_idx as u64 * 4096);

        if is_wxorx_violation(flags) {
            summary.violations += 1;
        }
    }

    Ok(())
}

/// Check if page flags violate W^X policy
///
/// A violation occurs when a page is both:
/// - WRITABLE (bit 1 set)
/// - EXECUTABLE (NO_EXECUTE bit NOT set, i.e., bit 63 = 0)
#[inline]
fn is_wxorx_violation(flags: PageTableFlags) -> bool {
    let writable = flags.contains(PageTableFlags::WRITABLE);
    let executable = !flags.contains(PageTableFlags::NO_EXECUTE);
    writable && executable
}

/// Canonicalize a 64-bit address for x86_64
///
/// x86_64 requires addresses to be in canonical form:
/// - Bits 48-63 must match bit 47 (sign extension)
#[inline]
fn canonicalize(addr: u64) -> u64 {
    // If bit 47 is set, extend with 1s in bits 48-63
    if addr & (1 << 47) != 0 {
        addr | 0xFFFF_0000_0000_0000
    } else {
        addr & 0x0000_FFFF_FFFF_FFFF
    }
}

/// Check a single virtual address for W^X compliance
///
/// # Arguments
///
/// * `virt_addr` - The virtual address to check
/// * `phys_offset` - Physical memory offset
///
/// # Returns
///
/// `true` if the page is W^X compliant, `false` if it violates the policy
pub fn check_address(virt_addr: VirtAddr, phys_offset: VirtAddr) -> Result<bool, WxorxError> {
    unsafe {
        page_table::with_current_manager(phys_offset, |manager| {
            match manager.translate_with_flags(virt_addr) {
                Some((_phys, flags)) => Ok(!is_wxorx_violation(flags)),
                None => Ok(true), // Unmapped pages don't violate W^X
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wxorx_violation() {
        // R-X (Read + Execute) - OK
        let rx = PageTableFlags::PRESENT;
        assert!(!is_wxorx_violation(rx));

        // RW- (Read + Write + No-Execute) - OK
        let rw = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        assert!(!is_wxorx_violation(rw));

        // RWX (Read + Write + Execute) - VIOLATION
        let rwx = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        assert!(is_wxorx_violation(rwx));
    }

    #[test]
    fn test_canonicalize() {
        // Low address - no change
        assert_eq!(canonicalize(0x1234), 0x1234);

        // High half address - sign extend
        assert_eq!(canonicalize(0x0000_8000_0000_0000), 0xFFFF_8000_0000_0000);
    }
}
