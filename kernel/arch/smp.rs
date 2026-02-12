//! SMP (Symmetric Multi-Processing) Bootstrap Support
//!
//! This module handles AP (Application Processor) bring-up for multi-core systems.
//!
//! # Overview
//!
//! The BSP (Bootstrap Processor) uses this module to:
//! 1. Enumerate available CPUs via ACPI MADT parsing
//! 2. Copy the AP trampoline to low memory
//! 3. Allocate per-AP stacks
//! 4. Send INIT-SIPI-SIPI sequences to wake each AP
//! 5. Wait for APs to signal ready
//!
//! # Security Considerations
//!
//! - Trampoline page is executable only during AP bring-up
//! - All APs inherit BSP's CR4/EFER security settings (SMEP, SMAP, NXE)
//! - Per-CPU stacks are properly isolated
//! - LAPIC ID mapping prevents CPU ID spoofing
//!
//! # Usage
//!
//! ```rust,ignore
//! // After BSP init, bring up APs
//! let num_cpus = arch::smp::start_aps();
//! kprintln!("Brought up {} CPUs", num_cpus);
//! ```

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::apic;
use crate::interrupts;
use crate::syscall;
use mm::page_table::recursive_pd;
use x86_64::instructions::tlb;
use x86_64::structures::paging::PageTableFlags;

// ============================================================================
// Constants
// ============================================================================

/// Physical address where trampoline is copied (must be < 1MB, page-aligned)
const TRAMPOLINE_PHYS: u64 = 0x8000;

/// SIPI vector = physical page number of trampoline
const TRAMPOLINE_VECTOR: u8 = (TRAMPOLINE_PHYS / 0x1000) as u8;

/// Number of 4KB pages for each AP's kernel stack
const AP_STACK_PAGES: usize = 4;

/// Total size of each AP's kernel stack (16KB)
const AP_STACK_SIZE: usize = AP_STACK_PAGES * 4096;

/// Physical memory offset for high-half kernel mapping
const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

/// Maximum physical address covered by high-half direct map
const MAX_PHYS_MAPPED: u64 = 0x1_0000_0000; // 4GB

/// Start of BIOS RSDP search region
const RSDP_SEARCH_START: u64 = 0xE0000;

/// End of BIOS RSDP search region
const RSDP_SEARCH_END: u64 = 0x100000;

/// Maximum CPUs we support
const MAX_CPUS: usize = 64;

/// Timeout for AP to signal ready (in spin iterations)
const AP_READY_TIMEOUT: usize = 1_000_000;

// ============================================================================
// Trampoline Data Structure
// ============================================================================

/// Data structure shared between BSP and AP during bootstrap.
///
/// This is written by BSP and read by AP trampoline code.
/// Located at a fixed offset within the trampoline.
///
/// # R67-2 FIX
///
/// Added `data_claimed` field - the AP sets this to 1 after reading all data,
/// allowing BSP to safely move to the next AP without risking data corruption.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ApTrampolineData {
    /// Physical address of PML4 page table
    pub pml4_phys: u64,
    /// Virtual address of AP stack top
    pub stack_top: u64,
    /// Virtual address of Rust entry point
    pub entry_point: u64,
    /// Logical CPU index (1, 2, 3, ...)
    pub cpu_index: u32,
    /// Hardware LAPIC ID
    pub lapic_id: u32,
    /// EFER MSR value (for NXE, LME, etc.)
    pub efer: u64,
    /// CR4 value (for PAE, SMEP, SMAP, etc.)
    pub cr4: u64,
    /// R67-2 FIX: Address of claim flag - AP writes 1 here after reading data
    pub claim_flag_addr: u64,
}

// ============================================================================
// AP Trampoline Binary
// ============================================================================
//
// This is a hand-assembled AP trampoline that:
// 1. Starts in 16-bit real mode
// 2. Transitions to 32-bit protected mode
// 3. Enables long mode and paging
// 4. Jumps to 64-bit code and calls the Rust entry point
//
// The trampoline uses a fixed layout with ApTrampolineData at offset 0x100.

/// Offset where ApTrampolineData is stored within the trampoline
const TRAMPOLINE_DATA_OFFSET: usize = 0x100;

/// Size of the complete trampoline including data
const TRAMPOLINE_SIZE: usize = 0x200;

/// R67-2 FIX: Offset of claim_flag_addr within ApTrampolineData (byte 48)
const CLAIM_FLAG_ADDR_OFFSET: u8 = 48;

/// Generate the AP trampoline binary.
/// Returns a fixed-size array that can be copied to low memory.
///
/// Layout:
/// - 0x00-0x3F: 16-bit real mode code
/// - 0x40-0x5F: 32-bit protected mode entry + segment setup
/// - 0x60-0x67: GDT pointer (6 bytes + 2 padding)
/// - 0x68-0x6F: Padding
/// - 0x70-0x8F: GDT (4 entries * 8 bytes = 32 bytes)
/// - 0x90-0xBF: 32-bit continuation code (CR4, CR3, EFER, enable paging)
/// - 0xC0-0xFF: 64-bit long mode entry
/// - 0x100-0x137: ApTrampolineData structure (56 bytes, includes R67-2 claim_flag_addr)
fn generate_trampoline() -> [u8; TRAMPOLINE_SIZE] {
    let mut code = [0u8; TRAMPOLINE_SIZE];
    let mut i = 0;

    // ============ 16-bit Real Mode Entry (offset 0x00) ============
    // cli
    code[i] = 0xFA;
    i += 1;
    // cld
    code[i] = 0xFC;
    i += 1;

    // xor ax, ax
    code[i] = 0x31;
    code[i + 1] = 0xC0;
    i += 2;
    // mov ds, ax
    code[i] = 0x8E;
    code[i + 1] = 0xD8;
    i += 2;
    // mov es, ax
    code[i] = 0x8E;
    code[i + 1] = 0xC0;
    i += 2;
    // mov ss, ax
    code[i] = 0x8E;
    code[i + 1] = 0xD0;
    i += 2;

    // Set up stack: mov sp, 0x8FF0
    code[i] = 0xBC;
    i += 1;
    let sp_addr = (TRAMPOLINE_PHYS as u16) + 0xFF0;
    code[i] = (sp_addr & 0xFF) as u8;
    i += 1;
    code[i] = ((sp_addr >> 8) & 0xFF) as u8;
    i += 1;

    // lgdt [gdt_ptr] - GDT pointer at offset 0x60
    let gdt_ptr_addr = TRAMPOLINE_PHYS as u16 + 0x60;
    code[i] = 0x0F;
    code[i + 1] = 0x01;
    code[i + 2] = 0x16;
    i += 3;
    code[i] = (gdt_ptr_addr & 0xFF) as u8;
    i += 1;
    code[i] = ((gdt_ptr_addr >> 8) & 0xFF) as u8;
    i += 1;

    // Enable protected mode: mov eax, cr0; or eax, 1; mov cr0, eax
    code[i] = 0x0F;
    code[i + 1] = 0x20;
    code[i + 2] = 0xC0;
    i += 3; // mov eax, cr0
    code[i] = 0x66;
    code[i + 1] = 0x83;
    code[i + 2] = 0xC8;
    code[i + 3] = 0x01;
    i += 4; // or eax, 1
    code[i] = 0x0F;
    code[i + 1] = 0x22;
    code[i + 2] = 0xC0;
    i += 3; // mov cr0, eax

    // Far jump to 32-bit protected mode at offset 0x40
    let pm_entry = TRAMPOLINE_PHYS as u32 + 0x40;
    code[i] = 0x66;
    code[i + 1] = 0xEA;
    i += 2;
    code[i] = (pm_entry & 0xFF) as u8;
    i += 1;
    code[i] = ((pm_entry >> 8) & 0xFF) as u8;
    i += 1;
    code[i] = ((pm_entry >> 16) & 0xFF) as u8;
    i += 1;
    code[i] = ((pm_entry >> 24) & 0xFF) as u8;
    i += 1;
    code[i] = 0x08;
    code[i + 1] = 0x00;
    i += 2; // selector 0x08

    // Pad to offset 0x40
    while i < 0x40 {
        code[i] = 0x90; // nop
        i += 1;
    }

    // ============ 32-bit Protected Mode Entry (offset 0x40) ============
    // Load data segments with selector 0x10
    code[i] = 0x66;
    code[i + 1] = 0xB8;
    code[i + 2] = 0x10;
    code[i + 3] = 0x00;
    i += 4; // mov ax, 0x10
    code[i] = 0x8E;
    code[i + 1] = 0xD8;
    i += 2; // mov ds, ax
    code[i] = 0x8E;
    code[i + 1] = 0xC0;
    i += 2; // mov es, ax
    code[i] = 0x8E;
    code[i + 1] = 0xD0;
    i += 2; // mov ss, ax
    code[i] = 0x8E;
    code[i + 1] = 0xE0;
    i += 2; // mov fs, ax
    code[i] = 0x8E;
    code[i + 1] = 0xE8;
    i += 2; // mov gs, ax

    // Load EDI with data structure address
    let data_addr = TRAMPOLINE_PHYS as u32 + TRAMPOLINE_DATA_OFFSET as u32;
    code[i] = 0xBF;
    i += 1; // mov edi, imm32
    code[i] = (data_addr & 0xFF) as u8;
    i += 1;
    code[i] = ((data_addr >> 8) & 0xFF) as u8;
    i += 1;
    code[i] = ((data_addr >> 16) & 0xFF) as u8;
    i += 1;
    code[i] = ((data_addr >> 24) & 0xFF) as u8;
    i += 1;

    // Jump to continuation at offset 0x90 (skip GDT area)
    let current_pos = i + 2;
    let rel_offset = 0x90i32 - current_pos as i32;
    code[i] = 0xEB;
    i += 1; // jmp rel8
    code[i] = rel_offset as u8;
    i += 1;

    // Pad to offset 0x60 (GDT pointer location)
    while i < 0x60 {
        code[i] = 0x90;
        i += 1;
    }

    // ============ GDT Pointer (offset 0x60) ============
    // Limit: 4 entries * 8 bytes - 1 = 31
    code[i] = 0x1F;
    code[i + 1] = 0x00;
    i += 2;
    // Base: GDT at offset 0x70
    let gdt_base = TRAMPOLINE_PHYS as u32 + 0x70;
    code[i] = (gdt_base & 0xFF) as u8;
    i += 1;
    code[i] = ((gdt_base >> 8) & 0xFF) as u8;
    i += 1;
    code[i] = ((gdt_base >> 16) & 0xFF) as u8;
    i += 1;
    code[i] = ((gdt_base >> 24) & 0xFF) as u8;
    i += 1;
    // Padding to 8 bytes
    code[i] = 0x00;
    code[i + 1] = 0x00;
    i += 2;

    // Pad to offset 0x70 (GDT location)
    while i < 0x70 {
        code[i] = 0x00;
        i += 1;
    }

    // ============ GDT (offset 0x70) ============
    // Entry 0: Null descriptor
    for _ in 0..8 {
        code[i] = 0x00;
        i += 1;
    }

    // Entry 1 (selector 0x08): 32-bit code descriptor
    // 0x00CF9A000000FFFF: Base=0, Limit=0xFFFFF, G=1, D/B=1, L=0, P=1, DPL=0, S=1, Type=0xA
    code[i] = 0xFF;
    code[i + 1] = 0xFF;
    code[i + 2] = 0x00;
    code[i + 3] = 0x00;
    code[i + 4] = 0x00;
    code[i + 5] = 0x9A;
    code[i + 6] = 0xCF;
    code[i + 7] = 0x00;
    i += 8;

    // Entry 2 (selector 0x10): 32-bit data descriptor
    // 0x00CF92000000FFFF: Base=0, Limit=0xFFFFF, G=1, D/B=1, L=0, P=1, DPL=0, S=1, Type=0x2
    code[i] = 0xFF;
    code[i + 1] = 0xFF;
    code[i + 2] = 0x00;
    code[i + 3] = 0x00;
    code[i + 4] = 0x00;
    code[i + 5] = 0x92;
    code[i + 6] = 0xCF;
    code[i + 7] = 0x00;
    i += 8;

    // Entry 3 (selector 0x18): 64-bit code descriptor
    // 0x00AF9A000000FFFF: Base=0, Limit=0xFFFFF, G=1, D/B=0, L=1, P=1, DPL=0, S=1, Type=0xA
    code[i] = 0xFF;
    code[i + 1] = 0xFF;
    code[i + 2] = 0x00;
    code[i + 3] = 0x00;
    code[i + 4] = 0x00;
    code[i + 5] = 0x9A;
    code[i + 6] = 0xAF;
    code[i + 7] = 0x00;
    i += 8;

    // GDT ends at 0x70 + 32 = 0x90

    // ============ 32-bit Continuation Code (offset 0x90) ============
    // NOTE: Keep this code minimal! Far jump at end targets 0xC0, only 48 bytes available.

    // Step 1: Load CR4 with PAE enabled
    // mov eax, [edi+40] (cr4 from data structure)
    code[i] = 0x8B;
    code[i + 1] = 0x47;
    code[i + 2] = 40;
    i += 3;
    // or eax, 0xA0 (PAE=bit5, PGE=bit7)
    code[i] = 0x0D;
    i += 1;
    code[i] = 0xA0;
    code[i + 1] = 0x00;
    code[i + 2] = 0x00;
    code[i + 3] = 0x00;
    i += 4;
    // mov cr4, eax
    code[i] = 0x0F;
    code[i + 1] = 0x22;
    code[i + 2] = 0xE0;
    i += 3;

    // Step 2: Load CR3 with PML4 physical address
    // mov eax, [edi] (pml4_phys low 32 bits)
    code[i] = 0x8B;
    code[i + 1] = 0x07;
    i += 2;
    // mov cr3, eax
    code[i] = 0x0F;
    code[i + 1] = 0x22;
    code[i + 2] = 0xD8;
    i += 3;

    // Step 3: Enable long mode in EFER MSR
    // mov ecx, 0xC0000080 (EFER MSR)
    code[i] = 0xB9;
    i += 1;
    code[i] = 0x80;
    code[i + 1] = 0x00;
    code[i + 2] = 0x00;
    code[i + 3] = 0xC0;
    i += 4;
    // mov eax, 0x901 (SCE | LME | NXE)
    code[i] = 0xB8;
    i += 1;
    code[i] = 0x01;
    code[i + 1] = 0x09;
    code[i + 2] = 0x00;
    code[i + 3] = 0x00;
    i += 4;
    // xor edx, edx (high 32 bits = 0)
    code[i] = 0x31;
    code[i + 1] = 0xD2;
    i += 2;
    // wrmsr
    code[i] = 0x0F;
    code[i + 1] = 0x30;
    i += 2;

    // Step 4: Enable paging (activates long mode)
    // mov eax, cr0
    code[i] = 0x0F;
    code[i + 1] = 0x20;
    code[i + 2] = 0xC0;
    i += 3;
    // or eax, 0x80000001 (PG | PE)
    code[i] = 0x0D;
    i += 1;
    code[i] = 0x01;
    code[i + 1] = 0x00;
    code[i + 2] = 0x00;
    code[i + 3] = 0x80;
    i += 4;
    // mov cr0, eax
    code[i] = 0x0F;
    code[i + 1] = 0x22;
    code[i + 2] = 0xC0;
    i += 3;

    // Far jump to 64-bit code at offset 0xC0
    let lm_entry = TRAMPOLINE_PHYS as u32 + 0xC0;
    code[i] = 0xEA;
    i += 1;
    code[i] = (lm_entry & 0xFF) as u8;
    i += 1;
    code[i] = ((lm_entry >> 8) & 0xFF) as u8;
    i += 1;
    code[i] = ((lm_entry >> 16) & 0xFF) as u8;
    i += 1;
    code[i] = ((lm_entry >> 24) & 0xFF) as u8;
    i += 1;
    code[i] = 0x18;
    code[i + 1] = 0x00;
    i += 2; // selector 0x18 (64-bit code)

    // Pad to offset 0xC0
    while i < 0xC0 {
        code[i] = 0x90;
        i += 1;
    }

    // ============ 64-bit Long Mode Entry (offset 0xC0) ============
    // Load RBX with data structure address (identity mapped)
    let data_virt = TRAMPOLINE_PHYS + TRAMPOLINE_DATA_OFFSET as u64;
    code[i] = 0x48;
    code[i + 1] = 0xBB;
    i += 2; // mov rbx, imm64
    for shift in (0..8).map(|x| x * 8) {
        code[i] = ((data_virt >> shift) & 0xFF) as u8;
        i += 1;
    }

    // mov rsp, [rbx+8] (stack_top)
    code[i] = 0x48;
    code[i + 1] = 0x8B;
    code[i + 2] = 0x63;
    code[i + 3] = 0x08;
    i += 4;

    // and rsp, -16 (align stack)
    code[i] = 0x48;
    code[i + 1] = 0x83;
    code[i + 2] = 0xE4;
    code[i + 3] = 0xF0;
    i += 4;

    // mov edi, [rbx+24] (cpu_index - first arg)
    code[i] = 0x8B;
    code[i + 1] = 0x7B;
    code[i + 2] = 24;
    i += 3;

    // mov esi, [rbx+28] (lapic_id - second arg)
    code[i] = 0x8B;
    code[i + 1] = 0x73;
    code[i + 2] = 28;
    i += 3;

    // mov rdx, [rbx+8] (stack_top - third arg)
    code[i] = 0x48;
    code[i + 1] = 0x8B;
    code[i + 2] = 0x53;
    code[i + 3] = 0x08;
    i += 4;

    // mov rax, [rbx+16] (entry_point)
    code[i] = 0x48;
    code[i + 1] = 0x8B;
    code[i + 2] = 0x43;
    code[i + 3] = 16;
    i += 4;

    // R67-2 FIX: Pass claim_flag_addr as fourth argument (rcx) so Rust can
    // perform an atomic release store. This ensures proper memory ordering
    // with BSP's acquire load and avoids mixing atomic/non-atomic accesses.
    //
    // mov rcx, [rbx+48] (claim_flag_addr - fourth arg in System V AMD64 ABI)
    code[i] = 0x48;
    code[i + 1] = 0x8B;
    code[i + 2] = 0x4B;
    code[i + 3] = CLAIM_FLAG_ADDR_OFFSET;
    i += 4;

    // call rax
    code[i] = 0xFF;
    code[i + 1] = 0xD0;
    i += 2;

    // Halt loop (shouldn't reach here)
    code[i] = 0xFA;
    i += 1; // cli
    code[i] = 0xF4;
    i += 1; // hlt
    code[i] = 0xEB;
    code[i + 1] = 0xFC; // jmp -2

    code
}

// ============================================================================
// Global State
// ============================================================================

/// Number of APs that have signaled ready
static AP_ONLINE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// R67-2 FIX: Flag set by AP trampoline after it has read bootstrap data.
///
/// BSP must wait for this flag before overwriting trampoline data for the next AP.
/// Without this, a slow AP could read the wrong data if BSP times out and moves on.
static AP_DATA_CLAIMED: AtomicU64 = AtomicU64::new(0);

/// Flag set when SMP bring-up is complete
static SMP_INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Total number of CPUs (including BSP)
static TOTAL_CPUS: AtomicUsize = AtomicUsize::new(1);

/// Physical address of the ACPI RSDP provided by the bootloader
static RSDP_PHYS_ADDR: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Trampoline Page Permissions
// ============================================================================

/// Make the trampoline page executable by clearing NX on the identity-mapped region.
///
/// Security hardening sets NX on identity-mapped memory, but the AP trampoline
/// must be executable for APs to boot.
///
/// # L-5 Compatibility
///
/// After L-5 fix, the first 2MB may be split into 4KB pages. In this case:
/// - PD[0] is a PT pointer (not a huge page)
/// - The trampoline PTE at 0x8000 should already have NX cleared by memory_hardening
/// - We still clear NX on the PD entry to ensure the hierarchy allows execution
/// - Then we also clear NX on the specific trampoline PTE if needed
///
/// # Safety
///
/// This temporarily makes the trampoline page executable.
/// The trampoline should only run briefly during AP bring-up.
fn make_trampoline_executable() {
    unsafe {
        use mm::page_table::recursive_pt;

        // Identity map is in PML4[0]/PDPT[0]; PD[0] covers 0x0-0x200000 (first 2MB)
        // The trampoline at 0x8000 falls within this range
        let pd = recursive_pd(0, 0);
        let pd_entry = &mut pd[0];

        if pd_entry.is_unused() {
            klog_always!("[SMP] WARNING: missing identity mapping for trampoline region");
            return;
        }

        let pd_flags = pd_entry.flags();
        let pd_addr = pd_entry.addr();
        let is_huge = pd_flags.contains(PageTableFlags::HUGE_PAGE);

        klog_always!(
            "[SMP] PD[0] addr=0x{:x} flags={:?} (huge={})",
            pd_addr.as_u64(),
            pd_flags,
            is_huge
        );

        if is_huge {
            // 2MB huge page: clear NX on the entire region
            if pd_flags.contains(PageTableFlags::NO_EXECUTE) {
                let mut new_flags = pd_flags;
                new_flags.remove(PageTableFlags::NO_EXECUTE);
                pd_entry.set_addr(pd_addr, new_flags);
                tlb::flush_all();
                klog_always!("[SMP] Trampoline (2MB huge) made executable");
            } else {
                klog_always!("[SMP] Trampoline (2MB huge) already executable");
            }
        } else {
            // L-5 FIX: PD[0] is a PT pointer, need to handle 4KB pages
            // First, ensure PD entry allows execution (clear NX if set)
            if pd_flags.contains(PageTableFlags::NO_EXECUTE) {
                let mut new_flags = pd_flags;
                new_flags.remove(PageTableFlags::NO_EXECUTE);
                pd_entry.set_addr(pd_addr, new_flags);
                klog_always!("[SMP] PD[0] NX cleared");
            }

            // Now clear NX on the specific trampoline PTE (0x8000 / 0x1000 = index 8)
            let pt = recursive_pt(0, 0, 0);
            let trampoline_pt_idx = (TRAMPOLINE_PHYS / 0x1000) as usize; // 0x8000 / 4096 = 8
            let pt_entry = &mut pt[trampoline_pt_idx];

            if !pt_entry.is_unused() {
                let pt_flags = pt_entry.flags();
                if pt_flags.contains(PageTableFlags::NO_EXECUTE) {
                    let mut new_flags = pt_flags;
                    new_flags.remove(PageTableFlags::NO_EXECUTE);
                    pt_entry.set_addr(pt_entry.addr(), new_flags);
                    klog_always!("[SMP] Trampoline PTE[{}] NX cleared", trampoline_pt_idx);
                } else {
                    klog_always!("[SMP] Trampoline PTE[{}] already executable", trampoline_pt_idx);
                }
            }

            tlb::flush_all();
            klog_always!("[SMP] Trampoline (4KB page) made executable");
        }
    }
}

/// Restore NX bit on the trampoline page after SMP bring-up is complete.
///
/// This re-enables W^X protection for the trampoline region after all APs have
/// booted. The trampoline code is no longer needed at this point.
///
/// # L-5 Compatibility
///
/// Handles both 2MB huge pages and 4KB pages (after L-5 split).
fn make_trampoline_nonexecutable() {
    unsafe {
        use mm::page_table::recursive_pt;

        let pd = recursive_pd(0, 0);
        let pd_entry = &mut pd[0];

        if pd_entry.is_unused() {
            return;
        }

        let pd_flags = pd_entry.flags();
        let pd_addr = pd_entry.addr();
        let is_huge = pd_flags.contains(PageTableFlags::HUGE_PAGE);

        if is_huge {
            // 2MB huge page: restore NX on the entire region
            if !pd_flags.contains(PageTableFlags::NO_EXECUTE) {
                let mut new_flags = pd_flags;
                new_flags.insert(PageTableFlags::NO_EXECUTE);
                pd_entry.set_addr(pd_addr, new_flags);
            }
        } else {
            // L-5 FIX: PD[0] is a PT pointer, need to handle 4KB pages
            // Restore NX on the specific trampoline PTE
            let pt = recursive_pt(0, 0, 0);
            let trampoline_pt_idx = (TRAMPOLINE_PHYS / 0x1000) as usize;
            let pt_entry = &mut pt[trampoline_pt_idx];

            if !pt_entry.is_unused() {
                let pt_flags = pt_entry.flags();
                if !pt_flags.contains(PageTableFlags::NO_EXECUTE) {
                    let mut new_flags = pt_flags;
                    new_flags.insert(PageTableFlags::NO_EXECUTE);
                    pt_entry.set_addr(pt_entry.addr(), new_flags);
                }
            }
        }

        // R68-2 FIX: Use cross-CPU TLB shootdown instead of local-only flush.
        //
        // After restoring NX on the trampoline page, ALL CPUs must invalidate
        // their TLB entries for this page. Using local flush_all() leaves remote
        // CPUs with stale executable mappings, creating a code injection vector
        // where an attacker could place shellcode in the trampoline area.
        mm::flush_current_as_all();
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Record the ACPI RSDP address provided by the bootloader.
///
/// This must be called before start_aps() for SMP to work on UEFI systems.
pub fn set_rsdp_address(rsdp_phys: u64) {
    RSDP_PHYS_ADDR.store(rsdp_phys, Ordering::Release);
    if rsdp_phys != 0 {
        klog_always!("[SMP] RSDP address set to 0x{:x}", rsdp_phys);
    }
}

/// Start all Application Processors.
///
/// This function:
/// 1. Enumerates CPUs via ACPI MADT
/// 2. Copies trampoline to low memory
/// 3. Sends INIT-SIPI-SIPI to each AP
/// 4. Waits for each AP to signal ready
///
/// Returns the total number of online CPUs (including BSP).
///
/// # Panics
///
/// Panics if trampoline copy fails or memory allocation fails.
pub fn start_aps() -> usize {
    if SMP_INIT_DONE.load(Ordering::Acquire) {
        return TOTAL_CPUS.load(Ordering::Acquire);
    }

    // Get BSP's LAPIC ID
    let bsp_lapic = unsafe { apic::lapic_id() };

    // Enumerate all CPU LAPIC IDs
    let all_lapic_ids = enumerate_cpus();

    // Filter out BSP to get AP list
    let ap_lapic_ids: Vec<u32> = all_lapic_ids
        .into_iter()
        .filter(|id| *id != bsp_lapic)
        .collect();

    if ap_lapic_ids.is_empty() {
        klog_always!("[SMP] Single-core system detected");
        SMP_INIT_DONE.store(true, Ordering::Release);
        TOTAL_CPUS.store(1, Ordering::Release);
        return 1;
    }

    klog_always!("[SMP] Found {} AP(s), starting...", ap_lapic_ids.len());

    // Ensure the identity-mapped trampoline region is executable
    // (Security hardening sets NX on identity-mapped memory)
    make_trampoline_executable();

    // Generate and copy trampoline to low memory
    let trampoline = generate_trampoline();
    let trampoline_virt = (PHYSICAL_MEMORY_OFFSET + TRAMPOLINE_PHYS) as *mut u8;
    unsafe {
        ptr::copy_nonoverlapping(trampoline.as_ptr(), trampoline_virt, TRAMPOLINE_SIZE);
    }

    // Read BSP's page table and CPU feature state
    let cr3_phys = read_cr3();
    let cr4 = read_cr4();
    let efer = read_efer();

    klog_always!(
        "[SMP] BSP CR3=0x{:x} CR4=0x{:x} EFER=0x{:x}",
        cr3_phys,
        cr4,
        efer
    );

    // Start each AP
    for (i, lapic_id) in ap_lapic_ids.iter().enumerate() {
        let cpu_index = i + 1; // BSP is CPU 0

        // R67-2 FIX: Reset claim flag before setting up this AP's data.
        // The AP will set this to 1 after reading all trampoline data.
        AP_DATA_CLAIMED.store(0, Ordering::Release);

        // Allocate per-AP stack
        let stack_top = alloc_ap_stack();

        // Fill in trampoline data
        let data_ptr = (PHYSICAL_MEMORY_OFFSET + TRAMPOLINE_PHYS + TRAMPOLINE_DATA_OFFSET as u64)
            as *mut ApTrampolineData;
        unsafe {
            (*data_ptr).pml4_phys = cr3_phys;
            (*data_ptr).stack_top = stack_top;
            (*data_ptr).entry_point = ap_rust_entry as *const () as u64;
            (*data_ptr).cpu_index = cpu_index as u32;
            (*data_ptr).lapic_id = *lapic_id;
            (*data_ptr).efer = efer;
            (*data_ptr).cr4 = cr4;
            // R67-2 FIX: Provide address where AP signals it has read all data.
            // We use the virtual address since the AP runs with paging enabled.
            (*data_ptr).claim_flag_addr =
                &AP_DATA_CLAIMED as *const AtomicU64 as u64;
        }

        // Send INIT-SIPI-SIPI sequence
        klog_always!("[SMP] Waking CPU {} (LAPIC ID {})", cpu_index, lapic_id);

        unsafe {
            // INIT IPI
            apic::send_init_ipi(*lapic_id);
            delay_10ms();

            // First SIPI
            apic::send_sipi(*lapic_id, TRAMPOLINE_VECTOR);
            delay_200us();

            // Second SIPI (per Intel spec)
            apic::send_sipi(*lapic_id, TRAMPOLINE_VECTOR);
        }

        // R67-2 FIX: Wait for AP to claim (read) trampoline data before we can
        // safely overwrite it for the next AP. This prevents data races where
        // a slow AP reads the wrong cpu_index, stack, or lapic_id.
        let mut claim_timeout = AP_READY_TIMEOUT;
        while AP_DATA_CLAIMED.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
            claim_timeout -= 1;
            if claim_timeout == 0 {
                // AP did not claim data - it may have failed during 16-bit/32-bit
                // mode before reaching the claim code. We cannot safely continue
                // to the next AP as this AP might still be running and could
                // read corrupted data later.
                klog_always!(
                    "[SMP] CRITICAL: CPU {} did not claim trampoline data - halting SMP init",
                    cpu_index
                );
                // Return early with partial CPU count rather than risk data corruption
                let partial_total = AP_ONLINE_COUNT.load(Ordering::Acquire) + 1;
                TOTAL_CPUS.store(partial_total, Ordering::Release);
                SMP_INIT_DONE.store(true, Ordering::Release);
                make_trampoline_nonexecutable();
                return partial_total;
            }
        }

        // Wait for AP to signal ready (fully initialized)
        let mut timeout = AP_READY_TIMEOUT;
        while AP_ONLINE_COUNT.load(Ordering::Acquire) < cpu_index {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                klog_always!("[SMP] WARNING: CPU {} failed to complete init!", cpu_index);
                break;
            }
        }

        if timeout > 0 {
            klog_always!("[SMP] CPU {} online", cpu_index);
        }
    }

    let total = AP_ONLINE_COUNT.load(Ordering::Acquire) + 1; // +1 for BSP
    TOTAL_CPUS.store(total, Ordering::Release);
    SMP_INIT_DONE.store(true, Ordering::Release);

    // Restore security: make trampoline page non-executable again
    // This is important for W^X policy compliance
    make_trampoline_nonexecutable();

    klog_always!("[SMP] {} CPU(s) online", total);
    total
}

/// Check if SMP initialization is complete.
#[inline]
pub fn smp_initialized() -> bool {
    SMP_INIT_DONE.load(Ordering::Acquire)
}

/// Get total number of online CPUs.
#[inline]
pub fn online_cpus() -> usize {
    TOTAL_CPUS.load(Ordering::Acquire)
}

// ============================================================================
// AP Entry Point
// ============================================================================

/// Rust entry point for Application Processors.
///
/// Called from the AP trampoline after switching to long mode.
/// At this point:
/// - Running in 64-bit mode with paging enabled
/// - Using per-AP stack from BSP
/// - Sharing page tables with BSP
///
/// # Arguments
///
/// * `cpu_index` - Logical CPU index (1, 2, 3, ...)
/// * `lapic_id` - Hardware LAPIC ID
/// * `stack_top` - Virtual address of stack top
/// * `claim_flag_addr` - Kernel virtual address of AP_DATA_CLAIMED atomic
///
/// # Safety
///
/// This is called from assembly and must never return.
#[no_mangle]
pub extern "C" fn ap_rust_entry(
    cpu_index: u64,
    lapic_id: u64,
    stack_top: u64,
    claim_flag_addr: u64,
) -> ! {
    // R67-2 FIX: Signal BSP that we have read all trampoline data BEFORE
    // any other initialization. This allows BSP to safely reuse the
    // trampoline buffer for the next AP. Use atomic Release store to
    // ensure all our reads of trampoline data are visible.
    //
    // SAFETY: claim_flag_addr is a valid pointer to AP_DATA_CLAIMED static,
    // passed from BSP via trampoline data. We're in long mode with the same
    // page tables as BSP, so the kernel virtual address is valid.
    unsafe {
        let claim_flag = claim_flag_addr as *const AtomicU64;
        (*claim_flag).store(1, Ordering::Release);
    }

    let cpu_idx = cpu_index as usize;

    // R67-3 FIX: Verify hardware LAPIC ID matches trampoline data
    // Prevents CPU spoofing via malformed MADT or misrouted SIPI
    let lapic_expected = lapic_id as u32;
    let lapic_actual = unsafe { apic::lapic_id() };
    if lapic_actual != lapic_expected {
        klog_always!(
            "[SMP] SECURITY: LAPIC ID mismatch (expected {}, found {}) - halting AP",
            lapic_expected,
            lapic_actual
        );
        // Critical security violation - halt this AP permanently
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
        }
    }
    let lapic = lapic_actual;

    // CRITICAL: Load the kernel GDT first!
    // The AP is currently using the trampoline's minimal GDT which has:
    // - Wrong segment selectors (0x08/0x10/0x18 vs kernel's layout)
    // - No TSS (required for interrupt handling)
    // This must be done before any other initialization that might trigger interrupts.
    //
    // R70-3 FIX: Each AP now gets its own TSS and GDT for proper privilege
    // level transitions. The kernel_stack_top is used for both RSP0 (syscall/interrupt
    // returns from Ring 3) and the double fault IST stack.
    unsafe {
        crate::gdt::init_for_ap(cpu_idx, stack_top);
    }

    // Register CPU in LAPIC ID map
    cpu_local::register_cpu_id(cpu_idx, lapic);

    // Load the IDT (shared with BSP)
    unsafe {
        interrupts::load_idt_for_ap();
    }

    // Initialize this AP's LAPIC (with LINT0 masked - only BSP has 8259 PIC)
    unsafe {
        apic::init_lapic_for_ap();
    }

    // Initialize per-CPU data
    cpu_local::init_ap(
        cpu_idx,
        lapic,
        stack_top as usize,
        stack_top as usize, // IRQ stack (same for now)
        stack_top as usize, // Syscall stack (same for now)
    );

    // R67-8 FIX: Initialize per-CPU syscall metadata and GS base for this AP
    unsafe {
        syscall::init_syscall_percpu(cpu_idx);
    }

    // R68-1 FIX: Enable interrupts BEFORE advertising this CPU as online.
    //
    // Critical for TLB shootdown correctness: If we mark ourselves online while
    // interrupts are disabled, other CPUs will include us in TLB shootdown targets
    // but we cannot receive or ACK the IPI. This causes either:
    // - Shootdown timeout leading to stale TLB entries on this CPU
    // - Deadlock if the requester blocks waiting for our ACK
    //
    // By enabling interrupts first, we guarantee that once we appear in the
    // ONLINE_CPU_MASK, we can immediately service any IPIs sent to us.
    //
    // Note: The IDT and LAPIC are already initialized above, so it's safe to
    // receive interrupts at this point.
    x86_64::instructions::interrupts::enable();

    // R67-1 FIX: Register with TLB shootdown subsystem before signaling online
    // This ensures the TLB shootdown guard (assert_single_core_mode) will correctly
    // panic if SMP is enabled but IPI-based shootdown is not yet implemented.
    mm::tlb_shootdown::register_cpu_online();

    // R70-2 FIX: Also update the cpu_local online count for scheduler's cpu_pool_size().
    // This ensures num_online_cpus() returns the correct count for load balancing
    // and kick_idle_cpus() iteration.
    cpu_local::mark_cpu_online();

    // Signal that we're online
    AP_ONLINE_COUNT.fetch_add(1, Ordering::Release);

    // R70-1: Enter scheduler-aware idle loop instead of dead HLT loop
    // This allows APs to participate in scheduling and receive work via IPIs
    ap_idle_loop();
}

/// Scheduler-aware idle path for APs.
///
/// R70-1 FIX: Race-free idle loop.
///
/// The original implementation had a race condition:
/// 1. Check reschedule_if_needed() -> returns (no work)
/// 2. [IPI arrives, sets need_resched=true, handler runs and returns]
/// 3. sti; hlt executes -> CPU halts with work pending!
///
/// Fix: Disable interrupts during the scheduling check, then use atomic
/// sti;hlt sequence. On x86, STI enables interrupts starting with the
/// NEXT instruction, so any pending interrupt will wake from HLT immediately.
///
/// This enables true SMP scheduling where all CPUs participate in running
/// user processes, not just the BSP.
fn ap_idle_loop() -> ! {
    loop {
        // R70-1 FIX: Disable interrupts during check to prevent race.
        // This ensures no IPI can slip in between the check and HLT.
        x86_64::instructions::interrupts::disable();

        // Check if scheduler has work for us (set by timer tick or reschedule IPI)
        kernel_core::reschedule_if_needed();

        // Check need_resched flag with interrupts disabled
        if cpu_local::current_cpu().need_resched.load(Ordering::SeqCst) {
            // Work is pending, enable interrupts and continue to next iteration
            x86_64::instructions::interrupts::enable();
            continue;
        }

        // No work pending - use atomic sti;hlt sequence.
        // x86 guarantees that STI takes effect starting with the NEXT instruction,
        // so if an IPI is pending, the CPU will wake from HLT immediately.
        unsafe {
            core::arch::asm!(
                "sti",   // Enable interrupts (takes effect starting with HLT)
                "hlt",   // Halt until interrupt - wakes immediately if interrupt pending
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

// ============================================================================
// Stack Allocation
// ============================================================================

/// Allocate a stack for an AP.
///
/// Returns the virtual address of the stack top (highest address).
fn alloc_ap_stack() -> u64 {
    // R70-5 FIX: AP stack must be in low memory (<4GB) because the high-half
    // direct map only covers the first MAX_PHYS_MAPPED bytes. If the buddy
    // allocator returns a frame above 4GB, the computed virtual address
    // would be unmapped, causing #PF → #DF when the AP handles interrupts.
    //
    // Try multiple allocations to find a low-memory frame.
    const MAX_ALLOC_ATTEMPTS: usize = 16;

    for attempt in 0..MAX_ALLOC_ATTEMPTS {
        let frame = mm::buddy_allocator::alloc_physical_pages(AP_STACK_PAGES)
            .expect("[SMP] Failed to allocate AP stack");

        let phys = frame.start_address().as_u64();

        // Check if frame is within direct-mapped range
        if phys + AP_STACK_SIZE as u64 <= MAX_PHYS_MAPPED {
            let virt = PHYSICAL_MEMORY_OFFSET + phys;

            // Zero the stack for security
            unsafe {
                ptr::write_bytes(virt as *mut u8, 0, AP_STACK_SIZE);
            }

            // Return stack top (highest address), 16-byte aligned
            return (virt + AP_STACK_SIZE as u64) & !0xFu64;
        }

        // Frame is above 4GB - cannot use for AP stack
        // Free it and try again (buddy allocator may give different frame)
        unsafe {
            mm::buddy_allocator::free_physical_pages(frame, AP_STACK_PAGES);
        }

        if attempt > 0 {
            klog_always!("[SMP] AP stack allocation attempt {} got high frame 0x{:x}, retrying...",
                     attempt + 1, phys);
        }
    }

    // All attempts returned high memory - this is a configuration issue
    // (system has very little RAM below 4GB)
    panic!("[SMP] Cannot allocate AP stack in low memory (<4GB) after {} attempts. \
            System may have insufficient low memory.", MAX_ALLOC_ATTEMPTS);
}

// ============================================================================
// CPU Enumeration
// ============================================================================

/// Enumerate all CPUs in the system.
///
/// Tries ACPI MADT first, falls back to BSP-only if parsing fails.
fn enumerate_cpus() -> Vec<u32> {
    // Try ACPI MADT parsing
    if let Some(ids) = unsafe { parse_madt() } {
        return ids;
    }

    // Fallback: BSP only
    klog_always!("[SMP] MADT not found, single-core fallback");
    vec![unsafe { apic::lapic_id() }]
}

// ============================================================================
// ACPI Parsing
// ============================================================================

/// RSDP v1 structure (ACPI 1.0)
#[repr(C, packed)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oemid: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// RSDP v2 structure (ACPI 2.0+)
#[repr(C, packed)]
struct RsdpV2 {
    v1: RsdpV1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header
///
/// E.1 HPET: Made pub(crate) so hpet.rs can access ACPI table parsing.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oemid: [u8; 6],
    pub oemtableid: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_rev: u32,
}

/// MADT header
#[repr(C, packed)]
struct Madt {
    header: SdtHeader,
    lapic_address: u32,
    flags: u32,
}

/// MADT entry: Processor Local APIC
#[repr(C, packed)]
struct ProcessorLocalApic {
    entry_type: u8,
    length: u8,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32,
}

/// Parse MADT to get list of LAPIC IDs.
unsafe fn parse_madt() -> Option<Vec<u32>> {
    // Find RSDP
    let (rsdt_phys, xsdt_phys) = find_rsdp()?;

    // Find MADT in XSDT or RSDT
    let madt_phys = if xsdt_phys != 0 {
        find_table_xsdt(xsdt_phys, b"APIC").or_else(|| find_table_rsdt(rsdt_phys, b"APIC"))
    } else {
        find_table_rsdt(rsdt_phys, b"APIC")
    }?;

    // Validate MADT header
    let header = read_sdt_header(madt_phys)?;
    let total_len = header.length as usize;
    let table = phys_slice(madt_phys, total_len)?;

    if !validate_checksum(table) {
        return None;
    }

    if total_len < core::mem::size_of::<Madt>() {
        return None;
    }

    // Parse MADT entries
    let mut ids = Vec::new();
    let mut offset = core::mem::size_of::<Madt>();

    while offset + 2 <= total_len {
        let entry_type = table[offset];
        let entry_len = table[offset + 1] as usize;

        if entry_len < 2 || offset + entry_len > total_len {
            break;
        }

        // Entry type 0 = Processor Local APIC
        if entry_type == 0 && entry_len >= core::mem::size_of::<ProcessorLocalApic>() {
            let pla = &*(table[offset..].as_ptr() as *const ProcessorLocalApic);
            // Check if processor is enabled (bit 0)
            if pla.flags & 1 != 0 {
                ids.push(pla.apic_id as u32);
            }
        }

        offset += entry_len;
    }

    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// Find RSDP using bootloader-provided address or BIOS memory fallback.
///
/// For UEFI systems, the bootloader provides the RSDP address from the
/// EFI Configuration Table. For legacy BIOS systems, we scan 0xE0000-0x100000.
///
/// E.1 HPET: Made pub(crate) so hpet.rs can locate ACPI tables.
pub(crate) unsafe fn find_rsdp() -> Option<(u64, u64)> {
    // First try bootloader-provided RSDP address (UEFI path)
    let rsdp_phys = RSDP_PHYS_ADDR.load(Ordering::Acquire);
    if rsdp_phys != 0 {
        if let Some(result) = validate_rsdp_at(rsdp_phys) {
            return Some(result);
        }
        klog_always!(
            "[SMP] Bootloader RSDP at 0x{:x} invalid, trying BIOS scan",
            rsdp_phys
        );
    }

    // Fallback: scan BIOS memory region (legacy BIOS path)
    for phys in (RSDP_SEARCH_START..RSDP_SEARCH_END).step_by(16) {
        if let Some(result) = validate_rsdp_at(phys) {
            return Some(result);
        }
    }
    None
}

/// Validate RSDP at a specific physical address and extract RSDT/XSDT addresses.
unsafe fn validate_rsdp_at(phys: u64) -> Option<(u64, u64)> {
    let slice = phys_slice(phys, core::mem::size_of::<RsdpV1>())?;

    // Check signature
    if &slice[0..8] != b"RSD PTR " {
        return None;
    }

    // Validate v1 checksum (first 20 bytes)
    if !validate_checksum(&slice[..20]) {
        return None;
    }

    let v1 = &*(slice.as_ptr() as *const RsdpV1);

    // ACPI 1.0
    if v1.revision < 2 {
        return Some((v1.rsdt_address as u64, 0));
    }

    // ACPI 2.0+
    let slice2 = phys_slice(phys, core::mem::size_of::<RsdpV2>())?;
    let v2 = &*(slice2.as_ptr() as *const RsdpV2);

    // Bounds check before checksum validation
    let v2_len = v2.length as usize;
    if v2_len > slice2.len() || v2_len < core::mem::size_of::<RsdpV1>() {
        return None;
    }

    // Validate extended checksum
    if !validate_checksum(&slice2[..v2_len]) {
        return None;
    }

    Some((v2.v1.rsdt_address as u64, v2.xsdt_address))
}

/// Find a table in RSDT by signature.
///
/// E.1 HPET: Made pub(crate) so hpet.rs can locate ACPI tables.
pub(crate) unsafe fn find_table_rsdt(rsdt_phys: u64, sig: &[u8; 4]) -> Option<u64> {
    let header = read_sdt_header(rsdt_phys)?;
    if &header.signature != b"RSDT" {
        return None;
    }

    let total_len = header.length as usize;
    let body = phys_slice(rsdt_phys, total_len)?;
    let entries = (total_len - core::mem::size_of::<SdtHeader>()) / 4;

    for i in 0..entries {
        let off = core::mem::size_of::<SdtHeader>() + i * 4;
        let entry_phys = u32::from_le_bytes(body[off..off + 4].try_into().ok()?) as u64;

        if let Some(hdr) = read_sdt_header(entry_phys) {
            if &hdr.signature == sig {
                return Some(entry_phys);
            }
        }
    }
    None
}

/// Find a table in XSDT by signature.
///
/// E.1 HPET: Made pub(crate) so hpet.rs can locate ACPI tables.
pub(crate) unsafe fn find_table_xsdt(xsdt_phys: u64, sig: &[u8; 4]) -> Option<u64> {
    let header = read_sdt_header(xsdt_phys)?;
    if &header.signature != b"XSDT" {
        return None;
    }

    let total_len = header.length as usize;
    let body = phys_slice(xsdt_phys, total_len)?;
    let entries = (total_len - core::mem::size_of::<SdtHeader>()) / 8;

    for i in 0..entries {
        let off = core::mem::size_of::<SdtHeader>() + i * 8;
        let entry_phys = u64::from_le_bytes(body[off..off + 8].try_into().ok()?);

        if let Some(hdr) = read_sdt_header(entry_phys) {
            if &hdr.signature == sig {
                return Some(entry_phys);
            }
        }
    }
    None
}

/// Read an SDT header from physical memory.
///
/// E.1 HPET: Made pub(crate) so hpet.rs can parse ACPI tables.
pub(crate) fn read_sdt_header(phys: u64) -> Option<SdtHeader> {
    let slice = phys_slice(phys, core::mem::size_of::<SdtHeader>())?;
    Some(unsafe { ptr::read_unaligned(slice.as_ptr() as *const SdtHeader) })
}

/// Get a slice of physical memory via high-half mapping.
///
/// E.1 HPET: Made pub(crate) so hpet.rs can read ACPI table data.
pub(crate) fn phys_slice(phys: u64, len: usize) -> Option<&'static [u8]> {
    if phys == 0 || phys + len as u64 > MAX_PHYS_MAPPED {
        return None;
    }
    let virt = (PHYSICAL_MEMORY_OFFSET + phys) as *const u8;
    Some(unsafe { core::slice::from_raw_parts(virt, len) })
}

/// Validate ACPI checksum (sum of all bytes must be 0).
///
/// E.1 HPET: Made pub(crate) so hpet.rs can validate ACPI tables.
pub(crate) fn validate_checksum(data: &[u8]) -> bool {
    data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)) == 0
}

// ============================================================================
// Low-level CPU Operations
// ============================================================================

/// Read CR3 (page table base register).
#[inline]
fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read CR4 (control register 4).
#[inline]
fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Read EFER MSR.
#[inline]
fn read_efer() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC0000080u32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

// ============================================================================
// Timing
// ============================================================================

/// Read the Time Stamp Counter (TSC).
#[inline]
fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Delay for approximately the given number of microseconds.
/// Uses TSC for more accurate timing (assumes ~2GHz CPU).
#[inline]
fn delay_us(microseconds: u64) {
    // Assume 2GHz CPU = 2000 cycles per microsecond
    // This is approximate but much better than spin_loop
    let cycles = microseconds * 2000;
    let start = read_tsc();
    while read_tsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Delay approximately 200 microseconds.
#[inline]
fn delay_200us() {
    delay_us(200);
}

/// Delay approximately 10 milliseconds.
#[inline]
fn delay_10ms() {
    delay_us(10_000);
}
