//! TLB Operations Library for x86_64
//!
//! This crate provides low-level TLB invalidation primitives, including INVPCID
//! instruction support for efficient TLB management with Process Context Identifiers.
//!
//! # Architecture
//!
//! This crate is designed to be a minimal, dependency-free foundation that can be
//! used by both architecture-specific code (`arch`) and memory management (`mm`)
//! without creating cyclic dependencies.
//!
//! # INVPCID Types
//!
//! | Type | Name | Description |
//! |------|------|-------------|
//! | 0 | Individual-address | Invalidate single (PCID, linear address) |
//! | 1 | Single-context | Invalidate all mappings for one PCID |
//! | 2 | All-context | Invalidate all non-global mappings (all PCIDs) |
//! | 3 | All-context-global | Invalidate all mappings including globals |
//!
//! # Safety
//!
//! All INVPCID functions are unsafe as they directly modify CPU TLB state.
//! Callers must ensure:
//! - INVPCID is supported (check `invpcid_supported()` first)
//! - PCID values are in range 0-4095
//! - Proper memory barriers are in place

#![no_std]
#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

/// Global flag indicating INVPCID support (cached after first check).
static INVPCID_CACHED: AtomicBool = AtomicBool::new(false);
static INVPCID_CHECKED: AtomicBool = AtomicBool::new(false);

/// Check if INVPCID instruction is supported.
///
/// Queries CPUID.(EAX=07H, ECX=0):EBX[10].
///
/// # Returns
///
/// `true` if INVPCID instruction is available.
#[inline]
pub fn invpcid_supported() -> bool {
    // Fast path: return cached value if already checked
    // Use Acquire ordering to ensure we see the cached value after the Release store
    if INVPCID_CHECKED.load(Ordering::Acquire) {
        return INVPCID_CACHED.load(Ordering::Acquire);
    }

    // Use CPUID leaf 7 (subleaf 0) to query EBX[10]
    // LLVM reserves rbx, so we must save/restore it manually.
    // We cannot use `options(nostack)` since we push/pop rbx.
    let ebx: u32;
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nomem),  // No nostack - we use push/pop
        );
    }
    let supported = (ebx & (1 << 10)) != 0;

    // Cache the result with proper ordering:
    // - Store cached value first (Relaxed is fine, will be read after Acquire of CHECKED)
    // - Then store CHECKED with Release to ensure the value is visible to other CPUs
    INVPCID_CACHED.store(supported, Ordering::Relaxed);
    INVPCID_CHECKED.store(true, Ordering::Release);

    supported
}

/// INVPCID descriptor structure.
///
/// The descriptor is passed to INVPCID in memory. It contains:
/// - `pcid`: 12-bit PCID value (bits 0-11), upper bits must be 0
/// - `address`: 64-bit linear address for type 0 invalidation
#[repr(C, packed)]
struct InvpcidDescriptor {
    /// PCID value (0-4095). Upper bits must be 0 or #GP occurs.
    pcid: u64,
    /// Linear address for single-address invalidation (type 0).
    address: u64,
}

/// Execute INVPCID instruction with given descriptor and type.
///
/// # Safety
///
/// - Caller must ensure INVPCID is supported
/// - PCID must be in range 0-4095
/// - Type must be 0-3
#[inline(always)]
unsafe fn invpcid(desc: &InvpcidDescriptor, typ: u64) {
    asm!(
        "invpcid {typ}, [{desc}]",
        desc = in(reg) desc,
        typ = in(reg) typ,
        options(nostack, preserves_flags),
    );
}

/// Invalidate a single linear address for a specific PCID (type 0).
///
/// This is the most efficient invalidation when only a single page
/// mapping has changed for a specific address space.
///
/// # Arguments
///
/// * `pcid` - Process Context Identifier (1-4095, 0 is kernel)
/// * `addr` - Linear address to invalidate
///
/// # Safety
///
/// - Caller must ensure INVPCID is supported (check `invpcid_supported()`)
/// - PCID must be valid (0-4095)
///
/// # Performance
///
/// Most efficient for single-page operations like COW resolution or
/// individual page unmapping.
#[inline(always)]
pub unsafe fn invpcid_address(pcid: u16, addr: u64) {
    let desc = InvpcidDescriptor {
        pcid: pcid as u64,
        address: addr,
    };
    invpcid(&desc, 0);
}

/// Invalidate all non-global translations for one PCID (type 1).
///
/// Invalidates all TLB entries for the specified PCID except those
/// marked as global (G bit set in PTE).
///
/// # Arguments
///
/// * `pcid` - Process Context Identifier to invalidate
///
/// # Safety
///
/// - Caller must ensure INVPCID is supported
/// - PCID must be valid (0-4095)
///
/// # Use Cases
///
/// - Process exit: invalidate all entries for that process's PCID
/// - Address space destruction
/// - Bulk page table changes
#[inline(always)]
pub unsafe fn invpcid_single_context(pcid: u16) {
    let desc = InvpcidDescriptor {
        pcid: pcid as u64,
        address: 0,
    };
    invpcid(&desc, 1);
}

/// Invalidate all non-global translations for all PCIDs (type 2).
///
/// Flushes all TLB entries except those marked as global. This is
/// equivalent to reloading CR3 without the NOFLUSH bit but more efficient.
///
/// # Safety
///
/// Caller must ensure INVPCID is supported.
///
/// # Use Cases
///
/// - Kernel page table changes affecting all address spaces
/// - System-wide TLB shootdown when per-PCID tracking unavailable
#[inline(always)]
pub unsafe fn invpcid_all_nonglobal() {
    let desc = InvpcidDescriptor { pcid: 0, address: 0 };
    invpcid(&desc, 2);
}

/// Invalidate all translations including global entries (type 3).
///
/// Complete TLB flush - invalidates all entries for all PCIDs including
/// entries marked as global.
///
/// # Safety
///
/// Caller must ensure INVPCID is supported.
///
/// # Warning
///
/// This is the most expensive invalidation type. Use sparingly:
/// - After modifying kernel mappings that use the Global bit
/// - When CR4.PGE is toggled
/// - During kernel security transitions
///
/// # Security Note
///
/// Global entries typically contain kernel mappings. Flushing them
/// provides defense-in-depth against Meltdown-style attacks but
/// significantly impacts performance.
#[inline(always)]
pub unsafe fn invpcid_all_global() {
    let desc = InvpcidDescriptor { pcid: 0, address: 0 };
    invpcid(&desc, 3);
}

/// Flush TLB entries for a specific PCID using the best available method.
///
/// This function automatically selects the best invalidation method:
/// - If INVPCID is available: use `invpcid_single_context`
/// - Otherwise: reload CR3 (full flush)
///
/// # Arguments
///
/// * `pcid` - Process Context Identifier to flush
///
/// # Safety
///
/// This function modifies TLB state. Caller must ensure:
/// - PCID is valid (0-4095)
/// - All necessary memory barriers are in place
pub unsafe fn flush_pcid(pcid: u16) {
    if invpcid_supported() {
        invpcid_single_context(pcid);
    } else {
        // Fall back to CR3 reload (flushes all non-global entries)
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Flush a single TLB entry using the best available method.
///
/// # Arguments
///
/// * `pcid` - Process Context Identifier (0 if PCID disabled)
/// * `addr` - Linear address to invalidate
///
/// # Safety
///
/// Caller must ensure the address and PCID are valid.
pub unsafe fn flush_address(pcid: u16, addr: u64) {
    if invpcid_supported() && pcid != 0 {
        invpcid_address(pcid, addr);
    } else {
        // Fall back to INVLPG (invalidates single address in current context)
        asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

/// Flush all non-global TLB entries using the best available method.
///
/// # Safety
///
/// This function modifies TLB state.
pub unsafe fn flush_all_nonglobal() {
    if invpcid_supported() {
        invpcid_all_nonglobal();
    } else {
        // Fall back to CR3 reload
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invpcid_descriptor_size() {
        // Descriptor must be exactly 16 bytes
        assert_eq!(core::mem::size_of::<InvpcidDescriptor>(), 16);
    }

    #[test]
    fn test_invpcid_descriptor_alignment() {
        // Descriptor is packed, no alignment requirement beyond byte
        assert_eq!(core::mem::align_of::<InvpcidDescriptor>(), 1);
    }
}
