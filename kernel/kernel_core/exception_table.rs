//! Exception table support (x86_64)
//!
//! H-26 FIX: A minimal Linux-style exception table for fault-tolerant kernel accesses.
//! Entries are emitted by assembly helpers into the `.ex_table` linker section.
//!
//! # Design
//!
//! The exception table maps faulting instruction addresses (RIP) to fixup addresses.
//! When a page fault occurs during a usercopy operation:
//! 1. The page fault handler calls `lookup(fault_rip)`
//! 2. If an entry is found, RIP is rewritten to the fixup address
//! 3. The usercopy helper returns an error code (EFAULT semantics)
//! 4. The syscall layer receives the error and returns EFAULT to userspace
//!
//! # Section Layout (PC-relative, PIE-compatible)
//!
//! Each `.ex_table` entry is 8 bytes: two signed 32-bit offsets.
//! - `fault_ip_rel`: offset from the field's own address to the faulting instruction
//! - `fixup_ip_rel`: offset from the field's own address to the fixup label
//!
//! Absolute addresses are recovered at runtime:
//!   `absolute = &field as usize + field as isize`
//!
//! This PC-relative encoding avoids R_X86_64_64 relocations, making the
//! exception table compatible with PIE/text-KASLR linking.

use core::ptr;

/// Exception table entry using PC-relative signed 32-bit offsets.
///
/// Each field stores the signed distance from its own address to the target.
/// This avoids absolute addresses and is compatible with PIE linking.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExceptionTableEntry {
    /// Signed offset from this field's address to the faulting instruction
    pub fault_ip_rel: i32,
    /// Signed offset from this field's address to the fixup label
    pub fixup_ip_rel: i32,
}

impl ExceptionTableEntry {
    /// Compute the absolute faulting instruction address.
    ///
    /// `absolute = &self.fault_ip_rel as usize + self.fault_ip_rel as isize`
    #[inline]
    unsafe fn fault_ip(&self) -> usize {
        let base = ptr::addr_of!(self.fault_ip_rel) as usize;
        base.wrapping_add(self.fault_ip_rel as isize as usize)
    }

    /// Compute the absolute fixup address.
    ///
    /// `absolute = &self.fixup_ip_rel as usize + self.fixup_ip_rel as isize`
    #[inline]
    unsafe fn fixup_ip(&self) -> usize {
        let base = ptr::addr_of!(self.fixup_ip_rel) as usize;
        base.wrapping_add(self.fixup_ip_rel as isize as usize)
    }
}

extern "C" {
    /// Start of the exception table section (defined by linker script)
    static __ex_table_start: u8;
    /// End of the exception table section (defined by linker script)
    static __ex_table_end: u8;
}

/// Look up a fixup address for the given faulting instruction pointer.
///
/// # Arguments
/// * `fault_ip` - The instruction pointer (RIP) that caused the fault
///
/// # Returns
/// * `Some(fixup_ip)` - Fixup address if `fault_ip` is in the exception table
/// * `None` - No exception table entry for this address
///
/// # Performance
///
/// This is a linear search O(n) where n is the number of exception table entries.
/// For a small kernel with few usercopy helpers, this is acceptable.
/// For larger systems, a sorted table with binary search would be more efficient.
#[inline]
pub fn lookup(fault_ip: usize) -> Option<usize> {
    // SAFETY: These symbols are defined by the linker script and point to valid memory.
    let start = unsafe { ptr::addr_of!(__ex_table_start) as *const ExceptionTableEntry };
    let end = unsafe { ptr::addr_of!(__ex_table_end) as *const ExceptionTableEntry };

    // Calculate number of entries
    let count = (end as usize - start as usize) / core::mem::size_of::<ExceptionTableEntry>();

    for i in 0..count {
        // SAFETY: `i` is within the exception table range; entry read is aligned (8-byte).
        let entry = unsafe { &*start.add(i) };
        let abs_fault = unsafe { entry.fault_ip() };
        if abs_fault == fault_ip {
            return Some(unsafe { entry.fixup_ip() });
        }
    }

    None
}

/// Get the number of entries in the exception table.
///
/// Useful for debugging and verification.
#[allow(dead_code)]
pub fn entry_count() -> usize {
    let start = unsafe { ptr::addr_of!(__ex_table_start) as usize };
    let end = unsafe { ptr::addr_of!(__ex_table_end) as usize };
    (end - start) / core::mem::size_of::<ExceptionTableEntry>()
}
