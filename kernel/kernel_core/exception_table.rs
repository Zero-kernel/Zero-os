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
//! # Section Layout
//!
//! The `.ex_table` section contains pairs of `(fault_ip, fixup_ip)` addresses.
//! Each entry is 16 bytes (two u64 pointers) aligned to 16 bytes.

use core::ptr;

/// Exception table entry mapping a faulting instruction to its fixup.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExceptionTableEntry {
    /// Address of the instruction that may fault
    pub fault_ip: usize,
    /// Address to jump to when a fault occurs at fault_ip
    pub fixup_ip: usize,
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
        // SAFETY: `i` is within the exception table range
        let entry = unsafe { ptr::read(start.add(i)) };
        if entry.fault_ip == fault_ip {
            return Some(entry.fixup_ip);
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
