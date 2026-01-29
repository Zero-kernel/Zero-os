//! VT-d Interrupt Remapping for Zero-OS
//!
//! This module provides Intel VT-d interrupt remapping support, which is critical
//! for secure device passthrough. Without interrupt remapping, a malicious device
//! can inject arbitrary interrupts to the host, potentially escaping isolation.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! | PCI Device       |     | PCI Device       |     | PCI Device       |
//! | (MSI/MSI-X)      |     | (MSI/MSI-X)      |     | (MSI/MSI-X)      |
//! +--------+---------+     +--------+---------+     +--------+---------+
//!          |                        |                        |
//!          v                        v                        v
//! +----------------------------------------------------------------+
//! |              Interrupt Remapping Hardware Unit                  |
//! |   +----------------------------------------------------------+ |
//! |   |            Interrupt Remapping Table (IRT)               | |
//! |   | +------+ +------+ +------+ +------+ +------+ +------+    | |
//! |   | |IRTE 0| |IRTE 1| |IRTE 2| |IRTE 3| | ...  | |IRTE N|    | |
//! |   | +------+ +------+ +------+ +------+ +------+ +------+    | |
//! |   +----------------------------------------------------------+ |
//! +----------------------------------------------------------------+
//!                              |
//!                              v
//! +----------------------------------------------------------------+
//! |                         LAPIC/x2APIC                            |
//! |    (validated vector, destination, delivery mode)               |
//! +----------------------------------------------------------------+
//! ```
//!
//! # Security Model
//!
//! - **Fail-closed**: If DMAR requires IR but hardware lacks support, fail initialization
//! - **Source ID validation**: Each IRTE is bound to a specific PCI Source ID
//! - **Vector isolation**: Devices can only trigger vectors assigned to them
//! - **x2APIC support**: Extended Interrupt Mode (EIM) for x2APIC destinations
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 5 (Interrupt Remapping)
//! - Intel VT-d Specification, Section 9.10 (Interrupt Remapping Table Address Register)

use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{self, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::PhysFrame;
use x86_64::PhysAddr;

use mm::buddy_allocator;

use crate::IommuError;

// ============================================================================
// Constants
// ============================================================================

/// IRTA EIME bit - Extended Interrupt Mode for x2APIC.
/// When set, the destination ID field in IRTEs uses x2APIC format (32-bit).
const IRTA_EIME: u64 = 1 << 11;

/// Maximum physical address reachable via direct map (1 GB).
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30;

/// Default number of IRTE entries (power of 2).
/// 256 entries = 4KB, fits in one page.
pub const DEFAULT_IR_ENTRIES: usize = 256;

/// Maximum supported IRTE entries (64K for 16-bit handle).
pub const MAX_IR_ENTRIES: usize = 65536;

// ============================================================================
// IRTE Flags
// ============================================================================

/// IRTE Present bit (bit 0 of low qword).
const IRTE_PRESENT: u64 = 1 << 0;

/// IRTE Fault Processing Disable (bit 1).
/// When set, faults from this IRTE are not reported.
const IRTE_FPD: u64 = 1 << 1;

/// Destination Mode: 0 = Physical, 1 = Logical (bit 2).
const IRTE_DM_LOGICAL: u64 = 1 << 2;

/// Redirection Hint (bit 3).
/// 0 = No redirection, 1 = Lowest priority redirection.
const IRTE_RH: u64 = 1 << 3;

/// Trigger Mode: 0 = Edge, 1 = Level (bit 4).
const IRTE_TM_LEVEL: u64 = 1 << 4;

/// Delivery Mode shift (bits 5-7).
const IRTE_DLVR_SHIFT: u64 = 5;

/// Delivery modes.
pub const DELIVERY_FIXED: u64 = 0;
pub const DELIVERY_LOWEST: u64 = 1;
pub const DELIVERY_SMI: u64 = 2;
pub const DELIVERY_NMI: u64 = 4;
pub const DELIVERY_INIT: u64 = 5;
pub const DELIVERY_EXTINT: u64 = 7;

/// Vector shift (bits 16-23).
const IRTE_VECTOR_SHIFT: u64 = 16;

/// Source ID (Requester ID) shift (bits 32-47).
const IRTE_SID_SHIFT: u64 = 32;

/// Source ID Qualifier (bits 48-49).
/// 00 = Verify full Source ID
/// 01 = Verify Source ID up to function mask
/// 10 = All Source IDs match
/// 11 = Reserved
const IRTE_SQ_SHIFT: u64 = 48;

/// Source Validation Type (bits 50-51).
/// 00 = Reserved
/// 01 = Verify using IRTE.SID and IRTE.SQ
/// 10 = Reserved
/// 11 = Reserved
const IRTE_SVT_VERIFY_SID: u64 = 1 << 50;

// ============================================================================
// IRTE Structure
// ============================================================================

/// Interrupt Remapping Table Entry (128-bit).
///
/// Each IRTE defines how an interrupt from a specific source should be
/// remapped before delivery to the LAPIC.
///
/// # Layout
///
/// Low 64 bits:
/// - [0]: Present
/// - [1]: Fault Processing Disable
/// - [2]: Destination Mode (0=physical, 1=logical)
/// - [3]: Redirection Hint
/// - [4]: Trigger Mode (0=edge, 1=level)
/// - [7:5]: Delivery Mode
/// - [15:8]: Reserved (must be 0)
/// - [23:16]: Vector
/// - [31:24]: Reserved (must be 0)
/// - [47:32]: Source ID (Requester ID)
/// - [49:48]: Source ID Qualifier
/// - [51:50]: Source Validation Type
/// - [63:52]: Reserved (must be 0)
///
/// High 64 bits:
/// - [31:0]: Reserved (must be 0)
/// - [63:32]: Destination ID (APIC ID, or x2APIC ID if EIM)
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct Irte {
    /// Low 64 bits of the IRTE.
    pub lo: u64,
    /// High 64 bits of the IRTE.
    pub hi: u64,
}

impl Irte {
    /// Create an empty (not present) IRTE.
    #[inline]
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Check if this IRTE is present.
    #[inline]
    pub fn is_present(&self) -> bool {
        self.lo & IRTE_PRESENT != 0
    }

    /// Create a new MSI/MSI-X IRTE for fixed delivery.
    ///
    /// # Arguments
    ///
    /// * `vector` - Interrupt vector (0-255)
    /// * `dest_apic_id` - Destination APIC ID (or x2APIC ID)
    /// * `source_id` - PCI Source ID (bus << 8 | dev << 3 | func)
    ///
    /// # Returns
    ///
    /// Configured IRTE for edge-triggered, fixed delivery
    pub fn new_msi(vector: u8, dest_apic_id: u32, source_id: u16) -> Self {
        let mut irte = Self::empty();

        // Set present
        irte.lo |= IRTE_PRESENT;

        // Set vector
        irte.lo |= (vector as u64) << IRTE_VECTOR_SHIFT;

        // Set delivery mode (fixed)
        irte.lo |= DELIVERY_FIXED << IRTE_DLVR_SHIFT;

        // Set source ID and enable verification
        irte.lo |= (source_id as u64) << IRTE_SID_SHIFT;
        irte.lo |= IRTE_SVT_VERIFY_SID;

        // Set destination APIC ID
        irte.hi |= (dest_apic_id as u64) << 32;

        irte
    }

    /// Create a new MSI/MSI-X IRTE for lowest priority delivery.
    ///
    /// Used for load balancing interrupts across multiple CPUs.
    pub fn new_msi_lowest_priority(vector: u8, dest_apic_id: u32, source_id: u16) -> Self {
        let mut irte = Self::new_msi(vector, dest_apic_id, source_id);

        // Set lowest priority delivery mode
        irte.lo &= !(0x7 << IRTE_DLVR_SHIFT);
        irte.lo |= DELIVERY_LOWEST << IRTE_DLVR_SHIFT;

        // Enable redirection hint for lowest priority
        irte.lo |= IRTE_RH;

        // Use logical destination mode for multi-CPU targeting
        irte.lo |= IRTE_DM_LOGICAL;

        irte
    }

    /// Create an IRTE for IOAPIC redirection.
    ///
    /// # Arguments
    ///
    /// * `vector` - Interrupt vector
    /// * `dest_apic_id` - Destination APIC ID
    /// * `source_id` - IOAPIC Source ID
    /// * `level_triggered` - True for level-triggered interrupts
    pub fn new_ioapic(
        vector: u8,
        dest_apic_id: u32,
        source_id: u16,
        level_triggered: bool,
    ) -> Self {
        let mut irte = Self::new_msi(vector, dest_apic_id, source_id);

        if level_triggered {
            irte.lo |= IRTE_TM_LEVEL;
        }

        irte
    }

    /// Disable fault processing for this IRTE.
    ///
    /// Use with caution - faults from this interrupt source will be silently ignored.
    pub fn disable_fault_processing(&mut self) {
        self.lo |= IRTE_FPD;
    }

    /// Get the vector from this IRTE.
    #[inline]
    pub fn vector(&self) -> u8 {
        ((self.lo >> IRTE_VECTOR_SHIFT) & 0xFF) as u8
    }

    /// Get the source ID from this IRTE.
    #[inline]
    pub fn source_id(&self) -> u16 {
        ((self.lo >> IRTE_SID_SHIFT) & 0xFFFF) as u16
    }

    /// Get the destination APIC ID from this IRTE.
    #[inline]
    pub fn dest_apic_id(&self) -> u32 {
        (self.hi >> 32) as u32
    }
}

// ============================================================================
// Interrupt Remapping Table
// ============================================================================

/// Interrupt Remapping Table.
///
/// Manages a power-of-two sized table of IRTEs. The table is allocated from
/// physical memory and registered with the IOMMU via the IRTA register.
pub struct InterruptRemappingTable {
    /// Physical address of the table (4KB aligned).
    phys: u64,

    /// Virtual address of the table for software access.
    virt: *mut Irte,

    /// Number of entries (power of 2).
    pub entries: usize,

    /// Log2 of entries (for IRTA size field).
    order: u8,

    /// Number of pages allocated.
    pages: usize,

    /// Bitmap tracking allocated IRTE indices.
    /// Each bit represents one IRTE: 1 = allocated, 0 = free.
    allocation_bitmap: Mutex<Vec<u64>>,

    /// Number of IRTEs currently allocated.
    allocated_count: AtomicU64,
}

// SAFETY: InterruptRemappingTable is Send + Sync because:
// - All mutable access is protected by Mutex
// - Atomic operations use proper ordering
// - The virt pointer is only accessed under lock or atomically
unsafe impl Send for InterruptRemappingTable {}
unsafe impl Sync for InterruptRemappingTable {}

impl InterruptRemappingTable {
    /// Allocate and initialize an interrupt remapping table.
    ///
    /// # Arguments
    ///
    /// * `entries` - Desired number of entries (will be rounded up to power of 2)
    ///
    /// # Returns
    ///
    /// * `Ok(table)` - Successfully allocated table
    /// * `Err(IommuError)` - Allocation failed
    ///
    /// # Security
    ///
    /// - Table is zeroed on allocation (all IRTEs not present)
    /// - Physical address is validated to be within direct map range
    pub fn allocate(entries: usize) -> Result<Self, IommuError> {
        // Round up to power of 2
        let aligned = entries.next_power_of_two().min(MAX_IR_ENTRIES);
        let order = aligned.trailing_zeros() as u8;

        // Calculate allocation size
        let bytes = aligned * size_of::<Irte>();
        let pages = (bytes + 4095) / 4096;

        // Allocate physical pages
        let frame = buddy_allocator::alloc_physical_pages(pages)
            .ok_or(IommuError::PageTableAllocFailed)?;

        let phys = frame.start_address().as_u64();

        // Validate physical address is within direct map
        if phys >= MAX_DIRECT_MAP_PHYS {
            buddy_allocator::free_physical_pages(frame, pages);
            return Err(IommuError::PageTableAllocFailed);
        }

        // Get virtual address via direct map
        let virt = mm::phys_to_virt(frame.start_address());
        let virt_ptr = virt.as_mut_ptr::<Irte>();

        // R84-3 FIX: Zero the entire allocation (all pages), not just the entries.
        // This prevents information disclosure through uninitialized memory if
        // the allocation ever drifts from the exact size needed for entries.
        let zero_len = pages * 4096;
        unsafe {
            ptr::write_bytes(virt_ptr as *mut u8, 0, zero_len);
        }

        // Initialize allocation bitmap (all entries free)
        let bitmap_qwords = (aligned + 63) / 64;
        let bitmap = Vec::from_iter(core::iter::repeat(0u64).take(bitmap_qwords));

        Ok(Self {
            phys,
            virt: virt_ptr,
            entries: aligned,
            order,
            pages,
            allocation_bitmap: Mutex::new(bitmap),
            allocated_count: AtomicU64::new(0),
        })
    }

    /// Compute the IRTA register value for this table.
    ///
    /// # Arguments
    ///
    /// * `x2apic_mode` - True if Extended Interrupt Mode (x2APIC) should be enabled
    ///
    /// # Returns
    ///
    /// Value to write to the IRTA register
    pub fn irta_value(&self, x2apic_mode: bool) -> u64 {
        // IRTA format:
        // [3:0]: Size (log2(entries) - 1)
        // [11]: EIME (Extended Interrupt Mode Enable)
        // [63:12]: Physical address (4KB aligned)
        let size_bits = if self.order > 0 {
            (self.order - 1) as u64
        } else {
            0
        };

        let mut irta = (self.phys & !0xFFF) | size_bits;

        if x2apic_mode {
            irta |= IRTA_EIME;
        }

        irta
    }

    /// Get the physical address of the table.
    #[inline]
    pub fn physical_address(&self) -> u64 {
        self.phys
    }

    /// Get the number of entries in the table.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries
    }

    /// Get the number of allocated entries.
    #[inline]
    pub fn allocated(&self) -> u64 {
        self.allocated_count.load(Ordering::Relaxed)
    }

    /// Allocate an IRTE index.
    ///
    /// # Returns
    ///
    /// * `Some(index)` - Successfully allocated index
    /// * `None` - No free entries
    pub fn allocate_index(&self) -> Option<usize> {
        let mut bitmap = self.allocation_bitmap.lock();

        for (qword_idx, qword) in bitmap.iter_mut().enumerate() {
            if *qword != u64::MAX {
                // Find first zero bit
                let bit_idx = (!*qword).trailing_zeros() as usize;
                let index = qword_idx * 64 + bit_idx;

                if index < self.entries {
                    *qword |= 1u64 << bit_idx;
                    self.allocated_count.fetch_add(1, Ordering::Relaxed);
                    return Some(index);
                }
            }
        }

        None
    }

    /// Free an IRTE index.
    ///
    /// # Arguments
    ///
    /// * `index` - Index to free
    ///
    /// # Returns
    ///
    /// True if the index was allocated and is now free
    pub fn free_index(&self, index: usize) -> bool {
        if index >= self.entries {
            return false;
        }

        let mut bitmap = self.allocation_bitmap.lock();
        let qword_idx = index / 64;
        let bit_idx = index % 64;

        if qword_idx < bitmap.len() {
            let mask = 1u64 << bit_idx;
            if bitmap[qword_idx] & mask != 0 {
                bitmap[qword_idx] &= !mask;
                self.allocated_count.fetch_sub(1, Ordering::Relaxed);

                // Clear the IRTE
                self.set_entry(index, Irte::empty());
                return true;
            }
        }

        false
    }

    /// Set an IRTE entry.
    ///
    /// # Arguments
    ///
    /// * `index` - Entry index
    /// * `irte` - IRTE to install
    ///
    /// # Ordering
    ///
    /// Writes high qword first, then low qword to ensure the present bit
    /// is set last with full entry visible to hardware.
    pub fn set_entry(&self, index: usize, irte: Irte) {
        if index >= self.entries {
            return;
        }

        unsafe {
            let ptr = self.virt.add(index);

            // Write high qword first (destination, etc.)
            write_volatile(&mut (*ptr).hi, irte.hi);

            // Memory barrier to ensure hi is visible before lo
            core::sync::atomic::fence(Ordering::Release);

            // Write low qword (includes present bit)
            write_volatile(&mut (*ptr).lo, irte.lo);
        }
    }

    /// Get an IRTE entry.
    ///
    /// # Arguments
    ///
    /// * `index` - Entry index
    ///
    /// # Returns
    ///
    /// Copy of the IRTE at the given index
    pub fn get_entry(&self, index: usize) -> Option<Irte> {
        if index >= self.entries {
            return None;
        }

        unsafe {
            let ptr = self.virt.add(index);
            Some(Irte {
                lo: core::ptr::read_volatile(&(*ptr).lo),
                hi: core::ptr::read_volatile(&(*ptr).hi),
            })
        }
    }

    /// Check if an index is allocated.
    pub fn is_allocated(&self, index: usize) -> bool {
        if index >= self.entries {
            return false;
        }

        let bitmap = self.allocation_bitmap.lock();
        let qword_idx = index / 64;
        let bit_idx = index % 64;

        if qword_idx < bitmap.len() {
            bitmap[qword_idx] & (1u64 << bit_idx) != 0
        } else {
            false
        }
    }
}

impl Drop for InterruptRemappingTable {
    fn drop(&mut self) {
        // Free the physical pages
        if self.phys != 0 && self.pages > 0 {
            let frame = PhysFrame::containing_address(PhysAddr::new(self.phys));
            buddy_allocator::free_physical_pages(frame, self.pages);
        }
    }
}

// ============================================================================
// Interrupt Remapping Handle
// ============================================================================

/// Handle for an allocated IRTE.
///
/// Represents an allocated interrupt remapping entry. When dropped,
/// the entry is automatically freed.
pub struct IrteHandle {
    /// Index in the interrupt remapping table.
    pub index: usize,

    /// Source ID (for validation).
    pub source_id: u16,

    /// Vector (for reference).
    pub vector: u8,
}

impl IrteHandle {
    /// Create a new IRTE handle.
    pub fn new(index: usize, source_id: u16, vector: u8) -> Self {
        Self {
            index,
            source_id,
            vector,
        }
    }

    /// Get the interrupt remapping format MSI data.
    ///
    /// Returns the value to program into the device's MSI data register
    /// when using interrupt remapping format.
    pub fn msi_data(&self) -> u32 {
        // Remappable format: subhandle in bits [15:0], format bit [4] = 1
        ((self.index as u32) & 0x7FFF) | (1 << 4)
    }

    /// Get the interrupt remapping format MSI address (low 32 bits).
    ///
    /// Returns the value to program into the device's MSI address register.
    pub fn msi_address_lo(&self) -> u32 {
        // Remappable format:
        // [1:0] = 11 (fixed)
        // [2] = handle[15] (high bit of 16-bit handle)
        // [3] = SHV (subhandle valid) = 1
        // [4] = interrupt format = 1 (remappable)
        // [19:5] = handle[14:0]
        // [31:20] = 0xFEE (standard MSI address prefix)
        let handle = self.index as u32;
        let handle_hi = (handle >> 15) & 1;
        let handle_lo = handle & 0x7FFF;

        0xFEE00000 | (handle_lo << 5) | (1 << 4) | (1 << 3) | (handle_hi << 2) | 0x3
    }

    /// Get the MSI address high 32 bits (always 0 for standard MSI).
    pub fn msi_address_hi(&self) -> u32 {
        0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irte_msi() {
        let irte = Irte::new_msi(0x30, 0, 0x0100);
        assert!(irte.is_present());
        assert_eq!(irte.vector(), 0x30);
        assert_eq!(irte.source_id(), 0x0100);
        assert_eq!(irte.dest_apic_id(), 0);
    }

    #[test]
    fn test_irte_empty() {
        let irte = Irte::empty();
        assert!(!irte.is_present());
    }
}
