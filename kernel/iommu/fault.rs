//! VT-d Fault Handling and Recovery for Zero-OS
//!
//! This module provides IOMMU fault detection, logging, and device isolation
//! capabilities. DMA faults indicate potential security issues such as:
//! - Misconfigured device drivers
//! - Malicious devices attempting to access unauthorized memory
//! - Translation table corruption
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |   DMA Request    |
//! +--------+---------+
//!          |
//!          v
//! +------------------+     Fault
//! |   VT-d IOMMU     |------------+
//! | (Translation)    |            |
//! +--------+---------+            |
//!          |                      v
//!          | Success     +------------------+
//!          v             | Fault Recording  |
//! +------------------+   | Registers (FRCD) |
//! | Physical Memory  |   +------------------+
//! +------------------+            |
//!                                 v
//!                        +------------------+
//!                        | Fault Handler    |
//!                        | - Log to audit   |
//!                        | - Isolate device |
//!                        +------------------+
//! ```
//!
//! # Security Model
//!
//! - **Audit logging**: All faults are logged with device ID, domain, address
//! - **Device isolation**: Option to disable bus mastering on faulting device
//! - **Bounded processing**: Maximum 16 fault records per handler invocation
//! - **Fail-closed**: Faults default to audit + warn, optionally isolate
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 7 (Fault Logging)
//! - Intel VT-d Specification, Section 10.4.7 (Fault Recording Registers)

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of fault records to read per handler invocation.
/// This bounds processing time and prevents DoS from fault floods.
pub const MAX_FAULT_RECORDS: usize = 16;

/// Fault Recording entry size (128 bits = 16 bytes).
const FRCD_ENTRY_SIZE: usize = 16;

/// Fault Status Register - Primary Fault Overflow (PFO) bit.
const FSTS_PFO: u32 = 1 << 0;

/// Fault Status Register - Primary Pending Fault (PPF) bit.
const FSTS_PPF: u32 = 1 << 1;

/// Fault Status Register - Fault Record Index mask (bits 15:8).
const FSTS_FRI_MASK: u32 = 0xFF << 8;
const FSTS_FRI_SHIFT: u32 = 8;

/// Fault Event Control Register - Interrupt Mask (IM) bit.
const FECTL_IM: u32 = 1 << 31;

// ============================================================================
// Fault Record Structure
// ============================================================================

/// VT-d fault reason codes.
///
/// These correspond to the FR (Fault Reason) field in fault recording registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// Reserved or unknown fault code.
    Reserved,
    /// Root table entry not present.
    RootEntryNotPresent,
    /// Context entry not present.
    ContextEntryNotPresent,
    /// Context entry invalid.
    ContextEntryInvalid,
    /// Address beyond MGAW (Maximum Guest Address Width).
    AddressBeyondMgaw,
    /// Write request to read-only page.
    WriteToReadOnly,
    /// Read request to no-read page.
    ReadNotPermitted,
    /// Page table entry invalid.
    PageEntryInvalid,
    /// Root table entry reserved bit set.
    RootEntryReserved,
    /// Context entry reserved bit set.
    ContextEntryReserved,
    /// Page table entry reserved bit set.
    PageEntryReserved,
    /// Invalid translation type.
    InvalidTranslationType,
    /// Unknown fault reason.
    Unknown(u8),
}

impl FaultReason {
    /// Decode fault reason from hardware code.
    pub fn from_code(code: u8) -> Self {
        match code {
            0x0 => Self::Reserved,
            0x1 => Self::RootEntryNotPresent,
            0x2 => Self::ContextEntryNotPresent,
            0x3 => Self::ContextEntryInvalid,
            0x4 => Self::AddressBeyondMgaw,
            0x5 => Self::WriteToReadOnly,
            0x6 => Self::ReadNotPermitted,
            0x7 => Self::PageEntryInvalid,
            0x8 => Self::RootEntryReserved,
            0x9 => Self::ContextEntryReserved,
            0xA => Self::PageEntryReserved,
            0xB => Self::InvalidTranslationType,
            other => Self::Unknown(other),
        }
    }

    /// Check if this fault indicates a potential security issue.
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::WriteToReadOnly
                | Self::ReadNotPermitted
                | Self::AddressBeyondMgaw
                | Self::InvalidTranslationType
        )
    }
}

/// Fault type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// Primary (DMA) fault.
    Primary,
    /// Page request fault (ATS).
    PageRequest,
    /// Interrupt remapping fault.
    InterruptRemap,
    /// Unknown fault type.
    Unknown(u8),
}

impl FaultType {
    /// Decode fault type from hardware code.
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Primary,
            1 => Self::PageRequest,
            2 => Self::InterruptRemap,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed VT-d fault record.
///
/// Contains all relevant information extracted from a fault recording register.
#[derive(Debug, Clone, Copy)]
pub struct FaultRecord {
    /// PCI Source ID (bus << 8 | device << 3 | function).
    pub source_id: u16,
    /// Domain ID associated with the fault.
    pub domain_id: u16,
    /// Fault reason code.
    pub fault_reason: FaultReason,
    /// Faulting address (page-aligned).
    pub fault_address: u64,
    /// Fault type (Primary, PageRequest, InterruptRemap).
    pub fault_type: FaultType,
    /// Whether this was a read (false) or write (true) request.
    pub is_write: bool,
    /// Whether the request was an execute request.
    pub is_execute: bool,
    /// Pasid present (for scalable mode).
    pub pasid_present: bool,
    /// PASID value (if present).
    pub pasid: u32,
}

impl FaultRecord {
    /// Get the PCI bus number from source ID.
    #[inline]
    pub fn bus(&self) -> u8 {
        (self.source_id >> 8) as u8
    }

    /// Get the PCI device number from source ID.
    #[inline]
    pub fn device(&self) -> u8 {
        ((self.source_id >> 3) & 0x1F) as u8
    }

    /// Get the PCI function number from source ID.
    #[inline]
    pub fn function(&self) -> u8 {
        (self.source_id & 0x7) as u8
    }

    /// Format as BDF string for logging.
    pub fn bdf_string(&self) -> ([u8; 10], usize) {
        let mut buf = [0u8; 10];
        let bus = self.bus();
        let device_num = self.device();
        let func = self.function();

        buf[0] = hex_char((bus >> 4) & 0xF);
        buf[1] = hex_char(bus & 0xF);
        buf[2] = b':';
        buf[3] = hex_char((device_num >> 4) & 0xF);
        buf[4] = hex_char(device_num & 0xF);
        buf[5] = b'.';
        buf[6] = hex_char(func & 0xF);

        (buf, 7)
    }
}

/// Convert nibble to hex character.
fn hex_char(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

// ============================================================================
// Fault Handler Implementation
// ============================================================================

/// Fault handler configuration.
#[derive(Debug, Clone, Copy)]
pub struct FaultConfig {
    /// Whether to isolate (disable bus mastering) faulting devices.
    pub isolate_devices: bool,
    /// Whether to log faults to audit subsystem.
    pub audit_logging: bool,
    /// Whether to print faults to console.
    pub console_logging: bool,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            isolate_devices: false,
            audit_logging: true,
            console_logging: true,
        }
    }
}

/// Read fault records from VT-d hardware.
///
/// # Arguments
///
/// * `reg_base` - VT-d register base address
/// * `fault_offset` - Offset to fault recording registers (from CAP.FRO)
/// * `num_fault_regs` - Number of fault recording registers (from CAP.NFR)
/// * `start_index` - Starting index from FRI (Fault Record Index)
///
/// # Returns
///
/// Vector of parsed fault records (bounded to MAX_FAULT_RECORDS).
///
/// # Safety
///
/// Caller must ensure `reg_base` and `fault_offset` are valid MMIO addresses.
///
/// # Security
///
/// R85-1 FIX: Use FRI-based rotation to avoid silently losing faults beyond index 15.
/// R85-2 FIX: Use checked arithmetic to avoid MMIO pointer wrapping on malformed DMAR.
pub unsafe fn read_fault_records(
    reg_base: u64,
    fault_offset: usize,
    num_fault_regs: usize,
    start_index: usize,
) -> Vec<FaultRecord> {
    // R85-2: Validate inputs to prevent wraparound attacks from malformed DMAR
    if num_fault_regs == 0 {
        return Vec::new();
    }

    let mut records = Vec::new();
    let max_records = num_fault_regs.min(MAX_FAULT_RECORDS);

    // R85-1: Start from FRI and wrap around the fault record ring buffer
    let mut idx = start_index % num_fault_regs;

    for _ in 0..max_records {
        // R85-2: Use checked arithmetic to avoid MMIO pointer wrapping
        let entry_base = match reg_base
            .checked_add(fault_offset as u64)
            .and_then(|base| base.checked_add((idx * FRCD_ENTRY_SIZE) as u64))
        {
            Some(addr) => addr,
            None => {
                // Overflow detected - likely malformed DMAR table
                break;
            }
        };

        // Read 128-bit fault record (two 64-bit reads)
        let lo = read_volatile(entry_base as *const u64);
        let hi = read_volatile((entry_base + 8) as *const u64);

        // Check F (Fault) bit - bit 127 of the record (bit 63 of hi)
        if hi & (1 << 63) == 0 {
            // Advance to next entry even if this one has no fault
            idx = (idx + 1) % num_fault_regs;
            continue;
        }

        // Parse fault record fields per VT-d spec section 10.4.7
        //
        // Low 64 bits:
        //   [11:0]  - Reserved
        //   [63:12] - Fault Info (FI) - page-aligned fault address
        //
        // High 64 bits:
        //   [15:0]  - Source ID (SID)
        //   [20:16] - Reserved
        //   [21]    - T2 (Type bit 2)
        //   [22]    - PRIV
        //   [23]    - EXE
        //   [24]    - PP (PASID Present)
        //   [27:25] - Reserved
        //   [29:28] - T1:T0 (Type bits 1:0)
        //   [31:30] - AT (Address Type)
        //   [51:32] - PASID
        //   [59:52] - FR (Fault Reason)
        //   [62:60] - Reserved
        //   [63]    - F (Fault) - already checked above

        let fault_address = lo & !0xFFF; // Page-aligned
        let source_id = (hi & 0xFFFF) as u16;
        let is_execute = (hi >> 23) & 1 != 0;
        let pasid_present = (hi >> 24) & 1 != 0;
        let fault_type_bits = ((hi >> 28) & 0x3) | (((hi >> 21) & 1) << 2);
        let pasid = ((hi >> 32) & 0xFFFFF) as u32;
        let fault_reason_code = ((hi >> 52) & 0xFF) as u8;

        // Domain ID is derived from context entry, not directly in fault record
        // For now, set to 0 and let caller look up from attached_devices
        let domain_id = 0u16;

        // Determine if write based on fault reason
        let is_write = matches!(
            FaultReason::from_code(fault_reason_code),
            FaultReason::WriteToReadOnly
        );

        records.push(FaultRecord {
            source_id,
            domain_id,
            fault_reason: FaultReason::from_code(fault_reason_code),
            fault_address,
            fault_type: FaultType::from_code(fault_type_bits as u8),
            is_write,
            is_execute,
            pasid_present,
            pasid,
        });

        // Clear the fault by writing 1 to F bit (W1C)
        write_volatile((entry_base + 8) as *mut u64, 1 << 63);

        // Advance to next entry (circular buffer)
        idx = (idx + 1) % num_fault_regs;
    }

    records
}

/// Read and clear fault status register.
///
/// # Arguments
///
/// * `reg_base` - VT-d register base address
///
/// # Returns
///
/// Tuple of (overflow_occurred, pending_fault, fault_record_index)
///
/// # Safety
///
/// Caller must ensure `reg_base` is a valid MMIO address.
///
/// # Security
///
/// R85-3 FIX: Clear FRI bits along with PFO/PPF to prevent stale index retriggering.
pub unsafe fn read_and_clear_fault_status(reg_base: u64) -> (bool, bool, u8) {
    const VTD_REG_FSTS: usize = 0x34;

    let status = read_volatile((reg_base + VTD_REG_FSTS as u64) as *const u32);

    let overflow = status & FSTS_PFO != 0;
    let pending = status & FSTS_PPF != 0;
    let fri = ((status & FSTS_FRI_MASK) >> FSTS_FRI_SHIFT) as u8;

    // R85-3: Clear all W1C status bits including FRI to prevent stale indices
    // from retriggering interrupts or masking new faults
    let clear_mask = status & (FSTS_PFO | FSTS_PPF | FSTS_FRI_MASK);
    if clear_mask != 0 {
        write_volatile(
            (reg_base + VTD_REG_FSTS as u64) as *mut u32,
            clear_mask,
        );
    }

    (overflow, pending, fri)
}

/// Enable or disable fault event interrupts.
///
/// # Arguments
///
/// * `reg_base` - VT-d register base address
/// * `enable` - true to enable interrupts, false to disable
///
/// # Safety
///
/// Caller must ensure `reg_base` is a valid MMIO address.
pub unsafe fn set_fault_interrupt_enabled(reg_base: u64, enable: bool) {
    const VTD_REG_FECTL: usize = 0x38;

    let mut ctl = read_volatile((reg_base + VTD_REG_FECTL as u64) as *const u32);

    if enable {
        ctl &= !FECTL_IM; // Clear interrupt mask
    } else {
        ctl |= FECTL_IM; // Set interrupt mask
    }

    write_volatile((reg_base + VTD_REG_FECTL as u64) as *mut u32, ctl);
}

/// Log a fault record to the kernel console.
pub fn log_fault_to_console(record: &FaultRecord, unit_index: usize) {
    let (bdf, _len) = record.bdf_string();
    let bdf_str = core::str::from_utf8(&bdf[..7]).unwrap_or("??:??.?");

    kprintln!(
        "[IOMMU] Unit {}: DMA fault from {} addr={:#x} reason={:?} type={:?}{}{}",
        unit_index,
        bdf_str,
        record.fault_address,
        record.fault_reason,
        record.fault_type,
        if record.is_write { " [W]" } else { " [R]" },
        if record.fault_reason.is_security_relevant() {
            " [SECURITY]"
        } else {
            ""
        }
    );
}

/// Log a fault record to the audit subsystem.
#[cfg(feature = "audit")]
pub fn log_fault_to_audit(record: &FaultRecord, unit_index: usize) {
    use audit::{emit_security_event, AuditEventType, AuditSecurityClass};

    emit_security_event(
        AuditEventType::IommuFault,
        AuditSecurityClass::DmaViolation,
        record.source_id as u64,
        record.fault_address,
        unit_index as u64,
    );
}

#[cfg(not(feature = "audit"))]
pub fn log_fault_to_audit(_record: &FaultRecord, _unit_index: usize) {
    // Audit disabled at compile time
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_reason_decode() {
        assert_eq!(
            FaultReason::from_code(0x1),
            FaultReason::RootEntryNotPresent
        );
        assert_eq!(
            FaultReason::from_code(0x5),
            FaultReason::WriteToReadOnly
        );
        assert!(matches!(FaultReason::from_code(0xFF), FaultReason::Unknown(0xFF)));
    }

    #[test]
    fn test_fault_record_bdf() {
        let record = FaultRecord {
            source_id: 0x1234, // bus=0x12, dev=0x06, func=0x4
            domain_id: 0,
            fault_reason: FaultReason::WriteToReadOnly,
            fault_address: 0x1000,
            fault_type: FaultType::Primary,
            is_write: true,
            is_execute: false,
            pasid_present: false,
            pasid: 0,
        };

        assert_eq!(record.bus(), 0x12);
        assert_eq!(record.device(), 0x06);
        assert_eq!(record.function(), 0x04);
    }

    #[test]
    fn test_security_relevant() {
        assert!(FaultReason::WriteToReadOnly.is_security_relevant());
        assert!(FaultReason::AddressBeyondMgaw.is_security_relevant());
        assert!(!FaultReason::RootEntryNotPresent.is_security_relevant());
    }
}
