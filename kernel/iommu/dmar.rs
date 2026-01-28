//! ACPI DMAR (DMA Remapping) Table Parser
//!
//! Parses the DMAR table from ACPI to discover IOMMU hardware units and their
//! associated device scopes.
//!
//! # DMAR Table Structure
//!
//! The DMAR table contains:
//! - Header (standard ACPI header + host address width + flags)
//! - Remapping structures:
//!   - DRHD (DMA Remapping Hardware Unit Definition)
//!   - RMRR (Reserved Memory Region Reporting)
//!   - ATSR (ACPI Namespace Device Declaration)
//!   - RHSA (Remapping Hardware Status Affinity)
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 8 (BIOS Considerations)
//! - ACPI Specification, Section 8 (DMAR)

use alloc::vec::Vec;
use core::ptr;

// ============================================================================
// Constants
// ============================================================================

/// DMAR table signature ("DMAR").
const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// DRHD structure type.
const DMAR_TYPE_DRHD: u16 = 0;

/// RMRR structure type.
const DMAR_TYPE_RMRR: u16 = 1;

/// ATSR structure type.
const DMAR_TYPE_ATSR: u16 = 2;

/// RHSA structure type.
const DMAR_TYPE_RHSA: u16 = 3;

/// ANDD structure type (ACPI Namespace Device Declaration).
const DMAR_TYPE_ANDD: u16 = 4;

/// Device scope entry type: PCI Endpoint Device.
const DEVICE_SCOPE_PCI_ENDPOINT: u8 = 0x01;

/// Device scope entry type: PCI Sub-hierarchy (bridge).
const DEVICE_SCOPE_PCI_BRIDGE: u8 = 0x02;

/// Device scope entry type: IOAPIC.
const DEVICE_SCOPE_IOAPIC: u8 = 0x03;

/// Device scope entry type: MSI Capable HPET.
const DEVICE_SCOPE_HPET: u8 = 0x04;

/// Device scope entry type: ACPI Namespace Device.
const DEVICE_SCOPE_ACPI_NAMESPACE: u8 = 0x05;

// ============================================================================
// Errors
// ============================================================================

/// DMAR parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// DMAR table not found in ACPI.
    NotFound,
    /// Invalid DMAR table signature.
    InvalidSignature,
    /// Invalid DMAR table checksum.
    InvalidChecksum,
    /// Invalid DMAR table structure.
    InvalidStructure,
    /// Unsupported DMAR table version.
    UnsupportedVersion,
}

// ============================================================================
// Raw Structures (packed for ACPI table parsing)
// ============================================================================

/// ACPI standard table header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AcpiHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// DMAR table header (after ACPI header).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DmarHeader {
    /// Host Address Width (number of bits - 1).
    host_address_width: u8,
    /// Flags.
    flags: u8,
    /// Reserved.
    reserved: [u8; 10],
}

/// DMAR remapping structure header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DmarStructureHeader {
    /// Structure type.
    structure_type: u16,
    /// Structure length.
    length: u16,
}

/// DRHD (DMA Remapping Hardware Unit Definition) structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DrhdRaw {
    header: DmarStructureHeader,
    /// Flags (bit 0: INCLUDE_PCI_ALL).
    flags: u8,
    /// Reserved.
    reserved: u8,
    /// PCI segment number.
    segment: u16,
    /// Register base address.
    register_base: u64,
    // Followed by device scope entries
}

/// RMRR (Reserved Memory Region Reporting) structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct RmrrRaw {
    header: DmarStructureHeader,
    /// Reserved.
    reserved: u16,
    /// PCI segment number.
    segment: u16,
    /// Reserved memory region base address.
    base_address: u64,
    /// Reserved memory region limit address.
    limit_address: u64,
    // Followed by device scope entries
}

/// Device scope entry.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DeviceScopeRaw {
    /// Device scope type.
    scope_type: u8,
    /// Length of this entry.
    length: u8,
    /// Reserved.
    reserved: u16,
    /// Enumeration ID (for IOAPIC/HPET).
    enumeration_id: u8,
    /// Start bus number.
    start_bus: u8,
    // Followed by path entries (device:function pairs)
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// Parsed DMAR table.
pub struct DmarTable {
    /// Host address width (number of address bits supported).
    host_address_width: u8,
    /// Whether interrupt remapping is required.
    interrupt_remap_required: bool,
    /// Whether x2APIC mode requires opt-in.
    x2apic_opt_out: bool,
    /// DRHD (DMA Remapping Hardware Unit) entries.
    drhd_entries: Vec<DrhdEntry>,
    /// RMRR (Reserved Memory Region) entries.
    rmrr_entries: Vec<RmrrEntry>,
}

/// DRHD (DMA Remapping Hardware Unit Definition) entry.
pub struct DrhdEntry {
    /// Whether this unit handles all PCI devices not in other units' scope.
    include_pci_all: bool,
    /// PCI segment number.
    segment: u16,
    /// Register base physical address.
    register_base: u64,
    /// Device scopes handled by this unit.
    device_scopes: Vec<DeviceScope>,
}

/// RMRR (Reserved Memory Region) entry.
pub struct RmrrEntry {
    /// PCI segment number.
    segment: u16,
    /// Reserved region base address (physical).
    base_address: u64,
    /// Reserved region limit address (physical).
    limit_address: u64,
    /// Devices that may DMA to this region.
    device_scopes: Vec<DeviceScope>,
}

/// Device scope entry.
#[derive(Debug, Clone)]
pub struct DeviceScope {
    /// Scope type.
    pub scope_type: DeviceScopeType,
    /// Start bus number.
    pub start_bus: u8,
    /// Path to device (series of device:function pairs).
    pub path: Vec<(u8, u8)>,
}

/// Device scope type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceScopeType {
    /// PCI endpoint device.
    PciEndpoint,
    /// PCI-to-PCI bridge (sub-hierarchy).
    PciBridge,
    /// IOAPIC.
    Ioapic(u8), // enumeration ID
    /// HPET.
    Hpet(u8), // enumeration ID
    /// ACPI namespace device.
    AcpiNamespace,
}

// ============================================================================
// Implementation
// ============================================================================

impl DmarTable {
    /// Get host address width (number of address bits).
    pub fn host_address_width(&self) -> u8 {
        self.host_address_width + 1
    }

    /// Check if interrupt remapping is required.
    pub fn interrupt_remap_required(&self) -> bool {
        self.interrupt_remap_required
    }

    /// Get number of DRHD units.
    pub fn drhd_count(&self) -> usize {
        self.drhd_entries.len()
    }

    /// Get number of RMRR regions.
    pub fn rmrr_count(&self) -> usize {
        self.rmrr_entries.len()
    }

    /// Iterate over DRHD entries.
    pub fn drhd_iter(&self) -> impl Iterator<Item = &DrhdEntry> {
        self.drhd_entries.iter()
    }

    /// Iterate over RMRR entries.
    pub fn rmrr_iter(&self) -> impl Iterator<Item = &RmrrEntry> {
        self.rmrr_entries.iter()
    }
}

impl DrhdEntry {
    /// Check if this unit handles all PCI devices.
    pub fn include_pci_all(&self) -> bool {
        self.include_pci_all
    }

    /// Get PCI segment number.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Get register base address.
    pub fn register_base(&self) -> u64 {
        self.register_base
    }

    /// Get device scopes.
    pub fn device_scopes(&self) -> &[DeviceScope] {
        &self.device_scopes
    }

    /// Check if this unit handles a specific device.
    pub fn handles_device(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.include_pci_all {
            return true;
        }

        for scope in &self.device_scopes {
            if scope.matches_device(bus, device, function) {
                return true;
            }
        }

        false
    }
}

impl RmrrEntry {
    /// Get PCI segment number.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Get base address.
    pub fn base(&self) -> u64 {
        self.base_address
    }

    /// Get limit address.
    pub fn limit(&self) -> u64 {
        self.limit_address
    }

    /// Get size in bytes.
    pub fn size(&self) -> u64 {
        self.limit_address - self.base_address + 1
    }
}

impl DeviceScope {
    /// Check if this scope matches a specific device.
    pub fn matches_device(&self, bus: u8, device: u8, function: u8) -> bool {
        // For PCI endpoint, the path must lead to exactly this device
        // For PCI bridge, all devices under the bridge are included
        if self.path.is_empty() {
            return false;
        }

        // Walk the path from start_bus
        let mut current_bus = self.start_bus;

        // For endpoint, check if path leads to exact device
        if matches!(self.scope_type, DeviceScopeType::PciEndpoint) {
            if let Some(&(last_dev, last_fn)) = self.path.last() {
                // TODO: Proper path walking through bridges
                return current_bus == bus && last_dev == device && last_fn == function;
            }
        }

        // For bridge, check if device is under this bridge hierarchy
        if matches!(self.scope_type, DeviceScopeType::PciBridge) {
            // TODO: Implement bridge sub-hierarchy checking
            return false;
        }

        false
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse the DMAR table from ACPI.
///
/// This function searches for the DMAR table in ACPI and parses its contents.
///
/// # Returns
///
/// * `Ok(DmarTable)` - Successfully parsed DMAR table
/// * `Err(DmarError)` - Parsing failed
pub fn parse_dmar_table() -> Result<DmarTable, DmarError> {
    // Find DMAR table in ACPI
    let table_ptr = find_dmar_table()?;

    unsafe { parse_dmar_at(table_ptr) }
}

/// Find the DMAR table in ACPI tables.
fn find_dmar_table() -> Result<*const u8, DmarError> {
    // TODO: Implement proper ACPI table discovery
    // For now, search known locations or use bootloader-provided ACPI info
    //
    // In a real implementation:
    // 1. Find RSDP (Root System Description Pointer)
    // 2. Parse RSDT or XSDT to find DMAR table
    //
    // For QEMU with intel-iommu=on, DMAR is present in ACPI tables

    // Placeholder: Search for DMAR in ACPI table area
    // This needs proper ACPI infrastructure
    Err(DmarError::NotFound)
}

/// Parse DMAR table at a given physical address.
///
/// # Safety
///
/// The caller must ensure the pointer is valid and points to a properly
/// mapped DMAR table.
unsafe fn parse_dmar_at(table_ptr: *const u8) -> Result<DmarTable, DmarError> {
    // Read ACPI header
    let acpi_header = ptr::read_unaligned(table_ptr as *const AcpiHeader);

    // Verify signature
    if acpi_header.signature != DMAR_SIGNATURE {
        return Err(DmarError::InvalidSignature);
    }

    // Verify checksum
    let table_len = acpi_header.length as usize;
    if !verify_checksum(table_ptr, table_len) {
        return Err(DmarError::InvalidChecksum);
    }

    // Read DMAR-specific header
    let dmar_header_ptr = table_ptr.add(core::mem::size_of::<AcpiHeader>());
    let dmar_header = ptr::read_unaligned(dmar_header_ptr as *const DmarHeader);

    let mut dmar = DmarTable {
        host_address_width: dmar_header.host_address_width,
        interrupt_remap_required: (dmar_header.flags & 0x01) != 0,
        x2apic_opt_out: (dmar_header.flags & 0x02) != 0,
        drhd_entries: Vec::new(),
        rmrr_entries: Vec::new(),
    };

    // Parse remapping structures
    let structures_start = table_ptr
        .add(core::mem::size_of::<AcpiHeader>())
        .add(core::mem::size_of::<DmarHeader>());
    let table_end = table_ptr.add(table_len);

    let mut current = structures_start;
    while (current as usize) < (table_end as usize) {
        // Bounds check: ensure we can read the header
        if (current as usize)
            .checked_add(core::mem::size_of::<DmarStructureHeader>())
            .ok_or(DmarError::InvalidStructure)?
            > (table_end as usize)
        {
            return Err(DmarError::InvalidStructure);
        }

        let header = ptr::read_unaligned(current as *const DmarStructureHeader);

        // Validate structure length
        if (header.length as usize) < core::mem::size_of::<DmarStructureHeader>() {
            return Err(DmarError::InvalidStructure);
        }

        // Bounds check: ensure structure fits within table
        let remaining = (table_end as usize).saturating_sub(current as usize);
        if header.length as usize > remaining {
            return Err(DmarError::InvalidStructure);
        }

        match header.structure_type {
            DMAR_TYPE_DRHD => {
                let entry = parse_drhd(current, header.length)?;
                dmar.drhd_entries.push(entry);
            }
            DMAR_TYPE_RMRR => {
                let entry = parse_rmrr(current, header.length)?;
                dmar.rmrr_entries.push(entry);
            }
            DMAR_TYPE_ATSR | DMAR_TYPE_RHSA | DMAR_TYPE_ANDD => {
                // Skip these structure types for now
            }
            _ => {
                // Unknown structure type, skip
            }
        }

        current = current.add(header.length as usize);
    }

    Ok(dmar)
}

/// Parse a DRHD structure.
unsafe fn parse_drhd(ptr: *const u8, length: u16) -> Result<DrhdEntry, DmarError> {
    if (length as usize) < core::mem::size_of::<DrhdRaw>() {
        return Err(DmarError::InvalidStructure);
    }

    let drhd = ptr::read_unaligned(ptr as *const DrhdRaw);

    let device_scopes = parse_device_scopes(
        ptr.add(core::mem::size_of::<DrhdRaw>()),
        length as usize - core::mem::size_of::<DrhdRaw>(),
    )?;

    Ok(DrhdEntry {
        include_pci_all: (drhd.flags & 0x01) != 0,
        segment: drhd.segment,
        register_base: drhd.register_base,
        device_scopes,
    })
}

/// Parse an RMRR structure.
unsafe fn parse_rmrr(ptr: *const u8, length: u16) -> Result<RmrrEntry, DmarError> {
    if (length as usize) < core::mem::size_of::<RmrrRaw>() {
        return Err(DmarError::InvalidStructure);
    }

    let rmrr = ptr::read_unaligned(ptr as *const RmrrRaw);

    let device_scopes = parse_device_scopes(
        ptr.add(core::mem::size_of::<RmrrRaw>()),
        length as usize - core::mem::size_of::<RmrrRaw>(),
    )?;

    Ok(RmrrEntry {
        segment: rmrr.segment,
        base_address: rmrr.base_address,
        limit_address: rmrr.limit_address,
        device_scopes,
    })
}

/// Parse device scope entries.
unsafe fn parse_device_scopes(ptr: *const u8, remaining: usize) -> Result<Vec<DeviceScope>, DmarError> {
    let mut scopes = Vec::new();
    let mut current = ptr;
    let end = ptr.add(remaining);

    while (current as usize) < (end as usize) {
        // Bounds check: ensure we can read the scope header
        if (current as usize)
            .checked_add(core::mem::size_of::<DeviceScopeRaw>())
            .ok_or(DmarError::InvalidStructure)?
            > (end as usize)
        {
            return Err(DmarError::InvalidStructure);
        }

        let scope = ptr::read_unaligned(current as *const DeviceScopeRaw);

        // Validate scope length
        if (scope.length as usize) < core::mem::size_of::<DeviceScopeRaw>() {
            return Err(DmarError::InvalidStructure);
        }

        // Bounds check: ensure scope fits within remaining data
        let available = (end as usize).saturating_sub(current as usize);
        let scope_len = scope.length as usize;
        if scope_len > available {
            return Err(DmarError::InvalidStructure);
        }

        let scope_type = match scope.scope_type {
            DEVICE_SCOPE_PCI_ENDPOINT => DeviceScopeType::PciEndpoint,
            DEVICE_SCOPE_PCI_BRIDGE => DeviceScopeType::PciBridge,
            DEVICE_SCOPE_IOAPIC => DeviceScopeType::Ioapic(scope.enumeration_id),
            DEVICE_SCOPE_HPET => DeviceScopeType::Hpet(scope.enumeration_id),
            DEVICE_SCOPE_ACPI_NAMESPACE => DeviceScopeType::AcpiNamespace,
            _ => {
                current = current.add(scope_len);
                continue;
            }
        };

        // Parse path entries (after the fixed header)
        let path_start = current.add(core::mem::size_of::<DeviceScopeRaw>());
        let path_len = scope_len - core::mem::size_of::<DeviceScopeRaw>();
        let mut path = Vec::new();

        for i in (0..path_len).step_by(2) {
            if i + 1 < path_len {
                let device = *path_start.add(i);
                let function = *path_start.add(i + 1);
                path.push((device, function));
            }
        }

        scopes.push(DeviceScope {
            scope_type,
            start_bus: scope.start_bus,
            path,
        });

        current = current.add(scope_len);
    }

    Ok(scopes)
}

/// Verify ACPI table checksum.
fn verify_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}
