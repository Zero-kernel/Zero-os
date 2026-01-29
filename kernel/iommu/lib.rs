//! IOMMU/VT-d Support for Zero-OS
//!
//! This crate provides DMA isolation through Intel VT-d (or AMD-Vi in future).
//! It prevents untrusted devices from accessing arbitrary physical memory,
//! which is critical for security in systems with DMA-capable devices.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! | PCI Device       |     | PCI Device       |     | PCI Device       |
//! | (bus:dev.fn)     |     | (bus:dev.fn)     |     | (bus:dev.fn)     |
//! +--------+---------+     +--------+---------+     +--------+---------+
//!          |                        |                        |
//!          v                        v                        v
//!    +-----------------------------------------------------------+
//!    |                    IOMMU Context Table                    |
//!    |  (per-device translation root, domain assignment)         |
//!    +----------------------------+------------------------------+
//!                                 |
//!                                 v
//!    +-----------------------------------------------------------+
//!    |                    IOMMU Domains                          |
//!    |  Domain 0: Identity map (kernel DMA buffers)              |
//!    |  Domain 1: VM1 guest memory (future passthrough)          |
//!    |  Domain 2: VM2 guest memory (future passthrough)          |
//!    +-----------------------------------------------------------+
//!                                 |
//!                                 v
//!    +-----------------------------------------------------------+
//!    |                    Physical Memory                        |
//!    +-----------------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! 1. Call `init()` during kernel boot to discover and initialize IOMMU units
//! 2. Before enabling bus mastering on a PCI device, call `attach_device()`
//! 3. Map DMA buffer ranges with `map_range()` (identity map by default)
//!
//! # Security Model
//!
//! - Fail-closed: If IOMMU is available but not initialized, refuse DMA
//! - One domain per isolation context (kernel, future VMs)
//! - Devices must be explicitly attached before DMA is allowed
//! - DMA faults are logged and device is disabled
//!
//! # References
//!
//! - Intel VT-d Specification: Chapter 3 (DMA Remapping)
//! - ACPI DMAR Table: Section 8 (DMA Remapping Reporting)
//! - Phase F.3 in roadmap.md

#![no_std]

extern crate alloc;

#[macro_use]
extern crate drivers;

pub mod dmar;
pub mod domain;
pub mod fault;
pub mod interrupt;
pub mod vtd;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Lazy, Mutex, RwLock};

// Re-export key types
pub use dmar::{DmarTable, DmarError};
pub use domain::{Domain, DomainId, DomainType};
pub use fault::{FaultConfig, FaultReason, FaultRecord, FaultType};
pub use interrupt::{Irte, IrteHandle, InterruptRemappingTable};
pub use vtd::{VtdUnit, VtdError};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of IOMMU units supported.
pub const MAX_IOMMU_UNITS: usize = 8;

/// Maximum number of domains per IOMMU unit.
pub const MAX_DOMAINS: usize = 256;

/// Default domain ID for kernel DMA (identity mapped).
pub const KERNEL_DOMAIN_ID: DomainId = 0;

// ============================================================================
// PCI Config Space Constants (for device isolation)
// ============================================================================

/// Legacy PCI configuration space address port (Mechanism #1).
pub(crate) const PCI_CONFIG_ADDRESS: u16 = 0xCF8;

/// Legacy PCI configuration space data port (Mechanism #1).
pub(crate) const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI Command register offset in configuration space.
pub(crate) const PCI_COMMAND_OFFSET: u8 = 0x04;

/// PCI Command register - Bus Master Enable bit (bit 2).
pub(crate) const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Vendor ID value indicating no device present.
pub(crate) const PCI_VENDOR_INVALID: u16 = 0xFFFF;

/// Lock for PCI configuration space access serialization.
/// R86-2 FIX: Prevents concurrent read-modify-write races.
pub(crate) static PCI_CONFIG_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Global State
// ============================================================================

/// Whether IOMMU is available and initialized.
static IOMMU_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether IOMMU initialization has been attempted.
static IOMMU_INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Number of IOMMU units discovered.
static IOMMU_UNIT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Registry of IOMMU units (VT-d hardware units).
static IOMMU_UNITS: Lazy<RwLock<Vec<Arc<VtdUnit>>>> = Lazy::new(|| RwLock::new(Vec::new()));

/// Registry of domains.
static DOMAINS: Lazy<RwLock<Vec<Arc<Domain>>>> = Lazy::new(|| RwLock::new(Vec::new()));

/// VM domain registry: maps domain ID to VM identifier.
/// Used to distinguish VM passthrough domains from kernel domains.
static VM_DOMAINS: Lazy<Mutex<BTreeMap<DomainId, u64>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Device-to-IRTE tracking for VM passthrough.
/// Key: (segment, bus, device, function), Value: (domain_id, IRTE index)
type DeviceKey = (u16, u8, u8, u8);
static VM_DEVICE_IRTES: Lazy<Mutex<BTreeMap<DeviceKey, (DomainId, usize)>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// ============================================================================
// Types
// ============================================================================

/// PCI device identifier (bus:device.function).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PciDeviceId {
    /// PCI segment (usually 0).
    pub segment: u16,
    /// PCI bus number (0-255).
    pub bus: u8,
    /// PCI device number (0-31).
    pub device: u8,
    /// PCI function number (0-7).
    pub function: u8,
}

impl PciDeviceId {
    /// Create a new PCI device ID.
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// Create from bus/device/function (segment 0).
    pub const fn from_bdf(bus: u8, device: u8, function: u8) -> Self {
        Self::new(0, bus, device, function)
    }

    /// Convert to source ID format for context table indexing.
    /// Source ID = (bus << 8) | (device << 3) | function
    pub const fn source_id(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

/// IOMMU operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuError {
    /// IOMMU hardware not available.
    NotAvailable,
    /// IOMMU not initialized.
    NotInitialized,
    /// ACPI DMAR table not found.
    NoDmarTable,
    /// Invalid DMAR table structure.
    InvalidDmar,
    /// Too many IOMMU units.
    TooManyUnits,
    /// Domain limit exceeded.
    TooManyDomains,
    /// Device not found in any IOMMU scope.
    DeviceNotFound,
    /// Domain not found in registry.
    DomainNotFound,
    /// Device not attached to the specified domain.
    DeviceNotAttached,
    /// Device already attached to a domain.
    DeviceAlreadyAttached,
    /// Invalid address range.
    InvalidRange,
    /// Page table allocation failed.
    PageTableAllocFailed,
    /// Hardware initialization failed.
    HardwareInitFailed,
    /// DMA fault occurred.
    DmaFault,
    /// Permission denied.
    PermissionDenied,
}

/// Result type for IOMMU operations.
pub type IommuResult<T> = Result<T, IommuError>;

// ============================================================================
// Public API
// ============================================================================

/// Initialize the IOMMU subsystem.
///
/// This function:
/// 1. Parses the ACPI DMAR table to discover IOMMU units
/// 2. Initializes each VT-d unit
/// 3. Creates the default kernel domain (identity mapped)
///
/// # Returns
///
/// * `Ok(count)` - Number of IOMMU units initialized
/// * `Err(IommuError)` - Initialization failed
///
/// # Note
///
/// This should be called early in boot, before PCI devices are initialized.
/// If IOMMU is not available, the kernel can still operate in bypass mode.
pub fn init() -> IommuResult<u32> {
    // Prevent double initialization
    if IOMMU_INIT_DONE.swap(true, Ordering::SeqCst) {
        return Err(IommuError::NotInitialized);
    }

    println!("[IOMMU] Initializing IOMMU subsystem...");

    // Parse ACPI DMAR table
    let dmar = match dmar::parse_dmar_table() {
        Ok(d) => d,
        Err(DmarError::NotFound) => {
            println!("[IOMMU] No DMAR table found - IOMMU not available");
            return Err(IommuError::NoDmarTable);
        }
        Err(e) => {
            println!("[IOMMU] DMAR table parse error: {:?}", e);
            return Err(IommuError::InvalidDmar);
        }
    };

    println!(
        "[IOMMU] DMAR table found: {} DRHD units, {} RMRR regions",
        dmar.drhd_count(),
        dmar.rmrr_count()
    );

    // Check if interrupt remapping is required by platform
    let ir_required = dmar.interrupt_remap_required();
    if ir_required {
        println!("[IOMMU]   Interrupt remapping required by platform");
    }

    // Initialize each DRHD (DMA Remapping Hardware Unit)
    let mut units = IOMMU_UNITS.write();
    let mut count = 0u32;

    for drhd in dmar.drhd_iter() {
        if count as usize >= MAX_IOMMU_UNITS {
            println!("[IOMMU] Warning: Too many IOMMU units, ignoring remaining");
            break;
        }

        match VtdUnit::new(drhd) {
            Ok(unit) => {
                let unit = Arc::new(unit);

                // F.3: Setup interrupt remapping if supported/required
                match unit.setup_interrupt_remapping(ir_required) {
                    Ok(enabled) => {
                        if enabled {
                            println!(
                                "[IOMMU]   Unit {}: base={:#x}, segment={}, IR=enabled",
                                count,
                                drhd.register_base(),
                                drhd.segment()
                            );
                        } else {
                            println!(
                                "[IOMMU]   Unit {}: base={:#x}, segment={}, IR=disabled",
                                count,
                                drhd.register_base(),
                                drhd.segment()
                            );
                        }
                    }
                    Err(e) => {
                        if ir_required {
                            // Fail-closed: If IR is required but setup fails, abort
                            println!(
                                "[IOMMU]   Unit {}: Interrupt remapping required but failed: {:?}",
                                count, e
                            );
                            return Err(IommuError::HardwareInitFailed);
                        } else {
                            println!(
                                "[IOMMU]   Unit {}: base={:#x}, segment={}, IR=unsupported",
                                count,
                                drhd.register_base(),
                                drhd.segment()
                            );
                        }
                    }
                }

                units.push(unit);
                count += 1;
            }
            Err(e) => {
                println!(
                    "[IOMMU]   Failed to initialize unit at {:#x}: {:?}",
                    drhd.register_base(),
                    e
                );
            }
        }
    }

    if count == 0 {
        println!("[IOMMU] No IOMMU units initialized");
        return Err(IommuError::HardwareInitFailed);
    }

    IOMMU_UNIT_COUNT.store(count, Ordering::SeqCst);
    drop(units);

    // Create default kernel domain with identity mapping
    let kernel_domain = Domain::new_identity(KERNEL_DOMAIN_ID)?;
    DOMAINS.write().push(Arc::new(kernel_domain));

    // Handle RMRR (Reserved Memory Region Reporting)
    // These are memory regions that devices may DMA to before OS takes control
    for rmrr in dmar.rmrr_iter() {
        println!(
            "[IOMMU]   RMRR: {:#x}-{:#x} (segment {})",
            rmrr.base(),
            rmrr.limit(),
            rmrr.segment()
        );
        // TODO: Map RMRR regions in all domains that may contain affected devices
    }

    IOMMU_ENABLED.store(true, Ordering::SeqCst);
    println!("[IOMMU] Initialized {} IOMMU units", count);

    Ok(count)
}

/// Check if IOMMU is available and enabled.
///
/// Returns true only if IOMMU hardware is present AND translation is active
/// on at least one unit.
#[inline]
pub fn is_enabled() -> bool {
    if !IOMMU_ENABLED.load(Ordering::Acquire) {
        return false;
    }

    // Verify at least one unit has translation enabled
    let units = IOMMU_UNITS.read();
    units.iter().any(|u| u.translation_enabled())
}

/// Check if IOMMU initialization has been attempted.
#[inline]
pub fn init_done() -> bool {
    IOMMU_INIT_DONE.load(Ordering::Acquire)
}

/// Get the number of IOMMU units.
#[inline]
pub fn unit_count() -> u32 {
    IOMMU_UNIT_COUNT.load(Ordering::Acquire)
}

/// Ensure IOMMU hardware is present and translation is active.
///
/// If VT-d units exist but translation is still disabled, return an error to
/// fail closed instead of silently bypassing DMA isolation.
fn ensure_iommu_ready() -> IommuResult<()> {
    if is_enabled() {
        return Ok(());
    }

    // If hardware exists but translation not enabled, fail closed
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) > 0 {
        return Err(IommuError::NotInitialized);
    }

    // No IOMMU hardware present - allow bypass (legacy mode)
    Ok(())
}

/// Attach a PCI device to the default kernel domain.
///
/// This must be called before enabling bus mastering on the device.
///
/// # Arguments
///
/// * `device` - PCI device identifier
///
/// # Returns
///
/// * `Ok(())` - Device successfully attached
/// * `Err(IommuError)` - Attachment failed
pub fn attach_device(device: PciDeviceId) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // No IOMMU units - allow DMA without isolation (legacy mode)
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }

    attach_device_to_domain(device, KERNEL_DOMAIN_ID)
}

/// Attach a PCI device to a specific domain.
///
/// # Arguments
///
/// * `device` - PCI device identifier
/// * `domain_id` - Target domain ID
///
/// # Returns
///
/// * `Ok(())` - Device successfully attached
/// * `Err(IommuError)` - Attachment failed
pub fn attach_device_to_domain(device: PciDeviceId, domain_id: DomainId) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // Find the IOMMU unit responsible for this device
    let units = IOMMU_UNITS.read();
    let unit = units
        .iter()
        .find(|u| u.handles_device(&device))
        .ok_or(IommuError::DeviceNotFound)?;

    // Verify translation is enabled on this unit (fail-closed)
    if !unit.translation_enabled() {
        return Err(IommuError::NotInitialized);
    }

    // Get or create domain
    let domains = DOMAINS.read();
    let domain = domains
        .iter()
        .find(|d| d.id() == domain_id)
        .ok_or(IommuError::DomainNotFound)?;

    // Attach device to domain via the IOMMU unit
    unit.attach_device(&device, domain)?;

    println!(
        "[IOMMU] Attached device {:02x}:{:02x}.{} to domain {}",
        device.bus, device.device, device.function, domain_id
    );

    Ok(())
}

/// Detach a PCI device from the default kernel domain.
///
/// This disables bus mastering and tears down the device's context entry,
/// preventing any further DMA from the device.
///
/// # Arguments
///
/// * `device` - PCI device identifier
///
/// # Returns
///
/// * `Ok(())` - Device successfully detached
/// * `Err(IommuError)` - Detachment failed
///
/// # Security
///
/// - Bus mastering is disabled before clearing context entry
/// - Context cache and IOTLB are invalidated after detachment
/// - Fail-closed: returns error if device not attached
pub fn detach_device(device: PciDeviceId) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // No IOMMU units - nothing to detach
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }

    detach_device_from_domain(device, KERNEL_DOMAIN_ID)
}

/// Detach a PCI device from a specific domain.
///
/// This disables bus mastering and tears down the device's context entry,
/// preventing any further DMA from the device.
///
/// # Arguments
///
/// * `device` - PCI device identifier
/// * `domain_id` - Domain to detach from
///
/// # Returns
///
/// * `Ok(())` - Device successfully detached
/// * `Err(IommuError)` - Detachment failed
///
/// # Security
///
/// - Bus mastering is disabled BEFORE clearing context entry (prevents post-detach DMA)
/// - Context cache and IOTLB are invalidated after detachment
/// - Validates device is actually attached to the specified domain
pub fn detach_device_from_domain(device: PciDeviceId, domain_id: DomainId) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // No IOMMU units - nothing to detach
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }

    // Find the IOMMU unit responsible for this device
    let units = IOMMU_UNITS.read();
    let unit = units
        .iter()
        .find(|u| u.handles_device(&device))
        .ok_or(IommuError::DeviceNotFound)?;

    // Verify translation is enabled on this unit (fail-closed)
    if !unit.translation_enabled() {
        return Err(IommuError::NotInitialized);
    }

    // Verify domain exists
    {
        let domains = DOMAINS.read();
        if !domains.iter().any(|d| d.id() == domain_id) {
            return Err(IommuError::DomainNotFound);
        }
    }

    // Detach device from domain via the IOMMU unit
    unit.detach_device(&device, domain_id)?;

    println!(
        "[IOMMU] Detached device {:02x}:{:02x}.{} from domain {}",
        device.bus, device.device, device.function, domain_id
    );

    Ok(())
}

/// Map a physical address range for DMA access.
///
/// For identity-mapped domains, this is a no-op but records the mapping
/// for future reference. For second-level page table domains, this
/// creates the necessary mappings.
///
/// # Arguments
///
/// * `domain_id` - Domain ID
/// * `iova` - IO virtual address (device-visible address)
/// * `phys` - Physical address
/// * `size` - Size in bytes (must be page-aligned)
/// * `write` - Whether write access is allowed
///
/// # Returns
///
/// * `Ok(())` - Mapping successful
/// * `Err(IommuError)` - Mapping failed
pub fn map_range(
    domain_id: DomainId,
    iova: u64,
    phys: u64,
    size: usize,
    write: bool,
) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // No IOMMU units - allow DMA without mapping (legacy mode)
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }

    let domains = DOMAINS.read();
    let domain = domains
        .iter()
        .find(|d| d.id() == domain_id)
        .ok_or(IommuError::DomainNotFound)?;

    domain.map_range(iova, phys, size, write)?;

    // Invalidate IOTLB for the affected range
    let units = IOMMU_UNITS.read();
    for unit in units.iter() {
        if unit.has_domain(domain_id) {
            unit.invalidate_iotlb_range(domain_id, iova, size)?;
        }
    }

    Ok(())
}

/// Unmap a physical address range.
///
/// # Arguments
///
/// * `domain_id` - Domain ID
/// * `iova` - IO virtual address to unmap
/// * `size` - Size in bytes
///
/// # Returns
///
/// * `Ok(())` - Unmapping successful
/// * `Err(IommuError)` - Unmapping failed
pub fn unmap_range(domain_id: DomainId, iova: u64, size: usize) -> IommuResult<()> {
    ensure_iommu_ready()?;

    // No IOMMU units - allow DMA without mapping (legacy mode)
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }

    let domains = DOMAINS.read();
    let domain = domains
        .iter()
        .find(|d| d.id() == domain_id)
        .ok_or(IommuError::DomainNotFound)?;

    domain.unmap_range(iova, size)?;

    // Invalidate IOTLB for the unmapped range
    let units = IOMMU_UNITS.read();
    for unit in units.iter() {
        if unit.has_domain(domain_id) {
            unit.invalidate_iotlb_range(domain_id, iova, size)?;
        }
    }

    Ok(())
}

/// Create a new domain for device isolation.
///
/// # Arguments
///
/// * `domain_type` - Type of domain (identity or page-table)
///
/// # Returns
///
/// * `Ok(domain_id)` - New domain ID
/// * `Err(IommuError)` - Domain creation failed
pub fn create_domain(domain_type: DomainType) -> IommuResult<DomainId> {
    let mut domains = DOMAINS.write();

    if domains.len() >= MAX_DOMAINS {
        return Err(IommuError::TooManyDomains);
    }

    let id = domains.len() as DomainId;
    let domain = match domain_type {
        DomainType::Identity => Domain::new_identity(id)?,
        DomainType::PageTable => Domain::new_paged(id)?,
    };

    domains.push(Arc::new(domain));

    println!("[IOMMU] Created domain {} ({:?})", id, domain_type);
    Ok(id)
}

// ============================================================================
// VM Passthrough API
// ============================================================================

/// Construct device key for VM passthrough tracking.
#[inline]
fn device_key(device: &PciDeviceId) -> DeviceKey {
    (device.segment, device.bus, device.device, device.function)
}

/// Resolve the VT-d unit responsible for a device.
///
/// Validates that the unit is initialized and translation is active.
/// Clones the Arc to avoid holding the units read-lock across operations.
fn resolve_unit(device: &PciDeviceId) -> IommuResult<Arc<VtdUnit>> {
    let units = IOMMU_UNITS.read();
    let unit = units
        .iter()
        .find(|u| u.handles_device(device))
        .cloned()
        .ok_or(IommuError::DeviceNotFound)?;

    if !unit.translation_enabled() {
        return Err(IommuError::NotInitialized);
    }

    Ok(unit)
}

/// Validate that a domain is a VM passthrough domain.
///
/// Returns the domain Arc if validation passes.
fn validate_vm_domain(domain_id: DomainId) -> IommuResult<Arc<Domain>> {
    let domains = DOMAINS.read();
    let domain = domains
        .iter()
        .find(|d| d.id() == domain_id)
        .cloned()
        .ok_or(IommuError::DomainNotFound)?;

    // VM passthrough requires PageTable domain type
    if domain.domain_type() != DomainType::PageTable {
        return Err(IommuError::PermissionDenied);
    }

    // Verify this domain was created via create_vm_domain
    if !VM_DOMAINS.lock().contains_key(&domain_id) {
        return Err(IommuError::DomainNotFound);
    }

    Ok(domain)
}

/// Obtain the interrupt remapping table from a VT-d unit.
///
/// For VM passthrough, interrupt remapping is mandatory to prevent
/// devices from injecting arbitrary interrupts to the host.
/// This function is fail-closed: returns error if IR is not available.
///
/// # Security (R88-1 FIX)
///
/// - Verifies hardware supports interrupt remapping
/// - Forces IR setup if not already enabled (fail-closed)
/// - Only proceeds if IR is actually enabled and table exists
fn require_ir_table(unit: &VtdUnit) -> IommuResult<Arc<InterruptRemappingTable>> {
    if !unit.supports_interrupt_remapping() {
        return Err(IommuError::HardwareInitFailed);
    }

    // R88-1 FIX: Force IR setup to ensure IRE is actually enabled
    // This handles the case where IR support exists but was disabled
    // during init (ir_required=false) or was disabled later.
    // For VM passthrough, IR is mandatory - fail closed if setup fails.
    unit.setup_interrupt_remapping(true)
        .map_err(|_| IommuError::HardwareInitFailed)?;

    unit.interrupt_remapping_table()
        .ok_or(IommuError::NotInitialized)
}

/// Create a VM-specific domain with isolated page tables.
///
/// VM domains use second-level page table translation, enabling arbitrary
/// IOVA-to-physical mappings for device passthrough. Each VM gets its own
/// domain to ensure DMA isolation between VMs.
///
/// # Arguments
///
/// * `vm_id` - Unique identifier for the VM this domain belongs to
///
/// # Returns
///
/// * `Ok(domain_id)` - Domain ID for the new VM domain
/// * `Err(IommuError)` - Creation failed
///
/// # Security
///
/// - Requires IOMMU hardware to be present and initialized (fail-closed)
/// - Domain is PageTable type for full translation (no identity bypass)
/// - VM association tracked separately to prevent kernel domain confusion
pub fn create_vm_domain(vm_id: u64) -> IommuResult<DomainId> {
    ensure_iommu_ready()?;

    // VM passthrough requires active IOMMU - no legacy bypass
    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Err(IommuError::NotAvailable);
    }

    let mut domains = DOMAINS.write();
    if domains.len() >= MAX_DOMAINS {
        return Err(IommuError::TooManyDomains);
    }

    let id = domains.len() as DomainId;
    let domain = Domain::new_paged(id)?;
    domains.push(Arc::new(domain));

    // Record VM association (hold domain write lock first, then VM lock)
    VM_DOMAINS.lock().insert(id, vm_id);

    println!(
        "[IOMMU] Created VM domain {} for VM {} (page-table)",
        id, vm_id
    );
    Ok(id)
}

/// Assign a PCI device to a VM domain for passthrough.
///
/// This function performs a full assignment sequence:
/// 1. Validates the VM domain exists and is the correct type
/// 2. Verifies the device is not already assigned
/// 3. Allocates an interrupt remapping entry for MSI isolation
/// 4. Attaches the device to the VM domain's IOMMU context
///
/// On partial failure, all changes are rolled back atomically.
///
/// # Arguments
///
/// * `device` - PCI device to assign
/// * `vm_domain_id` - Target VM domain (must be created via create_vm_domain)
///
/// # Returns
///
/// * `Ok(IrteHandle)` - Handle with MSI address/data for device programming
/// * `Err(IommuError)` - Assignment failed (no state changed)
///
/// # Security
///
/// - Interrupt remapping is mandatory (prevents interrupt injection attacks)
/// - Device must not be attached to any other domain (fail-closed)
/// - IRTE is allocated before attach; rolled back on attach failure
/// - Source ID validation in IRTE prevents spoofed interrupt injection
pub fn assign_device_to_vm(
    device: PciDeviceId,
    vm_domain_id: DomainId,
) -> IommuResult<IrteHandle> {
    ensure_iommu_ready()?;

    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Err(IommuError::NotAvailable);
    }

    // Validate VM domain
    let domain = validate_vm_domain(vm_domain_id)?;

    // Resolve IOMMU unit for this device
    let unit = resolve_unit(&device)?;

    // Fail-closed: reject if device is already attached to any domain
    if unit.get_device_domain(device.source_id()).is_some() {
        return Err(IommuError::DeviceAlreadyAttached);
    }

    // Check tracking table for duplicate
    let key = device_key(&device);
    {
        let tracker = VM_DEVICE_IRTES.lock();
        if tracker.contains_key(&key) {
            return Err(IommuError::DeviceAlreadyAttached);
        }
    }

    // Obtain interrupt remapping table (mandatory for passthrough)
    let ir_table = require_ir_table(&unit)?;

    // Allocate IRTE before touching device state for clean rollback
    let irte_index = ir_table
        .allocate_index()
        .ok_or(IommuError::HardwareInitFailed)?;

    // Clear the IRTE entry to ensure no stale interrupt mappings leak
    ir_table.set_entry(irte_index, Irte::empty());

    // Attach device to VM domain via IOMMU context table
    if let Err(e) = unit.attach_device(&device, &domain) {
        // Roll back IRTE allocation on failure
        ir_table.free_index(irte_index);
        return Err(e);
    }

    // Record device assignment in tracking table
    {
        let mut tracker = VM_DEVICE_IRTES.lock();
        tracker.insert(key, (vm_domain_id, irte_index));
    }

    let handle = IrteHandle::new(irte_index, device.source_id(), 0);

    println!(
        "[IOMMU] Assigned device {:02x}:{:02x}.{} to VM domain {} (IRTE {})",
        device.bus, device.device, device.function, vm_domain_id, irte_index
    );

    Ok(handle)
}

/// Unassign a PCI device from a VM domain.
///
/// This function reverses the assignment sequence:
/// 1. Validates the device is assigned to the specified VM domain
/// 2. Detaches the device from the IOMMU context
/// 3. Frees the interrupt remapping entry
/// 4. Removes tracking state
///
/// # Arguments
///
/// * `device` - PCI device to unassign
/// * `vm_domain_id` - VM domain the device is expected to be assigned to
///
/// # Returns
///
/// * `Ok(())` - Device successfully unassigned
/// * `Err(IommuError)` - Unassignment failed
///
/// # Security
///
/// - Validates device is actually assigned to the specified VM domain
/// - Bus mastering disabled during detach (via detach_device)
/// - IRTE cleared and freed after detach
/// - R88-2 FIX: Device detach proceeds even if IR cleanup fails (fail-closed on device)
pub fn unassign_device_from_vm(
    device: PciDeviceId,
    vm_domain_id: DomainId,
) -> IommuResult<()> {
    ensure_iommu_ready()?;

    if IOMMU_UNIT_COUNT.load(Ordering::Acquire) == 0 {
        return Err(IommuError::NotAvailable);
    }

    // Validate VM domain
    let _domain = validate_vm_domain(vm_domain_id)?;

    // Validate device assignment
    let key = device_key(&device);
    let irte_index = {
        let tracker = VM_DEVICE_IRTES.lock();
        match tracker.get(&key) {
            Some(&(domain_id, index)) if domain_id == vm_domain_id => index,
            _ => return Err(IommuError::DeviceNotAttached),
        }
    };

    // Resolve IOMMU unit
    let unit = resolve_unit(&device)?;

    // R88-2 FIX: Detach device FIRST, then attempt IR cleanup
    // This ensures device DMA/bus mastering is stopped even if IR cleanup fails.
    // The fail-closed priority is: stop device DMA > clean up IRTE
    unit.detach_device(&device, vm_domain_id)?;

    // Remove from tracking table immediately after detach
    // (even before IR cleanup, to prevent double-unassign races)
    {
        let mut tracker = VM_DEVICE_IRTES.lock();
        tracker.remove(&key);
    }

    // Attempt IR table cleanup (best-effort after device detach)
    let ir_cleanup_ok = match require_ir_table(&unit) {
        Ok(ir_table) => {
            // Clear IRTE entry before freeing to prevent stale interrupt delivery
            ir_table.set_entry(irte_index, Irte::empty());
            ir_table.free_index(irte_index)
        }
        Err(_) => {
            // IR table unavailable - log warning but device is already detached
            println!(
                "[IOMMU] WARNING: IR cleanup failed for device {:02x}:{:02x}.{} (IRTE {} orphaned)",
                device.bus, device.device, device.function, irte_index
            );
            false
        }
    };

    println!(
        "[IOMMU] Unassigned device {:02x}:{:02x}.{} from VM domain {} (IRTE {} {})",
        device.bus, device.device, device.function, vm_domain_id, irte_index,
        if ir_cleanup_ok { "freed" } else { "orphaned" }
    );

    Ok(())
}

/// Print IOMMU status for debugging.
pub fn print_status() {
    println!("=== IOMMU Status ===");
    println!("  Enabled: {}", is_enabled());
    println!("  Units: {}", unit_count());

    if is_enabled() {
        let units = IOMMU_UNITS.read();
        for (i, unit) in units.iter().enumerate() {
            println!("  Unit {}: segment={}", i, unit.segment());
        }

        let domains = DOMAINS.read();
        println!("  Domains: {}", domains.len());
        for domain in domains.iter() {
            println!(
                "    Domain {}: {:?}, {} mappings",
                domain.id(),
                domain.domain_type(),
                domain.mapping_count()
            );
        }
    }
}

// ============================================================================
// PCI Config Space Access (for device isolation)
// ============================================================================

/// Build PCI configuration address for legacy mechanism #1.
///
/// # Arguments
///
/// * `bus` - PCI bus number (0-255)
/// * `device` - PCI device number (0-31)
/// * `function` - PCI function number (0-7)
/// * `offset` - Register offset (will be aligned to DWORD boundary)
///
/// # Returns
///
/// 32-bit configuration address for I/O port 0xCF8
#[inline]
pub(crate) fn pci_cfg_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32)
}

/// Read 32-bit value from PCI configuration space.
///
/// # Arguments
///
/// * `bus` - PCI bus number
/// * `device` - PCI device number
/// * `function` - PCI function number
/// * `offset` - Register offset (will be aligned to DWORD boundary)
///
/// # Safety
///
/// Uses x86 I/O ports 0xCF8 and 0xCFC. Caller must ensure no concurrent
/// PCI config space access from other CPUs.
#[inline]
pub(crate) fn pci_cfg_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = pci_cfg_address(bus, device, function, offset);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

/// Read 16-bit value from PCI configuration space.
///
/// # Arguments
///
/// * `bus` - PCI bus number
/// * `device` - PCI device number
/// * `function` - PCI function number
/// * `offset` - Register offset (2-byte aligned)
///
/// # Safety
///
/// Uses x86 I/O ports. Caller must ensure no concurrent PCI config access.
#[inline]
pub(crate) fn pci_cfg_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let shift = (offset & 2) * 8;
    (pci_cfg_read32(bus, device, function, offset & 0xFC) >> shift) as u16
}

/// Write 16-bit value to PCI configuration space (read-modify-write).
///
/// # Arguments
///
/// * `bus` - PCI bus number
/// * `device` - PCI device number
/// * `function` - PCI function number
/// * `offset` - Register offset (2-byte aligned)
/// * `value` - 16-bit value to write
///
/// # Safety
///
/// Uses x86 I/O ports. Caller must ensure no concurrent PCI config access.
/// This function is NOT atomic - uses read-modify-write sequence.
#[inline]
pub(crate) fn pci_cfg_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let mut dword = pci_cfg_read32(bus, device, function, aligned);
    let mask = !(0xFFFFu32 << shift);
    dword = (dword & mask) | ((value as u32) << shift);

    let address = pci_cfg_address(bus, device, function, aligned);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, dword);
    }
}

/// Write 32-bit value to x86 I/O port.
#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

/// Read 32-bit value from x86 I/O port.
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Isolate a faulting PCI device by disabling bus mastering.
///
/// This function disables the Bus Master Enable bit in the PCI Command register,
/// preventing the device from initiating any further DMA transactions. This is
/// critical for containing devices that are generating DMA faults.
///
/// # Arguments
///
/// * `record` - Fault record containing the faulting device's source ID
/// * `segment` - PCI segment the device belongs to (from VT-d unit)
/// * `unit` - Reference to the VT-d unit for IOTLB invalidation
///
/// # Security
///
/// - R86-1 FIX: Includes segment validation for multi-segment systems
/// - R86-2 FIX: Serializes PCI config access via global lock
/// - R86-3 FIX: Invalidates device context/IOTLB after isolation
/// - Best-effort isolation: logs outcome regardless of success/failure
/// - Validates device exists before attempting isolation
/// - Verifies bus mastering was actually disabled
/// - All outcomes logged for audit trail
///
/// # Implementation Notes
///
/// Uses legacy PCI configuration space access (I/O ports 0xCF8/0xCFC).
/// Legacy PCI I/O port access only supports segment 0.
fn isolate_device(record: &FaultRecord, segment: u16, unit: &Arc<VtdUnit>) {
    let bus = record.bus();
    let device = record.device();
    let function = record.function();

    // R86-1 FIX: Validate segment - legacy PCI I/O only supports segment 0
    // Multi-segment systems require ECAM (memory-mapped config space)
    if segment != 0 {
        println!(
            "[IOMMU] WARNING: Cannot isolate device {:02x}:{:02x}.{} on segment {} - legacy PCI I/O only supports segment 0",
            bus, device, function, segment
        );
        println!(
            "[IOMMU] SECURITY: Faulting device on segment {} remains active (source ID {:04x})",
            segment, record.source_id
        );
        return;
    }

    // R86-2 FIX: Serialize PCI config space access to prevent RMW races
    let _pci_lock = PCI_CONFIG_LOCK.lock();

    // Validate device exists by checking vendor ID
    let vendor_device = pci_cfg_read32(bus, device, function, 0x00);
    let vendor = (vendor_device & 0xFFFF) as u16;
    if vendor == PCI_VENDOR_INVALID {
        println!(
            "[IOMMU] Isolation skipped: no PCI device at {:02x}:{:02x}.{} (source ID {:04x})",
            bus, device, function, record.source_id
        );
        return;
    }

    // Read current command register
    let command = pci_cfg_read16(bus, device, function, PCI_COMMAND_OFFSET);

    // Clear bus master enable bit
    let new_command = command & !PCI_COMMAND_BUS_MASTER;
    pci_cfg_write16(bus, device, function, PCI_COMMAND_OFFSET, new_command);

    // Verify the write took effect (read-back check)
    let verify = pci_cfg_read16(bus, device, function, PCI_COMMAND_OFFSET);

    // Drop PCI lock before IOTLB invalidation (avoid lock ordering issues)
    drop(_pci_lock);

    if verify & PCI_COMMAND_BUS_MASTER == 0 {
        println!(
            "[IOMMU] Isolated faulting device {:02x}:{:02x}.{} (source ID {:04x}): bus master disabled",
            bus, device, function, record.source_id
        );

        // R86-3 FIX: Invalidate device's context/IOTLB to quiesce outstanding DMA
        // This helps prevent in-flight DMA from completing after isolation
        let pci_id = PciDeviceId::from_bdf(bus, device, function);
        let _ = unit.invalidate_context_device(&pci_id);

        // Get domain ID for this device if known
        if let Some(domain_id) = unit.get_device_domain(record.source_id) {
            let _ = unit.invalidate_iotlb_domain(domain_id);
        }
    } else {
        // Isolation failed - log warning for audit
        println!(
            "[IOMMU] WARNING: Failed to disable bus mastering for {:02x}:{:02x}.{} (source ID {:04x}); command {:#06x} -> {:#06x} (verified {:#06x})",
            bus, device, function, record.source_id, command, new_command, verify
        );
    }
}

// ============================================================================
// Fault Handling API
// ============================================================================

/// Default fault handling configuration.
static FAULT_CONFIG: Lazy<Mutex<FaultConfig>> = Lazy::new(|| Mutex::new(FaultConfig::default()));

/// Set fault handling configuration.
///
/// # Arguments
///
/// * `config` - New fault configuration
pub fn set_fault_config(config: FaultConfig) {
    *FAULT_CONFIG.lock() = config;
}

/// Get current fault handling configuration.
pub fn get_fault_config() -> FaultConfig {
    *FAULT_CONFIG.lock()
}

/// Handle pending DMA faults on all IOMMU units.
///
/// This function should be called periodically (e.g., from a timer interrupt)
/// or in response to a fault interrupt to process any pending DMA faults.
///
/// # Returns
///
/// Total number of faults processed across all units.
///
/// # Security
///
/// - Logs all faults to console and audit subsystem
/// - Optionally isolates faulting devices (if configured)
/// - Bounded processing: max 16 records per unit per invocation
/// - R85-4: Masks fault interrupts on overflow to prevent interrupt storms
pub fn handle_dma_faults() -> usize {
    if !IOMMU_ENABLED.load(Ordering::Acquire) {
        return 0;
    }

    let config = *FAULT_CONFIG.lock();
    let units = IOMMU_UNITS.read();
    let mut total_faults = 0;

    // Fail-closed: Force audit logging when device isolation is enabled
    // This ensures all isolation actions have an audit trail
    let audit_enabled = config.audit_logging || config.isolate_devices;

    // R86-4 FIX: Force console logging in isolation mode when audit feature
    // may not be available, ensuring at least one logging path exists
    let console_forced = config.isolate_devices && !config.console_logging;

    for (unit_index, unit) in units.iter().enumerate() {
        let (records, overflow) = unit.read_fault_records();
        total_faults += records.len();

        // Get segment for this unit (for device isolation)
        let segment = unit.segment();

        // R85-4: Quiesce interrupt storms when overflow detected and isolation enabled
        if overflow && config.isolate_devices {
            unit.set_fault_interrupt_enabled(false);
            println!(
                "[IOMMU] Unit {} fault interrupts disabled due to overflow (isolation mode)",
                unit_index
            );
        }

        for record in &records {
            if config.console_logging {
                fault::log_fault_to_console(record, unit_index);
            }

            if audit_enabled {
                fault::log_fault_to_audit(record, unit_index);
            }

            // Security-relevant faults always get logged even if config says otherwise
            if record.fault_reason.is_security_relevant() && !config.console_logging {
                // R85-5: Redact low bits to avoid leaking full physical addresses
                let redacted = record.fault_address & !0xFFF;
                println!(
                    "[IOMMU] SECURITY: Unit {} fault from {:04x} addr~={:#x} reason={:?}",
                    unit_index,
                    record.source_id,
                    redacted,
                    record.fault_reason
                );
            }

            // R86-4 FIX: Ensure logging for isolation actions even without console_logging
            if console_forced && !record.fault_reason.is_security_relevant() {
                fault::log_fault_to_console(record, unit_index);
            }

            // R86: Device isolation - disable bus mastering on faulting device
            if config.isolate_devices {
                isolate_device(record, segment, unit);
            }
        }
    }

    total_faults
}
