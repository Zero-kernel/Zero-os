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
pub mod vtd;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Lazy, Mutex, RwLock};

// Re-export key types
pub use dmar::{DmarTable, DmarError};
pub use domain::{Domain, DomainId, DomainType};
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
                println!(
                    "[IOMMU]   Unit {}: base={:#x}, segment={}",
                    count,
                    drhd.register_base(),
                    drhd.segment()
                );
                units.push(Arc::new(unit));
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
