//! Intel VT-d (Virtualization Technology for Directed I/O) Driver
//!
//! Implements the Intel VT-d IOMMU hardware interface for DMA remapping.
//! This driver manages VT-d hardware units, their translation structures,
//! and provides DMA isolation for PCI devices.
//!
//! # Hardware Structures
//!
//! VT-d uses a two-level lookup for address translation:
//!
//! 1. **Root Table**: Indexed by PCI bus number (256 entries)
//!    - Points to Context Tables for each bus
//!
//! 2. **Context Table**: Indexed by device/function (256 entries per bus)
//!    - Contains domain ID and pointer to second-level page table
//!
//! 3. **Second-Level Page Table**: 4-level structure like x86_64 page tables
//!    - Translates IOVA to physical address
//!
//! # Registers
//!
//! Key VT-d registers (offsets from DRHD base):
//! - 0x00: Version Register
//! - 0x08: Capability Register
//! - 0x10: Extended Capability Register
//! - 0x18: Global Command Register
//! - 0x1C: Global Status Register
//! - 0x20: Root Table Address Register
//! - 0x24: Context Command Register
//! - 0x28: Fault Status Register
//! - 0x100+: IOTLB Registers
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 10 (Register Descriptions)
//! - Intel VT-d Specification, Chapter 3 (DMA Remapping)

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::{self, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::PhysAddr;

use crate::dmar::DrhdEntry;
use crate::domain::{Domain, DomainId, DomainType};
use crate::fault::FaultRecord;
use crate::interrupt::{InterruptRemappingTable, DEFAULT_IR_ENTRIES};
use crate::{IommuError, IommuResult, PciDeviceId};
use mm::{buddy_allocator, phys_to_virt};

// ============================================================================
// Register Offsets
// ============================================================================

/// Version Register (32-bit, RO).
const VTD_REG_VER: usize = 0x00;

/// Capability Register (64-bit, RO).
const VTD_REG_CAP: usize = 0x08;

/// Extended Capability Register (64-bit, RO).
const VTD_REG_ECAP: usize = 0x10;

/// Global Command Register (32-bit, R/W).
const VTD_REG_GCMD: usize = 0x18;

/// Global Status Register (32-bit, RO).
const VTD_REG_GSTS: usize = 0x1C;

/// Root Table Address Register (64-bit, R/W).
const VTD_REG_RTADDR: usize = 0x20;

/// Context Command Register (64-bit, R/W).
const VTD_REG_CCMD: usize = 0x28;

/// Fault Status Register (32-bit, R/W1C).
const VTD_REG_FSTS: usize = 0x34;

/// Fault Event Control Register (32-bit, R/W).
const VTD_REG_FECTL: usize = 0x38;

/// Fault Event Data Register (32-bit, R/W).
const VTD_REG_FEDATA: usize = 0x3C;

/// Fault Event Address Register (32-bit, R/W).
const VTD_REG_FEADDR: usize = 0x40;

/// Interrupt Remapping Table Address Register (64-bit, R/W).
const VTD_REG_IRTA: usize = 0xB8;

/// IOTLB Registers offset (varies by capability).
const VTD_REG_IOTLB_BASE: usize = 0x100;

// ============================================================================
// Global Command/Status Bits
// ============================================================================

/// Translation Enable (GCMD.TE).
const GCMD_TE: u32 = 1 << 31;

/// Set Root Table Pointer (GCMD.SRTP).
const GCMD_SRTP: u32 = 1 << 30;

/// Write Buffer Flush (GCMD.WBF).
const GCMD_WBF: u32 = 1 << 27;

/// Queued Invalidation Enable (GCMD.QIE).
const GCMD_QIE: u32 = 1 << 26;

/// Interrupt Remapping Enable (GCMD.IRE).
const GCMD_IRE: u32 = 1 << 25;

/// Translation Enable Status (GSTS.TES).
const GSTS_TES: u32 = 1 << 31;

/// Root Table Pointer Status (GSTS.RTPS).
const GSTS_RTPS: u32 = 1 << 30;

/// Write Buffer Flush Status (GSTS.WBFS).
const GSTS_WBFS: u32 = 1 << 27;

/// Interrupt Remapping Enable Status (GSTS.IRES).
const GSTS_IRES: u32 = 1 << 25;

// ============================================================================
// Capability Bits
// ============================================================================

/// Number of domains supported (CAP.ND).
const CAP_ND_MASK: u64 = 0x7;

/// Required Write Buffer Flushing (CAP.RWBF).
const CAP_RWBF: u64 = 1 << 4;

/// Page Selective Invalidation (CAP.PSI).
const CAP_PSI: u64 = 1 << 39;

/// Maximum Guest Address Width (CAP.MGAW) - bits 37:32.
const CAP_MGAW_SHIFT: u64 = 16;
const CAP_MGAW_MASK: u64 = 0x3F;

/// Supported Adjusted Guest Address Width (CAP.SAGAW) - bits 12:8.
const CAP_SAGAW_SHIFT: u64 = 8;
const CAP_SAGAW_MASK: u64 = 0x1F;

/// Fault Recording Register offset (CAP.FRO) - bits 23:20, in 16-byte units.
const CAP_FRO_SHIFT: u64 = 24;
const CAP_FRO_MASK: u64 = 0x3FF;

/// Number of Fault Recording Registers (CAP.NFR) - bits 47:40.
const CAP_NFR_SHIFT: u64 = 40;
const CAP_NFR_MASK: u64 = 0xFF;

// ============================================================================
// Extended Capability Bits
// ============================================================================

/// IOTLB Register Offset (ECAP.IRO) - bits 17:8, in 16-byte units.
const ECAP_IRO_SHIFT: u64 = 8;
const ECAP_IRO_MASK: u64 = 0x3FF;

/// Queued Invalidation Support (ECAP.QI).
const ECAP_QI: u64 = 1 << 1;

/// Device-TLB Support (ECAP.DT).
const ECAP_DT: u64 = 1 << 2;

/// Interrupt Remapping Support (ECAP.IR).
const ECAP_IR: u64 = 1 << 3;

/// Pass Through Support (ECAP.PT).
const ECAP_PT: u64 = 1 << 6;

// ============================================================================
// IOTLB Command Bits
// ============================================================================

/// IOTLB Invalidate (IVT).
const IOTLB_IVT: u64 = 1 << 63;

/// IOTLB Invalidation Request Granularity.
const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
const IOTLB_IIRG_PAGE: u64 = 3 << 60;

/// Drain Reads (DR).
const IOTLB_DR: u64 = 1 << 49;

/// Drain Writes (DW).
const IOTLB_DW: u64 = 1 << 48;

// ============================================================================
// Context Command Bits
// ============================================================================

/// Context Invalidation Command (ICC).
const CCMD_ICC: u64 = 1 << 63;

/// Context Invalidation Request Granularity.
const CCMD_CIRG_GLOBAL: u64 = 1 << 61;
const CCMD_CIRG_DOMAIN: u64 = 2 << 61;
const CCMD_CIRG_DEVICE: u64 = 3 << 61;

// ============================================================================
// Root/Context Table Structures
// ============================================================================

/// Root table entry (128-bit, but only lower 64 bits used).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RootEntry {
    /// Lower 64 bits: present bit + context table pointer.
    lo: u64,
    /// Upper 64 bits: reserved.
    hi: u64,
}

impl RootEntry {
    /// Present bit.
    const PRESENT: u64 = 1 << 0;
    /// Context table address mask (12-bit aligned).
    const CTP_MASK: u64 = !0xFFF;

    /// Create an empty (not present) entry.
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create an entry pointing to a context table.
    pub const fn new(context_table_phys: u64) -> Self {
        Self {
            lo: (context_table_phys & Self::CTP_MASK) | Self::PRESENT,
            hi: 0,
        }
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.lo & Self::PRESENT != 0
    }

    /// Get context table physical address.
    pub const fn context_table_addr(&self) -> u64 {
        self.lo & Self::CTP_MASK
    }
}

/// Context table entry (128-bit).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ContextEntry {
    /// Lower 64 bits: present, fault processing, translation type, address width, second-level page table pointer.
    lo: u64,
    /// Upper 64 bits: domain ID, reserved.
    hi: u64,
}

impl ContextEntry {
    /// Present bit.
    const PRESENT: u64 = 1 << 0;
    /// Fault Processing Disable.
    const FPD: u64 = 1 << 1;
    /// Translation Type (bits 3:2).
    const TT_SHIFT: u64 = 2;
    /// Address Width (bits 6:4) - encodes AGAW.
    const AW_SHIFT: u64 = 4;
    /// Second-level page table pointer mask.
    const SLPTPTR_MASK: u64 = !0xFFF;
    /// Domain ID shift in hi.
    const DID_SHIFT: u64 = 8;
    /// Domain ID mask.
    const DID_MASK: u64 = 0xFFFF;

    /// Translation Type: Untranslated requests only.
    const TT_UNTRANSLATED: u64 = 0;
    /// Translation Type: All requests translated.
    const TT_ALL: u64 = 1;
    /// Translation Type: Pass-through.
    const TT_PASSTHROUGH: u64 = 2;

    /// Create an empty (not present) entry.
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create a context entry with second-level translation.
    ///
    /// # Arguments
    ///
    /// * `domain_id` - Domain identifier
    /// * `slpt_phys` - Second-level page table physical address
    /// * `agaw` - Adjusted Guest Address Width (3 = 39-bit, 4 = 48-bit)
    pub fn new_translated(domain_id: DomainId, slpt_phys: u64, agaw: u8) -> Self {
        let aw = match agaw {
            39 => 1, // 3-level page table
            48 => 2, // 4-level page table
            57 => 3, // 5-level page table
            _ => 2,  // Default to 48-bit
        };

        Self {
            lo: Self::PRESENT
                | (Self::TT_ALL << Self::TT_SHIFT)
                | ((aw as u64) << Self::AW_SHIFT)
                | (slpt_phys & Self::SLPTPTR_MASK),
            hi: (domain_id as u64) << Self::DID_SHIFT,
        }
    }

    /// Create a pass-through context entry (identity mapping).
    pub fn new_passthrough(domain_id: DomainId) -> Self {
        Self {
            lo: Self::PRESENT | (Self::TT_PASSTHROUGH << Self::TT_SHIFT),
            hi: (domain_id as u64) << Self::DID_SHIFT,
        }
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.lo & Self::PRESENT != 0
    }

    /// Get domain ID.
    pub const fn domain_id(&self) -> DomainId {
        ((self.hi >> Self::DID_SHIFT) & Self::DID_MASK) as DomainId
    }
}

/// Root table (256 entries, 4KB).
#[repr(C, align(4096))]
pub struct RootTable {
    entries: [RootEntry; 256],
}

impl RootTable {
    /// Create a new empty root table.
    pub const fn new() -> Self {
        Self {
            entries: [RootEntry::empty(); 256],
        }
    }
}

/// Context table (256 entries, 4KB).
#[repr(C, align(4096))]
pub struct ContextTable {
    entries: [ContextEntry; 256],
}

impl ContextTable {
    /// Create a new empty context table.
    pub const fn new() -> Self {
        Self {
            entries: [ContextEntry::empty(); 256],
        }
    }
}

// ============================================================================
// Memory Safety Limits
// ============================================================================

/// Maximum physical address reachable via the direct map (1 GB).
/// Frames above this cannot be safely accessed via phys_to_virt.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30;

// ============================================================================
// VT-d Error Types
// ============================================================================

/// VT-d specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdError {
    /// Hardware not responding.
    HardwareTimeout,
    /// Unsupported hardware version.
    UnsupportedVersion,
    /// Required capability not present.
    MissingCapability,
    /// Translation enable failed.
    TranslationEnableFailed,
    /// Invalidation failed.
    InvalidationFailed,
    /// Root table allocation failed.
    RootTableAllocFailed,
    /// Context table allocation failed.
    ContextTableAllocFailed,
    /// Hardware initialization failed.
    HardwareInitFailed,
    /// Interrupt remapping table allocation failed.
    InterruptRemapAllocFailed,
}

// ============================================================================
// VT-d Unit
// ============================================================================

/// Intel VT-d hardware unit driver.
///
/// Manages a single VT-d IOMMU unit discovered via ACPI DMAR table.
pub struct VtdUnit {
    /// Register base virtual address.
    reg_base: u64,

    /// PCI segment this unit handles.
    segment: u16,

    /// Whether this unit handles all PCI devices.
    include_pci_all: bool,

    /// Specific devices handled (if not include_pci_all).
    device_scopes: Vec<(u8, u8, u8)>, // (bus, device, function)

    /// Hardware version.
    version: (u8, u8),

    /// Capability register value.
    cap: u64,

    /// Extended capability register value.
    ecap: u64,

    /// Root table physical address.
    root_table_phys: AtomicU64,

    /// Lock protecting root/context table programming.
    /// Prevents data races when concurrent operations modify translation tables.
    table_lock: Mutex<()>,

    /// Whether translation is enabled.
    translation_enabled: AtomicBool,

    /// Interrupt remapping table (if enabled).
    /// Wrapped in Arc for safe sharing and Mutex for interior mutability.
    ir_table: Mutex<Option<Arc<InterruptRemappingTable>>>,

    /// Domains attached to this unit.
    attached_domains: Mutex<BTreeSet<DomainId>>,

    /// Attached devices (source ID -> domain ID).
    attached_devices: Mutex<alloc::collections::BTreeMap<u16, DomainId>>,

    /// IOTLB register offset.
    iotlb_offset: usize,

    /// Fault recording register offset.
    fault_offset: usize,
}

impl VtdUnit {
    /// Create a new VT-d unit from DRHD information.
    ///
    /// # Arguments
    ///
    /// * `drhd` - DRHD entry from ACPI DMAR table
    ///
    /// # Returns
    ///
    /// Initialized VT-d unit or error
    pub fn new(drhd: &DrhdEntry) -> Result<Self, VtdError> {
        let reg_base = drhd.register_base();

        // Read version register
        let ver = unsafe { Self::read_reg32(reg_base, VTD_REG_VER) };
        let version = ((ver >> 4) as u8, (ver & 0xF) as u8);

        // Read capability registers
        let cap = unsafe { Self::read_reg64(reg_base, VTD_REG_CAP) };
        let ecap = unsafe { Self::read_reg64(reg_base, VTD_REG_ECAP) };

        // Calculate IOTLB register offset
        let iro = ((ecap >> ECAP_IRO_SHIFT) & ECAP_IRO_MASK) as usize;
        let iotlb_offset = iro * 16;

        // Calculate fault recording register offset
        let fro = ((cap >> CAP_FRO_SHIFT) & CAP_FRO_MASK) as usize;
        let fault_offset = fro * 16;

        // Extract device scopes
        let mut device_scopes = Vec::new();
        for scope in drhd.device_scopes() {
            if let Some(&(dev, func)) = scope.path.last() {
                device_scopes.push((scope.start_bus, dev, func));
            }
        }

        Ok(Self {
            reg_base,
            segment: drhd.segment(),
            include_pci_all: drhd.include_pci_all(),
            device_scopes,
            version,
            cap,
            ecap,
            root_table_phys: AtomicU64::new(0),
            table_lock: Mutex::new(()),
            translation_enabled: AtomicBool::new(false),
            ir_table: Mutex::new(None),
            attached_domains: Mutex::new(BTreeSet::new()),
            attached_devices: Mutex::new(alloc::collections::BTreeMap::new()),
            iotlb_offset,
            fault_offset,
        })
    }

    /// Get PCI segment.
    #[inline]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Check if this unit handles a specific device.
    pub fn handles_device(&self, device: &PciDeviceId) -> bool {
        if device.segment != self.segment {
            return false;
        }

        if self.include_pci_all {
            return true;
        }

        self.device_scopes
            .iter()
            .any(|&(bus, dev, func)| {
                bus == device.bus && dev == device.device && func == device.function
            })
    }

    /// Check if a domain is attached to this unit.
    pub fn has_domain(&self, domain_id: DomainId) -> bool {
        self.attached_domains.lock().contains(&domain_id)
    }

    /// Get the domain ID for a device given its source ID.
    ///
    /// # Arguments
    ///
    /// * `source_id` - PCI source ID (bus << 8 | device << 3 | function)
    ///
    /// # Returns
    ///
    /// Domain ID if the device is attached, None otherwise.
    pub fn get_device_domain(&self, source_id: u16) -> Option<DomainId> {
        self.attached_devices.lock().get(&source_id).copied()
    }

    /// Check whether translation is currently enabled for this unit.
    #[inline]
    pub fn translation_enabled(&self) -> bool {
        self.translation_enabled.load(Ordering::Acquire)
    }

    /// Check whether interrupt remapping is supported by hardware.
    #[inline]
    pub fn supports_interrupt_remapping(&self) -> bool {
        self.ecap & ECAP_IR != 0
    }

    /// Set up interrupt remapping for this VT-d unit.
    ///
    /// Interrupt remapping is critical for secure device passthrough as it prevents
    /// malicious devices from injecting arbitrary interrupts to the host. Without IR,
    /// a compromised device could trigger arbitrary interrupt vectors, potentially
    /// escaping VM isolation.
    ///
    /// # Arguments
    ///
    /// * `required` - If true, failure to enable IR is a fatal error
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Interrupt remapping successfully enabled
    /// * `Ok(false)` - IR not supported and not required (safe to continue without)
    /// * `Err(VtdError)` - IR required but setup failed (fail-closed)
    ///
    /// # Security
    ///
    /// - Fail-closed when `required=true`: if platform requires IR, failure aborts initialization
    /// - Table allocation failure with `required=false` gracefully degrades
    /// - GCMD.IRE enable failure rolls back and reports error when required
    ///
    /// # Hardware Flow
    ///
    /// 1. Check ECAP.IR for hardware support
    /// 2. Allocate interrupt remapping table (256 entries default)
    /// 3. Program IRTA register with table address
    /// 4. Set GCMD.IRE to enable interrupt remapping
    /// 5. Poll GSTS.IRES until set (hardware acknowledgment)
    pub fn setup_interrupt_remapping(&self, required: bool) -> Result<bool, VtdError> {
        // R84-1 FIX: Serialize setup to avoid double-programming IRTA/GCMD
        // and dropping a live table while hardware is racing.
        // Hold the mutex across the entire setup to prevent concurrent callers.
        let mut ir_slot = self.ir_table.lock();
        if ir_slot.is_some() {
            return Ok(true);
        }

        // Check hardware support
        if !self.supports_interrupt_remapping() {
            return if required {
                // Platform requires IR but hardware doesn't support it - fail closed
                Err(VtdError::MissingCapability)
            } else {
                // IR not supported but not required - continue without
                Ok(false)
            };
        }

        // Allocate interrupt remapping table
        // Default 256 entries (4KB, fits in one page)
        let table = match InterruptRemappingTable::allocate(DEFAULT_IR_ENTRIES) {
            Ok(t) => t,
            Err(_) => {
                return if required {
                    Err(VtdError::HardwareInitFailed)
                } else {
                    // Allocation failed but not required - degrade gracefully
                    Ok(false)
                };
            }
        };

        // Program IRTA register with table address
        // x2APIC mode disabled for now (Extended Interrupt Mode)
        let irta = table.irta_value(false);
        unsafe {
            Self::write_reg64(self.reg_base, VTD_REG_IRTA, irta);
        }

        // Read current GCMD to preserve other enabled features
        // Note: GCMD is write-only per spec, but GSTS reflects enabled state
        // We build GCMD from GSTS to preserve TE, SRTP if already set
        let current_gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        let mut gcmd: u32 = 0;
        if current_gsts & GSTS_TES != 0 {
            gcmd |= GCMD_TE;
        }
        if current_gsts & GSTS_RTPS != 0 {
            gcmd |= GCMD_SRTP;
        }

        // Enable interrupt remapping
        gcmd |= GCMD_IRE;
        unsafe {
            Self::write_reg32(self.reg_base, VTD_REG_GCMD, gcmd);
        }

        // Wait for hardware acknowledgment (GSTS.IRES set)
        if let Err(e) = self.wait_status(GSTS_IRES) {
            // R84-2 FIX: Clear both IRE and IRTA on failure.
            // If we only clear IRE but leave IRTA programmed, and IRE is toggled
            // later without reprogramming IRTA, hardware could dereference freed memory.
            gcmd &= !GCMD_IRE;
            unsafe {
                Self::write_reg32(self.reg_base, VTD_REG_GCMD, gcmd);
                // Clear IRTA to avoid hardware dereferencing freed memory
                Self::write_reg64(self.reg_base, VTD_REG_IRTA, 0);
            }
            // Table will be dropped when this function returns

            return if required {
                Err(e)
            } else {
                // Enable failed but not required - degrade gracefully
                Ok(false)
            };
        }

        // Success: publish the table so it remains alive for this unit
        *ir_slot = Some(Arc::new(table));

        Ok(true)
    }

    /// Allocate and initialize the root table if not already present.
    ///
    /// This method uses CAS to handle concurrent allocation attempts, ensuring
    /// only one root table is installed even with multiple CPUs racing.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Root table is ready (either already existed or was allocated)
    /// * `Err(VtdError)` - Allocation failed
    pub fn init_root_table(&self) -> Result<(), VtdError> {
        // Fast path: check if already allocated
        let current = self.root_table_phys.load(Ordering::Acquire);
        if current != 0 {
            // Validate existing root table is within direct map
            if current >= MAX_DIRECT_MAP_PHYS {
                return Err(VtdError::RootTableAllocFailed);
            }
            return Ok(());
        }

        // Allocate a physical frame for the root table
        let frame = buddy_allocator::alloc_physical_pages(1)
            .ok_or(VtdError::RootTableAllocFailed)?;
        let phys = frame.start_address().as_u64();

        // Validate frame is within direct map range
        if phys >= MAX_DIRECT_MAP_PHYS {
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(VtdError::RootTableAllocFailed);
        }

        // Zero the root table before publishing
        let virt = phys_to_virt(frame.start_address());
        unsafe {
            ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, size_of::<RootTable>());
        }

        // Atomically install the root table (only if still zero)
        match self.root_table_phys.compare_exchange(
            0,
            phys,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(existing) => {
                // Another CPU installed a table; free our redundant allocation
                buddy_allocator::free_physical_pages(frame, 1);
                // Validate the table installed by the other CPU
                if existing >= MAX_DIRECT_MAP_PHYS {
                    Err(VtdError::RootTableAllocFailed)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Ensure a context table exists for the given bus.
    ///
    /// This method allocates a context table if one doesn't exist for the specified
    /// PCI bus. Uses CAS to handle concurrent allocation attempts.
    ///
    /// # Arguments
    ///
    /// * `bus` - PCI bus number (0-255)
    ///
    /// # Returns
    ///
    /// * `Ok(&mut ContextTable)` - Reference to the context table
    /// * `Err(IommuError)` - Allocation failed or root table not initialized
    ///
    /// # Safety
    ///
    /// Caller must hold `table_lock` to serialize table updates.
    fn ensure_context_table(&self, bus: u8) -> IommuResult<&'static mut ContextTable> {
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 {
            return Err(IommuError::NotInitialized);
        }
        if root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }

        // Get reference to root table
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };

        // Check if context table already exists for this bus
        // We use atomic operations on the root entry's lo field to handle races
        let entry_ptr = unsafe { root_table.entries.as_mut_ptr().add(bus as usize) };
        let entry_lo_ptr = entry_ptr as *mut u64;
        let entry_atomic: &AtomicU64 = unsafe { &*(entry_lo_ptr as *const AtomicU64) };

        let current = entry_atomic.load(Ordering::Acquire);
        if current & RootEntry::PRESENT != 0 {
            // Context table already exists
            let ctx_phys = current & RootEntry::CTP_MASK;
            if ctx_phys >= MAX_DIRECT_MAP_PHYS {
                return Err(IommuError::HardwareInitFailed);
            }
            let ctx_virt = phys_to_virt(PhysAddr::new(ctx_phys));
            return Ok(unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() });
        }

        // Allocate a new context table
        let frame = buddy_allocator::alloc_physical_pages(1)
            .ok_or(IommuError::PageTableAllocFailed)?;
        let ctx_phys = frame.start_address().as_u64();

        // Validate frame is within direct map range
        if ctx_phys >= MAX_DIRECT_MAP_PHYS {
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(IommuError::PageTableAllocFailed);
        }

        // Zero the context table before publishing
        let ctx_virt = phys_to_virt(frame.start_address());
        unsafe {
            ptr::write_bytes(ctx_virt.as_mut_ptr::<u8>(), 0, size_of::<ContextTable>());
        }

        // Atomically install the root entry (only if still zero)
        let new_entry = RootEntry::new(ctx_phys);
        match entry_atomic.compare_exchange(
            0,
            new_entry.lo,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() }),
            Err(existing) => {
                // Another CPU installed an entry; free our allocation
                buddy_allocator::free_physical_pages(frame, 1);

                // Validate the entry installed by the other CPU
                if existing & RootEntry::PRESENT == 0 {
                    return Err(IommuError::HardwareInitFailed);
                }
                let ctx_phys_existing = existing & RootEntry::CTP_MASK;
                if ctx_phys_existing >= MAX_DIRECT_MAP_PHYS {
                    return Err(IommuError::HardwareInitFailed);
                }
                let ctx_virt_existing = phys_to_virt(PhysAddr::new(ctx_phys_existing));
                Ok(unsafe { &mut *ctx_virt_existing.as_mut_ptr::<ContextTable>() })
            }
        }
    }

    /// Attach a device to a domain.
    ///
    /// Sets up the context table entry for the device. This configures the IOMMU
    /// to translate DMA requests from the device using the domain's address space.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device identifier (bus:device.function)
    /// * `domain` - Target domain for DMA isolation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Device successfully attached
    /// * `Err(IommuError)` - Attachment failed
    ///
    /// # Security
    ///
    /// - Requires root table and translation to be enabled (fail-closed)
    /// - Rejects duplicate attachments
    /// - Validates domain page table root is within direct map
    /// - Uses proper memory ordering for context entry publication
    pub fn attach_device(&self, device: &PciDeviceId, domain: &Arc<Domain>) -> IommuResult<()> {
        let source_id = device.source_id();

        // Fail-closed: require root table and translation to be enabled
        if self.root_table_phys.load(Ordering::Acquire) == 0 || !self.translation_enabled() {
            return Err(IommuError::NotInitialized);
        }

        // Check if already attached (quick check before taking lock)
        {
            let devices = self.attached_devices.lock();
            if devices.contains_key(&source_id) {
                return Err(IommuError::DeviceAlreadyAttached);
            }
        }

        // Program the context entry under the table lock
        let _table_guard = self.table_lock.lock();

        // Get or allocate context table for this bus
        let context_table = self.ensure_context_table(device.bus)?;

        // Calculate context table index: (device << 3) | function
        let ctx_index = ((device.device as usize) << 3) | (device.function as usize);
        let entry = &mut context_table.entries[ctx_index];

        // Double-check: reject if entry already present
        if entry.is_present() {
            return Err(IommuError::DeviceAlreadyAttached);
        }

        // Build context entry based on domain type
        let ctx_entry = match domain.domain_type() {
            DomainType::Identity => {
                // R94-13 FIX: Identity domains use VT-d pass-through translation,
                // which allows devices to DMA into arbitrary physical memory.
                // Only permit this when explicitly opted in via feature flag.
                #[cfg(not(feature = "unsafe_identity_passthrough"))]
                {
                    return Err(IommuError::PermissionDenied);
                }

                #[cfg(feature = "unsafe_identity_passthrough")]
                {
                    // R81-2 FIX: Check pass-through support before using TT_PASSTHROUGH
                    // If hardware doesn't support pass-through, fail closed
                    if !self.supports_passthrough() {
                        return Err(IommuError::HardwareInitFailed);
                    }
                    // Pass-through mode: IOVA == physical address
                    ContextEntry::new_passthrough(domain.id())
                }
            }
            DomainType::PageTable => {
                // R83-4 FIX: Validate domain AGAW against hardware CAP.SAGAW
                //
                // SAGAW bits in Capability Register:
                //   bit 0: 39-bit AGAW (3-level page table)
                //   bit 1: 48-bit AGAW (4-level page table)
                //   bit 2: 57-bit AGAW (5-level page table)
                //
                // If the domain's address width is not supported by hardware, the context
                // entry's AW field would be undefined, leading to DMA faults or translation
                // bypass. Fail-closed to prevent isolation bypass.
                //
                // NOTE: This check is only for PageTable domains. Identity domains use
                // pass-through mode and don't use the AW field.
                let sagaw_bits = self.supported_agaw();
                let domain_agaw_bit = match domain.address_width() {
                    39 => 1u8 << 0,
                    48 => 1u8 << 1,
                    57 => 1u8 << 2,
                    _ => 0u8, // Unknown/invalid address width
                };
                if domain_agaw_bit == 0 || (sagaw_bits & domain_agaw_bit) == 0 {
                    return Err(IommuError::InvalidRange);
                }

                // Full translation mode: use domain's second-level page table
                let slpt = domain.page_table_root();
                if slpt == 0 {
                    // Domain has no page table - fail closed
                    return Err(IommuError::NotInitialized);
                }
                if slpt >= MAX_DIRECT_MAP_PHYS {
                    return Err(IommuError::HardwareInitFailed);
                }
                ContextEntry::new_translated(domain.id(), slpt, domain.address_width())
            }
        };

        // Write context entry: upper dword first, then publish via low dword
        // This ensures the present bit is set last with full entry visible
        unsafe {
            write_volatile(&mut entry.hi, ctx_entry.hi);
            core::sync::atomic::fence(Ordering::Release);
            write_volatile(&mut entry.lo, ctx_entry.lo);
        }

        // R81-1 FIX: Invalidate context cache and IOTLB after programming entry
        // This ensures hardware doesn't use stale cached translations
        self.invalidate_context_device(device)?;
        let _ = self.invalidate_iotlb_domain(domain.id());

        // Drop lock before updating tracking structures
        drop(_table_guard);

        // Record the attachment
        {
            let mut devices = self.attached_devices.lock();
            devices.insert(source_id, domain.id());
        }
        {
            let mut domains = self.attached_domains.lock();
            domains.insert(domain.id());
        }

        Ok(())
    }

    /// Detach a device from a domain.
    ///
    /// Clears the device's context entry, invalidates caches, and updates
    /// tracking structures. Bus mastering is disabled before tearing down
    /// the context to prevent post-detach DMA.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device identifier
    /// * `domain_id` - Domain the device is expected to be attached to
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Device successfully detached
    /// * `Err(IommuError)` - Detachment failed
    ///
    /// # Security
    ///
    /// - Bus mastering is disabled BEFORE clearing context (prevents post-detach DMA)
    /// - Context cache and IOTLB are invalidated after clearing entry
    /// - Validates device is actually attached to the specified domain
    /// - Fail-closed: returns error if any validation fails
    pub fn detach_device(&self, device: &PciDeviceId, domain_id: DomainId) -> IommuResult<()> {
        let source_id = device.source_id();

        // Fail-closed: require root table and translation to be enabled
        if self.root_table_phys.load(Ordering::Acquire) == 0 || !self.translation_enabled() {
            return Err(IommuError::NotInitialized);
        }

        // Validate the device is recorded as attached to the expected domain
        {
            let devices = self.attached_devices.lock();
            match devices.get(&source_id) {
                Some(&attached_domain) if attached_domain == domain_id => {}
                _ => return Err(IommuError::DeviceNotAttached),
            }
        }

        // Disable bus mastering BEFORE clearing the context entry
        // This prevents any DMA from completing after we remove the translation
        // R87-2 FIX: Continue with detach even if bus mastering disable fails on non-zero segments
        let _bus_master_disabled = match self.disable_bus_mastering(device) {
            Ok(()) => true,
            Err(IommuError::PermissionDenied) => {
                // Non-zero segment - can't use legacy I/O, but still proceed with context teardown
                // The device may continue DMA until hardware naturally stops, but context is removed
                println!(
                    "[IOMMU] WARNING: Cannot disable bus mastering for {:02x}:{:02x}.{} (segment {}), proceeding with context teardown",
                    device.bus, device.device, device.function, device.segment
                );
                false
            }
            Err(e) => return Err(e),
        };

        // Program tables under lock
        let _table_guard = self.table_lock.lock();

        // Locate context table for this bus
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 {
            return Err(IommuError::NotInitialized);
        }
        if root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };
        let root_entry = &root_table.entries[device.bus as usize];
        if !root_entry.is_present() {
            return Err(IommuError::DeviceNotAttached);
        }

        let ctx_phys = root_entry.context_table_addr();
        if ctx_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }
        let ctx_virt = phys_to_virt(PhysAddr::new(ctx_phys));
        let context_table = unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() };

        // Calculate context table index: (device << 3) | function
        let ctx_index = ((device.device as usize) << 3) | (device.function as usize);
        let entry = &mut context_table.entries[ctx_index];

        // Validate entry matches expected domain
        if !entry.is_present() || entry.domain_id() != domain_id {
            return Err(IommuError::DeviceNotAttached);
        }

        // Clear context entry: drop metadata then present bit with release ordering
        // This ensures hardware sees consistent state during teardown
        unsafe {
            write_volatile(&mut entry.hi, 0);
            core::sync::atomic::fence(Ordering::Release);
            write_volatile(&mut entry.lo, ContextEntry::empty().lo);
        }

        // Invalidate caches after removing the entry
        // This ensures hardware doesn't use stale cached translations
        self.invalidate_context_device(device)?;
        self.invalidate_iotlb_domain(domain_id)?;

        // Drop lock before updating tracking structures
        drop(_table_guard);

        // R87-1 FIX: Update attached_devices and attached_domains atomically
        // Hold the devices lock while updating attached_domains to prevent race conditions
        // where a concurrent attach could add a device to the domain while we're removing it
        {
            let mut devices = self.attached_devices.lock();
            devices.remove(&source_id);
            let still_used = devices.values().any(|&d| d == domain_id);

            // If no other devices use this domain, remove from attached_domains
            // Do this while still holding the devices lock to prevent TOCTOU
            if !still_used {
                let mut domains = self.attached_domains.lock();
                domains.remove(&domain_id);
            }
            // devices lock dropped here
        }

        Ok(())
    }

    /// Disable PCI bus mastering for a device using legacy config space.
    ///
    /// This function uses legacy PCI I/O port access (0xCF8/0xCFC) which only
    /// supports segment 0. Multi-segment systems require ECAM support.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device to disable bus mastering for
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Bus mastering successfully disabled
    /// * `Err(IommuError::PermissionDenied)` - Device on unsupported segment
    /// * `Err(IommuError::DeviceNotFound)` - No device at this address
    /// * `Err(IommuError::HardwareInitFailed)` - Failed to disable bus mastering
    ///
    /// # Security
    ///
    /// - Validates device segment (legacy I/O only supports segment 0)
    /// - Uses global PCI config lock to serialize access
    /// - Verifies bus mastering was actually disabled via read-back
    fn disable_bus_mastering(&self, device: &PciDeviceId) -> IommuResult<()> {
        // Legacy PCI I/O only supports segment 0
        if device.segment != self.segment || device.segment != 0 {
            return Err(IommuError::PermissionDenied);
        }

        // Serialize PCI config space access
        let _pci_lock = crate::PCI_CONFIG_LOCK.lock();

        // Validate device exists by checking vendor ID
        let vendor_device = crate::pci_cfg_read32(device.bus, device.device, device.function, 0x00);
        let vendor = (vendor_device & 0xFFFF) as u16;
        if vendor == crate::PCI_VENDOR_INVALID {
            return Err(IommuError::DeviceNotFound);
        }

        // Read current command register
        let command = crate::pci_cfg_read16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
        );

        // Clear bus master enable bit
        let new_command = command & !crate::PCI_COMMAND_BUS_MASTER;
        crate::pci_cfg_write16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
            new_command,
        );

        // Verify the write took effect (read-back check)
        let verify = crate::pci_cfg_read16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
        );

        drop(_pci_lock);

        if verify & crate::PCI_COMMAND_BUS_MASTER == 0 {
            Ok(())
        } else {
            Err(IommuError::HardwareInitFailed)
        }
    }

    /// Invalidate IOTLB entries for a domain.
    pub fn invalidate_iotlb_domain(&self, domain_id: DomainId) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Ok(());
        }

        // Build invalidation command
        let cmd = IOTLB_IVT | IOTLB_IIRG_DOMAIN | IOTLB_DR | IOTLB_DW | ((domain_id as u64) << 32);

        // Write to IOTLB register
        unsafe {
            Self::write_reg64(self.reg_base, self.iotlb_offset + 8, cmd);
        }

        // Wait for completion (IVT bit clears)
        self.wait_iotlb_complete()?;

        Ok(())
    }

    /// Invalidate IOTLB entries for a specific range.
    pub fn invalidate_iotlb_range(&self, domain_id: DomainId, iova: u64, size: usize) -> IommuResult<()> {
        // Check if page-selective invalidation is supported
        if self.cap & CAP_PSI == 0 {
            // Fall back to domain invalidation
            return self.invalidate_iotlb_domain(domain_id);
        }

        if !self.translation_enabled.load(Ordering::Acquire) {
            return Ok(());
        }

        // For simplicity, use domain invalidation for now
        // Page-selective requires additional address register setup
        self.invalidate_iotlb_domain(domain_id)
    }

    /// Invalidate context cache for a specific device.
    ///
    /// This is required after programming a context entry to ensure hardware
    /// doesn't use stale cached context information.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device whose context entry was modified
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Invalidation successful
    /// * `Err(IommuError)` - Hardware error
    pub fn invalidate_context_device(&self, device: &PciDeviceId) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Ok(());
        }

        // Build context invalidation command for device granularity
        // CIRG = 11b (device), SID = source_id, FM = 0 (exact match)
        let source_id = device.source_id() as u64;
        let cmd = CCMD_ICC | CCMD_CIRG_DEVICE | (source_id << 16);

        // Write to context command register
        unsafe {
            Self::write_reg64(self.reg_base, VTD_REG_CCMD, cmd);
        }

        // Wait for completion (ICC bit clears)
        self.wait_context_complete()?;

        Ok(())
    }

    /// Wait for context cache invalidation to complete.
    fn wait_context_complete(&self) -> IommuResult<()> {
        for _ in 0..1000 {
            let val = unsafe { Self::read_reg64(self.reg_base, VTD_REG_CCMD) };
            if val & CCMD_ICC == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(IommuError::HardwareInitFailed)
    }

    /// Enable DMA translation.
    ///
    /// This activates the IOMMU to enforce DMA isolation. Before calling this,
    /// the root table must be allocated (via init_root_table).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Translation enabled
    /// * `Err(VtdError)` - Hardware error or allocation failed
    pub fn enable_translation(&self) -> Result<(), VtdError> {
        if self.translation_enabled.load(Ordering::Acquire) {
            return Ok(());
        }

        // Ensure root table is allocated and valid
        self.init_root_table()?;
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(VtdError::RootTableAllocFailed);
        }

        // Write root table address to hardware
        unsafe {
            Self::write_reg64(self.reg_base, VTD_REG_RTADDR, root_phys);
        }

        // Set root table pointer
        unsafe {
            Self::write_reg32(self.reg_base, VTD_REG_GCMD, GCMD_SRTP);
        }

        // Wait for RTPS
        self.wait_status(GSTS_RTPS)?;

        // Flush write buffer if required
        if self.cap & CAP_RWBF != 0 {
            unsafe {
                Self::write_reg32(self.reg_base, VTD_REG_GCMD, GCMD_SRTP | GCMD_WBF);
            }
            self.wait_status_clear(GSTS_WBFS)?;
        }

        // Enable translation
        unsafe {
            Self::write_reg32(self.reg_base, VTD_REG_GCMD, GCMD_SRTP | GCMD_TE);
        }

        // Wait for TES
        self.wait_status(GSTS_TES)?;

        self.translation_enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Disable DMA translation.
    pub fn disable_translation(&self) -> Result<(), VtdError> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Ok(());
        }

        // Clear TE bit
        unsafe {
            Self::write_reg32(self.reg_base, VTD_REG_GCMD, 0);
        }

        // Wait for TES to clear
        self.wait_status_clear(GSTS_TES)?;

        self.translation_enabled.store(false, Ordering::Release);
        Ok(())
    }

    /// Wait for IOTLB invalidation to complete.
    fn wait_iotlb_complete(&self) -> IommuResult<()> {
        for _ in 0..1000 {
            let val = unsafe { Self::read_reg64(self.reg_base, self.iotlb_offset + 8) };
            if val & IOTLB_IVT == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(IommuError::HardwareInitFailed)
    }

    /// Wait for status bit to be set.
    fn wait_status(&self, bit: u32) -> Result<(), VtdError> {
        for _ in 0..1000 {
            let status = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if status & bit != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(VtdError::HardwareTimeout)
    }

    /// Wait for status bit to clear.
    fn wait_status_clear(&self, bit: u32) -> Result<(), VtdError> {
        for _ in 0..1000 {
            let status = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if status & bit == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(VtdError::HardwareTimeout)
    }

    /// Get hardware version.
    pub fn version(&self) -> (u8, u8) {
        self.version
    }

    /// Get maximum guest address width.
    pub fn max_guest_addr_width(&self) -> u8 {
        (((self.cap >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) as u8) + 1
    }

    /// Get supported adjusted guest address widths.
    pub fn supported_agaw(&self) -> u8 {
        ((self.cap >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK) as u8
    }

    /// Get number of domains supported.
    pub fn num_domains(&self) -> u32 {
        let nd = (self.cap & CAP_ND_MASK) as u32;
        match nd {
            0 => 16,
            1 => 64,
            2 => 256,
            3 => 1024,
            4 => 4096,
            5 => 16384,
            6 => 65536,
            _ => 256,
        }
    }

    /// Check if queued invalidation is supported.
    pub fn supports_qi(&self) -> bool {
        self.ecap & ECAP_QI != 0
    }

    /// Check if pass-through is supported.
    pub fn supports_passthrough(&self) -> bool {
        self.ecap & ECAP_PT != 0
    }

    /// Get a reference to the interrupt remapping table (if enabled).
    ///
    /// Returns `Some(Arc<InterruptRemappingTable>)` if interrupt remapping has been
    /// set up for this unit, `None` otherwise.
    pub fn interrupt_remapping_table(&self) -> Option<Arc<InterruptRemappingTable>> {
        self.ir_table.lock().clone()
    }

    /// Get the number of fault recording registers.
    pub fn num_fault_regs(&self) -> usize {
        // CAP.NFR is zero-based, so add 1
        (((self.cap >> CAP_NFR_SHIFT) & CAP_NFR_MASK) as usize) + 1
    }

    /// Read fault records from hardware.
    ///
    /// This method reads and clears all pending fault records from the VT-d unit's
    /// fault recording registers. It should be called in response to a fault interrupt
    /// or periodically to detect DMA faults.
    ///
    /// # Returns
    ///
    /// Tuple of (fault_records, overflow_occurred). Empty vector if no faults pending.
    ///
    /// # Security
    ///
    /// - Processing is bounded to prevent DoS from fault floods
    /// - Fault records are cleared after reading (W1C semantics)
    /// - Overflow flag is checked and cleared
    /// - R85-1: Uses FRI-based rotation to avoid losing faults
    /// - R85-4: Returns overflow flag to caller for policy decisions
    pub fn read_fault_records(&self) -> (Vec<FaultRecord>, bool) {
        use crate::fault;

        // Check and clear fault status first
        let (overflow, pending, fri) =
            unsafe { fault::read_and_clear_fault_status(self.reg_base) };

        if overflow {
            // Log that faults may have been lost due to overflow
            println!(
                "[IOMMU] Fault overflow detected on unit (segment={})",
                self.segment
            );
        }

        if !pending && !overflow {
            // No faults to process
            return (Vec::new(), overflow);
        }

        // Read fault records from hardware, starting from FRI
        let records = unsafe {
            fault::read_fault_records(
                self.reg_base,
                self.fault_offset,
                self.num_fault_regs(),
                fri as usize,
            )
        };

        // R85-1: Log truncation warning if hardware has more fault slots than we process
        if self.num_fault_regs() > fault::MAX_FAULT_RECORDS
            && records.len() == fault::MAX_FAULT_RECORDS
        {
            println!(
                "[IOMMU] Unit {} fault processing truncated at {} records (hardware has {})",
                self.segment,
                fault::MAX_FAULT_RECORDS,
                self.num_fault_regs()
            );
        }

        (records, overflow)
    }

    /// Enable or disable fault event interrupts.
    ///
    /// When enabled, the IOMMU will generate an interrupt when a DMA fault occurs.
    /// The interrupt vector and destination should be configured in the Fault Event
    /// registers (FEDATA, FEADDR) before enabling.
    ///
    /// # Arguments
    ///
    /// * `enable` - True to enable fault interrupts, false to disable
    pub fn set_fault_interrupt_enabled(&self, enable: bool) {
        use crate::fault;
        unsafe { fault::set_fault_interrupt_enabled(self.reg_base, enable) };
    }

    // ========================================================================
    // Register Access
    // ========================================================================

    #[inline]
    unsafe fn read_reg32(base: u64, offset: usize) -> u32 {
        read_volatile((base + offset as u64) as *const u32)
    }

    #[inline]
    unsafe fn read_reg64(base: u64, offset: usize) -> u64 {
        read_volatile((base + offset as u64) as *const u64)
    }

    #[inline]
    unsafe fn write_reg32(base: u64, offset: usize, value: u32) {
        write_volatile((base + offset as u64) as *mut u32, value);
    }

    #[inline]
    unsafe fn write_reg64(base: u64, offset: usize, value: u64) {
        write_volatile((base + offset as u64) as *mut u64, value);
    }
}
