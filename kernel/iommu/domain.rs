//! IOMMU Domain Management
//!
//! A domain represents an isolated DMA address space. Each domain has its own
//! IOVA (IO Virtual Address) to physical address translation. Devices attached
//! to the same domain share the same address space.
//!
//! # Domain Types
//!
//! - **Identity**: VT-d pass-through (untranslated). Unsafe; debug-only.
//! - **PageTable**: Second-level page table translation. Used for kernel and VMs.
//!
//! # Security Model
//!
//! - Kernel domain (ID 0) uses second-level translation by default
//! - DMA mappings are created on-demand via mm::dma::alloc_dma_buffer()
//! - Identity/pass-through domains are debug-only (`unsafe_identity_passthrough`)
//! - Each VM gets its own domain with isolated page tables
//! - Devices can only access memory explicitly mapped in their domain
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 3.4 (Second-Level Translation)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::IommuError;
use mm::{buddy_allocator, phys_to_virt};

// ============================================================================
// Constants
// ============================================================================

/// Page size for IOMMU mappings (4KB).
pub const IOMMU_PAGE_SIZE: usize = 4096;

/// Page shift for IOMMU mappings.
pub const IOMMU_PAGE_SHIFT: usize = 12;

/// Maximum address width supported (48-bit).
pub const MAX_ADDR_WIDTH: u8 = 48;

/// Page-size (PS) bit used to detect huge/superpage SL entries.
/// VT-d uses bit 7 as the PS flag for 2MB/1GB pages in non-leaf entries.
const SL_PTE_SUPERPAGE: u64 = 1 << 7;

/// Maximum physical address reachable via the direct map (1 GB).
/// Frames above this cannot be safely accessed via phys_to_virt.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30; // 1 GB

// ============================================================================
// Types
// ============================================================================

/// Domain identifier type.
pub type DomainId = u16;

/// Domain type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// Identity mapping (IOVA == physical address).
    /// Most efficient for kernel DMA buffers.
    Identity,
    /// Second-level page table translation.
    /// Required for VM device passthrough.
    PageTable,
}

/// Mapping entry tracking IOVA to physical mapping.
#[derive(Debug, Clone, Copy)]
pub struct MappingEntry {
    /// IO Virtual Address (device-visible).
    pub iova: u64,
    /// Physical address.
    pub phys: u64,
    /// Size in bytes.
    pub size: usize,
    /// Write permission.
    pub write: bool,
}

/// IOMMU Domain for DMA isolation.
///
/// Each domain maintains its own address space for DMA operations.
/// Devices attached to a domain can only access memory mapped within it.
pub struct Domain {
    /// Unique domain identifier.
    id: DomainId,

    /// Domain type (identity or page-table).
    domain_type: DomainType,

    /// Address width in bits (e.g., 48 for 48-bit addressing).
    /// Determines page table levels: 39=3-level, 48=4-level.
    address_width: u8,

    /// Mapping entries (for tracking, even in identity mode).
    mappings: Mutex<BTreeMap<u64, MappingEntry>>,

    /// Second-level page table root (physical address).
    /// Only used for PageTable type domains.
    page_table_root: AtomicU64,

    /// Lock protecting page table mutations (map/unmap).
    /// Prevents data races when concurrent operations modify the same domain.
    page_table_lock: Mutex<()>,

    /// Total bytes mapped (for statistics).
    mapped_bytes: AtomicU64,
}

impl Domain {
    /// Create a new identity-mapped domain.
    ///
    /// Identity domains have IOVA == physical address, requiring no translation
    /// tables. This is the most efficient mode for kernel DMA buffers.
    ///
    /// # Arguments
    ///
    /// * `id` - Domain identifier
    ///
    /// # Returns
    ///
    /// New identity-mapped domain
    pub fn new_identity(id: DomainId) -> Result<Self, IommuError> {
        Ok(Self {
            id,
            domain_type: DomainType::Identity,
            address_width: MAX_ADDR_WIDTH,
            mappings: Mutex::new(BTreeMap::new()),
            page_table_root: AtomicU64::new(0),
            page_table_lock: Mutex::new(()),
            mapped_bytes: AtomicU64::new(0),
        })
    }

    /// Create a new page-table domain.
    ///
    /// Page-table domains use second-level translation, allowing arbitrary
    /// IOVA to physical mappings. Required for VM device passthrough.
    ///
    /// # Arguments
    ///
    /// * `id` - Domain identifier
    ///
    /// # Returns
    ///
    /// New page-table domain with allocated root table
    pub fn new_paged(id: DomainId) -> Result<Self, IommuError> {
        // Page table is allocated on first mapping (lazy allocation)
        Ok(Self {
            id,
            domain_type: DomainType::PageTable,
            address_width: MAX_ADDR_WIDTH,
            mappings: Mutex::new(BTreeMap::new()),
            page_table_root: AtomicU64::new(0),
            page_table_lock: Mutex::new(()),
            mapped_bytes: AtomicU64::new(0),
        })
    }

    /// Create a new page-table domain with specific address width.
    ///
    /// # Arguments
    ///
    /// * `id` - Domain identifier
    /// * `address_width` - Address width in bits (39 for 3-level, 48 for 4-level)
    ///
    /// # Returns
    ///
    /// New page-table domain configured for the specified AGAW
    pub fn new_paged_with_agaw(id: DomainId, address_width: u8) -> Result<Self, IommuError> {
        // Validate supported address widths (39-bit 3-level, 48-bit 4-level)
        if address_width != 39 && address_width != 48 {
            return Err(IommuError::InvalidRange);
        }

        Ok(Self {
            id,
            domain_type: DomainType::PageTable,
            address_width,
            mappings: Mutex::new(BTreeMap::new()),
            page_table_root: AtomicU64::new(0),
            page_table_lock: Mutex::new(()),
            mapped_bytes: AtomicU64::new(0),
        })
    }

    /// Get domain identifier.
    #[inline]
    pub fn id(&self) -> DomainId {
        self.id
    }

    /// Get domain type.
    #[inline]
    pub fn domain_type(&self) -> DomainType {
        self.domain_type
    }

    /// Get address width.
    #[inline]
    pub fn address_width(&self) -> u8 {
        self.address_width
    }

    /// Get number of active mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.lock().len()
    }

    /// Get total mapped bytes.
    pub fn mapped_bytes(&self) -> u64 {
        self.mapped_bytes.load(Ordering::Relaxed)
    }

    /// Get page table root physical address.
    ///
    /// Returns 0 for identity-mapped domains.
    pub fn page_table_root(&self) -> u64 {
        self.page_table_root.load(Ordering::Acquire)
    }

    /// Map an IOVA range to physical memory.
    ///
    /// For identity domains, this records the mapping but doesn't create
    /// page tables. For page-table domains, this creates second-level
    /// page table entries.
    ///
    /// # Arguments
    ///
    /// * `iova` - IO virtual address (must be page-aligned)
    /// * `phys` - Physical address (must be page-aligned)
    /// * `size` - Size in bytes (must be page-aligned)
    /// * `write` - Whether write access is allowed
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Mapping successful
    /// * `Err(IommuError)` - Mapping failed
    pub fn map_range(&self, iova: u64, phys: u64, size: usize, write: bool) -> Result<(), IommuError> {
        // Validate alignment
        if (iova as usize) & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        if (phys as usize) & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        if size & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        if size == 0 {
            return Err(IommuError::InvalidRange);
        }

        // Check for address overflow
        let size_u64 = size as u64;
        let end_iova = iova.checked_add(size_u64).ok_or(IommuError::InvalidRange)?;
        let end_phys = phys.checked_add(size_u64).ok_or(IommuError::InvalidRange)?;

        // Check address width constraints
        let max_addr = if self.address_width >= 64 {
            u64::MAX
        } else {
            1u64 << self.address_width
        };
        if end_iova > max_addr || end_phys > max_addr {
            return Err(IommuError::InvalidRange);
        }

        // For identity domains, just record the mapping
        // For page-table domains, we would create page table entries
        match self.domain_type {
            DomainType::Identity => {
                // Identity mapping: enforce IOVA == physical to prevent aliasing
                if iova != phys {
                    return Err(IommuError::InvalidRange);
                }
            }
            DomainType::PageTable => {
                // TODO: Create second-level page table entries
                // This requires:
                // 1. Ensure page table root is allocated
                // 2. Walk/create intermediate tables
                // 3. Install leaf entries with phys + permissions
                self.ensure_page_table_root()?;
            }
        }

        // Record the mapping
        let entry = MappingEntry {
            iova,
            phys,
            size,
            write,
        };

        let mut mappings = self.mappings.lock();

        // Reject overlapping mappings to avoid aliasing the same IOVA range
        if let Some((_, prev)) = mappings.range(..=iova).next_back() {
            let prev_end = prev.iova.checked_add(prev.size as u64).unwrap_or(u64::MAX);
            if prev_end > iova {
                return Err(IommuError::InvalidRange);
            }
        }
        if let Some((_, next)) = mappings.range(iova..).next() {
            if next.iova < end_iova {
                return Err(IommuError::InvalidRange);
            }
        }

        // For page-table domains, install mapping after overlap validation
        if self.domain_type == DomainType::PageTable {
            self.install_mapping(iova, phys, size, write)?;
        }

        // Track any replaced mapping for accurate accounting
        if let Some(replaced) = mappings.insert(iova, entry) {
            self.mapped_bytes.fetch_sub(replaced.size as u64, Ordering::Relaxed);
        }
        self.mapped_bytes.fetch_add(size as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Unmap an IOVA range.
    ///
    /// # Arguments
    ///
    /// * `iova` - IO virtual address to unmap
    /// * `size` - Size in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Unmapping successful
    /// * `Err(IommuError)` - Unmapping failed
    pub fn unmap_range(&self, iova: u64, size: usize) -> Result<(), IommuError> {
        // Validate inputs
        if size == 0 || (size & (IOMMU_PAGE_SIZE - 1)) != 0 {
            return Err(IommuError::InvalidRange);
        }
        if (iova as usize) & (IOMMU_PAGE_SIZE - 1) != 0 {
            return Err(IommuError::InvalidRange);
        }
        let end_iova = iova.checked_add(size as u64).ok_or(IommuError::InvalidRange)?;
        let max_addr = if self.address_width >= 64 {
            u64::MAX
        } else {
            1u64 << self.address_width
        };
        if end_iova > max_addr {
            return Err(IommuError::InvalidRange);
        }

        let mut mappings = self.mappings.lock();

        // Find and remove matching mapping
        if let Some(entry) = mappings.remove(&iova) {
            if entry.size != size {
                // Partial unmap not supported in this simple implementation
                // Re-insert and return error
                mappings.insert(iova, entry);
                return Err(IommuError::InvalidRange);
            }

            self.mapped_bytes.fetch_sub(entry.size as u64, Ordering::Relaxed);

            // For page-table domains, clear the page table entries
            if self.domain_type == DomainType::PageTable {
                self.clear_mapping(iova, size)?;
            }

            Ok(())
        } else {
            Err(IommuError::InvalidRange)
        }
    }

    /// Get all current mappings.
    pub fn get_mappings(&self) -> Vec<MappingEntry> {
        self.mappings.lock().values().cloned().collect()
    }

    /// Ensure page table root is allocated.
    ///
    /// Allocates a 4KB-aligned page table root on first call. Uses CAS to handle
    /// concurrent allocation attempts safely, deallocating the redundant frame
    /// if another CPU wins the race.
    pub(crate) fn ensure_page_table_root(&self) -> Result<(), IommuError> {
        // Check if already allocated (fast path)
        if self.page_table_root.load(Ordering::Acquire) != 0 {
            return Ok(());
        }

        // Allocate a zeroed page table frame
        let frame = Self::alloc_zeroed_page_table()?;
        let phys = frame.start_address().as_u64();

        // Atomically install the root, only if still zero
        match self.page_table_root.compare_exchange(
            0,
            phys,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(_) => {
                // Another CPU won the race; free our redundant allocation
                buddy_allocator::free_physical_pages(frame, 1);
                Ok(())
            }
        }
    }

    /// Allocate a physical frame and zero it for use as a page table.
    ///
    /// # Security
    ///
    /// Validates that the allocated frame is within the direct map range (0-1GB)
    /// to prevent invalid pointer dereferences. Frames above this range cannot
    /// be safely accessed via phys_to_virt.
    ///
    /// Returns the allocated PhysFrame. The caller is responsible for freeing
    /// it if not used.
    fn alloc_zeroed_page_table() -> Result<PhysFrame<Size4KiB>, IommuError> {
        let frame = buddy_allocator::alloc_physical_pages(1)
            .ok_or(IommuError::PageTableAllocFailed)?;

        // R80-1 FIX: Verify frame is within direct map range
        // The direct map only covers physical addresses 0-1GB
        let phys_addr = frame.start_address().as_u64();
        if phys_addr >= MAX_DIRECT_MAP_PHYS {
            // Frame is outside direct map - cannot safely access it
            // Free it and fail (this should rarely happen with proper mm setup)
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(IommuError::PageTableAllocFailed);
        }

        // Zero the page table to ensure no stale mappings leak through
        let virt = phys_to_virt(frame.start_address());
        unsafe {
            ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, IOMMU_PAGE_SIZE);
        }

        Ok(frame)
    }

    /// Convert a physical address to a mutable reference to a second-level page table.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - The physical address is within the direct map range (0-1GB)
    /// - The physical address points to a valid, mapped page table
    /// - The page_table_lock is held to prevent concurrent access
    unsafe fn table_from_phys(phys: u64) -> &'static mut SlPageTable {
        // Note: Caller must have validated phys < MAX_DIRECT_MAP_PHYS
        debug_assert!(phys < MAX_DIRECT_MAP_PHYS, "physical address out of direct map range");
        let virt = phys_to_virt(PhysAddr::new(phys));
        &mut *virt.as_mut_ptr::<SlPageTable>()
    }

    /// Get or allocate a child page table at the given index.
    ///
    /// If the entry is already present, returns a reference to the existing table.
    /// If absent, allocates a new zeroed table and installs it.
    /// Rejects superpage (PS) entries since we only support 4KB mappings.
    fn get_or_create_table(
        parent: &mut SlPageTable,
        index: usize,
    ) -> Result<&'static mut SlPageTable, IommuError> {
        let entry = parent.entry(index);

        if entry.is_present() {
            // Reject huge-page mappings since we only support 4KB granularity
            if entry.raw() & SL_PTE_SUPERPAGE != 0 {
                return Err(IommuError::InvalidRange);
            }
            return unsafe { Ok(Self::table_from_phys(entry.addr())) };
        }

        // Allocate a new zeroed child table
        let frame = Self::alloc_zeroed_page_table()?;
        let phys = frame.start_address().as_u64();

        // Install the new table entry (PRESENT + WRITE for intermediate entries)
        parent.set_entry(index, SlPte::new_table(phys));

        unsafe { Ok(Self::table_from_phys(phys)) }
    }

    /// Install page table mapping entries.
    ///
    /// Walks the second-level page table structure, creating intermediate tables
    /// as needed, and installs leaf entries for each 4KB page in the range.
    ///
    /// # Arguments
    ///
    /// * `iova` - IO virtual address start (must be page-aligned)
    /// * `phys` - Physical address start (must be page-aligned)
    /// * `size` - Size in bytes (must be page-aligned)
    /// * `write` - Whether write permission is granted
    ///
    /// # Security
    ///
    /// - R80-2 FIX: Acquires page_table_lock to prevent concurrent mutation
    /// - R80-3 FIX: Respects domain's address_width for correct page table levels
    /// - Rejects superpage entries to prevent unexpected large mappings
    /// - Rejects if leaf entry already present (no silent overwrites)
    /// - R80-4 FIX: Does not set ACCESSED/DIRTY bits (reserved on some hardware)
    fn install_mapping(&self, iova: u64, phys: u64, size: usize, write: bool) -> Result<(), IommuError> {
        // Ensure the root page table exists
        self.ensure_page_table_root()?;

        // R80-2 FIX: Acquire lock for thread-safe page table mutation
        let _pt_guard = self.page_table_lock.lock();

        let root_phys = self.page_table_root.load(Ordering::Acquire);
        if root_phys == 0 {
            return Err(IommuError::PageTableAllocFailed);
        }

        // R80-3 FIX: Determine number of page table levels based on address width
        // 39-bit AGAW = 3 levels (PDPT->PD->PT), 48-bit AGAW = 4 levels (PML4->PDPT->PD->PT)
        let use_4_level = self.address_width >= 48;

        // Build leaf entry flags:
        // - PRESENT: Entry is valid
        // - WRITE: If write permission requested
        // - EXECUTE: Allow device instruction fetches (some devices need this)
        // R80-4 FIX: Don't set ACCESSED/DIRTY - they are reserved on some VT-d hardware
        // Hardware that supports A/D tracking will update these automatically
        let mut flags = SlPteFlags::PRESENT | SlPteFlags::EXECUTE;
        if write {
            flags |= SlPteFlags::WRITE;
        }
        let pte_flags = SlPteFlags::new(flags);

        // R83-1 FIX: Two-phase commit for atomicity
        //
        // Previously, we installed leaf PTEs as we walked the range. If a later
        // page failed (allocation failure, duplicate leaf entry), earlier pages
        // would already be mapped, creating "ghost" mappings with no tracking.
        // These ghost mappings would allow device DMA access to memory that the
        // caller thinks is unmapped, potentially causing memory corruption or
        // information disclosure.
        //
        // Phase 1: Validate all pages and collect staging entries
        // Phase 2: Commit all entries only if validation passes
        //
        // Note: Intermediate tables may still be created during Phase 1 via
        // get_or_create_table, but without leaf entries they don't enable DMA.
        let num_pages = (size + IOMMU_PAGE_SIZE - 1) / IOMMU_PAGE_SIZE;
        let mut staged: alloc::vec::Vec<(*mut SlPageTable, usize, SlPte)> =
            alloc::vec::Vec::with_capacity(num_pages);

        // Phase 1: Walk and validate mappings for each 4KB page
        for offset in (0..size).step_by(IOMMU_PAGE_SIZE) {
            let cur_iova = iova + offset as u64;
            let cur_phys = phys + offset as u64;

            // Extract page table indices from IOVA based on address width
            let l3_idx = ((cur_iova >> 30) & 0x1FF) as usize;
            let l2_idx = ((cur_iova >> 21) & 0x1FF) as usize;
            let l1_idx = ((cur_iova >> IOMMU_PAGE_SHIFT) & 0x1FF) as usize;

            // Get the leaf page table (may create intermediate tables)
            let pt = if use_4_level {
                // 4-level: PML4[47:39] -> PDPT[38:30] -> PD[29:21] -> PT[20:12]
                let l4_idx = ((cur_iova >> 39) & 0x1FF) as usize;
                let pml4 = unsafe { Self::table_from_phys(root_phys) };
                let pdpt = Self::get_or_create_table(pml4, l4_idx)?;
                let pd = Self::get_or_create_table(pdpt, l3_idx)?;
                Self::get_or_create_table(pd, l2_idx)?
            } else {
                // 3-level: PDPT[38:30] -> PD[29:21] -> PT[20:12]
                // Root is the PDPT for 39-bit AGAW
                let pdpt = unsafe { Self::table_from_phys(root_phys) };
                let pd = Self::get_or_create_table(pdpt, l3_idx)?;
                Self::get_or_create_table(pd, l2_idx)?
            };

            // Check if leaf entry already exists (reject to prevent aliasing)
            // R83-1 FIX: Do NOT install the entry yet, just validate
            if pt.entry(l1_idx).is_present() {
                return Err(IommuError::InvalidRange);
            }

            // Stage the leaf entry for commit after all pages are validated
            staged.push((pt as *mut SlPageTable, l1_idx, SlPte::new_leaf(cur_phys, pte_flags)));
        }

        // Phase 2: Commit all staged entries (only reached if all validations passed)
        for (pt_ptr, idx, entry) in staged {
            // SAFETY: pt_ptr is a valid pointer to a SlPageTable obtained from
            // get_or_create_table() in the validation loop above. The page_table_lock
            // is held throughout this function, preventing concurrent modification.
            unsafe { (*pt_ptr).set_entry(idx, entry) };
        }

        // R95-5 FIX: Memory fence to ensure all PTE writes are visible before
        // returning. The caller (map_range in lib.rs) will issue IOTLB invalidation
        // via MMIO writes. While x86 provides strong store ordering (stores are
        // not reordered with other stores), an explicit fence provides:
        // 1. Defense-in-depth for future non-x86 ports
        // 2. Clear documentation of the ordering requirement
        // 3. Ensures PTE writes complete before IOTLB invalidation MMIO
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    /// Clear page table mappings for an IOVA range.
    ///
    /// Walks the page table and clears leaf entries. Does not free intermediate
    /// tables (they may be reused for future mappings).
    ///
    /// # Security
    ///
    /// - R80-2 FIX: Acquires page_table_lock to prevent concurrent mutation
    /// - R80-3 FIX: Respects domain's address_width for correct page table levels
    /// - R80-5 FIX: Checks for and rejects superpage entries to prevent corruption
    ///
    /// # Note
    ///
    /// After calling this, the caller must issue IOTLB invalidation to ensure
    /// hardware doesn't use stale cached translations.
    fn clear_mapping(&self, iova: u64, size: usize) -> Result<(), IommuError> {
        // R80-2 FIX: Acquire lock for thread-safe page table mutation
        let _pt_guard = self.page_table_lock.lock();

        let root_phys = self.page_table_root.load(Ordering::Acquire);
        if root_phys == 0 {
            // No page tables allocated, nothing to clear
            return Ok(());
        }

        // R80-3 FIX: Determine number of page table levels based on address width
        let use_4_level = self.address_width >= 48;

        for offset in (0..size).step_by(IOMMU_PAGE_SIZE) {
            let cur_iova = iova + offset as u64;

            let l3_idx = ((cur_iova >> 30) & 0x1FF) as usize;
            let l2_idx = ((cur_iova >> 21) & 0x1FF) as usize;
            let l1_idx = ((cur_iova >> IOMMU_PAGE_SHIFT) & 0x1FF) as usize;

            // Walk the page table hierarchy (don't create tables during unmap)
            let (pdpt, pd_entry_idx) = if use_4_level {
                let l4_idx = ((cur_iova >> 39) & 0x1FF) as usize;
                let pml4 = unsafe { Self::table_from_phys(root_phys) };

                let l4_entry = pml4.entry(l4_idx);
                if !l4_entry.is_present() {
                    continue; // No PDPT, skip
                }
                // R80-5 FIX: Check for superpage - if PS bit set, this is a 1GB huge page
                if l4_entry.raw() & SL_PTE_SUPERPAGE != 0 {
                    return Err(IommuError::InvalidRange);
                }
                (unsafe { Self::table_from_phys(l4_entry.addr()) }, l3_idx)
            } else {
                // 3-level: root is PDPT
                (unsafe { Self::table_from_phys(root_phys) }, l3_idx)
            };

            let l3_entry = pdpt.entry(pd_entry_idx);
            if !l3_entry.is_present() {
                continue; // No PD, skip
            }
            // R80-5 FIX: Check for superpage - if PS bit set, this is a 1GB huge page
            if l3_entry.raw() & SL_PTE_SUPERPAGE != 0 {
                return Err(IommuError::InvalidRange);
            }
            let pd = unsafe { Self::table_from_phys(l3_entry.addr()) };

            let l2_entry = pd.entry(l2_idx);
            if !l2_entry.is_present() {
                continue; // No PT, skip
            }
            // R80-5 FIX: Check for superpage - if PS bit set, this is a 2MB huge page
            if l2_entry.raw() & SL_PTE_SUPERPAGE != 0 {
                return Err(IommuError::InvalidRange);
            }
            let pt = unsafe { Self::table_from_phys(l2_entry.addr()) };

            // Clear the leaf entry
            pt.set_entry(l1_idx, SlPte::empty());
        }

        // R95-5 FIX: Memory fence to ensure all PTE clears are visible before
        // returning. The caller will issue IOTLB invalidation after this.
        // Same rationale as install_mapping.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        Ok(())
    }
}

// ============================================================================
// Second-Level Page Table Structures
// ============================================================================

/// Second-level page table entry flags (Intel VT-d).
#[derive(Debug, Clone, Copy)]
pub struct SlPteFlags(u64);

impl SlPteFlags {
    /// Entry is present/valid.
    pub const PRESENT: u64 = 1 << 0;
    /// Write permission.
    pub const WRITE: u64 = 1 << 1;
    /// Execute permission (if supported).
    pub const EXECUTE: u64 = 1 << 2;
    /// Accessed flag.
    pub const ACCESSED: u64 = 1 << 8;
    /// Dirty flag.
    pub const DIRTY: u64 = 1 << 9;

    /// Create new flags.
    pub const fn new(flags: u64) -> Self {
        Self(flags)
    }

    /// Get raw value.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.0 & Self::PRESENT != 0
    }

    /// Check if writable.
    pub const fn is_writable(&self) -> bool {
        self.0 & Self::WRITE != 0
    }
}

/// Second-level page table entry.
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct SlPte(u64);

impl SlPte {
    /// Physical address mask (bits 12-51).
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Create an empty (not present) entry.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a leaf entry mapping to physical address.
    pub const fn new_leaf(phys: u64, flags: SlPteFlags) -> Self {
        Self((phys & Self::ADDR_MASK) | flags.bits())
    }

    /// Create an intermediate entry pointing to next level table.
    pub const fn new_table(table_phys: u64) -> Self {
        Self((table_phys & Self::ADDR_MASK) | SlPteFlags::PRESENT | SlPteFlags::WRITE)
    }

    /// Get physical address.
    pub const fn addr(&self) -> u64 {
        self.0 & Self::ADDR_MASK
    }

    /// Get flags.
    pub const fn flags(&self) -> SlPteFlags {
        SlPteFlags::new(self.0 & !Self::ADDR_MASK)
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.0 & SlPteFlags::PRESENT != 0
    }

    /// Get raw value.
    pub const fn raw(&self) -> u64 {
        self.0
    }
}

/// Second-level page table (512 entries, 4KB).
#[repr(C, align(4096))]
pub struct SlPageTable {
    entries: [SlPte; 512],
}

impl SlPageTable {
    /// Create a new empty page table.
    pub const fn new() -> Self {
        Self {
            entries: [SlPte::empty(); 512],
        }
    }

    /// Get entry at index.
    pub fn entry(&self, index: usize) -> SlPte {
        self.entries[index]
    }

    /// Set entry at index.
    pub fn set_entry(&mut self, index: usize, entry: SlPte) {
        self.entries[index] = entry;
    }
}
