//! Unified DMA Buffer Allocation with On-Demand IOMMU Mappings
//!
//! This module provides a unified API for allocating DMA-capable memory with
//! automatic IOMMU mapping support. When an IOMMU is initialized and registered,
//! DMA mappings are installed on-demand for each allocated buffer (instead of
//! pre-mapping large physical regions like 0-1GiB).
//!
//! When no IOMMU is present or initialized, the module falls back to legacy mode
//! where DMA address == physical address with no explicit mapping.
//!
//! # Security Benefits
//!
//! - **On-demand mapping**: Only explicitly allocated DMA buffers are accessible
//!   to devices, preventing DMA attacks against unmapped memory regions.
//! - **Defense-in-depth scrubbing**: Buffers are zeroed on allocation and free
//!   to prevent information leakage.
//! - **Fail-safe behavior**: On mapping failures, memory is scrubbed and leaked
//!   rather than reused under an unknown DMA state.
//!
//! # Usage
//!
//! ```ignore
//! use mm::dma::{alloc_dma_buffer, DmaBuffer};
//!
//! // Allocate a 4KB DMA buffer
//! let buf = alloc_dma_buffer(4096)?;
//!
//! // Get IOVA for device programming
//! let device_addr = buf.iova();
//!
//! // Get CPU-accessible pointer
//! let cpu_ptr = buf.virt_ptr();
//!
//! // Buffer is automatically unmapped and freed on drop
//! drop(buf);
//! ```
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | VirtIO Driver    |     | Network Driver   |
//! +--------+---------+     +--------+---------+
//!          |                        |
//!          v                        v
//! +-------------------------------------------+
//! |            mm::dma::alloc_dma_buffer()    |
//! |   - Allocates physical pages              |
//! |   - Calls IOMMU hooks if registered       |
//! |   - Returns DmaBuffer with iova/phys      |
//! +-------------------------------------------+
//!          |
//!          v (if IOMMU enabled)
//! +-------------------------------------------+
//! |          iommu::map_range()               |
//! |   - Installs SLPT entry for buffer        |
//! |   - Invalidates IOTLB                     |
//! +-------------------------------------------+
//! ```

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use spin::Once;
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::{buddy_allocator, PHYSICAL_MEMORY_OFFSET};

// ============================================================================
// Constants
// ============================================================================

/// IOMMU domain identifier type (matches iommu::DomainId without dependency).
pub type DomainId = u16;

/// DMA page size (4KiB, matching x86_64 page size).
pub const DMA_PAGE_SIZE: usize = 4096;

/// Maximum physical address reachable via the kernel direct-map (1 GiB).
///
/// The kernel's high-half direct map (PHYSICAL_MEMORY_OFFSET) only covers
/// physical addresses 0-1GiB. Allocations beyond this range cannot be accessed
/// by the CPU via `phys_to_virt`, so we reject them.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30; // 1 GiB

// ============================================================================
// Error Types
// ============================================================================

/// DMA allocation and mapping errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// Requested size is zero or would overflow alignment calculations.
    InvalidSize,
    /// Physical memory allocation failed (out of memory).
    NoMem,
    /// Allocated memory landed outside the CPU direct-map window (0-1GiB).
    OutOfDirectMapRange,
    /// IOMMU mapping failed (second-level page table error).
    /// The mapping state is uncertain - pages should be leaked to prevent
    /// a device from accessing reused memory.
    IommuMapFailed,
    /// R95-4 FIX: IOMMU mapping was rejected before any mapping was installed.
    /// This is a "safe" failure where pages can be safely freed because
    /// no IOMMU mapping was ever created. Examples:
    /// - IOMMU not initialized
    /// - Domain not found
    /// - Invalid address range (validation rejected)
    IommuMapRejected,
    /// IOMMU unmapping failed.
    IommuUnmapFailed,
}

// ============================================================================
// IOMMU Hooks (Dependency Inversion)
// ============================================================================

/// IOMMU operations registered by the IOMMU subsystem after successful init.
///
/// This struct uses function pointers to avoid a circular dependency between
/// the `mm` and `iommu` crates. The IOMMU crate registers these hooks during
/// initialization, and the DMA allocator calls them when allocating buffers.
pub struct IommuOps {
    /// Kernel IOMMU domain ID used for DMA isolation.
    pub kernel_domain_id: DomainId,
    /// Map an IOVA range to physical memory in a domain.
    /// Parameters: (domain_id, iova, phys, size, write_allowed)
    pub map_range: fn(DomainId, u64, u64, usize, bool) -> Result<(), DmaError>,
    /// Unmap an IOVA range from a domain.
    /// Parameters: (domain_id, iova, size)
    pub unmap_range: fn(DomainId, u64, usize) -> Result<(), DmaError>,
}

/// Global IOMMU operations registered by the IOMMU subsystem.
///
/// `None` indicates no IOMMU is available (legacy mode).
static IOMMU_OPS: Once<IommuOps> = Once::new();

/// Register IOMMU operations for DMA mapping.
///
/// Called by the IOMMU subsystem once during successful initialization.
/// Subsequent calls are ignored (first registration wins).
pub fn register_iommu_ops(ops: IommuOps) {
    IOMMU_OPS.call_once(|| ops);
}

/// Check if IOMMU operations are registered.
#[inline]
pub fn is_iommu_enabled() -> bool {
    IOMMU_OPS.get().is_some()
}

// ============================================================================
// DmaBuffer
// ============================================================================

/// A physically-contiguous DMA buffer with an (optional) IOMMU mapping.
///
/// When dropped, the buffer is automatically:
/// 1. Unmapped from the IOMMU domain (if IOMMU is enabled)
/// 2. Securely zeroed (defense-in-depth against info leaks)
/// 3. Returned to the physical page allocator
///
/// # Safety
///
/// The buffer owns its physical memory and IOMMU mapping. Callers must not
/// use the physical/IOVA addresses after the buffer is dropped.
///
/// # R95-8 FIX: Device Quiescence Requirement
///
/// **IMPORTANT**: Drivers MUST quiesce their devices before dropping DmaBuffer.
///
/// The Drop implementation unmaps the IOMMU pages, but this only prevents
/// **new** DMA transactions. It does NOT guarantee that **in-flight** DMA
/// transactions have completed. If a device has pending DMA operations when
/// the buffer is dropped:
///
/// 1. In-flight reads may complete after unmap but during scrub (defeating scrub)
/// 2. In-flight writes may corrupt newly-reused memory
///
/// To safely drop a DmaBuffer:
///
/// ```ignore
/// // 1. Disable device DMA (e.g., clear bus master enable, reset device)
/// device.disable_dma();
/// // or
/// device.reset();
///
/// // 2. Memory fence to ensure writes are visible
/// core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
///
/// // 3. Now safe to drop the buffer
/// drop(dma_buffer);
/// ```
///
/// Failure to quiesce the device before dropping DmaBuffer is a driver bug
/// that may result in memory corruption or security vulnerabilities.
#[derive(Debug)]
pub struct DmaBuffer {
    /// Physical address of the buffer (for tracking).
    phys: u64,
    /// IO Virtual Address (device-visible address).
    /// For identity mapping, iova == phys.
    iova: u64,
    /// Allocated size in bytes (page-aligned).
    size: usize,
    /// Domain ID this buffer is mapped in.
    domain_id: DomainId,
}

impl DmaBuffer {
    /// Physical address of the buffer.
    #[inline]
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// IO Virtual Address (device-visible address).
    ///
    /// Use this address when programming device DMA descriptors.
    #[inline]
    pub fn iova(&self) -> u64 {
        self.iova
    }

    /// Allocated size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Domain ID this buffer is mapped in.
    #[inline]
    pub fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// CPU-accessible pointer to the start of the buffer.
    ///
    /// This uses the kernel's direct-map (PHYSICAL_MEMORY_OFFSET) to convert
    /// the physical address to a virtual address.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid only while the DmaBuffer is alive.
    /// Callers must not dereference the pointer after drop().
    #[inline]
    pub fn virt_ptr(&self) -> *mut u8 {
        (self.phys + PHYSICAL_MEMORY_OFFSET) as *mut u8
    }

    /// Get a mutable slice covering the entire buffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent device DMA is accessing the buffer.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.virt_ptr(), self.size)
    }

    /// Get a slice covering the entire buffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent device DMA is writing to the buffer.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.virt_ptr(), self.size)
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        if self.size == 0 {
            return;
        }

        let pages = self.size / DMA_PAGE_SIZE;
        if pages == 0 {
            return;
        }

        // Calculate actual allocation size (buddy allocator rounds up to power-of-two).
        // R96-7 FIX: Check for next_power_of_two overflow.
        // When pages > isize::MAX, next_power_of_two() returns 0 due to overflow.
        // This would cause alloc_bytes to be 0, leading to incorrect behavior.
        let alloc_pages = pages.next_power_of_two();
        if alloc_pages == 0 {
            // Overflow in next_power_of_two - should never happen with valid buffers.
            // Scrub and leak pages to be safe.
            scrub_range(self.phys, self.size);
            return;
        }
        let alloc_bytes = match alloc_pages.checked_mul(DMA_PAGE_SIZE) {
            Some(b) => b,
            None => return, // Overflow - leak the pages (shouldn't happen)
        };

        // Step 1: Unmap from IOMMU domain first (prevents DMA into freed memory).
        if let Some(ops) = IOMMU_OPS.get() {
            if let Err(_) = (ops.unmap_range)(self.domain_id, self.iova, self.size) {
                // IOMMU unmap failed - scrub and leak pages to prevent reuse
                // under an unknown DMA state. This is fail-safe behavior.
                scrub_range(self.phys, alloc_bytes);
                kprintln!(
                    "[DMA] WARNING: IOMMU unmap failed for iova={:#x} size={}, leaking pages",
                    self.iova, self.size
                );
                return;
            }
        }

        // Step 2: Scrub the buffer (defense-in-depth against info leaks).
        scrub_range(self.phys, alloc_bytes);

        // Step 3: Return pages to the allocator.
        let frame = PhysFrame::containing_address(PhysAddr::new(self.phys));
        buddy_allocator::free_physical_pages(frame, pages);
    }
}

// ============================================================================
// Allocation API
// ============================================================================

/// Align a value up to the specified alignment.
#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}

/// Securely zero a physical memory range using volatile writes.
///
/// Uses volatile writes and a compiler fence to ensure the zeroing is not
/// optimized away by the compiler.
#[inline]
fn scrub_range(phys: u64, bytes: usize) {
    let virt = (phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;
    unsafe {
        for i in 0..bytes {
            ptr::write_volatile(virt.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Allocate a DMA buffer of at least `size` bytes.
///
/// The returned buffer:
/// - Has its size rounded up to 4KiB alignment
/// - Is zeroed (defense-in-depth)
/// - Is mapped into the kernel IOMMU domain (if IOMMU is enabled)
/// - Uses identity IOVA mapping (iova == phys) for simplicity
///
/// # Arguments
///
/// * `size` - Minimum buffer size in bytes (must be > 0)
///
/// # Returns
///
/// * `Ok(DmaBuffer)` - Successfully allocated and mapped buffer
/// * `Err(DmaError)` - Allocation or mapping failed
///
/// # Security
///
/// - On-demand mapping: Only this buffer is accessible to devices, not all
///   of the 0-1GiB region.
/// - Fail-safe: On mapping failure, memory is scrubbed and leaked (not reused).
/// - Scrubbed: Buffer is always zeroed before returning.
pub fn alloc_dma_buffer(size: usize) -> Result<DmaBuffer, DmaError> {
    if size == 0 {
        return Err(DmaError::InvalidSize);
    }

    // Round up to page alignment.
    let size = align_up(size, DMA_PAGE_SIZE).ok_or(DmaError::InvalidSize)?;
    let pages = size / DMA_PAGE_SIZE;
    if pages == 0 {
        return Err(DmaError::InvalidSize);
    }

    // Allocate physical pages from the buddy allocator.
    let frame = buddy_allocator::alloc_physical_pages(pages).ok_or(DmaError::NoMem)?;
    let phys = frame.start_address().as_u64();

    // Buddy allocator rounds up to power-of-two pages.
    // R96-7 FIX: Check for next_power_of_two overflow.
    // When pages > isize::MAX, next_power_of_two() returns 0 due to overflow.
    let alloc_pages = pages.next_power_of_two();
    if alloc_pages == 0 {
        // Overflow in next_power_of_two - free and fail.
        buddy_allocator::free_physical_pages(frame, pages);
        return Err(DmaError::InvalidSize);
    }
    let alloc_bytes = alloc_pages
        .checked_mul(DMA_PAGE_SIZE)
        .ok_or_else(|| {
            buddy_allocator::free_physical_pages(frame, pages);
            DmaError::InvalidSize
        })?;

    // Verify the allocation is within the CPU direct-map range.
    let end = phys
        .checked_add(alloc_bytes as u64 - 1)
        .ok_or(DmaError::InvalidSize)?;
    if end >= MAX_DIRECT_MAP_PHYS {
        // Allocation landed outside direct-map window - free and fail.
        buddy_allocator::free_physical_pages(frame, pages);
        return Err(DmaError::OutOfDirectMapRange);
    }

    // Always zero the buffer on allocation (defense-in-depth).
    scrub_range(phys, alloc_bytes);

    // Identity IOVA strategy: keep driver-facing DMA addresses unchanged.
    // This simplifies driver code since iova == phys.
    let iova = phys;
    let domain_id = IOMMU_OPS
        .get()
        .map(|ops| ops.kernel_domain_id)
        .unwrap_or(0);

    // On-demand IOMMU mapping (only if IOMMU ops registered).
    if let Some(ops) = IOMMU_OPS.get() {
        if let Err(e) = (ops.map_range)(domain_id, iova, phys, size, true) {
            // Always scrub before handling error
            scrub_range(phys, alloc_bytes);

            // R95-4 FIX: Classify error and decide whether to free or leak pages
            match e {
                DmaError::IommuMapRejected => {
                    // Safe error: no mapping was installed, we can free the pages
                    kprintln!(
                        "[DMA] INFO: IOMMU map rejected for phys={:#x} size={}, freeing pages",
                        phys, size
                    );
                    buddy_allocator::free_physical_pages(frame, pages);
                }
                DmaError::IommuMapFailed | _ => {
                    // Unsafe error: mapping state uncertain, must leak pages
                    // to prevent device from accessing reused memory
                    kprintln!(
                        "[DMA] WARNING: IOMMU map failed for phys={:#x} size={}, leaking pages",
                        phys, size
                    );
                }
            }
            return Err(e);
        }
    }

    Ok(DmaBuffer {
        phys,
        iova,
        size,
        domain_id,
    })
}

/// Explicit free API for callers that prefer it over implicit drop.
///
/// This is equivalent to `drop(buf)`.
#[inline]
pub fn free_dma_buffer(buf: DmaBuffer) {
    drop(buf);
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics about DMA allocation.
pub fn stats() -> DmaStats {
    DmaStats {
        iommu_enabled: is_iommu_enabled(),
    }
}

/// DMA subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct DmaStats {
    /// Whether IOMMU-backed allocation is active.
    pub iommu_enabled: bool,
}
