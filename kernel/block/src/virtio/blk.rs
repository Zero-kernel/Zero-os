//! VirtIO Block Device Driver for Zero-OS
//!
//! This module implements a virtio-blk driver supporting both MMIO and PCI transports.
//! It provides a simple synchronous interface for block I/O.
//!
//! # Features
//! - MMIO transport for embedded/virtio-mmio setups
//! - PCI modern transport for standard x86 VMs
//! - Synchronous read/write operations
//! - Proper feature negotiation
//! - Integration with Block Layer

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use mm::dma::{alloc_dma_buffer, DmaBuffer};

use super::{
    blk_features, blk_status, blk_types, mb, rmb, wmb, MmioTransport, VirtioBlkConfig,
    VirtioBlkReqHeader, VirtioPciAddrs, VirtioPciTransport, VirtioTransport, VringAvail, VringDesc,
    VringUsed, VringUsedElem, VIRTIO_DEVICE_BLK, VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE,
    VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK,
    VIRTIO_VERSION_LEGACY, VIRTIO_VERSION_MODERN, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
};
use crate::{Bio, BioOp, BioResult, BioVec, BlockDevice, BlockError};

// ============================================================================
// Constants
// ============================================================================

/// Default queue size.
const DEFAULT_QUEUE_SIZE: u16 = 128;

/// Maximum pending requests.
const MAX_PENDING: usize = 64;

// ============================================================================
// R37-3 FIX (Codex review): Timeout Resource Tracking
// ============================================================================
//
// KNOWN LIMITATION: When a request times out, we keep DMA buffers pinned to
// prevent UAF (device may complete later, DMAing into freed memory). However,
// this leaks resources permanently. A proper fix requires a device reset path
// to safely reclaim the descriptors and buffers.
//
// FIXME: Implement virtio-blk device reset to recover from timeouts without
// leaking resources. This counter tracks how many resources are leaked.
use core::sync::atomic::AtomicUsize;
static TIMEOUT_LEAKED_REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// Get the number of requests that have leaked due to timeouts.
/// Each leaked request holds: 3 descriptors + header buffer + status buffer + data buffer.
pub fn timeout_leaked_count() -> usize {
    TIMEOUT_LEAKED_REQUESTS.load(Ordering::Relaxed)
}

// ============================================================================
// DMA Address Translation (R28-1 Fix)
// ============================================================================

/// Translate a kernel virtual address to a DMA-safe physical address.
///
/// **NOTE**: This function only works correctly for addresses in the direct-mapped
/// kernel region (PHYSICAL_MEMORY_OFFSET). It does NOT work for heap allocations
/// which are mapped via the page table at different physical addresses.
/// For heap buffers, use `alloc_dma_memory` to get physically contiguous DMA-safe memory.
///
/// # Arguments
/// * `ptr` - Virtual address pointer
/// * `len` - Length of the buffer (must be > 0)
///
/// # Returns
/// Physical address suitable for DMA, or BlockError::Invalid if translation fails.
///
/// # Safety
/// The caller must ensure the buffer is in kernel address space (high-half direct map).
#[allow(dead_code)]
fn virt_to_phys_dma(ptr: *const u8, len: usize) -> Result<u64, BlockError> {
    if len == 0 {
        return Err(BlockError::Invalid);
    }

    let virt = ptr as u64;

    // Kernel high-half direct map: 0xffffffff80000000 -> physical 0x0
    // This covers the first 1GB of physical memory where kernel allocations reside.
    const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

    // Verify the address is in the expected kernel range
    if virt < PHYSICAL_MEMORY_OFFSET {
        // Address is not in kernel direct map - this is a programming error
        // User-space buffers should never reach here
        return Err(BlockError::Invalid);
    }

    let phys = virt - PHYSICAL_MEMORY_OFFSET;

    // Overflow check: ensure the entire buffer is within valid physical memory
    // The direct map covers 0-1GB (0x0 to 0x40000000)
    let end = phys
        .checked_add(len as u64 - 1)
        .ok_or(BlockError::Invalid)?;
    if end >= 0x4000_0000 {
        // Beyond direct map coverage - likely an error
        return Err(BlockError::Invalid);
    }

    Ok(phys)
}

// ============================================================================
// VirtQueue Implementation
// ============================================================================

/// A single virtqueue for the device.
pub struct VirtQueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Queue notify offset (for PCI transport).
    notify_off: u16,
    /// Descriptor table (DMA-able memory).
    desc: *mut VringDesc,
    /// Available ring.
    avail: *mut VringAvail,
    /// Used ring.
    used: *mut VringUsed,
    /// Free descriptor list (simple stack).
    free_head: AtomicU16,
    /// Free descriptor stack.
    free_list: Mutex<Vec<u16>>,
    /// R66-6 FIX: Allocation bitmap for double-free detection.
    /// True = descriptor is allocated, False = descriptor is free.
    alloc_bitmap: Mutex<Vec<bool>>,
    /// Last seen used index.
    last_used_idx: AtomicU16,
    /// Physical address of descriptor table.
    desc_phys: u64,
    /// Physical address of available ring.
    avail_phys: u64,
    /// Physical address of used ring.
    used_phys: u64,
}

// SAFETY: VirtQueue contains raw pointers to DMA-able memory
// which is only accessed within synchronized contexts.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate the size needed for a virtqueue.
    fn calc_size(queue_size: u16) -> usize {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize; // flags + idx + ring
        let used_size = 4 + 8 * queue_size as usize; // flags + idx + ring

        // Align each section to 4KB for DMA
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;
        let used_pages = (used_size + 4095) / 4096;

        (desc_pages + avail_pages + used_pages) * 4096
    }

    /// Create a new virtqueue at the given physical address.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid and DMA-able.
    /// DMA memory is accessed via the kernel's high-half mapping (PHYSICAL_MEMORY_OFFSET).
    unsafe fn new(base_phys: u64, queue_size: u16, _virt_offset: u64, notify_off: u16) -> Self {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize;

        // Calculate aligned offsets
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;

        let desc_phys = base_phys;
        let avail_phys = desc_phys + (desc_pages * 4096) as u64;
        let used_phys = avail_phys + (avail_pages * 4096) as u64;

        // Convert to virtual addresses using kernel's high-half mapping
        // DMA memory from buddy allocator uses PHYSICAL_MEMORY_OFFSET, not the MMIO virt_offset
        let desc = (desc_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringDesc;
        let avail = (avail_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringAvail;
        let used = (used_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringUsed;

        // Initialize free list
        let mut free_list = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_list.push(i);
        }

        // R66-3 FIX: Zero out entire ring structures, not just 1 byte.
        // Previously only 1 byte was zeroed, leaving uninitialized memory
        // exposed to device DMA (info leak) and causing random ring state.
        core::ptr::write_bytes(desc, 0, queue_size as usize);
        // avail ring: flags(2) + idx(2) + ring[queue_size](2*N) + used_event(2)
        let avail_bytes = 4 + 2 * queue_size as usize + 2;
        core::ptr::write_bytes(avail as *mut u8, 0, avail_bytes);
        // used ring: flags(2) + idx(2) + ring[queue_size](8*N) + avail_event(2)
        let used_bytes = 4 + 8 * queue_size as usize + 2;
        core::ptr::write_bytes(used as *mut u8, 0, used_bytes);

        // R66-6 FIX: Initialize allocation bitmap (all false = all free initially)
        let alloc_bitmap = vec![false; queue_size as usize];

        Self {
            size: queue_size,
            notify_off,
            desc,
            avail,
            used,
            free_head: AtomicU16::new(0),
            free_list: Mutex::new(free_list),
            alloc_bitmap: Mutex::new(alloc_bitmap),
            last_used_idx: AtomicU16::new(0),
            desc_phys,
            avail_phys,
            used_phys,
        }
    }

    /// Allocate a descriptor from the free list.
    /// R66-6 FIX: Track allocation in bitmap for double-free detection.
    fn alloc_desc(&self) -> Option<u16> {
        let mut alloc = self.alloc_bitmap.lock();
        let mut free = self.free_list.lock();
        let idx = free.pop()?;
        // Mark as allocated
        if let Some(slot) = alloc.get_mut(idx as usize) {
            *slot = true;
        }
        Some(idx)
    }

    /// Free a descriptor back to the free list.
    /// R66-6 FIX: Check bitmap to detect and prevent double-free.
    fn free_desc(&self, idx: u16) {
        // Bounds check
        if idx >= self.size {
            kprintln!(
                "[virtio-blk] R66-6: free_desc called with OOB index {}",
                idx
            );
            return;
        }

        // Check allocation bitmap - prevent double-free
        {
            let mut alloc = self.alloc_bitmap.lock();
            if let Some(slot) = alloc.get_mut(idx as usize) {
                if !*slot {
                    // Already free - double-free attempt detected
                    kprintln!(
                        "[virtio-blk] R66-6 SECURITY: double-free detected for descriptor {}",
                        idx
                    );
                    return;
                }
                // Mark as free
                *slot = false;
            } else {
                return; // Index out of bounds
            }
        }

        // Now safe to push back to free list
        self.free_list.lock().push(idx);
    }

    /// Get available descriptor count.
    fn available_descs(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Push a descriptor chain to the available ring.
    unsafe fn push_avail(&self, head: u16) {
        let avail = &mut *self.avail;
        let idx = read_volatile(&avail.idx);
        let ring_idx = (idx % self.size) as usize;

        // Write to ring
        let ring_ptr = avail.ring.as_mut_ptr();
        write_volatile(ring_ptr.add(ring_idx), head);

        // Memory barrier before updating idx
        wmb();

        // Update index
        write_volatile(&mut avail.idx, idx.wrapping_add(1));
    }

    /// Check if there are used entries to process.
    fn has_used(&self) -> bool {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);
            used_idx != last
        }
    }

    /// Pop a used entry.
    /// R66-5 FIX: Validate used.idx to detect malicious device behavior:
    /// - Large jumps (more entries than queue size)
    /// - Rollback attacks (used_idx going backwards)
    fn pop_used(&self) -> Option<VringUsedElem> {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);

            if used_idx == last {
                return None;
            }

            // R66-5 FIX: Calculate pending entries with wrapping arithmetic
            // pending = used_idx - last (handling u16 wrap)
            let pending = used_idx.wrapping_sub(last);

            // R66-5 FIX: Validate that pending entries don't exceed queue size
            // A malicious device could set used_idx to arbitrary values
            if pending > self.size {
                // Possible attack: device reported too many completions or rolled back
                kprintln!(
                    "[virtio-blk] R66-5 SECURITY: invalid used.idx jump detected! \
                     used_idx={}, last={}, pending={}, size={}",
                    used_idx, last, pending, self.size
                );
                // Reset last_used_idx to used_idx to prevent infinite loop
                // but don't process any entries
                self.last_used_idx.store(used_idx, Ordering::Relaxed);
                return None;
            }

            rmb();

            let ring_idx = (last % self.size) as usize;
            let ring_ptr = used.ring.as_ptr();
            let elem = read_volatile(ring_ptr.add(ring_idx));

            // R66-5 FIX: Validate that the returned descriptor ID is within bounds
            if elem.id >= self.size as u32 {
                kprintln!(
                    "[virtio-blk] R66-5 SECURITY: invalid used.id={} exceeds queue size={}",
                    elem.id, self.size
                );
                // Skip this invalid entry
                self.last_used_idx
                    .store(last.wrapping_add(1), Ordering::Relaxed);
                return None;
            }

            self.last_used_idx
                .store(last.wrapping_add(1), Ordering::Relaxed);

            Some(elem)
        }
    }

    /// Get descriptor at index.
    unsafe fn desc(&self, idx: u16) -> &mut VringDesc {
        &mut *self.desc.add(idx as usize)
    }
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// VirtIO block device.
pub struct VirtioBlkDevice {
    /// Device name.
    name: String,
    /// Transport layer (MMIO or PCI).
    transport: VirtioTransport,
    /// R105-3 FIX: Owned DMA buffer for virtqueue memory.
    /// Keeps the IOMMU mapping alive for the device's lifetime without mem::forget.
    /// Field is intentionally never read — held purely for RAII lifetime management.
    #[allow(dead_code)]
    virtqueue_dma: DmaBuffer,
    /// Virtqueue for requests.
    queue: VirtQueue,
    /// Device capacity in sectors.
    capacity: u64,
    /// Sector size.
    sector_size: u32,
    /// Read-only flag.
    read_only: bool,
    /// Negotiated features.
    features: u64,
    /// Lock for synchronous operations.
    lock: Mutex<()>,
    /// Request buffers (header + status).
    req_buffers: Mutex<Vec<RequestBuffer>>,
}

/// Buffer for a single request.
struct RequestBuffer {
    /// Request header.
    header: VirtioBlkReqHeader,
    /// Status byte.
    status: u8,
    /// In use flag.
    in_use: bool,
    /// R39-1 FIX: In-flight tracking metadata for safe completion handling.
    pending: Option<RequestMeta>,
}

/// R39-1 FIX: Metadata tracked per in-flight request to safely pair completions.
///
/// This structure stores all information needed to correctly free resources
/// when a completion arrives, preventing UAF on stale completions.
///
/// R94-13 Enhancement: Uses DmaBuffer for automatic IOMMU mapping management.
/// When DmaBuffer is dropped, the IOMMU mapping is automatically removed.
struct RequestMeta {
    /// Head descriptor index (matches used.id from the device).
    head: u16,
    /// Descriptor indices used by this request.
    desc_chain: [u16; 3],
    /// Number of valid descriptors in desc_chain.
    desc_count: usize,
    /// DMA buffer for header + status (replaces raw phys/virt addresses).
    header_status_dma: DmaBuffer,
    /// Size of the request header in bytes.
    header_size: usize,
    /// Request kind (I/O or flush) with data buffer tracking.
    kind: RequestKind,
    /// Marked when timed out so late completions are treated as stale.
    abandoned: bool,
}

/// R39-1 FIX: Type of request for proper resource cleanup.
/// R94-13 Enhancement: Uses DmaBuffer for automatic IOMMU unmapping on drop.
enum RequestKind {
    /// I/O request (read or write) with data buffer.
    Io {
        /// DMA buffer for data (with automatic IOMMU mapping).
        data_dma: DmaBuffer,
        /// Actual data length in bytes (may be less than data_dma.size() which is page-aligned).
        /// R94-13 FIX: Must track separately to avoid OOB copy on completion.
        data_len: usize,
        /// Pointer to caller's buffer for copy-back on read completion.
        data_buf: *mut u8,
        /// Whether this is a write operation.
        is_write: bool,
    },
    /// Flush request (no data buffer).
    Flush,
}

/// R39-1 FIX: Completion result types.
enum RequestCompletion {
    /// I/O request completed with result.
    Io(Result<usize, BlockError>),
    /// Flush request completed with result.
    Flush(Result<(), BlockError>),
}

// SAFETY: VirtioBlkDevice is designed for single-threaded access
// with internal locking for synchronization.
unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    /// Probe for a virtio-blk device using MMIO transport.
    ///
    /// # Arguments
    /// * `mmio_phys` - Physical address of the MMIO region
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO address is valid and mapped.
    pub unsafe fn probe_mmio(
        mmio_phys: u64,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = MmioTransport::probe(mmio_phys, virt_offset).ok_or(BlockError::NotFound)?;
        Self::probe_with_transport(VirtioTransport::Mmio(transport), virt_offset, name)
    }

    /// Probe for a virtio-blk device using virtio-pci modern transport.
    ///
    /// # Arguments
    /// * `pci_addrs` - Parsed PCI capability addresses
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO windows are mapped (identity mapped low memory).
    pub unsafe fn probe_pci(
        pci_addrs: VirtioPciAddrs,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = VirtioPciTransport::from_addrs(pci_addrs, virt_offset)
            .ok_or(BlockError::NotSupported)?;
        Self::probe_with_transport(VirtioTransport::Pci(transport), virt_offset, name)
    }

    /// Common probe logic for any transport.
    unsafe fn probe_with_transport(
        transport: VirtioTransport,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // Check device type
        let device_id = transport.device_id();
        if device_id != VIRTIO_DEVICE_BLK {
            return Err(BlockError::NotFound);
        }

        // Check version
        let version = transport.version();
        if version != VIRTIO_VERSION_LEGACY && version != VIRTIO_VERSION_MODERN {
            return Err(BlockError::NotSupported);
        }

        Self::init_device(transport, virt_offset, name)
    }

    /// Initialize the device.
    unsafe fn init_device(
        transport: VirtioTransport,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // Reset device
        transport.reset();
        mb();

        // Acknowledge device
        transport.set_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // Set DRIVER status
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_DRIVER);

        // Read device features
        let device_features = transport.device_features();

        // Select features we want
        let mut driver_features = 0u64;
        // Modern virtio devices (1.0+) require VIRTIO_F_VERSION_1 to be acknowledged
        if device_features & VIRTIO_F_VERSION_1 != 0 {
            driver_features |= VIRTIO_F_VERSION_1;
        }
        if device_features & blk_features::VIRTIO_BLK_F_RO != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_RO;
        }
        if device_features & blk_features::VIRTIO_BLK_F_FLUSH != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_FLUSH;
        }
        if device_features & blk_features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_BLK_SIZE;
        }

        // Write driver features
        transport.write_driver_features(driver_features);

        // Set FEATURES_OK
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_FEATURES_OK);

        // Verify FEATURES_OK
        let status = transport.status();
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            return Err(BlockError::NotSupported);
        }

        // Read device config using the generic read_config_struct method
        let config: VirtioBlkConfig = transport.read_config_struct();
        let capacity = config.capacity;
        let sector_size = if config.blk_size != 0 {
            config.blk_size
        } else {
            512
        };
        let read_only = driver_features & blk_features::VIRTIO_BLK_F_RO != 0;

        // Setup queue 0
        let queue_size_max = transport.queue_max(0);
        let queue_size = queue_size_max.min(DEFAULT_QUEUE_SIZE);

        if queue_size == 0 {
            return Err(BlockError::NotSupported);
        }

        // Allocate queue memory (simplified: use high physical memory)
        // In a real implementation, this would use a proper DMA allocator
        let queue_mem_size = VirtQueue::calc_size(queue_size);
        // R105-3 FIX: Keep DmaBuffer ownership instead of extracting phys + forget.
        let virtqueue_dma = Self::alloc_dma_memory(queue_mem_size)?;
        let queue_phys = virtqueue_dma.phys();

        // Get notify offset for PCI transport
        let notify_off = transport.queue_notify_off(0);

        // Create virtqueue
        let queue = VirtQueue::new(queue_phys, queue_size, virt_offset, notify_off);

        // Configure queue
        transport.setup_queue(
            0,
            queue_size,
            queue.desc_phys,
            queue.avail_phys,
            queue.used_phys,
        );
        transport.queue_ready(0, true);

        // Set DRIVER_OK
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_DRIVER_OK);

        // Create request buffers
        let mut req_buffers = Vec::with_capacity(MAX_PENDING);
        for _ in 0..MAX_PENDING {
            req_buffers.push(RequestBuffer {
                header: VirtioBlkReqHeader::default(),
                status: 0,
                in_use: false,
                pending: None, // R39-1 FIX: Initialize pending metadata
            });
        }

        Ok(Arc::new(Self {
            name: String::from(name),
            transport,
            virtqueue_dma,
            queue,
            capacity,
            sector_size,
            read_only,
            features: driver_features,
            lock: Mutex::new(()),
            req_buffers: Mutex::new(req_buffers),
        }))
    }

    /// Allocate DMA-able memory using the unified DMA allocator with IOMMU mapping.
    ///
    /// R105-3 FIX: Returns the `DmaBuffer` directly so ownership can be retained
    /// by the caller, avoiding `core::mem::forget` and ensuring the IOMMU mapping
    /// is automatically cleaned up when the device is dropped.
    fn alloc_dma_memory(size: usize) -> Result<DmaBuffer, BlockError> {
        alloc_dma_buffer(size).map_err(|_| BlockError::NoMem)
    }

    /// Notify the device of new available descriptors.
    fn notify(&self) {
        unsafe {
            self.transport.notify(0, self.queue.notify_off);
        }
    }

    /// R39-1 FIX: Match a used ring entry to the correct request and complete it.
    ///
    /// This method finds the request that corresponds to the given `used.id`,
    /// frees its resources correctly, and returns the completion result.
    /// For abandoned (timed-out) requests, it cleans up silently and returns None.
    ///
    /// R94-13 Enhancement: DmaBuffer is now dropped automatically when RequestMeta
    /// goes out of scope, ensuring IOMMU mappings are cleaned up properly.
    fn complete_used_entry(&self, used: VringUsedElem) -> Option<RequestCompletion> {
        let mut buffers = self.req_buffers.lock();

        // Find the request buffer matching this completion's head descriptor
        let (_idx, buffer) = match buffers.iter_mut().enumerate().find(|(_, b)| {
            b.in_use
                && b.pending
                    .as_ref()
                    .map(|meta| meta.head as u32 == used.id)
                    .unwrap_or(false)
        }) {
            Some(entry) => entry,
            None => {
                kprintln!(
                    "[virtio-blk] completion for unknown descriptor head={} ignored",
                    used.id
                );
                return None;
            }
        };

        // Take ownership of the metadata (DmaBuffers will be dropped when meta goes out of scope)
        let meta = match buffer.pending.take() {
            Some(m) => m,
            None => {
                kprintln!(
                    "[virtio-blk] completion for descriptor head={} without metadata",
                    used.id
                );
                return None;
            }
        };

        let RequestMeta {
            head,
            desc_chain,
            desc_count,
            header_status_dma,
            header_size,
            kind,
            abandoned,
        } = meta;

        // Read status from DMA buffer
        let status = unsafe { core::ptr::read(header_status_dma.virt_ptr().add(header_size)) };

        // Process based on request kind
        let completion = match kind {
            RequestKind::Io {
                data_dma,
                data_len,
                data_buf,
                is_write,
            } => {
                // For successful reads on non-abandoned requests, copy data back
                // R94-13 FIX: Use data_len (actual buffer size) not data_dma.size() (page-aligned)
                if !abandoned
                    && status == blk_status::VIRTIO_BLK_S_OK
                    && !is_write
                    && data_len > 0
                {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data_dma.virt_ptr(),
                            data_buf,
                            data_len,
                        );
                    }
                }

                if abandoned {
                    None
                } else {
                    Some(RequestCompletion::Io(match status {
                        blk_status::VIRTIO_BLK_S_OK => Ok(data_len),
                        blk_status::VIRTIO_BLK_S_IOERR => Err(BlockError::Io),
                        blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                        _ => Err(BlockError::Io),
                    }))
                }
                // data_dma is dropped here, automatically unmapping from IOMMU
            }
            RequestKind::Flush => {
                if abandoned {
                    None
                } else {
                    Some(RequestCompletion::Flush(match status {
                        blk_status::VIRTIO_BLK_S_OK => Ok(()),
                        blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                        _ => Err(BlockError::Io),
                    }))
                }
            }
        };

        // Free descriptors back to the pool
        for idx in desc_chain.iter().take(desc_count) {
            self.queue.free_desc(*idx);
        }

        // DmaBuffers (header_status_dma and data_dma if I/O) are automatically
        // dropped here, which triggers IOMMU unmapping via DmaBuffer::drop()

        // Release the request buffer slot
        buffer.in_use = false;

        // Handle abandoned requests (late completions)
        if abandoned {
            // Decrement leaked counter since we've now recovered the resources
            let _ =
                TIMEOUT_LEAKED_REQUESTS
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            kprintln!(
                "[virtio-blk] late completion for abandoned request head={} status={}",
                head, status
            );
            return None;
        }

        completion
    }

    /// Process a single synchronous request.
    fn do_request(&self, sector: u64, buf: &mut [u8], is_write: bool) -> Result<usize, BlockError> {
        if is_write && self.read_only {
            return Err(BlockError::ReadOnly);
        }

        // R28-2 Fix: Validate buffer alignment and capacity bounds
        // R32-BLK-1 FIX: Use consistent byte-based bounds checking
        // VirtIO spec: capacity is always in 512-byte sectors, but blk_size may differ
        if buf.is_empty() {
            return Err(BlockError::Invalid);
        }
        // R32-BLK-1 additional hardening: prevent u32 wrap in descriptor length
        if buf.len() > u32::MAX as usize {
            return Err(BlockError::Invalid);
        }
        const VIRTIO_CAPACITY_SECTOR_SIZE: u64 = 512;
        let sector_size = self.sector_size as u64;
        let buf_len = buf.len() as u64;

        // Buffer must be aligned to logical sector size
        if buf_len % sector_size != 0 {
            return Err(BlockError::Invalid);
        }

        // Convert to byte offsets for consistent bounds checking
        let start_byte = sector.checked_mul(sector_size).ok_or(BlockError::Invalid)?;
        let end_byte = start_byte.checked_add(buf_len).ok_or(BlockError::Invalid)?;
        let capacity_bytes = self
            .capacity
            .checked_mul(VIRTIO_CAPACITY_SECTOR_SIZE)
            .ok_or(BlockError::Invalid)?;

        // Start must be aligned to 512-byte boundary for VirtIO header
        if start_byte % VIRTIO_CAPACITY_SECTOR_SIZE != 0 {
            return Err(BlockError::Invalid);
        }

        // End must not exceed device capacity
        if end_byte > capacity_bytes {
            return Err(BlockError::Invalid);
        }

        // Calculate sector in 512-byte units for VirtIO request header
        let header_sector = start_byte / VIRTIO_CAPACITY_SECTOR_SIZE;

        let _lock = self.lock.lock();

        // Get a request buffer
        let buf_idx = {
            let mut buffers = self.req_buffers.lock();
            let idx = buffers.iter().position(|b| !b.in_use);
            match idx {
                Some(i) => {
                    buffers[i].in_use = true;
                    buffers[i].header.req_type = if is_write {
                        blk_types::VIRTIO_BLK_T_OUT
                    } else {
                        blk_types::VIRTIO_BLK_T_IN
                    };
                    buffers[i].header.reserved = 0;
                    buffers[i].header.sector = header_sector; // R32-BLK-1: Use 512-byte sector units
                    buffers[i].status = 0xFF; // Invalid status
                    i
                }
                None => return Err(BlockError::Busy),
            }
        };

        // DMA bounce buffer for header/status with on-demand IOMMU mapping (R94-13)
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let header_status_dma_size = if header_size + 1 < 32 {
            32
        } else {
            header_size + 1
        };
        let header_status_dma = match alloc_dma_buffer(header_status_dma_size) {
            Ok(buf) => buf,
            Err(_) => {
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // Copy header to DMA buffer and initialize status to 0xFF (invalid)
        unsafe {
            let header = {
                let buffers = self.req_buffers.lock();
                buffers[buf_idx].header
            };
            core::ptr::write(header_status_dma.virt_ptr() as *mut VirtioBlkReqHeader, header);
            core::ptr::write(header_status_dma.virt_ptr().add(header_size), 0xFFu8);
        }
        let header_phys = header_status_dma.phys();
        let status_phys = header_status_dma.phys() + header_size as u64;

        // DMA bounce buffer for data with on-demand IOMMU mapping (R94-13)
        let data_dma = match alloc_dma_buffer(buf.len()) {
            Ok(dma) => dma,
            Err(_) => {
                // header_status_dma is dropped automatically here, unmapping from IOMMU
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // For writes: copy from caller buffer into DMA buffer before I/O
        if is_write {
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), data_dma.virt_ptr(), buf.len());
            }
        }

        // Allocate 3 descriptors
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc2 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                self.queue.free_desc(desc1);
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };

        unsafe {
            // Descriptor 0: Header (device reads)
            let d0 = self.queue.desc(desc0);
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = VRING_DESC_F_NEXT;
            d0.next = desc1;

            // Descriptor 1: Data buffer (use DMA bounce buffer)
            let d1 = self.queue.desc(desc1);
            d1.addr = data_dma.phys();
            d1.len = buf.len() as u32;
            d1.flags = VRING_DESC_F_NEXT | if is_write { 0 } else { VRING_DESC_F_WRITE };
            d1.next = desc2;

            // Descriptor 2: Status (device writes)
            let d2 = self.queue.desc(desc2);
            d2.addr = status_phys;
            d2.len = 1;
            d2.flags = VRING_DESC_F_WRITE;
            d2.next = 0;
        }

        // R39-1 FIX: Store request metadata BEFORE pushing to available ring
        // R94-13: DmaBuffers are moved into RequestMeta, ownership transferred
        {
            let mut buffers = self.req_buffers.lock();
            buffers[buf_idx].pending = Some(RequestMeta {
                head: desc0,
                desc_chain: [desc0, desc1, desc2],
                desc_count: 3,
                header_status_dma,
                header_size,
                kind: RequestKind::Io {
                    data_dma,
                    data_len: buf.len(), // R94-13 FIX: Track actual buffer length
                    data_buf: buf.as_mut_ptr(),
                    is_write,
                },
                abandoned: false,
            });
        }

        unsafe {
            // Push to available ring
            self.queue.push_avail(desc0);
        }

        // Notify device
        mb();
        self.notify();

        // R39-1 FIX: Poll for completion using proper request matching
        let mut timeout = 1_000_000u32;
        let mut completion: Option<Result<usize, BlockError>> = None;

        while timeout > 0 && completion.is_none() {
            // Process all pending completions
            while let Some(used) = self.queue.pop_used() {
                match self.complete_used_entry(used) {
                    Some(RequestCompletion::Io(res)) => {
                        completion = Some(res);
                        break;
                    }
                    Some(RequestCompletion::Flush(_)) => {
                        // Unexpected flush completion during I/O wait
                        kprintln!(
                            "[virtio-blk] unexpected flush completion while waiting for I/O head={}",
                            desc0
                        );
                    }
                    None => {
                        // Stale completion handled, continue polling
                    }
                }
            }

            if completion.is_some() {
                break;
            }

            if !self.queue.has_used() {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }

        // R39-1 FIX: Handle timeout by marking request as abandoned
        let result = match completion {
            Some(res) => res,
            None => {
                // Timeout - mark request as abandoned (resources freed on late completion)
                let leaked = TIMEOUT_LEAKED_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                {
                    let mut buffers = self.req_buffers.lock();
                    if let Some(meta) = buffers[buf_idx].pending.as_mut() {
                        meta.abandoned = true;
                    }
                }
                kprintln!(
                    "[virtio-blk] timeout waiting for request head={} sector={} bytes={}, \
                     buffers pinned (reset required, total leaked={})",
                    desc0,
                    sector,
                    buf.len(),
                    leaked
                );
                // Leave req_buffers[buf_idx].in_use = true to prevent reuse until device completes
                return Err(BlockError::Io);
            }
        };

        // R39-1 FIX: Resources are now freed by complete_used_entry()
        // No need to free DMA buffers or release buffer slot here

        result
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn max_sectors_per_bio(&self) -> u32 {
        // Conservative limit for now
        128
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn submit_bio(&self, mut bio: Bio) -> Result<(), BlockError> {
        // Synchronous fallback: process the BIO immediately using do_request/flush.
        // A proper async implementation would queue the BIO and use interrupt-driven
        // completion. This fallback enables page cache writeback and basic BIO users.
        let result: BioResult = match bio.op {
            BioOp::Read => {
                if bio.vecs.is_empty() {
                    Err(BlockError::Invalid)
                } else if bio.vecs.len() == 1 {
                    // Single vector - use directly
                    // SAFETY: Caller ensures the buffer is valid and writable for read data
                    let buf = unsafe { bio.vecs[0].as_mut_slice() };
                    self.do_request(bio.sector, buf, false)
                } else {
                    // Multi-vector scatter-gather: process sequentially
                    let mut current_sector = bio.sector;
                    let sector_size = self.sector_size as u64;
                    let mut total_bytes = 0usize;
                    let mut err: Option<BlockError> = None;

                    for bv in bio.vecs.iter_mut() {
                        // Read len before mutable borrow
                        let bv_len = bv.len as u64;
                        let sectors = match bv_len.checked_div(sector_size) {
                            Some(s) if s > 0 => s,
                            _ => {
                                err = Some(BlockError::Invalid);
                                break;
                            }
                        };

                        // SAFETY: Caller ensures each buffer is valid
                        let buf = unsafe { bv.as_mut_slice() };
                        match self.do_request(current_sector, buf, false) {
                            Ok(n) => {
                                total_bytes += n;
                                match current_sector.checked_add(sectors) {
                                    Some(next) => current_sector = next,
                                    None => {
                                        err = Some(BlockError::Invalid);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }

                    err.map_or(Ok(total_bytes), Err)
                }
            }
            BioOp::Write => {
                if bio.vecs.is_empty() {
                    Err(BlockError::Invalid)
                } else if bio.vecs.len() == 1 {
                    // SAFETY: Caller ensures the buffer is valid and contains write data
                    let buf = unsafe { bio.vecs[0].as_mut_slice() };
                    self.do_request(bio.sector, buf, true)
                } else {
                    // Multi-vector scatter-gather: process sequentially
                    let mut current_sector = bio.sector;
                    let sector_size = self.sector_size as u64;
                    let mut total_bytes = 0usize;
                    let mut err: Option<BlockError> = None;

                    for bv in bio.vecs.iter_mut() {
                        // Read len before mutable borrow
                        let bv_len = bv.len as u64;
                        let sectors = match bv_len.checked_div(sector_size) {
                            Some(s) if s > 0 => s,
                            _ => {
                                err = Some(BlockError::Invalid);
                                break;
                            }
                        };

                        // SAFETY: Caller ensures each buffer is valid
                        let buf = unsafe { bv.as_mut_slice() };
                        match self.do_request(current_sector, buf, true) {
                            Ok(n) => {
                                total_bytes += n;
                                match current_sector.checked_add(sectors) {
                                    Some(next) => current_sector = next,
                                    None => {
                                        err = Some(BlockError::Invalid);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }

                    err.map_or(Ok(total_bytes), Err)
                }
            }
            BioOp::Flush => self.flush().map(|_| 0),
            BioOp::Discard => {
                // TRIM/Discard not supported by this driver
                Err(BlockError::NotSupported)
            }
        };

        // Complete the BIO (calls completion callback if set)
        bio.complete(result);

        // Convert BioResult to submit_bio result
        result.map(|_| ())
    }

    fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        self.do_request(sector, buf, false)
    }

    fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
        // Need mutable buffer for the interface, but we won't modify it
        let mut buf_copy = buf.to_vec();
        self.do_request(sector, &mut buf_copy, true)
    }

    fn flush(&self) -> Result<(), BlockError> {
        if self.features & blk_features::VIRTIO_BLK_F_FLUSH == 0 {
            return Ok(()); // No flush support, assume write-through
        }

        let _lock = self.lock.lock();

        // Acquire a request buffer slot
        let buf_idx = {
            let mut buffers = self.req_buffers.lock();
            let idx = buffers.iter().position(|b| !b.in_use);
            match idx {
                Some(i) => {
                    buffers[i].in_use = true;
                    buffers[i].header.req_type = blk_types::VIRTIO_BLK_T_FLUSH;
                    buffers[i].header.reserved = 0;
                    buffers[i].header.sector = 0; // Sector is ignored for flush
                    buffers[i].status = 0xFF;
                    i
                }
                None => return Err(BlockError::Busy),
            }
        };

        // DMA buffer for header + status with on-demand IOMMU mapping (R94-13)
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let header_status_dma_size = if header_size + 1 < 32 {
            32
        } else {
            header_size + 1
        };
        let header_status_dma = match alloc_dma_buffer(header_status_dma_size) {
            Ok(buf) => buf,
            Err(_) => {
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // Write header and initialize status byte
        unsafe {
            let header = {
                let buffers = self.req_buffers.lock();
                buffers[buf_idx].header
            };
            core::ptr::write(header_status_dma.virt_ptr() as *mut VirtioBlkReqHeader, header);
            core::ptr::write(header_status_dma.virt_ptr().add(header_size), 0xFFu8);
        }
        let header_phys = header_status_dma.phys();
        let status_phys = header_status_dma.phys() + header_size as u64;

        // Allocate descriptors (header + status, no data buffer for flush)
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                // DmaBuffer is dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                // DmaBuffer is dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };

        unsafe {
            // Descriptor 0: Header (device reads)
            let d0 = self.queue.desc(desc0);
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = VRING_DESC_F_NEXT;
            d0.next = desc1;

            // Descriptor 1: Status (device writes)
            let d1 = self.queue.desc(desc1);
            d1.addr = status_phys;
            d1.len = 1;
            d1.flags = VRING_DESC_F_WRITE;
            d1.next = 0;
        }

        // R39-1 FIX: Store request metadata BEFORE pushing to available ring
        // R94-13: DmaBuffer is moved into RequestMeta, ownership transferred
        {
            let mut buffers = self.req_buffers.lock();
            buffers[buf_idx].pending = Some(RequestMeta {
                head: desc0,
                desc_chain: [desc0, desc1, 0], // Only 2 descriptors for flush
                desc_count: 2,
                header_status_dma,
                header_size,
                kind: RequestKind::Flush,
                abandoned: false,
            });
        }

        unsafe {
            // Push to available ring
            self.queue.push_avail(desc0);
        }

        // Notify device
        mb();
        self.notify();

        // R39-1 FIX: Poll for completion using proper request matching
        let mut timeout = 1_000_000u32;
        let mut completion: Option<Result<(), BlockError>> = None;

        while timeout > 0 && completion.is_none() {
            // Process all pending completions
            while let Some(used) = self.queue.pop_used() {
                match self.complete_used_entry(used) {
                    Some(RequestCompletion::Flush(res)) => {
                        completion = Some(res);
                        break;
                    }
                    Some(RequestCompletion::Io(_)) => {
                        // Unexpected I/O completion during flush wait
                        kprintln!(
                            "[virtio-blk] unexpected I/O completion while waiting for flush head={}",
                            desc0
                        );
                    }
                    None => {
                        // Stale completion handled, continue polling
                    }
                }
            }

            if completion.is_some() {
                break;
            }

            if !self.queue.has_used() {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }

        // R39-1 FIX: Handle timeout by marking request as abandoned
        let result = match completion {
            Some(res) => res,
            None => {
                // Timeout - mark request as abandoned (resources freed on late completion)
                let leaked = TIMEOUT_LEAKED_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                {
                    let mut buffers = self.req_buffers.lock();
                    if let Some(meta) = buffers[buf_idx].pending.as_mut() {
                        meta.abandoned = true;
                    }
                }
                kprintln!(
                    "[virtio-blk] flush timeout head={}, buffers pinned (reset required, total leaked={})",
                    desc0, leaked
                );
                // Leave req_buffers[buf_idx].in_use = true to prevent reuse
                return Err(BlockError::Io);
            }
        };

        // R39-1 FIX: Resources are now freed by complete_used_entry()
        // No need to free DMA buffers or release buffer slot here

        result
    }
}
