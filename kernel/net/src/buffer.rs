//! Network packet buffer implementation.
//!
//! This module provides DMA-compatible packet buffers with configurable
//! headroom and tailroom for efficient protocol header manipulation.

use alloc::vec::Vec;
use core::slice;
use spin::Mutex;
use x86_64::PhysAddr;

use crate::{DEFAULT_HEADROOM, DEFAULT_MTU, DEFAULT_TAILROOM};
use mm::dma::{alloc_dma_buffer, DmaBuffer, DmaError, DMA_PAGE_SIZE};

// ============================================================================
// NetBuf - Network Packet Buffer
// ============================================================================

/// A network packet buffer with DMA support and headroom/tailroom management.
///
/// `NetBuf` provides a contiguous memory region for network packets, with
/// reserved space at the head and tail for protocol headers and trailers.
/// The buffer tracks both virtual and physical addresses for DMA operations.
///
/// # Memory Layout
///
/// ```text
/// +-------------+------------------+-------------+
/// |  headroom   |      data        |  tailroom   |
/// +-------------+------------------+-------------+
/// ^             ^                  ^             ^
/// |             |                  |             |
/// virt_base     data_offset        data_end      total_len
/// ```
///
/// # Safety
///
/// The buffer owns the physical memory and provides safe access through
/// slice references. Raw pointer access is only used internally.
#[derive(Debug)]
pub struct NetBuf {
    /// R98-2 FIX: DMA buffer backing this packet buffer (IOMMU-mapped).
    dma: DmaBuffer,
    /// Total buffer size in bytes.
    total_len: usize,
    /// Reserved headroom (bytes before data can start).
    headroom: usize,
    /// Reserved tailroom (bytes after max data can end).
    reserved_tailroom: usize,
    /// Current offset where data starts.
    data_offset: usize,
    /// Current data length.
    data_len: usize,
}

// SAFETY: NetBuf owns its memory exclusively and provides synchronized access.
// The raw pointer is only used for internal buffer access and is derived from
// a valid DMA buffer allocation.
unsafe impl Send for NetBuf {}
unsafe impl Sync for NetBuf {}

/// R48-5/R49-1/R98-2 FIX: Prevent leaks and information disclosure on drop.
///
/// `NetBuf` owns a `DmaBuffer`, whose `Drop` implementation handles IOMMU
/// unmapping (when enabled), scrubbing, and physical page freeing.
impl Drop for NetBuf {
    fn drop(&mut self) {
        // Cleanup is handled by `DmaBuffer`'s Drop.
    }
}

impl NetBuf {
    /// R98-2 FIX: Create a new buffer backed by a DMA buffer (IOMMU-mapped).
    ///
    /// # Arguments
    ///
    /// * `dma` - DMA buffer providing the backing memory (IOMMU-mapped)
    /// * `mtu` - Maximum transmission unit (payload capacity)
    /// * `headroom` - Bytes to reserve at the start for headers
    /// * `tailroom` - Bytes to reserve at the end for trailers
    ///
    /// # Returns
    ///
    /// `None` if `headroom + mtu + tailroom` exceeds the DMA buffer size.
    pub fn new(dma: DmaBuffer, mtu: usize, headroom: usize, tailroom: usize) -> Option<Self> {
        // R99-3 FIX: Use checked arithmetic to prevent integer overflow from
        // bypassing the DMA_PAGE_SIZE bound check below.
        let total_len = headroom.checked_add(mtu)?.checked_add(tailroom)?;

        // Validate that the requested layout fits within the DMA buffer
        if total_len > DMA_PAGE_SIZE || total_len > dma.size() {
            return None;
        }

        Some(NetBuf {
            dma,
            total_len,
            headroom,
            reserved_tailroom: tailroom,
            data_offset: headroom,
            data_len: 0,
        })
    }

    /// Create a buffer with default layout (MTU=1500, headroom=64, tailroom=64).
    ///
    /// Returns `None` if the DMA buffer is too small.
    pub fn with_defaults(dma: DmaBuffer) -> Option<Self> {
        Self::new(dma, DEFAULT_MTU, DEFAULT_HEADROOM, DEFAULT_TAILROOM)
    }

    /// Returns the current data length.
    #[inline]
    pub fn len(&self) -> usize {
        self.data_len
    }

    /// Returns true if the buffer contains no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }

    /// Returns the total buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.total_len
    }

    /// Returns the maximum payload capacity (excluding reserved headroom/tailroom).
    #[inline]
    pub fn payload_capacity(&self) -> usize {
        self.total_len - self.headroom - self.reserved_tailroom
    }

    /// Returns the available headroom (bytes before current data start).
    #[inline]
    pub fn headroom(&self) -> usize {
        self.data_offset
    }

    /// Returns the available tailroom (bytes after current data end).
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.total_len - (self.data_offset + self.data_len)
    }

    /// Returns an immutable view of the current data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.buffer_slice(self.data_offset, self.data_len)
    }

    /// Returns a mutable view of the current data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.buffer_slice_mut(self.data_offset, self.data_len)
    }

    /// Prepend space to the buffer, returning a mutable view of the new region.
    ///
    /// This operation expands the data region towards the start of the buffer,
    /// consuming headroom. Useful for prepending protocol headers.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to prepend
    ///
    /// # Returns
    ///
    /// `Some(&mut [u8])` containing the newly prepended region, or `None` if
    /// insufficient headroom is available.
    pub fn push_head(&mut self, len: usize) -> Option<&mut [u8]> {
        if len > self.data_offset {
            return None;
        }

        self.data_offset -= len;
        self.data_len += len;
        Some(self.buffer_slice_mut(self.data_offset, len))
    }

    /// Append space to the buffer, returning a mutable view of the new region.
    ///
    /// This operation expands the data region towards the end of the buffer,
    /// consuming tailroom. Useful for receiving data or adding trailers.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to append
    ///
    /// # Returns
    ///
    /// `Some(&mut [u8])` containing the newly appended region, or `None` if
    /// insufficient tailroom is available.
    pub fn push_tail(&mut self, len: usize) -> Option<&mut [u8]> {
        if len > self.tailroom() {
            return None;
        }

        let start = self.data_offset + self.data_len;
        self.data_len += len;
        Some(self.buffer_slice_mut(start, len))
    }

    /// Remove and return data from the head of the buffer.
    ///
    /// This operation shrinks the data region from the start, reclaiming
    /// headroom. Useful for stripping protocol headers after processing.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to remove
    ///
    /// # Returns
    ///
    /// `Some(&[u8])` containing the removed bytes, or `None` if `len` exceeds
    /// the current data length.
    pub fn pull_head(&mut self, len: usize) -> Option<&[u8]> {
        if len > self.data_len {
            return None;
        }

        let start = self.data_offset;
        // Create slice before modifying state
        let slice_ptr = self.dma.virt_ptr();
        self.data_offset += len;
        self.data_len -= len;

        // SAFETY: We've validated bounds and the buffer owns this memory
        Some(unsafe { slice::from_raw_parts(slice_ptr.add(start), len) })
    }

    /// Remove and return data from the tail of the buffer.
    ///
    /// This operation shrinks the data region from the end, reclaiming
    /// tailroom. Useful for removing trailers.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to remove
    ///
    /// # Returns
    ///
    /// `Some(&[u8])` containing the removed bytes, or `None` if `len` exceeds
    /// the current data length.
    pub fn pull_tail(&mut self, len: usize) -> Option<&[u8]> {
        if len > self.data_len {
            return None;
        }

        let start = self.data_offset + self.data_len - len;
        self.data_len -= len;

        // SAFETY: We've validated bounds and the buffer owns this memory
        Some(unsafe { slice::from_raw_parts(self.dma.virt_ptr().add(start), len) })
    }

    /// Returns the physical address of the current data start.
    ///
    /// Use this address for DMA operations when the device needs to read
    /// or write packet data.
    #[inline]
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.dma.phys()) + self.data_offset as u64
    }

    /// Returns the physical address of the buffer base.
    ///
    /// This is the start of the entire buffer including headroom.
    #[inline]
    pub fn buffer_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.dma.phys())
    }

    /// Reset the buffer for reuse.
    ///
    /// This restores the initial headroom/tailroom configuration and
    /// clears the data length.
    ///
    /// # R43-5 FIX (v3): Zero the ENTIRE buffer to prevent information leakage
    /// When buffers are returned to the pool and reused for RX, stale data
    /// could be exposed to DMA devices. We must zero the complete buffer
    /// including tailroom in case future offload features expose it.
    pub fn reset(&mut self) {
        // R43-5 FIX (v3): Zero the entire buffer including tailroom
        // This ensures no stale data is visible even if tailroom becomes
        // device-accessible in future (e.g., offloads, trailers)
        unsafe {
            core::ptr::write_bytes(self.dma.virt_ptr(), 0, self.total_len);
        }

        self.data_offset = self.headroom;
        self.data_len = 0;
    }

    /// Set the data length directly (for receive operations).
    ///
    /// # Arguments
    ///
    /// * `len` - New data length
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if `len` exceeds available space.
    pub fn set_len(&mut self, len: usize) -> bool {
        let max_len = self.total_len - self.data_offset;
        if len > max_len {
            return false;
        }
        self.data_len = len;
        true
    }

    /// Get an immutable slice of the buffer.
    ///
    /// # R43-4 FIX: Use assert! instead of debug_assert! for bounds checking
    /// The original debug_assert! would not run in release builds, allowing
    /// potential OOB access if the caller passes invalid offset/len.
    #[inline]
    fn buffer_slice(&self, offset: usize, len: usize) -> &[u8] {
        // R43-4 FIX: Use checked arithmetic and assert! for release safety
        assert!(
            offset
                .checked_add(len)
                .map_or(false, |end| end <= self.total_len),
            "NetBuf::buffer_slice OOB: offset={}, len={}, total={}",
            offset,
            len,
            self.total_len
        );
        // SAFETY: Bounds checked by assert above
        unsafe { slice::from_raw_parts(self.dma.virt_ptr().add(offset), len) }
    }

    /// Get a mutable slice of the buffer.
    ///
    /// # R43-4 FIX: Use assert! instead of debug_assert! for bounds checking
    #[inline]
    fn buffer_slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        // R43-4 FIX: Use checked arithmetic and assert! for release safety
        assert!(
            offset
                .checked_add(len)
                .map_or(false, |end| end <= self.total_len),
            "NetBuf::buffer_slice_mut OOB: offset={}, len={}, total={}",
            offset,
            len,
            self.total_len
        );
        // SAFETY: Bounds checked by assert above
        unsafe { slice::from_raw_parts_mut(self.dma.virt_ptr().add(offset), len) }
    }
}

// ============================================================================
// BufPool - Network Buffer Pool
// ============================================================================

/// A pool of preallocated network buffers for efficient packet handling.
///
/// `BufPool` maintains a collection of `NetBuf` instances that can be
/// allocated and freed without touching the system allocator in the
/// hot path. This is critical for network performance.
///
/// # Thread Safety
///
/// All operations are protected by a spin lock, making `BufPool` safe
/// for concurrent access from multiple contexts (e.g., interrupt handlers
/// and process context).
///
/// # Example
///
/// ```ignore
/// // Create a pool with 64 buffers
/// let pool = BufPool::new(64);
///
/// // Allocate a buffer
/// let buf = pool.alloc().expect("pool exhausted");
///
/// // Use the buffer...
///
/// // Return to pool
/// pool.free(buf);
/// ```
#[derive(Debug)]
pub struct BufPool {
    /// Available buffers.
    buffers: Mutex<Vec<NetBuf>>,
    /// MTU for buffers in this pool.
    mtu: usize,
    /// Headroom for buffers in this pool.
    headroom: usize,
    /// Tailroom for buffers in this pool.
    tailroom: usize,
    /// Total number of buffers allocated (including in-use).
    total_allocated: usize,
}

impl BufPool {
    /// Create a pool with default buffer layout (MTU=1500, headroom=64, tailroom=64).
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Number of buffers to preallocate
    ///
    /// # Returns
    ///
    /// A new buffer pool. If memory allocation fails for some buffers,
    /// the pool will contain fewer than `pool_size` buffers.
    pub fn new(pool_size: usize) -> Self {
        // Default layout (64 + 1500 + 64 = 1628) always fits in a page
        Self::with_layout(pool_size, DEFAULT_MTU, DEFAULT_HEADROOM, DEFAULT_TAILROOM)
            .expect("default buffer layout should fit in page")
    }

    /// Create a pool with custom buffer layout.
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Number of buffers to preallocate
    /// * `mtu` - Maximum transmission unit for each buffer
    /// * `headroom` - Bytes to reserve for headers
    /// * `tailroom` - Bytes to reserve for trailers
    ///
    /// # Returns
    ///
    /// `None` if the layout exceeds page size. Otherwise returns the pool
    /// (which may contain fewer buffers than requested if memory is low).
    pub fn with_layout(
        pool_size: usize,
        mtu: usize,
        headroom: usize,
        tailroom: usize,
    ) -> Option<Self> {
        // Validate layout fits in a page
        // R99-3 FIX: Use checked arithmetic to prevent integer overflow from
        // bypassing the DMA_PAGE_SIZE bound check below.
        let total_len = headroom.checked_add(mtu)?.checked_add(tailroom)?;
        if total_len > DMA_PAGE_SIZE {
            return None;
        }

        let mut buffers = Vec::with_capacity(pool_size);
        let mut allocated = 0;

        for _ in 0..pool_size {
            if let Ok(dma) = alloc_frame() {
                // SAFETY: We validated the layout fits in a page above
                if let Some(buf) = NetBuf::new(dma, mtu, headroom, tailroom) {
                    buffers.push(buf);
                    allocated += 1;
                }
            } else {
                // Allocation failed, stop allocating
                break;
            }
        }

        if allocated < pool_size {
            // Log warning about partial allocation
            drivers::println!(
                "[net] BufPool: only allocated {}/{} buffers",
                allocated,
                pool_size
            );
        }

        Some(BufPool {
            buffers: Mutex::new(buffers),
            mtu,
            headroom,
            tailroom,
            total_allocated: allocated,
        })
    }

    /// Allocate a buffer from the pool.
    ///
    /// # Returns
    ///
    /// `Some(NetBuf)` if a buffer is available, `None` if the pool is empty.
    pub fn alloc(&self) -> Option<NetBuf> {
        self.buffers.lock().pop()
    }

    /// Return a buffer to the pool.
    ///
    /// The buffer is reset before being returned to the pool.
    pub fn free(&self, mut buf: NetBuf) {
        buf.reset();
        self.buffers.lock().push(buf);
    }

    /// Returns the number of buffers currently available in the pool.
    pub fn available(&self) -> usize {
        self.buffers.lock().len()
    }

    /// Returns the total number of buffers managed by this pool.
    pub fn total(&self) -> usize {
        self.total_allocated
    }

    /// Returns the number of buffers currently in use.
    pub fn in_use(&self) -> usize {
        self.total_allocated - self.available()
    }

    /// Returns the buffer layout (mtu, headroom, tailroom).
    pub fn layout(&self) -> (usize, usize, usize) {
        (self.mtu, self.headroom, self.tailroom)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// R98-2 FIX: Allocate a DMA-mapped page for packet buffers.
///
/// This ensures proper IOMMU mapping when IOMMU is enabled, preventing
/// IOMMU fault storms when devices perform DMA to these buffers.
fn alloc_frame() -> Result<DmaBuffer, DmaError> {
    alloc_dma_buffer(DMA_PAGE_SIZE)
}
