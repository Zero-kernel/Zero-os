//! Block Layer for Zero-OS
//!
//! This module provides the core abstractions for block device I/O operations.
//! It follows a layered design similar to Linux's block layer:
//!
//! ```text
//! +----------------+     +----------------+
//! | File System    |     | Page Cache     |
//! +--------+-------+     +-------+--------+
//!          |                     |
//!          v                     v
//!      +---+---------------------+---+
//!      |       Block Layer           |
//!      | (Bio, RequestQueue, etc.)   |
//!      +-------------+---------------+
//!                    |
//!          +---------+---------+
//!          |                   |
//!          v                   v
//!    +-----------+       +-----------+
//!    | virtio-blk|       | AHCI      |
//!    +-----------+       +-----------+
//! ```
//!
//! # Key Components
//!
//! - [`BlockDevice`]: Trait for block device drivers
//! - [`Bio`]: Block I/O request structure
//! - [`BioVec`]: Scatter-gather vector for DMA
//! - [`RequestQueue`]: Per-device request queue with FIFO scheduling
//! - [`BlockDeviceRegistry`]: Global registry for block devices
//!
//! # Security Integration
//!
//! Each BIO can carry a [`SecurityTag`] containing inode/path information
//! for LSM policy enforcement at the block layer.

#![no_std]

extern crate alloc;

extern crate drivers;
#[macro_use]
extern crate klog;
extern crate mm;

pub mod pci;
pub mod virtio;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Default logical sector size in bytes.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Maximum sectors per BIO (512 KB with 512-byte sectors).
pub const MAX_BIO_SECTORS: u32 = 1024;

/// Maximum BIO payload size in bytes.
pub const MAX_BIO_BYTES: usize = (MAX_BIO_SECTORS as usize) * (DEFAULT_SECTOR_SIZE as usize);

/// Maximum number of scatter-gather vectors per BIO.
pub const MAX_BIO_VECS: usize = 256;

/// Maximum number of registered block devices.
pub const MAX_BLOCK_DEVICES: usize = 64;

// ============================================================================
// Error Types
// ============================================================================

/// Block layer error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Generic I/O failure.
    Io,
    /// Invalid arguments (alignment, overflow, etc.).
    Invalid,
    /// Request size exceeds device or global limits.
    TooLarge,
    /// Device is busy or queue is full.
    Busy,
    /// Memory allocation failed.
    NoMem,
    /// Operation not supported by device.
    NotSupported,
    /// Device not found.
    NotFound,
    /// Device offline or removed.
    Offline,
    /// Read-only device.
    ReadOnly,
    /// Media error (bad sector, etc.).
    MediaError,
    /// Permission denied (LSM policy).
    PermissionDenied,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::Io => write!(f, "I/O error"),
            BlockError::Invalid => write!(f, "invalid argument"),
            BlockError::TooLarge => write!(f, "request too large"),
            BlockError::Busy => write!(f, "device busy"),
            BlockError::NoMem => write!(f, "out of memory"),
            BlockError::NotSupported => write!(f, "operation not supported"),
            BlockError::NotFound => write!(f, "device not found"),
            BlockError::Offline => write!(f, "device offline"),
            BlockError::ReadOnly => write!(f, "read-only device"),
            BlockError::MediaError => write!(f, "media error"),
            BlockError::PermissionDenied => write!(f, "permission denied"),
        }
    }
}

// ============================================================================
// BIO Types
// ============================================================================

/// Block I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read data from device.
    Read,
    /// Write data to device.
    Write,
    /// Flush device write cache.
    Flush,
    /// Discard (TRIM) sectors.
    Discard,
}

impl fmt::Display for BioOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BioOp::Read => write!(f, "READ"),
            BioOp::Write => write!(f, "WRITE"),
            BioOp::Flush => write!(f, "FLUSH"),
            BioOp::Discard => write!(f, "DISCARD"),
        }
    }
}

/// Scatter-gather vector for BIO data transfer.
///
/// Each vector points to a contiguous memory region. For DMA-capable
/// devices, the physical address should also be provided.
#[derive(Clone, Copy)]
pub struct BioVec {
    /// Virtual address of the buffer.
    pub ptr: *mut u8,
    /// Length in bytes (must be sector-aligned for most operations).
    pub len: usize,
    /// Physical address for DMA (None if not applicable).
    pub phys: Option<u64>,
}

// SAFETY: BioVec contains raw pointers but is only used within the kernel
// where we control memory safety.
unsafe impl Send for BioVec {}
unsafe impl Sync for BioVec {}

impl BioVec {
    /// Create a new BioVec with virtual address only.
    pub const fn new(ptr: *mut u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            phys: None,
        }
    }

    /// Create a new BioVec with both virtual and physical addresses.
    pub const fn with_phys(ptr: *mut u8, len: usize, phys: u64) -> Self {
        Self {
            ptr,
            len,
            phys: Some(phys),
        }
    }

    /// Check if the buffer is aligned to the given sector size.
    #[inline]
    pub fn is_aligned(&self, sector_size: u32) -> bool {
        let sz = sector_size as usize;
        (self.len % sz == 0) && ((self.ptr as usize) % sz == 0)
    }

    /// Get the buffer as a byte slice (for read operations).
    ///
    /// # Safety
    /// Caller must ensure the pointer is valid and the buffer is readable.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.ptr, self.len)
    }

    /// Get the buffer as a mutable byte slice (for write operations).
    ///
    /// # Safety
    /// Caller must ensure the pointer is valid and the buffer is writable.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.ptr, self.len)
    }
}

impl fmt::Debug for BioVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BioVec")
            .field("ptr", &format_args!("{:p}", self.ptr))
            .field("len", &self.len)
            .field("phys", &self.phys)
            .finish()
    }
}

/// Security context tag for LSM integration.
///
/// This tag carries file/inode context through the block layer,
/// allowing LSM policies to be enforced at the device level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityTag {
    /// Inode number (0 if not applicable).
    pub ino: u64,
    /// File mode bits (type + permissions).
    pub mode: u32,
    /// Path hash for policy lookup (FNV-1a hash).
    pub path_hash: u64,
    /// Process ID that initiated the I/O.
    pub pid: u32,
    /// User ID that initiated the I/O.
    pub uid: u32,
}

impl SecurityTag {
    /// Create a new security tag with the given parameters.
    pub const fn new(ino: u64, mode: u32, path_hash: u64, pid: u32, uid: u32) -> Self {
        Self {
            ino,
            mode,
            path_hash,
            pid,
            uid,
        }
    }
}

/// BIO completion result.
pub type BioResult = Result<usize, BlockError>;

/// Asynchronous completion callback for BIO.
pub type BioComplete = Box<dyn FnOnce(BioResult) + Send + 'static>;

/// Block I/O request.
///
/// A Bio represents a single block I/O operation. It contains:
/// - The operation type (read/write/flush/discard)
/// - The starting sector (LBA)
/// - Scatter-gather list of buffers
/// - Optional completion callback for async operations
/// - Optional security tag for LSM integration
pub struct Bio {
    /// Unique BIO ID for tracking.
    pub id: u64,
    /// Operation type.
    pub op: BioOp,
    /// Starting sector (logical block address).
    pub sector: u64,
    /// Number of sectors (used for Discard operations).
    /// For Read/Write, this is derived from vecs.
    pub num_sectors: u64,
    /// Scatter-gather buffer list.
    pub vecs: Vec<BioVec>,
    /// Completion callback (called when I/O finishes).
    pub completion: Option<BioComplete>,
    /// Security context for LSM.
    pub sec_tag: Option<SecurityTag>,
    /// Device-private data (e.g., virtio descriptor index).
    pub private: u64,
    /// Timestamp when BIO was created (for latency tracking).
    pub timestamp: u64,
}

// Global BIO ID counter
static BIO_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

impl Bio {
    /// Create a new BIO for the given operation and starting sector.
    pub fn new(op: BioOp, sector: u64) -> Self {
        Self {
            id: BIO_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            op,
            sector,
            num_sectors: 0,
            vecs: Vec::new(),
            completion: None,
            sec_tag: None,
            private: 0,
            timestamp: 0, // Will be set by request queue
        }
    }

    /// Create a new Discard BIO with explicit sector count.
    pub fn new_discard(sector: u64, num_sectors: u64) -> Self {
        Self {
            id: BIO_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            op: BioOp::Discard,
            sector,
            num_sectors,
            vecs: Vec::new(),
            completion: None,
            sec_tag: None,
            private: 0,
            timestamp: 0,
        }
    }

    /// Set the completion callback.
    pub fn with_completion(mut self, cb: BioComplete) -> Self {
        self.completion = Some(cb);
        self
    }

    /// Set the security tag.
    pub fn with_security_tag(mut self, tag: SecurityTag) -> Self {
        self.sec_tag = Some(tag);
        self
    }

    /// Add a scatter-gather vector to the BIO.
    pub fn push_vec(&mut self, bv: BioVec) -> Result<(), BlockError> {
        if self.vecs.len() >= MAX_BIO_VECS {
            return Err(BlockError::TooLarge);
        }
        self.vecs.push(bv);
        Ok(())
    }

    /// Get the total payload length in bytes.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.vecs.iter().map(|v| v.len).sum()
    }

    /// Get the total number of sectors (rounded up).
    #[inline]
    pub fn total_sectors(&self, sector_size: u32) -> u64 {
        let bytes = self.total_len() as u64;
        if bytes == 0 {
            return 0;
        }
        (bytes + sector_size as u64 - 1) / sector_size as u64
    }

    /// Validate the BIO against device constraints.
    ///
    /// # Arguments
    /// * `sector_size` - Device sector size in bytes
    /// * `max_sectors` - Maximum sectors per BIO
    /// * `device_capacity` - Total device capacity in sectors (for bounds check)
    pub fn validate(
        &self,
        sector_size: u32,
        max_sectors: u32,
        device_capacity: u64,
    ) -> Result<(), BlockError> {
        // Flush operations don't need data buffers or bounds check
        if self.op == BioOp::Flush {
            return Ok(());
        }

        // Discard operations use explicit num_sectors
        if self.op == BioOp::Discard {
            if self.num_sectors == 0 || self.num_sectors > max_sectors as u64 {
                return Err(BlockError::TooLarge);
            }
            // Bounds check: sector + num_sectors must not overflow or exceed capacity
            let end_sector = self
                .sector
                .checked_add(self.num_sectors)
                .ok_or(BlockError::Invalid)?;
            if end_sector > device_capacity {
                return Err(BlockError::Invalid);
            }
            return Ok(());
        }

        // Read/Write operations need at least one buffer
        if self.vecs.is_empty() {
            return Err(BlockError::Invalid);
        }

        // Check alignment for all vectors
        for v in &self.vecs {
            if !v.is_aligned(sector_size) {
                return Err(BlockError::Invalid);
            }
        }

        // Check total size
        let sectors = self.total_sectors(sector_size);
        if sectors == 0 || sectors > max_sectors as u64 {
            return Err(BlockError::TooLarge);
        }

        // Bounds check: sector + total_sectors must not overflow or exceed capacity
        let end_sector = self
            .sector
            .checked_add(sectors)
            .ok_or(BlockError::Invalid)?;
        if end_sector > device_capacity {
            return Err(BlockError::Invalid);
        }

        Ok(())
    }

    /// Complete the BIO with the given result.
    ///
    /// This consumes the BIO and invokes the completion callback if set.
    pub fn complete(self, result: BioResult) {
        if let Some(cb) = self.completion {
            cb(result);
        }
    }

    /// Check if this is a read operation.
    #[inline]
    pub fn is_read(&self) -> bool {
        self.op == BioOp::Read
    }

    /// Check if this is a write operation.
    #[inline]
    pub fn is_write(&self) -> bool {
        self.op == BioOp::Write
    }
}

impl fmt::Debug for Bio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bio")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("sector", &self.sector)
            .field("vecs", &self.vecs.len())
            .field("total_len", &self.total_len())
            .field("has_completion", &self.completion.is_some())
            .field("sec_tag", &self.sec_tag)
            .finish()
    }
}

// ============================================================================
// Block Device Trait
// ============================================================================

/// Block device abstraction trait.
///
/// All block device drivers must implement this trait. It provides the
/// interface for submitting I/O requests and querying device properties.
pub trait BlockDevice: Send + Sync {
    /// Get the device name (e.g., "vda", "sda").
    fn name(&self) -> &str;

    /// Get the logical sector size in bytes.
    fn sector_size(&self) -> u32 {
        DEFAULT_SECTOR_SIZE
    }

    /// Get the maximum sectors per BIO for this device.
    fn max_sectors_per_bio(&self) -> u32 {
        MAX_BIO_SECTORS
    }

    /// Get the total device capacity in sectors.
    fn capacity_sectors(&self) -> u64;

    /// Check if the device is read-only.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Submit a BIO for asynchronous processing.
    ///
    /// The driver should queue the BIO and return immediately.
    /// When the I/O completes, the driver calls `bio.complete(result)`.
    fn submit_bio(&self, bio: Bio) -> Result<(), BlockError>;

    /// Synchronously read sectors from the device.
    ///
    /// This is a convenience method that creates a BIO and waits for completion.
    /// Not all devices support synchronous I/O.
    fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        let _ = (sector, buf);
        Err(BlockError::NotSupported)
    }

    /// Synchronously write sectors to the device.
    ///
    /// This is a convenience method that creates a BIO and waits for completion.
    /// Not all devices support synchronous I/O.
    fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
        let _ = (sector, buf);
        Err(BlockError::NotSupported)
    }

    /// Flush the device write cache.
    fn flush(&self) -> Result<(), BlockError> {
        Err(BlockError::NotSupported)
    }
}

// ============================================================================
// Request Queue
// ============================================================================

/// Per-device request queue with FIFO scheduling.
///
/// The request queue provides:
/// - Thread-safe BIO enqueueing
/// - FIFO scheduling (simple but fair)
/// - Optional request merging (future enhancement)
/// - Back-pressure through queue depth limits
///
/// # Completion Semantics
///
/// On enqueue failure, the BIO's completion callback is automatically invoked
/// with the error, ensuring callers never hang waiting for completion.
pub struct RequestQueue {
    /// Queued BIOs waiting for processing (VecDeque for O(1) pop).
    queue: Mutex<VecDeque<Bio>>,
    /// Maximum queue depth.
    max_depth: usize,
    /// Sector size for validation.
    sector_size: u32,
    /// Maximum sectors per BIO.
    max_sectors: u32,
    /// Device capacity in sectors (for bounds checking).
    device_capacity: u64,
    /// Statistics: total BIOs submitted.
    stats_submitted: AtomicU64,
    /// Statistics: total BIOs completed.
    stats_completed: AtomicU64,
    /// Statistics: total bytes transferred.
    stats_bytes: AtomicU64,
    /// Statistics: total BIOs rejected.
    stats_rejected: AtomicU64,
}

impl RequestQueue {
    /// Create a new request queue with the given parameters.
    pub fn new(sector_size: u32, max_sectors: u32, max_depth: usize, device_capacity: u64) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(max_depth)),
            max_depth,
            sector_size,
            max_sectors,
            device_capacity,
            stats_submitted: AtomicU64::new(0),
            stats_completed: AtomicU64::new(0),
            stats_bytes: AtomicU64::new(0),
            stats_rejected: AtomicU64::new(0),
        }
    }

    /// Enqueue a BIO for processing.
    ///
    /// On failure, the BIO's completion callback is invoked with the error.
    /// Returns `Err(BlockError::Busy)` if the queue is full.
    pub fn enqueue(&self, bio: Bio) -> Result<(), BlockError> {
        // Validate the BIO first
        if let Err(e) = bio.validate(self.sector_size, self.max_sectors, self.device_capacity) {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            // Invoke completion with error so caller doesn't hang
            bio.complete(Err(e));
            return Err(e);
        }

        let mut q = self.queue.lock();
        if q.len() >= self.max_depth {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            // Invoke completion with error so caller doesn't hang
            bio.complete(Err(BlockError::Busy));
            return Err(BlockError::Busy);
        }

        self.stats_submitted.fetch_add(1, Ordering::Relaxed);
        q.push_back(bio);
        Ok(())
    }

    /// Pop the next BIO from the queue (FIFO order, O(1)).
    pub fn pop(&self) -> Option<Bio> {
        self.queue.lock().pop_front()
    }

    /// Get the current queue depth.
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Check if the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= self.max_depth
    }

    /// Record a completed BIO (for statistics).
    pub fn record_completion(&self, bytes: usize) {
        self.stats_completed.fetch_add(1, Ordering::Relaxed);
        self.stats_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Get queue statistics.
    pub fn stats(&self) -> RequestQueueStats {
        RequestQueueStats {
            submitted: self.stats_submitted.load(Ordering::Relaxed),
            completed: self.stats_completed.load(Ordering::Relaxed),
            rejected: self.stats_rejected.load(Ordering::Relaxed),
            bytes_transferred: self.stats_bytes.load(Ordering::Relaxed),
            current_depth: self.len(),
            max_depth: self.max_depth,
        }
    }
}

/// Request queue statistics.
#[derive(Debug, Clone, Copy)]
pub struct RequestQueueStats {
    /// Total BIOs submitted successfully.
    pub submitted: u64,
    /// Total BIOs completed.
    pub completed: u64,
    /// Total BIOs rejected (validation failed or queue full).
    pub rejected: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Current queue depth.
    pub current_depth: usize,
    /// Maximum queue depth.
    pub max_depth: usize,
}

// ============================================================================
// Block Device Registry
// ============================================================================

/// Registered block device entry.
struct RegisteredDevice {
    /// Device name.
    name: String,
    /// Device instance.
    device: Arc<dyn BlockDevice>,
    /// Minor device number.
    minor: u32,
}

/// Global block device registry.
///
/// Provides device registration, lookup by name/minor number,
/// and integration with devfs.
pub struct BlockDeviceRegistry {
    /// Registered devices.
    devices: RwLock<Vec<RegisteredDevice>>,
    /// Next minor number to assign.
    next_minor: AtomicU64,
}

impl BlockDeviceRegistry {
    /// Create a new registry.
    pub const fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
            next_minor: AtomicU64::new(0),
        }
    }

    /// Register a new block device.
    ///
    /// Returns the assigned minor number on success.
    pub fn register(&self, device: Arc<dyn BlockDevice>) -> Result<u32, BlockError> {
        let mut devices = self.devices.write();

        if devices.len() >= MAX_BLOCK_DEVICES {
            return Err(BlockError::NoMem);
        }

        // Check for duplicate name
        let name = device.name().into();
        if devices.iter().any(|d| d.name == name) {
            return Err(BlockError::Invalid);
        }

        let minor = self.next_minor.fetch_add(1, Ordering::SeqCst) as u32;

        devices.push(RegisteredDevice {
            name,
            device,
            minor,
        });

        Ok(minor)
    }

    /// Unregister a block device by name.
    pub fn unregister(&self, name: &str) -> Result<(), BlockError> {
        let mut devices = self.devices.write();
        let pos = devices
            .iter()
            .position(|d| d.name == name)
            .ok_or(BlockError::NotFound)?;
        devices.remove(pos);
        Ok(())
    }

    /// Look up a device by name.
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn BlockDevice>> {
        let devices = self.devices.read();
        devices
            .iter()
            .find(|d| d.name == name)
            .map(|d| Arc::clone(&d.device))
    }

    /// Look up a device by minor number.
    pub fn get_by_minor(&self, minor: u32) -> Option<Arc<dyn BlockDevice>> {
        let devices = self.devices.read();
        devices
            .iter()
            .find(|d| d.minor == minor)
            .map(|d| Arc::clone(&d.device))
    }

    /// Get list of all registered device names.
    pub fn list_devices(&self) -> Vec<String> {
        let devices = self.devices.read();
        devices.iter().map(|d| d.name.clone()).collect()
    }

    /// Get the number of registered devices.
    pub fn count(&self) -> usize {
        self.devices.read().len()
    }
}

// Global registry instance
lazy_static::lazy_static! {
    /// Global block device registry.
    pub static ref BLOCK_REGISTRY: BlockDeviceRegistry = BlockDeviceRegistry::new();
}

// ============================================================================
// Public API
// ============================================================================

/// Register a block device.
pub fn register_device(device: Arc<dyn BlockDevice>) -> Result<u32, BlockError> {
    let minor = BLOCK_REGISTRY.register(device.clone())?;
    klog_always!(
        "  Block device registered: {} (minor={}, capacity={}MB)",
        device.name(),
        minor,
        device.capacity_sectors() * device.sector_size() as u64 / (1024 * 1024)
    );
    Ok(minor)
}

/// Unregister a block device.
pub fn unregister_device(name: &str) -> Result<(), BlockError> {
    BLOCK_REGISTRY.unregister(name)
}

/// Get a block device by name.
pub fn get_device(name: &str) -> Option<Arc<dyn BlockDevice>> {
    BLOCK_REGISTRY.get_by_name(name)
}

/// Get a block device by minor number.
pub fn get_device_by_minor(minor: u32) -> Option<Arc<dyn BlockDevice>> {
    BLOCK_REGISTRY.get_by_minor(minor)
}

/// List all registered block devices.
pub fn list_devices() -> Vec<String> {
    BLOCK_REGISTRY.list_devices()
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the block layer subsystem.
pub fn init() {
    klog_always!("  Block layer initialized");
    klog_always!("    Max BIO size: {} KB", MAX_BIO_BYTES / 1024);
    klog_always!("    Default sector size: {} bytes", DEFAULT_SECTOR_SIZE);
}

// ============================================================================
// High Address MMIO Mapping
// ============================================================================

use core::sync::atomic::AtomicU64 as MmioAtomicU64;

/// Base virtual address for mapping MMIO regions above 4GB.
/// This is in the kernel's higher-half address space, separate from the kernel image.
const HIGH_MMIO_VIRT_BASE: u64 = 0xffff_ffff_4000_0000;

/// Maximum size of the high MMIO virtual address region (256 MB).
const HIGH_MMIO_VIRT_SIZE: u64 = 256 * 1024 * 1024;

/// Current offset within the high MMIO virtual address region.
static HIGH_MMIO_OFFSET: MmioAtomicU64 = MmioAtomicU64::new(0);

/// Physical address threshold - addresses at or above this need mapping.
const PHYS_4GB: u64 = 0x1_0000_0000;

/// Map a physical MMIO region and return the virtual offset to use.
///
/// For physical addresses below 4GB, the bootloader's identity mapping is used
/// (virt_offset = 0, meaning virt == phys).
///
/// For physical addresses at or above 4GB, this function allocates a virtual
/// address in the HIGH_MMIO_VIRT region and creates the mapping.
///
/// # Arguments
/// * `phys_base` - Physical base address of the MMIO region
/// * `size` - Size of the MMIO region in bytes
///
/// # Returns
/// * `Ok(virt_offset)` - Offset to add to physical address to get virtual address
/// * `Err(BlockError)` - Mapping failed
///
/// # Safety
/// The caller must ensure the physical address is a valid MMIO region.
unsafe fn map_high_mmio(phys_base: u64, size: usize) -> Result<i64, BlockError> {
    // If below 4GB, use identity mapping
    if phys_base < PHYS_4GB && phys_base.saturating_add(size as u64) <= PHYS_4GB {
        return Ok(0);
    }

    // Allocate virtual address space (page-aligned)
    let aligned_size = (size + 0xFFF) & !0xFFF;
    let offset = HIGH_MMIO_OFFSET.fetch_add(aligned_size as u64, Ordering::SeqCst);

    if offset + aligned_size as u64 > HIGH_MMIO_VIRT_SIZE {
        klog_always!("      [ERROR] High MMIO virtual space exhausted");
        return Err(BlockError::NoMem);
    }

    let virt_addr = HIGH_MMIO_VIRT_BASE + offset;
    let virt_offset = virt_addr as i64 - phys_base as i64;

    klog_always!(
        "      [MMIO] Mapping phys {:#x} -> virt {:#x} (size {:#x})",
        phys_base, virt_addr, aligned_size
    );

    // Create the mapping using the mm crate's map_mmio function
    use x86_64::{PhysAddr, VirtAddr};
    let mut frame_alloc = mm::FrameAllocator::new();

    match mm::map_mmio(
        VirtAddr::new(virt_addr),
        PhysAddr::new(phys_base),
        aligned_size,
        &mut frame_alloc,
    ) {
        Ok(()) => {
            klog_always!("      [MMIO] Mapping successful");
            Ok(virt_offset)
        }
        Err(e) => {
            klog_always!("      [ERROR] MMIO mapping failed: {:?}", e);
            Err(BlockError::NoMem)
        }
    }
}

/// Probe for block devices and register them with VFS.
///
/// This function:
/// 1. Tries known virtio-mmio addresses (for embedded/VM configurations)
/// 2. Scans PCI bus 0 for virtio-blk devices (modern transport)
/// 3. Initializes found devices
/// 4. Returns the device for caller to register with VFS
///
/// # Returns
/// Option containing (device Arc, device name) if found
pub fn probe_devices() -> Option<(Arc<dyn BlockDevice>, &'static str)> {
    // Known virtio-mmio addresses to try (used by some VMs)
    // These use identity mapping (virt == phys for first 4GB)
    const VIRTIO_MMIO_BASES: [u64; 2] = [
        0x10001000, // Common virtio-mmio base
        0x10002000, // Secondary virtio-mmio base
    ];
    let mmio_virt_offset = 0u64; // Identity mapped for low addresses

    // First, try MMIO transport at known addresses
    for (idx, &base) in VIRTIO_MMIO_BASES.iter().enumerate() {
        let name = match idx {
            0 => "vda",
            1 => "vdb",
            _ => "vdx",
        };
        match unsafe { virtio::VirtioBlkDevice::probe_mmio(base, mmio_virt_offset, name) } {
            Ok(device) => {
                let capacity = device.capacity_sectors();
                let sector_size = device.sector_size();
                let size_mb = (capacity * sector_size as u64) / (1024 * 1024);
                klog_always!(
                    "    virtio-blk (mmio) /dev/{}: {} MB ({} sectors x {} bytes)",
                    name, size_mb, capacity, sector_size
                );
                return Some((device, name));
            }
            Err(BlockError::NotFound) => {
                // No device at this address, continue silently
            }
            Err(e) => {
                klog_always!("    MMIO virtio-blk at {:#x} failed: {:?}", base, e);
            }
        }
    }

    // Then, try PCI transport (virtio-pci modern)
    if let Some((pci_id, pci_addrs, name)) = pci::probe_virtio_blk() {
        // Calculate the range of physical addresses that need to be mapped
        let phys_addrs = [
            pci_addrs.common_cfg,
            pci_addrs.notify_base,
            pci_addrs.isr,
            pci_addrs.device_cfg,
        ];

        // Find the minimum non-zero physical address
        let min_phys = phys_addrs
            .iter()
            .filter(|&&a| a != 0)
            .copied()
            .min()
            .unwrap_or(0);

        // Find the maximum address (assume each region is at most 4KB)
        let max_phys = phys_addrs
            .iter()
            .filter(|&&a| a != 0)
            .copied()
            .max()
            .unwrap_or(0)
            + 0x1000; // Add 4KB for the last region

        let mmio_size = (max_phys - min_phys) as usize;

        // Map high MMIO if needed
        let virt_offset = match unsafe { map_high_mmio(min_phys, mmio_size) } {
            Ok(offset) => {
                // Convert i64 offset to u64 using wrapping arithmetic
                // This works because Rust's as conversion uses wrapping
                offset as u64
            }
            Err(e) => {
                // R82-3 FIX: Disable bus mastering on MMIO mapping failure
                let cmd = pci::pci_config_read32(pci_id.bus, pci_id.device, pci_id.function, 0x04) as u16;
                pci::pci_config_write16(pci_id.bus, pci_id.device, pci_id.function, 0x04, cmd & !0x04);
                klog_always!(
                    "    Failed to map virtio-blk MMIO region {:#x}-{:#x}: {:?} (bus master disabled)",
                    min_phys, max_phys, e
                );
                return None;
            }
        };

        match unsafe { virtio::VirtioBlkDevice::probe_pci(pci_addrs, virt_offset, name) } {
            Ok(device) => {
                let capacity = device.capacity_sectors();
                let sector_size = device.sector_size();
                let size_mb = (capacity * sector_size as u64) / (1024 * 1024);
                klog_always!(
                    "    virtio-blk (pci) /dev/{} @ {:02x}:{:02x}.{}: {} MB ({} sectors x {} bytes)",
                    name,
                    pci_id.bus,
                    pci_id.device,
                    pci_id.function,
                    size_mb,
                    capacity,
                    sector_size
                );
                return Some((device, name));
            }
            Err(e) => {
                // R82-3 FIX: Disable bus mastering on driver probe failure
                let cmd = pci::pci_config_read32(pci_id.bus, pci_id.device, pci_id.function, 0x04) as u16;
                pci::pci_config_write16(pci_id.bus, pci_id.device, pci_id.function, 0x04, cmd & !0x04);
                klog_always!(
                    "    Failed to probe virtio-blk /dev/{} @ {:02x}:{:02x}.{} (pci caps @ {:#x}): {:?} (bus master disabled)",
                    name,
                    pci_id.bus,
                    pci_id.device,
                    pci_id.function,
                    pci_addrs.common_cfg,
                    e
                );
            }
        }
    } else {
        klog_always!("    No virtio-blk devices found on PCI buses");
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bio_vec_alignment() {
        let buf = [0u8; 512];
        let bv = BioVec::new(buf.as_ptr() as *mut u8, 512);
        assert!(bv.is_aligned(512));
        assert!(!bv.is_aligned(1024));
    }

    #[test]
    fn test_bio_creation() {
        let bio = Bio::new(BioOp::Read, 0);
        assert!(bio.is_read());
        assert!(!bio.is_write());
        assert_eq!(bio.total_len(), 0);
    }

    #[test]
    fn test_bio_validation() {
        let mut bio = Bio::new(BioOp::Read, 0);
        let buf = [0u8; 512];
        bio.push_vec(BioVec::new(buf.as_ptr() as *mut u8, 512))
            .unwrap();

        // Should pass with matching sector size and sufficient capacity
        assert!(bio.validate(512, 1024, 1000).is_ok());

        // Should fail with larger sector size (not aligned)
        assert!(bio.validate(1024, 1024, 1000).is_err());

        // Should fail if exceeds device capacity
        let mut bio2 = Bio::new(BioOp::Read, 999);
        bio2.push_vec(BioVec::new(buf.as_ptr() as *mut u8, 512))
            .unwrap();
        assert!(bio2.validate(512, 1024, 1000).is_ok()); // sector 999 + 1 = 1000, OK

        let mut bio3 = Bio::new(BioOp::Read, 1000);
        bio3.push_vec(BioVec::new(buf.as_ptr() as *mut u8, 512))
            .unwrap();
        assert!(bio3.validate(512, 1024, 1000).is_err()); // sector 1000 + 1 = 1001, exceeds
    }

    #[test]
    fn test_discard_bio() {
        let bio = Bio::new_discard(0, 100);
        assert_eq!(bio.op, BioOp::Discard);
        assert_eq!(bio.num_sectors, 100);

        // Should pass validation
        assert!(bio.validate(512, 1024, 1000).is_ok());

        // Should fail if exceeds capacity
        let bio2 = Bio::new_discard(950, 100);
        assert!(bio2.validate(512, 1024, 1000).is_err()); // 950 + 100 = 1050 > 1000
    }

    #[test]
    fn test_request_queue() {
        let queue = RequestQueue::new(512, 1024, 16, 10000);
        assert!(queue.is_empty());

        let mut bio = Bio::new(BioOp::Read, 0);
        let buf = [0u8; 512];
        bio.push_vec(BioVec::new(buf.as_ptr() as *mut u8, 512))
            .unwrap();

        queue.enqueue(bio).unwrap();
        assert_eq!(queue.len(), 1);

        let popped = queue.pop();
        assert!(popped.is_some());
        assert!(queue.is_empty());
    }
}
