//! VirtIO Block Device Definitions for Zero-OS
//!
//! This module re-exports shared VirtIO primitives from the `virtio` crate
//! and provides block-device-specific types.
//!
//! # References
//! - VirtIO Spec: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html

pub mod blk;

pub use blk::VirtioBlkDevice;

// Re-export shared VirtIO primitives from the virtio crate
pub use virtio::{
    mb, mmio, rmb, wmb, MmioTransport, VirtioPciAddrs, VirtioPciTransport, VirtioTransport,
    VringAvail, VringDesc, VringUsed, VringUsedElem, VIRTIO_DEVICE_BLK, VIRTIO_F_VERSION_1,
    VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FAILED,
    VIRTIO_STATUS_FEATURES_OK, VIRTIO_VERSION_LEGACY, VIRTIO_VERSION_MODERN, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE,
};

// ============================================================================
// VirtIO Block Device Constants
// ============================================================================

/// VirtIO block device feature bits.
pub mod blk_features {
    /// Device has read-only flag.
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    /// Device supports flush command.
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    /// Device supports discard command.
    pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
    /// Device reports optimal I/O size.
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    /// Device reports topology.
    pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
    /// Device supports multiple queues.
    pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
}

/// VirtIO block request types.
pub mod blk_types {
    /// Read request.
    pub const VIRTIO_BLK_T_IN: u32 = 0;
    /// Write request.
    pub const VIRTIO_BLK_T_OUT: u32 = 1;
    /// Flush request.
    pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
    /// Discard request.
    pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
    /// Write zeroes request.
    pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;
}

/// VirtIO block status codes.
pub mod blk_status {
    /// Success.
    pub const VIRTIO_BLK_S_OK: u8 = 0;
    /// I/O error.
    pub const VIRTIO_BLK_S_IOERR: u8 = 1;
    /// Unsupported operation.
    pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;
}

/// VirtIO block request header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkReqHeader {
    /// Request type (IN/OUT/FLUSH/DISCARD).
    pub req_type: u32,
    /// Reserved.
    pub reserved: u32,
    /// Sector number (for read/write).
    pub sector: u64,
}

/// VirtIO block config structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkConfig {
    /// Capacity in 512-byte sectors.
    pub capacity: u64,
    /// Maximum segment size.
    pub size_max: u32,
    /// Maximum number of segments.
    pub seg_max: u32,
    /// Geometry (cylinders).
    pub geometry_cylinders: u16,
    /// Geometry (heads).
    pub geometry_heads: u8,
    /// Geometry (sectors).
    pub geometry_sectors: u8,
    /// Block size.
    pub blk_size: u32,
}
