//! VirtIO Transport Abstraction Layer
//!
//! This module provides a unified transport interface for VirtIO devices,
//! supporting both virtio-mmio and virtio-pci modern transports.
//!
//! # Transport Variants
//! - **MMIO**: Used for embedded systems and some VM configurations
//! - **PCI Modern**: Standard transport for x86 VMs (QEMU, etc.)
//!
//! # References
//! - VirtIO 1.2 Spec Section 4.1 (PCI Transport)
//! - VirtIO 1.2 Spec Section 4.2 (MMIO Transport)

use core::mem::MaybeUninit;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use crate::{mmio, VIRTIO_MAGIC, VIRTIO_VERSION_LEGACY, VIRTIO_VERSION_MODERN};

// ============================================================================
// Transport Abstraction
// ============================================================================

/// Transport abstraction for VirtIO devices.
///
/// This enum wraps the different transport implementations and provides
/// a unified interface for device drivers.
pub enum VirtioTransport {
    /// virtio-mmio transport
    Mmio(MmioTransport),
    /// virtio-pci modern transport
    Pci(VirtioPciTransport),
}

// SAFETY: VirtioTransport contains pointers to MMIO regions which are
// accessed through volatile operations. The regions are identity-mapped
// in kernel space and remain valid for the lifetime of the device.
unsafe impl Send for VirtioTransport {}
unsafe impl Sync for VirtioTransport {}

impl VirtioTransport {
    /// Returns the transport type name for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            VirtioTransport::Mmio(_) => "mmio",
            VirtioTransport::Pci(_) => "pci",
        }
    }

    /// Read the device ID from the transport.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn device_id(&self) -> u32 {
        match self {
            VirtioTransport::Mmio(t) => t.read_reg(mmio::DEVICE_ID),
            VirtioTransport::Pci(t) => t.virtio_device_type,
        }
    }

    /// Read the VirtIO version.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn version(&self) -> u32 {
        match self {
            VirtioTransport::Mmio(t) => t.version,
            VirtioTransport::Pci(_) => VIRTIO_VERSION_MODERN,
        }
    }

    /// Reset the device.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn reset(&self) {
        match self {
            VirtioTransport::Mmio(t) => t.write_reg(mmio::STATUS, 0),
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).device_status, 0);
            }
        }
    }

    /// Read the device status.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn status(&self) -> u32 {
        match self {
            VirtioTransport::Mmio(t) => t.read_reg(mmio::STATUS),
            VirtioTransport::Pci(t) => read_volatile(&(*t.common_cfg).device_status) as u32,
        }
    }

    /// Set the device status.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn set_status(&self, status: u32) {
        match self {
            VirtioTransport::Mmio(t) => t.write_reg(mmio::STATUS, status),
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).device_status, status as u8);
            }
        }
    }

    /// Read device features (64-bit).
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn device_features(&self) -> u64 {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::DEVICE_FEATURES_SEL, 0);
                let low = t.read_reg(mmio::DEVICE_FEATURES);
                t.write_reg(mmio::DEVICE_FEATURES_SEL, 1);
                let high = t.read_reg(mmio::DEVICE_FEATURES);
                ((high as u64) << 32) | (low as u64)
            }
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).device_feature_select, 0);
                let low = read_volatile(&(*t.common_cfg).device_feature);
                write_volatile(&mut (*t.common_cfg).device_feature_select, 1);
                let high = read_volatile(&(*t.common_cfg).device_feature);
                ((high as u64) << 32) | (low as u64)
            }
        }
    }

    /// Write driver features (64-bit).
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn write_driver_features(&self, features: u64) {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::DRIVER_FEATURES_SEL, 0);
                t.write_reg(mmio::DRIVER_FEATURES, features as u32);
                t.write_reg(mmio::DRIVER_FEATURES_SEL, 1);
                t.write_reg(mmio::DRIVER_FEATURES, (features >> 32) as u32);
            }
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).driver_feature_select, 0);
                write_volatile(&mut (*t.common_cfg).driver_feature, features as u32);
                write_volatile(&mut (*t.common_cfg).driver_feature_select, 1);
                write_volatile(&mut (*t.common_cfg).driver_feature, (features >> 32) as u32);
            }
        }
    }

    /// Get maximum queue size for a queue.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn queue_max(&self, queue: u16) -> u16 {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::QUEUE_SEL, queue as u32);
                t.read_reg(mmio::QUEUE_NUM_MAX) as u16
            }
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).queue_select, queue);
                read_volatile(&(*t.common_cfg).queue_size)
            }
        }
    }

    /// Get queue notify offset for PCI transport.
    ///
    /// For MMIO, this returns the queue index itself.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn queue_notify_off(&self, queue: u16) -> u16 {
        match self {
            VirtioTransport::Mmio(_) => queue,
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).queue_select, queue);
                read_volatile(&(*t.common_cfg).queue_notify_off)
            }
        }
    }

    /// Setup a virtqueue with descriptor, available, and used ring addresses.
    ///
    /// # Safety
    /// Caller must ensure:
    /// - The transport is properly initialized
    /// - The physical addresses are valid DMA-able memory
    pub unsafe fn setup_queue(
        &self,
        queue: u16,
        size: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::QUEUE_SEL, queue as u32);
                t.write_reg(mmio::QUEUE_NUM, size as u32);
                t.write_reg(mmio::QUEUE_DESC_LOW, desc_phys as u32);
                t.write_reg(mmio::QUEUE_DESC_HIGH, (desc_phys >> 32) as u32);
                t.write_reg(mmio::QUEUE_AVAIL_LOW, avail_phys as u32);
                t.write_reg(mmio::QUEUE_AVAIL_HIGH, (avail_phys >> 32) as u32);
                t.write_reg(mmio::QUEUE_USED_LOW, used_phys as u32);
                t.write_reg(mmio::QUEUE_USED_HIGH, (used_phys >> 32) as u32);
            }
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).queue_select, queue);
                write_volatile(&mut (*t.common_cfg).queue_size, size);
                write_volatile(&mut (*t.common_cfg).queue_desc, desc_phys);
                write_volatile(&mut (*t.common_cfg).queue_avail, avail_phys);
                write_volatile(&mut (*t.common_cfg).queue_used, used_phys);
                // Memory barrier to ensure all writes complete
                fence(Ordering::SeqCst);
            }
        }
    }

    /// Set queue ready state.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn queue_ready(&self, queue: u16, ready: bool) {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::QUEUE_SEL, queue as u32);
                t.write_reg(mmio::QUEUE_READY, if ready { 1 } else { 0 });
            }
            VirtioTransport::Pci(t) => {
                write_volatile(&mut (*t.common_cfg).queue_select, queue);
                write_volatile(&mut (*t.common_cfg).queue_enable, if ready { 1 } else { 0 });
                // Memory barrier to ensure writes are flushed
                fence(Ordering::SeqCst);
            }
        }
    }

    /// Notify the device that descriptors are available.
    ///
    /// # Arguments
    /// * `queue` - Queue index
    /// * `notify_off` - Notify offset (from queue_notify_off())
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized.
    pub unsafe fn notify(&self, queue: u16, notify_off: u16) {
        match self {
            VirtioTransport::Mmio(t) => {
                t.write_reg(mmio::QUEUE_NOTIFY, queue as u32);
            }
            VirtioTransport::Pci(t) => {
                // R34-VIRTIO-1 FIX: Check for overflow and bounds before MMIO write
                // A malicious device could set notify_off_multiplier to cause overflow
                // or point outside the mapped notify region.
                let offset_bytes = match (notify_off as u32).checked_mul(t.notify_off_multiplier) {
                    Some(off) => off,
                    None => {
                        // Overflow in offset calculation - drop the notify silently
                        return;
                    }
                };
                // R35-VIRTIO-1 FIX: Zero-length notify regions are invalid
                if t.notify_len == 0 {
                    return;
                }
                // Bounds check: offset + 2 (u16 write) must fit within notify window
                if offset_bytes > t.notify_len.saturating_sub(2) {
                    return;
                }
                let notify_ptr = t.notify_base.add(offset_bytes as usize) as *mut u16;
                write_volatile(notify_ptr, queue);
                // Memory barrier after notify
                fence(Ordering::SeqCst);
            }
        }
    }

    /// Base pointer for the device-specific configuration region.
    ///
    /// # Safety
    /// Caller must ensure the transport is properly initialized and the pointer
    /// is accessed with appropriate volatile semantics.
    pub unsafe fn device_config_base(&self) -> *mut u8 {
        match self {
            VirtioTransport::Mmio(t) => t.base.add(mmio::CONFIG),
            VirtioTransport::Pci(t) => t.device_cfg,
        }
    }

    /// Read raw bytes from the device-specific configuration region.
    ///
    /// # Safety
    /// Caller must ensure bounds are valid for the target device.
    pub unsafe fn read_config_bytes(&self, offset: usize, buf: &mut [u8]) {
        let base = self.device_config_base();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = read_volatile(base.add(offset + i));
        }
    }

    /// Read a device-specific configuration struct using volatile byte copy.
    ///
    /// This is a generic method that reads the device config into any `repr(C)` struct.
    ///
    /// # Safety
    /// The type `T` must be `repr(C)` and match the device's config layout.
    pub unsafe fn read_config_struct<T: Copy>(&self) -> T {
        let mut out = MaybeUninit::<T>::uninit();
        let raw =
            core::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, core::mem::size_of::<T>());
        self.read_config_bytes(0, raw);
        out.assume_init()
    }
}

// ============================================================================
// MMIO Transport
// ============================================================================

/// virtio-mmio transport implementation.
///
/// This transport uses fixed MMIO offsets as defined in the VirtIO spec.
pub struct MmioTransport {
    /// Base virtual address of MMIO region
    pub(crate) base: *mut u8,
    /// Cached version value
    pub(crate) version: u32,
}

// SAFETY: MmioTransport contains raw pointer to MMIO region which is
// accessed through volatile operations only.
unsafe impl Send for MmioTransport {}
unsafe impl Sync for MmioTransport {}

impl MmioTransport {
    /// Probe for a virtio-mmio device at the given physical address.
    ///
    /// # Arguments
    /// * `mmio_phys` - Physical address of the MMIO region
    /// * `virt_offset` - Offset to convert physical to virtual address
    ///
    /// # Returns
    /// `Some(MmioTransport)` if a valid VirtIO device is found.
    ///
    /// # Safety
    /// Caller must ensure the MMIO region is properly mapped.
    pub unsafe fn probe(mmio_phys: u64, virt_offset: u64) -> Option<Self> {
        let base = (mmio_phys + virt_offset) as *mut u8;

        // Check magic value
        let magic = read_volatile(base.add(mmio::MAGIC_VALUE) as *const u32);
        if magic != VIRTIO_MAGIC {
            return None;
        }

        // Check version
        let version = read_volatile(base.add(mmio::VERSION) as *const u32);
        if version != VIRTIO_VERSION_LEGACY && version != VIRTIO_VERSION_MODERN {
            return None;
        }

        Some(Self { base, version })
    }

    /// Read a 32-bit register.
    #[inline]
    pub(crate) unsafe fn read_reg(&self, offset: usize) -> u32 {
        read_volatile(self.base.add(offset) as *const u32)
    }

    /// Write a 32-bit register.
    #[inline]
    pub(crate) unsafe fn write_reg(&self, offset: usize, value: u32) {
        write_volatile(self.base.add(offset) as *mut u32, value);
    }
}

// ============================================================================
// PCI Transport
// ============================================================================

/// Parsed PCI capability addresses for virtio-pci modern transport.
///
/// These addresses are obtained by parsing the PCI capability list
/// and extracting the virtio-specific capabilities (vendor ID 0x09).
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioPciAddrs {
    /// VirtIO device type from PCI subsystem ID (e.g., 2 for block device)
    pub virtio_device_type: u16,
    /// Common configuration structure physical address
    pub common_cfg: u64,
    /// Notification structure base physical address
    pub notify_base: u64,
    /// Notification capability length (bytes) for bounds checking
    pub notify_len: u32,
    /// Notify offset multiplier (from notify capability)
    pub notify_off_multiplier: u32,
    /// ISR status register physical address
    pub isr: u64,
    /// Device-specific configuration physical address
    pub device_cfg: u64,
}

/// virtio-pci common configuration structure (VirtIO 1.1+).
///
/// This structure is defined in VirtIO spec section 4.1.4.3.
#[repr(C)]
pub struct VirtioPciCommonCfg {
    /// Device feature select (0=low, 1=high)
    pub device_feature_select: u32,
    /// Device features (based on select)
    pub device_feature: u32,
    /// Driver feature select (0=low, 1=high)
    pub driver_feature_select: u32,
    /// Driver features (based on select)
    pub driver_feature: u32,
    /// MSI-X config vector
    pub msix_config: u16,
    /// Number of queues
    pub num_queues: u16,
    /// Device status
    pub device_status: u8,
    /// Configuration generation
    pub config_generation: u8,
    /// Queue select
    pub queue_select: u16,
    /// Queue size
    pub queue_size: u16,
    /// Queue MSI-X vector
    pub queue_msix_vector: u16,
    /// Queue enable
    pub queue_enable: u16,
    /// Queue notify offset
    pub queue_notify_off: u16,
    /// Queue descriptor table address
    pub queue_desc: u64,
    /// Queue available ring address
    pub queue_avail: u64,
    /// Queue used ring address
    pub queue_used: u64,
}

/// virtio-pci modern transport implementation.
pub struct VirtioPciTransport {
    /// VirtIO device type (e.g., 2 for block device)
    pub(crate) virtio_device_type: u32,
    /// Pointer to common configuration
    pub(crate) common_cfg: *mut VirtioPciCommonCfg,
    /// Pointer to notification base
    pub(crate) notify_base: *mut u8,
    /// Size of notification structure (bytes) for bounds checking
    pub(crate) notify_len: u32,
    /// Notify offset multiplier
    pub(crate) notify_off_multiplier: u32,
    /// Pointer to ISR status
    #[allow(dead_code)]
    pub(crate) isr: *mut u8,
    /// Pointer to device configuration
    pub(crate) device_cfg: *mut u8,
}

// SAFETY: VirtioPciTransport contains raw pointers to MMIO regions
// which are accessed through volatile operations only.
unsafe impl Send for VirtioPciTransport {}
unsafe impl Sync for VirtioPciTransport {}

impl VirtioPciTransport {
    /// Create a PCI transport from parsed capability addresses.
    ///
    /// # Arguments
    /// * `addrs` - Parsed PCI capability addresses
    /// * `virt_offset` - Offset to convert physical to virtual address
    ///
    /// # Returns
    /// `Some(VirtioPciTransport)` if all required capabilities are present.
    ///
    /// # Safety
    /// Caller must ensure the MMIO regions are properly mapped.
    pub unsafe fn from_addrs(addrs: VirtioPciAddrs, virt_offset: u64) -> Option<Self> {
        // Validate required capabilities
        // R35-VIRTIO-1 FIX: Modern notify capability must advertise a usable window
        if addrs.virtio_device_type == 0
            || addrs.common_cfg == 0
            || addrs.notify_base == 0
            || addrs.device_cfg == 0
            || addrs.notify_len < 2
        {
            return None;
        }

        // Use wrapping_add for offset calculation
        let common_cfg = addrs.common_cfg.wrapping_add(virt_offset) as *mut VirtioPciCommonCfg;
        let notify_base = addrs.notify_base.wrapping_add(virt_offset) as *mut u8;
        let isr = if addrs.isr != 0 {
            addrs.isr.wrapping_add(virt_offset) as *mut u8
        } else {
            core::ptr::null_mut()
        };
        let device_cfg = addrs.device_cfg.wrapping_add(virt_offset) as *mut u8;

        Some(Self {
            virtio_device_type: addrs.virtio_device_type as u32,
            common_cfg,
            notify_base,
            notify_len: addrs.notify_len,
            notify_off_multiplier: addrs.notify_off_multiplier,
            isr,
            device_cfg,
        })
    }
}
