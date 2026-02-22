//! PCI scanning for network devices.
//!
//! This module provides PCI bus scanning to discover virtio-net devices.

use alloc::vec::Vec;
use core::arch::asm;
use iommu::{attach_device, PciDeviceId};
use virtio::VirtioPciAddrs;

// ============================================================================
// PCI Constants
// ============================================================================

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000; // Legacy/transitional device ID
const VIRTIO_NET_MODERN: u16 = 0x1041; // Modern device ID

const PCI_COMMAND: u8 = 0x04;
const PCI_BAR0: u8 = 0x10;
const PCI_SUBSYSTEM_ID: u8 = 0x2E;
const PCI_CAP_PTR: u8 = 0x34;

// VirtIO PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const PCI_CAP_ID_VNDR: u8 = 0x09; // Vendor-specific capability

// ============================================================================
// PCI Device Info
// ============================================================================

/// PCI slot location.
#[derive(Debug, Clone, Copy)]
pub struct PciSlot {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// Discovered virtio-net PCI device.
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetPciDevice {
    pub slot: PciSlot,
    pub addrs: VirtioPciAddrs,
}

// ============================================================================
// PCI Probing
// ============================================================================

/// Probe PCI buses for virtio-net devices.
pub fn probe_virtio_net() -> Vec<VirtioNetPciDevice> {
    let mut devices = Vec::new();
    let mut total_pci_devices = 0;

    // Scan all PCI buses (only scan first few buses for speed)
    for bus in 0u8..8 {
        for dev in 0u8..32 {
            // Check if multi-function device
            let header_type = pci_read8(bus, dev, 0, 0x0E);
            let max_func = if header_type & 0x80 != 0 { 8 } else { 1 };

            for func in 0u8..max_func {
                let vendor_device = pci_read32(bus, dev, func, 0x00);
                let vendor = (vendor_device & 0xFFFF) as u16;

                if vendor == 0xFFFF {
                    if func == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }

                total_pci_devices += 1;
                let device_id = ((vendor_device >> 16) & 0xFFFF) as u16;

                // Debug: Show all PCI devices found
                if vendor == VIRTIO_VENDOR {
                    klog!(Info, 
                        "    [DEBUG] VirtIO device @ {:02x}:{:02x}.{}: device_id={:#x} subsystem_id={:#x}",
                        bus, dev, func, device_id, pci_read16(bus, dev, func, PCI_SUBSYSTEM_ID)
                    );
                }

                // Check for VirtIO vendor
                if vendor != VIRTIO_VENDOR {
                    continue;
                }

                // VirtIO device ID detection:
                // - Transitional network: device_id = 0x1000 (with subsystem_id = 1)
                // - Modern network: device_id = 0x1041
                // - Legacy scheme: device_id = 0x1000-0x103F with subsystem_id encoding type
                //
                // QEMU typically uses:
                // - 0x1000 for transitional network (subsystem_id = 1)
                // - 0x1001 for transitional block (subsystem_id = 2)

                let subsystem_id = pci_read16(bus, dev, func, PCI_SUBSYSTEM_ID);

                // Check if this is a network device
                let is_net = match device_id {
                    // Transitional virtio-net (QEMU uses this)
                    0x1000 => subsystem_id == 1,
                    // Modern virtio-net
                    0x1041 => true,
                    // Not a network device
                    _ => false,
                };

                if !is_net {
                    continue;
                }

                klog!(Info, 
                    "    Probing virtio-net candidate: {:02x}:{:02x}.{} device={:#x} subsys={:#x}",
                    bus,
                    dev,
                    func,
                    device_id,
                    subsystem_id
                );

                // Attach device to IOMMU before enabling bus mastering (fail-closed)
                // R94-14 FIX: Handle NotAvailable explicitly - proceed with warning
                // for legacy systems without IOMMU, but fail on other errors.
                let pci_id = PciDeviceId::from_bdf(bus, dev, func);
                match attach_device(pci_id) {
                    Ok(()) => {}
                    Err(iommu::IommuError::NotAvailable) => {
                        // IOMMU not present - proceed without DMA isolation (legacy mode)
                        // This is an explicit acknowledgment of the security tradeoff.
                        klog!(Info, 
                            "    ! WARNING: No IOMMU - {:02x}:{:02x}.{} has unprotected DMA access",
                            bus,
                            dev,
                            func
                        );
                    }
                    Err(err) => {
                        // Other IOMMU errors - fail closed (skip device)
                        klog!(Info, 
                            "    ! IOMMU attach failed for {:02x}:{:02x}.{}: {:?}",
                            bus,
                            dev,
                            func,
                            err
                        );
                        continue;
                    }
                }

                // Enable memory space and bus mastering
                let cmd = pci_read16(bus, dev, func, PCI_COMMAND);
                pci_write16(bus, dev, func, PCI_COMMAND, cmd | 0x06);

                // Try to read modern capabilities
                if let Some(mut addrs) = read_virtio_caps(bus, dev, func) {
                    addrs.virtio_device_type = 1; // Network device

                    klog!(Info, 
                        "    Found virtio-net (PCI {:02x}:{:02x}.{}) common_cfg={:#x}",
                        bus,
                        dev,
                        func,
                        addrs.common_cfg
                    );

                    devices.push(VirtioNetPciDevice {
                        slot: PciSlot {
                            bus,
                            device: dev,
                            function: func,
                        },
                        addrs,
                    });
                } else {
                    // R82-1 FIX: Disable bus mastering if device lacks modern caps
                    // to prevent orphaned DMA-capable device
                    let cmd = pci_read16(bus, dev, func, PCI_COMMAND);
                    pci_write16(bus, dev, func, PCI_COMMAND, cmd & !0x04);
                    klog!(Info, 
                        "    ! virtio-net @ {:02x}:{:02x}.{} lacks modern capabilities (bus master disabled)",
                        bus,
                        dev,
                        func
                    );
                }
            }
        }
    }

    devices
}

/// Read VirtIO PCI capabilities from the capability list.
fn read_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioPciAddrs> {
    let mut addrs = VirtioPciAddrs::default();
    let mut ptr = pci_read8(bus, dev, func, PCI_CAP_PTR);

    // Walk capability list (limit iterations to prevent infinite loop)
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }

        let cap_id = pci_read8(bus, dev, func, ptr);
        let next = pci_read8(bus, dev, func, ptr + 1);
        let cap_len = pci_read8(bus, dev, func, ptr + 2);

        // Check for vendor-specific capability (virtio uses this)
        if cap_id == PCI_CAP_ID_VNDR && cap_len >= 16 {
            let cfg_type = pci_read8(bus, dev, func, ptr + 3);
            let bar = pci_read8(bus, dev, func, ptr + 4);
            let offset = pci_read32(bus, dev, func, ptr + 8);

            if let Some(bar_base) = read_bar(bus, dev, func, bar) {
                let phys = bar_base + offset as u64;

                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => {
                        addrs.common_cfg = phys;
                    }
                    VIRTIO_PCI_CAP_NOTIFY_CFG => {
                        addrs.notify_base = phys;
                        let notify_len = pci_read32(bus, dev, func, ptr + 12);
                        addrs.notify_len = notify_len;
                        if cap_len >= 20 {
                            addrs.notify_off_multiplier = pci_read32(bus, dev, func, ptr + 16);
                        }
                    }
                    VIRTIO_PCI_CAP_ISR_CFG => {
                        addrs.isr = phys;
                    }
                    VIRTIO_PCI_CAP_DEVICE_CFG => {
                        addrs.device_cfg = phys;
                    }
                    _ => {}
                }
            }
        }

        if next == 0 {
            break;
        }
        ptr = next;
    }

    // Require at least common_cfg, notify, and device_cfg for modern device
    if addrs.common_cfg != 0 && addrs.notify_base != 0 && addrs.device_cfg != 0 {
        Some(addrs)
    } else {
        None
    }
}

/// Read a BAR (Base Address Register) and return the physical address.
fn read_bar(bus: u8, dev: u8, func: u8, bar: u8) -> Option<u64> {
    if bar >= 6 {
        return None;
    }

    let offset = PCI_BAR0 + bar * 4;
    let low = pci_read32(bus, dev, func, offset);

    // I/O space BAR (bit 0 set) - not supported
    if low & 1 != 0 {
        return None;
    }

    let bar_type = (low >> 1) & 0x3;

    if bar_type == 2 {
        // 64-bit BAR
        if bar >= 5 {
            return None;
        }
        let high = pci_read32(bus, dev, func, offset + 4);
        let base = ((low & !0xF) as u64) | ((high as u64) << 32);
        if base == 0 {
            return None;
        }
        Some(base)
    } else {
        // 32-bit BAR
        let base = (low & !0xF) as u64;
        if base == 0 {
            return None;
        }
        Some(base)
    }
}

// ============================================================================
// PCI Config Space Access
// ============================================================================

#[inline]
fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let aligned = (offset & 0xFC) as u32;
    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | aligned;

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

#[inline]
fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let shift = (offset & 2) * 8;
    (pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u16
}

#[inline]
fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let shift = (offset & 3) * 8;
    (pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u8
}

#[inline]
fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let mut dword = pci_read32(bus, dev, func, aligned);
    let mask = !(0xFFFFu32 << shift);
    dword = (dword & mask) | ((val as u32) << shift);

    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | (aligned as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, dword);
    }
}

#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Disable bus mastering for a PCI device.
///
/// This should be called when a device fails to initialize properly after
/// bus mastering was enabled, to prevent orphaned DMA-capable devices.
pub fn disable_bus_master(slot: &PciSlot) {
    let cmd = pci_read16(slot.bus, slot.device, slot.function, PCI_COMMAND);
    pci_write16(slot.bus, slot.device, slot.function, PCI_COMMAND, cmd & !0x04);
}
