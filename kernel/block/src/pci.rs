//! Minimal PCI helper for virtio-blk probing (CF8/CFC)
//!
//! Provides:
//! - pci_config_read32 / pci_config_write16 using legacy I/O ports
//! - probe_virtio_blk: scan PCI buses for virtio-blk (transitional 0x1001 / modern 0x1042)
//! - PCI capability parsing for virtio-pci modern transport

use core::arch::asm;

use crate::virtio::VirtioPciAddrs;
use iommu::{attach_device, PciDeviceId};

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1af4;
// 0x1001 is transitional (QEMU default) - may expose modern PCI capabilities
const VIRTIO_BLK_TRANSITIONAL: u16 = 0x1001;
const VIRTIO_BLK_MODERN: u16 = 0x1042;

const PCI_COMMAND_OFFSET: u8 = 0x04;
const PCI_BAR0_OFFSET: u8 = 0x10;
const PCI_SUBSYSTEM_ID: u8 = 0x2E; // Subsystem ID (contains virtio device type)
const PCI_CAP_PTR: u8 = 0x34;

/// VirtIO PCI capability types (VirtIO 1.1 Section 4.1.4)
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Vendor-specific capability ID for VirtIO
const PCI_CAP_ID_VNDR: u8 = 0x09;

/// Write 32-bit value to an I/O port
#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

/// Read 32-bit value from an I/O port
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Build config address and read 32 bits from PCI configuration space.
///
/// # Arguments
/// * `bus` - PCI bus number (0-255)
/// * `dev` - Device number on the bus (0-31)
/// * `func` - Function number (0-7)
/// * `offset` - Register offset in configuration space (must be 4-byte aligned)
pub fn pci_config_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
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

/// Write 16 bits into PCI configuration space (read-modify-write).
///
/// # Arguments
/// * `bus` - PCI bus number
/// * `dev` - Device number
/// * `func` - Function number
/// * `offset` - Register offset (2-byte aligned)
/// * `val` - Value to write
pub fn pci_config_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let mut dword = pci_config_read32(bus, dev, func, aligned);
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

/// Read 8-bit value from PCI configuration space.
#[inline]
fn pci_config_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let shift = (offset & 3) * 8;
    (pci_config_read32(bus, dev, func, offset & 0xFC) >> shift) as u8
}

/// Read 16-bit value from PCI configuration space.
#[inline]
fn pci_config_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let shift = (offset & 2) * 8;
    (pci_config_read32(bus, dev, func, offset & 0xFC) >> shift) as u16
}

/// Read a BAR (Base Address Register) and return the physical address.
///
/// Handles both 32-bit and 64-bit BARs. Returns None for I/O BARs.
fn read_bar(bus: u8, dev: u8, func: u8, bar: u8) -> Option<u64> {
    if bar >= 6 {
        return None;
    }
    let off = PCI_BAR0_OFFSET + bar * 4;
    let low = pci_config_read32(bus, dev, func, off);

    // DEBUG: Print raw BAR value
    // println!("      [BAR] bar{} raw low={:#x}", bar, low);

    // Check if this is an I/O BAR (bit 0 = 1)
    if low & 1 != 0 {
        return None;
    }

    // Check BAR type (bits 1-2)
    let bar_type = (low >> 1) & 0x3;

    if bar_type == 2 {
        // 64-bit BAR: read the high 32 bits from the next BAR
        // The address might be entirely in the high 32 bits!
        if bar >= 5 {
            return None; // No room for high 32 bits
        }
        let high = pci_config_read32(bus, dev, func, off + 4);
        let base_low = (low & !0xFu32) as u64;
        let base = base_low | ((high as u64) << 32);
        if base == 0 {
            return None;
        }
        Some(base)
    } else {
        // 32-bit BAR
        let base = (low & !0xFu32) as u64;
        if base == 0 {
            return None;
        }
        Some(base)
    }
}

/// Parse VirtIO PCI capabilities from the capability list.
///
/// Walks the PCI capability list looking for VirtIO-specific capabilities
/// (vendor ID 0x09) and extracts the addresses for common config, notify,
/// ISR, and device-specific config regions.
fn read_virtio_pci_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioPciAddrs> {
    let mut caps = VirtioPciAddrs::default();
    let mut found_caps = 0u8;

    // Start from the capability pointer
    let mut ptr = pci_config_read8(bus, dev, func, PCI_CAP_PTR);

    // Walk the capability list (max 48 iterations to prevent infinite loop)
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }

        let cap_id = pci_config_read8(bus, dev, func, ptr);
        let next = pci_config_read8(bus, dev, func, ptr + 1);
        let cap_len = pci_config_read8(bus, dev, func, ptr + 2);

        // Check for VirtIO vendor-specific capability
        if cap_id == PCI_CAP_ID_VNDR && cap_len >= 16 {
            // VirtIO PCI capability structure:
            // offset 0: cap_vndr (0x09)
            // offset 1: cap_next
            // offset 2: cap_len
            // offset 3: cfg_type (1=common, 2=notify, 3=isr, 4=device)
            // offset 4: bar
            // offset 5-7: padding
            // offset 8-11: offset within BAR
            // offset 12-15: length
            let cfg_type = pci_config_read8(bus, dev, func, ptr + 3);
            let bar = pci_config_read8(bus, dev, func, ptr + 4);
            let offset = pci_config_read32(bus, dev, func, ptr + 8);

            found_caps += 1;

            if let Some(bar_base) = read_bar(bus, dev, func, bar) {
                let phys = bar_base + offset as u64;

                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => {
                        caps.common_cfg = phys;
                    }
                    VIRTIO_PCI_CAP_NOTIFY_CFG => {
                        caps.notify_base = phys;
                        // R34-VIRTIO-1 FIX: Read notify capability length for bounds checking
                        // The length field is at offset 12-15 within the capability structure
                        let notify_len = pci_config_read32(bus, dev, func, ptr + 12);
                        caps.notify_len = notify_len;
                        // Notify capability has extra field at offset 16
                        if cap_len >= 20 {
                            caps.notify_off_multiplier =
                                pci_config_read32(bus, dev, func, ptr + 16);
                        }
                    }
                    VIRTIO_PCI_CAP_ISR_CFG => {
                        caps.isr = phys;
                    }
                    VIRTIO_PCI_CAP_DEVICE_CFG => {
                        caps.device_cfg = phys;
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

    // Validate that we have the required capabilities
    if caps.common_cfg != 0 && caps.notify_base != 0 && caps.device_cfg != 0 {
        Some(caps)
    } else {
        None
    }
}

/// Probe PCI buses for the first virtio-blk device.
///
/// Scans all device slots on buses 0-255 looking for a virtio-blk device
/// (vendor 0x1af4, device 0x1001 transitional or 0x1042 modern).
///
/// When found, enables memory access and bus mastering, then parses
/// the PCI capability list to extract virtio-pci configuration addresses.
///
/// # Returns
/// * `Some((pci_id, pci_addrs, device_name))` - Found device with modern virtio-pci capabilities
/// * `None` - No compatible virtio-blk device found
pub fn probe_virtio_blk() -> Option<(PciDeviceId, VirtioPciAddrs, &'static str)> {
    // Scan all PCI buses (0-255)
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            // Check function 0 first
            let header_type = pci_config_read8(bus, dev, 0, 0x0E);
            let max_func = if header_type & 0x80 != 0 { 8 } else { 1 };

            for func in 0u8..max_func {
                let id = pci_config_read32(bus, dev, func, 0x00);

                // Check for valid device (0xFFFF vendor = no device)
                let vendor = (id & 0xFFFF) as u16;
                if vendor == 0xFFFF {
                    if func == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }

                let device = ((id >> 16) & 0xFFFF) as u16;

                if vendor != VIRTIO_VENDOR {
                    continue;
                }
                if device != VIRTIO_BLK_TRANSITIONAL && device != VIRTIO_BLK_MODERN {
                    continue;
                }

                // Attach device to IOMMU before enabling bus mastering (fail-closed)
                let pci_id = PciDeviceId::from_bdf(bus, dev, func);
                if let Err(err) = attach_device(pci_id) {
                    println!(
                        "    ! IOMMU attach failed for {:02x}:{:02x}.{}: {:?}",
                        bus, dev, func, err
                    );
                    continue;
                }

                // Enable MEM space access + BUS MASTER for DMA
                let mut cmd =
                    (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
                cmd |= 0x2 /* MEM */ | 0x4 /* BUS MASTER */;
                pci_config_write16(bus, dev, func, PCI_COMMAND_OFFSET, cmd);

                // Try to read modern PCI capabilities for both transitional and modern devices
                if let Some(mut caps) = read_virtio_pci_caps(bus, dev, func) {
                    // Read subsystem ID which contains the virtio device type
                    let subsystem_id = pci_config_read16(bus, dev, func, PCI_SUBSYSTEM_ID);
                    caps.virtio_device_type = subsystem_id;

                    let dev_type = if device == VIRTIO_BLK_MODERN {
                        "modern"
                    } else {
                        "transitional"
                    };
                    println!(
                        "    Found virtio-blk ({}) at PCI {:02x}:{:02x}.{}, type={}, common_cfg={:#x}",
                        dev_type, bus, dev, func, subsystem_id, caps.common_cfg
                    );
                    return Some((pci_id, caps, "vda"));
                } else {
                    // R82-2 FIX: Disable bus mastering if device lacks modern caps
                    // to prevent orphaned DMA-capable device
                    let cmd =
                        (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
                    pci_config_write16(bus, dev, func, PCI_COMMAND_OFFSET, cmd & !0x04);
                    let dev_type = if device == VIRTIO_BLK_MODERN {
                        "modern"
                    } else {
                        "transitional"
                    };
                    println!(
                        "    virtio-blk ({}) at PCI {:02x}:{:02x}.{} lacks modern capabilities (bus master disabled)",
                        dev_type, bus, dev, func
                    );
                }
            }
        }
    }
    None
}
