//! PCI scanning for network devices.
//!
//! This module provides PCI bus scanning to discover virtio-net devices.

use alloc::vec::Vec;
use core::arch::asm;
// R165-20 FIX: Share the IOMMU's PCI config lock so this module's CF8/CFC
// accesses are serialized against the IOMMU isolation code (the only other
// PCI config-space user). Without it, an RMW here could interleave with an
// IOMMU config access on another CPU and corrupt the CF8 address latch.
use iommu::{attach_device, PciDeviceId, PCI_CONFIG_LOCK};
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
                // R165-20 FIX: atomic RMW so a concurrent IOMMU config write
                // cannot be lost between the read and the write-back.
                pci_update16(bus, dev, func, PCI_COMMAND, |cmd| cmd | 0x06);

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
                    // R165-20 FIX: atomic RMW (see pci_update16).
                    pci_update16(bus, dev, func, PCI_COMMAND, |cmd| cmd & !0x04);
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
        // R169-L8 FIX: `ptr` is driven by the device-controlled `next` byte and
        // the per-cap reads compute `ptr + N` as a u8 (config offsets are u8). A
        // virtio cap is processed only when cap_len >= 16 (it occupies
        // ptr..ptr+15), so a valid start cannot exceed 0xF0 (ptr+15 <= 0xFF).
        // Reject ptr outside [0x40, 0xF0] so the base + notify-len reads (up to
        // ptr+12) never wrap u8 and never read outside the 256-byte config
        // space; the deeper ptr+16 notify-multiplier read is bounded separately
        // below. Without this a malicious device advertising a cap pointer in
        // 0xF1..=0xFF wraps the u8 add (release: misread offset; with
        // overflow-checks: panic-DoS).
        if !(0x40..=0xF0).contains(&ptr) {
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
                        // R169-L8 FIX: ptr+16 must not wrap the u8 add; only read
                        // it when ptr <= 0xEF (0xEF+16 == 0xFF). A cap claiming
                        // length >= 20 at a higher start is malformed — skip the
                        // optional multiplier rather than overflow.
                        if cap_len >= 20 && ptr <= 0xEF {
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

/// Raw (non-locking) 32-bit PCI config read.
///
/// R165-20 FIX: This performs the CF8/CFC port pair WITHOUT taking
/// `PCI_CONFIG_LOCK`. It must only be called by a public helper that already
/// holds the lock (otherwise the address/data pair is not atomic). Keeping the
/// raw form separate lets `pci_update16`'s read-modify-write run entirely under
/// a single lock acquisition — `spin::Mutex` is non-reentrant, so a public
/// helper calling another public helper while holding the lock would deadlock.
#[inline]
fn raw_pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
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
fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let _guard = PCI_CONFIG_LOCK.lock();
    raw_pci_read32(bus, dev, func, offset)
}

#[inline]
fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let _guard = PCI_CONFIG_LOCK.lock();
    let shift = (offset & 2) * 8;
    (raw_pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u16
}

#[inline]
fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let _guard = PCI_CONFIG_LOCK.lock();
    let shift = (offset & 3) * 8;
    (raw_pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u8
}

/// Atomically read-modify-write a 16-bit PCI config register under a single
/// lock acquisition.
///
/// R165-20 FIX: callers enable/disable bus mastering and memory space by
/// read-modify-writing PCI_COMMAND. Doing that as a separate `pci_read16`
/// followed by a 16-bit write would release `PCI_CONFIG_LOCK` between the read
/// and the write, so the IOMMU isolation path on another CPU could change the
/// register in the gap and then be clobbered by our stale value. This helper
/// performs the whole read-modify-write while holding the lock, eliminating the
/// command-register RMW race at the API level (there is intentionally no
/// stale-value `pci_write16`, which invited that footgun).
///
/// `f` receives the current 16-bit value and returns the new value to store.
#[inline]
fn pci_update16(bus: u8, dev: u8, func: u8, offset: u8, f: impl FnOnce(u16) -> u16) {
    let _guard = PCI_CONFIG_LOCK.lock();
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let cur = raw_pci_read32(bus, dev, func, aligned);
    let old = ((cur >> shift) & 0xFFFF) as u16;
    let new = f(old);
    let dword = (cur & !(0xFFFFu32 << shift)) | ((new as u32) << shift);

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
    // R165-20 FIX: atomic RMW (see pci_update16).
    pci_update16(slot.bus, slot.device, slot.function, PCI_COMMAND, |cmd| cmd & !0x04);
}
