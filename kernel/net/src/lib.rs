//! Zero-OS Network Primitives
//!
//! This crate provides core networking infrastructure for Zero-OS, including:
//! - DMA-compatible packet buffers with headroom/tailroom support
//! - Buffer pools for efficient packet allocation
//! - Network device trait abstraction (future)
//!
//! # Design
//!
//! Network buffers are designed for zero-copy DMA operations:
//! - Physical addresses are tracked for device DMA
//! - Headroom allows prepending protocol headers without copying
//! - Tailroom allows appending trailers (checksums, padding)
//!
//! # Example
//!
//! ```ignore
//! let pool = BufPool::new(64); // Preallocate 64 buffers
//! let mut buf = pool.alloc().expect("out of buffers");
//!
//! // Receive data into buffer
//! let data = buf.push_tail(1500).unwrap();
//! // ... DMA fills data ...
//!
//! // Process and prepend header
//! let hdr = buf.push_head(14).unwrap(); // Ethernet header
//! hdr.copy_from_slice(&eth_header);
//! ```

#![no_std]

extern crate alloc;
extern crate security;
#[macro_use]
extern crate klog;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once, RwLock};
use x86_64::{PhysAddr, VirtAddr};

pub mod arp;
pub mod buffer;
pub mod conntrack;
pub mod device;
pub mod ethernet;
pub mod firewall;
pub mod fragment;
pub mod icmp;
pub mod ipv4;
mod pci;
pub mod socket;
pub mod stack;
pub mod tcp;
pub mod udp;
pub mod virtio_net;

pub use arp::{
    build_arp_reply, build_arp_request, build_gratuitous_arp, parse_arp, process_arp,
    serialize_arp, ArpCache, ArpEntry, ArpEntryKind, ArpError, ArpOp, ArpPacket, ArpResult,
    ArpStats, ARP_RX_RATE_LIMITER, ARP_TX_RATE_LIMITER,
};
pub use buffer::{BufPool, NetBuf};
pub use device::{
    DeviceCaps, LinkStatus, MacAddress, NetDevice, NetError, OperatingMode, RxError, TxError,
};
pub use ethernet::{
    build_ethernet_frame, parse_ethernet, EthAddr, EthError, EthHeader, ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
};
pub use firewall::{
    firewall_table, log_match, CtStateMask, FirewallAction, FirewallPacket, FirewallRule,
    FirewallRuleBuilder, FirewallStats, FirewallStatsSnapshot, FirewallTable, FirewallVerdict,
    IpCidrMatch, PortRange,
};
pub use fragment::{
    cleanup_expired_fragments, fragment_cache, process_fragment, FragmentCache, FragmentDropReason,
    FragmentKey, FragmentStats, FRAG_TIMEOUT_MS, MAX_FRAGS_PER_QUEUE, MAX_PACKET_SIZE,
};
pub use icmp::{
    build_echo_reply, parse_icmp, IcmpError, IcmpHeader, TokenBucket, ICMP_RATE_LIMITER,
    ICMP_TYPE_DEST_UNREACHABLE, ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO_REQUEST,
    ICMP_TYPE_TIME_EXCEEDED,
};
pub use ipv4::{
    build_ipv4_header, compute_checksum, parse_ipv4, Ipv4Addr, Ipv4Error, Ipv4Header, Ipv4Proto,
};
pub use socket::{
    register_socket_wait_hooks, socket_table, PendingDatagram, SocketDomain, SocketError,
    SocketLabel, SocketProtocol, SocketState, SocketStats, SocketTable, SocketType,
    SocketWaitHooks, TableStats, TcpConnectResult, WaitOutcome, WaitQueue,
};
pub use stack::{
    handle_timer_tick, network_config, process_frame, transmit_tcp_segment, transmit_udp_datagram,
    DropReason, NetConfigSnapshot, NetStats, ProcessResult,
};
pub use tcp::{
    build_tcp_segment, build_tcp_segment_with_options, calc_wscale, compute_tcp_checksum,
    decode_window, encode_window, generate_isn, generate_syn_cookie_isn, handle_ack,
    handle_retransmission_timeout, initial_cwnd, parse_tcp_header, parse_tcp_options, seq_ge,
    seq_gt, seq_in_window, seq_le, seq_lt, serialize_tcp_option, serialize_tcp_options,
    syn_cookie_select_mss, update_congestion_control, update_rtt, validate_cwnd_after_idle,
    validate_syn_cookie, verify_tcp_checksum, AckUpdate, CongestionAction, SynCookieData,
    TcpCongestionState, TcpConnKey, TcpControlBlock, TcpError, TcpHeader, TcpOptionKind,
    TcpOptions, TcpResult, TcpSegment, TcpState, TcpStats, TCP_DEFAULT_MSS,
    TCP_DEFAULT_RCV_WINDOW_BYTES, TCP_DEFAULT_WINDOW, TCP_ETHERNET_MSS, TCP_FIN_TIMEOUT_MS,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
    TCP_HEADER_MAX_LEN, TCP_HEADER_MIN_LEN, TCP_INITIAL_SSTHRESH, TCP_MAX_ACCEPT_BACKLOG,
    TCP_MAX_FIN_RETRIES, TCP_MAX_RETRIES, TCP_MAX_RTO_MS, TCP_MAX_SCALED_WINDOW, TCP_MAX_SEND_SIZE,
    TCP_MAX_SYN_BACKLOG, TCP_MAX_WINDOW_SCALE, TCP_PROTO, TCP_SYN_COOKIE_MAX_AGE_MS,
    TCP_SYN_COOKIE_MSS_TABLE, TCP_TIME_WAIT_MS,
};
pub use udp::{
    build_udp_datagram, compute_udp_checksum, parse_udp, parse_udp_header, verify_udp_checksum,
    UdpError, UdpHeader, UdpResult, UdpStats, UDP_HEADER_LEN, UDP_PROTO,
};
pub use virtio_net::VirtioNetDevice;

// ============================================================================
// Network Constants
// ============================================================================

/// Default Maximum Transmission Unit for Ethernet payloads.
pub const DEFAULT_MTU: usize = 1500;

/// Default headroom reserved for protocol headers (Ethernet + IP + TCP/UDP).
/// 14 (Ethernet) + 20 (IP) + 20 (TCP) = 54, rounded up to 64 for alignment.
pub const DEFAULT_HEADROOM: usize = 64;

/// Default tailroom reserved for trailers (checksums, padding, VLAN tags).
pub const DEFAULT_TAILROOM: usize = 64;

/// Size of the VirtIO network header prepended by virtio-net devices.
/// This header contains checksum and segmentation offload information.
pub const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Ethernet header size (6 dst + 6 src + 2 ethertype).
pub const ETH_HEADER_SIZE: usize = 14;

/// Minimum Ethernet frame size (excluding FCS).
pub const ETH_MIN_FRAME_SIZE: usize = 60;

/// Maximum Ethernet frame size (excluding FCS, including header).
pub const ETH_MAX_FRAME_SIZE: usize = 1514;

/// Maximum number of network devices supported.
pub const MAX_NET_DEVICES: usize = 8;

// ============================================================================
// Network Device Registry
// ============================================================================

/// Handle type for registered network devices.
pub type NetDeviceHandle = Arc<Mutex<Box<dyn NetDevice>>>;

/// A registered network device entry.
struct RegisteredDevice {
    name: String,
    index: usize,
    device: NetDeviceHandle,
}

/// Global network device registry.
struct NetDeviceRegistry {
    devices: RwLock<Vec<RegisteredDevice>>,
    next_index: AtomicUsize,
}

impl NetDeviceRegistry {
    fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
            next_index: AtomicUsize::new(0),
        }
    }

    fn register<D: NetDevice + 'static>(&self, device: D) -> Result<usize, NetError> {
        let mut devices = self.devices.write();

        if devices.len() >= MAX_NET_DEVICES {
            return Err(NetError::InvalidState);
        }

        let name = String::from(device.name());
        if devices.iter().any(|d| d.name == name) {
            return Err(NetError::InvalidConfig);
        }

        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let handle: NetDeviceHandle = Arc::new(Mutex::new(Box::new(device)));

        devices.push(RegisteredDevice {
            name,
            index,
            device: handle,
        });

        Ok(index)
    }

    fn get_by_name(&self, name: &str) -> Option<NetDeviceHandle> {
        let devices = self.devices.read();
        devices
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.device.clone())
    }

    fn get_by_index(&self, index: usize) -> Option<NetDeviceHandle> {
        let devices = self.devices.read();
        devices
            .iter()
            .find(|d| d.index == index)
            .map(|d| d.device.clone())
    }

    fn count(&self) -> usize {
        self.devices.read().len()
    }

    fn list(&self) -> Vec<String> {
        let devices = self.devices.read();
        devices.iter().map(|d| d.name.clone()).collect()
    }
}

static NET_REGISTRY: Once<NetDeviceRegistry> = Once::new();

#[inline]
fn registry() -> &'static NetDeviceRegistry {
    NET_REGISTRY.call_once(NetDeviceRegistry::new)
}

/// Register a network device in the global registry.
pub fn register_device<D: NetDevice + 'static>(device: D) -> Result<usize, NetError> {
    registry().register(device)
}

/// Get a device by name.
pub fn get_device(name: &str) -> Option<NetDeviceHandle> {
    registry().get_by_name(name)
}

/// Get a device by registration index.
pub fn get_device_by_index(index: usize) -> Option<NetDeviceHandle> {
    registry().get_by_index(index)
}

/// Get the number of registered devices.
pub fn device_count() -> usize {
    registry().count()
}

/// List names of all registered network devices.
pub fn list_devices() -> Vec<String> {
    registry().list()
}

// ============================================================================
// MMIO Mapping for PCI Devices
// ============================================================================

/// Base virtual address for network MMIO regions.
/// Uses a separate range from block driver to avoid conflicts.
const NET_MMIO_VIRT_BASE: u64 = 0xffff_ffff_5000_0000;

/// Maximum size of the network MMIO virtual address region (64 MB).
const NET_MMIO_VIRT_SIZE: u64 = 64 * 1024 * 1024;

/// Current offset within the network MMIO virtual address region.
static NET_MMIO_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Map a physical MMIO region and return the virtual offset to use.
///
/// After security hardening, identity mapping is read-only, so we must
/// explicitly map MMIO regions to a writable virtual address range.
///
/// # Arguments
/// * `phys_base` - Physical base address of the MMIO region
/// * `size` - Size of the MMIO region in bytes
///
/// # Returns
/// * `Ok(virt_offset)` - Offset to add to physical address to get virtual address
/// * `Err(NetError)` - Mapping failed
///
/// # Safety
/// The caller must ensure the physical address is a valid MMIO region.
unsafe fn map_pci_mmio(phys_base: u64, size: usize) -> Result<i64, NetError> {
    // Allocate virtual address space (page-aligned)
    let aligned_size = (size + 0xFFF) & !0xFFF;
    let offset = NET_MMIO_OFFSET.fetch_add(aligned_size as u64, Ordering::SeqCst);

    if offset + aligned_size as u64 > NET_MMIO_VIRT_SIZE {
        klog!(Error, "      [NET MMIO] Virtual space exhausted");
        return Err(NetError::IoError);
    }

    let virt_addr = NET_MMIO_VIRT_BASE + offset;
    let virt_offset = virt_addr as i64 - phys_base as i64;

    klog!(Info, 
        "      [NET MMIO] Mapping phys {:#x} -> virt {:#x} (size {:#x})",
        phys_base,
        virt_addr,
        aligned_size
    );

    // Create the mapping using the mm crate's map_mmio function
    let mut frame_alloc = mm::FrameAllocator::new();

    match mm::map_mmio(
        VirtAddr::new(virt_addr),
        PhysAddr::new(phys_base),
        aligned_size,
        &mut frame_alloc,
    ) {
        Ok(()) => {
            klog!(Info, "      [NET MMIO] Mapping successful");
            Ok(virt_offset)
        }
        Err(e) => {
            klog!(Error, "      [NET MMIO] Mapping failed: {:?}", e);
            Err(NetError::IoError)
        }
    }
}

/// Map all MMIO regions from VirtioPciAddrs and return modified addrs with virtual offset.
///
/// This creates proper page table mappings for all PCI capability regions.
unsafe fn map_virtio_pci_regions(
    addrs: &virtio::VirtioPciAddrs,
) -> Result<(virtio::VirtioPciAddrs, i64), NetError> {
    // Calculate total MMIO range we need to map
    // The regions are: common_cfg, notify_base, isr, device_cfg
    // They're typically close together in a single BAR

    let min_addr = [
        addrs.common_cfg,
        addrs.notify_base,
        addrs.isr,
        addrs.device_cfg,
    ]
    .iter()
    .filter(|&&a| a != 0)
    .min()
    .copied()
    .ok_or(NetError::NotSupported)?;

    let max_addr = [
        addrs.common_cfg + 64, // VirtioPciCommonCfg is ~64 bytes
        addrs.notify_base + addrs.notify_len as u64,
        addrs.isr + 4,
        addrs.device_cfg + 16, // Device config varies, use reasonable size
    ]
    .iter()
    .max()
    .copied()
    .ok_or(NetError::NotSupported)?;

    let size = (max_addr - min_addr) as usize;
    let size = (size + 0xFFF) & !0xFFF; // Page align

    // Map the entire range
    let virt_offset = map_pci_mmio(min_addr, size)?;

    Ok((*addrs, virt_offset))
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the network subsystem.
///
/// This probes for network devices (currently virtio-net via PCI) and
/// registers them in the global device registry.
///
/// Returns the number of devices successfully initialized.
pub fn init() -> usize {
    klog_always!("  Network subsystem initialized");
    klog_always!("      Probing for network devices...");

    let mut registered = 0;

    // Probe PCI for virtio-net devices
    let pci_devices = pci::probe_virtio_net();

    if pci_devices.is_empty() {
        klog_always!("      No virtio-net devices found");
    } else {
        for (idx, pci_dev) in pci_devices.iter().enumerate() {
            let name = alloc::format!("eth{}", idx);

            // Map the MMIO regions for this device.
            // After security hardening, identity mapping is read-only,
            // so we must create explicit writable mappings.
            let virt_offset = match unsafe { map_virtio_pci_regions(&pci_dev.addrs) } {
                Ok((_, offset)) => offset,
                Err(e) => {
                    // R82-4 FIX: Disable bus mastering on MMIO mapping failure
                    pci::disable_bus_master(&pci_dev.slot);
                    klog!(Error,
                        "      ! MMIO mapping failed for {:02x}:{:02x}.{}: {:?} (bus master disabled)",
                        pci_dev.slot.bus,
                        pci_dev.slot.device,
                        pci_dev.slot.function,
                        e
                    );
                    continue;
                }
            };

            match unsafe { VirtioNetDevice::probe_pci(pci_dev.addrs, virt_offset as u64, &name) } {
                Ok(device) => {
                    let mac = device.mac_address();
                    let link = device.link_status();

                    match register_device(device) {
                        Ok(_) => {
                            klog!(Info, 
                                "      ✓ {} @ {:02x}:{:02x}.{} MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
                                name,
                                pci_dev.slot.bus,
                                pci_dev.slot.device,
                                pci_dev.slot.function,
                                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                                if link.up { "up" } else { "down" }
                            );
                            registered += 1;
                        }
                        Err(e) => {
                            // R82-4 FIX: Disable bus mastering on registration failure
                            pci::disable_bus_master(&pci_dev.slot);
                            klog!(Error,
                                "      ! Failed to register {}: {:?} (bus master disabled)",
                                name, e
                            );
                        }
                    }
                }
                Err(e) => {
                    // R82-4 FIX: Disable bus mastering on driver probe failure
                    pci::disable_bus_master(&pci_dev.slot);
                    klog!(Error,
                        "      ! virtio-net probe @ {:02x}:{:02x}.{} failed: {:?} (bus master disabled)",
                        pci_dev.slot.bus,
                        pci_dev.slot.device,
                        pci_dev.slot.function,
                        e
                    );
                }
            }
        }
    }

    if registered > 0 {
        klog_always!("      ✓ {} network device(s) registered", registered);
    }

    registered
}
