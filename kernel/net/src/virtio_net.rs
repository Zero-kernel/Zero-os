//! VirtIO Network Device Driver for Zero-OS
//!
//! This module implements a minimal virtio-net driver supporting:
//! - MMIO and PCI modern transports
//! - Basic TX/RX via virtqueues
//! - MAC address reading from device configuration
//!
//! # VirtIO Network Queue Layout
//! - Queue 0: Receive queue (device -> driver)
//! - Queue 1: Transmit queue (driver -> device)
//!
//! # References
//! - VirtIO Spec 1.2 Section 5.1: Network Device

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::write_bytes;

use crate::{
    BufPool, DeviceCaps, LinkStatus, MacAddress, NetBuf, NetDevice, NetError, OperatingMode,
    RxError, TxError, VIRTIO_NET_HDR_SIZE,
};
// R95-7 FIX: Import DmaBuffer to store queue memory ownership
use mm::dma::DmaBuffer;
use mm::PHYSICAL_MEMORY_OFFSET;
use virtio::{
    MmioTransport, VirtQueue, VirtioPciAddrs, VirtioPciTransport, VirtioTransport,
    VIRTIO_DEVICE_NET, VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER,
    VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK, VIRTIO_VERSION_MODERN, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE,
};

// ============================================================================
// VirtIO Network Feature Bits
// ============================================================================

/// Device has a MAC address in config space.
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Device status field is available.
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
/// Control channel is available.
#[allow(dead_code)]
const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;

// ============================================================================
// Queue Indices
// ============================================================================

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;
const DEFAULT_QUEUE_SIZE: u16 = 256;
/// R66-8 FIX: Maximum number of completed RX buffers we keep queued for delivery.
/// This prevents unbounded memory growth under packet flood conditions.
const MAX_RX_READY_QUEUE: usize = DEFAULT_QUEUE_SIZE as usize;

// ============================================================================
// VirtIO Network Header
// ============================================================================

/// VirtIO network header prepended to each packet.
///
/// This header is used for checksum offload and segmentation offload.
/// For our MVP, we zero it out (no offloads).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

const _: () = assert!(core::mem::size_of::<VirtioNetHdr>() == VIRTIO_NET_HDR_SIZE);

// ============================================================================
// VirtIO Network Device
// ============================================================================

/// VirtIO network device driver.
///
/// This driver implements the `NetDevice` trait and provides basic
/// packet transmission and reception via virtqueues.
pub struct VirtioNetDevice {
    /// Device name (e.g., "virtio-net0")
    name: String,
    /// VirtIO transport (MMIO or PCI)
    transport: VirtioTransport,
    /// Receive virtqueue
    rx_queue: VirtQueue,
    /// Transmit virtqueue
    tx_queue: VirtQueue,
    /// R95-7 FIX: DMA buffer backing the RX queue (owned, not leaked)
    rx_queue_dma: DmaBuffer,
    /// R95-7 FIX: DMA buffer backing the TX queue (owned, not leaked)
    tx_queue_dma: DmaBuffer,
    /// Device MAC address
    mac: MacAddress,
    /// Negotiated features
    features: u64,
    /// Device capabilities
    caps: DeviceCaps,
    /// Current link status
    link: LinkStatus,
    /// Operating mode (polling/interrupt)
    operating_mode: OperatingMode,
    /// Inflight TX buffers (indexed by descriptor head)
    tx_inflight: Vec<Option<NetBuf>>,
    /// R44-1 FIX: Driver-tracked TX chain links (device can't tamper)
    tx_chain_next: Vec<Option<u16>>,
    /// Inflight RX buffers (indexed by descriptor head)
    /// R65-24 FIX: Now stores RxInflight with driver-tracked capacity
    rx_inflight: Vec<Option<RxInflight>>,
    /// R44-1 FIX: Driver-tracked RX chain links (device can't tamper)
    rx_chain_next: Vec<Option<u16>>,
    /// Received packets ready for delivery
    rx_ready: Vec<NetBuf>,
    /// R96-4 FIX: RX buffers waiting to be reposted to the device.
    ///
    /// Error and overflow paths place buffers here instead of dropping them,
    /// preventing the BufPool from being drained under adversarial conditions.
    rx_recycle: Vec<NetBuf>,
    /// Statistics
    stats: NetStats,
}

/// Network device statistics.
#[derive(Default)]
struct NetStats {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    tx_errors: u64,
    rx_errors: u64,
    /// R66-8 FIX: Count of packets dropped due to RX ready queue overflow.
    rx_dropped: u64,
}

/// R65-24 FIX: Driver-owned metadata for inflight RX buffers.
///
/// Tracks the buffer and the maximum payload capacity we told the device.
/// This allows us to clamp device-reported lengths to prevent DMA overrun
/// attacks where a malicious device reports a larger length than the buffer.
struct RxInflight {
    /// The actual buffer
    buf: NetBuf,
    /// Maximum payload capacity posted to the device (excluding virtio-net header)
    capacity: usize,
}

// SAFETY: VirtioNetDevice manages virtqueue and transport resources
// which are accessed through synchronized mechanisms.
unsafe impl Send for VirtioNetDevice {}

impl VirtioNetDevice {
    /// Probe and initialize a virtio-net device via MMIO transport.
    ///
    /// # Safety
    /// Caller must ensure the MMIO region is properly mapped.
    pub unsafe fn probe_mmio(
        mmio_phys: u64,
        virt_offset: u64,
        name: &str,
    ) -> Result<Self, NetError> {
        let transport =
            MmioTransport::probe(mmio_phys, virt_offset).ok_or(NetError::NotInitialized)?;
        Self::init_with_transport(VirtioTransport::Mmio(transport), virt_offset, name)
    }

    /// Probe and initialize a virtio-net device via PCI transport.
    ///
    /// # Safety
    /// Caller must ensure the PCI BARs are properly mapped.
    pub unsafe fn probe_pci(
        pci_addrs: VirtioPciAddrs,
        virt_offset: u64,
        name: &str,
    ) -> Result<Self, NetError> {
        let transport =
            VirtioPciTransport::from_addrs(pci_addrs, virt_offset).ok_or(NetError::NotSupported)?;
        Self::init_with_transport(VirtioTransport::Pci(transport), virt_offset, name)
    }

    /// Initialize the device with a given transport.
    unsafe fn init_with_transport(
        transport: VirtioTransport,
        _virt_offset: u64, // Not used - we use PHYSICAL_MEMORY_OFFSET for DMA memory
        name: &str,
    ) -> Result<Self, NetError> {
        // Verify device type
        let device_id = transport.device_id();
        if device_id != VIRTIO_DEVICE_NET {
            return Err(NetError::NotSupported);
        }

        // Only support modern transport (legacy requires different queue setup)
        let version = transport.version();
        if version != VIRTIO_VERSION_MODERN {
            kprintln!("[net] Legacy virtio-net not supported, need modern transport");
            return Err(NetError::NotSupported);
        }

        // Reset device and start initialization
        transport.reset();
        transport.set_status(VIRTIO_STATUS_ACKNOWLEDGE);
        transport.set_status(transport.status() | VIRTIO_STATUS_DRIVER);

        // Feature negotiation
        let device_features = transport.device_features();
        let mut driver_features = 0u64;

        // Always try to negotiate VERSION_1 if available
        if device_features & VIRTIO_F_VERSION_1 != 0 {
            driver_features |= VIRTIO_F_VERSION_1;
        }
        // Request MAC address feature
        if device_features & VIRTIO_NET_F_MAC != 0 {
            driver_features |= VIRTIO_NET_F_MAC;
        }
        // Request status feature
        if device_features & VIRTIO_NET_F_STATUS != 0 {
            driver_features |= VIRTIO_NET_F_STATUS;
        }

        transport.write_driver_features(driver_features);
        transport.set_status(transport.status() | VIRTIO_STATUS_FEATURES_OK);

        // Verify features were accepted
        if transport.status() & VIRTIO_STATUS_FEATURES_OK == 0 {
            return Err(NetError::NotSupported);
        }

        // Read MAC address from config space
        let mut mac = [0u8; 6];
        if driver_features & VIRTIO_NET_F_MAC != 0 {
            transport.read_config_bytes(0, &mut mac);
        }

        // Setup RX queue (use PHYSICAL_MEMORY_OFFSET for DMA memory mapping)
        // R95-7 FIX: Store DmaBuffer ownership instead of leaking
        let (rx_queue, rx_queue_dma) =
            Self::setup_queue(&transport, QUEUE_RX, PHYSICAL_MEMORY_OFFSET)?;
        let rx_size = rx_queue.size() as usize;

        // Setup TX queue
        // R95-7 FIX: Store DmaBuffer ownership instead of leaking
        let (tx_queue, tx_queue_dma) =
            Self::setup_queue(&transport, QUEUE_TX, PHYSICAL_MEMORY_OFFSET)?;
        let tx_size = tx_queue.size() as usize;

        // Set DRIVER_OK to indicate we're ready
        transport.set_status(transport.status() | VIRTIO_STATUS_DRIVER_OK);

        // Initialize inflight buffer tracking
        let mut tx_inflight = Vec::with_capacity(tx_size);
        tx_inflight.resize_with(tx_size, || None);
        // R44-1 FIX: Initialize driver-owned chain metadata
        let mut tx_chain_next = Vec::with_capacity(tx_size);
        tx_chain_next.resize_with(tx_size, || None);

        let mut rx_inflight = Vec::with_capacity(rx_size);
        rx_inflight.resize_with(rx_size, || None);
        // R44-1 FIX: Initialize driver-owned chain metadata
        let mut rx_chain_next = Vec::with_capacity(rx_size);
        rx_chain_next.resize_with(rx_size, || None);

        kprintln!(
            "[net] {} ({}) MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            name,
            transport.kind(),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(Self {
            name: String::from(name),
            transport,
            rx_queue,
            tx_queue,
            // R95-7 FIX: Store DMA buffers to ensure proper cleanup
            rx_queue_dma,
            tx_queue_dma,
            mac,
            features: driver_features,
            caps: DeviceCaps {
                mtu: 1500,
                ..DeviceCaps::minimal()
            },
            link: LinkStatus::UP_UNKNOWN,
            operating_mode: OperatingMode::Polling,
            tx_inflight,
            tx_chain_next,
            rx_inflight,
            rx_chain_next,
            rx_ready: Vec::new(),
            rx_recycle: Vec::new(),
            stats: NetStats::default(),
        })
    }

    /// Setup a single virtqueue.
    ///
    /// # R95-7 FIX: Returns both VirtQueue and DmaBuffer
    ///
    /// The DmaBuffer is now returned instead of being leaked via `mem::forget`.
    /// The caller stores the DmaBuffer in the device struct, ensuring proper
    /// cleanup when the device is dropped.
    unsafe fn setup_queue(
        transport: &VirtioTransport,
        queue_idx: u16,
        virt_offset: u64,
    ) -> Result<(VirtQueue, DmaBuffer), NetError> {
        let max_size = transport.queue_max(queue_idx);
        let queue_size = max_size.min(DEFAULT_QUEUE_SIZE);

        if queue_size == 0 {
            return Err(NetError::InvalidConfig);
        }

        // Allocate DMA memory for the queue
        // R95-7 FIX: Keep ownership of DmaBuffer instead of leaking
        let mem_size = VirtQueue::layout_size(queue_size);
        let dma_buf = mm::dma::alloc_dma_buffer(mem_size).map_err(|_| NetError::IoError)?;
        let mem_phys = dma_buf.phys();

        // Get notify offset
        let notify_off = transport.queue_notify_off(queue_idx);

        // Create the virtqueue
        let queue = VirtQueue::new(mem_phys, queue_size, virt_offset, notify_off);

        // Configure the queue in the device
        transport.setup_queue(
            queue_idx,
            queue_size,
            queue.desc_table_phys(),
            queue.avail_ring_phys(),
            queue.used_ring_phys(),
        );

        // Enable the queue
        transport.queue_ready(queue_idx, true);

        Ok((queue, dma_buf))
    }

    /// Free a TX descriptor chain using driver-owned metadata.
    ///
    /// # R44-1 FIX: Uses tx_chain_next instead of device-controlled desc.next
    /// This prevents a malicious device from manipulating the descriptor chain
    /// to free descriptors belonging to other in-flight operations.
    fn free_tx_chain(&mut self, head: u16) {
        if head >= self.tx_queue.size() {
            return;
        }

        // Use driver-tracked chain link, not device-controlled descriptor
        if let Some(next) = self
            .tx_chain_next
            .get_mut(head as usize)
            .and_then(Option::take)
        {
            self.tx_queue.free_desc(next);
        }
        self.tx_queue.free_desc(head);
    }

    /// Free an RX descriptor chain using driver-owned metadata.
    ///
    /// # R44-1 FIX: Uses rx_chain_next instead of device-controlled desc.next
    fn free_rx_chain(&mut self, head: u16) {
        if head >= self.rx_queue.size() {
            return;
        }

        // Use driver-tracked chain link, not device-controlled descriptor
        if let Some(next) = self
            .rx_chain_next
            .get_mut(head as usize)
            .and_then(Option::take)
        {
            self.rx_queue.free_desc(next);
        }
        self.rx_queue.free_desc(head);
    }

    /// R96-4 FIX: Recycle an RX buffer for later reposting.
    ///
    /// When buffers cannot be delivered (error, invalid length, queue overflow),
    /// they should be recycled rather than dropped. This prevents the BufPool
    /// from being drained under adversarial conditions (packet floods, malformed
    /// packets, etc.).
    ///
    /// If a pool is available, return the buffer to it. Otherwise, stash it in
    /// `rx_recycle` so `replenish_rx()` can repost it later.
    ///
    /// The buffer is reset before recycling to ensure clean state for reuse.
    fn recycle_rx_buffer(&mut self, pool: Option<&BufPool>, mut buf: NetBuf) {
        buf.reset();
        if let Some(pool) = pool {
            pool.free(buf);
        } else {
            // Bound the recycle queue to prevent unbounded growth
            if self.rx_recycle.len() < MAX_RX_READY_QUEUE {
                self.rx_recycle.push(buf);
            }
            // If recycle queue is full, buffer is dropped (NetBuf::Drop frees the page)
        }
    }

    /// Process one used RX entry.
    ///
    /// # R43-1 FIX: Validates used.id from device before use as array index
    /// # R44-2 FIX: Validates length and re-arms buffer on error instead of leaking
    fn pop_rx_used(&mut self, pool: Option<&BufPool>) -> Result<Option<NetBuf>, RxError> {
        let used = match self.rx_queue.pop_used() {
            Some(u) => u,
            None => return Ok(None),
        };

        // R43-1 FIX: Validate used.id from device to prevent OOB access
        // A malicious/buggy device could return an arbitrary id value
        let qsize = self.rx_queue.size() as u32;
        let head_raw = used.id;
        if head_raw >= qsize {
            self.stats.rx_errors += 1;
            // Log the invalid descriptor for debugging
            kprintln!(
                "[net] WARNING: device returned invalid used.id {} >= {}",
                head_raw,
                qsize
            );
            return Err(RxError::BufferError);
        }
        let head = head_raw as u16;

        // R44-1 FIX: Get driver-owned chain metadata before freeing
        let data_idx = self
            .rx_chain_next
            .get_mut(head as usize)
            .and_then(Option::take);

        // Retrieve the buffer and its posted capacity
        // R65-24 FIX: Extract driver-tracked capacity for length clamping
        // R96-4 FIX: Release descriptors even if inflight tracking is lost
        let RxInflight { buf, capacity } = match self
            .rx_inflight
            .get_mut(head as usize)
            .and_then(Option::take)
        {
            Some(inflight) => inflight,
            None => {
                // R96-4 FIX: Bookkeeping mismatch - still release descriptors to
                // avoid leaking RX queue entries and causing queue stalls.
                self.stats.rx_errors += 1;
                if let Some(next) = data_idx {
                    self.rx_queue.free_desc(next);
                }
                self.rx_queue.free_desc(head);
                return Err(RxError::BufferError);
            }
        };

        // Calculate payload length (total - header)
        let total_len = used.len as usize;

        // R44-2 FIX: Validate length before consuming the buffer
        // If length is invalid, return buffer to pool instead of leaking it
        //
        // R48-5 FIX: When pool is None, recycle buffer locally to rx_ready
        // instead of dropping it. Although NetBuf now has Drop that frees
        // the page, recycling avoids the allocation overhead of getting a
        // new page from the buddy allocator on the next replenish.
        if total_len < VIRTIO_NET_HDR_SIZE {
            self.stats.rx_errors += 1;
            // R96-4 FIX: Recycle buffer via dedicated method to prevent pool drain
            self.recycle_rx_buffer(pool, buf);
            // Free descriptors using driver-owned metadata
            if let Some(next) = data_idx {
                self.rx_queue.free_desc(next);
            }
            self.rx_queue.free_desc(head);
            return Err(RxError::InvalidPacket);
        }

        // R65-24 FIX: Clamp payload length to driver-posted capacity
        // This prevents DMA overrun attacks where device reports larger length
        // than the buffer we actually posted. The DMA may have corrupted adjacent
        // memory, but we at least won't propagate the inflated length upstream.
        let raw_payload_len = total_len - VIRTIO_NET_HDR_SIZE;
        let payload_len = if raw_payload_len > capacity {
            // Device reported more bytes than we posted - log and count as error
            // This makes device misbehavior visible while still delivering data
            self.stats.rx_errors += 1;
            kprintln!(
                "[net] WARNING: device reported len {} > posted capacity {}, clamping",
                raw_payload_len,
                capacity
            );
            capacity
        } else {
            raw_payload_len
        };

        let mut buf = buf;
        if !buf.set_len(payload_len) {
            self.stats.rx_errors += 1;
            // R96-4 FIX: Recycle buffer via dedicated method to prevent pool drain
            self.recycle_rx_buffer(pool, buf);
            // Free descriptors using driver-owned metadata
            if let Some(next) = data_idx {
                self.rx_queue.free_desc(next);
            }
            self.rx_queue.free_desc(head);
            return Err(RxError::InvalidPacket);
        }

        // Free descriptors using driver-owned metadata (R44-1 FIX)
        if let Some(next) = data_idx {
            self.rx_queue.free_desc(next);
        }
        self.rx_queue.free_desc(head);

        self.stats.rx_packets += 1;
        self.stats.rx_bytes += payload_len as u64;

        Ok(Some(buf))
    }

    /// R66-8 FIX: Enqueue a completed RX buffer with bounded queue.
    ///
    /// When the queue exceeds MAX_RX_READY_QUEUE, excess buffers are moved to
    /// rx_recycle for later reposting rather than dropped. This prevents the
    /// BufPool from being drained under packet flood conditions.
    ///
    /// # R96-4 FIX: Recycle overflow buffers
    ///
    /// Previously, overflow buffers were dropped which would eventually drain
    /// the BufPool. Now they are moved to rx_recycle so replenish_rx() can
    /// repost them to the device.
    fn enqueue_rx_ready(&mut self, mut buf: NetBuf) {
        if self.rx_ready.len() >= MAX_RX_READY_QUEUE {
            // R96-4 FIX: Recycle instead of drop to prevent pool drain
            self.stats.rx_dropped += 1;
            buf.reset();
            if self.rx_recycle.len() < MAX_RX_READY_QUEUE {
                self.rx_recycle.push(buf);
            }
            // If recycle queue is also full, buffer is dropped (NetBuf::Drop frees page)
            return;
        }
        self.rx_ready.push(buf);
    }
}

/// R95-7 FIX: Implement Drop to quiesce device before DMA buffers are freed.
///
/// This ensures that:
/// 1. The device is reset (stops DMA operations)
/// 2. Queues are disabled (no new DMA can be issued)
/// 3. Then DMA buffers can be safely dropped (IOMMU unmapped + freed)
///
/// Without this, the DMA buffers were leaked via mem::forget(), causing
/// permanent physical memory and IOMMU mapping leaks.
impl Drop for VirtioNetDevice {
    fn drop(&mut self) {
        // SAFETY: These operations are safe as we're the only owner of the device
        // at this point (we're being dropped), and the device is being torn down.
        unsafe {
            // Disable queues first to stop accepting new operations
            self.transport.queue_ready(QUEUE_RX, false);
            self.transport.queue_ready(QUEUE_TX, false);

            // Reset the device to stop all DMA operations
            // This ensures no in-flight DMA transactions will complete after we
            // free the DMA buffers.
            self.transport.reset();
        }

        // Memory fence to ensure all writes are visible before dropping buffers
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // DMA buffers (rx_queue_dma, tx_queue_dma) will be automatically
        // dropped after this, which will:
        // 1. Unmap from IOMMU
        // 2. Scrub the memory
        // 3. Return pages to buddy allocator
    }
}

impl NetDevice for VirtioNetDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn set_mac_address(&mut self, _mac: MacAddress) -> Result<(), NetError> {
        // MAC address changing not supported in MVP
        Err(NetError::NotSupported)
    }

    fn capabilities(&self) -> DeviceCaps {
        self.caps
    }

    fn link_status(&self) -> LinkStatus {
        // TODO: Read from device if VIRTIO_NET_F_STATUS is negotiated
        self.link
    }

    fn operating_mode(&self) -> OperatingMode {
        self.operating_mode
    }

    fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), NetError> {
        self.operating_mode = mode;
        Ok(())
    }

    fn enable_interrupts(&mut self) -> Result<(), NetError> {
        // TODO: Configure virtqueue interrupt suppression
        Ok(())
    }

    fn disable_interrupts(&mut self) -> Result<(), NetError> {
        // TODO: Configure virtqueue interrupt suppression
        Ok(())
    }

    fn transmit(&mut self, buf: NetBuf) -> Result<(), (TxError, NetBuf)> {
        // Validate buffer
        if buf.headroom() < VIRTIO_NET_HDR_SIZE {
            return Err((TxError::InvalidBuffer, buf));
        }
        if buf.len() == 0 || buf.len() > u16::MAX as usize {
            return Err((TxError::InvalidBuffer, buf));
        }

        // Check queue space (we need 2 descriptors: header + data)
        if self.tx_queue.available_descs() < 2 {
            return Err((TxError::QueueFull, buf));
        }

        // Allocate descriptors
        let header_idx = match self.tx_queue.alloc_desc() {
            Some(i) => i,
            None => return Err((TxError::QueueFull, buf)),
        };
        let data_idx = match self.tx_queue.alloc_desc() {
            Some(i) => i,
            None => {
                self.tx_queue.free_desc(header_idx);
                return Err((TxError::QueueFull, buf));
            }
        };

        unsafe {
            // Write virtio-net header at buffer base (in headroom)
            let hdr_virt =
                (buf.buffer_phys_addr().as_u64() + PHYSICAL_MEMORY_OFFSET) as *mut VirtioNetHdr;
            write_bytes(hdr_virt, 0, 1);

            // Setup header descriptor (device reads)
            let desc0 = self.tx_queue.desc_mut(header_idx);
            desc0.addr = buf.buffer_phys_addr().as_u64();
            desc0.len = VIRTIO_NET_HDR_SIZE as u32;
            desc0.flags = VRING_DESC_F_NEXT;
            desc0.next = data_idx;

            // Setup data descriptor (device reads)
            let desc1 = self.tx_queue.desc_mut(data_idx);
            desc1.addr = buf.phys_addr().as_u64();
            desc1.len = buf.len() as u32;
            desc1.flags = 0;
            desc1.next = 0;

            // Track inflight buffer BEFORE notifying device (avoid race with completion)
            // R44-1 FIX: Track driver-owned chain link
            self.tx_chain_next[header_idx as usize] = Some(data_idx);
            self.tx_inflight[header_idx as usize] = Some(buf);

            // Add to available ring
            self.tx_queue.push_avail(header_idx);

            // Notify device
            self.transport
                .notify(QUEUE_TX, self.tx_queue.notify_offset());
        }

        Ok(())
    }

    fn reclaim_tx(&mut self) -> usize {
        let mut reclaimed = 0;
        let qsize = self.tx_queue.size() as u32;

        while let Some(used) = self.tx_queue.pop_used() {
            // R43-1 FIX: Validate used.id from device to prevent OOB access
            let head_raw = used.id;
            if head_raw >= qsize {
                self.stats.tx_errors += 1;
                kprintln!(
                    "[net] WARNING: TX device returned invalid used.id {} >= {}",
                    head_raw,
                    qsize
                );
                continue;
            }
            let head = head_raw as u16;

            // R44-1 FIX: Free descriptor chain using driver-owned metadata
            self.free_tx_chain(head);

            // Release buffer
            if let Some(buf) = self
                .tx_inflight
                .get_mut(head as usize)
                .and_then(Option::take)
            {
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += buf.len() as u64;
                reclaimed += 1;
                // Buffer is dropped here, returning memory to pool would require pool reference
            }
        }

        reclaimed
    }

    fn tx_queue_space(&self) -> usize {
        // Each TX needs 2 descriptors
        self.tx_queue.available_descs() / 2
    }

    fn receive(&mut self) -> Result<Option<NetBuf>, RxError> {
        // First check if we have buffered packets
        if let Some(buf) = self.rx_ready.pop() {
            return Ok(Some(buf));
        }

        // Poll for new packets (no pool for returning buffers in simple receive path)
        self.pop_rx_used(None)
    }

    fn replenish_rx(&mut self, pool: &BufPool, count: usize) -> usize {
        let mut posted = 0;

        for _ in 0..count {
            // Check queue space (we need 2 descriptors: header + data)
            if self.rx_queue.available_descs() < 2 {
                break;
            }

            // R96-4 FIX: Prefer recycled buffers to prevent pool drain.
            // Under packet flood or error conditions, buffers get recycled rather
            // than returned to pool. Reusing them here closes the lifecycle loop.
            let buf = if let Some(recycled) = self.rx_recycle.pop() {
                recycled
            } else {
                // Allocate a buffer from the pool
                match pool.alloc() {
                    Some(b) => b,
                    None => break,
                }
            };

            // Verify buffer has enough headroom
            if buf.headroom() < VIRTIO_NET_HDR_SIZE {
                pool.free(buf);
                continue;
            }

            // Allocate descriptors
            let header_idx = match self.rx_queue.alloc_desc() {
                Some(i) => i,
                None => {
                    pool.free(buf);
                    break;
                }
            };
            let data_idx = match self.rx_queue.alloc_desc() {
                Some(i) => i,
                None => {
                    self.rx_queue.free_desc(header_idx);
                    pool.free(buf);
                    break;
                }
            };

            unsafe {
                // Setup header descriptor (device writes header here)
                let desc0 = self.rx_queue.desc_mut(header_idx);
                desc0.addr = buf.buffer_phys_addr().as_u64();
                desc0.len = VIRTIO_NET_HDR_SIZE as u32;
                desc0.flags = VRING_DESC_F_WRITE | VRING_DESC_F_NEXT;
                desc0.next = data_idx;

                // Setup data descriptor (device writes payload here)
                let desc1 = self.rx_queue.desc_mut(data_idx);
                desc1.addr = buf.phys_addr().as_u64();
                desc1.len = buf.payload_capacity() as u32;
                desc1.flags = VRING_DESC_F_WRITE;
                desc1.next = 0;

                // Add to available ring
                self.rx_queue.push_avail(header_idx);
            }

            // Track inflight buffer
            // R44-1 FIX: Track driver-owned chain link
            self.rx_chain_next[header_idx as usize] = Some(data_idx);
            // R65-24 FIX: Store RxInflight with driver-tracked capacity
            // Capture capacity BEFORE moving buf into the struct
            let posted_capacity = buf.payload_capacity();
            self.rx_inflight[header_idx as usize] = Some(RxInflight {
                buf,
                capacity: posted_capacity,
            });
            posted += 1;
        }

        // Notify device about new buffers
        if posted > 0 {
            unsafe {
                self.transport
                    .notify(QUEUE_RX, self.rx_queue.notify_offset());
            }
        }

        posted
    }

    fn rx_queue_depth(&self) -> usize {
        self.rx_inflight.iter().filter(|e| e.is_some()).count()
    }

    fn poll(&mut self) -> bool {
        let tx_done = self.reclaim_tx();
        let mut rx_done = 0;

        // Process all available RX completions
        // Note: In poll context, we don't have the pool to return buffers on error
        loop {
            match self.pop_rx_used(None) {
                Ok(Some(buf)) => {
                    // R66-8 FIX: Use bounded enqueue to prevent memory exhaustion
                    self.enqueue_rx_ready(buf);
                    rx_done += 1;
                }
                Ok(None) => break,
                Err(_) => {
                    self.stats.rx_errors += 1;
                    break;
                }
            }
        }

        tx_done > 0 || rx_done > 0
    }

    fn handle_interrupt(&mut self) {
        // In interrupt context, just poll the queues
        let _ = self.poll();
    }

    fn tx_packets(&self) -> u64 {
        self.stats.tx_packets
    }

    fn tx_bytes(&self) -> u64 {
        self.stats.tx_bytes
    }

    fn rx_packets(&self) -> u64 {
        self.stats.rx_packets
    }

    fn rx_bytes(&self) -> u64 {
        self.stats.rx_bytes
    }

    fn tx_errors(&self) -> u64 {
        self.stats.tx_errors
    }

    fn rx_errors(&self) -> u64 {
        self.stats.rx_errors
    }

    fn rx_dropped(&self) -> u64 {
        self.stats.rx_dropped
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

// R95-7 FIX: Removed alloc_dma_memory() function that used mem::forget().
// DMA buffers are now allocated directly in setup_queue() and stored in the
// VirtioNetDevice struct for proper lifetime management.
