//! Common network device abstraction for Zero-OS drivers.
//!
//! This module defines the `NetDevice` trait, the core abstraction for network
//! device drivers. It is designed to be compatible with virtio-net and future
//! drivers (e.g., e1000, Intel NIC).
//!
//! # Design Principles
//!
//! 1. **Non-blocking I/O**: Transmit and receive operations are non-blocking.
//!    Drivers manage descriptor queues internally.
//!
//! 2. **Buffer ownership**: Transmit takes ownership of `NetBuf`; completed
//!    buffers are reclaimed by the driver. Receive returns owned `NetBuf`.
//!
//! 3. **Dual mode operation**: Supports both interrupt-driven and polling modes
//!    for flexibility in different kernel contexts.
//!
//! 4. **Capability negotiation**: Devices advertise their capabilities (checksum
//!    offload, TSO, etc.) for protocol stack optimization.

use crate::{BufPool, NetBuf};

// ============================================================================
// Type Aliases
// ============================================================================

/// Standard 6-byte Ethernet MAC address.
pub type MacAddress = [u8; 6];

// ============================================================================
// Device Capabilities
// ============================================================================

/// Capabilities advertised by a network device.
///
/// These flags indicate which offload features the device supports.
/// The network stack can use this information to optimize packet processing.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCaps {
    /// Hardware IP/TCP/UDP checksum offload on transmit.
    pub tx_checksum: bool,
    /// Hardware checksum verification on receive.
    pub rx_checksum: bool,
    /// TCP Segmentation Offload (TSO) - large send offload.
    pub tso: bool,
    /// UDP Fragmentation Offload (UFO).
    pub ufo: bool,
    /// Generic Segmentation Offload (GSO).
    pub gso: bool,
    /// Receive Side Scaling (RSS) - multiple RX queues.
    pub rss: bool,
    /// VLAN tag insertion/stripping.
    pub vlan_offload: bool,
    /// Promiscuous mode support.
    pub promiscuous: bool,
    /// Multicast filtering support.
    pub multicast_filter: bool,
    /// Maximum transmission unit (0 = default 1500).
    pub mtu: u16,
}

impl DeviceCaps {
    /// Create capabilities for a minimal device (no offloads).
    pub const fn minimal() -> Self {
        DeviceCaps {
            tx_checksum: false,
            rx_checksum: false,
            tso: false,
            ufo: false,
            gso: false,
            rss: false,
            vlan_offload: false,
            promiscuous: false,
            multicast_filter: false,
            mtu: 1500,
        }
    }
}

// ============================================================================
// Link Status
// ============================================================================

/// Current physical link state of a network device.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkStatus {
    /// Link is up and ready to transmit/receive.
    pub up: bool,
    /// Link speed in Mbps (e.g., 1000 for gigabit).
    /// `None` if speed is unknown or not applicable.
    pub speed_mbps: Option<u32>,
    /// Full duplex mode. `None` if unknown.
    pub full_duplex: Option<bool>,
}

impl LinkStatus {
    /// Link is down.
    pub const DOWN: Self = LinkStatus {
        up: false,
        speed_mbps: None,
        full_duplex: None,
    };

    /// Link is up with unknown speed.
    pub const UP_UNKNOWN: Self = LinkStatus {
        up: true,
        speed_mbps: None,
        full_duplex: None,
    };

    /// Create a link status for a specific speed.
    pub const fn up_at(speed_mbps: u32, full_duplex: bool) -> Self {
        LinkStatus {
            up: true,
            speed_mbps: Some(speed_mbps),
            full_duplex: Some(full_duplex),
        }
    }
}

// ============================================================================
// Operating Mode
// ============================================================================

/// Interrupt/polling mode selection for network device operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperatingMode {
    /// Poll-based operation - driver must call `poll()` to process completions.
    /// Lower latency in some cases, higher CPU usage.
    #[default]
    Polling,
    /// Interrupt-driven operation - device signals completions via interrupts.
    /// Lower CPU usage, potentially higher latency.
    Interrupt,
    /// Hybrid NAPI-style - use interrupts to trigger polling.
    Napi,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors from control-plane operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// Operation is not supported by this device.
    NotSupported,
    /// Device is not in a valid state for this operation.
    InvalidState,
    /// Device encountered an I/O or bus error.
    IoError,
    /// Configuration parameter is invalid.
    InvalidConfig,
    /// Device is not initialized.
    NotInitialized,
}

/// Errors from transmit operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// No descriptors available in the TX queue (try again later).
    QueueFull,
    /// Device link is down or TX queue is stopped.
    LinkDown,
    /// Buffer is invalid (too large, misaligned, etc.).
    InvalidBuffer,
    /// Device encountered an I/O or bus error.
    IoError,
}

/// Errors from receive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxError {
    /// No packet available (non-blocking poll returned empty).
    NoPacket,
    /// Device link is down or RX queue is stopped.
    LinkDown,
    /// Failed to allocate or manage receive buffers.
    BufferError,
    /// Device encountered an I/O or bus error.
    IoError,
    /// Received packet was corrupted or invalid.
    InvalidPacket,
}

// ============================================================================
// NetDevice Trait
// ============================================================================

/// Core trait for network device drivers.
///
/// This trait provides a uniform interface for network devices, abstracting
/// over the underlying hardware (virtio-net, e1000, etc.).
///
/// # Buffer Management
///
/// - **Transmit**: Caller provides a `NetBuf` which is consumed by the device.
///   The driver owns the buffer until transmission completes, at which point
///   it may return the buffer to a pool or drop it.
///
/// - **Receive**: Driver pre-posts buffers from a `BufPool`. When packets
///   arrive, `receive()` returns filled `NetBuf` instances.
///
/// # Thread Safety
///
/// Implementations should be safe to call from interrupt context (where noted)
/// and must handle internal synchronization appropriately.
pub trait NetDevice: Send {
    // ========================================================================
    // Device Identity & Configuration
    // ========================================================================

    /// Get the device name (e.g., "virtio-net0", "eth0").
    fn name(&self) -> &str;

    /// Get the current MAC address.
    fn mac_address(&self) -> MacAddress;

    /// Set the MAC address, if supported by the device.
    fn set_mac_address(&mut self, mac: MacAddress) -> Result<(), NetError>;

    /// Get device capabilities.
    fn capabilities(&self) -> DeviceCaps;

    /// Get the current MTU.
    fn mtu(&self) -> u16 {
        self.capabilities().mtu.max(1500)
    }

    // ========================================================================
    // Link State
    // ========================================================================

    /// Get the current link status.
    fn link_status(&self) -> LinkStatus;

    /// Check if the link is up.
    fn is_link_up(&self) -> bool {
        self.link_status().up
    }

    // ========================================================================
    // Operating Mode
    // ========================================================================

    /// Get the current operating mode.
    fn operating_mode(&self) -> OperatingMode;

    /// Set the operating mode (polling, interrupt, or NAPI).
    fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), NetError>;

    /// Enable device interrupts.
    fn enable_interrupts(&mut self) -> Result<(), NetError>;

    /// Disable device interrupts.
    fn disable_interrupts(&mut self) -> Result<(), NetError>;

    // ========================================================================
    // Data Path - Transmit
    // ========================================================================

    /// Submit a packet for transmission (non-blocking).
    ///
    /// The buffer is consumed by the device. On success, the driver owns the
    /// buffer until transmission completes. On error, the buffer is returned.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Packet queued for transmission
    /// - `Err((TxError, NetBuf))` - Failed, buffer returned to caller
    fn transmit(&mut self, buf: NetBuf) -> Result<(), (TxError, NetBuf)>;

    /// Reclaim completed TX buffers.
    ///
    /// Returns the number of buffers reclaimed. In polling mode, this should
    /// be called periodically to free descriptor slots.
    fn reclaim_tx(&mut self) -> usize;

    /// Get the number of available TX descriptor slots.
    fn tx_queue_space(&self) -> usize;

    // ========================================================================
    // Data Path - Receive
    // ========================================================================

    /// Poll for a received packet (non-blocking).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(buf))` - A packet was received
    /// - `Ok(None)` - No packet available
    /// - `Err(RxError)` - An error occurred
    fn receive(&mut self) -> Result<Option<NetBuf>, RxError>;

    /// Replenish the RX queue with buffers from the pool.
    ///
    /// Pre-posts up to `count` buffers for receiving packets.
    ///
    /// # Returns
    ///
    /// Number of buffers successfully posted.
    fn replenish_rx(&mut self, pool: &BufPool, count: usize) -> usize;

    /// Get the number of buffers currently posted to the RX queue.
    fn rx_queue_depth(&self) -> usize;

    // ========================================================================
    // Polling & Interrupt Handling
    // ========================================================================

    /// Process pending work in polling mode.
    ///
    /// This handles both TX completions and RX arrivals. Call this in a loop
    /// when using polling mode.
    ///
    /// # Returns
    ///
    /// `true` if any work was done, `false` if queues were empty.
    fn poll(&mut self) -> bool;

    /// Handle an interrupt from this device.
    ///
    /// This should acknowledge the interrupt and process any pending work.
    /// Safe to call from interrupt context.
    fn handle_interrupt(&mut self);

    // ========================================================================
    // Statistics (Optional)
    // ========================================================================

    /// Get the number of packets transmitted.
    fn tx_packets(&self) -> u64 {
        0
    }

    /// Get the number of bytes transmitted.
    fn tx_bytes(&self) -> u64 {
        0
    }

    /// Get the number of packets received.
    fn rx_packets(&self) -> u64 {
        0
    }

    /// Get the number of bytes received.
    fn rx_bytes(&self) -> u64 {
        0
    }

    /// Get the number of TX errors.
    fn tx_errors(&self) -> u64 {
        0
    }

    /// Get the number of RX errors.
    fn rx_errors(&self) -> u64 {
        0
    }

    /// Get the number of RX packets dropped due to queue overflow.
    /// R66-8: Added to track bounded RX queue drops.
    fn rx_dropped(&self) -> u64 {
        0
    }
}
