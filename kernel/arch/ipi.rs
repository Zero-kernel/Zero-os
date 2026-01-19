//! Inter-Processor Interrupt (IPI) Types and Infrastructure
//!
//! This module defines the IPI types used for cross-CPU communication in SMP systems.
//! Currently, Zero-OS runs in single-core mode, but this infrastructure is prepared
//! for Phase E (SMP) implementation.
//!
//! # IPI Types
//!
//! | Vector | Type | Purpose |
//! |--------|------|---------|
//! | 0xFB | RESCHEDULE | Request CPU to run scheduler |
//! | 0xFC | HALT | Stop CPU (for shutdown/panic) |
//! | 0xFD | PROFILE | Profiling interrupt for sampling |
//! | 0xFE | TLB_SHOOTDOWN | Cross-CPU TLB invalidation |
//! | 0xFF | PANIC | Panic broadcast to all CPUs |
//!
//! # Usage
//!
//! Currently stubs only. When SMP is implemented:
//!
//! ```rust,ignore
//! // Send reschedule IPI to CPU 2
//! send_ipi(2, IpiType::Reschedule);
//!
//! // Broadcast panic to all CPUs
//! broadcast_ipi(IpiType::Panic);
//! ```
//!
//! # SMP Upgrade Path
//!
//! 1. Implement LAPIC IPI sending in Phase E.1
//! 2. Register handlers for each IPI vector in IDT
//! 3. Replace stub functions with real implementations
//! 4. Add IPI acknowledgment mechanism

#![allow(dead_code)]

use crate::apic;
use core::sync::atomic::{AtomicU64, Ordering};
use cpu_local::{current_cpu_id, lapic_id_for_cpu, max_cpus};

// ============================================================================
// IPI Vector Assignments
// ============================================================================

/// IPI vector for reschedule request
///
/// Sent when a CPU should run the scheduler, e.g., when a higher-priority
/// process becomes runnable on another CPU's queue.
pub const IPI_VECTOR_RESCHEDULE: u8 = 0xFB;

/// IPI vector for CPU halt
///
/// Sent to stop a CPU during shutdown or when transitioning to a lower
/// power state. The target CPU should enter a halt loop.
pub const IPI_VECTOR_HALT: u8 = 0xFC;

/// IPI vector for profiling
///
/// Used by the profiler to sample CPU state. The target CPU should
/// record its current RIP and stack trace.
pub const IPI_VECTOR_PROFILE: u8 = 0xFD;

/// IPI vector for TLB shootdown
///
/// Sent when page table entries are modified and other CPUs may have
/// stale TLB entries. The target CPU should flush the affected TLB entries.
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 0xFE;

/// IPI vector for panic broadcast
///
/// Sent when a CPU panics to notify all other CPUs. Target CPUs should
/// stop normal execution, save state, and wait in a safe halt loop.
pub const IPI_VECTOR_PANIC: u8 = 0xFF;

// ============================================================================
// IPI Type Enum
// ============================================================================

/// Inter-Processor Interrupt types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpiType {
    /// Request target CPU to run scheduler
    Reschedule = IPI_VECTOR_RESCHEDULE,
    /// Request target CPU to halt
    Halt = IPI_VECTOR_HALT,
    /// Profiling sample request
    Profile = IPI_VECTOR_PROFILE,
    /// TLB shootdown request
    TlbShootdown = IPI_VECTOR_TLB_SHOOTDOWN,
    /// Panic notification
    Panic = IPI_VECTOR_PANIC,
}

impl IpiType {
    /// Get the interrupt vector for this IPI type
    #[inline]
    pub fn vector(self) -> u8 {
        self as u8
    }

    /// Convert from vector number to IPI type
    pub fn from_vector(vector: u8) -> Option<Self> {
        match vector {
            IPI_VECTOR_RESCHEDULE => Some(IpiType::Reschedule),
            IPI_VECTOR_HALT => Some(IpiType::Halt),
            IPI_VECTOR_PROFILE => Some(IpiType::Profile),
            IPI_VECTOR_TLB_SHOOTDOWN => Some(IpiType::TlbShootdown),
            IPI_VECTOR_PANIC => Some(IpiType::Panic),
            _ => None,
        }
    }

    /// Get a human-readable name for this IPI type
    pub fn name(self) -> &'static str {
        match self {
            IpiType::Reschedule => "RESCHEDULE",
            IpiType::Halt => "HALT",
            IpiType::Profile => "PROFILE",
            IpiType::TlbShootdown => "TLB_SHOOTDOWN",
            IpiType::Panic => "PANIC",
        }
    }
}

// ============================================================================
// IPI Statistics
// ============================================================================

/// Statistics for IPI operations
#[derive(Debug)]
pub struct IpiStats {
    /// Number of reschedule IPIs sent
    pub reschedule_sent: u64,
    /// Number of TLB shootdown IPIs sent
    pub tlb_shootdown_sent: u64,
    /// Number of halt IPIs sent
    pub halt_sent: u64,
    /// Number of profile IPIs sent
    pub profile_sent: u64,
    /// Number of panic IPIs sent
    pub panic_sent: u64,
}

// Atomic counters for SMP-safe statistics
static STATS_RESCHEDULE: AtomicU64 = AtomicU64::new(0);
static STATS_TLB_SHOOTDOWN: AtomicU64 = AtomicU64::new(0);
static STATS_HALT: AtomicU64 = AtomicU64::new(0);
static STATS_PROFILE: AtomicU64 = AtomicU64::new(0);
static STATS_PANIC: AtomicU64 = AtomicU64::new(0);

/// Get current IPI statistics
pub fn get_stats() -> IpiStats {
    IpiStats {
        reschedule_sent: STATS_RESCHEDULE.load(Ordering::Relaxed),
        tlb_shootdown_sent: STATS_TLB_SHOOTDOWN.load(Ordering::Relaxed),
        halt_sent: STATS_HALT.load(Ordering::Relaxed),
        profile_sent: STATS_PROFILE.load(Ordering::Relaxed),
        panic_sent: STATS_PANIC.load(Ordering::Relaxed),
    }
}

// ============================================================================
// IPI Target Specification
// ============================================================================

/// Target specification for IPI delivery
#[derive(Debug, Clone, Copy)]
pub enum IpiTarget {
    /// Send to a specific CPU
    Cpu(usize),
    /// Send to all CPUs except self
    AllExceptSelf,
    /// Send to all CPUs including self
    All,
    /// Send to CPUs in a specific mask (bit N = CPU N)
    Mask(u64),
}

/// Bump statistics for an IPI type
#[inline]
fn bump_stat(ipi_type: IpiType, count: u64) {
    match ipi_type {
        IpiType::Reschedule => STATS_RESCHEDULE.fetch_add(count, Ordering::Relaxed),
        IpiType::TlbShootdown => STATS_TLB_SHOOTDOWN.fetch_add(count, Ordering::Relaxed),
        IpiType::Halt => STATS_HALT.fetch_add(count, Ordering::Relaxed),
        IpiType::Profile => STATS_PROFILE.fetch_add(count, Ordering::Relaxed),
        IpiType::Panic => STATS_PANIC.fetch_add(count, Ordering::Relaxed),
    };
}

// ============================================================================
// IPI Send Functions
// ============================================================================

/// Send an IPI to a specific CPU
///
/// # Arguments
///
/// * `target_cpu` - CPU ID to send IPI to
/// * `ipi_type` - Type of IPI to send
///
/// # Implementation
///
/// Uses LAPIC ICR (Interrupt Command Register) to send the IPI:
/// 1. Look up target CPU's LAPIC ID from cpu_local mapping
/// 2. Call apic::send_ipi_raw with the vector and FIXED delivery mode
/// 3. Update statistics
#[inline]
pub fn send_ipi(target_cpu: usize, ipi_type: IpiType) {
    if let Some(dest_lapic) = lapic_id_for_cpu(target_cpu) {
        unsafe {
            apic::send_ipi_raw(dest_lapic, ipi_type.vector(), apic::icr_delivery::FIXED);
        }
        bump_stat(ipi_type, 1);
    }
}

/// Send an IPI to multiple CPUs based on target specification
///
/// # Arguments
///
/// * `target` - Target specification
/// * `ipi_type` - Type of IPI to send
///
/// # Implementation
///
/// Iterates over target CPUs and sends individual IPIs using `send_ipi()`.
/// For AllExceptSelf, excludes the current CPU.
/// For Mask, only sends to CPUs with corresponding bit set.
#[inline]
pub fn send_ipi_target(target: IpiTarget, ipi_type: IpiType) {
    match target {
        IpiTarget::Cpu(cpu) => send_ipi(cpu, ipi_type),
        IpiTarget::AllExceptSelf => {
            let self_id = current_cpu_id();
            for cpu in 0..max_cpus() {
                if cpu == self_id {
                    continue;
                }
                if lapic_id_for_cpu(cpu).is_some() {
                    send_ipi(cpu, ipi_type);
                }
            }
        }
        IpiTarget::All => {
            for cpu in 0..max_cpus() {
                if lapic_id_for_cpu(cpu).is_some() {
                    send_ipi(cpu, ipi_type);
                }
            }
        }
        IpiTarget::Mask(mask) => {
            let mut cpu = 0;
            let mut bits = mask;
            while bits != 0 {
                if bits & 1 != 0 {
                    send_ipi(cpu, ipi_type);
                }
                bits >>= 1;
                cpu += 1;
            }
        }
    }
}

/// Broadcast an IPI to all CPUs except self
///
/// Convenience wrapper for `send_ipi_target(IpiTarget::AllExceptSelf, ...)`.
#[inline]
pub fn broadcast_ipi(ipi_type: IpiType) {
    send_ipi_target(IpiTarget::AllExceptSelf, ipi_type);
}

/// Broadcast a panic IPI to all CPUs
///
/// This is called during kernel panic to notify all CPUs.
/// CPUs receiving this should enter a safe halt loop.
#[inline]
pub fn broadcast_panic() {
    broadcast_ipi(IpiType::Panic);
}

// ============================================================================
// IPI Handler Registration (Stubs)
// ============================================================================

/// Handler function type for IPI interrupts
pub type IpiHandler = fn();

/// Registered IPI handlers (one per IPI type)
/// These will be called from the IDT interrupt handlers
static mut IPI_HANDLERS: [Option<IpiHandler>; 5] = [None; 5];

/// Register a handler for an IPI type
///
/// # Safety
///
/// This function modifies global mutable state. It should only be called
/// during single-threaded initialization (before SMP bring-up).
///
/// # Arguments
///
/// * `ipi_type` - IPI type to register handler for
/// * `handler` - Handler function to call when IPI is received
pub unsafe fn register_ipi_handler(ipi_type: IpiType, handler: IpiHandler) {
    let index = match ipi_type {
        IpiType::Reschedule => 0,
        IpiType::Halt => 1,
        IpiType::Profile => 2,
        IpiType::TlbShootdown => 3,
        IpiType::Panic => 4,
    };
    IPI_HANDLERS[index] = Some(handler);
}

/// Get the registered handler for an IPI type
///
/// # Safety
///
/// Handler must only be called in appropriate interrupt context.
pub unsafe fn get_ipi_handler(ipi_type: IpiType) -> Option<IpiHandler> {
    let index = match ipi_type {
        IpiType::Reschedule => 0,
        IpiType::Halt => 1,
        IpiType::Profile => 2,
        IpiType::TlbShootdown => 3,
        IpiType::Panic => 4,
    };
    IPI_HANDLERS[index]
}

// ============================================================================
// LAPIC Interface (Stubs for SMP)
// ============================================================================

/// LAPIC memory-mapped register base address (default)
pub const LAPIC_BASE: u64 = 0xFEE0_0000;

/// LAPIC register offsets
pub mod lapic_regs {
    /// LAPIC ID Register
    pub const ID: u32 = 0x020;
    /// LAPIC Version Register
    pub const VERSION: u32 = 0x030;
    /// Task Priority Register
    pub const TPR: u32 = 0x080;
    /// End of Interrupt Register
    pub const EOI: u32 = 0x0B0;
    /// Logical Destination Register
    pub const LDR: u32 = 0x0D0;
    /// Destination Format Register
    pub const DFR: u32 = 0x0E0;
    /// Spurious Interrupt Vector Register
    pub const SIVR: u32 = 0x0F0;
    /// Interrupt Command Register (low)
    pub const ICR_LOW: u32 = 0x300;
    /// Interrupt Command Register (high)
    pub const ICR_HIGH: u32 = 0x310;
    /// Timer Local Vector Table Entry
    pub const LVT_TIMER: u32 = 0x320;
    /// Timer Initial Count Register
    pub const TIMER_INIT: u32 = 0x380;
    /// Timer Current Count Register
    pub const TIMER_CURRENT: u32 = 0x390;
    /// Timer Divide Configuration Register
    pub const TIMER_DIVIDE: u32 = 0x3E0;
}

/// Initialize IPI subsystem
///
/// Registers the TLB shootdown IPI sender with the mm layer.
/// Must be called after LAPIC is initialized but before SMP bring-up.
pub fn init() {
    // Register the TLB shootdown IPI sender to break circular dependency
    // between arch (ipi) and mm (tlb_shootdown) crates
    mm::tlb_shootdown::register_ipi_sender(send_tlb_shootdown_ipi);
}

/// Send a TLB shootdown IPI to a specific CPU
///
/// This is the callback registered with tlb_shootdown module.
fn send_tlb_shootdown_ipi(target_cpu: usize) {
    send_ipi(target_cpu, IpiType::TlbShootdown);
}
