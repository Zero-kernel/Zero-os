//! HPET (High Precision Event Timer) Support
//!
//! This module provides access to the HPET hardware timer for high-resolution timing.
//!
//! # Overview
//!
//! The HPET is a memory-mapped timer that provides:
//! - A main counter running at a fixed frequency (typically ~14.318 MHz)
//! - Multiple comparators for generating interrupts (not used here)
//! - Sub-microsecond timing resolution
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize HPET early in boot
//! match arch::hpet::init() {
//!     Ok(info) => println!("HPET: {} Hz", info.frequency_hz),
//!     Err(e) => println!("HPET unavailable: {:?}", e),
//! }
//!
//! // Read the main counter for precise timing
//! if let Some(ticks) = arch::hpet::read_main_counter() {
//!     // Convert to nanoseconds: ns = ticks * period_fs / 1_000_000
//! }
//! ```
//!
//! # Integration
//!
//! The HPET main counter is used as an alternative reference clock for
//! LAPIC timer calibration, providing more accurate results than the
//! legacy PIT timer.
//!
//! # Memory Mapping
//!
//! HPET registers are accessed via a dedicated high-half MMIO mapping
//! (not the identity-mapped region which becomes read-only after security
//! hardening). The mapping is created at HPET_VIRT_BASE.

use core::ptr::{read_unaligned, read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use mm::{map_mmio, FrameAllocator, MapError, PHYSICAL_MEMORY_OFFSET};
use spin::{Mutex, Once};
use x86_64::{PhysAddr, VirtAddr};

use crate::smp::{
    find_rsdp, find_table_rsdt, find_table_xsdt, phys_slice, read_sdt_header, validate_checksum,
    SdtHeader,
};

// ============================================================================
// HPET Constants
// ============================================================================

/// Default HPET base address (typical value, actual from ACPI table)
pub const HPET_DEFAULT_BASE: u64 = 0xFED0_0000;

/// HPET MMIO size (one page is sufficient for HPET registers)
const HPET_MMIO_SIZE: usize = 0x1000;

/// Dedicated high-half virtual address for HPET MMIO
/// Uses an unused slot in the high-half address space (similar to APIC_VIRT_ADDR)
const HPET_VIRT_BASE: u64 = 0xffff_ffff_fed0_0000;

/// HPET register offsets (memory-mapped)
pub mod regs {
    /// General Capabilities and ID Register (64-bit)
    pub const CAPS_ID: usize = 0x000;
    /// General Configuration Register (64-bit)
    pub const CONFIG: usize = 0x010;
    /// General Interrupt Status Register (64-bit)
    pub const INT_STATUS: usize = 0x020;
    /// Main Counter Value Register (64-bit)
    pub const COUNTER: usize = 0x0F0;
    /// Timer N Configuration and Capability (64-bit, N = 0..31)
    /// Offset = 0x100 + 0x20*N
    pub const TIMER_CONFIG_BASE: usize = 0x100;
    /// Timer N Comparator Value (64-bit, N = 0..31)
    /// Offset = 0x108 + 0x20*N
    pub const TIMER_COMPARATOR_BASE: usize = 0x108;
}

/// General Configuration Register bits
pub mod config_bits {
    /// Enable CNF (bit 0): Main counter enable
    pub const ENABLE_CNF: u64 = 1 << 0;
    /// Legacy Replacement Route (bit 1): Map timers to legacy IRQs
    pub const LEG_RT_CNF: u64 = 1 << 1;
}

/// General Capabilities Register bits
pub mod caps_bits {
    /// Counter size (bit 13): 1 = 64-bit counter, 0 = 32-bit counter
    pub const COUNT_SIZE_CAP: u64 = 1 << 13;
    /// Number of timers minus one (bits 8-12)
    pub const NUM_TIM_CAP_MASK: u64 = 0x1F << 8;
    pub const NUM_TIM_CAP_SHIFT: u64 = 8;
    /// Counter clock period in femtoseconds (bits 32-63)
    pub const CLK_PERIOD_MASK: u64 = 0xFFFF_FFFF_0000_0000;
    pub const CLK_PERIOD_SHIFT: u64 = 32;
}

// ============================================================================
// ACPI HPET Table Structures
// ============================================================================

/// ACPI Generic Address Structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GenericAddress {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
}

/// ACPI HPET Description Table
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct HpetTable {
    header: SdtHeader,
    event_timer_block_id: u32,
    base_address: GenericAddress,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
}

// ============================================================================
// HPET Info and Error Types
// ============================================================================

/// HPET hardware information
#[derive(Debug, Clone, Copy)]
pub struct HpetInfo {
    /// Physical base address of HPET registers
    pub base_phys: u64,
    /// Virtual base address for MMIO access
    pub base_virt: u64,
    /// Counter clock period in femtoseconds (10^-15 seconds)
    pub period_fs: u64,
    /// Calculated frequency in Hz
    pub frequency_hz: u64,
    /// Number of comparator timers
    pub comparator_count: u8,
    /// True if counter is 64-bit, false if 32-bit
    pub counter_64bit: bool,
}

/// HPET initialization errors
#[derive(Debug, Clone, Copy)]
pub enum HpetInitError {
    /// ACPI RSDP not found
    RsdpNotFound,
    /// HPET ACPI table not found
    TableNotFound,
    /// Table length is invalid
    InvalidLength,
    /// Table checksum validation failed
    InvalidChecksum,
    /// HPET base address is in unsupported address space
    UnsupportedAddressSpace(u8),
    /// HPET base address is zero or invalid
    MissingBase,
    /// Counter period is zero (invalid hardware)
    InvalidPeriod,
    /// Failed to create MMIO mapping
    MappingFailed,
}

// ============================================================================
// HPET State
// ============================================================================

/// HPET initialization state (once per boot)
static HPET_STATE: Once<HpetInfo> = Once::new();

/// Cached HPET virtual base address for fast counter reads
static HPET_VIRT: AtomicU64 = AtomicU64::new(0);

/// E.1 FIX: Serialization lock for init() to prevent race conditions.
/// Without this, concurrent callers could both call init_internal() and
/// attempt to double-map HPET_VIRT_BASE, causing a page fault or corruption.
static HPET_INIT_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Public API
// ============================================================================

/// Initialize HPET hardware and return its descriptor.
///
/// Locates the HPET via ACPI tables, creates an MMIO mapping, enables the
/// main counter, and caches hardware information for subsequent use.
///
/// # Returns
///
/// - `Ok(HpetInfo)` on successful initialization
/// - `Err(HpetInitError)` if HPET is unavailable or initialization fails
///
/// # Safety Note
///
/// This function modifies HPET hardware registers and creates page table
/// mappings. It should be called only once during early boot, before any
/// other code depends on HPET timing.
///
/// # Thread Safety
///
/// E.1 FIX: Uses HPET_INIT_LOCK to serialize concurrent init() calls,
/// preventing double-mapping of HPET_VIRT_BASE.
pub fn init() -> Result<HpetInfo, HpetInitError> {
    // Fast path: return cached state if already initialized
    if let Some(info) = HPET_STATE.get() {
        return Ok(*info);
    }

    // E.1 FIX: Acquire lock to serialize initialization attempts
    let _guard = HPET_INIT_LOCK.lock();

    // Double-check after acquiring lock (another thread may have completed init)
    if let Some(info) = HPET_STATE.get() {
        return Ok(*info);
    }

    // Perform initialization (only one thread reaches here)
    let info = unsafe { init_internal()? };

    // Store state (call_once handles any remaining edge cases)
    HPET_STATE.call_once(|| info);
    HPET_VIRT.store(info.base_virt, Ordering::Release);

    Ok(info)
}

/// Get HPET hardware info if already initialized.
///
/// # Returns
///
/// - `Some(HpetInfo)` if HPET was successfully initialized
/// - `None` if `init()` was not called or failed
#[inline]
pub fn info() -> Option<HpetInfo> {
    HPET_STATE.get().copied()
}

/// Read the HPET main counter value.
///
/// # Returns
///
/// - `Some(counter)` with the current counter value
/// - `None` if HPET is not initialized
///
/// # Counter Behavior
///
/// - 64-bit HPET: Returns full 64-bit counter value
/// - 32-bit HPET: Returns counter value masked to 32 bits
///
/// The counter increments at a fixed rate defined by `HpetInfo::frequency_hz`.
/// To convert ticks to time:
///
/// ```ignore
/// let ns = (ticks * info.period_fs) / 1_000_000;  // nanoseconds
/// let us = (ticks * info.period_fs) / 1_000_000_000_000;  // microseconds
/// ```
#[inline]
pub fn read_main_counter() -> Option<u64> {
    let base_virt = HPET_VIRT.load(Ordering::Acquire);
    if base_virt == 0 {
        return None;
    }

    // E.1 HPET: Reading is safe because:
    // 1. HPET registers are mapped via map_mmio() with proper MMIO flags
    // 2. HPET hardware is designed for concurrent register access
    // 3. Counter register is inherently atomic on 64-bit reads
    let value = unsafe { read_reg64(base_virt, regs::COUNTER) };

    // Handle 32-bit counter hardware
    if let Some(info) = HPET_STATE.get() {
        if !info.counter_64bit {
            return Some(value & 0xFFFF_FFFF);
        }
    }

    Some(value)
}

/// Check if HPET is initialized and available.
#[inline]
pub fn is_initialized() -> bool {
    HPET_VIRT.load(Ordering::Acquire) != 0
}

/// Get the HPET counter frequency in Hz.
#[inline]
pub fn frequency_hz() -> Option<u64> {
    HPET_STATE.get().map(|info| info.frequency_hz)
}

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal HPET initialization.
///
/// # Safety
///
/// - Requires ACPI tables to be mapped and valid
/// - Creates MMIO page table mappings
/// - Modifies HPET hardware registers
unsafe fn init_internal() -> Result<HpetInfo, HpetInitError> {
    // Step 1: Find RSDP
    let (rsdt_phys, xsdt_phys) = find_rsdp().ok_or(HpetInitError::RsdpNotFound)?;

    // Step 2: Find HPET table (prefer XSDT)
    let table_phys = if xsdt_phys != 0 {
        find_table_xsdt(xsdt_phys, b"HPET").or_else(|| find_table_rsdt(rsdt_phys, b"HPET"))
    } else {
        find_table_rsdt(rsdt_phys, b"HPET")
    }
    .ok_or(HpetInitError::TableNotFound)?;

    // Step 3: Read and validate HPET table header
    let header = read_sdt_header(table_phys).ok_or(HpetInitError::InvalidLength)?;
    if &header.signature != b"HPET" {
        return Err(HpetInitError::TableNotFound);
    }

    let total_len = header.length as usize;
    if total_len < core::mem::size_of::<HpetTable>() {
        return Err(HpetInitError::InvalidLength);
    }

    // Step 4: Read full table and validate checksum
    let table_bytes = phys_slice(table_phys, total_len).ok_or(HpetInitError::InvalidLength)?;
    if !validate_checksum(table_bytes) {
        return Err(HpetInitError::InvalidChecksum);
    }

    // Step 5: Parse HPET table
    let hpet_table: HpetTable = read_unaligned(table_bytes.as_ptr() as *const HpetTable);

    // Validate address space (must be system memory, not I/O port)
    if hpet_table.base_address.address_space_id != 0 {
        return Err(HpetInitError::UnsupportedAddressSpace(
            hpet_table.base_address.address_space_id,
        ));
    }

    let base_phys = hpet_table.base_address.address;
    if base_phys == 0 {
        return Err(HpetInitError::MissingBase);
    }

    // Step 6: Create dedicated MMIO mapping for HPET
    // We cannot use the identity-mapped region because security hardening
    // makes it read-only. Create a high-half mapping instead.
    let base_virt = HPET_VIRT_BASE;
    let mut frame_alloc = FrameAllocator::new();

    map_mmio(
        VirtAddr::new(base_virt),
        PhysAddr::new(base_phys),
        HPET_MMIO_SIZE,
        &mut frame_alloc,
    )
    .map_err(|_| HpetInitError::MappingFailed)?;

    // Step 7: Read capabilities register (using the new virtual mapping)
    let caps = read_reg64(base_virt, regs::CAPS_ID);

    // Extract counter period (femtoseconds per tick)
    let period_fs = (caps & caps_bits::CLK_PERIOD_MASK) >> caps_bits::CLK_PERIOD_SHIFT;
    if period_fs == 0 {
        return Err(HpetInitError::InvalidPeriod);
    }

    // Extract number of timers (value + 1)
    let comparator_count =
        (((caps & caps_bits::NUM_TIM_CAP_MASK) >> caps_bits::NUM_TIM_CAP_SHIFT) as u8) + 1;

    // Check if counter is 64-bit
    let counter_64bit = caps & caps_bits::COUNT_SIZE_CAP != 0;

    // Step 8: Configure and enable HPET
    // Disable counter first
    let mut config = read_reg64(base_virt, regs::CONFIG);
    config &= !config_bits::ENABLE_CNF;
    write_reg64(base_virt, regs::CONFIG, config);

    // E.1 FIX: Disarm all comparator timers that may have been armed by firmware.
    // Without this, firmware-configured timers could fire unexpected interrupts
    // or interfere with our use of the main counter.
    for i in 0..comparator_count {
        let timer_config_offset = regs::TIMER_CONFIG_BASE + (i as usize) * 0x20;
        // Clear timer configuration (disables interrupt, clears periodic mode)
        write_reg64(base_virt, timer_config_offset, 0);
        // Also clear comparator value to prevent any edge cases
        let timer_comparator_offset = regs::TIMER_COMPARATOR_BASE + (i as usize) * 0x20;
        write_reg64(base_virt, timer_comparator_offset, 0);
    }

    // Reset counter to 0
    write_reg64(base_virt, regs::COUNTER, 0);

    // Disable legacy routing (we use LAPIC timer for scheduling)
    config &= !config_bits::LEG_RT_CNF;

    // Enable main counter
    config |= config_bits::ENABLE_CNF;
    write_reg64(base_virt, regs::CONFIG, config);

    // Step 9: Calculate frequency
    // frequency = 10^15 fs/s / period_fs
    // Use 128-bit arithmetic to avoid overflow
    let frequency_hz = {
        const FEMTO_PER_SECOND: u128 = 1_000_000_000_000_000;
        ((FEMTO_PER_SECOND + (period_fs as u128 / 2)) / period_fs as u128) as u64
    };

    let info = HpetInfo {
        base_phys,
        base_virt,
        period_fs,
        frequency_hz,
        comparator_count,
        counter_64bit,
    };

    println!(
        "[HPET] Initialized: phys=0x{:x}, virt=0x{:x}, freq={} Hz, timers={}, 64-bit={}",
        base_phys, base_virt, frequency_hz, comparator_count, counter_64bit
    );

    Ok(info)
}

/// Read a 64-bit register from HPET MMIO space.
///
/// # Safety
///
/// - `base_virt` must be a valid mapped HPET virtual base address
#[inline]
unsafe fn read_reg64(base_virt: u64, offset: usize) -> u64 {
    let addr = (base_virt + offset as u64) as *const u64;
    read_volatile(addr)
}

/// Write a 64-bit register to HPET MMIO space.
///
/// # Safety
///
/// - `base_virt` must be a valid mapped HPET virtual base address
#[inline]
unsafe fn write_reg64(base_virt: u64, offset: usize, value: u64) {
    let addr = (base_virt + offset as u64) as *mut u64;
    write_volatile(addr, value);
}
