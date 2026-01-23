//! Local APIC and I/O APIC Support for SMP
//!
//! This module provides hardware abstraction for the Advanced Programmable Interrupt
//! Controller (APIC) subsystem, which is required for SMP operation on x86_64.
//!
//! # Architecture
//!
//! ```text
//! +----------------+     +----------------+     +----------------+
//! |     CPU 0      |     |     CPU 1      |     |     CPU N      |
//! |   (BSP)        |     |    (AP)        |     |    (AP)        |
//! +-------+--------+     +-------+--------+     +-------+--------+
//!         |                      |                      |
//!         v                      v                      v
//! +-------+--------+     +-------+--------+     +-------+--------+
//! |    LAPIC 0     |     |    LAPIC 1     |     |    LAPIC N     |
//! | (0xFEE00000)   |     | (0xFEE00000)   |     | (0xFEE00000)   |
//! +-------+--------+     +-------+--------+     +-------+--------+
//!         |                      |                      |
//!         +----------+-----------+----------------------+
//!                    |
//!                    v
//!            +-------+--------+
//!            |    I/O APIC    |
//!            | (0xFEC00000)   |
//!            | IRQ 0-23       |
//!            +----------------+
//! ```
//!
//! # LAPIC
//!
//! The Local APIC handles:
//! - Inter-Processor Interrupts (IPIs)
//! - Local timer interrupts
//! - Performance monitoring
//! - Thermal sensor interrupts
//!
//! # I/O APIC
//!
//! The I/O APIC routes external device interrupts to CPUs:
//! - Replaces the legacy 8259 PIC in SMP mode
//! - Supports up to 24 interrupt redirection entries
//! - Allows per-interrupt CPU targeting
//!
//! # Current Status
//!
//! This module is part of Phase E (SMP) and is currently single-core safe.
//! The LAPIC is initialized but only for single-core timer and interrupt handling.
//! I/O APIC and full SMP support will be added incrementally.

use core::hint::spin_loop;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::instructions::port::{Port, PortWriteOnly};

// ============================================================================
// LAPIC Constants and Registers
// ============================================================================

/// Default LAPIC base address (x2APIC mode uses MSRs instead)
pub const LAPIC_DEFAULT_BASE: u64 = 0xFEE0_0000;

/// LAPIC register offsets (memory-mapped)
pub mod lapic {
    pub const ID: u32 = 0x020; // LAPIC ID
    pub const VERSION: u32 = 0x030; // LAPIC Version
    pub const TPR: u32 = 0x080; // Task Priority Register
    pub const APR: u32 = 0x090; // Arbitration Priority Register
    pub const PPR: u32 = 0x0A0; // Processor Priority Register
    pub const EOI: u32 = 0x0B0; // End of Interrupt
    pub const RRD: u32 = 0x0C0; // Remote Read Register
    pub const LDR: u32 = 0x0D0; // Logical Destination Register
    pub const DFR: u32 = 0x0E0; // Destination Format Register
    pub const SIVR: u32 = 0x0F0; // Spurious Interrupt Vector Register
    pub const ISR_BASE: u32 = 0x100; // In-Service Register (8 registers)
    pub const TMR_BASE: u32 = 0x180; // Trigger Mode Register (8 registers)
    pub const IRR_BASE: u32 = 0x200; // Interrupt Request Register (8 registers)
    pub const ESR: u32 = 0x280; // Error Status Register
    pub const ICR_LOW: u32 = 0x300; // Interrupt Command Register (low)
    pub const ICR_HIGH: u32 = 0x310; // Interrupt Command Register (high)
    pub const LVT_TIMER: u32 = 0x320; // LVT Timer Register
    pub const LVT_THERMAL: u32 = 0x330; // LVT Thermal Sensor Register
    pub const LVT_PERF: u32 = 0x340; // LVT Performance Monitoring Register
    pub const LVT_LINT0: u32 = 0x350; // LVT LINT0 Register
    pub const LVT_LINT1: u32 = 0x360; // LVT LINT1 Register
    pub const LVT_ERROR: u32 = 0x370; // LVT Error Register
    pub const TIMER_INIT: u32 = 0x380; // Timer Initial Count
    pub const TIMER_CURRENT: u32 = 0x390; // Timer Current Count
    pub const TIMER_DIVIDE: u32 = 0x3E0; // Timer Divide Configuration
}

/// Spurious Interrupt Vector Register bits
pub mod sivr_bits {
    /// APIC Software Enable (bit 8)
    pub const APIC_ENABLED: u32 = 1 << 8;
    /// Focus Processor Checking (bit 9)
    pub const FOCUS_DISABLED: u32 = 1 << 9;
    /// EOI-Broadcast Suppression (bit 12)
    pub const EOI_BROADCAST_SUPPRESSION: u32 = 1 << 12;
}

/// LVT entry bits
pub mod lvt_bits {
    /// Delivery Mode: Fixed (000)
    pub const DELIVERY_FIXED: u32 = 0 << 8;
    /// Delivery Mode: SMI (010)
    pub const DELIVERY_SMI: u32 = 2 << 8;
    /// Delivery Mode: NMI (100)
    pub const DELIVERY_NMI: u32 = 4 << 8;
    /// Delivery Mode: ExtINT (111)
    pub const DELIVERY_EXTINT: u32 = 7 << 8;
    /// Interrupt pending (read-only)
    pub const PENDING: u32 = 1 << 12;
    /// Polarity: Active low (for level-triggered)
    pub const POLARITY_LOW: u32 = 1 << 13;
    /// Trigger Mode: Level (for LINT0/LINT1)
    pub const TRIGGER_LEVEL: u32 = 1 << 15;
    /// Masked (interrupt disabled)
    pub const MASKED: u32 = 1 << 16;
    /// Timer Mode: One-shot
    pub const TIMER_ONESHOT: u32 = 0 << 17;
    /// Timer Mode: Periodic
    pub const TIMER_PERIODIC: u32 = 1 << 17;
    /// Timer Mode: TSC-Deadline
    pub const TIMER_TSC_DEADLINE: u32 = 2 << 17;
}

/// LAPIC Timer Divider values (for TIMER_DIVIDE register)
pub mod timer_divide {
    pub const DIV_1: u32 = 0b1011;   // Divide by 1
    pub const DIV_2: u32 = 0b0000;   // Divide by 2
    pub const DIV_4: u32 = 0b0001;   // Divide by 4
    pub const DIV_8: u32 = 0b0010;   // Divide by 8
    pub const DIV_16: u32 = 0b0011;  // Divide by 16
    pub const DIV_32: u32 = 0b1000;  // Divide by 32
    pub const DIV_64: u32 = 0b1001;  // Divide by 64
    pub const DIV_128: u32 = 0b1010; // Divide by 128
}

/// ICR Delivery Mode
pub mod icr_delivery {
    pub const FIXED: u32 = 0 << 8;
    pub const LOWEST_PRIORITY: u32 = 1 << 8;
    pub const SMI: u32 = 2 << 8;
    pub const NMI: u32 = 4 << 8;
    pub const INIT: u32 = 5 << 8;
    pub const STARTUP: u32 = 6 << 8;
}

/// ICR Destination Shorthand
pub mod icr_dest {
    pub const NO_SHORTHAND: u32 = 0 << 18;
    pub const SELF: u32 = 1 << 18;
    pub const ALL_INCLUDING_SELF: u32 = 2 << 18;
    pub const ALL_EXCLUDING_SELF: u32 = 3 << 18;
}

/// ICR flags
pub mod icr_flags {
    /// Level: Assert (for INIT/INIT-deassert)
    pub const LEVEL_ASSERT: u32 = 1 << 14;
    /// Level: De-assert
    pub const LEVEL_DEASSERT: u32 = 0 << 14;
    /// Trigger: Edge
    pub const TRIGGER_EDGE: u32 = 0 << 15;
    /// Trigger: Level
    pub const TRIGGER_LEVEL: u32 = 1 << 15;
    /// Delivery Status: Pending (read-only)
    pub const DELIVERY_PENDING: u32 = 1 << 12;
}

// ============================================================================
// I/O APIC Constants and Registers
// ============================================================================

/// Default I/O APIC base address
pub const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;

/// I/O APIC register select (write address)
pub const IOAPIC_REGSEL: u32 = 0x00;
/// I/O APIC register data (read/write at REGSEL)
pub const IOAPIC_REGDATA: u32 = 0x10;

/// I/O APIC registers (accessed via REGSEL/REGDATA)
pub mod ioapic {
    /// I/O APIC ID Register
    pub const ID: u8 = 0x00;
    /// I/O APIC Version Register
    pub const VERSION: u8 = 0x01;
    /// I/O APIC Arbitration Register
    pub const ARB: u8 = 0x02;
    /// Redirection Table Entry (0-23, each is 2 registers)
    /// Entry N is at registers 0x10 + 2*N (low) and 0x11 + 2*N (high)
    pub const REDIR_TABLE_BASE: u8 = 0x10;
}

/// I/O APIC Redirection Entry bits
pub mod redir_bits {
    /// Delivery Mode: Fixed
    pub const DELIVERY_FIXED: u64 = 0 << 8;
    /// Delivery Mode: Lowest Priority
    pub const DELIVERY_LOWEST: u64 = 1 << 8;
    /// Delivery Mode: SMI
    pub const DELIVERY_SMI: u64 = 2 << 8;
    /// Delivery Mode: NMI
    pub const DELIVERY_NMI: u64 = 4 << 8;
    /// Delivery Mode: INIT
    pub const DELIVERY_INIT: u64 = 5 << 8;
    /// Delivery Mode: ExtINT
    pub const DELIVERY_EXTINT: u64 = 7 << 8;
    /// Destination Mode: Physical
    pub const DESTMODE_PHYSICAL: u64 = 0 << 11;
    /// Destination Mode: Logical
    pub const DESTMODE_LOGICAL: u64 = 1 << 11;
    /// Delivery Status: Pending (read-only)
    pub const DELIVERY_PENDING: u64 = 1 << 12;
    /// Polarity: Active low
    pub const POLARITY_LOW: u64 = 1 << 13;
    /// Remote IRR (read-only for level-triggered)
    pub const REMOTE_IRR: u64 = 1 << 14;
    /// Trigger Mode: Level
    pub const TRIGGER_LEVEL: u64 = 1 << 15;
    /// Masked (interrupt disabled)
    pub const MASKED: u64 = 1 << 16;
    /// Destination field shift (bits 56-63)
    pub const DEST_SHIFT: u64 = 56;
}

// ============================================================================
// APIC State
// ============================================================================

/// Global APIC initialization state
static LAPIC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static IOAPIC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// LAPIC base address (may be relocated via MSR)
static LAPIC_BASE: AtomicU32 = AtomicU32::new(LAPIC_DEFAULT_BASE as u32);

/// I/O APIC base address
static IOAPIC_BASE: AtomicU32 = AtomicU32::new(IOAPIC_DEFAULT_BASE as u32);

/// BSP LAPIC ID (stored during init)
static BSP_LAPIC_ID: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// LAPIC Timer Configuration
// ============================================================================

/// LAPIC timer interrupt vector (matches IRQ0/PIT on BSP for uniform handling)
const LAPIC_TIMER_VECTOR: u32 = 32;

/// Default LAPIC timer initial count (~1kHz with DIV_16 on typical CPUs)
/// This is a conservative default; call `set_lapic_timer_init_count()` with
/// a calibrated value for accurate timing.
const LAPIC_TIMER_DEFAULT_INIT_COUNT: u32 = 0x10000;

/// Shared LAPIC timer initial count (calibrated on BSP, used by all APs)
static LAPIC_TIMER_INIT_COUNT: AtomicU32 = AtomicU32::new(LAPIC_TIMER_DEFAULT_INIT_COUNT);

// ============================================================================
// PIT Channel 2 Calibration Constants
// ============================================================================

/// PIT base frequency (Hz) used for LAPIC calibration
const PIT_FREQUENCY_HZ: u32 = 1_193_182;
/// PIT command port
const PIT_COMMAND_PORT: u16 = 0x43;
/// PIT channel 2 data port (used as gate timer)
const PIT_CHANNEL2_DATA_PORT: u16 = 0x42;
/// PIT channel 2 gate/speaker control port
const PIT_CHANNEL2_GATE_PORT: u16 = 0x61;
/// PIT channel 2 gate enable bit (port 0x61)
const PIT_CHANNEL2_GATE_BIT: u8 = 1 << 0;
/// PIT speaker enable bit (port 0x61) - keep cleared to avoid audible beep
const PIT_CHANNEL2_SPEAKER_BIT: u8 = 1 << 1;
/// PIT channel 2 OUT status bit (port 0x61)
const PIT_CHANNEL2_OUT_BIT: u8 = 1 << 5;
/// Calibration window length in milliseconds
const LAPIC_CALIBRATION_WINDOW_MS: u32 = 10;

// ============================================================================
// LAPIC Operations
// ============================================================================

/// Read a LAPIC register
///
/// # Safety
///
/// The LAPIC must be mapped at the stored base address.
#[inline]
pub unsafe fn lapic_read(reg: u32) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as u64;
    let addr = (base + reg as u64) as *const u32;
    read_volatile(addr)
}

/// Write to a LAPIC register
///
/// # Safety
///
/// The LAPIC must be mapped at the stored base address.
#[inline]
pub unsafe fn lapic_write(reg: u32, value: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as u64;
    let addr = (base + reg as u64) as *mut u32;
    write_volatile(addr, value);
}

/// Get the current CPU's LAPIC ID
///
/// # Safety
///
/// LAPIC must be initialized.
#[inline]
pub unsafe fn lapic_id() -> u32 {
    (lapic_read(lapic::ID) >> 24) & 0xFF
}

/// Send End of Interrupt to LAPIC
///
/// This must be called at the end of interrupt handlers for
/// LAPIC-routed interrupts.
///
/// # Safety
///
/// Must be called in interrupt context after handling the interrupt.
#[inline]
pub unsafe fn lapic_eoi() {
    lapic_write(lapic::EOI, 0);
}

// ============================================================================
// LAPIC Timer Functions
// ============================================================================

/// Set the calibrated LAPIC timer initial count.
///
/// This value is shared across all CPUs. Call this on the BSP after
/// calibrating against the PIT or another known time source, before
/// starting APs.
///
/// # Arguments
///
/// * `count` - The timer initial count for ~1kHz ticks. If 0, uses default.
pub fn set_lapic_timer_init_count(count: u32) {
    let value = if count == 0 {
        LAPIC_TIMER_DEFAULT_INIT_COUNT
    } else {
        count
    };
    LAPIC_TIMER_INIT_COUNT.store(value, Ordering::Relaxed);
}

/// Get the current LAPIC timer initial count setting.
#[inline]
pub fn get_lapic_timer_init_count() -> u32 {
    LAPIC_TIMER_INIT_COUNT.load(Ordering::Relaxed)
}

/// Calibrate LAPIC timer against PIT channel 2 or HPET (if available).
///
/// E.1 HPET: First attempts HPET-based calibration for higher precision.
/// Falls back to PIT channel 2 calibration if HPET is unavailable.
///
/// Programs the reference timer for a fixed window, measures the LAPIC timer
/// decrement over that period, and derives an initial count that yields
/// ~1kHz ticks with a divide-by-16 configuration.
///
/// Returns the calibrated initial count on success and leaves the shared
/// `LAPIC_TIMER_INIT_COUNT` updated. On failure, the previous value is left
/// intact and an error is returned.
///
/// # Safety
///
/// - LAPIC must be initialized
/// - Should be called only on BSP before starting APs
/// - Interrupts MUST be disabled during calibration (enforced by assertion)
///
/// # Panics
///
/// Panics if called with interrupts enabled.
pub unsafe fn calibrate_lapic_timer() -> Result<u32, &'static str> {
    // R70-7 FIX: Assert interrupts are disabled to prevent measurement skew.
    // If an IRQ fires during calibration, the measured LAPIC frequency would
    // be lower than actual, causing timer ticks to fire too slowly.
    assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "calibrate_lapic_timer: interrupts must be disabled"
    );

    if !lapic_initialized() {
        drivers::println!("[APIC] calibrate_lapic_timer: LAPIC not initialized");
        return Err("lapic not initialized");
    }

    // E.1 HPET: Prefer HPET-based calibration for higher precision
    if let Some(result) = calibrate_with_hpet() {
        return Ok(result);
    }

    // Fallback to PIT-based calibration
    calibrate_with_pit()
}

/// E.1 HPET: Calibrate LAPIC timer using HPET as the reference clock.
///
/// HPET typically runs at ~14.318 MHz (compared to PIT's ~1.193 MHz),
/// providing more accurate calibration results.
///
/// # Returns
///
/// - `Some(init_count)` on successful calibration
/// - `None` if HPET is not available or calibration fails
///
/// # Safety
///
/// LAPIC must be initialized and interrupts must be disabled.
unsafe fn calibrate_with_hpet() -> Option<u32> {
    use crate::hpet;

    // Check if HPET is initialized
    let info = hpet::info()?;

    // Calculate the number of HPET ticks for the calibration window
    let window_ms = LAPIC_CALIBRATION_WINDOW_MS as u64;
    let window_ticks = info.frequency_hz.saturating_mul(window_ms) / 1000;
    if window_ticks == 0 {
        return None;
    }

    // Configure LAPIC timer in masked one-shot mode
    lapic_write(
        lapic::LVT_TIMER,
        LAPIC_TIMER_VECTOR | lvt_bits::TIMER_ONESHOT | lvt_bits::MASKED,
    );
    lapic_write(lapic::TIMER_DIVIDE, timer_divide::DIV_16);

    // Start LAPIC countdown
    let hpet_start = hpet::read_main_counter()?;
    lapic_write(lapic::TIMER_INIT, u32::MAX);

    // Wait for HPET window to elapse
    const MAX_HPET_POLLS: u64 = 200_000_000;
    let mut polls: u64 = 0;
    loop {
        let hpet_now = hpet::read_main_counter()?;
        if hpet_now.wrapping_sub(hpet_start) >= window_ticks {
            break;
        }
        polls = polls.wrapping_add(1);
        if polls >= MAX_HPET_POLLS {
            lapic_write(lapic::TIMER_INIT, 0);
            drivers::println!("[APIC] calibrate_with_hpet: HPET wait timeout");
            return None;
        }
        spin_loop();
    }

    // Read LAPIC timer and stop it
    let elapsed = u32::MAX - lapic_read(lapic::TIMER_CURRENT);
    lapic_write(lapic::TIMER_INIT, 0);

    if elapsed == 0 {
        drivers::println!("[APIC] calibrate_with_hpet: LAPIC timer did not decrement");
        return None;
    }

    // Calculate ticks per millisecond with rounding
    let per_ms = ((elapsed as u64) + (window_ms / 2)) / window_ms;
    let calibrated = per_ms.min(u32::MAX as u64) as u32;

    if calibrated == 0 {
        drivers::println!("[APIC] calibrate_with_hpet: computed init count is zero");
        return None;
    }

    LAPIC_TIMER_INIT_COUNT.store(calibrated, Ordering::Relaxed);
    drivers::println!(
        "[APIC] LAPIC timer calibrated via HPET: {} ticks in {} ms -> init_count={} (div=16, ~1kHz)",
        elapsed,
        window_ms,
        calibrated
    );
    Some(calibrated)
}

/// Calibrate LAPIC timer using PIT channel 2 as the reference clock.
///
/// Programs PIT channel 2 as a one-shot gate timer (using port 0x61 to toggle
/// the gate) for a fixed window, measures the LAPIC timer decrement over that
/// period, and derives an initial count that yields ~1kHz ticks.
///
/// # Safety
///
/// LAPIC must be initialized and interrupts must be disabled.
unsafe fn calibrate_with_pit() -> Result<u32, &'static str> {
    let mut pit_cmd = PortWriteOnly::<u8>::new(PIT_COMMAND_PORT);
    let mut pit_ch2 = PortWriteOnly::<u8>::new(PIT_CHANNEL2_DATA_PORT);
    let mut pit_gate = Port::<u8>::new(PIT_CHANNEL2_GATE_PORT);

    let saved_gate = pit_gate.read();
    // Hold gate low and disconnect speaker to avoid audible clicks.
    pit_gate.write(saved_gate & !(PIT_CHANNEL2_GATE_BIT | PIT_CHANNEL2_SPEAKER_BIT));

    // Calculate PIT reload value for the calibration window
    let pit_reload = ((PIT_FREQUENCY_HZ as u64 * LAPIC_CALIBRATION_WINDOW_MS as u64) + 500) / 1000;
    if pit_reload == 0 || pit_reload > u16::MAX as u64 {
        drivers::println!(
            "[APIC] calibrate_lapic_timer: invalid PIT reload value {}",
            pit_reload
        );
        pit_gate.write(saved_gate);
        return Err("invalid pit reload");
    }

    // Channel 2, lobyte/hibyte, mode 0 (one-shot), binary.
    pit_cmd.write(0b1011_0000);
    pit_ch2.write(pit_reload as u8);
    pit_ch2.write((pit_reload >> 8) as u8);

    // Prepare LAPIC timer in masked one-shot mode to avoid spurious IRQs.
    lapic_write(
        lapic::LVT_TIMER,
        LAPIC_TIMER_VECTOR | lvt_bits::TIMER_ONESHOT | lvt_bits::MASKED,
    );
    lapic_write(lapic::TIMER_DIVIDE, timer_divide::DIV_16);

    // Start PIT window and LAPIC countdown close together.
    pit_gate.write((saved_gate & !PIT_CHANNEL2_SPEAKER_BIT) | PIT_CHANNEL2_GATE_BIT);
    lapic_write(lapic::TIMER_INIT, u32::MAX);

    // Wait for PIT terminal count signaled via OUT bit.
    let mut polls: u32 = 0;
    const MAX_PIT_POLLS: u32 = 50_000_000;
    while pit_gate.read() & PIT_CHANNEL2_OUT_BIT == 0 {
        polls = polls.wrapping_add(1);
        if polls >= MAX_PIT_POLLS {
            pit_gate.write(saved_gate);
            lapic_write(lapic::TIMER_INIT, 0);
            drivers::println!("[APIC] calibrate_lapic_timer: PIT wait timeout");
            return Err("pit timeout");
        }
        spin_loop();
    }

    let elapsed = u32::MAX - lapic_read(lapic::TIMER_CURRENT);
    // Stop LAPIC timer and restore speaker port state.
    lapic_write(lapic::TIMER_INIT, 0);
    pit_gate.write(saved_gate);

    if elapsed == 0 {
        drivers::println!("[APIC] calibrate_lapic_timer: LAPIC timer did not decrement");
        return Err("lapic timer not running");
    }

    // Calculate ticks per millisecond and round
    let per_ms = ((elapsed as u64) + (LAPIC_CALIBRATION_WINDOW_MS as u64 / 2))
        / LAPIC_CALIBRATION_WINDOW_MS as u64;
    let calibrated = per_ms.min(u32::MAX as u64) as u32;

    if calibrated == 0 {
        drivers::println!("[APIC] calibrate_lapic_timer: computed init count is zero");
        return Err("calibration result zero");
    }

    LAPIC_TIMER_INIT_COUNT.store(calibrated, Ordering::Relaxed);
    drivers::println!(
        "[APIC] LAPIC timer calibrated: {} ticks in {} ms -> init_count={} (div=16, ~1kHz)",
        elapsed,
        LAPIC_CALIBRATION_WINDOW_MS,
        calibrated
    );
    Ok(calibrated)
}

/// Start the LAPIC timer in periodic mode.
///
/// Configures the local APIC timer to fire at approximately 1kHz using
/// the calibrated initial count. The timer uses vector 32 (same as BSP's
/// PIT IRQ0) for uniform interrupt handling.
///
/// # Safety
///
/// - LAPIC must be enabled and properly mapped
/// - IDT entry for vector 32 must be configured
/// - Should be called after LAPIC initialization
pub unsafe fn start_lapic_timer() {
    let initial_count = LAPIC_TIMER_INIT_COUNT
        .load(Ordering::Relaxed)
        .max(1); // Ensure non-zero to actually start the timer

    // Set divider to 16 for reasonable count range
    lapic_write(lapic::TIMER_DIVIDE, timer_divide::DIV_16);

    // Configure LVT Timer: vector 32, periodic mode, unmasked
    lapic_write(
        lapic::LVT_TIMER,
        LAPIC_TIMER_VECTOR | lvt_bits::TIMER_PERIODIC,
    );

    // Writing initial count starts the timer
    lapic_write(lapic::TIMER_INIT, initial_count);
}

/// Stop the LAPIC timer.
///
/// Masks the timer interrupt and clears the initial count.
///
/// # Safety
///
/// LAPIC must be enabled.
pub unsafe fn stop_lapic_timer() {
    // Mask the timer
    lapic_write(lapic::LVT_TIMER, lvt_bits::MASKED);
    // Clear initial count to stop
    lapic_write(lapic::TIMER_INIT, 0);
}

/// Check if this CPU's LAPIC timer is running.
///
/// # Safety
///
/// LAPIC must be mapped.
pub unsafe fn lapic_timer_running() -> bool {
    let lvt = lapic_read(lapic::LVT_TIMER);
    // Timer is running if not masked and has non-zero count
    (lvt & lvt_bits::MASKED) == 0 && lapic_read(lapic::TIMER_CURRENT) > 0
}

/// Check if LAPIC is enabled in hardware
pub fn lapic_hw_enabled() -> bool {
    // Read IA32_APIC_BASE MSR (0x1B)
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    let msr_value = ((high as u64) << 32) | (low as u64);
    // Bit 11 is the APIC Global Enable flag
    (msr_value & (1 << 11)) != 0
}

/// Enable LAPIC in hardware via IA32_APIC_BASE MSR
///
/// # Safety
///
/// This modifies CPU state and should only be called during early boot.
pub unsafe fn lapic_hw_enable() {
    let msr: u32 = 0x1B;
    let mut low: u32;
    let mut high: u32;

    // Read current value
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack)
    );

    // Set bit 11 (Global Enable) and preserve base address
    low |= 1 << 11;

    // Write back
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack)
    );
}

/// Initialize the LAPIC for this CPU
///
/// This sets up the LAPIC for interrupt handling:
/// - Enables the LAPIC software enable bit
/// - Sets the spurious interrupt vector
/// - Masks all LVT entries initially
/// - Clears any pending errors
///
/// # Safety
///
/// - Must be called early in boot before enabling interrupts
/// - LAPIC MMIO region must be identity-mapped or properly mapped
pub unsafe fn init_lapic() {
    if LAPIC_INITIALIZED.load(Ordering::Relaxed) {
        return; // Already initialized
    }

    // Enable LAPIC in hardware if not already
    if !lapic_hw_enabled() {
        lapic_hw_enable();
    }

    // Store BSP LAPIC ID
    let id = lapic_id();
    BSP_LAPIC_ID.store(id, Ordering::Relaxed);

    // Clear any existing errors
    lapic_write(lapic::ESR, 0);
    let _ = lapic_read(lapic::ESR); // Read clears the register

    // Set Task Priority to accept all interrupts
    lapic_write(lapic::TPR, 0);

    // Set Destination Format Register to flat model
    lapic_write(lapic::DFR, 0xFFFF_FFFF);

    // Set Logical Destination Register
    // In flat model, bits 24-31 are the logical ID
    lapic_write(lapic::LDR, 1 << 24);

    // Configure LVT entries: keep local sources masked, but allow legacy PIC via LINT0 (ExtINT)
    // LINT0 connects to the 8259 PIC's INTR output on the BSP; masking it blocks all PIC IRQs.
    // Use ExtINT delivery mode to pass through PIC interrupts when I/O APIC is not used.
    lapic_write(lapic::LVT_TIMER, lvt_bits::MASKED);
    lapic_write(lapic::LVT_LINT0, lvt_bits::DELIVERY_EXTINT);
    lapic_write(lapic::LVT_LINT1, lvt_bits::MASKED);
    lapic_write(lapic::LVT_ERROR, lvt_bits::MASKED);
    lapic_write(lapic::LVT_PERF, lvt_bits::MASKED);
    lapic_write(lapic::LVT_THERMAL, lvt_bits::MASKED);

    // Set spurious interrupt vector and enable APIC
    // Vector 0xFF is commonly used for spurious interrupts
    lapic_write(lapic::SIVR, sivr_bits::APIC_ENABLED | 0xFF);

    // Clear any pending interrupts by reading ISR
    for i in 0..8 {
        let _ = lapic_read(lapic::ISR_BASE + i * 0x10);
    }

    // Send EOI to clear any pending interrupt state
    lapic_eoi();

    LAPIC_INITIALIZED.store(true, Ordering::Release);
}

/// Initialize the LAPIC for an Application Processor (AP)
///
/// Similar to init_lapic() but keeps LINT0 masked because only the BSP
/// is connected to the 8259 PIC via LINT0. APs should not receive ExtINT.
///
/// # Safety
///
/// - Must be called from AP context (not BSP)
/// - LAPIC MMIO region must be accessible
pub unsafe fn init_lapic_for_ap() {
    // Enable LAPIC in hardware if not already
    if !lapic_hw_enabled() {
        lapic_hw_enable();
    }

    // Clear any existing errors
    lapic_write(lapic::ESR, 0);
    let _ = lapic_read(lapic::ESR);

    // Set Task Priority to accept all interrupts
    lapic_write(lapic::TPR, 0);

    // Set Destination Format Register to flat model
    lapic_write(lapic::DFR, 0xFFFF_FFFF);

    // Set Logical Destination Register
    lapic_write(lapic::LDR, 1 << 24);

    // Mask all LVT entries - APs should NOT have ExtINT on LINT0
    // Only the BSP is connected to the 8259 PIC
    lapic_write(lapic::LVT_TIMER, lvt_bits::MASKED);
    lapic_write(lapic::LVT_LINT0, lvt_bits::MASKED);
    lapic_write(lapic::LVT_LINT1, lvt_bits::MASKED);
    lapic_write(lapic::LVT_ERROR, lvt_bits::MASKED);
    lapic_write(lapic::LVT_PERF, lvt_bits::MASKED);
    lapic_write(lapic::LVT_THERMAL, lvt_bits::MASKED);

    // Set spurious interrupt vector and enable APIC
    lapic_write(lapic::SIVR, sivr_bits::APIC_ENABLED | 0xFF);

    // Clear any pending interrupts
    for i in 0..8 {
        let _ = lapic_read(lapic::ISR_BASE + i * 0x10);
    }

    // Send EOI
    lapic_eoi();

    // Start the LAPIC timer for this AP so it can receive scheduler ticks.
    // Without this, AP would never get timer interrupts (PIT IRQ0 only goes to BSP).
    start_lapic_timer();
}

/// Check if LAPIC is initialized
#[inline]
pub fn lapic_initialized() -> bool {
    LAPIC_INITIALIZED.load(Ordering::Acquire)
}

/// Get the BSP's LAPIC ID
#[inline]
pub fn bsp_lapic_id() -> u32 {
    BSP_LAPIC_ID.load(Ordering::Relaxed)
}

// ============================================================================
// IPI Operations
// ============================================================================

/// Wait for ICR delivery to complete
///
/// # Safety
///
/// LAPIC must be initialized.
unsafe fn wait_icr_idle() {
    // Bit 12 of ICR_LOW is the delivery status
    while lapic_read(lapic::ICR_LOW) & icr_flags::DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
    }
}

/// Send an IPI to a specific LAPIC ID
///
/// # Arguments
///
/// * `dest_lapic_id` - Destination LAPIC ID (for physical destination mode)
/// * `vector` - Interrupt vector (0-255)
/// * `delivery_mode` - Delivery mode (use icr_delivery constants)
///
/// # Safety
///
/// LAPIC must be initialized. The vector must be valid for the delivery mode.
pub unsafe fn send_ipi_raw(dest_lapic_id: u32, vector: u8, delivery_mode: u32) {
    wait_icr_idle();

    // Write destination to ICR high (bits 56-63 of physical APIC ID)
    lapic_write(lapic::ICR_HIGH, dest_lapic_id << 24);

    // Write vector, delivery mode, and edge trigger to ICR low
    // This triggers the IPI
    let icr_low = (vector as u32)
        | delivery_mode
        | icr_dest::NO_SHORTHAND
        | icr_flags::LEVEL_ASSERT
        | icr_flags::TRIGGER_EDGE;
    lapic_write(lapic::ICR_LOW, icr_low);
}

/// Send INIT IPI to a specific LAPIC
///
/// This is used to reset an AP to a known state before SIPI.
///
/// # Safety
///
/// Only valid during AP startup sequence.
pub unsafe fn send_init_ipi(dest_lapic_id: u32) {
    wait_icr_idle();

    lapic_write(lapic::ICR_HIGH, dest_lapic_id << 24);
    lapic_write(
        lapic::ICR_LOW,
        icr_delivery::INIT | icr_flags::LEVEL_ASSERT | icr_flags::TRIGGER_LEVEL,
    );

    // Wait for delivery
    wait_icr_idle();

    // Send INIT de-assert (level-triggered, de-assert)
    lapic_write(lapic::ICR_HIGH, dest_lapic_id << 24);
    lapic_write(
        lapic::ICR_LOW,
        icr_delivery::INIT | icr_flags::LEVEL_DEASSERT | icr_flags::TRIGGER_LEVEL,
    );
}

/// Send Startup IPI (SIPI) to a specific LAPIC
///
/// The vector field contains the page number (4K aligned) where the AP
/// will start executing (real mode, CS:IP = vector*0x100:0000).
///
/// # Arguments
///
/// * `dest_lapic_id` - Target AP's LAPIC ID
/// * `start_page` - 4K page number of AP trampoline code (e.g., 0x08 for 0x8000)
///
/// # Safety
///
/// Only valid during AP startup sequence after INIT IPI.
pub unsafe fn send_sipi(dest_lapic_id: u32, start_page: u8) {
    wait_icr_idle();

    lapic_write(lapic::ICR_HIGH, dest_lapic_id << 24);
    lapic_write(
        lapic::ICR_LOW,
        (start_page as u32) | icr_delivery::STARTUP | icr_flags::TRIGGER_EDGE,
    );
}

/// Broadcast an IPI to all CPUs except self
///
/// # Safety
///
/// LAPIC must be initialized.
pub unsafe fn broadcast_ipi_all_except_self(vector: u8) {
    wait_icr_idle();

    lapic_write(lapic::ICR_HIGH, 0);
    lapic_write(
        lapic::ICR_LOW,
        (vector as u32)
            | icr_delivery::FIXED
            | icr_dest::ALL_EXCLUDING_SELF
            | icr_flags::TRIGGER_EDGE,
    );
}

// ============================================================================
// I/O APIC Operations
// ============================================================================

/// Read an I/O APIC register
///
/// # Safety
///
/// I/O APIC must be mapped at the stored base address.
unsafe fn ioapic_read(reg: u8) -> u32 {
    let base = IOAPIC_BASE.load(Ordering::Relaxed) as u64;
    let regsel = base as *mut u32;
    let regdata = (base + IOAPIC_REGDATA as u64) as *const u32;

    write_volatile(regsel, reg as u32);
    read_volatile(regdata)
}

/// Write to an I/O APIC register
///
/// # Safety
///
/// I/O APIC must be mapped at the stored base address.
unsafe fn ioapic_write(reg: u8, value: u32) {
    let base = IOAPIC_BASE.load(Ordering::Relaxed) as u64;
    let regsel = base as *mut u32;
    let regdata = (base + IOAPIC_REGDATA as u64) as *mut u32;

    write_volatile(regsel, reg as u32);
    write_volatile(regdata, value);
}

/// Read an I/O APIC redirection entry (64-bit)
///
/// # Safety
///
/// I/O APIC must be initialized and irq must be valid (0-23).
pub unsafe fn ioapic_read_redir(irq: u8) -> u64 {
    let reg_low = ioapic::REDIR_TABLE_BASE + irq * 2;
    let reg_high = reg_low + 1;

    let low = ioapic_read(reg_low) as u64;
    let high = ioapic_read(reg_high) as u64;

    low | (high << 32)
}

/// Write an I/O APIC redirection entry (64-bit)
///
/// # Safety
///
/// I/O APIC must be initialized and irq must be valid (0-23).
pub unsafe fn ioapic_write_redir(irq: u8, entry: u64) {
    let reg_low = ioapic::REDIR_TABLE_BASE + irq * 2;
    let reg_high = reg_low + 1;

    // Must write high word first, then low word (to avoid race)
    ioapic_write(reg_high, (entry >> 32) as u32);
    ioapic_write(reg_low, entry as u32);
}

/// Get the number of I/O APIC redirection entries
///
/// # Safety
///
/// I/O APIC must be mapped.
pub unsafe fn ioapic_max_entries() -> u8 {
    let version = ioapic_read(ioapic::VERSION);
    // Bits 16-23 contain the maximum redirection entry number (0-based)
    ((version >> 16) & 0xFF) as u8 + 1
}

/// Initialize the I/O APIC
///
/// This masks all IRQs and prepares the I/O APIC for configuration.
/// Individual IRQs must be unmasked and routed after initialization.
///
/// # Safety
///
/// - I/O APIC MMIO region must be mapped
/// - Should be called after LAPIC initialization
pub unsafe fn init_ioapic() {
    if IOAPIC_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    let max_entries = ioapic_max_entries();

    // Mask all redirection entries
    for irq in 0..max_entries {
        let entry = redir_bits::MASKED;
        ioapic_write_redir(irq, entry);
    }

    IOAPIC_INITIALIZED.store(true, Ordering::Release);
}

/// Route an IRQ through the I/O APIC
///
/// # Arguments
///
/// * `irq` - IRQ number (0-23)
/// * `vector` - IDT vector to trigger (32-255 typically)
/// * `dest_lapic_id` - Destination LAPIC ID (physical mode)
/// * `level_triggered` - true for level-triggered, false for edge-triggered
/// * `active_low` - true for active-low polarity
///
/// # Safety
///
/// I/O APIC must be initialized. IRQ must be valid.
pub unsafe fn ioapic_route_irq(
    irq: u8,
    vector: u8,
    dest_lapic_id: u8,
    level_triggered: bool,
    active_low: bool,
) {
    let mut entry: u64 = vector as u64;
    entry |= redir_bits::DELIVERY_FIXED;
    entry |= redir_bits::DESTMODE_PHYSICAL;

    if level_triggered {
        entry |= redir_bits::TRIGGER_LEVEL;
    }
    if active_low {
        entry |= redir_bits::POLARITY_LOW;
    }

    entry |= (dest_lapic_id as u64) << redir_bits::DEST_SHIFT;

    ioapic_write_redir(irq, entry);
}

/// Mask an I/O APIC IRQ
pub unsafe fn ioapic_mask_irq(irq: u8) {
    let entry = ioapic_read_redir(irq);
    ioapic_write_redir(irq, entry | redir_bits::MASKED);
}

/// Unmask an I/O APIC IRQ
pub unsafe fn ioapic_unmask_irq(irq: u8) {
    let entry = ioapic_read_redir(irq);
    ioapic_write_redir(irq, entry & !redir_bits::MASKED);
}

/// Check if I/O APIC is initialized
#[inline]
pub fn ioapic_initialized() -> bool {
    IOAPIC_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Combined Initialization
// ============================================================================

/// Initialize the APIC subsystem (LAPIC + I/O APIC)
///
/// This should be called during early kernel boot after memory
/// management is set up but before enabling interrupts.
///
/// # Safety
///
/// - LAPIC and I/O APIC MMIO regions must be accessible
/// - Should be called only once, on BSP
pub unsafe fn init() {
    init_lapic();
    // I/O APIC init is optional for now - we still use 8259 PIC
    // init_ioapic();
}

/// Print APIC status information
pub fn print_status() {
    let lapic_init = lapic_initialized();
    let ioapic_init = ioapic_initialized();

    if lapic_init {
        let bsp_id = bsp_lapic_id();
        drivers::println!("  LAPIC: enabled (BSP ID: {})", bsp_id);
    } else {
        drivers::println!("  LAPIC: not initialized");
    }

    if ioapic_init {
        drivers::println!("  I/O APIC: enabled");
    } else {
        drivers::println!("  I/O APIC: not initialized (using 8259 PIC)");
    }
}
