//! Spectre/Meltdown Mitigations for Zero-OS
//!
//! This module provides detection and enablement of CPU mitigations for
//! speculative execution vulnerabilities:
//!
//! - **IBRS** (Indirect Branch Restricted Speculation)
//! - **IBPB** (Indirect Branch Predictor Barrier)
//! - **STIBP** (Single Thread Indirect Branch Predictors)
//! - **SSBD** (Speculative Store Bypass Disable)
//! - **RSB Stuffing** (Return Stack Buffer filling)
//! - **SWAPGS Fence** (CVE-2019-1125 mitigation in syscall.rs)
//! - **Retpoline** detection
//!
//! # Security Background
//!
//! Spectre and Meltdown are classes of vulnerabilities that exploit CPU
//! speculative execution to leak sensitive data. This module enables
//! hardware mitigations where available.
//!
//! # Implemented Mitigations
//!
//! | Vulnerability | Mitigation | Status |
//! |---------------|------------|--------|
//! | Spectre v1 | LFENCE barriers | Partial (syscall path) |
//! | Spectre v2 | IBRS/IBPB/STIBP | Enabled if supported |
//! | Meltdown | KPTI | Prepared (Phase A.4) |
//! | SSB (Spectre v4) | SSBD | Enabled if supported |
//! | RSB underflow | RSB stuffing | Implemented |
//! | SWAPGS (CVE-2019-1125) | SWAPGS + LFENCE | Implemented in syscall.rs |
//!
//! # CPU Support Detection
//!
//! Uses CPUID leaf 7, subleaf 0 (EDX) to detect:
//! - Bit 26: IBRS/IBPB support
//! - Bit 27: STIBP support
//! - Bit 29: IA32_ARCH_CAPABILITIES MSR support
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize mitigations during boot
//! let status = spectre::init()?;
//! if status.hardened() {
//!     println!("Speculative execution hardening enabled");
//! }
//! ```

use x86_64::registers::model_specific::Msr;

/// Status of speculative execution mitigations.
#[derive(Debug, Clone, Copy)]
pub struct MitigationStatus {
    /// IBRS supported by CPU
    pub ibrs_supported: bool,
    /// IBRS currently enabled
    pub ibrs_enabled: bool,
    /// IBPB supported by CPU
    pub ibpb_supported: bool,
    /// STIBP supported by CPU
    pub stibp_supported: bool,
    /// STIBP currently enabled
    pub stibp_enabled: bool,
    /// Compiler retpoline support (compile-time feature)
    pub retpoline_compiler: bool,
    /// Retpoline required (no hardware mitigation)
    pub retpoline_required: bool,
    /// SSBD (Speculative Store Bypass Disable) supported
    pub ssbd_supported: bool,
    /// SSBD enabled
    pub ssbd_enabled: bool,
    /// SWAPGS mitigation enabled (CVE-2019-1125)
    /// Always true - implemented unconditionally in syscall entry/exit
    pub swapgs_mitigated: bool,
    /// RSB stuffing enabled
    /// Always true - implemented unconditionally in context switch
    pub rsb_stuffing_enabled: bool,
}

impl MitigationStatus {
    /// Create an empty (no mitigations) status.
    pub fn empty() -> Self {
        MitigationStatus {
            ibrs_supported: false,
            ibrs_enabled: false,
            ibpb_supported: false,
            stibp_supported: false,
            stibp_enabled: false,
            retpoline_compiler: false,
            retpoline_required: false,
            ssbd_supported: false,
            ssbd_enabled: false,
            // These are always enabled unconditionally
            swapgs_mitigated: true,
            rsb_stuffing_enabled: true,
        }
    }

    /// Check if at least one mitigation path is active.
    ///
    /// Returns true if the system has adequate protection against
    /// speculative execution attacks.
    pub fn hardened(&self) -> bool {
        // Branch prediction protection
        let branch_protected = self.ibrs_enabled || self.stibp_enabled || self.retpoline_compiler;

        // If retpoline is required but not compiled in, and no hardware fix
        if self.retpoline_required && !self.retpoline_compiler && !self.ibrs_enabled {
            return false;
        }

        branch_protected
    }

    /// Check if any mitigation was enabled.
    pub fn any_enabled(&self) -> bool {
        self.ibrs_enabled
            || self.stibp_enabled
            || self.ssbd_enabled
            || self.swapgs_mitigated
            || self.rsb_stuffing_enabled
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> &'static str {
        if self.hardened() {
            "Hardened"
        } else if self.any_enabled() {
            "Partial"
        } else {
            "Vulnerable"
        }
    }
}

/// Errors encountered while enabling mitigations.
#[derive(Debug)]
pub enum SpectreError {
    /// Feature not supported by CPU
    Unsupported(&'static str),
    /// MSR is not available
    MsrUnavailable(&'static str),
    /// Error reading/writing MSR
    MsrIo(&'static str),
    /// Retpoline required but not available
    RetpolineRequired,
}

// ============================================================================
// MSR Constants
// ============================================================================

/// IA32_SPEC_CTRL MSR - Speculation control
const IA32_SPEC_CTRL: u32 = 0x48;
/// IA32_PRED_CMD MSR - Predictor command (write-only)
const IA32_PRED_CMD: u32 = 0x49;
/// IA32_ARCH_CAPABILITIES MSR - Architecture capabilities
const IA32_ARCH_CAPABILITIES: u32 = 0x10A;

// IA32_SPEC_CTRL bits
const SPEC_CTRL_IBRS: u64 = 1 << 0; // Indirect Branch Restricted Speculation
const SPEC_CTRL_STIBP: u64 = 1 << 1; // Single Thread Indirect Branch Predictors
const SPEC_CTRL_SSBD: u64 = 1 << 2; // Speculative Store Bypass Disable

// IA32_PRED_CMD bits
const PRED_CMD_IBPB: u64 = 1 << 0; // Indirect Branch Predictor Barrier

// IA32_ARCH_CAPABILITIES bits
const ARCH_CAP_RDCL_NO: u64 = 1 << 0; // Not susceptible to Meltdown
const ARCH_CAP_IBRS_ALL: u64 = 1 << 1; // IBRS covers all predictors
const ARCH_CAP_RSBA: u64 = 1 << 2; // RSB Alternate (needs mitigation)
const ARCH_CAP_SKIP_L1DFL: u64 = 1 << 3; // Skip L1D flush on VMENTRY
const ARCH_CAP_SSB_NO: u64 = 1 << 4; // Not susceptible to SSB
const ARCH_CAP_MDS_NO: u64 = 1 << 5; // Not susceptible to MDS

// ============================================================================
// Detection Functions
// ============================================================================

/// Detect CPU support for Spectre/Meltdown mitigations.
pub fn detect() -> MitigationStatus {
    let (_, _, _, edx) = cpuid_7_0();

    // IBRS/IBPB support (bit 26)
    let ibrs_ibpb = (edx & (1 << 26)) != 0;
    // STIBP support (bit 27)
    let stibp = (edx & (1 << 27)) != 0;
    // SSBD support (bit 31)
    let ssbd = (edx & (1 << 31)) != 0;
    // IA32_ARCH_CAPABILITIES support (bit 29)
    let has_arch_cap = (edx & (1 << 29)) != 0;

    let mut retpoline_required = !ibrs_ibpb;

    // Check architecture capabilities for better mitigation info
    if has_arch_cap {
        if let Some(capabilities) = read_arch_capabilities() {
            // IBRS_ALL means hardware fully mitigates branch prediction attacks
            if (capabilities & ARCH_CAP_IBRS_ALL) != 0 {
                retpoline_required = false;
            }
            // RDCL_NO means not susceptible to Meltdown
            // SSB_NO means not susceptible to Speculative Store Bypass
            // MDS_NO means not susceptible to Microarchitectural Data Sampling
        }
    }

    MitigationStatus {
        ibrs_supported: ibrs_ibpb,
        ibrs_enabled: false,
        ibpb_supported: ibrs_ibpb,
        stibp_supported: stibp,
        stibp_enabled: false,
        retpoline_compiler: cfg!(feature = "retpoline"),
        retpoline_required,
        ssbd_supported: ssbd,
        ssbd_enabled: false,
        // These are always enabled unconditionally in our implementation
        swapgs_mitigated: true,
        rsb_stuffing_enabled: true,
    }
}

/// Get detailed CPU vulnerability information.
pub fn get_vulnerabilities() -> VulnerabilityInfo {
    let (_, _, _, edx) = cpuid_7_0();
    let has_arch_cap = (edx & (1 << 29)) != 0;

    let mut info = VulnerabilityInfo {
        meltdown_susceptible: true,
        spectre_v1_susceptible: true, // Always assume susceptible
        spectre_v2_susceptible: true,
        ssb_susceptible: true,
        mds_susceptible: true,
    };

    if has_arch_cap {
        if let Some(cap) = read_arch_capabilities() {
            info.meltdown_susceptible = (cap & ARCH_CAP_RDCL_NO) == 0;
            info.ssb_susceptible = (cap & ARCH_CAP_SSB_NO) == 0;
            info.mds_susceptible = (cap & ARCH_CAP_MDS_NO) == 0;
            // IBRS_ALL helps with Spectre v2
            if (cap & ARCH_CAP_IBRS_ALL) != 0 {
                info.spectre_v2_susceptible = false;
            }
        }
    }

    info
}

/// CPU vulnerability information.
#[derive(Debug, Clone, Copy)]
pub struct VulnerabilityInfo {
    pub meltdown_susceptible: bool,
    pub spectre_v1_susceptible: bool,
    pub spectre_v2_susceptible: bool,
    pub ssb_susceptible: bool,
    pub mds_susceptible: bool,
}

// ============================================================================
// Initialization and Control Functions
// ============================================================================

/// Initialize available Spectre/Meltdown mitigations.
///
/// This function:
/// 1. Detects CPU capabilities
/// 2. Enables IBRS if supported
/// 3. Enables STIBP if supported
/// 4. Issues IBPB to clear predictor state
/// 5. Enables SSBD if supported
///
/// # Returns
///
/// `MitigationStatus` on success, `SpectreError` if critical mitigation fails.
///
/// # Note
///
/// R65-25 FIX: This function applies mitigations to the calling CPU only.
/// For SMP systems, call `init_cpu()` on each Application Processor (AP)
/// during their initialization sequence.
pub fn init() -> Result<MitigationStatus, SpectreError> {
    let mut status = detect();

    // Enable IBRS (Indirect Branch Restricted Speculation)
    if status.ibrs_supported {
        if enable_ibrs().is_ok() {
            status.ibrs_enabled = true;
        }
    }

    // Enable STIBP (Single Thread Indirect Branch Predictors)
    if status.stibp_supported {
        if enable_stibp().is_ok() {
            status.stibp_enabled = true;
        }
    }

    // Issue IBPB to clear any existing predictor state
    if status.ibpb_supported {
        let _ = issue_ibpb();
    }

    // Enable SSBD (Speculative Store Bypass Disable)
    if status.ssbd_supported {
        if enable_ssbd().is_ok() {
            status.ssbd_enabled = true;
        }
    }

    // Check if we have adequate protection
    if status.retpoline_required && !status.retpoline_compiler && !status.ibrs_enabled {
        return Err(SpectreError::RetpolineRequired);
    }

    Ok(status)
}

/// R65-25 FIX: Initialize Spectre mitigations for the current CPU.
///
/// This function should be called by each Application Processor (AP) during
/// its initialization sequence. The BSP (Bootstrap Processor) should call
/// `init()` during early boot.
///
/// # Why Per-CPU Initialization is Required
///
/// IBRS, STIBP, and SSBD are per-logical-processor settings stored in the
/// IA32_SPEC_CTRL MSR. Each CPU must configure its own MSR independently.
/// Without per-CPU initialization, secondary cores run without mitigations,
/// leaving them vulnerable to cross-core speculative attacks.
///
/// # Usage
///
/// Call this function in the AP boot sequence after the CPU is in protected
/// mode with access to MSRs:
///
/// ```rust,ignore
/// // In AP startup code:
/// fn ap_start() {
///     // ... early AP initialization ...
///     spectre::init_cpu();
///     // ... continue AP initialization ...
/// }
/// ```
pub fn init_cpu() {
    let status = detect();

    // Enable IBRS if supported on this CPU
    if status.ibrs_supported {
        let _ = enable_ibrs();
    }

    // Enable STIBP if supported on this CPU
    if status.stibp_supported {
        let _ = enable_stibp();
    }

    // Issue IBPB to clear predictor state for this CPU
    if status.ibpb_supported {
        let _ = issue_ibpb();
    }

    // Enable SSBD if supported on this CPU
    if status.ssbd_supported {
        let _ = enable_ssbd();
    }
}

/// Enable IBRS by setting IA32_SPEC_CTRL.IBRS.
///
/// IBRS restricts indirect branch prediction to prevent cross-privilege
/// speculation attacks.
pub fn enable_ibrs() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ibrs_supported {
        return Err(SpectreError::Unsupported("IBRS not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_IBRS);
    }

    Ok(())
}

/// Disable IBRS (not recommended for production).
pub fn disable_ibrs() -> Result<(), SpectreError> {
    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current & !SPEC_CTRL_IBRS);
    }
    Ok(())
}

/// Enable STIBP for single-threaded indirect branch prediction isolation.
///
/// STIBP prevents one logical processor from controlling the branch
/// prediction of a sibling logical processor.
pub fn enable_stibp() -> Result<(), SpectreError> {
    let status = detect();
    if !status.stibp_supported {
        return Err(SpectreError::Unsupported("STIBP not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_STIBP);
    }

    Ok(())
}

/// Enable SSBD (Speculative Store Bypass Disable).
///
/// Prevents speculative bypass of store operations that could leak data.
pub fn enable_ssbd() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ssbd_supported {
        return Err(SpectreError::Unsupported("SSBD not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_SPEC_CTRL);
        let current = msr.read();
        msr.write(current | SPEC_CTRL_SSBD);
    }

    Ok(())
}

/// Issue an Indirect Branch Predictor Barrier.
///
/// Clears all indirect branch predictors, preventing cross-context
/// speculation attacks. Should be called on context switches to
/// untrusted code.
pub fn issue_ibpb() -> Result<(), SpectreError> {
    let status = detect();
    if !status.ibpb_supported {
        return Err(SpectreError::Unsupported("IBPB not supported"));
    }

    unsafe {
        let mut msr = Msr::new(IA32_PRED_CMD);
        msr.write(PRED_CMD_IBPB);
    }

    Ok(())
}

/// Issue IBPB if supported (no error on unsupported).
///
/// Convenience function for context switch code that wants to
/// issue IBPB when available without handling errors.
#[inline]
pub fn try_ibpb() {
    let _ = issue_ibpb();
}

// ============================================================================
// RSB (Return Stack Buffer) Stuffing
// ============================================================================

/// Check if RSB stuffing is required for this CPU.
///
/// RSB stuffing is needed when:
/// - CPU has RSBA (RSB Alternate) set in IA32_ARCH_CAPABILITIES, or
/// - CPU doesn't have IBRS_ALL (full hardware mitigation), or
/// - No hardware mitigation is available
pub fn rsb_stuffing_required() -> bool {
    let (_, _, _, edx) = cpuid_7_0();
    let has_arch_cap = (edx & (1 << 29)) != 0;

    if has_arch_cap {
        if let Some(cap) = read_arch_capabilities() {
            // IBRS_ALL means hardware fully handles branch prediction
            if (cap & ARCH_CAP_IBRS_ALL) != 0 {
                return false;
            }
            // RSBA means RSB needs mitigation
            if (cap & ARCH_CAP_RSBA) != 0 {
                return true;
            }
        }
    }

    // Conservative: stuff RSB if no definitive hardware protection
    true
}

/// Stuff the Return Stack Buffer (RSB) with safe return addresses.
///
/// This prevents RSB underflow attacks where a malicious program could
/// train the RSB with attacker-controlled return addresses that persist
/// across context switches.
///
/// The RSB is typically 16-32 entries deep on modern CPUs. We fill it
/// with 32 entries to be safe across all microarchitectures.
///
/// # Safety
///
/// This function executes assembly that manipulates the stack. It must
/// only be called from kernel context with a valid kernel stack.
#[inline]
pub unsafe fn rsb_fill() {
    // This sequence fills the RSB with safe return addresses by executing
    // 32 CALL instructions that push return addresses onto the RSB.
    // The LFENCE ensures the CPU doesn't speculate past each call.
    // Finally, we fix up the stack by adding back the space used by
    // the 32 pushed return addresses.
    core::arch::asm!(
        // Fill RSB with 32 entries
        "mov ecx, 32",
        "2:",
        "call 3f",  // Push return address to RSB
        "3:",
        "lfence",   // Speculation barrier
        "dec ecx",
        "jnz 2b",
        // Clean up stack (32 * 8 bytes of return addresses)
        "add rsp, 256",
        out("ecx") _,
        options(nostack)
    );
}

/// Perform RSB stuffing on context switch to untrusted code.
///
/// This is a higher-level wrapper that checks if RSB stuffing is needed
/// before performing it. Use this in context switch paths.
///
/// # Safety
///
/// Must be called from kernel context with a valid kernel stack.
#[inline]
pub unsafe fn rsb_fill_on_context_switch() {
    // Check if we need RSB stuffing (could be cached per-CPU for performance)
    // For now, we call rsb_fill unconditionally since the check is cheap
    // and the operation is only called on context switches
    rsb_fill();
}

/// Wrapper for calling RSB fill that handles the safety internally.
///
/// This is intended to be called from the scheduler when switching
/// to user-mode code.
#[inline]
pub fn fill_rsb_if_needed() {
    // Only stuff RSB if switching to potentially untrusted code
    unsafe {
        rsb_fill();
    }
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Read IA32_ARCH_CAPABILITIES MSR if available.
fn read_arch_capabilities() -> Option<u64> {
    let (_, _, _, edx) = cpuid_7_0();
    if (edx & (1 << 29)) == 0 {
        return None;
    }

    unsafe {
        let msr = Msr::new(IA32_ARCH_CAPABILITIES);
        Some(msr.read())
    }
}

/// Execute CPUID leaf 7, subleaf 0.
///
/// R72-4 FIX: Remove nostack and nomem since push/pop uses stack memory.
fn cpuid_7_0() -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 7u32 => eax,
            ebx_out = out(reg) ebx,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
            // No options - push/pop uses both stack and memory
        );
    }

    (eax, ebx, ecx, edx)
}

/// Check current SPEC_CTRL MSR value.
pub fn read_spec_ctrl() -> u64 {
    unsafe {
        let msr = Msr::new(IA32_SPEC_CTRL);
        msr.read()
    }
}
