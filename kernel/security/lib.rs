//! Security Hardening Module for Zero-OS
//!
//! This module provides enterprise-grade security hardening features:
//!
//! - **W^X Enforcement**: Validates that no memory pages are both writable and executable
//! - **Identity Map Cleanup**: Removes or hardens the bootloader's identity mapping
//! - **NX Enforcement**: Ensures data pages have the No-Execute bit set
//! - **Hardware RNG**: RDRAND/RDSEED integration with CSPRNG (ChaCha20)
//! - **kptr Guard**: Obfuscates kernel pointers before logging to prevent KASLR bypass
//! - **Spectre/Meltdown Mitigations**: IBRS/IBPB/STIBP initialization
//! - **Runtime Security Tests**: Lightweight self-tests for core protections
//!
//! # Security Design Principles
//!
//! 1. **Defense in Depth**: Multiple layers of protection
//! 2. **Fail-Secure**: Errors result in more restrictive states
//! 3. **Least Privilege**: Minimal permissions by default
//! 4. **Audit Trail**: All security events are logged
//!
//! # Usage
//!
//! ```rust,ignore
//! let config = SecurityConfig::default();
//! let mut allocator = FrameAllocator::new();
//! let report = security::init(config, &mut allocator)?;
//! ```

#![no_std]
#![feature(abi_x86_interrupt)]

extern crate alloc;

#[macro_use]
extern crate drivers;

pub mod kaslr;
pub mod kptr;
pub mod memory_hardening;
pub mod rng;
pub mod spectre;
pub mod tests;
pub mod wxorx;

use mm::memory::FrameAllocator;
use x86_64::VirtAddr;

// Re-export public types
pub use kaslr::{
    enable_partial_kaslr, get_kernel_layout, init as init_kaslr, is_kaslr_enabled,
    is_kpti_enabled, is_partial_kaslr_enabled, partial_kaslr_status, KernelLayout, KptiContext,
    PartialKaslrFeature, PartialKaslrStatus, TrampolineDesc, KERNEL_PHYS_BASE, KERNEL_VIRT_BASE,
};
pub use kptr::KptrGuard;
pub use memory_hardening::{
    CleanupOutcome, HardeningError, IdentityCleanupStrategy, NxEnforcementSummary,
};
pub use rng::{fill_random, random_u32, random_u64, rdrand64_early, rdrand_available, try_fill_random, ChaCha20Rng, RngError};
pub use spectre::{MitigationStatus, SpectreError, VulnerabilityInfo};
pub use tests::{run_security_tests, SecurityTest, TestContext, TestReport, TestResult};
pub use wxorx::{PageLevel, ValidationSummary, Violation, WxorxError};

/// Security subsystem error types
#[derive(Debug)]
pub enum SecurityError {
    /// Memory hardening error (identity map, NX enforcement)
    Memory(HardeningError),
    /// W^X validation error
    Wxorx(WxorxError),
    /// Random number generator error
    Rng(RngError),
    /// Spectre/Meltdown mitigation error
    Spectre(SpectreError),
}

impl From<HardeningError> for SecurityError {
    fn from(err: HardeningError) -> Self {
        SecurityError::Memory(err)
    }
}

impl From<WxorxError> for SecurityError {
    fn from(err: WxorxError) -> Self {
        SecurityError::Wxorx(err)
    }
}

impl From<RngError> for SecurityError {
    fn from(err: RngError) -> Self {
        SecurityError::Rng(err)
    }
}

impl From<SpectreError> for SecurityError {
    fn from(err: SpectreError) -> Self {
        SecurityError::Spectre(err)
    }
}

/// Security hardening configuration
#[derive(Debug, Clone, Copy)]
pub struct SecurityConfig {
    /// Physical memory offset for page table access
    pub phys_offset: VirtAddr,
    /// Strategy for cleaning up identity mapping
    pub cleanup_strategy: IdentityCleanupStrategy,
    /// Whether to enforce NX bit on data pages
    pub enforce_nx: bool,
    /// Whether to validate W^X policy
    pub validate_wxorx: bool,
    /// Whether to initialize hardware RNG and CSPRNG
    pub initialize_rng: bool,
    /// Whether to panic on W^X violation (strict mode)
    pub strict_wxorx: bool,
    /// Whether to enable kernel pointer obfuscation
    pub enable_kptr_guard: bool,
    /// Whether to enable Spectre/Meltdown mitigations
    pub enable_spectre_mitigations: bool,
    /// Whether to run security self-tests
    pub run_security_tests: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            phys_offset: VirtAddr::new(mm::page_table::PHYSICAL_MEMORY_OFFSET),
            cleanup_strategy: IdentityCleanupStrategy::RemoveWritable,
            enforce_nx: true,
            validate_wxorx: true,
            initialize_rng: true,
            strict_wxorx: false, // Don't panic by default, just warn
            enable_kptr_guard: true,
            enable_spectre_mitigations: true,
            run_security_tests: false, // Disable by default, enable in strict mode
        }
    }
}

impl SecurityConfig {
    /// Create a strict security configuration (production recommended)
    pub fn strict() -> Self {
        SecurityConfig {
            strict_wxorx: true,
            run_security_tests: true,
            ..Self::default()
        }
    }

    /// Create a permissive configuration (for debugging)
    pub fn permissive() -> Self {
        SecurityConfig {
            enforce_nx: false,
            validate_wxorx: false,
            strict_wxorx: false,
            enable_kptr_guard: false,
            enable_spectre_mitigations: false,
            run_security_tests: false,
            ..Self::default()
        }
    }
}

/// Security hardening report
#[derive(Debug)]
pub struct SecurityReport {
    /// Identity map cleanup outcome
    pub identity_cleanup: CleanupOutcome,
    /// NX enforcement summary (if enabled)
    pub nx_summary: Option<NxEnforcementSummary>,
    /// W^X validation summary (if enabled)
    pub wxorx_summary: Option<ValidationSummary>,
    /// Whether CSPRNG is ready
    pub rng_ready: bool,
    /// Whether kptr guard is active
    pub kptr_guard_active: bool,
    /// Spectre/Meltdown mitigation status
    pub spectre_status: Option<MitigationStatus>,
    /// Security test report (if tests were run)
    pub test_report: Option<TestReport>,
    /// Total security violations detected (0 = secure)
    pub total_violations: usize,
}

impl SecurityReport {
    /// Create an empty report
    fn empty() -> Self {
        SecurityReport {
            identity_cleanup: CleanupOutcome::Skipped,
            nx_summary: None,
            wxorx_summary: None,
            rng_ready: false,
            kptr_guard_active: false,
            spectre_status: None,
            test_report: None,
            total_violations: 0,
        }
    }

    /// Check if the system is in a secure state
    pub fn is_secure(&self) -> bool {
        let tests_ok = self
            .test_report
            .as_ref()
            .map(|t| t.failed == 0)
            .unwrap_or(true);
        self.total_violations == 0 && self.rng_ready && tests_ok
    }

    /// Print the security report to console
    pub fn print(&self) {
        println!("=== Security Hardening Report ===");
        println!("Identity Map: {:?}", self.identity_cleanup);

        if let Some(ref nx) = self.nx_summary {
            println!("NX Enforcement:");
            println!("  Text (R-X): {} pages", nx.text_rx_pages);
            println!("  RoData (R--): {} pages", nx.ro_pages);
            println!("  Data (RW-): {} pages", nx.data_nx_pages);
        }

        if let Some(ref wx) = self.wxorx_summary {
            println!("W^X Validation:");
            println!("  Scanned: {} entries", wx.scanned_entries);
            println!("  Violations: {}", wx.violations);
        }

        println!(
            "CSPRNG: {}",
            if self.rng_ready { "Ready" } else { "Not Ready" }
        );
        println!(
            "kptr Guard: {}",
            if self.kptr_guard_active {
                "Active"
            } else {
                "Disabled"
            }
        );

        if let Some(ref spectre) = self.spectre_status {
            println!("Spectre/Meltdown Mitigations:");
            println!(
                "  IBRS: {} (supported: {})",
                if spectre.ibrs_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                spectre.ibrs_supported
            );
            println!(
                "  STIBP: {} (supported: {})",
                if spectre.stibp_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                spectre.stibp_supported
            );
            println!("  IBPB: supported: {}", spectre.ibpb_supported);
            println!("  Status: {}", spectre.summary());
        }

        if let Some(ref tests) = self.test_report {
            println!("Security Self-Tests:");
            println!(
                "  Passed: {}, Failed: {}, Warnings: {}",
                tests.passed, tests.failed, tests.warnings
            );
        }

        println!("Total Violations: {}", self.total_violations);
        println!(
            "Overall Status: {}",
            if self.is_secure() {
                "SECURE"
            } else {
                "WARNINGS"
            }
        );
    }
}

/// Initialize the security subsystem
///
/// This function performs the following hardening steps:
/// 1. Initialize kptr guard for pointer obfuscation
/// 2. Clean up or harden the identity mapping
/// 3. Enforce NX bit on data pages (if enabled)
/// 4. Validate W^X policy (if enabled)
/// 5. Initialize hardware RNG and CSPRNG (if enabled)
/// 6. Enable Spectre/Meltdown mitigations (if enabled)
/// 7. Run security self-tests (optional)
///
/// # Arguments
///
/// * `config` - Security configuration
/// * `frame_allocator` - Physical frame allocator for page table modifications
///
/// # Returns
///
/// A security report on success, or an error if critical hardening fails.
///
/// # Security Note
///
/// This function should be called early in kernel initialization,
/// after memory management but before enabling interrupts.
pub fn init(
    config: SecurityConfig,
    frame_allocator: &mut FrameAllocator,
) -> Result<SecurityReport, SecurityError> {
    let mut report = SecurityReport::empty();

    println!("  Initializing security hardening...");

    // Step 1: Initialize kptr guard (early, to protect all subsequent logs)
    if config.enable_kptr_guard {
        println!("    [1/7] Enabling kptr guard...");
        kptr::init();
        kptr::enable();
        report.kptr_guard_active = true;
    } else {
        println!("    [1/7] kptr guard: SKIPPED (disabled)");
        kptr::disable();
    }

    // Step 2: Clean up identity mapping
    println!(
        "    [2/7] Cleaning identity map ({:?})...",
        config.cleanup_strategy
    );
    let cleanup =
        memory_hardening::cleanup_identity_map(config.phys_offset, config.cleanup_strategy)?;
    report.identity_cleanup = cleanup;

    // Step 3: Enforce NX on kernel data sections
    if config.enforce_nx {
        println!("    [3/7] Enforcing NX bit on data pages...");
        let nx_summary =
            memory_hardening::enforce_nx_for_kernel(config.phys_offset, frame_allocator)?;
        report.nx_summary = Some(nx_summary);
    } else {
        println!("    [3/7] NX enforcement: SKIPPED (disabled)");
    }

    // Step 4: Validate W^X policy
    if config.validate_wxorx {
        println!("    [4/7] Validating W^X policy...");
        match wxorx::validate_active(config.phys_offset) {
            Ok(summary) => {
                report.wxorx_summary = Some(summary);
                report.total_violations += summary.violations;

                if summary.violations > 0 {
                    println!(
                        "      WARNING: {} W^X violation(s) detected",
                        summary.violations
                    );
                    if config.strict_wxorx {
                        return Err(SecurityError::Wxorx(WxorxError::PolicyViolation(
                            summary.violations,
                        )));
                    }
                }
            }
            Err(WxorxError::Violation(v)) => {
                println!("      WARNING: W^X violation at {:?}", v.virt_base);
                report.total_violations += 1;
                report.wxorx_summary = Some(ValidationSummary {
                    scanned_entries: 0,
                    violations: 1,
                });

                if config.strict_wxorx {
                    return Err(SecurityError::Wxorx(WxorxError::Violation(v)));
                }
            }
            Err(e) => {
                println!("      WARNING: W^X validation error: {:?}", e);
                if config.strict_wxorx {
                    return Err(SecurityError::Wxorx(e));
                }
            }
        }
    } else {
        println!("    [4/7] W^X validation: SKIPPED (disabled)");
    }

    // Step 5: Initialize hardware RNG and CSPRNG
    if config.initialize_rng {
        println!("    [5/7] Initializing hardware RNG and CSPRNG...");
        match rng::init_global() {
            Ok(()) => {
                report.rng_ready = true;

                // Verify RNG is working with a test read
                match random_u64() {
                    Ok(_) => {
                        println!("      CSPRNG verified operational");
                        // Reseed kptr guard with strong entropy
                        if config.enable_kptr_guard {
                            kptr::reseed_from_entropy();
                        }
                    }
                    Err(e) => {
                        println!("      WARNING: CSPRNG verification failed: {:?}", e);
                        report.rng_ready = false;
                    }
                }
            }
            Err(e) => {
                println!("      WARNING: RNG initialization failed: {:?}", e);
                report.rng_ready = false;
            }
        }
    } else {
        println!("    [5/7] RNG initialization: SKIPPED (disabled)");
    }

    // Step 6: Enable Spectre/Meltdown mitigations
    if config.enable_spectre_mitigations {
        println!("    [6/7] Enabling Spectre/Meltdown mitigations...");
        match spectre::init() {
            Ok(status) => {
                println!("      Mitigations: {}", status.summary());
                if status.retpoline_required && !status.retpoline_compiler && !status.ibrs_enabled {
                    println!("      WARNING: Retpoline required but not available");
                    report.total_violations += 1;
                }
                report.spectre_status = Some(status);
            }
            Err(e) => {
                println!("      WARNING: Spectre mitigations failed: {:?}", e);
                // Don't increment violations for unsupported CPUs
                if !matches!(e, SpectreError::Unsupported(_)) {
                    report.total_violations += 1;
                }
            }
        }
    } else {
        println!("    [6/7] Spectre mitigations: SKIPPED (disabled)");
    }

    // Step 7: Run security self-tests (optional)
    if config.run_security_tests {
        println!("    [7/7] Running security self-tests...");
        let ctx = TestContext {
            phys_offset: config.phys_offset,
        };
        let test_report = tests::run_security_tests(&ctx);

        if test_report.failed > 0 {
            println!(
                "      WARNING: {} security tests failed",
                test_report.failed
            );
            report.total_violations += test_report.failed;
        } else {
            println!("      All {} tests passed", test_report.passed);
        }

        report.test_report = Some(test_report);
    } else {
        println!("    [7/7] Security self-tests: SKIPPED (disabled)");
    }

    Ok(report)
}

/// Quick security check (for runtime validation)
///
/// This function performs a lightweight W^X check on the current page tables.
/// It can be called periodically to detect runtime violations.
pub fn quick_check(phys_offset: VirtAddr) -> Result<bool, SecurityError> {
    match wxorx::validate_active(phys_offset) {
        Ok(summary) => Ok(summary.violations == 0),
        Err(e) => Err(SecurityError::Wxorx(e)),
    }
}
