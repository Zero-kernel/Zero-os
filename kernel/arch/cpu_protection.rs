//! CPU hardening: SMEP / SMAP / UMIP detection and enablement
//!
//! These features provide hardware-enforced protection against common kernel exploits:
//!
//! - **SMEP** (CR4.SMEP, CPUID.07H:EBX[7]): Blocks kernel executing user pages
//! - **SMAP** (CR4.SMAP, CPUID.07H:EBX[20]): Blocks kernel accessing user pages unless STAC
//! - **UMIP** (CR4.UMIP, CPUID.07H:ECX[2]): Blocks usermode SGDT/SIDT/SLDT/SMSW/STR
//!
//! # Usage
//!
//! ```rust,ignore
//! let status = cpu_protection::enable_protections();
//! if !status.smep_enabled || !status.smap_enabled {
//!     kprintln!("WARNING: CPU lacks full protection");
//! }
//! ```
//!
//! # Note on SMAP
//!
//! When SMAP is enabled, intentional kernel access to user pages must be wrapped
//! with STAC (Set AC flag) and CLAC (Clear AC flag) instructions.

use x86_64::registers::control::{Cr4, Cr4Flags};

/// Detected and enabled status for CPU protection features
#[derive(Debug, Clone, Copy)]
pub struct CpuProtectionStatus {
    /// SMEP (Supervisor Mode Execution Prevention) supported by CPU
    pub smep_supported: bool,
    /// SMAP (Supervisor Mode Access Prevention) supported by CPU
    pub smap_supported: bool,
    /// UMIP (User Mode Instruction Prevention) supported by CPU
    pub umip_supported: bool,
    /// SMEP currently enabled in CR4
    pub smep_enabled: bool,
    /// SMAP currently enabled in CR4
    pub smap_enabled: bool,
    /// UMIP currently enabled in CR4
    pub umip_enabled: bool,
}

impl CpuProtectionStatus {
    /// Check if all protections are fully enabled
    pub fn is_fully_protected(&self) -> bool {
        self.smep_enabled && self.smap_enabled && self.umip_enabled
    }

    /// Print status summary
    pub fn print(&self) {
        kprintln!("CPU Protection Status:");
        kprintln!(
            "  SMEP: supported={}, enabled={}",
            self.smep_supported, self.smep_enabled
        );
        kprintln!(
            "  SMAP: supported={}, enabled={}",
            self.smap_supported, self.smap_enabled
        );
        kprintln!(
            "  UMIP: supported={}, enabled={}",
            self.umip_supported, self.umip_enabled
        );
    }
}

/// Detect CPU feature bits and current CR4 state
pub fn check_cpu_features() -> CpuProtectionStatus {
    let (_eax, ebx, ecx, _edx) = cpuid_leaf_7();

    // CPUID.07H:EBX[7] = SMEP
    let smep_supported = (ebx & (1 << 7)) != 0;
    // CPUID.07H:EBX[20] = SMAP
    let smap_supported = (ebx & (1 << 20)) != 0;
    // CPUID.07H:ECX[2] = UMIP
    let umip_supported = (ecx & (1 << 2)) != 0;

    let cr4 = Cr4::read();

    CpuProtectionStatus {
        smep_supported,
        smap_supported,
        umip_supported,
        smep_enabled: cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION),
        smap_enabled: cr4.contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION),
        umip_enabled: cr4.contains(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION),
    }
}

/// Enable supported protections and return resulting status
///
/// This function enables all supported CPU protection features by setting
/// the appropriate bits in CR4. It will not enable features that the CPU
/// does not support.
///
/// # Enable Order (I-1 fix)
///
/// Features are enabled in this order to minimize risk:
/// 1. UMIP - No kernel code dependencies, safe to enable first
/// 2. SMEP - Blocks kernel executing user pages, independent
/// 3. SMAP - Enabled last because kernel must already have STAC/CLAC
///           wrappers (UserAccessGuard) in place before SMAP is active
///
/// # Returns
///
/// The final protection status after enabling supported features.
///
/// # Safety Note
///
/// After enabling SMAP, any kernel code that intentionally accesses user
/// memory must use STAC/CLAC to temporarily disable the protection.
pub fn enable_protections() -> CpuProtectionStatus {
    let status = check_cpu_features();
    let mut cr4 = Cr4::read();
    let original_cr4 = cr4;

    // I-1 fix: Enable UMIP first (no kernel code dependencies)
    if status.umip_supported && !status.umip_enabled {
        cr4.insert(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION);
    }

    // I-1 fix: Enable SMEP second (blocks kernel executing user pages)
    if status.smep_supported && !status.smep_enabled {
        cr4.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
    }

    // I-1 fix: Enable SMAP last
    // SMAP requires UserAccessGuard/STAC/CLAC to be in place for intentional
    // user memory access. By enabling it last, we ensure all kernel code
    // paths that access user memory are already prepared.
    if status.smap_supported && !status.smap_enabled {
        cr4.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
    }

    // Write back only if changes were made
    if cr4 != original_cr4 {
        unsafe { Cr4::write(cr4) };
    }

    // Re-read to report final state
    check_cpu_features()
}

/// R102-5 FIX: Verify SMAP support and enablement at boot.
///
/// The kernel unconditionally uses CLAC/STAC instructions in syscall entry stubs
/// and usercopy paths. On CPUs without SMAP support, these instructions may
/// generate #UD (Undefined Opcode) on every syscall, causing a hard kernel crash.
///
/// This function MUST be called after `enable_protections()` during early boot.
/// It will panic (halt boot) if SMAP is not available or not enabled, enforcing
/// the fail-closed posture required by R102-5.
///
/// # Panics
///
/// - If the CPU does not support SMAP (CPUID.07H:EBX[20] not set)
/// - If SMAP is supported but CR4.SMAP is not set (enablement failure)
pub fn require_smap_support() {
    let status = check_cpu_features();

    if !status.smap_supported {
        panic!(
            "FATAL: CPU does not support SMAP (CPUID.07H:EBX[20]). \
             The kernel requires SMAP for CLAC/STAC user-memory access guards. \
             Boot halted."
        );
    }

    if !status.smap_enabled {
        panic!(
            "FATAL: SMAP is supported but not enabled in CR4. \
             The kernel requires SMAP enabled for CLAC/STAC user-memory access guards. \
             Boot halted."
        );
    }

    kprintln!("      ✓ SMAP requirement verified (CLAC/STAC safe)");
}

/// CPUID leaf 0x7 subleaf 0 (returns eax, ebx, ecx, edx)
///
/// This leaf contains extended feature flags including SMEP, SMAP, and UMIP.
///
/// Note: We need to save and restore rbx because LLVM uses it internally
/// and doesn't allow it as an inline asm operand.
fn cpuid_leaf_7() -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        // rbx is reserved by LLVM, so we save it, use it for cpuid, then restore
        core::arch::asm!(
            "push rbx",           // Save rbx (used by LLVM)
            "mov eax, 7",
            "xor ecx, ecx",       // Subleaf 0
            "cpuid",
            "mov {ebx_out:e}, ebx", // Copy ebx to output before restoring
            "pop rbx",            // Restore rbx
            ebx_out = out(reg) ebx,
            out("eax") eax,
            out("ecx") ecx,
            out("edx") edx,
        );
    }

    (eax, ebx, ecx, edx)
}

/// Temporarily disable SMAP for intentional user memory access
///
/// # Safety
///
/// Must be paired with `clac()` after the access is complete.
#[inline]
#[allow(dead_code)]
pub unsafe fn stac() {
    core::arch::asm!("stac", options(nostack, nomem));
}

/// Re-enable SMAP after intentional user memory access
///
/// # Safety
///
/// Must be called after `stac()` to restore SMAP protection.
#[inline]
#[allow(dead_code)]
pub unsafe fn clac() {
    core::arch::asm!("clac", options(nostack, nomem));
}

// ============================================================================
// Hypervisor Detection
// ============================================================================

/// Hypervisor type detected via CPUID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorType {
    /// No hypervisor detected (bare metal)
    None,
    /// QEMU TCG (software CPU emulation)
    QemuTcg,
    /// KVM (hardware-assisted virtualization)
    Kvm,
    /// VMware
    VMware,
    /// Microsoft Hyper-V
    HyperV,
    /// Xen
    Xen,
    /// Unknown hypervisor
    Unknown,
}

/// Check if running under a hypervisor using CPUID leaf 0x1
///
/// CPUID.01H:ECX[31] is the hypervisor present bit.
/// When set, the CPU is running in a virtualized environment.
///
/// R72-4 FIX: Remove nomem since push/pop uses stack memory.
#[inline]
pub fn hypervisor_present() -> bool {
    let ecx: u32;
    unsafe {
        // rbx is reserved by LLVM, so we save/restore it
        // Cannot use `nostack` or `nomem` with push/pop (uses stack memory)
        // R73-4 FIX: Initialize ECX to 0 for consistent behavior across CPU models
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            inout("ecx") 0u32 => ecx,
            lateout("edx") _,
            // No options - push/pop uses both stack and memory
        );
    }
    // Bit 31 = Hypervisor present
    (ecx & (1 << 31)) != 0
}

/// Detect hypervisor type using CPUID leaf 0x40000000
///
/// Returns the hypervisor vendor signature and type.
/// Common signatures:
/// - "TCGTCGTCGTCG" = QEMU TCG
/// - "KVMKVMKVM\0\0\0" = KVM
/// - "VMwareVMware" = VMware
/// - "Microsoft Hv" = Hyper-V
/// - "XenVMMXenVMM" = Xen
///
/// R72-4 FIX: Remove nomem since push/pop uses stack memory.
pub fn detect_hypervisor() -> HypervisorType {
    if !hypervisor_present() {
        return HypervisorType::None;
    }

    // CPUID leaf 0x40000000 returns hypervisor signature
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        // rbx is reserved by LLVM, so we save/restore it
        // Cannot use `nostack` or `nomem` with push/pop (uses stack memory)
        // R73-4 FIX: Initialize ECX to 0 for consistent behavior across CPU models
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            ebx_out = out(reg) ebx,
            inout("eax") 0x40000000u32 => _,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
            // No options - push/pop uses both stack and memory
        );
    }

    // Signature is stored in EBX:ECX:EDX (12 bytes)
    let sig = [
        (ebx & 0xFF) as u8,
        ((ebx >> 8) & 0xFF) as u8,
        ((ebx >> 16) & 0xFF) as u8,
        ((ebx >> 24) & 0xFF) as u8,
        (ecx & 0xFF) as u8,
        ((ecx >> 8) & 0xFF) as u8,
        ((ecx >> 16) & 0xFF) as u8,
        ((ecx >> 24) & 0xFF) as u8,
        (edx & 0xFF) as u8,
        ((edx >> 8) & 0xFF) as u8,
        ((edx >> 16) & 0xFF) as u8,
        ((edx >> 24) & 0xFF) as u8,
    ];

    // Match known hypervisor signatures
    // QEMU TCG: "TCGTCGTCGTCG"
    if sig.starts_with(b"TCGTCGTCG") {
        return HypervisorType::QemuTcg;
    }
    // KVM: "KVMKVMKVM"
    if sig.starts_with(b"KVMKVMKVM") {
        return HypervisorType::Kvm;
    }
    // VMware: "VMwareVMware"
    if sig.starts_with(b"VMwareVMwa") {
        return HypervisorType::VMware;
    }
    // Hyper-V: "Microsoft Hv"
    if sig.starts_with(b"Microsoft ") {
        return HypervisorType::HyperV;
    }
    // Xen: "XenVMMXenVMM"
    if sig.starts_with(b"XenVMMXenV") {
        return HypervisorType::Xen;
    }

    HypervisorType::Unknown
}

/// Check if running in software emulation (QEMU TCG)
///
/// Returns true if QEMU TCG is detected, which has significantly
/// higher IPI and interrupt latency compared to hardware or KVM.
#[inline]
pub fn is_software_emulated() -> bool {
    matches!(detect_hypervisor(), HypervisorType::QemuTcg)
}

/// Check if running in any virtualized environment
#[inline]
pub fn is_virtualized() -> bool {
    hypervisor_present()
}
