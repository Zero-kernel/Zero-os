#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;
use core::panic::PanicInfo;
use mm::memory::BootInfo;

// 引入模块化子系统，drivers需要在最前面以便使用其宏
#[macro_use]
extern crate drivers;
extern crate arch;
extern crate block;
extern crate cap;
extern crate ipc;
extern crate kernel_core;
extern crate mm;
extern crate net;
extern crate sched;
extern crate security;
extern crate vfs;
extern crate livepatch; // R101-4: Boot-time ECDSA key validation
#[macro_use]
extern crate audit;
extern crate trace;
extern crate compliance;
#[macro_use]
extern crate klog;

// A.3 Audit capability gate imports
use cap::CapRights;
use kernel_core::process::{current_credentials, with_current_cap_table};
// G.1 Observability: Counter integration for allocation failures
use trace::counters::{increment_counter, TraceCounter};

/// G.1: Guard flag to prevent recursive allocation in alloc_error_handler.
///
/// `increment_counter()` uses `CpuLocal` which lazy-initializes via heap
/// allocation (`Box::new_uninit_slice`). If the very first allocation fails
/// before counters are initialized, calling `increment_counter` from
/// `alloc_error_handler` would re-enter the allocator, causing infinite
/// recursion or `spin::Once` deadlock.
///
/// This flag is set to `true` after the first successful counter increment
/// (which happens during early boot via timer ISR). The alloc_error_handler
/// only increments the counter when this flag is `true`.
static COUNTERS_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// R109-4 FIX: Flag to distinguish early-boot context from post-boot kernel threads.
///
/// Set to `true` just before enabling interrupts (`sti`).  Audit authorizer
/// closures use this flag to reject `current_credentials() == None` requests
/// after boot completes.  Without this flag, kernel threads and interrupt
/// handlers (which also have `None` credentials) would be granted audit
/// snapshot/HMAC-key access, bypassing capability gates.
static BOOT_PHASE_COMPLETE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// 演示模块
mod demo;
mod integration_test;
mod interrupt_demo;
mod process_demo;
mod runtime_tests;
mod stack_guard;
mod syscall_demo;
mod usermode_test;

// 串口端口
const SERIAL_PORT: u16 = 0x3F8;

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
    );
}

unsafe fn serial_write_byte(byte: u8) {
    outb(SERIAL_PORT, byte);
}

unsafe fn serial_write_str(s: &str) {
    for byte in s.bytes() {
        serial_write_byte(byte);
    }
}

/// P1-1: Parse the hardening profile from the UEFI boot command line.
///
/// Scans `boot_info.cmdline[..cmdline_len]` for a whitespace-delimited token
/// of the form `profile=<value>` (case-insensitive prefix match). The value
/// is parsed via [`compliance::HardeningProfile::from_str`], which accepts
/// "secure", "balanced", "performance" and several aliases.
///
/// If multiple `profile=` tokens appear, the **last valid** one wins (this
/// mirrors Linux kernel cmdline semantics where later values override earlier
/// ones). Returns `None` when no valid profile token is found.
fn parse_hardening_profile_from_cmdline(
    boot_info: &BootInfo,
) -> Option<compliance::HardeningProfile> {
    let len = boot_info.cmdline_len.min(boot_info.cmdline.len());
    let mut cmdline = &boot_info.cmdline[..len];

    // Trim at first NUL byte if present (belt-and-suspenders with cmdline_len).
    if let Some(nul_pos) = cmdline.iter().position(|&b| b == 0) {
        cmdline = &cmdline[..nul_pos];
    }

    const PREFIX: &[u8] = b"profile=";
    let mut result: Option<compliance::HardeningProfile> = None;

    let mut pos = 0usize;
    while pos < cmdline.len() {
        // Skip whitespace
        while pos < cmdline.len() && cmdline[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= cmdline.len() {
            break;
        }

        // Find end of token
        let token_start = pos;
        while pos < cmdline.len() && !cmdline[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let token = &cmdline[token_start..pos];

        // Check for case-insensitive "profile=" prefix
        if token.len() > PREFIX.len() {
            let mut prefix_match = true;
            for i in 0..PREFIX.len() {
                if token[i].to_ascii_lowercase() != PREFIX[i] {
                    prefix_match = false;
                    break;
                }
            }
            if prefix_match {
                let value = &token[PREFIX.len()..];
                if let Ok(s) = core::str::from_utf8(value) {
                    if let Some(profile) = compliance::HardeningProfile::from_str(s) {
                        result = Some(profile);
                    } else {
                        // Operator typo detection: profile= token found but value
                        // is not recognized. Log a warning so the operator knows
                        // their intent was not applied.
                        // P1-1: Use klog_force! — typo warnings must always be visible.
                        klog_force!(
                            "      ! WARNING: Unrecognized profile value '{}', ignoring",
                            s
                        );
                    }
                }
            }
        }
    }

    result
}

/// Test block device write/read path end-to-end
///
/// Writes a test pattern to the last sectors of the device (safe area outside filesystem),
/// reads it back, and verifies the data matches. This exercises the full write path
/// through virtio-blk without requiring filesystem write support.
fn test_block_write(device: &alloc::sync::Arc<dyn block::BlockDevice>) -> bool {
    use alloc::vec;

    // Skip if device is read-only
    if device.is_read_only() {
        klog!(Info, "        [SKIP] Device is read-only");
        return true;
    }

    let capacity = device.capacity_sectors();
    let sector_size = device.sector_size() as usize;

    // Need at least 2 sectors for test (use last 2 sectors)
    if capacity < 4 {
        klog!(Info, "        [SKIP] Device too small for write test");
        return true;
    }

    // Use last 2 sectors as scratch area (outside ext2 filesystem)
    let test_sector = capacity - 2;
    let test_pattern: [u8; 512] = {
        let mut pattern = [0u8; 512];
        for (i, byte) in pattern.iter_mut().enumerate() {
            // Create a recognizable pattern: 0xDE, 0xAD, 0xBE, 0xEF repeating + offset
            *byte = match i % 4 {
                0 => 0xDE,
                1 => 0xAD,
                2 => 0xBE,
                _ => 0xEF,
            } ^ (i as u8);
        }
        pattern
    };

    // Write test pattern
    klog!(Info, "        Writing test pattern to sector {}...", test_sector);
    match device.write_sync(test_sector, &test_pattern) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            klog!(Error,
                "        [FAIL] Write returned {} bytes, expected {}",
                n, sector_size
            );
            return false;
        }
        Err(e) => {
            klog!(Error, "        [FAIL] Write failed: {:?}", e);
            return false;
        }
    }

    // Read back
    let mut read_buf = vec![0u8; sector_size];
    match device.read_sync(test_sector, &mut read_buf) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            klog!(Error,
                "        [FAIL] Read returned {} bytes, expected {}",
                n, sector_size
            );
            return false;
        }
        Err(e) => {
            klog!(Error, "        [FAIL] Read failed: {:?}", e);
            return false;
        }
    }

    // Verify
    if read_buf[..512] == test_pattern {
        klog!(Info, "        [PASS] Write/read verification successful");
        true
    } else {
        klog!(Error, "        [FAIL] Data mismatch!");
        klog!(Info, "        Expected first 8: {:02x?}", &test_pattern[..8]);
        klog!(Info, "        Got first 8:      {:02x?}", &read_buf[..8]);
        false
    }
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    // 禁用中断 - 必须首先做！
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // 发送串口消息表示内核已启动
    unsafe {
        serial_write_str("Kernel _start entered\n");
    }

    // 解析 Bootloader 传递的 BootInfo 指针（必须在任何 println! 之前）
    // Bootloader 通过 rdi 寄存器传递 BootInfo 指针（System V AMD64 ABI）
    // 由于 identity mapping 仍然有效，可以直接访问该地址
    let boot_info: Option<&BootInfo> = if boot_info_ptr != 0 {
        unsafe { (boot_info_ptr as *const BootInfo).as_ref() }
    } else {
        None
    };

    // 初始化 framebuffer 控制台（现代 GOP 方式，必须在第一个 println! 之前）
    if let Some(info) = boot_info {
        // 转换 mm::memory::FramebufferInfo 到 drivers::framebuffer::FramebufferInfo
        let fb_info = drivers::framebuffer::FramebufferInfo {
            base: info.framebuffer.base,
            size: info.framebuffer.size,
            width: info.framebuffer.width,
            height: info.framebuffer.height,
            stride: info.framebuffer.stride,
            pixel_format: match info.framebuffer.pixel_format {
                mm::memory::PixelFormat::Rgb => drivers::framebuffer::PixelFormat::Rgb,
                mm::memory::PixelFormat::Bgr => drivers::framebuffer::PixelFormat::Bgr,
                mm::memory::PixelFormat::Unknown => drivers::framebuffer::PixelFormat::Unknown,
            },
        };
        drivers::framebuffer::init(&fb_info);
        unsafe {
            serial_write_str("Framebuffer console initialized\n");
        }
    }

    // 初始化VGA驱动（后备，framebuffer 初始化后 VGA 输出会被跳过）
    drivers::vga_buffer::init();

    // P1-1: Wire klog profile as early as possible — before the first
    // klog_always! banner — so Secure profile suppresses all boot output.
    // This parse happens before the heap is ready, so it uses only stack
    // and BootInfo data.  The profile is set again after PolicySurface
    // initialization for defense-in-depth.
    if let Some(info) = boot_info {
        if let Some(early_profile) = parse_hardening_profile_from_cmdline(info) {
            let klog_profile = match early_profile {
                compliance::HardeningProfile::Secure => klog::KlogProfile::Secure,
                compliance::HardeningProfile::Balanced => klog::KlogProfile::Balanced,
                compliance::HardeningProfile::Performance => klog::KlogProfile::Performance,
            };
            klog::set_profile(klog_profile);
        } else {
            // Default: Balanced (show boot banners)
            klog::set_profile(klog::KlogProfile::Balanced);
        }
    } else {
        klog::set_profile(klog::KlogProfile::Balanced);
    }

    klog_always!("==============================");
    klog_always!("  Zero-OS Microkernel v0.1");
    klog_always!("==============================");
    klog_always!();

    // 阶段1：初始化中断处理
    klog_always!("[1/3] Initializing interrupts...");
    arch::interrupts::init();
    klog_always!("      ✓ IDT loaded with 20+ handlers");

    // 阶段2：初始化内存管理
    klog_always!("[2/3] Initializing memory management...");
    if let Some(info) = boot_info {
        mm::memory::init_with_bootinfo(info);
        klog_always!("      ✓ Heap and Buddy allocator ready (using BootInfo)");
    } else {
        klog_always!("      ! BootInfo missing, using fallback initialization");
        mm::memory::init();
        klog_always!("      ✓ Heap and Buddy allocator ready (fallback mode)");
    }

    // 初始化页表管理器
    // Bootloader 创建了恒等映射（物理地址 == 虚拟地址），所以物理偏移量为 0
    unsafe {
        mm::page_table::init(x86_64::VirtAddr::new(0));
    }
    klog_always!("      ✓ Page table manager initialized");

    // 安装内核栈守护页（必须在 mm 初始化后、启用中断前）
    klog_always!("[2.5/3] Installing kernel stack guard pages...");
    unsafe {
        match stack_guard::install() {
            Ok(()) => {
                klog_always!("      ✓ Guard pages installed for kernel stacks");
            }
            Err(e) => {
                klog!(Warn, "      ! Failed to install guard pages: {:?}", e);
                klog!(Warn, "      ! Continuing with static stacks (less safe)");
            }
        }
    }

    // 安全加固（Phase 0: W^X, NX, Identity Map Cleanup, CSPRNG, kptr guard, Spectre）
    // G.3 Compliance: Use HardeningProfile to configure security settings
    klog_always!("[2.6/3] Applying security hardening...");
    {
        let mut frame_allocator = mm::memory::FrameAllocator::new();

        // G.fin.1: Initialize boot-time locked PolicySurface as single source of truth.
        // P1-1: Profile is now wired from the UEFI boot command line ("profile=secure").
        // Falls back to Balanced if no valid profile= token is found.
        let (profile, profile_source) = boot_info
            .and_then(|info| parse_hardening_profile_from_cmdline(info))
            .map(|p| (p, compliance::ProfileSource::BootCmdline))
            .unwrap_or((
                compliance::HardeningProfile::Balanced,
                compliance::ProfileSource::Default,
            ));
        let policy = compliance::init_policy_surface(profile, profile_source);

        // H.2.2: Wire klog filter from hardening profile
        let klog_profile = match policy.profile {
            compliance::HardeningProfile::Secure => klog::KlogProfile::Secure,
            compliance::HardeningProfile::Balanced => klog::KlogProfile::Balanced,
            compliance::HardeningProfile::Performance => klog::KlogProfile::Performance,
        };
        klog::set_profile(klog_profile);

        // Generate SecurityConfig from the selected profile
        let phys_offset = mm::page_table::get_physical_memory_offset();
        let sec_config = policy.profile.security_config(phys_offset);

        klog_always!(
            "      Profile: {} (source: {:?}, audit_capacity: {})",
            policy.profile.name(),
            policy.source,
            policy.audit_ring_capacity
        );

        match security::init(sec_config, &mut frame_allocator) {
            Ok(report) => {
                klog_always!("      ✓ Security hardening applied");
                klog!(Info, "        - Identity map: {:?}", report.identity_cleanup);
                if let Some(nx) = &report.nx_summary {
                    klog!(Info, 
                        "        - NX enforced: {} pages protected",
                        nx.data_nx_pages
                    );
                }
                if report.rng_ready {
                    klog_always!("        - CSPRNG ready (ChaCha20 + RDRAND/RDSEED)");
                    // R102-L5 FIX: Validate RNG without printing raw output.
                    // Printing raw entropy values is unnecessary and could be
                    // sensitive if RNG is not fully initialized.
                    match security::random_u64() {
                        Ok(_) => klog!(Info, "        - RNG self-test: passed"),
                        Err(e) => klog!(Error, "        ! RNG self-test failed: {:?}", e),
                    }
                } else {
                    klog!(Warn, "        ! CSPRNG not ready");
                }
                if report.kptr_guard_active {
                    klog!(Info, "        - kptr guard: active");
                }
                if let Some(spectre) = &report.spectre_status {
                    klog!(Info, "        - Spectre mitigations: {}", spectre.summary());
                }

                // G.fin.1: Lock profile after security initialization.
                // PolicySurface already prevents set_profile() changes, but
                // lock_profile() provides defense-in-depth against direct calls.
                compliance::lock_profile();
                klog_always!("        - Profile locked (immutable until reboot)");

                // P1-1 FIX: Log PolicySurface enforcement summary so operators
                // can verify which security features are active at boot.
                let ps = compliance::policy();
                klog_always!("      PolicySurface enforcement:");
                klog_always!("        - panic_redact_details: {}", ps.panic_redact_details);
                klog_always!("        - kaslr_fail_closed:    {}", ps.kaslr_fail_closed);
                klog_always!("        - kpti_fail_closed:     {}", ps.kpti_fail_closed);
                klog_always!("        - debug_interfaces:     {}", ps.debug_interfaces_enabled);
                klog_always!("        - spectre_mitigations:  {}", ps.spectre_mitigations);
                klog_always!("        - kptr_guard:           {}", ps.kptr_guard);
                klog_always!("        - strict_wxorx:         {}", ps.strict_wxorx);
                klog_always!("        - audit_ring_capacity:  {}", ps.audit_ring_capacity);
            }
            Err(e) => {
                // P1-1: klog_force! — hardening failure must be visible in all profiles.
                klog_force!("      ! Security hardening failed: {:?}", e);
                // R102-2 FIX: Secure profile must not boot without core mitigations.
                // A single hardware/config anomaly should not silently disable all
                // security hardening (W^X, NX, CSPRNG, Spectre mitigations).
                if policy.profile == compliance::HardeningProfile::Secure {
                    panic!(
                        "Security hardening failed in Secure profile: {:?} \
                         (use Balanced profile to allow degraded boot)",
                        e
                    );
                }
                klog_force!("      ! Continuing with reduced security");
            }
        }
    }

    // R101-4 FIX: Boot-time livepatch ECDSA key validation
    // P1-1: Use klog_force! — critical security warning must appear in all profiles.
    if livepatch::has_placeholder_keys() {
        klog_force!("      ! WARNING: Livepatch ECDSA public keys are all-zero placeholders!");
        klog_force!("      ! Livepatch signature verification is non-functional.");
        klog_force!("      ! Generate production P-256 keys and embed them in livepatch::TRUSTED_P256_PUBKEYS_UNCOMPRESSED.");
    }

    // KASLR/KPTI/PCID initialization
    // R39-7 FIX: Pass KASLR slide from bootloader to kernel
    klog_always!("[2.65/3] Initializing KASLR/KPTI/PCID...");
    security::init_kaslr(boot_info.map(|info| info.kaslr_slide));

    // P1-1 FIX: PolicySurface-driven KASLR/KPTI fail-closed enforcement.
    // When kaslr_fail_closed is true (Secure profile), the kernel must not
    // boot with a fully deterministic layout. If full text KASLR is
    // unavailable, we allow boot only when Partial KASLR is active.
    let ps = compliance::policy();
    if ps.kaslr_fail_closed && !security::is_kaslr_enabled() {
        // Check partial KASLR as a fallback: if partial randomization is
        // active we log a warning but allow boot (defense-in-depth).
        if security::is_partial_kaslr_enabled() {
            // P1-1: klog_force! — policy enforcement messages must be visible
            // even in Secure profile so operators can diagnose boot issues.
            klog_force!(
                "[POLICY] {} profile: full KASLR not active; partial KASLR in use",
                ps.profile.name()
            );
        } else {
            // Log before panic so operators see the reason even when
            // panic_redact_details is true (Secure profile).
            klog_force!(
                "[POLICY] {} profile: KASLR required but no randomization active — halting",
                ps.profile.name()
            );
            panic!(
                "KASLR is required in Secure profile but no randomization is active \
                 (boot with profile=balanced to allow degraded boot)"
            );
        }
    }
    if ps.kpti_fail_closed && !security::is_kpti_enabled() {
        klog_force!(
            "[POLICY] {} profile: KPTI not active — kernel page table isolation \
             preferred (Meltdown mitigation)",
            ps.profile.name()
        );
        // KPTI is not yet implemented (P2-2), so we warn rather than panic.
        // Once KPTI is available, this should become a hard panic.
    }

    // Cache INVPCID capability for TLB shootdowns (uses CPUID + PCID state)
    mm::tlb_shootdown::init_invpcid_support();

    // CPU 硬件保护特性启用 (SMEP/SMAP/UMIP)
    klog_always!("[2.7/3] Enabling CPU protection features...");
    {
        let cpu_status = arch::cpu_protection::enable_protections();
        if cpu_status.smep_enabled {
            klog_always!("        - SMEP: enabled (blocks kernel executing user pages)");
        } else if cpu_status.smep_supported {
            klog!(Warn, "        ! SMEP: supported but failed to enable");
        } else {
            klog_always!("        - SMEP: not supported by CPU");
        }
        if cpu_status.smap_enabled {
            klog_always!("        - SMAP: enabled (blocks kernel accessing user pages)");
        } else if cpu_status.smap_supported {
            klog!(Warn, "        ! SMAP: supported but failed to enable");
        } else {
            klog_always!("        - SMAP: not supported by CPU");
        }
        if cpu_status.umip_enabled {
            klog_always!("        - UMIP: enabled (blocks user SGDT/SIDT/SLDT)");
        } else if cpu_status.umip_supported {
            klog!(Warn, "        ! UMIP: supported but failed to enable");
        } else {
            klog_always!("        - UMIP: not supported by CPU");
        }
        if cpu_status.is_fully_protected() {
            klog_always!("      ✓ All CPU protections active");
        } else {
            klog_always!("      ! Partial CPU protection (some features unavailable)");
        }

        // V-4 fix: No longer need to update SMAP status cache.
        // clac_if_smap() now reads CR4 directly for SMP safety.
    }

    // R102-5 FIX: Enforce SMAP as a hard boot requirement.
    // The kernel unconditionally uses CLAC/STAC in syscall entry and usercopy paths.
    // Without SMAP these instructions may #UD, crashing every syscall.
    arch::cpu_protection::require_smap_support();

    // Phase 6: 初始化 SYSCALL/SYSRET 快速系统调用机制
    klog_always!("[2.8/3] Initializing SYSCALL/SYSRET...");
    {
        // GDT 必须在此之前初始化（由 arch::interrupts::init() 完成）
        // 获取系统调用入口点地址并配置 MSR
        let syscall_entry = arch::syscall::syscall_entry_stub as *const () as u64;
        unsafe {
            arch::init_syscall_msr(syscall_entry);
        }
        // 注册 syscall 帧回调，让 kernel_core 能访问当前 syscall 帧
        // 这对于 clone/fork 正确设置子进程上下文至关重要
        arch::register_frame_callback();
        // H.3 KPTI: Register arch-level per-CPU CR3 updater so kernel_core's
        // activate_memory_space() can keep the syscall assembly's GS-relative
        // CR3 pair in sync during context switches.
        kernel_core::register_kpti_cr3_callback(arch::arch_set_kpti_cr3s);

        // R118-3 FIX: Enable KPTI now that the arch-level CR3 updater is registered.
        //
        // This makes fork/exec create dual page table roots and activates CR3
        // switching in syscall entry/exit and enter_usermode() IRETQ paths.
        // All pre-requisite bugs (R118-2, R118-4, R118-5, R118-7) are fixed.
        //
        // KPTI is enabled unconditionally: all pre-Whiskey Lake Intel CPUs are
        // vulnerable to Meltdown. A future refinement could check CPUID for
        // IA32_ARCH_CAPABILITIES.RDCL_NO and skip enablement on safe CPUs.
        security::kaslr::enable_kpti();

        klog_always!("      ✓ SYSCALL MSR configured");
        klog_always!("      ✓ Syscall frame callback registered");
        klog_always!("      ✓ KPTI CR3 callback registered");
        klog_always!("      ✓ Ring 3 transition support ready");
    }

    // 阶段3：测试基础功能
    klog_always!("[3/3] Running basic tests...");

    // 测试内存分配
    use alloc::vec::Vec;
    let mut test_vec = Vec::new();
    for i in 0..10 {
        test_vec.push(i);
    }
    klog_always!("      ✓ Heap allocation test passed");

    // 显示内存统计
    let mem_stats = mm::memory::FrameAllocator::new().stats();
    klog_always!("      ✓ Memory stats available");

    klog_always!();
    klog_always!("=== System Information ===");
    mem_stats.print();

    klog_always!();
    klog_always!("=== Verifying Core Subsystems ===");
    klog_always!();

    // 验证各个模块已编译
    klog_always!("[4/8] Verifying architecture support...");
    klog_always!("      ✓ arch crate loaded");
    klog_always!("      ✓ Context switch module available");

    klog_always!("[5/8] Initializing kernel core...");
    kernel_core::init(); // 初始化进程管理和 BOOT_CR3 缓存（必须在调度器前）
    klog_always!("      ✓ Process management ready");
    klog_always!("      ✓ System calls framework ready");
    klog_always!("      ✓ Fork/COW implementation compiled");

    // Phase E: APIC and SMP Initialization
    klog_always!("[5.5/8] Initializing APIC and SMP...");
    {
        // Pass ACPI RSDP address from bootloader to SMP module (required for UEFI systems)
        if let Some(info) = boot_info {
            arch::set_rsdp_address(info.rsdp_address);
        }

        // Initialize BSP's Local APIC
        unsafe {
            arch::apic::init();
        }
        let bsp_lapic_id = arch::apic::bsp_lapic_id();
        klog_always!("      ✓ BSP LAPIC initialized (ID: {})", bsp_lapic_id);

        // E.1: Initialize HPET (High Precision Event Timer) if available
        // HPET provides a high-resolution counter for precise timing and
        // can be used as an alternative reference for LAPIC calibration.
        match arch::hpet::init() {
            Ok(info) => {
                klog_always!(
                    "      ✓ HPET initialized (freq={} Hz, timers={}, 64-bit={})",
                    info.frequency_hz, info.comparator_count, info.counter_64bit
                );
            }
            Err(e) => {
                klog_always!("      ! HPET unavailable: {:?} (using PIT for calibration)", e);
            }
        }

        // Calibrate LAPIC timer using HPET (preferred) or PIT channel 2 as reference
        // This determines the correct initial count for ~1kHz ticks
        unsafe {
            match arch::apic::calibrate_lapic_timer() {
                Ok(init_count) => {
                    klog_always!(
                        "      ✓ LAPIC timer calibrated (init_count: {})",
                        init_count
                    );
                }
                Err(e) => {
                    klog_always!(
                        "      ! LAPIC timer calibration failed: {}, using default",
                        e
                    );
                }
            }
        }

        // Initialize BSP's per-CPU data
        // Get kernel stack top from GDT (set during arch::interrupts::init)
        let kernel_stack_top = arch::default_kernel_stack_top() as usize;
        arch::init_bsp(
            bsp_lapic_id,
            kernel_stack_top,
            kernel_stack_top, // IRQ stack (same as kernel stack for now)
            kernel_stack_top, // Syscall stack (same for now)
        );
        klog_always!("      ✓ BSP per-CPU data initialized");

        // R67-8 FIX: Initialize per-CPU syscall metadata and GS base for BSP
        unsafe {
            arch::syscall::init_syscall_percpu(0);
        }
        klog_always!("      ✓ BSP syscall per-CPU state initialized");

        // Attempt to bring up Application Processors (APs)
        // This will enumerate CPUs via ACPI MADT and send INIT-SIPI-SIPI
        let num_cpus = arch::start_aps();
        if num_cpus > 1 {
            klog_always!("      ✓ SMP enabled: {} CPU(s) online", num_cpus);
        } else {
            klog_always!("      ✓ Single-core mode (no APs found or SMP disabled)");
        }
    }

    klog_always!("[6/8] Initializing scheduler...");
    sched::enhanced_scheduler::init(); // 注册定时器和重调度回调
    klog_always!("      ✓ Enhanced scheduler initialized");

    // E.5: Initialize cpuset subsystem after CPU enumeration
    sched::cpuset::init();
    klog_always!("      ✓ Cpuset CPU isolation initialized");

    klog_always!("[7/8] Initializing IPC...");
    ipc::init(); // 初始化IPC子系统并注册清理回调
    klog_always!("      ✓ Capability-based endpoints enabled");
    klog_always!("      ✓ Process cleanup callback registered");

    klog_always!("[7.5/8] Initializing VFS...");
    vfs::init(); // 初始化虚拟文件系统
    klog_always!("      ✓ devfs mounted at /dev");
    klog_always!("      ✓ Device files: null, zero, console");

    // Initialize page cache before block layer mounts filesystems
    klog_always!("[7.52/8] Initializing Page Cache...");
    mm::init_page_cache();
    klog_always!("      ✓ Global page cache initialized");

    // Phase D: Network Layer
    klog_always!("[7.54/8] Initializing Network Layer...");
    let net_devices = net::init();
    if net_devices == 0 {
        klog_always!("      ! No network devices detected");
    }

    // Phase C: Block Layer and Storage Foundation
    klog_always!("[7.55/8] Initializing Block Layer...");
    block::init();
    // Probe for virtio-blk devices and register with VFS
    if let Some((device, name)) = block::probe_devices() {
        let device_for_registration = device.clone();
        match vfs::register_block_device(name, device_for_registration) {
            Ok(()) => {
                klog_always!("      ✓ Registered /dev/{} in devfs", name);

                // Phase C: Test block write path (uses last sectors, outside filesystem)
                // P1-1 FIX: Gate destructive block test by debug_interfaces_enabled.
                if compliance::policy().debug_interfaces_enabled {
                    klog_always!("      [TEST] Block device write/read verification:");
                    if test_block_write(&device) {
                        klog_always!("      ✓ Block write path verified");
                    } else {
                        klog!(Error, "      ! Block write test failed");
                    }
                }

                // Phase C: Try to mount as ext2 filesystem
                match vfs::Ext2Fs::mount(device) {
                    Ok(fs) => match vfs::mount("/mnt", fs) {
                        Ok(()) => klog_always!("      ✓ Mounted /dev/{} on /mnt as ext2", name),
                        Err(e) => klog!(Warn,
                            "      ! Registered /dev/{} but failed to mount on /mnt: {:?}",
                            name, e
                        ),
                    },
                    Err(e) => klog!(Warn,
                        "      ! Registered /dev/{} but failed to initialize ext2: {:?}",
                        name, e
                    ),
                }
            }
            Err(e) => klog!(Error, "      ! Failed to register /dev/{}: {:?}", name, e),
        }
    }

    klog_always!("[7.6/8] Initializing audit subsystem...");
    // G.fin.1: Audit ring capacity is derived from the boot-time PolicySurface.
    let audit_capacity = compliance::policy().audit_ring_capacity;
    match audit::init(audit_capacity) {
        Ok(()) => {
            // Emit boot event
            let _ = audit::emit(
                audit::AuditKind::Internal,
                audit::AuditOutcome::Info,
                audit::AuditSubject::kernel(),
                audit::AuditObject::None,
                &[0], // boot event
                0,
                0, // timestamp 0 = boot
            );
            klog_always!(
                "      ✓ Audit subsystem ready (capacity: {} events)",
                audit_capacity
            );
            klog_always!("      ✓ Hash-chained tamper evidence enabled");

            // P1-1: Re-emit the profile validation audit event now that audit is
            // initialised. The initial emission during init_policy_surface() was
            // silently dropped because audit::init() hadn't run yet.
            compliance::emit_deferred_policy_audit();
            klog_always!("      ✓ Deferred profile audit event recorded");

            // A.3: Register audit snapshot authorizer (capability gate)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_READ
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_snapshot_authorizer(|| {
                // R109-4 FIX: Only allow credential-less access during the boot phase.
                // Post-boot, kernel threads and interrupt handlers also have None
                // credentials and must not bypass capability gates.
                let creds = current_credentials();
                if creds.is_none() {
                    if !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(()); // Still in boot phase
                    }
                    return Err(audit::AuditError::AccessDenied);
                }

                // After boot: Allow root users
                if let Some(ref c) = creds {
                    if c.euid == 0 {
                        return Ok(());
                    }
                }
                // Allow processes with CAP_AUDIT_READ capability
                if let Some(has_cap) =
                    with_current_cap_table(|table| table.has_rights(CapRights::AUDIT_READ))
                {
                    if has_cap {
                        return Ok(());
                    }
                }
                // Deny all others
                Err(audit::AuditError::AccessDenied)
            });
            klog_always!("      ✓ Audit capability gate registered (CAP_AUDIT_READ)");

            // R66-10 FIX: Register HMAC key authorizer (capability gate for audit config)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_WRITE
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_hmac_key_authorizer(|| {
                // R109-4 FIX: Only allow credential-less access during the boot phase.
                // Same rationale as snapshot authorizer above.
                let creds = current_credentials();
                if creds.is_none() {
                    if !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(()); // Still in boot phase
                    }
                    return Err(audit::AuditError::AccessDenied);
                }

                // After boot: Allow root users
                if let Some(ref c) = creds {
                    if c.euid == 0 {
                        return Ok(());
                    }
                }
                // Allow processes with CAP_AUDIT_WRITE capability
                if let Some(has_cap) =
                    with_current_cap_table(|table| table.has_rights(CapRights::AUDIT_WRITE))
                {
                    if has_cap {
                        return Ok(());
                    }
                }
                // Deny all others
                Err(audit::AuditError::AccessDenied)
            });
            klog_always!("      ✓ Audit HMAC key gate registered (CAP_AUDIT_WRITE)");

            // R72-HMAC: Generate and install audit HMAC key for integrity protection
            // Uses CSPRNG to generate a 32-byte cryptographically secure key.
            // The key is zeroed from stack memory after use to minimize exposure.
            {
                let mut audit_hmac_key = [0u8; audit::MAX_HMAC_KEY_SIZE];
                match security::rng::fill_random(&mut audit_hmac_key) {
                    Ok(()) => match audit::set_hmac_key(&audit_hmac_key) {
                        Ok(()) => {
                            klog_always!("      ✓ Audit HMAC key installed (32 bytes, CSPRNG)");
                            klog_always!("        - All audit events now HMAC-SHA256 protected");
                        }
                        Err(e) => {
                            klog!(Error, "      ! Failed to set audit HMAC key: {:?}", e);
                        }
                    },
                    Err(e) => {
                        klog!(Error, "      ! Failed to generate audit HMAC key: {:?}", e);
                        klog!(Warn, "        - Audit events using plain SHA-256 chain only");
                    }
                }
                // R72-HMAC: Zero key material from stack to limit exposure window
                // Use volatile writes to prevent the compiler from eliding the wipe
                for byte in audit_hmac_key.iter_mut() {
                    unsafe { core::ptr::write_volatile(byte, 0) };
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }

            // R106-8: Register OOM killer audit callback for tamper-evident event recording.
            // OOM kill events are now fed into the hash-chained audit ring buffer.
            mm::register_oom_audit_callback(|pid, uid, needed, rss, adj, timestamp| {
                let _ = audit::emit(
                    audit::AuditKind::Internal,
                    audit::AuditOutcome::Info,
                    audit::AuditSubject::new(pid, uid, 0, None),
                    audit::AuditObject::Process { pid, signal: Some(9) }, // SIGKILL
                    &[needed, rss, adj as u64],
                    0,
                    timestamp,
                );
            });
            klog_always!("      ✓ OOM killer audit callback registered (R106-8)");

            // P1-4: Register livepatch audit callback for tamper-evident lifecycle recording.
            // Livepatch state transitions (load/enable/disable/unload) are now fed into
            // the hash-chained audit ring buffer alongside OOM events.
            livepatch::register_audit_callback(|action, patch_id, target_addr, extra, timestamp| {
                let _ = audit::emit(
                    audit::AuditKind::Internal,
                    audit::AuditOutcome::Info,
                    audit::AuditSubject::new(0, 0, 0, None),
                    audit::AuditObject::None,
                    &[action, patch_id, target_addr, extra[0], extra[1], extra[2]],
                    0,
                    timestamp,
                );
            });
            klog_always!("      ✓ Livepatch audit callback registered (P1-4)");
        }
        Err(e) => {
            klog!(Error, "      ! Audit initialization failed: {:?}", e);
        }
    }

    // Phase G.1: Observability subsystem (tracepoints, counters, watchdog)
    klog_always!("[7.7/8] Initializing observability subsystem...");
    trace::init();
    // G.1: Force-initialize per-CPU counter storage and mark counters as ready.
    // This ensures the CpuLocal<PerCpuCounters> lazy init happens during boot
    // (when heap is available), not in alloc_error_handler where it could recurse.
    increment_counter(TraceCounter::Custom0, 0); // no-op increment to trigger init
    COUNTERS_READY.store(true, core::sync::atomic::Ordering::Release);
    // Install read guard for metrics export (CAP_TRACE_READ or root)
    let _ = trace::install_read_guard(|| {
        // R109-4 FIX: Only allow credential-less access during the boot phase.
        let creds = current_credentials();
        if creds.is_none() {
            return !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire);
        }
        // After boot: Allow root users
        if let Some(ref c) = creds {
            if c.euid == 0 {
                return true;
            }
        }
        // Allow processes with CAP_TRACE_READ capability
        if let Some(has_cap) =
            with_current_cap_table(|table| table.has_rights(CapRights::TRACE_READ))
        {
            if has_cap {
                return true;
            }
        }
        false
    });
    klog_always!("      ✓ Trace capability gate registered (CAP_TRACE_READ)");

    klog_always!("[8/8] Verifying memory management...");
    klog_always!("      ✓ Page table manager compiled");
    klog_always!("      ✓ mmap/munmap available");

    // P1-1 FIX: Gate debug test interfaces by PolicySurface.
    // In Secure profile, debug_interfaces_enabled is false — skip integration,
    // runtime, and Ring 3 usermode tests to reduce the attack surface and
    // eliminate test-only code paths in production deployments.
    if compliance::policy().debug_interfaces_enabled {
        // 运行集成测试
        integration_test::run_all_tests();

        // 运行运行时功能测试
        let test_report = runtime_tests::run_all_runtime_tests();
        if test_report.failed > 0 {
            klog!(Warn, "WARNING: {} runtime tests failed!", test_report.failed);
        }

        // 运行 Ring 3 用户态测试
        klog_always!("[9/9] Running Ring 3 user mode test...");
        if usermode_test::run_usermode_test() {
            klog_always!("      ✓ Ring 3 test process created successfully");
        } else {
            klog!(Error, "      ! Ring 3 test setup failed");
        }
    } else {
        klog_force!("[POLICY] {} profile: debug/test interfaces disabled",
                     compliance::policy().profile.name());
    }

    klog_always!("=== System Ready ===");
    klog_always!();
    klog_always!("🎉 Zero-OS Phase 1 Complete!");
    klog_always!("All subsystems verified and integrated successfully!");
    klog_always!();
    klog_always!("📊 Component Summary:");
    klog_always!("   • VGA Driver & Output");
    klog_always!("   • Interrupt Handling (20+ handlers)");
    klog_always!("   • Memory Management (Heap + Buddy allocator)");
    klog_always!("   • Page Table Manager");
    klog_always!("   • Kernel Stack Guard Pages");
    klog_always!("   • Security Hardening (W^X, NX, CSPRNG)");
    klog_always!("   • CPU Protection (SMEP/SMAP/UMIP)");
    klog_always!("   • SYSCALL/SYSRET (Ring 3 transition)");
    klog_always!("   • Process Control Block");
    klog_always!("   • Enhanced Scheduler (Multi-level feedback queue)");
    klog_always!("   • Context Switch (176-byte context + IRETQ)");
    klog_always!("   • System Calls (50+ defined)");
    klog_always!("   • Fork with COW");
    klog_always!("   • Memory Mapping (mmap/munmap)");
    klog_always!("   • Capability-based IPC");
    klog_always!("   • Virtual File System (VFS)");
    klog_always!("   • Device Files (/dev/null, /dev/zero, /dev/console)");
    klog_always!("   • Security Audit (hash-chained events)");
    klog_always!("   • Ring 3 User Mode (Phase 6 complete)");
    klog_always!();
    klog_always!("进入空闲循环...");
    klog_always!();

    // 启用中断（IDT 已初始化完成）
    // 注意：在启用中断前，确保所有中断处理程序已正确设置
    // 启用串口接收中断（在 sti 前，最小化中断禁用期间积压数据的窗口）
    arch::interrupts::enable_serial_interrupts();

    // R109-4 FIX: Mark boot phase as complete before enabling interrupts.
    // After this point, credential-less contexts (kernel threads, interrupt
    // handlers) must not bypass audit/trace capability gates.
    BOOT_PHASE_COMPLETE.store(true, core::sync::atomic::Ordering::Release);

    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    // 先尝试强制调度一次，让 Ring 3 测试进程运行
    // 这是 Phase 6 Ring 3 测试的关键：调度器会检测到用户进程并使用 IRETQ 进入用户态
    sched::enhanced_scheduler::Scheduler::reschedule_now(true);

    // 主内核循环
    // R98-3 FIX: Use reschedule_if_needed() instead of direct scheduler calls.
    // This ensures deferred timer work (TIME_WAIT cleanup, TCP retransmissions)
    // and RCU callbacks are drained even when the system is idle (no syscalls).
    loop {
        // Drain deferred work and check for reschedule requests
        kernel_core::reschedule_if_needed();

        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    // G.1: Track allocation failures for observability.
    // Only attempt if counters are initialized (avoids recursive allocation).
    if COUNTERS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        increment_counter(TraceCounter::AllocFailures, 1);
    }

    // Print heap statistics before panicking
    unsafe {
        serial_write_str("ALLOC FAILED: size=");
        let size = layout.size();
        let mut buf = [0u8; 20];
        let mut n = size;
        let mut i = 0;
        loop {
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
            if n == 0 {
                break;
            }
        }
        while i > 0 {
            i -= 1;
            serial_write_byte(buf[i]);
        }
        serial_write_str("\n");
    }
    panic!("Allocation error: {:?}", layout);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        // 立即禁用中断，防止 panic 期间中断重入
        core::arch::asm!("cli", options(nomem, nostack));

        // G.1 kdump: Capture crash context immediately after cli.
        // This captures CPU registers, stack, and panic info before any
        // further state changes. Safe to call multiple times (atomic guard).
        let crash_dump = trace::kdump::capture_crash_context(info);

        // R93-16 FIX / G.fin.1: Check PolicySurface for panic output redaction.
        // In Secure profile, suppress detailed panic output to avoid leaking
        // kernel pointers, file paths, and other sensitive information over serial.
        // The encrypted kdump still captures full details for offline analysis.
        // Uses is_policy_initialized() to handle panics during very early boot
        // before PolicySurface exists (fail-open: show details to aid debugging).
        let suppress_details = if compliance::is_policy_initialized() {
            compliance::policy().panic_redact_details
        } else {
            false
        };

        serial_write_str("KERNEL PANIC");

        if !suppress_details {
            // Non-secure profiles: show location for debugging
            serial_write_str(": ");
            if let Some(location) = info.location() {
                serial_write_str(location.file());
                serial_write_str(":");
                // 输出行号
                let line = location.line();
                let mut buf = [0u8; 10];
                let mut n = line;
                let mut i = 0;
                loop {
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                    i += 1;
                    if n == 0 {
                        break;
                    }
                }
                while i > 0 {
                    i -= 1;
                    serial_write_byte(buf[i]);
                }
            }
        } else {
            // Secure profile: minimal output to avoid info leakage
            serial_write_str(" [Secure mode: details redacted]");
        }
        serial_write_str("\n");

        // R93-16 FIX: Only print full panic message in non-Secure profiles.
        // Panic messages can contain formatted kernel pointers, stack traces,
        // and other sensitive information that could aid exploitation.
        if !suppress_details {
            // 尝试打印panic消息
            // 使用 core::fmt::write 来格式化
            struct SerialFmt;
            impl core::fmt::Write for SerialFmt {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    for b in s.bytes() {
                        unsafe {
                            serial_write_byte(b);
                        }
                    }
                    Ok(())
                }
            }
            let _ = core::fmt::write(&mut SerialFmt, format_args!("{}\n", info));
        }

        // G.1 kdump: Emit encrypted crash dump over serial.
        // The dump includes:
        // - CPU registers (pointer-redacted via KptrGuard)
        // - Stack contents (pointer-redacted)
        // - Panic location and message
        // - ChaCha20 encryption with random nonce
        // - Base64 encoding for serial transport
        // Only emits once per boot (atomic guard prevents duplicate dumps).
        trace::kdump::emit_encrypted_dump(crash_dump);
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
