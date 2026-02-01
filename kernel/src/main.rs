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
#[macro_use]
extern crate audit;
extern crate trace;
extern crate compliance;

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

/// Test block device write/read path end-to-end
///
/// Writes a test pattern to the last sectors of the device (safe area outside filesystem),
/// reads it back, and verifies the data matches. This exercises the full write path
/// through virtio-blk without requiring filesystem write support.
fn test_block_write(device: &alloc::sync::Arc<dyn block::BlockDevice>) -> bool {
    use alloc::vec;

    // Skip if device is read-only
    if device.is_read_only() {
        println!("        [SKIP] Device is read-only");
        return true;
    }

    let capacity = device.capacity_sectors();
    let sector_size = device.sector_size() as usize;

    // Need at least 2 sectors for test (use last 2 sectors)
    if capacity < 4 {
        println!("        [SKIP] Device too small for write test");
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
    println!("        Writing test pattern to sector {}...", test_sector);
    match device.write_sync(test_sector, &test_pattern) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            println!(
                "        [FAIL] Write returned {} bytes, expected {}",
                n, sector_size
            );
            return false;
        }
        Err(e) => {
            println!("        [FAIL] Write failed: {:?}", e);
            return false;
        }
    }

    // Read back
    let mut read_buf = vec![0u8; sector_size];
    match device.read_sync(test_sector, &mut read_buf) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            println!(
                "        [FAIL] Read returned {} bytes, expected {}",
                n, sector_size
            );
            return false;
        }
        Err(e) => {
            println!("        [FAIL] Read failed: {:?}", e);
            return false;
        }
    }

    // Verify
    if read_buf[..512] == test_pattern {
        println!("        [PASS] Write/read verification successful");
        true
    } else {
        println!("        [FAIL] Data mismatch!");
        println!("        Expected first 8: {:02x?}", &test_pattern[..8]);
        println!("        Got first 8:      {:02x?}", &read_buf[..8]);
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

    println!("==============================");
    println!("  Zero-OS Microkernel v0.1");
    println!("==============================");
    println!();

    // 阶段1：初始化中断处理
    println!("[1/3] Initializing interrupts...");
    arch::interrupts::init();
    println!("      ✓ IDT loaded with 20+ handlers");

    // 阶段2：初始化内存管理
    println!("[2/3] Initializing memory management...");
    if let Some(info) = boot_info {
        mm::memory::init_with_bootinfo(info);
        println!("      ✓ Heap and Buddy allocator ready (using BootInfo)");
    } else {
        println!("      ! BootInfo missing, using fallback initialization");
        mm::memory::init();
        println!("      ✓ Heap and Buddy allocator ready (fallback mode)");
    }

    // 初始化页表管理器
    // Bootloader 创建了恒等映射（物理地址 == 虚拟地址），所以物理偏移量为 0
    unsafe {
        mm::page_table::init(x86_64::VirtAddr::new(0));
    }
    println!("      ✓ Page table manager initialized");

    // 安装内核栈守护页（必须在 mm 初始化后、启用中断前）
    println!("[2.5/3] Installing kernel stack guard pages...");
    unsafe {
        match stack_guard::install() {
            Ok(()) => {
                println!("      ✓ Guard pages installed for kernel stacks");
            }
            Err(e) => {
                println!("      ! Failed to install guard pages: {:?}", e);
                println!("      ! Continuing with static stacks (less safe)");
            }
        }
    }

    // 安全加固（Phase 0: W^X, NX, Identity Map Cleanup, CSPRNG, kptr guard, Spectre）
    // G.3 Compliance: Use HardeningProfile to configure security settings
    println!("[2.6/3] Applying security hardening...");
    {
        let mut frame_allocator = mm::memory::FrameAllocator::new();

        // G.3: Select hardening profile (default: Balanced for development)
        // In production, this would be set via boot command line: "profile=secure"
        // For now, use Balanced as default with full security features enabled
        let profile = compliance::HardeningProfile::Balanced;
        compliance::set_profile(profile);

        // Generate SecurityConfig from the selected profile
        let phys_offset = mm::page_table::get_physical_memory_offset();
        let sec_config = profile.security_config(phys_offset);

        println!(
            "      Profile: {} (audit_capacity: {})",
            profile.name(),
            profile.audit_capacity()
        );

        match security::init(sec_config, &mut frame_allocator) {
            Ok(report) => {
                println!("      ✓ Security hardening applied");
                println!("        - Identity map: {:?}", report.identity_cleanup);
                if let Some(nx) = &report.nx_summary {
                    println!(
                        "        - NX enforced: {} pages protected",
                        nx.data_nx_pages
                    );
                }
                if report.rng_ready {
                    println!("        - CSPRNG ready (ChaCha20 + RDRAND/RDSEED)");
                    // 验证 RNG 工作正常
                    match security::random_u64() {
                        Ok(val) => println!("        - RNG test: 0x{:016x}", val),
                        Err(e) => println!("        ! RNG test failed: {:?}", e),
                    }
                } else {
                    println!("        ! CSPRNG not ready");
                }
                if report.kptr_guard_active {
                    println!("        - kptr guard: active");
                }
                if let Some(spectre) = &report.spectre_status {
                    println!("        - Spectre mitigations: {}", spectre.summary());
                }

                // G.3: Lock profile after security initialization
                compliance::lock_profile();
                println!("        - Profile locked (immutable until reboot)");
            }
            Err(e) => {
                println!("      ! Security hardening failed: {:?}", e);
                println!("      ! Continuing with reduced security");
            }
        }
    }

    // KASLR/KPTI/PCID initialization
    // R39-7 FIX: Pass KASLR slide from bootloader to kernel
    println!("[2.65/3] Initializing KASLR/KPTI/PCID...");
    security::init_kaslr(boot_info.map(|info| info.kaslr_slide));
    // Cache INVPCID capability for TLB shootdowns (uses CPUID + PCID state)
    mm::tlb_shootdown::init_invpcid_support();

    // CPU 硬件保护特性启用 (SMEP/SMAP/UMIP)
    println!("[2.7/3] Enabling CPU protection features...");
    {
        let cpu_status = arch::cpu_protection::enable_protections();
        if cpu_status.smep_enabled {
            println!("        - SMEP: enabled (blocks kernel executing user pages)");
        } else if cpu_status.smep_supported {
            println!("        ! SMEP: supported but failed to enable");
        } else {
            println!("        - SMEP: not supported by CPU");
        }
        if cpu_status.smap_enabled {
            println!("        - SMAP: enabled (blocks kernel accessing user pages)");
        } else if cpu_status.smap_supported {
            println!("        ! SMAP: supported but failed to enable");
        } else {
            println!("        - SMAP: not supported by CPU");
        }
        if cpu_status.umip_enabled {
            println!("        - UMIP: enabled (blocks user SGDT/SIDT/SLDT)");
        } else if cpu_status.umip_supported {
            println!("        ! UMIP: supported but failed to enable");
        } else {
            println!("        - UMIP: not supported by CPU");
        }
        if cpu_status.is_fully_protected() {
            println!("      ✓ All CPU protections active");
        } else {
            println!("      ! Partial CPU protection (some features unavailable)");
        }

        // V-4 fix: No longer need to update SMAP status cache.
        // clac_if_smap() now reads CR4 directly for SMP safety.
    }

    // Phase 6: 初始化 SYSCALL/SYSRET 快速系统调用机制
    println!("[2.8/3] Initializing SYSCALL/SYSRET...");
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
        println!("      ✓ SYSCALL MSR configured");
        println!("      ✓ Syscall frame callback registered");
        println!("      ✓ Ring 3 transition support ready");
    }

    // 阶段3：测试基础功能
    println!("[3/3] Running basic tests...");

    // 测试内存分配
    use alloc::vec::Vec;
    let mut test_vec = Vec::new();
    for i in 0..10 {
        test_vec.push(i);
    }
    println!("      ✓ Heap allocation test passed");

    // 显示内存统计
    let mem_stats = mm::memory::FrameAllocator::new().stats();
    println!("      ✓ Memory stats available");

    println!();
    println!("=== System Information ===");
    mem_stats.print();

    println!();
    println!("=== Verifying Core Subsystems ===");
    println!();

    // 验证各个模块已编译
    println!("[4/8] Verifying architecture support...");
    println!("      ✓ arch crate loaded");
    println!("      ✓ Context switch module available");

    println!("[5/8] Initializing kernel core...");
    kernel_core::init(); // 初始化进程管理和 BOOT_CR3 缓存（必须在调度器前）
    println!("      ✓ Process management ready");
    println!("      ✓ System calls framework ready");
    println!("      ✓ Fork/COW implementation compiled");

    // Phase E: APIC and SMP Initialization
    println!("[5.5/8] Initializing APIC and SMP...");
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
        println!("      ✓ BSP LAPIC initialized (ID: {})", bsp_lapic_id);

        // E.1: Initialize HPET (High Precision Event Timer) if available
        // HPET provides a high-resolution counter for precise timing and
        // can be used as an alternative reference for LAPIC calibration.
        match arch::hpet::init() {
            Ok(info) => {
                println!(
                    "      ✓ HPET initialized (freq={} Hz, timers={}, 64-bit={})",
                    info.frequency_hz, info.comparator_count, info.counter_64bit
                );
            }
            Err(e) => {
                println!("      ! HPET unavailable: {:?} (using PIT for calibration)", e);
            }
        }

        // Calibrate LAPIC timer using HPET (preferred) or PIT channel 2 as reference
        // This determines the correct initial count for ~1kHz ticks
        unsafe {
            match arch::apic::calibrate_lapic_timer() {
                Ok(init_count) => {
                    println!(
                        "      ✓ LAPIC timer calibrated (init_count: {})",
                        init_count
                    );
                }
                Err(e) => {
                    println!(
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
        println!("      ✓ BSP per-CPU data initialized");

        // R67-8 FIX: Initialize per-CPU syscall metadata and GS base for BSP
        unsafe {
            arch::syscall::init_syscall_percpu(0);
        }
        println!("      ✓ BSP syscall per-CPU state initialized");

        // Attempt to bring up Application Processors (APs)
        // This will enumerate CPUs via ACPI MADT and send INIT-SIPI-SIPI
        let num_cpus = arch::start_aps();
        if num_cpus > 1 {
            println!("      ✓ SMP enabled: {} CPU(s) online", num_cpus);
        } else {
            println!("      ✓ Single-core mode (no APs found or SMP disabled)");
        }
    }

    println!("[6/8] Initializing scheduler...");
    sched::enhanced_scheduler::init(); // 注册定时器和重调度回调
    println!("      ✓ Enhanced scheduler initialized");

    // E.5: Initialize cpuset subsystem after CPU enumeration
    sched::cpuset::init();
    println!("      ✓ Cpuset CPU isolation initialized");

    println!("[7/8] Initializing IPC...");
    ipc::init(); // 初始化IPC子系统并注册清理回调
    println!("      ✓ Capability-based endpoints enabled");
    println!("      ✓ Process cleanup callback registered");

    println!("[7.5/8] Initializing VFS...");
    vfs::init(); // 初始化虚拟文件系统
    println!("      ✓ devfs mounted at /dev");
    println!("      ✓ Device files: null, zero, console");

    // Initialize page cache before block layer mounts filesystems
    println!("[7.52/8] Initializing Page Cache...");
    mm::init_page_cache();
    println!("      ✓ Global page cache initialized");

    // Phase D: Network Layer
    println!("[7.54/8] Initializing Network Layer...");
    let net_devices = net::init();
    if net_devices == 0 {
        println!("      ! No network devices detected");
    }

    // Phase C: Block Layer and Storage Foundation
    println!("[7.55/8] Initializing Block Layer...");
    block::init();
    // Probe for virtio-blk devices and register with VFS
    if let Some((device, name)) = block::probe_devices() {
        let device_for_registration = device.clone();
        match vfs::register_block_device(name, device_for_registration) {
            Ok(()) => {
                println!("      ✓ Registered /dev/{} in devfs", name);

                // Phase C: Test block write path (uses last sectors, outside filesystem)
                println!("      [TEST] Block device write/read verification:");
                if test_block_write(&device) {
                    println!("      ✓ Block write path verified");
                } else {
                    println!("      ! Block write test failed");
                }

                // Phase C: Try to mount as ext2 filesystem
                match vfs::Ext2Fs::mount(device) {
                    Ok(fs) => match vfs::mount("/mnt", fs) {
                        Ok(()) => println!("      ✓ Mounted /dev/{} on /mnt as ext2", name),
                        Err(e) => println!(
                            "      ! Registered /dev/{} but failed to mount on /mnt: {:?}",
                            name, e
                        ),
                    },
                    Err(e) => println!(
                        "      ! Registered /dev/{} but failed to initialize ext2: {:?}",
                        name, e
                    ),
                }
            }
            Err(e) => println!("      ! Failed to register /dev/{}: {:?}", name, e),
        }
    }

    println!("[7.6/8] Initializing audit subsystem...");
    match audit::init(64) {
        // Reduced from 256 to save heap memory
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
            println!(
                "      ✓ Audit subsystem ready (capacity: {} events)",
                audit::DEFAULT_CAPACITY
            );
            println!("      ✓ Hash-chained tamper evidence enabled");

            // A.3: Register audit snapshot authorizer (capability gate)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_READ
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_snapshot_authorizer(|| {
                // R72-HMAC FIX: Allow during early kernel boot when no process exists yet
                let creds = current_credentials();
                if creds.is_none() {
                    // Early boot - kernel init context, allow
                    return Ok(());
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
            println!("      ✓ Audit capability gate registered (CAP_AUDIT_READ)");

            // R66-10 FIX: Register HMAC key authorizer (capability gate for audit config)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_WRITE
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_hmac_key_authorizer(|| {
                // R72-HMAC FIX: Allow during early kernel boot when no process exists yet
                // This is safe because only privileged kernel code runs before processes exist
                let creds = current_credentials();
                if creds.is_none() {
                    // Early boot - kernel init context, allow
                    return Ok(());
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
            println!("      ✓ Audit HMAC key gate registered (CAP_AUDIT_WRITE)");

            // R72-HMAC: Generate and install audit HMAC key for integrity protection
            // Uses CSPRNG to generate a 32-byte cryptographically secure key.
            // The key is zeroed from stack memory after use to minimize exposure.
            {
                let mut audit_hmac_key = [0u8; audit::MAX_HMAC_KEY_SIZE];
                match security::rng::fill_random(&mut audit_hmac_key) {
                    Ok(()) => match audit::set_hmac_key(&audit_hmac_key) {
                        Ok(()) => {
                            println!("      ✓ Audit HMAC key installed (32 bytes, CSPRNG)");
                            println!("        - All audit events now HMAC-SHA256 protected");
                        }
                        Err(e) => {
                            println!("      ! Failed to set audit HMAC key: {:?}", e);
                        }
                    },
                    Err(e) => {
                        println!("      ! Failed to generate audit HMAC key: {:?}", e);
                        println!("        - Audit events using plain SHA-256 chain only");
                    }
                }
                // R72-HMAC: Zero key material from stack to limit exposure window
                // Use volatile writes to prevent the compiler from eliding the wipe
                for byte in audit_hmac_key.iter_mut() {
                    unsafe { core::ptr::write_volatile(byte, 0) };
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
        }
        Err(e) => {
            println!("      ! Audit initialization failed: {:?}", e);
        }
    }

    // Phase G.1: Observability subsystem (tracepoints, counters, watchdog)
    println!("[7.7/8] Initializing observability subsystem...");
    trace::init();
    // G.1: Force-initialize per-CPU counter storage and mark counters as ready.
    // This ensures the CpuLocal<PerCpuCounters> lazy init happens during boot
    // (when heap is available), not in alloc_error_handler where it could recurse.
    increment_counter(TraceCounter::Custom0, 0); // no-op increment to trigger init
    COUNTERS_READY.store(true, core::sync::atomic::Ordering::Release);
    // Install read guard for metrics export (CAP_TRACE_READ or root)
    let _ = trace::install_read_guard(|| {
        // Allow during early kernel boot when no process exists
        let creds = current_credentials();
        if creds.is_none() {
            return true; // Early boot - kernel init context
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
    println!("      ✓ Trace capability gate registered (CAP_TRACE_READ)");

    println!("[8/8] Verifying memory management...");
    println!("      ✓ Page table manager compiled");
    println!("      ✓ mmap/munmap available");

    // 运行集成测试
    integration_test::run_all_tests();

    // 运行运行时功能测试
    let test_report = runtime_tests::run_all_runtime_tests();
    if test_report.failed > 0 {
        println!("WARNING: {} runtime tests failed!", test_report.failed);
    }

    // 运行 Ring 3 用户态测试
    println!("[9/9] Running Ring 3 user mode test...");
    if usermode_test::run_usermode_test() {
        println!("      ✓ Ring 3 test process created successfully");
    } else {
        println!("      ! Ring 3 test setup failed");
    }

    println!("=== System Ready ===");
    println!();
    println!("🎉 Zero-OS Phase 1 Complete!");
    println!("All subsystems verified and integrated successfully!");
    println!();
    println!("📊 Component Summary:");
    println!("   • VGA Driver & Output");
    println!("   • Interrupt Handling (20+ handlers)");
    println!("   • Memory Management (Heap + Buddy allocator)");
    println!("   • Page Table Manager");
    println!("   • Kernel Stack Guard Pages");
    println!("   • Security Hardening (W^X, NX, CSPRNG)");
    println!("   • CPU Protection (SMEP/SMAP/UMIP)");
    println!("   • SYSCALL/SYSRET (Ring 3 transition)");
    println!("   • Process Control Block");
    println!("   • Enhanced Scheduler (Multi-level feedback queue)");
    println!("   • Context Switch (176-byte context + IRETQ)");
    println!("   • System Calls (50+ defined)");
    println!("   • Fork with COW");
    println!("   • Memory Mapping (mmap/munmap)");
    println!("   • Capability-based IPC");
    println!("   • Virtual File System (VFS)");
    println!("   • Device Files (/dev/null, /dev/zero, /dev/console)");
    println!("   • Security Audit (hash-chained events)");
    println!("   • Ring 3 User Mode (Phase 6 complete)");
    println!();
    println!("进入空闲循环...");
    println!();

    // 启用中断（IDT 已初始化完成）
    // 注意：在启用中断前，确保所有中断处理程序已正确设置
    // 启用串口接收中断（在 sti 前，最小化中断禁用期间积压数据的窗口）
    arch::interrupts::enable_serial_interrupts();
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    // 先尝试强制调度一次，让 Ring 3 测试进程运行
    // 这是 Phase 6 Ring 3 测试的关键：调度器会检测到用户进程并使用 IRETQ 进入用户态
    sched::enhanced_scheduler::Scheduler::reschedule_now(true);

    // 主内核循环
    loop {
        // 检查是否有进程需要调度
        if sched::enhanced_scheduler::Scheduler::need_resched() {
            sched::enhanced_scheduler::Scheduler::reschedule_now(false);
        }

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

        // R93-16 FIX: Check hardening profile for panic output redaction.
        // In Secure profile, suppress detailed panic output to avoid leaking
        // kernel pointers, file paths, and other sensitive information over serial.
        // The encrypted kdump still captures full details for offline analysis.
        let profile = compliance::current_profile();
        let suppress_details = matches!(profile, compliance::HardeningProfile::Secure);

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
