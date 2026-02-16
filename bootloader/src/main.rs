#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID};
use uefi::CStr16;
use uefi::Identify;
use xmas_elf::program::Type;
use xmas_elf::ElfFile;

// ============================================================================
// R39-7 FIX: KASLR Configuration
// ============================================================================

/// Kernel load base physical address (matches kernel/security/kaslr.rs)
const KERNEL_PHYS_BASE: u64 = 0x100000;

/// Maximum KASLR slide (512 MiB, within the 1GB high-half mapping)
const KASLR_MAX_SLIDE: u64 = 512 * 1024 * 1024;

/// KASLR slide granularity (2 MiB aligned for huge page compatibility)
const KASLR_SLIDE_GRANULARITY: u64 = 2 * 1024 * 1024;

/// Generate a random KASLR slide using RDRAND
///
/// Returns 0 if RDRAND is unavailable or fails
///
/// # Note (R39-7)
///
/// KASLR is currently disabled because the kernel is not compiled as
/// position-independent code (PIE). The kernel has absolute addresses
/// that don't work when relocated. To enable KASLR, the kernel must be:
/// 1. Compiled with -C relocation-model=pie
/// 2. Have relocation information in the ELF
/// 3. Have the bootloader apply relocations at load time
///
/// The infrastructure is in place for future PIE kernel support.
fn generate_kaslr_slide() -> u64 {
    // R39-7: KASLR disabled - kernel is not PIE
    // TODO: Enable once kernel is built as PIE with relocation support
    #[cfg(feature = "kaslr")]
    {
        let max_slots = KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY;
        if max_slots == 0 {
            return 0;
        }

        let mut val: u64 = 0;
        let success: u8;

        // Use RDRAND instruction to get random value
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {success}",
                val = out(reg) val,
                success = out(reg_byte) success,
                options(nostack, nomem),
            );
        }

        if success == 1 {
            // Generate slide as multiple of granularity
            (val % (max_slots + 1)) * KASLR_SLIDE_GRANULARITY
        } else {
            // RDRAND failed, disable KASLR
            0
        }
    }

    #[cfg(not(feature = "kaslr"))]
    {
        // KASLR disabled: return 0 slide
        0
    }
}

/// Locate the ACPI RSDP via the UEFI configuration table.
///
/// Prefers ACPI 2.0 GUID, falls back to ACPI 1.0 GUID if not available.
/// Returns 0 if RSDP cannot be found.
fn find_rsdp_address(system_table: &SystemTable<Boot>) -> u64 {
    // Try ACPI 2.0 first (preferred)
    for entry in system_table.config_table() {
        if entry.guid == ACPI2_GUID {
            let addr = entry.address as usize as u64;
            info!("ACPI 2.0 RSDP found at 0x{:x}", addr);
            return addr;
        }
    }

    // Fall back to ACPI 1.0
    for entry in system_table.config_table() {
        if entry.guid == ACPI_GUID {
            let addr = entry.address as usize as u64;
            info!("ACPI 1.0 RSDP found at 0x{:x}", addr);
            return addr;
        }
    }

    info!("ACPI RSDP not found in UEFI configuration table");
    0
}

/// P1-1: Read UEFI load options (boot command line) into a fixed-size ASCII buffer.
///
/// UEFI load options are UCS-2 (little-endian u16) encoded. This function
/// down-converts ASCII-range code points to single bytes (non-ASCII → `?`)
/// and truncates to 256 bytes. Returns `(len, buffer)`.
///
/// Must be called **before** `exit_boot_services()` — the LoadedImage
/// protocol becomes inaccessible after that point.
fn read_uefi_cmdline(handle: Handle, system_table: &SystemTable<Boot>) -> (usize, [u8; 256]) {
    let mut cmdline = [0u8; 256];
    let mut cmdline_len = 0usize;

    let boot_services = system_table.boot_services();
    if let Ok(loaded_image) = boot_services.open_protocol_exclusive::<LoadedImage>(handle) {
        if let Some(bytes) = loaded_image.load_options_as_bytes() {
            // UCS-2 little-endian: each character is 2 bytes (lo, hi).
            let mut i = 0;
            while i + 1 < bytes.len() && cmdline_len < cmdline.len() {
                let lo = bytes[i];
                let hi = bytes[i + 1];
                i += 2;
                // Stop at NUL terminator
                if lo == 0 && hi == 0 {
                    break;
                }
                // ASCII range: hi == 0 && lo <= 0x7F
                cmdline[cmdline_len] = if hi == 0 && lo <= 0x7F { lo } else { b'?' };
                cmdline_len += 1;
            }
        }
    }

    (cmdline_len, cmdline)
}

/// 内存映射信息，传递给内核
#[repr(C)]
pub struct MemoryMapInfo {
    pub buffer: u64,             // 内存映射缓冲区地址
    pub size: usize,             // 缓冲区大小
    pub descriptor_size: usize,  // 每个描述符的大小
    pub descriptor_version: u32, // 描述符版本
}

/// 像素格式
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum PixelFormat {
    /// RGB (8位红, 8位绿, 8位蓝, 8位保留)
    Rgb = 0,
    /// BGR (8位蓝, 8位绿, 8位红, 8位保留)
    Bgr = 1,
    /// 未知格式
    Unknown = 2,
}

/// 帧缓冲区信息 (GOP framebuffer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// 帧缓冲区物理地址
    pub base: u64,
    /// 帧缓冲区大小（字节）
    pub size: usize,
    /// 水平分辨率（像素）
    pub width: u32,
    /// 垂直分辨率（像素）
    pub height: u32,
    /// 每行的字节数（stride）
    pub stride: u32,
    /// 像素格式
    pub pixel_format: PixelFormat,
}

/// 引导信息结构，传递给内核
#[repr(C)]
pub struct BootInfo {
    pub memory_map: MemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    /// R39-7 FIX: KASLR slide value (0 if KASLR disabled)
    pub kaslr_slide: u64,
    /// ACPI RSDP physical address (from UEFI configuration table)
    pub rsdp_address: u64,
    /// P1-1: UEFI boot command line length in bytes (ASCII, max 256).
    pub cmdline_len: usize,
    /// P1-1: UEFI boot command line buffer (ASCII, NUL-padded).
    pub cmdline: [u8; 256],
}

#[entry]
fn efi_main(handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();

    info!("Rust Microkernel Bootloader v0.1");
    info!("Initializing...");

    // R39-7 FIX: Get entry point, KASLR slide, and kernel size from loading block
    // Codex Review Fix: kernel_size needed for accurate page table setup
    let (entry_point, kaslr_slide, kernel_size) =
        {
            let boot_services = system_table.boot_services();

            let fs_handle = boot_services
                .locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(
                    &SimpleFileSystem::GUID,
                ))
                .expect("Failed to locate file system handles");

            let fs_handle = fs_handle[0];

            let mut fs = boot_services
                .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
                .expect("Failed to open file system protocol");

            let mut root_dir = fs.open_volume().expect("Failed to open root directory");

            info!("Loading kernel...");
            let kernel_path = CStr16::from_u16_with_nul(&[
                b'k' as u16,
                b'e' as u16,
                b'r' as u16,
                b'n' as u16,
                b'e' as u16,
                b'l' as u16,
                b'.' as u16,
                b'e' as u16,
                b'l' as u16,
                b'f' as u16,
                0,
            ])
            .unwrap();

            let mut kernel_file = root_dir
                .open(kernel_path, FileMode::Read, FileAttribute::empty())
                .expect("Failed to open kernel.elf")
                .into_regular_file()
                .expect("kernel.elf is not a regular file");

            let mut info_buffer = [0u8; 512];
            let info = kernel_file
                .get_info::<FileInfo>(&mut info_buffer)
                .expect("Failed to get file info");

            let file_size = info.file_size() as usize;

            let mut kernel_data = Vec::with_capacity(file_size);
            kernel_data.resize(file_size, 0);

            // 循环读取直到完整读取整个文件
            let mut total_read = 0usize;
            while total_read < file_size {
                let read_size = kernel_file
                    .read(&mut kernel_data[total_read..])
                    .expect("Failed to read kernel file");

                if read_size == 0 {
                    // 读取返回0但文件未读完，说明发生了截断
                    panic!(
                        "Kernel file read truncated: expected {} bytes, got {} bytes",
                        file_size, total_read
                    );
                }
                total_read += read_size;
            }

            info!("Kernel loaded: {} bytes", total_read);

            info!("Parsing ELF...");
            let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF file");

            let entry_point = elf.header.pt2.entry_point();
            info!("Entry point: 0x{:x}", entry_point);

            assert_eq!(
                elf.header.pt1.magic,
                [0x7f, 0x45, 0x4c, 0x46],
                "Invalid ELF magic"
            );

            // 首先，计算内核需要的总内存大小
            let mut min_addr = u64::MAX;
            let mut max_addr = 0u64;

            for program_header in elf.program_iter() {
                if program_header.get_type() != Ok(Type::Load) {
                    continue;
                }
                let virt_addr = program_header.virtual_addr();
                let mem_size = program_header.mem_size();

                if virt_addr < min_addr {
                    min_addr = virt_addr;
                }
                if virt_addr + mem_size > max_addr {
                    max_addr = virt_addr + mem_size;
                }
            }

            // 分配一块连续的内存来容纳整个内核
            // A.4 KASLR: Generate slide value for future PIE support, but always
            // allocate at fixed address since page tables assume fixed mapping.
            // When kaslr feature is enabled AND kernel is compiled as PIE:
            // - generate_kaslr_slide() returns random 2MB-aligned value
            // - Bootloader applies ELF relocations
            // - Page tables are set up with slide offset
            // Until then, slide is always 0 and kernel loads at fixed address.
            let kaslr_slide = generate_kaslr_slide();
            let kernel_phys_base = KERNEL_PHYS_BASE; // Always fixed until PIE support
            let kernel_size = (max_addr - min_addr) as usize;
            let pages = (kernel_size + 0xFFF) / 0x1000;

            info!(
                "Allocating {} pages ({} bytes) for kernel at 0x{:x} (KASLR slide=0x{:x})",
                pages, kernel_size, kernel_phys_base, kaslr_slide
            );

            // Allocate at fixed address (KASLR address randomization requires PIE)
            let result = boot_services.allocate_pages(
                AllocateType::Address(kernel_phys_base),
                MemoryType::LOADER_DATA,
                pages,
            );

            let actual_phys_base = match result {
                Ok(_) => kernel_phys_base,
                Err(status) => {
                    panic!(
                        "FATAL: Cannot allocate kernel memory at 0x{:x}: {:?}. \
                        Page table mappings require kernel at this fixed address. \
                        Ensure no UEFI runtime or reserved regions overlap.",
                        kernel_phys_base, status
                    );
                }
            };

            info!("Kernel memory allocated at 0x{:x}", actual_phys_base);

            // 清零整块内存
            unsafe {
                core::ptr::write_bytes(actual_phys_base as *mut u8, 0, kernel_size);
            }

            // 加载所有程序段到物理地址 0x100000
            for program_header in elf.program_iter() {
                if program_header.get_type() != Ok(Type::Load) {
                    continue;
                }

                let virt_addr = program_header.virtual_addr();
                let mem_size = program_header.mem_size();
                let file_size = program_header.file_size();
                let file_offset = program_header.offset();

                // R24-10 fix: Validate that file_offset + file_size doesn't exceed kernel_data bounds
                // A malformed ELF could have segments pointing beyond the file, causing OOB read
                let file_end = file_offset
                    .checked_add(file_size)
                    .expect("ELF segment offset+size overflow");
                if file_end as usize > kernel_data.len() {
                    panic!(
                    "ELF segment out of bounds: offset=0x{:x}, file_size=0x{:x}, file_len=0x{:x}",
                    file_offset, file_size, kernel_data.len()
                );
                }

                // 计算物理地址：虚拟地址 - 虚拟基址 + 物理基址
                // 虚拟基址是 min_addr (0xffffffff80000000)，物理基址是 actual_phys_base (0x100000)
                let phys_addr = actual_phys_base + (virt_addr - min_addr);

                // 清零整个段内存区域（包括.bss）
                unsafe {
                    let dest = phys_addr as *mut u8;
                    core::ptr::write_bytes(dest, 0, mem_size as usize);
                }

                // 复制段数据（file_size可能小于mem_size，剩余部分已清零）
                if file_size > 0 {
                    unsafe {
                        let dest = phys_addr as *mut u8;
                        let src = kernel_data.as_ptr().add(file_offset as usize);
                        core::ptr::copy_nonoverlapping(src, dest, file_size as usize);
                    }
                }

                info!(
                    "Loaded segment: virt=0x{:x}, phys=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                    virt_addr, phys_addr, file_size, mem_size
                );
            }

            // 验证内核代码已加载到物理地址
            unsafe {
                let kernel_start = actual_phys_base as *const u8;
                let first_bytes = core::slice::from_raw_parts(kernel_start, 16);
                info!(
                    "First 16 bytes at phys 0x{:x}: {:x?}",
                    actual_phys_base, first_bytes
                );
            }

            // 链接脚本现在将入口点设置为 0xffffffff80100000
            // 这对应物理地址 0x100000，通过页表映射正确
            // R39-7 FIX: Apply KASLR slide to entry point
            let adjusted_entry = entry_point + kaslr_slide;
            info!(
                "Using ELF entry point: 0x{:x} (slide applied: 0x{:x}, final: 0x{:x})",
                entry_point, kaslr_slide, adjusted_entry
            );
            (adjusted_entry, kaslr_slide, kernel_size) // R39-7: Return entry, slide, and size
        };

    // 测试 VGA 缓冲区是否可访问 - 在 info! 之前
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + i as isize * 2 + 1) = 0x0E;
        }
    }

    info!("Automatically jumping to kernel...");

    // Find ACPI RSDP before exiting boot services (EFI config table won't be accessible after)
    let rsdp_address = find_rsdp_address(&system_table);

    // P1-1: Read UEFI load options (boot command line) before exiting boot services.
    // The LoadedImage protocol is inaccessible after exit_boot_services().
    let (cmdline_len, cmdline) = read_uefi_cmdline(handle, &system_table);
    if cmdline_len > 0 {
        info!("Boot cmdline ({} bytes): {:?}",
              cmdline_len,
              core::str::from_utf8(&cmdline[..cmdline_len]).unwrap_or("<invalid>"));
    }

    // 分配 BootInfo 结构的内存（在低于 4GiB 的位置，便于恒等映射访问）
    let boot_info_ptr = {
        let boot_services = system_table.boot_services();
        let boot_info_page = boot_services
            .allocate_pages(
                AllocateType::MaxAddress(0xFFFF_FFFF),
                MemoryType::LOADER_DATA,
                1,
            )
            .expect("Failed to allocate boot info page");
        boot_info_page as *mut BootInfo
    };

    // 构建四级页表结构，将物理内核地址映射到高半区虚拟地址
    let (_pml4_frame, entry_point_to_jump) = unsafe {
        // 最早的 VGA 写入 - 在任何其他操作之前
        let vga = 0xb8000 as *mut u8;
        let msg = b"SETUP";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 22 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 22 * 2 + i as isize * 2 + 1) = 0x09;
        }
        use x86_64::{
            registers::control::Cr3,
            structures::paging::{PageTable, PageTableFlags as Flags, PhysFrame},
            PhysAddr,
        };

        let boot_services = system_table.boot_services();

        // 分配并清零 PML4
        let pml4_frame = boot_services
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PML4");
        let pml4_ptr = pml4_frame as *mut PageTable;
        core::ptr::write_bytes(pml4_ptr as *mut u8, 0, 4096);

        // 分配并清零 PDPT（高半区）
        let pdpt_high_frame = boot_services
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PDPT");
        let pdpt_high_ptr = pdpt_high_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_high_ptr as *mut u8, 0, 4096);

        // 分配并清零 PD
        let pd_frame = boot_services
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate PD");
        let pd_ptr = pd_frame as *mut PageTable;
        core::ptr::write_bytes(pd_ptr as *mut u8, 0, 4096);

        // 使用2MB大页映射内核
        // 虚拟地址 0xffffffff80000000 映射到物理地址 0
        // 由于使用2MB大页，必须从2MB边界开始，所以实际映射：
        // 虚拟 0xffffffff80000000 → 物理 0x0
        //
        // A.4 KASLR NOTE: True KASLR requires Position Independent Executable (PIE)
        // compilation. The current kernel uses absolute addresses that cannot be
        // relocated. The kaslr_slide value is calculated and passed to the kernel
        // for informational purposes, but physical memory layout is not randomized.
        //
        // To enable true KASLR, the kernel must be:
        // 1. Compiled with -C relocation-model=pie
        // 2. Have relocation sections (.rela.dyn) in the ELF
        // 3. Bootloader must apply ELF relocations at load time
        //
        // The high-half mapping MUST remain at virtual→physical offset 0xffffffff80000000→0
        // because PHYSICAL_MEMORY_OFFSET is used throughout the kernel for phys_to_virt().
        //
        // W^X 安全说明：
        // - Calculate which PD entries contain the kernel
        //   只有包含内核的条目设为可执行，其他设为 NX
        //   由于 2MB 粒度太粗，无法正确分离代码和数据
        //   暂时保持 RWX，由内核启动后通过 enforce_nx_for_kernel() 拆分为 4KB 页
        let kernel_phys_start = KERNEL_PHYS_BASE; // A.4: Fixed at 0x100000 until PIE is implemented
        let kernel_phys_end = kernel_phys_start + (kernel_size as u64);
        let start_pd_idx = (kernel_phys_start / 0x200000) as usize;
        let end_pd_idx = ((kernel_phys_end + 0x1FFFFF) / 0x200000) as usize; // Round up

        for i in 0..512usize {
            let phys_addr = PhysAddr::new((i as u64) * 0x200000);
            let flags = if i >= start_pd_idx && i <= end_pd_idx {
                // Kernel code/data region: RWX for now, hardened by kernel later
                Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE
            } else {
                // Non-kernel region: writable but not executable
                Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE | Flags::NO_EXECUTE
            };
            (&mut *pd_ptr)[i].set_addr(phys_addr, flags);
        }

        // PDPT的第510项指向PD（对应虚拟地址的第30-38位）
        // Maps virtual 0xffffffff80000000-0xffffffffbfffffff (1GB) to physical 0x0-0x3fffffff
        (&mut *pdpt_high_ptr)[510].set_addr(
            PhysAddr::new(pd_frame as u64),
            Flags::PRESENT | Flags::WRITABLE,
        );

        // PML4的第511项指向高半区PDPT
        (&mut *pml4_ptr)[511].set_addr(
            PhysAddr::new(pdpt_high_frame as u64),
            Flags::PRESENT | Flags::WRITABLE,
        );

        // 建立恒等映射以防止切换页表时崩溃
        let pdpt_low_frame = boot_services
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("Failed to allocate low PDPT");
        let pdpt_low_ptr = pdpt_low_frame as *mut PageTable;
        core::ptr::write_bytes(pdpt_low_ptr as *mut u8, 0, 4096);

        // 恒等映射前 4GB（需要4个PD，每个PD映射1GB）
        // 这样可以确保 bootloader 代码、UEFI 固件、硬件MMIO（包括APIC在0xfee00000）都能访问
        //
        // 安全说明：
        // - 暂时保持 RWX 以确保 bootloader 可以正常运行
        // - 内核启动后通过 security::cleanup_identity_map() 将其加固为 RO+NX
        // - 这是一个已知的启动阶段安全妥协
        for pdpt_idx in 0..4usize {
            let pd_low_frame = boot_services
                .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
                .expect("Failed to allocate low PD");
            let pd_low_ptr = pd_low_frame as *mut PageTable;
            core::ptr::write_bytes(pd_low_ptr as *mut u8, 0, 4096);

            // 每个PD映射512个2MB页（1GB）
            for i in 0..512usize {
                let phys_addr = PhysAddr::new(((pdpt_idx * 512 + i) as u64) * 0x200000);
                (&mut *pd_low_ptr)[i].set_addr(
                    phys_addr,
                    Flags::PRESENT | Flags::WRITABLE | Flags::HUGE_PAGE,
                );
            }

            (&mut *pdpt_low_ptr)[pdpt_idx].set_addr(
                PhysAddr::new(pd_low_frame as u64),
                Flags::PRESENT | Flags::WRITABLE,
            );
        }

        (&mut *pml4_ptr)[0].set_addr(
            PhysAddr::new(pdpt_low_frame as u64),
            Flags::PRESENT | Flags::WRITABLE,
        );

        // 设置递归页表槽 (PML4[510] → PML4 自身)
        // 这允许通过特殊虚拟地址访问任何页表帧，无论其物理地址在哪里
        // 递归映射虚拟地址计算：
        //   PML4:  0xFFFFFF7FBFDFE000
        //   PDPT:  0xFFFFFF7FBFC00000 + pml4_idx * 0x1000
        //   PD:    0xFFFFFF7F80000000 + pml4_idx * 0x200000 + pdpt_idx * 0x1000
        //   PT:    0xFFFFFF0000000000 + pml4_idx * 0x40000000 + pdpt_idx * 0x200000 + pd_idx * 0x1000
        //
        // L-6 fix: Add NO_EXECUTE flag to prevent code execution from page table pages.
        // This is defense-in-depth: even if an attacker can write to page tables via
        // the recursive mapping, they cannot execute code from them.
        (&mut *pml4_ptr)[510].set_addr(
            PhysAddr::new(pml4_frame as u64),
            Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE,
        );

        // 在切换前写 VGA 测试
        let vga = 0xb8000 as *mut u8;
        let msg1 = b"B4CR3";
        for (i, &byte) in msg1.iter().enumerate() {
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + i as isize * 2), byte);
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + i as isize * 2 + 1), 0x0A);
        }

        // 加载新的页表
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(pml4_frame as u64)),
            Cr3::read().1,
        );

        // 在切换后写 VGA 测试
        let msg2 = b"AFCR3";
        for (i, &byte) in msg2.iter().enumerate() {
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + (i + 6) as isize * 2), byte);
            core::ptr::write_volatile(vga.offset(80 * 23 * 2 + (i + 6) as isize * 2 + 1), 0x0C);
        }

        (pml4_frame, entry_point)
    };

    // 获取 GOP 帧缓冲区信息（必须在 exit_boot_services 之前）
    let framebuffer_info = {
        let boot_services = system_table.boot_services();
        let gop_handle = boot_services
            .get_handle_for_protocol::<GraphicsOutput>()
            .expect("Failed to get GOP handle");
        let mut gop = boot_services
            .open_protocol_exclusive::<GraphicsOutput>(gop_handle)
            .expect("Failed to open GOP");

        let mode_info = gop.current_mode_info();
        let (width, height) = mode_info.resolution();
        let stride = mode_info.stride() as u32;

        let pixel_format = match mode_info.pixel_format() {
            GopPixelFormat::Rgb => PixelFormat::Rgb,
            GopPixelFormat::Bgr => PixelFormat::Bgr,
            _ => PixelFormat::Unknown,
        };

        let mut fb = gop.frame_buffer();
        let fb_base = fb.as_mut_ptr() as u64;
        let fb_size = fb.size();

        info!(
            "GOP framebuffer: {}x{}, stride={}, format={:?}",
            width, height, stride, pixel_format
        );
        info!("Framebuffer at 0x{:x}, size {} bytes", fb_base, fb_size);

        FramebufferInfo {
            base: fb_base,
            size: fb_size,
            width: width as u32,
            height: height as u32,
            stride,
            pixel_format,
        }
    };

    // 预先分配一块低地址缓冲区，用于在退出后保存内存映射副本，确保恒等映射可访问
    // 64 页（256 KiB）足以容纳常见的内存映射
    let (memory_map_copy_ptr, memory_map_copy_len) = {
        let pages = 64usize;
        let addr = system_table
            .boot_services()
            .allocate_pages(
                AllocateType::MaxAddress(0xFFFF_FFFF),
                MemoryType::LOADER_DATA,
                pages,
            )
            .expect("Failed to allocate low memory map copy buffer");
        (addr as *mut u8, pages * 0x1000)
    };

    // 退出 UEFI 引导服务，获取最终的内存映射
    // 这必须在页表设置之后、跳转之前完成
    let memory_map = unsafe {
        let (_runtime_system_table, memory_map) =
            system_table.exit_boot_services(MemoryType::LOADER_DATA);
        memory_map
    };

    // 将内存映射信息填充到 BootInfo 结构中
    // 需要将内存映射复制到低于4GiB的缓冲区，因为原始映射可能在高地址
    unsafe {
        let (memory_map_bytes, memory_map_meta) = memory_map.as_raw();

        // 确保预分配的缓冲区足够大
        assert!(
            memory_map_meta.map_size <= memory_map_copy_len,
            "Memory map larger than reserved copy buffer"
        );

        // 复制内存映射到低地址缓冲区
        core::ptr::copy_nonoverlapping(
            memory_map_bytes.as_ptr(),
            memory_map_copy_ptr,
            memory_map_meta.map_size,
        );

        *boot_info_ptr = BootInfo {
            memory_map: MemoryMapInfo {
                buffer: memory_map_copy_ptr as u64,
                size: memory_map_meta.map_size,
                descriptor_size: memory_map_meta.desc_size,
                descriptor_version: memory_map_meta.desc_version,
            },
            framebuffer: framebuffer_info,
            kaslr_slide,  // R39-7 FIX: Pass KASLR slide to kernel
            rsdp_address, // ACPI RSDP for SMP CPU enumeration
            cmdline_len,  // P1-1: Boot command line
            cmdline,
        };
        // 阻止 memory_map 被释放，因为内核需要访问它
        core::mem::forget(memory_map);
    }

    // 跳转到内核入口点 - 使用内联汇编确保正确跳转
    // 通过 rdi 传递 BootInfo 指针（System V AMD64 ABI 第一个参数）
    unsafe {
        core::arch::asm!(
            "mov rdi, {boot_info}",
            "jmp {entry}",
            boot_info = in(reg) boot_info_ptr as u64,
            entry = in(reg) entry_point_to_jump,
            options(noreturn)
        );
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("BOOTLOADER PANIC: {}", info);

    // 在屏幕上显示 panic
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT PANIC!";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize * 2) = byte;
            *vga.offset(i as isize * 2 + 1) = 0x4F;
        }
    }

    loop {}
}
