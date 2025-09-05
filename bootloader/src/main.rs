#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use log::info;
use uefi::prelude::*;
use uefi::proto::console::text::{Key, ScanCode};
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::CStr16;
use uefi::Identify;
use xmas_elf::program::Type;
use xmas_elf::ElfFile;

#[entry]
fn efi_main(_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();
    
    info!("Rust Microkernel Bootloader v0.1");
    info!("Initializing...");
    
    let entry_point = {
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
        let kernel_path = CStr16::from_u16_with_nul(
            &[
                b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, 
                b'e' as u16, b'l' as u16, b'.' as u16, b'e' as u16,
                b'l' as u16, b'f' as u16, 0,
            ]
        ).unwrap();

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
        
        let read_size = kernel_file
            .read(&mut kernel_data)
            .expect("Failed to read kernel file");
        
        info!("Kernel size: {} bytes", read_size);

        info!("Parsing ELF...");
        let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF file");
        
        let entry_point = elf.header.pt2.entry_point();
        info!("Entry point: 0x{:x}", entry_point);
        
        assert_eq!(elf.header.pt1.magic, [0x7f, 0x45, 0x4c, 0x46], "Invalid ELF magic");

        // 加载所有程序段
        for program_header in elf.program_iter() {
            if program_header.get_type() != Ok(Type::Load) {
                continue;
            }

            let virt_addr = program_header.virtual_addr();
            let mem_size = program_header.mem_size();
            let file_size = program_header.file_size();
            let file_offset = program_header.offset();

            let pages = ((mem_size + 0xFFF) / 0x1000) as usize;
            
            // 尝试在指定地址分配
            let _ = boot_services.allocate_pages(
                AllocateType::Address(virt_addr),
                MemoryType::LOADER_DATA,
                pages,
            );
            
            // 复制段数据
            unsafe {
                let dest = virt_addr as *mut u8;
                let src = kernel_data.as_ptr().add(file_offset as usize);
                core::ptr::copy_nonoverlapping(src, dest, file_size as usize);
                
                if mem_size > file_size {
                    let bss_start = dest.add(file_size as usize);
                    let bss_size = (mem_size - file_size) as usize;
                    core::ptr::write_bytes(bss_start, 0, bss_size);
                }
            }
            
            info!("Loaded segment: 0x{:x}, size: 0x{:x}", virt_addr, mem_size);
        }

        // 验证内核代码已加载
        unsafe {
            let kernel_start = entry_point as *const u8;
            let first_bytes = core::slice::from_raw_parts(kernel_start, 16);
            info!("First 16 bytes at entry: {:x?}", first_bytes);
        }
        
        entry_point
    };
    
    info!("Press any key to jump to kernel...");
    wait_for_key(&mut system_table);
    
    // 测试 VGA 缓冲区是否可访问
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg = b"BOOT->";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(80 * 24 * 2 + i as isize * 2) = byte;
            *vga.offset(80 * 24 * 2 + i as isize * 2 + 1) = 0x0E;
        }
    }
    
    info!("Jumping to kernel at 0x{:x}...", entry_point);
    
    // 跳转到内核
    unsafe {
        type KernelMain = extern "C" fn() -> !;
        let kernel_main: KernelMain = core::mem::transmute(entry_point);
        kernel_main();
    }
}

fn wait_for_key(system_table: &mut SystemTable<Boot>) {
    let mut events = [system_table.stdin().wait_for_key_event().unwrap()];
    let _ = system_table
        .boot_services()
        .wait_for_event(&mut events);
        
    let _ = system_table.stdin().reset(false);
    
    match system_table.stdin().read_key() {
        Ok(Some(Key::Special(ScanCode::ESCAPE))) => {},
        _ => {}
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
