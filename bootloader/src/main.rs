#![no_std]
#![no_main]

extern crate alloc;

use log::info;
use uefi::prelude::*;
use uefi::{helpers, CString16};
use uefi::proto::media::file::{File, FileMode, FileAttribute, FileInfo};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{MemoryType, AllocateType};
use alloc::vec;
use xmas_elf::ElfFile;
use xmas_elf::program::Type;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    helpers::init(&mut system_table).unwrap();
    info!("启动 Rust 微内核引导器...");
    
    system_table.stdout().clear().unwrap();
    system_table.stdout()
        .output_string(cstr16!("Rust Microkernel Bootloader v0.1\r\n"))
        .unwrap();
    
    // 加载内核
    info!("正在加载内核...");
    system_table.stdout()
        .output_string(cstr16!("Loading kernel...\r\n"))
        .unwrap();
    
    // 读取并解析内核文件
    let kernel_data = {
        let boot_services = system_table.boot_services();
        
        // 查找文件系统
        let handles = boot_services
            .find_handles::<SimpleFileSystem>()
            .expect("Failed to find file system handles");
        
        let mut kernel_data = None;
        
        for handle in handles {
            // 打开文件系统协议
            let mut fs = boot_services
                .open_protocol_exclusive::<SimpleFileSystem>(handle)
                .expect("Failed to open file system protocol");
            
            // 打开根目录
            let mut root = fs.open_volume().expect("Failed to open volume");
            
            // 尝试打开kernel.elf
            let kernel_path = CString16::try_from("kernel.elf").unwrap();
            
            if let Ok(kernel_file_handle) = root.open(
                &kernel_path,
                FileMode::Read,
                FileAttribute::empty()
            ) {
                // 将FileHandle转换为Regular File
                let mut kernel_file = kernel_file_handle
                    .into_regular_file()
                    .expect("kernel.elf is not a regular file");
                
                // 获取文件大小
                let mut info_buffer = [0u8; 512];
                let info = kernel_file
                    .get_info::<FileInfo>(&mut info_buffer)
                    .expect("Failed to get file info");
                
                let file_size = info.file_size() as usize;
                
                // 读取文件内容
                let mut data = vec![0u8; file_size];
                let bytes_read = kernel_file
                    .read(&mut data)
                    .expect("Failed to read kernel file");
                
                info!("读取内核文件: {} 字节", bytes_read);
                kernel_data = Some(data);
                break;
            }
        }
        
        kernel_data
    };
    
    if let Some(kernel_data) = kernel_data {
        system_table.stdout()
            .output_string(cstr16!("Kernel file loaded, parsing ELF...\r\n"))
            .unwrap();
        
        // 解析ELF文件
        let elf = ElfFile::new(&kernel_data).expect("Failed to parse ELF");
        
        // 获取入口点
        let entry = elf.header.pt2.entry_point();
        info!("内核入口点: 0x{:x}", entry);
        
// 加载ELF段到内存
        {
            let boot_services = system_table.boot_services();
            
            for program_header in elf.program_iter() {
                if program_header.get_type().unwrap() == Type::Load {
                    let virt_addr = program_header.virtual_addr();
                    let mem_size = program_header.mem_size();
                    let file_size = program_header.file_size();
                    let offset = program_header.offset() as usize;
                    
                    // 计算需要的页数
                    let pages = (mem_size + 0xfff) / 0x1000;
                    
                    // 使用AnyPages而不是指定地址，让UEFI选择合适的内存位置
                    let phys_addr = if virt_addr >= 0x100000 {
                        // 如果虚拟地址大于1MB，尝试在指定地址分配
                        boot_services
                            .allocate_pages(
                                AllocateType::Address(virt_addr),
                                MemoryType::LOADER_CODE,
                                pages as usize,
                            )
                            .or_else(|_| {
                                // 如果失败，让UEFI选择地址
                                boot_services.allocate_pages(
                                    AllocateType::AnyPages,
                                    MemoryType::LOADER_CODE,
                                    pages as usize,
                                )
                            })
                            .expect("Failed to allocate pages")
                    } else {
                        // 对于低地址，让UEFI选择合适的位置
                        boot_services
                            .allocate_pages(
                                AllocateType::AnyPages,
                                MemoryType::LOADER_CODE,
                                pages as usize,
                            )
                            .expect("Failed to allocate pages")
                    };
                    
                    // 复制段数据
                    let dest = phys_addr as *mut u8;
                    let src = &kernel_data[offset..offset + file_size as usize];
                    unsafe {
                        dest.copy_from_nonoverlapping(src.as_ptr(), file_size as usize);
                        // 清零BSS段
                        if mem_size > file_size {
                            dest.add(file_size as usize).write_bytes(0, (mem_size - file_size) as usize);
                        }
                    }
                    
                    info!("加载段: 虚拟地址 0x{:x}, 物理地址 0x{:x}, 大小 0x{:x}", 
                        virt_addr, phys_addr, mem_size);
                }
            }
        }


        
        system_table.stdout()
            .output_string(cstr16!("Segments loaded.\r\n"))
            .unwrap();
        
        system_table.stdout()
            .output_string(cstr16!("Press any key to jump to kernel...\r\n"))
            .unwrap();
        
        // 等待按键
        system_table.stdin().reset(false).unwrap();
        let _ = system_table.stdin().read_key().unwrap();
        
        // 退出引导服务
        let (_runtime_system_table, _memory_map) = unsafe {
            system_table.exit_boot_services(MemoryType::LOADER_DATA)
        };
        
        // 跳转到内核
        info!("跳转到内核入口点: 0x{:x}", entry);
        let kernel_main: extern "C" fn() -> ! = unsafe {
            core::mem::transmute(entry as *const ())
        };
        
        kernel_main();
        
    } else {
        system_table.stdout()
            .output_string(cstr16!("ERROR: kernel.elf not found!\r\n"))
            .unwrap();
        
        system_table.stdout()
            .output_string(cstr16!("Please ensure kernel.elf is in ESP root.\r\n"))
            .unwrap();
        
        // 等待按键
        system_table.stdin().reset(false).unwrap();
        let _ = system_table.stdin().read_key().unwrap();
    }
    
    Status::SUCCESS
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("BOOTLOADER PANIC: {}", info);
    loop {}
}
