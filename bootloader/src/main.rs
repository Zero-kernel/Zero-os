#![no_std]
#![no_main]

extern crate alloc;

use log::info;
use uefi::prelude::*;
use uefi::{CStr16, helpers};

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // 使用新的初始化方式（替代 uefi_services::init）
    helpers::init(&mut system_table).unwrap();
    
    info!("启动 Rust 微内核引导器...");
    
    // 清屏
    system_table.stdout().clear().unwrap();
    
    // 打印欢迎信息
    system_table.stdout()
        .output_string(cstr16!("Rust Microkernel Bootloader v0.1\r\n"))
        .unwrap();
    
    system_table.stdout()
        .output_string(cstr16!("UEFI Boot Services Initialized\r\n"))
        .unwrap();
    
    info!("UEFI 初始化成功");
    
    // 暂时停在这里
    system_table.stdout()
        .output_string(cstr16!("System ready. Press any key to continue...\r\n"))
        .unwrap();
    
    // 等待按键
    system_table.stdin().reset(false).unwrap();
    let _ = system_table
        .stdin()
        .read_key()
        .unwrap();
    
    system_table.stdout()
        .output_string(cstr16!("Shutting down...\r\n"))
        .unwrap();
    
    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

