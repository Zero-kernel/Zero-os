#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

mod vga_buffer;
mod interrupts;
mod memory;
mod process;
mod scheduler;
mod syscall;
mod ipc;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 先输出一个简单的消息
    vga_buffer::print_something();
    
    // 停机循环
    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}