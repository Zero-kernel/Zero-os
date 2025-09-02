#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]

extern crate alloc;

mod memory;
mod process;
mod ipc;
mod syscall;
mod scheduler;
mod interrupts;

use core::panic::PanicInfo;
use x86_64::instructions::hlt;

// 内核入口点
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 初始化内核
    kernel_init();
    
    // 启动调度器
    scheduler::init();
    scheduler::run();
    
    // 不应该到达这里
    loop {
        hlt();
    }
}

fn kernel_init() {
    // 初始化串口输出
    unsafe {
        SERIAL.lock().init();
    }
    
    println!("Initializing Rust Microkernel...");
    
    // 初始化内存管理
    memory::init();
    
    // 初始化中断处理
    interrupts::init();
    
    // 初始化系统调用
    syscall::init();
    
    // 初始化IPC
    ipc::init();
    
    println!("Kernel initialization complete!");
}

// 串口输出
use spin::Mutex;
use uart_16550::SerialPort;

lazy_static::lazy_static! {
    static ref SERIAL: Mutex<SerialPort> = {
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    SERIAL.lock().write_fmt(args).unwrap();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("Kernel panic: {}", info);
    loop {
        hlt();
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation error: {:?}", layout)
}
