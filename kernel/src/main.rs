#![no_std]
#![no_main]

use core::panic::PanicInfo;

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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        // 初始化串口
        outb(SERIAL_PORT + 1, 0x00);    // 禁用中断
        outb(SERIAL_PORT + 3, 0x80);    // 设置波特率除数
        outb(SERIAL_PORT + 0, 0x03);    // 设置波特率为38400
        outb(SERIAL_PORT + 1, 0x00);    
        outb(SERIAL_PORT + 3, 0x03);    // 8位，无奇偶校验，1停止位
        outb(SERIAL_PORT + 2, 0xC7);    // 启用FIFO
        outb(SERIAL_PORT + 4, 0x0B);    // 启用中断，设置RTS/DSR
        
        // 发送消息到串口
        serial_write_str("KERNEL: Started!\n");
        
        // 同时尝试写入VGA
        let vga = 0xb8000 as *mut u16;
        
        // 清屏
        for i in 0..(80 * 25) {
            *vga.offset(i) = 0x0720; // 空格，白色前景，黑色背景
        }
        
        // 写入消息
        let msg = b"KERNEL OK";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.offset(i as isize) = (byte as u16) | 0x0A00; // 绿色
        }
        
        serial_write_str("KERNEL: VGA write attempted\n");
    }
    
    // 无限循环
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        serial_write_str("KERNEL PANIC: ");
        if let Some(location) = info.location() {
            // 简单地输出位置信息
            serial_write_str(location.file());
        }
        serial_write_str("\n");
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
