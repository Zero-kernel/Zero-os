use crate::println;
use x86_64::structures::idt:: InterruptStackFrame;

// 系统调用包括subscribe、command、allow等，由内核核心处理
#[derive(Debug)]
pub enum Syscall {
    Exit(i32),
    Write(usize, *const u8, usize),
    Read(usize, *mut u8, usize),
    CreateProcess(*const u8),
    SendMessage(usize, usize, *const u8, usize),
    ReceiveMessage(usize, *mut u8, usize),
}

pub fn init() {
    println!("Syscall handler initialized");
}

pub extern "x86-interrupt" fn syscall_handler(
    _stack_frame: InterruptStackFrame,
    syscall_num: u64,
) {
    let syscall = unsafe { parse_syscall(syscall_num) };
    handle_syscall(syscall);
}

unsafe fn parse_syscall(num: u64) -> Syscall {
    match num {
        0 => Syscall::Exit(0),
        1 => Syscall::Write(1, core::ptr::null(), 0),
        // 添加更多系统调用
        _ => panic!("Unknown syscall: {}", num),
    }
}

fn handle_syscall(syscall: Syscall) {
    match syscall {
        Syscall::Exit(code) => {
            println!("Process exiting with code: {}", code);
            // 终止当前进程
        }
        Syscall::Write(fd, buf, len) => {
            // 处理写入
        }
        _ => {
            println!("Unimplemented syscall: {:?}", syscall);
        }
    }
}
