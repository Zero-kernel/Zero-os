use crate::println;
use alloc::{vec::Vec, string::String};
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: usize,
    pub name: String,
    pub state: ProcessState,
    pub memory_space: usize, // 简化的内存空间表示
    pub context: Context,
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl Process {
    pub fn new(pid: usize, name: String) -> Self {
        Process {
            pid,
            name,
            state: ProcessState::Ready,
            memory_space: 0,
            context: Context::default(),
        }
    }
}

lazy_static::lazy_static! {
    pub static ref PROCESS_TABLE: Mutex<Vec<Process>> = Mutex::new(Vec::new());
}

pub fn create_process(name: String) -> usize {
    let mut table = PROCESS_TABLE.lock();
    let pid = table.len();
    let process = Process::new(pid, name);
    table.push(process);
    pid
}
