use crate::println;
use crate::process::{Process, ProcessState, PROCESS_TABLE};
use alloc::collections::VecDeque;
use spin::Mutex;

// 调度器需要维护运行中的任务列表和当前运行任务的索引
pub struct Scheduler {
    ready_queue: VecDeque<usize>,
    current_process: Option<usize>,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            ready_queue: VecDeque::new(),
            current_process: None,
        }
    }
    
    pub fn add_process(&mut self, pid: usize) {
        self.ready_queue.push_back(pid);
    }
    
    pub fn schedule(&mut self) -> Option<usize> {
        if let Some(pid) = self.ready_queue.pop_front() {
            if let Some(current) = self.current_process {
                self.ready_queue.push_back(current);
            }
            self.current_process = Some(pid);
            Some(pid)
        } else {
            self.current_process
        }
    }
}

lazy_static::lazy_static! {
    static ref SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
}

pub fn init() {
    println!("Scheduler initialized");
    
    // 创建初始进程
    let init_pid = crate::process::create_process("init".into());
    SCHEDULER.lock().add_process(init_pid);
}

pub fn run() -> ! {
    loop {
        if let Some(pid) = SCHEDULER.lock().schedule() {
            // 切换到进程上下文并运行
            println!("Running process {}", pid);
            
            // 模拟进程执行
            x86_64::instructions::hlt();
        } else {
            // 没有进程可运行，进入空闲状态
            x86_64::instructions::hlt();
        }
    }
}
