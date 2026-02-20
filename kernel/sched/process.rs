//! 进程控制块 (Process Control Block)
//! 
//! 定义进程的数据结构和状态管理

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// 进程ID类型
pub type Pid = u64;

/// 全局进程ID计数器
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// 生成新的进程ID
///
/// P2-8 FIX: Use fetch_update + checked_add to prevent wrapping to 0 on u64
/// overflow, following the R105-5 pattern.  Returns None if the ID space is
/// exhausted (practically unreachable with u64).
pub fn allocate_pid() -> Option<Pid> {
    NEXT_PID
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
        .ok()
}

/// 进程状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 新创建
    New,
    /// 就绪态
    Ready,
    /// 运行态
    Running,
    /// 阻塞态
    Blocked,
    /// 僵尸态（已终止但未被父进程回收）
    Zombie,
    /// 已终止
    Terminated,
}

/// 进程优先级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub u8);

impl Priority {
    pub const IDLE: Priority = Priority(0);
    pub const LOW: Priority = Priority(5);
    pub const NORMAL: Priority = Priority(10);
    pub const HIGH: Priority = Priority(15);
    pub const REALTIME: Priority = Priority(20);
}

/// 进程控制块
#[derive(Debug)]
pub struct ProcessControlBlock {
    /// 进程ID
    pub pid: Pid,
    
    /// 父进程ID
    pub parent_pid: Option<Pid>,
    
    /// 进程名称
    pub name: String,
    
    /// 进程状态
    pub state: ProcessState,
    
    /// 优先级
    pub priority: Priority,
    
    /// 上下文（由arch模块定义）
    pub context: arch::Context,
    
    /// 页表根地址
    pub page_table_root: u64,
    
    /// 内核栈指针
    pub kernel_stack: u64,
    
    /// 用户栈指针
    pub user_stack: Option<u64>,
    
    /// 程序入口点
    pub entry_point: u64,
    
    /// 已使用的CPU时间（时钟滴答数）
    pub cpu_time: u64,
    
    /// 时间片（剩余时钟滴答数）
    pub time_slice: u64,
    
    /// 退出码
    pub exit_code: Option<i32>,
    
    /// 打开的文件描述符
    pub file_descriptors: Vec<Option<FileDescriptor>>,
    
    /// 工作目录
    pub working_directory: String,
}

/// 文件描述符（简化版）
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub fd: u32,
    pub flags: u32,
    // 实际实现中这里应该有文件句柄等信息
}

impl ProcessControlBlock {
    /// 创建新的进程控制块
    pub fn new(name: String, entry_point: u64, kernel_stack: u64) -> Option<Self> {
        let pid = allocate_pid()?;
        let context = arch::Context::init_for_process(entry_point, kernel_stack);

        Some(ProcessControlBlock {
            pid,
            parent_pid: None,
            name,
            state: ProcessState::New,
            priority: Priority::NORMAL,
            context,
            page_table_root: 0, // 需要分配页表
            kernel_stack,
            user_stack: None,
            entry_point,
            cpu_time: 0,
            time_slice: 100, // 默认时间片：100个时钟滴答
            exit_code: None,
            file_descriptors: Vec::new(),
            working_directory: String::from("/"),
        })
    }
    
    /// 创建用户态进程
    pub fn new_user_process(
        name: String,
        entry_point: u64,
        kernel_stack: u64,
        user_stack: u64,
    ) -> Option<Self> {
        let pid = allocate_pid()?;
        let context = arch::Context::init_for_user_process(entry_point, user_stack);

        Some(ProcessControlBlock {
            pid,
            parent_pid: None,
            name,
            state: ProcessState::New,
            priority: Priority::NORMAL,
            context,
            page_table_root: 0, // 需要分配页表
            kernel_stack,
            user_stack: Some(user_stack),
            entry_point,
            cpu_time: 0,
            time_slice: 100,
            exit_code: None,
            file_descriptors: Vec::new(),
            working_directory: String::from("/"),
        })
    }
    
    /// 标记进程为就绪态
    pub fn set_ready(&mut self) {
        self.state = ProcessState::Ready;
    }
    
    /// 标记进程为运行态
    pub fn set_running(&mut self) {
        self.state = ProcessState::Running;
    }
    
    /// 标记进程为阻塞态
    pub fn set_blocked(&mut self) {
        self.state = ProcessState::Blocked;
    }
    
    /// 标记进程为终止态
    pub fn set_terminated(&mut self, exit_code: i32) {
        self.state = ProcessState::Terminated;
        self.exit_code = Some(exit_code);
    }
    
    /// 标记进程为僵尸态
    pub fn set_zombie(&mut self, exit_code: i32) {
        self.state = ProcessState::Zombie;
        self.exit_code = Some(exit_code);
    }
    
    /// 重置时间片
    pub fn reset_time_slice(&mut self) {
        self.time_slice = match self.priority {
            Priority::IDLE => 50,
            Priority::LOW => 75,
            Priority::NORMAL => 100,
            Priority::HIGH => 150,
            Priority::REALTIME => 200,
            _ => 100,
        };
    }
    
    /// 消耗时间片
    pub fn consume_time_slice(&mut self) -> bool {
        if self.time_slice > 0 {
            self.time_slice -= 1;
            self.cpu_time += 1;
            self.time_slice == 0
        } else {
            true
        }
    }
    
    /// 是否可以被调度
    pub fn is_schedulable(&self) -> bool {
        matches!(self.state, ProcessState::Ready | ProcessState::Running)
    }
    
    /// 分配文件描述符
    pub fn allocate_fd(&mut self, fd_info: FileDescriptor) -> Option<u32> {
        // 查找第一个空闲的fd
        for (i, slot) in self.file_descriptors.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(fd_info);
                return Some(i as u32);
            }
        }
        
        // 没有空闲的，添加新的
        let fd = self.file_descriptors.len() as u32;
        self.file_descriptors.push(Some(fd_info));
        Some(fd)
    }
    
    /// 释放文件描述符
    pub fn free_fd(&mut self, fd: u32) -> Option<FileDescriptor> {
        if let Some(slot) = self.file_descriptors.get_mut(fd as usize) {
            slot.take()
        } else {
            None
        }
    }
    
    /// 获取文件描述符
    pub fn get_fd(&self, fd: u32) -> Option<&FileDescriptor> {
        self.file_descriptors.get(fd as usize)?.as_ref()
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::NORMAL
    }
}

/// 进程统计信息
#[derive(Debug, Clone)]
pub struct ProcessStats {
    pub pid: Pid,
    pub name: String,
    pub state: ProcessState,
    pub priority: Priority,
    pub cpu_time: u64,
    pub time_slice_remaining: u64,
}

impl ProcessStats {
    pub fn from_pcb(pcb: &ProcessControlBlock) -> Self {
        ProcessStats {
            pid: pcb.pid,
            name: pcb.name.clone(),
            state: pcb.state,
            priority: pcb.priority,
            cpu_time: pcb.cpu_time,
            time_slice_remaining: pcb.time_slice,
        }
    }
}