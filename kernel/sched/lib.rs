#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

extern crate kernel_core;
extern crate lazy_static;
extern crate spin;

pub use kernel_core::process;

pub mod cpuset;
pub mod enhanced_scheduler;
pub mod lock_ordering;
pub mod scheduler;

// Re-export Scheduler for runtime tests
pub use enhanced_scheduler::Scheduler;

// Re-export lockdep types for use by other modules
pub use lock_ordering::{LockClassKey, LockdepMutex, LockLevel};

// Re-export cpuset types
pub use cpuset::{CpusetError, CpusetId, CpusetNode};

pub fn init() {
    klog_always!("Scheduler module initialized");
    enhanced_scheduler::init();
    // Note: cpuset::init() should be called after CPU enumeration in main.rs
}

pub fn schedule() {
    // 简单的调度函数
}
