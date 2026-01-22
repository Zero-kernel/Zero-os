#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;

extern crate kernel_core;
extern crate lazy_static;
extern crate spin;

pub use kernel_core::process;

pub mod enhanced_scheduler;
pub mod lock_ordering;
pub mod scheduler;

// Re-export Scheduler for runtime tests
pub use enhanced_scheduler::Scheduler;

// Re-export lockdep types for use by other modules
pub use lock_ordering::{LockClassKey, LockdepMutex, LockLevel};

pub fn init() {
    println!("Scheduler module initialized");
    enhanced_scheduler::init();
}

pub fn schedule() {
    // 简单的调度函数
}
