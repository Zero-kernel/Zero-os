#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

pub mod buddy_allocator;
pub mod dma;
pub mod memory;
pub mod oom_killer;
pub mod page_cache;
pub mod page_table;
pub mod tlb_shootdown;

pub use memory::{BootInfo, FrameAllocator, MemoryMapInfo};
pub use oom_killer::{
    get_stats as get_oom_stats, on_allocation_failure as oom_allocation_failed,
    register_audit_callback as register_oom_audit_callback,
    register_callbacks as register_oom_callbacks, OomProcessInfo, OomStats,
};
pub use page_cache::{
    find_or_create_page, init as init_page_cache, read_page, reclaim_pages, sync_inode,
    writeback_dirty_pages, writeback_page, AddressSpace, GlobalPageCache, InodeId,
    MemoryPressureHandler, PageCacheEntry, PageCacheStats, PageIndex, PageState, WritebackStats,
    PAGE_CACHE, PAGE_SIZE, PRESSURE_HANDLER,
};
pub use page_table::{
    map_mmio, phys_to_virt, with_current_manager, MapError, PageTableManager, UnmapError,
    UpdateFlagsError, PHYSICAL_MEMORY_OFFSET,
};
pub use tlb_shootdown::{
    flush_current_as_all, flush_current_as_page, flush_current_as_range, get_stats as get_tlb_stats,
};

pub fn init() {
    klog_always!("Memory management module initialized");
}
