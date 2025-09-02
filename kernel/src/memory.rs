use crate::println;
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{PageTable, PageTableFlags, PhysFrame},
    VirtAddr, PhysAddr,
};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_START: usize = 0x4444_4444_0000;
const HEAP_SIZE: usize = 100 * 1024; // 100 KiB

pub fn init() {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    println!("Memory manager initialized");
}

// 简单的物理页分配器
pub struct FrameAllocator {
    next_free_frame: PhysFrame,
}

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator {
            next_free_frame: PhysFrame::containing_address(PhysAddr::new(0x10000000)),
        }
    }
    
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.next_free_frame;
        self.next_free_frame += 1;
        Some(frame)
    }
}
