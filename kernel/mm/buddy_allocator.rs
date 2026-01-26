//! Buddy内存分配器实现
//!
//! Buddy分配器是一种高效的内存管理算法，通过将内存分割成2的幂次大小的块来管理。
//! 当需要分配内存时，找到最小的能满足需求的块；释放时尝试与相邻的块合并。

use alloc::vec;
use alloc::vec::Vec;
use bit_vec::BitVec;
use spin::Mutex;
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::oom_killer;

/// 最大阶数（2^MAX_ORDER * PAGE_SIZE = 最大连续分配大小）
const MAX_ORDER: usize = 11; // 2^11 * 4KB = 8MB
/// 页面大小（4KB）
const PAGE_SIZE: usize = 4096;

/// Buddy分配器的核心结构
pub struct BuddyAllocator {
    /// 每个阶数的空闲链表
    /// free_lists[i] 包含大小为 2^i * PAGE_SIZE 的空闲块
    free_lists: [Vec<usize>; MAX_ORDER],

    /// 位图，用于跟踪块的状态
    /// 每个位表示对应的块是否已分配
    bitmap: BitVec,

    /// R74-4 Enhancement: Track allocation order for each block.
    ///
    /// Stores (order + 1) for allocated blocks, 0 for free.
    /// This prevents freeing with a mismatched order (e.g., freeing 1 page
    /// from an 8-page allocation), which would corrupt the allocator.
    ///
    /// MAX_ORDER=11 fits in 4 bits, so u8 is sufficient and keeps memory
    /// overhead reasonable (~1 byte per page).
    alloc_order: Vec<u8>,

    /// 内存起始物理地址
    base_addr: PhysAddr,

    /// 总页数
    total_pages: usize,

    /// 空闲页数
    free_pages: usize,

    /// 用于跟踪块的分割状态
    /// split_bitmap[i] 表示块是否被分割成更小的块
    split_bitmap: BitVec,
}

impl BuddyAllocator {
    /// 创建新的Buddy分配器
    ///
    /// # 参数
    /// * `base_addr` - 管理的内存区域起始地址
    /// * `size` - 管理的内存区域大小（字节）
    pub fn new(base_addr: PhysAddr, size: usize) -> Self {
        let total_pages = size / PAGE_SIZE;
        let bitmap_size = total_pages * 2; // 需要额外空间存储分割信息

        let mut allocator = BuddyAllocator {
            free_lists: Default::default(),
            bitmap: BitVec::from_elem(bitmap_size, false),
            alloc_order: vec![0u8; total_pages],  // R74-4: Initialize all as free (0)
            base_addr,
            total_pages,
            free_pages: total_pages,
            split_bitmap: BitVec::from_elem(bitmap_size, false),
        };

        // 初始化：将整个内存区域作为最大的块加入空闲链表
        allocator.init_memory_region();
        allocator
    }

    /// 初始化内存区域
    fn init_memory_region(&mut self) {
        let mut current_pages = self.total_pages;
        let mut current_addr = 0;

        // 将内存分割成尽可能大的块
        for order in (0..MAX_ORDER).rev() {
            let block_pages = 1 << order;
            while current_pages >= block_pages {
                self.free_lists[order].push(current_addr);
                current_addr += block_pages;
                current_pages -= block_pages;
            }
        }
    }

    /// 分配指定阶数的内存块
    ///
    /// # 参数
    /// * `order` - 需要分配的块的阶数（2^order * PAGE_SIZE）
    ///
    /// # 返回
    /// 成功返回分配的物理帧，失败返回None
    pub fn alloc_pages(&mut self, order: usize) -> Option<PhysFrame> {
        if order >= MAX_ORDER {
            return None;
        }

        // 从当前阶数开始向上查找可用块
        for current_order in order..MAX_ORDER {
            if !self.free_lists[current_order].is_empty() {
                // 找到可用块，从空闲链表中移除
                let block_idx = self.free_lists[current_order].pop().unwrap();

                // 如果块太大，需要分割
                self.split_block(block_idx, current_order, order);

                // 标记块为已分配
                let pages = 1 << order;
                self.mark_allocated(block_idx, pages);

                // R74-4 Enhancement: Record allocation order for verification at free time
                self.record_alloc_order(block_idx, pages, order);

                // 更新统计
                self.free_pages -= pages;

                // 计算物理地址
                let phys_addr = self.base_addr + (block_idx * PAGE_SIZE) as u64;
                return Some(PhysFrame::containing_address(phys_addr));
            }
        }

        None // 没有足够的内存
    }

    /// 分割块直到达到目标大小
    fn split_block(&mut self, mut block_idx: usize, mut current_order: usize, target_order: usize) {
        while current_order > target_order {
            current_order -= 1;
            let buddy_idx = block_idx + (1 << current_order);

            // 将分割出的buddy块加入空闲链表
            self.free_lists[current_order].push(buddy_idx);

            // 标记原块被分割
            self.split_bitmap.set(block_idx, true);
        }
    }

    /// 释放内存块
    ///
    /// # Arguments
    /// * `frame` - 要释放的物理帧
    /// * `order` - 块的阶数
    ///
    /// # Safety
    /// 调用者必须确保该帧确实是之前分配的，且未被双重释放
    pub fn free_pages(&mut self, frame: PhysFrame, order: usize) {
        if order >= MAX_ORDER {
            return;
        }

        let addr = frame.start_address();

        // 验证地址在管理范围内
        if addr < self.base_addr {
            return;
        }

        let block_idx = ((addr - self.base_addr) / PAGE_SIZE as u64) as usize;
        let pages = 1 << order;

        // R74-4 FIX: Enforce block alignment to prevent partial block frees.
        //
        // The buddy allocator requires that blocks be freed with the same order
        // they were allocated with. Freeing a sub-block of a larger allocation
        // would corrupt the allocator state and enable overlapping allocations,
        // leading to memory corruption and use-after-free vulnerabilities.
        //
        // Security check: Reject frees where block_idx is not aligned to the
        // block size (2^order pages). For example, freeing order=3 (8 pages)
        // requires block_idx to be divisible by 8.
        if block_idx & (pages - 1) != 0 {
            // Block is not aligned to its size - this is a partial free attempt
            return;
        }

        // 范围验证：确保不超出管理的内存区域
        if block_idx + pages > self.total_pages {
            return;
        }

        // R74-4 Enhancement: Verify freeing order matches recorded allocation order.
        //
        // The alignment check alone is insufficient. For example:
        // - Allocate 8 pages (order=3) at block_idx=0
        // - Free with order=0 at block_idx=0 (passes alignment: 0 & 0 == 0)
        // - This would free 1 page from an 8-page block → allocator corruption
        //
        // By storing the allocation order and checking it at free time, we catch
        // all order mismatch scenarios, preventing the Codex-identified edge case.
        let recorded = self.alloc_order.get(block_idx).copied().unwrap_or(0);
        if recorded == 0 {
            // No allocation starts here (already free or mid-block access)
            return;
        }
        let recorded_order = (recorded - 1) as usize;
        if recorded_order != order {
            // Order mismatch: trying to free with different order than allocated
            // This would corrupt the buddy allocator structure
            return;
        }

        // R74-4 FIX: Enhanced double-free/size-mismatch detection.
        // All pages in the range must be currently allocated. If any page is
        // already free or out of bounds, reject the operation to prevent
        // partial blocks from entering the free lists.
        for i in 0..pages {
            if block_idx + i >= self.bitmap.len() || !self.bitmap[block_idx + i] {
                // Page is out of bounds or already free - reject to prevent
                // allocator corruption and overlapping allocations
                return;
            }
        }

        // 标记块为空闲
        self.mark_free(block_idx, pages);
        self.free_pages += pages;

        // 尝试与 buddy 合并
        self.merge_blocks(block_idx, order);
    }

    /// 合并相邻的buddy块
    fn merge_blocks(&mut self, mut block_idx: usize, mut order: usize) {
        while order < MAX_ORDER - 1 {
            let buddy_idx = self.get_buddy_index(block_idx, order);

            // 检查buddy是否存在且空闲
            if !self.is_buddy_free(buddy_idx, order) {
                break;
            }

            // 从空闲链表中移除buddy
            if let Some(pos) = self.free_lists[order].iter().position(|&x| x == buddy_idx) {
                self.free_lists[order].remove(pos);
            }

            // 合并：使用较小的索引作为合并后的块
            if buddy_idx < block_idx {
                block_idx = buddy_idx;
            }

            order += 1;
        }

        // 将合并后的块加入空闲链表
        self.free_lists[order].push(block_idx);
    }

    /// 获取buddy块的索引
    fn get_buddy_index(&self, block_idx: usize, order: usize) -> usize {
        block_idx ^ (1 << order)
    }

    /// 检查buddy块是否空闲
    fn is_buddy_free(&self, buddy_idx: usize, order: usize) -> bool {
        if buddy_idx >= self.total_pages {
            return false;
        }

        let pages = 1 << order;
        for i in 0..pages {
            if self.bitmap[buddy_idx + i] {
                return false; // 有页面被分配
            }
        }

        true
    }

    /// 标记页面为已分配
    fn mark_allocated(&mut self, start_idx: usize, pages: usize) {
        for i in 0..pages {
            self.bitmap.set(start_idx + i, true);
        }
    }

    /// R74-4 Enhancement: Record allocation order for each page in the block.
    ///
    /// Stores (order + 1) so that 0 represents free. This allows us to detect:
    /// - Order mismatch on free (e.g., free order=0 from order=3 allocation)
    /// - Access from mid-block (non-starting page of an allocation)
    ///
    /// # Arguments
    /// * `start_idx` - Starting block index
    /// * `pages` - Number of pages in the block (2^order)
    /// * `order` - Allocation order (0 to MAX_ORDER-1)
    fn record_alloc_order(&mut self, start_idx: usize, pages: usize, order: usize) {
        let encoded_order = (order as u8) + 1;
        for i in 0..pages {
            if start_idx + i < self.alloc_order.len() {
                self.alloc_order[start_idx + i] = encoded_order;
            }
        }
    }

    /// 标记页面为空闲
    fn mark_free(&mut self, start_idx: usize, pages: usize) {
        for i in 0..pages {
            self.bitmap.set(start_idx + i, false);
        }
        // R74-4 Enhancement: Clear the allocation order tracking
        self.clear_alloc_order(start_idx, pages);
    }

    /// R74-4 Enhancement: Clear allocation order tracking for freed block.
    fn clear_alloc_order(&mut self, start_idx: usize, pages: usize) {
        for i in 0..pages {
            if start_idx + i < self.alloc_order.len() {
                self.alloc_order[start_idx + i] = 0;
            }
        }
    }

    /// 获取统计信息
    pub fn stats(&self) -> AllocatorStats {
        AllocatorStats {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            used_pages: self.total_pages - self.free_pages,
            fragmentation: self.calculate_fragmentation(),
        }
    }

    /// 计算内存碎片率
    fn calculate_fragmentation(&self) -> f32 {
        let mut total_free_blocks = 0;
        let mut largest_free_block = 0;

        for (order, list) in self.free_lists.iter().enumerate() {
            let block_size = 1 << order;
            total_free_blocks += list.len() * block_size;
            if !list.is_empty() && block_size > largest_free_block {
                largest_free_block = block_size;
            }
        }

        if total_free_blocks == 0 {
            return 0.0;
        }

        1.0 - (largest_free_block as f32 / total_free_blocks as f32)
    }
}

/// 分配器统计信息
#[derive(Debug, Clone, Copy)]
pub struct AllocatorStats {
    pub total_pages: usize,
    pub free_pages: usize,
    pub used_pages: usize,
    pub fragmentation: f32,
}

/// 全局Buddy分配器实例
static BUDDY_ALLOCATOR: Mutex<Option<BuddyAllocator>> = Mutex::new(None);

/// 初始化全局Buddy分配器
///
/// # 参数
/// * `base_addr` - 物理内存起始地址
/// * `size` - 管理的内存大小
pub fn init_buddy_allocator(base_addr: PhysAddr, size: usize) {
    let allocator = BuddyAllocator::new(base_addr, size);
    *BUDDY_ALLOCATOR.lock() = Some(allocator);

    println!("Buddy allocator initialized:");
    println!("  Base address: 0x{:x}", base_addr);
    println!("  Size: {} MB", size / (1024 * 1024));
    println!("  Total pages: {}", size / PAGE_SIZE);
}

/// 分配物理页面
///
/// # Arguments
/// * `count` - 需要分配的页面数量（必须 > 0）
///
/// # Returns
/// 成功返回物理帧，失败返回 None
///
/// # OOM Handling
/// 如果分配失败，会触发 OOM killer 尝试回收内存，然后重试一次
pub fn alloc_physical_pages(count: usize) -> Option<PhysFrame> {
    // 处理无效输入：count=0 时直接返回 None
    if count == 0 {
        return None;
    }

    let order = count.next_power_of_two().trailing_zeros() as usize;
    // Buddy allocator 实际分配的页数（向上取整到 2 的幂）
    let pages_needed = 1usize << order;

    // 第一次尝试分配
    let result = BUDDY_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.alloc_pages(order));

    if result.is_some() {
        return result;
    }

    // 分配失败，触发 OOM killer 尝试回收内存
    // 使用实际需要的页数（向上取整后），而非原始请求
    oom_killer::on_allocation_failure(pages_needed);

    // OOM 处理后重试一次
    BUDDY_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.alloc_pages(order))
}

/// 释放物理页面
///
/// # 参数
/// * `frame` - 要释放的物理帧
/// * `count` - 页面数量
pub fn free_physical_pages(frame: PhysFrame, count: usize) {
    let order = count.next_power_of_two().trailing_zeros() as usize;

    if let Some(allocator) = BUDDY_ALLOCATOR.lock().as_mut() {
        allocator.free_pages(frame, order);
    }
}

/// 获取分配器统计信息
pub fn get_allocator_stats() -> Option<AllocatorStats> {
    BUDDY_ALLOCATOR
        .lock()
        .as_ref()
        .map(|allocator| allocator.stats())
}

// 测试代码已移除（no_std环境不支持标准测试框架）
// 可以在内核初始化时运行自测函数

/// 运行Buddy分配器自测
pub fn run_self_test() {
    println!("Running Buddy allocator self-test...");

    let base = PhysAddr::new(0x10000000); // 256MB处
    let size = 16 * 1024 * 1024; // 16MB测试区域
    let mut allocator = BuddyAllocator::new(base, size);

    // 测试1: 基础分配
    let frame1 = allocator
        .alloc_pages(0)
        .expect("Test 1 failed: Cannot allocate 1 page");
    assert!(
        frame1.start_address() == base,
        "Test 1 failed: Wrong address"
    );
    println!("  Test 1 passed: Basic allocation");

    // 测试2: 分配和释放
    let initial_free = allocator.free_pages;
    let frame2 = allocator
        .alloc_pages(3)
        .expect("Test 2 failed: Cannot allocate 8 pages");
    assert!(
        allocator.free_pages == initial_free - 8,
        "Test 2 failed: Wrong free count"
    );
    allocator.free_pages(frame2, 3);
    assert!(
        allocator.free_pages == initial_free,
        "Test 2 failed: Free count not restored"
    );
    println!("  Test 2 passed: Allocation and free");

    // 测试3: Buddy合并
    let frame3 = allocator.alloc_pages(0).unwrap();
    let frame4 = allocator.alloc_pages(0).unwrap();
    allocator.free_pages(frame3, 0);
    allocator.free_pages(frame4, 0);
    let frame5 = allocator.alloc_pages(1); // 应该能分配大小为2的块
    assert!(frame5.is_some(), "Test 3 failed: Buddy merge failed");
    println!("  Test 3 passed: Buddy merge");

    println!("All Buddy allocator tests passed!");
}

/// 简单的断言宏（用于no_std环境）
macro_rules! assert {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            panic!($msg);
        }
    };
}
