use crate::buddy_allocator;
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{FrameAllocator as X64FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

// ============================================================================
// BootInfo 结构定义（与 bootloader 保持一致）
// ============================================================================

/// Bootloader 传入的内存映射信息
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapInfo {
    pub buffer: u64,
    pub size: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
}

/// 像素格式（与 bootloader 保持一致）
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGB (8位红, 8位绿, 8位蓝, 8位保留)
    Rgb = 0,
    /// BGR (8位蓝, 8位绿, 8位红, 8位保留)
    Bgr = 1,
    /// 未知格式
    Unknown = 2,
}

/// 帧缓冲区信息 (GOP framebuffer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// 帧缓冲区物理地址
    pub base: u64,
    /// 帧缓冲区大小（字节）
    pub size: usize,
    /// 水平分辨率（像素）
    pub width: u32,
    /// 垂直分辨率（像素）
    pub height: u32,
    /// 每行的字节数（stride）
    pub stride: u32,
    /// 像素格式
    pub pixel_format: PixelFormat,
}

/// Bootloader 传入的启动信息
#[repr(C)]
#[derive(Debug)]
pub struct BootInfo {
    pub memory_map: MemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    /// R39-7 FIX: KASLR slide value (0 if KASLR disabled)
    pub kaslr_slide: u64,
    /// ACPI RSDP physical address (from UEFI configuration table)
    pub rsdp_address: u64,
}

/// UEFI 内存描述符（按 UEFI 规范布局）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct EfiMemoryDescriptor {
    pub typ: u32,
    pub pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

/// UEFI 内存类型常量
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;

// ============================================================================
// 内存配置
// ============================================================================

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// 堆地址必须在 bootloader 映射的范围内
// Bootloader 映射了物理地址 0x0-0x1000000 (16MB) 到虚拟地址 0xffffffff80000000
// 内核代码占用了前面的部分，我们将堆放在 2MB 之后
const HEAP_START: usize = 0xffffffff80400000; // 虚拟地址 4MB 处（确保不与BSS段重叠）
const HEAP_SIZE: usize = 1024 * 1024; // 1MB (increased for runtime tests and buddy allocator bitmaps)

/// 物理内存管理起始地址（硬编码后备值，在256MB处）
const FALLBACK_PHYS_MEM_START: u64 = 0x10000000;
/// 物理内存管理大小（硬编码后备值，64MB）
const FALLBACK_PHYS_MEM_SIZE: usize = 64 * 1024 * 1024;

/// 页大小
const PAGE_SIZE: u64 = 0x1000;
/// 最小可用区域（跳过小于 2MB 的碎片区域）
const MIN_USABLE_REGION: u64 = 2 * 1024 * 1024;
/// 跳过低于 1MB 的区域（保护 BIOS/VGA 等）
const MIN_SAFE_ADDRESS: u64 = 0x100000;
/// 高半区直映上限（Bootloader 映射了物理 0-1GB 到 0xffffffff80000000-...）
/// 只能使用此范围内的物理内存（超出范围将不可访问）
const HIGH_HALF_MAP_LIMIT: u64 = 1 * 1024 * 1024 * 1024; // 1GB

// ============================================================================
// 初始化函数
// ============================================================================

/// 使用 BootInfo 初始化内存管理
///
/// # Arguments
/// * `boot_info` - Bootloader 传递的启动信息，包含 UEFI 内存映射
pub fn init_with_bootinfo(boot_info: &BootInfo) {
    // 初始化堆分配器
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    println!(
        "Heap allocator initialized: {} KB at 0x{:x}",
        HEAP_SIZE / 1024,
        HEAP_START
    );

    // 从 BootInfo 解析内存映射
    let (pmm_base, pmm_size) = select_region_from_bootinfo(boot_info).unwrap_or_else(|| {
        println!("  Warning: BootInfo memory map unavailable, using fallback region");
        (FALLBACK_PHYS_MEM_START, FALLBACK_PHYS_MEM_SIZE)
    });

    println!(
        "  Physical memory region: 0x{:x} - 0x{:x} ({} MB)",
        pmm_base,
        pmm_base + pmm_size as u64,
        pmm_size / (1024 * 1024)
    );

    // 初始化 Buddy 物理页分配器
    buddy_allocator::init_buddy_allocator(PhysAddr::new(pmm_base), pmm_size);

    // 运行自测（可选）
    #[cfg(debug_assertions)]
    buddy_allocator::run_self_test();

    println!("Memory manager fully initialized (using BootInfo)");
}

/// 后备初始化函数（无 BootInfo 时使用）
pub fn init() {
    // 初始化堆分配器
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    println!(
        "Heap allocator initialized: {} KB at 0x{:x}",
        HEAP_SIZE / 1024,
        HEAP_START
    );

    // 使用硬编码区域
    println!("  Warning: No BootInfo, using hardcoded memory region");
    buddy_allocator::init_buddy_allocator(
        PhysAddr::new(FALLBACK_PHYS_MEM_START),
        FALLBACK_PHYS_MEM_SIZE,
    );

    // 运行自测（可选）
    #[cfg(debug_assertions)]
    buddy_allocator::run_self_test();

    println!("Memory manager fully initialized (fallback mode)");
}

/// 从 BootInfo 选择最大的可用内存区域
///
/// 遍历 UEFI 内存映射，找到最大的 EfiConventionalMemory 区域
fn select_region_from_bootinfo(boot_info: &BootInfo) -> Option<(u64, usize)> {
    let map_info = &boot_info.memory_map;

    // 验证内存映射有效性
    if map_info.buffer == 0 || map_info.descriptor_size == 0 || map_info.size == 0 {
        return None;
    }

    let desc_count = map_info.size / map_info.descriptor_size;
    let mut best: Option<(u64, u64)> = None;
    let mut total_conventional: u64 = 0;

    println!("  Scanning UEFI memory map ({} descriptors)...", desc_count);

    for i in 0..desc_count {
        let addr = map_info.buffer + (i * map_info.descriptor_size) as u64;
        let desc = unsafe { &*(addr as *const EfiMemoryDescriptor) };

        // 只使用 Conventional Memory 和 Boot Services 区域（后者在 ExitBootServices 后可用）
        let usable = matches!(
            desc.typ,
            EFI_CONVENTIONAL_MEMORY | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA
        );

        if !usable || desc.page_count == 0 {
            continue;
        }

        let start = align_up(desc.phys_start, PAGE_SIZE);
        let raw_length = desc.page_count.saturating_mul(PAGE_SIZE);
        let usable_length = raw_length.saturating_sub(start.saturating_sub(desc.phys_start));

        // 跳过超出高半区直映范围的区域（>1GB）
        if start >= HIGH_HALF_MAP_LIMIT {
            continue;
        }

        // 如果区域跨越 1GB 边界，截断到 1GB
        let end = start.saturating_add(usable_length);
        let clamped_end = end.min(HIGH_HALF_MAP_LIMIT);
        let clamped_length = clamped_end.saturating_sub(start);

        // 跳过太小或地址太低的区域
        if clamped_length < MIN_USABLE_REGION || start < MIN_SAFE_ADDRESS {
            continue;
        }

        total_conventional += clamped_length;

        // 记录最大区域
        if best.map_or(true, |(_, size)| clamped_length > size) {
            best = Some((start, clamped_length));
        }
    }

    println!(
        "  Total usable memory: {} MB",
        total_conventional / (1024 * 1024)
    );

    best.map(|(base, size)| {
        // 限制最大使用量，避免占用太多内存
        let capped_size = size.min(256 * 1024 * 1024) as usize; // 最大 256MB
        (base, capped_size)
    })
}

/// 对齐到页边界（向上取整）
#[inline]
const fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

/// 改进的物理帧分配器（使用Buddy分配器）
pub struct FrameAllocator;

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator
    }

    /// 分配单个物理帧
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(1)
    }

    /// 分配连续的多个物理帧
    pub fn allocate_contiguous_frames(&mut self, count: usize) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(count)
    }

    /// 释放物理帧
    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        buddy_allocator::free_physical_pages(frame, 1);
    }

    /// 释放连续的多个物理帧
    pub fn deallocate_contiguous_frames(&mut self, frame: PhysFrame, count: usize) {
        buddy_allocator::free_physical_pages(frame, count);
    }

    /// 获取内存统计信息
    pub fn stats(&self) -> MemoryStats {
        let buddy_stats =
            buddy_allocator::get_allocator_stats().unwrap_or(buddy_allocator::AllocatorStats {
                total_pages: 0,
                free_pages: 0,
                used_pages: 0,
                fragmentation: 0.0,
            });

        MemoryStats {
            total_physical_pages: buddy_stats.total_pages,
            free_physical_pages: buddy_stats.free_pages,
            used_physical_pages: buddy_stats.used_pages,
            fragmentation_percent: (buddy_stats.fragmentation * 100.0) as u32,
            heap_used_bytes: HEAP_SIZE - unsafe { ALLOCATOR.lock().free() },
            heap_total_bytes: HEAP_SIZE,
        }
    }
}

/// 实现 x86_64 FrameAllocator trait 以便与页表管理器配合使用
unsafe impl X64FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_frame()
    }
}

/// 内存统计信息
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub total_physical_pages: usize,
    pub free_physical_pages: usize,
    pub used_physical_pages: usize,
    pub fragmentation_percent: u32,
    pub heap_used_bytes: usize,
    pub heap_total_bytes: usize,
}

impl MemoryStats {
    /// 打印内存统计信息
    pub fn print(&self) {
        println!("=== Memory Statistics ===");
        println!("Physical Memory:");
        println!(
            "  Total: {} pages ({} MB)",
            self.total_physical_pages,
            self.total_physical_pages * 4 / 1024
        );
        println!(
            "  Free:  {} pages ({} MB)",
            self.free_physical_pages,
            self.free_physical_pages * 4 / 1024
        );
        println!(
            "  Used:  {} pages ({} MB)",
            self.used_physical_pages,
            self.used_physical_pages * 4 / 1024
        );
        println!("  Fragmentation: {}%", self.fragmentation_percent);
        println!("Kernel Heap:");
        println!(
            "  Used:  {} KB / {} KB",
            self.heap_used_bytes / 1024,
            self.heap_total_bytes / 1024
        );
    }
}
