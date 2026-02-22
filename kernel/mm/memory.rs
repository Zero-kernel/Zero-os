use crate::buddy_allocator;
use crate::page_table::PHYSICAL_MEMORY_OFFSET;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// P1-1: UEFI boot command line length in bytes (ASCII, max 256).
    pub cmdline_len: usize,
    /// P1-1: UEFI boot command line buffer (ASCII, NUL-padded).
    pub cmdline: [u8; 256],
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

// ============================================================================
// Partial KASLR: Heap Randomization Configuration
// ============================================================================
//
// The heap address must reside within the bootloader's mapped region.
// Bootloader maps physical 0x0-0x40000000 (0-1GB) to high-half starting at
// 0xffffffff80000000. To avoid overlapping with kernel text/data sections,
// the minimum heap address is 0xffffffff80400000 (4MB offset, 2MB aligned).
//
// Randomization window: [HEAP_DEFAULT_BASE, HEAP_WINDOW_END)
// Alignment: 2MB for huge page compatibility

/// Default (fallback) heap base address when randomization is unavailable
pub const HEAP_DEFAULT_BASE: usize = 0xffffffff80400000;

/// Upper bound of heap randomization window (exclusive)
/// This leaves room for the heap itself within the 1GB mapped region
const HEAP_WINDOW_END: usize = 0xffffffff90000000;

/// Heap alignment (2MB for huge page compatibility)
const HEAP_ALIGNMENT: usize = 2 * 1024 * 1024;

/// Heap size in bytes
const HEAP_SIZE: usize = 1024 * 1024; // 1MB

/// Public constant for external modules
pub const HEAP_SIZE_BYTES: usize = HEAP_SIZE;

/// Actual heap base address (set during init via randomization or fallback)
static HEAP_BASE: AtomicUsize = AtomicUsize::new(HEAP_DEFAULT_BASE);

/// Whether heap was successfully randomized using early entropy
static HEAP_RANDOMIZED: AtomicBool = AtomicBool::new(false);

/// Whether heap address was validated against UEFI memory map
static HEAP_VALIDATED: AtomicBool = AtomicBool::new(false);

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
///
/// # R72-4 FIX: Memory Map Validation
/// Heap base is now validated against the UEFI memory map before selection,
/// ensuring the chosen address falls within EFI_CONVENTIONAL_MEMORY regions.
pub fn init_with_bootinfo(boot_info: &BootInfo) {
    // R72-4 FIX: Select heap base with UEFI memory map validation FIRST
    // This ensures the heap doesn't overlap with reserved ACPI/runtime regions
    let (heap_base, randomized, validated) =
        if let Some((base, rand)) = select_heap_base_from_bootinfo(boot_info) {
            (base, rand, true)
        } else {
            klog!(Warn, "  Warning: BootInfo memory map unavailable for heap validation, using default window");
            let (base, rand) = select_heap_base();
            (base, rand, false)
        };

    HEAP_VALIDATED.store(validated, Ordering::SeqCst);
    let heap_base = init_heap_allocator_at(heap_base, randomized);

    // Build accurate status message
    let status = match (randomized, validated) {
        (true, true) => " (randomized, validated)",
        (true, false) => " (randomized, UNVALIDATED)",
        (false, true) => " (static, validated)",
        (false, false) => " (static)",
    };
    klog!(
        Info,
        "Heap allocator initialized: {} KB at 0x{:x}{}",
        HEAP_SIZE / 1024,
        heap_base,
        status
    );

    // 从 BootInfo 解析内存映射
    let (pmm_base, pmm_size) = select_region_from_bootinfo(boot_info).unwrap_or_else(|| {
        klog!(Warn, "  Warning: BootInfo memory map unavailable, using fallback region");
        (FALLBACK_PHYS_MEM_START, FALLBACK_PHYS_MEM_SIZE)
    });

    klog!(
        Info,
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

    klog_always!("Memory manager fully initialized (using BootInfo)");
}

/// 后备初始化函数（无 BootInfo 时使用）
pub fn init() {
    // 初始化堆分配器（包含 Partial KASLR 堆随机化，但无法验证内存映射）
    let (heap_base, randomized) = select_heap_base();
    let heap_base = init_heap_allocator_at(heap_base, randomized);
    let status = if heap_randomized() {
        " (randomized, unvalidated)"
    } else {
        " (static)"
    };
    klog!(
        Info,
        "Heap allocator initialized: {} KB at 0x{:x}{}",
        HEAP_SIZE / 1024,
        heap_base,
        status
    );

    // 使用硬编码区域
    klog!(Warn, "  Warning: No BootInfo, using hardcoded memory region");
    buddy_allocator::init_buddy_allocator(
        PhysAddr::new(FALLBACK_PHYS_MEM_START),
        FALLBACK_PHYS_MEM_SIZE,
    );

    // 运行自测（可选）
    #[cfg(debug_assertions)]
    buddy_allocator::run_self_test();

    klog_always!("Memory manager fully initialized (fallback mode)");
}

// ============================================================================
// Partial KASLR: Heap Base Randomization
// ============================================================================

/// Initialize the heap allocator at a pre-selected address.
///
/// # R72-4 FIX: Separated selection from initialization
/// This allows the caller to validate the heap address against the UEFI
/// memory map before committing to it.
fn init_heap_allocator_at(heap_base: usize, randomized: bool) -> usize {
    HEAP_BASE.store(heap_base, Ordering::SeqCst);
    HEAP_RANDOMIZED.store(randomized, Ordering::SeqCst);

    unsafe {
        ALLOCATOR.lock().init(heap_base as *mut u8, HEAP_SIZE);
    }

    heap_base
}

/// Select a randomized heap base address using early RDRAND entropy.
///
/// The randomization window is [HEAP_DEFAULT_BASE, HEAP_WINDOW_END), with
/// 2MB alignment to maintain huge page compatibility.
///
/// # Returns
///
/// Tuple of (heap_base, was_randomized)
fn select_heap_base() -> (usize, bool) {
    // Calculate the maximum allowable heap base (ensuring heap fits within window)
    let max_base = HEAP_WINDOW_END.saturating_sub(HEAP_SIZE);
    let max_base_aligned = align_down(max_base as u64, HEAP_ALIGNMENT as u64) as usize;

    // Validate we have room for randomization
    if max_base_aligned < HEAP_DEFAULT_BASE {
        return (HEAP_DEFAULT_BASE, false);
    }

    // Calculate number of possible slots
    let slot_count = (max_base_aligned - HEAP_DEFAULT_BASE) / HEAP_ALIGNMENT;
    if slot_count == 0 {
        return (HEAP_DEFAULT_BASE, false);
    }

    // Attempt to get early entropy from RDRAND
    if let Some(rand) = rdrand64_early() {
        // Select a random slot (0 to slot_count inclusive)
        let slot = (rand as usize) % (slot_count + 1);
        let base = HEAP_DEFAULT_BASE + slot * HEAP_ALIGNMENT;
        return (base, true);
    }

    // Fallback to default if RDRAND unavailable
    (HEAP_DEFAULT_BASE, false)
}

/// Select a randomized heap base address with UEFI memory map validation.
///
/// # R72-4 FIX: Memory Map Aware Heap Selection
/// This function validates that the chosen heap address falls entirely within
/// EFI_CONVENTIONAL_MEMORY regions, preventing placement over ACPI tables,
/// EFI runtime services, or other reserved memory.
///
/// # Algorithm
/// 1. Attempt RDRAND to get entropy for random slot selection
/// 2. Try the random slot first, if it lands in usable memory, use it
/// 3. If not, iterate through all slots to find one in usable memory
/// 4. Return None if no valid slot exists (caller falls back to unvalidated selection)
fn select_heap_base_from_bootinfo(boot_info: &BootInfo) -> Option<(usize, bool)> {
    let map_info = &boot_info.memory_map;

    // Validate memory map is present
    if map_info.buffer == 0 || map_info.size == 0 || map_info.descriptor_size == 0 {
        return None;
    }

    // Calculate slot parameters (same as select_heap_base)
    let max_base = HEAP_WINDOW_END.saturating_sub(HEAP_SIZE);
    let max_base_aligned = align_down(max_base as u64, HEAP_ALIGNMENT as u64) as usize;
    if max_base_aligned < HEAP_DEFAULT_BASE {
        return None;
    }

    let slot_count = (max_base_aligned - HEAP_DEFAULT_BASE) / HEAP_ALIGNMENT;
    if slot_count == 0 {
        return None;
    }

    // Get optional entropy for random starting slot
    let rand_slot = rdrand64_early().map(|r| (r as usize) % (slot_count + 1));
    let start_slot = rand_slot.unwrap_or(0);

    // Iterate through all slots, starting from the random one
    for offset in 0..=slot_count {
        let slot_idx = (start_slot + offset) % (slot_count + 1);
        let heap_base = HEAP_DEFAULT_BASE + slot_idx * HEAP_ALIGNMENT;

        // Convert virtual address to physical (bootloader maps phys 0-1GB to 0xffffffff80000000)
        let phys_base = heap_base as u64 - PHYSICAL_MEMORY_OFFSET;

        if heap_range_usable(phys_base, HEAP_SIZE, map_info) {
            let randomized = rand_slot.is_some();
            return Some((heap_base, randomized));
        }
    }

    // No valid slot found in UEFI memory map
    None
}

/// Check if a candidate heap physical range is entirely within usable UEFI memory.
///
/// A range is usable if:
/// 1. It's within the bootloader's direct-map limit (1GB)
/// 2. It's above MIN_SAFE_ADDRESS (1MB, protecting legacy hardware)
/// 3. It's fully contained within an EFI_CONVENTIONAL_MEMORY or EFI_BOOT_SERVICES region
fn heap_range_usable(phys_base: u64, len: usize, map_info: &MemoryMapInfo) -> bool {
    let phys_end = phys_base.saturating_add(len as u64);

    // Must be within bootloader's direct-map range
    if phys_end > HIGH_HALF_MAP_LIMIT {
        return false;
    }

    // Must be above MIN_SAFE_ADDRESS
    if phys_base < MIN_SAFE_ADDRESS {
        return false;
    }

    let desc_count = map_info.size / map_info.descriptor_size;

    for i in 0..desc_count {
        let addr = map_info.buffer + (i * map_info.descriptor_size) as u64;
        let desc = unsafe { &*(addr as *const EfiMemoryDescriptor) };

        // Only consider usable memory types
        let usable = matches!(
            desc.typ,
            EFI_CONVENTIONAL_MEMORY | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA
        );
        if !usable || desc.page_count == 0 {
            continue;
        }

        let region_start = align_up(desc.phys_start, PAGE_SIZE);
        let region_end = desc
            .phys_start
            .saturating_add(desc.page_count.saturating_mul(PAGE_SIZE));

        // Check if heap range is fully contained within this region
        if region_start <= phys_base && phys_end <= region_end {
            return true;
        }
    }

    false
}

/// Early RDRAND access for heap randomization (no CSPRNG dependency).
///
/// This function directly accesses the RDRAND instruction without relying
/// on the ChaCha20 CSPRNG, which is initialized after the heap.
fn rdrand64_early() -> Option<u64> {
    if !rdrand_supported_early() {
        return None;
    }

    // Retry up to 32 times (RDRAND may fail if entropy pool is depleted)
    for _ in 0..32 {
        let mut value: u64 = 0;
        let ok: u8;

        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }

        if ok == 1 {
            return Some(value);
        }

        spin_loop();
    }

    None
}

/// Check if CPU supports RDRAND (early boot, no allocations).
///
/// R72-4 FIX: Properly handle CPUID's rbx clobbering without UB.
/// LLVM uses rbx internally, so we must save and restore it via the stack.
/// Since we use push/pop, we cannot use `nostack` or `nomem` options
/// (push/pop both use stack memory).
fn rdrand_supported_early() -> bool {
    // CPUID.01H:ECX.RDRAND[bit 30]
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            lateout("ecx") ecx,
            lateout("edx") _,
            // No options - push/pop uses both stack and memory
        );
    }
    (ecx & (1 << 30)) != 0
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

    klog_always!("  Scanning UEFI memory map ({} descriptors)...", desc_count);

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

    klog!(
        Info,
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

/// 对齐到页边界（向下取整）
#[inline]
const fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
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
        klog!(Info, "=== Memory Statistics ===");
        klog!(Info, "Physical Memory:");
        klog!(
            Info,
            "  Total: {} pages ({} MB)",
            self.total_physical_pages,
            self.total_physical_pages * 4 / 1024
        );
        klog!(
            Info,
            "  Free:  {} pages ({} MB)",
            self.free_physical_pages,
            self.free_physical_pages * 4 / 1024
        );
        klog!(
            Info,
            "  Used:  {} pages ({} MB)",
            self.used_physical_pages,
            self.used_physical_pages * 4 / 1024
        );
        klog!(Info, "  Fragmentation: {}%", self.fragmentation_percent);
        klog!(Info, "Kernel Heap:");
        klog!(
            Info,
            "  Used:  {} KB / {} KB",
            self.heap_used_bytes / 1024,
            self.heap_total_bytes / 1024
        );
    }
}

// ============================================================================
// Partial KASLR: Public Accessors
// ============================================================================

/// Return the current heap base address.
///
/// This may differ from `HEAP_DEFAULT_BASE` if heap randomization was successful.
#[inline]
pub fn heap_base() -> usize {
    HEAP_BASE.load(Ordering::SeqCst)
}

/// Return the heap size in bytes.
#[inline]
pub fn heap_size() -> usize {
    HEAP_SIZE
}

/// Check if the heap was successfully randomized using early entropy.
///
/// Returns `true` if RDRAND was available and produced entropy during boot,
/// allowing the heap to be placed at a random address within the safe window.
#[inline]
pub fn heap_randomized() -> bool {
    HEAP_RANDOMIZED.load(Ordering::SeqCst)
}

/// Check if the heap address was validated against UEFI memory map.
///
/// Returns `true` if the heap base was verified to fall within
/// EFI_CONVENTIONAL_MEMORY regions during boot, ensuring it doesn't
/// overlap with ACPI tables or other reserved memory.
#[inline]
pub fn heap_validated() -> bool {
    HEAP_VALIDATED.load(Ordering::SeqCst)
}
