//! 内核栈守护页
//!
//! 为内核栈和双重错误 IST 栈分配带守护页的新栈区域，
//! 防止栈溢出导致静默内存损坏。
//!
//! ## 工作原理
//!
//! - 在高半区选择一段未映射的虚拟地址区域
//! - 使用 4KB 页映射，第一页保留为守护页（不映射）
//! - 实际栈从第二页开始
//! - 栈溢出时触发页错误（#PF），而非静默损坏
//!
//! ## 初始化顺序
//!
//! 必须在以下条件满足后调用：
//! 1. 内存管理（mm）已初始化
//! 2. 页表管理器已初始化
//! 3. 中断尚未启用（sti 之前）

use x86_64::{
    structures::paging::{PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

/// 页大小
const PAGE_SIZE: usize = 4096;

/// 内核栈区域基址（高半区未映射区域）
/// 位于 PML4[511] 但不在内核代码所在的 PDPT[510] 中
/// Bootloader 只映射了 PDPT[510]，其他 PDPT 槽位未使用
const KERNEL_STACK_REGION_BASE: u64 = 0xFFFF_FFFF_7000_0000;

/// 双重错误栈区域基址
/// 同样位于 PML4[511] 的未映射 PDPT 槽位中
const DOUBLE_FAULT_STACK_REGION_BASE: u64 = 0xFFFF_FFFF_6F00_0000;

/// 栈守护页安装错误
#[derive(Debug)]
pub enum GuardPageError {
    /// 无法分配物理内存
    AllocationFailed,
    /// 页表映射失败
    MappingFailed,
    /// 虚拟地址区域已被映射
    RegionAlreadyMapped,
}

/// 安装内核栈守护页
///
/// 为 TSS 的 RSP0（特权级切换栈）和 IST0（双重错误栈）分配带守护页的新栈。
///
/// # Safety
///
/// - 必须在 mm 和 page_table 初始化后调用
/// - 必须在启用中断前调用
/// - 只能调用一次
pub unsafe fn install() -> Result<(), GuardPageError> {
    // 使用当前页表管理器分配和映射栈
    mm::with_current_manager(VirtAddr::new(0), |mgr| {
        let mut frame_alloc = mm::FrameAllocator::new();

        // 1. 安装内核栈（RSP0）
        let kernel_stack_result = map_guarded_stack(
            mgr,
            &mut frame_alloc,
            VirtAddr::new(KERNEL_STACK_REGION_BASE),
            arch::KERNEL_STACK_SIZE,
        );

        let kernel_stack_top = match kernel_stack_result {
            Ok(top) => top,
            Err(e) => return Err(e),
        };

        // 立即更新 RSP0，即使后续 IST 设置失败也能保护内核栈
        arch::set_kernel_stack(kernel_stack_top.as_u64());

        // 2. 安装双重错误栈（IST0）
        let double_fault_stack_result = map_guarded_stack(
            mgr,
            &mut frame_alloc,
            VirtAddr::new(DOUBLE_FAULT_STACK_REGION_BASE),
            arch::DOUBLE_FAULT_STACK_SIZE,
        );

        let double_fault_stack_top = match double_fault_stack_result {
            Ok(top) => top,
            Err(e) => {
                // 内核栈已设置，IST 设置失败
                // 打印警告但继续运行（内核栈仍受保护）
                klog!(Warn, "  Warning: Failed to set up IST guard stack: {:?}", e);
                klog!(Warn, "  Double-fault handler will use static stack (less safe)");
                // 仍然返回成功，因为内核栈已设置
                klog!(Info, "  Guard page stack installed (partial):");
                klog!(Info,
                    "    - Kernel stack: 0x{:x} ({}KB + 4KB guard)",
                    kernel_stack_top.as_u64(),
                    arch::KERNEL_STACK_SIZE / 1024
                );
                return Ok(());
            }
        };

        // 3. 更新 IST0
        arch::set_ist_stack(
            arch::DOUBLE_FAULT_IST_INDEX as usize,
            double_fault_stack_top,
        );

        klog!(Info, "  Guard page stacks installed:");
        klog!(Info,
            "    - Kernel stack: 0x{:x} ({}KB + 4KB guard)",
            kernel_stack_top.as_u64(),
            arch::KERNEL_STACK_SIZE / 1024
        );
        klog!(Info,
            "    - Double-fault IST: 0x{:x} ({}KB + 4KB guard)",
            double_fault_stack_top.as_u64(),
            arch::DOUBLE_FAULT_STACK_SIZE / 1024
        );

        Ok(())
    })
}

/// 映射带守护页的栈
///
/// 布局：[守护页 (未映射)] [栈空间 (映射)]
///       base             base+PAGE_SIZE
///
/// 返回栈顶地址（向下生长，所以是 base + PAGE_SIZE + size）
fn map_guarded_stack(
    mgr: &mut mm::PageTableManager,
    frame_alloc: &mut mm::FrameAllocator,
    base: VirtAddr,
    size: usize,
) -> Result<VirtAddr, GuardPageError> {
    // 验证大小是页对齐的
    if size % PAGE_SIZE != 0 {
        return Err(GuardPageError::AllocationFailed);
    }

    let page_count = size / PAGE_SIZE;
    let total_pages = page_count + 1; // +1 for guard page

    // 验证整个区域（守护页 + 栈页）都未被映射
    for i in 0..total_pages {
        let addr = base + (i * PAGE_SIZE) as u64;
        if mgr.translate_addr(addr).is_some() {
            return Err(GuardPageError::RegionAlreadyMapped);
        }
    }

    // 实际栈从守护页之后开始
    let stack_base = base + PAGE_SIZE as u64;

    // 分配连续的物理帧
    let phys_start = frame_alloc
        .allocate_contiguous_frames(page_count)
        .ok_or(GuardPageError::AllocationFailed)?
        .start_address();

    // 映射栈页面（不映射守护页）
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::GLOBAL;

    mgr.map_range(stack_base, phys_start, size, flags, frame_alloc)
        .map_err(|_| GuardPageError::MappingFailed)?;

    // 清零新栈
    unsafe {
        core::ptr::write_bytes(stack_base.as_mut_ptr::<u8>(), 0, size);
    }

    // 返回栈顶（x86 栈向下生长）
    Ok(stack_base + size as u64)
}
