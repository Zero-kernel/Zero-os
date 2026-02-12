//! 页表管理器
//!
//! 提供对x86_64页表的完整管理功能

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{
    instructions::interrupts,
    structures::paging::{
        page_table::PageTableEntry, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
        PageTableFlags, PhysFrame, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

/// 物理内存高半区偏移（bootloader 映射 0xffffffff80000000 -> 0）
/// 覆盖物理地址 0-1GB
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

/// VGA text buffer (phys 0xB8000) high-half alias
pub const VGA_PHYS_ADDR: u64 = 0x000b_8000;
pub const VGA_VIRT_ADDR: u64 = PHYSICAL_MEMORY_OFFSET + VGA_PHYS_ADDR;

/// Local APIC MMIO window (4 KiB at phys 0xFEE0_0000) dedicated high-half alias
pub const APIC_PHYS_ADDR: u64 = 0xfee0_0000;
pub const APIC_MMIO_SIZE: usize = 0x1000;
pub const APIC_VIRT_ADDR: u64 = 0xffff_ffff_fee0_0000; // PML4[511] unused slot

/// R67-5 FIX: Global page table lock for cross-CPU serialization.
///
/// This lock ensures that page table modifications from different CPUs are serialized.
/// Without this, concurrent calls to map_page/unmap_page from multiple CPUs could
/// cause torn PTE updates, partially written flags (W^X bypass), or frame reuse
/// while another CPU still has a stale TLB entry.
///
/// Long-term solution: Per-address-space locks + TLB shootdown with ACK.
static PT_LOCK: Mutex<()> = Mutex::new(());

/// R67-5 FIX: Public helper to acquire the global page table lock.
///
/// Use this when touching page tables directly (not via `with_current_manager`)
/// to ensure modifications remain serialized across CPUs.
///
/// # Example
///
/// ```rust,ignore
/// use mm::page_table::with_pt_lock;
///
/// with_pt_lock(|| {
///     // Safe to modify page tables here
///     recursive_pd(0, 0)[0].set_flags(...);
/// });
/// ```
#[inline]
pub fn with_pt_lock<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let _guard = PT_LOCK.lock();
    f()
}

#[inline]
fn get_phys_offset() -> VirtAddr {
    VirtAddr::new(PHYSICAL_MEMORY_OFFSET)
}

/// 将物理地址转换为可访问的虚拟地址（通过高半区直映）
///
/// # Safety
///
/// 调用者必须确保物理地址在 0-1GB 范围内（高半区直映覆盖的范围）
/// 超出此范围的物理地址将导致无效的虚拟地址
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYSICAL_MEMORY_OFFSET)
}

/// 页表管理器
pub struct PageTableManager {
    mapper: OffsetPageTable<'static>,
}

/// 基于当前活动的 CR3 构建临时页表管理器
///
/// 此函数在每次调用时从当前 CR3 读取页表根地址，确保始终操作正确的地址空间。
/// 这对于 COW 故障处理和 mmap/munmap 在多进程环境下正确工作至关重要。
///
/// # Safety
///
/// 调用者必须提供正确的物理内存偏移量。
/// 在回调函数执行期间，不得发生导致 CR3 切换的上下文切换。
///
/// # Security (R32-MM-1 fix)
///
/// 此函数在执行期间禁用中断，防止上下文切换导致操作错误的地址空间。
/// 这可以避免跨进程内存破坏漏洞。
///
/// # Security (R67-5 fix)
///
/// 此函数获取全局页表锁，防止多 CPU 并发修改页表导致的数据竞争。
pub unsafe fn with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> T
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    // R67-5 FIX: Acquire global page table lock to serialize cross-CPU modifications
    let _pt_guard = PT_LOCK.lock();

    // R32-MM-1 FIX: Disable interrupts to prevent CR3 switch during page table operations
    interrupts::without_interrupts(|| {
        let _ = physical_memory_offset; // 调用方参数保持兼容，实际使用固定偏移
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut manager = PageTableManager { mapper };
        f(&mut manager)
    })
}

impl PageTableManager {
    /// 创建新的页表管理器
    ///
    /// # Safety
    ///
    /// 调用者必须确保物理内存偏移量是正确的
    pub unsafe fn new(physical_memory_offset: VirtAddr) -> Self {
        let _ = physical_memory_offset; // 保持接口兼容
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);

        PageTableManager { mapper }
    }

    /// 映射虚拟页到物理帧
    pub fn map_page(
        &mut self,
        page: Page,
        frame: PhysFrame,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        use x86_64::structures::paging::mapper::MapToError;

        unsafe {
            self.mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|e| match e {
                    MapToError::FrameAllocationFailed => MapError::FrameAllocationFailed,
                    MapToError::ParentEntryHugePage => MapError::ParentEntryHugePage,
                    MapToError::PageAlreadyMapped(_) => MapError::PageAlreadyMapped,
                })?
                .flush();
        }

        Ok(())
    }

    /// 取消映射虚拟页
    pub fn unmap_page(&mut self, page: Page) -> Result<PhysFrame, UnmapError> {
        use x86_64::structures::paging::mapper::UnmapError as X64UnmapError;

        let (frame, flush) = self.mapper.unmap(page).map_err(|e| match e {
            X64UnmapError::PageNotMapped => UnmapError::PageNotMapped,
            X64UnmapError::ParentEntryHugePage => UnmapError::ParentEntryHugePage,
            X64UnmapError::InvalidFrameAddress(_) => UnmapError::InvalidFrameAddress,
        })?;

        flush.flush();
        Ok(frame)
    }

    /// 转换虚拟地址到物理地址
    pub fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        use x86_64::structures::paging::mapper::TranslateResult;

        match self.mapper.translate(addr) {
            TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
        }
    }

    /// 转换虚拟地址到物理地址并返回页表标志
    pub fn translate_with_flags(&self, addr: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        use x86_64::structures::paging::mapper::TranslateResult;

        match self.mapper.translate(addr) {
            TranslateResult::Mapped {
                frame,
                offset,
                flags,
                ..
            } => Some((frame.start_address() + offset, flags)),
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
        }
    }

    /// 修改页的标志位
    pub fn update_flags(
        &mut self,
        page: Page,
        flags: PageTableFlags,
    ) -> Result<(), UpdateFlagsError> {
        use x86_64::structures::paging::mapper::FlagUpdateError;

        unsafe {
            self.mapper
                .update_flags(page, flags)
                .map_err(|e| match e {
                    FlagUpdateError::PageNotMapped => UpdateFlagsError::PageNotMapped,
                    FlagUpdateError::ParentEntryHugePage => UpdateFlagsError::ParentEntryHugePage,
                })?
                .flush();
        }

        Ok(())
    }

    /// 映射一个连续的虚拟地址范围
    ///
    /// R32-MM-2 FIX: Uses checked arithmetic to prevent integer overflow
    /// R34-MM-1 FIX: Rolls back partial mappings on failure to prevent orphaned pages
    pub fn map_range(
        &mut self,
        start_virt: VirtAddr,
        start_phys: PhysAddr,
        size: usize,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        // R32-MM-2 FIX: Use checked_add to prevent overflow when rounding up
        let page_count = size.checked_add(0xfff).ok_or(MapError::InvalidRange)? / 0x1000;

        // R34-MM-1 FIX: Track successfully mapped pages for rollback on error
        let mut mapped_pages: Vec<Page<Size4KiB>> = Vec::with_capacity(page_count);

        for i in 0..page_count {
            // R32-MM-2 FIX: Use checked arithmetic for offset calculation
            let offset = (i as u64)
                .checked_mul(0x1000)
                .ok_or(MapError::InvalidRange)?;
            let virt_u64 = start_virt
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let phys_u64 = start_phys
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let page = Page::containing_address(VirtAddr::new(virt_u64));
            let frame = PhysFrame::containing_address(PhysAddr::new(phys_u64));

            // R34-MM-1 FIX: On error, roll back all previously mapped pages in this call
            if let Err(e) = self.map_page(page, frame, flags, frame_allocator) {
                // Unmap all pages that were successfully mapped before the failure
                for rollback_page in mapped_pages.drain(..) {
                    // Best effort: ignore errors during rollback
                    let _ = self.unmap_page(rollback_page);
                }
                return Err(e);
            }
            mapped_pages.push(page);
        }

        Ok(())
    }

    /// 取消映射一个连续的虚拟地址范围
    ///
    /// R35-MM-2 FIX: Uses checked arithmetic to prevent integer overflow,
    /// mirroring the safety measures in map_range().
    pub fn unmap_range(&mut self, start_virt: VirtAddr, size: usize) -> Result<(), UnmapError> {
        // R35-MM-2 FIX: Use checked_add to prevent overflow when rounding up
        let page_count = size.checked_add(0xfff).ok_or(UnmapError::InvalidRange)? / 0x1000;

        for i in 0..page_count {
            // R35-MM-2 FIX: Use checked arithmetic for offset calculation
            let offset = (i as u64)
                .checked_mul(0x1000)
                .ok_or(UnmapError::InvalidRange)?;
            let virt_u64 = start_virt
                .as_u64()
                .checked_add(offset)
                .ok_or(UnmapError::InvalidRange)?;
            let page = Page::containing_address(VirtAddr::new(virt_u64));
            self.unmap_page(page)?;
        }

        Ok(())
    }
}

/// 获取活动的4级页表
///
/// # Safety
///
/// 调用者必须确保物理内存偏移量是正确的
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

/// 以闭包方式访问当前活动的 PML4 页表
///
/// 此函数用于安全模块进行页表遍历和验证。
/// 它直接读取 CR3 获取当前活动的页表根。
///
/// # Safety
///
/// - 调用者必须确保在闭包执行期间 CR3 不会被切换
/// - 物理偏移量必须正确
/// - 不应在闭包中修改会导致当前执行路径无法访问的映射
///
/// # Example
///
/// ```rust,ignore
/// unsafe {
///     with_active_level_4_table(|pml4| {
///         for entry in pml4.iter() {
///             // Process entries...
///         }
///     });
/// }
/// ```
pub unsafe fn with_active_level_4_table<T, F>(f: F) -> T
where
    F: FnOnce(&mut PageTable) -> T,
{
    let phys_offset = get_phys_offset();
    let level_4_table = active_level_4_table(phys_offset);
    f(level_4_table)
}

/// 获取物理内存偏移量
///
/// 返回高半区直映的物理内存偏移量，用于安全模块访问页表。
#[inline]
pub fn get_physical_memory_offset() -> VirtAddr {
    get_phys_offset()
}

/// 页表映射错误
#[derive(Debug)]
pub enum MapError {
    FrameAllocationFailed,
    ParentEntryHugePage,
    PageAlreadyMapped,
    /// R32-MM-2 FIX: Invalid range (overflow in size or offset calculation)
    InvalidRange,
}

/// 页表取消映射错误
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress,
    /// R35-MM-2 FIX: Overflow or invalid range in unmap_range offset calculation
    InvalidRange,
}

/// 更新标志位错误
#[derive(Debug)]
pub enum UpdateFlagsError {
    PageNotMapped,
    ParentEntryHugePage,
}

/// 全局页表管理器实例
lazy_static::lazy_static! {
    pub static ref PAGE_TABLE_MANAGER: Mutex<Option<PageTableManager>> = Mutex::new(None);
}

/// 初始化页表管理器
///
/// # Safety
///
/// 只能调用一次，且必须在内核初始化早期调用
pub unsafe fn init(physical_memory_offset: VirtAddr) {
    let _ = physical_memory_offset; // 保持接口兼容
    let manager = PageTableManager::new(get_phys_offset());
    *PAGE_TABLE_MANAGER.lock() = Some(manager);

    klog_always!(
        "Page table manager initialized (PHYS_OFFSET: 0x{:x})",
        PHYSICAL_MEMORY_OFFSET
    );
}

/// 获取全局页表管理器
pub fn get_manager() -> Option<spin::MutexGuard<'static, Option<PageTableManager>>> {
    let guard = PAGE_TABLE_MANAGER.lock();
    if guard.is_some() {
        Some(guard)
    } else {
        None
    }
}

// ============================================================================
// 递归页表访问 - 用于访问任意物理地址的页表帧
// ============================================================================

/// 递归页表槽索引 (PML4[510] 指向 PML4 自身)
pub const RECURSIVE_INDEX: usize = 510;

/// 通过递归映射计算的 PML4 虚拟地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30 | 510 << 21 | 510 << 12)
pub const RECURSIVE_PML4_ADDR: u64 = 0xFFFF_FF7F_BFDF_E000;

/// 通过递归映射计算的 PDPT 基地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30 | 510 << 21)
pub const RECURSIVE_PDPT_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;

/// 通过递归映射计算的 PD 基地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30)
pub const RECURSIVE_PD_BASE: u64 = 0xFFFF_FF7F_8000_0000;

/// 通过递归映射计算的 PT 基地址
/// 地址计算: sign_extend(510 << 39)
pub const RECURSIVE_PT_BASE: u64 = 0xFFFF_FF00_0000_0000;

/// 获取当前活动的 PML4 表（通过递归映射）
///
/// # Safety
///
/// 需要递归页表槽已正确设置
#[inline]
pub unsafe fn recursive_pml4() -> &'static mut PageTable {
    &mut *(RECURSIVE_PML4_ADDR as *mut PageTable)
}

/// 获取指定 PML4 索引的 PDPT（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保该 PML4 条目存在且指向有效的 PDPT
#[inline]
pub unsafe fn recursive_pdpt(pml4_idx: usize) -> &'static mut PageTable {
    let addr = RECURSIVE_PDPT_BASE + (pml4_idx as u64) * 0x1000;
    &mut *(addr as *mut PageTable)
}

/// 获取指定索引的 PD（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保对应的页表条目存在且有效
#[inline]
pub unsafe fn recursive_pd(pml4_idx: usize, pdpt_idx: usize) -> &'static mut PageTable {
    let addr = RECURSIVE_PD_BASE + (pml4_idx as u64) * 0x20_0000 + (pdpt_idx as u64) * 0x1000;
    &mut *(addr as *mut PageTable)
}

/// 获取指定索引的 PT（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保对应的页表条目存在且有效
#[inline]
pub unsafe fn recursive_pt(
    pml4_idx: usize,
    pdpt_idx: usize,
    pd_idx: usize,
) -> &'static mut PageTable {
    let addr = RECURSIVE_PT_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pdpt_idx as u64) * 0x20_0000
        + (pd_idx as u64) * 0x1000;
    &mut *(addr as *mut PageTable)
}

// ============================================================================
// 4KB 页粒度支持 - 用于 MMIO 隔离和 W^X/NX 强制
// ============================================================================

/// Default flags for device MMIO mappings: RW, NX, uncached, write-through
#[inline]
pub fn mmio_flags() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
}

/// Demote a 2 MB PD huge page into a 4 KB page table, cloning flags.
///
/// This function splits a 2MB huge page entry into 512 4KB page entries,
/// preserving the original flags (minus HUGE_PAGE).
///
/// # Safety
///
/// - Caller must flush TLB after this operation if mappings are in use
/// - The pd_entry must point to a valid huge page entry
///
/// # Arguments
///
/// * `pd_entry` - Mutable reference to the PD entry to split
/// * `frame_allocator` - Allocator for the new page table frame
pub unsafe fn split_2m_entry(
    pd_entry: &mut PageTableEntry,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<&'static mut PageTable, MapError> {
    // Only split huge pages
    if !pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // Already a PT pointer, get the table
        let pt_virt = get_phys_offset() + pd_entry.addr().as_u64();
        return Ok(&mut *(pt_virt.as_mut_ptr::<PageTable>()));
    }

    // Allocate a new page table frame
    let pt_frame = frame_allocator
        .allocate_frame()
        .ok_or(MapError::FrameAllocationFailed)?;
    let pt_virt = get_phys_offset() + pt_frame.start_address().as_u64();
    let pt_ptr: *mut PageTable = pt_virt.as_mut_ptr();

    // Zero the new page table
    core::ptr::write_bytes(pt_ptr as *mut u8, 0, 4096);

    // Get base physical address from the huge page entry
    let base = pd_entry.addr().as_u64();

    // Prepare flags: remove HUGE_PAGE, ensure PRESENT
    let mut flags = pd_entry.flags();
    flags.remove(PageTableFlags::HUGE_PAGE);
    flags.insert(PageTableFlags::PRESENT);

    // Fill 512 PTEs, each mapping a 4KB page
    let pt = &mut *pt_ptr;
    for i in 0..512usize {
        let phys = PhysAddr::new(base + (i as u64) * 0x1000);
        pt[i].set_addr(phys, flags);
    }

    // Update PD entry to point to new page table (not a huge page anymore)
    // Preserve original flags (USER, NO_CACHE, etc.) minus leaf-only bits
    // HUGE_PAGE and DIRTY are leaf-only - must remove for PDE pointing to PT
    let mut pd_flags = pd_entry.flags();
    pd_flags.remove(PageTableFlags::HUGE_PAGE);
    pd_flags.remove(PageTableFlags::DIRTY);
    pd_flags.insert(PageTableFlags::PRESENT);
    pd_entry.set_addr(pt_frame.start_address(), pd_flags);

    Ok(&mut *pt_ptr)
}

/// Ensure a virtual page is backed by a 4 KB PTE (allocate tables or demote 2 MB leaves).
///
/// # Safety
///
/// Caller must ensure the virtual address is valid and CR3 won't change during operation.
///
/// # Note
///
/// This is an internal helper. Callers must hold PT_LOCK (see ensure_pte_range).
pub unsafe fn ensure_pte_level(
    page: Page<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    let phys_offset = get_phys_offset();
    let pml4 = active_level_4_table(phys_offset);

    // PML4 entry
    let pml4_idx = page.p4_index();
    let pml4e = &mut pml4[pml4_idx];
    if pml4e.is_unused() {
        return Err(MapError::ParentEntryHugePage);
    }

    // PDPT
    let pdpt_ptr: *mut PageTable = (phys_offset + pml4e.addr().as_u64()).as_mut_ptr();
    let pdpt = &mut *pdpt_ptr;
    let pdpt_idx = page.p3_index();
    let pdpte = &mut pdpt[pdpt_idx];

    // Check for 1GB huge page (not supported for demotion)
    if pdpte.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Err(MapError::ParentEntryHugePage);
    }

    // Allocate PD if needed
    if pdpte.is_unused() {
        let pd_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapError::FrameAllocationFailed)?;
        let pd_virt = phys_offset + pd_frame.start_address().as_u64();
        core::ptr::write_bytes(pd_virt.as_mut_ptr::<u8>(), 0, 4096);
        pdpte.set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    // PD
    let pd_ptr: *mut PageTable = (phys_offset + pdpte.addr().as_u64()).as_mut_ptr();
    let pd = &mut *pd_ptr;
    let pd_idx = page.p2_index();
    let pde = &mut pd[pd_idx];

    // Demote 2MB huge page to 4KB pages if needed
    if pde.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_2m_entry(pde, frame_allocator)?;
        // X-7 & R68-2 FIX: Flush the entire 2MB range on ALL CPUs.
        //
        // After splitting a huge page, remote CPUs may still have the original
        // 2MB TLB entry cached with (potentially) RWX permissions. If we only
        // flush locally, those CPUs will bypass any 4KB-level permission changes
        // (e.g., W^X enforcement) until the TLB entry naturally expires.
        //
        // We flush the entire 2MB region because TLB entries for huge pages
        // cover the whole range, not individual 4KB pages.
        let huge_base = page.start_address().as_u64() & !0x1f_ffffu64; // Align to 2MB
        crate::tlb_shootdown::flush_current_as_range(VirtAddr::new(huge_base), 0x20_0000);
    } else if pde.is_unused() {
        // Allocate new PT
        let pt_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapError::FrameAllocationFailed)?;
        let pt_virt = phys_offset + pt_frame.start_address().as_u64();
        core::ptr::write_bytes(pt_virt.as_mut_ptr::<u8>(), 0, 4096);
        pde.set_addr(
            pt_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    Ok(())
}

/// R67-5 FIX: Internal lock-free version of ensure_pte_range.
///
/// # Safety
///
/// - Caller must hold PT_LOCK
/// - Caller must ensure addresses are valid and CR3 won't change
unsafe fn ensure_pte_range_unlocked(
    start: VirtAddr,
    size: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    // R32-MM-2 FIX: Use checked_add to prevent overflow when rounding up
    let pages = size.checked_add(0xfff).ok_or(MapError::InvalidRange)? / 0x1000;
    for i in 0..pages {
        // R32-MM-2 FIX: Use checked arithmetic for offset calculation
        let offset = (i as u64)
            .checked_mul(0x1000)
            .ok_or(MapError::InvalidRange)?;
        let addr_u64 = start
            .as_u64()
            .checked_add(offset)
            .ok_or(MapError::InvalidRange)?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr_u64));
        ensure_pte_level(page, frame_allocator)?;
    }
    Ok(())
}

/// Ensure a range is mapped at PTE granularity (4KB pages).
///
/// # Safety
///
/// Caller must ensure addresses are valid and CR3 won't change.
///
/// R32-MM-2 FIX: Uses checked arithmetic to prevent integer overflow
///
/// # Security (R67-5 fix)
///
/// Acquires global PT_LOCK to serialize cross-CPU page table modifications.
pub unsafe fn ensure_pte_range(
    start: VirtAddr,
    size: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    // R67-5 FIX: Acquire global page table lock
    let _pt_guard = PT_LOCK.lock();
    ensure_pte_range_unlocked(start, size, frame_allocator)
}

/// Map or tighten an MMIO region with RW+NX+uncached flags.
///
/// This function ensures the target pages are at 4KB granularity and applies
/// MMIO-appropriate flags (writable, non-executable, non-cacheable).
///
/// # Safety
///
/// - Caller must ensure addresses are valid
/// - TLB will be flushed automatically
///
/// R32-MM-2 FIX: Uses checked arithmetic to prevent integer overflow
///
/// # Security (R67-5 fix)
///
/// Acquires global PT_LOCK once to serialize all page table modifications,
/// avoiding deadlock by using unlocked internal helpers.
pub unsafe fn map_mmio(
    virt: VirtAddr,
    phys: PhysAddr,
    size: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    // R67-5 FIX: Acquire global page table lock ONCE at top level
    let _pt_guard = PT_LOCK.lock();

    // R32-MM-2 FIX: Pre-calculate page count with overflow checking
    let pages = size.checked_add(0xfff).ok_or(MapError::InvalidRange)? / 0x1000;

    // R67-5 FIX: Keep CR3 stable and avoid preemption while the global lock is held.
    // Combine PTE splitting and mapping under a single interrupt-disabled section
    // to prevent CR3 switches while modifying page tables.
    let result = interrupts::without_interrupts(|| {
        // First ensure all pages are at 4KB granularity (use unlocked version)
        ensure_pte_range_unlocked(virt, size, frame_allocator)?;

        let flags = mmio_flags();
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut mgr = PageTableManager { mapper };

        for i in 0..pages {
            // R32-MM-2 FIX: Use checked arithmetic for offset calculation
            let offset = (i as u64)
                .checked_mul(0x1000)
                .ok_or(MapError::InvalidRange)?;
            let virt_u64 = virt
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let phys_u64 = phys
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_u64));
            let frame = PhysFrame::containing_address(PhysAddr::new(phys_u64));

            match mgr.map_page(page, frame, flags, frame_allocator) {
                Ok(()) => {}
                Err(MapError::PageAlreadyMapped) => {
                    // Verify existing mapping points to same physical frame
                    match mgr.translate_addr(page.start_address()) {
                        Some(mapped) if mapped == frame.start_address() => {
                            // Same frame, just update flags
                            mgr.update_flags(page, flags)
                                .map_err(|_| MapError::ParentEntryHugePage)?;
                        }
                        Some(_) => {
                            // Different frame mapped - conflict
                            return Err(MapError::PageAlreadyMapped);
                        }
                        None => {
                            // Inconsistent page table state
                            return Err(MapError::ParentEntryHugePage);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });

    result?;

    // R68-2 FIX: Propagate MMIO mapping/permission updates to ALL CPUs.
    //
    // MMIO mappings are typically shared across all CPUs (e.g., LAPIC, VGA buffer),
    // so remote CPUs must also invalidate their TLB entries. Using local-only flush
    // leaves stale entries on other CPUs, which could cause incorrect MMIO behavior
    // or permission bypass if the update was to tighten access.
    //
    // flush_current_as_range handles large ranges efficiently (full flush fallback).
    crate::tlb_shootdown::flush_current_as_range(virt, pages * 0x1000);

    Ok(())
}
