//! ELF 装载器
//!
//! 负责解析并加载 ELF64 可执行文件到用户地址空间
//!
//! 功能：
//! - 验证 ELF64 格式（x86_64, Executable）
//! - 按 PT_LOAD 段映射用户地址空间
//! - 处理 BSS（memsz > filesz 部分清零）
//! - 返回入口点和用户栈顶

use alloc::vec::Vec;
use core::{cmp, ptr};
use mm::memory::FrameAllocator;
use mm::{page_table, phys_to_virt};
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};
use xmas_elf::{
    header::{Class, Machine, Type as ElfType},
    program::Type as PhType,
    ElfFile,
};

// R93-6 FIX: Import cgroup module for memory accounting
use crate::cgroup;
use crate::process::current_cgroup_id;

/// 用户地址空间起始（4MB）
///
/// 用户程序加载在 4MB 处，这是经典的 Linux 用户空间起始地址。
/// 注意：bootloader 建立的恒等映射使用 2MB 大页，在映射用户空间前
/// 需要将冲突的大页拆分为 4KB 页（通过 ensure_pte_level）。
pub const USER_BASE: usize = 0x0040_0000;

/// 用户栈顶地址（用户空间顶部 - 8KB 守护页）
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// 用户栈大小（默认 2MB）
pub const USER_STACK_SIZE: usize = 0x20_0000;

/// 页大小
const PAGE_SIZE: usize = 0x1000;

/// Z-10 fix: 页映射记录类型，用于失败时统一回滚
type MappedEntry = (Page<Size4KiB>, PhysFrame<Size4KiB>);

/// ELF 加载错误
#[derive(Debug, Clone, Copy)]
pub enum ElfLoadError {
    /// ELF 魔数无效
    InvalidMagic,
    /// 不支持的 ELF 类型（非 64 位）
    UnsupportedClass,
    /// 不支持的机器架构（非 x86_64）
    UnsupportedMachine,
    /// 不支持的文件类型（非可执行文件）
    UnsupportedType,
    /// 非小端格式
    NotLittleEndian,
    /// 段地址超出允许范围
    SegmentOutOfRange,
    /// 同时可写可执行的段被拒绝（W^X 安全策略）
    WritableExecutableSegment,
    /// 段与栈区域重叠
    OverlapWithStack,
    /// 页映射失败
    MapFailed,
    /// 段数据越界
    OutOfBounds,
    /// 物理内存不足
    OutOfMemory,
    /// R93-6 FIX: Cgroup memory limit exceeded
    CgroupLimitExceeded,
}

/// ELF 加载结果
pub struct ElfLoadResult {
    /// 程序入口点地址
    pub entry: u64,
    /// 用户栈顶地址
    pub user_stack_top: u64,
    /// 堆起始地址（BSS 末尾，页对齐）
    ///
    /// 这是 brk(0) 的初始返回值，也是 brk_start 的初始值。
    /// 计算为所有 PT_LOAD 段中 (vaddr + memsz) 的最大值，向上对齐到页边界。
    pub brk_start: usize,
}

/// 为当前进程地址空间加载 ELF 映像
///
/// # 前置条件
///
/// - 调用方已切换到目标进程的地址空间（当前 CR3 是目标进程的页表）
/// - 用户空间未被映射（除内核高半区外）
///
/// # Arguments
///
/// * `image` - ELF 文件的原始字节
///
/// # Returns
///
/// 成功返回入口点和用户栈顶，失败返回错误码
pub fn load_elf(image: &[u8]) -> Result<ElfLoadResult, ElfLoadError> {
    let elf = ElfFile::new(image).map_err(|_| ElfLoadError::InvalidMagic)?;

    // 验证 ELF 头
    validate_elf_header(&elf)?;

    // R93-6 FIX: Get current process's cgroup ID for memory accounting.
    // Memory charged during ELF loading counts against the process's cgroup limits.
    // This prevents cgroup escape by loading large binaries.
    let cgroup_id = current_cgroup_id().unwrap_or(0);

    // Z-10 fix: 追踪所有已映射的页，用于失败时统一回滚
    // 这确保如果段 N 失败，段 0..N-1 的映射也会被清理
    //
    // 【性能优化】预分配容量避免动态扩容导致的堆分配
    // 估算：典型 ELF 约 10 个 LOAD 段 + 512 页用户栈
    // 每段平均 10 页 = 100 页 + 512 = ~612 页
    // 使用 1024 作为合理上限，避免堆碎片化
    let mut all_mappings: Vec<MappedEntry> = Vec::with_capacity(1024);

    // 追踪所有段的最高地址，用于计算 brk_start
    let mut highest_segment_end: usize = 0;

    // 加载所有 PT_LOAD 段
    for ph in elf.program_iter() {
        if ph.get_type() == Ok(PhType::Load) {
            // 计算段结束地址
            let vaddr = ph.virtual_addr() as usize;
            let memsz = ph.mem_size() as usize;
            if memsz > 0 {
                let segment_end = vaddr.saturating_add(memsz);
                if segment_end > highest_segment_end {
                    highest_segment_end = segment_end;
                }
            }

            if let Err(e) = load_segment_tracked(&elf, &ph, &mut all_mappings, cgroup_id) {
                // 回滚所有已成功映射的段
                rollback_all_mappings(&mut all_mappings, cgroup_id);
                return Err(e);
            }
        }
    }

    // 分配用户栈
    if let Err(e) = allocate_user_stack_tracked(&mut all_mappings, cgroup_id) {
        // 回滚所有已加载的段
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(e);
    }

    // 计算 brk_start：段末尾向上对齐到页边界
    let brk_start = (highest_segment_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // 验证 brk_start 不与栈区域重叠
    // 栈区域：[USER_STACK_TOP - USER_STACK_SIZE, USER_STACK_TOP)
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    if brk_start >= stack_base {
        println!(
            "ELF loader: brk_start 0x{:x} overlaps with stack at 0x{:x}",
            brk_start, stack_base
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::OverlapWithStack);
    }

    println!(
        "ELF loaded: entry=0x{:x}, brk_start=0x{:x}",
        elf.header.pt2.entry_point(),
        brk_start
    );

    // R24-9 fix: 验证入口点地址是 canonical 且在用户空间范围内
    // 防止恶意 ELF 设置内核地址或非法地址导致 #GP 或代码执行到错误位置
    let entry = elf.header.pt2.entry_point();
    if entry < USER_BASE as u64 || entry >= USER_STACK_TOP {
        println!(
            "ELF loader: invalid entry point 0x{:x} (valid range: 0x{:x}-0x{:x})",
            entry, USER_BASE, USER_STACK_TOP
        );
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }
    // 验证 canonical（虽然上面的范围检查已经隐含了这一点，但显式检查更安全）
    let sign_extended = ((entry as i64) >> 47) as u64;
    if sign_extended != 0 && sign_extended != 0x1FFFF {
        println!("ELF loader: non-canonical entry point 0x{:x}", entry);
        rollback_all_mappings(&mut all_mappings, cgroup_id);
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    // 【修复】初始 RSP 必须在已映射的栈页内
    // 栈分配从 (USER_STACK_TOP - USER_STACK_SIZE) 到 USER_STACK_TOP
    // 但 USER_STACK_TOP 所在的页边界不在映射范围内
    // 设置 RSP 为最后一个映射页的顶部，减去 16 字节确保 ABI 16字节对齐
    let initial_rsp = USER_STACK_TOP - 16;

    Ok(ElfLoadResult {
        entry: elf.header.pt2.entry_point(),
        user_stack_top: initial_rsp,
        brk_start,
    })
}

/// 验证 ELF 头
fn validate_elf_header(elf: &ElfFile) -> Result<(), ElfLoadError> {
    let hdr = &elf.header;

    // 验证魔数
    if hdr.pt1.magic != [0x7F, b'E', b'L', b'F'] {
        return Err(ElfLoadError::InvalidMagic);
    }

    // 验证 64 位
    match hdr.pt1.class() {
        Class::SixtyFour => {}
        _ => return Err(ElfLoadError::UnsupportedClass),
    }

    // 验证小端
    match hdr.pt1.data() {
        xmas_elf::header::Data::LittleEndian => {}
        _ => return Err(ElfLoadError::NotLittleEndian),
    }

    // 验证 x86_64
    if hdr.pt2.machine().as_machine() != Machine::X86_64 {
        return Err(ElfLoadError::UnsupportedMachine);
    }

    // 验证可执行文件
    if hdr.pt2.type_().as_type() != ElfType::Executable {
        return Err(ElfLoadError::UnsupportedType);
    }

    Ok(())
}

/// Z-10 fix: 加载单个程序段并追踪映射，便于失败时全局回滚
///
/// # Arguments
///
/// * `elf` - ELF 文件引用
/// * `ph` - 程序头
/// * `tracked` - 全局映射追踪向量，成功映射的页会被追加到此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory accounting
///
/// # Returns
///
/// 成功返回 Ok(())，失败时调用方负责使用 tracked 进行全局回滚
fn load_segment_tracked(
    elf: &ElfFile,
    ph: &xmas_elf::program::ProgramHeader,
    tracked: &mut Vec<MappedEntry>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(), ElfLoadError> {
    let vaddr = ph.virtual_addr() as usize;
    let memsz = ph.mem_size() as usize;
    let filesz = ph.file_size() as usize;
    let offset = ph.offset() as usize;

    // 跳过大小为 0 的段
    if memsz == 0 {
        return Ok(());
    }

    // R93-18 FIX: Reject malformed ELF with p_filesz > p_memsz.
    // In valid ELF, filesz <= memsz (the extra memsz - filesz bytes are BSS, zeroed).
    // If filesz > memsz, the segment is malformed and could cause truncated loads
    // or buffer overflows when copying file data.
    if filesz > memsz {
        return Err(ElfLoadError::OutOfBounds);
    }

    // 边界检查
    let end = vaddr.checked_add(memsz).ok_or(ElfLoadError::OutOfBounds)?;

    if vaddr < USER_BASE {
        return Err(ElfLoadError::SegmentOutOfRange);
    }

    if end as u64 >= USER_STACK_TOP - USER_STACK_SIZE as u64 {
        return Err(ElfLoadError::OverlapWithStack);
    }

    // 验证文件数据边界
    if offset.saturating_add(filesz) > elf.input.len() {
        return Err(ElfLoadError::OutOfBounds);
    }

    // 【W-1 安全修复】W^X (Write XOR Execute) 检查
    // 拒绝同时可写可执行的段，防止代码注入攻击
    // 恶意程序可能利用 RWX 段在运行时注入并执行任意代码
    let writable = ph.flags().is_write();
    let executable = ph.flags().is_execute();
    if writable && executable {
        return Err(ElfLoadError::WritableExecutableSegment);
    }

    // 计算需要映射的页
    let page_base = vaddr & !(PAGE_SIZE - 1);
    let page_offset = vaddr - page_base;
    let map_len = page_offset + memsz;
    let page_count = (map_len + PAGE_SIZE - 1) / PAGE_SIZE;

    // R93-6 FIX: Pre-charge memory for this segment.
    // This enforces cgroup memory limits during ELF loading, preventing bypass
    // by loading large binaries that exceed memory.max.
    let charge_bytes = (page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        println!(
            "ELF loader: cgroup memory limit exceeded for segment (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    // 确定页权限
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if ph.flags().is_write() {
        flags |= PageTableFlags::WRITABLE;
    }
    if !ph.flags().is_execute() {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    // Z-10 fix: 本段成功映射的页（用于数据复制）
    // 【性能优化】预分配精确容量，避免 push 时重新分配
    let mut segment_mapped: Vec<MappedEntry> = Vec::with_capacity(page_count);
    let mut frame_alloc = FrameAllocator::new();

    println!(
        "  load_segment: vaddr=0x{:x}, memsz={}, filesz={}, pages={}",
        vaddr, memsz, filesz, page_count
    );
    println!(
        "    flags: R={} W={} X={} => PTFlags: 0x{:x}",
        true,
        ph.flags().is_write(),
        ph.flags().is_execute(),
        flags.bits()
    );

    // 注意：用户地址空间的 4MB-6MB 区域已准备好 4KB 页表
    // ELF 加载器直接创建新的 4KB 页映射

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((page_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    println!(
                        "ELF loader: map_page FAILED for va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    // Z-10 fix: 释放刚分配但未映射成功的帧
                    // 调用方会使用 tracked 回滚所有已成功映射的页
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                // Z-10 fix: 追加到本段和全局追踪向量
                segment_mapped.push((page, frame));
                tracked.push((page, frame));
            }
            Ok(())
        })?;
    }

    // 【修复】使用直映物理地址访问内存，避免依赖当前 CR3
    // 首先清零所有映射的页面（防止信息泄漏）
    for (_, frame) in segment_mapped.iter() {
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        unsafe {
            ptr::write_bytes(base, 0, PAGE_SIZE);
        }
    }

    // 复制文件内容到正确的偏移位置
    let mut remaining_copy = filesz;
    let mut src_off = offset;
    for (idx, (_, frame)) in segment_mapped.iter().enumerate() {
        if remaining_copy == 0 {
            break;
        }
        let base = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        let start = if idx == 0 { page_offset } else { 0 };
        let len = cmp::min(PAGE_SIZE - start, remaining_copy);
        unsafe {
            ptr::copy_nonoverlapping(elf.input.as_ptr().add(src_off), base.add(start), len);
        }
        remaining_copy -= len;
        src_off += len;
    }

    Ok(())
}

/// Z-10 fix: 分配用户栈并追踪映射，便于失败时全局回滚
///
/// # Arguments
///
/// * `tracked` - 全局映射追踪向量，成功映射的页会被追加到此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory accounting
///
/// # Returns
///
/// 成功返回 Ok(())，失败时调用方负责使用 tracked 进行全局回滚
fn allocate_user_stack_tracked(
    tracked: &mut Vec<MappedEntry>,
    cgroup_id: cgroup::CgroupId,
) -> Result<(), ElfLoadError> {
    let stack_base = USER_STACK_TOP as usize - USER_STACK_SIZE;
    // 【修复】多分配一页，确保 USER_STACK_TOP 所在的页也被映射
    // musl libc 启动时会向上扫描栈查找 auxv 等数据结构
    let page_count = USER_STACK_SIZE / PAGE_SIZE + 1;

    // R93-6 FIX: Pre-charge memory for user stack.
    // This enforces cgroup memory limits for stack allocation.
    let charge_bytes = (page_count * PAGE_SIZE) as u64;
    if cgroup::try_charge_memory(cgroup_id, charge_bytes).is_err() {
        println!(
            "ELF loader: cgroup memory limit exceeded for stack (need {} bytes)",
            charge_bytes
        );
        return Err(ElfLoadError::CgroupLimitExceeded);
    }

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    // Z-10 fix: 本段成功映射的页（用于数据清零）
    // 【性能优化】预分配精确容量，避免 push 时重新分配
    let mut stack_mapped: Vec<MappedEntry> = Vec::with_capacity(page_count);
    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| -> Result<(), ElfLoadError> {
            for i in 0..page_count {
                let va = VirtAddr::new((stack_base + i * PAGE_SIZE) as u64);
                let page: Page<Size4KiB> = Page::containing_address(va);

                let frame = frame_alloc
                    .allocate_frame()
                    .ok_or(ElfLoadError::OutOfMemory)?;

                if let Err(e) = mgr.map_page(page, frame, flags, &mut frame_alloc) {
                    println!(
                        "ELF loader: map_page FAILED for stack va=0x{:x}: {:?}",
                        va.as_u64(),
                        e
                    );
                    // Z-10 fix: 释放刚分配但未映射成功的帧
                    // 调用方会使用 tracked 回滚所有已成功映射的页
                    frame_alloc.deallocate_frame(frame);
                    return Err(ElfLoadError::MapFailed);
                }

                // Z-10 fix: 追加到本段和全局追踪向量
                stack_mapped.push((page, frame));
                tracked.push((page, frame));
            }
            Ok(())
        })?;
    }

    // 【修复】使用直映物理地址清零栈区域
    let mut remaining = USER_STACK_SIZE;
    for (_, frame) in stack_mapped.iter() {
        let base = unsafe { phys_to_virt(frame.start_address()).as_mut_ptr::<u8>() };
        let len = cmp::min(PAGE_SIZE, remaining);
        unsafe {
            ptr::write_bytes(base, 0, len);
        }
        remaining -= len;
        if remaining == 0 {
            break;
        }
    }

    Ok(())
}

/// Z-10 fix: 回滚所有已追踪的映射（段 + 栈）
///
/// 当 ELF 加载过程中任何步骤失败时，调用此函数清理所有已成功建立的映射，
/// 防止物理帧泄漏和半成品地址空间。
///
/// # Arguments
///
/// * `tracked` - 已追踪的映射向量，函数会清空此向量
/// * `cgroup_id` - R93-6 FIX: Cgroup ID for memory uncharging
///
/// # Safety
///
/// 必须在当前进程的地址空间上下文中调用（CR3 指向目标页表）
fn rollback_all_mappings(tracked: &mut Vec<MappedEntry>, cgroup_id: cgroup::CgroupId) {
    if tracked.is_empty() {
        return;
    }

    let page_count = tracked.len();
    println!("ELF loader: rolling back {} mapped pages", page_count);

    // R93-6 FIX: Uncharge memory for all pages being rolled back.
    // This ensures cgroup memory accounting remains accurate on failure.
    let uncharge_bytes = (page_count * PAGE_SIZE) as u64;
    cgroup::uncharge_memory(cgroup_id, uncharge_bytes);

    let mut frame_alloc = FrameAllocator::new();

    unsafe {
        page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            while let Some((page, _expected_frame)) = tracked.pop() {
                // 尝试取消映射并释放物理帧
                match mgr.unmap_page(page) {
                    Ok(unmapped_frame) => {
                        frame_alloc.deallocate_frame(unmapped_frame);
                    }
                    Err(e) => {
                        println!(
                            "ELF rollback: unmap_page failed for va=0x{:x}: {:?}",
                            page.start_address().as_u64(),
                            e
                        );
                        // 继续尝试回滚其他页，不要因为一个失败就停止
                    }
                }
            }
        });
    }
}

/// 打印 ELF 文件信息（调试用）
pub fn print_elf_info(image: &[u8]) {
    if let Ok(elf) = ElfFile::new(image) {
        let hdr = &elf.header;
        println!("=== ELF Info ===");
        println!("Entry point: 0x{:x}", hdr.pt2.entry_point());
        println!("Program headers: {}", hdr.pt2.ph_count());

        for (i, ph) in elf.program_iter().enumerate() {
            if ph.get_type() == Ok(PhType::Load) {
                println!(
                    "  Segment {}: vaddr=0x{:x}, memsz=0x{:x}, filesz=0x{:x}",
                    i,
                    ph.virtual_addr(),
                    ph.mem_size(),
                    ph.file_size()
                );
            }
        }
    }
}
