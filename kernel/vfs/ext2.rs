//! Ext2 filesystem implementation with write support
//!
//! Provides ext2 filesystem support:
//! - Mount and validate superblock
//! - Directory traversal and lookup
//! - File reading with page cache integration
//! - Basic file write support (direct blocks only)
//! - Block allocation with bitmap management
//!
//! Based on ext2 specification (https://www.nongnu.org/ext2-doc/)

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use block::BlockDevice;
use core::any::Any;
use core::cmp;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::{FileOps, SyscallError, VfsStat};
use mm::{
    buddy_allocator, page_cache, PageCacheEntry, PageState, PAGE_CACHE, PAGE_SIZE,
    PHYSICAL_MEMORY_OFFSET,
};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Ext2 magic number
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock offset from partition start
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// Root inode number
pub const EXT2_ROOT_INO: u32 = 2;

/// Number of direct blocks in inode
pub const EXT2_NDIR_BLOCKS: usize = 12;

/// Indirect block index
pub const EXT2_IND_BLOCK: usize = 12;

/// Double indirect block index
pub const EXT2_DIND_BLOCK: usize = 13;

/// Triple indirect block index
pub const EXT2_TIND_BLOCK: usize = 14;

/// File type in mode field
pub const EXT2_S_IFMT: u16 = 0xF000;
pub const EXT2_S_IFREG: u16 = 0x8000;
pub const EXT2_S_IFDIR: u16 = 0x4000;
pub const EXT2_S_IFLNK: u16 = 0xA000;

/// Directory entry file types
pub const EXT2_FT_REG_FILE: u8 = 1;
pub const EXT2_FT_DIR: u8 = 2;
pub const EXT2_FT_CHRDEV: u8 = 3;
pub const EXT2_FT_BLKDEV: u8 = 4;
pub const EXT2_FT_SYMLINK: u8 = 7;

/// Inode flags
pub const EXT2_IMMUTABLE_FL: u32 = 0x00000010;
pub const EXT2_APPEND_FL: u32 = 0x00000020;

/// Global filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(100);

// ============================================================================
// Safe On-Disk Data Access Helpers
// ============================================================================

/// Read a little-endian u32 from a byte buffer at the given index.
///
/// Ext2 on-disk structures store multi-byte integers in little-endian format.
/// This function avoids creating an unaligned `&[u32]` view over a `Vec<u8>`
/// buffer, which would be undefined behavior in Rust (Vec<u8> only guarantees
/// 1-byte alignment).
///
/// # Arguments
///
/// * `buf` - The byte buffer to read from
/// * `index` - The u32 index (not byte offset) within the buffer
///
/// # Returns
///
/// * `Ok(u32)` - The value at the given index
/// * `Err(FsError::Invalid)` - Index out of bounds or overflow
///
/// # R96-1 Fix
///
/// This replaces unsafe `slice::from_raw_parts(buf.as_ptr() as *const u32, ...)`
/// patterns that created UB from unaligned access.
#[inline]
fn read_u32_le(buf: &[u8], index: usize) -> Result<u32, FsError> {
    let offset = index
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(FsError::Invalid)?;
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(FsError::Invalid)?;
    let bytes = buf.get(offset..end).ok_or(FsError::Invalid)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

// ============================================================================
// On-disk structures
// ============================================================================

/// Ext2 superblock (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub r_blocks_count: u32,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_frag_size: i32,
    pub blocks_per_group: u32,
    pub frags_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub max_mnt_count: i16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    // Rev 1 fields
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algo_bitmap: u32,
    // Padding to 1024 bytes
    _padding: [u8; 820],
}

/// Block group descriptor (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2GroupDesc {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
    pub free_blocks_count: u16,
    pub free_inodes_count: u16,
    pub used_dirs_count: u16,
    pub pad: u16,
    pub reserved: [u8; 12],
}

/// Ext2 inode (on-disk format)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ext2InodeRaw {
    pub mode: u16,
    pub uid: u16,
    pub size_lo: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; 15],
    pub generation: u32,
    pub file_acl: u32,
    pub size_high_or_dir_acl: u32,
    pub faddr: u32,
    pub osd2: [u8; 12],
}

/// Directory entry header (on-disk format)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2DirEntryHead {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

// ============================================================================
// Ext2 Filesystem
// ============================================================================

/// Ext2 filesystem instance
pub struct Ext2Fs {
    fs_id: u64,
    dev: Arc<dyn BlockDevice>,
    /// Superblock (protected for write updates)
    superblock: RwLock<Ext2Superblock>,
    /// Block group descriptor table
    group_descs: RwLock<Vec<Ext2GroupDesc>>,
    block_size: u32,
    /// R99-4 FIX: Cached immutable copy of `blocks_count` for lock-free block
    /// validation.  In ext2 the total block count is fixed at mkfs time and
    /// never changes (only `free_blocks_count` is modified during allocation).
    blocks_count: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    root: RwLock<Option<Arc<Ext2Inode>>>,
    /// Serialize metadata updates requiring read-modify-write
    meta_lock: Mutex<()>,
    self_ref: Mutex<Option<Weak<Ext2Fs>>>,
}

impl Ext2Fs {
    /// Mount an ext2 filesystem from a block device
    pub fn mount(dev: Arc<dyn BlockDevice>) -> Result<Arc<Self>, FsError> {
        // Read superblock
        let (superblock, block_size) = Self::read_super(&dev)?;

        // Load block group descriptors
        let group_descs = Self::load_group_descs(&dev, &superblock, block_size)?;

        let inode_size = if superblock.rev_level >= 1 {
            superblock.inode_size
        } else {
            128 // Rev 0 uses fixed 128-byte inodes
        };

        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        let fs = Arc::new(Self {
            fs_id,
            dev,
            superblock: RwLock::new(superblock),
            group_descs: RwLock::new(group_descs),
            block_size,
            blocks_count: superblock.blocks_count,
            blocks_per_group: superblock.blocks_per_group,
            inodes_per_group: superblock.inodes_per_group,
            inode_size,
            root: RwLock::new(None),
            meta_lock: Mutex::new(()),
            self_ref: Mutex::new(None),
        });

        // Store self reference
        *fs.self_ref.lock() = Some(Arc::downgrade(&fs));

        // Load root inode
        let root_raw = fs.read_inode_raw(EXT2_ROOT_INO)?;
        let root = fs.wrap_inode(EXT2_ROOT_INO, root_raw);
        *fs.root.write() = Some(root);

        Ok(fs)
    }

    /// Read and validate superblock
    fn read_super(dev: &Arc<dyn BlockDevice>) -> Result<(Ext2Superblock, u32), FsError> {
        let sector_size = dev.sector_size() as u64;
        let start_sector = SUPERBLOCK_OFFSET / sector_size;

        // Read superblock (1024 bytes, may span 2 sectors)
        let mut buf = alloc::vec![0u8; 1024];
        dev.read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;

        // Parse superblock
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        // Vec<u8> only guarantees 1-byte alignment, not the 4-byte alignment
        // that Ext2Superblock requires.
        let sb: Ext2Superblock = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };

        // Validate magic
        if sb.magic != EXT2_SUPER_MAGIC {
            return Err(FsError::Invalid);
        }

        // R96-2 FIX: Use checked_shl to prevent overflow on crafted log_block_size.
        // A malicious superblock with log_block_size >= 22 would cause panic.
        let block_size = 1024u32
            .checked_shl(sb.log_block_size)
            .ok_or(FsError::Invalid)?;

        // Validate block size (1K-64K)
        if block_size < 1024 || block_size > 65536 {
            return Err(FsError::Invalid);
        }

        // R97-2 FIX: Validate first_data_block consistency with block_size.
        //
        // Per ext2 specification:
        // - For 1KiB block size: first_data_block MUST be 1 (boot block + superblock occupy block 0-1)
        // - For larger block sizes: first_data_block MUST be 0 (superblock fits in block 0)
        //
        // Mismatched values indicate either corruption or a malicious image attempting
        // to exploit groups_count/block allocation calculations.
        let expected_first_data_block = if block_size == 1024 { 1 } else { 0 };
        if sb.first_data_block != expected_first_data_block {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-1 FIX: Validate critical superblock fields to prevent DoS.
        //
        // A malicious superblock can cause:
        // - Division by zero if blocks_per_group or inodes_per_group is 0
        // - Massive allocation if groups_count is unbounded
        // - Out-of-bounds access via crafted group descriptors
        //
        // Minimum reasonable values:
        // - blocks_per_group: at least 8 blocks (8 * 1024 = 8KB minimum)
        // - inodes_per_group: at least 1 inode
        // - blocks_count: at least 1 block
        if sb.blocks_per_group == 0 || sb.blocks_per_group < 8 {
            return Err(FsError::Invalid);
        }
        if sb.inodes_per_group == 0 {
            return Err(FsError::Invalid);
        }
        if sb.blocks_count == 0 {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-4 FIX: Validate blocks_per_group/inodes_per_group against bitmap capacity.
        //
        // Each block bitmap and inode bitmap is exactly one block in size.
        // A block can only describe block_size * 8 entries (1 bit per entry).
        // If blocks_per_group or inodes_per_group exceeds this, the bitmap scan
        // in allocate_block will read beyond the buffer, causing a kernel panic.
        let max_bitmap_entries = block_size.saturating_mul(8);
        if sb.blocks_per_group > max_bitmap_entries || sb.inodes_per_group > max_bitmap_entries {
            return Err(FsError::Invalid);
        }

        // R65-EXT2-2 FIX: Bound groups_count to prevent memory exhaustion.
        //
        // Maximum practical limit: 64K groups (each group desc is 32 bytes = 2MB total).
        // This allows filesystems up to 64K * 128MB = 8TB (with 128MB per group).
        //
        // R96-2 FIX: Use checked arithmetic to prevent overflow on crafted blocks_count.
        // A malicious superblock with blocks_count near u32::MAX could overflow.
        let groups_count = sb
            .blocks_count
            .checked_add(sb.blocks_per_group - 1)
            .ok_or(FsError::Invalid)?
            / sb.blocks_per_group;
        const MAX_GROUPS: u32 = 65536;
        if groups_count > MAX_GROUPS {
            return Err(FsError::Invalid);
        }

        Ok((sb, block_size))
    }

    /// Load block group descriptor table.
    ///
    /// # R99-2 FIX: Defense-in-depth checked arithmetic and BGDT bounds
    ///
    /// Although `read_super()` already validates `blocks_per_group >= 8` and
    /// `blocks_count > 0`, this function re-derives `groups_count` from the
    /// superblock.  Using checked arithmetic here guards against any future
    /// caller that bypasses `read_super()` validation, and validates that the
    /// BGDT itself fits within the filesystem.
    fn load_group_descs(
        dev: &Arc<dyn BlockDevice>,
        sb: &Ext2Superblock,
        block_size: u32,
    ) -> Result<Vec<Ext2GroupDesc>, FsError> {
        // R99-2 FIX: Calculate number of block groups using checked arithmetic.
        // ceil_div(blocks_count, blocks_per_group) without overflow.
        let bpg_minus_one = sb.blocks_per_group.checked_sub(1).ok_or(FsError::Invalid)?;
        let groups_count = sb
            .blocks_count
            .checked_add(bpg_minus_one)
            .ok_or(FsError::Invalid)?
            / sb.blocks_per_group;

        // BGDT starts at block 2 for 1K blocks, block 1 for larger blocks
        let bgdt_block: u32 = if block_size == 1024 { 2 } else { 1 };

        // R99-2 FIX: Validate that the BGDT start block is within filesystem bounds.
        if bgdt_block >= sb.blocks_count {
            return Err(FsError::Invalid);
        }

        let bgdt_offset = bgdt_block as u64 * block_size as u64;

        // Read BGDT
        let bgdt_size = (groups_count as usize)
            .checked_mul(size_of::<Ext2GroupDesc>())
            .ok_or(FsError::Invalid)?;
        let sector_size = dev.sector_size() as usize;
        if sector_size == 0 {
            return Err(FsError::Invalid);
        }
        let sectors_needed = bgdt_size
            .checked_add(sector_size - 1)
            .ok_or(FsError::Invalid)?
            / sector_size;
        let read_len = sectors_needed
            .checked_mul(sector_size)
            .ok_or(FsError::Invalid)?;

        // R99-2 FIX: Ensure the BGDT does not extend beyond the filesystem.
        let fs_byte_size = (sb.blocks_count as u64)
            .checked_mul(block_size as u64)
            .ok_or(FsError::Invalid)?;
        let bgdt_end = bgdt_offset
            .checked_add(read_len as u64)
            .ok_or(FsError::Invalid)?;
        if bgdt_end > fs_byte_size {
            return Err(FsError::Invalid);
        }

        let mut buf = alloc::vec![0u8; read_len];

        let start_sector = bgdt_offset / sector_size as u64;
        dev.read_sync(start_sector, &mut buf)
            .map_err(|_| FsError::Io)?;

        // Parse group descriptors
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        let mut descs = Vec::with_capacity(groups_count as usize);
        for i in 0..groups_count as usize {
            let offset = i * size_of::<Ext2GroupDesc>();
            let gd: Ext2GroupDesc =
                unsafe { core::ptr::read_unaligned(buf[offset..].as_ptr() as *const _) };
            descs.push(gd);
        }

        Ok(descs)
    }

    /// Read a block from the device.
    ///
    /// # R99-1 FIX: Defense-in-depth bounds validation
    ///
    /// Mirror `write_block()` by calling `validate_block()` before issuing I/O.
    /// Block 0 is treated as a sparse block (zero-filled) rather than performing
    /// a device read at offset 0.
    fn read_block(&self, block_no: u32, buf: &mut [u8]) -> Result<(), FsError> {
        if buf.len() < self.block_size as usize {
            return Err(FsError::Invalid);
        }

        // R99-1 FIX: Validate block number against filesystem bounds.
        // validate_block returns None for block 0 (sparse), Some(n) for valid,
        // or Err for out-of-bounds.  Deadlock-safe (R99-4: uses cached blocks_count).
        let block_no = match self.validate_block(block_no)? {
            Some(b) => b,
            None => {
                // Sparse block: zero-fill the buffer instead of reading
                buf[..self.block_size as usize].fill(0);
                return Ok(());
            }
        };

        let sector_size = self.dev.sector_size() as u64;
        let block_offset = block_no as u64 * self.block_size as u64;
        let start_sector = block_offset / sector_size;

        self.dev
            .read_sync(start_sector, &mut buf[..self.block_size as usize])
            .map(|_| ())
            .map_err(|_| FsError::Io)
    }

    /// Write a block to the device
    fn write_block(&self, block_no: u32, data: &[u8]) -> Result<(), FsError> {
        if data.len() < self.block_size as usize {
            return Err(FsError::Invalid);
        }
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        // Validate block number is within bounds
        let block_no = self.validate_block(block_no)?.ok_or(FsError::Invalid)?;

        let sector_size = self.dev.sector_size() as u64;
        let block_offset = block_no as u64 * self.block_size as u64;
        let start_sector = block_offset / sector_size;

        self.dev
            .write_sync(start_sector, &data[..self.block_size as usize])
            .map(|_| ())
            .map_err(|_| FsError::Io)
    }

    /// Read raw inode from disk
    fn read_inode_raw(&self, ino: u32) -> Result<Ext2InodeRaw, FsError> {
        let sb = self.superblock.read();
        if ino == 0 || ino > sb.inodes_count {
            return Err(FsError::NotFound);
        }
        let blocks_count = sb.blocks_count;
        drop(sb);

        // Calculate group and index
        let (group, index) = self.inode_group_index(ino);

        // Get inode table block
        // R65-EXT2-3 FIX: Bounds check group descriptor access to prevent OOB read.
        let group_descs = self.group_descs.read();
        if group >= group_descs.len() {
            return Err(FsError::Invalid);
        }
        let inode_table_block = group_descs[group].inode_table;
        drop(group_descs);

        // Validate inode table block is within filesystem bounds
        if inode_table_block == 0 || inode_table_block >= blocks_count {
            return Err(FsError::Invalid);
        }

        // Calculate offset within inode table
        let inode_offset = index as u64 * self.inode_size as u64;
        let block_offset = inode_offset / self.block_size as u64;
        let offset_in_block = inode_offset % self.block_size as u64;

        // R65-EXT2-5 FIX: Use checked arithmetic to prevent overflow and validate bounds.
        // A malicious inodes_per_group/inode_size could cause block_offset to overflow u32
        // or push the computed block past filesystem bounds.
        if block_offset > u32::MAX as u64 {
            return Err(FsError::Invalid);
        }
        let inode_block = inode_table_block
            .checked_add(block_offset as u32)
            .filter(|b| *b < blocks_count)
            .ok_or(FsError::Invalid)?;

        // Read the block containing the inode
        let mut block_buf = alloc::vec![0u8; self.block_size as usize];
        self.read_block(inode_block, &mut block_buf)?;

        // R95-3 FIX: Bounds check inode read to prevent OOB access.
        // A crafted inode_size or offset could cause reading past block boundary.
        let start = offset_in_block as usize;
        let end = start
            .checked_add(size_of::<Ext2InodeRaw>())
            .ok_or(FsError::Invalid)?;
        if end > block_buf.len() {
            return Err(FsError::Invalid);
        }

        // Parse inode
        // R95-3 FIX: Use read_unaligned to avoid UB on unaligned access.
        let inode: Ext2InodeRaw =
            unsafe { core::ptr::read_unaligned(block_buf[start..].as_ptr() as *const _) };

        Ok(inode)
    }

    /// Write raw inode back to disk
    fn write_inode_raw(&self, ino: u32, raw: &Ext2InodeRaw) -> Result<(), FsError> {
        let sb = self.superblock.read();
        if ino == 0 || ino > sb.inodes_count {
            return Err(FsError::NotFound);
        }
        let blocks_count = sb.blocks_count;
        drop(sb);

        // Serialize inode table updates
        let _guard = self.meta_lock.lock();

        let (group, index) = self.inode_group_index(ino);
        // R65-EXT2-3 FIX: Bounds check group descriptor access to prevent OOB read.
        let group_descs = self.group_descs.read();
        if group >= group_descs.len() {
            return Err(FsError::Invalid);
        }
        let inode_table_block = group_descs[group].inode_table;
        drop(group_descs);

        // Validate inode table block is within filesystem bounds
        if inode_table_block == 0 || inode_table_block >= blocks_count {
            return Err(FsError::Invalid);
        }

        let inode_offset = index as u64 * self.inode_size as u64;
        let block_offset = inode_offset / self.block_size as u64;
        let offset_in_block = inode_offset % self.block_size as u64;

        // R65-EXT2-5 FIX: Use checked arithmetic to prevent overflow and validate bounds.
        if block_offset > u32::MAX as u64 {
            return Err(FsError::Invalid);
        }
        let inode_block = inode_table_block
            .checked_add(block_offset as u32)
            .filter(|b| *b < blocks_count)
            .ok_or(FsError::Invalid)?;

        // Read-modify-write the block containing the inode
        let mut block_buf = alloc::vec![0u8; self.block_size as usize];
        self.read_block(inode_block, &mut block_buf)?;

        // Copy inode data into buffer
        let copy_len = cmp::min(self.inode_size as usize, size_of::<Ext2InodeRaw>());
        let start = offset_in_block as usize;
        let end = start + self.inode_size as usize;
        if end > block_buf.len() {
            return Err(FsError::Invalid);
        }

        let raw_bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(raw as *const _ as *const u8, copy_len) };
        block_buf[start..start + copy_len].copy_from_slice(raw_bytes);
        // Zero padding if inode_size > Ext2InodeRaw
        if self.inode_size as usize > copy_len {
            block_buf[start + copy_len..end].fill(0);
        }

        self.write_block(inode_block, &block_buf)
    }

    /// Write updated superblock to disk
    fn write_superblock(&self) -> Result<(), FsError> {
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        let sb = *self.superblock.read();
        let mut buf = alloc::vec![0u8; 1024];
        let sb_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(&sb as *const _ as *const u8, size_of::<Ext2Superblock>())
        };
        buf[..sb_bytes.len()].copy_from_slice(sb_bytes);

        let sector_size = self.dev.sector_size() as u64;
        let start_sector = SUPERBLOCK_OFFSET / sector_size;

        self.dev
            .write_sync(start_sector, &buf)
            .map(|_| ())
            .map_err(|_| FsError::Io)
    }

    /// Write a block group descriptor to disk
    fn write_group_desc(&self, group: usize, desc: &Ext2GroupDesc) -> Result<(), FsError> {
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        let descs_per_block = (self.block_size as usize) / size_of::<Ext2GroupDesc>();
        let bgdt_block = if self.block_size == 1024 { 2 } else { 1 };
        let block = bgdt_block + (group / descs_per_block) as u32;
        let offset = (group % descs_per_block) * size_of::<Ext2GroupDesc>();

        // Read-modify-write the block containing the descriptor
        let mut buf = alloc::vec![0u8; self.block_size as usize];
        self.read_block(block, &mut buf)?;

        let desc_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(desc as *const _ as *const u8, size_of::<Ext2GroupDesc>())
        };
        buf[offset..offset + size_of::<Ext2GroupDesc>()].copy_from_slice(desc_bytes);

        self.write_block(block, &buf)
    }

    /// Allocate a block by scanning the group bitmaps
    ///
    /// Returns the physical block number of the allocated block.
    ///
    /// FIXME(R38): If I/O fails after bitmap write but before descriptor/superblock
    /// persist, the block is leaked (marked used but counters not updated). A full
    /// fsck or journal would be needed to handle this properly.
    fn allocate_block(&self) -> Result<u32, FsError> {
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        // Serialize block allocation
        let _guard = self.meta_lock.lock();
        let mut sb = self.superblock.write();
        let mut group_descs = self.group_descs.write();

        if sb.free_blocks_count == 0 {
            return Err(FsError::NoSpace);
        }

        let groups_count = (sb.blocks_count + sb.blocks_per_group - 1) / sb.blocks_per_group;

        for group in 0..groups_count as usize {
            // R65-EXT2-3 FIX: Bounds check group descriptor access
            if group >= group_descs.len() {
                break;
            }
            if group_descs[group].free_blocks_count == 0 {
                continue;
            }

            // Validate block_bitmap is within filesystem bounds
            let block_bitmap = group_descs[group].block_bitmap;
            if block_bitmap == 0 || block_bitmap >= sb.blocks_count {
                continue; // Skip corrupted group descriptor
            }

            // Read the block bitmap for this group
            let mut bitmap = alloc::vec![0u8; self.block_size as usize];
            self.read_block(block_bitmap, &mut bitmap)?;

            // Calculate blocks in this group
            let group_blocks = cmp::min(
                sb.blocks_per_group,
                sb.blocks_count
                    .saturating_sub(group as u32 * sb.blocks_per_group),
            );
            let group_start = sb.first_data_block + group as u32 * sb.blocks_per_group;

            // Scan bitmap for free block
            for bit in 0..group_blocks {
                let byte_idx = (bit / 8) as usize;
                let bit_mask = 1u8 << (bit % 8);

                if (bitmap[byte_idx] & bit_mask) != 0 {
                    continue; // Block is in use
                }

                // Found free block - mark it as used
                bitmap[byte_idx] |= bit_mask;
                let phys_block = group_start + bit;

                // Write updated bitmap (using validated block_bitmap)
                self.write_block(block_bitmap, &bitmap)?;

                // Update counters
                group_descs[group].free_blocks_count -= 1;
                sb.free_blocks_count -= 1;

                // Persist metadata
                let desc = group_descs[group];
                drop(group_descs);
                drop(sb);

                self.write_group_desc(group, &desc)?;
                self.write_superblock()?;

                return Ok(phys_block);
            }
        }

        Err(FsError::NoSpace)
    }

    /// Set a direct block pointer in an inode
    ///
    /// Only supports direct blocks (0-11) for now.
    fn set_file_block(
        &self,
        raw: &mut Ext2InodeRaw,
        file_block: u32,
        phys_block: u32,
    ) -> Result<(), FsError> {
        if file_block >= EXT2_NDIR_BLOCKS as u32 {
            return Err(FsError::NotSupported); // Only direct blocks for now
        }

        // Validate the physical block
        if self.validate_block(phys_block)?.is_none() {
            return Err(FsError::Invalid);
        }

        let old = raw.block[file_block as usize];
        raw.block[file_block as usize] = phys_block;

        // Update block count if allocating a new block
        if old == 0 {
            let sectors_per_block = self.block_size / 512;
            raw.blocks_lo = raw
                .blocks_lo
                .checked_add(sectors_per_block)
                .ok_or(FsError::Invalid)?;
        }

        Ok(())
    }

    /// Wrap a raw inode into an Ext2Inode
    fn wrap_inode(self: &Arc<Self>, ino: u32, raw: Ext2InodeRaw) -> Arc<Ext2Inode> {
        let size = if raw.mode & EXT2_S_IFREG != 0 {
            // Regular file: use size_high for large files
            ((raw.size_high_or_dir_acl as u64) << 32) | (raw.size_lo as u64)
        } else {
            // Directories: only use size_lo
            raw.size_lo as u64
        };

        Arc::new(Ext2Inode {
            fs: Arc::downgrade(self),
            fs_id: self.fs_id,
            ino,
            raw: RwLock::new(raw),
            size: AtomicU64::new(size),
            write_lock: Mutex::new(()),
        })
    }

    /// Calculate group and index for an inode number
    fn inode_group_index(&self, ino: u32) -> (usize, usize) {
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as usize;
        (group, index)
    }

    /// R28-5 Fix: Validate block number against filesystem bounds.
    ///
    /// # R99-4 FIX: Lock-free block validation via cached `blocks_count`
    ///
    /// Previously this function used `self.superblock.read()` which caused a
    /// deadlock when called from `write_block()` → `allocate_block()` (the
    /// latter holds `superblock.write()`).  Since `blocks_count` is immutable
    /// after mkfs, we cache it in `Ext2Fs` at mount time and check against
    /// the cached copy — no lock required.
    #[inline]
    fn validate_block(&self, block: u32) -> Result<Option<u32>, FsError> {
        if block == 0 {
            Ok(None)
        } else if block >= self.blocks_count {
            Err(FsError::Invalid)
        } else {
            Ok(Some(block))
        }
    }

    /// Map a file block number to physical block number
    fn map_file_block(&self, raw: &Ext2InodeRaw, file_block: u32) -> Result<Option<u32>, FsError> {
        let ptrs_per_block = self.block_size / 4; // 4 bytes per u32 pointer

        // Direct blocks (0-11)
        if file_block < EXT2_NDIR_BLOCKS as u32 {
            let block = raw.block[file_block as usize];
            return self.validate_block(block);
        }

        let file_block = file_block - EXT2_NDIR_BLOCKS as u32;

        // Single indirect (block 12)
        if file_block < ptrs_per_block {
            // R28-5 Fix: Validate indirect block pointer
            let ind_block = match self.validate_block(raw.block[EXT2_IND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            let mut buf = alloc::vec![0u8; self.block_size as usize];
            self.read_block(ind_block, &mut buf)?;

            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ptr = read_u32_le(&buf, file_block as usize)?;
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptr);
        }

        let file_block = file_block - ptrs_per_block;

        // Double indirect (block 13)
        if file_block < ptrs_per_block * ptrs_per_block {
            // R28-5 Fix: Validate double indirect block pointer
            let dind_block = match self.validate_block(raw.block[EXT2_DIND_BLOCK])? {
                Some(b) => b,
                None => return Ok(None),
            };

            let mut buf = alloc::vec![0u8; self.block_size as usize];
            self.read_block(dind_block, &mut buf)?;

            let ind_index = file_block / ptrs_per_block;
            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ind_ptr = read_u32_le(&buf, ind_index as usize)?;
            // R28-5 Fix: Validate indirect block pointer from double indirect table
            let ind_block = match self.validate_block(ind_ptr)? {
                Some(b) => b,
                None => return Ok(None),
            };

            self.read_block(ind_block, &mut buf)?;

            let block_index = file_block % ptrs_per_block;
            // R96-1 Fix: Use safe little-endian read instead of UB from unaligned
            // slice::from_raw_parts. Vec<u8> only guarantees 1-byte alignment.
            let ptr = read_u32_le(&buf, block_index as usize)?;
            // R28-5 Fix: Validate data block pointer
            return self.validate_block(ptr);
        }

        // Triple indirect would go here, but for simplicity we return an error
        Err(FsError::Invalid)
    }
}

impl FileSystem for Ext2Fs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "ext2"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.read().as_ref().unwrap().clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Downcast to Ext2Inode
        let parent = parent
            .as_any()
            .downcast_ref::<Ext2Inode>()
            .ok_or(FsError::Invalid)?;

        if !parent.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        // Search directory entries
        parent.dir_lookup(name)
    }
}

// ============================================================================
// Ext2 Inode
// ============================================================================

/// Ext2 inode wrapper
pub struct Ext2Inode {
    fs: Weak<Ext2Fs>,
    fs_id: u64,
    ino: u32,
    /// On-disk inode data (protected for write updates)
    raw: RwLock<Ext2InodeRaw>,
    /// File size (atomic for concurrent reads)
    size: AtomicU64,
    /// Serialize writes to this inode
    write_lock: Mutex<()>,
}

impl Ext2Inode {
    /// Check if this is a directory
    fn is_dir_inner(&self) -> bool {
        (self.raw.read().mode & EXT2_S_IFMT) == EXT2_S_IFDIR
    }

    /// Check if this is a regular file
    fn is_file_inner(&self) -> bool {
        (self.raw.read().mode & EXT2_S_IFMT) == EXT2_S_IFREG
    }

    /// Look up a name in this directory
    fn dir_lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;

        let mut offset = 0u64;
        let file_size = self.size.load(Ordering::Acquire);
        let raw = *self.raw.read();
        let mut block_buf = alloc::vec![0u8; fs.block_size as usize];

        while offset < file_size {
            // Calculate which block to read
            let file_block_u64 = offset / fs.block_size as u64;
            // R97-3 FIX: Use try_from instead of truncating cast to prevent wraparound
            let file_block =
                u32::try_from(file_block_u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = offset % fs.block_size as u64;

            // Map to physical block
            let phys_block = fs.map_file_block(&raw, file_block)?;
            if let Some(phys) = phys_block {
                fs.read_block(phys, &mut block_buf)?;
            } else {
                // Hole - zero-filled
                block_buf.fill(0);
            }

            // Parse directory entry
            let data = &block_buf[offset_in_block as usize..];
            if data.len() < size_of::<Ext2DirEntryHead>() {
                break;
            }

            // R96-8 Fix: Use read_unaligned to avoid UB from unaligned access.
            // Vec<u8> only guarantees 1-byte alignment, but Ext2DirEntryHead
            // contains u32/u16 fields that may require higher alignment.
            let head: Ext2DirEntryHead =
                unsafe { core::ptr::read_unaligned(data.as_ptr() as *const _) };

            if head.rec_len == 0 {
                break;
            }

            // R28-4 Fix: Validate rec_len and name_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            let min_rec = size_of::<Ext2DirEntryHead>();
            if rec_len < min_rec || (offset_in_block as usize) + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }
            if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                return Err(FsError::Invalid);
            }

            if head.inode != 0 && head.name_len > 0 {
                let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                if let Ok(entry_name) = core::str::from_utf8(name_bytes) {
                    if entry_name == name {
                        // Found it!
                        let raw = fs.read_inode_raw(head.inode)?;
                        return Ok(fs.wrap_inode(head.inode, raw));
                    }
                }
            }

            offset += head.rec_len as u64;
        }

        Err(FsError::NotFound)
    }

    /// Read file data at offset using page cache
    ///
    /// This implementation routes all file reads through the global page cache,
    /// providing caching and reducing disk I/O for repeated accesses.
    fn read_file_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let file_size = self.size.load(Ordering::Acquire);
        if offset >= file_size {
            return Ok(0);
        }

        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        let block_size = fs.block_size as usize;

        // Create unique inode_id for page cache: combine fs_id and ino
        // Use upper 32 bits for fs_id, lower 32 bits for ino
        let cache_inode_id = (self.fs_id << 32) | (self.ino as u64);
        let raw_inode = *self.raw.read();

        let to_read = buf.len().min((file_size - offset) as usize);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let file_offset = offset + bytes_read as u64;
            let page_index = file_offset / PAGE_SIZE as u64;
            let offset_in_page = (file_offset % PAGE_SIZE as u64) as usize;
            let remaining_in_page = PAGE_SIZE - offset_in_page;
            let copy_len = cmp::min(remaining_in_page, to_read - bytes_read);

            // Clone fs for the I/O closure
            let fs_for_io = fs.clone();

            // Allocate physical frame for new page
            let alloc_pfn = || -> Option<u64> {
                let frame = buddy_allocator::alloc_physical_pages(1)?;
                Some(frame.start_address().as_u64() / PAGE_SIZE as u64)
            };

            // Read page from cache, or load from disk if not cached
            let page = page_cache::read_page(
                cache_inode_id,
                page_index,
                alloc_pfn,
                |page_entry: &PageCacheEntry| {
                    // This closure populates the page from disk
                    let page_phys = page_entry.physical_address();
                    let page_virt = (page_phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;

                    // Zero the page first (handles sparse files and EOF)
                    unsafe {
                        core::ptr::write_bytes(page_virt, 0, PAGE_SIZE);
                    }

                    // Calculate file offset for this page
                    let page_start_offset = page_entry.index * PAGE_SIZE as u64;
                    let mut filled = 0usize;

                    // Fill the page from disk blocks
                    while filled < PAGE_SIZE {
                        let global_offset = page_start_offset + filled as u64;

                        // Stop at end of file
                        if global_offset >= file_size {
                            break;
                        }

                        // Calculate which file block and offset within block
                        // R97-3 FIX: Use try_from instead of truncating cast
                        let file_block = u32::try_from(global_offset / block_size as u64)
                            .map_err(|_| ())?;
                        let offset_in_block = (global_offset % block_size as u64) as usize;

                        // Read the block from disk
                        let mut block_buf = alloc::vec![0u8; block_size];
                        let phys_block = match fs_for_io.map_file_block(&raw_inode, file_block) {
                            Ok(Some(b)) => Some(b),
                            Ok(None) => None, // Hole in file
                            Err(_) => return Err(()),
                        };

                        if let Some(phys) = phys_block {
                            if fs_for_io.read_block(phys, &mut block_buf).is_err() {
                                return Err(());
                            }
                        }
                        // For holes, block_buf is already zeroed

                        // Calculate how much to copy from this block
                        let bytes_left_in_block = block_size.saturating_sub(offset_in_block);
                        let bytes_left_in_page = PAGE_SIZE - filled;
                        let bytes_left_in_file = (file_size - global_offset) as usize;
                        let chunk = cmp::min(
                            cmp::min(bytes_left_in_block, bytes_left_in_page),
                            bytes_left_in_file,
                        );

                        if chunk == 0 {
                            break;
                        }

                        // Copy data to page
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                block_buf.as_ptr().add(offset_in_block),
                                page_virt.add(filled),
                                chunk,
                            );
                        }

                        filled += chunk;
                    }

                    Ok(())
                },
            )
            .ok_or(FsError::Io)?;

            // Copy data from cached page to user buffer
            let page_virt = (page.physical_address() + PHYSICAL_MEMORY_OFFSET) as *const u8;
            let src =
                unsafe { core::slice::from_raw_parts(page_virt.add(offset_in_page), copy_len) };
            buf[bytes_read..bytes_read + copy_len].copy_from_slice(src);

            // R36-FIX: Balance the page cache refcount so shrink() can reclaim this page.
            // find_get_page increments refcount, we must call put() when done using the page.
            page.put();

            bytes_read += copy_len;
        }

        Ok(bytes_read)
    }

    /// Convert raw mode to FileType
    fn file_type(&self) -> FileType {
        match self.raw.read().mode & EXT2_S_IFMT {
            EXT2_S_IFREG => FileType::Regular,
            EXT2_S_IFDIR => FileType::Directory,
            EXT2_S_IFLNK => FileType::Symlink,
            _ => FileType::Regular, // Default
        }
    }
}

impl Inode for Ext2Inode {
    fn ino(&self) -> u64 {
        self.ino as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let raw = *self.raw.read();
        let size = self.size.load(Ordering::Acquire);

        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino as u64,
            mode: FileMode::new(self.file_type(), raw.mode & 0o7777),
            nlink: raw.links_count as u32,
            uid: raw.uid as u32,
            gid: raw.gid as u32,
            rdev: 0,
            size,
            blksize: self.fs.upgrade().map(|fs| fs.block_size).unwrap_or(4096),
            blocks: raw.blocks_lo as u64,
            atime: TimeSpec::new(raw.atime as i64, 0),
            mtime: TimeSpec::new(raw.mtime as i64, 0),
            ctime: TimeSpec::new(raw.ctime as i64, 0),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        let raw = *self.raw.read();
        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;

        // Directories can only be opened for read-only operations (getdents64)
        if self.is_dir_inner() {
            if flags.is_writable() {
                return Err(FsError::IsDir);
            }
            // Return directory handle with seekable=false
            let inode = fs.wrap_inode(self.ino, raw);
            return Ok(Box::new(FileHandle::new(inode, flags, false)));
        }

        Ok(Box::new(Ext2File {
            inode: fs.wrap_inode(self.ino, raw),
            offset: Mutex::new(0),
        }))
    }

    fn is_dir(&self) -> bool {
        self.is_dir_inner()
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        if !self.is_dir_inner() {
            return Err(FsError::NotDir);
        }

        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        let file_size = self.size.load(Ordering::Acquire);
        let raw = *self.raw.read();
        let mut block_buf = alloc::vec![0u8; fs.block_size as usize];

        let mut current_offset = 0u64;
        let mut entry_index = 0usize;

        while current_offset < file_size {
            let file_block_u64 = current_offset / fs.block_size as u64;
            // R97-3 FIX: Use try_from instead of truncating cast
            let file_block =
                u32::try_from(file_block_u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = current_offset % fs.block_size as u64;

            let phys_block = fs.map_file_block(&raw, file_block)?;
            if let Some(phys) = phys_block {
                fs.read_block(phys, &mut block_buf)?;
            } else {
                block_buf.fill(0);
            }

            let data = &block_buf[offset_in_block as usize..];
            if data.len() < size_of::<Ext2DirEntryHead>() {
                break;
            }

            // R96-8 Fix: Use read_unaligned to avoid UB from unaligned access.
            // Vec<u8> only guarantees 1-byte alignment, but Ext2DirEntryHead
            // contains u32/u16 fields that may require higher alignment.
            let head: Ext2DirEntryHead =
                unsafe { core::ptr::read_unaligned(data.as_ptr() as *const _) };

            if head.rec_len == 0 {
                break;
            }

            // R28-4 Fix: Validate rec_len and name_len against buffer boundaries
            let rec_len = head.rec_len as usize;
            let min_rec = size_of::<Ext2DirEntryHead>();
            if rec_len < min_rec || (offset_in_block as usize) + rec_len > block_buf.len() {
                return Err(FsError::Invalid);
            }

            if head.inode != 0 && head.name_len > 0 {
                // Validate name_len before accessing
                if (head.name_len as usize) > rec_len.saturating_sub(min_rec) {
                    return Err(FsError::Invalid);
                }
                if entry_index == offset {
                    let name_bytes = &data[min_rec..min_rec + head.name_len as usize];
                    let name = String::from_utf8_lossy(name_bytes).into_owned();

                    let file_type = match head.file_type {
                        EXT2_FT_REG_FILE => FileType::Regular,
                        EXT2_FT_DIR => FileType::Directory,
                        EXT2_FT_SYMLINK => FileType::Symlink,
                        EXT2_FT_CHRDEV => FileType::CharDevice,
                        EXT2_FT_BLKDEV => FileType::BlockDevice,
                        _ => FileType::Regular,
                    };

                    return Ok(Some((
                        offset + 1,
                        DirEntry {
                            name,
                            ino: head.inode as u64,
                            file_type,
                        },
                    )));
                }
                entry_index += 1;
            }

            current_offset += head.rec_len as u64;
        }

        Ok(None)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.is_file_inner() {
            return Err(FsError::IsDir);
        }
        self.read_file_at(offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        if !self.is_file_inner() {
            return Err(FsError::IsDir);
        }
        if data.is_empty() {
            return Ok(0);
        }

        let fs = self.fs.upgrade().ok_or(FsError::Invalid)?;
        if fs.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }

        // Serialize writes to this inode
        let _inode_guard = self.write_lock.lock();
        let mut raw = self.raw.write();

        // Check immutable/append-only flags
        if (raw.flags & EXT2_IMMUTABLE_FL) != 0 {
            return Err(FsError::PermDenied);
        }
        if (raw.flags & EXT2_APPEND_FL) != 0 && offset != self.size.load(Ordering::Acquire) {
            // Append-only: writes must be at end of file
            return Err(FsError::PermDenied);
        }
        let block_size = fs.block_size as usize;

        let mut written = 0usize;
        let mut cursor = offset;

        while written < data.len() {
            // R97-3 FIX: Use try_from instead of truncating cast
            let file_block =
                u32::try_from(cursor / fs.block_size as u64).map_err(|_| FsError::Invalid)?;
            let offset_in_block = (cursor % fs.block_size as u64) as usize;
            let space = block_size - offset_in_block;
            let to_copy = cmp::min(space, data.len() - written);

            // Check if we have an existing block or need to allocate
            let existing = fs.map_file_block(&raw, file_block)?;
            let mut block_buf = alloc::vec![0u8; block_size];

            let (phys_block, is_new) = match existing {
                Some(b) => (b, false),
                None => {
                    // Allocate new block
                    let new_block = fs.allocate_block()?;
                    fs.set_file_block(&mut raw, file_block, new_block)?;
                    (new_block, true)
                }
            };

            // Read existing block if partial write, or zero new block
            if !is_new && to_copy != block_size {
                fs.read_block(phys_block, &mut block_buf)?;
            } else if is_new {
                block_buf.fill(0);
            }

            // Copy user data into block buffer
            block_buf[offset_in_block..offset_in_block + to_copy]
                .copy_from_slice(&data[written..written + to_copy]);

            // Write block to disk
            fs.write_block(phys_block, &block_buf)?;

            // Keep page cache coherent if pages are cached
            let inode_id = (self.fs_id << 32) | (self.ino as u64);
            let mut cache_remaining = to_copy;
            let mut cache_cursor = cursor;
            let mut data_pos = written;
            while cache_remaining > 0 {
                let page_index = cache_cursor / PAGE_SIZE as u64;
                let offset_in_page = (cache_cursor % PAGE_SIZE as u64) as usize;
                let page_room = PAGE_SIZE - offset_in_page;
                let chunk = cmp::min(cache_remaining, page_room);

                if let Some(page) = PAGE_CACHE.find_get_page(inode_id, page_index) {
                    let page_phys = page.physical_address();
                    let page_virt = (page_phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data[data_pos..].as_ptr(),
                            page_virt.add(offset_in_page),
                            chunk,
                        );
                    }
                    // Use global PAGE_CACHE method for correct dirty accounting
                    PAGE_CACHE.clear_dirty(&page);
                    page.set_state(PageState::Uptodate);
                    page.put();
                }

                cache_remaining -= chunk;
                cache_cursor += chunk as u64;
                data_pos += chunk;
            }

            written += to_copy;
            cursor += to_copy as u64;
        }

        // Update file size if we extended the file
        let end_offset = offset
            .checked_add(data.len() as u64)
            .ok_or(FsError::Invalid)?;
        let current_size = self.size.load(Ordering::Acquire);
        if end_offset > current_size {
            self.size.store(end_offset, Ordering::Release);
            raw.size_lo = end_offset as u32;
            raw.size_high_or_dir_acl = (end_offset >> 32) as u32;
        }

        // Update timestamps
        let now = TimeSpec::now();
        raw.mtime = now.sec as u32;
        raw.ctime = now.sec as u32;

        // Persist inode to disk
        fs.write_inode_raw(self.ino, &raw)?;

        Ok(written)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Ext2 File Handle
// ============================================================================

/// File handle for ext2 files
struct Ext2File {
    inode: Arc<Ext2Inode>,
    offset: Mutex<u64>,
}

impl FileOps for Ext2File {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(Ext2File {
            inode: self.inode.clone(),
            offset: Mutex::new(*self.offset.lock()),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "Ext2File"
    }

    /// R41-1 FIX: Return actual inode metadata for fstat.
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        let inode_stat = self.inode.stat().map_err(SyscallError::from)?;
        Ok(VfsStat::from(inode_stat))
    }
}
