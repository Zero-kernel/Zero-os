//! Device filesystem (devfs)
//!
//! Provides /dev virtual filesystem with device files:
//! - /dev/null - Discards all writes, returns EOF on read
//! - /dev/zero - Returns infinite zeros on read, discards writes
//! - /dev/console - Kernel console (serial output)
//! - /dev/vdX - Block devices (virtio-blk, etc.)

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use block::BlockDevice;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileOps;
use spin::{Mutex, RwLock};

/// Global device filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(1);

/// Device filesystem
pub struct DevFs {
    fs_id: u64,
    root: Arc<DevDirInode>,
}

impl DevFs {
    /// Create a new device filesystem with standard devices
    pub fn new() -> Arc<Self> {
        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        let mut devices: BTreeMap<String, Arc<dyn Inode>> = BTreeMap::new();

        // Create device inodes with self-references initialized
        // This enables open() to return FileHandle wrapping the inode
        let null_inode = Arc::new(NullDevInode::new(fs_id));
        *null_inode.self_ref.write() = Arc::downgrade(&null_inode);
        devices.insert("null".into(), null_inode);

        let zero_inode = Arc::new(ZeroDevInode::new(fs_id));
        *zero_inode.self_ref.write() = Arc::downgrade(&zero_inode);
        devices.insert("zero".into(), zero_inode);

        let console_inode = Arc::new(ConsoleDevInode::new(fs_id));
        *console_inode.self_ref.write() = Arc::downgrade(&console_inode);
        devices.insert("console".into(), console_inode);

        let root = Arc::new(DevDirInode {
            fs_id,
            ino: 1,
            entries: RwLock::new(devices),
            self_ref: RwLock::new(Weak::new()),
        });
        // Set self-reference after Arc creation
        *root.self_ref.write() = Arc::downgrade(&root);

        Arc::new(Self { fs_id, root })
    }

    /// Register a block device in devfs.
    ///
    /// Creates a device node at /dev/{name} for the given block device.
    pub fn register_block_device(
        &self,
        name: &str,
        device: Arc<dyn BlockDevice>,
    ) -> Result<(), FsError> {
        let mut entries = self.root.entries.write();

        if entries.contains_key(name) {
            return Err(FsError::Exists);
        }

        // Assign a unique inode number
        static NEXT_BLOCK_INO: AtomicU64 = AtomicU64::new(100);
        let ino = NEXT_BLOCK_INO.fetch_add(1, Ordering::SeqCst);

        // Create block device inode with self-reference initialized
        // This enables open() to return FileHandle wrapping the inode
        let inode = Arc::new(BlockDevInode::new(self.fs_id, ino, device));
        *inode.self_ref.write() = Arc::downgrade(&inode);
        entries.insert(String::from(name), inode);

        Ok(())
    }

    /// Unregister a block device from devfs.
    pub fn unregister_block_device(&self, name: &str) -> Result<(), FsError> {
        let mut entries = self.root.entries.write();
        entries.remove(name).ok_or(FsError::NotFound)?;
        Ok(())
    }
}

impl FileSystem for DevFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "devfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        Arc::clone(&self.root) as Arc<dyn Inode>
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Only root directory lookup supported
        if parent.ino() != 1 {
            return Err(FsError::NotDir);
        }

        let entries = self.root.entries.read();
        entries.get(name).cloned().ok_or(FsError::NotFound)
    }
}

/// Device directory inode (/dev)
struct DevDirInode {
    fs_id: u64,
    ino: u64,
    entries: RwLock<BTreeMap<String, Arc<dyn Inode>>>,
    /// Self-reference for creating Arc in open()
    self_ref: RwLock<Weak<Self>>,
}

impl DevDirInode {
    /// Get Arc<Self> from self_ref
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref.read().upgrade().ok_or(FsError::Invalid)
    }
}

impl Inode for DevDirInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::directory(0o755),
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        // Return directory handle with seekable=false
        let inode = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let entries = self.entries.read();
        let mut iter = entries.iter();

        // Skip to offset
        for _ in 0..offset {
            if iter.next().is_none() {
                return Ok(None);
            }
        }

        // Return next entry
        if let Some((name, inode)) = iter.next() {
            let stat = inode.stat()?;
            Ok(Some((
                offset + 1,
                DirEntry {
                    name: name.clone(),
                    ino: inode.ino(),
                    file_type: stat.mode.file_type,
                },
            )))
        } else {
            Ok(None)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /dev/null implementation
// ============================================================================

/// /dev/null inode
struct NullDevInode {
    fs_id: u64,
    ino: u64,
    /// Self-reference for creating Arc in open()
    self_ref: RwLock<Weak<Self>>,
}

impl NullDevInode {
    fn new(fs_id: u64) -> Self {
        Self {
            fs_id,
            ino: 2,
            self_ref: RwLock::new(Weak::new()),
        }
    }

    /// Get Arc<Self> from self_ref for FileHandle creation
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref.read().upgrade().ok_or(FsError::Invalid)
    }
}

impl Inode for NullDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 3), // major 1, minor 3 = /dev/null
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Return FileHandle wrapping this inode so fd_read/fd_write work correctly
        let inode: Arc<dyn Inode> = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/null always returns EOF
        Ok(0)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/null discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /dev/zero implementation
// ============================================================================

/// /dev/zero inode
struct ZeroDevInode {
    fs_id: u64,
    ino: u64,
    /// Self-reference for creating Arc in open()
    self_ref: RwLock<Weak<Self>>,
}

impl ZeroDevInode {
    fn new(fs_id: u64) -> Self {
        Self {
            fs_id,
            ino: 3,
            self_ref: RwLock::new(Weak::new()),
        }
    }

    /// Get Arc<Self> from self_ref for FileHandle creation
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref.read().upgrade().ok_or(FsError::Invalid)
    }
}

impl Inode for ZeroDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o666),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(1, 5), // major 1, minor 5 = /dev/zero
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Return FileHandle wrapping this inode so fd_read/fd_write work correctly
        let inode: Arc<dyn Inode> = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // /dev/zero returns infinite zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // /dev/zero discards all data
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /dev/console implementation
// ============================================================================

/// /dev/console inode
struct ConsoleDevInode {
    fs_id: u64,
    ino: u64,
    /// Self-reference for creating Arc in open()
    self_ref: RwLock<Weak<Self>>,
}

impl ConsoleDevInode {
    fn new(fs_id: u64) -> Self {
        Self {
            fs_id,
            ino: 4,
            self_ref: RwLock::new(Weak::new()),
        }
    }

    /// Get Arc<Self> from self_ref for FileHandle creation
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref.read().upgrade().ok_or(FsError::Invalid)
    }
}

impl Inode for ConsoleDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::char_device(0o620),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: make_dev(5, 1), // major 5, minor 1 = /dev/console
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Return FileHandle wrapping this inode so fd_read/fd_write work correctly
        let inode: Arc<dyn Inode> = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Console read: read from keyboard input buffer (non-blocking)
        Ok(drivers::keyboard_read(buf))
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Write to console via print
        if let Ok(s) = core::str::from_utf8(data) {
            print!("{}", s);
        } else {
            // Write raw bytes
            for &b in data {
                print!("{}", b as char);
            }
        }
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create device number from major and minor
#[inline]
fn make_dev(major: u32, minor: u32) -> u32 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & 0xFFF00) << 12)
}

// ============================================================================
// Block device implementation
// ============================================================================

/// Block device inode (/dev/vdX, /dev/sdX, etc.)
struct BlockDevInode {
    fs_id: u64,
    ino: u64,
    device: Arc<dyn BlockDevice>,
    /// Lock for serializing read-modify-write operations
    rw_lock: Arc<Mutex<()>>,
    /// Self-reference for creating Arc in open()
    self_ref: RwLock<Weak<Self>>,
}

impl BlockDevInode {
    fn new(fs_id: u64, ino: u64, device: Arc<dyn BlockDevice>) -> Self {
        Self {
            fs_id,
            ino,
            device,
            rw_lock: Arc::new(Mutex::new(())),
            self_ref: RwLock::new(Weak::new()),
        }
    }

    /// Get Arc<Self> from self_ref for FileHandle creation
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref.read().upgrade().ok_or(FsError::Invalid)
    }
}

impl Inode for BlockDevInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let capacity = self.device.capacity_sectors() * self.device.sector_size() as u64;
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::block_device(0o660),
            nlink: 1,
            uid: 0,
            gid: 6,                                     // disk group
            rdev: make_dev(8, (self.ino - 100) as u32), // major 8 = sd, minor = device index
            size: capacity,
            blksize: self.device.sector_size(),
            blocks: self.device.capacity_sectors(),
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Return FileHandle wrapping this inode so fd_read/fd_write work correctly
        // Block devices are seekable
        let inode: Arc<dyn Inode> = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let sector_size = self.device.sector_size() as u64;
        let capacity_bytes = self.device.capacity_sectors() * sector_size;

        // Check bounds and empty buffer
        if offset >= capacity_bytes || buf.is_empty() {
            return Ok(0); // EOF
        }

        let mut file_offset = offset;
        let mut buf_pos = 0usize;
        let mut sector_buf = alloc::vec![0u8; sector_size as usize];
        let limit = (capacity_bytes - offset) as usize;
        let to_read = buf.len().min(limit);

        while buf_pos < to_read && file_offset < capacity_bytes {
            let sector_idx = file_offset / sector_size;
            let sector_off = (file_offset % sector_size) as usize;
            let bytes_until_eof = (capacity_bytes - file_offset) as usize;
            let available = (sector_size as usize - sector_off)
                .min(to_read - buf_pos)
                .min(bytes_until_eof);

            // If sector-aligned and have at least one whole sector, batch the read
            if sector_off == 0
                && available == sector_size as usize
                && (to_read - buf_pos) >= sector_size as usize
            {
                let max_full = (to_read - buf_pos).min(bytes_until_eof);
                let full_len = max_full - (max_full % sector_size as usize);
                if full_len > 0 {
                    let aligned_buf = &mut buf[buf_pos..buf_pos + full_len];
                    self.device
                        .read_sync(sector_idx, aligned_buf)
                        .map_err(|_| FsError::Io)?;
                    buf_pos += full_len;
                    file_offset += full_len as u64;
                    continue;
                }
            }

            // Handle partial sector read
            self.device
                .read_sync(sector_idx, &mut sector_buf)
                .map_err(|_| FsError::Io)?;
            buf[buf_pos..buf_pos + available]
                .copy_from_slice(&sector_buf[sector_off..sector_off + available]);

            buf_pos += available;
            file_offset += available as u64;
        }

        Ok(buf_pos)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let sector_size = self.device.sector_size() as u64;
        let capacity_bytes = self.device.capacity_sectors() * sector_size;

        // Check bounds
        if offset >= capacity_bytes {
            return Err(FsError::NoSpace);
        }

        let max_write = (capacity_bytes - offset) as usize;
        let to_write = data.len().min(max_write);
        if to_write == 0 {
            return Ok(0);
        }

        // Serialize RMW operations to prevent data corruption
        let _guard = self.rw_lock.lock();
        let mut file_offset = offset;
        let mut data_pos = 0usize;
        let mut sector_buf = alloc::vec![0u8; sector_size as usize];

        while data_pos < to_write && file_offset < capacity_bytes {
            let sector_idx = file_offset / sector_size;
            let sector_off = (file_offset % sector_size) as usize;
            let bytes_until_eof = (capacity_bytes - file_offset) as usize;
            let available = (sector_size as usize - sector_off)
                .min(to_write - data_pos)
                .min(bytes_until_eof);

            // If sector-aligned and have at least one whole sector, batch the write
            if sector_off == 0
                && available == sector_size as usize
                && (to_write - data_pos) >= sector_size as usize
            {
                let max_full = (to_write - data_pos).min(bytes_until_eof);
                let full_len = max_full - (max_full % sector_size as usize);
                if full_len > 0 {
                    let aligned_data = &data[data_pos..data_pos + full_len];
                    self.device
                        .write_sync(sector_idx, aligned_data)
                        .map_err(|_| FsError::Io)?;
                    data_pos += full_len;
                    file_offset += full_len as u64;
                    continue;
                }
            }

            // Handle partial sector with read-modify-write
            self.device
                .read_sync(sector_idx, &mut sector_buf)
                .map_err(|_| FsError::Io)?;

            sector_buf[sector_off..sector_off + available]
                .copy_from_slice(&data[data_pos..data_pos + available]);

            self.device
                .write_sync(sector_idx, &sector_buf)
                .map_err(|_| FsError::Io)?;

            data_pos += available;
            file_offset += available as u64;
        }

        Ok(data_pos)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
