//! VFS trait definitions
//!
//! Core traits for filesystem and inode operations.

use crate::types::{DirEntry, FileMode, FsError, OpenFlags, Stat};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use kernel_core::{FileOps, SyscallError, VfsStat};

/// Filesystem trait
///
/// Each mounted filesystem implements this trait. The VFS uses these methods
/// for path resolution and metadata operations.
pub trait FileSystem: Send + Sync {
    /// Get unique filesystem ID
    fn fs_id(&self) -> u64;

    /// Get filesystem type name (e.g., "devfs", "ramfs")
    fn fs_type(&self) -> &'static str;

    /// Get root inode
    fn root_inode(&self) -> Arc<dyn Inode>;

    /// Look up a child entry by name
    ///
    /// # Arguments
    /// * `parent` - Parent inode (must be a directory)
    /// * `name` - Child entry name
    ///
    /// # Returns
    /// The child inode or FsError::NotFound
    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError>;

    /// Create a new file or directory
    ///
    /// # Arguments
    /// * `parent` - Parent directory inode
    /// * `name` - New entry name
    /// * `mode` - File mode (type + permissions)
    ///
    /// # Returns
    /// The new inode or error
    fn create(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let _ = (parent, name, mode);
        Err(FsError::NotSupported)
    }

    /// Remove a file or empty directory
    fn unlink(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<(), FsError> {
        let _ = (parent, name);
        Err(FsError::NotSupported)
    }

    /// Rename an entry
    fn rename(
        &self,
        old_parent: &Arc<dyn Inode>,
        old_name: &str,
        new_parent: &Arc<dyn Inode>,
        new_name: &str,
    ) -> Result<(), FsError> {
        let _ = (old_parent, old_name, new_parent, new_name);
        Err(FsError::NotSupported)
    }

    /// Sync filesystem to storage (flush caches)
    fn sync(&self) -> Result<(), FsError> {
        Ok(())
    }
}

/// Inode trait
///
/// Represents an in-memory inode. Each filesystem creates its own inode type
/// implementing this trait.
pub trait Inode: Send + Sync {
    /// Get inode number (unique within filesystem)
    fn ino(&self) -> u64;

    /// Get filesystem ID this inode belongs to
    fn fs_id(&self) -> u64;

    /// Get file metadata
    fn stat(&self) -> Result<Stat, FsError>;

    /// Open the inode, returning a file operations handle
    ///
    /// # Arguments
    /// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    ///
    /// # Returns
    /// A FileOps implementation for read/write operations
    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError>;

    /// Check if this inode is a directory
    fn is_dir(&self) -> bool {
        self.stat().map(|s| s.mode.is_dir()).unwrap_or(false)
    }

    /// Check if this inode is a regular file
    fn is_file(&self) -> bool {
        self.stat().map(|s| s.mode.is_file()).unwrap_or(false)
    }

    /// Read directory entries
    ///
    /// # Arguments
    /// * `offset` - Entry offset (0 for first entry)
    ///
    /// # Returns
    /// (next_offset, entry) or None if no more entries
    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let _ = offset;
        Err(FsError::NotDir)
    }

    /// Read data at given offset
    ///
    /// Default implementation returns NotSupported. Regular files should override.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let _ = (offset, buf);
        Err(FsError::NotSupported)
    }

    /// Write data at given offset
    ///
    /// Default implementation returns NotSupported. Regular files should override.
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let _ = (offset, data);
        Err(FsError::NotSupported)
    }

    /// Truncate file to given length
    fn truncate(&self, len: u64) -> Result<(), FsError> {
        let _ = len;
        Err(FsError::NotSupported)
    }

    /// Get as Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// File handle wrapper that implements FileOps
///
/// This wraps an inode with open state (offset, flags) and provides
/// the standard file operations.
pub struct FileHandle {
    /// The underlying inode
    pub inode: Arc<dyn Inode>,
    /// Current file offset (shared via Arc for clone to share offset)
    pub offset: Arc<spin::Mutex<u64>>,
    /// Open flags
    pub flags: OpenFlags,
    /// Whether this handle supports seeking
    pub seekable: bool,
}

/// R41-3 FIX: Implement Clone for FileHandle to allow dropping process lock before I/O.
///
/// Cloning a FileHandle shares the same offset via Arc, ensuring that
/// reads/writes from a clone update the original handle's position.
/// This enables fd_read/fd_write to release the process lock before performing
/// potentially blocking I/O operations while maintaining correct file position.
impl Clone for FileHandle {
    fn clone(&self) -> Self {
        Self {
            inode: Arc::clone(&self.inode),
            offset: Arc::clone(&self.offset),
            flags: self.flags,
            seekable: self.seekable,
        }
    }
}

impl FileHandle {
    /// Create a new file handle
    pub fn new(inode: Arc<dyn Inode>, flags: OpenFlags, seekable: bool) -> Self {
        Self {
            inode,
            offset: Arc::new(spin::Mutex::new(0)),
            flags,
            seekable,
        }
    }

    /// Read from current offset
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.flags.is_readable() {
            return Err(FsError::BadFd);
        }

        let mut offset = self.offset.lock();
        let n = self.inode.read_at(*offset, buf)?;
        *offset += n as u64;
        Ok(n)
    }

    /// Write to current offset (or end if append mode)
    pub fn write(&self, data: &[u8]) -> Result<usize, FsError> {
        if !self.flags.is_writable() {
            return Err(FsError::BadFd);
        }

        let mut offset = self.offset.lock();

        // Handle append mode
        if self.flags.is_append() {
            let stat = self.inode.stat()?;
            *offset = stat.size;
        }

        let n = self.inode.write_at(*offset, data)?;
        *offset += n as u64;
        Ok(n)
    }

    /// Seek to new offset
    pub fn seek(&self, off: i64, whence: crate::types::SeekWhence) -> Result<u64, FsError> {
        if !self.seekable {
            return Err(FsError::Seek);
        }

        let mut offset = self.offset.lock();
        let new_offset = match whence {
            crate::types::SeekWhence::Set => {
                if off < 0 {
                    return Err(FsError::Invalid);
                }
                off as u64
            }
            crate::types::SeekWhence::Cur => {
                let cur = *offset as i64;
                let new = cur.checked_add(off).ok_or(FsError::Invalid)?;
                if new < 0 {
                    return Err(FsError::Invalid);
                }
                new as u64
            }
            crate::types::SeekWhence::End => {
                let stat = self.inode.stat()?;
                let size = stat.size as i64;
                let new = size.checked_add(off).ok_or(FsError::Invalid)?;
                if new < 0 {
                    return Err(FsError::Invalid);
                }
                new as u64
            }
        };

        *offset = new_offset;
        Ok(new_offset)
    }

    /// Get current offset
    pub fn current_offset(&self) -> u64 {
        *self.offset.lock()
    }

    /// Get file stat
    pub fn stat(&self) -> Result<Stat, FsError> {
        self.inode.stat()
    }
}

impl FileOps for FileHandle {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(FileHandle {
            inode: Arc::clone(&self.inode),
            offset: Arc::clone(&self.offset),
            flags: self.flags,
            seekable: self.seekable,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "FileHandle"
    }

    /// R41-1 FIX: Return actual inode metadata for fstat.
    /// R154-1 FIX: MAC gate for fd-backed stat — prevents metadata probe
    /// via inherited/pre-policy fds that bypass path-based R153-2 check.
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        let inode_stat = self.inode.stat().map_err(SyscallError::from)?;
        let vfs_stat = VfsStat::from(inode_stat);
        if let Some(task) = lsm::ProcessCtx::from_current() {
            lsm::hook_file_permission(&task, vfs_stat.ino, 0).map_err(|_| SyscallError::EACCES)?;
        }
        Ok(vfs_stat)
    }
}
