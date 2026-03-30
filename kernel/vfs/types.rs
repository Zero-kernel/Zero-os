//! VFS type definitions
//!
//! Core types for the Virtual File System layer including:
//! - File types and modes
//! - Stat structure for file metadata
//! - VFS error types
//! - Open flags

use alloc::string::String;
use alloc::sync::Arc;
use kernel_core::{SyscallError, VfsStat};

/// File type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    /// Regular file
    Regular = 0,
    /// Directory
    Directory = 1,
    /// Character device (e.g., /dev/null, /dev/console)
    CharDevice = 2,
    /// Block device (e.g., /dev/sda)
    BlockDevice = 3,
    /// Symbolic link
    Symlink = 4,
    /// Named pipe (FIFO)
    Fifo = 5,
    /// Unix domain socket
    Socket = 6,
}

impl FileType {
    /// Convert to mode bits (upper 4 bits of st_mode)
    pub fn to_mode_bits(self) -> u32 {
        match self {
            FileType::Regular => 0o100000,
            FileType::Directory => 0o040000,
            FileType::CharDevice => 0o020000,
            FileType::BlockDevice => 0o060000,
            FileType::Symlink => 0o120000,
            FileType::Fifo => 0o010000,
            FileType::Socket => 0o140000,
        }
    }
}

/// File mode (type + permissions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode {
    /// File type
    pub file_type: FileType,
    /// Permission bits (lower 12 bits: rwxrwxrwx + setuid/setgid/sticky)
    pub perm: u16,
}

impl FileMode {
    /// Create a new file mode
    pub const fn new(file_type: FileType, perm: u16) -> Self {
        Self {
            file_type,
            perm: perm & 0o7777,
        }
    }

    /// Create mode for regular file with given permissions
    pub const fn regular(perm: u16) -> Self {
        Self::new(FileType::Regular, perm)
    }

    /// Create mode for directory with given permissions
    pub const fn directory(perm: u16) -> Self {
        Self::new(FileType::Directory, perm)
    }

    /// Create mode for character device with given permissions
    pub const fn char_device(perm: u16) -> Self {
        Self::new(FileType::CharDevice, perm)
    }

    /// Create mode for block device with given permissions
    pub const fn block_device(perm: u16) -> Self {
        Self::new(FileType::BlockDevice, perm)
    }

    /// Convert to raw st_mode value
    pub fn to_raw(&self) -> u32 {
        self.file_type.to_mode_bits() | (self.perm as u32)
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// Check if this is a character device
    pub fn is_char_device(&self) -> bool {
        self.file_type == FileType::CharDevice
    }
}

/// Timestamp for file metadata
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeSpec {
    /// Seconds since epoch
    pub sec: i64,
    /// Nanoseconds (0-999999999)
    pub nsec: i64,
}

impl TimeSpec {
    /// Create a new timestamp
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }

    /// Create timestamp from milliseconds
    pub fn from_ms(ms: u64) -> Self {
        Self {
            sec: (ms / 1000) as i64,
            nsec: ((ms % 1000) * 1_000_000) as i64,
        }
    }

    /// Get current time from kernel timer
    pub fn now() -> Self {
        let ms = kernel_core::current_timestamp_ms();
        Self::from_ms(ms)
    }
}

/// File status structure (similar to POSIX struct stat)
#[derive(Debug, Clone)]
pub struct Stat {
    /// Device ID containing file
    pub dev: u64,
    /// Inode number
    pub ino: u64,
    /// File mode (type + permissions)
    pub mode: FileMode,
    /// Number of hard links
    pub nlink: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Device ID (for special files)
    pub rdev: u32,
    /// File size in bytes
    pub size: u64,
    /// Block size for filesystem I/O
    pub blksize: u32,
    /// Number of 512-byte blocks allocated
    pub blocks: u64,
    /// Last access time
    pub atime: TimeSpec,
    /// Last modification time
    pub mtime: TimeSpec,
    /// Last status change time
    pub ctime: TimeSpec,
}

impl Default for Stat {
    fn default() -> Self {
        let now = TimeSpec::now();
        Self {
            dev: 0,
            ino: 0,
            mode: FileMode::regular(0o644),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

/// VFS error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Entry not found
    NotFound,
    /// Not a directory
    NotDir,
    /// Is a directory (when file expected)
    IsDir,
    /// Entry already exists
    Exists,
    /// Operation not supported
    NotSupported,
    /// I/O error
    Io,
    /// Invalid argument
    Invalid,
    /// Out of memory
    NoMem,
    /// Broken pipe
    Pipe,
    /// Bad file descriptor
    BadFd,
    /// Permission denied
    PermDenied,
    /// Read-only filesystem
    ReadOnly,
    /// No space left on device
    NoSpace,
    /// Name too long
    NameTooLong,
    /// Not empty (for directory removal)
    NotEmpty,
    /// Device or resource busy (EBUSY)
    Busy,
    /// Cross-device link
    CrossDev,
    /// Too many symbolic links or symlink traversal disallowed
    SymlinkLoop,
    /// Illegal seek (e.g., on pipe)
    Seek,
}

impl FsError {
    /// Convert to syscall error number (negative errno)
    pub fn to_errno(self) -> i64 {
        match self {
            FsError::NotFound => -2,      // ENOENT
            FsError::NotDir => -20,       // ENOTDIR
            FsError::IsDir => -21,        // EISDIR
            FsError::Exists => -17,       // EEXIST
            FsError::NotSupported => -38, // ENOSYS
            FsError::Io => -5,            // EIO
            FsError::Invalid => -22,      // EINVAL
            FsError::NoMem => -12,        // ENOMEM
            FsError::Pipe => -32,         // EPIPE
            FsError::BadFd => -9,         // EBADF
            FsError::PermDenied => -13,   // EACCES
            FsError::ReadOnly => -30,     // EROFS
            FsError::NoSpace => -28,      // ENOSPC
            FsError::NameTooLong => -36,  // ENAMETOOLONG
            FsError::NotEmpty => -39,     // ENOTEMPTY
            FsError::Busy => -16,         // EBUSY
            FsError::CrossDev => -18,     // EXDEV
            FsError::SymlinkLoop => -40,  // ELOOP
            FsError::Seek => -29,         // ESPIPE
        }
    }
}

// ============================================================================
// R41-1 FIX: Type conversions for fstat support
// ============================================================================

/// Convert VFS Stat to kernel_core VfsStat for syscall interface.
impl From<Stat> for VfsStat {
    fn from(stat: Stat) -> Self {
        VfsStat {
            dev: stat.dev,
            ino: stat.ino,
            mode: stat.mode.to_raw(),
            nlink: stat.nlink,
            uid: stat.uid,
            gid: stat.gid,
            rdev: stat.rdev,
            size: stat.size,
            blksize: stat.blksize,
            blocks: stat.blocks,
            atime_sec: stat.atime.sec,
            atime_nsec: stat.atime.nsec,
            mtime_sec: stat.mtime.sec,
            mtime_nsec: stat.mtime.nsec,
            ctime_sec: stat.ctime.sec,
            ctime_nsec: stat.ctime.nsec,
        }
    }
}

/// Convert FsError to SyscallError for unified error handling.
impl From<FsError> for SyscallError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::NotFound => SyscallError::ENOENT,
            FsError::PermDenied => SyscallError::EACCES,
            FsError::Exists => SyscallError::EEXIST,
            FsError::NotDir => SyscallError::ENOTDIR,
            FsError::IsDir => SyscallError::EISDIR,
            FsError::NotEmpty => SyscallError::EBUSY,
            FsError::Busy => SyscallError::EBUSY,
            FsError::ReadOnly => SyscallError::EACCES,
            FsError::NoSpace | FsError::NoMem => SyscallError::ENOMEM,
            FsError::Io => SyscallError::EIO,
            FsError::Invalid | FsError::NameTooLong | FsError::Seek => SyscallError::EINVAL,
            FsError::CrossDev => SyscallError::EXDEV,
            FsError::SymlinkLoop => SyscallError::ELOOP,
            FsError::NotSupported => SyscallError::ENOSYS,
            FsError::BadFd => SyscallError::EBADF,
            FsError::Pipe => SyscallError::EPIPE,
        }
    }
}

/// File open flags
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open for reading only
    pub const O_RDONLY: u32 = 0;
    /// Open for writing only
    pub const O_WRONLY: u32 = 1;
    /// Open for reading and writing
    pub const O_RDWR: u32 = 2;
    /// Access mode mask
    pub const O_ACCMODE: u32 = 3;
    /// Create file if it doesn't exist
    pub const O_CREAT: u32 = 0o100;
    /// Fail if file exists (with O_CREAT)
    pub const O_EXCL: u32 = 0o200;
    /// Truncate file to zero length
    pub const O_TRUNC: u32 = 0o1000;
    /// Append mode
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking mode
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Open directory
    pub const O_DIRECTORY: u32 = 0o200000;
    /// Do not follow the final symlink in path
    pub const O_NOFOLLOW: u32 = 0o400000;
    /// Path-only open (no read/write operations allowed)
    pub const O_PATH: u32 = 0o10000000;

    /// Create new flags
    pub const fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Check if readable
    pub fn is_readable(&self) -> bool {
        // R130-6 FIX: O_PATH fds are path-only references — no read/write
        // operations allowed (only fstat, close, dup per POSIX).
        if self.is_path() {
            return false;
        }
        let mode = self.0 & Self::O_ACCMODE;
        mode == Self::O_RDONLY || mode == Self::O_RDWR
    }

    /// Check if writable
    pub fn is_writable(&self) -> bool {
        // R130-6 FIX: O_PATH fds are path-only references — no write allowed.
        if self.is_path() {
            return false;
        }
        let mode = self.0 & Self::O_ACCMODE;
        mode == Self::O_WRONLY || mode == Self::O_RDWR
    }

    /// Check if create flag set
    pub fn is_create(&self) -> bool {
        (self.0 & Self::O_CREAT) != 0
    }

    /// Check if truncate flag set
    pub fn is_truncate(&self) -> bool {
        (self.0 & Self::O_TRUNC) != 0
    }

    /// Check if append flag set
    pub fn is_append(&self) -> bool {
        (self.0 & Self::O_APPEND) != 0
    }

    /// Check if non-blocking flag set
    pub fn is_nonblock(&self) -> bool {
        (self.0 & Self::O_NONBLOCK) != 0
    }

    /// Check if exclusive creation is requested (O_EXCL)
    pub fn is_exclusive(&self) -> bool {
        (self.0 & Self::O_EXCL) != 0
    }

    /// Check if final symlink should not be followed (O_NOFOLLOW)
    pub fn is_nofollow(&self) -> bool {
        (self.0 & Self::O_NOFOLLOW) != 0
    }

    /// Check if this is a path-only open (O_PATH)
    pub fn is_path(&self) -> bool {
        (self.0 & Self::O_PATH) != 0
    }

    /// Check if directory is required (O_DIRECTORY)
    pub fn is_directory(&self) -> bool {
        (self.0 & Self::O_DIRECTORY) != 0
    }
}

// ============================================================================
// Path Resolution Flags (openat2-compatible)
// ============================================================================

/// Path resolution flags for openat2-style operations
///
/// These flags control how symbolic links and mount boundaries
/// are handled during path resolution. Compatible with Linux openat2(2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolveFlags(pub u64);

impl ResolveFlags {
    /// Disallow crossing mount points during resolution
    pub const RESOLVE_NO_XDEV: u64 = 0x01;
    /// Reject /proc-style "magic" symlinks (e.g., /proc/self/fd/N)
    pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    /// Reject all symbolic links (fail with ELOOP if any symlink encountered)
    pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    /// Reject paths that escape the starting directory (go above via ..)
    pub const RESOLVE_BENEATH: u64 = 0x08;
    /// Treat the starting directory as the filesystem root
    pub const RESOLVE_IN_ROOT: u64 = 0x10;
    /// Treat trailing symlinks as final (don't follow even without O_NOFOLLOW)
    pub const RESOLVE_CACHED: u64 = 0x20;

    /// Empty flag set (default behavior)
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create from raw bits
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check if no symlinks allowed
    pub const fn no_symlinks(&self) -> bool {
        (self.0 & Self::RESOLVE_NO_SYMLINKS) != 0
    }

    /// Check if no mount crossing allowed
    pub const fn no_xdev(&self) -> bool {
        (self.0 & Self::RESOLVE_NO_XDEV) != 0
    }

    /// Check if magic links blocked
    pub const fn no_magiclinks(&self) -> bool {
        (self.0 & Self::RESOLVE_NO_MAGICLINKS) != 0
    }

    /// Check if path must stay beneath starting point
    pub const fn beneath(&self) -> bool {
        (self.0 & Self::RESOLVE_BENEATH) != 0
    }

    /// Check if starting directory is treated as root
    pub const fn in_root(&self) -> bool {
        (self.0 & Self::RESOLVE_IN_ROOT) != 0
    }

    /// Check if any resolve flags are set
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

/// Seek origin for lseek
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SeekWhence {
    /// Seek from beginning of file
    Set = 0,
    /// Seek from current position
    Cur = 1,
    /// Seek from end of file
    End = 2,
}

impl SeekWhence {
    /// Convert from raw value
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(SeekWhence::Set),
            1 => Some(SeekWhence::Cur),
            2 => Some(SeekWhence::End),
            _ => None,
        }
    }
}

/// Directory entry for readdir
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// Inode number
    pub ino: u64,
    /// File type
    pub file_type: FileType,
}
