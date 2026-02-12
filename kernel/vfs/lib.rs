//! Virtual File System (VFS) Layer
//!
//! This module provides a unified interface for different filesystems:
//! - Device filesystem (devfs) for /dev
//! - RAM filesystem (ramfs) for temporary storage
//! - Future: disk-based filesystems
//!
//! # Architecture
//!
//! ```text
//! +-------------------+
//! |   Syscalls        |  sys_open, sys_read, sys_write, sys_stat, etc.
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |   VFS Manager     |  Path resolution, mount table, caching
//! +-------------------+
//!          |
//!    +-----+-----+
//!    |           |
//!    v           v
//! +------+   +-------+
//! | devfs|   | ramfs |   FileSystem trait implementations
//! +------+   +-------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // Initialize VFS (sets up devfs at /dev)
//! vfs::init();
//!
//! // Open a device file
//! let fd = vfs::open("/dev/null", OpenFlags::new(OpenFlags::O_RDWR))?;
//!
//! // Get file status
//! let stat = vfs::stat("/dev/console")?;
//! ```

#![no_std]
extern crate alloc;

#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

pub mod cgroupfs;
pub mod devfs;
pub mod ext2;
pub mod initramfs;
pub mod manager;
pub mod mount_namespace;
pub mod procfs;
pub mod ramfs;
pub mod traits;
pub mod types;

// Re-exports for convenience
pub use cgroupfs::CgroupFs;
pub use devfs::DevFs;
pub use ext2::{Ext2Fs, Ext2Inode};
pub use initramfs::Initramfs;
pub use manager::{init, mount, open, readdir, register_block_device, stat, umount, VFS};
pub use procfs::ProcFs;
pub use ramfs::{RamFs, RamFsInode};
pub use traits::{FileHandle, FileSystem, Inode};
pub use types::{DirEntry, FileMode, FileType, FsError, OpenFlags, SeekWhence, Stat, TimeSpec};

// Mount namespace re-exports
pub use mount_namespace::{
    init as mount_ns_init, clone_namespace, copy_mounts, get_mount, add_mount, remove_mount,
    Mount, MountFlags, MountNamespace, MountNsError, MAX_MNT_NS_LEVEL, ROOT_MNT_NAMESPACE,
};

/// Initialize the VFS subsystem
///
/// This sets up:
/// - The global VFS instance
/// - Device filesystem mounted at /dev
/// - Standard device files (null, zero, console)
pub fn vfs_init() {
    manager::init();
    klog_always!("VFS subsystem initialized");
}
