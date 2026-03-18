//! Process filesystem (procfs)
//!
//! Provides /proc virtual filesystem with process information:
//! - /proc/self - Symlink to current process directory
//! - /proc/[pid]/ - Per-process directory
//! - /proc/[pid]/status - Process status
//! - /proc/[pid]/cmdline - Command line
//! - /proc/[pid]/stat - Process statistics
//! - /proc/meminfo - System memory information
//! - /proc/cpuinfo - CPU information

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileOps;
// R29-1 FIX: Import process module for real process information
use kernel_core::process::{self, ProcessState, PROCESS_TABLE};
// R36 FIX: Import time module for uptime and mm for memory stats
use kernel_core::time;
use mm::memory::FrameAllocator;
use mm::page_cache::PAGE_CACHE;
use spin::RwLock;

/// Global procfs ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(200);

// ============================================================================
// ProcFs
// ============================================================================

/// Process filesystem
pub struct ProcFs {
    fs_id: u64,
    root: Arc<ProcRootInode>,
}

impl ProcFs {
    /// Create a new procfs
    pub fn new() -> Arc<Self> {
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("procfs: NEXT_FS_ID overflow");

        let root = Arc::new(ProcRootInode { fs_id });

        Arc::new(Self { fs_id, root })
    }
}

impl FileSystem for ProcFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "proc"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Check if parent is root
        if parent.ino() == 1 {
            return self.root.lookup_child(name);
        }

        // Check if parent is a PID directory
        if let Some(proc_dir) = parent.as_any().downcast_ref::<ProcPidDirInode>() {
            return proc_dir.lookup_child(name);
        }

        // Traverse /proc/self/<...> by delegating to the current PID directory
        if let Some(self_link) = parent.as_any().downcast_ref::<ProcSelfSymlink>() {
            let alias_dir = ProcPidDirInode {
                fs_id: self.fs_id,
                pid: self_link.target_pid,
            };
            return alias_dir.lookup_child(name);
        }

        // Resolve entries under /proc/[pid]/fd
        if let Some(fd_dir) = parent.as_any().downcast_ref::<ProcPidFdDirInode>() {
            return fd_dir.lookup_child(name);
        }

        Err(FsError::NotFound)
    }
}

// ============================================================================
// Root Directory (/proc)
// ============================================================================

/// /proc root directory inode
struct ProcRootInode {
    fs_id: u64,
}

impl ProcRootInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "self" => {
                // Symlink to current process
                let pid = get_current_pid();
                Ok(Arc::new(ProcSelfSymlink {
                    fs_id: self.fs_id,
                    target_pid: pid,
                }))
            }
            "meminfo" => Ok(Arc::new(ProcMeminfoInode { fs_id: self.fs_id })),
            "cpuinfo" => Ok(Arc::new(ProcCpuinfoInode { fs_id: self.fs_id })),
            "uptime" => Ok(Arc::new(ProcUptimeInode { fs_id: self.fs_id })),
            "version" => Ok(Arc::new(ProcVersionInode { fs_id: self.fs_id })),
            _ => {
                // Try to parse as PID
                if let Ok(ns_pid) = name.parse::<u32>() {
                    // R141-5 FIX: Interpret the parsed PID as namespace-local.
                    // Translate to global PID so internal lookups work correctly.
                    // Without namespace context, treat as global (kernel context).
                    let global_pid = resolve_ns_pid_to_global(ns_pid).unwrap_or(ns_pid);

                    if process_exists(global_pid) {
                        // R134-1 FIX: Enforce PID namespace visibility for direct
                        // /proc/<pid> lookups.  R133-4 only fixed list_pids()
                        // (directory listing); the lookup path was unprotected,
                        // allowing container root to read host process info via
                        // /proc/<global_pid>/maps etc.
                        if !is_pid_visible_in_caller_ns(global_pid) {
                            return Err(FsError::NotFound);
                        }
                        // R31-1 FIX: Check access permission before returning PID directory
                        if !can_access_pid(global_pid) {
                            return Err(FsError::PermDenied);
                        }
                        return Ok(Arc::new(ProcPidDirInode {
                            fs_id: self.fs_id,
                            pid: global_pid,
                        }));
                    }
                }
                Err(FsError::NotFound)
            }
        }
    }
}

impl Inode for ProcRootInode {
    fn ino(&self) -> u64 {
        1
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 1,
            mode: FileMode::directory(0o555),
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
        let inode: Arc<dyn Inode> = Arc::new(ProcRootInode { fs_id: self.fs_id });
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // Static entries
        let static_entries = ["self", "meminfo", "cpuinfo", "uptime", "version"];

        if offset < static_entries.len() {
            let name = static_entries[offset];
            let file_type = if name == "self" {
                FileType::Symlink
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: String::from(name),
                    ino: (offset + 2) as u64,
                    file_type,
                },
            )));
        }

        // R31-1 FIX: List PIDs filtered by access control (self/root/same owner/gid)
        let pids: Vec<u32> = list_pids()
            .into_iter()
            .filter(|&pid| can_access_pid(pid))
            .collect();
        let pid_offset = offset - static_entries.len();

        if pid_offset < pids.len() {
            let global_pid = pids[pid_offset];

            // R141-5 FIX: Display namespace-local PID in directory names.
            // Without this, directory entries show global kernel PIDs that
            // don't match getpid() output in PID namespaces, breaking
            // open("/proc/" + getpid() + "/status") inside containers.
            let display_pid = caller_ns_local_pid(global_pid).unwrap_or(global_pid);

            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: format!("{}", display_pid),
                    // R142-3 FIX: Use namespace-local PID for inode number to
                    // prevent leaking global kernel PIDs via d_ino in getdents64().
                    ino: 1000 + display_pid as u64,
                    file_type: FileType::Directory,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/self Symlink
// ============================================================================

struct ProcSelfSymlink {
    fs_id: u64,
    target_pid: u32,
}

impl ProcSelfSymlink {
    fn pid_dir(&self) -> ProcPidDirInode {
        ProcPidDirInode {
            fs_id: self.fs_id,
            pid: self.target_pid,
        }
    }

    /// R141-5 FIX: Return namespace-local PID for symlink display.
    /// Internal operations still use `self.target_pid` (global).
    fn display_pid(&self) -> u32 {
        caller_ns_local_pid(self.target_pid).unwrap_or(self.target_pid)
    }
}

impl Inode for ProcSelfSymlink {
    fn ino(&self) -> u64 {
        2
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // R141-5 FIX: Use namespace-local PID for symlink target display.
        let target = format!("{}", self.display_pid());
        Ok(Stat {
            dev: self.fs_id,
            ino: 2,
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R141-5 FIX: Return namespace-local PID as symlink target.
        let target = format!("{}", self.display_pid());
        let bytes = target.as_bytes();
        let len = buf.len().min(bytes.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn is_dir(&self) -> bool {
        // Allow traversal through /proc/self/<...> before global symlink support exists
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        if !process_exists(self.target_pid) {
            return Err(FsError::NotFound);
        }
        self.pid_dir().readdir(offset)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/ Directory
// ============================================================================

struct ProcPidDirInode {
    fs_id: u64,
    pid: u32,
}

impl ProcPidDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // R31-1 FIX: Check access permission before returning child entries
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        match name {
            "status" => Ok(Arc::new(ProcPidStatusInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "cmdline" => Ok(Arc::new(ProcPidCmdlineInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "stat" => Ok(Arc::new(ProcPidStatInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "maps" => Ok(Arc::new(ProcPidMapsInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            "fd" => Ok(Arc::new(ProcPidFdDirInode {
                fs_id: self.fs_id,
                pid: self.pid,
            })),
            _ => Err(FsError::NotFound),
        }
    }
}

impl Inode for ProcPidDirInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Use namespace-local PID to prevent leaking global PIDs
        // via fstat()/getdents64() inode numbers on procfs PID directories.
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        1000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::directory(0o555),
            nlink: 2,
            uid,
            gid,
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
        let inode: Arc<dyn Inode> = Arc::new(ProcPidDirInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // R31-1 FIX: Check access permission before listing entries
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let entries = ["status", "cmdline", "stat", "maps", "fd"];

        if offset < entries.len() {
            let name = entries[offset];
            let file_type = if name == "fd" {
                FileType::Directory
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: String::from(name),
                    ino: self.ino() * 10 + offset as u64,
                    file_type,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/status
// ============================================================================

struct ProcPidStatusInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidStatusInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        10000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcPidStatusInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Security: Re-check access on each read to prevent PID reuse attacks
        // If the original process exits and a new process takes its PID,
        // we must not expose the new process's data to the original opener.
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let content = generate_status(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/cmdline
// ============================================================================

struct ProcPidCmdlineInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidCmdlineInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        20000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcPidCmdlineInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Security: Re-check access on each read to prevent PID reuse attacks
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let content = get_process_cmdline(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/stat
// ============================================================================

struct ProcPidStatInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidStatInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        30000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcPidStatInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Security: Re-check access on each read to prevent PID reuse attacks
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let content = generate_stat(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/maps
// ============================================================================

struct ProcPidMapsInode {
    fs_id: u64,
    pid: u32,
}

impl Inode for ProcPidMapsInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        40000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcPidMapsInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // Security: Re-check access on each read to prevent PID reuse attacks
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let content = generate_maps(self.pid);
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/ Directory
// ============================================================================

struct ProcPidFdDirInode {
    fs_id: u64,
    pid: u32,
}

impl ProcPidFdDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // R31-1 FIX: Check access permission before returning fd entries
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let fd: u32 = name.parse().map_err(|_| FsError::NotFound)?;
        let fds = list_process_fds(self.pid);
        if !fds.iter().any(|&n| n == fd) {
            return Err(FsError::NotFound);
        }
        Ok(Arc::new(ProcPidFdSymlink {
            fs_id: self.fs_id,
            pid: self.pid,
            fd,
        }))
    }
}

impl Inode for ProcPidFdDirInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        50000 + display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let (uid, gid) = get_process_owner(self.pid);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::directory(0o500),
            nlink: 2,
            uid,
            gid,
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
        let inode: Arc<dyn Inode> = Arc::new(ProcPidFdDirInode {
            fs_id: self.fs_id,
            pid: self.pid,
        });
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // R31-1 FIX: Defense-in-depth access check for fd listing
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let fds = list_process_fds(self.pid);
        if offset < fds.len() {
            let fd = fds[offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: format!("{}", fd),
                    ino: self.ino() * 1000 + fd as u64,
                    file_type: FileType::Symlink,
                },
            )));
        }
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/<n> Symlink
// ============================================================================

struct ProcPidFdSymlink {
    fs_id: u64,
    pid: u32,
    fd: u32,
}

impl Inode for ProcPidFdSymlink {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        let display_pid = caller_ns_local_pid(self.pid).unwrap_or(self.pid);
        (50000 + display_pid as u64) * 1000 + self.fd as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // R42-1 FIX: Re-check access permission on each stat call to prevent
        // PID-reuse information leaks. If the original process exits and a new
        // process reuses the PID, we must not expose the new process's FD info.
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let (uid, gid) = get_process_owner(self.pid);
        let target = get_fd_target(self.pid, self.fd);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R42-1 FIX: Defense-in-depth access check for each read operation.
        // Handles race conditions where PID is reused between open and read.
        if !can_access_pid(self.pid) {
            return Err(FsError::PermDenied);
        }
        let target = get_fd_target(self.pid, self.fd);
        read_from_content(&target, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/meminfo
// ============================================================================

struct ProcMeminfoInode {
    fs_id: u64,
}

impl Inode for ProcMeminfoInode {
    fn ino(&self) -> u64 {
        3
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 3,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcMeminfoInode { fs_id: self.fs_id });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_meminfo();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/cpuinfo
// ============================================================================

struct ProcCpuinfoInode {
    fs_id: u64,
}

impl Inode for ProcCpuinfoInode {
    fn ino(&self) -> u64 {
        4
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 4,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcCpuinfoInode { fs_id: self.fs_id });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_cpuinfo();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/uptime
// ============================================================================

struct ProcUptimeInode {
    fs_id: u64,
}

impl Inode for ProcUptimeInode {
    fn ino(&self) -> u64 {
        5
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 5,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcUptimeInode { fs_id: self.fs_id });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_uptime();
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// /proc/version
// ============================================================================

struct ProcVersionInode {
    fs_id: u64,
}

impl Inode for ProcVersionInode {
    fn ino(&self) -> u64 {
        6
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 6,
            mode: FileMode::regular(0o444),
            nlink: 1,
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
        // Return FileHandle so fd_read_callback can use inode.read_at()
        let inode: Arc<dyn Inode> = Arc::new(ProcVersionInode { fs_id: self.fs_id });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = "Zero-OS version 0.1.0 (rustc)\n";
        read_from_content(content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn read_from_content(content: &str, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    let bytes = content.as_bytes();
    if offset >= bytes.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let len = buf.len().min(bytes.len() - start);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    Ok(len)
}

/// Get current process ID
///
/// R29-1 FIX: Now returns the actual current PID from the scheduler
fn get_current_pid() -> u32 {
    process::current_pid().unwrap_or(0) as u32
}

/// R134-1 FIX: Check whether `pid` is visible from the caller's PID namespace.
///
/// A process is visible if it belongs to the caller's owning namespace or any
/// descendant namespace.  When the caller has no PID namespace (kernel context),
/// all processes are visible (global view).
///
/// Returns `false` (invisible) when `pid` is outside the caller's namespace
/// subtree, preventing cross-namespace information disclosure via direct
/// `/proc/<global_pid>` lookups.
fn is_pid_visible_in_caller_ns(pid: u32) -> bool {
    let table = PROCESS_TABLE.lock();

    // Determine the caller's owning PID namespace.
    let caller_ns = process::current_pid()
        .and_then(|cur_pid| table.get(cur_pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc_arc| {
            let p = proc_arc.lock();
            kernel_core::owning_namespace(&p.pid_ns_chain)
        });

    // Kernel context (no namespace): global visibility.
    let ns = match caller_ns {
        Some(ns) => ns,
        None => return true,
    };

    // Check target process visibility in the caller's namespace.
    match table.get(pid as usize) {
        Some(Some(proc_arc)) => {
            let p = proc_arc.lock();
            kernel_core::is_visible_in_namespace(&ns, &p.pid_ns_chain)
        }
        _ => false,
    }
}

/// R141-5 FIX: Translate a global PID to the namespace-local PID as seen by
/// the current caller. Returns `None` if the caller has no PID namespace
/// (kernel context) or the target is not visible.
///
/// Codex review: Drop PROCESS_TABLE lock before calling PID namespace methods
/// to avoid holding it across their internal Mutex acquisitions.
fn caller_ns_local_pid(global_pid: u32) -> Option<u32> {
    let caller_ns = {
        let table = PROCESS_TABLE.lock();
        process::current_pid()
            .and_then(|pid| table.get(pid))
            .and_then(|slot| slot.as_ref())
            .and_then(|proc_arc| {
                let p = proc_arc.lock();
                kernel_core::owning_namespace(&p.pid_ns_chain)
            })
    }?; // PROCESS_TABLE lock dropped here

    kernel_core::pid_in_namespace(&caller_ns, global_pid as usize).map(|p| p as u32)
}

/// R141-5 FIX: Resolve a namespace-local PID (as entered by the user) to a
/// global kernel PID. Returns `None` if the caller has no PID namespace
/// (kernel context — use the value as-is).
///
/// Codex review: Drop PROCESS_TABLE lock before namespace translation.
fn resolve_ns_pid_to_global(ns_pid: u32) -> Option<u32> {
    let caller_ns = {
        let table = PROCESS_TABLE.lock();
        process::current_pid()
            .and_then(|pid| table.get(pid))
            .and_then(|slot| slot.as_ref())
            .and_then(|proc_arc| {
                let p = proc_arc.lock();
                kernel_core::owning_namespace(&p.pid_ns_chain)
            })
    }?; // PROCESS_TABLE lock dropped here

    kernel_core::resolve_pid_in_namespace(&caller_ns, ns_pid as usize).map(|p| p as u32)
}

/// R31-1 FIX: Access control for /proc/[pid] entries.
///
/// Allow access if any of the following conditions are met:
/// - Accessing own process (self)
/// - Caller is host root (host euid 0)
/// - Caller has same owner UID as target process (host-mapped)
///
/// R37-6 FIX: Removed same-GID check. Allowing same-GID access is a security
/// vulnerability that lets group members snoop on each other's process info.
/// Linux /proc only allows same-UID or root access for sensitive data.
fn can_access_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let cur_pid = process::current_pid();
    // Self access is always allowed
    if let Some(cp) = cur_pid {
        if cp as u32 == pid {
            return true;
        }
    }
    // R134-1 FIX: Root check must use euid, not uid, matching POSIX semantics.
    // A process with euid==0 (via setuid) should have root-level /proc access.
    // R139-2 FIX: Use host-mapped euid for the root bypass. Namespace root
    // (ns-euid==0) must not get host-wide /proc access — same class as R135-1.
    let cur_host_euid = kernel_core::current_host_euid().unwrap_or(u32::MAX);
    if cur_host_euid == 0 {
        return true;
    }
    // R37-6 FIX: Only same UID can access; same GID is NOT sufficient
    // R140-5 FIX: Use host-mapped UIDs for both caller and target to prevent
    // cross-user-namespace collisions.  Two processes in different user namespaces
    // can have the same numeric UID (e.g., both mapped to 1000) but correspond to
    // completely different host users.
    // Codex review: use Option-based comparison — if either UID is unmapped,
    // deny access rather than risking a false match on OVERFLOW_UID.
    let cur_host_uid = cur_pid.and_then(|cp| get_process_host_uid_opt(cp as u32));
    let target_host_uid = get_process_host_uid_opt(pid);
    match (cur_host_uid, target_host_uid) {
        (Some(cur), Some(target)) => cur == target,
        _ => false, // Unmapped UID on either side → deny
    }
}

/// Check if a process exists
///
/// R29-1 FIX: Now checks the actual process table
fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    let table = PROCESS_TABLE.lock();
    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let state = proc.lock().state;
            !matches!(state, ProcessState::Zombie | ProcessState::Terminated)
        }
        _ => false,
    }
}

/// List all PIDs
///
/// R29-1 FIX: Now returns actual PIDs from the process table
/// R133-4 FIX: Filter by calling process's PID namespace for container isolation.
/// A process only sees PIDs that are visible from its owning PID namespace.
fn list_pids() -> Vec<u32> {
    let table = PROCESS_TABLE.lock();

    // R133-4 FIX: Determine the caller's owning PID namespace.
    let caller_ns = process::current_pid()
        .and_then(|pid| table.get(pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc_arc| {
            let p = proc_arc.lock();
            kernel_core::owning_namespace(&p.pid_ns_chain)
        });

    table
        .iter()
        .enumerate()
        .skip(1) // PID 0 is reserved
        .filter_map(|(pid, slot)| {
            slot.as_ref().and_then(|proc_arc| {
                let p = proc_arc.lock();
                if matches!(p.state, ProcessState::Zombie | ProcessState::Terminated) {
                    return None;
                }

                // R133-4 FIX: Only include PIDs visible in caller's namespace.
                if let Some(ref ns) = caller_ns {
                    if !kernel_core::is_visible_in_namespace(ns, &p.pid_ns_chain) {
                        return None;
                    }
                }

                Some(pid as u32)
            })
        })
        .collect()
}

/// Get process owner (uid, gid)
///
/// R29-1 FIX: Now returns actual process credentials
fn get_process_owner(pid: u32) -> (u32, u32) {
    if pid == 0 {
        return (0, 0);
    }

    let table = PROCESS_TABLE.lock();
    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            // R39-3 FIX: 使用共享凭证读取 uid/gid
            let creds = p.credentials.read();
            (creds.uid, creds.gid)
        }
        _ => (0, 0),
    }
}

/// R140-5 FIX: Map a process's UID through its user namespace to obtain the host UID.
///
/// Returns `None` if the process doesn't exist or the UID has no mapping in the
/// user namespace.  Callers should treat `None` as "deny" rather than collapsing
/// to a sentinel value (Codex review: prevents false match on OVERFLOW_UID).
///
/// Drops PROCESS_TABLE lock before calling into user_ns to avoid lock ordering issues
/// (same pattern as current_host_euid() in process.rs:1918).
fn get_process_host_uid_opt(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    let table = PROCESS_TABLE.lock();
    let (ns_uid, user_ns) = match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            let ns_uid = p.credentials.read().uid;
            let user_ns = p.user_ns.clone();
            (ns_uid, user_ns)
        }
        _ => return None,
    };

    // Drop PROCESS_TABLE lock before mapping to avoid holding it across
    // user_ns operations (follows established lock ordering pattern).
    drop(table);

    user_ns.map_uid_from_ns(ns_uid)
}

/// Get process command line
///
/// R29-1 FIX: Now returns actual process name from PCB
fn get_process_cmdline(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }

    let table = PROCESS_TABLE.lock();
    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            // Return process name with null terminator (Linux format)
            format!("{}\0", p.name)
        }
        _ => String::new(),
    }
}

/// List file descriptors for a process
///
/// R29-1 FIX: Now returns actual FD list from process
fn list_process_fds(pid: u32) -> Vec<u32> {
    if pid == 0 {
        return Vec::new();
    }

    let table = PROCESS_TABLE.lock();
    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            p.fd_table.keys().map(|&fd| fd as u32).collect()
        }
        _ => Vec::new(),
    }
}

/// Resolve a file descriptor target for /proc/[pid]/fd/<n>
///
/// R29-1 FIX: Now returns actual FD type from process
fn get_fd_target(pid: u32, fd: u32) -> String {
    if pid == 0 {
        return String::new();
    }

    let table = PROCESS_TABLE.lock();
    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            match p.fd_table.get(&(fd as i32)) {
                Some(fd_obj) => {
                    // Return type name as the "target"
                    format!("{}", fd_obj.type_name())
                }
                None => String::new(),
            }
        }
        _ => String::new(),
    }
}

/// Generate /proc/[pid]/status content
///
/// R29-1 FIX: Now uses real process data
fn generate_status(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }

    let table = PROCESS_TABLE.lock();

    // R140-7 FIX: Resolve the caller's owning PID namespace so that PIDs
    // emitted in /proc/[pid]/status are namespace-local, not global kernel PIDs.
    let caller_ns = process::current_pid()
        .and_then(|cur_pid| table.get(cur_pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc_arc| {
            let p = proc_arc.lock();
            kernel_core::owning_namespace(&p.pid_ns_chain)
        });

    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            // R98-1 FIX: Check orthogonal stopped flag before scheduler state.
            // Zombie/Terminated take priority, then stopped flag, then scheduler state.
            let (state_char, state_name) = match p.state {
                ProcessState::Zombie => ('Z', "zombie"),
                ProcessState::Terminated => ('X', "dead"),
                ProcessState::Stopped => ('T', "stopped"),
                _ if p.stopped => ('T', "stopped"),
                ProcessState::Ready | ProcessState::Running => ('R', "running"),
                ProcessState::Blocked | ProcessState::Sleeping => ('S', "sleeping"),
            };
            // R39-3 FIX: 使用共享凭证读取 uid/gid/euid/egid
            let creds = p.credentials.read();

            // R140-7 FIX: Emit namespace-local PIDs as seen from the caller's
            // owning PID namespace.  Cross-namespace parents are shown as 0.
            let (ns_tgid, ns_pid, ns_ppid) = if let Some(ref ns) = caller_ns {
                (
                    kernel_core::pid_in_namespace(ns, p.tgid).unwrap_or(0),
                    kernel_core::pid_in_namespace(ns, p.pid).unwrap_or(0),
                    kernel_core::pid_in_namespace(ns, p.ppid).unwrap_or(0),
                )
            } else {
                // Kernel context (no namespace): global view.
                (p.tgid, p.pid, p.ppid)
            };

            format!(
                "Name:\t{}\n\
                 Umask:\t{:04o}\n\
                 State:\t{} ({})\n\
                 Tgid:\t{}\n\
                 Pid:\t{}\n\
                 PPid:\t{}\n\
                 Uid:\t{}\t{}\t{}\t{}\n\
                 Gid:\t{}\t{}\t{}\t{}\n\
                 Threads:\t1\n",
                p.name,
                p.umask,
                state_char,
                state_name,
                ns_tgid,
                ns_pid,
                ns_ppid,
                creds.uid,
                creds.euid,
                creds.uid,
                creds.uid, // real, effective, saved, fs
                creds.gid,
                creds.egid,
                creds.gid,
                creds.gid,
            )
        }
        _ => String::new(),
    }
}

/// Generate /proc/[pid]/stat content
///
/// R29-1 FIX: Now uses real process data
fn generate_stat(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }

    let table = PROCESS_TABLE.lock();

    // R140-7 FIX: Resolve the caller's owning PID namespace for PID translation.
    let caller_ns = process::current_pid()
        .and_then(|cur_pid| table.get(cur_pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc_arc| {
            let p = proc_arc.lock();
            kernel_core::owning_namespace(&p.pid_ns_chain)
        });

    match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            // R98-1 FIX: Check orthogonal stopped flag before scheduler state.
            let state_char = match p.state {
                ProcessState::Zombie => 'Z',
                ProcessState::Terminated => 'X',
                ProcessState::Stopped => 'T',
                _ if p.stopped => 'T',
                ProcessState::Ready | ProcessState::Running => 'R',
                ProcessState::Blocked | ProcessState::Sleeping => 'S',
            };

            // R140-7 FIX: Emit namespace-local PIDs.
            let (ns_pid, ns_ppid) = if let Some(ref ns) = caller_ns {
                (
                    kernel_core::pid_in_namespace(ns, p.pid).unwrap_or(0),
                    kernel_core::pid_in_namespace(ns, p.ppid).unwrap_or(0),
                )
            } else {
                (p.pid, p.ppid)
            };

            // Minimal stat format: pid (comm) state ppid pgrp session tty_nr ...
            format!(
                "{} ({}) {} {} {} {} 0 -1 0 0 0 0 0 0 0 0 {} 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                ns_pid,
                p.name,
                state_char,
                ns_ppid,
                ns_pid, // pgrp = pid for now
                ns_pid, // session = pid for now
                p.priority,
            )
        }
        _ => String::new(),
    }
}

/// R117-2 FIX: Maximum number of mmap entries to emit in /proc/[pid]/maps.
/// Prevents kernel OOM when a process has 100K+ mmap regions.
const MAX_MAPS_ENTRIES: usize = 1000;

/// R117-2 FIX: Maximum byte budget for /proc/[pid]/maps output.
/// 64 KiB is sufficient for ~1000 entries at ~60 bytes each.
const MAX_MAPS_OUTPUT: usize = 64 * 1024;

/// Generate /proc/[pid]/maps content
///
/// Shows the memory mappings for the process in Linux format:
/// address           perms offset  dev   inode   pathname
///
/// R117-2 FIX: Output is bounded by MAX_MAPS_ENTRIES and MAX_MAPS_OUTPUT
/// to prevent kernel OOM from processes with many mmap regions. When the
/// budget is exceeded, a `... (truncated)\n` marker is appended.
fn generate_maps(pid: u32) -> String {
    let table = PROCESS_TABLE.lock();
    if let Some(Some(proc)) = table.get(pid as usize) {
        let proc = proc.lock();
        let mut result = String::new();
        let mut entries = 0usize;
        let mut truncated = false;

        // Output mmap regions
        // R36-FIX: Use 16 hex digits for 64-bit addresses
        for (&start, &size) in &proc.mmap_regions {
            if entries >= MAX_MAPS_ENTRIES || result.len() > MAX_MAPS_OUTPUT {
                truncated = true;
                break;
            }
            // R121-4 FIX: Strip pending-map/unmap flags from the stored length.
            // Page-aligned lengths use bits [12..] so mask off low 12 bits.
            let end = start.saturating_add(size & !0xfff);
            // Format: start-end perms offset dev:inode pathname
            let line = format!(
                "{:016x}-{:016x} rw-p 00000000 00:00 0    [anon]\n",
                start, end
            );
            if result.len().saturating_add(line.len()) > MAX_MAPS_OUTPUT {
                truncated = true;
                break;
            }
            result.push_str(&line);
            entries += 1;
        }

        // Add stack mapping if present (only if budget allows)
        if !truncated {
            if let Some(user_stack) = proc.user_stack {
                if entries < MAX_MAPS_ENTRIES {
                    let stack_top = user_stack.as_u64();
                    let stack_bottom = stack_top.saturating_sub(0x10000); // 64KB stack
                    let line = format!(
                        "{:016x}-{:016x} rw-p 00000000 00:00 0    [stack]\n",
                        stack_bottom, stack_top
                    );
                    if result.len().saturating_add(line.len()) <= MAX_MAPS_OUTPUT {
                        result.push_str(&line);
                    } else {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
        }

        if result.is_empty() && !truncated {
            // Fallback if no mappings
            result.push_str("0000000000400000-0000000000401000 r-xp 00000000 00:00 0    [code]\n");
        }

        if truncated {
            result.push_str("... (truncated)\n");
        }

        result
    } else {
        // Process not found, return empty
        String::new()
    }
}

/// Generate /proc/meminfo content
///
/// Shows real memory statistics from the buddy allocator and page cache.
/// R140-8 FIX: When the calling process is in a non-root cgroup with a
/// configured memory.max, returns cgroup-relative totals instead of
/// host-global physical memory stats.  This prevents namespaced containers
/// from fingerprinting the host or detecting co-residency.
fn generate_meminfo() -> String {
    // R140-8 FIX: Virtualize for cgroup-limited containers.
    if let Some(cgroup_id) = process::current_cgroup_id() {
        if cgroup_id != 0 {
            if let Some(cgroup) = kernel_core::cgroup::lookup_cgroup(cgroup_id) {
                let limits = cgroup.limits();
                if let Some(memory_max) = limits.memory_max {
                    // Treat u64::MAX as "no limit" (Linux cgroup2 "max" semantics).
                    if memory_max != u64::MAX {
                        let snap = cgroup.get_stats();
                        let memory_current = snap.memory_current;

                        let total_kb = (memory_max / 1024) as usize;
                        let used_kb = (memory_current / 1024) as usize;
                        let free_kb = (memory_max.saturating_sub(memory_current) / 1024) as usize;

                        return format!(
                            "MemTotal:       {:8} kB\n\
                             MemFree:        {:8} kB\n\
                             MemAvailable:   {:8} kB\n\
                             Buffers:        {:8} kB\n\
                             Cached:         {:8} kB\n\
                             SwapTotal:      {:8} kB\n\
                             SwapFree:       {:8} kB\n\
                             Active:         {:8} kB\n\
                             Inactive:       {:8} kB\n\
                             Dirty:          {:8} kB\n\
                             KernelHeap:     {:8} kB\n",
                            total_kb,
                            free_kb,
                            free_kb, // MemAvailable ~= MemFree in cgroup view
                            0,       // Buffers: not tracked per-cgroup
                            0,       // Cached: not tracked per-cgroup
                            0,       // SwapTotal
                            0,       // SwapFree
                            used_kb, // Active ~= memory.current
                            0,       // Inactive
                            0,       // Dirty
                            0,       // KernelHeap: host-global, not exposed
                        );
                    }
                }
            }
        }
    }

    // Root cgroup or no memory limit: show host-global stats (original behavior).
    let mem_stats = FrameAllocator::new().stats();
    let cache_stats = PAGE_CACHE.stats();

    // Convert pages to KB (4KB pages)
    let total_kb = mem_stats.total_physical_pages * 4;
    let free_kb = mem_stats.free_physical_pages * 4;
    let used_kb = mem_stats.used_physical_pages * 4;
    let cached_kb = cache_stats.nr_pages as usize * 4;
    let buffers_kb = cache_stats.nr_dirty as usize * 4;
    let available_kb = free_kb + cached_kb;

    format!(
        "MemTotal:       {:8} kB\n\
         MemFree:        {:8} kB\n\
         MemAvailable:   {:8} kB\n\
         Buffers:        {:8} kB\n\
         Cached:         {:8} kB\n\
         SwapTotal:      {:8} kB\n\
         SwapFree:       {:8} kB\n\
         Active:         {:8} kB\n\
         Inactive:       {:8} kB\n\
         Dirty:          {:8} kB\n\
         KernelHeap:     {:8} kB\n",
        total_kb,
        free_kb,
        available_kb,
        buffers_kb,
        cached_kb,
        0,          // SwapTotal - no swap
        0,          // SwapFree - no swap
        used_kb,    // Active = used pages
        cached_kb,  // Inactive = cached pages
        buffers_kb, // Dirty = dirty pages in cache
        mem_stats.heap_used_bytes / 1024,
    )
}

/// Generate /proc/cpuinfo content
fn generate_cpuinfo() -> String {
    String::from(
        "processor\t: 0\n\
         vendor_id\t: Zero-OS\n\
         cpu family\t: 6\n\
         model\t\t: 0\n\
         model name\t: Zero-OS Virtual CPU\n\
         stepping\t: 0\n\
         cpu MHz\t\t: 1000.000\n\
         cache size\t: 0 KB\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8\n\
         bogomips\t: 2000.00\n\n",
    )
}

/// Generate /proc/uptime content
///
/// Shows system uptime in seconds (timer tick count / 1000 assuming 1kHz timer).
/// Format: uptime_seconds idle_seconds
fn generate_uptime() -> String {
    let ticks = time::get_ticks();
    // Assuming timer runs at 1000 Hz (1 tick = 1 ms)
    let uptime_secs = ticks / 1000;
    let uptime_frac = (ticks % 1000) / 10; // Two decimal places

    // Idle time is approximated as a portion of uptime (simplified)
    // In a real system, this would track actual CPU idle time
    let idle_secs = uptime_secs / 2; // Rough approximation
    let idle_frac = uptime_frac;

    format!(
        "{}.{:02} {}.{:02}\n",
        uptime_secs, uptime_frac, idle_secs, idle_frac
    )
}
