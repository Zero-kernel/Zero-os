//! Cgroup v2 Filesystem (cgroupfs)
//!
//! Provides /sys/fs/cgroup virtual filesystem for cgroup management:
//! - Directory hierarchy mirrors cgroup tree
//! - mkdir/rmdir create/delete cgroups
//! - Control files for limits and statistics
//!
//! # Control Files
//!
//! - `cgroup.procs` - List/migrate task PIDs
//! - `cgroup.controllers` - Available controllers (read-only)
//! - `cgroup.subtree_control` - Controllers enabled for children
//! - `cpu.weight` - CPU scheduling weight (1-10000)
//! - `cpu.max` - CPU quota (quota period)
//! - `memory.max` - Memory hard limit
//! - `memory.high` - Memory soft limit
//! - `memory.current` - Current memory usage (read-only)
//! - `pids.max` - Maximum PIDs
//! - `pids.current` - Current PID count (read-only)
//! - `io.max` - I/O bandwidth/IOPS limits
//! - `io.stat` - I/O statistics (read-only)

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::cgroup::{
    self, CgroupControllers, CgroupError, CgroupId, CgroupLimits, CgroupNode,
};
use kernel_core::{process, FileOps};

/// Global cgroupfs ID counter (starts at 300 to avoid collision with other FS types)
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(300);

/// R154-2 FIX: Deterministic inode computation replaces unstable NEXT_INO counter.
/// Inode = (cgroup_id + 1) * STRIDE + file_offset.
/// J2-SHARED-CORE: STRIDE widened 16 → 64 (1 dir + up to 63 control files). The
/// previous 16 left only 3 spare slots; the J.2 items 7-10 add per-cgroup control
/// files (files.max/current, ports.max/current, vfs_dir.max/current, …) which
/// would push ctrl_index+1 ≥ 16 and ALIAS (cgroup_id+2)*16 = the next cgroup's dir
/// inode. The arithmetic below is stride-parametric, so widening before any file is
/// appended preserves R154-2 determinism and keeps inodes for files at the same
/// CtrlKind index stable.
/// file_offset: 0 = directory, 1..=63 = control files (CtrlKind::all() index + 1).
const CGROUPFS_INO_STRIDE: u64 = 64;

/// Compute deterministic inode for a cgroup directory.
fn cgroup_dir_ino(cgroup_id: CgroupId) -> u64 {
    (cgroup_id + 1) * CGROUPFS_INO_STRIDE
}

/// Compute deterministic inode for a cgroup control file.
/// `ctrl_index` is the 0-based index into CtrlKind::all().
fn cgroup_ctrl_ino(cgroup_id: CgroupId, ctrl_index: usize) -> u64 {
    (cgroup_id + 1) * CGROUPFS_INO_STRIDE + (ctrl_index as u64) + 1
}

// ============================================================================
// Control File Types
// ============================================================================

/// Types of control files in cgroupfs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtrlKind {
    /// cgroup.procs - List/migrate tasks
    Procs,
    /// cgroup.controllers - Available controllers (read-only)
    Controllers,
    /// cgroup.subtree_control - Controllers for children
    SubtreeControl,
    /// cpu.weight - CPU scheduling weight
    CpuWeight,
    /// cpu.max - CPU quota
    CpuMax,
    /// memory.max - Memory hard limit
    MemoryMax,
    /// memory.high - Memory soft limit
    MemoryHigh,
    /// memory.current - Current memory usage (read-only)
    MemoryCurrent,
    /// pids.max - Maximum PIDs
    PidsMax,
    /// pids.current - Current PID count (read-only)
    PidsCurrent,
    /// io.max - I/O bandwidth/IOPS limits
    IoMax,
    /// io.stat - I/O statistics (read-only)
    IoStat,
    // J.2 items 7/8/10: per-cgroup FD / ephemeral-port / VFS-dir control files.
    // APPENDED here AND in all() — the order is load-bearing: index() drives the
    // R154-2 deterministic inode, so a control file's inode stays stable only if
    // new kinds are added at the END. (kmem — item 9 — is intentionally NOT
    // exposed: its counter is not yet wired, see the StatsBuf note in syscall.rs.)
    /// J2-7: files.max - Maximum open file descriptors (FILES controller)
    FilesMax,
    /// J2-7: files.current - Current open FD count (read-only)
    FilesCurrent,
    /// J2-8: ports.max - Maximum ephemeral ports (NET controller)
    PortsMax,
    /// J2-8: ports.current - Current ephemeral-port count (read-only)
    PortsCurrent,
    /// J2-10: vfs_dir.max - Maximum per-tenant VFS dir-enumeration bytes (MEMORY controller)
    VfsDirMax,
    /// J2-10: vfs_dir.current - Current in-flight dir-enumeration bytes (read-only)
    VfsDirCurrent,
}

impl CtrlKind {
    /// Get the filename for this control file
    fn filename(&self) -> &'static str {
        match self {
            CtrlKind::Procs => "cgroup.procs",
            CtrlKind::Controllers => "cgroup.controllers",
            CtrlKind::SubtreeControl => "cgroup.subtree_control",
            CtrlKind::CpuWeight => "cpu.weight",
            CtrlKind::CpuMax => "cpu.max",
            CtrlKind::MemoryMax => "memory.max",
            CtrlKind::MemoryHigh => "memory.high",
            CtrlKind::MemoryCurrent => "memory.current",
            CtrlKind::PidsMax => "pids.max",
            CtrlKind::PidsCurrent => "pids.current",
            CtrlKind::IoMax => "io.max",
            CtrlKind::IoStat => "io.stat",
            CtrlKind::FilesMax => "files.max",
            CtrlKind::FilesCurrent => "files.current",
            CtrlKind::PortsMax => "ports.max",
            CtrlKind::PortsCurrent => "ports.current",
            CtrlKind::VfsDirMax => "vfs_dir.max",
            CtrlKind::VfsDirCurrent => "vfs_dir.current",
        }
    }

    /// Check if this control file is read-only
    fn is_readonly(&self) -> bool {
        matches!(
            self,
            CtrlKind::Controllers
                | CtrlKind::MemoryCurrent
                | CtrlKind::PidsCurrent
                | CtrlKind::IoStat
                | CtrlKind::FilesCurrent
                | CtrlKind::PortsCurrent
                | CtrlKind::VfsDirCurrent
        )
    }

    /// Check if this control requires a specific controller to be enabled
    fn required_controller(&self) -> Option<CgroupControllers> {
        match self {
            CtrlKind::CpuWeight | CtrlKind::CpuMax => Some(CgroupControllers::CPU),
            CtrlKind::MemoryMax | CtrlKind::MemoryHigh | CtrlKind::MemoryCurrent => {
                Some(CgroupControllers::MEMORY)
            }
            CtrlKind::PidsMax | CtrlKind::PidsCurrent => Some(CgroupControllers::PIDS),
            CtrlKind::IoMax | CtrlKind::IoStat => Some(CgroupControllers::IO),
            CtrlKind::FilesMax | CtrlKind::FilesCurrent => Some(CgroupControllers::FILES),
            CtrlKind::PortsMax | CtrlKind::PortsCurrent => Some(CgroupControllers::NET),
            CtrlKind::VfsDirMax | CtrlKind::VfsDirCurrent => Some(CgroupControllers::MEMORY),
            _ => None,
        }
    }

    /// Get all control file types
    fn all() -> &'static [CtrlKind] {
        &[
            CtrlKind::Procs,
            CtrlKind::Controllers,
            CtrlKind::SubtreeControl,
            CtrlKind::CpuWeight,
            CtrlKind::CpuMax,
            CtrlKind::MemoryMax,
            CtrlKind::MemoryHigh,
            CtrlKind::MemoryCurrent,
            CtrlKind::PidsMax,
            CtrlKind::PidsCurrent,
            CtrlKind::IoMax,
            CtrlKind::IoStat,
            // J.2 — appended last (inode stability, see CtrlKind doc).
            CtrlKind::FilesMax,
            CtrlKind::FilesCurrent,
            CtrlKind::PortsMax,
            CtrlKind::PortsCurrent,
            CtrlKind::VfsDirMax,
            CtrlKind::VfsDirCurrent,
        ]
    }

    /// R154-2 FIX: Get 0-based index of this control kind in all().
    fn index(&self) -> usize {
        CtrlKind::all().iter().position(|k| k == self).unwrap_or(0)
    }

    /// Parse filename to control kind
    fn from_filename(name: &str) -> Option<CtrlKind> {
        match name {
            "cgroup.procs" => Some(CtrlKind::Procs),
            "cgroup.controllers" => Some(CtrlKind::Controllers),
            "cgroup.subtree_control" => Some(CtrlKind::SubtreeControl),
            "cpu.weight" => Some(CtrlKind::CpuWeight),
            "cpu.max" => Some(CtrlKind::CpuMax),
            "memory.max" => Some(CtrlKind::MemoryMax),
            "memory.high" => Some(CtrlKind::MemoryHigh),
            "memory.current" => Some(CtrlKind::MemoryCurrent),
            "pids.max" => Some(CtrlKind::PidsMax),
            "pids.current" => Some(CtrlKind::PidsCurrent),
            "io.max" => Some(CtrlKind::IoMax),
            "io.stat" => Some(CtrlKind::IoStat),
            "files.max" => Some(CtrlKind::FilesMax),
            "files.current" => Some(CtrlKind::FilesCurrent),
            "ports.max" => Some(CtrlKind::PortsMax),
            "ports.current" => Some(CtrlKind::PortsCurrent),
            "vfs_dir.max" => Some(CtrlKind::VfsDirMax),
            "vfs_dir.current" => Some(CtrlKind::VfsDirCurrent),
            _ => None,
        }
    }
}

// ============================================================================
// CgroupFs
// ============================================================================

/// Cgroup v2 filesystem
pub struct CgroupFs {
    fs_id: u64,
    root: Arc<CgroupDirInode>,
}

impl CgroupFs {
    /// Create a new cgroupfs mounted at root cgroup
    pub fn new() -> Arc<Self> {
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("cgroupfs: NEXT_FS_ID overflow");

        // Root directory maps to root cgroup (id=0)
        // R154-2 FIX: Deterministic inode computation
        let root = Arc::new(CgroupDirInode {
            fs_id,
            ino: cgroup_dir_ino(0),
            cgroup_id: 0,
            name: String::new(),
        });

        Arc::new(Self { fs_id, root })
    }
}

impl FileSystem for CgroupFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "cgroup2"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Downcast to CgroupDirInode
        let dir = parent
            .as_any()
            .downcast_ref::<CgroupDirInode>()
            .ok_or(FsError::NotDir)?;

        dir.lookup_child(self.fs_id, name)
    }

    fn create(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        // Only directories (cgroups) can be created
        if !mode.is_dir() {
            return Err(FsError::NotSupported);
        }

        let dir = parent
            .as_any()
            .downcast_ref::<CgroupDirInode>()
            .ok_or(FsError::NotDir)?;

        // P1-3: Require root or delegated subtree owner on parent cgroup
        if !is_privileged_or_delegate(dir.cgroup_id) {
            return Err(FsError::PermDenied);
        }

        // Get parent cgroup to inherit controllers
        let parent_cgroup = cgroup::lookup_cgroup(dir.cgroup_id).ok_or(FsError::NotFound)?;
        let controllers = parent_cgroup.controllers();

        // Create child cgroup
        match cgroup::create_cgroup(dir.cgroup_id, controllers) {
            Ok(child) => {
                // R154-2 FIX: Deterministic inode from cgroup_id
                let ino = cgroup_dir_ino(child.id());
                Ok(Arc::new(CgroupDirInode {
                    fs_id: self.fs_id,
                    ino,
                    cgroup_id: child.id(),
                    name: String::from(name),
                }))
            }
            Err(CgroupError::DepthLimit) => Err(FsError::NoSpace),
            Err(CgroupError::CgroupLimit) => Err(FsError::NoSpace),
            Err(CgroupError::ControllerDisabled) => Err(FsError::Invalid),
            Err(_) => Err(FsError::Invalid),
        }
    }

    fn unlink(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<(), FsError> {
        let dir = parent
            .as_any()
            .downcast_ref::<CgroupDirInode>()
            .ok_or(FsError::NotDir)?;

        // P1-3: Require root or delegated subtree owner on parent cgroup
        if !is_privileged_or_delegate(dir.cgroup_id) {
            return Err(FsError::PermDenied);
        }

        // Find child cgroup by name
        let parent_cgroup = cgroup::lookup_cgroup(dir.cgroup_id).ok_or(FsError::NotFound)?;

        // CF-2 FIX: Find child cgroup by matching name against the pseudo-name (ID string)
        let child_id = parent_cgroup
            .children()
            .into_iter()
            .find(|child_id| {
                format!("{}", child_id) == name && cgroup::lookup_cgroup(*child_id).is_some()
            })
            .ok_or(FsError::NotFound)?;

        // Delete the cgroup
        match cgroup::delete_cgroup(child_id) {
            Ok(()) => Ok(()),
            Err(CgroupError::NotEmpty) => Err(FsError::NotEmpty),
            Err(CgroupError::NotFound) => Err(FsError::NotFound),
            Err(CgroupError::PermissionDenied) => Err(FsError::PermDenied),
            Err(_) => Err(FsError::Invalid),
        }
    }
}

// ============================================================================
// CgroupDirInode
// ============================================================================

/// Directory inode representing a cgroup
struct CgroupDirInode {
    fs_id: u64,
    ino: u64,
    cgroup_id: CgroupId,
    name: String,
}

impl CgroupDirInode {
    /// Look up a child by name (control file or child cgroup directory)
    fn lookup_child(&self, fs_id: u64, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // First, check if it's a control file
        if let Some(kind) = CtrlKind::from_filename(name) {
            // Check if the required controller is enabled
            if let Some(required) = kind.required_controller() {
                let cgroup = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
                if !cgroup.controllers().contains(required) {
                    return Err(FsError::NotFound);
                }
            }

            // R154-2 FIX: Deterministic inode from cgroup_id + control index
            let ino = cgroup_ctrl_ino(self.cgroup_id, kind.index());
            return Ok(Arc::new(CgroupCtrlInode {
                fs_id,
                ino,
                cgroup_id: self.cgroup_id,
                kind,
            }));
        }

        // Otherwise, look for a child cgroup directory
        // In a full implementation, we'd maintain a name->id mapping
        // For now, we check if the name matches any child cgroup ID
        let parent = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
        for child_id in parent.children() {
            // Simple matching: name could be the cgroup name or ID
            let id_str = format!("{}", child_id);
            if name == id_str {
                // R154-2 FIX: Deterministic inode from child cgroup_id
                let ino = cgroup_dir_ino(child_id);
                return Ok(Arc::new(CgroupDirInode {
                    fs_id,
                    ino,
                    cgroup_id: child_id,
                    name: String::from(name),
                }));
            }
        }

        Err(FsError::NotFound)
    }

    /// Get control files available for this cgroup
    fn available_ctrl_files(&self) -> Vec<CtrlKind> {
        let cgroup = match cgroup::lookup_cgroup(self.cgroup_id) {
            Some(cg) => cg,
            None => return Vec::new(),
        };
        let controllers = cgroup.controllers();

        CtrlKind::all()
            .iter()
            .filter(|kind| {
                match kind.required_controller() {
                    Some(req) => controllers.contains(req),
                    None => true, // Always available (cgroup.procs, etc.)
                }
            })
            .copied()
            .collect()
    }
}

impl Inode for CgroupDirInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // P1-3: Reflect delegated owner in DAC metadata so non-root
        // delegated managers pass VFS permission checks.
        let owner = effective_owner(self.cgroup_id);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: FileMode::directory(0o755),
            nlink: 2,
            uid: owner,
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
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        let inode: Arc<dyn Inode> = Arc::new(CgroupDirInode {
            fs_id: self.fs_id,
            ino: self.ino,
            cgroup_id: self.cgroup_id,
            name: self.name.clone(),
        });
        Ok(Box::new(FileHandle::new(inode, flags, false)))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let ctrl_files = self.available_ctrl_files();
        let ctrl_count = ctrl_files.len();

        // First, list control files
        if offset < ctrl_count {
            let kind = ctrl_files[offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: String::from(kind.filename()),
                    // R154-2 FIX: Deterministic inode
                    ino: cgroup_ctrl_ino(self.cgroup_id, kind.index()),
                    file_type: FileType::Regular,
                },
            )));
        }

        // Then, list child cgroup directories
        let parent = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
        let children = parent.children();
        let child_offset = offset - ctrl_count;

        if child_offset < children.len() {
            let child_id = children[child_offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    name: format!("{}", child_id),
                    // R154-2 FIX: Deterministic inode
                    ino: cgroup_dir_ino(child_id),
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
// CgroupCtrlInode
// ============================================================================

/// Control file inode for cgroup settings
struct CgroupCtrlInode {
    fs_id: u64,
    ino: u64,
    cgroup_id: CgroupId,
    kind: CtrlKind,
}

impl CgroupCtrlInode {
    /// Read control file content
    fn read_content(&self) -> Result<String, FsError> {
        let cgroup = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
        let limits = cgroup.limits();
        let stats = cgroup.get_stats();

        Ok(match self.kind {
            CtrlKind::Procs => {
                // List attached task PIDs
                let mut pids = String::new();
                // Note: We don't have direct access to process list here
                // In a full implementation, we'd query the cgroup's processes
                // For now, return empty or stats.pids_current as placeholder
                format!("# {} tasks attached\n", stats.pids_current)
            }
            CtrlKind::Controllers => controllers_string(cgroup.controllers()),
            // Same as controllers for now (no separate subtree_control field).
            CtrlKind::SubtreeControl => controllers_string(cgroup.controllers()),
            CtrlKind::CpuWeight => {
                let weight = limits.cpu_weight.unwrap_or(100);
                format!("{}\n", weight)
            }
            CtrlKind::CpuMax => {
                // CF-5 FIX: Display "max" instead of u64::MAX for unlimited quota
                match limits.cpu_max {
                    Some((quota, period)) => {
                        let quota_display = if quota == u64::MAX {
                            String::from("max")
                        } else {
                            quota.to_string()
                        };
                        format!("{} {}\n", quota_display, period)
                    }
                    None => String::from("max 100000\n"),
                }
            }
            CtrlKind::MemoryMax => {
                // CF-5 FIX: Display "max" instead of u64::MAX for unlimited
                match limits.memory_max {
                    Some(max) if max == u64::MAX => String::from("max\n"),
                    Some(max) => format!("{}\n", max),
                    None => String::from("max\n"),
                }
            }
            CtrlKind::MemoryHigh => {
                // CF-5 FIX: Display "max" instead of u64::MAX for unlimited
                match limits.memory_high {
                    Some(high) if high == u64::MAX => String::from("max\n"),
                    Some(high) => format!("{}\n", high),
                    None => String::from("max\n"),
                }
            }
            CtrlKind::MemoryCurrent => {
                format!("{}\n", stats.memory_current)
            }
            CtrlKind::PidsMax => {
                // CF-5 FIX: Display "max" instead of u64::MAX for unlimited
                match limits.pids_max {
                    Some(max) if max == u64::MAX => String::from("max\n"),
                    Some(max) => format!("{}\n", max),
                    None => String::from("max\n"),
                }
            }
            CtrlKind::PidsCurrent => {
                format!("{}\n", stats.pids_current)
            }
            CtrlKind::IoMax => {
                let mut parts = Vec::new();
                if let Some(bps) = limits.io_max_bytes_per_sec {
                    parts.push(format!("rbps={} wbps={}", bps, bps));
                }
                if let Some(iops) = limits.io_max_iops_per_sec {
                    parts.push(format!("riops={} wiops={}", iops, iops));
                }
                if parts.is_empty() {
                    String::from("default\n")
                } else {
                    parts.join(" ") + "\n"
                }
            }
            CtrlKind::IoStat => {
                format!(
                    "rbytes={} wbytes={} rios={} wios={} throttle_events={}\n",
                    stats.io_read_bytes,
                    stats.io_write_bytes,
                    stats.io_read_ios,
                    stats.io_write_ios,
                    stats.io_throttle_events
                )
            }
            // J2-7: files.max — unlimited (None or u64::MAX) prints "max".
            CtrlKind::FilesMax => match limits.fds_max {
                Some(max) if max == u64::MAX => String::from("max\n"),
                Some(max) => format!("{}\n", max),
                None => String::from("max\n"),
            },
            CtrlKind::FilesCurrent => format!("{}\n", stats.fds_current),
            // J2-8: ports.max — unlimited (None or u64::MAX) prints "max".
            CtrlKind::PortsMax => match limits.ports_max {
                Some(max) if max == u64::MAX => String::from("max\n"),
                Some(max) => format!("{}\n", max),
                None => String::from("max\n"),
            },
            CtrlKind::PortsCurrent => format!("{}\n", stats.ports_current),
            // J2-10: vfs_dir.max — unlimited (None or u64::MAX) prints "max".
            CtrlKind::VfsDirMax => match limits.vfs_dir_max {
                Some(max) if max == u64::MAX => String::from("max\n"),
                Some(max) => format!("{}\n", max),
                None => String::from("max\n"),
            },
            CtrlKind::VfsDirCurrent => format!("{}\n", stats.vfs_dir_current),
        })
    }

    /// Write control file content
    fn write_content(&self, data: &str) -> Result<(), FsError> {
        if self.kind.is_readonly() {
            return Err(FsError::PermDenied);
        }

        // P1-3: Determine caller identity and delegation status.
        // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
        // R134-2 FIX: Use host-mapped euid for delegation identity matching.
        // Namespace-relative euid can collide across user namespaces.
        let euid = kernel_core::current_host_euid().ok_or(FsError::PermDenied)?;
        let is_root = kernel_core::current_is_host_root();
        let cgroup = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
        let is_delegate = !is_root && cgroup.is_delegated_to(euid);

        if !is_root && !is_delegate {
            return Err(FsError::PermDenied);
        }

        let data = data.trim();

        match self.kind {
            CtrlKind::Procs => {
                // CF-1 FIX: Parse PID and properly migrate task between cgroups
                let pid_num: u64 = data.parse().map_err(|_| FsError::Invalid)?;
                let pid = usize::try_from(pid_num).map_err(|_| FsError::Invalid)?;

                // Resolve current cgroup from the task struct
                let proc = process::get_process(pid).ok_or(FsError::NotFound)?;
                let old_cgroup_id = { proc.lock().cgroup_id };

                // P1-3: Delegated managers can only move tasks within their subtree.
                if is_delegate {
                    let old_cg = cgroup::lookup_cgroup(old_cgroup_id).ok_or(FsError::NotFound)?;
                    if !old_cg.is_delegated_to(euid) {
                        return Err(FsError::PermDenied);
                    }
                }

                // R148-5 FIX: Block migration for tasks with CLONE_VM shared
                // address spaces. Migrating one sibling transfers ALL memory
                // charges but leaves other siblings in the source cgroup with
                // physical memory still mapped, enabling memory.max bypass.
                // Note: must NOT hold proc.lock() when calling
                // address_space_share_count (it acquires PROCESS_TABLE lock).
                let memory_space = proc.lock().memory_space;
                if memory_space != 0 && process::address_space_share_count(memory_space) > 1 {
                    return Err(FsError::Busy);
                }

                // R171 M2-1 SLICE-1 FIX + migrate_task lock-discipline
                // (cgroup.rs:1909 "hold the target Process lock across migrate_task"):
                // hold the Process lock across the ENTIRE migration window
                // (re-verify + exec gate + migrate_task + charge transfer + cgroup_id
                // update), mirroring sys_cgroup_attach (R155-5). The prior code called
                // migrate_task BEFORE taking proc_guard, which (a) violated
                // migrate_task's documented contract and (b) let a cgroup re-home
                // interleave an exec's lock-dropped load_elf charge window (the SLICE-1
                // bug). Hold the snapshot+update under one lock as before; just acquire
                // it one step earlier so the membership move is covered too.
                let mut proc_guard = proc.lock();
                // Re-verify memory_space under the held lock — exec/clone could have
                // changed it between the share-count check (lock-free) and here.
                if proc_guard.memory_space != memory_space {
                    return Err(FsError::Busy);
                }
                // SLICE-1: refuse to re-home a task mid-`sys_exec`. Its load_elf
                // charge (to the exec-time snapshot cgroup, Process lock dropped) must
                // not race this membership move. Bounded exec window → retry.
                // NOTE: this surfaces as EBUSY (FsError has no EAGAIN variant), where
                // the sibling `sys_cgroup_attach` syscall path returns EAGAIN for the
                // same condition — both are transient "retry" signals; the differing
                // errno is a pre-existing cgroupfs-vs-syscall vocabulary split, not a
                // semantic difference.
                if proc_guard.exec_in_progress {
                    return Err(FsError::Busy);
                }

                // Migrate task from old cgroup to this cgroup (atomic detach+attach),
                // now UNDER the held Process lock.
                cgroup::migrate_task(pid_num, old_cgroup_id, self.cgroup_id).map_err(
                    |e| match e {
                        CgroupError::PidsLimitExceeded => FsError::NoSpace,
                        CgroupError::TaskNotAttached => FsError::Invalid,
                        CgroupError::NotFound => FsError::NotFound,
                        _ => FsError::Invalid,
                    },
                )?;

                // R143-1 FIX: Transfer cgroup memory charges from source to
                // destination cgroup. Without this, exit-time uncharge targets
                // the wrong cgroup (destination instead of source), causing
                // permanent memory_current leak in the source and undercount
                // in the destination. The snapshot + transfer + cgroup_id update
                // stay under the SAME `proc_guard` acquired above.
                let total_charged_bytes = process::compute_cgroup_charged_bytes(&proc_guard);

                // J2-7: combined cgroup migration with a HOLE-FREE rollback (same
                // protocol as the sys_cgroup_attach path). Charge the FD count to
                // the DESTINATION first, then migrate memory (charge-dest-first),
                // then complete the FD move by uncharging the SOURCE. Every reverse
                // is a saturating uncharge (never fails) or the best-effort
                // migrate_task reverse — no fallible reverse-charge can strand a
                // charge in the destination.
                let fd_count = proc_guard.fds_charged_count;
                if let Err(_e) = cgroup::try_charge_fds(self.cgroup_id, fd_count) {
                    let _ = cgroup::migrate_task(pid_num, self.cgroup_id, old_cgroup_id);
                    drop(proc_guard);
                    return Err(FsError::NoSpace);
                }
                if let Err(e) = cgroup::migrate_memory_charges(
                    total_charged_bytes,
                    old_cgroup_id,
                    self.cgroup_id,
                ) {
                    // R157-2 FIX: Keep Process lock held during rollback.
                    // Memory dest-charge failed → source memory untouched (R148-1);
                    // undo the FD dest-charge (never fails) and revert the task.
                    cgroup::uncharge_fds(self.cgroup_id, fd_count);
                    let _ = cgroup::migrate_task(pid_num, self.cgroup_id, old_cgroup_id);
                    drop(proc_guard);
                    return Err(match e {
                        CgroupError::MemoryLimitExceeded => FsError::NoSpace,
                        CgroupError::NotFound => FsError::NotFound,
                        _ => FsError::Invalid,
                    });
                }
                // Complete the FD migration: uncharge the source (never fails).
                cgroup::uncharge_fds(old_cgroup_id, fd_count);

                // R170-3 FIX: this `cgroup.procs` write is the THIRD live
                // `cgroup_id` re-point (alongside sys_cgroup_attach and exit);
                // land any contention-deferred CPU-quota debt on the OLD
                // cgroup BEFORE re-pointing (take under the held proc_guard,
                // then flush). Without this, the next tick's tag-mismatch
                // branch would silently discard the source cgroup's deferred
                // charge — a narrowed re-opening of the R170-3 evasion.
                let quota_debt = (proc_guard.cpu_quota_debt_cgid, proc_guard.cpu_quota_debt_ns);
                proc_guard.cpu_quota_debt_ns = 0;
                cgroup::flush_cpu_quota_debt(
                    quota_debt.0,
                    quota_debt.1,
                    kernel_core::current_timestamp_ms().saturating_mul(1_000_000),
                );

                // Update process's cgroup_id in PCB to keep state synchronized.
                // Still under process lock — no window for concurrent memory ops
                // to charge against the wrong cgroup.
                proc_guard.cgroup_id = self.cgroup_id;
                Ok(())
            }
            CtrlKind::SubtreeControl => {
                // Parse +controller -controller format
                // This would modify subtree_control field
                // For now, return success (no-op since we don't have subtree_control field)
                Ok(())
            }
            // P1-3 NOTE: All limit-setting branches below use `apply_limit`,
            // which enforces delegation boundary checks when `is_delegate`.
            CtrlKind::CpuWeight => {
                let weight: u32 = data.parse().map_err(|_| FsError::Invalid)?;
                let limits = CgroupLimits {
                    cpu_weight: Some(weight),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            CtrlKind::CpuMax => {
                // Parse "quota period" or "max period"
                let parts: Vec<&str> = data.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(FsError::Invalid);
                }
                let quota = if parts[0] == "max" {
                    u64::MAX
                } else {
                    parts[0].parse().map_err(|_| FsError::Invalid)?
                };
                let period: u64 = parts[1].parse().map_err(|_| FsError::Invalid)?;
                let limits = CgroupLimits {
                    cpu_max: Some((quota, period)),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            CtrlKind::MemoryMax => {
                // CF-3 FIX: "max" means unlimited - use u64::MAX to properly clear limit
                let max = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    memory_max: Some(max),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            CtrlKind::MemoryHigh => {
                // CF-3 FIX: "max" means unlimited - use u64::MAX to properly clear limit
                let high = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    memory_high: Some(high),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            CtrlKind::PidsMax => {
                // CF-3 FIX: "max" means unlimited - use u64::MAX to properly clear limit
                let max = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    pids_max: Some(max),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            CtrlKind::IoMax => {
                // CF-4 FIX: Parse "rbps=N wbps=N riops=N wiops=N" format with strict validation
                let mut bps: Option<u64> = None;
                let mut iops: Option<u64> = None;
                let mut seen = false;

                for part in data.split_whitespace() {
                    if let Some(val) = part.strip_prefix("rbps=").or(part.strip_prefix("wbps=")) {
                        bps = Some(val.parse().map_err(|_| FsError::Invalid)?);
                        seen = true;
                    } else if let Some(val) =
                        part.strip_prefix("riops=").or(part.strip_prefix("wiops="))
                    {
                        iops = Some(val.parse().map_err(|_| FsError::Invalid)?);
                        seen = true;
                    } else {
                        // CF-4 FIX: Reject unrecognized tokens
                        return Err(FsError::Invalid);
                    }
                }

                // CF-4 FIX: Require at least one valid token
                if !seen {
                    return Err(FsError::Invalid);
                }

                let limits = CgroupLimits {
                    io_max_bytes_per_sec: bps,
                    io_max_iops_per_sec: iops,
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            // J2-7: files.max — "max" clears the limit (u64::MAX). apply_limit
            // enforces the FILES controller + delegation boundary.
            CtrlKind::FilesMax => {
                let max = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    fds_max: Some(max),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            // J2-8: ports.max — "max" clears the limit (u64::MAX). apply_limit
            // enforces the NET controller + delegation boundary.
            CtrlKind::PortsMax => {
                let max = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    ports_max: Some(max),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            // J2-10: vfs_dir.max — "max" clears the limit (u64::MAX). apply_limit
            // enforces the MEMORY controller + delegation boundary.
            CtrlKind::VfsDirMax => {
                let max = if data == "max" {
                    u64::MAX
                } else {
                    data.parse().map_err(|_| FsError::Invalid)?
                };
                let limits = CgroupLimits {
                    vfs_dir_max: Some(max),
                    ..Default::default()
                };
                apply_limit(&cgroup, &limits, is_delegate)?;
                Ok(())
            }
            _ => Err(FsError::NotSupported),
        }
    }
}

impl Inode for CgroupCtrlInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // R153-8 FIX: Reflect actual write permission in reported mode.
        // Previously all writable control files reported 0o644 regardless
        // of delegation status, making them appear writable to everyone
        // despite write_content() enforcing root/delegate checks. Now we
        // check delegation status and only report 0o644 for root or the
        // delegated UID; others see 0o444 for defense-in-depth at the
        // VFS DAC layer.
        let mode = if self.kind.is_readonly() {
            FileMode::regular(0o444)
        } else {
            // Check if current caller would be allowed to write
            let can_write = kernel_core::current_is_host_root()
                || kernel_core::current_host_euid()
                    .and_then(|euid| {
                        cgroup::lookup_cgroup(self.cgroup_id).filter(|cg| cg.is_delegated_to(euid))
                    })
                    .is_some();
            if can_write {
                FileMode::regular(0o644)
            } else {
                FileMode::regular(0o444)
            }
        };

        // P1-3: Reflect delegated owner in DAC metadata so non-root
        // delegated managers pass VFS permission checks on control files.
        let owner = effective_owner(self.cgroup_id);

        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode,
            nlink: 1,
            uid: owner,
            gid: 0,
            rdev: 0,
            size: 0, // Dynamic content
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Check write permission for read-only files
        if flags.is_writable() && self.kind.is_readonly() {
            return Err(FsError::PermDenied);
        }

        let inode: Arc<dyn Inode> = Arc::new(CgroupCtrlInode {
            fs_id: self.fs_id,
            ino: self.ino,
            cgroup_id: self.cgroup_id,
            kind: self.kind,
        });
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn is_dir(&self) -> bool {
        false
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = self.read_content()?;
        let content_bytes = content.as_bytes();

        if offset as usize >= content_bytes.len() {
            return Ok(0);
        }

        let start = offset as usize;
        let end = core::cmp::min(start + buf.len(), content_bytes.len());
        let len = end - start;

        buf[..len].copy_from_slice(&content_bytes[start..end]);
        Ok(len)
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Convert to string and write
        let content = core::str::from_utf8(data).map_err(|_| FsError::Invalid)?;
        self.write_content(content)?;
        Ok(data.len())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// P1-3: Resolve the effective owner UID for a cgroup inode.
///
/// Walks the ancestor chain to find the nearest delegation point.
/// If a delegation exists, the cgroup directory (and its control files)
/// are owned by the delegated UID so that DAC permission checks pass
/// for the delegated manager.  Returns 0 (root) if no delegation.
fn effective_owner(cgroup_id: CgroupId) -> u32 {
    if let Some(cg) = cgroup::lookup_cgroup(cgroup_id) {
        if let Some(uid) = cg.delegate_uid() {
            return uid;
        }
        // R169-L4 FIX: Bound the ancestor walk by MAX_CGROUP_DEPTH (mirrors the
        // other cgroup ancestor walks) so a corrupted/cyclic parent chain cannot
        // spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
        let mut cursor = cg.parent();
        while let Some(node) = cursor {
            if let Some(uid) = node.delegate_uid() {
                return uid;
            }
            if depth >= cgroup::MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = node.parent();
        }
    }
    0
}

/// P1-3: Check if current process is host root OR owns the delegated subtree
/// containing `cgroup_id`.
///
/// R134-2 FIX: Use host-mapped root check and host-mapped euid for delegation
/// identity. Namespace euid==0 is not equivalent to host root.
fn is_privileged_or_delegate(cgroup_id: CgroupId) -> bool {
    if kernel_core::current_is_host_root() {
        return true;
    }
    let euid = match kernel_core::current_host_euid() {
        Some(uid) => uid,
        None => return false,
    };
    cgroup::lookup_cgroup(cgroup_id)
        .map(|cg| cg.is_delegated_to(euid))
        .unwrap_or(false)
}

/// P1-3: Apply a resource limit to a cgroup, enforcing delegation boundaries.
///
/// When `is_delegate` is true the caller is a non-root delegated manager.
/// In that case we first verify that the requested limits do not exceed
/// the effective ancestor limits (via `check_limit_boundary`, which walks
/// the full ancestor chain), preventing privilege escalation through the
/// delegation mechanism.
fn apply_limit(
    cgroup: &Arc<CgroupNode>,
    limits: &CgroupLimits,
    is_delegate: bool,
) -> Result<(), FsError> {
    if is_delegate {
        cgroup.check_limit_boundary(limits).map_err(|e| match e {
            CgroupError::PermissionDenied => FsError::PermDenied,
            CgroupError::InvalidLimit => FsError::Invalid,
            _ => FsError::Invalid,
        })?;
    }
    cgroup.set_limit(limits.clone()).map_err(|e| match e {
        CgroupError::ControllerDisabled => FsError::Invalid,
        CgroupError::InvalidLimit => FsError::Invalid,
        CgroupError::PermissionDenied => FsError::PermDenied,
        _ => FsError::Invalid,
    })
}

/// Render the cgroup-v2 controller-name list shared by `cgroup.controllers` and
/// `cgroup.subtree_control`.
///
/// J.2 NOTE: the advertised set MUST stay in lockstep with
/// `CtrlKind::required_controller()` — every controller that gates a control
/// file's visibility is advertised here, otherwise `files.max`/`ports.max`/
/// `vfs_dir.max` would appear in a directory whose controller is unlisted.
fn controllers_string(controllers: CgroupControllers) -> String {
    let mut parts = Vec::new();
    if controllers.contains(CgroupControllers::CPU) {
        parts.push("cpu");
    }
    if controllers.contains(CgroupControllers::MEMORY) {
        parts.push("memory");
    }
    if controllers.contains(CgroupControllers::PIDS) {
        parts.push("pids");
    }
    if controllers.contains(CgroupControllers::IO) {
        parts.push("io");
    }
    if controllers.contains(CgroupControllers::FILES) {
        parts.push("files");
    }
    if controllers.contains(CgroupControllers::NET) {
        parts.push("net");
    }
    parts.join(" ") + "\n"
}

/// J.2 cgroupfs ABI self-test (wired into the kernel boot integration suite).
///
/// Verifies the control-file surface exposing the FILES / NET / MEMORY-vfs_dir
/// enforcement that J.2 items 7/8/10 landed: filename round-trip, read-only
/// classification, controller-gated visibility, append-only inode safety, and
/// the read/format path (numeric, unlimited="max", and *.current gauges).
///
/// The WRITE path (`write_content`) is intentionally NOT driven here: it is
/// process-credential-gated (`current_host_euid` / host-root) and would be
/// environment-dependent in boot context. Its RW arms are structural twins of
/// the proven `memory.max`/`pids.max` arms (parse → `CgroupLimits` → `apply_limit`)
/// and are covered by the Codex convergence review. Limits are instead set via
/// the `set_limit` primitive and read back through `read_content`.
///
/// Any failure panics — detected by `make test` / `make boot-check`.
pub fn run_cgroupfs_j2_abi_self_test() {
    // 1. Pure-function invariants over EVERY kind (catches an append-only slip).
    for kind in CtrlKind::all() {
        assert_eq!(
            CtrlKind::from_filename(kind.filename()),
            Some(*kind),
            "cgroupfs: filename<->from_filename round-trip broken"
        );
    }
    // Append-only inode safety: ctrl_index + 1 must stay within the stride or a
    // file's inode would alias the next cgroup's directory (R154-2).
    assert!(
        (CtrlKind::all().len() as u64) < CGROUPFS_INO_STRIDE,
        "cgroupfs: control-file count exceeds inode stride (aliasing risk)"
    );
    assert!(
        CtrlKind::FilesCurrent.is_readonly()
            && CtrlKind::PortsCurrent.is_readonly()
            && CtrlKind::VfsDirCurrent.is_readonly(),
        "cgroupfs: *.current must be read-only"
    );
    assert!(
        !CtrlKind::FilesMax.is_readonly()
            && !CtrlKind::PortsMax.is_readonly()
            && !CtrlKind::VfsDirMax.is_readonly(),
        "cgroupfs: *.max must be writable"
    );

    // 2. Read/format path on a real cgroup carrying FILES | NET | MEMORY.
    let cg = cgroup::create_cgroup(
        0,
        CgroupControllers::FILES | CgroupControllers::NET | CgroupControllers::MEMORY,
    )
    .expect("cgroupfs self-test: create cgroup");
    let cg_id = cg.id();
    cg.set_limit(CgroupLimits {
        fds_max: Some(7),
        ports_max: Some(11),
        vfs_dir_max: Some(4096),
        ..Default::default()
    })
    .expect("cgroupfs self-test: set limits");

    let read = |kind: CtrlKind| {
        CgroupCtrlInode {
            fs_id: 0,
            ino: cgroup_ctrl_ino(cg_id, kind.index()),
            cgroup_id: cg_id,
            kind,
        }
        .read_content()
        .expect("cgroupfs self-test: read_content")
    };
    assert_eq!(read(CtrlKind::FilesMax), "7\n");
    assert_eq!(read(CtrlKind::PortsMax), "11\n");
    assert_eq!(read(CtrlKind::VfsDirMax), "4096\n");
    // *.current gauges are readable numerics (task-less cgroup ⇒ "0\n").
    assert_eq!(read(CtrlKind::FilesCurrent), "0\n");
    assert_eq!(read(CtrlKind::PortsCurrent), "0\n");
    assert_eq!(read(CtrlKind::VfsDirCurrent), "0\n");

    // 3. Unlimited (unset) limit renders as "max".
    let cg2 =
        cgroup::create_cgroup(0, CgroupControllers::FILES).expect("cgroupfs self-test: create cg2");
    let cg2_id = cg2.id();
    let files_max_cg2 = CgroupCtrlInode {
        fs_id: 0,
        ino: cgroup_ctrl_ino(cg2_id, CtrlKind::FilesMax.index()),
        cgroup_id: cg2_id,
        kind: CtrlKind::FilesMax,
    }
    .read_content()
    .expect("cgroupfs self-test: read cg2 files.max");
    assert_eq!(files_max_cg2, "max\n");

    // 4. Controller-gated visibility.
    let dir = CgroupDirInode {
        fs_id: 0,
        ino: cgroup_dir_ino(cg2_id),
        cgroup_id: cg2_id,
        name: String::new(),
    };
    let avail = dir.available_ctrl_files();
    assert!(
        avail.contains(&CtrlKind::FilesMax),
        "cgroupfs: files.max must be visible under the FILES controller"
    );
    // ports.max must be hidden when the NET controller is absent (robust to
    // whatever controller set create_cgroup grants the child).
    if !cg2.controllers().contains(CgroupControllers::NET) {
        assert!(
            !avail.contains(&CtrlKind::PortsMax),
            "cgroupfs: ports.max must be hidden without the NET controller"
        );
    }

    // Cleanup (leaf, task-less ⇒ deletable).
    let _ = cgroup::delete_cgroup(cg_id);
    let _ = cgroup::delete_cgroup(cg2_id);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctrl_kind_filename() {
        assert_eq!(CtrlKind::Procs.filename(), "cgroup.procs");
        assert_eq!(CtrlKind::CpuWeight.filename(), "cpu.weight");
        assert_eq!(CtrlKind::MemoryCurrent.filename(), "memory.current");
        // J.2 control files.
        assert_eq!(CtrlKind::FilesMax.filename(), "files.max");
        assert_eq!(CtrlKind::PortsMax.filename(), "ports.max");
        assert_eq!(CtrlKind::VfsDirCurrent.filename(), "vfs_dir.current");
    }

    #[test]
    fn test_ctrl_kind_readonly() {
        assert!(!CtrlKind::Procs.is_readonly());
        assert!(CtrlKind::Controllers.is_readonly());
        assert!(CtrlKind::MemoryCurrent.is_readonly());
        assert!(CtrlKind::PidsCurrent.is_readonly());
        assert!(CtrlKind::IoStat.is_readonly());
        // J.2: *.max writable, *.current read-only.
        assert!(!CtrlKind::FilesMax.is_readonly());
        assert!(!CtrlKind::PortsMax.is_readonly());
        assert!(!CtrlKind::VfsDirMax.is_readonly());
        assert!(CtrlKind::FilesCurrent.is_readonly());
        assert!(CtrlKind::PortsCurrent.is_readonly());
        assert!(CtrlKind::VfsDirCurrent.is_readonly());
    }

    #[test]
    fn test_ctrl_kind_from_filename() {
        assert_eq!(
            CtrlKind::from_filename("cgroup.procs"),
            Some(CtrlKind::Procs)
        );
        assert_eq!(
            CtrlKind::from_filename("cpu.weight"),
            Some(CtrlKind::CpuWeight)
        );
        assert_eq!(CtrlKind::from_filename("invalid"), None);
        // J.2 round-trip.
        assert_eq!(
            CtrlKind::from_filename("files.current"),
            Some(CtrlKind::FilesCurrent)
        );
        assert_eq!(
            CtrlKind::from_filename("ports.max"),
            Some(CtrlKind::PortsMax)
        );
        assert_eq!(
            CtrlKind::from_filename("vfs_dir.max"),
            Some(CtrlKind::VfsDirMax)
        );
    }

    #[test]
    fn test_ctrl_kind_required_controller() {
        assert_eq!(
            CtrlKind::FilesMax.required_controller(),
            Some(CgroupControllers::FILES)
        );
        assert_eq!(
            CtrlKind::PortsCurrent.required_controller(),
            Some(CgroupControllers::NET)
        );
        assert_eq!(
            CtrlKind::VfsDirMax.required_controller(),
            Some(CgroupControllers::MEMORY)
        );
    }

    #[test]
    fn test_ctrl_index_within_inode_stride() {
        // Append-only inode safety (mirrors the boot self-test guard).
        assert!((CtrlKind::all().len() as u64) < CGROUPFS_INO_STRIDE);
    }
}
