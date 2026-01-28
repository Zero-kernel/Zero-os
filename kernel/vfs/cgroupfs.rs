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
use spin::RwLock;

/// Global cgroupfs ID counter (starts at 300 to avoid collision with other FS types)
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(300);

/// Next inode number counter
static NEXT_INO: AtomicU64 = AtomicU64::new(2);

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
        }
    }

    /// Check if this control file is read-only
    fn is_readonly(&self) -> bool {
        matches!(
            self,
            CtrlKind::Controllers | CtrlKind::MemoryCurrent | CtrlKind::PidsCurrent | CtrlKind::IoStat
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
        ]
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
        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);

        // Root directory maps to root cgroup (id=0)
        let root = Arc::new(CgroupDirInode {
            fs_id,
            ino: 1,
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

        // Security check: require root
        if !is_privileged() {
            return Err(FsError::PermDenied);
        }

        let dir = parent
            .as_any()
            .downcast_ref::<CgroupDirInode>()
            .ok_or(FsError::NotDir)?;

        // Get parent cgroup to inherit controllers
        let parent_cgroup =
            cgroup::lookup_cgroup(dir.cgroup_id).ok_or(FsError::NotFound)?;
        let controllers = parent_cgroup.controllers();

        // Create child cgroup
        match cgroup::create_cgroup(dir.cgroup_id, controllers) {
            Ok(child) => {
                let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
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
        // Security check: require root
        if !is_privileged() {
            return Err(FsError::PermDenied);
        }

        let dir = parent
            .as_any()
            .downcast_ref::<CgroupDirInode>()
            .ok_or(FsError::NotDir)?;

        // Find child cgroup by name
        let parent_cgroup =
            cgroup::lookup_cgroup(dir.cgroup_id).ok_or(FsError::NotFound)?;

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

            let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
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
                let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
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
                    ino: NEXT_INO.fetch_add(1, Ordering::SeqCst),
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
                    ino: NEXT_INO.fetch_add(1, Ordering::SeqCst),
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
            CtrlKind::Controllers => {
                // List available controllers
                let controllers = cgroup.controllers();
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
                parts.join(" ") + "\n"
            }
            CtrlKind::SubtreeControl => {
                // Same as controllers for now (no separate subtree_control field)
                let controllers = cgroup.controllers();
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
                parts.join(" ") + "\n"
            }
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
        })
    }

    /// Write control file content
    fn write_content(&self, data: &str) -> Result<(), FsError> {
        if self.kind.is_readonly() {
            return Err(FsError::PermDenied);
        }

        // Security check
        if !is_privileged() {
            return Err(FsError::PermDenied);
        }

        let cgroup = cgroup::lookup_cgroup(self.cgroup_id).ok_or(FsError::NotFound)?;
        let data = data.trim();

        match self.kind {
            CtrlKind::Procs => {
                // CF-1 FIX: Parse PID and properly migrate task between cgroups
                let pid_num: u64 = data.parse().map_err(|_| FsError::Invalid)?;
                let pid = usize::try_from(pid_num).map_err(|_| FsError::Invalid)?;

                // Resolve current cgroup from the task struct
                let proc = process::get_process(pid).ok_or(FsError::NotFound)?;
                let old_cgroup_id = { proc.lock().cgroup_id };

                // Migrate task from old cgroup to this cgroup (atomic detach+attach)
                cgroup::migrate_task(pid_num, old_cgroup_id, self.cgroup_id)
                    .map_err(|e| match e {
                        CgroupError::PidsLimitExceeded => FsError::NoSpace,
                        CgroupError::TaskNotAttached => FsError::Invalid,
                        CgroupError::NotFound => FsError::NotFound,
                        _ => FsError::Invalid,
                    })?;

                // Update process's cgroup_id in PCB to keep state synchronized
                proc.lock().cgroup_id = self.cgroup_id;
                Ok(())
            }
            CtrlKind::SubtreeControl => {
                // Parse +controller -controller format
                // This would modify subtree_control field
                // For now, return success (no-op since we don't have subtree_control field)
                Ok(())
            }
            CtrlKind::CpuWeight => {
                let weight: u32 = data.parse().map_err(|_| FsError::Invalid)?;
                let limits = CgroupLimits {
                    cpu_weight: Some(weight),
                    ..Default::default()
                };
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
                    } else if let Some(val) = part.strip_prefix("riops=").or(part.strip_prefix("wiops=")) {
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
                cgroup.set_limit(limits).map_err(|_| FsError::Invalid)?;
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
        let mode = if self.kind.is_readonly() {
            FileMode::regular(0o444)
        } else {
            FileMode::regular(0o644)
        };

        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode,
            nlink: 1,
            uid: 0,
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

/// Check if current process has root/admin privileges
fn is_privileged() -> bool {
    kernel_core::current_credentials()
        .map(|creds| creds.euid == 0)
        .unwrap_or(false)
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
    }

    #[test]
    fn test_ctrl_kind_readonly() {
        assert!(!CtrlKind::Procs.is_readonly());
        assert!(CtrlKind::Controllers.is_readonly());
        assert!(CtrlKind::MemoryCurrent.is_readonly());
        assert!(CtrlKind::PidsCurrent.is_readonly());
        assert!(CtrlKind::IoStat.is_readonly());
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
    }
}
