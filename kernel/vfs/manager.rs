//! VFS Manager
//!
//! Provides the central VFS operations including:
//! - Mount table management
//! - Path resolution
//! - Global file operations (open, stat, etc.)
//! - Syscall callback registration
//! - DAC (Discretionary Access Control) permission enforcement
//! - LSM (Linux Security Module) hook integration (R25-9 fix)

use crate::devfs::DevFs;
use crate::procfs::ProcFs;
use crate::ramfs::RamFs;
use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, ResolveFlags, Stat};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::BlockDevice;
use kernel_core::{
    current_egid, current_euid, current_supplementary_groups, current_umask, FileDescriptor,
    FileOps, SyscallError, VfsStat,
};
use spin::RwLock;

// R25-9 FIX: Import LSM hooks for MAC enforcement
use lsm::{FileCtx as LsmFileCtx, OpenFlags as LsmOpenFlags, ProcessCtx as LsmProcessCtx};

/// Simple FNV-1a 64-bit hash for path hashing in LSM contexts
/// R25-9 FIX: Used to generate path hashes for LSM hooks
#[inline]
fn hash_path(path: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Check if current process has required access permissions on a file
///
/// Implements POSIX-style DAC (Discretionary Access Control):
/// 1. Root (euid == 0) has all permissions
/// 2. File owner uses owner permission bits (0o700)
/// 3. File group member (primary or supplementary) uses group permission bits (0o070)
/// 4. Others use other permission bits (0o007)
///
/// # Arguments
/// * `stat` - File status containing uid, gid, and permission mode
/// * `need_read` - Whether read access is required
/// * `need_write` - Whether write access is required
/// * `need_exec` - Whether execute access is required
///
/// # Returns
/// `true` if access is permitted, `false` otherwise
fn check_access_permission(
    stat: &Stat,
    need_read: bool,
    need_write: bool,
    need_exec: bool,
) -> bool {
    // Get current process credentials (default to root if no process context)
    let euid = current_euid().unwrap_or(0);
    let egid = current_egid().unwrap_or(0);
    let supplementary = current_supplementary_groups().unwrap_or_default();

    // Root (euid 0) bypasses all permission checks
    if euid == 0 {
        return true;
    }

    let perm = stat.mode.perm;

    // Determine which permission bits to check based on uid/gid
    // Check supplementary groups in addition to primary group
    let check_bits = if euid == stat.uid {
        // Owner: use high bits (0o700)
        (perm >> 6) & 0o7
    } else if egid == stat.gid || supplementary.iter().any(|&g| g == stat.gid) {
        // Group (primary or supplementary): use middle bits (0o070)
        (perm >> 3) & 0o7
    } else {
        // Others: use low bits (0o007)
        perm & 0o7
    };

    // Check each requested permission
    if need_read && (check_bits & 0o4) == 0 {
        return false;
    }
    if need_write && (check_bits & 0o2) == 0 {
        return false;
    }
    if need_exec && (check_bits & 0o1) == 0 {
        return false;
    }

    true
}

/// Apply current process umask to requested permission bits
///
/// The umask bits are cleared from the requested permissions:
/// effective_perm = requested_perm & !umask
///
/// # Arguments
/// * `perm` - Requested permission bits (e.g., 0o666 for files, 0o777 for directories)
///
/// # Returns
/// Permission bits after applying umask
#[inline]
fn apply_umask(perm: u16) -> u16 {
    let mask = current_umask().unwrap_or(0) & 0o777;
    perm & !mask & 0o7777
}

/// Strip setuid/setgid bits from permission if caller is not root
///
/// # Security
///
/// Prevents unprivileged users from creating setuid/setgid executables.
/// - setuid (04000) is always stripped for non-root
/// - setgid (02000) is stripped for regular files for non-root
///   (but allowed on directories for proper setgid inheritance)
///
/// # Arguments
/// * `perm` - Permission bits to sanitize
/// * `is_dir` - Whether the target is a directory
///
/// # Returns
/// Sanitized permission bits
#[inline]
fn strip_suid_sgid_if_needed(perm: u16, is_dir: bool) -> u16 {
    let euid = current_euid().unwrap_or(0);

    if euid == 0 {
        // Root can create setuid/setgid files
        return perm;
    }

    let mut sanitized = perm;

    // Always strip setuid bit for non-root
    sanitized &= !0o4000;

    // Strip setgid bit for regular files (not directories)
    // Directories can keep setgid for proper inheritance
    if !is_dir {
        sanitized &= !0o2000;
    }

    sanitized
}

/// Mount point information
struct Mount {
    /// Absolute path where this filesystem is mounted
    path: String,
    /// The mounted filesystem
    fs: Arc<dyn FileSystem>,
}

/// Global VFS state
pub struct Vfs {
    /// Mount table: path -> filesystem
    mounts: RwLock<BTreeMap<String, Mount>>,
    /// Root filesystem
    root_fs: RwLock<Option<Arc<dyn FileSystem>>>,
    /// Device filesystem handle for block device registration
    devfs: RwLock<Option<Arc<DevFs>>>,
}

impl Vfs {
    /// Create a new VFS instance
    pub const fn new() -> Self {
        Self {
            mounts: RwLock::new(BTreeMap::new()),
            root_fs: RwLock::new(None),
            devfs: RwLock::new(None),
        }
    }

    /// Initialize the VFS with default mounts
    pub fn init(&self) {
        // Create ramfs as root filesystem
        let ramfs = RamFs::new();

        // Set ramfs as root
        *self.root_fs.write() = Some(ramfs.clone());

        // Mount ramfs at / first
        self.mount("/", ramfs.clone())
            .expect("Failed to mount ramfs at /");

        // Create mount point directories in root ramfs so they appear in ls
        // These directories are needed so that readdir("/") shows /dev and /proc
        let root_inode = ramfs.root_inode();
        let dir_mode = crate::types::FileMode::new(crate::types::FileType::Directory, 0o755);

        // Create /dev directory entry
        if let Err(e) = ramfs.create(&root_inode, "dev", dir_mode) {
            println!("Warning: failed to create /dev mountpoint: {:?}", e);
        }

        // Create /proc directory entry
        if let Err(e) = ramfs.create(&root_inode, "proc", dir_mode) {
            println!("Warning: failed to create /proc mountpoint: {:?}", e);
        }

        // Create and mount devfs at /dev
        let devfs = DevFs::new();
        self.mount("/dev", devfs.clone())
            .expect("Failed to mount devfs");
        *self.devfs.write() = Some(devfs);

        // Create and mount procfs at /proc
        let procfs = ProcFs::new();
        self.mount("/proc", procfs).expect("Failed to mount procfs");

        println!("VFS initialized: ramfs at /, devfs at /dev, procfs at /proc");
    }

    /// Mount a filesystem at the given path
    ///
    /// # Security (X-4 fix)
    ///
    /// Mount 操作仅限 root 用户（euid == 0）或内核初始化路径。
    /// 未授权的 mount 可能导致：
    /// - 攻击者注入恶意文件系统
    /// - setuid 二进制文件劫持
    /// - 数据泄露或完整性破坏
    pub fn mount(&self, path: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
        // X-4 安全修复：只有 root 可以执行 mount
        // current_euid() 返回 None 表示内核初始化阶段（允许）
        // 返回 Some(uid) 时需要检查是否为 root
        if let Some(euid) = current_euid() {
            if euid != 0 {
                return Err(FsError::PermDenied);
            }
        }

        let path = normalize_path(path)?;

        // R26-2 FIX: MAC gate for mount operations
        // LSM policy can block mounts even for root users
        if let Some(task) = LsmProcessCtx::from_current() {
            let path_hash = hash_path(&path);
            lsm::hook_file_mount(&task, 0, path_hash, 0, 0).map_err(|_| FsError::PermDenied)?;
        }

        let mut mounts = self.mounts.write();
        if mounts.contains_key(&path) {
            return Err(FsError::Exists);
        }

        mounts.insert(path.clone(), Mount { path, fs });
        Ok(())
    }

    /// Unmount filesystem at path
    ///
    /// # Security (X-4 fix)
    ///
    /// Umount 操作仅限 root 用户（euid == 0）。
    /// 未授权的 umount 可能导致 DoS（卸载关键文件系统）。
    pub fn umount(&self, path: &str) -> Result<(), FsError> {
        // X-4 安全修复：只有 root 可以执行 umount
        if let Some(euid) = current_euid() {
            if euid != 0 {
                return Err(FsError::PermDenied);
            }
        }

        let path = normalize_path(path)?;

        // R26-2 FIX: MAC gate for umount operations
        // LSM policy can block unmounts even for root users
        if let Some(task) = LsmProcessCtx::from_current() {
            let path_hash = hash_path(&path);
            lsm::hook_file_umount(&task, path_hash, 0).map_err(|_| FsError::PermDenied)?;
        }

        let mut mounts = self.mounts.write();

        if mounts.remove(&path).is_some() {
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    /// Resolve a path to an inode (default behavior: follow symlinks)
    ///
    /// Enforces execute/search permission on each directory component during traversal.
    /// This prevents unauthorized access to files in directories without "x" permission.
    pub fn lookup_path(&self, path: &str) -> Result<Arc<dyn Inode>, FsError> {
        self.lookup_path_with_flags(path, ResolveFlags::empty(), true)
    }

    /// Resolve a path with optional symlink following and resolve flags
    ///
    /// # Arguments
    ///
    /// * `path` - The path to resolve
    /// * `resolve_flags` - Flags controlling symlink and mount behavior
    /// * `follow_final_symlink` - Whether to follow the final path component if it's a symlink
    ///
    /// # Security
    ///
    /// - Enforces execute/search permission on each directory component
    /// - Limits symlink resolution to MAX_SYMLINK_DEPTH (40) to prevent loops
    /// - RESOLVE_NO_SYMLINKS rejects any symlink in the path
    /// - RESOLVE_BENEATH prevents escaping the starting directory
    /// - RESOLVE_NO_MAGICLINKS blocks /proc magic symlinks
    /// - RESOLVE_NO_XDEV prevents crossing mount boundaries
    pub fn lookup_path_with_flags(
        &self,
        path: &str,
        resolve_flags: ResolveFlags,
        follow_final_symlink: bool,
    ) -> Result<Arc<dyn Inode>, FsError> {
        const MAX_SYMLINK_DEPTH: usize = 40;

        let mut symlink_count: usize = 0;
        let is_absolute = path.starts_with('/');
        let mut path_to_resolve = normalize_path(path)?;

        // Capture the starting filesystem for RESOLVE_NO_XDEV
        let (anchor_mount, anchor_fs, _) = self.find_mount(&path_to_resolve)?;
        let anchor_fs_id = anchor_fs.fs_id();

        // R41-2 FIX: Reject absolute paths when confinement flags are set
        //
        // SECURITY: RESOLVE_BENEATH and RESOLVE_IN_ROOT are designed to confine
        // path resolution to a directory subtree. For this to work, paths must
        // be relative to the anchor directory. Absolute paths bypass this
        // confinement because anchor_mount for "/" makes all paths pass the
        // starts_with check. This matches Linux's openat2 behavior.
        if (resolve_flags.beneath() || resolve_flags.in_root())
            && is_absolute
            && path_to_resolve != anchor_mount
        {
            return Err(FsError::Invalid);
        }

        'resolve: loop {
            // RESOLVE_BENEATH / RESOLVE_IN_ROOT: check path stays within anchor
            if (resolve_flags.beneath() || resolve_flags.in_root())
                && !path_to_resolve.starts_with(&anchor_mount)
            {
                return Err(FsError::CrossDev);
            }

            let (mount_path, fs, relative_path) = self.find_mount(&path_to_resolve)?;

            // RESOLVE_NO_XDEV: reject if we crossed a mount boundary
            if resolve_flags.no_xdev() && fs.fs_id() != anchor_fs_id {
                return Err(FsError::CrossDev);
            }

            // R65-20 FIX: Validate execute permission on the mount point before crossing
            // into the mounted filesystem. This enforces directory traversal permissions
            // up to and including the mount point itself, preventing permission bypass.
            //
            // We must verify traverse permission on the mount point directory in the
            // parent filesystem before allowing access to the mounted filesystem's contents.
            if mount_path != "/" {
                // Split to get parent path and mount point name
                if let Some(last_slash) = mount_path.rfind('/') {
                    let parent_path = if last_slash == 0 {
                        "/".to_string()
                    } else {
                        mount_path[..last_slash].to_string()
                    };
                    let mp_name = &mount_path[last_slash + 1..];

                    if !mp_name.is_empty() {
                        // Resolve the parent directory path
                        if let Ok((_, parent_fs, parent_relative)) = self.find_mount(&parent_path) {
                            // Walk to the parent directory in the parent filesystem
                            let mut parent_inode = parent_fs.root_inode();
                            let parent_components: Vec<&str> = parent_relative
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .collect();

                            for comp in parent_components {
                                if !parent_inode.is_dir() {
                                    return Err(FsError::NotDir);
                                }
                                let dir_stat = parent_inode.stat()?;
                                if !check_access_permission(&dir_stat, false, false, true) {
                                    return Err(FsError::PermDenied);
                                }
                                parent_inode = parent_fs.lookup(&parent_inode, comp)?;
                            }

                            // Check execute permission on parent directory
                            if !parent_inode.is_dir() {
                                return Err(FsError::NotDir);
                            }
                            let parent_stat = parent_inode.stat()?;
                            if !check_access_permission(&parent_stat, false, false, true) {
                                return Err(FsError::PermDenied);
                            }

                            // Now check the mount point directory itself
                            if let Ok(mount_inode) = parent_fs.lookup(&parent_inode, mp_name) {
                                if mount_inode.is_dir() {
                                    let mount_stat = mount_inode.stat()?;
                                    if !check_access_permission(&mount_stat, false, false, true) {
                                        return Err(FsError::PermDenied);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut current = fs.root_inode();

            // Handle empty relative path (mount point itself)
            if relative_path.is_empty() || relative_path == "/" {
                return Ok(current);
            }

            // Track resolved prefix for relative symlink resolution
            let mut resolved_prefix: Vec<String> = mount_path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            let components: Vec<&str> =
                relative_path.split('/').filter(|s| !s.is_empty()).collect();

            for (idx, component) in components.iter().enumerate() {
                if !current.is_dir() {
                    return Err(FsError::NotDir);
                }

                // Check execute/search permission on directory before traversing
                if idx < components.len() - 1 || components.len() == 1 {
                    let dir_stat = current.stat()?;
                    if !check_access_permission(&dir_stat, false, false, true) {
                        return Err(FsError::PermDenied);
                    }
                }

                let next = fs.lookup(&current, component)?;
                let next_stat = next.stat()?;
                let is_final = idx == components.len() - 1;

                // Check if this is a symlink
                if next_stat.mode.file_type == FileType::Symlink {
                    // RESOLVE_NO_SYMLINKS: reject any symlink
                    if resolve_flags.no_symlinks() {
                        return Err(FsError::SymlinkLoop);
                    }

                    // Final symlink + nofollow: return ELOOP
                    if is_final && !follow_final_symlink {
                        return Err(FsError::SymlinkLoop);
                    }

                    // RESOLVE_NO_MAGICLINKS: block procfs magic symlinks
                    if resolve_flags.no_magiclinks() && fs.fs_type() == "proc" {
                        return Err(FsError::SymlinkLoop);
                    }

                    // Symlink loop detection
                    symlink_count += 1;
                    if symlink_count > MAX_SYMLINK_DEPTH {
                        return Err(FsError::SymlinkLoop);
                    }

                    // Read symlink target
                    let target_len = next_stat.size.min(4096) as usize;
                    let mut buf = Vec::with_capacity(target_len.max(1));
                    buf.resize(target_len.max(1), 0u8);
                    let read_len = next.read_at(0, &mut buf)?;
                    let target = core::str::from_utf8(&buf[..read_len])
                        .map_err(|_| FsError::Invalid)?
                        .to_string();

                    // Build new path based on symlink target
                    let new_path = if target.starts_with('/') {
                        // Absolute symlink
                        if resolve_flags.in_root() && anchor_mount != "/" {
                            // Reroot absolute symlinks within the anchor
                            let mut path = String::from(anchor_mount.trim_end_matches('/'));
                            path.push('/');
                            path.push_str(target.trim_start_matches('/'));
                            path
                        } else {
                            target
                        }
                    } else {
                        // Relative symlink: resolve from current directory
                        let mut prefix = String::from("/");
                        if !resolved_prefix.is_empty() {
                            prefix.push_str(&resolved_prefix.join("/"));
                        }
                        if !prefix.ends_with('/') {
                            prefix.push('/');
                        }
                        prefix.push_str(&target);
                        prefix
                    };

                    // Append remaining path components
                    let remaining: Vec<&str> = components.iter().skip(idx + 1).copied().collect();
                    let full_path = if remaining.is_empty() {
                        new_path
                    } else {
                        let mut path = String::from(new_path.trim_end_matches('/'));
                        path.push('/');
                        path.push_str(&remaining.join("/"));
                        path
                    };

                    path_to_resolve = normalize_path(&full_path)?;
                    continue 'resolve;
                }

                current = next;
                resolved_prefix.push((*component).to_string());
            }

            return Ok(current);
        }
    }

    /// Open a file by path
    ///
    /// Supports O_CREAT for file creation and O_EXCL for exclusive creation.
    pub fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        create_mode: u16,
    ) -> Result<Box<dyn FileOps>, FsError> {
        self.open_with_resolve(path, flags, create_mode, ResolveFlags::empty())
    }

    /// Open a file by path with resolve flags (openat2-compatible)
    ///
    /// # Arguments
    ///
    /// * `path` - The path to open
    /// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_CREAT, O_NOFOLLOW, etc.)
    /// * `create_mode` - Permission mode for file creation
    /// * `resolve_flags` - Flags controlling symlink and mount behavior
    ///
    /// # Security
    ///
    /// - O_NOFOLLOW: Returns ELOOP if final component is a symlink
    /// - RESOLVE_NO_SYMLINKS: Returns ELOOP for any symlink in path
    /// - Full DAC and LSM permission checks
    pub fn open_with_resolve(
        &self,
        path: &str,
        flags: OpenFlags,
        create_mode: u16,
        resolve_flags: ResolveFlags,
    ) -> Result<Box<dyn FileOps>, FsError> {
        let path = normalize_path(path)?;

        // O_NOFOLLOW: don't follow the final symlink
        let follow_final = !flags.is_nofollow();

        // Resolve existing path or create on demand
        let inode = match self.lookup_path_with_flags(&path, resolve_flags, follow_final) {
            Ok(inode) => {
                // File exists - check O_EXCL
                if flags.is_create() && flags.is_exclusive() {
                    return Err(FsError::Exists);
                }
                inode
            }
            Err(FsError::NotFound) if flags.is_create() => {
                // File doesn't exist and O_CREAT is set - create it
                let (parent_path, filename) = split_path(&path)?;
                // Parent lookup should always follow symlinks (the parent must be a real dir)
                let parent = self.lookup_path_with_flags(&parent_path, resolve_flags, true)?;
                if !parent.is_dir() {
                    return Err(FsError::NotDir);
                }

                // DAC check: need write+execute on parent directory to create files
                let parent_stat = parent.stat()?;
                if !check_access_permission(&parent_stat, false, true, true) {
                    return Err(FsError::PermDenied);
                }

                let (_, fs, _) = self.find_mount(&path)?;
                // Apply umask and strip setuid/setgid bits for non-root
                let requested = create_mode & 0o7777;
                let masked = apply_umask(requested);
                let sanitized = strip_suid_sgid_if_needed(masked, false);
                let mode = FileMode::regular(sanitized);

                // C.4 FIX: Revalidate permissions just before creation to shrink TOCTOU window
                let latest_parent_stat = parent.stat()?;
                if latest_parent_stat.ino != parent_stat.ino
                    || !check_access_permission(&latest_parent_stat, false, true, true)
                {
                    return Err(FsError::PermDenied);
                }

                // C.4 FIX: If the file appeared after the first lookup, honor O_EXCL but
                // otherwise fall back to opening the existing file (POSIX semantics)
                match fs.lookup(&parent, filename) {
                    Ok(existing) => {
                        if flags.is_exclusive() {
                            return Err(FsError::Exists);
                        }
                        existing
                    }
                    Err(FsError::NotFound) => {
                        // R26-1 FIX: MAC gate before file creation (using freshest metadata)
                        if let Some(task) = LsmProcessCtx::from_current() {
                            let name_hash = hash_path(filename);
                            lsm::hook_file_create(
                                &task,
                                latest_parent_stat.ino,
                                name_hash,
                                mode.to_raw(),
                            )
                            .map_err(|_| FsError::PermDenied)?;
                        }

                        fs.create(&parent, filename, mode)?
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };

        // V-1 fix: Enforce DAC permissions before opening
        //
        // Full POSIX-style permission model:
        // 1. If euid == 0 (root), allow all access
        // 2. If euid == file owner, check owner bits (0o700)
        // 3. If egid == file group, check group bits (0o070)
        // 4. Otherwise, check other bits (0o007)
        let stat = inode.stat()?;

        // R25-9 FIX: Call LSM hook before DAC check for MAC enforcement
        if let Some(task) = LsmProcessCtx::from_current() {
            let file_ctx = LsmFileCtx::new(stat.ino, stat.mode.to_raw(), hash_path(&path));
            lsm::hook_file_open(&task, stat.ino, LsmOpenFlags(flags.0), &file_ctx)
                .map_err(|_| FsError::PermDenied)?;
        }

        if !check_access_permission(&stat, flags.is_readable(), flags.is_writable(), false) {
            return Err(FsError::PermDenied);
        }

        // Check if opening a directory for writing
        if inode.is_dir() && flags.is_writable() {
            return Err(FsError::IsDir);
        }

        // Handle truncate for writable regular files
        // C.4 FIX: Revalidate write permission immediately before truncate
        if flags.is_truncate() && flags.is_writable() && !inode.is_dir() {
            let fresh_stat = inode.stat()?;
            if !check_access_permission(&fresh_stat, flags.is_readable(), true, false) {
                return Err(FsError::PermDenied);
            }
            inode.truncate(0)?;
        }

        inode.open(flags)
    }

    /// Get file status by path
    pub fn stat(&self, path: &str) -> Result<Stat, FsError> {
        let inode = self.lookup_path(path)?;
        inode.stat()
    }

    /// Read directory entries
    pub fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let inode = self.lookup_path(path)?;

        if !inode.is_dir() {
            return Err(FsError::NotDir);
        }

        // 【W-2 安全修复】读取目录需要 read + execute 权限
        // 仅有 --x 权限的目录允许通过已知文件名访问，但不允许枚举内容
        // 防止信息泄漏（如枚举 /home 下其他用户的目录名）
        let dir_stat = inode.stat()?;

        // R37-4 FIX: Enforce MAC via LSM before DAC for directory reads.
        // Access mask 0x05 = MAY_READ | MAY_EXEC (required to enumerate directory).
        if let Some(task) = LsmProcessCtx::from_current() {
            lsm::hook_file_permission(&task, dir_stat.ino, 0x05)
                .map_err(|_| FsError::PermDenied)?;
        }

        if !check_access_permission(&dir_stat, true, false, true) {
            return Err(FsError::PermDenied);
        }

        let mut entries = Vec::new();
        let mut offset = 0usize;

        loop {
            match inode.readdir(offset)? {
                Some((next_offset, entry)) => {
                    entries.push(entry);
                    offset = next_offset;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    /// Create a file or directory
    pub fn create(&self, path: &str, mode: FileMode) -> Result<Arc<dyn Inode>, FsError> {
        let path = normalize_path(path)?;

        // Get parent directory and filename
        let (parent_path, filename) = split_path(&path)?;

        // Lookup parent
        let parent = self.lookup_path(&parent_path)?;
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // DAC check: need write+execute on parent directory to create entries
        let parent_stat = parent.stat()?;
        if !check_access_permission(&parent_stat, false, true, true) {
            return Err(FsError::PermDenied);
        }

        // Find the filesystem
        let (_, fs, _) = self.find_mount(&path)?;

        // Apply umask and strip setuid/setgid bits for non-root
        let masked = apply_umask(mode.perm);
        let sanitized = strip_suid_sgid_if_needed(masked, mode.is_dir());
        let masked_mode = FileMode::new(mode.file_type, sanitized);

        // C.4 FIX: Revalidate parent permissions and absence right before create
        let latest_parent_stat = parent.stat()?;
        if latest_parent_stat.ino != parent_stat.ino
            || !check_access_permission(&latest_parent_stat, false, true, true)
        {
            return Err(FsError::PermDenied);
        }
        // Verify target still doesn't exist
        if fs.lookup(&parent, filename).is_ok() {
            return Err(FsError::Exists);
        }

        // R25-9 FIX: Call LSM hook before creating file/directory (using freshest metadata)
        if let Some(task) = LsmProcessCtx::from_current() {
            let name_hash = hash_path(filename);
            if masked_mode.is_dir() {
                lsm::hook_file_mkdir(
                    &task,
                    latest_parent_stat.ino,
                    name_hash,
                    masked_mode.to_raw(),
                )
                .map_err(|_| FsError::PermDenied)?;
            } else {
                lsm::hook_file_create(
                    &task,
                    latest_parent_stat.ino,
                    name_hash,
                    masked_mode.to_raw(),
                )
                .map_err(|_| FsError::PermDenied)?;
            }
        }

        // Create the entry with sanitized permissions
        fs.create(&parent, filename, masked_mode)
    }

    /// Remove a file or directory
    ///
    /// Enforces sticky-bit semantics: in a directory with sticky bit set (mode & 0o1000),
    /// only root, the directory owner, or the file owner may delete files.
    pub fn unlink(&self, path: &str) -> Result<(), FsError> {
        let path = normalize_path(path)?;

        let (parent_path, filename) = split_path(&path)?;
        let parent = self.lookup_path(&parent_path)?;

        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        let parent_stat = parent.stat()?;

        // DAC check: need write+execute on parent directory to unlink entries
        if !check_access_permission(&parent_stat, false, true, true) {
            return Err(FsError::PermDenied);
        }

        let (_, fs, _) = self.find_mount(&path)?;

        // Look up the child to check sticky bit permissions
        let child = fs.lookup(&parent, filename)?;
        let child_ino = child.ino();

        // C.4 FIX: Revalidate parent permissions as close as possible to the destructive op
        let latest_parent_stat = parent.stat()?;
        if latest_parent_stat.ino != parent_stat.ino
            || !check_access_permission(&latest_parent_stat, false, true, true)
        {
            return Err(FsError::PermDenied);
        }

        // C.4 FIX: Ensure the target hasn't been swapped since initial lookup
        let current = fs.lookup(&parent, filename)?;
        if current.ino() != child_ino {
            // Target was replaced by a different inode - reject to prevent wrong deletion
            return Err(FsError::PermDenied);
        }
        let current_stat = current.stat()?;

        // Enforce sticky-bit semantics on the current (revalidated) entry:
        // If parent directory has sticky bit set, only root, directory owner,
        // or file owner may delete the file
        if latest_parent_stat.mode.perm & 0o1000 != 0 {
            let euid = current_euid().unwrap_or(0);
            if euid != 0 && euid != current_stat.uid && euid != latest_parent_stat.uid {
                return Err(FsError::PermDenied);
            }
        }

        // R25-9 FIX: Call LSM hook before unlinking file/directory (using revalidated metadata)
        if let Some(task) = LsmProcessCtx::from_current() {
            let name_hash = hash_path(filename);
            if current.is_dir() {
                lsm::hook_file_rmdir(&task, latest_parent_stat.ino, name_hash)
                    .map_err(|_| FsError::PermDenied)?;
            } else {
                lsm::hook_file_unlink(&task, latest_parent_stat.ino, name_hash)
                    .map_err(|_| FsError::PermDenied)?;
            }
        }

        // C.4 FIX: Final TOCTOU guard - ensure the entry still refers to the expected inode
        // immediately before performing the unlink
        let final_lookup = fs.lookup(&parent, filename)?;
        if final_lookup.ino() != child_ino {
            return Err(FsError::PermDenied);
        }

        fs.unlink(&parent, filename)
    }

    /// Find the mount point for a given path
    fn find_mount(&self, path: &str) -> Result<(String, Arc<dyn FileSystem>, String), FsError> {
        let mounts = self.mounts.read();

        // Helper to check if path matches mount point with proper boundaries
        // e.g., /dev matches /dev and /dev/null, but not /device
        let mount_matches = |target: &str, mount_path: &str| -> bool {
            if mount_path == "/" {
                true
            } else if target == mount_path {
                true
            } else {
                target.starts_with(mount_path)
                    && target.as_bytes().get(mount_path.len()) == Some(&b'/')
            }
        };

        // Find longest matching mount point
        let mut best_match: Option<(&String, &Mount)> = None;

        for (mount_path, mount) in mounts.iter() {
            if mount_matches(path, mount_path.as_str()) {
                match best_match {
                    None => best_match = Some((mount_path, mount)),
                    Some((current_path, _)) => {
                        if mount_path.len() > current_path.len() {
                            best_match = Some((mount_path, mount));
                        }
                    }
                }
            }
        }

        if let Some((mount_path, mount)) = best_match {
            let relative = if path.len() > mount_path.len() {
                &path[mount_path.len()..]
            } else {
                "/"
            };
            Ok((
                mount_path.clone(),
                Arc::clone(&mount.fs),
                relative.to_string(),
            ))
        } else {
            // No mount found, check if we have a root fs
            let root_fs = self.root_fs.read();
            if let Some(fs) = root_fs.as_ref() {
                Ok(("/".to_string(), Arc::clone(fs), path.to_string()))
            } else {
                Err(FsError::NotFound)
            }
        }
    }

    /// Register a block device under /dev
    ///
    /// Creates a device node at /dev/{name} for the given block device.
    /// This enables filesystem mounting and raw device access.
    ///
    /// # Arguments
    /// * `name` - Device name (e.g., "vda", "sda")
    /// * `device` - Block device implementation
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(FsError::NotFound)` if VFS/devfs not initialized
    /// * `Err(FsError::Exists)` if device name already exists
    pub fn register_block_device(
        &self,
        name: &str,
        device: Arc<dyn BlockDevice>,
    ) -> Result<(), FsError> {
        // Clone Arc and release lock before calling into DevFs to avoid
        // holding our lock while DevFs acquires its internal lock
        let devfs = {
            let guard = self.devfs.read();
            guard.as_ref().cloned().ok_or(FsError::NotFound)?
        };
        devfs.register_block_device(name, device)
    }
}

/// Global VFS instance
lazy_static::lazy_static! {
    pub static ref VFS: Vfs = Vfs::new();
}

/// Initialize the global VFS
pub fn init() {
    VFS.init();
    register_syscall_callbacks();
}

// ============================================================================
// Path utilities
// ============================================================================

/// Normalize a path (remove . and .., ensure leading /)
///
/// # Security (R32-VFS-1 fix)
///
/// Rejects paths that attempt to traverse above the root directory.
/// Paths like "/../../etc/passwd" will return PermDenied to prevent
/// sandbox/mount jail escapes.
fn normalize_path(path: &str) -> Result<String, FsError> {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {} // Skip empty and current dir
            ".." => {
                // R32-VFS-1 FIX: Reject attempts to traverse above root
                if components.pop().is_none() {
                    return Err(FsError::PermDenied);
                }
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        Ok("/".to_string())
    } else {
        let mut result = String::new();
        for c in components {
            result.push('/');
            result.push_str(c);
        }
        Ok(result)
    }
}

/// Split path into parent directory and filename
fn split_path(path: &str) -> Result<(String, &str), FsError> {
    let path = path.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Err(FsError::Invalid);
    }

    match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let filename = &path[pos + 1..];
            if filename.is_empty() {
                Err(FsError::Invalid)
            } else {
                Ok((parent.to_string(), filename))
            }
        }
        None => Ok(("/".to_string(), path)),
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Open a file by path (global convenience function)
///
/// # Arguments
/// * `path` - Path to the file
/// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - Permission mode for file creation (only used with O_CREAT)
pub fn open(path: &str, flags: OpenFlags, mode: u16) -> Result<Box<dyn FileOps>, FsError> {
    VFS.open(path, flags, mode)
}

/// Get file status by path
pub fn stat(path: &str) -> Result<Stat, FsError> {
    VFS.stat(path)
}

/// Read directory entries
pub fn readdir(path: &str) -> Result<Vec<DirEntry>, FsError> {
    VFS.readdir(path)
}

/// Mount a filesystem
pub fn mount(path: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
    VFS.mount(path, fs)
}

/// Unmount a filesystem
pub fn umount(path: &str) -> Result<(), FsError> {
    VFS.umount(path)
}

/// Register a block device in devfs
///
/// Creates a device node at /dev/{name} for the given block device.
/// This is the main entry point for drivers to register block devices.
///
/// # Arguments
/// * `name` - Device name (e.g., "vda" for first virtio-blk device)
/// * `device` - Block device implementation
///
/// # Example
/// ```ignore
/// let virtio_dev = VirtioBlkDevice::probe(mmio_addr, virt_offset, "vda")?;
/// vfs::register_block_device("vda", Arc::new(virtio_dev))?;
/// ```
pub fn register_block_device(name: &str, device: Arc<dyn BlockDevice>) -> Result<(), FsError> {
    VFS.register_block_device(name, device)
}

// ============================================================================
// Syscall callbacks
// ============================================================================

/// Convert VFS FsError to kernel SyscallError
fn fs_error_to_syscall(e: FsError) -> SyscallError {
    match e {
        FsError::NotFound => SyscallError::ENOENT,
        FsError::PermDenied => SyscallError::EACCES,
        FsError::Exists => SyscallError::EEXIST,
        FsError::NotDir => SyscallError::ENOTDIR,
        FsError::IsDir => SyscallError::EISDIR,
        FsError::NotEmpty => SyscallError::EBUSY,
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

/// VFS open callback for syscall registration
///
/// Called by sys_open to open a file through VFS
fn vfs_open_callback(path: &str, flags: u32, mode: u32) -> Result<FileDescriptor, SyscallError> {
    let open_flags = OpenFlags::from_bits(flags);
    let perm = (mode & 0o7777) as u16;

    VFS.open(path, open_flags, perm)
        .map_err(fs_error_to_syscall)
}

/// VFS open with resolve flags callback (openat2 support)
///
/// Called by sys_openat2 to open a file with resolve flags through VFS
fn vfs_open_with_resolve_callback(
    path: &str,
    flags: u32,
    mode: u32,
    resolve: u64,
) -> Result<FileDescriptor, SyscallError> {
    let open_flags = OpenFlags::from_bits(flags);
    let resolve_flags = ResolveFlags::from_bits(resolve);
    let perm = (mode & 0o7777) as u16;

    VFS.open_with_resolve(path, open_flags, perm, resolve_flags)
        .map_err(fs_error_to_syscall)
}

/// VFS stat callback for syscall registration
///
/// Called by sys_stat to get file status through VFS
fn vfs_stat_callback(path: &str) -> Result<VfsStat, SyscallError> {
    let stat = VFS.stat(path).map_err(fs_error_to_syscall)?;

    Ok(VfsStat {
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
    })
}

/// VFS lseek callback for syscall registration
///
/// Called by sys_lseek to seek within a file
/// Receives a &dyn Any reference and attempts to downcast to FileHandle
fn vfs_lseek_callback(
    file_any: &dyn core::any::Any,
    offset: i64,
    whence: i32,
) -> Result<u64, SyscallError> {
    use crate::traits::FileHandle;
    use crate::types::SeekWhence;

    // Try to downcast to FileHandle
    if let Some(file_handle) = file_any.downcast_ref::<FileHandle>() {
        let seek_whence = match whence {
            0 => SeekWhence::Set,
            1 => SeekWhence::Cur,
            2 => SeekWhence::End,
            _ => return Err(SyscallError::EINVAL),
        };

        file_handle.seek(offset, seek_whence).map_err(|e| match e {
            FsError::Seek => SyscallError::EINVAL,
            FsError::Invalid => SyscallError::EINVAL,
            _ => SyscallError::EIO,
        })
    } else {
        // Not a VFS FileHandle (e.g., pipe), seek not supported
        Err(SyscallError::EINVAL)
    }
}

/// Register VFS callbacks with kernel_core
pub fn register_syscall_callbacks() {
    kernel_core::register_vfs_open_callback(vfs_open_callback);
    kernel_core::register_vfs_open_with_resolve_callback(vfs_open_with_resolve_callback);
    kernel_core::register_vfs_stat_callback(vfs_stat_callback);
    kernel_core::register_vfs_lseek_callback(vfs_lseek_callback);
    kernel_core::register_vfs_create_callback(vfs_create_callback);
    kernel_core::register_vfs_unlink_callback(vfs_unlink_callback);
    kernel_core::register_vfs_readdir_callback(vfs_readdir_callback);
    kernel_core::register_vfs_truncate_callback(vfs_truncate_callback);
    println!("VFS syscall callbacks registered (openat2 enabled)");
}

/// VFS create callback for syscall registration
///
/// Called by sys_mkdir to create directories
fn vfs_create_callback(path: &str, mode: u32, is_dir: bool) -> Result<(), SyscallError> {
    let file_mode = if is_dir {
        FileMode::directory((mode & 0o7777) as u16)
    } else {
        FileMode::regular((mode & 0o7777) as u16)
    };

    VFS.create(path, file_mode)
        .map(|_| ())
        .map_err(fs_error_to_syscall)
}

/// VFS unlink callback for syscall registration
///
/// Called by sys_unlink/sys_rmdir to delete files/directories
fn vfs_unlink_callback(path: &str) -> Result<(), SyscallError> {
    VFS.unlink(path).map_err(fs_error_to_syscall)
}

/// VFS readdir callback for syscall registration
///
/// Called by sys_getdents64 to read directory entries
fn vfs_readdir_callback(fd: i32) -> Result<alloc::vec::Vec<kernel_core::DirEntry>, SyscallError> {
    use kernel_core::current_pid;
    use kernel_core::get_process;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Get inode and current offset from the file handle
    // FIX: Extract inode Arc and offset to release process lock before I/O
    let (inode, start_offset) = {
        let proc = proc_arc.lock();
        let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

        // Downcast to FileHandle
        let file_handle = handle
            .as_any()
            .downcast_ref::<FileHandle>()
            .ok_or(SyscallError::ENOTDIR)?;

        if !file_handle.inode.is_dir() {
            return Err(SyscallError::ENOTDIR);
        }

        // Read offset before creating tuple to avoid lifetime issues
        let offset = *file_handle.offset.lock() as usize;
        (Arc::clone(&file_handle.inode), offset)
    };
    // Process lock released here - safe for procfs operations

    // R37-4 FIX (Codex review): Add MAC check for sys_getdents64.
    let dir_stat = inode.stat().map_err(fs_error_to_syscall)?;
    if let Some(task) = LsmProcessCtx::from_current() {
        lsm::hook_file_permission(&task, dir_stat.ino, 0x05).map_err(|_| SyscallError::EACCES)?;
    }

    // Read directory entries starting from current offset
    let mut entries = Vec::new();
    let mut offset = start_offset;

    loop {
        match inode.readdir(offset) {
            Ok(Some((next, entry))) => {
                // Convert VFS DirEntry to kernel_core DirEntry
                let file_type = match entry.file_type {
                    crate::types::FileType::Regular => kernel_core::FileType::Regular,
                    crate::types::FileType::Directory => kernel_core::FileType::Directory,
                    crate::types::FileType::CharDevice => kernel_core::FileType::CharDevice,
                    crate::types::FileType::BlockDevice => kernel_core::FileType::BlockDevice,
                    crate::types::FileType::Symlink => kernel_core::FileType::Symlink,
                    crate::types::FileType::Fifo => kernel_core::FileType::Fifo,
                    crate::types::FileType::Socket => kernel_core::FileType::Socket,
                };
                entries.push(kernel_core::DirEntry {
                    name: entry.name,
                    ino: entry.ino,
                    file_type,
                });
                offset = next;
            }
            Ok(None) => break,
            Err(e) => return Err(fs_error_to_syscall(e)),
        }
    }

    // Re-acquire process lock to update the original file handle's offset
    // FIX: Update the actual fd_table entry, not a clone
    {
        let proc = proc_arc.lock();
        if let Some(handle) = proc.get_fd(fd) {
            if let Some(file_handle) = handle.as_any().downcast_ref::<FileHandle>() {
                *file_handle.offset.lock() = offset as u64;
            }
        }
    }

    Ok(entries)
}

/// VFS truncate callback for syscall registration
///
/// Called by sys_ftruncate to truncate a file
fn vfs_truncate_callback(fd: i32, length: u64) -> Result<(), SyscallError> {
    use kernel_core::current_pid;
    use kernel_core::get_process;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let proc = proc_arc.lock();

    let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

    // Downcast to FileHandle
    let file_handle = handle
        .as_any()
        .downcast_ref::<FileHandle>()
        .ok_or(SyscallError::ENOSYS)?;

    // R26-5 FIX: MAC gate for truncate operations
    // LSM policy can block file truncation
    if let Some(task) = LsmProcessCtx::from_current() {
        let stat = file_handle.inode.stat().map_err(fs_error_to_syscall)?;
        lsm::hook_file_truncate(&task, stat.ino, length).map_err(|_| SyscallError::EPERM)?;
    }

    file_handle
        .inode
        .truncate(length)
        .map_err(fs_error_to_syscall)
}
