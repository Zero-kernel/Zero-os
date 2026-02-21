//! RAM Filesystem (RamFS)
//!
//! In-memory filesystem for temporary storage and boot files.
//! Supports file and directory creation, reading, writing, and deletion.
//!
//! # Resource Limits (V-3 fix)
//!
//! - MAX_FILE_SIZE: Maximum size of a single file (16 MiB)
//! - MAX_TOTAL_BYTES: Maximum total bytes across all ramfs instances (64 MiB)
//!
//! These limits prevent memory exhaustion DoS attacks.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use kernel_core::{current_credentials, FileOps};

/// Global filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(100);

/// V-3 fix: Maximum allowed file size in ramfs (bytes)
///
/// Prevents memory exhaustion DoS by limiting individual file sizes.
/// 16 MiB is sufficient for typical boot files and temporary data while
/// protecting against unbounded kernel heap allocation.
const MAX_FILE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Global quota: Maximum total bytes allowed across all ramfs instances
///
/// Provides defense-in-depth against memory exhaustion by limiting
/// the combined size of all files in all ramfs mounts.
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Global counter tracking total bytes used by all ramfs instances
static TOTAL_BYTES_USED: AtomicUsize = AtomicUsize::new(0);

/// Try to allocate bytes from the global quota
///
/// Returns true if allocation succeeded, false if would exceed quota.
fn quota_try_alloc(bytes: usize) -> bool {
    let mut current = TOTAL_BYTES_USED.load(Ordering::SeqCst);
    loop {
        let new_total = match current.checked_add(bytes) {
            Some(t) => t,
            None => return false, // overflow
        };
        if new_total > MAX_TOTAL_BYTES {
            return false; // would exceed quota
        }
        match TOTAL_BYTES_USED.compare_exchange_weak(
            current,
            new_total,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Release bytes back to the global quota
fn quota_release(bytes: usize) {
    // Use fetch_update for atomic saturating subtraction to avoid race conditions
    let _ = TOTAL_BYTES_USED.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
        Some(current.saturating_sub(bytes))
    });
}

/// Get current total bytes used by ramfs
#[allow(dead_code)]
pub fn ramfs_bytes_used() -> usize {
    TOTAL_BYTES_USED.load(Ordering::SeqCst)
}

/// Get maximum allowed bytes for ramfs
#[allow(dead_code)]
pub fn ramfs_max_bytes() -> usize {
    MAX_TOTAL_BYTES
}

/// Inode metadata
struct Meta {
    mode: FileMode,
    nlink: u32,
    size: u64,
    uid: u32,
    gid: u32,
    atime: TimeSpec,
    mtime: TimeSpec,
    ctime: TimeSpec,
}

impl Meta {
    fn new(mode: FileMode, uid: u32, gid: u32) -> Self {
        let now = TimeSpec::now();
        let initial_nlink = if mode.is_dir() { 2 } else { 1 };
        Self {
            mode,
            nlink: initial_nlink,
            size: 0,
            uid,
            gid,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

/// Node kind: file or directory
enum NodeKind {
    /// Regular file with data buffer
    File { data: RwLock<Vec<u8>> },
    /// Directory with child entries
    Dir {
        entries: RwLock<BTreeMap<String, Arc<RamFsInode>>>,
    },
}

/// RAM filesystem inode
pub struct RamFsInode {
    fs_id: u64,
    ino: u64,
    meta: RwLock<Meta>,
    kind: NodeKind,
    /// Weak self-reference for FileHandle creation
    self_ref: RwLock<Option<Weak<RamFsInode>>>,
}

impl RamFsInode {
    /// Create a new directory inode
    pub fn new_dir(fs_id: u64, ino: u64, perm: u16, uid: u32, gid: u32) -> Arc<Self> {
        let mode = FileMode::directory(perm);
        let inode = Arc::new(Self {
            fs_id,
            ino,
            meta: RwLock::new(Meta::new(mode, uid, gid)),
            kind: NodeKind::Dir {
                entries: RwLock::new(BTreeMap::new()),
            },
            self_ref: RwLock::new(None),
        });
        // Store weak self-reference
        *inode.self_ref.write() = Some(Arc::downgrade(&inode));
        inode
    }

    /// Create a new file inode
    pub fn new_file(fs_id: u64, ino: u64, perm: u16, uid: u32, gid: u32) -> Arc<Self> {
        let mode = FileMode::regular(perm);
        let inode = Arc::new(Self {
            fs_id,
            ino,
            meta: RwLock::new(Meta::new(mode, uid, gid)),
            kind: NodeKind::File {
                data: RwLock::new(Vec::new()),
            },
            self_ref: RwLock::new(None),
        });
        // Store weak self-reference
        *inode.self_ref.write() = Some(Arc::downgrade(&inode));
        inode
    }

    /// Get Arc<Self> from weak reference
    fn as_arc(&self) -> Result<Arc<Self>, FsError> {
        self.self_ref
            .read()
            .as_ref()
            .and_then(|w| w.upgrade())
            .ok_or(FsError::Invalid)
    }

    /// Look up a child entry in directory
    fn lookup_child(&self, name: &str) -> Result<Arc<RamFsInode>, FsError> {
        match &self.kind {
            NodeKind::Dir { entries } => entries.read().get(name).cloned().ok_or(FsError::NotFound),
            NodeKind::File { .. } => Err(FsError::NotDir),
        }
    }

    /// Add a child entry to directory
    fn add_child(&self, name: &str, child: Arc<RamFsInode>) -> Result<(), FsError> {
        // Validate name
        if name.is_empty() || name.len() > 255 || name.contains('/') {
            return Err(FsError::NameTooLong);
        }
        if name == "." || name == ".." {
            return Err(FsError::Invalid);
        }

        match &self.kind {
            NodeKind::Dir { entries } => {
                let mut entries = entries.write();
                if entries.contains_key(name) {
                    return Err(FsError::Exists);
                }
                entries.insert(name.to_string(), child);

                // Update parent directory timestamps
                let mut meta = self.meta.write();
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(())
            }
            NodeKind::File { .. } => Err(FsError::NotDir),
        }
    }

    /// Remove a child entry from directory
    fn remove_child(&self, name: &str) -> Result<Arc<RamFsInode>, FsError> {
        if name == "." || name == ".." {
            return Err(FsError::Invalid);
        }

        match &self.kind {
            NodeKind::Dir { entries } => {
                let mut entries = entries.write();
                let child = entries.remove(name).ok_or(FsError::NotFound)?;

                // Update parent directory timestamps
                let mut meta = self.meta.write();
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(child)
            }
            NodeKind::File { .. } => Err(FsError::NotDir),
        }
    }

    /// Get directory entry count
    fn child_count(&self) -> usize {
        match &self.kind {
            NodeKind::Dir { entries } => entries.read().len(),
            NodeKind::File { .. } => 0,
        }
    }

    /// Increment link count
    fn inc_nlink(&self) {
        let mut meta = self.meta.write();
        meta.nlink += 1;
        meta.ctime = TimeSpec::now();
    }

    /// Decrement link count
    fn dec_nlink(&self) {
        let mut meta = self.meta.write();
        if meta.nlink > 0 {
            meta.nlink -= 1;
        }
        meta.ctime = TimeSpec::now();
    }

    /// Update ctime without changing other metadata
    fn touch_ctime(&self) {
        self.meta.write().ctime = TimeSpec::now();
    }
}

/// Release quota when file inode is dropped
impl Drop for RamFsInode {
    fn drop(&mut self) {
        // Release quota for file data when inode is freed
        if let NodeKind::File { data } = &self.kind {
            let data = data.read();
            if !data.is_empty() {
                quota_release(data.len());
            }
        }
    }
}

impl Inode for RamFsInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let meta = self.meta.read();
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: meta.mode,
            nlink: meta.nlink,
            uid: meta.uid,
            gid: meta.gid,
            rdev: 0,
            size: meta.size,
            blksize: 4096,
            blocks: (meta.size + 511) / 512,
            atime: meta.atime,
            mtime: meta.mtime,
            ctime: meta.ctime,
        })
    }

    fn open(&self, flags: OpenFlags) -> Result<Box<dyn FileOps>, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if matches!(self.kind, NodeKind::Dir { .. }) {
            if flags.is_writable() {
                return Err(FsError::IsDir);
            }
            // Return directory handle with seekable=false
            let inode_arc = self.as_arc()?;
            return Ok(Box::new(FileHandle::new(inode_arc, flags, false)));
        }

        let inode_arc = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode_arc, flags, true)))
    }

    fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Dir { .. })
    }

    fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        match &self.kind {
            NodeKind::Dir { entries } => {
                let entries = entries.read();

                // Handle "." and ".." at offsets 0 and 1
                if offset == 0 {
                    return Ok(Some((
                        1,
                        DirEntry {
                            name: ".".to_string(),
                            ino: self.ino,
                            file_type: FileType::Directory,
                        },
                    )));
                }
                if offset == 1 {
                    // ".." points to self for root, otherwise would need parent reference
                    return Ok(Some((
                        2,
                        DirEntry {
                            name: "..".to_string(),
                            ino: self.ino,
                            file_type: FileType::Directory,
                        },
                    )));
                }

                // Real entries start at offset 2
                let real_offset = offset - 2;
                let entry = entries.iter().nth(real_offset);

                match entry {
                    Some((name, inode)) => {
                        let file_type = if inode.is_dir() {
                            FileType::Directory
                        } else {
                            FileType::Regular
                        };
                        Ok(Some((
                            offset + 1,
                            DirEntry {
                                name: name.clone(),
                                ino: inode.ino,
                                file_type,
                            },
                        )))
                    }
                    None => Ok(None),
                }
            }
            NodeKind::File { .. } => Err(FsError::NotDir),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        match &self.kind {
            NodeKind::File { data } => {
                let data = data.read();
                let offset = usize::try_from(offset).map_err(|_| FsError::Invalid)?;

                if offset >= data.len() {
                    return Ok(0); // EOF
                }

                let available = data.len() - offset;
                let to_read = buf.len().min(available);
                buf[..to_read].copy_from_slice(&data[offset..offset + to_read]);

                // Update atime (optional, can be skipped for performance)
                // self.meta.write().atime = TimeSpec::now();

                Ok(to_read)
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
        }
    }

    fn write_at(&self, offset: u64, data_in: &[u8]) -> Result<usize, FsError> {
        match &self.kind {
            NodeKind::File { data } => {
                let mut data = data.write();
                let offset = usize::try_from(offset).map_err(|_| FsError::Invalid)?;
                let current_len = data.len();

                // Expand file if needed (with checked addition)
                let required_len = offset.checked_add(data_in.len()).ok_or(FsError::Invalid)?;

                // V-3 fix: Enforce maximum file size to prevent memory exhaustion DoS
                if required_len > MAX_FILE_SIZE {
                    return Err(FsError::NoSpace);
                }

                // Check global quota for new bytes needed
                if required_len > current_len {
                    let additional_bytes = required_len - current_len;
                    if !quota_try_alloc(additional_bytes) {
                        return Err(FsError::NoSpace);
                    }
                    data.resize(required_len, 0);
                }

                // Write data
                data[offset..offset + data_in.len()].copy_from_slice(data_in);

                // Update metadata
                let mut meta = self.meta.write();
                meta.size = data.len() as u64;
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(data_in.len())
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
        }
    }

    fn truncate(&self, len: u64) -> Result<(), FsError> {
        match &self.kind {
            NodeKind::File { data } => {
                let new_len = usize::try_from(len).map_err(|_| FsError::Invalid)?;

                // V-3 fix: Enforce maximum file size to prevent memory exhaustion DoS
                if new_len > MAX_FILE_SIZE {
                    return Err(FsError::NoSpace);
                }

                let mut data = data.write();
                let current_len = data.len();

                // Handle quota for expansion or shrinking
                if new_len > current_len {
                    // Expanding: try to allocate additional bytes
                    let additional_bytes = new_len - current_len;
                    if !quota_try_alloc(additional_bytes) {
                        return Err(FsError::NoSpace);
                    }
                } else if new_len < current_len {
                    // Shrinking: release bytes back to quota
                    let freed_bytes = current_len - new_len;
                    quota_release(freed_bytes);
                }

                data.resize(new_len, 0);

                // Update metadata
                let mut meta = self.meta.write();
                meta.size = len;
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(())
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// RAM filesystem
pub struct RamFs {
    fs_id: u64,
    root: Arc<RamFsInode>,
    next_ino: AtomicU64,
}

impl RamFs {
    /// Create a new RAM filesystem
    pub fn new() -> Arc<Self> {
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("ramfs: NEXT_FS_ID overflow");
        // Root directory is owned by root (uid=0, gid=0)
        let root = RamFsInode::new_dir(fs_id, 1, 0o755, 0, 0);

        Arc::new(Self {
            fs_id,
            root,
            next_ino: AtomicU64::new(2),
        })
    }

    /// Allocate a new inode number (R112-2: overflow-safe)
    fn alloc_ino(&self) -> u64 {
        self.next_ino
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("ramfs: next_ino overflow")
    }

    /// Downcast an Inode to RamFsInode
    fn downcast_inode<'a>(&self, inode: &'a Arc<dyn Inode>) -> Result<&'a RamFsInode, FsError> {
        inode
            .as_any()
            .downcast_ref::<RamFsInode>()
            .ok_or(FsError::Invalid)
    }
}

impl FileSystem for RamFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "ramfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast_inode(parent)?;
        let child = parent.lookup_child(name)?;
        Ok(child as Arc<dyn Inode>)
    }

    fn create(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast_inode(parent)?;

        // Check if parent is a directory
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // Allocate inode number
        let ino = self.alloc_ino();

        // Get current process credentials for file ownership
        // New files are owned by the effective uid of the creating process
        let creds = current_credentials();
        let uid = creds.as_ref().map(|c| c.euid).unwrap_or(0);

        // For gid: respect setgid bit on parent directory
        // If parent has setgid (mode 02000), new files inherit parent's gid
        // Otherwise, use creating process's effective gid
        let parent_meta = parent.meta.read();
        let gid = if parent_meta.mode.perm & 0o2000 != 0 {
            // Setgid directory: inherit parent's gid
            parent_meta.gid
        } else {
            // Normal: use creator's egid
            creds.as_ref().map(|c| c.egid).unwrap_or(0)
        };
        drop(parent_meta);

        // For directories in setgid parents, also set the setgid bit
        let final_perm = if mode.is_dir() {
            let parent_meta = parent.meta.read();
            if parent_meta.mode.perm & 0o2000 != 0 {
                mode.perm | 0o2000 // Propagate setgid bit to subdirectories
            } else {
                mode.perm
            }
        } else {
            mode.perm
        };

        // Create new inode based on type
        let new_inode = if mode.is_dir() {
            RamFsInode::new_dir(self.fs_id, ino, final_perm, uid, gid)
        } else {
            RamFsInode::new_file(self.fs_id, ino, final_perm, uid, gid)
        };

        // Add to parent directory
        parent.add_child(name, new_inode.clone())?;

        // If creating a directory, increment parent's nlink
        if mode.is_dir() {
            parent.inc_nlink();
        }

        Ok(new_inode as Arc<dyn Inode>)
    }

    fn unlink(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<(), FsError> {
        let parent = self.downcast_inode(parent)?;

        // Check if parent is a directory
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // Look up the child first to check if it's a non-empty directory
        let child = parent.lookup_child(name)?;

        // If it's a directory, it must be empty
        if child.is_dir() && child.child_count() > 0 {
            return Err(FsError::NotEmpty);
        }

        // Remove from parent
        let removed = parent.remove_child(name)?;

        // If removing a directory, decrement parent's nlink
        if removed.is_dir() {
            parent.dec_nlink();
        }

        // Decrement the removed inode's nlink
        removed.dec_nlink();

        Ok(())
    }

    fn rename(
        &self,
        old_parent: &Arc<dyn Inode>,
        old_name: &str,
        new_parent: &Arc<dyn Inode>,
        new_name: &str,
    ) -> Result<(), FsError> {
        let old_parent = self.downcast_inode(old_parent)?;
        let new_parent = self.downcast_inode(new_parent)?;

        // Ensure both parents are directories
        if !old_parent.is_dir() || !new_parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // Get the inode to be moved
        let inode = old_parent.lookup_child(old_name)?;
        let inode_is_dir = inode.is_dir();

        // Check if destination exists
        if let Ok(existing) = new_parent.lookup_child(new_name) {
            // If moving to itself, do nothing
            if Arc::ptr_eq(&inode, &existing) {
                return Ok(());
            }

            // If existing is a directory, it must be empty
            if existing.is_dir() {
                if existing.child_count() > 0 {
                    return Err(FsError::NotEmpty);
                }
                // Type mismatch: can't replace dir with file or vice versa
                if !inode_is_dir {
                    return Err(FsError::IsDir);
                }
            } else if inode_is_dir {
                return Err(FsError::NotDir);
            }

            // Remove existing entry and decrement its nlink
            let removed = new_parent.remove_child(new_name)?;
            if existing.is_dir() {
                new_parent.dec_nlink();
            }
            removed.dec_nlink();
        }

        // Remove from old parent
        old_parent.remove_child(old_name)?;

        // Add to new parent
        new_parent.add_child(new_name, inode.clone())?;

        // Update nlink if directory and parents are different
        if inode_is_dir && !core::ptr::eq(old_parent, new_parent) {
            old_parent.dec_nlink();
            new_parent.inc_nlink();
        }

        // Rename is a metadata change
        inode.touch_ctime();

        Ok(())
    }
}

impl Default for RamFs {
    fn default() -> Self {
        // This creates a non-Arc version for internal use
        // R112-2: overflow-safe ID allocation
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("ramfs: NEXT_FS_ID overflow");
        // Root directory is owned by root (uid=0, gid=0)
        let root = RamFsInode::new_dir(fs_id, 1, 0o755, 0, 0);

        Self {
            fs_id,
            root,
            next_ino: AtomicU64::new(2),
        }
    }
}
