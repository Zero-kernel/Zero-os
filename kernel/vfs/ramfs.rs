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
// R172-22: ramfs directory entries use the allocation-fallible `FallibleOrderedMap`
// (mm/fallible_map.rs) instead of `BTreeMap` — stable no_std `BTreeMap::insert` allocates a
// B-tree node infallibly on leaf-split, so OOM aborts the kernel via `handle_alloc_error`.
// `FallibleOrderedMap::try_insert` returns `Err` (-> ENOSPC) instead. Read-side API is
// method-name-compatible (get/contains_key/remove/iter/values/len/range), so only the
// inserts change. (Sibling devfs/initramfs/manager/mount_namespace children maps are the
// SAME class — tracked as R172-22-FOLLOWON, out of this ramfs-scoped fix.)
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use mm::fallible_map::FallibleOrderedMap;
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
        entries: RwLock<FallibleOrderedMap<String, Arc<RamFsInode>>>,
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
                entries: RwLock::new(FallibleOrderedMap::new()),
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
                // R172-22: build the key String FALLIBLY then fallibly insert. try_insert
                // makes only the map SLOT fallible; `name.to_string()` would allocate the
                // String key infallibly -> handle_alloc_error abort under OOM (the SAME
                // class). Mirror the rename path (key.try_reserve + push_str). A genuine grow
                // (contains_key above ruled out a replace), so the map is unchanged on Err.
                let mut key = String::new();
                key.try_reserve(name.len()).map_err(|_| FsError::NoSpace)?;
                key.push_str(name);
                entries
                    .try_insert(key, child)
                    .map_err(|_| FsError::NoSpace)?;

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

    /// Update mtime+ctime (a directory was structurally modified). M0-6 slice 2: the
    /// atomic rename path mutates the raw `entries` map directly (bypassing
    /// add_child/remove_child), so it must touch the parent dir timestamps itself.
    fn touch_mtime_ctime(&self) {
        let mut meta = self.meta.write();
        let now = TimeSpec::now();
        meta.mtime = now;
        meta.ctime = now;
    }

    /// M0-6 slice 2: borrow the raw directory `entries` lock so the atomic rename can hold
    /// a SINGLE spanning write guard across the whole transaction (the self-locking
    /// add_child/remove_child each take their own lock — a two-lock atomicity gap that
    /// allowed a half-mutation when an insert failed after a remove). Returns None for files.
    fn dir_entries(&self) -> Option<&RwLock<FallibleOrderedMap<String, Arc<RamFsInode>>>> {
        match &self.kind {
            NodeKind::Dir { entries } => Some(entries),
            NodeKind::File { .. } => None,
        }
    }
}

/// M0-6 slice 2: serialize ALL ramfs renames (Linux `s_vfs_rename_mutex` pattern). A
/// cross-parent rename of a directory victim calls `victim.child_count()` (a THIRD
/// `entries` lock outside the two-parent low-ino order) while holding both parent guards;
/// two concurrent renames could then deadlock. A single rename-serialization mutex makes
/// that impossible (only one rename ever holds parent guards), and non-rename ops take a
/// single parent lock so they cannot close a cycle against a serialized rename. Renames are
/// rare, so the coarse grain is acceptable.
static RAMFS_RENAME_LOCK: spin::Mutex<()> = spin::Mutex::new(());

/// M0-6 slice 2: under the spanning lock, bind the manager's DAC/sticky/LSM decision (made
/// on `expected_src_ino` / `expected_dest_ino`) to the inode actually moved. A concurrent
/// create/unlink could swap a name between the manager's revalidation and this lock; if the
/// identity no longer matches, fail closed (PermDenied) rather than mutate an unauthorized
/// inode.
fn verify_rename_identity(
    inode: &Arc<RamFsInode>,
    dest: &Option<Arc<RamFsInode>>,
    expected_src_ino: u64,
    expected_dest_ino: Option<u64>,
) -> Result<(), FsError> {
    if inode.ino() != expected_src_ino {
        return Err(FsError::PermDenied);
    }
    match (dest.as_ref().map(|d| d.ino()), expected_dest_ino) {
        (Some(now), Some(exp)) if now == exp => Ok(()),
        (None, None) => Ok(()),
        _ => Err(FsError::PermDenied),
    }
}

/// M0-6 slice 2: the rename commit decision, computed UNDER the spanning lock from the
/// source inode + the (optional) destination inode, so the type/emptiness/noreplace checks
/// and the move are one atomic observation (no TOCTOU between the check and the mutation).
enum RenameDecision {
    /// Source and destination are the SAME inode — nothing to do.
    NoOp,
    /// Destination is absent — plain move.
    Move,
    /// Destination exists and will be overwritten (the victim is recovered from the
    /// commit insert's return value, under the same held lock).
    Replace,
}

/// Decide the rename outcome from the source inode and the destination slot (both read
/// under the held lock). Returns an error BEFORE any mutation if the move is illegal.
fn rename_decide(
    inode: &Arc<RamFsInode>,
    inode_is_dir: bool,
    dest: Option<Arc<RamFsInode>>,
    noreplace: bool,
    old_parent: &RamFsInode,
    new_parent: &RamFsInode,
) -> Result<RenameDecision, FsError> {
    match dest {
        None => Ok(RenameDecision::Move),
        Some(existing) => {
            // R172-28 FIX: RENAME_NOREPLACE rejects ANY existing destination NAME, even the
            // same inode (Linux gates the flag in may_create/vfs_rename BEFORE the
            // source==target no-op). Hoisted ABOVE the ptr_eq no-op so a self-target
            // renameat2(RENAME_NOREPLACE) returns EEXIST, not 0.
            if noreplace {
                return Err(FsError::Exists);
            }
            // Renaming an entry onto itself (same inode) is a no-op (without NOREPLACE).
            if Arc::ptr_eq(inode, &existing) {
                return Ok(RenameDecision::NoOp);
            }
            // R172-14 FIX: the victim must never be one of the parent `entries` maps whose
            // write guard the caller already holds — `existing.child_count()` below does
            // `entries.read()`, and `spin::RwLock` is NON-reentrant, so child_count() on a
            // held-write parent SELF-DEADLOCKS while holding RAMFS_RENAME_LOCK -> system-wide
            // rename DoS. Reachable as rename("/a/sub","/a") (dest == old_parent) and the
            // symmetric forms. Overwriting one's own parent/ancestor dir is structurally
            // illegal (it would orphan/cycle the subtree) => EINVAL, fail-closed UNDER the
            // held lock with NO path-string dependence (ramfs must not trust the manager's
            // lexical guard). Pure pointer ops: no new lock, no lock-order inversion. The
            // held write guards are exactly {old_parent.entries, new_parent.entries}, so this
            // covers every inode on which child_count() could re-enter a held lock.
            let ep: *const RamFsInode = Arc::as_ptr(&existing);
            if core::ptr::eq(ep, old_parent as *const RamFsInode)
                || core::ptr::eq(ep, new_parent as *const RamFsInode)
            {
                return Err(FsError::Invalid);
            }
            if existing.is_dir() {
                // A directory may only be replaced by a directory, and only if empty.
                if !inode_is_dir {
                    return Err(FsError::IsDir);
                }
                if existing.child_count() > 0 {
                    return Err(FsError::NotEmpty);
                }
            } else if inode_is_dir {
                // A file may not be replaced by a directory.
                return Err(FsError::NotDir);
            }
            Ok(RenameDecision::Replace)
        }
    }
}

/// R172-15: does the directory `root` CONTAIN `target_ino` in its subtree (or IS it
/// `target_ino`)? Iterative DFS holding AT MOST ONE `entries` read-lock at a time
/// (snapshot-clone the child Arcs, DROP the lock, then descend) so it never lock-couples /
/// ABBAs with create/unlink (each takes a single parent write). ino-based: inos are unique
/// within the fs and never reused (`next_ino` is checked_add), so there is no ABA. Called
/// UNDER RAMFS_RENAME_LOCK (topology quiescent — only rename re-parents a directory, and
/// renames serialize on that lock) to reject moving a directory under its own subtree, which
/// would commit a mutual `Arc<RamFsInode>` cycle detached from root. Fails CLOSED to NoSpace
/// on heap exhaustion (a rename failing on genuine OOM is acceptable — never a panic, never a
/// false negative that would let the cycle through).
fn dir_subtree_contains_ino(root: &Arc<RamFsInode>, target_ino: u64) -> Result<bool, FsError> {
    if root.ino() == target_ino {
        return Ok(true);
    }
    let mut stack: alloc::vec::Vec<Arc<RamFsInode>> = alloc::vec::Vec::new();
    stack.try_reserve(1).map_err(|_| FsError::NoSpace)?;
    stack.push(root.clone());
    while let Some(node) = stack.pop() {
        // Snapshot this directory's children under a TRANSIENT read, then drop the lock before
        // descending (so at most one entries read is ever held).
        let children: alloc::vec::Vec<Arc<RamFsInode>> = match node.dir_entries() {
            Some(entries) => {
                let guard = entries.read();
                let mut v: alloc::vec::Vec<Arc<RamFsInode>> = alloc::vec::Vec::new();
                v.try_reserve(guard.len()).map_err(|_| FsError::NoSpace)?;
                for child in guard.values() {
                    v.push(child.clone());
                }
                v // guard dropped here
            }
            None => continue,
        };
        for child in children {
            if child.ino() == target_ino {
                return Ok(true);
            }
            if child.dir_entries().is_some() {
                stack.try_reserve(1).map_err(|_| FsError::NoSpace)?;
                stack.push(child);
            }
        }
    }
    Ok(false)
}

/// Post-commit nlink / timestamp fixups (separate `meta` locks; run AFTER the spanning
/// `entries` guard(s) are released — lock order is always entries -> meta).
fn rename_apply_accounting(
    old_parent: &RamFsInode,
    new_parent: &RamFsInode,
    inode: &Arc<RamFsInode>,
    inode_is_dir: bool,
    victim: &Option<Arc<RamFsInode>>,
    same_parent: bool,
) {
    if let Some(victim) = victim {
        // An evicted directory removes its `..` link from the (new) parent.
        if victim.is_dir() {
            new_parent.dec_nlink();
        }
        victim.dec_nlink();
    }
    // A directory moved across parents re-homes its `..` link.
    if inode_is_dir && !same_parent {
        old_parent.dec_nlink();
        new_parent.inc_nlink();
    }
    inode.touch_ctime();
    old_parent.touch_mtime_ctime();
    if !same_parent {
        new_parent.touch_mtime_ctime();
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
        noreplace: bool,
        expected_src_ino: u64,
        expected_dest_ino: Option<u64>,
    ) -> Result<(), FsError> {
        let old_parent = self.downcast_inode(old_parent)?;
        let new_parent = self.downcast_inode(new_parent)?;

        // Both ends must be directories.
        if !old_parent.is_dir() || !new_parent.is_dir() {
            return Err(FsError::NotDir);
        }
        // '.'/'..' are never valid rename operands (defense-in-depth; the real
        // trailing-dot case is rejected at the manager BEFORE normalize_path collapses it).
        if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
            return Err(FsError::Invalid);
        }
        // Pre-validate new_name against add_child's rules so the commit insert can never
        // fail on name grounds (the insert is the only would-be-fallible commit step).
        if new_name.is_empty() || new_name.len() > 255 || new_name.contains('/') {
            return Err(FsError::NameTooLong);
        }
        // Reserve the key allocation up front, FALLIBLY — an OOM here returns NoSpace and
        // is a no-op (nothing has been mutated yet), never a panic, never a half-mutation.
        let mut key = String::new();
        key.try_reserve(new_name.len())
            .map_err(|_| FsError::NoSpace)?;
        key.push_str(new_name);

        let old_entries = old_parent.dir_entries().ok_or(FsError::NotDir)?;
        let new_entries = new_parent.dir_entries().ok_or(FsError::NotDir)?;
        let same_parent = core::ptr::eq(old_parent, new_parent);
        debug_assert!(
            same_parent || old_parent.ino() != new_parent.ino(),
            "distinct ramfs parents must have distinct inode numbers"
        );

        // Serialize all renames so the victim-dir `child_count()` lock (a third `entries`
        // lock taken inside the spanning section) can never deadlock against a concurrent
        // rename. Held for the whole transaction; released on return.
        let _rename_guard = RAMFS_RENAME_LOCK.lock();

        // R172-15 FIX: under RAMFS_RENAME_LOCK (topology now quiescent — only rename
        // re-parents a directory and renames serialize on this lock; create/mkdir mint fresh
        // inodes, unlink only removes, and there is no directory-hardlink op, so no non-rename
        // mutation can change directory ancestry), reject moving a DIRECTORY under its own
        // subtree (new_parent == source or a descendant of source). Committing that grafts a
        // mutual Arc<RamFsInode> cycle detached from root -> permanent subtree/data loss +
        // kernel-heap exhaustion via repeated cyclic renames. The manager's lexical guard
        // (manager.rs) is a path-string FAST-PATH that RACES two concurrent disjoint-subtree
        // renames against the original topology; this inode-identity walk UNDER the lock is the
        // authoritative check. Resolve the source transiently (its read-locks are all released
        // before the commit's write guards below, so no lock-coupling) for the cross-parent
        // directory case only (same-parent rename cannot change ancestry).
        if !same_parent {
            if let Ok(src) = old_parent.lookup_child(old_name) {
                if src.dir_entries().is_some() && dir_subtree_contains_ino(&src, new_parent.ino())?
                {
                    return Err(FsError::Invalid);
                }
            }
        }

        // === Spanning critical section: decide + commit atomically ===
        // Order is INSERT-NEW (overwrites any victim, returns it) then REMOVE-OLD: no
        // destructive step precedes the successful insert and no fallible step follows it,
        // so the move is all-or-nothing by construction. This closes the half-mutation bug
        // where the old code removed the source (and the victim) BEFORE the add, losing the
        // entry from both parents if the add raced an Exists. All mutation-deciding reads
        // happen UNDER the held guard(s) (closes the check-vs-move TOCTOU).
        let (inode, inode_is_dir, victim) = if same_parent {
            let mut g = old_entries.write();
            let inode = g.get(old_name).cloned().ok_or(FsError::NotFound)?;
            let inode_is_dir = inode.is_dir();
            let dest = g.get(new_name).cloned();
            verify_rename_identity(&inode, &dest, expected_src_ino, expected_dest_ino)?;
            match rename_decide(
                &inode,
                inode_is_dir,
                dest,
                noreplace,
                old_parent,
                new_parent,
            )? {
                RenameDecision::NoOp => return Ok(()),
                RenameDecision::Move => {
                    // R172-22: fallible insert FIRST (the only allocating/fallible step) —
                    // on OOM the map is UNCHANGED (try_insert reserves-before-mutate) and we
                    // return NoSpace before the remove, so the source survives in this parent
                    // (all-or-nothing). new_name is pre-validated absent -> Ok(None).
                    g.try_insert(key, inode.clone())
                        .map_err(|_| FsError::NoSpace)?;
                    g.remove(old_name);
                    (inode, inode_is_dir, None)
                }
                RenameDecision::Replace => {
                    // R172-22: dest exists -> try_insert is an in-place mem::replace with NO
                    // allocation, returning Ok(Some(victim)); the .map_err arm is dead but
                    // required for type-correctness. After `?`, victim is Option<V> directly.
                    let victim = g
                        .try_insert(key, inode.clone())
                        .map_err(|_| FsError::NoSpace)?;
                    g.remove(old_name);
                    (inode, inode_is_dir, victim)
                }
            }
        } else {
            // Acquire BOTH guards low-ino-first (ABBA-safe; ino is unique within the fs).
            let (mut og, mut ng) = if old_parent.ino() < new_parent.ino() {
                let og = old_entries.write();
                let ng = new_entries.write();
                (og, ng)
            } else {
                let ng = new_entries.write();
                let og = old_entries.write();
                (og, ng)
            };
            let inode = og.get(old_name).cloned().ok_or(FsError::NotFound)?;
            let inode_is_dir = inode.is_dir();
            let dest = ng.get(new_name).cloned();
            verify_rename_identity(&inode, &dest, expected_src_ino, expected_dest_ino)?;
            match rename_decide(
                &inode,
                inode_is_dir,
                dest,
                noreplace,
                old_parent,
                new_parent,
            )? {
                RenameDecision::NoOp => return Ok(()),
                RenameDecision::Move => {
                    // R172-22: fallible insert into the NEW parent FIRST; on OOM the map is
                    // unchanged and we return NoSpace before removing from the old parent
                    // (all-or-nothing; the source survives in og).
                    ng.try_insert(key, inode.clone())
                        .map_err(|_| FsError::NoSpace)?;
                    og.remove(old_name);
                    (inode, inode_is_dir, None)
                }
                RenameDecision::Replace => {
                    // R172-22: dest exists -> in-place replace, no allocation; after `?`,
                    // victim is Option<V>.
                    let victim = ng
                        .try_insert(key, inode.clone())
                        .map_err(|_| FsError::NoSpace)?;
                    og.remove(old_name);
                    (inode, inode_is_dir, victim)
                }
            }
        };
        // Guards released here -> nlink/timestamp fixups take only `meta` locks (entries
        // -> meta is the established lock order, so no inversion).
        rename_apply_accounting(
            old_parent,
            new_parent,
            &inode,
            inode_is_dir,
            &victim,
            same_parent,
        );
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
