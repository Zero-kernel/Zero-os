//! Initramfs (CPIO "newc") read-only filesystem
//!
//! - Parses an in-memory CPIO newc archive (070701 magic)
//! - Builds a tree of files, directories, and symlinks
//! - Implements FileSystem/Inode; all mutating ops return ReadOnly

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::traits::{FileHandle, FileSystem, Inode};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use kernel_core::FileOps;

/// CPIO "newc" magic number
const CPIO_MAGIC: &[u8; 6] = b"070701";
/// CPIO header length (fixed 110 bytes)
const CPIO_HEADER_LEN: usize = 110;
/// Start of generated inode numbers (for implicit directories)
const GENERATED_INO_START: u64 = 1 << 32;
/// R28-9 Fix: Maximum per-file size from initramfs to prevent OOM during boot
const MAX_INITRAMFS_FILE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Next filesystem ID
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(400);
/// Next generated inode number
static NEXT_GENERATED_INO: AtomicU64 = AtomicU64::new(GENERATED_INO_START);

// ============================================================================
// CPIO Header Parsing
// ============================================================================

/// Parsed CPIO header
#[derive(Debug, Clone, Copy)]
struct CpioHeader {
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    filesize: u32,
    #[allow(dead_code)]
    devmajor: u32,
    #[allow(dead_code)]
    devminor: u32,
    #[allow(dead_code)]
    rdevmajor: u32,
    #[allow(dead_code)]
    rdevminor: u32,
    namesize: u32,
    #[allow(dead_code)]
    check: u32,
}

/// Parse an 8-character hex field
fn parse_hex_u32(field: &[u8]) -> Result<u32, FsError> {
    let s = core::str::from_utf8(field).map_err(|_| FsError::Invalid)?;
    u32::from_str_radix(s, 16).map_err(|_| FsError::Invalid)
}

/// Parse a CPIO newc header from raw bytes
fn parse_header(raw: &[u8]) -> Result<CpioHeader, FsError> {
    if raw.len() < CPIO_HEADER_LEN {
        return Err(FsError::Invalid);
    }
    if &raw[..6] != CPIO_MAGIC {
        return Err(FsError::Invalid);
    }

    let mut pos = 6;
    let mut next = |pos: &mut usize| -> Result<u32, FsError> {
        let end = *pos + 8;
        let val = parse_hex_u32(&raw[*pos..end])?;
        *pos = end;
        Ok(val)
    };

    Ok(CpioHeader {
        ino: next(&mut pos)? as u64,
        mode: next(&mut pos)?,
        uid: next(&mut pos)?,
        gid: next(&mut pos)?,
        nlink: next(&mut pos)?,
        mtime: next(&mut pos)?,
        filesize: next(&mut pos)?,
        devmajor: next(&mut pos)?,
        devminor: next(&mut pos)?,
        rdevmajor: next(&mut pos)?,
        rdevminor: next(&mut pos)?,
        namesize: next(&mut pos)?,
        check: next(&mut pos)?,
    })
}

/// Align offset to 4-byte boundary
fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// Convert CPIO mode to FileType
fn file_type_from_mode(mode: u32) -> Option<FileType> {
    match mode & 0o170000 {
        0o010000 => Some(FileType::Fifo),
        0o020000 => Some(FileType::CharDevice),
        0o040000 => Some(FileType::Directory),
        0o060000 => Some(FileType::BlockDevice),
        0o100000 => Some(FileType::Regular),
        0o120000 => Some(FileType::Symlink),
        0o140000 => Some(FileType::Socket),
        _ => None,
    }
}

/// Allocate a new generated inode number
fn alloc_generated_ino() -> u64 {
    NEXT_GENERATED_INO.fetch_add(1, Ordering::SeqCst)
}

// ============================================================================
// Initramfs Filesystem
// ============================================================================

/// In-memory initramfs loaded from a CPIO archive
pub struct Initramfs {
    fs_id: u64,
    root: Arc<InitramfsInode>,
}

impl Initramfs {
    /// Parse a CPIO "newc" archive from a memory buffer
    pub fn from_cpio(buf: &[u8]) -> Result<Arc<Self>, FsError> {
        let fs_id = NEXT_FS_ID.fetch_add(1, Ordering::SeqCst);
        let now = TimeSpec::now();

        // Create root directory with a generated ino to avoid colliding with archive inodes
        let root = InitramfsInode::new_dir(
            fs_id,
            alloc_generated_ino(),
            FileMode::directory(0o755),
            2,
            0,
            0,
            now,
        );

        // Track inodes by their original inode number for hardlink support
        let mut inode_by_ino: BTreeMap<u64, Arc<InitramfsInode>> = BTreeMap::new();
        inode_by_ino.insert(root.ino, root.clone());

        let mut offset = 0usize;

        while offset + CPIO_HEADER_LEN <= buf.len() {
            let header = parse_header(&buf[offset..offset + CPIO_HEADER_LEN])?;
            offset += CPIO_HEADER_LEN;

            let name_len = usize::try_from(header.namesize).map_err(|_| FsError::Invalid)?;
            let name_end = offset.checked_add(name_len).ok_or(FsError::Invalid)?;
            if name_len == 0 || name_end > buf.len() {
                return Err(FsError::Invalid);
            }

            let name_bytes = &buf[offset..name_end];
            offset = align4(name_end);

            // Strip trailing NUL and normalize path
            let trimmed = if let Some((&last, rest)) = name_bytes.split_last() {
                if last == 0 {
                    rest
                } else {
                    name_bytes
                }
            } else {
                name_bytes
            };
            let mut name = core::str::from_utf8(trimmed).map_err(|_| FsError::Invalid)?;

            // Strip leading "./" if present
            if let Some(stripped) = name.strip_prefix("./") {
                name = stripped;
            }
            let name = name.trim_matches('/');

            // Check for end-of-archive marker
            if name == "TRAILER!!!" {
                break;
            }

            // Skip empty or root entries
            if name.is_empty() || name == "." {
                offset = align4(offset);
                continue;
            }

            // Read file data
            let data_len = usize::try_from(header.filesize).map_err(|_| FsError::Invalid)?;
            // R28-9 Fix: Reject files larger than MAX_INITRAMFS_FILE_SIZE to prevent OOM
            if data_len > MAX_INITRAMFS_FILE_SIZE {
                return Err(FsError::Invalid);
            }
            let data_end = offset.checked_add(data_len).ok_or(FsError::Invalid)?;
            if data_end > buf.len() {
                return Err(FsError::Invalid);
            }
            let data = &buf[offset..data_end];
            offset = align4(data_end);

            // Determine file type
            let file_type = file_type_from_mode(header.mode).ok_or(FsError::Invalid)?;

            // Only support regular files, directories, and symlinks
            if !matches!(
                file_type,
                FileType::Regular | FileType::Directory | FileType::Symlink
            ) {
                // Skip unsupported entry types (char/block devices, fifos, sockets)
                continue;
            }

            // Check for hardlink (same inode number seen before)
            let inode = if let Some(existing) = inode_by_ino.get(&header.ino) {
                existing.clone()
            } else {
                let mode = FileMode::new(file_type, (header.mode & 0o7777) as u16);
                let mtime = TimeSpec::new(header.mtime as i64, 0);
                let nlink = core::cmp::max(header.nlink, 1);

                let inode = match file_type {
                    FileType::Directory => InitramfsInode::new_dir(
                        fs_id,
                        header.ino,
                        mode,
                        core::cmp::max(nlink, 2),
                        header.uid,
                        header.gid,
                        mtime,
                    ),
                    FileType::Regular => InitramfsInode::new_file(
                        fs_id, header.ino, mode, nlink, header.uid, header.gid, mtime, data,
                    ),
                    FileType::Symlink => InitramfsInode::new_symlink(
                        fs_id, header.ino, mode, nlink, header.uid, header.gid, mtime, data,
                    ),
                    _ => unreachable!(),
                };
                inode_by_ino.insert(header.ino, inode.clone());
                inode
            };

            // Attach to directory tree
            attach_node(&root, name, inode)?;
        }

        Ok(Arc::new(Self { fs_id, root }))
    }

    /// Downcast a generic Inode to InitramfsInode
    fn downcast<'a>(&self, inode: &'a Arc<dyn Inode>) -> Result<&'a InitramfsInode, FsError> {
        inode
            .as_any()
            .downcast_ref::<InitramfsInode>()
            .ok_or(FsError::Invalid)
    }
}

impl FileSystem for Initramfs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "initramfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast(parent)?;
        let child = parent.lookup_child(name)?;
        Ok(child)
    }

    fn create(
        &self,
        _parent: &Arc<dyn Inode>,
        _name: &str,
        _mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        Err(FsError::ReadOnly)
    }

    fn unlink(&self, _parent: &Arc<dyn Inode>, _name: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn rename(
        &self,
        _old_parent: &Arc<dyn Inode>,
        _old_name: &str,
        _new_parent: &Arc<dyn Inode>,
        _new_name: &str,
    ) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }
}

// ============================================================================
// Initramfs Inode
// ============================================================================

/// Inode metadata
struct NodeMeta {
    mode: FileMode,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime: TimeSpec,
    mtime: TimeSpec,
    ctime: TimeSpec,
}

/// Inode content type
enum NodeKind {
    Directory {
        children: RwLock<BTreeMap<String, Arc<InitramfsInode>>>,
    },
    File {
        data: Arc<[u8]>,
    },
    Symlink {
        target: Arc<[u8]>,
    },
}

/// Initramfs inode
pub struct InitramfsInode {
    fs_id: u64,
    ino: u64,
    meta: RwLock<NodeMeta>,
    kind: NodeKind,
    self_ref: RwLock<Option<Weak<InitramfsInode>>>,
}

impl InitramfsInode {
    /// Create a new directory inode
    fn new_dir(
        fs_id: u64,
        ino: u64,
        mode: FileMode,
        nlink: u32,
        uid: u32,
        gid: u32,
        mtime: TimeSpec,
    ) -> Arc<Self> {
        let inode = Arc::new(Self {
            fs_id,
            ino,
            meta: RwLock::new(NodeMeta {
                mode,
                nlink,
                uid,
                gid,
                size: 0,
                atime: mtime,
                mtime,
                ctime: mtime,
            }),
            kind: NodeKind::Directory {
                children: RwLock::new(BTreeMap::new()),
            },
            self_ref: RwLock::new(None),
        });
        *inode.self_ref.write() = Some(Arc::downgrade(&inode));
        inode
    }

    /// Create a new regular file inode
    fn new_file(
        fs_id: u64,
        ino: u64,
        mode: FileMode,
        nlink: u32,
        uid: u32,
        gid: u32,
        mtime: TimeSpec,
        data: &[u8],
    ) -> Arc<Self> {
        let buf: Arc<[u8]> = data.to_vec().into();
        let size = buf.len() as u64;
        let inode = Arc::new(Self {
            fs_id,
            ino,
            meta: RwLock::new(NodeMeta {
                mode,
                nlink,
                uid,
                gid,
                size,
                atime: mtime,
                mtime,
                ctime: mtime,
            }),
            kind: NodeKind::File { data: buf },
            self_ref: RwLock::new(None),
        });
        *inode.self_ref.write() = Some(Arc::downgrade(&inode));
        inode
    }

    /// Create a new symlink inode
    fn new_symlink(
        fs_id: u64,
        ino: u64,
        mode: FileMode,
        nlink: u32,
        uid: u32,
        gid: u32,
        mtime: TimeSpec,
        data: &[u8],
    ) -> Arc<Self> {
        let target: Arc<[u8]> = data.to_vec().into();
        let size = target.len() as u64;
        let inode = Arc::new(Self {
            fs_id,
            ino,
            meta: RwLock::new(NodeMeta {
                mode,
                nlink,
                uid,
                gid,
                size,
                atime: mtime,
                mtime,
                ctime: mtime,
            }),
            kind: NodeKind::Symlink { target },
            self_ref: RwLock::new(None),
        });
        *inode.self_ref.write() = Some(Arc::downgrade(&inode));
        inode
    }

    /// Look up a child by name
    fn lookup_child(&self, name: &str) -> Result<Arc<InitramfsInode>, FsError> {
        match &self.kind {
            NodeKind::Directory { children } => {
                children.read().get(name).cloned().ok_or(FsError::NotFound)
            }
            _ => Err(FsError::NotDir),
        }
    }

    /// Insert a child entry
    fn insert_child(&self, name: &str, child: Arc<InitramfsInode>) -> Result<(), FsError> {
        if name.is_empty() || name.contains('/') {
            return Err(FsError::Invalid);
        }

        match &self.kind {
            NodeKind::Directory { children } => {
                let mut guard = children.write();
                if guard.contains_key(name) {
                    // Allow replacing existing entry for hardlink support
                    return Ok(());
                }
                guard.insert(name.to_string(), child);
                Ok(())
            }
            _ => Err(FsError::NotDir),
        }
    }

    /// Get Arc reference to self
    fn as_arc(&self) -> Result<Arc<InitramfsInode>, FsError> {
        self.self_ref
            .read()
            .as_ref()
            .and_then(|w| w.upgrade())
            .ok_or(FsError::Invalid)
    }
}

/// Attach a node to the directory tree, creating intermediate directories as needed
fn attach_node(
    root: &Arc<InitramfsInode>,
    path: &str,
    node: Arc<InitramfsInode>,
) -> Result<(), FsError> {
    let mut current = root.clone();
    let mut components = path.split('/').filter(|c| !c.is_empty()).peekable();

    while let Some(segment) = components.next() {
        let is_last = components.peek().is_none();
        if is_last {
            return current.insert_child(segment, node);
        }

        // Navigate or create intermediate directory
        let next = match current.lookup_child(segment) {
            Ok(child) => child,
            Err(FsError::NotFound) => {
                // Create implicit directory
                let dir = InitramfsInode::new_dir(
                    current.fs_id,
                    alloc_generated_ino(),
                    FileMode::directory(0o755),
                    2,
                    0,
                    0,
                    TimeSpec::now(),
                );
                current.insert_child(segment, dir.clone())?;
                dir
            }
            Err(e) => return Err(e),
        };
        current = next;
    }

    Ok(())
}

impl Inode for InitramfsInode {
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
        // Reject write operations on read-only filesystem
        if flags.is_writable() || flags.is_truncate() || flags.is_append() {
            return Err(FsError::ReadOnly);
        }
        if matches!(&self.kind, NodeKind::Directory { .. }) {
            return Err(FsError::IsDir);
        }

        let inode: Arc<dyn Inode> = self.as_arc()?;
        Ok(Box::new(FileHandle::new(inode, flags, true)))
    }

    fn is_dir(&self) -> bool {
        matches!(&self.kind, NodeKind::Directory { .. })
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        match &self.kind {
            NodeKind::Directory { children } => {
                let guard = children.read();

                // "." entry at offset 0
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

                // ".." entry at offset 1
                if offset == 1 {
                    return Ok(Some((
                        2,
                        DirEntry {
                            name: "..".to_string(),
                            ino: self.ino, // Parent would need separate tracking
                            file_type: FileType::Directory,
                        },
                    )));
                }

                // Real entries start at offset 2
                let real_offset = offset - 2;
                if let Some((name, child)) = guard.iter().nth(real_offset) {
                    let ft = match &child.kind {
                        NodeKind::Directory { .. } => FileType::Directory,
                        NodeKind::File { .. } => FileType::Regular,
                        NodeKind::Symlink { .. } => FileType::Symlink,
                    };
                    return Ok(Some((
                        offset + 1,
                        DirEntry {
                            name: name.clone(),
                            ino: child.ino,
                            file_type: ft,
                        },
                    )));
                }

                Ok(None)
            }
            _ => Err(FsError::NotDir),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        match &self.kind {
            NodeKind::File { data } => {
                let start = usize::try_from(offset).map_err(|_| FsError::Invalid)?;
                if start >= data.len() {
                    return Ok(0);
                }
                let to_copy = core::cmp::min(buf.len(), data.len() - start);
                buf[..to_copy].copy_from_slice(&data[start..start + to_copy]);
                Ok(to_copy)
            }
            NodeKind::Symlink { target } => {
                let start = usize::try_from(offset).map_err(|_| FsError::Invalid)?;
                if start >= target.len() {
                    return Ok(0);
                }
                let to_copy = core::cmp::min(buf.len(), target.len() - start);
                buf[..to_copy].copy_from_slice(&target[start..start + to_copy]);
                Ok(to_copy)
            }
            NodeKind::Directory { .. } => Err(FsError::IsDir),
        }
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<usize, FsError> {
        Err(FsError::ReadOnly)
    }

    fn truncate(&self, _len: u64) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
