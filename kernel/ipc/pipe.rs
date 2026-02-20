//! 匿名管道实现
//!
//! 提供进程间单向数据通道：
//! - pipe() 创建管道，返回读端和写端
//! - 环形缓冲区存储数据
//! - 阻塞/非阻塞模式支持
//! - 正确的关闭语义（EOF/EPIPE）

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::sync::WaitQueue;
use kernel_core::{FileOps, SyscallError, VfsStat};

/// 默认管道缓冲区大小（4KB）
pub const DEFAULT_PIPE_CAPACITY: usize = 4096;

/// 管道错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// 没有当前进程上下文
    NoCurrentProcess,
    /// 读端已关闭，写入会产生EPIPE
    BrokenPipe,
    /// 非阻塞模式下操作会阻塞
    WouldBlock,
    /// 管道已关闭
    Closed,
    /// 无效的管道ID
    InvalidPipe,
    /// 权限错误（尝试在错误的端读/写）
    InvalidOperation,
    /// 管道 ID 分配耗尽
    PipeIdExhausted,
}

/// 管道标志
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeFlags {
    /// 非阻塞模式
    pub nonblock: bool,
    /// exec时关闭
    pub cloexec: bool,
}

/// 管道ID类型
pub type PipeId = u64;

/// 管道端类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEndType {
    /// 读端
    Read,
    /// 写端
    Write,
}

/// 共享管道内部状态
struct PipeInner {
    /// 环形缓冲区
    buffer: Vec<u8>,
    /// 缓冲区容量
    capacity: usize,
    /// 读位置（head）
    read_pos: usize,
    /// 当前数据长度
    len: usize,
    /// 读端引用计数
    readers: usize,
    /// 写端引用计数
    writers: usize,
}

impl PipeInner {
    fn new(capacity: usize) -> Self {
        PipeInner {
            buffer: vec![0u8; capacity],
            capacity,
            read_pos: 0,
            len: 0,
            readers: 1,
            writers: 1,
        }
    }

    /// 检查缓冲区是否为空
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 检查缓冲区是否已满
    fn is_full(&self) -> bool {
        self.len >= self.capacity
    }

    /// 可读取的字节数
    fn available(&self) -> usize {
        self.len
    }

    /// 可写入的字节数
    fn space(&self) -> usize {
        self.capacity - self.len
    }

    /// 从缓冲区读取数据
    fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = core::cmp::min(dst.len(), self.len);
        if to_read == 0 {
            return 0;
        }

        let mut read = 0;
        while read < to_read {
            let chunk_size = core::cmp::min(to_read - read, self.capacity - self.read_pos);
            dst[read..read + chunk_size]
                .copy_from_slice(&self.buffer[self.read_pos..self.read_pos + chunk_size]);
            self.read_pos = (self.read_pos + chunk_size) % self.capacity;
            read += chunk_size;
        }

        self.len -= to_read;
        to_read
    }

    /// 向缓冲区写入数据
    fn write(&mut self, src: &[u8]) -> usize {
        let to_write = core::cmp::min(src.len(), self.space());
        if to_write == 0 {
            return 0;
        }

        let write_pos = (self.read_pos + self.len) % self.capacity;
        let mut written = 0;
        let mut pos = write_pos;

        while written < to_write {
            let chunk_size = core::cmp::min(to_write - written, self.capacity - pos);
            self.buffer[pos..pos + chunk_size].copy_from_slice(&src[written..written + chunk_size]);
            pos = (pos + chunk_size) % self.capacity;
            written += chunk_size;
        }

        self.len += to_write;
        to_write
    }
}

/// 管道对象
pub struct Pipe {
    /// 管道ID
    id: PipeId,
    /// 内部状态（受锁保护）
    inner: Mutex<PipeInner>,
    /// 等待读取的进程队列
    read_wait: WaitQueue,
    /// 等待写入的进程队列
    write_wait: WaitQueue,
}

impl Pipe {
    /// 创建新管道
    fn new(id: PipeId, capacity: usize) -> Self {
        Pipe {
            id,
            inner: Mutex::new(PipeInner::new(capacity)),
            read_wait: WaitQueue::new(),
            write_wait: WaitQueue::new(),
        }
    }

    /// 获取管道ID
    pub fn id(&self) -> PipeId {
        self.id
    }

    /// 从管道读取数据
    ///
    /// # Arguments
    /// * `dst` - 目标缓冲区
    /// * `flags` - 管道标志
    ///
    /// # Returns
    /// * `Ok(n)` - 成功读取n字节（0表示EOF）
    /// * `Err(WouldBlock)` - 非阻塞模式下缓冲区为空
    /// * `Err(Closed)` - 管道已关闭
    ///
    /// # Z-11 fix: Lost-wakeup race condition
    ///
    /// 使用 prepare_to_wait/finish_wait 模式防止丢失唤醒：
    /// 1. 在持有锁时调用 prepare_to_wait 加入等待队列
    /// 2. 释放锁
    /// 3. 调用 finish_wait 实际阻塞
    ///
    /// 这样即使写者在释放锁后立即唤醒，由于读者已在队列中，
    /// 唤醒信号不会丢失。
    pub fn read(&self, dst: &mut [u8], flags: PipeFlags) -> Result<usize, PipeError> {
        loop {
            let should_wait = {
                let mut inner = self.inner.lock();

                // 有数据可读
                if inner.len > 0 {
                    let n = inner.read(dst);
                    // 唤醒等待写入的进程
                    self.write_wait.wake_one();
                    return Ok(n);
                }

                // 缓冲区为空
                // 检查写端是否全部关闭
                if inner.writers == 0 {
                    return Ok(0); // EOF
                }

                // 非阻塞模式
                if flags.nonblock {
                    return Err(PipeError::WouldBlock);
                }

                // Z-11 fix: 在持有锁时加入等待队列
                // 这样即使写者在我们释放锁后立即写入并唤醒，
                // 我们已经在队列中，不会错过唤醒信号
                self.read_wait.prepare_to_wait()
            }; // 释放锁

            // 如果成功加入等待队列，实际阻塞
            if should_wait {
                self.read_wait.finish_wait();
            }
            // 被唤醒后循环回去重新检查条件
        }
    }

    /// 向管道写入数据
    ///
    /// # Arguments
    /// * `src` - 源数据
    /// * `flags` - 管道标志
    ///
    /// # Returns
    /// * `Ok(n)` - 成功写入n字节
    /// * `Err(BrokenPipe)` - 读端已关闭
    /// * `Err(WouldBlock)` - 非阻塞模式下缓冲区已满
    ///
    /// # Z-11 fix: Lost-wakeup race condition
    ///
    /// 使用 prepare_to_wait/finish_wait 模式防止丢失唤醒。
    pub fn write(&self, src: &[u8], flags: PipeFlags) -> Result<usize, PipeError> {
        let mut total_written = 0;

        while total_written < src.len() {
            let should_wait = {
                let mut inner = self.inner.lock();

                // 检查读端是否全部关闭
                if inner.readers == 0 {
                    if total_written > 0 {
                        return Ok(total_written);
                    }
                    return Err(PipeError::BrokenPipe);
                }

                // 有空间可写
                if inner.space() > 0 {
                    let n = inner.write(&src[total_written..]);
                    total_written += n;
                    // 唤醒等待读取的进程
                    self.read_wait.wake_one();

                    if total_written >= src.len() {
                        return Ok(total_written);
                    }
                }

                // 缓冲区已满
                // 非阻塞模式
                if flags.nonblock {
                    if total_written > 0 {
                        return Ok(total_written);
                    }
                    return Err(PipeError::WouldBlock);
                }

                // Z-11 fix: 在持有锁时加入等待队列
                self.write_wait.prepare_to_wait()
            }; // 释放锁

            // 如果成功加入等待队列，实际阻塞
            if should_wait {
                self.write_wait.finish_wait();
            }
        }

        Ok(total_written)
    }

    /// 关闭读端
    fn close_read(&self) {
        let mut inner = self.inner.lock();
        inner.readers = inner.readers.saturating_sub(1);
        // 唤醒所有写者，让它们检测到EPIPE
        self.write_wait.wake_all();
    }

    /// 关闭写端
    fn close_write(&self) {
        let mut inner = self.inner.lock();
        inner.writers = inner.writers.saturating_sub(1);
        // 唤醒所有读者，让它们检测到EOF
        self.read_wait.wake_all();
    }

    /// 增加读端引用
    fn add_reader(&self) {
        let mut inner = self.inner.lock();
        inner.readers += 1;
    }

    /// 增加写端引用
    fn add_writer(&self) {
        let mut inner = self.inner.lock();
        inner.writers += 1;
    }

    /// 获取管道状态
    pub fn status(&self) -> PipeStatus {
        let inner = self.inner.lock();
        PipeStatus {
            available: inner.available(),
            space: inner.space(),
            readers: inner.readers,
            writers: inner.writers,
        }
    }
}

/// 管道状态信息
#[derive(Debug, Clone, Copy)]
pub struct PipeStatus {
    /// 可读字节数
    pub available: usize,
    /// 可写字节数
    pub space: usize,
    /// 读端数量
    pub readers: usize,
    /// 写端数量
    pub writers: usize,
}

/// 管道端句柄
pub struct PipeHandle {
    /// 底层管道
    pipe: Arc<Pipe>,
    /// 端类型（读/写）
    end_type: PipeEndType,
    /// 标志
    flags: PipeFlags,
}

impl PipeHandle {
    /// 创建读端句柄
    fn new_read(pipe: Arc<Pipe>, flags: PipeFlags) -> Self {
        PipeHandle {
            pipe,
            end_type: PipeEndType::Read,
            flags,
        }
    }

    /// 创建写端句柄
    fn new_write(pipe: Arc<Pipe>, flags: PipeFlags) -> Self {
        PipeHandle {
            pipe,
            end_type: PipeEndType::Write,
            flags,
        }
    }

    /// 获取端类型
    pub fn end_type(&self) -> PipeEndType {
        self.end_type
    }

    /// 获取管道ID
    pub fn pipe_id(&self) -> PipeId {
        self.pipe.id()
    }

    /// 读取数据（仅读端有效）
    pub fn read(&self, dst: &mut [u8]) -> Result<usize, PipeError> {
        if self.end_type != PipeEndType::Read {
            return Err(PipeError::InvalidOperation);
        }
        self.pipe.read(dst, self.flags)
    }

    /// 写入数据（仅写端有效）
    pub fn write(&self, src: &[u8]) -> Result<usize, PipeError> {
        if self.end_type != PipeEndType::Write {
            return Err(PipeError::InvalidOperation);
        }
        self.pipe.write(src, self.flags)
    }

    /// 设置非阻塞模式
    pub fn set_nonblock(&mut self, nonblock: bool) {
        self.flags.nonblock = nonblock;
    }

    /// 检查是否为非阻塞模式
    pub fn is_nonblock(&self) -> bool {
        self.flags.nonblock
    }

    /// 获取管道状态
    pub fn status(&self) -> PipeStatus {
        self.pipe.status()
    }

    /// 复制句柄（用于fork）
    pub fn duplicate(&self) -> Self {
        // 增加相应端的引用计数
        match self.end_type {
            PipeEndType::Read => self.pipe.add_reader(),
            PipeEndType::Write => self.pipe.add_writer(),
        }

        PipeHandle {
            pipe: self.pipe.clone(),
            end_type: self.end_type,
            flags: self.flags,
        }
    }
}

impl Clone for PipeHandle {
    fn clone(&self) -> Self {
        self.duplicate()
    }
}

impl core::fmt::Debug for PipeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeHandle")
            .field("pipe_id", &self.pipe_id())
            .field("end_type", &self.end_type)
            .field("nonblock", &self.flags.nonblock)
            .field("cloexec", &self.flags.cloexec)
            .finish()
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        match self.end_type {
            PipeEndType::Read => self.pipe.close_read(),
            PipeEndType::Write => self.pipe.close_write(),
        }
    }
}

/// 实现 FileOps trait，支持在进程 fd_table 中存储
impl FileOps for PipeHandle {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(self.duplicate())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        match self.end_type {
            PipeEndType::Read => "PipeRead",
            PipeEndType::Write => "PipeWrite",
        }
    }

    /// R41-1 FIX: Return S_IFIFO mode for pipe fstat.
    ///
    /// Returns pipe metadata with FIFO type (S_IFIFO = 0o010000) and rw-rw-rw- permissions.
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
            dev: 0,
            ino: self.pipe_id() as u64,
            mode: 0o010000 | 0o666, // S_IFIFO | rw-rw-rw-
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        })
    }
}

/// 下一个管道ID
static NEXT_PIPE_ID: AtomicUsize = AtomicUsize::new(1);

/// 创建管道
///
/// 返回 (读端句柄, 写端句柄)
pub fn create_pipe(flags: PipeFlags) -> Result<(PipeHandle, PipeHandle), PipeError> {
    create_pipe_with_capacity(DEFAULT_PIPE_CAPACITY, flags)
}

/// 创建指定容量的管道
pub fn create_pipe_with_capacity(capacity: usize, flags: PipeFlags) -> Result<(PipeHandle, PipeHandle), PipeError> {
    // R111-3 FIX: Use fetch_update + checked_add to prevent wrapping to 0
    // on usize overflow.  Follows the R105-5 pattern established for IPC
    // endpoint IDs and socket IDs.
    let id = NEXT_PIPE_ID
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
        .map_err(|_| PipeError::PipeIdExhausted)? as PipeId;
    let pipe = Arc::new(Pipe::new(id, capacity));

    let read_handle = PipeHandle::new_read(pipe.clone(), flags);
    let write_handle = PipeHandle::new_write(pipe, flags);

    Ok((read_handle, write_handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 基本管道测试（在内核环境中运行）
    fn test_pipe_basic() {
        let flags = PipeFlags::default();
        let (read_end, write_end) = create_pipe(flags).unwrap();

        // 写入数据
        let data = b"Hello, Pipe!";
        let written = write_end.write(data).unwrap();
        assert_eq!(written, data.len());

        // 读取数据
        let mut buf = [0u8; 32];
        let read = read_end.read(&mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }
}
