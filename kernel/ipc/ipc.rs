//! 进程间通信 (IPC) 系统
//!
//! 实现基于能力的端点通信，提供：
//! - 每进程端点命名空间隔离
//! - 基于能力的访问控制（allowed_senders）
//! - 不可伪造的发送者身份（自动从current_pid获取）
//! - 有界消息队列（防止OOM）
//! - 背压机制（队列满时返回错误）
//! - R75-2 FIX: 按 IPC 命名空间分区端点表

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::process::{self, ProcessId};
use kernel_core::{current_ipc_ns_id, NamespaceId};

/// 端点标识符类型
pub type EndpointId = u64;

/// 每个端点的最大消息数量（背压阈值）
const MAX_MESSAGES_PER_ENDPOINT: usize = 64;

/// 每个进程可注册的最大端点数
const MAX_ENDPOINTS_PER_PROCESS: usize = 32;

/// 单条消息最大数据长度（字节）
const MAX_MESSAGE_SIZE: usize = 4096;

/// IPC消息
#[derive(Debug, Clone)]
pub struct Message {
    /// 发送者进程ID（由系统自动填充，不可伪造）
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// 接收到的消息
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// 发送者进程ID
    pub sender: ProcessId,
    /// 消息数据
    pub data: Vec<u8>,
}

/// IPC错误类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// 没有当前进程上下文
    NoCurrentProcess,
    /// 端点不存在
    EndpointNotFound,
    /// 访问被拒绝（无发送权限或非端点所有者）
    AccessDenied,
    /// 消息队列已满（背压）
    QueueFull,
    /// 消息过大
    MessageTooLarge,
    /// 端点数量超限
    TooManyEndpoints,
}

/// IPC端点
///
/// 每个端点属于一个进程（owner），只有owner可以接收消息。
/// 发送权限通过allowed_senders白名单控制。
#[derive(Debug)]
struct Endpoint {
    /// 端点所有者进程ID
    owner: ProcessId,
    /// 允许发送消息的进程ID集合
    allowed_senders: BTreeSet<ProcessId>,
    /// 消息队列
    queue: VecDeque<Message>,
}

impl Endpoint {
    /// 创建新端点
    fn new(owner: ProcessId, allowed_senders: &[ProcessId]) -> Self {
        let mut allowed = BTreeSet::new();
        // 所有者总是可以发送（给自己）
        allowed.insert(owner);
        for pid in allowed_senders {
            allowed.insert(*pid);
        }

        Endpoint {
            owner,
            allowed_senders: allowed,
            queue: VecDeque::new(),
        }
    }

    /// 检查进程是否有发送权限
    fn can_send(&self, sender: ProcessId) -> bool {
        self.allowed_senders.contains(&sender)
    }

    /// 授权另一个进程发送
    fn grant_access(&mut self, pid: ProcessId) {
        self.allowed_senders.insert(pid);
    }

    /// 撤销另一个进程的发送权限
    fn revoke_access(&mut self, pid: ProcessId) {
        // 所有者权限不可撤销
        if pid != self.owner {
            self.allowed_senders.remove(&pid);
        }
    }

    /// 推送消息到队列
    fn push_message(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.queue.len() >= MAX_MESSAGES_PER_ENDPOINT {
            return Err(IpcError::QueueFull);
        }
        self.queue.push_back(msg);
        Ok(())
    }
}

/// 全局端点注册表
///
/// R75-2 FIX: 按 IPC 命名空间分区，提供真正的 IPC 隔离。
/// 不同命名空间的端点互不可见、互不可访问。
#[derive(Default)]
struct EndpointRegistry {
    /// 每命名空间、每进程端点表: NamespaceId -> ProcessId -> (EndpointId -> Endpoint)
    per_ns: BTreeMap<NamespaceId, BTreeMap<ProcessId, BTreeMap<EndpointId, Endpoint>>>,
    /// 端点到所有者的索引: EndpointId -> (NamespaceId, ProcessId)
    owner_index: BTreeMap<EndpointId, (NamespaceId, ProcessId)>,
}

impl EndpointRegistry {
    /// 注册新端点
    ///
    /// R75-2 FIX: 端点注册在调用者的 IPC 命名空间内
    fn register_endpoint(
        &mut self,
        ns_id: NamespaceId,
        owner: ProcessId,
        allowed_senders: &[ProcessId],
    ) -> Result<EndpointId, IpcError> {
        // 检查端点数量限制
        let process_endpoints = self
            .per_ns
            .entry(ns_id)
            .or_default()
            .entry(owner)
            .or_default();
        if process_endpoints.len() >= MAX_ENDPOINTS_PER_PROCESS {
            return Err(IpcError::TooManyEndpoints);
        }

        let endpoint_id = NEXT_ENDPOINT_ID.fetch_add(1, Ordering::SeqCst);
        let endpoint = Endpoint::new(owner, allowed_senders);

        process_endpoints.insert(endpoint_id, endpoint);
        self.owner_index.insert(endpoint_id, (ns_id, owner));

        Ok(endpoint_id)
    }

    /// 获取端点的可变引用
    ///
    /// R75-2 FIX: 只返回同命名空间内的端点
    fn endpoint_mut(
        &mut self,
        ns_id: NamespaceId,
        endpoint_id: EndpointId,
    ) -> Option<&mut Endpoint> {
        let (stored_ns, owner) = *self.owner_index.get(&endpoint_id)?;
        if stored_ns != ns_id {
            // 命名空间不匹配 - 端点对调用者不可见
            return None;
        }
        self.per_ns
            .get_mut(&ns_id)
            .and_then(|by_pid| by_pid.get_mut(&owner))
            .and_then(|table| table.get_mut(&endpoint_id))
    }

    /// 获取端点的不可变引用
    ///
    /// R75-2 FIX: 只返回同命名空间内的端点
    fn endpoint(&self, ns_id: NamespaceId, endpoint_id: EndpointId) -> Option<&Endpoint> {
        let (stored_ns, owner) = *self.owner_index.get(&endpoint_id)?;
        if stored_ns != ns_id {
            // 命名空间不匹配 - 端点对调用者不可见
            return None;
        }
        self.per_ns
            .get(&ns_id)
            .and_then(|by_pid| by_pid.get(&owner))
            .and_then(|table| table.get(&endpoint_id))
    }

    /// 删除端点
    ///
    /// R75-2 FIX: 只能删除同命名空间内的端点
    fn remove_endpoint(&mut self, ns_id: NamespaceId, endpoint_id: EndpointId) -> bool {
        if let Some((stored_ns, owner)) = self.owner_index.get(&endpoint_id).copied() {
            if stored_ns != ns_id {
                // 命名空间不匹配 - 不允许跨命名空间删除
                return false;
            }
            self.owner_index.remove(&endpoint_id);
            if let Some(table) = self.per_ns.get_mut(&ns_id).and_then(|ns| ns.get_mut(&owner)) {
                table.remove(&endpoint_id);
                return true;
            }
        }
        false
    }

    /// 清理进程的所有端点（进程退出时调用）
    ///
    /// R75-2 FIX: 只清理指定命名空间内该进程的端点
    fn cleanup_process(&mut self, ns_id: NamespaceId, pid: ProcessId) {
        if let Some(endpoints) = self
            .per_ns
            .get_mut(&ns_id)
            .and_then(|by_pid| by_pid.remove(&pid))
        {
            for endpoint_id in endpoints.keys() {
                self.owner_index.remove(endpoint_id);
            }
        }
    }
}

/// 下一个可用的端点ID
static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(1);

lazy_static::lazy_static! {
    /// 全局端点注册表
    static ref ENDPOINTS: Mutex<EndpointRegistry> = Mutex::new(EndpointRegistry::default());
}

/// 初始化IPC系统
pub fn init() {
    println!("IPC system initialized (capability-based endpoints)");
}

/// 注册新端点
///
/// 当前进程成为端点的所有者，只有所有者可以接收消息。
///
/// R75-2 FIX: 端点注册在调用者的 IPC 命名空间内
///
/// # Arguments
///
/// * `allowed_senders` - 允许发送消息的进程ID列表（所有者自动包含）
///
/// # Returns
///
/// 成功返回端点ID，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `TooManyEndpoints` - 端点数量超过限制
pub fn register_endpoint(allowed_senders: &[ProcessId]) -> Result<EndpointId, IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;
    ENDPOINTS
        .lock()
        .register_endpoint(ns_id, owner, allowed_senders)
}

/// 发送消息到端点
///
/// 发送者身份自动从当前进程获取，不可伪造。
///
/// R75-2 FIX: 只能发送到同一 IPC 命名空间内的端点
///
/// # Arguments
///
/// * `endpoint_id` - 目标端点ID
/// * `data` - 消息数据
///
/// # Returns
///
/// 成功返回`Ok(())`，失败返回错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在或不在当前命名空间内
/// * `AccessDenied` - 当前进程无发送权限
/// * `QueueFull` - 端点消息队列已满
/// * `MessageTooLarge` - 消息数据超过大小限制
pub fn send_message(endpoint_id: EndpointId, data: Vec<u8>) -> Result<(), IpcError> {
    // 自动获取发送者身份（不可伪造）
    let sender = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    // 检查消息大小
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 检查发送权限
    if !endpoint.can_send(sender) {
        return Err(IpcError::AccessDenied);
    }

    endpoint.push_message(Message { sender, data })
}

/// 接收消息
///
/// 只有端点所有者可以接收消息。
///
/// R75-2 FIX: 只能从同一 IPC 命名空间内的端点接收
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
///
/// # Returns
///
/// * `Ok(Some(msg))` - 成功接收消息
/// * `Ok(None)` - 队列为空
/// * `Err(...)` - 发生错误
///
/// # Errors
///
/// * `NoCurrentProcess` - 无当前进程上下文
/// * `EndpointNotFound` - 端点不存在或不在当前命名空间内
/// * `AccessDenied` - 当前进程不是端点所有者
pub fn receive_message(endpoint_id: EndpointId) -> Result<Option<ReceivedMessage>, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 只有所有者可以接收
    if endpoint.owner != receiver {
        return Err(IpcError::AccessDenied);
    }

    Ok(endpoint.queue.pop_front().map(|msg| ReceivedMessage {
        sender: msg.sender,
        data: msg.data,
    }))
}

/// 授权进程发送权限
///
/// 只有端点所有者可以授权。
///
/// R75-2 FIX: 只能授权同一 IPC 命名空间内的端点
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要授权的进程ID
pub fn grant_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    endpoint.grant_access(pid);
    Ok(())
}

/// 撤销进程发送权限
///
/// 只有端点所有者可以撤销。所有者自身的权限不可撤销。
///
/// R75-2 FIX: 只能撤销同一 IPC 命名空间内端点的权限
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `pid` - 要撤销权限的进程ID
pub fn revoke_access(endpoint_id: EndpointId, pid: ProcessId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let mut registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint_mut(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    endpoint.revoke_access(pid);
    Ok(())
}

/// 删除端点
///
/// 只有端点所有者可以删除。
///
/// R75-2 FIX: 只能删除同一 IPC 命名空间内的端点
///
/// # X-6 安全修复
///
/// 销毁端点时必须清理关联的等待队列，唤醒所有阻塞等待的进程。
/// 否则这些进程会永久阻塞，造成资源泄漏和 DoS。
///
/// **重要**：必须先移除端点注册，再清理等待队列。这确保被唤醒的线程
/// 在下一次 receive_message 时立即看到 EndpointNotFound，避免重新创建
/// 新的等待队列导致再次阻塞。
pub fn destroy_endpoint(endpoint_id: EndpointId) -> Result<(), IpcError> {
    let owner = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    if endpoint.owner != owner {
        return Err(IpcError::AccessDenied);
    }

    drop(registry);

    // 先移除端点注册，确保被唤醒的等待者在下一次 receive 时立即得到 EndpointNotFound
    ENDPOINTS.lock().remove_endpoint(ns_id, endpoint_id);

    // X-6 修复：清理等待队列，唤醒所有阻塞的接收者
    // 被唤醒的进程会在下次 receive_message 时得到 EndpointNotFound 错误
    cleanup_wait_queue(endpoint_id);

    Ok(())
}

/// 清理进程的所有端点（进程退出时调用）
///
/// 此函数应在进程终止时由进程管理子系统调用。
///
/// R75-2 FIX: 接受 IPC 命名空间 ID 用于按命名空间清理端点
///
/// # X-6 安全修复
///
/// 进程退出时必须清理其所有端点的等待队列，唤醒所有阻塞等待的进程。
/// 否则其他进程会永久阻塞在已销毁的端点上。
///
/// **重要**：必须先移除端点注册，再清理等待队列。这确保被唤醒的线程
/// 在下一次 receive_message 时立即看到 EndpointNotFound，避免重新创建
/// 新的等待队列导致再次阻塞。
pub fn cleanup_process_endpoints(ns_id: NamespaceId, pid: ProcessId) {
    // X-6 修复：先收集该进程的所有端点 ID
    let endpoint_ids: Vec<EndpointId> = {
        let registry = ENDPOINTS.lock();
        registry
            .per_ns
            .get(&ns_id)
            .and_then(|by_pid| by_pid.get(&pid))
            .map(|table| table.keys().copied().collect())
            .unwrap_or_default()
    };

    // X-6 修复：先移除端点注册
    // 确保被唤醒的线程在下一次 receive 时立即看到 EndpointNotFound
    // 避免在等待队列清理后重新创建新的等待队列导致再次阻塞
    ENDPOINTS.lock().cleanup_process(ns_id, pid);

    // 然后清理每个端点的等待队列，唤醒阻塞的进程
    for endpoint_id in &endpoint_ids {
        cleanup_wait_queue(*endpoint_id);
    }
}

/// 获取端点队列中的消息数量
///
/// R75-2 FIX: 只能查询同一 IPC 命名空间内的端点
pub fn get_queue_length(endpoint_id: EndpointId) -> Result<usize, IpcError> {
    let receiver = process::current_pid().ok_or(IpcError::NoCurrentProcess)?;
    let ns_id = current_ipc_ns_id().ok_or(IpcError::NoCurrentProcess)?;

    let registry = ENDPOINTS.lock();
    let endpoint = registry
        .endpoint(ns_id, endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    // 只有所有者可以查看队列状态
    if endpoint.owner != receiver {
        return Err(IpcError::AccessDenied);
    }

    Ok(endpoint.queue.len())
}

// ============================================================================
// 阻塞IPC扩展
// ============================================================================

use crate::sync::WaitQueue;
use alloc::collections::BTreeMap as WaitQueueMap;

lazy_static::lazy_static! {
    /// 每端点等待队列：用于阻塞接收
    ///
    /// # X-6 安全增强
    ///
    /// 使用 Arc<WaitQueue> 引用计数，避免在锁外访问时发生 use-after-free。
    /// 当端点销毁时，通过 close() 关闭队列，唤醒所有等待者。
    static ref ENDPOINT_WAIT_QUEUES: spin::Mutex<WaitQueueMap<EndpointId, Arc<WaitQueue>>> =
        spin::Mutex::new(WaitQueueMap::new());
}

/// 获取或创建端点的等待队列
///
/// # X-6 安全增强
///
/// 返回 Arc<WaitQueue> 而非裸指针，确保引用计数正确管理内存。
fn get_or_create_wait_queue(endpoint_id: EndpointId) -> Arc<WaitQueue> {
    let mut queues = ENDPOINT_WAIT_QUEUES.lock();
    queues
        .entry(endpoint_id)
        .or_insert_with(|| Arc::new(WaitQueue::new()))
        .clone()
}

/// 发送消息并唤醒等待的接收者
///
/// 与send_message相同，但会唤醒在此端点上阻塞等待的进程。
pub fn send_message_notify(endpoint_id: EndpointId, data: Vec<u8>) -> Result<(), IpcError> {
    // 发送消息
    send_message(endpoint_id, data)?;

    // X-6: 克隆 Arc 后再释放锁，避免在持有锁时调用 wake
    let wq = {
        let queues = ENDPOINT_WAIT_QUEUES.lock();
        queues.get(&endpoint_id).cloned()
    };

    if let Some(wq) = wq {
        wq.wake_one();
    }

    Ok(())
}

/// 阻塞接收消息
///
/// 如果队列为空，当前进程会阻塞直到有消息到达。
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
///
/// # Returns
///
/// * `Ok(msg)` - 成功接收消息
/// * `Err(...)` - 发生错误
///
/// # X-6 安全增强
///
/// 使用 Arc<WaitQueue> 避免 use-after-free，检查 is_closed() 避免永久阻塞。
/// 如果端点在等待期间被销毁，返回 EndpointNotFound 错误。
pub fn receive_message_blocking(endpoint_id: EndpointId) -> Result<ReceivedMessage, IpcError> {
    loop {
        // 尝试接收
        match receive_message(endpoint_id)? {
            Some(msg) => return Ok(msg),
            None => {
                // 队列为空，准备阻塞等待
                // X-6: 使用 Arc 获取 wait queue，避免 use-after-free
                let wq = get_or_create_wait_queue(endpoint_id);

                // X-6: 如果端点已被销毁（队列已关闭），直接返回错误避免阻塞
                if wq.is_closed() {
                    return Err(IpcError::EndpointNotFound);
                }

                // 等待唤醒
                let waited = wq.wait();

                // X-6: wait() 返回 false 表示队列已关闭或无当前进程
                if !waited {
                    if wq.is_closed() {
                        return Err(IpcError::EndpointNotFound);
                    }
                    return Err(IpcError::NoCurrentProcess);
                }
            }
        }
    }
}

/// 带超时的接收消息（简化版：仅支持重试次数）
///
/// # Arguments
///
/// * `endpoint_id` - 端点ID
/// * `max_retries` - 最大重试次数（每次重试会yield）
///
/// # Returns
///
/// * `Ok(Some(msg))` - 成功接收消息
/// * `Ok(None)` - 超时（达到最大重试次数）
/// * `Err(...)` - 发生错误
pub fn receive_message_with_retries(
    endpoint_id: EndpointId,
    max_retries: usize,
) -> Result<Option<ReceivedMessage>, IpcError> {
    for _ in 0..max_retries {
        match receive_message(endpoint_id)? {
            Some(msg) => return Ok(Some(msg)),
            None => {
                // 让出CPU
                kernel_core::force_reschedule();
            }
        }
    }
    Ok(None)
}

/// 清理端点的等待队列（端点销毁时调用）
///
/// # X-6 安全增强
///
/// 使用 close() 方法而非仅 wake_all()，确保：
/// 1. 设置 closed 标志，阻止新的等待者加入
/// 2. 唤醒所有现有等待者
/// 3. 等待者被唤醒后会检查 is_closed() 并返回错误
fn cleanup_wait_queue(endpoint_id: EndpointId) {
    // X-6: 先取出 Arc，再释放锁后调用 close()
    // 这避免了在持有锁时调用可能导致调度的操作
    let wq = {
        let mut queues = ENDPOINT_WAIT_QUEUES.lock();
        queues.remove(&endpoint_id)
    };

    if let Some(wq) = wq {
        // 关闭队列并唤醒所有等待者
        // 被唤醒的进程会检查 is_closed() 并返回 EndpointNotFound
        wq.close();
    }
}
