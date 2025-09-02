use crate::println;
use alloc::{vec::Vec, collections::VecDeque};
use spin::Mutex;

// IPC用于在进程间传输信息，可以使用消息队列、共享内存等机制
pub struct Message {
    pub sender: usize,
    pub receiver: usize,
    pub data: Vec<u8>,
}

pub struct MessageQueue {
    messages: VecDeque<Message>,
}

impl MessageQueue {
    pub fn new() -> Self {
        MessageQueue {
            messages: VecDeque::new(),
        }
    }
    
    pub fn send(&mut self, msg: Message) {
        self.messages.push_back(msg);
    }
    
    pub fn receive(&mut self, receiver: usize) -> Option<Message> {
        self.messages
            .iter()
            .position(|m| m.receiver == receiver)
            .and_then(|idx| self.messages.remove(idx))
    }
}

lazy_static::lazy_static! {
    pub static ref IPC_QUEUE: Mutex<MessageQueue> = Mutex::new(MessageQueue::new());
}

pub fn init() {
    println!("IPC system initialized");
}

pub fn send_message(sender: usize, receiver: usize, data: Vec<u8>) {
    let msg = Message {
        sender,
        receiver,
        data,
    };
    IPC_QUEUE.lock().send(msg);
}

pub fn receive_message(receiver: usize) -> Option<Vec<u8>> {
    IPC_QUEUE.lock().receive(receiver).map(|m| m.data)
}
