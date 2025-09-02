[Switch to English (切换到英文)](README.md)

# Rust 微内核项目

## 1. 项目概述

这是一个使用 Rust 编写的简单微内核，旨在探索操作系统的基本原理。它包含一个 UEFI 引导加载程序和一个具备基本功能（如内存管理、进程管理、IPC 和调度）的内核。该项目被组织为一个 Cargo 工作区，包含两个主要组件：`bootloader` 和 `kernel`。

---

## 2. 项目结构

项目工作区结构如下：

```
rust-microkernel/
├── bootloader/         # UEFI 引导加载程序
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
├── kernel/             # 微内核代码
│   ├── src/
│   │   ├── main.rs         # 内核入口和初始化
│   │   ├── interrupts.rs   # 中断处理
│   │   ├── memory.rs       # 内存管理
│   │   ├── process.rs      # 进程管理
│   │   ├── ipc.rs          # 进程间通信 (IPC)
│   │   ├── scheduler.rs    # 调度器
│   │   └── syscall.rs      # 系统调用处理
│   ├── kernel.ld       # 链接器脚本
│   └── Cargo.toml
├── Cargo.toml          # 工作区配置
└── Makefile            # 构建脚本
```

### 2.1. 引导加载程序 (Bootloader)

`bootloader` 是一个 UEFI 应用程序，负责初始化系统并加载内核。它使用 `uefi` crate 与 UEFI 服务进行交互。

### 2.2. 内核 (Kernel)

`kernel` 是操作系统的核心，提供基础服务。

---

## 3. 核心组件

### `main.rs`
该文件包含内核的入口点 (`_start`)。它负责初始化所有内核子系统，包括内存、中断、系统调用和调度器，然后在启动调度循环。

### `interrupts.rs`
该文件设置中断描述符表（IDT），用于处理 CPU 异常，如断点、页错误和双重故障。这对于系统稳定性和调试至关重要。

### `memory.rs`
此模块提供基础的内存管理功能。它初始化了堆分配器（`LockedHeap`），并包含一个用于页面管理的简单物理帧分配器。

### `process.rs`
定义了 `Process` 结构体，用于表示一个进程，包含其 PID、状态和执行上下文。它还管理一个全局进程表。

### `ipc.rs`
实现了一个简单的基于消息传递的进程间通信（IPC）机制。它使用一个全局消息队列来允许进程发送和接收数据。

### `scheduler.rs`
包含一个简单的轮转调度器。它维护一个就绪进程队列，并在它们之间进行切换。

### `syscall.rs`
此模块定义了系统调用的接口并提供了一个基本的处理程序。它允许用户空间进程向内核请求服务。

---

## 4. 构建和运行

（本节为模板，您可能需要根据您的 `Makefile` 填写具体命令。）

要构建此项目，您通常需要一个 Rust nightly 工具链和 `cargo-xbuild`。

```sh
# 切换到正确的工具链
rustup override set nightly

# 构建内核
make build-kernel

# 构建引导加载程序
make build-bootloader

# 创建可引导镜像
make image

# 在 QEMU 中运行
make run