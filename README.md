[Switch to Chinese (切换到中文)](README_zh.md)

# ZERO-os

## 1. Overview

This is a simple microkernel written in Rust, designed to explore the basic principles of operating system kernels. It includes a UEFI bootloader and a kernel with basic features like memory management, process management, IPC, and scheduling. The project is structured as a Cargo workspace with two main components: `bootloader` and `kernel`.

---

## 2. Project Structure

The project workspace is organized as follows:

```
rust-microkernel/
├── bootloader/         # UEFI bootloader
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
├── kernel/             # Microkernel code
│   ├── src/
│   │   ├── main.rs         # Kernel entry and initialization
│   │   ├── interrupts.rs   # Interrupt handling
│   │   ├── memory.rs       # Memory management
│   │   ├── process.rs      # Process management
│   │   ├── ipc.rs          # Inter-Process Communication (IPC)
│   │   ├── scheduler.rs    # Scheduler
│   │   └── syscall.rs      # System call handling
│   ├── kernel.ld       # Linker script
│   └── Cargo.toml
├── Cargo.toml          # Workspace configuration
└── Makefile            # Build scripts
```

### 2.1. Bootloader

The `bootloader` is a UEFI application responsible for initializing the system and loading the kernel. It uses the `uefi` crate to interact with UEFI services.

### 2.2. Kernel

The `kernel` is the core of the operating system, providing fundamental services.

---

## 3. Core Components

### `main.rs`
This file contains the kernel's entry point (`_start`). It initializes all kernel subsystems, including memory, interrupts, system calls, and the scheduler, before starting the scheduling loop.

### `interrupts.rs`
It sets up the Interrupt Descriptor Table (IDT) to handle CPU exceptions like breakpoints, page faults, and double faults. This is crucial for system stability and debugging.

### `memory.rs`
This module provides basic memory management functionalities. It initializes the heap allocator (`LockedHeap`) and includes a simple physical frame allocator for page management.

### `process.rs`
Defines the `Process` structure, which represents a process with its PID, state, and execution context. It also manages a global process table.

### `ipc.rs`
Implements a simple message-passing mechanism for Inter-Process Communication (IPC). It uses a global message queue to allow processes to send and receive data.

### `scheduler.rs`
Contains a simple round-robin scheduler. It maintains a ready queue of processes and switches between them.

### `syscall.rs`
This module defines the interface for system calls and provides a basic handler. It allows user-space processes to request services from the kernel.

---

## 4. Build and Run

(This section is a template. You may need to fill in specific commands based on your `Makefile`.)

To build the project, you typically need a Rust nightly toolchain and `cargo-xbuild`.

```sh
# Switch to the correct toolchain
rustup override set nightly

# Build the kernel
make build-kernel

# Build the bootloader
make build-bootloader

# Create a bootable image
make image

# Run in QEMU
make run
