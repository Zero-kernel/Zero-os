[Switch to English (切换到英文)](README.md)

# Nilix

一个以安全为先的混合微内核操作系统，使用 Rust 编写，面向 x86_64 架构。

> **Nilix** 是一个递归缩写 —— **N**ilix **I**s **L**inux **I**ndependent e**X**istence（“Nilix 是独立于 Linux 的存在”）—— 沿袭 GNU、Linux 的自指命名传统。这个名字也概括了它的定位：与 Linux **兼容**（字节精确的系统调用 ABI 可原样运行真实的 musl libc 程序），却又**独立**于 Linux（自有的、从零用 Rust 编写的内核，而非分叉）。

**设计原则：** 安全性 > 正确性 > 效率 > 性能

---

## 1. 概述

Nilix 是一个企业级混合内核，灵感来自 Linux 的模块化设计，并经过 **172 轮持续安全审计**
加固。它将能力（capability）与 LSM 门控的内核内热路径相结合，并规划演进为一个去特权化的
Linux 兼容用户态人格（personality）。

- **内存安全** —— 完全使用 Rust（`no_std`）编写，配合硬件保护（NX、W^X、SMEP/SMAP/UMIP）
  以及 KASLR/KPTI。
- **进程隔离** —— 每进程独立地址空间、写时复制（COW）fork、用户栈守护页。
- **SMP** —— 多核启动（最多 64 核）、每 CPU 的 MLFQ 调度、工作窃取负载均衡、IPI 驱动的
  TLB shootdown、RCU 与 lockdep。
- **安全框架** —— 对象能力、LSM 钩子层（40+ 钩子点）、seccomp/pledge 系统调用过滤，以及
  SHA-256 哈希链的防篡改审计日志。
- **容器** —— 五种命名空间（PID/mount/IPC/net/user）与 cgroups v2（CPU、内存、PID、I/O、
  FD、端口控制器）。
- **网络** —— 完整的软件 TCP/IP 协议栈（TCP 含 NewReno、窗口缩放、SYN cookies、连接跟踪，
  以及默认 DROP 的有状态防火墙）。
- **Linux ABI** —— 字节精确的 x86-64 系统调用面；一个真正的 **静态链接 musl libc 程序可端到端
  运行** 于用户态 ABI 之上（Phase U / 里程碑 M0）。

### 当前状态

**里程碑：** 接近 **1.0-Preview** —— Phase A–G 已完成；**Phase U**（用户态 ABI）进行中。
1.0-Preview 发布门禁在 R172 审计 + 当日修复后当前为 **已合格（QUALIFIED）**（0 个未决 HIGH）。
详见[第 6 节](#6-安全审计状态)。

| 子系统                         | 状态        | 要点                                                                                            |
| ------------------------------ | ----------- | ----------------------------------------------------------------------------------------------- |
| 启动与内存                     | ✅ 完成     | UEFI 静态 PIE 启动、高半区映射、预留感知伙伴分配器、页缓存、COW fork、守护页、OOM killer        |
| 进程与线程                     | ✅ 完成     | 每进程地址空间、fork/exec/clone、线程 + TLS、wait/僵尸回收、挂起任务看门狗                      |
| 调度器                         | ✅ 完成     | 每 CPU MLFQ、抢占式、工作窃取 + 周期性负载均衡、CPU 亲和性 / cpuset                             |
| IPC                            | ✅ 完成     | 管道、基于能力的消息队列、futex（含优先级继承）、POSIX 信号                                     |
| 安全加固                       | ✅ 完成     | W^X/NX、SMEP/SMAP/UMIP、KASLR、KPTI、Spectre/Meltdown 缓解、ChaCha20 CSPRNG、kptr 守护          |
| 安全框架                       | ✅ 完成     | 能力、LSM（40+ 钩子）、seccomp/pledge、SHA-256/HMAC 哈希链审计、合规配置                        |
| VFS 与存储                     | ✅ 完成     | ramfs、ext2、procfs、devfs、initramfs（CPIO）、cgroupfs、DAC + openat2 RESOLVE 标志、virtio-blk |
| 网络                           | ✅ 完成     | virtio-net、ARP、IPv4（含重组）、ICMP、UDP、TCP、conntrack、有状态防火墙                        |
| SMP 与并发                     | ✅ 完成     | LAPIC/IOAPIC、AP 启动（≤64 核）、IPI TLB shootdown、PCID/INVPCID、RCU、lockdep                 |
| 容器                           | ✅ 完成     | PID/mount/IPC/net/user 命名空间、cgroups v2（6 个控制器）                                       |
| IOMMU / VT-d                   | 🟡 基础设施 | 完整 Intel VT-d 驱动（DMA 隔离、中断重映射、故障处理）；DMAR 发现接线待完成                     |
| 实时补丁                       | 🟡 基础设施 | ECDSA P-256 签名的 kpatch、INT3 detour、fail-closed 的 LSM 门控                                 |
| 用户模式与 ABI（Phase U / M0） | 🟡 进行中   | Ring 3、100+ Linux 系统调用、SysV auxv、信号投递、静态 musl libc 端到端运行                     |
| CI 与质量门禁                  | ✅ 完成     | GitHub Actions（fmt/clippy、build、lint、boot+musl）、自定义 lint 门禁、本地优先且可 SSH 卸载的 pre-push 钩子      |

---

## 2. 项目结构

内核是一个由若干聚焦 crate（`kernel/<子系统>/`）组成的 Cargo workspace，每个 crate 负责单一
关注点。引导加载程序与用户态程序是独立的构建单元。

```text
Nilix/
├── bootloader/             # UEFI 引导：ELF 加载、重定位（PIE）、高半区分页、KASLR 偏移
├── kernel/
│   ├── arch/               # x86_64：IDT/异常、上下文切换、SYSCALL/SYSRET、GDT/TSS、APIC、SMP、IPI、INVPCID
│   ├── mm/                 # 伙伴分配器、堆、页表、页缓存、TLB shootdown、OOM killer、fallible_map
│   ├── sched/              # 每 CPU MLFQ 调度器 + 文档化的锁顺序（lockdep）
│   ├── ipc/                # 管道、基于能力的消息队列、futex（含 PI）、WaitQueue/KMutex/Semaphore
│   ├── kernel_core/        # PCB 与进程表、fork（COW）、exec + ELF 加载器、信号、命名空间、cgroups、RCU、系统调用
│   ├── cap/                # 对象能力模型（CapId、CapRights、CapTable）
│   ├── lsm/                # Linux 安全模块钩子层 + 策略
│   ├── seccomp/            # seccomp/pledge 系统调用过滤（类 BPF 虚拟机）
│   ├── audit/              # SHA-256 / HMAC 哈希链防篡改审计日志
│   ├── crypto/             # 共享 no_std 加密（SHA-256、ECDSA P-256），供审计 + 实时补丁使用
│   ├── compliance/         # 加固配置（Secure / Balanced / Performance）
│   ├── security/           # W^X、NX、KASLR、KPTI、Spectre/Meltdown、kptr 守护、RNG、内存加固
│   ├── vfs/                # VFS 核心、ramfs、ext2、procfs、devfs、initramfs、cgroupfs、挂载命名空间
│   ├── block/              # 块层 + virtio-blk 驱动（PCI/MMIO）、BIO 队列
│   ├── virtio/             # 共享 VirtIO 传输（virtqueue）
│   ├── net/                # TCP/IP 栈：virtio-net、ARP、IPv4、ICMP、UDP、TCP、conntrack、防火墙、套接字
│   ├── iommu/              # Intel VT-d：DMAR 解析、域、故障处理、中断重映射
│   ├── cpu_local/          # 每 CPU 数据（CpuLocal<T>）、LAPIC-ID ↔ CPU 索引映射
│   ├── tlb_ops/            # PCID / INVPCID TLB 失效原语
│   ├── livepatch/          # 签名的实时内核补丁（kpatch 风格）
│   ├── trace/              # 静态 tracepoint、每 CPU 计数器、挂起任务看门狗
│   ├── klog/               # 配置感知的内核日志（klog!/klog_force!/kprintln!）
│   ├── drivers/            # VGA / 串口（UART 16550）/ PS-2 键盘
│   ├── src/                # 内核入口（main.rs）、运行时测试、Ring-3 启动诊断
│   └── kernel.ld           # 链接脚本
├── userspace/              # Ring-3 程序：shell、syscall_test、hello_musl.c（静态 musl 一致性程序）
├── scripts/                # CI 门禁脚本：boot_check.sh、musl_check.sh、smp_check.sh、iommu_check.sh…
├── docs/                   # roadmap.md、roadmap-enterprise.md、next-phase-plan.md、review/（QA 报告）
├── .github/workflows/ci.yml  # GitHub Actions 流水线
├── .githooks/pre-push      # 本地优先的 fmt + clippy 门禁（可选 SSH 卸载）
└── Makefile                # 构建 / 运行 / lint / 门禁 目标
```

---

## 3. 核心组件

### 3.1 启动与内存

- **UEFI 启动** —— 引导程序加载静态 PIE 的 `kernel.elf`，应用 `R_X86_64_RELATIVE` 重定位
  （配合 RDRAND 生成的 KASLR 偏移），建立 4 级分页，恒等映射低地址区供硬件访问，并将高半区
  内核映射到 `0xFFFFFFFF80000000`。
- **伙伴分配器** —— 预留感知的物理页分配：堆/内核/帧缓冲/UEFI 区域按页预留，永不与分配器
  冲突（溢出时 fail-closed）。
- **COW fork** —— 页表深拷贝，共享带引用计数的物理帧；fork 时进行 cgroup 内存计费。
- **页缓存** —— 全局哈希 LRU + 每 inode 索引、页状态跟踪、脏页回写，内存压力下回收。
- **守护页** —— 未映射的守护页保护内核栈与双重故障 IST 栈；用户栈带一个永久未映射的守护页。
- **OOM killer** —— 水位触发的缓存回收、每进程评分、带审计的紧急杀进程。

### 3.2 进程、线程与调度器

- **PCB** —— 完整的每任务状态：pid/tgid、优先级、CPU 亲和性、cgroup 成员、TLS（FS/GS base）、
  seccomp/pledge 状态、命名空间链、每任务资源限制。
- **fork / exec / clone** —— 独立地址空间（或 `CLONE_VM` 下共享的 `MmState`）；线程经
  `CLONE_THREAD` 携带 TLS、`set_tid_address`，以及用于退出时 futex 清理的 `robust_list`。
- **调度器** —— 每 CPU 的多级反馈队列，含饥饿检测与优先级提升、时钟节拍抢占、工作窃取、
  周期性负载均衡，以及 CPU 亲和性 / cpuset 隔离。
- **wait / exit** —— 经 `wait4`/`waitpid` 回收僵尸、向父进程投递 `SIGCHLD`、孤儿重新归属；
  跨 CPU 延迟终止；挂起任务看门狗心跳。

### 3.3 IPC 与信号

- **管道** —— FIFO 缓冲、读写端引用计数、信号可中断的阻塞 I/O。
- **消息队列** —— 基于能力的端点，按 IPC 命名空间分区。
- **Futex** —— `FUTEX_WAIT`/`FUTEX_WAKE`，以及带优先级继承的 `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI`
  和每线程组的 bucket 预算。
- **信号** —— 64 个 POSIX 信号、每任务的阻塞掩码与处置；在系统调用返回路径上同步投递处理函数，
  配合具备 SROP 防御的 `rt_sigframe` 构造器与 `rt_sigreturn`；阻塞的系统调用 EINTR 唤醒。

### 3.4 安全框架

- **能力（Capabilities）** —— 不可伪造的 `CapId`（代际 + 索引）、`CapRights` 位标志、每进程的
  `CapTable`，以及由 LSM 门控并审计的能力系统调用（分配 / 撤销 / 委派）。*（fd 表 → 能力的
  整合仍在进行中；文件描述符访问目前仍是环境式的。）*
- **LSM** —— 可插拔的 `LsmPolicy` trait，40+ 钩子点遍布系统调用、任务生命周期、VFS、内存、
  IPC、信号、网络与实时补丁；默认策略为放行，并支持全拒绝及自定义策略。拒绝为 fail-closed
  并审计。
- **Seccomp / Pledge** —— 类 BPF 过滤虚拟机，18 个 pledge promise 与快速放行位图；启动期分区
  自检防止 seccomp/分派出现分歧。
- **审计** —— SHA-256（FIPS 180-4）哈希链事件，可选 HMAC-SHA256 模式；带溢出跟踪的有界环形
  缓冲；基于游标、不消费的导出接口。
- **合规配置** —— Secure / Balanced / Performance，各自调节 W^X 严格度、Spectre 缓解、kptr
  守护、审计容量与日志详细度。

### 3.5 内存安全加固

W^X 强制（没有页面同时可写且可执行）、数据页 NX、SMEP/SMAP/UMIP、KASLR（内核堆/栈/mmap +
text 重定位基础设施）、KPTI 双页表隔离、Spectre/Meltdown 缓解（IBRS/IBPB/STIBP/SSBD、RSB
填充、SWAPGS+LFENCE）、由 RDRAND/RDSEED 播种的 ChaCha20 CSPRNG，以及内核指针混淆（kptr 守护）。

### 3.6 VFS 与存储

VFS inode 抽象之上有 ramfs、ext2（读/写，页缓存支持）、procfs（`/proc/self`、
`/proc/[pid]/…`、`/proc/meminfo`）、devfs（`/dev/null|zero|console`）、initramfs（CPIO
`newc`）与 cgroupfs。POSIX DAC（owner/group/other、umask、粘滞位）、`openat2` 的 `RESOLVE_*`
标志（`NO_SYMLINKS`/`BENEATH`/`IN_ROOT`/`NO_XDEV`/`NO_MAGICLINKS`）、符号链接循环检测，以及
每命名空间的写时复制挂载表。存储由 virtio-blk 驱动（PCI + MMIO）和 BIO 请求层支撑。

### 3.7 网络

软件 TCP/IP 栈：virtio-net 驱动、DMA 友好的数据包缓冲、Ethernet/ARP（反欺骗、限速）、IPv4
（校验和、源路由拒绝、带重叠检测的分片重组）、ICMP 与 UDP。TCP 实现完整状态机与三次握手、
RFC 6298 RTT/RTO（含 Karn 算法）、NewReno 拥塞控制、窗口缩放、SYN cookies、listen/accept 与
优雅关闭。协议之上是连接跟踪、优先级有序的有状态防火墙（ACCEPT/DROP/REJECT、默认 DROP），
以及带逐钩子 LSM 仲裁的基于能力的套接字 API。

### 3.8 SMP、IOMMU 与并发

LAPIC/IOAPIC 初始化、经 INIT-SIPI-SIPI 的 AP 启动（最多 64 核）、五种 IPI 类型、带每 CPU
邮箱的 IPI 驱动 TLB shootdown、PCID/INVPCID、每 CPU 数据（`CpuLocal<T>`）、RCU 宽限期回收，
以及带 lockdep 检查器的文档化 9 级锁顺序。Intel VT-d 驱动提供 DMAR 解析、域管理、DMA 二级页表、
故障处理与中断重映射（DMAR 表发现的接线是剩余的启动步骤）。

### 3.9 容器

五种命名空间 —— PID（init 级联杀）、mount（CoW 表）、IPC（System V）、network（每命名空间
设备/套接字）、user（供非特权容器的 UID/GID 映射）—— 由 `clone(2)`/`unshare(2)`/`setns(2)`
驱动。Cgroups v2 提供 CPU（`cpu.weight`/`cpu.max`）、内存（`memory.max`/`memory.high` + OOM
事件）、PID、I/O（令牌桶 `io.max`）、FD 与端口控制器，经由系统调用与 `/sys/fs/cgroup`
cgroupfs 挂载暴露，并支持子树委派。

### 3.10 用户模式与 Linux ABI（Phase U / M0）

经 SYSCALL/SYSRET 的 Ring-3 执行、**100+ Linux x86-64 系统调用**（113 个已分派）、初始栈上完整的
SysV AMD64 `auxv` 构造、带 DoS/损坏防护的 ELF 加载、`#!` shebang 解析、基于路径的 `execve` 与
原生镜像 spawn 的消歧，以及信号投递。标志性里程碑：**一个真正的静态链接 musl libc 程序可端到端
运行** —— crt 启动消费 auxv、musl stdio 的 `printf`→`writev`，以及干净的 `exit(0)` —— 由
`musl-check` 一致性门禁证明。

> M0 是基础性的，且有意与完整 Linux 存在差异：资源限制为建议性（尚未在 `brk`/`mmap` 上强制
> 执行），尚无动态链接（`ld.so`/vDSO）或用户态 ASLR，且 `readlink`/`symlink`/`chown` 等少数
> 系统调用被推迟。这些都在 `docs/next-phase-plan.md` 的 Phase U 中跟踪。

---

## 4. 构建与运行

### 前置条件

- Rust **nightly**，带 `rust-src` 与 `llvm-tools-preview`（在 `rust-toolchain.toml` 中固定；
  目标 `x86_64-unknown-none` 与 `x86_64-unknown-uefi`）
- 带 OVMF 固件的 QEMU（`qemu-system-x86_64`），用于 UEFI 启动
- GNU Make
- `musl-tools`（`musl-gcc`）—— 仅用于 musl 一致性门禁

### 常用命令

```bash
make build           # 将引导程序 + 内核构建到 EFI 系统分区（esp/）
make run             # 在 QEMU 中运行（图形 VGA 窗口）
make run-serial      # 在终端以串口控制台运行
make run-shell       # 构建 + 运行交互式 shell（串口）
make run-blk         # 挂载一个 64 MB 的 ext2 virtio-blk 磁盘
make run-smp         # 多核启动（SMP_CPUS=N，默认 2）
make debug           # 启动 QEMU 并暂停，等待 GDB 连接到 :1234
make clean           # 清理构建产物
```

QEMU 以暴露 `+smep,+smap,+umip,+rdrand` 的 CPU 模型启动，因此 SMEP/SMAP/UMIP 与硬件 RNG
默认即被使用。运行 `make help` 查看完整目标列表。

---

## 5. 持续集成与质量门禁

Nilix 自动强制执行正确性、风格与启动健康度——相同的门禁在 CI 中运行，贡献者也可在本地运行
（维护者的 Windows 镜像会卸载到 Linux 构建主机）。

### 5.1 GitHub Actions（`.github/workflows/ci.yml`）

在每次向 `main` 的 push 与 pull request 时运行，同一 ref 上进行中的运行会被取消。四个并行作业：

| 作业                       | 运行                                       | 断言                                                  |
| -------------------------- | ------------------------------------------ | ----------------------------------------------------- |
| **rustfmt + clippy** | `make fmt-check` · `make clippy`      | 所有 crate rustfmt 干净；clippy 无错误                |
| **build**            | `make build`                             | 引导程序 + 内核编译通过（PIE / build-std / 加固标志） |
| **custom lints**     | `make lint`                              | 四个基于 grep 的源码门禁通过（见下）                  |
| **boot + musl**      | `make boot-check` · `make musl-check` | 内核干净启动至用户态，且静态 musl 程序端到端运行      |

### 5.2 启动与一致性门禁

与 `make test`（即 `timeout 10 qemu … || true`，总是退出 0）不同，这些门禁的**退出码是真实的**——
从串口日志与 QEMU `-d int` 中断日志读取，而绝不从 QEMU 自身的退出码读取。

- **`make boot-check`**（`scripts/boot_check.sh`）—— 在 QEMU 下启动，除非内核到达用户态 /
  其空闲循环 **且** 发生了零次 NX 违例取指缺页（D1-BOOT-NX-KASLR-LAYOUT 类缺陷的
  `v=0e e=0011` 签名），否则失败。
- **`make musl-check`**（`scripts/musl_check.sh`）—— 以 `--features musl_test` 构建，使内嵌的
  `hello_musl.elf` 成为 Ring-3 init 程序，然后断言**以下全部**：libc 可归因的 `printf` 标记
  （`42 * 2 = 84`）、`musl libc test passed!` 成功行、干净的 `exit code 0`、零次 NX 违例 #PF，
  以及无内核 panic。该门禁是双向且 fail-closed 的——默认的（原生 Rust）内核同样退出 0，但绝不会
  打印 libc 标记，因此会使门禁失败。

### 5.3 自定义源码 lint（`make lint`）

轻量的基于 grep 的门禁，捕获编译器无法发现的回归：

| 门禁                 | 强制                                                                                                                                     |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `lint-release`     | 内核代码中无未门控的 `println!`（仅 `drivers/`、`klog/` 允许）；改用 `kprintln!` / `klog!` / `klog_force!`                   |
| `lint-smap`        | 仅 `usercopy.rs` 可实例化 `UserAccessGuard`（SMAP 窗口最小化）                                                                       |
| `lint-fetch-add`   | 核心/VFS 路径中 ID/引用计数不得用裸 `fetch_add(1)` —— 改用 `fetch_update` + `checked_add`（或显式 `// lint-fetch-add: allow`） |
| `lint-repr-c-copy` | 用户边界上对 `#[repr(C)]` 结构体的每个 `from_raw_parts` / `copy_nonoverlapping` / `transmute` 都必须带 padding 安全注解          |

### 5.4 风格门禁与 pre-push 钩子

- **`make fmt-check`** —— 对 workspace 与 userspace 执行 `cargo fmt --all --check`。
  `rustfmt.toml` 固定 `newline_style = "Windows"`，因为仓库存储 CRLF blob。
- **`make clippy`** —— 在三个构建单元（引导程序、内核、userspace）上分别于隔离的 target 目录
  运行 clippy；deny-by-default 的正确性错误会使构建失败。
- **`.githooks/pre-push`** —— 选择性启用（`make hooks`）。钩子是**本地优先**的：当存在本地 Rust
  工具链时直接在本地运行 `make fmt-check` + `make clippy`；对于无工具链的镜像，可经 SSH 卸载到
  远程（`git config zeroos.remote`/`zeroos.remoteDir`）。用 `SKIP_PREPUSH=1 git push` 跳过单次
  push。仓库还提供了等效的 pre-commit 框架配置（`.pre-commit-config.yaml`）——详见
  [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 6. 安全审计状态

Nilix 在持续的对抗式评审流程下开发：每一轮审计内核、按严重程度记录发现、修复它们，并在
该轮结束前经双向同行评审（Claude Code + Codex MCP）收敛。

| 指标                 | 数值                                     |
| -------------------- | ---------------------------------------- |
| 审计轮次             | **172**                            |
| 累计发现             | ~1,254                                   |
| 已修复/解决的发现    | ~1,152                                   |
| 最新轮次             | R172（`docs/review/qa-2026-06-23.md`） |
| 1.0-Preview 发布门禁 | **已合格** —— 0 个未决 HIGH      |

最近一轮（**R172**）是对新用户态 ABI 基础的首次完整审计。它暴露了一个既有的上下文切换 CRITICAL
（一个全新任务的首次切出可能携带用户 RIP 恢复进入 Ring-0）以及八个 HIGH 发现；全部于当日修复并
经同行收敛，恢复了 0-HIGH 连胜并重新使门禁合格。逐轮报告位于 `docs/review/`，实时计划见
`docs/next-phase-plan.md`。

---

## 7. 路线图

**已完成**

- **Phase A** —— 安全基础：usercopy/SMAP API、Spectre/Meltdown、审计升级、SMP 就绪接口
- **Phase B** —— 能力 + LSM + seccomp 框架，集成进系统调用/VFS/进程路径
- **Phase C** —— 存储：virtio-blk、页缓存、ext2、procfs/devfs/initramfs、OOM killer、`openat2`
- **Phase D** —— 网络：完整 TCP/IP 栈，含 conntrack 与有状态防火墙
- **Phase E** —— SMP 与并发：AP 启动、IPI TLB shootdown、每 CPU 调度、RCU、lockdep、futex PI
- **Phase F** —— 资源治理：五种命名空间、cgroups v2 控制器、IOMMU/VT-d 驱动
- **Phase G** —— 生产就绪加固：KASLR（H.2）、KPTI（H.3）、tracing 与看门狗、实时补丁

**进行中**

- **Phase U —— 用户模式与 ABI**（*Compat-ZeroABI*）：能力优先的原生核心，加上去特权化的
  Linux 兼容人格。里程碑 **M0** 在既有 Linux cABI 之上构建用户态基础（auxv、信号投递、缺失的
  系统调用、exec 消歧、用户栈守护），由静态 musl 一致性门禁证明，之后再提交原生/人格分叉。
- IOMMU DMAR 表发现接线；完整的按需增长用户栈；能力支撑的 fd 表。

**未来**

- 动态链接（`ld.so`/vDSO）、glibc + OCI 兼容、用户态 ASLR
- 每租户网络资源预算、NUMA 感知调度、KVM/虚拟机管理程序支持

完整路线图见 [docs/roadmap.md](docs/roadmap.md) 与
[docs/roadmap-enterprise.md](docs/roadmap-enterprise.md)。

---

## 8. 贡献指南

完整的环境搭建（工具链、钩子、PR 流程）见 **[CONTRIBUTING.md](CONTRIBUTING.md)**。简而言之：

1. 拥有本地 Rust 工具链的贡献者在本地完成构建、lint 与测试——与 CI 完全一致。（维护者的
   Windows 镜像没有工具链，会卸载到 Linux 构建主机。）
2. 推送前运行 `make build`、`make lint`、`make boot-check`，并（对 ABI 改动）运行
   `make musl-check`；用 `make hooks` 启用 pre-push 的 `fmt-check` + `clippy` 钩子。
3. 新功能需要更新文档；bug 修复应包含回归测试（内核在启动时运行内核内自检）。
4. Git 提交为手动 —— 不会自动提交或自动推送。

---

## 9. 许可证

本项目用于教育和研究目的。

---

## 10. 参考资料

- [OSDev Wiki](https://wiki.osdev.org)
- [用 Rust 写操作系统](https://os.phil-opp.com)
- [Linux 内核源码](https://kernel.org)
- [seL4 微内核](https://sel4.systems)
