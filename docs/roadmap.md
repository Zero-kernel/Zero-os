# Zero-OS Development Roadmap

**Last Updated:** 2026-02-06
**Architecture:** Security-First Hybrid Kernel
**Design Principle:** Security > Correctness > Efficiency > Performance

This document outlines the development roadmap for Zero-OS, a microkernel operating system written in Rust for x86_64 architecture, designed to evolve toward enterprise-grade security.

---

## Executive Summary

### Current Status: Phase G IN PROGRESS (Production Readiness)

Zero-OS has completed SMP infrastructure and resource governance:
- **99 security audits** with 496 issues found, 454 fixed (91.5%)
- **R95-R99 Security**: 28 new issues found, 27 fixed in-round + 16 retroactive fixes (ext2 filesystem hardening, conntrack bypass, DMA/VirtIO lifecycle, syscall safety, NetBuf overflow, signal handling)
- **R94 Security**: 16 issues found, **ALL 16 FIXED** (ECDSA KAT, FIPS fail-closed, PID namespace, TLB shootdown, kdump scrub, HMAC key scrub, firewall default DROP, IOMMU legacy signaling, verify_chain_hmac, **IOMMU kernel domain SLPT**)
- **R93 Security Debt**: ALL 18 issues FIXED (fork namespace escape, livepatch hardening, fail-open patterns, cgroup escape, kdump, TLB shootdown, FIPS KATs, panic redaction)
- **Ring 3 user mode** with SYSCALL/SYSRET support
- **Thread support** with Clone syscall and TLS inheritance
- **VFS** with POSIX DAC permissions, procfs, ext2
- **Security hardening**: W^X, SMEP/SMAP/UMIP, SHA-256 hash-chained audit, CSPRNG
- **Phase A**: ~90% complete (Usercopy ✅, Spectre ✅, SMP-stubs ✅, Audit gate ✅, KASLR partial)
- **Phase B**: ✅ **COMPLETE** (Cap/LSM/Seccomp integrated into syscall paths)
- **Phase C**: ✅ **COMPLETE** (virtio-blk, page cache, ext2, procfs, OOM killer, openat2, devfs read/write)
- **Phase D**: ✅ **COMPLETE** (Full network stack with loopback validation)
  - D.1: virtio-net driver, NetDevice trait ✅
  - D.2: TCP client/server with RFC 6298 RTT ✅
  - D.3: TCP hardening (MSS/WS validation, SYN cookies) ✅
  - D.4: Runtime loopback tests (UDP, TCP SYN, conntrack, firewall) ✅
- **Phase E**: ✅ **COMPLETE** (SMP & Concurrency)
  - E.1: LAPIC/IOAPIC initialization ✅, AP boot ✅, IPI ✅
  - E.2: TLB shootdown ✅ (IPI-based, PCID support, per-CPU queue)
  - E.3: PerCpuData ✅, Per-CPU runqueues ✅, FPU save areas ✅
  - E.4: RCU ✅ (timer-driven grace periods, callback batching), Lockdep ✅ (dependency graph), **Futex PI ✅** (R72-1, R72-2)
  - E.5: Per-CPU scheduler ✅, Load balancing ✅, CPU affinity syscalls ✅
  - E.6: Cpuset CPU isolation ✅ (runtime test added)
- **Phase F**: ✅ **COMPLETE** (Resource Governance)
  - F.1: Namespaces ✅ **COMPLETE**
    - PID namespace ✅ (CLONE_NEWPID, cascade kill, namespace-local PIDs)
    - Mount namespace ✅ (CLONE_NEWNS, sys_setns, per-namespace mount tables, R74-2 materialization fix)
    - IPC namespace ✅ (CLONE_NEWIPC, endpoint table partitioned by namespace - R75-2)
    - Network namespace ✅ (CLONE_NEWNET, socket table partitioned by namespace - R75-1)
    - User namespace ✅ (CLONE_NEWUSER, UID/GID mapping, unprivileged container support)
  - F.2: Cgroups v2 ✅ **COMPLETE**
    - Core infrastructure ✅ (CgroupNode, Registry, limits, stats, deleted flag - R77-1)
    - PIDs controller ✅ (fork protection, task tracking)
    - CPU controller ✅ (cpu.weight time slice scaling, cpu.max quota enforcement with throttling)
    - Memory controller ✅ (try_charge_memory/uncharge_memory in mmap/munmap/brk)
    - Syscalls ✅ (sys_cgroup_create/destroy/attach/set_limit/get_stats)
    - IO controller ✅ (io.max bps/iops with token bucket, throttle/wait_for_io_window, stats)
    - cgroup2 filesystem ✅ (/sys/fs/cgroup cgroupfs mount, control files)
  - F.3: IOMMU/VT-d ✅ **COMPLETE**
    - Core infrastructure ✅ (DMAR parser, VT-d driver, domain management, public API)
    - Fail-closed security ✅ (ensure_iommu_ready, translation_enabled checks)
    - DMA isolation ✅ (second-level page tables with AGAW support)
    - Device domain binding ✅ (context table programming with validation)
    - Interrupt remapping ✅ (IRTE allocation, MSI passthrough)
    - Fault handling ✅ (FRI rotation, flood mitigation, address redaction)
    - Device isolation ✅ (bus master disable, PCI config serialization)
    - Device detach ✅ (atomic domain tracking, multi-segment support)
    - VM passthrough ✅ (create_vm_domain, assign/unassign_device_to_vm, R88 hardening)
- **R91**: current_pid() IRQ deadlock ✅, CpuLocal stack overflow ✅, Profiler control race ✅ (ALL 3 FIXED)
- **R90**: IOMMU fail-closed ✅, Net NS ingress ✅, pids.max CAS ✅, Migrate lock ✅ (ALL 4 FIXED)
- **R88**: VM passthrough IR enable ✅, Unassign cleanup order ✅ (ALL 2 FIXED)
- **R93**: Fork namespace escape ✅, Livepatch compile guard ✅, Fail-open patterns ✅, Cgroup attach ✅, ELF cgroup ✅, Identity map ✅, kdump fallback ✅, TLB shootdown ✅ (ALL 9 CRITICAL/HIGH FIXED)
- **R77**: TCP child socket quota ✅, Fork cpuset rollback ✅, delete_cgroup race ✅, Memory accounting CAS ✅, Namespace guard ✅ (ALL 5 FIXED)
- **R75**: move_device permission check ✅, namespace FD refcount ✅, **IPC endpoint isolation ✅**, **Socket table isolation ✅** (ALL 4 FIXED)
- **R76**: Socket namespace enforcement ✅, Namespace count limits ✅, Per-namespace socket quotas ✅ (ALL 3 FIXED)
- **R54**: ISN secret auto-upgrade ✅, Challenge ACK rate limiting ✅
- **R55**: NewReno congestion control ✅ (RFC 6582 partial ACK handling)
- **R56**: Limited Transmit ✅ (RFC 3042 adapted for immediate-send architecture)
- **R57**: Idle cwnd validation ✅ (RFC 2861 stale burst prevention)
- **R58**: Window Scaling ✅ (RFC 7323 WSopt negotiation, up to 256KB windows)
- **R59**: Ephemeral port randomization ✅ (RFC 6056 CSPRNG)
- **R60**: IP fragment reassembly ✅ (RFC 791/815/5722 security hardening)
- **R61**: SYN cookies ✅ (RFC 4987 stateless SYN flood protection)
- **R66**: TCP options validation ✅, VirtIO hardening ✅, Runtime network tests ✅
- **R72**: RCU memory ordering fix ✅, PI chain iterative ✅, Futex waiter cleanup ✅
- **R74**: Mount namespace materialization fix ✅ (eager snapshot prevents mount leakage)

### Gap Analysis vs Linux Kernel

| Category | Linux | Zero-OS | Gap |
|----------|-------|---------|-----|
| **SMP** | 256+ CPUs | Multi-core (per-CPU runqueues, load balancing, affinity) | CPU isolation, NUMA |
| **Security Framework** | LSM/SELinux/AppArmor | LSM + Seccomp + Capabilities | ✅ Framework complete, policies needed |
| **Network** | Full TCP/IP stack | TCP (w/retransmission + NewReno CC + Window Scaling + SYN cookies + Conntrack + Firewall + Options validation), UDP, ICMP | SACK, Timestamps |
| **Storage** | ext4/xfs/btrfs/zfs | virtio-blk + ext2 + procfs | Extended FS support needed |
| **Drivers** | 10M+ LOC drivers | VGA/Serial/Keyboard/VirtIO | Driver framework needed |
| **Containers** | Namespaces/Cgroups | PID ✅, Mount ✅, IPC ✅, Network ✅, User ✅ namespaces; Cgroups v2 PIDs ✅, CPU ✅, Memory ✅, IO ✅, Syscalls ✅, cgroupfs ✅ | ✅ Container foundation complete |
| **Virtualization** | KVM/QEMU | IOMMU/VT-d ✅ (DMA isolation, device passthrough prep, interrupt remapping, VM domain API) | ✅ IOMMU complete, KVM/hypervisor pending |

---

## Completed Features

### Core Infrastructure (Phase 1-2)

- [x] UEFI Bootloader with ELF parsing
- [x] High-half kernel mapping (0xffffffff80000000)
- [x] VGA text mode driver + Framebuffer (GOP)
- [x] Serial port output (0x3F8)
- [x] IDT with 20+ exception handlers
- [x] Heap allocator (LockedHeap)
- [x] Buddy physical page allocator
- [x] GDT/TSS for user-kernel transitions
- [x] IST for double fault safety

### Process Management (Phase 3)

- [x] Process Control Block (PCB) structure
- [x] Enhanced scheduler (MLFQ with priority buckets)
- [x] Context switch framework (176-byte + FPU/SIMD)
- [x] Fork API with COW implementation
- [x] Clone syscall (CLONE_VM | CLONE_THREAD)
- [x] TLS inheritance for child threads
- [x] Per-process address space isolation (CR3)
- [x] Preemptive scheduling (timer connected)
- [x] IRQ-safe COW reference counting

### IPC (Phase 4)

- [x] Capability-based message queues
- [x] Pipes with blocking I/O
- [x] Futex (FUTEX_WAIT/FUTEX_WAKE)
- [x] Signals (SIGKILL, SIGTERM, SIGSTOP, SIGCONT)
- [x] Per-process file descriptor table

### VFS (Phase 5)

- [x] VFS layer with inode abstraction
- [x] ramfs (memory-backed)
- [x] devfs (/dev/null, /dev/zero, /dev/console)
- [x] POSIX DAC permissions (owner/group/other/umask)
- [x] Sticky bit semantics
- [x] Path traversal permission checks

### User Mode (Phase 6)

- [x] SYSCALL/SYSRET MSR configuration
- [x] IRETQ-based Ring 3 entry
- [x] System call framework (50+ defined, ~35 implemented)
- [x] User/kernel segment selectors (CS=0x23, SS=0x1B)

### Security Hardening

- [x] W^X enforcement (no writable+executable pages)
- [x] SMEP/SMAP/UMIP enabled
- [x] User pointer validation
- [x] mmap page zeroing (info leak prevention)
- [x] Kernel stack guard pages
- [x] CSPRNG (ChaCha20 + RDRAND/RDSEED)
- [x] kptr guard (kernel pointer obfuscation)
- [x] Spectre/Meltdown basic mitigations (IBRS/IBPB/STIBP)
- [x] Audit subsystem (hash-chained events)

---

## Architecture Vision: Hybrid Kernel

```
+------------------------------------------------------------------+
|                        USER SPACE                                 |
|  +---------------+  +---------------+  +---------------+          |
|  | FS Server     |  | Net Server    |  | Policy Daemon |          |
|  | (ext2, FAT)   |  | (TCP/IP L7)   |  | (LSM policy)  |          |
|  +-------+-------+  +-------+-------+  +-------+-------+          |
|          |                  |                  |                  |
|          v                  v                  v                  |
|  +----------------------------------------------------------+    |
|  |         Capability-Based IPC + Shared Memory              |    |
|  +----------------------------------------------------------+    |
+------------------------------------------------------------------+
|                       KERNEL SPACE                                |
|  +------------------+  +------------------+  +------------------+ |
|  | Scheduler        |  | VMM/PMM          |  | IPC Fast Path    | |
|  | (MLFQ + Per-CPU) |  | (COW, Page Cache)|  | (Ring Buffers)   | |
|  +------------------+  +------------------+  +------------------+ |
|  +------------------+  +------------------+  +------------------+ |
|  | Interrupt/Trap   |  | Block Layer      |  | Capability DB    | |
|  | (APIC/IOAPIC)    |  | (virtio-blk)     |  | + LSM Hooks      | |
|  +------------------+  +------------------+  +------------------+ |
|  +------------------+  +------------------+  +------------------+ |
|  | Network L2-L4    |  | Basic Drivers    |  | Audit Engine     | |
|  | (TCP/IP core)    |  | (Timer,RNG,UART) |  | (Hash-chained)   | |
|  +------------------+  +------------------+  +------------------+ |
+------------------------------------------------------------------+
|                        HARDWARE                                   |
+------------------------------------------------------------------+
```

### Design Rationale

**In-Kernel (Performance Critical)**:
1. Scheduler - Direct hardware access, minimal latency
2. VMM/PMM - Page tables, COW, page cache
3. IPC Fast Path - Zero-copy ring buffers
4. Interrupt Handling - APIC, exception handlers
5. Block Layer - I/O critical path
6. Network L2-L4 - TCP/IP core for DoS protection
7. Capability/LSM - Security-critical decisions
8. Audit - Tamper-evident logging

**User-Space (Isolation & Modularity)**:
1. File System Servers - ext2, tmpfs policy
2. Network L7 - Application protocols
3. Device Managers - Hot-plug, USB complex protocols
4. Policy Daemons - LSM policy loading, audit shipping
5. Init/Service Manager - PID 1 supervision

---

## Future Phases (Security-First Order)

### Phase A: Security Foundation [IN PROGRESS]

**Goal**: Establish minimum trusted base before adding features.

**Priority**: Critical
**Dependencies**: None (current baseline)
**Status**: ~80% Complete

#### A.1 Usercopy API Hardening ✅ COMPLETE

- [x] Unified `copy_from_user` / `copy_to_user` with SMAP guard (kernel/kernel_core/usercopy.rs)
- [x] Path string copy with length limits (`strncpy_from_user` with MAX_PATH)
- [x] Alignment and bounds validation (range checks, canonical address validation)
- [x] STAC/CLAC wrapper for all user memory access (`with_user_access!` macro)

#### A.2 Syscall Coverage (Partial)

- [ ] Eliminate all ENOSYS returns for defined syscalls (many still return ENOSYS)
- [x] Proper error code semantics (errno constants defined)
- [x] User-space signal handler infrastructure (signal dispatch in place)

#### A.3 Audit Enhancement (Mostly Complete)

- [x] Upgrade hash chain to SHA-256 (FNV-1a → SHA-256, domain separation)
- [x] Overflow handling policy (drop oldest with `dropped` counter)
- [x] Read-only export interface with capability gate (main.rs:450-469, CAP_AUDIT_READ)
- [ ] Persistent flush hook (for future storage)
- [ ] HMAC support (placeholder exists, not implemented)

#### A.4 KASLR/KPTI Preparation (Partial)

- [x] Linker script layering for randomization (KernelLayout struct with slide field)
- [x] KASLR slide reservation (with_slide() constructor ready)
- [x] KPTI dual page table skeleton (KptiContext with user_cr3/kernel_cr3)
- [ ] PCID support detection (field exists, not detected at boot)
- [ ] Actual KASLR slide application (layout remains fixed)

#### A.5 Spectre/Meltdown Hardening ✅ COMPLETE

- [x] Context switch IBPB on untrusted transition (issue_ibpb/try_ibpb)
- [x] RSB stuffing (spectre.rs rsb_fill with 32 entries)
- [x] IBRS/STIBP/SSBD detection and enablement (init() enables all supported)
- [x] Retpoline build option (cfg feature gate)
- [x] SWAPGS fence (CVE-2019-1125 mitigated in syscall.rs)
- [x] VulnerabilityInfo detection (reads IA32_ARCH_CAPABILITIES)

#### A.6 SMP-Ready Interfaces (Stubs) ✅ COMPLETE

- [x] Per-CPU data structure abstraction (kernel/cpu_local with CpuLocal<T>)
- [x] IPI type definitions (arch/ipi.rs - 5 types with vectors 0xFB-0xFF)
- [x] TLB shootdown API (mm/tlb_shootdown.rs - single-core with assert_single_core_mode)
- [x] Lock ordering documentation (sched/lock_ordering.rs - 9 levels documented)

**Security Requirements**:
- W^X/NX/SMEP/SMAP/UMIP enabled by default
- panic-on-UB configurable
- kptr guard active
- Audit cannot be disabled

**Testing Strategy**:
- Syscall fuzzer for all implemented syscalls
- Usercopy property tests
- Audit chain integrity verification
- KASLR randomness validation

---

### Phase B: Capability & MAC Framework [COMPLETE ✅]

**Goal**: Unified object capability model + LSM hooks + syscall filtering.

**Priority**: Critical
**Dependencies**: Phase A
**Status**: ✅ **COMPLETE** - All hooks integrated into syscall/process/VFS paths (verified 2026-01-02)

#### B.1 Capability System (Scaffolded - kernel/cap/)

```rust
// Implemented in kernel/cap/types.rs
pub struct CapId(u64);  // idx(32) | gen(32) ✅

pub enum CapObject {  // ✅ Defined
    Endpoint(Arc<Endpoint>),
    File(Arc<File>),
    Socket(Arc<Socket>),
    Shm(Arc<Shm>),
    Timer(Arc<Timer>),
    Process(Pid),
    Namespace(NsId),
}

bitflags! {
    pub struct CapRights: u64 {  // ✅ Defined
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXEC      = 1 << 2;
        const IOCTL     = 1 << 3;
        const ADMIN     = 1 << 4;
        const MAP       = 1 << 5;
        const BIND      = 1 << 6;
        const CONNECT   = 1 << 7;
        const SIGNAL    = 1 << 8;
        const BYPASS_DAC = 1 << 30;
    }
}
```

- [x] CapId structure with generation counter (types.rs)
- [x] CapObject enum with all variants (types.rs)
- [x] CapRights bitflags (types.rs)
- [x] CapEntry with rights and object (types.rs)
- [x] CapTable with allocate/lookup/revoke (lib.rs)
- [ ] **Integration**: fd_table -> CapId (NOT connected to syscalls)
- [ ] **Integration**: Process CapTable field (NOT in PCB)
- [ ] Delegation with rights restriction
- [ ] O_PATH/CLOEXEC/CLOFORK semantics

#### B.2 LSM Hook Infrastructure (Scaffolded - kernel/lsm/)

**Hook Points Defined**:
- Syscall: enter/exit ✅
- Process: fork/exec/exit/setuid ✅
- VFS: lookup/open/create/mmap/chmod/mount ✅
- IPC: mq send/recv, pipe, futex, shm ✅
- Signal: send_signal, ptrace ✅
- Network: socket/bind/connect/send/recv ✅

```rust
// Implemented in kernel/lsm/lib.rs
trait LsmPolicy: Send + Sync {  // ✅ Trait defined
    fn syscall_enter(&self, ctx: &SyscallCtx) -> Result<()>;
    fn file_open(&self, task: &Task, inode: &Inode, flags: OpenFlags) -> Result<()>;
    fn ipc_send(&self, task: &Task, ep: &Endpoint, bytes: usize) -> Result<()>;
    // ... other hooks
}
```

- [x] LsmPolicy trait with all hooks (lib.rs)
- [x] LsmContext wrapper (lib.rs)
- [x] DefaultPolicy (permissive) (policy.rs)
- [x] Hook registration infrastructure (lib.rs)
- [x] **Integration**: Hooks called from syscall dispatch (syscall.rs:1141, 1268)
- [x] **Integration**: Hooks called from VFS operations (file_open, file_create, etc.)
- [x] Build-time feature gate (lsm feature in Cargo.toml)

#### B.3 Seccomp/Pledge (Complete - kernel/seccomp/)

- [x] SeccompFilter structure (types.rs)
- [x] SeccompRule with syscall matching (types.rs)
- [x] SeccompAction enum (Allow/Log/Errno/Trap/Kill) (types.rs)
- [x] PledgePromise enum (Stdio/Rpath/Wpath/etc.) (types.rs)
- [x] Filter evaluation logic (lib.rs)
- [x] **Integration**: Per-process filter storage in PCB (process.rs:460-471)
- [x] **Integration**: sys_seccomp implemented (syscall 317, syscall.rs:3825)
- [x] Fork inheritance policy (syscall.rs:1703-1704)

#### B.4 Audit Integration (Complete)

- [x] AuditSecurityClass enum (Lsm/Seccomp/Capability) (audit/lib.rs)
- [x] emit_lsm_denial helper function (audit/lib.rs)
- [x] emit_seccomp_violation helper function (audit/lib.rs)
- [x] emit_capability_event helper function (audit/lib.rs)
- [x] **Integration**: Helpers called from security paths (lsm hooks emit audit events)
- [x] MAC decision logging from real denials (lsm::emit_denial_audit)
- [x] Seccomp violation tracking (seccomp::notify_violation)

**Security Requirements**:
- Default-allow policy initially
- Policy load requires ADMIN capability
- Deny decisions are fail-closed
- Generation counter prevents use-after-free

**Testing Strategy**:
- Capability/LSM/audit API unit tests
- Fork/exec inheritance behavior tests
- Seccomp rule matching (table-driven)
- Fuzzer coverage of syscall dispatch path

---

### Phase C: Storage Foundation [COMPLETE ✅]

**Goal**: Usable persistent storage with full permission chain.

**Priority**: High
**Dependencies**: Phase B (LSM/Capability hooks) ✅
**Status**: ✅ **COMPLETE** (2026-01-04) - All storage infrastructure ready, devfs read/write fixed

#### C.1 Block Layer ✅

- [x] virtio-blk driver (kernel/block/src/virtio/blk.rs)
- [x] BIO queue abstraction (kernel/block/src/lib.rs)
- [x] Minimal I/O scheduler (FIFO)
- [x] Request batching (VirtQueue)
- [x] PCI transport with 64-bit BAR support

#### C.2 Page Cache ✅

- [x] Radix/tree-based page cache (kernel/mm/page_cache.rs)
- [x] Page lifecycle with memory pressure handler
- [x] Writeback policy (dirty page tracking)
- [x] Cache invalidation (reclaim_pages)

#### C.3 File Systems ✅

- [x] ext2 read/write (kernel/vfs/ext2.rs)
- [x] tmpfs/ramfs (kernel/vfs/ramfs.rs)
- [x] procfs (/proc/self, /proc/[pid], /proc/meminfo) (kernel/vfs/procfs.rs)
- [x] Mount table and superblock cache
- [x] initramfs (CPIO archive) support
- [x] devfs character device read/write (FileHandle pattern)

#### C.4 Permission Chain Integration ✅

```
MAC (LSM hook) → CapRights → DAC (uid/gid/mode) → ACL →
inode flags (NOEXEC/IMMUTABLE/APPEND) → W^X (mmap)
```

- [x] All FS ops through LSM + DAC (R25-9 fix)
- [x] Path resolution depth limit (MAX_PATH_DEPTH)
- [x] RESOLVE_NO_SYMLINKS flag (openat2 syscall 437)
- [x] ResolveFlags: NO_SYMLINKS, NO_MAGICLINKS, BENEATH, IN_ROOT, NO_XDEV
- [x] O_NOFOLLOW, O_PATH open flags
- [x] Symlink loop detection (max 40 hops)
- [ ] Full capability integration

#### C.5 OOM Killer ✅

- [x] Memory pressure detection (kernel/mm/oom_killer.rs)
- [x] Process scoring (OomProcessInfo)
- [x] Kill policy (callback-based, audit event emission)

**Security Requirements**:
- Write operations enforce W^X
- Path traversal validates at each component
- Mount requires ADMIN capability
- No executable pages from untrusted storage without explicit allow

**Testing Strategy**:
- ext2 compatibility tests
- Page cache consistency tests
- Permission matrix (MAC/Cap/DAC/flags) table-driven
- fstress (concurrent open/read)

---

### Phase D: Network Foundation [IN PROGRESS]

**Goal**: Minimal usable network stack with kernel protection.

**Priority**: High
**Dependencies**: Phase B (Cap/LSM), Phase A (usercopy)
**Status**: D.1 Driver infrastructure complete. See [phase-d-network-plan.md](phase-d-network-plan.md) for detailed implementation plan.

**MVP Scope** (Phase D.1):
- virtio-net driver + IPv4 + ICMP (ping working)
- UDP sockets with LSM integration
- Security primitives (ISN randomization, rate limiting)
- TCP deferred to Phase D.2

#### D.1 Drivers ✅ COMPLETE

- [x] Shared VirtIO transport crate (kernel/virtio/)
- [x] NetBuf/BufPool packet buffer system (kernel/net/buffer.rs)
- [x] NetDevice trait abstraction (kernel/net/device.rs)
- [x] virtio-net driver MVP (kernel/net/virtio_net.rs)
- [x] VirtIO security hardening (R43: used.id validation, chain traversal limits, double-free detection)
- [ ] e1000 (fallback)
- [ ] Network device registration and discovery
- [ ] Interrupt coalescing

#### D.2 Protocol Stack [IN PROGRESS]

- [x] Ethernet frame parsing (kernel/net/ethernet.rs)
- [x] IPv4 header validation with security checks (kernel/net/ipv4.rs)
- [x] ICMP echo (ping) with rate limiting (kernel/net/icmp.rs)
- [x] Protocol stack integration (kernel/net/stack.rs)
- [x] Checksum verification (RFC 791 one's complement)
- [x] Source routing rejection (LSRR/SSRR per RFC 1122)
- [x] Broadcast echo suppression (Smurf attack prevention)
- [x] ARP protocol (kernel/net/arp.rs) - RFC 826 with anti-spoofing
- [x] UDP protocol (kernel/net/udp.rs) - RFC 768 with strict checksums
- [x] Socket API (kernel/net/socket.rs) - Capability-based UDP sockets with LSM hooks
- [x] **R48 FIXED**: VirtIO used.idx rewind attack prevention
- [x] **R48 FIXED**: NetBuf Drop impl (memory leak prevention)
- [x] **R48 FIXED**: ARP gratuitous learning restriction (poisoning prevention)
- [x] **R48 FIXED**: LSM check before UDP datagram copy (resource exhaustion)
- [x] **R48 FIXED**: Early IPv4 fragment filter (CPU DoS prevention)
- [x] **R49 FIXED**: NetBuf zero-fill before release (information leak prevention)
- [x] **R49 FIXED**: Huge page cleanup on process exit (memory leak prevention)
- [x] **R49 FIXED**: NET_BIND_SERVICE capability for privileged ports
- [x] TCP header parsing (kernel/net/tcp.rs) - RFC 793 with options support
- [x] TCP state machine (TcpControlBlock, TcpState enum)
- [x] TCP 3-way handshake (connect SYN → SYN-ACK → ACK)
- [x] TCP data transfer (PSH+ACK segments, receive buffering)
- [x] **R50 FIXED**: Keyed ISN generation (RFC 6528 compliant, CSPRNG-seeded)
- [x] **R50 FIXED**: Sequence window validation (RFC 793/5961)
- [x] **R50 FIXED**: RST validation + challenge ACK (RFC 5961 Section 3.2)
- [x] **R50 FIXED**: Global connection limit with stale entry pruning (DoS prevention)
- [x] **R53 IMPLEMENTED**: TCP retransmission (RFC 6298 RTT/RTO, Karn's algorithm, exponential backoff)
- [x] **R53-3 FIXED**: Dual timer system (200ms retransmission, 1s TIME_WAIT cleanup)
- [x] **R55 IMPLEMENTED**: NewReno congestion control (RFC 6582) with partial ACK handling
- [x] **R56 IMPLEMENTED**: Limited Transmit (RFC 3042) for small-window recovery
- [x] **R57 IMPLEMENTED**: Idle cwnd validation (RFC 2861) for stale burst prevention
- [x] **R58 IMPLEMENTED**: Window Scaling (RFC 7323) - WSopt negotiation, 256KB default window
- [x] TCP FIN/close states (graceful shutdown) - sys_shutdown, all RFC 793 states
- [x] **R51-1 FIXED**: TCP listen/accept (passive open) - SYN/accept queues implemented
- [x] **R60 IMPLEMENTED**: Fragment reassembly with RFC 791/815/5722 security hardening
- [x] **R51-2 FIXED**: Cap TCP sendto allocation (prevent OOM DoS)
- [x] **R51-3 FIXED**: Ignore SYN-ACK payload (set rcv_nxt = seq+1 only)
- [x] **R51-4 FIXED**: Rollback socket/cap on fd exhaustion
- [x] **R51-5 FIXED**: Abort connect on TX failure
- [x] **R51-6 FIXED**: Initialize FIN/TIME_WAIT timers immediately
- [x] **R52-1 FIXED**: SYN queue timeout (30s) for half-open connection cleanup
- [x] **R52-2 FIXED**: Listener close cleanup (SYN/accept queue resource release)

#### D.3 Protection Mechanisms

- [x] Rate limiting (token bucket, 10pps burst 20)
- [x] Broadcast/multicast response suppression
- [x] MAC filtering (process only frames addressed to us)
- [x] ARP rate limiting (RX 50pps, TX 20pps) and cache anti-spoofing
- [x] ISN randomization (RFC 6528) - R50-1 keyed hash
- [x] **R54-1 FIXED**: ISN secret auto-upgrade (weak→strong once CSPRNG ready)
- [x] **R54-2 FIXED**: Challenge ACK rate limiting (100/sec token bucket)
- [x] **R59-1 IMPLEMENTED**: Ephemeral port randomization (RFC 6056 style CSPRNG)
- [x] **R59-2 FIXED**: CSPRNG fallback uses RDTSC mixing (not predictable counter)
- [x] **R60 IMPLEMENTED**: Fragment reassembly anti-DoS (per-source limits, overlap rejection)
- [x] **R61 IMPLEMENTED**: SYN cookies (RFC 4987) - stateless SYN-ACK on backlog full
- [x] **R63 IMPLEMENTED**: Conntrack state machine (TCP/UDP/ICMP tracking, direction fix, LRU eviction)
- [x] **R63 IMPLEMENTED**: Basic firewall (match + action table, stateful filtering, ACCEPT/DROP/REJECT)
- [x] **R66-1 FIXED**: TCP MSS minimum validation (RFC 879, 536 bytes minimum)
- [x] **R66-2 FIXED**: TCP Window Scale maximum validation (RFC 7323, max shift 14)

#### D.4 Socket API ✅ COMPLETE

- [x] Socket as CapId handle (kernel/net/socket.rs)
- [x] LSM hooks for create/bind/connect/send/recv
- [x] Per-socket security context (SocketLabel)
- [x] NET_BIND_SERVICE capability for privileged ports (R49-3)
- [ ] Zero-copy path reservation (pinned buffers)

**Security Requirements**:
- Default DROP policy option
- Conntrack resource limits
- Fragment/TTL/checksum anomaly protection
- Each socket bound to security context

**Testing Strategy**:
- Loopback self-test
- TCP/UDP interop suite
- SYN flood benchmark
- Firewall rule table-driven tests
- Audit event coverage

---

### Phase E: SMP & Concurrency [IN PROGRESS]

**Goal**: Multi-core support with correct synchronization.

**Priority**: Medium-High (can be deferred after D)
**Dependencies**: Phase A.6 (SMP-ready interfaces)
**Status**: E.1/E.3 complete, AP bootstrap integrated in main.rs, APs park in HLT loop awaiting scheduler work

**R67 SMP Security Blockers** (2026-01-18): **ALL FIXED ✅**
- ~~R67-1 (CRITICAL): TLB shootdown ineffective~~ ✅
- ~~R67-2 (HIGH): Shared trampoline data races~~ ✅
- ~~R67-4 (HIGH): Scheduler globals not per-CPU~~ ✅
- ~~R67-5 (HIGH): Page table mutations lack cross-CPU serialization~~ ✅
- ~~R67-6 (HIGH): Fork/COW lacks per-MM lock~~ ✅
- ~~R67-8 (HIGH): SYSCALL per-CPU arrays use slot 0 only~~ ✅
- ~~R67-9 (HIGH): SYSRET path missing RFLAGS mask~~ ✅
- ~~R67-11 (HIGH): Syscall scratch stack depth unchecked~~ ✅
- ~~R67-3 (MEDIUM): LAPIC ID verification~~ ✅
- ~~R67-7 (MEDIUM): IRQ FPU nesting~~ ✅
- ~~R67-10 (MEDIUM): Context switch FPU interrupt safety~~ ✅

#### E.1 Hardware Initialization

- [x] LAPIC initialization (kernel/arch/apic.rs - init_lapic, lapic_eoi, lapic_id)
- [x] IOAPIC initialization (kernel/arch/apic.rs - init_ioapic, ioapic_route_irq)
- [ ] HPET timer
- [x] AP boot infrastructure (kernel/arch/smp.rs - start_aps, ap_rust_entry, ACPI MADT parsing)
- [x] AP trampoline (kernel/arch/smp.rs - generate_trampoline() runtime binary blob)
- [x] IPI type table (kernel/arch/ipi.rs - 5 types 0xFB-0xFF, kernel/arch/apic.rs - send_ipi/send_init_ipi/send_sipi)
- [x] AP boot integration (main.rs hooks arch::apic::init(), init_bsp(), start_aps())

#### E.2 TLB Shootdown

- [x] IPI-driven global/range invalidation (kernel/mm/tlb_shootdown.rs - R70 fixes)
- [ ] Batched shootdown
- [x] Online CPU count guard (assert_single_core_mode, R70-2 mailbox serialization)
- [x] PCID/ASID support (kernel/tlb_ops crate - INVPCID types 0-3, init_invpcid_support)

#### E.3 Per-CPU Data

- [x] Per-CPU segment (%gs) - CpuLocal<T> abstraction (kernel/cpu_local/lib.rs)
- [x] Syscall stack per-CPU (PerCpuData.syscall_stack_top)
- [x] Scheduler runqueue per-CPU (R69-1 fix - CpuLocal<Mutex<ReadyQueues>>)
- [x] IRQ stack per-CPU (PerCpuData.irq_stack_top)
- [x] Safe cross-CPU access API (current_cpu(), init_bsp(), init_ap())
- [x] Per-CPU FPU save areas (R66-7 fix - kernel/arch/interrupts.rs)
- [x] LAPIC ID → CPU index mapping (kernel/cpu_local/lib.rs - register_cpu_id, current_cpu_id)

#### E.4 Synchronization

- [x] Lock class annotations (LockClassKey, LockLevel in lock_ordering.rs)
- [x] Runtime lockdep checker (debug) - LockdepMutex with IRQ-safe validation (R71-3 fix)
- [x] RCU/epoch-based garbage collection - call_rcu with grace period advancement (R71-1 fix)
- [x] Futex priority inheritance - Iterative PI propagation (R72-1, R72-2 fixes)

#### E.5 Scheduler SMP

- [x] Per-CPU runqueues (R69-1 - CpuLocal<Mutex<ReadyQueues>> in enhanced_scheduler.rs)
- [x] Load balancing (R69 - work stealing + periodic migration in balance_queues())
- [x] CPU affinity (R72 - sched_setaffinity/sched_getaffinity syscalls 203/204)
- [x] CPU isolation (cpuset) - Runtime test validates hierarchical mask enforcement

**Security Requirements**:
- Cross-CPU kernel pointers obfuscated (kptr guard)
- IPI path audited
- SMP enable gate: assert IPI/TLB ready
- No global lock held during user code execution

**Testing Strategy**:
- SMP self-check (IPI ping-pong, TLB flush verification)
- RCU torture test
- Lockdep scenario tests
- Scheduler timing consistency

---

### Phase F: Resource Governance [IN PROGRESS]

**Goal**: Multi-tenant resource isolation.

**Priority**: Medium
**Dependencies**: Phase B (Cap/LSM), Phase C (storage), Phase D (network)
**Status**: F.1 Complete, F.2-F.3 pending

#### F.1 Namespaces ✅ **COMPLETE**

- [x] PID namespace (isolated PID numbering)
  - Hierarchical namespace tree with MAX_PID_NS_LEVEL=32 depth
  - CLONE_NEWPID and unshare(CLONE_NEWPID) support
  - Namespace-aware getpid/getppid/gettid/kill syscalls
  - Init death cascade (SIGKILL to all namespace members)
  - fork/clone/wait return namespace-local PIDs
- [x] Mount namespace (isolated FS view) ✅ **COMPLETE** (2026-01-25)
  - `kernel/kernel_core/mount_namespace.rs`: Core MountNamespace structure
  - Per-namespace mount tables in VFS (`NamespaceMountTable`)
  - CLONE_NEWNS in sys_clone with copy-on-write mount table
  - sys_unshare(CLONE_NEWNS) for process mount namespace isolation
  - sys_setns (syscall 308) for mount namespace switching
  - MountNamespaceFd for namespace file descriptor wrapper
  - R74-2 fix: Eager materialization prevents mount leakage
  - Security: CAP_SYS_ADMIN or root required, single-threaded validation
  - Runtime test: `MountNamespaceIsolationTest` (hierarchy, IDs, isolation, depth limit)
  - Audit events: `AuditObject::Namespace` for clone/unshare/setns logging
  - See [phase-f-mount-namespace-plan.md](phase-f-mount-namespace-plan.md) for details
- [x] IPC namespace (isolated message queues) ✅ **COMPLETE** (2026-01-25)
  - `kernel/kernel_core/ipc_namespace.rs`: Core IpcNamespace structure
  - Hierarchical namespace tree with MAX_IPC_NS_LEVEL=32 depth
  - CLONE_NEWIPC in sys_clone creates isolated IPC namespace
  - Isolated System V IPC resources (message queues, semaphores, shared memory)
  - IpcNamespaceFd for namespace file descriptor wrapper
  - Security: CAP_SYS_ADMIN or root required
  - Runtime test: `IpcNamespaceIsolationTest` (hierarchy, IDs, refcounting, depth limit)
  - Audit events: `AuditObject::Namespace` for clone logging
- [x] Network namespace (isolated stack) ✅ **COMPLETE** (2026-01-25)
  - `kernel/kernel_core/net_namespace.rs`: Core NetNamespace structure
  - Hierarchical namespace tree with MAX_NET_NS_LEVEL=32 depth
  - CLONE_NEWNET in sys_clone creates isolated network namespace
  - Device management (add_device, remove_device, move_device)
  - Each namespace has loopback interface by default
  - NetNamespaceFd for namespace file descriptor wrapper
  - Security: CAP_NET_ADMIN or root required
  - Runtime test: `NetNamespaceIsolationTest` (hierarchy, IDs, devices, refcounting, depth limit)
  - Audit events: `AuditObject::Namespace` for clone logging
- [x] User namespace (UID/GID mapping) ✅ **COMPLETE** (2026-01-27)
  - `kernel/kernel_core/user_namespace.rs`: Core UserNamespace structure
  - Hierarchical namespace tree with MAX_USER_NS_LEVEL=32 depth
  - CLONE_NEWUSER in sys_clone creates isolated user namespace
  - UID/GID mapping tables (up to 5 extents each, single-write semantics)
  - Mapping functions: map_uid_to_ns, map_uid_from_ns, map_gid_to_ns, map_gid_from_ns
  - UserNamespaceFd for namespace file descriptor wrapper
  - Security: Does NOT require CAP_SYS_ADMIN (enables unprivileged containers)
  - Permission checks: Root can set arbitrary mappings, non-root can only map own ID
  - Parent containment validation: Child mappings must be within parent's mapped ranges
  - CAS-based namespace count limiting (MAX_USER_NS_COUNT=1024)
  - Codex security review: 3 issues fixed (CAS loop, permission checks, parent validation)

#### F.2 Cgroups v2 ✅ **COMPLETE**

**Core Infrastructure** ✅
- [x] CgroupNode hierarchy management
- [x] CGROUP_REGISTRY global state
- [x] Limits: MAX_CGROUP_DEPTH=8, MAX_CGROUPS=4096
- [x] CgroupStats (lock-free atomic counters)
- [x] PCB integration (cgroup_id field, inheritance)
- [x] Codex security review (3 issues fixed)

**Controllers**
- [x] pids controller (process count limit in fork path)
- [x] cpu controller (cpu.weight time slice scaling, cpu.max quota enforcement with IRQ-safe throttling)
- [x] memory controller (try_charge_memory CAS in mmap/brk, uncharge_memory in munmap/brk-shrink)
- [x] io controller (io.max bps/iops with token bucket algorithm, stale token clamping, oversized I/O support)

**Syscalls & Interface** ✅
- [x] sys_cgroup_create / sys_cgroup_destroy (syscalls 500/501)
- [x] sys_cgroup_attach (syscall 502, self-migration)
- [x] sys_cgroup_set_limit / sys_cgroup_get_stats (syscalls 503/504)
- [x] cgroup2 filesystem (/sys/fs/cgroup) - cgroupfs mount with control files

#### F.3 IOMMU/VT-d [IN PROGRESS]

**Core Infrastructure** ✅
- [x] ACPI DMAR table parser (kernel/iommu/dmar.rs) - strict bounds checking, OOB prevention
- [x] VT-d hardware driver (kernel/iommu/vtd.rs) - register interface, root/context tables
- [x] Domain management (kernel/iommu/domain.rs) - identity/paged domains, overlap rejection
- [x] Public API (kernel/iommu/lib.rs) - init, attach_device, map_range, unmap_range
- [x] Fail-closed security model (ensure_iommu_ready, translation_enabled checks)
- [x] Codex security review R79: 3 issues fixed (fail-open paths, DMAR OOB, identity aliasing)

**DMA Isolation** ✅
- [x] Second-level page table allocation (alloc_zeroed_page_table with direct map validation)
- [x] 4-level page table walk (PML4→PDPT→PD→PT for 48-bit AGAW)
- [x] 3-level page table walk (PDPT→PD→PT for 39-bit AGAW)
- [x] Page table locking (page_table_lock prevents concurrent mutation)
- [x] Superpage detection and rejection (PS bit checking)
- [x] VT-d A/D flags handling (don't set reserved bits)
- [x] Codex security review R80: 5 issues fixed (direct map, locking, AGAW, A/D, superpage)

**Device Domain Binding** ✅
- [x] Root table allocation (init_root_table with CAS, direct map validation)
- [x] Context table allocation (ensure_context_table with CAS)
- [x] Context entry programming (attach_device with domain type handling)
- [x] Pass-through capability check (ECAP.PT validation, fail-closed)
- [x] Context cache invalidation (invalidate_context_device after programming)
- [x] IOTLB invalidation (domain-level after entry programming)
- [x] Codex security review R81: 3 issues (2 fixed, 1 documented)

**VirtIO Integration** ✅
- [x] IOMMU attach before bus mastering (kernel/net/src/pci.rs, kernel/block/src/pci.rs)
- [x] Fail-closed error handling (skip device if attach fails)
- [x] Bus master cleanup on probe failure (disable DMA capability)
- [x] Net/Block subsystem integration (lib.rs cleanup paths)
- [x] Codex security review R82: 4 issues fixed (attach order, cleanup paths)

**Interrupt Remapping** ✅
- [x] Interrupt Remapping Table Entry (IRTE) structure (kernel/iommu/interrupt.rs)
- [x] InterruptRemappingTable with bitmap allocator (256 entries default)
- [x] IrteHandle for MSI/MSI-X address/data programming
- [x] ECAP.IR hardware support detection
- [x] IRTA register programming with EIM support
- [x] GCMD.IRE enable with GSTS.IRES polling
- [x] Fail-closed when platform DMAR requires IR
- [x] Graceful degradation when IR not required
- [x] Codex security review R84: 3 issues fixed (concurrency, cleanup, zeroing), 1 documented (x2APIC)

**Fault Handling** ✅
- [x] FaultReason/FaultType enums with security-relevant detection
- [x] FaultRecord structure with BDF parsing
- [x] read_fault_records() with FRI-based rotation (R85-1)
- [x] Checked MMIO pointer arithmetic (R85-2)
- [x] read_and_clear_fault_status() with full W1C (R85-3)
- [x] Fault flood mitigation with interrupt masking (R85-4)
- [x] Console/audit logging with address redaction (R85-5)
- [x] VtdUnit integration (read_fault_records, set_fault_interrupt_enabled)
- [x] Public API (handle_dma_faults, FaultConfig)
- [x] Codex security review R85: 5 issues fixed (100% fix rate)

**Device Isolation** ✅
- [x] PCI configuration space access (legacy I/O port 0xCF8/0xCFC)
- [x] Bus Master Enable disable with verification read-back
- [x] Segment validation for multi-segment systems (R86-1)
- [x] PCI config RMW serialization via global lock (R86-2)
- [x] IOTLB/context invalidation after isolation (R86-3)
- [x] Forced console logging in isolation mode (R86-4)
- [x] VtdUnit get_device_domain() for domain lookup
- [x] Codex security review R86: 4 issues fixed (100% fix rate)

**Device Detach API** ✅
- [x] detach_device() public API (kernel/iommu/lib.rs)
- [x] detach_device_from_domain() for specific domain detach
- [x] VtdUnit::detach_device() with validation chain
- [x] VtdUnit::disable_bus_mastering() helper with read-back verification
- [x] DeviceNotAttached error variant
- [x] Atomic domain tracking update (R87-1 fix)
- [x] Multi-segment graceful degradation (R87-2 fix)
- [x] Codex security review R87: 2 issues fixed (100% fix rate)

**VM Passthrough Preparation** ✅
- [x] VM domain registry (VM_DOMAINS, VM_DEVICE_IRTES tracking)
- [x] create_vm_domain() for isolated VM address spaces
- [x] assign_device_to_vm() with IRTE allocation and rollback
- [x] unassign_device_from_vm() with detach-first ordering (R88-2)
- [x] VtdUnit::interrupt_remapping_table() accessor
- [x] IR enable enforcement for passthrough (R88-1 fix)
- [x] Device detach priority over IR cleanup (R88-2 fix)
- [x] Codex security review R88: 2 issues fixed (100% fix rate)

**Security Requirements**:
- Default resource limits
- Cross-namespace ops require ADMIN cap
- IOMMU binding validation
- OOM policy configurable

**Testing Strategy**:
- Namespace isolation matrix
- Cgroup stress and throttle tests
- DMA pollution prevention tests

---

### Phase G: Production Readiness [IN PROGRESS]

**Goal**: Observable, compliant, updatable.

**Priority**: Medium
**Dependencies**: All previous phases
**Status**: ✅ **G.1 COMPLETE** (tracepoints, counters, watchdog, profiler, kdump all implemented)

#### G.1 Observability ✅ **COMPLETE**

- [x] Tracepoints/counters infrastructure ✅ (R89 - trace crate with per-CPU counters)
- [x] Health monitoring (watchdog, hung-task) ✅ (R89 - 512-slot watchdog table)
- [x] Sampling profiler ✅ (R91 - PC sampling with per-CPU ring buffers, seqlock publishing)
- [x] Counter hot-path integration ✅ (all 15 TraceCounter variants wired to hot paths)
- [x] kdump (encrypted, redacted) ✅ (R92 - ChaCha20 encryption, KptrGuard redaction, panic-safe)

#### G.2 Live Patching ✅ **SECURITY COMPLETE** (R93 issues fixed)

**R93 Security Fixes Completed:**
- [x] Compile-time guard against insecure-ecdsa-stub in release builds (R93-2)
- [x] Default fail-closed when no ECDSA verifier wired (R93-2)
- [x] Patch target/handler address validation within kernel .text (R93-10)
- [x] W^X seal_exec enforcement - required trait method (R93-11)
- [x] Target mapping validation before volatile access (R93-12)
- [x] sys_kpatch_unload syscall for patch lifecycle (R93-13)

**Remaining for Production:**
- [x] Real ECDSA P-256 signature verification ✅ (p256 + ecdsa crates, KAT-gated, RFC 6979 test vector)
- [x] Rollback policy ✅ (rollback_recent_patches() auto-disables patches within TSC window on fault)
- [ ] Patch dependency tracking (ordered enable/disable)

#### G.3 Compliance ✅ **SECURITY COMPLETE** (R93 issues fixed)

**R93 Security Fixes Completed:**
- [x] FIPS self-tests with real KATs (R93-14) - SHA-256 + HMAC-SHA256 NIST vectors
- [x] kdump FIPS cipher selection (R93-15) - fail-closed in FIPS mode
- [x] Panic output redaction in Secure profile (R93-16)
- [x] Cgroup capability/namespace model (R93-17) - CAP_SYS_ADMIN checks

**Remaining for Production:**
- [ ] Hardening profiles policy wiring (Secure/Balanced/Performance)
- [ ] Audit remote delivery (sys_audit_export)
- [ ] Cgroup delegation for unprivileged container managers
- [x] ECDSA KAT when signature verification implemented ✅ (delegates to livepatch::ecdsa_p256 KAT)

**Security Requirements**:
- Debug interfaces require Cap/LSM authorization
- Dump redaction with kptr guard
- Patch signature mandatory

**Testing Strategy**:
- Trace/kdump regression
- Hot patch drill
- Benchmark and regression
- Compliance config scan

---

## Testing Strategy

### Current Tests

- Buddy allocator self-test
- Boot sequence validation
- Integration tests in QEMU
- Clone/thread test suite

### Testing Infrastructure Needed

| Category | Tests |
|----------|-------|
| **Syscall** | Fuzzer for all 35+ syscalls, error path coverage |
| **Memory** | COW stress, mmap/munmap cycles, page cache consistency |
| **IPC** | Pipe throughput, futex contention, signal delivery |
| **Security** | Capability inheritance, LSM policy enforcement, audit integrity |
| **SMP** | Lock contention, TLB shootdown, scheduler fairness |
| **Storage** | FS compatibility, I/O error handling |
| **Network** | Protocol compliance, DoS resistance |

### Debugging Tools

- QEMU monitor integration
- GDB remote debugging (:1234)
- Serial console logging
- kdump analysis (future)

---

## Code Quality Metrics

### Audit History

| Date | Round | Issues Found | Fixed | Notes |
|------|-------|--------------|-------|-------|
| 2025-12-09 | 1-3 | 25 | 24 | Initial security baseline |
| 2025-12-10 | 4-7 | 22 | 21 | Preemption, COW, scheduler |
| 2025-12-11 | 8-13 | 23 | 19 | IPC, signals, context switch |
| 2025-12-15-16 | 16-19 | 11 | 10 | VFS, W^X, audit subsystem |
| 2025-12-17-18 | 20-22 | 29 | 19 | Ring 3, SYSCALL/SYSRET |
| 2025-12-20 | 23-24 | 12 | 12 | Thread/Clone, TLS, usercopy |
| 2025-12-23 to 2026-01-02 | 25-40 | 36 | 32 | Cap/LSM/Seccomp integration, VirtIO |
| 2026-01-03 | 41 | 4 | 4 | sys_fstat, sys_execve LSM, openat2 |
| 2026-01-04 | 42 | 5 | 5 | procfs PID-reuse, getdents64, page cache - **ALL FIXED** |
| 2026-01-05 | 43 | 5 | 5 | VirtIO used.id OOB, descriptor chain loop, double-free - **ALL FIXED** |
| 2026-01-06 | 44-47 | 16 | 16 | ARP/UDP/Socket API, VirtIO hardening - **ALL FIXED** |
| 2026-01-07 | 48 | 6 | 6 | Network stack security audit - **ALL R48 FIXED** |
| 2026-01-08 | 49 | 3 | 3 | NetBuf leak, NET_BIND_SERVICE - **ALL R49 FIXED** |
| 2026-01-09 | 50 | 6 | 6 | TCP ISN/RST/limits, FIN/close states - **ALL R50 FIXED** |
| 2026-01-10 | 51 | 6 | 6 | TCP resource mgmt, listen/accept - **ALL R51 FIXED** |
| 2026-01-11 | 52-53 | 6 | 6 | SYN queue timeout, listener cleanup, RTT/RTO, timer granularity - **ALL FIXED** |
| 2026-01-12 | 54-58 | 12 | 10 | ISN upgrade, Challenge ACK, NewReno, Limited Transmit, Idle cwnd, Window Scaling - **2 DEFERRED** |
| 2026-01-13 | 59 | 2 | 2 | Ephemeral port randomization, CSPRNG fallback security - **ALL FIXED** |
| 2026-01-13 | 60 | 10 | 10 | IP fragment reassembly (RFC 791/815/5722), security hardening - **ALL FIXED** |
| 2026-01-13 | 61 | 2 | 2 | SYN cookies (RFC 4987), ACK validation, pure ACK enforcement - **ALL FIXED** |
| 2026-01-14 | 62 | 7 | 6 | ARP static eviction, timer contention, fragment byte limits, SYN cookie age, ISN entropy, LSM hooks - **6 FIXED, 1 DEFERRED** |
| 2026-01-14 | - | - | - | **Conntrack state machine implemented** (TCP/UDP/ICMP tracking, stateful firewall foundation) |
| 2026-01-15 | 63-64 | 12 | 11 | Conntrack direction fix, capacity bypass, LRU eviction, RST rate limit, timer monitoring, fragment count, firewall - **11 FIXED, 1 DOCUMENTED** |
| 2026-01-16 | 65 | 26 | 17 | Comprehensive audit - CLD fix, COW race, context switch validation, rate limiter CAS, conntrack accounting - **17 FIXED, 9 OPEN** |
| 2026-01-17 | 66 | 11 | 11 | TCP options validation (MSS/WS), VirtIO-blk ring init/jump detection/double-free, scheduler priority cap, fragment CAS, per-CPU FPU - **ALL FIXED** |
| 2026-01-18 | 67 | 11 | 11 | **SMP SECURITY AUDIT** - TLB shootdown ✅, trampoline claim flag ✅, LAPIC verification ✅, scheduler per-CPU ✅, PT cross-CPU lock ✅, fork/COW lock ✅, FPU nesting ✅, syscall GS-relative ✅, SYSRET RFLAGS ✅, syscall depth ✅, context switch FPU ✅ - **ALL FIXED** |
| 2026-01-19 | 68 | 7 | 7 | TLB shootdown ACK timeout, COW TLB flush, FPU nesting safety - **ALL FIXED** |
| 2026-01-20 | 69 | 5 | 5 | PhysicalPageRefCount ABA race, lazy FPU migration, load balancer affinity, ASID writer starvation, lock ordering docs - **ALL FIXED** |
| 2026-01-21 | 70 | 3 | 3 | AP idle loop race, TLB mailbox overwrite, CPU affinity semantics - **ALL FIXED** |
| 2026-01-22 | 71 | 4 | 4 | RCU grace period progress, RCU memory ordering, Lockdep IRQ window, TLB self-ACK safety - **ALL FIXED** |
| 2026-01-22 | 72 | 0 | 0 | CPU affinity syscalls (sched_setaffinity/sched_getaffinity) - **E.5 FEATURE** |
| 2026-01-25 | 74 | 1 | 1 | Mount namespace materialization (R74-2 eager snapshot) - **F.1 FEATURE** |
| 2026-01-25 | - | 0 | 0 | Mount namespace runtime test + audit events - **F.1 COMPLETE** |
| 2026-01-26 | 75 | 4 | 4 | **Namespace structure** - IPC/Net resource isolation gaps ✅, move_device permission ✅, NS FD refcount ✅ |
| 2026-01-26 | 76 | 3 | 3 | **Namespace enforcement** - Socket NS check ✅, NS count limits ✅, Socket quotas ✅ (F.1 COMPLETE) |
| 2026-01-27 | 77 | 5 | 5 | **Resource accounting** - TCP child socket quota ✅, Fork cpuset leak ✅, delete_cgroup race ✅, Memory CAS ✅, NS guard ✅ |
| 2026-01-27 | 78 | 3 | 3 | **User namespace** - CAS count guard ✅, Permission checks ✅, Parent containment validation ✅ (F.1 COMPLETE) |
| 2026-01-27 | 79 | 3 | 3 | **IOMMU/VT-d** - Fail-open paths ✅, DMAR OOB reads ✅, Identity aliasing ✅ (F.3 IN PROGRESS) |
| 2026-01-27 | 80 | 5 | 5 | **SL page tables** - Direct map range check ✅, PT lock concurrency ✅, AGAW-aware walk ✅, A/D flags reserved ✅, Superpage corruption ✅ |
| 2026-01-27 | 81 | 3 | 2 | **Context table** - Context/IOTLB invalidation ✅, Pass-through capability check ✅, Direct map bound (documented) |
| 2026-01-27 | 82 | 4 | 4 | **VirtIO IOMMU integration** - Attach before bus master ✅, Fail-closed on attach error ✅, Disable bus master on probe fail ✅, Net/Block cleanup ✅ |
| 2026-01-28 | 83 | 5 | 5 | **IOMMU/Cgroup security** - Page table atomicity ✅, setns fail-closed ✅, PIDs hierarchy ✅, AGAW validation ✅, CPU quota contention ✅ |
| 2026-01-28 | 84 | 4 | 3 | **Interrupt Remapping** - Concurrent setup race ✅, IRTA cleanup ✅, IR table zeroing ✅, x2APIC mode (documented) |
| 2026-01-28 | 85 | 5 | 5 | **Fault Handling** - FRI rotation ✅, MMIO bounds check ✅, FRI W1C clear ✅, Fault flood mitigation ✅, Address redaction ✅ |
| 2026-01-28 | 86 | 4 | 4 | **Device Isolation** - Segment validation ✅, PCI RMW serialization ✅, IOTLB quiesce ✅, Forced logging ✅ |
| 2026-01-28 | 87 | 2 | 2 | **Device Detach API** - Atomic domain tracking ✅, Multi-segment graceful degradation ✅ |
| 2026-01-28 | 88 | 2 | 2 | **VM Passthrough** - IR enable verification ✅, Unassign cleanup order ✅ |
| 2026-01-28 | 89 | 4 | 3 | **Observability (G.1)** - Watchdog race ✅, 64-bit generation ✅, transmute fix ✅, counter wrap (documented) |
| 2026-01-29 | 90 | 4 | 4 | **Cross-subsystem** - IOMMU fail-closed ✅, Net NS ingress ✅, pids.max CAS ✅, Migrate lock ✅ |
| 2026-01-30 | 91 | 3 | 3 | **Profiler (G.1)** - current_pid() IRQ deadlock ✅, CpuLocal stack overflow ✅, profiler control race ✅ |
| 2026-01-30 | 92 | 5 | 5 | **kdump (G.1)** - Multi-CPU race ✅, Stack page boundary ✅, ASCII hex redaction ✅, Key cleanup ✅, try_fill_random fallback ✅ |
| 2026-01-31 | 93 | 18 | 18 | **SECURITY DEBT** - Fork NS escape (CRITICAL) ✅, Livepatch guard (CRITICAL) ✅, Fail-open (HIGH) ✅, sys_access (HIGH) ✅, cgroup_attach (HIGH) ✅, ELF cgroup (HIGH) ✅, Identity map (HIGH) ✅, kdump fallback (HIGH) ✅, TLB shootdown (HIGH) ✅, Livepatch address (HIGH) ✅, seal_exec (HIGH) ✅, target mapping (MEDIUM) ✅, kpatch_unload (MEDIUM) ✅, FIPS KATs (MEDIUM) ✅, kdump FIPS (MEDIUM) ✅, panic redact (MEDIUM) ✅, cgroup caps (MEDIUM) ✅, ELF filesz (LOW) ✅ - **ALL 18 FIXED** |
| 2026-02-01 | 94 | 16 | 16 | **SECURITY AUDIT** - Identity map USER_ACCESSIBLE (CRITICAL) ✅, insecure-ecdsa-stub guard (CRITICAL) ✅, ECDSA KAT deadlock (HIGH) ✅, fips_state fail-open (HIGH) ✅, PID translation fail-open (HIGH) ✅, Firewall default DROP (HIGH) ✅, IOMMU legacy signaling (HIGH) ✅, IOMMU kernel domain SLPT (HIGH) ✅, TLB shootdown mailbox (MEDIUM→HIGH) ✅, current_profile fallback (MEDIUM) ✅, KAT negative tests (MEDIUM) ✅, kdump storage scrub (MEDIUM) ✅, HMAC key scrub (MEDIUM) ✅, cgroup TaskNotAttached (MEDIUM) ✅, kdump emit-once (LOW) ✅, verify_chain_hmac (LOW) ✅ - **ALL 16 FIXED** |
| 2026-02-02 | 95 | 8 | 8 | **DMA/CONNTRACK/EXT2** - Conntrack bypass (CRITICAL) ✅, Cpuset escape (CRITICAL) ✅, sys_fstatat/sys_openat ptr deref (HIGH) ✅, ext2 unaligned reads (HIGH) ✅, VirtIO DMA leak (HIGH) ✅, DMA leak amplification (MEDIUM) ✅, DMA drop fence (MEDIUM) ✅, IOMMU PTE ordering (LOW) ✅ - **ALL 8 FIXED** |
| 2026-02-03 | 96 | 9 | 9 | **EXT2/CONNTRACK/VIRTIO** - ext2 indirect block UB (HIGH) ✅, Conntrack LRU growth (HIGH) ✅, VirtIO RX lifecycle (HIGH) ✅, ext2 dir entry UB (HIGH) ✅, ext2 superblock overflow (MEDIUM) ✅, DmaError classification (MEDIUM) ✅, 3 LOW ✅ - **ALL 9 FIXED** |
| 2026-02-04 | 97 | 4 | 3+1 | **SYSCALL/EXT2** - sys_writev overflow+UB (HIGH) ✅, ext2 file_block truncation (HIGH) ✅, ext2 superblock validation (MEDIUM) ✅, VirtIO-net IOMMU mapping (DESIGN, documented) - **3 FIXED, 1 DOCUMENTED** |
| 2026-02-05 | 98 | 3 | 3 | **SIGNAL/NET/TIMER** - SIGSTOP/SIGCONT lost wakeups (HIGH) ✅, NetBuf IOMMU fault storm (MEDIUM) ✅, BSP idle loop drain (LOW) ✅ - **ALL 3 FIXED** |
| 2026-02-06 | 99 | 4 | 4 | **NET/EXT2** - NetBuf integer overflow bypasses size check (HIGH) ✅, ext2 read_block bounds (MEDIUM) ✅, ext2 BGDT overflow (MEDIUM) ✅, ext2 validate_block deadlock (LOW) ✅ - **ALL 4 FIXED** |
| **Total** | **99** | **496** | **454 (91.5%)** | **42 open (R65 SMP, R81-3/R84-4/R89-4 documented)** |

### Current Status

- **Fixed**: 454 issues (91.5%)
- **Open**: 42 issues (8.5%)
  - R65 remaining issues (SMP-related, non-blocking)
  - R81-3 (Direct map bound) documented risk
  - R84-4 (x2APIC mode) documented limitation
  - R89-4 (Counter overflow) documented acceptable risk
- **Phase E Progress**: ✅ **COMPLETE**
  - E.1 Hardware Init: ✅ LAPIC/IOAPIC, AP boot, IPI
  - E.2 TLB Shootdown: ✅ IPI-based, PCID support (batched pending)
  - E.3 Per-CPU Data: ✅ CpuLocal<T>, per-CPU stacks, runqueues
  - E.4 Synchronization: ✅ RCU (R71), Lockdep (R71), Futex PI (R72)
  - E.5 Scheduler SMP: ✅ Per-CPU runqueues, load balancing, CPU affinity syscalls
  - E.6 CPU Isolation: ✅ Cpuset with runtime test (R72)
- **Phase F Progress**: ✅ **COMPLETE**
  - F.1 Namespaces: ✅ **COMPLETE** - All 5 types: PID/Mount/IPC/Network/User with full isolation (R75-R78)
  - F.2 Cgroups v2: ✅ **COMPLETE** - PIDs/CPU/Memory/IO controllers + cgroup2 filesystem + R83 hierarchical PIDs
  - F.3 IOMMU/VT-d: ✅ **COMPLETE** - Core infrastructure ✅, Second-level page tables ✅, Context table ✅, VirtIO integration ✅, Interrupt Remapping ✅ (R84), Fault Handling ✅ (R85), Device Isolation ✅ (R86), Device Detach API ✅ (R87), **VM Passthrough ✅** (R88)
- **Phase G Progress**: **G.1/G.2/G.3 SECURITY COMPLETE**
  - G.1 Observability: ✅ **COMPLETE** - Tracepoints, Per-CPU counters, Watchdog (R89), Profiler (R91), Counter integration, kdump (R92)
  - G.2 Live Patching: ✅ **SECURITY COMPLETE** - R93-2,10,11,12,13 fixed; ECDSA P-256 ✅; Rollback policy ✅; remaining: dependencies
  - G.3 Compliance: ✅ **SECURITY COMPLETE** - R93-14,15,16,17 fixed; remaining: hardening profiles, audit delivery
- **R93 Security Debt**: ✅ **FULLY RESOLVED** - All 18 issues fixed (2 CRITICAL, 9 HIGH, 5 MEDIUM, 2 LOW)
- **SMP Ready**: All Phase E components complete, 8-core SMP testing verified
- **Container Foundation**: COMPLETE - All 5 namespace types + Cgroups v2 provide full container isolation
- **Virtualization Foundation**: COMPLETE - IOMMU/VT-d with VM passthrough preparation
- **R93 Key Fixes**: Fork namespace escape (CRITICAL), Livepatch compile guard (CRITICAL), Fail-closed patterns, Cgroup authorization, ELF memory accounting, Identity map isolation, kdump encryption required, TLB shootdown fail-closed, Address validation, seal_exec, kpatch_unload, FIPS KATs, Panic redaction, Cgroup capabilities
- **R94 Key Fixes**: ECDSA KAT deadlock-free, FIPS/Profile fail-closed, PID namespace fail-closed, TLB shootdown mailbox panic, kdump storage scrub, HMAC key scrub, cgroup attach fail-closed, firewall default DROP, IOMMU legacy fail-closed, verify_chain_hmac, **IOMMU kernel domain SLPT**
- **R95 Key Fixes**: Conntrack state bypass (CRITICAL), Cpuset escape (CRITICAL), sys_fstatat/sys_openat user ptr, ext2 unaligned reads, VirtIO DMA leak, DMA lifecycle
- **R96 Key Fixes**: ext2 indirect block UB, Conntrack LRU unbounded growth, VirtIO RX lifecycle, ext2 dir entry UB, syscall TOCTOU
- **R97 Key Fixes**: sys_writev integer overflow + unaligned UB, ext2 file_block u64→u32 truncation, ext2 superblock validation
- **R98 Key Fixes**: SIGSTOP/SIGCONT state overwrite lost wakeups (H-34), NetBuf IOMMU fault storm, BSP idle loop timer drain
- **R99 Key Fixes**: NetBuf integer overflow bypasses DMA size check, ext2 read_block bounds validation, ext2 BGDT checked arithmetic, ext2 validate_block lock-free (deadlock fix)

See [qa-2026-02-06.md](review/qa-2026-02-06.md) for latest audit report.

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1.x | 2025-12-09/10 | Phase 1-2: Boot, memory, security fixes |
| 0.2.0 | 2025-12-10 | Phase 2: Process isolation |
| 0.3.x | 2025-12-11 | Phase 3-4: Multi-process, IPC |
| 0.4.x | 2025-12-15/16 | Phase 5: VFS, security hardening |
| 0.5.x | 2025-12-17/18 | Phase 6.1: Ring 3, SYSCALL/SYSRET |
| **0.6.x** | **2025-12-20** | **Phase 6.2: Thread/Clone, security fixes** |
| **0.6.5** | **2025-12-21** | **Phase A: Security foundation (~80%), Phase B scaffolded** |
| 0.7.0 | TBD | Phase A: Security foundation complete |
| 0.8.0 | TBD | Phase B: Capability/MAC |
| 0.9.0 | TBD | Phase C: Storage |
| 0.10.0 | TBD | Phase D: Network |
| 0.11.0 | TBD | Phase E: SMP |
| 1.0.0 | TBD | First stable release |

---

## Contributing Guidelines

1. All code changes require security review for:
   - Syscall implementations
   - Memory management changes
   - IPC/network code
   - Capability checks

2. Run `make build && make test` before committing

3. Security-sensitive PRs require:
   - Threat model documentation
   - LSM hook integration
   - Audit event emission
   - Fuzz coverage

4. Follow existing code patterns and Rust idioms

---

*This roadmap reflects a security-first approach, prioritizing correctness and isolation over performance optimization. SMP support is intentionally deferred until the security framework is complete.*
