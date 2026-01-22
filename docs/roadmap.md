# Zero-OS Development Roadmap

**Last Updated:** 2026-01-17
**Architecture:** Security-First Hybrid Kernel
**Design Principle:** Security > Correctness > Efficiency > Performance

This document outlines the development roadmap for Zero-OS, a microkernel operating system written in Rust for x86_64 architecture, designed to evolve toward enterprise-grade security.

---

## Executive Summary

### Current Status: Phase E IN PROGRESS (SMP Infrastructure)

Zero-OS has completed network foundation with comprehensive validation:
- **66 security audits** with 316 issues found, ~265 fixed (83.9%)
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
- **Phase E**: 🔨 **IN PROGRESS** (SMP & Concurrency)
  - E.1: LAPIC/IOAPIC initialization ✅
  - E.3: PerCpuData structure ✅, Per-CPU FPU save areas ✅
  - Pending: AP bootstrap, TLB shootdown, per-CPU runqueues
- **R54**: ISN secret auto-upgrade ✅, Challenge ACK rate limiting ✅
- **R55**: NewReno congestion control ✅ (RFC 6582 partial ACK handling)
- **R56**: Limited Transmit ✅ (RFC 3042 adapted for immediate-send architecture)
- **R57**: Idle cwnd validation ✅ (RFC 2861 stale burst prevention)
- **R58**: Window Scaling ✅ (RFC 7323 WSopt negotiation, up to 256KB windows)
- **R59**: Ephemeral port randomization ✅ (RFC 6056 CSPRNG)
- **R60**: IP fragment reassembly ✅ (RFC 791/815/5722 security hardening)
- **R61**: SYN cookies ✅ (RFC 4987 stateless SYN flood protection)
- **R66**: TCP options validation ✅, VirtIO hardening ✅, Runtime network tests ✅

### Gap Analysis vs Linux Kernel

| Category | Linux | Zero-OS | Gap |
|----------|-------|---------|-----|
| **SMP** | 256+ CPUs | Single-core | Full implementation needed |
| **Security Framework** | LSM/SELinux/AppArmor | LSM + Seccomp + Capabilities | ✅ Framework complete, policies needed |
| **Network** | Full TCP/IP stack | TCP (w/retransmission + NewReno CC + Window Scaling + SYN cookies + Conntrack + Firewall + Options validation), UDP, ICMP | SACK, Timestamps |
| **Storage** | ext4/xfs/btrfs/zfs | virtio-blk + ext2 + procfs | Extended FS support needed |
| **Drivers** | 10M+ LOC drivers | VGA/Serial/Keyboard/VirtIO | Driver framework needed |
| **Containers** | Namespaces/Cgroups | Not started | Full implementation needed |
| **Virtualization** | KVM/QEMU | Not started | Future consideration |

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
- [ ] Scheduler runqueue per-CPU
- [x] IRQ stack per-CPU (PerCpuData.irq_stack_top)
- [x] Safe cross-CPU access API (current_cpu(), init_bsp(), init_ap())
- [x] Per-CPU FPU save areas (R66-7 fix - kernel/arch/interrupts.rs)
- [x] LAPIC ID → CPU index mapping (kernel/cpu_local/lib.rs - register_cpu_id, current_cpu_id)

#### E.4 Synchronization

- [ ] Lock class annotations
- [ ] Runtime lockdep checker (debug)
- [ ] RCU/epoch-based garbage collection
- [ ] Futex priority inheritance (preparation)

#### E.5 Scheduler SMP

- [ ] Per-CPU runqueues
- [ ] Load balancing
- [ ] CPU affinity
- [ ] CPU isolation (cpuset preparation)

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

### Phase F: Resource Governance

**Goal**: Multi-tenant resource isolation.

**Priority**: Medium
**Dependencies**: Phase B (Cap/LSM), Phase C (storage), Phase D (network)

#### F.1 Namespaces

- [ ] PID namespace (isolated PID numbering)
- [ ] Mount namespace (isolated FS view)
- [ ] IPC namespace (isolated message queues)
- [ ] Network namespace (isolated stack)
- [ ] User namespace (UID/GID mapping)

#### F.2 Cgroups v1.5

- [ ] cpu controller (shares, quota, burst)
- [ ] memory controller (hard/soft limits, OOM)
- [ ] pids controller (process count limit)
- [ ] io controller (bandwidth limit)

#### F.3 IOMMU/VT-d

- [ ] DMA isolation
- [ ] Device domain binding
- [ ] Passthrough preparation

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

### Phase G: Production Readiness

**Goal**: Observable, compliant, updatable.

**Priority**: Medium
**Dependencies**: All previous phases

#### G.1 Observability

- [ ] Tracepoints/counters infrastructure
- [ ] Sampling profiler
- [ ] kdump (encrypted, redacted)
- [ ] Health monitoring (watchdog, hung-task)

#### G.2 Live Patching

- [ ] Patch framework
- [ ] Rollback policy
- [ ] Signature verification

#### G.3 Compliance

- [ ] Hardening profiles (Secure/Balanced/Performance)
- [ ] Audit remote delivery
- [ ] FIPS mode preparation

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
| **Total** | **70** | **342** | **291 (85.1%)** | **51 open (R65 SMP + VirtIO IOMMU deferred)** |

### Current Status

- **Fixed**: 291 issues (85.1%)
- **Open**: 51 issues (14.9%)
  - R65 remaining issues (SMP-related, non-blocking)
  - R62-6 (VirtIO IOMMU) deferred to Phase F.3
- **Phase E Progress**: LAPIC/IOAPIC initialized, PerCpuData implemented, GS-relative syscall per-CPU, AP idle loop race-free, TLB shootdown serialized, **ALL R67-R70 SMP ISSUES FIXED**
- **SMP Ready**: All critical SMP security issues resolved, multi-core testing can proceed

See [qa-2026-01-21.md](review/qa-2026-01-21.md) for latest audit report.

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
