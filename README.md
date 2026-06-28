[Switch to Chinese (切换到中文)](README_zh.md)

# Nilix

A security-first hybrid microkernel operating system written in Rust for the x86_64 architecture.

> **Nilix** is a recursive acronym — **N**ilix **I**s **L**inux **I**ndependent e**X**istence — in the
> self-referential naming tradition of GNU and Linux. The name captures the positioning: Linux-*compatible*
> (a byte-exact syscall ABI runs a real musl libc binary unmodified) yet Linux-*independent* (its own
> from-scratch Rust kernel, not a fork).

**Design Principle:** Security > Correctness > Efficiency > Performance

---

## 1. Overview

Nilix is an enterprise-grade hybrid kernel inspired by Linux's modular design, hardened
through **172 successive security-audit rounds**. It pairs a capability- and LSM-gated
in-kernel hot path with a roadmap toward a de-privileged Linux-compatible user-space
personality.

- **Memory Safety** — written entirely in Rust (`no_std`), backed by hardware protections
  (NX, W^X, SMEP/SMAP/UMIP) and KASLR/KPTI.
- **Process Isolation** — per-process address spaces, Copy-on-Write fork, user-stack guard pages.
- **SMP** — multi-core bring-up (up to 64 CPUs), per-CPU MLFQ scheduling, work-stealing load
  balancing, IPI-driven TLB shootdown, RCU and lockdep.
- **Security Framework** — object capabilities, an LSM hook layer (40+ hook points),
  seccomp/pledge syscall filtering, and a SHA-256 hash-chained tamper-evident audit log.
- **Containers** — five namespaces (PID/mount/IPC/net/user) and cgroups v2 (CPU, memory, PIDs,
  I/O, FD, port controllers).
- **Network** — a full software TCP/IP stack (TCP with NewReno, window scaling, SYN cookies,
  connection tracking, and a stateful default-DROP firewall).
- **Linux ABI** — a byte-exact x86-64 syscall surface; a real **static-musl libc binary runs
  end-to-end** under the user-mode ABI (Phase U / milestone M0).

### Current Status

**Milestone:** approaching **1.0-Preview** — Phase A–G complete; **Phase U** (user-mode ABI)
in progress. The 1.0-Preview release gate is currently **QUALIFIED** (0 open HIGH findings)
after the R172 audit + same-day remediation. See [Section 6](#6-security-audit-status).

| Subsystem | Status | Highlights |
|-----------|--------|-----------|
| Boot & Memory | ✅ Complete | UEFI static-PIE boot, high-half map, reservation-aware buddy allocator, page cache, COW fork, guard pages, OOM killer |
| Process & Threads | ✅ Complete | Per-process address spaces, fork/exec/clone, threads + TLS, wait/zombie reaping, hung-task watchdog |
| Scheduler | ✅ Complete | Per-CPU MLFQ, preemptive, work-stealing + periodic load balancing, CPU affinity / cpuset |
| IPC | ✅ Complete | Pipes, capability message queues, futex (+ priority inheritance), POSIX signals |
| Hardening | ✅ Complete | W^X/NX, SMEP/SMAP/UMIP, KASLR, KPTI, Spectre/Meltdown mitigations, ChaCha20 CSPRNG, kptr guard |
| Security Framework | ✅ Complete | Capabilities, LSM (40+ hooks), seccomp/pledge, SHA-256/HMAC hash-chained audit, compliance profiles |
| VFS & Storage | ✅ Complete | ramfs, ext2, procfs, devfs, initramfs (CPIO), cgroupfs, DAC + openat2 RESOLVE flags, virtio-blk |
| Network | ✅ Complete | virtio-net, ARP, IPv4 (+reassembly), ICMP, UDP, TCP, conntrack, stateful firewall |
| SMP & Concurrency | ✅ Complete | LAPIC/IOAPIC, AP boot (≤64 CPUs), IPI TLB shootdown, PCID/INVPCID, RCU, lockdep |
| Containers | ✅ Complete | PID/mount/IPC/net/user namespaces, cgroups v2 (6 controllers) |
| IOMMU / VT-d | 🟡 Infrastructure | Full Intel VT-d driver (DMA isolation, IRQ remapping, fault handling); DMAR discovery wiring pending |
| Live Patching | 🟡 Infrastructure | ECDSA P-256 signed kpatch, INT3 detour, fail-closed LSM gate |
| User Mode & ABI (Phase U / M0) | 🟡 In Progress | Ring 3, 100+ Linux syscalls, SysV auxv, signal delivery, static-musl libc runs end-to-end |
| CI & Quality Gates | ✅ Complete | GitHub Actions (fmt/clippy, build, lint, boot+musl), custom lint gates, local-first pre-push hook with optional SSH offload |

---

## 2. Project Structure

The kernel is a Cargo workspace of focused crates (`kernel/<subsystem>/`), each owning one
concern. The bootloader and the user-space programs are separate build units.

```text
Nilix/
├── bootloader/             # UEFI bootloader: ELF load, relocation (PIE), high-half paging, KASLR slide
├── kernel/
│   ├── arch/               # x86_64: IDT/exceptions, context switch, SYSCALL/SYSRET, GDT/TSS, APIC, SMP, IPI, INVPCID
│   ├── mm/                 # Buddy allocator, heap, page tables, page cache, TLB shootdown, OOM killer, fallible_map
│   ├── sched/              # Per-CPU MLFQ scheduler + documented lock ordering (lockdep)
│   ├── ipc/                # Pipes, capability message queues, futex (+PI), WaitQueue/KMutex/Semaphore
│   ├── kernel_core/        # PCB & process table, fork (COW), exec + ELF loader, signals, namespaces, cgroups, RCU, syscalls
│   ├── cap/                # Object-capability model (CapId, CapRights, CapTable)
│   ├── lsm/                # Linux Security Module hook layer + policies
│   ├── seccomp/            # seccomp/pledge syscall filtering (BPF-like VM)
│   ├── audit/              # SHA-256 / HMAC hash-chained tamper-evident audit log
│   ├── crypto/             # Shared no_std crypto (SHA-256, ECDSA P-256) for audit + livepatch
│   ├── compliance/         # Hardening profiles (Secure / Balanced / Performance)
│   ├── security/           # W^X, NX, KASLR, KPTI, Spectre/Meltdown, kptr guard, RNG, memory hardening
│   ├── vfs/                # VFS core, ramfs, ext2, procfs, devfs, initramfs, cgroupfs, mount namespaces
│   ├── block/              # Block layer + virtio-blk driver (PCI/MMIO), BIO queue
│   ├── virtio/             # Shared VirtIO transport (virtqueues)
│   ├── net/                # TCP/IP stack: virtio-net, ARP, IPv4, ICMP, UDP, TCP, conntrack, firewall, sockets
│   ├── iommu/              # Intel VT-d: DMAR parse, domains, fault handling, interrupt remapping
│   ├── cpu_local/          # Per-CPU data (CpuLocal<T>), LAPIC-ID ↔ CPU-index mapping
│   ├── tlb_ops/            # PCID / INVPCID TLB invalidation primitives
│   ├── livepatch/          # Signed live kernel patching (kpatch-style)
│   ├── trace/              # Static tracepoints, per-CPU counters, hung-task watchdog
│   ├── klog/               # Profile-aware kernel logging (klog!/klog_force!/kprintln!)
│   ├── drivers/            # VGA / serial (UART 16550) / PS-2 keyboard
│   ├── src/                # Kernel entry (main.rs), runtime tests, Ring-3 boot diagnostics
│   └── kernel.ld           # Linker script
├── userspace/              # Ring-3 programs: shell, syscall_test, hello_musl.c (static-musl conformance binary)
├── scripts/                # CI gate scripts: boot_check.sh, musl_check.sh, smp_check.sh, iommu_check.sh, …
├── docs/                   # roadmap.md, roadmap-enterprise.md, next-phase-plan.md, review/ (QA reports)
├── .github/workflows/ci.yml  # GitHub Actions pipeline
├── .githooks/pre-push      # Local-first fmt + clippy gate (optional SSH offload)
└── Makefile                # Build / run / lint / gate targets
```

---

## 3. Core Components

### 3.1 Boot & Memory

- **UEFI boot** — the bootloader loads a static-PIE `kernel.elf`, applies `R_X86_64_RELATIVE`
  relocations (with an RDRAND-derived KASLR slide), sets up 4-level paging, identity-maps the
  low region for hardware access, and maps the high-half kernel at `0xFFFFFFFF80000000`.
- **Buddy allocator** — reservation-aware physical page allocation: heap/kernel/framebuffer/UEFI
  regions are reserved per-page so they can never collide with the allocator (fail-closed on
  overflow).
- **COW fork** — page-table deep-copy with shared, ref-counted physical frames; fork-time cgroup
  memory charging.
- **Page cache** — global hashed LRU with per-inode indexing, page-state tracking, dirty
  writeback, and reclaim under memory pressure.
- **Guard pages** — unmapped guard pages protect the kernel stack and the double-fault IST stack;
  user stacks carry a permanently-unmapped guard page.
- **OOM killer** — watermark-triggered cache reclaim, per-process scoring, audited emergency kill.

### 3.2 Process, Threads & Scheduler

- **PCB** — full per-task state: pid/tgid, priority, CPU affinity, cgroup membership, TLS
  (FS/GS base), seccomp/pledge state, namespace chains, per-task resource limits.
- **fork / exec / clone** — independent address spaces (or shared `MmState` under `CLONE_VM`);
  threads via `CLONE_THREAD` with TLS, `set_tid_address`, and a `robust_list` for futex cleanup.
- **Scheduler** — a per-CPU Multi-Level Feedback Queue with starvation detection and priority
  boosting, preemption on timer ticks, work-stealing, periodic load balancing, and CPU
  affinity / cpuset isolation.
- **Wait / exit** — zombie reaping via `wait4`/`waitpid`, `SIGCHLD` to the parent, orphan
  reparenting; cross-CPU deferred termination; a hung-task watchdog heartbeat.

### 3.3 IPC & Signals

- **Pipes** — FIFO buffers with reader/writer ref-counting and signal-interruptible blocking I/O.
- **Message queues** — capability-gated endpoints, partitioned per IPC namespace.
- **Futex** — `FUTEX_WAIT`/`FUTEX_WAKE`, plus `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI` with priority
  inheritance and per-thread-group bucket budgets.
- **Signals** — 64 POSIX signals, per-task blocked masks and dispositions; synchronous handler
  delivery on the syscall-return path with a SROP-defended `rt_sigframe` builder and
  `rt_sigreturn`; EINTR wake of blocked syscalls.

### 3.4 Security Framework

- **Capabilities** — non-forgeable `CapId` (generation + index), `CapRights` bitflags, a per-process
  `CapTable`, and capability syscalls (allocate / revoke / delegate) gated by LSM + audited.
  *(fd-table → capability integration is still in progress; file-descriptor access remains
  ambient for now.)*
- **LSM** — a pluggable `LsmPolicy` trait with 40+ hook points across syscalls, task lifecycle,
  VFS, memory, IPC, signals, network, and livepatch; default policy is permissive, with
  deny-all and custom policies supported. Denials are fail-closed and audited.
- **Seccomp / Pledge** — a BPF-like filter VM with 18 pledge promises and a fast-allow bitmap;
  a boot-time partition self-test guards against seccomp/dispatch divergence.
- **Audit** — SHA-256 (FIPS 180-4) hash-chained events with an optional HMAC-SHA256 mode,
  bounded ring buffer with overflow tracking, and a cursor-based non-draining export interface.
- **Compliance profiles** — Secure / Balanced / Performance, each tuning W^X strictness,
  Spectre mitigations, kptr guard, audit capacity, and log verbosity.

### 3.5 Memory-Safety Hardening

W^X enforcement (no page is both writable and executable), NX on data pages, SMEP/SMAP/UMIP,
KASLR (kernel heap/stack/mmap + text-relocation infrastructure), KPTI dual page-table isolation,
Spectre/Meltdown mitigations (IBRS/IBPB/STIBP/SSBD, RSB stuffing, SWAPGS+LFENCE), a ChaCha20
CSPRNG seeded from RDRAND/RDSEED, and kernel-pointer obfuscation (kptr guard).

### 3.6 VFS & Storage

VFS inode abstraction over ramfs, ext2 (read/write, page-cache-backed), procfs
(`/proc/self`, `/proc/[pid]/…`, `/proc/meminfo`), devfs (`/dev/null|zero|console`),
initramfs (CPIO `newc`), and cgroupfs. POSIX DAC (owner/group/other, umask, sticky bit),
`openat2` `RESOLVE_*` flags (`NO_SYMLINKS`/`BENEATH`/`IN_ROOT`/`NO_XDEV`/`NO_MAGICLINKS`),
symlink-loop detection, and per-namespace copy-on-write mount tables. Storage is backed by a
virtio-blk driver (PCI + MMIO) and a BIO request layer.

### 3.7 Network

A software TCP/IP stack: virtio-net driver, DMA-friendly packet buffers, Ethernet/ARP
(anti-spoofing, rate-limited), IPv4 (checksums, source-route rejection, fragment reassembly
with overlap detection), ICMP, and UDP. TCP implements the full state machine and 3-way
handshake, RFC 6298 RTT/RTO with Karn's algorithm, NewReno congestion control, window scaling,
SYN cookies, listen/accept, and graceful close. Above the protocols sit connection tracking,
a stateful priority-ordered firewall (ACCEPT/DROP/REJECT, default-DROP), and a
capability-based socket API with per-hook LSM mediation.

### 3.8 SMP, IOMMU & Concurrency

LAPIC/IOAPIC init, AP bring-up via INIT-SIPI-SIPI (up to 64 CPUs), five IPI types, IPI-driven
TLB shootdown with per-CPU mailboxes, PCID/INVPCID, per-CPU data (`CpuLocal<T>`), RCU
grace-period reclamation, and a documented 9-level lock ordering with a lockdep checker. The
Intel VT-d driver provides DMAR parsing, domain management, DMA second-level page tables, fault
handling, and interrupt remapping (DMAR table discovery wiring is the remaining boot step).

### 3.9 Containers

Five namespaces — PID (cascade init-kill), mount (CoW tables), IPC (System V), network
(per-NS devices/sockets), and user (UID/GID mapping for unprivileged containers) — driven by
`clone(2)`/`unshare(2)`/`setns(2)`. Cgroups v2 provide CPU (`cpu.weight`/`cpu.max`), memory
(`memory.max`/`memory.high` + OOM events), PIDs, I/O (token-bucket `io.max`), FD, and port
controllers, exposed via syscalls and a `/sys/fs/cgroup` cgroupfs mount, with subtree delegation.

### 3.10 User Mode & Linux ABI (Phase U / M0)

Ring-3 execution via SYSCALL/SYSRET, **100+ Linux x86-64 syscalls** (113 dispatched), a full
SysV AMD64 `auxv` builder on the initial stack, ELF loading with DoS/corruption guards, `#!`
shebang resolution, path-based `execve` vs. native image-spawn disambiguation, and signal
delivery. The headline milestone: **a genuine statically-linked musl libc binary runs
end-to-end** — crt startup consuming the auxv, musl stdio `printf`→`writev`, and a clean
`exit(0)` — proven by the `musl-check` conformance gate.

> M0 is foundational and intentionally divergent from full Linux: resource limits are advisory
> (not yet enforced on `brk`/`mmap`), there is no dynamic linking (`ld.so`/vDSO) or user-space
> ASLR yet, and `readlink`/`symlink`/`chown` and a few other syscalls are deferred. These are
> tracked under Phase U in `docs/next-phase-plan.md`.

---

## 4. Build and Run

### Prerequisites

- Rust **nightly** with `rust-src` and `llvm-tools-preview` (pinned in `rust-toolchain.toml`;
  targets `x86_64-unknown-none` and `x86_64-unknown-uefi`)
- QEMU (`qemu-system-x86_64`) with OVMF firmware for UEFI boot
- GNU Make
- `musl-tools` (`musl-gcc`) — only for the musl conformance gate

### Common commands

```bash
make build           # Build bootloader + kernel into the EFI System Partition (esp/)
make run             # Run in QEMU (graphical VGA window)
make run-serial      # Run with serial console on the terminal
make run-shell       # Build + run the interactive shell (serial)
make run-blk         # Attach a 64 MB ext2 virtio-blk disk
make run-smp         # Multi-core boot (SMP_CPUS=N, default 2)
make debug           # Start QEMU paused for GDB on :1234
make clean           # Remove build artifacts
```

QEMU is launched with a CPU model that exposes `+smep,+smap,+umip,+rdrand`, so SMEP/SMAP/UMIP
and hardware RNG are exercised by default. Run `make help` for the full target list.

---

## 5. Continuous Integration & Quality Gates

Nilix enforces correctness, style, and boot health automatically — the same gates run in CI, and
contributors can run them locally (the maintainer's Windows mirror offloads to a Linux build host).

### 5.1 GitHub Actions (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`, with in-progress runs on the same ref cancelled.
Four parallel jobs:

| Job | Runs | Asserts |
|-----|------|---------|
| **rustfmt + clippy** | `make fmt-check` · `make clippy` | All crates rustfmt-clean; clippy reports no errors |
| **build** | `make build` | Bootloader + kernel compile (PIE / build-std / hardened flags) |
| **custom lints** | `make lint` | Four grep-based source gates pass (below) |
| **boot + musl** | `make boot-check` · `make musl-check` | Kernel boots clean to user space, and a static-musl binary runs end-to-end |

### 5.2 Boot & conformance gates

Unlike `make test` (which is `timeout 10 qemu … || true` and always exits 0), these gates have
**real exit codes** read from the serial log and the QEMU `-d int` interrupt log — never from
QEMU's own exit code.

- **`make boot-check`** (`scripts/boot_check.sh`) — boots under QEMU and fails unless the kernel
  reaches user space / its idle loop **and** zero NX-violation instruction-fetch page faults
  occurred (the `v=0e e=0011` signature from the D1-BOOT-NX-KASLR-LAYOUT class of bugs).
- **`make musl-check`** (`scripts/musl_check.sh`) — builds with `--features musl_test` so the
  embedded `hello_musl.elf` is the Ring-3 init program, then asserts **all** of: the
  libc-attributable `printf` marker (`42 * 2 = 84`), the `musl libc test passed!` success line,
  a clean `exit code 0`, zero NX-violation #PF, and no kernel panic. The gate is bidirectional
  and fail-closed — the default (native-Rust) kernel, which also exits 0, never prints the libc
  marker and therefore fails the gate.

### 5.3 Custom source lints (`make lint`)

Lightweight grep-based gates that catch regressions the compiler can't:

| Gate | Enforces |
|------|----------|
| `lint-release` | No ungated `println!` in kernel code (only `drivers/`, `klog/`); use `kprintln!` / `klog!` / `klog_force!` |
| `lint-smap` | Only `usercopy.rs` may instantiate `UserAccessGuard` (SMAP-window minimization) |
| `lint-fetch-add` | No bare `fetch_add(1)` for IDs/refcounts in core/VFS paths — use `fetch_update` + `checked_add` (or an explicit `// lint-fetch-add: allow`) |
| `lint-repr-c-copy` | Every `from_raw_parts` / `copy_nonoverlapping` / `transmute` on a `#[repr(C)]` struct at the user boundary must carry a padding-safety annotation |

### 5.4 Style gates & pre-push hook

- **`make fmt-check`** — `cargo fmt --all --check` across the workspace and userspace.
  `rustfmt.toml` pins `newline_style = "Windows"` because the repo stores CRLF blobs.
- **`make clippy`** — clippy across all three build units (bootloader, kernel, userspace) in
  isolated target dirs; deny-by-default correctness errors fail the build.
- **`.githooks/pre-push`** — opt-in (`make hooks`). The hook is **local-first**: it runs
  `make fmt-check` + `make clippy` locally when a Rust toolchain is present, and can offload
  over SSH for a toolchain-less mirror (`git config zeroos.remote`/`zeroos.remoteDir`). Bypass
  a single push with `SKIP_PREPUSH=1 git push`. A pre-commit-framework equivalent
  (`.pre-commit-config.yaml`) is also provided — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 6. Security Audit Status

Nilix is developed under a continuous adversarial-review process: each round audits the
kernel, files findings by severity, fixes them, and converges via bidirectional peer review
(Claude Code + the Codex MCP) before the round closes.

| Metric | Value |
|--------|-------|
| Audit rounds | **172** |
| Cumulative findings | ~1,254 |
| Findings fixed/resolved | ~1,152 |
| Latest round | R172 (`docs/review/qa-2026-06-23.md`) |
| 1.0-Preview release gate | **QUALIFIED** — 0 open HIGH |

The most recent round (**R172**) was the first full audit over the new user-mode ABI
foundation. It surfaced a pre-existing context-switch CRITICAL (a fresh task's first switch-out
could resume into Ring-0 with a user RIP) plus eight HIGH findings; all were fixed and
peer-converged the same day, restoring the 0-HIGH streak and re-qualifying the gate. Per-round
reports live in `docs/review/`, and the live plan is `docs/next-phase-plan.md`.

---

## 7. Roadmap

**Completed**

- **Phase A** — Security foundation: usercopy/SMAP API, Spectre/Meltdown, audit upgrade, SMP-ready interfaces
- **Phase B** — Capability + LSM + seccomp framework, integrated into syscall/VFS/process paths
- **Phase C** — Storage: virtio-blk, page cache, ext2, procfs/devfs/initramfs, OOM killer, `openat2`
- **Phase D** — Network: full TCP/IP stack with conntrack and a stateful firewall
- **Phase E** — SMP & concurrency: AP boot, IPI TLB shootdown, per-CPU scheduling, RCU, lockdep, futex PI
- **Phase F** — Resource governance: five namespaces, cgroups v2 controllers, IOMMU/VT-d driver
- **Phase G** — Production-readiness hardening: KASLR (H.2), KPTI (H.3), tracing & watchdog, livepatch

**In progress**

- **Phase U — User Mode & ABI** (*Compat-ZeroABI*): a capability-first native core plus a
  de-privileged Linux-compatible personality. Milestone **M0** builds the user-mode foundation
  (auxv, signal delivery, missing syscalls, exec disambiguation, user-stack guards) on the
  existing Linux cABI, proven by the static-musl conformance gate, before the native/personality
  fork is committed.
- IOMMU DMAR table-discovery wiring; full demand-grown user stacks; capability-backed fd tables.

**Future**

- Dynamic linking (`ld.so`/vDSO), glibc + OCI compatibility, user-space ASLR
- Per-tenant network resource budgets, NUMA-aware scheduling, KVM/hypervisor support

See [docs/roadmap.md](docs/roadmap.md) and
[docs/roadmap-enterprise.md](docs/roadmap-enterprise.md) for the complete roadmap.

---

## 8. Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full setup (toolchain, hooks, PR flow). In short:

1. Contributors with a local Rust toolchain build, lint, and test locally — exactly what CI
   does. (The maintainer's Windows mirror has no toolchain and offloads to a Linux build host.)
2. Run `make build`, `make lint`, `make boot-check`, and (for ABI changes) `make musl-check`
   before pushing; enable the pre-push `fmt-check` + `clippy` hook with `make hooks`.
3. New features need documentation updates; bug fixes should include regression tests
   (the kernel runs in-kernel self-tests on boot).
4. Git commits are manual — nothing is auto-committed or auto-pushed.

---

## 9. License

This project is for educational and research purposes.

---

## 10. References

- [OSDev Wiki](https://wiki.osdev.org)
- [Writing an OS in Rust](https://os.phil-opp.com)
- [Linux Kernel Source](https://kernel.org)
- [seL4 Microkernel](https://sel4.systems)
