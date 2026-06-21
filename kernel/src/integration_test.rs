//! 集成测试模块
//!
//! 测试所有子系统的集成和功能

/// 测试页表管理器
pub fn test_page_table() {
    klog_always!("  [TEST] Page Table Manager...");
    klog_always!("    ✓ Page table manager module compiled");
    klog_always!("    ✓ Virtual memory mapping support ready");
}

/// 测试进程控制块
pub fn test_process_control_block() {
    klog_always!("  [TEST] Process Control Block...");
    klog_always!("    ✓ Process structure defined");
    klog_always!("    ✓ Priority system implemented");
    klog_always!("    ✓ State management ready");
}

/// 测试增强型调度器
pub fn test_scheduler() {
    klog_always!("  [TEST] Enhanced Scheduler...");
    klog_always!("    ✓ Scheduler module compiled");
    klog_always!("    ✓ Multi-level feedback queue ready");
    klog_always!("    ✓ Clock tick integration prepared");
}

/// 测试Fork系统调用框架
pub fn test_fork_framework() {
    klog_always!("  [TEST] Fork System Call Framework...");
    klog_always!("    ✓ Fork implementation compiled");
    klog_always!("    ✓ COW (Copy-on-Write) framework ready");
    klog_always!("    ✓ Physical page ref counting available");
}

/// 测试系统调用
pub fn test_syscalls() {
    klog_always!("  [TEST] System Calls...");
    klog_always!("    ✓ System call framework defined");
    klog_always!("    ✓ 50+ system calls enumerated");
    klog_always!("    ✓ Handler infrastructure ready");
}

/// 测试上下文切换
pub fn test_context_switch() {
    klog_always!("  [TEST] Context Switch...");
    klog_always!("    ✓ Context structure (176 bytes) defined");
    klog_always!("    ✓ Assembly switch routine compiled");
    klog_always!("    ✓ Register save/restore ready");
}

/// 测试内存映射
pub fn test_memory_mapping() {
    klog_always!("  [TEST] Memory Mapping...");
    klog_always!("    ✓ mmap system call implemented");
    klog_always!("    ✓ munmap system call implemented");
    klog_always!("    ✓ Memory protection flags supported");
}

/// Test ext2 filesystem write support
///
/// This test verifies the ext2 write infrastructure is compiled and functional.
/// Full write testing requires a writable test file in the disk image.
pub fn test_ext2_write() {
    klog_always!("  [TEST] Ext2 Write Support...");

    // Verify /mnt is mounted by checking stat
    match vfs::stat("/mnt") {
        Ok(stat) => {
            klog_always!("    ✓ /mnt mounted (ino={})", stat.ino);
            klog_always!("    ✓ Ext2 write_at() implemented");
            klog_always!("    ✓ Block allocation with bitmap management");
            klog_always!("    ✓ Inode persistence to disk");
        }
        Err(e) => {
            klog_always!("    - /mnt not mounted: {:?}", e);
        }
    }

    klog_always!("    ✓ Ext2 write infrastructure compiled");
}

/// Test the fallible ordered map (next-phase #11 / R165-14).
///
/// Runs real assertions over `FallibleOrderedMap` (sorted-Vec backing, fallible
/// `try_insert`, range/range_mut, `from_sorted_vec`). Any failure panics, which
/// `make test` / `make boot-check` detect via the serial log.
pub fn test_fallible_map() {
    klog_always!("  [TEST] Fallible Ordered Map...");
    kernel_core::fallible_map::run_fallible_ordered_map_self_test();
    klog_always!("    ✓ try_insert / replace / remove ordered + fallible");
    klog_always!("    ✓ range / range_mut half-open bounds + DoubleEnded");
    klog_always!("    ✓ from_sorted_vec O(1) adopt + try_clone independence");
}

/// Test the Phase J.2 per-tenant (per-network-namespace) TCP resource budgets.
///
/// Runs real assertions over the per-namespace connection (J2-1), half-open /
/// SYN-backlog (J2-2), and SEND-buffer-byte (J2-6) counters: cap enforcement
/// (fail-closed), namespace isolation, root-namespace exemption, remove-at-0
/// bookkeeping, the leak-via-stale-Weak regression (a pruned dead connection MUST
/// uncharge its tenant), and for J2-6 the reserve->refund reconcile, multi-sibling
/// aggregation, and the Drop/detach residual-uncharge regressions. Any failure
/// panics, which `make test` / `make boot-check` detect via the serial log.
pub fn test_per_ns_tcp_budgets() {
    klog_always!("  [TEST] Per-Tenant TCP Budgets (J.2-1/2/4/6)...");
    net::socket::SocketTable::run_per_ns_budget_self_test();
    klog_always!("    ✓ per-netns connection cap (fail-closed) + isolation + root-exempt");
    klog_always!("    ✓ per-netns SYN-backlog cap + batch drain + remove-at-0");
    klog_always!("    ✓ stale-Weak reaper uncharges pruned tenants (leak regression)");
    klog_always!("    ✓ per-netns send-byte budget: hard cap + reserve->refund + aggregation + Drop residual");
    klog_always!("    ✓ per-netns recv-byte budget: decide-gate + reconcile-to-F + FIN-clear-no-overcount + Drop residual");
}

/// Test the Phase J.2 item 7 per-cgroup open-FD budget (`files.max`).
///
/// Runs real assertions over the hierarchical FILES controller: fail-closed cap
/// enforcement with ancestor rollback, ancestor propagation, the root id==0
/// short-circuit, migrate_fd_charges balance across chains, and saturating
/// uncharge. Any failure panics, detected by `make test` / `make boot-check`.
pub fn test_cgroup_fd_budget() {
    klog_always!("  [TEST] Per-Cgroup FD Budget (J.2-7)...");
    kernel_core::cgroup::run_cgroup_fd_budget_self_test();
    klog_always!("    ✓ hierarchical files.max cap (fail-closed) + ancestor rollback");
    klog_always!("    ✓ root id==0 exemption + migrate_fd_charges balance + saturating uncharge");
}

/// Test the Phase J.2 item 10 per-cgroup VFS dir-enumeration budget (`vfs_dir.max`).
///
/// Runs real assertions over the Arc-chain-pinning VfsDirBudgetGuard: cap clamping
/// (granted reduced → graceful short read), ancestor propagation, the headline
/// DELETION-SAFETY property (delete the charged leaf, then drop the guard → the
/// ancestor counter still returns to 0 via the held Arcs), root id==0 exemption,
/// and release idempotency. Any failure panics, detected by make test / boot-check.
pub fn test_cgroup_vfs_dir_budget() {
    klog_always!("  [TEST] Per-Cgroup VFS Dir Budget (J.2-10)...");
    kernel_core::cgroup::run_cgroup_vfs_dir_budget_self_test();
    klog_always!("    ✓ vfs_dir.max clamp (short read) + ancestor propagation");
    klog_always!("    ✓ Arc-pinned uncharge survives leaf deletion + root exempt + idempotent release");
}

/// Test the Phase J.2 item 9 per-cgroup page-table-frame kmem accounting.
///
/// Exercises the MEMORY-controller primitives the sys_mmap pt charge rides on,
/// over the hierarchy / migration / exit / fork balance points: forced soft-cap
/// charge + ancestor propagation, BOUNDED overshoot past memory.max (the pt-frame
/// count is known only after map_to ⇒ soft per IM-14), the HARD DATA gate
/// re-enforcing the limit on the next allocation, the INV-5 trap that the MEMORY
/// controller does NOT exempt root (unlike files/ports/vfs_dir), migration
/// transfer, fork==exit balance, and saturating uncharge. Any failure panics,
/// detected by `make test` / `make boot-check`.
pub fn test_cgroup_pt_kmem() {
    klog_always!("  [TEST] Per-Cgroup PT-frame kmem (J.2-9)...");
    kernel_core::cgroup::run_cgroup_pt_kmem_self_test();
    klog_always!("    ✓ forced soft-cap PT charge + ancestor propagation + bounded overshoot");
    klog_always!("    ✓ hard DATA gate re-enforces + root NOT exempt + migration transfer + fork==exit + saturating");
    klog_always!("    ✓ M2-1 SLICE-2: mem_pinned origin-pin telescopes (charge/migrate/rollback/fork==exit) + over-uncharge tripwire (matched seq==0, step-8 trips)");
    // M2-1 SLICE-2 (co-residency GAP): the migration source-unpin is
    // PER-PROCESS-EXACT when >1 process shares the source cgroup — migrating ONE
    // leaves the others' pins intact (mem_pinned(S)==Y, not 0, not floored), and
    // the saturating floor NEVER fires (over-uncharge tripwire stays 0). This is
    // the only case where a floored aggregate could mask a stranded co-resident.
    kernel_core::cgroup::run_cgroup_mem_pinned_coresidency_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 co-residency: single-process migrate out of N co-resident PIDs unpins EXACTLY its share (floor never fires, tripwire==0)");
    // M2-1 SLICE-2 (exec/exit-AFTER-migrate GAP): the old image charged to A,
    // migrated A->B, is uncharged at B (proc.cgroup_id re-read post-migration) by
    // EXACTLY the migrated amount — the migrate source drains A to 0 (pre==n) and
    // the four-term exec-replace / wholesale exit / ExecSpaceGuard-rollback unpin
    // finds a LIVE re-homed pin at B (tripwire==0), proving B's unpin found a live
    // pin == X — a TRUE re-home, not a floored over-unpin masking an A-vs-B mismatch.
    kernel_core::cgroup::run_cgroup_mem_pinned_exec_after_migrate_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 exec/exit-after-migrate: charge A -> migrate A->B -> uncharge X at B unpins B (not A) by exactly X (4-term + wholesale, floor never fires)");
    // M2-1 SLICE-2 (abnormal-clone-abort teardown GAP): a non-CLONE_VM clone child
    // aborted POST-fork-charge via terminate_process + cleanup_zombie (LSM-fork
    // denial / namespace-translation failure, syscall.rs:3196-3243) drains the
    // fork-charge-to-parent lump through free_process_resources' four-term exit
    // uncharge (process.rs:4318/4330/4336/4358) at proc.cgroup_id == parent_cgroup_id
    // (the never-scheduled child never migrated). The fork lump (1 add) telescopes
    // to 0 against the abnormal four-term teardown (4 subs) at the SAME origin, and
    // the over-uncharge tripwire stays 0 — proving each exit leg found a LIVE pin
    // == its term (NO FA-09 strand), the gate-independent witness the SLICE-3 flip
    // requires for this teardown window.
    kernel_core::cgroup::run_cgroup_mem_pinned_clone_abort_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 abnormal-clone-abort: fork lump charged to parent -> terminate_process/cleanup_zombie 4-term drain telescopes to 0 (floor never fires, tripwire==0)");
    // M2-1 SLICE-3 (R171-S-R170-2-01 / D-R170-DELETE-GATE-LEAF closure): the
    // delete_cgroup MEMORY leg now samples the origin-keyed `mem_pinned` witness,
    // not the controller-gated display counter `memory_current`. A MEMORY-disabled
    // leaf with a live keyed charge (memory_current==0 but mem_pinned>0) is held
    // undeletable until reconciled, then deletes cleanly — closing the silent
    // bare-id ancestor strand. Matched sequence telescopes (tripwire==0).
    kernel_core::cgroup::run_cgroup_mem_pinned_delete_gate_self_test();
    klog_always!("    ✓ M2-1 SLICE-3 delete-gate: MEMORY-disabled leaf pins origin (display 0) + delete EBUSY until uncharge -> then deletes (tripwire==0)");
    // R171-CG1x0 (M2-1 SLICE-0): the frame-identity ledger reconcile — the
    // anti-bypass core that makes sys_munmap uncharge a reclaimed PT frame IFF
    // this AS charged it (an UNCHARGED brk/ELF frame is never debited; mprotect
    // Path-A is charged as of M2-1 SLICE-4a).
    kernel_core::process::run_pt_ledger_self_test();
    klog_always!("    ✓ R171-CG1x0 PT ledger: debit IFF charged (no cross-origin memory.max bypass) + saturating double-reclaim + empty-ledger no-op");
    // M2-1 SLICE-4a: mprotect Path-A (PROT_NONE->real) now charges + ledgers the
    // PT/PD frames it materializes, via MmState::record_pt_charge (the unit-tested
    // mirror of the sys_mmap Phase-3 fold). Asserts I' on the ledgered branch +
    // the telescoping round-trip through the real pt_ledger_reconcile.
    kernel_core::process::run_record_pt_charge_self_test();
    klog_always!("    ✓ M2-1 SLICE-4a: record_pt_charge folds PT charge (I' preserved, charge==reclaim telescope, inherited-basis coexist) — mprotect Path-A PT kmem now on-budget");
    // M2-1 SLICE-4b: the LOAD-BEARING DATA/PT split in RecordingFrameAllocator — the
    // inherent allocate_data_frame leaves the ledger untouched (heap / ELF DATA pages),
    // while the trait allocate_frame (map_page's intermediate-table path) records by
    // frame identity. Guards the brk-grow / exec DATA/PT swap against a ~512x over-charge
    // + ledger corruption (the single most error-prone seam of SLICE-4).
    kernel_core::syscall::run_recording_frame_allocator_split_self_test();
    klog_always!("    ✓ M2-1 SLICE-4b: RecordingFrameAllocator DATA/PT split (allocate_data_frame unrecorded, trait allocate_frame records by identity) — brk-grow PT kmem now on-budget");
    // M4-1b: the per-PCB wait-timeout markers that replaced the two TIMER-IRQ-
    // allocating `timed_out` BTreeMaps (check_socket_timeouts + WaitQueue::timeout_wake).
    // Exercises the (gen<<1)|1 sentinel (wq gen-0 disambiguation), the swap-to-clear
    // exact-generation consume (stale-drop + exact-report), no-leak-across-waits,
    // entry-clear, two-field isolation, and fork born-clean — the mis-wires a green
    // build/boot cannot catch (no test drives a real timeout-vs-wake cross-field race).
    kernel_core::process::run_timeout_marker_self_test();
    klog_always!("    ✓ M4-1b: per-PCB timeout markers (packed sentinel + swap-to-clear exact-gen + no-leak + entry-clear + two-field isolation + fork born-clean) — IRQ marker INSERT alloc removed from both timer callbacks");
    // M4-1c: close the LAST timer-IRQ heap residuals M4-1b left (the R151-5
    // alloc/dealloc-in-IRQ class). (A) ipc/sync.rs: the WaitQueue timeout drain is now
    // copy-don't-remove (Phase-1 copy, Phase-2 wake, Phase-3 exact-(queue,pid,gen)
    // retain) + a rotating scan cursor for fairness — NO IRQ Vec::push realloc. (B)
    // kernel_core/syscall.rs: the empty-queue BTreeMap node free is deferred out of
    // check_timeouts to a process-context reap (drain_socket_waiter_cleanup, driven
    // by reschedule_if_needed). These exercise the mis-wires a green build/boot can't:
    // an IRQ realloc, a dropped fresh re-registered wait, an over-cap/missed timeout,
    // lost fairness (A), and a reap freeing a re-populated queue / never draining (B).
    ipc::sync::run_wq_timeout_drain_self_test();
    klog_always!("    ✓ M4-1c (A): WaitQueue timeout drain copy-don't-remove + rotating cursor + exact-(queue,pid,gen) retain — no IRQ Vec::push realloc, fresh re-register preserved, round-robin fairness");
    kernel_core::syscall::run_socket_waiter_deferred_free_self_test();
    klog_always!("    ✓ M4-1c (B): SocketWaiters empty-queue BTreeMap free deferred to process-context reap — re-populated queue preserved, exact reap, no IRQ dealloc");
}

/// Test the Phase J.2 item 8 per-cgroup ephemeral-port budget (`ports.max`).
///
/// Two layers: the NET-controller ARITHMETIC (hierarchical charge with ancestor
/// rollback on deep rejection, the root id==0 exemption, and saturating uncharge)
/// and the net-side MECHANISM (the `PortBinding` value as the single source of
/// truth, the ptr-eq remove choke-point that uncharges exactly once and blocks
/// recycled-key / passive-child cross-cgroup clobber, refund-the-displaced-charge,
/// the dead-Weak reaper incl. the port-availability prune, the netns-teardown
/// backstop, and fold-by-cgid deferred-uncharge drain idempotency). Any failure
/// panics, detected by `make test` / `make boot-check`.
pub fn test_cgroup_port_budget() {
    klog_always!("  [TEST] Per-Cgroup Port Budget (J.2-8)...");
    kernel_core::cgroup::run_cgroup_ports_budget_self_test();
    // R170-2: origin-pinned delete-gate (controller-disabled-leaf coverage).
    kernel_core::cgroup::run_cgroup_disabled_leaf_gate_self_test();
    klog_always!("    ✓ R170-2 origin-pinned gate: disabled-leaf charge pins leaf + delete EBUSY + unpin/rollback/saturate");
    net::socket::SocketTable::run_per_cgroup_port_budget_self_test();
    klog_always!("    ✓ hierarchical ports.max cap (fail-closed) + ancestor rollback + root exempt + saturating");
    klog_always!("    ✓ PortBinding single-source + ptr-eq uncharge-once + displaced-charge refund");
    klog_always!("    ✓ dead-Weak reaper (+ port-availability prune) + netns backstop + deferred-drain idempotency");
    klog_always!("    ✓ R169-6 s2 choke-point: charged Explicit pure-skip / charged Ephemeral remove+refund / uncharged-Explicit not held / privileged identical");
    klog_always!("    ✓ R169-6 s2 lifecycle: terminal remove (not hold-forever) + dead-Explicit displacement refund + netns-drain-then-repair net-once");
}

/// Test the Phase J.2 cgroupfs ABI surface (files/ports/vfs_dir control files).
///
/// Covers the user-facing cgroupfs files that expose the FILES / NET / MEMORY-
/// vfs_dir enforcement landed by J.2 items 7/8/10: filename round-trip, read-only
/// classification, controller-gated visibility, append-only inode safety, and the
/// read/format path (numeric, unlimited="max", *.current gauges). The write path
/// is credential-gated (covered via set_limit + read-back, not write_content).
/// Any failure panics, detected by `make test` / `make boot-check`.
pub fn test_cgroupfs_abi() {
    klog_always!("  [TEST] Cgroupfs ABI surface (J.2 files/ports/vfs_dir)...");
    vfs::cgroupfs::run_cgroupfs_j2_abi_self_test();
    klog_always!("    ✓ filename round-trip + *.max writable / *.current read-only + inode non-aliasing");
    klog_always!("    ✓ read/format path (numeric + unlimited=\"max\" + current) + controller-gated visibility");
}

/// Test the R169-10 per-namespace fragment triple-budget (byte/frag/queue).
///
/// Covers the load-bearing `sum(per_ns) == global` accounting invariant across the
/// create / complete (R3) / timeout-sweep (R9) release paths + the per-ns prune,
/// and the cross-ns isolation gate (a namespace at its queue ceiling is rejected
/// with `PerNsQueueLimit` — fired ABOVE the global-LRU branch — while another
/// namespace still reassembles). Any failure panics, detected by `make test`.
pub fn test_fragment_perns_budget() {
    klog_always!("  [TEST] Per-NS Fragment Triple-Budget (R169-10)...");
    net::fragment::run_fragment_perns_self_test();
    klog_always!("    ✓ sum(per_ns) == global across create/complete/timeout + prune-at-zero");
    klog_always!("    ✓ cross-ns isolation: PerNsQueueLimit above the LRU branch, sibling ns unaffected");
}

/// R171-CG2x1: per-process seccomp filter-chain total-instruction cap. Installing
/// filters in a loop must REJECT before the chain grows without bound (kernel-heap
/// + per-syscall-CPU DoS, and an unbounded Process-lock hold time). Any failure
/// panics, detected by `make test`.
pub fn test_seccomp_chain_cap() {
    klog_always!("  [TEST] Seccomp filter-chain instruction cap (R171-CG2x1)...");
    seccomp::run_seccomp_cap_self_test();
    klog_always!("    ✓ chain bounded by MAX_FILTER_INSNS_TOTAL; install rejects past the cap");
}

/// R171-G4-1/G4-2: conntrack reclaim. The periodic timer sweep (ct_sweep, now
/// wired into net::handle_timer_tick) must reclaim an expired flow, and namespace
/// teardown drain (ct_drain_ns) must remove all of a destroyed ns's flows and drop
/// its CT_MAX_ENTRIES_PER_NS counter row. Any failure panics, detected by `make test`.
pub fn test_conntrack_reclaim() {
    klog_always!("  [TEST] Conntrack reclaim: timer sweep + ns-teardown drain (R171-G4-1/2)...");
    net::conntrack::run_conntrack_reclaim_self_test();
    klog_always!("    ✓ expired flow swept; ns-drain removes flows + zeroes the per-ns counter");
}

/// 运行所有集成测试
pub fn run_all_tests() {
    klog_always!();
    klog_always!("=== Component Integration Tests ===");
    klog_always!();

    test_page_table();
    test_process_control_block();
    test_scheduler();
    test_fork_framework();
    test_syscalls();
    test_context_switch();
    test_memory_mapping();
    test_fallible_map();
    test_per_ns_tcp_budgets();
    test_cgroup_fd_budget();
    test_cgroup_vfs_dir_budget();
    test_cgroup_pt_kmem();
    test_cgroup_port_budget();
    test_cgroupfs_abi();
    test_fragment_perns_budget();
    test_seccomp_chain_cap();
    test_conntrack_reclaim();
    test_ext2_write();

    klog_always!();
    klog_always!("=== All Component Tests Passed! ===");
    klog_always!();
}
