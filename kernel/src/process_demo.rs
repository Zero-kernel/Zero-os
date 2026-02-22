//! 进程管理和调度器演示模块

use kernel_core::process::{
    create_process, get_process, get_process_stats, terminate_process, ProcessState,
};
use sched::scheduler::{add_process, get_scheduler_stats, ready_count, schedule, tick};

/// 演示进程管理功能
pub fn demo_process_management() {
    klog!(Info, "\n=== Process Management Demo ===\n");

    // 演示1: 创建多个进程
    klog!(Info, "1. Creating multiple processes...");

    let proc1 = create_process("worker1".into(), 0, 10).expect("worker1"); // 高优先级
    let proc2 = create_process("worker2".into(), 0, 50).expect("worker2"); // 中优先级
    let proc3 = create_process("worker3".into(), 0, 100).expect("worker3"); // 低优先级

    klog!(Info, "   ✓ Created 3 worker processes");

    // 演示2: 将进程添加到调度器
    klog!(Info, "\n2. Adding processes to scheduler...");
    add_process(proc1);
    add_process(proc2);
    add_process(proc3);
    klog!(Info, "   ✓ {} processes in ready queue", ready_count());

    // 演示3: 查看进程信息
    klog!(Info, "\n3. Process information:");
    if let Some(process) = get_process(proc1) {
        let proc = process.lock();
        klog!(Info,
            "   Process {}: Name={}, Priority={}, State={:?}",
            proc.pid, proc.name, proc.priority, proc.state
        );
    }
    if let Some(process) = get_process(proc2) {
        let proc = process.lock();
        klog!(Info,
            "   Process {}: Name={}, Priority={}, State={:?}",
            proc.pid, proc.name, proc.priority, proc.state
        );
    }
    if let Some(process) = get_process(proc3) {
        let proc = process.lock();
        klog!(Info,
            "   Process {}: Name={}, Priority={}, State={:?}",
            proc.pid, proc.name, proc.priority, proc.state
        );
    }

    // 演示4: 模拟调度
    klog!(Info, "\n4. Simulating scheduling...");
    for i in 0..5 {
        if let Some(pid) = schedule() {
            if let Some(process) = get_process(pid) {
                let proc = process.lock();
                klog!(Info,
                    "   Round {}: Running PID={} ({}), Priority={}, TimeSlice={}ms",
                    i + 1,
                    pid,
                    proc.name,
                    proc.dynamic_priority,
                    proc.time_slice
                );
            }

            // 模拟时钟滴答
            for _ in 0..10 {
                tick();
            }
        }
    }

    // 演示5: 进程统计
    klog!(Info, "\n5. Process statistics:");
    let stats = get_process_stats();
    stats.print();

    // 演示6: 调度器统计
    klog!(Info, "\n6. Scheduler statistics:");
    let sched_stats = get_scheduler_stats();
    sched_stats.print();

    // 演示7: 终止进程
    klog!(Info, "\n7. Terminating processes...");
    terminate_process(proc1, 0);
    terminate_process(proc2, 0);
    terminate_process(proc3, 0);
    klog!(Info, "   ✓ All worker processes terminated");

    // 最终统计
    klog!(Info, "\n8. Final statistics:");
    let final_stats = get_process_stats();
    final_stats.print();

    klog!(Info, "\n✓ Process management demo completed!\n");
}

/// 演示优先级调度
pub fn demo_priority_scheduling() {
    klog!(Info, "\n=== Priority Scheduling Demo ===\n");

    klog!(Info, "1. Creating processes with different priorities...");

    // 创建不同优先级的进程
    let high_prio = create_process("high_priority".into(), 0, 0).expect("high_priority"); // 最高优先级
    let mid_prio = create_process("mid_priority".into(), 0, 70).expect("mid_priority"); // 中等优先级
    let low_prio = create_process("low_priority".into(), 0, 139).expect("low_priority"); // 最低优先级

    add_process(low_prio); // 先添加低优先级
    add_process(mid_prio); // 再添加中优先级
    add_process(high_prio); // 最后添加高优先级

    klog!(Info, "   ✓ Created processes with priorities: 0, 70, 139");

    klog!(Info, "\n2. Observing scheduling order (should be by priority):");

    for round in 0..3 {
        if let Some(pid) = schedule() {
            if let Some(process) = get_process(pid) {
                let proc = process.lock();
                klog!(Info,
                    "   Round {}: Selected PID={} ({}), Priority={}",
                    round + 1,
                    pid,
                    proc.name,
                    proc.dynamic_priority
                );
            }

            // 模拟执行
            for _ in 0..5 {
                tick();
            }
        }
    }

    klog!(Info, "\n✓ Priority scheduling demo completed!\n");
}

/// 演示时间片轮转
pub fn demo_time_slice() {
    klog!(Info, "\n=== Time Slice Demo ===\n");

    klog!(Info, "1. Creating processes with same priority...");

    let proc1 = create_process("equal1".into(), 0, 50).expect("equal1");
    let proc2 = create_process("equal2".into(), 0, 50).expect("equal2");
    let proc3 = create_process("equal3".into(), 0, 50).expect("equal3");

    add_process(proc1);
    add_process(proc2);
    add_process(proc3);

    klog!(Info, "   ✓ Created 3 processes with equal priority (50)");

    klog!(Info, "\n2. Observing time slice rotation:");

    for round in 0..6 {
        if let Some(pid) = schedule() {
            if let Some(process) = get_process(pid) {
                let mut proc = process.lock();
                let initial_slice = proc.time_slice;
                klog!(Info,
                    "   Round {}: PID={} ({}), Initial TimeSlice={}ms",
                    round + 1,
                    pid,
                    proc.name,
                    initial_slice
                );

                // 模拟时间片耗尽
                proc.time_slice = 0;
            }
        }
    }

    klog!(Info, "\n✓ Time slice demo completed!\n");
}

/// 运行所有进程管理演示
pub fn run_all_demos() {
    demo_process_management();
    demo_priority_scheduling();
    demo_time_slice();
}
