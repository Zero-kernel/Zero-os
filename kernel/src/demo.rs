//! 内存管理演示

use alloc::boxed::Box;
use alloc::vec::Vec;

/// 演示内存分配功能
pub fn memory_demo() {
    kprintln!("  Testing heap allocation...");

    // 测试Vec分配
    let mut vec = Vec::new();
    for i in 0..10 {
        vec.push(i);
    }
    kprintln!("    ✓ Vec allocation successful: {:?}", vec);

    // 测试Box分配
    let boxed = Box::new(42);
    kprintln!("    ✓ Box allocation successful: {}", *boxed);

    // 测试大块内存分配
    let large_vec: Vec<u64> = (0..1000).collect();
    kprintln!(
        "    ✓ Large allocation successful: {} elements",
        large_vec.len()
    );

    kprintln!("  Memory allocation tests passed!");
}
