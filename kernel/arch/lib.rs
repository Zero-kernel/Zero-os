#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

pub mod apic;
pub mod context_switch;
pub mod cpu_protection;
pub mod gdt;
pub mod hpet;
pub mod interrupts;
pub mod invpcid;
pub mod ipi;
pub mod smp;
pub mod syscall;

pub use context_switch::{
    assert_kernel_context, enter_usermode, init_fpu, jump_to_usermode, restore_context,
    save_context, switch_context, validate_kernel_context, Context, FxSaveArea, USER_CODE_SELECTOR,
    USER_DATA_SELECTOR,
};
pub use cpu_protection::{check_cpu_features, enable_protections, require_smap_support, CpuProtectionStatus};
pub use cpu_protection::{
    detect_hypervisor, hypervisor_present, is_software_emulated, is_virtualized, HypervisorType,
};
pub use gdt::{
    default_kernel_stack_top, get_kernel_stack, init as init_gdt, init_for_ap as init_gdt_for_ap,
    selectors, set_ist_stack, set_kernel_stack, Selectors, DOUBLE_FAULT_IST_INDEX,
    DOUBLE_FAULT_STACK_SIZE, KERNEL_STACK_SIZE,
};
pub use syscall::{
    init_syscall_msr, is_initialized as syscall_initialized,
    register_frame_callback, with_current_syscall_frame, SyscallFrame,
};

// Re-export cpu_local from the cpu_local crate for backwards compatibility
pub use cpu_local::{current_cpu_id, max_cpus, CpuLocal};

// Re-export PerCpuData and related functions for SMP support
pub use cpu_local::{
    current_cpu, init_bsp, num_online_cpus, register_cpu_id, PerCpuData, RawTaskPtr, PER_CPU_DATA,
};

// Re-export SMP bring-up functions
pub use smp::{ap_rust_entry, online_cpus, set_rsdp_address, smp_initialized, start_aps};

// Re-export INVPCID instruction wrappers
pub use invpcid::{
    flush_address, flush_all_nonglobal, flush_pcid, invpcid_address, invpcid_all_global,
    invpcid_all_nonglobal, invpcid_single_context, invpcid_supported,
};

pub fn init() {
    gdt::init();
    context_switch::init_fpu();
    syscall::register_frame_callback(); // 注册 syscall 帧回调
    klog_always!("Arch module initialized (FPU/SIMD enabled)");
}
