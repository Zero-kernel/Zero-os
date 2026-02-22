//! User Mode (Ring 3) Test Module
//!
//! Tests the Ring 3 execution path by loading and running a simple user-space program.
//!
//! The test program:
//! 1. Writes "Hello from Ring 3!" to stdout
//! 2. Gets and prints its PID
//! 3. Exits with code 0
//!
//! ## Test Flow
//!
//! 1. Create a new process
//! 2. Create a fresh address space
//! 3. Load the embedded ELF binary
//! 4. Switch to user mode via IRETQ
//! 5. User program executes SYSCALL instructions
//! 6. Kernel handles syscalls and program exits

use alloc::string::ToString;
use kernel_core::elf_loader::load_elf;
use kernel_core::fork::create_fresh_address_space;
use kernel_core::process::{create_process, get_process, FxSaveArea, ProcessState};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};

/// Debug: Dump page table entries for a virtual address
fn dump_page_table_for_addr(addr: u64) {
    klog!(Info, "\n[DEBUG] Page table dump for 0x{:x}:", addr);

    // Calculate indices
    let pml4_idx = ((addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((addr >> 12) & 0x1FF) as usize;

    klog!(Info, 
        "  Indices: PML4[{}] PDPT[{}] PD[{}] PT[{}]",
        pml4_idx, pdpt_idx, pd_idx, pt_idx
    );

    // Get current CR3
    let (cr3_frame, _) = Cr3::read();
    let pml4_phys = cr3_frame.start_address().as_u64();
    klog!(Info, "  CR3: 0x{:x}", pml4_phys);

    // Access page tables via physical memory offset
    let phys_offset = mm::page_table::get_physical_memory_offset().as_u64();

    unsafe {
        // PML4
        let pml4_virt = (phys_offset + pml4_phys) as *const PageTable;
        let pml4 = &*pml4_virt;
        let pml4_entry = &pml4[pml4_idx];
        klog!(Info, 
            "  PML4[{}]: flags=0x{:x}, addr=0x{:x}, USER={}",
            pml4_idx,
            pml4_entry.flags().bits(),
            pml4_entry.addr().as_u64(),
            pml4_entry.flags().contains(PageTableFlags::USER_ACCESSIBLE)
        );

        if !pml4_entry.flags().contains(PageTableFlags::PRESENT) {
            klog!(Info, "  -> PML4 entry not present!");
            return;
        }

        // PDPT
        let pdpt_phys = pml4_entry.addr().as_u64();
        let pdpt_virt = (phys_offset + pdpt_phys) as *const PageTable;
        let pdpt = &*pdpt_virt;
        let pdpt_entry = &pdpt[pdpt_idx];
        klog!(Info, 
            "  PDPT[{}]: flags=0x{:x}, addr=0x{:x}, USER={}",
            pdpt_idx,
            pdpt_entry.flags().bits(),
            pdpt_entry.addr().as_u64(),
            pdpt_entry.flags().contains(PageTableFlags::USER_ACCESSIBLE)
        );

        if !pdpt_entry.flags().contains(PageTableFlags::PRESENT) {
            klog!(Info, "  -> PDPT entry not present!");
            return;
        }

        if pdpt_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            klog!(Info, "  -> PDPT entry is 1GB huge page");
            return;
        }

        // PD
        let pd_phys = pdpt_entry.addr().as_u64();
        let pd_virt = (phys_offset + pd_phys) as *const PageTable;
        let pd = &*pd_virt;
        let pd_entry = &pd[pd_idx];
        klog!(Info, 
            "  PD[{}]: flags=0x{:x}, addr=0x{:x}, USER={}, HUGE={}",
            pd_idx,
            pd_entry.flags().bits(),
            pd_entry.addr().as_u64(),
            pd_entry.flags().contains(PageTableFlags::USER_ACCESSIBLE),
            pd_entry.flags().contains(PageTableFlags::HUGE_PAGE)
        );

        if !pd_entry.flags().contains(PageTableFlags::PRESENT) {
            klog!(Info, "  -> PD entry not present!");
            return;
        }

        if pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            klog!(Info, "  -> PD entry is 2MB huge page");
            return;
        }

        // PT
        let pt_phys = pd_entry.addr().as_u64();
        let pt_virt = (phys_offset + pt_phys) as *const PageTable;
        let pt = &*pt_virt;
        let pt_entry = &pt[pt_idx];
        klog!(Info, 
            "  PT[{}]: flags=0x{:x}, addr=0x{:x}, USER={}, NX={}",
            pt_idx,
            pt_entry.flags().bits(),
            pt_entry.addr().as_u64(),
            pt_entry.flags().contains(PageTableFlags::USER_ACCESSIBLE),
            pt_entry.flags().contains(PageTableFlags::NO_EXECUTE)
        );

        if !pt_entry.flags().contains(PageTableFlags::PRESENT) {
            klog!(Info, "  -> PT entry not present!");
            return;
        }

        klog!(Info, "  -> Final physical page: 0x{:x}", pt_entry.addr().as_u64());
    }
    klog!(Info, "");
}

/// Wrapper to ensure ELF data is properly aligned for parsing
///
/// xmas_elf uses the `zero` crate which requires alignment for zero-copy parsing.
/// `include_bytes!` doesn't guarantee alignment, so we wrap the data in an
/// aligned struct.
#[repr(C, align(8))]
struct AlignedElfData<const N: usize>([u8; N]);

/// Embedded Ring 3 test program (shell.elf) with proper alignment
///
/// This is a minimal interactive shell that demonstrates:
/// - Keyboard input via sys_read
/// - SYSCALL instruction from Ring 3
/// - sys_write (fd 1, stdout)
/// - sys_getpid, sys_getppid
/// - sys_exit
///
/// Built-in commands: help, echo, pid, ppid, clear, exit
#[cfg(feature = "shell")]
static USER_ELF_ALIGNED: AlignedElfData<{ include_bytes!("shell.elf").len() }> =
    AlignedElfData(*include_bytes!("shell.elf"));

/// Embedded syscall test program with proper alignment
///
/// Tests new musl-required syscalls:
/// - gettid, set_tid_address, set_robust_list, getrandom
#[cfg(feature = "syscall_test")]
static USER_ELF_ALIGNED: AlignedElfData<{ include_bytes!("syscall_test.elf").len() }> =
    AlignedElfData(*include_bytes!("syscall_test.elf"));

/// Embedded musl libc test program with proper alignment
///
/// Tests musl libc initialization and basic I/O:
/// - Full musl libc startup sequence
/// - stdio (printf, puts)
/// - syscalls (write, getpid, exit)
#[cfg(feature = "musl_test")]
static USER_ELF_ALIGNED: AlignedElfData<{ include_bytes!("musl_test.elf").len() }> =
    AlignedElfData(*include_bytes!("musl_test.elf"));

/// Embedded clone syscall test program with proper alignment
///
/// Tests thread creation via clone syscall:
/// - CLONE_VM | CLONE_THREAD flags
/// - Shared address space between parent and child
/// - Thread-like execution
#[cfg(feature = "clone_test")]
static USER_ELF_ALIGNED: AlignedElfData<{ include_bytes!("clone_test.elf").len() }> =
    AlignedElfData(*include_bytes!("clone_test.elf"));

/// Embedded Ring 3 test program (hello.elf) with proper alignment
///
/// This is a minimal user-space program that tests:
/// - SYSCALL instruction from Ring 3
/// - sys_write (fd 1, stdout)
/// - sys_getpid
/// - sys_exit
#[cfg(not(any(
    feature = "shell",
    feature = "syscall_test",
    feature = "musl_test",
    feature = "clone_test"
)))]
static USER_ELF_ALIGNED: AlignedElfData<{ include_bytes!("hello.elf").len() }> =
    AlignedElfData(*include_bytes!("hello.elf"));

/// Get aligned reference to the ELF data
fn user_elf() -> &'static [u8] {
    &USER_ELF_ALIGNED.0
}

#[cfg(feature = "shell")]
const PROCESS_NAME: &str = "shell";
#[cfg(feature = "syscall_test")]
const PROCESS_NAME: &str = "syscall_test";
#[cfg(feature = "musl_test")]
const PROCESS_NAME: &str = "musl_test";
#[cfg(feature = "clone_test")]
const PROCESS_NAME: &str = "clone_test";
#[cfg(not(any(
    feature = "shell",
    feature = "syscall_test",
    feature = "musl_test",
    feature = "clone_test"
)))]
const PROCESS_NAME: &str = "hello";

/// Run the Ring 3 test
///
/// Creates a user-space process and executes the embedded hello program.
/// This test verifies:
/// - SYSCALL/SYSRET mechanism works
/// - User-space programs can make system calls
/// - Privilege level transitions (Ring 0 <-> Ring 3)
///
/// Returns true if the test setup succeeded (actual execution is asynchronous).
pub fn run_usermode_test() -> bool {
    klog!(Info, "\n=== Ring 3 Execution Test ===\n");
    klog!(Info, "Embedded ELF size: {} bytes", user_elf().len());

    // Save current CR3 so we can restore it after loading the ELF
    let (saved_cr3_frame, _) = Cr3::read();
    let saved_cr3 = saved_cr3_frame.start_address().as_u64() as usize;

    // Step 1: Create a new process
    klog!(Info, "[1/4] Creating user process...");
    // create_process(name: String, ppid: ProcessId, priority: Priority) -> Result<ProcessId, ProcessCreateError>
    // ppid = 0 means init process is parent, priority = 50 (default)
    let pid = match create_process(PROCESS_NAME.to_string(), 0, 50) {
        Ok(pid) => pid,
        Err(e) => {
            klog!(Error, "      ✗ Failed to create process: {:?}", e);
            return false;
        }
    };
    klog!(Info, "      ✓ Process created with PID {}", pid);

    // Step 2: Create fresh address space
    klog!(Info, "[2/4] Creating address space...");
    let (_pml4_frame, memory_space) = match create_fresh_address_space() {
        Ok(result) => {
            klog!(Info, "      ✓ Address space created");
            result
        }
        Err(e) => {
            klog!(Error, "      ✗ Failed to create address space: {:?}", e);
            return false;
        }
    };

    // Step 3: Switch to new address space and load ELF
    klog!(Info, "[3/4] Loading ELF binary...");

    // Get reference to aligned ELF data
    let elf_data = user_elf();

    // Switch to user address space for ELF loading
    kernel_core::process::activate_memory_space(memory_space);

    let load_result = match load_elf(elf_data) {
        Ok(result) => {
            klog!(Info, "      ✓ ELF loaded at entry 0x{:x}", result.entry);
            klog!(Info, "      ✓ User stack top at 0x{:x}", result.user_stack_top);

            // Debug: Dump page table entries for the entry point and stack
            dump_page_table_for_addr(result.entry);
            // Dump stack page (one page below stack top)
            dump_page_table_for_addr(result.user_stack_top - 0x1000);

            result
        }
        Err(e) => {
            klog!(Error, "      ✗ Failed to load ELF: {:?}", e);
            // Restore original CR3
            kernel_core::process::activate_memory_space(saved_cr3);
            return false;
        }
    };

    // Step 4: Update process PCB with loaded state
    klog!(Info, "[4/4] Configuring process context...");
    if let Some(process) = get_process(pid) {
        let mut proc = process.lock();

        // Set memory space
        proc.memory_space = memory_space;
        proc.user_stack = Some(x86_64::VirtAddr::new(load_result.user_stack_top));

        // Set up context for Ring 3 execution
        proc.context.rip = load_result.entry;
        proc.context.rsp = load_result.user_stack_top;
        proc.context.rbp = load_result.user_stack_top;

        // User-mode segment selectors (Ring 3)
        // CS: 0x23 (user code selector with RPL=3)
        // SS: 0x1B (user data selector with RPL=3)
        proc.context.cs = arch::USER_CODE_SELECTOR as u64;
        proc.context.ss = arch::USER_DATA_SELECTOR as u64;

        // RFLAGS: Enable interrupts
        proc.context.rflags = 0x202;

        // Clear other registers
        proc.context.rax = 0;
        proc.context.rbx = 0;
        proc.context.rcx = 0;
        proc.context.rdx = 0;
        proc.context.rdi = 0;
        proc.context.rsi = 0;
        proc.context.r8 = 0;
        proc.context.r9 = 0;
        proc.context.r10 = 0;
        proc.context.r11 = 0;
        proc.context.r12 = 0;
        proc.context.r13 = 0;
        proc.context.r14 = 0;
        proc.context.r15 = 0;

        // Initialize FPU state with valid FCW/MXCSR values
        // This is critical - FXRSTOR with FCW=0 causes #UD
        proc.context.fx = FxSaveArea::default();

        // Mark as ready to run
        proc.state = ProcessState::Ready;

        klog!(Info, "      ✓ Process context configured");
        klog!(Info, "        Entry: 0x{:x}", load_result.entry);
        klog!(Info, "        RSP:   0x{:x}", load_result.user_stack_top);
        klog!(Info, "        CS:    0x{:x} (Ring 3)", proc.context.cs);
        klog!(Info, "        SS:    0x{:x} (Ring 3)", proc.context.ss);
    } else {
        klog!(Error, "      ✗ Failed to get process");
        kernel_core::process::activate_memory_space(saved_cr3);
        return false;
    }

    // Add process to scheduler's ready queue
    if let Some(process) = get_process(pid) {
        sched::enhanced_scheduler::Scheduler::add_process(process);
        klog!(Info, "      ✓ Process added to scheduler ready queue");
    }

    // Restore kernel address space (scheduler will switch when running the process)
    kernel_core::process::activate_memory_space(saved_cr3);

    klog!(Info, "\n✓ Ring 3 test process ready!");
    klog!(Info, "  The process will execute when scheduled.");
    klog!(Info, "  Expected output: \"Hello from Ring 3!\" followed by PID\n");

    true
}

/// Quick Ring 3 transition test (direct jump, blocking)
///
/// This is a more direct test that immediately jumps to user mode.
/// WARNING: This will not return if successful - the process exits via sys_exit.
///
/// Use this only for debugging the Ring 3 transition itself.
#[allow(dead_code)]
pub unsafe fn test_direct_ring3_jump() -> ! {
    klog!(Info, "\n=== Direct Ring 3 Jump Test ===\n");
    klog!(Warn, "WARNING: This test will not return!\n");

    // Create address space
    let (_pml4_frame, memory_space) =
        create_fresh_address_space().expect("Failed to create address space");

    // Switch to new address space
    kernel_core::process::activate_memory_space(memory_space);

    // Load ELF
    let load_result = load_elf(user_elf()).expect("Failed to load ELF");

    klog!(Info, "Jumping to Ring 3...");
    klog!(Info, "  Entry: 0x{:x}", load_result.entry);
    klog!(Info, "  Stack: 0x{:x}", load_result.user_stack_top);

    // Set TSS RSP0 for syscall return
    arch::set_kernel_stack(arch::default_kernel_stack_top());

    // Jump to user mode - this will not return
    arch::jump_to_usermode(load_result.entry, load_result.user_stack_top);
}
