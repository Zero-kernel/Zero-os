//! KASLR/KPTI Infrastructure for Zero-OS
//!
//! This module provides the infrastructure for Kernel Address Space Layout
//! Randomization (KASLR), Kernel Page Table Isolation (KPTI), and PCID support.
//!
//! # Current Implementation (Phase A.4)
//!
//! - PCID detection and CR4.PCIDE enablement
//! - PCID allocation/free for process-level TLB tagging
//! - KASLR slide generation (2 MiB aligned, 0-512 MiB range)
//! - KernelLayout: Provides runtime kernel location info
//! - KPTI stubs: No-op hooks for future CR3 switching
//!
//! # Implementation Status
//!
//! | Feature | Status | Notes |
//! |---------|--------|-------|
//! | PCID detection | ✅ Complete | CR4.PCIDE enabled if CPU supports |
//! | PCID allocation | ✅ Complete | Bitmap-based allocator (1-4095) |
//! | KASLR slide gen | ✅ Complete | Uses CSPRNG, 2 MiB aligned |
//! | KASLR actual | ❌ Requires bootloader | Kernel load at fixed address |
//! | KPTI framework | 🚧 Stubs only | Needs dual page tables from MM |
//! | KPTI CR3 switch | ❌ Blocked | Requires MM dual-root support |
//!
//! # Blocking Dependencies
//!
//! ## KASLR (Actual Kernel Relocation)
//!
//! The kernel is currently loaded at a fixed physical address (0x100000) by
//! the UEFI bootloader. True KASLR requires:
//!
//! 1. Bootloader generates random slide value
//! 2. Bootloader loads kernel at (base + slide)
//! 3. Bootloader passes slide to kernel via boot info
//! 4. Kernel adjusts all absolute addresses
//!
//! This requires bootloader cooperation - see bootloader/src/main.rs.
//!
//! ## KPTI (Dual Page Tables)
//!
//! Full KPTI requires separate page table hierarchies:
//!
//! - **User CR3**: User mappings + minimal trampoline (syscall entry/exit code)
//! - **Kernel CR3**: User mappings + full kernel
//!
//! The memory manager (kernel/mm/) would need to:
//!
//! 1. Allocate two PML4 roots per process
//! 2. Clone user mappings to both roots
//! 3. Map full kernel only in kernel CR3
//! 4. Map trampoline in both (USER | PRESENT | not-WRITABLE)
//!
//! Until MM provides dual-root support, KPTI hooks remain inert.
//!
//! # Design
//!
//! ```text
//! KASLR:
//! +------------------+
//! | Randomized Slide | (boot-time, from RDRAND via CSPRNG)
//! +------------------+
//! | Kernel Text      | 0xffffffff80000000 + slide
//! +------------------+
//! | Kernel Data      | Text + text_size + slide
//! +------------------+
//!
//! KPTI (future):
//! User CR3:             Kernel CR3:
//! +------------------+  +------------------+
//! | User mappings    |  | User mappings    |
//! +------------------+  +------------------+
//! | Trampoline only  |  | Full kernel      |
//! +------------------+  +------------------+
//! ```
//!
//! # Note on Runtime KASLR
//!
//! The kernel is loaded at a fixed physical address by the bootloader.
//! Full KASLR would require bootloader cooperation to randomize the load
//! address. The current implementation generates and stores a slide value
//! that can be used for:
//! - Future bootloader integration
//! - Runtime address randomization experiments
//! - ASLR for dynamically loaded kernel modules

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::registers::control::{Cr4, Cr4Flags};

use crate::rng;

/// Whether KASLR is enabled (future: set by bootloader)
static KASLR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether KPTI is enabled (future: set during init)
static KPTI_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether PCID is enabled (set during init if CPU supports it)
static PCID_ENABLED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// PCID Allocation Constants
// ============================================================================

/// Minimum valid PCID (0 is reserved for non-PCID CR3 loads)
const MIN_PCID: u16 = 1;

/// Maximum valid PCID (12-bit field, 0-4095, but 0 is reserved)
const MAX_PCID: u16 = 4095;

/// Number of u64 words needed to track all PCIDs as a bitmap
/// (4096 bits / 64 bits per word) = 64 words
const PCID_BITMAP_WORDS: usize = 64;

/// Bitmap tracking allocated PCIDs to avoid reuse collisions.
///
/// Each bit represents a PCID (0-4095). Bit set = allocated, clear = free.
/// Protected by Mutex for concurrent access from process creation/destruction.
static PCID_BITMAP: Mutex<[u64; PCID_BITMAP_WORDS]> = Mutex::new([0; PCID_BITMAP_WORDS]);

// ============================================================================
// KASLR Configuration Constants
// ============================================================================

/// Maximum randomized slide: 512 MiB
///
/// This must fit within the high-half kernel address space and leave
/// room for the kernel image, heap, and stack areas.
const KASLR_MAX_SLIDE: u64 = 512 * 1024 * 1024;

/// Slide granularity: 2 MiB (huge page alignment)
///
/// Using 2 MiB alignment allows the kernel to use huge pages for
/// better TLB efficiency and simplifies page table management.
const KASLR_SLIDE_GRANULARITY: u64 = 2 * 1024 * 1024;

/// Global kernel layout (updated during init)
static KERNEL_LAYOUT: Mutex<KernelLayout> = Mutex::new(KernelLayout::fixed());

// ============================================================================
// Kernel Layout
// ============================================================================

/// Current (fixed) kernel virtual base address
pub const KERNEL_VIRT_BASE: u64 = 0xffffffff80000000;

/// Current (fixed) kernel physical base address
pub const KERNEL_PHYS_BASE: u64 = 0x100000;

/// Current (fixed) kernel entry point offset from base
pub const KERNEL_ENTRY_OFFSET: u64 = 0x100000;

/// Current (fixed) physical memory offset for high-half direct mapping
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xffffffff80000000;

/// Kernel layout information
///
/// This struct provides runtime information about the kernel's location
/// in memory. Currently uses fixed values; will support randomized layout
/// when KASLR is implemented.
///
/// # Section Fields
///
/// The section fields (text_start, rodata_start, etc.) are currently set to
/// placeholder values. They will be populated from linker symbols when
/// KASLR is implemented. Do not rely on these for bounds checking until
/// they are properly initialized.
#[derive(Debug, Clone, Copy)]
pub struct KernelLayout {
    /// Virtual base address of the kernel (high-half mapping)
    pub virt_base: u64,

    /// Physical base address where kernel is loaded
    pub phys_base: u64,

    /// KASLR slide value (0 = no randomization)
    pub kaslr_slide: u64,

    /// Virtual address of kernel text section start
    pub text_start: u64,

    /// Size of kernel text section in bytes
    pub text_size: u64,

    /// Virtual address of kernel rodata section start
    pub rodata_start: u64,

    /// Size of kernel rodata section in bytes
    pub rodata_size: u64,

    /// Virtual address of kernel data section start
    pub data_start: u64,

    /// Size of kernel data section in bytes
    pub data_size: u64,

    /// Virtual address of kernel BSS section start
    pub bss_start: u64,

    /// Size of kernel BSS section in bytes
    pub bss_size: u64,

    /// Virtual address of kernel heap start
    pub heap_start: u64,

    /// Size of kernel heap in bytes
    pub heap_size: u64,

    /// Physical memory offset (for phys-to-virt translation)
    pub phys_offset: u64,
}

impl Default for KernelLayout {
    fn default() -> Self {
        Self::fixed()
    }
}

impl KernelLayout {
    /// Create a kernel layout with fixed (non-randomized) addresses
    ///
    /// This is the current configuration. KASLR support will add
    /// a constructor that accepts a slide value.
    pub const fn fixed() -> Self {
        Self {
            virt_base: KERNEL_VIRT_BASE,
            phys_base: KERNEL_PHYS_BASE,
            kaslr_slide: 0,
            // Section bounds - placeholders until linker symbol integration
            // TODO: Populate from linker symbols (__text_start, __text_end, etc.)
            text_start: KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET,
            text_size: 0, // Unknown until linker symbols integrated
            rodata_start: 0,
            rodata_size: 0,
            data_start: 0,
            data_size: 0,
            bss_start: 0,
            bss_size: 0,
            // Fixed heap address (matches mm::memory.rs)
            heap_start: 0xffffffff80200000,
            heap_size: 1 * 1024 * 1024, // 1 MiB
            phys_offset: PHYSICAL_MEMORY_OFFSET,
        }
    }

    /// Create a kernel layout with KASLR slide (future)
    ///
    /// # Safety
    ///
    /// The slide value must be page-aligned and must not cause the kernel
    /// to overlap with other memory regions.
    ///
    /// # R39-7 FIX
    ///
    /// phys_base is now also adjusted by the slide value to match
    /// the actual kernel load address.
    #[allow(dead_code)]
    pub const fn with_slide(slide: u64) -> Self {
        Self {
            virt_base: KERNEL_VIRT_BASE + slide,
            phys_base: KERNEL_PHYS_BASE + slide, // R39-7 FIX: Include slide in physical base
            kaslr_slide: slide,
            text_start: KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET + slide,
            text_size: 0,
            rodata_start: 0,
            rodata_size: 0,
            data_start: 0,
            data_size: 0,
            bss_start: 0,
            bss_size: 0,
            heap_start: 0xffffffff80200000 + slide,
            heap_size: 1 * 1024 * 1024,
            phys_offset: PHYSICAL_MEMORY_OFFSET,
        }
    }

    /// Check if this layout has KASLR enabled
    #[inline]
    pub fn has_kaslr(&self) -> bool {
        self.kaslr_slide != 0
    }

    /// Convert a physical address to virtual using this layout's offset
    #[inline]
    pub fn phys_to_virt(&self, phys: u64) -> u64 {
        phys + self.phys_offset
    }

    /// Convert a virtual address to physical (for high-half kernel addresses)
    #[inline]
    pub fn virt_to_phys(&self, virt: u64) -> Option<u64> {
        if virt >= self.virt_base {
            Some(virt - self.virt_base + self.phys_base)
        } else {
            None
        }
    }

    /// Get the kernel's entry point virtual address
    #[inline]
    pub fn entry_point(&self) -> u64 {
        self.text_start
    }
}

// ============================================================================
// Linker Symbols
// ============================================================================

// Linker-provided section boundaries (defined in kernel.ld)
extern "C" {
    static kernel_start: u8;
    static text_start: u8;
    static text_end: u8;
    static rodata_start: u8;
    static rodata_end: u8;
    static data_start: u8;
    static data_end: u8;
    static bss_start: u8;
    static bss_end: u8;
    static kernel_end: u8;
}

/// Convert a linker symbol reference to its virtual address
#[inline]
unsafe fn sym_addr(sym: &u8) -> u64 {
    sym as *const u8 as u64
}

/// Build kernel layout from linker symbols at runtime
///
/// This function reads the actual section boundaries from linker symbols
/// and populates the KernelLayout structure. This allows accurate bounds
/// checking even without bootloader-assisted KASLR.
///
/// # R39-7 FIX
///
/// phys_base is now calculated as KERNEL_PHYS_BASE + runtime_slide to match
/// the actual physical load address when KASLR is enabled.
fn build_kernel_layout_from_linker() -> KernelLayout {
    // Safety: symbols are provided by kernel.ld and valid after kernel load
    let kernel_start_addr = unsafe { sym_addr(&kernel_start) };
    let text_start_addr = unsafe { sym_addr(&text_start) };
    let text_end_addr = unsafe { sym_addr(&text_end) };
    let rodata_start_addr = unsafe { sym_addr(&rodata_start) };
    let rodata_end_addr = unsafe { sym_addr(&rodata_end) };
    let data_start_addr = unsafe { sym_addr(&data_start) };
    let data_end_addr = unsafe { sym_addr(&data_end) };
    let bss_start_addr = unsafe { sym_addr(&bss_start) };
    let bss_end_addr = unsafe { sym_addr(&bss_end) };

    // Calculate runtime slide by comparing actual vs expected addresses
    // If bootloader relocates kernel, this will show the offset
    let runtime_slide = kernel_start_addr.saturating_sub(KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET);

    KernelLayout {
        virt_base: KERNEL_VIRT_BASE + runtime_slide,
        phys_base: KERNEL_PHYS_BASE + runtime_slide, // R39-7 FIX: Include slide in physical base
        kaslr_slide: runtime_slide,
        text_start: text_start_addr,
        text_size: text_end_addr.saturating_sub(text_start_addr),
        rodata_start: rodata_start_addr,
        rodata_size: rodata_end_addr.saturating_sub(rodata_start_addr),
        data_start: data_start_addr,
        data_size: data_end_addr.saturating_sub(data_start_addr),
        bss_start: bss_start_addr,
        bss_size: bss_end_addr.saturating_sub(bss_start_addr),
        heap_start: KERNEL_VIRT_BASE + 0x200000 + runtime_slide,
        heap_size: 1 * 1024 * 1024, // 1 MiB
        phys_offset: PHYSICAL_MEMORY_OFFSET,
    }
}

/// Update the global kernel layout from linker symbols
fn set_kernel_layout(layout: KernelLayout) {
    KASLR_ENABLED.store(layout.kaslr_slide != 0, Ordering::SeqCst);
    let mut guard = KERNEL_LAYOUT.lock();
    *guard = layout;
}

// ============================================================================
// KPTI Infrastructure
// ============================================================================

/// Page table context for KPTI
///
/// When KPTI is enabled, each process has two page table roots:
/// - `user_cr3`: Contains user mappings + minimal trampoline
/// - `kernel_cr3`: Contains user mappings + full kernel
///
/// # CR3 Format
///
/// The `user_cr3` and `kernel_cr3` fields contain the physical address of
/// the PML4 page table root. They do NOT include PCID bits - the PCID is
/// stored separately in the `pcid` field. When loading CR3, the caller
/// must combine them appropriately:
///
/// - Without PCID: `mov cr3, [user_cr3 or kernel_cr3]`
/// - With PCID: `mov cr3, [cr3_value | (pcid as u64) | (no_flush_bit)]`
///
/// The `cr3_with_pcid()` method handles this combination.
#[derive(Debug, Clone, Copy)]
pub struct KptiContext {
    /// User-mode page table root (physical address of PML4)
    /// Contains user mappings and trampoline only
    /// Does NOT include PCID bits
    pub user_cr3: u64,

    /// Kernel-mode page table root (physical address of PML4)
    /// Contains user mappings and full kernel
    /// Does NOT include PCID bits
    pub kernel_cr3: u64,

    /// PCID (Process Context ID) for TLB optimization
    /// 0 = PCID not used, 1-4095 = valid PCID
    pub pcid: u16,
}

impl Default for KptiContext {
    fn default() -> Self {
        Self {
            user_cr3: 0,
            kernel_cr3: 0,
            pcid: 0,
        }
    }
}

impl KptiContext {
    /// Create a KPTI-disabled context (single CR3)
    ///
    /// When KPTI is not enabled, both CR3 values point to the same root.
    pub fn single(cr3: u64) -> Self {
        Self {
            user_cr3: cr3,
            kernel_cr3: cr3,
            pcid: 0,
        }
    }

    /// Create a KPTI-enabled context with separate roots
    #[allow(dead_code)]
    pub fn dual(user_cr3: u64, kernel_cr3: u64, pcid: u16) -> Self {
        Self {
            user_cr3,
            kernel_cr3,
            pcid,
        }
    }

    /// Check if this context has KPTI separation
    #[inline]
    pub fn has_kpti(&self) -> bool {
        self.user_cr3 != self.kernel_cr3
    }

    /// Get CR3 value with PCID bits for user mode
    ///
    /// Returns the user_cr3 combined with PCID if enabled.
    /// The NO_FLUSH bit (bit 63) is not set - caller should set if needed.
    #[inline]
    pub fn user_cr3_with_pcid(&self) -> u64 {
        if self.pcid != 0 {
            self.user_cr3 | (self.pcid as u64)
        } else {
            self.user_cr3
        }
    }

    /// Get CR3 value with PCID bits for kernel mode
    ///
    /// Returns the kernel_cr3 combined with PCID if enabled.
    /// The NO_FLUSH bit (bit 63) is not set - caller should set if needed.
    #[inline]
    pub fn kernel_cr3_with_pcid(&self) -> u64 {
        if self.pcid != 0 {
            self.kernel_cr3 | (self.pcid as u64)
        } else {
            self.kernel_cr3
        }
    }
}

/// Active KPTI context (shared for now, per-CPU in future SMP)
static KPTI_CONTEXT: Mutex<KptiContext> = Mutex::new(KptiContext {
    user_cr3: 0,
    kernel_cr3: 0,
    pcid: 0,
});

/// Install a new KPTI context (enables/disables KPTI based on separation)
///
/// # Arguments
///
/// * `ctx` - The KPTI context to install
///
/// # Note
///
/// This should only be called during process switch or KPTI setup.
/// Installing a context with different user/kernel CR3 enables KPTI.
pub fn install_kpti_context(ctx: KptiContext) {
    KPTI_ENABLED.store(ctx.has_kpti(), Ordering::SeqCst);
    let mut guard = KPTI_CONTEXT.lock();
    *guard = ctx;
}

/// Read the current KPTI context
#[inline]
pub fn current_kpti_context() -> KptiContext {
    *KPTI_CONTEXT.lock()
}

// ============================================================================
// KPTI CR3 Switching
// ============================================================================

/// Switch to kernel CR3 on syscall/interrupt entry
///
/// When KPTI is enabled, this switches from the user page table
/// (which has minimal kernel mappings) to the kernel page table
/// (which has full kernel access).
///
/// # Safety
///
/// This function modifies CR3 register. It should only be called
/// from syscall/interrupt entry paths before accessing kernel data.
#[inline]
pub fn enter_kernel_mode() {
    if !KPTI_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let ctx = current_kpti_context();
    if !ctx.has_kpti() {
        return;
    }

    // Switch to kernel CR3
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) ctx.kernel_cr3_with_pcid(),
            options(nostack, preserves_flags)
        );
    }
}

/// Switch to user CR3 before returning to userspace
///
/// When KPTI is enabled, this switches from the kernel page table
/// to the user page table (which has only trampoline + user mappings).
///
/// # Safety
///
/// This function modifies CR3 register. It should only be called
/// from syscall/interrupt exit paths just before returning to user mode.
#[inline]
pub fn return_to_user_mode() {
    if !KPTI_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let ctx = current_kpti_context();
    if !ctx.has_kpti() {
        return;
    }

    // Switch to user CR3
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) ctx.user_cr3_with_pcid(),
            options(nostack, preserves_flags)
        );
    }
}

/// Invalidate TLB entries for a specific address
///
/// When KPTI is enabled, this may need to invalidate entries in both
/// page table hierarchies.
#[inline]
pub fn invalidate_page(addr: u64) {
    // Use invlpg instruction
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// Perform a full TLB flush
///
/// When KPTI is enabled, this flushes all TLB entries.
/// May use PCID-aware flush if supported.
#[inline]
pub fn flush_tlb() {
    // Reload CR3 to flush TLB
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

// ============================================================================
// KASLR/KPTI State Queries
// ============================================================================

/// Check if KASLR is currently enabled
#[inline]
pub fn is_kaslr_enabled() -> bool {
    KASLR_ENABLED.load(Ordering::Relaxed)
}

/// Check if KPTI is currently enabled
#[inline]
pub fn is_kpti_enabled() -> bool {
    KPTI_ENABLED.load(Ordering::Relaxed)
}

/// Get the current kernel layout
///
/// Returns the global kernel layout, which may include a KASLR slide
/// if KASLR was enabled during initialization.
pub fn get_kernel_layout() -> KernelLayout {
    *KERNEL_LAYOUT.lock()
}

/// Enable KASLR (called by bootloader/early init)
///
/// # Safety
///
/// This should only be called once during boot, before any code
/// relies on the kernel layout. Once enabled, KASLR cannot be disabled.
#[allow(dead_code)]
pub fn enable_kaslr() {
    KASLR_ENABLED.store(true, Ordering::SeqCst);
}

/// Enable KPTI (called during security init)
///
/// # Safety
///
/// This should only be called after page tables are set up with
/// dual roots. Once enabled, all syscall/interrupt paths must
/// use the KPTI CR3 switching stubs.
#[allow(dead_code)]
pub fn enable_kpti() {
    KPTI_ENABLED.store(true, Ordering::SeqCst);
}

// ============================================================================
// PCID Detection and Enablement
// ============================================================================

/// Execute CPUID leaf 1 to get feature flags
///
/// Returns (eax, ebx, ecx, edx) where:
/// - ecx[17] = PCID support
/// - ecx[30] = RDRAND support
/// - edx[13] = PGE (Global Pages) support
fn cpuid_leaf1() -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            out("eax") eax,
            ebx_out = out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nomem, nostack)
        );
    }

    (eax, ebx, ecx, edx)
}

/// Check if PCID is supported (CPUID.01H:ECX[17])
///
/// PCID (Process Context Identifiers) allows the CPU to maintain TLB
/// entries tagged with a process ID, reducing TLB flushes on context switch.
fn pcid_supported() -> bool {
    let (_, _, ecx, _) = cpuid_leaf1();
    (ecx & (1 << 17)) != 0
}

/// Check if Global Pages are supported (CPUID.01H:EDX[13])
///
/// PGE is a prerequisite for PCID on some implementations.
fn pge_supported() -> bool {
    let (_, _, _, edx) = cpuid_leaf1();
    (edx & (1 << 13)) != 0
}

/// Enable PCID by setting CR4.PCIDE if CPU supports it
///
/// Returns true if PCID was successfully enabled.
///
/// # Prerequisites
///
/// - CPU must support PCID (CPUID.01H:ECX[17])
/// - CPU must support PGE (CPUID.01H:EDX[13])
fn enable_pcid_if_supported() -> bool {
    if !pcid_supported() {
        return false;
    }

    // Read current CR4
    let mut cr4 = Cr4::read();

    // Enable PGE (Global Pages) - often a prerequisite for PCID
    if pge_supported() && !cr4.contains(Cr4Flags::PAGE_GLOBAL) {
        cr4.insert(Cr4Flags::PAGE_GLOBAL);
    }

    // Enable PCID
    if !cr4.contains(Cr4Flags::PCID) {
        cr4.insert(Cr4Flags::PCID);
        unsafe { Cr4::write(cr4) };
    }

    // Verify PCID is now enabled
    let new_cr4 = Cr4::read();
    let enabled = new_cr4.contains(Cr4Flags::PCID);
    PCID_ENABLED.store(enabled, Ordering::SeqCst);
    enabled
}

/// Check if PCID is currently enabled
#[inline]
pub fn is_pcid_enabled() -> bool {
    PCID_ENABLED.load(Ordering::Relaxed)
}

// ============================================================================
// PCID Allocation
// ============================================================================

/// Convert a PCID to its bitmap index and bit mask.
///
/// # Arguments
///
/// * `pcid` - The PCID value (0-4095)
///
/// # Returns
///
/// Tuple of (word index, bit mask) for the bitmap
#[inline]
fn pcid_index_and_mask(pcid: u16) -> (usize, u64) {
    let idx = (pcid as usize) / 64;
    let bit = (pcid as usize) % 64;
    (idx, 1u64 << bit)
}

/// Allocate a new PCID for a process.
///
/// PCIDs (Process Context Identifiers) allow the CPU to tag TLB entries
/// with a process ID, reducing TLB flushes on context switch when KPTI
/// is enabled.
///
/// # Returns
///
/// * `Some(pcid)` - A valid PCID in the range 1-4095
/// * `None` - If PCID is not enabled or all PCIDs are exhausted
///
/// # Note
///
/// PCID 0 is reserved and never allocated. When PCID is disabled in CR4,
/// all CR3 loads implicitly use PCID 0.
///
/// # Example
///
/// ```rust,ignore
/// if let Some(pcid) = allocate_pcid() {
///     process.kpti_ctx.pcid = pcid;
/// }
/// ```
pub fn allocate_pcid() -> Option<u16> {
    if !is_pcid_enabled() {
        return None;
    }

    let mut bitmap = PCID_BITMAP.lock();

    // Search for first free PCID (bit not set)
    // Start from MIN_PCID to skip reserved PCID 0
    for pcid in MIN_PCID..=MAX_PCID {
        let (idx, mask) = pcid_index_and_mask(pcid);
        if bitmap[idx] & mask == 0 {
            // Mark as allocated
            bitmap[idx] |= mask;
            return Some(pcid);
        }
    }

    // All PCIDs exhausted
    None
}

/// Free a previously allocated PCID.
///
/// Returns the PCID to the pool for reuse by future processes.
/// Invalid PCIDs (0 or >4095) are silently ignored.
///
/// # Arguments
///
/// * `pcid` - The PCID to free (must be 1-4095)
///
/// # Safety
///
/// The caller must ensure the PCID is no longer in use by any CPU's CR3
/// and that all TLB entries for this PCID have been flushed.
///
/// # Example
///
/// ```rust,ignore
/// // During process cleanup
/// if process.kpti_ctx.pcid != 0 {
///     free_pcid(process.kpti_ctx.pcid);
/// }
/// ```
pub fn free_pcid(pcid: u16) {
    // Validate PCID range (0 is reserved, >4095 is invalid)
    if pcid < MIN_PCID || pcid > MAX_PCID {
        return;
    }

    let (idx, mask) = pcid_index_and_mask(pcid);
    let mut bitmap = PCID_BITMAP.lock();
    bitmap[idx] &= !mask;
}

/// Get the number of currently allocated PCIDs.
///
/// Useful for debugging and monitoring PCID usage.
///
/// # Returns
///
/// Count of allocated PCIDs (0 if PCID is disabled)
pub fn allocated_pcid_count() -> usize {
    if !is_pcid_enabled() {
        return 0;
    }

    let bitmap = PCID_BITMAP.lock();
    bitmap.iter().map(|w| w.count_ones() as usize).sum()
}

// ============================================================================
// KASLR Slide Generation
// ============================================================================

/// Convert a slot number to a KASLR slide value
///
/// Ensures the slide is 2 MiB aligned and within the maximum range.
fn slide_from_slot(slot: u64) -> u64 {
    let max_slots = KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY;
    let bounded_slot = slot % (max_slots + 1);
    bounded_slot * KASLR_SLIDE_GRANULARITY
}

/// Generate a random KASLR slide using the CSPRNG
///
/// Returns 0 on failure (KASLR will be disabled).
fn generate_kaslr_slide() -> u64 {
    let max_slots = KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY;

    match rng::random_range(max_slots + 1) {
        Ok(slot) => slide_from_slot(slot),
        Err(_) => {
            // RNG failure - fall back to no KASLR
            0
        }
    }
}

/// Apply a KASLR slide to the global kernel layout
///
/// If slide is 0, KASLR is disabled and the fixed layout is used.
fn apply_kaslr_slide(slide: u64) {
    let mut layout = KERNEL_LAYOUT.lock();

    if slide != 0 {
        *layout = KernelLayout::with_slide(slide);
        KASLR_ENABLED.store(true, Ordering::SeqCst);
    } else {
        *layout = KernelLayout::fixed();
        KASLR_ENABLED.store(false, Ordering::SeqCst);
    }
}

// ============================================================================
// Trampoline Support (Preparation for KPTI)
// ============================================================================

/// Trampoline mapping descriptor
///
/// The trampoline is a small code region that must be mapped in both
/// user and kernel page tables for KPTI to work. It contains the
/// syscall entry/exit code that switches CR3.
#[derive(Debug, Clone, Copy)]
pub struct TrampolineDesc {
    /// Virtual address of the trampoline
    pub virt_addr: u64,

    /// Physical address of the trampoline
    pub phys_addr: u64,

    /// Size of the trampoline in bytes (must be page-aligned)
    pub size: u64,

    /// Page table flags for the trampoline mapping
    /// Must be: PRESENT | USER | not-WRITABLE (code only)
    pub flags: u64,
}

impl Default for TrampolineDesc {
    fn default() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            size: 0,
            flags: 0,
        }
    }
}

impl TrampolineDesc {
    /// Check if this is a valid trampoline descriptor
    pub fn is_valid(&self) -> bool {
        self.virt_addr != 0 && self.phys_addr != 0 && self.size > 0
    }

    /// Get the number of pages required for this trampoline
    pub fn page_count(&self) -> u64 {
        (self.size + 4095) / 4096
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize KASLR/KPTI subsystem
///
/// # Arguments
///
/// * `boot_slide` - Optional KASLR slide value from bootloader (R39-7 FIX)
///
/// # R25-11 Fix
///
/// Until bootloader cooperation enables actual kernel relocation,
/// KASLR is always disabled and reported as such. The slide value
/// is set to 0 to prevent KernelLayout from containing incorrect addresses.
///
/// # R39-7 FIX
///
/// Now accepts the KASLR slide from the bootloader's BootInfo structure
/// and verifies it matches the runtime-detected slide from linker symbols.
pub fn init(boot_slide: Option<u64>) {
    // Step 1: Enable PCID if CPU supports it
    let pcid_enabled = enable_pcid_if_supported();

    // Step 2: Build kernel layout from linker symbols
    // This populates section bounds accurately even without bootloader-assisted KASLR
    let layout = build_kernel_layout_from_linker();

    // R39-7 FIX: Verify bootloader slide matches runtime-detected slide
    if let Some(expected) = boot_slide {
        if expected != 0 && expected != layout.kaslr_slide {
            println!(
                "  ! KASLR slide mismatch: bootloader=0x{:x}, runtime=0x{:x}",
                expected, layout.kaslr_slide
            );
        }
    }

    set_kernel_layout(layout);

    // Report status
    println!(
        "  PCID: {}",
        if pcid_enabled {
            "enabled"
        } else {
            "unsupported/disabled"
        }
    );
    println!(
        "  KASLR: {} (slide: 0x{:x})",
        if layout.kaslr_slide != 0 {
            "enabled"
        } else {
            "disabled"
        },
        layout.kaslr_slide
    );
    println!(
        "  Kernel sections: text={:#x}..{:#x} ({} bytes)",
        layout.text_start,
        layout.text_start + layout.text_size,
        layout.text_size
    );
    println!(
        "  KPTI: {} (stubs installed)",
        if is_kpti_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_layout_fixed() {
        let layout = KernelLayout::fixed();
        assert_eq!(layout.virt_base, KERNEL_VIRT_BASE);
        assert_eq!(layout.phys_base, KERNEL_PHYS_BASE);
        assert_eq!(layout.kaslr_slide, 0);
        assert!(!layout.has_kaslr());
    }

    #[test]
    fn test_kernel_layout_with_slide() {
        let slide = 0x200000; // 2 MiB slide
        let layout = KernelLayout::with_slide(slide);
        assert_eq!(layout.virt_base, KERNEL_VIRT_BASE + slide);
        assert_eq!(layout.kaslr_slide, slide);
        assert!(layout.has_kaslr());
    }

    #[test]
    fn test_virt_to_phys() {
        let layout = KernelLayout::fixed();
        let virt = KERNEL_VIRT_BASE + 0x1000;
        let phys = layout.virt_to_phys(virt);
        assert_eq!(phys, Some(KERNEL_PHYS_BASE + 0x1000));
    }

    #[test]
    fn test_kpti_context_single() {
        let ctx = KptiContext::single(0x12345000);
        assert_eq!(ctx.user_cr3, ctx.kernel_cr3);
        assert!(!ctx.has_kpti());
    }

    #[test]
    fn test_kpti_context_dual() {
        let ctx = KptiContext::dual(0x12345000, 0x67890000, 1);
        assert_ne!(ctx.user_cr3, ctx.kernel_cr3);
        assert!(ctx.has_kpti());
    }

    #[test]
    fn test_slide_from_slot_alignment() {
        // Test that slides are properly aligned to 2 MiB
        for slot in 0..10 {
            let slide = slide_from_slot(slot);
            assert_eq!(
                slide % KASLR_SLIDE_GRANULARITY,
                0,
                "Slide 0x{:x} should be 2 MiB aligned",
                slide
            );
            assert!(
                slide <= KASLR_MAX_SLIDE,
                "Slide 0x{:x} should be <= max 0x{:x}",
                slide,
                KASLR_MAX_SLIDE
            );
        }
    }

    #[test]
    fn test_slide_from_slot_wraps() {
        // Test that slot values beyond max wrap correctly
        let max_slots = KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY;
        let slide = slide_from_slot(max_slots + 10);
        assert!(
            slide <= KASLR_MAX_SLIDE,
            "Wrapped slide 0x{:x} should be <= max 0x{:x}",
            slide,
            KASLR_MAX_SLIDE
        );
        assert_eq!(
            slide % KASLR_SLIDE_GRANULARITY,
            0,
            "Wrapped slide should still be aligned"
        );
    }

    #[test]
    fn test_slide_zero_is_valid() {
        // Slot 0 should produce slide 0 (no KASLR)
        let slide = slide_from_slot(0);
        assert_eq!(slide, 0);
    }

    #[test]
    fn test_slide_granularity() {
        // Verify constants are correct
        assert_eq!(KASLR_SLIDE_GRANULARITY, 2 * 1024 * 1024); // 2 MiB
        assert_eq!(KASLR_MAX_SLIDE, 512 * 1024 * 1024); // 512 MiB

        // Max slots should be 256 (512 MiB / 2 MiB)
        let max_slots = KASLR_MAX_SLIDE / KASLR_SLIDE_GRANULARITY;
        assert_eq!(max_slots, 256);
    }

    #[test]
    fn test_pcid_index_and_mask() {
        // Test PCID 0
        let (idx, mask) = pcid_index_and_mask(0);
        assert_eq!(idx, 0);
        assert_eq!(mask, 1);

        // Test PCID 63 (last bit of first word)
        let (idx, mask) = pcid_index_and_mask(63);
        assert_eq!(idx, 0);
        assert_eq!(mask, 1u64 << 63);

        // Test PCID 64 (first bit of second word)
        let (idx, mask) = pcid_index_and_mask(64);
        assert_eq!(idx, 1);
        assert_eq!(mask, 1);

        // Test MAX_PCID (4095)
        let (idx, mask) = pcid_index_and_mask(MAX_PCID);
        assert_eq!(idx, 63); // 4095 / 64 = 63
        assert_eq!(mask, 1u64 << 63); // 4095 % 64 = 63
    }

    #[test]
    fn test_pcid_bitmap_size() {
        // Verify bitmap has enough words for all PCIDs
        assert_eq!(PCID_BITMAP_WORDS, 64); // 4096 bits / 64 bits per word
        assert!(PCID_BITMAP_WORDS * 64 >= (MAX_PCID as usize + 1));
    }

    #[test]
    fn test_pcid_constants() {
        // PCID 0 is reserved
        assert_eq!(MIN_PCID, 1);
        // PCID is a 12-bit field
        assert_eq!(MAX_PCID, 4095);
    }
}
