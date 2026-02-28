ENTRY(_start)

/* Text KASLR: Named constants for readability and to avoid magic numbers.
 * The kernel virtual base is the start of the high-half identity mapping.
 * The kernel text starts at a 1 MiB offset into that mapping, with the
 * physical load address at the matching 1 MiB physical offset.
 *
 * When the kernel is compiled as a static PIE (-C relocation-model=pie),
 * the linker emits .rela.dyn relocations referencing these link-time VAs.
 * The bootloader applies R_X86_64_RELATIVE relocations with kaslr_slide
 * as the load bias, so all absolute addresses point to the slid location. */
KERNEL_VIRT_BASE = 0xffffffff80000000;
KERNEL_PHYS_BASE = 0x100000;
KERNEL_ENTRY_OFFSET = 0x100000;
KERNEL_TEXT_BASE = KERNEL_VIRT_BASE + KERNEL_ENTRY_OFFSET;

SECTIONS {
    /* 虚拟地址从 KERNEL_TEXT_BASE 开始，映射到物理地址 KERNEL_PHYS_BASE */
    . = KERNEL_TEXT_BASE;

    PROVIDE(kernel_start = .);

    .text : AT(KERNEL_PHYS_BASE) {
        PROVIDE(text_start = .);
        *(.text._start)  /* 确保 _start 在最前面 */
        *(.text .text.*)
        . = ALIGN(4096);  /* 页对齐 */
        PROVIDE(text_end = .);
    }

    .rodata : AT(KERNEL_PHYS_BASE + (ADDR(.rodata) - KERNEL_TEXT_BASE)) {
        PROVIDE(rodata_start = .);
        *(.rodata .rodata.*)
        /* H-26: Exception table for usercopy fault recovery */
        . = ALIGN(16);
        __ex_table_start = .;
        KEEP(*(.ex_table .ex_table.*))
        __ex_table_end = .;
        . = ALIGN(4096);  /* 页对齐 */
        PROVIDE(rodata_end = .);
    }

    .data : AT(KERNEL_PHYS_BASE + (ADDR(.data) - KERNEL_TEXT_BASE)) {
        PROVIDE(data_start = .);
        *(.data .data.*)
        . = ALIGN(4096);  /* 页对齐 */
        PROVIDE(data_end = .);
    }

    .bss : AT(KERNEL_PHYS_BASE + (ADDR(.bss) - KERNEL_TEXT_BASE)) {
        PROVIDE(bss_start = .);
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);  /* 页对齐 */
        PROVIDE(bss_end = .);
    }

    PROVIDE(kernel_end = .);

    /* PIE Text KASLR: Retain dynamic relocation records (.rela.dyn) in the
     * output ELF so the bootloader can parse and apply R_X86_64_RELATIVE
     * relocations at load time. This section is NOT loaded into memory —
     * it is only read from the ELF file by the bootloader before jumping
     * to the kernel entry point.
     *
     * Address 0 is a non-loadable marker; the section header's sh_offset
     * still points to valid data in the ELF file on disk. */
    .rela.dyn 0 : {
        KEEP(*(.rela.dyn))
        KEEP(*(.rela.dyn.*))
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
    }
}
