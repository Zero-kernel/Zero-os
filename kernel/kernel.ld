ENTRY(_start)

SECTIONS {
    . = 0x100000;  /* 将内核加载到1MB位置，这是一个安全的地址 */
    
    .text : {
        *(.text._start)  /* 确保 _start 在最前面 */
        *(.text .text.*)
    }
    
    .rodata : {
        *(.rodata .rodata.*)
    }
    
    .data : {
        *(.data .data.*)
    }
    
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }
    
    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
    }
}
