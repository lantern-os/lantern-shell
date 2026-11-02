/* The launch binder (RFC-0020): a standalone riscv64 program, same layout
 * constraints as lantern-abi/demo/linker.ld. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x84000000;
MEGAPAGE_SIZE = 0x200000;

SECTIONS
{
    . = BASE_ADDRESS;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(MEGAPAGE_SIZE);

    .data : {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
