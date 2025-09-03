// hello_macos_arm64.s
.section __TEXT,__text
.globl _start
.p2align 2
_start:
    // write(1, buf, 14)
    mov     x0, #1
    adrp    x1, L_.str0@page
    add     x1, x1, L_.str0@pageoff
    mov     x2, #14
    mov     x16, #0x0004          // __NR_write = 0x2000004
    movk    x16, #0x0200, lsl #16
    svc     #0x80

    // exit(0)
    mov     x0, #0
    mov     x16, #0x0001          // __NR_exit = 0x2000001
    movk    x16, #0x0200, lsl #16
    svc     #0x80

.section __TEXT,__cstring
L_.str0:
    .ascii  "Hello, world!\n"
