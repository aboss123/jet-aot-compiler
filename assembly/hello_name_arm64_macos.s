.section __TEXT,__text
.globl _start
.p2align 2
_start:
    // n = read(0, buf, 255)
    mov     x0, #0
    adrp    x1, name@page
    add     x1, x1, name@pageoff
    mov     x2, #255
    mov     x16, #0x0003
    movk    x16, #0x0200, lsl #16
    svc     #0x80
    mov     x9, x0                 // bytes read

    // write(1, "Hello, ", 7)
    mov     x0, #1
    adrp    x1, hello@page
    add     x1, x1, hello@pageoff
    mov     x2, #7
    mov     x16, #0x0004
    movk    x16, #0x0200, lsl #16
    svc     #0x80

    // write(1, buf, n)
    mov     x0, #1
    adrp    x1, name@page
    add     x1, x1, name@pageoff
    mov     x2, x9
    mov     x16, #0x0004
    movk    x16, #0x0200, lsl #16
    svc     #0x80

    // exit(0)
    mov     x0, #0
    mov     x16, #0x0001
    movk    x16, #0x0200, lsl #16
    svc     #0x80

.section __DATA,__data
.balign 16
name:   .space 256

.section __TEXT,__cstring
hello:  .ascii "Hello, "
