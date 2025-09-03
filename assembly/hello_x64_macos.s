// hello_x64_macos.s
.section __TEXT,__text
.globl _start
_start:
    mov     $0x2000004, %rax      # write
    mov     $1, %rdi              # fd = 1
    lea     msg(%rip), %rsi       # buf
    mov     $14, %rdx             # count
    syscall

    mov     $0x2000001, %rax      # exit
    xor     %rdi, %rdi
    syscall

.section __TEXT,__cstring
msg:
    .ascii "Hello, world!\n"
