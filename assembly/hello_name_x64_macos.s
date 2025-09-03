// hello_name_x86.s  (macOS x86_64, AT&T syntax)
.section __TEXT,__text
.globl _start
_start:
    # n = read(0, name, 255)
    mov     $0x2000003, %rax
    xor     %rdi, %rdi
    lea     name(%rip), %rsi
    mov     $255, %rdx
    syscall
    mov     %rax, %r12            # save n

    # write(1, "Hello, ", 7)
    mov     $0x2000004, %rax
    mov     $1, %rdi
    lea     hello(%rip), %rsi
    mov     $7, %rdx
    syscall

    # write(1, name, n)
    mov     $0x2000004, %rax
    mov     $1, %rdi
    lea     name(%rip), %rsi
    mov     %r12, %rdx
    syscall

    # exit(0)
    mov     $0x2000001, %rax
    xor     %rdi, %rdi
    syscall

.section __TEXT,__cstring
hello:
    .ascii "Hello, "

.section __DATA,__bss
.lcomm name,256
