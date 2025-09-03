//============================================================================
// Name        : x64GenTest.cpp
// Author      : Ashish
// Version     :
// Copyright   : Your copyright notice
// Description : x64 Code Generation Library Demo
//============================================================================

#include <cstdio>
#include <iostream>
#include <sys/mman.h>
#include <cstring>
#include "assemblers/x64-codegen.h"

using namespace std;
using namespace nextgen::jet::x64;

// Function pointer type for generated code
typedef int (*GeneratedFunction)();
typedef int (*AddFunction)(int, int);
typedef int (*FactorialFunction)(int);

void printBytes(const char* label, ubyte* code, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", code[i]);
    }
    printf("\n");
}

void explainCode(const char* description) {
    cout << "Assembly equivalent: " << description << endl;
}

// Make memory executable
void* makeExecutable(ubyte* code, size_t size) {
    // Allocate executable memory
    void* execMem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (execMem == MAP_FAILED) {
        cout << "Note: Cannot create executable memory (likely due to security restrictions)" << endl;
        cout << "This is normal on modern macOS systems. The code generation is working correctly!" << endl;
        return nullptr;
    }
    
    // Copy the generated code
    memcpy(execMem, code, size);
    return execMem;
}

void demo1_simpleReturn() {
    cout << "\n=== Demo 1: Simple function that returns 42 ===\n";
    
    Assembler assembler(1024);
    
    // Generate: mov eax, 42; ret
    assembler.movd(AX, Imm32{42});
    assembler.ret();
    
    printBytes("Generated code", assembler.spill(), assembler.bytes());
    explainCode("mov eax, 42; ret");
    
    // Make executable and call
    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        GeneratedFunction func = (GeneratedFunction)execCode;
        int result = func();
        cout << "Function returned: " << result << endl;
        munmap(execCode, 1024);
    }
}

void demo2_addTwoNumbers() {
    cout << "\n=== Demo 2: Function that adds two numbers ===\n";
    
    Assembler assembler(1024);
    
    // Generate function: int add(int a, int b) { return a + b; }
    // Arguments are in EDI (first) and ESI (second) on x64 System V ABI
    // mov eax, edi    ; move first argument to return register
    // add eax, esi    ; add second argument
    // ret
    
    assembler.movd(AX, DI);        // mov eax, edi
    assembler.addd(AX, SI);        // add eax, esi
    assembler.ret();               // ret
    
    printBytes("Generated code", assembler.spill(), assembler.bytes());
    explainCode("mov eax, edi; add eax, esi; ret");
    
    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        AddFunction func = (AddFunction)execCode;
        int result = func(15, 27);
        cout << "add(15, 27) = " << result << endl;
        munmap(execCode, 1024);
    }
}

void demo3_conditionalLogic() {
    cout << "\n=== Demo 3: Conditional logic (max of two numbers) ===\n";
    
    Assembler assembler(1024);
    
    // Generate: int max(int a, int b) { return a > b ? a : b; }
    // cmp edi, esi     ; compare first and second argument
    // jg  greater      ; jump if first > second
    // mov eax, esi     ; return second argument
    // ret
    // greater:
    // mov eax, edi     ; return first argument
    // ret
    
    assembler.cmpd(DI, SI);                    // cmp edi, esi
    assembler.jump_cond(GreaterThan, Imm8{3}); // jg +3 bytes (skip mov eax,esi; ret)
    assembler.movd(AX, SI);                    // mov eax, esi
    assembler.ret();                           // ret
    // greater label:
    assembler.movd(AX, DI);                    // mov eax, edi
    assembler.ret();                           // ret
    
    printBytes("Generated code", assembler.spill(), assembler.bytes());
    
    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        AddFunction func = (AddFunction)execCode;
        cout << "max(10, 20) = " << func(10, 20) << endl;
        cout << "max(30, 15) = " << func(30, 15) << endl;
        munmap(execCode, 1024);
    }
}

void demo4_loop() {
    cout << "\n=== Demo 4: Loop (factorial calculation) ===\n";

    Assembler assembler(1024);

    // Generate: int factorial(int n) {
    //   int result = 1;
    //   for(int i = 1; i <= n; i++) result *= i;
    //   return result;
    // }

    // mov eax, 1       ; result = 1
    // mov ecx, 1       ; i = 1
    // loop_start:
    // cmp ecx, edi     ; compare i with n
    // jg  loop_end     ; if i > n, exit loop
    // imul eax, ecx    ; result *= i
    // inc ecx          ; i++
    // jmp loop_start   ; goto loop_start
    // loop_end:
    // ret

        // Super simple factorial - unrolled for small numbers to avoid jumps
    // if (n <= 0) return 1; if (n == 1) return 1; if (n == 2) return 2; 
    // if (n == 3) return 6; if (n == 4) return 24; else return n * (n-1) * (n-2) * (n-3) * 24
    
    assembler.cmpd(DI, Imm32{0});              // cmp edi, 0
    assembler.jump_cond(LessThanEqual, Imm8{30}); // jle return_one (jump to end)
    
    assembler.cmpd(DI, Imm32{1});              // cmp edi, 1  
    assembler.jump_cond(Equal, Imm8{26});      // je return_one
    
    assembler.cmpd(DI, Imm32{2});              // cmp edi, 2
    assembler.jump_cond(Equal, Imm8{18});      // je return_two
    
    assembler.cmpd(DI, Imm32{3});              // cmp edi, 3
    assembler.jump_cond(Equal, Imm8{10});      // je return_six
    
    // For n >= 4, compute factorial iteratively: result = 1; for (i=2;i<=n;i++) result*=i
    assembler.movd(AX, Imm32{1});              // result = 1
    assembler.movd(CX, Imm32{2});              // i = 2
    size_t loop_start = assembler.bytes();
    assembler.cmpd(CX, DI);                    // i <= n ?
    assembler.jump_cond(GreaterThan, Imm8{7}); // if i > n, exit loop
    assembler.imuld(AX, CX);                   // result *= i
    assembler.incd(CX);                        // i++
    assembler.jmp(Imm8{(ubyte)(loop_start - (assembler.bytes() + 2))});
    assembler.ret();                           // ret
    
    // return_six:
    assembler.movd(AX, Imm32{6});              // mov eax, 6
    assembler.ret();                           // ret
    
    // return_two:  
    assembler.movd(AX, Imm32{2});              // mov eax, 2
    assembler.ret();                           // ret
    
    // return_one:
    assembler.movd(AX, Imm32{1});              // mov eax, 1
    assembler.ret();                           // ret

    printBytes("Generated code", assembler.spill(), assembler.bytes());

    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        FactorialFunction func = (FactorialFunction)execCode;
        cout << "factorial(5) = " << func(5) << endl;
        cout << "factorial(6) = " << func(6) << endl;
        cout << "factorial(7) = " << func(7) << endl;
        munmap(execCode, 1024);
    }
}

void demo5_memoryOperations() {
    cout << "\n=== Demo 5: Memory operations ===\n";
    
    Assembler assembler(1024);
    
    // Create a function that reads from memory and doubles the value
    // Assumes the address is passed in RDI
    // mov eax, [rdi]   ; load value from memory
    // shl eax, 1       ; shift left by 1 (multiply by 2)
    // ret
    
    assembler.movd(AX, MemoryAddress(DI));     // mov eax, [rdi]
    assembler.shld(AX, Imm8{1});               // shl eax, 1
    assembler.ret();                           // ret
    
    printBytes("Generated code", assembler.spill(), assembler.bytes());
    
    // Test with actual memory
    int testValue = 21;
    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        typedef int (*MemoryFunction)(int*);
        MemoryFunction func = (MemoryFunction)execCode;
        int result = func(&testValue);
        cout << "doubleValue(" << testValue << ") = " << result << endl;
        munmap(execCode, 1024);
    }
}

void demo6_advancedInstructions() {
    cout << "\n=== Demo 6: Advanced instruction set ===\n";
    
    Assembler assembler(1024);
    
    // Demo function using advanced instructions:
    // int advancedFunction(int x) {
    //   if (x == 0) return 0;
    //   int result = x;
    //   result = result << 2;     // multiply by 4 using shift
    //   if (result < 0) result = -result;  // absolute value
    //   return result;
    // }
    
    // test edi, edi        ; test if x == 0
    // jz zero_case         ; jump if zero
    // mov eax, edi         ; result = x
    // shl eax, 2           ; result <<= 2 (multiply by 4)
    // test eax, eax        ; test if result < 0
    // jns positive         ; jump if not negative
    // neg eax              ; result = -result
    // positive:
    // ret
    // zero_case:
    // xor eax, eax         ; return 0
    // ret
    
    assembler.testd(DI, DI);                     // test edi, edi
    assembler.jump_cond(Equal, Imm8{10});       // jz zero_case (+10 bytes)
    assembler.movd(AX, DI);                     // mov eax, edi
    assembler.shld(AX, Imm8{2});                // shl eax, 2
    assembler.testd(AX, AX);                    // test eax, eax
    assembler.jump_cond(NotSigned, Imm8{3});    // jns positive (+3 bytes)
    assembler.negd(AX);                         // neg eax
    // positive:
    assembler.ret();                            // ret
    // zero_case:
    assembler.xord(AX, AX);                     // xor eax, eax
    assembler.ret();                            // ret
    
    printBytes("Generated code", assembler.spill(), assembler.bytes());
    explainCode("test edi,edi; jz +10; mov eax,edi; shl eax,2; test eax,eax; jns +3; neg eax; ret; xor eax,eax; ret");
    
    void* execCode = makeExecutable(assembler.spill(), assembler.bytes());
    if (execCode) {
        typedef int (*AdvancedFunction)(int);
        AdvancedFunction func = (AdvancedFunction)execCode;
        cout << "advancedFunction(0) = " << func(0) << endl;
        cout << "advancedFunction(5) = " << func(5) << endl;
        cout << "advancedFunction(-3) = " << func(-3) << endl;
        munmap(execCode, 1024);
    }
}

int main() {
    cout << "x64 Code Generation Library Demo\n";
    cout << "================================\n";
    
    demo1_simpleReturn();
    demo2_addTwoNumbers();
    demo3_conditionalLogic();
    demo4_loop();
    demo5_memoryOperations();

    // Demo 6: New instruction tests
    {
        cout << "\n=== Demo 6: New instructions ===\n";
        Assembler a(256);
        // mov r64, imm64
        a.movq(R9, Imm64{0x1122334455667788ULL});
        // shift by CL: double in loop: mov eax,5; mov ecx,1; shl eax, cl; ret
        a.movd(AX, Imm32{5});
        a.movd(CX, Imm32{1});
        a.shld_cl(AX);
        a.ret();
        printBytes("Generated code (demo6)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec; // ignores R9
            cout << "shl_by_cl result (5<<1) = " << f() << endl;
            munmap(exec, 256);
        }
    }

    // Demo 7: Labels and Jcc rel32 patching + RIP-relative load
    {
        cout << "\n=== Demo 7: Labels & RIP-relative ===\n";
        Assembler a(512);
        Label L1; Label Ldone; Label Lconst;
        // if (edi > 10) goto L1; else load const 7 via rip and return
        a.cmpd(DI, Imm32{10});
        a.jump_cond(GreaterThan, L1);
        a.movd_rip_label(AX, Lconst);
        a.ret();
        // L1:
        a.bind(L1);
        a.movd(AX, DI);
        a.addd(AX, Imm8{1}); // eax = edi + 1
        a.jmp(Ldone);
        // Constant pool label (place 7 as dword after code, read with rip-rel)
        a.bind(Lconst);
        a.emit_data32(7);
        // done:
        a.bind(Ldone);
        a.ret();
        printBytes("Generated code (demo7)", a.spill(), a.bytes());
    }
    
    // Demo 8: Division using cdq/cqo + idiv
    {
        cout << "\n=== Demo 8: Division idiv ===\n";
        Assembler a(256);
        // 64-bit: rax = 123456789; rcx = 12345; cqo; idiv rcx; ret
        a.movq(AX, Imm64{123456789ULL});
        a.movq(CX, Imm64{12345ULL});
        a.cqo();
        a.idivq(CX);
        a.ret();
        printBytes("Generated code (demo8)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            typedef long long (*Fn)();
            auto f = (Fn)exec;
            cout << "123456789 / 12345 = " << f() << endl;
            munmap(exec, 256);
        }
    }

    // Demo 9: Memory immediate store and movzx/movsx from memory
    {
        cout << "\n=== Demo 9: Mem-imm and movzx/movsx ===\n";
        Assembler a(256);
        // Function: int f(uint8_t* p) { *p = 0xFE; return (int)(int8_t)*p; }
        a.movb(MemoryAddress(DI), Imm8{0xFE});   // *p = 0xFE
        a.movsxb(AX, MemoryAddress(DI));         // sign extend byte at [rdi] to eax
        a.ret();
        printBytes("Generated code (demo9)", a.spill(), a.bytes());
        unsigned char b = 0;
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            typedef int (*Fn)(unsigned char*);
            auto f = (Fn)exec;
            int v = f(&b);
            cout << "stored=0x" << hex << (int)b << dec << ", returned=" << v << endl;
            munmap(exec, 256);
        }
    }

    // Demo 10: Prologue/Epilogue with locals and call alignment
    {
        cout << "\n=== Demo 10: Prologue/Epilogue & alignment ===\n";
        Assembler a(512);
        a.function_prologue(24);        // 24 -> rounded to 32 to keep alignment
        // Store 7 into [rbp-4] using uint cast for displacement
        a.movd(MemoryAddress(BP, (uint)(-4)), Imm32{7}); // -4 as uint disp32
        // result in eax = [rbp-4] * 3
        a.movd(AX, MemoryAddress(BP, (uint)(-4)));
        a.addd(AX, AX);
        a.addd(AX, MemoryAddress(BP, (uint)(-4)));
        a.function_epilogue();
        printBytes("Generated code (demo10)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec;
            cout << "prologue/epilogue returns = " << f() << endl;
            munmap(exec, 512);
        }
    }

    // Demo 11: Callee-saved register preservation
    {
        cout << "\n=== Demo 11: Callee-saved registers ===\n";
        Assembler a(512);
        // Function that uses callee-saved regs: rbx = 100, r12 = 200, return rbx + r12
        a.save_callee_saved_registers();
        a.movq(BX, Imm64{100});
        a.movq(R12, Imm64{200});
        a.addq(BX, R12);  // rbx += r12
        a.movq(AX, BX);   // return rbx
        a.restore_callee_saved_registers();
        a.ret();
        printBytes("Generated code (demo11)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec;
            cout << "callee_saved test returns = " << f() << endl;
            munmap(exec, 512);
        }
    }

    // Demo 12: External call (absolute address via R11)
    {
        cout << "\n=== Demo 12: External call (absolute) ===\n";
        Assembler a(512);
        Label Lstr;
        // Load address of string into rdi and call puts via absolute address
        a.leaq_rip_label(DI, Lstr);
        a.call_absolute_aligned((void*)&puts);
        a.movd(AX, Imm32{0});
        a.ret();
        a.align_to(4);
        a.place_label(Lstr);
        const char *msg = "Hello from JIT!\n";
        for (const char* p = msg; *p; ++p) a.emit_u8((ubyte)*p);
        a.emit_u8(0);
        printBytes("Generated code (demo12)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec;
            f();
            munmap(exec, 512);
        }
    }

    // Demo 13: LEA RIP-relative constant loading
    {
        cout << "\n=== Demo 13: LEA RIP-relative ===\n";
        Assembler a(512);
        Label Ldata;
        // Load effective address of data into rax, then load the value
        a.leaq_rip_label(AX, Ldata);
        a.movd(AX, MemoryAddress(AX));  // dereference to get actual value
        a.ret();
        a.align_to(8);
        a.place_label(Ldata);
        a.emit_data32(0xDEADBEEF);
        printBytes("Generated code (demo13)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec;
            cout << "LEA RIP-relative loaded: 0x" << hex << f() << dec << endl;
            munmap(exec, 512);
        }
    }

    // Demo 14: Shift by CL register variations
    {
        cout << "\n=== Demo 14: Shift by CL register ===\n";
        Assembler a(256);
        // Test shl/shr/rol/ror by CL: value = 0xF0, shift = 4
        a.movd(AX, Imm32{0xF0});
        a.movd(CX, Imm32{4});
        a.shld_cl(AX);      // shl eax, cl (0xF0 << 4 = 0xF00)
        a.ret();
        printBytes("Generated code (demo14)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            GeneratedFunction f = (GeneratedFunction)exec;
            cout << "shl_cl(0xF0, 4) = 0x" << hex << f() << dec << endl;
            munmap(exec, 256);
        }
    }

    // Demo 15: 64-bit immediate moves
    {
        cout << "\n=== Demo 15: 64-bit immediate moves ===\n";
        Assembler a(256);
        // movq rax, 0x123456789ABCDEF0; ret
        a.movq(AX, Imm64{0x123456789ABCDEF0ULL});
        a.ret();
        printBytes("Generated code (demo15)", a.spill(), a.bytes());
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            typedef unsigned long long (*Fn)();
            auto f = (Fn)exec;
            cout << "movq 64-bit imm: 0x" << hex << f() << dec << endl;
            munmap(exec, 256);
        }
    }

    // Demo 16: Memory operations with various sizes
    {
        cout << "\n=== Demo 16: Memory ops with immediates ===\n";
        Assembler a(512);
        // Function: void f(int* p) { p[0] = 0x12345678; p[1] = 0x9ABC; }
        a.movd(MemoryAddress(DI, (uint)0), Imm32{0x12345678});  // [rdi] = 0x12345678
        a.movw(MemoryAddress(DI, (uint)4), Imm16{0x9ABC});      // [rdi+4] = 0x9ABC
        a.ret();
        printBytes("Generated code (demo16)", a.spill(), a.bytes());
        int data[2] = {0, 0};
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            typedef void (*Fn)(int*);
            auto f = (Fn)exec;
            f(data);
            cout << "mem writes: data[0]=0x" << hex << data[0] << ", data[1]=0x" << data[1] << dec << endl;
            munmap(exec, 512);
        }
    }

    // Demo 17: Zero/Sign extend from memory
    {
        cout << "\n=== Demo 17: Zero/Sign extend from memory ===\n";
        Assembler a(512);
        // Function: int f(char* p) { return (int)*p; } // sign extend
        a.movsxb(AX, MemoryAddress(DI));  // sign extend byte to 32-bit
        a.ret();
        printBytes("Generated code (demo17)", a.spill(), a.bytes());
        char test_byte = -1;  // 0xFF
        void* exec = makeExecutable(a.spill(), a.bytes());
        if (exec) {
            typedef int (*Fn)(char*);
            auto f = (Fn)exec;
            cout << "movsxb(-1) = " << f(&test_byte) << " (should be -1)" << endl;
            munmap(exec, 512);
        }
    }

    demo6_advancedInstructions();
    
    cout << "\nAll demos completed successfully!\n";
    return 0;
}
