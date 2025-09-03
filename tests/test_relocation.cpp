#include "core/tools/module_linker.h"
#include <iostream>
#include <cstdio>

using namespace nextgen::jet::x64;

int main() {
    std::cout << "Testing Module Relocation Functionality" << std::endl;
    std::cout << "=======================================" << std::endl;
    
    ModuleLinker linker;
    
    // Test 1: Create a module with function call relocation
    {
        std::cout << "\nTest 1: Function call with relocation" << std::endl;
        
        Assembler helper(256);
        // Simple helper function that returns 42
        helper.movd(AX, Imm32{42});
        helper.ret();
        
        Assembler main_func(512);
        // Main function that calls helper
        main_func.subq(SP, Imm8{8});  // align stack
        size_t call_offset = main_func.bytes();
        main_func.emit_u8(0xE8);      // call instruction
        main_func.emit_u32(0x00000000); // placeholder for relocation
        main_func.addq(SP, Imm8{8});  // restore stack
        main_func.ret();
        
        // Add modules
        linker.add_module("helper_mod", helper, {"helper_func"});
        linker.add_module("main_mod", main_func, {"main"}, {"helper_func"});
        
        // Add relocation for the call instruction
        linker.add_relocation(call_offset + 1, "helper_func", 
                             ModuleLinker::RelocationType::CALL_REL32);
        
        // Resolve symbols and test
        if (linker.resolve_symbols()) {
            std::cout << "✅ Symbol resolution successful" << std::endl;
            std::cout << "   helper_func @ 0x" << std::hex 
                     << linker.get_symbol_address("helper_func") << std::endl;
            std::cout << "   main @ 0x" << std::hex 
                     << linker.get_symbol_address("main") << std::dec << std::endl;
        } else {
            std::cout << "❌ Symbol resolution failed" << std::endl;
        }
    }
    
    // Test 2: Create object file with relocations
    {
        std::cout << "\nTest 2: Object file generation with relocations" << std::endl;
        
        ModuleLinker obj_linker;
        
        Assembler data_module(256);
        // Data module with a constant
        data_module.align_to(8);
        data_module.emit_data32(0xDEADBEEF);
        
        Assembler code_module(512);  
        // Code module that loads the constant
        code_module.movd(AX, Imm32{0}); // placeholder - will be relocated
        code_module.ret();
        
        obj_linker.add_module("data_mod", data_module, {"my_constant"});
        obj_linker.add_module("code_mod", code_module, {"load_constant"}, {"my_constant"});
        
        // Add relocation for loading constant (offset 1 = after mov opcode)
        obj_linker.add_relocation(1, "my_constant", 
                                 ModuleLinker::RelocationType::ABS32);
        
        if (obj_linker.resolve_symbols()) {
            std::cout << "✅ Object symbols resolved" << std::endl;
            
            // Try to write object file
            if (obj_linker.link_object("/tmp/test_reloc.o")) {
                std::cout << "✅ Object file generated: /tmp/test_reloc.o" << std::endl;
                
                // Check if file exists and has content
                FILE* f = fopen("/tmp/test_reloc.o", "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long size = ftell(f);
                    fclose(f);
                    std::cout << "   File size: " << size << " bytes" << std::endl;
                } else {
                    std::cout << "❌ Could not read generated file" << std::endl;
                }
            } else {
                std::cout << "❌ Object file generation failed" << std::endl;
            }
        } else {
            std::cout << "❌ Object symbol resolution failed" << std::endl;
        }
    }
    
    // Test 3: External symbol relocation
    {
        std::cout << "\nTest 3: External symbol relocation" << std::endl;
        
        ModuleLinker ext_linker;
        
        // Add external symbol (puts function)
        ext_linker.add_external("puts", (void*)&puts);
        
        Assembler call_puts(256);
        // Placeholder for call instruction - will need relocation
        call_puts.movq(DI, Imm64{0}); // placeholder for string address
        call_puts.emit_u8(0xFF);      // call reg indirect
        call_puts.emit_u8(0x15);      // ModRM for call [rip+disp32]
        size_t puts_reloc_offset = call_puts.bytes();
        call_puts.emit_u32(0x00000000); // placeholder for puts address
        call_puts.ret();
        
        ext_linker.add_module("extern_test", call_puts, {"test_extern"}, {"puts"});
        ext_linker.add_relocation(puts_reloc_offset, "puts", 
                                 ModuleLinker::RelocationType::REL32);
        
        if (ext_linker.resolve_symbols()) {
            std::cout << "✅ External symbol resolution successful" << std::endl;
            std::cout << "   puts @ 0x" << std::hex 
                     << ext_linker.get_symbol_address("puts") << std::dec << std::endl;
        } else {
            std::cout << "❌ External symbol resolution failed" << std::endl;
        }
    }
    
    std::cout << "\n🎯 Relocation tests completed!" << std::endl;
    return 0;
}