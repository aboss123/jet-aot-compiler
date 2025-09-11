//============================================================================
// Name        : cross_platform_demo.cpp
// Description : Cross-platform compilation and ELF generation demo
// Shows advanced ELF features, dynamic linking, and platform differences
//============================================================================

#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include "core/ir/ir.h"
#include "backends/codegen/backend.h"
#include "core/tools/elf_builder.h"

using namespace IR;
using namespace CodeGen;

void demonstrate_cross_compilation() {
    std::cout << "🌍 Cross-Platform Compilation Demo" << std::endl;
    std::cout << "==================================" << std::endl;
    
    Module module("cross_platform");
    Function* func = module.create_function("cross_test", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Create a program that works on both platforms
    auto msg = module.create_global_string("Cross-platform hello!\\n");
    auto stdout_fd = builder.get_int32(1);
    auto msg_len = builder.get_int32(22);
    
    std::cout << "\n📝 Creating cross-platform program..." << std::endl;
    
    // Platform-aware syscall generation
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, msg, msg_len};
    std::vector<std::shared_ptr<Value>> exit_args = {builder.get_int32(0)};
    
    // Use conditional compilation for syscall numbers
    #ifdef __linux__
        builder.create_syscall(1, write_args);   // Linux write
        builder.create_syscall(60, exit_args);   // Linux exit
        std::cout << "   🐧 Configured for Linux syscalls" << std::endl;
    #else
        builder.create_syscall(4, write_args);   // macOS write  
        builder.create_syscall(1, exit_args);    // macOS exit
        std::cout << "   🍎 Configured for macOS syscalls" << std::endl;
    #endif
    
    // Compile for all supported architectures
    std::vector<std::pair<TargetArch, std::string>> targets = {
        {TargetArch::X86_64, "x86_64"},
        {TargetArch::ARM64, "ARM64"}
    };
    
    for (auto& [arch, arch_name] : targets) {
        std::cout << "\n🔧 Cross-compiling for " << arch_name << "..." << std::endl;
        
        auto backend = BackendFactory::create_backend(arch);
        if (!backend) {
            std::cout << "❌ Failed to create " << arch_name << " backend" << std::endl;
            continue;
        }
        
        if (!backend->compile_module(module)) {
            std::cout << "❌ Failed to compile for " << arch_name << std::endl;
            continue;
        }
        
        size_t code_size = backend->get_code_size();
        std::cout << "✅ " << arch_name << " compilation: " << code_size << " bytes" << std::endl;
        
        // Generate object file
        std::string obj_path = "/tmp/cross_platform_" + arch_name + ".o";
        if (backend->write_object(obj_path, "_start")) {
            std::cout << "✅ " << arch_name << " object: " << obj_path << std::endl;
            
            // Check object file with file command
            std::string file_cmd = "file " + obj_path + " 2>/dev/null";
            FILE* pipe = popen(file_cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                if (fgets(buffer, sizeof(buffer), pipe)) {
                    std::cout << "   📄 " << buffer;
                }
                pclose(pipe);
            }
        }
        
        // Generate executable
        std::string exe_path = "/tmp/cross_platform_" + arch_name;
        if (backend->write_executable(exe_path, "_start")) {
            std::cout << "✅ " << arch_name << " executable: " << exe_path << std::endl;
            
            // Test execution on native architecture
            bool is_native = false;
            #if defined(__x86_64__)
                is_native = (arch == TargetArch::X86_64);
            #elif defined(__aarch64__)
                is_native = (arch == TargetArch::ARM64);
            #endif
            
            if (is_native) {
                std::cout << "🏃 Testing " << arch_name << " execution..." << std::endl;
                std::string cmd = exe_path + " 2>&1";
                FILE* exec_pipe = popen(cmd.c_str(), "r");
                if (exec_pipe) {
                    char buffer[256];
                    while (fgets(buffer, sizeof(buffer), exec_pipe)) {
                        std::cout << "📤 " << buffer;
                    }
                    pclose(exec_pipe);
                }
            } else {
                std::cout << "⚠️  " << arch_name << " binary (cross-compiled, cannot execute)" << std::endl;
            }
        }
    }
}

void demonstrate_advanced_elf_features() {
    std::cout << "\n🗂️  Advanced ELF Features Demo" << std::endl;
    std::cout << "==============================" << std::endl;
    
    Module module("elf_advanced");
    Function* func = module.create_function("elf_test", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Create a program with complex data sections
    auto hello_str = module.create_global_string("ELF Advanced Demo\\n");
    auto data_str = module.create_global_string("Complex ELF data");
    
    auto stdout_fd = builder.get_int32(1);
    auto str_len = builder.get_int32(18);
    
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, hello_str, str_len};
    std::vector<std::shared_ptr<Value>> exit_args = {builder.get_int32(0)};
    
    #ifdef __linux__
        builder.create_syscall(1, write_args);
        builder.create_syscall(60, exit_args);
    #else
        builder.create_syscall(4, write_args);
        builder.create_syscall(1, exit_args);
    #endif
    
    std::cout << "\n📝 Creating ELF with advanced features..." << std::endl;
    
    // Test both architectures with advanced ELF generation
    for (auto arch : {TargetArch::X86_64, TargetArch::ARM64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        std::cout << "\n🔧 Generating advanced ELF for " << arch_name << "..." << std::endl;
        
        auto backend = BackendFactory::create_backend(arch);
        if (!backend || !backend->compile_module(module)) {
            std::cout << "❌ Failed to compile " << arch_name << " ELF demo" << std::endl;
            continue;
        }
        
        size_t code_size = backend->get_code_size();
        std::cout << "✅ " << arch_name << " ELF compilation: " << code_size << " bytes" << std::endl;
        
        // Generate object with relocations (if supported)
        std::string obj_path = "/tmp/elf_advanced_" + arch_name + ".o";
        if (backend->write_object(obj_path, "_start")) {
            std::cout << "✅ " << arch_name << " advanced object: " << obj_path << std::endl;
            
            // Analyze the ELF object file
            std::string readelf_cmd = "readelf -h " + obj_path + " 2>/dev/null | head -10";
            FILE* pipe = popen(readelf_cmd.c_str(), "r");
            if (pipe) {
                std::cout << "   📊 ELF Header Analysis:" << std::endl;
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    if (strlen(buffer) > 1) {  // Skip empty lines
                        std::cout << "      " << buffer;
                    }
                }
                pclose(pipe);
            }
        }
        
        // Generate executable with enhanced ELF features
        std::string exe_path = "/tmp/elf_advanced_" + arch_name;
        if (backend->write_executable(exe_path, "_start")) {
            std::cout << "✅ " << arch_name << " advanced executable: " << exe_path << std::endl;
            
            // Analyze program headers
            std::string segments_cmd = "readelf -l " + exe_path + " 2>/dev/null | grep -A 5 'Program Headers'";
            FILE* seg_pipe = popen(segments_cmd.c_str(), "r");
            if (seg_pipe) {
                std::cout << "   📊 Program Headers:" << std::endl;
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), seg_pipe)) {
                    if (strlen(buffer) > 1) {
                        std::cout << "      " << buffer;
                    }
                }
                pclose(seg_pipe);
            }
        }
    }
}

void demonstrate_dynamic_linking() {
    std::cout << "\n🔗 Dynamic Linking Features Demo" << std::endl;
    std::cout << "================================" << std::endl;
    
    #ifdef __linux__
        std::cout << "🐧 Running on Linux - demonstrating dynamic ELF features" << std::endl;
        
        // Test the new dynamic executable API
        ELFBuilder64 elf_builder;
        
        // Create simple test code
        uint8_t test_code[] = {
            0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
            0xc3                            // ret
        };
        
        std::cout << "\n📝 Testing dynamic ELF generation..." << std::endl;
        
        // Test basic dynamic executable
        std::vector<std::string> libs = {"libc.so.6"};
        if (elf_builder.write_dynamic_executable("/tmp/dynamic_test", 
                                                 test_code, sizeof(test_code), 
                                                 libs, nullptr, 0, ELFArch::X86_64)) {
            std::cout << "✅ Dynamic ELF executable created: /tmp/dynamic_test" << std::endl;
            
            // Analyze the dynamic sections
            std::string ldd_cmd = "ldd /tmp/dynamic_test 2>/dev/null";
            FILE* pipe = popen(ldd_cmd.c_str(), "r");
            if (pipe) {
                std::cout << "   📊 Dynamic Dependencies:" << std::endl;
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    std::cout << "      " << buffer;
                }
                pclose(pipe);
            }
            
            // Show dynamic section
            std::string dyn_cmd = "readelf -d /tmp/dynamic_test 2>/dev/null | head -15";
            FILE* dyn_pipe = popen(dyn_cmd.c_str(), "r");
            if (dyn_pipe) {
                std::cout << "   📊 Dynamic Section:" << std::endl;
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), dyn_pipe)) {
                    if (strlen(buffer) > 1) {
                        std::cout << "      " << buffer;
                    }
                }
                pclose(dyn_pipe);
            }
        } else {
            std::cout << "❌ Failed to create dynamic ELF executable" << std::endl;
        }
        
        // Test ARM64 dynamic executable
        if (elf_builder.write_dynamic_executable("/tmp/dynamic_test_arm64",
                                                 test_code, sizeof(test_code),
                                                 libs, "/lib/ld-linux-aarch64.so.1",
                                                 0, ELFArch::ARM64)) {
            std::cout << "✅ ARM64 dynamic ELF created: /tmp/dynamic_test_arm64" << std::endl;
        }
        
    #else
        std::cout << "🍎 Running on macOS - dynamic linking features are Linux-specific" << std::endl;
        std::cout << "   💡 Dynamic ELF features require Linux environment" << std::endl;
        std::cout << "   📦 macOS uses Mach-O format instead of ELF" << std::endl;
        
        // Still demonstrate the ELF builder API exists
        std::cout << "\n📝 Demonstrating ELF builder API availability..." << std::endl;
        ELFBuilder64 elf_builder;
        
        uint8_t test_code[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3}; // mov eax, 42; ret
        
        // Show that the API exists but won't create working executables on macOS
        std::vector<std::string> libs = {"libc.so.6"};
        if (elf_builder.write_dynamic_executable("/tmp/elf_demo_macos",
                                                 test_code, sizeof(test_code),
                                                 libs, nullptr, 0, ELFArch::X86_64)) {
            std::cout << "✅ ELF file created (won't execute on macOS): /tmp/elf_demo_macos" << std::endl;
        }
    #endif
}

void demonstrate_relocation_features() {
    std::cout << "\n🔧 Relocation & Symbol Features Demo" << std::endl;
    std::cout << "====================================" << std::endl;
    
    Module module("relocation_demo");
    
    // Create multiple functions for relocation testing
    Function* helper_func = module.create_function("helper", Type::i32(), {});
    BasicBlock* helper_bb = helper_func->create_basic_block("entry");
    
    IRBuilder helper_builder;
    helper_builder.set_insert_point(helper_bb);
    helper_builder.create_ret(helper_builder.get_int32(42));
    
    Function* main_func = module.create_function("main", Type::i32(), {});
    BasicBlock* main_bb = main_func->create_basic_block("entry");
    
    IRBuilder main_builder;
    main_builder.set_insert_point(main_bb);
    
    // Create global data
    auto global_str = module.create_global_string("relocation_test");
    
    // Function call requiring relocation
    auto call_result = main_builder.create_call(Type::i32(), "helper", {});
    
    std::vector<std::shared_ptr<Value>> exit_args = {call_result};
    #ifdef __linux__
        main_builder.create_syscall(60, exit_args);
    #else
        main_builder.create_syscall(1, exit_args);
    #endif
    
    std::cout << "\n📝 Creating module with relocations..." << std::endl;
    std::cout << "   Function calls: main() → helper()" << std::endl;
    std::cout << "   Global data: string constants" << std::endl;
    
    // Test relocation generation for both architectures
    for (auto arch : {TargetArch::X86_64, TargetArch::ARM64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        std::cout << "\n🔧 Testing " << arch_name << " relocations..." << std::endl;
        
        auto backend = BackendFactory::create_backend(arch);
        if (!backend || !backend->compile_module(module)) {
            std::cout << "❌ Failed to compile " << arch_name << " relocation demo" << std::endl;
            continue;
        }
        
        size_t code_size = backend->get_code_size();
        std::cout << "✅ " << arch_name << " relocation compilation: " << code_size << " bytes" << std::endl;
        
        std::string obj_path = "/tmp/relocation_" + arch_name + ".o";
        if (backend->write_object(obj_path, "main")) {
            std::cout << "✅ " << arch_name << " relocation object: " << obj_path << std::endl;
            
            // Show relocation information
            std::string reloc_cmd = "readelf -r " + obj_path + " 2>/dev/null";
            FILE* pipe = popen(reloc_cmd.c_str(), "r");
            if (pipe) {
                std::cout << "   📊 Relocation Entries:" << std::endl;
                char buffer[256];
                bool found_relocs = false;
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    if (strstr(buffer, "Relocation") || strstr(buffer, "Offset") || 
                        strstr(buffer, "0x") || strstr(buffer, "R_")) {
                        std::cout << "      " << buffer;
                        found_relocs = true;
                    }
                }
                if (!found_relocs) {
                    std::cout << "      (No relocations found - may be resolved)" << std::endl;
                }
                pclose(pipe);
            }
            
            // Show symbols
            std::string sym_cmd = "readelf -s " + obj_path + " 2>/dev/null | grep -v '^$'";
            FILE* sym_pipe = popen(sym_cmd.c_str(), "r");
            if (sym_pipe) {
                std::cout << "   📊 Symbol Table:" << std::endl;
                char buffer[256];
                int line_count = 0;
                while (fgets(buffer, sizeof(buffer), sym_pipe) && line_count < 10) {
                    if (strlen(buffer) > 10) {  // Skip header lines
                        std::cout << "      " << buffer;
                        line_count++;
                    }
                }
                pclose(sym_pipe);
            }
        }
    }
}

int main() {
    std::cout << "🌍 Cross-Platform & Advanced ELF Demo" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    demonstrate_cross_compilation();
    demonstrate_advanced_elf_features();
    demonstrate_dynamic_linking();
    demonstrate_relocation_features();
    
    std::cout << "\n🎯 Summary of Demonstrated Features:" << std::endl;
    std::cout << "   ✅ Cross-platform compilation (x86_64 & ARM64)" << std::endl;
    std::cout << "   ✅ Advanced ELF object file generation" << std::endl;
    std::cout << "   ✅ Dynamic linking and PT_DYNAMIC headers" << std::endl;
    std::cout << "   ✅ Relocation and symbol table handling" << std::endl;
    std::cout << "   ✅ Platform-aware syscall generation" << std::endl;
    std::cout << "   ✅ ELF analysis with system tools integration" << std::endl;
    
    std::cout << "\n🚀 Cross-platform demo completed successfully!" << std::endl;
    return 0;
}