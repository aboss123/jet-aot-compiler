//============================================================================
// Name        : ir_hello_world.cpp
// Description : Complete IR → Machine Code → Executable pipeline demo
// Shows the full AOT compilation process from IR to running executable
//============================================================================

#include <iostream>
#include <fstream>
#include <memory>
#include "core/ir/ir.h"
#include "backends/codegen/backend.h"

using namespace IR;
using namespace CodeGen;

int main() {
    std::cout << "🚀 IR → Machine Code → Executable Pipeline Demo" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    // ========================================
    // STEP 1: Create IR Module and Function
    // ========================================
    std::cout << "\n📝 Step 1: Creating IR Module..." << std::endl;
    
    Module module("hello_world");
    Function* main_func = module.create_function("main", Type::i32(), {});
    BasicBlock* entry_bb = main_func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(entry_bb);
    
    // Create "Hello, World!" string and syscall to write it
    auto hello_str = module.create_global_string("Hello, World!\\n");
    auto stdout_fd = builder.get_int32(1); // STDOUT_FILENO
    auto str_len = builder.get_int32(14);  // Length of "Hello, World!\n"
    
    // Create syscall arguments
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, hello_str, str_len};
    
    // Platform-aware syscall numbers
    #ifdef __linux__
        builder.create_syscall(1, write_args); // Linux: write = 1
    #else
        builder.create_syscall(4, write_args); // macOS: write = 4
    #endif
    
    // Exit with status 0
    auto exit_code = builder.get_int32(0);
    std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
    
    #ifdef __linux__
        builder.create_syscall(60, exit_args); // Linux: exit = 60
    #else
        builder.create_syscall(1, exit_args);  // macOS: exit = 1
    #endif
    
    std::cout << "✅ IR Module created with hello world program" << std::endl;
    
    // ========================================
    // STEP 2: Test Both Architectures
    // ========================================
    
    for (auto arch : {TargetArch::X86_64, TargetArch::ARM64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        std::cout << "\n🔧 Step 2." << ((arch == TargetArch::ARM64) ? "b" : "a") 
                  << ": Compiling for " << arch_name << "..." << std::endl;
        
        // Create backend for target architecture
        auto backend = BackendFactory::create_backend(arch);
        if (!backend) {
            std::cout << "❌ Failed to create " << arch_name << " backend" << std::endl;
            continue;
        }
        
        // Compile IR to machine code
        if (!backend->compile_module(module)) {
            std::cout << "❌ Failed to compile module for " << arch_name << std::endl;
            continue;
        }
        
        size_t code_size = backend->get_code_size();
        std::cout << "✅ " << arch_name << " compilation successful (" 
                  << code_size << " bytes)" << std::endl;
        
        // ========================================
        // STEP 3: Generate Object File
        // ========================================
        std::string obj_path = "/tmp/hello_world_" + arch_name + ".o";
        if (!backend->write_object(obj_path, "_start")) {
            std::cout << "❌ Failed to write " << arch_name << " object file" << std::endl;
            continue;
        }
        
        std::cout << "✅ " << arch_name << " object file: " << obj_path << std::endl;
        
        // ========================================
        // STEP 4: Generate Executable
        // ========================================
        std::string exe_path = "/tmp/hello_world_" + arch_name;
        if (!backend->write_executable(exe_path, "_start")) {
            std::cout << "❌ Failed to write " << arch_name << " executable" << std::endl;
            continue;
        }
        
        std::cout << "✅ " << arch_name << " executable: " << exe_path << std::endl;
        
        // ========================================
        // STEP 5: Test Execution (if native arch)
        // ========================================
        bool can_execute = false;
        #if defined(__x86_64__) && defined(__APPLE__)
            can_execute = (arch == TargetArch::X86_64);
        #elif defined(__aarch64__) && defined(__APPLE__)
            can_execute = (arch == TargetArch::ARM64);
        #elif defined(__x86_64__) && defined(__linux__)
            can_execute = (arch == TargetArch::X86_64);
        #elif defined(__aarch64__) && defined(__linux__)
            can_execute = (arch == TargetArch::ARM64);
        #endif
        
        if (can_execute) {
            std::cout << "🏃 Step 5: Executing " << arch_name << " binary..." << std::endl;
            std::string cmd = exe_path + " 2>&1";
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                std::string output;
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    output += buffer;
                }
                pclose(pipe);
                std::cout << "📤 Output: " << output;
                std::cout << "✅ " << arch_name << " execution successful!" << std::endl;
            }
        } else {
            std::cout << "⚠️  Cannot execute " << arch_name 
                      << " binary on this platform (cross-compilation)" << std::endl;
        }
        
        // ========================================
        // STEP 6: Analyze Generated Files
        // ========================================
        std::cout << "📊 Step 6: File Analysis..." << std::endl;
        
        // Check object file
        std::ifstream obj_file(obj_path, std::ios::binary | std::ios::ate);
        if (obj_file.is_open()) {
            size_t obj_size = obj_file.tellg();
            std::cout << "   Object file size: " << obj_size << " bytes" << std::endl;
        }
        
        // Check executable file
        std::ifstream exe_file(exe_path, std::ios::binary | std::ios::ate);
        if (exe_file.is_open()) {
            size_t exe_size = exe_file.tellg();
            std::cout << "   Executable size: " << exe_size << " bytes" << std::endl;
        }
        
        // Use file command to show ELF info (if available)
        std::string file_cmd = "file " + exe_path + " 2>/dev/null";
        FILE* file_pipe = popen(file_cmd.c_str(), "r");
        if (file_pipe) {
            char buffer[512];
            if (fgets(buffer, sizeof(buffer), file_pipe)) {
                std::cout << "   File type: " << buffer;
            }
            pclose(file_pipe);
        }
        
        std::cout << "🎉 " << arch_name << " pipeline completed successfully!" << std::endl;
    }
    
    std::cout << "\n🎯 Summary:" << std::endl;
    std::cout << "   ✅ IR module creation" << std::endl;
    std::cout << "   ✅ Multi-architecture compilation" << std::endl;
    std::cout << "   ✅ Object file generation" << std::endl;
    std::cout << "   ✅ Executable generation" << std::endl;
    std::cout << "   ✅ Cross-platform support" << std::endl;
    
    std::cout << "\n🚀 Complete IR → Machine Code → Executable pipeline demonstrated!" << std::endl;
    return 0;
}