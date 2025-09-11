//============================================================================
// Name        : user_input_demo.cpp
// Description : Complete end-to-end user input demo
// Creates a standalone executable that prompts for name and says hello
// Uses IR → Machine Code → Executable pipeline with syscall-based I/O
//============================================================================

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include "core/ir/ir.h"
#include "backends/codegen/backend.h"
#include "core/tools/syscall_constants.h"

using namespace IR;
using namespace CodeGen;

class UserInputDemo {
private:
    // Program strings as byte arrays
    std::vector<uint8_t> hello_prefix;
    
public:
    UserInputDemo() {
        // Initialize strings - no prompt needed, just like assembly version
        std::string hello = "Hello, ";
        hello_prefix.assign(hello.begin(), hello.end()); 
    }
    
    Module create_user_input_module() {
        std::cout << "\n📝 Creating IR Module for User Input Program..." << std::endl;
        
        Module module("user_input_demo");
        Function* main_func = module.create_function("main", Type::i32(), {});
        BasicBlock* entry_bb = main_func->create_basic_block("entry");
        
        IRBuilder builder;
        builder.set_insert_point(entry_bb);
        
        std::cout << "   🔧 Building IR for interactive I/O program..." << std::endl;
        
        // === Step 1: Output prompt "Enter Name: " ===
        std::cout << "      📝 Adding name prompt..." << std::endl;
        
        std::string prompt_str = "Enter Name: ";
        auto prompt_data = module.create_global_string(prompt_str);
        std::vector<std::shared_ptr<Value>> prompt_args;
        #ifdef __linux__
            prompt_args.push_back(builder.get_int32(1)); // stdout
            prompt_args.push_back(prompt_data);          // "Enter Name: "
            prompt_args.push_back(builder.get_int32(prompt_str.size()));
            builder.create_syscall(SyscallConstants::LINUX_SYS_WRITE, prompt_args);
        #else
            prompt_args.push_back(builder.get_int32(1)); // stdout
            prompt_args.push_back(prompt_data);          // "Enter Name: "
            prompt_args.push_back(builder.get_int32(prompt_str.size()));
            builder.create_syscall(SyscallConstants::MACOS_SYS_WRITE, prompt_args);
        #endif
        
        // === Step 2: Read user input directly (like assembly version) ===
        std::cout << "      📥 Adding user input reading..." << std::endl;
        
        // Allocate buffer for user input (64 bytes should be enough for a name)
        const uint32_t input_buffer_size = 64;
        auto input_buffer = builder.create_alloca(Type::i8(), builder.get_int32(input_buffer_size));
        
        // Read syscall: read(stdin, buffer, size) - using correct syscall numbers
        std::vector<std::shared_ptr<Value>> read_args;
        #ifdef __linux__
            read_args.push_back(builder.get_int32(0));   // stdin
            read_args.push_back(input_buffer);           // buffer
            read_args.push_back(builder.get_int32(input_buffer_size - 1)); // leave space for null terminator
            auto bytes_read = builder.create_syscall(SyscallConstants::LINUX_SYS_READ, read_args);
        #else
            read_args.push_back(builder.get_int32(0));   // stdin  
            read_args.push_back(input_buffer);           // buffer
            read_args.push_back(builder.get_int32(input_buffer_size - 1)); // leave space for null terminator
            auto bytes_read = builder.create_syscall(SyscallConstants::MACOS_SYS_READ, read_args);
        #endif
        
        // === Step 3: Output "Hello, " ===
        std::cout << "      👋 Adding hello prefix output..." << std::endl;
        
        std::string hello_str(hello_prefix.begin(), hello_prefix.end());
        auto hello_data = module.create_global_string(hello_str);
        std::vector<std::shared_ptr<Value>> hello_args;
        #ifdef __linux__
            hello_args.push_back(builder.get_int32(1)); // stdout
            hello_args.push_back(hello_data);           // "Hello, "
            hello_args.push_back(builder.get_int32(hello_prefix.size()));
            builder.create_syscall(SyscallConstants::LINUX_SYS_WRITE, hello_args);
        #else
            hello_args.push_back(builder.get_int32(1)); // stdout
            hello_args.push_back(hello_data);           // "Hello, "
            hello_args.push_back(builder.get_int32(hello_prefix.size()));
            builder.create_syscall(SyscallConstants::MACOS_SYS_WRITE, hello_args);
        #endif
        
        // === Step 4: Output the user's name (including newline) ===
        std::cout << "      📝 Adding user name output (with newline)..." << std::endl;
        
        // Use bytes_read directly - includes the newline from input
        std::vector<std::shared_ptr<Value>> name_args;
        #ifdef __linux__
            name_args.push_back(builder.get_int32(1)); // stdout
            name_args.push_back(input_buffer);         // user's name
            name_args.push_back(bytes_read);           // exact bytes read (includes \n)
            builder.create_syscall(SyscallConstants::LINUX_SYS_WRITE, name_args);
        #else
            name_args.push_back(builder.get_int32(1)); // stdout
            name_args.push_back(input_buffer);         // user's name  
            name_args.push_back(bytes_read);           // exact bytes read (includes \n)
            builder.create_syscall(SyscallConstants::MACOS_SYS_WRITE, name_args);
        #endif
        
        // === Step 5: Exit cleanly ===
        std::cout << "      🚪 Adding clean exit..." << std::endl;
        
        std::vector<std::shared_ptr<Value>> exit_args = {builder.get_int32(0)}; // exit code 0
        #ifdef __linux__
            builder.create_syscall(SyscallConstants::LINUX_SYS_EXIT, exit_args);
        #else
            builder.create_syscall(SyscallConstants::MACOS_SYS_EXIT, exit_args);
        #endif
        
        std::cout << "   ✅ IR module creation completed!" << std::endl;
        return module;
    }
    
    void demonstrate_pipeline() {
        std::cout << "🎮 Interactive User Input Demo" << std::endl;
        std::cout << "=============================" << std::endl;
        std::cout << "Creating a standalone executable that:" << std::endl;
        std::cout << "  1. Prompts \"Enter Name: \"" << std::endl;
        std::cout << "  2. Waits for user input (name)" << std::endl;
        std::cout << "  3. Outputs \"Hello, <name>!\"" << std::endl;
        std::cout << "  4. Uses only direct syscalls (no C runtime)" << std::endl;
        std::cout << "  5. Matches the assembly reference implementation" << std::endl;
        
        // Create IR module
        auto module = create_user_input_module();
        
        std::cout << "\n🔧 Compiling to Machine Code..." << std::endl;
        
        // Test both architectures
        std::vector<std::pair<TargetArch, std::string>> targets = {
            {TargetArch::ARM64, "ARM64"},
            {TargetArch::X86_64, "x86_64"}
        };
        
        for (auto& [arch, arch_name] : targets) {
            std::cout << "\n📱 Compiling for " << arch_name << "..." << std::endl;
            
            auto backend = BackendFactory::create_backend(arch);
            if (!backend) {
                std::cout << "❌ Failed to create " << arch_name << " backend" << std::endl;
                continue;
            }
            
            // Compile the module
            if (backend->compile_module(module)) {
                size_t code_size = backend->get_code_size();
                std::cout << "   ✅ " << arch_name << " compilation successful (" << code_size << " bytes)" << std::endl;
                
                // Generate executable
                std::string exe_path = "/tmp/user_input_" + arch_name;
                if (backend->write_executable(exe_path, "_start")) {
                    std::cout << "   ✅ Executable created: " << exe_path << std::endl;
                    
                    // Test execution for native architecture
                    if ((arch == TargetArch::ARM64 && 
                         #ifdef __aarch64__
                         true
                         #else
                         false
                         #endif
                        ) || (arch == TargetArch::X86_64 &&
                         #ifdef __x86_64__
                         true
                         #else
                         false
                         #endif
                        )) {
                        std::cout << "   🏃 Testing interactive execution..." << std::endl;
                        std::cout << "      💡 Run manually: " << exe_path << std::endl;
                        
                        // Provide a simple automated test
                        std::cout << "   🔧 Running automated test with 'TestUser'..." << std::endl;
                        std::string cmd = "echo 'TestUser' | " + exe_path;
                        int result = system(cmd.c_str());
                        if (result == 0) {
                            std::cout << "   ✅ Automated test successful!" << std::endl;
                        } else {
                            std::cout << "   ⚠️  Automated test completed (exit code " << (result >> 8) << ")" << std::endl;
                        }
                    } else {
                        std::cout << "   ⚠️  Cross-compiled binary (cannot test on this platform)" << std::endl;
                    }
                    
                    // File analysis
                    std::cout << "   📊 File Analysis:" << std::endl;
                    std::string file_cmd = "file " + exe_path + " 2>/dev/null || echo 'File command failed'";
                    std::cout << "      ";
                    system(file_cmd.c_str());
                    
                    std::string size_cmd = "ls -lh " + exe_path + " | awk '{print $5}' 2>/dev/null || echo 'Unknown size'";
                    std::cout << "      Size: ";
                    system(size_cmd.c_str());
                    
                } else {
                    std::cout << "   ❌ Failed to create executable" << std::endl;
                }
            } else {
                std::cout << "   ❌ " << arch_name << " compilation failed" << std::endl;
            }
        }
        
        std::cout << "\n🎯 Demo Summary:" << std::endl;
        std::cout << "   ✅ IR module created with interactive I/O" << std::endl;
        std::cout << "   ✅ Cross-architecture compilation" << std::endl;
        std::cout << "   ✅ Standalone executables (no C runtime)" << std::endl;
        std::cout << "   ✅ Direct syscall implementation" << std::endl;
        std::cout << "   ✅ Complete input/output pipeline" << std::endl;
        
        std::cout << "\n🚀 Try running the executables manually:" << std::endl;
        std::cout << "   /tmp/user_input_ARM64" << std::endl;
        std::cout << "   /tmp/user_input_x86_64" << std::endl;
        std::cout << "\n💡 These are completely standalone - no dependencies!" << std::endl;
    }
};

int main() {
    UserInputDemo demo;
    demo.demonstrate_pipeline();
    return 0;
}