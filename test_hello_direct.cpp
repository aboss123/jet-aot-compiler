#include <iostream>
#include <memory>
#include "src/core/ir/module.h"
#include "src/core/ir/ir_builder.h"
#include "src/backends/codegen/backend_factory.h"

using namespace IR;
using namespace CodeGen;

int main() {
    std::cout << "🧪 Creating 'Hello, ELF Debug!' executable..." << std::endl;

    // Create a module
    auto module = std::make_unique<Module>("elf_debug_test");
    IRBuilder builder;

    // Create global strings
    auto hello_str = module->create_global_string("Hello, ELF Debug!\n");
    auto world_str = module->create_global_string("World!\n");

    // Create _start function
    Function* start_func = module->create_function("_start", Type::void_type(), {});
    BasicBlock* start_bb = start_func->create_basic_block("entry");
    builder.set_insert_point(start_bb);

    // write(1, hello_str, 19) - Linux x64 SYS_write
    auto fd_val = builder.get_int32(1);
    auto hello_len = builder.get_int32(19);
    builder.create_syscall(1, {fd_val, hello_str, hello_len});

    // write(1, world_str, 7) - Linux x64 SYS_write
    auto world_len = builder.get_int32(7);
    builder.create_syscall(1, {fd_val, world_str, world_len});

    // exit(42) - Linux x64 SYS_exit
    auto exit_code = builder.get_int32(42);
    builder.create_syscall(60, {exit_code});

    std::cout << "📋 Module created with:" << std::endl;
    std::cout << "  • Global string: 'Hello, ELF Debug!\\n' (19 chars)" << std::endl;
    std::cout << "  • Global string: 'World!\\n' (7 chars)" << std::endl;
    std::cout << "  • _start function with 3 syscalls" << std::endl;

    // Try to create backends and generate executables
    auto x64_backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::LINUX);
    auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);

    if (x64_backend) {
        std::cout << "📋 Generating x64 ELF executable..." << std::endl;
        if (x64_backend->compile_module(*module)) {
            if (x64_backend->write_executable("elf_debug_x64_direct", "_start")) {
                std::cout << "✅ x64 ELF executable generated: elf_debug_x64_direct" << std::endl;
            }
        }
    }

    if (arm64_backend) {
        std::cout << "📋 Generating ARM64 ELF executable..." << std::endl;
        if (arm64_backend->compile_module(*module)) {
            if (arm64_backend->write_executable("elf_debug_arm64_direct", "_start")) {
                std::cout << "✅ ARM64 ELF executable generated: elf_debug_arm64_direct" << std::endl;
            }
        }
    }

    std::cout << "🎉 ELF executable generation completed!" << std::endl;
    return 0;
}

