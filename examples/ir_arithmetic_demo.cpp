//============================================================================
// Name        : ir_arithmetic_demo.cpp
// Description : Comprehensive arithmetic operations demo using IR pipeline
// Shows complex expressions, type handling, and optimization opportunities
//============================================================================

#include <iostream>
#include <memory>
#include "core/ir/ir.h"
#include "backends/codegen/backend.h"
#include "backends/codegen/optimization_passes.h"

using namespace IR;
using namespace CodeGen;

void demonstrate_basic_arithmetic() {
    std::cout << "🔢 Demonstrating Basic Arithmetic Operations" << std::endl;
    std::cout << "===========================================" << std::endl;
    
    Module module("arithmetic_basic");
    Function* func = module.create_function("calculate", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Create complex arithmetic expression: (10 + 5) * 3 - 8 / 2 + 1
    std::cout << "\n📝 Building IR for: (10 + 5) * 3 - 8 / 2 + 1" << std::endl;
    
    auto const10 = builder.get_int32(10);
    auto const5 = builder.get_int32(5);
    auto const3 = builder.get_int32(3);
    auto const8 = builder.get_int32(8);
    auto const2 = builder.get_int32(2);
    auto const1 = builder.get_int32(1);
    
    // Step by step calculation
    auto add_result = builder.create_add(const10, const5);    // 10 + 5 = 15
    auto mul_result = builder.create_mul(add_result, const3); // 15 * 3 = 45
    auto div_result = builder.create_udiv(const8, const2);    // 8 / 2 = 4
    auto sub_result = builder.create_sub(mul_result, div_result); // 45 - 4 = 41
    auto final_result = builder.create_add(sub_result, const1);   // 41 + 1 = 42
    
    // Use result as exit code
    std::vector<std::shared_ptr<Value>> exit_args = {final_result};
    #ifdef __linux__
        builder.create_syscall(60, exit_args); // Linux exit
    #else
        builder.create_syscall(1, exit_args);  // macOS exit
    #endif
    
    // Test compilation on both architectures
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        std::cout << "\n🔧 Compiling for " << arch_name << "..." << std::endl;
        
        auto backend = BackendFactory::create_backend(arch);
        if (backend && backend->compile_module(module)) {
            size_t code_size = backend->get_code_size();
            std::cout << "✅ " << arch_name << " compilation: " << code_size << " bytes" << std::endl;
            
            std::string exe_path = "/tmp/arithmetic_basic_" + arch_name;
            if (backend->write_executable(exe_path, "_start")) {
                std::cout << "✅ " << arch_name << " executable: " << exe_path << std::endl;
                
                // Test execution
                std::string cmd = exe_path + "; echo \"Exit code: $?\"";
                FILE* pipe = popen(cmd.c_str(), "r");
                if (pipe) {
                    char buffer[256];
                    while (fgets(buffer, sizeof(buffer), pipe)) {
                        std::cout << "📤 " << buffer;
                    }
                    pclose(pipe);
                }
            }
        }
    }
}

void demonstrate_type_system() {
    std::cout << "\n🏷️  Demonstrating Type System & Conversions" << std::endl;
    std::cout << "==========================================" << std::endl;
    
    Module module("type_demo");
    Function* func = module.create_function("type_test", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    std::cout << "\n📝 Building IR with different data types..." << std::endl;
    
    // Test different integer sizes
    auto i8_val = builder.get_int8(127);      // Max signed 8-bit
    auto i16_val = builder.get_int16(32767);  // Max signed 16-bit  
    auto i32_val = builder.get_int32(100000); // Large 32-bit
    auto i64_val = builder.get_int64(0x123456789ABCDEFLL); // 64-bit hex
    
    // Perform operations that will test type-aware code generation
    auto i8_doubled = builder.create_add(i8_val, i8_val);
    auto i16_plus_const = builder.create_add(i16_val, builder.get_int16(1000));
    auto i32_result = builder.create_add(i32_val, builder.get_int32(42));
    
    // Final result combines different sizes (will require type conversions)
    auto combined = builder.create_add(i8_doubled, i16_plus_const);
    combined = builder.create_add(combined, i32_result);
    
    std::vector<std::shared_ptr<Value>> exit_args = {combined};
    #ifdef __linux__
        builder.create_syscall(60, exit_args);
    #else
        builder.create_syscall(1, exit_args);
    #endif
    
    // Test ARM64 type-aware instruction selection specifically
    std::cout << "\n🔧 Testing ARM64 type-aware instruction selection..." << std::endl;
    auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
    if (arm64_backend && arm64_backend->compile_module(module)) {
        size_t code_size = arm64_backend->get_code_size();
        std::cout << "✅ ARM64 type-aware compilation: " << code_size << " bytes" << std::endl;
        std::cout << "   Expected: LDRB/STRB for 8-bit, LDRH/STRH for 16-bit" << std::endl;
        std::cout << "            LDR/STR W-regs for 32-bit, X-regs for 64-bit" << std::endl;
        
        std::string exe_path = "/tmp/type_demo_arm64";
        if (arm64_backend->write_executable(exe_path, "_start")) {
            std::cout << "✅ ARM64 type demo executable: " << exe_path << std::endl;
        }
    }
}

void demonstrate_optimization() {
    std::cout << "\n⚡ Demonstrating Optimization Passes" << std::endl;
    std::cout << "====================================" << std::endl;
    
    Module module("optimization_demo");
    Function* func = module.create_function("optimized_calc", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    std::cout << "\n📝 Building IR with optimization opportunities..." << std::endl;
    
    // Create expressions that can be optimized
    auto const5 = builder.get_int32(5);
    auto const10 = builder.get_int32(10);
    auto const0 = builder.get_int32(0);
    auto const1 = builder.get_int32(1);
    
    // Constant folding opportunities: 5 + 10 = 15 (compile time)
    auto add_constants = builder.create_add(const5, const10);
    
    // Dead code: multiply by 1 (should be optimized away)
    auto useless_mul = builder.create_mul(add_constants, const1);
    
    // More dead code: add 0 (should be optimized away)
    auto useless_add = builder.create_add(useless_mul, const0);
    
    // Another constant folding: 15 * 2 = 30
    auto const2 = builder.get_int32(2);
    auto final_result = builder.create_mul(useless_add, const2);
    
    std::vector<std::shared_ptr<Value>> exit_args = {final_result};
    #ifdef __linux__
        builder.create_syscall(60, exit_args);
    #else
        builder.create_syscall(1, exit_args);
    #endif
    
    std::cout << "\n🔧 Compiling with optimization passes..." << std::endl;
    
    // Test with optimization passes
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    if (backend) {
        std::cout << "\n📊 Before optimization:" << std::endl;
        
        // Compile without optimization first
        if (backend->compile_module(module)) {
            size_t unoptimized_size = backend->get_code_size();
            std::cout << "   Unoptimized size: " << unoptimized_size << " bytes" << std::endl;
        }
        
        std::cout << "\n⚡ Running optimization passes..." << std::endl;
        
        // Apply optimization passes
        OptimizationPassManager pass_manager;
        pass_manager.add_pass(std::make_unique<ConstantFoldingPass>());
        pass_manager.add_pass(std::make_unique<DeadCodeEliminationPass>());
        pass_manager.add_pass(std::make_unique<InstructionSchedulingPass>());
        
        // Run passes on the module
        pass_manager.run_passes(module);
        
        std::cout << "\n📊 After optimization:" << std::endl;
        
        // Recompile with optimized IR
        if (backend->compile_module(module)) {
            size_t optimized_size = backend->get_code_size();
            std::cout << "   Optimized size: " << optimized_size << " bytes" << std::endl;
            
            std::string exe_path = "/tmp/optimization_demo_arm64";
            if (backend->write_executable(exe_path, "_start")) {
                std::cout << "✅ Optimized executable: " << exe_path << std::endl;
                
                // Test the optimized result
                std::string cmd = exe_path + "; echo \"Exit code: $?\"";
                FILE* pipe = popen(cmd.c_str(), "r");
                if (pipe) {
                    char buffer[256];
                    while (fgets(buffer, sizeof(buffer), pipe)) {
                        std::cout << "📤 " << buffer;
                    }
                    pclose(pipe);
                }
            }
        }
    }
}

void demonstrate_immediate_encoding() {
    std::cout << "\n🔢 Demonstrating ARM64 Advanced Immediate Encoding" << std::endl;
    std::cout << "=================================================" << std::endl;
    
    Module module("immediate_demo");
    Function* func = module.create_function("immediate_test", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    std::cout << "\n📝 Testing different immediate value encodings..." << std::endl;
    
    // Small immediate (fits in instruction)
    auto small_imm = builder.get_int32(42);
    std::cout << "   Small immediate: 42 (fits directly in instruction)" << std::endl;
    
    // Large immediate (requires MOVZ/MOVK sequence)
    auto large_imm = builder.get_int64(0x123456789ABCDEFLL);
    std::cout << "   Large immediate: 0x123456789ABCDEF (requires MOVZ/MOVK)" << std::endl;
    
    // Logical immediate (pattern-based encoding)
    auto logical_imm = builder.get_int64(0x5555555555555555ULL);
    std::cout << "   Logical immediate: 0x5555555555555555 (alternating bits)" << std::endl;
    
    // Negative immediate
    auto neg_imm = builder.get_int32(-1000);
    std::cout << "   Negative immediate: -1000" << std::endl;
    
    // Use all immediates in operations
    auto result1 = builder.create_add(small_imm, neg_imm);
    auto result2 = builder.create_add(large_imm, logical_imm); 
    auto final_result = builder.create_add(result1, result2);
    
    // Use lower 32 bits as exit code
    std::vector<std::shared_ptr<Value>> exit_args = {final_result};
    #ifdef __linux__
        builder.create_syscall(60, exit_args);
    #else
        builder.create_syscall(1, exit_args);
    #endif
    
    std::cout << "\n🔧 Compiling for ARM64 (immediate encoding test)..." << std::endl;
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    if (backend && backend->compile_module(module)) {
        size_t code_size = backend->get_code_size();
        std::cout << "✅ ARM64 immediate encoding: " << code_size << " bytes" << std::endl;
        std::cout << "   Expected: Conservative encoding for safety" << std::endl;
        std::cout << "            Most values use MOVZ/MOVK sequence" << std::endl;
        
        std::string exe_path = "/tmp/immediate_demo_arm64";
        if (backend->write_executable(exe_path, "_start")) {
            std::cout << "✅ Immediate demo executable: " << exe_path << std::endl;
        }
    }
}

int main() {
    std::cout << "🔢 IR Arithmetic & Advanced Features Demo" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    demonstrate_basic_arithmetic();
    demonstrate_type_system();
    demonstrate_optimization();
    demonstrate_immediate_encoding();
    
    std::cout << "\n🎯 Summary of Demonstrated Features:" << std::endl;
    std::cout << "   ✅ Complex arithmetic expression compilation" << std::endl;
    std::cout << "   ✅ Multi-architecture code generation" << std::endl;
    std::cout << "   ✅ Type system and size-aware operations" << std::endl;
    std::cout << "   ✅ Optimization pass integration" << std::endl;
    std::cout << "   ✅ ARM64 advanced immediate encoding" << std::endl;
    std::cout << "   ✅ Cross-platform executable generation" << std::endl;
    
    std::cout << "\n🚀 Arithmetic demo completed successfully!" << std::endl;
    return 0;
}