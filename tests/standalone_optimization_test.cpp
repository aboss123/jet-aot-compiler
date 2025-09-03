#include <iostream>
#include <chrono>
#include "core/ir/ir.h"
#include "backends/codegen/optimization_passes.h"

using namespace IR;
using namespace CodeGen;

void test_constant_folding_pass() {
    std::cout << "Testing ConstantFoldingPass..." << std::endl;
    
    // Create a function with constant operations
    Module module("test_constant_folding");
    Function* func = module.create_function("const_ops", Type::i64(), {});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    // Create constants and operations that can be folded
    auto const5 = builder.get_int64(5);
    auto const10 = builder.get_int64(10);
    auto sum = builder.create_add(const5, const10);  // Should fold to 15
    builder.create_ret(sum);
    
    // Apply constant folding pass
    ConstantFoldingPass pass;
    bool modified = pass.run(module);
    
    std::cout << "ConstantFoldingPass result: " << (modified ? "MODIFIED" : "NO CHANGES") << std::endl;
}

void test_dead_code_elimination_pass() {
    std::cout << "Testing DeadCodeEliminationPass..." << std::endl;
    
    // Create a function with unused operations
    Module module("test_dce");
    Function* func = module.create_function("dead_code", Type::i64(), {Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto input = func->arguments[0];
    
    // Create a dead operation (result not used)
    auto dead_result = builder.create_mul(input, builder.get_int64(42));
    
    // Create the actual return value
    auto live_result = builder.create_add(input, builder.get_int64(1));
    builder.create_ret(live_result);
    
    // Apply dead code elimination pass
    DeadCodeEliminationPass pass;
    bool modified = pass.run(module);
    
    std::cout << "DeadCodeEliminationPass result: " << (modified ? "MODIFIED" : "NO CHANGES") << std::endl;
}

void test_instruction_scheduling_pass() {
    std::cout << "Testing InstructionSchedulingPass..." << std::endl;
    
    // Create a function with dependent operations
    Module module("test_scheduling");
    Function* func = module.create_function("scheduling_test", Type::i64(), {Type::i64(), Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto a = func->arguments[0];
    auto b = func->arguments[1];
    
    // Create operations with dependencies
    auto sum = builder.create_add(a, b);
    auto product = builder.create_mul(sum, a);  // Depends on sum
    auto final_result = builder.create_add(product, b);
    builder.create_ret(final_result);
    
    // Apply instruction scheduling pass
    InstructionSchedulingPass pass;
    bool modified = pass.run(module);
    
    std::cout << "InstructionSchedulingPass result: " << (modified ? "MODIFIED" : "NO CHANGES") << std::endl;
}

void test_optimization_pass_manager() {
    std::cout << "Testing OptimizationPassManager..." << std::endl;
    
    // Create a function that benefits from multiple optimizations
    Module module("test_pass_manager");
    Function* func = module.create_function("multi_opt", Type::i64(), {Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto input = func->arguments[0];
    
    // Constant operations (for folding)
    auto const1 = builder.get_int64(10);
    auto const2 = builder.get_int64(20);
    auto const_sum = builder.create_add(const1, const2);
    
    // Dead code
    auto dead_op = builder.create_mul(input, builder.get_int64(999));
    
    // Live operations with dependencies (for scheduling)
    auto live_sum = builder.create_add(input, const_sum);
    auto final_result = builder.create_mul(live_sum, builder.get_int64(2));
    builder.create_ret(final_result);
    
    // Create pass manager and add all passes
    OptimizationPassManager optimizer;
    optimizer.add_pass(std::make_unique<ConstantFoldingPass>());
    optimizer.add_pass(std::make_unique<DeadCodeEliminationPass>());
    optimizer.add_pass(std::make_unique<InstructionSchedulingPass>());
    
    // Run all passes
    bool any_modified = optimizer.run_passes(module);
    
    std::cout << "OptimizationPassManager result: " << (any_modified ? "MODIFIED" : "NO CHANGES") << std::endl;
    
    // Check that all passes ran
    auto results = optimizer.get_pass_results();
    std::cout << "Pass results count: " << results.size() << std::endl;
}


int main() {
    std::cout << "=== Standalone Optimization Tests ===" << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        test_constant_folding_pass();
        std::cout << std::endl;
        
        test_dead_code_elimination_pass();
        std::cout << std::endl;
        
        test_instruction_scheduling_pass();
        std::cout << std::endl;
        
        test_optimization_pass_manager();
        std::cout << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "=== All tests completed in " << duration.count() << "ms ===" << std::endl;
    return 0;
}