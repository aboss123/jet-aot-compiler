#pragma once

#include "core/ir/ir.h"
#include <memory>
#include <vector>
#include <unordered_set>

namespace CodeGen {

// Forward declarations
class OptimizationPass;
class OptimizationPassManager;

// Base class for all optimization passes
class OptimizationPass {
public:
    virtual ~OptimizationPass() = default;
    
    // Run the optimization pass on a module
    virtual bool run(IR::Module& module) = 0;
    
    // Get the name of this pass
    virtual std::string get_name() const = 0;
    
    // Check if this pass modified the IR
    bool modified_ir() const { return modified_; }
    
protected:
    void mark_modified() { modified_ = true; }
    
private:
    bool modified_ = false;
};

// Constant folding optimization pass
class ConstantFoldingPass : public OptimizationPass {
public:
    bool run(IR::Module& module) override;
    std::string get_name() const override { return "ConstantFolding"; }
    
private:
    // Try to fold a binary operation with constant operands
    std::shared_ptr<IR::Value> try_fold_binary_op(
        IR::Opcode opcode,
        std::shared_ptr<IR::Value> lhs,
        std::shared_ptr<IR::Value> rhs
    );
    
    // Try to fold a comparison operation with constant operands
    std::shared_ptr<IR::Value> try_fold_comparison(
        IR::Opcode opcode,
        std::shared_ptr<IR::Value> lhs,
        std::shared_ptr<IR::Value> rhs
    );
    
    // Try to fold a type conversion operation with constant operand
    std::shared_ptr<IR::Value> try_fold_conversion(
        IR::Opcode opcode,
        std::shared_ptr<IR::Value> operand
    );
    
    // Check if a value is a constant
    bool is_constant(const std::shared_ptr<IR::Value>& value) const;
    
    // Get constant value from a constant value
    int64_t get_constant_value(const std::shared_ptr<IR::Value>& value) const;
};

// Dead code elimination pass
class DeadCodeEliminationPass : public OptimizationPass {
public:
    bool run(IR::Module& module) override;
    std::string get_name() const override { return "DeadCodeElimination"; }
    
private:
    // Find all reachable instructions from entry points
    void find_reachable_instructions(
        IR::Function& function,
        std::unordered_set<uint32_t>& reachable
    );
    
    // Check if an instruction has side effects
    bool has_side_effects(const std::unique_ptr<IR::Instruction>& inst) const;
};

// Basic instruction scheduling pass
class InstructionSchedulingPass : public OptimizationPass {
public:
    bool run(IR::Module& module) override;
    std::string get_name() const override { return "InstructionScheduling"; }
    
private:
    // Reorder instructions within a basic block for better scheduling
    void schedule_basic_block(IR::BasicBlock* block);
    
    // Check if an instruction depends on another
    bool has_dependency(
        const std::unique_ptr<IR::Instruction>& inst1,
        const std::unique_ptr<IR::Instruction>& inst2
    );
    
    // Get instruction latency (simplified model)
    int get_instruction_latency(const std::unique_ptr<IR::Instruction>& inst) const;
};

// Peephole optimization pass
class PeepholeOptimizationPass : public OptimizationPass {
public:
    bool run(IR::Module& module) override;
    std::string get_name() const override { return "PeepholeOptimization"; }
    
private:
    // Apply peephole optimizations to a basic block
    bool optimize_basic_block(IR::BasicBlock* block);
    
    // Check if a value is a constant
    bool is_constant(const std::shared_ptr<IR::Value>& value) const;
    
    // Get constant value from a constant value
    int64_t get_constant_value(const std::shared_ptr<IR::Value>& value) const;
};

// Optimization pass manager
class OptimizationPassManager {
public:
    // Add an optimization pass
    void add_pass(std::unique_ptr<OptimizationPass> pass);
    
    // Run all passes on a module
    bool run_passes(IR::Module& module);
    
    // Get statistics about the optimization run
    const std::vector<std::string>& get_pass_results() const { return pass_results_; }
    
private:
    std::vector<std::unique_ptr<OptimizationPass>> passes_;
    std::vector<std::string> pass_results_;
};

} // namespace CodeGen
