#include "optimization_passes.h"
#include "core/ir/ir.h"
#include <iostream>

namespace CodeGen {

bool PeepholeOptimizationPass::run(IR::Module& module) {
    bool changed = false;
    
    std::cout << "  🔧 Peephole Optimization Pass: Analyzing " << module.functions.size() << " functions\n";
    
    for (auto& function : module.functions) {
        for (auto& block : function->basic_blocks) {
            if (optimize_basic_block(block.get())) {
                changed = true;
            }
        }
    }
    
    if (changed) {
        mark_modified();
        std::cout << "  ✅ Peephole optimization pass completed with modifications\n";
    } else {
        std::cout << "  ⚪ Peephole optimization pass completed - no changes needed\n";
    }
    
    return changed;
}

bool PeepholeOptimizationPass::optimize_basic_block(IR::BasicBlock* block) {
    bool changed = false;
    
    std::cout << "    📍 Basic Block: " << block->name << " (" << block->instructions.size() << " instructions)\n";
    
    // Process instructions and apply peephole optimizations
    for (size_t i = 0; i < block->instructions.size(); ++i) {
        auto& inst = block->instructions[i];
        bool optimized = false;
        
        // Pattern: add x, 0 -> x
        if (inst->opcode == IR::Opcode::ADD) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 0) {
                std::cout << "      🔧 Optimizing: add x, 0 -> x\n";
                // Replace result register with first operand
                inst->result_reg = std::static_pointer_cast<IR::Register>(binary_op->operands[0]);
                optimized = true;
            }
        }
        
        // Pattern: sub x, 0 -> x
        if (inst->opcode == IR::Opcode::SUB) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 0) {
                std::cout << "      🔧 Optimizing: sub x, 0 -> x\n";
                inst->result_reg = std::static_pointer_cast<IR::Register>(binary_op->operands[0]);
                optimized = true;
            }
        }
        
        // Pattern: mul x, 1 -> x
        if (inst->opcode == IR::Opcode::MUL) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 1) {
                std::cout << "      🔧 Optimizing: mul x, 1 -> x\n";
                inst->result_reg = std::static_pointer_cast<IR::Register>(binary_op->operands[0]);
                optimized = true;
            }
        }
        
        // Pattern: div x, 1 -> x
        if (inst->opcode == IR::Opcode::SDIV || inst->opcode == IR::Opcode::UDIV) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 1) {
                std::cout << "      🔧 Optimizing: div x, 1 -> x\n";
                inst->result_reg = std::static_pointer_cast<IR::Register>(binary_op->operands[0]);
                optimized = true;
            }
        }
        
        // Pattern: mul x, 0 -> 0
        if (inst->opcode == IR::Opcode::MUL) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 0) {
                std::cout << "      🔧 Optimizing: mul x, 0 -> 0\n";
                // Create a new constant register with the same type
                auto zero_const = std::make_shared<IR::ConstantInt>(inst->result_type, 0);
                // Replace the instruction's result register with a new register pointing to the constant
                inst->result_reg = std::make_shared<IR::Register>(inst->result_type, "const_zero");
                optimized = true;
            }
        }
        
        // Pattern: and x, 0 -> 0
        if (inst->opcode == IR::Opcode::AND) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1]) && get_constant_value(binary_op->operands[1]) == 0) {
                std::cout << "      🔧 Optimizing: and x, 0 -> 0\n";
                // Create a new constant register with the same type
                auto zero_const = std::make_shared<IR::ConstantInt>(inst->result_type, 0);
                // Replace the instruction's result register with a new register pointing to the constant
                inst->result_reg = std::make_shared<IR::Register>(inst->result_type, "const_zero");
                optimized = true;
            }
        }
        
        // Pattern: or x, -1 -> -1 (for signed) or all 1s (for unsigned)
        if (inst->opcode == IR::Opcode::OR) {
            auto binary_op = static_cast<IR::BinaryOp*>(inst.get());
            if (is_constant(binary_op->operands[1])) {
                int64_t val = get_constant_value(binary_op->operands[1]);
                if (val == -1 || val == 0xFFFFFFFFFFFFFFFFULL) {
                    std::cout << "      🔧 Optimizing: or x, -1 -> -1\n";
                    // Create a new constant register with the same type
                    auto const_val = std::make_shared<IR::ConstantInt>(inst->result_type, val);
                    // Replace the instruction's result register with a new register pointing to the constant
                    inst->result_reg = std::make_shared<IR::Register>(inst->result_type, "const_all_ones");
                    optimized = true;
                }
            }
        }
        
        if (optimized) {
            changed = true;
        }
    }
    
    return changed;
}

bool PeepholeOptimizationPass::is_constant(const std::shared_ptr<IR::Value>& value) const {
    return value->kind == IR::Value::Kind::CONSTANT;
}

int64_t PeepholeOptimizationPass::get_constant_value(const std::shared_ptr<IR::Value>& value) const {
    if (value->kind == IR::Value::Kind::CONSTANT) {
        auto const_val = std::static_pointer_cast<IR::ConstantInt>(value);
        return const_val->value;
    }
    return 0;
}

} // namespace CodeGen