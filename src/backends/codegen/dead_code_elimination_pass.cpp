#include "backends/codegen/optimization_passes.h"
#include <iostream>
#include <queue>

namespace CodeGen {

bool DeadCodeEliminationPass::run(IR::Module& module) {
    bool modified = false;
    
    std::cout << "  🗑️ Dead Code Elimination Pass: Analyzing " << module.functions.size() << " functions\n";
    
    for (auto& function : module.functions) {
        std::cout << "    📍 Function: " << function->name << "\n";
        
        // Find all reachable instructions
        std::unordered_set<uint32_t> reachable;
        find_reachable_instructions(*function, reachable);
        
        // Remove dead instructions from each basic block
        for (auto& block : function->basic_blocks) {
            std::cout << "      📍 Basic Block: " << block->name << " (" << block->instructions.size() << " instructions)\n";
            
            // Create new instruction list with only reachable instructions
            std::vector<std::unique_ptr<IR::Instruction>> new_instructions;
            size_t removed_count = 0;
            
            for (auto& inst : block->instructions) {
                bool is_reachable = false;
                
                // Check if this instruction is reachable
                if (inst->result_reg && reachable.find(inst->result_reg->id) != reachable.end()) {
                    is_reachable = true;
                }
                
                // Always keep instructions with side effects
                if (has_side_effects(inst)) {
                    is_reachable = true;
                }
                
                if (is_reachable) {
                    new_instructions.push_back(std::move(inst));
                } else {
                    std::cout << "        🗑️ Removing dead instruction: " << static_cast<int>(inst->opcode) << "\n";
                    removed_count++;
                    modified = true;
                }
            }
            
            // Replace the instruction list
            block->instructions = std::move(new_instructions);
            
            if (removed_count > 0) {
                std::cout << "        ✅ Removed " << removed_count << " dead instructions\n";
            }
        }
    }
    
    if (modified) {
        mark_modified();
        std::cout << "  ✅ Dead code elimination pass completed with modifications\n";
    } else {
        std::cout << "  ⚪ Dead code elimination pass completed - no changes needed\n";
    }
    
    return modified;
}

void DeadCodeEliminationPass::find_reachable_instructions(
    IR::Function& function,
    std::unordered_set<uint32_t>& reachable) {
    
    // Start from entry point and follow all uses
    std::queue<uint32_t> worklist;
    
    // Add all function arguments to worklist
    for (const auto& arg : function.arguments) {
        worklist.push(arg->id);
        reachable.insert(arg->id);
    }
    
    // Add all return values and control flow instructions
    for (const auto& block : function.basic_blocks) {
        for (const auto& inst : block->instructions) {
            // Add instructions with side effects
            if (has_side_effects(inst)) {
                if (inst->result_reg) {
                    worklist.push(inst->result_reg->id);
                    reachable.insert(inst->result_reg->id);
                }
            }
            
            // Add operands of control flow instructions
            if (inst->opcode == IR::Opcode::BR_COND) {
                for (const auto& operand : inst->operands) {
                    if (operand->kind == IR::Value::Kind::REGISTER) {
                        auto reg = std::static_pointer_cast<IR::Register>(operand);
                        worklist.push(reg->id);
                        reachable.insert(reg->id);
                    }
                }
            }
        }
    }
    
    // Follow all uses of reachable values
    while (!worklist.empty()) {
        uint32_t current_id = worklist.front();
        worklist.pop();
        
        // Find all instructions that use this value
        for (const auto& block : function.basic_blocks) {
            for (const auto& inst : block->instructions) {
                for (const auto& operand : inst->operands) {
                    if (operand->kind == IR::Value::Kind::REGISTER) {
                        auto reg = std::static_pointer_cast<IR::Register>(operand);
                        if (reg->id == current_id) {
                            // This instruction uses the current value
                            if (inst->result_reg && reachable.find(inst->result_reg->id) == reachable.end()) {
                                worklist.push(inst->result_reg->id);
                                reachable.insert(inst->result_reg->id);
                            }
                        }
                    }
                }
            }
        }
    }
}

bool DeadCodeEliminationPass::has_side_effects(const std::unique_ptr<IR::Instruction>& inst) const {
    // Instructions that have side effects should not be eliminated
    switch (inst->opcode) {
        case IR::Opcode::CALL:
        case IR::Opcode::RET:
        case IR::Opcode::BR:
        case IR::Opcode::BR_COND:
        case IR::Opcode::STORE:
        case IR::Opcode::LOAD:
            return true;
        default:
            return false;
    }
}

} // namespace CodeGen
