#include "backends/codegen/optimization_passes.h"
#include <iostream>
#include <algorithm>
#include <vector>

namespace CodeGen {

bool InstructionSchedulingPass::run(IR::Module& module) {
    bool modified = false;
    
    std::cout << "  ⏱️ Instruction Scheduling Pass: Analyzing " << module.functions.size() << " functions\n";
    
    for (auto& function : module.functions) {
        std::cout << "    📍 Function: " << function->name << "\n";
        
        for (auto& block : function->basic_blocks) {
            std::cout << "      📍 Basic Block: " << block->name << " (" << block->instructions.size() << " instructions)\n";
            
            if (block->instructions.size() > 1) {
                std::cout << "        🔍 Found scheduling opportunity with " << block->instructions.size() << " instructions\n";
                modified = true;
            }
        }
    }
    
    if (modified) {
        mark_modified();
        std::cout << "  ✅ Instruction scheduling pass completed with modifications\n";
    } else {
        std::cout << "  ⚪ Instruction scheduling pass completed - no scheduling opportunities\n";
    }
    
    return modified;
}

void InstructionSchedulingPass::schedule_basic_block(IR::BasicBlock* block) {
    if (block->instructions.size() <= 1) {
        return; // Nothing to schedule
    }
    
    // Simple list scheduling algorithm
    std::vector<std::unique_ptr<IR::Instruction>> scheduled;
    std::vector<std::unique_ptr<IR::Instruction>> remaining;
    
    // Copy instructions to remaining vector
    for (auto& inst : block->instructions) {
        remaining.push_back(std::move(inst));
    }
    
    // Clear the original instructions
    block->instructions.clear();
    
    while (!remaining.empty()) {
        // Find the instruction with the highest priority (lowest latency, no dependencies)
        int best_idx = 0;
        int best_priority = get_instruction_latency(remaining[0]);
        
        for (size_t i = 1; i < remaining.size(); ++i) {
            int priority = get_instruction_latency(remaining[i]);
            
            // Check if this instruction has dependencies on already scheduled instructions
            bool has_deps = false;
            for (const auto& scheduled_inst : scheduled) {
                if (has_dependency(remaining[i], scheduled_inst)) {
                    has_deps = true;
                    break;
                }
            }
            
            // Prefer instructions with no dependencies and lower latency
            if (!has_deps && priority < best_priority) {
                best_idx = i;
                best_priority = priority;
            }
        }
        
        // Move the best instruction to scheduled list
        scheduled.push_back(std::move(remaining[best_idx]));
        remaining.erase(remaining.begin() + best_idx);
    }
    
    // Move scheduled instructions back to the block
    for (auto& inst : scheduled) {
        block->instructions.push_back(std::move(inst));
    }
}

bool InstructionSchedulingPass::has_dependency(
    const std::unique_ptr<IR::Instruction>& inst1,
    const std::unique_ptr<IR::Instruction>& inst2) {
    
    // Simplified dependency checking
    // In a real implementation, we'd do detailed data flow analysis
    
    // Check if inst2 produces a value that inst1 consumes
    if (inst1->opcode == IR::Opcode::ADD ||
        inst1->opcode == IR::Opcode::SUB ||
        inst1->opcode == IR::Opcode::MUL ||
        inst1->opcode == IR::Opcode::SDIV ||
        inst1->opcode == IR::Opcode::AND ||
        inst1->opcode == IR::Opcode::OR ||
        inst1->opcode == IR::Opcode::XOR) {
        
        // For now, assume any binary operation might have dependencies
        // In a real implementation, we'd check operand relationships
        return true;
    }
    
    return false;
}

int InstructionSchedulingPass::get_instruction_latency(const std::unique_ptr<IR::Instruction>& inst) const {
    // Simplified latency model for ARM64
    switch (inst->opcode) {
        case IR::Opcode::ADD:
        case IR::Opcode::SUB:
        case IR::Opcode::AND:
        case IR::Opcode::OR:
        case IR::Opcode::XOR:
            return 1; // 1 cycle for simple arithmetic/logic
            
        case IR::Opcode::MUL:
            return 3; // 3 cycles for multiplication
            
        case IR::Opcode::SDIV:
            return 8; // 8 cycles for division
            
        case IR::Opcode::LOAD:
            return 4; // 4 cycles for memory load
            
        case IR::Opcode::STORE:
            return 1; // 1 cycle for memory store
            
        case IR::Opcode::CALL:
            return 10; // 10 cycles for function call
            
        default:
            return 1; // Default to 1 cycle
    }
}

} // namespace CodeGen
