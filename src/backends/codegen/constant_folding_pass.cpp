#include "backends/codegen/optimization_passes.h"
#include <iostream>
#include <cassert>

namespace CodeGen {

bool ConstantFoldingPass::run(IR::Module& module) {
    bool modified = false;
    
    std::cout << "  🔍 Constant Folding Pass: Analyzing " << module.functions.size() << " functions\n";
    
    for (auto& function : module.functions) {
        for (auto& block : function->basic_blocks) {
            std::cout << "    📍 Basic Block: " << block->name << " (" << block->instructions.size() << " instructions)\n";
            
            // Process instructions and fold constants
            for (size_t i = 0; i < block->instructions.size(); ++i) {
                auto& inst = block->instructions[i];
                std::shared_ptr<IR::Value> folded_value = nullptr;
                
                // Try to fold different types of operations
                switch (inst->opcode) {
                    case IR::Opcode::ADD:
                    case IR::Opcode::SUB:
                    case IR::Opcode::MUL:
                    case IR::Opcode::UDIV:
                    case IR::Opcode::SDIV:
                    case IR::Opcode::UREM:
                    case IR::Opcode::SREM:
                    case IR::Opcode::AND:
                    case IR::Opcode::OR:
                    case IR::Opcode::XOR:
                    case IR::Opcode::SHL:
                    case IR::Opcode::LSHR:
                    case IR::Opcode::ASHR:
                        if (inst->operands.size() >= 2) {
                            folded_value = try_fold_binary_op(inst->opcode, inst->operands[0], inst->operands[1]);
                        }
                        break;
                        
                    case IR::Opcode::ICMP_EQ:
                    case IR::Opcode::ICMP_NE:
                    case IR::Opcode::ICMP_ULT:
                    case IR::Opcode::ICMP_ULE:
                    case IR::Opcode::ICMP_UGT:
                    case IR::Opcode::ICMP_UGE:
                    case IR::Opcode::ICMP_SLT:
                    case IR::Opcode::ICMP_SLE:
                    case IR::Opcode::ICMP_SGT:
                    case IR::Opcode::ICMP_SGE:
                        if (inst->operands.size() >= 2) {
                            folded_value = try_fold_comparison(inst->opcode, inst->operands[0], inst->operands[1]);
                        }
                        break;
                        
                    case IR::Opcode::TRUNC:
                    case IR::Opcode::ZEXT:
                    case IR::Opcode::SEXT:
                    case IR::Opcode::BITCAST:
                        if (inst->operands.size() >= 1) {
                            folded_value = try_fold_conversion(inst->opcode, inst->operands[0]);
                        }
                        break;
                        
                    default:
                        break;
                }
                
                // If we successfully folded, replace the instruction
                if (folded_value) {
                    std::cout << "      🔧 Folded instruction " << static_cast<int>(inst->opcode) << " to constant\n";
                    
                    // Replace the instruction's result register with the folded constant
                    if (inst->result_reg) {
                        // Create a mapping from the old register to the new constant
                        // This is a simplified approach - in a real implementation, you'd need
                        // to update all uses of the register to use the constant instead
                        inst->result_reg = std::static_pointer_cast<IR::Register>(folded_value);
                    }
                    
                    modified = true;
                }
            }
        }
    }
    
    if (modified) {
        mark_modified();
        std::cout << "  ✅ Constant folding pass completed with modifications\n";
    } else {
        std::cout << "  ⚪ Constant folding pass completed - no changes needed\n";
    }
    
    return modified;
}

std::shared_ptr<IR::Value> ConstantFoldingPass::try_fold_binary_op(
    IR::Opcode opcode,
    std::shared_ptr<IR::Value> lhs,
    std::shared_ptr<IR::Value> rhs) {
    
    if (!is_constant(lhs) || !is_constant(rhs)) {
        return nullptr;
    }
    
    int64_t lhs_val = get_constant_value(lhs);
    int64_t rhs_val = get_constant_value(rhs);
    int64_t result = 0;
    
    switch (opcode) {
        case IR::Opcode::ADD:
            result = lhs_val + rhs_val;
            break;
        case IR::Opcode::SUB:
            result = lhs_val - rhs_val;
            break;
        case IR::Opcode::MUL:
            result = lhs_val * rhs_val;
            break;
        case IR::Opcode::SDIV:
            if (rhs_val == 0) return nullptr; // Division by zero
            result = lhs_val / rhs_val;
            break;
        case IR::Opcode::UDIV:
            if (rhs_val == 0) return nullptr; // Division by zero
            result = static_cast<uint64_t>(lhs_val) / static_cast<uint64_t>(rhs_val);
            break;
        case IR::Opcode::SREM:
            if (rhs_val == 0) return nullptr; // Modulo by zero
            result = lhs_val % rhs_val;
            break;
        case IR::Opcode::UREM:
            if (rhs_val == 0) return nullptr; // Modulo by zero
            result = static_cast<uint64_t>(lhs_val) % static_cast<uint64_t>(rhs_val);
            break;
        case IR::Opcode::AND:
            result = lhs_val & rhs_val;
            break;
        case IR::Opcode::OR:
            result = lhs_val | rhs_val;
            break;
        case IR::Opcode::XOR:
            result = lhs_val ^ rhs_val;
            break;
        case IR::Opcode::SHL:
            result = lhs_val << rhs_val;
            break;
        case IR::Opcode::LSHR:
            result = static_cast<uint64_t>(lhs_val) >> rhs_val;
            break;
        case IR::Opcode::ASHR:
            result = lhs_val >> rhs_val;
            break;
        default:
            return nullptr;
    }
    
    // Create a new constant with the folded result
    return std::make_shared<IR::ConstantInt>(lhs->type, result);
}

std::shared_ptr<IR::Value> ConstantFoldingPass::try_fold_comparison(
    IR::Opcode opcode,
    std::shared_ptr<IR::Value> lhs,
    std::shared_ptr<IR::Value> rhs) {
    
    if (!is_constant(lhs) || !is_constant(rhs)) {
        return nullptr;
    }
    
    int64_t lhs_val = get_constant_value(lhs);
    int64_t rhs_val = get_constant_value(rhs);
    bool result = false;
    
    switch (opcode) {
        case IR::Opcode::ICMP_EQ:
            result = (lhs_val == rhs_val);
            break;
        case IR::Opcode::ICMP_NE:
            result = (lhs_val != rhs_val);
            break;
        case IR::Opcode::ICMP_SLT:
            result = (lhs_val < rhs_val);
            break;
        case IR::Opcode::ICMP_SLE:
            result = (lhs_val <= rhs_val);
            break;
        case IR::Opcode::ICMP_SGT:
            result = (lhs_val > rhs_val);
            break;
        case IR::Opcode::ICMP_SGE:
            result = (lhs_val >= rhs_val);
            break;
        case IR::Opcode::ICMP_ULT:
            result = (static_cast<uint64_t>(lhs_val) < static_cast<uint64_t>(rhs_val));
            break;
        case IR::Opcode::ICMP_ULE:
            result = (static_cast<uint64_t>(lhs_val) <= static_cast<uint64_t>(rhs_val));
            break;
        case IR::Opcode::ICMP_UGT:
            result = (static_cast<uint64_t>(lhs_val) > static_cast<uint64_t>(rhs_val));
            break;
        case IR::Opcode::ICMP_UGE:
            result = (static_cast<uint64_t>(lhs_val) >= static_cast<uint64_t>(rhs_val));
            break;
        default:
            return nullptr;
    }
    
    // Create a new boolean constant
    return std::make_shared<IR::ConstantInt>(IR::Type::i1(), result ? 1 : 0);
}

std::shared_ptr<IR::Value> ConstantFoldingPass::try_fold_conversion(
    IR::Opcode opcode,
    std::shared_ptr<IR::Value> operand) {
    
    if (!is_constant(operand)) {
        return nullptr;
    }
    
    int64_t val = get_constant_value(operand);
    
    switch (opcode) {
        case IR::Opcode::TRUNC:
            // Truncate to smaller integer type
            // For now, just return the same value
            return std::make_shared<IR::ConstantInt>(operand->type, val);
        case IR::Opcode::ZEXT:
            // Zero extend - upper bits are already zero
            return std::make_shared<IR::ConstantInt>(operand->type, val);
        case IR::Opcode::SEXT:
            // Sign extend - handled by the type system
            return std::make_shared<IR::ConstantInt>(operand->type, val);
        case IR::Opcode::BITCAST:
            // Bitcast is just a type change
            return std::make_shared<IR::ConstantInt>(operand->type, val);
        default:
            return nullptr;
    }
}

bool ConstantFoldingPass::is_constant(const std::shared_ptr<IR::Value>& value) const {
    return value->kind == IR::Value::Kind::CONSTANT;
}

int64_t ConstantFoldingPass::get_constant_value(const std::shared_ptr<IR::Value>& value) const {
    assert(value->kind == IR::Value::Kind::CONSTANT);
    auto constant = std::static_pointer_cast<IR::ConstantInt>(value);
    return constant->value;
}

} // namespace CodeGen
