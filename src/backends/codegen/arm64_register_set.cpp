#include "arm64_register_set.h"
#include <algorithm>
#include <stdexcept>

namespace CodeGen {

ARM64RegisterSet::ARM64RegisterSet() {
    initialize_register_sets();
    
    // Reserve special registers that shouldn't be allocated
    reserve_register(get_stack_pointer());
    reserve_register(get_link_register());
    reserve_register(get_zero_register());
}

void ARM64RegisterSet::initialize_register_sets() {
    // General purpose registers (64-bit)
    // Caller-saved registers first (more efficient for temporary values)
    general_purpose_regs_ = {
        Register(0, "x0", RegisterClass::GENERAL_PURPOSE),    // Return value, 1st argument, caller-saved
        Register(1, "x1", RegisterClass::GENERAL_PURPOSE),    // 2nd argument, caller-saved
        Register(2, "x2", RegisterClass::GENERAL_PURPOSE),    // 3rd argument, caller-saved
        Register(3, "x3", RegisterClass::GENERAL_PURPOSE),    // 4th argument, caller-saved
        Register(4, "x4", RegisterClass::GENERAL_PURPOSE),    // 5th argument, caller-saved
        Register(5, "x5", RegisterClass::GENERAL_PURPOSE),    // 6th argument, caller-saved
        Register(6, "x6", RegisterClass::GENERAL_PURPOSE),    // 7th argument, caller-saved
        Register(7, "x7", RegisterClass::GENERAL_PURPOSE),    // 8th argument, caller-saved
        Register(8, "x8", RegisterClass::GENERAL_PURPOSE),    // Caller-saved
        Register(9, "x9", RegisterClass::GENERAL_PURPOSE),    // Caller-saved
        Register(10, "x10", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(11, "x11", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(12, "x12", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(13, "x13", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(14, "x14", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(15, "x15", RegisterClass::GENERAL_PURPOSE),  // Caller-saved
        Register(16, "x16", RegisterClass::GENERAL_PURPOSE),  // IP0, caller-saved
        Register(17, "x17", RegisterClass::GENERAL_PURPOSE),  // IP1, caller-saved
        Register(18, "x18", RegisterClass::GENERAL_PURPOSE),  // Platform register, caller-saved
        Register(19, "x19", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(20, "x20", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(21, "x21", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(22, "x22", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(23, "x23", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(24, "x24", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(25, "x25", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(26, "x26", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(27, "x27", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(28, "x28", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(29, "x29", RegisterClass::GENERAL_PURPOSE),  // Frame pointer, callee-saved
        Register(30, "x30", RegisterClass::GENERAL_PURPOSE)   // Link register, callee-saved
    };
    
    // Floating point registers (128-bit)
    floating_point_regs_ = {
        Register(100, "v0", RegisterClass::FLOATING_POINT),    // 1st FP argument, caller-saved
        Register(101, "v1", RegisterClass::FLOATING_POINT),    // 2nd FP argument, caller-saved
        Register(102, "v2", RegisterClass::FLOATING_POINT),    // 3rd FP argument, caller-saved
        Register(103, "v3", RegisterClass::FLOATING_POINT),    // 4th FP argument, caller-saved
        Register(104, "v4", RegisterClass::FLOATING_POINT),    // 5th FP argument, caller-saved
        Register(105, "v5", RegisterClass::FLOATING_POINT),    // 6th FP argument, caller-saved
        Register(106, "v6", RegisterClass::FLOATING_POINT),    // 7th FP argument, caller-saved
        Register(107, "v7", RegisterClass::FLOATING_POINT),    // 8th FP argument, caller-saved
        Register(108, "v8", RegisterClass::FLOATING_POINT),    // Callee-saved
        Register(109, "v9", RegisterClass::FLOATING_POINT),    // Callee-saved
        Register(110, "v10", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(111, "v11", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(112, "v12", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(113, "v13", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(114, "v14", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(115, "v15", RegisterClass::FLOATING_POINT),   // Callee-saved
        Register(116, "v16", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(117, "v17", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(118, "v18", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(119, "v19", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(120, "v20", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(121, "v21", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(122, "v22", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(123, "v23", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(124, "v24", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(125, "v25", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(126, "v26", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(127, "v27", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(128, "v28", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(129, "v29", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(130, "v30", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(131, "v31", RegisterClass::FLOATING_POINT)   // Caller-saved
    };
    
    // Vector registers (same as floating point in ARM64)
    vector_regs_ = floating_point_regs_;
    
    // Special registers
    special_regs_ = {
        Register(300, "sp", RegisterClass::SPECIAL),    // Stack pointer
        Register(301, "lr", RegisterClass::SPECIAL),    // Link register
        Register(302, "xzr", RegisterClass::SPECIAL)    // Zero register
    };
}

std::vector<Register> ARM64RegisterSet::get_registers(RegisterClass reg_class) const {
    switch (reg_class) {
        case RegisterClass::GENERAL_PURPOSE:
            return general_purpose_regs_;
        case RegisterClass::FLOATING_POINT:
            return floating_point_regs_;
        case RegisterClass::VECTOR:
            return vector_regs_;
        case RegisterClass::SPECIAL:
            return special_regs_;
        default:
            return {};
    }
}

size_t ARM64RegisterSet::get_register_count(RegisterClass reg_class) const {
    switch (reg_class) {
        case RegisterClass::GENERAL_PURPOSE:
            return general_purpose_regs_.size();
        case RegisterClass::FLOATING_POINT:
            return floating_point_regs_.size();
        case RegisterClass::VECTOR:
            return vector_regs_.size();
        case RegisterClass::SPECIAL:
            return special_regs_.size();
        default:
            return 0;
    }
}

bool ARM64RegisterSet::is_register_available(const Register& reg) const {
    // Check if the register is reserved
    if (is_reserved(reg)) {
        return false;
    }
    
    // Check if the register exists in our sets
    for (const auto& reg_set : {general_purpose_regs_, floating_point_regs_, vector_regs_}) {
        for (const auto& available_reg : reg_set) {
            if (available_reg.id() == reg.id()) {
                return true;
            }
        }
    }
    
    return false;
}

std::string ARM64RegisterSet::get_architecture_name() const {
    return "ARM64";
}

std::vector<Register> ARM64RegisterSet::get_preferred_order(RegisterClass reg_class) const {
    switch (reg_class) {
        case RegisterClass::GENERAL_PURPOSE:
            // Return registers in preferred allocation order
            // Caller-saved first (more efficient), then callee-saved
            return general_purpose_regs_;
            
        case RegisterClass::FLOATING_POINT:
            // Return vector registers in preferred order
            return floating_point_regs_;
            
        case RegisterClass::VECTOR:
            // Return vector registers in preferred order
            return vector_regs_;
            
        case RegisterClass::SPECIAL:
            // Special registers are not preferred for allocation
            return {};
            
        default:
            return {};
    }
}

void ARM64RegisterSet::reserve_register(const Register& reg) {
    reserved_registers_.insert(reg);
}

void ARM64RegisterSet::unreserve_register(const Register& reg) {
    reserved_registers_.erase(reg);
}

bool ARM64RegisterSet::is_reserved(const Register& reg) const {
    return reserved_registers_.find(reg) != reserved_registers_.end();
}

Register ARM64RegisterSet::get_stack_pointer() const {
    return Register(300, "sp", RegisterClass::SPECIAL);
}

Register ARM64RegisterSet::get_link_register() const {
    return Register(301, "lr", RegisterClass::SPECIAL);
}

Register ARM64RegisterSet::get_zero_register() const {
    return Register(302, "xzr", RegisterClass::SPECIAL);
}

Register ARM64RegisterSet::get_return_value_register() const {
    return Register(0, "x0", RegisterClass::GENERAL_PURPOSE);
}

std::vector<Register> ARM64RegisterSet::get_caller_saved_registers() const {
    // Return caller-saved registers (first 18 general purpose registers)
    return std::vector<Register>(general_purpose_regs_.begin(), general_purpose_regs_.begin() + 18);
}

std::vector<Register> ARM64RegisterSet::get_callee_saved_registers() const {
    // Return callee-saved registers (last 12 general purpose registers)
    return std::vector<Register>(general_purpose_regs_.begin() + 18, general_purpose_regs_.end());
}

std::vector<Register> ARM64RegisterSet::get_argument_registers() const {
    // Return argument registers (first 8 general purpose registers)
    return std::vector<Register>(general_purpose_regs_.begin(), general_purpose_regs_.begin() + 8);
}

} // namespace CodeGen
