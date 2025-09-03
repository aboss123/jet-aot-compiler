#include "x64_register_set.h"
#include <algorithm>
#include <stdexcept>

namespace CodeGen {

X64RegisterSet::X64RegisterSet() {
    initialize_register_sets();
    
    // Reserve special registers that shouldn't be allocated
    reserve_register(get_stack_pointer());
    reserve_register(get_base_pointer());
}

void X64RegisterSet::initialize_register_sets() {
    // General purpose registers (64-bit)
    // Caller-saved registers first (more efficient for temporary values)
    general_purpose_regs_ = {
        Register(0, "rax", RegisterClass::GENERAL_PURPOSE),   // Return value, caller-saved
        Register(1, "rcx", RegisterClass::GENERAL_PURPOSE),   // 4th argument, caller-saved
        Register(2, "rdx", RegisterClass::GENERAL_PURPOSE),   // 3rd argument, caller-saved
        Register(3, "rsi", RegisterClass::GENERAL_PURPOSE),   // 2nd argument, caller-saved
        Register(4, "rdi", RegisterClass::GENERAL_PURPOSE),   // 1st argument, caller-saved
        Register(5, "r8", RegisterClass::GENERAL_PURPOSE),    // 5th argument, caller-saved
        Register(6, "r9", RegisterClass::GENERAL_PURPOSE),    // 6th argument, caller-saved
        Register(7, "r10", RegisterClass::GENERAL_PURPOSE),   // Caller-saved
        Register(8, "r11", RegisterClass::GENERAL_PURPOSE),   // Caller-saved
        Register(9, "rbx", RegisterClass::GENERAL_PURPOSE),   // Callee-saved
        Register(10, "r12", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(11, "r13", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(12, "r14", RegisterClass::GENERAL_PURPOSE),  // Callee-saved
        Register(13, "r15", RegisterClass::GENERAL_PURPOSE)   // Callee-saved
    };
    
    // Floating point registers (128-bit XMM)
    floating_point_regs_ = {
        Register(100, "xmm0", RegisterClass::FLOATING_POINT),   // 1st FP argument, caller-saved
        Register(101, "xmm1", RegisterClass::FLOATING_POINT),   // 2nd FP argument, caller-saved
        Register(102, "xmm2", RegisterClass::FLOATING_POINT),   // 3rd FP argument, caller-saved
        Register(103, "xmm3", RegisterClass::FLOATING_POINT),   // 4th FP argument, caller-saved
        Register(104, "xmm4", RegisterClass::FLOATING_POINT),   // 5th FP argument, caller-saved
        Register(105, "xmm5", RegisterClass::FLOATING_POINT),   // 6th FP argument, caller-saved
        Register(106, "xmm6", RegisterClass::FLOATING_POINT),   // 7th FP argument, caller-saved
        Register(107, "xmm7", RegisterClass::FLOATING_POINT),   // 8th FP argument, caller-saved
        Register(108, "xmm8", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(109, "xmm9", RegisterClass::FLOATING_POINT),   // Caller-saved
        Register(110, "xmm10", RegisterClass::FLOATING_POINT),  // Caller-saved
        Register(111, "xmm11", RegisterClass::FLOATING_POINT),  // Caller-saved
        Register(112, "xmm12", RegisterClass::FLOATING_POINT),  // Caller-saved
        Register(113, "xmm13", RegisterClass::FLOATING_POINT),  // Caller-saved
        Register(114, "xmm14", RegisterClass::FLOATING_POINT),  // Caller-saved
        Register(115, "xmm15", RegisterClass::FLOATING_POINT)   // Caller-saved
    };
    
    // Vector registers (256-bit YMM)
    vector_regs_ = {
        Register(200, "ymm0", RegisterClass::VECTOR),   // 1st vector argument, caller-saved
        Register(201, "ymm1", RegisterClass::VECTOR),   // 2nd vector argument, caller-saved
        Register(202, "ymm2", RegisterClass::VECTOR),   // 3rd vector argument, caller-saved
        Register(203, "ymm3", RegisterClass::VECTOR),   // 4th vector argument, caller-saved
        Register(204, "ymm4", RegisterClass::VECTOR),   // 5th vector argument, caller-saved
        Register(205, "ymm5", RegisterClass::VECTOR),   // 6th vector argument, caller-saved
        Register(206, "ymm6", RegisterClass::VECTOR),   // 7th vector argument, caller-saved
        Register(207, "ymm7", RegisterClass::VECTOR),   // 8th vector argument, caller-saved
        Register(208, "ymm8", RegisterClass::VECTOR),   // Caller-saved
        Register(209, "ymm9", RegisterClass::VECTOR),   // Caller-saved
        Register(210, "ymm10", RegisterClass::VECTOR),  // Caller-saved
        Register(211, "ymm11", RegisterClass::VECTOR),  // Caller-saved
        Register(212, "ymm12", RegisterClass::VECTOR),  // Caller-saved
        Register(213, "ymm13", RegisterClass::VECTOR),  // Caller-saved
        Register(214, "ymm14", RegisterClass::VECTOR),  // Caller-saved
        Register(215, "ymm15", RegisterClass::VECTOR)   // Caller-saved
    };
    
    // Special registers
    special_regs_ = {
        Register(300, "rsp", RegisterClass::SPECIAL),   // Stack pointer
        Register(301, "rbp", RegisterClass::SPECIAL)    // Base pointer
    };
}

std::vector<Register> X64RegisterSet::get_registers(RegisterClass reg_class) const {
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

size_t X64RegisterSet::get_register_count(RegisterClass reg_class) const {
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

bool X64RegisterSet::is_register_available(const Register& reg) const {
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

std::string X64RegisterSet::get_architecture_name() const {
    return "x86_64";
}

std::vector<Register> X64RegisterSet::get_preferred_order(RegisterClass reg_class) const {
    switch (reg_class) {
        case RegisterClass::GENERAL_PURPOSE:
            // Return registers in preferred allocation order
            // Caller-saved first (more efficient), then callee-saved
            return general_purpose_regs_;
            
        case RegisterClass::FLOATING_POINT:
            // Return XMM registers in preferred order
            return floating_point_regs_;
            
        case RegisterClass::VECTOR:
            // Return YMM registers in preferred order
            return vector_regs_;
            
        case RegisterClass::SPECIAL:
            // Special registers are not preferred for allocation
            return {};
            
        default:
            return {};
    }
}

void X64RegisterSet::reserve_register(const Register& reg) {
    reserved_registers_.insert(reg);
}

void X64RegisterSet::unreserve_register(const Register& reg) {
    reserved_registers_.erase(reg);
}

bool X64RegisterSet::is_reserved(const Register& reg) const {
    return reserved_registers_.find(reg) != reserved_registers_.end();
}

Register X64RegisterSet::get_stack_pointer() const {
    return Register(300, "rsp", RegisterClass::SPECIAL);
}

Register X64RegisterSet::get_base_pointer() const {
    return Register(301, "rbp", RegisterClass::SPECIAL);
}

Register X64RegisterSet::get_return_value_register() const {
    return Register(0, "rax", RegisterClass::GENERAL_PURPOSE);
}

std::vector<Register> X64RegisterSet::get_caller_saved_registers() const {
    // Return caller-saved registers (first 9 general purpose registers)
    return std::vector<Register>(general_purpose_regs_.begin(), general_purpose_regs_.begin() + 9);
}

std::vector<Register> X64RegisterSet::get_callee_saved_registers() const {
    // Return callee-saved registers (last 4 general purpose registers)
    return std::vector<Register>(general_purpose_regs_.begin() + 9, general_purpose_regs_.end());
}

} // namespace CodeGen
