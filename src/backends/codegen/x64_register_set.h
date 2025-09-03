#pragma once
#include "backends/codegen/register_allocator.h"
#include <memory>
#include <vector>

namespace CodeGen {

// x86_64 specific register set implementation
class X64RegisterSet : public RegisterSet {
public:
    X64RegisterSet();
    ~X64RegisterSet() override = default;
    
    // RegisterSet interface implementation
    std::vector<Register> get_registers(RegisterClass reg_class) const override;
    size_t get_register_count(RegisterClass reg_class) const override;
    bool is_register_available(const Register& reg) const override;
    std::string get_architecture_name() const override;
    std::vector<Register> get_preferred_order(RegisterClass reg_class) const override;
    
    // x86_64 specific methods
    void reserve_register(const Register& reg);  // Reserve a register (e.g., rsp, rbp)
    void unreserve_register(const Register& reg);
    bool is_reserved(const Register& reg) const;
    
    // Get specific register types
    Register get_stack_pointer() const;
    Register get_base_pointer() const;
    Register get_return_value_register() const;
    std::vector<Register> get_caller_saved_registers() const;
    std::vector<Register> get_callee_saved_registers() const;

private:
    // Reserved registers (not available for allocation)
    std::unordered_set<Register, Register::Hash> reserved_registers_;
    
    // Initialize register sets
    void initialize_register_sets();
    
    // Register collections
    std::vector<Register> general_purpose_regs_;
    std::vector<Register> floating_point_regs_;
    std::vector<Register> vector_regs_;
    std::vector<Register> special_regs_;
};

} // namespace CodeGen
