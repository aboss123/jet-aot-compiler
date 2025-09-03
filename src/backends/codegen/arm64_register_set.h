#pragma once
#include "backends/codegen/register_allocator.h"
#include <memory>
#include <vector>

namespace CodeGen {

// ARM64 specific register set implementation
class ARM64RegisterSet : public RegisterSet {
public:
    ARM64RegisterSet();
    ~ARM64RegisterSet() override = default;
    
    // RegisterSet interface implementation
    std::vector<Register> get_registers(RegisterClass reg_class) const override;
    size_t get_register_count(RegisterClass reg_class) const override;
    bool is_register_available(const Register& reg) const override;
    std::string get_architecture_name() const override;
    std::vector<Register> get_preferred_order(RegisterClass reg_class) const override;
    
    // ARM64 specific methods
    void reserve_register(const Register& reg);  // Reserve a register (e.g., sp, lr, xzr)
    void unreserve_register(const Register& reg);
    bool is_reserved(const Register& reg) const;
    
    // Get specific register types
    Register get_stack_pointer() const;
    Register get_link_register() const;
    Register get_zero_register() const;
    Register get_return_value_register() const;
    std::vector<Register> get_caller_saved_registers() const;
    std::vector<Register> get_callee_saved_registers() const;
    std::vector<Register> get_argument_registers() const;

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
