#include "backends/codegen/register_allocator.h"
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <queue>
#include <cassert>

namespace CodeGen {

// ==================== RegisterAllocator Implementation ====================

RegisterAllocator::RegisterAllocator(AllocationStrategy strategy)
    : strategy_(strategy), max_registers_(16), spill_cost_threshold_(100),
      next_spill_offset_(0), total_spills_(0), total_register_uses_(0) {
    // Note: register_set_ must be set before allocation can begin
}

RegisterAllocator::~RegisterAllocator() = default;

void RegisterAllocator::set_register_set(std::shared_ptr<RegisterSet> reg_set) {
    register_set_ = reg_set;
    if (register_set_) {
        initialize_available_registers();
    }
}

void RegisterAllocator::initialize_available_registers() {
    if (!register_set_) {
        throw std::runtime_error("Register set not initialized");
    }
    
    available_registers_.clear();
    used_registers_.clear();
    
    // Initialize available registers from the register set
    for (auto reg_class : {RegisterClass::GENERAL_PURPOSE, RegisterClass::FLOATING_POINT, RegisterClass::VECTOR}) {
        auto regs = register_set_->get_registers(reg_class);
        for (const auto& reg : regs) {
            if (register_set_->is_register_available(reg)) {
                available_registers_.insert(reg);
            }
        }
    }
}

AllocationResult RegisterAllocator::allocate_registers(IR::Module& module) {
    AllocationResult result;
    result.success = true;
    
    if (!register_set_) {
        result.success = false;
        result.error_message = "Register set not initialized";
        return result;
    }
    
    try {
        for (auto& function : module.functions) {
            if (!allocate_function_registers(*function)) {
                result.success = false;
                result.error_message = "Failed to allocate registers for function: " + function->name;
                return result;
            }
        }
        
        // Copy results
        result.value_to_register = value_to_register_;
        result.spilled_values = std::vector<uint32_t>(spilled_values_.begin(), spilled_values_.end());
        result.spill_offsets = spill_offsets_;
        
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }
    
    return result;
}

bool RegisterAllocator::allocate_function_registers(IR::Function& function) {
    if (!register_set_) {
        throw std::runtime_error("Register set not initialized");
    }
    
    reset();
    
    // Analyze liveness first
    analyze_liveness(function);
    
    // Run the selected allocation strategy
    switch (strategy_) {
        case AllocationStrategy::LINEAR_SCAN:
            return run_linear_scan_allocation(function);
        case AllocationStrategy::GRAPH_COLORING:
            return run_graph_coloring_allocation(function);
        case AllocationStrategy::GREEDY:
            return run_greedy_allocation(function);
        case AllocationStrategy::INTERFERENCE_GRAPH:
            return run_graph_coloring_allocation(function);
        default:
            return run_linear_scan_allocation(function);
    }
}

bool RegisterAllocator::run_linear_scan_allocation(IR::Function& function) {
    // Sort values by their live ranges (start position)
    std::vector<std::pair<uint32_t, uint32_t>> live_ranges;
    
    for (const auto& [value_id, liveness] : liveness_info_) {
        if (!liveness.is_constant && !liveness.is_global) {
            uint32_t start = liveness.def_blocks.empty() ? 0 : *liveness.def_blocks.begin();
            uint32_t end = liveness.last_use;
            live_ranges.emplace_back(value_id, end);
        }
    }
    
    // Sort by end position (linear scan order)
    std::sort(live_ranges.begin(), live_ranges.end(), 
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    // Active intervals (currently live values)
    std::set<std::pair<uint32_t, uint32_t>> active_intervals; // (end_pos, value_id)
    
    for (const auto& [value_id, end_pos] : live_ranges) {
        // Expire finished intervals
        while (!active_intervals.empty() && active_intervals.begin()->first <= end_pos) {
            uint32_t expired_value = active_intervals.begin()->second;
            free_register(std::make_shared<IR::Value>(IR::Value::Kind::REGISTER, IR::Type::i32()));
            active_intervals.erase(active_intervals.begin());
        }
        
        // Try to allocate a register
        RegisterClass reg_class = get_register_class(IR::Type::i32()); // Default to i32
        Register reg = allocate_register(std::make_shared<IR::Value>(IR::Value::Kind::REGISTER, IR::Type::i32()), reg_class);
        
        if (reg.id() != -1) {
            // Successfully allocated
            active_intervals.emplace(end_pos, value_id);
            total_register_uses_++;
        } else {
            // Need to spill
            spill_value(value_id);
            total_spills_++;
        }
    }
    
    return true;
}

bool RegisterAllocator::run_graph_coloring_allocation(IR::Function& function) {
    // Build interference graph
    build_interference_graph(function);
    
    // Enhanced graph coloring with spill handling
    std::unordered_map<uint32_t, Register> coloring;
    std::vector<uint32_t> spill_candidates;
    
    // Sort values by spill cost (number of uses)
    std::vector<std::pair<uint32_t, int>> value_costs;
    for (const auto& [value_id, liveness] : liveness_info_) {
        if (liveness.is_constant || liveness.is_global) continue;
        
        int cost = liveness.use_blocks.size() + liveness.def_blocks.size();
        value_costs.emplace_back(value_id, cost);
    }
    
    std::sort(value_costs.begin(), value_costs.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Try to color each value
    for (const auto& [value_id, cost] : value_costs) {
        // Find interfering values that are already colored
        std::set<uint32_t> interfering_colors;
        for (const auto& [v1, v2] : interference_edges_) {
            if (v1 == value_id) {
                auto it = coloring.find(v2);
                if (it != coloring.end()) {
                    interfering_colors.insert(it->second.id());
                }
            } else if (v2 == value_id) {
                auto it = coloring.find(v1);
                if (it != coloring.end()) {
                    interfering_colors.insert(it->second.id());
                }
            }
        }
        
        // Find available register
        RegisterClass reg_class = get_register_class(IR::Type::i32());
        Register reg = select_best_register_with_constraints(reg_class, interfering_colors);
        
        if (reg.id() != -1) {
            coloring[value_id] = reg;
            mark_register_used(reg, value_id);
        } else {
            // This value needs to be spilled
            spill_candidates.push_back(value_id);
        }
    }
    
    // Handle spill candidates
    for (uint32_t value_id : spill_candidates) {
        spill_value(value_id);
        total_spills_++;
    }
    
    // Apply coloring
    value_to_register_ = coloring;
    
    std::cout << "  🎨 Graph coloring completed: " << coloring.size() 
              << " values colored, " << spill_candidates.size() << " spilled\n";
    
    return true;
}

bool RegisterAllocator::run_greedy_allocation(IR::Function& function) {
    // Simple greedy allocation: allocate registers as needed
    for (const auto& [value_id, liveness] : liveness_info_) {
        if (liveness.is_constant || liveness.is_global) continue;
        
        RegisterClass reg_class = get_register_class(IR::Type::i32());
        Register reg = allocate_register(std::make_shared<IR::Value>(IR::Value::Kind::REGISTER, IR::Type::i32()), reg_class);
        
        if (reg.id() == -1) {
            spill_value(value_id);
            total_spills_++;
        } else {
            total_register_uses_++;
        }
    }
    
    return true;
}

void RegisterAllocator::analyze_liveness(IR::Function& function) {
    LivenessAnalyzer analyzer;
    liveness_info_ = analyzer.analyze_function(function);
}

void RegisterAllocator::compute_live_in_out(IR::Function& function) {
    // This is handled by LivenessAnalyzer
}

void RegisterAllocator::build_interference_graph(IR::Function& function) {
    interference_edges_.clear();
    
    // For each pair of values, check if they interfere
    std::vector<uint32_t> value_ids;
    for (const auto& [value_id, liveness] : liveness_info_) {
        if (!liveness.is_constant && !liveness.is_global) {
            value_ids.push_back(value_id);
        }
    }
    
    for (size_t i = 0; i < value_ids.size(); ++i) {
        for (size_t j = i + 1; j < value_ids.size(); ++j) {
            uint32_t v1 = value_ids[i];
            uint32_t v2 = value_ids[j];
            
            if (has_interference(v1, v2)) {
                interference_edges_.emplace_back(v1, v2);
            }
        }
    }
}

Register RegisterAllocator::select_best_register(RegisterClass reg_class, const std::set<uint32_t>& interfering_values) {
    // Simple implementation - just return the first available register
    auto available_regs = get_available_registers(reg_class);
    for (const auto& reg : available_regs) {
        if (is_register_available(reg)) {
            return reg;
        }
    }
    return Register(); // No register available
}

Register RegisterAllocator::select_best_register_with_constraints(RegisterClass reg_class, const std::set<uint32_t>& interfering_colors) {
    if (!register_set_) {
        return Register(); // Return invalid register
    }
    
    auto available_regs = get_available_registers(reg_class);
    
    for (const auto& reg : available_regs) {
        if (is_register_available(reg)) {
            // Check if this register's color conflicts with interfering colors
            if (interfering_colors.find(reg.id()) == interfering_colors.end()) {
                return reg;
            }
        }
    }
    
    return Register(); // No available register
}

bool RegisterAllocator::is_register_available(const Register& reg) const {
    return available_registers_.find(reg) != available_registers_.end();
}

void RegisterAllocator::mark_register_used(const Register& reg, uint32_t value_id) {
    available_registers_.erase(reg);
    used_registers_.insert(reg);
    register_to_value_[reg] = value_id;
}

void RegisterAllocator::mark_register_free(const Register& reg) {
    used_registers_.erase(reg);
    available_registers_.insert(reg);
    register_to_value_.erase(reg);
}

Register RegisterAllocator::allocate_register(std::shared_ptr<IR::Value> value, RegisterClass reg_class) {
    if (is_allocated(value)) {
        return get_register(value);
    }
    
    Register reg = select_best_register(reg_class, {});
    if (reg.id() != -1) {
        value_to_register_[value->id] = reg;
        mark_register_used(reg, value->id);
        return reg;
    }
    
    return Register(); // No register available
}

void RegisterAllocator::free_register(std::shared_ptr<IR::Value> value) {
    auto it = value_to_register_.find(value->id);
    if (it != value_to_register_.end()) {
        Register reg = it->second;
        value_to_register_.erase(it);
        mark_register_free(reg);
    }
}

Register RegisterAllocator::get_register(std::shared_ptr<IR::Value> value) {
    auto it = value_to_register_.find(value->id);
    if (it != value_to_register_.end()) {
        return it->second;
    }
    return Register(); // Return invalid register
}

bool RegisterAllocator::is_allocated(std::shared_ptr<IR::Value> value) {
    return value_to_register_.find(value->id) != value_to_register_.end();
}

void RegisterAllocator::spill_value(uint32_t value_id) {
    spilled_values_.insert(value_id);
    
    // Get the type information for proper spill size calculation
    // For now, use a default size but this should be enhanced to get actual type info
    int32_t spill_size = 8; // Default to 8 bytes (64-bit)
    int32_t alignment = 8;   // Default alignment
    
    // TODO: Get actual type information from value_id to determine if it's a vector
    // For vector types, use vector-specific spill size and alignment
    
    // Align the spill offset properly
    int32_t aligned_offset = (next_spill_offset_ + alignment - 1) & ~(alignment - 1);
    
    spill_offsets_[value_id] = aligned_offset;
    next_spill_offset_ = aligned_offset + spill_size;
    
    total_spills_++;
}

bool RegisterAllocator::is_spilled(uint32_t value_id) const {
    return spilled_values_.find(value_id) != spilled_values_.end();
}

int32_t RegisterAllocator::get_spill_offset(uint32_t value_id) const {
    auto it = spill_offsets_.find(value_id);
    return it != spill_offsets_.end() ? it->second : -1;
}

void RegisterAllocator::set_allocation_strategy(AllocationStrategy strategy) {
    strategy_ = strategy;
}

void RegisterAllocator::set_max_registers(uint32_t max_regs) {
    max_registers_ = max_regs;
}

void RegisterAllocator::set_spill_cost_threshold(uint32_t threshold) {
    spill_cost_threshold_ = threshold;
}

const std::unordered_map<uint32_t, LivenessInfo>& RegisterAllocator::get_liveness_info() const {
    return liveness_info_;
}

const std::vector<uint32_t>& RegisterAllocator::get_spilled_values() const {
    static std::vector<uint32_t> result;
    result.clear();
    result.insert(result.end(), spilled_values_.begin(), spilled_values_.end());
    return result;
}

void RegisterAllocator::reset() {
    value_to_register_.clear();
    register_to_value_.clear();
    spilled_values_.clear();
    spill_offsets_.clear();
    next_spill_offset_ = 0;
    
    // Reset available registers
    if (register_set_) {
        initialize_available_registers();
    }
}

void RegisterAllocator::print_allocation_stats() const {
    std::cout << "Register Allocation Statistics:\n";
    std::cout << "  Architecture: " << (register_set_ ? register_set_->get_architecture_name() : "Unknown") << "\n";
    std::cout << "  Strategy: " << static_cast<int>(strategy_) << "\n";
    std::cout << "  Total spills: " << total_spills_ << "\n";
    std::cout << "  Total register uses: " << total_register_uses_ << "\n";
    std::cout << "  Spilled values: " << spilled_values_.size() << "\n";
    std::cout << "  Allocated values: " << value_to_register_.size() << "\n";
}

uint32_t RegisterAllocator::get_total_spills() const {
    return total_spills_;
}

uint32_t RegisterAllocator::get_total_register_uses() const {
    return total_register_uses_;
}

RegisterClass RegisterAllocator::get_register_class(const IR::Type& type) const {
    if (type.is_vector()) {
        return RegisterClass::VECTOR;
    } else if (type.is_float()) {
        return RegisterClass::FLOATING_POINT;
    } else if (type.is_integer() || type.is_pointer()) {
        return RegisterClass::GENERAL_PURPOSE;
    } else {
        return RegisterClass::GENERAL_PURPOSE; // Default
    }
}

std::vector<Register> RegisterAllocator::get_available_registers(RegisterClass reg_class) const {
    if (!register_set_) {
        return {};
    }
    return register_set_->get_registers(reg_class);
}

bool RegisterAllocator::has_interference(uint32_t value1, uint32_t value2) const {
    // Check if two values have overlapping live ranges
    auto it1 = liveness_info_.find(value1);
    auto it2 = liveness_info_.find(value2);
    
    if (it1 == liveness_info_.end() || it2 == liveness_info_.end()) {
        return false;
    }
    
    const auto& liveness1 = it1->second;
    const auto& liveness2 = it2->second;
    
    // Check if they are live in the same basic blocks
    for (uint32_t block : liveness1.live_in) {
        if (liveness2.live_in.find(block) != liveness2.live_in.end()) {
            return true;
        }
    }
    
    return false;
}

// Vector-specific allocation methods
bool RegisterAllocator::requires_vector_alignment(const IR::Type& type) const {
    // Vector types require aligned memory access
    return type.is_vector();
}

uint32_t RegisterAllocator::get_vector_spill_size(const IR::Type& type) const {
    if (!type.is_vector()) {
        return type.size_bytes();
    }
    
    // Vector types need aligned spill slots
    uint32_t size = type.size_bytes();
    uint32_t alignment = type.alignment();
    
    // Round up to alignment boundary
    return (size + alignment - 1) & ~(alignment - 1);
}

std::vector<Register> RegisterAllocator::get_vector_register_aliases(const Register& vector_reg) const {
    std::vector<Register> aliases;
    
    if (!register_set_) {
        return aliases;
    }
    
    // For x64: YMM registers overlap with XMM registers
    // For ARM64: Vector registers can be accessed as different sizes (V, D, S, H, B)
    if (register_set_->get_architecture_name() == "x86_64") {
        // YMM0 overlaps with XMM0, etc.
        if (vector_reg.reg_class() == RegisterClass::VECTOR) {
            int xmm_id = vector_reg.id() - 200 + 100; // Convert YMM id to XMM id
            std::string xmm_name = "xmm" + std::to_string(vector_reg.id() - 200);
            aliases.push_back(Register(xmm_id, xmm_name, RegisterClass::FLOATING_POINT));
        }
    } else if (register_set_->get_architecture_name() == "ARM64") {
        // ARM64 V registers can be accessed as different sizes
        if (vector_reg.reg_class() == RegisterClass::VECTOR || vector_reg.reg_class() == RegisterClass::FLOATING_POINT) {
            // V registers are the same as floating point registers in ARM64
            aliases.push_back(vector_reg);
        }
    }
    
    return aliases;
}

// ==================== LivenessAnalyzer Implementation ====================

LivenessAnalyzer::LivenessAnalyzer() = default;

std::unordered_map<uint32_t, LivenessInfo> LivenessAnalyzer::analyze_function(IR::Function& function) {
    liveness_info_.clear();
    gen_sets_.clear();
    kill_sets_.clear();
    
    // Initialize liveness info for all values
    for (const auto& bb : function.basic_blocks) {
        for (const auto& inst : bb->instructions) {
            if (inst->result_reg) {
                LivenessInfo info;
                info.value_id = inst->result_reg->id;
                info.last_use = 0;
                info.is_constant = false;
                info.is_global = false;
                liveness_info_[info.value_id] = info;
            }
            
            for (const auto& operand : inst->operands) {
                if (auto reg = std::dynamic_pointer_cast<IR::Register>(operand)) {
                    LivenessInfo info;
                    info.value_id = reg->id;
                    info.last_use = 0;
                    info.is_constant = false;
                    info.is_global = false;
                    liveness_info_[info.value_id] = info;
                }
            }
        }
    }
    
    // Compute gen/kill sets and build def/use chains
    compute_gen_kill_sets(function);
    build_def_use_chains(function);
    
    // Iterate liveness equations until convergence
    iterate_liveness_equations(function);
    
    return liveness_info_;
}

void LivenessAnalyzer::compute_gen_kill_sets(IR::Function& function) {
    uint32_t block_id = 0;
    for (const auto& bb : function.basic_blocks) {
        for (const auto& inst : bb->instructions) {
            // Gen set: values that are used in this instruction
            for (const auto& operand : inst->operands) {
                if (auto reg = std::dynamic_pointer_cast<IR::Register>(operand)) {
                    gen_sets_[block_id].insert(reg->id);
                }
            }
            
            // Kill set: values that are defined in this instruction
            if (inst->result_reg) {
                kill_sets_[block_id].insert(inst->result_reg->id);
            }
        }
        block_id++;
    }
}

void LivenessAnalyzer::build_def_use_chains(IR::Function& function) {
    uint32_t block_id = 0;
    for (const auto& bb : function.basic_blocks) {
        for (const auto& inst : bb->instructions) {
            // Record definition
            if (inst->result_reg) {
                liveness_info_[inst->result_reg->id].def_blocks.insert(block_id);
            }
            
            // Record uses
            for (const auto& operand : inst->operands) {
                if (auto reg = std::dynamic_pointer_cast<IR::Register>(operand)) {
                    liveness_info_[reg->id].use_blocks.insert(block_id);
                }
            }
        }
        block_id++;
    }
}

void LivenessAnalyzer::iterate_liveness_equations(IR::Function& function) {
    bool changed = true;
    uint32_t iterations = 0;
    const uint32_t max_iterations = 100; // Prevent infinite loops
    
    while (changed && iterations < max_iterations) {
        changed = false;
        iterations++;
        
        // Process basic blocks in reverse order for better convergence
        for (int i = function.basic_blocks.size() - 1; i >= 0; --i) {
            uint32_t block_id = i;
            
            // Compute live_out for this block
            std::set<uint32_t> new_live_out;
            
            // For a simplified implementation, just use the gen set from successors
            // In a complete implementation, we'd analyze the control flow graph properly
            // For now, avoid the infinite loop by not using incorrect liveness_info_ access
            
            // Compute live_in: (live_out - kill) union gen
            std::set<uint32_t> new_live_in = new_live_out;
            
            // Subtract kill set
            for (uint32_t killed_value : kill_sets_[block_id]) {
                new_live_in.erase(killed_value);
            }
            
            // Add gen set
            for (uint32_t generated_value : gen_sets_[block_id]) {
                new_live_in.insert(generated_value);
            }
            
            // Update liveness info for values in this block, not indexed by block_id
            // For now, since we have a simplified implementation, just mark as converged
            // In a complete implementation, we'd properly track live_in/live_out per block
            
            // To prevent infinite loop, just do one iteration for now
            changed = false;
        }
    }
}

std::pair<uint32_t, uint32_t> LivenessAnalyzer::get_live_range(uint32_t value_id) const {
    auto it = liveness_info_.find(value_id);
    if (it == liveness_info_.end()) {
        return {0, 0};
    }
    
    const auto& liveness = it->second;
    uint32_t start = liveness.def_blocks.empty() ? 0 : *liveness.def_blocks.begin();
    uint32_t end = liveness.last_use;
    
    return {start, end};
}

bool LivenessAnalyzer::values_interfere(uint32_t value1, uint32_t value2) const {
    auto range1 = get_live_range(value1);
    auto range2 = get_live_range(value2);
    
    // Check for overlap: range1.start < range2.end && range2.start < range1.end
    return range1.first < range2.second && range2.first < range1.second;
}

// ==================== SpillManager Implementation ====================

SpillManager::SpillManager() : next_offset_(0), total_size_(0) {}

void SpillManager::add_spill(uint32_t value_id, int32_t offset) {
    spilled_values_.insert(value_id);
    spill_offsets_[value_id] = offset;
    next_offset_ = std::max(next_offset_, offset + 8); // Assume 8-byte alignment
    total_size_ = std::max(total_size_, static_cast<uint32_t>(next_offset_));
}

bool SpillManager::is_spilled(uint32_t value_id) const {
    return spilled_values_.find(value_id) != spilled_values_.end();
}

int32_t SpillManager::get_spill_offset(uint32_t value_id) const {
    auto it = spill_offsets_.find(value_id);
    return it != spill_offsets_.end() ? it->second : -1;
}

const std::unordered_set<uint32_t>& SpillManager::get_spilled_values() const {
    return spilled_values_;
}

uint32_t SpillManager::get_total_spill_size() const {
    return total_size_;
}

void SpillManager::reset() {
    spilled_values_.clear();
    spill_offsets_.clear();
    next_offset_ = 0;
    total_size_ = 0;
}

} // namespace CodeGen
