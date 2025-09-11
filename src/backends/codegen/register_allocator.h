#pragma once
#include "core/ir/ir.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <set>
#include <functional>
#include <string>

namespace CodeGen {

// Forward declarations
class LivenessAnalyzer;
class SpillManager;

// Register allocation strategy
enum class AllocationStrategy {
    GREEDY,           // Simple greedy allocation (current approach)
    LINEAR_SCAN,      // Linear scan register allocation
    GRAPH_COLORING,   // Graph coloring allocation
    INTERFERENCE_GRAPH // Build interference graph and color
};

// Register class for different types of values
enum class RegisterClass {
    GENERAL_PURPOSE,  // Integer and pointer registers
    FLOATING_POINT,   // Floating point registers
    VECTOR,           // SIMD/vector registers
    SPECIAL           // Special purpose registers (SP, BP, etc.)
};

// Generic register representation - backend-agnostic
class Register {
public:
    Register() : id_(-1), name_(""), class_(RegisterClass::GENERAL_PURPOSE) {}
    Register(int id, const std::string& name, RegisterClass reg_class = RegisterClass::GENERAL_PURPOSE)
        : id_(id), name_(name), class_(reg_class) {}
    
    int id() const { return id_; }
    const std::string& name() const { return name_; }
    RegisterClass reg_class() const { return class_; }
    
    bool operator==(const Register& other) const { return id_ == other.id_; }
    bool operator<(const Register& other) const { return id_ < other.id_; }
    
    // Hash support
    struct Hash {
        std::size_t operator()(const Register& reg) const {
            return std::hash<int>{}(reg.id());
        }
    };

private:
    int id_;
    std::string name_;
    RegisterClass class_;
};

// Register allocation result
struct AllocationResult {
    bool success;
    std::string error_message;
    std::unordered_map<uint32_t, Register> value_to_register;
    std::vector<uint32_t> spilled_values;
    std::unordered_map<uint32_t, int32_t> spill_offsets;
};

// Liveness information for a value
struct LivenessInfo {
    uint32_t value_id;
    std::set<uint32_t> live_in;      // Basic blocks where value is live at entry
    std::set<uint32_t> live_out;     // Basic blocks where value is live at exit
    std::set<uint32_t> def_blocks;   // Basic blocks where value is defined
    std::set<uint32_t> use_blocks;   // Basic blocks where value is used
    uint32_t last_use;               // Last instruction that uses this value
    bool is_constant;                // Whether this value is a constant
    bool is_global;                  // Whether this value is global
};

// Abstract register set interface for different architectures
class RegisterSet {
public:
    virtual ~RegisterSet() = default;
    
    // Get available registers for a specific class
    virtual std::vector<Register> get_registers(RegisterClass reg_class) const = 0;
    
    // Get total number of registers for a class
    virtual size_t get_register_count(RegisterClass reg_class) const = 0;
    
    // Check if a register is available for allocation
    virtual bool is_register_available(const Register& reg) const = 0;
    
    // Get architecture name
    virtual std::string get_architecture_name() const = 0;
    
    // Get preferred register order for allocation
    virtual std::vector<Register> get_preferred_order(RegisterClass reg_class) const = 0;
};

// Advanced register allocator with liveness analysis and spill management
class RegisterAllocator {
public:
    RegisterAllocator(AllocationStrategy strategy = AllocationStrategy::LINEAR_SCAN);
    ~RegisterAllocator();
    
    // Set the register set for this architecture
    void set_register_set(std::shared_ptr<RegisterSet> reg_set);
    
    // Main allocation interface
    AllocationResult allocate_registers(IR::Module& module);
    
    // Per-function allocation
    bool allocate_function_registers(IR::Function& function);
    
    // Register management
    Register allocate_register(std::shared_ptr<IR::Value> value, RegisterClass reg_class);
    void free_register(std::shared_ptr<IR::Value> value);
    Register get_register(std::shared_ptr<IR::Value> value);
    bool is_allocated(std::shared_ptr<IR::Value> value);
    
    // Spill management
    void spill_value(uint32_t value_id);
    bool is_spilled(uint32_t value_id) const;
    int32_t get_spill_offset(uint32_t value_id) const;
    
    // Configuration
    void set_allocation_strategy(AllocationStrategy strategy);
    void set_max_registers(uint32_t max_regs);
    void set_spill_cost_threshold(uint32_t threshold);
    
    // Analysis results
    const std::unordered_map<uint32_t, LivenessInfo>& get_liveness_info() const;
    const std::vector<uint32_t>& get_spilled_values() const;
    
    // Reset for new compilation
    void reset();
    
    // Debug and statistics
    void print_allocation_stats() const;
    uint32_t get_total_spills() const;
    uint32_t get_total_register_uses() const;
    
    // Public helper methods
    RegisterClass get_register_class(const IR::Type& type) const;
    
    // Vector-specific allocation methods
    bool requires_vector_alignment(const IR::Type& type) const;
    uint32_t get_vector_spill_size(const IR::Type& type) const;
    std::vector<Register> get_vector_register_aliases(const Register& vector_reg) const;

private:
    // Core allocation logic
    bool run_linear_scan_allocation(IR::Function& function);
    bool run_graph_coloring_allocation(IR::Function& function);
    bool run_greedy_allocation(IR::Function& function);
    
    // Liveness analysis
    void analyze_liveness(IR::Function& function);
    void compute_live_in_out(IR::Function& function);
    void build_interference_graph(IR::Function& function);
    
    // Register selection
    Register select_best_register(RegisterClass reg_class, const std::set<uint32_t>& interfering_values);
    
    // Select register with color constraints (for graph coloring)
    Register select_best_register_with_constraints(RegisterClass reg_class, const std::set<uint32_t>& interfering_colors);
    
    bool is_register_available(const Register& reg) const;
    void mark_register_used(const Register& reg, uint32_t value_id);
    void mark_register_free(const Register& reg);
    
    // Spill management
    void compute_spill_costs(IR::Function& function);
    uint32_t select_spill_candidate(const std::set<uint32_t>& candidates);
    void insert_spill_code(IR::Function& function);
    
    // Helper methods
    std::vector<Register> get_available_registers(RegisterClass reg_class) const;
    bool has_interference(uint32_t value1, uint32_t value2) const;
    
    // Member variables
    AllocationStrategy strategy_;
    uint32_t max_registers_;
    uint32_t spill_cost_threshold_;
    
    // Architecture-specific register set
    std::shared_ptr<RegisterSet> register_set_;
    
    // Current allocation state
    std::unordered_map<uint32_t, Register> value_to_register_;
    std::unordered_map<Register, uint32_t, Register::Hash> register_to_value_;
    std::unordered_set<Register, Register::Hash> available_registers_;
    std::unordered_set<Register, Register::Hash> used_registers_;
    
    // Liveness and interference information
    std::unordered_map<uint32_t, LivenessInfo> liveness_info_;
    std::vector<std::pair<uint32_t, uint32_t>> interference_edges_;
    
    // Spill management
    std::unordered_set<uint32_t> spilled_values_;
    std::unordered_map<uint32_t, int32_t> spill_offsets_;
    int32_t next_spill_offset_;
    
    // Statistics
    uint32_t total_spills_;
    uint32_t total_register_uses_;
    
    // Initialize available registers from register set
    void initialize_available_registers();
};

// Liveness analyzer for computing live ranges
class LivenessAnalyzer {
public:
    LivenessAnalyzer();
    
    // Analyze liveness for a function
    std::unordered_map<uint32_t, LivenessInfo> analyze_function(IR::Function& function);
    
    // Get live ranges for a value
    std::pair<uint32_t, uint32_t> get_live_range(uint32_t value_id) const;
    
    // Check if two values interfere
    bool values_interfere(uint32_t value1, uint32_t value2) const;

private:
    void compute_gen_kill_sets(IR::Function& function);
    void iterate_liveness_equations(IR::Function& function);
    void build_def_use_chains(IR::Function& function);
    
    std::unordered_map<uint32_t, LivenessInfo> liveness_info_;
    std::unordered_map<uint32_t, std::set<uint32_t>> gen_sets_;
    std::unordered_map<uint32_t, std::set<uint32_t>> kill_sets_;
};

// Spill manager for handling register spills
class SpillManager {
public:
    SpillManager();
    
    // Add a spill
    void add_spill(uint32_t value_id, int32_t offset);
    
    // Check if value is spilled
    bool is_spilled(uint32_t value_id) const;
    
    // Get spill offset
    int32_t get_spill_offset(uint32_t value_id) const;
    
    // Get all spilled values
    const std::unordered_set<uint32_t>& get_spilled_values() const;
    
    // Get total spill size needed
    uint32_t get_total_spill_size() const;
    
    // Reset for new function
    void reset();

private:
    std::unordered_set<uint32_t> spilled_values_;
    std::unordered_map<uint32_t, int32_t> spill_offsets_;
    int32_t next_offset_;
    uint32_t total_size_;
};

} // namespace CodeGen
