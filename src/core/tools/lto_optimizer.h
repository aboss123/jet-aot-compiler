#pragma once
#include "standalone_linker.h"
#include <unordered_map>
#include <unordered_set>

namespace Linker {

// Forward declarations
class LTOOptimizer;
class CrossModuleAnalyzer;
class InterProceduralOptimizer;
class WholeProgramOptimizer;

// LTO optimization levels
enum class LTOLevel {
    NONE = 0,
    BASIC = 1,      // Basic cross-module optimizations
    AGGRESSIVE = 2, // Aggressive inter-procedural optimizations
    WHOLE_PROGRAM = 3 // Whole-program analysis and optimization
};

// Function call information for inter-procedural analysis
struct CallSiteInfo {
    std::string caller_function;
    std::string callee_function;
    uint64_t call_offset;
    std::vector<std::string> argument_types;
    bool is_direct_call = true;
    bool is_tail_call = false;
    uint32_t call_frequency = 1; // For hot/cold analysis
    
    CallSiteInfo() = default;
    CallSiteInfo(const std::string& caller, const std::string& callee, uint64_t offset)
        : caller_function(caller), callee_function(callee), call_offset(offset) {}
};

// Function information for whole-program analysis
struct FunctionInfo {
    std::string name;
    std::string module_name;
    uint64_t size = 0;
    bool is_exported = false;
    bool is_inline_candidate = false;
    bool is_hot = false;
    bool is_leaf_function = false;
    bool has_side_effects = true;
    uint32_t call_count = 0;
    std::vector<std::string> called_functions;
    std::vector<std::string> callers;
    std::vector<CallSiteInfo> call_sites;
    
    FunctionInfo() = default;
    FunctionInfo(const std::string& n) : name(n) {}
};

// Global variable information for cross-module analysis
struct GlobalVarInfo {
    std::string name;
    std::string module_name;
    uint64_t size = 0;
    bool is_exported = false;
    bool is_read_only = false;
    bool is_constant = false;
    bool is_used = false;
    std::vector<std::string> accessing_functions;
    
    GlobalVarInfo() = default;
    GlobalVarInfo(const std::string& n) : name(n) {}
};

// Cross-module dependency information
struct ModuleDependency {
    std::string from_module;
    std::string to_module;
    std::vector<std::string> imported_symbols;
    std::vector<std::string> exported_symbols;
    uint32_t dependency_strength = 1; // For module ordering
    
    ModuleDependency() = default;
    ModuleDependency(const std::string& from, const std::string& to) 
        : from_module(from), to_module(to) {}
};

// LTO optimization statistics
struct LTOStats {
    uint32_t functions_analyzed = 0;
    uint32_t functions_inlined = 0;
    uint32_t functions_eliminated = 0;
    uint32_t global_vars_eliminated = 0;
    uint32_t call_sites_optimized = 0;
    uint64_t code_size_before = 0;
    uint64_t code_size_after = 0;
    double optimization_time_ms = 0.0;
    
    double get_size_reduction_percent() const {
        if (code_size_before == 0) return 0.0;
        return ((double)(code_size_before - code_size_after) / code_size_before) * 100.0;
    }
};

// Cross-module analyzer - analyzes dependencies and call graphs across modules
class CrossModuleAnalyzer {
public:
    CrossModuleAnalyzer() = default;
    ~CrossModuleAnalyzer() = default;
    
    // Analyze all object files for cross-module dependencies
    bool analyze_modules(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                        SymbolResolver& symbol_resolver);
    
    // Build call graph across modules
    bool build_call_graph(const std::vector<std::unique_ptr<ObjectFile>>& object_files);
    
    // Identify hot/cold functions based on call frequency
    bool analyze_function_hotness();
    
    // Find inlining opportunities
    std::vector<std::pair<std::string, std::string>> find_inline_candidates();
    
    // Identify dead code across modules
    std::vector<std::string> find_dead_functions();
    
    // Get function information
    const FunctionInfo* get_function_info(const std::string& name) const;
    
    // Get global variable information
    const GlobalVarInfo* get_global_var_info(const std::string& name) const;
    
    // Get module dependencies
    const std::vector<ModuleDependency>& get_module_dependencies() const { return module_dependencies; }
    
    // Get all functions
    const std::unordered_map<std::string, FunctionInfo>& get_functions() const { return functions; }
    
    // Get call graph (needed by optimizers)
    const std::unordered_map<std::string, std::vector<CallSiteInfo>>& get_call_graph() const { return call_graph; }
    
private:
    std::unordered_map<std::string, FunctionInfo> functions;
    std::unordered_map<std::string, GlobalVarInfo> global_vars;
    std::vector<ModuleDependency> module_dependencies;
    std::unordered_map<std::string, std::vector<CallSiteInfo>> call_graph;
    
    // Analysis helpers
    bool analyze_function_symbols(const ObjectFile& obj_file);
    bool analyze_global_symbols(const ObjectFile& obj_file);
    bool analyze_relocations(const ObjectFile& obj_file);
    void build_dependency_graph();
    void propagate_hotness_information();
    bool is_function_small_enough_to_inline(const FunctionInfo& func) const;
};

// Inter-procedural optimizer - performs optimizations across function boundaries
class InterProceduralOptimizer {
public:
    InterProceduralOptimizer(CrossModuleAnalyzer& analyzer);
    ~InterProceduralOptimizer() = default;
    
    // Perform function inlining across modules
    bool inline_functions(std::vector<Section>& sections);
    
    // Optimize call sites (tail call optimization, etc.)
    bool optimize_call_sites(std::vector<Section>& sections);
    
    // Propagate constants across function boundaries
    bool propagate_constants(std::vector<Section>& sections);
    
    // Eliminate unused parameters
    bool eliminate_unused_parameters(std::vector<Section>& sections);
    
    // Specialize functions based on call sites
    bool specialize_functions(std::vector<Section>& sections);
    
    // Get optimization statistics
    const LTOStats& get_stats() const { return stats; }
    
private:
    CrossModuleAnalyzer& module_analyzer;
    LTOStats stats;
    
    // Inlining helpers
    bool can_inline_function(const std::string& caller, const std::string& callee);
    bool inline_function_at_call_site(Section& section, const CallSiteInfo& call_site);
    void update_call_graph_after_inlining(const std::string& caller, const std::string& inlined);
    
    // Call site optimization helpers
    bool convert_to_tail_call(Section& section, const CallSiteInfo& call_site);
    bool optimize_direct_call(Section& section, const CallSiteInfo& call_site);
    
    // Constant propagation helpers
    bool trace_constant_values(const std::string& function_name);
    bool propagate_constant_to_callers(const std::string& function_name, const std::string& param_name, uint64_t value);
};

// Whole-program optimizer - performs global optimizations
class WholeProgramOptimizer {
public:
    WholeProgramOptimizer(CrossModuleAnalyzer& analyzer);
    ~WholeProgramOptimizer() = default;
    
    // Eliminate dead code across the entire program
    bool eliminate_dead_code(std::vector<Section>& sections, SymbolResolver& symbol_resolver);
    
    // Optimize global variable layout and access
    bool optimize_global_variables(std::vector<Section>& sections);
    
    // Perform whole-program constant propagation
    bool propagate_global_constants(std::vector<Section>& sections);
    
    // Optimize virtual function calls (devirtualization)
    bool devirtualize_calls(std::vector<Section>& sections);
    
    // Merge similar functions
    bool merge_identical_functions(std::vector<Section>& sections);
    
    // Get optimization statistics
    const LTOStats& get_stats() const { return stats; }
    
private:
    CrossModuleAnalyzer& module_analyzer;
    LTOStats stats;
    
    // Dead code elimination helpers
    void mark_reachable_functions(const std::string& entry_point, std::unordered_set<std::string>& reachable);
    bool remove_unreachable_functions(std::vector<Section>& sections, const std::unordered_set<std::string>& reachable);
    
    // Global variable optimization helpers
    bool merge_read_only_globals(std::vector<Section>& sections);
    bool eliminate_unused_globals(std::vector<Section>& sections);
    
    // Function merging helpers
    bool functions_are_identical(const std::string& func1, const std::string& func2);
    bool merge_functions(std::vector<Section>& sections, const std::string& keep, const std::string& remove);
};

// Main LTO optimizer coordinator
class LTOOptimizer {
public:
    LTOOptimizer(LTOLevel level = LTOLevel::BASIC);
    ~LTOOptimizer() = default;
    
    // Set optimization level
    void set_optimization_level(LTOLevel level) { opt_level = level; }
    
    // Enable/disable specific optimizations
    void enable_inlining(bool enabled) { enable_function_inlining = enabled; }
    void enable_dead_code_elimination(bool enabled) { enable_dead_code_elim = enabled; }
    void enable_constant_propagation(bool enabled) { enable_const_prop = enabled; }
    void enable_call_site_optimization(bool enabled) { enable_call_site_opt = enabled; }
    
    // Perform LTO on linked modules
    bool optimize(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                  std::vector<Section>& sections,
                  SymbolResolver& symbol_resolver,
                  const std::string& entry_point = "_start");
    
    // Get optimization statistics
    const LTOStats& get_combined_stats() const;
    
    // Get analysis results
    const CrossModuleAnalyzer& get_analyzer() const { return cross_module_analyzer; }
    
    // Configuration
    void set_inline_threshold(uint32_t threshold) { inline_size_threshold = threshold; }
    void set_hot_function_threshold(uint32_t threshold) { hot_function_threshold = threshold; }
    
private:
    LTOLevel opt_level;
    uint32_t inline_size_threshold = 100;  // Max function size for inlining (bytes)
    uint32_t hot_function_threshold = 10;  // Min call count for hot functions
    
    // Optimization flags
    bool enable_function_inlining = true;
    bool enable_dead_code_elim = true;
    bool enable_const_prop = true;
    bool enable_call_site_opt = true;
    
    // Optimization components
    CrossModuleAnalyzer cross_module_analyzer;
    InterProceduralOptimizer interprocedural_optimizer;
    WholeProgramOptimizer whole_program_optimizer;
    
    // Combined statistics
    mutable LTOStats combined_stats;
    
    // Optimization pipeline
    bool run_basic_optimizations(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                std::vector<Section>& sections,
                                SymbolResolver& symbol_resolver);
    
    bool run_aggressive_optimizations(std::vector<Section>& sections);
    
    bool run_whole_program_optimizations(std::vector<Section>& sections,
                                        SymbolResolver& symbol_resolver,
                                        const std::string& entry_point);
    
    // Statistics aggregation
    void update_combined_stats();
};

} // namespace Linker
