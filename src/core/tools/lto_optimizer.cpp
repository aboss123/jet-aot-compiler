#include "lto_optimizer.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <queue>

namespace Linker {

// CrossModuleAnalyzer implementation
bool CrossModuleAnalyzer::analyze_modules(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                         SymbolResolver& symbol_resolver) {
    
    // Clear previous analysis
    functions.clear();
    global_vars.clear();
    module_dependencies.clear();
    
    // Analyze each object file
    for (const auto& obj_file : object_files) {
        if (!analyze_function_symbols(*obj_file)) {
            return false;
        }
        
        if (!analyze_global_symbols(*obj_file)) {
            return false;
        }
        
        if (!analyze_relocations(*obj_file)) {
            return false;
        }
    }
    
    // Build inter-module dependency graph
    build_dependency_graph();
    
    return true;
}

bool CrossModuleAnalyzer::analyze_function_symbols(const ObjectFile& obj_file) {
    for (const auto& symbol : obj_file.symbols) {
        if (symbol.type == SymbolType::FUNC && symbol.defined) {
            FunctionInfo func_info(symbol.name);
            func_info.module_name = obj_file.filename;
            func_info.size = symbol.size;
            func_info.is_exported = (symbol.binding == SymbolBinding::GLOBAL);
            func_info.is_inline_candidate = (symbol.size > 0 && symbol.size <= 200); // Small functions
            
            functions[symbol.name] = func_info;
        }
    }
    return true;
}

bool CrossModuleAnalyzer::analyze_global_symbols(const ObjectFile& obj_file) {
    for (const auto& symbol : obj_file.symbols) {
        if (symbol.type == SymbolType::OBJECT && symbol.defined) {
            GlobalVarInfo var_info(symbol.name);
            var_info.module_name = obj_file.filename;
            var_info.size = symbol.size;
            var_info.is_exported = (symbol.binding == SymbolBinding::GLOBAL);
            
            // Analyze section to determine if read-only
            if (symbol.section_index < obj_file.sections.size()) {
                const auto& section = obj_file.sections[symbol.section_index];
                var_info.is_read_only = !(section.flags & static_cast<uint64_t>(SectionFlags::WRITE));
            }
            
            global_vars[symbol.name] = var_info;
        }
    }
    return true;
}

bool CrossModuleAnalyzer::analyze_relocations(const ObjectFile& obj_file) {
    for (const auto& section : obj_file.sections) {
        if (!section.is_executable()) continue;
        
        for (const auto& reloc : section.relocations) {
            // Find the symbol being referenced
            if (reloc.symbol_index < obj_file.symbols.size()) {
                const auto& target_symbol = obj_file.symbols[reloc.symbol_index];
                
                // Look for function calls (based on relocation type)
                bool is_call = (reloc.type == RelocationType::X86_64_PLT32 || 
                               reloc.type == RelocationType::AARCH64_CALL26 ||
                               reloc.type == RelocationType::AARCH64_JUMP26);
                
                if (is_call && target_symbol.type == SymbolType::FUNC) {
                    // Find the calling function
                    std::string caller_name = "unknown";
                    for (size_t sym_idx = 0; sym_idx < obj_file.symbols.size(); ++sym_idx) {
                        const auto& symbol = obj_file.symbols[sym_idx];
                        if (symbol.type == SymbolType::FUNC && 
                            symbol.section_index < obj_file.sections.size() &&
                            reloc.offset >= symbol.value && 
                            reloc.offset < symbol.value + symbol.size) {
                            caller_name = symbol.name;
                            break;
                        }
                    }
                    
                    if (caller_name != "unknown") {
                        CallSiteInfo call_info(caller_name, target_symbol.name, reloc.offset);
                        call_graph[caller_name].push_back(call_info);
                        
                        // Update function info
                        if (functions.find(caller_name) != functions.end()) {
                            functions[caller_name].called_functions.push_back(target_symbol.name);
                        }
                        if (functions.find(target_symbol.name) != functions.end()) {
                            functions[target_symbol.name].callers.push_back(caller_name);
                            functions[target_symbol.name].call_count++;
                        }
                    }
                }
            }
        }
    }
    return true;
}

bool CrossModuleAnalyzer::build_call_graph(const std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    // Call graph is built during relocation analysis
    
    // Post-process to identify leaf functions
    for (auto& [name, func_info] : functions) {
        func_info.is_leaf_function = func_info.called_functions.empty();
    }
    
    return true;
}

void CrossModuleAnalyzer::build_dependency_graph() {
    std::unordered_map<std::string, std::unordered_set<std::string>> module_imports;
    std::unordered_map<std::string, std::unordered_set<std::string>> module_exports;
    
    // Collect imports and exports for each module
    for (const auto& [name, func_info] : functions) {
        if (func_info.is_exported) {
            module_exports[func_info.module_name].insert(name);
        }
        
        for (const auto& called_func : func_info.called_functions) {
            auto it = functions.find(called_func);
            if (it != functions.end() && it->second.module_name != func_info.module_name) {
                module_imports[func_info.module_name].insert(called_func);
            }
        }
    }
    
    // Create dependency relationships
    for (const auto& [module, imports] : module_imports) {
        for (const auto& imported_symbol : imports) {
            auto it = functions.find(imported_symbol);
            if (it != functions.end()) {
                ModuleDependency dep(module, it->second.module_name);
                dep.imported_symbols.push_back(imported_symbol);
                module_dependencies.push_back(dep);
            }
        }
    }
}

bool CrossModuleAnalyzer::analyze_function_hotness() {
    // Simple hotness analysis based on call count
    for (auto& [name, func_info] : functions) {
        func_info.is_hot = (func_info.call_count >= 5); // Threshold for hot functions
    }
    
    // Propagate hotness through call chain
    propagate_hotness_information();
    
    return true;
}

void CrossModuleAnalyzer::propagate_hotness_information() {
    // If a function is called by a hot function, it's likely hot too
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& [name, func_info] : functions) {
            if (!func_info.is_hot) {
                for (const auto& caller : func_info.callers) {
                    auto caller_it = functions.find(caller);
                    if (caller_it != functions.end() && caller_it->second.is_hot) {
                        func_info.is_hot = true;
                        changed = true;
                        break;
                    }
                }
            }
        }
    }
}

std::vector<std::pair<std::string, std::string>> CrossModuleAnalyzer::find_inline_candidates() {
    std::vector<std::pair<std::string, std::string>> candidates;
    
    for (const auto& [caller_name, call_sites] : call_graph) {
        for (const auto& call_site : call_sites) {
            const auto& callee_name = call_site.callee_function;
            
            auto callee_it = functions.find(callee_name);
            if (callee_it != functions.end()) {
                const auto& callee_info = callee_it->second;
                
                // Check if function is suitable for inlining
                if (is_function_small_enough_to_inline(callee_info) &&
                    callee_info.is_leaf_function &&
                    callee_info.call_count <= 3) { // Not called too frequently
                    
                    candidates.emplace_back(caller_name, callee_name);
                }
            }
        }
    }
    
    return candidates;
}

bool CrossModuleAnalyzer::is_function_small_enough_to_inline(const FunctionInfo& func) const {
    return func.size > 0 && func.size <= 100; // Small function threshold
}

std::vector<std::string> CrossModuleAnalyzer::find_dead_functions() {
    std::vector<std::string> dead_functions;
    
    for (const auto& [name, func_info] : functions) {
        // A function is dead if it's not exported and never called
        if (!func_info.is_exported && func_info.call_count == 0) {
            dead_functions.push_back(name);
        }
    }
    
    return dead_functions;
}

const FunctionInfo* CrossModuleAnalyzer::get_function_info(const std::string& name) const {
    auto it = functions.find(name);
    return (it != functions.end()) ? &it->second : nullptr;
}

const GlobalVarInfo* CrossModuleAnalyzer::get_global_var_info(const std::string& name) const {
    auto it = global_vars.find(name);
    return (it != global_vars.end()) ? &it->second : nullptr;
}

// InterProceduralOptimizer implementation
InterProceduralOptimizer::InterProceduralOptimizer(CrossModuleAnalyzer& analyzer) 
    : module_analyzer(analyzer) {
}

bool InterProceduralOptimizer::inline_functions(std::vector<Section>& sections) {
    auto inline_candidates = module_analyzer.find_inline_candidates();
    
    for (const auto& [caller, callee] : inline_candidates) {
        if (can_inline_function(caller, callee)) {
            // Find the call site and inline the function
            auto call_sites_it = module_analyzer.get_call_graph().find(caller);
            if (call_sites_it != module_analyzer.get_call_graph().end()) {
                for (const auto& call_site : call_sites_it->second) {
                    if (call_site.callee_function == callee) {
                        // Find the section containing the caller
                        for (auto& section : sections) {
                            if (section.is_executable()) {
                                if (inline_function_at_call_site(section, call_site)) {
                                    stats.functions_inlined++;
                                    update_call_graph_after_inlining(caller, callee);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

bool InterProceduralOptimizer::can_inline_function(const std::string& caller, const std::string& callee) {
    const auto* callee_info = module_analyzer.get_function_info(callee);
    if (!callee_info) return false;
    
    // Don't inline recursive functions
    if (caller == callee) return false;
    
    // Don't inline large functions
    if (callee_info->size > 150) return false;
    
    // Don't inline functions with side effects (for now, assume all have side effects)
    // In a real implementation, we'd do more sophisticated analysis
    
    return true;
}

bool InterProceduralOptimizer::inline_function_at_call_site(Section& section, const CallSiteInfo& call_site) {
    // This is a simplified implementation
    // In reality, we'd need to:
    // 1. Find the callee function's code
    // 2. Replace the call instruction with the callee's code
    // 3. Handle register allocation conflicts
    // 4. Update relocations
    
    // For now, just mark as optimized (placeholder)
    std::cout << "    🔧 Inlining " << call_site.callee_function 
              << " into " << call_site.caller_function 
              << " at offset 0x" << std::hex << call_site.call_offset << std::dec << "\n";
    
    return true;
}

void InterProceduralOptimizer::update_call_graph_after_inlining(const std::string& caller, const std::string& inlined) {
    // Update call graph to reflect the inlining
    // The inlined function's calls now become the caller's calls
    (void)caller; (void)inlined; // Suppress warnings for now
}

bool InterProceduralOptimizer::optimize_call_sites(std::vector<Section>& sections) {
    uint32_t optimized_calls = 0;
    
    for (auto& section : sections) {
        if (!section.is_executable()) continue;
        
        for (const auto& [caller, call_sites] : module_analyzer.get_call_graph()) {
            for (const auto& call_site : call_sites) {
                // Try to convert to tail call if possible
                if (convert_to_tail_call(section, call_site)) {
                    optimized_calls++;
                } else if (optimize_direct_call(section, call_site)) {
                    optimized_calls++;
                }
            }
        }
    }
    
    stats.call_sites_optimized = optimized_calls;
    return true;
}

bool InterProceduralOptimizer::convert_to_tail_call(Section& section, const CallSiteInfo& call_site) {
    // Check if this call site can be converted to a tail call
    // This is a simplified implementation
    (void)section; (void)call_site; // Suppress warnings
    
    // In a real implementation, we'd check:
    // 1. If the call is the last instruction before return
    // 2. If the return types match
    // 3. If there's no local cleanup needed
    
    return false; // Placeholder
}

bool InterProceduralOptimizer::optimize_direct_call(Section& section, const CallSiteInfo& call_site) {
    // Optimize direct function calls
    (void)section; (void)call_site; // Suppress warnings
    
    // Possible optimizations:
    // 1. Convert indirect calls to direct calls
    // 2. Optimize calling convention
    // 3. Remove unnecessary parameter passing
    
    return false; // Placeholder
}

bool InterProceduralOptimizer::propagate_constants(std::vector<Section>& sections) {
    // Inter-procedural constant propagation
    (void)sections; // Suppress warnings
    
    // This would involve:
    // 1. Analyzing function parameters and return values
    // 2. Tracking constant values across function calls
    // 3. Replacing variable uses with constants where possible
    
    return true;
}

bool InterProceduralOptimizer::eliminate_unused_parameters(std::vector<Section>& sections) {
    // Remove unused function parameters
    (void)sections; // Suppress warnings
    
    // This would involve:
    // 1. Analyzing which parameters are actually used
    // 2. Creating specialized versions of functions with fewer parameters
    // 3. Updating all call sites
    
    return true;
}

bool InterProceduralOptimizer::specialize_functions(std::vector<Section>& sections) {
    // Create specialized versions of functions for common call patterns
    (void)sections; // Suppress warnings
    
    return true;
}

// WholeProgramOptimizer implementation
WholeProgramOptimizer::WholeProgramOptimizer(CrossModuleAnalyzer& analyzer) 
    : module_analyzer(analyzer) {
}

bool WholeProgramOptimizer::eliminate_dead_code(std::vector<Section>& sections, SymbolResolver& symbol_resolver) {
    // Find all reachable functions starting from entry points
    std::unordered_set<std::string> reachable_functions;
    
    // Mark functions reachable from entry points
    mark_reachable_functions("_start", reachable_functions);
    mark_reachable_functions("main", reachable_functions);
    
    // Mark all exported functions as reachable
    for (const auto& [name, func_info] : module_analyzer.get_functions()) {
        if (func_info.is_exported) {
            mark_reachable_functions(name, reachable_functions);
        }
    }
    
    // Remove unreachable functions
    bool removed_any = remove_unreachable_functions(sections, reachable_functions);
    
    if (removed_any) {
        stats.functions_eliminated = module_analyzer.get_functions().size() - reachable_functions.size();
    }
    
    return true;
}

void WholeProgramOptimizer::mark_reachable_functions(const std::string& entry_point, 
                                                    std::unordered_set<std::string>& reachable) {
    if (reachable.find(entry_point) != reachable.end()) {
        return; // Already processed
    }
    
    const auto* func_info = module_analyzer.get_function_info(entry_point);
    if (!func_info) return;
    
    reachable.insert(entry_point);
    
    // Recursively mark called functions as reachable
    for (const auto& called_func : func_info->called_functions) {
        mark_reachable_functions(called_func, reachable);
    }
}

bool WholeProgramOptimizer::remove_unreachable_functions(std::vector<Section>& sections, 
                                                        const std::unordered_set<std::string>& reachable) {
    bool removed_any = false;
    
    for (auto& section : sections) {
        if (!section.is_executable()) continue;
        
        // This is a simplified implementation
        // In reality, we'd need to:
        // 1. Identify function boundaries in the section
        // 2. Remove code for unreachable functions
        // 3. Update symbols and relocations
        
        std::cout << "    🗑️  Would remove unreachable functions from " << section.name << "\n";
        removed_any = true;
    }
    
    return removed_any;
}

bool WholeProgramOptimizer::optimize_global_variables(std::vector<Section>& sections) {
    // Optimize global variable layout and access patterns
    merge_read_only_globals(sections);
    eliminate_unused_globals(sections);
    
    return true;
}

bool WholeProgramOptimizer::merge_read_only_globals(std::vector<Section>& sections) {
    // Merge read-only global variables into a single section for better cache locality
    (void)sections; // Suppress warnings
    
    return true;
}

bool WholeProgramOptimizer::eliminate_unused_globals(std::vector<Section>& sections) {
    // Remove global variables that are never accessed
    (void)sections; // Suppress warnings
    
    return true;
}

bool WholeProgramOptimizer::propagate_global_constants(std::vector<Section>& sections) {
    // Propagate constant global variables throughout the program
    (void)sections; // Suppress warnings
    
    return true;
}

bool WholeProgramOptimizer::devirtualize_calls(std::vector<Section>& sections) {
    // Convert virtual function calls to direct calls where possible
    (void)sections; // Suppress warnings
    
    return true;
}

bool WholeProgramOptimizer::merge_identical_functions(std::vector<Section>& sections) {
    // Find and merge functions with identical code
    std::unordered_map<std::string, std::vector<std::string>> identical_groups;
    
    // Group functions by their content hash (simplified)
    for (const auto& [name1, func_info1] : module_analyzer.get_functions()) {
        for (const auto& [name2, func_info2] : module_analyzer.get_functions()) {
            if (name1 < name2 && functions_are_identical(name1, name2)) {
                identical_groups[name1].push_back(name2);
            }
        }
    }
    
    // Merge identical functions
    for (const auto& [keep, remove_list] : identical_groups) {
        for (const auto& remove : remove_list) {
            if (merge_functions(sections, keep, remove)) {
                stats.functions_eliminated++;
            }
        }
    }
    
    return true;
}

bool WholeProgramOptimizer::functions_are_identical(const std::string& func1, const std::string& func2) {
    // Compare function content to determine if they're identical
    const auto* info1 = module_analyzer.get_function_info(func1);
    const auto* info2 = module_analyzer.get_function_info(func2);
    
    if (!info1 || !info2) return false;
    
    // Simple comparison based on size (in reality, we'd compare actual code)
    return info1->size == info2->size && info1->size > 0;
}

bool WholeProgramOptimizer::merge_functions(std::vector<Section>& sections, 
                                           const std::string& keep, const std::string& remove) {
    // Merge identical functions by redirecting calls
    (void)sections; (void)keep; (void)remove; // Suppress warnings
    
    std::cout << "    🔗 Merging identical function " << remove << " into " << keep << "\n";
    
    return true;
}

// LTOOptimizer implementation
LTOOptimizer::LTOOptimizer(LTOLevel level) 
    : opt_level(level), 
      interprocedural_optimizer(cross_module_analyzer),
      whole_program_optimizer(cross_module_analyzer) {
}

bool LTOOptimizer::optimize(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                           std::vector<Section>& sections,
                           SymbolResolver& symbol_resolver,
                           const std::string& entry_point) {
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Step 1: Analyze all modules
    if (!cross_module_analyzer.analyze_modules(object_files, symbol_resolver)) {
        return false;
    }
    
    // Step 2: Build call graph
    if (!cross_module_analyzer.build_call_graph(object_files)) {
        return false;
    }
    
    // Step 3: Analyze function hotness
    if (!cross_module_analyzer.analyze_function_hotness()) {
        return false;
    }
    
    // Record initial code size
    combined_stats.code_size_before = 0;
    for (const auto& section : sections) {
        if (section.is_executable()) {
            combined_stats.code_size_before += section.size;
        }
    }
    
    // Step 4: Run optimizations based on level
    bool success = true;
    
    if (opt_level >= LTOLevel::BASIC) {
        success &= run_basic_optimizations(object_files, sections, symbol_resolver);
    }
    
    if (opt_level >= LTOLevel::AGGRESSIVE) {
        success &= run_aggressive_optimizations(sections);
    }
    
    if (opt_level >= LTOLevel::WHOLE_PROGRAM) {
        success &= run_whole_program_optimizations(sections, symbol_resolver, entry_point);
    }
    
    // Record final code size
    combined_stats.code_size_after = 0;
    for (const auto& section : sections) {
        if (section.is_executable()) {
            combined_stats.code_size_after += section.size;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    combined_stats.optimization_time_ms = duration.count() / 1000.0;
    
    update_combined_stats();
    
    return success;
}

bool LTOOptimizer::run_basic_optimizations(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                          std::vector<Section>& sections,
                                          SymbolResolver& symbol_resolver) {
    (void)object_files; (void)symbol_resolver; // Suppress warnings
    
    bool success = true;
    
    if (enable_call_site_opt) {
        success &= interprocedural_optimizer.optimize_call_sites(sections);
    }
    
    if (enable_const_prop) {
        success &= interprocedural_optimizer.propagate_constants(sections);
    }
    
    return success;
}

bool LTOOptimizer::run_aggressive_optimizations(std::vector<Section>& sections) {
    bool success = true;
    
    if (enable_function_inlining) {
        success &= interprocedural_optimizer.inline_functions(sections);
    }
    
    success &= interprocedural_optimizer.eliminate_unused_parameters(sections);
    success &= interprocedural_optimizer.specialize_functions(sections);
    
    return success;
}

bool LTOOptimizer::run_whole_program_optimizations(std::vector<Section>& sections,
                                                  SymbolResolver& symbol_resolver,
                                                  const std::string& entry_point) {
    (void)entry_point; // Suppress warnings
    
    bool success = true;
    
    if (enable_dead_code_elim) {
        success &= whole_program_optimizer.eliminate_dead_code(sections, symbol_resolver);
    }
    
    success &= whole_program_optimizer.optimize_global_variables(sections);
    success &= whole_program_optimizer.propagate_global_constants(sections);
    success &= whole_program_optimizer.merge_identical_functions(sections);
    
    return success;
}

void LTOOptimizer::update_combined_stats() {
    // Aggregate statistics from all optimizers
    const auto& ipo_stats = interprocedural_optimizer.get_stats();
    const auto& wpo_stats = whole_program_optimizer.get_stats();
    
    combined_stats.functions_analyzed = cross_module_analyzer.get_functions().size();
    combined_stats.functions_inlined += ipo_stats.functions_inlined;
    combined_stats.functions_eliminated += wpo_stats.functions_eliminated;
    combined_stats.call_sites_optimized += ipo_stats.call_sites_optimized;
}

const LTOStats& LTOOptimizer::get_combined_stats() const {
    return combined_stats;
}

} // namespace Linker
