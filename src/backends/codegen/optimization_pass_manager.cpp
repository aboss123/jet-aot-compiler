#include "backends/codegen/optimization_passes.h"
#include <iostream>

namespace CodeGen {

void OptimizationPassManager::add_pass(std::unique_ptr<OptimizationPass> pass) {
    passes_.push_back(std::move(pass));
}

bool OptimizationPassManager::run_passes(IR::Module& module) {
    bool any_modified = false;
    pass_results_.clear();
    
    std::cout << "🚀 Running optimization passes...\n";
    std::cout << "================================\n";
    
    for (size_t i = 0; i < passes_.size(); ++i) {
        auto& pass = passes_[i];
        std::cout << "Pass " << (i + 1) << "/" << passes_.size() 
                  << ": " << pass->get_name() << "\n";
        
        // Run the pass
        bool modified = pass->run(module);
        
        if (modified) {
            std::cout << "  ✅ Modified IR\n";
            any_modified = true;
        } else {
            std::cout << "  ⚪ No changes\n";
        }
        
        // Store result
        std::string result = pass->get_name() + ": " + 
                           (modified ? "Modified" : "No changes");
        pass_results_.push_back(result);
        
        std::cout << "\n";
    }
    
    std::cout << "🎯 Optimization complete!\n";
    std::cout << "Total passes: " << passes_.size() << "\n";
    std::cout << "Passes that modified IR: " 
              << std::count_if(passes_.begin(), passes_.end(),
                              [](const auto& pass) { return pass->modified_ir(); })
              << "\n";
    
    return any_modified;
}

} // namespace CodeGen
