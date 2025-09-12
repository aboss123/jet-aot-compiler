#pragma once
#include "standalone_linker.h"
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace Linker {

// Section merger for combining sections from multiple object files
class SectionMerger {
public:
    // Merged section information
    struct MergedSection {
        std::string name;
        SectionType type;
        uint64_t flags;
        uint64_t alignment;
        std::vector<uint8_t> data;
        std::vector<Relocation> relocations;
        
        // Track which object files contributed to this section
        struct Contribution {
            ObjectFile* obj_file;
            uint32_t original_section_index;
            uint64_t offset_in_merged;  // Offset where this contribution starts
            uint64_t size;
        };
        std::vector<Contribution> contributions;
        
        MergedSection(const std::string& n, SectionType t) : name(n), type(t), flags(0), alignment(1) {}
    };
    
    SectionMerger() = default;
    ~SectionMerger() = default;
    
    // Main merging interface
    bool merge_sections(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                       std::vector<MergedSection>& merged_sections);
    
    // Section compatibility checking
    bool are_sections_compatible(const Section& section1, const Section& section2);
    
    // Get merged section by name
    MergedSection* get_merged_section(const std::string& name, 
                                    std::vector<MergedSection>& merged_sections);
    
    // Symbol address adjustment for merged sections
    void adjust_symbol_addresses(const std::vector<MergedSection>& merged_sections,
                               const std::vector<std::unique_ptr<ObjectFile>>& object_files);
    
    // Relocation adjustment for merged sections
    void adjust_relocations(std::vector<MergedSection>& merged_sections,
                          const std::vector<std::unique_ptr<ObjectFile>>& object_files);
    
private:
    // Section grouping strategies
    std::string get_section_group_name(const Section& section);
    bool should_merge_sections(const Section& section1, const Section& section2);
    
    // Data merging
    bool merge_section_data(const std::vector<const Section*>& sections, MergedSection& merged);
    bool merge_string_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    bool merge_symbol_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    
    // Alignment handling
    uint64_t calculate_merged_alignment(const std::vector<const Section*>& sections);
    uint64_t align_offset(uint64_t offset, uint64_t alignment);
    
    // Deduplication
    bool deduplicate_string_data(MergedSection& merged);
    bool deduplicate_symbol_data(MergedSection& merged);
    
    // Section type specific merging
    bool merge_text_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    bool merge_data_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    bool merge_bss_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    bool merge_rodata_sections(const std::vector<const Section*>& sections, MergedSection& merged);
    
    // Helper functions
    void update_contribution_info(MergedSection& merged, const Section& section, 
                                ObjectFile* obj_file, uint32_t section_index);
};

// Cross-file symbol resolver for handling symbols across merged sections
class CrossFileResolver {
public:
    CrossFileResolver() = default;
    ~CrossFileResolver() = default;
    
    // Resolve symbols across merged sections
    bool resolve_cross_file_symbols(const std::vector<SectionMerger::MergedSection>& merged_sections,
                                   const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                   SymbolResolver& symbol_resolver);
    
    // Handle duplicate symbols across files
    bool resolve_duplicate_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                 SymbolResolver& symbol_resolver);
    
    // Update symbol addresses after merging
    bool update_merged_symbol_addresses(const std::vector<SectionMerger::MergedSection>& merged_sections,
                                      const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                      SymbolResolver& symbol_resolver);
    
private:
    // Symbol conflict resolution
    enum class ConflictResolution {
        KEEP_FIRST,     // Keep the first definition found
        KEEP_GLOBAL,    // Prefer global over weak/local
        KEEP_STRONG,    // Prefer non-weak symbols
        ERROR           // Report as error
    };
    
    ConflictResolution determine_conflict_resolution(const Symbol& sym1, const Symbol& sym2);
    bool resolve_symbol_conflict(const std::string& symbol_name,
                               const std::vector<std::pair<ObjectFile*, Symbol*>>& definitions,
                               SymbolResolver& resolver);
    
    // Address calculation helpers
    uint64_t calculate_symbol_address_in_merged_section(const Symbol& symbol,
                                                       const SectionMerger::MergedSection& merged_section,
                                                       ObjectFile* source_file);
};

} // namespace Linker
