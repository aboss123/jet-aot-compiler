#include "section_merger.h"
#include <iostream>
#include <algorithm>
#include <unordered_map>
#include <cstring>

namespace Linker {

bool SectionMerger::merge_sections(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                  std::vector<MergedSection>& merged_sections) {
    
    // Group sections by name and compatibility
    std::unordered_map<std::string, std::vector<std::pair<ObjectFile*, const Section*>>> section_groups;
    
    for (const auto& obj_file : object_files) {
        for (size_t i = 0; i < obj_file->sections.size(); ++i) {
            const auto& section = obj_file->sections[i];
            
            // Skip empty sections and certain types
            if (section.type == SectionType::NULL_SECTION ||
                section.type == SectionType::SYMTAB ||
                section.type == SectionType::STRTAB) {
                continue;
            }
            
            std::string group_name = get_section_group_name(section);
            section_groups[group_name].emplace_back(obj_file.get(), &section);
        }
    }
    
    // Create merged sections
    for (const auto& group : section_groups) {
        const std::string& section_name = group.first;
        const auto& sections = group.second;
        
        if (sections.empty()) continue;
        
        // Check compatibility
        const Section* first_section = sections[0].second;
        bool compatible = true;
        for (size_t i = 1; i < sections.size(); ++i) {
            if (!are_sections_compatible(*first_section, *sections[i].second)) {
                std::cerr << "Incompatible sections with name: " << section_name << std::endl;
                compatible = false;
                break;
            }
        }
        
        if (!compatible) {
            return false;
        }
        
        // Create merged section
        MergedSection merged(section_name, first_section->type);
        merged.flags = first_section->flags;
        
        // Collect section pointers for merging
        std::vector<const Section*> section_ptrs;
        for (const auto& pair : sections) {
            section_ptrs.push_back(pair.second);
        }
        
        // Merge based on section type
        bool merge_success = false;
        if (section_name.find(".text") == 0 || first_section->is_executable()) {
            merge_success = merge_text_sections(section_ptrs, merged);
        } else if (section_name.find(".data") == 0 || section_name.find(".rodata") == 0) {
            merge_success = merge_data_sections(section_ptrs, merged);
        } else if (section_name.find(".bss") == 0 || first_section->type == SectionType::NOBITS) {
            merge_success = merge_bss_sections(section_ptrs, merged);
        } else {
            merge_success = merge_data_sections(section_ptrs, merged); // Default fallback
        }
        
        if (!merge_success) {
            std::cerr << "Failed to merge section: " << section_name << std::endl;
            return false;
        }
        
        // Add contribution information
        for (size_t i = 0; i < sections.size(); ++i) {
            ObjectFile* obj_file = sections[i].first;
            const Section* section = sections[i].second;
            
            // Find original section index
            uint32_t section_index = 0;
            for (size_t j = 0; j < obj_file->sections.size(); ++j) {
                if (&obj_file->sections[j] == section) {
                    section_index = static_cast<uint32_t>(j);
                    break;
                }
            }
            
            update_contribution_info(merged, *section, obj_file, section_index);
        }
        
        merged_sections.push_back(std::move(merged));
    }
    
    return true;
}

bool SectionMerger::are_sections_compatible(const Section& section1, const Section& section2) {
    // Must have same type
    if (section1.type != section2.type) {
        return false;
    }
    
    // Must have compatible flags
    uint64_t important_flags = static_cast<uint64_t>(SectionFlags::WRITE) |
                              static_cast<uint64_t>(SectionFlags::ALLOC) |
                              static_cast<uint64_t>(SectionFlags::EXECINSTR);
    
    if ((section1.flags & important_flags) != (section2.flags & important_flags)) {
        return false;
    }
    
    // Entry size must match for structured sections
    if (section1.entry_size != section2.entry_size) {
        return false;
    }
    
    return true;
}

SectionMerger::MergedSection* SectionMerger::get_merged_section(const std::string& name, 
                                               std::vector<MergedSection>& merged_sections) {
    for (auto& section : merged_sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

void SectionMerger::adjust_symbol_addresses(const std::vector<MergedSection>& merged_sections,
                                           const std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    
    for (const auto& obj_file : object_files) {
        for (auto& symbol : obj_file->symbols) {
            if (!symbol.defined || symbol.section_index >= obj_file->sections.size()) {
                continue;
            }
            
            const Section& original_section = obj_file->sections[symbol.section_index];
            
            // Find corresponding merged section
            for (const auto& merged : merged_sections) {
                for (const auto& contribution : merged.contributions) {
                    if (contribution.obj_file == obj_file.get() &&
                        contribution.original_section_index == symbol.section_index) {
                        
                        // Adjust symbol address
                        symbol.value = contribution.offset_in_merged + symbol.value;
                        break;
                    }
                }
            }
        }
    }
}

void SectionMerger::adjust_relocations(std::vector<MergedSection>& merged_sections,
                                     const std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    
    for (auto& merged : merged_sections) {
        for (auto& contribution : merged.contributions) {
            const Section& original_section = contribution.obj_file->sections[contribution.original_section_index];
            
            // Copy and adjust relocations
            for (const auto& reloc : original_section.relocations) {
                Relocation adjusted_reloc = reloc;
                adjusted_reloc.offset += contribution.offset_in_merged;
                merged.relocations.push_back(adjusted_reloc);
            }
        }
    }
}

std::string SectionMerger::get_section_group_name(const Section& section) {
    // Group sections by name, handling common patterns
    const std::string& name = section.name;
    
    // Handle numbered sections (.text.1, .text.2, etc.)
    size_t dot_pos = name.find_last_of('.');
    if (dot_pos != std::string::npos && dot_pos < name.length() - 1) {
        std::string suffix = name.substr(dot_pos + 1);
        bool is_number = std::all_of(suffix.begin(), suffix.end(), ::isdigit);
        if (is_number) {
            return name.substr(0, dot_pos);
        }
    }
    
    return name;
}

bool SectionMerger::should_merge_sections(const Section& section1, const Section& section2) {
    return get_section_group_name(section1) == get_section_group_name(section2) &&
           are_sections_compatible(section1, section2);
}

bool SectionMerger::merge_section_data(const std::vector<const Section*>& sections, MergedSection& merged) {
    merged.alignment = calculate_merged_alignment(sections);
    uint64_t current_offset = 0;
    
    for (const auto* section : sections) {
        // Align to section requirements
        current_offset = align_offset(current_offset, section->alignment);
        
        // Resize merged data if necessary
        if (current_offset + section->data.size() > merged.data.size()) {
            merged.data.resize(current_offset + section->data.size());
        }
        
        // Copy section data
        if (!section->data.empty()) {
            std::memcpy(merged.data.data() + current_offset, 
                       section->data.data(), 
                       section->data.size());
        }
        
        current_offset += section->data.size();
    }
    
    return true;
}

bool SectionMerger::merge_text_sections(const std::vector<const Section*>& sections, MergedSection& merged) {
    // Text sections need proper alignment for instructions
    merged.alignment = std::max(static_cast<uint64_t>(16), calculate_merged_alignment(sections));
    uint64_t current_offset = 0;
    
    for (const auto* section : sections) {
        // Align to instruction boundaries
        uint64_t alignment = std::max(section->alignment, static_cast<uint64_t>(4));
        current_offset = align_offset(current_offset, alignment);
        
        // Record contribution offset
        MergedSection::Contribution contribution;
        contribution.offset_in_merged = current_offset;
        contribution.size = section->data.size();
        
        // Resize and copy data
        if (current_offset + section->data.size() > merged.data.size()) {
            merged.data.resize(current_offset + section->data.size());
        }
        
        if (!section->data.empty()) {
            std::memcpy(merged.data.data() + current_offset, 
                       section->data.data(), 
                       section->data.size());
        }
        
        current_offset += section->data.size();
    }
    
    return true;
}

bool SectionMerger::merge_data_sections(const std::vector<const Section*>& sections, MergedSection& merged) {
    return merge_section_data(sections, merged);
}

bool SectionMerger::merge_bss_sections(const std::vector<const Section*>& sections, MergedSection& merged) {
    // BSS sections don't have data, just track size
    merged.alignment = calculate_merged_alignment(sections);
    uint64_t total_size = 0;
    
    for (const auto* section : sections) {
        total_size = align_offset(total_size, section->alignment);
        total_size += section->size;
    }
    
    // BSS sections have no data but we track the size
    merged.data.clear(); // Ensure no data
    
    return true;
}

bool SectionMerger::merge_rodata_sections(const std::vector<const Section*>& sections, MergedSection& merged) {
    return merge_section_data(sections, merged);
}

uint64_t SectionMerger::calculate_merged_alignment(const std::vector<const Section*>& sections) {
    uint64_t max_alignment = 1;
    for (const auto* section : sections) {
        max_alignment = std::max(max_alignment, section->alignment);
    }
    return max_alignment;
}

uint64_t SectionMerger::align_offset(uint64_t offset, uint64_t alignment) {
    if (alignment <= 1) return offset;
    return (offset + alignment - 1) & ~(alignment - 1);
}

void SectionMerger::update_contribution_info(MergedSection& merged, const Section& section, 
                                            ObjectFile* obj_file, uint32_t section_index) {
    MergedSection::Contribution contribution;
    contribution.obj_file = obj_file;
    contribution.original_section_index = section_index;
    contribution.size = section.data.size();
    
    // Calculate offset (this is a simplified version - real implementation would track during merging)
    contribution.offset_in_merged = merged.data.size() > 0 ? merged.data.size() - section.data.size() : 0;
    
    merged.contributions.push_back(contribution);
}

// CrossFileResolver implementation
bool CrossFileResolver::resolve_cross_file_symbols(const std::vector<SectionMerger::MergedSection>& merged_sections,
                                                  const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                                  SymbolResolver& symbol_resolver) {
    
    // First, handle duplicate symbol resolution
    if (!resolve_duplicate_symbols(object_files, symbol_resolver)) {
        return false;
    }
    
    // Update symbol addresses based on merged sections
    if (!update_merged_symbol_addresses(merged_sections, object_files, symbol_resolver)) {
        return false;
    }
    
    return true;
}

bool CrossFileResolver::resolve_duplicate_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                                 SymbolResolver& symbol_resolver) {
    
    // Collect all symbol definitions
    std::unordered_map<std::string, std::vector<std::pair<ObjectFile*, Symbol*>>> symbol_definitions;
    
    for (const auto& obj_file : object_files) {
        for (auto& symbol : obj_file->symbols) {
            if (symbol.defined && symbol.binding != SymbolBinding::LOCAL) {
                symbol_definitions[symbol.name].emplace_back(obj_file.get(), &symbol);
            }
        }
    }
    
    // Resolve conflicts
    for (const auto& pair : symbol_definitions) {
        const std::string& symbol_name = pair.first;
        const auto& definitions = pair.second;
        
        if (definitions.size() > 1) {
            if (!resolve_symbol_conflict(symbol_name, definitions, symbol_resolver)) {
                return false;
            }
        }
    }
    
    return true;
}

bool CrossFileResolver::update_merged_symbol_addresses(const std::vector<SectionMerger::MergedSection>& merged_sections,
                                                     const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                                     SymbolResolver& symbol_resolver) {
    
    for (const auto& obj_file : object_files) {
        for (const auto& symbol : obj_file->symbols) {
            if (!symbol.defined) continue;
            
            // Find the merged section this symbol belongs to
            if (symbol.section_index < obj_file->sections.size()) {
                const Section& original_section = obj_file->sections[symbol.section_index];
                
                for (const auto& merged : merged_sections) {
                    for (const auto& contribution : merged.contributions) {
                        if (contribution.obj_file == obj_file.get() &&
                            contribution.original_section_index == symbol.section_index) {
                            
                            // Calculate new address
                            uint64_t new_address = calculate_symbol_address_in_merged_section(
                                symbol, merged, obj_file.get());
                            
                            // Update in symbol resolver
                            auto* resolved = symbol_resolver.get_symbol(symbol.name);
                            if (resolved) {
                                resolved->address = new_address;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

CrossFileResolver::ConflictResolution 
CrossFileResolver::determine_conflict_resolution(const Symbol& sym1, const Symbol& sym2) {
    
    // Global beats weak
    if (sym1.binding == SymbolBinding::GLOBAL && sym2.binding == SymbolBinding::WEAK) {
        return ConflictResolution::KEEP_FIRST;
    }
    if (sym2.binding == SymbolBinding::GLOBAL && sym1.binding == SymbolBinding::WEAK) {
        return ConflictResolution::KEEP_GLOBAL;
    }
    
    // Both global - error
    if (sym1.binding == SymbolBinding::GLOBAL && sym2.binding == SymbolBinding::GLOBAL) {
        return ConflictResolution::ERROR;
    }
    
    // Both weak - keep first
    if (sym1.binding == SymbolBinding::WEAK && sym2.binding == SymbolBinding::WEAK) {
        return ConflictResolution::KEEP_FIRST;
    }
    
    return ConflictResolution::KEEP_FIRST;
}

bool CrossFileResolver::resolve_symbol_conflict(const std::string& symbol_name,
                                              const std::vector<std::pair<ObjectFile*, Symbol*>>& definitions,
                                              SymbolResolver& resolver) {
    
    if (definitions.empty()) return true;
    
    // Find the best definition
    const Symbol* best_symbol = definitions[0].second;
    ObjectFile* best_file = definitions[0].first;
    
    for (size_t i = 1; i < definitions.size(); ++i) {
        const Symbol* current = definitions[i].second;
        
        ConflictResolution resolution = determine_conflict_resolution(*best_symbol, *current);
        
        switch (resolution) {
            case ConflictResolution::KEEP_FIRST:
                // Keep current best
                break;
            case ConflictResolution::KEEP_GLOBAL:
            case ConflictResolution::KEEP_STRONG:
                best_symbol = current;
                best_file = definitions[i].first;
                break;
            case ConflictResolution::ERROR:
                std::cerr << "Multiple definitions of global symbol: " << symbol_name << std::endl;
                return false;
        }
    }
    
    // Update resolver with the chosen definition
    SymbolResolver::ResolvedSymbol resolved;
    resolved.name = symbol_name;
    resolved.address = best_symbol->value; // Will be updated later
    resolved.size = best_symbol->size;
    resolved.type = best_symbol->type;
    resolved.source_file = best_file;
    
    resolver.resolved_symbols[symbol_name] = resolved;
    
    return true;
}

uint64_t CrossFileResolver::calculate_symbol_address_in_merged_section(const Symbol& symbol,
                                                                     const SectionMerger::MergedSection& merged_section,
                                                                     ObjectFile* source_file) {
    
    // Find the contribution from the source file
    for (const auto& contribution : merged_section.contributions) {
        if (contribution.obj_file == source_file &&
            contribution.original_section_index == symbol.section_index) {
            
            return contribution.offset_in_merged + symbol.value;
        }
    }
    
    return symbol.value; // Fallback
}

} // namespace Linker
