#include "standalone_linker.h"
#include "relocation_engine.h"
#include "elf_object_parser.h"
#include "section_merger.h"
#include "dynamic_linker.h"
#include "lto_optimizer.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstring>

namespace Linker {

// ObjectFile implementation
Section* ObjectFile::get_section(const std::string& name) {
    auto it = section_name_map.find(name);
    if (it != section_name_map.end() && it->second < sections.size()) {
        return &sections[it->second];
    }
    return nullptr;
}

Symbol* ObjectFile::get_symbol(const std::string& name) {
    auto it = symbol_name_map.find(name);
    if (it != symbol_name_map.end() && it->second < symbols.size()) {
        return &symbols[it->second];
    }
    return nullptr;
}

uint32_t ObjectFile::add_section(const Section& section) {
    uint32_t index = static_cast<uint32_t>(sections.size());
    sections.push_back(section);
    section_name_map[section.name] = index;
    return index;
}

uint32_t ObjectFile::add_symbol(const Symbol& symbol) {
    uint32_t index = static_cast<uint32_t>(symbols.size());
    symbols.push_back(symbol);
    symbol_name_map[symbol.name] = index;
    return index;
}

// MemoryLayout implementation
void MemoryLayout::layout_sections(const std::vector<Section>& sections) {
    segments.clear();
    current_address = base_address;
    
    // Create segments based on section properties
    SegmentInfo text_segment, data_segment, bss_segment;
    
    // Text segment (executable sections)
    text_segment.virtual_address = current_address;
    text_segment.file_offset = 0x1000; // Standard offset
    text_segment.flags = 0x5; // Read + Execute
    
    // Data segment (writable sections)
    data_segment.flags = 0x6; // Read + Write
    
    // BSS segment (uninitialized data)
    bss_segment.flags = 0x6; // Read + Write
    
    uint64_t text_size = 0, data_size = 0, bss_size = 0;
    
    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& section = sections[i];
        
        if (!section.is_allocatable()) {
            continue; // Skip non-allocatable sections
        }
        
        if (section.is_executable()) {
            text_segment.section_indices.push_back(static_cast<uint32_t>(i));
            align_address(section.alignment);
            text_size += section.size;
        } else if (section.type == SectionType::NOBITS) {
            bss_segment.section_indices.push_back(static_cast<uint32_t>(i));
            bss_size += section.size;
        } else if (section.is_writable()) {
            data_segment.section_indices.push_back(static_cast<uint32_t>(i));
            align_address(section.alignment);
            data_size += section.size;
        } else {
            // Read-only data goes in text segment
            text_segment.section_indices.push_back(static_cast<uint32_t>(i));
            align_address(section.alignment);
            text_size += section.size;
        }
    }
    
    // Finalize segment sizes and addresses
    if (!text_segment.section_indices.empty()) {
        text_segment.memory_size = text_segment.file_size = text_size;
        segments.push_back(text_segment);
        current_address += text_size;
        align_address(0x1000); // Page align
    }
    
    if (!data_segment.section_indices.empty()) {
        data_segment.virtual_address = current_address;
        data_segment.file_offset = text_segment.file_offset + text_segment.file_size;
        data_segment.memory_size = data_segment.file_size = data_size;
        segments.push_back(data_segment);
        current_address += data_size;
    }
    
    if (!bss_segment.section_indices.empty()) {
        bss_segment.virtual_address = current_address;
        bss_segment.file_offset = data_segment.file_offset + data_segment.file_size;
        bss_segment.memory_size = bss_size;
        bss_segment.file_size = 0; // BSS has no file content
        segments.push_back(bss_segment);
    }
}

void MemoryLayout::align_address(uint64_t alignment) {
    if (alignment > 1) {
        current_address = (current_address + alignment - 1) & ~(alignment - 1);
    }
}

MemoryLayout::SegmentInfo* MemoryLayout::get_segment_for_section(uint32_t section_index) {
    for (auto& segment : segments) {
        auto it = std::find(segment.section_indices.begin(), segment.section_indices.end(), section_index);
        if (it != segment.section_indices.end()) {
            return &segment;
        }
    }
    return nullptr;
}

// SymbolResolver implementation
void SymbolResolver::add_object_symbols(ObjectFile* obj_file) {
    for (const auto& symbol : obj_file->symbols) {
        if (symbol.binding == SymbolBinding::LOCAL) {
            continue; // Skip local symbols for now
        }
        
        if (symbol.defined) {
            // Defined symbol
            auto it = resolved_symbols.find(symbol.name);
            if (it != resolved_symbols.end()) {
                // Symbol conflict - handle based on binding
                if (symbol.binding == SymbolBinding::GLOBAL && 
                    it->second.type != SymbolType::NOTYPE) {
                    // Multiple definitions of global symbol - error
                    std::cerr << "Multiple definitions of symbol: " << symbol.name << std::endl;
                    continue;
                }
                if (symbol.binding == SymbolBinding::WEAK) {
                    continue; // Keep existing definition
                }
            }
            
            ResolvedSymbol resolved;
            resolved.name = symbol.name;
            resolved.address = symbol.value; // Will be adjusted during layout
            resolved.size = symbol.size;
            resolved.type = symbol.type;
            resolved.source_file = obj_file;
            resolved_symbols[symbol.name] = resolved;
            
            // Remove from undefined if it was there
            undefined_symbols.erase(symbol.name);
        } else {
            // Undefined symbol
            if (resolved_symbols.find(symbol.name) == resolved_symbols.end()) {
                undefined_symbols.insert(symbol.name);
            }
        }
    }
}

void SymbolResolver::add_external_symbol(const std::string& name, uint64_t address) {
    ResolvedSymbol resolved;
    resolved.name = name;
    resolved.address = address;
    resolved.type = SymbolType::FUNC; // Assume function for external symbols
    resolved.is_external = true;
    resolved_symbols[name] = resolved;
    
    // Remove from undefined
    undefined_symbols.erase(name);
}

bool SymbolResolver::resolve_all_symbols() {
    process_symbol_conflicts();
    return undefined_symbols.empty();
}

SymbolResolver::ResolvedSymbol* SymbolResolver::get_symbol(const std::string& name) {
    auto it = resolved_symbols.find(name);
    return (it != resolved_symbols.end()) ? &it->second : nullptr;
}

std::vector<std::string> SymbolResolver::get_undefined_symbols() const {
    return std::vector<std::string>(undefined_symbols.begin(), undefined_symbols.end());
}

void SymbolResolver::process_symbol_conflicts() {
    // Handle weak symbols and other conflicts
    // For now, just report conflicts
    std::unordered_map<std::string, int> symbol_counts;
    for (const auto& pair : resolved_symbols) {
        if (!pair.second.is_external) {
            symbol_counts[pair.first]++;
        }
    }
    
    for (const auto& pair : symbol_counts) {
        if (pair.second > 1) {
            std::cerr << "Warning: Multiple definitions of symbol " << pair.first << std::endl;
        }
    }
}

// StandaloneLinker implementation
StandaloneLinker::StandaloneLinker(Architecture arch, Platform platform) 
    : target_arch(arch), target_platform(platform) {
    
    // Set default library paths based on platform
    switch (platform) {
        case Platform::LINUX:
            library_paths.push_back("/lib64");
            library_paths.push_back("/usr/lib64");
            library_paths.push_back("/lib");
            library_paths.push_back("/usr/lib");
            break;
        case Platform::MACOS:
            library_paths.push_back("/usr/lib");
            library_paths.push_back("/System/Library/Frameworks");
            break;
        case Platform::WINDOWS:
            // TODO: Add Windows library paths
            break;
    }
}

bool StandaloneLinker::add_object_file(const std::string& filename) {
    auto obj_file = std::make_unique<ObjectFile>(filename);
    obj_file->arch = target_arch;
    obj_file->platform = target_platform;
    
    if (!parse_object_file(filename, obj_file.get())) {
        add_error("Failed to parse object file: " + filename);
        return false;
    }
    
    symbol_resolver.add_object_symbols(obj_file.get());
    object_files.push_back(std::move(obj_file));
    return true;
}

bool StandaloneLinker::add_object_data(const std::vector<uint8_t>& data, const std::string& name) {
    auto obj_file = std::make_unique<ObjectFile>(name);
    obj_file->arch = target_arch;
    obj_file->platform = target_platform;
    
    bool success = false;
    if (data.size() >= 4) {
        // Check for ELF magic
        if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            success = parse_elf_object(data, obj_file.get());
        }
        // Check for Mach-O magic
        else if ((data.size() >= 4) && 
                 ((*reinterpret_cast<const uint32_t*>(data.data()) == 0xFEEDFACF) || // MH_MAGIC_64
                  (*reinterpret_cast<const uint32_t*>(data.data()) == 0xCFFAEDFE))) { // MH_CIGAM_64
            success = parse_macho_object(data, obj_file.get());
        }
    }
    
    if (!success) {
        add_error("Failed to parse object data: " + name);
        return false;
    }
    
    symbol_resolver.add_object_symbols(obj_file.get());
    object_files.push_back(std::move(obj_file));
    return true;
}

bool StandaloneLinker::link() {
    clear_errors();
    
    // Step 1: Merge sections from multiple object files
    std::vector<SectionMerger::MergedSection> merged_sections;
    SectionMerger section_merger;
    if (!section_merger.merge_sections(object_files, merged_sections)) {
        add_error("Failed to merge sections from object files");
        return false;
    }
    
    // Step 2: Resolve cross-file symbols
    CrossFileResolver cross_file_resolver;
    if (!cross_file_resolver.resolve_cross_file_symbols(merged_sections, object_files, symbol_resolver)) {
        add_error("Failed to resolve cross-file symbols");
        return false;
    }
    
    // Step 3: Process dynamic linking if enabled
    std::vector<Section> dynamic_sections;
    if (enable_dynamic_linking) {
        DynamicLinker dynamic_linker(target_arch, target_platform);
        
        // Add library dependencies
        for (const auto& lib : libraries) {
            dynamic_linker.add_library_dependency(lib);
        }
        
        // Process dynamic symbols
        if (!dynamic_linker.process_dynamic_symbols(object_files, symbol_resolver)) {
            add_error("Failed to process dynamic symbols");
            return false;
        }
        
        // Generate dynamic sections (PLT, GOT, etc.)
        if (!dynamic_linker.generate_dynamic_sections(dynamic_sections, memory_layout.base_address)) {
            add_error("Failed to generate dynamic sections");
            return false;
        }
    }
    
    // Step 4: Resolve all symbols
    if (!symbol_resolver.resolve_all_symbols()) {
        auto undefined = symbol_resolver.get_undefined_symbols();
        
        if (enable_dynamic_linking) {
            // In dynamic linking mode, some undefined symbols are expected (from shared libraries)
            std::cout << "Dynamic linking mode: " << undefined.size() << " symbols will be resolved at runtime\n";
        } else {
            // In static linking mode, all symbols must be resolved
            for (const auto& sym : undefined) {
                add_error("Undefined symbol: " + sym);
            }
            return false;
        }
    }
    
    // Step 5: Layout merged sections in memory
    std::vector<Section> layout_sections;
    for (const auto& merged : merged_sections) {
        Section section(merged.name, merged.type);
        section.flags = merged.flags;
        section.alignment = merged.alignment;
        section.data = merged.data;
        section.relocations = merged.relocations;
        section.size = merged.data.size();
        layout_sections.push_back(section);
    }
    
    // Add dynamic sections to layout
    layout_sections.insert(layout_sections.end(), dynamic_sections.begin(), dynamic_sections.end());
    
    memory_layout.layout_sections(layout_sections);
    
    // Step 6: Generate final layout
    if (!generate_executable_layout()) {
        add_error("Failed to generate executable layout");
        return false;
    }
    
    // Step 7: Apply relocations
    if (!resolve_relocations()) {
        add_error("Failed to resolve relocations");
        return false;
    }
    
    // Step 8: Perform Link-Time Optimization if enabled
    if (lto_enabled && lto_optimizer) {
        std::cout << "🚀 Performing Link-Time Optimization...\n";
        if (!lto_optimizer->optimize(object_files, layout_sections, symbol_resolver, entry_symbol)) {
            add_error("Failed to perform link-time optimization");
            return false;
        }
        
        // Display LTO statistics
        const auto& lto_stats = lto_optimizer->get_combined_stats();
        std::cout << "📊 LTO Results:\n";
        std::cout << "   Functions analyzed: " << lto_stats.functions_analyzed << "\n";
        std::cout << "   Functions inlined: " << lto_stats.functions_inlined << "\n";
        std::cout << "   Functions eliminated: " << lto_stats.functions_eliminated << "\n";
        std::cout << "   Call sites optimized: " << lto_stats.call_sites_optimized << "\n";
        std::cout << "   Code size reduction: " << lto_stats.get_size_reduction_percent() << "%\n";
        std::cout << "   Optimization time: " << lto_stats.optimization_time_ms << " ms\n";
        
        // Update memory layout with optimized sections
        memory_layout.layout_sections(layout_sections);
    }
    
    return true;
}

void StandaloneLinker::enable_lto(LTOLevel level) {
    lto_enabled = true;
    lto_optimizer = std::make_unique<LTOOptimizer>(level);
}

void StandaloneLinker::set_lto_inline_threshold(uint32_t threshold) {
    if (lto_optimizer) {
        lto_optimizer->set_inline_threshold(threshold);
    }
}

bool StandaloneLinker::write_executable(const std::string& output_path) {
    if (has_errors()) {
        return false;
    }
    
    switch (target_platform) {
        case Platform::LINUX:
            return write_elf_executable(output_path);
        case Platform::MACOS:
            return write_macho_executable(output_path);
        case Platform::WINDOWS:
            add_error("Windows executable generation not yet implemented");
            return false;
        default:
            add_error("Unknown target platform");
            return false;
    }
}

bool StandaloneLinker::write_shared_library(const std::string& output_path) {
    add_error("Shared library generation not yet implemented");
    return false;
}

const std::vector<std::string>& StandaloneLinker::get_undefined_symbols() const {
    static std::vector<std::string> undefined = symbol_resolver.get_undefined_symbols();
    return undefined;
}

const SymbolResolver::ResolvedSymbol* StandaloneLinker::get_symbol_info(const std::string& name) const {
    return const_cast<SymbolResolver&>(symbol_resolver).get_symbol(name);
}

// Private implementation methods
bool StandaloneLinker::parse_object_file(const std::string& filename, ObjectFile* obj_file) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Read file into memory
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    file.close();
    
    // Parse based on file format
    if (data.size() >= 4) {
        // Check for ELF magic
        if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            return parse_elf_object(data, obj_file);
        }
        // Check for Mach-O magic
        else if ((*reinterpret_cast<const uint32_t*>(data.data()) == 0xFEEDFACF) || // MH_MAGIC_64
                 (*reinterpret_cast<const uint32_t*>(data.data()) == 0xCFFAEDFE)) {   // MH_CIGAM_64
            return parse_macho_object(data, obj_file);
        }
    }
    
    return false;
}

bool StandaloneLinker::parse_elf_object(const std::vector<uint8_t>& data, ObjectFile* obj_file) {
    ELFObjectParser parser;
    return parser.parse(data, obj_file);
}

bool StandaloneLinker::parse_macho_object(const std::vector<uint8_t>& data, ObjectFile* obj_file) {
    // Basic Mach-O parsing - simplified for now
    // TODO: Implement full Mach-O object file parsing
    
    if (data.size() < 32) { // Minimum Mach-O header size
        return false;
    }
    
    // For now, create a dummy text section
    Section text_section("__text", SectionType::PROGBITS);
    text_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC) | 
                        static_cast<uint64_t>(SectionFlags::EXECINSTR);
    text_section.alignment = 16;
    text_section.data = std::vector<uint8_t>(data.begin() + 32, data.end()); // Skip header
    text_section.size = text_section.data.size();
    
    obj_file->add_section(text_section);
    
    // Add a dummy symbol (with underscore prefix for macOS)
    Symbol main_symbol("_main", 0);
    main_symbol.binding = SymbolBinding::GLOBAL;
    main_symbol.type = SymbolType::FUNC;
    main_symbol.defined = true;
    main_symbol.section_index = 0;
    
    obj_file->add_symbol(main_symbol);
    
    return true;
}

bool StandaloneLinker::resolve_relocations() {
    RelocationEngine relocation_engine(target_arch);
    bool success = true;
    
    for (auto& obj_file : object_files) {
        for (auto& section : obj_file->sections) {
            if (section.relocations.empty()) {
                continue;
            }
            
            if (!relocation_engine.process_section_relocations(section, obj_file->symbols, 
                                                              memory_layout.base_address)) {
                add_error("Failed to process relocations in section: " + section.name);
                success = false;
            }
        }
    }
    
    return success;
}

bool StandaloneLinker::apply_relocation(const Relocation& reloc, Section& section, 
                                       const Symbol& symbol, uint64_t symbol_address) {
    // TODO: Implement architecture-specific relocation application
    return true;
}

bool StandaloneLinker::generate_executable_layout() {
    // Update symbol addresses based on memory layout
    for (auto& obj_file : object_files) {
        for (size_t i = 0; i < obj_file->sections.size(); ++i) {
            auto& section = obj_file->sections[i];
            if (!section.is_allocatable()) {
                continue;
            }
            
            // Find segment for this section
            auto* segment = memory_layout.get_segment_for_section(static_cast<uint32_t>(i));
            if (segment) {
                section.address = segment->virtual_address;
                // Update symbols in this section
                for (auto& symbol : obj_file->symbols) {
                    if (symbol.section_index == i && symbol.defined) {
                        auto* resolved = symbol_resolver.get_symbol(symbol.name);
                        if (resolved) {
                            resolved->address = section.address + symbol.value;
                        }
                    }
                }
            }
        }
    }
    
    return true;
}

bool StandaloneLinker::write_elf_executable(const std::string& output_path) {
    // TODO: Implement ELF executable generation using our ELFBuilder64
    add_error("ELF executable generation not yet implemented in standalone linker");
    return false;
}

bool StandaloneLinker::write_macho_executable(const std::string& output_path) {
    // TODO: Implement Mach-O executable generation using our MachOBuilder64
    add_error("Mach-O executable generation not yet implemented in standalone linker");
    return false;
}

void StandaloneLinker::add_error(const std::string& message) {
    error_messages.push_back(message);
    std::cerr << "Linker error: " << message << std::endl;
}

bool StandaloneLinker::is_valid_relocation_for_arch(RelocationType type) const {
    switch (target_arch) {
        case Architecture::X86_64:
            return (static_cast<int>(type) >= static_cast<int>(RelocationType::X86_64_NONE) &&
                    static_cast<int>(type) <= static_cast<int>(RelocationType::X86_64_GOTPCREL));
        case Architecture::ARM64:
            return (static_cast<int>(type) >= static_cast<int>(RelocationType::AARCH64_NONE) &&
                    static_cast<int>(type) <= static_cast<int>(RelocationType::AARCH64_LDST64_ABS_LO12_NC));
        default:
            return false;
    }
}

uint64_t StandaloneLinker::calculate_relocation_value(RelocationType type, uint64_t symbol_addr, 
                                                     uint64_t reloc_addr, int64_t addend) const {
    switch (type) {
        // x86_64 relocations
        case RelocationType::X86_64_64:
            return symbol_addr + addend;
        case RelocationType::X86_64_PC32:
            return symbol_addr + addend - reloc_addr;
        case RelocationType::X86_64_32:
            return symbol_addr + addend;
        case RelocationType::X86_64_32S:
            return symbol_addr + addend;
            
        // ARM64 relocations
        case RelocationType::AARCH64_ABS64:
            return symbol_addr + addend;
        case RelocationType::AARCH64_ABS32:
            return symbol_addr + addend;
        case RelocationType::AARCH64_CALL26:
        case RelocationType::AARCH64_JUMP26:
            return (symbol_addr + addend - reloc_addr) >> 2; // 26-bit word offset
            
        default:
            return 0;
    }
}

} // namespace Linker
