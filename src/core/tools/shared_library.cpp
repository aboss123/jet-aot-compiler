#include "shared_library.h"
#include "elf_builder.h"
#include "section_merger.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <regex>

namespace Linker {

// PICGenerator implementation
PICGenerator::PICGenerator(Architecture arch) : target_arch(arch) {
}

bool PICGenerator::make_position_independent(std::vector<Section>& sections) {
    for (auto& section : sections) {
        if (section.is_executable() || section.name == ".data" || section.name == ".rodata") {
            if (target_arch == Architecture::X86_64) {
                if (!transform_x64_to_pic(section)) {
                    return false;
                }
            } else if (target_arch == Architecture::ARM64) {
                if (!transform_arm64_to_pic(section)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool PICGenerator::transform_x64_to_pic(Section& section) {
    // Convert absolute addressing to RIP-relative addressing for x86_64
    std::vector<uint8_t>& data = section.data;
    
    // Look for absolute memory references and convert to RIP-relative
    for (size_t i = 0; i < data.size() - 6; ++i) {
        // Look for MOV instructions with absolute addressing
        if (data[i] == 0x48 && data[i+1] == 0x8B) { // MOV r64, [abs]
            // Convert to MOV r64, [RIP + offset]
            if ((data[i+2] & 0xC0) == 0x00) { // Direct addressing mode
                data[i+2] = (data[i+2] & 0x38) | 0x05; // Convert to RIP-relative
                // The offset will be adjusted during relocation
            }
        }
        
        // Look for CALL instructions with absolute addressing
        if (data[i] == 0xE8) { // CALL rel32
            // Already relative, but ensure it's properly handled
            continue;
        }
        
        // Look for JMP instructions
        if (data[i] == 0xE9) { // JMP rel32
            // Already relative
            continue;
        }
    }
    
    return true;
}

bool PICGenerator::transform_arm64_to_pic(Section& section) {
    // ARM64 is naturally more position-independent friendly
    std::vector<uint8_t>& data = section.data;
    
    // Look for absolute addressing patterns and convert to PC-relative
    for (size_t i = 0; i < data.size() - 4; i += 4) {
        uint32_t* instr = reinterpret_cast<uint32_t*>(&data[i]);
        
        // Look for ADRP instructions (already PC-relative, good for PIC)
        if ((*instr & 0x9F000000) == 0x90000000) {
            // ADRP is already PC-relative, perfect for PIC
            continue;
        }
        
        // Look for LDR with absolute addressing
        if ((*instr & 0xFF000000) == 0x58000000) { // LDR Xt, [literal]
            // Convert to PC-relative if needed (already is for literal pool)
            continue;
        }
        
        // Look for direct branches
        if ((*instr & 0xFC000000) == 0x14000000) { // B (unconditional branch)
            // Already PC-relative
            continue;
        }
        
        if ((*instr & 0xFC000000) == 0x94000000) { // BL (branch with link)
            // Already PC-relative
            continue;
        }
    }
    
    return true;
}

bool PICGenerator::generate_pic_relocations(Section& section, const std::vector<Symbol>& symbols) {
    // Generate PIC-compatible relocations
    for (auto& reloc : section.relocations) {
        if (!is_pic_compatible(reloc)) {
            // Try to convert to PIC-compatible relocation
            if (is_absolute_relocation(reloc)) {
                // Convert absolute to relative addressing
                if (target_arch == Architecture::X86_64) {
                    if (reloc.type == RelocationType::X86_64_64) {
                        reloc.type = RelocationType::X86_64_PC32;
                    } else if (reloc.type == RelocationType::X86_64_32) {
                        reloc.type = RelocationType::X86_64_PC32;
                    }
                } else if (target_arch == Architecture::ARM64) {
                    if (reloc.type == RelocationType::AARCH64_ABS64) {
                        reloc.type = RelocationType::AARCH64_CALL26;
                    }
                }
            }
        }
    }
    
    return true;
}

bool PICGenerator::is_pic_compatible(const Relocation& reloc) {
    // Check if relocation type is compatible with PIC
    switch (reloc.type) {
        case RelocationType::X86_64_PC32:
        case RelocationType::X86_64_PLT32:
        case RelocationType::AARCH64_CALL26:
        case RelocationType::AARCH64_JUMP26:
            return true; // Relative relocations are PIC-friendly
            
        case RelocationType::X86_64_64:
        case RelocationType::X86_64_32:
        case RelocationType::AARCH64_ABS64:
        case RelocationType::AARCH64_ABS32:
            return false; // Absolute relocations are not PIC-friendly
            
        default:
            return true; // Assume other types are compatible
    }
}

bool PICGenerator::is_absolute_relocation(const Relocation& reloc) {
    return reloc.type == RelocationType::X86_64_64 || reloc.type == RelocationType::X86_64_32 ||
           reloc.type == RelocationType::AARCH64_ABS64 || reloc.type == RelocationType::AARCH64_ABS32;
}

// SymbolVersionManager implementation
void SymbolVersionManager::add_symbol_version(const std::string& symbol_name, const std::string& version) {
    SymbolVersion sym_version(symbol_name, version);
    sym_version.version_id = static_cast<uint32_t>(symbol_versions[symbol_name].size() + 1);
    
    symbol_versions[symbol_name].push_back(sym_version);
    
    // Set as default if it's the first version
    if (symbol_versions[symbol_name].size() == 1) {
        default_versions[symbol_name] = version;
        sym_version.is_default = true;
    }
}

void SymbolVersionManager::set_default_version(const std::string& symbol_name, const std::string& version) {
    default_versions[symbol_name] = version;
    
    // Update the is_default flag
    auto& versions = symbol_versions[symbol_name];
    for (auto& ver : versions) {
        ver.is_default = (ver.version_string == version);
    }
}

SymbolVersion* SymbolVersionManager::get_symbol_version(const std::string& symbol_name, const std::string& version) {
    auto it = symbol_versions.find(symbol_name);
    if (it == symbol_versions.end()) {
        return nullptr;
    }
    
    if (version.empty()) {
        // Return default version
        auto default_it = default_versions.find(symbol_name);
        if (default_it != default_versions.end()) {
            for (auto& ver : it->second) {
                if (ver.version_string == default_it->second) {
                    return &ver;
                }
            }
        }
        // Return first version if no default
        return it->second.empty() ? nullptr : &it->second[0];
    } else {
        // Return specific version
        for (auto& ver : it->second) {
            if (ver.version_string == version) {
                return &ver;
            }
        }
    }
    
    return nullptr;
}

bool SymbolVersionManager::generate_version_sections(std::vector<Section>& sections) {
    // Generate .gnu.version section
    Section version_section;
    if (!generate_gnu_version_section(version_section)) {
        return false;
    }
    if (!version_section.data.empty()) {
        sections.push_back(version_section);
    }
    
    // Generate .gnu.version_d section
    Section version_d_section;
    if (!generate_gnu_version_d_section(version_d_section)) {
        return false;
    }
    if (!version_d_section.data.empty()) {
        sections.push_back(version_d_section);
    }
    
    return true;
}

bool SymbolVersionManager::generate_gnu_version_section(Section& version_section) {
    version_section.name = ".gnu.version";
    version_section.type = SectionType::GNU_VERSYM;
    version_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    version_section.alignment = 2;
    version_section.entry_size = 2; // 16-bit version indices
    
    // Generate version indices for each symbol
    std::vector<uint16_t> version_indices;
    
    for (const auto& symbol_entry : symbol_versions) {
        for (const auto& version : symbol_entry.second) {
            version_indices.push_back(static_cast<uint16_t>(version.version_id));
        }
    }
    
    // Convert to byte data
    version_section.data.resize(version_indices.size() * 2);
    for (size_t i = 0; i < version_indices.size(); ++i) {
        *reinterpret_cast<uint16_t*>(&version_section.data[i * 2]) = version_indices[i];
    }
    
    version_section.size = version_section.data.size();
    return true;
}

bool SymbolVersionManager::generate_gnu_version_d_section(Section& version_d_section) {
    version_d_section.name = ".gnu.version_d";
    version_d_section.type = SectionType::GNU_VERDEF;
    version_d_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    version_d_section.alignment = 4;
    
    // Generate version definitions (simplified)
    std::vector<uint8_t> version_data;
    
    for (const auto& symbol_entry : symbol_versions) {
        for (const auto& version : symbol_entry.second) {
            // ELF version definition structure (simplified)
            struct {
                uint16_t vd_version = 1;    // Version of structure
                uint16_t vd_flags = 0;      // Flags
                uint16_t vd_ndx = 0;        // Version index
                uint16_t vd_cnt = 1;        // Number of associated aux entries
                uint32_t vd_hash = 0;       // Hash of version name
                uint32_t vd_aux = 20;       // Offset to aux entries
                uint32_t vd_next = 0;       // Offset to next version definition
            } ver_def;
            
            ver_def.vd_ndx = static_cast<uint16_t>(version.version_id);
            ver_def.vd_flags = version.is_default ? 1 : 0;
            
            // Simple hash of version string
            ver_def.vd_hash = std::hash<std::string>{}(version.version_string);
            
            // Append to data
            const uint8_t* ver_def_bytes = reinterpret_cast<const uint8_t*>(&ver_def);
            version_data.insert(version_data.end(), ver_def_bytes, ver_def_bytes + sizeof(ver_def));
        }
    }
    
    version_d_section.data = version_data;
    version_d_section.size = version_data.size();
    
    return true;
}

bool SymbolVersionManager::generate_gnu_version_r_section(Section& version_r_section) {
    // Generate version requirements section (for imported symbols)
    version_r_section.name = ".gnu.version_r";
    version_r_section.type = SectionType::GNU_VERNEED;
    version_r_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    version_r_section.alignment = 4;
    
    // For now, create empty section (would be populated with imported symbol requirements)
    version_r_section.data.clear();
    version_r_section.size = 0;
    
    return true;
}

// SharedLibraryBuilder implementation
SharedLibraryBuilder::SharedLibraryBuilder(Architecture arch, Platform platform) 
    : target_arch(arch), target_platform(platform), pic_generator(arch), dynamic_linker(arch, platform) {
    
    // Enable shared library mode in dynamic linker
    dynamic_linker.set_shared_library_mode(true);
}

void SharedLibraryBuilder::add_exported_symbol(const std::string& name, const std::string& version) {
    if (use_symbol_versioning && !version.empty()) {
        version_manager.add_symbol_version(name, version);
    }
    
    SymbolVersion exported_symbol(name, version.empty() ? library_version : version);
    library_info.exported_symbols.push_back(exported_symbol);
}

void SharedLibraryBuilder::add_dependency(const std::string& library_name) {
    auto it = std::find(library_info.dependencies.begin(), library_info.dependencies.end(), library_name);
    if (it == library_info.dependencies.end()) {
        library_info.dependencies.push_back(library_name);
    }
}

bool SharedLibraryBuilder::build_shared_library(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                               const std::string& output_path) {
    
    // Validate symbols for shared library
    if (!validate_shared_library_symbols(object_files)) {
        return false;
    }
    
    // Generate sections
    std::vector<Section> sections;
    if (!generate_shared_library_sections(object_files, sections)) {
        return false;
    }
    
    // Make sections position-independent
    if (!prepare_pic_sections(sections)) {
        return false;
    }
    
    // Generate symbol versioning sections
    if (use_symbol_versioning) {
        if (!version_manager.generate_version_sections(sections)) {
            return false;
        }
    }
    
    // Write shared library file
    if (target_platform == Platform::LINUX) {
        return write_elf_shared_library(sections, output_path);
    } else if (target_platform == Platform::MACOS) {
        return write_macho_shared_library(sections, output_path);
    }
    
    return false;
}

bool SharedLibraryBuilder::generate_shared_library_sections(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                                          std::vector<Section>& sections) {
    
    // Merge sections from object files
    SectionMerger section_merger;
    std::vector<SectionMerger::MergedSection> merged_sections;
    if (!section_merger.merge_sections(object_files, merged_sections)) {
        return false;
    }
    
    // Convert merged sections to regular sections
    for (const auto& merged : merged_sections) {
        Section section(merged.name, merged.type);
        section.flags = merged.flags;
        section.alignment = merged.alignment;
        section.data = merged.data;
        section.relocations = merged.relocations;
        section.size = merged.data.size();
        sections.push_back(section);
    }
    
    // Generate dynamic sections
    SymbolResolver symbol_resolver;
    for (const auto& obj_file : object_files) {
        symbol_resolver.add_object_symbols(obj_file.get());
    }
    
    if (!dynamic_linker.process_dynamic_symbols(object_files, symbol_resolver)) {
        return false;
    }
    
    std::vector<Section> dynamic_sections;
    if (!dynamic_linker.generate_dynamic_sections(dynamic_sections, 0x0)) {
        return false;
    }
    
    sections.insert(sections.end(), dynamic_sections.begin(), dynamic_sections.end());
    
    // Generate export table
    Section export_section;
    if (!generate_export_table(object_files, export_section)) {
        return false;
    }
    sections.push_back(export_section);
    
    // Generate SONAME section
    Section soname_section;
    if (!generate_soname_section(soname_section)) {
        return false;
    }
    sections.push_back(soname_section);
    
    return true;
}

bool SharedLibraryBuilder::prepare_pic_sections(std::vector<Section>& sections) {
    return pic_generator.make_position_independent(sections);
}

bool SharedLibraryBuilder::generate_export_table(const std::vector<std::unique_ptr<ObjectFile>>& object_files, 
                                                 Section& export_section) {
    export_section.name = ".export";
    export_section.type = SectionType::PROGBITS;
    export_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    export_section.alignment = 8;
    
    // Generate export table with exported symbols
    std::vector<uint8_t> export_data;
    
    for (const auto& exported_symbol : library_info.exported_symbols) {
        // Export table entry (simplified)
        struct {
            uint64_t name_offset = 0;
            uint64_t address = 0;
            uint32_t flags = 0;
            uint32_t version_id = 0;
        } export_entry;
        
        export_entry.name_offset = export_data.size(); // Would be proper string table offset
        
        // Find symbol in object files
        for (const auto& obj_file : object_files) {
            for (const auto& symbol : obj_file->symbols) {
                if (symbol.name == exported_symbol.name && symbol.defined) {
                    export_entry.address = symbol.value;
                    break;
                }
            }
        }
        
        const uint8_t* entry_bytes = reinterpret_cast<const uint8_t*>(&export_entry);
        export_data.insert(export_data.end(), entry_bytes, entry_bytes + sizeof(export_entry));
        
        // Add symbol name
        export_data.insert(export_data.end(), exported_symbol.name.begin(), exported_symbol.name.end());
        export_data.push_back(0); // Null terminator
    }
    
    export_section.data = export_data;
    export_section.size = export_data.size();
    
    return true;
}

bool SharedLibraryBuilder::generate_soname_section(Section& soname_section) {
    soname_section.name = ".soname";
    soname_section.type = SectionType::STRTAB;
    soname_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    soname_section.alignment = 1;
    
    // Store SONAME string
    soname_section.data.insert(soname_section.data.end(), 
                              library_info.soname.begin(), library_info.soname.end());
    soname_section.data.push_back(0); // Null terminator
    soname_section.size = soname_section.data.size();
    
    return true;
}

bool SharedLibraryBuilder::validate_shared_library_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files) {
    // Check that all exported symbols are defined
    for (const auto& exported_symbol : library_info.exported_symbols) {
        bool found = false;
        for (const auto& obj_file : object_files) {
            for (const auto& symbol : obj_file->symbols) {
                if (symbol.name == exported_symbol.name && symbol.defined) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        
        if (!found) {
            std::cerr << "Error: Exported symbol '" << exported_symbol.name << "' is not defined\n";
            return false;
        }
    }
    
    return true;
}

bool SharedLibraryBuilder::write_elf_shared_library(const std::vector<Section>& sections, const std::string& output_path) {
    // Create a simple shared library using ELFBuilder64
    ELFBuilder64 elf_builder;
    
    // Find .text section
    const Section* text_section = nullptr;
    const Section* data_section = nullptr;
    
    for (const auto& section : sections) {
        if (section.name == ".text") {
            text_section = &section;
        } else if (section.name == ".data") {
            data_section = &section;
        }
    }
    
    if (!text_section) {
        std::cerr << "Error: No .text section found for shared library\n";
        return false;
    }
    
    // Write as dynamic executable for now (shared library support would need ELFBuilder extension)
    ELFArch arch = (target_arch == Architecture::X86_64) ? ELFArch::X86_64 : ELFArch::ARM64;
    
    std::vector<std::string> libraries;
    for (const auto& dep : library_info.dependencies) {
        libraries.push_back(dep);
    }
    
    const char* interpreter = (target_arch == Architecture::X86_64) ? 
        "/lib64/ld-linux-x86-64.so.2" : "/lib/ld-linux-aarch64.so.1";
    
    return elf_builder.write_dynamic_executable(output_path.c_str(),
                                               text_section->data.data(),
                                               static_cast<uint32_t>(text_section->data.size()),
                                               libraries,
                                               interpreter,
                                               0,
                                               arch);
}

bool SharedLibraryBuilder::write_macho_shared_library(const std::vector<Section>& sections, const std::string& output_path) {
    // Mach-O shared library generation (simplified)
    std::ofstream file(output_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Write Mach-O header for shared library
    struct mach_header_64 {
        uint32_t magic;
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t reserved;
    } header;
    
    header.magic = 0xfeedfacf;      // MH_MAGIC_64
    header.cputype = (target_arch == Architecture::X86_64) ? 0x01000007 : 0x0100000c; // CPU_TYPE_X86_64 or CPU_TYPE_ARM64
    header.cpusubtype = 3;          // CPU_SUBTYPE_X86_64_ALL or CPU_SUBTYPE_ARM64_ALL
    header.filetype = 6;            // MH_DYLIB
    header.ncmds = 0;               // Number of load commands
    header.sizeofcmds = 0;          // Size of load commands
    header.flags = 0x00000085;      // MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL
    header.reserved = 0;
    
    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    // Write sections (simplified)
    for (const auto& section : sections) {
        file.write(reinterpret_cast<const char*>(section.data.data()), section.data.size());
    }
    
    file.close();
    return true;
}

// LibraryLoader implementation
LibraryLoader::LibraryLoader(Architecture arch, Platform platform) 
    : target_arch(arch), target_platform(platform) {
    
    // Add default library paths
    if (platform == Platform::LINUX) {
        library_paths = {"/lib", "/usr/lib", "/usr/local/lib", "/lib64", "/usr/lib64"};
    } else if (platform == Platform::MACOS) {
        library_paths = {"/usr/lib", "/usr/local/lib", "/System/Library/Frameworks"};
    }
}

bool LibraryLoader::load_library(const std::string& library_path) {
    // Find library file
    std::string full_path = find_library_file(library_path);
    if (full_path.empty()) {
        return false;
    }
    
    // Parse library metadata
    SharedLibraryInfo info;
    if (!parse_library_metadata(full_path, info)) {
        return false;
    }
    
    // Validate compatibility
    if (!validate_library_compatibility(info)) {
        return false;
    }
    
    // Load library
    info.base_address = calculate_load_address(0x7f0000000000ULL, info.size, 
                                              std::vector<SharedLibraryInfo>());
    
    // Store in loaded libraries
    loaded_libraries[info.soname] = info;
    
    // Update symbol cache
    update_symbol_cache(info);
    
    return true;
}

std::string LibraryLoader::find_library_file(const std::string& library_name) {
    // Try direct path first
    std::ifstream test_file(library_name);
    if (test_file.good()) {
        test_file.close();
        return library_name;
    }
    
    // Search in library paths
    std::vector<std::string> search_names = SharedLibraryUtils::generate_search_order(library_name);
    
    for (const auto& path : library_paths) {
        for (const auto& name : search_names) {
            std::string full_path = path + "/" + name;
            std::ifstream test_file(full_path);
            if (test_file.good()) {
                test_file.close();
                return full_path;
            }
        }
    }
    
    return ""; // Not found
}

bool LibraryLoader::parse_library_metadata(const std::string& library_path, SharedLibraryInfo& info) {
    // Parse library file to extract metadata (simplified)
    std::ifstream file(library_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read file header to determine format
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.close();
    
    info.real_name = library_path;
    info.soname = SharedLibraryUtils::extract_soname(library_path);
    info.is_position_independent = true; // Assume PIC for shared libraries
    
    // Would parse actual ELF/Mach-O metadata here
    return true;
}

void* LibraryLoader::resolve_symbol(const std::string& symbol_name, const std::string& version) {
    std::string lookup_key = symbol_name + (version.empty() ? "" : "@" + version);
    
    auto it = symbol_cache.find(lookup_key);
    if (it != symbol_cache.end()) {
        return it->second;
    }
    
    // Symbol not found in cache
    return nullptr;
}

bool LibraryLoader::validate_library_compatibility(const SharedLibraryInfo& info) {
    // Check architecture compatibility
    (void)info; // Suppress unused warning
    // Would check actual compatibility here
    return true;
}

void LibraryLoader::update_symbol_cache(const SharedLibraryInfo& info) {
    for (const auto& symbol : info.exported_symbols) {
        std::string key = symbol.name + "@" + symbol.version_string;
        // Would store actual symbol address here
        symbol_cache[key] = reinterpret_cast<void*>(info.base_address + 0x1000); // Placeholder
    }
}

SharedLibraryInfo* LibraryLoader::get_library_info(const std::string& library_name) {
    auto it = loaded_libraries.find(library_name);
    return (it != loaded_libraries.end()) ? &it->second : nullptr;
}

std::vector<std::string> LibraryLoader::get_loaded_libraries() const {
    std::vector<std::string> names;
    for (const auto& lib : loaded_libraries) {
        names.push_back(lib.first);
    }
    return names;
}

bool LibraryLoader::unload_library(const std::string& library_name) {
    auto it = loaded_libraries.find(library_name);
    if (it != loaded_libraries.end()) {
        loaded_libraries.erase(it);
        return true;
    }
    return false;
}

bool LibraryLoader::resolve_runtime_symbols(const std::vector<std::string>& undefined_symbols) {
    for (const auto& symbol : undefined_symbols) {
        if (resolve_symbol(symbol) == nullptr) {
            return false; // Symbol not found
        }
    }
    return true;
}

uint64_t LibraryLoader::calculate_load_address(uint64_t preferred_base, uint64_t size,
                                              const std::vector<SharedLibraryInfo>& loaded_libraries) {
    return SharedLibraryUtils::calculate_load_address(preferred_base, size, loaded_libraries);
}

// SharedLibraryUtils implementation
std::string SharedLibraryUtils::extract_soname(const std::string& library_path) {
    // Extract filename from path
    size_t last_slash = library_path.find_last_of("/\\");
    std::string filename = (last_slash == std::string::npos) ? library_path : library_path.substr(last_slash + 1);
    
    // Remove lib prefix if present
    if (filename.substr(0, 3) == "lib") {
        filename = filename.substr(3);
    }
    
    // Find first dot (version separator)
    size_t first_dot = filename.find('.');
    if (first_dot != std::string::npos) {
        return "lib" + filename.substr(0, first_dot) + ".so";
    }
    
    return "lib" + filename + ".so";
}

std::vector<std::string> SharedLibraryUtils::generate_search_order(const std::string& library_name) {
    std::vector<std::string> search_names;
    
    // Add original name
    search_names.push_back(library_name);
    
    // Add with lib prefix if not present
    if (library_name.substr(0, 3) != "lib") {
        search_names.push_back("lib" + library_name);
        search_names.push_back("lib" + library_name + ".so");
        search_names.push_back("lib" + library_name + ".dylib");
    }
    
    // Add .so extension if not present
    if (library_name.find(".so") == std::string::npos && library_name.find(".dylib") == std::string::npos) {
        search_names.push_back(library_name + ".so");
        search_names.push_back(library_name + ".dylib");
    }
    
    return search_names;
}

bool SharedLibraryUtils::is_valid_soname(const std::string& soname) {
    // Basic validation of SO name format
    std::regex soname_pattern(R"(lib[a-zA-Z0-9_+-]+\.so(\.[0-9]+)*)");
    return std::regex_match(soname, soname_pattern);
}

uint64_t SharedLibraryUtils::calculate_load_address(uint64_t preferred_base, uint64_t size,
                                                   const std::vector<SharedLibraryInfo>& loaded_libraries) {
    uint64_t address = preferred_base;
    
    // Find non-overlapping address
    bool overlap = true;
    while (overlap) {
        overlap = false;
        for (const auto& lib : loaded_libraries) {
            if (address < lib.base_address + lib.size && address + size > lib.base_address) {
                overlap = true;
                address = lib.base_address + lib.size;
                address = (address + 0xFFF) & ~0xFFFULL; // Align to page boundary
                break;
            }
        }
    }
    
    return address;
}

std::string SharedLibraryUtils::parse_version_from_soname(const std::string& soname) {
    // Extract version from SO name like "libc.so.6"
    size_t last_dot = soname.find_last_of('.');
    if (last_dot != std::string::npos && last_dot > 0) {
        return soname.substr(last_dot + 1);
    }
    return "1";
}

std::vector<std::string> SharedLibraryUtils::generate_compatible_names(const std::string& base_name, 
                                                                      const std::string& version) {
    std::vector<std::string> names;
    names.push_back(base_name + ".so." + version);
    names.push_back(base_name + ".so");
    names.push_back(base_name + ".dylib");
    return names;
}

bool SharedLibraryUtils::is_position_independent(const std::vector<Section>& sections) {
    // Check if sections contain position-independent code
    for (const auto& section : sections) {
        if (section.is_executable()) {
            // Check for absolute relocations (not PIC-friendly)
            for (const auto& reloc : section.relocations) {
                if (reloc.type == RelocationType::X86_64_64 || reloc.type == RelocationType::X86_64_32 ||
                    reloc.type == RelocationType::AARCH64_ABS64 || reloc.type == RelocationType::AARCH64_ABS32) {
                    return false;
                }
            }
        }
    }
    return true;
}

} // namespace Linker
