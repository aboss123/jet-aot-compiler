#pragma once
#include "standalone_linker.h"
#include "dynamic_linker.h"
#include <unordered_map>
#include <unordered_set>

namespace Linker {

// Forward declarations
class SharedLibraryBuilder;
class LibraryLoader;
class SymbolVersionManager;

// Symbol version information
struct SymbolVersion {
    std::string name;
    std::string version_string;
    uint32_t version_id;
    bool is_default = true;
    bool is_weak = false;
    
    SymbolVersion() = default;
    SymbolVersion(const std::string& n, const std::string& v) : name(n), version_string(v) {}
};

// Shared library metadata
struct SharedLibraryInfo {
    std::string soname;           // SO name (e.g., "libc.so.6")
    std::string real_name;        // Real filename (e.g., "libc-2.31.so")
    std::string linker_name;      // Linker name (e.g., "libc.so")
    uint64_t base_address = 0;
    uint64_t size = 0;
    std::vector<std::string> dependencies;
    std::vector<SymbolVersion> exported_symbols;
    std::vector<SymbolVersion> imported_symbols;
    bool is_position_independent = true;
    
    SharedLibraryInfo() = default;
    SharedLibraryInfo(const std::string& name) : soname(name), real_name(name), linker_name(name) {}
};

// Position Independent Code (PIC) generator
class PICGenerator {
public:
    PICGenerator(Architecture arch);
    ~PICGenerator() = default;
    
    // Convert sections to position-independent code
    bool make_position_independent(std::vector<Section>& sections);
    
    // Generate PIC-compatible relocations
    bool generate_pic_relocations(Section& section, const std::vector<Symbol>& symbols);
    
    // Check if relocation is PIC-compatible
    bool is_pic_compatible(const Relocation& reloc);
    
    // Convert absolute relocations to relative
    bool convert_to_relative_addressing(Section& section, std::vector<Relocation>& relocations);
    
private:
    Architecture target_arch;
    
    // Architecture-specific PIC transformations
    bool transform_x64_to_pic(Section& section);
    bool transform_arm64_to_pic(Section& section);
    
    // Helper functions
    bool is_absolute_relocation(const Relocation& reloc);
    bool can_convert_to_relative(const Relocation& reloc, uint64_t section_base);
};

// Symbol versioning manager
class SymbolVersionManager {
public:
    SymbolVersionManager() = default;
    ~SymbolVersionManager() = default;
    
    // Add symbol version
    void add_symbol_version(const std::string& symbol_name, const std::string& version);
    
    // Set default version for symbol
    void set_default_version(const std::string& symbol_name, const std::string& version);
    
    // Get symbol version
    SymbolVersion* get_symbol_version(const std::string& symbol_name, const std::string& version = "");
    
    // Generate version sections
    bool generate_version_sections(std::vector<Section>& sections);
    
    // Get all versions for symbol
    std::vector<SymbolVersion> get_symbol_versions(const std::string& symbol_name);
    
private:
    std::unordered_map<std::string, std::vector<SymbolVersion>> symbol_versions;
    std::unordered_map<std::string, std::string> default_versions;
    
    // Generate .gnu.version section
    bool generate_gnu_version_section(Section& version_section);
    
    // Generate .gnu.version_d section (version definitions)
    bool generate_gnu_version_d_section(Section& version_d_section);
    
    // Generate .gnu.version_r section (version requirements)
    bool generate_gnu_version_r_section(Section& version_r_section);
};

// Shared library builder
class SharedLibraryBuilder {
public:
    SharedLibraryBuilder(Architecture arch, Platform platform);
    ~SharedLibraryBuilder() = default;
    
    // Configuration
    void set_soname(const std::string& name) { library_info.soname = name; }
    void set_version(const std::string& version) { library_version = version; }
    void add_exported_symbol(const std::string& name, const std::string& version = "");
    void add_dependency(const std::string& library_name);
    
    // Build shared library
    bool build_shared_library(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                             const std::string& output_path);
    
    // Generate shared library sections
    bool generate_shared_library_sections(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                         std::vector<Section>& sections);
    
    // Get library information
    const SharedLibraryInfo& get_library_info() const { return library_info; }
    
    // Enable/disable features
    void enable_symbol_versioning(bool enabled) { use_symbol_versioning = enabled; }
    void enable_lazy_binding(bool enabled) { use_lazy_binding = enabled; }
    
private:
    Architecture target_arch;
    Platform target_platform;
    SharedLibraryInfo library_info;
    std::string library_version = "1.0";
    bool use_symbol_versioning = true;
    bool use_lazy_binding = true;
    
    PICGenerator pic_generator;
    SymbolVersionManager version_manager;
    DynamicLinker dynamic_linker;
    
    // Internal methods
    bool prepare_pic_sections(std::vector<Section>& sections);
    bool generate_export_table(const std::vector<std::unique_ptr<ObjectFile>>& object_files, Section& export_section);
    bool generate_soname_section(Section& soname_section);
    bool validate_shared_library_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files);
    bool write_elf_shared_library(const std::vector<Section>& sections, const std::string& output_path);
    bool write_macho_shared_library(const std::vector<Section>& sections, const std::string& output_path);
};

// Dynamic library loader interface
class LibraryLoader {
public:
    LibraryLoader(Architecture arch, Platform platform);
    ~LibraryLoader() = default;
    
    // Load shared library
    bool load_library(const std::string& library_path);
    
    // Resolve symbol from loaded libraries
    void* resolve_symbol(const std::string& symbol_name, const std::string& version = "");
    
    // Get library information
    SharedLibraryInfo* get_library_info(const std::string& library_name);
    
    // List loaded libraries
    std::vector<std::string> get_loaded_libraries() const;
    
    // Unload library
    bool unload_library(const std::string& library_name);
    
    // Set library search paths
    void add_library_path(const std::string& path) { library_paths.push_back(path); }
    void set_library_paths(const std::vector<std::string>& paths) { library_paths = paths; }
    
    // Runtime symbol resolution
    bool resolve_runtime_symbols(const std::vector<std::string>& undefined_symbols);
    
private:
    Architecture target_arch;
    Platform target_platform;
    std::vector<std::string> library_paths;
    std::unordered_map<std::string, SharedLibraryInfo> loaded_libraries;
    std::unordered_map<std::string, void*> symbol_cache;
    
    // Internal methods
    std::string find_library_file(const std::string& library_name);
    bool parse_library_metadata(const std::string& library_path, SharedLibraryInfo& info);
    bool validate_library_compatibility(const SharedLibraryInfo& info);
    void update_symbol_cache(const SharedLibraryInfo& info);
    uint64_t calculate_load_address(uint64_t preferred_base, uint64_t size,
                                   const std::vector<SharedLibraryInfo>& loaded_libraries);
};

// Shared library utilities
class SharedLibraryUtils {
public:
    // Extract SO name from library path
    static std::string extract_soname(const std::string& library_path);
    
    // Generate library search order
    static std::vector<std::string> generate_search_order(const std::string& library_name);
    
    // Validate SO name format
    static bool is_valid_soname(const std::string& soname);
    
    // Parse version from SO name
    static std::string parse_version_from_soname(const std::string& soname);
    
    // Generate compatible library names
    static std::vector<std::string> generate_compatible_names(const std::string& base_name, 
                                                             const std::string& version);
    
    // Check if library is position independent
    static bool is_position_independent(const std::vector<Section>& sections);
    
    // Calculate library load address
    static uint64_t calculate_load_address(uint64_t preferred_base, uint64_t size,
                                          const std::vector<SharedLibraryInfo>& loaded_libraries);
};

} // namespace Linker
