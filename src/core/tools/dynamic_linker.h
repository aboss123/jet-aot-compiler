#pragma once
#include "standalone_linker.h"
#include <unordered_map>
#include <unordered_set>

namespace Linker {

// Forward declarations
class DynamicSymbolTable;
class PLTGenerator;
class GOTGenerator;

// Dynamic symbol information
struct DynamicSymbol {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    SymbolType type = SymbolType::NOTYPE;
    SymbolBinding binding = SymbolBinding::GLOBAL;
    bool is_external = false;
    bool needs_plt = false;
    bool needs_got = false;
    uint32_t plt_index = 0;
    uint32_t got_index = 0;
    std::string library_name;  // For external symbols
    
    DynamicSymbol() = default;
    DynamicSymbol(const std::string& n) : name(n) {}
};

// PLT entry structure
struct PLTEntry {
    uint32_t index;
    std::string symbol_name;
    uint64_t address = 0;
    uint64_t got_offset = 0;
    std::vector<uint8_t> code;  // Architecture-specific PLT stub code
    
    PLTEntry(uint32_t idx, const std::string& name) : index(idx), symbol_name(name) {}
};

// GOT entry structure  
struct GOTEntry {
    uint32_t index;
    std::string symbol_name;
    uint64_t address = 0;
    uint64_t value = 0;  // Runtime address or PLT address
    bool is_function = false;
    
    GOTEntry(uint32_t idx, const std::string& name) : index(idx), symbol_name(name) {}
};

// Dynamic section types
enum class DynamicTag : uint64_t {
    DT_NULL = 0,
    DT_NEEDED = 1,      // Needed library
    DT_PLTRELSZ = 2,    // Size of PLT relocations
    DT_PLTGOT = 3,      // PLT/GOT address
    DT_HASH = 4,        // Hash table address
    DT_STRTAB = 5,      // String table address
    DT_SYMTAB = 6,      // Symbol table address
    DT_RELA = 7,        // Rela relocations address
    DT_RELASZ = 8,      // Rela relocations size
    DT_RELAENT = 9,     // Rela entry size
    DT_STRSZ = 10,      // String table size
    DT_SYMENT = 11,     // Symbol entry size
    DT_INIT = 12,       // Initialization function
    DT_FINI = 13,       // Termination function
    DT_SONAME = 14,     // Shared object name
    DT_RPATH = 15,      // Library search path
    DT_SYMBOLIC = 16,   // Symbolic linking
    DT_REL = 17,        // Rel relocations address
    DT_RELSZ = 18,      // Rel relocations size
    DT_RELENT = 19,     // Rel entry size
    DT_PLTREL = 20,     // PLT relocation type
    DT_DEBUG = 21,      // Debug info
    DT_TEXTREL = 22,    // Text relocations
    DT_JMPREL = 23,     // PLT relocations address
    DT_BIND_NOW = 24,   // Bind now flag
    DT_INIT_ARRAY = 25, // Initialization array
    DT_FINI_ARRAY = 26, // Termination array
    DT_INIT_ARRAYSZ = 27, // Init array size
    DT_FINI_ARRAYSZ = 28, // Fini array size
    DT_RUNPATH = 29,    // Library search path
    DT_FLAGS = 30,      // Flags
};

// Dynamic section entry
struct DynamicEntry {
    DynamicTag tag;
    uint64_t value;
    
    DynamicEntry(DynamicTag t, uint64_t v) : tag(t), value(v) {}
};

// PLT Generator - creates procedure linkage table
class PLTGenerator {
public:
    PLTGenerator(Architecture arch);
    ~PLTGenerator() = default;
    
    // Generate PLT section
    bool generate_plt_section(const std::vector<DynamicSymbol>& dynamic_symbols,
                             Section& plt_section, uint64_t got_address);
    
    // Get PLT entry for symbol
    PLTEntry* get_plt_entry(const std::string& symbol_name);
    
    // Get all PLT entries
    const std::vector<PLTEntry>& get_plt_entries() const { return plt_entries; }
    
    // Get PLT section size
    uint64_t get_plt_size() const;
    
private:
    Architecture target_arch;
    std::vector<PLTEntry> plt_entries;
    std::unordered_map<std::string, uint32_t> symbol_to_plt_index;
    
    // Architecture-specific PLT code generation
    std::vector<uint8_t> generate_plt_header_x64(uint64_t got_address);
    std::vector<uint8_t> generate_plt_entry_x64(uint32_t index, uint64_t got_offset);
    std::vector<uint8_t> generate_plt_header_arm64(uint64_t got_address);
    std::vector<uint8_t> generate_plt_entry_arm64(uint32_t index, uint64_t got_offset);
    
    // Helper functions
    void add_plt_entry(const std::string& symbol_name, uint64_t got_offset);
    uint64_t calculate_plt_entry_address(uint32_t index, uint64_t plt_base_address);
};

// GOT Generator - creates global offset table
class GOTGenerator {
public:
    GOTGenerator(Architecture arch);
    ~GOTGenerator() = default;
    
    // Generate GOT section
    bool generate_got_section(const std::vector<DynamicSymbol>& dynamic_symbols,
                             Section& got_section, uint64_t plt_address);
    
    // Get GOT entry for symbol
    GOTEntry* get_got_entry(const std::string& symbol_name);
    
    // Get all GOT entries
    const std::vector<GOTEntry>& get_got_entries() const { return got_entries; }
    
    // Get GOT section size
    uint64_t get_got_size() const;
    
    // Add symbol to GOT
    uint32_t add_got_entry(const std::string& symbol_name, bool is_function = false);
    
private:
    Architecture target_arch;
    std::vector<GOTEntry> got_entries;
    std::unordered_map<std::string, uint32_t> symbol_to_got_index;
    uint64_t entry_size = 8; // 8 bytes for 64-bit architectures
    
    // Helper functions
    void add_got_reserved_entries(); // Add reserved GOT entries
    uint64_t calculate_got_entry_address(uint32_t index, uint64_t got_base_address);
};

// Dynamic Symbol Table - manages dynamic symbols
class DynamicSymbolTable {
public:
    DynamicSymbolTable() = default;
    ~DynamicSymbolTable() = default;
    
    // Add dynamic symbol
    void add_symbol(const DynamicSymbol& symbol);
    
    // Get symbol by name
    DynamicSymbol* get_symbol(const std::string& name);
    
    // Get all symbols
    const std::vector<DynamicSymbol>& get_symbols() const { return symbols; }
    
    // Mark symbol as needing PLT/GOT
    void mark_symbol_needs_plt(const std::string& name);
    void mark_symbol_needs_got(const std::string& name);
    
    // Generate dynamic symbol table section
    bool generate_dynsym_section(Section& dynsym_section);
    
    // Generate dynamic string table section
    bool generate_dynstr_section(Section& dynstr_section);
    
    // Get symbols needing PLT
    std::vector<DynamicSymbol> get_plt_symbols() const;
    
    // Get symbols needing GOT
    std::vector<DynamicSymbol> get_got_symbols() const;
    
private:
    std::vector<DynamicSymbol> symbols;
    std::unordered_map<std::string, uint32_t> name_to_index;
    
    // Helper functions
    uint32_t add_string_to_table(const std::string& str, std::vector<uint8_t>& string_table);
};

// Dynamic Linker - main dynamic linking coordinator
class DynamicLinker {
public:
    DynamicLinker(Architecture arch, Platform platform);
    ~DynamicLinker() = default;
    
    // Process symbols for dynamic linking
    bool process_dynamic_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                SymbolResolver& symbol_resolver);
    
    // Generate dynamic sections
    bool generate_dynamic_sections(std::vector<Section>& sections, uint64_t base_address);
    
    // Add library dependency
    void add_library_dependency(const std::string& library_name);
    
    // Set shared library creation mode
    void set_shared_library_mode(bool enabled) { is_shared_library = enabled; }
    
    // Get dynamic symbol table
    DynamicSymbolTable& get_symbol_table() { return dynamic_symbols; }
    
    // Get required libraries
    const std::vector<std::string>& get_required_libraries() const { return required_libraries; }
    
private:
    Architecture target_arch;
    Platform target_platform;
    bool is_shared_library = false;
    
    DynamicSymbolTable dynamic_symbols;
    PLTGenerator plt_generator;
    GOTGenerator got_generator;
    std::vector<std::string> required_libraries;
    std::vector<DynamicEntry> dynamic_entries;
    
    // Symbol analysis
    bool analyze_symbol_dependencies(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                   SymbolResolver& symbol_resolver);
    
    // Section generation
    bool generate_plt_section(Section& plt_section, uint64_t base_address);
    bool generate_got_section(Section& got_section, uint64_t base_address);
    bool generate_dynamic_section(Section& dynamic_section);
    bool generate_hash_section(Section& hash_section);
    
    // Dynamic relocations
    bool generate_dynamic_relocations(Section& rela_plt_section, Section& rela_dyn_section);
    
    // Helper functions
    void add_dynamic_entry(DynamicTag tag, uint64_t value);
    bool is_external_symbol(const std::string& symbol_name, SymbolResolver& resolver);
    std::string get_symbol_library(const std::string& symbol_name);
};

} // namespace Linker
