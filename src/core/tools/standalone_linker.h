#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>

// Forward declaration for LTO
namespace Linker { 
    class LTOOptimizer; 
    enum class LTOLevel;
}

namespace Linker {

// Forward declarations
class ObjectFile;
class Section;
class Symbol;
class Relocation;

// Target architecture for linking
enum class Architecture {
    X86_64,
    ARM64
};

// Target platform for linking
enum class Platform {
    LINUX,
    MACOS,
    WINDOWS
};

// Symbol binding types
enum class SymbolBinding {
    LOCAL,
    GLOBAL,
    WEAK
};

// Symbol types
enum class SymbolType {
    NOTYPE,
    OBJECT,
    FUNC,
    SECTION,
    FILE,
    TLS
};

// Section types
enum class SectionType {
    NULL_SECTION,
    PROGBITS,
    SYMTAB,
    STRTAB,
    RELA,
    HASH,
    DYNAMIC,
    NOTE,
    NOBITS,
    REL,
    DYNSYM,
    GNU_VERSYM,
    GNU_VERDEF,
    GNU_VERNEED
};

// Section flags
enum class SectionFlags : uint32_t {
    WRITE = 0x1,
    ALLOC = 0x2,
    EXECINSTR = 0x4,
    MERGE = 0x10,
    STRINGS = 0x20,
    INFO_LINK = 0x40,
    LINK_ORDER = 0x80,
    OS_NONCONFORMING = 0x100,
    GROUP = 0x200,
    TLS = 0x400
};

// Relocation types - architecture specific
enum class RelocationType {
    // x86_64 relocations
    X86_64_NONE = 0,
    X86_64_64 = 1,       // Direct 64 bit
    X86_64_PC32 = 2,     // PC relative 32 bit signed
    X86_64_GOT32 = 3,    // 32 bit GOT entry
    X86_64_PLT32 = 4,    // 32 bit PLT address
    X86_64_32 = 10,      // Direct 32 bit zero extended
    X86_64_32S = 11,     // Direct 32 bit sign extended
    X86_64_PC64 = 24,    // PC relative 64 bit
    X86_64_GOTPCREL = 9, // 32 bit signed PC relative offset to GOT
    
    // ARM64 relocations
    AARCH64_NONE = 0,
    AARCH64_ABS64 = 257,           // Direct 64 bit
    AARCH64_ABS32 = 258,           // Direct 32 bit
    AARCH64_CALL26 = 283,          // PC-rel. 26 bit, word aligned
    AARCH64_JUMP26 = 282,          // PC-rel. 26 bit, word aligned
    AARCH64_ADR_PREL_PG_HI21 = 275, // Page(S+A)-Page(P)
    AARCH64_ADD_ABS_LO12_NC = 277,   // S+A
    AARCH64_LDST64_ABS_LO12_NC = 286 // S+A
};

// Symbol class representing a symbol in object files
class Symbol {
public:
    std::string name;
    uint64_t value = 0;
    uint64_t size = 0;
    SymbolBinding binding = SymbolBinding::LOCAL;
    SymbolType type = SymbolType::NOTYPE;
    uint16_t section_index = 0;  // Index into section table
    bool defined = false;
    
    Symbol() = default;
    Symbol(const std::string& n, uint64_t val = 0) : name(n), value(val) {}
};

// Relocation class representing relocations in object files
class Relocation {
public:
    uint64_t offset = 0;        // Offset in section where relocation applies
    RelocationType type = RelocationType::X86_64_NONE;
    uint32_t symbol_index = 0;  // Index into symbol table
    int64_t addend = 0;         // Addend for RELA relocations
    
    Relocation() = default;
    Relocation(uint64_t off, RelocationType t, uint32_t sym, int64_t add = 0)
        : offset(off), type(t), symbol_index(sym), addend(add) {}
};

// Section class representing sections in object files
class Section {
public:
    std::string name;
    SectionType type = SectionType::NULL_SECTION;
    uint64_t flags = 0;
    uint64_t address = 0;       // Virtual address when loaded
    uint64_t offset = 0;        // File offset
    uint64_t size = 0;
    uint32_t link = 0;          // Link to other section
    uint32_t info = 0;          // Additional info
    uint64_t alignment = 1;
    uint64_t entry_size = 0;    // Entry size for fixed-size entries
    
    std::vector<uint8_t> data;
    std::vector<Relocation> relocations;
    
    Section() = default;
    Section(const std::string& n, SectionType t) : name(n), type(t) {}
    
    // Helper methods
    bool is_executable() const { return (flags & static_cast<uint64_t>(SectionFlags::EXECINSTR)) != 0; }
    bool is_writable() const { return (flags & static_cast<uint64_t>(SectionFlags::WRITE)) != 0; }
    bool is_allocatable() const { return (flags & static_cast<uint64_t>(SectionFlags::ALLOC)) != 0; }
};

// Object file class representing input object files
class ObjectFile {
public:
    std::string filename;
    Architecture arch = Architecture::X86_64;
    Platform platform = Platform::LINUX;
    
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::unordered_map<std::string, uint32_t> section_name_map;
    std::unordered_map<std::string, uint32_t> symbol_name_map;
    
    ObjectFile() = default;
    ObjectFile(const std::string& fname) : filename(fname) {}
    
    // Helper methods
    Section* get_section(const std::string& name);
    Symbol* get_symbol(const std::string& name);
    uint32_t add_section(const Section& section);
    uint32_t add_symbol(const Symbol& symbol);
};

// Memory layout manager for organizing sections in memory
class MemoryLayout {
public:
    struct SegmentInfo {
        uint64_t virtual_address = 0;
        uint64_t file_offset = 0;
        uint64_t memory_size = 0;
        uint64_t file_size = 0;
        uint32_t flags = 0;  // Read/Write/Execute permissions
        std::vector<uint32_t> section_indices;
    };
    
    std::vector<SegmentInfo> segments;
    uint64_t base_address = 0x400000;  // Default base address
    uint64_t current_address = 0;
    
    // Layout sections into memory segments
    void layout_sections(const std::vector<Section>& sections);
    
    // Get segment for a given section
    SegmentInfo* get_segment_for_section(uint32_t section_index);
    
private:
    void align_address(uint64_t alignment);
};

// Symbol resolution engine
class SymbolResolver {
public:
    struct ResolvedSymbol {
        std::string name;
        uint64_t address = 0;
        uint32_t size = 0;
        SymbolType type = SymbolType::NOTYPE;
        bool is_external = false;
        ObjectFile* source_file = nullptr;
    };
    
    std::unordered_map<std::string, ResolvedSymbol> resolved_symbols;
    std::unordered_set<std::string> undefined_symbols;
    
    // Add symbols from an object file
    void add_object_symbols(ObjectFile* obj_file);
    
    // Add external symbol (from libraries)
    void add_external_symbol(const std::string& name, uint64_t address);
    
    // Resolve all symbols
    bool resolve_all_symbols();
    
    // Get resolved symbol
    ResolvedSymbol* get_symbol(const std::string& name);
    
    // Check for undefined symbols
    bool has_undefined_symbols() const { return !undefined_symbols.empty(); }
    std::vector<std::string> get_undefined_symbols() const;
    
private:
    void process_symbol_conflicts();
};

// Main standalone linker class
class StandaloneLinker {
public:
    StandaloneLinker(Architecture arch, Platform platform);
    ~StandaloneLinker() = default;
    
    // Configuration
    void set_base_address(uint64_t address) { memory_layout.base_address = address; }
    void set_entry_point(const std::string& symbol_name) { entry_symbol = symbol_name; }
    void add_library_path(const std::string& path) { library_paths.push_back(path); }
    void add_library(const std::string& lib_name) { libraries.push_back(lib_name); }
    void enable_dynamic_linking_mode(bool enabled) { enable_dynamic_linking = enabled; }
    
    // LTO configuration
    void enable_lto(LTOLevel level);
    void set_lto_inline_threshold(uint32_t threshold);
    void disable_lto() { lto_enabled = false; }
    
    // Input handling
    bool add_object_file(const std::string& filename);
    bool add_object_data(const std::vector<uint8_t>& data, const std::string& name = "");
    
    // Linking process
    bool link();
    
    // Output generation
    bool write_executable(const std::string& output_path);
    bool write_shared_library(const std::string& output_path);
    
    // Information access
    const std::vector<std::string>& get_undefined_symbols() const;
    const SymbolResolver::ResolvedSymbol* get_symbol_info(const std::string& name) const;
    
    // Error handling
    bool has_errors() const { return !error_messages.empty(); }
    const std::vector<std::string>& get_errors() const { return error_messages; }
    void clear_errors() { error_messages.clear(); }
    
private:
    Architecture target_arch;
    Platform target_platform;
    std::string entry_symbol = "_start";
    
    std::vector<std::unique_ptr<ObjectFile>> object_files;
    std::vector<std::string> library_paths;
    std::vector<std::string> libraries;
    std::vector<std::string> error_messages;
    bool enable_dynamic_linking = false;
    bool lto_enabled = false;
    std::unique_ptr<LTOOptimizer> lto_optimizer;
    
    SymbolResolver symbol_resolver;
    MemoryLayout memory_layout;
    
    // Internal methods
    bool parse_object_file(const std::string& filename, ObjectFile* obj_file);
    bool parse_elf_object(const std::vector<uint8_t>& data, ObjectFile* obj_file);
    bool parse_macho_object(const std::vector<uint8_t>& data, ObjectFile* obj_file);
    
    bool resolve_relocations();
    bool apply_relocation(const Relocation& reloc, Section& section, const Symbol& symbol, uint64_t symbol_address);
    
    bool generate_executable_layout();
    bool write_elf_executable(const std::string& output_path);
    bool write_macho_executable(const std::string& output_path);
    
    void add_error(const std::string& message);
    
    // Architecture-specific helpers
    bool is_valid_relocation_for_arch(RelocationType type) const;
    uint64_t calculate_relocation_value(RelocationType type, uint64_t symbol_addr, 
                                       uint64_t reloc_addr, int64_t addend) const;
};

} // namespace Linker
