#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

namespace Linker {

// Forward declarations
class ObjectFile;
class Section;
class Symbol;
class Relocation;

// Import types from standalone_linker.h
enum class Architecture;
enum class SectionType;
enum class SymbolBinding;
enum class SymbolType;
enum class RelocationType;

// ELF file header structures
struct ELF64_Header {
    uint8_t e_ident[16];    // ELF identification
    uint16_t e_type;        // Object file type
    uint16_t e_machine;     // Architecture
    uint32_t e_version;     // Object file version
    uint64_t e_entry;       // Entry point virtual address
    uint64_t e_phoff;       // Program header table file offset
    uint64_t e_shoff;       // Section header table file offset
    uint32_t e_flags;       // Processor-specific flags
    uint16_t e_ehsize;      // ELF header size in bytes
    uint16_t e_phentsize;   // Program header table entry size
    uint16_t e_phnum;       // Program header table entry count
    uint16_t e_shentsize;   // Section header table entry size
    uint16_t e_shnum;       // Section header table entry count
    uint16_t e_shstrndx;    // Section header string table index
};

struct ELF64_SectionHeader {
    uint32_t sh_name;       // Section name (string tbl index)
    uint32_t sh_type;       // Section type
    uint64_t sh_flags;      // Section flags
    uint64_t sh_addr;       // Section virtual addr at execution
    uint64_t sh_offset;     // Section file offset
    uint64_t sh_size;       // Section size in bytes
    uint32_t sh_link;       // Link to another section
    uint32_t sh_info;       // Additional section information
    uint64_t sh_addralign;  // Section alignment
    uint64_t sh_entsize;    // Entry size if section holds table
};

struct ELF64_Symbol {
    uint32_t st_name;       // Symbol name (string table index)
    uint8_t st_info;        // Symbol type and binding
    uint8_t st_other;       // Symbol visibility
    uint16_t st_shndx;      // Section index
    uint64_t st_value;      // Symbol value
    uint64_t st_size;       // Symbol size
};

struct ELF64_Rela {
    uint64_t r_offset;      // Address
    uint64_t r_info;        // Relocation type and symbol index
    int64_t r_addend;       // Addend
};

struct ELF64_Rel {
    uint64_t r_offset;      // Address
    uint64_t r_info;        // Relocation type and symbol index
};

// ELF constants
enum ELF_SectionType {
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_RELA = 4,
    SHT_HASH = 5,
    SHT_DYNAMIC = 6,
    SHT_NOTE = 7,
    SHT_NOBITS = 8,
    SHT_REL = 9,
    SHT_SHLIB = 10,
    SHT_DYNSYM = 11
};

enum ELF_SectionFlags {
    SHF_WRITE = 0x1,
    SHF_ALLOC = 0x2,
    SHF_EXECINSTR = 0x4,
    SHF_MERGE = 0x10,
    SHF_STRINGS = 0x20,
    SHF_INFO_LINK = 0x40,
    SHF_LINK_ORDER = 0x80,
    SHF_OS_NONCONFORMING = 0x100,
    SHF_GROUP = 0x200,
    SHF_TLS = 0x400
};

enum ELF_SymbolBinding {
    STB_LOCAL = 0,
    STB_GLOBAL = 1,
    STB_WEAK = 2
};

enum ELF_SymbolType {
    STT_NOTYPE = 0,
    STT_OBJECT = 1,
    STT_FUNC = 2,
    STT_SECTION = 3,
    STT_FILE = 4,
    STT_TLS = 6
};

// ELF Object Parser
class ELFObjectParser {
public:
    ELFObjectParser() = default;
    ~ELFObjectParser() = default;
    
    // Parse ELF object file
    bool parse(const std::vector<uint8_t>& data, ObjectFile* obj_file);
    
    // Validation
    bool is_valid_elf(const std::vector<uint8_t>& data);
    bool is_64bit_elf(const std::vector<uint8_t>& data);
    bool is_object_file(const std::vector<uint8_t>& data);
    
    // Architecture detection
    bool is_x86_64(const std::vector<uint8_t>& data);
    bool is_arm64(const std::vector<uint8_t>& data);
    
private:
    // Header parsing
    bool parse_elf_header(const std::vector<uint8_t>& data, ELF64_Header& header);
    bool parse_section_headers(const std::vector<uint8_t>& data, const ELF64_Header& header,
                              std::vector<ELF64_SectionHeader>& sections);
    
    // String table handling
    std::string get_string(const std::vector<uint8_t>& data, uint32_t str_table_offset, 
                          uint32_t str_offset, uint32_t str_table_size);
    bool parse_string_table(const std::vector<uint8_t>& data, const ELF64_SectionHeader& section,
                           std::unordered_map<uint32_t, std::string>& string_table);
    
    // Section parsing
    bool parse_sections(const std::vector<uint8_t>& data, const ELF64_Header& header,
                       const std::vector<ELF64_SectionHeader>& section_headers,
                       const std::unordered_map<uint32_t, std::string>& string_table,
                       ObjectFile* obj_file);
    
    // Symbol table parsing
    bool parse_symbol_table(const std::vector<uint8_t>& data, const ELF64_SectionHeader& symtab_section,
                           const std::unordered_map<uint32_t, std::string>& string_table,
                           ObjectFile* obj_file);
    
    // Relocation parsing
    bool parse_relocations(const std::vector<uint8_t>& data, const ELF64_SectionHeader& rela_section,
                          uint32_t target_section_index, ObjectFile* obj_file);
    
    // Type conversion helpers
    SectionType convert_section_type(uint32_t elf_type);
    SymbolBinding convert_symbol_binding(uint8_t elf_binding);
    SymbolType convert_symbol_type(uint8_t elf_type);
    RelocationType convert_relocation_type(uint32_t elf_type, Architecture arch);
    
    // Endianness handling
    template<typename T>
    T read_value(const uint8_t* data, bool is_little_endian = true);
    
    // Validation helpers
    bool validate_header(const ELF64_Header& header);
    bool validate_section_header(const ELF64_SectionHeader& section, size_t file_size);
};

} // namespace Linker
