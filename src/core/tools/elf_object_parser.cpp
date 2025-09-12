#include "elf_object_parser.h"
#include "standalone_linker.h"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace Linker {

bool ELFObjectParser::parse(const std::vector<uint8_t>& data, ObjectFile* obj_file) {
    if (!is_valid_elf(data)) {
        std::cerr << "Invalid ELF file" << std::endl;
        return false;
    }
    
    if (!is_64bit_elf(data)) {
        std::cerr << "Only 64-bit ELF files are supported" << std::endl;
        return false;
    }
    
    if (!is_object_file(data)) {
        std::cerr << "Only ELF object files (ET_REL) are supported" << std::endl;
        return false;
    }
    
    // Parse ELF header
    ELF64_Header header;
    if (!parse_elf_header(data, header)) {
        std::cerr << "Failed to parse ELF header" << std::endl;
        return false;
    }
    
    // Set architecture
    if (is_x86_64(data)) {
        obj_file->arch = Architecture::X86_64;
    } else if (is_arm64(data)) {
        obj_file->arch = Architecture::ARM64;
    } else {
        std::cerr << "Unsupported architecture" << std::endl;
        return false;
    }
    
    // Parse section headers
    std::vector<ELF64_SectionHeader> section_headers;
    if (!parse_section_headers(data, header, section_headers)) {
        std::cerr << "Failed to parse section headers" << std::endl;
        return false;
    }
    
    // Parse string table (section header string table)
    std::unordered_map<uint32_t, std::string> string_table;
    if (header.e_shstrndx < section_headers.size()) {
        parse_string_table(data, section_headers[header.e_shstrndx], string_table);
    }
    
    // Parse sections
    if (!parse_sections(data, header, section_headers, string_table, obj_file)) {
        std::cerr << "Failed to parse sections" << std::endl;
        return false;
    }
    
    return true;
}

bool ELFObjectParser::is_valid_elf(const std::vector<uint8_t>& data) {
    if (data.size() < 16) return false;
    
    // Check ELF magic number
    return data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
}

bool ELFObjectParser::is_64bit_elf(const std::vector<uint8_t>& data) {
    if (data.size() < 5) return false;
    return data[4] == 2; // ELFCLASS64
}

bool ELFObjectParser::is_object_file(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(ELF64_Header)) return false;
    
    ELF64_Header header;
    if (!parse_elf_header(data, header)) return false;
    
    return header.e_type == 1; // ET_REL
}

bool ELFObjectParser::is_x86_64(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(ELF64_Header)) return false;
    
    ELF64_Header header;
    if (!parse_elf_header(data, header)) return false;
    
    return header.e_machine == 0x3E; // EM_X86_64
}

bool ELFObjectParser::is_arm64(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(ELF64_Header)) return false;
    
    ELF64_Header header;
    if (!parse_elf_header(data, header)) return false;
    
    return header.e_machine == 0xB7; // EM_AARCH64
}

bool ELFObjectParser::parse_elf_header(const std::vector<uint8_t>& data, ELF64_Header& header) {
    if (data.size() < sizeof(ELF64_Header)) {
        return false;
    }
    
    const uint8_t* ptr = data.data();
    
    // Copy identification bytes
    std::memcpy(header.e_ident, ptr, 16);
    ptr += 16;
    
    // Read remaining header fields (assuming little-endian)
    header.e_type = read_value<uint16_t>(ptr); ptr += 2;
    header.e_machine = read_value<uint16_t>(ptr); ptr += 2;
    header.e_version = read_value<uint32_t>(ptr); ptr += 4;
    header.e_entry = read_value<uint64_t>(ptr); ptr += 8;
    header.e_phoff = read_value<uint64_t>(ptr); ptr += 8;
    header.e_shoff = read_value<uint64_t>(ptr); ptr += 8;
    header.e_flags = read_value<uint32_t>(ptr); ptr += 4;
    header.e_ehsize = read_value<uint16_t>(ptr); ptr += 2;
    header.e_phentsize = read_value<uint16_t>(ptr); ptr += 2;
    header.e_phnum = read_value<uint16_t>(ptr); ptr += 2;
    header.e_shentsize = read_value<uint16_t>(ptr); ptr += 2;
    header.e_shnum = read_value<uint16_t>(ptr); ptr += 2;
    header.e_shstrndx = read_value<uint16_t>(ptr);
    
    return validate_header(header);
}

bool ELFObjectParser::parse_section_headers(const std::vector<uint8_t>& data, const ELF64_Header& header,
                                           std::vector<ELF64_SectionHeader>& sections) {
    if (header.e_shoff == 0 || header.e_shnum == 0) {
        return true; // No sections
    }
    
    if (header.e_shoff + header.e_shnum * sizeof(ELF64_SectionHeader) > data.size()) {
        return false;
    }
    
    sections.resize(header.e_shnum);
    const uint8_t* ptr = data.data() + header.e_shoff;
    
    for (uint16_t i = 0; i < header.e_shnum; ++i) {
        ELF64_SectionHeader& section = sections[i];
        
        section.sh_name = read_value<uint32_t>(ptr); ptr += 4;
        section.sh_type = read_value<uint32_t>(ptr); ptr += 4;
        section.sh_flags = read_value<uint64_t>(ptr); ptr += 8;
        section.sh_addr = read_value<uint64_t>(ptr); ptr += 8;
        section.sh_offset = read_value<uint64_t>(ptr); ptr += 8;
        section.sh_size = read_value<uint64_t>(ptr); ptr += 8;
        section.sh_link = read_value<uint32_t>(ptr); ptr += 4;
        section.sh_info = read_value<uint32_t>(ptr); ptr += 4;
        section.sh_addralign = read_value<uint64_t>(ptr); ptr += 8;
        section.sh_entsize = read_value<uint64_t>(ptr); ptr += 8;
        
        if (!validate_section_header(section, data.size())) {
            return false;
        }
    }
    
    return true;
}

std::string ELFObjectParser::get_string(const std::vector<uint8_t>& data, uint32_t str_table_offset, 
                                       uint32_t str_offset, uint32_t str_table_size) {
    uint64_t offset = str_table_offset + str_offset;
    if (offset >= data.size() || str_offset >= str_table_size) {
        return "";
    }
    
    const char* str = reinterpret_cast<const char*>(data.data() + offset);
    size_t max_len = std::min(static_cast<size_t>(data.size() - offset), 
                             static_cast<size_t>(str_table_size - str_offset));
    
    // Find null terminator
    for (size_t i = 0; i < max_len; ++i) {
        if (str[i] == '\0') {
            return std::string(str, i);
        }
    }
    
    return std::string(str, max_len);
}

bool ELFObjectParser::parse_string_table(const std::vector<uint8_t>& data, const ELF64_SectionHeader& section,
                                        std::unordered_map<uint32_t, std::string>& string_table) {
    if (section.sh_type != SHT_STRTAB || section.sh_size == 0) {
        return true;
    }
    
    if (section.sh_offset + section.sh_size > data.size()) {
        return false;
    }
    
    const char* str_data = reinterpret_cast<const char*>(data.data() + section.sh_offset);
    uint32_t offset = 0;
    
    while (offset < section.sh_size) {
        if (str_data[offset] != '\0') {
            std::string str;
            uint32_t start = offset;
            
            while (offset < section.sh_size && str_data[offset] != '\0') {
                str += str_data[offset];
                offset++;
            }
            
            string_table[start] = str;
        }
        offset++;
    }
    
    return true;
}

bool ELFObjectParser::parse_sections(const std::vector<uint8_t>& data, const ELF64_Header& header,
                                    const std::vector<ELF64_SectionHeader>& section_headers,
                                    const std::unordered_map<uint32_t, std::string>& string_table,
                                    ObjectFile* obj_file) {
    
    // First pass: create sections and collect symbol/string tables
    std::unordered_map<uint32_t, std::string> symbol_string_table;
    
    for (size_t i = 0; i < section_headers.size(); ++i) {
        const auto& sh = section_headers[i];
        
        // Get section name
        std::string section_name;
        auto name_it = string_table.find(sh.sh_name);
        if (name_it != string_table.end()) {
            section_name = name_it->second;
        } else {
            section_name = ".section" + std::to_string(i);
        }
        
        // Skip null section
        if (sh.sh_type == SHT_NULL) {
            continue;
        }
        
        // Handle string tables for symbols
        if (sh.sh_type == SHT_STRTAB && section_name != ".shstrtab") {
            parse_string_table(data, sh, symbol_string_table);
            continue;
        }
        
        // Handle symbol tables
        if (sh.sh_type == SHT_SYMTAB) {
            parse_symbol_table(data, sh, symbol_string_table, obj_file);
            continue;
        }
        
        // Handle relocation sections
        if (sh.sh_type == SHT_RELA || sh.sh_type == SHT_REL) {
            parse_relocations(data, sh, sh.sh_info, obj_file);
            continue;
        }
        
        // Create regular section
        Section section(section_name, convert_section_type(sh.sh_type));
        section.flags = sh.sh_flags;
        section.address = sh.sh_addr;
        section.offset = sh.sh_offset;
        section.size = sh.sh_size;
        section.link = sh.sh_link;
        section.info = sh.sh_info;
        section.alignment = sh.sh_addralign;
        section.entry_size = sh.sh_entsize;
        
        // Copy section data
        if (sh.sh_type == SHT_PROGBITS && sh.sh_size > 0) {
            if (sh.sh_offset + sh.sh_size <= data.size()) {
                section.data.resize(sh.sh_size);
                std::memcpy(section.data.data(), data.data() + sh.sh_offset, sh.sh_size);
            }
        }
        
        obj_file->add_section(section);
    }
    
    return true;
}

bool ELFObjectParser::parse_symbol_table(const std::vector<uint8_t>& data, const ELF64_SectionHeader& symtab_section,
                                        const std::unordered_map<uint32_t, std::string>& string_table,
                                        ObjectFile* obj_file) {
    if (symtab_section.sh_entsize != sizeof(ELF64_Symbol)) {
        return false;
    }
    
    uint64_t num_symbols = symtab_section.sh_size / sizeof(ELF64_Symbol);
    if (symtab_section.sh_offset + symtab_section.sh_size > data.size()) {
        return false;
    }
    
    const uint8_t* ptr = data.data() + symtab_section.sh_offset;
    
    for (uint64_t i = 0; i < num_symbols; ++i) {
        ELF64_Symbol elf_sym;
        
        elf_sym.st_name = read_value<uint32_t>(ptr); ptr += 4;
        elf_sym.st_info = *ptr++; 
        elf_sym.st_other = *ptr++;
        elf_sym.st_shndx = read_value<uint16_t>(ptr); ptr += 2;
        elf_sym.st_value = read_value<uint64_t>(ptr); ptr += 8;
        elf_sym.st_size = read_value<uint64_t>(ptr); ptr += 8;
        
        // Get symbol name
        std::string sym_name;
        if (elf_sym.st_name != 0) {
            auto name_it = string_table.find(elf_sym.st_name);
            if (name_it != string_table.end()) {
                sym_name = name_it->second;
            } else {
                sym_name = "sym_" + std::to_string(i);
            }
        }
        
        // Skip empty symbols
        if (sym_name.empty() && elf_sym.st_value == 0 && elf_sym.st_size == 0) {
            continue;
        }
        
        // Create symbol
        Symbol symbol(sym_name, elf_sym.st_value);
        symbol.size = elf_sym.st_size;
        symbol.binding = convert_symbol_binding(elf_sym.st_info >> 4);
        symbol.type = convert_symbol_type(elf_sym.st_info & 0xF);
        symbol.section_index = elf_sym.st_shndx;
        symbol.defined = (elf_sym.st_shndx != 0); // SHN_UNDEF
        
        obj_file->add_symbol(symbol);
    }
    
    return true;
}

bool ELFObjectParser::parse_relocations(const std::vector<uint8_t>& data, const ELF64_SectionHeader& rela_section,
                                      uint32_t target_section_index, ObjectFile* obj_file) {
    if (target_section_index >= obj_file->sections.size()) {
        return false;
    }
    
    Section& target_section = obj_file->sections[target_section_index];
    
    if (rela_section.sh_type == SHT_RELA) {
        // RELA relocations (with explicit addend)
        if (rela_section.sh_entsize != sizeof(ELF64_Rela)) {
            return false;
        }
        
        uint64_t num_relocs = rela_section.sh_size / sizeof(ELF64_Rela);
        const uint8_t* ptr = data.data() + rela_section.sh_offset;
        
        for (uint64_t i = 0; i < num_relocs; ++i) {
            ELF64_Rela elf_rela;
            
            elf_rela.r_offset = read_value<uint64_t>(ptr); ptr += 8;
            elf_rela.r_info = read_value<uint64_t>(ptr); ptr += 8;
            elf_rela.r_addend = read_value<int64_t>(ptr); ptr += 8;
            
            uint32_t sym_index = elf_rela.r_info >> 32;
            uint32_t type = elf_rela.r_info & 0xFFFFFFFF;
            
            Relocation reloc(elf_rela.r_offset, 
                           convert_relocation_type(type, obj_file->arch),
                           sym_index, elf_rela.r_addend);
            
            target_section.relocations.push_back(reloc);
        }
    } else if (rela_section.sh_type == SHT_REL) {
        // REL relocations (addend in relocated location)
        if (rela_section.sh_entsize != sizeof(ELF64_Rel)) {
            return false;
        }
        
        uint64_t num_relocs = rela_section.sh_size / sizeof(ELF64_Rel);
        const uint8_t* ptr = data.data() + rela_section.sh_offset;
        
        for (uint64_t i = 0; i < num_relocs; ++i) {
            ELF64_Rel elf_rel;
            
            elf_rel.r_offset = read_value<uint64_t>(ptr); ptr += 8;
            elf_rel.r_info = read_value<uint64_t>(ptr); ptr += 8;
            
            uint32_t sym_index = elf_rel.r_info >> 32;
            uint32_t type = elf_rel.r_info & 0xFFFFFFFF;
            
            Relocation reloc(elf_rel.r_offset, 
                           convert_relocation_type(type, obj_file->arch),
                           sym_index, 0); // No explicit addend
            
            target_section.relocations.push_back(reloc);
        }
    }
    
    return true;
}

// Type conversion helpers
SectionType ELFObjectParser::convert_section_type(uint32_t elf_type) {
    switch (elf_type) {
        case SHT_NULL: return SectionType::NULL_SECTION;
        case SHT_PROGBITS: return SectionType::PROGBITS;
        case SHT_SYMTAB: return SectionType::SYMTAB;
        case SHT_STRTAB: return SectionType::STRTAB;
        case SHT_RELA: return SectionType::RELA;
        case SHT_HASH: return SectionType::HASH;
        case SHT_DYNAMIC: return SectionType::DYNAMIC;
        case SHT_NOTE: return SectionType::NOTE;
        case SHT_NOBITS: return SectionType::NOBITS;
        case SHT_REL: return SectionType::REL;
        case SHT_DYNSYM: return SectionType::DYNSYM;
        default: return SectionType::PROGBITS;
    }
}

SymbolBinding ELFObjectParser::convert_symbol_binding(uint8_t elf_binding) {
    switch (elf_binding) {
        case STB_LOCAL: return SymbolBinding::LOCAL;
        case STB_GLOBAL: return SymbolBinding::GLOBAL;
        case STB_WEAK: return SymbolBinding::WEAK;
        default: return SymbolBinding::LOCAL;
    }
}

SymbolType ELFObjectParser::convert_symbol_type(uint8_t elf_type) {
    switch (elf_type) {
        case STT_NOTYPE: return SymbolType::NOTYPE;
        case STT_OBJECT: return SymbolType::OBJECT;
        case STT_FUNC: return SymbolType::FUNC;
        case STT_SECTION: return SymbolType::SECTION;
        case STT_FILE: return SymbolType::FILE;
        case STT_TLS: return SymbolType::TLS;
        default: return SymbolType::NOTYPE;
    }
}

RelocationType ELFObjectParser::convert_relocation_type(uint32_t elf_type, Architecture arch) {
    if (arch == Architecture::X86_64) {
        switch (elf_type) {
            case 0: return RelocationType::X86_64_NONE;
            case 1: return RelocationType::X86_64_64;
            case 2: return RelocationType::X86_64_PC32;
            case 3: return RelocationType::X86_64_GOT32;
            case 4: return RelocationType::X86_64_PLT32;
            case 9: return RelocationType::X86_64_GOTPCREL;
            case 10: return RelocationType::X86_64_32;
            case 11: return RelocationType::X86_64_32S;
            case 24: return RelocationType::X86_64_PC64;
            default: return RelocationType::X86_64_NONE;
        }
    } else if (arch == Architecture::ARM64) {
        switch (elf_type) {
            case 0: return RelocationType::AARCH64_NONE;
            case 257: return RelocationType::AARCH64_ABS64;
            case 258: return RelocationType::AARCH64_ABS32;
            case 275: return RelocationType::AARCH64_ADR_PREL_PG_HI21;
            case 277: return RelocationType::AARCH64_ADD_ABS_LO12_NC;
            case 282: return RelocationType::AARCH64_JUMP26;
            case 283: return RelocationType::AARCH64_CALL26;
            case 286: return RelocationType::AARCH64_LDST64_ABS_LO12_NC;
            default: return RelocationType::AARCH64_NONE;
        }
    }
    
    return RelocationType::X86_64_NONE;
}

template<typename T>
T ELFObjectParser::read_value(const uint8_t* data, bool is_little_endian) {
    T value = 0;
    if (is_little_endian) {
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(data[i]) << (i * 8);
        }
    } else {
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(data[i]) << ((sizeof(T) - 1 - i) * 8);
        }
    }
    return value;
}

bool ELFObjectParser::validate_header(const ELF64_Header& header) {
    // Check magic number
    if (header.e_ident[0] != 0x7F || header.e_ident[1] != 'E' || 
        header.e_ident[2] != 'L' || header.e_ident[3] != 'F') {
        return false;
    }
    
    // Check class (64-bit)
    if (header.e_ident[4] != 2) {
        return false;
    }
    
    // Check version
    if (header.e_version != 1) {
        return false;
    }
    
    return true;
}

bool ELFObjectParser::validate_section_header(const ELF64_SectionHeader& section, size_t file_size) {
    // Check bounds
    if (section.sh_offset > file_size) {
        return false;
    }
    
    if (section.sh_size > 0 && section.sh_offset + section.sh_size > file_size) {
        return false;
    }
    
    return true;
}

} // namespace Linker
