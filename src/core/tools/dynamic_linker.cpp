#include "dynamic_linker.h"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace Linker {

// PLTGenerator implementation
PLTGenerator::PLTGenerator(Architecture arch) : target_arch(arch) {
}

bool PLTGenerator::generate_plt_section(const std::vector<DynamicSymbol>& dynamic_symbols,
                                       Section& plt_section, uint64_t got_address) {
    plt_section.name = ".plt";
    plt_section.type = SectionType::PROGBITS;
    plt_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC) | 
                       static_cast<uint64_t>(SectionFlags::EXECINSTR);
    plt_section.alignment = 16;
    
    // Generate PLT header
    std::vector<uint8_t> plt_data;
    if (target_arch == Architecture::X86_64) {
        auto header = generate_plt_header_x64(got_address);
        plt_data.insert(plt_data.end(), header.begin(), header.end());
    } else if (target_arch == Architecture::ARM64) {
        auto header = generate_plt_header_arm64(got_address);
        plt_data.insert(plt_data.end(), header.begin(), header.end());
    }
    
    // Generate PLT entries for each dynamic symbol
    uint32_t entry_index = 0;
    for (const auto& symbol : dynamic_symbols) {
        if (symbol.needs_plt) {
            uint64_t got_offset = symbol.got_index * 8; // 8 bytes per GOT entry
            
            std::vector<uint8_t> entry_code;
            if (target_arch == Architecture::X86_64) {
                entry_code = generate_plt_entry_x64(entry_index, got_offset);
            } else if (target_arch == Architecture::ARM64) {
                entry_code = generate_plt_entry_arm64(entry_index, got_offset);
            }
            
            plt_data.insert(plt_data.end(), entry_code.begin(), entry_code.end());
            
            // Create PLT entry
            PLTEntry entry(entry_index, symbol.name);
            entry.address = plt_data.size() - entry_code.size();
            entry.got_offset = got_offset;
            entry.code = entry_code;
            
            plt_entries.push_back(entry);
            symbol_to_plt_index[symbol.name] = entry_index;
            entry_index++;
        }
    }
    
    plt_section.data = plt_data;
    plt_section.size = plt_data.size();
    
    return true;
}

std::vector<uint8_t> PLTGenerator::generate_plt_header_x64(uint64_t got_address) {
    // x86_64 PLT header
    std::vector<uint8_t> header = {
        // pushq GOT[1] (link_map)
        0xff, 0x35, 0x00, 0x00, 0x00, 0x00,  // pushq 0x0(%rip) - will be patched
        // jmpq *GOT[2] (dl_runtime_resolve)
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmpq *0x0(%rip) - will be patched
        // padding
        0x90, 0x90, 0x90, 0x90
    };
    
    // Patch GOT offsets (simplified - would need proper relocation in real implementation)
    // For now, just placeholder offsets
    *reinterpret_cast<uint32_t*>(&header[2]) = 8;  // GOT[1] offset
    *reinterpret_cast<uint32_t*>(&header[8]) = 16; // GOT[2] offset
    
    return header;
}

std::vector<uint8_t> PLTGenerator::generate_plt_entry_x64(uint32_t index, uint64_t got_offset) {
    // x86_64 PLT entry
    std::vector<uint8_t> entry = {
        // jmpq *GOT[n]
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmpq *offset(%rip) - will be patched
        // pushq $index
        0x68, static_cast<uint8_t>(index), static_cast<uint8_t>(index >> 8), 
        static_cast<uint8_t>(index >> 16), static_cast<uint8_t>(index >> 24),
        // jmpq PLT[0]
        0xe9, 0x00, 0x00, 0x00, 0x00  // jmpq offset - will be patched
    };
    
    // Patch GOT offset (simplified)
    *reinterpret_cast<uint32_t*>(&entry[2]) = static_cast<uint32_t>(got_offset);
    
    // Patch jump to PLT[0] (simplified)
    int32_t plt0_offset = -(static_cast<int32_t>(index + 1) * 16 + 5); // Approximate
    *reinterpret_cast<int32_t*>(&entry[11]) = plt0_offset;
    
    return entry;
}

std::vector<uint8_t> PLTGenerator::generate_plt_header_arm64(uint64_t got_address) {
    // ARM64 PLT header (simplified)
    std::vector<uint8_t> header = {
        // stp x16, x30, [sp, #-16]!
        0xf0, 0x7b, 0xbf, 0xa9,
        // adrp x16, GOT[1]
        0x10, 0x00, 0x00, 0x90,  // Will need proper relocation
        // ldr x17, [x16, #GOT[1]]
        0x11, 0x0a, 0x40, 0xf9,
        // add x16, x16, #GOT[1]
        0x10, 0x42, 0x00, 0x91,
        // br x17
        0x20, 0x02, 0x1f, 0xd6
    };
    
    return header;
}

std::vector<uint8_t> PLTGenerator::generate_plt_entry_arm64(uint32_t index, uint64_t got_offset) {
    // ARM64 PLT entry (simplified)
    std::vector<uint8_t> entry = {
        // adrp x16, GOT[n]
        0x10, 0x00, 0x00, 0x90,  // Will need proper relocation
        // ldr x17, [x16, #GOT[n]]
        0x11, 0x02, 0x40, 0xf9,  // Will need proper offset
        // add x16, x16, #GOT[n]
        0x10, 0x02, 0x00, 0x91,  // Will need proper offset
        // br x17
        0x20, 0x02, 0x1f, 0xd6
    };
    
    return entry;
}

PLTEntry* PLTGenerator::get_plt_entry(const std::string& symbol_name) {
    auto it = symbol_to_plt_index.find(symbol_name);
    if (it != symbol_to_plt_index.end() && it->second < plt_entries.size()) {
        return &plt_entries[it->second];
    }
    return nullptr;
}

uint64_t PLTGenerator::get_plt_size() const {
    // PLT header + entries
    uint64_t header_size = (target_arch == Architecture::X86_64) ? 16 : 20;
    uint64_t entry_size = (target_arch == Architecture::X86_64) ? 16 : 16;
    return header_size + plt_entries.size() * entry_size;
}

// GOTGenerator implementation
GOTGenerator::GOTGenerator(Architecture arch) : target_arch(arch) {
    entry_size = 8; // 64-bit pointers
}

bool GOTGenerator::generate_got_section(const std::vector<DynamicSymbol>& dynamic_symbols,
                                       Section& got_section, uint64_t plt_address) {
    got_section.name = ".got.plt";
    got_section.type = SectionType::PROGBITS;
    got_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC) | 
                       static_cast<uint64_t>(SectionFlags::WRITE);
    got_section.alignment = 8;
    
    // Add reserved GOT entries
    add_got_reserved_entries();
    
    // Add entries for dynamic symbols
    for (const auto& symbol : dynamic_symbols) {
        if (symbol.needs_got) {
            GOTEntry entry(static_cast<uint32_t>(got_entries.size()), symbol.name);
            entry.is_function = (symbol.type == SymbolType::FUNC);
            
            // For functions, initially point to PLT resolver
            if (entry.is_function && symbol.needs_plt) {
                entry.value = plt_address + 6; // Skip PLT header push instruction
            } else {
                entry.value = 0; // Will be resolved at runtime
            }
            
            got_entries.push_back(entry);
            symbol_to_got_index[symbol.name] = entry.index;
        }
    }
    
    // Generate GOT data
    std::vector<uint8_t> got_data;
    got_data.resize(got_entries.size() * entry_size);
    
    for (size_t i = 0; i < got_entries.size(); ++i) {
        uint64_t* entry_ptr = reinterpret_cast<uint64_t*>(got_data.data() + i * entry_size);
        *entry_ptr = got_entries[i].value;
    }
    
    got_section.data = got_data;
    got_section.size = got_data.size();
    
    return true;
}

void GOTGenerator::add_got_reserved_entries() {
    // GOT[0]: Address of dynamic section (filled by loader)
    GOTEntry dynamic_entry(0, "_DYNAMIC");
    dynamic_entry.value = 0;
    got_entries.push_back(dynamic_entry);
    
    // GOT[1]: Link map pointer (filled by loader)
    GOTEntry linkmap_entry(1, "_LINKMAP");
    linkmap_entry.value = 0;
    got_entries.push_back(linkmap_entry);
    
    // GOT[2]: dl_runtime_resolve function (filled by loader)
    GOTEntry resolver_entry(2, "_DL_RUNTIME_RESOLVE");
    resolver_entry.value = 0;
    got_entries.push_back(resolver_entry);
}

uint32_t GOTGenerator::add_got_entry(const std::string& symbol_name, bool is_function) {
    uint32_t index = static_cast<uint32_t>(got_entries.size());
    GOTEntry entry(index, symbol_name);
    entry.is_function = is_function;
    got_entries.push_back(entry);
    symbol_to_got_index[symbol_name] = index;
    return index;
}

GOTEntry* GOTGenerator::get_got_entry(const std::string& symbol_name) {
    auto it = symbol_to_got_index.find(symbol_name);
    if (it != symbol_to_got_index.end() && it->second < got_entries.size()) {
        return &got_entries[it->second];
    }
    return nullptr;
}

uint64_t GOTGenerator::get_got_size() const {
    return got_entries.size() * entry_size;
}

// DynamicSymbolTable implementation
void DynamicSymbolTable::add_symbol(const DynamicSymbol& symbol) {
    auto it = name_to_index.find(symbol.name);
    if (it != name_to_index.end()) {
        // Update existing symbol
        symbols[it->second] = symbol;
    } else {
        // Add new symbol
        uint32_t index = static_cast<uint32_t>(symbols.size());
        symbols.push_back(symbol);
        name_to_index[symbol.name] = index;
    }
}

DynamicSymbol* DynamicSymbolTable::get_symbol(const std::string& name) {
    auto it = name_to_index.find(name);
    if (it != name_to_index.end()) {
        return &symbols[it->second];
    }
    return nullptr;
}

void DynamicSymbolTable::mark_symbol_needs_plt(const std::string& name) {
    auto* symbol = get_symbol(name);
    if (symbol) {
        symbol->needs_plt = true;
        symbol->needs_got = true; // PLT entries need GOT entries
    }
}

void DynamicSymbolTable::mark_symbol_needs_got(const std::string& name) {
    auto* symbol = get_symbol(name);
    if (symbol) {
        symbol->needs_got = true;
    }
}

std::vector<DynamicSymbol> DynamicSymbolTable::get_plt_symbols() const {
    std::vector<DynamicSymbol> plt_symbols;
    for (const auto& symbol : symbols) {
        if (symbol.needs_plt) {
            plt_symbols.push_back(symbol);
        }
    }
    return plt_symbols;
}

std::vector<DynamicSymbol> DynamicSymbolTable::get_got_symbols() const {
    std::vector<DynamicSymbol> got_symbols;
    for (const auto& symbol : symbols) {
        if (symbol.needs_got) {
            got_symbols.push_back(symbol);
        }
    }
    return got_symbols;
}

bool DynamicSymbolTable::generate_dynsym_section(Section& dynsym_section) {
    dynsym_section.name = ".dynsym";
    dynsym_section.type = SectionType::DYNSYM;
    dynsym_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    dynsym_section.alignment = 8;
    dynsym_section.entry_size = 24; // ELF64_Sym size
    
    // Generate symbol table data (simplified)
    std::vector<uint8_t> symtab_data;
    
    // Add null symbol first
    symtab_data.resize(24, 0);
    
    // Add dynamic symbols
    for (const auto& symbol : symbols) {
        if (symbol.is_external || symbol.binding == SymbolBinding::GLOBAL) {
            // Create ELF64_Sym entry (simplified)
            std::vector<uint8_t> sym_entry(24, 0);
            
            // st_name (string table offset) - would need proper string table
            *reinterpret_cast<uint32_t*>(&sym_entry[0]) = 0;
            
            // st_info (binding and type)
            uint8_t binding = (symbol.binding == SymbolBinding::GLOBAL) ? 1 : 0;
            uint8_t type = (symbol.type == SymbolType::FUNC) ? 2 : 1;
            sym_entry[4] = (binding << 4) | type;
            
            // st_other (visibility)
            sym_entry[5] = 0;
            
            // st_shndx (section index)
            *reinterpret_cast<uint16_t*>(&sym_entry[6]) = symbol.is_external ? 0 : 1;
            
            // st_value (address)
            *reinterpret_cast<uint64_t*>(&sym_entry[8]) = symbol.address;
            
            // st_size (size)
            *reinterpret_cast<uint64_t*>(&sym_entry[16]) = symbol.size;
            
            symtab_data.insert(symtab_data.end(), sym_entry.begin(), sym_entry.end());
        }
    }
    
    dynsym_section.data = symtab_data;
    dynsym_section.size = symtab_data.size();
    
    return true;
}

bool DynamicSymbolTable::generate_dynstr_section(Section& dynstr_section) {
    dynstr_section.name = ".dynstr";
    dynstr_section.type = SectionType::STRTAB;
    dynstr_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC);
    dynstr_section.alignment = 1;
    
    std::vector<uint8_t> string_data;
    
    // Add null string first
    string_data.push_back(0);
    
    // Add symbol names
    for (const auto& symbol : symbols) {
        if (symbol.is_external || symbol.binding == SymbolBinding::GLOBAL) {
            add_string_to_table(symbol.name, string_data);
        }
    }
    
    dynstr_section.data = string_data;
    dynstr_section.size = string_data.size();
    
    return true;
}

uint32_t DynamicSymbolTable::add_string_to_table(const std::string& str, std::vector<uint8_t>& string_table) {
    uint32_t offset = static_cast<uint32_t>(string_table.size());
    string_table.insert(string_table.end(), str.begin(), str.end());
    string_table.push_back(0); // Null terminator
    return offset;
}

// DynamicLinker implementation
DynamicLinker::DynamicLinker(Architecture arch, Platform platform) 
    : target_arch(arch), target_platform(platform), plt_generator(arch), got_generator(arch) {
}

bool DynamicLinker::process_dynamic_symbols(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                          SymbolResolver& symbol_resolver) {
    
    // Analyze symbol dependencies
    if (!analyze_symbol_dependencies(object_files, symbol_resolver)) {
        return false;
    }
    
    // Assign PLT/GOT indices
    uint32_t plt_index = 0;
    uint32_t got_index = 3; // Skip reserved GOT entries
    
    auto& all_symbols = const_cast<std::vector<DynamicSymbol>&>(dynamic_symbols.get_symbols());
    for (auto& symbol : all_symbols) {
        if (symbol.needs_plt) {
            symbol.plt_index = plt_index++;
        }
        if (symbol.needs_got) {
            symbol.got_index = got_index++;
        }
    }
    
    return true;
}

bool DynamicLinker::analyze_symbol_dependencies(const std::vector<std::unique_ptr<ObjectFile>>& object_files,
                                               SymbolResolver& symbol_resolver) {
    
    // Collect all undefined external symbols
    std::unordered_set<std::string> external_symbols;
    
    for (const auto& obj_file : object_files) {
        for (const auto& symbol : obj_file->symbols) {
            if (!symbol.defined && symbol.binding != SymbolBinding::LOCAL) {
                external_symbols.insert(symbol.name);
            }
        }
    }
    
    // Process external symbols
    for (const auto& symbol_name : external_symbols) {
        if (is_external_symbol(symbol_name, symbol_resolver)) {
            DynamicSymbol dyn_symbol(symbol_name);
            dyn_symbol.is_external = true;
            dyn_symbol.binding = SymbolBinding::GLOBAL;
            dyn_symbol.library_name = get_symbol_library(symbol_name);
            
            // Determine if symbol needs PLT/GOT
            // For now, assume all external function symbols need PLT
            // and all external data symbols need GOT
            auto* resolved = symbol_resolver.get_symbol(symbol_name);
            if (resolved) {
                dyn_symbol.type = resolved->type;
                if (resolved->type == SymbolType::FUNC) {
                    dyn_symbol.needs_plt = true;
                    dyn_symbol.needs_got = true;
                } else {
                    dyn_symbol.needs_got = true;
                }
            } else {
                // Assume function if unknown
                dyn_symbol.type = SymbolType::FUNC;
                dyn_symbol.needs_plt = true;
                dyn_symbol.needs_got = true;
            }
            
            dynamic_symbols.add_symbol(dyn_symbol);
            
            // Add library dependency
            if (!dyn_symbol.library_name.empty()) {
                auto it = std::find(required_libraries.begin(), required_libraries.end(), 
                                   dyn_symbol.library_name);
                if (it == required_libraries.end()) {
                    required_libraries.push_back(dyn_symbol.library_name);
                }
            }
        }
    }
    
    return true;
}

bool DynamicLinker::generate_dynamic_sections(std::vector<Section>& sections, uint64_t base_address) {
    
    // Generate PLT section
    Section plt_section;
    if (!generate_plt_section(plt_section, base_address)) {
        return false;
    }
    sections.push_back(plt_section);
    
    // Generate GOT section
    Section got_section;
    uint64_t plt_address = base_address + 0x1000; // Simplified address calculation
    if (!generate_got_section(got_section, plt_address)) {
        return false;
    }
    sections.push_back(got_section);
    
    // Generate dynamic symbol table
    Section dynsym_section;
    if (!dynamic_symbols.generate_dynsym_section(dynsym_section)) {
        return false;
    }
    sections.push_back(dynsym_section);
    
    // Generate dynamic string table
    Section dynstr_section;
    if (!dynamic_symbols.generate_dynstr_section(dynstr_section)) {
        return false;
    }
    sections.push_back(dynstr_section);
    
    // Generate dynamic section
    Section dynamic_section;
    if (!generate_dynamic_section(dynamic_section)) {
        return false;
    }
    sections.push_back(dynamic_section);
    
    return true;
}

bool DynamicLinker::generate_plt_section(Section& plt_section, uint64_t base_address) {
    auto plt_symbols = dynamic_symbols.get_plt_symbols();
    uint64_t got_address = base_address + 0x2000; // Simplified
    return plt_generator.generate_plt_section(plt_symbols, plt_section, got_address);
}

bool DynamicLinker::generate_got_section(Section& got_section, uint64_t plt_address) {
    auto got_symbols = dynamic_symbols.get_got_symbols();
    return got_generator.generate_got_section(got_symbols, got_section, plt_address);
}

bool DynamicLinker::generate_dynamic_section(Section& dynamic_section) {
    dynamic_section.name = ".dynamic";
    dynamic_section.type = SectionType::DYNAMIC;
    dynamic_section.flags = static_cast<uint64_t>(SectionFlags::ALLOC) | 
                           static_cast<uint64_t>(SectionFlags::WRITE);
    dynamic_section.alignment = 8;
    dynamic_section.entry_size = 16; // DT_* entry size
    
    // Add dynamic entries
    add_dynamic_entry(DynamicTag::DT_STRTAB, 0); // String table address
    add_dynamic_entry(DynamicTag::DT_SYMTAB, 0); // Symbol table address
    add_dynamic_entry(DynamicTag::DT_STRSZ, 0);  // String table size
    add_dynamic_entry(DynamicTag::DT_SYMENT, 24); // Symbol entry size
    
    // Add library dependencies
    for (const auto& library : required_libraries) {
        (void)library; // Suppress unused warning - would use library name offset in real implementation
        add_dynamic_entry(DynamicTag::DT_NEEDED, 0); // Library name offset in string table
    }
    
    // Add PLT/GOT entries
    if (!dynamic_symbols.get_plt_symbols().empty()) {
        add_dynamic_entry(DynamicTag::DT_PLTGOT, 0);   // GOT address
        add_dynamic_entry(DynamicTag::DT_PLTRELSZ, 0); // PLT relocation size
        add_dynamic_entry(DynamicTag::DT_PLTREL, 7);   // PLT relocation type (RELA)
        add_dynamic_entry(DynamicTag::DT_JMPREL, 0);   // PLT relocations address
    }
    
    // Terminator
    add_dynamic_entry(DynamicTag::DT_NULL, 0);
    
    // Generate section data
    std::vector<uint8_t> dynamic_data;
    dynamic_data.resize(dynamic_entries.size() * 16);
    
    for (size_t i = 0; i < dynamic_entries.size(); ++i) {
        uint64_t* entry_ptr = reinterpret_cast<uint64_t*>(dynamic_data.data() + i * 16);
        entry_ptr[0] = static_cast<uint64_t>(dynamic_entries[i].tag);
        entry_ptr[1] = dynamic_entries[i].value;
    }
    
    dynamic_section.data = dynamic_data;
    dynamic_section.size = dynamic_data.size();
    
    return true;
}

void DynamicLinker::add_dynamic_entry(DynamicTag tag, uint64_t value) {
    dynamic_entries.emplace_back(tag, value);
}

void DynamicLinker::add_library_dependency(const std::string& library_name) {
    auto it = std::find(required_libraries.begin(), required_libraries.end(), library_name);
    if (it == required_libraries.end()) {
        required_libraries.push_back(library_name);
    }
}

bool DynamicLinker::is_external_symbol(const std::string& symbol_name, SymbolResolver& resolver) {
    auto* resolved = resolver.get_symbol(symbol_name);
    return !resolved || resolved->is_external;
}

std::string DynamicLinker::get_symbol_library(const std::string& symbol_name) {
    // Simplified library detection - would need proper symbol resolution
    // Common C library functions
    if (symbol_name == "printf" || symbol_name == "malloc" || symbol_name == "free" ||
        symbol_name == "strlen" || symbol_name == "strcmp" || symbol_name == "memcpy") {
        return "libc.so.6";
    }
    
    // Math library functions
    if (symbol_name == "sin" || symbol_name == "cos" || symbol_name == "sqrt") {
        return "libm.so.6";
    }
    
    // Default to libc
    return "libc.so.6";
}

} // namespace Linker
