#include "relocation_engine.h"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace Linker {

RelocationEngine::RelocationEngine(Architecture arch) : target_arch(arch) {
    switch (arch) {
        case Architecture::X86_64:
            init_x86_64_handlers();
            break;
        case Architecture::ARM64:
            init_arm64_handlers();
            break;
    }
}

bool RelocationEngine::process_relocation(const Relocation& reloc, Section& section, 
                                         uint64_t symbol_address, uint64_t base_address) {
    if (!is_valid_relocation(reloc.type)) {
        std::cerr << "Invalid relocation type: " << static_cast<int>(reloc.type) << std::endl;
        return false;
    }
    
    if (reloc.offset >= section.data.size()) {
        std::cerr << "Relocation offset out of bounds: " << reloc.offset 
                  << " >= " << section.data.size() << std::endl;
        return false;
    }
    
    uint64_t relocation_address = section.address + reloc.offset;
    
    auto handler_it = handlers.find(reloc.type);
    if (handler_it != handlers.end()) {
        return handler_it->second(reloc, section, symbol_address, relocation_address);
    }
    
    std::cerr << "No handler for relocation type: " << static_cast<int>(reloc.type) << std::endl;
    return false;
}

bool RelocationEngine::process_section_relocations(Section& section, 
                                                  const std::vector<Symbol>& symbols,
                                                  uint64_t base_address) {
    bool success = true;
    
    for (const auto& reloc : section.relocations) {
        if (reloc.symbol_index >= symbols.size()) {
            std::cerr << "Invalid symbol index in relocation: " << reloc.symbol_index << std::endl;
            success = false;
            continue;
        }
        
        const auto& symbol = symbols[reloc.symbol_index];
        uint64_t symbol_address = base_address + symbol.value;
        
        if (!process_relocation(reloc, section, symbol_address, base_address)) {
            success = false;
        }
    }
    
    return success;
}

bool RelocationEngine::is_valid_relocation(RelocationType type) const {
    return handlers.find(type) != handlers.end();
}

uint32_t RelocationEngine::get_relocation_size(RelocationType type) const {
    switch (type) {
        case RelocationType::X86_64_64:
        case RelocationType::X86_64_PC64:
        case RelocationType::AARCH64_ABS64:
            return 8;
            
        case RelocationType::X86_64_PC32:
        case RelocationType::X86_64_32:
        case RelocationType::X86_64_32S:
        case RelocationType::X86_64_PLT32:
        case RelocationType::X86_64_GOTPCREL:
        case RelocationType::AARCH64_ABS32:
        case RelocationType::AARCH64_CALL26:
        case RelocationType::AARCH64_JUMP26:
        case RelocationType::AARCH64_ADR_PREL_PG_HI21:
        case RelocationType::AARCH64_ADD_ABS_LO12_NC:
        case RelocationType::AARCH64_LDST64_ABS_LO12_NC:
            return 4;
            
        default:
            return 0;
    }
}

bool RelocationEngine::is_pc_relative(RelocationType type) const {
    switch (type) {
        case RelocationType::X86_64_PC32:
        case RelocationType::X86_64_PC64:
        case RelocationType::X86_64_PLT32:
        case RelocationType::X86_64_GOTPCREL:
        case RelocationType::AARCH64_CALL26:
        case RelocationType::AARCH64_JUMP26:
        case RelocationType::AARCH64_ADR_PREL_PG_HI21:
            return true;
        default:
            return false;
    }
}

void RelocationEngine::init_x86_64_handlers() {
    handlers[RelocationType::X86_64_64] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_64(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_PC32] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_pc32(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_32] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_32(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_32S] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_32s(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_PC64] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_pc64(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_PLT32] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_plt32(r, s, sym, rel);
    };
    handlers[RelocationType::X86_64_GOTPCREL] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_x86_64_gotpcrel(r, s, sym, rel);
    };
}

void RelocationEngine::init_arm64_handlers() {
    handlers[RelocationType::AARCH64_ABS64] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_abs64(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_ABS32] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_abs32(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_CALL26] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_call26(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_JUMP26] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_jump26(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_ADR_PREL_PG_HI21] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_adr_prel_pg_hi21(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_ADD_ABS_LO12_NC] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_add_abs_lo12_nc(r, s, sym, rel);
    };
    handlers[RelocationType::AARCH64_LDST64_ABS_LO12_NC] = [this](const Relocation& r, Section& s, uint64_t sym, uint64_t rel) {
        return handle_aarch64_ldst64_abs_lo12_nc(r, s, sym, rel);
    };
}

// x86_64 relocation handlers
bool RelocationEngine::handle_x86_64_64(const Relocation& reloc, Section& section, 
                                        uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t value = symbol_addr + reloc.addend;
    return write_relocation_value(section, reloc.offset, value, 8);
}

bool RelocationEngine::handle_x86_64_pc32(const Relocation& reloc, Section& section, 
                                          uint64_t symbol_addr, uint64_t reloc_addr) {
    int64_t value = static_cast<int64_t>(symbol_addr + reloc.addend - reloc_addr);
    
    // Check if value fits in 32-bit signed integer
    if (value < INT32_MIN || value > INT32_MAX) {
        std::cerr << "PC32 relocation out of range: " << value << std::endl;
        return false;
    }
    
    return write_relocation_value(section, reloc.offset, static_cast<uint32_t>(value), 4);
}

bool RelocationEngine::handle_x86_64_32(const Relocation& reloc, Section& section, 
                                        uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t value = symbol_addr + reloc.addend;
    
    // Check if value fits in 32-bit unsigned integer
    if (value > UINT32_MAX) {
        std::cerr << "32-bit relocation out of range: " << value << std::endl;
        return false;
    }
    
    return write_relocation_value(section, reloc.offset, static_cast<uint32_t>(value), 4);
}

bool RelocationEngine::handle_x86_64_32s(const Relocation& reloc, Section& section, 
                                         uint64_t symbol_addr, uint64_t reloc_addr) {
    int64_t value = static_cast<int64_t>(symbol_addr + reloc.addend);
    
    // Check if value fits in 32-bit signed integer
    if (value < INT32_MIN || value > INT32_MAX) {
        std::cerr << "32S relocation out of range: " << value << std::endl;
        return false;
    }
    
    return write_relocation_value(section, reloc.offset, static_cast<uint32_t>(value), 4);
}

bool RelocationEngine::handle_x86_64_pc64(const Relocation& reloc, Section& section, 
                                          uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t value = symbol_addr + reloc.addend - reloc_addr;
    return write_relocation_value(section, reloc.offset, value, 8);
}

bool RelocationEngine::handle_x86_64_plt32(const Relocation& reloc, Section& section, 
                                           uint64_t symbol_addr, uint64_t reloc_addr) {
    // For now, treat PLT32 like PC32 (no PLT table yet)
    return handle_x86_64_pc32(reloc, section, symbol_addr, reloc_addr);
}

bool RelocationEngine::handle_x86_64_gotpcrel(const Relocation& reloc, Section& section, 
                                              uint64_t symbol_addr, uint64_t reloc_addr) {
    // For now, treat GOTPCREL like PC32 (no GOT table yet)
    return handle_x86_64_pc32(reloc, section, symbol_addr, reloc_addr);
}

// ARM64 relocation handlers
bool RelocationEngine::handle_aarch64_abs64(const Relocation& reloc, Section& section, 
                                            uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t value = symbol_addr + reloc.addend;
    return write_relocation_value(section, reloc.offset, value, 8);
}

bool RelocationEngine::handle_aarch64_abs32(const Relocation& reloc, Section& section, 
                                            uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t value = symbol_addr + reloc.addend;
    
    // Check if value fits in 32-bit
    if (value > UINT32_MAX) {
        std::cerr << "ABS32 relocation out of range: " << value << std::endl;
        return false;
    }
    
    return write_relocation_value(section, reloc.offset, static_cast<uint32_t>(value), 4);
}

bool RelocationEngine::handle_aarch64_call26(const Relocation& reloc, Section& section, 
                                             uint64_t symbol_addr, uint64_t reloc_addr) {
    int64_t offset = static_cast<int64_t>(symbol_addr + reloc.addend - reloc_addr);
    
    // Check 26-bit branch range (±128MB)
    if (offset < -0x8000000 || offset > 0x7FFFFFF) {
        std::cerr << "CALL26 relocation out of range: " << offset << std::endl;
        return false;
    }
    
    // Read existing instruction
    uint32_t existing_insn = read_relocation_value(section, reloc.offset, 4);
    
    // Encode branch offset (word-aligned)
    uint32_t branch_offset = static_cast<uint32_t>((offset >> 2) & 0x3FFFFFF);
    uint32_t new_insn = (existing_insn & 0xFC000000) | branch_offset;
    
    return write_relocation_value(section, reloc.offset, new_insn, 4);
}

bool RelocationEngine::handle_aarch64_jump26(const Relocation& reloc, Section& section, 
                                             uint64_t symbol_addr, uint64_t reloc_addr) {
    // Same as CALL26 for unconditional branches
    return handle_aarch64_call26(reloc, section, symbol_addr, reloc_addr);
}

bool RelocationEngine::handle_aarch64_adr_prel_pg_hi21(const Relocation& reloc, Section& section, 
                                                       uint64_t symbol_addr, uint64_t reloc_addr) {
    uint64_t target_page = (symbol_addr + reloc.addend) & ~0xFFF;
    uint64_t reloc_page = reloc_addr & ~0xFFF;
    int64_t page_offset = static_cast<int64_t>(target_page - reloc_page);
    
    // Check 21-bit page offset range
    if (page_offset < -0x100000000LL || page_offset > 0xFFFFF000LL) {
        std::cerr << "ADR_PREL_PG_HI21 relocation out of range: " << page_offset << std::endl;
        return false;
    }
    
    // Read existing instruction
    uint32_t existing_insn = read_relocation_value(section, reloc.offset, 4);
    
    // Encode page offset in ADRP instruction
    uint32_t imm_lo = static_cast<uint32_t>((page_offset >> 12) & 0x3);
    uint32_t imm_hi = static_cast<uint32_t>((page_offset >> 14) & 0x7FFFF);
    uint32_t new_insn = (existing_insn & 0x9F00001F) | (imm_lo << 29) | (imm_hi << 5);
    
    return write_relocation_value(section, reloc.offset, new_insn, 4);
}

bool RelocationEngine::handle_aarch64_add_abs_lo12_nc(const Relocation& reloc, Section& section, 
                                                      uint64_t symbol_addr, uint64_t reloc_addr) {
    uint32_t page_offset = static_cast<uint32_t>((symbol_addr + reloc.addend) & 0xFFF);
    
    // Read existing instruction
    uint32_t existing_insn = read_relocation_value(section, reloc.offset, 4);
    
    // Encode immediate in ADD instruction
    uint32_t new_insn = (existing_insn & 0xFFC003FF) | (page_offset << 10);
    
    return write_relocation_value(section, reloc.offset, new_insn, 4);
}

bool RelocationEngine::handle_aarch64_ldst64_abs_lo12_nc(const Relocation& reloc, Section& section, 
                                                         uint64_t symbol_addr, uint64_t reloc_addr) {
    uint32_t page_offset = static_cast<uint32_t>((symbol_addr + reloc.addend) & 0xFFF);
    
    // For 64-bit loads/stores, offset must be 8-byte aligned
    if (page_offset & 0x7) {
        std::cerr << "LDST64 relocation not 8-byte aligned: " << page_offset << std::endl;
        return false;
    }
    
    // Read existing instruction
    uint32_t existing_insn = read_relocation_value(section, reloc.offset, 4);
    
    // Encode scaled immediate (divide by 8 for 64-bit access)
    uint32_t scaled_imm = page_offset >> 3;
    uint32_t new_insn = (existing_insn & 0xFFC003FF) | (scaled_imm << 10);
    
    return write_relocation_value(section, reloc.offset, new_insn, 4);
}

// Helper functions
bool RelocationEngine::write_relocation_value(Section& section, uint64_t offset, 
                                             uint64_t value, uint32_t size) {
    if (offset + size > section.data.size()) {
        std::cerr << "Relocation write out of bounds" << std::endl;
        return false;
    }
    
    uint8_t* ptr = section.data.data() + offset;
    
    switch (size) {
        case 1:
            *ptr = static_cast<uint8_t>(value);
            break;
        case 2:
            *reinterpret_cast<uint16_t*>(ptr) = static_cast<uint16_t>(value);
            break;
        case 4:
            *reinterpret_cast<uint32_t*>(ptr) = static_cast<uint32_t>(value);
            break;
        case 8:
            *reinterpret_cast<uint64_t*>(ptr) = value;
            break;
        default:
            std::cerr << "Invalid relocation size: " << size << std::endl;
            return false;
    }
    
    return true;
}

bool RelocationEngine::check_relocation_bounds(uint64_t value, uint32_t size, bool is_signed) {
    switch (size) {
        case 1:
            return is_signed ? (static_cast<int64_t>(value) >= INT8_MIN && 
                               static_cast<int64_t>(value) <= INT8_MAX) :
                              (value <= UINT8_MAX);
        case 2:
            return is_signed ? (static_cast<int64_t>(value) >= INT16_MIN && 
                               static_cast<int64_t>(value) <= INT16_MAX) :
                              (value <= UINT16_MAX);
        case 4:
            return is_signed ? (static_cast<int64_t>(value) >= INT32_MIN && 
                               static_cast<int64_t>(value) <= INT32_MAX) :
                              (value <= UINT32_MAX);
        case 8:
            return true; // 64-bit can hold any value
        default:
            return false;
    }
}

uint64_t RelocationEngine::read_relocation_value(const Section& section, uint64_t offset, uint32_t size) {
    if (offset + size > section.data.size()) {
        return 0;
    }
    
    const uint8_t* ptr = section.data.data() + offset;
    
    switch (size) {
        case 1:
            return *ptr;
        case 2:
            return *reinterpret_cast<const uint16_t*>(ptr);
        case 4:
            return *reinterpret_cast<const uint32_t*>(ptr);
        case 8:
            return *reinterpret_cast<const uint64_t*>(ptr);
        default:
            return 0;
    }
}

// RelocationOptimizer implementation
bool RelocationOptimizer::optimize_relocations(std::vector<Section>& sections) {
    bool optimized = false;
    
    for (auto& section : sections) {
        if (convert_to_pc_relative(section, section.relocations)) {
            optimized = true;
        }
        if (merge_relocations(section.relocations)) {
            optimized = true;
        }
        if (eliminate_redundant_relocations(section.relocations)) {
            optimized = true;
        }
    }
    
    return optimized;
}

bool RelocationOptimizer::convert_to_pc_relative(Section& section, std::vector<Relocation>& relocations) {
    // TODO: Implement PC-relative conversion optimization
    return false;
}

bool RelocationOptimizer::merge_relocations(std::vector<Relocation>& relocations) {
    // TODO: Implement relocation merging optimization
    return false;
}

bool RelocationOptimizer::eliminate_redundant_relocations(std::vector<Relocation>& relocations) {
    // Remove relocations that don't actually change anything
    size_t original_size = relocations.size();
    
    relocations.erase(
        std::remove_if(relocations.begin(), relocations.end(),
            [](const Relocation& reloc) {
                return reloc.addend == 0 && reloc.type == RelocationType::X86_64_NONE;
            }),
        relocations.end()
    );
    
    return relocations.size() != original_size;
}

bool RelocationOptimizer::can_convert_to_pc_relative(const Relocation& reloc, uint64_t symbol_addr, 
                                                    uint64_t reloc_addr) const {
    // Check if the distance fits in PC-relative addressing
    int64_t distance = static_cast<int64_t>(symbol_addr - reloc_addr);
    
    switch (target_arch) {
        case Architecture::X86_64:
            // Can convert to PC32 if distance fits in 32-bit signed
            return (distance >= INT32_MIN && distance <= INT32_MAX);
        case Architecture::ARM64:
            // Can convert to branch if distance fits in 26-bit signed (word-aligned)
            return (distance >= -0x8000000 && distance <= 0x7FFFFFF && (distance & 0x3) == 0);
        default:
            return false;
    }
}

} // namespace Linker
