#pragma once
#include "standalone_linker.h"
#include <functional>
#include <unordered_map>

namespace Linker {

// Relocation processing engine with architecture-specific handlers
class RelocationEngine {
public:
    // Relocation handler function type
    using RelocationHandler = std::function<bool(const Relocation& reloc, 
                                               Section& section, 
                                               uint64_t symbol_address,
                                               uint64_t relocation_address)>;
    
    RelocationEngine(Architecture arch);
    ~RelocationEngine() = default;
    
    // Process a single relocation
    bool process_relocation(const Relocation& reloc, Section& section, 
                           uint64_t symbol_address, uint64_t base_address = 0);
    
    // Process all relocations in a section
    bool process_section_relocations(Section& section, 
                                   const std::vector<Symbol>& symbols,
                                   uint64_t base_address = 0);
    
    // Validate relocation type for current architecture
    bool is_valid_relocation(RelocationType type) const;
    
    // Get relocation size in bytes
    uint32_t get_relocation_size(RelocationType type) const;
    
    // Check if relocation is PC-relative
    bool is_pc_relative(RelocationType type) const;
    
private:
    Architecture target_arch;
    std::unordered_map<RelocationType, RelocationHandler> handlers;
    
    // Initialize architecture-specific handlers
    void init_x86_64_handlers();
    void init_arm64_handlers();
    
    // x86_64 relocation handlers
    bool handle_x86_64_64(const Relocation& reloc, Section& section, 
                         uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_pc32(const Relocation& reloc, Section& section, 
                           uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_32(const Relocation& reloc, Section& section, 
                         uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_32s(const Relocation& reloc, Section& section, 
                          uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_pc64(const Relocation& reloc, Section& section, 
                           uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_plt32(const Relocation& reloc, Section& section, 
                            uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_x86_64_gotpcrel(const Relocation& reloc, Section& section, 
                               uint64_t symbol_addr, uint64_t reloc_addr);
    
    // ARM64 relocation handlers
    bool handle_aarch64_abs64(const Relocation& reloc, Section& section, 
                             uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_abs32(const Relocation& reloc, Section& section, 
                             uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_call26(const Relocation& reloc, Section& section, 
                              uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_jump26(const Relocation& reloc, Section& section, 
                              uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_adr_prel_pg_hi21(const Relocation& reloc, Section& section, 
                                        uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_add_abs_lo12_nc(const Relocation& reloc, Section& section, 
                                       uint64_t symbol_addr, uint64_t reloc_addr);
    bool handle_aarch64_ldst64_abs_lo12_nc(const Relocation& reloc, Section& section, 
                                          uint64_t symbol_addr, uint64_t reloc_addr);
    
    // Helper functions
    bool write_relocation_value(Section& section, uint64_t offset, 
                               uint64_t value, uint32_t size);
    bool check_relocation_bounds(uint64_t value, uint32_t size, bool is_signed = false);
    uint64_t read_relocation_value(const Section& section, uint64_t offset, uint32_t size);
    
    // ARM64 instruction encoding helpers
    uint32_t encode_aarch64_branch(uint64_t target_offset);
    uint32_t encode_aarch64_adrp(uint64_t page_offset);
    uint32_t encode_aarch64_add_imm(uint32_t existing_insn, uint32_t imm);
    uint32_t encode_aarch64_ldst_imm(uint32_t existing_insn, uint32_t imm);
};

// Advanced relocation features
class RelocationOptimizer {
public:
    RelocationOptimizer(Architecture arch) : target_arch(arch) {}
    
    // Optimize relocations for performance
    bool optimize_relocations(std::vector<Section>& sections);
    
    // Convert absolute relocations to PC-relative where possible
    bool convert_to_pc_relative(Section& section, std::vector<Relocation>& relocations);
    
    // Merge adjacent relocations
    bool merge_relocations(std::vector<Relocation>& relocations);
    
    // Eliminate unnecessary relocations
    bool eliminate_redundant_relocations(std::vector<Relocation>& relocations);
    
private:
    Architecture target_arch;
    
    // Check if conversion is safe
    bool can_convert_to_pc_relative(const Relocation& reloc, uint64_t symbol_addr, 
                                   uint64_t reloc_addr) const;
};

} // namespace Linker
