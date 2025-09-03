#include "module_linker.h"
#include <iostream>
#include <cstring>

using namespace nextgen::jet::x64;

void ModuleLinker::add_module(const std::string& name, 
                             const Assembler& assembler,
                             const std::vector<std::string>& exports,
                             const std::vector<std::string>& imports) {
  Module mod;
  mod.name = name;
  mod.code.assign(assembler.spill(), assembler.spill() + assembler.bytes());
  mod.exports = exports;
  mod.imports = imports;
  
  // For now, assume single export at offset 0
  if (!exports.empty()) {
    mod.symbol_offsets[exports[0]] = 0;
  }
  
  modules.push_back(std::move(mod));
  symbols_resolved = false;
}

void ModuleLinker::add_external(const std::string& name, void* address) {
  externals[name] = ExternalSymbol{name, address};
}

bool ModuleLinker::resolve_symbols() {
  resolved_symbols.clear();
  uint64_t current_addr = base_address;
  
  // Layout modules sequentially
  for (auto& mod : modules) {
    // Align each module to 16 bytes
    current_addr = (current_addr + 15) & ~15ULL;
    
    // Resolve exports from this module
    for (const auto& exp : mod.exports) {
      uint64_t symbol_addr = current_addr + mod.symbol_offsets[exp];
      resolved_symbols[exp] = symbol_addr;
    }
    
    current_addr += mod.code.size();
  }
  
  // Add externals
  for (const auto& ext : externals) {
    resolved_symbols[ext.first] = (uint64_t)ext.second.address;
  }
  
  // Check all imports are satisfied
  for (const auto& mod : modules) {
    for (const auto& imp : mod.imports) {
      if (resolved_symbols.find(imp) == resolved_symbols.end()) {
        std::cerr << "Unresolved symbol: " << imp << std::endl;
        return false;
      }
    }
  }
  
  symbols_resolved = true;
  return true;
}

bool ModuleLinker::link_executable(const std::string& output_path, const std::string& entry_symbol) {
  if (!symbols_resolved && !resolve_symbols()) {
    return false;
  }
  
  // Check entry symbol exists
  if (resolved_symbols.find(entry_symbol) == resolved_symbols.end()) {
    std::cerr << "Entry symbol not found: " << entry_symbol << std::endl;
    return false;
  }
  
  layout_modules();
  apply_relocations();
  
  uint64_t entry_addr = resolved_symbols[entry_symbol];
  uint32_t entry_offset = (uint32_t)(entry_addr - base_address);
  
  MachOBuilder64 builder;
  return builder.write_executable(output_path.c_str(), 
                                linked_code.data(), 
                                (uint32_t)linked_code.size(), 
                                entry_offset);
}

bool ModuleLinker::link_object(const std::string& output_path) {
  if (!symbols_resolved && !resolve_symbols()) {
    return false;
  }
  
  layout_modules();
  apply_relocations();
  
  // For object files, we need the first exported symbol as the main symbol
  std::string main_symbol = "main";
  for (const auto& mod : modules) {
    if (!mod.exports.empty()) {
      main_symbol = mod.exports[0];
      break;
    }
  }
  
  MachOBuilder64 builder;
  return builder.write_object(output_path.c_str(),
                            linked_code.data(),
                            (uint32_t)linked_code.size(),
                            ("_" + main_symbol).c_str(),
                            0);
}

uint64_t ModuleLinker::get_symbol_address(const std::string& name) const {
  auto it = resolved_symbols.find(name);
  return (it != resolved_symbols.end()) ? it->second : 0;
}

void ModuleLinker::add_relocation(uint32_t offset, const std::string& symbol_name, 
                                 RelocationType type, int32_t addend) {
  if (modules.empty()) {
    std::cerr << "Error: No modules to add relocation to" << std::endl;
    return;
  }
  
  Relocation reloc;
  reloc.offset = offset;
  reloc.symbol_name = symbol_name;
  reloc.type = type;
  reloc.addend = addend;
  
  modules.back().relocations.push_back(reloc);
}

void ModuleLinker::layout_modules() {
  linked_code.clear();
  uint64_t current_addr = base_address;
  
  for (const auto& mod : modules) {
    // Align to 16 bytes
    while ((current_addr % 16) != 0) {
      linked_code.push_back(0x90); // NOP padding
      current_addr++;
    }
    
    linked_code.insert(linked_code.end(), mod.code.begin(), mod.code.end());
    current_addr += mod.code.size();
  }
}

void ModuleLinker::apply_relocations() {
  uint64_t current_addr = base_address;
  
  // Process each module and apply relocations
  for (auto& mod : modules) {
    // Align module to 16 bytes
    current_addr = (current_addr + 15) & ~15ULL;
    uint64_t module_base = current_addr;
    
    // Apply relocations for this module
    for (const auto& reloc : mod.relocations) {
      // Find target symbol address
      auto symbol_it = resolved_symbols.find(reloc.symbol_name);
      if (symbol_it == resolved_symbols.end()) {
        std::cerr << "Relocation error: Symbol not found: " << reloc.symbol_name << std::endl;
        continue;
      }
      
      uint64_t symbol_addr = symbol_it->second + reloc.addend;
      uint64_t reloc_addr = module_base + reloc.offset;
      
      // Calculate offset in linked_code for this relocation
      size_t linked_offset = reloc_addr - base_address;
      if (linked_offset >= linked_code.size()) {
        std::cerr << "Relocation error: Invalid offset" << std::endl;
        continue;
      }
      
      // Apply relocation based on type
      switch (reloc.type) {
        case RelocationType::REL32: {
          // 32-bit relative (RIP-relative)
          int64_t rel_value = symbol_addr - (reloc_addr + 4); // +4 for instruction size
          if (rel_value < INT32_MIN || rel_value > INT32_MAX) {
            std::cerr << "Relocation error: REL32 out of range" << std::endl;
            continue;
          }
          uint32_t rel32 = (uint32_t)(int32_t)rel_value;
          memcpy(&linked_code[linked_offset], &rel32, 4);
          break;
        }
        
        case RelocationType::ABS64: {
          // 64-bit absolute address
          memcpy(&linked_code[linked_offset], &symbol_addr, 8);
          break;
        }
        
        case RelocationType::ABS32: {
          // 32-bit absolute address
          if (symbol_addr > UINT32_MAX) {
            std::cerr << "Relocation error: ABS32 out of range" << std::endl;
            continue;
          }
          uint32_t abs32 = (uint32_t)symbol_addr;
          memcpy(&linked_code[linked_offset], &abs32, 4);
          break;
        }
        
        case RelocationType::CALL_REL32: {
          // 32-bit relative call
          int64_t rel_value = symbol_addr - (reloc_addr + 4);
          if (rel_value < INT32_MIN || rel_value > INT32_MAX) {
            std::cerr << "Relocation error: CALL_REL32 out of range" << std::endl;
            continue;
          }
          uint32_t rel32 = (uint32_t)(int32_t)rel_value;
          memcpy(&linked_code[linked_offset], &rel32, 4);
          break;
        }
        
        default:
          std::cerr << "Relocation error: Unknown relocation type" << std::endl;
          break;
      }
    }
    
    current_addr += mod.code.size();
  }
}

uint32_t ModuleLinker::find_symbol_in_modules(const std::string& name, uint32_t& module_idx) const {
  for (uint32_t i = 0; i < modules.size(); ++i) {
    auto it = modules[i].symbol_offsets.find(name);
    if (it != modules[i].symbol_offsets.end()) {
      module_idx = i;
      return it->second;
    }
  }
  return UINT32_MAX;
}

// SimpleModule implementation
ModuleLinker::Module SimpleModule::create_function(const std::string& func_name,
                                                  const Assembler& assembler) {
  ModuleLinker::Module mod;
  mod.name = func_name + "_module";
  mod.code.assign(assembler.spill(), assembler.spill() + assembler.bytes());
  mod.exports = {func_name};
  mod.symbol_offsets[func_name] = 0;
  return mod;
}

ModuleLinker::Module SimpleModule::create_main_syscall(const std::string& message) {
  Assembler a(512);
  Label Lstr;
  
  // write(1, message, len)
  size_t len = message.length();
  a.movq(AX, Imm64{0x2000004ULL});      // SYS_write
  a.movq(DI, Imm64{1});                 // stdout
  a.leaq_rip_label(SI, Lstr);           // message address
  a.movq(DX, Imm64{(uint64_t)len});     // length
  a.syscall();
  
  // exit(0)
  a.movq(AX, Imm64{0x2000001ULL});      // SYS_exit
  a.movd(DI, Imm32{0});                 // status
  a.syscall();
  
  // Data
  a.align_to(4);
  a.place_label(Lstr);
  for (char c : message) a.emit_u8((ubyte)c);
  a.emit_u8(0);
  
  return create_function("main", a);
}
