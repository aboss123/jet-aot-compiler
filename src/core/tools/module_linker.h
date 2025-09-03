#pragma once
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "assemblers/x64-codegen.h"
#include "macho_builder.h"

// Multi-object linker that combines multiple Assembler outputs into a single executable
class ModuleLinker {
public:
  // Relocation types
  enum class RelocationType {
    REL32,      // 32-bit relative (RIP-relative on x64)
    ABS64,      // 64-bit absolute address
    ABS32,      // 32-bit absolute address
    CALL_REL32  // 32-bit relative call
  };
  
  struct Relocation {
    uint32_t offset;           // offset in code where relocation applies
    std::string symbol_name;   // name of symbol being referenced
    RelocationType type;       // type of relocation
    int32_t addend = 0;        // additional offset to add
  };

  struct Module {
    std::string name;
    std::vector<uint8_t> code;
    std::vector<std::string> exports;     // symbols this module exports
    std::vector<std::string> imports;     // symbols this module needs
    std::map<std::string, uint32_t> symbol_offsets; // export name -> offset in code
    std::vector<Relocation> relocations;  // relocations needed
  };
  
  struct ExternalSymbol {
    std::string name;
    void* address;  // resolved address
  };
  
  // Add a module from an Assembler
  void add_module(const std::string& name, 
                  const nextgen::jet::x64::Assembler& assembler,
                  const std::vector<std::string>& exports = {},
                  const std::vector<std::string>& imports = {});
  
  // Add an external symbol (e.g., libc functions)
  void add_external(const std::string& name, void* address);
  
  // Resolve all symbols and create final layout
  bool resolve_symbols();
  
  // Link into a single executable
  bool link_executable(const std::string& output_path, const std::string& entry_symbol = "main");
  
  // Link into a single object file (for further linking with system linker)
  bool link_object(const std::string& output_path);
  
  // Get final address of a symbol (after linking)
  uint64_t get_symbol_address(const std::string& name) const;
  
  // Add a relocation to the most recently added module
  void add_relocation(uint32_t offset, const std::string& symbol_name, 
                     RelocationType type, int32_t addend = 0);

private:
  std::vector<Module> modules;
  std::map<std::string, ExternalSymbol> externals;
  std::map<std::string, uint64_t> resolved_symbols;
  std::vector<uint8_t> linked_code;
  bool symbols_resolved = false;
  
  uint64_t base_address = 0x100000000ULL;  // Standard macOS base
  
  void layout_modules();
  void apply_relocations();
  uint32_t find_symbol_in_modules(const std::string& name, uint32_t& module_idx) const;
};

// Helper to create simple single-function modules
class SimpleModule {
public:
  static ModuleLinker::Module create_function(const std::string& func_name,
                                            const nextgen::jet::x64::Assembler& assembler);
  
  static ModuleLinker::Module create_main_syscall(const std::string& message);
};
