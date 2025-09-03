#pragma once
#include "backends/codegen/backend.h"
#include "backends/codegen/register_allocator.h"
#include "backends/codegen/x64_register_set.h"
#include "assemblers/x64-codegen.h"
#include "core/tools/macho_builder.h"
#include <map>
#include <memory>

namespace CodeGen {

// Forward declarations
class RegisterAllocator;
class X64RegisterSet;

class X64Backend : public Backend {
public:
  X64Backend();
  ~X64Backend() override = default;
  
  bool compile_module(const IR::Module& module) override;
  const uint8_t* get_code() const override;
  size_t get_code_size() const override;
  bool write_object(const std::string& path, const std::string& entry_symbol = "main") override;
  bool link_executable(const std::string& obj_path, const std::string& exe_path) override;

private:
  std::unique_ptr<nextgen::jet::x64::Assembler> assembler;
  MachOBuilder64 macho_builder;
  
  // Register allocation
  std::unique_ptr<RegisterAllocator> register_allocator;
  std::shared_ptr<X64RegisterSet> register_set;
  AllocationResult current_allocation;
  
  // Legacy naive allocation (fallback)
  std::map<uint32_t, nextgen::jet::x64::Register> reg_map;
  nextgen::jet::x64::Register next_reg;
  bool use_advanced_allocation;
  
  // Data section and relocation support (like ARM64 backend)
  std::vector<uint8_t> data_section;
  std::map<std::string, uint32_t> string_offsets;
  std::vector<MachOBuilder64::Relocation> relocations;
  std::vector<std::pair<std::string, uint32_t>> data_symbols;
  
  // Code generation
  void compile_function(const IR::Function& func);
  void compile_basic_block(const IR::BasicBlock& bb);
  void compile_instruction(const IR::Instruction& inst);
  
  // Register allocation helpers
  nextgen::jet::x64::Register get_allocated_register(uint32_t value_id);
  nextgen::jet::x64::Register convert_to_native_register(const Register& generic_reg);
  void emit_spill_code(uint32_t value_id, const IR::Instruction& inst);
  void emit_reload_code(uint32_t value_id, const IR::Instruction& inst);
  
  // Legacy helpers (for fallback)
  nextgen::jet::x64::Register get_or_alloc_register(const IR::Value& val);
  nextgen::jet::x64::Register get_or_alloc_register(const std::shared_ptr<IR::Register>& reg);
  nextgen::jet::x64::Register get_operand_register(const std::shared_ptr<IR::Value>& operand);
  nextgen::jet::x64::Register get_register_for_type(const IR::Type& type);
  void emit_syscall_exit(int32_t code);
  void emit_syscall_write(const std::string& message);
  
  // Atomic operation helpers
  void emit_atomic_load(const IR::AtomicLoadInst& inst);
  void emit_atomic_store(const IR::AtomicStoreInst& inst);
  void emit_atomic_cas(const IR::AtomicCASInst& inst);
  void emit_atomic_rmw(const IR::AtomicRMWInst& inst);
  void emit_atomic_fence(const IR::AtomicFenceInst& inst);
  void emit_memory_barrier(IR::MemoryOrdering ordering);
  
  // Data section and relocation support
  void emit_syscall(uint32_t syscall_number, const std::vector<std::shared_ptr<IR::Value>>& args);
  void add_string_to_data_section(const std::string& str);
  
  // String materialization (generic, not hardcoded)
  void emit_string_to_stack(const std::string& str);
  
  // Embedded string support (like hello2 pattern)
  void add_string_to_embedded_section(const std::string& str);
  std::vector<uint8_t> embedded_strings;
  std::map<std::string, nextgen::jet::x64::Label> string_labels;
};

} // namespace CodeGen
