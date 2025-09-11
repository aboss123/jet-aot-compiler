#pragma once
#include "backends/codegen/backend.h"
#include "assemblers/arm64-codegen.h"
#include "core/tools/macho_builder.h"
#include "core/tools/elf_builder.h"
#include <map>

namespace CodeGen {

class ARM64Backend : public Backend {
public:
  ARM64Backend(TargetPlatform platform = TargetPlatform::MACOS);
  ~ARM64Backend() override = default;
  
  bool compile_module(const IR::Module& module) override;
  const uint8_t* get_code() const override;
  size_t get_code_size() const override;
  bool write_object(const std::string& path, const std::string& entry_symbol = "main") override;
  bool write_executable(const std::string& path, const std::string& entry_symbol = "main") override;
  bool link_executable(const std::string& obj_path, const std::string& exe_path) override;

private:
  std::unique_ptr<nextgen::jet::arm64::Assembler> assembler;
  TargetPlatform target_platform;
  std::vector<uint8_t> data_section;
  std::map<std::string, size_t> string_offsets; // string -> offset in data section
  std::vector<MachOBuilder64::Relocation> relocations;
  std::vector<std::pair<std::string, uint32_t>> data_symbols; // name -> data offset
  MachOBuilder64 macho_builder;
  ELFBuilder64 elf_builder;
  
  // Label management for control flow
  std::map<std::string, nextgen::jet::arm64::Label> string_labels;
  
  // Register allocation (simple for now)
  std::map<uint32_t, nextgen::jet::arm64::Register> reg_map;
  nextgen::jet::arm64::Register next_reg;
  
  // Code generation
  void compile_function(const IR::Function& func);
  void compile_basic_block(const IR::BasicBlock& bb);
  void compile_instruction(const IR::Instruction& inst);
  
  // Helpers
  nextgen::jet::arm64::Register get_or_alloc_register(const IR::Value& val);
  nextgen::jet::arm64::Register get_or_alloc_register(const std::shared_ptr<IR::Register>& reg);
  nextgen::jet::arm64::Register get_operand_register(const std::shared_ptr<IR::Value>& operand);
  nextgen::jet::arm64::Register get_register_for_type(const IR::Type& type);
  void emit_syscall_exit(int32_t code);
  void emit_syscall_write(const std::string& message);
  void emit_syscall(const IR::SyscallInst& inst);
  
  // Data section support
  void add_string_to_data_section(const std::string& str);
  
  // Atomic operation helpers
  void emit_atomic_load(const IR::AtomicLoadInst& inst);
  void emit_atomic_store(const IR::AtomicStoreInst& inst);
  void emit_atomic_cas(const IR::AtomicCASInst& inst);
  void emit_atomic_rmw(const IR::AtomicRMWInst& inst);
  void emit_atomic_fence(const IR::AtomicFenceInst& inst);
  void emit_memory_barrier(IR::MemoryOrdering ordering);
};

} // namespace CodeGen
