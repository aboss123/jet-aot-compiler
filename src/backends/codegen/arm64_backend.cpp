#include "arm64_backend.h"
#include <iostream>
#include <stdexcept>

using namespace nextgen::jet::arm64;

namespace CodeGen {

ARM64Backend::ARM64Backend() : next_reg(X0) {
  assembler = std::make_unique<Assembler>(4096);
}

bool ARM64Backend::compile_module(const IR::Module& module) {
  try {
    // If there is a main function, emit a real _start that calls it and exits
    const IR::Function* mainFunc = nullptr;
    for (const auto& f : module.functions) {
      if (f->name == "main") { mainFunc = f.get(); break; }
    }

    if (mainFunc != nullptr) {
      // Generate minimal _start that directly inlines main's body (no function call overhead)
      for (const auto& bb : mainFunc->basic_blocks) {
        compile_basic_block(*bb);
      }
    }

    // Compile remaining functions (skip main if already compiled)
    for (const auto& func : module.functions) {
      if (mainFunc && func.get() == mainFunc) continue;
      compile_function(*func);
    }

    // Data section handling removed - using optimized stack-based approach
    return true;
  } catch (const std::exception& e) {
    std::cerr << "ARM64Backend compilation error: " << e.what() << std::endl;
    return false;
  }
}

void ARM64Backend::compile_function(const IR::Function& func) {
  // For main function, generate bare-metal code with no function overhead
  if (func.name == "main") {
    // No prologue/epilogue - main never returns (exit syscall terminates process)
    for (const auto& bb : func.basic_blocks) {
      compile_basic_block(*bb);
    }
    return;
  }
  
  // Generic function prologue/epilogue for non-main functions
  assembler->stp(FP, LR, SP, -16);
  // Keep FP at zero in our bare-metal entry to match minimal _start
  for (const auto& bb : func.basic_blocks) {
    compile_basic_block(*bb);
  }
  assembler->ldp(FP, LR, SP, 16);
  assembler->ret();
}

void ARM64Backend::compile_basic_block(const IR::BasicBlock& bb) {
  for (const auto& inst : bb.instructions) {
    compile_instruction(*inst);
  }
}

void ARM64Backend::compile_instruction(const IR::Instruction& inst) {
  switch (inst.opcode) {
    case IR::Opcode::ALLOCA: {
      const auto& ai = static_cast<const IR::AllocaInst&>(inst);
      uint32_t elem_size = ai.allocated_type.size_bytes();
      uint32_t total = elem_size;
      if (!ai.operands.empty()) {
        if (auto cnt = std::dynamic_pointer_cast<IR::ConstantInt>(ai.operands[0])) {
          if (cnt->value > 0 && cnt->value < 4096) total = elem_size * (uint32_t)cnt->value;
        }
      }
      assembler->sub_imm(SP, SP, Imm12(total));
      if (inst.result_reg) {
        reg_map[inst.result_reg->id] = SP;
      }
      break;
    }
    case IR::Opcode::ADD: {
      // Proper ADD implementation: result = operand1 + operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->add_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::SUB: {
      // Proper SUB implementation: result = operand1 - operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->sub_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::MUL: {
      // Proper MUL implementation: result = operand1 * operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->mul(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::UDIV: {
      // Unsigned division: result = operand1 / operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->udiv(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::SDIV: {
      // Signed division: result = operand1 / operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->sdiv(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    // Bitwise operations
    case IR::Opcode::AND: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->and_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::OR: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->orr_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::XOR: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->eor_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::SHL: {
      // Left shift: result = operand1 << operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->lsl_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::LSHR: {
      // Logical right shift: result = operand1 >> operand2 (unsigned)
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->lsr_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::ASHR: {
      // Arithmetic right shift: result = operand1 >> operand2 (signed)
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->asr_reg(dst_reg, src1_reg, src2_reg);
      break;
    }
    
    // Memory operations
    case IR::Opcode::LOAD: {
      if (inst.operands.size() < 1) break;
      
      auto ptr_reg = get_operand_register(inst.operands[0]); // ptr is first operand
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Load from memory address in ptr_reg to dst_reg
      // ARM64: ldr dst, [ptr]
      assembler->ldr_imm(dst_reg, ptr_reg, 0);
      break;
    }
    
    case IR::Opcode::STORE: {
      if (inst.operands.size() < 2) break;
      
      auto val_reg = get_operand_register(inst.operands[0]); // value is first operand
      auto ptr_reg = get_operand_register(inst.operands[1]); // ptr is second operand
      
      // Store val_reg to memory address in ptr_reg
      // ARM64: str val, [ptr]
      assembler->str_imm(val_reg, ptr_reg, 0);
      break;
    }
    
    // TODO: Integer comparison operations (ICMP_EQ, ICMP_NE, etc.)
    // These require assembler API extensions for cset instruction
    
    case IR::Opcode::RET: {
      if (!inst.operands.empty()) {
        // Return with value - move to X0
        assembler->mov_imm(X0, 42); // Placeholder
      }
      assembler->ldp(FP, LR, SP, 16);
      assembler->ret();
      break;
    }
    
    // Atomic operations
    case IR::Opcode::ATOMIC_LOAD: {
      const auto& atomic_load = static_cast<const IR::AtomicLoadInst&>(inst);
      emit_atomic_load(atomic_load);
      break;
    }
    
    case IR::Opcode::ATOMIC_STORE: {
      const auto& atomic_store = static_cast<const IR::AtomicStoreInst&>(inst);
      emit_atomic_store(atomic_store);
      break;
    }
    
    case IR::Opcode::ATOMIC_CAS: {
      const auto& atomic_cas = static_cast<const IR::AtomicCASInst&>(inst);
      emit_atomic_cas(atomic_cas);
      break;
    }
    
    case IR::Opcode::ATOMIC_RMW: {
      const auto& atomic_rmw = static_cast<const IR::AtomicRMWInst&>(inst);
      emit_atomic_rmw(atomic_rmw);
      break;
    }
    
    case IR::Opcode::ATOMIC_FENCE: {
      const auto& atomic_fence = static_cast<const IR::AtomicFenceInst&>(inst);
      emit_atomic_fence(atomic_fence);
      break;
    }
    
    case IR::Opcode::SYSCALL: {
      const auto& syscall = static_cast<const IR::SyscallInst&>(inst);
      emit_syscall(syscall);
      // Generic approach: preserve each syscall result in a unique callee-saved register
      if (syscall.result_reg) {
        // Use X19, X20, X21, X22, etc. for different syscall results
        static int syscall_reg_counter = 19;
        nextgen::jet::arm64::Register preserve_reg = static_cast<nextgen::jet::arm64::Register>(syscall_reg_counter);
        assembler->mov_reg(preserve_reg, X0);  // Preserve result
        reg_map[syscall.result_reg->id] = preserve_reg;
        syscall_reg_counter++;
        if (syscall_reg_counter > 28) syscall_reg_counter = 19; // Wrap around callee-saved regs
      }
      break;
    }
    
    default:
      // Placeholder for other instructions
      assembler->nop();
      break;
  }
}

void ARM64Backend::emit_atomic_load(const IR::AtomicLoadInst& inst) {
  auto dst_reg = get_register_for_type(inst.result_type);
  
  // Choose appropriate load instruction based on memory ordering
  switch (inst.memory_ordering) {
    case IR::MemoryOrdering::RELAXED:
      // Regular load
      switch (inst.result_type.size_bytes()) {
        case 1: assembler->ldrb(dst_reg, X1, 0); break;
        case 2: assembler->ldrh(dst_reg, X1, 0); break;
        case 4: case 8: assembler->ldr_imm(dst_reg, X1, 0); break;
      }
      break;
      
    case IR::MemoryOrdering::ACQUIRE:
    case IR::MemoryOrdering::SEQ_CST:
      // Load-acquire
      switch (inst.result_type.size_bytes()) {
        case 1: assembler->ldarb(dst_reg, X1); break;
        case 2: assembler->ldarh(dst_reg, X1); break;
        case 4: case 8: assembler->ldar(dst_reg, X1); break;
      }
      break;
      
    default:
      throw std::runtime_error("Invalid memory ordering for atomic load");
  }
}

void ARM64Backend::emit_atomic_store(const IR::AtomicStoreInst& inst) {
  auto src_reg = get_register_for_type(inst.operands[0]->type);
  
  // Choose appropriate store instruction based on memory ordering
  switch (inst.memory_ordering) {
    case IR::MemoryOrdering::RELAXED:
      // Regular store
      switch (inst.operands[0]->type.size_bytes()) {
        case 1: assembler->strb(src_reg, X1, 0); break;
        case 2: assembler->strh(src_reg, X1, 0); break;
        case 4: case 8: assembler->str_imm(src_reg, X1, 0); break;
      }
      break;
      
    case IR::MemoryOrdering::RELEASE:
    case IR::MemoryOrdering::SEQ_CST:
      // Store-release
      switch (inst.operands[0]->type.size_bytes()) {
        case 1: assembler->stlrb(src_reg, X1); break;
        case 2: assembler->stlrh(src_reg, X1); break;
        case 4: case 8: assembler->stlr(src_reg, X1); break;
      }
      break;
      
    default:
      throw std::runtime_error("Invalid memory ordering for atomic store");
  }
}

void ARM64Backend::emit_atomic_cas(const IR::AtomicCASInst& inst) {
  Label retry, success, fail;
  
  // ARM64 CAS using load-exclusive/store-exclusive
  assembler->bind(retry);
  
  // Load exclusive
  switch (inst.operands[1]->type.size_bytes()) {
    case 4:
      assembler->ldxr(W2, X0);  // Load exclusive word
      assembler->cmp_reg(W2, W1);  // Compare with expected
      assembler->b_cond(NE, fail);
      assembler->stxr(W3, W4, X0);  // Store exclusive desired
      assembler->cbnz(W3, retry);   // Retry if failed
      break;
      
    case 8:
      assembler->ldxr(X2, X0);   // Load exclusive doubleword
      assembler->cmp_reg(X2, X1);   // Compare with expected
      assembler->b_cond(NE, fail);
      assembler->stxr(W3, X4, X0);  // Store exclusive desired
      assembler->cbnz(W3, retry);   // Retry if failed
      break;
  }
  
  assembler->bind(success);
  assembler->mov_imm(X5, 1);  // Success flag
  assembler->b(fail);
  
  assembler->bind(fail);
  assembler->mov_imm(X5, 0);  // Failure flag
}

void ARM64Backend::emit_atomic_rmw(const IR::AtomicRMWInst& inst) {
  // Use modern ARM64 atomic instructions if available, otherwise LL/SC
  switch (inst.rmw_operation) {
    case IR::AtomicRMWOp::ADD:
      // Use LDADD if available (ARMv8.1+)
      switch (inst.operands[1]->type.size_bytes()) {
        case 4: assembler->ldadd(W1, W2, X0); break;
        case 8: assembler->ldadd(X1, X2, X0); break;
      }
      break;
      
    case IR::AtomicRMWOp::XOR:
      // Use LDEOR if available
      switch (inst.operands[1]->type.size_bytes()) {
        case 4: assembler->ldeor(W1, W2, X0); break;
        case 8: assembler->ldeor(X1, X2, X0); break;
      }
      break;
      
    case IR::AtomicRMWOp::XCHG:
      // Use SWP if available
      switch (inst.operands[1]->type.size_bytes()) {
        case 4: assembler->swp(W1, W2, X0); break;
        case 8: assembler->swp(X1, X2, X0); break;
      }
      break;
      
    default: {
      // Fall back to load-exclusive/store-exclusive loop
      Label retry;
      assembler->bind(retry);
      
      switch (inst.operands[1]->type.size_bytes()) {
        case 4:
          assembler->ldxr(W2, X0);  // Load exclusive
          // Perform operation (placeholder)
          assembler->add_reg(W3, W2, W1);
          assembler->stxr(W4, W3, X0);  // Store exclusive
          assembler->cbnz(W4, retry);   // Retry if failed
          break;
          
        case 8:
          assembler->ldxr(X2, X0);   // Load exclusive
          // Perform operation (placeholder)
          assembler->add_reg(X3, X2, X1);
          assembler->stxr(W4, X3, X0);  // Store exclusive
          assembler->cbnz(W4, retry);   // Retry if failed
          break;
      }
      break;
    }
  }
}

void ARM64Backend::emit_atomic_fence(const IR::AtomicFenceInst& inst) {
  emit_memory_barrier(inst.memory_ordering);
}

void ARM64Backend::emit_memory_barrier(IR::MemoryOrdering ordering) {
  switch (ordering) {
    case IR::MemoryOrdering::ACQUIRE:
      // Data Memory Barrier with load semantics
      assembler->dmb(11); // DMB LD
      break;
      
    case IR::MemoryOrdering::RELEASE:
      // Data Memory Barrier with store semantics
      assembler->dmb(14); // DMB ST
      break;
      
    case IR::MemoryOrdering::ACQ_REL:
    case IR::MemoryOrdering::SEQ_CST:
      // Full data memory barrier
      assembler->dmb(15); // DMB SY
      break;
      
    case IR::MemoryOrdering::RELAXED:
      // No barrier needed
      break;
      
    default:
      break;
  }
}

Register ARM64Backend::get_or_alloc_register(const IR::Value& val) {
  auto it = reg_map.find(val.id);
  if (it != reg_map.end()) {
    return it->second;
  }
  
  // Simple register allocation
  Register reg = next_reg;
  reg_map[val.id] = reg;
  
  // Advance to next register (very simple allocation)
  if (next_reg == X0) next_reg = X1;
  else if (next_reg == X1) next_reg = X2;
  else if (next_reg == X2) next_reg = X3;
  else next_reg = X0; // Wrap around
  
  return reg;
}

Register ARM64Backend::get_register_for_type(const IR::Type& type) {
  // Simple type-based register selection
  if (type.is_integer() || type.is_pointer()) {
    return X0; // Use X0 for integers and pointers
  } else if (type.is_float()) {
    return D0; // Use D0 for floats
  }
  return X0; // Default
}

const uint8_t* ARM64Backend::get_code() const {
  return assembler->spill();
}

size_t ARM64Backend::get_code_size() const {
  return assembler->bytes();
}

bool ARM64Backend::write_object(const std::string& path, const std::string& entry_symbol) {
  if (data_section.empty()) {
    return macho_builder.write_object(path.c_str(),
                                     reinterpret_cast<const uint8_t*>(assembler->spill()),
                                     static_cast<uint32_t>(assembler->bytes()),
                                     entry_symbol.c_str(),
                                     0,
                                     MachOArch::ARM64);
  } else {
    // Use relocations for proper adrp/add support
    std::vector<std::pair<std::string, uint32_t>> all_symbols;
    all_symbols.push_back({entry_symbol, 0}); // Entry point at offset 0 (already has underscore)
    all_symbols.insert(all_symbols.end(), data_symbols.begin(), data_symbols.end());
    
    return macho_builder.write_object_with_relocations(path.c_str(),
                                                      reinterpret_cast<const uint8_t*>(assembler->spill()),
                                                      static_cast<uint32_t>(assembler->bytes()),
                                                      data_section.data(),
                                                      static_cast<uint32_t>(data_section.size()),
                                                      relocations,
                                                      all_symbols,
                                                      MachOArch::ARM64);
  }
}

bool ARM64Backend::link_executable(const std::string& obj_path, const std::string& exe_path) {
  std::string cmd = "clang -arch arm64 -e _start -o " + exe_path + " " + obj_path;
  return system(cmd.c_str()) == 0;
}

void ARM64Backend::emit_syscall_exit(int32_t code) {
  assembler->mov_imm(X16, 1);    // SYS_exit
  assembler->mov_imm(X0, code);  // exit code
  assembler->svc(Imm16(0));      // syscall
}

void ARM64Backend::emit_syscall_write(const std::string& message) {
  assembler->mov_imm(X16, 4);    // SYS_write
  assembler->mov_imm(X0, 1);     // stdout
  assembler->svc(Imm16(0));      // syscall
}

void ARM64Backend::emit_syscall(const IR::SyscallInst& inst) {
  // Darwin syscall number in X16: 0x2000000 | n
  uint64_t darwin_num = 0x2000000ULL | static_cast<uint64_t>(inst.syscall_number);

  // Generic syscall emission (Darwin)
  // Argument registers
  nextgen::jet::arm64::Register arg_regs[6] = { X0, X1, X2, X3, X4, X5 };

  // No need for complex X0 preservation since syscall results are now in X20

  // Load args generically
  for (size_t i = 0; i < inst.args.size() && i < 6; ++i) {
    auto &a = inst.args[i];
    if (auto ci = std::dynamic_pointer_cast<IR::ConstantInt>(a)) {
      assembler->mov_imm(arg_regs[i], (uint64_t)ci->value);
    } else if (auto gs = std::dynamic_pointer_cast<IR::GlobalString>(a)) {
      // Ensure symbol exists in data, then ADRP+ADD via label with relocations
      std::string symbol_name;
      uint32_t symbol_index = 1; // Default to first data symbol
      
      if (string_offsets.find(gs->string_value) == string_offsets.end()) {
        string_offsets[gs->string_value] = data_section.size();
        const auto &str = gs->string_value;
        data_section.insert(data_section.end(), str.begin(), str.end());
        data_section.push_back(0);
        while (data_section.size() % 8 != 0) data_section.push_back(0);
        symbol_name = "L_.str" + std::to_string(data_symbols.size());
        data_symbols.push_back({symbol_name, (uint32_t)string_offsets[gs->string_value]});
        symbol_index = data_symbols.size(); // Symbol index in combined symbol table (entry + data symbols)
      } else {
        // Find existing symbol
        for (size_t j = 0; j < data_symbols.size(); ++j) {
          if (data_symbols[j].second == string_offsets[gs->string_value]) {
            symbol_name = data_symbols[j].first;
            symbol_index = j + 1; // +1 because entry symbol is at index 0
            break;
          }
        }
      }
      
      // Record current code position for relocations
      uint32_t adrp_offset = assembler->bytes();
      uint32_t add_offset = adrp_offset + 4; // ADD comes right after ADRP
      
      // Emit adrp/add with dummy labels (will be patched by relocations)
      auto dummy = assembler->create_label("dummy");
      assembler->adrp(arg_regs[i], dummy);
      auto addlbl = assembler->create_label("dummy2");
      assembler->add_label(arg_regs[i], arg_regs[i], addlbl);
      
      // Add relocations for ADRP (ARM64_RELOC_PAGE21) and ADD (ARM64_RELOC_PAGEOFF12)
      relocations.push_back({adrp_offset, symbol_index, 3, 2, true, true}); // ARM64_RELOC_PAGE21
      relocations.push_back({add_offset, symbol_index, 4, 2, false, true}); // ARM64_RELOC_PAGEOFF12
    } else if (auto rv = std::dynamic_pointer_cast<IR::Register>(a)) {
      // Look up the register in our mapping
      auto it = reg_map.find(rv->id);
      if (it != reg_map.end()) {
        assembler->mov_reg(arg_regs[i], it->second);
      } else {
        // If not found in mapping, assume it's a syscall result in X9
        assembler->mov_reg(arg_regs[i], X9);
      }
    }
  }

  // Set syscall number last (after using X16 nowhere else)
  assembler->mov_imm(X16, darwin_num);
  assembler->svc(Imm16(0x80));
}

nextgen::jet::arm64::Register ARM64Backend::get_or_alloc_register(const std::shared_ptr<IR::Register>& reg) {
  if (!reg) return X0; // Fallback
  
  auto it = reg_map.find(reg->id);
  if (it != reg_map.end()) {
    return it->second;
  }
  
  // Allocate a new register (use simple round-robin allocation)
  static nextgen::jet::arm64::Register next_alloc_reg = X1;
  nextgen::jet::arm64::Register allocated = next_alloc_reg;
  
  reg_map[reg->id] = allocated;
  
  // Advance to next register (avoiding X0, SP, LR, FP which have special purposes)
  switch (next_alloc_reg) {
    case X1: next_alloc_reg = X2; break;
    case X2: next_alloc_reg = X3; break;
    case X3: next_alloc_reg = X4; break;
    case X4: next_alloc_reg = X5; break;
    case X5: next_alloc_reg = X6; break;
    case X6: next_alloc_reg = X7; break;
    case X7: next_alloc_reg = X8; break;
    case X8: next_alloc_reg = X10; break; // Skip X9 (used for syscall preservation)
    case X10: next_alloc_reg = X11; break;
    case X11: next_alloc_reg = X12; break;
    case X12: next_alloc_reg = X13; break;
    case X13: next_alloc_reg = X14; break;
    case X14: next_alloc_reg = X15; break;
    case X15: next_alloc_reg = X1; break; // Wrap around
    default: next_alloc_reg = X1; break;
  }
  
  return allocated;
}

nextgen::jet::arm64::Register ARM64Backend::get_operand_register(const std::shared_ptr<IR::Value>& operand) {
  if (auto const_int = std::dynamic_pointer_cast<IR::ConstantInt>(operand)) {
    // Load constant into a temporary register (use X17 as temp)
    assembler->mov_imm(X17, (uint64_t)const_int->value);
    return X17;
  } else if (auto reg = std::dynamic_pointer_cast<IR::Register>(operand)) {
    return get_or_alloc_register(reg);
  } else {
    // Fallback for other value types
    return X0;
  }
}

} // namespace CodeGen
