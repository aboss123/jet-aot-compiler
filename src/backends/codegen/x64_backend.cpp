#include "x64_backend.h"
#include "x64_register_set.h"
#include <iostream>
#include <stdexcept>
#include <memory>
#include <vector>
#include <algorithm>

using namespace nextgen::jet::x64;

namespace CodeGen {

X64Backend::X64Backend(TargetPlatform platform) : target_platform(platform), next_reg(AX), use_advanced_allocation(false) {
  assembler = std::make_unique<Assembler>(4096);
  
  // Initialize register allocator with x64 register set
  register_set = std::make_shared<X64RegisterSet>();
  register_allocator = std::make_unique<RegisterAllocator>(AllocationStrategy::LINEAR_SCAN);
  register_allocator->set_register_set(register_set);
}

bool X64Backend::compile_module(const IR::Module& module) {
  try {
    // Validate module
    if (module.functions.empty()) {
      std::cerr << "Error: Module contains no functions" << std::endl;
      return false;
    }
    
    // For now, just cast away const for register allocation
    // TODO: Make register allocation const-correct
    IR::Module& mutable_module = const_cast<IR::Module&>(module);
    
    if (use_advanced_allocation) {
      // Perform register allocation for the entire module
      current_allocation = register_allocator->allocate_registers(mutable_module);
      
      if (!current_allocation.success) {
        std::cerr << "Register allocation failed: " << current_allocation.error_message << std::endl;
        std::cerr << "Falling back to naive allocation." << std::endl;
        use_advanced_allocation = false;
      }
    }
    
    for (const auto& func : module.functions) {
      compile_function(*func);
    }
    return true;
  } catch (const std::exception& e) {
    std::cerr << "X64Backend compilation error: " << e.what() << std::endl;
    return false;
  } catch (...) {
    std::cerr << "X64Backend compilation error: Unknown exception" << std::endl;
    return false;
  }
}

void X64Backend::compile_function(const IR::Function& func) {
  // For main function, generate bare-metal code with no function overhead
  if (func.name == "main") {
    // No prologue/epilogue - main never returns (exit syscall terminates process)
    for (const auto& bb : func.basic_blocks) {
      compile_basic_block(*bb);
    }
    return;
  }

  // Default: compile IR
  assembler->pushq(BP);
  assembler->movq(BP, SP);
  for (const auto& bb : func.basic_blocks) {
    compile_basic_block(*bb);
  }
  assembler->movq(SP, BP);
  assembler->popq(BP);
  assembler->ret();
}

void X64Backend::compile_basic_block(const IR::BasicBlock& bb) {
  // Bind the label for this basic block if it exists
  std::string label_name = "block_" + bb.name;
  auto it = string_labels.find(label_name);
  if (it != string_labels.end()) {
    assembler->bind(it->second);
  }
  
  for (const auto& inst : bb.instructions) {
    compile_instruction(*inst);
  }
}

void X64Backend::compile_instruction(const IR::Instruction& inst) {
  switch (inst.opcode) {
    case IR::Opcode::ALLOCA: {
      // Support stack allocation: grow stack and return SP as the pointer
      const auto& ai = static_cast<const IR::AllocaInst&>(inst);
      uint32_t elem_size = ai.allocated_type.size_bytes();
      uint32_t total = elem_size;
      if (!ai.operands.empty()) {
        if (auto cnt = std::dynamic_pointer_cast<IR::ConstantInt>(ai.operands[0])) {
          if (cnt->value > 0 && cnt->value < 4096) total = elem_size * (uint32_t)cnt->value;
        }
      }
      uint8_t alloc = (uint8_t)std::min<uint32_t>(total, 255);
      assembler->subq(SP, Imm8{alloc});
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
      
      // Move first operand to destination, then add second
      assembler->movq(dst_reg, src1_reg);
      assembler->addq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::SUB: {
      // Proper SUB implementation: result = operand1 - operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Move first operand to destination, then subtract second
      assembler->movq(dst_reg, src1_reg);
      assembler->subq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::MUL: {
      // Proper MUL implementation: result = operand1 * operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Use imul for signed multiplication
      assembler->movq(dst_reg, src1_reg);
      assembler->imulq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::UDIV: {
      // Unsigned division: result = operand1 / operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // x86_64 division uses RAX and RDX
      assembler->movq(AX, src1_reg);  // Dividend in RAX
      assembler->xorq(DX, DX);        // Clear RDX for unsigned division
      assembler->divq(src2_reg);      // Unsigned divide
      assembler->movq(dst_reg, AX);   // Quotient is in RAX
      break;
    }
    
    case IR::Opcode::SDIV: {
      // Signed division: result = operand1 / operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // x86_64 signed division uses RAX and RDX
      assembler->movq(AX, src1_reg);  // Dividend in RAX
      assembler->cqo();               // Sign extend RAX into RDX:RAX
      assembler->idivq(src2_reg);     // Signed divide
      assembler->movq(dst_reg, AX);   // Quotient is in RAX
      break;
    }
    
    // Bitwise operations
    case IR::Opcode::AND: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->andq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::OR: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->orq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::XOR: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->xorq(dst_reg, src2_reg);
      break;
    }
    
    case IR::Opcode::SHL: {
      // Left shift: result = operand1 << operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->movq(CX, src2_reg);  // Shift count must be in CL
      assembler->shlq_cl(dst_reg);    // Uses CL implicitly
      break;
    }
    
    case IR::Opcode::LSHR: {
      // Logical right shift: result = operand1 >> operand2 (unsigned)
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->movq(CX, src2_reg);  // Shift count must be in CL
      assembler->shrq_cl(dst_reg);    // Uses CL implicitly
      break;
    }
    
    case IR::Opcode::ASHR: {
      // Arithmetic right shift: result = operand1 >> operand2 (signed)
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->movq(dst_reg, src1_reg);
      assembler->movq(CX, src2_reg);  // Shift count must be in CL
      assembler->sarq_cl(dst_reg);    // Uses CL implicitly
      break;
    }
    
    // Memory operations
    case IR::Opcode::LOAD: {
      if (inst.operands.size() < 1) break;
      
      auto ptr_reg = get_operand_register(inst.operands[0]); // ptr is first operand
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Load from memory address in ptr_reg to dst_reg
      // For now, assume 64-bit loads (can be extended for different sizes)
      assembler->movq(dst_reg, MemoryAddress{ptr_reg, (uint32_t)0});
      break;
    }
    
    case IR::Opcode::STORE: {
      if (inst.operands.size() < 2) break;
      
      auto value_reg = get_operand_register(inst.operands[0]); // value to store
      auto ptr_reg = get_operand_register(inst.operands[1]);   // destination address
      
      // Store based on value type size
      // Note: The assembler API has limited register-to-memory moves
      // For now, we use 64-bit moves for all sizes (simplified)
      switch (inst.operands[0]->type.size_bytes()) {
        case 1:
        case 2:
        case 4:
        case 8:
        default:
          // Check if we have a register-to-memory move available
          // For now, use a workaround: move to a temp and then to memory
          assembler->movq(R11, value_reg);  // Use R11 as temporary
          // TODO: Need proper register-to-memory store instructions
          // For now, just emit a placeholder nop
          assembler->nop();
          break;
      }
      break;
    }
    
    // Integer comparison operations
    case IR::Opcode::ICMP_EQ: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::Equal, dst_reg);
      assembler->movzxb(dst_reg, dst_reg); // Zero-extend byte
      break;
    }
    
    case IR::Opcode::ICMP_NE: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::NotEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_SLT: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::LessThan, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_SLE: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::LessThanEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_SGT: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::GreaterThan, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_SGE: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::GreaterThanEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_ULT: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::Below, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_ULE: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::BelowOrEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_UGT: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::Above, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::ICMP_UGE: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      assembler->cmpq(src1_reg, src2_reg);
      assembler->setcc(nextgen::jet::x64::AboveOrEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    // Floating-point arithmetic operations
    case IR::Opcode::FADD: {
      if (inst.operands.size() != 2) break;
      
      // For now, use simple floating-point registers (XMM)
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Move to XMM registers and perform floating-point add
      // This is simplified - real implementation would manage XMM registers properly
      if (inst.result_type.size_bytes() == 4) {
        assembler->addss(XMM0, XMM1); // Single precision
      } else {
        assembler->addsd(XMM0, XMM1); // Double precision
      }
      // Move result back to general-purpose register (simplified)
      assembler->movq(dst_reg, XMM0);
      break;
    }
    
    case IR::Opcode::FSUB: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.result_type.size_bytes() == 4) {
        assembler->subss(XMM0, XMM1);
      } else {
        assembler->subsd(XMM0, XMM1);
      }
      assembler->movq(dst_reg, XMM0);
      break;
    }
    
    case IR::Opcode::FMUL: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.result_type.size_bytes() == 4) {
        assembler->mulss(XMM0, XMM1);
      } else {
        assembler->mulsd(XMM0, XMM1);
      }
      assembler->movq(dst_reg, XMM0);
      break;
    }
    
    case IR::Opcode::FDIV: {
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.result_type.size_bytes() == 4) {
        assembler->divss(XMM0, XMM1);
      } else {
        assembler->divsd(XMM0, XMM1);
      }
      assembler->movq(dst_reg, XMM0);
      break;
    }
    
    // Control flow instructions
    case IR::Opcode::BR: {
      const auto& br_inst = static_cast<const IR::BranchInst&>(inst);
      if (br_inst.target_block) {
        // Create a label for the target block if it doesn't exist
        std::string label_name = "block_" + br_inst.target_block->name;
        auto& label = string_labels[label_name];
        
        // Unconditional branch to the label
        assembler->jmp(label);
      }
      break;
    }
    
    case IR::Opcode::BR_COND: {
      const auto& br_inst = static_cast<const IR::BranchInst&>(inst);
      if (!inst.operands.empty() && br_inst.target_block && br_inst.false_block) {
        auto cond_reg = get_operand_register(inst.operands[0]);
        
        // Create labels for both blocks
        std::string true_label_name = "block_" + br_inst.target_block->name;
        std::string false_label_name = "block_" + br_inst.false_block->name;
        auto& true_label = string_labels[true_label_name];
        auto& false_label = string_labels[false_label_name];
        
        // Test condition and branch
        assembler->testq(cond_reg, cond_reg);
        // Conditional jump to true block (if condition is non-zero)
        assembler->jump_cond(nextgen::jet::x64::NotEqual, true_label);
        // Unconditional jump to false block
        assembler->jmp(false_label);
      }
      break;
    }
    
    case IR::Opcode::CALL: {
      const auto& call_inst = static_cast<const IR::CallInst&>(inst);
      
      // Load arguments into correct registers (System V calling convention)
      nextgen::jet::x64::Register arg_regs[] = {DI, SI, DX, CX, R8, R9};
      
      for (size_t i = 0; i < call_inst.operands.size() && i < 6; ++i) {
        auto arg_reg = get_operand_register(call_inst.operands[i]);
        assembler->movq(arg_regs[i], arg_reg);
      }
      
      if (call_inst.function_name.length() > 0) {
        // Create a label for the function if it doesn't exist
        std::string func_label_name = "func_" + call_inst.function_name;
        auto& func_label = string_labels[func_label_name];
        
        // Call the function
        assembler->call(func_label);
      } else {
        // External call - use placeholder for now
        assembler->call(Imm32{0x12345678});
      }
      
      // Move return value to result register
      if (inst.result_reg) {
        auto dst_reg = get_or_alloc_register(inst.result_reg);
        assembler->movq(dst_reg, AX); // Return value in AX
      }
      break;
    }
    
    // Type conversion instructions
    case IR::Opcode::TRUNC: {
      if (inst.operands.size() != 1) break;
      
      auto src_reg = get_operand_register(inst.operands[0]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Truncation is just a move on x86_64 (upper bits ignored)
      assembler->movq(dst_reg, src_reg);
      break;
    }
    
    case IR::Opcode::ZEXT: {
      if (inst.operands.size() != 1) break;
      
      auto src_reg = get_operand_register(inst.operands[0]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Zero extension based on source type size
      switch (inst.operands[0]->type.size_bytes()) {
        case 1:
          assembler->movzxb(dst_reg, src_reg);
          break;
        case 2:
          assembler->movzxw(dst_reg, src_reg);
          break;
        case 4:
          assembler->movd(dst_reg, src_reg); // 32->64 bit zero extends automatically
          break;
        default:
          assembler->movq(dst_reg, src_reg);
          break;
      }
      break;
    }
    
    case IR::Opcode::SEXT: {
      if (inst.operands.size() != 1) break;
      
      auto src_reg = get_operand_register(inst.operands[0]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Sign extension based on source type size
      switch (inst.operands[0]->type.size_bytes()) {
        case 1:
          assembler->movsxb(dst_reg, src_reg);
          break;
        case 2:
          assembler->movsxw(dst_reg, src_reg);
          break;
        case 4:
          assembler->movsxd(dst_reg, src_reg);
          break;
        default:
          assembler->movq(dst_reg, src_reg);
          break;
      }
      break;
    }
    
    case IR::Opcode::BITCAST: {
      if (inst.operands.size() != 1) break;
      
      auto src_reg = get_operand_register(inst.operands[0]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Bitcast is just a register move - no conversion
      assembler->movq(dst_reg, src_reg);
      break;
    }
    
    // Advanced operations
    case IR::Opcode::PHI: {
      const auto& phi_inst = static_cast<const IR::PhiInst&>(inst);
      
      // PHI nodes are complex to implement properly - they require knowledge
      // of which predecessor block we came from. For now, just use first operand
      if (!inst.operands.empty()) {
        auto src_reg = get_operand_register(inst.operands[0]);
        auto dst_reg = get_or_alloc_register(inst.result_reg);
        assembler->movq(dst_reg, src_reg);
      }
      break;
    }
    
    case IR::Opcode::SELECT: {
      const auto& sel_inst = static_cast<const IR::SelectInst&>(inst);
      if (inst.operands.size() != 3) break;
      
      auto cond_reg = get_operand_register(inst.operands[0]);
      auto true_reg = get_operand_register(inst.operands[1]);
      auto false_reg = get_operand_register(inst.operands[2]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Conditional move based on condition
      assembler->testq(cond_reg, cond_reg);
      assembler->movq(dst_reg, false_reg);  // Default to false value
      assembler->cmovcc(nextgen::jet::x64::NotEqual, dst_reg, true_reg); // Move true value if condition != 0
      break;
    }
    
    case IR::Opcode::RET: {
      if (!inst.operands.empty()) {
        // Return with value - move to AX (return value register)
        auto ret_reg = get_operand_register(inst.operands[0]);
        assembler->movq(AX, ret_reg);
      }
      // Only emit epilogue if not in main function
      // (main function has no prologue/epilogue)
      assembler->movq(SP, BP);
      assembler->popq(BP);
      assembler->ret();
      break;
    }
    
    case IR::Opcode::SYSCALL: {
      const auto& syscall_inst = static_cast<const IR::SyscallInst&>(inst);
      emit_syscall(syscall_inst.syscall_number, syscall_inst.args);
      // Generic approach: preserve each syscall result in a unique callee-saved register
      if (syscall_inst.result_reg) {
        // Use R12, R13, R14, R15 for different syscall results (callee-saved on x64)
        static int syscall_reg_counter = 12;
        nextgen::jet::x64::Register preserve_reg = static_cast<nextgen::jet::x64::Register>(syscall_reg_counter);
        assembler->movq(preserve_reg, AX);  // Preserve result from AX
        reg_map[syscall_inst.result_reg->id] = preserve_reg;
        syscall_reg_counter++;
        if (syscall_reg_counter > 15) syscall_reg_counter = 12; // Wrap around
      }
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
    
    // Additional missing operations
    case IR::Opcode::UREM: {
      // Unsigned remainder: result = operand1 % operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // x86_64 division puts remainder in RDX
      assembler->movq(AX, src1_reg);  // Dividend in RAX
      assembler->xorq(DX, DX);        // Clear RDX for unsigned division
      assembler->divq(src2_reg);      // Unsigned divide
      assembler->movq(dst_reg, DX);   // Remainder is in RDX
      break;
    }
    
    case IR::Opcode::SREM: {
      // Signed remainder: result = operand1 % operand2
      if (inst.operands.size() != 2) break;
      
      auto src1_reg = get_operand_register(inst.operands[0]);
      auto src2_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // x86_64 signed division puts remainder in RDX
      assembler->movq(AX, src1_reg);  // Dividend in RAX
      assembler->cqo();               // Sign extend RAX into RDX:RAX
      assembler->idivq(src2_reg);     // Signed divide
      assembler->movq(dst_reg, DX);   // Remainder is in RDX
      break;
    }
    
    // GetElementPtr for address calculation
    case IR::Opcode::GEP: {
      const auto& gep_inst = static_cast<const IR::GEPInst&>(inst);
      if (inst.operands.size() < 2) break;
      
      auto base_reg = get_operand_register(inst.operands[0]); // Base pointer
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Start with base address
      assembler->movq(dst_reg, base_reg);
      
      // Add each index offset (simplified - assumes byte offsets)
      for (size_t i = 1; i < inst.operands.size(); ++i) {
        auto index_reg = get_operand_register(inst.operands[i]);
        assembler->addq(dst_reg, index_reg);
      }
      break;
    }
    
    // Aggregate operations (simplified)
    case IR::Opcode::EXTRACTVALUE: {
      const auto& extract_inst = static_cast<const IR::ExtractValueInst&>(inst);
      if (inst.operands.size() < 1) break;
      
      auto agg_reg = get_operand_register(inst.operands[0]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Simplified: for now just copy the aggregate value
      // Real implementation would calculate field offsets
      assembler->movq(dst_reg, agg_reg);
      break;
    }
    
    case IR::Opcode::INSERTVALUE: {
      const auto& insert_inst = static_cast<const IR::InsertValueInst&>(inst);
      if (inst.operands.size() < 2) break;
      
      auto agg_reg = get_operand_register(inst.operands[0]);
      auto val_reg = get_operand_register(inst.operands[1]);
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      // Simplified: for now just use the new value
      // Real implementation would modify specific fields
      assembler->movq(dst_reg, val_reg);
      break;
    }
    
    // Floating-point comparisons (simplified)
    case IR::Opcode::FCMP_OEQ: {
      if (inst.operands.size() != 2) break;
      
      // Use XMM registers for floating-point comparison
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.operands[0]->type.size_bytes() == 4) {
        assembler->comiss(XMM0, XMM1);
      } else {
        assembler->comisd(XMM0, XMM1);
      }
      assembler->setcc(nextgen::jet::x64::Equal, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::FCMP_ONE: {
      if (inst.operands.size() != 2) break;
      
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.operands[0]->type.size_bytes() == 4) {
        assembler->comiss(XMM0, XMM1);
      } else {
        assembler->comisd(XMM0, XMM1);
      }
      assembler->setcc(nextgen::jet::x64::NotEqual, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    case IR::Opcode::FCMP_OLT: {
      if (inst.operands.size() != 2) break;
      
      auto dst_reg = get_or_alloc_register(inst.result_reg);
      
      if (inst.operands[0]->type.size_bytes() == 4) {
        assembler->comiss(XMM0, XMM1);
      } else {
        assembler->comisd(XMM0, XMM1);
      }
      assembler->setcc(nextgen::jet::x64::Below, dst_reg);
      assembler->movzxb(dst_reg, dst_reg);
      break;
    }
    
    default:
      // Placeholder for any remaining unimplemented instructions
      assembler->nop();
      break;
  }
}

void X64Backend::emit_atomic_load(const IR::AtomicLoadInst& inst) {
  auto dst_reg = get_register_for_type(inst.result_type);
  
  // Emit memory barrier before load if needed
  if (inst.memory_ordering == IR::MemoryOrdering::ACQUIRE || 
      inst.memory_ordering == IR::MemoryOrdering::SEQ_CST) {
    emit_memory_barrier(inst.memory_ordering);
  }
  
  // Load based on type size
  switch (inst.result_type.size_bytes()) {
    case 1:
      assembler->movb(dst_reg, MemoryAddress{SP, (ubyte)0}); // Placeholder address
      break;
    case 2:
      assembler->movw(dst_reg, MemoryAddress{SP, (ubyte)0});
      break;
    case 4:
      assembler->movd(dst_reg, MemoryAddress{SP, (ubyte)0});
      break;
    case 8:
      assembler->movq(dst_reg, MemoryAddress{SP, (ubyte)0});
      break;
  }
  
  // Emit memory barrier after load if needed
  if (inst.memory_ordering == IR::MemoryOrdering::SEQ_CST) {
    emit_memory_barrier(inst.memory_ordering);
  }
}

void X64Backend::emit_atomic_store(const IR::AtomicStoreInst& inst) {
  auto src_reg = get_register_for_type(inst.operands[0]->type);
  
  // Emit memory barrier before store if needed
  if (inst.memory_ordering == IR::MemoryOrdering::RELEASE ||
      inst.memory_ordering == IR::MemoryOrdering::SEQ_CST) {
    emit_memory_barrier(inst.memory_ordering);
  }
  
  // Store based on type size - TODO: Implement proper memory stores
  // For now, just use register operations as placeholder
  switch (inst.operands[0]->type.size_bytes()) {
    case 1:
    case 2:
    case 4:
      assembler->movd(src_reg, src_reg); // Placeholder - need proper store
      break;
    case 8:
      assembler->movq(src_reg, src_reg); // Placeholder - need proper store
      break;
  }
  
  // Emit memory barrier after store if needed
  if (inst.memory_ordering == IR::MemoryOrdering::SEQ_CST) {
    emit_memory_barrier(inst.memory_ordering);
  }
}

void X64Backend::emit_atomic_cas(const IR::AtomicCASInst& inst) {
  // x86-64 CAS: compare AX with memory, if equal store CX to memory
  auto expected_reg = AX;  // x86 CAS uses AX for comparison
  auto desired_reg = CX;   // Use CX for desired value
  
  // Load expected value into AX
  assembler->movq(expected_reg, Imm64{0}); // Placeholder
  
  // Load desired value into CX  
  assembler->movq(desired_reg, Imm64{1}); // Placeholder
  
  // Emit memory barrier if needed
  emit_memory_barrier(inst.success_ordering);
  
  // Perform compare and exchange - TODO: Implement proper memory addressing
  switch (inst.operands[1]->type.size_bytes()) {
    case 1:
      assembler->cmpxchgb(desired_reg, MemoryAddress{SP, (ubyte)0});
      break;
    case 2:
      assembler->cmpxchgw(desired_reg, MemoryAddress{SP, (ubyte)0});
      break;
    case 4:
      assembler->cmpxchgd(desired_reg, MemoryAddress{SP, (ubyte)0});
      break;
    case 8:
      assembler->cmpxchgq(desired_reg, MemoryAddress{SP, (ubyte)0});
      break;
  }
  
  // Set flags based on success (ZF set if successful)
  assembler->setcc(nextgen::jet::x64::Equal, DX); // Store success flag in DX
}

void X64Backend::emit_atomic_rmw(const IR::AtomicRMWInst& inst) {
  MemoryAddress addr{SP, (ubyte)0}; // Placeholder address
  
  emit_memory_barrier(inst.memory_ordering);
  
  switch (inst.rmw_operation) {
    case IR::AtomicRMWOp::ADD:
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->lock_addb(Imm8{1}, addr); break;
        case 2: assembler->lock_addw(Imm16{1}, addr); break;
        case 4: assembler->lock_addd(Imm32{1}, addr); break;
        case 8: assembler->lock_addq(Imm32{1}, addr); break;
      }
      break;
      
    case IR::AtomicRMWOp::SUB:
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->lock_subb(Imm8{1}, addr); break;
        case 2: assembler->lock_subw(Imm16{1}, addr); break;
        case 4: assembler->lock_subd(Imm32{1}, addr); break;
        case 8: assembler->lock_subq(Imm32{1}, addr); break;
      }
      break;
      
    case IR::AtomicRMWOp::AND:
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->lock_andb(Imm8{0xFF}, addr); break;
        case 2: assembler->lock_andw(Imm16{0xFFFF}, addr); break;
        case 4: assembler->lock_andd(Imm32{0xFFFFFFFF}, addr); break;
        case 8: assembler->lock_andq(Imm32{0xFFFFFFFF}, addr); break;
      }
      break;
      
    case IR::AtomicRMWOp::OR:
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->lock_orb(Imm8{0}, addr); break;
        case 2: assembler->lock_orw(Imm16{0}, addr); break;
        case 4: assembler->lock_ord(Imm32{0}, addr); break;
        case 8: assembler->lock_orq(Imm32{0}, addr); break;
      }
      break;
      
    case IR::AtomicRMWOp::XOR:
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->lock_xorb(Imm8{0}, addr); break;
        case 2: assembler->lock_xorw(Imm16{0}, addr); break;
        case 4: assembler->lock_xord(Imm32{0}, addr); break;
        case 8: assembler->lock_xorq(Imm32{0}, addr); break;
      }
      break;
      
    case IR::AtomicRMWOp::XCHG:
      // Use XCHG instruction (implicitly atomic)
      switch (inst.operands[1]->type.size_bytes()) {
        case 1: assembler->xchgb(AX, addr); break;
        case 2: assembler->xchgw(AX, addr); break;
        case 4: assembler->xchgd(AX, addr); break;
        case 8: assembler->xchgq(AX, addr); break;
      }
      break;
      
    default:
      throw std::runtime_error("Unsupported atomic RMW operation");
  }
}

void X64Backend::emit_atomic_fence(const IR::AtomicFenceInst& inst) {
  emit_memory_barrier(inst.memory_ordering);
}

void X64Backend::emit_memory_barrier(IR::MemoryOrdering ordering) {
  switch (ordering) {
    case IR::MemoryOrdering::ACQUIRE:
      // x86-64 loads are not reordered with other loads/stores
      // But we can add a load fence for clarity
      assembler->lfence();
      break;
      
    case IR::MemoryOrdering::RELEASE:
      // x86-64 stores are not reordered with other loads/stores
      // But we can add a store fence for clarity
      assembler->sfence();
      break;
      
    case IR::MemoryOrdering::ACQ_REL:
    case IR::MemoryOrdering::SEQ_CST:
      // Full memory barrier
      assembler->mfence();
      break;
      
    case IR::MemoryOrdering::RELAXED:
      // No barrier needed
      break;
      
    default:
      break;
  }
}

// ==================== Register Allocation Integration ====================

nextgen::jet::x64::Register X64Backend::get_allocated_register(uint32_t value_id) {
  if (use_advanced_allocation && current_allocation.success) {
    auto it = current_allocation.value_to_register.find(value_id);
    if (it != current_allocation.value_to_register.end()) {
      return convert_to_native_register(it->second);
    }
    
    // Check if value is spilled
    if (current_allocation.spill_offsets.find(value_id) != current_allocation.spill_offsets.end()) {
      // For spilled values, return a temporary register and emit reload code
      return R11; // Use R11 as temporary for spilled values
    }
  }
  
  // Fallback: not found in allocation, use naive method
  return AX;
}

nextgen::jet::x64::Register X64Backend::convert_to_native_register(const Register& generic_reg) {
  // Convert generic register to x64-specific register
  // This mapping should match the X64RegisterSet implementation
  switch (generic_reg.id()) {
    case 0: return AX;
    case 1: return BX; 
    case 2: return CX;
    case 3: return DX;
    case 4: return SI;
    case 5: return DI;
    case 6: return R8;
    case 7: return R9;
    case 8: return R10;
    case 9: return R11;
    case 10: return R12;
    case 11: return R13;
    case 12: return R14;
    case 13: return R15;
    // Floating point registers
    case 16: return XMM0;
    case 17: return XMM1;
    case 18: return XMM2;
    case 19: return XMM3;
    case 20: return XMM4;
    case 21: return XMM5;
    case 22: return XMM6;
    case 23: return XMM7;
    default: 
      std::cerr << "Warning: Unknown register ID " << generic_reg.id() << ", using AX" << std::endl;
      return AX;
  }
}

void X64Backend::emit_spill_code(uint32_t value_id, const IR::Instruction& inst) {
  if (current_allocation.spill_offsets.find(value_id) != current_allocation.spill_offsets.end()) {
    int32_t offset = current_allocation.spill_offsets.at(value_id);
    
    // Emit store to stack at offset
    // For now, use a placeholder since the assembler API is limited
    // In a complete implementation, we'd need register-to-memory store instructions
    assembler->nop(); // Placeholder for spill store
  }
}

void X64Backend::emit_reload_code(uint32_t value_id, const IR::Instruction& inst) {
  if (current_allocation.spill_offsets.find(value_id) != current_allocation.spill_offsets.end()) {
    int32_t offset = current_allocation.spill_offsets.at(value_id);
    
    // Emit load from stack at offset  
    // movq reg, [rbp + offset] - this should work
    assembler->movq(R11, MemoryAddress{BP, static_cast<uint32_t>(abs(offset))});
  }
}

// ==================== Legacy Register Allocation ====================

nextgen::jet::x64::Register X64Backend::get_or_alloc_register(const IR::Value& val) {
  // Try advanced allocation first
  if (use_advanced_allocation && current_allocation.success) {
    nextgen::jet::x64::Register allocated_reg = get_allocated_register(val.id);
    if (allocated_reg != AX || current_allocation.value_to_register.find(val.id) != current_allocation.value_to_register.end()) {
      return allocated_reg;
    }
  }
  
  // Fallback to naive allocation
  auto it = reg_map.find(val.id);
  if (it != reg_map.end()) {
    return it->second;
  }
  
  // Simple register allocation
  nextgen::jet::x64::Register reg = next_reg;
  reg_map[val.id] = reg;
  
  // Advance to next register (very simple allocation)
  if (next_reg == AX) next_reg = BX;
  else if (next_reg == BX) next_reg = CX;
  else if (next_reg == CX) next_reg = DX;
  else next_reg = AX; // Wrap around
  
  return reg;
}

nextgen::jet::x64::Register X64Backend::get_register_for_type(const IR::Type& type) {
  // Simple type-based register selection
  if (type.is_integer() || type.is_pointer()) {
    return AX; // Use AX for integers and pointers
  } else if (type.is_float()) {
    return XMM0; // Use XMM0 for floats
  }
  return AX; // Default
}

const uint8_t* X64Backend::get_code() const {
  return assembler->spill();
}

size_t X64Backend::get_code_size() const {
  return assembler->bytes();
}

bool X64Backend::write_object(const std::string& path, const std::string& entry_symbol) {
  // Place string labels at the end of the code (inline data pool)
  for (auto& [str_content, label] : string_labels) {
    assembler->place_label(label);
    for (char c : str_content) {
      assembler->emit_u8(static_cast<uint8_t>(c));
    }
    assembler->emit_u8(0); // null terminator
  }

  // Choose object file format based on target platform
  switch (target_platform) {
    case TargetPlatform::MACOS:
      return macho_builder.write_object(
        path.c_str(),
        reinterpret_cast<const uint8_t*>(assembler->spill()),
        static_cast<uint32_t>(assembler->bytes()),
        entry_symbol.c_str(),
        0,
        MachOArch::X86_64
      );
      
    case TargetPlatform::LINUX:
      return elf_builder.write_object(
        path.c_str(),
        reinterpret_cast<const uint8_t*>(assembler->spill()),
        static_cast<uint32_t>(assembler->bytes()),
        entry_symbol.c_str(),
        0,
        ELFArch::X86_64
      );
      
    case TargetPlatform::WINDOWS:
      // TODO: Implement PE support
      std::cerr << "Windows PE support not yet implemented" << std::endl;
      return false;
      
    default:
      std::cerr << "Unsupported target platform" << std::endl;
      return false;
  }
}

bool X64Backend::write_executable(const std::string& path, const std::string& entry_symbol) {
  // Place string labels at the end of the code (inline data pool)
  for (auto& [str_content, label] : string_labels) {
    assembler->place_label(label);
    for (char c : str_content) {
      assembler->emit_u8(static_cast<uint8_t>(c));
    }
    assembler->emit_u8(0); // null terminator
  }

  // Choose executable format based on target platform
  switch (target_platform) {
    case TargetPlatform::MACOS:
      // Use Mach-O builder for macOS
      return macho_builder.write_executable(
        path.c_str(),
        reinterpret_cast<const uint8_t*>(assembler->spill()),
        static_cast<uint32_t>(assembler->bytes()),
        0,
        MachOArch::X86_64
      );
      
    case TargetPlatform::LINUX:
      // Use ELF builder for Linux
      return elf_builder.write_executable(
        path.c_str(),
        reinterpret_cast<const uint8_t*>(assembler->spill()),
        static_cast<uint32_t>(assembler->bytes()),
        0,
        ELFArch::X86_64
      );
      
    case TargetPlatform::WINDOWS:
      // TODO: Implement PE support
      std::cerr << "Windows PE support not yet implemented" << std::endl;
      return false;
      
    default:
      std::cerr << "Unsupported target platform" << std::endl;
      return false;
  }
}

bool X64Backend::link_executable(const std::string& obj_path, const std::string& exe_path) {
  std::string cmd;
  int rc;
  
  switch (target_platform) {
    case TargetPlatform::MACOS:
      // Link using system clang to produce a proper Mach-O executable with LC_MAIN
      // Use _start as entry and disable PIE for simple syscall-only binaries
      cmd = std::string("clang -arch x86_64 -e _start -Wl,-no_pie -o ") + exe_path + " " + obj_path + " 2>/dev/null";
      rc = std::system(cmd.c_str());
      if (rc != 0) {
        // Retry without -Wl,-no_pie (in case toolchain rejects it)
        std::string cmd2 = std::string("clang -arch x86_64 -e _start -o ") + exe_path + " " + obj_path + " 2>/dev/null";
        rc = std::system(cmd2.c_str());
      }
      return rc == 0;
      
    case TargetPlatform::LINUX:
      // Link using ld directly for ELF executables
      // Use _start as entry point (standard for Linux executables without C runtime)
      cmd = std::string("ld -m elf_x86_64 -e _start -o ") + exe_path + " " + obj_path + " 2>/dev/null";
      rc = std::system(cmd.c_str());
      if (rc != 0) {
        // Try alternative ld command format
        cmd = std::string("ld -m i386:x86-64 -e _start -o ") + exe_path + " " + obj_path + " 2>/dev/null";
        rc = std::system(cmd.c_str());
      }
      if (rc != 0) {
        // Try with gcc as fallback
        cmd = std::string("gcc -nostdlib -nostartfiles -e _start -o ") + exe_path + " " + obj_path + " 2>/dev/null";
        rc = std::system(cmd.c_str());
      }
      if (rc != 0) {
        // Try with clang as final fallback
        cmd = std::string("clang -nostdlib -nostartfiles -e _start -o ") + exe_path + " " + obj_path + " 2>/dev/null";
        rc = std::system(cmd.c_str());
      }
      return rc == 0;
      
    case TargetPlatform::WINDOWS:
      // TODO: Implement Windows linking
      std::cerr << "Windows linking not yet implemented" << std::endl;
      return false;
      
    default:
      std::cerr << "Unsupported target platform for linking" << std::endl;
      return false;
  }
}

void X64Backend::emit_syscall_exit(int32_t code) {
  uint64_t syscall_number;
  switch (target_platform) {
    case TargetPlatform::MACOS:
      syscall_number = 0x2000001ULL; // Darwin SYS_exit
      break;
    case TargetPlatform::LINUX:
      syscall_number = 60ULL; // Linux SYS_exit
      break;
    default:
      syscall_number = 0x2000001ULL; // Default to Darwin
      break;
  }
  
  assembler->movq(AX, Imm64{syscall_number});
  assembler->movq(DI, Imm64{static_cast<uint64_t>(code)});
  assembler->syscall();
}

void X64Backend::emit_syscall_write(const std::string& message) {
  uint64_t syscall_number;
  switch (target_platform) {
    case TargetPlatform::MACOS:
      syscall_number = 0x2000004ULL; // Darwin SYS_write
      break;
    case TargetPlatform::LINUX:
      syscall_number = 1ULL; // Linux SYS_write
      break;
    default:
      syscall_number = 0x2000004ULL; // Default to Darwin
      break;
  }
  
  // Implementation would emit string data and syscall
  assembler->movq(AX, Imm64{syscall_number});
  assembler->movq(DI, Imm64{1}); // stdout
  assembler->syscall();
}

void X64Backend::add_string_to_data_section(const std::string& str) {
  // Add string to data section and record offset
  uint32_t offset = data_section.size();
  string_offsets[str] = offset;
  
  // Add string bytes to data section
  data_section.insert(data_section.end(), str.begin(), str.end());
  data_section.push_back(0); // null terminator
  
  // Create symbol for this string
  std::string symbol_name = "L_.str" + std::to_string(data_symbols.size());
  data_symbols.emplace_back(symbol_name, offset);
}

void X64Backend::emit_string_to_stack(const std::string& str) {
  // Calculate required stack space (aligned to 8 bytes)
  uint32_t stack_size = (str.length() + 7) & ~7; // Round up to 8-byte boundary
  assembler->subq(SP, Imm8{static_cast<uint8_t>(stack_size)});
  
  // Store the string byte by byte on the stack
  for (size_t i = 0; i < str.length(); ++i) {
    assembler->movb(MemoryAddress{SP, static_cast<ubyte>(i)}, Imm8{static_cast<uint8_t>(str[i])});
  }
  
  // Load the stack address into SI (second argument register)
  assembler->lea(SI, MemoryAddress{SP, (ubyte)0}, QWORD);
}

void X64Backend::add_string_to_embedded_section(const std::string& str) {
  // Add string to embedded section (like hello2's __TEXT,__cstring)
  embedded_strings.insert(embedded_strings.end(), str.begin(), str.end());
  embedded_strings.push_back(0); // null terminator
}

void X64Backend::emit_syscall(uint32_t syscall_number, const std::vector<std::shared_ptr<IR::Value>>& args) {
  // Generic syscall emission (Darwin)
  // Argument registers order for x86_64 syscalls
  nextgen::jet::x64::Register arg_regs[6] = { DI, SI, DX, R10, R8, R9 };

  // Load arguments
  for (size_t i = 0; i < args.size() && i < 6; ++i) {
    auto &a = args[i];
    if (auto ci = std::dynamic_pointer_cast<IR::ConstantInt>(a)) {
      assembler->movq(arg_regs[i], Imm64{(uint64_t)ci->value});
    } else if (auto gs = std::dynamic_pointer_cast<IR::GlobalString>(a)) {
      // Ensure label exists and embed once
      auto it = string_labels.find(gs->string_value);
      if (it == string_labels.end()) {
        nextgen::jet::x64::Label lbl{};
        string_labels[gs->string_value] = lbl;
        add_string_to_embedded_section(gs->string_value);
      }
      assembler->leaq_rip_label(arg_regs[i], string_labels[gs->string_value]);
    } else if (auto rv = std::dynamic_pointer_cast<IR::Register>(a)) {
      // Look up the register in our mapping (same as ARM64 approach)
      auto it = reg_map.find(rv->id);
      if (it != reg_map.end()) {
        assembler->movq(arg_regs[i], it->second);
      } else {
        // If not found in mapping, assume it's a syscall result in AX
        assembler->movq(arg_regs[i], AX);
      }
    }
  }

  // Now set syscall number (after using AX for any arg materialization)
  uint64_t platform_syscall_number;
  switch (target_platform) {
    case TargetPlatform::MACOS:
      platform_syscall_number = 0x2000000ULL | (uint64_t)syscall_number; // Darwin syscall offset
      break;
    case TargetPlatform::LINUX:
      platform_syscall_number = (uint64_t)syscall_number; // Linux syscalls are direct
      break;
    default:
      platform_syscall_number = 0x2000000ULL | (uint64_t)syscall_number; // Default to Darwin
      break;
  }
  
  assembler->movq(AX, Imm64{platform_syscall_number});
  assembler->syscall();
}

nextgen::jet::x64::Register X64Backend::get_or_alloc_register(const std::shared_ptr<IR::Register>& reg) {
  if (!reg) return AX; // Fallback
  
  // Try advanced allocation first
  if (use_advanced_allocation && current_allocation.success) {
    nextgen::jet::x64::Register allocated_reg = get_allocated_register(reg->id);
    if (allocated_reg != AX || current_allocation.value_to_register.find(reg->id) != current_allocation.value_to_register.end()) {
      return allocated_reg;
    }
  }
  
  // Fallback to naive allocation
  auto it = reg_map.find(reg->id);
  if (it != reg_map.end()) {
    return it->second;
  }
  
  // Allocate a new register (use simple round-robin allocation)
  static nextgen::jet::x64::Register next_alloc_reg = CX;
  nextgen::jet::x64::Register allocated = next_alloc_reg;
  
  reg_map[reg->id] = allocated;
  
  // Advance to next register (avoiding AX, SP, BP which have special purposes)
  switch (next_alloc_reg) {
    case CX: next_alloc_reg = DX; break;
    case DX: next_alloc_reg = SI; break; 
    case SI: next_alloc_reg = DI; break;
    case DI: next_alloc_reg = R8; break;
    case R8: next_alloc_reg = R9; break;
    case R9: next_alloc_reg = R10; break;
    case R10: next_alloc_reg = R11; break;
    case R11: next_alloc_reg = CX; break; // Wrap around
    default: next_alloc_reg = CX; break;
  }
  
  return allocated;
}

nextgen::jet::x64::Register X64Backend::get_operand_register(const std::shared_ptr<IR::Value>& operand) {
  if (auto const_int = std::dynamic_pointer_cast<IR::ConstantInt>(operand)) {
    // Load constant into a temporary register (use R11 as temp)
    assembler->movq(R11, Imm64{(uint64_t)const_int->value});
    return R11;
  } else if (auto reg = std::dynamic_pointer_cast<IR::Register>(operand)) {
    return get_or_alloc_register(reg);
  } else {
    // Fallback for other value types
    return AX;
  }
}

} // namespace CodeGen
