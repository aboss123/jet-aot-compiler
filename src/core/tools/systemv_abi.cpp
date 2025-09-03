#include "systemv_abi.h"
#include <algorithm>

using namespace nextgen::jet::x64;
using namespace SystemV;

static uint32_t round_up_to(uint32_t value, uint32_t align) {
  return (value + align - 1) & ~(align - 1);
}

Type Type::struct_type(std::vector<Type> fields) {
  Type t{STRUCT, 0, 1, std::move(fields)};
  for (const auto& f : t.fields) {
    t.size = round_up_to(t.size, f.align) + f.size;
    t.align = std::max(t.align, f.align);
  }
  t.size = round_up_to(t.size, t.align);
  return t;
}

ArgClass ABIHandler::classify_type(const Type& type) {
  switch (type.kind) {
    case Type::VOID: return ArgClass::NO_CLASS;
    case Type::I8: case Type::I16: case Type::I32: case Type::I64: case Type::PTR:
      return ArgClass::INTEGER;
    case Type::F32: case Type::F64:
      return ArgClass::SSE;
    case Type::STRUCT:
      if (type.size > 16) return ArgClass::MEMORY;
      // Simplified: small structs go to INTEGER for now
      return ArgClass::INTEGER;
    default:
      return ArgClass::MEMORY;
  }
}

uint32_t ABIHandler::round_up(uint32_t value, uint32_t align) {
  return round_up_to(value, align);
}

CallConvention ABIHandler::analyze_call(const Type& ret_type, const std::vector<Type>& arg_types) {
  CallConvention cc{};
  
  // System V register order: RDI, RSI, RDX, RCX, R8, R9 for integers
  // XMM0-XMM7 for SSE
  Register int_regs[] = {DI, SI, DX, CX, R8, R9};
  Register sse_regs[] = {XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7};
  
  int int_used = 0, sse_used = 0;
  int32_t stack_offset = 0;
  
  // Handle sret (large struct return)
  cc.has_sret = (ret_type.kind == Type::STRUCT && ret_type.size > 16);
  if (cc.has_sret) {
    int_used++; // RDI used for sret pointer
  }
  
  // Classify arguments
  for (const auto& arg : arg_types) {
    ArgLocation loc{};
    ArgClass cls = classify_type(arg);
    loc.cls = cls;
    
    switch (cls) {
      case ArgClass::INTEGER:
        if (int_used < 6) {
          loc.reg = int_regs[int_used++];
        } else {
          loc.cls = ArgClass::MEMORY;
          loc.stack_offset = stack_offset;
          stack_offset += round_up(arg.size, 8);
        }
        break;
      case ArgClass::SSE:
        if (sse_used < 8) {
          loc.reg = sse_regs[sse_used++];
        } else {
          loc.cls = ArgClass::MEMORY;
          loc.stack_offset = stack_offset;
          stack_offset += round_up(arg.size, 8);
        }
        break;
      case ArgClass::MEMORY:
        loc.stack_offset = stack_offset;
        stack_offset += round_up(arg.size, 8);
        break;
      default:
        break;
    }
    cc.args.push_back(loc);
  }
  
  // Classify return type
  cc.return_loc.cls = cc.has_sret ? ArgClass::MEMORY : classify_type(ret_type);
  if (cc.return_loc.cls == ArgClass::INTEGER) {
    cc.return_loc.reg = AX;
  } else if (cc.return_loc.cls == ArgClass::SSE) {
    cc.return_loc.reg = XMM0;
  }
  
  // Align stack to 16 bytes
  cc.stack_size = round_up(stack_offset, 16);
  
  return cc;
}

void ABIHandler::emit_prologue(Assembler& a, const CallConvention& cc, uint32_t local_stack) {
  a.pushq(BP);
  a.movq(BP, SP);
  
  uint32_t total_stack = round_up(local_stack + (uint32_t)cc.stack_size, 16);
  if (total_stack > 0) {
    a.subq(SP, Imm32{total_stack});
  }
  
  // Save callee-saved registers if needed
  a.save_callee_saved_registers();
}

void ABIHandler::emit_epilogue(Assembler& a, const CallConvention& cc) {
  a.restore_callee_saved_registers();
  a.movq(SP, BP);
  a.popq(BP);
  a.ret();
}

void ABIHandler::emit_call(Assembler& a, const CallConvention& cc, 
                          const std::string& target_name, bool is_external) {
  // Align stack for call (System V requires 16-byte alignment before call)
  if (cc.stack_size > 0) {
    a.subq(SP, Imm32{(uint32_t)cc.stack_size});
  }
  
  // TODO: Setup arguments (would need values to move)
  // For now, assume arguments are already in the right places
  
  if (is_external) {
    // External call - would need symbol resolution in real implementation
    // For now, just emit a placeholder
    a.call_external(target_name.c_str());
  } else {
    // Internal call - would use labels
    // a.call(label);
  }
  
  // Cleanup stack
  if (cc.stack_size > 0) {
    a.addq(SP, Imm32{(uint32_t)cc.stack_size});
  }
}

void ABIHandler::load_argument(Assembler& a, const ArgLocation& loc, Register dest_reg) {
  switch (loc.cls) {
    case ArgClass::INTEGER:
      if (loc.reg != dest_reg) {
        a.movq(dest_reg, loc.reg);
      }
      break;
    case ArgClass::MEMORY:
      a.movq(dest_reg, MemoryAddress(BP, (uint)(loc.stack_offset + 16))); // +16 for saved rbp + return addr
      break;
    case ArgClass::SSE:
      // Would need XMM move instructions
      break;
    default:
      break;
  }
}

void ABIHandler::store_return(Assembler& a, const ArgLocation& loc, Register src_reg) {
  switch (loc.cls) {
    case ArgClass::INTEGER:
      if (src_reg != AX) {
        a.movq(AX, src_reg);
      }
      break;
    case ArgClass::SSE:
      // Would need XMM move instructions
      break;
    default:
      break;
  }
}
