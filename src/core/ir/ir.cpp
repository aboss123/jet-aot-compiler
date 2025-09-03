#include "ir.h"
#include <stdexcept>
#include <cmath>

namespace IR {

uint32_t Value::next_id = 1;
uint32_t BasicBlock::next_id = 1;

// SafetyChecker implementation
bool SafetyChecker::is_atomic_compatible_type(const Type& type) {
  // Atomic operations are only valid for integer types and pointers
  // Sizes must be power of 2 and <= 64 bits for most architectures
  // NOTE: Floating-point types are NOT directly supported by hardware atomic operations
  // on x86-64 and ARM64. They require compare-and-swap on bit representation.
  switch (type.kind) {
    case TypeKind::I1:
    case TypeKind::I8:
    case TypeKind::I16:
    case TypeKind::I32:
    case TypeKind::I64:
    case TypeKind::PTR:
      return is_power_of_two(type.size_bytes());
    case TypeKind::F32:
    case TypeKind::F64:
      // Hardware does NOT support atomic float operations directly
      // std::atomic<float> is implemented via CAS on bit representation
      return false;
    default:
      return false;
  }
}

bool SafetyChecker::is_valid_pointer_type(const Type& type) {
  return type.kind == TypeKind::PTR && type.element_type != nullptr;
}

bool SafetyChecker::is_valid_memory_ordering_for_load(MemoryOrdering ordering) {
  // Loads cannot use RELEASE or ACQ_REL
  switch (ordering) {
    case MemoryOrdering::RELAXED:
    case MemoryOrdering::CONSUME:
    case MemoryOrdering::ACQUIRE:
    case MemoryOrdering::SEQ_CST:
      return true;
    case MemoryOrdering::RELEASE:
    case MemoryOrdering::ACQ_REL:
      return false;
  }
  return false;
}

bool SafetyChecker::is_valid_memory_ordering_for_store(MemoryOrdering ordering) {
  // Stores cannot use CONSUME or ACQUIRE
  switch (ordering) {
    case MemoryOrdering::RELAXED:
    case MemoryOrdering::RELEASE:
    case MemoryOrdering::SEQ_CST:
      return true;
    case MemoryOrdering::CONSUME:
    case MemoryOrdering::ACQUIRE:
    case MemoryOrdering::ACQ_REL:
      return false;
  }
  return false;
}

bool SafetyChecker::is_valid_memory_ordering_for_rmw(MemoryOrdering ordering) {
  // RMW operations can use any ordering except CONSUME
  switch (ordering) {
    case MemoryOrdering::RELAXED:
    case MemoryOrdering::ACQUIRE:
    case MemoryOrdering::RELEASE:
    case MemoryOrdering::ACQ_REL:
    case MemoryOrdering::SEQ_CST:
      return true;
    case MemoryOrdering::CONSUME:
      return false;
  }
  return false;
}

bool SafetyChecker::is_valid_memory_ordering_for_cas(MemoryOrdering success, MemoryOrdering failure) {
  // Both orderings must be valid for RMW
  if (!is_valid_memory_ordering_for_rmw(success) || !is_valid_memory_ordering_for_rmw(failure)) {
    return false;
  }
  
  // Failure ordering cannot be stronger than success ordering
  // and cannot include release semantics
  switch (failure) {
    case MemoryOrdering::RELEASE:
    case MemoryOrdering::ACQ_REL:
      return false;
    default:
      break;
  }
  
  // Check relative strength: RELAXED < ACQUIRE/CONSUME < RELEASE < ACQ_REL < SEQ_CST
  auto get_strength = [](MemoryOrdering ord) -> int {
    switch (ord) {
      case MemoryOrdering::RELAXED: return 0;
      case MemoryOrdering::CONSUME:
      case MemoryOrdering::ACQUIRE: return 1;
      case MemoryOrdering::RELEASE: return 2;
      case MemoryOrdering::ACQ_REL: return 3;
      case MemoryOrdering::SEQ_CST: return 4;
    }
    return -1;
  };
  
  return get_strength(failure) <= get_strength(success);
}

bool SafetyChecker::is_valid_alignment(uint32_t alignment) {
  return alignment > 0 && is_power_of_two(alignment);
}

bool SafetyChecker::is_power_of_two(uint32_t value) {
  return value > 0 && (value & (value - 1)) == 0;
}

bool SafetyChecker::validate_instruction(const Instruction& inst) {
  // Basic validation - can be extended with more checks
  switch (inst.opcode) {
    case Opcode::ATOMIC_LOAD: {
      if (inst.operands.size() != 1) return false;
      auto ptr_type = inst.operands[0]->type;
      return is_valid_pointer_type(ptr_type);
    }
    case Opcode::ATOMIC_STORE: {
      if (inst.operands.size() != 2) return false;
      auto value_type = inst.operands[0]->type;
      auto ptr_type = inst.operands[1]->type;
      return is_atomic_compatible_type(value_type) && is_valid_pointer_type(ptr_type);
    }
    case Opcode::ATOMIC_CAS: {
      if (inst.operands.size() != 3) return false;
      auto ptr_type = inst.operands[0]->type;
      auto expected_type = inst.operands[1]->type;
      auto desired_type = inst.operands[2]->type;
      return is_valid_pointer_type(ptr_type) &&
             is_atomic_compatible_type(expected_type) &&
             expected_type.kind == desired_type.kind;
    }
    case Opcode::ATOMIC_RMW: {
      if (inst.operands.size() != 2) return false;
      auto ptr_type = inst.operands[0]->type;
      auto operand_type = inst.operands[1]->type;
      return is_valid_pointer_type(ptr_type) && is_atomic_compatible_type(operand_type);
    }
    default:
      return true; // Other instructions assumed valid for now
  }
}

bool SafetyChecker::validate_function(const Function& func) {
  for (const auto& bb : func.basic_blocks) {
    for (const auto& inst : bb->instructions) {
      if (!validate_instruction(*inst)) {
        return false;
      }
    }
    
    // Check that basic block ends with terminator
    if (!bb->get_terminator()) {
      return false;
    }
  }
  return true;
}

bool SafetyChecker::validate_module(const Module& module) {
  for (const auto& func : module.functions) {
    if (!validate_function(*func)) {
      return false;
    }
  }
  return true;
}

// Extended validation with detailed error reporting
std::vector<std::string> SafetyChecker::validate_instruction_detailed(const Instruction& inst) {
  std::vector<std::string> errors;
  
  switch (inst.opcode) {
    case Opcode::ATOMIC_LOAD: {
      if (inst.operands.size() != 1) {
        errors.push_back("ATOMIC_LOAD requires exactly 1 operand, got " + std::to_string(inst.operands.size()));
      }
      if (!inst.operands.empty()) {
        auto ptr_type = inst.operands[0]->type;
        if (!is_valid_pointer_type(ptr_type)) {
          errors.push_back("ATOMIC_LOAD operand must be a valid pointer type");
        }
        if (ptr_type.element_type && !is_atomic_compatible_type(*ptr_type.element_type)) {
          errors.push_back("ATOMIC_LOAD pointer target type is not atomic-compatible");
        }
      }
      break;
    }
    case Opcode::ATOMIC_STORE: {
      if (inst.operands.size() != 2) {
        errors.push_back("ATOMIC_STORE requires exactly 2 operands, got " + std::to_string(inst.operands.size()));
      }
      if (inst.operands.size() >= 2) {
        auto value_type = inst.operands[0]->type;
        auto ptr_type = inst.operands[1]->type;
        if (!is_atomic_compatible_type(value_type)) {
          errors.push_back("ATOMIC_STORE value type is not atomic-compatible");
        }
        if (!is_valid_pointer_type(ptr_type)) {
          errors.push_back("ATOMIC_STORE pointer operand must be a valid pointer type");
        }
      }
      break;
    }
    case Opcode::ADD:
    case Opcode::SUB:
    case Opcode::MUL: {
      if (inst.operands.size() != 2) {
        errors.push_back("Binary arithmetic requires exactly 2 operands, got " + std::to_string(inst.operands.size()));
      }
      if (inst.operands.size() >= 2) {
        auto type1 = inst.operands[0]->type;
        auto type2 = inst.operands[1]->type;
        if (type1.kind != type2.kind) {
          errors.push_back("Binary arithmetic operands must have same type");
        }
        if (!type1.is_integer() && !type1.is_float()) {
          errors.push_back("Binary arithmetic operands must be integer or float types");
        }
      }
      break;
    }
    case Opcode::LOAD: {
      if (inst.operands.size() != 1) {
        errors.push_back("LOAD requires exactly 1 operand, got " + std::to_string(inst.operands.size()));
      }
      if (!inst.operands.empty() && !is_valid_pointer_type(inst.operands[0]->type)) {
        errors.push_back("LOAD operand must be a valid pointer type");
      }
      break;
    }
    case Opcode::STORE: {
      if (inst.operands.size() != 2) {
        errors.push_back("STORE requires exactly 2 operands, got " + std::to_string(inst.operands.size()));
      }
      if (inst.operands.size() >= 2 && !is_valid_pointer_type(inst.operands[1]->type)) {
        errors.push_back("STORE second operand must be a valid pointer type");
      }
      break;
    }
    default:
      // Basic validation passed for other instruction types
      break;
  }
  
  return errors;
}

std::vector<std::string> SafetyChecker::validate_function_detailed(const Function& func) {
  std::vector<std::string> errors;
  
  if (func.basic_blocks.empty()) {
    errors.push_back("Function '" + func.name + "' has no basic blocks");
    return errors;
  }
  
  // Check each basic block
  for (size_t i = 0; i < func.basic_blocks.size(); ++i) {
    const auto& bb = func.basic_blocks[i];
    std::string bb_name = bb->name.empty() ? ("bb" + std::to_string(i)) : bb->name;
    
    if (bb->instructions.empty()) {
      errors.push_back("Basic block '" + bb_name + "' is empty");
      continue;
    }
    
    // Check terminator
    if (!bb->get_terminator()) {
      errors.push_back("Basic block '" + bb_name + "' lacks terminator instruction");
    }
    
    // Validate each instruction
    for (size_t j = 0; j < bb->instructions.size(); ++j) {
      const auto& inst = bb->instructions[j];
      auto inst_errors = validate_instruction_detailed(*inst);
      for (const auto& error : inst_errors) {
        errors.push_back("In " + bb_name + " instruction " + std::to_string(j) + ": " + error);
      }
    }
  }
  
  return errors;
}

std::vector<std::string> SafetyChecker::validate_module_detailed(const Module& module) {
  std::vector<std::string> errors;
  
  if (module.functions.empty()) {
    errors.push_back("Module '" + module.name + "' has no functions");
  }
  
  // Check for duplicate function names
  std::set<std::string> func_names;
  for (const auto& func : module.functions) {
    if (func_names.count(func->name)) {
      errors.push_back("Duplicate function name: '" + func->name + "'");
    }
    func_names.insert(func->name);
    
    // Validate each function
    auto func_errors = validate_function_detailed(*func);
    for (const auto& error : func_errors) {
      errors.push_back("In function '" + func->name + "': " + error);
    }
  }
  
  return errors;
}

// IRDumper static members
int IRDumper::indent_size = 2;
bool IRDumper::show_types = true;
bool IRDumper::show_ids = false;

std::string IRDumper::dump_module(const Module& module, DumpFormat format) {
  std::string result;
  
  switch (format) {
    case DumpFormat::HUMAN_READABLE:
    case DumpFormat::DEBUG:
      result += "Module: " + module.name + "\n";
      result += "Functions: " + std::to_string(module.functions.size()) + "\n\n";
      break;
    case DumpFormat::LLVM_STYLE:
      result += "; ModuleID = '" + module.name + "'\n\n";
      break;
    case DumpFormat::COMPACT:
      result += "module " + module.name + " {";
      break;
  }
  
  for (const auto& func : module.functions) {
    result += dump_function(*func, format);
    if (format == DumpFormat::HUMAN_READABLE || format == DumpFormat::DEBUG) {
      result += "\n";
    }
  }
  
  if (format == DumpFormat::COMPACT) {
    result += "}";
  }
  
  return result;
}

std::string IRDumper::dump_function(const Function& func, DumpFormat format) {
  std::string result;
  
  switch (format) {
    case DumpFormat::HUMAN_READABLE:
      result += "Function: " + func.name + "\n";
      result += indent(1) + "Return type: " + dump_type(func.return_type, format) + "\n";
      result += indent(1) + "Arguments: " + std::to_string(func.arguments.size()) + "\n";
      for (const auto& arg : func.arguments) {
        result += indent(2) + dump_value(*arg, format) + "\n";
      }
      result += indent(1) + "Basic blocks: " + std::to_string(func.basic_blocks.size()) + "\n";
      break;
      
    case DumpFormat::LLVM_STYLE:
      result += "define " + dump_type(func.return_type, format) + " @" + func.name + "(";
      for (size_t i = 0; i < func.arguments.size(); ++i) {
        if (i > 0) result += ", ";
        result += dump_value(*func.arguments[i], format);
      }
      result += ") {\n";
      break;
      
    case DumpFormat::DEBUG:
      result += "Function: " + func.name + " (ID: " + std::to_string(reinterpret_cast<uintptr_t>(&func)) + ")\n";
      result += indent(1) + "Return type: " + dump_type(func.return_type, format) + "\n";
      result += indent(1) + "Arguments: " + std::to_string(func.arguments.size()) + "\n";
      for (const auto& arg : func.arguments) {
        result += indent(2) + dump_value(*arg, format) + "\n";
      }
      break;
      
    case DumpFormat::COMPACT:
      result += " func " + func.name + "(";
      for (size_t i = 0; i < func.arguments.size(); ++i) {
        if (i > 0) result += ",";
        result += dump_value(*func.arguments[i], format);
      }
      result += ")";
      break;
  }
  
  for (const auto& bb : func.basic_blocks) {
    result += dump_basic_block(*bb, format);
  }
  
  if (format == DumpFormat::LLVM_STYLE) {
    result += "}\n";
  }
  
  return result;
}

std::string IRDumper::dump_basic_block(const BasicBlock& bb, DumpFormat format) {
  std::string result;
  std::string bb_name = bb.name.empty() ? ("bb" + std::to_string(bb.id)) : bb.name;
  
  switch (format) {
    case DumpFormat::HUMAN_READABLE:
      result += indent(1) + "Block: " + bb_name + " (" + std::to_string(bb.instructions.size()) + " instructions)\n";
      break;
    case DumpFormat::LLVM_STYLE:
      result += bb_name + ":\n";
      break;
    case DumpFormat::DEBUG:
      result += indent(1) + "Block: " + bb_name + " (ID: " + std::to_string(bb.id) + 
                ", " + std::to_string(bb.instructions.size()) + " instructions)\n";
      break;
    case DumpFormat::COMPACT:
      result += " " + bb_name + ":";
      break;
  }
  
  for (const auto& inst : bb.instructions) {
    result += dump_instruction(*inst, format);
    if (format != DumpFormat::COMPACT) {
      result += "\n";
    } else {
      result += ";";
    }
  }
  
  return result;
}

std::string IRDumper::dump_instruction(const Instruction& inst, DumpFormat format) {
  std::string result;
  int base_indent = (format == DumpFormat::LLVM_STYLE) ? 1 : 2;
  
  if (format != DumpFormat::COMPACT) {
    result += indent(base_indent);
  }
  
  // Result register
  if (inst.result_reg && inst.result_type.kind != TypeKind::VOID) {
    result += dump_value(*inst.result_reg, format) + " = ";
  }
  
  // Opcode
  result += opcode_to_string(inst.opcode);
  
  // Type information
  if (show_types && inst.result_type.kind != TypeKind::VOID) {
    result += " " + dump_type(inst.result_type, format);
  }
  
  // Operands
  if (!inst.operands.empty()) {
    result += " " + format_operands(inst.operands, format);
  }
  
  // Special instruction-specific information
  switch (inst.opcode) {
    case Opcode::ATOMIC_LOAD:
    case Opcode::ATOMIC_STORE:
    case Opcode::ATOMIC_CAS:
    case Opcode::ATOMIC_RMW:
    case Opcode::ATOMIC_FENCE:
      // Add memory ordering information for atomic operations
      result += " ; atomic";
      break;
    default:
      break;
  }
  
  return result;
}

std::string IRDumper::dump_value(const Value& val, DumpFormat format) {
  std::string result;
  
  switch (val.kind) {
    case Value::Kind::CONSTANT: {
      if (auto ci = dynamic_cast<const ConstantInt*>(&val)) {
        result = std::to_string(ci->value);
      } else if (auto cf = dynamic_cast<const ConstantFloat*>(&val)) {
        result = std::to_string(cf->value);
      } else {
        result = "const";
      }
      break;
    }
    case Value::Kind::REGISTER: {
      auto reg = static_cast<const Register*>(&val);
      if (!reg->name.empty()) {
        result = "%" + reg->name;
      } else {
        result = "%r" + std::to_string(val.id);
      }
      break;
    }
    case Value::Kind::ARGUMENT: {
      auto arg = static_cast<const Argument*>(&val);
      if (!arg->name.empty()) {
        result = "%" + arg->name;
      } else {
        result = "%arg" + std::to_string(arg->index);
      }
      break;
    }
    case Value::Kind::GLOBAL: {
      result = "@global" + std::to_string(val.id);
      break;
    }
  }
  
  if (show_types) {
    result += ":" + dump_type(val.type, format);
  }
  
  if (show_ids && format == DumpFormat::DEBUG) {
    result += " (id:" + std::to_string(val.id) + ")";
  }
  
  return result;
}

std::string IRDumper::dump_type(const Type& type, DumpFormat format) {
  switch (type.kind) {
    case TypeKind::VOID: return "void";
    case TypeKind::I1: return "i1";
    case TypeKind::I8: return "i8"; 
    case TypeKind::I16: return "i16";
    case TypeKind::I32: return "i32";
    case TypeKind::I64: return "i64";
    case TypeKind::F32: return "f32";
    case TypeKind::F64: return "f64";
    case TypeKind::PTR:
      return dump_type(*type.element_type, format) + "*";
    case TypeKind::ARRAY:
      return "[" + std::to_string(type.array_length) + " x " + 
             dump_type(*type.element_type, format) + "]";
    case TypeKind::STRUCT: {
      std::string result = "{";
      for (size_t i = 0; i < type.struct_fields.size(); ++i) {
        if (i > 0) result += ", ";
        result += dump_type(type.struct_fields[i], format);
      }
      result += "}";
      return result;
    }
    case TypeKind::VECTOR:
      return "<vector " + dump_type(*type.element_type, format) + ">";
  }
  return "unknown";
}

std::string IRDumper::opcode_to_string(Opcode op) {
  switch (op) {
    case Opcode::ADD: return "add";
    case Opcode::SUB: return "sub";
    case Opcode::MUL: return "mul";
    case Opcode::UDIV: return "udiv";
    case Opcode::SDIV: return "sdiv";
    case Opcode::UREM: return "urem";
    case Opcode::SREM: return "srem";
    case Opcode::FADD: return "fadd";
    case Opcode::FSUB: return "fsub";
    case Opcode::FMUL: return "fmul";
    case Opcode::FDIV: return "fdiv";
    case Opcode::FREM: return "frem";
    case Opcode::AND: return "and";
    case Opcode::OR: return "or";
    case Opcode::XOR: return "xor";
    case Opcode::SHL: return "shl";
    case Opcode::LSHR: return "lshr";
    case Opcode::ASHR: return "ashr";
    case Opcode::NOT: return "not";
    case Opcode::LOAD: return "load";
    case Opcode::STORE: return "store";
    case Opcode::ALLOCA: return "alloca";
    case Opcode::EXTRACTVALUE: return "extractvalue";
    case Opcode::INSERTVALUE: return "insertvalue";
    case Opcode::GEP: return "getelementptr";
    case Opcode::ICMP_EQ: return "icmp eq";
    case Opcode::ICMP_NE: return "icmp ne";
    case Opcode::ICMP_ULT: return "icmp ult";
    case Opcode::ICMP_ULE: return "icmp ule";
    case Opcode::ICMP_UGT: return "icmp ugt";
    case Opcode::ICMP_UGE: return "icmp uge";
    case Opcode::ICMP_SLT: return "icmp slt";
    case Opcode::ICMP_SLE: return "icmp sle";
    case Opcode::ICMP_SGT: return "icmp sgt";
    case Opcode::ICMP_SGE: return "icmp sge";
    case Opcode::BR: return "br";
    case Opcode::BR_COND: return "br";
    case Opcode::RET: return "ret";
    case Opcode::CALL: return "call";
    case Opcode::PHI: return "phi";
    case Opcode::SELECT: return "select";
    case Opcode::ATOMIC_LOAD: return "atomic_load";
    case Opcode::ATOMIC_STORE: return "atomic_store";
    case Opcode::ATOMIC_CAS: return "atomic_cas";
    case Opcode::ATOMIC_RMW: return "atomic_rmw";
    case Opcode::ATOMIC_FENCE: return "atomic_fence";
    case Opcode::SYSCALL: return "syscall";
    default: return "unknown";
  }
}

std::string IRDumper::memory_ordering_to_string(MemoryOrdering ordering) {
  switch (ordering) {
    case MemoryOrdering::RELAXED: return "relaxed";
    case MemoryOrdering::CONSUME: return "consume";
    case MemoryOrdering::ACQUIRE: return "acquire";
    case MemoryOrdering::RELEASE: return "release";
    case MemoryOrdering::ACQ_REL: return "acq_rel";
    case MemoryOrdering::SEQ_CST: return "seq_cst";
  }
  return "unknown";
}

std::string IRDumper::atomic_rmw_op_to_string(AtomicRMWOp op) {
  switch (op) {
    case AtomicRMWOp::XCHG: return "xchg";
    case AtomicRMWOp::ADD: return "add";
    case AtomicRMWOp::SUB: return "sub";
    case AtomicRMWOp::AND: return "and";
    case AtomicRMWOp::NAND: return "nand";
    case AtomicRMWOp::OR: return "or";
    case AtomicRMWOp::XOR: return "xor";
    case AtomicRMWOp::MAX: return "max";
    case AtomicRMWOp::MIN: return "min";
    case AtomicRMWOp::UMAX: return "umax";
    case AtomicRMWOp::UMIN: return "umin";
  }
  return "unknown";
}

std::string IRDumper::indent(int level) {
  return std::string(level * indent_size, ' ');
}

std::string IRDumper::format_operands(const std::vector<std::shared_ptr<Value>>& operands, DumpFormat format) {
  std::string result;
  for (size_t i = 0; i < operands.size(); ++i) {
    if (i > 0) result += ", ";
    result += dump_value(*operands[i], format);
  }
  return result;
}

// IRAnalyzer implementations
IRAnalyzer::ModuleStats IRAnalyzer::analyze_module(const Module& module) {
  ModuleStats stats;
  stats.num_functions = module.functions.size();
  
  for (const auto& func : module.functions) {
    stats.num_basic_blocks += func->basic_blocks.size();
    
    for (const auto& bb : func->basic_blocks) {
      stats.num_instructions += bb->instructions.size();
      
      for (const auto& inst : bb->instructions) {
        stats.instruction_counts[inst->opcode]++;
        stats.type_counts[inst->result_type.kind]++;
        
        // Count specific operation types
        switch (inst->opcode) {
          case Opcode::LOAD:
            stats.load_count++;
            break;
          case Opcode::STORE:
            stats.store_count++;
            break;
          case Opcode::ATOMIC_LOAD:
          case Opcode::ATOMIC_STORE:
          case Opcode::ATOMIC_CAS:
          case Opcode::ATOMIC_RMW:
          case Opcode::ATOMIC_FENCE:
            stats.atomic_count++;
            break;
          case Opcode::CALL:
            stats.call_count++;
            break;
          default:
            break;
        }
        
        stats.num_values += inst->operands.size();
        if (inst->result_reg) {
          stats.num_values++;
        }
      }
    }
  }
  
  return stats;
}

std::string IRAnalyzer::ModuleStats::to_string() const {
  std::string result;
  result += "Module Statistics:\n";
  result += "  Functions: " + std::to_string(num_functions) + "\n";
  result += "  Basic Blocks: " + std::to_string(num_basic_blocks) + "\n";
  result += "  Instructions: " + std::to_string(num_instructions) + "\n";
  result += "  Values: " + std::to_string(num_values) + "\n";
  result += "  Memory Operations:\n";
  result += "    Loads: " + std::to_string(load_count) + "\n";
  result += "    Stores: " + std::to_string(store_count) + "\n";
  result += "    Atomic: " + std::to_string(atomic_count) + "\n";
  result += "  Calls: " + std::to_string(call_count) + "\n";
  result += "  Top Instructions:\n";
  
  // Show top 5 most used instructions
  std::vector<std::pair<Opcode, uint32_t>> sorted_insts(instruction_counts.begin(), instruction_counts.end());
  std::sort(sorted_insts.begin(), sorted_insts.end(), 
            [](const auto& a, const auto& b) { return a.second > b.second; });
  
  for (size_t i = 0; i < std::min(sorted_insts.size(), size_t(5)); ++i) {
    result += "    " + IRDumper::opcode_to_string(sorted_insts[i].first) + ": " + 
              std::to_string(sorted_insts[i].second) + "\n";
  }
  
  return result;
}

} // namespace IR
