#pragma once
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <variant>
#include <algorithm>
#include <map>
#include <set>

namespace IR {

// Forward declarations
class Module;
class Function;
class BasicBlock;
class Instruction;
class Value;

// Memory ordering for atomic operations (matches C++11 memory model)
enum class MemoryOrdering {
  RELAXED,      // No ordering constraints, only atomicity guaranteed
  CONSUME,      // Data dependency ordering (deprecated, treated as ACQUIRE)
  ACQUIRE,      // Acquire semantics for loads
  RELEASE,      // Release semantics for stores  
  ACQ_REL,      // Both acquire and release semantics
  SEQ_CST       // Sequential consistency (strongest ordering)
};

// Atomic RMW (Read-Modify-Write) operations
enum class AtomicRMWOp {
  XCHG,    // Exchange (swap)
  ADD,     // Fetch and add
  SUB,     // Fetch and subtract
  AND,     // Fetch and bitwise AND
  NAND,    // Fetch and bitwise NAND
  OR,      // Fetch and bitwise OR
  XOR,     // Fetch and bitwise XOR
  MAX,     // Fetch and max (signed)
  MIN,     // Fetch and min (signed)
  UMAX,    // Fetch and max (unsigned)
  UMIN     // Fetch and min (unsigned)
};



// Types in the IR - Complete type system for AOT compilation
enum class TypeKind { 
  VOID,           // No type/value
  I1, I8, I16, I32, I64,  // Integer types
  F32, F64,       // Floating point types  
  PTR,            // Pointer type
  STRUCT,         // Aggregate struct type
  ARRAY,          // Fixed-size array type
  VECTOR          // Dynamic vector type
};

struct Type {
  TypeKind kind;
  uint32_t size_bits;           // Size in bits for primitive types
  uint32_t array_length;        // Length for arrays (0 for dynamic vectors)
  std::unique_ptr<Type> element_type; // Element type for arrays/vectors/pointers
  std::vector<Type> struct_fields;    // Field types for structs
  std::vector<std::string> field_names; // Field names for structs (optional)
  
  // Default constructor
  Type() : kind(TypeKind::VOID), size_bits(0), array_length(0) {}
  
  // Copy constructor
  Type(const Type& other) 
    : kind(other.kind), size_bits(other.size_bits), array_length(other.array_length),
      struct_fields(other.struct_fields), field_names(other.field_names) {
    if (other.element_type) {
      element_type = std::make_unique<Type>(*other.element_type);
    }
  }
  
  // Assignment operator
  Type& operator=(const Type& other) {
    if (this != &other) {
      kind = other.kind;
      size_bits = other.size_bits;
      array_length = other.array_length;
      struct_fields = other.struct_fields;
      field_names = other.field_names;
      element_type = other.element_type ? std::make_unique<Type>(*other.element_type) : nullptr;
    }
    return *this;
  }
  
  // Factory methods for primitive types
  static Type void_type() { 
    Type t; t.kind = TypeKind::VOID; t.size_bits = 0; return t; 
  }
  static Type i1() { 
    Type t; t.kind = TypeKind::I1; t.size_bits = 1; return t; 
  }
  static Type i8() { 
    Type t; t.kind = TypeKind::I8; t.size_bits = 8; return t; 
  }
  static Type i16() { 
    Type t; t.kind = TypeKind::I16; t.size_bits = 16; return t; 
  }
  static Type i32() { 
    Type t; t.kind = TypeKind::I32; t.size_bits = 32; return t; 
  }
  static Type i64() { 
    Type t; t.kind = TypeKind::I64; t.size_bits = 64; return t; 
  }
  static Type f32() { 
    Type t; t.kind = TypeKind::F32; t.size_bits = 32; return t; 
  }
  static Type f64() { 
    Type t; t.kind = TypeKind::F64; t.size_bits = 64; return t; 
  }
  
  // Factory methods for composite types
  static Type ptr(const Type& pointee_type) {
    Type t;
    t.kind = TypeKind::PTR;
    t.size_bits = 64; // 64-bit pointers
    t.element_type = std::make_unique<Type>(pointee_type);
    return t;
  }
  
  static Type ptr_to(const Type& pointee_type) {
    return ptr(pointee_type);
  }
  
  static Type array(const Type& element_type, uint32_t length) {
    Type t;
    t.kind = TypeKind::ARRAY;
    t.array_length = length;
    t.size_bits = element_type.size_bits * length;
    t.element_type = std::make_unique<Type>(element_type);
    return t;
  }
  
  static Type vector(const Type& element_type) {
    Type t;
    t.kind = TypeKind::VECTOR;
    t.array_length = 0; // Dynamic size
    t.size_bits = 64;   // Pointer to data + metadata
    t.element_type = std::make_unique<Type>(element_type);
    return t;
  }
  
  static Type struct_type(const std::vector<Type>& fields, 
                         const std::vector<std::string>& names = {}) {
    Type t;
    t.kind = TypeKind::STRUCT;
    t.struct_fields = fields;
    t.field_names = names;
    
    // Calculate struct size with proper alignment
    uint32_t offset = 0;
    uint32_t max_align = 1;
    for (const auto& field : fields) {
      uint32_t field_align = field.alignment();
      max_align = std::max(max_align, field_align);
      offset = (offset + field_align - 1) & ~(field_align - 1); // Align
      offset += field.size_bytes();
    }
    // Final struct size aligned to largest member
    t.size_bits = ((offset + max_align - 1) & ~(max_align - 1)) * 8;
    return t;
  }
  
  // Type queries
  bool is_integer() const { return kind >= TypeKind::I1 && kind <= TypeKind::I64; }
  bool is_float() const { return kind == TypeKind::F32 || kind == TypeKind::F64; }
  bool is_pointer() const { return kind == TypeKind::PTR; }
  bool is_aggregate() const { return kind == TypeKind::STRUCT || kind == TypeKind::ARRAY; }
  bool is_void() const { return kind == TypeKind::VOID; }
  
  // Size calculations
  uint32_t size_bytes() const { return (size_bits + 7) / 8; }
  uint32_t alignment() const {
    switch (kind) {
      case TypeKind::I1: case TypeKind::I8: return 1;
      case TypeKind::I16: return 2;
      case TypeKind::I32: case TypeKind::F32: return 4;
      case TypeKind::I64: case TypeKind::F64: case TypeKind::PTR: return 8;
      case TypeKind::STRUCT: {
        uint32_t max_align = 1;
        for (const auto& field : struct_fields) {
          max_align = std::max(max_align, field.alignment());
        }
        return max_align;
      }
      case TypeKind::ARRAY: 
        return element_type ? element_type->alignment() : 1;
      case TypeKind::VECTOR:
        return 8; // Pointer alignment
      default: return 1;
    }
  }
  
  // Get field offset in struct
  uint32_t get_field_offset(uint32_t field_index) const {
    if (kind != TypeKind::STRUCT || field_index >= struct_fields.size()) {
      return 0;
    }
    
    uint32_t offset = 0;
    for (uint32_t i = 0; i < field_index; ++i) {
      uint32_t field_align = struct_fields[i].alignment();
      offset = (offset + field_align - 1) & ~(field_align - 1);
      offset += struct_fields[i].size_bytes();
    }
    
    // Align for the target field
    uint32_t target_align = struct_fields[field_index].alignment();
    return (offset + target_align - 1) & ~(target_align - 1);
  }
  
  // Get pointee type for pointers
  const Type* get_pointee_type() const {
    return (kind == TypeKind::PTR && element_type) ? element_type.get() : nullptr;
  }
  
  // Get element type for arrays/vectors
  const Type* get_element_type() const {
    return ((kind == TypeKind::ARRAY || kind == TypeKind::VECTOR) && element_type) 
           ? element_type.get() : nullptr;
  }
};

// Safety and validation utilities
class SafetyChecker {
public:
  // Type safety validation
  static bool is_atomic_compatible_type(const Type& type);
  static bool is_valid_pointer_type(const Type& type);
  static bool is_valid_memory_ordering_for_load(MemoryOrdering ordering);
  static bool is_valid_memory_ordering_for_store(MemoryOrdering ordering);
  static bool is_valid_memory_ordering_for_rmw(MemoryOrdering ordering);
  static bool is_valid_memory_ordering_for_cas(MemoryOrdering success, MemoryOrdering failure);
  
  // Value range validation
  static bool is_valid_alignment(uint32_t alignment);
  static bool is_power_of_two(uint32_t value);
  
  // Instruction validation
  static bool validate_instruction(const Instruction& inst);
  static bool validate_function(const Function& func);
  static bool validate_module(const Module& module);
  
  // Extended validation with detailed error reporting
  static std::vector<std::string> validate_instruction_detailed(const Instruction& inst);
  static std::vector<std::string> validate_function_detailed(const Function& func);
  static std::vector<std::string> validate_module_detailed(const Module& module);
};

// Values: constants, registers, function arguments
class Value {
public:
  enum class Kind { CONSTANT, REGISTER, ARGUMENT, GLOBAL };
  
  Value(Kind k, Type t) : kind(k), type(t), id(next_id++) {}
  virtual ~Value() = default;
  
  Kind kind;
  Type type;
  uint32_t id;
  
private:
  static uint32_t next_id;
};

class ConstantInt : public Value {
public:
  ConstantInt(Type t, int64_t v) : Value(Kind::CONSTANT, t), value(v) {}
  int64_t value;
};

class ConstantFloat : public Value {
public:
  ConstantFloat(Type t, double v) : Value(Kind::CONSTANT, t), value(v) {}
  double value;
};

class Register : public Value {
public:
  Register(Type t, const std::string& n = "") : Value(Kind::REGISTER, t), name(n) {}
  std::string name;
};

class Argument : public Value {
public:
  Argument(Type t, uint32_t idx, const std::string& n = "") 
    : Value(Kind::ARGUMENT, t), index(idx), name(n) {}
  uint32_t index;
  std::string name;
};

class GlobalString : public Value {
public:
  GlobalString(const std::string& str) 
    : Value(Kind::GLOBAL, Type::ptr_to(Type::i8())), string_value(str) {}
  std::string string_value;
};

// Instructions - Complete instruction set for AOT compilation
enum class Opcode {
  // Arithmetic operations
  ADD, SUB, MUL, UDIV, SDIV, UREM, SREM,
  FADD, FSUB, FMUL, FDIV, FREM,
  
  // Bitwise operations
  AND, OR, XOR, SHL, LSHR, ASHR, NOT,
  
  // Memory operations
  LOAD, STORE, ALLOCA,
  
  // Aggregate operations (structs/arrays)
  EXTRACTVALUE,    // Extract field from struct/array
  INSERTVALUE,     // Insert value into struct/array
  GEP,            // GetElementPtr - calculate addresses
  
  // Comparison operations
  ICMP_EQ, ICMP_NE, ICMP_ULT, ICMP_ULE, ICMP_UGT, ICMP_UGE,
  ICMP_SLT, ICMP_SLE, ICMP_SGT, ICMP_SGE,
  FCMP_OEQ, FCMP_ONE, FCMP_OLT, FCMP_OLE, FCMP_OGT, FCMP_OGE,
  FCMP_UEQ, FCMP_UNE, FCMP_ULT, FCMP_ULE, FCMP_UGT, FCMP_UGE,
  
  // Control flow
  BR, BR_COND, RET, CALL, INVOKE,
  
  // Type conversions
  TRUNC, ZEXT, SEXT,                    // Integer conversions
  FPTRUNC, FPEXT,                       // Float conversions  
  FPTOUI, FPTOSI, UITOFP, SITOFP,      // Float/int conversions
  PTRTOINT, INTTOPTR,                   // Pointer conversions
  BITCAST,                              // Type punning
  
  // Advanced operations
  PHI,              // SSA phi node
  SELECT,           // Conditional select
  SWITCH,           // Multi-way branch
  
  // Vector operations (for SIMD)
  VECTOR_EXTRACT,   // Extract element from vector
  VECTOR_INSERT,    // Insert element into vector
  VECTOR_SHUFFLE,   // Shuffle vector elements
  
  // Atomic operations with memory ordering
  ATOMIC_LOAD, ATOMIC_STORE, ATOMIC_CAS, ATOMIC_RMW,
  ATOMIC_FENCE,
  
  // System calls
  SYSCALL,
  
  // Exception handling
  LANDINGPAD, RESUME, UNREACHABLE
};

class Instruction {
public:
  Instruction(Opcode op, Type result_type) 
    : opcode(op), result_type(result_type), result_reg(nullptr) {
    if (result_type.kind != TypeKind::VOID) {
      result_reg = std::make_shared<Register>(result_type);
    }
  }
  virtual ~Instruction() = default;
  
  Opcode opcode;
  Type result_type;
  std::shared_ptr<Register> result_reg;
  std::vector<std::shared_ptr<Value>> operands;
  
  // void add_operand(std::shared_ptr<Value> val) { operands.push_back(val); }
  
  // Instruction-specific data
  std::string extra_string;
  BasicBlock* extra_block = nullptr;
};

// Binary operations (add, sub, mul, etc.)
class BinaryOp : public Instruction {
public:
  BinaryOp(Opcode op, std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs)
    : Instruction(op, lhs->type) {
    operands.push_back(lhs);
    operands.push_back(rhs);
  }
};

// Memory operations
class LoadInst : public Instruction {
public:
  LoadInst(Type load_type, std::shared_ptr<Value> ptr)
    : Instruction(Opcode::LOAD, load_type) {
    operands.push_back(ptr);
  }
};

class StoreInst : public Instruction {
public:
  StoreInst(std::shared_ptr<Value> value, std::shared_ptr<Value> ptr)
    : Instruction(Opcode::STORE, Type::void_type()) {
    operands.push_back(value);
    operands.push_back(ptr);
  }
};

// Control flow
class ReturnInst : public Instruction {
public:
  ReturnInst(std::shared_ptr<Value> val = nullptr) 
    : Instruction(Opcode::RET, Type::void_type()) {
    if (val) operands.push_back(val);
  }
};

class BranchInst : public Instruction {
public:
  BranchInst(BasicBlock* target)
    : Instruction(Opcode::BR, Type::void_type()), target_block(target) {}
  
  BranchInst(std::shared_ptr<Value> cond, BasicBlock* true_bb, BasicBlock* false_bb)
    : Instruction(Opcode::BR_COND, Type::void_type()), 
      target_block(true_bb), false_block(false_bb) {
    operands.push_back(cond);
  }
  
  BasicBlock* target_block;
  BasicBlock* false_block = nullptr;
};

class CallInst : public Instruction {
public:
  CallInst(Type ret_type, const std::string& func_name, 
           const std::vector<std::shared_ptr<Value>>& args)
    : Instruction(Opcode::CALL, ret_type), function_name(func_name) {
    for (auto arg : args) operands.push_back(arg);
  }
  
  std::string function_name;
};

// Aggregate operations for structs and arrays
class ExtractValueInst : public Instruction {
public:
  ExtractValueInst(std::shared_ptr<Value> aggregate, const std::vector<uint32_t>& indices)
    : Instruction(Opcode::EXTRACTVALUE, get_extracted_type(aggregate->type, indices)), 
      field_indices(indices) {
    operands.push_back(aggregate);
  }
  
  std::vector<uint32_t> field_indices;

private:
  Type get_extracted_type(const Type& agg_type, const std::vector<uint32_t>& indices) {
    const Type* current = &agg_type;
    for (uint32_t idx : indices) {
      if (current->kind == TypeKind::STRUCT && idx < current->struct_fields.size()) {
        current = &current->struct_fields[idx];
      } else if (current->kind == TypeKind::ARRAY && current->element_type) {
        current = current->element_type.get();
      } else {
        return Type::void_type(); // Error case
      }
    }
    return *current;
  }
};

class InsertValueInst : public Instruction {
public:
  InsertValueInst(std::shared_ptr<Value> aggregate, std::shared_ptr<Value> value,
                  const std::vector<uint32_t>& indices)
    : Instruction(Opcode::INSERTVALUE, aggregate->type), field_indices(indices) {
    operands.push_back(aggregate);
    operands.push_back(value);
  }
  
  std::vector<uint32_t> field_indices;
};

// GetElementPtr for address calculation
class GEPInst : public Instruction {
public:
  GEPInst(std::shared_ptr<Value> ptr, const std::vector<std::shared_ptr<Value>>& indices)
    : Instruction(Opcode::GEP, Type::ptr(get_gep_type(ptr->type, indices))) {
    operands.push_back(ptr);
    for (auto idx : indices) operands.push_back(idx);
  }

private:
  Type get_gep_type(const Type& ptr_type, const std::vector<std::shared_ptr<Value>>& indices) {
    if (!ptr_type.is_pointer() || !ptr_type.element_type) {
      return Type::i8(); // Default to i8 on error
    }
    
    const Type* current = ptr_type.element_type.get();
    for (size_t i = 1; i < indices.size(); ++i) { // Skip first index (pointer deref)
      if (current->kind == TypeKind::STRUCT && i-1 < current->struct_fields.size()) {
        current = &current->struct_fields[i-1];
      } else if (current->kind == TypeKind::ARRAY && current->element_type) {
        current = current->element_type.get();
      }
    }
    return *current;
  }
};

// Comparison instructions
class ICmpInst : public Instruction {
public:
  ICmpInst(Opcode cmp_op, std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs)
    : Instruction(cmp_op, Type::i1()) {
    operands.push_back(lhs);
    operands.push_back(rhs);
  }
};

class FCmpInst : public Instruction {
public:
  FCmpInst(Opcode cmp_op, std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs)
    : Instruction(cmp_op, Type::i1()) {
    operands.push_back(lhs);
    operands.push_back(rhs);
  }
};

// Type conversion instructions
class CastInst : public Instruction {
public:
  CastInst(Opcode cast_op, std::shared_ptr<Value> value, Type dest_type)
    : Instruction(cast_op, dest_type) {
    operands.push_back(value);
  }
};

// Alloca instruction for stack allocation
class AllocaInst : public Instruction {
public:
  AllocaInst(Type allocated_type, std::shared_ptr<Value> array_size = nullptr)
    : Instruction(Opcode::ALLOCA, Type::ptr(allocated_type)), allocated_type(allocated_type) {
    if (array_size) operands.push_back(array_size);
  }
  
  Type allocated_type;
};

// PHI instruction for SSA form
class PhiInst : public Instruction {
public:
  PhiInst(Type phi_type) : Instruction(Opcode::PHI, phi_type) {}
  
  void add_incoming(std::shared_ptr<Value> value, BasicBlock* block) {
    operands.push_back(value);
    incoming_blocks.push_back(block);
  }
  
  std::vector<BasicBlock*> incoming_blocks;
};

// Select instruction (conditional)
class SelectInst : public Instruction {
public:
  SelectInst(std::shared_ptr<Value> condition, std::shared_ptr<Value> true_val, 
             std::shared_ptr<Value> false_val)
    : Instruction(Opcode::SELECT, true_val->type) {
    operands.push_back(condition);
    operands.push_back(true_val);
    operands.push_back(false_val);
  }
};

// Atomic operations with safety and memory ordering
class AtomicLoadInst : public Instruction {
public:
  AtomicLoadInst(Type load_type, std::shared_ptr<Value> ptr, 
                 MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                 uint32_t alignment = 0)
    : Instruction(Opcode::ATOMIC_LOAD, load_type), 
      memory_ordering(ordering), alignment(alignment) {
    
    // Safety validation
    if (!SafetyChecker::is_atomic_compatible_type(load_type)) {
      throw std::runtime_error("Type not compatible with atomic operations");
    }
    if (!SafetyChecker::is_valid_pointer_type(ptr->type)) {
      throw std::runtime_error("Atomic load requires a pointer operand");
    }
    // Verify pointer points to the correct type
    if (ptr->type.element_type && ptr->type.element_type->kind != load_type.kind) {
      throw std::runtime_error("Pointer type mismatch for atomic load");
    }
    if (!SafetyChecker::is_valid_memory_ordering_for_load(ordering)) {
      throw std::runtime_error("Invalid memory ordering for atomic load");
    }
    if (alignment == 0) {
      this->alignment = load_type.alignment();
    }
    if (!SafetyChecker::is_valid_alignment(this->alignment)) {
      throw std::runtime_error("Invalid alignment for atomic load");
    }
    
    operands.push_back(ptr);
  }
  
  MemoryOrdering memory_ordering;
  uint32_t alignment;
};

class AtomicStoreInst : public Instruction {
public:
  AtomicStoreInst(std::shared_ptr<Value> value, std::shared_ptr<Value> ptr,
                  MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                  uint32_t alignment = 0)
    : Instruction(Opcode::ATOMIC_STORE, Type::void_type()),
      memory_ordering(ordering), alignment(alignment) {
    
    // Safety validation
    if (!SafetyChecker::is_atomic_compatible_type(value->type)) {
      throw std::runtime_error("Type not compatible with atomic operations");
    }
    if (!SafetyChecker::is_valid_memory_ordering_for_store(ordering)) {
      throw std::runtime_error("Invalid memory ordering for atomic store");
    }
    if (alignment == 0) {
      this->alignment = value->type.alignment();
    }
    if (!SafetyChecker::is_valid_alignment(this->alignment)) {
      throw std::runtime_error("Invalid alignment for atomic store");
    }
    
    operands.push_back(value);
    operands.push_back(ptr);
  }
  
  MemoryOrdering memory_ordering;
  uint32_t alignment;
};

class AtomicCASInst : public Instruction {
public:
  AtomicCASInst(std::shared_ptr<Value> ptr, std::shared_ptr<Value> expected,
                std::shared_ptr<Value> desired,
                MemoryOrdering success_ordering = MemoryOrdering::SEQ_CST,
                MemoryOrdering failure_ordering = MemoryOrdering::SEQ_CST,
                uint32_t alignment = 0)
    : Instruction(Opcode::ATOMIC_CAS, 
                  Type::struct_type({expected->type, Type::i1()}, {"value", "success"})),
      success_ordering(success_ordering), failure_ordering(failure_ordering),
      alignment(alignment) {
    
    // Safety validation
    if (!SafetyChecker::is_atomic_compatible_type(expected->type)) {
      throw std::runtime_error("Type not compatible with atomic operations");
    }
    if (expected->type.kind != desired->type.kind) {
      throw std::runtime_error("Expected and desired values must have same type");
    }
    if (!SafetyChecker::is_valid_memory_ordering_for_cas(success_ordering, failure_ordering)) {
      throw std::runtime_error("Invalid memory ordering for atomic CAS");
    }
    if (alignment == 0) {
      this->alignment = expected->type.alignment();
    }
    if (!SafetyChecker::is_valid_alignment(this->alignment)) {
      throw std::runtime_error("Invalid alignment for atomic CAS");
    }
    
    operands.push_back(ptr);
    operands.push_back(expected);
    operands.push_back(desired);
  }
  
  MemoryOrdering success_ordering;
  MemoryOrdering failure_ordering;
  uint32_t alignment;
};

class AtomicRMWInst : public Instruction {
public:
  AtomicRMWInst(AtomicRMWOp operation, std::shared_ptr<Value> ptr, 
                std::shared_ptr<Value> operand,
                MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                uint32_t alignment = 0)
    : Instruction(Opcode::ATOMIC_RMW, operand->type),
      rmw_operation(operation), memory_ordering(ordering), alignment(alignment) {
    
    // Safety validation
    if (!SafetyChecker::is_atomic_compatible_type(operand->type)) {
      throw std::runtime_error("Type not compatible with atomic operations");
    }
    if (!SafetyChecker::is_valid_memory_ordering_for_rmw(ordering)) {
      throw std::runtime_error("Invalid memory ordering for atomic RMW");
    }
    if (alignment == 0) {
      this->alignment = operand->type.alignment();
    }
    if (!SafetyChecker::is_valid_alignment(this->alignment)) {
      throw std::runtime_error("Invalid alignment for atomic RMW");
    }
    
    operands.push_back(ptr);
    operands.push_back(operand);
  }
  
  AtomicRMWOp rmw_operation;
  MemoryOrdering memory_ordering;
  uint32_t alignment;
};

class AtomicFenceInst : public Instruction {
public:
  AtomicFenceInst(MemoryOrdering ordering = MemoryOrdering::SEQ_CST)
    : Instruction(Opcode::ATOMIC_FENCE, Type::void_type()),
      memory_ordering(ordering) {
    
    // Fence can use any ordering except CONSUME
    if (ordering == MemoryOrdering::CONSUME) {
      throw std::runtime_error("CONSUME ordering not valid for fence");
    }
  }
  
  MemoryOrdering memory_ordering;
};

class SyscallInst : public Instruction {
public:
  SyscallInst(uint32_t syscall_num, const std::vector<std::shared_ptr<Value>>& syscall_args)
    : Instruction(Opcode::SYSCALL, Type::i64()),
      syscall_number(syscall_num), args(syscall_args) {
    result_reg = std::make_shared<Register>(Type::i64(), "syscall_result");
  }
  
  uint32_t syscall_number;
  std::vector<std::shared_ptr<Value>> args;
};

// Basic Block: sequence of instructions ending with terminator
class BasicBlock {
public:
  BasicBlock(const std::string& n = "") : name(n), id(next_id++) {}
  
  std::string name;
  uint32_t id;
  std::vector<std::unique_ptr<Instruction>> instructions;
  
  void add_instruction(std::unique_ptr<Instruction> inst) {
    instructions.push_back(std::move(inst));
  }
  
  Instruction* get_terminator() const {
    if (instructions.empty()) return nullptr;
    auto* last = instructions.back().get();
    return (last->opcode == Opcode::RET || last->opcode == Opcode::BR || 
            last->opcode == Opcode::BR_COND) ? last : nullptr;
  }
  
private:
  static uint32_t next_id;
};

// Function: arguments + basic blocks
class Function {
public:
  Function(const std::string& n, Type ret_type, const std::vector<Type>& param_types)
    : name(n), return_type(ret_type) {
    for (uint32_t i = 0; i < param_types.size(); ++i) {
      arguments.push_back(std::make_shared<Argument>(param_types[i], i, "arg" + std::to_string(i)));
    }
  }
  
  std::string name;
  Type return_type;
  std::vector<std::shared_ptr<Argument>> arguments;
  std::vector<std::unique_ptr<BasicBlock>> basic_blocks;
  
  BasicBlock* create_basic_block(const std::string& name = "") {
    auto bb = std::make_unique<BasicBlock>(name);
    BasicBlock* ptr = bb.get();
    basic_blocks.push_back(std::move(bb));
    return ptr;
  }
  
  BasicBlock* get_entry_block() const {
    return basic_blocks.empty() ? nullptr : basic_blocks[0].get();
  }
};

// Module: collection of functions and globals
class Module {
public:
  Module(const std::string& n) : name(n) {}
  
  std::string name;
  std::vector<std::unique_ptr<Function>> functions;
  
  Function* create_function(const std::string& name, Type ret_type, 
                           const std::vector<Type>& param_types) {
    auto func = std::make_unique<Function>(name, ret_type, param_types);
    Function* ptr = func.get();
    functions.push_back(std::move(func));
    return ptr;
  }
  
  Function* get_function(const std::string& name) const {
    for (const auto& func : functions) {
      if (func->name == name) return func.get();
    }
    return nullptr;
  }
  
  // Create global string constant
  std::shared_ptr<Value> create_global_string(const std::string& str) {
    // For now, return a placeholder - this would need backend support
    auto global = std::make_shared<GlobalString>(str);
    globals.push_back(global);
    return global;
  }
  
  std::vector<std::shared_ptr<Value>> globals;
};

// IR Builder for convenient construction - Enhanced with complete instruction set
class IRBuilder {
public:
  IRBuilder() : current_block(nullptr) {}
  
  void set_insert_point(BasicBlock* bb) { current_block = bb; }
  
  // Constants creation
  std::shared_ptr<ConstantInt> get_int1(bool val) {
    return std::make_shared<ConstantInt>(Type::i1(), val ? 1 : 0);
  }
  
  std::shared_ptr<ConstantInt> get_int8(int8_t val) {
    return std::make_shared<ConstantInt>(Type::i8(), val);
  }
  
  std::shared_ptr<ConstantInt> get_int16(int16_t val) {
    return std::make_shared<ConstantInt>(Type::i16(), val);
  }
  
  std::shared_ptr<ConstantInt> get_int32(int32_t val) {
    return std::make_shared<ConstantInt>(Type::i32(), val);
  }
  
  std::shared_ptr<ConstantInt> get_int64(int64_t val) {
    return std::make_shared<ConstantInt>(Type::i64(), val);
  }
  
  std::shared_ptr<ConstantFloat> get_float(float val) {
    return std::make_shared<ConstantFloat>(Type::f32(), val);
  }
  
  std::shared_ptr<ConstantFloat> get_double(double val) {
    return std::make_shared<ConstantFloat>(Type::f64(), val);
  }
  
  // Integer arithmetic
  std::shared_ptr<Register> create_add(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::ADD, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_sub(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::SUB, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_mul(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::MUL, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_udiv(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::UDIV, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_sdiv(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::SDIV, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Float arithmetic
  std::shared_ptr<Register> create_fadd(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::FADD, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_fsub(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::FSUB, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_fmul(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::FMUL, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_fdiv(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::FDIV, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Bitwise operations
  std::shared_ptr<Register> create_and(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::AND, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_or(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::OR, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_xor(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::XOR, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_shl(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::SHL, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_lshr(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::LSHR, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_ashr(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<BinaryOp>(Opcode::ASHR, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Memory operations
  std::shared_ptr<Register> create_load(Type type, std::shared_ptr<Value> ptr) {
    auto inst = std::make_unique<LoadInst>(type, ptr);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  void create_store(std::shared_ptr<Value> val, std::shared_ptr<Value> ptr) {
    auto inst = std::make_unique<StoreInst>(val, ptr);
    current_block->add_instruction(std::move(inst));
  }
  
  std::shared_ptr<Register> create_alloca(Type allocated_type, std::shared_ptr<Value> array_size = nullptr) {
    auto inst = std::make_unique<AllocaInst>(allocated_type, array_size);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Aggregate operations
  std::shared_ptr<Register> create_extractvalue(std::shared_ptr<Value> aggregate, 
                                               const std::vector<uint32_t>& indices) {
    auto inst = std::make_unique<ExtractValueInst>(aggregate, indices);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_insertvalue(std::shared_ptr<Value> aggregate, 
                                              std::shared_ptr<Value> value,
                                              const std::vector<uint32_t>& indices) {
    auto inst = std::make_unique<InsertValueInst>(aggregate, value, indices);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_gep(std::shared_ptr<Value> ptr, 
                                      const std::vector<std::shared_ptr<Value>>& indices) {
    auto inst = std::make_unique<GEPInst>(ptr, indices);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Comparisons
  std::shared_ptr<Register> create_icmp_eq(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<ICmpInst>(Opcode::ICMP_EQ, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_icmp_ne(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<ICmpInst>(Opcode::ICMP_NE, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_icmp_slt(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<ICmpInst>(Opcode::ICMP_SLT, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_icmp_sgt(std::shared_ptr<Value> lhs, std::shared_ptr<Value> rhs) {
    auto inst = std::make_unique<ICmpInst>(Opcode::ICMP_SGT, lhs, rhs);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Type conversions
  std::shared_ptr<Register> create_trunc(std::shared_ptr<Value> val, Type dest_type) {
    auto inst = std::make_unique<CastInst>(Opcode::TRUNC, val, dest_type);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_zext(std::shared_ptr<Value> val, Type dest_type) {
    auto inst = std::make_unique<CastInst>(Opcode::ZEXT, val, dest_type);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_sext(std::shared_ptr<Value> val, Type dest_type) {
    auto inst = std::make_unique<CastInst>(Opcode::SEXT, val, dest_type);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_bitcast(std::shared_ptr<Value> val, Type dest_type) {
    auto inst = std::make_unique<CastInst>(Opcode::BITCAST, val, dest_type);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Control flow
  void create_ret(std::shared_ptr<Value> val = nullptr) {
    auto inst = std::make_unique<ReturnInst>(val);
    current_block->add_instruction(std::move(inst));
  }
  
  void create_br(BasicBlock* target) {
    auto inst = std::make_unique<BranchInst>(target);
    current_block->add_instruction(std::move(inst));
  }
  
  void create_cond_br(std::shared_ptr<Value> cond, BasicBlock* true_bb, BasicBlock* false_bb) {
    auto inst = std::make_unique<BranchInst>(cond, true_bb, false_bb);
    current_block->add_instruction(std::move(inst));
  }
  
  std::shared_ptr<Register> create_call(Type ret_type, const std::string& func_name,
                                       const std::vector<std::shared_ptr<Value>>& args) {
    auto inst = std::make_unique<CallInst>(ret_type, func_name, args);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Advanced operations
  std::shared_ptr<Register> create_phi(Type phi_type) {
    auto inst = std::make_unique<PhiInst>(phi_type);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_select(std::shared_ptr<Value> condition, 
                                         std::shared_ptr<Value> true_val,
                                         std::shared_ptr<Value> false_val) {
    auto inst = std::make_unique<SelectInst>(condition, true_val, false_val);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // System call support
  std::shared_ptr<Register> create_syscall(uint32_t syscall_number, 
                                          const std::vector<std::shared_ptr<Value>>& args) {
    auto inst = std::make_unique<SyscallInst>(syscall_number, args);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  // Atomic operations with safety validation
  std::shared_ptr<Register> create_atomic_load(Type load_type, std::shared_ptr<Value> ptr,
                                              MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                                              uint32_t alignment = 0) {
    auto inst = std::make_unique<AtomicLoadInst>(load_type, ptr, ordering, alignment);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  void create_atomic_store(std::shared_ptr<Value> value, std::shared_ptr<Value> ptr,
                          MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                          uint32_t alignment = 0) {
    auto inst = std::make_unique<AtomicStoreInst>(value, ptr, ordering, alignment);
    current_block->add_instruction(std::move(inst));
  }
  
  std::shared_ptr<Register> create_atomic_cas(std::shared_ptr<Value> ptr,
                                             std::shared_ptr<Value> expected,
                                             std::shared_ptr<Value> desired,
                                             MemoryOrdering success_ordering = MemoryOrdering::SEQ_CST,
                                             MemoryOrdering failure_ordering = MemoryOrdering::SEQ_CST,
                                             uint32_t alignment = 0) {
    auto inst = std::make_unique<AtomicCASInst>(ptr, expected, desired, 
                                               success_ordering, failure_ordering, alignment);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  std::shared_ptr<Register> create_atomic_rmw(AtomicRMWOp operation, std::shared_ptr<Value> ptr,
                                             std::shared_ptr<Value> operand,
                                             MemoryOrdering ordering = MemoryOrdering::SEQ_CST,
                                             uint32_t alignment = 0) {
    auto inst = std::make_unique<AtomicRMWInst>(operation, ptr, operand, ordering, alignment);
    auto result = inst->result_reg;
    current_block->add_instruction(std::move(inst));
    return result;
  }
  
  void create_atomic_fence(MemoryOrdering ordering = MemoryOrdering::SEQ_CST) {
    auto inst = std::make_unique<AtomicFenceInst>(ordering);
    current_block->add_instruction(std::move(inst));
  }
  
  // Convenience methods for common atomic operations
  std::shared_ptr<Register> create_atomic_fetch_add(std::shared_ptr<Value> ptr, 
                                                   std::shared_ptr<Value> value,
                                                   MemoryOrdering ordering = MemoryOrdering::SEQ_CST) {
    return create_atomic_rmw(AtomicRMWOp::ADD, ptr, value, ordering);
  }
  
  std::shared_ptr<Register> create_atomic_exchange(std::shared_ptr<Value> ptr,
                                                  std::shared_ptr<Value> value,
                                                  MemoryOrdering ordering = MemoryOrdering::SEQ_CST) {
    return create_atomic_rmw(AtomicRMWOp::XCHG, ptr, value, ordering);
  }
  
private:
  BasicBlock* current_block;
};

// IR Dumper and Pretty Printer
class IRDumper {
public:
  enum class DumpFormat {
    HUMAN_READABLE,   // Human-readable format with indentation
    LLVM_STYLE,       // LLVM IR-like format
    COMPACT,          // Compact single-line format
    DEBUG             // Detailed debug format with all metadata
  };
  
  // Dump entire module
  static std::string dump_module(const Module& module, DumpFormat format = DumpFormat::HUMAN_READABLE);
  
  // Dump individual components
  static std::string dump_function(const Function& func, DumpFormat format = DumpFormat::HUMAN_READABLE);
  static std::string dump_basic_block(const BasicBlock& bb, DumpFormat format = DumpFormat::HUMAN_READABLE);
  static std::string dump_instruction(const Instruction& inst, DumpFormat format = DumpFormat::HUMAN_READABLE);
  static std::string dump_value(const Value& val, DumpFormat format = DumpFormat::HUMAN_READABLE);
  static std::string dump_type(const Type& type, DumpFormat format = DumpFormat::HUMAN_READABLE);
  
  // Utility methods
  static std::string opcode_to_string(Opcode op);
  static std::string memory_ordering_to_string(MemoryOrdering ordering);
  static std::string atomic_rmw_op_to_string(AtomicRMWOp op);
  
  // Configuration
  static void set_indent_size(int size) { indent_size = size; }
  static void set_show_types(bool show) { show_types = show; }
  static void set_show_ids(bool show) { show_ids = show; }
  
private:
  static int indent_size;
  static bool show_types;
  static bool show_ids;
  
  static std::string indent(int level);
  static std::string format_operands(const std::vector<std::shared_ptr<Value>>& operands, DumpFormat format);
};

// IR Analysis and Verification Tools
class IRAnalyzer {
public:
  struct ModuleStats {
    uint32_t num_functions = 0;
    uint32_t num_basic_blocks = 0;
    uint32_t num_instructions = 0;
    uint32_t num_values = 0;
    uint32_t total_code_size = 0;
    
    // Instruction type breakdown
    std::map<Opcode, uint32_t> instruction_counts;
    
    // Type usage statistics
    std::map<TypeKind, uint32_t> type_counts;
    
    // Memory operations statistics
    uint32_t load_count = 0;
    uint32_t store_count = 0;
    uint32_t atomic_count = 0;
    uint32_t call_count = 0;
    
    std::string to_string() const;
  };
  
  struct CFGInfo {
    std::map<std::string, std::vector<std::string>> predecessors;
    std::map<std::string, std::vector<std::string>> successors;
    std::vector<std::string> unreachable_blocks;
    std::vector<std::string> blocks_without_terminator;
    bool is_well_formed = true;
    
    std::string to_string() const;
  };
  
  // Analysis functions
  static ModuleStats analyze_module(const Module& module);
  static CFGInfo analyze_control_flow(const Function& func);
  static std::vector<std::string> find_undefined_values(const Function& func);
  static std::vector<std::string> find_type_mismatches(const Function& func);
  static bool is_in_ssa_form(const Function& func);
  
  // Optimization analysis
  static std::vector<std::string> suggest_optimizations(const Function& func);
  static uint32_t estimate_register_pressure(const BasicBlock& bb);
};

} // namespace IR
