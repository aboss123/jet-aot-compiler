#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include "assemblers/x64-codegen.h"

namespace SystemV {

enum class ArgClass { INTEGER, SSE, MEMORY, NO_CLASS };

struct Type {
  enum Kind { VOID, I8, I16, I32, I64, F32, F64, PTR, STRUCT } kind;
  uint32_t size;
  uint32_t align;
  std::vector<Type> fields; // for structs
  
  static Type void_type() { return {VOID, 0, 1, {}}; }
  static Type i32() { return {I32, 4, 4, {}}; }
  static Type i64() { return {I64, 8, 8, {}}; }
  static Type ptr() { return {PTR, 8, 8, {}}; }
  static Type f64() { return {F64, 8, 8, {}}; }
  static Type struct_type(std::vector<Type> fields);
};

struct ArgLocation {
  ArgClass cls;
  nextgen::jet::x64::Register reg;  // if INTEGER/SSE
  int32_t stack_offset;             // if MEMORY
};

struct CallConvention {
  std::vector<ArgLocation> args;
  ArgLocation return_loc;
  bool has_sret;                    // large struct return via hidden pointer
  int32_t stack_size;               // total stack space needed
};

class ABIHandler {
public:
  // Analyze function signature and determine calling convention
  CallConvention analyze_call(const Type& ret_type, const std::vector<Type>& arg_types);
  
  // Emit function prologue with proper stack setup
  void emit_prologue(nextgen::jet::x64::Assembler& a, const CallConvention& cc, uint32_t local_stack = 0);
  
  // Emit function epilogue 
  void emit_epilogue(nextgen::jet::x64::Assembler& a, const CallConvention& cc);
  
  // Emit call sequence: setup args, call, handle return
  void emit_call(nextgen::jet::x64::Assembler& a, const CallConvention& cc, 
                 const std::string& target_name, bool is_external = true);
  
  // Load argument from calling convention location
  void load_argument(nextgen::jet::x64::Assembler& a, const ArgLocation& loc, 
                     nextgen::jet::x64::Register dest_reg);
  
  // Store return value according to calling convention
  void store_return(nextgen::jet::x64::Assembler& a, const ArgLocation& loc, 
                    nextgen::jet::x64::Register src_reg);

private:
  ArgClass classify_type(const Type& type);
  uint32_t round_up(uint32_t value, uint32_t align);
};

} // namespace SystemV
