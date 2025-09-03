#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <map>
#include <string>

namespace nextgen { namespace jet { namespace arm64 {

using ubyte = uint8_t;
using ushort = uint16_t;
using uint = uint32_t;
using ulong = uint64_t;

// ARM64 Registers
enum Register : ubyte {
  // General purpose registers (64-bit)
  X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15,
  X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30, XZR = 31,
  
  // 32-bit views of general purpose registers
  W0 = 32, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15,
  W16, W17, W18, W19, W20, W21, W22, W23, W24, W25, W26, W27, W28, W29, W30, WZR = 63,
  
  // Stack pointer and frame pointer aliases
  SP = 31, FP = X29, LR = X30,
  
  // SIMD/FP registers
  V0 = 64, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15,
  V16, V17, V18, V19, V20, V21, V22, V23, V24, V25, V26, V27, V28, V29, V30, V31,
  
  // Double precision views
  D0 = 96, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12, D13, D14, D15,
  D16, D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31,
  
  // Single precision views
  S0 = 128, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15,
  S16, S17, S18, S19, S20, S21, S22, S23, S24, S25, S26, S27, S28, S29, S30, S31
};

// Condition codes
enum Condition : ubyte {
  EQ = 0,  // Equal
  NE = 1,  // Not equal
  CS = 2,  // Carry set / unsigned higher or same
  CC = 3,  // Carry clear / unsigned lower
  MI = 4,  // Minus / negative
  PL = 5,  // Plus / positive or zero
  VS = 6,  // Overflow
  VC = 7,  // No overflow
  HI = 8,  // Unsigned higher
  LS = 9,  // Unsigned lower or same
  GE = 10, // Signed greater than or equal
  LT = 11, // Signed less than
  GT = 12, // Signed greater than
  LE = 13, // Signed less than or equal
  AL = 14, // Always
  NV = 15  // Never
};

// Immediate types
template<typename T>
struct Imm {
  T value;
  explicit Imm(T v) : value(v) {}
};

using Imm8 = Imm<uint8_t>;
using Imm12 = Imm<uint16_t>; // 12-bit immediate
using Imm16 = Imm<uint16_t>;
using Imm32 = Imm<uint32_t>;
using Imm64 = Imm<uint64_t>;

// Label for jumps and branches
struct Label {
  size_t offset = 0;
  std::vector<size_t> patch_locations;
  bool is_bound = false;
};

// ARM64 Assembler
class Assembler {
public:
  explicit Assembler(size_t initial_size = 4096);
  ~Assembler();
  
  // Get generated code
  ubyte* spill() const { return memory; }
  size_t bytes() const { return used; }
  
  // Label management
  Label create_label(const std::string& name = "");
  void bind(Label& label);
  void emit_data(const std::vector<uint8_t>& data);
  
  // Basic operations
  void nop();
  
  // Data movement
  void mov_imm(Register dst, uint64_t imm);      // Move immediate (various encodings)
  void mov_reg(Register dst, Register src);      // Move register
  void movz(Register dst, Imm16 imm, int shift = 0); // Move wide with zeros
  void movk(Register dst, Imm16 imm, int shift = 0); // Move wide keep
  void adrp(Register dst, Label& label);         // Address of page
  void add_label(Register dst, Register src, Label& label); // Add label offset
  
  // Arithmetic
  void add_imm(Register dst, Register src, Imm12 imm);
  void add_reg(Register dst, Register src1, Register src2);
  void sub_imm(Register dst, Register src, Imm12 imm);
  void sub_reg(Register dst, Register src1, Register src2);
  void mul(Register dst, Register src1, Register src2);
  
  // Logical
  void and_imm(Register dst, Register src, uint64_t imm);
  void and_reg(Register dst, Register src1, Register src2);
  void orr_imm(Register dst, Register src, uint64_t imm);
  void orr_reg(Register dst, Register src1, Register src2);
  void eor_reg(Register dst, Register src1, Register src2);
  
  // Memory operations
  void ldr_imm(Register dst, Register base, int32_t offset = 0);
  void str_imm(Register src, Register base, int32_t offset = 0);
  void ldr_literal(Register dst, Label& label);  // PC-relative load
  
  // Branches
  void b(Label& label);                          // Unconditional branch
  void bl(Label& label);                         // Branch with link
  void b_cond(Condition cond, Label& label);     // Conditional branch
  void cbz(Register reg, Label& label);          // Compare and branch if zero
  void cbnz(Register reg, Label& label);         // Compare and branch if not zero
  
  // Compare
  void cmp_imm(Register src, Imm12 imm);
  void cmp_reg(Register src1, Register src2);
  
  // Division operations
  void udiv(Register dst, Register src1, Register src2);
  void sdiv(Register dst, Register src1, Register src2);
  
  // Shift operations
  void lsl_imm(Register dst, Register src, uint8_t shift);
  void lsr_imm(Register dst, Register src, uint8_t shift);
  void asr_imm(Register dst, Register src, uint8_t shift);
  void lsl_reg(Register dst, Register src1, Register src2);
  void lsr_reg(Register dst, Register src1, Register src2);
  void asr_reg(Register dst, Register src1, Register src2);
  
  // Extended memory operations
  void ldp(Register dst1, Register dst2, Register base, int32_t offset = 0);
  void stp(Register src1, Register src2, Register base, int32_t offset = 0);
  void ldrb(Register dst, Register base, int32_t offset = 0);
  void strb(Register src, Register base, int32_t offset = 0);
  void ldrh(Register dst, Register base, int32_t offset = 0);
  void strh(Register src, Register base, int32_t offset = 0);
  
  // Conditional operations
  void csel(Register dst, Register src1, Register src2, Condition cond);
  void csinc(Register dst, Register src1, Register src2, Condition cond);
  void csinv(Register dst, Register src1, Register src2, Condition cond);
  void csneg(Register dst, Register src1, Register src2, Condition cond);
  
  // Bit manipulation
  void clz(Register dst, Register src);         // Count leading zeros
  void cls(Register dst, Register src);         // Count leading sign bits
  void rbit(Register dst, Register src);        // Reverse bits
  void rev(Register dst, Register src);         // Reverse bytes
  
  // Advanced arithmetic
  void madd(Register dst, Register src1, Register src2, Register addend);
  void msub(Register dst, Register src1, Register src2, Register subtrahend);
  void smull(Register dst, Register src1, Register src2);  // Signed multiply long
  void umull(Register dst, Register src1, Register src2);  // Unsigned multiply long
  
  // Floating point operations (basic set)
  void fmov_imm(Register dst, double imm);      // Move immediate to FP register
  void fmov_reg(Register dst, Register src);    // Move between FP registers
  void fadd_d(Register dst, Register src1, Register src2);
  void fsub_d(Register dst, Register src1, Register src2);
  void fmul_d(Register dst, Register src1, Register src2);
  void fdiv_d(Register dst, Register src1, Register src2);
  void fcmp_d(Register src1, Register src2);
  void fabs_d(Register dst, Register src);
  void fneg_d(Register dst, Register src);
  void fsqrt_d(Register dst, Register src);
  
  // Floating point conversions
  void fcvt_s_d(Register dst, Register src);    // Double to single
  void fcvt_d_s(Register dst, Register src);    // Single to double
  void fcvtzs_x_d(Register dst, Register src);  // Double to signed 64-bit int
  void fcvtzu_x_d(Register dst, Register src);  // Double to unsigned 64-bit int
  void scvtf_d_x(Register dst, Register src);   // Signed 64-bit int to double
  void ucvtf_d_x(Register dst, Register src);   // Unsigned 64-bit int to double
  
  // SIMD/NEON operations (basic set)
  void add_v(Register dst, Register src1, Register src2); // Vector add
  void sub_v(Register dst, Register src1, Register src2); // Vector subtract
  void mul_v(Register dst, Register src1, Register src2); // Vector multiply
  void ld1(Register dst, Register base);                  // Load vector
  void st1(Register src, Register base);                  // Store vector
  
  // Atomic operations
  void ldxr(Register dst, Register addr);       // Load exclusive
  void stxr(Register result, Register src, Register addr); // Store exclusive
  void ldxp(Register dst1, Register dst2, Register addr);   // Load exclusive pair
  void stxp(Register result, Register src1, Register src2, Register addr); // Store exclusive pair
  
  // Atomic RMW operations (ARMv8.1+)
  void ldadd(Register src, Register dst, Register addr);    // Atomic add
  void ldclr(Register src, Register dst, Register addr);    // Atomic clear
  void ldeor(Register src, Register dst, Register addr);    // Atomic XOR
  void ldset(Register src, Register dst, Register addr);    // Atomic set
  void swp(Register src, Register dst, Register addr);      // Atomic swap
  
  // Memory barriers
  void dmb(uint8_t option = 15);               // Data memory barrier
  void dsb(uint8_t option = 15);               // Data synchronization barrier
  void isb(uint8_t option = 15);               // Instruction synchronization barrier
  
  // Load-acquire/Store-release
  void ldar(Register dst, Register addr);       // Load-acquire
  void stlr(Register src, Register addr);       // Store-release
  void ldarb(Register dst, Register addr);      // Load-acquire byte
  void stlrb(Register src, Register addr);      // Store-release byte
  void ldarh(Register dst, Register addr);      // Load-acquire halfword
  void stlrh(Register src, Register addr);      // Store-release halfword
  
  // System calls and special
  void svc(Imm16 imm);                          // Supervisor call (syscall)
  void ret(Register reg = LR);                  // Return
  void brk(Imm16 imm = Imm16(0));              // Breakpoint
  
  // Advanced control flow
  void tbz(Register reg, uint8_t bit, Label& label);    // Test bit and branch if zero
  void tbnz(Register reg, uint8_t bit, Label& label);   // Test bit and branch if not zero
  
  // Labels (already declared above)
  
  // Data emission
  void emit_u32(uint32_t value);
  void emit_u64(uint64_t value);
  void align_to(size_t alignment);
  
private:
  ubyte* memory;
  size_t capacity;
  size_t used;
  
  void ensure_space(size_t bytes);
  void emit32(uint32_t instruction);
  void patch_branch(size_t location, int32_t offset);
  
  // Instruction encoding helpers
  bool is_valid_imm12(uint64_t imm) const;
  uint32_t encode_logical_imm(uint64_t imm, bool is_64bit) const;
  uint32_t reg_code(Register reg) const;
  bool is_64bit_reg(Register reg) const;
};

}}} // namespace nextgen::jet::arm64
