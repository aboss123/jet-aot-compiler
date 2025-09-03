//
// Created by Owner on 9/16/2021.
//

#ifndef JET_X64_ASSEMBLER_H
#define JET_X64_ASSEMBLER_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <unordered_map>
#include <string>

#include <cstdint>
typedef uint8_t  ubyte;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulong;

#define instruction_unary(name) \
void name##b(Register reg); \
void name##w(Register reg); \
void name##d(Register reg); \
void name##q(Register reg);     \
\
void name##b(const MemoryAddress &addr); \
void name##w(const MemoryAddress &addr); \
void name##d(const MemoryAddress &addr); \
void name##q(const MemoryAddress &addr); \

#define instruction_binary(name) \
void name##b(Register dest, Register src);\
void name##w(Register dest, Register src);\
void name##d(Register dest, Register src);\
void name##q(Register dest, Register src);\
\
void name##b(Register dest, const MemoryAddress &src);\
void name##w(Register dest, const MemoryAddress &src);\
void name##d(Register dest, const MemoryAddress &src);\
void name##q(Register dest, const MemoryAddress &src);\
\
void name##b(const MemoryAddress &dest, Register src);\
void name##w(const MemoryAddress &dest, Register src);\
void name##d(const MemoryAddress &dest, Register src);\
void name##q(const MemoryAddress &dest, Register src);\
\
void name##b(Register reg, Imm8 imm); \
void name##w(Register reg, Imm8 imm); \
void name##d(Register reg, Imm8 imm); \
void name##q(Register reg, Imm8 imm); \
\
void name##w(Register reg, Imm16 imm);\
void name##w(Register reg, Imm32 imm);\
\
void name##d(Register reg, Imm16 imm);\
void name##d(Register reg, Imm32 imm);\
\
void name##q(Register reg, Imm16 imm);\
void name##q(Register reg, Imm32 imm);    \

#define instruction_float_binary(name) \
void name##ss(Register dest, Register src); \
void name##ss(Register reg, const MemoryAddress &addr);\
\
void name##sd(Register dest, Register src);\
void name##sd(Register reg, const MemoryAddress &addr);\

namespace nextgen { namespace jet { namespace x64 {
struct Label {
  size_t pos{0};
  bool bound{false};
};

typedef struct Imm8 { ubyte value; }    Imm8;
typedef struct Imm16 { ushort value; }  Imm16;
typedef struct Imm32 { uint value; }    Imm32;
typedef struct Imm64 { ulong value; }   Imm64;

enum Condition {
  Overflow = 0,
  NotOverflow = 1,
  Below       = 2,
  AboveOrEqual = 3,
  Equal     = 4,
  NotEqual  = 5,
  BelowOrEqual = 6,
  Above     = 7,
  Signed    = 8,
  NotSigned = 9,
  LessThan = 0xC,
  LessThanEqual = 0xE,
  GreaterThan   = 0xF,
  GreaterThanEqual = 0xD,
};

enum REX {
  REX_PREFIX = 0b01000000,
  REX_W = 0b00001000,
  REX_R = 0b00000100,
  REX_X = 0b00000010,
  REX_B = 0b00000001
};

enum MOD {
  MOD_INDIRECT = 0b00,
  MOD_DISP8    = 0b01,
  MOD_DISP32   = 0b10,
  MOD_REG      = 0b11
};


enum Register : ubyte {
  AX = 0b000, CX = 0b001, DX = 0b010, BX = 0b011,
  SP = 0b100, BP = 0b101, SI = 0b110, DI = 0b111,

  R8, R9, R10, R11, R12, R13, R14, R15,

  XMM0 = 0b000, XMM1 = 0b001, XMM2 = 0b010, XMM3 = 0b011,
  XMM4 = 0b100, XMM5 = 0b101, XMM6 = 0b110, XMM7 = 0b111,

  XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15
};


enum OperandSize {
  BYTE,
  WORD,
  DWORD,
  QWORD,
  };

// Reference: https://blog.yossarian.net/2020/06/13/How-x86_64-addresses-memory
enum MemoryAddressKind {
  Disp32,               // [disp32]
  Base,                 // [base]
  BaseIndex,            // [base + index]
  BaseDisp32,           // [base + disp32]
  BaseDisp8,            // [base + disp8]
  BaseIndexScale,       // [base + (index * scale)]
  BaseIndexDisp32,      // [base + (index * scale) + disp32]
  BaseIndexDisp8,       // [base + (index * scale) + disp8]
};

enum SibScale : ubyte {
  Scale1 = 0b00,
  Scale2 = 0b01,
  Scale4 = 0b10,
  Scale8 = 0b11
};

struct MemoryAddress {
  bool has_disp8  = false;
  bool has_disp32 = false;
  bool has_sib    = false;
  bool rip_relative = false;

  ubyte    scale = Scale1;
  ubyte    mod   = MOD_INDIRECT;
  int32_t  disp  = 0;

  Register base  = BP;
  Register index = SP;

  // [disp32]
  explicit MemoryAddress(uint disp32);
  explicit MemoryAddress(int32_t disp32, bool rip_relative_in);

  // [base]
  explicit MemoryAddress(Register base);

  // [base + disp8]
  explicit MemoryAddress(Register base, ubyte disp8);

  // [base + disp32]
  explicit MemoryAddress(Register base, uint disp32);

  // [base + (index * scale)]
  explicit MemoryAddress(Register base,
                         Register index,
                         SibScale scale);

  // [base + (index * scale) + disp8]
  explicit MemoryAddress(Register base, Register index, SibScale,
                         ubyte disp8);

  // [base + (index * scale) + disp32]
  explicit MemoryAddress(Register base, Register index, SibScale,
                         uint disp32);
};

class Assembler {
private:
  ubyte *memory;
  size_t used = 0;
  size_t capacity = 0;
  long long stack_depth = 0; // bytes adjusted from entry (push/sub add/pop)
  std::unordered_map<const Label*, std::vector<size_t>> pending_rel32;
  std::unordered_map<std::string, std::vector<size_t>> pending_externals;

  // Writing primitive values to buffer
  void write(ubyte value);
  void write_16(ushort value);
  void write_32(uint value);
  void write_64(ulong value);

  // Write Immediate values to the buffer
  void write(Imm8 imm);
  void write(Imm16 imm);
  void write(Imm32 imm);
  void write(Imm64 imm);
  void patch_32_at(size_t at, int32_t value);
  void ensure(size_t more);

  // Write a memory address given the register destination
  /// Reference: http://www.c-jump.com/CIS77/CPU/x86/lecture.html
  void write_address(const MemoryAddress &addr, Register dest);


  // Some useful overrides when writing multiple values.
  // There is no need for a custom implementation because
  // we don't write more than 4 values at a given time in a row.
  //
  // We depend on the compiler on choosing the correct function for the
  // value that is passed in -- the choice should be clear given distinct
  // parameter values.

  template<typename T, typename K>
  void write(T f, K s);

  template<typename T, typename K, typename L>
  void write(T f, K s, L t);

  template<typename T, typename K, typename L, typename Q>
  void write(T f, K s, L t, Q fr);

  /// Write rex-byte based on a single register for a BYTE operation.
  void rex_optional_r1(Register reg);

  /// Write rex-byte based on a single register for a WORD operation.
  void rex_optional_r2(Register reg);

  /// Write rex-byte based on a single register for a DWORD operation.
  void rex_optional_r3(Register reg);

  /// Writes rex-values for 64-bit argument operations. This applies for
  /// the long-mode of x86-- which is x64. It also integrates rex-prefix
  /// with special register R8-R15.
  void rex_optional_r4(Register reg);

  /// Binary Operation Rex Byte -- BYTE SIZE
  void rex_optional_rr1(Register dest, Register src);

  /// Binary Operation Rex Byte -- WORD SIZE
  void rex_optional_rr2(Register dest, Register src);


  /// Binary Operation Rex Byte -- DWORD SIZE
  void rex_optional_rr3(Register dest, Register src);

  /// Binary Operation Rex Byte -- QWORD SIZE
  void rex_optional_rr4(Register dest, Register src);

  /// Memory Operation Rex Byte -- BYTE SIZE
  void rex_optional_rm1(Register reg, const MemoryAddress &addr);

  /// Memory Operation Rex Byte -- WORD SIZE
  void rex_optional_rm2(Register reg, const MemoryAddress &addr);

  /// Memory Operation Rex Byte -- DWORD SIZE
  void rex_optional_rm3(Register reg, const MemoryAddress &addr);

  /// Memory Operation Rex Byte -- QWORD SIZE
  void rex_optional_rm4(Register reg, const MemoryAddress &addr);


public:

  explicit Assembler(size_t size);
  explicit Assembler(size_t size, bool executable);

  /// Spill the memory buffer containing machine code bytes written
  ubyte *spill() const;

  /// The number of bytes that have been written to the memory buffer
  ulong bytes() const;

  /// Get a given byte that has been generated by the assembler
  ubyte operator[](size_t index) { return memory[index]; }

  void popq(Register reg);
  void popw(Register reg);

  void pushq(Register reg);
  void pushw(Register reg);

  void movb(Register reg, Imm8 imm);
  template<typename Imm>
  void movw(Register reg, Imm imm);
  template<typename Imm>
  void movd(Register reg, Imm imm);
  template<typename Imm>
  void movq(Register reg, Imm imm);
  void movq(Register reg, Imm64 imm);

  void movb(Register reg, const MemoryAddress &addr);
  void movw(Register reg, const MemoryAddress &addr);
  void movd(Register reg, const MemoryAddress &addr);
  void movq(Register reg, const MemoryAddress &addr);
  // Memory immediate moves
  void movb(const MemoryAddress &dest, Imm8 imm);
  void movw(const MemoryAddress &dest, Imm16 imm);
  void movd(const MemoryAddress &dest, Imm32 imm);
  void movq(const MemoryAddress &dest, Imm32 imm); // sign-extended to 64-bit

  // Register to memory store operations
  void movb(const MemoryAddress &dest, Register src);
  void movw(const MemoryAddress &dest, Register src);
  void movd(const MemoryAddress &dest, Register src);
  void movq(const MemoryAddress &dest, Register src);

  void movb(Register dest, Register src);
  void movw(Register dest, Register src);
  void movd(Register dest, Register src);
  void movq(Register dest, Register src);

  void shlb(Register dest, Imm8 count);
  void shlw(Register dest, Imm8 count);
  void shld(Register dest, Imm8 count);
  void shlq(Register dest, Imm8 count);

  void shlb(Register dest);
  void shlw(Register dest);
  void shld(Register dest);
  void shlq(Register dest);

  void shrb(Register dest, Imm8 count);
  void shrw(Register dest, Imm8 count);
  void shrd(Register dest, Imm8 count);
  void shrq(Register dest, Imm8 count);
  // Shift by CL
  void shld_cl(Register dest);  // shl dword by CL
  void shlq_cl(Register dest);  // shl qword by CL
  void shrd_cl(Register dest);  // shr dword by CL
  void shrq_cl(Register dest);  // shr qword by CL
  void sard_cl(Register dest);  // sar dword by CL
  void sarq_cl(Register dest);  // sar qword by CL

  void jmp(Imm8 rel8);
  void jmp(Imm16 rel16);
  void jmp(Imm32 rel32);

  void jmpw(Register reg);
  void jmpq(Register reg);

  void jump_cond(Condition cond, Imm8 rel8);
  void jump_cond(Condition cond, Imm16 rel16);
  void jump_cond(Condition cond, Imm32 rel32);

  // NOTE: imul instruction order for rex is (src, dest), yes, this is
  // correct.
  void imulw(Register dest, Register src);
  void imuld(Register dest, Register src);
  void imulq(Register dest, Register src);

  void lea(Register reg, const MemoryAddress &addr, OperandSize size);

  void movss(Register dest, Register src);
  void movss(Register dest, const MemoryAddress &addr);
  void movss(const MemoryAddress& dest, Register src);

  instruction_binary(add);
  instruction_binary(sub);
  instruction_binary(and);
  instruction_binary(cmp);
  instruction_binary(xor);
  instruction_binary(or);

  instruction_float_binary(add);
  instruction_float_binary(sub);
  instruction_float_binary(div);
  instruction_float_binary(mul);

  instruction_unary(inc);
  instruction_unary(dec);
  instruction_unary(not);
  instruction_unary(mul);
  instruction_unary(neg);
  instruction_unary(div);
  instruction_unary(idiv);

  void ret();
  
  // Labels and branch patching (always emits rel32; we patch later)
  void bind(Label &label);
  void jmp(Label &label);
  void jump_cond(Condition cond, Label &label);
  // RIP-relative label load (load from [rip+disp32] to reg), patched on bind
  void movd_rip_label(Register dest, Label &label);
  void leaq_rip_label(Register dest, Label &label);

  // Calls
  void call(Label &label);             // call rel32 to label
  void call_external(const char *name); // record external symbol to patch later
  void patch_external(const char *name, void *addr);
  void call_aligned(Label &label);
  void call_external_aligned(const char *name);
  void call_absolute(void *addr);
  void call_absolute_aligned(void *addr);

  // Prologue/Epilogue and callee-saved helpers (SysV)
  void function_prologue(uint32_t stack_bytes);
  void function_epilogue();
  void save_callee_saved();   // saves rbx, r12-r15
  void restore_callee_saved();

  // Buffer finalize
  void *make_executable_copy();
  
  // Constant/data pool helpers
  void place_label(Label &label) { bind(label); }
  void emit_data32(uint value) { emit_u32(value); }
  void emit_data64(ulong value) { emit_u64(value); }
  
  // Data emission helpers (public interface)
  void emit_u8(ubyte v) { write(v); }
  void emit_u16(ushort v) { write_16(v); }
  void emit_u32(uint v) { write_32(v); }
  void emit_u64(ulong v) { write_64(v); }
  void align_to(size_t n);
  
  // Callee-saved register management
  void save_callee_saved_registers();
  void restore_callee_saved_registers();
  
  // === Additional Essential Instructions ===
  
  // Stack frame management
  void enter(Imm16 frameSize, Imm8 nestingLevel);
  void leave();
  
  // Function calls
  void call(Imm32 rel32);
  void callq(Register reg);
  void callq(const MemoryAddress &addr);
  
  // Test instruction (like AND but only sets flags)
  void testb(Register reg1, Register reg2);
  void testw(Register reg1, Register reg2);
  void testd(Register reg1, Register reg2);
  void testq(Register reg1, Register reg2);
  
  void testb(Register reg, Imm8 imm);
  void testw(Register reg, Imm16 imm);
  void testd(Register reg, Imm32 imm);
  void testq(Register reg, Imm32 imm);
  
  // Arithmetic with carry
  instruction_binary(adc);  // Add with carry
  instruction_binary(sbb);  // Subtract with borrow
  
  // Zero/Sign extend moves
  void movzxb(Register dest, Register src);   // Zero extend byte to word/dword/qword
  void movzxw(Register dest, Register src);   // Zero extend word to dword/qword
  void movsxb(Register dest, Register src);   // Sign extend byte to word/dword/qword
  void movsxw(Register dest, Register src);   // Sign extend word to dword/qword
  void movsxd(Register dest, Register src);   // Sign extend dword to qword
  // Memory forms
  void movzxb(Register dest, const MemoryAddress &src);
  void movzxw(Register dest, const MemoryAddress &src);
  void movsxb(Register dest, const MemoryAddress &src);
  void movsxw(Register dest, const MemoryAddress &src);
  void movsxd(Register dest, const MemoryAddress &src);
  
  // Bit manipulation
  void btd(Register reg, Imm8 bit);           // Bit test
  void btq(Register reg, Imm8 bit);
  void btsd(Register reg, Imm8 bit);          // Bit test and set
  void btsq(Register reg, Imm8 bit);
  void btrd(Register reg, Imm8 bit);          // Bit test and reset
  void btrq(Register reg, Imm8 bit);
  
  // Bit scan
  void bsfw(Register dest, Register src);     // Bit scan forward
  void bsfd(Register dest, Register src);
  void bsfq(Register dest, Register src);
  void bsrw(Register dest, Register src);     // Bit scan reverse
  void bsrd(Register dest, Register src);
  void bsrq(Register dest, Register src);
  
  // Rotate instructions
  void rolb(Register reg, Imm8 count);
  void rolw(Register reg, Imm8 count);
  void rold(Register reg, Imm8 count);
  void rolq(Register reg, Imm8 count);
  
  void rorb(Register reg, Imm8 count);
  void rorw(Register reg, Imm8 count);
  void rord(Register reg, Imm8 count);
  void rorq(Register reg, Imm8 count);
  // Rotate by CL
  void rold_cl(Register reg);
  void rolq_cl(Register reg);
  void rord_cl(Register reg);
  void rorq_cl(Register reg);
  
  // Conditional set instructions
  void setcc(Condition cond, Register reg);   // Set byte on condition
  void setcc(Condition cond, const MemoryAddress &addr);
  
  // String operations
  void rep_movsb();                           // Repeat move string byte
  void rep_movsw();                           // Repeat move string word
  void rep_movsd();                           // Repeat move string dword
  void rep_movsq();                           // Repeat move string qword
  
  void rep_stosb();                           // Repeat store string byte
  void rep_stosw();                           // Repeat store string word
  void rep_stosd();                           // Repeat store string dword
  void rep_stosq();                           // Repeat store string qword
  
  // Utility instructions
  void nop();                                 // No operation
  void int3();                                // Software breakpoint
  void hlt();                                 // Halt processor
  void cld();                                 // Clear direction flag
  void std();                                 // Set direction flag
  void syscall();                             // Syscall instruction (0F 05)
  
  // Sign-extend accumulator
  void cdq();  // EDX:EAX from EAX
  void cqo();  // RDX:RAX from RAX
  
  // Conditional moves
  void cmovcc(Condition cond, Register dest, Register src);
  void cmovcc(Condition cond, Register dest, const MemoryAddress &src);
  
  // Additional floating point
  void comisd(Register reg1, Register reg2);  // Compare scalar double
  void comiss(Register reg1, Register reg2);  // Compare scalar single
  void ucomisd(Register reg1, Register reg2); // Unordered compare scalar double
  void ucomiss(Register reg1, Register reg2); // Unordered compare scalar single
  
  void cvtsi2sd(Register dest, Register src); // Convert signed int to double
  void cvtsi2ss(Register dest, Register src); // Convert signed int to single
  void cvtsd2si(Register dest, Register src); // Convert double to signed int
  void cvtss2si(Register dest, Register src); // Convert single to signed int
  void cvtsd2ss(Register dest, Register src); // Convert double to single
  void cvtss2sd(Register dest, Register src); // Convert single to double
  
  // More shift operations
  void sarb(Register dest, Imm8 count);       // Arithmetic right shift
  void sarw(Register dest, Imm8 count);
  void sard(Register dest, Imm8 count);
  void sarq(Register dest, Imm8 count);
  
  void sarb(Register dest);                   // Arithmetic right shift by 1
  void sarw(Register dest);
  void sard(Register dest);
  void sarq(Register dest);
  
  // Atomic operations
  void lock();                                // LOCK prefix for next instruction
  
  // Atomic exchange
  void xchgb(Register reg, const MemoryAddress &addr);  // Atomic exchange byte
  void xchgw(Register reg, const MemoryAddress &addr);  // Atomic exchange word
  void xchgd(Register reg, const MemoryAddress &addr);  // Atomic exchange dword
  void xchgq(Register reg, const MemoryAddress &addr);  // Atomic exchange qword
  void xchg(Register reg1, Register reg2);              // Exchange registers
  
  // Atomic compare and exchange
  void cmpxchgb(Register reg, const MemoryAddress &addr);  // Compare and exchange byte
  void cmpxchgw(Register reg, const MemoryAddress &addr);  // Compare and exchange word
  void cmpxchgd(Register reg, const MemoryAddress &addr);  // Compare and exchange dword
  void cmpxchgq(Register reg, const MemoryAddress &addr);  // Compare and exchange qword
  
  // Double-width compare and exchange
  void cmpxchg8b(const MemoryAddress &addr);   // Compare and exchange 8 bytes
  void cmpxchg16b(const MemoryAddress &addr);  // Compare and exchange 16 bytes
  
  // Atomic read-modify-write operations (with LOCK prefix)
  void lock_addb(Imm8 imm, const MemoryAddress &addr);    // Atomic add byte
  void lock_addw(Imm16 imm, const MemoryAddress &addr);   // Atomic add word
  void lock_addd(Imm32 imm, const MemoryAddress &addr);   // Atomic add dword
  void lock_addq(Imm32 imm, const MemoryAddress &addr);   // Atomic add qword
  void lock_add(Register reg, const MemoryAddress &addr); // Atomic add register
  
  void lock_subb(Imm8 imm, const MemoryAddress &addr);    // Atomic sub byte
  void lock_subw(Imm16 imm, const MemoryAddress &addr);   // Atomic sub word
  void lock_subd(Imm32 imm, const MemoryAddress &addr);   // Atomic sub dword
  void lock_subq(Imm32 imm, const MemoryAddress &addr);   // Atomic sub qword
  void lock_sub(Register reg, const MemoryAddress &addr); // Atomic sub register
  
  void lock_andb(Imm8 imm, const MemoryAddress &addr);    // Atomic and byte
  void lock_andw(Imm16 imm, const MemoryAddress &addr);   // Atomic and word
  void lock_andd(Imm32 imm, const MemoryAddress &addr);   // Atomic and dword
  void lock_andq(Imm32 imm, const MemoryAddress &addr);   // Atomic and qword
  void lock_and(Register reg, const MemoryAddress &addr); // Atomic and register
  
  void lock_orb(Imm8 imm, const MemoryAddress &addr);     // Atomic or byte
  void lock_orw(Imm16 imm, const MemoryAddress &addr);    // Atomic or word
  void lock_ord(Imm32 imm, const MemoryAddress &addr);    // Atomic or dword
  void lock_orq(Imm32 imm, const MemoryAddress &addr);    // Atomic or qword
  void lock_or(Register reg, const MemoryAddress &addr);  // Atomic or register
  
  void lock_xorb(Imm8 imm, const MemoryAddress &addr);    // Atomic xor byte
  void lock_xorw(Imm16 imm, const MemoryAddress &addr);   // Atomic xor word
  void lock_xord(Imm32 imm, const MemoryAddress &addr);   // Atomic xor dword
  void lock_xorq(Imm32 imm, const MemoryAddress &addr);   // Atomic xor qword
  void lock_xor(Register reg, const MemoryAddress &addr); // Atomic xor register
  
  // Memory barriers and fences
  void mfence();                              // Memory fence (load + store barrier)
  void sfence();                              // Store fence (store barrier)
  void lfence();                              // Load fence (load barrier)
  
  // Pause instruction for spin loops
  void pause();                               // Hint for spin-wait loops
};
}}}

#endif //JET_X64_ASSEMBLER_H


