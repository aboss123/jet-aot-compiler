#include "arm64-codegen.h"
#include <sys/mman.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>

using namespace nextgen::jet::arm64;

Assembler::Assembler(size_t initial_size) : capacity(initial_size), used(0) {
  memory = static_cast<ubyte*>(mmap(nullptr, capacity, 
                                   PROT_READ | PROT_WRITE | PROT_EXEC,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (memory == MAP_FAILED) {
    memory = static_cast<ubyte*>(malloc(capacity));
  }
}

Assembler::~Assembler() {
  if (memory) {
    munmap(memory, capacity);
  }
}

void Assembler::ensure_space(size_t bytes) {
  if (used + bytes > capacity) {
    capacity = std::max(capacity * 2, used + bytes);
    // For simplicity, just use malloc/realloc for growing
    ubyte* new_mem = static_cast<ubyte*>(malloc(capacity));
    if (memory) {
      memcpy(new_mem, memory, used);
      munmap(memory, used);
    }
    memory = new_mem;
  }
}

void Assembler::emit32(uint32_t instruction) {
  ensure_space(4);
  *reinterpret_cast<uint32_t*>(memory + used) = instruction;
  used += 4;
}

uint32_t Assembler::reg_code(Register reg) const {
  if (reg >= X0 && reg <= XZR) return reg - X0;
  if (reg >= W0 && reg <= WZR) return reg - W0;
  if (reg >= V0 && reg <= V31) return reg - V0;
  if (reg >= D0 && reg <= D31) return reg - D0;
  if (reg >= S0 && reg <= S31) return reg - S0;
  return 31; // Default to XZR/WZR
}

bool Assembler::is_64bit_reg(Register reg) const {
  return (reg >= X0 && reg <= XZR) || (reg >= V0 && reg <= V31);
}

void Assembler::nop() {
  emit32(0xD503201F); // NOP
}

void Assembler::udiv(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1AC00800; // UDIV W
  if (is_64bit) inst |= 0x80000000; // UDIV X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::sdiv(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1AC00C00; // SDIV W
  if (is_64bit) inst |= 0x80000000; // SDIV X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::lsl_imm(Register dst, Register src, uint8_t shift) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x53000000; // LSL W (UBFM)
  if (is_64bit) inst |= 0x80400000; // LSL X
  
  uint32_t width = is_64bit ? 64 : 32;
  uint32_t r = (width - shift) % width;
  uint32_t s = width - 1 - shift;
  
  inst |= (r << 16) | (s << 10) | (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::lsr_imm(Register dst, Register src, uint8_t shift) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x53000000; // LSR W (UBFM)
  if (is_64bit) inst |= 0x80400000; // LSR X
  
  uint32_t width = is_64bit ? 64 : 32;
  inst |= (shift << 16) | ((width - 1) << 10) | (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::asr_imm(Register dst, Register src, uint8_t shift) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x13000000; // ASR W (SBFM)
  if (is_64bit) inst |= 0x80400000; // ASR X
  
  uint32_t width = is_64bit ? 64 : 32;
  inst |= (shift << 16) | ((width - 1) << 10) | (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::lsl_reg(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1AC02000; // LSLV W
  if (is_64bit) inst |= 0x80000000; // LSLV X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::lsr_reg(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1AC02400; // LSRV W
  if (is_64bit) inst |= 0x80000000; // LSRV X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::asr_reg(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1AC02800; // ASRV W
  if (is_64bit) inst |= 0x80000000; // ASRV X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::mov_imm(Register dst, uint64_t imm) {
  // Use MOVZ/MOVK sequence for large immediates
  uint32_t dst_code = reg_code(dst);
  bool is_64bit = is_64bit_reg(dst);
  
  if (imm <= 0xFFFF) {
    // Single MOVZ
    uint32_t inst = 0x52800000; // MOVZ W
    if (is_64bit) inst |= 0x80000000; // MOVZ X
    inst |= (imm << 5) | dst_code;
    emit32(inst);
  } else {
    // Multi-instruction sequence
    movz(dst, Imm16(imm & 0xFFFF), 0);
    if (imm > 0xFFFF) {
      movk(dst, Imm16((imm >> 16) & 0xFFFF), 16);
    }
    if (is_64bit && imm > 0xFFFFFFFF) {
      movk(dst, Imm16((imm >> 32) & 0xFFFF), 32);
      if (imm > 0xFFFFFFFFFFFF) {
        movk(dst, Imm16((imm >> 48) & 0xFFFF), 48);
      }
    }
  }
}

void Assembler::mov_reg(Register dst, Register src) {
  // Handle SP specially - use ADD dst, src, #0 instead of ORR
  if (src == SP || dst == SP) {
    add_imm(dst, src, Imm12{0});
    return;
  }
  
  // ORR dst, XZR, src (equivalent to MOV for non-SP registers)
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x2A000000; // ORR W
  if (is_64bit) inst |= 0x80000000; // ORR X
  inst |= (src_code << 16) | (31 << 5) | dst_code; // src, XZR, dst
  emit32(inst);
}

void Assembler::movz(Register dst, Imm16 imm, int shift) {
  uint32_t dst_code = reg_code(dst);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x52800000; // MOVZ W
  if (is_64bit) inst |= 0x80000000; // MOVZ X
  inst |= ((shift / 16) << 21) | (imm.value << 5) | dst_code;
  emit32(inst);
}

void Assembler::movk(Register dst, Imm16 imm, int shift) {
  uint32_t dst_code = reg_code(dst);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x72800000; // MOVK W
  if (is_64bit) inst |= 0x80000000; // MOVK X
  inst |= ((shift / 16) << 21) | (imm.value << 5) | dst_code;
  emit32(inst);
}

Label Assembler::create_label(const std::string& name) {
  Label label;
  label.is_bound = false;
  return label;
}

void Assembler::bind(Label& label) {
  label.offset = used;
  label.is_bound = true;
  
  // Patch all references to this label
  for (size_t patch_loc : label.patch_locations) {
    // Patch the instruction at patch_loc with the actual offset
    int32_t relative_offset = static_cast<int32_t>(label.offset - patch_loc);
    // For now, assume all patches are for branch instructions
    uint32_t* inst_ptr = reinterpret_cast<uint32_t*>(memory + patch_loc);
    *inst_ptr |= (relative_offset >> 2) & 0x3FFFFFF; // 26-bit signed offset
  }
  label.patch_locations.clear();
}

void Assembler::adrp(Register dst, Label& label) {
  uint32_t dst_code = reg_code(dst);
  uint32_t inst = 0x90000000; // ADRP
  inst |= dst_code;
  
  if (label.is_bound) {
    // Calculate page offset
    uint64_t current_page = (used + 4) & ~0xFFFULL;
    uint64_t target_page = label.offset & ~0xFFFULL;
    int64_t page_diff = static_cast<int64_t>(target_page - current_page) >> 12;
    
    // Encode immediate (21-bit signed)
    uint32_t imm_lo = (page_diff & 0x3) << 29;
    uint32_t imm_hi = ((page_diff >> 2) & 0x7FFFF) << 5;
    inst |= imm_lo | imm_hi;
  } else {
    // Add patch location for later resolution
    label.patch_locations.push_back(used);
  }
  
  emit32(inst);
}

void Assembler::add_label(Register dst, Register src, Label& label) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  uint32_t inst = 0x91000000; // ADD (immediate) X
  inst |= (src_code << 5) | dst_code;
  
  if (label.is_bound) {
    // Calculate page offset (low 12 bits)
    uint32_t page_offset = label.offset & 0xFFF;
    inst |= (page_offset << 10);
  } else {
    // Add patch location for later resolution
    label.patch_locations.push_back(used);
  }
  
  emit32(inst);
}

void Assembler::emit_data(const std::vector<uint8_t>& data) {
  ensure_space(data.size());
  std::memcpy(memory + used, data.data(), data.size());
  used += data.size();
}

void Assembler::add_imm(Register dst, Register src, Imm12 imm) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x11000000; // ADD W
  if (is_64bit) inst |= 0x80000000; // ADD X
  inst |= (imm.value << 10) | (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::add_reg(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x0B000000; // ADD W
  if (is_64bit) inst |= 0x80000000; // ADD X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::sub_imm(Register dst, Register src, Imm12 imm) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x51000000; // SUB W
  if (is_64bit) inst |= 0x80000000; // SUB X
  inst |= (imm.value << 10) | (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::sub_reg(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x4B000000; // SUB W
  if (is_64bit) inst |= 0x80000000; // SUB X
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::mul(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1B007C00; // MADD W (with XZR as addend = MUL)
  if (is_64bit) inst |= 0x80000000; // MADD X
  inst |= (src2_code << 16) | (31 << 10) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::ldr_imm(Register dst, Register base, int32_t offset) {
  uint32_t dst_code = reg_code(dst);
  uint32_t base_code = reg_code(base);
  bool is_64bit = is_64bit_reg(dst);
  
  // Use post-index addressing for simplicity
  uint32_t inst = 0xB8400000; // LDR W
  if (is_64bit) inst |= 0x40000000; // LDR X
  
  if (offset >= -256 && offset <= 255) {
    // 9-bit signed immediate, post-index
    inst |= ((offset & 0x1FF) << 12) | (base_code << 5) | dst_code;
  } else {
    // For larger offsets, would need different addressing mode
    // For now, just use the 9-bit form
    inst |= ((offset & 0x1FF) << 12) | (base_code << 5) | dst_code;
  }
  emit32(inst);
}

void Assembler::str_imm(Register src, Register base, int32_t offset) {
  uint32_t src_code = reg_code(src);
  uint32_t base_code = reg_code(base);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8000000; // STR W
  if (is_64bit) inst |= 0x40000000; // STR X
  
  if (offset >= -256 && offset <= 255) {
    inst |= ((offset & 0x1FF) << 12) | (base_code << 5) | src_code;
  } else {
    inst |= ((offset & 0x1FF) << 12) | (base_code << 5) | src_code;
  }
  emit32(inst);
}

void Assembler::cmp_imm(Register src, Imm12 imm) {
  // CMP is SUB with XZR as destination
  uint32_t src_code = reg_code(src);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0x7100001F; // CMP W (SUBS WZR, src, imm)
  if (is_64bit) inst |= 0x80000000; // CMP X
  inst |= (imm.value << 10) | (src_code << 5);
  emit32(inst);
}

void Assembler::cmp_reg(Register src1, Register src2) {
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(src1);
  
  uint32_t inst = 0x6B00001F; // CMP W (SUBS WZR, src1, src2)
  if (is_64bit) inst |= 0x80000000; // CMP X
  inst |= (src2_code << 16) | (src1_code << 5);
  emit32(inst);
}

void Assembler::b(Label& label) {
  if (label.is_bound) {
    int32_t offset = static_cast<int32_t>(label.offset - used) / 4;
    uint32_t inst = 0x14000000 | (offset & 0x3FFFFFF);
    emit32(inst);
  } else {
    label.patch_locations.push_back(used);
    emit32(0x14000000); // B with 0 offset, will be patched
  }
}

void Assembler::bl(Label& label) {
  if (label.is_bound) {
    int32_t offset = static_cast<int32_t>(label.offset - used) / 4;
    uint32_t inst = 0x94000000 | (offset & 0x3FFFFFF);
    emit32(inst);
  } else {
    label.patch_locations.push_back(used);
    emit32(0x94000000); // BL with 0 offset, will be patched
  }
}

void Assembler::b_cond(Condition cond, Label& label) {
  if (label.is_bound) {
    int32_t offset = static_cast<int32_t>(label.offset - used) / 4;
    uint32_t inst = 0x54000000 | ((offset & 0x7FFFF) << 5) | cond;
    emit32(inst);
  } else {
    label.patch_locations.push_back(used);
    emit32(0x54000000 | cond); // B.cond with 0 offset, will be patched
  }
}

void Assembler::cbz(Register reg, Label& label) {
  uint32_t reg_num = reg_code(reg);
  bool is_64bit = is_64bit_reg(reg);
  
  if (label.is_bound) {
    int32_t offset = static_cast<int32_t>(label.offset - used) / 4;
    uint32_t inst = 0x34000000; // CBZ W
    if (is_64bit) inst |= 0x80000000; // CBZ X
    inst |= ((offset & 0x7FFFF) << 5) | reg_num;
    emit32(inst);
  } else {
    label.patch_locations.push_back(used);
    uint32_t inst = 0x34000000; // CBZ W
    if (is_64bit) inst |= 0x80000000; // CBZ X
    inst |= reg_num;
    emit32(inst);
  }
}

void Assembler::cbnz(Register reg, Label& label) {
  uint32_t reg_num = reg_code(reg);
  bool is_64bit = is_64bit_reg(reg);
  
  if (label.is_bound) {
    int32_t offset = static_cast<int32_t>(label.offset - used) / 4;
    uint32_t inst = 0x35000000; // CBNZ W
    if (is_64bit) inst |= 0x80000000; // CBNZ X
    inst |= ((offset & 0x7FFFF) << 5) | reg_num;
    emit32(inst);
  } else {
    label.patch_locations.push_back(used);
    uint32_t inst = 0x35000000; // CBNZ W
    if (is_64bit) inst |= 0x80000000; // CBNZ X
    inst |= reg_num;
    emit32(inst);
  }
}

void Assembler::ret(Register reg) {
  uint32_t reg_num = reg_code(reg);
  uint32_t inst = 0xD65F0000 | (reg_num << 5);
  emit32(inst);
}

void Assembler::svc(Imm16 imm) {
  uint32_t inst = 0xD4000001 | (imm.value << 5);
  emit32(inst);
}

// Extended memory operations
void Assembler::ldp(Register dst1, Register dst2, Register base, int32_t offset) {
  uint32_t dst1_code = reg_code(dst1);
  uint32_t dst2_code = reg_code(dst2);
  uint32_t base_code = reg_code(base);
  bool is_64bit = is_64bit_reg(dst1);
  
  uint32_t inst = 0x29400000; // LDP W
  if (is_64bit) inst |= 0x80000000; // LDP X
  
  // Offset is in multiples of register size (4 for W, 8 for X)
  int32_t scaled_offset = offset / (is_64bit ? 8 : 4);
  inst |= ((scaled_offset & 0x7F) << 15) | (dst2_code << 10) | (base_code << 5) | dst1_code;
  emit32(inst);
}

void Assembler::stp(Register src1, Register src2, Register base, int32_t offset) {
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  uint32_t base_code = reg_code(base);
  bool is_64bit = is_64bit_reg(src1);
  
  uint32_t inst = 0x29000000; // STP W
  if (is_64bit) inst |= 0x80000000; // STP X
  
  int32_t scaled_offset = offset / (is_64bit ? 8 : 4);
  inst |= ((scaled_offset & 0x7F) << 15) | (src2_code << 10) | (base_code << 5) | src1_code;
  emit32(inst);
}

void Assembler::ldrb(Register dst, Register base, int32_t offset) {
  uint32_t dst_code = reg_code(dst);
  uint32_t base_code = reg_code(base);
  
  uint32_t inst = 0x39400000; // LDRB
  if (offset >= 0 && offset <= 4095) {
    inst |= (offset << 10) | (base_code << 5) | dst_code;
  } else {
    // Use post-index for larger offsets
    inst = 0x38400400 | ((offset & 0x1FF) << 12) | (base_code << 5) | dst_code;
  }
  emit32(inst);
}

void Assembler::strb(Register src, Register base, int32_t offset) {
  uint32_t src_code = reg_code(src);
  uint32_t base_code = reg_code(base);
  
  uint32_t inst = 0x39000000; // STRB
  if (offset >= 0 && offset <= 4095) {
    inst |= (offset << 10) | (base_code << 5) | src_code;
  } else {
    inst = 0x38000400 | ((offset & 0x1FF) << 12) | (base_code << 5) | src_code;
  }
  emit32(inst);
}

void Assembler::ldrh(Register dst, Register base, int32_t offset) {
  uint32_t dst_code = reg_code(dst);
  uint32_t base_code = reg_code(base);
  
  uint32_t inst = 0x79400000; // LDRH
  if (offset >= 0 && offset <= 8190 && (offset & 1) == 0) {
    inst |= ((offset >> 1) << 10) | (base_code << 5) | dst_code;
  } else {
    inst = 0x78400400 | ((offset & 0x1FF) << 12) | (base_code << 5) | dst_code;
  }
  emit32(inst);
}

void Assembler::strh(Register src, Register base, int32_t offset) {
  uint32_t src_code = reg_code(src);
  uint32_t base_code = reg_code(base);
  
  uint32_t inst = 0x79000000; // STRH
  if (offset >= 0 && offset <= 8190 && (offset & 1) == 0) {
    inst |= ((offset >> 1) << 10) | (base_code << 5) | src_code;
  } else {
    inst = 0x78000400 | ((offset & 0x1FF) << 12) | (base_code << 5) | src_code;
  }
  emit32(inst);
}

// Conditional operations
void Assembler::csel(Register dst, Register src1, Register src2, Condition cond) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x1A800000; // CSEL W
  if (is_64bit) inst |= 0x80000000; // CSEL X
  inst |= (src2_code << 16) | (cond << 12) | (src1_code << 5) | dst_code;
  emit32(inst);
}

// Floating point operations
void Assembler::fmov_imm(Register dst, double imm) {
  uint32_t dst_code = reg_code(dst);
  
  // For simplicity, only support 0.0 immediate
  if (imm == 0.0) {
    uint32_t inst = 0x1E601000; // FMOV D, #0.0
    inst |= dst_code;
    emit32(inst);
  } else {
    // Would need complex immediate encoding for other values
    // For now, just emit 0.0
    uint32_t inst = 0x1E601000;
    inst |= dst_code;
    emit32(inst);
  }
}

void Assembler::fmov_reg(Register dst, Register src) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src_code = reg_code(src);
  
  uint32_t inst = 0x1E604000; // FMOV D, D
  inst |= (src_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::fadd_d(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  
  uint32_t inst = 0x1E602800; // FADD D
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::fsub_d(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  
  uint32_t inst = 0x1E603800; // FSUB D
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::fmul_d(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  
  uint32_t inst = 0x1E600800; // FMUL D
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::fdiv_d(Register dst, Register src1, Register src2) {
  uint32_t dst_code = reg_code(dst);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  
  uint32_t inst = 0x1E601800; // FDIV D
  inst |= (src2_code << 16) | (src1_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::fcmp_d(Register src1, Register src2) {
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  
  uint32_t inst = 0x1E602000; // FCMP D
  inst |= (src2_code << 16) | (src1_code << 5);
  emit32(inst);
}

// Atomic operations implementation
void Assembler::ldxr(Register dst, Register addr) {
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x885F7C00; // LDXR W
  if (is_64bit) inst |= 0x40000000; // LDXR X
  inst |= (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::stxr(Register result, Register src, Register addr) {
  uint32_t result_code = reg_code(result);
  uint32_t src_code = reg_code(src);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0x88007C00; // STXR W
  if (is_64bit) inst |= 0x40000000; // STXR X
  inst |= (result_code << 16) | (addr_code << 5) | src_code;
  emit32(inst);
}

void Assembler::ldxp(Register dst1, Register dst2, Register addr) {
  uint32_t dst1_code = reg_code(dst1);
  uint32_t dst2_code = reg_code(dst2);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(dst1);
  
  uint32_t inst = 0x887F0000; // LDXP W
  if (is_64bit) inst |= 0x80000000; // LDXP X
  inst |= (dst2_code << 10) | (addr_code << 5) | dst1_code;
  emit32(inst);
}

void Assembler::stxp(Register result, Register src1, Register src2, Register addr) {
  uint32_t result_code = reg_code(result);
  uint32_t src1_code = reg_code(src1);
  uint32_t src2_code = reg_code(src2);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src1);
  
  uint32_t inst = 0x88200000; // STXP W
  if (is_64bit) inst |= 0x80000000; // STXP X
  inst |= (result_code << 16) | (src2_code << 10) | (addr_code << 5) | src1_code;
  emit32(inst);
}

void Assembler::ldadd(Register src, Register dst, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8200000; // LDADD W
  if (is_64bit) inst |= 0x40000000; // LDADD X
  inst |= (src_code << 16) | (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::ldclr(Register src, Register dst, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8201000; // LDCLR W
  if (is_64bit) inst |= 0x40000000; // LDCLR X
  inst |= (src_code << 16) | (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::ldeor(Register src, Register dst, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8202000; // LDEOR W
  if (is_64bit) inst |= 0x40000000; // LDEOR X
  inst |= (src_code << 16) | (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::ldset(Register src, Register dst, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8203000; // LDSET W
  if (is_64bit) inst |= 0x40000000; // LDSET X
  inst |= (src_code << 16) | (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::swp(Register src, Register dst, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0xB8208000; // SWP W
  if (is_64bit) inst |= 0x40000000; // SWP X
  inst |= (src_code << 16) | (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::dmb(uint8_t option) {
  uint32_t inst = 0xD5033BBF; // DMB SY (default)
  inst |= (option << 8);
  emit32(inst);
}

void Assembler::dsb(uint8_t option) {
  uint32_t inst = 0xD5033B9F; // DSB SY (default)
  inst |= (option << 8);
  emit32(inst);
}

void Assembler::isb(uint8_t option) {
  uint32_t inst = 0xD5033FDF; // ISB SY (default)
  inst |= (option << 8);
  emit32(inst);
}

void Assembler::ldar(Register dst, Register addr) {
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(dst);
  
  uint32_t inst = 0x885FFC00; // LDAR W
  if (is_64bit) inst |= 0x40000000; // LDAR X
  inst |= (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::stlr(Register src, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t addr_code = reg_code(addr);
  bool is_64bit = is_64bit_reg(src);
  
  uint32_t inst = 0x889FFC00; // STLR W
  if (is_64bit) inst |= 0x40000000; // STLR X
  inst |= (addr_code << 5) | src_code;
  emit32(inst);
}

void Assembler::ldarb(Register dst, Register addr) {
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  
  uint32_t inst = 0x085FFC00; // LDARB
  inst |= (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::stlrb(Register src, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t addr_code = reg_code(addr);
  
  uint32_t inst = 0x089FFC00; // STLRB
  inst |= (addr_code << 5) | src_code;
  emit32(inst);
}

void Assembler::ldarh(Register dst, Register addr) {
  uint32_t dst_code = reg_code(dst);
  uint32_t addr_code = reg_code(addr);
  
  uint32_t inst = 0x485FFC00; // LDARH
  inst |= (addr_code << 5) | dst_code;
  emit32(inst);
}

void Assembler::stlrh(Register src, Register addr) {
  uint32_t src_code = reg_code(src);
  uint32_t addr_code = reg_code(addr);
  
  uint32_t inst = 0x489FFC00; // STLRH
  inst |= (addr_code << 5) | src_code;
  emit32(inst);
}

void Assembler::emit_u32(uint32_t value) {
  ensure_space(4);
  *reinterpret_cast<uint32_t*>(memory + used) = value;
  used += 4;
}

void Assembler::emit_u64(uint64_t value) {
  ensure_space(8);
  *reinterpret_cast<uint64_t*>(memory + used) = value;
  used += 8;
}

void Assembler::align_to(size_t alignment) {
  size_t aligned = (used + alignment - 1) & ~(alignment - 1);
  ensure_space(aligned - used);
  while (used < aligned) {
    memory[used++] = 0;
  }
}

// Bitwise operations - register variants
void Assembler::and_reg(Register dst, Register src1, Register src2) {
  // ARM64: AND Xd, Xn, Xm (64-bit)
  uint32_t instr = 0x8A000000;  // AND base opcode
  instr |= (static_cast<uint32_t>(dst) & 0x1F);        // Rd
  instr |= ((static_cast<uint32_t>(src1) & 0x1F) << 5); // Rn
  instr |= ((static_cast<uint32_t>(src2) & 0x1F) << 16); // Rm
  emit_u32(instr);
}

void Assembler::orr_reg(Register dst, Register src1, Register src2) {
  // ARM64: ORR Xd, Xn, Xm (64-bit)
  uint32_t instr = 0xAA000000;  // ORR base opcode
  instr |= (static_cast<uint32_t>(dst) & 0x1F);        // Rd
  instr |= ((static_cast<uint32_t>(src1) & 0x1F) << 5); // Rn
  instr |= ((static_cast<uint32_t>(src2) & 0x1F) << 16); // Rm
  emit_u32(instr);
}

void Assembler::eor_reg(Register dst, Register src1, Register src2) {
  // ARM64: EOR Xd, Xn, Xm (64-bit)
  uint32_t instr = 0xCA000000;  // EOR base opcode
  instr |= (static_cast<uint32_t>(dst) & 0x1F);        // Rd
  instr |= ((static_cast<uint32_t>(src1) & 0x1F) << 5); // Rn
  instr |= ((static_cast<uint32_t>(src2) & 0x1F) << 16); // Rm
  emit_u32(instr);
}
