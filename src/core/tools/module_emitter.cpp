#include "module_emitter.h"
#include <fstream>

using namespace nextgen::jet::x64;

void ModuleEmitter::add_function(const std::string& name,
                                 const Assembler& a,
                                 uint32_t align) {
  functions.push_back(Function{ name, &a, align });
}

void ModuleEmitter::add_rodata(const std::string& name,
                               const std::vector<uint8_t>& data,
                               uint32_t align) {
  rodatas.push_back(Rodata{ name, data, align });
}

static void emit_alignment(std::ofstream& os, uint32_t align) {
  // GAS expects power-of-two alignment in bytes for .p2align
  // e.g., .p2align 4 -> 16-byte alignment
  uint32_t p2 = 0; uint32_t a = 1;
  while (a < align && p2 < 31) { a <<= 1; ++p2; }
  os << "  .p2align " << p2 << "\n";
}

bool ModuleEmitter::write_s(const std::string& out_path) const {
  std::ofstream os(out_path);
  if (!os) return false;

  // .text with all functions
  os << ".text\n";
  for (const auto& fn : functions) {
    os << ".globl _" << fn.name << "\n";
    emit_alignment(os, fn.align);
    os << "_" << fn.name << ":\n";
    const Assembler* a = fn.asmref;
    os << "  .byte ";
    for (size_t i = 0; i < a->bytes(); ++i) {
      unsigned v = a->spill()[i];
      static const char* hex = "0123456789ABCDEF";
      os << "0x" << hex[(v>>4)&0xF] << hex[v&0xF];
      if (i + 1 < a->bytes()) os << ", ";
    }
    os << "\n";
  }

  // __TEXT,__const with named constants
  if (!rodatas.empty()) {
    os << ".section __TEXT,__const\n";
    for (const auto& rd : rodatas) {
      emit_alignment(os, rd.align);
      os << "_" << rd.name << ":\n  .byte ";
      for (size_t i = 0; i < rd.bytes.size(); ++i) {
        unsigned v = rd.bytes[i];
        static const char* hex = "0123456789ABCDEF";
        os << "0x" << hex[(v>>4)&0xF] << hex[v&0xF];
        if (i + 1 < rd.bytes.size()) os << ", ";
      }
      os << "\n";
    }
  }

  return true;
}


