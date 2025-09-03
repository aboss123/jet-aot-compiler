#include <vector>
#include <string>
#include <cstring>
#include "assemblers/x64-codegen.h"
#include "module_emitter.h"

using namespace nextgen::jet::x64;

int main(int argc, char** argv) {
  const char* out_s = (argc > 1) ? argv[1] : "module.s";

  // Build hello function using syscalls
  Assembler hello(256);
  Label Lstr;
  const char* msg = "Hello from ModuleEmitter!\n";
  size_t len = std::strlen(msg);
  hello.movq(AX, Imm64{0x2000004ULL});      // write
  hello.movq(DI, Imm64{1});
  hello.leaq_rip_label(SI, Lstr);
  hello.movq(DX, Imm64{(uint64_t)len});
  hello.syscall();
  hello.movq(AX, Imm64{0x2000001ULL});      // exit
  hello.movd(DI, Imm32{0});
  hello.syscall();
  hello.align_to(4);
  hello.place_label(Lstr);
  for (const char* p = msg; *p; ++p) hello.emit_u8((ubyte)*p);
  hello.emit_u8(0);

  ModuleEmitter mod;
  mod.add_function("main", hello);
  if (!mod.write_s(out_s)) return 1;
  return 0;
}


