#include <cstdio>
#include <cstdint>
#include <cstring>
#include "assemblers/x64-codegen.h"
#include "macho_builder.h"

using namespace nextgen::jet::x64;

// Build a simple hello world using syscalls (write/exit), then write a Mach-O exe.
int main(int argc, char** argv) {
  const char* out = (argc > 1) ? argv[1] : "hello_macho";

  Assembler a(1024);
  Label Lstr;

  // write(1, msg, len)
  const char *msg = "Hello World from Mach-O!\n";
  size_t len = std::strlen(msg);
  a.movq(AX, Imm64{0x2000004ULL});      // SYS_write
  a.movq(DI, Imm64{1});                 // fd = 1
  a.leaq_rip_label(SI, Lstr);           // rsi = &msg
  a.movq(DX, Imm64{(uint64_t)len});     // rdx = len
  a.syscall();
  // exit(0)
  a.movq(AX, Imm64{0x2000001ULL});      // SYS_exit
  a.movd(DI, Imm32{0});                 // status
  a.syscall();

  // Place string in the buffer
  a.align_to(4);
  a.place_label(Lstr);
  for (const char* p = msg; *p; ++p) a.emit_u8((ubyte)*p);
  a.emit_u8(0);

  MachOBuilder64 b;
  // Write as object and link with clang (preferred AOT pipeline)
  std::string obj = std::string(out) + ".o";
  if (!b.write_object(obj.c_str(), a.spill(), (uint32_t)a.bytes(), "_main", 0)) {
    std::fprintf(stderr, "Failed to write Mach-O object: %s\n", obj.c_str());
    return 1;
  }
  // Link with clang
  std::string cmd = std::string("clang -arch x86_64 ") + obj + " -o " + out;
  int rc = std::system(cmd.c_str());
  if (rc != 0) { std::fprintf(stderr, "Link failed: %d\n", rc); return 2; }
  std::printf("Wrote %s (via .o + clang)\n", out);
  return 0;
}


