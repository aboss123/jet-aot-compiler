#include <iostream>
#include "assemblers/x64-codegen.h"
#include "systemv_abi.h"
#include "macho_builder.h"

using namespace nextgen::jet::x64;
using namespace SystemV;

int main(int argc, char** argv) {
  const char* output = (argc > 1) ? argv[1] : "simple_abi_test";
  
  std::cout << "=== Simple SystemV ABI Demo ===\n";
  
  // Create a function using proper ABI that exits with code 42
  Assembler func(256);
  ABIHandler abi;
  
  // Analyze calling convention for: int main()
  CallConvention cc = abi.analyze_call(Type::i32(), {});
  
  std::cout << "Function: int main() -> exit(42)\n";
  std::cout << "Return: " << (cc.return_loc.cls == ArgClass::INTEGER ? "INTEGER" : "OTHER") 
            << " in register " << (int)cc.return_loc.reg << "\n";
  
  // Emit function with ABI compliance - but use syscalls to avoid dyld issues
  abi.emit_prologue(func, cc);
  
  // Function body: exit(42) via syscall
  func.movq(AX, Imm64{0x2000001ULL});  // SYS_exit
  func.movd(DI, Imm32{42});            // exit code
  func.syscall();
  
  // No epilogue needed - we exit via syscall
  
  // Write as object and link with clang (working path)
  MachOBuilder64 builder;
  std::string obj = std::string(output) + ".o";
  
  if (!builder.write_object(obj.c_str(), func.spill(), (uint32_t)func.bytes(), "_main", 0)) {
    std::cerr << "Failed to write object: " << obj << std::endl;
    return 1;
  }
  
  // Link with system linker
  std::string cmd = std::string("clang -arch x86_64 ") + obj + " -o " + output;
  int rc = std::system(cmd.c_str());
  if (rc != 0) {
    std::cerr << "Link failed: " << rc << std::endl;
    return 2;
  }
  
  std::cout << "Generated: " << output << " (via .o + clang)\n";
  std::cout << "Run: arch -x86_64 " << output << "; echo $?\n";
  std::cout << "Expected exit code: 42\n";
  
  return 0;
}
