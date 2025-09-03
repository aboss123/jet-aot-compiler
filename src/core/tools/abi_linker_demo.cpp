#include <iostream>
#include "assemblers/x64-codegen.h"
#include "systemv_abi.h"
#include "module_linker.h"

using namespace nextgen::jet::x64;
using namespace SystemV;

int main(int argc, char** argv) {
  const char* output = (argc > 1) ? argv[1] : "abi_demo";
  
  std::cout << "=== SystemV ABI & Module Linker Demo ===\n";
  
  // Create a simple function that adds two integers using proper ABI
  Assembler add_func(256);
  ABIHandler abi;
  
  // Analyze calling convention for: int add(int a, int b)
  std::vector<Type> args = {Type::i32(), Type::i32()};
  CallConvention cc = abi.analyze_call(Type::i32(), args);
  
  std::cout << "Function signature: int add(int a, int b)\n";
  std::cout << "Arguments: " << cc.args.size() << "\n";
  std::cout << "  arg0: " << (cc.args[0].cls == ArgClass::INTEGER ? "INTEGER" : "OTHER") 
            << " in register " << (int)cc.args[0].reg << "\n";
  std::cout << "  arg1: " << (cc.args[1].cls == ArgClass::INTEGER ? "INTEGER" : "OTHER") 
            << " in register " << (int)cc.args[1].reg << "\n";
  std::cout << "Return: " << (cc.return_loc.cls == ArgClass::INTEGER ? "INTEGER" : "OTHER") 
            << " in register " << (int)cc.return_loc.reg << "\n";
  
  // Emit function with ABI compliance
  abi.emit_prologue(add_func, cc);
  
  // Function body: return a + b (args are in RDI, RSI per System V)
  add_func.movd(AX, DI);        // eax = a (first arg)
  add_func.addd(AX, SI);        // eax += b (second arg)
  
  abi.emit_epilogue(add_func, cc);
  
  // Create main function that calls add(10, 32) and exits with the result
  Assembler main_func(512);
  
  // Set up call to add(10, 32)
  main_func.movd(DI, Imm32{10});    // first arg
  main_func.movd(SI, Imm32{32});    // second arg
  // In a real implementation, we'd use call with relocation
  // For now, just inline the add operation
  main_func.movd(AX, DI);
  main_func.addd(AX, SI);
  
  // Exit with result
  main_func.movd(DI, AX);           // exit status = result
  main_func.movq(AX, Imm64{0x2000001ULL}); // SYS_exit
  main_func.syscall();
  
  // Use ModuleLinker to combine modules
  ModuleLinker linker;
  
  // Add modules
  linker.add_module("add_module", add_func, {"add"}, {});
  linker.add_module("main_module", main_func, {"main"}, {"add"});
  
  // Link to executable
  if (!linker.link_executable(output, "main")) {
    std::cerr << "Linking failed\n";
    return 1;
  }
  
  std::cout << "Generated executable: " << output << "\n";
  std::cout << "Run with: arch -x86_64 " << output << "; echo $?\n";
  std::cout << "Expected exit code: 42 (10 + 32)\n";
  
  return 0;
}
