#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "assemblers/x64-codegen.h"

// Simple AOT module emitter that writes a macOS x86_64 assembly file (.s)
// with multiple functions and optional read-only data. The output is suitable
// for assembling/linking with: clang -arch x86_64 module.s -o module
class ModuleEmitter {
public:
  struct Function {
    std::string name;           // without leading underscore
    const nextgen::jet::x64::Assembler* asmref; // not owned
    uint32_t align = 16;        // code alignment
  };

  struct Rodata {
    std::string name;           // without leading underscore
    std::vector<uint8_t> bytes;
    uint32_t align = 4;
  };

  void add_function(const std::string& name,
                    const nextgen::jet::x64::Assembler& a,
                    uint32_t align = 16);

  void add_rodata(const std::string& name,
                  const std::vector<uint8_t>& data,
                  uint32_t align = 4);

  // Writes a single .s file with .text and __TEXT,__const sections.
  bool write_s(const std::string& out_path) const;

private:
  std::vector<Function> functions;
  std::vector<Rodata>   rodatas;
};


