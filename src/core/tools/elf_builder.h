#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <utility>

// ELF 64-bit builder for Linux executables and object files
// Similar to MachOBuilder64 but for ELF format
enum class ELFArch {
  X86_64,
  ARM64
};

class ELFBuilder64 {
public:
  // Writes an ELF executable to path for the specified architecture.
  // buffer: code (and optionally trailing data) with RIP-relative references already patched.
  // entry_offset: file offset of entry point within buffer (usually 0).
  bool write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset = 0, ELFArch arch = ELFArch::X86_64);

  // Writes an ELF object file (.o) with a single .text section and one global symbol.
  // The symbol (e.g., "_start") is placed at symbol_offset within the section (usually 0).
  bool write_object(const char* path,
                    const uint8_t* buffer,
                    uint32_t size,
                    const char* global_symbol,
                    uint32_t symbol_offset = 0,
                    ELFArch arch = ELFArch::X86_64);

  // Writes an ELF object file with both .text and .data sections
  bool write_object_with_data(const char* path,
                              const uint8_t* text_buffer,
                              uint32_t text_size,
                              const uint8_t* data_buffer,
                              uint32_t data_size,
                              const char* global_symbol,
                              uint32_t symbol_offset = 0,
                              ELFArch arch = ELFArch::X86_64);

  // Writes an ELF object with relocations
  struct Relocation {
    uint64_t offset;       // Offset in section
    uint32_t symbol;       // Symbol table index  
    uint32_t type;         // Relocation type
    int64_t addend;        // Addend for RELA relocations
  };
  
  bool write_object_with_relocations(const char* path,
                                    const uint8_t* text_buffer,
                                    uint32_t text_size,
                                    const uint8_t* data_buffer,
                                    uint32_t data_size,
                                    const std::vector<Relocation>& relocations,
                                    const std::vector<std::pair<std::string, uint32_t>>& symbols, // name, offset
                                    ELFArch arch = ELFArch::X86_64);
};
