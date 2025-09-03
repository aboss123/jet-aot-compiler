#pragma once
#include <cstdint>
#include <vector>

// Minimal Mach-O 64-bit builder for MH_EXECUTE with LC_SEGMENT_64 + LC_MAIN
// Code and data are placed contiguously in __TEXT,__text. Entry is at offset 0 by default.
// Architecture types for Mach-O files
enum class MachOArch {
  X86_64,
  ARM64
};

class MachOBuilder64 {
public:
  // Writes a Mach-O executable to path for the specified architecture.
  // buffer: code (and optionally trailing data) with RIP-relative references already patched.
  // entry_offset: file offset of entry point within buffer (usually 0).
  bool write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset = 0, MachOArch arch = MachOArch::X86_64);

  // Writes a Mach-O object file (.o) with a single __TEXT,__text section and one global symbol.
  // The symbol (e.g., "_main") is placed at symbol_offset within the section (usually 0).
  bool write_object(const char* path,
                    const uint8_t* buffer,
                    uint32_t size,
                    const char* global_symbol,
                    uint32_t symbol_offset = 0,
                    MachOArch arch = MachOArch::X86_64);

  // Writes a Mach-O object file with both __TEXT,__text and __DATA,__data sections
  bool write_object_with_data(const char* path,
                              const uint8_t* text_buffer,
                              uint32_t text_size,
                              const uint8_t* data_buffer,
                              uint32_t data_size,
                              const char* global_symbol,
                              uint32_t symbol_offset = 0,
                              MachOArch arch = MachOArch::X86_64);

  // Writes a Mach-O object with relocations for adrp/add sequences
  struct Relocation {
    uint32_t address;      // Offset in text section
    uint32_t symbol_num;   // Symbol table index  
    uint8_t type;          // Relocation type
    uint8_t length;        // Size (2 = 4 bytes, 3 = 8 bytes)
    bool pc_rel;           // PC-relative
    bool external;         // External symbol
  };
  
  bool write_object_with_relocations(const char* path,
                                    const uint8_t* text_buffer,
                                    uint32_t text_size,
                                    const uint8_t* data_buffer,
                                    uint32_t data_size,
                                    const std::vector<Relocation>& relocations,
                                    const std::vector<std::pair<std::string, uint32_t>>& symbols, // name, offset
                                    MachOArch arch = MachOArch::X86_64);
};


