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

  // Writes a dynamically linked ELF executable with interpreter and dynamic linking support
  bool write_dynamic_executable(const char* path,
                                const uint8_t* buffer,
                                uint32_t size,
                                const std::vector<std::string>& libraries = {},
                                const char* interpreter = nullptr,
                                uint32_t entry_offset = 0,
                                ELFArch arch = ELFArch::X86_64);

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
    uint32_t type;         // Architecture-specific relocation type
    int64_t addend;        // Addend for RELA relocations
    
    // Helper constructors for common relocation types
    static Relocation abs64(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 1, addend}; // Type 1 = ABS64 for both x64 and ARM64
    }
    
    static Relocation pc_rel32(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 2, addend}; // Type 2 = PC-relative 32-bit
    }
    
    // ARM64-specific relocations
    static Relocation adrp_page21(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 3, addend}; // Type 3 = ADRP (page-relative)
    }
    
    static Relocation add_lo12(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 4, addend}; // Type 4 = ADD low 12 bits
    }
    
    static Relocation call26(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 5, addend}; // Type 5 = BL/B call 26-bit
    }
    
    static Relocation jump26(uint64_t offset, uint32_t symbol, int64_t addend = 0) {
      return {offset, symbol, 6, addend}; // Type 6 = B jump 26-bit
    }
  };
  
  bool write_object_with_relocations(const char* path,
                                    const uint8_t* text_buffer,
                                    uint32_t text_size,
                                    const uint8_t* data_buffer,
                                    uint32_t data_size,
                                    const std::vector<Relocation>& relocations,
                                    const std::vector<std::pair<std::string, uint32_t>>& symbols, // name, offset
                                    ELFArch arch = ELFArch::X86_64);

private:
  // GNU hash table implementation for faster symbol lookup
  struct GnuHashTable {
    uint32_t nbuckets;
    uint32_t symoffset; 
    uint32_t bloom_size;
    uint32_t bloom_shift;
    std::vector<uint64_t> bloom_filter;
    std::vector<uint32_t> buckets;
    std::vector<uint32_t> chain;
    
    void build(const std::vector<std::string>& symbols);
    static uint32_t gnu_hash(const char* name);
  };
};
