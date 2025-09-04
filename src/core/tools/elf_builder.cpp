#include "elf_builder.h"
#include <cstring>
#include <fstream>
#include <sys/stat.h>

// ELF constants
static constexpr uint8_t  ELFMAG0       = 0x7f;
static constexpr uint8_t  ELFMAG1       = 'E';
static constexpr uint8_t  ELFMAG2       = 'L';
static constexpr uint8_t  ELFMAG3       = 'F';
static constexpr uint8_t  ELFCLASS64    = 2;
static constexpr uint8_t  ELFDATA2LSB   = 1;
static constexpr uint8_t  EV_CURRENT    = 1;
static constexpr uint8_t  ELFOSABI_SYSV = 0;

static constexpr uint16_t ET_REL        = 1;  // Relocatable file
static constexpr uint16_t ET_EXEC       = 2;  // Executable file
static constexpr uint16_t EM_X86_64     = 62; // AMD x86-64 architecture
static constexpr uint16_t EM_AARCH64    = 183;// ARM aarch64

static constexpr uint32_t PT_LOAD       = 1;  // Loadable program segment
static constexpr uint32_t PF_X          = 1;  // Execute
static constexpr uint32_t PF_W          = 2;  // Write
static constexpr uint32_t PF_R          = 4;  // Read

static constexpr uint32_t SHT_NULL      = 0;  // Section header table entry unused
static constexpr uint32_t SHT_PROGBITS  = 1;  // Program data
static constexpr uint32_t SHT_SYMTAB    = 2;  // Symbol table
static constexpr uint32_t SHT_STRTAB    = 3;  // String table
static constexpr uint32_t SHT_RELA      = 4;  // Relocation entries with addends

static constexpr uint32_t SHF_WRITE     = 1;  // Writable
static constexpr uint32_t SHF_ALLOC     = 2;  // Occupies memory during execution
static constexpr uint32_t SHF_EXECINSTR = 4;  // Executable

// Symbol binding and type
static constexpr uint8_t STB_LOCAL      = 0;
static constexpr uint8_t STB_GLOBAL     = 1;
static constexpr uint8_t STT_NOTYPE     = 0;
static constexpr uint8_t STT_FUNC       = 2;

// x86_64 relocation types
static constexpr uint32_t R_X86_64_64   = 1;  // Direct 64 bit
static constexpr uint32_t R_X86_64_PC32 = 2;  // PC relative 32 bit signed

// AArch64 relocation types
static constexpr uint32_t R_AARCH64_ABS64 = 257; // Direct 64 bit
static constexpr uint32_t R_AARCH64_PREL32 = 261; // PC-relative 32 bit

static inline uint64_t align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

#pragma pack(push, 1)
struct Elf64_Ehdr {
  uint8_t  e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct Elf64_Phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

struct Elf64_Shdr {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
};

struct Elf64_Sym {
  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

struct Elf64_Rela {
  uint64_t r_offset;
  uint64_t r_info;
  int64_t  r_addend;
};
#pragma pack(pop)

bool ELFBuilder64::write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset, ELFArch arch) {
  if (buffer == nullptr || size == 0) return false;

  // ELF header
  Elf64_Ehdr ehdr = {};
  ehdr.e_ident[0] = ELFMAG0;
  ehdr.e_ident[1] = ELFMAG1;
  ehdr.e_ident[2] = ELFMAG2;
  ehdr.e_ident[3] = ELFMAG3;
  ehdr.e_ident[4] = ELFCLASS64;
  ehdr.e_ident[5] = ELFDATA2LSB;
  ehdr.e_ident[6] = EV_CURRENT;
  ehdr.e_ident[7] = ELFOSABI_SYSV;
  // e_ident[8-15] are zero

  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = 1;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = 0; // No section headers for executable
  ehdr.e_shstrndx = 0;

  // Program header for loadable segment
  Elf64_Phdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_X; // Read + Execute
  phdr.p_offset = 0;
  phdr.p_vaddr = 0x400000; // Standard Linux load address
  phdr.p_paddr = 0x400000;
  phdr.p_align = 0x1000; // 4KB alignment

  // Calculate layout
  uint64_t code_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
  code_offset = align_up(code_offset, 16);
  
  phdr.p_filesz = code_offset + size;
  phdr.p_memsz = phdr.p_filesz;
  
  ehdr.e_phoff = sizeof(Elf64_Ehdr);
  ehdr.e_entry = phdr.p_vaddr + code_offset + entry_offset;

  // Write file
  std::vector<uint8_t> out;
  out.reserve(code_offset + size);
  
  auto emit = [&](const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  };

  emit(&ehdr, sizeof(ehdr));
  emit(&phdr, sizeof(phdr));
  
  // Pad to code offset
  if (out.size() < code_offset) {
    out.resize(code_offset, 0);
  }
  
  emit(buffer, size);

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();

  // Make executable
  chmod(path, 0755);
  return true;
}

bool ELFBuilder64::write_object(const char* path,
                                const uint8_t* buffer,
                                uint32_t size,
                                const char* global_symbol,
                                uint32_t symbol_offset,
                                ELFArch arch) {
  if (!buffer || size == 0 || !global_symbol) return false;

  // Build string table
  std::vector<char> strtab;
  strtab.push_back('\0'); // Empty string at index 0
  
  // Section names
  uint32_t shstrtab_idx = strtab.size();
  const char shstrtab_str[] = ".shstrtab";
  strtab.insert(strtab.end(), shstrtab_str, shstrtab_str + sizeof(shstrtab_str));
  
  uint32_t text_idx = strtab.size();
  const char text_str[] = ".text";
  strtab.insert(strtab.end(), text_str, text_str + sizeof(text_str));
  
  uint32_t symtab_idx = strtab.size();
  const char symtab_str[] = ".symtab";
  strtab.insert(strtab.end(), symtab_str, symtab_str + sizeof(symtab_str));
  
  uint32_t str_idx = strtab.size();
  const char str_str[] = ".strtab";
  strtab.insert(strtab.end(), str_str, str_str + sizeof(str_str));

  // Symbol string table
  std::vector<char> sym_strtab;
  sym_strtab.push_back('\0'); // Empty string at index 0
  
  uint32_t symbol_name_idx = sym_strtab.size();
  sym_strtab.insert(sym_strtab.end(), global_symbol, global_symbol + std::strlen(global_symbol) + 1);

  // Build symbols
  std::vector<Elf64_Sym> symbols;
  
  // First symbol is always null
  Elf64_Sym null_sym = {};
  symbols.push_back(null_sym);
  
  // Global symbol
  Elf64_Sym sym = {};
  sym.st_name = symbol_name_idx;
  sym.st_info = (STB_GLOBAL << 4) | STT_FUNC;
  sym.st_other = 0;
  sym.st_shndx = 1; // .text section
  sym.st_value = symbol_offset;
  sym.st_size = 0;
  symbols.push_back(sym);

  // ELF header
  Elf64_Ehdr ehdr = {};
  ehdr.e_ident[0] = ELFMAG0;
  ehdr.e_ident[1] = ELFMAG1;
  ehdr.e_ident[2] = ELFMAG2;
  ehdr.e_ident[3] = ELFMAG3;
  ehdr.e_ident[4] = ELFCLASS64;
  ehdr.e_ident[5] = ELFDATA2LSB;
  ehdr.e_ident[6] = EV_CURRENT;
  ehdr.e_ident[7] = ELFOSABI_SYSV;

  ehdr.e_type = ET_REL;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = 0;
  ehdr.e_phnum = 0;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = 5; // null, .text, .symtab, .strtab, .shstrtab
  ehdr.e_shstrndx = 4; // .shstrtab section

  // Calculate offsets
  uint64_t text_offset = sizeof(Elf64_Ehdr);
  uint64_t symtab_offset = align_up(text_offset + size, 8);
  uint64_t strtab_offset = symtab_offset + symbols.size() * sizeof(Elf64_Sym);
  uint64_t shstrtab_offset = strtab_offset + sym_strtab.size();
  uint64_t shdr_offset = align_up(shstrtab_offset + strtab.size(), 8);
  
  ehdr.e_shoff = shdr_offset;

  // Section headers
  std::vector<Elf64_Shdr> sections;
  
  // Null section
  Elf64_Shdr null_shdr = {};
  sections.push_back(null_shdr);
  
  // .text section
  Elf64_Shdr text_shdr = {};
  text_shdr.sh_name = text_idx;
  text_shdr.sh_type = SHT_PROGBITS;
  text_shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  text_shdr.sh_addr = 0;
  text_shdr.sh_offset = text_offset;
  text_shdr.sh_size = size;
  text_shdr.sh_link = 0;
  text_shdr.sh_info = 0;
  text_shdr.sh_addralign = 16;
  text_shdr.sh_entsize = 0;
  sections.push_back(text_shdr);
  
  // .symtab section
  Elf64_Shdr symtab_shdr = {};
  symtab_shdr.sh_name = symtab_idx;
  symtab_shdr.sh_type = SHT_SYMTAB;
  symtab_shdr.sh_flags = 0;
  symtab_shdr.sh_addr = 0;
  symtab_shdr.sh_offset = symtab_offset;
  symtab_shdr.sh_size = symbols.size() * sizeof(Elf64_Sym);
  symtab_shdr.sh_link = 3; // .strtab section
  symtab_shdr.sh_info = 1; // First global symbol index
  symtab_shdr.sh_addralign = 8;
  symtab_shdr.sh_entsize = sizeof(Elf64_Sym);
  sections.push_back(symtab_shdr);
  
  // .strtab section
  Elf64_Shdr strtab_shdr = {};
  strtab_shdr.sh_name = str_idx;
  strtab_shdr.sh_type = SHT_STRTAB;
  strtab_shdr.sh_flags = 0;
  strtab_shdr.sh_addr = 0;
  strtab_shdr.sh_offset = strtab_offset;
  strtab_shdr.sh_size = sym_strtab.size();
  strtab_shdr.sh_link = 0;
  strtab_shdr.sh_info = 0;
  strtab_shdr.sh_addralign = 1;
  strtab_shdr.sh_entsize = 0;
  sections.push_back(strtab_shdr);
  
  // .shstrtab section
  Elf64_Shdr shstrtab_shdr = {};
  shstrtab_shdr.sh_name = shstrtab_idx;
  shstrtab_shdr.sh_type = SHT_STRTAB;
  shstrtab_shdr.sh_flags = 0;
  shstrtab_shdr.sh_addr = 0;
  shstrtab_shdr.sh_offset = shstrtab_offset;
  shstrtab_shdr.sh_size = strtab.size();
  shstrtab_shdr.sh_link = 0;
  shstrtab_shdr.sh_info = 0;
  shstrtab_shdr.sh_addralign = 1;
  shstrtab_shdr.sh_entsize = 0;
  sections.push_back(shstrtab_shdr);

  // Write file
  std::vector<uint8_t> out;
  out.reserve(shdr_offset + sections.size() * sizeof(Elf64_Shdr));
  
  auto emit = [&](const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  };

  emit(&ehdr, sizeof(ehdr));
  emit(buffer, size);
  
  // Pad to symtab
  if (out.size() < symtab_offset) {
    out.resize(symtab_offset, 0);
  }
  
  emit(symbols.data(), symbols.size() * sizeof(Elf64_Sym));
  emit(sym_strtab.data(), sym_strtab.size());
  emit(strtab.data(), strtab.size());
  
  // Pad to section headers
  if (out.size() < shdr_offset) {
    out.resize(shdr_offset, 0);
  }
  
  emit(sections.data(), sections.size() * sizeof(Elf64_Shdr));

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();
  return true;
}

bool ELFBuilder64::write_object_with_data(const char* path,
                                          const uint8_t* text_buffer,
                                          uint32_t text_size,
                                          const uint8_t* data_buffer,
                                          uint32_t data_size,
                                          const char* global_symbol,
                                          uint32_t symbol_offset,
                                          ELFArch arch) {
  if (!text_buffer || text_size == 0 || !global_symbol) return false;

  // Build section string table
  std::vector<char> strtab;
  strtab.push_back('\0'); // Empty string at index 0
  
  uint32_t shstrtab_idx = strtab.size();
  const char shstrtab_str[] = ".shstrtab";
  strtab.insert(strtab.end(), shstrtab_str, shstrtab_str + sizeof(shstrtab_str));
  
  uint32_t text_idx = strtab.size();
  const char text_str[] = ".text";
  strtab.insert(strtab.end(), text_str, text_str + sizeof(text_str));
  
  uint32_t data_idx = strtab.size();
  const char data_str[] = ".data";
  strtab.insert(strtab.end(), data_str, data_str + sizeof(data_str));
  
  uint32_t symtab_idx = strtab.size();
  const char symtab_str[] = ".symtab";
  strtab.insert(strtab.end(), symtab_str, symtab_str + sizeof(symtab_str));
  
  uint32_t str_idx = strtab.size();
  const char str_str[] = ".strtab";
  strtab.insert(strtab.end(), str_str, str_str + sizeof(str_str));

  // Symbol string table
  std::vector<char> sym_strtab;
  sym_strtab.push_back('\0'); // Empty string at index 0
  
  uint32_t symbol_name_idx = sym_strtab.size();
  sym_strtab.insert(sym_strtab.end(), global_symbol, global_symbol + std::strlen(global_symbol) + 1);

  // Build symbols
  std::vector<Elf64_Sym> symbols;
  
  // First symbol is always null
  Elf64_Sym null_sym = {};
  symbols.push_back(null_sym);
  
  // Global symbol in text section
  Elf64_Sym sym = {};
  sym.st_name = symbol_name_idx;
  sym.st_info = (STB_GLOBAL << 4) | STT_FUNC;
  sym.st_other = 0;
  sym.st_shndx = 1; // .text section
  sym.st_value = symbol_offset;
  sym.st_size = 0;
  symbols.push_back(sym);

  // ELF header
  Elf64_Ehdr ehdr = {};
  ehdr.e_ident[0] = ELFMAG0;
  ehdr.e_ident[1] = ELFMAG1;
  ehdr.e_ident[2] = ELFMAG2;
  ehdr.e_ident[3] = ELFMAG3;
  ehdr.e_ident[4] = ELFCLASS64;
  ehdr.e_ident[5] = ELFDATA2LSB;
  ehdr.e_ident[6] = EV_CURRENT;
  ehdr.e_ident[7] = ELFOSABI_SYSV;

  ehdr.e_type = ET_REL;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = 0;
  ehdr.e_phnum = 0;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = 6; // null, .text, .data, .symtab, .strtab, .shstrtab
  ehdr.e_shstrndx = 5; // .shstrtab section

  // Calculate offsets
  uint64_t text_offset = sizeof(Elf64_Ehdr);
  uint64_t data_offset = align_up(text_offset + text_size, 8);
  uint64_t symtab_offset = align_up(data_offset + data_size, 8);
  uint64_t strtab_offset = symtab_offset + symbols.size() * sizeof(Elf64_Sym);
  uint64_t shstrtab_offset = strtab_offset + sym_strtab.size();
  uint64_t shdr_offset = align_up(shstrtab_offset + strtab.size(), 8);
  
  ehdr.e_shoff = shdr_offset;

  // Section headers
  std::vector<Elf64_Shdr> sections;
  
  // Null section
  Elf64_Shdr null_shdr = {};
  sections.push_back(null_shdr);
  
  // .text section
  Elf64_Shdr text_shdr = {};
  text_shdr.sh_name = text_idx;
  text_shdr.sh_type = SHT_PROGBITS;
  text_shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  text_shdr.sh_addr = 0;
  text_shdr.sh_offset = text_offset;
  text_shdr.sh_size = text_size;
  text_shdr.sh_link = 0;
  text_shdr.sh_info = 0;
  text_shdr.sh_addralign = 16;
  text_shdr.sh_entsize = 0;
  sections.push_back(text_shdr);
  
  // .data section
  Elf64_Shdr data_shdr = {};
  data_shdr.sh_name = data_idx;
  data_shdr.sh_type = SHT_PROGBITS;
  data_shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
  data_shdr.sh_addr = 0;
  data_shdr.sh_offset = data_offset;
  data_shdr.sh_size = data_size;
  data_shdr.sh_link = 0;
  data_shdr.sh_info = 0;
  data_shdr.sh_addralign = 8;
  data_shdr.sh_entsize = 0;
  sections.push_back(data_shdr);
  
  // .symtab section
  Elf64_Shdr symtab_shdr = {};
  symtab_shdr.sh_name = symtab_idx;
  symtab_shdr.sh_type = SHT_SYMTAB;
  symtab_shdr.sh_flags = 0;
  symtab_shdr.sh_addr = 0;
  symtab_shdr.sh_offset = symtab_offset;
  symtab_shdr.sh_size = symbols.size() * sizeof(Elf64_Sym);
  symtab_shdr.sh_link = 4; // .strtab section
  symtab_shdr.sh_info = 1; // First global symbol index
  symtab_shdr.sh_addralign = 8;
  symtab_shdr.sh_entsize = sizeof(Elf64_Sym);
  sections.push_back(symtab_shdr);
  
  // .strtab section
  Elf64_Shdr strtab_shdr = {};
  strtab_shdr.sh_name = str_idx;
  strtab_shdr.sh_type = SHT_STRTAB;
  strtab_shdr.sh_flags = 0;
  strtab_shdr.sh_addr = 0;
  strtab_shdr.sh_offset = strtab_offset;
  strtab_shdr.sh_size = sym_strtab.size();
  strtab_shdr.sh_link = 0;
  strtab_shdr.sh_info = 0;
  strtab_shdr.sh_addralign = 1;
  strtab_shdr.sh_entsize = 0;
  sections.push_back(strtab_shdr);
  
  // .shstrtab section
  Elf64_Shdr shstrtab_shdr = {};
  shstrtab_shdr.sh_name = shstrtab_idx;
  shstrtab_shdr.sh_type = SHT_STRTAB;
  shstrtab_shdr.sh_flags = 0;
  shstrtab_shdr.sh_addr = 0;
  shstrtab_shdr.sh_offset = shstrtab_offset;
  shstrtab_shdr.sh_size = strtab.size();
  shstrtab_shdr.sh_link = 0;
  shstrtab_shdr.sh_info = 0;
  shstrtab_shdr.sh_addralign = 1;
  shstrtab_shdr.sh_entsize = 0;
  sections.push_back(shstrtab_shdr);

  // Write file
  std::vector<uint8_t> out;
  out.reserve(shdr_offset + sections.size() * sizeof(Elf64_Shdr));
  
  auto emit = [&](const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  };

  emit(&ehdr, sizeof(ehdr));
  emit(text_buffer, text_size);
  
  // Pad to data
  if (out.size() < data_offset) {
    out.resize(data_offset, 0);
  }
  
  if (data_buffer && data_size > 0) {
    emit(data_buffer, data_size);
  }
  
  // Pad to symtab
  if (out.size() < symtab_offset) {
    out.resize(symtab_offset, 0);
  }
  
  emit(symbols.data(), symbols.size() * sizeof(Elf64_Sym));
  emit(sym_strtab.data(), sym_strtab.size());
  emit(strtab.data(), strtab.size());
  
  // Pad to section headers
  if (out.size() < shdr_offset) {
    out.resize(shdr_offset, 0);
  }
  
  emit(sections.data(), sections.size() * sizeof(Elf64_Shdr));

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();
  return true;
}

bool ELFBuilder64::write_object_with_relocations(const char* path,
                                                const uint8_t* text_buffer,
                                                uint32_t text_size,
                                                const uint8_t* data_buffer,
                                                uint32_t data_size,
                                                const std::vector<Relocation>& relocations,
                                                const std::vector<std::pair<std::string, uint32_t>>& symbols,
                                                ELFArch arch) {
  // This is a simplified version - full implementation would require proper relocation handling
  // For now, fall back to the simpler version
  if (symbols.empty()) return false;
  
  return write_object_with_data(path, text_buffer, text_size, data_buffer, data_size, 
                               symbols[0].first.c_str(), symbols[0].second, arch);
}
