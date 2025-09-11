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
static constexpr uint8_t ELFOSABI_NONE = 0;
static constexpr uint8_t ELFOSABI_LINUX = 3;
static constexpr uint8_t ELFOSABI_FREEBSD = 9;
static constexpr uint8_t ELFOSABI_ARM = 97;

// ELF identification indices
static constexpr uint8_t EI_NIDENT = 16;
static constexpr uint8_t EI_MAG0 = 0;
static constexpr uint8_t EI_MAG1 = 1;
static constexpr uint8_t EI_MAG2 = 2;
static constexpr uint8_t EI_MAG3 = 3;
static constexpr uint8_t EI_CLASS = 4;
static constexpr uint8_t EI_DATA = 5;
static constexpr uint8_t EI_VERSION = 6;
static constexpr uint8_t EI_OSABI = 7;
static constexpr uint8_t EI_ABIVERSION = 8;
static constexpr uint8_t EI_PAD = 9;

static constexpr uint16_t ET_REL        = 1;  // Relocatable file
static constexpr uint16_t ET_EXEC       = 2;  // Executable file
static constexpr uint16_t EM_X86_64     = 62; // AMD x86-64 architecture
static constexpr uint16_t EM_AARCH64    = 183;// ARM aarch64

static constexpr uint32_t PT_LOAD       = 1;  // Loadable program segment
static constexpr uint32_t PT_DYNAMIC    = 2;  // Dynamic linking information
static constexpr uint32_t PT_INTERP     = 3;  // Program interpreter
static constexpr uint32_t PT_GNU_STACK  = 0x6474e551; // GNU stack permissions
static constexpr uint32_t PT_GNU_RELRO  = 0x6474e552; // GNU read-only after relocation
static constexpr uint32_t PF_X          = 1;  // Execute
static constexpr uint32_t PF_W          = 2;  // Write
static constexpr uint32_t PF_R          = 4;  // Read

static constexpr uint32_t SHT_NULL      = 0;  // Section header table entry unused
static constexpr uint32_t SHT_PROGBITS  = 1;  // Program data
static constexpr uint32_t SHT_SYMTAB    = 2;  // Symbol table
static constexpr uint32_t SHT_STRTAB    = 3;  // String table
static constexpr uint32_t SHT_RELA      = 4;  // Relocation entries with addends
static constexpr uint32_t SHT_HASH      = 5;  // Symbol hash table
static constexpr uint32_t SHT_DYNAMIC   = 6;  // Dynamic linking information
static constexpr uint32_t SHT_DYNSYM    = 11; // Dynamic linker symbol table
static constexpr uint32_t SHT_GNU_HASH  = 0x6ffffff6; // GNU-style hash table

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

// AArch64 relocation types - Complete set for ARM64 ELF support
static constexpr uint32_t R_AARCH64_NONE = 0;
static constexpr uint32_t R_AARCH64_ABS64 = 257;          // Direct 64 bit
static constexpr uint32_t R_AARCH64_ABS32 = 258;          // Direct 32 bit 
static constexpr uint32_t R_AARCH64_ABS16 = 259;          // Direct 16 bit
static constexpr uint32_t R_AARCH64_PREL64 = 260;         // PC-relative 64 bit
static constexpr uint32_t R_AARCH64_PREL32 = 261;         // PC-relative 32 bit
static constexpr uint32_t R_AARCH64_PREL16 = 262;         // PC-relative 16 bit
static constexpr uint32_t R_AARCH64_ADR_PREL_PG_HI21 = 275; // Page-relative ADRP
static constexpr uint32_t R_AARCH64_ADD_ABS_LO12_NC = 277;   // Direct ADD immediate
static constexpr uint32_t R_AARCH64_LDST8_ABS_LO12_NC = 278; // Direct LDST8 immediate
static constexpr uint32_t R_AARCH64_LDST16_ABS_LO12_NC = 284; // Direct LDST16 immediate
static constexpr uint32_t R_AARCH64_LDST32_ABS_LO12_NC = 285; // Direct LDST32 immediate
static constexpr uint32_t R_AARCH64_LDST64_ABS_LO12_NC = 286; // Direct LDST64 immediate
static constexpr uint32_t R_AARCH64_LDST128_ABS_LO12_NC = 299; // Direct LDST128 immediate
static constexpr uint32_t R_AARCH64_JUMP26 = 282;         // PC-relative 26 bit
static constexpr uint32_t R_AARCH64_CALL26 = 283;         // PC-relative 26 bit

// Dynamic linking tags
static constexpr uint32_t DT_NULL       = 0;  // Marks end of dynamic array
static constexpr uint32_t DT_NEEDED     = 1;  // String table offset of needed library
static constexpr uint32_t DT_PLTRELSZ   = 2;  // Size of PLT relocations
static constexpr uint32_t DT_PLTGOT     = 3;  // Address of PLT GOT
static constexpr uint32_t DT_HASH       = 4;  // Address of symbol hash table
static constexpr uint32_t DT_STRTAB     = 5;  // Address of string table
static constexpr uint32_t DT_SYMTAB     = 6;  // Address of symbol table
static constexpr uint32_t DT_RELA       = 7;  // Address of RELA relocs
static constexpr uint32_t DT_RELASZ     = 8;  // Size of RELA relocs
static constexpr uint32_t DT_RELAENT    = 9;  // Size of one RELA reloc
static constexpr uint32_t DT_STRSZ      = 10; // Size of string table
static constexpr uint32_t DT_SYMENT     = 11; // Size of one symbol table entry
static constexpr uint32_t DT_SONAME     = 14; // String table offset of shared object name
static constexpr uint32_t DT_RPATH      = 15; // String table offset of library search path
static constexpr uint32_t DT_RUNPATH    = 29; // String table offset of library search path
static constexpr uint32_t DT_GNU_HASH   = 0x6ffffef5; // Address of GNU hash table

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

struct Elf64_Dyn {
  int64_t  d_tag;   // Dynamic entry type
  union {
    uint64_t d_val; // Integer value
    uint64_t d_ptr; // Program virtual address
  } d_un;
};
#pragma pack(pop)

bool ELFBuilder64::write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset, ELFArch arch) {
  if (buffer == nullptr || size == 0) return false;

  // Architecture-specific configuration
  uint64_t page_size = (arch == ELFArch::ARM64) ? 0x10000 : 0x1000; // 64KB for ARM64, 4KB for x64
  uint64_t load_addr = (arch == ELFArch::ARM64) ? 0x400000 : 0x400000; // Standard load addresses aligned to page boundaries
  
  // Calculate offsets with proper ARM64 alignment
  uint64_t phdr_offset = sizeof(Elf64_Ehdr);
  uint64_t total_phdrs = 2; // PT_LOAD + PT_GNU_STACK for proper execution
  uint64_t phdrs_size = total_phdrs * sizeof(Elf64_Phdr);
  // ARM64 needs proper page alignment, ensure code starts on page boundary
  uint64_t code_offset = align_up(phdr_offset + phdrs_size, page_size);

  // ELF header
  Elf64_Ehdr ehdr = {};
  memset(&ehdr, 0, sizeof(ehdr));  // Initialize all bytes to 0

  // Set ELF magic and identification
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;  // ABI version
  // Bytes 9-15 (EI_PAD to EI_NIDENT-1) are already 0 from memset

  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_entry = load_addr + code_offset + entry_offset;
  ehdr.e_phoff = phdr_offset;
  ehdr.e_shoff = 0; // No section headers
  ehdr.e_flags = 0;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = total_phdrs; // PT_LOAD + PT_GNU_STACK
  ehdr.e_shentsize = 0;
  ehdr.e_shnum = 0;
  ehdr.e_shstrndx = 0;

  // Program header 1: LOAD segment (executable code)
  Elf64_Phdr load_phdr = {};
  load_phdr.p_type = PT_LOAD;
  load_phdr.p_flags = PF_R | PF_X; // Read + Execute
  load_phdr.p_offset = 0; // Load entire file from beginning
  load_phdr.p_vaddr = load_addr;
  load_phdr.p_paddr = load_addr;
  load_phdr.p_filesz = code_offset + size; // Headers + code
  load_phdr.p_memsz = code_offset + size;  // Same as file size
  load_phdr.p_align = page_size;

  // Program header 2: GNU_STACK (required for ARM64 stack permissions)
  Elf64_Phdr stack_phdr = {};
  stack_phdr.p_type = PT_GNU_STACK;
  stack_phdr.p_flags = PF_R | PF_W; // Read + Write (no execute - NX stack)
  stack_phdr.p_offset = 0;
  stack_phdr.p_vaddr = 0;
  stack_phdr.p_paddr = 0;
  stack_phdr.p_filesz = 0;
  stack_phdr.p_memsz = 0;
  stack_phdr.p_align = (arch == ELFArch::ARM64) ? 0x10 : 0x8; // ARM64 needs 16-byte alignment

  // Build output file
  std::vector<uint8_t> out;
  auto emit = [&](const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  };

  // Emit ELF header
  emit(&ehdr, sizeof(ehdr));

  // Emit program headers
  emit(&load_phdr, sizeof(load_phdr));
  emit(&stack_phdr, sizeof(stack_phdr));

  // Pad to code section with proper page alignment
  while (out.size() < code_offset) {
    out.push_back(0);
  }

  // Emit code
  emit(buffer, size);

  // Write to file
  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();

  // Make executable with proper permissions
  chmod(path, 0755);
  return true;
}

bool ELFBuilder64::write_dynamic_executable(const char* path,
                                            const uint8_t* buffer,
                                            uint32_t size,
                                            const std::vector<std::string>& libraries,
                                            const char* interpreter,
                                            uint32_t entry_offset,
                                            ELFArch arch) {
  if (buffer == nullptr || size == 0) return false;

  // Default interpreter paths for different architectures
  const char* default_interp = nullptr;
  if (!interpreter) {
    if (arch == ELFArch::ARM64) {
      default_interp = "/lib/ld-linux-aarch64.so.1";
    } else {
      default_interp = "/lib64/ld-linux-x86-64.so.2";
    }
  } else {
    default_interp = interpreter;
  }

  // Architecture-specific configuration
  uint64_t page_size = (arch == ELFArch::ARM64) ? 0x10000 : 0x1000;
  uint64_t load_addr = 0x400000;

  // Build dynamic string table
  std::vector<char> dynstr;
  dynstr.push_back('\0'); // Empty string at index 0

  // Add interpreter path
  uint32_t interp_idx = dynstr.size();
  dynstr.insert(dynstr.end(), default_interp, default_interp + std::strlen(default_interp) + 1);

  // Add library names for DT_NEEDED
  std::vector<uint32_t> lib_indices;
  for (const auto& lib : libraries) {
    lib_indices.push_back(dynstr.size());
    dynstr.insert(dynstr.end(), lib.begin(), lib.end());
    dynstr.push_back('\0');
  }

  // Build dynamic section
  std::vector<Elf64_Dyn> dynamic;
  
  // Add DT_NEEDED entries for libraries
  for (uint32_t lib_idx : lib_indices) {
    Elf64_Dyn entry = {};
    entry.d_tag = DT_NEEDED;
    entry.d_un.d_val = lib_idx;
    dynamic.push_back(entry);
  }

  // Add basic dynamic entries
  if (!dynstr.empty()) {
    Elf64_Dyn strtab_entry = {};
    strtab_entry.d_tag = DT_STRTAB;
    strtab_entry.d_un.d_ptr = 0; // Will be filled later
    dynamic.push_back(strtab_entry);

    Elf64_Dyn strsz_entry = {};
    strsz_entry.d_tag = DT_STRSZ;
    strsz_entry.d_un.d_val = dynstr.size();
    dynamic.push_back(strsz_entry);
  }

  // Null terminator
  Elf64_Dyn null_entry = {};
  null_entry.d_tag = DT_NULL;
  dynamic.push_back(null_entry);

  // Calculate layout
  uint64_t ehdr_size = sizeof(Elf64_Ehdr);
  uint64_t phdr_count = 4; // LOAD, DYNAMIC, INTERP, GNU_STACK
  uint64_t phdr_size = phdr_count * sizeof(Elf64_Phdr);
  
  uint64_t interp_offset = align_up(ehdr_size + phdr_size, 8);
  uint64_t interp_size = std::strlen(default_interp) + 1;
  
  uint64_t dynstr_offset = align_up(interp_offset + interp_size, 8);
  uint64_t dynamic_offset = align_up(dynstr_offset + dynstr.size(), 8);
  uint64_t code_offset = align_up(dynamic_offset + dynamic.size() * sizeof(Elf64_Dyn), page_size);

  // ELF header
  Elf64_Ehdr ehdr = {};
  memset(&ehdr, 0, sizeof(ehdr));

  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;

  ehdr.e_type = ET_EXEC;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_entry = load_addr + code_offset + entry_offset;
  ehdr.e_phoff = ehdr_size;
  ehdr.e_shoff = 0; // No section headers for simple dynamic executable
  ehdr.e_flags = 0;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = phdr_count;
  ehdr.e_shentsize = 0;
  ehdr.e_shnum = 0;
  ehdr.e_shstrndx = 0;

  // Update dynamic entries with actual addresses
  for (auto& dyn : dynamic) {
    if (dyn.d_tag == DT_STRTAB) {
      dyn.d_un.d_ptr = load_addr + dynstr_offset;
    }
  }

  // Program headers
  std::vector<Elf64_Phdr> phdrs(phdr_count);

  // LOAD segment (entire file)
  phdrs[0].p_type = PT_LOAD;
  phdrs[0].p_flags = PF_R | PF_X;
  phdrs[0].p_offset = 0;
  phdrs[0].p_vaddr = load_addr;
  phdrs[0].p_paddr = load_addr;
  phdrs[0].p_filesz = code_offset + size;
  phdrs[0].p_memsz = code_offset + size;
  phdrs[0].p_align = page_size;

  // DYNAMIC segment
  phdrs[1].p_type = PT_DYNAMIC;
  phdrs[1].p_flags = PF_R;
  phdrs[1].p_offset = dynamic_offset;
  phdrs[1].p_vaddr = load_addr + dynamic_offset;
  phdrs[1].p_paddr = load_addr + dynamic_offset;
  phdrs[1].p_filesz = dynamic.size() * sizeof(Elf64_Dyn);
  phdrs[1].p_memsz = dynamic.size() * sizeof(Elf64_Dyn);
  phdrs[1].p_align = 8;

  // INTERP segment
  phdrs[2].p_type = PT_INTERP;
  phdrs[2].p_flags = PF_R;
  phdrs[2].p_offset = interp_offset;
  phdrs[2].p_vaddr = load_addr + interp_offset;
  phdrs[2].p_paddr = load_addr + interp_offset;
  phdrs[2].p_filesz = interp_size;
  phdrs[2].p_memsz = interp_size;
  phdrs[2].p_align = 1;

  // GNU_STACK segment
  phdrs[3].p_type = PT_GNU_STACK;
  phdrs[3].p_flags = PF_R | PF_W;
  phdrs[3].p_offset = 0;
  phdrs[3].p_vaddr = 0;
  phdrs[3].p_paddr = 0;
  phdrs[3].p_filesz = 0;
  phdrs[3].p_memsz = 0;
  phdrs[3].p_align = (arch == ELFArch::ARM64) ? 0x10 : 0x8;

  // Build output file
  std::vector<uint8_t> out;
  auto emit = [&](const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
  };

  // Emit ELF header
  emit(&ehdr, sizeof(ehdr));

  // Emit program headers
  emit(phdrs.data(), phdrs.size() * sizeof(Elf64_Phdr));

  // Pad to interpreter
  while (out.size() < interp_offset) out.push_back(0);
  emit(default_interp, interp_size);

  // Pad to dynamic string table
  while (out.size() < dynstr_offset) out.push_back(0);
  emit(dynstr.data(), dynstr.size());

  // Pad to dynamic section
  while (out.size() < dynamic_offset) out.push_back(0);
  emit(dynamic.data(), dynamic.size() * sizeof(Elf64_Dyn));

  // Pad to code section
  while (out.size() < code_offset) out.push_back(0);

  // Emit code
  emit(buffer, size);

  // Write to file
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
  memset(&ehdr, 0, sizeof(ehdr));  // Initialize all bytes to 0

  // Set ELF magic and identification
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;  // ABI version
  // Bytes 9-15 (EI_PAD to EI_NIDENT-1) are already 0 from memset

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
  uint64_t shdr_offset = align_up(shstrtab_offset + strtab.size(), 4); // ELF spec requires 4-byte alignment for section headers
  
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
  memset(&ehdr, 0, sizeof(ehdr));  // Initialize all bytes to 0

  // Set ELF magic and identification
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;  // ABI version
  // Bytes 9-15 (EI_PAD to EI_NIDENT-1) are already 0 from memset

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
  uint64_t shdr_offset = align_up(shstrtab_offset + strtab.size(), 4); // ELF spec requires 4-byte alignment for section headers
  
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
  if (!text_buffer || text_size == 0 || symbols.empty()) return false;

  // Build section string table
  std::vector<char> strtab;
  strtab.push_back('\0'); // Empty string at index 0
  
  uint32_t shstrtab_idx = strtab.size();
  const char shstrtab_str[] = ".shstrtab";
  strtab.insert(strtab.end(), shstrtab_str, shstrtab_str + sizeof(shstrtab_str));
  
  uint32_t text_idx = strtab.size();
  const char text_str[] = ".text";
  strtab.insert(strtab.end(), text_str, text_str + sizeof(text_str));
  
  uint32_t data_idx = 0;
  if (data_buffer && data_size > 0) {
    data_idx = strtab.size();
    const char data_str[] = ".data";
    strtab.insert(strtab.end(), data_str, data_str + sizeof(data_str));
  }
  
  uint32_t rela_text_idx = 0;
  if (!relocations.empty()) {
    rela_text_idx = strtab.size();
    const char rela_text_str[] = ".rela.text";
    strtab.insert(strtab.end(), rela_text_str, rela_text_str + sizeof(rela_text_str));
  }
  
  uint32_t symtab_idx = strtab.size();
  const char symtab_str[] = ".symtab";
  strtab.insert(strtab.end(), symtab_str, symtab_str + sizeof(symtab_str));
  
  uint32_t str_idx = strtab.size();
  const char str_str[] = ".strtab";
  strtab.insert(strtab.end(), str_str, str_str + sizeof(str_str));

  // Symbol string table
  std::vector<char> sym_strtab;
  sym_strtab.push_back('\0'); // Empty string at index 0
  
  // Add all symbol names to string table
  std::vector<uint32_t> symbol_name_indices;
  for (const auto& sym : symbols) {
    symbol_name_indices.push_back(sym_strtab.size());
    sym_strtab.insert(sym_strtab.end(), sym.first.begin(), sym.first.end());
    sym_strtab.push_back('\0');
  }

  // Build symbols
  std::vector<Elf64_Sym> elf_symbols;
  
  // First symbol is always null
  Elf64_Sym null_sym = {};
  elf_symbols.push_back(null_sym);
  
  // Add all symbols
  for (size_t i = 0; i < symbols.size(); ++i) {
    Elf64_Sym sym = {};
    sym.st_name = symbol_name_indices[i];
    sym.st_info = (STB_GLOBAL << 4) | (i == 0 ? STT_FUNC : STT_NOTYPE);
    sym.st_other = 0;
    sym.st_shndx = (symbols[i].second < text_size) ? 1 : 2; // .text or .data section
    sym.st_value = symbols[i].second;
    sym.st_size = 0;
    elf_symbols.push_back(sym);
  }

  // Build relocations for ARM64/x64
  std::vector<Elf64_Rela> elf_relocations;
  for (const auto& rel : relocations) {
    Elf64_Rela elf_rel = {};
    elf_rel.r_offset = rel.offset;
    elf_rel.r_addend = rel.addend;
    
    // Map relocation types based on architecture
    uint32_t elf_type = 0;
    if (arch == ELFArch::ARM64) {
      // ARM64 relocation type mapping
      switch (rel.type) {
        case 1: elf_type = R_AARCH64_ABS64; break;
        case 2: elf_type = R_AARCH64_PREL32; break;
        case 3: elf_type = R_AARCH64_ADR_PREL_PG_HI21; break; // ADRP
        case 4: elf_type = R_AARCH64_ADD_ABS_LO12_NC; break;  // ADD immediate
        case 5: elf_type = R_AARCH64_CALL26; break;           // BL/B calls
        case 6: elf_type = R_AARCH64_JUMP26; break;           // B jumps
        default: elf_type = R_AARCH64_ABS64; break;           // Fallback
      }
    } else {
      // x86_64 relocation type mapping  
      switch (rel.type) {
        case 1: elf_type = R_X86_64_64; break;
        case 2: elf_type = R_X86_64_PC32; break;
        default: elf_type = R_X86_64_64; break;
      }
    }
    
    elf_rel.r_info = ((uint64_t)rel.symbol << 32) | elf_type;
    elf_relocations.push_back(elf_rel);
  }

  // Calculate section count and offsets
  uint32_t section_count = 4; // null, .text, .symtab, .strtab, .shstrtab
  if (data_buffer && data_size > 0) section_count++;
  if (!relocations.empty()) section_count++;

  // ELF header
  Elf64_Ehdr ehdr = {};
  memset(&ehdr, 0, sizeof(ehdr));  // Initialize all bytes to 0

  // Set ELF magic and identification
  ehdr.e_ident[EI_MAG0] = ELFMAG0;
  ehdr.e_ident[EI_MAG1] = ELFMAG1;
  ehdr.e_ident[EI_MAG2] = ELFMAG2;
  ehdr.e_ident[EI_MAG3] = ELFMAG3;
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_ident[EI_ABIVERSION] = 0;  // ABI version
  // Bytes 9-15 (EI_PAD to EI_NIDENT-1) are already 0 from memset

  ehdr.e_type = ET_REL;
  ehdr.e_machine = (arch == ELFArch::ARM64) ? EM_AARCH64 : EM_X86_64;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_ehsize = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = 0;
  ehdr.e_phnum = 0;
  ehdr.e_shentsize = sizeof(Elf64_Shdr);
  ehdr.e_shnum = section_count + 1; // +1 for .shstrtab
  ehdr.e_shstrndx = section_count; // .shstrtab is last section

  // Calculate offsets
  uint64_t text_offset = sizeof(Elf64_Ehdr);
  uint64_t data_offset = align_up(text_offset + text_size, 8);
  uint64_t rela_offset = data_buffer ? align_up(data_offset + data_size, 8) : data_offset;
  uint64_t symtab_offset = !relocations.empty() ? 
                          align_up(rela_offset + elf_relocations.size() * sizeof(Elf64_Rela), 8) :
                          rela_offset;
  uint64_t strtab_offset = symtab_offset + elf_symbols.size() * sizeof(Elf64_Sym);
  uint64_t shstrtab_offset = strtab_offset + sym_strtab.size();
  uint64_t shdr_offset = align_up(shstrtab_offset + strtab.size(), 4); // ELF spec requires 4-byte alignment for section headers
  
  ehdr.e_shoff = shdr_offset;

  // Section headers
  std::vector<Elf64_Shdr> sections;
  
  // Null section
  sections.push_back({});
  
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
  
  // .data section (if present)
  if (data_buffer && data_size > 0) {
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
  }
  
  // .rela.text section (if relocations present)
  if (!relocations.empty()) {
    Elf64_Shdr rela_shdr = {};
    rela_shdr.sh_name = rela_text_idx;
    rela_shdr.sh_type = SHT_RELA;
    rela_shdr.sh_flags = 0;
    rela_shdr.sh_addr = 0;
    rela_shdr.sh_offset = rela_offset;
    rela_shdr.sh_size = elf_relocations.size() * sizeof(Elf64_Rela);
    rela_shdr.sh_link = sections.size() + 1; // Points to .symtab (next section)
    rela_shdr.sh_info = 1; // Points to .text section (section being relocated)
    rela_shdr.sh_addralign = 8;
    rela_shdr.sh_entsize = sizeof(Elf64_Rela);
    sections.push_back(rela_shdr);
  }
  
  // .symtab section
  Elf64_Shdr symtab_shdr = {};
  symtab_shdr.sh_name = symtab_idx;
  symtab_shdr.sh_type = SHT_SYMTAB;
  symtab_shdr.sh_flags = 0;
  symtab_shdr.sh_addr = 0;
  symtab_shdr.sh_offset = symtab_offset;
  symtab_shdr.sh_size = elf_symbols.size() * sizeof(Elf64_Sym);
  symtab_shdr.sh_link = sections.size() + 1; // Points to .strtab (next section)
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
  
  // Pad to data section
  if (data_buffer && data_size > 0) {
    while (out.size() < data_offset) out.push_back(0);
    emit(data_buffer, data_size);
  }
  
  // Emit relocations if present
  if (!relocations.empty()) {
    while (out.size() < rela_offset) out.push_back(0);
    emit(elf_relocations.data(), elf_relocations.size() * sizeof(Elf64_Rela));
  }
  
  // Pad to symtab
  while (out.size() < symtab_offset) out.push_back(0);
  
  emit(elf_symbols.data(), elf_symbols.size() * sizeof(Elf64_Sym));
  emit(sym_strtab.data(), sym_strtab.size());
  emit(strtab.data(), strtab.size());
  
  // Pad to section headers
  while (out.size() < shdr_offset) out.push_back(0);
  
  emit(sections.data(), sections.size() * sizeof(Elf64_Shdr));

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();
  return true;
}
