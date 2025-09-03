#include "macho_builder.h"
#include <cstring>
#include <fstream>
#include <sys/stat.h>

static constexpr uint32_t MH_MAGIC_64      = 0xFEEDFACF;
static constexpr uint32_t MH_EXECUTE       = 0x2;
static constexpr uint32_t MH_OBJECT        = 0x1;
static constexpr uint32_t CPU_TYPE_X86     = 7;
static constexpr uint32_t CPU_ARCH_ABI64   = 0x01000000;
static constexpr uint32_t CPU_TYPE_X86_64  = CPU_TYPE_X86 | CPU_ARCH_ABI64; // 0x01000007
static constexpr uint32_t CPU_SUBTYPE_X86_64_ALL = 3;

static constexpr uint32_t CPU_TYPE_ARM     = 12;
static constexpr uint32_t CPU_TYPE_ARM64   = CPU_TYPE_ARM | CPU_ARCH_ABI64; // 0x0100000C
static constexpr uint32_t CPU_SUBTYPE_ARM64_ALL = 0;

static constexpr uint32_t LC_SEGMENT_64    = 0x19;
static constexpr uint32_t LC_MAIN          = 0x80000028;
static constexpr uint32_t LC_LOAD_DYLINKER = 0x0E;
static constexpr uint32_t LC_SYMTAB        = 0x2;

static constexpr uint32_t VM_PROT_READ     = 0x01;
static constexpr uint32_t VM_PROT_WRITE    = 0x02;
static constexpr uint32_t VM_PROT_EXECUTE  = 0x04;

static constexpr uint32_t S_REGULAR                  = 0x0;
static constexpr uint32_t S_ATTR_SOME_INSTRUCTIONS   = 0x00000400;
static constexpr uint32_t S_ATTR_PURE_INSTRUCTIONS   = 0x80000000;

// Symbol table constants
static constexpr uint8_t N_EXT  = 0x01; // External symbol
static constexpr uint8_t N_SECT = 0x0E; // Symbol is in a section

static inline uint64_t align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

#pragma pack(push, 1)
struct mach_header_64_t {
  uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype; uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags; uint32_t reserved;
};
struct segment_command_64_t {
  uint32_t cmd; uint32_t cmdsize; char segname[16]; uint64_t vmaddr; uint64_t vmsize; uint64_t fileoff; uint64_t filesize; uint32_t maxprot; uint32_t initprot; uint32_t nsects; uint32_t flags;
};
struct section_64_t {
  char sectname[16]; char segname[16]; uint64_t addr; uint64_t size; uint32_t offset; uint32_t align; uint32_t reloff; uint32_t nreloc; uint32_t flags; uint32_t reserved1; uint32_t reserved2; uint32_t reserved3;
};
struct entry_point_command_t { uint32_t cmd; uint32_t cmdsize; uint64_t entryoff; uint64_t stacksize; };
#pragma pack(pop)

#pragma pack(push, 1)
struct dylinker_command_t { uint32_t cmd; uint32_t cmdsize; uint32_t name; /* char name[] */ };
struct symtab_command { uint32_t cmd; uint32_t cmdsize; uint32_t symoff; uint32_t nsyms; uint32_t stroff; uint32_t strsize; };
struct nlist_64 { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };
#pragma pack(pop)

bool MachOBuilder64::write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset, MachOArch arch) {
  if (buffer == nullptr || size == 0) return false;

  // Build load commands
  // 1) __PAGEZERO
  segment_command_64_t pagezero{}; pagezero.cmd = LC_SEGMENT_64; pagezero.nsects = 0; pagezero.cmdsize = sizeof(segment_command_64_t);
  std::memset(pagezero.segname, 0, sizeof(pagezero.segname)); std::memcpy(pagezero.segname, "__PAGEZERO", 10);
  pagezero.vmaddr = 0; pagezero.vmsize = 0x100000000ull; pagezero.fileoff = 0; pagezero.filesize = 0;
  pagezero.maxprot = 0; pagezero.initprot = 0; pagezero.flags = 0;

  // 2) __TEXT with one __text section
  segment_command_64_t seg{}; seg.cmd = LC_SEGMENT_64; seg.nsects = 1; seg.cmdsize = (uint32_t)(sizeof(segment_command_64_t) + sizeof(section_64_t));
  std::memset(seg.segname, 0, sizeof(seg.segname)); std::memcpy(seg.segname, "__TEXT", 6);
  const uint64_t image_base = 0x100000000ull; seg.vmaddr = image_base; seg.vmsize = 0; seg.fileoff = 0; seg.filesize = 0; seg.maxprot = VM_PROT_READ | VM_PROT_EXECUTE; seg.initprot = VM_PROT_READ | VM_PROT_EXECUTE; seg.flags = 0;

  section_64_t text{}; std::memset(text.sectname, 0, sizeof(text.sectname)); std::memcpy(text.sectname, "__text", 6); std::memset(text.segname, 0, sizeof(text.segname)); std::memcpy(text.segname, "__TEXT", 6);
  text.addr = 0; text.size = size; text.offset = 0; text.align = 4; text.reloff = 0; text.nreloc = 0; text.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS; text.reserved1 = text.reserved2 = text.reserved3 = 0;

  // 3) LC_LOAD_DYLINKER /usr/lib/dyld
  const char dyld_path[] = "/usr/lib/dyld"; // NUL-terminated
  dylinker_command_t dl{}; dl.cmd = LC_LOAD_DYLINKER; dl.name = sizeof(dylinker_command_t);
  uint32_t dl_cmdsize = (uint32_t)(sizeof(dylinker_command_t) + sizeof(dyld_path));
  // align to 8 bytes for safety
  dl.cmdsize = (dl_cmdsize + 7u) & ~7u;

  // 4) LC_MAIN entry point
  entry_point_command_t ep{}; ep.cmd = LC_MAIN; ep.cmdsize = sizeof(entry_point_command_t); ep.entryoff = 0; ep.stacksize = 0;

  std::vector<uint8_t> lc; lc.reserve(512);
  auto append = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; lc.insert(lc.end(), b, b+n); };
  // Track positions to patch later
  append(&pagezero, sizeof(pagezero));
  size_t seg_pos = lc.size();
  append(&seg, sizeof(seg));
  size_t sect_pos = lc.size();
  append(&text, sizeof(text));
  // dylinker with padded string
  {
    size_t before = lc.size();
    append(&dl, sizeof(dl));
    append(dyld_path, sizeof(dyld_path));
    // pad to dl.cmdsize
    size_t pad = dl.cmdsize - (lc.size() - before);
    if (pad) { static const uint8_t z[8] = {0}; lc.insert(lc.end(), z, z + pad); }
  }
  append(&ep, sizeof(ep));

  // Set CPU type based on architecture
  uint32_t cpu_type, cpu_subtype;
  if (arch == MachOArch::ARM64) {
    cpu_type = CPU_TYPE_ARM64;
    cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
  } else {
    cpu_type = CPU_TYPE_X86_64;
    cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
  }
  
  mach_header_64_t mh{}; mh.magic = MH_MAGIC_64; mh.cputype = (int32_t)cpu_type; mh.cpusubtype = (int32_t)cpu_subtype; mh.filetype = MH_EXECUTE; mh.ncmds = 4; mh.sizeofcmds = (uint32_t)lc.size(); mh.flags = 0; mh.reserved = 0;

  const uint32_t header_size = (uint32_t)sizeof(mach_header_64_t);
  uint32_t code_off = (uint32_t)align_up(header_size + (uint32_t)lc.size(), 16);

  // Patch section + entry with proper offsets/addresses
  ((section_64_t*)(lc.data() + sect_pos))->offset = code_off;
  ((section_64_t*)(lc.data() + sect_pos))->addr   = image_base + code_off;
  // Entry command is last; compute its position
  size_t ep_pos = lc.size() - sizeof(entry_point_command_t);
  ((entry_point_command_t*)(lc.data() + ep_pos))->entryoff = code_off + entry_offset;

  uint32_t file_size = code_off + size; uint64_t vmsize = align_up(file_size, 0x1000);
  ((segment_command_64_t*)(lc.data() + seg_pos))->filesize = file_size;
  ((segment_command_64_t*)(lc.data() + seg_pos))->vmsize   = vmsize;

  std::vector<uint8_t> out; out.reserve(file_size);
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };
  emit(&mh, sizeof(mh)); emit(lc.data(), lc.size()); if (out.size() < code_off) out.resize(code_off, 0x90); emit(buffer, size);

  std::ofstream f(path, std::ios::binary); if (!f) return false; f.write((const char*)out.data(), (std::streamsize)out.size()); f.close();
  // Make executable
  #ifdef __APPLE__
  chmod(path, 0755);
  #endif
  return true;
}

// Minimal MH_OBJECT writer: one __TEXT,__text section, one global symbol
bool MachOBuilder64::write_object(const char* path,
                                  const uint8_t* buffer,
                                  uint32_t size,
                                  const char* global_symbol,
                                  uint32_t symbol_offset,
                                  MachOArch arch) {
  if (!buffer || size == 0 || !global_symbol) return false;

  // Basic structs
  struct nlist_64 { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };
  struct symtab_command { uint32_t cmd; uint32_t cmdsize; uint32_t symoff; uint32_t nsyms; uint32_t stroff; uint32_t strsize; };

  // Build load commands: LC_SEGMENT_64 + one section, LC_SYMTAB
  segment_command_64_t seg{}; seg.cmd = LC_SEGMENT_64; seg.nsects = 1; seg.cmdsize = (uint32_t)(sizeof(segment_command_64_t) + sizeof(section_64_t));
  std::memset(seg.segname, 0, sizeof(seg.segname)); std::memcpy(seg.segname, "__TEXT", 6);
  seg.vmaddr = 0; seg.vmsize = size; seg.fileoff = 0; seg.filesize = 0; seg.maxprot = VM_PROT_READ | VM_PROT_EXECUTE; seg.initprot = VM_PROT_READ | VM_PROT_EXECUTE; seg.flags = 0;

  section_64_t text{}; std::memset(text.sectname, 0, sizeof(text.sectname)); std::memcpy(text.sectname, "__text", 6);
  std::memset(text.segname, 0, sizeof(text.segname)); std::memcpy(text.segname, "__TEXT", 6);
  text.addr = 0; text.size = size; text.offset = 0; text.align = 4; text.reloff = 0; text.nreloc = 0; text.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

  symtab_command st{}; st.cmd = LC_SYMTAB; st.cmdsize = sizeof(symtab_command);

  // Build symbol and string table
  std::vector<char> strtab; strtab.push_back('\0'); // index 0 empty
  uint32_t name_off = (uint32_t)strtab.size();
  // On macOS, C symbols should have underscore prefix; allow raw when caller passes leading '_'
  if (global_symbol[0] != '_') strtab.push_back('_');
  strtab.insert(strtab.end(), global_symbol, global_symbol + std::strlen(global_symbol) + 1);

  nlist_64 sym{}; sym.n_strx = name_off; sym.n_type = 0x0F; /* N_EXT|N_SECT */ sym.n_sect = 1; sym.n_desc = 0; sym.n_value = symbol_offset; // address within section

  std::vector<uint8_t> syms; syms.resize(sizeof(nlist_64)); std::memcpy(syms.data(), &sym, sizeof(sym));

  // Assemble load commands buffer
  std::vector<uint8_t> lc; lc.reserve(256);
  auto append = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; lc.insert(lc.end(), b, b+n); };
  append(&seg, sizeof(seg)); append(&text, sizeof(text));
  append(&st, sizeof(st));

  // Set CPU type based on architecture
  uint32_t cpu_type, cpu_subtype;
  if (arch == MachOArch::ARM64) {
    cpu_type = CPU_TYPE_ARM64;
    cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
  } else {
    cpu_type = CPU_TYPE_X86_64;
    cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
  }
  
  // Header
  mach_header_64_t mh{}; mh.magic = MH_MAGIC_64; mh.cputype = (int32_t)cpu_type; mh.cpusubtype = (int32_t)cpu_subtype; mh.filetype = MH_OBJECT; mh.ncmds = 2; mh.sizeofcmds = (uint32_t)lc.size(); mh.flags = 0; mh.reserved = 0;

  // Compute layout: [hdr][lc][sect data][symtab][strtab]
  uint32_t off_hdr = 0;
  uint32_t off_lc  = off_hdr + (uint32_t)sizeof(mach_header_64_t);
  uint32_t off_sect= off_lc + (uint32_t)lc.size();
  uint32_t off_sym = (uint32_t)((off_sect + size + 15) & ~15u);
  uint32_t off_str = off_sym + (uint32_t)syms.size();

  // Patch segment/section offsets
  ((segment_command_64_t*)lc.data())->fileoff = off_sect; ((segment_command_64_t*)lc.data())->filesize = size;
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t)))->offset = off_sect; ((section_64_t*)(lc.data() + sizeof(segment_command_64_t)))->addr = 0;

  // Patch symtab
  symtab_command* stp = (symtab_command*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t));
  stp->symoff = off_sym; stp->nsyms = 1; stp->stroff = off_str; stp->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out; out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };
  emit(&mh, sizeof(mh)); emit(lc.data(), lc.size()); if (out.size() < off_sect) out.resize(off_sect, 0); emit(buffer, size);
  if (out.size() < off_sym) out.resize(off_sym, 0); emit(syms.data(), syms.size());
  emit(strtab.data(), strtab.size());

  std::ofstream f(path, std::ios::binary); if (!f) return false; f.write((const char*)out.data(), (std::streamsize)out.size()); f.close();
  return true;
}

bool MachOBuilder64::write_object_with_data(const char* path,
                                            const uint8_t* text_buffer,
                                            uint32_t text_size,
                                            const uint8_t* data_buffer,
                                            uint32_t data_size,
                                            const char* global_symbol,
                                            uint32_t symbol_offset,
                                            MachOArch arch) {
  // Mach-O header
  mach_header_64_t mh = {};
  mh.magic = 0xfeedfacf; // MH_MAGIC_64
  mh.filetype = 1; // MH_OBJECT
  mh.ncmds = 2; // LC_SEGMENT_64 for __TEXT and __DATA, LC_SYMTAB
  mh.flags = 0;
  mh.reserved = 0;

  // Set architecture
  if (arch == MachOArch::ARM64) {
    mh.cputype = 0x0100000c; // CPU_TYPE_ARM64
    mh.cpusubtype = 0; // CPU_SUBTYPE_ARM64_ALL
  } else {
    mh.cputype = 0x01000007; // CPU_TYPE_X86_64
    mh.cpusubtype = 3; // CPU_SUBTYPE_X86_64_ALL
  }

  // Build load commands
  std::vector<uint8_t> lc;

  // LC_SEGMENT_64 for __TEXT
  segment_command_64_t seg_text = {};
  seg_text.cmd = 0x19; // LC_SEGMENT_64
  seg_text.cmdsize = sizeof(segment_command_64_t) + sizeof(section_64_t);
  std::strncpy(seg_text.segname, "__TEXT", 16);
  seg_text.vmaddr = 0;
  seg_text.vmsize = text_size;
  seg_text.fileoff = 0; // Will be patched
  seg_text.filesize = text_size;
  seg_text.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_text.initprot = 5; // VM_PROT_READ | VM_PROT_EXECUTE
  seg_text.nsects = 1;
  seg_text.flags = 0;

  section_64_t sect_text = {};
  std::strncpy(sect_text.sectname, "__text", 16);
  std::strncpy(sect_text.segname, "__TEXT", 16);
  sect_text.addr = 0;
  sect_text.size = text_size;
  sect_text.offset = 0; // Will be patched
  sect_text.align = 2; // 2^2 = 4-byte alignment
  sect_text.reloff = 0;
  sect_text.nreloc = 0;
  sect_text.flags = 0x80000400; // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
  sect_text.reserved1 = 0;
  sect_text.reserved2 = 0;
  sect_text.reserved3 = 0;

  // LC_SEGMENT_64 for __DATA
  segment_command_64_t seg_data = {};
  seg_data.cmd = 0x19; // LC_SEGMENT_64
  seg_data.cmdsize = sizeof(segment_command_64_t) + sizeof(section_64_t);
  std::strncpy(seg_data.segname, "__DATA", 16);
  seg_data.vmaddr = text_size; // Start after text
  seg_data.vmsize = data_size;
  seg_data.fileoff = 0; // Will be patched
  seg_data.filesize = data_size;
  seg_data.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_data.initprot = 3; // VM_PROT_READ | VM_PROT_WRITE
  seg_data.nsects = 1;
  seg_data.flags = 0;

  section_64_t sect_data = {};
  std::strncpy(sect_data.sectname, "__data", 16);
  std::strncpy(sect_data.segname, "__DATA", 16);
  sect_data.addr = text_size; // Start after text
  sect_data.size = data_size;
  sect_data.offset = 0; // Will be patched
  sect_data.align = 3; // 2^3 = 8-byte alignment
  sect_data.reloff = 0;
  sect_data.nreloc = 0;
  sect_data.flags = 0; // S_REGULAR
  sect_data.reserved1 = 0;
  sect_data.reserved2 = 0;
  sect_data.reserved3 = 0;

  // LC_SYMTAB
  symtab_command st = {};
  st.cmd = 2; // LC_SYMTAB
  st.cmdsize = sizeof(symtab_command);

  // Add load commands
  lc.insert(lc.end(), (uint8_t*)&seg_text, (uint8_t*)&seg_text + sizeof(seg_text));
  lc.insert(lc.end(), (uint8_t*)&sect_text, (uint8_t*)&sect_text + sizeof(sect_text));
  lc.insert(lc.end(), (uint8_t*)&seg_data, (uint8_t*)&seg_data + sizeof(seg_data));
  lc.insert(lc.end(), (uint8_t*)&sect_data, (uint8_t*)&sect_data + sizeof(sect_data));
  lc.insert(lc.end(), (uint8_t*)&st, (uint8_t*)&st + sizeof(st));

  mh.sizeofcmds = (uint32_t)lc.size();

  // Calculate offsets
  uint32_t off_text = sizeof(mh) + (uint32_t)lc.size();
  off_text = (off_text + 7) & ~7; // 8-byte align
  uint32_t off_data = off_text + text_size;
  off_data = (off_data + 7) & ~7; // 8-byte align
  uint32_t off_sym = off_data + data_size;
  uint32_t off_str = off_sym + sizeof(nlist_64);

  // Build symbol table
  std::vector<uint8_t> syms(sizeof(nlist_64));
  std::vector<char> strtab;
  strtab.push_back(0); // Empty string at offset 0

  uint32_t name_off = (uint32_t)strtab.size();
  // On macOS, C symbols should have underscore prefix
  strtab.push_back('_');
  // Always use _start as the primary global symbol for executables
  const char* start_str = "_start";
  strtab.insert(strtab.end(), start_str, start_str + std::strlen(start_str) + 1);

  nlist_64 sym{};
  sym.n_strx = name_off;
  sym.n_type = 0x0F; // N_EXT | N_SECT
  sym.n_desc = 0;
  sym.n_value = symbol_offset; // address within section
  std::memcpy(syms.data(), &sym, sizeof(sym));

  // Patch offsets in load commands
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t)))->offset = off_text;
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t) + sizeof(segment_command_64_t)))->offset = off_data;
  ((segment_command_64_t*)(lc.data()))->fileoff = off_text;
  ((segment_command_64_t*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t)))->fileoff = off_data;

  // Patch symtab
  symtab_command* stp = (symtab_command*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t) + sizeof(segment_command_64_t) + sizeof(section_64_t));
  stp->symoff = off_sym;
  stp->nsyms = 1;
  stp->stroff = off_str;
  stp->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out;
  out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };

  emit(&mh, sizeof(mh));
  emit(lc.data(), lc.size());
  if (out.size() < off_text) out.resize(off_text, 0);
  emit(text_buffer, text_size);
  if (out.size() < off_data) out.resize(off_data, 0);
  emit(data_buffer, data_size);
  if (out.size() < off_sym) out.resize(off_sym, 0);
  emit(syms.data(), syms.size());
  emit(strtab.data(), strtab.size());

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();
  return true;
}

bool MachOBuilder64::write_object_with_relocations(const char* path,
                                                  const uint8_t* text_buffer,
                                                  uint32_t text_size,
                                                  const uint8_t* data_buffer,
                                                  uint32_t data_size,
                                                  const std::vector<Relocation>& relocations,
                                                  const std::vector<std::pair<std::string, uint32_t>>& symbols,
                                                  MachOArch arch) {
  // ARM64 relocation types
  static constexpr uint8_t ARM64_RELOC_PAGE21 = 5;
  static constexpr uint8_t ARM64_RELOC_PAGEOFF12 = 6;
  
  // Mach-O header
  mach_header_64_t mh = {0};
  mh.magic = 0xfeedfacf; // MH_MAGIC_64
  mh.filetype = 1; // MH_OBJECT
  mh.ncmds = 3; // LC_SEGMENT_64 for __TEXT, __DATA, and LC_SYMTAB
  mh.flags = 0;

  // Set architecture
  if (arch == MachOArch::ARM64) {
    mh.cputype = 0x0100000c; // CPU_TYPE_ARM64
    mh.cpusubtype = 0; // CPU_SUBTYPE_ARM64_ALL
  } else {
    mh.cputype = 0x01000007; // CPU_TYPE_X86_64
    mh.cpusubtype = 3; // CPU_SUBTYPE_X86_64_ALL
  }

  std::vector<uint8_t> lc;

  // LC_SEGMENT_64 for __TEXT
  segment_command_64_t seg_text = {};
  seg_text.cmd = 0x19; // LC_SEGMENT_64
  seg_text.cmdsize = sizeof(segment_command_64_t) + sizeof(section_64_t);
  std::strncpy(seg_text.segname, "__TEXT", 16);
  seg_text.vmaddr = 0;
  seg_text.vmsize = text_size;
  seg_text.fileoff = 0; // Will be patched
  seg_text.filesize = text_size;
  seg_text.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_text.initprot = 5; // VM_PROT_READ | VM_PROT_EXECUTE
  seg_text.nsects = 1;
  seg_text.flags = 0;

  section_64_t sect_text = {};
  std::strncpy(sect_text.sectname, "__text", 16);
  std::strncpy(sect_text.segname, "__TEXT", 16);
  sect_text.addr = 0;
  sect_text.size = text_size;
  sect_text.offset = 0; // Will be patched
  sect_text.align = 2; // 2^2 = 4-byte alignment
  sect_text.reloff = 0; // Will be patched
  sect_text.nreloc = relocations.size();
  sect_text.flags = 0x80000400; // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
  sect_text.reserved1 = 0;
  sect_text.reserved2 = 0;
  sect_text.reserved3 = 0;

  // LC_SEGMENT_64 for __DATA
  segment_command_64_t seg_data = {};
  seg_data.cmd = 0x19; // LC_SEGMENT_64
  seg_data.cmdsize = sizeof(segment_command_64_t) + sizeof(section_64_t);
  std::strncpy(seg_data.segname, "__DATA", 16);
  seg_data.vmaddr = text_size; // Start after text
  seg_data.vmsize = data_size;
  seg_data.fileoff = 0; // Will be patched
  seg_data.filesize = data_size;
  seg_data.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_data.initprot = 3; // VM_PROT_READ | VM_PROT_WRITE
  seg_data.nsects = 1;
  seg_data.flags = 0;

  section_64_t sect_data = {};
  std::strncpy(sect_data.sectname, "__data", 16);
  std::strncpy(sect_data.segname, "__DATA", 16);
  sect_data.addr = text_size; // Start after text
  sect_data.size = data_size;
  sect_data.offset = 0; // Will be patched
  sect_data.align = 3; // 2^3 = 8-byte alignment
  sect_data.reloff = 0;
  sect_data.nreloc = 0;
  sect_data.flags = 0; // S_REGULAR
  sect_data.reserved1 = 0;
  sect_data.reserved2 = 0;
  sect_data.reserved3 = 0;

  // LC_SYMTAB
  symtab_command st = {};
  st.cmd = 2; // LC_SYMTAB
  st.cmdsize = sizeof(symtab_command);

  // Add load commands
  lc.insert(lc.end(), (uint8_t*)&seg_text, (uint8_t*)&seg_text + sizeof(seg_text));
  lc.insert(lc.end(), (uint8_t*)&sect_text, (uint8_t*)&sect_text + sizeof(sect_text));
  lc.insert(lc.end(), (uint8_t*)&seg_data, (uint8_t*)&seg_data + sizeof(seg_data));
  lc.insert(lc.end(), (uint8_t*)&sect_data, (uint8_t*)&sect_data + sizeof(sect_data));
  lc.insert(lc.end(), (uint8_t*)&st, (uint8_t*)&st + sizeof(st));

  mh.sizeofcmds = (uint32_t)lc.size();

  // Calculate offsets
  uint32_t off_text = sizeof(mh) + (uint32_t)lc.size();
  off_text = (off_text + 7) & ~7; // 8-byte align
  uint32_t off_data = off_text + text_size;
  off_data = (off_data + 7) & ~7; // 8-byte align
  
  // Relocations come after data
  uint32_t off_reloc = off_data + data_size;
  off_reloc = (off_reloc + 7) & ~7; // 8-byte align
  
  uint32_t off_sym = off_reloc + relocations.size() * 8; // 8 bytes per relocation entry
  uint32_t off_str = off_sym + symbols.size() * sizeof(nlist_64);

  // Build symbol table
  std::vector<uint8_t> syms(symbols.size() * sizeof(nlist_64));
  std::vector<char> strtab;
  strtab.push_back(0); // Empty string at offset 0

  for (size_t i = 0; i < symbols.size(); ++i) {
    uint32_t name_off = (uint32_t)strtab.size();
    
    // Add underscore prefix for first symbol (entry point) only if not already present
    if (i == 0 && symbols[i].first[0] != '_') {
      strtab.push_back('_');
    }
    
    const char* sym_name = symbols[i].first.c_str();
    strtab.insert(strtab.end(), sym_name, sym_name + std::strlen(sym_name) + 1);

    nlist_64 sym{};
    sym.n_strx = name_off;
    if (i == 0) {
      sym.n_type = 0x0F; // N_EXT | N_SECT (external symbol in text section)
      sym.n_sect = 1; // Text section
      sym.n_value = symbols[i].second; // Offset in text section
    } else {
      sym.n_type = 0x0F; // N_EXT | N_SECT (external symbol in data section for relocations)
      sym.n_sect = 2; // Data section
      sym.n_value = text_size + symbols[i].second; // Offset in data section + text base
    }
    sym.n_desc = 0;
    
    std::memcpy(syms.data() + i * sizeof(nlist_64), &sym, sizeof(sym));
  }

  // Build relocations
  std::vector<uint8_t> reloc_data(relocations.size() * 8);
  for (size_t i = 0; i < relocations.size(); ++i) {
    const auto& rel = relocations[i];
    
    // Standard Mach-O relocation_info format
    uint32_t r_address = rel.address;
    // Standard format: [31:28]=type, [27]=extern, [26:25]=length, [24]=pcrel, [23:0]=symbolnum  
    uint32_t r_info = ((uint32_t)rel.type << 28) |          // bits 31:28 for type
                      (rel.external ? (1U << 27) : 0) |     // bit 27 for extern
                      (((uint32_t)rel.length & 0x3) << 25) |// bits 26:25 for length
                      (rel.pc_rel ? (1U << 24) : 0) |       // bit 24 for pc_rel
                      (rel.symbol_num & 0xFFFFFF);          // bits 23:0 for symbol number
    
    std::memcpy(reloc_data.data() + i * 8, &r_address, 4);
    std::memcpy(reloc_data.data() + i * 8 + 4, &r_info, 4);
  }

  // Patch offsets in load commands
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t)))->offset = off_text;
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t)))->reloff = off_reloc;
  ((section_64_t*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t) + sizeof(segment_command_64_t)))->offset = off_data;
  ((segment_command_64_t*)(lc.data()))->fileoff = off_text;
  ((segment_command_64_t*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t)))->fileoff = off_data;

  // Patch symtab
  symtab_command* stp = (symtab_command*)(lc.data() + sizeof(segment_command_64_t) + sizeof(section_64_t) + sizeof(segment_command_64_t) + sizeof(section_64_t));
  stp->symoff = off_sym;
  stp->nsyms = symbols.size();
  stp->stroff = off_str;
  stp->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out;
  out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };

  emit(&mh, sizeof(mh));
  emit(lc.data(), lc.size());
  if (out.size() < off_text) out.resize(off_text, 0);
  emit(text_buffer, text_size);
  if (out.size() < off_data) out.resize(off_data, 0);
  emit(data_buffer, data_size);
  if (out.size() < off_reloc) out.resize(off_reloc, 0);
  emit(reloc_data.data(), reloc_data.size());
  if (out.size() < off_sym) out.resize(off_sym, 0);
  emit(syms.data(), syms.size());
  emit(strtab.data(), strtab.size());

  std::ofstream f(path, std::ios::binary);
  if (!f) return false;
  f.write((const char*)out.data(), (std::streamsize)out.size());
  f.close();
  return true;
}


