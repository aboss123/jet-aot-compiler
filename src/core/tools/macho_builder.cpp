#include "macho_builder.h"
#include <cstring>
#include <fstream>
#include <sys/stat.h>

// Mach-O magic numbers
static constexpr uint32_t MH_MAGIC         = 0xFEEDFACE;      /* the mach magic number */
static constexpr uint32_t MH_CIGAM         = 0xCEFAEDFE;      /* NXSwapInt(MH_MAGIC) */
static constexpr uint32_t MH_MAGIC_64      = 0xFEEDFACF;      /* the 64-bit mach magic number */
static constexpr uint32_t MH_CIGAM_64      = 0xCFFAEDFE;      /* NXSwapInt(MH_MAGIC_64) */

// Mach-O file types
static constexpr uint32_t MH_OBJECT        = 0x1;             /* relocatable object file */
static constexpr uint32_t MH_EXECUTE       = 0x2;             /* demand paged executable file */
static constexpr uint32_t MH_FVMLIB        = 0x3;             /* fixed VM shared library file */
static constexpr uint32_t MH_CORE          = 0x4;             /* core file */
static constexpr uint32_t MH_PRELOAD       = 0x5;             /* preloaded executable file */
static constexpr uint32_t MH_DYLIB         = 0x6;             /* dynamically bound shared library */
static constexpr uint32_t MH_DYLINKER      = 0x7;             /* dynamic link editor */
static constexpr uint32_t MH_BUNDLE        = 0x8;             /* dynamically bound bundle file */
static constexpr uint32_t MH_DYLIB_STUB    = 0x9;             /* shared library stub for static linking only, no section contents */
static constexpr uint32_t MH_DSYM          = 0xA;             /* companion file with only debug sections */
static constexpr uint32_t MH_KEXT_BUNDLE   = 0xB;             /* x86_64 kexts */

// Mach-O header flags
static constexpr uint32_t MH_NOUNDEFS      = 0x1;             /* the object file has no undefined references */
static constexpr uint32_t MH_INCRLINK      = 0x2;             /* the object file is the output of an incremental link against a base file and can't be link edited again */
static constexpr uint32_t MH_DYLDLINK      = 0x4;             /* the object file is input for the dynamic linker and can't be staticly link edited again */
static constexpr uint32_t MH_BINDATLOAD    = 0x8;             /* the object file's undefined references are bound by the dynamic linker when loaded. */
static constexpr uint32_t MH_PREBOUND      = 0x10;            /* the file has its dynamic undefined references prebound. */
static constexpr uint32_t MH_SPLIT_SEGS    = 0x20;            /* the file has its read-only and read-write segments split */
static constexpr uint32_t MH_LAZY_INIT     = 0x40;            /* the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete) */
static constexpr uint32_t MH_TWOLEVEL      = 0x80;            /* the image is using two-level name space bindings */
static constexpr uint32_t MH_FORCE_FLAT    = 0x100;           /* the executable is forcing all images to use flat name space bindings */
static constexpr uint32_t MH_NOMULTIDEFS   = 0x200;           /* this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used. */
static constexpr uint32_t MH_NOFIXPREBINDING = 0x400;         /* do not have dyld notify the prebinding agent about this executable */
static constexpr uint32_t MH_PREBINDABLE   = 0x800;           /* the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set. */
static constexpr uint32_t MH_ALLMODSBOUND  = 0x1000;          /* indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set. */
static constexpr uint32_t MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000;/* safe to divide up the sections into sub-sections via symbols for dead code stripping */
static constexpr uint32_t MH_CANONICAL     = 0x4000;          /* the binary has been canonicalized via the unprebind operation */
static constexpr uint32_t MH_WEAK_DEFINES  = 0x8000;          /* the final linked image contains external weak symbols */
static constexpr uint32_t MH_BINDS_TO_WEAK = 0x10000;         /* the final linked image uses weak symbols */
static constexpr uint32_t MH_ALLOW_STACK_EXECUTION = 0x20000; /* When this bit is set, all stacks in the task will be given stack execution privilege. Only used in MH_EXECUTE filetypes. */
static constexpr uint32_t MH_ROOT_SAFE     = 0x40000;         /* When this bit is set, the binary declares it is safe for use in processes with uid zero */
static constexpr uint32_t MH_SETUID_SAFE   = 0x80000;         /* When this bit is set, the binary declares it is safe for use in processes when issetugid() is true */
static constexpr uint32_t MH_NO_REEXPORTED_DYLIBS = 0x100000; /* When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported */
static constexpr uint32_t MH_PIE            = 0x200000;        /* When this bit is set, the OS will load the main executable at a random address. Only used in MH_EXECUTE filetypes. */
static constexpr uint32_t MH_DEAD_STRIPPABLE_DYLIB = 0x400000;/* Only for use on dylibs. When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib. */
static constexpr uint32_t MH_HAS_TLV_DESCRIPTORS = 0x800000;  /* Contains a section of type S_THREAD_LOCAL_VARIABLES */
static constexpr uint32_t MH_NO_HEAP_EXECUTION = 0x1000000;   /* When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes. */
static constexpr uint32_t CPU_TYPE_X86     = 7;
static constexpr uint32_t CPU_ARCH_ABI64   = 0x01000000;
static constexpr uint32_t CPU_TYPE_X86_64  = CPU_TYPE_X86 | CPU_ARCH_ABI64; // 0x01000007
static constexpr uint32_t CPU_SUBTYPE_X86_64_ALL = 3;

static constexpr uint32_t CPU_TYPE_ARM     = 12;
static constexpr uint32_t CPU_TYPE_ARM64   = CPU_TYPE_ARM | CPU_ARCH_ABI64; // 0x0100000C
static constexpr uint32_t CPU_SUBTYPE_ARM64_ALL = 0;

// Load commands
static constexpr uint32_t LC_REQ_DYLD            = 0x80000000;
static constexpr uint32_t LC_SEGMENT              = 0x1;        /* segment of this file to be mapped */
static constexpr uint32_t LC_SYMTAB               = 0x2;        /* link-edit stab symbol table info */
static constexpr uint32_t LC_SYMSEG               = 0x3;        /* link-edit gdb symbol table info (obsolete) */
static constexpr uint32_t LC_THREAD               = 0x4;        /* thread */
static constexpr uint32_t LC_UNIXTHREAD           = 0x5;        /* unix thread (includes a stack) */
static constexpr uint32_t LC_LOADFVMLIB           = 0x6;        /* load a specified fixed VM shared library */
static constexpr uint32_t LC_IDFVMLIB             = 0x7;        /* fixed VM shared library identification */
static constexpr uint32_t LC_IDENT                = 0x8;        /* object identification info (obsolete) */
static constexpr uint32_t LC_FVMFILE              = 0x9;        /* fixed VM file inclusion (internal use) */
static constexpr uint32_t LC_PREPAGE              = 0xa;        /* prepage command (internal use) */
static constexpr uint32_t LC_DYSYMTAB             = 0xb;        /* dynamic link-edit symbol table info */
static constexpr uint32_t LC_LOAD_DYLIB           = 0xc;        /* load a dynamically linked shared library */
static constexpr uint32_t LC_ID_DYLIB             = 0xd;        /* dynamically linked shared lib ident */
static constexpr uint32_t LC_LOAD_DYLINKER        = 0xe;        /* load a dynamic linker */
static constexpr uint32_t LC_ID_DYLINKER          = 0xf;        /* dynamic linker identification */
static constexpr uint32_t LC_PREBOUND_DYLIB       = 0x10;       /* modules prebound for a dynamically linked shared library */
static constexpr uint32_t LC_ROUTINES             = 0x11;       /* image routines */
static constexpr uint32_t LC_SUB_FRAMEWORK         = 0x12;       /* sub framework */
static constexpr uint32_t LC_SUB_UMBRELLA         = 0x13;       /* sub umbrella */
static constexpr uint32_t LC_SUB_CLIENT           = 0x14;       /* sub client */
static constexpr uint32_t LC_SUB_LIBRARY          = 0x15;       /* sub library */
static constexpr uint32_t LC_TWOLEVEL_HINTS       = 0x16;       /* two-level namespace lookup hints */
static constexpr uint32_t LC_PREBIND_CKSUM        = 0x17;       /* prebind checksum */
static constexpr uint32_t LC_LOAD_WEAK_DYLIB      = (0x18 | LC_REQ_DYLD); /* load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported). */
static constexpr uint32_t LC_SEGMENT_64           = 0x19;       /* 64-bit segment of this file to be mapped */
static constexpr uint32_t LC_ROUTINES_64          = 0x1a;       /* 64-bit image routines */
static constexpr uint32_t LC_UUID                 = 0x1b;       /* the uuid */
static constexpr uint32_t LC_RPATH                = (0x1c | LC_REQ_DYLD); /* runpath additions */
static constexpr uint32_t LC_CODE_SIGNATURE       = 0x1d;       /* local of code signature */
static constexpr uint32_t LC_SEGMENT_SPLIT_INFO   = 0x1e;       /* local of info to split segments */
static constexpr uint32_t LC_REEXPORT_DYLIB       = (0x1f | LC_REQ_DYLD); /* load and re-export dylib */
static constexpr uint32_t LC_LAZY_LOAD_DYLIB      = 0x20;       /* delay load of dylib until first use */
static constexpr uint32_t LC_ENCRYPTION_INFO      = 0x21;       /* encrypted segment information */
static constexpr uint32_t LC_DYLD_INFO            = 0x22;       /* compressed dyld information */
static constexpr uint32_t LC_DYLD_INFO_ONLY       = (0x22|LC_REQ_DYLD); /* compressed dyld information only */
static constexpr uint32_t LC_LOAD_UPWARD_DYLIB    = (0x23 | LC_REQ_DYLD); /* load upward dylib */
static constexpr uint32_t LC_VERSION_MIN_MACOSX   = 0x24;       /* build for MacOSX min OS version */
static constexpr uint32_t LC_VERSION_MIN_IPHONEOS = 0x25;       /* build for iPhoneOS min OS version */
static constexpr uint32_t LC_FUNCTION_STARTS      = 0x26;       /* compressed table of function start addresses */
static constexpr uint32_t LC_DYLD_ENVIRONMENT     = 0x27;       /* environment variable */
static constexpr uint32_t LC_MAIN                 = (0x28|LC_REQ_DYLD); /* replacement for LC_UNIXTHREAD */
static constexpr uint32_t LC_DATA_IN_CODE         = 0x29;       /* table of non-instructions in __text */
static constexpr uint32_t LC_SOURCE_VERSION       = 0x2A;       /* source version used to build binary */
static constexpr uint32_t LC_DYLIB_CODE_SIGN_DRS  = 0x2B;       /* Code signing DRs copied from linked dylibs */
static constexpr uint32_t LC_ENCRYPTION_INFO_64   = 0x2C;       /* 64-bit encrypted segment information */
static constexpr uint32_t LC_LINKER_OPTION        = 0x2D;       /* linker options in MH_OBJECT files */
static constexpr uint32_t LC_LINKER_OPTIMIZATION_HINT = 0x2E;   /* optimization hints in MH_OBJECT files */
static constexpr uint32_t LC_VERSION_MIN_TVOS     = 0x2F;       /* build for AppleTV min OS version */
static constexpr uint32_t LC_VERSION_MIN_WATCHOS  = 0x30;       /* build for Watch min OS version */
static constexpr uint32_t LC_NOTE                 = 0x31;       /* arbitrary data included within a Mach-O file */
static constexpr uint32_t LC_BUILD_VERSION        = 0x32;       /* build for platform min OS version */
static constexpr uint32_t LC_DYLD_EXPORTS_TRIE   = (0x33 | LC_REQ_DYLD); /* used with linkedit_data_command, payload is trie */
static constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = (0x34 | LC_REQ_DYLD); /* used with linkedit_data_command */

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
struct MachHeader64 {
    uint32_t magic;           /* mach magic number identifier */
    int32_t  cputype;         /* cpu specifier */
    int32_t  cpusubtype;      /* machine specifier */
    uint32_t filetype;        /* type of file */
    uint32_t ncmds;           /* number of load commands */
    uint32_t sizeofcmds;      /* the size of all the load commands */
    uint32_t flags;           /* flags */
    uint32_t reserved;        /* reserved, pad to 64bit */
};

struct SegmentCommand64 {
    uint32_t cmd;             /* LC_SEGMENT_64 */
    uint32_t cmdsize;         /* includes sizeof section_64 structs */
    char     segname[16];     /* segment name */
    uint64_t vmaddr;          /* memory address of this segment */
    uint64_t vmsize;          /* memory size of this segment */
    uint64_t fileoff;         /* file offset of this segment */
    uint64_t filesize;        /* amount to map from the file */
    uint32_t maxprot;         /* maximum VM protection */
    uint32_t initprot;        /* initial VM protection */
    uint32_t nsects;          /* number of sections in segment */
    uint32_t flags;           /* flags */
};

struct Section64 {
    char     sectname[16];    /* name of this section */
    char     segname[16];     /* segment this section goes in */
    uint64_t addr;            /* memory address of this section */
    uint64_t size;            /* size in bytes of this section */
    uint32_t offset;          /* file offset of this section */
    uint32_t align;           /* section alignment (power of 2) */
    uint32_t reloff;          /* file offset of relocation entries */
    uint32_t nreloc;          /* number of relocation entries */
    uint32_t flags;           /* flags (section type and attributes)*/
    uint32_t reserved1;       /* reserved (for offset or index) */
    uint32_t reserved2;       /* reserved (for count or sizeof) */
    uint32_t reserved3;       /* reserved */
};

struct EntryPointCommand {
    uint32_t cmd;             /* LC_MAIN only used in MH_EXECUTE filetypes */
    uint32_t cmdsize;         /* 24 */
    uint64_t entryoff;        /* file (__TEXT) offset of main() */
    uint64_t stacksize;       /* if not zero, initial stack size */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct DylinkerCommand { uint32_t cmd; uint32_t cmdsize; uint32_t name; /* char name[] */ };
struct SymtabCommand { uint32_t cmd; uint32_t cmdsize; uint32_t symoff; uint32_t nsyms; uint32_t stroff; uint32_t strsize; };
struct Nlist64 { uint32_t n_strx; uint8_t n_type; uint8_t n_sect; uint16_t n_desc; uint64_t n_value; };
#pragma pack(pop)

bool MachOBuilder64::write_executable(const char* path, const uint8_t* buffer, uint32_t size, uint32_t entry_offset, MachOArch arch) {
  if (buffer == nullptr || size == 0) return false;

  // Build load commands
  // 1) __PAGEZERO
  SegmentCommand64 pagezero{}; pagezero.cmd = LC_SEGMENT_64; pagezero.nsects = 0; pagezero.cmdsize = sizeof(SegmentCommand64);
  std::memset(pagezero.segname, 0, sizeof(pagezero.segname)); std::memcpy(pagezero.segname, "__PAGEZERO", 10);
  pagezero.vmaddr = 0; pagezero.vmsize = 0x100000000ull; pagezero.fileoff = 0; pagezero.filesize = 0;
  pagezero.maxprot = 0; pagezero.initprot = 0; pagezero.flags = 0;

  // 2) __TEXT with one __text section
  SegmentCommand64 segment{}; segment.cmd = LC_SEGMENT_64; segment.nsects = 1; segment.cmdsize = (uint32_t)(sizeof(SegmentCommand64) + sizeof(Section64));
  std::memset(segment.segname, 0, sizeof(segment.segname)); std::memcpy(segment.segname, "__TEXT", 6);
  const uint64_t image_base = 0x100000000ull; segment.vmaddr = image_base; segment.vmsize = 0; segment.fileoff = 0; segment.filesize = 0; segment.maxprot = VM_PROT_READ | VM_PROT_EXECUTE; segment.initprot = VM_PROT_READ | VM_PROT_EXECUTE; segment.flags = 0;

  Section64 text_section{}; std::memset(text_section.sectname, 0, sizeof(text_section.sectname)); std::memcpy(text_section.sectname, "__text", 6); std::memset(text_section.segname, 0, sizeof(text_section.segname)); std::memcpy(text_section.segname, "__TEXT", 6);
  text_section.addr = 0; text_section.size = size; text_section.offset = 0; text_section.align = 4; text_section.reloff = 0; text_section.nreloc = 0; text_section.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS; text_section.reserved1 = text_section.reserved2 = text_section.reserved3 = 0;

  // 3) LC_LOAD_DYLINKER /usr/lib/dyld
  const char dyld_path[] = "/usr/lib/dyld"; // NUL-terminated
  DylinkerCommand dylinker{}; dylinker.cmd = LC_LOAD_DYLINKER; dylinker.name = sizeof(DylinkerCommand);
  uint32_t dl_cmdsize = (uint32_t)(sizeof(DylinkerCommand) + sizeof(dyld_path));
  // align to 8 bytes for safety
  dylinker.cmdsize = (dl_cmdsize + 7u) & ~7u;

  // 4) LC_MAIN entry point
  EntryPointCommand entry_point{}; entry_point.cmd = LC_MAIN; entry_point.cmdsize = sizeof(EntryPointCommand); entry_point.entryoff = 0; entry_point.stacksize = 0;

  std::vector<uint8_t> lc; lc.reserve(512);
  auto append = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; lc.insert(lc.end(), b, b+n); };
  // Track positions to patch later
  append(&pagezero, sizeof(pagezero));
  size_t segment_pos = lc.size();
  append(&segment, sizeof(segment));
  size_t section_pos = lc.size();
  append(&text_section, sizeof(text_section));
  // dylinker with padded string
  {
    size_t before = lc.size();
    append(&dylinker, sizeof(dylinker));
    append(dyld_path, sizeof(dyld_path));
    // pad to dylinker.cmdsize
    size_t pad = dylinker.cmdsize - (lc.size() - before);
    if (pad) { static const uint8_t z[8] = {0}; lc.insert(lc.end(), z, z + pad); }
  }
  append(&entry_point, sizeof(entry_point));

  // Set CPU type based on architecture
  uint32_t cpu_type, cpu_subtype;
  if (arch == MachOArch::ARM64) {
    cpu_type = CPU_TYPE_ARM64;
    cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
  } else {
    cpu_type = CPU_TYPE_X86_64;
    cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
  }
  
  MachHeader64 mach_header{};
  mach_header.magic = MH_MAGIC_64;
  mach_header.cputype = (int32_t)cpu_type;
  mach_header.cpusubtype = (int32_t)cpu_subtype;
  mach_header.filetype = MH_EXECUTE;
  mach_header.ncmds = 4;
  mach_header.sizeofcmds = (uint32_t)lc.size();
  mach_header.flags = 0;
  mach_header.reserved = 0;

  const uint32_t header_size = (uint32_t)sizeof(MachHeader64);
  uint32_t code_offset = (uint32_t)align_up(header_size + (uint32_t)lc.size(), 16);

  // Patch section + entry with proper offsets/addresses
  ((Section64*)(lc.data() + section_pos))->offset = code_offset;
  ((Section64*)(lc.data() + section_pos))->addr   = image_base + code_offset;
  // Entry command is last; compute its position
  size_t entry_pos = lc.size() - sizeof(EntryPointCommand);
  ((EntryPointCommand*)(lc.data() + entry_pos))->entryoff = code_offset + entry_offset;

  uint32_t file_size = code_offset + size; uint64_t vm_size = align_up(file_size, 0x1000);
  ((SegmentCommand64*)(lc.data() + segment_pos))->filesize = file_size;
  ((SegmentCommand64*)(lc.data() + segment_pos))->vmsize   = vm_size;

  std::vector<uint8_t> out; out.reserve(file_size);
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };
  emit(&mach_header, sizeof(mach_header)); emit(lc.data(), lc.size()); if (out.size() < code_offset) out.resize(code_offset, 0x90); emit(buffer, size);

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

  // Build load commands: LC_SEGMENT_64 + one section, LC_SYMTAB
  SegmentCommand64 segment{}; segment.cmd = LC_SEGMENT_64; segment.nsects = 1; segment.cmdsize = (uint32_t)(sizeof(SegmentCommand64) + sizeof(Section64));
  std::memset(segment.segname, 0, sizeof(segment.segname)); std::memcpy(segment.segname, "__TEXT", 6);
  segment.vmaddr = 0; segment.vmsize = size; segment.fileoff = 0; segment.filesize = 0; segment.maxprot = VM_PROT_READ | VM_PROT_EXECUTE; segment.initprot = VM_PROT_READ | VM_PROT_EXECUTE; segment.flags = 0;

  Section64 text_section{}; std::memset(text_section.sectname, 0, sizeof(text_section.sectname)); std::memcpy(text_section.sectname, "__text", 6);
  std::memset(text_section.segname, 0, sizeof(text_section.segname)); std::memcpy(text_section.segname, "__TEXT", 6);
  text_section.addr = 0; text_section.size = size; text_section.offset = 0; text_section.align = 4; text_section.reloff = 0; text_section.nreloc = 0; text_section.flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;

  SymtabCommand symtab_cmd{}; symtab_cmd.cmd = LC_SYMTAB; symtab_cmd.cmdsize = sizeof(SymtabCommand);

  // Build symbol and string table
  std::vector<char> strtab; strtab.push_back('\0'); // index 0 empty
  uint32_t name_off = (uint32_t)strtab.size();
  // On macOS, C symbols should have underscore prefix; allow raw when caller passes leading '_'
  if (global_symbol[0] != '_') strtab.push_back('_');
  strtab.insert(strtab.end(), global_symbol, global_symbol + std::strlen(global_symbol) + 1);

  Nlist64 symbol{}; symbol.n_strx = name_off; symbol.n_type = N_EXT | N_SECT; symbol.n_sect = 1; symbol.n_desc = 0; symbol.n_value = symbol_offset; // address within section

  std::vector<uint8_t> symbols_data; symbols_data.resize(sizeof(Nlist64)); std::memcpy(symbols_data.data(), &symbol, sizeof(symbol));

  // Assemble load commands buffer
  std::vector<uint8_t> lc; lc.reserve(256);
  auto append = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; lc.insert(lc.end(), b, b+n); };
  append(&segment, sizeof(segment)); append(&text_section, sizeof(text_section));
  append(&symtab_cmd, sizeof(symtab_cmd));

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
  MachHeader64 mach_header{};
  mach_header.magic = MH_MAGIC_64;
  mach_header.cputype = (int32_t)cpu_type;
  mach_header.cpusubtype = (int32_t)cpu_subtype;
  mach_header.filetype = MH_OBJECT;
  mach_header.ncmds = 2;
  mach_header.sizeofcmds = (uint32_t)lc.size();
  mach_header.flags = 0;
  mach_header.reserved = 0;

  // Compute layout: [hdr][lc][sect data][symtab][strtab]
  uint32_t off_hdr = 0;
  uint32_t off_lc  = off_hdr + (uint32_t)sizeof(MachHeader64);
  uint32_t off_sect= off_lc + (uint32_t)lc.size();
  uint32_t off_sym = (uint32_t)((off_sect + size + 15) & ~15u);
  uint32_t off_str = off_sym + (uint32_t)symbols_data.size();

  // Patch segment/section offsets
  ((SegmentCommand64*)lc.data())->fileoff = off_sect; ((SegmentCommand64*)lc.data())->filesize = size;
  ((Section64*)(lc.data() + sizeof(SegmentCommand64)))->offset = off_sect; ((Section64*)(lc.data() + sizeof(SegmentCommand64)))->addr = 0;

  // Patch symtab
  SymtabCommand* symtab_ptr = (SymtabCommand*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64));
  symtab_ptr->symoff = off_sym; symtab_ptr->nsyms = 1; symtab_ptr->stroff = off_str; symtab_ptr->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out; out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };
  emit(&mach_header, sizeof(mach_header)); emit(lc.data(), lc.size()); if (out.size() < off_sect) out.resize(off_sect, 0); emit(buffer, size);
  if (out.size() < off_sym) out.resize(off_sym, 0); emit(symbols_data.data(), symbols_data.size());
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
  MachHeader64 mach_header = {};
  mach_header.magic = MH_MAGIC_64;
  mach_header.filetype = MH_OBJECT;
  mach_header.ncmds = 2; // LC_SEGMENT_64 for __TEXT and __DATA, LC_SYMTAB
  mach_header.flags = 0;
  mach_header.reserved = 0;

  // Set architecture
  if (arch == MachOArch::ARM64) {
    mach_header.cputype = CPU_TYPE_ARM64;
    mach_header.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
  } else {
    mach_header.cputype = CPU_TYPE_X86_64;
    mach_header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  }

  // Build load commands
  std::vector<uint8_t> lc;

  // LC_SEGMENT_64 for __TEXT
  SegmentCommand64 seg_text = {};
  seg_text.cmd = LC_SEGMENT_64;
  seg_text.cmdsize = sizeof(SegmentCommand64) + sizeof(Section64);
  std::strncpy(seg_text.segname, "__TEXT", 16);
  seg_text.vmaddr = 0;
  seg_text.vmsize = text_size;
  seg_text.fileoff = 0; // Will be patched
  seg_text.filesize = text_size;
  seg_text.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_text.initprot = 5; // VM_PROT_READ | VM_PROT_EXECUTE
  seg_text.nsects = 1;
  seg_text.flags = 0;

  Section64 sect_text = {};
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
  SegmentCommand64 seg_data = {};
  seg_data.cmd = LC_SEGMENT_64;
  seg_data.cmdsize = sizeof(SegmentCommand64) + sizeof(Section64);
  std::strncpy(seg_data.segname, "__DATA", 16);
  seg_data.vmaddr = text_size; // Start after text
  seg_data.vmsize = data_size;
  seg_data.fileoff = 0; // Will be patched
  seg_data.filesize = data_size;
  seg_data.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_data.initprot = 3; // VM_PROT_READ | VM_PROT_WRITE
  seg_data.nsects = 1;
  seg_data.flags = 0;

  Section64 sect_data = {};
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
  SymtabCommand st = {};
  st.cmd = LC_SYMTAB;
  st.cmdsize = sizeof(SymtabCommand);

  // Add load commands
  lc.insert(lc.end(), (uint8_t*)&seg_text, (uint8_t*)&seg_text + sizeof(seg_text));
  lc.insert(lc.end(), (uint8_t*)&sect_text, (uint8_t*)&sect_text + sizeof(sect_text));
  lc.insert(lc.end(), (uint8_t*)&seg_data, (uint8_t*)&seg_data + sizeof(seg_data));
  lc.insert(lc.end(), (uint8_t*)&sect_data, (uint8_t*)&sect_data + sizeof(sect_data));
  lc.insert(lc.end(), (uint8_t*)&st, (uint8_t*)&st + sizeof(st));

  mach_header.sizeofcmds = (uint32_t)lc.size();

  // Calculate offsets
  uint32_t off_text = sizeof(mach_header) + (uint32_t)lc.size();
  off_text = (off_text + 7) & ~7; // 8-byte align
  uint32_t off_data = off_text + text_size;
  off_data = (off_data + 7) & ~7; // 8-byte align
  uint32_t off_sym = off_data + data_size;
  uint32_t off_str = off_sym + sizeof(Nlist64);

  // Build symbol table
  std::vector<uint8_t> syms(sizeof(Nlist64));
  std::vector<char> strtab;
  strtab.push_back(0); // Empty string at offset 0

  uint32_t name_off = (uint32_t)strtab.size();
  // On macOS, C symbols should have underscore prefix
  strtab.push_back('_');
  // Always use _start as the primary global symbol for executables
  const char* start_str = "_start";
  strtab.insert(strtab.end(), start_str, start_str + std::strlen(start_str) + 1);

  Nlist64 sym{};
  sym.n_strx = name_off;
  sym.n_type = 0x0F; // N_EXT | N_SECT
  sym.n_desc = 0;
  sym.n_value = symbol_offset; // address within section
  std::memcpy(syms.data(), &sym, sizeof(sym));

  // Patch offsets in load commands
  ((Section64*)(lc.data() + sizeof(SegmentCommand64)))->offset = off_text;
  ((Section64*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64) + sizeof(SegmentCommand64)))->offset = off_data;
  ((SegmentCommand64*)(lc.data()))->fileoff = off_text;
  ((SegmentCommand64*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64)))->fileoff = off_data;

  // Patch symtab
  SymtabCommand* stp = (SymtabCommand*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64) + sizeof(SegmentCommand64) + sizeof(Section64));
  stp->symoff = off_sym;
  stp->nsyms = 1;
  stp->stroff = off_str;
  stp->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out;
  out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };

  emit(&mach_header, sizeof(mach_header));
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
  MachHeader64 mach_header = {0};
  mach_header.magic = MH_MAGIC_64;
  mach_header.filetype = MH_OBJECT;
  mach_header.ncmds = 3; // LC_SEGMENT_64 for __TEXT, __DATA, and LC_SYMTAB
  mach_header.flags = 0;

  // Set architecture
  if (arch == MachOArch::ARM64) {
    mach_header.cputype = CPU_TYPE_ARM64;
    mach_header.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
  } else {
    mach_header.cputype = CPU_TYPE_X86_64;
    mach_header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  }

  std::vector<uint8_t> lc;

  // LC_SEGMENT_64 for __TEXT
  SegmentCommand64 seg_text = {};
  seg_text.cmd = LC_SEGMENT_64;
  seg_text.cmdsize = sizeof(SegmentCommand64) + sizeof(Section64);
  std::strncpy(seg_text.segname, "__TEXT", 16);
  seg_text.vmaddr = 0;
  seg_text.vmsize = text_size;
  seg_text.fileoff = 0; // Will be patched
  seg_text.filesize = text_size;
  seg_text.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_text.initprot = 5; // VM_PROT_READ | VM_PROT_EXECUTE
  seg_text.nsects = 1;
  seg_text.flags = 0;

  Section64 sect_text = {};
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
  SegmentCommand64 seg_data = {};
  seg_data.cmd = LC_SEGMENT_64;
  seg_data.cmdsize = sizeof(SegmentCommand64) + sizeof(Section64);
  std::strncpy(seg_data.segname, "__DATA", 16);
  seg_data.vmaddr = text_size; // Start after text
  seg_data.vmsize = data_size;
  seg_data.fileoff = 0; // Will be patched
  seg_data.filesize = data_size;
  seg_data.maxprot = 7; // VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
  seg_data.initprot = 3; // VM_PROT_READ | VM_PROT_WRITE
  seg_data.nsects = 1;
  seg_data.flags = 0;

  Section64 sect_data = {};
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
  SymtabCommand st = {};
  st.cmd = LC_SYMTAB;
  st.cmdsize = sizeof(SymtabCommand);

  // Add load commands
  lc.insert(lc.end(), (uint8_t*)&seg_text, (uint8_t*)&seg_text + sizeof(seg_text));
  lc.insert(lc.end(), (uint8_t*)&sect_text, (uint8_t*)&sect_text + sizeof(sect_text));
  lc.insert(lc.end(), (uint8_t*)&seg_data, (uint8_t*)&seg_data + sizeof(seg_data));
  lc.insert(lc.end(), (uint8_t*)&sect_data, (uint8_t*)&sect_data + sizeof(sect_data));
  lc.insert(lc.end(), (uint8_t*)&st, (uint8_t*)&st + sizeof(st));

  mach_header.sizeofcmds = (uint32_t)lc.size();

  // Calculate offsets
  uint32_t off_text = sizeof(mach_header) + (uint32_t)lc.size();
  off_text = (off_text + 7) & ~7; // 8-byte align
  uint32_t off_data = off_text + text_size;
  off_data = (off_data + 7) & ~7; // 8-byte align
  
  // Relocations come after data
  uint32_t off_reloc = off_data + data_size;
  off_reloc = (off_reloc + 7) & ~7; // 8-byte align
  
  uint32_t off_sym = off_reloc + relocations.size() * 8; // 8 bytes per relocation entry
  uint32_t off_str = off_sym + symbols.size() * sizeof(Nlist64);

  // Build symbol table
  std::vector<uint8_t> syms(symbols.size() * sizeof(Nlist64));
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

    Nlist64 sym{};
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
    
    std::memcpy(syms.data() + i * sizeof(Nlist64), &sym, sizeof(sym));
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
  ((Section64*)(lc.data() + sizeof(SegmentCommand64)))->offset = off_text;
  ((Section64*)(lc.data() + sizeof(SegmentCommand64)))->reloff = off_reloc;
  ((Section64*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64) + sizeof(SegmentCommand64)))->offset = off_data;
  ((SegmentCommand64*)(lc.data()))->fileoff = off_text;
  ((SegmentCommand64*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64)))->fileoff = off_data;

  // Patch symtab
  SymtabCommand* stp = (SymtabCommand*)(lc.data() + sizeof(SegmentCommand64) + sizeof(Section64) + sizeof(SegmentCommand64) + sizeof(Section64));
  stp->symoff = off_sym;
  stp->nsyms = symbols.size();
  stp->stroff = off_str;
  stp->strsize = (uint32_t)strtab.size();

  // Emit file
  std::vector<uint8_t> out;
  out.reserve(off_str + (uint32_t)strtab.size());
  auto emit = [&](const void* p, size_t n){ const uint8_t* b = (const uint8_t*)p; out.insert(out.end(), b, b+n); };

  emit(&mach_header, sizeof(mach_header));
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


