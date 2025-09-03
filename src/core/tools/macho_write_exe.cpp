#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include "assemblers/x64-codegen.h"

using namespace nextgen::jet::x64;

// Minimal Mach-O 64-bit writer for macOS x86_64 (MH_EXECUTE + LC_SEGMENT_64 + LC_MAIN)
// Produces a standalone executable containing the generated machine code.

static constexpr uint32_t MH_MAGIC_64      = 0xFEEDFACF;
static constexpr uint32_t MH_EXECUTE       = 0x2;
static constexpr uint32_t CPU_TYPE_X86     = 7;
static constexpr uint32_t CPU_ARCH_ABI64   = 0x01000000;
static constexpr uint32_t CPU_TYPE_X86_64  = CPU_TYPE_X86 | CPU_ARCH_ABI64; // 0x01000007
static constexpr uint32_t CPU_SUBTYPE_X86_64_ALL = 3;

static constexpr uint32_t LC_SEGMENT_64    = 0x19;
static constexpr uint32_t LC_MAIN          = 0x80000028;

static constexpr uint32_t VM_PROT_READ     = 0x01;
static constexpr uint32_t VM_PROT_WRITE    = 0x02;
static constexpr uint32_t VM_PROT_EXECUTE  = 0x04;

static constexpr uint32_t S_REGULAR                  = 0x0;
static constexpr uint32_t S_ATTR_SOME_INSTRUCTIONS   = 0x00000400;
static constexpr uint32_t S_ATTR_PURE_INSTRUCTIONS   = 0x80000000;

static inline uint64_t align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

#pragma pack(push, 1)
struct mach_header_64_t {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct segment_command_64_t {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64_t {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct entry_point_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};
#pragma pack(pop)

int main(int argc, char** argv) {
    const char* out_path = (argc > 1) ? argv[1] : "macho_generated";

    // 1) Generate some code: int main() { return 42; }
    Assembler a(64);
    a.movd(AX, Imm32{42});
    a.ret();
    const uint8_t* code = a.spill();
    const uint32_t code_size = (uint32_t)a.bytes();

    // Mach-O layout: [header][LC_SEGMENT_64 + section][LC_MAIN][code]
    // We'll include headers inside __TEXT segment (fileoff=0).

    mach_header_64_t mh{};
    mh.magic      = MH_MAGIC_64;
    mh.cputype    = (int32_t)CPU_TYPE_X86_64;
    mh.cpusubtype = (int32_t)CPU_SUBTYPE_X86_64_ALL;
    mh.filetype   = MH_EXECUTE;
    // We'll set ncmds/sizeofcmds after we build load commands
    mh.flags      = 0; // keep minimal
    mh.reserved   = 0;

    // Build load commands in a temporary buffer to compute sizes
    std::vector<uint8_t> loadcmds;
    auto append_bytes = [&](const void* p, size_t n){
        const uint8_t* b = reinterpret_cast<const uint8_t*>(p);
        loadcmds.insert(loadcmds.end(), b, b + n);
    };

    // LC_SEGMENT_64 with one __text section
    segment_command_64_t seg{};
    seg.cmd      = LC_SEGMENT_64;
    // cmdsize = sizeof(segment) + nsects*sizeof(section)
    seg.nsects   = 1;
    seg.cmdsize  = (uint32_t)(sizeof(segment_command_64_t) + sizeof(section_64_t));
    std::memset(seg.segname, 0, sizeof(seg.segname));
    std::memcpy(seg.segname, "__TEXT", 6);
    // Use typical 64-bit image base
    const uint64_t image_base = 0x100000000ull;
    // We'll put entire file in this segment; set fileoff=0
    // sizes will be filled after we know file size
    seg.vmaddr   = image_base;
    seg.vmsize   = 0; // fill later
    seg.fileoff  = 0;
    seg.filesize = 0; // fill later
    seg.maxprot  = VM_PROT_READ | VM_PROT_EXECUTE;
    seg.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    seg.flags    = 0;

    section_64_t text{};
    std::memset(text.sectname, 0, sizeof(text.sectname));
    std::memcpy(text.sectname, "__text", 6);
    std::memset(text.segname, 0, sizeof(text.segname));
    std::memcpy(text.segname, "__TEXT", 6);
    // We'll place code right after header+loadcmds; fill later
    text.addr    = 0; // fill later (image_base + file offset)
    text.size    = code_size;
    text.offset  = 0; // fill later (file offset to code)
    text.align   = 4; // 16-byte alignment
    text.reloff  = 0;
    text.nreloc  = 0;
    text.flags   = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
    text.reserved1 = 0;
    text.reserved2 = 0;
    text.reserved3 = 0;

    append_bytes(&seg, sizeof(seg));
    append_bytes(&text, sizeof(text));

    // LC_MAIN entry point
    entry_point_command_t maincmd{};
    maincmd.cmd     = LC_MAIN;
    maincmd.cmdsize = sizeof(entry_point_command_t);
    // entryoff will be file offset to code; fill later
    maincmd.entryoff  = 0; // fill later
    maincmd.stacksize = 0; // default
    append_bytes(&maincmd, sizeof(maincmd));

    // Now compute file offsets
    const uint32_t header_size = (uint32_t)sizeof(mach_header_64_t);
    const uint32_t loadcmds_size = (uint32_t)loadcmds.size();
    uint32_t file_off_code = header_size + loadcmds_size;
    // Align code start to 16
    file_off_code = (uint32_t)align_up(file_off_code, 16);

    // Patch section and entry
    section_64_t* text_ptr = reinterpret_cast<section_64_t*>(&loadcmds[sizeof(segment_command_64_t)]);
    text_ptr->offset = file_off_code;
    text_ptr->addr   = image_base + file_off_code;

    entry_point_command_t* ep_ptr = reinterpret_cast<entry_point_command_t*>(&loadcmds[sizeof(segment_command_64_t) + sizeof(section_64_t)]);
    ep_ptr->entryoff = file_off_code;

    // Compute full file size and set segment sizes
    uint32_t file_size = file_off_code + code_size;
    // No additional padding required; for vmsize round up to 4K
    uint64_t vmsize = align_up(file_size, 0x1000);

    segment_command_64_t* seg_ptr = reinterpret_cast<segment_command_64_t*>(&loadcmds[0]);
    seg_ptr->filesize = file_size;
    seg_ptr->vmsize   = vmsize;

    // Fill header counts
    mh.ncmds      = 2;
    mh.sizeofcmds = loadcmds_size;

    // 2) Write file
    std::vector<uint8_t> out;
    out.reserve(file_size);
    auto emit = [&](const void* p, size_t n){
        const uint8_t* b = reinterpret_cast<const uint8_t*>(p);
        out.insert(out.end(), b, b + n);
    };

    emit(&mh, sizeof(mh));
    emit(loadcmds.data(), loadcmds.size());
    // pad to code offset
    if (out.size() < file_off_code) out.resize(file_off_code, 0x90); // NOPs
    emit(code, code_size);

    std::ofstream f(out_path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "Failed to open output: %s\n", out_path);
        return 1;
    }
    f.write(reinterpret_cast<const char*>(out.data()), (std::streamsize)out.size());
    f.close();
    // Make it executable
    chmod(out_path, 0755);

    std::printf("Wrote Mach-O x86_64 executable: %s (%u bytes)\n", out_path, (unsigned)out.size());
    std::printf("Run with: arch -x86_64 %s ; echo $? (should be 42)\n", out_path);
    return 0;
}


