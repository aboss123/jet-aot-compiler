#include "backends/codegen/backend.h"
#include "x64_backend.h"
#include "arm64_backend.h"
#include <memory>

namespace CodeGen {

#ifdef __x86_64__
  constexpr TargetArch NATIVE_ARCH = TargetArch::X86_64;
#elif __aarch64__
  constexpr TargetArch NATIVE_ARCH = TargetArch::ARM64;
#else
  constexpr TargetArch NATIVE_ARCH = TargetArch::X86_64;  // Default fallback
#endif

std::unique_ptr<Backend> BackendFactory::create_backend(TargetArch arch) {
  switch (arch) {
    case TargetArch::X86_64:
      return std::make_unique<X64Backend>();
    case TargetArch::ARM64:
      return std::make_unique<ARM64Backend>();
    default:
      return nullptr;
  }
}

TargetArch BackendFactory::get_native_arch() {
  return NATIVE_ARCH;
}

std::string BackendFactory::arch_to_string(TargetArch arch) {
  switch (arch) {
    case TargetArch::X86_64: return "x86_64";
    case TargetArch::ARM64: return "arm64";
    default: return "unknown";
  }
}

} // namespace CodeGen
