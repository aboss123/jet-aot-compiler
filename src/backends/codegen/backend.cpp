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

#ifdef __APPLE__
  constexpr TargetPlatform NATIVE_PLATFORM = TargetPlatform::MACOS;
#elif __linux__
  constexpr TargetPlatform NATIVE_PLATFORM = TargetPlatform::LINUX;
#elif _WIN32
  constexpr TargetPlatform NATIVE_PLATFORM = TargetPlatform::WINDOWS;
#else
  constexpr TargetPlatform NATIVE_PLATFORM = TargetPlatform::LINUX;  // Default fallback
#endif

std::unique_ptr<Backend> BackendFactory::create_backend(TargetArch arch, TargetPlatform platform) {
  switch (arch) {
    case TargetArch::X86_64:
      return std::make_unique<X64Backend>(platform);
    case TargetArch::ARM64:
      return std::make_unique<ARM64Backend>(platform);
    default:
      return nullptr;
  }
}

TargetArch BackendFactory::get_native_arch() {
  return NATIVE_ARCH;
}

TargetPlatform BackendFactory::get_native_platform() {
  return NATIVE_PLATFORM;
}

std::string BackendFactory::arch_to_string(TargetArch arch) {
  switch (arch) {
    case TargetArch::X86_64: return "x86_64";
    case TargetArch::ARM64: return "arm64";
    default: return "unknown";
  }
}

std::string BackendFactory::platform_to_string(TargetPlatform platform) {
  switch (platform) {
    case TargetPlatform::MACOS: return "macOS";
    case TargetPlatform::LINUX: return "Linux";
    case TargetPlatform::WINDOWS: return "Windows";
    default: return "unknown";
  }
}

} // namespace CodeGen
