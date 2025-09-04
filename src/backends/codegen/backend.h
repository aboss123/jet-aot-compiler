#pragma once
#include "core/ir/ir.h"
#include <memory>

namespace CodeGen {

// Abstract backend interface
class Backend {
public:
  virtual ~Backend() = default;
  
  // Compile IR module to native code
  virtual bool compile_module(const IR::Module& module) = 0;
  
  // Get generated code
  virtual const uint8_t* get_code() const = 0;
  virtual size_t get_code_size() const = 0;
  
  // Write to object file
  virtual bool write_object(const std::string& path, const std::string& entry_symbol = "main") = 0;
  
  // Link to executable (via system linker)
  virtual bool link_executable(const std::string& obj_path, const std::string& exe_path) = 0;
};

// Factory for creating backends
enum class TargetArch { X86_64, ARM64 };
enum class TargetPlatform { MACOS, LINUX, WINDOWS };

class BackendFactory {
public:
  static std::unique_ptr<Backend> create_backend(TargetArch arch, TargetPlatform platform = get_native_platform());
  static TargetArch get_native_arch();
  static TargetPlatform get_native_platform();
  static std::string arch_to_string(TargetArch arch);
  static std::string platform_to_string(TargetPlatform platform);
};

} // namespace CodeGen
