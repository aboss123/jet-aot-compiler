cmake_minimum_required(VERSION 3.25)
project(AOTCompiler VERSION 1.0.0 LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =============================================================================
# PROJECT STRUCTURE
# =============================================================================
# src/
#   ├── core/           - Core components (IR, tools)
#   ├── assemblers/     - Platform-specific assemblers
#   └── backends/       - Code generation backends
# examples/             - Example programs demonstrating features
# tests/               - Test suite and benchmarks
# assembly/            - Hand-written assembly reference files
# docs/                - Documentation

# =============================================================================
# COMPILER OPTIONS
# =============================================================================
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

# =============================================================================
# CORE LIBRARIES
# =============================================================================

# IR (Intermediate Representation) Library
add_library(ir STATIC 
    src/core/ir/ir.cpp
)
target_include_directories(ir PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# x64 Assembler Library
add_library(x64_assembler STATIC 
    src/assemblers/x64-codegen.cpp
)
target_include_directories(x64_assembler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ARM64 Assembler Library  
add_library(arm64_assembler STATIC 
    src/assemblers/arm64-codegen.cpp
)
target_include_directories(arm64_assembler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Mach-O Builder Library
add_library(macho_builder STATIC 
    src/core/tools/macho_builder.cpp
)
target_include_directories(macho_builder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Module System Libraries
add_library(module_emitter STATIC 
    src/core/tools/module_emitter.cpp
)
target_include_directories(module_emitter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(systemv_abi STATIC 
    src/core/tools/systemv_abi.cpp
)
target_include_directories(systemv_abi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(module_linker STATIC 
    src/core/tools/module_linker.cpp
)
target_link_libraries(module_linker PRIVATE macho_builder)
target_include_directories(module_linker PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Backend Libraries
add_library(backend STATIC 
    src/backends/codegen/backend.cpp 
    src/backends/codegen/x64_backend.cpp 
    src/backends/codegen/arm64_backend.cpp
)
target_link_libraries(backend PRIVATE ir x64_assembler arm64_assembler macho_builder)
target_include_directories(backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Register Allocator and Optimization Library
add_library(register_allocator STATIC 
    src/backends/codegen/register_allocator.cpp
    src/backends/codegen/x64_register_set.cpp
    src/backends/codegen/arm64_register_set.cpp
    src/backends/codegen/constant_folding_pass.cpp
    src/backends/codegen/dead_code_elimination_pass.cpp
    src/backends/codegen/instruction_scheduling_pass.cpp
    src/backends/codegen/optimization_pass_manager.cpp
)
target_link_libraries(register_allocator PRIVATE ir)
target_include_directories(register_allocator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# =============================================================================
# EXAMPLES AND DEMOS
# =============================================================================

# x64 Assembler Demo - Shows basic x64 code generation capabilities
add_executable(x64_assembler_demo examples/x64_assembler_demo.cpp)
target_link_libraries(x64_assembler_demo PRIVATE x64_assembler)

# Core Tools Examples
add_executable(hello_macho src/core/tools/hello_macho.cpp)
target_link_libraries(hello_macho PRIVATE x64_assembler macho_builder)

add_executable(hello_module src/core/tools/hello_module.cpp)
target_link_libraries(hello_module PRIVATE x64_assembler module_emitter)

add_executable(abi_linker_demo src/core/tools/abi_linker_demo.cpp)
target_link_libraries(abi_linker_demo PRIVATE x64_assembler systemv_abi module_linker macho_builder)

add_executable(simple_abi_demo src/core/tools/simple_abi_demo.cpp)
target_link_libraries(simple_abi_demo PRIVATE x64_assembler systemv_abi macho_builder)

# Code Generation Examples
add_executable(emit_exe src/core/tools/emit_exe.cpp)
target_link_libraries(emit_exe PRIVATE x64_assembler)

add_executable(macho_write_exe src/core/tools/macho_write_exe.cpp)
target_link_libraries(macho_write_exe PRIVATE x64_assembler)

# =============================================================================
# TEST SUITE
# =============================================================================

# Main Test Suite
add_executable(test_suite tests/test_suite.cpp)
target_link_libraries(test_suite PRIVATE ir backend register_allocator)

# Standalone Optimization Test
add_executable(standalone_optimization_test tests/standalone_optimization_test.cpp)
target_link_libraries(standalone_optimization_test PRIVATE ir backend register_allocator)

# Relocation Test
add_executable(test_relocation tests/test_relocation.cpp)
target_link_libraries(test_relocation PRIVATE x64_assembler module_linker macho_builder)

# =============================================================================
# ASSEMBLY REFERENCE EXECUTABLES
# =============================================================================

enable_language(ASM)

# Generate assembly and link it into an executable
set(GENERATED_S "${CMAKE_CURRENT_BINARY_DIR}/generated.s")
add_custom_command(
  OUTPUT ${GENERATED_S}
  COMMAND emit_exe ${GENERATED_S}
  DEPENDS emit_exe
  COMMENT "Generating ${GENERATED_S} from code generator"
)

# Create executable with platform-specific linking
if(APPLE)
  add_executable(generated ${GENERATED_S})
  add_dependencies(generated emit_exe)
  set_target_properties(generated PROPERTIES XCODE_ATTRIBUTE_ARCHS "x86_64")
else()
  # On Linux, link without C runtime since we use syscalls directly
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/generated_exe
    COMMAND ${CMAKE_C_COMPILER} -nostdlib -nostartfiles -e main -o ${CMAKE_BINARY_DIR}/generated_exe ${GENERATED_S}
    DEPENDS ${GENERATED_S}
    COMMENT "Linking generated executable with direct syscalls"
  )
  add_custom_target(generated ALL DEPENDS ${CMAKE_BINARY_DIR}/generated_exe)
endif()

# Hello world syscall-only demos (only build on macOS)
if(APPLE)
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/hello_name_x64_exe
    COMMAND clang -arch x86_64 -e _start -Wl,-no_pie -o ${CMAKE_BINARY_DIR}/hello_name_x64_exe ${CMAKE_SOURCE_DIR}/assembly/hello_name_x64_macos.s
    DEPENDS ${CMAKE_SOURCE_DIR}/assembly/hello_name_x64_macos.s
    COMMENT "Building hello_name_x64 executable"
  )
  add_custom_target(hello_name_x64 ALL DEPENDS ${CMAKE_BINARY_DIR}/hello_name_x64_exe)

  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/hello_name_arm64_exe
    COMMAND clang -arch arm64 -e _start -Wl,-no_pie -o ${CMAKE_BINARY_DIR}/hello_name_arm64_exe ${CMAKE_SOURCE_DIR}/assembly/hello_name_arm64_macos.s
    DEPENDS ${CMAKE_SOURCE_DIR}/assembly/hello_name_arm64_macos.s
    COMMENT "Building hello_name_arm64 executable"
  )
  add_custom_target(hello_name_arm64 ALL DEPENDS ${CMAKE_BINARY_DIR}/hello_name_arm64_exe)
else()
  # On non-macOS systems, create dummy targets to avoid build errors
  add_custom_target(hello_name_x64
    COMMAND ${CMAKE_COMMAND} -E echo "hello_name_x64: Skipping macOS-specific assembly build on this platform"
  )
  add_custom_target(hello_name_arm64 
    COMMAND ${CMAKE_COMMAND} -E echo "hello_name_arm64: Skipping macOS-specific assembly build on this platform"
  )
endif()

# =============================================================================
# BUILD TARGETS SUMMARY
# =============================================================================
# Libraries:
#   - ir: Intermediate representation core
#   - x64_assembler: x64 machine code generation
#   - arm64_assembler: ARM64 machine code generation
#   - backend: Multi-architecture backend
#   - register_allocator: Register allocation and optimization
#   - macho_builder: Mach-O object file creation
#   - module_emitter: Module system
#   - module_linker: Module linking
#   - systemv_abi: System V ABI support
#
# Examples:
#   - x64_assembler_demo: Core x64 assembly features
#   - hello_macho: Basic Mach-O executable generation
#   - hello_module: Module system demonstration
#   - abi_linker_demo: ABI and linking features
#   - simple_abi_demo: Basic ABI usage
#   - emit_exe: Assembly file generation
#   - macho_write_exe: Direct executable writing
#
# Tests:
#   - test_suite: Comprehensive test suite (36 tests)
#   - standalone_optimization_test: Optimization pass testing
#   - test_relocation: Relocation functionality tests
#
# Reference:
#   - generated: Generated assembly executable
#   - hello_name_x64/arm64: Minimal syscall demos