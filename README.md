# Jet AOT Compiler

[![Build Status](https://github.com/aboss123/jet-aot-compiler/workflows/CI/badge.svg)](https://github.com/aboss123/jet-aot-compiler/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/aboss123/jet-aot-compiler)

A comprehensive **Ahead-of-Time (AOT) compiler framework** supporting multiple architectures with advanced code generation, optimization, and linking capabilities. This project demonstrates modern compiler design patterns including IR-based compilation, register allocation, optimization passes, and cross-platform code generation.

## 🌟 Key Features

- **Multi-Architecture Support**: x86-64 and ARM64 code generation
- **IR-based Compilation Pipeline**: Type-safe intermediate representation with validation
- **Advanced Optimization**: Constant folding, dead code elimination, instruction scheduling
- **Smart Register Allocation**: Architecture-specific register management
- **Object File Generation**: Native Mach-O format support with relocations
- **Module System**: Advanced linking and ABI compliance
- **Comprehensive Testing**: 36 automated tests covering all components

## 📁 Project Structure

```
jet-aot-compiler/
├── src/                          # Core source code
│   ├── core/                     # Core components
│   │   ├── ir/                   # Intermediate representation
│   │   └── tools/                # Build tools (Mach-O, linker, ABI)
│   ├── assemblers/               # Platform-specific assemblers
│   │   ├── x64-codegen.{cpp,h}   # x86-64 machine code generation
│   │   └── arm64-codegen.{cpp,h} # ARM64 machine code generation
│   └── backends/                 # Code generation backends
│       └── codegen/              # Backend implementations & optimization
├── examples/                     # Example programs and demos
├── tests/                        # Test suite and benchmarks
├── assembly/                     # Hand-written assembly reference files
├── cmake-build-debug/            # CMake build directory
└── docs/                         # Documentation (auto-generated)
```

## 🚀 Quick Start

### Prerequisites

- **C++20** compatible compiler (GCC 10+, Clang 12+, or MSVC 2019+)
- **CMake 3.25+**
- **macOS** (for Mach-O target support)

### Building

```bash
# Clone the repository
git clone https://github.com/aboss123/jet-aot-compiler.git
cd jet-aot-compiler

# Create build directory and configure
mkdir -p cmake-build-debug && cd cmake-build-debug
cmake ..

# Build all targets
make -j$(nproc)

# Or build specific targets
make test_suite                    # Build test suite
make x64_assembler_demo           # Build main demo
make hello_macho                  # Build Mach-O example
```

### Running Tests

```bash
# Run comprehensive test suite (36 tests)
./test_suite

# Run optimization-specific tests
./standalone_optimization_test

# Run relocation and linking tests
./test_relocation
```

## 🎯 Usage Examples

### Basic x64 Assembly Generation

```bash
# Run the main demonstration program
./x64_assembler_demo
```

This demonstrates:
- Simple function generation (`return 42`)
- Parameter handling and arithmetic
- Conditional logic and branching
- Loop constructs and memory operations
- Advanced instruction sets and optimizations

### Object File Generation

```bash
# Generate and link Mach-O executable
./hello_macho

# Create assembly files
./emit_exe output.s
clang -arch x86_64 output.s -o executable
```

### Module System

```bash
# Demonstrate module linking
./abi_linker_demo

# Test ABI compliance
./simple_abi_demo
```

## 🔧 Architecture Overview

### Compilation Pipeline

```
Source Code → IR Generation → Optimization Passes → Code Generation → Object Files → Linking
```

1. **IR Generation**: Convert input to type-safe intermediate representation
2. **Optimization**: Apply constant folding, dead code elimination, instruction scheduling  
3. **Code Generation**: Target-specific machine code generation
4. **Object Files**: Native Mach-O format with relocations and symbols
5. **Linking**: Module linking with ABI compliance

### Core Components

#### IR System (`src/core/ir/`)
- Type-safe intermediate representation
- Safety validation and analysis
- Statistics and debugging support
- Atomic operation modeling

#### Assemblers (`src/assemblers/`)
- **x64-codegen**: Complete x86-64 instruction set
  - All addressing modes and operand types
  - Labels, jumps, and control flow
  - Function prologue/epilogue generation
  - Advanced instructions (shifts, division, memory ops)

- **arm64-codegen**: ARM64/AArch64 instruction set
  - NEON SIMD support
  - Exception handling
  - System call interface

#### Backends (`src/backends/`)
- **Multi-Architecture Backend**: Unified interface for code generation
- **Register Allocation**: Smart register assignment with spilling
- **Optimization Passes**: 
  - Constant folding with value propagation
  - Dead code elimination 
  - Instruction scheduling for pipeline optimization

#### Build Tools (`src/core/tools/`)
- **Mach-O Builder**: Native object file generation
- **Module System**: Advanced linking and symbol resolution
- **System V ABI**: Standard calling convention support

## 📊 Testing & Validation

The project includes a comprehensive test suite with **36 automated tests**:

### Test Categories

- **IR Tests** (9): Type system, validation, analysis
- **Backend Tests** (6): ARM64 and x86-64 code generation  
- **Integration Tests** (3): Multi-architecture compilation, performance
- **AOT Compiler Tests** (4): System calls, cross-platform compatibility
- **Instruction Tests** (4): Arithmetic, bitwise, complex expressions
- **Error Handling Tests** (2): Edge cases and invalid inputs
- **Register Allocation Tests** (5): Basic allocation, strategies, high pressure
- **Optimization Tests** (3): All optimization passes

### Test Results

```
✅ All 36 tests passing
✅ Cross-platform compatibility verified
✅ Performance benchmarks included
✅ Memory safety validated
```

## 🛠️ Build Targets

### Libraries

| Target | Description |
|--------|-------------|
| `ir` | Intermediate representation core |
| `x64_assembler` | x86-64 machine code generation |
| `arm64_assembler` | ARM64 machine code generation |
| `backend` | Multi-architecture backend |
| `register_allocator` | Register allocation and optimization |
| `macho_builder` | Mach-O object file creation |
| `module_emitter` | Module system |
| `module_linker` | Module linking |
| `systemv_abi` | System V ABI support |

### Examples

| Target | Description |
|--------|-------------|
| `x64_assembler_demo` | Core x64 assembly features demonstration |
| `hello_macho` | Basic Mach-O executable generation |
| `hello_module` | Module system demonstration |
| `abi_linker_demo` | ABI and linking features |
| `simple_abi_demo` | Basic ABI usage |
| `emit_exe` | Assembly file generation |
| `macho_write_exe` | Direct executable writing |

### Tests

| Target | Description |
|--------|-------------|
| `test_suite` | Comprehensive test suite (36 tests) |
| `standalone_optimization_test` | Optimization pass testing |
| `test_relocation` | Relocation functionality tests |

### Reference Executables

| Target | Description |
|--------|-------------|
| `generated` | Generated assembly executable |
| `hello_name_x64` | Minimal x64 syscall demo |
| `hello_name_arm64` | Minimal ARM64 syscall demo |

## 🧪 Development & Testing

### Adding New Tests

Tests are located in `tests/` and use a custom testing framework:

```cpp
DEFINE_TEST_SUITE("MyNewSuite") {
    DEFINE_TEST("MyTest") {
        // Test implementation
        TEST_ASSERT(condition, "Error message");
    }
}
```

### Adding New Architecture Support

1. Create new assembler in `src/assemblers/`
2. Implement backend in `src/backends/codegen/`
3. Add register set in `src/backends/codegen/`
4. Update CMakeLists.txt
5. Add architecture-specific tests

### Code Style

- **C++20** with modern idioms
- RAII and smart pointer usage
- Comprehensive error handling
- Extensive documentation and comments

## 🔍 Advanced Features

### Optimization Pipeline

The compiler includes sophisticated optimization passes:

```cpp
OptimizationPassManager manager;
manager.addPass(std::make_unique<ConstantFoldingPass>());
manager.addPass(std::make_unique<DeadCodeEliminationPass>());  
manager.addPass(std::make_unique<InstructionSchedulingPass>());
manager.runAll(module);
```

### Register Allocation

Smart register allocation with interference graphs:

```cpp
RegisterAllocator allocator(RegisterSet::x64());
auto assignment = allocator.allocate(function, AllocationStrategy::GRAPH_COLORING);
```

### Object File Generation

Native Mach-O support with relocations:

```cpp
MachoBuilder builder;
builder.addSection(".text", code_bytes);
builder.addSymbol("_main", 0x1000);
builder.writeObjectFile("output.o");
```

## 📚 Documentation

- **API Documentation**: Generated from source comments
- **Architecture Guide**: Detailed design documentation  
- **Performance Analysis**: Benchmarking and profiling results
- **Examples**: Comprehensive usage examples

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is open source and available under standard licensing terms.

---

**AOT Compiler Framework** - Modern compiler design with multi-architecture support, advanced optimization, and comprehensive testing. Perfect for learning compiler construction or building production code generation systems.