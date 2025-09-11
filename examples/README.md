# AOT Compiler Examples

This directory contains comprehensive examples demonstrating the complete IR → Machine Code → Executable pipeline of the AOT compiler.

## Overview

The examples showcase the full capabilities of the compiler, from basic IR creation to advanced cross-platform executable generation with ARM64 and ELF optimizations.

## Examples

### 1. `x64_assembler_demo.cpp` 
**Original low-level assembler demonstration**
- Direct x64 machine code generation using the assembler
- Memory mapping and execution of generated code
- Comprehensive instruction set coverage
- **Run:** `./x64_assembler_demo`

### 2. `ir_hello_world.cpp`
**Basic IR → Executable pipeline**
- Creates IR module with "Hello, World!" program
- Compiles for both x86_64 and ARM64 architectures  
- Generates object files and executables
- Tests cross-platform syscall generation
- **Features:** Cross-compilation, platform awareness
- **Run:** `./ir_hello_world`

### 3. `ir_arithmetic_demo.cpp`
**Advanced arithmetic and optimization**
- Complex arithmetic expression compilation
- Type system demonstration (i8, i16, i32, i64)
- ARM64 advanced immediate encoding testing
- Optimization pass integration and impact analysis
- **Features:** Type-aware instruction selection, immediate encoding
- **Run:** `./ir_arithmetic_demo`

### 4. `ir_control_flow_demo.cpp`
**Control flow and function calls**
- Conditional branches and PHI nodes
- Loop constructs with back-edges  
- Function calls with ARM64 calling conventions
- Memory addressing mode demonstrations
- **Features:** Complex control flow graphs, calling conventions
- **Run:** `./ir_control_flow_demo`

### 5. `cross_platform_demo.cpp`
**Cross-platform and advanced ELF features**
- Multi-architecture compilation (x86_64 + ARM64)
- Advanced ELF generation with dynamic linking
- Relocation and symbol table handling
- Integration with system analysis tools (readelf, file, etc.)
- **Features:** Dynamic ELF, PT_DYNAMIC headers, relocations  
- **Run:** `./cross_platform_demo`

### 6. `performance_benchmarks.cpp`
**Performance analysis and benchmarking**
- Compilation speed vs complexity analysis
- Optimization pass impact measurement
- Memory usage profiling
- Cross-architecture performance comparison
- **Features:** Performance metrics, detailed reporting
- **Run:** `./performance_benchmarks`

## Key Features Demonstrated

### 🏗️ **IR → Machine Code Pipeline**
- Complete compilation from IR to executable binaries
- Multi-pass optimization integration
- Platform-aware code generation

### 🎯 **ARM64 Advanced Features**
- **Advanced immediate encoding** - Conservative logical immediate handling
- **Comprehensive memory addressing** - Base, immediate, scaled, and register modes  
- **Type-aware instruction selection** - LDRB/LDRH/LDR based on data types
- **Syscall execution fixes** - Proper Darwin syscall number handling

### 🗂️ **Enhanced ELF Generation**
- **Dynamic linking support** - PT_DYNAMIC, PT_INTERP program headers
- **Advanced relocations** - Function and data relocations for both architectures
- **Cross-architecture ELF** - Proper machine type and relocation mapping
- **GNU hash table API** - Fast symbol lookup (infrastructure)

### ⚡ **Optimization & Performance**
- **Constant folding** - Compile-time arithmetic evaluation
- **Dead code elimination** - Removal of unnecessary operations
- **Instruction scheduling** - Pipeline optimization analysis
- **Performance metrics** - Compilation speed and code size analysis

### 🌍 **Cross-Platform Support**
- **Multi-architecture** - x86_64 and ARM64 compilation
- **Platform awareness** - Linux vs macOS syscall handling
- **Cross-compilation** - Generate binaries for different targets
- **System integration** - Works with standard Linux/Unix tools

## Building Examples

```bash
# From project root
mkdir build && cd build
cmake ..
make

# Run individual examples
./examples/ir_hello_world
./examples/ir_arithmetic_demo
./examples/cross_platform_demo
```

## Example Output Analysis

The examples generate various test files in `/tmp/`:
- **Object files** (`*.o`) - ELF relocatable files for linking
- **Executables** - Final runnable binaries
- **Performance reports** - Detailed analysis in Markdown format

Use standard tools to analyze generated files:
```bash
# Analyze ELF structure
file /tmp/hello_world_ARM64
readelf -h /tmp/hello_world_ARM64.o

# Check dynamic dependencies  
ldd /tmp/dynamic_test  # Linux only

# View relocations and symbols
readelf -r /tmp/relocation_ARM64.o
readelf -s /tmp/cross_platform_x86_64.o
```

## Architecture-Specific Features

### ARM64 Highlights
- **Conservative immediate encoding** - Ensures correctness over optimization
- **Type-aware instructions** - Optimal instruction selection per data type
- **Memory addressing** - Full range of ARM64 addressing modes
- **64KB page alignment** - Proper ARM64 memory layout

### x86_64 Highlights  
- **REX prefix handling** - 64-bit register access
- **Complex addressing** - ModRM + SIB encoding
- **Immediate varieties** - 8/16/32/64-bit immediate handling
- **4KB page alignment** - Standard x86_64 memory layout

## Testing and Validation

Each example includes:
- ✅ **Compilation verification** - Ensures code generation succeeds
- ✅ **Size analysis** - Validates reasonable output sizes  
- ✅ **Execution testing** - Tests generated binaries where possible
- ✅ **Cross-architecture** - Validates both ARM64 and x86_64 paths
- ✅ **Error handling** - Graceful handling of platform limitations

## Integration with Test Suite

These examples complement the comprehensive test suite (`tests/test_suite.cpp`) by providing:
- **Real-world usage patterns** - How to use the compiler in practice
- **Performance characteristics** - Understanding compilation costs
- **Feature demonstrations** - Visual proof of implemented capabilities
- **Debug information** - Detailed output for troubleshooting

## Future Extensions

The example framework supports easy addition of:
- **More complex IR patterns** - Advanced control flow constructs
- **Additional architectures** - Future target support
- **Optimization techniques** - New compiler passes
- **Analysis tools** - Enhanced debugging and profiling

---

🚀 **Start with `ir_hello_world.cpp` for the basic pipeline, then explore the advanced features in the other examples!**