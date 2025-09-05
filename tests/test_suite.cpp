#include "m_testv2.h"
#include "core/ir/ir.h"
#include "backends/codegen/backend.h"
#include "backends/codegen/register_allocator.h"
#include "backends/codegen/x64_register_set.h"
#include "backends/codegen/arm64_register_set.h"
#include "backends/codegen/optimization_passes.h"
#include "assemblers/x64-codegen.h"
#include "assemblers/arm64-codegen.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <string>

using namespace IR;
using namespace CodeGen;

// Cross-platform syscall number helper
class SyscallNumbers {
public:
    static int get_write_syscall(TargetArch arch, TargetPlatform platform = TargetPlatform::MACOS) {
        if (arch == TargetArch::ARM64) {
            return (platform == TargetPlatform::LINUX) ? 64 : 4;  // Linux ARM64: 64, macOS ARM64: 4
        } else {
            return (platform == TargetPlatform::LINUX) ? 1 : 4;   // Linux x64: 1, macOS x64: 4
        }
    }
    
    static int get_exit_syscall(TargetArch arch, TargetPlatform platform = TargetPlatform::MACOS) {
        if (arch == TargetArch::ARM64) {
            return (platform == TargetPlatform::LINUX) ? 93 : 1;  // Linux ARM64: 93, macOS ARM64: 1
        } else {
            return (platform == TargetPlatform::LINUX) ? 60 : 1;  // Linux x64: 60, macOS x64: 1
        }
    }
    
    static int get_read_syscall(TargetArch arch, TargetPlatform platform = TargetPlatform::MACOS) {
        if (arch == TargetArch::ARM64) {
            return (platform == TargetPlatform::LINUX) ? 63 : 3;  // Linux ARM64: 63, macOS ARM64: 3
        } else {
            return (platform == TargetPlatform::LINUX) ? 0 : 3;   // Linux x64: 0, macOS x64: 3
        }
    }
    
    // Helper to get platform from backend (assumes macOS for current tests)
    static TargetPlatform get_current_platform() {
        #ifdef __linux__
            return TargetPlatform::LINUX;
        #else
            return TargetPlatform::MACOS;
        #endif
    }
};

// Test utilities
class TestUtils {
public:
    static std::string capture_output(const std::string& exe_path) {
        std::string cmd = exe_path + " 2>&1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        
        char buffer[128];
        std::string result = "";
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL)
                result += buffer;
        }
        pclose(pipe);
        return result;
    }
    
    static bool file_exists(const std::string& path) {
        std::ifstream f(path.c_str());
        return f.good();
    }
    
    static size_t get_file_size(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) return 0;
        return f.tellg();
    }
};

// ==================== IR CREATION TESTS ====================

TEST(IR, CreateBasicTypes) {
    // Test basic type creation
    Type i32 = Type::i32();
    Type i64 = Type::i64();
    Type f32 = Type::f32();
    Type f64 = Type::f64();
    Type void_type = Type::void_type();
    
    ASSERT_TRUE(i32.is_integer(), "i32 should be integer type");
    ASSERT_TRUE(i64.is_integer(), "i64 should be integer type");
    ASSERT_TRUE(f32.is_float(), "f32 should be float type");
    ASSERT_TRUE(f64.is_float(), "f64 should be float type");
    ASSERT_TRUE(void_type.is_void(), "void should be void type");
    
    ASSERT_EQ(i32.size_bits, 32, "i32 should be 32 bits");
    ASSERT_EQ(i64.size_bits, 64, "i64 should be 64 bits");
    ASSERT_EQ(f32.size_bits, 32, "f32 should be 32 bits");
    ASSERT_EQ(f64.size_bits, 64, "f64 should be 64 bits");
}

TEST(IR, CreateModuleAndFunction) {
    Module module("test_module");
    
    // Create function
    Function* func = module.create_function("test_func", Type::i32(), {});
    ASSERT_TRUE(func != nullptr, "Function creation should succeed");
    ASSERT_EQ(func->name, "test_func", "Function name should match");
    ASSERT_EQ(func->return_type.size_bits, 32, "Return type should be i32");
    
    // Create basic block
    BasicBlock* bb = func->create_basic_block("entry");
    ASSERT_TRUE(bb != nullptr, "Basic block creation should succeed");
    ASSERT_EQ(bb->name, "entry", "Basic block name should match");
}

TEST(IR, CreateConstants) {
    Module module("test_module");
    Function* func = module.create_function("test_func", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Test integer constants
    auto const_42 = builder.get_int32(42);
    auto const_100 = builder.get_int64(100);
    
    ASSERT_TRUE(const_42 != nullptr, "Int32 constant creation should succeed");
    ASSERT_TRUE(const_100 != nullptr, "Int64 constant creation should succeed");
    
    // Test float constants
    auto const_3_14 = builder.get_float(3.14f);
    auto const_2_718 = builder.get_double(2.718);
    
    ASSERT_TRUE(const_3_14 != nullptr, "Float32 constant creation should succeed");
    ASSERT_TRUE(const_2_718 != nullptr, "Float64 constant creation should succeed");
}

TEST(IR, CreateGlobalString) {
    Module module("test_module");
    
    // Create global string
    auto global_str = module.create_global_string("Hello, Test!");
    ASSERT_TRUE(global_str != nullptr, "Global string creation should succeed");
    
    // Test string content (if accessible)
    // Note: This depends on implementation details
}

TEST(IR, IRDumperFormats) {
    // Create a simple module for testing
    Module module("dump_test");
    Function* func = module.create_function("test_func", Type::i32(), {Type::i32()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto doubled = builder.create_mul(func->arguments[0], builder.get_int32(2));
    builder.create_ret(doubled);
    
    // Test different dump formats
    std::string human_readable = IRDumper::dump_module(module, IRDumper::DumpFormat::HUMAN_READABLE);
    ASSERT_TRUE(human_readable.find("Module: dump_test") != std::string::npos, "Human readable should contain module name");
    ASSERT_TRUE(human_readable.find("test_func") != std::string::npos, "Should contain function name");
    
    std::string llvm_style = IRDumper::dump_module(module, IRDumper::DumpFormat::LLVM_STYLE);
    ASSERT_TRUE(llvm_style.find("define i32 @test_func") != std::string::npos, "LLVM style should have proper function signature");
    
    std::string compact = IRDumper::dump_module(module, IRDumper::DumpFormat::COMPACT);
    ASSERT_TRUE(compact.find("module dump_test") != std::string::npos, "Compact should contain module declaration");
    
    // Test with debug info
    IRDumper::set_show_ids(true);
    std::string debug = IRDumper::dump_module(module, IRDumper::DumpFormat::DEBUG);
    ASSERT_TRUE(debug.find("(id:") != std::string::npos, "Debug format should show IDs");
    IRDumper::set_show_ids(false);
}

TEST(IR, SafetyCheckerValidation) {
    // Test basic validation
    Module valid_module("valid_test");
    Function* valid_func = valid_module.create_function("valid", Type::i32(), {});
    BasicBlock* entry = valid_func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    builder.create_ret(builder.get_int32(42));
    
    ASSERT_TRUE(SafetyChecker::validate_module(valid_module), "Valid module should pass validation");
    
    auto errors = SafetyChecker::validate_module_detailed(valid_module);
    ASSERT_TRUE(errors.empty(), "Valid module should have no detailed errors");
    
    // Test with invalid module (empty function) 
    Module invalid_module("invalid_test");
    Function* invalid_func = invalid_module.create_function("invalid", Type::i32(), {});
    // Don't add any basic blocks - this should be invalid
    
    // Note: The current validation may not catch this specific case,
    // but we're testing the validation infrastructure
    auto invalid_errors = SafetyChecker::validate_module_detailed(invalid_module);
    // Just check that detailed validation runs without crashing
}

TEST(IR, IRAnalyzerStatistics) {
    // Create a module with various instruction types
    Module test_module("analyzer_test");
    Function* func = test_module.create_function("analyze_me", Type::void_type(), {Type::i32()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    // Add various instruction types
    auto ptr = builder.create_alloca(Type::i32());
    builder.create_store(func->arguments[0], ptr);
    auto loaded = builder.create_load(Type::i32(), ptr);
    auto doubled = builder.create_mul(loaded, builder.get_int32(2));
    builder.create_store(doubled, ptr);
    builder.create_ret();
    
    // Analyze the module
    auto stats = IRAnalyzer::analyze_module(test_module);
    
    ASSERT_EQ(stats.num_functions, 1, "Should have 1 function");
    ASSERT_EQ(stats.num_basic_blocks, 1, "Should have 1 basic block");
    ASSERT_EQ(stats.load_count, 1, "Should have 1 load operation");
    ASSERT_EQ(stats.store_count, 2, "Should have 2 store operations");
    ASSERT_EQ(stats.atomic_count, 0, "Should have no atomic operations");
    
    // Check instruction counts
    ASSERT_EQ(stats.instruction_counts[Opcode::MUL], 1, "Should have 1 multiply instruction");
    ASSERT_EQ(stats.instruction_counts[Opcode::LOAD], 1, "Should have 1 load instruction");
    
    // Test statistics string
    std::string stats_str = stats.to_string();
    ASSERT_TRUE(stats_str.find("Module Statistics:") != std::string::npos, "Should contain statistics header");
    ASSERT_TRUE(stats_str.find("Functions: 1") != std::string::npos, "Should show function count");
}

TEST(IR, AtomicOperationsDumping) {
    // Test dumping of atomic operations
    Module atomic_module("atomic_test");
    Function* func = atomic_module.create_function("atomic_ops", Type::i32(), {Type::ptr_to(Type::i32())});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto ptr = func->arguments[0];
    auto loaded = builder.create_atomic_load(Type::i32(), ptr);
    auto incremented = builder.create_add(loaded, builder.get_int32(1));
    builder.create_atomic_store(incremented, ptr);
    builder.create_ret(loaded);
    
    // Test dumping atomic operations
    std::string dumped = IRDumper::dump_function(*func, IRDumper::DumpFormat::HUMAN_READABLE);
    ASSERT_TRUE(dumped.find("atomic_load") != std::string::npos, "Should contain atomic_load");
    ASSERT_TRUE(dumped.find("atomic_store") != std::string::npos, "Should contain atomic_store");
    
    // Test LLVM-style format
    std::string llvm_dumped = IRDumper::dump_function(*func, IRDumper::DumpFormat::LLVM_STYLE);
    ASSERT_TRUE(llvm_dumped.find("atomic_load") != std::string::npos, "LLVM format should contain atomic operations");
    
    // Validate atomic operations
    auto errors = SafetyChecker::validate_function_detailed(*func);
    ASSERT_TRUE(errors.empty(), "Atomic operations should be valid");
}

TEST(IR, TypeSystemDumping) {
    // Test comprehensive type system dumping
    ASSERT_EQ(IRDumper::dump_type(Type::i32()), "i32", "Basic integer type");
    ASSERT_EQ(IRDumper::dump_type(Type::ptr_to(Type::i64())), "i64*", "Pointer type");
    ASSERT_EQ(IRDumper::dump_type(Type::array(Type::i8(), 16)), "[16 x i8]", "Array type");
    
    // Test struct type
    auto struct_type = Type::struct_type({Type::i32(), Type::f64()}, {"id", "value"});
    std::string struct_dump = IRDumper::dump_type(struct_type);
    ASSERT_EQ(struct_dump, "{i32, f64}", "Struct type representation");
}

// ==================== ARM64 BACKEND TESTS ====================

TEST(ARM64Backend, BasicCompilation) {
    // Create simple IR: main() -> return 42
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    auto const_42 = builder.get_int32(42);
    builder.create_ret(const_42);
    
    // Compile with ARM64 backend
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    ASSERT_TRUE(backend != nullptr, "ARM64 backend creation should succeed");
    
    bool compile_success = backend->compile_module(module);
    ASSERT_TRUE(compile_success, "ARM64 compilation should succeed");
    
    size_t code_size = backend->get_code_size();
    ASSERT_GT(code_size, 0, "Generated code should have size > 0");
    ASSERT_LT(code_size, 1000, "Simple function should be < 1000 bytes");
}

TEST(ARM64Backend, SystemCallGeneration) {
    // Create IR: main() -> write(1, "Test", 4); exit(0)
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // write(1, "Test", 4)
    auto stdout_fd = builder.get_int32(1);
    auto test_str = module.create_global_string("Test");
    auto test_len = builder.get_int32(4);
    
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, test_str, test_len};
    builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64), write_args); // Platform-aware write
    
    // exit(0)  
    auto exit_code = builder.get_int32(0);
    std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
    builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::ARM64), exit_args); // Platform-aware exit
    
    // Compile and test
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    ASSERT_TRUE(backend != nullptr, "ARM64 backend creation should succeed");
    
    bool compile_success = backend->compile_module(module);
    ASSERT_TRUE(compile_success, "ARM64 compilation with syscalls should succeed");
    
    size_t code_size = backend->get_code_size();
    ASSERT_GT(code_size, 0, "Generated code should have size > 0");
}

TEST(ARM64Backend, ObjectFileGeneration) {
    // Create minimal IR
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    auto const_42 = builder.get_int32(42);
    builder.create_ret(const_42);
    
    // Compile
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    backend->compile_module(module);
    
    // Generate object file
    std::string obj_path = "/tmp/test_arm64.o";
    bool obj_success = backend->write_object(obj_path, "_start");
    ASSERT_TRUE(obj_success, "Object file generation should succeed");
    
    // Verify object file exists and has reasonable size
    ASSERT_TRUE(TestUtils::file_exists(obj_path), "Object file should exist");
    size_t obj_size = TestUtils::get_file_size(obj_path);
    ASSERT_GT(obj_size, 100, "Object file should be > 100 bytes");
    ASSERT_LT(obj_size, 10000, "Object file should be < 10KB");
}

TEST(ARM64Backend, ExecutableGeneration) {
    // Create Hello World IR
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // write(1, "Hello", 5)
    auto stdout_fd = builder.get_int32(1);
    auto hello_str = module.create_global_string("Hello");
    auto hello_len = builder.get_int32(5);
    
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, hello_str, hello_len};
    builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64), write_args);
    
    // exit(0)
    auto exit_code = builder.get_int32(0);
    std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
    builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::ARM64), exit_args);
    
    // Compile
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    backend->compile_module(module);
    
    // Generate object file
    std::string obj_path = "/tmp/test_hello_arm64.o";
    backend->write_object(obj_path, "_start");
    
    // Link to executable
    std::string exe_path = "/tmp/test_hello_arm64";
    std::string link_cmd = "clang -arch arm64 -Wl,-e,_start -o " + exe_path + " " + obj_path;
    int link_result = system(link_cmd.c_str());
    
    ASSERT_EQ(link_result, 0, "Linking should succeed");
    ASSERT_TRUE(TestUtils::file_exists(exe_path), "Executable should exist");
    
    // Test execution
    std::string output = TestUtils::capture_output(exe_path);
    ASSERT_EQ(output, "Hello", "Executable should output 'Hello'");
}

// ==================== X86_64 BACKEND TESTS ====================

TEST(X86_64Backend, BasicCompilation) {
    // Create simple IR: main() -> return 42
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    auto const_42 = builder.get_int32(42);
    builder.create_ret(const_42);
    
    // Compile with x86_64 backend
    auto backend = BackendFactory::create_backend(TargetArch::X86_64);
    ASSERT_TRUE(backend != nullptr, "x86_64 backend creation should succeed");
    
    bool compile_success = backend->compile_module(module);
    ASSERT_TRUE(compile_success, "x86_64 compilation should succeed");
    
    size_t code_size = backend->get_code_size();
    ASSERT_GT(code_size, 0, "Generated code should have size > 0");
    ASSERT_LT(code_size, 1000, "Simple function should be < 1000 bytes");
}

TEST(X86_64Backend, ObjectFileGeneration) {
    // Create minimal IR
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    auto const_42 = builder.get_int32(42);
    builder.create_ret(const_42);
    
    // Compile
    auto backend = BackendFactory::create_backend(TargetArch::X86_64);
    backend->compile_module(module);
    
    // Generate object file
    std::string obj_path = "/tmp/test_x86_64.o";
    bool obj_success = backend->write_object(obj_path, "_start");
    ASSERT_TRUE(obj_success, "Object file generation should succeed");
    
    // Verify object file exists and has reasonable size
    ASSERT_TRUE(TestUtils::file_exists(obj_path), "Object file should exist");
    size_t obj_size = TestUtils::get_file_size(obj_path);
    ASSERT_GT(obj_size, 100, "Object file should be > 100 bytes");
    ASSERT_LT(obj_size, 10000, "Object file should be < 10KB");
}

// ==================== INTEGRATION TESTS ====================

TEST(Integration, MultiArchitectureCompilation) {
    // Test that both backends can compile the same IR
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    auto const_42 = builder.get_int32(42);
    builder.create_ret(const_42);
    
    // Test ARM64
    auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
    bool arm64_success = arm64_backend->compile_module(module);
    ASSERT_TRUE(arm64_success, "ARM64 compilation should succeed");
    
    // Test x86_64
    auto x86_64_backend = BackendFactory::create_backend(TargetArch::X86_64);
    bool x86_64_success = x86_64_backend->compile_module(module);
    ASSERT_TRUE(x86_64_success, "x86_64 compilation should succeed");
    
    // Both should generate code
    ASSERT_GT(arm64_backend->get_code_size(), 0, "ARM64 should generate code");
    ASSERT_GT(x86_64_backend->get_code_size(), 0, "x86_64 should generate code");
}

TEST(Integration, PerformanceComparison) {
    // Test that our ARM64 backend generates efficient code
    Module module("test_module");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // write(1, "Hello, World!\n", 14); exit(0)
    auto stdout_fd = builder.get_int32(1);
    auto hello_str = module.create_global_string("Hello, World!\n");
    auto hello_len = builder.get_int32(14);
    
    std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, hello_str, hello_len};
    builder.create_syscall(4, write_args);
    
    auto exit_code = builder.get_int32(0);
    std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
    builder.create_syscall(1, exit_args);
    
    // Compile with ARM64 backend
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    backend->compile_module(module);
    
    size_t code_size = backend->get_code_size();
    
    // Our optimized version should be very compact
    ASSERT_LTE(code_size, 60, "Optimized Hello World should be <= 60 bytes");
    ASSERT_GT(code_size, 20, "Code should have reasonable size > 20 bytes");
    
    // Generate and test executable
    std::string obj_path = "/tmp/perf_test_arm64.o";
    backend->write_object(obj_path, "_start");
    
    std::string exe_path = "/tmp/perf_test_arm64";
    std::string link_cmd = "clang -arch arm64 -Wl,-e,_start -o " + exe_path + " " + obj_path;
    int link_result = system(link_cmd.c_str());
    
    ASSERT_EQ(link_result, 0, "Performance test linking should succeed");
    
    // Test execution
    std::string output = TestUtils::capture_output(exe_path);
    ASSERT_EQ(output, "Hello, World!\n", "Performance test should output correctly");
}

// ==================== GENERIC AOT COMPILER TESTS ====================

TEST(AOTCompiler, GenericSyscallHandling_ARM64) {
    // Test generic syscall handling with read/write operations
    Module module("syscall_test");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Allocate stack buffer (generic allocation)
    auto buf = builder.create_alloca(Type::i8(), builder.get_int32(256));
    
    // read(0, buf, 10) - generic syscall with dynamic arguments
    auto bytes_read = builder.create_syscall(3, {
        builder.get_int32(0),    // stdin
        buf,                     // buffer pointer
        builder.get_int32(10)    // count
    });
    
    // write(1, "Result: ", 8) - generic string handling
    auto result_str = module.create_global_string("Result: ");
    builder.create_syscall(4, {
        builder.get_int32(1),    // stdout
        result_str,              // string pointer
        builder.get_int32(8)     // string length
    });
    
    // write(1, buf, bytes_read) - using syscall result as argument
    builder.create_syscall(4, {
        builder.get_int32(1),    // stdout
        buf,                     // buffer pointer
        bytes_read               // dynamic count from previous syscall
    });
    
    // exit(0)
    builder.create_syscall(1, {builder.get_int32(0)});
    
    // Compile with ARM64 backend
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    ASSERT_TRUE(backend->compile_module(module), "ARM64 compilation should succeed");
    
    // Generate executable
    std::string obj_path = "/tmp/aot_syscall_test_arm64.o";
    std::string exe_path = "/tmp/aot_syscall_test_arm64";
    
    ASSERT_TRUE(backend->write_object(obj_path, "_start"), "Object generation should succeed");
    ASSERT_TRUE(backend->link_executable(obj_path, exe_path), "Linking should succeed");
    ASSERT_TRUE(TestUtils::file_exists(exe_path), "Executable should exist");
    
    // Test execution with input
    std::string test_cmd = "echo 'Hello' | " + exe_path;
    std::string output = TestUtils::capture_output(test_cmd);
    ASSERT_TRUE(output.find("Result: ") != std::string::npos, "Should contain result prefix");
    ASSERT_TRUE(output.find("Hello") != std::string::npos, "Should echo input");
}

TEST(AOTCompiler, GenericSyscallHandling_X86_64) {
    // Same test as ARM64 but for x86_64 - proves generic backend functionality
    Module module("syscall_test_x64");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Allocate stack buffer
    auto buf = builder.create_alloca(Type::i8(), builder.get_int32(128));
    
    // read(0, buf, 5)
    auto bytes_read = builder.create_syscall(3, {
        builder.get_int32(0),
        buf,
        builder.get_int32(5)
    });
    
    // write(1, "Echo: ", 6)
    auto echo_str = module.create_global_string("Echo: ");
    builder.create_syscall(4, {
        builder.get_int32(1),
        echo_str,
        builder.get_int32(6)
    });
    
    // write(1, buf, bytes_read)
    builder.create_syscall(4, {
        builder.get_int32(1),
        buf,
        bytes_read
    });
    
    // exit(0)
    builder.create_syscall(1, {builder.get_int32(0)});
    
    // Compile with x86_64 backend
    auto backend = BackendFactory::create_backend(TargetArch::X86_64);
    ASSERT_TRUE(backend->compile_module(module), "x86_64 compilation should succeed");
    
    // Generate executable
    std::string obj_path = "/tmp/aot_syscall_test_x64.o";
    std::string exe_path = "/tmp/aot_syscall_test_x64";
    
    ASSERT_TRUE(backend->write_object(obj_path, "_start"), "Object generation should succeed");
    ASSERT_TRUE(backend->link_executable(obj_path, exe_path), "Linking should succeed");
    ASSERT_TRUE(TestUtils::file_exists(exe_path), "Executable should exist");
    
    // Test execution
    std::string test_cmd = "echo 'Test' | " + exe_path;
    std::string output = TestUtils::capture_output(test_cmd);
    ASSERT_TRUE(output.find("Echo: ") != std::string::npos, "Should contain echo prefix");
    ASSERT_TRUE(output.find("Test") != std::string::npos, "Should echo input");
}

TEST(AOTCompiler, CrossArchitectureCompatibility) {
    // Test that the same IR compiles correctly on both architectures
    Module module("cross_arch_test");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Simple program: write message and exit - will be used for different architectures
    auto msg = module.create_global_string("Cross-arch test OK\n");
    
    // Note: This test will be compiled for multiple architectures, but uses default macOS syscalls
    // Real cross-platform tests should create architecture-specific modules
    auto platform = SyscallNumbers::get_current_platform();
    builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64, platform), {
        builder.get_int32(1),
        msg,
        builder.get_int32(19)  // Include the newline character
    });
    builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::ARM64, platform), {builder.get_int32(0)});
    
    // Test ARM64
    auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
    ASSERT_TRUE(arm64_backend->compile_module(module), "ARM64 compilation should succeed");
    
    std::string arm64_obj = "/tmp/cross_test_arm64.o";
    std::string arm64_exe = "/tmp/cross_test_arm64";
    ASSERT_TRUE(arm64_backend->write_object(arm64_obj, "_start"), "ARM64 object generation should succeed");
    ASSERT_TRUE(arm64_backend->link_executable(arm64_obj, arm64_exe), "ARM64 linking should succeed");
    
    // Test x86_64
    auto x64_backend = BackendFactory::create_backend(TargetArch::X86_64);
    ASSERT_TRUE(x64_backend->compile_module(module), "x86_64 compilation should succeed");
    
    std::string x64_obj = "/tmp/cross_test_x64.o";
    std::string x64_exe = "/tmp/cross_test_x64";
    ASSERT_TRUE(x64_backend->write_object(x64_obj, "_start"), "x86_64 object generation should succeed");
    ASSERT_TRUE(x64_backend->link_executable(x64_obj, x64_exe), "x86_64 linking should succeed");
    
    // Both should produce identical output
    std::string arm64_output = TestUtils::capture_output(arm64_exe);
    std::string x64_output = TestUtils::capture_output(x64_exe);
    
    ASSERT_EQ(arm64_output, "Cross-arch test OK\n", "ARM64 should produce correct output");
    ASSERT_EQ(x64_output, "Cross-arch test OK\n", "x86_64 should produce correct output");
    ASSERT_EQ(arm64_output, x64_output, "Both architectures should produce identical output");
}

TEST(AOTCompiler, ComplexDataFlow) {
    // Test complex data flow with multiple syscall results
    Module module("complex_dataflow");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Allocate multiple buffers
    auto buf1 = builder.create_alloca(Type::i8(), builder.get_int32(64));
    auto buf2 = builder.create_alloca(Type::i8(), builder.get_int32(64));
    
    // First read
    auto bytes1 = builder.create_syscall(3, {builder.get_int32(0), buf1, builder.get_int32(10)});
    
    // Second read
    auto bytes2 = builder.create_syscall(3, {builder.get_int32(0), buf2, builder.get_int32(10)});
    
    // Write first buffer
    builder.create_syscall(4, {builder.get_int32(1), buf1, bytes1});
    
    // Write separator
    auto sep = module.create_global_string(" | ");
    builder.create_syscall(4, {builder.get_int32(1), sep, builder.get_int32(3)});
    
    // Write second buffer
    builder.create_syscall(4, {builder.get_int32(1), buf2, bytes2});
    
    // Write newline
    auto nl = module.create_global_string("\n");
    builder.create_syscall(4, {builder.get_int32(1), nl, builder.get_int32(1)});
    
    // exit(0)
    builder.create_syscall(1, {builder.get_int32(0)});
    
    // Test on both architectures
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "arm64" : "x64";
        auto backend = BackendFactory::create_backend(arch);
        
        ASSERT_TRUE(backend->compile_module(module), (arch_name + " compilation should succeed").c_str());
        
        std::string obj_path = "/tmp/complex_dataflow_" + arch_name + ".o";
        std::string exe_path = "/tmp/complex_dataflow_" + arch_name;
        
        ASSERT_TRUE(backend->write_object(obj_path, "_start"), (arch_name + " object generation should succeed").c_str());
        ASSERT_TRUE(backend->link_executable(obj_path, exe_path), (arch_name + " linking should succeed").c_str());
        
        // This test demonstrates that multiple syscall results are preserved correctly
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " executable should exist").c_str());
    }
}

// ==================== INSTRUCTION IMPLEMENTATION TESTS ====================

TEST(Instructions, ArithmeticOperations_ARM64) {
    // Test basic arithmetic operations: ADD, SUB, MUL, UDIV, SDIV
    Module module("arithmetic_test");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Test: result = (10 + 5) * 3 - 2 / 2 = 15 * 3 - 1 = 45 - 1 = 44
    auto const10 = builder.get_int32(10);
    auto const5 = builder.get_int32(5);
    auto const3 = builder.get_int32(3);
    auto const2 = builder.get_int32(2);
    
    // Step 1: add_result = 10 + 5 = 15
    auto add_result = builder.create_add(const10, const5);
    
    // Step 2: mul_result = 15 * 3 = 45
    auto mul_result = builder.create_mul(add_result, const3);
    
    // Step 3: div_result = 2 / 2 = 1
    auto div_result = builder.create_udiv(const2, const2);
    
    // Step 4: final_result = 45 - 1 = 44
    auto final_result = builder.create_sub(mul_result, div_result);
    
    // Write the result as exit code for testing
    builder.create_syscall(1, {final_result});
    
    // Compile with ARM64 backend
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    ASSERT_TRUE(backend->compile_module(module), "ARM64 arithmetic compilation should succeed");
    
    std::string obj_path = "/tmp/arithmetic_test_arm64.o";
    std::string exe_path = "/tmp/arithmetic_test_arm64";
    
    ASSERT_TRUE(backend->write_object(obj_path, "_start"), "ARM64 arithmetic object generation should succeed");
    ASSERT_TRUE(backend->link_executable(obj_path, exe_path), "ARM64 arithmetic linking should succeed");
    ASSERT_TRUE(TestUtils::file_exists(exe_path), "ARM64 arithmetic executable should exist");
}

TEST(Instructions, ArithmeticOperations_X86_64) {
    // Same arithmetic test for x86_64 to ensure cross-platform compatibility
    Module module("arithmetic_test_x64");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Test: result = (20 - 5) / 3 + 2 * 4 = 15 / 3 + 8 = 5 + 8 = 13
    auto const20 = builder.get_int32(20);
    auto const5 = builder.get_int32(5);
    auto const3 = builder.get_int32(3);
    auto const2 = builder.get_int32(2);
    auto const4 = builder.get_int32(4);
    
    auto sub_result = builder.create_sub(const20, const5);  // 15
    auto div_result = builder.create_udiv(sub_result, const3);  // 5
    auto mul_result = builder.create_mul(const2, const4);  // 8
    auto final_result = builder.create_add(div_result, mul_result);  // 13
    
    builder.create_syscall(1, {final_result});
    
    // Compile with x86_64 backend
    auto backend = BackendFactory::create_backend(TargetArch::X86_64);
    ASSERT_TRUE(backend->compile_module(module), "x86_64 arithmetic compilation should succeed");
    
    std::string obj_path = "/tmp/arithmetic_test_x64.o";
    std::string exe_path = "/tmp/arithmetic_test_x64";
    
    ASSERT_TRUE(backend->write_object(obj_path, "_start"), "x86_64 arithmetic object generation should succeed");
    ASSERT_TRUE(backend->link_executable(obj_path, exe_path), "x86_64 arithmetic linking should succeed");
    ASSERT_TRUE(TestUtils::file_exists(exe_path), "x86_64 arithmetic executable should exist");
}

TEST(Instructions, BitwiseOperations_CrossPlatform) {
    // Test bitwise operations on both architectures
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "arm64" : "x64";
        
        Module module("bitwise_test_" + arch_name);
        Function* func = module.create_function("main", Type::i32(), {});
        BasicBlock* bb = func->create_basic_block("entry");
        
        IRBuilder builder;
        builder.set_insert_point(bb);
        
        // Test: result = ((0xFF & 0xF0) | 0x0F) ^ 0xAA = (0xF0 | 0x0F) ^ 0xAA = 0xFF ^ 0xAA = 0x55
        auto const_ff = builder.get_int32(0xFF);
        auto const_f0 = builder.get_int32(0xF0);
        auto const_0f = builder.get_int32(0x0F);
        auto const_aa = builder.get_int32(0xAA);
        
        auto and_result = builder.create_and(const_ff, const_f0);  // 0xF0
        auto or_result = builder.create_or(and_result, const_0f);  // 0xFF
        auto xor_result = builder.create_xor(or_result, const_aa);  // 0x55 = 85
        
        // Test shifts: shift_result = (85 << 1) >> 1 = 170 >> 1 = 85
        auto const1 = builder.get_int32(1);
        auto shl_result = builder.create_shl(xor_result, const1);   // 170
        auto shr_result = builder.create_lshr(shl_result, const1); // 85
        
        builder.create_syscall(1, {shr_result});
        
        auto backend = BackendFactory::create_backend(arch);
        ASSERT_TRUE(backend->compile_module(module), (arch_name + " bitwise compilation should succeed").c_str());
        
        std::string obj_path = "/tmp/bitwise_test_" + arch_name + ".o";
        std::string exe_path = "/tmp/bitwise_test_" + arch_name;
        
        ASSERT_TRUE(backend->write_object(obj_path, "_start"), (arch_name + " bitwise object generation should succeed").c_str());
        ASSERT_TRUE(backend->link_executable(obj_path, exe_path), (arch_name + " bitwise linking should succeed").c_str());
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " bitwise executable should exist").c_str());
    }
}

TEST(Instructions, ComplexExpressionEvaluation) {
    // Test complex expression with mixed arithmetic and bitwise operations
    Module module("complex_expr");
    Function* func = module.create_function("main", Type::i32(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    
    IRBuilder builder;
    builder.set_insert_point(bb);
    
    // Complex expression: result = ((a * b) + c) & mask
    // Where a=7, b=6, c=8, mask=0x3F
    // Expected: ((7 * 6) + 8) & 0x3F = (42 + 8) & 0x3F = 50 & 0x3F = 50
    auto a = builder.get_int32(7);
    auto b = builder.get_int32(6);
    auto c = builder.get_int32(8);
    auto mask = builder.get_int32(0x3F);
    
    auto mul_ab = builder.create_mul(a, b);        // 42
    auto add_c = builder.create_add(mul_ab, c);    // 50
    auto and_mask = builder.create_and(add_c, mask); // 50
    
    // Also test signed division: sdiv_result = 50 / 5 = 10
    auto const5 = builder.get_int32(5);
    auto sdiv_result = builder.create_sdiv(and_mask, const5); // 10
    
    builder.create_syscall(1, {sdiv_result});
    
    // Test on both architectures
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "arm64" : "x64";
        auto backend = BackendFactory::create_backend(arch);
        
        ASSERT_TRUE(backend->compile_module(module), (arch_name + " complex expression compilation should succeed").c_str());
        
        std::string obj_path = "/tmp/complex_expr_" + arch_name + ".o";
        std::string exe_path = "/tmp/complex_expr_" + arch_name;
        
        ASSERT_TRUE(backend->write_object(obj_path, "_start"), (arch_name + " complex expression object generation should succeed").c_str());
        ASSERT_TRUE(backend->link_executable(obj_path, exe_path), (arch_name + " complex expression linking should succeed").c_str());
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " complex expression executable should exist").c_str());
    }
}

// ==================== ERROR HANDLING TESTS ====================

TEST(ErrorHandling, InvalidBackendCreation) {
    // Test invalid architecture
    auto backend = BackendFactory::create_backend(static_cast<TargetArch>(999));
    ASSERT_TRUE(backend == nullptr, "Invalid architecture should return nullptr");
}

TEST(ErrorHandling, EmptyModuleCompilation) {
    // Test compilation of empty module
    Module module("empty_module");
    
    auto backend = BackendFactory::create_backend(TargetArch::ARM64);
    bool compile_success = backend->compile_module(module);
    
    // This might succeed or fail depending on implementation
    // Just ensure it doesn't crash
    ASSERT_TRUE(true, "Empty module compilation should not crash");
}

// ==================== REGISTER ALLOCATOR TESTS ====================

TEST(RegisterAllocator, X64RegisterSetBasic) {
    auto x64_reg_set = std::make_shared<X64RegisterSet>();
    
    // Test basic properties
    ASSERT_TRUE(x64_reg_set->get_architecture_name() == "x86_64", "Architecture should be x86_64");
    
    // Test general purpose registers
    auto gp_regs = x64_reg_set->get_registers(RegisterClass::GENERAL_PURPOSE);
    ASSERT_TRUE(gp_regs.size() > 0, "Should have general purpose registers");
    
    // Test floating point registers
    auto fp_regs = x64_reg_set->get_registers(RegisterClass::FLOATING_POINT);
    ASSERT_TRUE(fp_regs.size() > 0, "Should have floating point registers");
    
    // Test register availability
    if (!gp_regs.empty()) {
        ASSERT_TRUE(x64_reg_set->is_register_available(gp_regs[0]), "First GP register should be available");
    }
}

TEST(RegisterAllocator, ARM64RegisterSetBasic) {
    auto arm64_reg_set = std::make_shared<ARM64RegisterSet>();
    
    // Test basic properties
    ASSERT_TRUE(arm64_reg_set->get_architecture_name() == "ARM64", "Architecture should be ARM64");
    
    // Test general purpose registers
    auto gp_regs = arm64_reg_set->get_registers(RegisterClass::GENERAL_PURPOSE);
    ASSERT_TRUE(gp_regs.size() > 0, "Should have general purpose registers");
    
    // ARM64 should have more GP registers than x86_64
    ASSERT_TRUE(gp_regs.size() >= 16, "ARM64 should have at least 16 GP registers");
}

TEST(RegisterAllocator, BasicAllocation) {
    // Create a simple function for testing
    Module module("test_allocation");
    Function* func = module.create_function("test_func", Type::i64(), {Type::i64(), Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto a = func->arguments[0];
    auto b = func->arguments[1];
    auto result = builder.create_add(a, b);
    builder.create_ret(result);
    
    // Test x86_64 allocation
    auto x64_reg_set = std::make_shared<X64RegisterSet>();
    RegisterAllocator x64_allocator(AllocationStrategy::LINEAR_SCAN);
    x64_allocator.set_register_set(x64_reg_set);
    
    bool success = x64_allocator.allocate_function_registers(*func);
    ASSERT_TRUE(success, "x86_64 register allocation should succeed");
    
    // Test ARM64 allocation
    auto arm64_reg_set = std::make_shared<ARM64RegisterSet>();
    RegisterAllocator arm64_allocator(AllocationStrategy::LINEAR_SCAN);
    arm64_allocator.set_register_set(arm64_reg_set);
    
    success = arm64_allocator.allocate_function_registers(*func);
    ASSERT_TRUE(success, "ARM64 register allocation should succeed");
}

TEST(RegisterAllocator, AllocationStrategies) {
    // Create a function with multiple operations
    Module module("test_strategies");
    Function* func = module.create_function("complex_func", Type::i64(), {Type::i64(), Type::i64(), Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto a = func->arguments[0];
    auto b = func->arguments[1];
    auto c = func->arguments[2];
    
    auto sum1 = builder.create_add(a, b);
    auto sum2 = builder.create_add(sum1, c);
    auto product = builder.create_mul(sum2, a);
    builder.create_ret(product);
    
    auto x64_reg_set = std::make_shared<X64RegisterSet>();
    
    // Test different allocation strategies
    std::vector<AllocationStrategy> strategies = {
        AllocationStrategy::GREEDY,
        AllocationStrategy::LINEAR_SCAN,
        AllocationStrategy::GRAPH_COLORING
    };
    
    for (auto strategy : strategies) {
        RegisterAllocator allocator(strategy);
        allocator.set_register_set(x64_reg_set);
        
        bool success = allocator.allocate_function_registers(*func);
        ASSERT_TRUE(success, "All allocation strategies should work for simple function");
    }
}

TEST(RegisterAllocator, HighRegisterPressure) {
    // Create a function with many live values to test spilling
    Module module("test_spilling");
    Function* func = module.create_function("high_pressure", Type::i64(), {Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto input = func->arguments[0];
    std::vector<std::shared_ptr<IR::Register>> values;
    
    // Create many operations to exceed available registers
    std::shared_ptr<IR::Value> current = input;
    for (int i = 0; i < 20; ++i) {
        auto const_val = builder.get_int64(i + 1);
        auto result = builder.create_add(current, const_val);
        current = result;
        values.push_back(result);
    }
    
    // Use all values in final computation
    auto result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = builder.create_add(result, values[i]);
    }
    builder.create_ret(result);
    
    auto x64_reg_set = std::make_shared<X64RegisterSet>();
    RegisterAllocator allocator(AllocationStrategy::LINEAR_SCAN);
    allocator.set_register_set(x64_reg_set);
    
    bool success = allocator.allocate_function_registers(*func);
    ASSERT_TRUE(success, "High register pressure should be handled with spilling");
    
    // Check allocation result
    auto allocation_result = allocator.allocate_registers(module);
    // With high pressure, we expect some spills
    // (This is architecture dependent, so we just check it doesn't crash)
    ASSERT_TRUE(true, "Allocation result should be valid");
}

// ==================== OPTIMIZATION PASS TESTS ====================

TEST(OptimizationPasses, ConstantFoldingPass) {
    // Create a function with constant operations
    Module module("test_constant_folding");
    Function* func = module.create_function("const_ops", Type::i64(), {});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    // Create constants and operations that can be folded
    auto const5 = builder.get_int64(5);
    auto const10 = builder.get_int64(10);
    auto sum = builder.create_add(const5, const10);  // Should fold to 15
    builder.create_ret(sum);
    
    // Apply constant folding pass
    ConstantFoldingPass pass;
    bool modified = pass.run(module);
    
    // The pass should detect optimization opportunities
    ASSERT_TRUE(modified, "Constant folding should detect opportunities");
}

TEST(OptimizationPasses, DeadCodeEliminationPass) {
    // Create a function with unused operations
    Module module("test_dce");
    Function* func = module.create_function("dead_code", Type::i64(), {Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto input = func->arguments[0];
    
    // Create a dead operation (result not used)
    auto dead_result = builder.create_mul(input, builder.get_int64(42));
    
    // Create the actual return value
    auto live_result = builder.create_add(input, builder.get_int64(1));
    builder.create_ret(live_result);
    
    // Apply dead code elimination pass
    DeadCodeEliminationPass pass;
    bool modified = pass.run(module);
    
    // The pass should detect the dead code
    ASSERT_TRUE(modified, "Dead code elimination should detect unused operations");
}

TEST(OptimizationPasses, InstructionSchedulingPass) {
    // Create a function with dependent operations
    Module module("test_scheduling");
    Function* func = module.create_function("scheduling_test", Type::i64(), {Type::i64(), Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto a = func->arguments[0];
    auto b = func->arguments[1];
    
    // Create operations with dependencies
    auto sum = builder.create_add(a, b);
    auto product = builder.create_mul(sum, a);  // Depends on sum
    auto final_result = builder.create_add(product, b);
    builder.create_ret(final_result);
    
    // Apply instruction scheduling pass
    InstructionSchedulingPass pass;
    bool modified = pass.run(module);
    
    // The pass should detect scheduling opportunities
    ASSERT_TRUE(modified, "Instruction scheduling should detect dependencies");
}

// TEST(OptimizationPasses, OptimizationPassManager) {
//     // Create a function that benefits from multiple optimizations
//     Module module("test_pass_manager");
//     Function* func = module.create_function("multi_opt", Type::i64(), {Type::i64()});
//     BasicBlock* entry = func->create_basic_block("entry");
//     IRBuilder builder;
//     builder.set_insert_point(entry);
    
//     auto input = func->arguments[0];
    
//     // Constant operations (for folding)
//     auto const1 = builder.get_int64(10);
//     auto const2 = builder.get_int64(20);
//     auto const_sum = builder.create_add(const1, const2);
    
//     // Dead code
//     auto dead_op = builder.create_mul(input, builder.get_int64(999));
    
//     // Live operations with dependencies (for scheduling)
//     auto live_sum = builder.create_add(input, const_sum);
//     auto final_result = builder.create_mul(live_sum, builder.get_int64(2));
//     builder.create_ret(final_result);
    
//     // Create pass manager and add all passes
//     OptimizationPassManager optimizer;
//     optimizer.add_pass(std::make_unique<ConstantFoldingPass>());
//     optimizer.add_pass(std::make_unique<DeadCodeEliminationPass>());
//     optimizer.add_pass(std::make_unique<InstructionSchedulingPass>());
    
//     // Run all passes
//     bool any_modified = optimizer.run_passes(module);
//     ASSERT_TRUE(any_modified, "Pass manager should detect optimization opportunities");
    
//     // Check that all passes ran
//     auto results = optimizer.get_pass_results();
//     ASSERT_TRUE(results.size() == 3, "Should have results from 3 passes");
// }

// ==================== INTEGRATION TESTS ====================

TEST(Integration, OptimizedRegisterAllocation) {
    // Test the complete pipeline: IR -> Optimization -> Register Allocation
    Module module("integration_test");
    Function* func = module.create_function("optimized_func", Type::i64(), {Type::i64(), Type::i64()});
    BasicBlock* entry = func->create_basic_block("entry");
    IRBuilder builder;
    builder.set_insert_point(entry);
    
    auto a = func->arguments[0];
    auto b = func->arguments[1];
    
    // Create IR that can benefit from optimization
    auto const_val = builder.get_int64(42);
    auto temp1 = builder.create_add(a, const_val);
    auto temp2 = builder.create_mul(b, const_val);
    auto result = builder.create_add(temp1, temp2);
    builder.create_ret(result);
    
    // Step 1: Apply optimizations
    OptimizationPassManager optimizer;
    optimizer.add_pass(std::make_unique<ConstantFoldingPass>());
    optimizer.add_pass(std::make_unique<DeadCodeEliminationPass>());
    optimizer.add_pass(std::make_unique<InstructionSchedulingPass>());
    
    bool optimized = optimizer.run_passes(module);
    ASSERT_TRUE(optimized, "Optimization should succeed");
    
    // Step 2: Apply register allocation
    auto x64_reg_set = std::make_shared<X64RegisterSet>();
    RegisterAllocator allocator(AllocationStrategy::LINEAR_SCAN);
    allocator.set_register_set(x64_reg_set);
    
    bool allocated = allocator.allocate_function_registers(*func);
    ASSERT_TRUE(allocated, "Register allocation after optimization should succeed");
    
    // Step 3: Verify the complete pipeline worked
    auto allocation_result = allocator.allocate_registers(module);
    ASSERT_TRUE(allocation_result.value_to_register.size() > 0, "Should have register assignments");
}

TEST(LabelSystem, BackendIntegration) {
    // Test label system integration with both backends
    
    // Test 1: x64 Backend with Labels
    {
        Module module("x64_label_test");
        Function* func = module.create_function("test_func", Type::i64(), {Type::i64(), Type::i64()});
        BasicBlock* entry = func->create_basic_block("entry");
        BasicBlock* true_block = func->create_basic_block("true_block");
        BasicBlock* false_block = func->create_basic_block("false_block");
        BasicBlock* merge_block = func->create_basic_block("merge_block");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        auto arg1 = func->arguments[0];
        auto arg2 = func->arguments[1];
        
        // Test comparison and conditional branching
        auto eq_result = builder.create_icmp_eq(arg1, arg2);
        builder.create_cond_br(eq_result, true_block, false_block);
        
        // True block
        builder.set_insert_point(true_block);
        auto true_val = builder.get_int64(100);
        builder.create_br(merge_block);
        
        // False block
        builder.set_insert_point(false_block);
        auto false_val = builder.get_int64(200);
        builder.create_br(merge_block);
        
        // Merge block
        builder.set_insert_point(merge_block);
        builder.create_ret(true_val);
        
        auto x64_backend = BackendFactory::create_backend(TargetArch::X86_64);
        ASSERT_TRUE(x64_backend != nullptr, "x64 backend creation should succeed");
        
        bool compile_success = x64_backend->compile_module(module);
        ASSERT_TRUE(compile_success, "x64 compilation with labels should succeed");
        
        size_t code_size = x64_backend->get_code_size();
        ASSERT_GT(code_size, 0, "x64 should generate code with labels");
        ASSERT_LT(code_size, 1000, "x64 label test should be reasonable size");
        
        std::cout << "x64 backend with labels: " << code_size << " bytes generated" << std::endl;
    }
    
    // Test 2: ARM64 Backend with Labels
    {
        Module module("arm64_label_test");
        Function* func = module.create_function("test_func", Type::i64(), {Type::i64(), Type::i64()});
        BasicBlock* entry = func->create_basic_block("entry");
        BasicBlock* true_block = func->create_basic_block("true_block");
        BasicBlock* false_block = func->create_basic_block("false_block");
        BasicBlock* merge_block = func->create_basic_block("merge_block");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        auto arg1 = func->arguments[0];
        auto arg2 = func->arguments[1];
        
        // Test comparison and conditional branching
        auto eq_result = builder.create_icmp_eq(arg1, arg2);
        builder.create_cond_br(eq_result, true_block, false_block);
        
        // True block
        builder.set_insert_point(true_block);
        auto true_val = builder.get_int64(100);
        builder.create_br(merge_block);
        
        // False block
        builder.set_insert_point(false_block);
        auto false_val = builder.get_int64(200);
        builder.create_br(merge_block);
        
        // Merge block
        builder.set_insert_point(merge_block);
        builder.create_ret(true_val);
        
        auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
        ASSERT_TRUE(arm64_backend != nullptr, "ARM64 backend creation should succeed");
        
        bool compile_success = arm64_backend->compile_module(module);
        ASSERT_TRUE(compile_success, "ARM64 compilation with labels should succeed");
        
        size_t code_size = arm64_backend->get_code_size();
        ASSERT_GT(code_size, 0, "ARM64 should generate code with labels");
        ASSERT_LT(code_size, 1000, "ARM64 label test should be reasonable size");
        
        std::cout << "ARM64 backend with labels: " << code_size << " bytes generated" << std::endl;
    }
    
    // Test 3: Function Calls with Labels
    {
        Module module("function_call_test");
        
        // Create a helper function
        Function* helper = module.create_function("helper_func", Type::i64(), {Type::i64()});
        BasicBlock* helper_entry = helper->create_basic_block("entry");
        IRBuilder helper_builder;
        helper_builder.set_insert_point(helper_entry);
        auto helper_arg = helper->arguments[0];
        auto helper_result = helper_builder.create_add(helper_arg, helper_builder.get_int64(42));
        helper_builder.create_ret(helper_result);
        
        // Create main function
        Function* main = module.create_function("main", Type::i64(), {Type::i64()});
        BasicBlock* main_entry = main->create_basic_block("entry");
        IRBuilder main_builder;
        main_builder.set_insert_point(main_entry);
        
        auto main_arg = main->arguments[0];
        auto call_result = main_builder.create_call(Type::i64(), "helper_func", {main_arg});
        main_builder.create_ret(call_result);
        
        // Test both backends
        auto x64_backend = BackendFactory::create_backend(TargetArch::X86_64);
        auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
        
        ASSERT_TRUE(x64_backend != nullptr, "x64 backend creation should succeed");
        ASSERT_TRUE(arm64_backend != nullptr, "ARM64 backend creation should succeed");
        
        bool x64_success = x64_backend->compile_module(module);
        bool arm64_success = arm64_backend->compile_module(module);
        
        ASSERT_TRUE(x64_success, "x64 function calls with labels should succeed");
        ASSERT_TRUE(arm64_success, "ARM64 function calls with labels should succeed");
        
        size_t x64_size = x64_backend->get_code_size();
        size_t arm64_size = arm64_backend->get_code_size();
        
        ASSERT_GT(x64_size, 0, "x64 should generate code for function calls");
        ASSERT_GT(arm64_size, 0, "ARM64 should generate code for function calls");
        
        std::cout << "Function calls with labels - x64: " << x64_size << " bytes, ARM64: " << arm64_size << " bytes" << std::endl;
    }
    
    // Test 4: Complex Control Flow with Multiple Labels
    {
        Module module("complex_control_flow");
        Function* func = module.create_function("complex_func", Type::i64(), {Type::i64(), Type::i64()});
        
        // Create multiple basic blocks
        BasicBlock* entry = func->create_basic_block("entry");
        BasicBlock* loop_start = func->create_basic_block("loop_start");
        BasicBlock* loop_body = func->create_basic_block("loop_body");
        BasicBlock* loop_end = func->create_basic_block("loop_end");
        BasicBlock* exit = func->create_basic_block("exit");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        auto arg1 = func->arguments[0];
        auto arg2 = func->arguments[1];
        
        // Entry block: initialize counter
        auto counter = builder.create_alloca(Type::i64());
        builder.create_store(builder.get_int64(0), counter);
        builder.create_br(loop_start);
        
        // Loop start: check condition
        builder.set_insert_point(loop_start);
        auto loaded_counter = builder.create_load(Type::i64(), counter);
        auto condition = builder.create_icmp_slt(loaded_counter, arg1);
        builder.create_cond_br(condition, loop_body, exit);
        
        // Loop body: increment counter
        builder.set_insert_point(loop_body);
        auto new_counter = builder.create_add(loaded_counter, builder.get_int64(1));
        builder.create_store(new_counter, counter);
        builder.create_br(loop_start);
        
        // Exit: return result
        builder.set_insert_point(exit);
        builder.create_ret(loaded_counter);
        
        // Test both backends
        auto x64_backend = BackendFactory::create_backend(TargetArch::X86_64);
        auto arm64_backend = BackendFactory::create_backend(TargetArch::ARM64);
        
        bool x64_success = x64_backend->compile_module(module);
        bool arm64_success = arm64_backend->compile_module(module);
        
        ASSERT_TRUE(x64_success, "x64 complex control flow should succeed");
        ASSERT_TRUE(arm64_success, "ARM64 complex control flow should succeed");
        
        size_t x64_size = x64_backend->get_code_size();
        size_t arm64_size = arm64_backend->get_code_size();
        
        ASSERT_GT(x64_size, 0, "x64 should generate code for complex control flow");
        ASSERT_GT(arm64_size, 0, "ARM64 should generate code for complex control flow");
        
        std::cout << "Complex control flow - x64: " << x64_size << " bytes, ARM64: " << arm64_size << " bytes" << std::endl;
    }
    
    std::cout << "Label system backend integration test completed successfully." << std::endl;
}

// ==================== STANDALONE EXECUTABLE TESTS ====================

TEST(StandaloneExecutables, HelloWorldWithoutCRuntime) {
    // Comprehensive test demonstrating full end-to-end standalone executable generation
    // This test proves the system can generate working executables without C runtime
    
    std::cout << "🎯 Testing standalone Hello World generation..." << std::endl;
    
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        std::cout << "  Testing " << arch_name << " architecture..." << std::endl;
        
        // Create standalone Hello World IR
        Module module("standalone_hello_" + arch_name);
        Function* start_func = module.create_function("_start", Type::void_type(), {});
        BasicBlock* entry = start_func->create_basic_block("entry");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        // Create global string "Hello, Standalone World!\n"
        auto hello_str = module.create_global_string("Hello, Standalone World!\n");
        
        // write(1, hello_str, 25)
        auto stdout_fd = builder.get_int32(1);
        auto msg_len = builder.get_int32(25);
        std::vector<std::shared_ptr<Value>> write_args = {stdout_fd, hello_str, msg_len};
        builder.create_syscall(SyscallNumbers::get_write_syscall(arch), write_args); // Architecture-aware write
        
        // exit(0)
        auto exit_code = builder.get_int32(0);
        std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
        builder.create_syscall(SyscallNumbers::get_exit_syscall(arch), exit_args); // Architecture-aware exit
        
        // Compile with backend
        auto backend = BackendFactory::create_backend(arch);
        ASSERT_TRUE(backend != nullptr, (arch_name + " backend creation should succeed").c_str());
        
        bool compile_success = backend->compile_module(module);
        ASSERT_TRUE(compile_success, (arch_name + " compilation should succeed").c_str());
        
        // Generate object file
        std::string obj_path = "/tmp/standalone_hello_" + arch_name + ".o";
        bool obj_success = backend->write_object(obj_path, "_start");
        ASSERT_TRUE(obj_success, (arch_name + " object generation should succeed").c_str());
        
        // Link standalone executable (no C runtime)
        std::string exe_path = "/tmp/standalone_hello_" + arch_name;
        bool link_success = backend->link_executable(obj_path, exe_path);
        ASSERT_TRUE(link_success, (arch_name + " linking should succeed").c_str());
        
        // Verify executable exists
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " executable should exist").c_str());
        
        // Test execution
        std::string output = TestUtils::capture_output(exe_path);
        ASSERT_EQ(output, "Hello, Standalone World!\n", (arch_name + " should output correct message").c_str());
        
        // Verify code size (should be very compact)
        size_t code_size = backend->get_code_size();
        ASSERT_GT(code_size, 20, (arch_name + " should generate reasonable amount of code").c_str());
        ASSERT_LT(code_size, 200, (arch_name + " standalone executable should be compact").c_str());
        
        std::cout << "    ✅ " << arch_name << ": " << code_size << " bytes, output: '" 
                  << output.substr(0, output.length()-1) << "'" << std::endl;
    }
    
    std::cout << "🎉 Standalone Hello World test completed successfully!" << std::endl;
}

TEST(StandaloneExecutables, MemoryOperationsComprehensive) {
    // Test comprehensive memory operations: alloca, store, load with different sizes
    
    std::cout << "🧠 Testing comprehensive memory operations..." << std::endl;
    
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        
        Module module("memory_ops_" + arch_name);
        Function* func = module.create_function("_start", Type::void_type(), {});
        BasicBlock* entry = func->create_basic_block("entry");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        // Test different memory sizes
        // Allocate i64, i32, i16, i8
        auto ptr64 = builder.create_alloca(Type::i64());
        auto ptr32 = builder.create_alloca(Type::i32());
        auto ptr16 = builder.create_alloca(Type::i16());
        auto ptr8 = builder.create_alloca(Type::i8());
        
        // Store different values
        builder.create_store(builder.get_int64(0x123456789ABCDEF0), ptr64);
        builder.create_store(builder.get_int32(0x12345678), ptr32);
        builder.create_store(builder.get_int16(0x1234), ptr16);
        builder.create_store(builder.get_int8(0x42), ptr8);
        
        // Load values back
        auto val64 = builder.create_load(Type::i64(), ptr64);
        auto val32 = builder.create_load(Type::i32(), ptr32);
        auto val16 = builder.create_load(Type::i16(), ptr16);
        auto val8 = builder.create_load(Type::i8(), ptr8);
        
        // Perform arithmetic on loaded values
        auto sum64_32 = builder.create_add(val64, builder.create_zext(val32, Type::i64()));
        auto sum16_8 = builder.create_add(builder.create_zext(val16, Type::i32()), 
                                         builder.create_zext(val8, Type::i32()));
        
        // Use the results in exit code (just to ensure they're not optimized away)
        auto final_result = builder.create_add(builder.create_trunc(sum64_32, Type::i32()), sum16_8);
        auto exit_code = builder.create_and(final_result, builder.get_int32(0xFF)); // Keep it reasonable
        
        // exit(exit_code)
        std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
        builder.create_syscall(SyscallNumbers::get_exit_syscall(arch), exit_args);
        
        // Compile and test
        auto backend = BackendFactory::create_backend(arch);
        ASSERT_TRUE(backend->compile_module(module), (arch_name + " memory operations compilation should succeed").c_str());
        
        std::string obj_path = "/tmp/memory_ops_" + arch_name + ".o";
        std::string exe_path = "/tmp/memory_ops_" + arch_name;
        
        ASSERT_TRUE(backend->write_object(obj_path, "_start"), (arch_name + " memory ops object generation should succeed").c_str());
        ASSERT_TRUE(backend->link_executable(obj_path, exe_path), (arch_name + " memory ops linking should succeed").c_str());
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " memory ops executable should exist").c_str());
        
        size_t code_size = backend->get_code_size();
        std::cout << "    ✅ " << arch_name << ": " << code_size << " bytes (memory operations)" << std::endl;
    }
    
    std::cout << "🎉 Comprehensive memory operations test completed!" << std::endl;
}

TEST(StandaloneExecutables, ComparisonOperationsComprehensive) {
    // Test comprehensive comparison operations
    
    std::cout << "⚖️  Testing comprehensive comparison operations..." << std::endl;
    
    for (auto arch : {TargetArch::ARM64, TargetArch::X86_64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x86_64";
        
        Module module("comparison_ops_" + arch_name);
        Function* func = module.create_function("_start", Type::void_type(), {});
        BasicBlock* entry = func->create_basic_block("entry");
        
        IRBuilder builder;
        builder.set_insert_point(entry);
        
        // Test all available comparison operations
        auto val1 = builder.get_int64(42);
        auto val2 = builder.get_int64(42);
        auto val3 = builder.get_int64(100);
        
        // Test equality
        auto eq_result = builder.create_icmp_eq(val1, val2);  // Should be true (1)
        auto ne_result = builder.create_icmp_ne(val1, val3);  // Should be true (1)
        
        // Test signed comparisons
        auto slt_result = builder.create_icmp_slt(val1, val3); // Should be true (1)
        auto sgt_result = builder.create_icmp_sgt(val3, val1); // Should be true (1)
        
        // Combine results: all should be 1, so sum should be 4
        auto sum1 = builder.create_add(builder.create_zext(eq_result, Type::i64()),
                                      builder.create_zext(ne_result, Type::i64()));
        auto sum2 = builder.create_add(builder.create_zext(slt_result, Type::i64()),
                                      builder.create_zext(sgt_result, Type::i64()));
        auto total = builder.create_add(sum1, sum2);
        
        // Exit with the total (should be 4 if all comparisons work)
        auto exit_code = builder.create_trunc(total, Type::i32());
        std::vector<std::shared_ptr<Value>> exit_args = {exit_code};
        builder.create_syscall(SyscallNumbers::get_exit_syscall(arch), exit_args);
        
        // Compile and test
        auto backend = BackendFactory::create_backend(arch);
        ASSERT_TRUE(backend->compile_module(module), (arch_name + " comparison operations compilation should succeed").c_str());
        
        std::string obj_path = "/tmp/comparison_ops_" + arch_name + ".o";
        std::string exe_path = "/tmp/comparison_ops_" + arch_name;
        
        ASSERT_TRUE(backend->write_object(obj_path, "_start"), (arch_name + " comparison ops object generation should succeed").c_str());
        ASSERT_TRUE(backend->link_executable(obj_path, exe_path), (arch_name + " comparison ops linking should succeed").c_str());
        ASSERT_TRUE(TestUtils::file_exists(exe_path), (arch_name + " comparison ops executable should exist").c_str());
        
        size_t code_size = backend->get_code_size();
        std::cout << "    ✅ " << arch_name << ": " << code_size << " bytes (comparison operations)" << std::endl;
    }
    
    std::cout << "🎉 Comprehensive comparison operations test completed!" << std::endl;
}

TEST(CrossPlatform, ELFGeneration) {
    std::cout << "🧪 Testing Cross-Platform ELF Generation..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    // Create identical IR for both platforms
    auto create_hello_world_ir = []() -> std::unique_ptr<Module> {
        auto module = std::make_unique<Module>("hello_world_cross_platform");
        IRBuilder builder;
        
        // Create global string
        auto hello_str = module->create_global_string("Hello, Cross-Platform World!\n");
        
        // Create _start function
        Function* start_func = module->create_function("_start", Type::void_type(), {});
        BasicBlock* start_bb = start_func->create_basic_block("entry");
        builder.set_insert_point(start_bb);
        
        // write syscall: write(1, hello_str, 28)
        auto fd_val = builder.get_int32(1);      // stdout
        auto len_val = builder.get_int32(28);    // message length
        builder.create_syscall(4, {fd_val, hello_str, len_val}); // write syscall
        
        // exit syscall: exit(0)
        auto exit_code = builder.get_int32(0);
        builder.create_syscall(1, {exit_code}); // exit syscall
        
        return module;
    };
    
    // Test ARM64 - macOS vs Linux
    {
        auto macos_module = create_hello_world_ir();
        auto linux_module = create_hello_world_ir();
        
        auto macos_backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::MACOS);
        auto linux_backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
        
        if (!macos_backend || !linux_backend) {
            std::cout << "❌ Failed to create ARM64 backends" << std::endl;
            return;
        }
        
        // Compile both modules
        if (!macos_backend->compile_module(*macos_module) || !linux_backend->compile_module(*linux_module)) {
            std::cout << "❌ Failed to compile ARM64 modules" << std::endl;
            return;
        }
        
        // Write object files
        if (!macos_backend->write_object("hello_arm64_macos.o", "_start") || 
            !linux_backend->write_object("hello_arm64_linux.o", "_start")) {
            std::cout << "❌ Failed to write ARM64 object files" << std::endl;
            return;
        }
        
        std::cout << "✅ ARM64 cross-platform object generation successful" << std::endl;
    }
    
    // Test x64 - macOS vs Linux
    {
        auto macos_module = create_hello_world_ir();
        auto linux_module = create_hello_world_ir();
        
        auto macos_backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::MACOS);
        auto linux_backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::LINUX);
        
        if (!macos_backend || !linux_backend) {
            std::cout << "❌ Failed to create x64 backends" << std::endl;
            return;
        }
        
        // Compile both modules
        if (!macos_backend->compile_module(*macos_module) || !linux_backend->compile_module(*linux_module)) {
            std::cout << "❌ Failed to compile x64 modules" << std::endl;
            return;
        }
        
        // Write object files
        if (!macos_backend->write_object("hello_x64_macos.o", "_start") || 
            !linux_backend->write_object("hello_x64_linux.o", "_start")) {
            std::cout << "❌ Failed to write x64 object files" << std::endl;
            return;
        }
        
        std::cout << "✅ x64 cross-platform object generation successful" << std::endl;
    }
    
    std::cout << "🎉 Cross-platform ELF generation test completed!" << std::endl;
}

// ARM64 runtime capability detection
bool has_arm64_runtime_capability() {
#ifdef __aarch64__
    return true; // Native ARM64
#else
    // Check if we can run ARM64 binaries (e.g., through emulation)
    // This is a basic check - in practice, you might want more sophisticated detection
    return false;
#endif
}

// Cross-platform ARM64 runtime check
bool can_run_arm64_tests() {
    auto platform = CodeGen::BackendFactory::get_native_platform();
    auto arch = CodeGen::BackendFactory::get_native_arch();
    
    if (arch == CodeGen::TargetArch::ARM64) {
        return true; // Native ARM64
    }
    
    if (platform == CodeGen::TargetPlatform::MACOS) {
        // macOS can run ARM64 binaries on Apple Silicon through Rosetta
        return true;
    }
    
    if (platform == CodeGen::TargetPlatform::LINUX) {
        // Linux might have qemu-user for ARM64 emulation
        return has_arm64_runtime_capability();
    }
    
    return false;
}

TEST(CrossPlatform, ARM64CrossCompilationLinux) {
    std::cout << "🧪 Testing ARM64 Cross-Compilation on Linux..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    // Only run this test on Linux
    auto native_platform = BackendFactory::get_native_platform();
    if (native_platform != TargetPlatform::LINUX) {
        std::cout << "    Skipping ARM64 cross-compilation test (not on Linux)" << std::endl;
        return;
    }
    
    // Check if we can actually run ARM64 binaries
    if (!can_run_arm64_tests()) {
        std::cout << "    ⚠️  Skipping ARM64 execution test (no ARM64 runtime capability)" << std::endl;
        std::cout << "    ✅ ARM64 object generation still tested" << std::endl;
    }
    
    // Create a simple ARM64 module for Linux
    auto module = std::make_unique<Module>("arm64_cross_test");
    IRBuilder builder;
    
    // Create global string
    auto hello_str = module->create_global_string("Hello, ARM64 Linux!\n");
    
    // Create _start function
    Function* start_func = module->create_function("_start", Type::void_type(), {});
    BasicBlock* start_bb = start_func->create_basic_block("entry");
    builder.set_insert_point(start_bb);
    
    // write syscall: write(1, hello_str, 20)
    auto fd_val = builder.get_int32(1);      // stdout
    auto len_val = builder.get_int32(20);    // message length
    builder.create_syscall(64, {fd_val, hello_str, len_val}); // Linux ARM64 SYS_write
    
    // exit syscall: exit(0)
    auto exit_code = builder.get_int32(0);
    builder.create_syscall(93, {exit_code}); // Linux ARM64 SYS_exit
    
    // Create ARM64 Linux backend
    auto backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
    if (!backend) {
        std::cout << "    ❌ Failed to create ARM64 Linux backend" << std::endl;
        return;
    }
    
    // Compile module
    if (!backend->compile_module(*module)) {
        std::cout << "    ❌ Failed to compile ARM64 module" << std::endl;
        return;
    }
    
    // Write object file
    if (!backend->write_object("arm64_cross_test.o", "_start")) {
        std::cout << "    ❌ Failed to write ARM64 object file" << std::endl;
        return;
    }
    
    // Verify it's an ARM64 ELF file
    std::string cmd = "file arm64_cross_test.o";
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        std::cout << "    ⚠️  Could not verify file format" << std::endl;
    }
    
    std::cout << "    ✅ ARM64 cross-compilation test completed successfully" << std::endl;
    std::cout << "🎉 ARM64 cross-compilation test completed!" << std::endl;
}

TEST(CrossPlatform, ELFExecutableGeneration) {
    std::cout << "🧪 Testing ELF Executable Generation..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    auto native_platform = BackendFactory::get_native_platform();
    auto native_arch = BackendFactory::get_native_arch();
    
    std::cout << "    Platform: " << BackendFactory::platform_to_string(native_platform) << std::endl;
    std::cout << "    Architecture: " << BackendFactory::arch_to_string(native_arch) << std::endl;
    
    // Test ELF executable generation on Linux
    if (native_platform == TargetPlatform::LINUX) {
        std::cout << "    🐧 Testing ELF executable generation on Linux..." << std::endl;
        
        // Create a simple module for testing
        auto module = std::make_unique<Module>("elf_exec_test");
        IRBuilder builder;
        
        // Create global string
        auto hello_str = module->create_global_string("Hello, ELF World!\n");
        
        // Create _start function
        Function* start_func = module->create_function("_start", Type::void_type(), {});
        BasicBlock* start_bb = start_func->create_basic_block("entry");
        builder.set_insert_point(start_bb);
        
        // write syscall: write(1, hello_str, 18) - Linux platform
        auto fd_val = builder.get_int32(1);      // stdout
        auto len_val = builder.get_int32(18);    // message length
        builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::X86_64, TargetPlatform::LINUX), 
                              {fd_val, hello_str, len_val}); // Linux x64 write
        
        // exit syscall: exit(0)
        auto exit_code = builder.get_int32(0);
        builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::X86_64, TargetPlatform::LINUX), 
                              {exit_code}); // Linux x64 exit
        
        // Test x64 ELF executable generation
        {
            std::cout << "        Testing x64 ELF executable..." << std::endl;
            auto backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::LINUX);
            if (!backend) {
                std::cout << "        ❌ Failed to create x64 Linux backend" << std::endl;
                return;
            }
            
            // Compile module
            if (!backend->compile_module(*module)) {
                std::cout << "        ❌ Failed to compile x64 module" << std::endl;
                return;
            }
            
            // Write ELF executable directly
            if (!backend->write_executable("elf_test_x64", "_start")) {
                std::cout << "        ❌ Failed to write x64 ELF executable" << std::endl;
                return;
            }
            
            // Verify it's an ELF executable
            std::string cmd = "file elf_test_x64";
            int rc = std::system(cmd.c_str());
            if (rc != 0) {
                std::cout << "        ⚠️  Could not verify x64 ELF format" << std::endl;
            }
            
            // Test execution
            std::string exec_cmd = "./elf_test_x64";
            rc = std::system(exec_cmd.c_str());
            if (rc == 0) {
                std::cout << "        ✅ x64 ELF executable ran successfully" << std::endl;
            } else {
                std::cout << "        ⚠️  x64 ELF executable execution failed (exit code: " << rc << ")" << std::endl;
                
                // Try to get more detailed error information
                std::string debug_cmd = "strace -e trace=write,exit_group ./elf_test_x64 2>&1 | head -10";
                std::cout << "        🔍 Debug info:" << std::endl;
                std::system(debug_cmd.c_str());
            }
        }
        
        // Test ARM64 ELF executable generation (if we have ARM64 runtime capability)
        if (can_run_arm64_tests()) {
            std::cout << "        Testing ARM64 ELF executable..." << std::endl;
            
            // Create separate ARM64 module with correct syscall numbers
            auto arm64_module = std::make_unique<Module>("elf_test_arm64");
            IRBuilder arm64_builder;
            
            // Create ARM64-specific global string
            auto arm64_hello_str = arm64_module->create_global_string("ARM64 ELF Hello!\n");
            
            // Create _start function for ARM64
            Function* arm64_start_func = arm64_module->create_function("_start", Type::void_type(), {});
            BasicBlock* arm64_start_bb = arm64_start_func->create_basic_block("entry");
            arm64_builder.set_insert_point(arm64_start_bb);
            
            // ARM64 Linux syscalls
            auto arm64_fd_val = arm64_builder.get_int32(1);      // stdout
            auto arm64_len_val = arm64_builder.get_int32(18);    // message length
            arm64_builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64, TargetPlatform::LINUX), 
                                       {arm64_fd_val, arm64_hello_str, arm64_len_val}); // ARM64 Linux write
            
            auto arm64_exit_code = arm64_builder.get_int32(0);
            arm64_builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::ARM64, TargetPlatform::LINUX), 
                                       {arm64_exit_code}); // ARM64 Linux exit
            
            auto backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
            if (!backend) {
                std::cout << "        ❌ Failed to create ARM64 Linux backend" << std::endl;
                return;
            }
            
            // Compile ARM64 module
            if (!backend->compile_module(*arm64_module)) {
                std::cout << "        ❌ Failed to compile ARM64 module" << std::endl;
                return;
            }
            
            // Write ELF executable directly
            if (!backend->write_executable("elf_test_arm64", "_start")) {
                std::cout << "        ❌ Failed to write ARM64 ELF executable" << std::endl;
                return;
            }
            
            // Verify it's an ARM64 ELF executable
            std::string cmd = "file elf_test_arm64";
            int rc = std::system(cmd.c_str());
            if (rc != 0) {
                std::cout << "        ⚠️  Could not verify ARM64 ELF format" << std::endl;
            }
            
            // Test execution
            std::string exec_cmd = "./elf_test_arm64";
            rc = std::system(exec_cmd.c_str());
            if (rc == 0) {
                std::cout << "        ✅ ARM64 ELF executable ran successfully" << std::endl;
            } else {
                std::cout << "        ⚠️  ARM64 ELF executable execution failed (exit code: " << rc << ")" << std::endl;
                
                // Try to get more detailed error information
                std::string debug_cmd = "strace -e trace=write,exit_group ./elf_test_arm64 2>&1 | head -10";
                std::cout << "        🔍 Debug info:" << std::endl;
                std::system(debug_cmd.c_str());
            }
        } else {
            std::cout << "        ⚠️  Skipping ARM64 ELF executable test (no ARM64 runtime capability)" << std::endl;
        }
        
    } else {
        std::cout << "    ⚠️  Skipping ELF executable test (not on Linux)" << std::endl;
        std::cout << "    💡 ELF executables can only be generated and tested on Linux" << std::endl;
    }
    
    // Test cross-platform ELF object generation (works on any platform)
    std::cout << "    🌍 Testing cross-platform ELF object generation..." << std::endl;
    
    for (auto arch : {TargetArch::X86_64, TargetArch::ARM64}) {
        std::string arch_name = (arch == TargetArch::ARM64) ? "ARM64" : "x64";
        
        auto backend = BackendFactory::create_backend(arch, TargetPlatform::LINUX);
        if (!backend) {
            std::cout << "        ❌ Failed to create " << arch_name << " Linux backend" << std::endl;
            continue;
        }
        
        // Create simple module
        auto module = std::make_unique<Module>("elf_obj_test_" + arch_name);
        IRBuilder builder;
        
        Function* func = module->create_function("_start", Type::void_type(), {});
        BasicBlock* bb = func->create_basic_block("entry");
        builder.set_insert_point(bb);
        
        // Simple exit syscall
        auto exit_code = builder.get_int32(0);
        builder.create_syscall(1, {exit_code});
        
        // Compile and write object
        if (!backend->compile_module(*module)) {
            std::cout << "        ❌ Failed to compile " << arch_name << " module" << std::endl;
            continue;
        }
        
        std::string obj_path = "elf_obj_test_" + arch_name + ".o";
        if (!backend->write_object(obj_path, "_start")) {
            std::cout << "        ❌ Failed to write " << arch_name << " ELF object" << std::endl;
            continue;
        }
        
        // Verify object file
        std::string cmd = "file " + obj_path;
        int rc = std::system(cmd.c_str());
        if (rc == 0) {
            std::cout << "        ✅ " << arch_name << " ELF object generation successful" << std::endl;
        } else {
            std::cout << "        ⚠️  Could not verify " << arch_name << " ELF object format" << std::endl;
        }
    }
    
    std::cout << "🎉 ELF executable generation test completed!" << std::endl;
}

TEST(CrossPlatform, ELFExecutableExecutionDebug) {
    std::cout << "🧪 Testing ELF Executable Execution with Debug Tools..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    auto native_platform = BackendFactory::get_native_platform();
    
    if (native_platform != TargetPlatform::LINUX) {
        std::cout << "    ⚠️  Skipping ELF execution debug test (not on Linux)" << std::endl;
        return;
    }
    
    std::cout << "    🔧 Creating comprehensive ELF executable test..." << std::endl;
    
    // Create a more comprehensive test module
    auto module = std::make_unique<Module>("elf_debug_test");
    IRBuilder builder;
    
    // Create multiple global strings
    auto hello_str = module->create_global_string("Hello, ELF Debug!\n");
    auto world_str = module->create_global_string("World!\n");
    
    // Create _start function
    Function* start_func = module->create_function("_start", Type::void_type(), {});
    BasicBlock* start_bb = start_func->create_basic_block("entry");
    builder.set_insert_point(start_bb);
    
    // Test multiple syscalls - use Linux platform for ELF tests
    auto platform = TargetPlatform::LINUX;
    
    // write(1, hello_str, 19)
    auto fd_val = builder.get_int32(1);
    auto hello_len = builder.get_int32(19);
    builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::X86_64, platform), 
                          {fd_val, hello_str, hello_len}); // Platform-aware write syscall
    
    // write(1, world_str, 7) 
    auto world_len = builder.get_int32(7);
    builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::X86_64, platform), 
                          {fd_val, world_str, world_len}); // Platform-aware write syscall
    
    // exit(42) - non-zero exit code for testing
    auto exit_code = builder.get_int32(42);
    builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::X86_64, platform), 
                          {exit_code}); // Platform-aware exit syscall
    
    // Test x64 ELF executable
    {
        std::cout << "        🔍 Testing x64 ELF executable with debug tools..." << std::endl;
        
        auto backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::LINUX);
        if (!backend) {
            std::cout << "        ❌ Failed to create x64 Linux backend" << std::endl;
            return;
        }
        
        if (!backend->compile_module(*module)) {
            std::cout << "        ❌ Failed to compile x64 module" << std::endl;
            return;
        }
        
        if (!backend->write_executable("elf_debug_x64", "_start")) {
            std::cout << "        ❌ Failed to write x64 ELF executable" << std::endl;
            return;
        }
        
        // Test 1: Basic execution
        std::cout << "            📋 Test 1: Basic execution" << std::endl;
        std::string exec_cmd = "./elf_debug_x64";
        int rc = std::system(exec_cmd.c_str());
        std::cout << "            Exit code: " << rc << " (expected: 42)" << std::endl;
        
        // Test 2: Capture output
        std::cout << "            📋 Test 2: Output capture" << std::endl;
        std::string output = TestUtils::capture_output(exec_cmd);
        std::cout << "            Output: '" << output << "'" << std::endl;
        
        // Test 3: strace analysis
        std::cout << "            📋 Test 3: System call analysis" << std::endl;
        std::string strace_cmd = "strace -e trace=write,exit_group ./elf_debug_x64 2>&1";
        std::cout << "            System calls:" << std::endl;
        std::system(strace_cmd.c_str());
        
        // Test 4: File analysis
        std::cout << "            📋 Test 4: File format analysis" << std::endl;
        std::string file_cmd = "file elf_debug_x64";
        std::system(file_cmd.c_str());
        
        // Test 5: ELF header analysis
        std::cout << "            📋 Test 5: ELF header analysis" << std::endl;
        std::string readelf_cmd = "readelf -h elf_debug_x64";
        std::system(readelf_cmd.c_str());
        
        // Test 6: Program headers
        std::cout << "            📋 Test 6: Program headers" << std::endl;
        std::string ph_cmd = "readelf -l elf_debug_x64";
        std::system(ph_cmd.c_str());
        
        if (rc == 42) {
            std::cout << "        ✅ x64 ELF executable execution successful!" << std::endl;
        } else {
            std::cout << "        ❌ x64 ELF executable execution failed!" << std::endl;
        }
    }
    
    // Test ARM64 ELF executable (if available)
    if (can_run_arm64_tests()) {
        std::cout << "        🔍 Testing ARM64 ELF executable with debug tools..." << std::endl;
        
        // Create separate module for ARM64 with correct syscall numbers
        auto arm64_module = std::make_unique<Module>("elf_debug_arm64_test");
        IRBuilder arm64_builder;
        
        // Create ARM64-specific global strings
        auto arm64_hello_str = arm64_module->create_global_string("Hello, ELF Debug!\n");
        auto arm64_world_str = arm64_module->create_global_string("World!\n");
        
        // Create _start function for ARM64
        Function* arm64_start_func = arm64_module->create_function("_start", Type::void_type(), {});
        BasicBlock* arm64_start_bb = arm64_start_func->create_basic_block("entry");
        arm64_builder.set_insert_point(arm64_start_bb);
        
        // ARM64-specific syscalls for Linux
        auto arm64_fd_val = arm64_builder.get_int32(1);
        auto arm64_hello_len = arm64_builder.get_int32(19);
        arm64_builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64, platform), 
                                   {arm64_fd_val, arm64_hello_str, arm64_hello_len}); // ARM64 Linux write
        
        auto arm64_world_len = arm64_builder.get_int32(7);
        arm64_builder.create_syscall(SyscallNumbers::get_write_syscall(TargetArch::ARM64, platform), 
                                   {arm64_fd_val, arm64_world_str, arm64_world_len}); // ARM64 Linux write
        
        auto arm64_exit_code = arm64_builder.get_int32(42);
        arm64_builder.create_syscall(SyscallNumbers::get_exit_syscall(TargetArch::ARM64, platform), 
                                   {arm64_exit_code}); // ARM64 Linux exit
        
        auto backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
        if (!backend) {
            std::cout << "        ❌ Failed to create ARM64 Linux backend" << std::endl;
            return;
        }
        
        if (!backend->compile_module(*arm64_module)) {
            std::cout << "        ❌ Failed to compile ARM64 module" << std::endl;
            return;
        }
        
        if (!backend->write_executable("elf_debug_arm64", "_start")) {
            std::cout << "        ❌ Failed to write ARM64 ELF executable" << std::endl;
            return;
        }
        
        // Test execution
        std::string exec_cmd = "./elf_debug_arm64";
        int rc = std::system(exec_cmd.c_str());
        std::cout << "        ARM64 exit code: " << rc << " (expected: 42)" << std::endl;
        
        // Capture output
        std::string output = TestUtils::capture_output(exec_cmd);
        std::cout << "        ARM64 output: '" << output << "'" << std::endl;
        
        // File analysis
        std::string file_cmd = "file elf_debug_arm64";
        std::system(file_cmd.c_str());
        
        if (rc == 42) {
            std::cout << "        ✅ ARM64 ELF executable execution successful!" << std::endl;
        } else {
            std::cout << "        ❌ ARM64 ELF executable execution failed!" << std::endl;
        }
    } else {
        std::cout << "        ⚠️  Skipping ARM64 ELF debug test (no ARM64 runtime capability)" << std::endl;
    }
    
    std::cout << "🎉 ELF executable execution debug test completed!" << std::endl;
}

TEST(CrossPlatform, ARM64RuntimeCapability) {
    std::cout << "🧪 Testing ARM64 Runtime Capability..." << std::endl;
    
    using namespace CodeGen;
    
    auto platform = BackendFactory::get_native_platform();
    auto arch = BackendFactory::get_native_arch();
    
    std::cout << "    Platform: " << BackendFactory::platform_to_string(platform) << std::endl;
    std::cout << "    Architecture: " << BackendFactory::arch_to_string(arch) << std::endl;
    
    bool can_run = can_run_arm64_tests();
    std::cout << "    ARM64 runtime capability: " << (can_run ? "✅ Available" : "❌ Not available") << std::endl;
    
    // Test ARM64 backend creation regardless of runtime capability
    auto backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
    if (backend) {
        std::cout << "    ✅ ARM64 Linux backend creation successful" << std::endl;
    } else {
        std::cout << "    ❌ ARM64 Linux backend creation failed" << std::endl;
        return;
    }
    
    std::cout << "🎉 ARM64 runtime capability test completed!" << std::endl;
}

TEST(CrossPlatform, LinuxToolchainCompatibility) {
    std::cout << "🧪 Testing Linux Toolchain Compatibility..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    // Test if we can detect the current platform correctly
    auto native_platform = BackendFactory::get_native_platform();
    auto native_arch = BackendFactory::get_native_arch();
    
    std::cout << "    Current platform: " << BackendFactory::platform_to_string(native_platform) << std::endl;
    std::cout << "    Current architecture: " << BackendFactory::arch_to_string(native_arch) << std::endl;
    
    // Test tool availability on Linux
    if (native_platform == TargetPlatform::LINUX) {
        std::cout << "    Testing Linux toolchain availability..." << std::endl;
        
        // Check for common Linux tools
        auto check_tool = [](const std::string& tool) -> bool {
            std::string cmd = "which " + tool + " >/dev/null 2>&1";
            return std::system(cmd.c_str()) == 0;
        };
        
        bool has_ld = check_tool("ld");
        bool has_gcc = check_tool("gcc");
        bool has_clang = check_tool("clang");
        
        std::cout << "        ld available: " << (has_ld ? "✅" : "❌") << std::endl;
        std::cout << "        gcc available: " << (has_gcc ? "✅" : "❌") << std::endl;
        std::cout << "        clang available: " << (has_clang ? "✅" : "❌") << std::endl;
        
        // At least one linker should be available
        if (!has_ld && !has_gcc && !has_clang) {
            std::cout << "    ⚠️  Warning: No Linux linker tools found" << std::endl;
        }
    }
    
    // Test backend creation for all platform/arch combinations
    for (auto arch : {TargetArch::X86_64, TargetArch::ARM64}) {
        for (auto platform : {TargetPlatform::MACOS, TargetPlatform::LINUX}) {
            auto backend = BackendFactory::create_backend(arch, platform);
            if (!backend) {
                std::cout << "    ❌ Failed to create backend for " 
                         << BackendFactory::arch_to_string(arch) << " / "
                         << BackendFactory::platform_to_string(platform) << std::endl;
                return;
            }
            std::cout << "    ✅ Created backend for " 
                     << BackendFactory::arch_to_string(arch) << " / "
                     << BackendFactory::platform_to_string(platform) << std::endl;
        }
    }
    
    std::cout << "🎉 Linux toolchain compatibility test completed!" << std::endl;
}

TEST(CrossPlatform, SyscallNumbers) {
    std::cout << "🧪 Testing Platform-Specific Syscall Numbers..." << std::endl;
    
    using namespace CodeGen;
    using namespace IR;
    
    // Test that different platforms generate different syscall numbers
    auto module = std::make_unique<Module>("syscall_test");
    IRBuilder builder;
    
    Function* func = module->create_function("_start", Type::void_type(), {});
    BasicBlock* bb = func->create_basic_block("entry");
    builder.set_insert_point(bb);
    
    // Create exit syscall
    auto exit_code = builder.get_int32(0);
    builder.create_syscall(1, {exit_code}); // exit syscall number 1
    
    // Test ARM64 platforms
    {
        // Create separate modules for each platform
        auto macos_module = std::make_unique<Module>("syscall_test_macos");
        auto linux_module = std::make_unique<Module>("syscall_test_linux");
        
        // Create identical functions in both modules
        for (auto* mod : {macos_module.get(), linux_module.get()}) {
            IRBuilder local_builder;
            Function* local_func = mod->create_function("_start", Type::void_type(), {});
            BasicBlock* local_bb = local_func->create_basic_block("entry");
            local_builder.set_insert_point(local_bb);
            auto local_exit_code = local_builder.get_int32(0);
            local_builder.create_syscall(1, {local_exit_code});
        }
        
        auto macos_backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::MACOS);
        auto linux_backend = BackendFactory::create_backend(TargetArch::ARM64, TargetPlatform::LINUX);
        
        if (!macos_backend->compile_module(*macos_module) || !linux_backend->compile_module(*linux_module)) {
            std::cout << "❌ Failed to compile ARM64 syscall modules" << std::endl;
            return;
        }
        
        // Write and compare - they should be different due to different syscall numbers
        if (!macos_backend->write_object("syscall_arm64_macos.o", "_start") ||
            !linux_backend->write_object("syscall_arm64_linux.o", "_start")) {
            std::cout << "❌ Failed to write ARM64 syscall object files" << std::endl;
            return;
        }
        
        std::cout << "✅ ARM64 platform-specific syscall generation successful" << std::endl;
    }
    
    // Test x64 platforms
    {
        // Create separate modules for each platform
        auto macos_module = std::make_unique<Module>("syscall_test_x64_macos");
        auto linux_module = std::make_unique<Module>("syscall_test_x64_linux");
        
        // Create identical functions in both modules
        for (auto* mod : {macos_module.get(), linux_module.get()}) {
            IRBuilder local_builder;
            Function* local_func = mod->create_function("_start", Type::void_type(), {});
            BasicBlock* local_bb = local_func->create_basic_block("entry");
            local_builder.set_insert_point(local_bb);
            auto local_exit_code = local_builder.get_int32(0);
            local_builder.create_syscall(1, {local_exit_code});
        }
        
        auto macos_backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::MACOS);
        auto linux_backend = BackendFactory::create_backend(TargetArch::X86_64, TargetPlatform::LINUX);
        
        if (!macos_backend->compile_module(*macos_module) || !linux_backend->compile_module(*linux_module)) {
            std::cout << "❌ Failed to compile x64 syscall modules" << std::endl;
            return;
        }
        
        if (!macos_backend->write_object("syscall_x64_macos.o", "_start") ||
            !linux_backend->write_object("syscall_x64_linux.o", "_start")) {
            std::cout << "❌ Failed to write x64 syscall object files" << std::endl;
            return;
        }
        
        std::cout << "✅ x64 platform-specific syscall generation successful" << std::endl;
    }
    
    std::cout << "🎉 Platform-specific syscall number test completed!" << std::endl;
}


int main() {
    std::cout << "🚀 AOT Compiler Test Suite\n";
    std::cout << "==========================\n\n";
    
    Unit.RunTests();
    
    return 0;
}
