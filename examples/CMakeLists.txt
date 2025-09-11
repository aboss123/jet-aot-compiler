# Examples CMakeLists.txt
# Builds comprehensive examples demonstrating the IR → Machine Code → Executable pipeline

# Add example executables (x64_assembler_demo already defined in main CMakeLists.txt)

add_executable(ir_hello_world ir_hello_world.cpp)
target_link_libraries(ir_hello_world ir backend x64_assembler arm64_assembler register_allocator)

add_executable(ir_arithmetic_demo ir_arithmetic_demo.cpp) 
target_link_libraries(ir_arithmetic_demo ir backend x64_assembler arm64_assembler register_allocator)

add_executable(ir_control_flow_demo ir_control_flow_demo.cpp)
target_link_libraries(ir_control_flow_demo ir backend x64_assembler arm64_assembler register_allocator)

add_executable(cross_platform_demo cross_platform_demo.cpp)
target_link_libraries(cross_platform_demo ir backend x64_assembler arm64_assembler register_allocator elf_builder)

add_executable(performance_benchmarks performance_benchmarks.cpp)
target_link_libraries(performance_benchmarks ir backend x64_assembler arm64_assembler register_allocator)

add_executable(user_input_demo user_input_demo.cpp)
target_link_libraries(user_input_demo ir backend x64_assembler arm64_assembler register_allocator)

# Set properties for all examples
set_target_properties(
    ir_hello_world 
    ir_arithmetic_demo 
    ir_control_flow_demo
    cross_platform_demo
    performance_benchmarks
    user_input_demo
    PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)