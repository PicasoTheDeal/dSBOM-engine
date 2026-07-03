cmake_minimum_required(VERSION 3.20)
# explicitly enable both cxx and c
project(dSbomEngine CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# hardcore security flags for compiling safety
add_compile_options(-Wall -Wextra -Wpedantic -Werror -O3 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2)
add_link_options(-pie -Wl,-z,relro,-z,now)

# pull in local openssl crypto libraries for fast hashing
find_package(OpenSSL REQUIRED)

include_directories(include)

# main engine target definition
add_executable(dSBOM
    src/main.cpp
    src/process_spawner.cpp
    src/memory_sniffer.cpp
    src/artifact_generator.cpp
)

# link openssl crypto directly to the engine
target_link_libraries(dSBOM PRIVATE OpenSSL::Crypto)

# loop through and compile the c test binaries
foreach(test_name basic_link dynamic_load stress_syscall memory_injections fork_tree)
    add_executable(${test_name} tests/${test_name}.c)
    target_link_libraries(${test_name} PRIVATE m dl)
endforeach()