cmake_minimum_required(VERSION 3.25)
project(zk_auth VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ZK_SANITIZE "Build everything with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ZK_FUZZ "Build libFuzzer targets (clang only)" OFF)
option(ZK_BUILD_BENCH "Build Google Benchmark targets" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Deps)

if(ZK_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer
                      -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

if(EMSCRIPTEN)
  # Native WebAssembly exception handling: our parsers report bad input by
  # throwing, and the JS-emulated alternative is several times slower.
  add_compile_options(-fwasm-exceptions)
  add_link_options(-fwasm-exceptions)
endif()

include(Libsnark)
add_subdirectory(core)

if(EMSCRIPTEN)
  add_subdirectory(prover-wasm)
else()
  add_subdirectory(tools)
  add_subdirectory(server)
  enable_testing()
  add_subdirectory(tests)
endif()
