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

if(NOT EMSCRIPTEN)
  enable_testing()
  add_subdirectory(tests)
endif()
