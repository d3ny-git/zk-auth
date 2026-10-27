# Every third-party dependency that is not a git submodule is pinned here by
# exact release tarball + SHA-256, so a configure step can never silently pick
# up a different version. Declaring is cheap; each subdirectory calls
# FetchContent_MakeAvailable() only for what it actually needs.
include(FetchContent)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW) # use extraction time as file timestamps
endif()

FetchContent_Declare(Catch2
  URL      https://github.com/catchorg/Catch2/archive/refs/tags/v3.16.1.tar.gz
  URL_HASH SHA256=d16bd1b8b2364918bd472cb216394acb93bde6784890df0d91bccfb3f28d777d)

FetchContent_Declare(benchmark
  URL      https://github.com/google/benchmark/archive/refs/tags/v1.10.0.tar.gz
  URL_HASH SHA256=acc5c7c0fbed855c4aaa2d7c3c36fb82b0c15c28f4e151e3f679c2fc0aa404af)

FetchContent_Declare(nlohmann_json
  URL      https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa)

# Standalone Asio has no CMakeLists; SOURCE_SUBDIR points at a directory that
# does not exist so MakeAvailable only downloads it.
FetchContent_Declare(asio
  URL      https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-36-0.tar.gz
  URL_HASH SHA256=0310a76b27e1854f09f696b30de57dc490b5e1b17faed1eb8c9a2891f956e52b
  SOURCE_SUBDIR do-not-build)

FetchContent_Declare(Crow
  URL      https://github.com/CrowCpp/Crow/archive/refs/tags/v1.3.3.tar.gz
  URL_HASH SHA256=b18621bd69f851f2df288fac715785ff8e4d0d468b99fc930cb2ff45a26c4ca6)

# Test oracle only: bitcoin-core's libsecp256k1 with the recovery module.
FetchContent_Declare(secp256k1
  URL      https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.7.1.tar.gz
  URL_HASH SHA256=958f204dbafc117e73a2604285dc2eb2a5128344d3499c114dcba5de54cb7a9e)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(BENCHMARK_ENABLE_TESTING OFF CACHE INTERNAL "")
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE INTERNAL "")
set(BENCHMARK_ENABLE_INSTALL OFF CACHE INTERNAL "")
set(BENCHMARK_ENABLE_WERROR OFF CACHE INTERNAL "")
set(CROW_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(CROW_BUILD_TESTS OFF CACHE INTERNAL "")
set(CROW_INSTALL OFF CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE INTERNAL "")
set(SECP256K1_BUILD_TESTS OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_BENCHMARK OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE INTERNAL "")
set(SECP256K1_INSTALL OFF CACHE INTERNAL "")

# Crow finds Asio through its own Findasio.cmake, which honours this variable.
macro(zk_fetch_crow)
  FetchContent_MakeAvailable(asio)
  set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include" CACHE PATH "" FORCE)
  FetchContent_MakeAvailable(Crow)
endmacro()
