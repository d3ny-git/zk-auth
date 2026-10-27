# Builds the slice of libff + libsnark that Zk-Auth uses, from the
# third_party/libsnark submodule, with *identical* settings for the native and
# the WebAssembly builds.
#
# Why not add_subdirectory(third_party/libsnark)?  Its CMakeLists forces
# -std=c++11 and -march=native into CMAKE_CXX_FLAGS, unconditionally requires
# Boost.program_options and pkg-config libcrypto, builds gtest, gadgetlib2 and
# TinyRAM, and sets its configuration with directory-scoped add_definitions().
# Those definitions would NOT reach our own targets, yet they change data
# layouts and serialisation formats (BINARY_OUTPUT, NO_PT_COMPRESSION, ...):
# compiling our code with different ones than the library is an ODR violation
# that fails silently. Here the same switches are INTERFACE definitions on one
# target, so everything that links it agrees. See docs/build-notes.md.
#
# Mapping from libsnark/libff CMake options to what we set:
#   CURVE=ALT_BN128        -> CURVE_ALT_BN128
#   WITH_PROCPS=OFF        -> NO_PROCPS
#   MULTICORE=OFF          -> (MULTICORE not defined)
#   BINARY_OUTPUT=ON       -> BINARY_OUTPUT
#   MONTGOMERY_OUTPUT=ON   -> MONTGOMERY_OUTPUT
#   USE_PT_COMPRESSION=OFF -> NO_PT_COMPRESSION=1  (no square roots when the
#                             browser loads the proving key)
#   USE_ASM=ON (native) / OFF (wasm) -> USE_ASM
#   WITH_SUPERCOP=OFF      -> not built (ADSNARK only)
# libff's SHA512_rng (reachable from the Merkle gadget's headers) needs
# OpenSSL: the system one natively, an Emscripten build of it in wasm.

set(ZK_LIBSNARK_ROOT "${PROJECT_SOURCE_DIR}/third_party/libsnark")

if(NOT EXISTS "${ZK_LIBSNARK_ROOT}/depends/libff/libff")
  message(FATAL_ERROR "libsnark submodule missing: run 'git submodule update --init --recursive'")
endif()
execute_process(
  COMMAND sh "${PROJECT_SOURCE_DIR}/third_party/apply-patches.sh"
  RESULT_VARIABLE _zk_patch_result)
if(NOT _zk_patch_result EQUAL 0)
  message(FATAL_ERROR "applying third_party/patches failed")
endif()
set(ZK_LIBFF_ROOT    "${ZK_LIBSNARK_ROOT}/depends/libff")
set(ZK_LIBFQFFT_ROOT "${ZK_LIBSNARK_ROOT}/depends/libfqfft")

add_library(zk_libsnark STATIC
  ${ZK_LIBFF_ROOT}/libff/algebra/curves/alt_bn128/alt_bn128_g1.cpp
  ${ZK_LIBFF_ROOT}/libff/algebra/curves/alt_bn128/alt_bn128_g2.cpp
  ${ZK_LIBFF_ROOT}/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
  ${ZK_LIBFF_ROOT}/libff/algebra/curves/alt_bn128/alt_bn128_pairing.cpp
  ${ZK_LIBFF_ROOT}/libff/algebra/curves/alt_bn128/alt_bn128_pp.cpp
  ${ZK_LIBFF_ROOT}/libff/common/double.cpp
  ${ZK_LIBFF_ROOT}/libff/common/profiling.cpp
  ${ZK_LIBFF_ROOT}/libff/common/utils.cpp
  ${ZK_LIBSNARK_ROOT}/libsnark/gadgetlib1/constraint_profiling.cpp)
add_library(zk::libsnark ALIAS zk_libsnark)

target_include_directories(zk_libsnark SYSTEM PUBLIC
  ${ZK_LIBSNARK_ROOT}
  ${ZK_LIBFF_ROOT}
  ${ZK_LIBFQFFT_ROOT})

target_compile_definitions(zk_libsnark PUBLIC
  CURVE_ALT_BN128
  NO_PROCPS
  BINARY_OUTPUT
  MONTGOMERY_OUTPUT
  NO_PT_COMPRESSION=1)

if(EMSCRIPTEN)
  # GMP cross-compiled by prover-wasm/build-gmp.sh (generic C, 32-bit limbs).
  set(ZK_GMP_WASM_PREFIX "" CACHE PATH "Install prefix of the Emscripten-built GMP")
  if(NOT EXISTS "${ZK_GMP_WASM_PREFIX}/lib/libgmp.a")
    message(FATAL_ERROR "Emscripten GMP not found under '${ZK_GMP_WASM_PREFIX}'. "
                        "Run prover-wasm/build-gmp.sh first.")
  endif()
  # libcrypto cross-compiled by prover-wasm/build-openssl.sh.
  set(ZK_OPENSSL_WASM_PREFIX "" CACHE PATH "Install prefix of the Emscripten-built OpenSSL")
  if(NOT EXISTS "${ZK_OPENSSL_WASM_PREFIX}/lib/libcrypto.a")
    message(FATAL_ERROR "Emscripten OpenSSL not found under '${ZK_OPENSSL_WASM_PREFIX}'. "
                        "Run prover-wasm/build-openssl.sh first.")
  endif()
  target_include_directories(zk_libsnark SYSTEM PUBLIC
    "${ZK_GMP_WASM_PREFIX}/include" "${ZK_OPENSSL_WASM_PREFIX}/include")
  target_link_libraries(zk_libsnark PUBLIC
    "${ZK_GMP_WASM_PREFIX}/lib/libgmp.a" "${ZK_OPENSSL_WASM_PREFIX}/lib/libcrypto.a")
else()
  find_path(GMP_INCLUDE_DIR NAMES gmp.h REQUIRED)
  find_library(GMP_LIBRARY NAMES gmp REQUIRED)
  # OpenSSL >= 3.2 for KECCAK-256 (server); libff also includes its headers.
  find_package(OpenSSL 3.2 REQUIRED)
  target_include_directories(zk_libsnark SYSTEM PUBLIC "${GMP_INCLUDE_DIR}")
  target_link_libraries(zk_libsnark PUBLIC "${GMP_LIBRARY}" OpenSSL::Crypto)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    # libff's hand-written 4-limb Montgomery multiplication (fp_aux.tcc).
    target_compile_definitions(zk_libsnark PUBLIC USE_ASM)
  endif()
endif()

# The vendored sources predate C++20 and are not ours to lint.
target_compile_options(zk_libsnark PRIVATE -w)
