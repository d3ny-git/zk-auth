# libFuzzer targets (preset native-fuzz, clang). Everything in the build is
# compiled with -fsanitize=fuzzer-no-link,address,undefined (top-level
# CMakeLists); the targets themselves link the libFuzzer driver.
foreach(t fuzz_proof_json fuzz_siwe fuzz_signature)
  add_executable(${t} ${t}.cpp)
  target_link_libraries(${t} PRIVATE zk::server_lib)
  target_link_options(${t} PRIVATE -fsanitize=fuzzer)
endforeach()
