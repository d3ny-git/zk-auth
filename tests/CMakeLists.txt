FetchContent_MakeAvailable(Catch2 secp256k1)
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)

find_package(OpenSSL 3.2 REQUIRED)

add_executable(zk_tests
  test_listener.cpp
  test_smoke.cpp
  test_encoding.cpp
  test_formats.cpp
  test_circuit.cpp
  test_proof.cpp
  test_multiexp.cpp
  test_eth_sig.cpp
  test_siwe.cpp)
target_link_libraries(zk_tests PRIVATE zk::core zk::server_lib OpenSSL::Crypto secp256k1 Catch2::Catch2WithMain)
target_compile_definitions(zk_tests PRIVATE ZK_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors")
target_compile_options(zk_tests PRIVATE -Wall -Wextra)

# PRE_TEST discovery: listing happens when ctest runs, not at build time, so a
# build never executes test binaries.
catch_discover_tests(zk_tests DISCOVERY_MODE PRE_TEST)
