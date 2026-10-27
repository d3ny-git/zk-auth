find_package(OpenSSL 3.2 REQUIRED)

# Everything except main(): linked by the server, the tests, the fuzzers and
# the benchmarks.
add_library(zk_server_lib STATIC
  eth_sig.cpp
  siwe.cpp
  stores.cpp
  token.cpp
  routes.cpp)
add_library(zk::server_lib ALIAS zk_server_lib)
target_include_directories(zk_server_lib PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(zk_server_lib PUBLIC zk::core OpenSSL::Crypto)
target_compile_options(zk_server_lib PRIVATE -Wall -Wextra)

zk_fetch_crow()
add_executable(zkauth-server main.cpp)
target_link_libraries(zkauth-server PRIVATE zk::server_lib Crow::Crow)
target_compile_options(zkauth-server PRIVATE -Wall -Wextra)
