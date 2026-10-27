FetchContent_MakeAvailable(benchmark secp256k1)

# Request bodies for every benchmark (needs keys/pk.bin).
add_executable(zkauth-bench-fixtures gen_fixtures.cpp)
target_link_libraries(zkauth-bench-fixtures PRIVATE zk::server_lib secp256k1)

# C++ micro-benchmarks with per-operation p50/p99.
add_executable(zkauth-microbench microbench.cpp)
target_link_libraries(zkauth-microbench PRIVATE zk::server_lib benchmark::benchmark)

foreach(t zkauth-bench-fixtures zkauth-microbench)
  target_compile_options(${t} PRIVATE -Wall -Wextra)
endforeach()
