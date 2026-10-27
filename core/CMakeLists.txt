FetchContent_MakeAvailable(nlohmann_json)

add_library(zk_core STATIC
  snark.cpp
  encoding.cpp
  formats.cpp
  circuit.cpp
  merkle_tree.cpp
  prover.cpp)
add_library(zk::core ALIAS zk_core)
target_include_directories(zk_core PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(zk_core PUBLIC zk::libsnark nlohmann_json::nlohmann_json)
target_compile_options(zk_core PRIVATE -Wall -Wextra)
