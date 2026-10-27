FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)

add_executable(zk_tests
  test_smoke.cpp)
target_link_libraries(zk_tests PRIVATE Catch2::Catch2WithMain)

# PRE_TEST discovery: listing happens when ctest runs, not at build time, so a
# build never executes test binaries.
catch_discover_tests(zk_tests DISCOVERY_MODE PRE_TEST)
