add_executable(zkauth-toy toy.cpp)
target_link_libraries(zkauth-toy PRIVATE zk::core)
