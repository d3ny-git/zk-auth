find_package(OpenSSL 3.2 REQUIRED)

add_executable(zkauth-toy toy.cpp)
target_link_libraries(zkauth-toy PRIVATE zk::core)

add_executable(zkauth-setup setup.cpp)
target_link_libraries(zkauth-setup PRIVATE zk::core OpenSSL::Crypto)

add_executable(zkauth-issuer issuer.cpp)
target_link_libraries(zkauth-issuer PRIVATE zk::core OpenSSL::Crypto)

add_executable(zkauth-prove prove.cpp)
target_link_libraries(zkauth-prove PRIVATE zk::core)

foreach(t zkauth-setup zkauth-issuer zkauth-prove)
  target_compile_options(${t} PRIVATE -Wall -Wextra)
endforeach()
