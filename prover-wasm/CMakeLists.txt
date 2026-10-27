# The browser prover: libsnark + libff + GMP compiled to WebAssembly, exposed to
# JavaScript through Embind. Built only by the `wasm` preset.
add_executable(zkauth_prover bindings.cpp)
target_link_libraries(zkauth_prover PRIVATE zk::core)
target_compile_options(zkauth_prover PRIVATE -Wall -Wextra)
set_target_properties(zkauth_prover PROPERTIES SUFFIX ".mjs")
target_link_options(zkauth_prover PRIVATE
  -lembind
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createProver
  -sENVIRONMENT=worker,node        # Web Worker in the page; Node for tests
  -sALLOW_MEMORY_GROWTH=1
  -sINITIAL_MEMORY=64MB
  -sMAXIMUM_MEMORY=4GB             # the wasm32 ceiling; the real proving key needs hundreds of MB
  -sSTACK_SIZE=8MB                 # default is 64 KB; libsnark keeps big temporaries on the stack
  )
