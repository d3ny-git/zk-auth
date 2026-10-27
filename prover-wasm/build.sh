#!/bin/bash
# Builds the WebAssembly prover and copies it into client/wasm/.
# Runs inside the wasm-toolchain image; on the host use build-in-docker.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
./prover-wasm/build-gmp.sh "$PWD/build/gmp-wasm"
cmake --preset wasm >/dev/null
cmake --build --preset wasm -j"${JOBS:-4}"
mkdir -p client/wasm
cp build/wasm/prover-wasm/zkauth_prover.mjs build/wasm/prover-wasm/zkauth_prover.wasm client/wasm/
ls -l client/wasm/
