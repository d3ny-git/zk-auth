#!/bin/bash
# Host wrapper: runs build.sh in the pinned Emscripten image as the current
# user, with the repo mounted at the same path so CMake caches stay valid.
#   DOCKER="sudo docker" prover-wasm/build-in-docker.sh   (if not in the docker group)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
${DOCKER:-docker} image inspect zk-auth:wasm-toolchain >/dev/null 2>&1 ||
    ${DOCKER:-docker} build --target wasm-toolchain -t zk-auth:wasm-toolchain "$root"
exec ${DOCKER:-docker} run --rm -u "$(id -u):$(id -g)" \
    -e EM_CACHE="$root/build/emcache" -e JOBS="${JOBS:-4}" -e HOME=/tmp \
    -v "$root:$root" -w "$root" zk-auth:wasm-toolchain ./prover-wasm/build.sh
