# syntax=docker/dockerfile:1
# Every base image is pinned by digest; every downloaded source by SHA-256.
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c
ARG EMSDK_IMAGE=emscripten/emsdk:6.0.13@sha256:fb7864e398acfda863dfcea78b8bc8adad359fa60c6a0bbeb845931de64aa68a
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ARG NGINX_IMAGE=nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de

# ---------------------------------------------------------------------------
# toolchain: Ubuntu 24.04 + OpenSSL built from source.
# 24.04 ships OpenSSL 3.0, whose default provider has no KECCAK-256 (added in
# 3.2), and Ethereum addresses are Keccak-256 hashes — so we build our own.
# ---------------------------------------------------------------------------
FROM ${UBUNTU_IMAGE} AS toolchain
ARG JOBS=4
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates curl perl \
      pkg-config libgmp-dev python3 xz-utils \
 && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=3.6.4
ARG OPENSSL_SHA256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
RUN curl -fsSL -o /tmp/openssl.tgz \
      https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
 && echo "${OPENSSL_SHA256}  /tmp/openssl.tgz" | sha256sum -c - \
 && tar -C /tmp -xzf /tmp/openssl.tgz \
 && cd /tmp/openssl-${OPENSSL_VERSION} \
 && ./Configure --prefix=/opt/openssl --libdir=lib no-tests no-docs shared \
 && make -j${JOBS} build_sw >/dev/null && make install_sw >/dev/null \
 && rm -rf /tmp/openssl*
ENV OPENSSL_ROOT_DIR=/opt/openssl \
    LD_LIBRARY_PATH=/opt/openssl/lib \
    PATH=/opt/openssl/bin:${PATH}

# ---------------------------------------------------------------------------
# test: the M0 acceptance check — debug build under ASan + UBSan, then ctest.
# ---------------------------------------------------------------------------
FROM toolchain AS test
ARG JOBS=4
WORKDIR /src
COPY . .
RUN cmake --preset native-debug \
 && cmake --build --preset native-debug -j${JOBS} \
 && ctest --preset native-debug

# ---------------------------------------------------------------------------
# wasm-toolchain: pinned Emscripten + the two tools its image lacks
# (GMP's configure needs m4; our presets use Ninja).
# ---------------------------------------------------------------------------
FROM ${EMSDK_IMAGE} AS wasm-toolchain
RUN apt-get update && apt-get install -y --no-install-recommends m4 ninja-build \
 && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# native-build: release build of the server and the command-line tools.
# ---------------------------------------------------------------------------
FROM toolchain AS native-build
# Separate from JOBS above: changing it must not invalidate the toolchain
# layers. native-build and wasm-build run in parallel, so 2 jobs each keeps
# the peak memory of a first build around 6 GB.
ARG BUILD_JOBS=2
WORKDIR /src
COPY . .
RUN cmake --preset native-release -DZK_BUILD_BENCH=OFF \
 && cmake --build --preset native-release -j${BUILD_JOBS} \
      --target zkauth-server zkauth-setup zkauth-issuer zkauth-prove

# ---------------------------------------------------------------------------
# wasm-build: GMP + OpenSSL libcrypto + libsnark -> client/wasm/.
# ---------------------------------------------------------------------------
FROM wasm-toolchain AS wasm-build
ARG BUILD_JOBS=2
WORKDIR /src
COPY . .
RUN JOBS=${BUILD_JOBS} ./prover-wasm/build.sh

# ---------------------------------------------------------------------------
# runtime: zkauth-server and the CLIs on plain Ubuntu 24.04, with the
# OpenSSL 3.6.4 and GMP libraries copied from the build.
# ---------------------------------------------------------------------------
FROM ${UBUNTU_IMAGE} AS runtime
COPY --from=native-build /opt/openssl/lib/libcrypto.so.3 /opt/openssl/lib/
COPY --from=native-build /usr/lib/x86_64-linux-gnu/libgmp.so.10* /usr/lib/x86_64-linux-gnu/
COPY --from=native-build /src/build/native-release/server/zkauth-server \
                         /src/build/native-release/tools/zkauth-setup \
                         /src/build/native-release/tools/zkauth-issuer \
                         /src/build/native-release/tools/zkauth-prove /usr/local/bin/
COPY docker/init.sh /usr/local/bin/zkauth-init
ENV LD_LIBRARY_PATH=/opt/openssl/lib
RUN useradd --system --uid 10001 zkauth && mkdir -p /data /demo && chown zkauth /data
USER zkauth
CMD ["zkauth-server"]

# ---------------------------------------------------------------------------
# baseline: the Node.js comparison server (Fastify + snarkjs + ethers v6).
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS baseline
WORKDIR /app
COPY baseline-node/package.json baseline-node/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY baseline-node/*.mjs ./
USER node
CMD ["sh", "-c", "node convert.mjs /data/keys/vk.json > /tmp/verification_key.json && VK=/tmp/verification_key.json exec node server.mjs"]

# ---------------------------------------------------------------------------
# web: nginx serving the client and the proving key, proxying /api/ to the server.
# ---------------------------------------------------------------------------
FROM ${NGINX_IMAGE} AS web
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY client/index.html client/app.js client/worker.js client/style.css /usr/share/nginx/html/
COPY --from=wasm-build /src/client/wasm /usr/share/nginx/html/wasm
