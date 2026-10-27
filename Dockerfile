# syntax=docker/dockerfile:1
# Every base image is pinned by digest; every downloaded source by SHA-256.
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c

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
