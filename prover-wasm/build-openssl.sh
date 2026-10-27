#!/bin/bash
# Cross-compiles OpenSSL's libcrypto to wasm32 with Emscripten. Runs inside the
# wasm-toolchain image. Usage: build-openssl.sh PREFIX
#
# The browser prover uses it for SHA-256 (the proof hash that goes into the
# signed SIWE statement, computed by the same OpenSSL code as on the server),
# and libff needs its headers (libff::SHA512_rng).
#   linux-generic32  plain C, 32-bit target (wasm32)
#   no-asm           no x86 assembly
#   no-threads/sock/dso/engine/module/...  nothing a browser sandbox can use
set -euo pipefail
PREFIX=${1:?usage: build-openssl.sh PREFIX}
OPENSSL_VERSION=3.6.4
OPENSSL_SHA256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef

if [ -f "$PREFIX/lib/libcrypto.a" ]; then
    echo "OpenSSL already built in $PREFIX"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/openssl.tgz" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
echo "$OPENSSL_SHA256  $work/openssl.tgz" | sha256sum -c -
tar -C "$work" -xzf "$work/openssl.tgz"
cd "$work/openssl-$OPENSSL_VERSION"
emconfigure ./Configure linux-generic32 -static --prefix="$PREFIX" --openssldir=/ssl \
    no-asm no-threads no-shared no-dso no-engine no-sock no-afalgeng no-ui-console \
    no-tests no-docs no-apps no-module no-secure-memory no-async >/dev/null
# emconfigure exports CC as an absolute path; Configure also derives a
# CROSS_COMPILE prefix from it and would prepend that again.
sed -i 's|^CROSS_COMPILE=.*$|CROSS_COMPILE=|' Makefile
emmake make -j"$(nproc)" build_generated >/dev/null
emmake make -j"$(nproc)" libcrypto.a >/dev/null
mkdir -p "$PREFIX/lib" "$PREFIX/include"
cp libcrypto.a "$PREFIX/lib/"
cp -r include/openssl "$PREFIX/include/"
echo "OpenSSL $OPENSSL_VERSION libcrypto installed to $PREFIX"
