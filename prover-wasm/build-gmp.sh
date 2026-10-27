#!/bin/bash
# Cross-compiles GMP to wasm32 with Emscripten. Runs inside the
# wasm-toolchain image (see Dockerfile). Usage: build-gmp.sh PREFIX
#
#   --host=none          GMP's "no CPU" target: portable C only
#   --disable-assembly   no x86 assembly (it would not assemble to wasm anyway)
# wasm32 has 32-bit `long`, so GMP picks 32-bit limbs; libff adapts to that.
set -euo pipefail
PREFIX=${1:?usage: build-gmp.sh PREFIX}
GMP_VERSION=6.3.0
GMP_SHA256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

if [ -f "$PREFIX/lib/libgmp.a" ]; then
    echo "GMP already built in $PREFIX"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/gmp.tar.xz" "https://ftp.gnu.org/gnu/gmp/gmp-$GMP_VERSION.tar.xz"
echo "$GMP_SHA256  $work/gmp.tar.xz" | sha256sum -c -
tar -C "$work" -xf "$work/gmp.tar.xz"
cd "$work/gmp-$GMP_VERSION"
emconfigure ./configure --host=none --disable-assembly --disable-shared --enable-static \
    --prefix="$PREFIX" CFLAGS="-O3" >/dev/null
emmake make -j"$(nproc)" >/dev/null
emmake make install >/dev/null
echo "GMP $GMP_VERSION installed to $PREFIX"
