#!/bin/sh
# Idempotently applies third_party/patches/*.patch to the libsnark submodule
# (libsnark-*.patch) and to its libff / libfqfft submodules (libff-*.patch,
# libfqfft-*.patch). Safe to run
# repeatedly; CMake runs it at configure time. Each patch is explained in
# docs/build-notes.md.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

apply() { # $1 = tree, $2 = patch
    if (cd "$1" && git apply --check "$2" 2>/dev/null); then
        (cd "$1" && git apply "$2")
        echo "zk-auth: applied $(basename "$2")"
    elif (cd "$1" && git apply --reverse --check "$2" 2>/dev/null); then
        : # already applied
    else
        echo "zk-auth: patch $(basename "$2") does not apply to $1" >&2
        exit 1
    fi
}

for p in "$here"/patches/libsnark-*.patch; do apply "$here/libsnark" "$p"; done
for p in "$here"/patches/libff-*.patch; do apply "$here/libsnark/depends/libff" "$p"; done
for p in "$here"/patches/libfqfft-*.patch; do apply "$here/libsnark/depends/libfqfft" "$p"; done
