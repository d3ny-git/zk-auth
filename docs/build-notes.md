# Build notes

Everything needed to rebuild Zk-Auth bit-for-bit, and every change made to
third-party code.

## Toolchains

| Where | Compiler | CMake | Other |
|---|---|---|---|
| Development host | GCC 16.2.1, Clang 22.1.8 (Arch Linux, kernel 7.2) | 4.4.4 | OpenSSL 3.6.4 (system) |
| Docker `toolchain` stage | GCC 13 (Ubuntu 24.04 `@sha256:24737cef…`) | 3.28 | OpenSSL 3.6.4 built from source |
| Docker `wasm-toolchain` stage | Emscripten 6.0.13 (`emscripten/emsdk@sha256:fb7864e3…`) | 3.28 | GMP 6.3.0 cross-compiled |

Pinned sources:

| Dependency | Version | Pin |
|---|---|---|
| libsnark | scipr-lab master | submodule commit `27993768` (+ recursive submodules) |
| GMP (wasm) | 6.3.0 | SHA-256 `a3c2b802…` in `prover-wasm/build-gmp.sh` |
| OpenSSL (Docker) | 3.6.4 | SHA-256 `9bffaa1a…` in `Dockerfile` |
| Catch2, Google Benchmark, nlohmann/json, Asio, Crow, libsecp256k1 | see `cmake/Deps.cmake` | release tarball + SHA-256 |

## How libsnark is built (and why not with its own CMake)

`cmake/Libsnark.cmake` compiles the slice of libff + libsnark we use (the
alt_bn128 curve, libff's common utilities and gadgetlib1's profiling table;
everything else is header-only templates) as one static target, `zk_libsnark`.

libsnark's own `CMakeLists.txt` does several things that are wrong for us:

* forces `-std=c++11 -march=native` into `CMAKE_CXX_FLAGS` (`-march=native` makes
  Docker images non-portable, and emcc rejects it);
* unconditionally requires Boost.program_options and pkg-config `libcrypto`, and
  builds gtest, gadgetlib2, TinyRAM and ate-pairing, none of which we use;
* configures itself with **directory-scoped** `add_definitions()`. Those
  definitions do not reach our own targets, yet they change data layouts and
  the serialisation format. If our code saw `BINARY_OUTPUT` but the library
  did not (or the other way round), the program would still link and then read
  keys wrongly. That is an ODR violation that fails without any error.

The shim puts the same switches on one target as `PUBLIC` compile definitions,
so the library, our code and the WebAssembly build always agree:

| libsnark / libff CMake option | Our setting | Preprocessor effect |
|---|---|---|
| `CURVE=ALT_BN128` | same | `-DCURVE_ALT_BN128` |
| `WITH_PROCPS=OFF` | same | `-DNO_PROCPS` |
| `MULTICORE=OFF` | same | (no `-DMULTICORE`) |
| `WITH_SUPERCOP=OFF` | same | supercop not compiled |
| `BINARY_OUTPUT=ON` | same | `-DBINARY_OUTPUT` |
| `MONTGOMERY_OUTPUT=ON` | same | `-DMONTGOMERY_OUTPUT` |
| `USE_PT_COMPRESSION=ON` (default) | **OFF** | `-DNO_PT_COMPRESSION=1` |
| `USE_ASM=ON` | ON natively, **OFF** in wasm | `-DUSE_ASM` (x86-64 only) |

`USE_PT_COMPRESSION=OFF` stores both coordinates of every point. Keys get
about 1.5× bigger, but the browser no longer computes a modular square root for
every point while loading the proving key.

### Why one proving key works for both 64-bit and 32-bit builds

libff stores a field element as `n` GMP limbs: 4 × 64-bit natively, 8 × 32-bit
in wasm32 (GMP built with `--host=none` uses `long`, which is 32 bits there).
`alt_bn128_init.cpp` carries constants for both limb sizes. With
`MONTGOMERY_OUTPUT`, a field element is written as its raw Montgomery form
`a·R mod p` with `R = 2^(limb_bits · n) = 2^256` in **both** builds. The limbs
are little-endian, so the 32 bytes written are identical. Integers (vector
lengths, indices) are written as decimal text, so the difference between a
4-byte and an 8-byte `size_t` does not matter either. M1 confirmed this: a key
written natively loads in wasm, and proofs made there verify natively.

## Patches (`third_party/patches/`, applied by `third_party/apply-patches.sh`)

The script runs at CMake configure time. It applies each patch once and treats
an already-applied patch as success, so re-configuring is safe.

| Patch | Applies to | Why |
|---|---|---|
| `libsnark-0001-gate-stdout-prints.patch` | libsnark | The generator, prover and multi-exponentiation `printf` statistics unconditionally (QAP sizes, key sizes, "Elements of w skipped", "Swap is not beneficial", and "Input length differs" on a failed verification). That corrupts CLI JSON on stdout, floods the server log, and becomes a `printf` per rejected proof under load. Each is now wrapped in `if (!libff::inhibit_profiling_info)`, the flag libsnark already uses for its other output. |
| `libff-0001-gate-stdout-prints.patch` | libff | The same fix for `multi_exp_with_mixed_addition`. |
| `libfqfft-0001-replace-removed-bind1st.patch` | libfqfft | `std::bind1st` was removed in C++17. GCC's libstdc++ still ships it, so the native build worked. Emscripten's libc++ does not, so the wasm build failed. It is replaced by an equivalent lambda. |

No patch was needed for GCC 16 or Clang 22 in C++20 mode for the parts we
compile. The prompt warned about missing standard headers and deprecated Boost,
but those affect the parts of libsnark we no longer build (gadgetlib2, the
profiling binaries, Boost.program_options).

## WebAssembly build (`prover-wasm/`)

* `build-in-docker.sh` (host) → runs `build.sh` in the `wasm-toolchain` image as
  the calling user, with the repository mounted at the same absolute path so
  CMake caches stay valid.
* `build-gmp.sh` cross-compiles GMP 6.3.0: `emconfigure ./configure
  --host=none --disable-assembly --disable-shared`. GMP's configure requires
  `m4`, which the emsdk image lacks; the `wasm-toolchain` stage adds it (and
  Ninja). `gmpxx` is not built, because nothing we compile uses it.
* Link flags (`prover-wasm/CMakeLists.txt`): ES6 module factory
  (`createProver`), `ENVIRONMENT=worker,node`, memory growth up to the 4 GB
  wasm32 limit, an 8 MB stack (the default is 64 KB), and native wasm
  exceptions (`-fwasm-exceptions`) everywhere.
* The prover's zero-knowledge blinding (`r`, `s`) comes from libff's
  `random_element()` → `std::random_device` → in Emscripten `getentropy()` →
  `crypto.getRandomValues()`. So proofs made in the browser are blinded with the
  browser's CSPRNG.

## Milestone log

| Milestone | Result |
|---|---|
| M0 | `cmake --preset native-debug && ctest` in Docker: 1/1 passed (ASan + UBSan, GCC 13) |
| M1 | Toy circuit x³+x+5=35: 3 constraints. Native prove 2.4 ms, verify 2.5–3.1 ms (includes processing the vk). Wasm: `zkauth_prover.wasm` 485,342 B (toy build), Chrome 156 Web Worker prove 22.3 ms, i.e. about 9× native on this tiny circuit. The browser proof verifies natively. A tampered public input (36 instead of 35) is rejected. |
