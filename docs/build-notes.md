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
| `libsnark-0002-sha256-round-constant-unsigned.patch` | libsnark | **Wrong proofs from the browser.** `sha256_round_function_gadget` stored the round constant in a `long` and used `FieldT(K)`. On wasm32 `long` is 32 bits, so the 32 SHA-256 constants ≥ 2³¹ became *negative* field elements. The wasm-built circuit was self-consistent and even hashed correctly (the error cancels mod 2³²), but its coefficients differed from the native constraint system inside `pk.bin`, starting at constraint 9,922. Every browser proof was invalid. Now `K` is `unsigned long` and built with `FieldT(K, /*is_unsigned=*/true)`. Native output is unchanged, so existing keys stay valid. Found by comparing the wasm and native constraint systems (`debug_witness` export). |
| `libff-0002-multiexp-asm-volatile-memory.patch` | libff | **Valid proofs rejected by the native verifier.** libsnark's Groth16 verifier computes `Σ publicᵢ·ICᵢ` with libff's Bos–Coster multi-exponentiation, whose heap compares bigints with x86-64 inline asm. That asm was not `volatile` and did not declare that it reads memory (it only receives pointers). GCC 16 at `-O3` reused stale comparison results inside the heap loop, so the accumulation was wrong for about 2/3 of random public inputs (8 of 12 random nonces). The fix: `__asm__ volatile` + `"memory"` clobber. The regression test `tests/test_multiexp.cpp` (500 random public-input vectors, Bos–Coster vs naive) fails without the patch and passes with it. wasm was never affected (no asm there). |
| `libff-0003-wasm32-call-free-field-arithmetic.patch` | libff | **Speed (wasm only).** The browser prover was 9.6× slower than native in every phase (FFTs 14.2 s, H multi-exponentiation 24.8 s, total 42.4 s). That is the cost of generic field arithmetic: each Montgomery multiplication made about 20 calls into GMP's portable `mpn_*` code. The new `fp_wasm32.tcc` implements CIOS Montgomery multiplication and modular add/sub for 8 × 32-bit limbs with 64-bit accumulators (wasm has native `i64.mul`), with no calls. It is enabled only under `__EMSCRIPTEN__` with 32-bit limbs; native builds keep libff's x86-64 asm. Checked by: 1.2 M random mul/add/sub results vs a GMP `mpz` reference on the raw Montgomery values (`selftest_field`); 60 scalar/point results identical to native (`debug_arith`); every prover intermediate identical to native (`debug_parts`); 12/12 random-nonce proofs verify natively. Result: **42.4 s → 10.3–10.5 s** in Chrome. |
| `libfqfft-0001-replace-removed-bind1st.patch` | libfqfft | `std::bind1st` was removed in C++17. GCC's libstdc++ still ships it, so the native build worked. Emscripten's libc++ does not, so the wasm build failed. It is replaced by an equivalent lambda. |
| `libsnark-0003-cxx20-constructor-names.patch` | libsnark | `knowledge_commitment<T1,T2>(…)` and `digest_variable<FieldT>(…)` declare constructors with a *template-id* as the name. C++20 forbids that (DR 2237). GCC 13, the Ubuntu 24.04 compiler in Docker, rejects it; GCC 14+ and Clang only warn, so the host build (GCC 16) never showed it. The fix uses the injected class name. Found by syntax-checking every source with GCC 13 inside the Docker toolchain image. |


The prompt warned about missing standard headers and deprecated Boost. Those
affect parts of libsnark we no longer build (gadgetlib2, the profiling
binaries, Boost.program_options). What the parts we *do* build needed is the
table above: one fix for older compilers (0003), one for Emscripten's libc++
(libfqfft-0001), and three correctness and performance fixes that only appear
across platforms (libsnark-0002, libff-0002, libff-0003).

## OpenSSL in the browser

libff includes `<openssl/sha.h>` (for `SHA512_rng`, reachable through the
Merkle gadget's headers). So the wasm build needs OpenSSL headers, and we use
the library for real work too: `prover-wasm/build-openssl.sh` cross-compiles
**libcrypto from the same OpenSSL 3.6.4 source** (`linux-generic32 no-asm
no-threads no-sock no-dso no-engine no-module …`). The browser computes the
proof hash that goes into the signed SIWE statement with OpenSSL's
`EVP_Digest(SHA-256)`, the same call the server makes. One wrinkle:
`emconfigure` exports `CC` as an absolute path, and OpenSSL's Configure also
derives a `CROSS_COMPILE` prefix from it, so the generated Makefile's
`CROSS_COMPILE=` line is blanked.

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
| M2 | `ZkAuthCircuit`: **280,670 constraints**, 255,817 variables, 8 public inputs (breakdown in how-it-works §4). Native, single thread: setup 15.0 s, prove 4.57 s, verify < 3.5 ms incl. vk processing. 25 test cases pass in release (49 s) and 24 under ASan + UBSan (191 s). |
| M3 | `zkauth-setup`: pk.bin 148,499,473 B (65.0 MB of it is the R1CS), vk.bin 1,249 B, vk.json 2,836 B. `zkauth-issuer` tree: 20 dummies + 1 real credential at leaf 20, root `ec375622…3fd6`. The path verifies natively (`zkauth-issuer check`), and a native proof with that credential verifies (`zkauth-prove`: pk load 300 ms, witness 242 ms, prove 4,522 ms). |
| M4 | Real wasm prover (libsnark + libff + GMP + OpenSSL libcrypto). First measurement: Chrome 156 Web Worker prove **42.4 s** vs native 4.42 s, over the 30 s threshold. ⛔ asked; decision: keep depth 8 and optimise the wasm field arithmetic (patch libff-0003). After that: **`zkauth_prover.wasm` 2,548,838 B; Chrome 156 Web Worker prove 10.3–10.5 s** (wall 10.8–11.5 s incl. witness 0.40 s and key parse 0.44 s; cold download, in-memory and Cache API runs alike). Node profile: FFTs 14.21 → 3.43 s, H multiexp 24.76 → 5.46 s, A+B+L 3.45 → 0.77 s, total 42.44 → 9.67 s, i.e. 2.2× native. The browser proof and 12/12 random-nonce wasm proofs verify natively. `tests/e2e/wasm-consistency.mjs` passes. |
| M5 | `server/eth_sig.*` (OpenSSL only: `EVP_MD_fetch("KECCAK-256")`, EIP-191, secp256k1 recovery via `EC_POINT_set_compressed_coordinates` + one `EC_POINT_mul`, EIP-55) and `server/siwe.*` (strict EIP-4361). Tests: 10,000 libsecp256k1 (v0.7.1) signatures recover identically, both v encodings (20,000 recoveries); 4 MetaMask `personal_sign` vectors from `@metamask/eth-sig-util` 9.0.0, one reproducing eth-sig-util's documented signature; high-s, r/s range, bad v, off-curve r rejected; 19 malformed SIWE variants rejected. 9 test cases, 20,181 assertions, 4.6 s in release. |
| M6 | `zkauth-server` (Crow 1.3.3, standalone Asio 1.36.0, `.multithreaded()`): `/nonce`, `/login` (9-step check chain), `/verify-proof`, `/verify-sig`, `/me`, `/health`; sharded nonce/nullifier stores, atomically reloaded roots, Ed25519 JWT sessions (15 min). Client steps 5–7: SIWE with the EIP-55 address computed by OpenSSL Keccak in wasm, `personal_sign`, login, `/me`, "what the server saw". `tests/e2e/m6-login.mjs` (headless Chrome 156, real server, mock EIP-1193 wallet): full login in 13.1 s (proving 10.6 s); token `sub` = wallet; PII-absence checks pass on every captured request; replay rejected by `nonce`. |
| M7 | Attack lab (5 attacks) caught by the expected checks in headless Chrome (`m7-attack-lab.mjs`: nonce, groth16, site-id, body, signature). `test_login.cpp`: 26 failure-path sections, each asserting its check and the generic 401; sessions, nullifier conflict, re-randomised proof, production mode, 8-thread Groth16. `test_stores.cpp`: TTL, single use (16 threads × 50 rounds), nullifier races, atomic root reload, base64url, key persistence. **libFuzzer** (clang 22, ASan + UBSan, `tests/fuzz/run.sh`): `fuzz_proof_json` 600 s, 12.6 M execs, corpus 1,765, no crashes; `fuzz_signature` 600 s, 43.3 M execs, corpus 74, no crashes; `fuzz_siwe` **found a bug** after 3.4 M execs (`Chain ID: 06` parsed as 6, so two signed texts meant one chain; fixed by rejecting leading zeros, regression in `tests/fuzz/regressions/` and `test_siwe.cpp`), then 600 s, 21.3 M execs, corpus 2,986, no crashes. Full suite under ASan + UBSan: **53/53** in 9 min 48 s. |
| M8 | Node baseline (Fastify 5.12.7, snarkjs 0.7.6 algorithm with the curve and vk cached, ethers 6.17.0) in `node:24` LTS; libsnark → snarkjs converter validated (100 valid + 100 tampered proofs: both servers 100/100 correct, 0 disagreements). Micro p50: Groth16 2.30 ms (C++) vs 6.73 ms (Node); ecrecover 0.22 vs 1.12 ms. Load at 64 connections, 12 threads/workers: `/verify-proof` 2,759 vs 1,141 req/s; `/verify-sig` 28,768 vs 5,535 req/s; 100% correct verdicts over 2,612,284 requests. Optimisations: processed vk 1.15×, reused OpenSSL contexts 1.04×, Crow 1→12 threads 7.8×/6.7×, wasm field arithmetic 4.1×. Raw data in `bench/results/`, write-up in `docs/results.md`. Tooling note: building wrk from source was blocked in this environment, so k6 (official image, pinned) is the load generator. |
| M9 | Docker: stages `native-build`, `wasm-build`, `runtime` (Ubuntu 24.04 + OpenSSL 3.6.4 libs), `baseline` (`node:24`), `web` (`nginx:1.29-alpine`), all pinned by digest; `docker-compose.yml` with a one-shot `init` (setup, issuer tree, demo credential in `./demo/`). The first compose build hit a GCC 13-only C++20 error in libsnark (patch libsnark-0003). After that, `docker compose up` → headless login through nginx at http://localhost:8080 in the Docker-built wasm: proving 10.2 s, `/me` OK, PII checks pass. Release suite after the patch: 53/53. |
