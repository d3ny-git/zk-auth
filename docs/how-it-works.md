# How Zk-Auth works

This document is written for a computer-science student who knows C++ but has
never used a zero-knowledge proof. It is updated after every milestone. All
numbers and hex values are real outputs from this repository's test runs.

Contents:

1. [The problem](#1-the-problem)
2. [The login, end to end](#2-the-login-end-to-end)
3. [zk-SNARKs from zero](#3-zk-snarks-from-zero)
4. [The circuit, gadget by gadget](#4-the-circuit-gadget-by-gadget)
5. [Commitments, Merkle trees and nullifiers](#5-commitments-merkle-trees-and-nullifiers)
6. [How the browser proves](#6-how-the-browser-proves)
7. [Ethereum signatures and address recovery](#7-ethereum-signatures-and-address-recovery)
8. [The server's check chain](#8-the-servers-check-chain)
9. [The attack lab](#9-the-attack-lab)
10. [What the benchmarks show](#10-what-the-benchmarks-show)
11. [Limitations](#11-limitations)

---

## 1. The problem

A website that must only admit adults usually asks for a date of birth, or
worse, a scan of an ID. It then stores that personal data forever and becomes a
target for anyone who wants it. What the site actually needs is one bit: *is
this person over 18?* It also needs assurance that the bit came from someone
trustworthy rather than from the user typing a fake date. Zk-Auth gives the site
exactly that and nothing more. A trusted **issuer** (think: a government office
or a bank that has seen your ID) gives you a credential once. From then on your
browser produces a short mathematical proof that "the issuer vouched for a date
of birth that is at least 18 years ago, and I hold that credential". The site
verifies the proof in milliseconds and never sees the date, the credential, or
even *which* of the issuer's credentials you hold. It also proves that you
control an Ethereum wallet, which becomes your account identifier on the site.

## 2. The login, end to end

*(Sequence diagram added at M6, when the full protocol runs.)*

## 3. zk-SNARKs from zero

### Statements and witnesses

A zero-knowledge proof convinces a **verifier** that a **statement** is true
without revealing *why* it is true. The statement has two kinds of inputs:

* **public inputs**, which both sides know (in the toy example: `out = 35`);
* the **witness**, private values only the prover knows (the toy: `x = 3`).

The statement for the M1 risk spike is "I know an `x` with x³ + x + 5 = out".
The verifier learns that such an `x` exists and that the prover knows it.
Nothing else.

**zk-SNARK** stands for *zero-knowledge succinct non-interactive argument of
knowledge*. "Succinct" means the proof is tiny and quick to check. "Non-
interactive" means it is a single message, with no back-and-forth.

### From a program to R1CS

A SNARK cannot run C++. The statement must first be written as a **rank-1
constraint system (R1CS)**: a list of equations, each of the form

```
(linear combination) × (linear combination) = (linear combination)
```

over a vector of variables `z`. For the toy, `z = (1, out, x, x2, x3)` and the
constraints (see `core/toy_circuit.hpp`) are:

| # | A | × B | = C | with the witness z = (1, 35, 3, 9, 27) |
|---|---|---|---|---|
| 1 | x | x | x2 | 3 × 3 = 9 ✓ |
| 2 | x2 | x | x3 | 9 × 3 = 27 ✓ |
| 3 | x3 + x + 5 | 1 | out | 35 × 1 = 35 ✓ |

Every value lives in a prime field: arithmetic is modulo the 254-bit prime
`r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
That is why everything in our formats is a 32-byte number. One multiplication
per constraint is the only primitive available. So anything non-arithmetic
(bits, comparisons, SHA-256) has to be built from many constraints, which is
why Zk-Auth's real circuit has about 280,000 of them.

### Why the proof is tiny and verification is fast

The prover turns the constraint list into polynomials (a **QAP**, quadratic
arithmetic program). "All constraints hold" then becomes "polynomial
`A(t)·B(t) − C(t)` is divisible by a known polynomial `Z(t)`". The prover
shows this divisibility at a single secret point `τ`. Nobody knows `τ`; it
exists only "in the exponent", baked into elliptic-curve points by the trusted
setup.

In **Groth16**, the proof system we use, a proof is exactly three curve points:

* `A` in G1, `B` in G2, `C` in G1 (BN254 / alt_bn128 curve).

That is 128 bytes compressed, or 256 bytes in our uncompressed JSON. The size
is the same for 3 constraints or 3 million. The verifier checks one equation
with a **pairing** `e(·,·)`, a bilinear map from G1 × G2 into a target group:

```
e(A, B) = e(α, β) · e(L, γ) · e(C, δ),     L = IC₀ + Σ publicᵢ · ICᵢ
```

Here `α, β, γ, δ` and the `ICᵢ` come from the verification key. The cost is three
pairings plus one small multi-scalar multiplication with one term per public
input. It does **not** depend on the circuit size. That is why the server can
verify a proof of a 280,000-constraint statement in about a millisecond.

The M1 browser proof for `x = 3` (from `build/m1/browser_proof.json`):

```json
{"a": {"x": "2880e9e8…6f3f", "y": "07f97f76…a4bb"},
 "b": {"x": ["256b7782…1b0e", "0017a8b5…b353"], "y": ["2c20b099…abf1", "0687cc40…6362"]},
 "c": {"x": "2de8adad…e046", "y": "2be941e4…4d7d"}}
public: ["00…0023"]   (0x23 = 35)
```

Changing the public input to 36 makes the native verifier answer `INVALID`.

### The trusted setup, and why it matters

Groth16 needs a one-time **setup** per circuit. It samples random secrets
(`τ, α, β, γ, δ`), publishes curve points derived from them as the **proving
key** and **verification key**, and must then destroy the secrets. These
secrets are called the "toxic waste". Anyone who kept them could forge proofs
of false statements, for example "I am over 18" without a credential. Our
`zkauth-setup` is a *single-party* setup and prints a warning saying so. It is
fine for a demo. In production, a multi-party ceremony (e.g. "powers of tau")
is used: many participants each add their own randomness, and the result is
safe as long as *one* of them destroyed their share.

### Where the "zero knowledge" comes from

The prover adds two fresh random field elements (`r`, `s`) to every proof. Two
proofs of the same statement therefore look unrelated, and a proof reveals
nothing about the witness. In the browser that randomness comes from
`crypto.getRandomValues()` (libff `random_element()` → `std::random_device` →
Emscripten `getentropy()`).

## 4. The circuit, gadget by gadget

*(Written at M2.)*

## 5. Commitments, Merkle trees and nullifiers

*(Written at M2/M3, with a worked example from the fixtures.)*

## 6. How the browser proves

### Compiling libsnark to WebAssembly

The prover is the same C++ code as the native tools. libsnark, its field and
curve library libff, and the big-number library GMP are compiled with
Emscripten into one `.wasm` module (`prover-wasm/`). The steps that make this
work, and the three small patches it needed, are in
[build-notes.md](build-notes.md). The one surprising detail is that the native
build uses 64-bit limbs and the browser 32-bit ones, yet the proving key file
is byte-for-byte compatible (explained in build-notes).

### The Web Worker

Proving takes seconds and would freeze the page if it ran on the main thread.
`client/*-worker.js` loads the wasm module inside a **Web Worker**. The page
sends it the inputs with `postMessage` and receives a JSON proof back. The M1
check confirms the proof really was made in a `DedicatedWorkerGlobalScope`.

*(Proving key size, caching and the real proving time are added at M4.)*

## 7. Ethereum signatures and address recovery

*(Written at M5.)*

## 8. The server's check chain

*(Written at M6.)*

## 9. The attack lab

*(Written at M7.)*

## 10. What the benchmarks show

*(Written at M8.)*

## 11. Limitations

*(Completed at M9.)* Already known: the trusted setup is single-party (§3).
