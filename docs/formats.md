# Formats

The exact encoding of every value that crosses a boundary (file, network,
wasm↔JS). Code: `core/encoding.*`, `core/formats.*`, `core/circuit.*`. Every
format has a round-trip test in `tests/test_formats.cpp` or
`tests/test_encoding.cpp`.

## Conventions

* **Hex in proof / public / credential / path JSON** is lowercase, has no `0x`
  prefix, and has exactly `2 × bytes` characters. Anything else is rejected.
  Each value therefore has exactly one text form. That matters because the
  wallet signs a hash of this text (see [Proof hash](#proof-hash)).
* **Ethereum values** (addresses, signatures) arrive from wallets as `0x…` in
  either case; they are parsed leniently but with an exact length.
* **Bits of a byte string** are numbered most-significant-bit first, so bit 0 is
  the top bit of byte 0. This is how libsnark's SHA-256 gadget numbers its
  input and output wires.
* **Parsers fail closed.** A JSON object must have exactly the expected keys:
  missing *and* unexpected keys are both errors.

## Field elements

32-byte big-endian hex of the canonical value, which must be **less than the
modulus**. Otherwise `x` and `x + p` would be two encodings of one element.

| Field | Modulus |
|---|---|
| Fr (scalar field, circuit values, public inputs) | `30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001` |
| Fq (base field, point coordinates) | `30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47` |

## Curve points (alt_bn128 / BN254)

* **G1:** affine `{"x": Fq, "y": Fq}`. Parsing checks the point is on
  `y² = x³ + 3`. G1 has cofactor 1, so that also places it in the prime-order
  group.
* **G2:** affine `{"x": [c0, c1], "y": [c0, c1]}`, where an Fq2 element is
  `c0 + c1·u` with `u² = −1`. This is the order snarkjs uses; Ethereum's
  precompile ABI uses `[c1, c0]`. Parsing checks the point is on the twist
  curve **and** that `r·P = 0`, i.e. it is in the order-r subgroup. The twist
  has a huge cofactor.
* The point at infinity is written with all coordinates zero. That is accepted
  only where it can legitimately occur (verification-key entries), never in a
  proof.

## Proof

```json
{"a": G1, "b": G2, "c": G1}
```

Three points, 256 bytes of coordinates. libsnark names them `g_A, g_B, g_C`;
snarkjs calls them `pi_a, pi_b, pi_c`.

## Keys

| File | Format | Size (M3) | Used by |
|---|---|---|---|
| `keys/pk.bin` | libsnark binary serialisation (see build-notes for the flags) | 148,499,473 B | browser prover (downloaded once, cached with the Cache API) |
| `keys/vk.bin` | libsnark binary serialisation | 1,249 B | C++ server (processed once at start-up) |
| `keys/vk.json` | `{protocol, curve, n_public, alpha_g1, beta_g2, gamma_g2, delta_g2, ic[]}`, all points as above | 2,836 B | Node baseline converter |
| `keys/manifest.json` | constraint counts, sizes, SHA-256 of pk/vk | | client cache key, docs |

libsnark's verification key stores only the pairing `e(α, β)`, not `α` and
`β` themselves. snarkjs needs the two points, so `zkauth-setup` copies
`alpha_g1` and `beta_g2` from the proving key into `vk.json`. A test checks
that `e(alpha_g1, beta_g2)` equals the vk's stored value.

Why is the proving key so large? Measured by `zkauth-setup` (each part
serialised on its own):

| Part | Entries | Bytes | What it is for |
|---|---|---|---|
| `A_query` (G1) | 255,818 | 16.6 MB | one point per variable: builds proof element A |
| `B_query` (G2 + G1, sparse) | 155,004 | 31.1 MB | B in G2 (and G1 for C); only variables that appear in some B |
| `H_query` (G1) | 294,911 | 19.2 MB | the quotient polynomial h(τ); evaluation domain 2¹⁸ + 2¹⁶ |
| `L_query` (G1) | 255,809 | 16.6 MB | the private-variable part of C |
| `constraint_system` (R1CS) | 280,670 | 65.0 MB | the prover re-evaluates A·B−C on a domain to get h(x) |

The R1CS is 44% of the file. It is not secret and it is deterministic (the
circuit code generates it), so it does not strictly need to be downloaded.
See M4 in build-notes.

## The hash `H`

```
H(a, b) = SHA256Compress(IV, a ‖ b)      a, b: 256 bits each
```

This is the SHA-256 **compression function**: one 512-bit block, the standard
initial value, **no padding and no length block**. It is *not* `SHA256(a ‖ b)`;
a test computes both and shows they differ. In-circuit it is libsnark's
`sha256_two_to_one_hash_gadget` (27,280 constraints). Natively it is the same
gadget's static `get_hash`, cross-checked against an independent textbook
implementation (`tests/sha256_reference.hpp`).

```
H(0²⁵⁶, 0²⁵⁶) = da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8
```

A value shorter than 256 bits is left-padded with zeros, big-endian:
`pad256(11456) = 00…002cc0`.

## Credential: `cred.json` (held by the user, never sent anywhere)

```json
{"secret": "<64 hex>", "dob": "2001-05-14"}
```

* `secret`: 256 bits from the issuer's CSPRNG (`RAND_bytes`).
* `dob`: in the circuit an unsigned 32-bit count of **days since 1970-01-01
  (UTC)**: `2001-05-14` = 11456 = `0x2cc0`. In the file it is ISO-8601 for
  readability. Days before 1970 cannot be encoded. The issuer records such
  holders as born on `1970-01-01`, which gives the same answer to
  "`dob ≤ cutoff`" for every cutoff after 1970.

`commitment = H(secret, pad256(dob))` is the Merkle leaf.

## Merkle path: `path.json` (from the issuer; public, but personal)

```json
{"index": 20, "siblings": ["<64 hex>", … 8 entries …], "root": "<64 hex>"}
```

* Depth 8, so 256 leaves. Node = `H(left, right)`; an empty leaf is 256 zero
  bits.
* `siblings[k]` is the sibling at height `k`; `k = 0` is the leaf level.
* Bit `k` of `index` is 1 when the path node at height `k` is a **right** child
  (its sibling is on the left). libsnark orders its path variable top-down;
  `ZkAuthCircuit::generate_witness` converts.

## Public inputs (`public` in requests)

| Field | Bytes | Hex chars | Packed into |
|---|---|---|---|
| `merkle_root` | 32 | 64 | 2 field elements |
| `nullifier` | 32 | 64 | 2 |
| `site_id` | 32 | 64 | 2 |
| `age_cutoff` | 4 (uint32 BE, days since epoch) | 8 | 1 |
| `nonce` | 16 | 32 | 1 |
| `packed` | 8 × Fr | 8 × 64 | what the verifier actually uses |

Packing (libsnark `multipacking_gadget`, natively
`libff::pack_bit_vector_into_field_element_vector`): a field element holds 253
bits (the field's capacity). Element `i` of a value is

```
Σ_{j=0}^{252} bit[253·i + j] · 2^j
```

For digests, `bit[0]` is the digest's most significant bit, so element 0 is
the first 253 bits *reversed* and element 1 holds the last 3 bits. For
`age_cutoff` and `nonce` the bits are taken least-significant first, so the
field element simply **equals the integer**. That makes them readable in the
snarkjs `publicSignals`.

The server **recomputes** `packed` from the named fields and rejects the
request if the two disagree. Otherwise a client could display one set of
values and get a different set verified.

### Worked example (test fixture credential 0, `[example]` test)

```
secret        1111111111111111111111111111111111111111111111111111111111111111
dob           2001-05-14 = 11456 days
pad256(dob)   0000000000000000000000000000000000000000000000000000000000002cc0
commitment    a55c6c30a851a0bc0bb0fb4dabb0314349a92fea91d40ec910e803efb1595163
site_id       5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
nullifier     17f35bff1aac58f073d36556b4f794d1fd0715238ace48800b6c23b8168ae899
root          7e9034f3dc1518c05f91667d3cea0b5d1e2c87d7b1358e8c9f4880127c918a08
```

```json
{
  "age_cutoff": "00003763",
  "merkle_root": "7e9034f3dc1518c05f91667d3cea0b5d1e2c87d7b1358e8c9f4880127c918a08",
  "nonce": "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
  "nullifier": "17f35bff1aac58f073d36556b4f794d1fd0715238ace48800b6c23b8168ae899",
  "packed": [
    "1051893e480112f93171ac8debe13478bad0573cbe6689fa0318a83bcf2c097e",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "191751681dc436d001127351c4a8e0bf8b29ef2d6aa6cbce0f1a3558ffdacfe8",
    "0000000000000000000000000000000000000000000000000000000000000004",
    "1a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000003763",
    "000000000000000000000000000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
  ],
  "site_id": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
}
```

`0x3763` = 14179 = `2008-10-27`, the cutoff on 2026-10-27. `packed[4]` shows
the reversal: `0x5a` = `01011010`, reversed `01011010` (a palindrome), so the
`5a` pattern survives, shifted by the 253-bit boundary.

## Server-issued values

* `nonce`: 128 bits from `RAND_bytes`, 32 hex characters. Single use, with a
  120 s TTL.
* `site_id = SHA-256("zk-auth:" ‖ site_domain)`. This is *standard* padded
  SHA-256, computed off-circuit and treated as an opaque 256-bit public value.
* `age_cutoff` = days since epoch of (today UTC − 18 years). If that calendar
  day does not exist (29 February), the last day of the month is used.

## Canonical JSON and the proof hash

`canonical(v)` is JSON with object keys sorted (byte order), no whitespace,
and only strings and arrays as leaves, so no number-formatting ambiguity:

```
proof_hash = SHA-256( canonical(proof) ‖ canonical(public) )
```

The wallet signs a SIWE message whose statement contains
`zk-auth-proof:0x<proof_hash>`. *(SIWE message layout: M5.)*
