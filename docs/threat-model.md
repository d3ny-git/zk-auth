# Threat model

**Assets:** the user's date of birth and credential secret (must never leave
the device), the user's account on the site (must not be usable by anyone
else), and the site's guarantee that each account belongs to a distinct adult
credential holder.

**Trusted:** the issuer (vouches for dates of birth, publishes roots), the
trusted setup (see Limitations), the user's browser and wallet.
**Untrusted:** the network, other users, and anything in a request body.

Check numbers refer to the `/login` chain in
[how-it-works.md §8](how-it-works.md#8-the-servers-check-chain). Every test
listed passes: `ctest --preset native-release` (C++), `node tests/e2e/*.mjs`
(browser), `tests/fuzz/run.sh` (fuzzers).

## Threats and what stops them

| # | Threat | Stopped by | Proven by (passing test) |
|---|---|---|---|
| T1 | **Replay** of a captured login request | check 2: nonce single-use, removed atomically under its shard lock | [test_login.cpp](../tests/test_login.cpp) "nonce used twice (replay)"; [test_stores.cpp](../tests/test_stores.cpp) "exactly one of many concurrent logins can consume a nonce" (16 threads × 50 rounds); [m6-login.mjs](../tests/e2e/m6-login.mjs) "replayed request rejected"; attack lab *replay* ([m7-attack-lab.mjs](../tests/e2e/m7-attack-lab.mjs)) |
| T2 | Harvested **old nonce** | check 2: 120 s TTL (+ periodic sweep) | test_login "nonce expired (TTL 120 s)"; test_stores "nonces are single use and expire" |
| T3 | **Moving a proof** to a new nonce (pre-computed proofs, proof theft) | Groth16 binds every public input (check 6); SIWE nonce must equal the proof's (check 3) | [test_proof.cpp](../tests/test_proof.cpp) "wrong nonce"; test_login "valid proof, but for a different nonce", "SIWE: nonce differs from the proof's nonce"; attack lab *nonce* |
| T4 | **Cross-site reuse** of a proof | `site_id` is a public input pinned by the server (check 4) | test_login "proof made for another site"; test_proof "wrong site id"; attack lab *site* |
| T5 | **Cross-site linkage** (sites comparing databases) | per-site nullifier `H(secret, site_id)`; no global identifier is ever sent | [test_circuit.cpp](../tests/test_circuit.cpp) "one credential gives unrelated nullifiers on different sites"; m6-login.mjs PII checks |
| T6 | **Credential sharing**: one credential, many accounts | check 8: nullifier → address binding | test_login "one credential = one account per site"; test_stores "concurrent binds of one nullifier: one winner" |
| T7 | **Under-age** holder | circuit `dob ≤ age_cutoff` (32-bit range enforced); server pins the cutoff it issued with the nonce (check 4) | test_circuit "the age check is dob <= cutoff, inclusive", "a later cutoff is satisfiable, so the server must pin age_cutoff"; test_login "later age cutoff than the server issued" |
| T8 | **Fake credential** / self-built tree | Merkle membership in-circuit; root must be published by the issuer (check 5) | test_circuit "a credential that is not in the tree yields a different root"; test_login "Merkle root the issuer never published" |
| T9 | **Forged or foreign signature** | check 7: recovered signer == SIWE address | test_login "signature from a different wallet"; [test_eth_sig.cpp](../tests/test_eth_sig.cpp) "10,000 libsecp256k1 signatures recover identically", "MetaMask personal_sign vectors"; attack lab *wallet* |
| T10 | **Signature malleability** (high-s twin) | low-s rule (EIP-2), `r, s` ranges, `v` set, `r` on curve, `Q ≠ ∞` | test_eth_sig "malformed and malleable signatures are rejected" |
| T11 | **Phishing**: a signature made for another site, URI or chain | check 3: SIWE domain, URI, chain id | test_login "SIWE: signed for another domain (phishing)", "scheme-qualified domain", "other URI", "other chain" |
| T12 | **Stale or post-dated** signatures | check 3: issued-at within 5 min (30 s skew), Expiration Time / Not Before | test_login "SIWE: issued more than 5 minutes ago", "issued in the future", "past its Expiration Time" |
| T13 | **Proof swapping**: valid signature, different proof | check 3: statement commits to `sha256(canonical(proof) ‖ canonical(public))`; exactly one tag | test_login "statement commits to a different proof", "statement with two proof tags", "statement without the proof tag" |
| T14 | **Groth16 proof malleability** (re-randomisation `A/r, rB, C`) | does not matter: the re-randomised proof has a different hash than the one the wallet signed (check 3), and the nonce is single-use (check 2) | test_login "a re-randomised proof verifies, but cannot reuse a signature" |
| T15 | **Invalid-curve / small-subgroup** points | parse: G1 on curve; G2 on twist *and* `r·P = 0`; field elements `< p` | [test_formats.cpp](../tests/test_formats.cpp) "G1 … off-curve …", "G2 … out-of-subgroup are rejected", "field elements … must be reduced"; test_login "proof point off the curve" |
| T16 | **Malformed input**, parser bugs, memory corruption | 16 KB limit, strict parsers (exact keys, exact hex, strict EIP-4361/RFC 3339/base64url), fail closed; ASan + UBSan; fuzzing | test_login body sections; [test_siwe.cpp](../tests/test_siwe.cpp) "malformed SIWE messages are rejected"; libFuzzer targets in [tests/fuzz/](../tests/fuzz) (results in build-notes); `ctest --preset native-debug` under ASan + UBSan |
| T17 | **Error oracle** (learning which check failed) | generic `401 authentication failed`; reason only in the server log (and in a header only in development mode) | test_login "production mode never reveals which check failed"; every failure section checks the generic body |
| T18 | **PII reaching the server** | protocol: only `{proof, public, siwe_message, signature}` is sent; proof is zero-knowledge (fresh `r, s` from `crypto.getRandomValues`) | m6-login.mjs PII-absence test on every captured request (secret; dob as text, day count and circuit hex; Merkle path) |
| T19 | **Session token** forgery, `alg` confusion, theft | Ed25519 JWT with exactly `{"alg":"EdDSA","typ":"JWT"}`; 15 min expiry; key file 0600, git-ignored | test_login "success, session token, /me" (tampered payload/signature, `alg:none`, expiry); test_stores "session keys are generated once, kept private, and survive restarts" |
| T20 | **Races** under concurrent load (double use of nonce or nullifier) | 64-way sharded locks; atomic roots swap; read-only processed vk | test_stores concurrency cases; test_login "Groth16 verification is safe to run on many threads at once" |
| T21 | **Cheap denial of service** against the pairing check | check order: everything costing µs runs before the ~1 ms pairing; nonce burned on first failure | test_login "cheap checks run before the pairing check" |
| T22 | **Prover/verifier disagreement** across platforms (found in M4) | patches libsnark-0002, libff-0002, libff-0003 | [wasm-consistency.mjs](../tests/e2e/wasm-consistency.mjs); [test_multiexp.cpp](../tests/test_multiexp.cpp) "Bos-Coster accumulation equals the naive sum" |

## If the server is compromised

An attacker with the server's memory or database gets:

* the **nullifier → address** map: per-site pseudonyms and the Ethereum
  addresses that logged in. Addresses are public on-chain anyway. Nullifiers
  cannot be linked to nullifiers on other sites without credential secrets
  (T5).
* outstanding **nonces** (worthless after 120 s), the published **roots**
  (public), the **verification key** (public), and the **session-signing
  key**. With that key they can mint sessions for *this* site. Rotating it
  invalidates all sessions.

They do **not** get any date of birth, credential secret or Merkle path,
because the server never receives them (T18). A breach therefore exposes who
logged in with which wallet, but not who those people are or how old they
are.

## Limitations (accepted, documented risks)

| Limitation | Consequence | Closest test / mitigation |
|---|---|---|
| **Single-party trusted setup** (`zkauth-setup`) | Whoever ran it could have kept τ, α, β, γ, δ and could forge proofs of false statements. | `zkauth-setup` prints a warning. Production: a multi-party ceremony (e.g. a perpetual powers of tau plus a circuit-specific phase 2), safe if any one participant was honest. |
| **Single issuer, fully trusted** | A dishonest issuer can issue credentials for false birthdays or for people who do not exist (Sybil). | The server trusts exactly the roots in `roots.json` (test_login "Merkle root the issuer never published"). Production: several issuers, issuer accountability, revocation lists. |
| **No revocation** | A leaked `cred.json` works until the issuer stops publishing roots that contain it. | The nullifier binding (T6) limits a stolen credential to one account per site. Production: revocation via a non-membership proof or epoch-based roots. |
| **Anonymity set = tree** | Membership hides the user among the tree's commitments (20 dummies + real users, up to 256). | `zkauth-issuer init --dummies`. Production: much larger trees (depth 20–32) and more efficient hashes (Poseidon). |
| **Body size limit is after buffering** | Crow buffers the full request before the 16 KB check, so a large body still costs memory. | Put a reverse proxy with a body limit in front (the Docker setup's nginx does: `client_max_body_size 16k`). |
| **Clock trust** | `issued-at` and the age cutoff use the server clock. | NTP on the server; 30 s skew allowance. |
