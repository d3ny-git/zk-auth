// The client's proving step, shared by the WebAssembly module (browser) and
// the native zkauth-prove CLI (fixtures, tests), so both run identical code.
#pragma once

#include <stdexcept>

#include "circuit.hpp"
#include "formats.hpp"

namespace zk {

// The statement is false for this credential (not in the tree, under age):
// no proof is produced. The message is meant for the credential holder.
struct ProveError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct ProveRequest {
    Credential cred;            // cred.json  (never leaves the device)
    MerklePath path;            // path.json
    Digest issuer_root{};       // path.json "root"
    Digest site_id{};           // GET /nonce
    std::uint32_t age_cutoff{}; // GET /nonce
    Nonce nonce{};              // GET /nonce
};

struct ProveResult {
    Proof proof;
    PublicInputs pub;
    double witness_ms = 0, prove_ms = 0;
};

// cred.json, path.json and the /nonce response (extra fields such as
// issued_at are ignored; only site_id, age_cutoff and nonce are used).
ProveRequest prove_request_from_json(const json& cred, const json& path, const json& server);

ProveResult prove_login(const ProvingKey& pk, const ProveRequest& req);

// Diagnostic: re-runs the Groth16 prover's internal steps with zero blinding
// and returns each intermediate (H coefficients digest, A/B/H/L multi-
// exponentiations). Native and wasm results must be identical; this is how
// cross-platform arithmetic bugs are localised.
json debug_prover_parts(const ProvingKey& pk, const ProveRequest& req);
// Diagnostic: for each scalar k (Fr hex), k*G1, k*G2, k^-1 and k*k.
json debug_arith(const json& scalars);

// {"proof": {...}, "public": {...}, "proof_hash": "<hex>", "timings": {...}}
json prove_result_to_json(const ProveResult& r);

} // namespace zk
