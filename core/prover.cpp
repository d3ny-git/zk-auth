#include "prover.hpp"

#include <chrono>

namespace zk {

namespace {
double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}
} // namespace

ProveRequest prove_request_from_json(const json& cred, const json& path, const json& server) {
    ProveRequest r;
    r.cred = credential_from_json(cred);
    r.path = path_from_json(path, &r.issuer_root);
    r.site_id = digest_from_hex(expect_string(server, "site_id"));
    r.age_cutoff = read_u32_be(from_hex(expect_string(server, "age_cutoff"), 4));
    r.nonce = nonce_from_hex(expect_string(server, "nonce"));
    return r;
}

ProveResult prove_login(const ProvingKey& pk, const ProveRequest& req) {
    // Cheap native pre-checks give the user a clear reason instead of an
    // unsatisfied circuit (and save the seconds a doomed proof would take).
    if (root_from_path(commitment_of(req.cred), req.path) != req.issuer_root)
        throw ProveError("credential is not in the issuer's tree (credential and path do not match the root)");
    if (req.cred.dob > req.age_cutoff)
        throw ProveError("the credential's date of birth is after the age cutoff (under 18)");

    ProveResult out;
    auto t0 = std::chrono::steady_clock::now();
    ZkAuthCircuit circuit;
    out.pub = circuit.generate_witness(req.cred, req.path, req.site_id, req.age_cutoff, req.nonce);
    if (!circuit.pb().is_satisfied()) throw ProveError("internal error: witness does not satisfy the circuit");
    out.witness_ms = ms_since(t0);

    t0 = std::chrono::steady_clock::now();
    out.proof = libsnark::r1cs_gg_ppzksnark_prover<ppT>(pk, circuit.pb().primary_input(),
                                                         circuit.pb().auxiliary_input());
    out.prove_ms = ms_since(t0);
    return out;
}

json prove_result_to_json(const ProveResult& r) {
    return {{"proof", proof_to_json(r.proof)},
            {"public", public_to_json(r.pub)},
            {"timings", {{"witness_ms", r.witness_ms}, {"prove_ms", r.prove_ms}}}};
}

} // namespace zk
