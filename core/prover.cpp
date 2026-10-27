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

json debug_prover_parts(const ProvingKey& pk, const ProveRequest& req) {
    using namespace libsnark;
    ZkAuthCircuit circuit;
    circuit.generate_witness(req.cred, req.path, req.site_id, req.age_cutoff, req.nonce);
    const auto primary = circuit.pb().primary_input();
    const auto aux = circuit.pb().auxiliary_input();
    const auto qap_wit = r1cs_to_qap_witness_map(pk.constraint_system, primary, aux, Fr::zero(), Fr::zero(), Fr::zero());
    std::string h_bytes;
    for (const Fr& c : qap_wit.coefficients_for_H) h_bytes += fr_to_hex(c);
    libff::Fr_vector<ppT> assignment(1, Fr::one());
    assignment.insert(assignment.end(), qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.end());
    const std::size_t nv = qap_wit.num_variables();
    const G1 At = libff::multi_exp_with_mixed_addition<G1, Fr, libff::multi_exp_method_BDLO12>(
        pk.A_query.begin(), pk.A_query.begin() + nv + 1, assignment.begin(), assignment.begin() + nv + 1, 1);
    const auto Bt = kc_multi_exp_with_mixed_addition<G2, G1, Fr, libff::multi_exp_method_BDLO12>(
        pk.B_query, 0, nv + 1, assignment.begin(), assignment.begin() + nv + 1, 1);
    const G1 Ht = libff::multi_exp<G1, Fr, libff::multi_exp_method_BDLO12>(
        pk.H_query.begin(), pk.H_query.begin() + (qap_wit.degree() - 1), qap_wit.coefficients_for_H.begin(),
        qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1), 1);
    const G1 Lt = libff::multi_exp_with_mixed_addition<G1, Fr, libff::multi_exp_method_BDLO12>(
        pk.L_query.begin(), pk.L_query.end(), assignment.begin() + qap_wit.num_inputs() + 1, assignment.begin() + nv + 1, 1);
    return {{"degree", qap_wit.degree()},
            {"H_coeffs", qap_wit.coefficients_for_H.size()},
            {"H_sha256", to_hex(sha256(h_bytes))},
            {"H_first", fr_to_hex(qap_wit.coefficients_for_H[0])},
            {"At", g1_to_json(At)},
            {"Bt_g", g2_to_json(Bt.g)},
            {"Bt_h", g1_to_json(Bt.h)},
            {"Ht", g1_to_json(Ht)},
            {"Lt", g1_to_json(Lt)}};
}

json debug_arith(const json& scalars) {
    json out = json::array();
    for (const auto& h : scalars) {
        const Fr k = fr_from_hex(h.get<std::string>());
        out.push_back({{"k", h},
                       {"kG1", g1_to_json(k * G1::one())},
                       {"kG2", g2_to_json(k * G2::one())},
                       {"inv", fr_to_hex(k.inverse())},
                       {"sq", fr_to_hex(k * k)}});
    }
    return out;
}

json prove_result_to_json(const ProveResult& r) {
    return {{"proof", proof_to_json(r.proof)},
            {"public", public_to_json(r.pub)},
            {"proof_hash", proof_hash_hex(r.proof, r.pub)},
            {"timings", {{"witness_ms", r.witness_ms}, {"prove_ms", r.prove_ms}}}};
}

} // namespace zk
