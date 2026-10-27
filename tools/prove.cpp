// zkauth-prove: the native twin of the browser prover (same core/prover.cpp).
// Used to make fixtures and to check proofs without a browser.
//
//   zkauth-prove --pk keys/pk.bin --cred cred.json --path path.json
//                --server nonce.json --out proof.json
//   zkauth-prove verify --vk keys/vk.bin --in proof.json
//
// nonce.json is a GET /nonce response: {"nonce", "age_cutoff", "site_id", ...}.
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include <libff/common/profiling.hpp>

#include "core/prover.hpp"
#include "tools/cli.hpp"

using namespace zk;

int main(int argc, char** argv) {
    try {
        init_snark();
        if (std::getenv("ZK_PROFILE")) { // libff's per-phase timing table, on stderr-free stdout
            libff::inhibit_profiling_info = false;
            libff::inhibit_profiling_counters = false;
        }
        const auto a = cli::Args::parse(argc, argv);
        if (!a.positional.empty() && a.positional[0] == "verify") {
            const auto vk = deserialize<VerificationKey>(read_file(a.require("vk")));
            const json in = json::parse(read_file(a.require("in")));
            const Proof proof = proof_from_json(in.at("proof"));
            const PublicInputs pub = public_from_json(in.at("public"));
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, pack_public_inputs(pub), proof);
            std::printf("%s (%.2f ms incl. vk processing)\n", ok ? "VALID" : "INVALID",
                        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());
            return ok ? 0 : 1;
        }
        if (!a.positional.empty() && a.positional[0] == "debug-accumulate") {
            const auto vk = deserialize<VerificationKey>(read_file(a.require("vk")));
            const json in = json::parse(read_file(a.require("in")));
            const PrimaryInput x = pack_public_inputs(public_from_json(in.at("public")));
            G1 naive = vk.gamma_ABC_g1.first;
            for (std::size_t i = 0; i < x.size(); ++i) naive = naive + x[i] * vk.gamma_ABC_g1.rest.values[i];
            const auto acc = vk.gamma_ABC_g1.accumulate_chunk<Fr>(x.begin(), x.end(), 0);
            std::printf("naive == accumulate_chunk: %s\n", naive == acc.first ? "yes" : "NO");
            const Proof pr = proof_from_json(in.at("proof"));
            const auto lhs = ppT::reduced_pairing(pr.g_A, pr.g_B);
            const auto rhs = vk.alpha_g1_beta_g2 * ppT::reduced_pairing(naive, vk.gamma_g2) *
                             ppT::reduced_pairing(pr.g_C, vk.delta_g2);
            std::printf("pairing check with naive accumulation: %s\n", lhs == rhs ? "VALID" : "INVALID");
            return 0;
        }
        if (!a.positional.empty() && a.positional[0] == "debug-arith") {
            std::printf("%s\n", debug_arith(json::parse(read_file(a.require("in")))).dump().c_str());
            return 0;
        }
        if (!a.positional.empty() && a.positional[0] == "debug-parts") {
            const auto pk = deserialize<ProvingKey>(read_file(a.require("pk")));
            const ProveRequest req = prove_request_from_json(json::parse(read_file(a.require("cred"))),
                                                             json::parse(read_file(a.require("path"))),
                                                             json::parse(read_file(a.require("server"))));
            std::printf("%s\n", debug_prover_parts(pk, req).dump().c_str());
            return 0;
        }
        const auto t0 = std::chrono::steady_clock::now();
        const auto pk = deserialize<ProvingKey>(read_file(a.require("pk")));
        const double load_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        const ProveRequest req = prove_request_from_json(json::parse(read_file(a.require("cred"))),
                                                         json::parse(read_file(a.require("path"))),
                                                         json::parse(read_file(a.require("server"))));
        const ProveResult r = prove_login(pk, req);
        json out = prove_result_to_json(r);
        out["timings"]["pk_load_ms"] = load_ms;
        write_file(a.require("out"), out.dump(2) + "\n");
        std::printf("proof written to %s (pk load %.0f ms, witness %.0f ms, prove %.0f ms)\n",
                    a.require("out").c_str(), load_ms, r.witness_ms, r.prove_ms);
        return 0;
    } catch (const ProveError& e) {
        std::fprintf(stderr, "cannot prove: %s\n", e.what());
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zkauth-prove: %s\n", e.what());
        return 1;
    }
}
