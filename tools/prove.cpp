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

#include "core/prover.hpp"
#include "tools/cli.hpp"

using namespace zk;

int main(int argc, char** argv) {
    try {
        init_snark();
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
