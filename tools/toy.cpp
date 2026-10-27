// zkauth-toy: the M1 risk spike. Proves end to end that a Groth16 proof made by
// libsnark (natively or in the browser) verifies with the native verifier.
//
//   zkauth-toy setup  DIR           writes DIR/toy_pk.bin and DIR/toy_vk.bin
//   zkauth-toy prove  DIR X         prints {"proof":..., "public":[...]} (native prover)
//   zkauth-toy verify DIR FILE      exit status 0 iff the proof in FILE verifies
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>

#include "core/formats.hpp"
#include "core/toy_circuit.hpp"

using namespace zk;

namespace {

int usage() {
    std::fprintf(stderr, "usage: zkauth-toy setup DIR | prove DIR X | verify DIR FILE\n");
    return 2;
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) return usage();
    init_snark();
    const std::string cmd = argv[1], dir = argv[2];
    try {
        if (cmd == "setup" && argc == 3) {
            ToyCircuit c;
            Keypair kp = libsnark::r1cs_gg_ppzksnark_generator<ppT>(c.pb.get_constraint_system());
            const std::string pk = serialize(kp.pk), vk = serialize(kp.vk);
            write_file(dir + "/toy_pk.bin", pk);
            write_file(dir + "/toy_vk.bin", vk);
            std::printf("constraints=%zu pk=%zu bytes vk=%zu bytes\n",
                        c.pb.num_constraints(), pk.size(), vk.size());
            return 0;
        }
        if (cmd == "prove" && argc == 4) {
            auto pk = deserialize<ProvingKey>(read_file(dir + "/toy_pk.bin"));
            ToyCircuit c;
            c.generate_witness(std::stol(argv[3]));
            if (!c.pb.is_satisfied()) throw std::runtime_error("witness does not satisfy the circuit");
            auto t0 = std::chrono::steady_clock::now();
            Proof proof = libsnark::r1cs_gg_ppzksnark_prover<ppT>(pk, c.pb.primary_input(), c.pb.auxiliary_input());
            std::fprintf(stderr, "native prove: %.2f ms\n", ms_since(t0));
            json out = {{"proof", proof_to_json(proof)}, {"public", {fr_to_hex(c.pb.val(c.out))}}};
            std::cout << out.dump(2) << "\n";
            return 0;
        }
        if (cmd == "verify" && argc == 4) {
            auto vk = deserialize<VerificationKey>(read_file(dir + "/toy_vk.bin"));
            json in = json::parse(read_file(argv[3]));
            Proof proof = proof_from_json(in.at("proof"));
            PrimaryInput primary;
            for (const auto& v : in.at("public")) primary.push_back(fr_from_hex(v.get<std::string>()));
            auto t0 = std::chrono::steady_clock::now();
            bool ok = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(vk, primary, proof);
            std::printf("verify: %s (%.2f ms)\n", ok ? "VALID" : "INVALID", ms_since(t0));
            return ok ? 0 : 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return usage();
}
