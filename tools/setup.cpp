// zkauth-setup: the (single-party, demo-only) Groth16 trusted setup for
// ZkAuthCircuit.
//
//   zkauth-setup --out keys/
//
// Writes keys/pk.bin (proving key, downloaded once by the browser),
// keys/vk.bin (verification key, loaded by the server), keys/vk.json (the vk
// as hex points plus alpha_g1/beta_g2 from the proving key, for the snarkjs
// baseline) and keys/manifest.json (sizes, hashes, constraint counts).
#include <chrono>
#include <cstdio>
#include <filesystem>

#include <openssl/evp.h>

#include "core/circuit.hpp"
#include "core/formats.hpp"
#include "tools/cli.hpp"

using namespace zk;

namespace {

std::string sha256_hex(std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_Digest failed");
    return to_hex(std::span<const std::uint8_t>(md, len));
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto args = cli::Args::parse(argc, argv);
        const std::string out = args.get("out", "keys");
        std::filesystem::create_directories(out);
        init_snark();

        std::fprintf(stderr,
            "\n  WARNING: this is a SINGLE-PARTY trusted setup, for demonstration only.\n"
            "  Whoever runs it could keep the secret randomness (\"toxic waste\") and\n"
            "  forge proofs. Production systems use a multi-party ceremony.\n\n");

        ZkAuthCircuit circuit;
        std::printf("ZkAuthCircuit constraint breakdown:\n");
        for (const auto& [what, n] : circuit.constraint_breakdown())
            std::printf("  %8zu  %s\n", n, what.c_str());
        std::printf("  %8zu  TOTAL constraints (%zu variables, %zu public inputs)\n",
                    circuit.num_constraints(), circuit.num_variables(), circuit.pb().num_inputs());

        const auto t0 = std::chrono::steady_clock::now();
        Keypair kp = libsnark::r1cs_gg_ppzksnark_generator<ppT>(circuit.pb().get_constraint_system());
        const double setup_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();

        const std::string pk = serialize(kp.pk), vk = serialize(kp.vk);
        write_file(out + "/pk.bin", pk);
        write_file(out + "/vk.bin", vk);
        write_file(out + "/vk.json", vk_to_json(kp.vk, kp.pk.alpha_g1, kp.pk.beta_g2).dump(2) + "\n");

        // What the 148 MB proving key is made of (each part serialised alone).
        const json pk_parts = {
            {"A_query (G1)", {{"entries", kp.pk.A_query.size()}, {"bytes", serialize(kp.pk.A_query).size()}}},
            {"B_query (G2+G1, sparse)", {{"entries", kp.pk.B_query.values.size()}, {"bytes", serialize(kp.pk.B_query).size()}}},
            {"H_query (G1)", {{"entries", kp.pk.H_query.size()}, {"bytes", serialize(kp.pk.H_query).size()}}},
            {"L_query (G1)", {{"entries", kp.pk.L_query.size()}, {"bytes", serialize(kp.pk.L_query).size()}}},
            {"constraint_system (R1CS)", {{"entries", kp.pk.constraint_system.num_constraints()},
                                          {"bytes", serialize(kp.pk.constraint_system).size()}}},
        };
        std::printf("proving key parts:\n");
        for (const auto& [name, part] : pk_parts.items())
            std::printf("  %-28s %8zu entries %11zu bytes\n", name.c_str(), part["entries"].get<std::size_t>(),
                        part["bytes"].get<std::size_t>());

        json breakdown = json::array();
        for (const auto& [what, n] : circuit.constraint_breakdown()) breakdown.push_back({{"component", what}, {"constraints", n}});
        json manifest = {
            {"circuit", "ZkAuthCircuit"},
            {"tree_depth", kTreeDepth},
            {"constraints", circuit.num_constraints()},
            {"variables", circuit.num_variables()},
            {"public_inputs", circuit.pb().num_inputs()},
            {"breakdown", breakdown},
            {"pk_bytes", pk.size()},
            {"pk_parts", pk_parts},
            {"pk_sha256", sha256_hex(pk)},
            {"vk_bytes", vk.size()},
            {"vk_sha256", sha256_hex(vk)},
            {"setup_ms", setup_ms},
            {"trusted_setup", "single-party, demo only"},
        };
        write_file(out + "/manifest.json", manifest.dump(2) + "\n");

        std::printf("setup: %.1f s\n", setup_ms / 1000);
        std::printf("wrote %s/pk.bin (%zu bytes), vk.bin (%zu bytes), vk.json, manifest.json\n",
                    out.c_str(), pk.size(), vk.size());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zkauth-setup: %s\n", e.what());
        return 1;
    }
}
