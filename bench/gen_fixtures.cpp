// zkauth-bench-fixtures: request bodies for the benchmarks.
//
//   zkauth-bench-fixtures --pk keys/pk.bin --out build/bench-fixtures
//                         [--proofs 1000] [--sigs 1000] [--threads 8] [--domain bench.local]
//
// Writes, under --out:
//   proofs.json  [{"body": {"proof","public"}, "valid": bool}]  1000 valid + 10% invalid
//   sigs.json    [{"body": {"message","signature","address"}, "valid": bool}]  likewise
//   issuer/      the issuer state (20 dummies + 200 credentials) and roots.json
// Valid proofs use 200 different credentials and a fresh random nonce each.
// Invalid entries are well-formed (they parse) but must fail verification,
// so both servers do the full amount of work on them.
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <random>
#include <thread>

#include <openssl/rand.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "core/merkle_tree.hpp"
#include "core/prover.hpp"
#include "server/eth_sig.hpp"
#include "server/routes.hpp"
#include "tools/cli.hpp"

using namespace zk;
namespace fs = std::filesystem;

namespace {

template <class T>
T random_bytes() {
    T v;
    if (RAND_bytes(v.data(), static_cast<int>(v.size())) != 1) throw std::runtime_error("RAND_bytes");
    return v;
}

std::string siwe_like(const std::string& domain, const std::string& address, const std::string& nonce) {
    return domain + " wants you to sign in with your Ethereum account:\n" + address +
           "\n\nLog in to Zk-Auth. zk-auth-proof:0x" + to_hex(random_bytes<Digest>()) +
           "\n\nURI: https://" + domain + "\nVersion: 1\nChain ID: 1\nNonce: " + nonce +
           "\nIssued At: 2026-10-27T12:00:00.000Z";
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto a = cli::Args::parse(argc, argv);
        const fs::path out = a.get("out", "build/bench-fixtures");
        const int n_proofs = std::stoi(a.get("proofs", "1000")), n_sigs = std::stoi(a.get("sigs", "1000"));
        const int threads = std::stoi(a.get("threads", "8"));
        const std::string domain = a.get("domain", "bench.local");
        fs::create_directories(out / "issuer");
        init_snark();

        // Issuer: 20 dummies + 200 real credentials.
        constexpr int kDummies = 20, kCreds = 200;
        MerkleTree tree;
        std::vector<Credential> creds;
        std::mt19937 rng(7);
        std::uniform_int_distribution<std::uint32_t> dob(0, days_from_iso_date("2007-12-31"));
        for (int i = 0; i < kDummies + kCreds; ++i) {
            Credential c{random_bytes<Digest>(), dob(rng)};
            tree.set_leaf(i, commitment_of(c));
            if (i >= kDummies) creds.push_back(c);
        }
        write_file((out / "issuer/roots.json").string(),
                   json{{"current", to_hex(tree.root())}, {"roots", {to_hex(tree.root())}}}.dump(2));

        const Digest site = server::site_id_for(domain);
        const std::uint32_t cutoff = age_cutoff_days(today_utc_days());
        std::fprintf(stderr, "loading proving key…\n");
        const auto pk = deserialize<ProvingKey>(read_file(a.require("pk")));

        // Proofs, on `threads` threads sharing the (read-only) proving key.
        std::vector<json> proofs(n_proofs);
        std::atomic<int> next{0}, done{0};
        const auto t0 = std::chrono::steady_clock::now();
        std::vector<std::thread> pool;
        for (int t = 0; t < threads; ++t)
            pool.emplace_back([&] {
                for (int i; (i = next++) < n_proofs;) {
                    const int c = i % kCreds;
                    ProveRequest req{creds[c], tree.path(kDummies + c), tree.root(), site, cutoff, random_bytes<Nonce>()};
                    const ProveResult r = prove_login(pk, req);
                    proofs[i] = {{"proof", proof_to_json(r.proof)}, {"public", public_to_json(r.pub)}};
                    if (++done % 50 == 0) std::fprintf(stderr, "  %d/%d proofs\n", done.load(), n_proofs);
                }
            });
        for (auto& t : pool) t.join();
        const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::fprintf(stderr, "%d proofs in %.0f s on %d threads\n", n_proofs, secs, threads);

        json proof_fixtures = json::array();
        for (auto& p : proofs) proof_fixtures.push_back({{"body", p}, {"valid", true}});
        for (int i = 0; i < n_proofs / 10; ++i) { // well-formed but invalid: three kinds of tamper
            json body = proofs[i];
            if (i % 3 == 0) { // proof moved to another nonce (public inputs re-packed consistently)
                PublicInputs pub = public_from_json(body["public"]);
                pub.nonce = random_bytes<Nonce>();
                body["public"] = public_to_json(pub);
            } else if (i % 3 == 1) { // C negated: still on the curve
                body["proof"]["c"] = g1_to_json(-g1_from_json(body["proof"]["c"]));
            } else { // A and C swapped
                std::swap(body["proof"]["a"], body["proof"]["c"]);
            }
            proof_fixtures.push_back({{"body", body}, {"valid", false}});
        }
        write_file((out / "proofs.json").string(), proof_fixtures.dump());

        // Signatures: libsecp256k1, EIP-191 over SIWE-sized messages.
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        eth::Verifier v;
        json sigs = json::array();
        std::vector<json> valid;
        for (int i = 0; i < n_sigs; ++i) {
            std::array<std::uint8_t, 32> key;
            do key = random_bytes<std::array<std::uint8_t, 32>>(); while (!secp256k1_ec_seckey_verify(ctx, key.data()));
            secp256k1_pubkey pub;
            if (!secp256k1_ec_pubkey_create(ctx, &pub, key.data())) throw std::runtime_error("pubkey");
            std::uint8_t raw[65];
            size_t len = sizeof raw;
            secp256k1_ec_pubkey_serialize(ctx, raw, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
            const auto h = v.keccak256(std::span<const std::uint8_t>(raw + 1, 64));
            eth::Address addr;
            std::copy(h.begin() + 12, h.end(), addr.begin());
            const std::string address = eth::to_checksum_address(addr);
            const std::string message = siwe_like(domain, address, to_hex(random_bytes<Nonce>()));
            const auto digest = v.eip191_digest(message);
            secp256k1_ecdsa_recoverable_signature rs;
            secp256k1_ecdsa_sign_recoverable(ctx, &rs, digest.data(), key.data(), nullptr, nullptr);
            std::array<std::uint8_t, 65> sig;
            int recid = 0;
            secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig.data(), &recid, &rs);
            sig[64] = std::uint8_t(27 + recid);
            valid.push_back({{"message", message}, {"signature", "0x" + to_hex(sig)}, {"address", address}});
            sigs.push_back({{"body", valid.back()}, {"valid", true}});
        }
        for (int i = 0; i < n_sigs / 10; ++i) { // valid signature, but claims another signer
            json body = valid[i];
            body["address"] = valid[i + 1]["address"];
            sigs.push_back({{"body", body}, {"valid", false}});
        }
        secp256k1_context_destroy(ctx);
        write_file((out / "sigs.json").string(), sigs.dump());
        std::printf("wrote %zu proof and %zu signature fixtures to %s\n", proof_fixtures.size(), sigs.size(),
                    out.string().c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zkauth-bench-fixtures: %s\n", e.what());
        return 1;
    }
}
