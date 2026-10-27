// Proof-level tests: a real Groth16 setup + proof for ZkAuthCircuit, then
// verification against tampered public inputs and a tampered proof. Slow (one
// trusted setup per test process), so everything shares one cached keypair.
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <iostream>

#include "core/formats.hpp"
#include "fixtures.hpp"
#include "keys_cache.hpp"

using namespace zk;
using namespace zk::test;

namespace {

struct Shared {
    TreeFixture f;
    const Keypair& kp;
    ProcessedVerificationKey pvk;
    Proof proof;
    PublicInputs pub;

    Shared() : kp(cached_keypair()), pvk(libsnark::r1cs_gg_ppzksnark_verifier_process_vk<ppT>(kp.vk)) {
        ZkAuthCircuit c;
        pub = c.generate_witness(f.creds[0], f.tree.path(0), f.site_id, f.age_cutoff, f.nonce);
        REQUIRE(c.pb().is_satisfied());
        auto t0 = std::chrono::steady_clock::now();
        proof = libsnark::r1cs_gg_ppzksnark_prover<ppT>(kp.pk, c.pb().primary_input(), c.pb().auxiliary_input());
        std::cout << "prove: " << ms(t0) << " ms\n";
    }

    static double ms(std::chrono::steady_clock::time_point t0) {
        return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    }


    bool verify(const PublicInputs& p, const Proof& pr) const {
        return libsnark::r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, pack_public_inputs(p), pr);
    }
};

Shared& shared() {
    static Shared s;
    return s;
}

} // namespace

TEST_CASE("Groth16 binds every public input and the proof itself", "[proof][slow]") {
    Shared& s = shared();
    REQUIRE(s.verify(s.pub, s.proof));

    PublicInputs lie = s.pub;
    SECTION("wrong nonce (replaying a proof made for another login)") { lie.nonce[15] ^= 1; }
    SECTION("wrong site id") { lie.site_id[0] ^= 1; }
    SECTION("wrong Merkle root") { lie.merkle_root[0] ^= 1; }
    SECTION("wrong nullifier") { lie.nullifier[31] ^= 1; }
    SECTION("wrong age cutoff") { lie.age_cutoff += 1; }
    CHECK_FALSE(s.verify(lie, s.proof));
}

TEST_CASE("a tampered proof fails to parse or to verify", "[proof][slow]") {
    Shared& s = shared();
    json j = proof_to_json(s.proof);
    SECTION("swap A and C") {
        std::swap(j["a"], j["c"]);
        CHECK_FALSE(s.verify(s.pub, proof_from_json(j)));
    }
    SECTION("flip one bit of A.x: the point leaves the curve") {
        std::string x = j["a"]["x"];
        x[63] = x[63] == '0' ? '1' : '0';
        j["a"]["x"] = x;
        CHECK_THROWS_AS(proof_from_json(j), FormatError);
    }
    SECTION("negate C: still on the curve, but wrong") {
        j["c"] = g1_to_json(-s.proof.g_C);
        CHECK_FALSE(s.verify(s.pub, proof_from_json(j)));
    }
    SECTION("JSON round trip of the honest proof still verifies") {
        CHECK(s.verify(s.pub, proof_from_json(json::parse(j.dump()))));
    }
}
