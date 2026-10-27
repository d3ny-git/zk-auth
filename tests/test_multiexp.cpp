// Regression test for patch libff-0002 (docs/build-notes.md).
//
// libsnark's Groth16 verifier accumulates sum(public_i * IC_i) with libff's
// Bos-Coster multi-exponentiation. On x86-64 its heap comparison is inline
// asm; upstream that asm was neither `volatile` nor declared to read memory,
// so GCC at -O3 could reuse a stale comparison result inside the heap loop.
// The accumulation then came out wrong and valid proofs were rejected for
// about two thirds of random nonces.
#include <catch2/catch_test_macros.hpp>

#include <random>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>

#include "core/circuit.hpp"
#include "core/formats.hpp"

using namespace zk;

TEST_CASE("Bos-Coster accumulation equals the naive sum for our public-input shapes", "[multiexp][regression]") {
    std::mt19937_64 rng(20261027);
    std::vector<G1> bases(kNumPublicInputs);
    for (auto& b : bases) b = G1::random_element();

    int mismatches = 0;
    for (int trial = 0; trial < 500; ++trial) {
        // Exactly what pack_public_inputs produces for random requests.
        PublicInputs p;
        for (auto* d : {&p.merkle_root, &p.nullifier, &p.site_id})
            for (auto& byte : *d) byte = std::uint8_t(rng());
        for (auto& byte : p.nonce) byte = std::uint8_t(rng());
        p.age_cutoff = std::uint32_t(rng() % 30000);
        const PrimaryInput x = pack_public_inputs(p);

        G1 naive = G1::zero();
        for (std::size_t i = 0; i < x.size(); ++i) naive = naive + x[i] * bases[i];
        const G1 bos_coster = libff::multi_exp<G1, Fr, libff::multi_exp_method_bos_coster>(
            bases.begin(), bases.end(), x.begin(), x.end(), 1);
        if (!(naive == bos_coster)) ++mismatches;
    }
    CHECK(mismatches == 0);
}
