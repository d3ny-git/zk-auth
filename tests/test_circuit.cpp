// Constraint-level tests of ZkAuthCircuit: a valid witness satisfies every
// constraint, and each kind of lie about the public inputs breaks at least one.
#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <iostream>

#include <openssl/sha.h>

#include "core/formats.hpp"
#include "fixtures.hpp"
#include "sha256_reference.hpp"

using namespace zk;
using namespace zk::test;

TEST_CASE("H is the SHA-256 compression function, not padded SHA-256", "[circuit][hash]") {
    Digest a, b;
    for (int i = 0; i < 32; ++i) { a[i] = std::uint8_t(i); b[i] = std::uint8_t(0xff - i); }
    std::array<std::uint8_t, 64> block;
    std::copy(a.begin(), a.end(), block.begin());
    std::copy(b.begin(), b.end(), block.begin() + 32);

    CHECK(hash2(a, b) == sha256_compress(block));

    unsigned char padded[32];
    SHA256(block.data(), block.size(), padded); // standard SHA-256 adds a padding block
    CHECK(std::memcmp(padded, hash2(a, b).data(), 32) != 0);

    Digest zero{};
    std::cout << "H(0^256, 0^256) = " << to_hex(hash2(zero, zero)) << "\n";
    CHECK(hash2(zero, zero) == sha256_compress({}));
}

TEST_CASE("native Merkle tree paths recompute the root", "[circuit][merkle]") {
    TreeFixture f;
    for (std::size_t i : {0u, 1u, 4u, 200u, 255u})
        CHECK(root_from_path(f.tree.leaf(i), f.tree.path(i)) == f.tree.root());
    MerklePath p = f.tree.path(1);
    p.siblings[3][0] ^= 1;
    CHECK(root_from_path(f.tree.leaf(1), p) != f.tree.root());
}

TEST_CASE("a valid credential satisfies the circuit", "[circuit]") {
    TreeFixture f;
    ZkAuthCircuit c;
    std::cout << "ZkAuthCircuit: " << c.num_constraints() << " constraints, "
              << c.num_variables() << " variables, " << c.pb().num_inputs() << " public inputs\n";
    CHECK(c.pb().num_inputs() == kNumPublicInputs);

    PublicInputs pub = c.generate_witness(f.creds[0], f.tree.path(0), f.site_id, f.age_cutoff, f.nonce);
    CHECK(c.pb().is_satisfied());
    CHECK(pub.merkle_root == f.tree.root());
    CHECK(pub.nullifier == nullifier_of(f.creds[0].secret, f.site_id));
    CHECK(c.pb().primary_input() == pack_public_inputs(pub));
}

TEST_CASE("the age check is dob <= cutoff, inclusive", "[circuit][age]") {
    TreeFixture f;
    SECTION("turns 18 today: accepted") {
        ZkAuthCircuit c;
        REQUIRE(f.creds[2].dob == f.age_cutoff);
        c.generate_witness(f.creds[2], f.tree.path(2), f.site_id, f.age_cutoff, f.nonce);
        CHECK(c.pb().is_satisfied());
    }
    SECTION("turns 18 tomorrow: rejected") {
        ZkAuthCircuit c;
        REQUIRE(f.creds[3].dob == f.age_cutoff + 1);
        c.generate_witness(f.creds[3], f.tree.path(3), f.site_id, f.age_cutoff, f.nonce);
        CHECK_FALSE(c.pb().is_satisfied());
    }
    SECTION("born on the epoch: accepted") {
        ZkAuthCircuit c;
        c.generate_witness(f.creds[4], f.tree.path(4), f.site_id, f.age_cutoff, f.nonce);
        CHECK(c.pb().is_satisfied());
    }
}

TEST_CASE("lying about a public input breaks the constraints", "[circuit][tamper]") {
    TreeFixture f;
    ZkAuthCircuit c;
    const PublicInputs honest = c.generate_witness(f.creds[0], f.tree.path(0), f.site_id, f.age_cutoff, f.nonce);
    REQUIRE(c.pb().is_satisfied());
    PublicInputs lie = honest;

    SECTION("wrong Merkle root") { lie.merkle_root[31] ^= 1; }
    SECTION("wrong nullifier (e.g. to dodge the one-account rule)") { lie.nullifier[0] ^= 0x80; }
    SECTION("wrong site id (reuse a nullifier from another site)") { lie.site_id[5] ^= 4; }
    SECTION("cutoff earlier than the holder's dob") { lie.age_cutoff = f.creds[0].dob - 1; }
    c.overwrite_public_inputs(lie);
    CHECK_FALSE(c.pb().is_satisfied());
}

TEST_CASE("a later cutoff is satisfiable, so the server must pin age_cutoff", "[circuit][age]") {
    // A 17-year-old can always prove "dob <= some later date". The circuit
    // cannot know today's date; the server's check 4 (public.age_cutoff must
    // equal its own value) is what turns this into "at least 18 today".
    TreeFixture f;
    ZkAuthCircuit c;
    const std::uint32_t too_late = f.creds[3].dob; // what an under-18 holder would claim
    c.generate_witness(f.creds[3], f.tree.path(3), f.site_id, too_late, f.nonce);
    CHECK(c.pb().is_satisfied());
    CHECK(too_late != f.age_cutoff);
}

TEST_CASE("a credential that is not in the tree yields a different root", "[circuit][tamper]") {
    TreeFixture f;
    Credential outsider{};
    outsider.secret.fill(0x99);
    outsider.dob = f.creds[0].dob;
    ZkAuthCircuit c;
    // Using leaf 0's path with a credential the issuer never issued: the
    // circuit computes some root, but not the issuer's...
    PublicInputs pub = c.generate_witness(outsider, f.tree.path(0), f.site_id, f.age_cutoff, f.nonce);
    CHECK(pub.merkle_root != f.tree.root());
    // ...and claiming the issuer's root anyway violates the constraints.
    pub.merkle_root = f.tree.root();
    c.overwrite_public_inputs(pub);
    CHECK_FALSE(c.pb().is_satisfied());
}

TEST_CASE("changing the nonce alone keeps the circuit satisfiable", "[circuit][nonce]") {
    // The nonce has no constraint of its own; it is bound by Groth16 itself
    // (see test_proof.cpp, "wrong nonce"). This test documents that.
    TreeFixture f;
    ZkAuthCircuit c;
    PublicInputs pub = c.generate_witness(f.creds[0], f.tree.path(0), f.site_id, f.age_cutoff, f.nonce);
    pub.nonce[0] ^= 1;
    c.overwrite_public_inputs(pub);
    CHECK(c.pb().is_satisfied());
}

TEST_CASE("worked example used in docs/formats.md and how-it-works.md", "[circuit][example]") {
    // Fixture credential 0: secret = 0x11 repeated, dob = 2001-05-14.
    TreeFixture f;
    const Credential& c = f.creds[0];
    const Digest commitment = commitment_of(c);
    const Digest nul = nullifier_of(c.secret, f.site_id);
    const MerklePath p = f.tree.path(0);
    std::cout << "secret        " << to_hex(c.secret) << "\n"
              << "dob           2001-05-14 = " << c.dob << " days\n"
              << "pad256(dob)   " << to_hex(pad256_u32(c.dob)) << "\n"
              << "commitment    " << to_hex(commitment) << "\n"
              << "site_id       " << to_hex(f.site_id) << "\n"
              << "nullifier     " << to_hex(nul) << "\n"
              << "leaf 1        " << to_hex(f.tree.leaf(1)) << "\n"
              << "sibling[0]    " << to_hex(p.siblings[0]) << "\n"
              << "sibling[1]    " << to_hex(p.siblings[1]) << "\n"
              << "sibling[2]    " << to_hex(p.siblings[2]) << "\n"
              << "root          " << to_hex(f.tree.root()) << "\n";
    PublicInputs pub{f.tree.root(), nul, f.site_id, f.age_cutoff, f.nonce};
    std::cout << public_to_json(pub).dump(2) << "\n";
    CHECK(p.siblings[0] == f.tree.leaf(1));
    CHECK(p.siblings[1] == hash2(f.tree.leaf(2), f.tree.leaf(3)));
}
