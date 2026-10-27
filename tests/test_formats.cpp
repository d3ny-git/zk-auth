// Round-trip tests for every wire format in docs/formats.md, plus the
// rejections that make the parsers fail closed.
#include <catch2/catch_test_macros.hpp>

#include "core/formats.hpp"
#include "core/toy_circuit.hpp"

using namespace zk;

namespace {
const char* kR = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"; // scalar field order
const char* kQ = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"; // base field order
} // namespace

TEST_CASE("field elements round-trip and must be reduced", "[formats]") {
    for (int i = 0; i < 20; ++i) {
        Fr x = Fr::random_element();
        CHECK(fr_from_hex(fr_to_hex(x)) == x);
        Fq y = Fq::random_element();
        CHECK(fq_from_hex(fq_to_hex(y)) == y);
    }
    CHECK(fr_to_hex(Fr(35)) == "0000000000000000000000000000000000000000000000000000000000000023");
    // The modulus itself (== 0 mod r) has a different, canonical encoding.
    CHECK_THROWS_AS(fr_from_hex(kR), FormatError);
    CHECK_THROWS_AS(fq_from_hex(kQ), FormatError);
}

TEST_CASE("G1 points round-trip; off-curve and infinity are rejected", "[formats]") {
    for (int i = 0; i < 10; ++i) {
        G1 p = G1::random_element();
        CHECK(g1_from_json(g1_to_json(p)) == p);
    }
    json j = g1_to_json(G1::one());
    j["y"] = fq_to_hex(Fq(5)); // same x, wrong y
    CHECK_THROWS_AS(g1_from_json(j), FormatError);

    json inf = g1_to_json(G1::zero());
    CHECK_THROWS_AS(g1_from_json(inf), FormatError);
    CHECK(g1_from_json(inf, /*allow_infinity=*/true).is_zero());
}

TEST_CASE("G2 points round-trip; off-curve and out-of-subgroup are rejected", "[formats]") {
    for (int i = 0; i < 5; ++i) {
        G2 p = G2::random_element();
        CHECK(g2_from_json(g2_to_json(p)) == p);
    }
    json bad = g2_to_json(G2::one());
    bad["y"][0] = fq_to_hex(Fq(7));
    CHECK_THROWS_AS(g2_from_json(bad), FormatError);

    // Find a point on the twist curve that is NOT in the order-r subgroup:
    // pick x until x^3 + b' is a square, then take its square root.
    Fq2 x = Fq2::one();
    Fq2 rhs;
    do {
        x = x + Fq2::one();
        rhs = x.squared() * x + libff::alt_bn128_twist_coeff_b;
    } while ((rhs ^ Fq2::euler) != Fq2::one());
    G2 outsider(x, rhs.sqrt(), Fq2::one());
    REQUIRE(outsider.is_well_formed());         // on the curve...
    REQUIRE_FALSE((G2::order() * outsider).is_zero()); // ...but not in the subgroup
    CHECK_THROWS_AS(g2_from_json(g2_to_json(outsider)), FormatError);
}

TEST_CASE("proof JSON round-trips and rejects unexpected shapes", "[formats]") {
    Proof p(G1::random_element(), G2::random_element(), G1::random_element());
    json j = proof_to_json(p);
    CHECK(proof_from_json(j) == p);
    CHECK(proof_from_json(json::parse(j.dump())) == p);

    json extra = j;
    extra["d"] = j["a"];
    CHECK_THROWS_AS(proof_from_json(extra), FormatError);
    json missing = j;
    missing.erase("c");
    CHECK_THROWS(proof_from_json(missing));
    json wrong_type = j;
    wrong_type["a"]["x"] = 5;
    CHECK_THROWS(proof_from_json(wrong_type));
}

TEST_CASE("keys round-trip through libsnark binary serialisation", "[formats]") {
    ToyCircuit c;
    Keypair kp = libsnark::r1cs_gg_ppzksnark_generator<ppT>(c.pb.get_constraint_system());
    const std::string pk = serialize(kp.pk), vk = serialize(kp.vk);
    CHECK(deserialize<ProvingKey>(pk) == kp.pk);
    CHECK(deserialize<VerificationKey>(vk) == kp.vk);
    CHECK_THROWS_AS(deserialize<VerificationKey>(std::string_view(vk).substr(0, vk.size() - 10)), FormatError);
    CHECK_THROWS_AS(deserialize<VerificationKey>(vk + "x"), FormatError);

    json vkj = vk_to_json(kp.vk, kp.pk.alpha_g1, kp.pk.beta_g2);
    CHECK(vkj["n_public"] == 1);
    CHECK(vkj["ic"].size() == 2);
    CHECK(g2_from_json(vkj["gamma_g2"]) == kp.vk.gamma_g2);
    // alpha and beta from the proving key reproduce the vk's precomputed pairing.
    CHECK(ppT::reduced_pairing(g1_from_json(vkj["alpha_g1"]), g2_from_json(vkj["beta_g2"])) ==
          kp.vk.alpha_g1_beta_g2);
}

TEST_CASE("credential, path and public-input JSON round-trip", "[formats]") {
    Credential c{digest_from_hex("11" + std::string(62, '2')), days_from_iso_date("2001-05-14")};
    json cj = credential_to_json(c);
    CHECK(cj["dob"] == "2001-05-14");
    Credential c2 = credential_from_json(cj);
    CHECK(c2.secret == c.secret);
    CHECK(c2.dob == c.dob);

    MerklePath p;
    p.index = 37;
    for (std::size_t k = 0; k < kTreeDepth; ++k) p.siblings[k].fill(std::uint8_t(k));
    Digest root;
    root.fill(0xee);
    Digest root2;
    MerklePath p2 = path_from_json(path_to_json(p, root), &root2);
    CHECK(p2.index == 37u);
    CHECK(p2.siblings == p.siblings);
    CHECK(root2 == root);
    json bad_index = path_to_json(p, root);
    bad_index["index"] = kNumLeaves;
    CHECK_THROWS_AS(path_from_json(bad_index), FormatError);

    PublicInputs pub;
    pub.merkle_root.fill(0xaa);
    pub.nullifier.fill(0xbb);
    pub.site_id.fill(0xcc);
    pub.age_cutoff = days_from_iso_date("2008-10-27");
    pub.nonce.fill(0xdd);
    json pj = public_to_json(pub);
    CHECK(pj["age_cutoff"] == "00003763"); // 14179 days
    CHECK(pj["packed"].size() == kNumPublicInputs);
    CHECK(public_from_json(pj) == pub);
    // age_cutoff and nonce are packed least-significant bit first, so the
    // field element is just the integer.
    CHECK(fr_from_hex(pj["packed"][6].get<std::string>()) == Fr(14179));

    json lying = pj;
    lying["nonce"] = std::string(32, 'e'); // named field changed, packed left alone
    CHECK_THROWS_AS(public_from_json(lying), FormatError);
}

TEST_CASE("canonical JSON sorts keys and has no whitespace", "[formats]") {
    json j;
    j["b"] = "2";
    j["a"] = json::array({"x", "y"});
    CHECK(canonical(j) == R"({"a":["x","y"],"b":"2"})");
}
