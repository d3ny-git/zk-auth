// Ethereum signature verification (server/eth_sig.*) against known vectors,
// MetaMask's signing library, and 10,000 signatures from bitcoin-core's
// libsecp256k1 used as an independent oracle.
#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <iostream>
#include <random>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "core/encoding.hpp"
#include "server/eth_sig.hpp"

using namespace zk;
using namespace zk::eth;

namespace {

// secp256k1 group order n.
const char* kOrder = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

Signature with_s(const Signature& sig, const Bytes& s) {
    Signature out = sig;
    std::copy(s.begin(), s.end(), out.begin() + 32);
    return out;
}

// n - s as 32 big-endian bytes.
Bytes negate_mod_n(std::span<const std::uint8_t> s) {
    Bytes n = from_hex(kOrder, 32), out(32);
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int d = int(n[i]) - int(s[i]) - borrow;
        borrow = d < 0;
        out[i] = std::uint8_t(d + (borrow ? 256 : 0));
    }
    return out;
}

Address address_of(const secp256k1_context* ctx, const secp256k1_pubkey& pk, Verifier& v) {
    std::uint8_t pub[65];
    size_t len = sizeof pub;
    secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
    const Hash32 h = v.keccak256(std::span<const std::uint8_t>(pub + 1, 64));
    Address a;
    std::copy(h.begin() + 12, h.end(), a.begin());
    return a;
}

} // namespace

TEST_CASE("Keccak-256 known vectors (and it is not SHA3-256)", "[eth][keccak]") {
    Verifier v;
    CHECK(to_hex(v.keccak256(std::string_view(""))) ==
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    CHECK(to_hex(v.keccak256(std::string_view("abc"))) ==
          "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    // SHA3-256("") differs only in the padding byte, and yields a different hash.
    unsigned char sha3[32];
    unsigned int len = 0;
    EVP_Digest("", 0, sha3, &len, EVP_sha3_256(), nullptr);
    CHECK(to_hex(std::span<const std::uint8_t>(sha3, 32)) != to_hex(v.keccak256(std::string_view(""))));
}

TEST_CASE("EIP-55 checksum addresses (examples from the EIP)", "[eth][eip55]") {
    for (const char* a : {"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                          "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"}) {
        auto parsed = parse_address(a);
        REQUIRE(parsed);
        CHECK(to_checksum_address(*parsed) == a);
        std::string lower(a);
        for (auto& c : lower) c = char(std::tolower(c));
        CHECK(parse_address(lower) == parsed); // all-lowercase: no checksum claim
    }
    CHECK_FALSE(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")); // one case flipped
    CHECK_FALSE(parse_address("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
    CHECK_FALSE(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA"));
}

TEST_CASE("MetaMask personal_sign vectors recover their signer", "[eth][metamask]") {
    std::ifstream in(std::string(ZK_TEST_VECTORS_DIR) + "/metamask_personal_sign.json");
    REQUIRE(in);
    const auto vectors = nlohmann::json::parse(in);
    REQUIRE(vectors.size() >= 3);
    Verifier v;
    for (const auto& t : vectors) {
        INFO(t.at("message").get<std::string>());
        auto sig = parse_signature(t.at("signature").get<std::string>());
        auto want = parse_address(t.at("address").get<std::string>());
        REQUIRE(sig);
        REQUIRE(want);
        CHECK(v.recover_personal(t.at("message").get<std::string>(), *sig) == want);
        CHECK(v.recover_personal(t.at("message").get<std::string>() + " ", *sig) != want);
    }
}

TEST_CASE("10,000 libsecp256k1 signatures recover identically", "[eth][oracle]") {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    std::mt19937_64 rng(4361);
    Verifier v;
    int mismatches = 0;
    for (int i = 0; i < 10000; ++i) {
        std::uint8_t key[32];
        do {
            for (auto& b : key) b = std::uint8_t(rng());
        } while (!secp256k1_ec_seckey_verify(ctx, key));
        std::string message(rng() % 300, '\0');
        for (auto& c : message) c = char(rng());

        const Hash32 digest = v.eip191_digest(message);
        secp256k1_ecdsa_recoverable_signature rsig;
        REQUIRE(secp256k1_ecdsa_sign_recoverable(ctx, &rsig, digest.data(), key, nullptr, nullptr));
        Signature sig;
        int recid = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig.data(), &recid, &rsig);
        sig[64] = std::uint8_t(27 + recid);

        secp256k1_pubkey pk;
        REQUIRE(secp256k1_ec_pubkey_create(ctx, &pk, key));
        const Address want = address_of(ctx, pk, v);

        if (v.recover(digest, sig) != want) ++mismatches;
        Signature raw_v = sig;
        raw_v[64] = std::uint8_t(recid); // 0/1 form, as some libraries emit
        if (v.recover(digest, raw_v) != want) ++mismatches;
        if (i < 50) CHECK(recover_personal_fresh(message, sig) == want); // the per-request path agrees
    }
    CHECK(mismatches == 0);
    secp256k1_context_destroy(ctx);
}

TEST_CASE("malformed and malleable signatures are rejected", "[eth][reject]") {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    Verifier v;
    std::uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = std::uint8_t(i + 1);
    const Hash32 digest = v.eip191_digest("zk-auth");
    secp256k1_ecdsa_recoverable_signature rsig;
    REQUIRE(secp256k1_ecdsa_sign_recoverable(ctx, &rsig, digest.data(), key, nullptr, nullptr));
    Signature sig;
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig.data(), &recid, &rsig);
    sig[64] = std::uint8_t(27 + recid);
    REQUIRE(v.recover(digest, sig));

    SECTION("high-s twin (n - s, flipped parity): valid ECDSA, but not canonical") {
        Signature hs = with_s(sig, negate_mod_n(std::span(sig).subspan(32, 32)));
        hs[64] = std::uint8_t(27 + (recid ^ 1));
        CHECK_FALSE(v.recover(digest, hs));
    }
    SECTION("v outside {0, 1, 27, 28}") {
        for (int bad_v : {2, 26, 29, 35, 255}) {
            Signature s2 = sig;
            s2[64] = std::uint8_t(bad_v);
            CHECK_FALSE(v.recover(digest, s2));
        }
    }
    SECTION("r = 0, s = 0, r = n") {
        Signature z = sig;
        std::fill(z.begin(), z.begin() + 32, 0);
        CHECK_FALSE(v.recover(digest, z));
        CHECK_FALSE(v.recover(digest, with_s(sig, Bytes(32, 0))));
        Signature rn = sig;
        Bytes n = from_hex(kOrder, 32);
        std::copy(n.begin(), n.end(), rn.begin());
        CHECK_FALSE(v.recover(digest, rn));
    }
    SECTION("r that is not an x-coordinate on the curve") {
        Signature off = sig;
        int rejected = 0;
        for (int t = 1; t <= 40; ++t) { // about half of all x values have no point
            off[31] = std::uint8_t(t);
            off[0] = 0x01;
            rejected += !v.recover(digest, off);
        }
        CHECK(rejected > 0);
    }
    SECTION("a different message recovers a different (useless) address") {
        CHECK(v.recover(v.eip191_digest("zk-auth!"), sig) != v.recover(digest, sig));
    }
    CHECK_FALSE(parse_signature("0x1234"));
    CHECK_FALSE(parse_signature(std::string(132, 'z')));
    secp256k1_context_destroy(ctx);
}

TEST_CASE("worked example for how-it-works.md section 7", "[eth][example]") {
    // eth-sig-util's documented vector: key 4af1…8bb0 signs "Hello, world!".
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    const Bytes key = from_hex("4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0", 32);
    Verifier v;
    const std::string msg = "Hello, world!";
    const auto sig = parse_signature("0x90a938f7457df6e8f741264c32697fc52f9a8f867c52dd70713d9d2d472f2e41"
                                     "5d9c94148991bbe1f4a1818d1dff09165782749c877f5cf1eff4ef126e55714d1c");
    REQUIRE(sig);
    secp256k1_pubkey pk;
    REQUIRE(secp256k1_ec_pubkey_create(ctx, &pk, key.data()));
    std::uint8_t pub[65];
    size_t len = sizeof pub;
    secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
    std::cout << "prefixed  \"\\x19Ethereum Signed Message:\\n13Hello, world!\"\n"
              << "digest    " << to_hex(v.eip191_digest(msg)) << "\n"
              << "r         " << to_hex(std::span(*sig).subspan(0, 32)) << "\n"
              << "s         " << to_hex(std::span(*sig).subspan(32, 32)) << "\n"
              << "v         " << int((*sig)[64]) << "\n"
              << "Q (X||Y)  " << to_hex(std::span<const std::uint8_t>(pub + 1, 64)) << "\n"
              << "keccak(Q) " << to_hex(v.keccak256(std::span<const std::uint8_t>(pub + 1, 64))) << "\n"
              << "address   " << to_checksum_address(*v.recover_personal(msg, *sig)) << "\n";
    CHECK(to_checksum_address(*v.recover_personal(msg, *sig)) == "0x29C76e6aD8f28BB1004902578Fb108c507Be341b");
    secp256k1_context_destroy(ctx);
}
