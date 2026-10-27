// /login integration tests: every failure path of the check chain, each
// asserted to be caught by the check that is supposed to catch it (read from
// the development-mode X-ZkAuth-Reject header), plus the success path,
// sessions, the one-credential-one-account rule, and the benchmark endpoints.
// The service is driven directly (no sockets) with an injectable clock.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <random>
#include <thread>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "core/prover.hpp"
#include "fixtures.hpp"
#include "keys_cache.hpp"
#include "server/routes.hpp"
#include "server/siwe.hpp"

using namespace zk;
using namespace zk::test;
namespace fs = std::filesystem;

namespace {

constexpr std::int64_t kNow = 1793102400000; // 2026-10-27T12:00:00Z
const std::string kDomain = "localhost:8080", kUri = "http://localhost:8080";

std::string rfc3339(std::int64_t ms) {
    const auto days = static_cast<std::uint32_t>(ms / 86'400'000);
    const std::int64_t r = ms % 86'400'000;
    char b[40];
    std::snprintf(b, sizeof b, "%sT%02d:%02d:%02d.%03dZ", iso_date_from_days(days).c_str(), int(r / 3'600'000),
                  int(r / 60'000 % 60), int(r / 1000 % 60), int(r % 1000));
    return b;
}

// A wallet backed by bitcoin-core's libsecp256k1 (independent of server/eth_sig).
struct TestWallet {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    std::array<std::uint8_t, 32> key{};
    std::string address;

    explicit TestWallet(std::uint8_t seed) {
        key.fill(seed);
        secp256k1_pubkey pk;
        REQUIRE(secp256k1_ec_pubkey_create(ctx, &pk, key.data()));
        std::uint8_t pub[65];
        size_t len = sizeof pub;
        secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
        eth::Verifier v;
        const auto h = v.keccak256(std::span<const std::uint8_t>(pub + 1, 64));
        eth::Address a;
        std::copy(h.begin() + 12, h.end(), a.begin());
        address = eth::to_checksum_address(a);
    }
    ~TestWallet() { secp256k1_context_destroy(ctx); }

    std::string sign(std::string_view message) const {
        eth::Verifier v;
        const auto digest = v.eip191_digest(message);
        secp256k1_ecdsa_recoverable_signature rs;
        REQUIRE(secp256k1_ecdsa_sign_recoverable(ctx, &rs, digest.data(), key.data(), nullptr, nullptr));
        std::array<std::uint8_t, 65> sig;
        int recid = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig.data(), &recid, &rs);
        sig[64] = std::uint8_t(27 + recid);
        return "0x" + to_hex(sig);
    }
};

struct Env {
    TreeFixture tree;
    fs::path dir;
    std::atomic<std::int64_t> now{kNow};
    std::unique_ptr<server::AuthService> svc;

    explicit Env(bool development = true) {
        dir = fs::temp_directory_path() / ("zk-login-test-" + std::to_string(std::random_device{}()));
        fs::create_directories(dir);
        write_file((dir / "vk.bin").string(), serialize(cached_keypair().vk));
        write_file((dir / "roots.json").string(), json{{"roots", {to_hex(tree.tree.root())}}}.dump());
        server::Config cfg;
        cfg.domain = kDomain;
        cfg.uri = kUri;
        cfg.vk_path = (dir / "vk.bin").string();
        cfg.roots_path = (dir / "roots.json").string();
        cfg.session_key_path = (dir / "session.pem").string();
        cfg.debug_reject_header = development;
        svc = std::make_unique<server::AuthService>(cfg, [this] { return now.load(); });
    }
    ~Env() { fs::remove_all(dir); }

    Nonce fresh_nonce() { return nonce_from_hex(json::parse(svc->nonce().body).at("nonce").get<std::string>()); }

    // A real proof for credential `idx`, bound to `n`, for this server's site.
    ProveResult prove(const Nonce& n, std::size_t idx = 0) {
        ProveRequest req{tree.creds[idx], tree.tree.path(idx), tree.tree.root(), svc->site_id(), tree.age_cutoff, n};
        return prove_login(cached_keypair().pk, req);
    }

    siwe::Message siwe_for(const std::string& address, const Proof& proof, const PublicInputs& pub) const {
        siwe::Message m;
        m.domain = kDomain;
        m.address_text = address;
        m.address = *eth::parse_address(address);
        m.statement = "Log in to Zk-Auth. zk-auth-proof:0x" + proof_hash_hex(proof, pub);
        m.uri = kUri;
        m.version = "1";
        m.chain_id = 1;
        m.nonce = to_hex(pub.nonce);
        m.issued_at = rfc3339(now.load());
        m.issued_at_ms = now.load();
        return m;
    }

    static std::string body(const Proof& proof, const PublicInputs& pub, const std::string& message,
                            const std::string& signature) {
        return json{{"proof", proof_to_json(proof)}, {"public", public_to_json(pub)},
                    {"siwe_message", message}, {"signature", signature}}.dump();
    }

    struct Outcome {
        int status;
        std::string check; // X-ZkAuth-Reject, empty if none
        json body;
    };
    Outcome login(const std::string& body) {
        const auto r = svc->login(body);
        std::string check;
        for (const auto& [k, v] : r.headers)
            if (k == "X-ZkAuth-Reject") check = v;
        return {r.status, check, json::parse(r.body)};
    }
};

// One real proof shared by the cheap failure paths: they all fail before the
// pairing check, so the proof need not be bound to their fresh nonce.
const ProveResult& stale_proof(Env& env) {
    static const ProveResult p = env.prove(Nonce{});
    return p;
}

} // namespace

TEST_CASE("login: each failure path is caught by its check", "[login][failure]") {
    Env env;
    const TestWallet wallet(0x42);
    const ProveResult& base = stale_proof(env);

    // A request that passes checks 1-5, built around the stale proof and a
    // fresh nonce; each section breaks exactly one thing.
    Proof proof = base.proof;
    PublicInputs pub = base.pub;
    pub.nonce = env.fresh_nonce();
    siwe::Message m = env.siwe_for(wallet.address, proof, pub);
    std::string expect;
    std::function<std::string()> build = [&] {
        m.statement = "Log in to Zk-Auth. zk-auth-proof:0x" + proof_hash_hex(proof, pub);
        const std::string text = siwe::format(m);
        return Env::body(proof, pub, text, wallet.sign(text));
    };
    std::string body;

    SECTION("body over 16 KB") { body = build() + std::string(17 * 1024, ' '); expect = "body"; }
    SECTION("body is not JSON") { body = build().substr(0, 100); expect = "body"; }
    SECTION("unexpected extra field") {
        json j = json::parse(build()); j["dob"] = "2001-05-14"; body = j.dump(); expect = "body";
    }
    SECTION("packed inputs disagree with the named fields") {
        json j = json::parse(build()); j["public"]["packed"][7] = std::string(64, '0'); body = j.dump(); expect = "body";
    }
    SECTION("proof point off the curve (one flipped byte)") {
        json j = json::parse(build());
        std::string x = j["proof"]["a"]["x"];
        x[10] = x[10] == '1' ? '2' : '1';
        j["proof"]["a"]["x"] = x;
        body = j.dump();
        expect = "body";
    }
    SECTION("malformed signature") {
        json j = json::parse(build()); j["signature"] = "0x1234"; body = j.dump(); expect = "body";
    }
    SECTION("nonce never issued") { pub.nonce[0] ^= 0xff; m.nonce = to_hex(pub.nonce); body = build(); expect = "nonce"; }
    SECTION("nonce expired (TTL 120 s)") { env.now += 121'000; m.issued_at = rfc3339(env.now); m.issued_at_ms = env.now; body = build(); expect = "nonce"; }
    SECTION("nonce used twice (replay)") {
        body = build();
        pub.site_id[0] ^= 1; // the first attempt fails later, but still burns the nonce
        REQUIRE(env.login(build()).check == "site-id");
        expect = "nonce";
    }
    SECTION("SIWE: not EIP-4361 (trailing newline)") {
        const std::string text = siwe::format(m) + "\n";
        body = Env::body(proof, pub, text, wallet.sign(text));
        expect = "siwe-format";
    }
    SECTION("SIWE: signed for another domain (phishing)") { m.domain = "evil.example"; body = build(); expect = "siwe-domain"; }
    SECTION("SIWE: scheme-qualified domain") { m.scheme = "https"; body = build(); expect = "siwe-domain"; }
    SECTION("SIWE: other URI") { m.uri = "http://localhost:9999"; body = build(); expect = "siwe-uri"; }
    SECTION("SIWE: other chain") { m.chain_id = 137; body = build(); expect = "siwe-chain-id"; }
    SECTION("SIWE: issued more than 5 minutes ago") {
        m.issued_at = rfc3339(env.now - 301'000); body = build(); expect = "siwe-time";
    }
    SECTION("SIWE: issued in the future") { m.issued_at = rfc3339(env.now + 120'000); body = build(); expect = "siwe-time"; }
    SECTION("SIWE: past its Expiration Time") {
        m.expiration_time = rfc3339(env.now - 1000); body = build(); expect = "siwe-time";
    }
    SECTION("SIWE: nonce differs from the proof's nonce") { m.nonce = std::string(32, 'a'); body = build(); expect = "siwe-nonce"; }
    SECTION("statement without the proof tag") {
        const std::string text = [&] { auto m2 = m; m2.statement = "Log in to Zk-Auth."; return siwe::format(m2); }();
        body = Env::body(proof, pub, text, wallet.sign(text));
        expect = "proof-hash";
    }
    SECTION("statement commits to a different proof") {
        const std::string text = [&] {
            auto m2 = m;
            m2.statement = "Log in to Zk-Auth. zk-auth-proof:0x" + std::string(64, 'b');
            return siwe::format(m2);
        }();
        body = Env::body(proof, pub, text, wallet.sign(text));
        expect = "proof-hash";
    }
    SECTION("statement with two proof tags") {
        const std::string text = [&] {
            auto m2 = m;
            m2.statement = *m.statement + " zk-auth-proof:0x" + proof_hash_hex(proof, pub);
            return siwe::format(m2);
        }();
        body = Env::body(proof, pub, text, wallet.sign(text));
        expect = "proof-hash";
    }
    SECTION("proof made for another site") { pub.site_id = server::site_id_for("evil.example"); body = build(); expect = "site-id"; }
    SECTION("later age cutoff than the server issued (under-18 attack)") { pub.age_cutoff += 365; body = build(); expect = "age-cutoff"; }
    SECTION("Merkle root the issuer never published") { pub.merkle_root[3] ^= 1; body = build(); expect = "merkle-root"; }
    SECTION("valid proof, but for a different nonce") { body = build(); expect = "groth16"; }
    SECTION("on-curve tamper: C negated") { proof.g_C = -proof.g_C; body = build(); expect = "groth16"; }

    const auto r = env.login(body);
    CHECK(r.status == 401);
    CHECK(r.body == json{{"error", "authentication failed"}}); // generic for every failure
    CHECK(r.check == expect);
}

TEST_CASE("login: cheap checks run before the pairing check", "[login][order]") {
    Env env;
    const TestWallet wallet(0x42);
    const ProveResult& base = stale_proof(env);
    PublicInputs pub = base.pub; // stale nonce: was never issued by this server
    const std::string text = siwe::format(env.siwe_for(wallet.address, base.proof, pub));
    // Both the nonce and the proof are wrong; the nonce check must answer.
    CHECK(env.login(Env::body(base.proof, pub, text, wallet.sign(text))).check == "nonce");
}

TEST_CASE("login: success, session token, /me", "[login][session][slow]") {
    Env env;
    const TestWallet wallet(0x42);
    const Nonce n = env.fresh_nonce();
    const ProveResult p = env.prove(n);
    const std::string text = siwe::format(env.siwe_for(wallet.address, p.proof, p.pub));
    const auto ok = env.login(Env::body(p.proof, p.pub, text, wallet.sign(text)));
    REQUIRE(ok.status == 200);
    CHECK(ok.body["address"] == wallet.address);
    const std::string token = ok.body["token"];

    auto me = [&](const std::string& auth) { return env.svc->me(auth); };
    const auto r = me("Bearer " + token);
    REQUIRE(r.status == 200);
    const json payload = json::parse(r.body);
    CHECK(payload["sub"] == wallet.address);
    CHECK(payload["site"] == kDomain);
    CHECK(payload["nul"] == to_hex(p.pub.nullifier).substr(0, 16));
    CHECK(payload["exp"].get<std::int64_t>() - payload["iat"].get<std::int64_t>() == 900);

    SECTION("tampered payload") {
        std::string t = token;
        const auto d1 = t.find('.');
        t[d1 + 5] = t[d1 + 5] == 'A' ? 'B' : 'A';
        CHECK(me("Bearer " + t).status == 401);
    }
    SECTION("tampered signature") {
        std::string t = token;
        t[t.size() - 3] = t[t.size() - 3] == 'A' ? 'B' : 'A';
        CHECK(me("Bearer " + t).status == 401);
    }
    SECTION("alg none") {
        const std::string none = server::base64url_encode(R"({"alg":"none","typ":"JWT"})");
        CHECK(me("Bearer " + none + token.substr(token.find('.'))).status == 401);
    }
    SECTION("expired after 15 minutes") {
        env.now += 901'000;
        CHECK(me("Bearer " + token).status == 401);
    }
    SECTION("missing or malformed Authorization") {
        CHECK(me("").status == 401);
        CHECK(me(token).status == 401);
        CHECK(me("Bearer garbage").status == 401);
    }
}

TEST_CASE("login: signature from a different wallet", "[login][signature][slow]") {
    Env env;
    const TestWallet claimed(0x42), signer(0x43);
    const ProveResult p = env.prove(env.fresh_nonce());
    const std::string text = siwe::format(env.siwe_for(claimed.address, p.proof, p.pub));
    CHECK(env.login(Env::body(p.proof, p.pub, text, signer.sign(text))).check == "signature");
}

TEST_CASE("login: one credential = one account per site", "[login][nullifier][slow]") {
    Env env;
    const TestWallet alice(0x42), mallory(0x43);
    auto attempt = [&](const TestWallet& w) {
        const ProveResult p = env.prove(env.fresh_nonce(), 0); // same credential every time
        const std::string text = siwe::format(env.siwe_for(w.address, p.proof, p.pub));
        return env.login(Env::body(p.proof, p.pub, text, w.sign(text)));
    };
    CHECK(attempt(alice).status == 200);
    CHECK(attempt(alice).status == 200);               // same address again: fine
    CHECK(attempt(mallory).check == "nullifier");      // shared credential, other account: rejected
}

TEST_CASE("production mode never reveals which check failed", "[login][production]") {
    Env env(/*development=*/false);
    const auto r = env.svc->login("not json");
    CHECK(r.status == 401);
    CHECK(r.headers.empty());
    CHECK(json::parse(r.body) == json{{"error", "authentication failed"}});
}

TEST_CASE("benchmark endpoints /verify-proof and /verify-sig", "[login][endpoints]") {
    Env env;
    const ProveResult& base = stale_proof(env);
    const std::string good = json{{"proof", proof_to_json(base.proof)}, {"public", public_to_json(base.pub)}}.dump();
    CHECK(env.svc->verify_proof(good).body == R"({"valid":true})");
    PublicInputs other = base.pub;
    other.nonce[0] ^= 1;
    const auto bad = env.svc->verify_proof(json{{"proof", proof_to_json(base.proof)}, {"public", public_to_json(other)}}.dump());
    CHECK((bad.status == 200 && bad.body == R"({"valid":false})"));
    CHECK(env.svc->verify_proof("{}").status == 400);

    const TestWallet w(0x42);
    const std::string msg = "hello";
    CHECK(env.svc->verify_sig(json{{"message", msg}, {"signature", w.sign(msg)}, {"address", w.address}}.dump()).body ==
          R"({"valid":true})");
    CHECK(env.svc->verify_sig(json{{"message", msg + "!"}, {"signature", w.sign(msg)}, {"address", w.address}}.dump()).body ==
          R"({"valid":false})");
    CHECK(env.svc->verify_sig(R"({"message":"x"})").status == 400);
}

TEST_CASE("Groth16 verification is safe to run on many threads at once", "[login][concurrency]") {
    Env env;
    const ProveResult& base = stale_proof(env);
    PublicInputs wrong = base.pub;
    wrong.nonce[0] ^= 1;
    std::atomic<int> good{0}, bad{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&] {
            for (int i = 0; i < 10; ++i) {
                good += env.svc->verify_groth16(base.proof, base.pub);
                bad += env.svc->verify_groth16(base.proof, wrong);
            }
        });
    for (auto& t : threads) t.join();
    CHECK(good == 80);
    CHECK(bad == 0);
}

TEST_CASE("a re-randomised proof verifies, but cannot reuse a signature", "[login][malleability]") {
    // Groth16 proofs are malleable: (A/r, r*B, C) satisfies the same pairing
    // equation for any r != 0, without knowing the witness. Harmless here:
    // the wallet signed the hash of the exact proof bytes, and the nonce is
    // single use.
    Env env;
    const TestWallet wallet(0x42);
    const ProveResult& base = stale_proof(env);
    const Fr r = Fr::random_element();
    const Proof mauled(r.inverse() * base.proof.g_A, r * base.proof.g_B, G1(base.proof.g_C));
    CHECK(env.svc->verify_groth16(mauled, base.pub)); // still a valid proof
    CHECK_FALSE(mauled == base.proof);

    PublicInputs pub = base.pub;
    pub.nonce = env.fresh_nonce();
    const std::string text = siwe::format(env.siwe_for(wallet.address, base.proof, pub)); // signs the original
    CHECK(env.login(Env::body(mauled, pub, text, wallet.sign(text))).check == "proof-hash");
}
