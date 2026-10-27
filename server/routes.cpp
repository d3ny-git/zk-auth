#include "routes.hpp"

#include <cstdio>

#include <openssl/rand.h>

#include "server/eth_sig.hpp"
#include "server/siwe.hpp"

namespace zk::server {

namespace {

constexpr std::string_view kProofTag = "zk-auth-proof:0x";

std::string rfc3339_ms(std::int64_t ms) {
    const std::uint32_t days = static_cast<std::uint32_t>(ms / 86'400'000);
    const std::int64_t rem = ms % 86'400'000;
    char buf[40];
    std::snprintf(buf, sizeof buf, "%sT%02d:%02d:%02d.%03dZ", iso_date_from_days(days).c_str(), int(rem / 3'600'000),
                  int(rem / 60'000 % 60), int(rem / 1000 % 60), int(rem % 1000));
    return buf;
}

std::string u32_hex(std::uint32_t v) {
    const std::array<std::uint8_t, 4> b{std::uint8_t(v >> 24), std::uint8_t(v >> 16), std::uint8_t(v >> 8), std::uint8_t(v)};
    return to_hex(b);
}

HttpResult json_result(int status, const json& body) { return {status, body.dump(), {}}; }

eth::Verifier& thread_eth() {
    thread_local eth::Verifier v; // OpenSSL contexts reused per worker thread
    return v;
}

// The proof hash the wallet signed: exactly one "zk-auth-proof:0x<64 hex>" in
// the statement. Two different tags would make "which proof was signed?"
// ambiguous, so that is rejected too.
std::optional<std::string> signed_proof_hash(const std::string& statement) {
    const auto pos = statement.find(kProofTag);
    if (pos == std::string::npos || statement.find(kProofTag, pos + 1) != std::string::npos) return std::nullopt;
    const std::string h = statement.substr(pos + kProofTag.size(), 64);
    if (h.size() != 64 || h.find_first_not_of("0123456789abcdef") != std::string::npos) return std::nullopt;
    return h;
}

} // namespace

const char* check_name(Check c) {
    switch (c) {
    case Check::Body: return "body";
    case Check::Nonce: return "nonce";
    case Check::Siwe: return "siwe-format";
    case Check::SiweDomain: return "siwe-domain";
    case Check::SiweUri: return "siwe-uri";
    case Check::SiweChain: return "siwe-chain-id";
    case Check::SiweTime: return "siwe-time";
    case Check::SiweNonce: return "siwe-nonce";
    case Check::ProofHash: return "proof-hash";
    case Check::SiteId: return "site-id";
    case Check::AgeCutoff: return "age-cutoff";
    case Check::MerkleRoot: return "merkle-root";
    case Check::Groth16: return "groth16";
    case Check::Signature: return "signature";
    case Check::Nullifier: return "nullifier";
    }
    return "unknown";
}

Digest site_id_for(std::string_view domain) { return sha256("zk-auth:" + std::string(domain)); }

std::int64_t AuthService::system_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

AuthService::AuthService(Config cfg, Clock now_ms)
    : cfg_(std::move(cfg)),
      now_ms_(std::move(now_ms)),
      site_id_(site_id_for(cfg_.domain)),
      // Processing the vk once (precomputing pairing lines for gamma, delta)
      // saves that work on every request.
      pvk_(libsnark::r1cs_gg_ppzksnark_verifier_process_vk<ppT>(deserialize<VerificationKey>(read_file(cfg_.vk_path)))),
      roots_(cfg_.roots_path),
      tokens_(cfg_.session_key_path) {}

bool AuthService::verify_groth16(const Proof& proof, const PublicInputs& pub) const {
    return libsnark::r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk_, pack_public_inputs(pub), proof);
}

HttpResult AuthService::reject(Check c, const std::string& detail) const {
    // The specific reason goes to the server log only; clients always get the
    // same generic answer, so failures cannot be used as an oracle.
    std::fprintf(stderr, "login rejected: check=%s detail=%s\n", check_name(c), detail.c_str());
    HttpResult r = json_result(401, {{"error", "authentication failed"}});
    if (cfg_.debug_reject_header) r.headers.emplace_back("X-ZkAuth-Reject", check_name(c));
    return r;
}

HttpResult AuthService::nonce() {
    const std::int64_t now = now_ms_();
    const std::uint32_t cutoff = age_cutoff_days(static_cast<std::uint32_t>(now / 86'400'000));
    const Nonce n = nonces_.issue(now, cfg_.nonce_ttl_ms, cutoff);
    return json_result(200, {{"nonce", to_hex(n)},
                             {"age_cutoff", u32_hex(cutoff)},
                             {"site_id", to_hex(site_id_)},
                             {"issued_at", rfc3339_ms(now)},
                             // Informational, so the client can tell the user
                             // which domain and chain this server expects.
                             {"domain", cfg_.domain},
                             {"chain_id", cfg_.chain_id}});
}

HttpResult AuthService::login(std::string_view body) {
    const std::int64_t now = now_ms_();

    // 1. Parse and size-limit. Oversized bodies are cheap to send and costly to parse.
    if (body.size() > kMaxBodyBytes) return reject(Check::Body, "body over 16 KB");
    Proof proof;
    PublicInputs pub;
    std::string message;
    eth::Signature sig;
    try {
        const json j = json::parse(body);
        expect_keys(j, {"proof", "public", "siwe_message", "signature"});
        proof = proof_from_json(j.at("proof"));  // on-curve and subgroup checks happen here
        pub = public_from_json(j.at("public"));  // packed inputs must match the named fields
        message = expect_string(j, "siwe_message");
        auto s = eth::parse_signature(expect_string(j, "signature"));
        if (!s) throw FormatError("bad signature encoding");
        sig = *s;
    } catch (const std::exception& e) {
        return reject(Check::Body, e.what());
    }

    // 2. One-time nonce, removed atomically: a captured request cannot be replayed.
    const auto nonce_entry = nonces_.consume(pub.nonce, now);
    if (!nonce_entry) return reject(Check::Nonce, "unknown, expired or already used nonce");

    // 3. The SIWE message: right site, right chain, fresh, same nonce, and it
    //    commits to exactly this proof.
    siwe::Message m;
    try {
        m = siwe::parse(message);
    } catch (const std::exception& e) {
        return reject(Check::Siwe, e.what());
    }
    if (m.domain != cfg_.domain || !m.scheme.empty())  // phishing: signed for another site
        return reject(Check::SiweDomain, m.domain);
    if (m.uri != cfg_.uri) return reject(Check::SiweUri, m.uri);
    if (m.chain_id != cfg_.chain_id) return reject(Check::SiweChain, std::to_string(m.chain_id));
    // Stale or post-dated messages: a signature harvested long ago is useless.
    if (m.issued_at_ms < now - cfg_.siwe_max_age_ms || m.issued_at_ms > now + cfg_.clock_skew_ms ||
        (m.expiration_ms && *m.expiration_ms <= now) || (m.not_before_ms && *m.not_before_ms > now + cfg_.clock_skew_ms))
        return reject(Check::SiweTime, m.issued_at);
    // The signed nonce must be the proof's nonce: binds wallet and proof to this login.
    if (m.nonce != to_hex(pub.nonce)) return reject(Check::SiweNonce, m.nonce);
    // The wallet signed a hash of these exact proof bytes and public inputs:
    // swapping in another proof (or re-randomising this one) breaks it.
    const auto signed_hash = m.statement ? signed_proof_hash(*m.statement) : std::nullopt;
    if (!signed_hash || *signed_hash != proof_hash_hex(proof, pub))
        return reject(Check::ProofHash, "statement does not commit to this proof");

    // 4. Public inputs the server itself decides.
    if (pub.site_id != site_id_) return reject(Check::SiteId, "proof made for another site");          // cross-site reuse
    if (pub.age_cutoff != nonce_entry->age_cutoff) return reject(Check::AgeCutoff, u32_hex(pub.age_cutoff)); // under-age with a later cutoff

    // 5. Only roots the issuer actually published: a self-made tree proves nothing.
    if (!roots_.contains(pub.merkle_root)) return reject(Check::MerkleRoot, to_hex(pub.merkle_root));

    // 6. The pairing check, last among the proof checks because it is the most expensive.
    if (!verify_groth16(proof, pub)) return reject(Check::Groth16, "proof does not verify");

    // 7. The wallet that signed must be the address claimed in the message.
    const auto signer = thread_eth().recover_personal(message, sig);
    if (!signer || *signer != m.address) return reject(Check::Signature, "signature does not match address");

    // 8. One credential = one account per site.
    if (nullifiers_.bind(pub.nullifier, m.address) == NullifierStore::Bind::Conflict)
        return reject(Check::Nullifier, "credential already bound to another address");

    // 9. Session token.
    const std::int64_t iat = now / 1000;
    std::array<std::uint8_t, 16> jti;
    RAND_bytes(jti.data(), static_cast<int>(jti.size()));
    const std::string address = eth::to_checksum_address(m.address);
    const json payload = {{"sub", address},
                          {"site", cfg_.domain},
                          {"nul", to_hex(pub.nullifier).substr(0, 16)},
                          {"iat", iat},
                          {"exp", iat + cfg_.session_ttl_s},
                          {"jti", to_hex(jti)}};
    return json_result(200, {{"token", tokens_.issue(payload)},
                             {"address", address},
                             {"expires_at", rfc3339_ms((iat + cfg_.session_ttl_s) * 1000)}});
}

HttpResult AuthService::verify_proof(std::string_view body) {
    if (body.size() > kMaxBodyBytes) return json_result(400, {{"valid", false}});
    try {
        const json j = json::parse(body);
        expect_keys(j, {"proof", "public"});
        const Proof proof = proof_from_json(j.at("proof"));
        const PublicInputs pub = public_from_json(j.at("public"));
        return json_result(200, {{"valid", verify_groth16(proof, pub)}});
    } catch (const std::exception&) {
        return json_result(400, {{"valid", false}});
    }
}

HttpResult AuthService::verify_sig(std::string_view body) {
    if (body.size() > kMaxBodyBytes) return json_result(400, {{"valid", false}});
    try {
        const json j = json::parse(body);
        expect_keys(j, {"message", "signature", "address"});
        const auto sig = eth::parse_signature(expect_string(j, "signature"));
        const auto addr = eth::parse_address(expect_string(j, "address"));
        if (!sig || !addr) return json_result(400, {{"valid", false}});
        const auto signer = thread_eth().recover_personal(expect_string(j, "message"), *sig);
        return json_result(200, {{"valid", signer && *signer == *addr}});
    } catch (const std::exception&) {
        return json_result(400, {{"valid", false}});
    }
}

HttpResult AuthService::me(std::string_view authorization) {
    constexpr std::string_view kBearer = "Bearer ";
    if (authorization.starts_with(kBearer)) {
        if (auto payload = tokens_.verify(authorization.substr(kBearer.size()), now_ms_() / 1000))
            return json_result(200, *payload);
    }
    return json_result(401, {{"error", "authentication failed"}});
}

HttpResult AuthService::health() const { return json_result(200, {{"ok", true}}); }

void AuthService::maintain() {
    nonces_.sweep(now_ms_());
    try {
        if (roots_.reload_if_changed()) std::fprintf(stderr, "reloaded roots.json (%zu roots)\n", roots_.size());
    } catch (const std::exception& e) {
        std::fprintf(stderr, "roots.json reload failed, keeping previous roots: %s\n", e.what());
    }
}

} // namespace zk::server
