// The Zk-Auth HTTP API as plain C++ (no Crow types), so tests can drive every
// endpoint without a network; main.cpp binds it to a Crow app.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/formats.hpp"
#include "server/stores.hpp"
#include "server/token.hpp"

namespace zk::server {

inline constexpr std::size_t kMaxBodyBytes = 16 * 1024;

struct Config {
    std::string domain = "localhost:8080";      // SIWE domain: the client's origin host
    std::string uri = "http://localhost:8080";  // SIWE URI
    std::uint64_t chain_id = 1;
    std::string vk_path = "keys/vk.bin";
    std::string roots_path = "data/issuer/roots.json";
    std::string session_key_path = "data/server/session_ed25519.pem";
    // Development mode adds X-ZkAuth-Reject: <check> to rejected logins (the
    // attack lab shows it). Production mode never reveals which check failed.
    bool debug_reject_header = false;
    std::int64_t nonce_ttl_ms = 120'000;
    std::int64_t siwe_max_age_ms = 300'000;
    std::int64_t clock_skew_ms = 30'000;
    std::int64_t session_ttl_s = 900;
};

// The /login check chain, in order; the name is what the debug header shows.
enum class Check {
    Body, Nonce, Siwe, SiweDomain, SiweUri, SiweChain, SiweTime, SiweNonce, ProofHash,
    SiteId, AgeCutoff, MerkleRoot, Groth16, Signature, Nullifier,
};
const char* check_name(Check c);

struct HttpResult {
    int status = 200;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

class AuthService {
public:
    using Clock = std::function<std::int64_t()>; // milliseconds since the Unix epoch
    static std::int64_t system_now_ms();

    explicit AuthService(Config cfg, Clock now_ms = &AuthService::system_now_ms);

    HttpResult nonce();
    HttpResult login(std::string_view body);
    HttpResult verify_proof(std::string_view body);
    HttpResult verify_sig(std::string_view body);
    HttpResult me(std::string_view authorization_header);
    HttpResult health() const;

    // Periodic maintenance (sweeper thread): expire nonces, reload roots.json.
    void maintain();

    const Config& config() const { return cfg_; }
    const Digest& site_id() const { return site_id_; }
    NonceStore& nonces() { return nonces_; }
    NullifierStore& nullifiers() { return nullifiers_; }

    // Groth16 with the processed key: the expensive part of /login, exposed
    // for benchmarks.
    bool verify_groth16(const Proof& proof, const PublicInputs& pub) const;

private:
    struct LoginError {
        Check check;
        std::string detail;
    };
    HttpResult reject(Check c, const std::string& detail) const;

    Config cfg_;
    Clock now_ms_;
    Digest site_id_{};
    ProcessedVerificationKey pvk_;
    NonceStore nonces_;
    NullifierStore nullifiers_;
    KnownRoots roots_;
    TokenSigner tokens_;
};

// SHA-256("zk-auth:" || domain)
Digest site_id_for(std::string_view domain);

} // namespace zk::server
