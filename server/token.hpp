// Session tokens: compact JWTs signed with Ed25519 (header {"alg":"EdDSA","typ":"JWT"}).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include "core/encoding.hpp"

namespace zk::server {

std::string base64url_encode(std::string_view data);
// Strict: unpadded base64url alphabet only; throws FormatError otherwise.
std::string base64url_decode(std::string_view s);

class TokenSigner {
public:
    // Loads an Ed25519 private key (PEM). If the file does not exist, a new key
    // is generated and written with mode 0600. Keys live under data/, which is
    // git-ignored: a committed session key would let anyone mint sessions.
    explicit TokenSigner(const std::string& pem_path);
    ~TokenSigner();
    TokenSigner(const TokenSigner&) = delete;
    TokenSigner& operator=(const TokenSigner&) = delete;

    // header.payload.signature
    std::string issue(const nlohmann::json& payload) const;

    // The payload if the token is well-formed, carries exactly our header,
    // has a valid signature and is unexpired at `now_s`; otherwise nullopt.
    std::optional<nlohmann::json> verify(std::string_view token, std::int64_t now_s) const;

private:
    EVP_PKEY* key_ = nullptr;
};

} // namespace zk::server
