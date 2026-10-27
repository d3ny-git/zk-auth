// Ethereum signature verification with OpenSSL only: Keccak-256, EIP-191
// "personal_sign" digests, secp256k1 public-key recovery and EIP-55 addresses.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace zk::eth {

using Hash32 = std::array<std::uint8_t, 32>;
using Address = std::array<std::uint8_t, 20>;
using Signature = std::array<std::uint8_t, 65>; // r || s || v

// "0x" + 40 hex with the EIP-55 mixed-case checksum.
std::string to_checksum_address(const Address& a);

// Accepts "0x" + 40 hex. All-lowercase or all-uppercase is accepted as is;
// mixed case must be a correct EIP-55 checksum (a typo detector: a wrong
// checksum means the address was mistyped or tampered with).
std::optional<Address> parse_address(std::string_view s);

// "0x" + 130 hex (either case).
std::optional<Signature> parse_signature(std::string_view s);

// Holds the reusable OpenSSL objects (fetched KECCAK-256, digest context,
// secp256k1 group, BN_CTX, constants). Creating them costs far more than one
// verification, so the server keeps one per thread. NOT thread-safe.
class Verifier {
public:
    Verifier();
    ~Verifier();
    Verifier(const Verifier&) = delete;
    Verifier& operator=(const Verifier&) = delete;

    Hash32 keccak256(std::span<const std::uint8_t> data);
    Hash32 keccak256(std::string_view data);

    // keccak256("\x19Ethereum Signed Message:\n" + decimal(len(msg)) + msg)
    Hash32 eip191_digest(std::string_view message);

    // The address whose key produced `sig` over `digest`, or nullopt if the
    // signature is malformed, high-s, or recovers to no valid key.
    std::optional<Address> recover(const Hash32& digest, const Signature& sig);

    // personal_sign convenience: recover(eip191_digest(message), sig).
    std::optional<Address> recover_personal(std::string_view message, const Signature& sig);

private:
    EVP_MD* keccak_ = nullptr;
    EVP_MD_CTX* md_ctx_ = nullptr;
    EC_GROUP* group_ = nullptr;
    BN_CTX* bn_ctx_ = nullptr;
    BIGNUM* half_n_ = nullptr;
};

// Benchmark baseline for the "reuse per thread vs per request" experiment:
// builds every OpenSSL object from scratch for one recovery.
std::optional<Address> recover_personal_fresh(std::string_view message, const Signature& sig);

} // namespace zk::eth
