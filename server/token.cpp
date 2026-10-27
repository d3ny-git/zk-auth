#include "token.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>

#include <openssl/pem.h>

namespace zk::server {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const nlohmann::json& expected_header() {
    static const nlohmann::json h = {{"alg", "EdDSA"}, {"typ", "JWT"}};
    return h;
}

using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

} // namespace

std::string base64url_encode(std::string_view in) {
    std::string out;
    std::uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        buf = buf << 8 | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(kAlphabet[(buf >> bits) & 63]);
        }
    }
    if (bits > 0) out.push_back(kAlphabet[(buf << (6 - bits)) & 63]);
    return out;
}

std::string base64url_decode(std::string_view in) {
    if (in.size() % 4 == 1) throw FormatError("base64url: bad length");
    std::string out;
    std::uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '-') v = 62;
        else if (c == '_') v = 63;
        else throw FormatError("base64url: bad character");
        buf = buf << 6 | std::uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xff));
        }
    }
    // Leftover bits must be zero, or two strings would decode to the same bytes.
    if ((buf & ((1u << bits) - 1)) != 0) throw FormatError("base64url: non-canonical encoding");
    return out;
}

TokenSigner::TokenSigner(const std::string& pem_path) {
    if (std::filesystem::exists(pem_path)) {
        Bio bio(BIO_new_file(pem_path.c_str(), "r"), BIO_free);
        if (bio) key_ = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (!key_ || EVP_PKEY_get_id(key_) != EVP_PKEY_ED25519)
            throw std::runtime_error("session key " + pem_path + " is not an Ed25519 private key");
        return;
    }
    key_ = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!key_) throw std::runtime_error("Ed25519 key generation failed");
    std::filesystem::create_directories(std::filesystem::path(pem_path).parent_path());
    Bio bio(BIO_new_file(pem_path.c_str(), "w"), BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key_, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        throw std::runtime_error("cannot write " + pem_path);
    bio.reset();
    std::filesystem::permissions(pem_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace);
}

TokenSigner::~TokenSigner() { EVP_PKEY_free(key_); }

std::string TokenSigner::issue(const nlohmann::json& payload) const {
    const std::string signing_input =
        base64url_encode(expected_header().dump()) + "." + base64url_encode(payload.dump());
    MdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    unsigned char sig[64];
    size_t sig_len = sizeof sig;
    // Ed25519 hashes internally ("pure" EdDSA): no separate digest, hence NULL md.
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_) != 1 ||
        EVP_DigestSign(ctx.get(), sig, &sig_len, reinterpret_cast<const unsigned char*>(signing_input.data()),
                       signing_input.size()) != 1)
        throw std::runtime_error("Ed25519 signing failed");
    return signing_input + "." + base64url_encode(std::string_view(reinterpret_cast<char*>(sig), sig_len));
}

std::optional<nlohmann::json> TokenSigner::verify(std::string_view token, std::int64_t now_s) const {
    try {
        const auto d1 = token.find('.');
        const auto d2 = token.find('.', d1 == std::string_view::npos ? d1 : d1 + 1);
        if (d1 == std::string_view::npos || d2 == std::string_view::npos ||
            token.find('.', d2 + 1) != std::string_view::npos)
            return std::nullopt;
        // Algorithm confusion ("alg":"none", HS256 with the public key, …):
        // only our exact header is accepted.
        if (nlohmann::json::parse(base64url_decode(token.substr(0, d1))) != expected_header()) return std::nullopt;
        const std::string sig = base64url_decode(token.substr(d2 + 1));
        if (sig.size() != 64) return std::nullopt;
        const std::string_view signing_input = token.substr(0, d2);
        MdCtx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        // Forged or modified token: the Ed25519 signature must verify.
        if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key_) != 1 ||
            EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
                             reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size()) != 1)
            return std::nullopt;
        nlohmann::json payload = nlohmann::json::parse(base64url_decode(token.substr(d1 + 1, d2 - d1 - 1)));
        // Stolen old tokens stop working after 15 minutes.
        if (!payload.contains("exp") || !payload["exp"].is_number_integer() || payload["exp"].get<std::int64_t>() <= now_s)
            return std::nullopt;
        return payload;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace zk::server
