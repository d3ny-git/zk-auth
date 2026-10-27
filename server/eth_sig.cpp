#include "eth_sig.hpp"

#include <cctype>
#include <stdexcept>

#include "core/encoding.hpp"

namespace zk::eth {

namespace {

// Frees BN_CTX_start() temporaries on every return path.
struct BnFrame {
    BN_CTX* ctx;
    explicit BnFrame(BN_CTX* c) : ctx(c) { BN_CTX_start(ctx); }
    ~BnFrame() { BN_CTX_end(ctx); }
    BIGNUM* get() {
        BIGNUM* b = BN_CTX_get(ctx);
        if (!b) throw std::bad_alloc();
        return b;
    }
};

struct PointGuard {
    EC_POINT* p;
    explicit PointGuard(const EC_GROUP* g) : p(EC_POINT_new(g)) {
        if (!p) throw std::bad_alloc();
    }
    ~PointGuard() { EC_POINT_free(p); }
};

Verifier& thread_verifier() {
    thread_local Verifier v;
    return v;
}

} // namespace

Verifier::Verifier() {
    // KECCAK-256 is the original Keccak padding, which Ethereum uses; it is
    // NOT "SHA3-256" (different padding byte, different output).
    keccak_ = EVP_MD_fetch(nullptr, "KECCAK-256", nullptr);
    md_ctx_ = EVP_MD_CTX_new();
    group_ = EC_GROUP_new_by_curve_name(NID_secp256k1);
    bn_ctx_ = BN_CTX_new();
    if (!keccak_ || !md_ctx_ || !group_ || !bn_ctx_)
        throw std::runtime_error("OpenSSL >= 3.2 with KECCAK-256 and secp256k1 is required");
    half_n_ = BN_dup(EC_GROUP_get0_order(group_));
    if (!half_n_ || !BN_rshift1(half_n_, half_n_)) throw std::bad_alloc();
}

Verifier::~Verifier() {
    BN_free(half_n_);
    BN_CTX_free(bn_ctx_);
    EC_GROUP_free(group_);
    EVP_MD_CTX_free(md_ctx_);
    EVP_MD_free(keccak_);
}

Hash32 Verifier::keccak256(std::span<const std::uint8_t> data) {
    Hash32 out;
    unsigned int len = 0;
    if (EVP_DigestInit_ex2(md_ctx_, keccak_, nullptr) != 1 ||
        EVP_DigestUpdate(md_ctx_, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(md_ctx_, out.data(), &len) != 1 || len != out.size())
        throw std::runtime_error("KECCAK-256 failed");
    return out;
}

Hash32 Verifier::keccak256(std::string_view data) {
    return keccak256(std::span(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

Hash32 Verifier::eip191_digest(std::string_view message) {
    // The prefix makes a signed login message impossible to replay as a
    // signed Ethereum transaction (transactions never start with 0x19).
    std::string buf = "\x19" "Ethereum Signed Message:\n" + std::to_string(message.size());
    buf.append(message);
    return keccak256(buf);
}

std::optional<Address> Verifier::recover(const Hash32& digest, const Signature& sig) {
    unsigned v = sig[64];
    if (v >= 27) v -= 27;  // wallets send 27/28; some libraries 0/1
    if (v > 1) return std::nullopt; // ids 2/3 (r >= n) are never produced by wallets

    BnFrame f(bn_ctx_);
    BIGNUM *r = f.get(), *s = f.get(), *e = f.get(), *rinv = f.get(), *u1 = f.get(), *u2 = f.get();
    if (!BN_bin2bn(sig.data(), 32, r) || !BN_bin2bn(sig.data() + 32, 32, s) || !BN_bin2bn(digest.data(), 32, e))
        return std::nullopt;
    const BIGNUM* n = EC_GROUP_get0_order(group_);

    // Not an ECDSA signature at all: r and s must lie in [1, n-1].
    if (BN_is_zero(r) || BN_cmp(r, n) >= 0 || BN_is_zero(s) || BN_cmp(s, n) >= 0) return std::nullopt;
    // Signature malleability (EIP-2): (r, n - s) verifies too; only the low-s
    // form is canonical, so a replay cannot arrive under a second encoding.
    if (BN_cmp(s, half_n_) > 0) return std::nullopt;

    // R is the curve point with x = r and the y parity given by v. An r that
    // is not an x-coordinate on the curve cannot come from a real signature.
    PointGuard R(group_), Q(group_);
    if (EC_POINT_set_compressed_coordinates(group_, R.p, r, static_cast<int>(v), bn_ctx_) != 1)
        return std::nullopt;

    // Q = r^-1 (s*R - e*G) = (-e * r^-1) * G + (s * r^-1) * R
    if (!BN_mod_inverse(rinv, r, n, bn_ctx_) || !BN_mod_mul(u1, e, rinv, n, bn_ctx_) ||
        !BN_mod_sub(u1, n, u1, n, bn_ctx_) || !BN_mod_mul(u2, s, rinv, n, bn_ctx_))
        return std::nullopt;
    if (EC_POINT_mul(group_, Q.p, u1, R.p, u2, bn_ctx_) != 1) return std::nullopt;
    // The point at infinity is not a public key; accepting it would "recover"
    // a meaningless address from crafted (r, s).
    if (EC_POINT_is_at_infinity(group_, Q.p)) return std::nullopt;

    std::uint8_t pub[65];
    if (EC_POINT_point2oct(group_, Q.p, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof pub, bn_ctx_) != sizeof pub)
        return std::nullopt;
    // Address = last 20 bytes of keccak256(X || Y), without the 0x04 prefix.
    const Hash32 h = keccak256(std::span<const std::uint8_t>(pub + 1, 64));
    Address a;
    std::copy(h.begin() + 12, h.end(), a.begin());
    return a;
}

std::optional<Address> Verifier::recover_personal(std::string_view message, const Signature& sig) {
    return recover(eip191_digest(message), sig);
}

std::optional<Address> recover_personal_fresh(std::string_view message, const Signature& sig) {
    Verifier v;
    return v.recover_personal(message, sig);
}

std::string to_checksum_address(const Address& a) {
    std::string hex = to_hex(a);
    const Hash32 h = thread_verifier().keccak256(hex);
    for (std::size_t i = 0; i < hex.size(); ++i) {
        const int nibble = (h[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 0xf;
        if (hex[i] >= 'a' && nibble >= 8) hex[i] = static_cast<char>(std::toupper(hex[i]));
    }
    return "0x" + hex;
}

std::optional<Address> parse_address(std::string_view s) {
    if (s.size() != 42 || !s.starts_with("0x")) return std::nullopt;
    Address a;
    try {
        Bytes b = from_eth_hex(s, 20);
        std::copy(b.begin(), b.end(), a.begin());
    } catch (const FormatError&) {
        return std::nullopt;
    }
    const std::string_view body = s.substr(2);
    const bool has_lower = body.find_first_of("abcdef") != std::string_view::npos;
    const bool has_upper = body.find_first_of("ABCDEF") != std::string_view::npos;
    // Mixed case is a checksum claim, and a false claim means a typo or tampering.
    if (has_lower && has_upper && to_checksum_address(a) != s) return std::nullopt;
    return a;
}

std::optional<Signature> parse_signature(std::string_view s) {
    if (s.size() != 132 || !s.starts_with("0x")) return std::nullopt;
    try {
        Bytes b = from_eth_hex(s, 65);
        Signature sig;
        std::copy(b.begin(), b.end(), sig.begin());
        return sig;
    } catch (const FormatError&) {
        return std::nullopt;
    }
}

} // namespace zk::eth
