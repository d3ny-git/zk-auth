#include "formats.hpp"

#include <fstream>
#include <iterator>

namespace zk {

namespace {

// Both fields are < 2^256, and libff stores them as n limbs of
// GMP_NUMB_BITS bits: 4 x 64 natively, 8 x 32 in wasm32. Converting byte by
// byte keeps this code identical on both.
template <mp_size_t n>
Bytes bigint_to_be32(const libff::bigint<n>& b) {
    static_assert(n * sizeof(mp_limb_t) == 32, "field element must be 32 bytes");
    Bytes out(32, 0);
    for (std::size_t k = 0; k < 32; ++k) {
        std::size_t limb = k / sizeof(mp_limb_t), shift = 8 * (k % sizeof(mp_limb_t));
        out[31 - k] = static_cast<std::uint8_t>(b.data[limb] >> shift);
    }
    return out;
}

template <mp_size_t n>
libff::bigint<n> be32_to_bigint(const Bytes& be) {
    libff::bigint<n> b; // zero-initialised
    for (std::size_t k = 0; k < 32; ++k) {
        std::size_t limb = k / sizeof(mp_limb_t), shift = 8 * (k % sizeof(mp_limb_t));
        b.data[limb] |= static_cast<mp_limb_t>(be[31 - k]) << shift;
    }
    return b;
}

template <class F>
F field_from_be32(const Bytes& be) {
    auto b = be32_to_bigint<F::num_limbs>(be);
    // Non-canonical encodings (value >= modulus) would make proofs malleable
    // at the encoding level: two different strings, one field element.
    if (mpn_cmp(b.data, F::field_char().data, F::num_limbs) >= 0)
        throw FormatError("field element not reduced modulo the field order");
    return F(b);
}

const json& expect_array(const json& j, const char* key, std::size_t size) {
    const json& a = j.at(key);
    if (!a.is_array() || a.size() != size) throw FormatError(std::string("expected array ") + key);
    return a;
}

Fq2 fq2_from_json(const json& a) {
    if (!a.is_array() || a.size() != 2 || !a[0].is_string() || !a[1].is_string())
        throw FormatError("Fq2: expected [c0, c1]");
    return Fq2(fq_from_hex(a[0].get_ref<const std::string&>()),
               fq_from_hex(a[1].get_ref<const std::string&>()));
}

} // namespace

void expect_keys(const json& j, std::initializer_list<const char*> keys) {
    if (!j.is_object() || j.size() != keys.size()) throw FormatError("unexpected JSON object shape");
    for (const char* k : keys)
        if (!j.contains(k)) throw FormatError(std::string("missing field ") + k);
}

const std::string& expect_string(const json& j, const char* key) {
    const json& v = j.at(key);
    if (!v.is_string()) throw FormatError(std::string("expected string ") + key);
    return v.get_ref<const std::string&>();
}

std::string fq_to_hex(const Fq& v) { return to_hex(bigint_to_be32(v.as_bigint())); }
std::string fr_to_hex(const Fr& v) { return to_hex(bigint_to_be32(v.as_bigint())); }
Bytes fr_to_bytes(const Fr& v) { return bigint_to_be32(v.as_bigint()); }

Fq fq_from_hex(std::string_view hex) { return field_from_be32<Fq>(from_hex(hex, 32)); }
Fr fr_from_hex(std::string_view hex) { return field_from_be32<Fr>(from_hex(hex, 32)); }
Fr fr_from_bytes(const Bytes& be32) {
    if (be32.size() != 32) throw FormatError("Fr: need 32 bytes");
    return field_from_be32<Fr>(be32);
}

json g1_to_json(const G1& p) {
    if (p.is_zero()) return {{"x", fq_to_hex(Fq::zero())}, {"y", fq_to_hex(Fq::zero())}};
    G1 a = p;
    a.to_affine_coordinates();
    return {{"x", fq_to_hex(a.X)}, {"y", fq_to_hex(a.Y)}};
}

json g2_to_json(const G2& p) {
    auto fq2 = [](const Fq2& v) { return json::array({fq_to_hex(v.c0), fq_to_hex(v.c1)}); };
    if (p.is_zero()) return {{"x", fq2(Fq2::zero())}, {"y", fq2(Fq2::zero())}};
    G2 a = p;
    a.to_affine_coordinates();
    return {{"x", fq2(a.X)}, {"y", fq2(a.Y)}};
}

G1 g1_from_json(const json& j, bool allow_infinity) {
    expect_keys(j, {"x", "y"});
    Fq x = fq_from_hex(expect_string(j, "x"));
    Fq y = fq_from_hex(expect_string(j, "y"));
    if (x.is_zero() && y.is_zero()) {
        if (!allow_infinity) throw FormatError("G1: point at infinity not allowed here");
        return G1::zero();
    }
    G1 p(x, y, Fq::one());
    // Invalid-curve attack: arithmetic on an off-curve point happens on a
    // different (weak) curve. BN254 G1 has cofactor 1, so on-curve suffices.
    if (!p.is_well_formed()) throw FormatError("G1: point not on curve");
    return p;
}

G2 g2_from_json(const json& j, bool allow_infinity) {
    expect_keys(j, {"x", "y"});
    Fq2 x = fq2_from_json(j.at("x"));
    Fq2 y = fq2_from_json(j.at("y"));
    if (x.is_zero() && y.is_zero()) {
        if (!allow_infinity) throw FormatError("G2: point at infinity not allowed here");
        return G2::zero();
    }
    G2 p(x, y, Fq2::one());
    if (!p.is_well_formed()) throw FormatError("G2: point not on twist curve");
    // Small-subgroup attack: the twist has a large cofactor, so an on-curve
    // point can still lie outside the order-r subgroup the pairing expects.
    if (!(G2::order() * p).is_zero()) throw FormatError("G2: point not in the order-r subgroup");
    return p;
}

json proof_to_json(const Proof& proof) {
    return {{"a", g1_to_json(proof.g_A)}, {"b", g2_to_json(proof.g_B)}, {"c", g1_to_json(proof.g_C)}};
}

Proof proof_from_json(const json& j) {
    expect_keys(j, {"a", "b", "c"});
    return Proof(g1_from_json(j.at("a")), g2_from_json(j.at("b")), g1_from_json(j.at("c")));
}

json vk_to_json(const VerificationKey& vk, const G1& alpha_g1, const G2& beta_g2) {
    json ic = json::array();
    ic.push_back(g1_to_json(vk.gamma_ABC_g1.first));
    for (const G1& p : vk.gamma_ABC_g1.rest.values) ic.push_back(g1_to_json(p));
    return {
        {"protocol", "groth16"},
        {"curve", "alt_bn128"},
        {"n_public", vk.gamma_ABC_g1.rest.values.size()},
        {"alpha_g1", g1_to_json(alpha_g1)},
        {"beta_g2", g2_to_json(beta_g2)},
        {"gamma_g2", g2_to_json(vk.gamma_g2)},
        {"delta_g2", g2_to_json(vk.delta_g2)},
        {"ic", ic},
    };
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_file(const std::string& path, std::string_view data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + path);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) throw std::runtime_error("short write to " + path);
}

} // namespace zk
