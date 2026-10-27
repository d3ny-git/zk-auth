// Wire formats for field elements, curve points, proofs and keys.
// docs/formats.md is the human-readable specification of everything here.
#pragma once

#include <cstddef>
#include <istream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "encoding.hpp"
#include "snark.hpp"

namespace zk {

using json = nlohmann::json;

// --- field elements: 32-byte big-endian lowercase hex ----------------------
std::string fq_to_hex(const Fq& v);
std::string fr_to_hex(const Fr& v);
// Reject values >= the modulus: otherwise "x" and "x + p" would be two
// encodings of one element, and the proof hash signed by the wallet would
// stop being unique.
Fq fq_from_hex(std::string_view hex);
Fr fr_from_hex(std::string_view hex);
Fr fr_from_bytes(const Bytes& be32);
Bytes fr_to_bytes(const Fr& v);

// --- curve points: affine coordinates --------------------------------------
// The point at infinity is written as all-zero coordinates; (0,0) is on
// neither curve, so the encoding is unambiguous.
json g1_to_json(const G1& p);
json g2_to_json(const G2& p);
G1 g1_from_json(const json& j, bool allow_infinity = false);
G2 g2_from_json(const json& j, bool allow_infinity = false);

// --- proofs and keys ---------------------------------------------------------
json proof_to_json(const Proof& proof);
Proof proof_from_json(const json& j);

// vk.json: the verification key as hex points, plus alpha_g1 and beta_g2 taken
// from the proving key (libsnark's vk only stores the pairing e(alpha, beta),
// but snarkjs needs the two points separately).
json vk_to_json(const VerificationKey& vk, const G1& alpha_g1, const G2& beta_g2);

// Rejects any JSON object whose keys are not exactly `keys` (fail closed:
// unexpected fields are an error, not something to ignore).
void expect_keys(const json& j, std::initializer_list<const char*> keys);
const std::string& expect_string(const json& j, const char* key);

// --- binary (libsnark operator<< / operator>>) -----------------------------
template <class T>
std::string serialize(const T& value) {
    std::ostringstream ss;
    ss << value;
    return std::move(ss).str();
}

// Reads without copying the buffer (proving keys are tens of MB, and in the
// browser every copy counts against the 4 GB wasm32 address space).
class MemoryStreambuf : public std::streambuf {
public:
    explicit MemoryStreambuf(std::string_view data) {
        char* p = const_cast<char*>(data.data());
        setg(p, p, p + data.size());
    }
};

template <class T>
T deserialize(std::string_view bytes) {
    MemoryStreambuf buf(bytes);
    std::istream in(&buf);
    T value;
    in >> value;
    if (!in || in.peek() != std::char_traits<char>::eof())
        throw FormatError("binary key/proof: truncated or trailing data");
    return value;
}

std::string read_file(const std::string& path);
void write_file(const std::string& path, std::string_view data);

} // namespace zk
