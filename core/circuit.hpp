// The Zk-Auth statement, as data types, native helpers and an R1CS circuit.
//
// Statement proved in zero knowledge:
//   "I know (secret, dob, merkle path) such that
//      commitment = H(secret, pad256(dob)) is a leaf of the tree with root `merkle_root`,
//      nullifier  = H(secret, site_id),
//      dob <= age_cutoff                        (born at least 18 years ago)
//    and this proof is for `nonce`."
// H is the SHA-256 compression function on 512 bits (NOT padded SHA-256).
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <libsnark/gadgetlib1/protoboard.hpp>

#include "encoding.hpp"
#include "snark.hpp"

namespace zk {

inline constexpr std::size_t kTreeDepth = 8;
inline constexpr std::size_t kNumLeaves = std::size_t{1} << kTreeDepth;
inline constexpr std::size_t kNumPublicInputs = 8; // field elements, see pack_public_inputs

using Digest = std::array<std::uint8_t, 32>;
using Nonce = std::array<std::uint8_t, 16>;

struct Credential {
    Digest secret{};        // 256 random bits, never leaves the user's device
    std::uint32_t dob = 0;  // days since 1970-01-01 (UTC)
};

// Authentication path for leaf `index`. siblings[k] is the sibling at height k
// (k = 0 is the leaf level). Bit k of `index` is 1 when the node on our path at
// height k is a right child, so its sibling sits on the left.
struct MerklePath {
    std::uint32_t index = 0;
    std::array<Digest, kTreeDepth> siblings{};
};

struct PublicInputs {
    Digest merkle_root{};
    Digest nullifier{};
    Digest site_id{};
    std::uint32_t age_cutoff = 0; // days since epoch of (today - 18 years)
    Nonce nonce{};

    bool operator==(const PublicInputs&) const = default;
};

// --- native versions of the in-circuit computations -------------------------
// Uses sha256_two_to_one_hash_gadget::get_hash, i.e. literally the same code
// the circuit is built from.
Digest hash2(const Digest& left, const Digest& right);
Digest commitment_of(const Credential& c);
Digest nullifier_of(const Digest& secret, const Digest& site_id);
Digest root_from_path(const Digest& leaf, const MerklePath& path);

// The 8 field elements the verifier sees, in this order:
//   merkle_root (2), nullifier (2), site_id (2), age_cutoff (1), nonce (1).
// Digests are packed 253 bits per element (the field's capacity), bit 0 of a
// digest (its most significant bit) being the least significant bit of the
// first element. age_cutoff and nonce are packed least-significant bit first,
// so each element simply equals the integer.
PrimaryInput pack_public_inputs(const PublicInputs& p);

// --- the circuit -------------------------------------------------------------
class ZkAuthCircuit {
public:
    ZkAuthCircuit();   // allocates every variable and generates every constraint
    ~ZkAuthCircuit();
    ZkAuthCircuit(const ZkAuthCircuit&) = delete;
    ZkAuthCircuit& operator=(const ZkAuthCircuit&) = delete;

    // Assigns every wire. The nullifier and Merkle root are *outputs* of the
    // circuit: the returned PublicInputs carries the values the proof will
    // attest to. The caller must still check pb.is_satisfied() (it is false
    // when, e.g., dob > age_cutoff).
    PublicInputs generate_witness(const Credential& cred, const MerklePath& path,
                                  const Digest& site_id, std::uint32_t age_cutoff,
                                  const Nonce& nonce);

    // Test hook: after generate_witness, overwrite the public wires (bits and
    // packed values) to model a prover lying about a public input.
    void overwrite_public_inputs(const PublicInputs& p);

    libsnark::protoboard<Fr>& pb();
    const libsnark::protoboard<Fr>& pb() const;
    std::size_t num_constraints() const;
    std::size_t num_variables() const;
    // (component, constraints it contributes), in construction order.
    const std::vector<std::pair<std::string, std::size_t>>& constraint_breakdown() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace zk
