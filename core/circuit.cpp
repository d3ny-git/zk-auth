#include "circuit.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

namespace zk {

using namespace libsnark;
using Hash = sha256_two_to_one_hash_gadget<Fr>;

namespace {

Digest digest_from_bits(const libff::bit_vector& bits) {
    Bytes b = bits_to_bytes(bits);
    Digest d;
    std::copy(b.begin(), b.end(), d.begin());
    return d;
}

// Least-significant-bit-first bits of a big-endian byte string.
libff::bit_vector lsb_first_bits(std::span<const std::uint8_t> be) {
    libff::bit_vector bits;
    for (std::size_t j = 0; j < be.size() * 8; ++j)
        bits.push_back((be[be.size() - 1 - j / 8] >> (j % 8)) & 1);
    return bits;
}

std::array<std::uint8_t, 4> u32_be(std::uint32_t v) {
    return {std::uint8_t(v >> 24), std::uint8_t(v >> 16), std::uint8_t(v >> 8), std::uint8_t(v)};
}

pb_variable_array<Fr> slice(const pb_variable_array<Fr>& a, std::size_t from, std::size_t n) {
    return pb_variable_array<Fr>(a.begin() + from, a.begin() + from + n);
}

} // namespace

// --- native helpers -----------------------------------------------------------

Digest hash2(const Digest& left, const Digest& right) {
    libff::bit_vector block = bytes_to_bits(left);
    libff::bit_vector r = bytes_to_bits(right);
    block.insert(block.end(), r.begin(), r.end());
    return digest_from_bits(Hash::get_hash(block));
}

Digest commitment_of(const Credential& c) {
    Bytes padded = pad256_u32(c.dob);
    Digest dob_block;
    std::copy(padded.begin(), padded.end(), dob_block.begin());
    return hash2(c.secret, dob_block);
}

Digest nullifier_of(const Digest& secret, const Digest& site_id) { return hash2(secret, site_id); }

Digest root_from_path(const Digest& leaf, const MerklePath& path) {
    Digest node = leaf;
    for (std::size_t k = 0; k < kTreeDepth; ++k) {
        const bool is_right = (path.index >> k) & 1;
        node = is_right ? hash2(path.siblings[k], node) : hash2(node, path.siblings[k]);
    }
    return node;
}

PrimaryInput pack_public_inputs(const PublicInputs& p) {
    PrimaryInput out;
    auto pack = [&](const libff::bit_vector& bits) {
        auto v = libff::pack_bit_vector_into_field_element_vector<Fr>(bits, Fr::capacity());
        out.insert(out.end(), v.begin(), v.end());
    };
    pack(bytes_to_bits(p.merkle_root));
    pack(bytes_to_bits(p.nullifier));
    pack(bytes_to_bits(p.site_id));
    pack(lsb_first_bits(u32_be(p.age_cutoff)));
    pack(lsb_first_bits(p.nonce));
    return out;
}

// --- the circuit ----------------------------------------------------------------

struct ZkAuthCircuit::Impl {
    protoboard<Fr> pb;

    // Public: the 8 packed field elements, and the bits they are packed from.
    pb_variable_array<Fr> packed;
    std::unique_ptr<digest_variable<Fr>> root, nullifier, site_id;
    pb_variable_array<Fr> age_bits, nonce_bits; // least-significant bit first
    std::vector<multipacking_gadget<Fr>> packers;

    // Private witness.
    std::unique_ptr<digest_variable<Fr>> secret;
    std::unique_ptr<digest_variable<Fr>> dob_block;   // pad256(dob): 224 zero bits, then dob
    std::unique_ptr<digest_variable<Fr>> commitment;  // H(secret, dob_block), the Merkle leaf
    pb_variable_array<Fr> address_bits;               // the 8 direction bits
    std::unique_ptr<merkle_authentication_path_variable<Fr, Hash>> path;

    // Gadgets.
    std::unique_ptr<Hash> commit_hash, nullifier_hash;
    std::unique_ptr<merkle_tree_check_read_gadget<Fr, Hash>> merkle;
    pb_linear_combination<Fr> dob_value;
    pb_variable<Fr> less, less_or_eq;
    std::unique_ptr<comparison_gadget<Fr>> age_check;

    Impl() {
        const std::size_t cap = Fr::capacity(); // 253 bits fit in one element

        // Public inputs are, by libsnark convention, the first variables
        // allocated; set_input_sizes() marks them.
        packed.allocate(pb, kNumPublicInputs, "packed_public");
        pb.set_input_sizes(kNumPublicInputs);

        root = std::make_unique<digest_variable<Fr>>(pb, 256, "merkle_root");
        nullifier = std::make_unique<digest_variable<Fr>>(pb, 256, "nullifier");
        site_id = std::make_unique<digest_variable<Fr>>(pb, 256, "site_id");
        age_bits.allocate(pb, 32, "age_cutoff_bits");
        nonce_bits.allocate(pb, 128, "nonce_bits");
        packers.emplace_back(pb, root->bits, slice(packed, 0, 2), cap, "pack_root");
        packers.emplace_back(pb, nullifier->bits, slice(packed, 2, 2), cap, "pack_nullifier");
        packers.emplace_back(pb, site_id->bits, slice(packed, 4, 2), cap, "pack_site_id");
        packers.emplace_back(pb, age_bits, slice(packed, 6, 1), cap, "pack_age_cutoff");
        packers.emplace_back(pb, nonce_bits, slice(packed, 7, 1), cap, "pack_nonce");

        secret = std::make_unique<digest_variable<Fr>>(pb, 256, "secret");
        dob_block = std::make_unique<digest_variable<Fr>>(pb, 256, "dob_block");
        commitment = std::make_unique<digest_variable<Fr>>(pb, 256, "commitment");
        address_bits.allocate(pb, kTreeDepth, "address_bits");
        path = std::make_unique<merkle_authentication_path_variable<Fr, Hash>>(pb, kTreeDepth, "path");

        // 1. commitment = H(secret, pad256(dob))
        commit_hash = std::make_unique<Hash>(pb, *secret, *dob_block, *commitment, "commit_hash");
        // 2. commitment is a leaf under merkle_root
        merkle = std::make_unique<merkle_tree_check_read_gadget<Fr, Hash>>(
            pb, kTreeDepth, address_bits, *commitment, *root, *path,
            pb_variable<Fr>(0) /* the constant-1 wire: always check */, "merkle");
        // 3. nullifier = H(secret, site_id); the hash output wires ARE the
        //    public nullifier wires, so they cannot differ.
        nullifier_hash = std::make_unique<Hash>(pb, *secret, *site_id, *nullifier, "nullifier_hash");
        // 4. dob <= age_cutoff. dob is the low 32 bits of dob_block, most
        //    significant first; re-read them least-significant first to get
        //    the integer as a linear combination (no extra variables).
        const pb_variable_array<Fr>& dob_bits = dob_block->bits;
        pb_variable_array<Fr> dob_lsb_first(dob_bits.rbegin(), dob_bits.rbegin() + 32);
        dob_value.assign(pb, pb_packing_sum<Fr>(pb_linear_combination_array<Fr>(dob_lsb_first)));
        less.allocate(pb, "dob_lt_cutoff");
        less_or_eq.allocate(pb, "dob_le_cutoff");
        age_check = std::make_unique<comparison_gadget<Fr>>(
            pb, 32, dob_value, pb_linear_combination<Fr>(packed[6]), less, less_or_eq, "age_check");
        // 5. nonce: a public input and nothing else. Groth16 binds every
        //    public input into the proof (libsnark adds an "input * 0 = 0"
        //    constraint per input during the QAP reduction), so a proof made
        //    for one nonce fails verification for any other.

        generate_constraints();
    }

    std::vector<std::pair<std::string, std::size_t>> breakdown;

    // Runs `step` and records how many constraints it added.
    template <class F>
    void counted(const char* what, F&& step) {
        const std::size_t before = pb.num_constraints();
        step();
        breakdown.emplace_back(what, pb.num_constraints() - before);
    }

    void generate_constraints() {
        // Bitness of every public bit comes from the packers: a non-boolean
        // "bit" would let one packed value correspond to many bit strings.
        counted("public inputs: bit decomposition + packing (928 bits -> 8 elements)", [&] {
            for (auto& p : packers) p.generate_r1cs_constraints(/*enforce_bitness=*/true);
        });

        counted("secret and pad256(dob): booleanity + 224 zero-padding bits", [&] {
            secret->generate_r1cs_constraints();
            dob_block->generate_r1cs_constraints();
            // The upper 224 bits of pad256(dob) must be zero; this is also
            // what makes dob a genuine 32-bit number, which comparison_gadget
            // needs (it is only sound for inputs below 2^n).
            for (std::size_t i = 0; i < 224; ++i)
                pb.add_r1cs_constraint(r1cs_constraint<Fr>(dob_block->bits[i], 1, 0), "dob_pad_zero");
        });

        counted("commitment = H(secret, pad256(dob))", [&] {
            commit_hash->generate_r1cs_constraints(/*ensure_output_bitness=*/true);
        });

        counted("Merkle path: direction bits + sibling digests (booleanity)", [&] {
            // Direction bits must be 0/1, or the selector could blend left and right.
            for (std::size_t i = 0; i < kTreeDepth; ++i)
                generate_boolean_r1cs_constraint<Fr>(pb, address_bits[i], "address_bit");
            path->generate_r1cs_constraints();
        });
        counted("Merkle membership: 8 x (select + H) + root equality", [&] {
            merkle->generate_r1cs_constraints();
        });

        counted("nullifier = H(secret, site_id)", [&] {
            nullifier_hash->generate_r1cs_constraints(/*ensure_output_bitness=*/true);
        });

        counted("dob <= age_cutoff (32-bit comparison)", [&] {
            age_check->generate_r1cs_constraints();
            // Under-age attack: without this, the comparison is computed but not enforced.
            pb.add_r1cs_constraint(r1cs_constraint<Fr>(less_or_eq, 1, 1), "dob_le_cutoff_is_true");
        });
    }

    static void fill_bits(protoboard<Fr>& pb, const pb_variable_array<Fr>& vars, const libff::bit_vector& bits) {
        for (std::size_t i = 0; i < vars.size(); ++i) pb.val(vars[i]) = bits[i] ? Fr::one() : Fr::zero();
    }

    void set_public_bits(const PublicInputs& p) {
        root->generate_r1cs_witness(bytes_to_bits(p.merkle_root));
        nullifier->generate_r1cs_witness(bytes_to_bits(p.nullifier));
        site_id->generate_r1cs_witness(bytes_to_bits(p.site_id));
        fill_bits(pb, age_bits, lsb_first_bits(u32_be(p.age_cutoff)));
        fill_bits(pb, nonce_bits, lsb_first_bits(p.nonce));
        for (auto& p2 : packers) p2.generate_r1cs_witness_from_bits();
    }
};

ZkAuthCircuit::ZkAuthCircuit() : impl_(std::make_unique<Impl>()) {}
ZkAuthCircuit::~ZkAuthCircuit() = default;

PublicInputs ZkAuthCircuit::generate_witness(const Credential& cred, const MerklePath& mpath,
                                             const Digest& site_id, std::uint32_t age_cutoff,
                                             const Nonce& nonce) {
    Impl& c = *impl_;
    c.secret->generate_r1cs_witness(bytes_to_bits(cred.secret));
    c.dob_block->generate_r1cs_witness(bytes_to_bits(pad256_u32(cred.dob)));
    c.commit_hash->generate_r1cs_witness();

    // libsnark orders the path top-down and the address bits bottom-up
    // (address_bits[0] is the leaf level); ours is bottom-up throughout.
    c.address_bits.fill_with_bits_of_ulong(c.pb, mpath.index);
    std::vector<merkle_authentication_node> top_down(kTreeDepth);
    for (std::size_t k = 0; k < kTreeDepth; ++k)
        top_down[kTreeDepth - 1 - k] = bytes_to_bits(mpath.siblings[k]);
    c.path->generate_r1cs_witness(mpath.index, top_down);
    // Computes the path hashes bottom-up and copies the computed root into
    // the public root wires.
    c.merkle->generate_r1cs_witness();

    c.site_id->generate_r1cs_witness(bytes_to_bits(site_id));
    c.nullifier_hash->generate_r1cs_witness();

    Impl::fill_bits(c.pb, c.age_bits, lsb_first_bits(u32_be(age_cutoff)));
    Impl::fill_bits(c.pb, c.nonce_bits, lsb_first_bits(nonce));
    for (auto& p : c.packers) p.generate_r1cs_witness_from_bits();

    c.age_check->generate_r1cs_witness();

    PublicInputs out;
    out.merkle_root = digest_from_bits(c.root->get_digest());
    out.nullifier = digest_from_bits(c.nullifier->get_digest());
    out.site_id = site_id;
    out.age_cutoff = age_cutoff;
    out.nonce = nonce;
    return out;
}

void ZkAuthCircuit::overwrite_public_inputs(const PublicInputs& p) {
    impl_->set_public_bits(p);
    impl_->age_check->generate_r1cs_witness();
}

libsnark::protoboard<Fr>& ZkAuthCircuit::pb() { return impl_->pb; }
const libsnark::protoboard<Fr>& ZkAuthCircuit::pb() const { return impl_->pb; }
std::size_t ZkAuthCircuit::num_constraints() const { return impl_->pb.num_constraints(); }
std::size_t ZkAuthCircuit::num_variables() const { return impl_->pb.num_variables(); }
const std::vector<std::pair<std::string, std::size_t>>& ZkAuthCircuit::constraint_breakdown() const {
    return impl_->breakdown;
}

} // namespace zk
