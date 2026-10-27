// The issuer's Merkle tree of credential commitments (depth kTreeDepth).
// Node = H(left, right); an empty leaf is 256 zero bits.
#pragma once

#include <vector>

#include "circuit.hpp"

namespace zk {

class MerkleTree {
public:
    MerkleTree();

    void set_leaf(std::size_t index, const Digest& leaf); // updates the 8 nodes above it
    const Digest& leaf(std::size_t index) const { return levels_[0].at(index); }
    const Digest& root() const { return levels_[kTreeDepth][0]; }
    MerklePath path(std::size_t index) const;

private:
    // levels_[0] = leaves, levels_[k] = nodes at height k, levels_[kTreeDepth] = {root}
    std::vector<std::vector<Digest>> levels_;
};

} // namespace zk
