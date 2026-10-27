#include "merkle_tree.hpp"

#include <stdexcept>

namespace zk {

MerkleTree::MerkleTree() {
    // An empty tree: all leaves zero; each level is H of two copies of the
    // empty node below, so only one hash per level is needed.
    Digest empty{};
    for (std::size_t k = 0; k <= kTreeDepth; ++k) {
        levels_.emplace_back(kNumLeaves >> k, empty);
        empty = hash2(empty, empty);
    }
}

void MerkleTree::set_leaf(std::size_t index, const Digest& leaf) {
    if (index >= kNumLeaves) throw std::out_of_range("leaf index");
    levels_[0][index] = leaf;
    for (std::size_t k = 1; k <= kTreeDepth; ++k) {
        index >>= 1;
        levels_[k][index] = hash2(levels_[k - 1][2 * index], levels_[k - 1][2 * index + 1]);
    }
}

MerklePath MerkleTree::path(std::size_t index) const {
    if (index >= kNumLeaves) throw std::out_of_range("leaf index");
    MerklePath p;
    p.index = static_cast<std::uint32_t>(index);
    for (std::size_t k = 0; k < kTreeDepth; ++k) {
        p.siblings[k] = levels_[k][index ^ 1];
        index >>= 1;
    }
    return p;
}

} // namespace zk
