// Deterministic test fixtures: a small issuer tree and the server's public
// values. Secrets are fixed patterns so worked examples in the docs are
// reproducible.
#pragma once

#include <vector>

#include "core/merkle_tree.hpp"

namespace zk::test {

struct TreeFixture {
    MerkleTree tree;
    std::vector<Credential> creds;
    Digest site_id{};
    Nonce nonce{};
    std::uint32_t age_cutoff = days_from_iso_date("2008-10-27"); // "today" = 2026-10-27

    explicit TreeFixture(std::size_t n = 5) {
        const char* dobs[] = {"2001-05-14", "1990-01-01", "2008-10-27", "2008-10-28", "1970-01-01"};
        for (std::size_t i = 0; i < n; ++i) {
            Credential c;
            c.secret.fill(std::uint8_t(0x11 * (i + 1)));
            c.dob = days_from_iso_date(dobs[i % 5]);
            tree.set_leaf(i, commitment_of(c));
            creds.push_back(c);
        }
        site_id.fill(0x5a);
        nonce.fill(0x0f);
    }
};

} // namespace zk::test
