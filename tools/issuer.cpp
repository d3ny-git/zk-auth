// zkauth-issuer: issues credentials and maintains the Merkle tree of their
// commitments. The issuer stores only commitments, never secrets or dates of
// birth: it hands {secret, dob} to the user and forgets them.
//
//   zkauth-issuer init  [--state DIR] [--dummies 20]
//   zkauth-issuer new   [--state DIR] --dob YYYY-MM-DD --out cred.json
//   zkauth-issuer root  [--state DIR] [--roots-out FILE]   (default DIR/roots.json)
//   zkauth-issuer path  [--state DIR] --index N --out path.json
//   zkauth-issuer check --cred cred.json --path path.json [--roots FILE]
#include <cstdio>
#include <filesystem>
#include <random>

#include <openssl/rand.h>

#include "core/formats.hpp"
#include "core/merkle_tree.hpp"
#include "tools/cli.hpp"

using namespace zk;

namespace {

constexpr const char* kUsage =
    "usage: zkauth-issuer init  [--state DIR] [--dummies N]\n"
    "       zkauth-issuer new   [--state DIR] --dob YYYY-MM-DD --out cred.json\n"
    "       zkauth-issuer root  [--state DIR] [--roots-out FILE]\n"
    "       zkauth-issuer path  [--state DIR] --index N --out path.json\n"
    "       zkauth-issuer check --cred cred.json --path path.json [--roots FILE]\n";

Digest random_digest() {
    Digest d;
    // A predictable secret would let anyone recompute the commitment and the
    // per-site nullifiers: use the OS CSPRNG via OpenSSL.
    if (RAND_bytes(d.data(), static_cast<int>(d.size())) != 1) throw std::runtime_error("RAND_bytes failed");
    return d;
}

// Persistent issuer state: the commitments (leaves) in order, and every root
// ever published (the server accepts any of them, so holders of older paths
// can still log in).
struct State {
    std::string dir;
    std::vector<Digest> leaves;
    std::vector<Digest> roots;

    std::string file() const { return dir + "/issuer.json"; }

    static State load(const std::string& dir) {
        State s{dir, {}, {}};
        json j = json::parse(read_file(s.file()));
        for (const auto& h : j.at("leaves")) s.leaves.push_back(digest_from_hex(h.get<std::string>()));
        for (const auto& h : j.at("roots")) s.roots.push_back(digest_from_hex(h.get<std::string>()));
        return s;
    }
    void save() const {
        json j = {{"version", 1}, {"tree_depth", kTreeDepth}, {"leaves", json::array()}, {"roots", json::array()}};
        for (const auto& d : leaves) j["leaves"].push_back(to_hex(d));
        for (const auto& d : roots) j["roots"].push_back(to_hex(d));
        write_file(file(), j.dump(2) + "\n");
    }
    MerkleTree tree() const {
        MerkleTree t;
        for (std::size_t i = 0; i < leaves.size(); ++i) t.set_leaf(i, leaves[i]);
        return t;
    }
    std::size_t append(const Digest& commitment) {
        if (leaves.size() >= kNumLeaves) throw std::runtime_error("tree is full (" + std::to_string(kNumLeaves) + " leaves)");
        leaves.push_back(commitment);
        return leaves.size() - 1;
    }
};

int cmd_init(const cli::Args& a) {
    const std::string dir = a.get("state", "data/issuer");
    if (std::filesystem::exists(dir + "/issuer.json") && !a.has("force"))
        throw std::runtime_error(dir + "/issuer.json exists (use --force to overwrite)");
    std::filesystem::create_directories(dir);
    State s{dir, {}, {}};
    // Dummy credentials make tree membership mean something: a proof shows
    // "one of these N commitments is mine" without saying which. Their
    // secrets are generated and immediately discarded.
    const int dummies = std::stoi(a.get("dummies", "20"));
    std::random_device rd;
    std::uniform_int_distribution<std::uint32_t> dob(0, days_from_iso_date("2007-12-31"));
    for (int i = 0; i < dummies; ++i) s.append(commitment_of({random_digest(), dob(rd)}));
    s.save();
    std::printf("initialised %s with %d dummy credentials\n", s.file().c_str(), dummies);
    return 0;
}

// dob is unsigned days since 1970-01-01, so earlier births cannot be encoded.
// The circuit only ever asks "dob <= cutoff", so recording such a holder as
// born on 1970-01-01 gives the same answer for every cutoff after 1970.
std::uint32_t dob_days_clamped(const std::string& iso) {
    if (iso.size() == 10 && iso.compare(0, 4, "1970") < 0) {
        days_from_iso_date("1970" + iso.substr(4)); // still validate month/day shape
        std::fprintf(stderr, "note: %s is before 1970-01-01; recorded as 1970-01-01 "
                             "(equivalent for every age check after 1970)\n", iso.c_str());
        return 0;
    }
    return days_from_iso_date(iso);
}

int cmd_new(const cli::Args& a) {
    State s = State::load(a.get("state", "data/issuer"));
    Credential c{random_digest(), dob_days_clamped(a.require("dob"))};
    const std::size_t index = s.append(commitment_of(c));
    s.save();
    write_file(a.require("out"), credential_to_json(c).dump(2) + "\n");
    std::printf("issued credential at leaf index %zu -> %s\n", index, a.require("out").c_str());
    std::printf("next: 'zkauth-issuer root' to publish the new root, then "
                "'zkauth-issuer path --index %zu --out path.json'\n", index);
    return 0;
}

int cmd_root(const cli::Args& a) {
    State s = State::load(a.get("state", "data/issuer"));
    const Digest root = s.tree().root();
    if (s.roots.empty() || s.roots.back() != root) s.roots.push_back(root);
    s.save();
    json roots = {{"current", to_hex(root)}, {"roots", json::array()}};
    for (const auto& r : s.roots) roots["roots"].push_back(to_hex(r));
    const std::string out = a.get("roots-out", s.dir + "/roots.json");
    write_file(out, roots.dump(2) + "\n");
    std::printf("%s\n", to_hex(root).c_str());
    std::fprintf(stderr, "(%zu leaves; %zu published roots written to %s)\n", s.leaves.size(), s.roots.size(), out.c_str());
    return 0;
}

int cmd_path(const cli::Args& a) {
    State s = State::load(a.get("state", "data/issuer"));
    const std::size_t index = std::stoul(a.require("index"));
    if (index >= s.leaves.size()) throw std::runtime_error("no credential at that index");
    const MerkleTree t = s.tree();
    write_file(a.require("out"), path_to_json(t.path(index), t.root()).dump(2) + "\n");
    std::printf("wrote authentication path for leaf %zu (root %s) -> %s\n", index, to_hex(t.root()).c_str(),
                a.require("out").c_str());
    return 0;
}

int cmd_check(const cli::Args& a) {
    const Credential c = credential_from_json(json::parse(read_file(a.require("cred"))));
    Digest root;
    const MerklePath p = path_from_json(json::parse(read_file(a.require("path"))), &root);
    const Digest leaf = commitment_of(c);
    const Digest computed = root_from_path(leaf, p);
    std::printf("commitment     %s\ncomputed root  %s\npath root      %s\n", to_hex(leaf).c_str(),
                to_hex(computed).c_str(), to_hex(root).c_str());
    bool ok = computed == root;
    if (a.has("roots")) {
        json roots = json::parse(read_file(a.require("roots")));
        bool published = false;
        for (const auto& r : roots.at("roots")) published |= r.get<std::string>() == to_hex(root);
        std::printf("root published: %s\n", published ? "yes" : "NO");
        ok &= published;
    }
    std::printf("%s\n", ok ? "OK: the credential's path verifies" : "FAIL");
    return ok ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fputs(kUsage, stderr);
        return 2;
    }
    try {
        init_snark();
        const std::string cmd = argv[1];
        const auto args = cli::Args::parse(argc, argv, 2);
        if (cmd == "init") return cmd_init(args);
        if (cmd == "new") return cmd_new(args);
        if (cmd == "root") return cmd_root(args);
        if (cmd == "path") return cmd_path(args);
        if (cmd == "check") return cmd_check(args);
        std::fputs(kUsage, stderr);
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zkauth-issuer: %s\n", e.what());
        return 1;
    }
}
