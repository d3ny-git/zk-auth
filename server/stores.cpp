#include "stores.hpp"

#include <stdexcept>

#include <openssl/rand.h>

#include "core/formats.hpp"

namespace zk::server {

Nonce NonceStore::issue(Millis now, Millis ttl, std::uint32_t age_cutoff) {
    Nonce n;
    // Predictable nonces would let an attacker prepare a proof before the
    // victim asks for one: use the CSPRNG.
    if (RAND_bytes(n.data(), static_cast<int>(n.size())) != 1) throw std::runtime_error("RAND_bytes failed");
    map_.with_shard(n, [&](auto& m) { m[n] = Entry{now + ttl, age_cutoff}; });
    return n;
}

std::optional<NonceStore::Entry> NonceStore::consume(const Nonce& n, Millis now) {
    return map_.with_shard(n, [&](auto& m) -> std::optional<Entry> {
        auto it = m.find(n);
        if (it == m.end()) return std::nullopt;
        const Entry e = it->second;
        m.erase(it); // removed whether or not it expired: single use, under the shard lock
        if (e.expires_at < now) return std::nullopt;
        return e;
    });
}

std::size_t NonceStore::sweep(Millis now) {
    std::size_t removed = 0;
    map_.for_each_shard([&](auto& m) {
        removed += std::erase_if(m, [&](const auto& kv) { return kv.second.expires_at < now; });
    });
    return removed;
}

std::size_t NonceStore::size() {
    std::size_t n = 0;
    map_.for_each_shard([&](auto& m) { n += m.size(); });
    return n;
}

NullifierStore::Bind NullifierStore::bind(const Digest& nullifier, const eth::Address& address) {
    return map_.with_shard(nullifier, [&](auto& m) {
        auto [it, inserted] = m.try_emplace(nullifier, address);
        if (inserted) return Bind::New;
        return it->second == address ? Bind::SameAddress : Bind::Conflict;
    });
}

std::size_t NullifierStore::size() {
    std::size_t n = 0;
    map_.for_each_shard([&](auto& m) { n += m.size(); });
    return n;
}

KnownRoots::KnownRoots(std::filesystem::path roots_json) : path_(std::move(roots_json)) { load(); }

void KnownRoots::load() {
    const auto mtime = std::filesystem::last_write_time(path_);
    const json j = json::parse(read_file(path_.string()));
    auto set = std::make_shared<Set>();
    for (const auto& r : j.at("roots")) set->insert(digest_from_hex(r.get<std::string>()));
    if (set->empty()) throw std::runtime_error("roots.json lists no roots");
    roots_.store(std::move(set));
    mtime_ = mtime;
}

bool KnownRoots::reload_if_changed() {
    std::error_code ec;
    const auto mtime = std::filesystem::last_write_time(path_, ec);
    if (ec || mtime == mtime_) return false;
    load();
    return true;
}

bool KnownRoots::contains(const Digest& root) const { return roots_.load()->contains(root); }
std::size_t KnownRoots::size() const { return roots_.load()->size(); }

} // namespace zk::server
