// Server state shared by all Crow worker threads:
//   NonceStore     one-time login nonces with a TTL
//   NullifierStore nullifier -> the one address it may log in as
//   KnownRoots     Merkle roots published by the issuer (roots.json)
// The two maps are sharded: a key hashes to one of 64 independently locked
// buckets, so concurrent logins rarely contend on the same mutex.
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "core/circuit.hpp"
#include "server/eth_sig.hpp"

namespace zk::server {

// Keys here are uniformly random bytes (nonces, hashes), so their first 8
// bytes are already a good hash.
struct BytesHash {
    template <std::size_t N>
    std::size_t operator()(const std::array<std::uint8_t, N>& a) const noexcept {
        static_assert(N >= sizeof(std::size_t));
        std::size_t h;
        std::memcpy(&h, a.data(), sizeof h);
        return h;
    }
};

template <class K, class V, std::size_t Shards = 64>
class ShardedMap {
public:
    template <class F>
    auto with_shard(const K& key, F&& f) {
        Shard& s = shards_[BytesHash{}(key) % Shards];
        std::lock_guard lock(s.mu);
        return f(s.map);
    }
    template <class F>
    void for_each_shard(F&& f) {
        for (Shard& s : shards_) {
            std::lock_guard lock(s.mu);
            f(s.map);
        }
    }

private:
    struct alignas(64) Shard { // one cache line per lock: no false sharing
        std::mutex mu;
        std::unordered_map<K, V, BytesHash> map;
    };
    std::array<Shard, Shards> shards_;
};

using Millis = std::int64_t; // milliseconds on the service clock

class NonceStore {
public:
    struct Entry {
        Millis expires_at;
        std::uint32_t age_cutoff; // the cutoff handed out with this nonce
    };

    // A fresh 128-bit nonce from RAND_bytes, remembered until now + ttl.
    Nonce issue(Millis now, Millis ttl, std::uint32_t age_cutoff);

    // Atomically removes the nonce and returns its entry if it existed and had
    // not expired. A second call with the same nonce always fails: replaying
    // a captured login request is rejected here.
    std::optional<Entry> consume(const Nonce& n, Millis now);

    // Drops expired entries (lazy expiry happens in consume; this bounds memory).
    std::size_t sweep(Millis now);
    std::size_t size();

private:
    ShardedMap<Nonce, Entry> map_;
};

class NullifierStore {
public:
    enum class Bind { New, SameAddress, Conflict };
    // First login with a nullifier binds it to the address; later logins must
    // use the same address. One credential = one account per site.
    Bind bind(const Digest& nullifier, const eth::Address& address);
    std::size_t size();

private:
    ShardedMap<Digest, eth::Address> map_;
};

class KnownRoots {
public:
    explicit KnownRoots(std::filesystem::path roots_json);
    bool contains(const Digest& root) const;
    // Re-reads roots.json if its modification time changed. Readers keep
    // using the old set until the new one is swapped in atomically.
    bool reload_if_changed();
    std::size_t size() const;

private:
    using Set = std::unordered_set<Digest, BytesHash>;
    std::filesystem::path path_;
    std::filesystem::file_time_type mtime_{};
    std::atomic<std::shared_ptr<const Set>> roots_;
    void load();
};

} // namespace zk::server
