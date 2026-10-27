// Server state: one-time nonces (TTL, single use, races), nullifier binding,
// published roots (atomic reload), and session-token primitives.
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <random>
#include <thread>

#include "core/formats.hpp"
#include "server/stores.hpp"
#include "server/token.hpp"

using namespace zk;
using namespace zk::server;
namespace fs = std::filesystem;

namespace {
fs::path temp_dir(const char* tag) {
    fs::path d = fs::temp_directory_path() / (std::string(tag) + std::to_string(std::random_device{}()));
    fs::create_directories(d);
    return d;
}
} // namespace

TEST_CASE("nonces are single use and expire", "[stores][nonce]") {
    NonceStore s;
    const Nonce n = s.issue(/*now=*/1000, /*ttl=*/120'000, /*cutoff=*/14179);
    REQUIRE(s.size() == 1);
    const auto e = s.consume(n, 2000);
    REQUIRE(e);
    CHECK(e->age_cutoff == 14179u);
    CHECK_FALSE(s.consume(n, 2000)); // replay
    CHECK(s.size() == 0);

    const Nonce old = s.issue(1000, 120'000, 0);
    CHECK_FALSE(s.consume(old, 1000 + 120'001)); // expired
    CHECK_FALSE(s.consume(Nonce{}, 1000));       // never issued

    for (int i = 0; i < 100; ++i) s.issue(1000, 10, 0);
    s.issue(1000, 1'000'000, 0);
    CHECK(s.sweep(5000) == 100);
    CHECK(s.size() == 1);
}

TEST_CASE("exactly one of many concurrent logins can consume a nonce", "[stores][nonce][concurrency]") {
    for (int round = 0; round < 50; ++round) {
        NonceStore s;
        const Nonce n = s.issue(0, 120'000, 0);
        std::atomic<int> winners{0};
        std::vector<std::thread> ts;
        for (int t = 0; t < 16; ++t) ts.emplace_back([&] { winners += s.consume(n, 1).has_value(); });
        for (auto& t : ts) t.join();
        REQUIRE(winners == 1);
    }
}

TEST_CASE("concurrent nonce issuing loses nothing", "[stores][nonce][concurrency]") {
    NonceStore s;
    std::vector<std::thread> ts;
    std::vector<std::vector<Nonce>> issued(8);
    for (int t = 0; t < 8; ++t)
        ts.emplace_back([&, t] { for (int i = 0; i < 1000; ++i) issued[t].push_back(s.issue(0, 120'000, 0)); });
    for (auto& t : ts) t.join();
    CHECK(s.size() == 8000);
    std::size_t consumed = 0;
    for (auto& v : issued) for (auto& n : v) consumed += s.consume(n, 1).has_value();
    CHECK(consumed == 8000);
}

TEST_CASE("a nullifier binds to its first address", "[stores][nullifier]") {
    NullifierStore s;
    Digest nul{};
    nul.fill(7);
    eth::Address a{}, b{};
    a.fill(1);
    b.fill(2);
    CHECK(s.bind(nul, a) == NullifierStore::Bind::New);
    CHECK(s.bind(nul, a) == NullifierStore::Bind::SameAddress);
    CHECK(s.bind(nul, b) == NullifierStore::Bind::Conflict);
}

TEST_CASE("concurrent binds of one nullifier: one winner, the rest conflict", "[stores][nullifier][concurrency]") {
    NullifierStore s;
    Digest nul{};
    nul.fill(9);
    std::atomic<int> created{0}, conflicts{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < 16; ++t)
        ts.emplace_back([&, t] {
            eth::Address a{};
            a.fill(std::uint8_t(t + 1));
            const auto r = s.bind(nul, a);
            created += r == NullifierStore::Bind::New;
            conflicts += r == NullifierStore::Bind::Conflict;
        });
    for (auto& t : ts) t.join();
    CHECK(created == 1);
    CHECK(conflicts == 15);
}

TEST_CASE("known roots reload atomically when roots.json changes", "[stores][roots]") {
    const fs::path d = temp_dir("zk-roots-");
    const std::string file = (d / "roots.json").string();
    Digest r1{}, r2{};
    r1.fill(1);
    r2.fill(2);
    write_file(file, json{{"roots", {to_hex(r1)}}}.dump());
    KnownRoots roots(file);
    CHECK(roots.contains(r1));
    CHECK_FALSE(roots.contains(r2));
    CHECK_FALSE(roots.reload_if_changed());

    write_file(file, json{{"roots", {to_hex(r1), to_hex(r2)}}}.dump());
    fs::last_write_time(file, fs::last_write_time(file) + std::chrono::seconds(2));
    CHECK(roots.reload_if_changed());
    CHECK(roots.contains(r2));

    write_file(file, "{ broken");
    fs::last_write_time(file, fs::last_write_time(file) + std::chrono::seconds(4));
    CHECK_THROWS(roots.reload_if_changed()); // the server logs this and keeps serving…
    CHECK(roots.contains(r2));               // …with the previous set
    fs::remove_all(d);
}

TEST_CASE("base64url is strict", "[token][base64]") {
    for (const std::string& s : std::vector<std::string>{"", "f", "fo", "foo", "foob", "fooba", "foobar", std::string("\x00\xff\x10", 3)})
        CHECK(base64url_decode(base64url_encode(s)) == s);
    CHECK(base64url_encode("\xfb\xff") == "-_8");
    CHECK_THROWS_AS(base64url_decode("Zm9v="), FormatError); // padding
    CHECK_THROWS_AS(base64url_decode("Zm+v"), FormatError);  // base64, not base64url
    CHECK_THROWS_AS(base64url_decode("Zh"), FormatError);    // non-zero leftover bits
    CHECK_THROWS_AS(base64url_decode("Z"), FormatError);
}

TEST_CASE("session keys are generated once, kept private, and survive restarts", "[token][key]") {
    const fs::path d = temp_dir("zk-token-");
    const std::string pem = (d / "session.pem").string();
    std::string token;
    {
        TokenSigner s(pem);
        token = s.issue({{"sub", "x"}, {"exp", 2000}});
        CHECK(s.verify(token, 1000));
        CHECK_FALSE(s.verify(token, 2000)); // exp is exclusive
    }
    const auto perms = fs::status(pem).permissions();
    CHECK((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);
    TokenSigner reloaded(pem);
    CHECK(reloaded.verify(token, 1000)); // same key after a restart
    TokenSigner other((d / "other.pem").string());
    CHECK_FALSE(other.verify(token, 1000)); // a different key rejects it
    fs::remove_all(d);
}
