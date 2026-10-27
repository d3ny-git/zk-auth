// EIP-4361 (Sign-In with Ethereum) parser: valid messages round-trip, and
// every deviation from the grammar is rejected.
#include <catch2/catch_test_macros.hpp>

#include "server/siwe.hpp"

using namespace zk;

namespace {

const std::string kAddress = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c";

std::string valid(bool statement = true) {
    std::string s = "localhost:8080 wants you to sign in with your Ethereum account:\n" + kAddress + "\n\n";
    if (statement) s += "Log in to Zk-Auth. zk-auth-proof:0x" + std::string(64, 'a') + "\n";
    s += "\n"
         "URI: http://localhost:8080\n"
         "Version: 1\n"
         "Chain ID: 1\n"
         "Nonce: 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\n"
         "Issued At: 2026-10-27T12:00:00.000Z";
    return s;
}

std::string replace(std::string s, const std::string& from, const std::string& to) {
    const auto pos = s.find(from);
    REQUIRE(pos != std::string::npos);
    return s.replace(pos, from.size(), to);
}

} // namespace

TEST_CASE("valid SIWE messages parse and round-trip", "[siwe]") {
    const auto m = siwe::parse(valid());
    CHECK(m.domain == "localhost:8080");
    CHECK(m.address_text == kAddress);
    REQUIRE(m.statement);
    CHECK(m.statement->ends_with(std::string(64, 'a')));
    CHECK(m.uri == "http://localhost:8080");
    CHECK(m.chain_id == 1u);
    CHECK(m.nonce == "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    CHECK(m.issued_at_ms == 1793102400000);
    CHECK(siwe::format(m) == valid());

    const auto bare = siwe::parse(valid(false));
    CHECK_FALSE(bare.statement);
    CHECK(siwe::format(bare) == valid(false));

    const std::string full = valid() +
        "\nExpiration Time: 2026-10-27T12:05:00Z"
        "\nNot Before: 2026-10-27T11:59:00+00:00"
        "\nRequest ID: req-42"
        "\nResources:\n- ipfs://bafybeigdyrzt\n- https://example.com/terms";
    const auto f = siwe::parse(full);
    CHECK(f.expiration_ms == 1793102700000);
    CHECK(f.not_before_ms == 1793102340000);
    CHECK(f.resources.size() == 2);
    CHECK(siwe::format(f) == full);

    CHECK(siwe::parse("https://" + valid()).scheme == "https");
}

TEST_CASE("RFC 3339 timestamps", "[siwe][time]") {
    CHECK(siwe::parse_rfc3339_ms("2026-10-27T12:00:00Z") == 1793102400000);
    CHECK(siwe::parse_rfc3339_ms("2026-10-27T14:00:00+02:00") == 1793102400000);
    CHECK(siwe::parse_rfc3339_ms("2026-10-27T12:00:00.5Z") == 1793102400500);
    CHECK(siwe::parse_rfc3339_ms("2026-10-27T12:00:00.123456Z") == 1793102400123);
    for (const char* bad : {"2026-10-27 12:00:00Z", "2026-10-27T12:00:00", "2026-02-30T12:00:00Z",
                            "2026-10-27T25:00:00Z", "2026-10-27T12:00:00.Z", "2026-10-27T12:00:00+0200",
                            "2026-10-27T12:00:00Zjunk", ""})
        CHECK_THROWS_AS(siwe::parse_rfc3339_ms(bad), FormatError);
}

TEST_CASE("malformed SIWE messages are rejected", "[siwe][reject]") {
    const std::string v = valid();
    const std::vector<std::pair<const char*, std::string>> cases = {
        {"CRLF line endings", replace(v, "\nURI:", "\r\nURI:")},
        {"trailing newline", v + "\n"},
        {"lowercase address", replace(v, kAddress, "0xfcad0b19bb29d4674531d6f115237e16afce377c")},
        {"wrong checksum", replace(v, kAddress, "0xFCAd0B19bB29D4674531d6f115237E16AfCE377C")},
        {"missing blank line", replace(v, kAddress + "\n\n", kAddress + "\n")},
        {"version 2", replace(v, "Version: 1", "Version: 2")},
        {"hex chain id", replace(v, "Chain ID: 1", "Chain ID: 0x1")},
        {"chain id with a leading zero (fuzz_siwe finding)", replace(v, "Chain ID: 1", "Chain ID: 01")},
        {"short nonce", replace(v, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "abc123")},
        {"nonce with dash", replace(v, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "0f0f0f0f-0f0f0f0f")},
        {"bad issued-at", replace(v, "2026-10-27T12:00:00.000Z", "yesterday")},
        {"fields out of order", replace(replace(v, "Version: 1\n", ""), "Chain ID: 1\n", "Chain ID: 1\nVersion: 1\n")},
        {"unknown trailing field", v + "\nFoo: bar"},
        {"statement with a tab", replace(v, "Log in", "Log\tin")},
        {"domain with a space", replace(v, "localhost:8080 wants", "local host wants")},
        {"wrong header", replace(v, "wants you to sign in", "wants you to log in")},
        {"URI without scheme", replace(v, "URI: http://localhost:8080", "URI: localhost")},
        {"empty Resources", v + "\nResources:"},
        {"truncated", v.substr(0, v.size() / 2)},
        {"oversized", v + "\nRequest ID: " + std::string(5000, 'x')},
    };
    for (const auto& [what, text] : cases) {
        INFO(what);
        CHECK_THROWS_AS(siwe::parse(text), FormatError);
    }
}
