// Sign-In with Ethereum (EIP-4361) messages: a strict parser and a formatter.
//
//   ${domain} wants you to sign in with your Ethereum account:
//   ${address}
//
//   ${statement}
//
//   URI: ${uri}
//   Version: 1
//   Chain ID: ${chain-id}
//   Nonce: ${nonce}
//   Issued At: ${issued-at}
//   [Expiration Time: ${expiration-time}]
//   [Not Before: ${not-before}]
//   [Request ID: ${request-id}]
//   [Resources:
//   - ${uri} ...]
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/encoding.hpp"
#include "server/eth_sig.hpp"

namespace zk::siwe {

inline constexpr std::size_t kMaxMessageBytes = 4096;

struct Message {
    std::string scheme; // optional "https" in "https://example.com wants you…"; empty if absent
    std::string domain; // RFC 3986 authority, e.g. "localhost:8080"
    eth::Address address{};
    std::string address_text; // as written (EIP-55)
    std::optional<std::string> statement;
    std::string uri;
    std::string version; // always "1"
    std::uint64_t chain_id = 0;
    std::string nonce;
    std::string issued_at;
    std::int64_t issued_at_ms = 0;
    std::optional<std::string> expiration_time;
    std::optional<std::int64_t> expiration_ms;
    std::optional<std::string> not_before;
    std::optional<std::int64_t> not_before_ms;
    std::optional<std::string> request_id;
    std::vector<std::string> resources;
};

// Strict: anything that is not exactly the EIP-4361 grammar (CR characters,
// trailing newline, fields out of order, unknown fields, lowercase or wrongly
// checksummed address, short nonce, …) throws FormatError. The text the
// wallet showed the user is the text we interpret, nothing looser.
Message parse(std::string_view text);

// The inverse of parse(): produces the exact text (tests, fixtures, docs).
std::string format(const Message& m);

// RFC 3339 date-time -> milliseconds since the Unix epoch. Throws FormatError.
std::int64_t parse_rfc3339_ms(std::string_view s);

} // namespace zk::siwe
