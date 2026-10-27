// Byte, hex and bit encodings shared by every component.
//
// Conventions (see docs/formats.md):
//   * hex in proof/public JSON is lowercase, unprefixed and of exact length,
//     so every value has exactly one textual form (needed for hashing);
//   * a byte string becomes bits most-significant bit first, which is how the
//     libsnark SHA-256 gadget numbers its input and output bits.
#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <libff/common/utils.hpp>

namespace zk {

using Bytes = std::vector<std::uint8_t>;

// Thrown for any malformed external input. Callers on the server turn it into
// a generic authentication failure; the message is for the server log only.
struct FormatError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string to_hex(std::span<const std::uint8_t> bytes);

// Strict: lowercase [0-9a-f] only, exactly 2*expected_len characters.
Bytes from_hex(std::string_view hex, std::size_t expected_len);

// Lenient variant for Ethereum values that arrive from wallets: optional "0x",
// either case. Length is still exact.
Bytes from_eth_hex(std::string_view hex, std::size_t expected_len);

libff::bit_vector bytes_to_bits(std::span<const std::uint8_t> bytes);
Bytes bits_to_bytes(const libff::bit_vector& bits); // bits.size() % 8 == 0

// pad256(v): v as a 32-byte big-endian integer (left-padded with zeros).
Bytes pad256_u32(std::uint32_t v);

std::uint32_t read_u32_be(std::span<const std::uint8_t> four);

// --- dates: days since 1970-01-01 (UTC), the encoding of dob and age_cutoff --
// Strict "YYYY-MM-DD"; rejects impossible dates and anything before 1970.
std::uint32_t days_from_iso_date(std::string_view yyyy_mm_dd);
std::string iso_date_from_days(std::uint32_t days);
std::uint32_t today_utc_days();
// Days-since-epoch of (today - years). When that calendar date does not exist
// (29 February in a non-leap year) the last day of the month is used, so a
// person born on 29 Feb 2008 counts as 18 from 1 Mar 2026.
std::uint32_t age_cutoff_days(std::uint32_t today_days, int years = 18);

} // namespace zk
