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

} // namespace zk
