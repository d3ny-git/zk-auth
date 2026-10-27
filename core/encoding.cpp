#include "encoding.hpp"

namespace zk {

namespace {

int nibble(char c, bool allow_upper) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (allow_upper && c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes decode(std::string_view hex, std::size_t expected_len, bool allow_upper) {
    if (hex.size() != 2 * expected_len)
        throw FormatError("hex: expected " + std::to_string(2 * expected_len) +
                          " chars, got " + std::to_string(hex.size()));
    Bytes out(expected_len);
    for (std::size_t i = 0; i < expected_len; ++i) {
        int hi = nibble(hex[2 * i], allow_upper);
        int lo = nibble(hex[2 * i + 1], allow_upper);
        if (hi < 0 || lo < 0) throw FormatError("hex: invalid character");
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return out;
}

} // namespace

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0xf]);
    }
    return s;
}

Bytes from_hex(std::string_view hex, std::size_t expected_len) {
    return decode(hex, expected_len, /*allow_upper=*/false);
}

Bytes from_eth_hex(std::string_view hex, std::size_t expected_len) {
    if (hex.starts_with("0x") || hex.starts_with("0X")) hex.remove_prefix(2);
    return decode(hex, expected_len, /*allow_upper=*/true);
}

libff::bit_vector bytes_to_bits(std::span<const std::uint8_t> bytes) {
    libff::bit_vector bits;
    bits.reserve(bytes.size() * 8);
    for (std::uint8_t b : bytes)
        for (int i = 7; i >= 0; --i) bits.push_back((b >> i) & 1);
    return bits;
}

Bytes bits_to_bytes(const libff::bit_vector& bits) {
    if (bits.size() % 8 != 0) throw FormatError("bits_to_bytes: length not a multiple of 8");
    Bytes out(bits.size() / 8, 0);
    for (std::size_t i = 0; i < bits.size(); ++i)
        if (bits[i]) out[i / 8] |= static_cast<std::uint8_t>(0x80 >> (i % 8));
    return out;
}

Bytes pad256_u32(std::uint32_t v) {
    Bytes out(32, 0);
    out[28] = static_cast<std::uint8_t>(v >> 24);
    out[29] = static_cast<std::uint8_t>(v >> 16);
    out[30] = static_cast<std::uint8_t>(v >> 8);
    out[31] = static_cast<std::uint8_t>(v);
    return out;
}

std::uint32_t read_u32_be(std::span<const std::uint8_t> four) {
    if (four.size() != 4) throw FormatError("read_u32_be: need 4 bytes");
    return std::uint32_t{four[0]} << 24 | std::uint32_t{four[1]} << 16 |
           std::uint32_t{four[2]} << 8 | std::uint32_t{four[3]};
}

} // namespace zk
