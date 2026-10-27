#include "encoding.hpp"

#include <chrono>
#include <cstdio>

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

namespace {

using namespace std::chrono;

std::uint32_t to_days(const year_month_day& ymd) {
    const auto d = sys_days(ymd).time_since_epoch().count();
    if (d < 0) throw FormatError("date before 1970-01-01");
    return static_cast<std::uint32_t>(d);
}

} // namespace

std::uint32_t days_from_iso_date(std::string_view s) {
    auto digits = [&](std::size_t from, std::size_t n) {
        int v = 0;
        for (std::size_t i = from; i < from + n; ++i) {
            if (s[i] < '0' || s[i] > '9') throw FormatError("date: expected YYYY-MM-DD");
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') throw FormatError("date: expected YYYY-MM-DD");
    const year_month_day ymd{year{digits(0, 4)}, month{unsigned(digits(5, 2))}, day{unsigned(digits(8, 2))}};
    if (!ymd.ok()) throw FormatError("date: no such calendar day");
    return to_days(ymd);
}

std::string iso_date_from_days(std::uint32_t days) {
    const year_month_day ymd{sys_days{std::chrono::days{days}}};
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02u", int(ymd.year()), unsigned(ymd.month()), unsigned(ymd.day()));
    return buf;
}

std::uint32_t today_utc_days() {
    return static_cast<std::uint32_t>(floor<std::chrono::days>(system_clock::now()).time_since_epoch().count());
}

std::uint32_t age_cutoff_days(std::uint32_t today_days, int years_back) {
    const year_month_day today{sys_days{std::chrono::days{today_days}}};
    year_month_day then{today.year() - years{years_back}, today.month(), today.day()};
    if (!then.ok()) then = year_month_day{year_month_day_last{then.year(), month_day_last{then.month()}}};
    return to_days(then);
}

} // namespace zk
