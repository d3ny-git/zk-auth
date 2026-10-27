// Encoding round-trips and the edge cases of the strict parsers.
#include <catch2/catch_test_macros.hpp>

#include "core/encoding.hpp"

using namespace zk;

TEST_CASE("hex round-trips and is strict", "[encoding]") {
    const Bytes b{0x00, 0x01, 0xab, 0xff};
    CHECK(to_hex(b) == "0001abff");
    CHECK(from_hex("0001abff", 4) == b);

    CHECK_THROWS_AS(from_hex("0001ABFF", 4), FormatError);  // uppercase: not canonical
    CHECK_THROWS_AS(from_hex("0x0001ab", 4), FormatError);  // prefix not allowed here
    CHECK_THROWS_AS(from_hex("0001ab", 4), FormatError);    // too short
    CHECK_THROWS_AS(from_hex("0001abff00", 4), FormatError);
    CHECK_THROWS_AS(from_hex("0001abfg", 4), FormatError);
}

TEST_CASE("Ethereum hex accepts 0x and either case, but still exact length", "[encoding]") {
    CHECK(from_eth_hex("0xABcd", 2) == Bytes{0xab, 0xcd});
    CHECK(from_eth_hex("abcd", 2) == Bytes{0xab, 0xcd});
    CHECK_THROWS_AS(from_eth_hex("0xabc", 2), FormatError);
}

TEST_CASE("bytes <-> bits is most-significant-bit first", "[encoding]") {
    const Bytes b{0x80, 0x01};
    auto bits = bytes_to_bits(b);
    REQUIRE(bits.size() == 16);
    CHECK(bits[0] == true);   // 0x80's top bit
    CHECK(bits[15] == true);  // 0x01's bottom bit
    CHECK(bits_to_bytes(bits) == b);
    CHECK_THROWS_AS(bits_to_bytes(libff::bit_vector(7)), FormatError);
}

TEST_CASE("pad256 left-pads big-endian", "[encoding]") {
    Bytes p = pad256_u32(11456);
    CHECK(to_hex(p) == "0000000000000000000000000000000000000000000000000000000000002cc0");
    CHECK(read_u32_be(std::span(p).subspan(28)) == 11456u);
}

TEST_CASE("dates are days since 1970-01-01", "[encoding][dates]") {
    CHECK(days_from_iso_date("1970-01-01") == 0u);
    CHECK(days_from_iso_date("2001-05-14") == 11456u);
    CHECK(iso_date_from_days(11456) == "2001-05-14");
    CHECK(days_from_iso_date("2000-02-29") == 11016u); // leap year

    CHECK_THROWS_AS(days_from_iso_date("2001-02-29"), FormatError); // not a leap year
    CHECK_THROWS_AS(days_from_iso_date("1969-12-31"), FormatError);
    CHECK_THROWS_AS(days_from_iso_date("2001-5-14"), FormatError);
    CHECK_THROWS_AS(days_from_iso_date("2001/05/14"), FormatError);
    CHECK_THROWS_AS(days_from_iso_date("2001-13-01"), FormatError);
}

TEST_CASE("age cutoff is today minus 18 years", "[encoding][dates]") {
    CHECK(age_cutoff_days(days_from_iso_date("2026-10-27")) == days_from_iso_date("2008-10-27"));
    // 29 Feb 2028 - 18 years = 29 Feb 2010, which does not exist -> 28 Feb 2010.
    CHECK(age_cutoff_days(days_from_iso_date("2028-02-29")) == days_from_iso_date("2010-02-28"));
    // Someone born 29 Feb 2008 is not yet 18 on 28 Feb 2026, and is on 1 Mar 2026.
    const auto born = days_from_iso_date("2008-02-29");
    CHECK(born > age_cutoff_days(days_from_iso_date("2026-02-28")));
    CHECK(born <= age_cutoff_days(days_from_iso_date("2026-03-01")));
}
