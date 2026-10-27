// M0 smoke test: proves the toolchain, Catch2 and the sanitizer flags work
// together before any cryptography is involved.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

TEST_CASE("toolchain compiles C++20 and runs under the sanitizers", "[smoke]") {
    std::vector<int> v{1, 2, 3};
    CHECK(std::ranges::find(v, 2) != v.end());
    std::string s = "zk-auth";
    CHECK(s.starts_with("zk"));
}
