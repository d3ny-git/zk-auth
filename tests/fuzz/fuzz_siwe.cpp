// libFuzzer target: the EIP-4361 parser. Properties: never crash; and every
// accepted message re-formats to exactly the input bytes, so the server
// interprets precisely the text the wallet displayed.
#include <cstdint>
#include <string_view>

#include "server/siwe.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    try {
        const zk::siwe::Message m = zk::siwe::parse(text);
        if (zk::siwe::format(m) != text) __builtin_trap();
    } catch (const std::exception&) {
    }
    return 0;
}
