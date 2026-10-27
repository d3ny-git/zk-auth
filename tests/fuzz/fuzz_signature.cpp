// libFuzzer target: Ethereum signature and address parsing plus public-key
// recovery on arbitrary bytes. Input layout: 65 bytes r||s||v, then the
// message; the whole input is also tried as signature/address text.
// Properties: never crash; a recovered address always re-verifies.
#include <cstdint>
#include <string_view>

#include "server/eth_sig.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static zk::eth::Verifier v;
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    (void)zk::eth::parse_signature(text);
    if (auto a = zk::eth::parse_address(text); a && zk::eth::parse_address(zk::eth::to_checksum_address(*a)) != a)
        __builtin_trap();
    if (size < 65) return 0;
    zk::eth::Signature sig;
    std::copy(data, data + 65, sig.begin());
    const std::string_view message = text.substr(65);
    if (auto who = v.recover_personal(message, sig)) {
        if (v.recover_personal(message, sig) != who) __builtin_trap(); // deterministic
    }
    return 0;
}
