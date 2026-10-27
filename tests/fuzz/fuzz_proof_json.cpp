// libFuzzer target: the /login and /verify-proof body parser (JSON, field
// elements, curve points incl. on-curve and subgroup checks, public inputs
// incl. the packed-vs-named consistency check). Property: never crash, hang
// or trip a sanitizer; FormatError/json exceptions are the only allowed failure.
#include <cstdint>
#include <string_view>

#include "core/formats.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const bool init = (zk::init_snark(), true);
    (void)init;
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    try {
        const zk::json j = zk::json::parse(text);
        if (!j.is_object()) return 0;
        if (j.contains("proof")) {
            const zk::Proof p = zk::proof_from_json(j.at("proof"));
            // Accepted points must re-serialise to the canonical text.
            const zk::json again = zk::proof_to_json(p);
            if (zk::proof_from_json(again) != p) __builtin_trap();
        }
        if (j.contains("public")) {
            const zk::PublicInputs pub = zk::public_from_json(j.at("public"));
            if (!(zk::public_from_json(zk::public_to_json(pub)) == pub)) __builtin_trap();
        }
    } catch (const std::exception&) {
    }
    return 0;
}
