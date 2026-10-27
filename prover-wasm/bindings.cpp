// JavaScript-facing API of the WebAssembly prover (Embind).
//
// Every function returns a JSON string. Errors come back as {"error": "..."}
// rather than as thrown exceptions, so the Web Worker never has to decode a
// WebAssembly.Exception.
#include <emscripten/bind.h>
#include <emscripten/version.h>

#include <chrono>
#include <string>

#include "core/formats.hpp"
#include "core/toy_circuit.hpp"

using namespace zk;

namespace {

template <class F>
std::string guarded(F&& f) {
    try {
        init_snark();
        return f().dump();
    } catch (const std::exception& e) {
        return json{{"error", e.what()}}.dump();
    }
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

// M1 risk spike: prove x^3 + x + 5 == out for the given x.
std::string toy_prove(const std::string& pk_bytes, int x) {
    return guarded([&] {
        auto t0 = std::chrono::steady_clock::now();
        auto pk = deserialize<ProvingKey>(pk_bytes);
        double load_ms = ms_since(t0);
        ToyCircuit c;
        c.generate_witness(x);
        if (!c.pb.is_satisfied()) throw FormatError("witness does not satisfy the circuit");
        t0 = std::chrono::steady_clock::now();
        Proof proof = libsnark::r1cs_gg_ppzksnark_prover<ppT>(pk, c.pb.primary_input(), c.pb.auxiliary_input());
        return json{{"proof", proof_to_json(proof)},
                    {"public", {fr_to_hex(c.pb.val(c.out))}},
                    {"pk_load_ms", load_ms},
                    {"prove_ms", ms_since(t0)}};
    });
}

std::string version() {
    return guarded([] {
        return json{{"name", "zkauth-prover"},
                    {"curve", "alt_bn128"},
                    {"limb_bits", GMP_NUMB_BITS},
                    {"emscripten", std::to_string(__EMSCRIPTEN_major__) + "." +
                                       std::to_string(__EMSCRIPTEN_minor__) + "." +
                                       std::to_string(__EMSCRIPTEN_tiny__)}};
    });
}

} // namespace

EMSCRIPTEN_BINDINGS(zkauth_prover) {
    emscripten::function("toyProve", &toy_prove);
    emscripten::function("version", &version);
}
