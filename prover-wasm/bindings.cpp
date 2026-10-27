// JavaScript-facing API of the WebAssembly prover (Embind).
//
//   prove(pk_bytes, credential_json, path_json, public_json) -> proof_json
//   compute_nullifier(secret_hex, site_id_hex)                -> nullifier_json
//   version()                                                  -> version_json
//
// Every function returns a JSON string. Errors come back as {"error": "..."}
// rather than as thrown exceptions, so the Web Worker never has to decode a
// WebAssembly.Exception.
//
// The proving key is ~150 MB. Parsing it takes a while and the parsed key lives
// in wasm memory, so prove() keeps it: pass the bytes on the first call and an
// empty buffer afterwards to reuse the key already loaded.
#include <emscripten/bind.h>
#include <emscripten/version.h>

#include <chrono>
#include <memory>
#include <string>

#include <libff/common/profiling.hpp>

#include "core/prover.hpp"
#include "core/toy_circuit.hpp"

using namespace zk;

namespace {

template <class F>
std::string guarded(F&& f) {
    try {
        init_snark();
        return f().dump();
    } catch (const ProveError& e) {
        return json{{"error", e.what()}, {"kind", "statement"}}.dump();
    } catch (const std::exception& e) {
        return json{{"error", e.what()}, {"kind", "input"}}.dump();
    }
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

std::unique_ptr<ProvingKey>& cached_pk() {
    static std::unique_ptr<ProvingKey> pk;
    return pk;
}

std::string prove(const std::string& pk_bytes, const std::string& credential_json,
                  const std::string& path_json, const std::string& public_json) {
    return guarded([&] {
        double load_ms = 0;
        if (!pk_bytes.empty()) {
            const auto t0 = std::chrono::steady_clock::now();
            cached_pk().reset(); // free the old key before parsing the new one
            cached_pk() = std::make_unique<ProvingKey>(deserialize<ProvingKey>(pk_bytes));
            load_ms = ms_since(t0);
        }
        if (!cached_pk()) throw FormatError("no proving key loaded: pass pk_bytes on the first call");

        const ProveRequest req = prove_request_from_json(
            json::parse(credential_json), json::parse(path_json), json::parse(public_json));
        json out = prove_result_to_json(prove_login(*cached_pk(), req));
        out["timings"]["pk_load_ms"] = load_ms;
        return out;
    });
}

// Diagnostic: does the witness computed here satisfy (a) the constraint system
// this module generates and (b) the one shipped in the proving key?
std::string debug_witness(const std::string& pk_bytes, const std::string& credential_json,
                          const std::string& path_json, const std::string& public_json) {
    return guarded([&] {
        auto pk = deserialize<ProvingKey>(pk_bytes);
        const ProveRequest req = prove_request_from_json(
            json::parse(credential_json), json::parse(path_json), json::parse(public_json));
        ZkAuthCircuit c;
        c.generate_witness(req.cred, req.path, req.site_id, req.age_cutoff, req.nonce);
        const auto& own = c.pb().get_constraint_system();
        const auto& shipped = pk.constraint_system;
        const auto primary = c.pb().primary_input();
        const auto aux = c.pb().auxiliary_input();
        long first_bad = -1;
        libsnark::r1cs_variable_assignment<Fr> full = primary;
        full.insert(full.end(), aux.begin(), aux.end());
        for (std::size_t i = 0; i < shipped.constraints.size(); ++i) {
            const auto& con = shipped.constraints[i];
            if (con.a.evaluate(full) * con.b.evaluate(full) != con.c.evaluate(full)) { first_bad = long(i); break; }
        }
        long first_diff = -1;
        for (std::size_t i = 0; i < own.constraints.size() && i < shipped.constraints.size(); ++i) {
            const auto& x = own.constraints[i];
            const auto& y = shipped.constraints[i];
            if (!((x.a == y.a && x.b == y.b) || (x.a == y.b && x.b == y.a)) || !(x.c == y.c)) { first_diff = long(i); break; }
        }
        return json{{"own_satisfied", own.is_satisfied(primary, aux)},
                    {"shipped_satisfied", shipped.is_satisfied(primary, aux)},
                    {"own_constraints", own.num_constraints()}, {"shipped_constraints", shipped.num_constraints()},
                    {"own_vars", own.num_variables()}, {"shipped_vars", shipped.num_variables()},
                    {"first_unsatisfied_shipped", first_bad}, {"first_differing_constraint", first_diff}};
    });
}

std::string debug_parts(const std::string& pk_bytes, const std::string& credential_json,
                        const std::string& path_json, const std::string& public_json) {
    return guarded([&] {
        auto pk = deserialize<ProvingKey>(pk_bytes);
        return debug_prover_parts(pk, prove_request_from_json(json::parse(credential_json), json::parse(path_json),
                                                              json::parse(public_json)));
    });
}

std::string debug_arith_js(const std::string& scalars_json) {
    return guarded([&] { return debug_arith(json::parse(scalars_json)); });
}

// Diagnostic: turn libff's per-phase timing output (printed to the console) on/off.
void set_profiling(bool on) {
    init_snark();
    libff::inhibit_profiling_info = !on;
    libff::inhibit_profiling_counters = !on;
}

std::string compute_nullifier(const std::string& secret_hex, const std::string& site_id_hex) {
    return guarded([&] {
        return json{{"nullifier", to_hex(nullifier_of(digest_from_hex(secret_hex), digest_from_hex(site_id_hex)))}};
    });
}

// M1 risk spike, kept as a smoke test of the toolchain.
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
                    {"tree_depth", kTreeDepth},
                    {"limb_bits", GMP_NUMB_BITS},
                    {"emscripten", std::to_string(__EMSCRIPTEN_major__) + "." +
                                       std::to_string(__EMSCRIPTEN_minor__) + "." +
                                       std::to_string(__EMSCRIPTEN_tiny__)}};
    });
}

} // namespace

EMSCRIPTEN_BINDINGS(zkauth_prover) {
    emscripten::function("prove", &prove);
    emscripten::function("compute_nullifier", &compute_nullifier);
    emscripten::function("version", &version);
    emscripten::function("toyProve", &toy_prove);
    emscripten::function("debug_witness", &debug_witness);
    emscripten::function("debug_parts", &debug_parts);
    emscripten::function("debug_arith", &debug_arith_js);
    emscripten::function("set_profiling", &set_profiling);
}
