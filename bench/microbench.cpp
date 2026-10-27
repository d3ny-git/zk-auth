// Micro-benchmarks (Google Benchmark) for the C++ side.
//
//   zkauth-microbench --fixtures build/bench-fixtures --vk keys/vk.bin [benchmark flags]
//
// Each benchmark times ONE operation per repetition (Iterations(1)) and runs
// many repetitions, so the reported aggregates are per-operation percentiles:
// _p50 and _p99 (plus Google Benchmark's mean/median/stddev).
//
// Optimisation experiments (before / after):
//   groth16_verify/unprocessed_vk  vs  groth16_verify/processed_vk
//   ecrecover/fresh_contexts       vs  ecrecover/reused_contexts
#include <benchmark/benchmark.h>

#include <algorithm>
#include <filesystem>
#include <random>

#include "core/formats.hpp"
#include "server/eth_sig.hpp"
#include "server/routes.hpp"
#include "tools/cli.hpp"

using namespace zk;
namespace fs = std::filesystem;

namespace {

struct Fixtures {
    VerificationKey vk;
    ProcessedVerificationKey pvk;
    std::vector<std::pair<Proof, PublicInputs>> proofs;   // valid ones, parsed
    std::vector<std::string> proof_bodies;                // valid ones, as sent
    std::vector<std::pair<std::string, eth::Signature>> sigs;
    std::vector<std::string> sig_bodies;
    std::unique_ptr<server::AuthService> svc;
};
Fixtures* F = nullptr;

double percentile(const std::vector<double>& v, double q) {
    std::vector<double> s = v;
    std::sort(s.begin(), s.end());
    return s[static_cast<std::size_t>(q * double(s.size() - 1))];
}

void stats(benchmark::Benchmark* b, int reps) {
    b->Iterations(1)->Repetitions(reps)->UseRealTime()->Unit(benchmark::kMicrosecond)
        ->ComputeStatistics("p50", [](const std::vector<double>& v) { return percentile(v, 0.50); })
        ->ComputeStatistics("p99", [](const std::vector<double>& v) { return percentile(v, 0.99); })
        ->ReportAggregatesOnly(true);
}

std::size_t pick(std::size_t n) {
    static std::size_t i = 0;
    return i++ % n;
}

void groth16_processed(benchmark::State& st) {
    for (auto _ : st) {
        const auto& [proof, pub] = F->proofs[pick(F->proofs.size())];
        bool ok = libsnark::r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(F->pvk, pack_public_inputs(pub), proof);
        if (!ok) st.SkipWithError("valid proof rejected");
        benchmark::DoNotOptimize(ok);
    }
}

void groth16_unprocessed(benchmark::State& st) {
    for (auto _ : st) {
        const auto& [proof, pub] = F->proofs[pick(F->proofs.size())];
        // Processes the vk (G2 line precomputation for gamma, delta) on every call.
        bool ok = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(F->vk, pack_public_inputs(pub), proof);
        if (!ok) st.SkipWithError("valid proof rejected");
        benchmark::DoNotOptimize(ok);
    }
}

void proof_parse(benchmark::State& st) {
    for (auto _ : st) {
        const json j = json::parse(F->proof_bodies[pick(F->proof_bodies.size())]);
        benchmark::DoNotOptimize(proof_from_json(j.at("proof")));
        benchmark::DoNotOptimize(public_from_json(j.at("public")));
    }
}

void verify_proof_endpoint(benchmark::State& st) { // what POST /verify-proof does, minus HTTP
    for (auto _ : st) benchmark::DoNotOptimize(F->svc->verify_proof(F->proof_bodies[pick(F->proof_bodies.size())]));
}

void ecrecover_reused(benchmark::State& st) {
    static eth::Verifier v;
    for (auto _ : st) {
        const auto& [msg, sig] = F->sigs[pick(F->sigs.size())];
        benchmark::DoNotOptimize(v.recover_personal(msg, sig));
    }
}

void ecrecover_fresh(benchmark::State& st) {
    for (auto _ : st) {
        const auto& [msg, sig] = F->sigs[pick(F->sigs.size())];
        benchmark::DoNotOptimize(eth::recover_personal_fresh(msg, sig));
    }
}

void verify_sig_endpoint(benchmark::State& st) { // what POST /verify-sig does, minus HTTP
    for (auto _ : st) benchmark::DoNotOptimize(F->svc->verify_sig(F->sig_bodies[pick(F->sig_bodies.size())]));
}

} // namespace

BENCHMARK(groth16_processed)->Name("groth16_verify/processed_vk")->Apply([](auto* b) { stats(b, 1000); });
BENCHMARK(groth16_unprocessed)->Name("groth16_verify/unprocessed_vk")->Apply([](auto* b) { stats(b, 1000); });
BENCHMARK(proof_parse)->Name("proof_json_parse")->Apply([](auto* b) { stats(b, 1000); });
BENCHMARK(verify_proof_endpoint)->Name("endpoint/verify_proof")->Apply([](auto* b) { stats(b, 1000); });
BENCHMARK(ecrecover_reused)->Name("ecrecover/reused_contexts")->Apply([](auto* b) { stats(b, 3000); });
BENCHMARK(ecrecover_fresh)->Name("ecrecover/fresh_contexts")->Apply([](auto* b) { stats(b, 3000); });
BENCHMARK(verify_sig_endpoint)->Name("endpoint/verify_sig")->Apply([](auto* b) { stats(b, 3000); });

int main(int argc, char** argv) {
    // Our own flags first; the rest go to Google Benchmark.
    std::vector<char*> rest{argv[0]};
    std::string fixtures = "build/bench-fixtures", vk = "keys/vk.bin";
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (s == "--fixtures" && i + 1 < argc) fixtures = argv[++i];
        else if (s == "--vk" && i + 1 < argc) vk = argv[++i];
        else rest.push_back(argv[i]);
    }
    init_snark();
    Fixtures f;
    f.vk = deserialize<VerificationKey>(read_file(vk));
    f.pvk = libsnark::r1cs_gg_ppzksnark_verifier_process_vk<ppT>(f.vk);
    for (const auto& e : json::parse(read_file(fixtures + "/proofs.json"))) {
        if (!e["valid"].get<bool>()) continue;
        f.proofs.emplace_back(proof_from_json(e["body"]["proof"]), public_from_json(e["body"]["public"]));
        f.proof_bodies.push_back(e["body"].dump());
    }
    for (const auto& e : json::parse(read_file(fixtures + "/sigs.json"))) {
        if (!e["valid"].get<bool>()) continue;
        f.sigs.emplace_back(e["body"]["message"].get<std::string>(), *eth::parse_signature(e["body"]["signature"].get<std::string>()));
        f.sig_bodies.push_back(e["body"].dump());
    }
    server::Config cfg;
    cfg.domain = "bench.local";
    cfg.vk_path = vk;
    cfg.roots_path = fixtures + "/issuer/roots.json";
    cfg.session_key_path = (fs::temp_directory_path() / "zk-microbench-session.pem").string();
    f.svc = std::make_unique<server::AuthService>(cfg);
    F = &f;

    int n = static_cast<int>(rest.size());
    benchmark::Initialize(&n, rest.data());
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
