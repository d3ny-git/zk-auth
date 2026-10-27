// One Groth16 keypair for ZkAuthCircuit, shared by every test process.
// catch_discover_tests runs each TEST_CASE in its own process, and a trusted
// setup takes ~15 s, so the first process to need keys writes them under the
// build tree (ZK_TEST_CACHE_DIR) and later ones load them (~0.3 s).
#pragma once

#include <filesystem>

#include "core/circuit.hpp"
#include "core/formats.hpp"

namespace zk::test {

inline const Keypair& cached_keypair() {
    static const Keypair kp = [] {
        namespace fs = std::filesystem;
        const fs::path dir = ZK_TEST_CACHE_DIR;
        const fs::path pk = dir / "pk.bin", vk = dir / "vk.bin";
        if (fs::exists(pk) && fs::exists(vk))
            return Keypair(deserialize<ProvingKey>(read_file(pk.string())), deserialize<VerificationKey>(read_file(vk.string())));
        ZkAuthCircuit c;
        Keypair fresh = libsnark::r1cs_gg_ppzksnark_generator<ppT>(c.pb().get_constraint_system());
        fs::create_directories(dir);
        // Write-then-rename: a concurrent reader never sees half a file.
        const auto tmp_pk = pk.string() + ".tmp", tmp_vk = vk.string() + ".tmp";
        write_file(tmp_pk, serialize(fresh.pk));
        write_file(tmp_vk, serialize(fresh.vk));
        fs::rename(tmp_vk, vk);
        fs::rename(tmp_pk, pk);
        return fresh;
    }();
    return kp;
}

} // namespace zk::test
