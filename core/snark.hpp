// Type aliases for the one proof system Zk-Auth uses: Groth16 over alt_bn128
// (BN254), as implemented by libsnark's r1cs_gg_ppzksnark.
#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace zk {

using ppT = libff::alt_bn128_pp;
using Fr  = libff::Fr<ppT>;           // scalar field: circuit values live here
using Fq  = libff::alt_bn128_Fq;      // base field: curve coordinates live here
using Fq2 = libff::alt_bn128_Fq2;
using G1  = libff::G1<ppT>;
using G2  = libff::G2<ppT>;

using ProvingKey            = libsnark::r1cs_gg_ppzksnark_proving_key<ppT>;
using VerificationKey       = libsnark::r1cs_gg_ppzksnark_verification_key<ppT>;
using ProcessedVerificationKey = libsnark::r1cs_gg_ppzksnark_processed_verification_key<ppT>;
using Proof                 = libsnark::r1cs_gg_ppzksnark_proof<ppT>;
using Keypair               = libsnark::r1cs_gg_ppzksnark_keypair<ppT>;
using PrimaryInput          = libsnark::r1cs_primary_input<Fr>;

// Initialises the curve constants and silences libff's profiling output.
// Must run once, before any other libff call and before any threads start:
// libff keeps the curve parameters (and its profiling tables) in globals.
void init_snark();

} // namespace zk
