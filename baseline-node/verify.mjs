// Groth16 verification for the baseline: snarkjs's own algorithm
// (src/groth16_verify.js: one multi-pairing e(-A,B)·e(L,γ)·e(C,δ)·e(α,β) == 1)
// with the curve built ONCE and the verification key parsed ONCE, instead of
// per request. `snarkjsVerify` is the unmodified library call, kept for the
// micro-benchmark comparison.
import { buildBn128, Scalar } from 'ffjavascript';
import * as snarkjs from 'snarkjs';

export async function makeVerifier(snarkVk, { singleThread = true } = {}) {
  // singleThread: an 8-point multi-exponentiation is far too small to be
  // worth shipping to ffjavascript's worker threads.
  const curve = await buildBn128(singleThread);
  const G1 = curve.G1, G2 = curve.G2;
  const toBig = (a) => a.map((v) => (Array.isArray(v) ? toBig(v) : BigInt(v)));
  const IC0 = G1.fromObject(toBig(snarkVk.IC[0]));
  const n = snarkVk.IC.length - 1;
  const IC = new Uint8Array(G1.F.n8 * 2 * n);
  for (let i = 0; i < n; i++) IC.set(G1.fromObject(toBig(snarkVk.IC[i + 1])), i * G1.F.n8 * 2);
  const gamma = G2.fromObject(toBig(snarkVk.vk_gamma_2)), delta = G2.fromObject(toBig(snarkVk.vk_delta_2));
  const alpha = G1.fromObject(toBig(snarkVk.vk_alpha_1)), beta = G2.fromObject(toBig(snarkVk.vk_beta_2));

  return async function verify(proof, publicSignals) {
    if (publicSignals.length !== n) return false;
    const w = new Uint8Array(curve.Fr.n8 * n);
    for (let i = 0; i < n; i++) {
      const s = BigInt(publicSignals[i]);
      if (s >= curve.r) return false;
      Scalar.toRprLE(w, curve.Fr.n8 * i, s, curve.Fr.n8);
    }
    const cpub = G1.add(await G1.multiExpAffine(IC, w), IC0);
    const a = G1.fromObject(toBig(proof.pi_a)), b = G2.fromObject(toBig(proof.pi_b)), c = G1.fromObject(toBig(proof.pi_c));
    if (!G1.isValid(a) || !G2.isValid(b) || !G1.isValid(c)) return false;
    return curve.pairingEq(G1.neg(a), b, cpub, gamma, c, delta, alpha, beta);
  };
}

export const snarkjsVerify = (vk, publicSignals, proof) => snarkjs.groth16.verify(vk, publicSignals, proof);
