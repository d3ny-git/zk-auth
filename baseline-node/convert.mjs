// Converts Zk-Auth / libsnark JSON (hex, affine points) to snarkjs JSON
// (decimal strings, projective with z = 1), and re-implements the server's
// public-input packing so the baseline validates requests exactly like the
// C++ server.
//
//   node convert.mjs keys/vk.json > verification_key.json
import { readFileSync } from 'node:fs';

const dec = (hex) => BigInt('0x' + hex).toString();
const g1 = (p) => [dec(p.x), dec(p.y), '1'];
const g2 = (p) => [[dec(p.x[0]), dec(p.x[1])], [dec(p.y[0]), dec(p.y[1])], ['1', '0']]; // [c0, c1]

// libsnark's vk keeps only e(alpha, beta); zkauth-setup exports alpha_g1 and
// beta_g2 from the proving key into vk.json for exactly this conversion.
export function convertVk(vk) {
  return {
    protocol: 'groth16', curve: 'bn128', nPublic: vk.n_public,
    vk_alpha_1: g1(vk.alpha_g1), vk_beta_2: g2(vk.beta_g2),
    vk_gamma_2: g2(vk.gamma_g2), vk_delta_2: g2(vk.delta_g2),
    IC: vk.ic.map(g1),
  };
}

export const convertProof = (p) => ({ protocol: 'groth16', curve: 'bn128', pi_a: g1(p.a), pi_b: g2(p.b), pi_c: g1(p.c) });
export const convertPublic = (pub) => pub.packed.map(dec);

// --- strict request validation (mirrors core/formats.cpp) -------------------
const hex = (n) => new RegExp(`^[0-9a-f]{${2 * n}}$`);
const H32 = hex(32), H16 = hex(16), H4 = hex(4);
const Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
const R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const exactKeys = (o, keys) => o && typeof o === 'object' && !Array.isArray(o) &&
  Object.keys(o).length === keys.length && keys.every((k) => k in o);
const fq = (h) => typeof h === 'string' && H32.test(h) && BigInt('0x' + h) < Q;
const g1ok = (p) => exactKeys(p, ['x', 'y']) && fq(p.x) && fq(p.y);
const g2ok = (p) => exactKeys(p, ['x', 'y']) && [p.x, p.y].every((c) => Array.isArray(c) && c.length === 2 && c.every(fq));

// Bits of a digest, most significant first, packed 253 per element with
// bit j of a chunk weighted 2^j (libsnark multipacking).
function packDigest(h) {
  const bits = [];
  for (let i = 0; i < 64; i += 2) { const b = parseInt(h.slice(i, i + 2), 16); for (let k = 7; k >= 0; k--) bits.push((b >> k) & 1); }
  const out = [];
  for (let c = 0; c < bits.length; c += 253) {
    let v = 0n;
    for (let j = 0; j < 253 && c + j < bits.length; j++) if (bits[c + j]) v |= 1n << BigInt(j);
    out.push(v);
  }
  return out;
}
export function packPublic(pub) {
  return [...packDigest(pub.merkle_root), ...packDigest(pub.nullifier), ...packDigest(pub.site_id),
    BigInt('0x' + pub.age_cutoff), BigInt('0x' + pub.nonce)];
}

// Throws on anything the C++ server would reject while parsing.
export function validateProofBody(body) {
  if (!exactKeys(body, ['proof', 'public'])) throw new Error('shape');
  const { proof, public: pub } = body;
  if (!exactKeys(proof, ['a', 'b', 'c']) || !g1ok(proof.a) || !g2ok(proof.b) || !g1ok(proof.c)) throw new Error('proof');
  if (!exactKeys(pub, ['merkle_root', 'nullifier', 'site_id', 'age_cutoff', 'nonce', 'packed'])) throw new Error('public');
  if (![pub.merkle_root, pub.nullifier, pub.site_id].every((h) => typeof h === 'string' && H32.test(h)) ||
      !H4.test(pub.age_cutoff) || !H16.test(pub.nonce)) throw new Error('public hex');
  if (!Array.isArray(pub.packed) || pub.packed.length !== 8) throw new Error('packed');
  const want = packPublic(pub);
  pub.packed.forEach((h, i) => {
    if (typeof h !== 'string' || !H32.test(h) || BigInt('0x' + h) >= R || BigInt('0x' + h) !== want[i]) throw new Error('packed mismatch');
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.stdout.write(JSON.stringify(convertVk(JSON.parse(readFileSync(process.argv[2], 'utf8'))), null, 2) + '\n');
}
