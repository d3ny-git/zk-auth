// Node micro-benchmarks: per-operation timings (process.hrtime) after a
// warm-up, reported as p50 / p99 / mean in microseconds.
//   node microbench.mjs <fixtures dir> <verification_key.json> > micro_node.json
import { readFileSync } from 'node:fs';
import { verifyMessage } from 'ethers';
import { convertProof, convertPublic, validateProofBody } from './convert.mjs';
import { makeVerifier, snarkjsVerify } from './verify.mjs';

const [dir, vkPath] = process.argv.slice(2);
const vk = JSON.parse(readFileSync(vkPath, 'utf8'));
const proofs = JSON.parse(readFileSync(`${dir}/proofs.json`, 'utf8')).filter((e) => e.valid).map((e) => e.body);
const sigs = JSON.parse(readFileSync(`${dir}/sigs.json`, 'utf8')).filter((e) => e.valid).map((e) => e.body);
const converted = proofs.map((b) => [convertProof(b.proof), convertPublic(b.public)]);

async function bench(name, n, op) {
  for (let i = 0; i < Math.min(50, n); i++) await op(i); // warm-up (JIT, caches)
  const t = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    const ok = await op(i);
    t.push(Number(process.hrtime.bigint() - t0) / 1000);
    if (ok === false) throw new Error(`${name}: valid input rejected`);
  }
  t.sort((a, b) => a - b);
  const r = { n, p50_us: t[Math.floor(0.5 * (n - 1))], p99_us: t[Math.floor(0.99 * (n - 1))], mean_us: t.reduce((a, b) => a + b, 0) / n };
  console.error(`${name.padEnd(36)} p50 ${r.p50_us.toFixed(1).padStart(9)} µs   p99 ${r.p99_us.toFixed(1).padStart(9)} µs`);
  return [name, r];
}

const verify = await makeVerifier(vk);
const results = Object.fromEntries([
  await bench('groth16_verify/cached_curve', 1000, (i) => verify(...converted[i % converted.length])),
  await bench('groth16_verify/snarkjs_default', 300, (i) => snarkjsVerify(vk, converted[i % converted.length][1], converted[i % converted.length][0])),
  await bench('endpoint/verify_proof', 1000, (i) => {
    const b = structuredClone(proofs[i % proofs.length]); // what the handler receives after JSON parsing
    validateProofBody(b);
    return verify(convertProof(b.proof), convertPublic(b.public));
  }),
  await bench('ecrecover/ethers_verifyMessage', 3000, (i) => {
    const s = sigs[i % sigs.length];
    return verifyMessage(s.message, s.signature) === s.address;
  }),
]);
console.log(JSON.stringify({ node: process.version, ...results }, null, 2));
process.exit(0);
