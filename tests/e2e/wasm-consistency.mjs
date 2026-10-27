// Cross-platform consistency of the WebAssembly prover (wasm32, 32-bit limbs)
// with the native build (x86-64, 64-bit limbs). Guards against the classes of
// bug found in M4 (docs/build-notes.md, patches libsnark-0002, libff-0002,
// libff-0003):
//   1. field fast paths vs an independent GMP mpz reference,
//   2. the circuit generated in wasm == the constraint system in pk.bin,
//   3. proofs for random nonces made in wasm verify with the native verifier.
// Needs keys/ (zkauth-setup) and build/native-release/tools/zkauth-issuer|prove.
import { execFileSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { repoRoot } from './lib.mjs';

const N = Number(process.env.PROOFS ?? 4);
const tools = `${repoRoot}build/native-release/tools`;
const dir = mkdtempSync(join(tmpdir(), 'zk-wasm-'));
const run = (bin, args) => execFileSync(`${tools}/${bin}`, args, { encoding: 'utf8' });
let failures = 0;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failures++; };

// Fresh issuer state with one real credential.
run('zkauth-issuer', ['init', '--state', dir, '--dummies', '20']);
run('zkauth-issuer', ['new', '--state', dir, '--dob', '1999-12-31', '--out', `${dir}/cred.json`]);
run('zkauth-issuer', ['root', '--state', dir]);
run('zkauth-issuer', ['path', '--state', dir, '--index', '20', '--out', `${dir}/path.json`]);
const cred = readFileSync(`${dir}/cred.json`, 'utf8');
const path = readFileSync(`${dir}/path.json`, 'utf8');

const { default: createProver } = await import(`${repoRoot}client/wasm/zkauth_prover.mjs`);
const prover = await createProver();
const pk = new Uint8Array(readFileSync(`${repoRoot}keys/pk.bin`));

const st = JSON.parse(prover.selftest_field(100_000));
check(st.Fr_mismatches === 0 && st.Fq_mismatches === 0, `field arithmetic vs mpz reference (${st.iterations} x 3 ops x 2 fields)`);

const server = (nonce) => JSON.stringify({
  nonce, age_cutoff: '00003763', site_id: createHash('sha256').update('zk-auth:consistency').digest('hex'),
});
const w = JSON.parse(prover.debug_witness(pk, cred, path, server(randomBytes(16).toString('hex'))));
check(w.first_differing_constraint === -1 && w.shipped_satisfied,
  `wasm circuit == pk.bin constraint system (${w.own_constraints} constraints)`);

let key = pk;
for (let i = 0; i < N; i++) {
  const nonce = randomBytes(16).toString('hex');
  const t0 = performance.now();
  const out = JSON.parse(prover.prove(key, cred, path, server(nonce)));
  key = new Uint8Array(0);
  if (out.error) { check(false, `prove: ${out.error}`); continue; }
  const file = `${dir}/proof-${i}.json`;
  writeFileSync(file, JSON.stringify({ proof: out.proof, public: out.public }));
  let verdict;
  try { verdict = run('zkauth-prove', ['verify', '--vk', `${repoRoot}keys/vk.bin`, '--in', file]).trim(); }
  catch (e) { verdict = String(e.stdout).trim(); }
  check(verdict.startsWith('VALID'), `wasm proof ${i} (nonce ${nonce}, ${((performance.now() - t0) / 1000).toFixed(1)} s) -> native verifier: ${verdict}`);
}
process.exit(failures ? 1 : 0);
