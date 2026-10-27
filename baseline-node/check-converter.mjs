// Validates the libsnark -> snarkjs conversion end to end: the first 100
// valid and 100 tampered fixture proofs must get the same verdict from both
// servers (and the expected one).
//   CPP=http://127.0.0.1:8081 NODE=http://127.0.0.1:8082 node check-converter.mjs <fixtures dir>
import { readFileSync } from 'node:fs';

const fixtures = JSON.parse(readFileSync(`${process.argv[2]}/proofs.json`, 'utf8'));
const pick = [...fixtures.filter((e) => e.valid).slice(0, 100), ...fixtures.filter((e) => !e.valid).slice(0, 100)];
const ask = async (base, body) => {
  const r = await fetch(`${base}/verify-proof`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return r.status === 200 ? (await r.json()).valid : `HTTP ${r.status}`;
};
const tally = { valid: { cpp: 0, node: 0 }, tampered: { cpp: 0, node: 0 } };
let disagreements = 0;
for (const e of pick) {
  const [c, n] = await Promise.all([ask(process.env.CPP, e.body), ask(process.env.NODE, e.body)]);
  const kind = e.valid ? 'valid' : 'tampered';
  tally[kind].cpp += c === e.valid;
  tally[kind].node += n === e.valid;
  if (c !== n || c !== e.valid) disagreements++;
}
console.log(JSON.stringify({ checked: pick.length, correct: tally, disagreements }));
process.exit(disagreements ? 1 : 0);
