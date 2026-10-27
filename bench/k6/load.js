// k6 load test for /verify-proof and /verify-sig.
//   ENDPOINT=verify-proof|verify-sig URL=http://127.0.0.1:8081 VUS=8 DURATION=10s OUT=/out/x.json
// Each VU posts fixture bodies round-robin (10% are invalid on purpose) and
// checks the server's verdict, so a fast-but-wrong server would show up as
// failed checks rather than as a better number.
import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';

const ENDPOINT = __ENV.ENDPOINT;
const FILE = ENDPOINT === 'verify-proof' ? '/fixtures/proofs.json' : '/fixtures/sigs.json';
const fixtures = new SharedArray('fixtures', () =>
  JSON.parse(open(FILE)).map((e) => ({ body: JSON.stringify(e.body), valid: e.valid })));

export const options = {
  scenarios: { load: { executor: 'constant-vus', vus: Number(__ENV.VUS), duration: __ENV.DURATION || '10s' } },
  summaryTrendStats: ['avg', 'med', 'p(99)', 'max'],
};

export default function () {
  const f = fixtures[((__VU - 1) * 7919 + __ITER) % fixtures.length];
  const r = http.post(`${__ENV.URL}/${ENDPOINT}`, f.body, { headers: { 'Content-Type': 'application/json' } });
  check(r, { 'correct verdict': (x) => x.status === 200 && x.json('valid') === f.valid });
}

export function handleSummary(data) {
  return { [__ENV.OUT]: JSON.stringify(data) };
}
