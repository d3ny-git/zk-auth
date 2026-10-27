// M1 acceptance: a Groth16 proof of x^3 + x + 5 = 35 is produced by the
// WebAssembly prover inside a real browser Web Worker, then saved so the
// native verifier can check it (see the command printed at the end).
import { writeFileSync } from 'node:fs';
import { launchBrowser, repoRoot, startStatic } from './lib.mjs';

const srv = await startStatic();
const browser = await launchBrowser();
try {
  const page = await browser.newPage();
  page.on('console', (m) => console.log('[page]', m.text()));
  await page.goto(`${srv.url}/client/toy.html?auto`);
  const handle = await page.waitForFunction(() => window.__toyResult, { timeout: 120_000 });
  const result = await handle.jsonValue();
  if (result.error) throw new Error(result.error);
  const out = `${repoRoot}build/m1/browser_proof.json`;
  writeFileSync(out, JSON.stringify(result, null, 2));
  console.log(JSON.stringify({
    browser: await browser.version(), scope: result.scope, version: result.version,
    wasm_init_ms: result.wasm_init_ms, pk_load_ms: result.pk_load_ms, prove_ms: result.prove_ms,
  }, null, 2));
  console.log(`saved ${out}; check with: zkauth-toy verify build/m1 build/m1/browser_proof.json`);
} finally {
  await browser.close();
  srv.close();
}
