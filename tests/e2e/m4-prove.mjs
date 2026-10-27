// M4 acceptance: a proof for a real issued credential (data/cred.json +
// data/path.json) is made in a Chrome Web Worker by the WebAssembly prover,
// then verified natively:
//   zkauth-prove verify --vk keys/vk.bin --in build/m4/browser_proof.json
import { mkdirSync, writeFileSync } from 'node:fs';
import { installMockWallet, launchBrowser, repoRoot, startStatic, stubNonce } from './lib.mjs';

const srv = await startStatic({
  api: (req, res, body, path) => {
    if (path === '/nonce') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(stubNonce(req.headers.host)));
    } else res.writeHead(404).end();
  },
});
const browser = await launchBrowser();
try {
  const page = await browser.newPage();
  page.on('console', (m) => console.log('[page]', m.text()));
  await installMockWallet(page);
  await page.goto(`${srv.url}/client/index.html`);

  const upload = async (sel, file) => (await page.$(sel)).uploadFile(`${repoRoot}${file}`);
  await upload('#cred-file', 'data/cred.json');
  await upload('#path-file', 'data/path.json');
  const step = async (btn, n) => {
    await page.click(btn);
    await page.waitForFunction((k) => ['done', 'error'].includes(document.getElementById(`step-${k}`).dataset.state),
      { timeout: 900_000, polling: 500 }, n);
    const st = await page.$eval(`#step-${n}`, (e) => e.dataset.state);
    if (st !== 'done') throw new Error(`step ${n}: ${await page.$eval(`#out-${n}`, (e) => e.textContent)}`);
  };
  await step('#load-btn', 1);
  await step('#wallet-btn', 2);
  await step('#nonce-btn', 3);

  const runs = [];
  for (const label of ['cold (download + parse + prove)', 'warm (key already in wasm memory)']) {
    await step('#nonce-btn', 3); // a fresh nonce for every proof
    await step('#prove-btn', 4);
    const r = await page.evaluate(() => window.__zk.lastProof);
    runs.push({ label, ...r.timings, key: r.key, worker: r.worker });
    if (runs.length === 1) {
      mkdirSync(`${repoRoot}build/m4`, { recursive: true });
      writeFileSync(`${repoRoot}build/m4/browser_proof.json`, JSON.stringify({ proof: r.proof, public: r.public }, null, 2));
    }
  }
  // Reload: the worker restarts, so the key comes from the Cache API this time.
  await page.reload();
  await upload('#cred-file', 'data/cred.json');
  await upload('#path-file', 'data/path.json');
  await step('#load-btn', 1);
  await step('#wallet-btn', 2);
  await step('#nonce-btn', 3);
  await step('#prove-btn', 4);
  const r = await page.evaluate(() => window.__zk.lastProof);
  runs.push({ label: 'after reload (key from Cache API)', ...r.timings, key: r.key, worker: r.worker });

  console.log(JSON.stringify({ browser: await browser.version(), runs }, null, 2));
  writeFileSync(`${repoRoot}build/m4/browser_timings.json`, JSON.stringify(runs, null, 2));
} finally {
  await browser.close();
  srv.close();
}
