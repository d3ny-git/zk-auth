// Drives one full login against a running deployment (e.g. docker compose):
//   node tests/e2e/demo-login.mjs [http://localhost:8080] [demo/cred.json] [demo/path.json]
// With FRAMES=dir it also saves a screenshot after every step (used to make
// docs/img/demo.gif). Uses the mock EIP-1193 wallet; with a real browser you
// would click through the same steps with MetaMask.
import { mkdirSync } from 'node:fs';
import { installMockWallet, launchBrowser } from './lib.mjs';

const [base = 'http://localhost:8080', cred = 'demo/cred.json', path = 'demo/path.json'] = process.argv.slice(2);
const frames = process.env.FRAMES;
if (frames) mkdirSync(frames, { recursive: true });
const browser = await launchBrowser();
let shot = 0;
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 900, height: 1000 });
  const wallet = await installMockWallet(page);
  const snap = async (n) => {
    if (!frames) return;
    await page.$eval(`#step-${n}`, (el) => el.scrollIntoView({ block: 'center' }));
    await page.screenshot({ path: `${frames}/${String(shot++).padStart(2, '0')}.png` });
  };
  await page.goto(base);
  await (await page.$('#cred-file')).uploadFile(cred);
  await (await page.$('#path-file')).uploadFile(path);
  for (const [btn, n] of [['#load-btn', 1], ['#wallet-btn', 2], ['#nonce-btn', 3], ['#prove-btn', 4], ['#sign-btn', 5], ['#login-btn', 6]]) {
    await page.click(btn);
    if (n === 4) await snap(4); // "proving…"
    await page.waitForFunction((k) => ['done', 'error'].includes(document.getElementById(`step-${k}`).dataset.state),
      { timeout: 900_000, polling: 250 }, n);
    const st = await page.$eval(`#step-${n}`, (e) => e.dataset.state);
    if (st !== 'done') throw new Error(`step ${n} failed: ${await page.$eval(`#out-${n}`, (e) => e.textContent)}`);
    await snap(n);
  }
  await snap(7);
  const s = await page.evaluate(() => ({ session: window.__zk.session, pii: window.__zk.piiChecks, t: window.__zk.lastProof.timings }));
  if (frames) {
    await page.click('#attack-replay');
    await page.waitForFunction(() => document.getElementById('badge-replay').dataset.state === 'done', { timeout: 60_000 });
    await page.$eval('#attack-lab', (el) => el.scrollIntoView({ block: 'center' }));
    await page.screenshot({ path: `${frames}/${String(shot++).padStart(2, '0')}.png` });
  }
  const ok = s.session.login.address === wallet.address && s.session.me.sub === wallet.address && s.pii.every(([, v]) => v);
  console.log(JSON.stringify({ base, loggedInAs: s.session.login.address, me: s.session.me, proveMs: Math.round(s.t.prove_ms),
    piiChecks: s.pii.map(([w, v]) => `${v ? 'ok' : 'FAIL'}: ${w}`) }, null, 2));
  process.exitCode = ok ? 0 : 1;
} finally {
  await browser.close();
}
