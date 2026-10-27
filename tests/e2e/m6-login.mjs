// M6 acceptance: the full browser login against the real Crow server, plus
// the PII-absence test: the exact bytes the client sends must not contain the
// credential secret, the date of birth (in any encoding) or the Merkle path.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { freePort, freshIssuer, installMockWallet, launchBrowser, startServer, startStatic } from './lib.mjs';

const issuer = freshIssuer('2001-05-14');
const cred = JSON.parse(readFileSync(`${issuer}/cred.json`, 'utf8'));
const apiPort = await freePort();
const srv = await startStatic({ api: `http://127.0.0.1:${apiPort}` });
const host = new URL(srv.url).host;
const server = await startServer({ port: apiPort, domain: host, uri: srv.url, roots: `${issuer}/roots.json` });
const browser = await launchBrowser();
let failures = 0;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) failures++; };

try {
  const page = await browser.newPage();
  page.on('console', (m) => { if (!m.text().includes('Failed to load resource')) console.log('[page]', m.text()); });
  const wallet = await installMockWallet(page);
  const requests = [];
  page.on('request', (r) => requests.push({ url: r.url(), method: r.method(), body: r.postData() ?? '' }));
  await page.goto(`${srv.url}/client/index.html`);

  await (await page.$('#cred-file')).uploadFile(`${issuer}/cred.json`);
  await (await page.$('#path-file')).uploadFile(`${issuer}/path.json`);
  const step = async (btn, n) => {
    await page.click(btn);
    await page.waitForFunction((k) => ['done', 'error'].includes(document.getElementById(`step-${k}`).dataset.state),
      { timeout: 600_000, polling: 250 }, n);
    const st = await page.$eval(`#step-${n}`, (e) => e.dataset.state);
    if (st !== 'done') throw new Error(`step ${n}: ${await page.$eval(`#out-${n}`, (e) => e.textContent)}`);
  };
  const t0 = Date.now();
  await step('#load-btn', 1);
  await step('#wallet-btn', 2);
  await step('#nonce-btn', 3);
  await step('#prove-btn', 4);
  await step('#sign-btn', 5);
  await step('#login-btn', 6);
  const session = await page.evaluate(() => window.__zk.session);
  const piiChecks = await page.evaluate(() => window.__zk.piiChecks);
  const timings = await page.evaluate(() => window.__zk.lastProof.timings);

  check(session.login.address === wallet.address, `logged in as the wallet address ${wallet.address}`);
  check(session.meStatus === 200 && session.me.sub === wallet.address, `GET /me with the token returns sub = ${session.me.sub}`);
  check(session.me.site === host && /^[0-9a-f]{16}$/.test(session.me.nul) && session.me.exp - session.me.iat === 900,
    `token payload: site=${session.me.site}, nul=${session.me.nul}, exp-iat=${session.me.exp - session.me.iat}`);
  for (const [what, ok] of piiChecks) check(ok, `step 7 (in page): ${what}`);

  // The PII-absence test proper, on the bytes captured at the network layer.
  const login = requests.find((r) => r.url.endsWith('/api/login'));
  assert.ok(login, 'POST /api/login captured');
  const body = JSON.parse(login.body);
  const keysDeep = (o) => (o && typeof o === 'object') ? Object.keys(o).flatMap((k) => [k, ...keysDeep(o[k])]) : [];
  check(JSON.stringify(Object.keys(body).sort()) === '["proof","public","signature","siwe_message"]',
    `login body has exactly proof, public, siwe_message, signature (${login.body.length} bytes)`);
  check(!keysDeep(body).some((k) => ['dob', 'secret', 'siblings', 'index', 'credential', 'path'].includes(k)),
    'no dob / secret / path field at any depth');
  const days = Math.round(Date.parse(`${cred.dob}T00:00:00Z`) / 86_400_000);
  const leaks = [cred.secret, cred.dob, days.toString(16).padStart(8, '0'), String(days)];
  for (const r of requests)
    check(!leaks.some((x) => r.url.includes(x) || r.body.includes(x)), `no secret or dob in ${r.method} ${new URL(r.url).pathname}`);

  // Replaying the identical request must fail (the nonce was consumed).
  const replay = await page.evaluate((b) => window.__zk.postLogin(b), login.body);
  check(replay.status === 401 && replay.rejectedBy === 'nonce', `replayed request rejected by check "${replay.rejectedBy}"`);

  console.log(`browser login: ${((Date.now() - t0) / 1000).toFixed(1)} s total; proving ${(timings.prove_ms / 1000).toFixed(1)} s`);
} finally {
  await browser.close();
  srv.close();
  server.stop();
}
process.exit(failures ? 1 : 0);
