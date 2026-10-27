// M7: every attack-lab button against the real server (development mode, so
// the X-ZkAuth-Reject header names the check that caught it).
import { freePort, freshIssuer, installMockWallet, launchBrowser, startServer, startStatic } from './lib.mjs';

const issuer = freshIssuer('1990-01-01');
const apiPort = await freePort();
const srv = await startStatic({ api: `http://127.0.0.1:${apiPort}` });
const server = await startServer({ port: apiPort, domain: new URL(srv.url).host, uri: srv.url, roots: `${issuer}/roots.json` });
const browser = await launchBrowser();
let failures = 0;
try {
  const page = await browser.newPage();
  await installMockWallet(page);
  await page.goto(`${srv.url}/client/index.html`);
  await (await page.$('#cred-file')).uploadFile(`${issuer}/cred.json`);
  await (await page.$('#path-file')).uploadFile(`${issuer}/path.json`);
  for (const [btn, n] of [['#load-btn', 1], ['#wallet-btn', 2], ['#nonce-btn', 3], ['#prove-btn', 4], ['#sign-btn', 5], ['#login-btn', 6]]) {
    await page.click(btn);
    await page.waitForFunction((k) => ['done', 'error'].includes(document.getElementById(`step-${k}`).dataset.state),
      { timeout: 600_000, polling: 250 }, n);
  }
  const expected = { replay: 'nonce', nonce: 'groth16', site: 'site-id', flip: 'body', wallet: 'signature' };
  for (const [id, expect] of Object.entries(expected)) {
    await page.click(`#attack-${id}`);
    await page.waitForFunction((i) => document.getElementById(`badge-${i}`).dataset.state === 'done',
      { timeout: 600_000, polling: 250 }, id);
    const { text, check } = await page.$eval(`#badge-${id}`, (b) => ({ text: b.textContent, check: b.dataset.check }));
    const ok = check === expect;
    if (!ok) failures++;
    console.log(`${ok ? 'ok  ' : 'FAIL'} attack "${id}": ${text}`);
  }
  await page.screenshot({ path: `${process.env.SCREENSHOT_DIR ?? '/tmp'}/zk-auth-attack-lab.png`, fullPage: true });
} finally {
  await browser.close();
  srv.close();
  server.stop();
}
process.exit(failures ? 1 : 0);
