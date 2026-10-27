// Shared helpers for the headless-browser checks.
import { createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import puppeteer from 'puppeteer-core';
import { Wallet } from 'ethers';

export const repoRoot = new URL('../..', import.meta.url).pathname;

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm',
  '.bin': 'application/octet-stream',
};

// Static file server rooted at the repo (test use only). Requests to /api/*
// go to `api`: either a function (req, res, body) => void (a stub), or a
// base URL to proxy to (the real Crow server).
export function startStatic({ root = repoRoot, api } = {}) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/') && api) {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = Buffer.concat(chunks);
      if (typeof api === 'function') return api(req, res, body, url.pathname.slice(4));
      const target = new URL(url.pathname.slice(4) + url.search, api);
      const p = httpRequest(target, { method: req.method, headers: { ...req.headers, host: target.host } }, (r) => {
        res.writeHead(r.statusCode, r.headers);
        r.pipe(res);
      });
      p.on('error', () => res.writeHead(502).end());
      p.end(body);
      return;
    }
    const path = normalize(decodeURIComponent(url.pathname));
    if (path.includes('..')) { res.writeHead(403).end(); return; }
    try {
      const body = await readFile(join(root, path));
      res.writeHead(200, { 'content-type': MIME[extname(path)] ?? 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () =>
    resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

// Stand-in for GET /nonce until the Crow server exists (M4 only).
export function stubNonce(host) {
  const today = Math.floor(Date.now() / 86_400_000);
  const d = new Date(today * 86_400_000);
  d.setUTCFullYear(d.getUTCFullYear() - 18);
  const cutoff = Math.floor(d.getTime() / 86_400_000);
  return {
    nonce: createHash('sha256').update(String(Math.random())).digest('hex').slice(0, 32),
    age_cutoff: cutoff.toString(16).padStart(8, '0'),
    site_id: createHash('sha256').update(`zk-auth:${host}`).digest('hex'),
    issued_at: new Date().toISOString(),
  };
}

export function launchBrowser() {
  return puppeteer.launch({
    executablePath: process.env.CHROME ?? '/usr/bin/chromium',
    headless: true,
    args: ['--no-sandbox'],
    protocolTimeout: 900_000,
  });
}

// Installs an EIP-1193 provider as window.ethereum, backed by an ethers
// Wallet held in Node. Real MetaMask cannot run headless; this mock speaks
// the same RPC methods the page uses (eth_requestAccounts, eth_chainId,
// personal_sign) and signs exactly like MetaMask's personal_sign (EIP-191).
export async function installMockWallet(page, wallet = Wallet.createRandom(), chainId = 1) {
  await page.exposeFunction('__mockWalletRpc', async (method, params) => {
    switch (method) {
      case 'eth_requestAccounts':
      case 'eth_accounts': return [wallet.address];
      case 'eth_chainId': return `0x${chainId.toString(16)}`;
      case 'personal_sign': {
        const [hexMessage] = params;
        return wallet.signMessage(Buffer.from(hexMessage.slice(2), 'hex'));
      }
      default: throw new Error(`mock wallet: unsupported ${method}`);
    }
  });
  await page.evaluateOnNewDocument(() => {
    window.ethereum = {
      isMetaMask: false,
      request: ({ method, params }) => window.__mockWalletRpc(method, params ?? []),
    };
  });
  return wallet;
}

// Runs the native tools from build/native-release.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer as createNetServer } from 'node:net';

const tools = `${repoRoot}build/native-release`;
export const runTool = (bin, args) => execFileSync(`${tools}/tools/${bin}`, args, { encoding: 'utf8' });

// A fresh issuer state with 20 dummies and one real credential.
export function freshIssuer(dob = '2001-05-14') {
  const dir = mkdtempSync(join(tmpdir(), 'zk-issuer-'));
  runTool('zkauth-issuer', ['init', '--state', dir, '--dummies', '20']);
  runTool('zkauth-issuer', ['new', '--state', dir, '--dob', dob, '--out', `${dir}/cred.json`]);
  runTool('zkauth-issuer', ['root', '--state', dir]);
  runTool('zkauth-issuer', ['path', '--state', dir, '--index', '20', '--out', `${dir}/path.json`]);
  return dir;
}

export function freePort() {
  return new Promise((resolve) => {
    const s = createNetServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// Starts zkauth-server and resolves once /health answers.
export async function startServer({ port, domain, uri, roots, mode = 'development', extra = [] }) {
  const dir = mkdtempSync(join(tmpdir(), 'zk-server-'));
  const proc = spawn(`${tools}/server/zkauth-server`, [
    '--port', String(port), '--bind', '127.0.0.1', '--domain', domain, '--uri', uri,
    '--vk', `${repoRoot}keys/vk.bin`, '--roots', roots, '--session-key', `${dir}/session.pem`,
    '--mode', mode, ...extra,
  ], { stdio: ['ignore', 'inherit', 'pipe'] });
  const log = [];
  proc.stderr.on('data', (d) => log.push(String(d)));
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return { proc, log, stop: () => proc.kill() }; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  proc.kill();
  throw new Error(`zkauth-server did not start:\n${log.join('')}`);
}
