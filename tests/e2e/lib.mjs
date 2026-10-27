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
