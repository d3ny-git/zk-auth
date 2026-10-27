// Shared helpers for the headless-browser checks.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import puppeteer from 'puppeteer-core';

export const repoRoot = new URL('../..', import.meta.url).pathname;

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm',
  '.bin': 'application/octet-stream',
};

// Minimal static file server rooted at `root` (test use only).
export function startStatic(root = repoRoot) {
  const server = createServer(async (req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname));
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

export function launchBrowser() {
  return puppeteer.launch({
    executablePath: process.env.CHROME ?? '/usr/bin/chromium',
    headless: true,
    args: ['--no-sandbox'],
  });
}
