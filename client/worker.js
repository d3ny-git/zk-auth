// Web Worker that owns the WebAssembly prover. Proving takes seconds of pure
// computation; running it here keeps the page responsive.
//
// Messages in:  {type: 'prove', credential, path, server}   (JSON strings)
//               {type: 'nullifier', secret, siteId}
//               {type: 'checksum', address}          EIP-55 via OpenSSL KECCAK-256
// Messages out: {type: 'progress', phase, loaded, total}
//               {type: 'proved', result}   result = {proof, public, proof_hash, timings}
//               {type: 'error', message, kind}
import createProver from './wasm/zkauth_prover.mjs';

const KEY_BASE = new URL('../keys/', self.location.href); // pk.bin + manifest.json
const CACHE_NAME = 'zk-auth-proving-key';

const proverReady = createProver();
let keyLoaded = false; // the wasm module keeps the parsed key after the first prove()

const post = (msg) => self.postMessage(msg);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

// Download pk.bin once and keep it in the Cache API, keyed by its SHA-256 so
// a new trusted setup automatically invalidates the old copy.
async function provingKeyBytes() {
  const manifest = await (await fetch(new URL('manifest.json', KEY_BASE), { cache: 'no-cache' })).json();
  const url = new URL(`pk.bin?sha256=${manifest.pk_sha256}`, KEY_BASE).href;
  const cache = await caches.open(CACHE_NAME);
  let fromCache = true;
  let response = await cache.match(url);
  if (!response) {
    fromCache = false;
    const r = await fetch(url);
    if (!r.ok) throw new Error(`proving key download failed: HTTP ${r.status}`);
    const total = Number(r.headers.get('content-length')) || manifest.pk_bytes;
    const reader = r.body.getReader();
    const chunks = [];
    let loaded = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      loaded += value.length;
      post({ type: 'progress', phase: 'download', loaded, total });
    }
    const blob = new Blob(chunks);
    for (const old of await cache.keys()) await cache.delete(old); // drop keys of older setups
    await cache.put(url, new Response(blob));
    response = new Response(blob);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  // Integrity: a truncated download or a stale cache entry must not reach the prover.
  const digest = hex(await crypto.subtle.digest('SHA-256', bytes));
  if (digest !== manifest.pk_sha256) {
    await caches.delete(CACHE_NAME);
    throw new Error('proving key does not match manifest.json (cache cleared; retry)');
  }
  return { bytes, fromCache, manifest };
}

self.onmessage = async ({ data }) => {
  try {
    const prover = await proverReady;
    if (data.type === 'nullifier') {
      post({ type: 'nullifier', result: JSON.parse(prover.compute_nullifier(data.secret, data.siteId)) });
      return;
    }
    if (data.type === 'checksum') {
      post({ type: 'checksum', result: JSON.parse(prover.checksum_address(data.address)) });
      return;
    }
    if (data.type !== 'prove') return;

    let pk = new Uint8Array(0);
    let keyInfo = { fromCache: null, bytes: null };
    if (!keyLoaded) {
      post({ type: 'progress', phase: 'key' });
      const k = await provingKeyBytes();
      pk = k.bytes;
      keyInfo = { fromCache: k.fromCache, bytes: k.bytes.length };
    }
    post({ type: 'progress', phase: 'prove' });
    const t0 = performance.now();
    const result = JSON.parse(prover.prove(pk, data.credential, data.path, data.server));
    const wallMs = performance.now() - t0;
    if (result.error) {
      post({ type: 'error', message: result.error, kind: result.kind });
      return;
    }
    keyLoaded = true;
    result.timings.wall_ms = wallMs;
    result.key = keyInfo;
    result.worker = self.constructor.name; // DedicatedWorkerGlobalScope
    post({ type: 'proved', result });
  } catch (e) {
    post({ type: 'error', message: String(e?.message ?? e), kind: 'worker' });
  }
};
