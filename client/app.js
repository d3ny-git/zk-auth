// Zk-Auth browser client: the numbered login steps.
// The credential and Merkle path live only in the `state` object below
// (memory of this tab); nothing is written to storage.

const params = new URLSearchParams(location.search);
const API = params.get('api') ?? '/api'; // the static server proxies /api/* to the Crow server

const state = {
  credential: null, // cred.json text: {secret, dob}. NEVER sent anywhere.
  path: null,       // path.json text: {index, siblings, root}
  address: null,
  chainId: null,
  server: null,     // GET /nonce response
  proved: null,     // {proof, public, proof_hash, timings}
};
window.__zk = { state }; // read by the headless end-to-end tests

const $ = (id) => document.getElementById(id);
const worker = new Worker('./worker.js', { type: 'module' });

// ---------------------------------------------------------------- helpers
function setStep(n, s) { $(`step-${n}`).dataset.state = s; }
function show(n, html) { $(`out-${n}`).innerHTML = html; }
function fail(n, message) {
  setStep(n, 'error');
  show(n, `<span class="bad">✗ ${escapeHtml(message)}</span>`);
}
function enable(n) {
  const btn = $(`step-${n}`).querySelector('button');
  if (btn) btn.disabled = false;
  if ($(`step-${n}`).dataset.state !== 'done') setStep(n, 'active');
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function table(rows) {
  return `<table>${rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join('')}</table>`;
}
const isHex = (s, bytes) => typeof s === 'string' && new RegExp(`^[0-9a-f]{${2 * bytes}}$`).test(s);
const daysToDate = (days) => new Date(days * 86_400_000).toISOString().slice(0, 10);
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`;

// ---------------------------------------------------------------- step 1
async function readInput(fileInput, textarea) {
  const f = fileInput.files[0];
  return f ? await f.text() : textarea.value.trim();
}

$('load-btn').onclick = async () => {
  try {
    const credText = await readInput($('cred-file'), $('cred-text'));
    const pathText = await readInput($('path-file'), $('path-text'));
    const cred = JSON.parse(credText);
    const path = JSON.parse(pathText);
    if (!isHex(cred.secret, 32) || !/^\d{4}-\d{2}-\d{2}$/.test(cred.dob))
      throw new Error('cred.json must be {"secret": <64 hex>, "dob": "YYYY-MM-DD"}');
    if (!Number.isInteger(path.index) || !Array.isArray(path.siblings) || path.siblings.length !== 8 ||
        !path.siblings.every((s) => isHex(s, 32)) || !isHex(path.root, 32))
      throw new Error('path.json must be {"index", "siblings": [8 × 64 hex], "root"}');
    state.credential = credText;
    state.path = pathText;
    setStep(1, 'done');
    show(1, table([
      ['credential', 'secret and date of birth loaded, held in this tab only'],
      ['leaf index', `${path.index} (private: proven, never sent)`],
      ['issuer root', short(path.root)],
    ]));
    enable(2);
  } catch (e) {
    fail(1, e.message);
  }
};

// ---------------------------------------------------------------- step 2
$('wallet-btn').onclick = async () => {
  try {
    if (!window.ethereum) throw new Error('No Ethereum wallet found. Install MetaMask and reload.');
    setStep(2, 'busy');
    const [address] = await window.ethereum.request({ method: 'eth_requestAccounts' });
    state.address = address;
    state.chainId = parseInt(await window.ethereum.request({ method: 'eth_chainId' }), 16);
    setStep(2, 'done');
    show(2, table([['address', address], ['chain id', String(state.chainId)]]));
    enable(3);
  } catch (e) {
    fail(2, e.message);
  }
};

// ---------------------------------------------------------------- step 3
$('nonce-btn').onclick = async () => {
  try {
    setStep(3, 'busy');
    const r = await fetch(`${API}/nonce`);
    if (!r.ok) throw new Error(`GET /nonce: HTTP ${r.status}`);
    state.server = await r.json();
    state.proved = null;
    const cutoff = parseInt(state.server.age_cutoff, 16);
    setStep(3, 'done');
    show(3, table([
      ['nonce', state.server.nonce],
      ['age cutoff', `${daysToDate(cutoff)} (${cutoff} days since 1970: born on or before this date = 18+)`],
      ['site id', short(state.server.site_id)],
      ['issued at', state.server.issued_at],
    ]));
    enable(4);
  } catch (e) {
    fail(3, e.message);
  }
};

// ---------------------------------------------------------------- step 4
function prove() {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const ticker = setInterval(() => {
      if ($('step-4').dataset.state === 'busy' && $('dl-progress').hidden)
        show(4, `proving… ${((performance.now() - started) / 1000).toFixed(0)} s`);
    }, 500);
    worker.onmessage = ({ data }) => {
      if (data.type === 'progress') {
        if (data.phase === 'download') {
          $('dl-progress').hidden = false;
          $('dl-progress').max = data.total;
          $('dl-progress').value = data.loaded;
          show(4, `downloading proving key… ${(data.loaded / 1e6).toFixed(0)} / ${(data.total / 1e6).toFixed(0)} MB`);
        } else {
          $('dl-progress').hidden = true;
          show(4, data.phase === 'key' ? 'loading proving key…' : 'proving…');
        }
      } else if (data.type === 'proved') {
        clearInterval(ticker);
        resolve(data.result);
      } else if (data.type === 'error') {
        clearInterval(ticker);
        reject(new Error(data.message));
      }
    };
    worker.postMessage({
      type: 'prove', credential: state.credential, path: state.path, server: JSON.stringify(state.server),
    });
  });
}

$('prove-btn').onclick = async () => {
  try {
    setStep(4, 'busy');
    $('prove-btn').disabled = true;
    const result = await prove();
    state.proved = result;
    window.__zk.lastProof = result;
    const t = result.timings;
    const pub = result.public;
    setStep(4, 'done');
    show(4, `<div class="stat">Proof generated in ${(t.prove_ms / 1000).toFixed(1)} s</div>` + table([
      ['witness', `${t.witness_ms.toFixed(0)} ms`],
      ['proving key', result.key.bytes == null ? 'already loaded in the worker'
        : `${(result.key.bytes / 1e6).toFixed(1)} MB, ${result.key.fromCache ? 'from Cache API' : 'downloaded'}, parsed in ${t.pk_load_ms.toFixed(0)} ms`],
      ['ran in', result.worker],
      ['public: merkle_root', pub.merkle_root],
      ['public: nullifier', pub.nullifier],
      ['public: site_id', pub.site_id],
      ['public: age_cutoff', `${pub.age_cutoff} (${daysToDate(parseInt(pub.age_cutoff, 16))})`],
      ['public: nonce', pub.nonce],
      ['proof hash', result.proof_hash],
    ]));
    enable(5);
  } catch (e) {
    fail(4, e.message);
  } finally {
    $('prove-btn').disabled = false;
  }
};

// The wasm module loads in the worker as soon as the page opens.
worker.postMessage({ type: 'nullifier', secret: '00'.repeat(32), siteId: '00'.repeat(32) });
worker.onmessage = ({ data }) => {
  if (data.type === 'nullifier') $('prover-version').textContent = 'WebAssembly prover ready';
};
