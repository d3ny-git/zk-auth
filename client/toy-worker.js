// Runs the WebAssembly prover off the main thread, so the page stays
// responsive while libsnark works.
import createProver from './wasm/zkauth_prover.mjs';

self.onmessage = async ({ data }) => {
  try {
    const t0 = performance.now();
    const prover = await createProver();
    const wasmInitMs = performance.now() - t0;
    const pk = new Uint8Array(await (await fetch(data.pkUrl)).arrayBuffer());
    const t1 = performance.now();
    const result = JSON.parse(prover.toyProve(pk, data.x));
    self.postMessage({
      ...result,
      wasm_init_ms: wasmInitMs,
      call_ms: performance.now() - t1,
      version: JSON.parse(prover.version()),
      scope: self.constructor.name, // DedicatedWorkerGlobalScope: proof made off the main thread
    });
  } catch (e) {
    self.postMessage({ error: String(e) });
  }
};
