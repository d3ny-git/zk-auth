// Node.js baseline server: the same /verify-proof and /verify-sig endpoints,
// request format and status codes as zkauth-server.
//   VK=verification_key.json PORT=8082 WORKERS=0 node server.mjs
// WORKERS=0: a single process; WORKERS=N: node:cluster with N workers.
import cluster from 'node:cluster';
import { readFileSync } from 'node:fs';
import Fastify from 'fastify';
import { getAddress, verifyMessage } from 'ethers';
import { convertProof, convertPublic, validateProofBody } from './convert.mjs';
import { makeVerifier } from './verify.mjs';

const PORT = Number(process.env.PORT ?? 8082);
const WORKERS = Number(process.env.WORKERS ?? 0);

if (WORKERS > 0 && cluster.isPrimary) {
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on('exit', (w, code) => { console.error(`worker ${w.process.pid} exited (${code})`); process.exit(1); });
  console.error(`baseline: cluster of ${WORKERS} workers on :${PORT}`);
} else {
  const verify = await makeVerifier(JSON.parse(readFileSync(process.env.VK ?? 'verification_key.json', 'utf8')));
  const app = Fastify({ logger: false, bodyLimit: 16 * 1024 });
  // Malformed input: 400 {"valid": false}, exactly like the C++ server.
  app.setErrorHandler((err, req, reply) => reply.code(400).send({ valid: false }));

  app.get('/health', async () => ({ ok: true }));

  app.post('/verify-proof', async (req, reply) => {
    try { validateProofBody(req.body); } catch { return reply.code(400).send({ valid: false }); }
    return { valid: await verify(convertProof(req.body.proof), convertPublic(req.body.public)) };
  });

  app.post('/verify-sig', async (req, reply) => {
    const b = req.body;
    let claimed;
    try {
      if (!b || typeof b.message !== 'string' || typeof b.signature !== 'string' || Object.keys(b).length !== 3)
        throw new Error('shape');
      claimed = getAddress(b.address); // rejects a wrong EIP-55 checksum
    } catch { return reply.code(400).send({ valid: false }); }
    try {
      return { valid: verifyMessage(b.message, b.signature) === claimed };
    } catch {
      return reply.code(400).send({ valid: false }); // malformed signature
    }
  });

  await app.listen({ port: PORT, host: process.env.HOST ?? '0.0.0.0' });
  if (!cluster.isWorker) console.error(`baseline: single process on :${PORT}`);
}
