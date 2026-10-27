// Generates tests/vectors/metamask_personal_sign.json with MetaMask's own
// signing library, @metamask/eth-sig-util (personalSign is what MetaMask's
// keyring runs for the personal_sign RPC). The keys are public test keys.
// Real signatures captured from the MetaMask extension can be appended with
// the client's "export signature vector" debug button; see tests/vectors/README.md.
import { writeFileSync } from 'node:fs';
import { personalSign, recoverPersonalSignature } from '@metamask/eth-sig-util';
import { Wallet } from 'ethers';
import { repoRoot } from './lib.mjs';

const cases = [
  // The example from eth-sig-util's own test suite / docs.
  { key: '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0', message: 'Hello, world!' },
  // A Zk-Auth SIWE message: multi-line, the shape the server actually sees.
  { key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', message:
`localhost:8080 wants you to sign in with your Ethereum account:
@ADDRESS@

Log in to Zk-Auth. zk-auth-proof:0x5a1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8

URI: http://localhost:8080
Version: 1
Chain ID: 1
Nonce: 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
Issued At: 2026-10-27T12:00:00.000Z` },
  // Multi-byte UTF-8: the EIP-191 length prefix counts bytes, not characters.
  { key: 'aa00000000000000000000000000000000000000000000000000000000000001', message: 'Grüße, 世界 — ✓' },
  // Empty message.
  { key: 'b0b0000000000000000000000000000000000000000000000000000000000002', message: '' },
];

const vectors = cases.map(({ key, message: template }) => {
  const message = template.replace('@ADDRESS@', new Wallet('0x' + key).address);
  const data = '0x' + Buffer.from(message, 'utf8').toString('hex'); // MetaMask passes hex-encoded data
  const signature = personalSign({ privateKey: Buffer.from(key, 'hex'), data });
  const address = new Wallet('0x' + key).address;
  if (recoverPersonalSignature({ data, signature }).toLowerCase() !== address.toLowerCase())
    throw new Error('self-check failed');
  return { message, address, signature, source: '@metamask/eth-sig-util personalSign' };
});
writeFileSync(`${repoRoot}tests/vectors/metamask_personal_sign.json`, JSON.stringify(vectors, null, 2) + '\n');
console.log(JSON.stringify(vectors.map((v) => [v.address, v.signature.slice(0, 20) + '…']), null, 1));
