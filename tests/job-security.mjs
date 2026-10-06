import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve, relative, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { API, makeJob, validateJob, jobHash, selectWitness, validateResult, consume, jsonRead, boundedRead } from '../jobs.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
// Recorded real KuCoin transcript is used only to test local policies; it is not
// represented as a fresh proof or as a new cryptographic verification.
const fixture = jsonRead(join(root, 'tests/fixtures/historical-kucoin-verified.json'));
const now = fixture.tlsSessionTimeSeconds * 1000;
const job = makeJob(now);
const result = { ...fixture, jobChallenge: jobHash(job) };
const peers = ['1'.repeat(64), '2'.repeat(64), '3'.repeat(64)].map(id => ({ id }));
const chosen = selectWitness(job, peers);
assert.equal(selectWitness(job, peers.reverse()), chosen, 'witness selection ignores peer order');
assert.equal(selectWitness(structuredClone(job), peers), chosen, 'same job cannot reroll witness');
const hashes = validateResult(result, job, now, true);
assert.equal(hashes.requestSha256.length, 64);
assert.throws(() => validateResult(result, { ...job, challenge: 'b'.repeat(64) }, now), /expected job/);
assert.throws(() => validateResult(result, { ...job, execution: 1 }, now), /expected job/);
assert.throws(() => validateResult(result, job, job.notAfter + 1, true), /stale/);
const old = { ...result, tlsSessionTimeSeconds: fixture.tlsSessionTimeSeconds - 3600 };
assert.throws(() => validateResult(old, job, now), /outside/);
assert.throws(() => validateResult({ ...result, server: 'attacker.invalid' }, job, now), /Unexpected/);
assert.throws(() => validateResult({ ...result, requestHex: 'xx' }, job, now), /transcript/);
assert.throws(() => validateJob({ ...job, unexpected: true }), /schema/);
assert.throws(() => validateJob({ ...job, api: { ...API, method: 'POST' } }), /Unsupported/);
assert.throws(() => validateJob({ ...job, execution: '0' }), /identity/);
assert.throws(() => validateJob({ ...job, notAfter: job.notBefore + 600001 }), /window/);
const dir = mkdtempSync(join(tmpdir(), 'oracle-job-security-'));
try {
  const ledger = join(dir, 'ledger.json');
  const proof = 'a'.repeat(64);
  consume(ledger, job, proof);
  assert.throws(() => consume(ledger, job, 'b'.repeat(64)), /Replay/);
  assert.throws(() => consume(ledger, { ...job, id: 'other' }, proof), /Replay/);
  writeFileSync(join(dir, 'large.json'), 'a'.repeat(1025));
  assert.throws(() => jsonRead(join(dir, 'large.json'), 1024), /size limit/);
  assert.throws(() => boundedRead(dir), /regular file|EISDIR|EPERM/);
  writeFileSync(ledger + '.lock', '');
  assert.throws(() => consume(ledger, { ...job, id: 'another' }, 'c'.repeat(64)), /busy/);
} finally {
  const rel = relative(resolve(tmpdir()), resolve(dir));
  assert.ok(rel && !rel.startsWith('..') && !isAbsolute(rel) && rel.startsWith('oracle-job-security-'), 'cleanup target is the test directory inside temp root');
  rmSync(resolve(dir), { recursive: true, force: true });
}
console.log('PASS job policy: fixed witnesses, transcript/job binding, windows, duplicate job/proof rejection, schema/file limits, locked ledger');
