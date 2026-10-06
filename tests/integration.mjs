import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, createWriteStream, cpSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { API } from '../jobs.mjs';
const exec = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'oracle-node.mjs');
mkdirSync(join(ROOT, 'tests/results'), { recursive: true });
const resultsRoot = resolve(process.env.ORACLE_TEST_RESULTS || join(ROOT, 'tests/results'));
mkdirSync(resultsRoot, { recursive: true, mode: 0o700 });
const resultDir = mkdtempSync(join(resultsRoot, 'run-'));
const A = join(resultDir, 'node-a'); const B = join(resultDir, 'node-b');
const logs = [];
const processes = new Set();
const delay = ms => new Promise(ok => setTimeout(ok, ms));
async function cli(...args) { const result = await exec(process.execPath, [CLI, ...args], { timeout: 330000, maxBuffer: 8 * 1024 * 1024 }); return result.stdout.trim(); }
function read(path) { return JSON.parse(readFileSync(path, 'utf8')); }
async function start(data) {
  const log = createWriteStream(join(data, 'node.log'), { flags: 'a' });
  const child = spawn(process.execPath, [CLI, 'start', '--data', data], { stdio: ['ignore', 'pipe', 'pipe'] });
  processes.add(child); logs.push(log);
  child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
  await new Promise((ok, no) => {
    const timer = setTimeout(() => no(new Error('Node startup timeout')), 15000);
    child.once('error', error => { clearTimeout(timer); no(error); });
    child.once('exit', code => { clearTimeout(timer); no(new Error('Node exited early: ' + code)); });
    child.stdout.on('data', chunk => { if (chunk.toString().includes('NODE READY')) { clearTimeout(timer); ok(); } });
  });
  return child;
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise(ok => { child.once('exit', ok); child.kill('SIGTERM'); });
  processes.delete(child);
}
async function waitForPeer(data, id) {
  for (let i = 0; i < 150; i++) {
    try { if (read(join(data, 'peers.json')).some(p => p.id === id && Date.now() - p.lastSeen < 10000)) return; } catch {}
    await delay(100);
  }
  throw new Error('Peer not discovered');
}
const report = { testStartedAt: new Date().toISOString(), checks: [], results: [] };
try {
  const a = JSON.parse(await cli('init', '--data', A, '--address', '127.0.0.1:19443', '--notary-port', '19047'));
  const b = JSON.parse(await cli('init', '--data', B, '--address', '127.0.0.1:20443', '--notary-port', '20047'));
  assert.notEqual(a.id, b.id);
  await cli('add-seed', '--data', A, '--address', b.address, '--id', b.id);
  await cli('add-seed', '--data', B, '--address', a.address, '--id', a.id);
  const processA = await start(A); let processB = await start(B);
  await waitForPeer(A, b.id); await waitForPeer(B, a.id);
  report.checks.push('Different persistent identities; both peers discovered via authenticated TLS');
  console.log('PASS: both nodes discovered and authenticated each other');
  const expectedPath = join(resultDir, 'expected-job.json');
  const scheduled = { version: 1, id: 'integration-job', execution: 1, challenge: randomBytes(32).toString('hex'), notBefore: Date.now() - 2000, notAfter: Date.now() + 35000, api: { ...API } };
  writeFileSync(expectedPath, JSON.stringify(scheduled));
  const first = JSON.parse(await cli('fetch', '--data', A, '--job-spec', expectedPath));
  assert.equal(first.peerId, b.id); assert.equal(first.verified, true);
  report.results.push(first);
  console.log('PASS: A queried real KuCoin API through B with a verified TLSNotary proof');
  await stop(processB);
  processB = await start(B);
  assert.equal(read(join(B, 'config.json')).id, b.id);
  await waitForPeer(B, a.id); await waitForPeer(A, b.id);
  report.checks.push('Peer B restarted with same identity and reconnected');
  console.log('PASS: B restarted, retained identity and reconnected');
  const second = JSON.parse(await cli('fetch', '--data', B));
  assert.equal(second.peerId, a.id); assert.equal(second.verified, true);
  report.results.push(second);
  console.log('PASS: B queried real KuCoin API through A with a verified TLSNotary proof');
  await stop(processA); await stop(processB);
  for (const result of report.results) {
    const verified = JSON.parse(await cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId));
    assert.equal(verified.verified, true);
    assert.equal(verified.accepted, false);
    const expected = result === first ? expectedPath : join(result.job, 'job-spec.json');
    const ledger = join(resultDir, 'verifier-' + (result === first ? 'a' : 'b') + '.json');
    const accepted = JSON.parse(await cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId, '--expected-job', expected, '--state', ledger));
    assert.equal(accepted.accepted, true);
    await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId, '--expected-job', expected, '--state', ledger), /Replay rejected/);
    const wrongJob = read(expected); wrongJob.challenge = randomBytes(32).toString('hex');
    const wrongExpected = join(result.job, 'wrong-expected-job.json'); writeFileSync(wrongExpected, JSON.stringify(wrongJob));
    await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId, '--expected-job', wrongExpected, '--state', ledger), /independently expected job/);
    await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.peerId, '--peer-id', result.peerId), /Invalid node receipt/);
    await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.nodeId), /Unexpected peer/);
    const envelopeFile = join(result.job, 'node-receipt.json');
    const originalEnvelope = readFileSync(envelopeFile);
    const envelope = JSON.parse(originalEnvelope);
    const payload = JSON.parse(Buffer.from(envelope.payload, 'base64'));
    payload.price = '999.999';
    envelope.payload = Buffer.from(JSON.stringify(payload)).toString('base64');
    writeFileSync(envelopeFile, JSON.stringify(envelope));
    try { await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId), /Invalid node receipt/); }
    finally { writeFileSync(envelopeFile, originalEnvelope); }
    const presentation = readFileSync(join(result.job, 'kucoin.presentation.tlsn'));
    const changed = Buffer.from(presentation);
    const needle = Buffer.from('"price":"' + result.price + '"');
    const pos = changed.indexOf(needle);
    assert.ok(pos >= 0, 'Actual price bytes must be found inside proof');
    const offset = pos + Buffer.byteLength('"price":"');
    changed[offset] = changed[offset] === 57 ? 56 : 57;
    const changedFile = join(result.job, 'tampered.presentation.tlsn'); writeFileSync(changedFile, changed);
    await assert.rejects(exec(join(ROOT, 'bin/verify'), [], { env: { ...process.env, OUTPUT_DIR: result.job, TRUSTED_NOTARY_KEY: join(result.job, 'notary.pub'), PRESENTATION_FILE: changedFile } }), /hash opening does not match any commitment/);
  }
  report.checks.push('Both saved proofs verified with both nodes stopped');
  report.checks.push('Both rounds rejected wrong node identity, wrong peer identity, changed receipt, and changed price inside TLSNotary proof');
  report.checks.push('Both job-bound API proofs accepted once and repeated submission rejected; altered expected challenge rejected');
  while (Date.now() <= scheduled.notAfter + 2000) await delay(Math.min(1000, Math.max(20, scheduled.notAfter + 2001 - Date.now())));
  await assert.rejects(cli('verify', '--job', first.job, '--node-id', first.nodeId, '--peer-id', first.peerId, '--expected-job', expectedPath, '--state', join(resultDir, 'fresh-stale-ledger.json')), /stale/);
  report.checks.push('Genuine proof rejected for live submission after job window expired, even with fresh replay ledger');
  console.log('PASS: job challenge binding, durable replay rejection and real proof expiration');
  report.passed = true; report.completedAt = new Date().toISOString();
  writeFileSync(join(resultDir, 'report.json'), JSON.stringify(report, null, 2));
  writeFileSync(join(ROOT, 'tests/results/latest.txt'), resultDir + '\n');
  console.log('PASS: offline verification and all identity/receipt/price manipulation checks');
  console.log('RESULTS:', resultDir);
} catch (error) {
  report.passed = false; report.error = error.message;
  writeFileSync(join(resultDir, 'report.json'), JSON.stringify(report, null, 2));
  console.error(error); process.exitCode = 1;
} finally {
  for (const child of [...processes]) await stop(child);
  for (const log of logs) log.end();
  if (resultsRoot !== join(ROOT, 'tests/results')) {
    const exported = join(ROOT, 'tests/results', 'export-' + basename(resultDir));
    cpSync(resultDir, exported, { recursive: true, filter: path => !path.endsWith('.key') && !path.endsWith('.secrets.tlsn') });
    const copy = structuredClone(report);
    copy.nativeResults = resultDir;
    for (const result of copy.results) result.job = result.job.replace(resultDir, exported);
    writeFileSync(join(exported, 'report.json'), JSON.stringify(copy, null, 2));
    if (report.passed) writeFileSync(join(ROOT, 'tests/results/latest.txt'), exported + '\n');
    console.log('PUBLIC ARTIFACTS:', exported);
  }
}
