import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, createWriteStream, cpSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { API, makeJob, jobHash } from '../jobs.mjs';

// Blackbox test: only the published CLI, persisted public peer observations,
// and the submitted/imported artifacts are used. Requires Linux engines and
// real KuCoin connectivity; it does not establish operator independence.
const execute = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'oracle-node.mjs');
const publicResults = join(ROOT, 'tests/results');
const resultsRoot = resolve(process.env.ORACLE_TEST_RESULTS || publicResults);
mkdirSync(resultsRoot, { recursive: true, mode: 0o700 });
const resultDir = mkdtempSync(join(resultsRoot, 'peer-jobs-'));
const processes = new Set(); const logs = [];
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const delay = ms => new Promise(ok => setTimeout(ok, ms));
const report = { startedAt: new Date().toISOString(), checks: [], results: [] };
async function cli(...args) {
  const result = await execute(process.execPath, [CLI, ...args], { timeout: 360000, maxBuffer: 8 * 1024 * 1024 });
  const output = result.stdout.trim();
  if (['init', 'submit', 'job-status', 'job-result', 'verify', 'fetch', 'peers'].includes(args[0])) return JSON.parse(output);
  return output;
}
async function start(data) {
  const log = createWriteStream(join(data, 'peer-jobs.log'), { flags: 'a', mode: 0o600 }); logs.push(log);
  const child = spawn(process.execPath, [CLI, 'start', '--data', data], { stdio: ['ignore', 'pipe', 'pipe'] });
  processes.add(child); child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
  await new Promise((ok, no) => {
    const timer = setTimeout(() => no(new Error('Peerjobs startup timeout')), 20000);
    const fail = error => { clearTimeout(timer); no(error); };
    child.once('error', fail); child.once('exit', code => fail(new Error('Node exited before ready: ' + code)));
    child.stdout.on('data', chunk => { if (chunk.toString().includes('NODE READY')) { clearTimeout(timer); ok(); } });
  }); return child;
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) { processes.delete(child); return; }
  await new Promise((ok, no) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); no(new Error('Node shutdown exceeded 30 seconds')); }, 30000);
    child.once('exit', () => { clearTimeout(timer); ok(); }); child.kill('SIGTERM');
  }); processes.delete(child);
}
async function peersObserved(checks) {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    if (checks.every(({ data, id }) => {
      try { return read(join(data, 'peers.json')).some(p => p.id === id && p.lastSeen > 0 && Date.now() - p.lastSeen < 15000); } catch { return false; }
    })) return;
    await delay(250);
  } throw new Error('Expected authenticated peers did not appear');
}
async function completed(data, peerId, queueId) {
  const deadline = Date.now() + 330000;
  while (Date.now() < deadline) {
    const status = await cli('job-status', '--data', data, '--peer-id', peerId, '--queue-id', queueId);
    assert.equal(status.queueId, queueId);
    if (status.status === 'completed') return status;
    if (status.status === 'failed') throw new Error('Remote job failed: ' + JSON.stringify(status.error));
    assert.ok(['pending', 'running'].includes(status.status)); await delay(500);
  } throw new Error('Peer job exceeded execution deadline');
}
try {
  const aData = join(resultDir, 'node-a'); const bData = join(resultDir, 'node-b'); const cData = join(resultDir, 'node-c');
  const a = await cli('init', '--data', aData, '--address', '127.0.0.1:32443', '--notary-port', '32047', '--discovery', 'local-test');
  const b = await cli('init', '--data', bData, '--outbound-only', 'true', '--listen', '127.0.0.1:33443', '--notary-port', '33047', '--discovery', 'local-test');
  assert.equal(b.address, null);
  await cli('add-bootstrap', '--data', bData, '--address', a.address, '--id', a.id);
  let aProcess = await start(aData); let bProcess = await start(bData);
  await peersObserved([{ data: aData, id: b.id }, { data: bData, id: a.id }]);
  const peerB = read(join(aData, 'peers.json')).find(p => p.id === b.id);
  assert.equal(peerB.address, null); assert.equal(peerB.dialable, false);
  assert.equal(read(join(aData, 'config.json')).seeds.length, 0);
  await assert.rejects(cli('fetch', '--data', aData), /trusted|pinned|witness/i);
  report.checks.push('Outbound-only B establishes bootstrap mesh; A cannot directly dial B; discovery alone grants no witness trust');
  await cli('trust-peer', '--data', aData, '--id', b.id);
  await cli('trust-peer', '--data', bData, '--id', a.id);
  await stop(bProcess); await stop(aProcess);
  aProcess = await start(aData); bProcess = await start(bData);
  await peersObserved([{ data: aData, id: b.id }, { data: bData, id: a.id }]);
  const spec = { ...makeJob(), id: 'peer-mesh-job', api: { ...API } };
  const specPath = join(resultDir, 'expected-job.json'); writeFileSync(specPath, JSON.stringify(spec), { mode: 0o600 });
  const submitted = await cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', specPath);
  assert.match(submitted.queueId, /^[a-f0-9]{64}$/); assert.equal(submitted.jobHash, jobHash(spec));
  const duplicate = await cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', specPath);
  assert.equal(duplicate.queueId, submitted.queueId);
  const altered = { ...spec, challenge: 'a'.repeat(64) };
  const alteredPath = join(resultDir, 'conflicting-job.json'); writeFileSync(alteredPath, JSON.stringify(altered), { mode: 0o600 });
  await assert.rejects(cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', alteredPath), /conflict|specification|mismatch/i);
  const status = await completed(bData, a.id, submitted.queueId);
  assert.equal(status.jobHash, jobHash(spec)); assert.equal(status.result.verified, true);
  assert.equal(status.result.nodeId, a.id); assert.equal(status.result.peerId, b.id);
  const imported = await cli('job-result', '--data', bData, '--peer-id', a.id, '--queue-id', submitted.queueId);
  assert.equal(imported.verified, true); assert.equal(imported.accepted, true);
  assert.equal(imported.nodeId, a.id); assert.equal(imported.peerId, b.id);
  assert.deepEqual(read(join(imported.job, 'job-spec.json')), spec);
  report.results.push(imported);
  await assert.rejects(cli('job-result', '--data', bData, '--peer-id', a.id, '--queue-id', submitted.queueId), /Replay|consumed|already/i);
  report.checks.push('Outbound-only B submits to A; A notarizes through B over reverse mesh, status completes, result proof imported and independently job-bound verified');
  report.checks.push('Idempotent resubmission keeps queue ID; conflicting same execution rejected; repeated result acceptance rejected');
  console.log('PASS: outbound-only peer job submission, reverse witness, result verification and replay controls');
  const c = await cli('init', '--data', cData, '--outbound-only', 'true', '--listen', '127.0.0.1:34443', '--notary-port', '34047', '--discovery', 'local-test');
  await cli('add-bootstrap', '--data', cData, '--address', a.address, '--id', a.id);
  // C locally trusts A, but A does not authorize C. This tests remote access
  // control rather than merely the CLI's own outbound permission check.
  await cli('add-seed', '--data', cData, '--address', a.address, '--id', a.id);
  await start(cData); await peersObserved([{ data: cData, id: a.id }, { data: aData, id: c.id }]);
  // Simulate an attacker who knows the public queue ID and job specification.
  // A forged local submission record bypasses the CLI's missing-record check;
  // server-side authorization must still deny C's authenticated identity.
  mkdirSync(join(cData, 'submitted-jobs'), { mode: 0o700 });
  writeFileSync(join(cData, 'submitted-jobs', submitted.queueId + '.json'),
    readFileSync(join(bData, 'submitted-jobs', submitted.queueId + '.json')), { mode: 0o600 });
  for (const command of ['job-status', 'job-result']) {
    await assert.rejects(cli(command, '--data', cData, '--peer-id', a.id, '--queue-id', submitted.queueId), /authorized|approved|permitted|trusted|requester/i);
  }
  await assert.rejects(cli('submit', '--data', cData, '--peer-id', a.id, '--job-spec', specPath), /authorized|approved|permitted|trusted|requester/i);
  report.checks.push('Unapproved discovery participant cannot submit jobs or read another requester status/result');
  const reverseSpec = { ...makeJob(), id: 'reverse-mesh-job', api: { ...API } };
  const reversePath = join(resultDir, 'reverse-job.json'); writeFileSync(reversePath, JSON.stringify(reverseSpec), { mode: 0o600 });
  const reverse = await cli('submit', '--data', aData, '--peer-id', b.id, '--job-spec', reversePath, '--wait', 'true');
  assert.equal(reverse.verified, true); assert.equal(reverse.accepted, true);
  assert.equal(reverse.nodeId, b.id); assert.equal(reverse.peerId, a.id); report.results.push(reverse);
  report.checks.push('A submits back to undialable B over existing mesh; wait retrieves a second real verified TLSNotary job with roles reversed');
  const seriesSpec = { ...makeJob(), id: 'interval-mesh-job', notBefore: Date.now() + 2000, notAfter: Date.now() + 120000, api: { ...API } };
  const seriesPath = join(resultDir, 'interval-job.json'); writeFileSync(seriesPath, JSON.stringify(seriesSpec), { mode: 0o600 });
  const series = await cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', seriesPath, '--interval-seconds', '10', '--count', '2');
  assert.equal(series.jobs.length, 2); assert.notEqual(series.jobs[0].queueId, series.jobs[1].queueId);
  const repeatedSeries = await cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', seriesPath, '--interval-seconds', '10', '--count', '2');
  assert.deepEqual(repeatedSeries.jobs.map(job => [job.queueId, job.jobHash]), series.jobs.map(job => [job.queueId, job.jobHash]), 'series retry retains execution and challenge bindings');
  for (const [seconds, count] of [['9', '2'], ['10', '33'], ['601', '2']]) {
    await assert.rejects(cli('submit', '--data', bData, '--peer-id', a.id, '--job-spec', seriesPath, '--interval-seconds', seconds, '--count', count), /interval|series|future|window|count|minute/i);
  }
  const secondEarly = await cli('job-status', '--data', bData, '--peer-id', a.id, '--queue-id', series.jobs[1].queueId);
  assert.equal(secondEarly.status, 'pending', 'second execution cannot run before its scheduled slot');
  const seriesResults = [];
  for (const entry of series.jobs) {
    await completed(bData, a.id, entry.queueId);
    const result = await cli('job-result', '--data', bData, '--peer-id', a.id, '--queue-id', entry.queueId);
    assert.equal(result.verified, true); assert.equal(result.accepted, true);
    assert.equal(result.nodeId, a.id); assert.equal(result.peerId, b.id);
    report.results.push(result); seriesResults.push(result);
  }
  const firstSlot = read(join(seriesResults[0].job, 'job-spec.json'));
  const secondSlot = read(join(seriesResults[1].job, 'job-spec.json'));
  assert.equal(firstSlot.id, seriesSpec.id); assert.equal(secondSlot.id, seriesSpec.id);
  assert.equal(firstSlot.execution, seriesSpec.execution); assert.equal(secondSlot.execution, seriesSpec.execution + 1);
  assert.equal(secondSlot.notBefore - firstSlot.notBefore, 10000);
  assert.notEqual(firstSlot.challenge, secondSlot.challenge);
  assert.equal(read(join(seriesResults[0].job, 'kucoin.verified.json.tlsn')).jobChallenge, jobHash(firstSlot));
  const authenticatedSecond = read(join(seriesResults[1].job, 'kucoin.verified.json.tlsn'));
  assert.equal(authenticatedSecond.jobChallenge, jobHash(secondSlot));
  assert.ok(authenticatedSecond.tlsSessionTimeSeconds * 1000 + 999 >= secondSlot.notBefore, 'second authenticated API session starts in its scheduled interval slot');
  report.checks.push('Bounded two-job series uses ten-second scheduled slots, increasing executions and distinct authenticated challenges; stable retries preserve queue IDs and invalid count/interval/future limits rejected; both real API proofs accepted independently');
  console.log('PASS: real ten-second interval series with fresh job-bound TLSNotary proofs');
  for (const process of [...processes]) await stop(process);
  for (const result of report.results) {
    const offline = await cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId);
    assert.equal(offline.verified, true); assert.equal(offline.accepted, false);
    const file = join(result.job, 'node-receipt.json'); const original = readFileSync(file); const envelope = JSON.parse(original);
    const receipt = JSON.parse(Buffer.from(envelope.payload, 'base64')); receipt.price = '999.999';
    envelope.payload = Buffer.from(JSON.stringify(receipt)).toString('base64'); writeFileSync(file, JSON.stringify(envelope));
    try { await assert.rejects(cli('verify', '--job', result.job, '--node-id', result.nodeId, '--peer-id', result.peerId), /Invalid node receipt/); }
    finally { writeFileSync(file, original); }
  }
  report.checks.push('All imported proofs verify offline after all nodes stop; changed receipt rejected for every execution'); report.success = true;
} catch (error) {
  report.success = false; report.error = error.message; process.exitCode = 1; console.error(error.stack);
} finally {
  const outcomes = await Promise.allSettled([...processes].map(stop));
  for (const outcome of outcomes) if (outcome.status === 'rejected') { report.success = false; report.shutdownError = outcome.reason.message; process.exitCode = 1; }
  for (const log of logs) log.end(); report.finishedAt = new Date().toISOString();
  writeFileSync(join(resultDir, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
  if (resultsRoot !== publicResults) {
    const destination = join(publicResults, 'export-' + basename(resultDir));
    cpSync(resultDir, destination, { recursive: true, filter: path => !path.endsWith('.key') && !path.endsWith('.secrets.tlsn') });
    const copy = structuredClone(report); copy.nativeResults = resultDir;
    for (const result of copy.results) result.job = result.job.replace(resultDir, destination);
    writeFileSync(join(destination, 'report.json'), JSON.stringify(copy, null, 2));
  }
  console.log(JSON.stringify({ success: report.success, report: join(resultDir, 'report.json') }));
}
