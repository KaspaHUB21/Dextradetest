// Opt-in: uses the real deployed public anchor, two fresh outbound identities,
// public single-job admission, and an independently pinned bundled witness.
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_BOOTSTRAP } from '../network-defaults.mjs';
const run = promisify(execFile);
const cliFile = fileURLToPath(new URL('../oracle-node.mjs', import.meta.url));
const root = mkdtempSync(join(tmpdir(), 'oracle-public-network-'));
const aData = join(root, 'a'), bData = join(root, 'b');
const children = new Set();
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const cli = async (...args) => (await run(process.execPath, [cliFile, ...args], { timeout: 330000, maxBuffer: 4 * 1024 * 1024 })).stdout.trim();
const read = path => JSON.parse(readFileSync(path));
async function start(data) {
  const child = spawn(process.execPath, [cliFile, 'start', '--data', data], { stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  let logs = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { logs = (logs + bytes).slice(-16000); });
  await new Promise((ok, no) => {
    const timer = setTimeout(() => no(new Error('Node startup timeout: ' + logs)), 20000);
    child.once('error', error => { clearTimeout(timer); no(error); });
    child.once('exit', () => { clearTimeout(timer); no(new Error('Node exited: ' + logs)); });
    child.stdout.on('data', bytes => { if (bytes.toString().includes('NODE READY')) { clearTimeout(timer); ok(); } });
  });
}
async function stopAll() {
  for (const child of children) if (child.exitCode === null && child.signalCode === null) {
    await new Promise(resolve => {
      const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
      child.once('exit', () => { clearTimeout(timer); resolve(); }); child.kill('SIGTERM');
    });
  }
}
const report = { startedAt: new Date().toISOString(), scope: 'Two new local identities and real public bootstrap; no claim of independent operators', checks: [] };
try {
  const a = JSON.parse(await cli('init', '--data', aData, '--listen', '127.0.0.1:48443', '--notary-port', '48047'));
  const b = JSON.parse(await cli('init', '--data', bData, '--listen', '127.0.0.1:49443', '--notary-port', '49047'));
  await start(aData); await start(bData);
  const deadline = Date.now() + 90000;
  let found = false;
  while (Date.now() < deadline) {
    try {
      found = [[aData, b.id], [bData, a.id]].every(([data, id]) => read(join(data, 'peers.json')).some(peer => peer.id === id && peer.confirmed && peer.relayVia === DEFAULT_BOOTSTRAP.id && Date.now() - peer.lastSeen < 30000));
    } catch {}
    if (found) break; await delay(500);
  }
  assert.ok(found, 'Fresh nodes must find/authenticate each other through the public relay without manual peer configuration');
  report.checks.push('Fresh installs discover and authenticate each other through public bootstrap, with no manual seeds or caller grants');
  const job = join(root, 'job.json');
  await cli('job-create', '--template', fileURLToPath(new URL('../templates/generic-api.job.json', import.meta.url)), '--out', job);
  const started = Date.now();
  const result = JSON.parse(await cli('submit', '--data', aData, '--peer-id', b.id, '--job-spec', job, '--wait', 'true'));
  assert.equal(result.verified, true); assert.equal(result.nodeId, b.id); assert.equal(result.peerId, DEFAULT_BOOTSTRAP.id);
  assert.equal(typeof result.values.price, 'string');
  report.jobElapsedMs = Date.now() - started;
  report.checks.push('Public requester sends Coinbase job to discovered worker; complete proof verified against pinned bundled witness');
  await stopAll();
  const inspected = JSON.parse(await cli('verify', '--data', aData, '--job', result.job, '--node-id', b.id, '--peer-id', result.peerId));
  assert.equal(inspected.verified, true);
  await assert.rejects(cli('verify', '--data', aData, '--job', result.job, '--node-id', b.id, '--peer-id', result.peerId, '--expected-job', job), /Replay/);
  report.checks.push('Result stays verifiable with both new nodes stopped; repeated acceptance rejected');
  report.success = true;
} catch (error) { report.success = false; report.error = error.message; process.exitCode = 1; }
finally {
  await stopAll(); report.finishedAt = new Date().toISOString();
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(JSON.stringify({ ...report, report: join(root, 'report.json') }));
}
