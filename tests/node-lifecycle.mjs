import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, readlinkSync } from 'node:fs';
import { createJobQueue } from '../job-queue.mjs';
import { makeJob } from '../jobs.mjs';
const exec = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'oracle-node.mjs');
const resultsRoot = resolve(process.env.ORACLE_TEST_RESULTS || join(ROOT, 'tests/results'));
mkdirSync(resultsRoot, { recursive: true, mode: 0o700 });
const resultDir = mkdtempSync(join(resultsRoot, 'node-lifecycle-'));
const DATA = join(resultDir, 'node'); const checks = [];
const servers = new Set(); const children = new Set(); const output = [];
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const delay = ms => new Promise(ok => setTimeout(ok, ms));
async function listen(port) {
  const server = net.createServer(socket => socket.destroy()); server.on('error', () => {});
  await new Promise((ok, no) => { server.once('error', no); server.listen(port, '127.0.0.1', ok); });
  servers.add(server); return server;
}
async function close(server) { servers.delete(server); if (server.listening) await new Promise(ok => server.close(ok)); }
async function allocatePorts() {
  const peer = await listen(0); const peerPort = peer.address().port; await close(peer);
  for (let base = 27047; base < 29000; base += 7) {
    const held = [];
    try { for (let offset = 0; offset < 4; offset++) held.push(await listen(base + offset)); }
    catch { for (const server of held) await close(server); continue; }
    for (const server of held) await close(server);
    return { peerPort, base };
  }
  throw new Error('No free internal port range');
}
async function ensureFree(ports) { for (const port of ports) { const server = await listen(port); await close(server); } }
async function failedStart(label) {
  const began = Date.now(); let failure;
  try { await exec(process.execPath, [CLI, 'start', '--data', DATA], { timeout: 9500, maxBuffer: 1024 * 1024 }); }
  catch (error) { failure = error; }
  assert.ok(failure, label + ' must fail'); assert.equal(failure.killed, false, label + ' must exit on its own before deadline');
  assert.ok(Date.now() - began < 10000); assert.match(failure.stderr, /EADDRINUSE|address already in use/i);
  output.push(label + ': ' + failure.stderr.trim());
  assert.equal(existsSync(join(DATA, 'job-queue.owner')), false, label + ' must leave no queue owner marker');
}
async function start() {
  const child = spawn(process.execPath, [CLI, 'start', '--data', DATA], { stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child); let text = '';
  child.stdout.on('data', chunk => { text += chunk; }); child.stderr.on('data', chunk => { text += chunk; });
  for (let i = 0; i < 100; i++) { if (text.includes('NODE READY')) return child; if (child.exitCode !== null) throw new Error(text); await delay(50); }
  throw new Error('Healthy startup deadline exceeded: ' + text);
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((ok, no) => { const timer = setTimeout(() => { child.kill('SIGKILL'); no(new Error('Node shutdown deadline')); }, 8000); child.once('exit', code => { clearTimeout(timer); code === 0 ? ok() : no(new Error('Node shutdown failed: ' + code)); }); child.kill('SIGTERM'); });
  children.delete(child);
}
const { peerPort, base } = await allocatePorts();
try {
  const node = JSON.parse((await exec(process.execPath, [CLI, 'init', '--data', DATA, '--address', '127.0.0.1:' + peerPort, '--notary-port', String(base)], { timeout: 30000 })).stdout);
  const queue = createJobQueue({ data: DATA, nodeId: node.id, execute: () => { throw new Error('Persisted fixture must never execute while fixture queue open'); } });
  const future = makeJob(Date.now() + 120000), due = makeJob();
  await queue.submit({ spec: future, requesterId: node.id }); await queue.submit({ spec: due, requesterId: node.id }); await queue.stop();
  assert.ok(read(join(DATA, 'job-queue.json')).records.every(record => record.status === 'pending'));
  const initialState = readFileSync(join(DATA, 'job-queue.json'), 'utf8');
  const broker = await listen(base + 3);
  await failedStart('Occupied broker port with due and future persisted jobs');
  await ensureFree([peerPort, base, base + 1, base + 2]); await close(broker);
  assert.equal(readFileSync(join(DATA, 'job-queue.json'), 'utf8'), initialState);
  checks.push('Broker bind failure exits promptly with pending jobs unchanged, no owner marker or notary/listener leaks');
  const peer = await listen(peerPort);
  await failedStart('Occupied peer listener port');
  await ensureFree([base, base + 1, base + 2, base + 3]); await close(peer);
  assert.equal(readFileSync(join(DATA, 'job-queue.json'), 'utf8'), initialState);
  checks.push('Peer bind failure exits promptly and cleans native notary resources without changing queued jobs');
  const running = await start();
  assert.equal(existsSync(join(DATA, 'job-queue.owner')), true);
  // No trusted witness exists: due job fails safely; future job stays pending.
  for (let i = 0; i < 100; i++) { if (read(join(DATA, 'job-queue.json')).records.find(r => r.spec.id === due.id).status === 'failed') break; await delay(50); }
  assert.equal(read(join(DATA, 'job-queue.json')).records.find(r => r.spec.id === due.id).status, 'failed');
  assert.equal(read(join(DATA, 'job-queue.json')).records.find(r => r.spec.id === future.id).status, 'pending');
  let duplicateFailure;
  try { await exec(process.execPath, [CLI, 'start', '--data', DATA], { timeout: 9500 }); } catch (error) { duplicateFailure = error; }
  assert.ok(duplicateFailure && !duplicateFailure.killed, 'Duplicate daemon fails promptly');
  assert.equal(running.exitCode, null); assert.equal(read(join(DATA, 'job-queue.owner')).pid, running.pid);
  checks.push('Duplicate daemon cannot take ownership or stop existing healthy daemon');
  await stop(running);
  assert.equal(existsSync(join(DATA, 'job-queue.owner')), false); await ensureFree([peerPort, base, base + 1, base + 2, base + 3]);
  checks.push('Healthy restart executes due job safely, preserves future job, and shutdown releases ownership and all ports');
  const report = { passed: true, checks, output, resultDirectory: resultDir };
  writeFileSync(join(resultDir, 'report.json'), JSON.stringify(report, null, 2)); console.log(JSON.stringify(report));
} finally {
  for (const server of servers) await close(server);
  for (const child of children) { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await delay(200); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); } }
  // Cleanup only native children demonstrably running in this test's private data directory.
  if (process.platform === 'linux') for (const pid of readdirSync('/proc').filter(name => /^\d+$/.test(name))) {
    try { if (readlinkSync('/proc/' + pid + '/cwd') === DATA && readlinkSync('/proc/' + pid + '/exe').endsWith('/notary')) process.kill(Number(pid), 'SIGKILL'); } catch {}
  }
}
