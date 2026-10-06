import assert from 'node:assert/strict';
import tls from 'node:tls';
import { X509Certificate, createHash, createPrivateKey, sign } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, mkdtempSync, createWriteStream, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'oracle-node.mjs');
const resultRoot = resolve(process.env.ORACLE_TEST_RESULTS || join(ROOT, 'tests/results'));
mkdirSync(resultRoot, { recursive: true, mode: 0o700 });
const resultDir = mkdtempSync(join(resultRoot, 'discovery-'));
const children = new Set();
const logs = [];
const delay = ms => new Promise(ok => setTimeout(ok, ms));
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const cli = async (...args) => (await run(process.execPath, [CLI, ...args], { timeout: 30000, maxBuffer: 1024 * 1024 })).stdout.trim();
async function start(data) {
  const log = createWriteStream(join(data, 'discovery-node.log'), { flags: 'a', mode: 0o600 });
  logs.push(log);
  const child = spawn(process.execPath, [CLI, 'start', '--data', data], { stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child);
  child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
  await new Promise((ok, no) => {
    const timer = setTimeout(() => no(new Error('Discovery node startup timeout')), 20000);
    const fail = error => { clearTimeout(timer); no(error); };
    child.once('error', fail);
    child.once('exit', code => fail(new Error('Discovery node exited early: ' + code)));
    child.stdout.on('data', chunk => {
      if (chunk.toString().includes('NODE READY')) { clearTimeout(timer); ok(); }
    });
  });
  return child;
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) { children.delete(child); return; }
  await new Promise((ok, no) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); no(new Error('Node did not terminate cleanly')); }, 10000);
    child.once('exit', () => { clearTimeout(timer); ok(); }); child.kill('SIGTERM');
  });
  children.delete(child);
}
async function waitPeers(checks) {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    let success = true;
    for (const { data, id } of checks) {
      try {
        const peer = read(join(data, 'peers.json')).find(p => p.id === id);
        if (!peer || !(peer.lastSeen > 0) || Date.now() - peer.lastSeen >= 15000 || peer.confirmed === false) success = false;
      } catch { success = false; }
    }
    if (success) return;
    await delay(200);
  }
  throw new Error('Transitive discovery did not authenticate every expected peer within 45 seconds');
}
async function exchange(fromData, destination, body) {
  const socket = tls.connect({ host: '127.0.0.1', port: Number(destination.address.split(':').at(-1)),
    key: readFileSync(join(fromData, 'identity.key')), cert: readFileSync(join(fromData, 'identity.crt')),
    minVersion: 'TLSv1.3', rejectUnauthorized: false });
  socket.on('error', () => {});
  socket.setTimeout(10000, () => socket.destroy(new Error('Discovery connection timeout')));
  try {
    await new Promise((ok, no) => { socket.once('secureConnect', ok); socket.once('error', no); });
    const cert = new X509Certificate(socket.getPeerCertificate().raw);
    const id = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    assert.equal(id, destination.id, 'discovery endpoint presents expected identity');
    return await new Promise((ok, no) => {
      let buffer = '';
      const timer = setTimeout(() => no(new Error('Discovery protocol response timeout')), 10000);
      const done = (error, value) => { clearTimeout(timer); error ? no(error) : ok(value); };
      socket.on('data', chunk => {
        buffer += chunk.toString();
        if (buffer.length > 128 * 1024) return done(new Error('Oversized discovery response'));
        const n = buffer.indexOf('\n');
        if (n >= 0) {
          try { done(null, JSON.parse(buffer.slice(0, n))); } catch (e) { done(e); }
        }
      });
      socket.once('error', error => done(error));
      socket.once('end', () => { if (!buffer.includes('\n')) done(new Error('Discovery response closed')); });
      socket.write(JSON.stringify({ ...body, descriptor: body.descriptor || read(join(fromData, 'descriptor.json')) }) + '\n');
    });
  } finally { socket.destroy(); }
}
function changedDescriptor(data, address) {
  const envelope = read(join(data, 'descriptor.json'));
  const value = JSON.parse(Buffer.from(envelope.payload, 'base64'));
  value.address = address;
  const payload = Buffer.from(JSON.stringify(value));
  const signature = sign(null, Buffer.concat([Buffer.from('oracle-node-prototype/descriptor/v1\0'), payload]), createPrivateKey(readFileSync(join(data, 'identity.key'))));
  return { payload: payload.toString('base64'), signature: signature.toString('base64') };
}
const report = { startedAt: new Date().toISOString(), checks: [], resultDir };
try {
  const nodes = [];
  for (const [name, port, internal] of [['a',26443,26047],['b',27443,27047],['c',28443,28047]]) {
    const data = join(resultDir, 'node-' + name);
    const node = JSON.parse(await cli('init', '--data', data, '--address', '127.0.0.1:' + port, '--notary-port', String(internal), '--discovery', 'local-test'));
    nodes.push({ ...node, data });
  }
  const [a,b,c] = nodes;
  await cli('add-bootstrap', '--data', b.data, '--address', a.address, '--id', a.id);
  await cli('add-bootstrap', '--data', c.data, '--address', a.address, '--id', a.id);
  assert.equal(read(join(a.data, 'config.json')).seeds.length, 0);
  for (const node of nodes) assert.equal(read(join(node.data, 'config.json')).seeds.length, 0);
  await start(a.data); await start(b.data); await start(c.data);
  await waitPeers([{ data:b.data,id:a.id }, {data:c.data,id:a.id}, {data:b.data,id:c.id}, {data:c.data,id:b.id}]);
  report.checks.push('B and C independently bootstrap from A and authenticate each other through transitive discovery');
  console.log('PASS: three nodes discover and authenticate peers without reciprocal notarizer pins');
  const clientData = join(resultDir, 'node-outbound');
  const client = JSON.parse(await cli('init', '--data', clientData, '--outbound-only', 'true', '--listen', '127.0.0.1:30443', '--notary-port', '30047', '--discovery', 'local-test'));
  assert.equal(client.address, null);
  await cli('add-bootstrap', '--data', clientData, '--address', a.address, '--id', a.id);
  await start(clientData);
  await waitPeers([{data:clientData,id:a.id},{data:a.data,id:client.id}]);
  const inboundClient = read(join(a.data, 'peers.json')).find(p => p.id === client.id);
  assert.equal(inboundClient.dialable, false);
  assert.equal(inboundClient.trusted, false);
  assert.equal((await exchange(clientData, a, {op:'reserve'})).ok, false);
  const offeredToB = await exchange(b.data, a, {op:'hello'});
  assert.ok(!offeredToB.peers.some(p => JSON.parse(Buffer.from(p.payload,'base64')).id === client.id), 'undialable clients must not enter gossip');
  const invalidClient = await exchange(clientData, a, {op:'hello', descriptor:changedDescriptor(clientData,'192.168.10.20:30443')});
  assert.equal(invalidClient.ok,false,'outbound-only declaration cannot advertise a private target');
  report.checks.push('Outbound-only client without public listener authenticates bootstrap; cannot reserve, advertise a private target, or enter dialable gossip');
  console.log('PASS: outbound-only client connects safely without a public address');
  for (const node of [b,c]) {
    for (const peer of read(join(node.data, 'peers.json'))) assert.notEqual(peer.trusted, true, 'discovery cannot grant notary trust');
  }
  const hello = await exchange(c.data, a, { op: 'hello' });
  assert.equal(hello.ok, true, 'discovery-only authenticated hello accepted');
  for (const op of [{ op:'reserve' }, { op:'channel', token:'0'.repeat(64), channel:'mpc' }]) {
    const answer = await exchange(c.data, a, op);
    assert.equal(answer.ok, false, 'unpinned participant denied ' + op.op);
    assert.match(answer.error, /authorized|trusted|pinned|permitted|approved/i);
  }
  await assert.rejects(cli('fetch', '--data', b.data), /trusted|pinned|witness/i);
  report.checks.push('Discovery-only peers can exchange hello but cannot reserve, tunnel, or become selected TLSNotary witnesses');
  console.log('PASS: discovery remains separate from witness authorization');
  const poisoned = await exchange(a.data, b, { op: 'hello', descriptor: changedDescriptor(a.data, '127.0.0.1:29443') });
  assert.equal(poisoned.ok, false, 'valid signature cannot redirect pinned bootstrap address');
  assert.match(poisoned.error, /pinned|redirect|admission/i);
  assert.equal(read(join(b.data, 'config.json')).bootstraps.find(p => p.id === a.id).address, a.address);
  assert.equal(read(join(b.data, 'peers.json')).find(p => p.id === a.id).address, a.address);
  const privateTarget = await exchange(c.data, a, { op: 'hello', descriptor: changedDescriptor(c.data, '192.168.10.20:28443') });
  assert.equal(privateTarget.ok, false, 'signed private non-loopback advertisement is rejected in local-test discovery');
  assert.match(privateTarget.error, /permitted|admission|address/i);
  assert.equal(read(join(a.data, 'peers.json')).find(p => p.id === c.id).address, c.address);
  report.checks.push('Signed pinned-bootstrap address redirection and numeric private non-loopback discovery targets rejected without changing known addresses');
  console.log('PASS: descriptor signatures do not bypass address pinning or discovery network restrictions');
  for (const node of nodes) assert.equal(read(join(node.data, 'config.json')).seeds.length, 0);
  report.success = true;
} catch (error) {
  report.success = false; report.error = error.message; process.exitCode = 1; console.error(error.stack);
} finally {
  const outcomes = await Promise.allSettled([...children].map(stop));
  for (const outcome of outcomes) if (outcome.status === 'rejected') { report.success = false; report.shutdownError = outcome.reason.message; process.exitCode = 1; }
  for (const log of logs) log.end();
  report.finishedAt = new Date().toISOString();
  writeFileSync(join(resultDir, 'report.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ success: report.success, report: join(resultDir, 'report.json') }));
}
