import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';
import net from 'node:net';
import { createPrivateKey, sign } from 'node:crypto';
import assert from 'node:assert/strict';
const exec = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'oracle-node.mjs');
const resultsRoot = resolve(process.env.ORACLE_TEST_RESULTS || join(ROOT, 'tests/results'));
mkdirSync(resultsRoot, { recursive: true, mode: 0o700 });
const dir = mkdtempSync(join(resultsRoot, 'peer-security-'));
const A = join(dir, 'a'), B = join(dir, 'b'), C = join(dir, 'c');
const checks = []; const live = new Set(); let child;
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const delay = ms => new Promise(ok => setTimeout(ok, ms));
async function cli(...args) { return (await exec(process.execPath, [CLI, ...args], { timeout: 30000 })).stdout.trim(); }
async function message(data, body, extra) {
  const socket = tls.connect({ host: '127.0.0.1', port: 24443, key: readFileSync(join(data, 'identity.key')), cert: readFileSync(join(data, 'identity.crt')), rejectUnauthorized: false, minVersion: 'TLSv1.3' });
  live.add(socket); socket.on('error', () => {}); socket.once('close', () => live.delete(socket));
  await new Promise((ok, no) => { socket.once('secureConnect', ok); socket.once('error', no); });
  return await new Promise((ok, no) => {
    const timer = setTimeout(() => { socket.destroy(); no(new Error('Response timeout')); }, 12000);
    let buffer = '';
    socket.on('data', bytes => { buffer += bytes; const pos = buffer.indexOf('\n'); if (pos >= 0) { clearTimeout(timer); socket.destroy(); ok(JSON.parse(buffer.slice(0, pos))); } });
    socket.once('close', () => { clearTimeout(timer); no(new Error('Connection closed')); });
    socket.write(extra || JSON.stringify({ ...body, descriptor: read(join(data, 'descriptor.json')) }) + '\n');
  });
}
try {
  const a = JSON.parse(await cli('init', '--data', A, '--address', '127.0.0.1:23443', '--notary-port', '23047'));
  const b = JSON.parse(await cli('init', '--data', B, '--address', '127.0.0.1:24443', '--notary-port', '24047'));
  await cli('init', '--data', C, '--address', '127.0.0.1:25443', '--notary-port', '25047');
  await cli('add-seed', '--data', B, '--id', a.id, '--address', a.address);
  child = spawn(process.execPath, [CLI, 'start', '--data', B], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
  for (let i = 0; i < 150 && !output.includes('NODE READY'); i++) { if (child.exitCode !== null) throw new Error(output); await delay(100); }
  assert.match(output, /NODE READY/);
  assert.equal((await message(A, { op: 'hello' })).ok, true); checks.push('Pinned peer hello succeeds');
  assert.equal((await message(C, { op: 'hello' })).ok, false); checks.push('Unapproved identity rejected before peer admission');
  assert.equal(read(join(B, 'peers.json')).length, 1);
  const envelope = read(join(A, 'descriptor.json'));
  const desc = JSON.parse(Buffer.from(envelope.payload, 'base64')); desc.address = '127.0.0.1:12345';
  const payload = Buffer.from(JSON.stringify(desc));
  const altered = { payload: payload.toString('base64'), signature: sign(null, Buffer.concat([Buffer.from('oracle-node-prototype/descriptor/v1\0'), payload]), createPrivateKey(readFileSync(join(A, 'identity.key')))).toString('base64') };
  const mismatch = await message(A, {}, JSON.stringify({ op: 'hello', descriptor: altered }) + '\n');
  assert.equal(mismatch.ok, false); checks.push('Validly signed address change cannot redirect pinned identity');
  assert.equal(read(join(B, 'peers.json'))[0].address, a.address);
  const huge = await message(A, {}, 'x'.repeat(140000) + '\n');
  assert.equal(huge.ok, false); checks.push('Oversized peer message rejected');
  assert.equal((await message(A, { op: 'channel', channel: 'control', token: 'wrong' })).ok, false); checks.push('Unauthorized session channel rejected');
  const { token, ok } = await message(A, { op: 'reserve' }); assert.equal(ok, true);
  assert.equal((await message(A, { op: 'reserve' })).ok, false); checks.push('Parallel reservation rejected');
  assert.equal((await message(A, { op: 'channel', channel: 'mpc', token })).ok, true);
  assert.equal((await message(A, { op: 'channel', channel: 'mpc', token })).ok, false); checks.push('Duplicate session channel rejected');
  assert.equal((await message(A, { op: 'release', token: 'wrong' })).ok, false);
  assert.equal((await message(A, { op: 'release', token })).ok, true); checks.push('Release requires owner token; valid release restarts notary');
  for (let i = 0; i < 5; i++) { const session = await message(A, { op: 'reserve' }); assert.equal(session.ok, true); assert.equal((await message(A, { op: 'release', token: session.token })).ok, true); }
  const limited = await message(A, { op: 'reserve' }); assert.equal(limited.ok, false); assert.match(limited.error, /rate/); checks.push('Per-peer reservation rate enforced');
  await delay(100);
  const raw = [];
  for (let i = 0; i < 9; i++) { const s = net.connect(24443, '127.0.0.1'); s.on('error', () => {}); live.add(s); s.once('close', () => live.delete(s)); raw.push(s); await delay(30); }
  await delay(100); assert.ok(raw[8].destroyed); checks.push('Pre-handshake TCP connections capped per IP');
  for (const s of raw) s.destroy();
  assert.equal((await message(A, { op: 'hello' })).ok, true); checks.push('Service remains responsive after negative tests');
  writeFileSync(join(dir, 'report.json'), JSON.stringify({ passed: true, checks }, null, 2));
  console.log(JSON.stringify({ passed: true, checks, resultDirectory: dir }));
} finally {
  for (const s of live) s.destroy();
  if (child && child.exitCode === null && child.signalCode === null) {
    await new Promise(ok => { const timeout = setTimeout(() => { child.kill('SIGKILL'); ok(); }, 8000); child.once('exit', () => { clearTimeout(timeout); ok(); }); child.kill('SIGTERM'); });
  }
}
