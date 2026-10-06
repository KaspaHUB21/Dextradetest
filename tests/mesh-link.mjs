import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { randomBytes, createHash } from 'node:crypto';
import { createMeshLink } from '../mesh-link.mjs';
const checks = [];
const delay = ms => new Promise(ok => setTimeout(ok, ms));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function sockets() {
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const accept = once(server, 'connection');
  const client = net.connect(server.address().port, '127.0.0.1'); await once(client, 'connect');
  const [remote] = await accept; server.close();
  for (const socket of [client, remote]) { socket.pause(); socket.on('error', () => {}); socket.getPeerCertificate = () => ({ marker: 'authenticated-by-caller' }); }
  return [client, remote];
}
function collect(stream) { return new Promise((ok, no) => { const parts = []; stream.on('data', data => parts.push(data)); stream.once('end', () => ok(Buffer.concat(parts))); stream.once('error', no); }); }
function frame(type, id, payload = Buffer.alloc(0)) { const output = Buffer.alloc(9 + payload.length); output.writeUInt32BE(payload.length, 0); output.writeUInt32BE(id, 4); output[8] = type; payload.copy(output, 9); return output; }
async function pair(onA, onB) {
  const [a, b] = await sockets();
  const A = createMeshLink(a, { initiator: true, onStream: onA || (s => s.end()) });
  const B = createMeshLink(b, { initiator: false, onStream: onB || (s => s.end()) });
  return { A, B, a, b, close() { A.close(); B.close(); } };
}
async function withDeadline(promise, milliseconds = 10000) {
  let timer; try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Test deadline')), milliseconds); })]); } finally { clearTimeout(timer); }
}
{
  const incomingA = [], incomingB = [];
  const p = await pair(s => incomingA.push(s), s => incomingB.push(s));
  try {
    const a = p.A.openStream(), b = p.B.openStream();
    await delay(20); assert.equal(incomingA.length, 1); assert.equal(incomingB.length, 1);
    assert.equal(a.id, 1); assert.equal(b.id, 2); assert.equal(incomingA[0].id, 2); assert.equal(incomingB[0].id, 1);
    assert.equal(incomingA[0].remoteAddress, '127.0.0.1'); assert.equal(incomingA[0].getPeerCertificate().marker, 'authenticated-by-caller');
    const bytesA = randomBytes(3 * 1024 * 1024), bytesB = randomBytes(2 * 1024 * 1024);
    const receiveA = collect(incomingB[0]); const receiveB = collect(incomingA[0]); const replyA = collect(a); const replyB = collect(b);
    a.end(bytesA); b.end(bytesB); incomingA[0].end(Buffer.from('reply-b')); incomingB[0].end(Buffer.from('reply-a'));
    const [gotA, gotB, gotReplyA, gotReplyB] = await withDeadline(Promise.all([receiveA, receiveB, replyA, replyB]));
    assert.equal(hash(gotA), hash(bytesA)); assert.equal(hash(gotB), hash(bytesB)); assert.equal(gotReplyA.toString(), 'reply-a'); assert.equal(gotReplyB.toString(), 'reply-b');
    checks.push('Both peers open streams; binary transfers and half-close replies match');
    await delay(20); assert.equal(p.A.stats.streams, 0); assert.equal(p.B.stats.streams, 0); checks.push('Finished streams release capacity');
  } finally { p.close(); }
}
{
  let remote; const p = await pair(undefined, s => { remote = s; });
  try {
    const stream = p.A.openStream(); await delay(20);
    let completed = false; stream.write(randomBytes(2 * 1024 * 1024), () => { completed = true; });
    await delay(100); assert.equal(completed, false); assert.ok(remote.readableLength <= 256 * 1024); assert.ok(p.A.stats.queuedBytes <= 1024 * 1024);
    checks.push('Unread peer stalls sender with bounded receive/window/socket buffers');
    const read = collect(remote); remote.end(); stream.end(); stream.resume(); await withDeadline(read);
    assert.equal(completed, true); checks.push('Consuming stalled stream resumes credit flow');
  } finally { p.close(); }
}
{
  const p = await pair();
  try { const streams = Array.from({ length: 64 }, () => p.A.openStream()); assert.throws(() => p.A.openStream(), /limit/); await delay(20); assert.equal(p.B.stats.streams, 64); for (const s of streams) s.destroy(); checks.push('Maximum 64 concurrent streams enforced'); }
  finally { p.close(); }
}
{
  let remote; const p = await pair(undefined, s => { remote = s; });
  try { const stream = p.A.openStream(); await delay(20); const error = once(remote, 'error'); stream.destroy(new Error('Local cancellation')); assert.match((await withDeadline(error))[0].message, /reset/); checks.push('Reset propagates cancellation to remote stream'); }
  finally { p.close(); }
}
{
  const p = await pair();
  try { const stream = p.A.openStream(); const error = once(stream, 'error'); stream.setTimeout(30); assert.match((await withDeadline(error))[0].message, /idle/); checks.push('Stream idle timeout closes abandoned stream'); }
  finally { p.close(); }
}
async function malformed(bytes, expected) {
  const [attacker, victim] = await sockets(); let closeError;
  const link = createMeshLink(victim, { initiator: false, onStream: () => {}, onClose: e => { closeError = e; } });
  try { attacker.write(bytes); for (let i = 0; i < 100 && !link.closed; i++) await delay(5); assert.equal(link.closed, true); assert.match(closeError.message, expected); }
  finally { link.close(); attacker.destroy(); }
}
{
  const p = await pair(undefined, s => s.resume());
  try {
    const stream = p.A.openStream(); const block = Buffer.alloc(1024 * 1024, 42);
    await withDeadline((async () => { for (let i = 0; i < 128; i++) await new Promise((ok, no) => stream.write(block, error => error ? no(error) : ok())); })(), 20000);
    const error = once(stream, 'error');
    await new Promise(ok => stream.write(Buffer.from('x'), failure => { assert.match(failure.message, /byte limit/); ok(); }));
    assert.match((await withDeadline(error))[0].message, /byte limit/);
    checks.push('Actual 128 MiB transfer succeeds; next byte exceeds stream limit');
  } finally { p.close(); }
}
{
  const originalInterval = globalThis.setInterval; const originalNow = Date.now;
  const ticks = []; let now = originalNow(); let p;
  try {
    globalThis.setInterval = callback => { ticks.push(callback); return originalInterval(() => {}, 1000000000); };
    Date.now = () => now;
    p = await pair(); now += 15000; ticks.forEach(tick => tick()); await delay(20);
    assert.equal(p.A.closed, false); assert.equal(p.B.closed, false);
    p.b.pause(); now += 15000; ticks[0](); await delay(20);
    now += 45000; ticks[0](); assert.equal(p.A.closed, true);
    checks.push('Heartbeat exchange keeps link alive; missing reply closes after timeout');
  } finally { p?.close(); globalThis.setInterval = originalInterval; Date.now = originalNow; }
}
{
  const pending = [];
  const p = await pair(s => { const result = collect(s); s.end(Buffer.from('from-a')); pending.push(result); }, s => { const result = collect(s); s.end(Buffer.from('from-b')); pending.push(result); });
  try {
    const answers = [];
    for (let i = 0; i < 24; i++) {
      const a = p.A.openStream(), b = p.B.openStream();
      answers.push(collect(a), collect(b)); a.end(Buffer.alloc(128 * 1024, i)); b.end(Buffer.alloc(128 * 1024, i + 24));
    }
    const received = await withDeadline(Promise.all(answers));
    assert.equal(received.length, 48);
    for (let i = 0; i < received.length; i++) assert.equal(received[i].toString(), i % 2 ? 'from-a' : 'from-b');
    const payloads = await withDeadline(Promise.all(pending)); assert.equal(payloads.length, 48);
    assert.ok(payloads.every(bytes => bytes.length === 128 * 1024 && bytes.every(byte => byte === bytes[0])));
    checks.push('48 concurrent bidirectional streams transfer six MiB without cross-stream mixing');
  } finally { p.close(); }
}
{
  const [attacker, victim] = await sockets(); let incoming;
  const link = createMeshLink(victim, { initiator: false, onStream: s => { incoming = s; } });
  try {
    const bytes = Buffer.concat([frame(1, 1), frame(2, 1, Buffer.from('fragmented')), frame(3, 1)]);
    for (const byte of bytes) { attacker.write(Buffer.from([byte])); await delay(1); }
    const received = await withDeadline(collect(incoming)); assert.equal(received.toString(), 'fragmented');
    incoming.end(); checks.push('Partial binary headers and payloads reassemble correctly');
  } finally { link.close(); attacker.destroy(); }
}
{
  let remote; const p = await pair(undefined, s => { remote = s; });
  try {
    const stream = p.A.openStream(); await delay(20);
    const errorA = once(stream, 'error'), errorB = once(remote, 'error');
    p.a.destroy(); await withDeadline(Promise.all([errorA, errorB]));
    assert.equal(p.A.closed, true); assert.equal(p.B.closed, true);
    checks.push('Abrupt transport loss closes both links and all streams');
  } finally { p.close(); }
}
await malformed(frame(1, 2), /open/);
await malformed(Buffer.concat([frame(1, 1), frame(1, 1)]), /open/);
await malformed(frame(2, 1, Buffer.from('unknown')), /Unknown/);
await malformed(frame(99, 1), /Unknown/);
await malformed(frame(1, 1, Buffer.from('bad')), /open/);
await malformed(frame(6, 0, Buffer.alloc(1)), /heartbeat/);
await malformed(frame(7, 0, Buffer.alloc(8)), /heartbeat/);
const tooLarge = frame(2, 1); tooLarge.writeUInt32BE(65537, 0); await malformed(tooLarge, /large/);
const excessCredit = Buffer.alloc(4); excessCredit.writeUInt32BE(1); await malformed(Buffer.concat([frame(1, 1), frame(5, 1, excessCredit)]), /credit/);
await malformed(Buffer.concat([frame(1, 1), frame(3, 1), frame(2, 1, Buffer.from('after-end'))]), /end/);
checks.push('Wrong parity, duplicate IDs, unknown streams/types, malformed controls, oversized frames, excess credit, data after end fail closed');
console.log(JSON.stringify({ passed: true, checks }));
