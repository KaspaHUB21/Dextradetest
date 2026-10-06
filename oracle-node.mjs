import tls from 'node:tls';
import net from 'node:net';
import { createHash, createPrivateKey, createPublicKey, X509Certificate, sign, verify, randomBytes, randomInt } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, createWriteStream, renameSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { chmodSync, statSync, readdirSync, unlinkSync } from 'node:fs';
import { boundedRead, jsonRead, makeJob, validateJob, jobHash, selectWitness, validateResult, consume } from './jobs.mjs';
import { discoveryTarget, isDiscoveryAddressAllowed } from './discovery-address.mjs';
const run = promisify(execFile);
const ROOT = dirname(fileURLToPath(import.meta.url));
const BIN = process.env.ORACLE_ENGINE_DIR || join(ROOT, 'bin');
const DOMAIN = Buffer.from('oracle-node-prototype/descriptor/v1\0');
const args = process.argv.slice(2);
const command = args.shift();
function option(name, fallback) { const i = args.indexOf('--' + name); return i < 0 ? fallback : args[i + 1]; }
const DATA = resolve(option('data', './node-data'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const keyId = key => sha(createPublicKey(key).export({ type: 'spki', format: 'der' }));
const outbound = new Set();
function address(value) {
  const url = new URL('tls://' + value);
  if (!url.hostname || !url.port || url.username || url.password || url.pathname || url.search || url.hash) throw new Error('Use host:port address');
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1025 || port > 65535) throw new Error('Invalid peer port');
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port };
}
function readJson(path) { return JSON.parse(readFileSync(path, 'utf8')); }
function writeJson(path, object) { const temp = path + '.' + randomBytes(4).toString('hex') + '.tmp'; writeFileSync(temp, JSON.stringify(object, null, 2) + '\n', { mode: 0o600 }); renameSync(temp, path); }
function config() { return readJson(join(DATA, 'config.json')); }
function discoveryMode(cfg) {
  const mode = cfg.discovery || 'closed';
  if (!['closed', 'public', 'local-test'].includes(mode)) throw new Error('Invalid discovery mode');
  return mode;
}
function discoveryPins(cfg) { return [...cfg.seeds, ...(cfg.bootstraps || [])]; }
function credentials() { return { key: readFileSync(join(DATA, 'identity.key')), cert: readFileSync(join(DATA, 'identity.crt')) }; }
function validateDescriptor(envelope) {
  if (typeof envelope?.payload !== 'string' || envelope.payload.length > 16000 || typeof envelope.signature !== 'string') throw new Error('Invalid descriptor');
  const bytes = Buffer.from(envelope.payload, 'base64');
  const value = JSON.parse(bytes);
  if (value.version !== 1 || !/^[a-f0-9]{64}$/.test(value.id)) throw new Error('Invalid identity');
  const pub = createPublicKey(value.publicKey);
  if (pub.asymmetricKeyType !== 'ed25519' || keyId(value.publicKey) !== value.id ||
      !verify(null, Buffer.concat([DOMAIN, bytes]), pub, Buffer.from(envelope.signature, 'base64'))) throw new Error('Invalid descriptor signature');
  if (!/^(02|03)[a-f0-9]{64}$/.test(value.notaryPublicKey)) throw new Error('Invalid notary key');
  address(value.address);
  return value;
}
function peerId(socket) {
  const raw = socket.getPeerCertificate().raw;
  if (!raw) throw new Error('Peer certificate missing');
  const cert = new X509Certificate(raw);
  if (Date.now() < Date.parse(cert.validFrom) || Date.now() > Date.parse(cert.validTo)) throw new Error('Peer certificate expired');
  return sha(cert.publicKey.export({ type: 'spki', format: 'der' }));
}
function send(socket, value) { socket.write(JSON.stringify(value) + '\n'); }
function line(socket) {
  return new Promise((resolveLine, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => { socket.off('data', data); socket.off('error', error); socket.off('close', closed); clearTimeout(timer); };
    const error = e => { cleanup(); reject(e); };
    const closed = () => error(new Error('Peer closed connection'));
    const data = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 128 * 1024) return error(new Error('Peer message too large'));
      const pos = buffer.indexOf(10);
      if (pos < 0) return;
      socket.pause(); cleanup();
      if (pos + 1 < buffer.length) socket.unshift(buffer.subarray(pos + 1));
      try { resolveLine(JSON.parse(buffer.subarray(0, pos))); } catch (e) { reject(e); }
    };
    const timer = setTimeout(() => error(new Error('Peer message timeout')), 10000);
    socket.on('data', data); socket.once('error', error); socket.once('close', closed); socket.resume();
  });
}
async function connect(peer, request) {
  const cfg = config();
  const approved = cfg.seeds.find(seed => seed.id === peer.id && seed.address === peer.address);
  const pin = discoveryPins(cfg).find(seed => seed.id === peer.id);
  if (pin && pin.address !== peer.address) throw new Error('Discovery cannot redirect pinned peer');
  const discoveryOnly = !approved && request.op === 'hello' && discoveryMode(cfg) !== 'closed';
  if (!approved && !discoveryOnly) throw new Error('Outbound peer is not explicitly approved at this address');
  if (outbound.size >= 32) throw new Error('Outbound connection limit');
  const target = discoveryOnly ? await discoveryTarget(peer.address, discoveryMode(cfg)) : address(peer.address);
  const socket = tls.connect({ ...target, ...credentials(), minVersion: 'TLSv1.3', rejectUnauthorized: false });
  outbound.add(socket); socket.once('close', () => outbound.delete(socket));
  socket.on('error', () => {});
  const timer = setTimeout(() => socket.destroy(new Error('Connection timeout')), 10000);
  try {
    await new Promise((ok, no) => {
      const done = error => { socket.off('secureConnect', ready); socket.off('error', failed); socket.off('close', closed); error ? no(error) : ok(); };
      const ready = () => done(); const failed = error => done(error); const closed = () => done(new Error('Peer closed during TLS handshake'));
      socket.once('secureConnect', ready); socket.once('error', failed); socket.once('close', closed);
    });
    if (peerId(socket) !== peer.id) throw new Error('Peer identity does not match pinned ID');
    send(socket, { ...request, descriptor: readJson(join(DATA, 'descriptor.json')) });
    const response = await line(socket);
    if (!response.ok) throw new Error(response.error || 'Peer rejected request');
    return { socket, response };
  } catch (e) { socket.destroy(); throw e; } finally { clearTimeout(timer); }
}
async function request(peer, body) {
  const { socket, response } = await connect(peer, body);
  socket.end(); socket.destroy(); return response;
}
async function init() {
  if (existsSync(join(DATA, 'config.json')) || existsSync(join(DATA, 'identity.key'))) throw new Error('Node already exists; identity will not be overwritten');
  const advertised = option('address', '127.0.0.1:9443'); address(advertised);
  const listen = option('listen', advertised); address(listen);
  const discovery = discoveryMode({ discovery: option('discovery', 'closed') });
  if (discovery !== 'closed') await discoveryTarget(advertised, discovery);
  if (discovery === 'local-test') await discoveryTarget(listen, discovery);
  const base = Number(option('notary-port', '17047'));
  if (!Number.isInteger(base) || base < 1025 || base > 65532) throw new Error('Invalid internal port');
  mkdirSync(DATA, { recursive: true, mode: 0o700 });
  await run('openssl', ['req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '365', '-subj', '/CN=oracle-node-prototype', '-keyout', join(DATA, 'identity.key'), '-out', join(DATA, 'identity.crt')]);
  chmodSync(join(DATA, 'identity.key'), 0o600);
  const privatePem = readFileSync(join(DATA, 'identity.key'));
  const publicKey = createPublicKey(privatePem).export({ type: 'spki', format: 'pem' });
  const id = keyId(privatePem);
  await run(join(BIN, 'notary'), ['init'], { cwd: DATA });
  chmodSync(join(DATA, 'notary.key'), 0o600);
  const descriptor = { version: 1, id, address: advertised, publicKey, notaryPublicKey: readFileSync(join(DATA, 'notary.pub'), 'utf8').trim() };
  const bytes = Buffer.from(JSON.stringify(descriptor));
  writeJson(join(DATA, 'descriptor.json'), { payload: bytes.toString('base64'), signature: sign(null, Buffer.concat([DOMAIN, bytes]), createPrivateKey(privatePem)).toString('base64') });
  writeJson(join(DATA, 'config.json'), { version: 1, id, listen, address: advertised, notaryPort: base, seeds: [], bootstraps: [], discovery });
  console.log(JSON.stringify({ id, address: advertised, data: DATA }));
}
function addSeed() {
  const cfg = config(); const peer = { address: option('address'), id: option('id') };
  address(peer.address);
  if (!/^[a-f0-9]{64}$/.test(peer.id) || peer.id === cfg.id) throw new Error('Invalid other node ID');
  if ((cfg.bootstraps || []).some(p => p.id === peer.id && p.address !== peer.address)) throw new Error('Conflicting bootstrap address');
  if (!cfg.seeds.some(p => p.id === peer.id) && cfg.seeds.length >= 32) throw new Error('Pinned peer limit reached; remove a seed explicitly');
  cfg.seeds = [...cfg.seeds.filter(p => p.id !== peer.id), peer];
  writeJson(join(DATA, 'config.json'), cfg); console.log('Seed saved; this identity is explicitly trusted for the prototype.');
}
async function addBootstrap() {
  const cfg = config(); const peer = { address: option('address'), id: option('id') };
  if (!/^[a-f0-9]{64}$/.test(peer.id) || peer.id === cfg.id) throw new Error('Invalid bootstrap identity');
  await discoveryTarget(peer.address, discoveryMode(cfg) === 'local-test' ? 'local-test' : 'public');
  if (cfg.seeds.some(p => p.id === peer.id && p.address !== peer.address)) throw new Error('Conflicting trusted peer address');
  const old = cfg.bootstraps || [];
  if (!old.some(p => p.id === peer.id) && old.length >= 8) throw new Error('Bootstrap limit reached');
  cfg.bootstraps = [...old.filter(p => p.id !== peer.id), peer]; writeJson(join(DATA, 'config.json'), cfg);
  console.log('Bootstrap saved for discovery only; no witness trust granted. Restart node to apply.');
}
function removeBootstrap() {
  const cfg = config(); const id = option('id');
  if (!(cfg.bootstraps || []).some(p => p.id === id)) throw new Error('Unknown bootstrap ID');
  cfg.bootstraps = cfg.bootstraps.filter(p => p.id !== id); writeJson(join(DATA, 'config.json'), cfg);
  console.log('Bootstrap removed. Restart node to apply.');
}
async function setDiscovery() {
  const cfg = config(); const mode = discoveryMode({ discovery: option('mode') });
  if (!option('mode')) throw new Error('Discovery mode required');
  if (mode !== 'closed') await discoveryTarget(cfg.address, mode);
  if (mode === 'local-test') await discoveryTarget(cfg.listen, mode);
  cfg.discovery = mode; writeJson(join(DATA, 'config.json'), cfg);
  console.log('Discovery mode saved. Restart node to apply.');
}
function removeSeed() {
  const cfg = config(); const id = option('id');
  if (!/^[a-f0-9]{64}$/.test(id) || !cfg.seeds.some(p => p.id === id)) throw new Error('Unknown pinned peer ID');
  cfg.seeds = cfg.seeds.filter(p => p.id !== id);
  writeJson(join(DATA, 'config.json'), cfg);
  console.log('Peer pin removed. Restart the running node to revoke inbound authorization.');
}
function checkLocalIdentity(cfg) {
  const keyPath = join(DATA, 'identity.key');
  if (keyId(boundedRead(keyPath, 16384)) !== cfg.id) throw new Error('Local private key does not match configured identity');
  if (process.platform !== 'win32' && (statSync(keyPath).mode & 0o077)) throw new Error('Private identity key must have mode 0600');
}
async function renewCertificate() {
  const cfg = config(); checkLocalIdentity(cfg);
  const temp = join(DATA, 'identity.crt.' + randomBytes(8).toString('hex') + '.tmp');
  try {
    await run('openssl', ['req', '-x509', '-key', join(DATA, 'identity.key'), '-days', '365', '-subj', '/CN=oracle-node-prototype', '-out', temp], { timeout: 10000 });
    const cert = new X509Certificate(boundedRead(temp, 16384));
    if (sha(cert.publicKey.export({ type: 'spki', format: 'der' })) !== cfg.id) throw new Error('Renewed certificate identity mismatch');
    renameSync(temp, join(DATA, 'identity.crt'));
    console.log('Certificate renewed with unchanged identity. Restart node to load it. Compromised keys require a new identity and updated pins.');
  } finally { if (existsSync(temp)) unlinkSync(temp); }
}
async function start() {
  const cfg = config();
  const mode = discoveryMode(cfg);
  checkLocalIdentity(cfg);
  if (mode !== 'closed') await discoveryTarget(cfg.address, mode);
  if (mode === 'local-test') await discoveryTarget(cfg.listen, mode);
  const approved = new Map(cfg.seeds.map(p => [p.id, p]));
  const pins = new Map(discoveryPins(cfg).map(p => [p.id, p]));
  const peers = new Map(); const incoming = new Set(); const ipCounts = new Map();
  const retries = new Map();
  const rates = new Map(); let lease; let child; let stopping = false; let releaseTask;
  let launching = false; let restartTimer; let restartAttempts = 0; let server; let timer;
  function rate(key, limit, period) {
    const now = Date.now();
    for (const [name, entry] of rates) if (now >= entry.until) rates.delete(name);
    let entry = rates.get(key);
    if (!entry) { if (rates.size >= 256) return false; entry = { count: 0, until: now + period }; rates.set(key, entry); }
    return ++entry.count <= limit;
  }
  async function remember(envelope, online = false) {
    const desc = validateDescriptor(envelope); const pin = pins.get(desc.id);
    if (desc.id === cfg.id || (pin && pin.address !== desc.address)) return false;
    if (!approved.has(desc.id)) {
      if (mode === 'closed') return false;
      await discoveryTarget(desc.address, mode);
    }
    const previous = peers.get(desc.id);
    if (previous && previous.address !== desc.address) return false;
    if (!previous && !pin && [...peers.values()].filter(p => !pins.has(p.id)).length >= 32) return false;
    if (!previous && peers.size >= 64) {
      if (!pin) return false;
      const evict = [...peers.values()].filter(p => !pins.has(p.id)).sort((a, b) => a.lastSeen - b.lastSeen)[0];
      if (!evict) return false;
      peers.delete(evict.id); retries.delete(evict.id);
    }
    peers.set(desc.id, { descriptor: envelope, ...desc, trusted: approved.has(desc.id), learnedAt: previous?.learnedAt || Date.now(), lastSeen: online ? Date.now() : (previous?.lastSeen || 0), confirmed: online || Boolean(previous?.confirmed) });
    writeJson(join(DATA, 'peers.json'), [...peers.values()]);
    return true;
  }
  function invalidateLease() {
    const previous = lease; lease = undefined;
    if (previous) for (const socket of previous.sockets) socket.destroy();
  }
  async function killNotary() {
    const previous = child; child = undefined;
    if (!previous || previous.exitCode !== null || previous.signalCode !== null) return;
    await new Promise(ok => {
      const timer = setTimeout(() => { previous.kill('SIGKILL'); }, 2000);
      const deadline = setTimeout(done, 5000);
      function done() { clearTimeout(timer); clearTimeout(deadline); previous.off('exit', done); ok(); }
      previous.once('exit', done); previous.kill('SIGTERM');
    });
  }
  function scheduleRestart() {
    if (stopping || launching || releaseTask || restartTimer || restartAttempts >= 5) return;
    restartTimer = setTimeout(() => {
      restartTimer = undefined; restartAttempts++;
      launchNotary().catch(() => scheduleRestart());
    }, Math.min(30000, 1000 * 2 ** restartAttempts));
  }
  async function launchNotary() {
    if (launching || stopping) return;
    launching = true;
    const log = createWriteStream(join(DATA, 'notary.log'), { flags: 'w', mode: 0o600 });
    log.on('error', () => { /* Logging failure must not crash the network service. */ });
    let logBytes = 0;
    const instance = spawn(join(BIN, 'notary'), [], { cwd: DATA, env: { ...process.env, NOTARY_BASE_PORT: String(cfg.notaryPort) }, stdio: ['ignore', 'pipe', 'pipe'] });
    child = instance;
    const logData = data => { if (logBytes + data.length <= 8 * 1024 * 1024) { logBytes += data.length; log.write(data); } };
    instance.stdout.on('data', logData); instance.stderr.on('data', logData);
    instance.on('error', () => {});
    instance.once('close', () => log.end());
    instance.once('exit', () => {
      if (child === instance) { child = undefined; invalidateLease(); scheduleRestart(); }
    });
    try {
      await new Promise((ok, no) => {
        let readyText = '';
        const timer = setTimeout(() => finish(new Error('Notary startup timeout')), 10000);
        const failed = () => finish(new Error('Notary startup failed'));
        const ready = data => { readyText = (readyText + data.toString()).slice(-4096); if (readyText.includes('service ready')) finish(); };
        function finish(error) { clearTimeout(timer); instance.off('error', failed); instance.off('exit', failed); instance.stdout.off('data', ready); error ? no(error) : ok(); }
        instance.once('error', failed); instance.once('exit', failed); instance.stdout.on('data', ready);
      });
    } catch (error) { await killNotary(); throw error; }
    finally { launching = false; }
  }
  async function release() {
    if (releaseTask) return releaseTask;
    if (!lease) return;
    invalidateLease();
    releaseTask = (async () => {
      await killNotary();
      if (!stopping) await launchNotary();
    })();
    try { await releaseTask; } catch (error) { scheduleRestart(); throw error; }
    finally { releaseTask = undefined; if (!child && !stopping) scheduleRestart(); }
  }
  await launchNotary();
  server = tls.createServer({ ...credentials(), requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.3', handshakeTimeout: 10000 }, socket => {
    socket.on('error', () => {});
    socket.setTimeout(15000, () => socket.destroy());
    (async () => {
      const id = peerId(socket);
      if (mode === 'local-test' && !isDiscoveryAddressAllowed(socket.remoteAddress, 'local-test')) throw new Error('Local-test accepts loopback connections only');
      // Closed mode preserves admission before parsing; open mode admits discovery only.
      if (!approved.has(id) && mode === 'closed') throw new Error('Peer identity not approved');
      if (!rate('peer:' + id, 90, 60000)) throw new Error('Peer request rate exceeded');
      const msg = await line(socket);
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('Invalid peer request');
      const desc = validateDescriptor(msg.descriptor);
      if (desc.id !== id || (pins.has(id) && desc.address !== pins.get(id).address)) throw new Error('Descriptor does not match pinned peer');
      if (!approved.has(id) && msg.op !== 'hello') throw new Error('Peer identity not approved for notary sessions');
      // Inbound TLS proves possession of a key, not reachability of its advertised address.
      if (!await remember(msg.descriptor, approved.has(id))) throw new Error('Peer discovery admission rejected');
      if (msg.op === 'hello') {
        const shared = [...peers.values()].filter(p => p.confirmed && Date.now() - p.lastSeen < 30000 && p.id !== id);
        const offset = shared.length ? randomInt(shared.length) : 0;
        send(socket, { ok: true, descriptor: readJson(join(DATA, 'descriptor.json')), peers: [...shared.slice(offset), ...shared.slice(0, offset)].slice(0, 32).map(p => p.descriptor) }); socket.end(); return;
      }
      if (msg.op === 'reserve') {
        if (lease || releaseTask || launching || !child || child.exitCode !== null) throw new Error('Notary busy or unavailable');
        if (!rate('reserve:' + id, 6, 60000)) throw new Error('Reservation rate exceeded');
        lease = { owner: id, token: randomBytes(32).toString('hex'), started: Date.now(), sockets: new Set(), channels: new Set() };
        send(socket, { ok: true, token: lease.token }); socket.end(); return;
      }
      if (!lease || lease.owner !== id || lease.token !== msg.token) throw new Error('Invalid session authorization');
      if (msg.op === 'release') { await release(); send(socket, { ok: true }); socket.end(); return; }
      const offsets = { mpc: 0, control: 1, proxy: 2 };
      if (msg.op !== 'channel' || !Object.hasOwn(offsets, msg.channel) || lease.channels.has(msg.channel)) throw new Error('Invalid or duplicate session channel');
      const session = lease;
      session.channels.add(msg.channel); session.sockets.add(socket);
      const local = net.connect({ host: '127.0.0.1', port: cfg.notaryPort + offsets[msg.channel] });
      session.sockets.add(local); local.on('error', () => socket.destroy());
      socket.once('close', () => { local.destroy(); session.sockets.delete(socket); });
      local.once('close', () => { socket.destroy(); session.sockets.delete(local); });
      local.setTimeout(120000, () => { local.destroy(); socket.destroy(); });
      socket.setTimeout(120000, () => { local.destroy(); socket.destroy(); });
      await new Promise((ok, no) => {
        const timer = setTimeout(() => { local.destroy(); no(new Error('Internal channel timeout')); }, 5000);
        const done = error => { clearTimeout(timer); local.off('connect', success); local.off('error', failed); error ? no(error) : ok(); };
        const success = () => done(); const failed = error => done(error);
        local.once('connect', success); local.once('error', failed);
      });
      if (lease !== session || stopping) throw new Error('Session already ended');
      let bytes = 0;
      const count = data => { bytes += data.length; if (bytes > 128 * 1024 * 1024) { socket.destroy(); local.destroy(); } };
      socket.on('data', count); local.on('data', count);
      send(socket, { ok: true }); socket.pipe(local); local.pipe(socket); socket.resume();
    })().catch(error => { if (!socket.destroyed) { send(socket, { ok: false, error: error.message }); socket.end(); } });
  });
  // Count TCP sockets before the TLS handshake; unauthenticated clients are bounded too.
  server.maxConnections = 64;
  server.on('connection', socket => {
    const ip = socket.remoteAddress || 'unknown'; const count = ipCounts.get(ip) || 0;
    if (incoming.size >= 64 || count >= 8 || !rate('ip:' + ip, 120, 60000)) { socket.destroy(); return; }
    incoming.add(socket); ipCounts.set(ip, count + 1); socket.on('error', () => {});
    socket.once('close', () => { incoming.delete(socket); const left = (ipCounts.get(ip) || 1) - 1; left ? ipCounts.set(ip, left) : ipCounts.delete(ip); });
  });
  server.on('tlsClientError', (_error, socket) => socket.destroy());
  const target = address(cfg.listen);
  try { await new Promise((ok, no) => { server.once('error', no); server.listen(target.port, target.host, ok); }); }
  catch (error) { stopping = true; await killNotary(); throw error; }
  server.on('error', error => { console.error('Peer listener failed:', error.message); stop(1).catch(() => {}); });
  console.log('NODE READY', cfg.address);
  let probing = false;
  const probe = async () => {
    if (probing || stopping) return; probing = true;
    try {
      const began = Date.now(); let pruned = false;
      for (const p of peers.values()) if (!pins.has(p.id) && Date.now() - (p.lastSeen || p.learnedAt) > 120000) { peers.delete(p.id); retries.delete(p.id); pruned = true; }
      if (pruned) writeJson(join(DATA, 'peers.json'), [...peers.values()]);
      const candidates = new Map(cfg.seeds.map(p => [p.id, p]));
      if (mode !== 'closed') {
        for (const p of (cfg.bootstraps || [])) candidates.set(p.id, p);
        for (const p of peers.values()) if (!candidates.has(p.id)) candidates.set(p.id, p);
      }
      const discovered = [...candidates.values()].filter(p => !pins.has(p.id));
      const offset = discovered.length ? randomInt(discovered.length) : 0;
      const pinned = [...candidates.values()].filter(p => pins.has(p.id));
      const pinOffset = pinned.length ? randomInt(pinned.length) : 0;
      const batch = [...pinned.slice(pinOffset), ...pinned.slice(0, pinOffset)].slice(0, 8).concat([...discovered.slice(offset), ...discovered.slice(0, offset)].slice(0, 4));
      // Every discovered dial resolves to a checked numeric IP; gossip never grants witness trust.
      for (let pos = 0; pos < batch.length; pos += 4) {
        if (Date.now() - began > 15000 || stopping) break;
        await Promise.allSettled(batch.slice(pos, pos + 4).map(async peer => {
        if (stopping) return;
        const retry = retries.get(peer.id);
        if (retry && Date.now() < retry.after) return;
        try {
          const response = await request(peer, { op: 'hello' });
          const desc = validateDescriptor(response.descriptor);
          if (desc.id !== peer.id || desc.address !== peer.address) throw new Error('Unexpected peer descriptor');
          if (!await remember(response.descriptor, true)) throw new Error('Peer admission rejected');
          retries.delete(peer.id);
          if (mode !== 'closed' && Array.isArray(response.peers)) {
            const offered = response.peers.slice(0, 32); const offerOffset = offered.length ? randomInt(offered.length) : 0;
            for (const discovered of [...offered.slice(offerOffset), ...offered.slice(0, offerOffset)].slice(0, 4)) {
              if (Date.now() - began > 15000 || stopping) break;
              try { await remember(discovered); } catch {}
            }
          }
        } catch {
          const failures = Math.min(6, (retry?.failures || 0) + 1);
          retries.set(peer.id, { failures, after: Date.now() + Math.min(60000, 1000 * 2 ** failures) });
          if (retries.size > 72) retries.delete(retries.keys().next().value);
        }
        }));
      }
    } finally { probing = false; }
  };
  timer = setInterval(() => { probe().catch(() => {}); if (lease && Date.now() - lease.started > 300000) release().catch(() => {}); }, 5000);
  const stop = async (exitCode = 0) => {
    if (stopping) return; stopping = true; clearInterval(timer); clearTimeout(restartTimer);
    server.close(); for (const s of incoming) s.destroy(); for (const s of outbound) s.destroy();
    invalidateLease(); if (releaseTask) await releaseTask.catch(() => {}); await killNotary(); process.exit(exitCode);
  };
  process.once('SIGINT', () => stop().catch(() => process.exit(1)));
  process.once('SIGTERM', () => stop().catch(() => process.exit(1)));
  probe().catch(() => {});
}

async function fetchApi() {
  const cfg = config();
  checkLocalIdentity(cfg);
  const jobsDir = join(DATA, 'jobs');
  if (existsSync(jobsDir) && readdirSync(jobsDir).length >= 1000) throw new Error('Job storage limit reached; archive completed jobs before fetching');
  const specPath = option('job-spec');
  const spec = specPath ? validateJob(jsonRead(resolve(specPath))) : makeJob();
  if (Date.now() < spec.notBefore || Date.now() > spec.notAfter) throw new Error('Job is stale or not yet executable');
  const peers = existsSync(join(DATA, 'peers.json')) ? readJson(join(DATA, 'peers.json')) : [];
  const chosenId = selectWitness(spec, cfg.seeds);
  const candidates = peers.filter(p => p.id === chosenId && Date.now() - p.lastSeen < 30000);
  if (!candidates.length) throw new Error('No reachable, explicitly trusted peer; start node and configure seed');
  const selected = candidates[0];
  // Reauthenticate the peer before accepting its current notary key.
  const hello = await request(selected, { op: 'hello' });
  const peer = validateDescriptor(hello.descriptor);
  if (peer.id !== selected.id) throw new Error('Peer changed identity');
  const tunnels = []; const sockets = new Set();
  const job = join(DATA, 'jobs', Date.now() + '-' + randomBytes(4).toString('hex'));
  mkdirSync(job, { recursive: true, mode: 0o700 });
  writeJson(join(job, 'job-spec.json'), spec);
  const trustFile = join(job, 'notary.pub'); writeFileSync(trustFile, peer.notaryPublicKey + '\n');
  writeJson(join(job, 'peer-descriptor.json'), hello.descriptor);
  const { token } = await request(peer, { op: 'reserve' });
  try {
    const env = { ...process.env, JOB_CHALLENGE: jobHash(spec), OUTPUT_DIR: job, TRUSTED_NOTARY_KEY: trustFile, PRESENTATION_FILE: join(job, 'kucoin.presentation.tlsn') };
    for (const channel of ['control', 'mpc', 'proxy']) {
      const localServer = net.createServer(local => {
        sockets.add(local); local.pause(); local.on('error', () => {});
        connect(peer, { op: 'channel', token, channel }).then(({ socket }) => {
          sockets.add(socket); local.once('close', () => socket.destroy()); socket.once('close', () => local.destroy());
          local.pipe(socket); socket.pipe(local); local.resume(); socket.resume();
        }).catch(error => local.destroy(error));
      });
      await new Promise(ok => localServer.listen(0, '127.0.0.1', ok)); tunnels.push(localServer);
      env[channel.toUpperCase() + '_ADDR'] = '127.0.0.1:' + localServer.address().port;
    }
    for (const binary of ['prove', 'present', 'verify']) {
      const result = await run(join(BIN, binary), [], { cwd: DATA, env, timeout: 300000, maxBuffer: 4 * 1024 * 1024 });
      writeFileSync(join(job, binary + '.log'), result.stdout + result.stderr);
    }
    const result = readJson(join(job, 'kucoin.verified.json.tlsn'));
    const transcript = validateResult(result, spec, Date.now(), true);
    if (result.jobChallenge !== jobHash(spec)) throw new Error('Authenticated API request does not bind expected job');
    const proof = boundedRead(join(job, 'kucoin.presentation.tlsn'));
    const receipt = { version: 2, nodeId: cfg.id, peerId: peer.id, notaryPublicKey: peer.notaryPublicKey, job: spec, jobSha256: jobHash(spec), ...transcript, presentationSha256: sha(proof), price: result.price, completedAt: new Date().toISOString() };
    const payload = Buffer.from(JSON.stringify(receipt));
    writeJson(join(job, 'node-receipt.json'), { payload: payload.toString('base64'), signature: sign(null, Buffer.concat([Buffer.from('oracle-node-prototype/receipt/v1\0'), payload]), createPrivateKey(credentials().key)).toString('base64'), descriptor: readJson(join(DATA, 'descriptor.json')) });
    console.log(JSON.stringify({ verified: true, nodeId: cfg.id, peerId: peer.id, price: result.price, job }));
  } finally {
    for (const socket of sockets) socket.destroy(); for (const server of tunnels) server.close();
    await request(peer, { op: 'release', token }).catch(() => {});
  }
}
async function verifyJob() {
  if (!option('job')) throw new Error('Supply --job DIRECTORY');
  const job = resolve(option('job', ''));
  const nodeId = option('node-id'); const expectedPeer = option('peer-id');
  if (!nodeId || !expectedPeer) throw new Error('Supply independently trusted --node-id and --peer-id');
  const envelope = jsonRead(join(job, 'node-receipt.json'));
  if (typeof envelope?.payload !== 'string' || envelope.payload.length > 16000 || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.payload) || !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature)) throw new Error('Invalid node receipt envelope');
  const node = validateDescriptor(envelope.descriptor);
  const bytes = Buffer.from(envelope.payload, 'base64');
  if (node.id !== nodeId || !verify(null, Buffer.concat([Buffer.from('oracle-node-prototype/receipt/v1\0'), bytes]), createPublicKey(node.publicKey), Buffer.from(envelope.signature, 'base64'))) throw new Error('Invalid node receipt identity or signature');
  const receipt = JSON.parse(bytes);
  if (receipt.version !== 2) throw new Error('Unsupported receipt version; regenerate proof with job binding');
  const spec = validateJob(receipt.job);
  if (receipt.jobSha256 !== jobHash(spec)) throw new Error('Invalid job binding');
  const expectedPath = option('expected-job');
  const expected = expectedPath ? validateJob(jsonRead(resolve(expectedPath))) : spec;
  if (jobHash(expected) !== receipt.jobSha256) throw new Error('Receipt does not match independently expected job');
  const peer = validateDescriptor(jsonRead(join(job, 'peer-descriptor.json')));
  if (peer.id !== expectedPeer || receipt.nodeId !== nodeId || receipt.peerId !== peer.id || receipt.notaryPublicKey !== peer.notaryPublicKey) throw new Error('Unexpected peer or notary');
  if (receipt.presentationSha256 !== sha(boundedRead(join(job, 'kucoin.presentation.tlsn')))) throw new Error('Presentation changed since node signed it');
  // Derive the TLSNotary key from the separately pinned peer identity, not an arbitrary PEM in the job.
  const trust = join(job, 'verify-trusted-notary.pub'); writeFileSync(trust, peer.notaryPublicKey + '\n');
  await run(join(BIN, 'verify'), [], { env: { ...process.env, JOB_CHALLENGE: jobHash(expected), OUTPUT_DIR: job, TRUSTED_NOTARY_KEY: trust, PRESENTATION_FILE: join(job, 'kucoin.presentation.tlsn') }, timeout: 30000, maxBuffer: 1024 * 1024 });
  const result = jsonRead(join(job, 'kucoin.verified.json.tlsn'), 512 * 1024);
  const transcript = validateResult(result, expected, Date.now(), Boolean(expectedPath));
  if (result.jobChallenge !== jobHash(expected) || transcript.requestSha256 !== receipt.requestSha256 || transcript.responseSha256 !== receipt.responseSha256) throw new Error('Receipt does not match authenticated job request/response');
  if (result.price !== receipt.price) throw new Error('Receipt price differs from authenticated API response');
  if (expectedPath) consume(resolve(option('state', join(DATA, 'verification-ledger.json'))), expected, receipt.presentationSha256);
  console.log(JSON.stringify({ verified: true, accepted: Boolean(expectedPath), mode: expectedPath ? 'submission' : 'inspection', nodeId, peerId: peer.id, price: result.price, jobId: spec.id, execution: spec.execution }));
}
async function main() {
  const flags = {
    init: ['data', 'address', 'listen', 'notary-port', 'discovery'], 'add-seed': ['data', 'address', 'id'], 'remove-seed': ['data', 'id'],
    'add-bootstrap': ['data', 'address', 'id'], 'remove-bootstrap': ['data', 'id'], discovery: ['data', 'mode'],
    'renew-cert': ['data'], start: ['data'], peers: ['data'], fetch: ['data', 'job-spec'], verify: ['data', 'job', 'node-id', 'peer-id', 'expected-job', 'state']
  };
  const allowed = flags[command];
  if (allowed) {
    const seen = new Set();
    for (let i = 0; i < args.length; i += 2) {
      const name = args[i]?.slice(2);
      if (!args[i]?.startsWith('--') || !allowed.includes(name) || seen.has(name) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Unknown, duplicate, or missing CLI option');
      seen.add(name);
    }
  }
  if (command === 'init') return init();
  if (command === 'add-seed') return addSeed();
  if (command === 'remove-seed') return removeSeed();
  if (command === 'add-bootstrap') return addBootstrap();
  if (command === 'remove-bootstrap') return removeBootstrap();
  if (command === 'discovery') return setDiscovery();
  if (command === 'renew-cert') return renewCertificate();
  if (command === 'start') return start();
  if (command === 'fetch') return fetchApi();
  if (command === 'verify') return verifyJob();
  if (command === 'peers') { console.log(JSON.stringify(existsSync(join(DATA, 'peers.json')) ? readJson(join(DATA, 'peers.json')) : [], null, 2)); return; }
  throw new Error('Commands: init, add-seed, remove-seed, add-bootstrap, remove-bootstrap, discovery, renew-cert, start, peers, fetch, verify; use --data DIRECTORY');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
