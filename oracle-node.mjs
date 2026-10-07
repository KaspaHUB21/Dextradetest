import tls from 'node:tls';
import net from 'node:net';
import { createHash, createPrivateKey, createPublicKey, X509Certificate, sign, verify, randomBytes, randomInt } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, createWriteStream, renameSync, openSync, closeSync, fsyncSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { chmodSync, statSync, readdirSync, unlinkSync } from 'node:fs';
import { boundedRead, jsonRead, makeJob, makeApiJob, apiEnvironment, extractValues, validateJob, jobHash, validateResult, consume } from './jobs.mjs';
import { discoveryTarget, isDiscoveryAddressAllowed } from './discovery-address.mjs';
import { createMeshLink } from './mesh-link.mjs';
import { createJobQueue, recoverQueueOwner } from './job-queue.mjs';
import { selectWitnessOnce } from './witness-selection.mjs';
import { DEFAULT_BOOTSTRAP, initialBootstraps, pinAcceptsAddress } from './network-defaults.mjs';
import { loadWitnessPolicy, isWitnessAdmitted, publicNotaryCallerAllowed, publicJobCallerAllowed } from './witness-policy.mjs';
import { networkStatus } from './node-status.mjs';
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
let activeDaemon = false;
const links = new Map();
// Relay routes carry only identities authenticated over the relay's live mesh.
// Every relayed connection establishes a separate end-to-end mutual TLS session.
const relayRoutes = new Map();
const PROOF_FILES = ['kucoin.presentation.tlsn', 'node-receipt.json', 'peer-descriptor.json', 'job-spec.json'];
function address(value) {
  const url = new URL('tls://' + value);
  if (!url.hostname || !url.port || url.username || url.password || url.pathname || url.search || url.hash) throw new Error('Use host:port address');
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1025 || port > 65535) throw new Error('Invalid peer port');
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port };
}
function readJson(path) { return JSON.parse(readFileSync(path, 'utf8')); }
function writeJson(path, object) {
  const temp = path + '.' + randomBytes(8).toString('hex') + '.tmp';
  const fd = openSync(temp, 'wx', 0o600);
  try { writeFileSync(fd, JSON.stringify(object, null, 2) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temp, path);
  if (process.platform !== 'win32') { const dir = openSync(dirname(path), 'r'); try { fsyncSync(dir); } finally { closeSync(dir); } }
}
function config() { return readJson(join(DATA, 'config.json')); }
function runtimeConfig() {
  const cfg = config();
  return { ...cfg, seeds: loadWitnessPolicy(DATA, cfg).seeds };
}
function assertCurrentWitness(peer) {
  if (!existsSync(join(DATA, 'config.json'))) return; // Explicit offline --peer-id trust.
  const current = runtimeConfig();
  if (peer.id === current.id) {
    if (peer.notaryPublicKey !== validateDescriptor(readJson(join(DATA, 'descriptor.json'))).notaryPublicKey) throw new Error('Local notary key mismatch');
  } else if (!isWitnessAdmitted(current, peer)) throw new Error('Witness not admitted by current policy');
}
function discoveryMode(cfg) {
  const mode = cfg.discovery || 'closed';
  if (!['closed', 'public', 'local-test'].includes(mode)) throw new Error('Invalid discovery mode');
  return mode;
}
function discoveryPins(cfg) { return [...cfg.seeds, ...(cfg.bootstraps || []), ...(cfg.clients || []).map(id => ({ id, address: null }))]; }
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
  if (value.outboundOnly === true) {
    if (value.address !== null) throw new Error('Outbound-only peer cannot advertise an address');
  } else {
    if (value.outboundOnly !== undefined && value.outboundOnly !== false) throw new Error('Invalid outbound-only declaration');
    address(value.address);
  }
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
function authorizeOutbound(peer, request, cfg) {
  const approved = isWitnessAdmitted(cfg, peer);
  const identityPins = discoveryPins(cfg).filter(seed => seed.id === peer.id);
  if (identityPins.length && !identityPins.some(pin => pinAcceptsAddress(pin, peer.address))) throw new Error('Discovery cannot redirect pinned peer');
  const discoveryOnly = !approved && ['hello', 'link', 'relay', 'relay-deliver'].includes(request.op) && discoveryMode(cfg) !== 'closed';
  // Worker honesty is not assumed: downloaded results require an independently
  // admitted witness's proof. This permission grants only job transport.
  const publicJobTransport = discoveryMode(cfg) === 'public' && ['submit', 'job-status', 'job-result'].includes(request.op);
  if (!approved && !discoveryOnly && !publicJobTransport) throw new Error('Outbound peer is not explicitly approved');
  return !approved;
}
async function exchange(socket, request) {
  socket.on('error', () => {});
  send(socket, { ...request, descriptor: readJson(join(DATA, 'descriptor.json')) });
  try {
    const response = await line(socket);
    if (!response.ok) throw new Error(response.error || 'Peer rejected request');
    return { socket, response };
  } catch (error) { socket.destroy(); throw error; }
}
async function connect(peer, request) {
  const cfg = runtimeConfig(); authorizeOutbound(peer, request, cfg);
  if (activeDaemon) {
    const link = links.get(peer.id);
    if (link && !link.closed) return exchange(link.openStream(), request);
    if (!peer.address && relayRoutes.has(peer.id)) return relayConnect(peer, request);
    return directConnect(peer, request);
  }
  // The local, identity-pinned broker opens streams through the running daemon.
  const socket = tls.connect({ host: '127.0.0.1', port: cfg.notaryPort + 3, ...credentials(), minVersion: 'TLSv1.3', rejectUnauthorized: false });
  socket.on('error', () => {});
  const deadline = setTimeout(() => socket.destroy(new Error('Local node broker timeout; start the node first')), 10000);
  try {
    await new Promise((ok, no) => {
      const done = error => { socket.off('secureConnect', ready); socket.off('error', failed); socket.off('close', closed); error ? no(error) : ok(); };
      const ready = () => done(); const failed = error => done(error); const closed = () => done(new Error('Local broker closed during TLS handshake'));
      socket.once('secureConnect', ready); socket.once('error', failed); socket.once('close', closed);
    });
    if (peerId(socket) !== cfg.id) throw new Error('Local broker identity mismatch');
    send(socket, { op: 'route', targetId: peer.id, request });
    const response = await line(socket);
    if (!response.ok) throw new Error(response.error || 'Peer rejected request');
    return { socket, response };
  } catch (error) { socket.destroy(); throw error; }
  finally { clearTimeout(deadline); }
}
async function directConnect(peer, request) {
  const cfg = runtimeConfig();
  const discoveryOnly = authorizeOutbound(peer, request, cfg);
  if (!peer.address) throw new Error('Outbound-only peer requires an established mesh link');
  if (outbound.size >= 32) throw new Error('Outbound connection limit');
  const mode = discoveryMode(cfg);
  const addressPinned = cfg.seeds.some(pin => pin.id === peer.id && pin.address !== undefined);
  const target = mode !== 'closed' ? await discoveryTarget(peer.address, mode) : !addressPinned && cfg.seeds.some(pin => pin.id === peer.id) ? await discoveryTarget(peer.address, 'public') : address(peer.address);
  if (outbound.size >= 32) throw new Error('Outbound connection limit');
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
    return await exchange(socket, request);
  } catch (e) { socket.destroy(); throw e; } finally { clearTimeout(timer); }
}
async function relayConnect(peer, request) {
  authorizeOutbound(peer, request, runtimeConfig());
  const via = relayRoutes.get(peer.id);
  const link = via && links.get(via);
  if (!link || link.closed) throw new Error('Relay route unavailable');
  const transport = (await exchange(link.openStream(), { op: 'relay', targetId: peer.id })).socket;
  const socket = tls.connect({ socket: transport, ...credentials(), minVersion: 'TLSv1.3', rejectUnauthorized: false });
  socket.on('error', () => {});
  const timer = setTimeout(() => socket.destroy(new Error('Relayed TLS handshake timeout')), 10000);
  try {
    await new Promise((ok, no) => {
      socket.once('secureConnect', ok); socket.once('error', no);
      socket.once('close', () => no(new Error('Relayed TLS connection closed')));
    });
    if (peerId(socket) !== peer.id) throw new Error('End-to-end relay identity mismatch');
    return await exchange(socket, request);
  } catch (error) { socket.destroy(); transport.destroy(); throw error; }
  finally { clearTimeout(timer); }
}
async function request(peer, body) {
  const { socket, response } = await connect(peer, body);
  socket.end(); socket.destroy(); return response;
}
async function init() {
  if (existsSync(join(DATA, 'config.json')) || existsSync(join(DATA, 'identity.key'))) throw new Error('Node already exists; identity will not be overwritten');
  const outboundFlag = option('outbound-only', option('address') ? 'false' : 'true');
  if (!['true', 'false'].includes(outboundFlag)) throw new Error('Outbound-only must be true or false');
  const outboundOnly = outboundFlag === 'true';
  if (outboundOnly && option('address')) throw new Error('Outbound-only nodes do not advertise an address');
  const advertised = outboundOnly ? null : option('address', '127.0.0.1:9443');
  if (advertised !== null) address(advertised);
  const listen = option('listen', advertised || '127.0.0.1:9443'); address(listen);
  // Explicit loopback setups retain their isolated default. Normal installations
  // use public discovery and can join through an outbound link behind NAT.
  const localAddress = advertised !== null && isDiscoveryAddressAllowed(address(advertised).host, 'local-test');
  const discovery = discoveryMode({ discovery: option('discovery', localAddress ? 'closed' : 'public') });
  if (outboundOnly) await discoveryTarget(listen, 'local-test');
  if (!outboundOnly && discovery !== 'closed') await discoveryTarget(advertised, discovery);
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
  const descriptor = { version: 1, id, address: advertised, ...(outboundOnly ? { outboundOnly: true } : {}), apiJobs: [1, 2], publicKey, notaryPublicKey: readFileSync(join(DATA, 'notary.pub'), 'utf8').trim() };
  const bytes = Buffer.from(JSON.stringify(descriptor));
  writeJson(join(DATA, 'descriptor.json'), { payload: bytes.toString('base64'), signature: sign(null, Buffer.concat([DOMAIN, bytes]), createPrivateKey(privatePem)).toString('base64') });
  writeJson(join(DATA, 'config.json'), { version: 1, id, listen, address: advertised, outboundOnly, notaryPort: base, seeds: [], bootstraps: initialBootstraps(discovery, id), discovery, witnessTrust: discovery === 'public' ? 'bundled' : 'pinned', publicNotary: discovery === 'public', publicJobs: discovery === 'public' });
  console.log(JSON.stringify({ id, address: advertised, data: DATA }));
}
function addSeed() {
  const cfg = config(); const peer = { address: option('address'), id: option('id') };
  address(peer.address);
  if (!/^[a-f0-9]{64}$/.test(peer.id) || peer.id === cfg.id) throw new Error('Invalid other node ID');
  if ((cfg.clients || []).includes(peer.id)) throw new Error('Identity is already an outbound-only client');
  if ((cfg.bootstraps || []).some(p => p.id === peer.id && !pinAcceptsAddress(p, peer.address))) throw new Error('Conflicting bootstrap address');
  if (!cfg.seeds.some(p => p.id === peer.id) && cfg.seeds.length >= 32) throw new Error('Pinned peer limit reached; remove a seed explicitly');
  cfg.seeds = [...cfg.seeds.filter(p => p.id !== peer.id), peer];
  writeJson(join(DATA, 'config.json'), cfg); console.log('Seed saved; this identity is explicitly trusted for the prototype.');
}
function trustPeer() {
  const cfg = config(); const id = option('id');
  if (!/^[a-f0-9]{64}$/.test(id) || id === cfg.id) throw new Error('Invalid other node identity');
  const known = jsonRead(join(DATA, 'peers.json')).find(p => p.id === id && p.confirmed && Date.now() - p.lastSeen < 30000);
  if (!known) throw new Error('Peer must be freshly authenticated and discovered first');
  const desc = validateDescriptor(known.descriptor);
  if (!cfg.seeds.some(p => p.id === id) && cfg.seeds.length >= 32) throw new Error('Pinned peer limit reached');
  cfg.seeds = [...cfg.seeds.filter(p => p.id !== id), { id, address: desc.address, notaryPublicKey: desc.notaryPublicKey }];
  cfg.clients = (cfg.clients || []).filter(value => value !== id);
  writeJson(join(DATA, 'config.json'), cfg);
  console.log('Authenticated peer approved for jobs and witnessing. Restart node to apply.');
}
function allowClient(remove = false) {
  const cfg = config(); const id = option('id'); const clients = cfg.clients || [];
  if (!/^[a-f0-9]{64}$/.test(id) || id === cfg.id) throw new Error('Invalid client identity');
  if (remove) {
    if (!clients.includes(id)) throw new Error('Unknown authorized client');
    cfg.clients = clients.filter(value => value !== id);
  } else {
    if ([...cfg.seeds, ...(cfg.bootstraps || [])].some(p => p.id === id)) throw new Error('Identity already has a dialable peer pin');
    if (!clients.includes(id) && clients.length >= 32) throw new Error('Authorized client limit reached');
    cfg.clients = [...new Set([...clients, id])];
  }
  writeJson(join(DATA, 'config.json'), cfg);
  console.log('Client authorization saved. Restart node to apply. Client is not a trusted witness.');
}
async function addBootstrap() {
  const cfg = config(); const peer = { address: option('address'), id: option('id') };
  if (peer.id === DEFAULT_BOOTSTRAP.id && peer.address === DEFAULT_BOOTSTRAP.address) peer.descriptorAddress = DEFAULT_BOOTSTRAP.descriptorAddress;
  if (!/^[a-f0-9]{64}$/.test(peer.id) || peer.id === cfg.id) throw new Error('Invalid bootstrap identity');
  await discoveryTarget(peer.address, discoveryMode(cfg) === 'local-test' ? 'local-test' : 'public');
  if (cfg.seeds.some(p => p.id === peer.id && !pinAcceptsAddress(peer, p.address))) throw new Error('Conflicting trusted peer address');
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
  if (!cfg.outboundOnly && mode !== 'closed') await discoveryTarget(cfg.address, mode);
  if (cfg.outboundOnly) await discoveryTarget(cfg.listen, 'local-test');
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
  const cfg = runtimeConfig();
  activeDaemon = true;
  const mode = discoveryMode(cfg);
  checkLocalIdentity(cfg);
  if (existsSync(join(DATA, 'job-queue.owner'))) throw new Error('Node queue already owned or requires explicit queue-recover after a stopped process');
  if (!cfg.outboundOnly && mode !== 'closed') await discoveryTarget(cfg.address, mode);
  if (cfg.outboundOnly) await discoveryTarget(cfg.listen, 'local-test');
  if (mode === 'local-test') await discoveryTarget(cfg.listen, mode);
  const approved = new Map(cfg.seeds.map(p => [p.id, p]));
  const clients = new Set(cfg.clients || []);
  const pins = new Map(discoveryPins(cfg).map(p => [p.id, p]));
  const peers = new Map(); const incoming = new Set(); const meshStreams = new Set(); const localSockets = new Set(); const ipCounts = new Map();
  const retries = new Map();
  const relaying = new Map();
  const rates = new Map(); let lease; let child; let stopping = false; let releaseTask;
  let launching = false; let restartTimer; let restartAttempts = 0; let server; let timer; let broker;
  let ready;
  const executions = new Set();
  const daemonReady = new Promise(resolveReady => { ready = resolveReady; });
  let queue;
  const executeJob = async spec => {
    await daemonReady;
    if (stopping) throw new Error('Node is stopping');
    const specPath = join(DATA, 'executing-job.json'); writeJson(specPath, spec);
    const controller = new AbortController(); executions.add(controller);
    try {
      const result = await run(process.execPath, [join(ROOT, 'oracle-node.mjs'), 'fetch', '--data', DATA, '--job-spec', specPath], { env: { ...process.env, ORACLE_ENGINE_DIR: BIN }, signal: controller.signal, timeout: 310000, maxBuffer: 1024 * 1024 });
      return JSON.parse(result.stdout.trim());
    } catch (error) { writeFileSync(join(DATA, 'last-job-error.log'), String(error.stderr || error.message).slice(-8192), { mode: 0o600 }); throw error; }
    finally { executions.delete(controller); }
  };
  function rate(key, limit, period) {
    const now = Date.now();
    for (const [name, entry] of rates) if (now >= entry.until) rates.delete(name);
    let entry = rates.get(key);
    if (!entry) { if (rates.size >= 256) return false; entry = { count: 0, until: now + period }; rates.set(key, entry); }
    return ++entry.count <= limit;
  }
  async function remember(envelope, online = false) {
    const desc = validateDescriptor(envelope); const pin = pins.get(desc.id);
    if (desc.id === cfg.id || (pin && !pinAcceptsAddress(pin, desc.address))) return false;
    if (!approved.has(desc.id)) {
      if (mode === 'closed' && !clients.has(desc.id)) return false;
      if (clients.has(desc.id) && !desc.outboundOnly) return false;
      if (!desc.outboundOnly) await discoveryTarget(desc.address, mode);
    }
    if (approved.has(desc.id) && mode !== 'closed' && !desc.outboundOnly) await discoveryTarget(desc.address, mode);
    if (approved.has(desc.id) && mode === 'closed' && approved.get(desc.id).address === undefined && !desc.outboundOnly) await discoveryTarget(desc.address, 'public');
    const previous = peers.get(desc.id);
    if (previous && previous.address !== desc.address) return false;
    if (!previous && !pin && [...peers.values()].filter(p => !pins.has(p.id)).length >= 32) return false;
    if (!previous && peers.size >= 64) {
      if (!pin) return false;
      const evict = [...peers.values()].filter(p => !pins.has(p.id)).sort((a, b) => a.lastSeen - b.lastSeen)[0];
      if (!evict) return false;
      peers.delete(evict.id); retries.delete(evict.id);
    }
    const relayVia = relayRoutes.get(desc.id);
    peers.set(desc.id, { descriptor: envelope, ...desc, dialable: !desc.outboundOnly, trusted: approved.has(desc.id), learnedAt: previous?.learnedAt || Date.now(), lastSeen: online ? Date.now() : (previous?.lastSeen || 0), confirmed: online || Boolean(previous?.confirmed), mesh: Boolean(links.get(desc.id) && !links.get(desc.id).closed), ...(relayVia && links.get(relayVia) && !links.get(relayVia).closed ? { relayVia } : {}) });
    writeJson(join(DATA, 'peers.json'), [...peers.values()]);
    return true;
  }
  // Retain a bounded signed peer cache across restarts. Cached entries are not
  // marked online/trusted until a fresh authenticated connection succeeds.
  if (mode !== 'closed' && existsSync(join(DATA, 'peers.json'))) {
    let cached;
    try { cached = JSON.parse(boundedRead(join(DATA, 'peers.json'), 1024 * 1024)); } catch { cached = []; }
    const cacheStarted = Date.now();
    if (Array.isArray(cached)) for (const entry of cached.slice(0, 32)) {
      if (Date.now() - cacheStarted >= 8000) break;
      try { if (entry.descriptor && !validateDescriptor(entry.descriptor).outboundOnly) await remember(entry.descriptor); } catch {}
    }
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
  async function startupFailure() {
    stopping = true; clearTimeout(restartTimer);
    server?.close(); broker?.close();
    for (const socket of incoming) socket.destroy();
    for (const socket of localSockets) socket.destroy();
    for (const socket of outbound) socket.destroy();
    for (const link of links.values()) link.close();
    for (const controller of executions) controller.abort();
    await queue?.stop().catch(() => {});
    await killNotary();
  }
  try { await launchNotary(); } catch (error) { await startupFailure(); throw error; }
  function attachLink(id, socket, initiator) {
    const old = links.get(id);
    if (old && !old.closed) { socket.destroy(); throw new Error('Peer already has a mesh link'); }
    socket.setTimeout(0);
    let link;
    try { link = createMeshLink(socket, { initiator, onStream: handlePeer, onClose: () => { if (links.get(id) === link) links.delete(id); } }); }
    catch (error) { socket.destroy(); throw error; }
    links.set(id, link); return link;
  }
  function publicStatus(value) {
    const { result, ...status } = value;
    if (result) status.result = { verified: result.verified, nodeId: result.nodeId, peerId: result.peerId, ...(result.values ? { values: result.values } : { price: result.price }) };
    return status;
  }
  function handlePeer(socket) {
    if (socket.socket) {
      if (meshStreams.size >= 128) { socket.destroy(); return; }
      meshStreams.add(socket); socket.once('close', () => meshStreams.delete(socket));
    }
    socket.on('error', () => {});
    socket.setTimeout(15000, () => socket.destroy());
    (async () => {
      const id = peerId(socket);
      if (mode === 'local-test' && !socket.oracleRelayed && !isDiscoveryAddressAllowed(socket.remoteAddress, 'local-test')) throw new Error('Local-test accepts loopback connections only');
      // Closed mode preserves admission before parsing; open mode admits discovery only.
      if (!approved.has(id) && !clients.has(id) && mode === 'closed') throw new Error('Peer identity not approved');
      if (!rate('peer:' + id, 90, 60000)) throw new Error('Peer request rate exceeded');
      const msg = await line(socket);
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new Error('Invalid peer request');
      const desc = validateDescriptor(msg.descriptor);
      if (desc.id !== id || (pins.has(id) && !pinAcceptsAddress(pins.get(id), desc.address))) throw new Error('Descriptor does not match pinned peer');
      const current = runtimeConfig(); // Recheck live policy expiry and revocation.
      const admitted = isWitnessAdmitted(current, desc);
      if (!admitted && !clients.has(id) && !['hello', 'link', 'relay', 'relay-deliver'].includes(msg.op) && !publicNotaryCallerAllowed(current, msg.op) && !publicJobCallerAllowed(current, msg.op)) throw new Error('Peer identity not approved for jobs or notary sessions');
      // Inbound TLS proves possession of a key, not reachability of its advertised address.
      if (!await remember(msg.descriptor, approved.has(id) || desc.outboundOnly === true)) throw new Error('Peer discovery admission rejected');
      if (msg.op === 'hello' || msg.op === 'link') {
        const shared = [...peers.values()].filter(p => p.dialable && p.confirmed && Date.now() - p.lastSeen < 30000 && p.id !== id);
        const offset = shared.length ? randomInt(shared.length) : 0;
        if (msg.op === 'link' && links.get(id) && !links.get(id).closed) throw new Error('Peer already linked');
        const relayCandidates = [...peers.values()].filter(p => p.outboundOnly && p.id !== id && links.get(p.id) && !links.get(p.id).closed);
        const relayOffset = relayCandidates.length ? randomInt(relayCandidates.length) : 0;
        const relayedPeers = [...relayCandidates.slice(relayOffset), ...relayCandidates.slice(0, relayOffset)].slice(0, 8).map(p => p.descriptor);
        send(socket, { ok: true, descriptor: readJson(join(DATA, 'descriptor.json')), notaryReady: Boolean(child && !lease && !releaseTask && !launching), peers: [...shared.slice(offset), ...shared.slice(0, offset)].slice(0, 32).map(p => p.descriptor), relayedPeers });
        if (msg.op === 'link') attachLink(id, socket, false); else socket.end(); return;
      }
      if (msg.op === 'relay-deliver') {
        // Only a live mesh neighbor may deliver an opaque tunnel. Its assertion
        // grants no identity: the inner TLS certificate is checked by handlePeer.
        if (!socket.socket || !links.get(id) || links.get(id).closed) throw new Error('Relay delivery requires live mesh');
        send(socket, { ok: true });
        const inner = new tls.TLSSocket(socket, { isServer: true, secureContext: tls.createSecureContext(credentials()), requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.3' });
        inner.oracleRelayed = true;
        inner.on('error', () => {});
        const deadline = setTimeout(() => inner.destroy(), 10000);
        inner.once('secure', () => { clearTimeout(deadline); if (inner.getProtocol() !== 'TLSv1.3') inner.destroy(); else handlePeer(inner); });
        inner.once('close', () => clearTimeout(deadline));
        socket.resume(); return;
      }
      if (msg.op === 'relay') {
        if (!socket.socket || !/^[a-f0-9]{64}$/.test(msg.targetId) || msg.targetId === id || msg.targetId === cfg.id) throw new Error('Invalid relay target');
        const destination = links.get(msg.targetId);
        const active = [...relaying.values()].reduce((a, b) => a + b, 0);
        if (!destination || destination.closed || active >= 8 || (relaying.get(id) || 0) >= 4 || !rate('relay:global', 60, 60000) || !rate('relay:' + id, 30, 60000)) throw new Error('Relay unavailable or rate limited');
        relaying.set(id, (relaying.get(id) || 0) + 1);
        let tunnel;
        const deadline = setTimeout(() => { socket.destroy(); tunnel?.destroy(); }, 310000);
        let cleaned = false;
        const cleanup = () => { if (cleaned) return; cleaned = true; clearTimeout(deadline); const remaining = (relaying.get(id) || 1) - 1; remaining ? relaying.set(id, remaining) : relaying.delete(id); socket.destroy(); tunnel?.destroy(); };
        socket.once('close', cleanup);
        try {
          tunnel = (await exchange(destination.openStream(), { op: 'relay-deliver' })).socket;
          tunnel.once('close', cleanup); send(socket, { ok: true });
          socket.pipe(tunnel); tunnel.pipe(socket); socket.resume(); tunnel.resume();
        } catch (error) { cleanup(); throw error; }
        return;
      }
      if (msg.op === 'submit' || msg.op === 'submit-series') {
        if (!admitted && !clients.has(id) && (msg.op !== 'submit' || !rate('public-submit:global', 4, 60000) || !rate('public-submit:' + id, 2, 60000))) throw new Error('Public job admission limit exceeded');
        if (!rate('submit:' + id, 12, 60000)) throw new Error('Job submission rate exceeded');
        if (msg.op === 'submit-series') {
          const jobs = await queue.submitBatch({ specs: msg.specs, requesterId: id });
          send(socket, { ok: true, jobs: jobs.map(publicStatus) });
        } else {
          const status = await queue.submit({ spec: msg.spec, requesterId: id });
          send(socket, { ok: true, ...publicStatus(status) });
        }
        socket.end(); return;
      }
      if (msg.op === 'job-status' || msg.op === 'job-result') {
        const status = queue.status(msg.queueId, id);
        if (msg.op === 'job-status') { send(socket, { ok: true, ...publicStatus(status) }); socket.end(); return; }
        if (status.status !== 'completed' || !status.result?.job) throw new Error('Job result is not ready');
        const bundle = Buffer.from(JSON.stringify(Object.fromEntries(PROOF_FILES.map(name => [name, boundedRead(join(status.result.job, name), 2 * 1024 * 1024).toString('base64')]))));
        if (bundle.length > 8 * 1024 * 1024) throw new Error('Job proof bundle too large');
        send(socket, { ok: true, size: bundle.length }); socket.end(bundle); return;
      }
      if (msg.op === 'reserve') {
        if (lease || releaseTask || launching || !child || child.exitCode !== null) throw new Error('Notary busy or unavailable');
        if (!admitted && !clients.has(id) && !rate('public-reserve:global', 6, 60000)) throw new Error('Public notary admission limit exceeded');
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
  }
  server = tls.createServer({ ...credentials(), requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.3', handshakeTimeout: 10000 }, handlePeer);
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
  catch (error) { await startupFailure(); throw error; }
  server.on('error', error => { console.error('Peer listener failed:', error.message); stop(1).catch(() => {}); });
  broker = tls.createServer({ ...credentials(), requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.3', handshakeTimeout: 5000 }, socket => {
    localSockets.add(socket); socket.once('close', () => localSockets.delete(socket));
    socket.on('error', () => {}); socket.setTimeout(10000, () => socket.destroy());
    (async () => {
      if (peerId(socket) !== cfg.id) throw new Error('Local broker requires own node identity');
      const msg = await line(socket);
      if (msg.op !== 'route' || !/^[a-f0-9]{64}$/.test(msg.targetId) || !msg.request || typeof msg.request.op !== 'string' || msg.request.op === 'link') throw new Error('Invalid local route');
      const peer = peers.get(msg.targetId) || cfg.seeds.find(p => p.id === msg.targetId);
      if (!peer) throw new Error('Unknown target peer');
      const remote = await connect(peer, msg.request);
      send(socket, remote.response);
      socket.setTimeout(120000, () => socket.destroy());
      socket.once('close', () => remote.socket.destroy()); remote.socket.once('close', () => socket.end());
      socket.pipe(remote.socket); remote.socket.pipe(socket); socket.resume(); remote.socket.resume();
    })().catch(error => { if (!socket.destroyed) { send(socket, { ok: false, error: error.message }); socket.end(); } });
  });
  broker.maxConnections = 32;
  try { await new Promise((ok, no) => { broker.once('error', no); broker.listen(cfg.notaryPort + 3, '127.0.0.1', ok); }); }
  catch (error) { await startupFailure(); throw error; }
  broker.on('error', error => { console.error('Local broker failed:', error.message); stop(1).catch(() => {}); });
  try { queue = createJobQueue({ data: DATA, nodeId: cfg.id, execute: executeJob }); }
  catch (error) { await startupFailure(); throw error; }
  ready();
  console.log('NODE READY', cfg.address || 'outbound-only');
  let probing = false;
  const probe = async () => {
    if (probing || stopping) return; probing = true;
    try {
      const began = Date.now(); let pruned = false;
      for (const [id, via] of relayRoutes) if (!links.get(via) || links.get(via).closed) { relayRoutes.delete(id); const peer = peers.get(id); if (peer?.relayVia) { delete peer.relayVia; pruned = true; } }
      for (const p of peers.values()) if (!pins.has(p.id) && Date.now() - (p.lastSeen || p.learnedAt) > 120000) { links.get(p.id)?.close(); peers.delete(p.id); retries.delete(p.id); relayRoutes.delete(p.id); pruned = true; }
      if (pruned) writeJson(join(DATA, 'peers.json'), [...peers.values()]);
      const candidates = new Map(cfg.seeds.filter(p => p.address || links.has(p.id)).map(p => [p.id, p]));
      if (mode !== 'closed') {
        for (const p of (cfg.bootstraps || [])) candidates.set(p.id, p);
        for (const p of peers.values()) if ((p.dialable || relayRoutes.has(p.id)) && !candidates.has(p.id)) candidates.set(p.id, p);
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
        // Relayed probes consume finite shared transport slots; reserve room for
        // actual jobs while keeping successful observations inside freshness.
        if (relayRoutes.has(peer.id) && peer.lastSeen && Date.now() - peer.lastSeen < 15000) return;
        try {
          if (!links.get(peer.id) && peer.address) {
            // Stable initiator ordering avoids both public peers racing to open duplicate links.
            if (cfg.outboundOnly || !peer.outboundOnly && cfg.id < peer.id || (cfg.bootstraps || []).some(p => p.id === peer.id)) {
              const opened = await directConnect(peer, { op: 'link' });
              const desc = validateDescriptor(opened.response.descriptor);
              if (desc.id !== peer.id || !(pins.get(peer.id)?.descriptorAddress ? pinAcceptsAddress(pins.get(peer.id), desc.address) : desc.address === peer.address)) { opened.socket.destroy(); throw new Error('Mesh descriptor mismatch'); }
              attachLink(peer.id, opened.socket, true);
            }
          }
          const response = await request(peer, { op: 'hello' });
          const desc = validateDescriptor(response.descriptor);
          if (desc.id !== peer.id || !(pins.get(peer.id)?.descriptorAddress ? pinAcceptsAddress(pins.get(peer.id), desc.address) : desc.address === peer.address)) throw new Error('Unexpected peer descriptor');
          if (!await remember(response.descriptor, true)) throw new Error('Peer admission rejected');
          peers.get(peer.id).notaryReady = response.notaryReady === true;
          writeJson(join(DATA, 'peers.json'), [...peers.values()]);
          retries.delete(peer.id);
          if (mode !== 'closed' && Array.isArray(response.peers)) {
            const offered = response.peers.slice(0, 32); const offerOffset = offered.length ? randomInt(offered.length) : 0;
            for (const discovered of [...offered.slice(offerOffset), ...offered.slice(0, offerOffset)].slice(0, 4)) {
              if (Date.now() - began > 15000 || stopping) break;
              try { if (!validateDescriptor(discovered).outboundOnly) await remember(discovered); } catch {}
            }
          }
          if (mode !== 'closed' && Array.isArray(response.relayedPeers) && links.get(peer.id) && !links.get(peer.id).closed) {
            for (const envelope of response.relayedPeers.slice(0, 8)) {
              try {
                const relayed = validateDescriptor(envelope);
                if (relayed.outboundOnly && await remember(envelope)) relayRoutes.set(relayed.id, peer.id);
              } catch { /* Unverified route advertisements are never used. */ }
            }
          }
        } catch (error) {
          const failedPeer = peers.get(peer.id);
          if (failedPeer) { failedPeer.lastError = String(error.message).slice(0, 160); writeJson(join(DATA, 'peers.json'), [...peers.values()]); }
          const failures = Math.min(6, (retry?.failures || 0) + 1);
          retries.set(peer.id, { failures, after: Date.now() + Math.min(60000, 1000 * 2 ** failures) });
          if (retries.size > 72) retries.delete(retries.keys().next().value);
        }
        }));
      }
    } finally { probing = false; }
  };
  timer = setInterval(() => { probe().catch(() => {}); if (lease && Date.now() - lease.started > 300000) release().catch(() => {}); }, 5000);
  async function stop(exitCode = 0) {
    if (stopping) return; stopping = true; clearInterval(timer); clearTimeout(restartTimer);
    for (const controller of executions) controller.abort();
    await queue?.stop().catch(() => {});
    broker.close(); for (const socket of localSockets) socket.destroy(); for (const link of links.values()) link.close();
    server.close(); for (const s of incoming) s.destroy(); for (const s of outbound) s.destroy();
    invalidateLease(); if (releaseTask) await releaseTask.catch(() => {}); await killNotary(); process.exit(exitCode);
  }
  process.once('SIGINT', () => stop().catch(() => process.exit(1)));
  process.once('SIGTERM', () => stop().catch(() => process.exit(1)));
  probe().catch(() => {});
}

async function fetchApi() {
  const cfg = runtimeConfig();
  checkLocalIdentity(cfg);
  const jobsDir = join(DATA, 'jobs');
  if (existsSync(jobsDir) && readdirSync(jobsDir).length >= 1000) throw new Error('Job storage limit reached; archive completed jobs before fetching');
  const specPath = option('job-spec');
  const spec = specPath ? validateJob(jsonRead(resolve(specPath))) : makeJob();
  if (Date.now() < spec.notBefore || Date.now() > spec.notAfter) throw new Error('Job is stale or not yet executable');
  const peers = existsSync(join(DATA, 'peers.json')) ? readJson(join(DATA, 'peers.json')) : [];
  const eligible = peers.filter(p => isWitnessAdmitted(cfg, p) && p.id !== cfg.id && p.confirmed && Date.now() - p.lastSeen < 30000 && p.notaryReady !== false && (p.dialable || p.mesh || p.relayVia) && (spec.version === 1 || p.apiJobs?.includes(2)));
  const selection = selectWitnessOnce({ data: DATA, spec, candidates: eligible });
  const candidates = eligible.filter(p => p.id === selection.id);
  if (!candidates.length) throw new Error('No reachable, explicitly trusted peer; start node and configure seed');
  const selected = candidates[0];
  // Reauthenticate the peer before accepting its current notary key.
  const hello = await request(selected, { op: 'hello' });
  const peer = validateDescriptor(hello.descriptor);
  if (peer.id !== selected.id) throw new Error('Peer changed identity');
  const pin = cfg.seeds.find(p => p.id === peer.id);
  if (pin?.notaryPublicKey && pin.notaryPublicKey !== peer.notaryPublicKey) throw new Error('Pinned notary key changed');
  const tunnels = []; const sockets = new Set();
  const job = join(DATA, 'jobs', Date.now() + '-' + randomBytes(4).toString('hex'));
  mkdirSync(job, { recursive: true, mode: 0o700 });
  writeJson(join(job, 'job-spec.json'), spec);
  writeJson(join(job, 'witness-selection.json'), selection);
  const trustFile = join(job, 'notary.pub'); writeFileSync(trustFile, peer.notaryPublicKey + '\n');
  writeJson(join(job, 'peer-descriptor.json'), hello.descriptor);
  const { token } = await request(peer, { op: 'reserve' });
  try {
    const env = { ...process.env, ...apiEnvironment(spec), JOB_CHALLENGE: jobHash(spec), OUTPUT_DIR: job, TRUSTED_NOTARY_KEY: trustFile, PRESENTATION_FILE: join(job, 'kucoin.presentation.tlsn') };
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
    const cancellation = new AbortController();
    const cancel = () => cancellation.abort();
    process.once('SIGTERM', cancel); process.once('SIGINT', cancel);
    try {
      for (const binary of ['prove', 'present', 'verify']) {
        const result = await run(join(BIN, binary), [], { cwd: DATA, env, signal: cancellation.signal, timeout: 300000, maxBuffer: 4 * 1024 * 1024 });
        writeFileSync(join(job, binary + '.log'), result.stdout + result.stderr);
      }
    } finally { process.off('SIGTERM', cancel); process.off('SIGINT', cancel); }
    const result = readJson(join(job, 'kucoin.verified.json.tlsn'));
    const transcript = validateResult(result, spec, Date.now(), true);
    if (result.jobChallenge !== jobHash(spec)) throw new Error('Authenticated API request does not bind expected job');
    const proof = boundedRead(join(job, 'kucoin.presentation.tlsn'));
    if (!isWitnessAdmitted(runtimeConfig(), peer)) throw new Error('Witness admission changed during job');
    const output = spec.version === 2 ? { values: extractValues(result.response, spec.api) } : { price: result.price };
    const receipt = { version: 2, nodeId: cfg.id, peerId: peer.id, notaryPublicKey: peer.notaryPublicKey, job: spec, jobSha256: jobHash(spec), ...transcript, presentationSha256: sha(proof), ...output, completedAt: new Date().toISOString() };
    const payload = Buffer.from(JSON.stringify(receipt));
    writeJson(join(job, 'node-receipt.json'), { payload: payload.toString('base64'), signature: sign(null, Buffer.concat([Buffer.from('oracle-node-prototype/receipt/v1\0'), payload]), createPrivateKey(credentials().key)).toString('base64'), descriptor: readJson(join(DATA, 'descriptor.json')) });
    console.log(JSON.stringify({ verified: true, nodeId: cfg.id, peerId: peer.id, ...output, job }));
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
  if (peer.id === nodeId) throw new Error('Worker cannot witness its own execution');
  if (peer.id !== expectedPeer || receipt.nodeId !== nodeId || receipt.peerId !== peer.id || receipt.notaryPublicKey !== peer.notaryPublicKey) throw new Error('Unexpected peer or notary');
  if (receipt.presentationSha256 !== sha(boundedRead(join(job, 'kucoin.presentation.tlsn')))) throw new Error('Presentation changed since node signed it');
  // Derive the TLSNotary key from the separately pinned peer identity, not an arbitrary PEM in the job.
  const trust = join(job, 'verify-trusted-notary.pub'); writeFileSync(trust, peer.notaryPublicKey + '\n');
  assertCurrentWitness(peer);
  await run(join(BIN, 'verify'), [], { env: { ...process.env, ...apiEnvironment(expected), JOB_CHALLENGE: jobHash(expected), OUTPUT_DIR: job, TRUSTED_NOTARY_KEY: trust, PRESENTATION_FILE: join(job, 'kucoin.presentation.tlsn') }, timeout: 30000, maxBuffer: 1024 * 1024 });
  const result = jsonRead(join(job, 'kucoin.verified.json.tlsn'), 512 * 1024);
  const transcript = validateResult(result, expected, Date.now(), Boolean(expectedPath));
  if (result.jobChallenge !== jobHash(expected) || transcript.requestSha256 !== receipt.requestSha256 || transcript.responseSha256 !== receipt.responseSha256) throw new Error('Receipt does not match authenticated job request/response');
  const output = spec.version === 2 ? { values: extractValues(result.response, spec.api) } : { price: result.price };
  if (spec.version === 2 ? JSON.stringify(output.values) !== JSON.stringify(receipt.values) : result.price !== receipt.price) throw new Error('Receipt values differ from authenticated API response');
  assertCurrentWitness(peer); // Do not publish a result revoked during verification.
  if (expectedPath) consume(resolve(option('state', join(DATA, 'verification-ledger.json'))), expected, receipt.presentationSha256);
  console.log(JSON.stringify({ verified: true, accepted: Boolean(expectedPath), mode: expectedPath ? 'submission' : 'inspection', nodeId, peerId: peer.id, ...output, jobId: spec.id, execution: spec.execution }));
}
function jobPeer() {
  const cfg = runtimeConfig(); checkLocalIdentity(cfg);
  const id = option('peer-id');
  const pin = cfg.seeds.find(p => p.id === id);
  if (pin) return pin;
  const observed = jsonRead(join(DATA, 'peers.json')).find(peer => peer.id === id && peer.confirmed && Date.now() - peer.lastSeen < 30000);
  if (cfg.discovery !== 'public' || !observed) throw new Error('Job worker must be a freshly authenticated discovered peer or an explicitly approved peer');
  return observed;
}
async function enableNetwork() {
  const cfg = config(); checkLocalIdentity(cfg);
  if (!cfg.outboundOnly) await discoveryTarget(cfg.address, 'public');
  cfg.discovery = 'public';
  cfg.witnessTrust = option('witness-trust', 'bundled');
  if (!['bundled', 'pinned'].includes(cfg.witnessTrust)) throw new Error('Invalid witness trust profile');
  for (const name of ['public-notary', 'public-jobs']) if (!['true', 'false'].includes(option(name, 'true'))) throw new Error('Public service flags must be true or false');
  cfg.publicNotary = option('public-notary', 'true') === 'true';
  cfg.publicJobs = option('public-jobs', 'true') === 'true';
  cfg.bootstraps = [...(cfg.bootstraps || []).filter(peer => peer.id !== DEFAULT_BOOTSTRAP.id), ...initialBootstraps('public', cfg.id)];
  loadWitnessPolicy(DATA, cfg); // Validate before committing configuration.
  const envelope = readJson(join(DATA, 'descriptor.json'));
  const desc = validateDescriptor(envelope); desc.apiJobs = [1, 2];
  const payload = Buffer.from(JSON.stringify(desc));
  writeJson(join(DATA, 'descriptor.json'), { payload: payload.toString('base64'), signature: sign(null, Buffer.concat([DOMAIN, payload]), createPrivateKey(credentials().key)).toString('base64') });
  writeJson(join(DATA, 'config.json'), cfg);
  console.log('Public network profile enabled, witness trust: ' + cfg.witnessTrust + '. Restart node after updating native engines.');
}
function createJobTemplate() {
  const template = jsonRead(resolve(option('template')));
  const spec = makeApiJob(template.api || template);
  const out = resolve(option('out'));
  if (existsSync(out)) throw new Error('Job output already exists; do not overwrite an execution');
  writeJson(out, spec);
  console.log(JSON.stringify({ job: out, id: spec.id, jobHash: jobHash(spec) }));
}
function configurePolicy() {
  const trust = jsonRead(resolve(option('trust-file')));
  if (!trust || Object.keys(trust).length !== 2 || !Array.isArray(trust.authorities) || !Number.isSafeInteger(trust.threshold)) throw new Error('Supply local authority PEM keys and threshold');
  const cfg = config(); cfg.witnessPolicy = trust;
  // Installing authority trust and its first policy is one explicit operation.
  const envelope = jsonRead(resolve(option('policy-file')), 256 * 1024);
  const path = join(DATA, 'witness-policy.json');
  const previous = existsSync(path) ? readFileSync(path) : null;
  writeJson(path, envelope);
  try { loadWitnessPolicy(DATA, cfg); writeJson(join(DATA, 'config.json'), cfg); }
  catch (error) { previous ? writeFileSync(path, previous, { mode: 0o600 }) : unlinkSync(path); throw error; }
  console.log('Locally trusted policy authorities and threshold policy installed. Restart to refresh discovery routing; admission/revocation is checked on every job.');
}
function submissionPath(queueId) {
  if (!/^[a-f0-9]{64}$/.test(queueId)) throw new Error('Invalid queue identity');
  return join(DATA, 'submitted-jobs', queueId + '.json');
}
async function submitJob() {
  const peer = jobPeer();
  const spec = option('job-spec') ? validateJob(jsonRead(resolve(option('job-spec')))) : makeJob();
  const wait = option('wait', 'false');
  if (!['true', 'false'].includes(wait)) throw new Error('Wait must be true or false');
  const count = Number(option('count', '1'));
  const interval = Number(option('interval-seconds', '0')) * 1000;
  if (!Number.isSafeInteger(count) || count < 1 || count > 32 || !Number.isSafeInteger(interval) || (count > 1 && interval < 10000) || interval < 0 || interval * (count - 1) > 600000) throw new Error('Series requires count 1..32, interval at least 10 seconds, and last execution within 10 minutes');
  const specs = Array.from({ length: count }, (_, i) => validateJob({ ...spec, execution: spec.execution + i, challenge: i ? sha(Buffer.from('oracle-series-v1\0' + spec.challenge + '\0' + (spec.execution + i))) : spec.challenge, notBefore: spec.notBefore + i * interval, notAfter: spec.notAfter + i * interval }));
  const dir = join(DATA, 'submitted-jobs'); mkdirSync(dir, { recursive: true, mode: 0o700 });
  const records = specs.map(value => ({ peerId: peer.id, queueId: sha(Buffer.from(value.id + '\0' + value.execution)), jobHash: jobHash(value), spec: value }));
  if (readdirSync(dir).length + records.filter(r => !existsSync(submissionPath(r.queueId))).length > 1000) throw new Error('Submitted job storage limit reached');
  for (const record of records) {
    const path = submissionPath(record.queueId);
    if (existsSync(path)) {
      const previous = jsonRead(path);
      if (previous.peerId !== peer.id || previous.jobHash !== record.jobHash) throw new Error('Submitted execution already bound to another worker or job');
    }
  }
  // Persist expectations before sending, including when the response is lost.
  for (const record of records) if (!existsSync(submissionPath(record.queueId))) writeJson(submissionPath(record.queueId), record);
  const response = await request(peer, count === 1 ? { op: 'submit', spec } : { op: 'submit-series', specs });
  const statuses = count === 1 ? [response] : response.jobs;
  if (!Array.isArray(statuses) || statuses.length !== records.length || statuses.some((value, i) => value.queueId !== records[i].queueId || value.jobHash !== records[i].jobHash)) throw new Error('Worker returned a different job binding');
  if (wait === 'false') { console.log(JSON.stringify(count === 1 ? { queueId: response.queueId, status: response.status, jobHash: response.jobHash } : { jobs: statuses })); return; }
  const results = [];
  for (const record of records) {
    let done = false;
    while (Date.now() <= record.spec.notAfter) {
      const current = await request(peer, { op: 'job-status', queueId: record.queueId });
      if (current.jobHash !== record.jobHash) throw new Error('Worker changed job binding');
      if (current.status === 'completed') { results.push(await downloadResult(peer, record.queueId, false)); done = true; break; }
      if (current.status === 'failed') throw new Error(current.error?.message || 'Job failed');
      await new Promise(ok => setTimeout(ok, 3000));
    }
    if (!done) throw new Error('Job window expired while waiting');
  }
  console.log(JSON.stringify(count === 1 ? results[0] : { results }));
}
function readBody(socket, size) {
  if (!Number.isSafeInteger(size) || size < 1 || size > 8 * 1024 * 1024) throw new Error('Invalid proof bundle size');
  return new Promise((ok, no) => {
    const chunks = []; let length = 0;
    const timer = setTimeout(() => finish(new Error('Proof download timeout')), 30000);
    const data = chunk => { length += chunk.length; if (length > size) return finish(new Error('Proof exceeds declared size')); chunks.push(chunk); if (length === size) finish(); };
    const closed = () => finish(new Error('Incomplete proof download'));
    function finish(error) { clearTimeout(timer); socket.off('data', data); socket.off('close', closed); socket.off('end', closed); socket.off('error', finish); socket.pause(); error ? no(error) : ok(Buffer.concat(chunks)); }
    socket.on('data', data); socket.once('close', closed); socket.once('end', closed); socket.once('error', finish); socket.resume();
  });
}
async function downloadResult(peer, queueId, print = true) {
  const saved = jsonRead(submissionPath(queueId));
  if (saved.peerId !== peer.id) throw new Error('Result worker does not match submitted job');
  const { socket, response } = await connect(peer, { op: 'job-result', queueId });
  let bundle;
  try { bundle = JSON.parse(await readBody(socket, response.size)); } finally { socket.destroy(); }
  if (!bundle || Object.keys(bundle).length !== PROOF_FILES.length || PROOF_FILES.some(name => typeof bundle[name] !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(bundle[name]))) throw new Error('Invalid proof bundle contents');
  const jobs = join(DATA, 'jobs'); mkdirSync(jobs, { recursive: true, mode: 0o700 });
  if (readdirSync(jobs).length >= 1000) throw new Error('Job storage limit reached');
  const job = join(jobs, 'received-' + queueId.slice(0, 16) + '-' + randomBytes(4).toString('hex')); mkdirSync(job, { mode: 0o700 });
  for (const name of PROOF_FILES) {
    const bytes = Buffer.from(bundle[name], 'base64');
    if (bytes.length > 2 * 1024 * 1024 || bytes.toString('base64') !== bundle[name]) throw new Error('Invalid proof encoding or size');
    writeFileSync(join(job, name), bytes, { mode: 0o600 });
  }
  const receipt = JSON.parse(Buffer.from(jsonRead(join(job, 'node-receipt.json')).payload, 'base64'));
  const cfg = runtimeConfig();
  const notary = cfg.seeds.find(p => p.id === receipt.peerId);
  if (!notary && receipt.peerId !== cfg.id) throw new Error('Result witness is not independently approved');
  const witness = validateDescriptor(jsonRead(join(job, 'peer-descriptor.json')));
  if (notary?.notaryPublicKey && witness.notaryPublicKey !== notary.notaryPublicKey || receipt.peerId === cfg.id && witness.notaryPublicKey !== validateDescriptor(readJson(join(DATA, 'descriptor.json'))).notaryPublicKey) throw new Error('Result notary key differs from independent pin');
  const expected = join(job, 'expected-job.json'); writeJson(expected, validateJob(saved.spec));
  const result = await run(process.execPath, [join(ROOT, 'oracle-node.mjs'), 'verify', '--data', DATA, '--job', job, '--node-id', peer.id, '--peer-id', receipt.peerId, '--expected-job', expected], { env: { ...process.env, ORACLE_ENGINE_DIR: BIN }, timeout: 40000, maxBuffer: 1024 * 1024 });
  const verified = { ...JSON.parse(result.stdout.trim()), job };
  if (print) console.log(JSON.stringify(verified));
  return verified;
}
async function jobStatus() {
  const peer = jobPeer(); const queueId = option('queue-id');
  const saved = jsonRead(submissionPath(queueId));
  if (saved.peerId !== peer.id) throw new Error('Unexpected worker for submitted job');
  const response = await request(peer, { op: 'job-status', queueId });
  if (response.jobHash !== saved.jobHash) throw new Error('Status does not match submitted job');
  delete response.ok; console.log(JSON.stringify(response));
}
async function main() {
  const flags = {
    'network-enable': ['data', 'witness-trust', 'public-notary', 'public-jobs'],
    'job-create': ['data', 'template', 'out'], 'policy-configure': ['data', 'trust-file', 'policy-file'], status: ['data'],
    init: ['data', 'address', 'listen', 'notary-port', 'discovery', 'outbound-only'], 'add-seed': ['data', 'address', 'id'], 'remove-seed': ['data', 'id'],
    'add-bootstrap': ['data', 'address', 'id'], 'remove-bootstrap': ['data', 'id'], discovery: ['data', 'mode'],
    'allow-client': ['data', 'id'], 'remove-client': ['data', 'id'],
    'trust-peer': ['data', 'id'], 'queue-recover': ['data', 'pid'], submit: ['data', 'peer-id', 'job-spec', 'wait', 'interval-seconds', 'count'], 'job-status': ['data', 'peer-id', 'queue-id'], 'job-result': ['data', 'peer-id', 'queue-id'],
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
  if (command === 'network-enable') return enableNetwork();
  if (command === 'job-create') return createJobTemplate();
  if (command === 'policy-configure') return configurePolicy();
  if (command === 'status') { const cfg = runtimeConfig(); console.log(JSON.stringify(networkStatus(cfg, existsSync(join(DATA, 'peers.json')) ? readJson(join(DATA, 'peers.json')) : [], cfg.seeds), null, 2)); return; }
  if (command === 'add-seed') return addSeed();
  if (command === 'remove-seed') return removeSeed();
  if (command === 'allow-client') return allowClient();
  if (command === 'trust-peer') return trustPeer();
  if (command === 'queue-recover') { recoverQueueOwner(DATA, { expectedPid: Number(option('pid')) }); console.log('Stopped queue owner recovered. Interrupted executions will fail without repetition.'); return; }
  if (command === 'submit') return submitJob();
  if (command === 'job-status') return jobStatus();
  if (command === 'job-result') return downloadResult(jobPeer(), option('queue-id'));
  if (command === 'remove-client') return allowClient(true);
  if (command === 'add-bootstrap') return addBootstrap();
  if (command === 'remove-bootstrap') return removeBootstrap();
  if (command === 'discovery') return setDiscovery();
  if (command === 'renew-cert') return renewCertificate();
  if (command === 'start') return start();
  if (command === 'fetch') return fetchApi();
  if (command === 'verify') return verifyJob();
  if (command === 'peers') { console.log(JSON.stringify(existsSync(join(DATA, 'peers.json')) ? readJson(join(DATA, 'peers.json')) : [], null, 2)); return; }
  throw new Error('Commands: ' + Object.keys(flags).join(', ') + '; use --data DIRECTORY');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
