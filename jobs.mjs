import { createHash, randomBytes } from 'node:crypto';
import { readSync, statSync, fstatSync, fsyncSync, openSync, closeSync, writeFileSync, renameSync, mkdirSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';

export const API = Object.freeze({ server: 'api.kucoin.com', path: '/api/v1/market/orderbook/level1?symbol=KAS-USDT', method: 'GET', symbol: 'KAS-USDT' });
export function validateApi(api) {
  const keys = ['server', 'path', 'method', 'extract'];
  if (!api || typeof api !== 'object' || Array.isArray(api) || Object.keys(api).length !== keys.length || Object.keys(api).some(k => !keys.includes(k))) throw new Error('Invalid API schema');
  if (typeof api.server !== 'string' || api.server.length > 253 || api.server !== api.server.toLowerCase() || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(api.server) || /\.(?:localhost|local|internal|test|invalid|example|onion)$/.test(api.server)) throw new Error('API must use a public DNS hostname');
  if (api.method !== 'GET' || typeof api.path !== 'string' || api.path.length > 1024 || !/^\/[\x21-\x7e]*$/.test(api.path) || api.path.startsWith('//') || /[#\\]/.test(api.path) || /%(?![a-fA-F0-9]{2})/.test(api.path)) throw new Error('API supports bounded GET paths only');
  if (!Array.isArray(api.extract) || api.extract.length < 1 || api.extract.length > 16) throw new Error('API needs one to sixteen extraction fields');
  const names = new Set();
  const extract = api.extract.map(field => {
    if (!field || Object.keys(field).length !== 3 || Object.keys(field).some(k => !['name','pointer','type'].includes(k)) || typeof field.name !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(field.name) || ['constructor','prototype','__proto__'].includes(field.name) || names.has(field.name) || typeof field.pointer !== 'string' || field.pointer.length > 256 || !/^(?:\/(?:[^~\x00-\x1f]|~[01])*)*$/.test(field.pointer) || !['string','number','boolean','decimal'].includes(field.type)) throw new Error('Invalid JSON extraction field');
    names.add(field.name); return { name: field.name, pointer: field.pointer, type: field.type };
  });
  return { server: api.server, path: api.path, method: 'GET', extract };
}
export function extractValues(response, api) {
  const values = Object.create(null);
  for (const field of validateApi(api).extract) {
    let value = response;
    for (const segment of field.pointer === '' ? [] : field.pointer.slice(1).split('/').map(v => v.replace(/~1/g, '/').replace(/~0/g, '~'))) {
      if (value === null || typeof value !== 'object' || !Object.hasOwn(value, segment)) throw new Error('Missing authenticated JSON field: ' + field.name);
      value = value[segment];
    }
    const valid = field.type === 'decimal' ? typeof value === 'string' && /^-?\d{1,20}(\.\d{1,20})?$/.test(value) : typeof value === field.type && (field.type !== 'number' || (Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)))) && (field.type !== 'string' || value.length <= 4096);
    if (!valid) throw new Error('Unexpected authenticated JSON field type: ' + field.name);
    values[field.name] = value;
  }
  return values;
}
export const apiEnvironment = job => ({ API_SERVER: validateJob(job).api.server, API_PATH: validateJob(job).api.path, API_GENERIC: job.version === 2 ? '1' : '0' });
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function boundedRead(path, limit = 8 * 1024 * 1024) {
  const fd = openSync(path, 'r');
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error('Input file exceeds size limit or is not a regular file');
    const data = Buffer.alloc(limit + 1);
    let total = 0;
    while (total < data.length) {
      const n = readSync(fd, data, total, data.length - total, null);
      if (!n) break;
      total += n;
    }
    if (total > limit) throw new Error('Input file exceeds size limit');
    return data.subarray(0, total);
  } finally { closeSync(fd); }
}
export function jsonRead(path, limit = 128 * 1024) {
  if (statSync(path).size > limit) throw new Error('Input file exceeds size limit');
  return JSON.parse(boundedRead(path, limit));
}
export function validateJob(job) {
  const keys = ['version', 'id', 'execution', 'challenge', 'notBefore', 'notAfter', 'api'];
  if (!job || typeof job !== 'object' || Array.isArray(job) || Object.keys(job).length !== keys.length || Object.keys(job).some(k => !keys.includes(k))) throw new Error('Invalid job schema');
  if (![1, 2].includes(job.version) || typeof job.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(job.id) || !Number.isSafeInteger(job.execution) || job.execution < 0 || typeof job.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(job.challenge)) throw new Error('Invalid job identity or challenge');
  if (!Number.isSafeInteger(job.notBefore) || !Number.isSafeInteger(job.notAfter) || job.notBefore < 0 || job.notAfter <= job.notBefore || job.notAfter - job.notBefore > 600000) throw new Error('Invalid job execution window (maximum ten minutes)');
  if (job.version === 2) return { version: 2, id: job.id, execution: job.execution, challenge: job.challenge, notBefore: job.notBefore, notAfter: job.notAfter, api: validateApi(job.api) };
  if (!job.api || typeof job.api !== 'object' || Array.isArray(job.api) || Object.keys(job.api).length !== Object.keys(API).length || Object.entries(API).some(([k,v]) => job.api[k] !== v)) throw new Error('Unsupported API specification');
  return { version: 1, id: job.id, execution: job.execution, challenge: job.challenge, notBefore: job.notBefore, notAfter: job.notAfter, api: { ...API } };
}
export function makeJob(now = Date.now()) {
  return validateJob({ version: 1, id: 'local-' + randomBytes(12).toString('hex'), execution: 0, challenge: randomBytes(32).toString('hex'), notBefore: now - 2000, notAfter: now + 300000, api: { ...API } });
}
export function makeApiJob(api, now = Date.now()) {
  return validateJob({ ...makeJob(now), version: 2, api: validateApi(api) });
}
export const jobHash = job => hash(JSON.stringify(validateJob(job)));
export function selectWitness(job, seeds) {
  const ids = [...new Set(seeds.map(s => s.id))].sort();
  if (!ids.length || ids.some(id => !/^[a-f0-9]{64}$/.test(id))) throw new Error('No valid pinned witnesses');
  const index = Number(BigInt('0x' + hash('oracle-witness-v1\0' + jobHash(job))) % BigInt(ids.length));
  return ids[index];
}
export function validateResult(result, job, now = Date.now(), live = false) {
  validateJob(job);
  if (result?.jobChallenge !== jobHash(job)) throw new Error('Authenticated API request does not bind expected job');
  if (job.version === 2) {
    if (result?.verified !== true || result.server !== job.api.server || result.path !== job.api.path || result.method !== 'GET') throw new Error('Unexpected authenticated API result');
    extractValues(result.response, job.api);
  } else if (result?.verified !== true || result.server !== API.server || result.path !== API.path || result.symbol !== API.symbol || typeof result.price !== 'string' || !/^\d{1,20}(\.\d{1,20})?$/.test(result.price)) throw new Error('Unexpected authenticated API result');
  if (!Number.isSafeInteger(result.tlsSessionTimeSeconds)) throw new Error('Missing authenticated session time');
  const time = result.tlsSessionTimeSeconds * 1000;
  // TLSNotary reports whole seconds: test overlap with that one-second interval.
  if (time + 999 < job.notBefore || time > job.notAfter) throw new Error('TLS proof is outside expected job window');
  if (live && (now < job.notBefore || now > job.notAfter)) throw new Error('Job is stale or not yet executable');
  for (const name of ['requestHex', 'responseHex']) if (typeof result[name] !== 'string' || result[name].length > 256 * 1024 || !/^(?:[a-f0-9]{2})+$/.test(result[name])) throw new Error('Invalid authenticated transcript');
  return { requestSha256: hash(Buffer.from(result.requestHex, 'hex')), responseSha256: hash(Buffer.from(result.responseHex, 'hex')) };
}
export function consume(path, job, proofHash) {
  validateJob(job);
  if (typeof proofHash !== 'string' || !/^[a-f0-9]{64}$/.test(proofHash)) throw new Error('Invalid proof hash');
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let lock;
  try { lock = openSync(path + '.lock', 'wx', 0o600); } catch { throw new Error('Replay ledger busy; retry without changing the job'); }
  try {
    let state = { version: 1, jobs: {}, proofs: {} };
    try { state = jsonRead(path, 8 * 1024 * 1024); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (state.version !== 1 || !state.jobs || typeof state.jobs !== 'object' || Array.isArray(state.jobs) || !state.proofs || typeof state.proofs !== 'object' || Array.isArray(state.proofs)) throw new Error('Invalid replay ledger');
    const id = hash(job.id + '\0' + job.execution);
    if (Object.hasOwn(state.jobs, id) || Object.hasOwn(state.proofs, proofHash)) throw new Error('Replay rejected: job execution or TLS proof already consumed');
    if (Object.keys(state.jobs).length >= 10000) throw new Error('Replay ledger full; archive policy required');
    state.jobs[id] = jobHash(job); state.proofs[proofHash] = id;
    const temp = path + '.' + randomBytes(8).toString('hex') + '.tmp';
    const fd = openSync(temp, 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify(state)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path);
    if (process.platform !== 'win32') {
      const dirFd = openSync(dirname(path), 'r');
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    }
  } finally { closeSync(lock); unlinkSync(path + '.lock'); }
}
