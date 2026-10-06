import { createHash, randomBytes } from 'node:crypto';
import { readSync, statSync, fstatSync, fsyncSync, openSync, closeSync, writeFileSync, renameSync, mkdirSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';

export const API = Object.freeze({ server: 'api.kucoin.com', path: '/api/v1/market/orderbook/level1?symbol=KAS-USDT', method: 'GET', symbol: 'KAS-USDT' });
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
  if (job.version !== 1 || typeof job.id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(job.id) || !Number.isSafeInteger(job.execution) || job.execution < 0 || typeof job.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(job.challenge)) throw new Error('Invalid job identity or challenge');
  if (!Number.isSafeInteger(job.notBefore) || !Number.isSafeInteger(job.notAfter) || job.notBefore < 0 || job.notAfter <= job.notBefore || job.notAfter - job.notBefore > 600000) throw new Error('Invalid job execution window (maximum ten minutes)');
  if (!job.api || typeof job.api !== 'object' || Array.isArray(job.api) || Object.keys(job.api).length !== Object.keys(API).length || Object.entries(API).some(([k,v]) => job.api[k] !== v)) throw new Error('Unsupported API specification');
  return { version: 1, id: job.id, execution: job.execution, challenge: job.challenge, notBefore: job.notBefore, notAfter: job.notAfter, api: { ...API } };
}
export function makeJob(now = Date.now()) {
  return validateJob({ version: 1, id: 'local-' + randomBytes(12).toString('hex'), execution: 0, challenge: randomBytes(32).toString('hex'), notBefore: now - 2000, notAfter: now + 300000, api: { ...API } });
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
  if (result?.verified !== true || result.server !== API.server || result.path !== API.path || result.symbol !== API.symbol || typeof result.price !== 'string' || !/^\d{1,20}(\.\d{1,20})?$/.test(result.price)) throw new Error('Unexpected authenticated API result');
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
