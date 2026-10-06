import { randomBytes, createHash } from 'node:crypto';
import { openSync, closeSync, writeFileSync, fsyncSync, renameSync, unlinkSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { validateJob, jobHash, jsonRead } from './jobs.mjs';

const MAX_RECORDS = 1000;
const MAX_ACTIVE = 32;
const MAX_RESULT_BYTES = 64 * 1024;
const hash = value => createHash('sha256').update(value).digest('hex');
const executionKey = spec => hash(spec.id + '\0' + spec.execution);
const identity = id => typeof id === 'string' && /^[a-f0-9]{64}$/.test(id);
const statuses = new Set(['pending', 'running', 'completed', 'failed']);
function atomic(path, value) {
  const temporary = path + '.' + randomBytes(8).toString('hex') + '.tmp';
  const fd = openSync(temporary, 'wx', 0o600);
  try { writeFileSync(fd, JSON.stringify(value)); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, path);
  if (process.platform !== 'win32') {
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
}
function serializable(value, limit, label) {
  let text;
  try { text = JSON.stringify(value); } catch { throw new Error('Invalid ' + label); }
  if (typeof text !== 'string' || Buffer.byteLength(text) > limit) throw new Error(label + ' exceeds size limit');
  return JSON.parse(text);
}
function validateRecord(record) {
  if (!record || typeof record !== 'object' || !/^[a-f0-9]{64}$/.test(record.queueId) || !identity(record.requesterId) || !statuses.has(record.status) || !Number.isSafeInteger(record.createdAt) || !Number.isSafeInteger(record.updatedAt)) throw new Error('Invalid persisted queue record');
  const spec = validateJob(record.spec);
  if (record.queueId !== executionKey(spec) || record.jobHash !== jobHash(spec)) throw new Error('Persisted queue job binding mismatch');
  if (record.result !== undefined) serializable(record.result, MAX_RESULT_BYTES, 'result');
  if (record.error && (typeof record.error.code !== 'string' || typeof record.error.message !== 'string' || record.error.message.length > 1024)) throw new Error('Invalid persisted queue error');
  return record;
}
// Crash recovery is an explicit operator action. A marker is never removed just
// because it is old; PID reuse fails closed and requires manual investigation.
export function recoverQueueOwner(data, { expectedPid } = {}) {
  const path = join(resolve(data), 'job-queue.owner');
  const marker = jsonRead(path, 1024);
  if (!Number.isSafeInteger(expectedPid) || expectedPid <= 0 || marker.pid !== expectedPid || typeof marker.nonce !== 'string') throw new Error('Queue recovery requires exact previous process ID');
  try { process.kill(expectedPid, 0); } catch (error) {
    if (error.code !== 'ESRCH') throw new Error('Cannot establish that queue owner has stopped');
    const latest = jsonRead(path, 1024);
    if (latest.pid !== marker.pid || latest.nonce !== marker.nonce) throw new Error('Queue owner changed during recovery');
    unlinkSync(path); return;
  }
  throw new Error('Queue owner is still running; recovery refused');
}
export function createJobQueue({ data, execute, nodeId }) {
  if (typeof data !== 'string' || !identity(nodeId) || typeof execute !== 'function') throw new Error('Invalid job queue configuration');
  const directory = resolve(data); mkdirSync(directory, { recursive: true, mode: 0o700 });
  const statePath = join(directory, 'job-queue.json');
  const ownerPath = join(directory, 'job-queue.owner');
  const owner = { pid: process.pid, nonce: randomBytes(16).toString('hex'), nodeId };
  let ownerFd;
  try { ownerFd = openSync(ownerPath, 'wx', 0o600); } catch { throw new Error('Queue already owned or stale owner marker requires explicit recovery'); }
  try { writeFileSync(ownerFd, JSON.stringify(owner)); fsyncSync(ownerFd); } finally { closeSync(ownerFd); }
  let state;
  try {
    state = existsSync(statePath) ? jsonRead(statePath, 80 * 1024 * 1024) : { version: 1, nodeId, records: [] };
    if (state.version !== 1 || state.nodeId !== nodeId || !Array.isArray(state.records) || state.records.length > MAX_RECORDS) throw new Error('Invalid persisted queue');
    const ids = new Set();
    for (const record of state.records) {
      validateRecord(record);
      if (ids.has(record.queueId)) throw new Error('Duplicate persisted queue execution');
      ids.add(record.queueId);
      if (record.status === 'running') {
        record.status = 'failed'; record.updatedAt = Date.now();
        record.error = { code: 'AMBIGUOUS_RESTART', message: 'Previous execution was interrupted. It will not be repeated automatically.' };
      }
    }
    if (state.records.filter(r => r.status === 'pending').length > MAX_ACTIVE) throw new Error('Persisted queue exceeds pending limit');
    atomic(statePath, state);
  } catch (error) { unlinkSync(ownerPath); throw error; }
  let stopped = false; let timer; let active; let stopPromise;
  function save() { atomic(statePath, state); }
  function snapshot(record) { return serializable(record, MAX_RESULT_BYTES + 32 * 1024, 'queue status'); }
  function fail(record, code, message) {
    record.status = 'failed'; record.updatedAt = Date.now(); record.error = { code, message }; save();
  }
  function diskFull() {
    const jobs = join(directory, 'jobs');
    return existsSync(jobs) && readdirSync(jobs).length >= MAX_RECORDS;
  }
  function admit(specs, requesterId, requestId) {
    if (stopped) throw new Error('Queue is stopping or unavailable');
    if (!identity(requesterId) || (requestId !== undefined && (typeof requestId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(requestId)))) throw new Error('Invalid requester or request ID');
    if (!Array.isArray(specs) || !specs.length || specs.length > MAX_ACTIVE) throw new Error('Job batch must contain one to 32 specifications');
    // Validate every member before checking or changing the durable queue.
    const canonical = specs.map(spec => validateJob(serializable(spec, 16 * 1024, 'job specification')));
    const now = Date.now(); const staged = new Map(); const responses = [];
    for (const spec of canonical) {
      const id = executionKey(spec); const binding = jobHash(spec);
      const existing = state.records.find(record => record.queueId === id) || staged.get(id);
      if (existing) {
        if (existing.requesterId !== requesterId) throw new Error('Job execution belongs to another requester');
        if (existing.jobHash !== binding) throw new Error('Conflicting specification for existing job execution');
        responses.push({ queueId: id, status: existing.status, jobHash: binding }); continue;
      }
      if (spec.notAfter < now || spec.notBefore - now > 600000) throw new Error('Job window expired or scheduled too far in the future');
      staged.set(id, { queueId: id, jobHash: binding, requesterId, ...(requestId ? { requestId } : {}), spec, status: 'pending', createdAt: now, updatedAt: now });
      responses.push({ queueId: id, status: 'pending', jobHash: binding });
    }
    if (!staged.size) return responses;
    const pending = state.records.filter(record => record.status === 'pending').length;
    if (pending + staged.size > MAX_ACTIVE) throw new Error('Pending job queue is full');
    const jobs = join(directory, 'jobs');
    const onDisk = existsSync(jobs) ? readdirSync(jobs).length : 0;
    if (state.records.length + staged.size > MAX_RECORDS || onDisk + pending + staged.size > MAX_RECORDS) throw new Error('Job storage limit reached');
    const previous = state.records;
    state.records = previous.concat([...staged.values()]);
    try { save(); } catch (error) {
      state.records = previous;
      // An fsync error can follow a successful rename. Stop scheduling rather
      // than guessing whether the batch committed; restart reads durable state.
      stopped = true; clearTimeout(timer); throw error;
    }
    schedule(); return responses;
  }
  async function runNext() {
    if (stopped || active) return;
    clearTimeout(timer); timer = undefined;
    const pending = state.records.filter(r => r.status === 'pending').sort((a,b) => a.spec.notBefore - b.spec.notBefore || a.createdAt - b.createdAt);
    if (!pending.length) return;
    const record = pending[0]; const now = Date.now();
    if (now > record.spec.notAfter) { fail(record, 'JOB_EXPIRED', 'Job execution window expired.'); schedule(); return; }
    if (now < record.spec.notBefore) { timer = setTimeout(schedule, Math.min(record.spec.notBefore - now, 10000)); return; }
    if (diskFull()) { fail(record, 'STORAGE_LIMIT', 'Job storage limit reached.'); schedule(); return; }
    record.status = 'running'; record.updatedAt = now; save();
    active = (async () => {
      try {
        const context = Object.freeze({ queueId: record.queueId, requesterId: record.requesterId, requestId: record.requestId, jobHash: record.jobHash, nodeId });
        const result = await execute(structuredClone(record.spec), context);
        if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Invalid execution result');
        if (Date.now() > record.spec.notAfter) { fail(record, 'JOB_EXPIRED', 'Execution completed after its allowed window.'); return; }
        record.result = serializable(result, MAX_RESULT_BYTES, 'result');
        record.status = 'completed'; record.updatedAt = Date.now(); save();
      } catch {
        fail(record, 'EXECUTION_FAILED', 'Job execution failed. Inspect the local execution log for details.');
      }
    })();
    try { await active; } finally { active = undefined; schedule(); }
  }
  function schedule() {
    if (stopped || active) return;
    clearTimeout(timer);
    timer = setTimeout(() => { runNext().catch(() => { stopped = true; }); }, 0);
  }
  const queue = {
    ready: Promise.resolve(),
    async submit({ spec, requesterId, requestId } = {}) {
      return admit([spec], requesterId, requestId)[0];
    },
    async submitBatch({ specs, requesterId } = {}) {
      return admit(specs, requesterId);
    },
    status(queueId, requesterId) {
      if (typeof queueId !== 'string' || !/^[a-f0-9]{64}$/.test(queueId) || !identity(requesterId)) throw new Error('Invalid status request');
      const record = state.records.find(r => r.queueId === queueId);
      if (!record || record.requesterId !== requesterId) throw new Error('Unknown job or requester not authorized');
      return snapshot(record);
    },
    list(requesterId) {
      if (!identity(requesterId)) throw new Error('Invalid requester');
      return state.records.filter(r => r.requesterId === requesterId).map(snapshot);
    },
    async stop() {
      if (stopPromise) return stopPromise;
      stopped = true; clearTimeout(timer);
      stopPromise = (async () => {
        if (active) await active;
        const latest = jsonRead(ownerPath, 1024);
        if (latest.pid !== owner.pid || latest.nonce !== owner.nonce) throw new Error('Queue owner marker changed');
        unlinkSync(ownerPath);
      })();
      return stopPromise;
    }
  };
  schedule(); return queue;
}
