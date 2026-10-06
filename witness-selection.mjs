import { randomInt, randomBytes, createHash } from 'node:crypto';
import { openSync, closeSync, writeFileSync, fsyncSync, mkdirSync, renameSync, unlinkSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { validateJob, jobHash, jsonRead } from './jobs.mjs';

// Local random selection is persisted before contacting the witness. It is not
// a network-verifiable lottery and cannot restrain a malicious local operator.
export function selectWitnessOnce({ data, spec, candidates }) {
  const job = validateJob(spec); const binding = jobHash(job);
  if (typeof data !== 'string' || !Array.isArray(candidates) || candidates.length > 32) throw new Error('Invalid witness selection input');
  const ids = [...new Set(candidates.map(candidate => typeof candidate === 'string' ? candidate : candidate?.id))].sort();
  if (ids.some(id => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))) throw new Error('Invalid eligible witness identity');
  const directory = resolve(data); mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, 'witness-selections.json');
  const key = createHash('sha256').update(job.id + '\0' + job.execution).digest('hex');
  let lock;
  try { lock = openSync(path + '.lock', 'wx', 0o600); } catch { throw new Error('Witness selection ledger busy or stale lock; do not reroll'); }
  try {
    const state = existsSync(path) ? jsonRead(path, 8 * 1024 * 1024) : { version: 1, selections: {} };
    if (state.version !== 1 || !state.selections || typeof state.selections !== 'object' || Array.isArray(state.selections) || Object.keys(state.selections).length > 1000) throw new Error('Invalid witness selection ledger');
    const existing = state.selections[key];
    if (existing) {
      if (existing.jobHash !== binding) throw new Error('Conflicting job specification for persisted witness selection');
      if (typeof existing.id !== 'string' || !/^[a-f0-9]{64}$/.test(existing.id) || !Array.isArray(existing.eligibleIds) || !Number.isSafeInteger(existing.selectedAt)) throw new Error('Invalid persisted witness selection');
      if (!ids.includes(existing.id)) throw new Error('Previously selected witness is unavailable; no reroll allowed');
      return structuredClone(existing);
    }
    if (!ids.length) throw new Error('No eligible reachable trusted witness');
    if (Object.keys(state.selections).length >= 1000) throw new Error('Witness selection ledger full');
    const selection = { id: ids[randomInt(ids.length)], jobHash: binding, eligibleIds: ids, selectedAt: Date.now() };
    state.selections[key] = selection;
    const temp = path + '.' + randomBytes(8).toString('hex') + '.tmp';
    const fd = openSync(temp, 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify(state)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temp, path);
    if (process.platform !== 'win32') {
      const fd = openSync(dirname(path), 'r'); try { fsyncSync(fd); } finally { closeSync(fd); }
    }
    return structuredClone(selection);
  } finally { closeSync(lock); unlinkSync(path + '.lock'); }
}
