import { createHash, createPublicKey, verify, sign } from 'node:crypto';
import { existsSync, openSync, closeSync, writeFileSync, fsyncSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { jsonRead } from './jobs.mjs';

const DOMAIN = Buffer.from('oracle-node/witness-policy/v1\0');
const ID = /^[a-f0-9]{64}$/;
const KEY = /^(02|03)[a-f0-9]{64}$/;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
export function authorityId(publicKey) {
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Policy authority must use Ed25519');
  return digest(key.export({ type: 'spki', format: 'der' }));
}
export function normalizeWitnessPolicy(value) {
  if (!exact(value, ['version', 'network', 'sequence', 'issuedAt', 'expiresAt', 'witnesses', 'revoked']) || value.version !== 1 || value.network !== 'oracle-node-v1') throw new Error('Invalid witness policy schema');
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1 || !Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0 || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 31 * 86400000) throw new Error('Invalid witness policy lifetime or sequence');
  if (!Array.isArray(value.witnesses) || value.witnesses.length > 256 || !Array.isArray(value.revoked) || value.revoked.length > 256) throw new Error('Witness policy roster limit');
  const seen = new Set();
  const witnesses = value.witnesses.map(pin => {
    if (!exact(pin, ['id', 'notaryPublicKey']) || !ID.test(pin.id) || !KEY.test(pin.notaryPublicKey) || seen.has(pin.id)) throw new Error('Invalid or duplicate admitted witness');
    seen.add(pin.id); return { id: pin.id, notaryPublicKey: pin.notaryPublicKey };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const revoked = [...value.revoked].sort();
  if (revoked.some(id => typeof id !== 'string' || !ID.test(id)) || new Set(revoked).size !== revoked.length || revoked.some(id => seen.has(id))) throw new Error('Invalid or conflicting witness revocation');
  return { version: 1, network: value.network, sequence: value.sequence, issuedAt: value.issuedAt, expiresAt: value.expiresAt, witnesses, revoked };
}
export function witnessPolicySignature(policy, privateKey, publicKey) {
  const payload = Buffer.from(JSON.stringify(normalizeWitnessPolicy(policy)));
  return { keyId: authorityId(publicKey), signature: sign(null, Buffer.concat([DOMAIN, payload]), privateKey).toString('base64') };
}
// Authority keys and threshold are local trust configuration, never supplied by
// the downloaded policy. No network participant earns trust merely by discovery.
export function verifyWitnessPolicy(envelope, { authorities, threshold, now = Date.now(), previous } = {}) {
  if (!exact(envelope, ['payload', 'signatures']) || typeof envelope.payload !== 'string' || envelope.payload.length > 256 * 1024 || !Array.isArray(envelope.signatures) || envelope.signatures.length > 32) throw new Error('Invalid witness policy envelope');
  if (!Array.isArray(authorities) || !authorities.length || authorities.length > 32 || !Number.isInteger(threshold) || threshold < 1 || threshold > authorities.length) throw new Error('Invalid locally trusted policy authorities');
  const keys = new Map(authorities.map(key => [authorityId(key), createPublicKey(key)]));
  if (keys.size !== authorities.length) throw new Error('Duplicate policy authority');
  const payload = Buffer.from(envelope.payload, 'base64');
  if (payload.toString('base64') !== envelope.payload) throw new Error('Noncanonical policy encoding');
  const policy = normalizeWitnessPolicy(JSON.parse(payload));
  if (JSON.stringify(policy) !== payload.toString('utf8')) throw new Error('Noncanonical witness policy payload');
  if (!Number.isSafeInteger(now) || now < policy.issuedAt || now >= policy.expiresAt) throw new Error('Witness policy not current');
  const policyHash = digest(payload);
  if (previous && (!Number.isSafeInteger(previous.sequence) || !ID.test(previous.policyHash) || policy.sequence < previous.sequence || policy.sequence === previous.sequence && policyHash !== previous.policyHash)) throw new Error('Witness policy rollback or equivocation rejected');
  const accepted = new Set();
  for (const signature of envelope.signatures) {
    if (!exact(signature, ['keyId', 'signature']) || !ID.test(signature.keyId) || typeof signature.signature !== 'string' || signature.signature.length > 128) throw new Error('Invalid policy signature');
    const bytes = Buffer.from(signature.signature, 'base64');
    if (bytes.toString('base64') !== signature.signature || bytes.length !== 64) throw new Error('Invalid policy signature encoding');
    const key = keys.get(signature.keyId);
    if (key && verify(null, Buffer.concat([DOMAIN, payload]), key, bytes)) accepted.add(signature.keyId);
  }
  if (accepted.size < threshold) throw new Error('Witness policy signature threshold not met');
  return { policy, policyHash, sequence: policy.sequence, signerIds: [...accepted].sort() };
}

// Revocation in the current signed policy overrides bundled and manually pinned
// admission. Authentication of a descriptor must additionally pin this exact key.
export function admittedWitnesses({ bundled = [], pinned = [], verifiedPolicy } = {}) {
  const revoked = new Set(verifiedPolicy?.policy.revoked || []);
  const admitted = new Map();
  for (const pin of [...bundled, ...pinned, ...(verifiedPolicy?.policy.witnesses || [])]) {
    if (!ID.test(pin?.id) || !KEY.test(pin?.notaryPublicKey)) throw new Error('Invalid admitted witness pin');
    if (revoked.has(pin.id)) continue;
    const old = admitted.get(pin.id);
    if (old && old.notaryPublicKey !== pin.notaryPublicKey) throw new Error('Conflicting admitted witness key');
    admitted.set(pin.id, { ...pin });
  }
  return [...admitted.values()];
}

export const BUNDLED_WITNESS = Object.freeze({
  id: 'bc1886af011f62966d09dce0441216b83078e55258fd68e5f83510ba0e516188',
  address: '152.53.92.135:9443',
  notaryPublicKey: '02280b78d5b3da0d63e728c33fefec4658fac3962d4a593f7f20c589fbd4cb671c',
});

// The default public profile explicitly trusts this shipped witness. This is a
// federation entry point, not proof that arbitrary discovered operators are honest.
export function loadWitnessPolicy(data, cfg, now = Date.now()) {
  let verifiedPolicy;
  if (cfg.witnessPolicy !== undefined) {
    if (!exact(cfg.witnessPolicy, ['authorities', 'threshold'])) throw new Error('Invalid local witness policy configuration');
    const policyPath = join(data, 'witness-policy.json');
    const statePath = join(data, 'witness-policy-state.json');
    const envelope = jsonRead(policyPath, 256 * 1024);
    const previous = existsSync(statePath) ? jsonRead(statePath, 1024) : undefined;
    verifiedPolicy = verifyWitnessPolicy(envelope, { ...cfg.witnessPolicy, now, previous });
    if (!previous || verifiedPolicy.policyHash !== previous.policyHash) {
      let lock;
      try { lock = openSync(statePath + '.lock', 'wx', 0o600); } catch { throw new Error('Witness policy state busy or stale lock; admission fails closed'); }
      const temp = statePath + '.' + process.pid + '.tmp';
      try {
        const latest = existsSync(statePath) ? jsonRead(statePath, 1024) : undefined;
        verifiedPolicy = verifyWitnessPolicy(envelope, { ...cfg.witnessPolicy, now, previous: latest });
        const fd = openSync(temp, 'wx', 0o600);
        try { writeFileSync(fd, JSON.stringify({ sequence: verifiedPolicy.sequence, policyHash: verifiedPolicy.policyHash })); fsyncSync(fd); } finally { closeSync(fd); }
        renameSync(temp, statePath);
        if (process.platform !== 'win32') { const dir = openSync(data, 'r'); try { fsyncSync(dir); } finally { closeSync(dir); } }
      } finally { if (existsSync(temp)) unlinkSync(temp); closeSync(lock); unlinkSync(statePath + '.lock'); }
    }
  }
  if (cfg.witnessTrust !== undefined && !['bundled', 'pinned'].includes(cfg.witnessTrust)) throw new Error('Invalid witness trust profile');
  const bundled = cfg.discovery === 'public' && cfg.witnessTrust === 'bundled' && cfg.id !== BUNDLED_WITNESS.id ? [BUNDLED_WITNESS] : [];
  const seeds = Array.isArray(cfg.seeds) ? cfg.seeds : [];
  const admitted = admittedWitnesses({ bundled, pinned: seeds.filter(pin => pin.notaryPublicKey), verifiedPolicy });
  const revoked = new Set(verifiedPolicy?.policy.revoked || []);
  const effective = new Map(seeds.filter(pin => !revoked.has(pin.id)).map(pin => [pin.id, { ...pin }]));
  for (const pin of admitted) {
    const existing = effective.get(pin.id);
    // Discovery routing remains separate; policies never dictate dial addresses.
    effective.set(pin.id, { ...existing, ...pin, ...(existing?.address ? { address: existing.address } : {}) });
  }
  return { seeds: [...effective.values()], policy: verifiedPolicy?.policy, state: verifiedPolicy && { sequence: verifiedPolicy.sequence, policyHash: verifiedPolicy.policyHash } };
}

export function publicNotaryCallerAllowed(cfg, op) {
  return cfg.discovery === 'public' && cfg.publicNotary === true && ['reserve', 'channel', 'release'].includes(op);
}

export function publicJobCallerAllowed(cfg, op) {
  return cfg.discovery === 'public' && cfg.publicJobs === true && ['submit', 'job-status', 'job-result'].includes(op);
}

export function isWitnessAdmitted(cfg, peer) {
  const pin = cfg.seeds?.find(candidate => candidate.id === peer?.id);
  return Boolean(pin && (!pin.notaryPublicKey || pin.notaryPublicKey === peer.notaryPublicKey) && (!pin.address || pin.address === peer.address || pin.descriptorAddress === peer.address));
}
