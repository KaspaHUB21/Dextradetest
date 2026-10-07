import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeWitnessPolicy, witnessPolicySignature, verifyWitnessPolicy, admittedWitnesses, loadWitnessPolicy, BUNDLED_WITNESS, publicNotaryCallerAllowed, publicJobCallerAllowed, isWitnessAdmitted } from '../witness-policy.mjs';
const keys = Array.from({ length: 3 }, () => generateKeyPairSync('ed25519'));
const authorities = keys.map(k => k.publicKey.export({ type: 'spki', format: 'pem' }));
const now = 100000;
const id = 'a'.repeat(64), other = 'b'.repeat(64);
const notaryPublicKey = '02' + '1'.repeat(64);
const spec = { version: 1, network: 'oracle-node-v1', sequence: 1, issuedAt: now - 1, expiresAt: now + 1000, witnesses: [{ id, notaryPublicKey }], revoked: [] };
const envelope = (value, signers = [0, 1]) => ({ payload: Buffer.from(JSON.stringify(normalizeWitnessPolicy(value))).toString('base64'), signatures: signers.map(i => witnessPolicySignature(value, keys[i].privateKey, authorities[i])) });
const options = { authorities, threshold: 2, now };
const current = verifyWitnessPolicy(envelope(spec), options);
const checks = [];
function pass(name, test) { test(); checks.push(name); }
pass('Two independently configured authority signatures admit exact witness key', () => assert.deepEqual(current.policy.witnesses, spec.witnesses));
pass('Insufficient signatures fail closed', () => assert.throws(() => verifyWitnessPolicy(envelope(spec, [0]), options), /threshold/));
pass('Duplicate signer cannot meet threshold', () => assert.throws(() => verifyWitnessPolicy(envelope(spec, [0, 0]), options), /threshold/));
pass('Unknown authority cannot meet threshold', () => assert.throws(() => verifyWitnessPolicy(envelope(spec, [0, 2]), { ...options, authorities: authorities.slice(0, 2) }), /threshold/));
pass('Tampered payload fails signature verification', () => { const changed = envelope({ ...spec, witnesses: [{ id: other, notaryPublicKey }] }); changed.signatures = envelope(spec).signatures; assert.throws(() => verifyWitnessPolicy(changed, options), /threshold/); });
pass('Expired and future policies fail closed', () => { assert.throws(() => verifyWitnessPolicy(envelope(spec), { ...options, now: spec.expiresAt }), /current/); assert.throws(() => verifyWitnessPolicy(envelope(spec), { ...options, now: spec.issuedAt - 1 }), /current/); });
pass('Rollback and same-sequence equivocation are rejected', () => { const previous = { sequence: current.sequence, policyHash: current.policyHash }; assert.throws(() => verifyWitnessPolicy(envelope({ ...spec, witnesses: [] }), { ...options, previous }), /equivocation/); assert.throws(() => verifyWitnessPolicy(envelope(spec), { ...options, previous: { ...previous, sequence: 2 } }), /rollback/); assert.equal(verifyWitnessPolicy(envelope(spec), { ...options, previous }).policyHash, current.policyHash); });
pass('Signed revocation removes bundled and manually pinned witness', () => { const revoked = verifyWitnessPolicy(envelope({ ...spec, sequence: 2, witnesses: [], revoked: [id] }), options); assert.deepEqual(admittedWitnesses({ bundled: spec.witnesses, pinned: spec.witnesses, verifiedPolicy: revoked }), []); });
pass('Conflicting witness keys cannot silently rotate', () => assert.throws(() => admittedWitnesses({ bundled: spec.witnesses, pinned: [{ id, notaryPublicKey: '03' + '2'.repeat(64) }] }), /Conflicting/));
pass('Noncanonical payload and oversized authority sets are rejected', () => { const e = envelope(spec); e.payload = Buffer.from(JSON.stringify(normalizeWitnessPolicy(spec), null, 2)).toString('base64'); assert.throws(() => verifyWitnessPolicy(e, options), /Noncanonical/); assert.throws(() => verifyWitnessPolicy(envelope(spec), { ...options, authorities: [...authorities, authorities[0]] }), /Duplicate/); });
pass('Active/revoked duplicates and unknown schema keys are rejected', () => { assert.throws(() => normalizeWitnessPolicy({ ...spec, revoked: [id] }), /conflicting/); assert.throws(() => normalizeWitnessPolicy({ ...spec, extra: true }), /schema/); });
pass('Explicit bundled profile is usable without trusting arbitrary discovered peers', () => {
  const cfg = { id: other, discovery: 'public', witnessTrust: 'bundled', seeds: [] };
  assert.deepEqual(loadWitnessPolicy('.', cfg, now).seeds, [BUNDLED_WITNESS]);
  assert.deepEqual(loadWitnessPolicy('.', { ...cfg, witnessTrust: 'pinned' }, now).seeds, []);
  assert.deepEqual(loadWitnessPolicy('.', { ...cfg, witnessTrust: undefined }, now).seeds, []);
  assert.equal(isWitnessAdmitted({ seeds: [BUNDLED_WITNESS] }, { ...BUNDLED_WITNESS, notaryPublicKey: '03' + '2'.repeat(64) }), false);
  assert.equal(isWitnessAdmitted({ seeds: spec.witnesses }, spec.witnesses[0]), true);
});
pass('Public notary caller opt-in grants only bounded session operations', () => {
  const cfg = { discovery: 'public', publicNotary: true };
  assert.equal(publicNotaryCallerAllowed(cfg, 'reserve'), true);
  for (const op of ['submit', 'job-result', 'trust-peer']) assert.equal(publicNotaryCallerAllowed(cfg, op), false);
  assert.equal(publicNotaryCallerAllowed({ discovery: 'public' }, 'reserve'), false);
});
pass('Public jobs opt-in grants single-submit and ownership-gated reads, never series or witness trust', () => {
  const cfg = { discovery: 'public', publicJobs: true };
  for (const op of ['submit', 'job-status', 'job-result']) assert.equal(publicJobCallerAllowed(cfg, op), true);
  for (const op of ['submit-series', 'reserve', 'trust-peer', 'relay']) assert.equal(publicJobCallerAllowed(cfg, op), false);
  assert.equal(publicJobCallerAllowed({ discovery: 'public' }, 'submit'), false);
});
pass('Runtime persists anti-rollback state, reloads revocation and fails closed on expiration', () => {
  const data = mkdtempSync(join(tmpdir(), 'oracle-policy-'));
  try {
    const cfg = { seeds: spec.witnesses, witnessPolicy: { authorities, threshold: 2 } };
    writeFileSync(join(data, 'witness-policy.json'), JSON.stringify(envelope(spec)));
    assert.equal(loadWitnessPolicy(data, cfg, now).seeds.length, 1);
    assert.equal(JSON.parse(readFileSync(join(data, 'witness-policy-state.json'))).sequence, 1);
    const next = { ...spec, sequence: 2, witnesses: [], revoked: [id] };
    writeFileSync(join(data, 'witness-policy.json'), JSON.stringify(envelope(next)));
    assert.equal(loadWitnessPolicy(data, cfg, now).seeds.length, 0);
    assert.throws(() => loadWitnessPolicy(data, cfg, spec.expiresAt), /current/);
    writeFileSync(join(data, 'witness-policy.json'), JSON.stringify(envelope(spec)));
    assert.throws(() => loadWitnessPolicy(data, cfg, now), /rollback/);
  } finally { rmSync(data, { recursive: true, force: true }); }
});
console.log(JSON.stringify({ passed: true, checks }, null, 2));
