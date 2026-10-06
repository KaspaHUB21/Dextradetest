import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve, relative, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createJobQueue, recoverQueueOwner } from '../job-queue.mjs';
import { makeJob, jobHash } from '../jobs.mjs';
import { selectWitnessOnce } from '../witness-selection.mjs';

const NODE = 'a'.repeat(64), OWNER = 'b'.repeat(64), OTHER = 'c'.repeat(64);
const tempRoot = resolve(tmpdir());
const dir = mkdtempSync(join(tempRoot, 'oracle-queue-test-'));
const active = new Set();
const delay = ms => new Promise(ok => setTimeout(ok, ms));
async function terminal(queue, id) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const value = queue.status(id, OWNER);
    if (value.status === 'completed' || value.status === 'failed') return value;
    await delay(5);
  }
  throw new Error('Queue did not finish job');
}
function create(data, execute) {
  const queue = createJobQueue({ data, execute, nodeId: NODE }); active.add(queue); return queue;
}
async function stop(queue) { await queue.stop(); active.delete(queue); }
try {
  const data = join(dir, 'basic');
  let calls = 0, executing = 0, maximum = 0;
  const queue = create(data, async spec => {
    calls++; executing++; maximum = Math.max(maximum, executing);
    await delay(15); executing--;
    return { price: '1.2', execution: spec.execution };
  });
  const spec = makeJob();
  const accepted = await queue.submit({ spec, requesterId: OWNER, requestId: 'request_1' });
  const duplicate = await queue.submit({ spec, requesterId: OWNER });
  assert.equal(accepted.queueId, duplicate.queueId);
  await assert.rejects(queue.submit({ spec: { ...spec, challenge: 'd'.repeat(64) }, requesterId: OWNER }), /Conflicting/);
  await assert.rejects(queue.submit({ spec, requesterId: OTHER }), /another requester/);
  assert.throws(() => queue.status(accepted.queueId, OTHER), /authorized/);
  const next = await queue.submit({ spec: { ...makeJob(), id: 'second' }, requesterId: OWNER });
  assert.equal((await terminal(queue, accepted.queueId)).status, 'completed');
  assert.equal((await terminal(queue, next.queueId)).status, 'completed');
  assert.equal(calls, 2); assert.equal(maximum, 1, 'executions are sequential');
  const copy = queue.status(accepted.queueId, OWNER); copy.result.price = 'modified';
  assert.equal(queue.status(accepted.queueId, OWNER).result.price, '1.2');
  await stop(queue);
  const restarted = create(data, async () => { throw new Error('completed job unexpectedly executed'); });
  assert.equal((await restarted.submit({ spec, requesterId: OWNER })).status, 'completed');
  assert.equal(restarted.status(accepted.queueId, OWNER).result.price, '1.2');
  assert.throws(() => createJobQueue({ data, execute: async () => ({}), nodeId: NODE }), /owned/);
  await stop(restarted);

  const scheduledData = join(dir, 'scheduled');
  const future = { ...makeJob(), id: 'future', notBefore: Date.now() + 120, notAfter: Date.now() + 2000 };
  const scheduled = create(scheduledData, async () => ({ ok: true }));
  const scheduledId = (await scheduled.submit({ spec: future, requesterId: OWNER })).queueId;
  await stop(scheduled);
  const resumed = create(scheduledData, async () => ({ resumed: true }));
  assert.equal((await terminal(resumed, scheduledId)).result.resumed, true);
  const expired = { ...makeJob(), notBefore: Date.now() - 1000, notAfter: Date.now() - 1 };
  await assert.rejects(resumed.submit({ spec: expired, requesterId: OWNER }), /expired/);
  const distant = { ...makeJob(), notBefore: Date.now() + 700000, notAfter: Date.now() + 701000 };
  await assert.rejects(resumed.submit({ spec: distant, requesterId: OWNER }), /future/);
  await stop(resumed);

  const expiringData = join(dir, 'expired-pending');
  const expiring = create(expiringData, async () => { throw new Error('expired pending job ran'); });
  const expiresSoon = { ...makeJob(), id: 'expires_pending', notBefore: Date.now() + 30, notAfter: Date.now() + 60 };
  const expiredId = (await expiring.submit({ spec: expiresSoon, requesterId: OWNER })).queueId;
  await stop(expiring); await delay(80);
  const expiredRestart = create(expiringData, async () => { throw new Error('expired job reran after restart'); });
  assert.equal((await terminal(expiredRestart, expiredId)).error.code, 'JOB_EXPIRED');
  await stop(expiredRestart);

  let releaseExecution;
  const draining = create(join(dir, 'draining'), async () => {
    await new Promise(ok => { releaseExecution = ok; }); return { drained: true };
  });
  const drainingId = (await draining.submit({ spec: makeJob(), requesterId: OWNER })).queueId;
  while (!releaseExecution) await delay(1);
  let stopped = false;
  const stopping = draining.stop().then(() => { stopped = true; });
  await delay(5); assert.equal(stopped, false, 'stop waits current execution');
  await assert.rejects(draining.submit({ spec: makeJob(), requesterId: OWNER }), /stopping/);
  releaseExecution(); await stopping; active.delete(draining);
  assert.equal(draining.status(drainingId, OWNER).result.drained, true);
  await draining.stop(); // idempotent shutdown

  const failure = create(join(dir, 'failure'), async () => { throw new Error('private secret /private/path'); });
  const failedId = (await failure.submit({ spec: makeJob(), requesterId: OWNER })).queueId;
  const failed = await terminal(failure, failedId);
  assert.equal(failed.status, 'failed'); assert.equal(failed.error.code, 'EXECUTION_FAILED');
  assert.ok(!JSON.stringify(failed).includes('private secret'), 'execution exception is not leaked');
  await stop(failure);
  const oversized = create(join(dir, 'oversized'), async () => ({ value: 'x'.repeat(65537) }));
  const oversizedId = (await oversized.submit({ spec: makeJob(), requesterId: OWNER })).queueId;
  assert.equal((await terminal(oversized, oversizedId)).status, 'failed');
  await stop(oversized);

  const capacity = create(join(dir, 'capacity'), async () => ({}));
  for (let i = 0; i < 32; i++) {
    const waiting = { ...makeJob(), id: 'capacity_' + i, notBefore: Date.now() + 10000, notAfter: Date.now() + 20000 };
    await capacity.submit({ spec: waiting, requesterId: OWNER });
  }
  await assert.rejects(capacity.submit({ spec: makeJob(), requesterId: OWNER }), /full/);
  await assert.rejects(capacity.submit({ spec: { ...makeJob(), unexpected: 'x'.repeat(16384) }, requesterId: OWNER }), /size limit/);
  await stop(capacity);
  const fullData = join(dir, 'full-disk'); mkdirSync(join(fullData, 'jobs'), { recursive: true });
  for (let i = 0; i < 1000; i++) writeFileSync(join(fullData, 'jobs', String(i)), '');
  const full = create(fullData, async () => ({}));
  await assert.rejects(full.submit({ spec: makeJob(), requesterId: OWNER }), /storage limit/);
  await stop(full);

  const batchData = join(dir, 'batch'); let batchCalls = 0;
  const batch = create(batchData, async spec => { batchCalls++; return { execution: spec.execution }; });
  const batchNow = Date.now();
  const base = makeJob();
  const series = [0,1,2].map(execution => ({ ...makeJob(), id: 'interval_series', execution, notBefore: batchNow + 150 + execution * 25, notAfter: batchNow + 2000 }));
  await assert.rejects(batch.submitBatch({ specs: [...series, { ...base, execution: 'bad' }], requesterId: OWNER }), /identity/);
  assert.equal(batch.list(OWNER).length, 0, 'invalid final member leaves no jobs admitted');
  assert.equal(JSON.parse(readFileSync(join(batchData, 'job-queue.json'))).records.length, 0);
  const admitted = await batch.submitBatch({ specs: series, requesterId: OWNER });
  assert.equal(admitted.length, 3); assert.equal(batch.list(OWNER).length, 3);
  assert.deepEqual(await batch.submitBatch({ specs: series, requesterId: OWNER }), admitted, 'entire batch is idempotent');
  const additional = { ...makeJob(), id: 'would_be_added', notBefore: batchNow + 300, notAfter: batchNow + 2000 };
  await assert.rejects(batch.submitBatch({ specs: [additional, { ...series[2], challenge: 'f'.repeat(64) }], requesterId: OWNER }), /Conflicting/);
  assert.equal(batch.list(OWNER).length, 3, 'conflict leaves staged new member unpersisted');
  await assert.rejects(batch.submitBatch({ specs: [additional, series[1]], requesterId: OTHER }), /another requester/);
  assert.equal(batch.list(OTHER).length, 0);
  await assert.rejects(batch.submitBatch({ specs: Array.from({ length: 33 }, () => makeJob()), requesterId: OWNER }), /32/);
  const tooMany = Array.from({ length: 30 }, (_,i) => ({ ...makeJob(), id: 'would_overflow_' + i, notBefore: Date.now() + 10000, notAfter: Date.now() + 20000 }));
  await assert.rejects(batch.submitBatch({ specs: tooMany, requesterId: OWNER }), /full/);
  assert.equal(batch.list(OWNER).length, 3, 'capacity rejection is atomic');
  await stop(batch);
  assert.equal(batchCalls, 0, 'future interval members do not start during admission');
  const batchRestart = create(batchData, async spec => { batchCalls++; return { execution: spec.execution }; });
  for (const member of admitted) assert.equal((await terminal(batchRestart, member.queueId)).status, 'completed');
  assert.equal(batchCalls, 3, 'persisted future series executes each member once after restart');
  await batchRestart.submitBatch({ specs: series, requesterId: OWNER }); await delay(20);
  assert.equal(batchCalls, 3, 'series retry does not repeat completed executions');
  await stop(batchRestart);

  const witnessData = join(dir, 'witness'); const witnessJob = makeJob();
  const candidates = [OWNER, OTHER];
  const chosen = selectWitnessOnce({ data: witnessData, spec: witnessJob, candidates });
  assert.ok(candidates.includes(chosen.id));
  assert.deepEqual(selectWitnessOnce({ data: witnessData, spec: witnessJob, candidates: candidates.toReversed() }), chosen);
  assert.throws(() => selectWitnessOnce({ data: witnessData, spec: witnessJob, candidates: candidates.filter(id => id !== chosen.id) }), /no reroll/);
  assert.throws(() => selectWitnessOnce({ data: witnessData, spec: { ...witnessJob, execution: witnessJob.execution, challenge: 'e'.repeat(64) }, candidates }), /Conflicting/);
  assert.equal(chosen.jobHash, jobHash(witnessJob));

  const crashData = join(dir, 'crash');
  const moduleUrl = pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../job-queue.mjs')).href;
  const jobsUrl = pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../jobs.mjs')).href;
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import {createJobQueue} from ${JSON.stringify(moduleUrl)};
    import {makeJob} from ${JSON.stringify(jobsUrl)};
    const queue=createJobQueue({data:process.env.QUEUE_TEST_DATA,nodeId:'${NODE}',execute:async()=>{
      console.log('RUNNING'); await new Promise(()=>{});
    }});
    await queue.submit({spec:makeJob(),requesterId:'${OWNER}'});
    setInterval(()=>{},1000);
  `], { env: { ...process.env, QUEUE_TEST_DATA: crashData }, stdio: ['ignore','pipe','pipe'] });
  try {
    await new Promise((ok,no) => {
      const timer = setTimeout(() => no(new Error('Crash simulation did not start')), 3000);
      child.once('error', e => { clearTimeout(timer); no(e); });
      child.once('exit', () => { clearTimeout(timer); no(new Error('Crash child exited early')); });
      child.stdout.on('data', data => { if (data.toString().includes('RUNNING')) { clearTimeout(timer); ok(); } });
    });
    assert.throws(() => recoverQueueOwner(crashData, { expectedPid: child.pid }), /still running/);
    await new Promise(ok => { child.once('exit', ok); child.kill('SIGKILL'); });
    assert.throws(() => createJobQueue({ data: crashData, nodeId: NODE, execute: async () => ({}) }), /stale/);
    recoverQueueOwner(crashData, { expectedPid: child.pid });
    const recovery = create(crashData, async () => { throw new Error('ambiguous job rerun'); });
    assert.equal(recovery.list(OWNER)[0].status, 'failed');
    assert.equal(recovery.list(OWNER)[0].error.code, 'AMBIGUOUS_RESTART');
    await stop(recovery);
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  console.log('PASS queue: durable idempotency, ownership, sequential execution, scheduling/restart, expiry, failure limits, disk capacity, random witness persistence, explicit crash recovery');
} finally {
  await Promise.allSettled([...active].map(queue => queue.stop()));
  const rel = relative(tempRoot, resolve(dir));
  assert.ok(rel && !rel.startsWith('..') && !isAbsolute(rel) && rel.startsWith('oracle-queue-test-'));
  rmSync(resolve(dir), { recursive: true, force: true });
}
