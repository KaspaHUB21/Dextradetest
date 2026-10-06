import { spawn } from 'node:child_process';
import { createHash, createECDH } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, chmodSync, statSync, rmSync, accessSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { makeJob, jobHash, validateResult } from '../../jobs.mjs';
import { runWarm } from './warm-prove-wrapper.mjs';

if (process.platform !== 'linux') throw new Error('Linux only; run this opt-in benchmark in a disposable test environment');
const args = process.argv.slice(2);
let samples = 2, port, output;
for (let i = 0; i < args.length; i += 2) {
  if (!args[i + 1]) throw new Error('Expected --samples N, --port N or --output FILE');
  if (args[i] === '--samples') samples = Number(args[i + 1]);
  else if (args[i] === '--port') port = Number(args[i + 1]);
  else if (args[i] === '--output') output = args[i + 1];
  else throw new Error('Unknown option');
}
if (!Number.isInteger(samples) || samples < 1 || samples > 10 || (port !== undefined && (!Number.isInteger(port) || port <= 1024 || port >= 65533))) throw new Error('Invalid experiment options');
const base = dirname(fileURLToPath(import.meta.url));
// GNU coreutils timeout also stops the isolated notary after runner SIGKILL.
accessSync('/usr/bin/timeout', constants.X_OK);
const binaries = join(base, 'bin');
const sha = data => createHash('sha256').update(data).digest('hex');
const binarySha256 = Object.fromEntries(['prove', 'notary', 'present', 'verify'].map(name => [name, sha(readFileSync(join(binaries, name)))]));
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(ORACLE_PROBE_|ORACLE_WARM_)/.test(name) && !['LD_PRELOAD', 'LD_LIBRARY_PATH', 'RUST_LOG', 'NOTARY_BASE_PORT', 'CONTROL_ADDR', 'MPC_ADDR', 'PROXY_ADDR', 'JOB_CHALLENGE', 'OUTPUT_DIR', 'TRUSTED_NOTARY_KEY', 'PRESENTATION_FILE'].includes(name)));
const controller = new AbortController();
const cancel = () => controller.abort();
process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
const children = new Set();
function killGroup(child, name) { if (child.pid) { try { process.kill(-child.pid, name); } catch (error) { if (error.code !== 'ESRCH') throw error; } } }
async function stopChild(child) {
  if (!children.has(child)) return;
  killGroup(child, 'SIGTERM');
  const timer = setTimeout(() => killGroup(child, 'SIGKILL'), 1000);
  try { await child.closed; } finally { clearTimeout(timer); killGroup(child, 'SIGKILL'); children.delete(child); }
}
function childProcess(binary, argv, env, cwd) {
  if (controller.signal.aborted) throw new Error('Experiment cancelled');
  const child = spawn(binary, argv, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  children.add(child); child.stdoutText = ''; child.stderrText = '';
  child.closed = new Promise(resolve => child.once('close', resolve));
  child.once('error', error => { child.failure = error; });
  for (const name of ['stdout', 'stderr']) child[name].on('data', data => {
    child[name + 'Text'] += data;
    if (Buffer.byteLength(child.stdoutText) + Buffer.byteLength(child.stderrText) > 4 * 1024 * 1024) { child.failure ??= new Error('Child log limit exceeded'); killGroup(child, 'SIGKILL'); }
  });
  return child;
}
async function run(binary, argv, env, cwd, timeoutMs = 30000, expectRejection = false) {
  const child = childProcess(binary, argv, env, cwd);
  const terminate = () => { child.failure ??= new Error('Experiment cancelled'); stopChild(child).catch(() => {}); };
  controller.signal.addEventListener('abort', terminate, { once: true });
  const timer = setTimeout(() => { child.failure ??= new Error('Child deadline exceeded'); stopChild(child).catch(() => {}); }, timeoutMs);
  try {
    const code = await child.closed;
    if (child.failure || code === null) throw child.failure ?? new Error('Child terminated by signal');
    if (expectRejection) {
      if (!Number.isInteger(code) || code <= 0) throw new Error('Verifier unexpectedly accepted modified input');
      return { passed: true, exitCode: code };
    }
    if (code !== 0) throw new Error(`Native child failed with exit code ${code}`);
    return child.stdoutText;
  } finally { clearTimeout(timer); controller.signal.removeEventListener('abort', terminate); await stopChild(child); }
}
async function availableTrio(candidate) {
  const listeners = [];
  try {
    for (let offset = 0; offset < 3; offset++) {
      const listener = net.createServer(); listeners.push(listener);
      await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(candidate + offset, '127.0.0.1', resolve); });
    }
    return true;
  } catch { return false; }
  finally { await Promise.all(listeners.map(listener => new Promise(resolve => listener.close(() => resolve())))); }
}
const data = mkdtempSync(join(tmpdir(), 'oracle-subsecond-')); chmodSync(data, 0o700);
if ((statSync(data).mode & 0o777) !== 0o700) { rmSync(data, { recursive: true, force: true }); throw new Error('Temporary filesystem must enforce private Linux permissions'); }
const report = { version: 1, productionChanged: false, scope: 'Opt-in Linux loopback known-job benchmark; API request sent after local trigger. Preparation, three-second time-based TLS warming and two-second demonstration hold excluded from trigger latency. No public-peer or arbitrary-arriving-job SLA.', effectiveConfig: { server: 'api.kucoin.com', symbol: 'KAS-USDT', protocol: 'MPC', network: 'Bandwidth', sentLimit: 512, recvLimit: 16384, sentRecords: 2, recvRecordsOnline: 2, revealAll: false, singleUse: true, warmDeadlineMs: 60000, isolatedNotaryLifetimeMs: 65000, requiredRuntime: 'Linux, Node.js, GNU coreutils timeout' }, binarySha256, samples: [] };
try {
  if (port === undefined) {
    for (let n = 0; n < 100; n++) { const candidate = 20000 + Math.floor(Math.random() * 30000); if (await availableTrio(candidate)) { port = candidate; break; } }
    if (port === undefined) throw new Error('No free loopback port trio');
  } else if (!await availableTrio(port)) throw new Error('Requested loopback port trio is occupied');
  for (let i = 0; i < samples; i++) {
    const sampleDir = join(data, 'sample-' + i); mkdirSync(sampleDir, { mode: 0o700 });
    await run(join(binaries, 'notary'), ['init'], cleanEnv, sampleDir);
    const notary = childProcess('/usr/bin/timeout', ['--signal=TERM', '--kill-after=1s', '65s', join(binaries, 'notary')], { ...cleanEnv, NOTARY_BASE_PORT: String(port) }, sampleDir);
    try {
      const waiting = Date.now();
      while (!notary.stdoutText.includes('Local MPC notary')) {
        if (controller.signal.aborted || notary.failure || notary.exitCode !== null || Date.now() - waiting > 10000) throw new Error('Isolated notary not ready');
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      const spec = makeJob(); const trigger = join(sampleDir, 'start');
      const env = { ...cleanEnv, OUTPUT_DIR: sampleDir, PRESENTATION_FILE: join(sampleDir, 'kucoin.presentation.tlsn'), TRUSTED_NOTARY_KEY: join(sampleDir, 'notary.pub'), JOB_CHALLENGE: jobHash(spec), CONTROL_ADDR: '127.0.0.1:' + (port + 1), MPC_ADDR: '127.0.0.1:' + port, PROXY_ADDR: '127.0.0.1:' + (port + 2), ORACLE_PROBE_START_FILE: trigger, ORACLE_PROBE_WARM_TLS: 'true', ORACLE_PROBE_NETWORK: 'bandwidth', ORACLE_PROBE_NODELAY: 'true', ORACLE_PROBE_SENT_LIMIT: '512', ORACLE_PROBE_RECV_LIMIT: '16384', ORACLE_PROBE_SENT_RECORDS: '2', ORACLE_PROBE_RECV_RECORDS_ONLINE: '2' };
      const begin = process.hrtime.bigint();
      const proof = await runWarm({ binary: join(binaries, 'prove'), cwd: sampleDir, env, trigger, signal: controller.signal });
      await run(join(binaries, 'present'), [], env, sampleDir);
      await run(join(binaries, 'verify'), [], env, sampleDir);
      const result = JSON.parse(readFileSync(join(sampleDir, 'kucoin.verified.json.tlsn')));
      validateResult(result, spec, Date.now(), true);
      const end = process.hrtime.bigint();
      const presentation = readFileSync(join(sampleDir, 'kucoin.presentation.tlsn'));
      const phases = Object.fromEntries([...proof.stdout.matchAll(/PROFILE phase=(\w+) elapsed_ms=(\d+)/g)].map(m => [m[1], Number(m[2])]));
      // HTTP headers can contain cookies even for this public endpoint. Keep
      // the transcript/proof private, including on successful benchmark runs.
      const needle = Buffer.from('"price":"' + result.price + '"');
      const offset = presentation.indexOf(needle);
      if (offset < 0) throw new Error('Cannot locate authenticated price for mutation check');
      const modified = Buffer.from(presentation);
      const lastDigit = offset + needle.length - 2;
      modified[lastDigit] = modified[lastDigit] === 48 ? 49 : 48;
      const tampered = join(sampleDir, 'tampered.presentation.tlsn');
      writeFileSync(tampered, modified, { flag: 'wx', mode: 0o600 });
      const otherKey = createECDH('secp256k1'); otherKey.generateKeys();
      const wrongKey = join(sampleDir, 'wrong-notary.pub');
      writeFileSync(wrongKey, otherKey.getPublicKey('hex', 'compressed') + '\n', { flag: 'wx', mode: 0o600 });
      const challenge = jobHash(spec);
      const securityChecks = [{ name: 'original', passed: true, exitCode: 0 }];
      for (const [name, changes] of [
        ['modified-api-price', { PRESENTATION_FILE: tampered }],
        ['wrong-notary', { TRUSTED_NOTARY_KEY: wrongKey }],
        ['wrong-job', { JOB_CHALLENGE: (challenge[0] === '0' ? '1' : '0') + challenge.slice(1) }],
      ]) {
        const outcome = await run(join(binaries, 'verify'), [], { ...env, ...changes }, sampleDir, 30000, true);
        securityChecks.push({ name, ...outcome });
      }
      report.samples.push({ jobSpec: spec, verified: true, price: result.price, totalMs: Number(end - begin) / 1e6, triggerToVerifiedMs: Number(end - BigInt(readFileSync(trigger, 'utf8'))) / 1e6, phases, sessionReused: false, notaryPublicKey: readFileSync(join(sampleDir, 'notary.pub'), 'utf8').trim(), presentationSha256: sha(presentation), presentationBytes: presentation.length, requestSha256: sha(Buffer.from(result.requestHex, 'hex')), responseSha256: sha(Buffer.from(result.responseHex, 'hex')), requestBytes: result.requestHex.length / 2, responseBytes: result.responseHex.length / 2, securityChecks });
    } finally { await stopChild(notary); }
  }
  report.success = true;
} catch (error) { report.success = false; report.error = error.message; process.exitCode = 1; }
finally {
  controller.abort(); await Promise.all([...children].map(stopChild));
  rmSync(data, { recursive: true, force: true });
  process.off('SIGINT', cancel); process.off('SIGTERM', cancel);
}
const json = JSON.stringify(report, null, 2) + '\n';
if (output) writeFileSync(output, json, { flag: 'wx', mode: 0o600 });
else process.stdout.write(json);
