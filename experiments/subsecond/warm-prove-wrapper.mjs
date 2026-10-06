import { spawn } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// One fresh child/session. Never reuse preparation material across requests.
export function runWarm({ binary, cwd, env, trigger, deadlineMs = 60000, signal }) {
  if (process.platform !== 'linux') throw new Error('This experiment requires Linux');
  if (!Number.isInteger(deadlineMs) || deadlineMs < 100 || deadlineMs > 60000) throw new Error('Invalid warm deadline');
  if (signal?.aborted) return Promise.reject(new Error('Experiment cancelled'));
  if (existsSync(trigger) || existsSync(trigger + '.ready')) throw new Error('Trigger must be fresh');
  return new Promise((resolve, reject) => {
    const child = spawn(binary, [], { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', failure, fireTimer, killTimer, fired = false;
    const groupSignal = name => { if (child.pid) { try { process.kill(-child.pid, name); } catch (error) { if (error.code !== 'ESRCH') failure ??= error; } } };
    const stop = error => {
      failure ??= error;
      clearInterval(poll); clearTimeout(fireTimer);
      groupSignal('SIGTERM');
      killTimer ??= setTimeout(() => groupSignal('SIGKILL'), 1000);
    };
    const cancel = () => stop(new Error('Experiment cancelled'));
    const poll = setInterval(() => {
      if (!existsSync(trigger + '.ready') || fired || fireTimer || failure) return;
      fireTimer = setTimeout(() => {
        if (failure) return;
        try { writeFileSync(trigger, process.hrtime.bigint().toString(), { flag: 'wx', mode: 0o600 }); fired = true; }
        catch (error) { stop(error); }
      }, 2000);
    }, 10);
    const timer = setTimeout(() => stop(new Error('Warm experiment deadline exceeded')), deadlineMs);
    signal?.addEventListener('abort', cancel, { once: true });
    const capture = (name, data) => {
      if (name === 'stdout') stdout += data; else stderr += data;
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 4 * 1024 * 1024) stop(new Error('Prover log limit exceeded'));
    };
    child.stdout.on('data', data => capture('stdout', data));
    child.stderr.on('data', data => capture('stderr', data));
    child.once('error', error => { failure ??= error; });
    child.once('close', (code, endedSignal) => {
      clearInterval(poll); clearTimeout(timer); clearTimeout(fireTimer); clearTimeout(killTimer);
      signal?.removeEventListener('abort', cancel);
      // Also remove any descendants that survived the prover itself.
      groupSignal('SIGKILL');
      if (failure || code !== 0 || !fired) reject(failure ?? new Error(`Prover failed (${code ?? endedSignal})`));
      else resolve({ stdout, stderr });
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once('SIGTERM', cancel); process.once('SIGINT', cancel);
  try {
    const result = await runWarm({ binary: process.env.ORACLE_WARM_PROVE, cwd: process.cwd(), env: process.env, trigger: process.env.ORACLE_PROBE_START_FILE, signal: controller.signal });
    process.stdout.write(result.stdout); process.stderr.write(result.stderr);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
  finally { process.off('SIGTERM', cancel); process.off('SIGINT', cancel); }
}
