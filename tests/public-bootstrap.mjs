// Opt-in live test: initializes a fresh identity and contacts the public anchor.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DEFAULT_BOOTSTRAP } from '../network-defaults.mjs';
const run = promisify(execFile);
const cli = fileURLToPath(new URL('../oracle-node.mjs', import.meta.url));
const data = mkdtempSync(join(tmpdir(), 'oracle-bootstrap-'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
let child; let logs = '';
try {
  await run(process.execPath, [cli, 'init', '--data', data, '--listen', '127.0.0.1:37443', '--notary-port', '37047'], { timeout: 30000 });
  const cfg = JSON.parse(readFileSync(join(data, 'config.json')));
  assert.equal(cfg.discovery, 'public');
  assert.equal(cfg.outboundOnly, true);
  assert.equal(cfg.address, null);
  assert.deepEqual(cfg.bootstraps, [DEFAULT_BOOTSTRAP]);
  assert.deepEqual(cfg.seeds, []);
  child = spawn(process.execPath, [cli, 'start', '--data', data], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.on('error', error => { logs += error.message; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { logs = (logs + bytes).slice(-16000); });
  const deadline = Date.now() + 45000;
  let peer;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error('Node exited: ' + logs);
    try { peer = JSON.parse(readFileSync(join(data, 'peers.json'))).find(p => p.id === DEFAULT_BOOTSTRAP.id); } catch {}
    if (peer?.confirmed && peer.mesh && Date.now() - peer.lastSeen < 15000) break;
    await delay(250);
  }
  assert.ok(peer?.confirmed && peer.mesh && Date.now() - peer.lastSeen < 15000, 'Fresh node must authenticate and connect to the built-in bootstrap: ' + logs);
  assert.deepEqual(JSON.parse(readFileSync(join(data, 'config.json'))).seeds, [], 'Discovery never grants witness trust');
  console.log(JSON.stringify({ passed: true, bootstrap: DEFAULT_BOOTSTRAP.address, identity: peer.id, authenticated: true, mesh: true, automaticWitnessTrust: false }));
} finally {
  if (child && child.exitCode === null && child.signalCode === null) {
    await new Promise(resolve => {
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
      child.kill('SIGTERM');
    });
  }
  rmSync(data, { recursive: true, force: true });
}
