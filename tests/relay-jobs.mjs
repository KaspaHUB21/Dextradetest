import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, createWriteStream } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeJob } from '../jobs.mjs';

const run = promisify(execFile);
const CLI = resolve(dirname(fileURLToPath(import.meta.url)), '../oracle-node.mjs');
const root = process.env.ORACLE_TEST_RESULTS || '/tmp/oracle-relay-tests';
mkdirSync(root, { recursive: true, mode: 0o700 });
const directory = mkdtempSync(join(root, 'relay-job-'));
const children = new Set(); const logs = [];
const read = file => JSON.parse(readFileSync(file, 'utf8'));
const delay = ms => new Promise(ok => setTimeout(ok, ms));
const cli = async (...args) => {
  const { stdout } = await run(process.execPath, [CLI, ...args], { timeout: 360000, maxBuffer: 8 * 1024 * 1024 });
  return ['init','submit','job-status','job-result','verify'].includes(args[0]) ? JSON.parse(stdout) : stdout;
};
async function start(data) {
  const log = createWriteStream(join(data, 'relay-job.log'), { mode: 0o600 }); logs.push(log);
  const child = spawn(process.execPath, [CLI,'start','--data',data]); children.add(child);
  child.stdout.pipe(log); child.stderr.pipe(log,{end:false});
  await new Promise((ok,no) => {
    const timer = setTimeout(() => no(new Error('Startup timeout')),20000);
    child.once('error',no); child.once('exit',code => no(new Error('Startup exited '+code)));
    child.stdout.on('data',data => { if(data.toString().includes('NODE READY')) {clearTimeout(timer);ok();} });
  }); return child;
}
async function stop(child) {
  if(child.exitCode !== null || child.signalCode !== null) {children.delete(child);return;}
  await new Promise((ok,no) => {const timer=setTimeout(()=>{child.kill('SIGKILL');no(new Error('Shutdown timeout'));},10000);child.once('exit',()=>{clearTimeout(timer);ok();});child.kill('SIGTERM');});children.delete(child);
}
async function observed(data,id,relay=false) {
  const until=Date.now()+45000;
  while(Date.now()<until) {
    try {const p=read(join(data,'peers.json')).find(p=>p.id===id);if(p?.confirmed && Date.now()-p.lastSeen<25000 && (!relay||p.relayVia)) return;}catch{}
    await delay(200);
  } throw new Error('Peer not authenticated '+id);
}
const report={startedAt:new Date().toISOString(),checks:[]};
try {
  const aData=join(directory,'entry'),bData=join(directory,'worker'),cData=join(directory,'witness'),dData=join(directory,'requester');
  const a=await cli('init','--data',aData,'--address','127.0.0.1:42443','--notary-port','42047','--discovery','local-test');
  const b=await cli('init','--data',bData,'--outbound-only','true','--listen','127.0.0.1:43443','--notary-port','43047','--discovery','local-test');
  const c=await cli('init','--data',cData,'--outbound-only','true','--listen','127.0.0.1:44443','--notary-port','44047','--discovery','local-test');
  const d=await cli('init','--data',dData,'--outbound-only','true','--listen','127.0.0.1:46443','--notary-port','46047','--discovery','local-test');
  for(const data of [bData,cData,dData]) await cli('add-bootstrap','--data',data,'--address',a.address,'--id',a.id);
  for(const data of [aData,bData,cData,dData]) await start(data);
  await observed(bData,c.id,true);await observed(cData,b.id,true);await observed(aData,b.id);await observed(aData,c.id);
  await observed(dData,b.id,true);await observed(dData,c.id,true);
  await cli('trust-peer','--data',bData,'--id',c.id);
  await cli('trust-peer','--data',dData,'--id',b.id);
  await cli('trust-peer','--data',dData,'--id',c.id);
  await cli('allow-client','--data',bData,'--id',d.id);
  await cli('allow-client','--data',cData,'--id',b.id);
  for(const child of [...children]) await stop(child);
  for(const data of [aData,bData,cData,dData]) await start(data);
  await observed(bData,c.id,true);await observed(cData,b.id,true);await observed(aData,b.id);
  await observed(dData,b.id,true);await observed(dData,c.id,true);
  const spec={...makeJob(),id:'relayed-witness-job',notAfter:Date.now()+300000};
  const specPath=join(directory,'job.json');writeFileSync(specPath,JSON.stringify(spec),{mode:0o600});
  const submitted=await cli('submit','--data',dData,'--peer-id',b.id,'--job-spec',specPath);
  const until=Date.now()+310000;
  while(true){
    const status=await cli('job-status','--data',dData,'--peer-id',b.id,'--queue-id',submitted.queueId);
    if(status.status==='failed') throw new Error('Relayed job failed '+JSON.stringify(status.error));
    if(status.status==='completed') break;
    if(Date.now()>until) throw new Error('Relayed job timeout');
    await delay(5000);
  }
  const result=await cli('job-result','--data',dData,'--peer-id',b.id,'--queue-id',submitted.queueId);
  assert.equal(result.verified,true);assert.equal(result.accepted,true);assert.equal(result.peerId,c.id);assert.equal(result.nodeId,b.id);
  await assert.rejects(cli('job-result','--data',dData,'--peer-id',b.id,'--queue-id',submitted.queueId),/Replay|consumed|already/i);
  report.checks.push('Outbound requester submits to outbound worker, which proves real KuCoin response with outbound witness over end-to-end encrypted relay');
  for(const child of [...children]) await stop(child);
  const offline=await cli('verify','--job',result.job,'--node-id',b.id,'--peer-id',c.id);
  assert.equal(offline.verified,true);
  report.checks.push('Imported relay proof verifies with all nodes stopped; duplicate acceptance rejected');
  report.result={verified:true,nodeId:b.id,peerId:c.id,job:result.job};report.success=true;
}catch(error){report.success=false;report.error=error.message;console.error(error.stack);process.exitCode=1;}
finally{
  const outcomes=await Promise.allSettled([...children].map(stop));
  if(outcomes.some(x=>x.status==='rejected')){report.success=false;report.shutdownError='Node shutdown failed';process.exitCode=1;}
  for(const log of logs)log.end();report.finishedAt=new Date().toISOString();
  writeFileSync(join(directory,'report.json'),JSON.stringify(report,null,2),{mode:0o600});
  console.log(JSON.stringify({success:report.success,report:join(directory,'report.json')}));
}
