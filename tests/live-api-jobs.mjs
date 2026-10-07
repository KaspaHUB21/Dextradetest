// Opt-in real TLSNotary multi-API integration. Linux only; no production data.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, createWriteStream } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, sign } from 'node:crypto';
const execute = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT,'oracle-node.mjs');
const root = mkdtempSync(join(tmpdir(),'oracle-live-api-v2-'));
const active = new Set();
const read = path => JSON.parse(readFileSync(path,'utf8'));
const delay = ms => new Promise(ok => setTimeout(ok,ms));
const report = {startedAt:new Date().toISOString(), scope:'Two isolated local nodes, public API TLSNotary v2 jobs, explicitly admitted witnesses', checks:[], results:[], failures:[]};
async function cli(...args) { const r = await execute(process.execPath,[CLI,...args],{timeout:340000,maxBuffer:4*1024*1024}); return JSON.parse(r.stdout.trim()); }
async function command(...args) { return execute(process.execPath,[CLI,...args],{timeout:340000,maxBuffer:4*1024*1024}); }
async function start(data) {
  const log = createWriteStream(join(data,'test-node.log'),{mode:0o600});
  const child = spawn(process.execPath,[CLI,'start','--data',data],{stdio:['ignore','pipe','pipe']}); active.add(child); child.stdout.pipe(log); child.stderr.pipe(log);
  await new Promise((ok,no) => { const timer=setTimeout(()=>no(new Error('Node startup timeout')),20000); child.once('error',no); child.once('exit',code=>{clearTimeout(timer);no(new Error('Early node exit '+code));}); child.stdout.on('data',chunk=>{if(chunk.toString().includes('NODE READY')){clearTimeout(timer);ok();}}); }); return child;
}
async function stop(child) { if(child.exitCode!==null || child.signalCode!==null) return; await new Promise((ok,no)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');no(new Error('Node shutdown timeout'));},30000);child.once('exit',()=>{clearTimeout(timer);ok();});child.kill('SIGTERM');});active.delete(child); }
async function waitPeer(data,id) { for(let n=0;n<80;n++){try{const p=read(join(data,'peers.json')).find(p=>p.id===id&&p.confirmed&&p.apiJobs?.includes(2));if(p)return p;}catch{} await delay(250);}throw new Error('V2 peer not found'); }
const aData=join(root,'a'),bData=join(root,'b');
try {
  const a=await cli('init','--data',aData,'--address','127.0.0.1:41443','--notary-port','41047','--discovery','local-test');
  const b=await cli('init','--data',bData,'--address','127.0.0.1:45443','--notary-port','45047','--discovery','local-test');
  await command('add-seed','--data',aData,'--address',b.address,'--id',b.id);
  await command('add-seed','--data',bData,'--address',a.address,'--id',a.id);
  await start(aData);await start(bData);await waitPeer(aData,b.id);await waitPeer(bData,a.id);
  report.checks.push('Both nodes authenticated with signed v2 capability and approved witness identity');
  for(const template of ['kucoin-btc.job.json','generic-api.job.json']) {
    const specFile=join(root,template);await command('job-create','--template',join(ROOT,'templates',template),'--out',specFile);
    const started=Date.now();
    try {
      const result=await cli('fetch','--data',aData,'--job-spec',specFile);assert.equal(result.verified,true);assert.ok(result.values?.price);
      report.results.push({template,elapsedMs:Date.now()-started,...result,specFile});
    } catch(error) {report.failures.push({template,elapsedMs:Date.now()-started,message:String(error.message).slice(0,1200)});console.log('API compatibility failure:',template);}
  }
  for(const child of [...active])await stop(child);
  for(const result of report.results) {
    const verify=['verify','--data',aData,'--job',result.job,'--node-id',a.id,'--peer-id',b.id];
    const offline=await cli(...verify);assert.equal(offline.verified,true);assert.deepEqual(offline.values,result.values);
    const expected=read(result.specFile);const changed=join(root,'changed-expected.json');writeFileSync(changed,JSON.stringify({...expected,api:{...expected.api,path:'/wrong'}}));
    await assert.rejects(command(...verify,'--expected-job',changed),/expected job|binding|mismatch/i);
    const receiptFile=join(result.job,'node-receipt.json');const original=readFileSync(receiptFile);const envelope=JSON.parse(original);const receipt=JSON.parse(Buffer.from(envelope.payload,'base64'));
    receipt.values.price='999999.999';const bytes=Buffer.from(JSON.stringify(receipt));envelope.payload=bytes.toString('base64');envelope.signature=sign(null,Buffer.concat([Buffer.from('oracle-node-prototype/receipt/v1\0'),bytes]),createPrivateKey(readFileSync(join(aData,'identity.key')))).toString('base64');writeFileSync(receiptFile,JSON.stringify(envelope));
    await assert.rejects(command(...verify),/values differ|authenticated API response/i);writeFileSync(receiptFile,original);
    const proofFile=join(result.job,'kucoin.presentation.tlsn');const proof=readFileSync(proofFile);const modified=Buffer.from(proof);modified[modified.length-1]^=1;writeFileSync(proofFile,modified);await assert.rejects(command(...verify),/Presentation changed|changed|invalid/i);writeFileSync(proofFile,proof);
    const accepted=await cli(...verify,'--expected-job',result.specFile);assert.equal(accepted.accepted,true);await assert.rejects(command(...verify,'--expected-job',result.specFile),/Replay|consumed/i);
    report.checks.push(result.template+': offline full proof and extracted values verified, wrong endpoint/job rejected, validly node-signed false value rejected against TLS proof, modified proof rejected, replay rejected');
  }
  assert.ok(report.results.some(r=>r.template==='kucoin-btc.job.json'),'KuCoin BTC must succeed');
  report.finishedAt=new Date().toISOString();
  const reportPath=process.env.ORACLE_API_TEST_REPORT||join(root,'report.json');writeFileSync(reportPath,JSON.stringify(report,null,2),{mode:0o600});
  console.log(JSON.stringify({passed:true,report:reportPath,testDirectory:root,results:report.results.length,compatibilityFailures:report.failures.length}));
} finally { for(const child of [...active])await stop(child).catch(()=>{}); }
