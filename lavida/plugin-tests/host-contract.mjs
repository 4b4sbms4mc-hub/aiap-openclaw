// Exercises unchanged OpenClaw runner regions with only external service shims.
// Event identity is simulated; this is not a complete Gateway/NAS test.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {runInNewContext} from 'node:vm';
import {AsyncLocalStorage} from 'node:async_hooks';
import {randomUUID,createHash} from 'node:crypto';
import plugin from '../plugin/index.js';
import {Adapter,validateConfig} from '../plugin/adapter.js';

const sourcePath=process.env.OPENCLAW_HOOK_SOURCE ?? new URL('../../openclaw_reference/dist/hook-runner-global-BhDCl4qm.mjs',import.meta.url);
const source=await readFile(sourcePath,'utf8');
const regions=['src/plugins/hook-decision-types.ts','src/plugins/hook-isolation.ts','src/plugins/hook-types.ts','src/plugins/hooks.ts'];
const region=name=>{
 const begin=source.indexOf('//#region '+name+'\n');assert(begin>=0,name);
 const end=source.indexOf('//#endregion',begin);assert(end>begin,name);
 return source.slice(begin,end);
};
const {createHookRunner}=runInNewContext(regions.map(region).join('\n')+'\n({createHookRunner});',{
 AsyncLocalStorage,randomUUID,setTimeout,clearTimeout,structuredClone,
 trackAsyncWork:work=>Promise.resolve().then(work),
 clampPositiveTimerTimeoutMs:n=>typeof n==='number' && n>0 ? n : undefined,
 formatErrorMessage:e=>e?.message ?? String(e),formatHookErrorForLog:e=>e?.message ?? String(e)
});
console.log('OpenClaw hook source sha256: '+createHash('sha256').update(source).digest('hex'));
const registryFor=fn=>({plugins:[{id:'fixture'}],typedHooks:[{pluginId:'fixture',hookName:'before_agent_run',handler:fn}]});
assert.equal(await createHookRunner(registryFor(()=>undefined)).runBeforeAgentRun({},{}),undefined);
assert.equal((await createHookRunner(registryFor(()=>({outcome:'pass'}))).runBeforeAgentRun({},{})).decision.outcome,'pass');
assert.equal((await createHookRunner(registryFor(()=>({outcome:'invalid'}))).runBeforeAgentRun({},{})).decision.outcome,'block');
console.log('PASS upstream runner allows void and explicit pass; invalid nonempty decisions block');

const child=spawn(process.env.AIAP_TEST_PYTHON??'python3',[new URL('./fixture.py',import.meta.url).pathname],{env:process.env,stdio:['ignore','pipe','inherit']});
const lines=createInterface({input:child.stdout});
try {
 const f=JSON.parse(await Promise.race([once(lines,'line').then(x=>x[0]),once(child,'exit').then(()=>{throw Error('Core fixture exited')})]));
 const cfg=validateConfig({baseUrl:f.baseUrl,avatarId:f.avatarId,bindings:{main:{spaceRef:'space:general',credentialFile:f.directory+'/general.json',purpose:'lavida-memory',runtimeRef:'openclaw-general',sessionKeys:['agent:main:main']}},autoPropose:{enabled:true,stateDir:f.directory+'/host-contract'}});
 const registry={plugins:[{id:'lavida-aiap',packageVersion:'0.3.4'}],typedHooks:[]},factories=new Map();
 plugin.register({pluginConfig:cfg,on:(name,fn,opts)=>registry.typedHooks.push({pluginId:'lavida-aiap',hookName:name,handler:fn,...opts}),registerTool:(fn,opts)=>factories.set(opts.names[0],fn),registerMemoryCapability:()=>{}});
 const runner=createHookRunner(registry);
 const tool=factories.get('aiap_memory_status')({agentId:'main',sessionKey:'agent:main:main',senderIsOwner:true});
 const status=async()=> (await tool.execute('status',{})).details.automatic_proposals;
 const idle=await status();assert.equal(idle.diagnostics.before_agent_run,0);assert.equal(idle.diagnostics.agent_end,0);
 let seq=0;
 const turn=async(text,ctxPatch={},beforePatch={},messagePatch={},endPatch={})=>{
  const ctx={agentId:'main',sessionKey:'agent:main:main',sessionId:'host-session',runId:'run-'+(++seq),trigger:'user',...ctxPatch};
  const result=await runner.runBeforeAgentRun({messages:[],senderIsOwner:true,...beforePatch},ctx);
  assert.equal(result.decision.outcome,'pass');
  await runner.runAgentEnd({success:true,messages:[{role:'user',content:text,timestamp:Date.now(),idempotencyKey:'turn-'+seq+':user',__openclaw:{senderIsOwner:true},...messagePatch}],...endPatch},ctx);
  return status();
 };
 const text='我喜欢使用简洁的分点回答。';
 const proposed=await turn(text);assert.equal(proposed.last.outcome,'proposed');assert.equal(proposed.candidates.length,1);
 assert.equal(proposed.diagnostics.before_agent_run,1);assert.equal(proposed.diagnostics.agent_end,1);
 assert.equal(proposed.diagnostics.last_before.outcome,'armed');assert(proposed.diagnostics.last_end.source_checks.owner_confirmed);
 assert.equal((await new Adapter(cfg,cfg.bindings.main).search({query:text})).results.length,0);
 console.log('PASS plugin generates one pending candidate through upstream before/end dispatch; no active memory before owner approval');
 const cases=[
  [{trigger:undefined},{},{},{},'E_AUTO_TRIGGER'],
  [{},{senderIsOwner:false},{},{},'E_AUTO_OWNER'],
  [{},{senderIsOwner:undefined},{},{},'E_AUTO_OWNER'],
  [{sessionId:undefined},{},{},{},'E_AUTO_CONTEXT'],
  [{sandboxed:true},{},{},{},'E_AUTO_SANDBOX'],
  [{inputProvenance:{kind:'inter_session'}},{},{},{},'E_AUTO_PROVENANCE'],
  [{},{},{idempotencyKey:undefined},{},'E_AUTO_SOURCE'],
  [{},{},{__openclaw:{senderIsOwner:false}},{},'E_AUTO_OWNER'],
  [{},{},{},{success:false},'E_AUTO_RUN_FAILED']
 ];
 for(const [ctx,before,message,end,reason] of cases) {
  const value=await turn('我喜欢完整而清晰的说明。',ctx,before,message,end);
  assert.equal(value.last.reason,reason);
  assert.equal(value.candidates.length,1);
  assert.equal(value.diagnostics.instance_id,idle.diagnostics.instance_id);
 }
 console.log('PASS missing trigger/owner/context, sandbox, internal input, missing source and failed runs are diagnosed without additional writes');
 const snapshot=await status();
 await turn('你好');assert.equal(snapshot.diagnostics.before_agent_run,seq-1);
 assert(!JSON.stringify(snapshot.diagnostics).includes('完整而清晰'));assert(!JSON.stringify(snapshot.diagnostics).includes('host-session'));
 console.log('PASS status snapshots retain stable counters and disclose no message text or session identifiers');
 console.log('PASS 4 host contract checks. Upstream runner regions, simulated host event identity, real temporary Core HTTP. NAS acceptance required.');
} finally {lines.close();child.kill('SIGTERM')}
