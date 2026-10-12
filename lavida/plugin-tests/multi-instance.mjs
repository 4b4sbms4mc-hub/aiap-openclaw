// Separate plugin registrations and independently evaluated module copies.
// Dispatch identity is simulated; the Core HTTP service is real and temporary.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {readFile} from 'node:fs/promises';
import plugin from '../plugin/index.js';
import {Adapter,validateConfig} from '../plugin/adapter.js';
import {ProcessObserver} from '../plugin/diagnostics.js';

const child=spawn(process.env.AIAP_TEST_PYTHON??'python3',[new URL('./fixture.py',import.meta.url).pathname],{env:process.env,stdio:['ignore','pipe','inherit']});
const lines=createInterface({input:child.stdout});
try {
 const f=JSON.parse(await Promise.race([once(lines,'line').then(x=>x[0]),once(child,'exit').then(()=>{throw Error('Core fixture exited')})]));
 const cfg=validateConfig({baseUrl:f.baseUrl,avatarId:f.avatarId,bindings:{main:{spaceRef:'space:general',credentialFile:f.directory+'/general.json',purpose:'lavida-memory',runtimeRef:'openclaw-general',sessionKeys:['agent:main:main']}},autoPropose:{enabled:true,stateDir:f.directory+'/multi-instance'}});
 const logs=[];
 const register=(mode,config=cfg)=>{
  const hooks=new Map(),tools=new Map();
  plugin.register({pluginConfig:config,registrationMode:mode,logger:{info:s=>logs.push(s)},on:(name,fn)=>hooks.set(name,fn),registerTool:(fn,o)=>tools.set(o.names[0],fn),registerMemoryCapability:()=>{}});
  const tool=tools.get('aiap_memory_status')({agentId:'main',sessionKey:'agent:main:main',senderIsOwner:true});
  return {hooks,status:async()=> (await tool.execute('status',{})).details.automatic_proposals};
 };
 const root=register('full'),generation=register('discovery');
 const ctx={agentId:'main',sessionKey:'agent:main:main',sessionId:'private-host-session',runId:'private-run-1',trigger:'user'};
 const text='我喜欢使用简洁的分点回答。';
 generation.hooks.get('before_agent_run')({messages:[],senderIsOwner:true},ctx);
 await generation.hooks.get('agent_end')({success:true,messages:[{role:'user',content:text,timestamp:Date.now(),idempotencyKey:'private-message-1',__openclaw:{senderIsOwner:true}}]},ctx);
 const observed=await root.status(),d=observed.diagnostics,p=d.process_observer;
 assert.equal(d.before_agent_run,0);assert.equal(d.agent_end,0);
 assert.equal(p.before_agent_run,1);assert.equal(p.agent_end,1);assert.equal(p.registrations,2);
 assert.equal(p.registration_modes.full,1);assert.equal(p.registration_modes.discovery,1);
 assert.notEqual(p.last_before.instance_id,p.status_instance_id);
 assert.equal(p.last_before.outcome,'armed');assert.equal(p.last_end.capture_result.outcome,'proposed');
 assert.equal(observed.candidates.length,1);assert.equal(observed.candidates[0].status,'proposed');
 assert.equal((await new Adapter(cfg,cfg.bindings.main).search({query:text})).results.length,0);
 console.log('PASS tool and event instances differ: process observation sees callbacks and pending candidate, still no active memory');

 const {ProcessObserver:IndependentObserver}=await import('../plugin/diagnostics.js?independent-module=1');
 const copy=new IndependentObserver(cfg,'independent-copy','tool-discovery');
 assert.equal(copy.snapshot().process_id,p.process_id);assert.equal(copy.snapshot().before_agent_run,1);
 const reordered={...cfg,bindings:{main:{sessionKeys:cfg.bindings.main.sessionKeys,runtimeRef:cfg.bindings.main.runtimeRef,purpose:cfg.bindings.main.purpose,credentialFile:cfg.bindings.main.credentialFile,spaceRef:cfg.bindings.main.spaceRef}}};
 assert.equal(new ProcessObserver(reordered,'reordered','full').snapshot().before_agent_run,1);
 const foreignCfg={...cfg,avatarId:'avatar:another',autoPropose:{...cfg.autoPropose,stateDir:f.directory+'/foreign'}};
 assert.equal(new ProcessObserver(foreignCfg,'foreign','full').snapshot().before_agent_run,0);
 assert.equal(new ProcessObserver({...cfg,bindings:{main:{...cfg.bindings.main,credentialFile:'/another-private-file'}}},'other-grant','full').snapshot().agent_end,0);
 console.log('PASS independently loaded modules share observations; reordered equivalent bindings match; different bindings and credentials remain isolated');

 const split=register('discovery');
 const next={...ctx,runId:'private-run-2'};
 generation.hooks.get('before_agent_run')({messages:[],senderIsOwner:true},next);
 await split.hooks.get('agent_end')({success:true,messages:[]},next);
 const mismatch=await root.status();
 assert.equal(mismatch.diagnostics.process_observer.last_end.reason,'E_AUTO_NO_GATE');
 assert.equal(mismatch.candidates.length,1);
 assert.equal(observed.diagnostics.process_observer.before_agent_run,1);
 assert.equal(observed.diagnostics.process_observer.registrations,2);
 console.log('PASS split before/end registrations are diagnosed without sharing run gates or changing captures; snapshots remain stable');

 for(const value of [observed.diagnostics,mismatch.diagnostics,logs]) {
  const output=JSON.stringify(value);
  for(const secret of [text,'private-host-session','private-run-1','private-message-1',cfg.baseUrl,cfg.bindings.main.credentialFile,f.avatarId,JSON.parse(await readFile(cfg.bindings.main.credentialFile)).token])assert(!output.includes(secret),secret);
 }
 assert(logs.some(s=>s.includes('event=registered')&&s.includes('mode=full')));
 assert(logs.some(s=>s.includes('event=before_agent_run')&&s.includes('mode=discovery')));
 assert(logs.filter(s=>s.includes('event=before_agent_run')).length===1);
 const bad=new ProcessObserver(cfg,'safe-id','sensitive-arbitrary-mode',{info:s=>logs.push(s)});bad.registered();
 assert(!JSON.stringify(logs).includes('sensitive-arbitrary-mode'));
 console.log('PASS bounded receipt logs and status diagnostics exclude chat text, session/run/message IDs, configuration and credentials');
 console.log('PASS 4 multi-instance checks. Simulated host registry dispatch; real Core HTTP. Live NAS acceptance required.');
} finally {lines.close();child.kill('SIGTERM')}
