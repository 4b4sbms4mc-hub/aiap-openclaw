// Actual SQLite storage and Core HTTP, simulated OpenClaw event identity.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {mkdir,readFile,rename,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {createHash} from 'node:crypto';
import plugin from '../plugin/index.js';
import {AutoProposer} from '../plugin/auto.js';
import {Adapter,validateConfig} from '../plugin/adapter.js';
import {readCanonicalOwnerMessage,sourceDiagnostics} from '../plugin/source.js';

// Execute unchanged host message creation and non-replay append regions.
// External media helpers and time are controlled; this is not a full Gateway test.
const runtimePath=process.env.OPENCLAW_RUNTIME_SOURCE ?? new URL('../../openclaw_reference/dist/resource-loader-Bu_pVD2t.mjs',import.meta.url);
const messagePath=process.env.OPENCLAW_MESSAGE_SOURCE ?? new URL('../../openclaw_reference/dist/user-turn-transcript.message-C84t0g-c.mjs',import.meta.url);
const runtimeSource=await readFile(runtimePath,'utf8'),messageSource=await readFile(messagePath,'utf8');
const region=(source,start,end)=>{
 const i=source.indexOf(start);assert(i>=0,start);const j=source.indexOf(end,i+start.length);assert(j>i,end);return source.slice(i,j);
};
const create=region(runtimeSource,'\tcreateUserMessage(text, images, preparedMessage) {','\n\t/**');
const merge=region(messageSource,'function mergePreparedUserTurnMessageForRuntime(params) {','\n//#endregion');
const appendStart=runtimeSource.indexOf('\t\t\tif (!replayPersistedTurn) messages.push({');assert(appendStart>=0);
const appendEnd=runtimeSource.indexOf('\n\t\t\t});',appendStart);assert(appendEnd>appendStart);
const append=runtimeSource.slice(appendStart,appendEnd+'\n\t\t\t});'.length);
let runtimeClock;
const hostSession=runInNewContext(merge+'\n({'+create+'})',{
 Date:{now:()=>runtimeClock},readRuntimePromptImageFactIndexes:()=>undefined,
 isUserMessage:m=>m?.role==='user',isBeforeAgentRunBlockedMessage:m=>m?.__openclaw?.beforeAgentRunBlocked!==undefined,
 readOpenClawMessageMeta:m=>m?.__openclaw,userMessageHasImageContent:m=>Array.isArray(m?.content)&&m.content.some(b=>b?.type==='image')
});
hostSession.createUserContent=(text,images)=>[{type:'text',text},...images??[]];
const project=runInNewContext('(function(expandedText,persistedUserIdempotencyKey){const currentImages=undefined,replayPersistedTurn=false,messages=[];'+append+';return messages[0]})');
const hostRuntime=(text,key,stamp)=>{runtimeClock=stamp;return project.call(hostSession,text,key)};
console.log('OpenClaw runtime source sha256: '+createHash('sha256').update(runtimeSource).digest('hex'));
console.log('OpenClaw user message source sha256: '+createHash('sha256').update(messageSource).digest('hex'));
const projected=hostRuntime('runtime projection','example:user',123456);
assert.equal(projected.timestamp,123456);assert.equal(projected.idempotencyKey,'example:user');assert.equal(projected.__openclaw,undefined);
runtimeClock=200000;
const replayed=hostSession.createUserMessage('runtime projection',undefined,{role:'user',content:'canonical text',timestamp:100000,idempotencyKey:'example:user',__openclaw:{senderIsOwner:true}});
assert.equal(replayed.timestamp,100000);assert.equal(replayed.__openclaw.senderIsOwner,true);
console.log('PASS unchanged host creation uses a new runtime timestamp without owner metadata for a non-replay message; prepared replay retains canonical timestamp and ownership');

const child=spawn(process.env.AIAP_TEST_PYTHON??'python3',[new URL('./fixture.py',import.meta.url).pathname],{env:process.env,stdio:['ignore','pipe','inherit']});
const lines=createInterface({input:child.stdout});
const originalStateDir=process.env.OPENCLAW_STATE_DIR;
let db;
try {
 const f=JSON.parse(await Promise.race([once(lines,'line').then(x=>x[0]),once(child,'exit').then(()=>{throw Error('Core fixture exited')})]));
 const stateDir=join(f.directory,'openclaw');process.env.OPENCLAW_STATE_DIR=stateDir;
 const dbPath=join(stateDir,'agents','main','agent','openclaw-agent.sqlite');await mkdir(join(stateDir,'agents','main','agent'),{recursive:true,mode:0o700});
 db=new DatabaseSync(dbPath);
 // Same table and JSON shape used by the 2026.9.4 canonical transcript owner.
 db.exec(`CREATE TABLE session_nodes (session_key TEXT PRIMARY KEY,current_session_id TEXT NOT NULL);
 CREATE TABLE transcript_events (session_id TEXT NOT NULL,seq INTEGER NOT NULL,event_json TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(session_id,seq));`);
 db.prepare('INSERT INTO session_nodes VALUES (?,?)').run('agent:main:main','canonical-session');
 const cfg=validateConfig({baseUrl:f.baseUrl,avatarId:f.avatarId,bindings:{main:{spaceRef:'space:general',credentialFile:f.directory+'/general.json',purpose:'lavida-memory',runtimeRef:'openclaw-general',sessionKeys:['agent:main:main']}},autoPropose:{enabled:true,stateDir:f.directory+'/canonical-journal'}});
 const a=new Adapter(cfg,cfg.bindings.main);
 let seq=0,turnNo=0;
 const append=(message,sessionId='canonical-session')=>db.prepare('INSERT INTO transcript_events VALUES (?,?,?,?)').run(sessionId,++seq,JSON.stringify({type:'message',id:'entry-'+seq,message}),Date.now());
 const records=(text,opts={})=>{
  const ctx={agentId:'main',sessionKey:'agent:main:main',sessionId:'canonical-session',runId:'canonical-run-'+(++turnNo),trigger:'user',...opts.ctx};
  const raw={role:'user',content:text,timestamp:Date.now(),idempotencyKey:ctx.runId+':user',__openclaw:{senderIsOwner:true},...opts.raw};
  append(raw,opts.storedSession??ctx.sessionId);
  if (opts.receipt!==false) append({role:'assistant',content:'已回复',timestamp:Date.now(),stopReason:'stop',__openclaw:{runId:ctx.runId},...opts.receipt},opts.storedSession??ctx.sessionId);
  const runtime={...raw,__openclaw:{},...opts.runtime};
  return {ctx,raw,runtime};
 };
 const register=mode=>{
  const hooks=new Map(),tools=new Map();
  plugin.register({pluginConfig:cfg,registrationMode:mode,on:(name,fn)=>hooks.set(name,fn),registerTool:(fn,o)=>tools.set(o.names[0],fn),registerMemoryCapability:()=>{}});
  const tool=tools.get('aiap_memory_status')({agentId:'main',sessionKey:'agent:main:main',senderIsOwner:true});
  return {hooks,status:async()=> (await tool.execute('status',{})).details.automatic_proposals};
 };
 const root=register('full'),generation=register('discovery');
 const text='我喜欢使用简洁的分点回答。';
 const r=records(text);
 r.runtime=hostRuntime('变换后的运行时文本',r.raw.idempotencyKey,r.raw.timestamp+12000);
 generation.hooks.get('before_agent_run')({messages:[],senderIsOwner:true},r.ctx);
 await generation.hooks.get('agent_end')({success:true,messages:[r.runtime]},r.ctx);
 const s=await root.status(),checks=s.diagnostics.process_observer.last_end.source_checks;
 assert.equal(s.candidates.length,1);assert.equal(s.candidates[0].status,'proposed');
 assert.equal(checks.runtime_owner_marker,'missing');assert.equal(checks.owner_confirmed,true);
 assert.equal(checks.canonical_source.run_matches,true);assert.equal(checks.runtime_text_matches,false);
 assert.equal(checks.canonical_source.key_matches_run,true);assert.equal(checks.canonical_source.runtime_timestamp_matches,false);
 assert.equal(checks.canonical_source.canonical_timestamp_recent,true);assert.equal(checks.canonical_source.stage,'verified');
 assert.equal(s.candidates[0].observed_at,new Date(r.raw.timestamp).toISOString());
 assert.equal((await a.search({query:text})).results.length,0);
 const owner=JSON.parse(await readFile(f.directory+'/owner-credentials.json'));
 const ownerCall=async(path,body)=>{const result=await fetch(f.baseUrl+path,{method:'POST',headers:{Authorization:'Bearer '+owner.token,'Content-Type':'application/json'},body:JSON.stringify(body)});assert.equal(result.status,200);return result.json()};
 const delta=s.candidates[0].delta_id,review=await ownerCall('/v1/deltas/review',{delta_id:delta});
 assert.equal(review.candidate.delta.changes[0].candidate.content,text);
 assert.equal(review.candidate.delta.changes[0].candidate.source.source_type,'explicit-user');
 assert.equal(review.candidate.delta.changes[0].candidate.created_at,new Date(r.raw.timestamp).toISOString());
 console.log('PASS real host projection with a different timestamp and body recovers exact current-run canonical owner text; one pending candidate uses canonical observed_at across registration instances');

 const bytes=await readFile(dbPath);
 const sourceFor=rec=>({...rec.ctx,key:rec.raw.idempotencyKey,stamp:rec.runtime.timestamp,started:Date.now()});
 const verified=await readCanonicalOwnerMessage(sourceFor(r));
 assert.equal(verified.message.content,text);assert.deepEqual(await readFile(dbPath),bytes);
 const invalidPath=join(f.directory,'wrong-schema.sqlite'),wrong=new DatabaseSync(invalidPath);wrong.close();
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(r),invalidPath),e=>e.code==='E_AUTO_TRANSCRIPT_UNAVAILABLE');
 const untouched=new DatabaseSync(invalidPath,{readOnly:true});assert.equal(untouched.prepare('SELECT count(*) AS n FROM sqlite_master').get().n,0);untouched.close();
 console.log('PASS successful source recovery leaves canonical database bytes unchanged; an unknown schema is neither accepted nor initialized');

 let auto=new AutoProposer(cfg),reads=0;
 const reader=auto.sourceReader;auto.sourceReader=async source=>{reads++;return reader(source)};
 const turn=async(content,opts={})=>{
  const rec=records(content,opts);
  auto.before({messages:opts.oldMessages??[],senderIsOwner:opts.beforeOwner??true},rec.ctx);
  if (opts.afterAppend) opts.afterAppend(rec);
  await auto.end({success:opts.success??true,messages:[rec.runtime]},rec.ctx);
  return {rec,last:auto.last,diagnostics:auto.diagnostics};
 };
 const beforeReads=reads;
 for (const patch of [{__openclaw:{senderIsOwner:false}},{__openclaw:{senderIsOwner:'true'}}]) {
  assert.equal((await turn('我喜欢温暖的室内照明。',{runtime:patch})).last.reason,'E_AUTO_OWNER');
 }
 assert.equal(reads,beforeReads);
 assert.equal((await turn('我喜欢温暖的室内照明。',{beforeOwner:false})).last.reason,'E_AUTO_OWNER');
 assert.equal(reads,beforeReads);
 console.log('PASS explicit false/invalid runtime ownership and unauthenticated before event remain denied without a transcript read');

 const cases=[
  [{raw:{__openclaw:{senderIsOwner:false}}},'E_AUTO_OWNER'],
  [{raw:{__openclaw:{}}},'E_AUTO_OWNER'],
  [{runtime:{idempotencyKey:'different-key'}},'E_AUTO_TRANSCRIPT_KEY'],
  [{raw:{timestamp:Date.now()-600000},runtime:{timestamp:Date.now()}},'E_AUTO_TRANSCRIPT_TIME'],
  [{raw:{timestamp:Date.now()+600000},runtime:{timestamp:Date.now()}},'E_AUTO_TRANSCRIPT_TIME'],
  [{receipt:false},'E_AUTO_TRANSCRIPT_RUN'],
  [{receipt:{__openclaw:{runId:'different-run'}}},'E_AUTO_TRANSCRIPT_RUN'],
  [{receipt:{stopReason:'toolUse'}},'E_AUTO_TRANSCRIPT_RUN'],
  [{receipt:{stopReason:'error'}},'E_AUTO_TRANSCRIPT_RUN'],
  [{ctx:{sessionId:'another-session'}},'E_AUTO_TRANSCRIPT_SESSION'],
  [{raw:{display:false}},'E_AUTO_SOURCE'],
  [{raw:{provenance:{kind:'inter_session'}}},'E_AUTO_SOURCE'],
  [{raw:{__openclaw:{senderIsOwner:true,lateMedia:true}}},'E_AUTO_TRANSCRIPT_SOURCE'],
  [{raw:{__openclaw:{senderIsOwner:true,beforeAgentRunBlocked:{}}}},'E_AUTO_TRANSCRIPT_SOURCE'],
  [{runtime:{display:false}},'E_AUTO_SOURCE'],
  [{runtime:{__openclaw:{lateMedia:true}}},'E_AUTO_SOURCE'],
  [{ctx:{sandboxed:true}},'E_AUTO_SANDBOX'],
  [{ctx:{sessionKey:'agent:main:group:test'}},undefined],
  [{success:false},'E_AUTO_RUN_FAILED']
 ];
 for (const [opts,reason] of cases) {
  const v=await turn('我喜欢温暖的室内照明。',opts);
  if (reason) assert.equal(v.last.reason,reason,JSON.stringify(opts));
  if (reason==='E_AUTO_TRANSCRIPT_TIME') {
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.stage,'time');
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.canonical_timestamp_recent,false);
  }
  if (reason==='E_AUTO_TRANSCRIPT_RUN') {
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.stage,'receipt');
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.run_matches,false);
  }
  if (opts.runtime?.idempotencyKey==='different-key') {
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.stage,'context');
   assert.equal(v.diagnostics.last_end.source_checks.canonical_source.key_matches_run,false);
  }
  assert.equal((await root.status()).candidates.length,1);
 }
 console.log('PASS false/missing canonical owner, source-key/run/session mismatch and stale/future canonical time, hidden/internal/blocked/media messages, group, sandbox and failed runs never add candidates');

 const later=await turn('我喜欢温暖的室内照明。',{afterAppend:()=>append({role:'user',content:'后来的另一条消息',timestamp:Date.now(),idempotencyKey:'later',__openclaw:{senderIsOwner:true}})});
 assert.equal(later.last.reason,'E_AUTO_TRANSCRIPT_KEY');
 assert.equal(later.diagnostics.last_end.source_checks.canonical_source.stage,'key');
 assert.equal(later.diagnostics.last_end.source_checks.canonical_source.key_matches,false);
 const history=records('我喜欢温暖的室内照明。');
 auto.before({messages:[history.runtime],senderIsOwner:true},history.ctx);await auto.end({success:true,messages:[history.runtime]},history.ctx);
 assert.equal(auto.last.reason,'E_AUTO_SOURCE');
 db.prepare('UPDATE session_nodes SET current_session_id=?').run('replacement-session');
 const changed=await turn('我喜欢温暖的室内照明。');
 assert.equal(changed.last.reason,'E_AUTO_TRANSCRIPT_SESSION');
 assert.equal(changed.diagnostics.last_end.source_checks.canonical_source.session_matches,false);
 db.prepare('UPDATE session_nodes SET current_session_id=?').run('canonical-session');
 console.log('PASS later admitted users, historical snapshots and replaced sessions cannot be recovered as the current owner source');

 const recent=records('我喜欢温暖的室内照明。');
 for (let i=0;i<64;i++) append({role:'toolResult',content:'x'});
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(recent)),e=>e.code==='E_AUTO_TRANSCRIPT_SOURCE');
 const huge=records('x'.repeat(70000));
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(huge)),e=>e.code==='E_AUTO_TRANSCRIPT_LIMIT');
 db.close();db=null;
 const before=await readFile(dbPath);
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(huge)),e=>e.code==='E_AUTO_TRANSCRIPT_LIMIT');
 assert.deepEqual(await readFile(dbPath),before);
 await rename(dbPath,dbPath+'.saved');
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(huge)),e=>e.code==='E_AUTO_TRANSCRIPT_UNAVAILABLE');
 await symlink(dbPath+'.saved',dbPath);
 await assert.rejects(()=>readCanonicalOwnerMessage(sourceFor(huge)),e=>e.code==='E_AUTO_TRANSCRIPT_UNAVAILABLE');
 await rename(dbPath+'.saved',dbPath+'.original');
 console.log('PASS bounded lookback and payload, missing databases and symlinks fail closed; read-only recovery does not change database bytes');

 // Reopen only the test writer, with no symlink, for positive approval/dedupe tests.
 const {unlink}=await import('node:fs/promises');await unlink(dbPath);await rename(dbPath+'.original',dbPath);
 db=new DatabaseSync(dbPath);
 await ownerCall('/v1/deltas/decide',{delta_id:delta,approve:true});
 assert.equal((await a.search({query:text})).results[0].revision,1);
 auto=new AutoProposer(cfg);assert.equal((await turn(text)).last.outcome,'duplicate');assert.equal(auto.last.delta_id,delta);assert.equal(auto.last.status,'accepted');
 assert.equal((await root.status()).candidates.length,1);
 for (const value of [s.diagnostics,auto.diagnostics]) {
  const output=JSON.stringify(value);
  for (const privateValue of [text,r.ctx.runId,r.ctx.sessionId,r.raw.idempotencyKey,dbPath,owner.token]) assert(!output.includes(privateValue));
 }
 console.log('PASS owner approval alone activates revision 1; repeated recovered source after proposer restart is deduplicated; status excludes private source text/keys and credentials');
 assert.deepEqual(sourceDiagnostics({stage:text,session_matches:true,key_matches:'secret-key',runtime_timestamp_matches:false,token:owner.token}),{method:'canonical-transcript',session_matches:true,runtime_timestamp_matches:false});
 console.log('PASS source diagnostic projection permits only fixed stages and boolean checks; arbitrary strings are excluded');
 console.log('PASS 9 canonical source groups. Unchanged host message creation regions, real SQLite and Core HTTP; simulated host identities. Live NAS acceptance remains required.');
} finally {
 db?.close();if(originalStateDir===undefined) delete process.env.OPENCLAW_STATE_DIR;else process.env.OPENCLAW_STATE_DIR=originalStateDir;
 lines.close();child.kill('SIGTERM');
}
