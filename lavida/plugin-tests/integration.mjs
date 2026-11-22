import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {readFile,chmod} from 'node:fs/promises';
import {once} from 'node:events';
import {createServer} from 'node:http';
import {Adapter,validateConfig,bindingFor} from '../plugin/adapter.js';
import plugin from '../plugin/index.js';

const python=process.env.AIAP_TEST_PYTHON ?? 'python3';
const child=spawn(python,[new URL('./fixture.py',import.meta.url).pathname],{env:process.env,stdio:['ignore','pipe','inherit']});
const lines=createInterface({input:child.stdout});
let count=0;
function ok(name){count++;console.log('PASS '+name);}
async function rejects(action,code){await assert.rejects(action,e=>e.message===code);}
try {
  const line=await Promise.race([once(lines,'line').then(x=>x[0]),once(child,'exit').then(()=>{throw Error('Core fixture exited');})]);
  const f=JSON.parse(line);
  const binding={spaceRef:'space:work',credentialFile:f.directory+'/work.json',purpose:'lavida-memory',runtimeRef:'openclaw-work',sessionKeys:['agent:main:main']};
  const cfg=validateConfig({baseUrl:f.baseUrl,avatarId:f.avatarId,bindings:{main:binding}});
  const ctx={agentId:'main',sessionKey:'agent:main:main',senderIsOwner:true};
  assert.equal(bindingFor(cfg,ctx),binding);
  for(const bad of [{...ctx,senderIsOwner:false},{...ctx,senderIsOwner:undefined},{...ctx,agentId:'other'},{...ctx,sessionKey:'agent:main:group:test'},{...ctx,sandboxed:true}])assert.equal(bindingFor(cfg,bad),null);
  ok('host identity, session and sandbox isolation');
  const a=new Adapter(cfg,binding);
  if(process.env.AIAP_TEST_SEMANTIC){
    const semantic=await a.search({query:'air travel comfort'});
    assert.equal(semantic.retrieval,'scoped-hybrid-cosine');assert.equal(semantic.degraded,false);assert.equal(semantic.results.length,1);
    const fallback=await a.search({query:'PROVIDER_FAIL'});assert.equal(fallback.degraded,true);assert.equal(fallback.semantic_unavailable,'E_EMBED_UNAVAILABLE');
    ok('semantic HTTP results and explicit fallback reach plugin');
  }
  if(process.env.AIAP_TEST_SEMANTIC){console.log('PASS semantic plugin HTTP bridge');} else {
  assert.deepEqual((await a.status(undefined,{preference_conditions_after:''})).preference_conditions,
    {conditions:['Release'],next_after:null});
  const prefPage = await a.search({query:'', preference_condition:' Release '});
  assert.equal(prefPage.preference_defaults.length,1);
  assert.equal(prefPage.preference_defaults[0].statement,'Review the plan');
  assert.equal(prefPage.preference_defaults[0].exception,'Local experiment');
  assert.equal(prefPage.possibly_more_preferences,false);
  assert.equal('preference_defaults' in await a.search({query:''}),false);
  assert.deepEqual((await a.search({query:'',preference_condition:'Other'})).preference_defaults,[]);
  assert.equal((await a.status()).role,'adapter');ok('scoped authentication against actual Core');
  const work=await a.search({query:'CLASS'});
  assert.equal(work.results.length,1);assert.match(work.results[0].content,/BUSINESS/);assert(!JSON.stringify(work).includes('ECONOMY'));
  ok('work credential cannot retrieve life memory');
  await rejects(()=>a.search({query:'',space_refs:['space:life']}),'E_ARGUMENTS');ok('model cannot override fixed scope');
  const life=new Adapter(cfg,{...binding,spaceRef:'space:life',runtimeRef:'openclaw-life',credentialFile:f.directory+'/life.json'});
  assert.match((await life.search({query:'CLASS'})).results[0].content,/ECONOMY/);ok('separate life binding reads only life memory');
  const owner=JSON.parse(await readFile(f.directory+'/owner-credentials.json'));
  const ownerCall=async(path,body)=>{
    const r=await fetch(f.baseUrl+path,{method:'POST',headers:{Authorization:'Bearer '+owner.token,'Content-Type':'application/json'},body:JSON.stringify(body)});
    assert.equal(r.status,200);return r.json();
  };
  const proposal=await a.propose({text:'REMEMBER_TEST 每次只给一个步骤。'});
  assert.equal(proposal.status,'proposed');assert.equal((await a.search({query:'REMEMBER_TEST'})).results.length,0);
  ok('proposal does not silently become active memory');
  const review=await ownerCall('/v1/deltas/review',{delta_id:proposal.delta_id});
  assert(JSON.stringify(review).includes('inferred'));
  await ownerCall('/v1/deltas/decide',{delta_id:proposal.delta_id,approve:true});
  assert.equal((await a.search({query:'REMEMBER_TEST'})).results.length,1);ok('owner review and approval enables recall');
  const task=await a.propose({text:'TASK_FIXTURE hypothesis to revisit',level:'M1',memory_type:'project-context'});
  assert.equal(task.level,'M1');assert.equal(task.source_type,'inferred');
  assert.equal((await a.search({query:'TASK_FIXTURE'})).results.length,0);
  await ownerCall('/v1/deltas/decide',{delta_id:task.delta_id,approve:true});
  const recalled=(await a.search({query:'TASK_FIXTURE'})).results[0];
  assert.equal(recalled.level,'M1');assert.equal(recalled.memory_type,'project-context');
  assert.equal(recalled.source_type,'inferred');assert.equal(recalled.confidence,0.5);
  for (const fields of [{level:'M0'},{level:'M3'},{level:null},{memory_type:'hypothesis'},{confidence:1}]) {
    await rejects(()=>a.propose({text:'INVALID_FIXTURE',...fields}),'E_ARGUMENTS');
  }
  ok('typed task candidates preserve approval, classification and inferred provenance');
  assert.equal((await a.status()).proposal_revision,true);
  const original = {text:'以后请默认用中文回复。', memory_type:'preference-evidence', trigger:'user-request'};
  const originalProposal = await a.propose(original);
  const pendingDuplicate = await a.propose(original);
  assert.equal(pendingDuplicate.delta_id,originalProposal.delta_id);
  assert.equal(pendingDuplicate.status,'duplicate');
  const accepted = await ownerCall('/v1/deltas/decide',{delta_id:originalProposal.delta_id,approve:true});
  const [memory] = accepted.objects;
  const change = {...original,text:'以后请默认用英文回复。'};
  const comparison = await a.propose(change);
  assert.equal(comparison.status,'review-revision');
  assert.deepEqual(comparison.matches,[{memory_id:memory.memory_id,revision:memory.revision}]);
  const correction = {text:change.text,memory_id:memory.memory_id,base_revision:memory.revision,trigger:'user-request'};
  const revised = await a.propose(correction);
  assert.equal(revised.status,'proposed');
  assert.equal(revised.memory_type,'preference-evidence');
  const prior = (await a.search({query:original.text})).results[0];
  assert.equal(prior.content,original.text);
  await ownerCall('/v1/deltas/decide',{delta_id:revised.delta_id,approve:true});
  const updated = (await a.search({query:change.text})).results[0];
  assert.equal(updated.id,memory.memory_id);
  assert.equal(updated.revision,memory.revision+1);
  await rejects(()=>a.propose(correction),'E_HTTP_409');
  ok('checked proposals and Owner-approved revision preserve record identity');
  const legacy = new Adapter(cfg,binding);
  const session = legacy.session.bind(legacy);
  legacy.session = async (...args) => {
    const result = await session(...args);
    delete result.session.proposal_admission;
    delete result.session.proposal_revision;
    return result;
  };
  await rejects(()=>legacy.propose(correction),'E_PROPOSAL_REVISION_UNSUPPORTED');
  assert.equal((await legacy.propose({text:'LEGACY_FIXTURE compatibility'})).status,'proposed');
  ok('legacy Core capability keeps normal proposals and declines revisions');
  const cred=JSON.parse(await readFile(binding.credentialFile));
  const deny=await fetch(f.baseUrl+'/v1/deltas/decide',{method:'POST',headers:{Authorization:'Bearer '+cred.token,'Content-Type':'application/json'},body:JSON.stringify({delta_id:proposal.delta_id,approve:true})});
  assert.equal(deny.status,403);ok('adapter credential cannot approve');
  await rejects(()=>new Adapter(cfg,{...binding,credentialFile:f.directory+'/owner-credentials.json'}).status(),'E_CREDENTIAL_ROLE');
  await rejects(()=>new Adapter(cfg,{...binding,credentialFile:f.directory+'/multi.json'}).status(),'E_GRANT_BINDING');
  await rejects(()=>new Adapter({...cfg,avatarId:'avatar:wrong'},binding).status(),'E_GRANT_BINDING');
  ok('reject owner token, multi-space token and wrong avatar');
  await chmod(binding.credentialFile,0o644);await rejects(()=>a.status(),'E_CREDENTIAL_PERMISSIONS');await chmod(binding.credentialFile,0o600);ok('credential permissions enforced');
  const factories=new Map();let capability;
  plugin.register({pluginConfig:cfg,registerMemoryCapability(c){capability=c},registerTool(factory,o){factories.set(o.names[0],factory)}});
  assert.equal(factories.size,3);assert.equal(capability.supportsPrivateTranscriptRecall,false);
  assert.equal(factories.get('aiap_memory_search')({...ctx,senderIsOwner:false}),null);
  const tool=factories.get('aiap_memory_search')(ctx);
  const output=await tool.execute('test',{query:'BUSINESS'});
  assert.match(output.content[0].text,/BUSINESS/);assert(!output.content[0].text.includes(cred.token));
  assert(capability.promptBuilder({availableTools:new Set(['aiap_memory_search'])}).length>0);
  ok('plugin registration contract and tool execution (host harness)');
  const aborted=AbortSignal.abort();await rejects(()=>a.status(aborted),'E_TIMEOUT_OR_CANCELLED');ok('cancellation forwarded');
  // The Core verifies expiry on every request. Exercise expiry with a fresh short-lived fixture grant via CLI helper.
  const mutation=spawn(python,['-c','from aiap_core.service import Service; import sys; s=Service(sys.argv[1]); s.revoke_grant(sys.argv[2])',f.directory,cred.grant_id],{env:process.env,stdio:'inherit'});
  assert.equal((await once(mutation,'exit'))[0],0);
  await rejects(()=>a.search({query:'BUSINESS'}),'E_HTTP_401');ok('revocation effective on next query; no stale cache');
  const err=await tool.execute('test',{query:''});assert.equal(err.isError,true);assert(!JSON.stringify(err).includes(cred.token));ok('safe error reporting without secrets');
  let redirected=0;
  const target=createServer((req,res)=>{redirected++;res.end('{}')});await new Promise(r=>target.listen(0,'127.0.0.1',r));
  const redirect=createServer((req,res)=>{res.writeHead(302,{Location:`http://127.0.0.1:${target.address().port}/steal`});res.end()});await new Promise(r=>redirect.listen(0,'127.0.0.1',r));
  try{await rejects(()=>new Adapter({...cfg,baseUrl:`http://127.0.0.1:${redirect.address().port}`},binding).status(),'E_CONNECTION');assert.equal(redirected,0);ok('redirect cannot forward bearer token');}
  finally{target.close();redirect.close();}
  console.log(`PASS ${count} checks; actual AIAP HTTP server + plugin host harness. Full OpenClaw runtime not executed.`);
  }
} finally { lines.close();child.kill('SIGTERM'); }
