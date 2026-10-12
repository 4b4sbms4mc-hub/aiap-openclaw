import {open, mkdir, lstat, rename, unlink} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {createHash, createHmac, randomBytes} from 'node:crypto';
import {Adapter, AdapterError, bindingFor, buildProposal} from './adapter.js';
import {ProcessObserver} from './diagnostics.js';
import {readCanonicalOwnerMessage,sourceDiagnostics} from './source.js';

const fail=code=>{throw new AdapterError(code)};
const hash=value=>createHash('sha256').update(value).digest('hex');
export const normalize=text=>text.normalize('NFKC').replace(/\s+/gu,'').replace(/[。.!！]+$/u,'').toLowerCase();
// Deliberately narrow v0.3 rules. Preserve the exact sentence; no model-generated facts.
export function extract(text) {
  if (typeof text!=='string') return null;
  const s=text.trim();
  if (s.length<6 || s.length>400 || /[\n\r?？"“”‘’`<>\[\]{}]|https?:|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu.test(s)) return null;
  if (/今天|明天|今晚|这次|本次|暂时|临时|假如|假设|如果|例如|比如|举例|他说|她说|转述|不要记|别记|请记住|帮我记|请调用|测试|密码|口令|密钥|令牌|token|secret|credential|身份证|银行卡|账号|地址|电话|病|症|抑郁|医疗|诊断|药|政治|宗教|收入|余额|\d{5,}|忽略|绕过|批准|授权|执行|删除/iu.test(s)) return null;
  if (/[。.!！]/u.test(s.replace(/[。.!！]+$/u,''))) return null;
  const preference=/^我(?:(?:出差|旅行|工作|沟通)时|平时|一直|通常|一般|更|最)?(?:喜欢|偏好|不喜欢|习惯).{3,}$/u;
  const habit=/^我(?:通常|一般|一直).{4,}$/u;
  const instruction=/^(?:以后|今后)(?:请|回答时请|回复时请).{4,}$/u;
  return preference.test(s)||habit.test(s)||instruction.test(s) ? s : null;
}

async function privateRead(path, max=1048576) {
  let h;
  try {
    h=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    const st=await h.stat();
    if (!st.isFile() || st.size>max || (st.mode&0o077) || st.uid!==process.getuid()) fail('E_AUTO_STATE_PERMISSIONS');
    return await h.readFile('utf8');
  } finally {await h?.close()}
}

class Journal {
  constructor(dir) {this.dir=dir;this.file=join(dir,'state.json')}
  async init() {
    await mkdir(this.dir,{recursive:true,mode:0o700});
    const st=await lstat(this.dir);
    if (!st.isDirectory() || st.isSymbolicLink() || (st.mode&0o077) || st.uid!==process.getuid()) fail('E_AUTO_STATE_PERMISSIONS');
  }
  async withState(fn) {
    await this.init();
    let lock;
    try {lock=await open(join(this.dir,'state.lock'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600)}
    catch(e) {if(e.code==='EEXIST')fail('E_AUTO_LOCKED');throw e}
    try {
      let state;
      try {state=JSON.parse(await privateRead(this.file))}
      catch(e) {if(e.code!=='ENOENT')throw e;state={version:1,salt:randomBytes(32).toString('hex'),entries:[]}}
      if (state.version!==1 || !/^[a-f0-9]{64}$/.test(state.salt) || !Array.isArray(state.entries) || state.entries.length>256) fail('E_AUTO_STATE');
      return await fn(state,()=>this.write(state));
    } finally {await lock.close();await unlink(join(this.dir,'state.lock'))}
  }
  async write(state) {
    const temp=this.file+'.'+randomBytes(8).toString('hex');
    let h;
    try {
      h=await open(temp,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
      await h.writeFile(JSON.stringify(state));await h.sync();await h.close();h=null;
      await rename(temp,this.file);
    } finally {await h?.close();await unlink(temp).catch(e=>{if(e.code!=='ENOENT')throw e})}
  }
}

const keyOf=m=>typeof m?.idempotencyKey==='string' && m.idempotencyKey.length>0 && m.idempotencyKey.length<=512 ? m.idempotencyKey : null;
const markerOf=m=>m?.__openclaw?.senderIsOwner===true ? 'true' : m?.__openclaw?.senderIsOwner===false ? 'false' : m?.__openclaw?.senderIsOwner===undefined ? 'missing' : 'invalid';
function safeUserMessage(m) {
  return m?.role==='user' && (m.__openclaw==null || (typeof m.__openclaw==='object' && !Array.isArray(m.__openclaw))) && m.display!==false && m.excludeFromContext!==true && m.__openclaw?.lateMedia!==true && m.__openclaw?.beforeAgentRunBlocked===undefined && (!m.provenance || m.provenance.kind==='external_user');
}
function plainText(m) {
  if (typeof m.content==='string') return m.content;
  if (Array.isArray(m.content) && m.content.length===1 && m.content[0].type==='text') return m.content[0].text;
  return null;
}
function ownerText(m) {
  return safeUserMessage(m) && m.__openclaw?.senderIsOwner===true ? plainText(m) : null;
}

export class AutoProposer {
  constructor(cfg,logger,hostConfig={},registrationMode,sourceReader=readCanonicalOwnerMessage) {
    this.cfg=cfg;this.logger=logger;this.runs=new Map();this.queue=Promise.resolve();
    this.journal=new Journal(cfg.autoPropose.stateDir);this.last={outcome:'idle'};this.pending=0;
    this.hostConfig=hostConfig;
    this.sourceReader=sourceReader;
    this.diagnostics={instance_id:randomBytes(12).toString('hex'),before_agent_run:0,agent_end:0,last_before:{outcome:'idle'},last_end:{outcome:'idle'}};
    this.observer=new ProcessObserver(cfg,this.diagnostics.instance_id,registrationMode,logger);
  }
  inScope(ctx) {return ctx?.agentId==='main' && ctx.sessionKey==='agent:main:main'}
  eligibilityReason(ctx) {
    if (!this.inScope(ctx)) return 'E_AUTO_SCOPE';
    const host=ctx?.config ?? this.hostConfig;
    const agent=host.agents?.list?.find(a=>a.id==='main');
    const mode=agent?.sandbox?.mode ?? host.agents?.defaults?.sandbox?.mode ?? 'off';
    if (mode!=='off' || ctx?.sandboxed===true) return 'E_AUTO_SANDBOX';
    if (ctx?.inputProvenance && ctx.inputProvenance.kind!=='external_user') return 'E_AUTO_PROVENANCE';
    if (ctx?.trigger!=='user') return 'E_AUTO_TRIGGER';
    if (typeof ctx.sessionId!=='string' || !ctx.sessionId || typeof ctx.runId!=='string' || !ctx.runId) return 'E_AUTO_CONTEXT';
    if (bindingFor(this.cfg,{...ctx,senderIsOwner:true})===null) return 'E_AUTO_BINDING';
    return null;
  }
  eligible(ctx) {return this.eligibilityReason(ctx)===null}
  // Only remember host identity and historical keys. The current input is appended later.
  before(event,ctx) {
    this.diagnostics.before_agent_run++;
    this.observer.receive('before_agent_run');
    const checks={agent_matches:ctx?.agentId==='main',session_matches:ctx?.sessionKey==='agent:main:main',has_session_id:typeof ctx?.sessionId==='string' && !!ctx.sessionId,has_run_id:typeof ctx?.runId==='string' && !!ctx.runId,trigger:['user','cron','heartbeat'].includes(ctx?.trigger) ? ctx.trigger : ctx?.trigger==null ? 'missing' : 'other',owner_confirmed:event?.senderIsOwner===true,has_messages:Array.isArray(event?.messages)};
    this.diagnostics.last_before={outcome:'skipped',reason:'E_AUTO_SCOPE',checks};
    try {
      this.runs.delete(ctx?.runId);
      for (const [key,v] of this.runs) if (Date.now()-v.started>3600000) this.runs.delete(key);
      const reason=this.eligibilityReason(ctx) ?? (event?.senderIsOwner!==true ? 'E_AUTO_OWNER' : !Array.isArray(event.messages) ? 'E_AUTO_MESSAGES' : null);
      if (reason) {
        this.diagnostics.last_before={outcome:'skipped',reason,checks};
        if (this.inScope(ctx)) this.last={outcome:'skipped',reason};
        return;
      }
      if (this.runs.size>=32) {this.last={outcome:'skipped',reason:'E_AUTO_BUSY'};this.diagnostics.last_before={...this.last,checks};return}
      this.runs.set(ctx.runId,{sessionId:ctx.sessionId,started:Date.now(),oldKeys:new Set(event.messages.filter(m=>m.role==='user').map(keyOf).filter(Boolean))});
      this.diagnostics.last_before={outcome:'armed',checks};
    } catch {this.last={outcome:'skipped',reason:'E_AUTO_CONTEXT'};this.diagnostics.last_before={...this.last,checks}}
    finally {this.observer.finish('before_agent_run',this.diagnostics.last_before,this.last)}
  }
  async end(event,ctx) {
    this.diagnostics.agent_end++;
    this.observer.receive('agent_end');
    try {await this.finishEnd(event,ctx)}
    finally {this.observer.finish('agent_end',this.diagnostics.last_end,this.last)}
  }
  async finishEnd(event,ctx) {
    const gate=this.runs.get(ctx?.runId);this.runs.delete(ctx?.runId);
    if (!gate) {
      this.diagnostics.last_end={outcome:'skipped',reason:'E_AUTO_NO_GATE'};
      if (this.inScope(ctx) && this.last.outcome==='idle') this.last={...this.diagnostics.last_end};
      return;
    }
    this.diagnostics.last_end={outcome:'received'};
    const runReason=this.eligibilityReason(ctx) ?? (ctx.sessionId!==gate.sessionId ? 'E_AUTO_SESSION_CHANGED' : event?.success!==true ? 'E_AUTO_RUN_FAILED' : !Array.isArray(event.messages) ? 'E_AUTO_MESSAGES' : null);
    if (runReason) {this.last={outcome:'skipped',reason:runReason};this.diagnostics.last_end={...this.last};return}
    const message=event.messages.findLast(m=>m.role==='user'), key=keyOf(message);
    let stamp=message?.timestamp;
    const checks=this.diagnostics.last_end.source_checks={has_message_key:!!key,new_message:!!key && !gate.oldKeys.has(key),recent_timestamp:Number.isFinite(stamp) && stamp>=gate.started-300000 && stamp<=Date.now()+30000,runtime_owner_marker:markerOf(message),owner_confirmed:message?.__openclaw?.senderIsOwner===true,has_owner_text:ownerText(message)!==null};
    if (!key || gate.oldKeys.has(key) || !Number.isFinite(stamp) || stamp<gate.started-300000 || stamp>Date.now()+30000 || !safeUserMessage(message)) {this.last={outcome:'skipped',reason:'E_AUTO_SOURCE'};return}
    let owned=message;
    if (markerOf(message)==='missing') {
      try {
        const canonical=await this.sourceReader({agentId:ctx.agentId,sessionKey:ctx.sessionKey,sessionId:ctx.sessionId,runId:ctx.runId,key,stamp,started:gate.started});
        owned=canonical.message;
        const reject=code=>{const error=new AdapterError(code);error.sourceChecks={...canonical.checks,stage:'canonical-message'};throw error};
        if (keyOf(owned)!==key || key!==ctx.runId+':user') reject('E_AUTO_TRANSCRIPT_KEY');
        if (!Number.isFinite(owned?.timestamp) || owned.timestamp<gate.started-300000 || owned.timestamp>Date.now()+30000) reject('E_AUTO_TRANSCRIPT_TIME');
        if (ownerText(owned)===null) reject('E_AUTO_TRANSCRIPT_SOURCE');
        Object.assign(checks,{canonical_source:{...sourceDiagnostics(canonical.checks),verified:true},owner_confirmed:true,has_owner_text:true,runtime_text_matches:plainText(message)===plainText(owned)});
        stamp=owned.timestamp;
      } catch(e) {this.last={outcome:'skipped',reason:e instanceof AdapterError ? e.code : 'E_AUTO_TRANSCRIPT_UNAVAILABLE'};checks.canonical_source={...sourceDiagnostics(e.sourceChecks),verified:false,reason:this.last.reason};return}
    } else if (markerOf(message)!=='true') {this.last={outcome:'skipped',reason:'E_AUTO_OWNER'};return}
    // Canonical admission text is authoritative; never elevate a transformed snapshot.
    const text=extract(ownerText(owned));
    if (!text) {this.last={outcome:'skipped',reason:'not_a_supported_statement'};return}
    if (this.pending>=8) {this.last={outcome:'skipped',reason:'E_AUTO_BUSY'};return}
    this.pending++;
    const signal=AbortSignal.timeout(20000);
    const work=()=>this.process(text,{key,stamp,sessionId:ctx.sessionId},signal);
    const task=this.queue.then(work,work);this.queue=task.catch(()=>{});
    try {await task} finally {this.pending--}
  }
  async process(text,source,signal=AbortSignal.timeout(20000)) {
    try {
      await this.journal.withState(async(state,save)=>{
        const keyed=value=>createHmac('sha256',state.salt).update(value).digest('hex');
        const b=this.cfg.bindings.main, a=new Adapter(this.cfg,b);
        const {token,session}=await a.session(signal);
        const fp=keyed(JSON.stringify([session.subject_ref,this.cfg.avatarId,b.spaceRef,b.runtimeRef,normalize(text)]));
        let item=state.entries.find(e=>e.fingerprint===fp);
        if (item) {
          if (item.grant!==session.auth_evidence_ref) {this.last={outcome:'skipped',reason:'E_AUTO_OLD_GRANT'};return}
          if (['accepted','rejected','active_duplicate'].includes(item.status)) {this.last={outcome:'duplicate',status:item.status,delta_id:item.delta_id};return}
          try {
            const r=await a.call(token,'/v1/deltas/review',{delta_id:item.delta_id},signal);
            item.status=r.status;delete item.error;await save();
            this.last={outcome:'duplicate',status:r.status,delta_id:item.delta_id};return;
          } catch(e) {if (e.code!=='E_HTTP_404') throw e}
          if (item.raw_hash!==keyed(text)) {this.last={outcome:'skipped',reason:'E_AUTO_RETRY_TEXT_CHANGED'};return}
        }
        // An exact-text active match suppresses a fresh proposal. Semantic similarity alone does not.
        const active=await a.search({query:text,limit:10},signal);
        if (active.results.some(m=>normalize(m.content)===normalize(text))) {this.last={outcome:'duplicate',status:'active_duplicate'};return}
        if (!item) {
          if (state.entries.length>=256 || state.entries.filter(e=>['proposed','submitting','uncertain'].includes(e.status)).length>=20) fail('E_AUTO_CAPACITY');
          const deltaId=keyed(fp+session.auth_evidence_ref);
          item={fingerprint:fp,raw_hash:keyed(text),grant:session.auth_evidence_ref,deltaId,delta_id:'aiap:state-delta:'+deltaId,
            sourceRef:'evidence:lavida-auto:'+keyed(JSON.stringify([source.sessionId,source.key,source.stamp,hash(text)])),
            observedAt:new Date(source.stamp).toISOString(),session_id:source.sessionId,message_key:source.key,status:'submitting'};
          state.entries.push(item);await save();
        }
        const envelope=buildProposal(session,b.spaceRef,text,item);
        try {
          const r=await a.call(token,'/v1/deltas/propose',envelope,signal);
          if (r.delta_id!==item.delta_id || !['proposed','accepted','rejected'].includes(r.status)) fail('E_RESPONSE');
          item.status=r.status;delete item.error;await save();
          this.last={outcome:r.status==='proposed'?'proposed':'duplicate',delta_id:r.delta_id,status:r.status};
          this.logger?.info?.('La Vida automatic candidate: '+r.delta_id+' ('+r.status+')');
        } catch(e) {item.status='uncertain';item.error=e instanceof AdapterError?e.code:'E_AUTO';await save();throw e}
      });
    } catch(e) {
      const code=e instanceof AdapterError?e.code:'E_AUTO_STATE';
      this.last={outcome:'unavailable',reason:code};this.logger?.warn?.('La Vida automatic proposal unavailable: '+code);
    }
  }
  async status(signal) {
    try {
      const candidates=await this.journal.withState(async(state,save)=>{
        const a=new Adapter(this.cfg,this.cfg.bindings.main), {token,session}=await a.session(signal);
        for (const item of state.entries.filter(e=>['proposed','submitting','uncertain'].includes(e.status))) {
          if (item.grant!==session.auth_evidence_ref) continue;
          try {const r=await a.call(token,'/v1/deltas/review',{delta_id:item.delta_id},signal);item.status=r.status;delete item.error}
          catch(e) {item.error=e instanceof AdapterError?e.code:'E_AUTO'}
        }
        await save();
        return state.entries.slice(-20).map(e=>({delta_id:e.delta_id,status:e.status,source_ref:e.sourceRef,observed_at:e.observedAt,...e.error?{error:e.error}:{}}));
      });
      return {enabled:true,mode:'direct-statement-rules',scope:'space:general',last:{...this.last},candidates,requires_owner_confirmation:true,diagnostics:{...structuredClone(this.diagnostics),process_observer:this.observer.snapshot()}};
    } catch(e) {return {enabled:true,unavailable:true,error:e instanceof AdapterError?e.code:'E_AUTO_STATE',last:{...this.last},diagnostics:{...structuredClone(this.diagnostics),process_observer:this.observer.snapshot()}}}
  }
}
