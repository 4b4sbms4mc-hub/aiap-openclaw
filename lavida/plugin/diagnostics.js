import {createHash,randomBytes} from 'node:crypto';

// Observation only. Never share proposer objects, run gates, messages or credentials.
// Symbol.for also joins observations when the host reloads this module independently.
const symbol=Symbol.for('lavida-aiap:process-observer:0.3.4');
const state=globalThis[symbol] ??= {id:randomBytes(12).toString('hex'),scopes:new Map()};
const modes=['full','discovery','tool-discovery'];
const modeOf=value=>modes.includes(value) ? value : 'unknown';
const keyOf=cfg=>{
  const b=cfg.bindings.main;
  return createHash('sha256').update(JSON.stringify([
    cfg.baseUrl,cfg.avatarId,b.spaceRef,b.credentialFile,b.purpose,b.runtimeRef,
    [...b.sessionKeys].sort(),cfg.autoPropose.stateDir
  ])).digest('hex');
};
const clone=value=>structuredClone(value);

export class ProcessObserver {
  constructor(cfg,instanceId,registrationMode,logger) {
    this.instanceId=instanceId;this.mode=modeOf(registrationMode);this.logger=logger;
    const key=keyOf(cfg);
    let scope=state.scopes.get(key);
    if (!scope) {
      // Bounded process memory. Existing observers retain their own scope on eviction.
      if (state.scopes.size>=32) state.scopes.delete(state.scopes.keys().next().value);
      scope={registrations:0,registration_modes:{full:0,discovery:0,'tool-discovery':0,unknown:0},before_agent_run:0,agent_end:0,last_before:{outcome:'idle'},last_end:{outcome:'idle'}};
      state.scopes.set(key,scope);
    }
    this.scope=scope;this.seen=new Set();
    scope.registrations++;scope.registration_modes[this.mode]++;
  }
  registered() {
    this.log('registered');
  }
  log(event) {
    // No input strings, configuration, file paths, session IDs, run IDs or delta IDs.
    try {this.logger?.info?.(`La Vida diagnostic 0.3.4 event=${event} process=${state.id} instance=${this.instanceId} mode=${this.mode}`)} catch {}
  }
  receive(name) {
    this.scope[name]++;
    if (!this.seen.has(name)) {this.seen.add(name);this.log(name)}
  }
  finish(name,diagnostics,last) {
    const field=name==='before_agent_run' ? 'last_before' : 'last_end';
    this.scope[field]={instance_id:this.instanceId,registration_mode:this.mode,...clone(diagnostics)};
    // Report the processing result separately from source checks.
    if (name==='agent_end') this.scope[field].capture_result=clone(last);
  }
  snapshot() {
    return {process_id:state.id,status_instance_id:this.instanceId,coverage:'same-process-same-binding',...clone(this.scope)};
  }
}
