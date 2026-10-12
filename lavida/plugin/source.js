import {lstat} from 'node:fs/promises';
import {homedir} from 'node:os';
import {isAbsolute,join,resolve} from 'node:path';
import {AdapterError} from './adapter.js';

const fail=code=>{throw new AdapterError(code)};
const stages=['context','database','session','latest-user','payload','message','key','time','owner','receipt','verified','canonical-message'];
const flags=['session_matches','latest_user_found','key_matches','key_matches_run','canonical_timestamp_recent','runtime_timestamp_matches','owner_confirmed','run_matches','identity_matches'];
export function sourceDiagnostics(value={}) {
  const safe={method:'canonical-transcript'};
  if (stages.includes(value.stage)) safe.stage=value.stage;
  for (const name of flags) if (typeof value[name]==='boolean') safe[name]=value[name];
  return safe;
}
// OpenClaw 2026.9.4 NAS storage profile, not a general transcript search API.
// Only the current main session is read, after an authenticated successful turn.
export function canonicalDatabasePath() {
  const override=process.env.OPENCLAW_STATE_DIR?.trim();
  if (override && (!isAbsolute(override) || override.includes('\0'))) fail('E_AUTO_TRANSCRIPT_UNAVAILABLE');
  return join(override ? resolve(override) : join(homedir(),'.openclaw'),'agents','main','agent','openclaw-agent.sqlite');
}

export async function readCanonicalOwnerMessage(source,databasePath=canonicalDatabasePath()) {
  const checks={method:'canonical-transcript',stage:'context'};
  const reject=code=>{const error=new AdapterError(code);error.sourceChecks=sourceDiagnostics(checks);throw error};
  if (source.agentId!=='main' || source.sessionKey!=='agent:main:main' ||
      typeof source.sessionId!=='string' || !source.sessionId || source.sessionId.length>128 ||
      typeof source.runId!=='string' || !source.runId || source.runId.length>512 ||
      typeof source.key!=='string' || !source.key || source.key.length>512 ||
      !Number.isFinite(source.stamp) || !Number.isFinite(source.started)) reject('E_AUTO_SOURCE');
  // In this storage profile the stable user key is derived from the logical run.
  // Runtime creation time is not the canonical ingress time (OpenClaw 2026.9.4).
  checks.key_matches_run=source.key===source.runId+':user';
  if (!checks.key_matches_run) reject('E_AUTO_TRANSCRIPT_KEY');
  let db;
  try {
    checks.stage='database';
    const st=await lstat(databasePath);
    if (!st.isFile() || st.isSymbolicLink()) reject('E_AUTO_TRANSCRIPT_UNAVAILABLE');
    const {DatabaseSync}=await import('node:sqlite');
    db=new DatabaseSync(databasePath,{readOnly:true});
    db.exec('PRAGMA busy_timeout=1000; BEGIN');
    checks.stage='session';
    const node=db.prepare('SELECT current_session_id FROM session_nodes WHERE session_key=?').get(source.sessionKey);
    checks.session_matches=node?.current_session_id===source.sessionId;
    if (!checks.session_matches) reject('E_AUTO_TRANSCRIPT_SESSION');
    // At most 64 recent events; each returned payload is capped at 64 KiB.
    // JSON role extraction prevents a truncated later user row being overlooked.
    const rows=db.prepare(`
      SELECT e.seq, json_extract(e.event_json,'$.message.role') AS role,
             substr(CAST(e.event_json AS BLOB),1,65537) AS event_blob
      FROM transcript_events e
      WHERE e.session_id=?
      ORDER BY e.seq DESC LIMIT 64
    `).all(source.sessionId);
    checks.stage='latest-user';
    const row=rows.find(r=>r.role==='user');
    checks.latest_user_found=!!row;
    if (!row) reject('E_AUTO_TRANSCRIPT_SOURCE');
    checks.stage='payload';
    if (row.event_blob.length>65536) reject('E_AUTO_TRANSCRIPT_LIMIT');
    const event=JSON.parse(Buffer.from(row.event_blob).toString('utf8')),message=event.message;
    checks.stage='message';
    if (event.type!=='message' || message?.role!=='user') reject('E_AUTO_TRANSCRIPT_SOURCE');
    checks.stage='key';checks.key_matches=message.idempotencyKey===source.key;
    if (!checks.key_matches) reject('E_AUTO_TRANSCRIPT_KEY');
    checks.stage='time';
    checks.runtime_timestamp_matches=message.timestamp===source.stamp;
    const now=Date.now(),recent=t=>Number.isFinite(t) && t>=source.started-300000 && t<=now+30000;
    checks.canonical_timestamp_recent=recent(message.timestamp);
    if (!recent(source.stamp) || !checks.canonical_timestamp_recent) reject('E_AUTO_TRANSCRIPT_TIME');
    checks.stage='owner';checks.owner_confirmed=message.__openclaw?.senderIsOwner===true;
    if (!checks.owner_confirmed) reject('E_AUTO_OWNER');
    // A matching terminal assistant receipt ties the canonical user to this run.
    // Never recover a historical user just because its text resembles the prompt.
    checks.stage='receipt';
    const runMatches=rows.some(r=>{
      if (r.role!=='assistant' || r.seq<=row.seq || r.event_blob.length>65536) return false;
      let e;try {e=JSON.parse(Buffer.from(r.event_blob).toString('utf8'))} catch {return false}
      const m=e.message;
      return e.type==='message' && m?.__openclaw?.runId===source.runId &&
        !['aborted','error','toolUse'].includes(m.stopReason) &&
        !(Array.isArray(m.content) && m.content.some(b=>['toolCall','toolUse','functionCall'].includes(b?.type)));
    });
    checks.run_matches=runMatches;
    if (!runMatches) reject('E_AUTO_TRANSCRIPT_RUN');
    checks.stage='verified';checks.identity_matches=true;
    return {message,checks:sourceDiagnostics(checks)};
  } catch(e) {
    if (e instanceof AdapterError) throw e;
    reject('E_AUTO_TRANSCRIPT_UNAVAILABLE');
  } finally {db?.close()}
}
