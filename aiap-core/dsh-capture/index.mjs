import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { bindOwnerIngress } from './owner-ingress.mjs';

export const inject = ['sessionController'];

const sessionLimit = 16;
const enableCommand = '开启 AIAP 自动提案';
const disableCommand = '关闭 AIAP 自动提案';
const validId = id => typeof id === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(id);

function readSessions(file) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return new Set();
    throw error;
  }
  const values = JSON.parse(raw);
  if (!Array.isArray(values) || values.length > sessionLimit || !values.every(validId)) {
    throw new Error('Invalid AIAP session preferences.');
  }
  return new Set(values);
}

function saveSessions(file, sessions) {
  const temporary = file + '.' + randomUUID();
  try {
    writeFileSync(temporary, JSON.stringify([...sessions]) + '\n', { flag: 'wx', mode: 0o600 });
    renameSync(temporary, file);
  } finally {
    try {
      unlinkSync(temporary);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}

export function apply(ctx, config) {
  const { python, dataDir, credentialFile, preferencesFile } = config;
  if (![python, dataDir, credentialFile, preferencesFile]
    .every(path => typeof path === 'string' && isAbsolute(path))) {
    throw new Error('Configure absolute paths for AIAP capture.');
  }
  const logger = ctx.logger('aiap-capture');
  let enabledSessions;
  try {
    enabledSessions = readSessions(preferencesFile);
  } catch {
    logger.warn('AIAP automatic capture is inactive because session preferences could not be read.');
    return;
  }
  const ingress = bindOwnerIngress(ctx.sessionController);
  if (!ingress) {
    logger.warn('AIAP automatic capture is inactive on this DSH host version.');
    return;
  }
  const turns = new Map();
  const running = new Map();

  function submit(sessionId, message) {
    if (running.size >= 4 || running.has(sessionId)) {
      logger.warn('AIAP skipped an automatic proposal because capture is busy.');
      return;
    }
    const child = spawn(python, ['-m', 'aiap_core', '--data-dir', dataDir,
      'capture-owner-observation', '--credential-file', credentialFile, '--space', 'space:general'],
      { stdio: ['pipe', 'ignore', 'ignore'], timeout: 10000, killSignal: 'SIGKILL', windowsHide: true });
    running.set(sessionId, child);
    child.on('close', code => {
      if (running.get(sessionId) === child) running.delete(sessionId);
      if (code !== 0 && !child.killed) logger.warn('AIAP automatic capture did not complete.');
    });
    child.on('error', () => child.stdin.destroy());
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify({ session_id: sessionId, message_id: message.id, text: message.content[0].text }));
  }

  function updatePreference(sessionId, enabled) {
    if (enabledSessions.has(sessionId) === enabled) return;
    if (enabled && enabledSessions.size >= sessionLimit) {
      logger.warn('AIAP automatic capture reached its session limit.');
      return;
    }
    const next = new Set(enabledSessions);
    if (enabled) next.add(sessionId);
    else {
      next.delete(sessionId);
      enabledSessions.delete(sessionId);
      running.get(sessionId)?.kill();
    }
    try {
      saveSessions(preferencesFile, next);
      enabledSessions = next;
      logger.info(enabled ? 'AIAP automatic capture enabled for a session.' : 'AIAP automatic capture disabled for a session.');
    } catch {
      logger.warn('AIAP could not save the automatic capture preference.');
    }
  }

  ctx.effect(() => () => {
    ingress.dispose();
    for (const child of running.values()) child.kill();
    turns.clear();
  });
  ctx.on('session/disposed', session => turns.delete(session));
  ctx.on('session/event', (session, event) => {
    if (!validId(session.id)) return;
    if (event.type === 'turn/start') {
      turns.set(session, { turn: event.data.turn, directMessages: 0 });
      return;
    }
    const current = turns.get(session);
    if (!current) return;
    if (event.type === 'user/message' && event.surfaceOp === 'append' && event.data?.role === 'user'
        && ['user', 'retry'].includes(event.data.source?.kind)) {
      const message = event.data;
      current.directMessages++;
      const block = message.content?.[0];
      if (!validId(message.id) || message.content.length !== 1 || block?.type !== 'text'
          || !ingress.consume(session.id, message.source, block.text)) return;
      const command = block.text.trim();
      if (command === enableCommand || command === disableCommand) {
        // Disable immediately when the observed Owner message arrives.
        if (command === disableCommand) updatePreference(session.id, false);
        else if (current.directMessages === 1) current.enable = true;
      } else if (current.directMessages === 1 && enabledSessions.has(session.id) && command && block.text.length <= 400) {
        current.message = message;
      }
      return;
    }
    if (event.type === 'turn/end') {
      turns.delete(session);
      if (event.data.turn !== current.turn || event.data.reason?.kind !== 'completed'
          || current.directMessages !== 1) return;
      if (current.enable) updatePreference(session.id, true);
      if (current.message && enabledSessions.has(session.id)) submit(session.id, current.message);
    }
  });
}
