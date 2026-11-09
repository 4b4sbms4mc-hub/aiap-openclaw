# SPDX-License-Identifier: Apache-2.0
"""Experimental local-only snapshot recovery, gated by an independently trusted pin.

The operator must provide a genuinely current checkpoint from outside the backup.
A signature/hash cannot establish freshness by itself. No production or HTTP API.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lavida/core'))
from aiap_core.service import Service, SQL, stamp, parse, uid, save_private
from aiap_core.contracts import canonical, digest, b64, unb64, require, exact, validate, Fault
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = 'x-aiap-local-recovery-checkpoint-v1'
DOMAIN = b'AIAP-LOCAL-RECOVERY-CHECKPOINT-v1\x00'


def read_file(path, limit=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'E_RECOVERY_FILE')
        raw = file.read(limit + 1)
        require(len(raw) <= limit, 'E_RECOVERY_FILE')
        return raw


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'E_SCHEMA')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def public_key(pem):
    key = serialization.load_pem_private_key(pem, None)
    return b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def manifest(core):
    validate('avatar-core', core)
    require(core['profile_summary'] == [] and core['procedural_index'] == [], 'E_OPERATION_UNSUPPORTED')
    require(core['extensions'] == [{'namespace': 'x-aiap-core-profile', 'version': '0.1-draft', 'critical': True}], 'E_CRITICAL_EXTENSION')
    refs = core['state_index']
    require(len({r['id'] for r in refs}) == len(refs), 'E_INTEGRITY')
    return {r['id']: r for r in refs}


def expected_scope(payload, space):
    spaces = {s['id']: s for s in payload['spaces']}
    require(space in spaces, 'E_SCOPE')
    s = spaces[space]
    return {'owner_ref': payload['core']['owner']['owner_ref'], 'space_ref': space,
            'policy_ref': {'id': s['policy'], 'version': s['revision']}}


def validate_payload(payload, now):
    exact(payload, ['profile', 'checkpoint_id', 'issued_at', 'expires_at', 'core',
                    'enrollment', 'spaces', 'tombstones', 'revocation_epoch'])
    require(payload['profile'] == PROFILE, 'E_CRITICAL_EXTENSION')
    issued, expires = parse(payload['issued_at']), parse(payload['expires_at'])
    require(issued <= now < expires and timedelta(0) < expires - issued <= timedelta(hours=24), 'E_EXPIRED')
    require(type(payload['revocation_epoch']) is int and payload['revocation_epoch'] >= 0, 'E_SCHEMA')
    core = payload['core']
    refs = manifest(core)
    require(Service('.').verify_local_core(core, payload['enrollment']), 'E_INTEGRITY')
    require(isinstance(payload['spaces'], list) and len(payload['spaces']) == 3, 'E_SCOPE')
    require({s['id'] for s in payload['spaces']} == {'space:general', 'space:life', 'space:work'}, 'E_SCOPE')
    for s in payload['spaces']:
        exact(s, ['avatar', 'id', 'kind', 'policy', 'revision'])
        require(s['avatar'] == core['avatar_id'] and type(s['revision']) is int and s['revision'] > 0, 'E_SCOPE')
    for ref in refs.values():
        require(ref['scope'] == expected_scope(payload, ref['scope']['space_ref']), 'E_SCOPE')
    require(isinstance(payload['tombstones'], list), 'E_SCHEMA')
    ids = set()
    for row in payload['tombstones']:
        exact(row, ['avatar', 'id', 'space', 'revision', 'body'])
        tomb = strict_json(row['body'])
        validate('tombstone', tomb)
        require(row['avatar'] == core['avatar_id'] and row['id'] not in ids
                and row['id'] == tomb['object_ref']['id'] and row['revision'] == tomb['object_ref']['version']
                and row['space'] == tomb['scope']['space_ref']
                and tomb['scope']['owner_ref'] == core['owner']['owner_ref'], 'E_SCOPE')
        require(row['id'] not in refs, 'E_INTEGRITY')
        ids.add(row['id'])
    return refs


def export_checkpoint(data_dir, output, ttl_hours=1, clock=None):
    require(type(ttl_hours) is int and 1 <= ttl_hours <= 24, 'E_SCHEMA')
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    service = Service(data_dir, clock=lambda: now)
    with service.tx() as db:
        core = strict_json(db.execute('SELECT body FROM cores WHERE avatar=?',
                                     (service.meta(db, 'avatar'),)).fetchone()[0])
        payload = {'profile': PROFILE, 'checkpoint_id': uid('recovery:'), 'issued_at': stamp(now),
                   'expires_at': stamp(now + timedelta(hours=ttl_hours)), 'core': core,
                   'enrollment': service.meta(db, 'enrollment'),
                   'spaces': [dict(r) for r in db.execute('SELECT * FROM spaces ORDER BY id')],
                   'tombstones': [dict(r) for r in db.execute('SELECT * FROM tombstones ORDER BY id')],
                   'revocation_epoch': service.meta(db, 'revocation_epoch')}
        refs = validate_payload(payload, now)
        rows = {r['id']: r for r in db.execute('SELECT * FROM memories')}
        require(set(rows) == set(refs), 'E_INTEGRITY')
        for ident, row in rows.items():
            require(digest(strict_json(row['body'])) == refs[ident]['sha256'], 'E_INTEGRITY')
        key_bytes = read_file(Path(data_dir) / 'owner-key.pem', 16384)
        require(public_key(key_bytes) == payload['enrollment']['payload']['owner_public_key'], 'E_INTEGRITY')
        key = serialization.load_pem_private_key(key_bytes, None)
        envelope = {'payload': payload, 'signature': b64(key.sign(DOMAIN + canonical(payload)))}
    raw = canonical(envelope)
    save_private(Path(output), raw)
    return {'checkpoint_sha256': hashlib.sha256(raw).hexdigest(),
            'expires_at': payload['expires_at'], 'trust': 'operator must pin a current checkpoint outside the backup'}


def load_checkpoint(path, expected_sha256, now):
    require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256), 'E_CHECKPOINT_PIN')
    raw = read_file(path)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'E_CHECKPOINT_PIN')
    envelope = strict_json(raw)
    exact(envelope, ['payload', 'signature'])
    payload = envelope['payload']
    refs = validate_payload(payload, now)
    try:
        key = unb64(payload['enrollment']['payload']['owner_public_key'])
        Ed25519PublicKey.from_public_bytes(key).verify(unb64(envelope['signature']), DOMAIN + canonical(payload))
    except Exception:
        raise Fault('E_INTEGRITY') from None
    return payload, refs


def schema(db):
    return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()


def restore_snapshot(snapshot_dir, checkpoint, expected_sha256, target_dir, clock=None):
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    payload, refs = load_checkpoint(checkpoint, expected_sha256, now)
    snapshot, target = Path(snapshot_dir), Path(target_dir)
    require(not snapshot.is_symlink() and snapshot.is_dir(), 'E_RECOVERY_FILE')
    require(not target.exists() and not target.is_symlink() and target.parent.is_dir(), 'E_OUTPUT_EXISTS')
    require(not target.resolve().is_relative_to(snapshot.resolve()), 'E_RECOVERY_FILE')
    require(not Path(checkpoint).resolve().is_relative_to(snapshot.resolve()), 'E_CHECKPOINT_LOCATION')
    parent = target.parent.stat()
    require(not parent.st_mode & 0o022 and (not hasattr(os, 'getuid') or parent.st_uid == os.getuid()), 'E_RECOVERY_FILE')
    db_path = snapshot / 'core.sqlite3'
    require(not db_path.is_symlink() and db_path.is_file() and db_path.stat().st_size <= 64 * 1024 * 1024, 'E_RECOVERY_FILE')
    require(not any((snapshot / ('core.sqlite3' + suffix)).exists()
                    for suffix in ('-wal', '-shm', '-journal')), 'E_OPERATION_UNSUPPORTED')
    owner_key = read_file(snapshot / 'owner-key.pem', 16384)
    avatar_key = read_file(snapshot / 'avatar-key.pem', 16384)
    enrollment = payload['enrollment']['payload']
    require(public_key(owner_key) == enrollment['owner_public_key']
            and public_key(avatar_key) == enrollment['avatar_public_key'], 'E_INTEGRITY')
    expected_db = sqlite3.connect(':memory:')
    expected_db.executescript(SQL)
    expected_schema = schema(expected_db)
    expected_db.close()
    source = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    stage = None
    reserved = False
    try:
        source.execute('PRAGMA trusted_schema=OFF')
        source.execute('BEGIN')
        require(schema(source) == expected_schema, 'E_OPERATION_UNSUPPORTED')
        require(source.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'E_INTEGRITY')
        meta = {k: strict_json(v) for k, v in source.execute('SELECT key,value FROM meta')}
        require(set(meta) == {'avatar', 'owner', 'enrollment', 'revocation_epoch'}, 'E_OPERATION_UNSUPPORTED')
        require(meta['enrollment'] == payload['enrollment'] and meta['avatar'] == payload['core']['avatar_id']
                and meta['owner'] == enrollment['owner_ref'], 'E_IDENTITY')
        cores = source.execute('SELECT avatar,owner,revision,body FROM cores').fetchall()
        require(len(cores) == 1 and cores[0][0] == meta['avatar'] and cores[0][1] == meta['owner'], 'E_IDENTITY')
        old_core = strict_json(cores[0][3])
        require(cores[0][2] == old_core['revision'], 'E_INTEGRITY')
        require(Service(snapshot).verify_local_core(old_core, meta['enrollment']), 'E_INTEGRITY')
        old_refs = manifest(old_core)
        require(old_core['revision'] <= payload['core']['revision']
                and meta['revocation_epoch'] <= payload['revocation_epoch'], 'E_CHECKPOINT_ROLLBACK')
        stored = source.execute('SELECT avatar,id,space,revision,body FROM memories').fetchall()
        old_memories = {row[1]: strict_json(row[4]) for row in stored}
        require(len(old_memories) == len(stored), 'E_IDENTITY')
        require(set(old_memories) == set(old_refs), 'E_INTEGRITY')
        for ident, memory in old_memories.items():
            validate('memory-record', memory)
            require(memory['memory_id'] == ident and digest(memory) == old_refs[ident]['sha256'], 'E_INTEGRITY')
            require(isinstance(memory['content'], str) and memory['derived_from'] == []
                    and not memory.get('extensions'), 'E_OPERATION_UNSUPPORTED')
            require(memory['scope'] == old_refs[ident]['scope']
                    and memory['revision'] == old_refs[ident]['version'], 'E_INTEGRITY')
        for avatar, ident, space, revision, _ in stored:
            memory = old_memories[ident]
            require(avatar == meta['avatar'] and space == memory['scope']['space_ref']
                    and revision == memory['revision'], 'E_SCOPE')
        tombstones = {r['id']: r for r in payload['tombstones']}
        for avatar, ident, space, revision, body in source.execute('SELECT * FROM tombstones'):
            tomb = strict_json(body)
            validate('tombstone', tomb)
            require(avatar == meta['avatar'] and ident == tomb['object_ref']['id']
                    and space == tomb['scope']['space_ref']
                    and revision == tomb['object_ref']['version']
                    and tomb['scope']['owner_ref'] == meta['owner'], 'E_SCOPE')
            require(ident not in refs, 'E_INTEGRITY')
            require(ident in tombstones and revision <= tombstones[ident]['revision']
                    and space == tombstones[ident]['space'], 'E_CHECKPOINT_ROLLBACK')
        # Reserve the destination exclusively; it stays empty until atomic publication.
        target.mkdir(mode=0o700)
        reserved = True
        reservation = target.stat().st_ino
        stage = Path(tempfile.mkdtemp(prefix='.aiap-recovery-', dir=target.parent))
        new_db = stage / 'core.sqlite3'
        fd = os.open(new_db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(new_db) as copied:
            source.backup(copied)
        source.rollback()
        save_private(stage / 'owner-key.pem', owner_key)
        save_private(stage / 'avatar-key.pem', avatar_key)
        recovered = Service(stage, clock=lambda: now)
        kept = set()
        with recovered.tx() as db:
            for table in ('history', 'deltas', 'views', 'audit', 'tombstones', 'spaces'):
                db.execute('DELETE FROM ' + table)
            for row in payload['spaces']:
                db.execute('INSERT INTO spaces VALUES(?,?,?,?,?)', tuple(row[k] for k in ('avatar', 'id', 'kind', 'policy', 'revision')))
            for row in tombstones.values():
                db.execute('INSERT INTO tombstones VALUES(?,?,?,?,?)', tuple(row[k] for k in ('avatar', 'id', 'space', 'revision', 'body')))
            for ident, memory in old_memories.items():
                ref = refs.get(ident)
                valid = (ident not in tombstones and ref is not None and memory['status'] == 'active'
                         and memory['revision'] == ref['version'] and memory['scope'] == ref['scope']
                         and digest(memory) == ref['sha256'])
                if valid:
                    kept.add(ident)
                else:
                    db.execute('DELETE FROM memories WHERE id=?', (ident,))
            # Every old credential is invalid, including formerly active Owner grants.
            revoked = db.execute('SELECT count(*) FROM grants').fetchone()[0]
            db.execute('UPDATE grants SET revoked=1')
            db.execute("UPDATE meta SET value=? WHERE key='revocation_epoch'", (str(payload['revocation_epoch'] + 1),))
            db.execute('UPDATE cores SET revision=?', (payload['core']['revision'],))
            recovered._rebuild_core(db, meta['avatar'])
            recovered._audit(db, meta['avatar'], None, 'recovery-checkpoint-applied', expected_sha256, 'local-operator')
        owner = recovered.issue_grant([s['id'] for s in payload['spaces']], 'owner-maintenance', 'owner-local', 'owner', 30)
        save_private(stage / 'owner-credentials.json', canonical(owner))
        with sqlite3.connect(new_db) as db:
            db.execute('VACUUM')
            require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'E_INTEGRITY')
        report = {'profile': PROFILE, 'checkpoint_sha256': expected_sha256,
                  'restored_objects': len(kept), 'excluded_backup_objects': len(old_memories) - len(kept),
                  'missing_current_objects': len(set(refs) - kept), 'old_grants_revoked': revoked,
                  'pending_history_views_discarded': True, 'tombstones_preserved': len(tombstones),
                  'restore_guarantee': 'complete-for-current-memory-index' if set(refs) == kept else 'partial-current-memory-index',
                  'trust': 'operator-pinned checkpoint at capture time; no live revocation synchronization',
                  'fresh_owner_credential_file': 'owner-credentials.json'}
        save_private(stage / 'recovery-report.json', canonical(report))
        require((clock or (lambda: datetime.now(timezone.utc)))() < parse(payload['expires_at']), 'E_EXPIRED')
        require(target.stat().st_ino == reservation and not list(target.iterdir()), 'E_OUTPUT_EXISTS')
        os.replace(stage, target)
        stage = None
        reserved = False
        return report
    finally:
        source.close()
        if stage is not None:
            shutil.rmtree(stage)
        if reserved:
            try:
                target.rmdir()  # Never remove concurrent content in the reserved destination.
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    checkpoint = commands.add_parser('checkpoint')
    checkpoint.add_argument('--data-dir', type=Path, required=True)
    checkpoint.add_argument('--output', type=Path, required=True)
    checkpoint.add_argument('--ttl-hours', type=int, default=1)
    restore = commands.add_parser('restore')
    restore.add_argument('--snapshot', type=Path, required=True)
    restore.add_argument('--checkpoint', type=Path, required=True)
    restore.add_argument('--checkpoint-sha256', required=True)
    restore.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'checkpoint':
        result = export_checkpoint(args.data_dir, args.output, args.ttl_hours)
    else:
        result = restore_snapshot(args.snapshot, args.checkpoint, args.checkpoint_sha256, args.target)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Fault, ValueError, TypeError, KeyError, RecursionError, OSError, sqlite3.DatabaseError):
        print('Recovery rejected; no usable destination was activated.', file=sys.stderr)
        raise SystemExit(1)
