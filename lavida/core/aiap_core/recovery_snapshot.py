# SPDX-License-Identifier: Apache-2.0
"""Prepare a private recovered snapshot and publish it through a caller's optional guard."""
from contextlib import closing, nullcontext
from datetime import datetime, timezone
import errno
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile

from cryptography.hazmat.primitives import serialization

from .contracts import Fault, b64, canonical, digest, require, validate
from .recovery_checkpoint import PROFILE, load_checkpoint, manifest, read_file, strict_json
from .service import Service, SQL, parse, save_private


def public_key(pem):
    key = serialization.load_pem_private_key(pem, None)
    return b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def schema(db):
    return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name").fetchall()


def restore_snapshot(snapshot_dir, checkpoint, expected_sha256, target_dir, clock=None,
                     *, publication_guard=None):
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
    require(not any(os.path.lexists(snapshot / ('core.sqlite3' + suffix))
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
    reservation = None
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
        require(Service.verify_local_core(old_core, meta['enrollment']), 'E_INTEGRITY')
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
        with closing(sqlite3.connect(new_db)) as copied:
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
        with closing(sqlite3.connect(new_db)) as db:
            db.execute('VACUUM')
            require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'E_INTEGRITY')
        report = {'profile': PROFILE, 'checkpoint_sha256': expected_sha256,
                  'restored_objects': len(kept), 'excluded_backup_objects': len(old_memories) - len(kept),
                  'missing_current_objects': len(set(refs) - kept), 'old_grants_revoked': revoked,
                  'pending_history_views_discarded': True, 'tombstones_preserved': len(tombstones),
                  'restore_guarantee': 'complete-for-current-memory-index' if set(refs) == kept else 'partial-current-memory-index',
                  'trust': 'operator-pinned checkpoint at capture time; no live revocation synchronization',
                  'fresh_owner_credential_file': 'owner-credentials.json'}
        # Nothing can publish until the caller's final gate has entered successfully.
        guard = publication_guard() if publication_guard else nullcontext()
        with guard as evidence:
            if evidence is not None:
                report.update(status='isolated-recovery-created', production_activation=False,
                              publication_evidence=evidence,
                              trust='point-in-time source observation; no production activation or revocation lease')
            save_private(stage / 'recovery-report.json', canonical(report))
            activated_at = (clock or (lambda: datetime.now(timezone.utc)))()
            require(parse(payload['issued_at']) <= activated_at < parse(payload['expires_at']), 'E_EXPIRED')
            if evidence is not None:
                require(parse(evidence['verified_at']) <= activated_at
                        < parse(evidence['source_observation_expires_at']), 'E_EXPIRED')
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_ino == reservation
                    and not list(target.iterdir()), 'E_OUTPUT_EXISTS')
            try:
                os.replace(stage, target)
            except OSError as exc:
                if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
                    raise Fault('E_OUTPUT_EXISTS') from exc
                raise
            stage = None
            reserved = False
        return report
    finally:
        source.close()
        if stage is not None:
            shutil.rmtree(stage)
        if reserved:
            try:
                info = target.lstat()
                if stat.S_ISDIR(info.st_mode) and info.st_ino == reservation:
                    target.rmdir()  # Never remove concurrent content or another reservation.
            except OSError:
                pass
