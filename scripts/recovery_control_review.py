# SPDX-License-Identifier: Apache-2.0
"""Read-only evidence for owner review after local control-storage loss.

Requires a stopped consistent source snapshot and an independent durable reader.
Never re-enrolls, creates keys, signs checkpoints or authorizes activation.
"""
from pathlib import Path
import sqlite3

from recovery_guard import (Service, SQL, schema, strict_json, digest, manifest,
                            require, validate, read_file)
from recovery_highwater import DurableWitnessReader, private_path
from recovery_source_gate import governance


def control_condition(directory):
    directory = Path(directory)
    if not directory.exists() and not directory.is_symlink():
        return 'missing-directory'
    private_path(directory, directory=True)
    for name in ('gate.lock', 'gate-state.json'):
        path = directory / name
        if not path.exists() and not path.is_symlink():
            return 'missing-' + name
        private_path(path)
    # Do not trust or print a private key while preparing a loss report.
    try:
        state = strict_json(read_file(directory / 'gate-state.json'))
        if not isinstance(state, dict):
            return 'corrupt-state-requires-owner-review'
    except (ValueError, TypeError):
        return 'corrupt-state-requires-owner-review'
    return 'present-requires-separate-authentication'


def review_control_loss(source_dir, control_dir, reader):
    require(isinstance(reader, DurableWitnessReader), 'E_READER_ENROLLMENT')
    # This validates stored historical signatures using the externally registered key.
    floor = reader.head
    source = Path(source_dir)
    control = Path(control_dir)
    require(not source.resolve().is_relative_to(control.resolve()) and
            not control.resolve().is_relative_to(source.resolve()), 'E_GATE_LOCATION')
    require(not reader.directory.resolve().is_relative_to(source.resolve()) and
            not reader.directory.resolve().is_relative_to(control.resolve()), 'E_GATE_LOCATION')
    private_path(source, directory=True)
    db_path = source / 'core.sqlite3'
    private_path(db_path)
    require(db_path.stat().st_size <= 64 * 1024 * 1024, 'E_RECOVERY_FILE')
    require(not any((source / ('core.sqlite3' + suffix)).exists() for suffix in
                    ('-wal', '-shm', '-journal')), 'E_OPERATION_UNSUPPORTED')
    # No file creation, journal replay, key loading, service startup or writes.
    db = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    db.row_factory = sqlite3.Row
    expected = sqlite3.connect(':memory:')
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        expected.executescript(SQL)
        require([tuple(r) for r in schema(db)] == schema(expected), 'E_OPERATION_UNSUPPORTED')
        require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'E_INTEGRITY')
        current = governance(db)
        meta = {r[0]: strict_json(r[1]) for r in db.execute('SELECT key,value FROM meta')}
        core = current['core']
        require(digest(meta['enrollment']) == reader.trust['enrollment_sha256']
                and core['avatar_id'] == meta['avatar'] == reader.trust['avatar']
                and core['owner']['owner_ref'] == meta['owner'], 'E_IDENTITY')
        require(Service('.').verify_local_core(core, meta['enrollment']), 'E_INTEGRITY')
        refs = manifest(core)
        rows = db.execute('SELECT avatar,id,space,revision,body FROM memories').fetchall()
        require(len(rows) == len(refs), 'E_INTEGRITY')
        for row in rows:
            memory = strict_json(row['body'])
            validate('memory-record', memory)
            require(row['id'] in refs and memory['memory_id'] == row['id']
                    and digest(memory) == refs[row['id']]['sha256']
                    and row['avatar'] == core['avatar_id']
                    and row['revision'] == memory['revision'] == refs[row['id']]['version']
                    and row['space'] == memory['scope']['space_ref']
                    and memory['scope'] == refs[row['id']]['scope'], 'E_INTEGRITY')
        revision, epoch = core['revision'], current['revocation_epoch']
        require(type(revision) is int and revision >= 1 and type(epoch) is int and epoch >= 0, 'E_SCHEMA')
        rollback = revision < floor['core_revision'] or epoch < floor['revocation_epoch']
        equal = revision == floor['core_revision'] and epoch == floor['revocation_epoch']
        divergent = equal and digest(current) != floor['governance_sha256']
        condition = control_condition(control)
        return {'profile': 'x-aiap-control-loss-review-v1',
                'status': 'blocked-source-rollback-or-divergence' if rollback or divergent
                          else 'manual-owner-review-required',
                'control_condition': condition, 'trust_fingerprint': digest(reader.trust),
                'last_seen_sequence': floor['sequence'], 'last_seen_head_sha256': digest(floor),
                'source_core_revision': revision, 'last_seen_core_revision': floor['core_revision'],
                'source_revocation_epoch': epoch, 'last_seen_revocation_epoch': floor['revocation_epoch'],
                'source_governance_sha256': digest(current),
                'source_relation': 'rollback-or-divergent' if rollback or divergent else
                                   ('equal-to-last-seen' if equal else 'counters-newer-than-last-seen'),
                'automatic_reenrollment': False, 'proofs_may_resume': False,
                'scope': 'stopped snapshot evidence only; no currentness or independent-owner verification'}
    finally:
        db.close()
        expected.close()
