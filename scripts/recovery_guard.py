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
import sqlite3
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lavida/core'))
from aiap_core.service import Service, SQL, stamp, parse, uid, save_private
from aiap_core.contracts import canonical, digest, b64, unb64, require, exact, validate, Fault
from cryptography.hazmat.primitives import serialization
from aiap_core.recovery_checkpoint import (DOMAIN, PROFILE, expected_scope, inspect_checkpoint_index, load_checkpoint,
                                          manifest, read_file, strict_json, validate_issuance_source, validate_payload)
from aiap_core.recovery_snapshot import public_key, restore_snapshot, schema

def export_checkpoint(data_dir, output, ttl_hours=1, clock=None):
    require(type(ttl_hours) is int and 1 <= ttl_hours <= 24, 'E_SCHEMA')
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    service = Service(data_dir, clock=lambda: now)
    with service.tx(read_only=True) as db:
        avatar = service.meta(db, 'avatar')
        row = db.execute('SELECT body,revision FROM cores WHERE avatar=?', (avatar,)).fetchone()
        require(row is not None, 'E_INTEGRITY')
        core = strict_json(row['body'])
        require(core['avatar_id'] == avatar and core['revision'] == row['revision'], 'E_INTEGRITY')
        payload = {'profile': PROFILE, 'checkpoint_id': uid('recovery:'), 'issued_at': stamp(now),
                   'expires_at': stamp(now + timedelta(hours=ttl_hours)), 'core': core,
                   'enrollment': service.meta(db, 'enrollment'),
                   'spaces': [dict(r) for r in db.execute('SELECT * FROM spaces ORDER BY id')],
                   'tombstones': [dict(r) for r in db.execute('SELECT * FROM tombstones ORDER BY id')],
                   'revocation_epoch': service.meta(db, 'revocation_epoch')}
        refs = validate_issuance_source(service, db, payload, now)
        checked = 0
        for row in db.execute('SELECT * FROM memories'):
            ref = refs.get(row['id'])
            require(ref is not None and row['avatar'] == avatar and row['revision'] == ref['version']
                    and row['space'] == ref['scope']['space_ref']
                    and digest(strict_json(row['body'])) == ref['sha256'], 'E_INTEGRITY')
            checked += 1
        require(checked == len(refs), 'E_INTEGRITY')
        key_bytes = read_file(Path(data_dir) / 'owner-key.pem', 16384)
        require(public_key(key_bytes) == payload['enrollment']['payload']['owner_public_key'], 'E_INTEGRITY')
        key = serialization.load_pem_private_key(key_bytes, None)
        envelope = {'payload': payload, 'signature': b64(key.sign(DOMAIN + canonical(payload)))}
    raw = canonical(envelope)
    save_private(Path(output), raw)
    return {'checkpoint_sha256': hashlib.sha256(raw).hexdigest(),
            'expires_at': payload['expires_at'], 'trust': 'operator must pin a current checkpoint outside the backup'}


def review_checkpoint(checkpoint, expected_sha256, diagnostic, clock=None):
    """Compare signed checkpoint metadata with a GOVREAD diagnostic report."""
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    index = inspect_checkpoint_index(checkpoint, expected_sha256, now)
    report = strict_json(read_file(diagnostic, 4096))
    if isinstance(report, dict) and set(report) == {'source', 'recorded_at', 'plan_sha256', 'result'}:
        report = report['result']
    exact(report, ['profile', 'enrollment_sha256', 'governance_sha256', 'core_revision',
                   'space_count', 'tombstone_count', 'database_access', 'trust'])
    require(report['profile'] == 'x-aiap-governance-digest-preflight-v1'
            and report['database_access'] == 'read-only'
            and report['trust'] == 'diagnostic-only-not-a-checkpoint-or-source-proof',
            'E_GOVERNANCE_DIAGNOSTIC')
    expected = {key: index[key] for key in ('enrollment_sha256', 'governance_sha256', 'core_revision',
                                            'space_count', 'tombstone_count')}
    require(all(type(report[key]) is type(value) and report[key] == value
                for key, value in expected.items()), 'E_GOVERNANCE_MISMATCH')
    return {
        'status': 'checkpoint-matches-diagnostic',
        'checkpoint_sha256': expected_sha256,
        'expires_at': index['expires_at'],
        'source_currentness_verified': False,
        'registration_performed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    checkpoint = commands.add_parser('checkpoint')
    checkpoint.add_argument('--data-dir', type=Path, required=True)
    checkpoint.add_argument('--output', type=Path, required=True)
    checkpoint.add_argument('--ttl-hours', type=int, default=1)
    review = commands.add_parser('review-checkpoint', help='compare a pinned signed checkpoint with a GOVREAD report')
    review.add_argument('--checkpoint', type=Path, required=True)
    review.add_argument('--checkpoint-sha256', required=True, help='checkpoint digest obtained independently')
    review.add_argument('--diagnostic', type=Path, required=True, help='raw or locally recorded GOVREAD JSON')
    restore = commands.add_parser('restore')
    restore.add_argument('--snapshot', type=Path, required=True)
    restore.add_argument('--checkpoint', type=Path, required=True)
    restore.add_argument('--checkpoint-sha256', required=True)
    restore.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'checkpoint':
        result = export_checkpoint(args.data_dir, args.output, args.ttl_hours)
    elif args.command == 'review-checkpoint':
        result = review_checkpoint(args.checkpoint, args.checkpoint_sha256, args.diagnostic)
    else:
        result = restore_snapshot(args.snapshot, args.checkpoint, args.checkpoint_sha256, args.target)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Fault, ValueError, TypeError, KeyError, RecursionError, OSError, sqlite3.DatabaseError):
        print('Recovery rejected; no usable destination was activated.', file=sys.stderr)
        raise SystemExit(1)
