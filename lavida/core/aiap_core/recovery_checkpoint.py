# SPDX-License-Identifier: Apache-2.0
"""Validation shared by the Core registry and offline recovery tools."""
import hashlib
import json
import os
import re
import stat
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical, digest, exact, Fault, require, unb64, validate
from .service import Service, parse, _BASE_EXTENSION


PROFILE = 'x-aiap-local-recovery-checkpoint-v1'
DOMAIN = b'AIAP-LOCAL-RECOVERY-CHECKPOINT-v1\x00'


def read_file(path, limit=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
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


def manifest(core):
    memories, _ = _index_parts(core, allow_preferences=False)
    return memories


def _index_parts(core, *, allow_preferences):
    validate('avatar-core', core)
    require(core['profile_summary'] == [] and core['procedural_index'] == [], 'E_OPERATION_UNSUPPORTED')
    preferences = {}
    if core['extensions'] != [_BASE_EXTENSION]:
        require(allow_preferences, 'E_CRITICAL_EXTENSION')
        preferences = Service._preference_references(core)
    refs = core['state_index']
    require(len({r['id'] for r in refs}) == len(refs), 'E_INTEGRITY')
    preference_ids = {ref['id'] for ref in preferences.values()}
    return {r['id']: r for r in refs if r['id'] not in preference_ids}, preferences


def expected_scope(payload, space):
    spaces = {s['id']: s for s in payload['spaces']}
    require(space in spaces, 'E_SCOPE')
    s = spaces[space]
    return {'owner_ref': payload['core']['owner']['owner_ref'], 'space_ref': space,
            'policy_ref': {'id': s['policy'], 'version': s['revision']}}


def validate_payload(payload, now):
    memories, _ = _validate_payload(payload, now, allow_preferences=False)
    return memories


def validate_issuance_source(service, db, payload, now):
    """Check signed preference commitments against the issuer's open SQLite snapshot."""
    core = payload['core']
    if core['extensions'] == [_BASE_EXTENSION]:
        return validate_payload(payload, now)
    memories, preferences = _validate_payload(payload, now, allow_preferences=True)
    _check_registry_coverage(service, db, core, preferences)
    return memories


def _check_registry_coverage(service, db, core, preferences):
    accounted = 0
    for ref in preferences.values():
        manifest = service._check_preference_ref(db, core, ref['scope'], preferences)
        accounted += manifest['record_count']
    stored = db.execute("SELECT COUNT(*) FROM meta WHERE key GLOB 'preference:*'").fetchone()[0]
    require(accounted == stored, 'E_INTEGRITY', 500)


def _validate_payload(payload, now, *, allow_preferences):
    exact(payload, ['profile', 'checkpoint_id', 'issued_at', 'expires_at', 'core',
                    'enrollment', 'spaces', 'tombstones', 'revocation_epoch'])
    require(payload['profile'] == PROFILE, 'E_CRITICAL_EXTENSION')
    issued, expires = parse(payload['issued_at']), parse(payload['expires_at'])
    require(issued <= now < expires and timedelta(0) < expires - issued <= timedelta(hours=24), 'E_EXPIRED')
    require(type(payload['revocation_epoch']) is int and payload['revocation_epoch'] >= 0, 'E_SCHEMA')
    core = payload['core']
    memories, preferences = _index_parts(core, allow_preferences=allow_preferences)
    require(Service.verify_local_core(core, payload['enrollment']), 'E_INTEGRITY')
    require(isinstance(payload['spaces'], list), 'E_SCOPE')
    standard = {'space:general', 'space:life', 'space:work'}
    scopes = {}
    for s in payload['spaces']:
        exact(s, ['avatar', 'id', 'kind', 'policy', 'revision'])
        sid = s['id']
        require(isinstance(sid, str) and sid not in scopes, 'E_SCOPE')
        if sid not in standard:
            require(allow_preferences and re.fullmatch(r'space:project:[a-z0-9][a-z0-9-]{0,62}', sid)
                    and s['kind'] == 'project' and s['policy'] == 'policy:project:' + sid.split(':', 2)[2], 'E_SCOPE')
        scopes[sid] = {'owner_ref': core['owner']['owner_ref'], 'space_ref': sid,
                       'policy_ref': {'id': s['policy'], 'version': s['revision']}}
        require(s['avatar'] == core['avatar_id'] and type(s['revision']) is int and s['revision'] > 0, 'E_SCOPE')
    require(standard <= scopes.keys(), 'E_SCOPE')
    for ref in core['state_index']:
        require(ref['scope'] == scopes.get(ref['scope']['space_ref']), 'E_SCOPE')
    require(isinstance(payload['tombstones'], list), 'E_SCHEMA')
    active_ids = {ref['id'] for ref in core['state_index']}
    ids = set()
    for row in payload['tombstones']:
        exact(row, ['avatar', 'id', 'space', 'revision', 'body'])
        tomb = strict_json(row['body'])
        validate('tombstone', tomb)
        require(row['avatar'] == core['avatar_id'] and row['id'] not in ids
                and row['id'] == tomb['object_ref']['id'] and row['revision'] == tomb['object_ref']['version']
                and row['space'] == tomb['scope']['space_ref']
                and tomb['scope']['owner_ref'] == core['owner']['owner_ref'], 'E_SCOPE')
        require(row['id'] not in active_ids, 'E_INTEGRITY')
        ids.add(row['id'])
    return memories, preferences


def load_checkpoint(path, expected_sha256, now):
    payload, memories, _ = _load_checkpoint(path, expected_sha256, now, allow_preferences=False)
    return payload, memories


def load_checkpoint_index(path, expected_sha256, now):
    """Load a pinned checkpoint for metadata inspection or registration."""
    require(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_NONBLOCK'), 'E_OPERATION_UNSUPPORTED')
    try:
        return _load_checkpoint(path, expected_sha256, now, allow_preferences=True)
    except OSError:
        raise Fault('E_RECOVERY_FILE') from None
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, AttributeError):
        raise Fault('E_SCHEMA') from None


def inspect_checkpoint_index(path, expected_sha256, now):
    payload, memories, preferences = load_checkpoint_index(path, expected_sha256, now)
    governance = {key: payload[key] for key in ('core', 'spaces', 'tombstones', 'revocation_epoch')}
    return {'status': 'checkpoint-index-inspected', 'checkpoint_sha256': expected_sha256,
            'enrollment_sha256': digest(payload['enrollment']), 'governance_sha256': digest(governance),
            'space_count': len(payload['spaces']), 'tombstone_count': len(payload['tombstones']),
            'expires_at': payload['expires_at'],
            'core_revision': payload['core']['revision'], 'memory_reference_count': len(memories),
            'preference_manifest_count': len(preferences), 'source_currentness_verified': False}


def compare_local_checkpoint(service, token, path, pin):
    """Compare a pinned file to one local Owner-authorized governance snapshot."""
    started = service.now()
    with service.tx(read_only=True) as db:
        owner, _, core, enrollment = service._owner_core(db, token)
        payload, memories, preferences = load_checkpoint_index(path, pin, started)
        require(payload['enrollment'] == enrollment and core['avatar_id'] == service.meta(db, 'avatar')
                and core['owner']['owner_ref'] == service.meta(db, 'owner'), 'E_IDENTITY')
        current = {'core': core, 'revocation_epoch': service.meta(db, 'revocation_epoch'),
                   'spaces': [dict(row) for row in db.execute('SELECT * FROM spaces ORDER BY id')],
                   'tombstones': [dict(row) for row in db.execute('SELECT * FROM tombstones ORDER BY id')]}
        require(digest(current) == digest({key: payload[key] for key in current}), 'E_SOURCE_DIVERGED')
        indexed = core['extensions'] != [_BASE_EXTENSION]
        if indexed:
            _check_registry_coverage(service, db, core, preferences)
        finished = service.now()
        require(started <= finished < min(parse(owner['expires']), parse(payload['expires_at'])), 'E_EXPIRED')
        return {'status': 'local-governance-matches-checkpoint', 'checkpoint_sha256': pin,
                'core_revision': core['revision'], 'memory_reference_count': len(memories),
                'preference_manifest_count': len(preferences), 'preference_registry_checked': indexed,
                'restore_authorized': False}


def _load_checkpoint(path, expected_sha256, now, *, allow_preferences):
    require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256), 'E_CHECKPOINT_PIN')
    raw = read_file(path)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'E_CHECKPOINT_PIN')
    envelope = strict_json(raw)
    exact(envelope, ['payload', 'signature'])
    payload = envelope['payload']
    memories, preferences = _validate_payload(payload, now, allow_preferences=allow_preferences)
    try:
        key = unb64(payload['enrollment']['payload']['owner_public_key'])
        Ed25519PublicKey.from_public_bytes(key).verify(unb64(envelope['signature']), DOMAIN + canonical(payload))
    except Exception:
        raise Fault('E_INTEGRITY') from None
    return payload, memories, preferences
