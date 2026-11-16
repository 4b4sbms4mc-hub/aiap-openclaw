# SPDX-License-Identifier: Apache-2.0
"""Validation shared by the Core registry and offline recovery tools."""
import hashlib
import json
import os
import re
import stat
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical, exact, Fault, require, unb64, validate
from .service import Service, parse


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
    require(Service.verify_local_core(core, payload['enrollment']), 'E_INTEGRITY')
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
