# SPDX-License-Identifier: Apache-2.0
"""Avatar-key v2 isolated availability-first experiment; no server, deployment or activation.

Normal Core writers do not depend on this witness. Every recovery selection needs
a nonce-bound observation of the live source, not a cached witness checkpoint.
This is a point-in-time observation, not a lease or proof of unseen offline history.
The in-memory witness/key below is deliberately unsuitable for production custody.
"""
from datetime import timedelta
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from recovery_guard import (SQL, Fault, require, canonical, digest, b64,
                            unb64, parse, stamp, read_file, strict_json, public_key,
                            load_checkpoint, schema)
from recovery_source_gate import governance
from recovery_witness import SyntheticWitness, hex_digest, DOMAIN

OBS_DOMAIN = b'AIAP-LIVE-SOURCE-OBSERVATION-v2\x00'
OBS_PROFILE = 'x-aiap-live-source-observation-v2'


def checkpoint_governance(payload):
    return {k: payload[k] for k in ('core', 'spaces', 'tombstones', 'revocation_epoch')}


def verify_observation(envelope, nonce, pin, payload, enrollment_sha256, now):
    # v2 is explicitly selected; no legacy verifier fallback is permitted.
    require(isinstance(envelope, dict) and set(envelope) == {'payload', 'signature'}, 'E_SCHEMA')
    body = envelope['payload']
    require(isinstance(body, dict) and set(body) == {'profile', 'nonce', 'checkpoint_sha256',
            'enrollment_sha256', 'issued_at', 'expires_at'}, 'E_SCHEMA')
    require(body['profile'] == OBS_PROFILE, 'E_SCHEMA')
    require(digest(payload['enrollment']) == enrollment_sha256
            and body['enrollment_sha256'] == enrollment_sha256, 'E_IDENTITY')
    try:
        Ed25519PublicKey.from_public_bytes(unb64(payload['enrollment']['payload']['avatar_public_key'])).verify(
            unb64(envelope['signature']), OBS_DOMAIN + canonical(body))
    except Exception:
        raise Fault('E_INTEGRITY') from None
    require(body['nonce'] == nonce and body['checkpoint_sha256'] == pin, 'E_SOURCE_OBSERVATION')
    try:
        issued, expires = parse(body['issued_at']), parse(body['expires_at'])
        valid = (parse(payload['issued_at']) <= issued <= now < expires <= parse(payload['expires_at'])
                 and timedelta(0) < expires - issued <= timedelta(seconds=30))
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise Fault('E_EXPIRED') from None
    require(valid, 'E_EXPIRED')


def observe_source(source_dir, checkpoint, pin, nonce, clock):
    """Read-only SQLite snapshot, signed locally with the source Avatar key.

    Only call against synthetic fixtures for now. Production would require an
    authenticated, restricted source endpoint and separate key-access review.
    No key material or memory bodies are returned. No database is created.
    """
    require(hex_digest(nonce), 'E_WITNESS_NONCE')
    now = clock()
    payload, _ = load_checkpoint(checkpoint, pin, now)
    source = Path(source_dir)
    path = source / 'core.sqlite3'
    require(not source.is_symlink() and not path.is_symlink() and path.is_file(), 'E_RECOVERY_FILE')
    # Limit this lab reader to the tested rollback-journal fixture. SQLite may
    # need sidecar handling even on a read-only WAL connection; do not claim it.
    require(not any((source / ('core.sqlite3' + suffix)).exists()
                    for suffix in ('-wal', '-shm', '-journal')), 'E_OPERATION_UNSUPPORTED')
    expected = sqlite3.connect(':memory:')
    try:
        expected.executescript(SQL)
        expected_schema = schema(expected)
    finally:
        expected.close()
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=1)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('BEGIN')
        require([tuple(row) for row in schema(db)] == expected_schema, 'E_OPERATION_UNSUPPORTED')
        meta = {row[0]: strict_json(row[1]) for row in db.execute('SELECT key,value FROM meta')}
        require(set(meta) == {'avatar', 'owner', 'enrollment', 'revocation_epoch'}, 'E_OPERATION_UNSUPPORTED')
        require(meta['enrollment'] == payload['enrollment']
                and meta['avatar'] == payload['core']['avatar_id']
                and meta['owner'] == payload['core']['owner']['owner_ref'], 'E_IDENTITY')
        require(digest(governance(db)) == digest(checkpoint_governance(payload)), 'E_SOURCE_DIVERGED')
        # Sign the exact captured state while the read snapshot is still held.
        # An ordinary writer may change the source after this snapshot; no lease.
        key_bytes = read_file(source / 'avatar-key.pem', 16384)
        require(public_key(key_bytes) == payload['enrollment']['payload']['avatar_public_key'], 'E_INTEGRITY')
        body = {'profile': OBS_PROFILE, 'nonce': nonce, 'checkpoint_sha256': pin,
                'enrollment_sha256': digest(payload['enrollment']),
                'issued_at': stamp(now),
                'expires_at': stamp(min(now + timedelta(seconds=30), parse(payload['expires_at'])))}
        key = serialization.load_pem_private_key(key_bytes, None)
        return {'payload': body, 'signature': b64(key.sign(OBS_DOMAIN + canonical(body)))}
    finally:
        db.close()


class AvatarObservationWitness(SyntheticWitness):
    """In-memory Mac-side model. No observation means no recovery proof.

    Source and witness paths/keys remain separate in tests; there is no shared
    writer lock and no dependency from normal source writes to this object.
    """
    def answer(self, nonce, *, checkpoint=None, pin=None, observation=None):
        require(observation is not None and checkpoint is not None and pin is not None,
                'E_WITNESS_UNAVAILABLE')
        require(hex_digest(nonce), 'E_WITNESS_NONCE')
        now = self.clock()
        payload, _ = load_checkpoint(checkpoint, pin, now)
        require(payload['core']['avatar_id'] == self.avatar, 'E_IDENTITY')
        verify_observation(observation, nonce, pin, payload, self.enrollment_sha256, now)
        if self.head is None or pin != self.head['checkpoint_sha256']:
            ticket = self.begin_update(self.head['sequence'] if self.head else 0)
            self.publish(ticket, checkpoint, pin)
        proof = super().answer(nonce)
        # A witness proof must not outlive the source observation it checked.
        require(parse(observation['payload']['issued_at']) <= parse(proof['payload']['issued_at'])
                < parse(observation['payload']['expires_at']), 'E_EXPIRED')
        proof['payload']['expires_at'] = stamp(min(parse(proof['payload']['expires_at']),
                                                    parse(observation['payload']['expires_at'])))
        proof['signature'] = b64(self._key.sign(DOMAIN + canonical(proof['payload'])))
        return proof
