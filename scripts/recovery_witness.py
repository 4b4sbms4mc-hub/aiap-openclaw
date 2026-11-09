# SPDX-License-Identifier: Apache-2.0
"""In-memory synthetic witness model. No server, durable ledger or activation API.

Trusted enrollment, generation and witness public key are supplied out of band.
All source mutations must first call begin_update; bypassing it is NOT detected.
"""
from copy import deepcopy
from datetime import timedelta
import re
import secrets

from recovery_guard import (load_checkpoint, canonical, digest, b64, unb64,
                            parse, stamp, require, Fault)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOMAIN = b'AIAP-SYNTHETIC-WITNESS-PROOF-v1\x00'
PROFILE = 'x-aiap-synthetic-witness-v1'


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def monotonic_head(previous, current):
    # Local-model draft supplied the comparison structure; Codex tightened
    # strict types (bool is not a counter), malformed input and full hex matching.
    def valid(head):
        return (isinstance(head, dict) and
                all(type(head.get(k)) is int and head[k] >= 0 for k in
                    ('sequence', 'core_revision', 'revocation_epoch')) and
                head['sequence'] >= 1 and
                all(hex_digest(head.get(k)) for k in
                    ('checkpoint_sha256', 'governance_sha256')))
    if not valid(current) or (previous is not None and not valid(previous)):
        return False
    if previous is None:
        return True
    if current['sequence'] <= previous['sequence']:
        return False
    if any(current[k] < previous[k] for k in ('core_revision', 'revocation_epoch')):
        return False
    if all(current[k] == previous[k] for k in ('core_revision', 'revocation_epoch')):
        return current['governance_sha256'] == previous['governance_sha256']
    return True


class SyntheticWitness:
    """Single-threaded reference state machine; deliberately not a deployed service."""
    def __init__(self, avatar, enrollment_sha256, clock):
        require(isinstance(avatar, str) and hex_digest(enrollment_sha256), 'E_IDENTITY')
        self.avatar, self.enrollment_sha256, self.clock = avatar, enrollment_sha256, clock
        self.generation = secrets.token_hex(32)
        self._key = Ed25519PrivateKey.generate()
        self._head = None
        self._pending = None

    @property
    def public_key(self):
        return b64(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    @property
    def head(self):
        return deepcopy(self._head)

    def begin_update(self, expected_sequence):
        require(type(expected_sequence) is int and expected_sequence ==
                (self._head['sequence'] if self._head else 0), 'E_WITNESS_SEQUENCE')
        require(self._pending is None, 'E_WITNESS_PENDING')
        self._pending = secrets.token_hex(32)
        return self._pending

    def publish(self, ticket, checkpoint, pin):
        require(self._pending is not None and ticket == self._pending, 'E_WITNESS_PENDING')
        payload, _ = load_checkpoint(checkpoint, pin, self.clock())
        require(payload['core']['avatar_id'] == self.avatar and
                digest(payload['enrollment']) == self.enrollment_sha256, 'E_IDENTITY')
        head = {'profile': PROFILE, 'avatar_id': self.avatar,
                'enrollment_sha256': self.enrollment_sha256, 'generation': self.generation,
                'sequence': self._head['sequence'] + 1 if self._head else 1,
                'previous_sha256': digest(self._head) if self._head else '0' * 64,
                'checkpoint_sha256': pin, 'core_revision': payload['core']['revision'],
                'revocation_epoch': payload['revocation_epoch'],
                'governance_sha256': digest({k: payload[k] for k in
                    ('core', 'spaces', 'tombstones', 'revocation_epoch')}),
                'checkpoint_issued_at': payload['issued_at'],
                'checkpoint_expires_at': payload['expires_at']}
        require(monotonic_head(self._head, head), 'E_WITNESS_ROLLBACK')
        # Failed publication leaves pending set. No unsafe abort-to-old-head operation.
        self._head, self._pending = head, None
        return self.head

    def answer(self, nonce):
        require(hex_digest(nonce), 'E_WITNESS_NONCE')
        require(self._pending is None and self._head is not None, 'E_WITNESS_UNAVAILABLE')
        now = self.clock()
        require(parse(self._head['checkpoint_issued_at']) <= now <
                parse(self._head['checkpoint_expires_at']), 'E_EXPIRED')
        body = {'head': self.head, 'nonce': nonce, 'issued_at': stamp(now),
                'expires_at': stamp(min(now + timedelta(seconds=60),
                                      parse(self._head['checkpoint_expires_at'])))}
        return {'payload': body, 'signature': b64(self._key.sign(DOMAIN + canonical(body)))}


class WitnessReader:
    """One process's trusted high-water state; restart persistence is NOT provided."""
    def __init__(self, avatar, enrollment_sha256, generation, public_key, clock):
        self.avatar, self.enrollment_sha256 = avatar, enrollment_sha256
        self.generation, self.public_key, self.clock = generation, public_key, clock
        self._head = None
        self._challenge = None

    @property
    def head(self):
        return deepcopy(self._head)

    def challenge(self):
        self._challenge = secrets.token_hex(32)
        return self._challenge

    def verify(self, proof):
        # Every verification attempt consumes its challenge, even on failure.
        nonce, self._challenge = self._challenge, None
        require(nonce is not None, 'E_WITNESS_NONCE')
        try:
            body = proof['payload']
            Ed25519PublicKey.from_public_bytes(unb64(self.public_key)).verify(
                unb64(proof['signature']), DOMAIN + canonical(body))
        except Exception:
            raise Fault('E_INTEGRITY') from None
        require(set(body) == {'head', 'nonce', 'issued_at', 'expires_at'} and
                body['nonce'] == nonce, 'E_WITNESS_NONCE')
        now = self.clock()
        issued, expires = parse(body['issued_at']), parse(body['expires_at'])
        require(issued <= now < expires and timedelta(0) < expires-issued <=
                timedelta(seconds=60), 'E_EXPIRED')
        head = body['head']
        require(set(head) == {'profile', 'avatar_id', 'enrollment_sha256', 'generation',
                'sequence', 'previous_sha256', 'checkpoint_sha256', 'core_revision',
                'revocation_epoch', 'governance_sha256', 'checkpoint_issued_at',
                'checkpoint_expires_at'}, 'E_SCHEMA')
        require(head['profile'] == PROFILE and head['avatar_id'] == self.avatar and
                head['enrollment_sha256'] == self.enrollment_sha256 and
                head['generation'] == self.generation, 'E_IDENTITY')
        require(parse(head['checkpoint_issued_at']) <= issued and expires <=
                parse(head['checkpoint_expires_at']), 'E_EXPIRED')
        require(hex_digest(head['previous_sha256']) and monotonic_head(None, head), 'E_SCHEMA')
        if self._head:
            if head['sequence'] == self._head['sequence']:
                require(head == self._head, 'E_WITNESS_FORK')
            else:
                require(monotonic_head(self._head, head), 'E_WITNESS_ROLLBACK')
                if head['sequence'] == self._head['sequence'] + 1:
                    require(head['previous_sha256'] == digest(self._head), 'E_WITNESS_FORK')
        self._head = deepcopy(head)
        # This is a checkpoint selection result, not a reusable activation grant.
        return head['checkpoint_sha256']
