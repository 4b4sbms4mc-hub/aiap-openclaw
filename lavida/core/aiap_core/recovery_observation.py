# SPDX-License-Identifier: Apache-2.0
"""Offline verifier for the Avatar v2 live-source observation format."""
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import Fault, canonical, digest, require, unb64
from .service import parse


OBS_DOMAIN = b'AIAP-LIVE-SOURCE-OBSERVATION-v2\x00'
OBS_PROFILE = 'x-aiap-live-source-observation-v2'


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
