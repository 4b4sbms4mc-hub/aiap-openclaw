<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Key Management Specification v0.3

> Status: AIAP Core v0.3 — normative draft
> Author: Wang Lu
> Normative terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as requirements.


## 1. Scope
This specification defines Owner keys, Avatar keys, lifecycle rules, rotation, revocation, and recovery.

## 2. Key classes
### Owner Verification Key
Proves authorization by the Owner. It MUST NOT be exported as plaintext private-key material by a conforming user-facing implementation.

### Avatar Key
Represents the Avatar object for authentication, signing, or encryption. Avatar keys MUST be logically distinct from Owner keys.

## 3. Algorithms
Core v0.3 supports:
- `Ed25519` — RECOMMENDED for general AIAP signatures.
- `ES256` — supported for interoperable platform/WebAuthn environments.
- `RS256` — permitted for compatibility, but SHOULD NOT be chosen for new lightweight implementations when Ed25519 or ES256 is available.

Implementations MUST reject algorithms they do not explicitly support. Algorithm identifiers MUST NOT be inferred from key material.

## 4. Public-key representation
AIAP v0.3 uses JWK-compatible public key objects:
- OKP/Ed25519: `kty`, `crv`, `x`, `kid`
- EC/P-256: `kty`, `crv`, `x`, `y`, `kid`
- RSA: `kty`, `n`, `e`, `kid`

Private key parameters MUST NOT appear in portable Identity Records.

## 5. Key lifecycle
Key status is `active`, `rotated`, or `revoked`.
Every key SHOULD include `created_at`; revoked keys MUST include `revoked_at`.
New protected operations MUST use an active key.

## 6. Rotation
Rotation MUST:
1. authenticate using an existing active Owner key or an approved recovery process;
2. register the replacement key;
3. assign a new `kid`;
4. record effective timestamps;
5. preserve sufficient historical public-key metadata to verify past audit records.

## 7. Revocation
Revocation MUST prevent future authorization. Implementations SHOULD propagate revocation quickly to custodians that host the Avatar.

## 8. Recovery
Recovery MAY use:
- a recovery credential;
- multiple registered Owner keys;
- threshold recovery;
- a high-assurance external identity extension.

Recovery MUST NOT silently replace the Owner. Recovery events MUST be auditable and SHOULD trigger user notification.

## 9. WebAuthn/Passkeys
WebAuthn/Passkeys SHOULD be used as a user-friendly owner-authentication mechanism. AIAP does not redefine WebAuthn credential ceremonies. An adapter MUST bind the WebAuthn assertion/challenge to the AIAP operation being authorized.

## 10. Storage
Private keys SHOULD be held in platform authenticators, secure hardware, OS key stores, or equivalent protected storage. Servers MUST NOT log private keys or raw authenticator secrets.
