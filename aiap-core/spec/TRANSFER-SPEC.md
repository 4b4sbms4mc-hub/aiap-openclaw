<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Secure Avatar Transfer Specification v0.3

> Status: AIAP Core v0.3 — normative draft
> Author: Wang Lu
> Normative terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as requirements.


## 1. Scope
This specification defines secure transfer of an Avatar between custodians/runtimes.

## 2. Security objective
Transfer is an authorization protocol, not file copying. The authorization MUST bind the Avatar, Owner, source, destination, transfer scope, nonce, issue time, expiry, and cryptographic proof.

## 3. Roles
- Owner: authorizes transfer.
- Source: current custodian/runtime.
- Destination: intended receiving custodian/runtime.
- Avatar: transferred logical identity and selected state.

## 4. Protocol flow
1. Destination creates an unpredictable challenge and transfer nonce.
2. Source constructs a transfer intent and presents the destination and scope to the Owner.
3. Owner authorizes the intent with an active Owner key.
4. Source produces a Transfer Certificate.
5. Destination validates schema, signature, key status, `avatar_id`, `owner_id`, source, destination, nonce, time window, scope, and certificate status.
6. Destination imports only the authorized scope.
7. On success, the certificate MUST transition to `consumed`.
8. A consumed, expired, or revoked certificate MUST be rejected.

## 5. Transfer modes
- `full`: transfer all portable Core data permitted by policy.
- `selective`: transfer only explicitly selected categories.
- `copy`: create an authorized copy while the source remains active. Copy semantics MUST NOT imply ownership duplication beyond the same Owner.

## 6. Certificate canonicalization and signing
The unsigned certificate payload MUST be canonicalized using RFC 8785 JSON Canonicalization Scheme (JCS) before signing.
The `proof.signature` MUST NOT be included in the bytes being signed.
The domain-separation prefix is the UTF-8 string:

`AIAP-TRANSFER-V0.3\n`

The signed bytes are:
`prefix || JCS(unsigned_certificate)`

## 7. Replay protection
- `nonce` MUST contain at least 128 bits of unpredictability.
- `expires_at` MUST be later than `issued_at`.
- Implementations SHOULD use short-lived certificates; 10 minutes is RECOMMENDED for interactive transfers.
- `single_use` MUST be true for ownership-preserving transfer.
- Destination MUST persist consumed certificate IDs/nonces for at least the certificate validity period plus an implementation-defined replay window.

## 8. Verification order
Destination MUST:
1. parse without duplicate JSON member names;
2. validate the JSON Schema;
3. verify destination binding;
4. verify time window;
5. verify nonce/challenge;
6. resolve the active Owner verification key;
7. verify the signature;
8. verify Avatar and Owner status;
9. enforce transfer scope;
10. atomically consume the certificate after successful import.

## 9. Failure behavior
Any failed mandatory check MUST reject the protected import. Implementations SHOULD return machine-readable error codes without exposing sensitive key or account information.

## 10. Privacy
The certificate SHOULD contain pseudonymous identifiers and MUST NOT require unnecessary PII. Sensitive Avatar data SHOULD be encrypted separately; the certificate proves authorization but is not the data-encryption container.
