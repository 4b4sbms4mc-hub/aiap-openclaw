<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Ownership Specification v0.3

> Status: AIAP Core v0.3 — normative draft
> Author: Wang Lu
> Normative terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as requirements.


## 1. Scope
This specification defines how control of an AI Avatar is established, proven, delegated, rotated, revoked, and recovered.

## 2. Ownership model
`Human Owner -> Owner Key -> Avatar Identity`

The Owner is the control principal. A Custodian/Runtime hosts or executes the Avatar but does not acquire ownership through custody.

## 3. Ownership proof
A protected ownership operation MUST include a signature verifiable against an active Owner verification key registered in the Avatar Identity Record.

The signed payload MUST bind:
- operation type
- `avatar_id`
- `owner_id`
- intended audience/destination where applicable
- challenge/nonce
- issued time
- expiry
- operation-specific scope

## 4. User presence and consent
For interactive high-impact operations, implementations SHOULD use a phishing-resistant public-key authentication mechanism such as Passkey/WebAuthn. User-facing software MUST display the target Avatar, destination, requested scope, and material consequences before authorization.

## 5. Delegation
Delegated control MAY be supported by extensions. Delegation MUST be scope-limited and MUST NOT silently become full ownership.

## 6. Ownership continuity
A change of platform, model, runtime, or custodian MUST NOT change `avatar_id` or `owner_id` unless the Owner explicitly creates a new Avatar identity.

## 7. Prohibited shortcuts
Implementations MUST NOT treat any of the following alone as proof of ownership:
- possession of `avatar.aiap`
- possession of exported Memory/Profile data
- login to a hosting platform
- knowledge of an Avatar display name
- a copied Transfer Certificate whose nonce has already been consumed

## 8. Revocation and audit
Ownership-sensitive operations MUST be auditable. Revoked Owner keys MUST NOT authorize new operations after the effective revocation time.
