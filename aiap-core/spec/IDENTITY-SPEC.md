<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP Identity Specification v0.3

> Status: AIAP Core v0.3 — normative draft
> Author: Wang Lu
> Normative terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as requirements.


## 1. Scope
This specification defines the stable identity object for an AI Avatar and its Owner. AIAP separates Human Identity, Owner Identity, Avatar Identity, and Custodian/Runtime identity.

## 2. Core principles
1. An Avatar MUST have a globally unique `avatar_id`.
2. An Owner MUST be represented by an `owner_id`.
3. Ownership MUST be proven cryptographically; possession of an Avatar package is not proof of ownership.
4. Owner identity and real-world identity MUST remain logically separable.
5. A hosting platform MUST NOT infer ownership merely from platform-account control.
6. Avatar identity MUST survive a change of model or runtime.

## 3. Identifier syntax
- Avatar ID: `aiap:avatar:<opaque-id>`
- Owner ID: `aiap:owner:<opaque-id>`
- Key ID: implementation-defined URI or stable opaque identifier.
Identifiers MUST NOT embed unnecessary PII.

## 4. Identity Record
Required fields:
- `schema_version`
- `avatar_id`
- `owner`
- `avatar_key`
- `status`
- `created_at`
- `updated_at`

`owner` contains `owner_id`, `identity_assurance`, and one or more owner verification keys.
`avatar_key` contains one or more public keys used by the Avatar for authentication/signing/encryption.

## 5. Identity assurance
`identity_assurance` is one of:
- `anonymous`
- `verified`
- `high_assurance`

AIAP Core does not prescribe KYC. OIDC, Verifiable Credentials, KYC, or equivalent systems MAY be used as extensions.

## 6. Status
Avatar status is one of `active`, `suspended`, `revoked`, `transferred`.
A revoked Avatar MUST NOT initiate a new protected transfer.

## 7. Privacy
Identity Records SHOULD minimize PII. Display names, email addresses, phone numbers, government identifiers, and biometric data are not Core requirements.

## 8. Conformance
A conforming implementation MUST validate Identity Records against `schemas/identity.schema.json` and MUST preserve unknown extension namespaces when safely possible.
