<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AI Avatar Protocol (AIAP) Core Specification v0.3

Status: Normative Draft  
Author / Project Maintainer: Wang Lu

## Core objects
AIAP v0.3 defines the following portable Core objects:

- Avatar Manifest
- Identity Record
- Owner / Ownership Proof
- Public Key Set
- Profile
- Memory Entry
- Permission Grant
- Session
- Artifact
- Extension Manifest
- Transfer Certificate

## Core invariants
1. The user is the control principal for a user-owned Avatar.
2. Custody does not imply ownership.
3. Avatar identity is independent of any single model or runtime.
4. Protected ownership operations require cryptographic authorization.
5. Secure Avatar Transfer is authorization plus data portability, not file copying.
6. Unknown extensions must not redefine Core semantics.
7. Implementations should follow data minimization and least privilege.

## Formal schemas
All machine-readable schemas are under `schemas/` and use JSON Schema Draft 2020-12.

## Security profile
See:
- `IDENTITY-SPEC.md`
- `OWNERSHIP-SPEC.md`
- `TRANSFER-SPEC.md`
- `KEY-MANAGEMENT.md`
