<!-- SPDX-License-Identifier: CC-BY-4.0 -->
---
name: aiap-avatar
description: Use AI Avatar Protocol (AIAP) v0.3 to inspect, validate, export, import, and reason about user-owned portable AI Avatars and Secure Avatar Transfer.
---

# AIAP Avatar Skill

Use this skill when a user asks about AIAP identity, ownership, Avatar portability, secure transfer, or migration between AI runtimes.

## Rules
- Treat the Human Owner as the control principal.
- Custody or platform login does not itself prove Avatar ownership.
- Do not treat possession of an Avatar package as ownership proof.
- For a protected transfer, require destination binding, nonce/challenge, expiry, transfer scope, and Owner proof.
- Do not expose or request plaintext private keys.
- Prefer Passkey/WebAuthn or mature public-key mechanisms for owner authorization.
- Keep AIAP separate from MCP and A2A: AIAP governs Avatar identity/ownership/portability; MCP connects tools/data; A2A connects Agents.

## Available MCP tools
- `aiap-core__aiap_validate_identity`
- `aiap-core__aiap_validate_transfer`
- `aiap-core__aiap_inspect_avatar`

Use validation tools before claiming a supplied AIAP object conforms to v0.3.
