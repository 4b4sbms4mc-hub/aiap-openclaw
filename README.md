<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP for OpenClaw — La Vida memory integration

**Author / Project Maintainer: Wang Lu**

AIAP is a runtime-neutral protocol for user-controlled AI state. This repository contains two separate OpenClaw integrations.

| Integration | Version | Purpose |
|---|---|---|
| La Vida native memory plugin | 0.3.5 source candidate (published: 0.3.4) | Scoped recall, pending proposals, independent owner approval |
| AIAP Core Service | 0.2.0 | Local identity and persistent memory state used by La Vida |
| Legacy Agent Plugins bundle | 0.3.0 | AIAP object inspection and MCP validation tools |

## First usable memory release

The experimental La Vida release is in [lavida/](lavida/README.md).
[中文说明](lavida/README_CN.md) · [Fresh installation](lavida/docs/INSTALL_CN.md) · [Validation evidence](lavida/docs/VALIDATION.md) · [Releases](https://github.com/4b4sbms4mc-hub/aiap-openclaw/releases)

The initial loop is: an authenticated owner session proposes a memory; the owner reviews and approves or rejects it outside the plugin; approved memories become searchable and survive restart. Pending/rejected candidates are not active memories.

Default entry: one owner, one fixed space per adapter binding, literal search, manual requests, automatic proposals off and background archival off. Existing optional semantic/automatic functionality is retained.

The three native tools are `aiap_memory_status`, `aiap_memory_search`, and `aiap_memory_propose`.
Tested target: OpenClaw 2026.9.4, Node 24.22.1, Core Service 0.2.0. The plugin itself needs Node 22+ with node:sqlite; the pinned host requires >=24.16.0 <25 or >=26.1.0.
The release ZIP is standalone; installing the repository root installs the legacy bundle, not the new memory plugin. Follow the La Vida guide and install its `.tgz`.

Validation: 66 Core tests + 15 plugin integration checks + 15 automatic-candidate regression checks. On 2026-11-09, real OpenClaw Gateway HTTP tests passed release-ZIP fresh installation and isolated stopped-snapshot restoration, including restored tool calls and a new approval/recall loop. A separate local [real conversation probe](lavida/docs/CONVERSATION_ACCEPTANCE_CN.md) passed with LM Studio `qwen/qwen3.5-9b`, including independent approval, cross-session recall, restore and revoked access. Prior NAS results and Core Docker CI remain separate evidence. Full Docker/NAS OpenClaw new installation remains pending; the model result is limited to the tested configuration and is not run in default CI. See [Gateway procedure and exact limits](lavida/docs/GATEWAY_ACCEPTANCE_CN.md).

The [latest protocol design drafts](https://github.com/4b4sbms4mc-hub/ai-avatar-protocol/tree/main/drafts) are versioned separately. Validation runs on relevant PR/main changes. Publishing a new tag is an explicit workflow-dispatch operation; existing 0.3.4 release assets are not overwritten by documentation or test updates.

Multi-member Bundle/Shared Space, organization management, secure cross-runtime transfer, a general MCP memory server and full workflow execution are future work. This release does not claim full AIAP compliance.

An experimental repository-only [old-snapshot recovery governance tool](lavida/docs/RECOVERY_GOVERNANCE_CN.md) applies an independently pinned current local checkpoint, excludes deleted/stale records, and revokes all old credentials. Its 22 isolated tests do not establish checkpoint freshness by themselves, production/NAS recovery or secure transfer. Core Service and plugin behavior versions are unchanged by this development helper.

A repository-only [synthetic witness experiment](lavida/docs/RECOVERY_WITNESS_CN.md) adds 16 tests for signed nonce-bound heads, pending-update blocking and in-process rollback checks. It also reproduces source-update bypass and loss of rollback memory after restart; it does not supply an independent production witness.

The [persistent reader experiment](lavida/docs/RECOVERY_HIGHWATER_CN.md) adds 16 tests for trusted local high-water storage, restart, process termination around commit and concurrent stale readers. It does not protect against rollback of the entire trusted store or enforce source-update coupling.

A local-only [source transaction gate experiment](lavida/docs/RECOVERY_SOURCE_GATE_CN.md) adds 20 tests for persisting pending before source commit, publishing checkpoints afterward, restart recovery and concurrent gated writers. Existing production Service/HTTP entry points do not use this gate; whole-store rollback and cross-device trust remain outside its guarantee.

The [renewal and control-loss review experiment](lavida/docs/RECOVERY_RENEWAL_LOSS_CN.md) adds 22 tests (96 recovery-governance total): explicit source-checked checkpoint renewal and read-only owner-review evidence after control loss. It never automatically re-enrolls a lost witness or grants activation; independent deployment inputs remain unconfirmed.

A [read-only NAS/Mac readiness collector](lavida/docs/NAS_MAC_READINESS_CN.md) fingerprints only known public code/Schema and SQLite schema metadata, with 4 privacy/read-only tests. The [availability-first recovery experiment](lavida/docs/RECOVERY_AVAILABILITY_CN.md) adds 18 tests: ordinary Core writes continue without the witness, while recovery selection requires a nonce-bound live-source observation. The 119 scripts/tests include explicit negative cases for unseen offline source rollback and changes after observation. No cross-device service is deployed.

## Legacy v0.3.0 bundle

The existing root `plugin.json`, `mcp.json`, `bin/`, `skills/` and embedded `aiap-core/` remain the legacy protocol-validation bundle. Its MCP tools are `aiap_validate_identity`, `aiap_validate_transfer` and `aiap_inspect_avatar`; these do not provide the La Vida persistent-memory interface.
[Original installation and description](docs/legacy-v0.3.0.md).

## Protocol and licenses

The authoritative protocol repository is [ai-avatar-protocol](https://github.com/4b4sbms4mc-hub/ai-avatar-protocol).
AIAP protocol, whitepaper, Core Service, plugin and legacy-bundle versions are independent. OpenClaw is a reference integration target.

Code, schemas, examples and tests: Apache-2.0.
Whitepapers, specifications and prose documentation: CC BY 4.0.
Existing [license map](LICENSE), [open-standard policy](OPEN-STANDARD-POLICY.md), [IP policy](IP-POLICY.md) and [trademark policy](TRADEMARK.md) remain in force.
