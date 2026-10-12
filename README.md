<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP for OpenClaw — La Vida memory integration

**Author / Project Maintainer: Wang Lu**

AIAP is a runtime-neutral protocol for user-controlled AI state. This repository contains two separate OpenClaw integrations.

| Integration | Version | Purpose |
|---|---|---|
| La Vida native memory plugin | 0.3.4 | Scoped recall, pending proposals, independent owner approval |
| AIAP Core Service | 0.2.0 | Local identity and persistent memory state used by La Vida |
| Legacy Agent Plugins bundle | 0.3.0 | AIAP object inspection and MCP validation tools |

## First usable memory release

The experimental La Vida release is in [lavida/](lavida/README.md).
[中文说明](lavida/README_CN.md) · [Fresh installation](lavida/docs/INSTALL_CN.md) · [Validation evidence](lavida/docs/VALIDATION.md) · [Releases](https://github.com/4b4sbms4mc-hub/aiap-openclaw/releases)

The initial loop is: an authenticated owner session proposes a memory; the owner reviews and approves or rejects it outside the plugin; approved memories become searchable and survive restart. Pending/rejected candidates are not active memories.

Default entry: one owner, one fixed space per adapter binding, literal search, manual requests, automatic proposals off and background archival off. Existing optional semantic/automatic functionality is retained.

The three native tools are `aiap_memory_status`, `aiap_memory_search`, and `aiap_memory_propose`.
Tested target: OpenClaw 2026.9.4, Node 22+ with node:sqlite, Core Service 0.2.0.
The release ZIP is standalone; installing the repository root installs the legacy bundle, not the new memory plugin. Follow the La Vida guide and install its `.tgz`.

Local validation: 66 Core tests + 15 plugin integration checks + 15 automatic-candidate regression checks. Prior NAS deployment and isolated restore evidence are listed separately. GitHub CI additionally checks fresh Core Docker approval/recall and restart; see the exact commit checks and release CI_VALIDATION.json. Fresh OpenClaw installation and restored Gateway-to-Core tool calls remain pending.

Multi-member Bundle/Shared Space, organization management, secure cross-runtime transfer, a general MCP memory server and full workflow execution are future work. This release does not claim full AIAP compliance.

## Legacy v0.3.0 bundle

The existing root `plugin.json`, `mcp.json`, `bin/`, `skills/` and embedded `aiap-core/` remain the legacy protocol-validation bundle. Its MCP tools are `aiap_validate_identity`, `aiap_validate_transfer` and `aiap_inspect_avatar`; these do not provide the La Vida persistent-memory interface.
[Original installation and description](docs/legacy-v0.3.0.md).

## Protocol and licenses

The authoritative protocol repository is [ai-avatar-protocol](https://github.com/4b4sbms4mc-hub/ai-avatar-protocol).
AIAP protocol, whitepaper, Core Service, plugin and legacy-bundle versions are independent. OpenClaw is a reference integration target.

Code, schemas, examples and tests: Apache-2.0.
Whitepapers, specifications and prose documentation: CC BY 4.0.
Existing [license map](LICENSE), [open-standard policy](OPEN-STANDARD-POLICY.md), [IP policy](IP-POLICY.md) and [trademark policy](TRADEMARK.md) remain in force.
