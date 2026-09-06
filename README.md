<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP v0.3 for OpenClaw

> **Public Release v0.3.0** — AIAP is intended as an open interoperability standard. Independent open-source and proprietary implementations are permitted under the repository license map. See `OPEN-STANDARD-POLICY.md`, `GOVERNANCE.md`, `LICENSE`, `IP-POLICY.md`, and `TRADEMARK.md`.


**Author / Project Maintainer: Wang Lu**

This is the OpenClaw-compatible distribution of AI Avatar Protocol v0.3.

It is packaged as an **Agent Plugins 1.0.0 bundle**, which OpenClaw can map into:
- a workspace-compatible AIAP Skill
- an MCP stdio server exposing AIAP validation/inspection tools
- the complete AIAP v0.3 Core specifications, Schemas, examples, reference code, and English Whitepaper

## Install

From the unpacked directory:

```bash
openclaw plugins install .
openclaw plugins list
openclaw plugins inspect aiap-avatar
openclaw gateway restart
```

OpenClaw should detect the root `plugin.json` as an Agent Plugins bundle.

## Included AIAP MCP tools
- `aiap_validate_identity`
- `aiap_validate_transfer`
- `aiap_inspect_avatar`

OpenClaw exposes bundle MCP tools with a server-name prefix.

## Design choice

This distribution intentionally uses the portable Agent Plugins bundle format instead of a native in-process OpenClaw plugin. The bundle has a narrower trust boundary and avoids depending on experimental OpenClaw native Plugin SDK APIs.

## Requirements
- OpenClaw version supporting Agent Plugins bundles and bundle MCP stdio tools
- Python 3 available on PATH for the included zero-dependency MCP validator

## Full protocol
The complete standalone AIAP repository is embedded under `aiap-core/`.