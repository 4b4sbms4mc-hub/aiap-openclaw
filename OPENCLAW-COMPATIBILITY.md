<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# OpenClaw Compatibility Notes

Target integration surface:
- Agent Plugins bundle format 1.0.0
- root `plugin.json`
- immediate-child `skills/<skill>/SKILL.md`
- root `mcp.json`
- stdio MCP server launched from a `./`-relative executable

The AIAP bundle does not modify or fork OpenClaw. It acts as an adapter/distribution layer.

OpenClaw native Plugin SDK APIs are intentionally not required by this package because those APIs may evolve independently. A future native adapter may be added after the bundle-based interoperability proof is stable.
