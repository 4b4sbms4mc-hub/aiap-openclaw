<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# La Vida for OpenClaw 0.3.6 — Typed memory proposals

Author: Wang Lu. This prerelease targets OpenClaw 2026.9.4 and AIAP Core Service 0.2.0.

Manual memory proposals accept an optional memory level and type. Use M1 for active work such as open tasks, blockers and labeled hypotheses. Use M2 for lasting preferences, decisions and reusable knowledge. Existing text-only calls still default to M2 and fact. The tool returns a pending proposal for independent Owner approval.

Search shows the level, type, source and confidence alongside recalled text. The manual proposal guidance is shared with AIAP Memory MCP 0.3.2. This release keeps the existing automatic capture behavior.

Validated against a temporary Core through the plugin host harness, including 16 HTTP integration checks and 15 automatic capture checks. The release workflow also verifies a fresh installation and isolated restore with the real OpenClaw Gateway.

Code, schemas and tests: Apache-2.0. Prose: CC BY 4.0. Existing trademark and third-party policies remain in force.
