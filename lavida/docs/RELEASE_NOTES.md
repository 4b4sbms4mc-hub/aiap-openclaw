<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# La Vida for OpenClaw 0.3.4 — First Usable Memory Release

Author: Wang Lu. Experimental prerelease.

Core Service 0.2.0 + native La Vida plugin 0.3.4, targeting OpenClaw 2026.9.4. Versions are independent from the AIAP protocol/whitepaper versions.

## Usable memory loop

Local persistent Avatar identity and SQLite state; one-space adapter credentials; trusted owner/session checks; aiap_memory_status, aiap_memory_search and aiap_memory_propose; candidate → independent owner review → approve/reject → recall; pending/rejected candidates excluded; identity and memory revision survive restart.

The default entry disables automatic proposals, semantic retrieval and background archival. Existing optional implementations are retained. No personal databases, memories, credentials, keys or NAS backups are included.

## Validation

Local: 66 Core tests, 15 plugin HTTP integration checks and 15 automatic-candidate checks passed. Plugin host registration and automatic events in these tests are simulated.

Prior NAS deployment: actual plugin load/tool calls, scoped hybrid search, acceptance/rejection and restart persistence; backup checksums; isolated Core identity/signature/memory restoration; isolated plugin load; Gateway health and readiness HTTP 200.

GitHub CI runs the same automated suites and fresh Core Docker initialization, owner approval/recall and restart checks. CI_VALIDATION.json in the downloadable ZIP records successful CI execution and its commit/run URL. The newly packaged OpenClaw installation path and restored Gateway→La Vida→Core tool-call chain remain to be tested.

## Boundaries

This is not a full AIAP compliance, multi-owner, MCP memory server, secure-transfer or workflow-execution release. The earlier v0.3.0 bundle/MCP validation tools remain available separately. Existing data is not migrated automatically.

## License

Code, schemas and tests: Apache-2.0. Documentation: CC BY 4.0. Existing trademark policy remains. Runtime behavior is unchanged; release metadata, license notices, installation documentation and packaging are updated.
