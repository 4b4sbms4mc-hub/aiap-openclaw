<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# La Vida for OpenClaw 0.3.5 — Manual proposal guidance

Author: Wang Lu. Experimental source candidate; the existing published 0.3.4 tag/assets are preserved. Core Service remains 0.2.0; OpenClaw target remains 2026.9.4. Protocol and runtime versions are independent.

## Behavior change

A Chinese conversation probe exposed confusion between disabled automatic capture and the manual proposal tool. The plugin now explicitly instructs the model to submit a pending candidate for an explicit remember request even when automatic proposals are off, explain actual pending status, and never invent an approval command. Independent Owner review is still required before active recall. No identity, scope or approval checks are relaxed.

Search guidance now matches the default literal-substring backend: use an exact project identifier or short keyword and shorten a zero-hit query rather than appending the whole question or translated words. The optional local-model test presents the three tool schemas directly with the host's documented `tools.toolSearch: false`; default dynamic-directory behavior is not certified by this result.

## Validation

Real local-model probes use LM Studio `qwen/qwen3.5-9b` through the normal OpenClaw agent path, with no forced tool choice or mocked model output. They check model-created candidates, independent approval, random-code recall in new conversations before/after isolated restore, denied controls and unavailable-access reporting after revocation. Results are model/configuration specific; see [procedure and failure history](CONVERSATION_ACCEPTANCE_CN.md). Default CI does not run this local model.

CI reruns 66 Core tests, 15 plugin integration checks and 15 automatic-candidate checks; real Gateway release installation/restore; a network-isolated Docker fixture containing real Gateway/Core processes; and the separate Compose Core tests. The Docker fixture is synthetic and does not prove the user's existing NAS, separate-container production topology or model inference in Docker.

Release ZIPs are reproducible. `scripts/build_plugin.py` rebuilds the matching plugin archive from its reviewed source. CI packaging requires Gateway evidence for the exact commit, plugin/Core versions and tested source ZIP. Publishing a new prerelease remains an explicit workflow-dispatch operation; old tags are never overwritten.

## Boundaries and licenses

Automatic capture, semantic retrieval and background archival remain disabled by default. This is not complete AIAP compliance, multi-owner, MCP memory-server, secure-transfer, workflow-execution or historical revocation-aware recovery certification. No personal databases, keys, credentials or NAS backups are included.

Code, schemas and tests: Apache-2.0. Prose: CC BY 4.0. Existing trademark and third-party policies remain in force.
