<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Validation evidence and limits

## Read-only NAS/Mac readiness collector (2026-11-09)

The collector and literal SQLite-prefix regressions bring scripts/tests coverage to 101 (97 recovery governance + 4 metadata privacy/read-only tests). Internal objects are excluded by a literal sqlite_ prefix; lookalike custom tables are included in fingerprints and refused by recovery/reader schema checks. Known public files only are fingerprinted; synthetic source files remain unchanged, application markers/tokens are absent, missing DBs are not created and symlinks are refused. Actual deployment paths and reports remain private. No cross-device service or production modification is claimed. [Collector and readiness boundaries](NAS_MAC_READINESS_CN.md).

## Checkpoint renewal and control-loss review (2026-11-09)

Ten renewal and twelve read-only review tests bring recovery-governance coverage to 96. Expired checkpoint renewal preserves source bytes and grants; strict sequence contention and child SIGKILL boundaries pass. Loss reports compare signed source snapshots with independently retained reader heads but never re-enroll or authorize activation. [Contracts, limits and deployment decisions](RECOVERY_RENEWAL_LOSS_CN.md).

## Local source transaction gate experiment (2026-11-09)

Twenty source-gate tests bring recovery governance coverage to 74. Actual source transactions, persistent pending/head/key, four child SIGKILL boundaries, two-process writers and a durable-reader-to-isolated-restore flow pass. Production Service/HTTP are unchanged; whole source/control rollback and post-proof races from bypass writers remain explicit limits. [Ordering and failure semantics](RECOVERY_SOURCE_GATE_CN.md).

## Persistent reader high-water experiment (2026-11-09)

Sixteen additional tests bring recovery/witness/high-water coverage to 54. Actual child-process restart, SIGKILL before/after SQLite commit and concurrent stale-reader serialization pass. Stored signed heads survive normal restarts; an explicit whole-store rollback negative test remains. This is trusted local reader storage, not durable witness storage or production freshness. [Contract and limits](RECOVERY_HIGHWATER_CN.md).

## Synthetic witness state machine (2026-11-09)

Sixteen in-memory witness tests plus the 22 recovery tests pass (38 total), using real Ed25519 signatures and a checkpoint-to-isolated-restore flow. Two explicit negative tests demonstrate source-update bypass and rollback after reader-state loss; this is not a durable independent witness or activation service. [Behavior, reproduction and remaining trust gaps](RECOVERY_WITNESS_CN.md).

## Experimental old-snapshot governance (2026-11-09)

Twenty-two local development tests passed for `scripts/recovery_guard.py`, including a real CLI restore followed by a new HTTP Core process. Current pinned checkpoint tombstones and exact record manifests exclude deleted/stale data; all old grants are revoked and fresh credentials are required. Source snapshots remain unchanged. Catchable failures clean staging; SIGKILL before publication leaves private residue and an empty reservation, while SIGKILL after rename leaves a complete target. No power-loss durability claim is made. A within-TTL stale-checkpoint negative test demonstrates that signatures and pins do not detect subsequent source deletion. [Trust assumptions, bounds and reproduction](RECOVERY_GOVERNANCE_CN.md). This helper is not a production Core API or remote transfer implementation; the operator must independently establish current checkpoint freshness.

## Real Gateway fresh install and isolated restore (2026-11-09)

Codex executed `scripts/check_openclaw_gateway.py` with the packaged release ZIP, official OpenClaw 2026.9.4, Node 24.22.1 and Python 3.12.14 on macOS. Real Gateway HTTP tools exercised archive installation, pending/approved/rejected handling, fixed-space isolation, wrong-token/unbound-session rejection, stopped-snapshot checksums/SQLite integrity, original-state isolation, restored identity/memory/revision/local-signature continuity, and a new proposal/approval/recall after restore. Generated private state and processes were removed.

This is authenticated `/tools/invoke` evidence, not model-selected conversational tool use or Docker/NAS OpenClaw installation evidence. [Procedure and limits](GATEWAY_ACCEPTANCE_CN.md). Core's existing 66 tests, 15 HTTP integration checks and 15 automatic regression checks also passed again. Historical results below retain their original scope.

## Real local-model conversation probe (2026-11-09)

The optional `--conversation-model` probe also passed with actual LM Studio `qwen/qwen3.5-9b` in OpenClaw, without client tools, forced tool choice or mocked model outputs. It checks a model-generated pending candidate, independent Owner approval, new-session recall of a random answer absent from the question, denied controls, restored new-session recall, and explicit access-unavailable behavior after adapter revocation. [Configuration, reproducible steps and limits](CONVERSATION_ACCEPTANCE_CN.md). Default CI does not claim to execute this local model; the machine-readable local report is in the repository's root `validation/` directory.

## Existing deployment evidence (user-executed NAS tests, 2026-10-12)

- Core 0.2.0 / La Vida 0.3.4 / OpenClaw 2026.9.4.
- Three real plugin tools; candidate excluded before owner approval; approved recall and rejection behavior.
- Original preference remained the same memory identifier / revision 1 across restart.
- Main automatic capture and explicitly bound dashboard behavior tested separately; dashboard automatic proposals remained disabled.
- Three backup files passed SHA256 verification; restored SQLite integrity check returned ok.
- Isolated Core restored identity, local signatures/private-key correspondence, original approved record and rejected marker exclusion.
- Actual restored plugin inspection: loaded 0.3.4, two hooks and three tools, zero diagnostics.
- Isolated Gateway: /healthz=200, /readyz=200. Startup required setting gateway.mode=local in the run copy; original backup unchanged.
- Temporary containers removed; production Core and OpenClaw running/healthy.

## Local candidate validation

Executed 2026-10-12 with Python 3.12 and Node 22+:

- Core: 66 tests passed (service, process restart, semantic-provider mock coverage).
- Plugin integration: 15 checks passed against an actual temporary Core HTTP server and a simulated OpenClaw registration host.
- Automatic proposals: 15 regression checks passed against an actual temporary Core and simulated host events.
- Complete Core and plugin source bytes match the delivered 0.2.0 / 0.3.4 sources.

Logs: validation/core.log, validation/integration.log, validation/automatic.log. Tests used already-installed local Python dependencies at the versions in core/requirements.txt; dependency download / fresh virtualenv installation was not rerun.

To reproduce, install core/requirements.txt into a virtualenv, then run from the release root:

```sh
(cd core && ../.venv/bin/python -m unittest discover -s tests -v)
PYTHONPATH=core AIAP_TEST_PYTHON="$PWD/.venv/bin/python" node plugin-tests/integration.mjs
PYTHONPATH=core AIAP_TEST_PYTHON="$PWD/.venv/bin/python" node plugin-tests/automatic.mjs
```

Other retained host-contract/canonical-source tests require matching official OpenClaw source files supplied through OPENCLAW_HOOK_SOURCE, OPENCLAW_RUNTIME_SOURCE and OPENCLAW_MESSAGE_SOURCE. They were not rerun for this packaging candidate. The upgrade-only deployment test is omitted because the upgrade manager is not a fresh-install entry.

Core code and plugin source are copied without functional edits. This is release packaging, not a new runtime version.

## Not verified by those results

At the original packaging date: fresh Docker image build/Compose install from this package; restored Gateway→plugin→Core tool calls; second runtime/MCP; multi-owner isolation; secure cross-runtime transfer. Later Docker CI and the real Gateway HTTP validation above address their stated subsets. Prior backup tests do not prove full AIAP secure-transfer or revocation-aware recovery compliance.

## Fresh Core Docker CI

The release workflow checks a fresh isolated Core container, candidate exclusion before approval, approved recall, and identity/memory revision across restart. Successful release assets include CI_VALIDATION.json identifying the exact commit and workflow run. This does not instantiate an OpenClaw Gateway or prove its fresh-install path.
