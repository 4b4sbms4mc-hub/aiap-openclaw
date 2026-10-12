<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Validation evidence and limits

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

Fresh Docker image build/Compose install from this package; restored Gateway→plugin→Core tool calls; second runtime/MCP; multi-owner isolation; secure cross-runtime transfer. Prior backup tests do not prove full AIAP secure-transfer or revocation-aware recovery compliance.

## Fresh Core Docker CI

The release workflow checks a fresh isolated Core container, candidate exclusion before approval, approved recall, and identity/memory revision across restart. Successful release assets include CI_VALIDATION.json identifying the exact commit and workflow run. This does not instantiate an OpenClaw Gateway or prove its fresh-install path.
