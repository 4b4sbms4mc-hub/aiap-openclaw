<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AIAP first usable release — La Vida for OpenClaw

Author: Wang Lu. **Experimental first usable release.**

A local, single-owner memory service and OpenClaw adapter. Keep approved memories in an AIAP Core on your own machine, give the assistant a scoped credential, and require independent owner approval before a proposal becomes active memory.

[中文说明](README_CN.md) · [Fresh installation](docs/INSTALL_CN.md) · [Release notes](docs/RELEASE_NOTES.md) · [Validation](docs/VALIDATION.md) · [License scope](LICENSE_SCOPE.md)

| Component | Version |
|---|---|
| AIAP whitepaper reference | 0.4.2 draft |
| Core Service | 0.2.0 |
| La Vida for OpenClaw | 0.3.4 |
| Tested OpenClaw runtime | 2026.9.4 |

Versions are independent. This release is a subset, not full AIAP compliance.

## First-release scope

- Persistent local Avatar identity and SQLite memories.
- Three fixed spaces: general, life and work. Each adapter binding has one scoped credential.
- Three tools: `aiap_memory_status`, `aiap_memory_search`, `aiap_memory_propose`.
- Proposal → owner review → approve/reject → recall; pending/rejected candidates are excluded from active recall.
- Trusted host identity, fixed agent/session binding, expiry and revocation checks.
- Stable memory identity and revision across restart.

The entry configuration uses literal search, disables automatic proposals, and disables background archival. Existing optional semantic and automatic-proposal code is retained unchanged; these features need explicit configuration and separate validation.

## Start the Core locally

Python 3.12 is the reference environment. From this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r core/requirements.txt
(cd core && ../.venv/bin/python -m aiap_core --data-dir ../data init)
(cd core && ../.venv/bin/python -m aiap_core --data-dir ../data serve --archive-interval 0)
```

Run each command separately. Initialization generates private credentials and keys; never upload the `data/` directory. The HTTP listener defaults to loopback. Windows uses `.venv\Scripts\python.exe`.

For Docker and OpenClaw, follow the Chinese installation guide. The included Compose uses a new project/volume, loopback port 8043 and a private network. It does not restore or upgrade the user's existing deployment.

## Roadmap

MCP and a second runtime; secure transfer and replay prevention; multi-member Bundle and Shared Space; organization management; workflow/capability execution. These are future work, not claims about this candidate.

## Licensing

Code, schemas and tests: Apache-2.0. Prose documentation: CC BY 4.0. Author: Wang Lu. Existing trademark policy is retained. See LICENSE_SCOPE.md and the included license texts. The npm private flag only prevents registry publication.
