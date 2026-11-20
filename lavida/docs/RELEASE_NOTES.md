<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# La Vida for OpenClaw 0.3.7 — Checked memory proposals

Author: Wang Lu. Tested host target is OpenClaw 2026.9.4. The recommended Core version is 0.2.2.

Manual proposals use Core candidate admission when advertised. Approval stays with the Owner. Related candidates can be compared with existing records, submitted as an explicit correction, or submitted as a separate entry when the user requests it. On older Core versions, ordinary proposals retain their existing behavior.

Opt-in automatic candidates use the same admission rules. Exact duplicates and entries that need review against an existing record do not add a pending candidate. Scope and authenticated Owner-session checks still apply.

The plugin regression suite exercises 18 HTTP integration checks and 17 automatic-candidate checks with a temporary Core. The release workflow also verifies fresh installation and isolated restore through the real OpenClaw Gateway.

Code, schemas and tests are Apache-2.0. Prose is CC BY 4.0. Existing trademark and third-party policies remain in force.
