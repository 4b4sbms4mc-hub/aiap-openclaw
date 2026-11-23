<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AI Avatar Protocol (AIAP) v0.3

**Author / Project Maintainer: Wang Lu**

AIAP is an open protocol for user-owned, verifiable, portable, and extensible personal AI Avatars.

## This release contains
- English Whitepaper v0.3 (`WHITEPAPER.md` and DOCX)
- Normative Identity / Ownership / Transfer / Key Management specifications
- JSON Schema Draft 2020-12 schemas for Core objects
- Python reference validator and Transfer Certificate signing helpers
- examples and tests

## Quick start

```bash
python -m venv .venv
# activate the virtual environment
pip install -e .[dev]
aiap validate identity examples/identity.json
pytest
```

## Memory MCP (stdio)

### Fresh DSH installation with a local Core

Download both wheels and `SHA256SUMS-MCP.txt` from [AIAP Memory MCP 0.3.8](https://github.com/4b4sbms4mc-hub/aiap-openclaw/releases/tag/aiap-mcp-v0.3.8). Use Python 3.12 and run the commands from the download directory.

On macOS and Linux:

```sh
shasum -a 256 -c SHA256SUMS-MCP.txt
VENV="$HOME/.local/share/aiap-dsh/venv"
DATA="$HOME/.local/share/aiap-dsh/core"
python3.12 -m venv "$VENV"
"$VENV/bin/python" -m pip install ./aiap_core_service-0.2.4-py3-none-any.whl './aiap_reference-0.3.8-py3-none-any.whl[mcp]'
"$VENV/bin/python" -m aiap_core --data-dir "$DATA" init
"$VENV/bin/python" -m aiap_core --data-dir "$DATA" grant --spaces space:general \
  --purpose aiap-memory --runtime deepseek-harness --output "$DATA/adapter.json"
```

On Windows, use PowerShell and keep the Core in your Windows profile:

```powershell
$Venv = Join-Path $env:LOCALAPPDATA 'AIAP\venv'
$Data = Join-Path $env:LOCALAPPDATA 'AIAP\core'
py -3.12 -m venv $Venv
$Python = Join-Path $Venv 'Scripts\python.exe'
& $Python -m pip install .\aiap_core_service-0.2.4-py3-none-any.whl '.\aiap_reference-0.3.8-py3-none-any.whl[mcp]'
& $Python -m aiap_core --data-dir $Data init
& $Python -m aiap_core --data-dir $Data grant --spaces space:general --purpose aiap-memory --runtime deepseek-harness --output (Join-Path $Data 'adapter.json')
```

Copy the Avatar ID printed by `init`. In the DSH profile patch below, set `command` to the absolute path of the new environment's `bin/aiap` or `Scripts\aiap.exe` on Windows. In YAML, use single quotes around Windows paths containing backslashes. Replace `--base-url` and its value with `--data-dir` and the absolute Core directory. Use the new Avatar ID and `adapter.json` in the remaining arguments. DSH launches the MCP process, which opens the local SQLite database. Start by calling `aiap_memory_status` in DSH to check the binding.

When the MCP tool returns a pending proposal ID, review and decide from the Owner terminal. Replace `DELTA_ID` with the returned ID.

```sh
"$VENV/bin/python" -m aiap_core --data-dir "$DATA" review --local \
  --credential-file "$DATA/owner-credentials.json" --delta-id DELTA_ID
"$VENV/bin/python" -m aiap_core --data-dir "$DATA" decide --local \
  --credential-file "$DATA/owner-credentials.json" --delta-id DELTA_ID --approve
```

Keep the Owner credential separate from the DSH profile. The adapter grant expires after seven days by default. To renew, run `grant` again with a new output file, then update the credential path in DSH.

For Owner commands in Windows PowerShell, use `& $Python` as the executable and `$Data` as the data directory. For an existing local installation, install both new wheels and reuse the same Core data directory and credential files.

#### macOS system embeddings

On macOS, install the Core wheel with the optional bridge using `"$VENV/bin/python" -m pip install './aiap_core_service-0.2.4-py3-none-any.whl[system-embedding]'`.
On macOS 14 or later, add `--system-embedding-language zh-Hans` to the local MCP server arguments, or set `AIAP_SYSTEM_EMBED_LANG=zh-Hans` and `AIAP_EMBED_SPACES=space:general` on a standalone Core server. Use the locale that best matches the indexed space. An explicit HTTP embedding endpoint takes precedence in the standalone server.

Run `aiap embedding status --language zh-Hans` to check whether the system model is available. If Apple reports missing assets, the MCP status and degraded search include the command `aiap embedding download --language zh-Hans`. This command asks macOS to download its own assets. Searches use offline BM25 while the system model is unavailable.

The active model and revision identify the vector representation. The backend pools token vectors and normalizes the result locally. All vectors in a query use the configured language and model. Use separate retrieval configurations for separate language groups when needed. System embeddings currently support the macOS runtime. On other platforms, use offline BM25 or the supported HTTP embedding configuration.

To enable hybrid semantic retrieval in local mode, add `--embedding-url http://127.0.0.1:1234 --embedding-model qwen3-embedding-0.6b` to the MCP command arguments, with the origin and model ID from your trusted local OpenAI-compatible embedding server. The server receives the query and approved memory text from the adapter's authorized space. Use `--embedding-dimensions` if the model's vector size differs from 1024. Search results report `retrieval`, `embedding_model` and any `semantic_unavailable` reason. With embeddings disabled or unavailable, Core prioritizes exact substrings and ranks additional matches with SQLite FTS5 BM25 over Chinese character pairs and word tokens. The in-memory index is built from eligible records in the authorized space for the current query. SQLite builds without FTS5 retain exact substring matching.

Search reports the actual retrieval method for the request. On a Core with retrieval diagnostics, `retrieval_reason` distinguishes `hybrid-ranked`, `embedding-not-configured`, `scope-not-enabled`, `empty-query`, `no-eligible-records`, and `embedding-unavailable`. A provider failure sets `degraded` to true and supplies its error code in `semantic_unavailable`. When an older Core omits a diagnostic, MCP returns null for that field.

### Browse approved memories

To suggest archiving a memory, call `aiap_memory_propose_archive` with its ID, current revision, and reason. The Owner reviews the request and decides through the local Core CLI. After approval, the memory appears under M3.

After submission, call `aiap_memory_proposal_status` with the returned `delta_id`. The issuing adapter can see `proposed`, `accepted`, `rejected`, or `invalidated` in its bound space. An unknown or inaccessible ID returns `not-found`; a preview creates no submission. Owner decisions use the existing local review and decide commands.

Search results expose the source reference, proposal-reported confidence, creation and update timestamps, last verification and last recorded use. A missing timestamp is null. MCP-created inferred proposals default to 0.5. This value is supplied by the proposal; it is not a calibrated probability. Core's verification time records Owner approval or verification of the record, not independent verification of its source.

Call `aiap_memory_list` to browse the bound space without a query. Use `level` (M1/M2 by default, M3 explicitly), `memory_type`, `updated_from` (inclusive), and `updated_before` (exclusive). Times require an offset. Pass `next_after` as `after` with the same filters until it is null. Results contain up to 240 characters of text per memory. Each page reflects current authorizations and records; newly matching IDs before the cursor appear on a fresh traversal. Check `memory_browse` in status for Core support.

### Candidate preflight

Use the read-only MCP tool `aiap_memory_preview` to check a new candidate in the bound space before submission. It returns the requested classification and the Core admission decision, including visible duplicate or revision matches. On older Core versions it reports `E_PROPOSAL_PREVIEW_UNSUPPORTED`.

Before submitting a candidate, call Core `POST /v1/deltas/preflight` with an Adapter or Owner grant that can read and write the selected space. The operator can also pass the same JSON on stdin to `python -m aiap_core --data-dir "$DATA" preflight-candidate --credential-file "$DATA/adapter.json"`.

The request contains `space_ref`, `purpose`, `text`, `level`, `memory_type`, and `trigger` (`user-request`, `host-observation`, or `agent-inference`). Supply `source_ref` for a host observation or to check an earlier submission from the same grant. Set `target_memory_id` to check an intended revision.

Core returns `ready-to-propose`, `duplicate`, `review-revision`, or `insufficient-information` with a reason. Related matches provide memory IDs and revisions for comparison. Shared terms indicate a possible relationship. Source and trigger are caller declarations; `source_verified` is false. This read-only operation has no model calls and creates no proposal. A subsequent submission still requires Owner approval.

Clients can use `POST /v1/deltas/propose-checked` to submit one regular memory change in one space. Send `{"envelope": existing_state_delta_envelope, "trigger": "user-request"}`. Core repeats the same checks and inserts the pending candidate in one SQLite transaction. A response with `submitted: false` carries the preflight decision and adds no proposal. A new entry with related matches needs an explicit revision target or a repeat with `confirm_new: true` to keep the entries separate. The flag records the caller's choice and provides no approval.

The checked endpoint preserves proposal idempotency for identical retries and records the declared trigger for Owner review. Pending proposals from other adapters remain private. The original `/v1/deltas/propose` endpoint remains available to existing clients.

Memory MCP and La Vida's manual proposal tool use checked submission when Core advertises `proposal_admission: checked-v1` in its session. Use `aiap_memory_status` to check the mode. The proposal tool can report duplicates and possible revisions directly, and returns the matching memory IDs and revisions. If the user explicitly asks to keep a related entry separately, pass `confirm_new: true`. Older Core installations use the original pending-proposal flow.

When the session advertises `proposal_revision: true`, the user can choose to correct an existing memory. Pass its ID and revision as `memory_id` and `base_revision`, provide the new text, and set `trigger: user-request` in `aiap_memory_propose`. Core keeps the original level, type and retention settings. It rechecks the target revision on submission and approval. A stale revision returns a 409, so the caller can refresh and show the current record. HTTP adapters may use `POST /v1/deltas/propose-revision` with `space_ref`, `purpose`, `memory_id`, `base_revision`, and `text`.

Owner approval of a checked candidate repeats exact duplicate detection within the approval transaction. If another record now has the same text, level and type in the same space, approval returns `E_DUPLICATE_MEMORY` (409) and the proposal stays pending. The Owner can compare the existing ID and revision in `review --local --changes` and reject the duplicate proposal.

Owner review with `review --local --changes` reports `approval_check` for pending candidates. It shows whether approval would pass the current grant, policy, revision and duplicate checks. The preview is read-only. Core rechecks these conditions when the Owner approves.

Use `pending --credential-file "$DATA/owner-credentials.json" --trigger host-observation` to list pending proposals that report an automatic trigger. Other filters include `user-request`, `agent-inference`, and `legacy` for proposals that have no checked-submission trigger. Trigger filtering combines with `--space` and pagination. Use the Owner review to see the submitting runtime and the reported source reference.

La Vida's opt-in automatic capture uses checked submission with the host-observation trigger when the Core supports it. When an active comparison is needed, the hook reports the existing reference and skips the candidate. Explicit user-requested separation remains available through the manual proposal tool.

### DSH automatic proposals

Automatic proposals use an optional DSH host plugin alongside the Memory MCP. This release supports the audited DSH Desktop 0.2.2-rc.5 SessionController and disables capture on unknown host versions. It leaves the signed DSH application files untouched. The standard Memory MCP remains available independently.

1. Download `dsh-aiap-capture-0.3.6.tar.gz`, `SHA256SUMS-MCP.txt`, and `install-dsh-capture.sh` from the [release](https://github.com/4b4sbms4mc-hub/aiap-openclaw/releases/tag/aiap-mcp-v0.3.8). Open a terminal in the download directory.
2. On macOS, run the installer. For a different DSH profile, pass its path as the second argument.

   ```sh
   sh ./install-dsh-capture.sh ./dsh-aiap-capture-0.3.6.tar.gz
   ```

   The installer verifies the archive, copies it to `vendor/aiap/` inside the profile, and runs `pnpm add`. This records a relative `file:` dependency in the profile's `package.json` and `pnpm-lock.yaml`. Keep the tarball at that path so pnpm can recreate the installation. The installer uses the bundled macOS pnpm when available. A shell with pnpm and `shasum` on PATH can use the same installer with an explicit profile path.

   **Already installed by hand?** Run the same command. It registers the existing plugin package with pnpm. Keep the current Cordis entry, Adapter grant, and preferences, then restart DSH. To change versions, use the desired release archive and its checksum manifest.

3. For a fresh capture setup, use the Core CLI to issue a separate single-space Adapter grant for `space:general`, with `--purpose aiap-auto-capture --runtime deepseek-harness`. Store it in a private file. Only the Adapter credential belongs in the plugin configuration.
4. For a fresh capture setup, add the following as an additional item in the same profile's `cordis.patch.yml` list and restart DSH. Use absolute paths. Keep the preferences file inside a private directory.

```yaml
- insert:
    - id: aiap-capture
      name: dsh-aiap-capture
      config:
        python: /absolute/path/to/venv/bin/python
        dataDir: /absolute/path/to/core
        credentialFile: /absolute/path/to/capture-adapter.json
        preferencesFile: /absolute/private/path/to/capture-sessions.json
```

Automatic proposals start off in every session. Send the exact message `开启 AIAP 自动提案` as the authenticated Owner in a session and let that turn complete. Send `关闭 AIAP 自动提案` to stop capture in that session. The allowlist is stored on the device (up to 16 sessions) and applies to future turns. Control messages themselves are excluded from proposals.

The plugin considers one short, direct Owner statement from a completed turn. It validates a one-use binding to the active DSH invocation, session, RPC ID and statement. Core applies its host-observation admission rules and keeps accepted candidates pending. Use the Owner terminal to review those proposals. Core records host-reported provenance; it does not independently authenticate the original DSH prompt. To uninstall capture, remove its Cordis entry, run `pnpm remove dsh-aiap-capture` in that profile using its pnpm, and restart DSH.

### Connecting to an existing Core over HTTP

From the repository root, install the optional SDK with `python -m pip install './aiap-core[mcp]'` in a virtual environment. Run the server with the address of an existing La Vida Core and a separate one-space Adapter credential:

```sh
aiap mcp serve --base-url http://127.0.0.1:8042 \
  --credential-file /absolute/path/to/aiap-adapter.json \
  --avatar-id 'avatar:YOUR_ID' --space space:general \
  --purpose aiap-memory --runtime deepseek-harness
```

Use the same Avatar, space, purpose and runtime that the Core grant was issued for. Store the credential in a private regular file. On macOS and Linux, use mode `0600` and the MCP process user's ownership. On Windows, use your Windows profile's private permissions. The ACL may grant access to your account, SYSTEM and local Administrators. The Core origin must use HTTPS or loopback HTTP, such as a local Core or a local tunnel to the NAS.

Configure DeepSeek Harness with the following profile patch. Replace the executable and credential paths and the Avatar ID with your own values.

```yaml
- insert:
    - id: aiap-memory
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: aiap
        transport: stdio
        command: /absolute/path/to/venv/bin/aiap
        args:
          - mcp
          - serve
          - --base-url
          - http://127.0.0.1:8042
          - --credential-file
          - /absolute/path/to/aiap-adapter.json
          - --avatar-id
          - 'avatar:YOUR_ID'
          - --space
          - space:general
          - --purpose
          - aiap-memory
          - --runtime
          - deepseek-harness
```

The three tools expose authorization status, active memory search and pending proposals. Core performs approval separately through the existing Owner workflow. Search excerpts enter the MCP client's tool results and can reach its configured model provider.

The current source MCP and OpenClaw manual proposal tools accept optional `level` (`M1` or `M2`) and `memory_type` fields. Choose M1 for task continuity, unfinished work, blockers and explicitly labeled hypotheses to revisit. Choose M2 for lasting preferences, decisions and knowledge. For example, submit `{"text":"Project X next step is to verify the pending hypothesis from today's investigation.","level":"M1","memory_type":"project-context"}`. Stable preferences use `preference-evidence`; the other supported types are `fact`, `decision`, `event`, `relationship`, `workflow-evidence`, `summary` and `other`.

Include relevant context, source, time and uncertainty in the text. Private information must fit the authorized space and purpose. Exclude passwords, tokens and private keys. These content guidelines are supplied to the runtime; the Core enforces schema, authorization, revisions and independent Owner approval. Manual candidates retain `inferred` provenance and confidence 0.5. Approval authorizes storage and does not establish factual certainty. Search results expose level, type, provenance and confidence. Existing text-only proposals default to M2/fact.

## Repository layout

```text
spec/        normative specifications
schemas/     formal JSON Schemas
src/aiap/    reference implementation
examples/    example AIAP objects
tests/       conformance-oriented tests
whitepaper/  publication files
```

## Protocol relationship

AIAP = Avatar identity / ownership / portability layer  
MCP = Agent/model ↔ tools and data  
A2A = Agent ↔ Agent collaboration

AIAP is designed to interoperate with MCP and A2A through adapters rather than replacing them.

## License model
- Code, Schemas, SDK/reference implementation: Apache-2.0
- Whitepaper/specification documentation: CC BY 4.0
- AIAP / AI Avatar Protocol names and logos: separate trademark policy

Search is read-only. For explicit feedback, retrieve a view with `aiap_memory_context`, call `aiap_memory_ack_delivery` after delivery, and call `aiap_memory_report_adoption` only for versions actually used. Report the version returned by the view. A retry within the view lifetime is idempotent. The Owner can filter the audit by `runtime-reported-adoption`. This is the runtime's own report.

For isolated projects, run the local Core operator command `project-space orchard`, issue a single-space adapter grant for `space:project:orchard`, and configure that project's MCP server with the matching credential and `--space space:project:orchard`. Issue a separate Owner grant for local review. Select the matching server in the runtime's project or session configuration. Repeat with a separate space and credential for other projects. Revoking a grant affects subsequent calls. Network sync for project spaces is outside the local feature.

Use `aiap_memory_batch` for up to 20 user-requested adds or revisions. Preview is read-only and compares each row against the current Core. Submission commits eligible rows individually and reports row indices. On interruption retry with the same batch ID, credential and identical rows. Reordering rows preserves their proposal IDs. Changed row content constitutes a new request. Every proposal still requires Owner approval.

For a consolidation review, `aiap_memory_similar` compares an approved record with other current records of the same level and type. Exact text and term overlap produce suggestions. Both texts and source references are returned so the reviewer can keep exceptions and conditions. No changes are submitted. `aiap_memory_relations` lists direct same-space replacements in either direction and records citing the same evidence reference. Replacement edges carry the revision at which the replacement was selected. Removed or inaccessible targets are omitted. The limit applies to direct edges or suggestions, with `possibly_more` when the cap truncates results.

For a turn that matches a known Owner condition, call `aiap_memory_context` with `preference_condition` (for example `Release`). The OpenClaw source adapter accepts the same optional argument on `aiap_memory_search`. The condition matches exactly after trimming. Omit it when the current request overrides the default. Returned `preference_defaults` include applicable exceptions; only ordinary memory items participate in delivery acknowledgments. Both adapters require a supporting Core when using this option.

To discover the exact condition names, call `aiap_memory_status` with `preference_conditions_after: ""`. Its optional `preference_conditions` page contains up to 20 distinct labels for confirmed preferences visible to this runtime in this space. Pass `next_after` to continue. Select a label only if the request fits, check the returned exceptions, and give an explicit turn override priority. Core rechecks the grant on recall.

If a condition has more defaults, repeat the tool call with the same condition and pass `next_preference_after` as `preference_after`. It pages only the preference list. Each page checks current authorization and withdrawals; earlier IDs added during a scan require restarting. When the current instruction overrides a default, omit both arguments. Older servers may report additional defaults without supplying a cursor.
