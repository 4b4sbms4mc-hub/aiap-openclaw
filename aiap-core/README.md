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

From the repository root, install the optional SDK with `python -m pip install './aiap-core[mcp]'` in a virtual environment. Run the server with the address of an existing La Vida Core and a separate one-space Adapter credential:

```sh
aiap mcp serve --base-url http://127.0.0.1:8042 \
  --credential-file /absolute/path/to/aiap-adapter.json \
  --avatar-id 'avatar:YOUR_ID' --space space:general \
  --purpose aiap-memory --runtime deepseek-harness
```

Use the same Avatar, space, purpose and runtime that the Core grant was issued for. Store the credential in a regular file owned by the MCP process user with mode `0600`. The Core origin must use HTTPS or loopback HTTP, such as a local Core or a local tunnel to the NAS.

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
