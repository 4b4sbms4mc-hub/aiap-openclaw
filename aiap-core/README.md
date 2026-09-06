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
