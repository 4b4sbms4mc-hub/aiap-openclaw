# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Wang Lu
from __future__ import annotations
import argparse, json
from .validation import validate_document

SCHEMAS = {
    "avatar":"avatar.schema.json",
    "identity":"identity.schema.json",
    "transfer":"transfer-certificate.schema.json",
    "memory":"memory.schema.json",
    "permission":"permission.schema.json",
    "extension":"extension.schema.json",
    "session":"session.schema.json",
    "artifact":"artifact.schema.json",
}

def main():
    p=argparse.ArgumentParser(prog="aiap", description="AIAP v0.3 reference CLI")
    sub=p.add_subparsers(dest="cmd", required=True)
    v=sub.add_parser("validate")
    v.add_argument("type", choices=SCHEMAS)
    v.add_argument("file")
    mcp = sub.add_parser("mcp", help="Connect an MCP host to AIAP Core memory")
    commands = mcp.add_subparsers(dest="mcp_command", required=True)
    serve = commands.add_parser("serve", help="Run the AIAP memory server over stdio")
    serve.add_argument("--base-url", default="http://127.0.0.1:8042")
    serve.add_argument("--credential-file", required=True)
    serve.add_argument("--avatar-id", required=True)
    serve.add_argument("--space", choices=("space:general", "space:life", "space:work"), required=True)
    serve.add_argument("--purpose", required=True)
    serve.add_argument("--runtime", required=True)
    a=p.parse_args()
    if a.cmd=="validate":
        doc=json.load(open(a.file, encoding="utf-8"))
        validate_document(doc, SCHEMAS[a.type])
        print("VALID")
    elif a.cmd == "mcp":
        try:
            from .memory_mcp import serve
        except ImportError as exc:
            if not exc.name or exc.name.split(".", 1)[0] != "mcp":
                raise
            p.error("MCP support requires the aiap-reference[mcp] extra")
        return serve(a)

if __name__=="__main__":
    raise SystemExit(main())
