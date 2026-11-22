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
    source = serve.add_mutually_exclusive_group()
    source.add_argument("--base-url", default="http://127.0.0.1:8042", help="Existing Core HTTP endpoint")
    source.add_argument("--data-dir", help="Private local Core data directory for in-process storage")
    serve.add_argument("--embedding-url", help="Trusted OpenAI-compatible embedding server origin for --data-dir")
    serve.add_argument("--embedding-model", help="Model ID for --embedding-url")
    serve.add_argument("--embedding-dimensions", type=int, help="Embedding vector size (default: 1024)")
    serve.add_argument("--credential-file", required=True)
    serve.add_argument("--avatar-id", required=True)
    serve.add_argument("--space", help="Exact space in the single-space adapter grant.", required=True)
    serve.add_argument("--purpose", required=True)
    serve.add_argument("--runtime", required=True)
    serve.add_argument("--system-embedding-language", help="Use system embedding for this language in local mode")
    embedding = sub.add_parser("embedding", help="Inspect or acquire system-managed model assets")
    embedding_commands = embedding.add_subparsers(dest="embedding_command", required=True)
    for name in ("status", "download"):
        command = embedding_commands.add_parser(name)
        command.add_argument("--language", default="zh-Hans")
    a=p.parse_args()
    if a.cmd=="validate":
        doc=json.load(open(a.file, encoding="utf-8"))
        validate_document(doc, SCHEMAS[a.type])
        print("VALID")
    elif a.cmd == "embedding":
        from aiap_core.contracts import Fault
        from aiap_core.system_embedding import SystemEmbedding
        try:
            engine = SystemEmbedding(a.language, ["space:general"])
        except Fault:
            p.error("invalid system embedding language")
        result = engine.download() if a.embedding_command == "download" else engine.setup()
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["state"] == "ready" else 1
    elif a.cmd == "mcp":
        if a.system_embedding_language is not None and (a.data_dir is None or a.embedding_url):
            p.error("--system-embedding-language requires --data-dir and cannot be combined with --embedding-url")
        if a.embedding_url is not None:
            if a.data_dir is None or not a.embedding_model:
                p.error("--embedding-url requires --data-dir and --embedding-model")
        elif a.embedding_model is not None or a.embedding_dimensions is not None:
            p.error("--embedding-model and --embedding-dimensions require --embedding-url")
        try:
            from .memory_mcp import serve
        except ImportError as exc:
            if not exc.name or exc.name.split(".", 1)[0] != "mcp":
                raise
            p.error("MCP support requires the aiap-reference[mcp] extra")
        return serve(a)

if __name__=="__main__":
    raise SystemExit(main())
