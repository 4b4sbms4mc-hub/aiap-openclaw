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
    a=p.parse_args()
    if a.cmd=="validate":
        doc=json.load(open(a.file, encoding="utf-8"))
        validate_document(doc, SCHEMAS[a.type])
        print("VALID")

if __name__=="__main__":
    main()
