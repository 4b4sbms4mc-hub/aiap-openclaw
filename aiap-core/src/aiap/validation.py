# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Wang Lu
from __future__ import annotations
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"

def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))

def validate_document(document: dict, schema_name: str) -> None:
    schema = load_schema(schema_name)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        lines = []
        for e in errors:
            path = ".".join(str(x) for x in e.absolute_path) or "$"
            lines.append(f"{path}: {e.message}")
        raise ValueError("\n".join(lines))
