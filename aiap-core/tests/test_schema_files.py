# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Wang Lu
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

def test_all_schemas_are_valid():
    for path in (ROOT/"schemas").glob("*.json"):
        schema=json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
