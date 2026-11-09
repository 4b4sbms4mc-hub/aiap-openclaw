# SPDX-License-Identifier: Apache-2.0
"""Read only code/schema fingerprints. Never select application rows or keys."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


CODE_FILES = (
    '__init__.py',
    '__main__.py',
    'client.py',
    'contracts.py',
    'semantic.py',
    'server.py',
    'service.py',
)
PROFILE_FILES = (
    'SOURCE_MANIFEST.json',
    'schemas/access-request.schema.json',
    'schemas/authorized-view.schema.json',
    'schemas/avatar-core.schema.json',
    'schemas/bundle-manifest.schema.json',
    'schemas/common.schema.json',
    'schemas/consent-policy.schema.json',
    'schemas/lifecycle-policy.schema.json',
    'schemas/membership.schema.json',
    'schemas/memory-record.schema.json',
    'schemas/object-reference.schema.json',
    'schemas/profile-manifest.schema.json',
    'schemas/scoped-transfer-certificate.schema.json',
    'schemas/space.schema.json',
    'schemas/state-delta.schema.json',
    'schemas/state-profile.schema.json',
    'schemas/tombstone.schema.json',
    'schemas/transfer-manifest.schema.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/MANIFEST.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/schemas/runtime-adapter-descriptor.schema.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/schemas/runtime-context.schema.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/schemas/runtime-profile.schema.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/schemas/state-delta.schema.json',
    'upstream/AIAP_Runtime_Adapter_Protocol_v0.1/schemas/state-request.schema.json',
    'upstream/aiap-procedural-state-v0.1/schemas/capability.schema.json',
    'upstream/aiap-procedural-state-v0.1/schemas/execution-trace.schema.json',
    'upstream/aiap-procedural-state-v0.1/schemas/runtime-binding.schema.json',
    'upstream/aiap-procedural-state-v0.1/schemas/skill-descriptor.schema.json',
    'upstream/aiap-procedural-state-v0.1/schemas/workflow-descriptor.schema.json',
    'upstream/aiap-state-schema-v0.1/aiap-state.schema.json',
    'upstream/aiap-state-schema-v0.1/common.schema.json',
    'upstream/aiap-state-schema-v0.1/identity.schema.json',
    'upstream/aiap-state-schema-v0.1/memory.schema.json',
    'upstream/aiap-state-schema-v0.1/permission.schema.json',
    'upstream/aiap-state-schema-v0.1/preferences.schema.json',
    'upstream/aiap-state-schema-v0.1/skill.schema.json',
    'upstream/aiap-state-schema-v0.1/workflow.schema.json',
)


def known_hashes(base, names):
    # Based on the local coder draft; Codex corrected path/string handling,
    # base symlink checks and descriptor type checks before acceptance.
    if base.is_symlink():
        raise ValueError('Symlinked public-code directory refused')
    results = {}
    for name in names:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Only fixed relative public paths are allowed')
        current = base
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('Symlinked public file refused')
        try:
            if not stat.S_ISREG(current.lstat().st_mode):
                raise ValueError('Public file must be regular')
            fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise ValueError('Public file must be regular')
                raw = file.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('Code/schema file exceeds collector bound')
            results[name] = sha(raw)
        except FileNotFoundError:
            continue
    return results


def inspect(package_dir, data_dir):
    package, data = Path(package_dir), Path(data_dir)
    result = {'profile': 'x-aiap-core-public-fingerprint-v1',
              'code_sha256': known_hashes(package, CODE_FILES),
              'profile_sha256': {}, 'database_present': False, 'schema_status': 'missing'}
    profile = package.parent / 'profile'
    if profile.is_dir():
        result['profile_sha256'] = known_hashes(profile, PROFILE_FILES)
    database = data / 'core.sqlite3'
    if database.is_symlink():
        result['schema_status'] = 'refused-symlink'
        return result
    if not database.is_file():
        return result  # never creates a missing database
    result['database_present'] = True
    try:
        db = sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True, timeout=3)
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('BEGIN')
            rows = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                              "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
            raw = json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode()
            result.update(schema_status='read-only', schema_sha256=sha(raw), schema_object_count=len(rows))
        finally:
            db.close()
    except sqlite3.Error as error:
        result.update(schema_status='unavailable', error_type=type(error).__name__)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=Path('/data'))
    args = parser.parse_args()
    spec = importlib.util.find_spec('aiap_core')
    if spec is None or spec.origin is None:
        raise SystemExit('AIAP Core package not found; no data was read')
    result = inspect(Path(spec.origin).parent, args.data_dir)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
