# SPDX-License-Identifier: Apache-2.0
import json
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_core_public import inspect
from recovery_guard import Service


class PublicInspectionTests(unittest.TestCase):
    def test_collects_only_code_and_schema_without_application_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / 'data'
            Service(data).initialize()
            owner = json.loads((data / 'owner-credentials.json').read_text())['token']
            from aiap_core.client import proposal
            service = Service(data)
            candidate = service.propose(owner, proposal(service.session(owner), 'space:general',
                'PRIVATE_MEMORY_NOT_TO_EXPORT'))
            before = {p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}
            package = Path(__file__).resolve().parents[2] / 'lavida/core/aiap_core'
            result = inspect(package, data)
            raw = json.dumps(result)
            self.assertEqual(result['schema_status'], 'read-only')
            self.assertIn('service.py', result['code_sha256'])
            self.assertTrue(result['profile_sha256'])
            for marker in (owner, candidate['delta_id'], 'PRIVATE_MEMORY_NOT_TO_EXPORT', 'PRIVATE KEY'):
                self.assertNotIn(marker, raw)
            self.assertEqual({p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}, before)

    def test_unknown_files_are_not_hashed_and_public_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / 'code'
            package.mkdir()
            (package / '__init__.py').write_text('')
            (package / 'private_config.py').write_text('TOKEN_NOT_TO_HASH')
            profile = root / 'profile'
            profile.mkdir()
            (profile / 'private.json').write_text('PASSWORD_NOT_TO_HASH')
            result = inspect(package, root / 'missing')
            self.assertEqual(set(result['code_sha256']), {'__init__.py'})
            self.assertEqual(result['profile_sha256'], {})
            (package / 'service.py').symlink_to(package / 'private_config.py')
            with self.assertRaises(ValueError):
                inspect(package, root / 'missing')

    def test_sqlite_lookalike_table_changes_schema_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / 'data'
            Service(data).initialize()
            package = Path(__file__).resolve().parents[2] / 'lavida/core/aiap_core'
            before = inspect(package, data)
            with sqlite3.connect(data / 'core.sqlite3') as db:
                db.execute('CREATE TABLE sqliteXextra(secret TEXT)')
            after = inspect(package, data)
            self.assertEqual(after['schema_object_count'], before['schema_object_count'] + 1)
            self.assertNotEqual(after['schema_sha256'], before['schema_sha256'])

    def test_missing_database_not_created_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / 'code'
            package.mkdir()
            (package / '__init__.py').write_text('')
            data = root / 'not-created'
            self.assertEqual(inspect(package, data)['schema_status'], 'missing')
            self.assertFalse(data.exists())
            data.mkdir()
            (data / 'core.sqlite3').symlink_to(root / 'elsewhere')
            self.assertEqual(inspect(package, data)['schema_status'], 'refused-symlink')


if __name__ == '__main__':
    unittest.main()
