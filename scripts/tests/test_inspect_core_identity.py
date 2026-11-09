# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as recovery_tests
from inspect_core_identity import inspect_identity
from recovery_guard import Fault


class IdentityInspectionTests(unittest.TestCase):
    def setUp(self):
        self.f=recovery_tests.RecoveryTests();self.f.setUp();self.addCleanup(self.f.tearDown)

    def test_read_only_without_private_key_files_or_application_content(self):
        for name in ('owner-key.pem','avatar-key.pem','owner-credentials.json'):
            (self.f.current/name).unlink()
        before=self.f.hashes(self.f.current)
        result=inspect_identity(self.f.current)
        self.assertEqual(self.f.hashes(self.f.current),before)
        self.assertEqual(result['database_access'],'read-only')
        self.assertEqual(result['local_enrollment_signature'],'valid')
        for value in ('KEEP_SYNTHETIC',self.f.owner,self.f.keep,self.f.pending,'PRIVATE KEY'):
            self.assertNotIn(value,json.dumps(result))

    def test_missing_database_symlink_and_sidecar_refused_without_creation_or_cleanup(self):
        absent=self.f.root/'missing';absent.mkdir()
        with self.assertRaises(Fault):inspect_identity(absent)
        self.assertEqual(list(absent.iterdir()),[])
        linked=self.f.root/'linked';linked.symlink_to(self.f.current,target_is_directory=True)
        with self.assertRaises(Fault):inspect_identity(linked)
        sidecar=self.f.current/'core.sqlite3-wal';sidecar.write_bytes(b'UNSUPPORTED')
        with self.assertRaises(Fault):inspect_identity(self.f.current)
        self.assertEqual(sidecar.read_bytes(),b'UNSUPPORTED')

    def test_tampered_enrollment_or_identity_is_not_reported_as_valid(self):
        with sqlite3.connect(self.f.current/'core.sqlite3') as db:
            value=json.loads(db.execute("SELECT value FROM meta WHERE key='enrollment'").fetchone()[0])
            value['signature']='INVALID'
            db.execute("UPDATE meta SET value=? WHERE key='enrollment'",(json.dumps(value),))
        with self.assertRaises(Fault):inspect_identity(self.f.current)

    def test_lookalike_internal_table_is_not_silently_ignored(self):
        with sqlite3.connect(self.f.current/'core.sqlite3') as db:
            db.execute('CREATE TABLE sqliteXextra(secret TEXT)')
        with self.assertRaises(Fault):inspect_identity(self.f.current)


if __name__=='__main__':unittest.main()
