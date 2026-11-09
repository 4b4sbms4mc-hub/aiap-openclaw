# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import selectors
import shutil
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_recovery_witness as witness_tests
from recovery_highwater import DurableWitnessReader
from recovery_guard import digest, restore_snapshot

CHILD = '''
import json,sys
from datetime import datetime
sys.path.insert(0, sys.argv[1])
from recovery_highwater import DurableWitnessReader
from recovery_guard import Fault
config=json.loads(sys.argv[3])
reader=DurableWitnessReader(sys.argv[2], clock=lambda:datetime.fromisoformat(sys.argv[4]), **config)
print(reader.challenge(),flush=True)
proof=json.loads(sys.stdin.readline())
original=reader._commit
def barrier(db):
    if sys.argv[5]=='after': original(db)
    print('AT_COMMIT',flush=True)
    sys.stdin.readline()
    if sys.argv[5]=='before': original(db)
if sys.argv[5]!='normal': reader._commit=barrier
try: print('ACCEPT:'+reader.verify(proof),flush=True)
except Fault as error: print('REJECT:'+error.code,flush=True)
'''


class DurableReaderTests(unittest.TestCase):
    def setUp(self):
        self.x = witness_tests.WitnessTests()
        self.x.setUp()
        self.addCleanup(self.x.doCleanups)
        self.directory = self.x.f.root / 'trusted-reader'
        initial = self.x.w.answer(self.x.r.challenge())
        self.d = DurableWitnessReader.enroll(self.directory, self.x.r, initial,
                                            digest(self.x.old_head))
        self.trust = self.d.trust

    def open(self, **kwargs):
        return DurableWitnessReader(self.directory, clock=lambda: self.x.now,
                                    **dict(self.trust, **kwargs))

    def verify(self, reader=None):
        reader = reader or self.d
        return reader.verify(self.x.w.answer(reader.challenge()))

    def advance(self):
        self.x.publish(self.x.f.checkpoint, self.x.f.pin)

    def reject(self, code, callback):
        self.x.reject(code, callback)

    def line(self, process, timeout=10):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout), 'child timed out')
        return process.stdout.readline().strip()

    def child(self, phase='normal'):
        p = subprocess.Popen([sys.executable, '-c', CHILD,
            str(Path(__file__).resolve().parents[1]), str(self.directory),
            json.dumps(self.trust), self.x.now.isoformat(), phase],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop, p)
        nonce = self.line(p)
        self.assertEqual(len(nonce), 64)
        return p, nonce

    def stop(self, process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def send(self, process, proof):
        process.stdin.write(json.dumps(proof)+'\n')
        process.stdin.flush()

    def test_restart_retains_high_water_and_rejects_signed_old_head(self):
        self.advance()
        self.verify()
        self.assertEqual(self.open().head['sequence'], 2)
        self.x.w._head = deepcopy(self.x.old_head)
        self.reject('E_WITNESS_ROLLBACK', lambda: self.verify(self.open()))
        self.assertEqual(self.open().head['sequence'], 2)

    def test_real_new_process_rejects_old_head_after_restart(self):
        self.advance()
        self.verify()
        self.x.w._head = deepcopy(self.x.old_head)
        process, nonce = self.child()
        self.send(process, self.x.w.answer(nonce))
        self.assertEqual(self.line(process), 'REJECT:E_WITNESS_ROLLBACK')
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_persisted_selection_feeds_real_isolated_restore(self):
        self.advance()
        pin = self.verify()
        report = restore_snapshot(self.x.f.snapshot, self.x.f.checkpoint, pin,
            self.x.f.target, clock=lambda: self.x.now)
        self.assertEqual(report['restored_objects'], 1)
        self.assertEqual(self.open().head['checkpoint_sha256'], pin)
        self.assertEqual(self.x.f.hashes(self.x.f.snapshot), self.x.f.original_files)

    def test_interrupted_enrollment_is_not_automatically_replaced(self):
        new = self.x.f.root / 'interrupted-enrollment'
        proof = self.x.w.answer(self.x.r.challenge())
        with patch('recovery_highwater.os.fsync', side_effect=OSError('INJECTED_DIRECTORY_SYNC_FAILURE')):
            with self.assertRaises(OSError):
                DurableWitnessReader.enroll(new, self.x.r, proof, digest(self.x.old_head))
        self.assertTrue((new / 'reader.sqlite3').is_file())
        proof = self.x.w.answer(self.x.r.challenge())
        with self.assertRaises(FileExistsError):
            DurableWitnessReader.enroll(new, self.x.r, proof, digest(self.x.old_head))
        # Explicit opening may inspect a fully committed state; no success was reported
        # by the interrupted enrollment and it must never silently reinitialize it.
        recovered = DurableWitnessReader(new, clock=lambda: self.x.now, **self.trust)
        self.assertEqual(recovered.head['sequence'], 1)

    def test_explicit_enrollment_pin_and_existing_directory_protected(self):
        new = self.x.f.root / 'bad-enrollment'
        proof = self.x.w.answer(self.x.r.challenge())
        self.reject('E_READER_ENROLLMENT', lambda: DurableWitnessReader.enroll(
            new, self.x.r, proof, '0'*64))
        self.assertFalse(new.exists())
        before = self.d.db.read_bytes()
        proof = self.x.w.answer(self.x.r.challenge())
        with self.assertRaises(FileExistsError):
            DurableWitnessReader.enroll(self.directory, self.x.r, proof, digest(self.x.old_head))
        self.assertEqual(self.d.db.read_bytes(), before)

    def test_missing_store_is_never_silently_reenrolled(self):
        self.d.db.unlink()
        with self.assertRaises(FileNotFoundError): self.open()
        self.assertFalse(self.d.db.exists())

    def test_wrong_trust_and_tampered_signature_rejected(self):
        self.reject('E_READER_ENROLLMENT', lambda: self.open(generation='different'))
        with sqlite3.connect(self.d.db) as db:
            state=json.loads(db.execute('SELECT body FROM reader_state').fetchone()[0])
            state['proof']['payload']['head']['sequence'] = 900
            db.execute('UPDATE reader_state SET body=?', (json.dumps(state),))
        self.reject('E_INTEGRITY', self.open)

    def test_unknown_schema_and_corrupt_db_rejected(self):
        with sqlite3.connect(self.d.db) as db: db.execute('CREATE TABLE unexpected(x)')
        self.reject('E_READER_STORAGE', self.open)
        self.d.db.write_bytes(b'CORRUPT_DATABASE')
        with self.assertRaises(sqlite3.DatabaseError): self.open()

    def test_permissions_and_symlinks_rejected(self):
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.d.db.stat().st_mode & 0o777, 0o600)
        self.d.db.chmod(0o644)
        self.reject('E_READER_STORAGE', self.open)
        self.d.db.chmod(0o600)
        moved = self.directory / 'original.sqlite3'
        self.d.db.rename(moved)
        self.d.db.symlink_to(moved)
        self.reject('E_READER_STORAGE', self.open)

    def test_commit_failure_rolls_back_and_never_returns_pin(self):
        self.advance()
        proof = self.x.w.answer(self.d.challenge())
        with patch.object(self.d, '_commit', side_effect=OSError('INJECTED_COMMIT_FAILURE')):
            with self.assertRaises(OSError): self.d.verify(proof)
        self.assertEqual(self.open().head['sequence'], 1)
        self.reject('E_WITNESS_NONCE', lambda: self.d.verify(proof))
        self.assertEqual(self.verify(), self.x.f.pin)

    def test_invalid_incoming_signature_leaves_store_unchanged(self):
        proof = self.x.w.answer(self.d.challenge())
        proof['payload']['head']['sequence'] = 100
        before = self.d.db.read_bytes()
        self.reject('E_INTEGRITY', lambda: self.d.verify(proof))
        self.assertEqual(before, self.d.db.read_bytes())

    def test_proof_expiring_during_commit_returns_no_pin_but_keeps_new_head(self):
        self.advance()
        proof = self.x.w.answer(self.d.challenge())
        commit = self.d._commit
        def delayed(db):
            commit(db)
            self.x.now += timedelta(seconds=61)
        with patch.object(self.d, '_commit', side_effect=delayed):
            self.reject('E_EXPIRED', lambda: self.d.verify(proof))
        self.assertEqual(self.open().head['sequence'], 2)

    def test_historical_proof_is_readable_after_expiry_but_not_reused_as_fresh(self):
        self.x.now += timedelta(hours=2)
        self.assertEqual(self.open().head['sequence'], 1)
        self.reject('E_EXPIRED', lambda: self.x.w.answer(self.d.challenge()))

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX kill and pipe readiness')
    def test_sigkill_before_and_after_commit_retains_last_committed_head(self):
        self.advance()
        for phase, expected in [('before',1), ('after',2)]:
            with self.subTest(phase=phase):
                process, nonce = self.child(phase)
                self.send(process, self.x.w.answer(nonce))
                self.assertEqual(self.line(process), 'AT_COMMIT')
                process.kill()
                process.communicate(timeout=5)
                self.assertLess(process.returncode, 0)
                self.assertEqual(self.open().head['sequence'], expected)
        self.x.w._head = deepcopy(self.x.old_head)
        self.reject('E_WITNESS_ROLLBACK', lambda: self.verify(self.open()))

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX subprocess pipes')
    def test_concurrent_stale_process_cannot_overwrite_committed_new_head(self):
        # Both processes open at head 1; process A holds the SQLite writer lock.
        a, an = self.child('before')
        b, bn = self.child()
        old = self.x.w.answer(bn)
        self.advance()
        self.send(a, self.x.w.answer(an))
        self.assertEqual(self.line(a), 'AT_COMMIT')
        self.send(b, old)
        with selectors.DefaultSelector() as selector:
            selector.register(b.stdout, selectors.EVENT_READ)
            self.assertFalse(selector.select(timeout=0.2), 'stale process bypassed writer lock')
        a.stdin.write('COMMIT\n');a.stdin.flush()
        self.assertEqual(self.line(a), 'ACCEPT:'+self.x.f.pin)
        self.assertEqual(self.line(b), 'REJECT:E_WITNESS_ROLLBACK')
        self.assertEqual(self.open().head['sequence'], 2)

    def test_whole_store_rollback_remains_an_explicit_trusted_storage_limit(self):
        saved = self.x.f.root / 'old-reader.sqlite3'
        shutil.copyfile(self.d.db, saved)
        self.advance()
        self.verify()
        shutil.copyfile(saved, self.d.db)
        self.x.w._head = deepcopy(self.x.old_head)
        self.assertEqual(self.verify(self.open()), self.x.f.older_pin)
        # A valid old signed proof and the complete store can be rolled back together.


if __name__ == '__main__': unittest.main()
