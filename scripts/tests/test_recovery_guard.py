# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import sqlite3
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recovery_guard import export_checkpoint, restore_snapshot
from aiap_core.service import Service
from aiap_core.client import proposal
from aiap_core.client import Client
from aiap_core.contracts import Fault, canonical


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = datetime(2026, 11, 9, tzinfo=timezone.utc)
        self.current = self.root / 'current'
        self.service = Service(self.current, clock=lambda: self.now)
        self.service.initialize()
        self.owner = json.loads((self.current / 'owner-credentials.json').read_text())['token']
        self.adapter = self.service.issue_grant(['space:general'], 'memory', 'test-runtime')
        self.keep = self.add('KEEP_SYNTHETIC')
        self.deleted = self.add('DELETED_SYNTHETIC')
        self.stale = self.add('OLD_VERSION_SYNTHETIC')
        old = self.find(self.deleted)
        update = proposal(self.service.session(self.owner), 'space:general', 'DELETED_LATEST_SYNTHETIC', old=old)
        delta = self.service.propose(self.owner, update)
        self.service.decide(self.owner, delta['delta_id'], True)
        pending = proposal(self.service.session(self.adapter['token']), 'space:general',
                           'DELETED_PENDING_SYNTHETIC', old=self.find(self.deleted))
        self.pending = self.service.propose(self.adapter['token'], pending)['delta_id']
        self.view = self.service.search(self.adapter['token'], {'space_refs': ['space:general'],
            'purpose': 'memory', 'query': ''}, context=True)['authorized_view']['view_id']
        self.older_checkpoint = self.root / 'older-checkpoint.json'
        self.older_pin = export_checkpoint(self.current, self.older_checkpoint, clock=lambda: self.now)['checkpoint_sha256']
        self.snapshot = self.root / 'snapshot'
        shutil.copytree(self.current, self.snapshot)
        self.original_files = self.hashes(self.snapshot)
        self.service.delete(self.owner, {'memory_id': self.deleted, 'space_ref': 'space:general', 'base_revision': 2})
        update = proposal(self.service.session(self.owner), 'space:general', 'NEW_VERSION_SYNTHETIC', old=self.find(self.stale))
        delta = self.service.propose(self.owner, update)
        self.service.decide(self.owner, delta['delta_id'], True)
        self.add('NEW_AFTER_BACKUP_SYNTHETIC')
        self.service.revoke_grant(self.adapter['grant_id'])
        self.checkpoint = self.root / 'checkpoint.json'
        self.pin = export_checkpoint(self.current, self.checkpoint, clock=lambda: self.now)['checkpoint_sha256']
        self.target = self.root / 'restored'

    def tearDown(self):
        self.tmp.cleanup()

    def hashes(self, directory):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()}

    def add(self, text):
        p = proposal(self.service.session(self.owner), 'space:general', text)
        d = self.service.propose(self.owner, p)
        self.service.decide(self.owner, d['delta_id'], True)
        return p['bindings'][0]['target_object_id']

    def find(self, mid):
        return next(m for m in self.service.search(self.owner, {'space_refs': ['space:general'],
            'purpose': 'owner-maintenance', 'query': ''})['items'] if m['memory_id'] == mid)

    def restore(self, **overrides):
        params = dict(snapshot_dir=self.snapshot, checkpoint=self.checkpoint, expected_sha256=self.pin,
                      target_dir=self.target, clock=lambda: self.now)
        params.update(overrides)
        return restore_snapshot(**params)

    def reject(self, code, **overrides):
        with self.assertRaises(Fault) as error:
            self.restore(**overrides)
        self.assertEqual(error.exception.code, code)
        self.assertFalse(self.target.exists())

    def test_current_tombstone_and_manifest_filter_historical_data(self):
        report = self.restore()
        self.assertEqual(report['restored_objects'], 1)
        self.assertEqual(report['excluded_backup_objects'], 2)
        self.assertEqual(report['missing_current_objects'], 2)
        self.assertEqual(report['restore_guarantee'], 'partial-current-memory-index')
        service = Service(self.target, clock=lambda: self.now)
        owner = json.loads((self.target / 'owner-credentials.json').read_text())['token']
        records = service.search(owner, {'space_refs': ['space:general'], 'purpose': 'owner-maintenance', 'query': ''})['items']
        self.assertEqual([(r['memory_id'], r['content']) for r in records], [(self.keep, 'KEEP_SYNTHETIC')])
        signed = service.core(owner)
        self.assertTrue(service.verify_local_core(signed['avatar_core'], signed['local_enrollment']))
        self.assertEqual(self.hashes(self.snapshot), self.original_files)
        with sqlite3.connect(service.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM tombstones WHERE id=?', (self.deleted,)).fetchone()[0], 1)
            for table in ('history', 'deltas', 'views'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)
        raw = service.db.read_bytes()
        for marker in (b'DELETED_SYNTHETIC', b'DELETED_LATEST_SYNTHETIC', b'DELETED_PENDING_SYNTHETIC', b'OLD_VERSION_SYNTHETIC'):
            self.assertNotIn(marker, raw)

    def test_all_old_credentials_fail_and_new_approval_still_works(self):
        self.restore()
        service = Service(self.target, clock=lambda: self.now)
        for token in (self.owner, self.adapter['token']):
            with self.assertRaises(Fault) as error:
                service.session(token)
            self.assertEqual(error.exception.code, 'E_IDENTITY')
        owner = json.loads((self.target / 'owner-credentials.json').read_text())['token']
        grant = service.issue_grant(['space:general'], 'restored', 'new-runtime')
        draft = proposal(service.session(grant['token']), 'space:general', 'NEW_APPROVED_SYNTHETIC')
        candidate = service.propose(grant['token'], draft)
        with self.assertRaises(Fault):
            service.decide(grant['token'], candidate['delta_id'], True)
        service.decide(owner, candidate['delta_id'], True)
        self.assertEqual(service.search(grant['token'], {'space_refs': ['space:general'],
            'purpose': 'restored', 'query': 'NEW_APPROVED'})['count'], 1)
        self.assertEqual(service.session(owner)['avatar_id'], self.service.session(self.owner)['avatar_id'])

    def test_checkpoint_has_no_memory_text_or_secrets(self):
        raw = self.checkpoint.read_bytes()
        for marker in (b'KEEP_SYNTHETIC', b'DELETED_SYNTHETIC', self.owner.encode(), self.adapter['token'].encode(), b'PRIVATE KEY'):
            self.assertNotIn(marker, raw)
        self.assertEqual(self.checkpoint.stat().st_mode & 0o077, 0)

    def test_wrong_pin(self):
        self.reject('E_CHECKPOINT_PIN', expected_sha256='0' * 64)

    def test_expired_and_future_checkpoints(self):
        self.reject('E_EXPIRED', clock=lambda: self.now + timedelta(hours=2))
        self.reject('E_EXPIRED', clock=lambda: self.now - timedelta(minutes=1))

    def test_modified_checkpoint_even_with_recomputed_pin(self):
        data = json.loads(self.checkpoint.read_text())
        data['payload']['revocation_epoch'] += 10
        raw = canonical(data)
        self.checkpoint.write_bytes(raw)
        self.reject('E_INTEGRITY', expected_sha256=hashlib.sha256(raw).hexdigest())

    def test_known_newer_snapshot_rejects_checkpoint_rollback(self):
        newer = self.root / 'newer'
        shutil.copytree(self.current, newer)
        self.reject('E_CHECKPOINT_ROLLBACK', snapshot_dir=newer,
                    checkpoint=self.older_checkpoint, expected_sha256=self.older_pin)

    def test_wrong_identity_keys(self):
        other = self.root / 'other'
        Service(other, clock=lambda: self.now).initialize()
        shutil.copyfile(other / 'owner-key.pem', self.snapshot / 'owner-key.pem')
        self.reject('E_INTEGRITY')

    def test_row_scope_tamper_not_hidden_by_valid_core_signature(self):
        with sqlite3.connect(self.snapshot / 'core.sqlite3') as db:
            db.execute("UPDATE memories SET space='space:life' WHERE id=?", (self.keep,))
        self.reject('E_SCOPE')

    def test_memory_body_tamper(self):
        with sqlite3.connect(self.snapshot / 'core.sqlite3') as db:
            body = json.loads(db.execute('SELECT body FROM memories WHERE id=?', (self.keep,)).fetchone()[0])
            body['content'] = 'TAMPERED'
            db.execute('UPDATE memories SET body=? WHERE id=?', (json.dumps(body), self.keep))
        self.reject('E_INTEGRITY')

    def test_unknown_schema_is_rejected(self):
        with sqlite3.connect(self.snapshot / 'core.sqlite3') as db:
            db.execute('CREATE TABLE unexpected(secret TEXT)')
        self.reject('E_OPERATION_UNSUPPORTED')

    def test_active_journal_or_wal_snapshot_is_rejected_without_mutation(self):
        sidecar = self.snapshot / 'core.sqlite3-wal'
        sidecar.write_bytes(b'NOT_A_STOPPED_SNAPSHOT')
        before = self.hashes(self.snapshot)
        self.reject('E_OPERATION_UNSUPPORTED')
        self.assertEqual(self.hashes(self.snapshot), before)

    def test_existing_destination_untouched(self):
        self.target.mkdir()
        sentinel = self.target / 'keep.txt'
        sentinel.write_text('USER_EXISTING_DATA')
        with self.assertRaises(Fault) as error:
            self.restore()
        self.assertEqual(error.exception.code, 'E_OUTPUT_EXISTS')
        self.assertEqual(sentinel.read_text(), 'USER_EXISTING_DATA')

    def test_symlink_checkpoint_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.checkpoint)
        with self.assertRaises(OSError):
            self.restore(checkpoint=link)
        self.assertFalse(self.target.exists())

    def test_checkpoint_inside_backup_is_not_an_independent_control(self):
        enclosed = self.snapshot / 'checkpoint.json'
        shutil.copyfile(self.checkpoint, enclosed)
        self.reject('E_CHECKPOINT_LOCATION', checkpoint=enclosed)

    def test_real_cli_restore_and_new_http_process(self):
        helper = Path(__file__).resolve().parents[1] / 'recovery_guard.py'
        live_checkpoint = self.root / 'live-checkpoint.json'
        exported = subprocess.run([sys.executable, str(helper), 'checkpoint', '--data-dir', str(self.current),
            '--output', str(live_checkpoint)], capture_output=True, text=True, timeout=15)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        pin = json.loads(exported.stdout)['checkpoint_sha256']
        result = subprocess.run([sys.executable, str(helper), 'restore', '--snapshot', str(self.snapshot),
            '--checkpoint', str(live_checkpoint), '--checkpoint-sha256', pin,
            '--target', str(self.target)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['restored_objects'], 1)
        owner = json.loads((self.target / 'owner-credentials.json').read_text())['token']
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        core_root = Path(__file__).resolve().parents[2] / 'lavida/core'
        process = subprocess.Popen([sys.executable, '-m', 'aiap_core', '--data-dir', str(self.target),
            'serve', '--port', str(port), '--archive-interval', '0'], cwd=core_root,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            self.assertIn('listening', process.stdout.readline())
            base = 'http://127.0.0.1:' + str(port)
            client = Client(base, owner)
            self.assertEqual(client.call('/v1/search', {'space_refs': ['space:general'],
                'purpose': 'owner-maintenance', 'query': ''})['count'], 1)
            with self.assertRaisesRegex(RuntimeError, '401'):
                Client(base, self.adapter['token']).call('/v1/session')
            with self.assertRaisesRegex(RuntimeError, '404'):
                client.call('/v1/deltas/review', {'delta_id': self.pending})
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_expiry_during_restore_never_publishes_destination(self):
        times = iter([self.now, self.now + timedelta(hours=2)])
        self.reject('E_EXPIRED', clock=lambda: next(times))
        self.assertFalse(list(self.root.glob('.aiap-recovery-*')))

    def test_clock_rollback_during_restore_never_publishes_destination(self):
        times = iter([self.now, self.now - timedelta(minutes=1)])
        self.reject('E_EXPIRED', clock=lambda: next(times))
        self.assertFalse(list(self.root.glob('.aiap-recovery-*')))

    def test_publication_io_failure_cleans_private_stage_and_reservation(self):
        with patch('recovery_guard.os.replace', side_effect=OSError('INJECTED_PUBLICATION_FAILURE')):
            with self.assertRaises(OSError):
                self.restore()
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.root.glob('.aiap-recovery-*')))
        self.assertEqual(self.hashes(self.snapshot), self.original_files)

    def test_valid_older_checkpoint_demonstrates_external_freshness_requirement(self):
        # Deliberately supply a stale but valid pin. This is a limitation test,
        # not an assertion that resurrecting a subsequently deleted record is safe.
        report = self.restore(checkpoint=self.older_checkpoint, expected_sha256=self.older_pin)
        self.assertEqual(report['restored_objects'], 3)
        self.assertEqual(report['restore_guarantee'], 'complete-for-current-memory-index')
        owner = json.loads((self.target / 'owner-credentials.json').read_text())['token']
        recovered = Service(self.target, clock=lambda: self.now)
        rows = recovered.search(owner, {'space_refs': ['space:general'],
            'purpose': 'owner-maintenance', 'query': ''})['items']
        self.assertIn(self.deleted, {row['memory_id'] for row in rows})
        # The genuine current checkpoint contains a tombstone; the old one does not.
        current = json.loads(self.checkpoint.read_text())['payload']
        self.assertIn(self.deleted, {row['id'] for row in current['tombstones']})
        self.assertEqual(self.hashes(self.snapshot), self.original_files)

    def test_concurrent_destination_content_is_preserved(self):
        def interfere():
            (self.target / 'concurrent.txt').write_text('KEEP_CONCURRENT_DATA')
            return self.now
        times = iter([self.now, None])
        def clock():
            return self.now if next(times) is not None else interfere()
        with self.assertRaises(Fault) as error:
            self.restore(clock=clock)
        self.assertEqual(error.exception.code, 'E_OUTPUT_EXISTS')
        self.assertEqual((self.target / 'concurrent.txt').read_text(), 'KEEP_CONCURRENT_DATA')
        self.assertEqual(list(self.target.iterdir()), [self.target / 'concurrent.txt'])
        self.assertFalse(list(self.root.glob('.aiap-recovery-*')))
        self.assertEqual(self.hashes(self.snapshot), self.original_files)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX process kill and pipe readiness')
    def test_sigkill_around_publication_has_explicit_recovery_outcomes(self):
        # Pause at a deterministic barrier; kill a real child process, bypassing finally.
        script = '''
import sys, time
from datetime import datetime
sys.path.insert(0, sys.argv[1])
import recovery_guard as guard
original = guard.os.replace
def barrier(source, target):
    if sys.argv[6] == 'after':
        original(source, target)
    print('AT_PUBLICATION_BARRIER', flush=True)
    while True:
        time.sleep(1)
guard.os.replace = barrier
guard.restore_snapshot(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
                       clock=lambda: datetime.fromisoformat(sys.argv[7]))
'''
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                target = self.root / ('killed-' + phase)
                process = subprocess.Popen([sys.executable, '-c', script,
                    str(Path(__file__).resolve().parents[1]), str(self.snapshot),
                    str(self.checkpoint), self.pin, str(target), phase, self.now.isoformat()],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=15), 'child did not reach publication')
                    self.assertEqual(process.stdout.readline().strip(), 'AT_PUBLICATION_BARRIER')
                    process.kill()
                    process.communicate(timeout=5)
                    self.assertLess(process.returncode, 0)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                    stages = list(self.root.glob('.aiap-recovery-*'))
                    if phase == 'before':
                        self.assertEqual(list(target.iterdir()), [])
                        self.assertEqual(len(stages), 1)
                        self.assertEqual(stages[0].stat().st_mode & 0o777, 0o700)
                        with self.assertRaises(Fault) as error:
                            self.restore(target_dir=target)
                        self.assertEqual(error.exception.code, 'E_OUTPUT_EXISTS')
                        # Only remove this test's private residue after its child has stopped.
                        shutil.rmtree(stages[0])
                        target.rmdir()
                        self.assertEqual(self.restore(target_dir=target)['restored_objects'], 1)
                    else:
                        self.assertEqual(stages, [])
                    owner = json.loads((target / 'owner-credentials.json').read_text())['token']
                    recovered = Service(target, clock=lambda: self.now)
                    rows = recovered.search(owner, {'space_refs': ['space:general'],
                        'purpose': 'owner-maintenance', 'query': ''})['items']
                    self.assertEqual([row['memory_id'] for row in rows], [self.keep])
                    for token in (self.owner, self.adapter['token']):
                        with self.assertRaises(Fault):
                            recovered.session(token)
                    self.assertEqual(self.hashes(self.snapshot), self.original_files)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
