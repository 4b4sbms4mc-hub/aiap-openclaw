# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import test_recovery_guard as fixtures
from recovery_guard import Fault, canonical, digest, export_checkpoint, review_checkpoint


class CheckpointReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.report = self.fixture.root / 'diagnostic.json'
        payload = json.loads(self.fixture.checkpoint.read_bytes())['payload']
        self.diagnostic = {
            'profile': 'x-aiap-governance-digest-preflight-v1',
            'enrollment_sha256': digest(payload['enrollment']),
            'governance_sha256': digest({key: payload[key] for key in
                                         ('core', 'spaces', 'tombstones', 'revocation_epoch')}),
            'core_revision': payload['core']['revision'],
            'space_count': len(payload['spaces']),
            'tombstone_count': len(payload['tombstones']),
            'database_access': 'read-only',
            'trust': 'diagnostic-only-not-a-checkpoint-or-source-proof',
        }
        self.report.write_bytes(canonical(self.diagnostic))

    def review(self, checkpoint=None, pin=None):
        return review_checkpoint(checkpoint or self.fixture.checkpoint, pin or self.fixture.pin,
                                 self.report, lambda: self.fixture.now)

    def test_raw_and_recorded_result_match_without_granting_trust(self):
        for report in [self.diagnostic, dict(source='operator report', recorded_at='local record',
                                           plan_sha256='recorded plan', result=self.diagnostic)]:
            self.report.write_bytes(canonical(report))
            before = self.fixture.hashes(self.fixture.root)
            result = self.review()
            self.assertEqual(result['status'], 'checkpoint-matches-diagnostic')
            self.assertFalse(result['source_currentness_verified'])
            self.assertFalse(result['registration_performed'])
            self.assertEqual(before, self.fixture.hashes(self.fixture.root))

    def test_other_source_governance_and_noninteger_count_rejected(self):
        for field, value in [('enrollment_sha256', '0' * 64), ('governance_sha256', '0' * 64),
                             ('core_revision', 0), ('space_count', 4), ('tombstone_count', True)]:
            with self.subTest(field=field):
                self.report.write_bytes(canonical({**self.diagnostic, field: value}))
                with self.assertRaises(Fault):
                    self.review()

    def test_valid_older_checkpoint_does_not_match(self):
        with self.assertRaises(Fault):
            self.review(self.fixture.older_checkpoint, self.fixture.older_pin)

    def test_wrong_pin_and_forged_signature_rejected(self):
        with self.assertRaises(Fault):
            self.review(pin='0' * 64)
        envelope = json.loads(self.fixture.checkpoint.read_bytes())
        envelope['signature'] = 'A' * 86
        raw = canonical(envelope)
        forged = self.fixture.root / 'forged.json'
        forged.write_bytes(raw)
        with self.assertRaises(Fault):
            self.review(forged, hashlib.sha256(raw).hexdigest())

    def test_cli_matches_and_rejects_fifo_without_waiting_for_writer(self):
        path = self.fixture.root / 'fresh-checkpoint.json'
        pin = export_checkpoint(self.fixture.current, path)['checkpoint_sha256']
        script = Path(__file__).resolve().parents[1] / 'recovery_guard.py'
        argv = [sys.executable, str(script), 'review-checkpoint', '--checkpoint', str(path),
                '--checkpoint-sha256', pin, '--diagnostic', str(self.report)]
        result = subprocess.run(argv, capture_output=True, check=True, timeout=10)
        self.assertEqual(json.loads(result.stdout)['status'], 'checkpoint-matches-diagnostic')
        self.report.unlink()
        os.mkfifo(self.report)
        result = subprocess.run(argv, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
