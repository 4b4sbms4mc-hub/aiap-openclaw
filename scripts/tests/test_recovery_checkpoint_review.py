# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta
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

    def indexed_checkpoint(self):
        from cryptography.hazmat.primitives import serialization
        from aiap_core.contracts import b64
        from aiap_core.recovery_checkpoint import DOMAIN
        from aiap_core.service import stamp
        envelope = json.loads(self.fixture.checkpoint.read_bytes())
        payload = envelope['payload']
        payload['issued_at'] = stamp(self.fixture.now)
        core = payload['core']
        manifest = self.fixture.service.preference_manifest(self.fixture.owner, 'space:work')
        core['extensions'].append({'namespace':'x-aiap-local-preference-index','version':'1','critical':True})
        core['state_index'].append({'id':'preference-manifest:space:work','version':1,
                                    'scope':manifest['scope'],'sha256':manifest['sha256']})
        del core['integrity']
        self.fixture.service._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00')
        key = serialization.load_pem_private_key((self.fixture.current/'owner-key.pem').read_bytes(), None)
        envelope['signature'] = b64(key.sign(DOMAIN + canonical(payload)))
        path = self.fixture.root/'indexed-checkpoint.json'
        path.write_bytes(canonical(envelope))
        pin = digest(envelope)
        return path, pin, payload

    def test_preference_index_requires_matching_diagnostic(self):
        path, pin, payload = self.indexed_checkpoint()
        with self.assertRaises(Fault) as mismatch:
            self.review(path, pin)
        self.assertEqual(mismatch.exception.code, 'E_GOVERNANCE_MISMATCH')
        self.diagnostic['governance_sha256'] = digest({k:payload[k] for k in
            ('core','spaces','tombstones','revocation_epoch')})
        self.report.write_bytes(canonical(self.diagnostic))
        before = self.fixture.hashes(self.fixture.root)
        self.assertEqual(self.review(path, pin)['status'], 'checkpoint-matches-diagnostic')
        self.assertEqual(self.fixture.hashes(self.fixture.root), before)

    def test_indexed_registry_review_and_live_format_boundary(self):
        from aiap_core.recovery_registry import CheckpointRegistry
        registry = CheckpointRegistry(self.fixture.root/'registry', self.fixture.current, lambda: self.fixture.now)
        registry.initialize(self.diagnostic['enrollment_sha256'])
        old = registry.register(self.fixture.older_checkpoint, self.fixture.older_pin)
        self.assertEqual(old['preference_manifest_count'], 0)
        self.fixture.now += timedelta(seconds=1)
        path, pin, payload = self.indexed_checkpoint()
        report = registry.register(path, pin)
        with self.assertRaises(Fault) as rollback:
            registry.register(self.fixture.older_checkpoint, self.fixture.older_pin)
        self.assertEqual(rollback.exception.code, 'E_CHECKPOINT_ROLLBACK')
        self.assertEqual(report['status'], 'checkpoint-registered')
        self.assertEqual(report['current_object_count'], len(payload['core']['state_index'])-1)
        self.assertEqual(report['preference_manifest_count'], 1)
        self.assertEqual(registry.register(path, pin)['status'], 'checkpoint-already-registered')
        self.assertEqual(registry.status()['head'], report['head'])
        review = registry.review(path)
        self.assertEqual(review['preference_manifest_count'], 1)
        self.assertFalse(review['source_currentness_verified'])
        self.assertFalse(review['restore_authorized'])
        with self.assertRaises(Fault) as incompatible:
            registry.review_live(path, lambda *_: self.fail('unexpected source connection'), allow_indexed=False)
        self.assertEqual(incompatible.exception.code, 'E_CRITICAL_EXTENSION')
        with self.assertRaises(Fault):
            registry.register(path, '0'*64)
        self.assertEqual(registry.status()['head'], report['head'])

    def test_issue_indexed_checkpoint_reconciles_actual_registry(self):
        from aiap_core.recovery_checkpoint import inspect_checkpoint_index
        s = self.fixture.service
        space = 'space:work'
        fields = dict(statement='PRIVATE SYNTHETIC PREFERENCE', condition='release', runtimes=['example'])
        owner = self.fixture.owner
        pin = s.preview_preference(owner, space, **fields)['preview_sha256']
        record = s.confirm_preference(owner, space, pin, **fields)
        core = s.core(owner)['avatar_core']
        memory_count = len(core['state_index'])
        manifest = s.preference_manifest(owner, space)
        core['extensions'].append(dict(namespace='x-aiap-local-preference-index', version='1', critical=True))
        core['state_index'].append(dict(id='preference-manifest:'+space, version=1,
                                        scope=manifest['scope'], sha256=manifest['sha256']))
        del core['integrity']
        s._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00')
        with s.tx() as db:
            db.execute('UPDATE cores SET body=?', (canonical(core).decode(),))
        def issue(filename):
            return export_checkpoint(self.fixture.current, filename, clock=lambda: self.fixture.now)
        output = self.fixture.root/'issued.json'
        source_before = self.fixture.hashes(self.fixture.current)
        result = issue(output)
        from aiap_core.recovery_checkpoint import compare_local_checkpoint
        def compare():
            return compare_local_checkpoint(s, owner, output, result['checkpoint_sha256'])
        self.assertTrue(compare()['preference_registry_checked'])
        index = inspect_checkpoint_index(output, result['checkpoint_sha256'], self.fixture.now)
        self.assertEqual((index['memory_reference_count'], index['preference_manifest_count']), (memory_count, 1))
        self.assertNotIn(fields['statement'].encode(), output.read_bytes())
        self.assertEqual(source_before, self.fixture.hashes(self.fixture.current))
        from recovery_avatar_observation import observe_source
        from aiap_core.recovery_registry import CheckpointRegistry
        registry = CheckpointRegistry(self.fixture.root/'registry', self.fixture.current, lambda: self.fixture.now)
        registry.initialize(index['enrollment_sha256'])
        registry.register(output, result['checkpoint_sha256'])
        def observe(nonce, pin):
            return observe_source(self.fixture.current, output, pin, nonce, lambda: self.fixture.now)
        from source_avatar_observation_rpc import LaboratoryAvatarObservationRPC, PROFILE, verify_reply
        rpc = LaboratoryAvatarObservationRPC(self.fixture.current, {result['checkpoint_sha256']: output},
                                              lambda: self.fixture.now)
        def transport(nonce, pin):
            request = canonical(dict(profile=PROFILE, op='observe', nonce=nonce, checkpoint_sha256=pin))
            return verify_reply(rpc.respond(request), request, output, lambda: self.fixture.now)
        live = registry.review_live(output, transport)
        self.assertTrue(live['source_currentness_verified'])
        self.assertFalse(live['restore_authorized'])
        self.assertEqual(live['preference_manifest_count'], 1)
        self.assertEqual(source_before, self.fixture.hashes(self.fixture.current))
        def downgrade(nonce, pin):
            from cryptography.hazmat.primitives import serialization
            from aiap_core.contracts import b64
            from aiap_core.recovery_observation import OBS_DOMAIN, OBS_PROFILE
            envelope = observe(nonce, pin)
            body = envelope['payload']
            body['profile'] = OBS_PROFILE
            key = serialization.load_pem_private_key((self.fixture.current/'avatar-key.pem').read_bytes(), None)
            return dict(payload=body, signature=b64(key.sign(OBS_DOMAIN + canonical(body))))
        with self.assertRaises(Fault) as downgraded:
            registry.review_live(output, downgrade)
        self.assertEqual(downgraded.exception.code, 'E_SCHEMA')
        rejected = self.fixture.root/'rejected.json'
        with s.tx() as db:
            db.execute("INSERT INTO meta VALUES('preference:orphan','{}')")
        with self.assertRaises(Fault) as unindexed:
            compare()
        self.assertEqual(unindexed.exception.code, 'E_INTEGRITY')
        with self.assertRaises(Fault) as orphan:
            issue(rejected)
        self.assertEqual(orphan.exception.code, 'E_INTEGRITY')
        self.assertFalse(rejected.exists())
        with s.tx() as db:
            db.execute("DELETE FROM meta WHERE key='preference:orphan'")
            db.execute("UPDATE meta SET value=json_set(value,'$.statement','Edited') WHERE key=?",
                       (record['preference_id'],))
        with self.assertRaises(Fault) as modified:
            compare()
        self.assertEqual(modified.exception.code, 'E_INTEGRITY')
        with self.assertRaises(Fault) as live_mismatch:
            registry.review_live(output, observe)
        self.assertEqual(live_mismatch.exception.code, 'E_INTEGRITY')
        with self.assertRaises(Fault) as mismatch:
            issue(rejected)
        self.assertEqual(mismatch.exception.code, 'E_INTEGRITY')
        self.assertFalse(rejected.exists())

    def test_compare_local_legacy_governance_is_owner_only(self):
        from aiap_core.recovery_checkpoint import compare_local_checkpoint
        f = self.fixture
        def compare(token):
            return compare_local_checkpoint(f.service, token, f.checkpoint, f.pin)
        adapter = f.service.issue_grant(['space:general'], 'work', 'test-runtime')['token']
        before = f.hashes(f.current)
        self.assertFalse(compare(f.owner)['preference_registry_checked'])
        with self.assertRaises(Fault) as denied:
            compare(adapter)
        self.assertEqual(denied.exception.code, 'E_DENIED')
        self.assertEqual(before, f.hashes(f.current))
        f.service.revoke_grant(f.service.session(adapter)['auth_evidence_ref'])
        with self.assertRaises(Fault) as changed:
            compare(f.owner)
        self.assertEqual(changed.exception.code, 'E_SOURCE_DIVERGED')

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
