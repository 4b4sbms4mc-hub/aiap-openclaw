# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as recovery_tests
from recovery_guard import (Fault, Service, digest, export_checkpoint, restore_snapshot,
                            canonical, b64, stamp, read_file)
from recovery_avatar_observation import AvatarObservationWitness as LiveObservationWitness, observe_source, OBS_DOMAIN
from recovery_witness import WitnessReader
from recovery_highwater import DurableWitnessReader
from cryptography.hazmat.primitives import serialization


class AvatarObservationTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery_tests.RecoveryTests()
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.now = self.f.now
        self.checkpoint, self.pin = self.f.checkpoint, self.f.pin
        payload = json.loads(self.checkpoint.read_text())['payload']
        self.witness = LiveObservationWitness(payload['core']['avatar_id'],
                                              digest(payload['enrollment']), lambda: self.now)
        self.reader = WitnessReader(self.witness.avatar, self.witness.enrollment_sha256,
                                    self.witness.generation, self.witness.public_key, lambda: self.now)
        self.counter = 0

    def reject(self, code, call):
        with self.assertRaises(Fault) as error:
            call()
        self.assertEqual(error.exception.code, code)

    def observation(self, nonce):
        return observe_source(self.f.current, self.checkpoint, self.pin, nonce, lambda: self.now)

    def proof(self, nonce=None, observation=None):
        nonce = nonce or self.reader.challenge()
        return self.witness.answer(nonce, checkpoint=self.checkpoint, pin=self.pin,
                                   observation=observation or self.observation(nonce))

    def refresh_checkpoint(self):
        self.counter += 1
        self.checkpoint = self.f.root / ('live-%s.json' % self.counter)
        self.pin = export_checkpoint(self.f.current, self.checkpoint, clock=lambda: self.now)['checkpoint_sha256']

    def delete(self):
        self.f.service.delete(self.f.owner, {'memory_id': self.f.keep,
            'space_ref': 'space:general', 'base_revision': 1})

    def resign(self, observation):
        key = serialization.load_pem_private_key(read_file(self.f.current/'avatar-key.pem'), None)
        observation['signature'] = b64(key.sign(OBS_DOMAIN + canonical(observation['payload'])))
        return observation

    def test_normal_writes_while_witness_absent_then_old_checkpoint_denied(self):
        self.reader.verify(self.proof())
        before = self.witness.head
        self.delete()  # ordinary Service has no reference to witness and succeeds
        self.assertEqual(self.witness.head, before)
        self.reject('E_SOURCE_DIVERGED', lambda: self.observation(self.reader.challenge()))
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.witness.answer(self.reader.challenge()))
        self.refresh_checkpoint()
        self.assertEqual(self.reader.verify(self.proof()), self.pin)
        restore_snapshot(self.f.snapshot, self.checkpoint, self.pin, self.f.target, clock=lambda: self.now)
        with sqlite3.connect(self.f.target/'core.sqlite3') as db:
            self.assertIsNone(db.execute('SELECT id FROM memories WHERE id=?', (self.f.keep,)).fetchone())

    def test_offline_revocation_changes_epoch_without_core_revision(self):
        self.reader.verify(self.proof())
        before = self.witness.head
        grant = self.f.service.issue_grant(['space:general'], 'memory', 'extra')
        self.f.service.revoke_grant(grant['grant_id'])
        self.reject('E_SOURCE_DIVERGED', lambda: self.observation(self.reader.challenge()))
        self.refresh_checkpoint(); self.reader.verify(self.proof())
        self.assertEqual(self.witness.head['core_revision'], before['core_revision'])
        self.assertGreater(self.witness.head['revocation_epoch'], before['revocation_epoch'])

    def test_source_observation_does_not_modify_source_or_return_private_content(self):
        before = self.f.hashes(self.f.current)
        obs = self.observation(self.reader.challenge())
        self.assertEqual(self.f.hashes(self.f.current), before)
        raw = canonical(obs)
        for marker in (b'KEEP_SYNTHETIC', self.f.owner.encode(), b'PRIVATE KEY'):
            self.assertNotIn(marker, raw)

    def test_cached_observation_cannot_answer_a_new_challenge(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        self.reader.verify(self.proof(nonce, obs))
        other = self.reader.challenge()
        self.reject('E_SOURCE_OBSERVATION', lambda: self.proof(other, obs))

    def test_reader_consumes_nonce_even_for_replayed_proof(self):
        proof = self.proof(); self.reader.verify(proof)
        self.reject('E_WITNESS_NONCE', lambda: self.reader.verify(proof))

    def test_unchanged_checkpoint_still_needs_a_new_observation(self):
        self.reader.verify(self.proof()); head = self.witness.head
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.witness.answer(self.reader.challenge(),
                    checkpoint=self.checkpoint, pin=self.pin))
        self.reader.verify(self.proof()); self.assertEqual(self.witness.head, head)

    def test_signature_and_checkpoint_binding(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        tampered = deepcopy(obs); tampered['payload']['checkpoint_sha256'] = 'f'*64
        self.reject('E_INTEGRITY', lambda: self.proof(nonce, tampered))
        self.resign(tampered)
        self.reject('E_SOURCE_OBSERVATION', lambda: self.proof(nonce, tampered))

    def test_schema_and_enrollment_binding(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        extra = deepcopy(obs); extra['payload']['extra'] = True
        self.reject('E_SCHEMA', lambda: self.proof(nonce, extra))
        obs['payload']['enrollment_sha256'] = '0'*64
        self.resign(obs)
        self.reject('E_IDENTITY', lambda: self.proof(nonce, obs))

    def test_observation_expiry_and_clock_rollback(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        self.now += timedelta(seconds=30)
        self.reject('E_EXPIRED', lambda: self.proof(nonce, obs))
        self.now -= timedelta(seconds=31)
        self.reject('E_EXPIRED', lambda: self.proof(nonce, obs))

    def test_source_signed_invalid_time_ranges_and_malformed_time(self):
        nonce = self.reader.challenge(); original = self.observation(nonce)
        for value in (stamp(self.now+timedelta(seconds=31)), stamp(self.now), 'invalid', None):
            obs = deepcopy(original); obs['payload']['expires_at'] = value; self.resign(obs)
            self.reject('E_EXPIRED', lambda: self.proof(nonce, obs))

    def test_witness_proof_never_outlives_source_observation(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        self.now += timedelta(seconds=29)
        proof = self.proof(nonce, obs)
        self.assertEqual(proof['payload']['expires_at'], obs['payload']['expires_at'])
        self.now += timedelta(seconds=1)
        self.reject('E_EXPIRED', lambda: self.reader.verify(proof))

    def test_missing_database_is_not_created(self):
        absent = self.f.root/'absent'; absent.mkdir()
        self.reject('E_RECOVERY_FILE', lambda: observe_source(absent, self.checkpoint,
                    self.pin, self.reader.challenge(), lambda: self.now))
        self.assertEqual(list(absent.iterdir()), [])

    def test_source_unknown_schema_and_symlink_rejected(self):
        with sqlite3.connect(self.f.current/'core.sqlite3') as db:
            db.execute('CREATE TABLE sqliteXextra(value TEXT)')
        self.reject('E_OPERATION_UNSUPPORTED', lambda: self.observation(self.reader.challenge()))
        linked = self.f.root/'linked'; linked.symlink_to(self.f.current, target_is_directory=True)
        self.reject('E_RECOVERY_FILE', lambda: observe_source(linked, self.checkpoint,
                    self.pin, self.reader.challenge(), lambda: self.now))

    def test_sidecars_refused_without_opening_or_deleting_them(self):
        sidecar = self.f.current/'core.sqlite3-wal'; sidecar.write_bytes(b'UNSUPPORTED')
        before = self.f.hashes(self.f.current)
        self.reject('E_OPERATION_UNSUPPORTED', lambda: self.observation(self.reader.challenge()))
        self.assertEqual(self.f.hashes(self.f.current), before)

    def test_durable_reader_and_recreated_witness_require_existing_trust(self):
        initial = self.proof()
        durable = DurableWitnessReader.enroll(self.f.root/'reader', self.reader, initial,
                                              digest(self.witness.head))
        nonce = durable.challenge()
        durable.verify(self.proof(nonce))
        # Restarting the in-memory witness generates a new trust root. It is not
        # an automatic production recovery mechanism, even for unchanged source.
        other = LiveObservationWitness(self.witness.avatar, self.witness.enrollment_sha256,
                                       lambda: self.now)
        nonce = durable.challenge()
        proof = other.answer(nonce, checkpoint=self.checkpoint, pin=self.pin,
                             observation=self.observation(nonce))
        self.reject('E_INTEGRITY', lambda: durable.verify(proof))

    def test_known_source_rollback_is_rejected_by_witness_floor(self):
        saved = self.f.root/'saved'; shutil.copytree(self.f.current, saved)
        self.reader.verify(self.proof()); self.delete(); self.refresh_checkpoint()
        self.reader.verify(self.proof())
        shutil.rmtree(self.f.current); shutil.copytree(saved, self.f.current)
        self.refresh_checkpoint()
        self.reject('E_WITNESS_ROLLBACK', self.proof)

    def test_negative_unseen_offline_mutation_then_whole_source_rollback_not_detected(self):
        self.reader.verify(self.proof())
        saved = self.f.root/'saved'; shutil.copytree(self.f.current, saved)
        self.delete()  # Mac never observes this deletion
        shutil.rmtree(self.f.current); shutil.copytree(saved, self.f.current)
        # Current source can sign a fresh nonce for its rolled-back state.
        self.assertEqual(self.reader.verify(self.proof()), self.pin)

    def test_negative_mutation_after_observation_is_not_a_write_lease(self):
        nonce = self.reader.challenge(); obs = self.observation(nonce)
        self.delete()  # no production writer gate and no continuous activation check
        self.assertEqual(self.reader.verify(self.proof(nonce, obs)), self.pin)
        self.reject('E_SOURCE_DIVERGED', lambda: self.observation(self.reader.challenge()))


    def test_v1_and_v2_cannot_cross_verify(self):
        import recovery_live_observation as legacy
        import recovery_avatar_observation as avatar
        payload = json.loads(self.checkpoint.read_text())['payload']
        nonce = self.reader.challenge()
        old = legacy.observe_source(self.f.current, self.checkpoint, self.pin, nonce, lambda: self.now)
        new = self.observation(nonce)
        for verifier, envelope in [(avatar.verify_observation, old), (legacy.verify_observation, new)]:
            with self.assertRaises(Fault):
                verifier(envelope, nonce, self.pin, payload, digest(payload['enrollment']), self.now)
        # Even relabeling the profile does not convert the signature domain/key.
        old['payload']['profile'] = avatar.OBS_PROFILE
        self.reject('E_INTEGRITY', lambda: avatar.verify_observation(old, nonce, self.pin, payload,
                    digest(payload['enrollment']), self.now))

    def test_owner_private_key_not_needed_by_v2(self):
        (self.f.current/'owner-key.pem').unlink()
        self.reader.verify(self.proof())

    def test_owner_private_key_cannot_replace_avatar_key(self):
        shutil.copyfile(self.f.current/'owner-key.pem', self.f.current/'avatar-key.pem')
        self.reject('E_INTEGRITY', lambda: self.observation(self.reader.challenge()))

if __name__ == '__main__':
    unittest.main()
