# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as recovery_tests
from recovery_guard import restore_snapshot, digest, canonical, b64, Fault
from recovery_witness import SyntheticWitness, WitnessReader, monotonic_head, DOMAIN
from aiap_core.service import Service


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery_tests.RecoveryTests()
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.now = self.f.now
        payload = json.loads(self.f.checkpoint.read_text())['payload']
        self.avatar = payload['core']['avatar_id']
        self.enrollment = digest(payload['enrollment'])
        self.w = SyntheticWitness(self.avatar, self.enrollment, lambda: self.now)
        self.r = self.reader()
        self.old_head = self.publish(self.f.older_checkpoint, self.f.older_pin)

    def reader(self, **kwargs):
        args = dict(avatar=self.avatar, enrollment_sha256=self.enrollment,
                    generation=self.w.generation, public_key=self.w.public_key,
                    clock=lambda: self.now)
        args.update(kwargs)
        return WitnessReader(**args)

    def publish(self, checkpoint, pin):
        ticket = self.w.begin_update(self.w.head['sequence'] if self.w.head else 0)
        return self.w.publish(ticket, checkpoint, pin)

    def proof(self):
        return self.w.answer(self.r.challenge())

    def signed(self, body):
        return {'payload': body, 'signature': b64(self.w._key.sign(DOMAIN + canonical(body)))}

    def reject(self, code, callback):
        with self.assertRaises(Fault) as error:
            callback()
        self.assertEqual(error.exception.code, code)

    def test_current_proof_selects_checkpoint_for_actual_isolated_restore(self):
        self.assertEqual(self.r.verify(self.proof()), self.f.older_pin)
        self.publish(self.f.checkpoint, self.f.pin)
        pin = self.r.verify(self.proof())
        self.assertEqual(pin, self.f.pin)
        report = restore_snapshot(self.f.snapshot, self.f.checkpoint, pin, self.f.target,
                                  clock=lambda: self.now)
        self.assertEqual(report['restored_objects'], 1)
        owner = json.loads((self.f.target / 'owner-credentials.json').read_text())['token']
        recovered = Service(self.f.target, clock=lambda: self.now)
        rows = recovered.search(owner, {'space_refs': ['space:general'],
            'purpose': 'owner-maintenance', 'query': ''})['items']
        self.assertEqual([r['memory_id'] for r in rows], [self.f.keep])
        for token in (self.f.owner, self.f.adapter['token']):
            self.reject('E_IDENTITY', lambda token=token: recovered.session(token))
        self.assertEqual(self.f.hashes(self.f.snapshot), self.f.original_files)

    def test_pending_mutation_blocks_answers_until_checkpoint_commit(self):
        ticket = self.w.begin_update(1)
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.w.answer(self.r.challenge()))
        self.reject('E_CHECKPOINT_PIN', lambda: self.w.publish(ticket, self.f.checkpoint, '0'*64))
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.w.answer(self.r.challenge()))
        self.w.publish(ticket, self.f.checkpoint, self.f.pin)
        self.assertEqual(self.r.verify(self.proof()), self.f.pin)

    def test_wrong_ticket_and_stale_writer_sequence_cannot_commit(self):
        self.reject('E_WITNESS_SEQUENCE', lambda: self.w.begin_update(0))
        ticket = self.w.begin_update(1)
        self.reject('E_WITNESS_PENDING', lambda: self.w.begin_update(1))
        self.reject('E_WITNESS_PENDING', lambda: self.w.publish('wrong', self.f.checkpoint, self.f.pin))
        self.w.publish(ticket, self.f.checkpoint, self.f.pin)
        self.reject('E_WITNESS_PENDING', lambda: self.w.publish(ticket, self.f.checkpoint, self.f.pin))

    def test_response_replay_and_wrong_nonce_rejected(self):
        proof = self.proof()
        self.r.verify(proof)
        self.reject('E_WITNESS_NONCE', lambda: self.r.verify(proof))
        self.r.challenge()
        self.reject('E_WITNESS_NONCE', lambda: self.r.verify(proof))
        self.assertIsNone(self.r._challenge)

    def test_signature_tamper_does_not_advance_reader(self):
        proof = self.proof()
        proof['payload']['head']['sequence'] += 1
        self.reject('E_INTEGRITY', lambda: self.r.verify(proof))
        self.assertIsNone(self.r.head)

    def test_wrong_pinned_identity_generation_or_witness_key(self):
        other = SyntheticWitness(self.avatar, self.enrollment, lambda: self.now)
        for kwargs, code in [({'avatar': 'avatar:wrong'}, 'E_IDENTITY'),
            ({'enrollment_sha256': '0'*64}, 'E_IDENTITY'),
            ({'generation': other.generation}, 'E_IDENTITY'),
            ({'public_key': other.public_key}, 'E_INTEGRITY')]:
            with self.subTest(kwargs=kwargs):
                reader = self.reader(**kwargs)
                proof = self.w.answer(reader.challenge())
                self.reject(code, lambda: reader.verify(proof))

    def test_expired_future_and_overlong_proof_rejected(self):
        proof = self.proof()
        self.now += timedelta(seconds=61)
        self.reject('E_EXPIRED', lambda: self.r.verify(proof))
        self.now = self.f.now - timedelta(seconds=1)
        self.r._challenge = proof['payload']['nonce']
        self.reject('E_EXPIRED', lambda: self.r.verify(proof))
        self.now = self.f.now
        proof = self.proof()
        from aiap_core.service import stamp
        proof['payload']['expires_at'] = stamp(self.now + timedelta(seconds=61))
        self.reject('E_EXPIRED', lambda: self.r.verify(self.signed(proof['payload'])))

    def test_expired_checkpoint_and_empty_witness_are_unavailable(self):
        empty = SyntheticWitness(self.avatar, self.enrollment, lambda: self.now)
        self.reject('E_WITNESS_UNAVAILABLE', lambda: empty.answer(self.r.challenge()))
        self.now += timedelta(hours=2)
        self.reject('E_EXPIRED', lambda: self.w.answer(self.r.challenge()))

    def test_signed_rollback_rejected_by_existing_reader(self):
        self.publish(self.f.checkpoint, self.f.pin)
        self.r.verify(self.proof())
        saved = self.r.head
        self.w._head = deepcopy(self.old_head)  # simulate rollback of trusted witness storage
        self.reject('E_WITNESS_ROLLBACK', lambda: self.r.verify(self.proof()))
        self.assertEqual(self.r.head, saved)

    def test_same_sequence_fork_and_adjacent_wrong_parent_rejected(self):
        self.r.verify(self.proof())
        body = self.proof()['payload']
        body['head']['checkpoint_sha256'] = 'a'*64
        self.reject('E_WITNESS_FORK', lambda: self.r.verify(self.signed(body)))
        self.publish(self.f.checkpoint, self.f.pin)
        body = self.proof()['payload']
        body['head']['previous_sha256'] = 'b'*64
        self.reject('E_WITNESS_FORK', lambda: self.r.verify(self.signed(body)))

    def test_checkpoint_substitution_and_old_checkpoint_commit_rejected(self):
        self.publish(self.f.checkpoint, self.f.pin)
        pin = self.r.verify(self.proof())
        self.reject('E_CHECKPOINT_PIN', lambda: restore_snapshot(self.f.snapshot,
            self.f.older_checkpoint, pin, self.f.target, clock=lambda: self.now))
        ticket = self.w.begin_update(2)
        self.reject('E_WITNESS_ROLLBACK', lambda: self.w.publish(ticket,
            self.f.older_checkpoint, self.f.older_pin))
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.w.answer(self.r.challenge()))

    def test_identity_mismatch_during_publish_leaves_witness_pending(self):
        self.w.enrollment_sha256 = 'f'*64
        ticket = self.w.begin_update(1)
        self.reject('E_IDENTITY', lambda: self.w.publish(ticket, self.f.checkpoint, self.f.pin))
        self.reject('E_WITNESS_UNAVAILABLE', lambda: self.w.answer(self.r.challenge()))

    def test_monotonic_counters_strict_types_and_refresh(self):
        old = self.old_head
        refresh = dict(old, sequence=2, checkpoint_sha256='a'*64)
        self.assertTrue(monotonic_head(old, refresh))
        for changes in ({'sequence': True}, {'sequence': 0}, {'sequence': 1},
            {'core_revision': -1}, {'revocation_epoch': True},
            {'checkpoint_sha256': 'a'*64+'\n'}, {'governance_sha256': 'b'*64}):
            with self.subTest(changes=changes):
                self.assertFalse(monotonic_head(old, dict(refresh, **changes)))
        for value in (None, [], {}, {'sequence': 1}):
            self.assertFalse(monotonic_head(old, value))
            if value is not None:
                self.assertFalse(monotonic_head(value, refresh))


    def test_proof_has_metadata_but_no_memory_body_or_credentials(self):
        raw = canonical(self.proof())
        for marker in (b'KEEP_SYNTHETIC', b'DELETED_SYNTHETIC',
                       self.f.owner.encode(), self.f.adapter['token'].encode(), b'PRIVATE KEY'):
            self.assertNotIn(marker, raw)
        copy = self.w.head
        copy['sequence'] = 100
        self.assertEqual(self.w.head['sequence'], 1)

    def test_source_bypass_is_an_explicit_unresolved_limitation(self):
        # Fixture source has already deleted a record after old capture. Without
        # an enforced begin_update hook the witness has no way to learn this.
        pin = self.r.verify(self.proof())
        self.assertEqual(pin, self.f.older_pin)
        report = restore_snapshot(self.f.snapshot, self.f.older_checkpoint, pin,
            self.f.target, clock=lambda: self.now)
        self.assertEqual(report['restored_objects'], 3)
        owner = json.loads((self.f.target / 'owner-credentials.json').read_text())['token']
        rows = Service(self.f.target, clock=lambda: self.now).search(owner,
            {'space_refs': ['space:general'], 'purpose': 'owner-maintenance', 'query': ''})['items']
        self.assertIn(self.f.deleted, {r['memory_id'] for r in rows})

    def test_new_reader_loses_rollback_memory_without_durable_high_water(self):
        self.publish(self.f.checkpoint, self.f.pin)
        self.r.verify(self.proof())
        self.w._head = deepcopy(self.old_head)
        restarted = self.reader()
        self.assertEqual(restarted.verify(self.w.answer(restarted.challenge())), self.f.older_pin)
        # Passing negative boundary: not a claim of persistent rollback resistance.


if __name__ == '__main__':
    unittest.main()
