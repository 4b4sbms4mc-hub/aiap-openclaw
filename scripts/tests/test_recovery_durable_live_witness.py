# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta
from pathlib import Path
import shutil
import sqlite3
import json
import secrets
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_recovery_live_observation as live_tests
from recovery_guard import Fault, digest, stamp, canonical
from recovery_durable_live_witness import DurableLiveWitness
from recovery_witness import WitnessReader
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


class DurableLiveWitnessTests(unittest.TestCase):
    def setUp(self):
        self.live = live_tests.LiveObservationTests(); self.live.setUp()
        self.addCleanup(self.live.doCleanups)
        w = self.live.witness
        self.trust = dict(avatar=w.avatar, enrollment_sha256=w.enrollment_sha256,
                          generation=w.generation, public_key=w.public_key)
        self.signer, self.clock = w._key, lambda: self.live.now
        self.directory = self.live.f.root/'independent-witness'
        nonce = self.live.reader.challenge(); proof = self.live.proof(nonce)
        self.witness = DurableLiveWitness.enroll(self.directory, self.trust, self.signer,
            proof, nonce, digest(w.head), self.clock)
        self.live.reader.verify(proof)

    def reopen(self, signer=None):
        return DurableLiveWitness(self.directory, self.trust, signer or self.signer, self.clock)

    def proof(self, witness=None):
        nonce = self.live.reader.challenge()
        return (witness or self.witness).answer(nonce, checkpoint=self.live.checkpoint,
            pin=self.live.pin, observation=self.live.observation(nonce))

    def changed_source(self):
        self.live.delete(); self.live.refresh_checkpoint()

    def reject(self, code, callback):
        with self.assertRaises(Fault) as e: callback()
        self.assertEqual(e.exception.code, code)

    def test_reopen_preserves_generation_key_and_monotonic_head(self):
        self.changed_source()
        self.live.reader.verify(self.proof())
        head = self.witness.head
        restarted = self.reopen()
        self.assertEqual(restarted.head, head)
        self.live.reader.verify(self.proof(restarted))
        self.assertEqual(restarted.head, head)

    def test_stale_instance_cannot_overwrite_newer_committed_state(self):
        stale = self.reopen()
        old_checkpoint, old_pin = self.live.checkpoint, self.live.pin
        nonce = self.live.reader.challenge(); old_observation = self.live.observation(nonce)
        self.changed_source(); self.live.reader.verify(self.proof())
        self.reject('E_WITNESS_ROLLBACK', lambda: stale.answer(nonce, checkpoint=old_checkpoint,
                    pin=old_pin, observation=old_observation))
        self.assertEqual(stale.head, self.witness.head)

    def test_before_commit_failure_returns_no_proof_and_rolls_back(self):
        old = self.witness.head; self.changed_source()
        def event(phase):
            if phase == 'before_commit': raise OSError('INJECTED')
        with patch.object(self.witness, '_event', side_effect=event):
            with self.assertRaises(OSError): self.proof()
        self.assertEqual(self.reopen().head, old)
        self.live.reader.verify(self.proof(self.reopen()))
        self.assertEqual(self.witness.head['sequence'], old['sequence']+1)

    def test_after_commit_failure_retry_does_not_double_advance(self):
        old = self.witness.head; self.changed_source()
        def event(phase):
            if phase == 'after_commit': raise OSError('INJECTED')
        with patch.object(self.witness, '_event', side_effect=event):
            with self.assertRaises(OSError): self.proof()
        head = self.reopen().head
        self.assertEqual(head['sequence'], old['sequence']+1)
        self.live.reader.verify(self.proof(self.reopen()))
        self.assertEqual(self.witness.head, head)

    def test_expiry_after_commit_never_returns_an_expired_proof(self):
        self.changed_source()
        def event(phase):
            if phase == 'after_commit': self.live.now += timedelta(seconds=31)
        with patch.object(self.witness, '_event', side_effect=event):
            self.reject('E_EXPIRED', self.proof)
        head = self.reopen().head
        self.live.reader.verify(self.proof(self.reopen()))
        self.assertEqual(self.witness.head, head)

    def test_wrong_external_signer_never_replaces_or_creates_state(self):
        old = (self.directory/'reader.sqlite3').read_bytes()
        self.reject('E_WITNESS_SIGNER', lambda: self.reopen(Ed25519PrivateKey.generate()))
        self.assertEqual((self.directory/'reader.sqlite3').read_bytes(), old)

    def test_invalid_signer_response_never_corrupts_saved_head(self):
        delegate = self.signer
        class BadSigner:
            def public_key(self): return delegate.public_key()
            def sign(self, message): return b'INVALID'
        witness = self.reopen(BadSigner()); old = witness.head
        self.changed_source()
        self.reject('E_INTEGRITY', lambda: self.proof(witness))
        self.assertEqual(self.reopen().head, old)

    def test_missing_state_never_regenerates_store_or_key(self):
        (self.directory/'reader.sqlite3').unlink()
        with self.assertRaises(OSError): self.reopen()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_unknown_schema_fails_closed(self):
        with sqlite3.connect(self.directory/'reader.sqlite3') as db:
            db.execute('CREATE TABLE sqliteXextra(x)')
        self.reject('E_READER_STORAGE', self.reopen)

    def test_corrupt_saved_signature_fails_closed(self):
        with sqlite3.connect(self.directory/'reader.sqlite3') as db:
            state = json.loads(db.execute('SELECT body FROM reader_state').fetchone()[0])
            state['proof']['signature'] = 'INVALID'
            db.execute('UPDATE reader_state SET body=?', (canonical(state).decode(),))
        self.reject('E_INTEGRITY', self.reopen)

    def test_new_process_reopens_with_external_signer_and_existing_head(self):
        self.changed_source(); self.live.reader.verify(self.proof())
        code = '''
import json,sys
from datetime import datetime
sys.path.insert(0,sys.argv[1])
from recovery_durable_live_witness import DurableLiveWitness
from cryptography.hazmat.primitives import serialization
key=serialization.load_pem_private_key(sys.stdin.buffer.read(),None)
w=DurableLiveWitness(sys.argv[2],json.loads(sys.argv[3]),key,lambda:datetime.fromisoformat(sys.argv[4]))
print(json.dumps(w.head))
'''
        result = subprocess.run([sys.executable, '-c', code, str(Path(__file__).resolve().parents[1]),
            str(self.directory), json.dumps(self.trust), stamp(self.live.now)],
            input=self.signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), self.witness.head)

    def test_two_writers_reload_floor_after_sqlite_lock_contention(self):
        first, stale = self.reopen(), self.reopen()
        old_path, old_pin = self.live.checkpoint, self.live.pin
        old_nonce = secrets.token_hex(32); old_obs = self.live.observation(old_nonce)
        self.changed_source()
        new_nonce = secrets.token_hex(32); new_obs = self.live.observation(new_nonce)
        holding, release, competing = threading.Event(), threading.Event(), threading.Event()
        outcomes = {}
        def event(phase):
            if phase == 'before_commit':
                holding.set()
                if not release.wait(5): raise RuntimeError('TEST_BARRIER_TIMEOUT')
        first._event = event
        original_connect = stale._store._connect
        def connect():
            db = original_connect()
            db.set_trace_callback(lambda sql: competing.set() if sql == 'BEGIN IMMEDIATE' else None)
            return db
        stale._store._connect = connect
        def answer(name, witness, nonce, path, pin, obs):
            try:
                outcomes[name] = witness.answer(nonce, checkpoint=path, pin=pin, observation=obs)
            except Exception as error:
                outcomes[name] = error
        a = threading.Thread(target=answer, args=('new',first,new_nonce,self.live.checkpoint,self.live.pin,new_obs))
        b = threading.Thread(target=answer, args=('old',stale,old_nonce,old_path,old_pin,old_obs))
        try:
            a.start(); self.assertTrue(holding.wait(5))
            b.start(); self.assertTrue(competing.wait(5))
        finally:
            release.set(); a.join(6)
            if b.ident is not None: b.join(6)
        self.assertFalse(a.is_alive()); self.assertFalse(b.is_alive())
        self.assertIsInstance(outcomes['new'], dict)
        self.assertIsInstance(outcomes['old'], Fault)
        self.assertEqual(outcomes['old'].code, 'E_WITNESS_ROLLBACK')
        self.assertEqual(self.reopen().head, outcomes['new']['payload']['head'])

    def test_bootstrap_pin_nonce_and_existing_directory_require_explicit_enrollment(self):
        other = self.live.f.root/'other'
        nonce = self.live.reader.challenge(); proof = self.proof()
        self.reject('E_WITNESS_NONCE', lambda: DurableLiveWitness.enroll(other, self.trust,
                    self.signer, proof, nonce, digest(self.witness.head), self.clock))
        self.assertFalse(other.exists())
        nonce = proof['payload']['nonce']
        self.reject('E_READER_ENROLLMENT', lambda: DurableLiveWitness.enroll(other, self.trust,
                    self.signer, proof, nonce, '0'*64, self.clock))
        self.assertFalse(other.exists())
        with self.assertRaises(FileExistsError):
            DurableLiveWitness.enroll(self.directory,self.trust,self.signer,proof,nonce,
                                      digest(self.witness.head),self.clock)

    def test_store_contains_only_public_trust_and_signed_metadata(self):
        self.live.reader.verify(self.proof())
        raw = (self.directory/'reader.sqlite3').read_bytes()
        private = self.signer.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        for secret in (private, b'KEEP_SYNTHETIC', self.live.f.owner.encode(), b'PRIVATE KEY'):
            self.assertNotIn(secret, raw)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory/'reader.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_historical_store_is_readable_but_cannot_answer_without_live_observation(self):
        self.live.now += timedelta(hours=2)
        restarted = self.reopen()
        self.assertEqual(restarted.head, self.witness.head)
        self.reject('E_WITNESS_UNAVAILABLE', lambda: restarted.answer(self.live.reader.challenge()))

    def test_negative_whole_source_and_witness_store_rollback_needs_independent_reader(self):
        saved_store = (self.directory/'reader.sqlite3').read_bytes()
        source = self.live.f.current; saved_source = self.live.f.root/'source-backup'
        shutil.copytree(source, saved_source)
        old_checkpoint, old_pin = self.live.checkpoint, self.live.pin
        self.changed_source(); self.live.reader.verify(self.proof())
        shutil.rmtree(source); shutil.copytree(saved_source, source)
        (self.directory/'reader.sqlite3').write_bytes(saved_store)
        self.live.checkpoint, self.live.pin = old_checkpoint, old_pin
        proof = self.proof(self.reopen())
        self.reject('E_WITNESS_ROLLBACK', lambda: self.live.reader.verify(proof))
        # Losing the reader floor too permits the old signed state: explicit limit.
        fresh = WitnessReader(clock=self.clock, **self.trust)
        fresh._challenge = proof['payload']['nonce']
        self.assertEqual(fresh.verify(proof), old_pin)


if __name__ == '__main__':
    unittest.main()
