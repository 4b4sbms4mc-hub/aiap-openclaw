# SPDX-License-Identifier: Apache-2.0
"""Isolated independent witness persistence with an externally supplied signer.

No server or production key provider. Only public trust and signed metadata are
stored. A trusted local filesystem and independently retained reader are needed;
whole-store rollback is outside the storage guarantee.
"""
from copy import deepcopy

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from recovery_guard import b64, canonical, require, parse
from recovery_highwater import DurableWitnessReader
from recovery_live_observation import LiveObservationWitness
from recovery_witness import WitnessReader


class DurableLiveWitness:
    """Reuse the tested signed-proof SQLite store, not its reader challenge API.

    Source writers never reference this store. Each answer needs a fresh source
    observation. Opening never creates state, a generation or a signing key.
    """
    def __init__(self, state_dir, trust, signer, clock):
        self.trust, self.signer, self.clock = dict(trust), signer, clock
        self._check_signer()
        self._store = DurableWitnessReader(state_dir, clock=clock, **self.trust)

    def _check_signer(self):
        require(b64(self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
                == self.trust['public_key'], 'E_WITNESS_SIGNER')

    @classmethod
    def enroll(cls, state_dir, trust, signer, proof, nonce, expected_head_sha256, clock):
        # Verify signer and explicit bootstrap challenge/pin before creating files.
        candidate = object.__new__(cls)
        candidate.trust, candidate.signer = dict(trust), signer
        candidate._check_signer()
        reader = WitnessReader(clock=clock, **trust)
        reader._challenge = nonce
        DurableWitnessReader.enroll(state_dir, reader, proof, expected_head_sha256)
        return cls(state_dir, trust, signer, clock)

    @property
    def head(self):
        return self._store.head

    def _event(self, phase):
        """Fault barrier for isolated tests only."""

    def answer(self, nonce, *, checkpoint=None, pin=None, observation=None):
        self._check_signer()
        db = self._store._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            head = self._store._load(db)  # reread under writer lock, including on stale instances
            witness = object.__new__(LiveObservationWitness)
            witness.avatar = self.trust['avatar']
            witness.enrollment_sha256 = self.trust['enrollment_sha256']
            witness.generation = self.trust['generation']
            witness.clock, witness._key = self.clock, self.signer
            witness._head, witness._pending = deepcopy(head), None
            proof = witness.answer(nonce, checkpoint=checkpoint, pin=pin, observation=observation)
            # A provider returning malformed signatures must never corrupt the store.
            verifier = WitnessReader(clock=self.clock, **self.trust)
            verifier._head, verifier._challenge = head, nonce
            verifier.verify(proof)
            state = {'format': 1, 'trust': self.trust, 'proof': deepcopy(proof)}
            db.execute('UPDATE reader_state SET body=? WHERE id=1', (canonical(state).decode(),))
            self._event('before_commit')
            self._store._commit(db)
            self._event('after_commit')
            now = self.clock()
            require(parse(proof['payload']['issued_at']) <= now <
                    parse(proof['payload']['expires_at']), 'E_EXPIRED')
            return proof  # no response before successful commit and final expiry check
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()
