# SPDX-License-Identifier: Apache-2.0
"""POSIX local-only source/witness coordination experiment, not a production gate.

Only ExperimentalGatedService transactions participate. Production Service, direct
SQL, source/control whole-store rollback and remote activation remain outside it.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import secrets
import tempfile

from recovery_guard import (Service, canonical, digest, b64, unb64, read_file,
                            strict_json, require, Fault, export_checkpoint, load_checkpoint, parse)
from recovery_highwater import private_path
from recovery_witness import SyntheticWitness, monotonic_head, hex_digest, PROFILE
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def governance(db):
    meta = {row[0]: strict_json(row[1]) for row in db.execute('SELECT key,value FROM meta')}
    return {'core': strict_json(db.execute('SELECT body FROM cores WHERE avatar=?',
                                          (meta['avatar'],)).fetchone()[0]),
            'spaces': [dict(row) for row in db.execute('SELECT * FROM spaces ORDER BY id')],
            'tombstones': [dict(row) for row in db.execute('SELECT * FROM tombstones ORDER BY id')],
            'revocation_epoch': meta['revocation_epoch']}


def bound_digest(db, witness):
    enrollment = Service('.').meta(db, 'enrollment')
    require(digest(enrollment) == witness.enrollment_sha256, 'E_IDENTITY')
    current = governance(db)
    require(current['core']['avatar_id'] == witness.avatar
            and Service('.').meta(db, 'avatar') == witness.avatar
            and Service('.').meta(db, 'owner') == current['core']['owner']['owner_ref'], 'E_IDENTITY')
    return digest(current)


class SourceGate:
    def __init__(self, source_dir, control_dir, trust, clock):
        self.source = Path(source_dir).resolve()
        self.directory = Path(control_dir)
        require(not self.directory.resolve().is_relative_to(self.source)
                and not self.source.is_relative_to(self.directory.resolve()), 'E_GATE_LOCATION')
        self.trust, self.clock = dict(trust), clock
        with self._lock():
            self._load()

    @classmethod
    def enroll(cls, source_dir, control_dir, checkpoint, pin, clock):
        source, directory = Path(source_dir).resolve(), Path(control_dir)
        require(not directory.resolve().is_relative_to(source)
                and not source.is_relative_to(directory.resolve()), 'E_GATE_LOCATION')
        payload, _ = load_checkpoint(checkpoint, pin, clock())
        with Service(source, clock=clock).tx() as db:
            require(digest(governance(db)) == digest({k: payload[k] for k in
                    ('core', 'spaces', 'tombstones', 'revocation_epoch')}), 'E_SOURCE_DIVERGED')
            enrollment = Service(source).meta(db, 'enrollment')
            require(enrollment == payload['enrollment'], 'E_IDENTITY')
        private_path(directory.parent, directory=True)
        directory.mkdir(mode=0o700)
        fd = os.open(directory / 'gate.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        w = SyntheticWitness(payload['core']['avatar_id'], digest(payload['enrollment']), clock)
        ticket = w.begin_update(0)
        w.publish(ticket, checkpoint, pin)
        trust = dict(avatar=w.avatar, enrollment_sha256=w.enrollment_sha256,
                     generation=w.generation, public_key=w.public_key)
        gate = object.__new__(cls)
        gate.source, gate.directory, gate.trust, gate.clock = source, directory, trust, clock
        with gate._lock():
            name = 'checkpoint-' + pin + '.json'
            gate._write(directory / name, read_file(checkpoint))
            gate._save(w, name)
        return cls(source, directory, trust, clock)

    @contextmanager
    def _lock(self, blocking=True):
        private_path(self.directory, directory=True)
        lock = self.directory / 'gate.lock'
        private_path(lock)
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Fault('E_WITNESS_UNAVAILABLE') from None
            yield
        finally:
            os.close(fd)

    def _write(self, path, raw):
        fd, name = tempfile.mkstemp(prefix='.gate-write-', dir=self.directory)
        try:
            with os.fdopen(fd, 'wb') as file:
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            os.replace(name, path)
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _save(self, w, checkpoint_name):
        state = {'format': 1, 'source': str(self.source), 'trust': self.trust,
                 'key': b64(w._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                 'head': w.head, 'pending': w._pending, 'checkpoint': checkpoint_name}
        self._write(self.directory / 'gate-state.json', canonical(state))

    def _load(self):
        path = self.directory / 'gate-state.json'
        private_path(path)
        state = strict_json(read_file(path))
        require(set(state) == {'format', 'source', 'trust', 'key', 'head', 'pending', 'checkpoint'}
                and type(state['format']) is int and state['format'] == 1
                and state['source'] == str(self.source) and state['trust'] == self.trust, 'E_GATE_ENROLLMENT')
        w = SyntheticWitness(self.trust['avatar'], self.trust['enrollment_sha256'], self.clock)
        w._key = Ed25519PrivateKey.from_private_bytes(unb64(state['key']))
        w.generation, w._head, w._pending = self.trust['generation'], state['head'], state['pending']
        require(w.public_key == self.trust['public_key'] and monotonic_head(None, w.head)
                and w.head['avatar_id'] == w.avatar
                and w.head['enrollment_sha256'] == w.enrollment_sha256
                and w.head['generation'] == w.generation and w.head['profile'] == PROFILE, 'E_GATE_ENROLLMENT')
        require(w._pending is None or hex_digest(w._pending), 'E_SCHEMA')
        require(state['checkpoint'] == 'checkpoint-' + w.head['checkpoint_sha256'] + '.json', 'E_SCHEMA')
        return w, state['checkpoint']

    def _event(self, phase):
        """Deterministic fault barrier, overridden only by isolated tests."""

    def _publish_current(self, w, expected_governance=None):
        require(w._pending is not None, 'E_WITNESS_PENDING')
        path = self.directory / ('checkpoint-' + secrets.token_hex(32) + '.json')
        try:
            result = export_checkpoint(self.source, path, clock=self.clock)
            pin = result['checkpoint_sha256']
            fixed = self.directory / ('checkpoint-' + pin + '.json')
            self._write(fixed, read_file(path))
        finally:
            if path.exists():
                path.unlink()
        self._event('checkpoint_exported')
        payload, _ = load_checkpoint(fixed, pin, self.clock())
        captured = digest({k: payload[k] for k in ('core', 'spaces', 'tombstones', 'revocation_epoch')})
        # Keep the source SQLite writer lock through head publication, so a
        # checkpoint captured before an intervening source change cannot publish.
        with Service(self.source, clock=self.clock).tx() as db:
            require(bound_digest(db, w) == captured, 'E_SOURCE_DIVERGED')
            require(expected_governance is None or captured == expected_governance, 'E_SOURCE_DIVERGED')
            w.publish(w._pending, fixed, pin)
            self._save(w, fixed.name)
        self._event('head_published')
        return w.head

    @property
    def head(self):
        with self._lock():
            return self._load()[0].head

    def answer(self, nonce):
        with self._lock(blocking=False):
            w, name = self._load()
            require(w._pending is None, 'E_WITNESS_UNAVAILABLE')
            with Service(self.source, clock=self.clock).tx() as db:
                require(bound_digest(db, w) == w.head['governance_sha256'], 'E_SOURCE_DIVERGED')
                load_checkpoint(self.directory / name, w.head['checkpoint_sha256'], self.clock())
                return w.answer(nonce)

    def refresh(self, expected_sequence):
        """Explicit renewal from an unchanged live source, not a backup TTL rewrite."""
        with self._lock():
            w, name = self._load()
            require(w._pending is None, 'E_WITNESS_PENDING')
            require(type(expected_sequence) is int and expected_sequence == w.head['sequence'],
                    'E_WITNESS_SEQUENCE')
            head = w.head
            require(self.clock() >= parse(head['checkpoint_issued_at']), 'E_EXPIRED')
            # Expired historical evidence still authenticates the old selected state.
            payload, _ = load_checkpoint(self.directory / name, head['checkpoint_sha256'],
                                         parse(head['checkpoint_issued_at']))
            require(digest(payload['enrollment']) == w.enrollment_sha256
                    and digest({k: payload[k] for k in
                        ('core', 'spaces', 'tombstones', 'revocation_epoch')}) == head['governance_sha256']
                    and payload['core']['revision'] == head['core_revision']
                    and payload['revocation_epoch'] == head['revocation_epoch']
                    and payload['issued_at'] == head['checkpoint_issued_at']
                    and payload['expires_at'] == head['checkpoint_expires_at'], 'E_INTEGRITY')
            with Service(self.source, clock=self.clock).tx() as db:
                require(bound_digest(db, w) == head['governance_sha256'], 'E_SOURCE_DIVERGED')
            w.begin_update(head['sequence'])
            self._save(w, name)
            self._event('refresh_pending_saved')
            return self._publish_current(w, expected_governance=head['governance_sha256'])

    def resync(self):
        """Explicit recovery after uncertain outcome; never repeats the source mutation."""
        with self._lock():
            w, name = self._load()
            if w._pending is None:
                with Service(self.source, clock=self.clock).tx() as db:
                    require(bound_digest(db, w) == w.head['governance_sha256'], 'E_SOURCE_DIVERGED')
                return w.head  # already published: idempotent inspection, not re-enrollment
            return self._publish_current(w)


class ExperimentalGatedService(Service):
    def __init__(self, gate):
        super().__init__(gate.source, clock=gate.clock)
        self.gate = gate

    def initialize(self):
        raise Fault('E_OPERATION_UNSUPPORTED')  # enrollment requires a separately initialized Core

    @contextmanager
    def tx(self):
        with self.gate._lock():
            w, checkpoint_name = self.gate._load()
            require(w._pending is None, 'E_WITNESS_PENDING')
            changed = False
            with super().tx() as db:
                before = bound_digest(db, w)
                require(before == w.head['governance_sha256'], 'E_SOURCE_DIVERGED')
                yield db
                changed = bound_digest(db, w) != before
                if changed:
                    w.begin_update(w.head['sequence'])
                    self.gate._save(w, checkpoint_name)  # must succeed BEFORE source commit
                    self.gate._event('pending_saved')
            if changed:
                self.gate._event('source_committed')
                self.gate._publish_current(w)
