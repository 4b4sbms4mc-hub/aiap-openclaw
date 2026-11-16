# SPDX-License-Identifier: Apache-2.0
"""Local checkpoint registration for a single independently pinned enrollment."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

from .contracts import Fault, canonical, digest, exact, require
from .recovery_checkpoint import load_checkpoint, strict_json
from .recovery_observation import verify_observation
from .service import parse, stamp

TABLE = ('CREATE TABLE registry (id INTEGER PRIMARY KEY CHECK(id=1), '
         'enrollment_sha256 TEXT NOT NULL, head TEXT)')
GOVERNANCE = ('core', 'spaces', 'tombstones', 'revocation_epoch')


def _digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _time(value):
    require(isinstance(value, str), 'E_RECOVERY_REGISTRY')
    dt = parse(value)
    require(dt.utcoffset() is not None, 'E_RECOVERY_REGISTRY')
    return dt


def _private_path(path, directory=False):
    info = path.lstat()
    mode_check = stat.S_ISDIR if directory else stat.S_ISREG
    require(mode_check(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, 'E_RECOVERY_REGISTRY')


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CheckpointRegistry:
    def __init__(self, directory, core_data_dir, clock=None):
        self.directory = Path(directory)
        self.path = self.directory / 'registry.sqlite3'
        self.core = Path(core_data_dir).resolve()
        location = self.directory.resolve()
        require(not location.is_relative_to(self.core) and not self.core.is_relative_to(location),
                'E_RECOVERY_REGISTRY_LOCATION')
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _check_parent(self):
        info = self.directory.parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o022, 'E_RECOVERY_REGISTRY')

    @contextmanager
    def _transaction(self, write=False, *, reserve_head=False):
        try:
            self._check_parent()
            _private_path(self.directory, directory=True)
            _private_path(self.path)
            mode = 'rw' if write or reserve_head else 'ro'
            db = sqlite3.connect(self.path.absolute().as_uri() + '?mode=' + mode,
                                 uri=True, timeout=5, isolation_level=None)
            try:
                db.execute('PRAGMA trusted_schema=OFF')
                if write:
                    db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE' if write or reserve_head else 'BEGIN')
                yield db
                if not reserve_head:
                    db.commit()
            finally:
                db.close()
        except (OSError, sqlite3.Error, ValueError, RecursionError) as exc:
            raise Fault('E_RECOVERY_REGISTRY') from exc

    def initialize(self, enrollment_sha256):
        require(_digest(enrollment_sha256), 'E_RECOVERY_ENROLLMENT_PIN')
        parent = self.directory.parent
        try:
            self._check_parent()
            self.directory.mkdir(mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with self._transaction(write=True) as db:
                db.execute(TABLE)
                db.execute('INSERT INTO registry VALUES (1, ?, NULL)', (enrollment_sha256,))
            _sync_dir(self.directory)
            _sync_dir(parent)
        except FileExistsError as exc:
            raise Fault('E_RECOVERY_REGISTRY_EXISTS', 409) from exc
        except OSError as exc:
            raise Fault('E_RECOVERY_REGISTRY') from exc
        return self._report(enrollment_sha256, None, 'registry-initialized')

    def _read(self, db):
        objects = db.execute("SELECT type,name,sql FROM sqlite_master "
                             "WHERE name NOT GLOB 'sqlite_*'").fetchall()
        require(objects == [('table', 'registry', TABLE)], 'E_RECOVERY_REGISTRY')
        rows = db.execute('SELECT id,enrollment_sha256,head FROM registry').fetchall()
        require(len(rows) == 1 and rows[0][0] == 1 and _digest(rows[0][1]), 'E_RECOVERY_REGISTRY')
        _, enrollment, raw = rows[0]
        if raw is None:
            return enrollment, None
        require(isinstance(raw, str) and len(raw) <= 2048, 'E_RECOVERY_REGISTRY')
        head = strict_json(raw)
        exact(head, ['checkpoint_sha256', 'governance_sha256', 'core_revision',
                     'revocation_epoch', 'issued_at', 'expires_at', 'registered_at'])
        require(_digest(head['checkpoint_sha256']) and _digest(head['governance_sha256'])
                and type(head['core_revision']) is int and head['core_revision'] >= 1
                and type(head['revocation_epoch']) is int and head['revocation_epoch'] >= 0,
                'E_RECOVERY_REGISTRY')
        issued, expires = _time(head['issued_at']), _time(head['expires_at'])
        require(issued <= _time(head['registered_at']) < expires
                and expires - issued <= timedelta(hours=24), 'E_RECOVERY_REGISTRY')
        return enrollment, head

    def _candidate(self, checkpoint_path, checkpoint_sha256, enrollment, now):
        checkpoint = Path(checkpoint_path)
        require(not checkpoint.resolve().is_relative_to(self.core), 'E_CHECKPOINT_LOCATION')
        try:
            payload, refs = load_checkpoint(checkpoint, checkpoint_sha256, now)
        except (OSError, ValueError, AttributeError, TypeError, KeyError, RecursionError) as exc:
            raise Fault('E_CHECKPOINT_INPUT') from exc
        require(digest(payload['enrollment']) == enrollment, 'E_RECOVERY_ENROLLMENT_PIN')
        head = {
            'checkpoint_sha256': checkpoint_sha256,
            'governance_sha256': digest({key: payload[key] for key in GOVERNANCE}),
            'core_revision': payload['core']['revision'],
            'revocation_epoch': payload['revocation_epoch'],
            'issued_at': payload['issued_at'],
            'expires_at': payload['expires_at'],
        }
        return head, payload, refs

    def register(self, checkpoint_path, checkpoint_sha256):
        with self._transaction(write=True) as db:
            enrollment, previous = self._read(db)
            now = self.clock()
            head, _, _ = self._candidate(checkpoint_path, checkpoint_sha256, enrollment, now)
            registered = self.clock()
            require(registered >= now and (previous is None or registered >= _time(previous['registered_at'])),
                    'E_RECOVERY_CLOCK_ROLLBACK')
            require(registered < _time(head['expires_at']), 'E_EXPIRED')
            head['registered_at'] = stamp(registered)
            status = 'checkpoint-registered'
            if previous and head['checkpoint_sha256'] == previous['checkpoint_sha256']:
                require(all(head[key] == previous[key] for key in head if key != 'registered_at'),
                        'E_RECOVERY_REGISTRY')
                head, status = previous, 'checkpoint-already-registered'
            elif previous:
                revision, epoch = head['core_revision'], head['revocation_epoch']
                old_revision, old_epoch = previous['core_revision'], previous['revocation_epoch']
                require(revision >= old_revision and epoch >= old_epoch
                        and _time(head['issued_at']) > _time(previous['issued_at']),
                        'E_CHECKPOINT_ROLLBACK')
                if (revision, epoch) == (old_revision, old_epoch):
                    require(head['governance_sha256'] == previous['governance_sha256'],
                            'E_CHECKPOINT_DIVERGENCE')
            if status == 'checkpoint-registered':
                db.execute('UPDATE registry SET head=? WHERE id=1', (canonical(head).decode(),))
        return self._report(enrollment, head, status)

    def status(self):
        with self._transaction() as db:
            enrollment, head = self._read(db)
        return self._report(enrollment, head, 'checkpoint-recorded' if head else 'registry-empty')

    def review(self, checkpoint_path):
        """Reverify the exact registered file without reading a backup or granting restoration."""
        with self._transaction() as db:
            report, _ = self._review(db, checkpoint_path)
            return report

    def review_live(self, checkpoint_path, observe):
        """Validate a fresh point-in-time source observation via a trusted caller's transport.

        observe(nonce, checkpoint_sha256) returns the signed Avatar v2 envelope.
        Transport configuration, timeouts and source access belong to the caller.
        This method neither signs a witness proof nor authorizes restoration.
        """
        with self._verified_source(checkpoint_path, observe) as report:
            return report

    @contextmanager
    def _verified_source(self, checkpoint_path, observe, *, expected=None, reserve_head=False):
        with self._transaction() as db:
            before, _ = self._review(db, checkpoint_path, expected=expected)
        started = self.clock()
        require(started >= _time(before['head']['registered_at']), 'E_RECOVERY_CLOCK_ROLLBACK')
        require(started < _time(before['head']['expires_at']), 'E_EXPIRED')
        nonce = secrets.token_hex(32)
        # Do not keep a registry transaction open across transport I/O.
        envelope = observe(nonce, before['head']['checkpoint_sha256'])
        # For publication, prevent other registry writers changing the head after
        # verification and before rename. No registry write or commit is needed.
        with self._transaction(reserve_head=reserve_head) as db:
            after, payload = self._review(db, checkpoint_path, expected=before)
            now = self.clock()
            require(now >= started, 'E_RECOVERY_CLOCK_ROLLBACK')
            verify_observation(envelope, nonce, after['head']['checkpoint_sha256'],
                               payload, after['enrollment_sha256'], now)
            proof = envelope['payload']
            verified = self.clock()
            require(verified >= now, 'E_RECOVERY_CLOCK_ROLLBACK')
            require(verified < _time(proof['expires_at']), 'E_EXPIRED')
            yield dict(after, status='source-observation-verified',
                       source_currentness_verified=True,
                       source_observed_at=proof['issued_at'],
                       source_observation_expires_at=proof['expires_at'],
                       verified_at=stamp(verified))

    def _review(self, db, checkpoint_path, expected=None):
        enrollment, head = self._read(db)
        require(head is not None, 'E_RECOVERY_REGISTRY_EMPTY')
        if expected is not None:
            require(head == expected['head'] and enrollment == expected['enrollment_sha256'],
                    'E_RECOVERY_REGISTRY_CHANGED')
        now = self.clock()
        require(now >= _time(head['registered_at']), 'E_RECOVERY_CLOCK_ROLLBACK')
        actual, payload, refs = self._candidate(
            checkpoint_path, head['checkpoint_sha256'], enrollment, now)
        require(actual == {key: value for key, value in head.items() if key != 'registered_at'},
                'E_RECOVERY_REGISTRY')
        report = self._report(enrollment, head, 'checkpoint-matches-registration', not_before=now)
        require(report['checkpoint_window'] == 'within-validity-window', 'E_EXPIRED')
        return dict(report, current_object_count=len(refs),
                    tombstone_count=len(payload['tombstones'])), payload

    def _report(self, enrollment, head, status, not_before=None):
        now = self.clock()
        require(not_before is None or now >= not_before, 'E_RECOVERY_CLOCK_ROLLBACK')
        window = (None if head is None else
                  'clock-before-registration' if now < _time(head['registered_at']) else
                  'expired' if now >= _time(head['expires_at']) else 'within-validity-window')
        return {'profile': 'x-aiap-local-checkpoint-registry-v1', 'status': status,
                'enrollment_sha256': enrollment, 'head': head, 'checkpoint_window': window,
                'source_currentness_verified': False, 'restore_authorized': False}
