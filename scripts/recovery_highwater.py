# SPDX-License-Identifier: Apache-2.0
"""Experimental persistent reader high-water state on a trusted local filesystem.

Not a durable witness, source mutation gate, remote service or activation grant.
Whole-store rollback/deletion by the storage owner is outside this guarantee.
"""
from copy import deepcopy
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from recovery_guard import canonical, digest, strict_json, require, parse
from recovery_witness import WitnessReader

TABLE = 'CREATE TABLE reader_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)'


def private_path(path, directory=False):
    info = Path(path).lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_mode & 0o077 == 0 and info.st_uid == os.getuid(), 'E_READER_STORAGE')


class DurableWitnessReader:
    def __init__(self, state_dir, avatar, enrollment_sha256, generation, public_key, clock):
        self.directory = Path(state_dir)
        self.db = self.directory / 'reader.sqlite3'
        self.trust = dict(avatar=avatar, enrollment_sha256=enrollment_sha256,
                          generation=generation, public_key=public_key)
        self.clock = clock
        self._challenge = None
        # Opening is never enrollment. Missing/corrupt state is a hard failure.
        db = self._connect()
        try:
            self._load(db)
        finally:
            db.close()

    @classmethod
    def enroll(cls, state_dir, reader, proof, expected_head_sha256):
        """Explicit initial enrollment. Caller obtains trust and initial pin independently."""
        reader.verify(proof)
        require(digest(reader.head) == expected_head_sha256, 'E_READER_ENROLLMENT')
        directory = Path(state_dir)
        parent = directory.parent.stat()
        require(stat.S_ISDIR(parent.st_mode) and not parent.st_mode & 0o022
                and parent.st_uid == os.getuid(), 'E_READER_STORAGE')
        directory.mkdir(mode=0o700)  # exclusive: do not replace/re-enroll existing state
        path = directory / 'reader.sqlite3'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        trust = {key: getattr(reader, key) for key in
                 ('avatar', 'enrollment_sha256', 'generation', 'public_key')}
        state = {'format': 1, 'trust': trust, 'proof': deepcopy(proof)}
        db = sqlite3.connect(path, isolation_level=None)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute(TABLE)
            db.execute('INSERT INTO reader_state VALUES(1,?)', (canonical(state).decode(),))
            db.execute('COMMIT')
        finally:
            db.close()
        # Directory entry durability is requested on supported local POSIX filesystems.
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(directory, clock=reader.clock, **trust)

    def _connect(self):
        private_path(self.directory, directory=True)
        private_path(self.db)
        # mode=rw forbids automatic creation if the file disappears.
        db = sqlite3.connect(self.db.resolve().as_uri() + '?mode=rw', uri=True,
                             timeout=5, isolation_level=None)
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _load(self, db):
        require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'E_READER_STORAGE')
        objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        require(objects == [('table', 'reader_state', TABLE)], 'E_READER_STORAGE')
        rows = db.execute('SELECT id,body FROM reader_state').fetchall()
        require(len(rows) == 1 and rows[0][0] == 1, 'E_READER_STORAGE')
        state = strict_json(rows[0][1])
        require(set(state) == {'format', 'trust', 'proof'} and type(state['format']) is int
                and state['format'] == 1 and state['trust'] == self.trust, 'E_READER_ENROLLMENT')
        proof = state['proof']
        # Historical evidence authenticates the saved head. It is not a fresh reply.
        historical = WitnessReader(clock=lambda: parse(proof['payload']['issued_at']), **self.trust)
        historical._challenge = proof['payload']['nonce']
        historical.verify(proof)
        return historical.head

    @property
    def head(self):
        db = self._connect()
        try:
            return self._load(db)
        finally:
            db.close()

    def challenge(self):
        self._challenge = secrets.token_hex(32)
        return self._challenge

    def _commit(self, db):
        db.execute('COMMIT')

    def verify(self, proof):
        nonce, self._challenge = self._challenge, None
        require(nonce is not None, 'E_WITNESS_NONCE')
        db = self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            saved_head = self._load(db)  # reload under writer lock, never trust stale object state
            reader = WitnessReader(clock=self.clock, **self.trust)
            reader._head, reader._challenge = saved_head, nonce
            pin = reader.verify(proof)
            state = {'format': 1, 'trust': self.trust, 'proof': deepcopy(proof)}
            db.execute('UPDATE reader_state SET body=? WHERE id=1', (canonical(state).decode(),))
            self._commit(db)  # never return a pin before successful durable transaction commit
            now = self.clock()
            require(parse(proof['payload']['issued_at']) <= now <
                    parse(proof['payload']['expires_at']), 'E_EXPIRED')
            return pin
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()
