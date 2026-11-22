# SPDX-License-Identifier: Apache-2.0
"""Coordinate local isolated recovery against a pinned backup and live source."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat

from .contracts import Fault, require
from .recovery_snapshot import restore_snapshot

MAX_BACKUP = 64 * 1024 * 1024


def _verify_backup(snapshot, expected):
    require(not any(os.path.lexists(snapshot / ('core.sqlite3' + suffix))
                    for suffix in ('-wal', '-shm', '-journal')), 'E_OPERATION_UNSUPPORTED')
    fd = os.open(snapshot / 'core.sqlite3', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        size = os.fstat(file.fileno())
        require(stat.S_ISREG(size.st_mode) and size.st_size <= MAX_BACKUP, 'E_RECOVERY_FILE')
        total = 0
        checksum = hashlib.sha256()
        while chunk := file.read(1024 * 1024):
            total += len(chunk)
            require(total <= MAX_BACKUP, 'E_RECOVERY_FILE')
            checksum.update(chunk)
        require(total == size.st_size and checksum.hexdigest() == expected, 'E_RECOVERY_BACKUP_PIN')


def restore_isolated(registry, checkpoint, snapshot, snapshot_sha256, target, observe):
    require(isinstance(snapshot_sha256, str) and re.fullmatch('[0-9a-f]{64}', snapshot_sha256),
            'E_RECOVERY_BACKUP_PIN')
    checkpoint, snapshot, target = map(Path, (checkpoint, snapshot, target))
    try:
        core, control = registry.core, registry.directory.resolve()
        backup, output = snapshot.resolve(), target.resolve()
        paths = (core, control, backup, output)
        require(not any(a.is_relative_to(b) for i, a in enumerate(paths)
                        for j, b in enumerate(paths) if i != j), 'E_RECOVERY_LOCATION')
        require(not checkpoint.resolve().is_relative_to(backup), 'E_CHECKPOINT_LOCATION')
        require(not os.path.lexists(target), 'E_OUTPUT_EXISTS')
        info = snapshot.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077, 'E_RECOVERY_FILE')
        before = registry.review_live(checkpoint, observe)
        _verify_backup(snapshot, snapshot_sha256)

        @contextmanager
        def publication_guard():
            # Recheck the backup after staging, before requesting the final short-lived proof.
            _verify_backup(snapshot, snapshot_sha256)
            with registry._verified_source(checkpoint, observe, expected=before,
                                           reserve_head=True, index_only=True) as final:
                yield {
                    'backup_sha256': snapshot_sha256,
                    'governance_sha256': final['head']['governance_sha256'],
                    'core_revision': final['head']['core_revision'],
                    'revocation_epoch': final['head']['revocation_epoch'],
                    'source_observed_at': final['source_observed_at'],
                    'source_observation_expires_at': final['source_observation_expires_at'],
                    'verified_at': final['verified_at'],
                }

        return restore_snapshot(snapshot, checkpoint, before['head']['checkpoint_sha256'], target,
                                clock=registry.clock, publication_guard=publication_guard)
    except (OSError, RuntimeError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        raise Fault('E_RECOVERY_FILE') from exc
