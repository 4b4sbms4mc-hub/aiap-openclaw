# SPDX-License-Identifier: Apache-2.0
"""Private local Mirror files, serialized by the owning Core's transaction."""
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from uuid import uuid4

from .contracts import Fault, canonical, digest, exact, require
from .service import save_private


def path_for(service, avatar, space):
    return service.directory / ('owner-mirror-' + digest([avatar, space]) + '.json')


def read(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise Fault('E_MIRROR_FILE') from None
    try:
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
                    and os.path.samestat(info, path.lstat()), 'E_MIRROR_FILE')
            if hasattr(os, 'geteuid'):
                require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'E_MIRROR_FILE')
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'E_MIRROR_FILE')
        record = json.loads(raw)
        exact(record, ['generation', 'portrait'])
        require(isinstance(record['generation'], str) and len(record['generation']) == 32, 'E_MIRROR_FILE')
        return record
    except (OSError, ValueError, RecursionError):
        raise Fault('E_MIRROR_FILE') from None


def write(path, portrait):
    record = {'generation': uuid4().hex, 'portrait': portrait}
    data = canonical(record)
    require(len(data) <= 65536, 'E_MIRROR_INPUT_SIZE')
    with TemporaryDirectory(prefix='.aiap-mirror-', dir=path.parent) as directory:
        staged = Path(directory) / 'pending'
        save_private(staged, data)
        with staged.open('rb') as stream:
            os.fsync(stream.fileno())
        staged.replace(path)
