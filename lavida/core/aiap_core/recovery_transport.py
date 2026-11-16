# SPDX-License-Identifier: Apache-2.0
"""Bounded Core client for an operator-managed Avatar v2 stdio launcher."""
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

from .contracts import Fault, canonical, exact, require
from .recovery_checkpoint import strict_json

RPC_PROFILE = 'x-aiap-source-observation-rpc-v2'
MAX_RESPONSE = 4096


def _trusted_executable(executable):
    path = Path(executable)
    require(path.is_absolute() and not path.is_symlink(), 'E_SOURCE_RPC_CONFIGURATION')
    path = path.resolve()
    trusted_uids = {0, os.getuid()}
    for parent in path.parents:
        info = parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in trusted_uids
                and not info.st_mode & 0o022, 'E_SOURCE_RPC_CONFIGURATION')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid in trusted_uids
            and not info.st_mode & 0o022 and os.access(path, os.X_OK), 'E_SOURCE_RPC_CONFIGURATION')
    return path


def trusted_stdio_observer(executable, *, timeout=10, outside=()):
    """Return an observer that sends only the nonce and checkpoint hash."""
    require(type(timeout) in (int, float) and 0 < timeout <= 15, 'E_SOURCE_RPC_CONFIGURATION')
    try:
        path = _trusted_executable(executable)
        require(not any(path.is_relative_to(Path(p).resolve()) for p in outside),
                'E_SOURCE_RPC_CONFIGURATION')
    except (OSError, RuntimeError) as exc:
        raise Fault('E_SOURCE_RPC_CONFIGURATION') from exc

    def observe(nonce, checkpoint_sha256):
        request = canonical({'profile': RPC_PROFILE, 'op': 'observe', 'nonce': nonce,
                             'checkpoint_sha256': checkpoint_sha256})
        child = None
        try:
            deadline = time.monotonic() + timeout
            # Run a fixed executable, without shell, inherited credentials, or a
            # working directory containing restore data. The launcher owns endpoint auth.
            child = subprocess.Popen([os.fspath(path)], cwd=path.parent,
                                     env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home())},
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)
            # Single write smaller than POSIX PIPE_BUF, into a fresh empty pipe.
            require(len(request) <= 512 and child.stdin.write(request) == len(request),
                    'E_SOURCE_RPC_TRANSPORT')
            child.stdin.close()
            output = bytearray()
            with selectors.DefaultSelector() as poll:
                poll.register(child.stdout, selectors.EVENT_READ)
                while poll.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'E_SOURCE_RPC_TRANSPORT')
                    for key, _ in poll.select(remaining):
                        part = os.read(key.fd, MAX_RESPONSE + 1 - len(output))
                        if not part:
                            poll.unregister(key.fileobj)
                        else:
                            output.extend(part)
                            require(len(output) <= MAX_RESPONSE, 'E_SOURCE_RPC_RESPONSE')
            remaining = deadline - time.monotonic()
            require(remaining > 0 and child.wait(timeout=remaining) == 0, 'E_SOURCE_RPC_TRANSPORT')
            reply = strict_json(bytes(output).decode('utf-8'))
            exact(reply, ['profile', 'status', 'observation'])
            require(reply['profile'] == RPC_PROFILE and reply['status'] == 'observed',
                    'E_SOURCE_RPC_RESPONSE')
            return reply['observation']
        except (OSError, subprocess.SubprocessError) as exc:
            raise Fault('E_SOURCE_RPC_TRANSPORT') from exc
        except (ValueError, RecursionError) as exc:
            raise Fault('E_SOURCE_RPC_RESPONSE') from exc
        finally:
            if child is not None:
                if child.returncode is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                child.stdin.close()
                child.stdout.close()

    return observe
