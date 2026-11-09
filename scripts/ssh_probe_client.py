# SPDX-License-Identifier: Apache-2.0
"""Bounded transport-probe exchange; not recovery/source proof verification."""
import json
import os
import re
import selectors
import subprocess
import time

from recovery_guard import Fault, require, strict_json
from ssh_transport_probe import PROFILE


def exchange(arguments, nonce, expected_uid, timeout=10, *, expected_rejection=False):
    require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{64}', nonce) is not None,
            'E_SSH_PROBE_REQUEST')
    require(type(expected_uid) is int and expected_uid > 0 and 0 < timeout <= 15
            and type(expected_rejection) is bool,
            'E_SSH_PROBE_REQUEST')
    raw=json.dumps(dict(profile=PROFILE, op='probe', nonce=nonce)).encode()
    process=None
    try:
        process=subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        process.stdin.write(raw); process.stdin.close()
        result=bytearray();deadline=time.monotonic()+timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                require(remaining>0, 'E_SSH_PROBE_TRANSPORT')
                for key, _ in selector.select(remaining):
                    part=os.read(key.fileobj.fileno(), 1024)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        result.extend(part)
                        require(len(result)<=2048, 'E_SSH_PROBE_TRANSPORT')
        returncode=process.wait(timeout=max(0.001, deadline-time.monotonic()))
        data=strict_json(bytes(result))
        if expected_rejection:
            require(returncode==2 and data=={'error':'E_PROBE_REQUEST'},'E_SSH_PROBE_RESPONSE')
            return data
        require(returncode==0,'E_SSH_PROBE_TRANSPORT')
        require(isinstance(data,dict) and set(data)=={'profile','nonce','uid',
                'source_observation_available'} and data['profile']==PROFILE
                and data['nonce']==nonce and type(data['uid']) is int
                and data['uid']==expected_uid and data['source_observation_available'] is False,
                'E_SSH_PROBE_RESPONSE')
        return data
    except Fault:
        raise
    except Exception:
        raise Fault('E_SSH_PROBE_TRANSPORT') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
