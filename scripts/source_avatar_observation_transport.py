# SPDX-License-Identifier: Apache-2.0
"""Bounded lab stdio client. argv is trusted configuration, never request data."""
import os
import selectors
import subprocess
import time

from recovery_guard import Fault,require
from source_avatar_observation_rpc import request,verify_reply,MAX_RESPONSE


def fetch_avatar_observation(arguments,raw,checkpoint,clock,*,timeout=10):
    request(raw)  # reject untrusted input before any child can run
    require(type(timeout) in (int,float) and 0<timeout<=15,'E_SOURCE_RPC_TRANSPORT')
    child=None
    try:
        deadline=time.monotonic()+timeout
        child=subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        child.stdin.write(raw);child.stdin.close()
        output=bytearray()
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout,selectors.EVENT_READ)
            while poll.get_map():
                remaining=deadline-time.monotonic()
                require(remaining>0,'E_SOURCE_RPC_TRANSPORT')
                for key,_ in poll.select(remaining):
                    part=os.read(key.fileobj.fileno(),1024)
                    if not part:poll.unregister(key.fileobj)
                    else:
                        output.extend(part)
                        require(len(output)<=MAX_RESPONSE,'E_SOURCE_RPC_TRANSPORT')
        require(child.wait(timeout=max(0.001,deadline-time.monotonic()))==0,'E_SOURCE_RPC_TRANSPORT')
        return verify_reply(bytes(output),raw,checkpoint,clock)
    except Fault:raise
    except Exception:raise Fault('E_SOURCE_RPC_TRANSPORT') from None
    finally:
        if child is not None:
            if child.poll() is None:child.kill()
            child.wait()
            for stream in (child.stdin,child.stdout):
                if stream is not None and not stream.closed:stream.close()
