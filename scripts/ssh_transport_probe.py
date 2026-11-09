# SPDX-License-Identifier: Apache-2.0
"""Unprivileged forced-command bootstrap. Never a source/recovery proof."""
import json
import os
import re
import signal
import sys

PROFILE = 'x-aiap-ssh-transport-probe-v1'
COMMAND = 'aiap-source-proof-v1'
MAX_INPUT = 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def answer(raw, command, uid):
    if command != COMMAND:
        raise ValueError('command')
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT:
        raise ValueError('size')
    data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    if (not isinstance(data, dict) or set(data) != {'profile', 'op', 'nonce'}
            or data['profile'] != PROFILE or data['op'] != 'probe'
            or not isinstance(data['nonce'], str)
            or re.fullmatch('[0-9a-f]{64}', data['nonce']) is None):
        raise ValueError('request')
    return {'profile': PROFILE, 'nonce': data['nonce'], 'uid': uid,
            'source_observation_available': False}


def main():
    def timeout(signum, frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(5)
    try:
        # Reject arbitrary commands before consuming a potentially blocking pipe.
        command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
        if command != COMMAND:
            raise ValueError('command')
        result = answer(sys.stdin.buffer.read(MAX_INPUT + 1), command, os.getuid())
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except (ValueError, UnicodeError, TypeError, RecursionError, TimeoutError):
        print('{"error":"E_PROBE_REQUEST"}')
        return 2
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
