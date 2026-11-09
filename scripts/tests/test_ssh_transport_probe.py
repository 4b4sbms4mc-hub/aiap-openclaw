# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ssh_transport_probe import answer, COMMAND, PROFILE, MAX_INPUT


class SSHTransportProbeTests(unittest.TestCase):
    def request(self, **extra):
        return dict(profile=PROFILE, op='probe', nonce='a'*64, **extra)

    def test_probe_explicitly_cannot_supply_a_source_observation(self):
        result = answer(json.dumps(self.request()).encode(), COMMAND, 10002)
        self.assertEqual(result, dict(profile=PROFILE, nonce='a'*64, uid=10002,
                                      source_observation_available=False))

    def test_arbitrary_and_missing_commands_refused(self):
        for command in ['', '/bin/sh', COMMAND+';id', COMMAND+' ', 'scp -t /tmp/x']:
            with self.assertRaises(ValueError):
                answer(json.dumps(self.request()).encode(), command, 10002)

    def test_duplicate_fields_and_nonobject_refused(self):
        for raw in [b'[]', b'null', b'{}', b'{"op":"probe","op":"probe"}', b'{']:
            with self.assertRaises(ValueError):
                answer(raw, COMMAND, 10002)

    def test_extra_paths_and_privileged_operations_refused(self):
        for data in [self.request(path='/data'), self.request(command='id'),
                     dict(self.request(), op='observe'), dict(self.request(), profile='other')]:
            with self.assertRaises(ValueError):
                answer(json.dumps(data).encode(), COMMAND, 10002)

    def test_nonce_type_case_and_length_refused(self):
        for nonce in [True, 1, None, 'A'*64, 'a'*63, 'a'*65, 'a'*63+'\n']:
            with self.assertRaises(ValueError):
                answer(json.dumps(dict(self.request(), nonce=nonce)).encode(), COMMAND, 10002)

    def test_size_utf8_and_exact_boundary(self):
        raw=json.dumps(self.request()).encode()
        self.assertEqual(answer(raw+b' '*(MAX_INPUT-len(raw)), COMMAND, 10002)['nonce'], 'a'*64)
        for invalid in [raw+b' '*(MAX_INPUT-len(raw)+1), b'\xff']:
            with self.assertRaises((ValueError, UnicodeError)):
                answer(invalid, COMMAND, 10002)

    def test_isolated_process_output_and_error_are_bounded(self):
        script=Path(__file__).resolve().parents[1]/'ssh_transport_probe.py'
        result=subprocess.run([sys.executable, '-I', str(script)],
            env=dict(os.environ, SSH_ORIGINAL_COMMAND=COMMAND),
            input=json.dumps(self.request()).encode(), capture_output=True, timeout=7)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['source_observation_available'])
        denied=subprocess.run([sys.executable, '-I', str(script)],
            env=dict(os.environ, SSH_ORIGINAL_COMMAND='id'), input=b'PRIVATE_INPUT_SENTINEL',
            capture_output=True, timeout=7)
        self.assertEqual(denied.returncode, 2)
        self.assertEqual(denied.stdout, b'{"error":"E_PROBE_REQUEST"}\n')
        self.assertEqual(denied.stderr, b'')


if __name__ == '__main__':
    unittest.main()
