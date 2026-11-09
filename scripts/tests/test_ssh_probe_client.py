# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from recovery_guard import Fault
from ssh_probe_client import exchange


class SSHProbeClientTests(unittest.TestCase):
    def child(self, code):
        return [sys.executable,'-I','-c',code]

    def test_valid_bound_probe(self):
        args=self.child('import sys,json;d=json.load(sys.stdin);print(json.dumps(dict(profile=d["profile"],nonce=d["nonce"],uid=10002,source_observation_available=False)))')
        self.assertEqual(exchange(args,'a'*64,10002)['uid'],10002)

    def test_uid_nonce_and_source_proof_claim_rejected(self):
        for changes in ['uid=10003','nonce="b"*64','source_observation_available=True','extra="x"']:
            args=self.child('import sys,json;d=json.load(sys.stdin);r=dict(profile=d["profile"],nonce=d["nonce"],uid=10002,source_observation_available=False);r.update('+changes+');print(json.dumps(r))')
            with self.assertRaises(Fault):exchange(args,'a'*64,10002)

    def test_flood_is_bounded(self):
        with self.assertRaises(Fault):
            exchange(self.child('import sys;sys.stdin.read();sys.stdout.write("X"*1000000)'), 'a'*64,10002)

    def test_hang_is_terminated(self):
        with self.assertRaises(Fault):
            exchange(self.child('import sys,time;sys.stdin.read();time.sleep(20)'), 'a'*64,10002,timeout=0.1)

    def test_remote_error_is_not_returned_as_proof_or_raw_output(self):
        with self.assertRaises(Fault) as context:
            exchange(self.child('import sys;sys.stdin.read();print("PRIVATE_SENTINEL");sys.exit(2)'), 'a'*64,10002)
        self.assertNotIn('PRIVATE_SENTINEL',str(context.exception))


if __name__=='__main__':unittest.main()
