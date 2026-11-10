# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as fixtures
from recovery_guard import Fault,canonical
from source_avatar_observation_rpc import LaboratoryAvatarObservationRPC,PROFILE
from source_avatar_observation_transport import fetch_avatar_observation


class AvatarObservationTransportTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RecoveryTests();self.f.setUp();self.addCleanup(self.f.tearDown)
        self.raw=canonical(dict(profile=PROFILE,op='observe',nonce='a'*64,checkpoint_sha256=self.f.pin))
        self.reply=LaboratoryAvatarObservationRPC(self.f.current,{self.f.pin:self.f.checkpoint},lambda:self.f.now).respond(self.raw)

    def argv(self,code):return [sys.executable,'-I','-c',code]
    def fetch(self,code,**options):
        return fetch_avatar_observation(self.argv(code),self.raw,self.f.checkpoint,lambda:self.f.now,**options)

    def test_valid_subprocess_response_verified(self):
        result=self.fetch('import sys;sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(self.reply)+')')
        self.assertEqual(result['payload']['nonce'],'a'*64)

    def test_malformed_request_cannot_start_child(self):
        marker=self.f.root/'must-not-run'
        code='from pathlib import Path;Path('+repr(str(marker))+').write_text("ran")'
        for raw in [b'{}',self.raw+b' ' * 1024]:
            with self.assertRaises(Fault):
                fetch_avatar_observation(self.argv(code),raw,self.f.checkpoint,lambda:self.f.now)
        self.assertFalse(marker.exists())

    def test_hang_and_flood_are_bounded(self):
        for code in ['import sys,time;sys.stdin.read();time.sleep(20)',
                     'import sys;sys.stdin.read();sys.stdout.write("X"*1000000)']:
            start=time.monotonic()
            with self.assertRaises(Fault):self.fetch(code,timeout=0.1)
            self.assertLess(time.monotonic()-start,3)

    def test_unavailable_wrong_exit_and_invalid_signature_rejected_without_stderr(self):
        for code in ['import sys;sys.stdin.read();print(\'{"status":"unavailable"}\')',
                     'import sys;sys.stdin.read();sys.stderr.write("PRIVATE_SENTINEL");sys.exit(2)',
                     'import sys;sys.stdin.read();sys.stdout.buffer.write('+repr(self.reply.replace(b'"signature":"',b'"signature":"X'))+')']:
            with self.assertRaises(Fault) as error:self.fetch(code)
            self.assertNotIn('PRIVATE_SENTINEL',str(error.exception))


if __name__=='__main__':unittest.main()
