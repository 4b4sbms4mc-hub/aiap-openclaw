# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as fixtures
from recovery_guard import Fault,canonical
from recovery_avatar_observation import AvatarObservationWitness as LiveObservationWitness
from recovery_witness import WitnessReader
from source_avatar_observation_rpc import LaboratoryAvatarObservationRPC,verify_reply,PROFILE,MAX_REQUEST,MAX_RESPONSE


class AvatarObservationRPCTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RecoveryTests();self.f.setUp();self.addCleanup(self.f.tearDown)
        self.now=self.f.now
        self.rpc=LaboratoryAvatarObservationRPC(self.f.current,{self.f.pin:self.f.checkpoint},lambda:self.now)

    def request(self,**changes):
        data=dict(profile=PROFILE,op='observe',nonce='a'*64,checkpoint_sha256=self.f.pin)
        data.update(changes);return canonical(data)

    def verify(self,raw,request=None):
        return verify_reply(raw,request or self.request(),self.f.checkpoint,lambda:self.now)

    def test_signed_rpc_roundtrip_feeds_existing_witness_and_reader(self):
        from recovery_guard import digest
        payload=json.loads(self.f.checkpoint.read_text())['payload']
        witness=LiveObservationWitness(payload['core']['avatar_id'],digest(payload['enrollment']),lambda:self.now)
        reader=WitnessReader(witness.avatar,witness.enrollment_sha256,witness.generation,witness.public_key,lambda:self.now)
        raw=self.request(nonce=reader.challenge())
        observation=self.verify(self.rpc.respond(raw),raw)
        proof=witness.answer(json.loads(raw)['nonce'],checkpoint=self.f.checkpoint,pin=self.f.pin,observation=observation)
        self.assertEqual(reader.verify(proof),self.f.pin)
        with self.assertRaises(Fault):reader.verify(proof)

    def test_arbitrary_paths_operations_duplicates_and_sizes_never_call_observer(self):
        calls=[]
        def observer(*args):calls.append(args);raise AssertionError('must not call')
        rpc=LaboratoryAvatarObservationRPC(self.f.current,{self.f.pin:self.f.checkpoint},lambda:self.now,observer=observer)
        for raw in [self.request(path='/data/owner-key.pem'),self.request(op='sign'),
                    self.request(nonce='A'*64),self.request(nonce=True),b'{"op":"observe","op":"observe"}',
                    b'[]',b'\xff',b' '* (MAX_REQUEST+1),self.request(checkpoint_sha256='0'*64)]:
            self.assertEqual(json.loads(rpc.respond(raw)),dict(profile=PROFILE,status='unavailable'))
        self.assertEqual(calls,[])

    def test_readonly_source_and_no_memory_or_private_content_in_response(self):
        before=self.f.hashes(self.f.current);reply=self.rpc.respond(self.request())
        self.assertEqual(self.f.hashes(self.f.current),before)
        for sentinel in [b'KEEP_SYNTHETIC',b'PRIVATE KEY',self.f.owner.encode(),str(self.f.current).encode()]:
            self.assertNotIn(sentinel,reply)
        self.verify(reply)

    def test_stale_checkpoint_and_source_mutation_are_unavailable(self):
        self.f.service.delete(self.f.owner,{'memory_id':self.f.keep,'space_ref':'space:general','base_revision':1})
        reply=self.rpc.respond(self.request())
        self.assertEqual(json.loads(reply)['status'],'unavailable')
        with self.assertRaises(Fault):self.verify(reply)

    def test_cached_tampered_and_expired_replies_are_rejected(self):
        reply=self.rpc.respond(self.request())
        with self.assertRaises(Fault):self.verify(reply,self.request(nonce='b'*64))
        changed=json.loads(reply);changed['observation']['payload']['checkpoint_sha256']='0'*64
        with self.assertRaises(Fault):self.verify(canonical(changed))
        self.now+=timedelta(seconds=31)
        with self.assertRaises(Fault):self.verify(reply)

    def test_probe_and_malformed_or_oversized_responses_never_become_observations(self):
        for reply in [b'{"source_observation_available":false}',b'null',b'\xff',b' '* (MAX_RESPONSE+1),
                      b'{"profile":"x","profile":"x"}']:
            with self.assertRaises(Fault):self.verify(reply)

    def test_observer_exceptions_and_oversized_output_are_not_reflected(self):
        def failed(*args):raise RuntimeError('PRIVATE_KEY_SECRET /private/path')
        for observer in [failed,lambda *args:{'secret':'X'*MAX_RESPONSE},
                         lambda *args:{'secret':'SMALL_SECRET'}]:
            rpc=LaboratoryAvatarObservationRPC(self.f.current,{self.f.pin:self.f.checkpoint},lambda:self.now,observer=observer)
            self.assertEqual(json.loads(rpc.respond(self.request())),dict(profile=PROFILE,status='unavailable'))

    def test_registration_map_cannot_be_changed_by_external_mutation(self):
        pins={self.f.pin:self.f.checkpoint}
        rpc=LaboratoryAvatarObservationRPC(self.f.current,pins,lambda:self.now)
        pins.clear();self.verify(rpc.respond(self.request()))
        with self.assertRaises(Fault):LaboratoryAvatarObservationRPC(self.f.current,{},lambda:self.now)


    def test_legacy_requests_are_not_accepted_or_downgraded(self):
        import source_observation_rpc as legacy
        old = legacy.LaboratoryObservationRPC(self.f.current,{self.f.pin:self.f.checkpoint},lambda:self.now)
        old_request = self.request(profile=legacy.PROFILE)
        self.assertEqual(json.loads(self.rpc.respond(old_request))['status'],'unavailable')
        self.assertEqual(json.loads(old.respond(self.request()))['status'],'unavailable')
        with self.assertRaises(Fault): self.verify(old.respond(old_request))
        with self.assertRaises(Fault): legacy.verify_reply(self.rpc.respond(self.request()),old_request,self.f.checkpoint,lambda:self.now)

    def test_rpc_works_without_owner_private_key(self):
        (self.f.current/'owner-key.pem').unlink()
        self.verify(self.rpc.respond(self.request()))

if __name__=='__main__':unittest.main()
