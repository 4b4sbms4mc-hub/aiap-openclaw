# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import json
from pathlib import Path
import secrets
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from keychain_witness_signer import (KeychainWitnessSigner, NativeKeychain, SERVICE,
                                     BINDING_PROFILE, public_plan)
from recovery_guard import Fault, b64, unb64, canonical, digest
from recovery_witness import DOMAIN, WitnessReader
from recovery_durable_live_witness import DurableLiveWitness
import test_recovery_live_observation as live_tests


class FakeStore:
    """LM Studio draft; test-only, never selected by the production CLI."""
    def __init__(self):
        self.items={}
        self.denied=False

    def get(self,service,account):
        if self.denied:raise Fault('E_KEYCHAIN_UNAVAILABLE')
        return self.items.get((service,account))

    def create(self,service,account,value):
        if self.denied:raise Fault('E_KEYCHAIN_UNAVAILABLE')
        key=(service,account)
        if key in self.items:raise Fault('E_KEYCHAIN_EXISTS')
        self.items[key]=value


class KeychainSignerTests(unittest.TestCase):
    def setUp(self):
        self.store=FakeStore()
        self.binding={'profile':BINDING_PROFILE,'avatar':'avatar:synthetic',
                      'enrollment_sha256':'a'*64,'generation':secrets.token_hex(32)}

    def reject(self,code,callback):
        with self.assertRaises(Fault) as error:callback()
        self.assertEqual(error.exception.code,code)

    def provision(self):
        return KeychainWitnessSigner.provision(self.binding,confirmed=True,backend=self.store)

    def test_default_cli_only_prints_public_plan_without_keyring_dependency(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            binding=Path(tmp)/'binding.json';binding.write_text(json.dumps(self.binding))
            result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'keychain_witness_signer.py'),
                '--binding',str(binding)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),public_plan(self.binding))
        self.assertNotIn('private_key',result.stdout.decode())
        self.assertEqual(self.store.items,{})

    def test_provision_requires_explicit_confirmation_before_any_write(self):
        self.reject('E_KEYCHAIN_CONFIRMATION',lambda:KeychainWitnessSigner.provision(self.binding,backend=self.store))
        self.assertEqual(self.store.items,{})

    def test_duplicate_never_overwrites_existing_key(self):
        config=self.provision();before=deepcopy(self.store.items)
        self.reject('E_KEYCHAIN_EXISTS',self.provision)
        self.assertEqual(self.store.items,before)
        signer=KeychainWitnessSigner(config,backend=self.store)
        message=DOMAIN+b'SYNTHETIC_PROBE'
        signer.public_key().verify(signer.sign(message),message)

    def test_reopen_uses_same_key_and_public_config_contains_no_secret(self):
        config=self.provision()
        first=KeychainWitnessSigner(config,backend=self.store)
        second=KeychainWitnessSigner(config,backend=self.store)
        message=DOMAIN+canonical({'probe':'synthetic'})
        second.public_key().verify(first.sign(message),message)
        secret=json.loads(self.store.items[(SERVICE,config['account'])])['private_key']
        self.assertNotIn(secret,json.dumps(config))
        self.assertEqual(KeychainWitnessSigner.inspect_existing(self.binding,backend=self.store),config)
        self.assertNotIn('private_key',vars(first))
        self.assertNotIn('_key',vars(first))

    def test_missing_or_denied_item_never_regenerates_or_falls_back(self):
        config=self.provision();signer=KeychainWitnessSigner(config,backend=self.store)
        self.store.denied=True;before=deepcopy(self.store.items)
        self.reject('E_KEYCHAIN_UNAVAILABLE',lambda:signer.sign(DOMAIN+b'X'))
        self.assertEqual(self.store.items,before)
        self.store.denied=False;self.store.items.clear()
        self.reject('E_KEYCHAIN_MISSING',lambda:KeychainWitnessSigner(config,backend=self.store))
        self.reject('E_KEYCHAIN_MISSING',lambda:KeychainWitnessSigner.inspect_existing(self.binding,backend=self.store))
        self.reject('E_KEYCHAIN_MISSING',lambda:signer.sign(DOMAIN+b'X'))
        self.assertEqual(self.store.items,{})

    def test_binding_and_secret_corruption_fail_closed(self):
        config=self.provision();wrong=deepcopy(config);wrong['binding']['enrollment_sha256']='b'*64
        self.reject('E_KEYCHAIN_BINDING',lambda:KeychainWitnessSigner(wrong,backend=self.store))
        item=(SERVICE,config['account']);record=json.loads(self.store.items[item])
        record['private_key']=b64(b'\0'*32);self.store.items[item]=canonical(record).decode()
        self.reject('E_KEYCHAIN_RECORD',lambda:KeychainWitnessSigner(config,backend=self.store))

    def test_signer_refuses_other_signature_domains_before_loading_secret(self):
        signer=KeychainWitnessSigner(self.provision(),backend=self.store)
        self.store.denied=True
        self.reject('E_KEYCHAIN_SCOPE',lambda:signer.sign(b'AIAP-LOCAL-CORE-v1\0X'))

    def test_native_duplicate_uses_atomic_add_and_never_delete_or_update(self):
        class API:
            def __init__(self):self.calls=[]
            def k_(self,name):return name
            def create_query(self,**kwargs):return kwargs
            def SecItemAdd(self,query,result):self.calls.append(query);return -25299
        native=object.__new__(NativeKeychain);native.api=API()
        native._query=lambda **kwargs:kwargs
        native.data_create=lambda *args:1234;native.release=lambda value:None
        self.reject('E_KEYCHAIN_EXISTS',lambda:native.create(SERVICE,'synthetic','TEST_ONLY'))
        self.assertEqual(len(native.api.calls),1)
        self.assertEqual(native.api.calls[0]['kSecAttrService'],SERVICE)

    def test_non_macos_native_backend_never_selects_a_fallback(self):
        with patch('keychain_witness_signer.sys.platform','linux'):
            self.reject('E_KEYCHAIN_PLATFORM',NativeKeychain)

    def test_signer_integrates_with_durable_live_proof_and_denial_rolls_back(self):
        f=live_tests.LiveObservationTests();f.setUp();self.addCleanup(f.doCleanups)
        self.binding.update(avatar=f.witness.avatar,enrollment_sha256=f.witness.enrollment_sha256)
        config=self.provision();provider=KeychainWitnessSigner(config,backend=self.store)
        f.witness._key=provider;f.witness.generation=self.binding['generation']
        trust=dict(avatar=f.witness.avatar,enrollment_sha256=f.witness.enrollment_sha256,
                   generation=f.witness.generation,public_key=config['public_key'])
        f.reader=WitnessReader(clock=lambda:f.now,**trust)
        nonce=f.reader.challenge();initial=f.proof(nonce)
        durable=DurableLiveWitness.enroll(f.f.root/'keychain-witness',trust,provider,initial,nonce,
                                          digest(f.witness.head),lambda:f.now)
        f.reader.verify(initial);before=durable.head
        f.delete();f.refresh_checkpoint()
        nonce=f.reader.challenge();observation=f.observation(nonce)
        self.store.denied=True
        self.reject('E_KEYCHAIN_UNAVAILABLE',lambda:durable.answer(nonce,checkpoint=f.checkpoint,
                    pin=f.pin,observation=observation))
        self.assertEqual(durable.head,before)
        self.store.denied=False
        reopened=DurableLiveWitness(f.f.root/'keychain-witness',trust,
            KeychainWitnessSigner(config,backend=self.store),lambda:f.now)
        nonce=f.reader.challenge()
        proof=reopened.answer(nonce,checkpoint=f.checkpoint,pin=f.pin,observation=f.observation(nonce))
        self.assertEqual(f.reader.verify(proof),f.pin)
        self.assertEqual(reopened.head['sequence'],before['sequence']+1)


if __name__=='__main__':unittest.main()
