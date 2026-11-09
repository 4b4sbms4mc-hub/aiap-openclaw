# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from keychain_ssh_identity import (KeychainSSHIdentity,SSHNativeKeychain,DedicatedAgent,
    BINDING_PROFILE,SERVICE,REMOTE_COMMAND,public_plan,public_blob,pack_string,take_string)
from keychain_witness_signer import NativeKeychain,SERVICE as WITNESS_SERVICE
from recovery_guard import Fault,canonical,b64
from test_keychain_witness_signer import FakeStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SSHIdentityTests(unittest.TestCase):
    def setUp(self):
        self.store=FakeStore()
        host=public_blob(Ed25519PrivateKey.generate().public_key())
        self.binding={'profile':BINDING_PROFILE,'host':'127.0.0.1','port':22,'user':'aiaplab',
            'server_key':base64.b64encode(host).decode(),
            'server_fingerprint':'SHA256:'+base64.b64encode(hashlib.sha256(host).digest()).decode().rstrip('='),
            'generation':secrets.token_hex(32)}

    def reject(self,code,call):
        with self.assertRaises(Fault) as error:call()
        self.assertEqual(error.exception.code,code)

    def provision(self):
        return KeychainSSHIdentity.provision(self.binding,confirmed=True,backend=self.store)

    def test_agent_string_boundaries_and_types(self):
        value=b'SYNTHETIC';self.assertEqual(take_string(pack_string(value)),(value,len(value)+4))
        for raw,offset in [(b'',0),(b'\0'*3,0),(pack_string(value),True),('invalid',0),
                           (struct.pack('>I',8193),0),(pack_string(value),-1)]:
            self.reject('E_SSH_AGENT_FRAME',lambda:take_string(raw,offset))
        self.reject('E_SSH_AGENT_FRAME',lambda:pack_string(b'X'*8193))

    def test_default_cli_is_public_plan_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'binding.json';path.write_text(json.dumps(self.binding))
            result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'keychain_ssh_identity.py'),
                '--binding',str(path)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),public_plan(self.binding))
        self.assertNotIn('private_key',result.stdout.decode())
        self.assertEqual(self.store.items,{})

    def test_confirmation_required_before_create(self):
        self.reject('E_SSH_KEY_CONFIRMATION',lambda:KeychainSSHIdentity.provision(self.binding,backend=self.store))
        self.assertEqual(self.store.items,{})

    def test_duplicate_preserves_existing_identity(self):
        config=self.provision();saved=deepcopy(self.store.items)
        self.reject('E_KEYCHAIN_EXISTS',self.provision)
        self.assertEqual(self.store.items,saved)
        self.assertEqual(KeychainSSHIdentity.inspect_existing(self.binding,backend=self.store),config)

    def test_real_agent_signs_then_process_socket_and_files_are_removed(self):
        config=self.provision();identity=KeychainSSHIdentity(config,backend=self.store)
        ambient=os.environ.get('SSH_AUTH_SOCK')
        with DedicatedAgent() as agent:
            process=agent.process;path=agent.path;directory=Path(agent.directory.name)
            self.assertEqual(agent.identities(),[])
            agent.load(identity);agent.self_test(config)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.reject('E_SSH_AGENT_NOT_EMPTY',lambda:agent.load(identity))
            self.assertNotIn('_key',vars(identity))
        self.assertIsNotNone(process.poll())
        self.assertFalse(path.exists());self.assertFalse(directory.exists())
        self.assertEqual(os.environ.get('SSH_AUTH_SOCK'),ambient)

    def test_real_agent_lifetime_expires_without_reloading(self):
        identity=KeychainSSHIdentity(self.provision(),backend=self.store)
        with DedicatedAgent(lifetime=1) as agent:
            agent.load(identity)
            deadline=time.monotonic()+4
            while agent.identities() and time.monotonic()<deadline:time.sleep(0.05)
            self.assertEqual(agent.identities(),[])
            self.reject('E_SSH_AGENT_SIGN',lambda:agent.self_test(identity.config))

    def test_missing_denied_and_corrupt_record_never_regenerates(self):
        config=self.provision();identity=KeychainSSHIdentity(config,backend=self.store)
        self.store.denied=True
        with DedicatedAgent() as agent:
            self.reject('E_KEYCHAIN_UNAVAILABLE',lambda:agent.load(identity))
            self.assertEqual(agent.identities(),[])
        self.store.denied=False
        item=(SERVICE,config['account']);record=json.loads(self.store.items[item]);record['private_key']=b64(b'\0'*32)
        self.store.items[item]=canonical(record).decode()
        self.reject('E_SSH_KEY_RECORD',lambda:KeychainSSHIdentity(config,backend=self.store))
        self.store.items.clear()
        self.reject('E_SSH_KEY_MISSING',lambda:KeychainSSHIdentity(config,backend=self.store))
        self.assertEqual(self.store.items,{})

    def test_client_config_is_parsed_without_connection_and_contains_no_private_files(self):
        config=self.provision()
        with DedicatedAgent() as agent:
            args=agent.client_arguments(config)
            self.assertEqual(args[-1],REMOTE_COMMAND)
            result=subprocess.run(args[:1]+['-G']+args[1:],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            settings={line.split(' ',1)[0]:line.split(' ',1)[1] for line in result.stdout.splitlines() if ' ' in line}
            self.assertEqual(settings['passwordauthentication'],'no')
            self.assertEqual(settings['forwardagent'],'no')
            self.assertEqual(settings['identitiesonly'],'yes')
            self.assertIn(settings['stricthostkeychecking'],('true','yes'))
            self.assertEqual(settings['hostkeyalgorithms'],'ssh-ed25519')
            self.assertEqual(settings['user'],self.binding['user'])
            for path in Path(agent.directory.name).iterdir():
                if path.is_file():
                    self.assertEqual(path.stat().st_mode&0o777,0o600)
                    self.assertNotIn(b'PRIVATE KEY',path.read_bytes())

    def test_unpinned_host_and_injected_user_fail_before_any_create(self):
        for field,value,code in [('server_fingerprint','SHA256:wrong','E_SSH_HOST_PIN'),
                                 ('user','bad;id','E_SSH_BINDING'),('host','localhost','E_SSH_BINDING')]:
            binding=deepcopy(self.binding);binding[field]=value
            self.reject(code,lambda:KeychainSSHIdentity.provision(binding,confirmed=True,backend=self.store))
        self.assertEqual(self.store.items,{})

    def test_namespaces_and_key_roles_are_separate(self):
        witness=object.__new__(NativeKeychain)
        transport=object.__new__(SSHNativeKeychain)
        self.reject('E_KEYCHAIN_SCOPE',lambda:witness.get(SERVICE,'synthetic'))
        self.reject('E_KEYCHAIN_SCOPE',lambda:transport.get(WITNESS_SERVICE,'synthetic'))
        with DedicatedAgent() as agent:
            self.reject('E_SSH_ROLE',lambda:agent.load(object()))
            self.assertEqual(agent.identities(),[])


if __name__=='__main__':unittest.main()
