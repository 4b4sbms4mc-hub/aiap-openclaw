# SPDX-License-Identifier: Apache-2.0
"""Mac-only SSH credential preparation; no NAS authorization or remote execution.

Private keys stay in Keychain and a short-lived, private OpenSSH agent. The CLI
defaults to a public plan. Test backends are explicitly injected, never selected.
"""
from copy import deepcopy
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from recovery_guard import Fault, require, canonical, digest, b64, unb64, strict_json, read_file, save_private
from recovery_witness import hex_digest
from keychain_witness_signer import NativeKeychain

SERVICE='aiap.mac-witness.ssh.v1'
BINDING_PROFILE='x-aiap-ssh-destination-v1'
CONFIG_PROFILE='x-aiap-keychain-ssh-identity-v1'
RECORD_PROFILE='x-aiap-keychain-ssh-record-v1'
REMOTE_COMMAND='aiap-source-proof-v1'


def pack_string(value):
    require(isinstance(value,bytes) and len(value)<=8192,'E_SSH_AGENT_FRAME')
    return struct.pack('>I',len(value))+value


def take_string(raw,offset=0):
    require(isinstance(raw,bytes) and type(offset) is int and offset>=0
            and offset+4<=len(raw),'E_SSH_AGENT_FRAME')
    size=struct.unpack('>I',raw[offset:offset+4])[0]
    end=offset+4+size
    require(size<=8192 and end<=len(raw),'E_SSH_AGENT_FRAME')
    return raw[offset+4:end],end


def public_blob(key):
    return pack_string(b'ssh-ed25519')+pack_string(key.public_bytes(Encoding.Raw,PublicFormat.Raw))


def parse_public_blob(encoded):
    try:
        require(isinstance(encoded,str) and len(encoded)<=256,'E_SSH_BINDING')
        raw=base64.b64decode(encoded,validate=True)
        algorithm,end=take_string(raw);public,end=take_string(raw,end)
        require(algorithm==b'ssh-ed25519' and len(public)==32 and end==len(raw),'E_SSH_BINDING')
        return raw,public
    except Exception:
        raise Fault('E_SSH_BINDING') from None


def validate_binding(binding):
    require(isinstance(binding,dict) and set(binding)=={'profile','host','port','user',
            'server_key','server_fingerprint','generation'},'E_SSH_BINDING')
    try:
        require(binding['profile']==BINDING_PROFILE and isinstance(binding['host'],str)
                and str(ipaddress.ip_address(binding['host']))==binding['host']
                and type(binding['port']) is int and 1<=binding['port']<=65535
                and isinstance(binding['user'],str)
                and re.fullmatch('[a-z_][a-z0-9_-]{0,31}',binding['user']) is not None
                and hex_digest(binding['generation']),'E_SSH_BINDING')
        raw,_=parse_public_blob(binding['server_key'])
        fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
        require(binding['server_fingerprint']==fingerprint,'E_SSH_HOST_PIN')
    except Fault:
        raise
    except Exception:
        raise Fault('E_SSH_BINDING') from None
    return deepcopy(binding)


def public_plan(binding):
    binding=validate_binding(binding)
    return {'service':SERVICE,'account':digest(binding),'binding':binding,
            'action':'create-one-local-ssh-keychain-item-only','nas_authorization':False}


class SSHNativeKeychain(NativeKeychain):
    allowed_service=SERVICE  # separate fixed namespace; never use the witness key


class KeychainSSHIdentity:
    def __init__(self,config,*,backend=None):
        require(isinstance(config,dict) and set(config)=={'profile','binding','service','account',
                'client_public_key'},'E_SSH_BINDING')
        plan=public_plan(config['binding'])
        require(config['profile']==CONFIG_PROFILE and config['service']==SERVICE
                and config['account']==plan['account'],'E_SSH_BINDING')
        parse_public_blob(config['client_public_key'])
        self.config=deepcopy(config)
        self.backend=backend if backend is not None else SSHNativeKeychain()
        self._load()

    def _load(self):
        try:
            raw=self.backend.get(SERVICE,self.config['account'])
            require(raw is not None,'E_SSH_KEY_MISSING')
            require(isinstance(raw,str) and len(raw.encode())<=8192,'E_SSH_KEY_RECORD')
            record=strict_json(raw)
            require(isinstance(record,dict) and set(record)=={'profile','config','private_key'}
                    and record['profile']==RECORD_PROFILE and record['config']==self.config,'E_SSH_KEY_RECORD')
            key=Ed25519PrivateKey.from_private_bytes(unb64(record['private_key']))
            require(base64.b64encode(public_blob(key.public_key())).decode()
                    ==self.config['client_public_key'],'E_SSH_KEY_RECORD')
            return key
        except Fault:
            raise
        except Exception:
            raise Fault('E_SSH_KEY_UNAVAILABLE') from None

    @classmethod
    def provision(cls,binding,*,confirmed=False,backend=None):
        require(confirmed is True,'E_SSH_KEY_CONFIRMATION')
        plan=public_plan(binding)
        require(Path('/usr/bin/ssh-agent').is_file() and os.access('/usr/bin/ssh-agent',os.X_OK),
                'E_SSH_AGENT_START')
        store=backend if backend is not None else SSHNativeKeychain()
        key=Ed25519PrivateKey.generate()
        config={'profile':CONFIG_PROFILE,'binding':plan['binding'],'service':SERVICE,
                'account':plan['account'],
                'client_public_key':base64.b64encode(public_blob(key.public_key())).decode()}
        record={'profile':RECORD_PROFILE,'config':config,
                'private_key':b64(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))}
        store.create(SERVICE,plan['account'],canonical(record).decode())
        identity=cls(config,backend=store)
        with DedicatedAgent() as agent:
            agent.load(identity);agent.self_test(config)
        return deepcopy(config)

    @classmethod
    def inspect_existing(cls,binding,*,backend=None):
        plan=public_plan(binding)
        store=backend if backend is not None else SSHNativeKeychain()
        try:
            raw=store.get(SERVICE,plan['account']);require(raw is not None,'E_SSH_KEY_MISSING')
            require(isinstance(raw,str) and len(raw.encode())<=8192,'E_SSH_KEY_RECORD')
            record=strict_json(raw)
            require(isinstance(record,dict) and isinstance(record.get('config'),dict)
                    and record['config'].get('binding')==plan['binding'],'E_SSH_KEY_RECORD')
            return deepcopy(cls(record['config'],backend=store).config)
        except Fault:
            raise
        except Exception:
            raise Fault('E_SSH_KEY_UNAVAILABLE') from None


class DedicatedAgent:
    def __init__(self,lifetime=60):
        require(type(lifetime) is int and 1<=lifetime<=60,'E_SSH_AGENT_LIFETIME')
        self.lifetime=lifetime;self.process=None;self.directory=None

    def __enter__(self):
        try:
            self.directory=tempfile.TemporaryDirectory(prefix='aiap-ssh-',dir='/tmp')
            self.path=Path(self.directory.name)/'agent.sock'
            self.process=subprocess.Popen(['/usr/bin/ssh-agent','-D','-a',str(self.path),'-t',str(self.lifetime)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+3
            while not self.path.exists():
                require(self.process.poll() is None and time.monotonic()<deadline,'E_SSH_AGENT_START')
                time.sleep(0.01)
            info=self.path.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid()
                    and not info.st_mode&0o077,'E_SSH_AGENT_SOCKET')
            require(self.identities()==[],'E_SSH_AGENT_NOT_EMPTY')
            return self
        except BaseException:
            self.close();raise

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        if self.directory is not None:self.directory.cleanup()

    def __exit__(self,*args):self.close()

    def request(self,message):
        require(isinstance(message,bytes) and 0<len(message)<=8192,'E_SSH_AGENT_FRAME')
        def receive(connection,count):
            raw=b''
            while len(raw)<count:
                part=connection.recv(count-len(raw));require(bool(part),'E_SSH_AGENT_FRAME');raw+=part
            return raw
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(3);connection.connect(str(self.path))
            connection.sendall(struct.pack('>I',len(message))+message)
            size=struct.unpack('>I',receive(connection,4))[0]
            require(0<size<=8192,'E_SSH_AGENT_FRAME')
            return receive(connection,size)

    def identities(self):
        response=self.request(b'\x0b')
        require(len(response)>=5 and response[0]==12,'E_SSH_AGENT_FRAME')
        count=struct.unpack('>I',response[1:5])[0];require(count<=16,'E_SSH_AGENT_FRAME')
        offset=5;keys=[]
        for _ in range(count):
            key,offset=take_string(response,offset);_,offset=take_string(response,offset);keys.append(key)
        require(offset==len(response),'E_SSH_AGENT_FRAME');return keys

    def load(self,identity):
        require(isinstance(identity,KeychainSSHIdentity),'E_SSH_ROLE')
        require(self.identities()==[],'E_SSH_AGENT_NOT_EMPTY')
        key=identity._load()
        public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        private=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
        message=(b'\x19'+pack_string(b'ssh-ed25519')+pack_string(public)+pack_string(private+public)
                 +pack_string(b'aiap-dedicated-proof-transport')+b'\x01'+struct.pack('>I',self.lifetime))
        require(self.request(message)==b'\x06','E_SSH_AGENT_ADD')
        require(self.identities()==[parse_public_blob(identity.config['client_public_key'])[0]],'E_SSH_AGENT_KEY')

    def self_test(self,config):
        blob,public=parse_public_blob(config['client_public_key'])
        message=b'AIAP-SSH-AGENT-SELFTEST-v1\x00'+secrets.token_bytes(32)
        response=self.request(b'\x0d'+pack_string(blob)+pack_string(message)+struct.pack('>I',0))
        require(response[:1]==b'\x0e','E_SSH_AGENT_SIGN')
        signature,end=take_string(response,1);require(end==len(response),'E_SSH_AGENT_FRAME')
        algorithm,offset=take_string(signature);signed,offset=take_string(signature,offset)
        require(algorithm==b'ssh-ed25519' and offset==len(signature),'E_SSH_AGENT_FRAME')
        try:Ed25519PublicKey.from_public_bytes(public).verify(signed,message)
        except Exception:raise Fault('E_SSH_AGENT_SIGN') from None

    def client_arguments(self,config):
        """Render fixed-purpose SSH arguments only; never start a connection here."""
        require(isinstance(config,dict) and set(config)=={'profile','binding','service','account',
                'client_public_key'},'E_SSH_BINDING')
        binding=validate_binding(config['binding']);parse_public_blob(config['client_public_key'])
        require(config['profile']==CONFIG_PROFILE and config['service']==SERVICE
                and config['account']==digest(binding),'E_SSH_BINDING')
        root=Path(self.directory.name)
        public_path=root/'identity.pub';known_path=root/'known_hosts'
        require(not public_path.exists() and not known_path.exists(),'E_SSH_AGENT_FILES')
        save_private(public_path,('ssh-ed25519 '+config['client_public_key']+' aiap-proof\n').encode())
        host=binding['host'] if binding['port']==22 else '['+binding['host']+']:'+str(binding['port'])
        save_private(known_path,(host+' ssh-ed25519 '+binding['server_key']+'\n').encode())
        options={'BatchMode':'yes','IdentitiesOnly':'yes','IdentityAgent':str(self.path),
                 'UserKnownHostsFile':str(known_path),'GlobalKnownHostsFile':'/dev/null',
                 'StrictHostKeyChecking':'yes','UpdateHostKeys':'no','HostKeyAlgorithms':'ssh-ed25519',
                 'PasswordAuthentication':'no','KbdInteractiveAuthentication':'no','ForwardAgent':'no',
                 'PreferredAuthentications':'publickey','PubkeyAuthentication':'yes',
                 'GSSAPIAuthentication':'no','HostbasedAuthentication':'no',
                 'ClearAllForwardings':'yes','RequestTTY':'no','PermitLocalCommand':'no',
                 'ConnectTimeout':'5','ConnectionAttempts':'1','AddKeysToAgent':'no'}
        args=['/usr/bin/ssh','-F','/dev/null','-T','-i',str(public_path)]
        for key,value in options.items():args.extend(['-o',key+'='+value])
        return args+['-p',str(binding['port']),'-l',binding['user'],binding['host'],REMOTE_COMMAND]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding',required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--confirm-create',action='store_true')
    mode.add_argument('--inspect-existing',action='store_true')
    args=parser.parse_args()
    try:
        binding=strict_json(read_file(args.binding,8192))
        result=(KeychainSSHIdentity.provision(binding,confirmed=True) if args.confirm_create else
                KeychainSSHIdentity.inspect_existing(binding) if args.inspect_existing else public_plan(binding))
        print(json.dumps(result,indent=2))
    except Exception as error:
        print(json.dumps({'status':'unavailable','code':getattr(error,'code','E_SSH_KEY_UNAVAILABLE')}))
        raise SystemExit(2)
