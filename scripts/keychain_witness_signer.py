# SPDX-License-Identifier: Apache-2.0
"""Explicit, create-only macOS witness signer provisioning; no daemon or NAS writes.

Default CLI mode only prints a public plan. Creation needs --confirm-create.
Tests inject an in-memory store; production never selects a fallback backend.
"""
from copy import deepcopy
import argparse
import ctypes
import importlib.metadata
import json
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from recovery_guard import Fault, require, digest, canonical, b64, unb64, strict_json, read_file
from recovery_witness import DOMAIN, hex_digest

SERVICE = 'aiap.mac-witness.signer.v1'
BINDING_PROFILE = 'x-aiap-witness-key-binding-v1'
CONFIG_PROFILE = 'x-aiap-macos-keychain-signer-v1'
RECORD_PROFILE = 'x-aiap-keychain-witness-record-v1'


def validate_binding(binding):
    require(isinstance(binding,dict) and set(binding)=={'profile','avatar','enrollment_sha256','generation'},
            'E_KEYCHAIN_BINDING')
    require(binding['profile']==BINDING_PROFILE and isinstance(binding['avatar'],str)
            and binding['avatar'].startswith('avatar:') and len(binding['avatar'])<=200
            and hex_digest(binding['enrollment_sha256']) and hex_digest(binding['generation']),
            'E_KEYCHAIN_BINDING')
    return deepcopy(binding)


def public_plan(binding):
    binding=validate_binding(binding)
    return {'service':SERVICE,'account':digest(binding),'binding':binding,
            'action':'create-one-local-keychain-item-only','network_service':False}


class NativeKeychain:
    """Pinned native bindings, exact service, atomic SecItemAdd; no delete/update."""
    allowed_service=SERVICE
    def __init__(self):
        require(sys.platform=='darwin','E_KEYCHAIN_PLATFORM')
        try:
            require(importlib.metadata.version('keyring')=='25.7.0','E_KEYCHAIN_BACKEND')
            from keyring.backends.macOS import api
            self.api=api
            self.release=api._found.CFRelease
            self.release.argtypes=[ctypes.c_void_p];self.release.restype=None
            self.data_create=api._found.CFDataCreate
            self.data_create.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_long]
            self.data_create.restype=ctypes.c_void_p
        except Exception:
            raise Fault('E_KEYCHAIN_BACKEND') from None

    def _query(self,**fields):
        a=self.api;values=[];owned=[]
        try:
            for value in fields.values():
                converted=a.create_cf(value)
                if isinstance(value,(str,int,bool)):
                    require(bool(converted),'E_KEYCHAIN_UNAVAILABLE');owned.append(converted)
                values.append(converted)
            query=a.CFDictionaryCreate(None,
                (ctypes.c_void_p*len(fields))(*map(a.k_,fields)),
                (ctypes.c_void_p*len(fields))(*values),len(fields),
                a._found.kCFTypeDictionaryKeyCallBacks,a._found.kCFTypeDictionaryValueCallBacks)
            require(bool(query),'E_KEYCHAIN_UNAVAILABLE')
            return query  # dictionary retains values; release our temporary ownership
        finally:
            for value in owned:self.release(value)

    def get(self, service, account):
        require(service==self.allowed_service,'E_KEYCHAIN_SCOPE')
        a=self.api
        query=self._query(kSecClass=a.k_('kSecClassGenericPassword'),kSecAttrService=service,
            kSecAttrAccount=account,kSecReturnData=True,kSecMatchLimit=a.k_('kSecMatchLimitOne'),
            kSecUseAuthenticationUI=a.k_('kSecUseAuthenticationUIFail'))
        data=ctypes.c_void_p()
        try:
            status=a.SecItemCopyMatching(query,ctypes.byref(data))
            if status==-25300:return None
            require(status==0 and data.value is not None,'E_KEYCHAIN_UNAVAILABLE')
            size=a.CFDataGetLength(data)
            require(0<size<=8192,'E_KEYCHAIN_RECORD')
            return ctypes.string_at(a.CFDataGetBytePtr(data),size).decode('utf-8')
        finally:
            if data.value:self.release(data)
            self.release(query)

    def create(self, service, account, value):
        require(service==self.allowed_service and isinstance(value,str),'E_KEYCHAIN_SCOPE')
        raw=value.encode('utf-8');require(len(raw)<=8192,'E_KEYCHAIN_RECORD')
        buffer=ctypes.create_string_buffer(raw)
        data=self.data_create(None,ctypes.cast(buffer,ctypes.c_void_p),len(raw))
        require(data is not None,'E_KEYCHAIN_UNAVAILABLE')
        query=None
        try:
            a=self.api
            query=self._query(kSecClass=a.k_('kSecClassGenericPassword'),kSecAttrService=service,
                                 kSecAttrAccount=account,kSecValueData=ctypes.c_void_p(data))
            status=a.SecItemAdd(query,None)
            require(status!=-25299,'E_KEYCHAIN_EXISTS')
            require(status==0,'E_KEYCHAIN_UNAVAILABLE')
        finally:
            if query:self.release(query)
            self.release(data)


class KeychainWitnessSigner:
    def __init__(self, config, *, backend=None):
        require(isinstance(config,dict) and set(config)=={'profile','binding','service','account','public_key'},
                'E_KEYCHAIN_BINDING')
        plan=public_plan(config['binding'])
        require(config['profile']==CONFIG_PROFILE and config['service']==SERVICE
                and config['account']==plan['account'],'E_KEYCHAIN_BINDING')
        self.config=deepcopy(config)
        self.backend=backend if backend is not None else NativeKeychain()
        self._load()  # never regenerate if the item is absent, locked or inconsistent

    @classmethod
    def provision(cls, binding, *, confirmed=False, backend=None):
        require(confirmed is True,'E_KEYCHAIN_CONFIRMATION')
        plan=public_plan(binding)
        store=backend if backend is not None else NativeKeychain()
        key=Ed25519PrivateKey.generate()
        config={'profile':CONFIG_PROFILE,'binding':plan['binding'],'service':SERVICE,
                'account':plan['account'],
                'public_key':b64(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))}
        record={'profile':RECORD_PROFILE,'config':config,
                'private_key':b64(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))}
        # SecItemAdd alone rejects a duplicate. keyring.set_password deletes first
        # on this pinned backend, so it is deliberately never used here.
        store.create(SERVICE,plan['account'],canonical(record).decode())
        signer=cls(config,backend=store)  # failures never auto-delete/retry
        message=DOMAIN+canonical({'key_self_test':secrets.token_hex(32)})
        signer.public_key().verify(signer.sign(message),message)
        return deepcopy(config)  # public metadata only, never the private record

    @classmethod
    def inspect_existing(cls,binding,*,backend=None):
        plan=public_plan(binding)
        store=backend if backend is not None else NativeKeychain()
        try:
            raw=store.get(SERVICE,plan['account'])
            require(raw is not None,'E_KEYCHAIN_MISSING')
            require(isinstance(raw,str) and len(raw.encode('utf-8'))<=8192,'E_KEYCHAIN_RECORD')
            record=strict_json(raw)
            require(isinstance(record,dict) and isinstance(record.get('config'),dict)
                    and record['config'].get('binding')==plan['binding'],'E_KEYCHAIN_RECORD')
            signer=cls(record['config'],backend=store)
            return deepcopy(signer.config)  # recovery of public metadata, never re-enrollment
        except Fault:
            raise
        except Exception:
            raise Fault('E_KEYCHAIN_UNAVAILABLE') from None

    def _load(self):
        try:
            raw=self.backend.get(SERVICE,self.config['account'])
            require(raw is not None,'E_KEYCHAIN_MISSING')
            require(isinstance(raw,str) and len(raw.encode('utf-8'))<=8192,'E_KEYCHAIN_RECORD')
            record=strict_json(raw)
            require(isinstance(record,dict) and set(record)=={'profile','config','private_key'}
                    and record['profile']==RECORD_PROFILE and record['config']==self.config,'E_KEYCHAIN_RECORD')
            key=Ed25519PrivateKey.from_private_bytes(unb64(record['private_key']))
            require(b64(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
                    ==self.config['public_key'],'E_KEYCHAIN_RECORD')
            return key
        except Fault:
            raise
        except Exception:
            raise Fault('E_KEYCHAIN_UNAVAILABLE') from None

    def public_key(self):
        return Ed25519PublicKey.from_public_bytes(unb64(self.config['public_key']))

    def sign(self, message):
        require(isinstance(message,bytes) and message.startswith(DOMAIN),'E_KEYCHAIN_SCOPE')
        return self._load().sign(message)  # load only for this call, no cached private key


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding',required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--confirm-create',action='store_true')
    mode.add_argument('--inspect-existing',action='store_true')
    args=parser.parse_args()
    try:
        binding=strict_json(read_file(args.binding,8192))
        result=(KeychainWitnessSigner.provision(binding,confirmed=True) if args.confirm_create else
                KeychainWitnessSigner.inspect_existing(binding) if args.inspect_existing else public_plan(binding))
        print(json.dumps(result,indent=2))
    except Exception as error:
        print(json.dumps({'status':'unavailable','code':getattr(error,'code','E_KEYCHAIN_UNAVAILABLE')}))
        raise SystemExit(2)
