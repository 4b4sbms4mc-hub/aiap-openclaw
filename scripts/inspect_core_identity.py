# SPDX-License-Identifier: Apache-2.0
"""Read-only public enrollment fingerprint, never private keys or memory rows."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

if __file__ != '<stdin>':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lavida/core'))
from aiap_core.service import SQL
from aiap_core.contracts import canonical, digest, unb64, require, Fault
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'E_IDENTITY_SCHEMA')
            result[key]=value
        return result
    def invalid(_):
        raise Fault('E_IDENTITY_SCHEMA')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)


def inspect_identity(data_dir):
    directory = Path(data_dir)
    path = directory/'core.sqlite3'
    require(not directory.is_symlink() and not path.is_symlink() and path.is_file(), 'E_IDENTITY_FILE')
    require(not any((directory/('core.sqlite3'+suffix)).exists()
                    for suffix in ('-wal','-shm','-journal')), 'E_IDENTITY_SIDECAR')
    expected = sqlite3.connect(':memory:')
    query = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name"
    try:
        expected.executescript(SQL)
        schema = expected.execute(query).fetchall()
    finally:
        expected.close()
    db = sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True, timeout=1)
    try:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF'); db.execute('BEGIN')
        require(db.execute(query).fetchall() == schema, 'E_IDENTITY_SCHEMA')
        meta = {}
        for name in ('avatar','owner','enrollment'):
            row = db.execute('SELECT value FROM meta WHERE key=? AND length(value)<=65536',(name,)).fetchone()
            require(row is not None, 'E_IDENTITY_SCHEMA')
            meta[name] = strict_json(row[0])
        enrollment = meta['enrollment']
        require(isinstance(enrollment,dict) and set(enrollment)=={'payload','signature'}, 'E_IDENTITY_SCHEMA')
        payload = enrollment['payload']
        require(isinstance(payload,dict) and set(payload)=={'profile','avatar_id','owner_ref',
                'owner_public_key','avatar_public_key','created_at'}, 'E_IDENTITY_SCHEMA')
        require(payload['profile']=='x-aiap-local-enrollment-v1'
                and isinstance(meta['avatar'],str) and meta['avatar'].startswith('avatar:')
                and isinstance(meta['owner'],str) and meta['owner'].startswith('aiap-id:')
                and payload['avatar_id']==meta['avatar'] and payload['owner_ref']==meta['owner'], 'E_IDENTITY')
        try:
            owner = unb64(payload['owner_public_key']); avatar = unb64(payload['avatar_public_key'])
            Ed25519PublicKey.from_public_bytes(avatar)
            Ed25519PublicKey.from_public_bytes(owner).verify(unb64(enrollment['signature']),
                b'AIAP-LOCAL-ENROLLMENT-v1\x00'+canonical(payload))
        except Exception:
            raise Fault('E_INTEGRITY') from None
        return {'profile':'x-aiap-public-identity-fingerprint-v1','avatar_id':meta['avatar'],
                'owner_ref':meta['owner'],'enrollment_sha256':digest(enrollment),
                'owner_public_key_sha256':hashlib.sha256(owner).hexdigest(),
                'avatar_public_key_sha256':hashlib.sha256(avatar).hexdigest(),
                'local_enrollment_signature':'valid','database_access':'read-only',
                'trust':'operator must confirm intended source; not a global ownership proof'}
    finally:
        db.close()


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(inspect_identity(args.data_dir),indent=2))
    except Exception as error:
        print(json.dumps({'status':'unavailable','code':getattr(error,'code','E_IDENTITY_READ')}))
        raise SystemExit(2)
