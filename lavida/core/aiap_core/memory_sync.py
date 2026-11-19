"""Create a signed, single-space snapshot for a specific recipient Core."""
from datetime import timedelta
from hashlib import sha256
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import Fault, b64, canonical, digest, exact, require, unb64, validate
from .recovery_checkpoint import manifest, read_file, strict_json
from .service import parse, save_private, stamp


PROFILE = 'x-aiap-local-memory-sync-v1'
DOMAIN = b'AIAP-LOCAL-MEMORY-SYNC-v1\x00'
MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 512
SPACES = ('space:general', 'space:life', 'space:work')


def _publish_private(output, raw):
    path = Path(output)
    try:
        parent = path.parent.stat()
        require(parent.st_uid == os.getuid() and not parent.st_mode & 0o077, 'E_SYNC_OUTPUT')
        with TemporaryDirectory(prefix='.aiap-sync-', dir=path.parent) as staging:
            staged = Path(staging) / 'bundle.json'
            save_private(staged, raw)
            os.link(staged, path)
    except FileExistsError:
        raise Fault('E_OUTPUT_EXISTS', 409) from None
    except OSError:
        raise Fault('E_SYNC_OUTPUT') from None


def export_memory(service, token, source_space, target_space, target_enrollment, output):
    require(re.fullmatch('[0-9a-f]{64}', target_enrollment), 'E_SYNC_TARGET')
    require(target_space in SPACES, 'E_SYNC_TARGET')
    with service.tx(read_only=True) as connection:
        grant = service._grant(connection, token)
        service._allow(grant, [source_space], 'read', owner=True)
        source_scope = service._scope(connection, grant, source_space)
        avatar = grant['avatar']
        enrollment = service.meta(connection, 'enrollment')
        require(digest(enrollment) != target_enrollment, 'E_SYNC_TARGET')
        row = connection.execute('SELECT revision,body FROM cores WHERE avatar=?', (avatar,)).fetchone()
        require(row is not None, 'E_INTEGRITY')
        core = strict_json(row['body'])
        require(core['avatar_id'] == avatar and row['revision'] == core['revision']
                and service.verify_local_core(core, enrollment), 'E_INTEGRITY')
        refs = manifest(core)
        scope_refs = {ident: ref for ident, ref in refs.items() if ref['scope']['space_ref'] == source_space}
        require(len(scope_refs) <= MAX_ROWS, 'E_SYNC_SIZE')
        memory_rows = connection.execute(
            'SELECT id,revision,body FROM memories WHERE avatar=? AND space=? ORDER BY id LIMIT ?',
            (avatar, source_space, MAX_ROWS + 1),
        ).fetchall()
        require({record['id'] for record in memory_rows} == set(scope_refs), 'E_INTEGRITY')
        memories = []
        for record in memory_rows:
            memory = strict_json(record['body'])
            validate('memory-record', memory)
            ref = scope_refs[record['id']]
            require(memory['memory_id'] == record['id'] and memory['scope'] == source_scope == ref['scope']
                    and record['revision'] == memory['revision'] == ref['version']
                    and digest(memory) == ref['sha256'], 'E_INTEGRITY')
            require(memory['status'] == 'active' and isinstance(memory['content'], str)
                    and not memory['derived_from'] and not memory.get('extensions'), 'E_OPERATION_UNSUPPORTED')
            memories.append({field: memory[field] for field in ('memory_id', 'revision', 'content', 'level')})
        deleted_rows = connection.execute(
            'SELECT id,revision,body FROM tombstones WHERE avatar=? AND space=? ORDER BY id LIMIT ?',
            (avatar, source_space, MAX_ROWS - len(memories) + 1),
        ).fetchall()
        require(len(memories) + len(deleted_rows) <= MAX_ROWS, 'E_SYNC_SIZE')
        tombstones = []
        for record in deleted_rows:
            tombstone = strict_json(record['body'])
            validate('tombstone', tombstone)
            require(tombstone['scope'] == source_scope and record['id'] not in refs
                    and tombstone['object_ref'] == {'id': record['id'], 'version': record['revision']}
                    and tombstone['supersedes_through_revision'] == record['revision'], 'E_INTEGRITY')
            tombstones.append({'memory_id': record['id'], 'revision': record['revision']})
        now = service.now()
        service._grant(connection, token)
        payload = {
            'profile': PROFILE, 'source_enrollment': enrollment, 'source_space': source_space,
            'source_revision': core['revision'], 'source_revocation_epoch': service.meta(connection, 'revocation_epoch'),
            'target_enrollment_sha256': target_enrollment, 'target_space': target_space,
            'issued_at': stamp(now), 'expires_at': stamp(now + timedelta(hours=1)),
            'memories': memories, 'tombstones': tombstones,
        }
        key = serialization.load_pem_private_key(read_file(service.directory / 'avatar-key.pem', 16384), None)
        actual_key = b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        require(actual_key == enrollment['payload']['avatar_public_key'], 'E_INTEGRITY')
        raw = canonical({'payload': payload, 'signature': b64(key.sign(DOMAIN + canonical(payload)))})
        require(len(raw) <= MAX_BYTES, 'E_SYNC_SIZE')
    _publish_private(output, raw)
    return {'status': 'exported', 'sha256': sha256(raw).hexdigest(), 'memories': len(memories),
            'tombstones': len(tombstones), 'expires_at': payload['expires_at']}


def _verify_bundle(path, source_enrollment, now):
    require(re.fullmatch('[0-9a-f]{64}', source_enrollment), 'E_SYNC_SOURCE')
    try:
        envelope = strict_json(read_file(path, MAX_BYTES))
        exact(envelope, ['payload', 'signature'])
        payload = envelope['payload']
        exact(payload, ['profile', 'source_enrollment', 'source_space', 'source_revision',
                        'source_revocation_epoch', 'target_enrollment_sha256', 'target_space',
                        'issued_at', 'expires_at', 'memories', 'tombstones'])
        require(payload['profile'] == PROFILE, 'E_CRITICAL_EXTENSION')
        enrollment = payload['source_enrollment']
        require(digest(enrollment) == source_enrollment, 'E_SYNC_SOURCE')
        exact(enrollment, ['payload', 'signature'])
        identity = enrollment['payload']
        exact(identity, ['profile', 'owner_ref', 'avatar_id', 'owner_public_key', 'avatar_public_key', 'created_at'])
        require(identity['profile'] == 'x-aiap-local-enrollment-v1', 'E_CRITICAL_EXTENSION')
        Ed25519PublicKey.from_public_bytes(unb64(identity['owner_public_key'])).verify(
            unb64(enrollment['signature']), b'AIAP-LOCAL-ENROLLMENT-v1\x00' + canonical(identity))
        Ed25519PublicKey.from_public_bytes(unb64(identity['avatar_public_key'])).verify(
            unb64(envelope['signature']), DOMAIN + canonical(payload))
        issued, expires = parse(payload['issued_at']), parse(payload['expires_at'])
        require(issued <= now < expires and expires - issued <= timedelta(hours=1), 'E_EXPIRED')
        require(payload['source_space'] in SPACES and payload['target_space'] in SPACES, 'E_SCOPE')
        require(type(payload['source_revision']) is int and payload['source_revision'] > 0
                and type(payload['source_revocation_epoch']) is int and payload['source_revocation_epoch'] >= 0)
        memories, tombstones = payload['memories'], payload['tombstones']
        require(isinstance(memories, list) and isinstance(tombstones, list))
        require(len(memories) + len(tombstones) <= MAX_ROWS, 'E_SYNC_SIZE')
        identifiers = set()
        for records, fields in ((memories, ['content', 'level']), (tombstones, [])):
            for record in records:
                exact(record, ['memory_id', 'revision', *fields])
                ident = record['memory_id']
                require(isinstance(ident, str) and 0 < len(ident) <= 200 and ident not in identifiers
                        and type(record['revision']) is int and record['revision'] > 0)
                identifiers.add(ident)
                if fields:
                    require(isinstance(record['content'], str) and 0 < len(record['content']) <= 16000
                            and record['level'] in ('M1', 'M2', 'M3'))
        return payload
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, InvalidSignature):
        raise Fault('E_SYNC_BUNDLE') from None


def preview_memory(service, token, path, source_enrollment, source_space, target_space):
    with service.tx(read_only=True) as connection:
        grant = service._grant(connection, token)
        service._allow(grant, [target_space], 'write', owner=True)
        service._scope(connection, grant, target_space)
        recipient = digest(service.meta(connection, 'enrollment'))
        require(recipient != source_enrollment, 'E_SYNC_SOURCE')
        payload = _verify_bundle(path, source_enrollment, service.now())
        require(payload['source_space'] == source_space, 'E_SCOPE', 403)
        require(payload['target_enrollment_sha256'] == recipient and payload['target_space'] == target_space,
                'E_SYNC_TARGET')
        service._grant(connection, token)
    return {'status': 'verified-no-import', 'source_space': payload['source_space'], 'target_space': target_space,
            'source_revision': payload['source_revision'], 'source_revocation_epoch': payload['source_revocation_epoch'],
            'memories': len(payload['memories']), 'tombstones': len(payload['tombstones']),
            'expires_at': payload['expires_at']}
