"""Single-owner local Core Service. No remote identity/transfer activation.
Wang Lu. Request authorization is resolved inside each SQLite transaction.
"""
import sqlite3,json,secrets,hashlib,os,uuid,copy
import re
import hmac
import stat
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime,timezone,timedelta
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from . import lexical
from .contracts import Fault,require,validate,canonical,digest,b64,unb64,exact,names,search_levels

def uid(prefix):return prefix+str(uuid.uuid4())
def stamp(dt):return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
def parse(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def encode(data):return canonical(data).decode('utf-8')
def save_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)

SQL='''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cores(avatar TEXT PRIMARY KEY,owner TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS spaces(avatar TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,policy TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(avatar,id));
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,avatar TEXT NOT NULL,subject TEXT NOT NULL,role TEXT NOT NULL,scopes TEXT NOT NULL,actions TEXT NOT NULL,purpose TEXT NOT NULL,runtime TEXT NOT NULL,session TEXT NOT NULL,issued TEXT NOT NULL,expires TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS memories(avatar TEXT NOT NULL,id TEXT NOT NULL,space TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(avatar,id));
CREATE INDEX IF NOT EXISTS memories_scope ON memories(avatar,space);
CREATE TABLE IF NOT EXISTS deltas(avatar TEXT NOT NULL,id TEXT NOT NULL,issuer TEXT NOT NULL,scopes TEXT NOT NULL,payload_hash TEXT NOT NULL,body TEXT,status TEXT NOT NULL,outcome TEXT,PRIMARY KEY(avatar,id));
CREATE TABLE IF NOT EXISTS history(avatar TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,space TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(avatar,id,revision));
CREATE TABLE IF NOT EXISTS tombstones(avatar TEXT NOT NULL,id TEXT NOT NULL,space TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,PRIMARY KEY(avatar,id));
CREATE TABLE IF NOT EXISTS views(id TEXT PRIMARY KEY,avatar TEXT NOT NULL,grant_id TEXT NOT NULL,scopes TEXT NOT NULL,body TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0,invalidated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,avatar TEXT NOT NULL,space TEXT,event TEXT NOT NULL,object_id TEXT,at TEXT NOT NULL,actor TEXT NOT NULL);
'''

# The Owner must cover every participating space, even when filtering to one.
_PROPOSAL_SCOPES_VISIBLE = '''NOT EXISTS (
    SELECT 1 FROM json_each(delta.scopes) AS scope
    WHERE NOT EXISTS (
        SELECT 1 FROM json_each(:allowed) AS allowed WHERE allowed.value = scope.value
    )
)'''
_BASE_EXTENSION = {'namespace': 'x-aiap-core-profile', 'version': '0.1-draft', 'critical': True}
_PREFERENCE_EXTENSION = {'namespace': 'x-aiap-local-preference-index', 'version': '1', 'critical': True}
_PREFERENCE_REF_PREFIX = 'preference-manifest:'
_COMPACT_CORE_PROFILE = 'x-aiap-local-compact-core-v1'
_SPACE_MANIFEST_PROFILE = 'x-aiap-local-space-manifest-v1'
_SUMMARY_SELECTION_FILE = 'profile-summary-selections.json'
_SUMMARY_SELECTION_LIMIT = 16384
LOCAL_LIFECYCLE_EXTENSION = 'x-aiap-local-memory-lifecycle'
LOCAL_ADMISSION_EXTENSION = 'x-aiap-local-memory-admission'
LOCAL_LIFECYCLE_DOMAIN = 'aiap.memory.lifecycle'
LOCAL_LIFECYCLE_TRANSITIONS = {
    'promote': (('M1',), 'M2', 'memory-promoted'),
    'reactivate': (('M3',), 'M1', 'memory-reactivated'),
    'archive': (('M1', 'M2'), 'M3', 'memory-archived'),
}

VALIDITY_EXTENSION = 'x-aiap-memory-validity-v1'

DECISION_REASONS = ('owner-confirmed', 'duplicate', 'outdated', 'incorrect', 'insufficient-evidence', 'out-of-scope')

class Service:
    def __init__(self,data_dir,clock=None,*,enable_semantic=True):
        from .semantic import Semantic
        self.semantic=Semantic.from_environment() if enable_semantic else None
        self.directory=Path(data_dir);self.db=self.directory/'core.sqlite3';self.clock=clock or (lambda:datetime.now(timezone.utc))
    def now(self):return self.clock().astimezone(timezone.utc)
    @contextmanager
    def tx(self, *, read_only=False):
        require(self.db.exists(),'E_NOT_INITIALIZED',503)
        location = self.db.resolve().as_uri() + '?mode=ro' if read_only else self.db
        connection = sqlite3.connect(location, uri=read_only, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute('PRAGMA foreign_keys=ON')
            if not read_only:
                connection.execute('PRAGMA secure_delete=ON')
            connection.execute('BEGIN' if read_only else 'BEGIN IMMEDIATE')
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
    def initialize(self):
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        require(not self.db.exists(),'E_ALREADY_INITIALIZED',409)
        # Exclusive DB creation prevents simultaneous bootstraps silently replacing identity.
        fd=os.open(self.db,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        c=sqlite3.connect(self.db);c.executescript(SQL);c.close()
        owner=uid('aiap-id:');avatar=uid('avatar:')
        owner_key=Ed25519PrivateKey.generate();avatar_key=Ed25519PrivateKey.generate()
        def pem(k):return k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        save_private(self.directory/'owner-key.pem',pem(owner_key));save_private(self.directory/'avatar-key.pem',pem(avatar_key))
        owner_pub=b64(owner_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        avatar_pub=b64(avatar_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        enrollment={'owner_ref':owner,'avatar_id':avatar,'owner_public_key':owner_pub,'avatar_public_key':avatar_pub,'created_at':stamp(self.now()),'profile':'x-aiap-local-enrollment-v1'}
        enrollment={'payload':enrollment,'signature':b64(owner_key.sign(b'AIAP-LOCAL-ENROLLMENT-v1\x00'+canonical(enrollment)))}
        with self.tx() as c:
            for key,value in [('enrollment',enrollment),('avatar',avatar),('owner',owner),('revocation_epoch',0)]:c.execute('INSERT INTO meta VALUES(?,?)',(key,encode(value)))
            for kind in ['general','life','work']:
                sid='space:'+kind
                c.execute('INSERT INTO spaces VALUES(?,?,?,?,?)',(avatar,sid,'personal-'+kind,'policy:'+kind,1))
            c.execute('INSERT INTO cores VALUES(?,?,?,?)',(avatar,owner,0,'{}'))
            self._rebuild_core(c,avatar)
        credential=self.issue_grant(['space:general','space:life','space:work'],'owner-maintenance','owner-local','owner',30)
        save_private(self.directory/'owner-credentials.json',canonical(credential))
        return {'initialized':True,'avatar_id':avatar,'credential_file':'owner-credentials.json'}
    def meta(self,c,key):
        r=c.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone();require(r is not None,'E_STORAGE',500);return json.loads(r[0])
    def _audit(self,c,av,space,event,obj,actor):
        ident=uid('audit:');c.execute('INSERT INTO audit VALUES(?,?,?,?,?,?,?)',(ident,av,space,event,obj,stamp(self.now()),actor));return ident
    def _rebuild_core(self,c,av):
        row=c.execute('SELECT * FROM cores WHERE avatar=?',(av,)).fetchone();require(row is not None,'E_DENIED',403)
        extras = []
        extensions = [_BASE_EXTENSION]
        expected_key = None
        if row['revision']:
            previous, enrollment = self._load_signed_core(c, av)
            extensions = previous['extensions']
            expected_key = enrollment['payload']['avatar_public_key']
            if extensions != [_BASE_EXTENSION]:
                commitments = self._preference_references(previous)
                for sid, ref in commitments.items():
                    scope = self._scope(c, {'avatar': av, 'subject': previous['owner']['owner_ref']}, sid)
                    self._check_preference_ref(c, previous, scope, commitments)
                    extras.append(ref)
        refs=[]
        for r in c.execute('SELECT body FROM memories WHERE avatar=? ORDER BY id',(av,)):
            m=json.loads(r['body']);refs.append({'id':m['memory_id'],'version':m['revision'],'scope':m['scope'],'sha256':digest(m)})
        if extensions != [_BASE_EXTENSION]:
            require(all(not ref['id'].startswith(_PREFERENCE_REF_PREFIX) for ref in refs), 'E_INTEGRITY', 500)
        refs.extend(extras)
        n=row['revision']+1
        core={'aiap_version':'0.4.2','profile_version':'0.1-draft','avatar_id':av,'owner':{'owner_ref':row['owner'],'owner_key_ref':'local-key:owner','avatar_key_ref':'local-key:avatar'},'revision':n,'previous_revision':n-1 if n>1 else None,'identity_refs':['local-identity:enrollment'],'profile_summary':[],'state_index':refs,'procedural_index':[],'extensions':extensions,'updated_at':stamp(self.now())}
        self._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00', expected_public_key=expected_key)
        validate('avatar-core',core);c.execute('UPDATE cores SET revision=?,body=? WHERE avatar=?',(n,encode(core),av))

    def _sign_core(self, core, profile, domain, *, expected_public_key=None):
        payload = canonical(core)
        key = serialization.load_pem_private_key((self.directory / 'avatar-key.pem').read_bytes(), None)
        if expected_public_key is not None:
            require(isinstance(key, Ed25519PrivateKey)
                    and b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                    == expected_public_key, 'E_INTEGRITY', 500)
        core['integrity'] = {
            'manifest_sha256': hashlib.sha256(payload).hexdigest(),
            'proofs': [{'crypto_profile': profile, 'key_ref': 'local-key:avatar',
                        'signature': b64(key.sign(domain + payload))}],
        }

    @staticmethod
    def verify_local_core(core,enrollment):
        try:
            p=enrollment['payload'];require(p['profile']=='x-aiap-local-enrollment-v1','E_INTEGRITY');Ed25519PublicKey.from_public_bytes(unb64(p['owner_public_key'])).verify(unb64(enrollment['signature']),b'AIAP-LOCAL-ENROLLMENT-v1\x00'+canonical(p))
            bare=copy.deepcopy(core);proof=bare.pop('integrity');raw=canonical(bare)
            require(len(proof['proofs'])==1 and proof['proofs'][0]['crypto_profile']=='x-aiap-local-ed25519-json-v1' and proof['proofs'][0]['key_ref']=='local-key:avatar','E_INTEGRITY')
            require(proof['manifest_sha256']==hashlib.sha256(raw).hexdigest(),'E_INTEGRITY')
            require(p['avatar_id']==core['avatar_id'] and p['owner_ref']==core['owner']['owner_ref'],'E_INTEGRITY')
            Ed25519PublicKey.from_public_bytes(unb64(p['avatar_public_key'])).verify(unb64(proof['proofs'][0]['signature']),b'AIAP-LOCAL-CORE-v1\x00'+raw)
            return True
        except Exception:return False
    def create_project_space(self, slug):
        """Local operator operation. Creating a space never expands existing grants."""
        require(isinstance(slug, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', slug))
        space = 'space:project:' + slug
        with self.tx() as connection:
            avatar = self.meta(connection, 'avatar')
            row = connection.execute('SELECT kind FROM spaces WHERE avatar=? AND id=?', (avatar, space)).fetchone()
            if row:
                require(row['kind'] == 'project', 'E_SCOPE', 409)
                return {'space_ref': space, 'created': False}
            connection.execute('INSERT INTO spaces VALUES(?,?,?,?,?)',
                               (avatar, space, 'project', 'policy:project:' + slug, 1))
            self._audit(connection, avatar, space, 'project-space-created', space, 'local-operator')
            return {'space_ref': space, 'created': True}

    def issue_grant(self,scopes,purpose,runtime,role='adapter',days=7):
        # Local operator command only; never exposed over HTTP.
        require(names(scopes) and isinstance(purpose,str) and 0<len(purpose)<=200 and isinstance(runtime,str) and 0<len(runtime)<=200)
        require(role in ('owner','adapter') and isinstance(days,int) and 1<=days<=30)
        actions = ['read', 'write', 'delete', 'admin'] if role == 'owner' else ['read', 'write']
        with self.tx() as connection:
            avatar = self.meta(connection, 'avatar')
            subject = self.meta(connection, 'owner')
            return self._insert_grant(connection, avatar, subject, role, scopes, actions,
                                      purpose, runtime, self.now(), days)

    def reissue_grant(self, grant_id, *, days=7):
        require(isinstance(grant_id, str) and 0 < len(grant_id) <= 200)
        require(type(days) is int and 1 <= days <= 30)
        with self.tx() as connection:
            avatar = self.meta(connection, 'avatar')
            grant = connection.execute('SELECT * FROM grants WHERE avatar=? AND id=?',
                                       (avatar, grant_id)).fetchone()
            require(grant is not None, 'E_NOT_FOUND', 404)
            now = self.now()
            require(not grant['revoked'] and parse(grant['issued']) <= now, 'E_GRANT_NOT_REISSUABLE', 409)
            return self._insert_grant(connection, avatar, grant['subject'], grant['role'],
                                      json.loads(grant['scopes']), json.loads(grant['actions']),
                                      grant['purpose'], grant['runtime'], now, days)

    def _insert_grant(self, connection, avatar, subject, role, scopes, actions, purpose, runtime, now, days):
        known = {row['id'] for row in connection.execute('SELECT id FROM spaces WHERE avatar=?', (avatar,))}
        require(set(scopes) <= known, 'E_SCOPE', 403)
        token = secrets.token_urlsafe(32)
        grant_id = uid('grant:')
        expires = stamp(now + timedelta(days=days))
        connection.execute('INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)',
                           (grant_id, hashlib.sha256(token.encode()).hexdigest(), avatar, subject,
                            role, encode(scopes), encode(actions), purpose, runtime, uid('session:'),
                            stamp(now), expires))
        self._audit(connection, avatar, None, 'credential-issued', grant_id, 'local-operator')
        return {'token': token, 'grant_id': grant_id, 'avatar_id': avatar, 'role': role,
                'space_refs': scopes, 'purpose': purpose, 'runtime_ref': runtime, 'expires_at': expires}

    def revoke_grant(self,ident):
        with self.tx() as c:
            grant = c.execute('SELECT avatar, revoked FROM grants WHERE id=?', (ident,)).fetchone()
            require(grant is not None, 'E_NOT_FOUND', 404)
            if grant['revoked']:
                return
            c.execute('UPDATE grants SET revoked=1 WHERE id=?', (ident,))
            epoch = self.meta(c, 'revocation_epoch') + 1
            c.execute('UPDATE meta SET value=? WHERE key=?', (encode(epoch), 'revocation_epoch'))
            self._audit(c, grant['avatar'], None, 'credential-revoked', ident, 'local-operator')
    def grant_status(self, token):
        require(isinstance(token, str) and 20 <= len(token) <= 200, 'E_IDENTITY', 401)
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
        except UnicodeEncodeError:
            raise Fault('E_IDENTITY', 401) from None
        with self.tx(read_only=True) as c:
            grant = c.execute(
                'SELECT id, role, scopes, issued, expires, revoked FROM grants WHERE token_hash=?',
                (token_hash,),
            ).fetchone()
            now = self.now()
        if grant is None:
            return {'status': 'unknown'}
        return self._grant_summary(grant, now)

    @staticmethod
    def _grant_summary(grant, now):
        if grant['revoked']:
            status = 'revoked'
        elif now < parse(grant['issued']):
            status = 'not-yet-valid'
        elif now >= parse(grant['expires']):
            status = 'expired'
        else:
            status = 'active'
        return {
            'status': status,
            'grant_id': grant['id'],
            'role': grant['role'],
            'space_refs': json.loads(grant['scopes']),
            'issued_at': grant['issued'],
            'expires_at': grant['expires'],
        }

    def list_grants(self, *, role=None, after=None, limit=20):
        # Local operator command only, like grant issuance and revocation.
        require(role in (None, 'owner', 'adapter'))
        require(after is None or (isinstance(after, str) and 0 < len(after) <= 200))
        require(type(limit) is int and 1 <= limit <= 100)
        with self.tx(read_only=True) as connection:
            avatar = self.meta(connection, 'avatar')
            now = self.now()
            rows = connection.execute('''
                SELECT id, role, scopes, purpose, runtime, issued, expires, revoked
                FROM grants
                WHERE avatar = :avatar AND id > :after
                  AND (:role IS NULL OR role = :role)
                ORDER BY id LIMIT :page_size
            ''', {'avatar': avatar, 'after': after or '', 'role': role, 'page_size': limit + 1}).fetchall()
        grants = [{**self._grant_summary(row, now), 'purpose': row['purpose'], 'runtime_ref': row['runtime']}
                  for row in rows[:limit]]
        return {'grants': grants, 'next_after': grants[-1]['grant_id'] if len(rows) > limit else None}

    def _grant(self,c,token=None,ident=None):
        if token is not None:
            require(isinstance(token,str) and 20<=len(token)<=200,'E_IDENTITY',401)
            g=c.execute('SELECT * FROM grants WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        else:g=c.execute('SELECT * FROM grants WHERE id=?',(ident,)).fetchone()
        require(g is not None and not g['revoked'],'E_IDENTITY',401)
        require(parse(g['issued'])<=self.now()<parse(g['expires']),'E_IDENTITY',401)
        return dict(g)
    def _allow(self,g,scopes,action,purpose=None,owner=False):
        require(names(scopes),'E_SCHEMA')
        require(set(scopes)<=set(json.loads(g['scopes'])) and action in json.loads(g['actions']),'E_DENIED',403)
        if purpose is not None:require(purpose==g['purpose'],'E_DENIED',403)
        if owner:require(g['role']=='owner','E_DENIED',403)
    def _scope(self,c,g,sid):
        r=c.execute('SELECT * FROM spaces WHERE avatar=? AND id=?',(g['avatar'],sid)).fetchone();require(r is not None,'E_DENIED',403)
        return {'owner_ref':g['subject'],'space_ref':sid,'policy_ref':{'id':r['policy'],'version':r['revision']}}
    def session(self,token):
        with self.tx(read_only=True) as c:
            g=self._grant(c,token);scopes=json.loads(g['scopes'])
            result = {'avatar_id':g['avatar'],'subject_ref':g['subject'],'role':g['role'],'runtime_ref':g['runtime'],'session_ref':g['session'],'auth_evidence_ref':g['id'],'purpose':g['purpose'],'space_refs':scopes,'scopes':[self._scope(c,g,s) for s in scopes],'issued_at':g['issued'],'expires_at':g['expires'],'actions':json.loads(g['actions']),'retrieval':('scoped-hybrid-cosine' if self.semantic and set(scopes)<=self.semantic.scopes else lexical.METHOD)}
            result['memory_browse'] = 'cursor-v1'
            result['proposal_admission'] = 'checked-v1'
            result['proposal_revision'] = True
            result['proposal_status'] = 'issuer-v1'
            result['archive_proposal'] = True
            result['context_feedback'] = True
            result['proposal_batch'] = True
            result['memory_links'] = True
            if self.semantic and set(scopes) <= self.semantic.scopes:
                if setup := getattr(self.semantic, 'setup', None):
                    result['embedding_setup'] = setup()
            return result
    def core(self,token):
        with self.tx() as c:
            _, _, core, enrollment = self._owner_core(c, token)
            return {'avatar_core':core,'local_enrollment':enrollment,'trust_model':'local-bootstrap; not remote-owner-verification'}

    def _owner_core(self, connection, token):
        owner = self._grant(connection, token)
        avatar = owner['avatar']
        spaces = [row['id'] for row in connection.execute('SELECT id FROM spaces WHERE avatar=? ORDER BY id', (avatar,))]
        self._allow(owner, spaces, 'read', owner=True)
        core, enrollment = self._load_signed_core(connection, avatar)
        return owner, spaces, core, enrollment

    def _load_signed_core(self, connection, avatar):
        row = connection.execute('SELECT revision, body FROM cores WHERE avatar=?', (avatar,)).fetchone()
        require(row is not None, 'E_INTEGRITY', 500)
        core = json.loads(row['body'])
        enrollment = self.meta(connection, 'enrollment')
        require(core['avatar_id'] == avatar and core['revision'] == row['revision']
                and self.verify_local_core(core, enrollment), 'E_INTEGRITY', 500)
        return core, enrollment

    def _summary_source(self, connection, owner, ref):
        space = ref['scope']['space_ref']
        self._allow(owner, [space], 'read', owner=True)
        row = connection.execute(
            'SELECT revision, body FROM memories WHERE avatar=? AND space=? AND id=?',
            (owner['avatar'], space, ref['id']),
        ).fetchone()
        require(row is not None and row['revision'] == ref['version'], 'E_VERSION_CONFLICT', 409)
        memory = json.loads(row['body'])
        require(memory['scope'] == ref['scope'] == self._scope(connection, owner, space)
                and digest(memory) == ref['sha256'], 'E_INTEGRITY', 500)
        require(self.current_memory(memory) and memory['level'] == 'M2' and memory['retention']['pinned']
                and isinstance(memory['content'], str) and len(memory['content']) <= 1024,
                'E_SUMMARY_SOURCE', 409)
        return memory['content']

    def read_profile_summary(self, token, space, memory_id=None, revision=None):
        use_saved = memory_id is None and revision is None
        require(use_saved or (isinstance(memory_id, str) and 0 < len(memory_id) <= 200
                              and type(revision) is int and revision > 0))
        with self.tx(read_only=True) as connection:
            owner = self._grant(connection, token)
            self._allow(owner, [space], 'read', owner=True)
            selection = None
            if use_saved:
                selection = self._load_summary_selections(owner['avatar']).get(space)
                require(selection is not None, 'E_NOT_FOUND', 404)
                memory_id, revision = selection['id'], selection['version']
            ref = self._current_summary_ref(connection, owner, space, memory_id, revision)
            if selection is not None:
                require(ref['sha256'] == selection['sha256'], 'E_VERSION_CONFLICT', 409)
            return {'reference': ref, 'text': self._summary_source(connection, owner, ref)}

    def _current_summary_ref(self, connection, owner, space, memory_id, revision):
        core, _ = self._load_signed_core(connection, owner['avatar'])
        ref = next((ref for ref in core['state_index']
                    if ref['id'] == memory_id and ref['scope']['space_ref'] == space), None)
        require(ref is not None, 'E_NOT_FOUND', 404)
        require(ref['version'] == revision, 'E_VERSION_CONFLICT', 409)
        return ref

    def _load_summary_selections(self, avatar):
        path = self.directory / _SUMMARY_SELECTION_FILE
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return {}
        except OSError:
            raise Fault('E_SUMMARY_SELECTION_FILE') from None
        try:
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                        'E_SUMMARY_SELECTION_FILE')
                raw = stream.read(_SUMMARY_SELECTION_LIMIT + 1)
            require(len(raw) <= _SUMMARY_SELECTION_LIMIT, 'E_SUMMARY_SELECTION_FILE')
            data = json.loads(raw)
            exact(data, ['avatar_id', 'spaces'])
            require(data['avatar_id'] == avatar and isinstance(data['spaces'], dict)
                    and len(data['spaces']) <= 16, 'E_SUMMARY_SELECTION_FILE')
            for space, selection in data['spaces'].items():
                exact(selection, ['id', 'version', 'sha256'])
                require(0 < len(space) <= 200 and isinstance(selection['id'], str)
                        and 0 < len(selection['id']) <= 200 and type(selection['version']) is int
                        and selection['version'] > 0 and isinstance(selection['sha256'], str)
                        and re.fullmatch('[0-9a-f]{64}', selection['sha256']), 'E_SUMMARY_SELECTION_FILE')
            return data['spaces']
        except (OSError, ValueError, RecursionError):
            raise Fault('E_SUMMARY_SELECTION_FILE') from None

    def set_summary_selection(self, token, space, *, memory_id=None, revision=None):
        clearing = memory_id is None and revision is None
        require(clearing or (isinstance(memory_id, str) and 0 < len(memory_id) <= 200
                             and type(revision) is int and revision > 0))
        with self.tx() as connection:
            owner = self._grant(connection, token)
            self._allow(owner, [space], 'write', owner=True)
            self._scope(connection, owner, space)
            selections = self._load_summary_selections(owner['avatar'])
            if clearing:
                if selections.pop(space, None) is None:
                    return {'space_ref': space, 'selection': None}
            else:
                ref = self._current_summary_ref(connection, owner, space, memory_id, revision)
                self._summary_source(connection, owner, ref)
                selections[space] = {key: ref[key] for key in ('id', 'version', 'sha256')}
            data = canonical({'avatar_id': owner['avatar'], 'spaces': selections})
            require(len(selections) <= 16 and len(data) <= _SUMMARY_SELECTION_LIMIT, 'E_SUMMARY_SELECTION_FILE')
            try:
                with TemporaryDirectory(prefix='.aiap-summary-', dir=self.directory) as staging:
                    temporary = Path(staging) / _SUMMARY_SELECTION_FILE
                    save_private(temporary, data)
                    with temporary.open('rb') as written:
                        os.fsync(written.fileno())
                    temporary.replace(self.directory / _SUMMARY_SELECTION_FILE)
            except OSError:
                raise Fault('E_SUMMARY_SELECTION_FILE') from None
            return {'space_ref': space, 'selection': selections.get(space)}

    def compact_core(self, token, *, space=None, revision=None, summary_ids=()):
        require((space is None and revision is None)
                or (isinstance(space, str) and type(revision) is int and revision > 0 and not summary_ids))
        with self.tx(read_only=True) as connection:
            owner, spaces, core, enrollment = self._owner_core(connection, token)
            require(len(summary_ids) <= len(spaces) and all(isinstance(ident, str) and 0 < len(ident) <= 200
                                                          for ident in summary_ids))
            selected = set(summary_ids)
            require(len(selected) == len(summary_ids))
            preference_refs = {}
            indexed_preferences = core['extensions'] != [_BASE_EXTENSION]
            if indexed_preferences:
                preference_refs = self._preference_references(core)
                require(set(preference_refs) <= set(spaces), 'E_INTEGRITY', 500)
            require(core['profile_summary'] == [] and core['procedural_index'] == [], 'E_OPERATION_UNSUPPORTED')
            if space is not None:
                require(space in spaces, 'E_SCOPE', 403)
                require(revision == core['revision'], 'E_VERSION_CONFLICT', 409)
            saved = self._load_summary_selections(owner['avatar']) if space is None and not selected else {}
            manifests = {sid: {'profile': _SPACE_MANIFEST_PROFILE, 'avatar_id': core['avatar_id'],
                               'core_revision': core['revision'], 'scope': self._scope(connection, owner, sid),
                               'entries': []} for sid in spaces}
            if indexed_preferences:
                for sid, manifest in manifests.items():
                    if sid in preference_refs:
                        self._check_preference_ref(connection, core, manifest['scope'], preference_refs)
                        manifest['preference_manifest'] = preference_refs[sid]
                    else:
                        require(self._preference_manifest(connection, core['avatar_id'], manifest['scope'])['record_count'] == 0,
                                'E_INTEGRITY', 500)
                    manifest['profile'] = 'x-aiap-local-space-manifest-v2'
            summaries = {}
            for ref in core['state_index']:
                manifest = manifests.get(ref['scope']['space_ref'])
                require(manifest is not None and ref['scope'] == manifest['scope'], 'E_SCOPE', 409)
                if indexed_preferences and ref['id'].startswith(_PREFERENCE_REF_PREFIX):
                    continue
                manifest['entries'].append(ref)
                sid = ref['scope']['space_ref']
                selection = saved.get(sid)
                if ref['id'] in selected or (selection is not None and all(ref[key] == value for key, value in selection.items())):
                    require(sid not in summaries, 'E_SUMMARY_SOURCE', 409)
                    self._summary_source(connection, owner, ref)
                    summaries[sid] = ref
            if selected:
                require(len(summaries) == len(selected), 'E_NOT_FOUND', 404)
            if space is not None:
                manifest = manifests[space]
                return {'manifest': manifest, 'sha256': digest(manifest)}

            core.pop('integrity')
            core['profile_summary'] = [summaries[sid] for sid in spaces if sid in summaries]
            core['state_index'] = [
                {'id': f'manifest:{sid}', 'version': core['revision'],
                 'scope': manifest['scope'], 'sha256': digest(manifest)}
                for sid, manifest in manifests.items()
            ]
            core['extensions'].append({'namespace': _COMPACT_CORE_PROFILE, 'version': '1', 'critical': True})
            self._sign_core(core, _COMPACT_CORE_PROFILE, b'AIAP-LOCAL-COMPACT-CORE-v1\x00',
                            expected_public_key=enrollment['payload']['avatar_public_key'])
            validate('avatar-core', core)
            result = {'avatar_core': core, 'local_enrollment': enrollment}
            stale = set(saved) - set(summaries)
            if stale:
                result['stale_summary_spaces'] = sorted(stale)
            return result

    def list_memories(self, token, body):
        """Keyset page of currently authorized records, ordered by immutable ID."""
        from .admission import MEMORY_TYPES

        exact(body, ['space_ref', 'purpose'], ['level', 'memory_type', 'updated_from', 'updated_before', 'after', 'limit', 'validity'])
        space, purpose = body['space_ref'], body['purpose']
        require(isinstance(purpose, str) and bool(purpose))
        level = body.get('level')
        kind = body.get('memory_type')
        state = body.get('validity', 'current')
        require(state in ('current', 'expired', 'superseded'))
        default_levels = ('M1', 'M2') if state == 'current' else ('M1', 'M2', 'M3')
        require('level' not in body or level in ('M1', 'M2', 'M3'))
        require('memory_type' not in body or kind in MEMORY_TYPES)
        limit = body.get('limit', 20)
        require(type(limit) is int and 1 <= limit <= 100)

        def timestamp(field):
            if field not in body:
                return None
            value = body[field]
            require(isinstance(value, str) and len(value) <= 40 and 'T' in value)
            try:
                dt = parse(value)
                require(dt.tzinfo is not None)
                return stamp(dt)
            except (ValueError, OverflowError):
                raise Fault('E_SCHEMA') from None

        start, end = timestamp('updated_from'), timestamp('updated_before')
        require(not (start and end) or start < end)
        with self.tx(read_only=True) as connection:
            grant = self._grant(connection, token)
            self._allow(grant, [space], 'read', purpose, owner=state != 'current')
            scope = self._scope(connection, grant, space)
            now = self.now()
            cursor_domain = 'memory-list-v1' if state == 'current' else 'memory-list-v1:' + state
            def cursor_tag(memory_id):
                message = canonical([cursor_domain, grant['avatar'], grant['id'], scope,
                                     purpose, level, kind, start, end, memory_id])
                return hmac.digest(token.encode(), message, 'sha256').hex()

            after = ''
            if 'after' in body:
                cursor = body['after']
                require(isinstance(cursor, str) and 0 < len(cursor) <= 512, 'E_CURSOR')
                tag, separator, after = cursor.partition('.')
                require(separator and after and re.fullmatch('[0-9a-f]{64}', tag)
                        and hmac.compare_digest(tag, cursor_tag(after)), 'E_CURSOR')
            rows = connection.execute(
                'SELECT body FROM memories WHERE avatar=? AND space=? AND id>? ORDER BY id',
                (grant['avatar'], space, after))
            items = []
            next_after = None
            for row in rows:
                memory = json.loads(row['body'])
                if memory['scope'] != scope or self._memory_validity(memory, now) != state:
                    continue
                if memory['level'] not in ((level,) if level else default_levels):
                    continue
                if kind and memory['type'] != kind:
                    continue
                updated = stamp(parse(memory['updated_at']))
                if (start and updated < start) or (end and updated >= end):
                    continue
                if len(items) == limit:
                    last = items[-1]['memory_id']
                    next_after = cursor_tag(last) + '.' + last
                    break
                item = {key: memory[key] for key in ('memory_id', 'revision', 'level', 'type', 'updated_at')}
                item['scope'] = scope
                if state != 'current':
                    item['validity'] = memory.get('extensions', {}).get(VALIDITY_EXTENSION, {})
                item['excerpt'] = memory['content'][:240]
                items.append(item)
            return {'space_ref': space, 'items': items, 'next_after': next_after}

    def search(self,token,body,context=False):
        if self.semantic is not None and not context:
            from .semantic import semantic_search
            return semantic_search(self,token,body)
        result = self._literal_search(token, body, context)
        result.update(retrieval_reason="context-lexical" if context else "embedding-not-configured", degraded=False)
        return result
    def _literal_search(self,token,body,context=False):
        condition = None
        override = False
        if context and isinstance(body, dict):
            body = body.copy()
            if 'preference_condition' in body:
                condition = body.pop('preference_condition')
                require(isinstance(condition, str) and condition.strip() and len(condition) <= 2000)
                require(isinstance(body.get('space_refs'), list) and len(body['space_refs']) == 1)
            override = body.pop('skip_preferences', False)
            require(type(override) is bool)
        levels = search_levels(body)
        limit = body.get('limit', 20)
        with self.tx() as c:
            g=self._grant(c,token);scopes=body['space_refs'];self._allow(g,scopes,'read',body['purpose'])
            placeholders=','.join('?' for _ in scopes)
            # SQL scope predicate runs before any body reaches application scoring/context.
            rows=c.execute(f'SELECT body FROM memories WHERE avatar=? AND space IN ({placeholders}) ORDER BY id',(g['avatar'],*scopes))
            result=[]
            for row in rows:
                m=json.loads(row[0])
                if not self.current_memory(m) or m['level'] not in levels:continue
                if m['scope']!=self._scope(c,g,m['scope']['space_ref']):continue
                result.append(m)
                if not body['query'] and len(result) > limit:
                    break
            result, more, method = lexical.rank(result, body['query'], limit)
            out={'items':result,'count':len(result),'retrieval':method,'space_refs':scopes,'possibly_more':more}
            if context:
                if condition is not None:
                    defaults = {'preferences': [], 'possibly_more': False}
                    if not override and 'M2' in levels:
                        defaults = self._matching_preferences(c, g, scopes[0], condition, limit)
                    out['preference_defaults'] = defaults['preferences']
                    out['possibly_more_preferences'] = defaults['possibly_more']
                refs=[{'id':m['memory_id'],'version':m['revision'],'scope':m['scope'],'sha256':digest(m)} for m in result]
                view={'view_id':uid('view:'),'request_ref':uid('request:'),'avatar_id':g['avatar'],'subject_ref':g['subject'],'session_ref':g['session'],'runtime_ref':g['runtime'],'purpose':g['purpose'],'space_refs':scopes,'objects':refs,'policy_versions':[self._scope(c,g,s)['policy_ref'] for s in scopes],'revocation_epoch':self.meta(c,'revocation_epoch'),'compiled_at':stamp(self.now()),'expires_at':stamp(min(parse(g['expires']),self.now()+timedelta(minutes=5)))}
                deadlines = [m.get('extensions', {}).get(VALIDITY_EXTENSION, {}).get('expires_at') for m in result]
                view['expires_at'] = min([view['expires_at']] + [t for t in deadlines if t])
                validate('authorized-view',view);c.execute('INSERT INTO views VALUES(?,?,?,?,?,0,0)',(view['view_id'],g['avatar'],g['id'],encode(scopes),encode(view)));out['authorized_view']=view
            return out
    def acknowledge(self,token,body):
        exact(body,['view_id']);require(isinstance(body['view_id'],str))
        with self.tx() as c:
            g=self._grant(c,token);r=c.execute('SELECT * FROM views WHERE id=? AND avatar=? AND grant_id=?',(body['view_id'],g['avatar'],g['id'])).fetchone()
            require(r is not None and not r['invalidated'],'E_NOT_FOUND',404)
            self._allow(g,json.loads(r['scopes']),'read');v=json.loads(r['body'])
            require(self.now()<parse(v['expires_at']),'E_EXPIRED',403)
            require(v['revocation_epoch']==self.meta(c,'revocation_epoch'),'E_REVOKED',403)
            if r['acked']:return {'acknowledged':True,'idempotent':True}
            touched=False
            for obj in v['objects']:
                row=c.execute('SELECT * FROM memories WHERE avatar=? AND id=?',(g['avatar'],obj['id'])).fetchone()
                require(row is not None and row['revision']==obj['version'],'E_VERSION_CONFLICT',409)
                memory = json.loads(row['body'])
                require(memory['scope'] == self._scope(c, g, memory['scope']['space_ref']), 'E_POLICY_VERSION', 409)
                self._record_memory_use(c, row, memory, 'context_use_count')
                touched = True
            c.execute('UPDATE views SET acked=1 WHERE id=?',(body['view_id'],))
            if touched:self._rebuild_core(c,g['avatar'])
            self._audit(c,g['avatar'],None,'context-use-acknowledged',body['view_id'],g['id'])
            return {'acknowledged':True,'idempotent':False}

    def report_adoption(self, token, body):
        """Record runtime-reported use of one delivered version, once per view."""
        exact(body, ['view_id', 'memory_id', 'revision'])
        view_id, ident, rev = body['view_id'], body['memory_id'], body['revision']
        require(all(isinstance(v, str) and 0 < len(v) <= 200 for v in (view_id, ident)))
        require(type(rev) is int and rev > 0)
        with self.tx() as c:
            grant = self._grant(c, token)
            row = c.execute('SELECT * FROM views WHERE id=? AND avatar=? AND grant_id=?',
                            (view_id, grant['avatar'], grant['id'])).fetchone()
            require(row and not row['invalidated'], 'E_NOT_FOUND', 404)
            view = json.loads(row['body'])
            self._allow(grant, view['space_refs'], 'read', view['purpose'])
            require(view['revocation_epoch'] == self.meta(c, 'revocation_epoch'), 'E_REVOKED', 403)
            require(self.now() < parse(view['expires_at']), 'E_EXPIRED', 403)
            require(row['acked'], 'E_DELIVERY_REQUIRED', 409)
            ref = next((obj for obj in view['objects'] if obj['id'] == ident and obj['version'] == rev), None)
            require(ref is not None, 'E_NOT_FOUND', 404)
            space = ref['scope']['space_ref']
            require(ref['scope'] == self._scope(c, grant, space), 'E_POLICY_VERSION', 409)
            receipt = f"adoption:{view_id}:{rev}:{digest(ident)}"
            prior = c.execute('SELECT 1 FROM audit WHERE id=?', (receipt,)).fetchone()
            if not prior:
                c.execute('INSERT INTO audit VALUES(?,?,?,?,?,?,?)',
                          (receipt, grant['avatar'], space, 'runtime-reported-adoption', ident,
                           stamp(self.now()), grant['id']))
            return {'view_id': view_id, 'memory_id': ident, 'revision': rev, 'idempotent': bool(prior)}

    def _record_memory_use(self, connection, row, memory, counter):
        connection.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',
                           (row['avatar'], row['id'], row['revision'], row['space'], row['body']))
        now = stamp(self.now())
        memory['lifecycle']['last_used_at'] = now
        memory['lifecycle'][counter] += 1
        memory['previous_revision'] = row['revision']
        memory['revision'] = row['revision'] + 1
        memory['updated_at'] = now
        validate('memory-record', memory)
        connection.execute('UPDATE memories SET revision=?, body=? WHERE avatar=? AND id=?',
                           (memory['revision'], encode(memory), row['avatar'], row['id']))

    def confirm_memory_use(self, token, space, memory_id, revision):
        require(isinstance(memory_id, str) and 0 < len(memory_id) <= 200)
        require(type(revision) is int and revision > 0)
        with self.tx() as connection:
            owner = self._grant(connection, token)
            self._allow(owner, [space], 'read', owner=True)
            self._allow(owner, [space], 'write')
            row = connection.execute('SELECT * FROM memories WHERE avatar=? AND space=? AND id=?',
                                     (owner['avatar'], space, memory_id)).fetchone()
            require(row is not None, 'E_NOT_FOUND', 404)
            require(row['revision'] == revision, 'E_VERSION_CONFLICT', 409)
            memory = json.loads(row['body'])
            require(self.current_memory(memory), 'E_NOT_FOUND', 404)
            require(memory['scope'] == self._scope(connection, owner, space), 'E_POLICY_VERSION', 409)
            self._record_memory_use(connection, row, memory, 'confirmed_use_count')
            self._rebuild_core(connection, owner['avatar'])
            self._audit(connection, owner['avatar'], space, 'memory-use-confirmed', memory_id, owner['id'])
            return {'memory_id': memory_id, 'space_ref': space, 'revision': memory['revision'],
                    'confirmed_use_count': memory['lifecycle']['confirmed_use_count']}

    def preflight_candidate(self, token, body):
        with self.tx(read_only=True) as connection:
            grant = self._grant(connection, token)
            return self._candidate_preflight(connection, grant, body)

    def _active_admission_memories(self, connection, avatar, scope):
        rows = connection.execute('SELECT body FROM memories WHERE avatar=? AND space=? ORDER BY id',
                                  (avatar, scope['space_ref']))
        for row in rows:
            record = json.loads(row['body'])
            if self.current_memory(record) and record['level'] != 'M3' and record['scope'] == scope:
                yield record

    def _approval_duplicate(self, connection, avatar, candidate):
        from .admission import normalize_text, same_memory_text

        text = normalize_text(candidate['content'])
        for record in self._active_admission_memories(connection, avatar, candidate['scope']):
            if record['memory_id'] != candidate['memory_id'] and same_memory_text(
                    record, text, candidate['level'], candidate['type']):
                return {key: record[key] for key in ('memory_id', 'revision')}
        return None

    def _candidate_preflight(self, connection, grant, body):
        from .admission import comparison_score, normalize_text, observation_reason, same_memory_text, validate_preflight

        validate_preflight(body)
        space = body['space_ref']
        text = normalize_text(body['text'])
        level = body['level']
        memory_type = body['memory_type']
        source = body.get('source_ref')
        target = body.get('target_memory_id')
        context = {'space_ref': space, 'level': level, 'memory_type': memory_type, 'trigger': body['trigger'],
                   'runtime_ref': grant['runtime'], 'source_verified': False, 'requires_owner_confirmation': True}

        def decision(status, reason, **details):
            return {**context, 'status': status, 'reason': reason, **details}

        self._allow(grant, [space], 'read', body['purpose'])
        self._allow(grant, [space], 'write', body['purpose'])
        scope = self._scope(connection, grant, space)

        # Proposal review already limits visibility to the issuer or an Owner with all participating spaces.
        rows = connection.execute(f"""
            SELECT delta.id, delta.issuer, delta.body FROM deltas AS delta
            WHERE delta.avatar = :avatar AND delta.status = 'proposed'
              AND (:owner OR delta.issuer = :issuer)
              AND EXISTS (SELECT 1 FROM json_each(delta.scopes) WHERE value = :space)
              AND {_PROPOSAL_SCOPES_VISIBLE}
            ORDER BY delta.id
        """, {'avatar': grant['avatar'], 'owner': grant['role'] == 'owner', 'issuer': grant['id'],
              'space': space, 'allowed': grant['scopes']})
        duplicate = None
        for row in rows:
            envelope = json.loads(row['body'])
            for change in envelope['delta']['changes']:
                candidate = change['candidate']
                if change['domain'] != 'aiap.memory' or candidate['scope'] != scope:
                    continue
                same_candidate = (normalize_text(candidate['content']) == text and candidate['level'] == level
                                  and candidate['type'] == memory_type
                                  and ((change['operation'] == 'add' and target is None)
                                       or (change['operation'] == 'update' and target == candidate['memory_id'])))
                if source is not None and row['issuer'] == grant['id'] and candidate['source']['source_ref'] == source:
                    if not same_candidate:
                        return decision('insufficient-information', 'source-reference-reused-with-different-candidate')
                    return decision('duplicate', 'same-pending-source', delta_id=row['id'])
                if same_candidate and duplicate is None:
                    duplicate = row['id']

        query_terms = set(lexical.terms(text))
        related = []
        direct = None
        for record in self._active_admission_memories(connection, grant['avatar'], scope):
            ref = {key: record[key] for key in ('memory_id', 'revision', 'level', 'type')}
            if record['memory_id'] == target:
                direct = ref
            if same_memory_text(record, text, level, memory_type):
                return decision('duplicate', 'same-active-memory', matches=[ref])
            if target is None and record['level'] == level and record['type'] == memory_type:
                score = comparison_score(query_terms, record['content'])
                if score >= 0.5:
                    related.append((score, ref))

        if target is not None and (direct is None or direct['level'] != level):
            return decision('insufficient-information', 'target-unavailable-or-level-mismatch')
        if duplicate:
            return decision('duplicate', 'same-pending-candidate', delta_id=duplicate)
        if reason := observation_reason(body):
            return decision('insufficient-information', reason)
        if direct is not None:
            return decision('review-revision', 'explicit-revision-target', matches=[direct])
        if related:
            related.sort(key=lambda item: (-item[0], item[1]['memory_id']))
            return decision('review-revision', 'shared-terms-compare-before-submitting',
                            matches=[ref for _, ref in related[:3]])
        return decision('ready-to-propose', 'no-visible-duplicate')

    def _validate_delta(self,c,g,envelope,*,allow_lifecycle=False):
        validate('state-delta',envelope);d=envelope['delta'];q=envelope['request'];bs=envelope['bindings'];scopes=q['space_refs']
        self._allow(g,scopes,'write',q['purpose'])
        extensions = d.get('extensions', {})
        lifecycle = extensions.get(LOCAL_LIFECYCLE_EXTENSION)
        if LOCAL_LIFECYCLE_EXTENSION in extensions:
            require(allow_lifecycle, 'E_OPERATION_UNSUPPORTED', 422)
            exact(lifecycle, ['kind', 'reason'])
            require(isinstance(lifecycle['kind'], str) and lifecycle['kind'] in LOCAL_LIFECYCLE_TRANSITIONS
                    and isinstance(lifecycle['reason'], str) and lifecycle['reason'].strip()
                    and len(lifecycle['reason']) <= 500 and len(d['changes']) == 1, 'E_LIFECYCLE_TRANSITION')
            self._allow(g, scopes, 'read', q['purpose'], owner=lifecycle['kind'] != 'archive')
        require(q['authenticated_subject_ref']==g['subject'] and q['auth_evidence_ref']==g['id'] and q['avatar_id']==g['avatar'] and q['session_ref']==g['session'] and q['runtime_ref']==g['runtime'],'E_IDENTITY',403)
        require(q['action']=='write' and q['processor_refs']==[],'E_DENIED',403)
        require(d['avatar_id']==g['avatar'] and d['runtime_id']==g['runtime'],'E_SCOPE',403)
        require(parse(g['issued'])<=parse(q['issued_at'])<=self.now()<parse(q['expires_at'])<=parse(g['expires']),'E_EXPIRED',403)
        require(len(d['changes'])<=20 and len(bs)==len(d['changes']))
        ids=[x['change_id'] for x in d['changes']];bids=[x['change_id'] for x in bs]
        require(len(set(ids))==len(ids) and len(set(bids))==len(bids) and set(ids)==set(bids))
        targets=[x['target_object_id'] for x in bs];require(len(set(targets))==len(targets))
        by={x['change_id']:x for x in bs};records=[]
        domain = LOCAL_LIFECYCLE_DOMAIN if lifecycle is not None else 'aiap.memory'
        for ch in d['changes']:
            require(ch['domain']==domain and ch['operation'] in ('add','update'),'E_OPERATION_UNSUPPORTED',422)
            b=by[ch['change_id']];m=ch['candidate'];validate('memory-record',m)
            require(isinstance(m['content'],str) and 0<len(m['content'])<=16000,'E_OPERATION_UNSUPPORTED',422)
            require(m['derived_from']==[], 'E_OPERATION_UNSUPPORTED',422)
            require(m['status']=='candidate' and m['level'] in ('M1','M2','M3'),'E_OPERATION_UNSUPPORTED',422)
            require(0<len(m['memory_id'])<=200 and m['memory_id']==b['target_object_id'])
            require(b['confirmation_ref'] is None,'E_CONFIRMATION_REQUIRED',409)
            require(m['scope']['space_ref'] in scopes,'E_DENIED',403)
            expected=self._scope(c,g,m['scope']['space_ref'])
            require(m['scope']==expected and b['scope']==expected,'E_SCOPE',403)
            require(c.execute('SELECT 1 FROM tombstones WHERE avatar=? AND id=?',(g['avatar'],m['memory_id'])).fetchone() is None,'E_DENIED',403)
            old=c.execute('SELECT * FROM memories WHERE avatar=? AND id=?',(g['avatar'],m['memory_id'])).fetchone()
            if old:
                require(old['space'] in scopes and old['space']==m['scope']['space_ref'],'E_DENIED',403)
                require(ch['operation']=='update' and b['base_revision']==old['revision'],'E_VERSION_CONFLICT',409)
            else:require(ch['operation']=='add' and b['base_revision']==0,'E_VERSION_CONFLICT',409)
            require(m['source']['source_type'] in ('explicit-user','observed','inferred','imported'),'E_OPERATION_UNSUPPORTED',422)
            require(m['source']['source_ref'] in b['source_refs'])
            require(m['lifecycle']['policy_ref']=={'id':'lifecycle:default','version':1},'E_POLICY_VERSION',409)
            require(m['retention'].get('minimum_level') is None and m['retention'].get('inactive_after_days_override') is None,'E_OPERATION_UNSUPPORTED',422)
            prior = json.loads(old['body']) if old else None
            require(not m.get('extensions') or (prior and m['extensions'] == prior.get('extensions')),
                    'E_OPERATION_UNSUPPORTED', 422)
            require(prior is None or prior['status'] == 'active', 'E_LIFECYCLE_TRANSITION', 409)
            if lifecycle is not None:
                previous_levels, target_level, _ = LOCAL_LIFECYCLE_TRANSITIONS[lifecycle['kind']]
                require(prior is not None and ch['operation'] == 'update' and prior['status'] == 'active'
                        and prior['level'] in previous_levels, 'E_LIFECYCLE_TRANSITION', 409)
                require(m == {**prior, 'level': target_level, 'status': 'candidate'}, 'E_LIFECYCLE_TRANSITION', 409)
            elif prior is not None:
                require(m['level'] == prior['level'], 'E_LIFECYCLE_TRANSITION', 409)
            records.append((m, prior))
        return records
    def propose(self, token, envelope, *, allow_lifecycle=False):
        return self._submit_proposal(token, envelope, allow_lifecycle=allow_lifecycle)

    def propose_checked(self, token, body):
        from .admission import TRIGGERS

        exact(body, ['envelope', 'trigger'], ['confirm_new'])
        trigger = body['trigger']
        confirm_new = body.get('confirm_new', False)
        require(trigger in TRIGGERS and type(confirm_new) is bool)
        require(trigger != 'host-observation' or not confirm_new, 'E_CONFIRMATION_REQUIRED', 409)
        return self._submit_proposal(token, body['envelope'], trigger=trigger,
                                     confirm_new=confirm_new)

    def related_memories(self, token, body, *, similar=False):
        from .memory_links import related_memories
        return related_memories(self, token, body, similar=similar)

    def memory_batch(self, token, body):
        from .batch import memory_batch
        return memory_batch(self, token, body)

    def propose_revision(self, token, body):
        from .client import proposal

        exact(body, ['space_ref', 'purpose', 'memory_id', 'base_revision', 'text'])
        text = body['text']
        require(isinstance(text, str) and 0 < len(text) <= 4000 and text.strip() and '\x00' not in text)
        session = self.session(token)
        require(body['purpose'] == session['purpose'], 'E_DENIED', 403)
        space = body['space_ref']
        previous = self.memory_for_update(token, space, body['memory_id'], body['base_revision'])
        envelope = proposal(session, space, text, old=previous, source_type='inferred')
        result = self.propose_checked(token, {'envelope': envelope, 'trigger': 'user-request'})
        return {**result, 'memory_id': previous['memory_id'], 'base_revision': previous['revision'],
                'level': previous['level'], 'memory_type': previous['type']}

    def _submit_proposal(self, token, envelope, *, allow_lifecycle=False, trigger=None, confirm_new=False):
        validate('state-delta', envelope)
        delta = envelope['delta']
        scopes = envelope['request']['space_refs']
        purpose = envelope['request']['purpose']
        extensions = delta.get('extensions', {})
        require(LOCAL_ADMISSION_EXTENSION not in extensions, 'E_OPERATION_UNSUPPORTED', 422)
        if LOCAL_LIFECYCLE_EXTENSION in extensions:
            require(allow_lifecycle, 'E_OPERATION_UNSUPPORTED', 422)
        if trigger is not None:
            require(len(delta['changes']) == len(scopes) == 1, 'E_OPERATION_UNSUPPORTED', 422)
            envelope = copy.deepcopy(envelope)
            delta = envelope['delta']
            delta.setdefault('extensions', {})[LOCAL_ADMISSION_EXTENSION] = {
                'trigger': trigger, 'source_verified': False, 'confirm_new_requested': confirm_new,
            }
        delta_id = delta['delta_id']
        payload_hash = digest(envelope)

        with self.tx() as connection:
            grant = self._grant(connection, token)
            self._allow(grant, scopes, 'write', purpose)
            if trigger is not None:
                self._allow(grant, scopes, 'read', purpose)
            prior = connection.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',
                                       (grant['avatar'], delta_id)).fetchone()
            if prior:
                require(prior['issuer'] == grant['id'], 'E_DENIED', 403)
                require(prior['payload_hash'] == payload_hash, 'E_IDEMPOTENCY_CONFLICT', 409)
                return {'delta_id': delta_id, 'status': prior['status'], 'idempotent': True}

            records = self._validate_delta(connection, grant, envelope, allow_lifecycle=allow_lifecycle)
            if trigger is not None:
                (candidate, previous), = records
                request = {'space_ref': scopes[0], 'purpose': purpose, 'text': candidate['content'],
                           'level': candidate['level'], 'memory_type': candidate['type'],
                           'trigger': trigger, 'source_ref': candidate['source']['source_ref']}
                if previous is not None:
                    request['target_memory_id'] = previous['memory_id']
                preview = self._candidate_preflight(connection, grant, request)
                can_submit = (preview['status'] == 'ready-to-propose'
                              or preview['status'] == 'review-revision' and (previous is not None or confirm_new))
                if not can_submit:
                    return {**preview, 'submitted': False}
            connection.execute('INSERT INTO deltas VALUES(?,?,?,?,?,?,?,?)',
                               (grant['avatar'], delta_id, grant['id'], encode(scopes), payload_hash,
                                encode(envelope), 'proposed', None))
            self._audit(connection, grant['avatar'], None, 'delta-proposed', delta_id, grant['id'])
            return {'delta_id': delta_id, 'status': 'proposed', 'idempotent': False}

    def propose_archive(self, token, body):
        exact(body, ['space_ref', 'purpose', 'memory_id', 'base_revision', 'reason'])
        session = self.session(token)
        require(body['purpose'] == session['purpose'], 'E_DENIED', 403)
        return self._lifecycle_draft(token, session, body['space_ref'], body['memory_id'], body['base_revision'],
                                     kind='archive', reason=body['reason'])

    def propose_lifecycle(self, token, space, memory_id, revision, *, kind, reason):
        session = self.session(token)
        require(session['role'] == 'owner', 'E_DENIED', 403)
        return self._lifecycle_draft(token, session, space, memory_id, revision, kind=kind, reason=reason)

    def _lifecycle_draft(self, token, session, space, memory_id, revision, *, kind, reason):
        from .client import proposal
        require(isinstance(kind, str) and kind in LOCAL_LIFECYCLE_TRANSITIONS, 'E_LIFECYCLE_TRANSITION')
        require(isinstance(reason, str) and reason.strip() and len(reason) <= 500, 'E_LIFECYCLE_TRANSITION')
        previous = self.memory_for_update(token, space, memory_id, revision)
        previous_levels, target_level, _ = LOCAL_LIFECYCLE_TRANSITIONS[kind]
        require(previous['status'] == 'active' and previous['level'] in previous_levels, 'E_LIFECYCLE_TRANSITION', 409)
        draft = proposal(session, space, previous['content'], old=previous)
        draft['delta']['changes'][0].update(domain=LOCAL_LIFECYCLE_DOMAIN,
                                          candidate={**previous, 'level': target_level, 'status': 'candidate'})
        draft['delta']['extensions'] = {LOCAL_LIFECYCLE_EXTENSION: {'kind': kind, 'reason': reason.strip()}}
        draft['bindings'][0]['source_refs'] = [previous['source']['source_ref']]
        return self.propose(token, draft, allow_lifecycle=True)

    def memory_for_update(self, token, space, memory_id, revision):
        require(isinstance(memory_id, str) and 0 < len(memory_id) <= 200)
        require(type(revision) is int and revision > 0)
        with self.tx(read_only=True) as connection:
            grant = self._grant(connection, token)
            self._allow(grant, [space], 'read')
            self._allow(grant, [space], 'write')
            row = connection.execute(
                'SELECT revision, body FROM memories WHERE avatar=? AND space=? AND id=?',
                (grant['avatar'], space, memory_id),
            ).fetchone()
            require(row is not None, 'E_NOT_FOUND', 404)
            require(row['revision'] == revision, 'E_VERSION_CONFLICT', 409)
            return json.loads(row['body'])

    @staticmethod
    def _memory_validity(memory, now):
        if memory['status'] != 'active':
            return memory['status']
        validity = memory.get('extensions', {}).get(VALIDITY_EXTENSION, {})
        expiry = validity.get('expires_at')
        return 'expired' if expiry is not None and now >= parse(expiry) else 'current'

    def current_memory(self, memory):
        return self._memory_validity(memory, self.now()) == 'current'

    def set_memory_validity(self, token, space, memory_id, revision, *, expires_at=None,
                            successor_id=None, successor_revision=None, clear_expiry=False):
        """Owner-only compare-and-set. Both endpoints must belong to the same current policy."""
        require(isinstance(memory_id, str) and memory_id and type(revision) is int and revision > 0)
        require(type(clear_expiry) is bool and sum((expires_at is not None, successor_id is not None, clear_expiry)) == 1)
        require((successor_revision is None) == (successor_id is None))
        if expires_at is not None:
            require(isinstance(expires_at, str) and len(expires_at) <= 40 and 'T' in expires_at)
            try:
                dt = parse(expires_at)
                require(dt.tzinfo is not None)
                expiry = stamp(dt)
            except (ValueError, OverflowError):
                raise Fault('E_SCHEMA') from None
        elif successor_id is not None:
            require(isinstance(successor_id, str) and successor_id and successor_id != memory_id
                    and type(successor_revision) is int and successor_revision > 0)
        with self.tx() as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'write', owner=True)
            self._allow(owner, [space], 'read')
            scope = self._scope(c, owner, space)

            def load(ident, expected):
                row = c.execute('SELECT revision,body FROM memories WHERE avatar=? AND space=? AND id=?',
                                (owner['avatar'], space, ident)).fetchone()
                require(row is not None, 'E_NOT_FOUND', 404)
                record = json.loads(row['body'])
                require(record['scope'] == scope, 'E_SCOPE', 403)
                require(row['revision'] == expected, 'E_VERSION_CONFLICT', 409)
                return row, record

            row, record = load(memory_id, revision)
            require(record['status'] == 'active', 'E_LIFECYCLE_TRANSITION', 409)
            validity = record.setdefault('extensions', {}).setdefault(VALIDITY_EXTENSION, {})
            if successor_id is not None:
                _, successor = load(successor_id, successor_revision)
                require(self.current_memory(successor) and successor['level'] in ('M1', 'M2'),
                        'E_LIFECYCLE_TRANSITION', 409)
                validity['superseded_by'] = {'id': successor_id, 'revision': successor_revision}
                record['status'] = 'superseded'
                event = 'memory-superseded'
            elif clear_expiry:
                if 'expires_at' not in validity:
                    return {'memory_id': memory_id, 'revision': revision, 'validity': validity}
                del validity['expires_at']
                if not validity:
                    del record['extensions'][VALIDITY_EXTENSION]
                    if not record['extensions']:
                        del record['extensions']
                event = 'memory-expiry-cleared'
            else:
                validity['expires_at'] = expiry
                event = 'memory-expiry-set'
            record.update(previous_revision=revision, revision=revision + 1, updated_at=stamp(self.now()))
            validate('memory-record', record)
            c.execute('INSERT INTO history VALUES(?,?,?,?,?)',
                      (owner['avatar'], memory_id, revision, space, row['body']))
            c.execute('UPDATE memories SET revision=?,body=? WHERE avatar=? AND id=?',
                      (revision + 1, encode(record), owner['avatar'], memory_id))
            self._audit(c, owner['avatar'], space, event, memory_id, owner['id'])
            self._rebuild_core(c, owner['avatar'])
            return {'memory_id': memory_id, 'revision': revision + 1, 'validity': validity}

    def preference_candidates(self, token, space, *, after='', limit=20):
        """Discover repeated wording in active M1 preference evidence for Owner review."""
        from itertools import groupby
        from .admission import normalize_text
        require(isinstance(after, str))
        require(type(limit) is int and 1 <= limit <= 100)
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            scope = self._scope(c, owner, space)
            c.create_function('normalized_text', 1, normalize_text, deterministic=True)
            rows = c.execute("""
                SELECT body, normalized_text(json_extract(body, '$.content')) AS wording
                FROM memories WHERE avatar=? AND space=?
                AND json_extract(body, '$.level')='M1' AND json_extract(body, '$.type')='preference-evidence'
                AND json_extract(body, '$.status')='active'
                AND json_extract(body, '$.source.source_type') IN ('observed', 'explicit-user')
                AND normalized_text(json_extract(body, '$.content'))>?
                ORDER BY wording, json_extract(body, '$.source.source_ref'), id
            """, (owner['avatar'], space, after))
            now = self.now()
            items = []
            more = False
            for wording, records in groupby(rows, key=lambda row: row['wording']):
                previous_ref = None
                source_count = record_count = 0
                sample_revisions = {}
                for row in records:
                    record = json.loads(row['body'])
                    if record['scope'] != scope or self._memory_validity(record, now) != 'current':
                        continue
                    record_count += 1
                    ref = record['source']['source_ref']
                    if ref != previous_ref:
                        source_count += 1
                        previous_ref = ref
                        if len(sample_revisions) < 50:
                            sample_revisions[record['memory_id']] = record['revision']
                if source_count < 2:
                    continue
                if len(items) == limit:
                    more = True
                    break
                items.append({'wording': wording, 'source_count': source_count, 'record_count': record_count,
                              'sample_memory_ids': list(sample_revisions), 'sample_revisions': sample_revisions})
            self._grant(c, token)
            return {'space_ref': space, 'as_of': stamp(now), 'candidates': items,
                    'next_after': items[-1]['wording'] if more else None}

    def find_preference_evidence(self, token, space, query, limit=20):
        """Find possible paraphrases and counterexamples for a local Owner's review."""
        from .semantic import semantic_search
        require(isinstance(query, str) and query.strip() and len(query) <= 1000)
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
        request = {'query': query, 'level': 'M1', 'limit': limit, 'space_refs': [space], 'purpose': owner['purpose']}
        result = semantic_search(self, token, request, preference_evidence=True)
        result['items'] = [{'memory_id': m['memory_id'], 'revision': m['revision'], 'content': m['content'],
                            'source_ref': m['source']['source_ref'], 'source_type': m['source']['source_type'],
                            'match_ranks': m['match_ranks']} for m in result['items']]
        return result

    def review_preference_evidence(self, token, space, memory_ids):
        """Group selected current M1 observations for local Owner review."""
        require(isinstance(memory_ids, list) and 1 <= len(memory_ids) <= 50)
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            return self._preference_sources(c, owner, space, memory_ids)

    def preview_preference(self, token, space, **fields):
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            preview = self._preference_draft(c, owner, space, **fields)
            return {**preview, 'preview_sha256': digest(preview)}

    def confirm_preference(self, token, space, preview_sha256, **fields):
        with self.tx() as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'admin', owner=True)
            update = self._prepare_preference_update(c, owner, space)
            draft = self._preference_draft(c, owner, space, **fields)
            require(digest(draft) == preview_sha256, 'E_VERSION_CONFLICT', 409)
            key = 'preference:' + preview_sha256
            existing = c.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
            if existing:
                record = json.loads(existing['value'])
                require(record['status'] == 'confirmed', 'E_VERSION_CONFLICT', 409)
                return record
            if draft.get('replaces'):
                old = self._owner_preference(c, owner, space, draft['replaces'])
                require(old['status'] == 'confirmed', 'E_VERSION_CONFLICT', 409)
                old.update(status='superseded', level='M3', successor=key, superseded_at=stamp(self.now()))
                c.execute('UPDATE meta SET value=? WHERE key=?', (encode(old), old['preference_id']))
                self._audit(c, owner['avatar'], space, 'preference-superseded', old['preference_id'], owner['id'])
            # Keep references and roles for provenance, without duplicating observation text.
            references = [{'memory_id': item['memory_id'], 'revision': item['revision'],
                           'roles': item['roles'], 'source_ref': group['source_ref']}
                          for group in draft.pop('evidence')['sources'] for item in group['observations']]
            record = {**draft, 'status': 'confirmed', 'level': 'M2', 'preference_id': key, 'confirmed_at': stamp(self.now()),
                      'evidence_refs': references}
            c.execute('INSERT INTO meta VALUES(?,?)', (key, encode(record)))
            self._commit_preference_update(c, update)
            self._audit(c, owner['avatar'], space, 'preference-confirmed', key, owner['id'])
            return record

    def recall_preferences(self, token, space, condition):
        require(isinstance(condition, str) and condition.strip() and len(condition) <= 2000)
        with self.tx(read_only=True) as c:
            grant = self._grant(c, token)
            self._allow(grant, [space], 'read')
            return self._matching_preferences(c, grant, space, condition, 100)

    def _matching_preferences(self, c, grant, space, condition, limit):
        scope = self._scope(c, grant, space)
        self._verify_preference_space(c, grant['avatar'], scope)
        rows = c.execute("""
            SELECT value FROM meta WHERE key GLOB 'preference:*'
            AND json_extract(value, '$.avatar_id')=? AND json_extract(value, '$.space_ref')=?
            AND json_extract(value, '$.scope.policy_ref.version')=?
            AND json_extract(value, '$.scope.policy_ref.id')=?
            AND json_extract(value, '$.status')='confirmed' AND json_extract(value, '$.condition')=?
            AND EXISTS (SELECT 1 FROM json_each(meta.value, '$.allowed_runtimes') WHERE value=?)
            ORDER BY key LIMIT ?
        """, (grant['avatar'], space, scope['policy_ref']['version'], scope['policy_ref']['id'], condition.strip(), grant['runtime'], limit + 1))
        fields = ('preference_id', 'statement', 'condition', 'exception', 'confirmed_at')
        items = []
        for row in rows:
            record = json.loads(row['value'])
            if record['scope'] == scope:
                items.append({field: record[field] for field in fields})
        return {'space_ref': space, 'preferences': items[:limit], 'possibly_more': len(items) > limit}

    def withdraw_preference(self, token, space, preference_id):
        with self.tx() as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'admin', owner=True)
            update = self._prepare_preference_update(c, owner, space)
            record = self._owner_preference(c, owner, space, preference_id)
            if record['status'] == 'confirmed':
                record.update(status='withdrawn', level='M3', withdrawn_at=stamp(self.now()))
                c.execute('UPDATE meta SET value=? WHERE key=?', (encode(record), preference_id))
                self._commit_preference_update(c, update)
                self._audit(c, owner['avatar'], space, 'preference-withdrawn', preference_id, owner['id'])
            return record

    def _owner_preference(self, c, owner, space, preference_id):
        require(isinstance(preference_id, str) and re.fullmatch(r'preference:[0-9a-f]{64}', preference_id))
        row = c.execute('SELECT value FROM meta WHERE key=?', (preference_id,)).fetchone()
        require(row is not None, 'E_NOT_FOUND', 404)
        record = json.loads(row['value'])
        require(record['avatar_id'] == owner['avatar'] and record['space_ref'] == space, 'E_NOT_FOUND', 404)
        return record

    def preview_preference_baseline(self, token):
        """Describe exactly which legacy registry state would be enrolled."""
        with self.tx(read_only=True) as c:
            owner, spaces, core, _ = self._owner_core(c, token)
            require(core['extensions'] == [_BASE_EXTENSION], 'E_CRITICAL_EXTENSION', 409)
            require(not any(ref['id'].startswith(_PREFERENCE_REF_PREFIX) for ref in core['state_index']),
                    'E_VERSION_CONFLICT', 409)
            manifests = [self._preference_manifest(c, owner['avatar'], self._scope(c, owner, sid))
                         for sid in spaces]
            stored = c.execute("SELECT count(*) FROM meta WHERE key GLOB 'preference:*'").fetchone()[0]
            require(stored == sum(m['record_count'] for m in manifests), 'E_INTEGRITY', 500)
            baseline = {'profile': 'x-aiap-preference-baseline-review-v1', 'avatar_id': owner['avatar'],
                        'core_revision': core['revision'], 'signed_core_sha256': digest(core), 'spaces': manifests}
            return {'status': 'preview', 'baseline': baseline, 'baseline_sha256': digest(baseline)}

    def preference_manifest(self, token, space):
        """Compute a scoped digest and verify its commitment when the index declares one."""
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            scope = self._scope(c, owner, space)
            return self._verify_preference_space(c, owner['avatar'], scope, include_manifest=True)

    def _prepare_preference_update(self, c, owner, space):
        core, enrollment = self._load_signed_core(c, owner['avatar'])
        if core['extensions'] == [_BASE_EXTENSION]:
            return None
        refs = self._preference_references(core)
        scope = self._scope(c, owner, space)
        self._check_preference_ref(c, core, scope, refs)
        return core, refs[space], enrollment['payload']['avatar_public_key']

    def _commit_preference_update(self, c, update):
        if update is None:
            return
        core, ref, public_key = update
        manifest = self._preference_manifest(c, core['avatar_id'], ref['scope'])
        ref.update(version=ref['version'] + 1, sha256=manifest['sha256'])
        del core['integrity']
        core.update(previous_revision=core['revision'], revision=core['revision'] + 1, updated_at=stamp(self.now()))
        self._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00',
                        expected_public_key=public_key)
        validate('avatar-core', core)
        c.execute('UPDATE cores SET revision=?,body=? WHERE avatar=?',
                  (core['revision'], encode(core), core['avatar_id']))

    def _verify_preference_space(self, c, avatar, scope, *, include_manifest=False):
        core, _ = self._load_signed_core(c, avatar)
        if core['extensions'] == [_BASE_EXTENSION]:
            if include_manifest:
                return self._preference_manifest(c, avatar, scope)
            return
        refs = self._preference_references(core)
        return self._check_preference_ref(c, core, scope, refs)

    @staticmethod
    def _preference_references(core):
        require(core['extensions'] == [_BASE_EXTENSION, _PREFERENCE_EXTENSION], 'E_CRITICAL_EXTENSION')
        try:
            validate('avatar-core', core)
        except Fault as error:
            raise Fault('E_INTEGRITY', 500) from error
        refs = {}
        for ref in core['state_index']:
            if ref['id'].startswith(_PREFERENCE_REF_PREFIX):
                sid = ref['scope']['space_ref']
                require(sid not in refs and ref['id'] == _PREFERENCE_REF_PREFIX + sid
                        and ref['scope']['owner_ref'] == core['owner']['owner_ref'], 'E_INTEGRITY', 500)
                refs[sid] = ref
        return refs

    def _check_preference_ref(self, c, core, scope, refs):
        ref = refs.get(scope['space_ref'])
        require(ref is not None and ref['scope'] == scope, 'E_INTEGRITY', 500)
        manifest = self._preference_manifest(c, core['avatar_id'], scope)
        require(ref['sha256'] == manifest['sha256'], 'E_INTEGRITY', 500)
        return {**manifest, 'signed': True, 'core_revision': core['revision'], 'manifest_version': ref['version']}

    def _preference_manifest(self, c, avatar, scope):
        profile = 'x-aiap-local-preference-manifest-v1'
        header = {'profile': profile, 'avatar_id': avatar, 'scope': scope}
        hasher = hashlib.sha256(canonical(header) + b'\n')
        rows = c.execute("""SELECT key, value FROM meta WHERE key GLOB 'preference:*'
            AND json_extract(value, '$.avatar_id')=? AND json_extract(value, '$.space_ref')=?
            ORDER BY key""", (avatar, scope['space_ref']))
        count = 0
        for row in rows:
            record = json.loads(row['value'])
            require(record.get('preference_id') == row['key']
                    and record.get('status') in ('confirmed', 'superseded', 'withdrawn'),
                    'E_INTEGRITY', 500)
            entry = {'id': row['key'], 'sha256': digest(record)}
            hasher.update(canonical(entry) + b'\n')
            count += 1
        return {**header, 'record_count': count, 'sha256': hasher.hexdigest(), 'signed': False}

    def preference_history(self, token, space, preference_id, *, limit=20, check_evidence=False):
        """Read a bounded chain from the selected revision towards its predecessors."""
        require(type(limit) is int and 1 <= limit <= 100)
        require(type(check_evidence) is bool)
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            scope = self._scope(c, owner, space)
            self._verify_preference_space(c, owner['avatar'], scope)
            now = self.now()
            records = []
            seen = set()
            record = self._owner_preference(c, owner, space, preference_id)
            while True:
                require(record['preference_id'] == preference_id and preference_id not in seen,
                        'E_INTEGRITY', 500)
                if len(records) == limit:
                    return {'preferences': records, 'next_preference_id': preference_id}
                seen.add(preference_id)
                if check_evidence:
                    record['evidence_status'] = self._preference_evidence_status(c, owner, space, scope, record, now)
                records.append(record)
                preference_id = record.get('replaces')
                if preference_id is None:
                    return {'preferences': records, 'next_preference_id': None}
                predecessor = self._owner_preference(c, owner, space, preference_id)
                require(predecessor.get('successor') == record['preference_id']
                        and predecessor['status'] == 'superseded', 'E_INTEGRITY', 500)
                record = predecessor

    def _preference_evidence_status(self, c, owner, space, scope, preference, now):
        refs = preference['evidence_refs']
        if not refs:
            return []
        slots = ','.join('?' for _ in refs)
        rows = c.execute(f'SELECT id, body FROM memories WHERE avatar=? AND space=? AND id IN ({slots})',
                         (owner['avatar'], space, *(ref['memory_id'] for ref in refs)))
        versions = {}
        for row in rows:
            memory = json.loads(row['body'])
            if (memory['scope'] == scope and memory['level'] == 'M1'
                    and self._memory_validity(memory, now) == 'current'):
                versions[row['id']] = memory['revision']
        statuses = []
        for ref in refs:
            revision = versions.get(ref['memory_id'])
            state = 'unavailable' if revision is None else 'current' if revision == ref['revision'] else 'revised'
            statuses.append({'memory_id': ref['memory_id'], 'confirmed_revision': ref['revision'],
                             'current_revision': revision, 'state': state})
        return statuses

    def list_preferences(self, token, space, *, after='', limit=20):
        require(isinstance(after, str) and (after == '' or re.fullmatch(r'preference:[0-9a-f]{64}', after)))
        require(type(limit) is int and 1 <= limit <= 100)
        with self.tx(read_only=True) as c:
            owner = self._grant(c, token)
            self._allow(owner, [space], 'read', owner=True)
            self._verify_preference_space(c, owner['avatar'], self._scope(c, owner, space))
            rows = c.execute("""SELECT value FROM meta WHERE key GLOB 'preference:*' AND key>?
                AND json_extract(value, '$.avatar_id')=? AND json_extract(value, '$.space_ref')=?
                ORDER BY key LIMIT ?""", (after, owner['avatar'], space, limit + 1))
            records = [json.loads(row[0]) for row in rows]
            return {'preferences': records[:limit],
                    'next_after': records[limit - 1]['preference_id'] if len(records) > limit else None}

    def _preference_draft(self, c, owner, space, *, statement, condition, runtimes, exception=None,
                          project_rule=None, supporting=None, counterexamples=None, replaces=None, same_event=None,
                          evidence_revisions=None):
        for value in (statement, condition):
            require(isinstance(value, str) and 0 < len(value.strip()) and len(value) <= 2000)
        for value in (exception, project_rule):
            require(value is None or (isinstance(value, str) and value.strip() and len(value) <= 2000))
        require(isinstance(runtimes, list) and 1 <= len(runtimes) <= 50)
        require(all(isinstance(r, str) and r == r.strip() and 0 < len(r) <= 200 for r in runtimes))
        supporting = [] if supporting is None else supporting
        counterexamples = [] if counterexamples is None else counterexamples
        require(isinstance(supporting, list) and isinstance(counterexamples, list))
        sources = self._preference_sources(c, owner, space, supporting + counterexamples)
        if evidence_revisions is None:
            evidence_revisions = {}
        require(isinstance(evidence_revisions, dict)
                and evidence_revisions.keys() <= set(supporting + counterexamples))
        require(all(type(version) is int and 1 <= version < 2**63 for version in evidence_revisions.values()))
        for group in sources['sources']:
            for observation in group['observations']:
                mid = observation['memory_id']
                if mid in evidence_revisions:
                    require(observation['revision'] == evidence_revisions[mid], 'E_VERSION_CONFLICT', 409)
                observation['roles'] = [role for role, ids in (('supporting', supporting),
                                        ('counterexample', counterexamples)) if mid in ids]
        review = {}
        if same_event is not None:
            require(isinstance(same_event, list) and len(same_event) <= 25)
            if same_event:
                events = self._preference_events(sources['sources'], same_event)
                review.update(event_group_count=len(events), event_groups=events)
        if replaces is not None:
            self._owner_preference(c, owner, space, replaces)
            review['replaces'] = replaces
        return {**review, 'status': 'preview', 'target_level': 'M2', 'space_ref': space, 'avatar_id': owner['avatar'],
                'scope': self._scope(c, owner, space),
                'statement': statement.strip(), 'condition': condition.strip(),
                'exception': exception, 'project_rule': project_rule,
                'allowed_runtimes': sorted(set(runtimes)), 'evidence': sources}

    @staticmethod
    def _preference_events(sources, same_event):
        roles = {group['source_ref']: {role for obs in group['observations'] for role in obs['roles']}
                 for group in sources}
        remaining = set(roles)
        groups = []
        for refs in same_event:
            require(isinstance(refs, list) and 2 <= len(refs) <= len(remaining))
            require(all(isinstance(ref, str) and ref in remaining for ref in refs))
            require(len(set(refs)) == len(refs))
            remaining.difference_update(refs)
            groups.append(sorted(refs))
        groups.extend([ref] for ref in remaining)
        return [{'source_refs': refs, 'roles': sorted(set.union(*(roles[ref] for ref in refs)))}
                for refs in sorted(groups)]

    def _preference_sources(self, c, owner, space, memory_ids):
        require(len(memory_ids) <= 50)
        require(all(isinstance(mid, str) and 0 < len(mid) <= 200 for mid in memory_ids))
        ids = sorted(set(memory_ids))
        scope = self._scope(c, owner, space)
        if not ids:
            return {'space_ref': space, 'record_count': 0, 'source_count': 0, 'sources': []}
        placeholders = ','.join('?' for _ in ids)
        rows = c.execute(f'SELECT body FROM memories WHERE avatar=? AND space=? AND id IN ({placeholders}) ORDER BY id',
                         (owner['avatar'], space, *ids))
        groups = {}
        now = self.now()
        selected = 0
        for row in rows:
            record = json.loads(row['body'])
            require(record['scope'] == scope and record['level'] == 'M1'
                    and self._memory_validity(record, now) == 'current', 'E_NOT_FOUND', 404)
            source = record['source']
            groups.setdefault(source['source_ref'], []).append({
                'memory_id': record['memory_id'], 'revision': record['revision'],
                'source_type': source['source_type'], 'content': record['content'],
                'origin_runtime': source.get('origin_runtime')})
            selected += 1
        require(selected == len(ids), 'E_NOT_FOUND', 404)
        return {'space_ref': space, 'record_count': selected, 'source_count': len(groups),
                'sources': [{'source_ref': ref, 'observations': groups[ref]} for ref in sorted(groups)]}

    def memory_history(self, token, space, memory_id, *, revision=None, before=None, limit=20):
        require(isinstance(memory_id, str) and 0 < len(memory_id) <= 200)
        require(type(limit) is int and 1 <= limit <= 100)
        require(revision is None or before is None)
        for number in (revision, before):
            require(number is None or (type(number) is int and 1 <= number <= (1 << 63) - 1))

        with self.tx(read_only=True) as connection:
            owner = self._grant(connection, token)
            self._allow(owner, [space], 'read', owner=True)
            target = {'avatar': owner['avatar'], 'space': space, 'id': memory_id}
            scope = 'avatar=:avatar AND space=:space AND id=:id'
            current = connection.execute(f'SELECT revision FROM memories WHERE {scope}', target).fetchone()
            require(current is not None, 'E_NOT_FOUND', 404)
            latest = current['revision']
            result = {'memory_id': memory_id, 'space_ref': space, 'current_revision': latest}

            if revision is not None:
                require(revision <= latest, 'E_NOT_FOUND', 404)
                table = 'memories' if revision == latest else 'history'
                row = connection.execute(
                    f'SELECT body FROM {table} WHERE {scope} AND revision=:revision',
                    {**target, 'revision': revision},
                ).fetchone()
                require(row is not None, 'E_NOT_FOUND', 404)
                return {**result, 'record': json.loads(row['body'])}

            revisions = [latest] if before is None or latest < before else []
            revisions.extend(row['revision'] for row in connection.execute(
                f'SELECT revision FROM history WHERE {scope} AND revision < :ceiling '
                'ORDER BY revision DESC LIMIT :page_size',
                {**target, 'ceiling': latest if before is None else min(latest, before),
                 'page_size': limit + 1 - len(revisions)},
            ))
            return {**result, 'revisions': revisions[:limit],
                    'next_before': revisions[limit - 1] if len(revisions) > limit else None}

    @staticmethod
    def _review_classification(memory):
        return {'level': memory['level'], 'type': memory['type'],
                'reported_source_type': memory['source']['source_type'],
                'confidence': memory['confidence'],
                'stable_preference': memory['lifecycle']['stable_preference']}

    def proposal_status(self, token, body):
        """Report only the caller's single-space proposal state."""
        exact(body, ['delta_id', 'space_ref', 'purpose'])
        ident, space, purpose = body['delta_id'], body['space_ref'], body['purpose']
        require(isinstance(ident, str) and 0 < len(ident) <= 512)
        require(isinstance(purpose, str) and purpose)
        with self.tx(read_only=True) as connection:
            grant = self._grant(connection, token)
            self._allow(grant, [space], 'read', purpose)
            row = connection.execute(
                'SELECT scopes, status FROM deltas WHERE avatar=? AND issuer=? AND id=?',
                (grant['avatar'], grant['id'], ident)).fetchone()
            status = row['status'] if row and json.loads(row['scopes']) == [space] else 'not-found'
            return {'delta_id': ident, 'status': status}

    def review(self, token, ident, *, changes=False):
        require(isinstance(ident, str))
        with self.tx(read_only=True) as connection:
            grant = self._grant(connection, token)
            row = connection.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',
                                     (grant['avatar'], ident)).fetchone()
            require(row is not None and set(json.loads(row['scopes'])) <= set(json.loads(grant['scopes'])),
                    'E_NOT_FOUND', 404)
            scopes = json.loads(row['scopes'])
            self._allow(grant, scopes, 'read', owner=changes)
            require(grant['role'] == 'owner' or grant['id'] == row['issuer'], 'E_DENIED', 403)
            result = {'delta_id': ident, 'status': row['status'],
                      'outcome': json.loads(row['outcome']) if row['outcome'] else None}
            if grant['role'] == 'owner' and row['status'] in ('accepted', 'rejected'):
                reason = connection.execute(
                    "SELECT event FROM audit WHERE avatar=? AND object_id=? AND event GLOB 'delta-decision-reason:*' LIMIT 1",
                    (grant['avatar'], ident)).fetchone()
                result['decision_reason'] = reason[0].partition(':')[2] if reason else None
            if not changes:
                return {**result, 'candidate': json.loads(row['body']) if row['body'] else None}
            if row['status'] != 'proposed':
                return {**result, 'changes': []}

            envelope = json.loads(row['body'])
            extensions = envelope['delta'].get('extensions', {})
            lifecycle = extensions.get(LOCAL_LIFECYCLE_EXTENSION)
            admission = extensions.get(LOCAL_ADMISSION_EXTENSION)
            bindings = {binding['change_id']: binding for binding in envelope['bindings']}
            preview = []
            for change in envelope['delta']['changes']:
                binding = bindings[change['change_id']]
                memory_id = binding['target_object_id']
                space = binding['scope']['space_ref']
                require(space in scopes, 'E_NOT_FOUND', 404)
                current = connection.execute(
                    'SELECT revision, body FROM memories WHERE avatar=? AND space=? AND id=?',
                    (grant['avatar'], space, memory_id),
                ).fetchone()
                revision = current['revision'] if current else None
                base_revision = binding['base_revision']
                current_memory = json.loads(current['body']) if current else None
                change_preview = {
                    'memory_id': memory_id, 'space_ref': space, 'operation': change['operation'],
                    'base_revision': base_revision, 'current_revision': revision,
                    'revision_conflict': base_revision != (0 if revision is None else revision),
                    'current_text': current_memory['content'] if current_memory else None,
                    'proposed_text': change['candidate']['content'],
                    'current_classification': self._review_classification(current_memory) if current_memory else None,
                    'proposed_classification': self._review_classification(change['candidate']),
                    'proposal_source': {'runtime_ref': envelope['delta']['runtime_id'],
                                        'reported_reference': change['candidate']['source']['source_ref']},
                }
                if lifecycle is not None:
                    change_preview.update(current_level=current_memory['level'] if current_memory else None,
                                          proposed_level=change['candidate']['level'], transition_reason=lifecycle['reason'])
                if admission is not None:
                    duplicate = self._approval_duplicate(connection, grant['avatar'], change['candidate'])
                    if duplicate is not None:
                        change_preview['active_duplicate'] = duplicate
                preview.append(change_preview)
            if admission is not None:
                result['admission'] = admission
            try:
                self._allow(grant, scopes, 'write', owner=True)
                self._approval_records(connection, grant, row, envelope, allow_lifecycle=True)
            except Fault as exc:
                result['approval_check'] = {'status': 'blocked', 'code': exc.code}
            else:
                result['approval_check'] = {'status': 'ready'}
            return {**result, 'changes': preview}

    def pending_proposals(self, token, *, space=None, after=None, limit=20, trigger=None):
        from .admission import TRIGGERS

        require(trigger is None or trigger in (*TRIGGERS, 'legacy'))
        trigger_value = "COALESCE(json_extract(delta.body, :trigger_path), 'legacy')"
        require(type(limit) is int and 1 <= limit <= 100)
        require(after is None or (isinstance(after, str) and after))
        with self.tx(read_only=True) as connection:
            owner = self._grant(connection, token)
            allowed_spaces = json.loads(owner['scopes'])
            self._allow(owner, allowed_spaces if space is None else [space], 'read', owner=True)
            rows = connection.execute(f'''
                SELECT delta.id, delta.scopes, {trigger_value} AS trigger FROM deltas AS delta
                WHERE delta.avatar = :avatar AND delta.status = 'proposed'
                  AND delta.id > :after
                  AND (:trigger IS NULL OR {trigger_value} = :trigger)
                  AND (:space IS NULL OR EXISTS (
                      SELECT 1 FROM json_each(delta.scopes) WHERE value = :space
                  ))
                  AND {_PROPOSAL_SCOPES_VISIBLE}
                ORDER BY delta.id LIMIT :page_size
            ''', {'avatar': owner['avatar'], 'space': space, 'after': after or '',
                  'allowed': owner['scopes'], 'page_size': limit + 1, 'trigger': trigger,
                  'trigger_path': f'$.delta.extensions."{LOCAL_ADMISSION_EXTENSION}".trigger'}).fetchall()
            proposals = []
            for row in rows[:limit]:
                entry = {'delta_id': row['id'], 'space_refs': json.loads(row['scopes'])}
                if row['trigger'] != 'legacy' or trigger is not None:
                    entry['trigger'] = row['trigger']
                proposals.append(entry)
            return {'proposals': proposals,
                    'next_after': proposals[-1]['delta_id'] if len(rows) > limit else None}

    def local_summary(self, token, *, space=None):
        with self.tx(read_only=True) as connection:
            owner = self._grant(connection, token)
            scopes = json.loads(owner['scopes']) if space is None else [space]
            self._allow(owner, scopes, 'read', owner=True)
            params = {'avatar': owner['avatar'], 'visible': encode(scopes), 'allowed': owner['scopes']}
            memory_counts = {row['space']: row for row in connection.execute('''
                SELECT memory.space,
                       count(CASE WHEN json_extract(memory.body, '$.level') IN ('M1', 'M2') THEN 1 END) AS active,
                       count(CASE WHEN json_extract(memory.body, '$.level') = 'M3' THEN 1 END) AS archived
                FROM memories AS memory
                JOIN spaces ON spaces.avatar = memory.avatar AND spaces.id = memory.space
                WHERE memory.avatar = :avatar
                  AND memory.space IN (SELECT value FROM json_each(:visible))
                  AND json_extract(memory.body, '$.status') = 'active'
                  AND COALESCE(json_extract(memory.body, '$.extensions."x-aiap-memory-validity-v1".expires_at'), '9999Z') > :now
                  AND json_extract(memory.body, '$.scope.owner_ref') = :owner_ref
                  AND json_extract(memory.body, '$.scope.space_ref') = memory.space
                  AND json_extract(memory.body, '$.scope.policy_ref.id') = spaces.policy
                  AND json_extract(memory.body, '$.scope.policy_ref.version') = spaces.revision
                GROUP BY memory.space
            ''', {**params, 'owner_ref': owner['subject'], 'now': stamp(self.now())})}
            pending_counts = dict(connection.execute(f'''
                SELECT participant.value, count(DISTINCT delta.id)
                FROM deltas AS delta JOIN json_each(delta.scopes) AS participant
                WHERE delta.avatar = :avatar AND delta.status = 'proposed'
                  AND participant.value IN (SELECT value FROM json_each(:visible))
                  AND {_PROPOSAL_SCOPES_VISIBLE}
                GROUP BY participant.value
            ''', params))
            return {'spaces': [
                {'space_ref': scope,
                 'active_memories': memory_counts[scope]['active'] if scope in memory_counts else 0,
                 'archived_memories': memory_counts[scope]['archived'] if scope in memory_counts else 0,
                 'pending_proposals': pending_counts.get(scope, 0)}
                for scope in sorted(scopes)
            ]}

    def list_audit(self, token, *, space=None, event=None, object_id=None, before=None, limit=20):
        require(type(limit) is int and 1 <= limit <= 100)
        require(before is None or (isinstance(before, str) and 0 < len(before) <= 200))
        require(event is None or (isinstance(event, str) and 0 < len(event) <= 200))
        require(object_id is None or (isinstance(object_id, str) and bool(object_id)))
        with self.tx(read_only=True) as connection:
            owner = self._grant(connection, token)
            scopes = json.loads(owner['scopes'])
            self._allow(owner, scopes if space is None else [space], 'read', owner=True)
            known_spaces = {row['id'] for row in connection.execute(
                'SELECT id FROM spaces WHERE avatar=?', (owner['avatar'],),
            )}
            visible = '''avatar = :avatar AND (
                space IN (SELECT value FROM json_each(:scopes))
                OR (space IS NULL AND :include_unscoped)
            ) AND (:event IS NULL OR event = :event)
              AND (:object_id IS NULL OR object_id = :object_id)'''
            params = {'avatar': owner['avatar'], 'scopes': encode(scopes if space is None else [space]),
                      'include_unscoped': space is None and known_spaces <= set(scopes),
                      'event': event, 'object_id': object_id}
            cursor_time = None
            if before is not None:
                cursor = connection.execute(f'SELECT at FROM audit WHERE {visible} AND id = :before',
                                            {**params, 'before': before}).fetchone()
                require(cursor is not None, 'E_NOT_FOUND', 404)
                cursor_time = cursor['at']
            rows = connection.execute(f'''
                SELECT id AS audit_id, space AS space_ref, event, object_id, at, actor
                FROM audit WHERE {visible}
                  AND (:cursor_time IS NULL OR (at, id) < (:cursor_time, :before))
                ORDER BY at DESC, id DESC LIMIT :page_size
            ''', {**params, 'cursor_time': cursor_time, 'before': before, 'page_size': limit + 1}).fetchall()
        return {'events': [dict(row) for row in rows[:limit]],
                'next_before': rows[limit - 1]['audit_id'] if len(rows) > limit else None}

    def _approval_records(self, connection, owner, pending, envelope, *, allow_lifecycle):
        issuer = self._grant(connection, ident=pending['issuer'])
        records = self._validate_delta(connection, issuer, envelope, allow_lifecycle=allow_lifecycle)
        if LOCAL_ADMISSION_EXTENSION in envelope['delta'].get('extensions', {}):
            for candidate, _ in records:
                require(self._approval_duplicate(connection, owner['avatar'], candidate) is None,
                        'E_DUPLICATE_MEMORY', 409)
        return records

    def decide(self,token,ident,approve,*,allow_lifecycle=False,reason=None):
        require(reason is None or reason in DECISION_REASONS)
        require(isinstance(ident,str) and type(approve) is bool)
        with self.tx() as c:
            owner=self._grant(c,token);require(owner['role']=='owner','E_DENIED',403);r=c.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',(owner['avatar'],ident)).fetchone()
            require(r is not None and set(json.loads(r['scopes']))<=set(json.loads(owner['scopes'])),'E_NOT_FOUND',404);self._allow(owner,json.loads(r['scopes']),'write',owner=True)
            final='accepted' if approve else 'rejected'
            if r['status']==final:return {'delta_id':ident,'status':final,'idempotent':True}
            require(r['status']=='proposed','E_VERSION_CONFLICT',409)
            if reason is not None:
                self._audit(c, owner['avatar'], None, 'delta-decision-reason:' + reason, ident, owner['id'])
            if not approve:
                c.execute('UPDATE deltas SET status=?,body=NULL WHERE avatar=? AND id=?',('rejected',owner['avatar'],ident));self._audit(c,owner['avatar'],None,'delta-rejected',ident,owner['id'])
                return {'delta_id':ident,'status':'rejected','idempotent':False}
            envelope = json.loads(r['body'])
            records = self._approval_records(c, owner, r, envelope, allow_lifecycle=allow_lifecycle)
            lifecycle = envelope['delta'].get('extensions', {}).get(LOCAL_LIFECYCLE_EXTENSION)
            receipt=self._audit(c,owner['avatar'],None,'delta-accepted',ident,owner['id']);out=[]
            for proposed,old in records:
                m=copy.deepcopy(proposed)
                if old and old.get('extensions'):
                    m['extensions'] = copy.deepcopy(old['extensions'])
                if old:c.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',(owner['avatar'],old['memory_id'],old['revision'],old['scope']['space_ref'],encode(old)))
                now=stamp(self.now());m['revision']=old['revision']+1 if old else 1;m['previous_revision']=old['revision'] if old else None
                m['created_at']=old['created_at'] if old else now;m['updated_at']=now;m['status']='active'
                # Caller timestamps/counts/trust flags never become trusted usage evidence.
                for k in ('last_used_at','context_use_count','confirmed_use_count'):
                    m['lifecycle'][k]=old['lifecycle'][k] if old else (None if k=='last_used_at' else 0)
                m['recall_count']=old.get('recall_count',0) if old else 0
                if lifecycle is not None:
                    _, target_level, event = LOCAL_LIFECYCLE_TRANSITIONS[lifecycle['kind']]
                    m['retention']['last_transition'] = {'from': old['level'], 'to': target_level,
                                                          'reason': lifecycle['reason'], 'at': now}
                    if target_level == 'M3':
                        m['retention']['demotion_count'] = m['retention'].get('demotion_count', 0) + 1
                    self._audit(c, owner['avatar'], m['scope']['space_ref'], event, m['memory_id'], owner['id'])
                else:
                    m['lifecycle']['last_verified'] = now
                    m['source'] = {k:v for k,v in m['source'].items() if k in ('source_type','source_ref','origin_runtime','origin_device')}
                    m['source'].update(verified=False,signed=False,confirmation_ref=receipt)
                # Confirmation is attestation of an owner-approved record, not verification of external evidence.
                validate('memory-record',m)
                c.execute('INSERT INTO memories VALUES(?,?,?,?,?) ON CONFLICT(avatar,id) DO UPDATE SET space=excluded.space,revision=excluded.revision,body=excluded.body',(owner['avatar'],m['memory_id'],m['scope']['space_ref'],m['revision'],encode(m)))
                out.append({'memory_id':m['memory_id'],'revision':m['revision'],'space_ref':m['scope']['space_ref']})
            self._rebuild_core(c,owner['avatar'])
            c.execute('UPDATE deltas SET status=?,body=NULL,outcome=? WHERE avatar=? AND id=?',('accepted',encode(out),owner['avatar'],ident))
            return {'delta_id':ident,'status':'accepted','objects':out,'idempotent':False}
    def _deletion_target(self, connection, token, body):
        exact(body, ['memory_id', 'space_ref', 'base_revision'])
        memory_id, space_ref, revision = body['memory_id'], body['space_ref'], body['base_revision']
        require(isinstance(memory_id, str) and isinstance(space_ref, str) and type(revision) is int)
        grant = self._grant(connection, token)
        self._allow(grant, [space_ref], 'delete', owner=True)
        row = connection.execute(
            'SELECT * FROM memories WHERE avatar=? AND id=? AND space=?',
            (grant['avatar'], memory_id, space_ref),
        ).fetchone()
        require(row is not None, 'E_NOT_FOUND', 404)
        require(row['revision'] == revision, 'E_VERSION_CONFLICT', 409)
        return grant, row

    def _deletion_dependencies(self, connection, avatar, memory_id):
        deltas = connection.execute('SELECT id,body FROM deltas WHERE avatar=? AND body IS NOT NULL', (avatar,))
        delta_ids = [row['id'] for row in deltas if any(
            binding['target_object_id'] == memory_id for binding in json.loads(row['body'])['bindings']
        )]
        views = connection.execute('SELECT id,body FROM views WHERE avatar=? AND invalidated=0', (avatar,))
        view_ids = [row['id'] for row in views if any(
            item['id'] == memory_id for item in json.loads(row['body'])['objects']
        )]
        return delta_ids, view_ids

    def preview_delete(self, token, body):
        with self.tx(read_only=True) as connection:
            grant, row = self._deletion_target(connection, token, body)
            identity = (grant['avatar'], row['id'])
            history_count = connection.execute(
                'SELECT count(*) FROM history WHERE avatar=? AND id=?', identity,
            ).fetchone()[0]
            delta_ids, view_ids = self._deletion_dependencies(connection, *identity)
            return {
                'memory_id': row['id'],
                'space_ref': row['space'],
                'base_revision': row['revision'],
                'history_versions_to_remove': history_count,
                'proposals_to_invalidate': len(delta_ids),
                'views_to_invalidate': len(view_ids),
                'tombstone_purge_status': 'backup-expiry-pending',
                'physical_backup_erasure': 'not_guaranteed',
            }

    def delete(self, token, body):
        with self.tx() as connection:
            grant, row = self._deletion_target(connection, token, body)
            avatar, memory_id, revision = grant['avatar'], row['id'], row['revision']
            delta_ids, view_ids = self._deletion_dependencies(connection, avatar, memory_id)
            audit_id = self._audit(connection, avatar, row['space'], 'memory-deleted', memory_id, grant['id'])
            tombstone = {
                'object_ref': {'id': memory_id, 'version': revision},
                'scope': json.loads(row['body'])['scope'],
                'deleted_at': stamp(self.now()),
                'authorization_ref': {'id': audit_id, 'version': 1},
                'purge_status': 'backup-expiry-pending',
                'supersedes_through_revision': revision,
            }
            validate('tombstone', tombstone)
            connection.execute('INSERT INTO tombstones VALUES(?,?,?,?,?)',
                               (avatar, memory_id, row['space'], revision, encode(tombstone)))
            connection.execute('DELETE FROM memories WHERE avatar=? AND id=?', (avatar, memory_id))
            connection.execute('DELETE FROM history WHERE avatar=? AND id=?', (avatar, memory_id))
            connection.executemany('UPDATE deltas SET status=?,body=NULL WHERE avatar=? AND id=?',
                                   (('invalidated', avatar, delta_id) for delta_id in delta_ids))
            connection.executemany('UPDATE views SET invalidated=1 WHERE avatar=? AND id=?',
                                   ((avatar, view_id) for view_id in view_ids))
            self._rebuild_core(connection, avatar)
            return {'deleted': True, 'tombstone': tombstone, 'physical_backup_erasure': 'not_guaranteed'}
    def archive_cycle(self, *, dry_run=False):
        # Trusted internal job, not an unauthenticated network operation. No data leaves the service.
        changed=[]
        candidates = []
        eligible = 0
        with self.tx(read_only=dry_run) as c:
            now = self.now()
            for row in c.execute('SELECT * FROM memories ORDER BY avatar,id').fetchall():
                m=json.loads(row['body']);lc=m['lifecycle'];ret=m['retention']
                if not self.current_memory(m) or m['level'] not in ('M1','M2'):continue
                if ret['pinned'] or ret['decay_exempt'] or lc['stable_preference'] or lc['recurrence_ref'] or lc['active_task_refs']:continue
                expected_use = parse(lc['expected_next_use']) if lc['expected_next_use'] else None
                if expected_use and timedelta(0) <= expected_use - now <= timedelta(days=30):
                    continue
                # A newly approved correction starts a fresh inactivity window without counting as a use.
                last = max(parse(value) for value in
                           (m['created_at'], lc['last_used_at'], lc.get('last_verified')) if value)
                # The stored revision already exists at its Core-assigned update time.
                if last > now or parse(m['updated_at']) > now:
                    continue
                transition = ret.get('last_transition')
                if transition and transition['to'] == m['level'] and (
                        transition['from'], transition['to']) in (('M3', 'M1'), ('M1', 'M2')):
                    entered_level = parse(transition['at'])
                    if entered_level <= now:
                        last = max(last, entered_level)
                threshold=30 if m['level']=='M1' else 180
                if (now-last).total_seconds()<threshold*86400:continue
                if dry_run:
                    eligible += 1
                    if len(candidates) < 20:
                        eligible_since = last + timedelta(days=threshold)
                        if expected_use and eligible_since <= expected_use < now:
                            eligible_since = expected_use + timedelta(microseconds=1)
                        candidates.append({'memory_id': row['id'], 'space_ref': row['space'],
                                           'base_revision': row['revision'], 'from_level': m['level'],
                                           'to_level': 'M3', 'eligible_since': stamp(eligible_since)})
                    continue
                c.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',(row['avatar'],row['id'],row['revision'],row['space'],row['body']))
                old=m['level'];m['level']='M3';m['previous_revision']=m['revision'];m['revision']+=1;m['updated_at']=stamp(now)
                m['retention']['last_transition']={'from':old,'to':'M3','reason':'lifecycle:default@1 inactivity threshold; protections evaluated','at':stamp(now)}
                m['retention']['demotion_count']=m['retention'].get('demotion_count',0)+1
                validate('memory-record',m);c.execute('UPDATE memories SET revision=?,body=? WHERE avatar=? AND id=?',(m['revision'],encode(m),row['avatar'],row['id']))
                self._audit(c,row['avatar'],row['space'],'memory-archived',row['id'],'internal-lifecycle');changed.append(row['avatar'])
            for av in set(changed):self._rebuild_core(c,av)
        if dry_run:
            return {'eligible': eligible, 'candidates': candidates, 'possibly_more': eligible > len(candidates)}
        return {'archived':len(changed)}
