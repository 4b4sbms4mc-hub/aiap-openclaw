"""Single-owner local Core Service. No remote identity/transfer activation.
Wang Lu. Request authorization is resolved inside each SQLite transaction.
"""
import sqlite3,json,secrets,hashlib,os,uuid,copy
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .contracts import Fault,require,validate,canonical,digest,b64,unb64,exact,names

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
class Service:
    def __init__(self,data_dir,clock=None):
        from .semantic import Semantic
        self.semantic=Semantic.from_environment()
        self.directory=Path(data_dir);self.db=self.directory/'core.sqlite3';self.clock=clock or (lambda:datetime.now(timezone.utc))
    def now(self):return self.clock().astimezone(timezone.utc)
    @contextmanager
    def tx(self):
        require(self.db.exists(),'E_NOT_INITIALIZED',503)
        c=sqlite3.connect(self.db,timeout=10,isolation_level=None);c.row_factory=sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA secure_delete=ON');c.execute('BEGIN IMMEDIATE')
        try:yield c;c.commit()
        except BaseException:c.rollback();raise
        finally:c.close()
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
        refs=[]
        for r in c.execute('SELECT body FROM memories WHERE avatar=? ORDER BY id',(av,)):
            m=json.loads(r['body']);refs.append({'id':m['memory_id'],'version':m['revision'],'scope':m['scope'],'sha256':digest(m)})
        n=row['revision']+1
        core={'aiap_version':'0.4.2','profile_version':'0.1-draft','avatar_id':av,'owner':{'owner_ref':row['owner'],'owner_key_ref':'local-key:owner','avatar_key_ref':'local-key:avatar'},'revision':n,'previous_revision':n-1 if n>1 else None,'identity_refs':['local-identity:enrollment'],'profile_summary':[],'state_index':refs,'procedural_index':[],'extensions':[{'namespace':'x-aiap-core-profile','version':'0.1-draft','critical':True}],'updated_at':stamp(self.now())}
        payload=canonical(core);key=serialization.load_pem_private_key((self.directory/'avatar-key.pem').read_bytes(),None)
        core['integrity']={'manifest_sha256':hashlib.sha256(payload).hexdigest(),'proofs':[{'crypto_profile':'x-aiap-local-ed25519-json-v1','key_ref':'local-key:avatar','signature':b64(key.sign(b'AIAP-LOCAL-CORE-v1\x00'+payload))}]}
        validate('avatar-core',core);c.execute('UPDATE cores SET revision=?,body=? WHERE avatar=?',(n,encode(core),av))
    def verify_local_core(self,core,enrollment):
        try:
            p=enrollment['payload'];require(p['profile']=='x-aiap-local-enrollment-v1','E_INTEGRITY');Ed25519PublicKey.from_public_bytes(unb64(p['owner_public_key'])).verify(unb64(enrollment['signature']),b'AIAP-LOCAL-ENROLLMENT-v1\x00'+canonical(p))
            bare=copy.deepcopy(core);proof=bare.pop('integrity');raw=canonical(bare)
            require(len(proof['proofs'])==1 and proof['proofs'][0]['crypto_profile']=='x-aiap-local-ed25519-json-v1' and proof['proofs'][0]['key_ref']=='local-key:avatar','E_INTEGRITY')
            require(proof['manifest_sha256']==hashlib.sha256(raw).hexdigest(),'E_INTEGRITY')
            require(p['avatar_id']==core['avatar_id'] and p['owner_ref']==core['owner']['owner_ref'],'E_INTEGRITY')
            Ed25519PublicKey.from_public_bytes(unb64(p['avatar_public_key'])).verify(unb64(proof['proofs'][0]['signature']),b'AIAP-LOCAL-CORE-v1\x00'+raw)
            return True
        except Exception:return False
    def issue_grant(self,scopes,purpose,runtime,role='adapter',days=7):
        # Local operator command only; never exposed over HTTP.
        require(names(scopes) and isinstance(purpose,str) and 0<len(purpose)<=200 and isinstance(runtime,str) and 0<len(runtime)<=200)
        require(role in ('owner','adapter') and isinstance(days,int) and 1<=days<=30)
        raw=secrets.token_urlsafe(32);ident=uid('grant:');now=self.now()
        with self.tx() as c:
            av=self.meta(c,'avatar');owner=self.meta(c,'owner')
            known={r[0] for r in c.execute('SELECT id FROM spaces WHERE avatar=?',(av,))}
            require(set(scopes)<=known,'E_SCOPE',403)
            actions=['read','write','delete','admin'] if role=='owner' else ['read','write']
            c.execute('INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)',(ident,hashlib.sha256(raw.encode()).hexdigest(),av,owner,role,encode(scopes),encode(actions),purpose,runtime,uid('session:'),stamp(now),stamp(now+timedelta(days=days))))
            self._audit(c,av,None,'credential-issued',ident,'local-operator')
        return {'token':raw,'grant_id':ident,'avatar_id':av,'role':role,'space_refs':scopes,'purpose':purpose,'runtime_ref':runtime,'expires_at':stamp(now+timedelta(days=days))}
    def revoke_grant(self,ident):
        with self.tx() as c:
            r=c.execute('SELECT avatar FROM grants WHERE id=?',(ident,)).fetchone();require(r is not None,'E_NOT_FOUND',404)
            c.execute('UPDATE grants SET revoked=1 WHERE id=?',(ident,));epoch=self.meta(c,'revocation_epoch')+1;c.execute('UPDATE meta SET value=? WHERE key=?',(encode(epoch),'revocation_epoch'))
            self._audit(c,r['avatar'],None,'credential-revoked',ident,'local-operator')
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
        with self.tx() as c:
            g=self._grant(c,token);scopes=json.loads(g['scopes'])
            return {'avatar_id':g['avatar'],'subject_ref':g['subject'],'role':g['role'],'runtime_ref':g['runtime'],'session_ref':g['session'],'auth_evidence_ref':g['id'],'purpose':g['purpose'],'space_refs':scopes,'scopes':[self._scope(c,g,s) for s in scopes],'issued_at':g['issued'],'expires_at':g['expires'],'actions':json.loads(g['actions']),'retrieval':('scoped-hybrid-cosine' if self.semantic and set(scopes)<=self.semantic.scopes else 'scoped-literal-substring')}
    def core(self,token):
        with self.tx() as c:
            g=self._grant(c,token);allspaces=[r[0] for r in c.execute('SELECT id FROM spaces WHERE avatar=?',(g['avatar'],))]
            self._allow(g,allspaces,'read',owner=True)
            core=json.loads(c.execute('SELECT body FROM cores WHERE avatar=?',(g['avatar'],)).fetchone()[0]);en=self.meta(c,'enrollment')
            require(self.verify_local_core(core,en),'E_INTEGRITY',500)
            return {'avatar_core':core,'local_enrollment':en,'trust_model':'local-bootstrap; not remote-owner-verification'}
    def search(self,token,body,context=False):
        if self.semantic is not None and not context:
            from .semantic import semantic_search
            return semantic_search(self,token,body)
        return self._literal_search(token,body,context)
    def _literal_search(self,token,body,context=False):
        exact(body,['space_refs','purpose','query'],['include_archived','limit'])
        require(isinstance(body['query'],str) and len(body['query'])<=1000)
        limit=body.get('limit',20);require(type(limit) is int and 1<=limit<=100)
        include=body.get('include_archived',False);require(type(include) is bool)
        with self.tx() as c:
            g=self._grant(c,token);scopes=body['space_refs'];self._allow(g,scopes,'read',body['purpose'])
            placeholders=','.join('?' for _ in scopes)
            # SQL scope predicate runs before any body reaches application scoring/context.
            rows=c.execute(f'SELECT body FROM memories WHERE avatar=? AND space IN ({placeholders}) ORDER BY id',(g['avatar'],*scopes))
            result=[]
            q=body['query'].casefold()
            for row in rows:
                m=json.loads(row[0])
                if m['status']!='active' or (m['level']=='M3' and not include):continue
                if m['scope']!=self._scope(c,g,m['scope']['space_ref']):continue
                if q and q not in m['content'].casefold():continue
                result.append(m)
                if len(result)>=limit:break
            out={'items':result,'count':len(result),'retrieval':'scoped-literal-substring','space_refs':scopes}
            if context:
                refs=[{'id':m['memory_id'],'version':m['revision'],'scope':m['scope'],'sha256':digest(m)} for m in result]
                view={'view_id':uid('view:'),'request_ref':uid('request:'),'avatar_id':g['avatar'],'subject_ref':g['subject'],'session_ref':g['session'],'runtime_ref':g['runtime'],'purpose':g['purpose'],'space_refs':scopes,'objects':refs,'policy_versions':[self._scope(c,g,s)['policy_ref'] for s in scopes],'revocation_epoch':self.meta(c,'revocation_epoch'),'compiled_at':stamp(self.now()),'expires_at':stamp(min(parse(g['expires']),self.now()+timedelta(minutes=5)))}
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
                m=json.loads(row['body']);c.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',(g['avatar'],m['memory_id'],m['revision'],row['space'],row['body']));require(m['scope']==self._scope(c,g,m['scope']['space_ref']),'E_POLICY_VERSION',409)
                m['lifecycle']['last_used_at']=stamp(self.now());m['lifecycle']['context_use_count']+=1
                m['previous_revision']=m['revision'];m['revision']+=1;m['updated_at']=stamp(self.now())
                validate('memory-record',m);c.execute('UPDATE memories SET revision=?,body=? WHERE avatar=? AND id=?',(m['revision'],encode(m),g['avatar'],m['memory_id']));touched=True
            c.execute('UPDATE views SET acked=1 WHERE id=?',(body['view_id'],))
            if touched:self._rebuild_core(c,g['avatar'])
            self._audit(c,g['avatar'],None,'context-use-acknowledged',body['view_id'],g['id'])
            return {'acknowledged':True,'idempotent':False}
    def _validate_delta(self,c,g,envelope):
        validate('state-delta',envelope);d=envelope['delta'];q=envelope['request'];bs=envelope['bindings'];scopes=q['space_refs']
        self._allow(g,scopes,'write',q['purpose'])
        require(q['authenticated_subject_ref']==g['subject'] and q['auth_evidence_ref']==g['id'] and q['avatar_id']==g['avatar'] and q['session_ref']==g['session'] and q['runtime_ref']==g['runtime'],'E_IDENTITY',403)
        require(q['action']=='write' and q['processor_refs']==[],'E_DENIED',403)
        require(d['avatar_id']==g['avatar'] and d['runtime_id']==g['runtime'],'E_SCOPE',403)
        require(parse(g['issued'])<=parse(q['issued_at'])<=self.now()<parse(q['expires_at'])<=parse(g['expires']),'E_EXPIRED',403)
        require(len(d['changes'])<=20 and len(bs)==len(d['changes']))
        ids=[x['change_id'] for x in d['changes']];bids=[x['change_id'] for x in bs]
        require(len(set(ids))==len(ids) and len(set(bids))==len(bids) and set(ids)==set(bids))
        targets=[x['target_object_id'] for x in bs];require(len(set(targets))==len(targets))
        by={x['change_id']:x for x in bs};records=[]
        for ch in d['changes']:
            require(ch['domain']=='aiap.memory' and ch['operation'] in ('add','update'),'E_OPERATION_UNSUPPORTED',422)
            b=by[ch['change_id']];m=ch['candidate'];validate('memory-record',m)
            require(isinstance(m['content'],str) and 0<len(m['content'])<=16000,'E_OPERATION_UNSUPPORTED',422)
            require(m['derived_from']==[] and not m.get('extensions'),'E_OPERATION_UNSUPPORTED',422)
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
            records.append((m,json.loads(old['body']) if old else None))
        return records
    def propose(self,token,envelope):
        validate('state-delta',envelope)
        with self.tx() as c:
            g=self._grant(c,token);d=envelope['delta'];scopes=envelope['request']['space_refs'];self._allow(g,scopes,'write',envelope['request']['purpose'])
            prior=c.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',(g['avatar'],d['delta_id'])).fetchone()
            if prior:
                require(prior['issuer']==g['id'],'E_DENIED',403)
                require(prior['payload_hash']==digest(envelope),'E_IDEMPOTENCY_CONFLICT',409)
                return {'delta_id':d['delta_id'],'status':prior['status'],'idempotent':True}
            self._validate_delta(c,g,envelope)
            c.execute('INSERT INTO deltas VALUES(?,?,?,?,?,?,?,?)',(g['avatar'],d['delta_id'],g['id'],encode(scopes),digest(envelope),encode(envelope),'proposed',None))
            self._audit(c,g['avatar'],None,'delta-proposed',d['delta_id'],g['id'])
            return {'delta_id':d['delta_id'],'status':'proposed','idempotent':False}
    def review(self,token,ident):
        require(isinstance(ident,str))
        with self.tx() as c:
            g=self._grant(c,token);r=c.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',(g['avatar'],ident)).fetchone()
            require(r is not None and set(json.loads(r['scopes']))<=set(json.loads(g['scopes'])),'E_NOT_FOUND',404);self._allow(g,json.loads(r['scopes']),'read')
            require(g['role']=='owner' or g['id']==r['issuer'],'E_DENIED',403)
            return {'delta_id':ident,'status':r['status'],'candidate':json.loads(r['body']) if r['body'] else None,'outcome':json.loads(r['outcome']) if r['outcome'] else None}
    def decide(self,token,ident,approve):
        require(isinstance(ident,str) and type(approve) is bool)
        with self.tx() as c:
            owner=self._grant(c,token);require(owner['role']=='owner','E_DENIED',403);r=c.execute('SELECT * FROM deltas WHERE avatar=? AND id=?',(owner['avatar'],ident)).fetchone()
            require(r is not None and set(json.loads(r['scopes']))<=set(json.loads(owner['scopes'])),'E_NOT_FOUND',404);self._allow(owner,json.loads(r['scopes']),'write',owner=True)
            final='accepted' if approve else 'rejected'
            if r['status']==final:return {'delta_id':ident,'status':final,'idempotent':True}
            require(r['status']=='proposed','E_VERSION_CONFLICT',409)
            if not approve:
                c.execute('UPDATE deltas SET status=?,body=NULL WHERE avatar=? AND id=?',('rejected',owner['avatar'],ident));self._audit(c,owner['avatar'],None,'delta-rejected',ident,owner['id'])
                return {'delta_id':ident,'status':'rejected','idempotent':False}
            issuer=self._grant(c,ident=r['issuer']);envelope=json.loads(r['body']);records=self._validate_delta(c,issuer,envelope)
            receipt=self._audit(c,owner['avatar'],None,'delta-accepted',ident,owner['id']);out=[]
            for proposed,old in records:
                m=copy.deepcopy(proposed)
                if old:c.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',(owner['avatar'],old['memory_id'],old['revision'],old['scope']['space_ref'],encode(old)))
                now=stamp(self.now());m['revision']=old['revision']+1 if old else 1;m['previous_revision']=old['revision'] if old else None
                m['created_at']=old['created_at'] if old else now;m['updated_at']=now;m['status']='active'
                # Caller timestamps/counts/trust flags never become trusted usage evidence.
                for k in ('last_used_at','context_use_count','confirmed_use_count'):
                    m['lifecycle'][k]=old['lifecycle'][k] if old else (None if k=='last_used_at' else 0)
                m['lifecycle']['last_verified']=now;m['recall_count']=old.get('recall_count',0) if old else 0
                m['source']={k:v for k,v in m['source'].items() if k in ('source_type','source_ref','origin_runtime','origin_device')}
                m['source'].update(verified=False,signed=False,confirmation_ref=receipt)
                # Confirmation is attestation of an owner-approved record, not verification of external evidence.
                validate('memory-record',m)
                c.execute('INSERT INTO memories VALUES(?,?,?,?,?) ON CONFLICT(avatar,id) DO UPDATE SET space=excluded.space,revision=excluded.revision,body=excluded.body',(owner['avatar'],m['memory_id'],m['scope']['space_ref'],m['revision'],encode(m)))
                out.append({'memory_id':m['memory_id'],'revision':m['revision'],'space_ref':m['scope']['space_ref']})
            self._rebuild_core(c,owner['avatar'])
            c.execute('UPDATE deltas SET status=?,body=NULL,outcome=? WHERE avatar=? AND id=?',('accepted',encode(out),owner['avatar'],ident))
            return {'delta_id':ident,'status':'accepted','objects':out,'idempotent':False}
    def delete(self,token,body):
        exact(body,['memory_id','space_ref','base_revision']);require(isinstance(body['memory_id'],str) and isinstance(body['space_ref'],str) and type(body['base_revision']) is int)
        with self.tx() as c:
            g=self._grant(c,token);self._allow(g,[body['space_ref']],'delete',owner=True)
            r=c.execute('SELECT * FROM memories WHERE avatar=? AND id=? AND space=?',(g['avatar'],body['memory_id'],body['space_ref'])).fetchone();require(r is not None,'E_NOT_FOUND',404)
            require(r['revision']==body['base_revision'],'E_VERSION_CONFLICT',409);m=json.loads(r['body'])
            a=self._audit(c,g['avatar'],body['space_ref'],'memory-deleted',body['memory_id'],g['id'])
            tomb={'object_ref':{'id':body['memory_id'],'version':r['revision']},'scope':m['scope'],'deleted_at':stamp(self.now()),'authorization_ref':{'id':a,'version':1},'purge_status':'backup-expiry-pending','supersedes_through_revision':r['revision']}
            validate('tombstone',tomb);c.execute('INSERT INTO tombstones VALUES(?,?,?,?,?)',(g['avatar'],body['memory_id'],body['space_ref'],r['revision'],encode(tomb)))
            c.execute('DELETE FROM memories WHERE avatar=? AND id=?',(g['avatar'],body['memory_id']))
            c.execute('DELETE FROM history WHERE avatar=? AND id=?',(g['avatar'],body['memory_id']))
            for d in c.execute('SELECT id,body FROM deltas WHERE avatar=? AND body IS NOT NULL',(g['avatar'],)).fetchall():
                e=json.loads(d['body'])
                if any(b['target_object_id']==body['memory_id'] for b in e['bindings']):c.execute('UPDATE deltas SET status=?,body=NULL WHERE avatar=? AND id=?',('invalidated',g['avatar'],d['id']))
            for view in c.execute('SELECT id,body FROM views WHERE avatar=? AND invalidated=0',(g['avatar'],)).fetchall():
                if any(x['id']==body['memory_id'] for x in json.loads(view['body'])['objects']):c.execute('UPDATE views SET invalidated=1 WHERE id=?',(view['id'],))
            self._rebuild_core(c,g['avatar']);return {'deleted':True,'tombstone':tomb,'physical_backup_erasure':'not_guaranteed'}
    def archive_cycle(self):
        # Trusted internal job, not an unauthenticated network operation. No data leaves the service.
        changed=[]
        with self.tx() as c:
            for row in c.execute('SELECT * FROM memories').fetchall():
                m=json.loads(row['body']);lc=m['lifecycle'];ret=m['retention'];now=self.now()
                if m['status']!='active' or m['level'] not in ('M1','M2'):continue
                if ret['pinned'] or ret['decay_exempt'] or lc['stable_preference'] or lc['recurrence_ref'] or lc['active_task_refs']:continue
                if lc['expected_next_use'] and parse(lc['expected_next_use'])<=now+timedelta(days=30):continue
                last=parse(lc['last_used_at'] or m['created_at'])
                if last>now or parse(m['created_at'])>now:continue
                threshold=30 if m['level']=='M1' else 180
                if (now-last).total_seconds()<threshold*86400:continue
                c.execute('INSERT OR IGNORE INTO history VALUES(?,?,?,?,?)',(row['avatar'],row['id'],row['revision'],row['space'],row['body']))
                old=m['level'];m['level']='M3';m['previous_revision']=m['revision'];m['revision']+=1;m['updated_at']=stamp(now)
                m['retention']['last_transition']={'from':old,'to':'M3','reason':'lifecycle:default@1 inactivity threshold; protections evaluated','at':stamp(now)}
                m['retention']['demotion_count']=m['retention'].get('demotion_count',0)+1
                validate('memory-record',m);c.execute('UPDATE memories SET revision=?,body=? WHERE avatar=? AND id=?',(m['revision'],encode(m),row['avatar'],row['id']))
                self._audit(c,row['avatar'],row['space'],'memory-archived',row['id'],'internal-lifecycle');changed.append(row['avatar'])
            for av in set(changed):self._rebuild_core(c,av)
        return {'archived':len(changed)}
