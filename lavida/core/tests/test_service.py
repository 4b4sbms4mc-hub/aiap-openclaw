import unittest,tempfile,json,copy,threading,concurrent.futures,urllib.request,urllib.error,sqlite3
from pathlib import Path
from datetime import datetime,timezone,timedelta
from aiap_core.service import Service
from aiap_core.client import Client,proposal
from aiap_core.server import Server
from aiap_core.contracts import Fault,validate,canonical

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.now=datetime(2026,9,19,tzinfo=timezone.utc);self.s=Service(self.tmp.name,clock=lambda:self.now);self.s.initialize()
        self.owner=json.loads((Path(self.tmp.name)/'owner-credentials.json').read_text())['token']
        self.work=self.s.issue_grant(['space:work'],'work-task','test-work')['token'];self.life=self.s.issue_grant(['space:life'],'life-task','test-life')['token']
    def tearDown(self):self.tmp.cleanup()
    def draft(self,text='work fact',space='space:work',token=None,**kwargs):return proposal(self.s.session(token or self.work),space,text,**kwargs)
    def add(self,text='work fact',space='space:work',token=None,**kwargs):
        p=self.draft(text,space,token,**kwargs);t=token or self.work;r=self.s.propose(t,p);self.s.decide(self.owner,r['delta_id'],True);return p['bindings'][0]['target_object_id']
    def search(self,token=None,space='space:work',**kwargs):
        t=token or self.work;return self.s.search(t,{'space_refs':[space],'purpose':self.s.session(t)['purpose'],'query':'',**kwargs})['items']
    def fault(self,code,call):
        with self.assertRaises(Fault) as cm:call()
        self.assertEqual(cm.exception.code,code)
    def test_initial_identity_and_signature(self):
        r=self.s.core(self.owner);validate('avatar-core',r['avatar_core']);self.assertTrue(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))
    def test_init_no_overwrite(self):self.fault('E_ALREADY_INITIALIZED',self.s.initialize)
    def test_token_hash_only_in_database(self):
        with sqlite3.connect(self.s.db) as c:rows=str(c.execute('SELECT * FROM grants').fetchall())
        self.assertNotIn(self.owner,rows);self.assertNotIn(self.work,rows)
    def test_untrusted_token(self):self.fault('E_IDENTITY',lambda:self.s.session('x'*43))
    def test_adapter_no_full_core(self):self.fault('E_DENIED',lambda:self.s.core(self.work))
    def test_no_implicit_general(self):self.fault('E_DENIED',lambda:self.search(space='space:general'))
    def test_pending_not_searchable(self):self.s.propose(self.work,self.draft());self.assertEqual(self.search(),[])
    def test_owner_approval_persists(self):self.add();self.assertEqual(self.search()[0]['content'],'work fact')
    def test_inferred_requires_owner(self):
        p=self.draft(source_type='inferred');r=self.s.propose(self.work,p);self.assertEqual(self.search(),[]);self.s.decide(self.owner,r['delta_id'],True);m=self.search()[0];self.assertEqual(m['source']['source_type'],'inferred');self.assertFalse(m['source']['verified'])
    def test_adapter_cannot_approve(self):
        r=self.s.propose(self.work,self.draft());self.fault('E_DENIED',lambda:self.s.decide(self.work,r['delta_id'],True))
    def test_rejection_stays_out(self):
        r=self.s.propose(self.work,self.draft());self.s.decide(self.owner,r['delta_id'],False);self.assertEqual(self.search(),[])
    def test_life_not_in_work(self):
        self.add('private pottery',space='space:life',token=self.life);self.add('public work');self.assertNotIn('pottery',json.dumps(self.search()))
    def test_scope_expansion_denied(self):self.fault('E_DENIED',lambda:self.search(space='space:life'))
    def test_wrong_purpose(self):self.fault('E_DENIED',lambda:self.s.search(self.work,{'space_refs':['space:work'],'purpose':'life-task','query':''}))
    def test_subject_forgery(self):
        p=self.draft();p['request']['authenticated_subject_ref']='aiap-id:someone-else';self.fault('E_IDENTITY',lambda:self.s.propose(self.work,p))
    def test_avatar_forgery(self):
        p=self.draft();p['delta']['avatar_id']='avatar:someone-else';self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_scope_forgery(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['scope']['owner_ref']='org:fake';self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_wrong_policy_version(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['scope']['policy_ref']['version']=9;self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_caller_confirmation_not_accepted(self):
        p=self.draft();p['bindings'][0]['confirmation_ref']='pretend-confirmed';self.fault('E_CONFIRMATION_REQUIRED',lambda:self.s.propose(self.work,p))
    def test_unknown_memory_extension_rejected(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['extensions']={'x-unknown':{'critical':True}};self.fault('E_OPERATION_UNSUPPORTED',lambda:self.s.propose(self.work,p))
    def test_unsupported_identity_delta(self):
        p=self.draft();p['delta']['changes'][0]['domain']='aiap.identity';self.fault('E_OPERATION_UNSUPPORTED',lambda:self.s.propose(self.work,p))
    def test_no_outbound_embedding_authorization(self):
        p=self.draft();p['request']['processor_refs']=['ollama'];self.fault('E_DENIED',lambda:self.s.propose(self.work,p))
    def test_duplicate_proposal_idempotent(self):
        p=self.draft();self.s.propose(self.work,p);self.assertTrue(self.s.propose(self.work,p)['idempotent'])
    def test_same_id_different_body(self):
        p=self.draft();self.s.propose(self.work,p);p['delta']['changes'][0]['candidate']['content']='changed';self.fault('E_IDEMPOTENCY_CONFLICT',lambda:self.s.propose(self.work,p))
    def test_double_approve_idempotent(self):
        p=self.draft();r=self.s.propose(self.work,p);self.s.decide(self.owner,r['delta_id'],True);self.assertTrue(self.s.decide(self.owner,r['delta_id'],True)['idempotent']);self.assertEqual(self.search()[0]['revision'],1)
    def test_stale_proposal(self):
        self.add();old=self.search()[0];a=self.draft('first',old=old);b=self.draft('second',old=old)
        self.s.propose(self.work,a);self.s.propose(self.work,b);self.s.decide(self.owner,a['delta']['delta_id'],True)
        self.fault('E_VERSION_CONFLICT',lambda:self.s.decide(self.owner,b['delta']['delta_id'],True));self.assertEqual(self.search()[0]['content'],'first')
    def test_concurrent_compare_and_swap(self):
        self.add();old=self.search()[0];drafts=[self.draft(x,old=old) for x in ['A','B']]
        for p in drafts:self.s.propose(self.work,p)
        def decide(p):
            try:return self.s.decide(self.owner,p['delta']['delta_id'],True)['status']
            except Fault as e:return e.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(decide,drafts))
        self.assertCountEqual(results,['accepted','E_VERSION_CONFLICT']);self.assertEqual(self.search()[0]['revision'],2)
    def test_multiple_changes_atomic(self):
        self.add('one');self.add('two');one,two=self.search();a=self.draft('new one',old=one);b=self.draft('new two',old=two)
        a['delta']['changes']+=b['delta']['changes'];a['bindings']+=b['bindings'];self.s.propose(self.work,a)
        c=self.draft('competing two',old=two);self.s.propose(self.work,c);self.s.decide(self.owner,c['delta']['delta_id'],True)
        self.fault('E_VERSION_CONFLICT',lambda:self.s.decide(self.owner,a['delta']['delta_id'],True));by={m['memory_id']:m for m in self.search()};self.assertEqual(by[one['memory_id']]['revision'],1)
    def test_revocation_blocks_new_read(self):
        g=self.s.session(self.work)['auth_evidence_ref'];self.s.revoke_grant(g);self.fault('E_IDENTITY',lambda:self.s.session(self.work))
    def test_revocation_blocks_pending_approval(self):
        r=self.s.propose(self.work,self.draft());self.s.revoke_grant(self.s.session(self.work)['auth_evidence_ref']);self.fault('E_IDENTITY',lambda:self.s.decide(self.owner,r['delta_id'],True))
    def test_expiry(self):self.now+=timedelta(days=8);self.fault('E_IDENTITY',lambda:self.s.session(self.work))
    def test_restart_persists_identity_and_record(self):
        self.add();av=self.s.session(self.owner)['avatar_id'];self.s=Service(self.tmp.name,clock=lambda:self.now);self.assertEqual(self.s.session(self.owner)['avatar_id'],av);self.assertEqual(len(self.search()),1)
    def test_deleted_id_cannot_resurrect(self):
        mid=self.add();self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1});self.assertEqual(self.search(),[]);self.fault('E_DENIED',lambda:self.s.propose(self.work,self.draft(memory_id=mid)))
    def test_deleted_pending_invalidated(self):
        mid=self.add();p=self.draft(old=self.search()[0]);r=self.s.propose(self.work,p);self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1});self.assertEqual(self.s.review(self.owner,r['delta_id'])['status'],'invalidated')
    def test_delete_body_removed_from_live_rows(self):
        mid=self.add('UNIQUE_DELETE_BODY');self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1})
        with sqlite3.connect(self.s.db) as c:
            allrows=''.join(str(c.execute('SELECT * FROM '+t).fetchall()) for t in ['memories','history','deltas','audit','cores','tombstones'])
        self.assertNotIn('UNIQUE_DELETE_BODY',allrows)
    def test_archive_ordinary_but_protect_pinned(self):
        self.add('ordinary');self.add('pinned',pinned=True);self.now+=timedelta(days=181);self.assertEqual(self.s.archive_cycle()['archived'],1)
        t=self.s.issue_grant(['space:work'],'work-task','test-work')['token'];ms=self.search(token=t,include_archived=True);self.assertEqual({m['content']:m['level'] for m in ms},{'ordinary':'M3','pinned':'M2'})
    def test_recurrence_protected(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['lifecycle']['recurrence_ref']='annual:review';r=self.s.propose(self.work,p);self.s.decide(self.owner,r['delta_id'],True);self.now+=timedelta(days=400);self.assertEqual(self.s.archive_cycle()['archived'],0)
    def test_search_not_counted_as_use(self):self.add();self.search();self.assertIsNone(self.search()[0]['lifecycle']['last_used_at'])
    def context(self):return self.s.search(self.work,{'space_refs':['space:work'],'purpose':'work-task','query':''},context=True)
    def test_context_ack_once(self):
        self.add();v=self.context()['authorized_view'];self.s.acknowledge(self.work,{'view_id':v['view_id']});self.assertTrue(self.s.acknowledge(self.work,{'view_id':v['view_id']})['idempotent']);self.assertEqual(self.search()[0]['lifecycle']['context_use_count'],1)
    def test_ack_requires_same_grant(self):
        self.add();v=self.context()['authorized_view'];self.fault('E_NOT_FOUND',lambda:self.s.acknowledge(self.owner,{'view_id':v['view_id']}))
    def test_expired_view(self):
        self.add();v=self.context()['authorized_view'];self.now+=timedelta(minutes=6);self.fault('E_EXPIRED',lambda:self.s.acknowledge(self.work,{'view_id':v['view_id']}))
    def test_context_no_life_leak(self):
        self.add('private!',space='space:life',token=self.life);self.add('work');v=self.context();self.assertNotIn('private!',json.dumps(v));validate('authorized-view',v['authorized_view'])
    def test_update_preserves_previous_version(self):
        self.add('previous');old=self.search()[0];p=self.draft('current',old=old);self.s.propose(self.work,p);self.s.decide(self.owner,p['delta']['delta_id'],True)
        with sqlite3.connect(self.s.db) as c:prior=json.loads(c.execute('SELECT body FROM history WHERE id=?',(old['memory_id'],)).fetchone()[0])
        self.assertEqual(prior['content'],'previous');self.assertEqual(prior['revision'],1)
    def test_local_signature_detects_tamper(self):
        r=self.s.core(self.owner);r['avatar_core']['owner']['owner_ref']='attacker';self.assertFalse(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))
    def test_unknown_local_crypto_profile_rejected(self):
        r=self.s.core(self.owner);r['avatar_core']['integrity']['proofs'][0]['crypto_profile']='unknown';self.assertFalse(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))
    def test_database_core_tamper_fails(self):
        with sqlite3.connect(self.s.db) as c:
            raw=json.loads(c.execute('SELECT body FROM cores').fetchone()[0]);raw['avatar_id']='attacker';c.execute('UPDATE cores SET body=?',(json.dumps(raw),))
        self.fault('E_INTEGRITY',lambda:self.s.core(self.owner))

class HTTPTests(ServiceTests):
    # Reuse fixtures, but do not duplicate inherited service tests.
    def setUp(self):
        ServiceTests.setUp(self);self.http=Server(('127.0.0.1',0),self.s);self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start();self.base='http://127.0.0.1:'+str(self.http.server_port);self.client=Client(self.base,self.work)
    def tearDown(self):self.http.shutdown();self.http.server_close();self.thread.join();ServiceTests.tearDown(self)
    def test_http_real_save_review_approve_read(self):
        p=proposal(self.client.call('/v1/session'),'space:work','HTTP memory');r=self.client.call('/v1/deltas/propose',p)
        with self.assertRaisesRegex(RuntimeError,'403'):self.client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
        owner=Client(self.base,self.owner);self.assertEqual(owner.call('/v1/deltas/review',{'delta_id':r['delta_id']})['status'],'proposed');owner.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
        self.assertEqual(self.client.call('/v1/search',{'space_refs':['space:work'],'purpose':'work-task','query':'HTTP'})['count'],1)
    def test_http_cross_scope_denied(self):
        with self.assertRaisesRegex(RuntimeError,'403'):self.client.call('/v1/search',{'space_refs':['space:life'],'purpose':'work-task','query':''})
    def test_http_no_token(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(self.base+'/v1/core')
        self.assertEqual(cm.exception.code,401)
    def test_http_duplicate_json_rejected(self):
        req=urllib.request.Request(self.base+'/v1/search',data=b'{"query":"a","query":"b"}',headers={'Authorization':'Bearer '+self.work,'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code,400)
    def test_http_origin_rejected(self):
        req=urllib.request.Request(self.base+'/v1/session',headers={'Authorization':'Bearer '+self.work,'Origin':'https://example.invalid'})
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code,403)
    def test_http_no_store(self):
        req=urllib.request.Request(self.base+'/v1/session',headers={'Authorization':'Bearer '+self.work})
        with urllib.request.urlopen(req) as r:self.assertEqual(r.headers['Cache-Control'],'no-store')
# unittest would otherwise run every inherited method twice. Keep only HTTP tests on this class.
for name in list(ServiceTests.__dict__):
    if name.startswith('test_'):setattr(HTTPTests,name,None)
if __name__=='__main__':unittest.main()
