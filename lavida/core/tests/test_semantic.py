import unittest,json,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import test_service
from aiap_core.semantic import Semantic,ProviderUnavailable
from aiap_core.contracts import Fault

class SemanticTests(unittest.TestCase):
    setUp=test_service.ServiceTests.setUp
    tearDown=test_service.ServiceTests.tearDown
    draft=test_service.ServiceTests.draft
    add=test_service.ServiceTests.add
    fault=test_service.ServiceTests.fault
    def setup_engine(self):
        self.engine=Semantic('http://127.0.0.1:1',['space:work'],dimensions=2)
        self.s.semantic=self.engine;self.sent=[]
        def embed(texts,deadline):
            self.sent.extend(texts)
            return [[1.,0.] if any(w in t for w in ['商务','出差','travel']) else [0.,1.] for t in texts]
        self.engine.embed=embed
    def query(self,q='travel',**kw):
        return self.s.search(self.work,{'space_refs':['space:work'],'purpose':'work-task','query':q,**kw})
    def test_semantic_no_literal_overlap_and_cache(self):
        self.setup_engine();mid=self.add('我出差乘坐商务舱');self.add('pottery')
        r=self.query();self.assertEqual([x['memory_id'] for x in r['items']],[mid]);self.assertEqual(r['retrieval'],'scoped-hybrid-cosine')
        self.sent.clear();self.query();self.assertEqual(len(self.sent),1)
    def test_scope_filter_before_provider(self):
        self.setup_engine();self.add('work travel');self.add('SECRET travel',space='space:life',token=self.life)
        self.query();self.assertNotIn('SECRET',str(self.sent))
    def test_pending_not_sent(self):
        self.setup_engine();self.s.propose(self.work,self.draft('pending travel'));self.add('work travel')
        self.query();self.assertNotIn('pending',str(self.sent))
    def test_unauthorized_no_network(self):
        self.setup_engine();self.add('work travel')
        self.fault('E_DENIED',lambda:self.s.search(self.work,{'space_refs':['space:life'],'purpose':'work-task','query':'travel'}));self.assertEqual(self.sent,[])
    def test_processor_scope_opt_in(self):
        self.setup_engine();self.engine.scopes={'space:general'};self.add('work travel')
        r=self.query();self.assertEqual(self.sent,[]);self.assertEqual(r['semantic_unavailable'],'E_EMBED_SCOPE_NOT_ENABLED')
    def test_provider_failure_explicit_fallback(self):
        self.setup_engine();self.add('work travel')
        def down(*a):raise ProviderUnavailable('E_EMBED_UNAVAILABLE')
        self.engine.embed=down;r=self.query();self.assertTrue(r['degraded']);self.assertEqual(r['retrieval'],'scoped-literal-substring');self.assertEqual(len(r['items']),1)
    def test_revocation_during_embedding_no_result(self):
        self.setup_engine();self.add('work travel');grant=self.s.session(self.work)['auth_evidence_ref']
        original=self.engine.embed
        def revoke(*args):
            r=original(*args);self.s.revoke_grant(grant);return r
        self.engine.embed=revoke;self.fault('E_IDENTITY',lambda:self.query())
    def test_content_change_during_embedding(self):
        self.setup_engine();mid=self.add('work travel');original=self.engine.embed
        def change(*args):
            r=original(*args)
            with self.s.tx() as c:c.execute('DELETE FROM memories WHERE id=?',(mid,))
            return r
        self.engine.embed=change;self.fault('E_SEARCH_STATE_CHANGED',lambda:self.query())
    def test_cache_does_not_resurrect_deleted_memory(self):
        self.setup_engine();mid=self.add('work travel');self.query()
        with self.s.tx() as c:c.execute('DELETE FROM memories WHERE id=?',(mid,))
        self.assertEqual(self.query()['items'],[])
    def test_archived_excluded_before_embedding(self):
        self.setup_engine();mid=self.add('old travel');self.add('new travel')
        with self.s.tx() as c:
            m=json.loads(c.execute('SELECT body FROM memories WHERE id=?',(mid,)).fetchone()[0]);m['level']='M3';c.execute('UPDATE memories SET body=? WHERE id=?',(json.dumps(m),mid))
        self.query();self.assertNotIn('old travel',self.sent)
    def test_literal_priority_and_no_usage_increment(self):
        self.setup_engine();mid=self.add('travel');self.add('出差商务')
        r=self.query(limit=1);self.assertEqual(r['items'][0]['memory_id'],mid);self.assertTrue(r['possibly_more']);self.assertEqual(r['items'][0]['lifecycle']['context_use_count'],0)
    def test_bad_params_denied(self):
        self.setup_engine();self.fault('E_SCHEMA',lambda:self.query(limit=True));self.fault('E_SCHEMA',lambda:self.query(endpoint='http://bad'))

class ProviderTests(unittest.TestCase):
    def test_real_http_transport_validation_and_redirect(self):
        events=[];mode=['ok']
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));events.append((self.path,body,self.headers.get('Authorization')))
                if mode[0]=='redirect':
                    self.send_response(307);self.send_header('Location','http://127.0.0.1:1/leak');self.end_headers();return
                vector=[3,4] if mode[0]=='ok' else [float('nan'),4]
                raw=json.dumps({'model':'qwen3-embedding:0.6b','embeddings':[vector]}).encode();self.send_response(200);self.end_headers();self.wfile.write(raw)
        http=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
        try:
            e=Semantic('http://127.0.0.1:'+str(http.server_port),['space:work'],dimensions=2)
            self.assertEqual(e.embed(['text'],time.monotonic()+5),[[.6,.8]])
            self.assertEqual(events[0][0],'/api/embed');self.assertFalse(events[0][1]['truncate']);self.assertIsNone(events[0][2])
            for value in ['nan','redirect']:
                mode[0]=value
                with self.assertRaises(ProviderUnavailable):e.embed(['text'],time.monotonic()+5)
        finally:http.shutdown();http.server_close()
