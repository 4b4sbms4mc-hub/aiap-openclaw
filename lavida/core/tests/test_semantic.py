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
    def test_owner_preference_search_authorizes_before_embedding_and_on_fallback(self):
        self.setup_engine()
        def evidence(text, sid='space:work', token=None):
            env = self.draft(text, space=sid, token=token, level='M1', source_type='observed')
            candidate = env['delta']['changes'][0]['candidate']
            candidate['type'] = 'preference-evidence'
            self.s.decide(self.owner, self.s.propose(token or self.work, env)['delta_id'], True)
            return candidate['memory_id']
        first = evidence('我出差时希望提前订票')
        opposite = evidence('这次出差希望晚些订票')
        evidence('life travel private', 'space:life', self.life)
        self.add('work travel fact', level='M1')
        self.add('travel standing instruction')
        def lookup(token, query):
            return self.s.find_preference_evidence(token, 'space:work', query)
        before = self.s.db.read_bytes()
        self.fault('E_DENIED', lambda: lookup(self.work, 'travel'))
        self.assertFalse(self.sent)
        result = lookup(self.owner, 'travel')
        self.assertEqual({m['memory_id'] for m in result['items']}, {first, opposite})
        self.assertEqual(set(self.sent[1:]), {'我出差时希望提前订票', '这次出差希望晚些订票'})
        self.assertEqual(result['retrieval_reason'], 'hybrid-ranked')
        self.assertEqual([item['match_ranks'] for item in result['items']], [{'semantic': 1}, {'semantic': 2}])
        both = lookup(self.owner, '出差')
        self.assertTrue(all(set(item['match_ranks']) == {'semantic', 'lexical'} for item in both['items']))
        def unavailable(*args):
            raise ProviderUnavailable('E_EMBED_UNAVAILABLE')
        self.engine.embed = unavailable
        fallback = lookup(self.owner, '出差')
        self.assertTrue(fallback['degraded'])
        self.assertEqual([m['match_ranks'] for m in fallback['items']], [{'lexical': 1}, {'lexical': 2}])
        self.assertEqual({m['memory_id'] for m in fallback['items']}, {first, opposite})
        self.assertFalse(lookup(self.owner, 'travel')['items'])
        self.s.semantic = None
        self.assertEqual(lookup(self.owner, '出差')['retrieval_reason'], 'embedding-not-configured')
        self.assertEqual(before, self.s.db.read_bytes())

    def test_disabling_embedding_scope_during_evidence_query_stops_delivery(self):
        self.setup_engine()
        env = self.draft('Private source text', level='M1', source_type='observed')
        env['delta']['changes'][0]['candidate']['type'] = 'preference-evidence'
        self.s.decide(self.owner, self.s.propose(self.work, env)['delta_id'], True)
        def disable(texts, deadline):
            self.sent.extend(texts)
            self.engine.scopes.clear()
            return [[1., 0.] for _ in texts]
        self.engine.embed = disable
        self.fault('E_SEARCH_STATE_CHANGED', lambda: self.s.find_preference_evidence(
            self.owner, 'space:work', 'release'))
        self.assertEqual(len(self.sent), 1)
        self.assertNotIn('Private source text', self.sent)
        # The next request uses scoped lexical fallback.
        result = self.s.find_preference_evidence(self.owner, 'space:work', 'source')
        self.assertEqual(result['retrieval_reason'], 'scope-not-enabled')
        self.assertEqual(result['items'][0]['match_ranks'], {'lexical': 1})

    def test_project_semantic_recall_across_200_record_boundary(self):
        import copy
        self.setup_engine()
        space = self.s.create_project_space('expense-review')['space_ref']
        token = self.s.issue_grant([space], 'expenses', 'project')['token']
        self.s.semantic = Semantic('http://127.0.0.1:1', [space], dimensions=2)
        self.s.semantic.embed = lambda texts, deadline: self.engine.embed(
            [t.replace('商旅交通', 'travel') for t in texts], deadline)
        self.owner = self.s.issue_grant([space], 'project-review', 'owner', role='owner')['token']
        target = self.add('我出差乘坐商务舱', space=space, token=token)
        request = {'space_refs':[space], 'purpose':'expenses', 'query':'商旅交通', 'limit':20}
        avatar = self.s.session(token)['avatar_id']
        seed = self.s.memory_for_update(token, space, target, 1)
        for start, end in [(0, 199), (199, 200), (200, 999)]:
            with self.s.tx() as c:
                for k in range(start, end):
                    m = copy.deepcopy(seed)
                    m.update(memory_id=f'mem:fixture-{k}', content=f'陶器编号{k}')
                    c.execute('INSERT INTO memories VALUES(?,?,?,?,?)',
                              (avatar, m['memory_id'], space, 1, json.dumps(m)))
            result = self.s.search(token, request)
            self.assertFalse(result['degraded'])
            self.assertEqual(result['fusion'], 'reciprocal-rank')
            self.assertEqual([r['memory_id'] for r in result['items']], [target])
        self.fault('E_EMBED_CONFIG', lambda: Semantic('http://localhost', ['space:project:*']))

    def test_fusion_can_recall_partial_terms_below_vector_threshold(self):
        self.setup_engine()
        sem = self.add('出差乘坐商务舱')
        lex = self.add('Project ORCHARD schedule')
        self.add('unrelated record')
        r = self.query('ORCHARD travel')
        self.assertEqual({i['memory_id'] for i in r['items']}, {sem, lex})
        self.assertEqual(r['lexical_retrieval'], 'scoped-offline-bm25')

    def test_retrieval_diagnostics(self):
        self.assertEqual(self.query()['retrieval_reason'], 'embedding-not-configured')
        self.setup_engine()
        self.assertEqual(self.query()['retrieval_reason'], 'no-eligible-records')
        self.add('我出差乘坐商务舱')
        self.assertEqual(self.query('')['retrieval_reason'], 'empty-query')
        self.assertFalse(self.sent)
        self.assertEqual(self.query()['retrieval_reason'], 'hybrid-ranked')
        self.assertTrue(any('travel' in text for text in self.sent))
        self.engine.scopes.clear()
        self.assertEqual(self.query()['retrieval_reason'], 'scope-not-enabled')

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
        self.engine.embed=down;r=self.query();self.assertTrue(r['degraded']);self.assertEqual(r['retrieval_reason'],'embedding-unavailable');self.assertEqual(r['retrieval'],'scoped-offline-bm25');self.assertEqual(len(r['items']),1)
    def test_revocation_during_embedding_no_result(self):
        self.setup_engine();self.add('work travel');grant=self.s.session(self.work)['auth_evidence_ref']
        original=self.engine.embed
        def revoke(*args):
            r=original(*args);self.s.revoke_grant(grant);return r
        self.engine.embed=revoke;self.fault('E_IDENTITY',lambda:self.query())
    def test_expiry_during_embedding_rechecks_before_sending_record(self):
        from datetime import timedelta
        self.setup_engine()
        ident = self.add('work travel')
        deadline = self.now + timedelta(seconds=1)
        self.s.set_memory_validity(self.owner, 'space:work', ident, 1, expires_at=deadline.isoformat())
        original = self.engine.embed
        def advance(texts, timeout):
            result = original(texts, timeout)
            self.now = deadline
            return result
        self.engine.embed = advance
        self.fault('E_SEARCH_STATE_CHANGED', self.query)
        self.assertNotIn('work travel', self.sent)
        self.assertEqual(self.query()['items'], [])

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
    def test_task_only_recall_filters_before_embedding_and_during_fallback(self):
        self.setup_engine()
        task = self.add('travel task', level='M1')
        self.add('travel preference', level='M2')
        result = self.query(level='M1', limit=1)
        self.assertEqual([item['memory_id'] for item in result['items']], [task])
        self.assertNotIn('travel preference', self.sent)

        def unavailable(*args):
            raise ProviderUnavailable('E_EMBED_UNAVAILABLE')
        self.engine.embed = unavailable
        result = self.query(level='M1')
        self.assertTrue(result['degraded'])
        self.assertEqual([item['memory_id'] for item in result['items']], [task])
        self.fault('E_SCHEMA', lambda: self.query(level='M3'))
        self.fault('E_SCHEMA', lambda: self.query(level=None))

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
    def test_openai_embedding_reorders_by_index_and_rejects_duplicates(self):
        requests = []
        indices = [1, 0]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append((self.path, body))
                raw = json.dumps({'model': 'fixture-embed', 'data': [
                    {'index': index, 'embedding': vector}
                    for index, vector in zip(indices, [[0, 3], [2, 0]])
                ]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

        http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            engine = Semantic(f'http://127.0.0.1:{http.server_port}', ['space:work'],
                              'fixture-embed', dimensions=2, provider='openai')
            self.assertEqual(engine.embed(['one', 'two'], time.monotonic() + 5), [[1, 0], [0, 1]])
            self.assertEqual(requests[0], ('/v1/embeddings', {
                'model': 'fixture-embed', 'input': ['one', 'two'], 'encoding_format': 'float',
            }))
            indices[:] = [0, 0]
            with self.assertRaises(ProviderUnavailable):
                engine.embed(['one', 'two'], time.monotonic() + 5)
        finally:
            http.shutdown()
            http.server_close()

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
