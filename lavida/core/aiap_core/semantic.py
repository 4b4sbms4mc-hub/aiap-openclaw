"""Opt-in scoped embedding retrieval. Wang Lu. No persistent vector index."""
import json, math, os, re, time, threading, urllib.request, urllib.parse
from collections import OrderedDict
from . import lexical
from .contracts import Fault, require, digest, search_levels

class ProviderUnavailable(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ProviderUnavailable('E_EMBED_REDIRECT')

class VectorRanker:
    def __init__(self, scopes):
        require(isinstance(scopes, (tuple, list, set, frozenset)) and scopes and all(
            isinstance(scope, str) and (scope in ('space:general', 'space:life', 'space:work')
            or re.fullmatch(r'space:project:[a-z0-9][a-z0-9-]{0,62}', scope)) for scope in scopes
        ), 'E_EMBED_CONFIG')
        self.scopes = set(scopes)
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)

    def rank(self, query, records, namespace, guard, depth):
        if any(len(m['content']) > 16000 for m in records):
            raise ProviderUnavailable('E_EMBED_LIMIT')
        if not self.slots.acquire(blocking=False):
            raise ProviderUnavailable('E_EMBED_BUSY')
        try:
            deadline = time.monotonic() + 100
            prefix = (namespace, self.provider, self.model_key, self.model, self.dimensions)
            with self.lock:
                for key in list(self.cache):
                    if self.cache[key][0] < time.monotonic():
                        del self.cache[key]
            prompt = query
            if self.provider == 'ollama' or (self.provider == 'openai' and 'qwen3-embedding' in self.model.lower()):
                prompt = 'Instruct: Retrieve personal memories relevant to the question.\nQuery:' + query
            guard([])
            query_vector = self.embed([prompt], deadline)[0]
            ranked = []
            for start in range(0, len(records), 8):
                batch = records[start:start + 8]
                keys = [(*prefix, m['memory_id'], m['revision'], digest(m)) for m in batch]
                vectors = {}
                with self.lock:
                    for key in keys:
                        if key in self.cache:
                            vectors[key] = self.cache[key][1]
                            self.cache.move_to_end(key)
                missing = [(key, m) for key, m in zip(keys, batch) if key not in vectors]
                if missing:
                    outbound = [m for _, m in missing]
                    guard(outbound)
                    embedded = self.embed([m['content'] for m in outbound], deadline)
                    guard(outbound)
                    with self.lock:
                        for (key, _), vector in zip(missing, embedded):
                            self.cache[key] = (time.monotonic() + 300, vector)
                            vectors[key] = vector
                        while len(self.cache) > 2048:
                            self.cache.popitem(last=False)
                for key, record in zip(keys, batch):
                    score = sum(a*b for a, b in zip(query_vector, vectors[key]))
                    if score >= 0.5:
                        ranked.append((score, record))
                if len(ranked) > depth:
                    ranked.sort(key=lambda pair: (-pair[0], pair[1]['memory_id']))
                    del ranked[depth:]
            ranked.sort(key=lambda pair: (-pair[0], pair[1]['memory_id']))
            return [record for _, record in ranked]
        finally:
            self.slots.release()


def fuse(records, query, semantic, depth, *, match_ranks=None):
    words, _, lexical_method = lexical.rank(records, query, depth)
    scores, candidates = {}, {}
    for channel, ranking in (('semantic', semantic[:depth]), ('lexical', words)):
        for position, record in enumerate(ranking, 1):
            ident = record['memory_id']
            if match_ranks is not None:
                match_ranks.setdefault(ident, {})[channel] = position
            scores[ident] = scores.get(ident, 0) + 1 / (60 + position)
            candidates[ident] = record
    needle = query.casefold()
    return sorted(candidates.values(), key=lambda m: (
        needle not in m['content'].casefold(), -scores[m['memory_id']], m['memory_id'])), lexical_method


class Semantic(VectorRanker):
    def __init__(self, endpoint, scopes, model='qwen3-embedding:0.6b', dimensions=1024, *, provider='ollama'):
        u=urllib.parse.urlsplit(endpoint)
        require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ('','/'), 'E_EMBED_CONFIG')
        super().__init__(scopes)
        require(provider in ('ollama', 'openai') and isinstance(model, str) and 0 < len(model.strip()) <= 200
                and type(dimensions) is int and 1 <= dimensions <= 4096, 'E_EMBED_CONFIG')
        self.endpoint = self.model_key = endpoint.rstrip('/')
        self.model = model
        self.dimensions = dimensions
        self.provider = provider
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    @classmethod
    def from_environment(cls):
        endpoint=os.environ.get('AIAP_EMBED_URL')
        language = os.environ.get('AIAP_SYSTEM_EMBED_LANG')
        if language and not endpoint:
            from .system_embedding import SystemEmbedding
            return SystemEmbedding(language, os.environ.get('AIAP_EMBED_SPACES', '').split(','))
        if not endpoint:return None
        return cls(endpoint,os.environ.get('AIAP_EMBED_SPACES','').split(','))
    def embed(self,texts,deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ProviderUnavailable('E_EMBED_TIMEOUT')
        payload = {'model': self.model, 'input': texts}
        if self.provider == 'ollama':
            path = '/api/embed'
            payload['truncate'] = False
        else:
            path = '/v1/embeddings'
            payload['encoding_format'] = 'float'
        req=urllib.request.Request(self.endpoint+path,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        try:
            with self.opener.open(req,timeout=min(remaining,90)) as r:
                raw=r.read(2_000_001)
                if len(raw)>2_000_000:raise ValueError('size')
                data=json.loads(raw)
            if time.monotonic()>deadline:raise ValueError('deadline')
            if data.get('model')!=self.model:raise ValueError('model')
            if self.provider == 'ollama':
                vectors = data['embeddings']
            else:
                entries = data['data']
                indices = [entry['index'] for entry in entries]
                if any(type(index) is not int for index in indices) or sorted(indices) != list(range(len(texts))):
                    raise ValueError('index')
                vectors = [entry['embedding'] for entry in sorted(entries, key=lambda entry: entry['index'])]
            if len(vectors)!=len(texts):raise ValueError('count')
            out=[]
            for v in vectors:
                if len(v)!=self.dimensions or any(type(x) not in (int,float) or not math.isfinite(x) for x in v):raise ValueError('vector')
                norm=math.sqrt(sum(x*x for x in v))
                if not math.isfinite(norm) or norm<=0:raise ValueError('norm')
                out.append([x/norm for x in v])
            return out
        except ProviderUnavailable:raise
        except Exception:raise ProviderUnavailable('E_EMBED_UNAVAILABLE') from None

def semantic_search(service,token,body, *, preference_evidence=False):
    """Authorize before embedding; recheck grant, epoch and full scoped snapshot after I/O."""
    levels = search_levels(body)
    limit = body.get('limit', 20)
    scopes=body['space_refs']
    def snapshot(batch=None):
        with service.tx(read_only=True) as c:
            g=service._grant(c,token);service._allow(g,scopes,'read',body['purpose'],owner=preference_evidence)
            policies=[service._scope(c,g,s) for s in scopes]
            epoch=service.meta(c,'revocation_epoch')
            sql = 'SELECT body FROM memories WHERE avatar=? AND space IN (' + ','.join('?' for _ in scopes) + ')'
            if preference_evidence:
                sql += """ AND json_extract(body, '$.type')='preference-evidence'
                    AND json_extract(body, '$.level')='M1'
                    AND json_extract(body, '$.source.source_type') IN ('observed','explicit-user')"""
            params = [g['avatar'], *scopes]
            if batch is not None:
                ids = [m['memory_id'] for m in batch]
                sql += ' AND id IN (' + (','.join('?' for _ in ids) or 'NULL') + ')'
                params.extend(ids)
            rows = c.execute(sql + ' ORDER BY id', params)
            records=[]
            for row in rows:
                m=json.loads(row[0])
                if service.current_memory(m) and m['level'] in levels and m['scope'] in policies:records.append(m)
            namespace=(g['avatar'],g['subject'],g['id'],g['purpose'],g['runtime'],epoch,digest(policies))
            return namespace,records
    namespace,records=snapshot()
    engine=service.semantic
    def literal_result():
        if not preference_evidence:
            return service._literal_search(token, body)
        ranked, more, method = lexical.rank(records, body['query'], limit)
        latest_namespace, latest = snapshot()
        require(namespace == latest_namespace and digest(records) == digest(latest), 'E_SEARCH_STATE_CHANGED', 409)
        ranked = [dict(record, match_ranks={'lexical': i}) for i, record in enumerate(ranked, 1)]
        return {'items': ranked, 'count': len(ranked), 'possibly_more': more,
                'retrieval': method, 'space_refs': scopes}

    enabled = engine is not None and set(scopes) <= engine.scopes
    if not body['query'].strip() or not records or not enabled:
        result = literal_result()
        result['semantic_enabled'] = enabled
        result['degraded'] = False
        if engine is None:
            result['retrieval_reason'] = 'embedding-not-configured'
        elif not result['semantic_enabled']:
            result['semantic_unavailable'] = 'E_EMBED_SCOPE_NOT_ENABLED'
            result['retrieval_reason'] = 'scope-not-enabled'
        elif not body['query'].strip():
            result['retrieval_reason'] = 'empty-query'
        else:
            result['retrieval_reason'] = 'no-eligible-records'
        return result
    signature=digest(records)
    def guard(batch=None):
        require(service.semantic is engine and set(scopes) <= engine.scopes, 'E_SEARCH_STATE_CHANGED', 409)
        current,objects=snapshot(batch)
        expected = signature if batch is None else digest(batch)
        require(current==namespace and digest(objects)==expected,'E_SEARCH_STATE_CHANGED',409)
    try:
        depth = max(60, limit + 1)
        semantic = engine.rank(body['query'], records, namespace, guard, depth)
        match_ranks = {} if preference_evidence else None
        ranked, lexical_method = fuse(records, body['query'], semantic, depth, match_ranks=match_ranks)
    except ProviderUnavailable as e:
        require(service.semantic is engine and set(scopes) <= engine.scopes, 'E_SEARCH_STATE_CHANGED', 409)
        result=literal_result()
        result.update(semantic_enabled=True,degraded=True,retrieval_reason="embedding-unavailable",semantic_unavailable=str(e))
        if setup := getattr(engine, 'setup', None):
            result['embedding_setup'] = setup()
        return result
    guard()
    items = ranked[:limit]
    if preference_evidence:
        items = [dict(record, match_ranks=match_ranks[record['memory_id']]) for record in items]
    return {'items':items,'count':len(items),'possibly_more':len(ranked)>limit,'retrieval':'scoped-hybrid-cosine','retrieval_reason':'hybrid-ranked','space_refs':scopes,'semantic_enabled':True,'degraded':False,'embedding_model':engine.model,
            'fusion':'reciprocal-rank','lexical_retrieval':lexical_method}
