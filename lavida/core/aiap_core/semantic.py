"""Opt-in local Ollama retrieval. Wang Lu. No persistent vector index."""
import json, math, os, time, threading, urllib.request, urllib.parse
from collections import OrderedDict
from .contracts import Fault, require, digest

class ProviderUnavailable(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ProviderUnavailable('E_EMBED_REDIRECT')

class Semantic:
    def __init__(self, endpoint, scopes, model='qwen3-embedding:0.6b', dimensions=1024):
        u=urllib.parse.urlsplit(endpoint)
        require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ('','/'), 'E_EMBED_CONFIG')
        require(scopes and set(scopes)<= {'space:general','space:life','space:work'}, 'E_EMBED_CONFIG')
        self.endpoint=endpoint.rstrip('/'); self.scopes=set(scopes); self.model=model; self.dimensions=dimensions
        self.cache=OrderedDict(); self.lock=threading.Lock(); self.slots=threading.BoundedSemaphore(2)
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    @classmethod
    def from_environment(cls):
        endpoint=os.environ.get('AIAP_EMBED_URL')
        if not endpoint:return None
        return cls(endpoint,os.environ.get('AIAP_EMBED_SPACES','').split(','))
    def embed(self,texts,deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ProviderUnavailable('E_EMBED_TIMEOUT')
        req=urllib.request.Request(self.endpoint+'/api/embed',data=json.dumps({'model':self.model,'input':texts,'truncate':False}).encode(),headers={'Content-Type':'application/json'},method='POST')
        try:
            with self.opener.open(req,timeout=min(remaining,90)) as r:
                raw=r.read(2_000_001)
                if len(raw)>2_000_000:raise ValueError('size')
                data=json.loads(raw)
            if time.monotonic()>deadline:raise ValueError('deadline')
            vectors=data['embeddings']
            if data.get('model')!=self.model or len(vectors)!=len(texts):raise ValueError('model/count')
            out=[]
            for v in vectors:
                if len(v)!=self.dimensions or any(type(x) not in (int,float) or not math.isfinite(x) for x in v):raise ValueError('vector')
                norm=math.sqrt(sum(x*x for x in v))
                if not math.isfinite(norm) or norm<=0:raise ValueError('norm')
                out.append([x/norm for x in v])
            return out
        except ProviderUnavailable:raise
        except Exception:raise ProviderUnavailable('E_EMBED_UNAVAILABLE') from None
    def rank(self,query,records,namespace,guard):
        if len(records)>200 or any(len(m['content'])>16000 for m in records):raise ProviderUnavailable('E_EMBED_LIMIT')
        if not self.slots.acquire(blocking=False):raise ProviderUnavailable('E_EMBED_BUSY')
        try:
            deadline=time.monotonic()+100
            keys=[(namespace,self.endpoint,self.model,self.dimensions,m['memory_id'],m['revision'],digest(m)) for m in records]
            vectors={}; missing=[]
            with self.lock:
                for k in list(self.cache):
                    if self.cache[k][0]<time.monotonic():del self.cache[k]
                for i,k in enumerate(keys):
                    if k in self.cache:
                        vectors[i]=self.cache[k][1]; self.cache.move_to_end(k)
                    else:missing.append(i)
            prompt='Instruct: Retrieve personal memories relevant to the question.\nQuery:'+query
            guard()
            qv=self.embed([prompt],deadline)[0]
            for start in range(0,len(missing),8):
                indices=missing[start:start+8]
                guard()
                batch=self.embed([records[i]['content'] for i in indices],deadline)
                guard()
                with self.lock:
                    for i,v in zip(indices,batch):
                        vectors[i]=v; self.cache[keys[i]]=(time.monotonic()+300,v)
                    while len(self.cache)>2048:self.cache.popitem(last=False)
            ranked=[]
            for i,m in enumerate(records):
                score=sum(a*b for a,b in zip(qv,vectors[i])); literal=query.casefold() in m['content'].casefold()
                if literal or score>=0.5:ranked.append((literal,score,m))
            ranked.sort(key=lambda x:(-int(x[0]),-x[1],x[2]['memory_id']))
            return [m for _,_,m in ranked]
        finally:self.slots.release()

def semantic_search(service,token,body):
    """Authorize before embedding; recheck grant, epoch and full scoped snapshot after I/O."""
    from .contracts import exact
    exact(body,['space_refs','purpose','query'],['include_archived','limit'])
    require(isinstance(body['query'],str) and len(body['query'])<=1000)
    limit=body.get('limit',20);require(type(limit) is int and 1<=limit<=100)
    include=body.get('include_archived',False);require(type(include) is bool)
    scopes=body['space_refs']
    def snapshot():
        with service.tx() as c:
            g=service._grant(c,token);service._allow(g,scopes,'read',body['purpose'])
            policies=[service._scope(c,g,s) for s in scopes]
            epoch=service.meta(c,'revocation_epoch')
            rows=c.execute('SELECT body FROM memories WHERE avatar=? AND space IN ('+','.join('?' for _ in scopes)+') ORDER BY id',(g['avatar'],*scopes))
            records=[]
            for row in rows:
                m=json.loads(row[0])
                if m['status']=='active' and (include or m['level']!='M3') and m['scope'] in policies:records.append(m)
            namespace=(g['avatar'],g['subject'],g['id'],g['purpose'],g['runtime'],epoch,digest(policies))
            return namespace,records
    namespace,records=snapshot()
    engine=service.semantic
    if not body['query'].strip() or not records or not set(scopes)<=engine.scopes:
        result=service._literal_search(token,body)
        result['semantic_enabled']=set(scopes)<=engine.scopes
        if not set(scopes)<=engine.scopes:result['semantic_unavailable']='E_EMBED_SCOPE_NOT_ENABLED'
        return result
    signature=digest(records)
    def guard():
        current,objects=snapshot()
        require(current==namespace and digest(objects)==signature,'E_SEARCH_STATE_CHANGED',409)
    try:
        ranked=engine.rank(body['query'],records,namespace,guard)
    except ProviderUnavailable as e:
        result=service._literal_search(token,body)
        result.update(semantic_enabled=True,degraded=True,semantic_unavailable=str(e))
        return result
    guard()
    return {'items':ranked[:limit],'count':min(limit,len(ranked)),'possibly_more':len(ranked)>limit,'retrieval':'scoped-hybrid-cosine','space_refs':scopes,'semantic_enabled':True,'degraded':False,'embedding_model':engine.model}
