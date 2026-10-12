import tempfile, pathlib, json, sys, os
from aiap_core.service import Service, save_private
from aiap_core.client import proposal
from aiap_core.contracts import canonical
from aiap_core.server import Server
with tempfile.TemporaryDirectory() as tmp:
    p=pathlib.Path(tmp);s=Service(p);s.initialize()
    owner=json.loads((p/'owner-credentials.json').read_text())
    for space,text in [('space:work','BUSINESS_CLASS work preference'),('space:life','ECONOMY_CLASS private preference')]:
        q=proposal(s.session(owner['token']),space,text)
        d=s.propose(owner['token'],q);s.decide(owner['token'],d['delta_id'],True)
    for name,space in [('work','space:work'),('life','space:life'),('general','space:general')]:
        c=s.issue_grant([space],'lavida-memory','openclaw-'+name,'adapter',7)
        save_private(p/(name+'.json'),canonical(c))
    multi=s.issue_grant(['space:life','space:work'],'lavida-memory','openclaw-work','adapter',7)
    save_private(p/'multi.json',canonical(multi))
    if os.environ.get('AIAP_TEST_SEMANTIC'):
        from aiap_core.semantic import Semantic, ProviderUnavailable
        engine=Semantic('http://127.0.0.1:1', ['space:work','space:life'])
        def embed(texts, deadline):
            if any('PROVIDER_FAIL' in t for t in texts):raise ProviderUnavailable('E_EMBED_UNAVAILABLE')
            return [[1.0]+[0.0]*1023 for t in texts]
        engine.embed=embed;s.semantic=engine
    server=Server(('127.0.0.1',0),s)
    print(json.dumps({'directory':str(p),'baseUrl':'http://127.0.0.1:'+str(server.server_port),'avatarId':owner['avatar_id']}),flush=True)
    server.serve_forever()
