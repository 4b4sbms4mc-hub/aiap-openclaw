# SPDX-License-Identifier: Apache-2.0
"""Run a synthetic Owner capture check using a stock macOS DSH Desktop host.

Run with PYTHONPATH set to the absolute lavida/core path, or install the Core
wheel first. Requires the supported DeepSeek Harness desktop build.
"""
import argparse
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, Request
from aiap_core.contracts import canonical
from aiap_core.service import Service, save_private

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app', type=Path, default=Path('/Applications/DeepSeek Harness.app'))
parser.add_argument('--plugin', type=Path, default=Path(__file__).resolve().parents[1] / 'aiap-core/dsh-capture')
args = parser.parse_args()
resources = args.app / 'Contents/Resources'
binary = str(resources.parent/'MacOS/DeepSeek Harness')
entry = resources/'app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js'
with tempfile.TemporaryDirectory(prefix='aiap-owner-web.') as name:
    root=Path(name); home=root/'home'
    profile=home/'profiles/web'; profile.mkdir(parents=True)
    shutil.copytree(args.plugin, profile/'node_modules/dsh-aiap-capture')
    db=root/'core'; core=Service(db,enable_semantic=False); core.initialize()
    owner=json.loads((db/'owner-credentials.json').read_text())['token']
    save_private(db/'adapter.json',canonical(core.issue_grant(['space:general'],'fixture','deepseek-harness')))
    model_queries=[]
    class FixtureModel(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            input_=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            model_queries.append(input_.get('messages'))
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream')
            self.end_headers()
            for content,reason in [({'role':'assistant','content':'OK'},None),({},'stop')]:
                event={'id':'chatcmpl-fixture','model':'fixture','object':'chat.completion.chunk',
                       'choices':[{'index':0,'delta':content,'finish_reason':reason}]}
                self.wfile.write(('data: '+json.dumps(event)+'\n\n').encode())
            self.wfile.write(b'data: [DONE]\n\n')
    model=ThreadingHTTPServer(('127.0.0.1',0),FixtureModel)
    threading.Thread(target=model.serve_forever,daemon=True).start()
    def plugin(id__,name_,config):
        return dict(id=id__,name=name_,config=config)
    allowed='session-aiap-owner-fixture'
    patch=[
        plugin('agent-default-model','@deepseek-ai/dsh-agent-default-model',dict(provider='fixture',model='fixture')),
        plugin('llm-pi-ai','@deepseek-ai/dsh-llm-pi-ai',dict(providers={'fixture':dict(displayName='fixture',
              api='openai-completions',baseURL=f'http://127.0.0.1:{model.server_port}/v1',apiKeyEnv='FIXTURE_KEY',
              models=[dict(id='fixture',name='fixture',contextWindow=65536,maxTokens=2048)])})),
        {'insert':[plugin('aiap-capture','dsh-aiap-capture',dict(python=sys.executable,dataDir=str(db),credentialFile=str(db/'adapter.json'),preferencesFile=str(root/'capture-preferences.json')))]},
    ]
    (profile/'cordis.patch.yml').write_text(json.dumps(patch))
    command=[binary,'--expose-internals',str(entry),'web','--no-open','--host','127.0.0.1','--port','0']
    process=subprocess.Popen(command,cwd=root,env={**os.environ,'DSH_HOME':str(home),'FIXTURE_KEY':'test','ELECTRON_RUN_AS_NODE':'1'},
                             stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    ready=queue.Queue()
    diagnostics=[]
    def read_output():
        for line in process.stdout:
            if found:=re.search(r'dsh web: (http://[^\s]+)',line):
                ready.put(found[1])
            elif 'token=' not in line:
                diagnostics.append(line.strip())
    threading.Thread(target=read_output,daemon=True).start()
    try:
        launch=ready.get(timeout=22)
        url=urlsplit(launch)
        base=f'{url.scheme}://{url.netloc}'
        def rpc(client,endpoint,request):
            envelope={'type':'client-request','rpcId':'rpc-'+endpoint.replace('/','-'),
                      'method':endpoint,'payload':{'args':{'request':request}}}
            operation=Request(base+'/api/'+endpoint,data=json.dumps(envelope).encode(),
                              headers={'Content-Type':'application/json','Origin':base})
            with client.open(operation,timeout=10) as response:
                result=json.load(response)['result']
            if not result['ok']:
                raise AssertionError(result['error']['code'])
            return result.get('value')
        try:
            rpc(build_opener(),'session/create',{'sessionId':allowed,'cwd':str(root)})
        except HTTPError as error:
            assert error.code == 401, error.code
        else:
            raise AssertionError('DSH accepted unauthenticated session creation')
        client=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        client.open(launch,timeout=8).close()
        assert rpc(client,'session/create',{'sessionId':allowed,'cwd':str(root)})['sessionId']==allowed
        def prompt(request_id, text):
            return {'sessionId': allowed, 'requestId': request_id, 'mode': 'queue',
                    'content': [{'type': 'text', 'text': text}]}

        # Wait until the model has completed the synthetic turn. The next
        # prompt independently confirms the session is still usable.
        def send(request, expected_calls):
            assert rpc(client, 'session/prompt', request)['accepted']
            for _ in range(80):
                if len(model_queries) >= expected_calls:
                    return
                time.sleep(.15)
            raise AssertionError('Synthetic model did not receive the prompt')

        control = prompt('aiap-opt-in', '开启 AIAP 自动提案')
        try:
            rpc(build_opener(), 'session/prompt', control)
        except HTTPError as error:
            assert error.code == 401, error.code
        else:
            raise AssertionError('DSH accepted unauthenticated activation')
        send(prompt('aiap-before-opt-in', '我喜欢用详细的格式写周报。'), 1)
        assert not (root/'capture-preferences.json').exists()
        assert not core.pending_proposals(owner, trigger='host-observation')['proposals']
        send(control, 2)
        for _ in range(80):
            if (root/'capture-preferences.json').exists(): break
            time.sleep(.15)
        assert (root/'capture-preferences.json').exists(), 'Opt-in did not persist'
        assert json.loads((root/'capture-preferences.json').read_text()) == [allowed]
        request = prompt('aiap-owner-capture-1', '我喜欢用简洁的格式写周报。')
        send(request, 3)
        for _ in range(100):
            pending=core.pending_proposals(owner,trigger='host-observation')['proposals']
            if pending: break
            time.sleep(.15)
        assert len(pending)==1, (len(model_queries),len(pending))
        result=core.review(owner,pending[0]['delta_id'],changes=True)
        assert result['changes'][0]['proposed_text']==request['content'][0]['text']
        assert result['approval_check']['status']=='ready'
        assert rpc(client,'session/prompt',request)['accepted']
        time.sleep(.5)
        assert len(core.pending_proposals(owner,trigger='host-observation')['proposals'])==1
        assert any(input_ and any('简洁的格式写周报' in str(m.get('content')) for m in input_) for input_ in model_queries)
        send(prompt('aiap-opt-out', '关闭 AIAP 自动提案'), 4)
        for _ in range(80):
            if json.loads((root/'capture-preferences.json').read_text()) == []:
                break
            time.sleep(.15)
        assert json.loads((root/'capture-preferences.json').read_text()) == []
        send(prompt('aiap-after-opt-out', '我通常把月报做成三列表格。'), 5)
        time.sleep(.8)
        assert len(core.pending_proposals(owner, trigger='host-observation')['proposals']) == 1
        print('DSH owner capture: default off, unauthenticated activation denied, one pending proposal, replay deduplicated, and capture disabled.')
    except Exception:
        print('DSH diagnostic tail:', ' | '.join(diagnostics[-25:]))
        raise
    finally:
        process.terminate()
        try: process.wait(8)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
        model.shutdown(); model.server_close()
