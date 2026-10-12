"""Exercise actual CLI initialization and server process restart."""
import unittest,tempfile,subprocess,sys,socket,json,os
from pathlib import Path
from aiap_core.client import Client,proposal
ROOT=Path(__file__).resolve().parents[1]
class ProcessTests(unittest.TestCase):
    def test_actual_process_restart(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=[sys.executable,'-m','aiap_core','--data-dir',d]
            subprocess.run(cmd+['init'],cwd=ROOT,check=True,capture_output=True,text=True)
            token=json.loads((Path(d)/'owner-credentials.json').read_text())['token']
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            def start():
                proc=subprocess.Popen(cmd+['serve','--port',str(port),'--archive-interval','0'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                line=proc.stdout.readline()
                if 'listening' not in line:
                    proc.terminate();proc.wait(timeout=5);raise AssertionError('Server did not start')
                return proc
            client=Client('http://127.0.0.1:'+str(port),token);proc=start()
            try:
                session=client.call('/v1/session');p=proposal(session,'space:work','PROCESS_PERSISTENCE');r=client.call('/v1/deltas/propose',p);client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True});avatar=session['avatar_id']
            finally:proc.terminate();proc.communicate(timeout=5)
            proc=start()
            try:
                self.assertEqual(client.call('/v1/session')['avatar_id'],avatar)
                r=client.call('/v1/search',{'space_refs':['space:work'],'purpose':'owner-maintenance','query':'PROCESS_PERSISTENCE'});self.assertEqual(r['count'],1)
            finally:proc.terminate();proc.communicate(timeout=5)
