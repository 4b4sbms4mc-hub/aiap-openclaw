"""Local HTTP transport. Never logs tokens, requests or memory bodies."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,sqlite3,threading
from .contracts import Fault,exact,require,canonical

def reject_duplicates(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ValueError('duplicate JSON key')
        out[k]=v
    return out
class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,service):self.service=service;super().__init__(address,Handler)
class Handler(BaseHTTPRequestHandler):
    server_version='AIAP-Core/0.2.0'
    def setup(self):super().setup();self.connection.settimeout(10)
    def log_message(self,*args):pass
    def reply(self,status,data):
        raw=canonical(data);self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Connection','close');self.end_headers();self.wfile.write(raw)
    def do_GET(self):self.run_request()
    def do_POST(self):self.run_request()
    def run_request(self):
        try:
            require(not self.headers.get('Origin'),'E_ORIGIN',403)
            if self.command=='GET' and self.path=='/health':return self.reply(200,{'service':'aiap-core','version':'0.2.0','initialized':self.server.service.db.exists()})
            auth=self.headers.get('Authorization','');require(auth.startswith('Bearer '),'E_IDENTITY',401);token=auth[7:];s=self.server.service
            if self.command=='GET':
                if self.path=='/v1/session':result=s.session(token)
                elif self.path=='/v1/core':result=s.core(token)
                else:raise Fault('E_NOT_FOUND',404)
            else:
                require(not self.headers.get('Transfer-Encoding'),'E_SCHEMA')
                require(len(self.headers.get_all('Content-Length',[]))==1,'E_SCHEMA')
                length=int(self.headers.get('Content-Length','0'));require(0<length<=524288,'E_BODY_SIZE',413)
                require(self.headers.get_content_type()=='application/json','E_CONTENT_TYPE',415)
                raw=self.rfile.read(length);require(len(raw)==length)
                body=json.loads(raw,object_pairs_hook=reject_duplicates,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
                if self.path=='/v1/search':result=s.search(token,body)
                elif self.path=='/v1/context':result=s.search(token,body,context=True)
                elif self.path=='/v1/context/ack':result=s.acknowledge(token,body)
                elif self.path=='/v1/deltas/propose':result=s.propose(token,body)
                elif self.path=='/v1/deltas/review':exact(body,['delta_id']);result=s.review(token,body['delta_id'])
                elif self.path=='/v1/deltas/decide':exact(body,['delta_id','approve']);result=s.decide(token,body['delta_id'],body['approve'])
                elif self.path=='/v1/memories/delete':result=s.delete(token,body)
                else:raise Fault('E_NOT_FOUND',404)
            self.reply(200,result)
        except Fault as e:self.reply(e.status,{'error':{'code':e.code}})
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):self.reply(400,{'error':{'code':'E_SCHEMA'}})
        except sqlite3.OperationalError:self.reply(503,{'error':{'code':'E_STORAGE_BUSY'}})
        except (BrokenPipeError,ConnectionResetError,TimeoutError):pass
        except Exception:self.reply(500,{'error':{'code':'E_INTERNAL'}})

def serve(service,host,port,archive_interval=3600):
    require(service.db.exists(),'E_NOT_INITIALIZED',503);stop=threading.Event()
    def cycle():
        while not stop.wait(archive_interval):
            try:service.archive_cycle()
            except Exception:print('AIAP lifecycle job failed; no success claimed.',flush=True)
    if archive_interval>0:threading.Thread(target=cycle,daemon=True).start()
    http=Server((host,port),service)
    try:print('AIAP Core Service listening on '+host+':'+str(port),flush=True);http.serve_forever()
    finally:stop.set();http.server_close()
