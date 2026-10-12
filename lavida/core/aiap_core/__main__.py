import argparse,json,os
from pathlib import Path
from .service import Service,save_private
from .server import serve
from .client import Client,proposal
from .contracts import canonical,Fault

def main():
    ap=argparse.ArgumentParser(description='AIAP Core Service 0.2.0 — Wang Lu');ap.add_argument('--data-dir',default=os.environ.get('AIAP_DATA_DIR','./data'));sp=ap.add_subparsers(dest='command',required=True)
    sp.add_parser('init',help='Initialize once without overwriting an existing identity.')
    sv=sp.add_parser('serve');sv.add_argument('--host',default='127.0.0.1');sv.add_argument('--port',type=int,default=8042);sv.add_argument('--archive-interval',type=int,default=3600)
    g=sp.add_parser('grant');g.add_argument('--spaces',nargs='+',required=True);g.add_argument('--purpose',required=True);g.add_argument('--runtime',required=True);g.add_argument('--role',choices=['adapter','owner'],default='adapter');g.add_argument('--days',type=int,default=7);g.add_argument('--output',required=True)
    rev=sp.add_parser('revoke');rev.add_argument('--grant-id',required=True);sp.add_parser('archive')
    for command in ['session','core','search','propose','review','decide','demo']:
        x=sp.add_parser(command);x.add_argument('--credential-file',required=True);x.add_argument('--base-url',default='http://127.0.0.1:8042')
        if command in ['search','propose']:x.add_argument('--space',required=True)
        if command=='search':x.add_argument('--query',default='');x.add_argument('--include-archived',action='store_true')
        if command=='propose':x.add_argument('--text',required=True);x.add_argument('--pinned',action='store_true')
        if command in ['review','decide']:x.add_argument('--delta-id',required=True)
        if command=='decide':x.add_argument('--approve',action='store_true',help='Explicitly approve the reviewed candidate; otherwise reject.')
    args=ap.parse_args();s=Service(args.data_dir)
    if args.command=='init':result=s.initialize()
    elif args.command=='serve':return serve(s,args.host,args.port,args.archive_interval)
    elif args.command=='archive':result=s.archive_cycle()
    elif args.command=='grant':
        if Path(args.output).exists():raise Fault('E_OUTPUT_EXISTS',409)
        r=s.issue_grant(args.spaces,args.purpose,args.runtime,args.role,args.days)
        try:save_private(Path(args.output),canonical(r))
        except Exception:s.revoke_grant(r['grant_id']);raise
        result={'grant_id':r['grant_id'],'credential_file':args.output,'expires_at':r['expires_at']}
    elif args.command=='revoke':s.revoke_grant(args.grant_id);result={'revoked':True}
    else:
        credential=json.loads(Path(args.credential_file).read_text(encoding='utf-8'));client=Client(args.base_url,credential['token']);session=client.call('/v1/session')
        if args.command=='session':result=session
        elif args.command=='core':result=client.call('/v1/core')
        elif args.command=='search':result=client.call('/v1/search',{'space_refs':[args.space],'purpose':session['purpose'],'query':args.query,'include_archived':args.include_archived})
        elif args.command=='propose':result=client.call('/v1/deltas/propose',proposal(session,args.space,args.text,pinned=args.pinned))
        elif args.command=='review':result=client.call('/v1/deltas/review',{'delta_id':args.delta_id})
        elif args.command=='decide':result=client.call('/v1/deltas/decide',{'delta_id':args.delta_id,'approve':args.approve})
        else:
            if session['role']!='owner':raise Fault('E_DENIED',403)
            for space,text in [('space:work','DEMO：配置服务器时每次只给一步。'),('space:life','DEMO：周六参加陶艺活动。')]:
                p=proposal(session,space,text,pinned=(space=='space:work'));r=client.call('/v1/deltas/propose',p);client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
            result={'synthetic_demo_created':True,'note':'Verify isolation using separate scoped credentials.'}
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':
    try:main()
    except (Fault,RuntimeError) as e:print(str(e));raise SystemExit(1)
