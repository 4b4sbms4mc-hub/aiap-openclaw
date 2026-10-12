"""Local API client, not an installed OpenClaw Adapter."""
import json,uuid,urllib.request,urllib.error
from .contracts import canonical
class Client:
    def __init__(self,base,token):self.base=base.rstrip('/');self.token=token
    def call(self,path,body=None):
        req=urllib.request.Request(self.base+path,data=canonical(body) if body is not None else None,headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'},method='POST' if body is not None else 'GET')
        try:
            with urllib.request.urlopen(req,timeout=120) as r:return json.load(r)
        except urllib.error.HTTPError as e:
            try:detail=json.load(e)['error']['code']
            except Exception:detail='E_HTTP'
            raise RuntimeError(str(e.code)+' '+detail) from None

def proposal(session,space,text,*,memory_id=None,old=None,pinned=False,source_type='explicit-user',level='M2'):
    """Prepare a candidate only; separate owner approval is required."""
    source='evidence:local-input:'+str(uuid.uuid4());now=session['issued_at'];scope=next(x for x in session['scopes'] if x['space_ref']==space)
    mid=old['memory_id'] if old else (memory_id or 'mem:'+str(uuid.uuid4()))
    m={'memory_id':mid,'level':level,'type':'preference-evidence' if pinned else 'fact','content':text,'source':{'source_type':source_type,'source_ref':source},'confidence':1 if source_type=='explicit-user' else 0.5,'created_at':now,'updated_at':now,'status':'candidate','retention':{'pinned':pinned,'decay_exempt':pinned},'scope':scope,'revision':old['revision'] if old else 1,'previous_revision':old.get('previous_revision') if old else None,'derived_from':[],'lifecycle':{'policy_ref':{'id':'lifecycle:default','version':1},'last_used_at':None,'context_use_count':0,'confirmed_use_count':0,'stable_preference':pinned,'recurrence_ref':None,'expected_next_use':None,'last_verified':None,'active_task_refs':[]}}
    q={'request_id':'request:'+str(uuid.uuid4()),'authenticated_subject_ref':session['subject_ref'],'auth_evidence_ref':session['auth_evidence_ref'],'avatar_id':session['avatar_id'],'session_ref':session['session_ref'],'runtime_ref':session['runtime_ref'],'space_refs':[space],'action':'write','purpose':session['purpose'],'processor_refs':[],'issued_at':session['issued_at'],'expires_at':session['expires_at']}
    did='aiap:state-delta:'+str(uuid.uuid4());cid='change:'+str(uuid.uuid4())
    return {'profile_version':'0.1-draft','request':q,'delta':{'schema_version':'0.1','delta_id':did,'avatar_id':session['avatar_id'],'runtime_id':session['runtime_ref'],'created_at':now,'changes':[{'change_id':cid,'domain':'aiap.memory','operation':'update' if old else 'add','candidate':m,'confidence':m['confidence'],'evidence':[{'source_ref':source}],'requires_user_confirmation':True}],'status':'proposed'},'bindings':[{'change_id':cid,'target_object_id':mid,'scope':scope,'base_revision':old['revision'] if old else 0,'source_refs':[source],'confirmation_ref':None}]}
