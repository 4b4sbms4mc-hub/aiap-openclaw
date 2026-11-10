# SPDX-License-Identifier: Apache-2.0
"""Lab-only bounded observation messages. No listener, SSH or production binding.

Checkpoint paths and source/key access come from trusted local configuration,
never request data. This adapter is not an authentication or authorization layer.
"""
from pathlib import Path

from recovery_guard import Fault, canonical, strict_json, require, load_checkpoint, digest
from recovery_avatar_observation import observe_source, verify_observation
from recovery_witness import hex_digest

PROFILE='x-aiap-source-observation-rpc-v2'
MAX_REQUEST=1024
MAX_RESPONSE=4096


def request(raw):
    require(isinstance(raw,bytes) and len(raw)<=MAX_REQUEST,'E_SOURCE_RPC_REQUEST')
    try:data=strict_json(raw.decode('utf-8'))
    except Exception:raise Fault('E_SOURCE_RPC_REQUEST') from None
    require(isinstance(data,dict) and set(data)=={'profile','op','nonce','checkpoint_sha256'}
            and data['profile']==PROFILE and data['op']=='observe'
            and hex_digest(data['nonce']) and hex_digest(data['checkpoint_sha256']),
            'E_SOURCE_RPC_REQUEST')
    return data


class LaboratoryAvatarObservationRPC:
    def __init__(self,source,checkpoints,clock,*,observer=observe_source):
        require(isinstance(checkpoints,dict) and 1<=len(checkpoints)<=16
                and all(hex_digest(k) and isinstance(v,Path) for k,v in checkpoints.items()),
                'E_SOURCE_RPC_CONFIGURATION')
        self.source=Path(source);self.checkpoints=dict(checkpoints)
        self.clock=clock;self.observer=observer

    def respond(self,raw):
        try:
            data=request(raw)
            path=self.checkpoints.get(data['checkpoint_sha256'])
            require(path is not None,'E_SOURCE_RPC_CHECKPOINT')
            observation=self.observer(self.source,path,data['checkpoint_sha256'],data['nonce'],self.clock)
            now=self.clock()
            payload,_=load_checkpoint(path,data['checkpoint_sha256'],now)
            verify_observation(observation,data['nonce'],data['checkpoint_sha256'],payload,
                               digest(payload['enrollment']),now)
            result=canonical({'profile':PROFILE,'status':'observed','observation':observation})
            require(len(result)<=MAX_RESPONSE,'E_SOURCE_RPC_RESPONSE')
            return result
        except Exception:
            # Never reflect input, source paths, exception text or key material.
            return canonical({'profile':PROFILE,'status':'unavailable'})


def verify_reply(raw,request_raw,checkpoint,clock):
    data=request(request_raw)
    require(isinstance(raw,bytes) and len(raw)<=MAX_RESPONSE,'E_SOURCE_RPC_RESPONSE')
    try:reply=strict_json(raw.decode('utf-8'))
    except Exception:raise Fault('E_SOURCE_RPC_RESPONSE') from None
    require(isinstance(reply,dict) and set(reply)=={'profile','status','observation'}
            and reply['profile']==PROFILE and reply['status']=='observed','E_SOURCE_RPC_RESPONSE')
    now=clock()
    payload,_=load_checkpoint(checkpoint,data['checkpoint_sha256'],now)
    verify_observation(reply['observation'],data['nonce'],data['checkpoint_sha256'],payload,
                       digest(payload['enrollment']),now)
    return reply['observation']
