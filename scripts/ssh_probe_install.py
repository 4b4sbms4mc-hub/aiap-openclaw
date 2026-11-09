# SPDX-License-Identifier: Apache-2.0
"""Create-only SSH probe installation. CLI defaults to a read-only plan check."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import sys

TARGET = '/usr/local/bin/aiap-ssh-probe-v1.py'
CONFIGS = ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/trim_sshd.conf']
FIELDS = {'profile','user','uid','gid','home','source_address','public_key',
          'host_fingerprint','config_sha256','endpoint_sha256','installer_sha256','request_id'}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'E_PLAN');result[k]=v
    return result


def validate(plan):
    need(isinstance(plan,dict) and set(plan)==FIELDS,'E_PLAN')
    need(plan['profile']=='x-aiap-ssh-probe-install-plan-v1','E_PLAN')
    need(isinstance(plan['user'],str) and re.fullmatch('[a-z_][a-z0-9_-]{0,31}',plan['user']), 'E_PLAN')
    need(type(plan['uid']) is int and plan['uid']>0 and type(plan['gid']) is int and plan['gid']>=0,'E_PLAN')
    need(isinstance(plan['home'],str) and plan['home'].startswith('/')
         and all(p not in ('','.', '..') for p in plan['home'][1:].split('/')),'E_PLAN')
    need(str(ipaddress.IPv4Address(plan['source_address']))==plan['source_address'],'E_PLAN')
    need(isinstance(plan['public_key'],str) and len(plan['public_key'])<256,'E_PLAN')
    blob=base64.b64decode(plan['public_key'],validate=True)
    need(len(blob)==51 and blob[:19]==struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32),'E_PLAN')
    need(isinstance(plan['host_fingerprint'],str) and re.fullmatch('SHA256:[A-Za-z0-9+/]{43}',plan['host_fingerprint']),'E_PLAN')
    need(isinstance(plan['config_sha256'],dict) and sorted(plan['config_sha256'])==sorted(CONFIGS),'E_PLAN')
    for value in list(plan['config_sha256'].values())+[plan['endpoint_sha256'],plan['installer_sha256']]:
        need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value),'E_PLAN')
    need(isinstance(plan['request_id'],str) and re.fullmatch('AIAP-[A-Z0-9-]{1,64}',plan['request_id']),'E_PLAN')


class Installer:
    # The projected root/owner are only used by imported isolated test fixtures.
    # The production CLI exposes neither override.
    def __init__(self, plan, payload, *, root=Path('/'), root_uid=0):
        validate(plan);need(sha(payload)==plan['endpoint_sha256'],'E_PAYLOAD')
        self.plan=plan;self.payload=payload;self.root=Path(root).resolve();self.root_uid=root_uid

    def directory(self, logical, *, home=False):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            parts=Path(logical).parts[1:]
            for i,part in enumerate(parts):
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new;info=os.fstat(fd)
                owner=self.plan['uid'] if home and i==len(parts)-1 else self.root_uid
                need(info.st_uid==owner and not info.st_mode&0o022,'E_DIRECTORY')
            return fd
        except BaseException:
            os.close(fd);raise

    def read(self, logical, *, owner=None, limit=1048576):
        parent,name=str(Path(logical).parent),Path(logical).name
        directory=self.directory(parent)
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as file:
                info=os.fstat(file.fileno())
                need(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                     and info.st_uid==(self.root_uid if owner is None else owner)
                     and not info.st_mode&0o022 and info.st_size<=limit,'E_FILE')
                raw=file.read(limit+1);need(len(raw)<=limit,'E_FILE');return raw
        finally:os.close(directory)

    def key_line(self):
        endpoint=str(self.root/TARGET.lstrip('/'))
        # Production path is fixed; test fixture paths are deliberately simple.
        need(re.fullmatch('/[A-Za-z0-9_./-]+',endpoint),'E_DIRECTORY')
        return ('restrict,from="'+self.plan['source_address']+'",command="/usr/bin/python3 -I '
                +endpoint+'" ssh-ed25519 '+self.plan['public_key']+' '+self.plan['request_id']+'\n').encode()

    def preflight(self):
        account=pwd.getpwnam(self.plan['user'])
        need((account.pw_uid,account.pw_gid,account.pw_dir)==
             (self.plan['uid'],self.plan['gid'],self.plan['home']),'E_ACCOUNT')
        for path,digest in self.plan['config_sha256'].items():
            need(sha(self.read(path))==digest,'E_CONFIGURATION_CHANGED')
        directory=self.directory('/etc/ssh/sshd_config.d')
        try:need(sorted(n for n in os.listdir(directory) if n.endswith('.conf'))==['trim_sshd.conf'],'E_CONFIGURATION_CHANGED')
        finally:os.close(directory)
        host=self.read('/etc/ssh/ssh_host_ed25519_key.pub',limit=8192).split()
        need(len(host)>=2 and host[0]==b'ssh-ed25519','E_HOST')
        fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(host[1],validate=True)).digest()).decode().rstrip('=')
        need(fingerprint==self.plan['host_fingerprint'],'E_HOST')
        home=self.directory(self.plan['home'],home=True)
        parent=self.directory('/usr/local/bin')
        try:
            for fd,name in [(home,'.ssh'),(parent,Path(TARGET).name)]:
                try:os.stat(name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:continue
                raise ValueError('E_INSTALL_CONFLICT')
        finally:os.close(home);os.close(parent)
        self.key_line()
        return {'status':'plan-checked','source_observation_available':False}

    def user_phase(self, remove=False):
        home=self.directory(self.plan['home'],home=True)
        try:
            if remove:
                try:ssh=os.open('.ssh',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=home)
                except FileNotFoundError:return
            else:
                os.mkdir('.ssh',0o700,dir_fd=home)
                ssh=os.open('.ssh',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=home)
            try:
                info=os.fstat(ssh)
                need(info.st_uid==self.plan['uid'] and stat.S_IMODE(info.st_mode)==0o700,'E_KEY_DIRECTORY')
                if remove:
                    try:fd=os.open('authorized_keys',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=ssh)
                    except FileNotFoundError:fd=None
                    if fd is not None:
                        with os.fdopen(fd,'rb') as file:
                            info=os.fstat(file.fileno());raw=file.read(8193)
                            need(stat.S_ISREG(info.st_mode) and info.st_uid==self.plan['uid']
                                 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
                                 and raw==self.key_line(),'E_KEY_CHANGED')
                        os.unlink('authorized_keys',dir_fd=ssh);os.fsync(ssh)
                else:
                    fd=os.open('authorized_keys',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=ssh)
                    with os.fdopen(fd,'wb') as file:
                        os.fchmod(file.fileno(),0o600);file.write(self.key_line());file.flush();os.fsync(file.fileno())
                    os.fsync(ssh)
            finally:os.close(ssh)
            if remove:
                # Extra files are preserved; a non-empty .ssh remains in place.
                try:os.rmdir('.ssh',dir_fd=home)
                except OSError:pass
            os.fsync(home)
        finally:os.close(home)

    def as_user(self, remove=False):
        pid=os.fork()
        if pid==0:
            try:
                if os.geteuid()!=self.plan['uid']:
                    os.setgroups([]);os.setgid(self.plan['gid']);os.setuid(self.plan['uid'])
                os.umask(0o077)
                self.user_phase(remove);os._exit(0)
            except BaseException:os._exit(2)
        _,status=os.waitpid(pid,0)
        need(os.waitstatus_to_exitcode(status)==0,'E_USER_PHASE_REVIEW_STATE')

    def apply(self):
        self.preflight()
        parent=self.directory('/usr/local/bin')
        try:
            fd=os.open(Path(TARGET).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=parent)
            with os.fdopen(fd,'wb') as file:
                os.fchmod(file.fileno(),0o644);file.write(self.payload);file.flush();os.fsync(file.fileno())
            os.fsync(parent)
        finally:os.close(parent)
        # Root creates only its fixed helper. Account files are written after
        # irreversible child privilege drop, never as root through user paths.
        self.as_user()
        return {'status':'installed-transport-probe-only','source_observation_available':False}

    def rollback(self):
        # Revoke the exact key before touching the helper. Changed account files
        # cause a stop for review rather than overwriting unrelated entries.
        self.as_user(remove=True)
        try:raw=self.read(TARGET)
        except FileNotFoundError:return {'status':'key-revoked-helper-already-absent'}
        need(sha(raw)==self.plan['endpoint_sha256'],'E_HELPER_CHANGED_KEY_REVOKED')
        parent=self.directory('/usr/local/bin')
        try:os.unlink(Path(TARGET).name,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
        return {'status':'rolled-back'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True)
    parser.add_argument('--payload',required=True)
    parser.add_argument('--expected-plan-sha256',required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--apply',action='store_true')
    mode.add_argument('--rollback',action='store_true')
    parser.add_argument('--approved-plan-sha256')
    args=parser.parse_args()
    try:
        need(sys.platform.startswith('linux') and os.geteuid()==0,'E_LINUX_ROOT_REQUIRED')
        raw=Path(args.plan).read_bytes();need(len(raw)<=16384 and sha(raw)==args.expected_plan_sha256,'E_PLAN_DIGEST')
        plan=json.loads(raw,object_pairs_hook=unique)
        validate(plan);need(sha(Path(__file__).read_bytes())==plan['installer_sha256'],'E_INSTALLER_DIGEST')
        payload=Path(args.payload).read_bytes();need(len(payload)<=16384,'E_PAYLOAD')
        instance=Installer(plan,payload)
        if args.apply or args.rollback:
            need(args.approved_plan_sha256==args.expected_plan_sha256,'E_EXPLICIT_APPROVAL_REQUIRED')
        result=instance.apply() if args.apply else instance.rollback() if args.rollback else instance.preflight()
        print(json.dumps(result,sort_keys=True));return 0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) and re.fullmatch('E_[A-Z0-9_]+',str(error)) else 'E_INSTALL_UNAVAILABLE'
        print(json.dumps({'status':'stopped','code':code}));return 2


if __name__=='__main__':sys.exit(main())
