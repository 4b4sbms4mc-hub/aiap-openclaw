# SPDX-License-Identifier: Apache-2.0
"""Root-only ephemeral Linux SSH lab; never point this at a real NAS."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import tempfile
import time

from ssh_probe_install import Installer, TARGET, CONFIGS, sha
from ssh_transport_probe import COMMAND, PROFILE


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=15, **kwargs)


def main():
    assert os.geteuid()==0 and os.uname().sysname=='Linux'
    user='aiapprobe'+str(os.getpid());created=False;server=None
    with tempfile.TemporaryDirectory(prefix='aiap-ssh-lab-',dir='/run') as tmp:
        top=Path(tmp);top.chmod(0o755)
        try:
            home=top/'account-home';home.mkdir(mode=0o700)
            run(['useradd','-M','-d',str(home),'-s','/bin/sh',user]);created=True
            run(['passwd','-d',user]);account=pwd.getpwnam(user)
            os.chown(home,account.pw_uid,account.pw_gid)
            # A user rc would execute a marker if the key failed to disable it.
            (home/'.ssh').mkdir(mode=0o700);os.chown(home/'.ssh',account.pw_uid,account.pw_gid)
            marker=home/'rc-ran';(home/'.ssh/rc').write_text('touch '+str(marker)+'\n')
            os.chown(home/'.ssh/rc',account.pw_uid,account.pw_gid)
            for name in ['host','client','wrong']:
                run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(top/name)])
            root=top/'fs';root.mkdir(mode=0o755)
            for directory in ['etc/ssh/sshd_config.d','usr/local/bin',str(home).lstrip('/')]:
                path=root/directory;path.mkdir(parents=True,exist_ok=True,mode=0o755)
            projected_home=root/str(home).lstrip('/')
            os.chown(projected_home,account.pw_uid,account.pw_gid)
            for path in CONFIGS:(root/path.lstrip('/')).write_text('# synthetic lab configuration\n')
            host_blob=(top/'host.pub').read_text().split()[1]
            (root/'etc/ssh/ssh_host_ed25519_key.pub').write_bytes((top/'host.pub').read_bytes())
            payload=(Path(__file__).parent/'ssh_transport_probe.py').read_bytes()
            plan=dict(profile='x-aiap-ssh-probe-install-plan-v1',user=user,uid=account.pw_uid,
                gid=account.pw_gid,home=str(home),source_address='127.0.0.1',
                public_key=(top/'client.pub').read_text().split()[1],
                host_fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(host_blob)).digest()).decode().rstrip('='),
                config_sha256={p:sha((root/p.lstrip('/')).read_bytes()) for p in CONFIGS},
                endpoint_sha256=sha(payload),installer_sha256=sha((Path(__file__).parent/'ssh_probe_install.py').read_bytes()),
                request_id='AIAP-SYNTHETIC-SSH-LAB')
            installer=Installer(plan,payload,root=root)
            assert installer.preflight()['status']=='plan-checked'
            assert not (root/TARGET.lstrip('/')).exists()
            assert installer.apply()['status']=='installed-transport-probe-only'
            assert (projected_home/'.ssh/authorized_keys').stat().st_uid==account.pw_uid
            assert (root/TARGET.lstrip('/')).stat().st_uid==0
            try:installer.apply();raise AssertionError('duplicate install accepted')
            except ValueError as error:assert str(error)=='E_INSTALL_CONFLICT'
            print('INSTALL_AND_CONFLICT_CHECK_PASSED',flush=True)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            os.makedirs('/run/sshd',mode=0o755,exist_ok=True)
            config=top/'sshd_config'
            config.write_text('\n'.join([
                'ListenAddress 127.0.0.1','Port '+str(port),'HostKey '+str(top/'host'),
                'PidFile '+str(top/'sshd.pid'),'AuthorizedKeysFile '+str(projected_home/'.ssh/authorized_keys'),
                'AllowUsers '+user,'PasswordAuthentication no','KbdInteractiveAuthentication no',
                'UsePAM no','StrictModes yes','PubkeyAuthentication yes','PermitUserRC yes',
                'AllowTcpForwarding yes','AllowAgentForwarding yes','PermitTTY yes','LogLevel ERROR'])+'\n')
            log=open(top/'sshd.log','wb')
            server=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(config)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
            deadline=time.monotonic()+5
            while True:
                assert server.poll() is None,'synthetic sshd did not start'
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=0.2):break
                except OSError:
                    assert time.monotonic()<deadline;time.sleep(0.05)
            known=top/'known_hosts';known.write_text('[127.0.0.1]:'+str(port)+' ssh-ed25519 '+host_blob+'\n')
            args=['/usr/bin/ssh','-F','/dev/null','-p',str(port),'-l',user,'-i',str(top/'client'),
                '-o','IdentityAgent=none','-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
                '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
                '-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519']
            request=json.dumps(dict(profile=PROFILE,op='probe',nonce='a'*64)).encode()
            def call(extra, **kwargs):
                return subprocess.run(args+extra,input=request,capture_output=True,timeout=8,**kwargs)
            ok=call(['127.0.0.1',COMMAND]);assert ok.returncode==0,ok.stderr.decode()
            result=json.loads(ok.stdout);assert result['nonce']=='a'*64 and result['uid']==account.pw_uid
            assert result['source_observation_available'] is False and not marker.exists()
            denied=call(['127.0.0.1','id']);assert denied.returncode==2 and json.loads(denied.stdout)=={'error':'E_PROBE_REQUEST'}
            forward=call(['-N','-o','ExitOnForwardFailure=yes','-R','127.0.0.1:0:127.0.0.1:9','127.0.0.1'])
            assert forward.returncode!=0 and b'remote port forwarding failed' in forward.stderr
            direct=call(['-W','127.0.0.1:9','127.0.0.1'])
            assert direct.returncode!=0 and b'administratively prohibited' in direct.stderr
            pty=call(['-tt','127.0.0.1',COMMAND]);assert b'PTY allocation request failed' in pty.stderr
            wrong=list(args);wrong[wrong.index(str(top/'client'))]=str(top/'wrong')
            bad=subprocess.run(wrong+['127.0.0.1',COMMAND],input=request,capture_output=True,timeout=8)
            assert bad.returncode==255
            print('REAL_SSH_COMMAND_FORWARDING_PTY_RC_AND_KEY_CHECKS_PASSED',flush=True)
            keyfile=projected_home/'.ssh/authorized_keys';original=keyfile.read_bytes()
            keyfile.write_bytes(original+b'# changed by synthetic operator\n')
            try:installer.rollback();raise AssertionError('modified key file overwritten')
            except ValueError as error:assert str(error)=='E_USER_PHASE_REVIEW_STATE'
            assert keyfile.read_bytes().endswith(b'# changed by synthetic operator\n')
            keyfile.write_bytes(original)
            assert installer.rollback()['status']=='rolled-back'
            assert not keyfile.exists() and not (root/TARGET.lstrip('/')).exists()
            print('ROLLBACK_AND_CHANGED_FILE_REFUSAL_PASSED',flush=True)
            projected_home.joinpath('.ssh').symlink_to(top,target_is_directory=True)
            try:installer.apply();raise AssertionError('symlink conflict accepted')
            except ValueError as error:assert str(error)=='E_INSTALL_CONFLICT'
            assert not (root/TARGET.lstrip('/')).exists()
            print('AIAP_SYNTHETIC_SSH_LAB_PASSED_NO_NAS_CONNECTION',flush=True)
        finally:
            if server is not None:
                try:os.killpg(server.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                server.wait(timeout=5);log.close()
            if created:subprocess.run(['userdel',user],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)


if __name__=='__main__':main()
