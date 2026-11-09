# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NASAccessInspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.tools=self.root/'tools';self.tools.mkdir()
        self.home=self.root/'home';(self.home/'.ssh').mkdir(parents=True)
        (self.home/'.ssh/id_ed25519').write_text('SYNTHETIC_PRIVATE_KEY_MUST_NOT_READ')
        (self.home/'.ssh/authorized_keys').write_text('EXISTING_PUBLIC_ENTRY_MUST_NOT_DUMP')
        self.audit=self.root/'audit.jsonl'
        self.script=Path(__file__).resolve().parents[1]/'inspect_nas_access.sh'
        self.tool('uname',"print('Linux')")
        self.tool('id',"print('0')")
        self.tool('getent',"print('aiaplab:PASSWD_FIELD_MUST_NOT_OUTPUT:10002:10002:ignored:'+"+repr(str(self.home))+"+':/bin/sh')")
        self.tool('stat',"print('10002' if sys.argv[1:2]==['-c'] and sys.argv[2:3]==['%u'] else 'PATH_METADATA=uid:10002,gid:10002,mode:700,type:directory')")
        self.tool('getfacl',"print('user::rwx\\ngroup::---\\nother::---')")
        self.tool('pgrep',"raise SystemExit(1)")
        self.tool('docker',"print('CORE_NAME=/synthetic-core CORE_IMAGE_ID=sha256:synthetic CORE_RUNNING=true CORE_USER=10001:10001')")
        self.tool('sshd',"""
if os.environ.get('AIAP_TEST_G_FAIL')=='1':raise SystemExit(2)
if sys.argv[1:2]!=['-G']:raise SystemExit(99)
print('pubkeyauthentication yes')
print('authorizedkeysfile /vendor/keys/%u')
print('strictmodes yes')
print('authenticationmethods publickey')
print('authorizedkeyscommand /secret/command --token=COMMAND_TOKEN_MUST_NOT_OUTPUT')
print('forcecommand /secret/forced --password=FORCE_SECRET_MUST_NOT_OUTPUT')
print('setenv API_KEY=ENV_SECRET_MUST_NOT_OUTPUT')
print('hostkey /secret/HOST_KEY_PATH_MUST_NOT_OUTPUT')
""")
        self.env=dict(os.environ,PATH=str(self.tools)+':/usr/bin:/bin:/usr/sbin:/sbin')

    def tool(self,name,body):
        code=("#!"+sys.executable+"\nimport sys,os,json\n"
              +"with open("+repr(str(self.audit))+",'a') as f:f.write(json.dumps(["+repr(name)+"]+sys.argv[1:])+'\\n')\n"+body+'\n')
        path=self.tools/name;path.write_text(code);path.chmod(0o755)

    def run_script(self,args=None,env=None):
        return subprocess.run(['/bin/sh',str(self.script)]+(args or ['aiaplab','127.0.0.1','127.0.0.2','synthetic-core']),
                              env=env or self.env,capture_output=True,text=True,timeout=10)

    def home_hashes(self):
        return {p.relative_to(self.home).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.home.rglob('*') if p.is_file() and not p.is_symlink()}

    def test_read_only_filtered_metadata_and_no_private_or_command_values(self):
        before=self.home_hashes();result=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.home_hashes(),before)
        self.assertIn('SSH_SETTING=authorizedkeysfile /vendor/keys/%u',result.stdout)
        self.assertIn('authorizedkeyscommand_present yes',result.stdout)
        self.assertIn('forcecommand_present yes',result.stdout)
        self.assertIn('PREFLIGHT_DONE_NO_CONFIGURATION_CHANGED',result.stdout)
        for secret in ('SYNTHETIC_PRIVATE_KEY_MUST_NOT_READ','EXISTING_PUBLIC_ENTRY_MUST_NOT_DUMP',
                       'PASSWD_FIELD_MUST_NOT_OUTPUT','COMMAND_TOKEN_MUST_NOT_OUTPUT',
                       'FORCE_SECRET_MUST_NOT_OUTPUT','ENV_SECRET_MUST_NOT_OUTPUT','HOST_KEY_PATH_MUST_NOT_OUTPUT'):
            self.assertNotIn(secret,result.stdout+result.stderr)
        calls=[json.loads(line) for line in self.audit.read_text().splitlines()]
        sshd=[c for c in calls if c[0]=='sshd'];self.assertEqual(len(sshd),1);self.assertEqual(sshd[0][1],'-G')
        docker=[c for c in calls if c[0]=='docker'];self.assertEqual(len(docker),1)
        self.assertIn('unix:///var/run/docker.sock',docker[0]);self.assertIn('inspect',docker[0])
        self.assertNotIn('.Config.Env',' '.join(docker[0]))

    def test_unsupported_G_never_falls_back_to_key_loading_tests(self):
        env=dict(self.env,AIAP_TEST_G_FAIL='1');result=self.run_script(env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('SSH_CONFIG_STATUS=unavailable_no_T_or_t_fallback',result.stdout)
        calls=[json.loads(line) for line in self.audit.read_text().splitlines()]
        self.assertEqual([c[1] for c in calls if c[0]=='sshd'],['-G'])

    def test_invalid_user_or_multiline_address_is_rejected_before_account_lookup(self):
        for args in [['bad;id','127.0.0.1','127.0.0.2','synthetic-core'],
                     ['aiaplab','127.0.0.1\n127.0.0.2','127.0.0.2','synthetic-core']]:
            result=self.run_script(args=args);self.assertEqual(result.returncode,2)
        calls=[json.loads(line) for line in self.audit.read_text().splitlines()]
        self.assertFalse(any(c[0] in ('getent','sshd','docker') for c in calls))

    def test_authorized_file_symlink_is_reported_without_following_or_editing(self):
        path=self.home/'.ssh/authorized_keys';path.unlink();path.symlink_to(self.home/'.ssh/id_ed25519')
        before=self.home_hashes();result=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('PATH_STATUS=symlink_no_content_read',result.stdout)
        self.assertEqual(self.home_hashes(),before);self.assertTrue(path.is_symlink())
        self.assertIn('runtime_flags_and_reverse_hostname_not_verified',result.stdout)


if __name__=='__main__':unittest.main()
