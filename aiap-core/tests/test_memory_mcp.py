"""Exercise typed MCP candidates against a temporary local Core."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
from types import SimpleNamespace
import unittest

from aiap.memory_mcp import _Core, _LocalCore, _credential, _server
from aiap_core.contracts import Fault
from aiap_core.server import Server
from aiap_core.service import Service, save_private
from mcp.server.mcpserver.exceptions import ToolError
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MemoryAdmissionTests(unittest.IsolatedAsyncioTestCase):
    local = False

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        data = Path(self.directory.name)
        self.core = Service(data)
        avatar = self.core.initialize()['avatar_id']
        self.owner = json.loads((data / 'owner-credentials.json').read_text())['token']
        grant = self.core.issue_grant(['space:general'], 'aiap-memory', 'fixture')
        self.adapter = grant['token']
        credential = data / 'adapter.json'
        save_private(credential, json.dumps(grant).encode())
        args = SimpleNamespace(credential_file=credential, avatar_id=avatar,
                               space='space:general', purpose='aiap-memory', runtime='fixture')
        if self.local:
            args.data_dir = data
            self.server = _server(_LocalCore(args))
            return
        http = Server(('127.0.0.1', 0), self.core)
        thread = Thread(target=http.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        self.addCleanup(http.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(http.shutdown)
        args.base_url = f'http://127.0.0.1:{http.server_port}'
        self.server = _server(_Core(args))

    async def call(self, name, **arguments):
        result = await self.server.call_tool(name, arguments)
        return result.structured_content or json.loads(result.content[0].text)

    async def test_task_and_legacy_candidates_require_approval_and_retain_classification(self):
        cases = [({'text': 'Hypothesis to revisit for fixture task', 'level': 'M1',
                   'memory_type': 'project-context'}, 'M1', 'project-context'),
                 ({'text': 'Legacy candidate fixture'}, 'M2', 'fact')]
        for arguments, level, kind in cases:
            result = await self.call('aiap_memory_propose', **arguments)
            self.assertEqual(result['status'], 'proposed')
            delta = result['delta_id']
            candidate = self.core.review(self.owner, delta)['candidate']['delta']['changes'][0]['candidate']
            self.assertEqual((candidate['level'], candidate['type']), (level, kind))
            self.assertEqual(candidate['source']['source_type'], 'inferred')
            self.assertEqual(candidate['confidence'], 0.5)
            before = (await self.call('aiap_memory_search', query=arguments['text']))['results']
            self.assertNotIn(candidate['memory_id'], [item['id'] for item in before])
            with self.assertRaises(Fault):
                self.core.decide(self.adapter, delta, True)
            self.core.decide(self.owner, delta, True)
            found = (await self.call('aiap_memory_search', query=arguments['text']))['results'][0]
            self.assertEqual((found['level'], found['memory_type'], found['source_type'], found['confidence']),
                             (level, kind, 'inferred', 0.5))

    async def test_invalid_classification_cannot_create_a_proposal(self):
        before = self.core.db.read_bytes()
        for arguments in ({'level': 'M0'}, {'level': 'M3'}, {'level': None},
                          {'memory_type': 'hypothesis'}, {'memory_type': None}):
            with self.assertRaises(ToolError):
                await self.call('aiap_memory_propose', text='Fixture', **arguments)
        self.assertEqual(self.core.db.read_bytes(), before)


class LocalMemoryAdmissionTests(MemoryAdmissionTests):
    local = True


class InstalledLocalMCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_launch_and_recall_after_local_owner_approval(self):
        with tempfile.TemporaryDirectory(prefix='AIAP Windows and POSIX ') as directory:
            data = Path(directory) / 'private core'
            core_cli = [sys.executable, '-m', 'aiap_core', '--data-dir', str(data)]
            avatar = json.loads(subprocess.check_output([*core_cli, 'init'], timeout=15))['avatar_id']
            credential = data / 'adapter.json'
            subprocess.check_output([*core_cli, 'grant', '--spaces', 'space:general',
                                     '--purpose', 'aiap-memory', '--runtime', 'deepseek-harness',
                                     '--output', str(credential)], timeout=15)
            parameters = StdioServerParameters(
                command=sys.executable,
                args=['-m', 'aiap.cli', 'mcp', 'serve', '--data-dir', str(data), '--avatar-id', avatar,
                      '--credential-file', str(credential), '--space', 'space:general',
                      '--purpose', 'aiap-memory', '--runtime', 'deepseek-harness'],
                env={'PYTHONPATH': os.environ['PYTHONPATH']} if 'PYTHONPATH' in os.environ else None,
            )

            async def call(session, tool, arguments=None):
                result = await session.call_tool(tool, arguments)
                self.assertFalse(result.is_error, result.content)
                return result.structured_content or json.loads(result.content[0].text)

            query = 'Fixture task for platform compatibility'
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.assertTrue((await call(session, 'aiap_memory_status'))['ok'])
                    proposal = await call(session, 'aiap_memory_propose',
                                          {'text': query, 'level': 'M1', 'memory_type': 'project-context'})
                    self.assertEqual((await call(session, 'aiap_memory_search', {'query': query}))['results'], [])

            decision = json.loads(subprocess.check_output(
                [*core_cli, 'decide', '--local', '--credential-file', str(data / 'owner-credentials.json'),
                 '--delta-id', proposal['delta_id'], '--approve'], timeout=15,
            ))
            self.assertEqual(decision['status'], 'accepted')
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    results = (await call(session, 'aiap_memory_search', {'query': query}))['results']
                    self.assertEqual([(r['content'], r['level']) for r in results], [(query, 'M1')])

    @unittest.skipUnless(os.name == 'nt', 'Windows ACLs')
    def test_windows_rejects_credential_with_public_acl(self):
        import win32con
        import win32security

        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / 'adapter.json'
            token = 'fixture-token-with-allowed-characters'
            save_private(credential, json.dumps({'role': 'adapter', 'token': token}).encode())
            self.assertEqual(_credential(credential), token)
            path = str(credential)
            obj = win32security.SE_FILE_OBJECT
            info = win32security.DACL_SECURITY_INFORMATION
            original = win32security.GetNamedSecurityInfo(path, obj, info)
            acl = original.GetSecurityDescriptorDacl()
            acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ,
                                    win32security.CreateWellKnownSid(win32security.WinWorldSid, None))
            win32security.SetNamedSecurityInfo(path, obj, info, None, None, acl, None)
            with self.assertRaisesRegex(ToolError, 'E_CREDENTIAL_FILE'):
                _credential(credential)


if __name__ == '__main__':
    unittest.main()
