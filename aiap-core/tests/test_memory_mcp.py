"""Exercise typed MCP candidates against a temporary local Core."""
import json
from pathlib import Path
import tempfile
from threading import Thread
from types import SimpleNamespace
import unittest

from aiap.memory_mcp import _Core, _LocalCore, _server
from aiap_core.contracts import Fault
from aiap_core.server import Server
from aiap_core.service import Service, save_private
from mcp.server.mcpserver.exceptions import ToolError


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
            self.assertEqual((await self.call('aiap_memory_search', query=arguments['text']))['results'], [])
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


if __name__ == '__main__':
    unittest.main()
