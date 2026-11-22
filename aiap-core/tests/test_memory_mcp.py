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
        self.args = args
        self.bound_service = self.core
        if self.local:
            args.data_dir = data
            binding = _LocalCore(args)
            self.bound_service = binding.service
            self.server = _server(binding)
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
            search = await self.call('aiap_memory_search', query=arguments['text'])
            self.assertEqual(search['retrieval_reason'], 'embedding-not-configured')
            self.assertFalse(search['degraded'])
            before = search['results']
            self.assertNotIn(candidate['memory_id'], [item['id'] for item in before])
            with self.assertRaises(Fault):
                self.core.decide(self.adapter, delta, True)
            self.core.decide(self.owner, delta, True)
            found = (await self.call('aiap_memory_search', query=arguments['text']))['results'][0]
            self.assertTrue(found['created_at'] and found['updated_at'] and found['last_verified_at'])
            self.assertIsNone(found['last_used_at'])
            self.assertEqual(found['confidence_basis'], 'proposal-reported')
            self.assertEqual(found['source_ref'], candidate['source']['source_ref'])
            self.assertEqual((found['level'], found['memory_type'], found['source_type'], found['confidence']),
                             (level, kind, 'inferred', 0.5))

    async def test_review_pairs_and_scoped_one_hop_links(self):
        from aiap_core.client import proposal

        def seed(text, token=self.adapter, space='space:general'):
            env = proposal(self.core.session(token), space, text)
            ref = 'evidence:weekly-report'
            change = env['delta']['changes'][0]
            change['candidate']['source']['source_ref'] = ref
            change['evidence'] = [{'source_ref': ref}]
            env['bindings'][0]['source_refs'] = [ref]
            delta = self.core.propose(token, env)
            self.core.decide(self.owner, delta['delta_id'], True)
            return change['candidate']['memory_id']

        first = seed('Send weekly report every Friday unless incident')
        second = seed('Send weekly report every Friday except incident escalations')
        other = self.core.issue_grant(['space:work'], 'aiap-memory', 'fixture')['token']
        foreign = seed('Send weekly report every Friday', other, 'space:work')
        before = self.core.db.read_bytes()
        page = await self.call('aiap_memory_similar', memory_id=first)
        pair, = page['suggestions']
        self.assertEqual(pair['candidate']['memory_id'], second)
        self.assertIn('unless incident', page['anchor']['content'])
        self.assertIn('except incident escalations', pair['candidate']['content'])
        self.assertEqual(page, await self.call('aiap_memory_similar', memory_id=first))
        links = await self.call('aiap_memory_relations', memory_id=first)
        edge, = links['edges']
        self.assertEqual((edge['kind'], edge['other']['memory_id']), ('shared-evidence-reference', second))
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_relations', memory_id=foreign)
        self.assertEqual(before, self.core.db.read_bytes())
        self.core.set_memory_validity(self.owner, 'space:general', first, 1, successor_id=second, successor_revision=1)
        for ident, kind in ((first, 'superseded-by'), (second, 'supersedes')):
            page = await self.call('aiap_memory_relations', memory_id=ident)
            self.assertEqual({e['kind'] for e in page['edges']}, {kind, 'shared-evidence-reference'})
            self.assertEqual([e['replacement_revision'] for e in page['edges'] if e['kind'] == kind], [1])

    async def test_batch_partial_failure_and_retry(self):
        args = dict(batch_id='import-one', items=[{'text':'Green orchard'}, {'text':''}])
        before = self.core.db.read_bytes()
        preview = (await self.call('aiap_memory_batch', **args))['results']
        self.assertEqual([r['status'] for r in preview], ['ready-to-propose', 'error'])
        duplicates = await self.call('aiap_memory_batch', batch_id='preview-duplicates',
                                     items=[{'text':'Green orchard'}, {'text':'Green  orchard'}])
        self.assertEqual(duplicates['results'][1]['first_index'], 0)
        self.assertEqual(duplicates['results'][1]['status'], 'duplicate')
        self.assertEqual(before, self.core.db.read_bytes())
        sent = (await self.call('aiap_memory_batch', **args, submit=True))['results'][0]
        self.core.decide(self.owner, sent['delta_id'], True)
        retried = (await self.call('aiap_memory_batch', **args, submit=True))['results'][0]
        self.assertEqual((retried['delta_id'], retried['status']), (sent['delta_id'], 'accepted'))
        record, = (await self.call('aiap_memory_list'))['results']
        edit = {'memory_id':record['id'], 'text':'Fresh crop', 'base_revision':record['revision']}
        rows = (await self.call('aiap_memory_batch', batch_id='edit', submit=True,
                                items=[{**edit, 'base_revision':99}, edit]))['results']
        self.assertEqual(rows[0]['code'], 'E_VERSION_CONFLICT')
        self.assertEqual(rows[1]['status'], 'proposed')

    async def test_project_bindings_and_revocation(self):
        from copy import copy
        servers, grants = [], []
        for slug in ('orchard', 'turbine'):
            space = self.core.create_project_space(slug)['space_ref']
            self.assertFalse(self.core.create_project_space(slug)['created'])
            args = copy(self.args)
            args.space = space
            args.credential_file = self.core.db.parent / (slug + '.json')
            grant = self.core.issue_grant([space], 'aiap-memory', 'fixture')
            save_private(args.credential_file, json.dumps(grant).encode())
            self.server = _server(_LocalCore(args) if self.local else _Core(args))
            self.assertEqual((await self.call('aiap_memory_status'))['space_ref'], space)
            draft = await self.call('aiap_memory_propose', text=slug)
            owner = self.core.issue_grant([space], 'project-review', 'fixture-owner', role='owner')
            self.core.decide(owner['token'], draft['delta_id'], True)
            servers.append(self.server)
            grants.append(grant)
        for server, slug in zip(servers, ('orchard', 'turbine')):
            self.server = server
            items = (await self.call('aiap_memory_search', query=''))['results']
            self.assertEqual([r['content'] for r in items], [slug])
        self.core.revoke_grant(grants[1]['grant_id'])
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_search', query='')

    async def test_context_pages_preferences_and_rechecks_withdrawals(self):
        space = 'space:general'
        keys = []
        for statement in ('Check the plan', 'Read the changelog', 'Review the risks'):
            fields = dict(statement=statement, condition='Release', runtimes=['fixture'])
            pin = self.core.preview_preference(self.owner, space, **fields)['preview_sha256']
            keys.append(self.core.confirm_preference(self.owner, space, pin, **fields)['preference_id'])
        keys.sort()
        async def page(**fields):
            return await self.call('aiap_memory_context', query='', limit=1, **fields)
        first = await page(preference_condition='Release')
        self.assertEqual(first['preference_defaults'][0]['preference_id'], keys[0])
        cursor = first['next_preference_after']
        self.core.withdraw_preference(self.owner, space, keys[1])
        last = await page(preference_condition='Release', preference_after=cursor)
        self.assertEqual(last['preference_defaults'][0]['preference_id'], keys[2])
        self.assertFalse(last['possibly_more_preferences'])
        self.assertNotIn('next_preference_after', last)
        with self.assertRaises(ToolError):
            await page(preference_condition='Another', preference_after=cursor)
        with self.assertRaises(ToolError):
            await page(preference_after=cursor)
        self.assertNotIn('preference_defaults', await page())

    async def test_context_applies_only_confirmed_matching_runtime_preferences(self):
        space = 'space:general'
        fields = dict(statement='Review the release plan', condition='Release', exception='Local experiment',
                      runtimes=['fixture', 'openclaw-work'])
        pin = self.core.preview_preference(self.owner, space, **fields)['preview_sha256']
        async def context(**args):
            return await self.call('aiap_memory_context', query='', **args)
        self.assertEqual((await context(preference_condition='Release'))['preference_defaults'], [])
        record = self.core.confirm_preference(self.owner, space, pin, **fields)
        private = {**fields, 'statement': 'Another runtime only', 'runtimes': ['other']}
        other = self.core.preview_preference(self.owner, space, **private)
        self.core.confirm_preference(self.owner, space, other['preview_sha256'], **private)
        self.assertNotIn('preference_conditions', await self.call('aiap_memory_status'))
        discovery = await self.call('aiap_memory_status', preference_conditions_after='')
        self.assertEqual(discovery['preference_conditions'], {'conditions': ['Release'], 'next_after': None})
        page = await context(preference_condition=' Release ')
        item, = page['preference_defaults']
        self.assertEqual(item['preference_id'], record['preference_id'])
        self.assertEqual(item['exception'], 'Local experiment')
        self.assertNotIn('evidence_refs', item)
        self.assertEqual(page['items'], [])
        self.assertNotIn('preference_defaults', await context())
        self.assertEqual((await context(preference_condition='Other'))['preference_defaults'], [])
        self.core.withdraw_preference(self.owner, space, record['preference_id'])
        self.assertEqual((await context(preference_condition='Release'))['preference_defaults'], [])

    async def test_report_adoption_is_bound_to_delivered_version(self):
        draft = await self.call('aiap_memory_propose', text='Orchard planted')
        self.core.decide(self.owner, draft['delta_id'], True)
        view = await self.call('aiap_memory_context', query='Orchard')
        item, = view['items']
        request = dict(view_id=view['view_id'], memory_id=item['id'], revision=item['revision'])
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_report_adoption', **request)
        await self.call('aiap_memory_ack_delivery', view_id=view['view_id'])
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_report_adoption', **{**request, 'revision':item['revision'] + 1})
        for retry in (False, True):
            result = await self.call('aiap_memory_report_adoption', **request)
            self.assertEqual(result['idempotent'], retry)
        events = self.core.list_audit(self.owner, event='runtime-reported-adoption')['events']
        self.assertEqual([e['object_id'] for e in events], [item['id']])

    async def test_archive_request_keeps_memory_visible_until_owner_accepts(self):
        initial = await self.call('aiap_memory_propose', text='Retired project milestone')
        self.core.decide(self.owner, initial['delta_id'], True)
        item, = (await self.call('aiap_memory_list'))['results']
        req = await self.call('aiap_memory_propose_archive', memory_id=item['id'],
                              base_revision=item['revision'], reason='Project closed')
        self.assertEqual((await self.call('aiap_memory_list'))['results'], [item])
        self.core.decide(self.owner, req['delta_id'], True, allow_lifecycle=True)
        self.assertEqual((await self.call('aiap_memory_list'))['results'], [])
        self.assertEqual((await self.call('aiap_memory_list', level='M3'))['results'][0]['id'], item['id'])

    async def test_status_exposes_only_own_proposal_state(self):
        lookup = 'aiap_memory_proposal_status'
        for text, approve, final in [('Orchard harvest', True, 'accepted'), ('Turbine blades', False, 'rejected')]:
            proposal = await self.call('aiap_memory_propose', text=text)
            ident = proposal['delta_id']
            self.assertEqual(await self.call(lookup, delta_id=ident), {'delta_id': ident, 'status': 'proposed'})
            self.core.decide(self.owner, ident, approve)
            self.assertEqual((await self.call(lookup, delta_id=ident))['status'], final)
        other = self.core.issue_grant(['space:general'], 'aiap-memory', 'fixture')
        replacement = self.core.db.parent / 'other-adapter.json'
        save_private(replacement, json.dumps(other).encode())
        replacement.replace(self.core.db.parent / 'adapter.json')
        before = self.core.db.read_bytes()
        for candidate in (ident, 'delta:missing'):
            self.assertEqual((await self.call(lookup, delta_id=candidate))['status'], 'not-found')
        self.assertEqual(before, self.core.db.read_bytes())

    async def test_browse_pages_are_scoped_filtered_and_read_only(self):
        texts = ['Orchard harvest window', 'Turbine blade dimensions']
        for text in texts:
            proposal = await self.call('aiap_memory_propose', text=text)
            self.core.decide(self.owner, proposal['delta_id'], True)
        await self.call('aiap_memory_propose', text='Pending shipyard schedule')
        before = self.core.db.read_bytes()
        self.assertTrue((await self.call('aiap_memory_status'))['memory_browse'])
        filters = dict(level='M2', memory_type='fact', limit=1)
        first = await self.call('aiap_memory_list', **filters)
        self.assertTrue(first['next_after'])
        last = await self.call('aiap_memory_list', after=first['next_after'], **filters)
        self.assertIsNone(last['next_after'])
        self.assertCountEqual([r['excerpt'] for r in first['results'] + last['results']], texts)
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_list', level='M1', after=first['next_after'])
        empty = await self.call('aiap_memory_list', updated_before='2000-01-01T00:00:00Z')
        self.assertEqual(empty['results'], [])
        self.assertEqual(before, self.core.db.read_bytes())

    async def test_preview_is_scoped_and_read_only(self):
        args = dict(text='Fixture owner preference', level='M2', memory_type='preference-evidence')
        before = self.core.db.read_bytes()
        result = await self.call('aiap_memory_preview', **args)
        self.assertEqual(result['status'], 'ready-to-propose')
        self.assertFalse(result['submitted'])
        self.assertEqual(result['requested_classification']['memory_type'], args['memory_type'])
        self.assertEqual(before, self.core.db.read_bytes())
        created = await self.call('aiap_memory_propose', **args)
        before = self.core.db.read_bytes()
        result = await self.call('aiap_memory_preview', **args)
        self.assertEqual((result['status'], result['delta_id']), ('duplicate', created['delta_id']))
        self.assertEqual(before, self.core.db.read_bytes())
        self.core.decide(self.owner, created['delta_id'], True)
        before = self.core.db.read_bytes()
        result = await self.call('aiap_memory_preview', **{**args, 'text': args['text'] + ' revised'})
        self.assertEqual(result['status'], 'review-revision')
        self.assertTrue(result['matches'])
        self.assertEqual(before, self.core.db.read_bytes())

        # A rotated credential for another space cannot preview through this binding.
        other = self.core.issue_grant(['space:work'], 'aiap-memory', 'fixture')
        replacement = self.core.db.parent / 'other-adapter.json'
        save_private(replacement, json.dumps(other).encode())
        replacement.replace(self.core.db.parent / 'adapter.json')
        before = self.core.db.read_bytes()
        with self.assertRaises(ToolError):
            await self.call('aiap_memory_preview', **args)
        self.assertEqual(before, self.core.db.read_bytes())

    async def test_checked_proposals_report_duplicates_and_related_records(self):
        status = await self.call('aiap_memory_status')
        self.assertEqual(status['proposal_admission'], 'checked-v1')
        original = {'text': '以后请默认用中文回复。', 'memory_type': 'preference-evidence',
                    'trigger': 'user-request'}
        created = await self.call('aiap_memory_propose', **original)
        repeated = await self.call('aiap_memory_propose', **original)
        self.assertEqual((repeated['status'], repeated['delta_id']), ('duplicate', created['delta_id']))
        self.assertFalse(repeated['submitted'])
        approved = self.core.decide(self.owner, created['delta_id'], True)['objects'][0]
        self.assertEqual((await self.call('aiap_memory_propose', **original))['reason'], 'same-active-memory')

        changed = {**original, 'text': '以后请默认用英文回复。'}
        compared = await self.call('aiap_memory_propose', **changed)
        self.assertEqual(compared['status'], 'review-revision')
        self.assertEqual(compared['matches'], [{'memory_id': approved['memory_id'], 'revision': 1}])
        self.assertEqual(self.core.pending_proposals(self.owner)['proposals'], [])
        separate = await self.call('aiap_memory_propose', **changed, confirm_new=True)
        self.assertEqual(separate['status'], 'proposed')
        review = self.core.review(self.owner, separate['delta_id'], changes=True)
        self.assertEqual(review['admission']['trigger'], 'user-request')
        self.assertTrue(review['admission']['confirm_new_requested'])

    async def test_user_can_propose_a_revision_with_current_scope_and_version(self):
        from aiap_core.client import proposal

        previous = self.core.propose(self.owner, proposal(
            self.core.session(self.owner), 'space:general', '一直使用中文回复。', pinned=True))
        approved = self.core.decide(self.owner, previous['delta_id'], True)['objects'][0]
        status = await self.call('aiap_memory_status')
        self.assertTrue(status['proposal_revision'])
        arguments = {'text': '以后改用英文回复。', 'trigger': 'user-request',
                     'memory_id': approved['memory_id'], 'base_revision': approved['revision']}
        with self.assertRaisesRegex(ToolError, 'E_ARGUMENTS'):
            await self.call('aiap_memory_propose', **{**arguments, 'trigger': 'agent-inference'})
        with self.assertRaisesRegex(ToolError, '409'):
            await self.call('aiap_memory_propose', **{**arguments, 'base_revision': approved['revision'] + 1})

        result = await self.call('aiap_memory_propose', **arguments)
        self.assertEqual((result['status'], result['memory_id'], result['memory_type']),
                         ('proposed', approved['memory_id'], 'preference-evidence'))
        review, = self.core.review(self.owner, result['delta_id'], changes=True)['changes']
        self.assertEqual(review['current_text'], '一直使用中文回复。')
        self.assertEqual(review['proposed_text'], '以后改用英文回复。')
        self.assertTrue(review['proposed_classification']['stable_preference'])
        self.core.decide(self.owner, result['delta_id'], True)
        found = (await self.call('aiap_memory_search', query='以后改用英文回复。'))['results']
        self.assertEqual([(item['id'], item['revision']) for item in found], [(approved['memory_id'], 2)])
        with self.assertRaisesRegex(ToolError, '409'):
            await self.call('aiap_memory_propose', **arguments)

    async def test_legacy_capability_uses_existing_proposal_path(self):
        from unittest.mock import patch

        old_session = self.bound_service.session

        def legacy_session(token):
            return {key: val for key, val in old_session(token).items() if key not in {'proposal_admission', 'proposal_revision', 'memory_browse'}}

        with patch.object(self.bound_service, 'session', side_effect=legacy_session):
            self.assertEqual((await self.call('aiap_memory_status'))['proposal_admission'], 'legacy')
            with self.assertRaisesRegex(ToolError, 'E_PROPOSAL_REVISION_UNSUPPORTED'):
                await self.call('aiap_memory_propose', text='Old Core revision request', trigger='user-request',
                                memory_id='mem:fixture', base_revision=1)
            with self.assertRaisesRegex(ToolError, 'E_PROPOSAL_PREVIEW_UNSUPPORTED'):
                await self.call('aiap_memory_preview', text='Legacy preview')
            with self.assertRaisesRegex(ToolError, 'E_MEMORY_BROWSE_UNSUPPORTED'):
                await self.call('aiap_memory_list')
            result = await self.call('aiap_memory_propose', text='Legacy grant scenario')
            self.assertEqual(result['status'], 'proposed')
            review = self.core.review(self.owner, result['delta_id'], changes=True)
            self.assertNotIn('admission', review)

    async def test_invalid_classification_cannot_create_a_proposal(self):
        before = self.core.db.read_bytes()
        for arguments in ({'level': 'M0'}, {'level': 'M3'}, {'level': None},
                          {'memory_type': 'hypothesis'}, {'memory_type': None},
                          {'trigger': 'host-observation'}, {'confirm_new': 'true'}):
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
                    page = await call(session, 'aiap_memory_list', {'level': 'M1'})
                    self.assertEqual([r['excerpt'] for r in page['results']], [query])
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
