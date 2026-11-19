"""Exercise actual CLI initialization and server process restart."""
import unittest,tempfile,subprocess,sys,socket,json,os
from pathlib import Path
from aiap_core.client import Client,proposal
from aiap_core.contracts import Fault
from aiap_core.service import Service
ROOT=Path(__file__).resolve().parents[1]
class ProcessTests(unittest.TestCase):
    def test_local_procedural_registries(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            service = Service(data, enable_semantic=False)
            avatar = service.initialize()['avatar_id']
            owner = data / 'owner-credentials.json'
            adapter = data / 'adapter.json'
            adapter.write_text(json.dumps(service.issue_grant(['space:work'], 'capability-test', 'cli-test')))
            descriptor = data / 'descriptor.json'
            body = {'schema_version': '0.1', 'capability_id': 'aiap:capability:document.summary',
                    'name': 'Summarize a document', 'semantic_namespace': 'document.summary',
                    'description': 'Return the main points.', 'version': '1.0.0', 'status': 'active'}
            descriptor.write_text(json.dumps(body))
            db_before = service.db.read_bytes()

            def run(command, *options, kind='capability', space='space:work', credential=owner, error=None):
                result = subprocess.run(
                    [sys.executable, '-m', 'aiap_core', '--data-dir', directory, kind, command,
                     '--credential-file', str(credential), '--space', space, *options],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )
                if error:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.strip(), error)
                    return
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                return json.loads(result.stdout)

            target = ('--capability-id', body['capability_id'])
            source = ('--file', str(descriptor))
            run('get', *target, error='E_NOT_FOUND')
            self.assertEqual(run('list')['capabilities'], [])
            run('put', *source, '--base-revision', '0', credential=adapter, error='E_DENIED')
            first = run('put', *source, '--base-revision', '0')
            self.assertEqual(first['revision'], 1)
            read = run('get', *target)
            self.assertEqual(read['sha256'], first['sha256'])
            self.assertEqual(read['record']['descriptor'], body)
            self.assertEqual(read['record']['scope']['space_ref'], 'space:work')
            run('get', *target, space='space:life', error='E_NOT_FOUND')
            run('get', *target, credential=adapter, error='E_DENIED')
            revised = {**body, 'version': '1.1.0'}
            descriptor.write_text(json.dumps(revised))
            run('put', *source, '--base-revision', '0', error='E_VERSION_CONFLICT')
            self.assertEqual(run('get', *target), read)
            self.assertEqual(run('put', *source, '--base-revision', '1')['revision'], 2)
            current = run('get', *target)['record']
            self.assertEqual(current['previous_revision'], 1)
            self.assertEqual(current['descriptor'], revised)
            descriptor.write_text(json.dumps({**body, 'unknown_field': True}))
            run('put', *source, '--base-revision', '2', error='E_SCHEMA')
            self.assertEqual(run('get', *target)['record'], current)
            stored, = (data / 'local-capabilities').rglob('*.json')
            self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
            extra = {**body, 'capability_id': 'aiap:capability:document.compose', 'name': 'Compose a document'}
            descriptor.write_text(json.dumps(extra))
            run('put', *source, '--base-revision', '0')
            run('put', *source, '--base-revision', '0', space='space:life')
            first_page = run('list', '--limit', '1')
            second_page = run('list', '--limit', '1', '--after', first_page['next_after'])
            self.assertEqual([page['capabilities'][0]['capability_id'] for page in (first_page, second_page)],
                             [extra['capability_id'], body['capability_id']])
            self.assertEqual(second_page['capabilities'][0]['revision'], 2)
            self.assertIsNone(second_page['next_after'])
            self.assertNotIn('description', second_page['capabilities'][0])
            self.assertEqual(len(run('list', space='space:life')['capabilities']), 1)
            run('list', credential=adapter, error='E_DENIED')
            workflow_id = 'aiap:workflow:document.review'
            workflow = {'schema_version': '0.1', 'workflow_id': workflow_id, 'owner_avatar_id': avatar,
                        'name': 'Review a document', 'intent': 'Review before sharing', 'origin': 'user_defined',
                        'version': '1.0.0', 'status': 'personal', 'steps': [
                            {'step_id': 'summarize', 'capability_id': body['capability_id'], 'required': False},
                            {'step_id': 'compose', 'capability_id': extra['capability_id'], 'depends_on': ['summarize']},
                        ]}
            workflow_source = data / 'workflow.json'
            command = ('--file', str(workflow_source), '--base-revision')
            workflow_target = ('--workflow-id', workflow_id)
            workflow_source.write_text(json.dumps({**workflow, 'owner_avatar_id': 'avatar:other'}))
            run('put', *command, '0', kind='workflow', error='E_SCOPE')
            cyclic = {**workflow, 'steps': [{**workflow['steps'][0], 'depends_on': ['compose']}, workflow['steps'][1]]}
            workflow_source.write_text(json.dumps(cyclic))
            run('put', *command, '0', kind='workflow', error='E_WORKFLOW_GRAPH')
            workflow_source.write_text(json.dumps(workflow))
            run('put', *command, '0', kind='workflow', space='space:life', error='E_WORKFLOW_CAPABILITY')
            run('put', *command, '0', kind='workflow', credential=adapter, error='E_DENIED')
            saved = run('put', *command, '0', kind='workflow')
            self.assertEqual(run('list', kind='workflow')['workflows'][0]['workflow_id'], workflow_id)
            read = run('get', *workflow_target, kind='workflow')
            self.assertEqual(read['sha256'], saved['sha256'])
            self.assertEqual(read['record']['descriptor'], workflow)
            self.assertEqual(read['record']['capability_refs'][body['capability_id']]['revision'], 2)
            self.assertEqual(read['stale_capability_ids'], [])
            run('put', *command, '0', kind='workflow', error='E_VERSION_CONFLICT')
            binding = {'schema_version': '0.1', 'binding_id': 'aiap:binding:document.summary',
                       'capability_id': body['capability_id'], 'runtime': {'runtime_id': 'fixture-runtime'},
                       'implementation': {'type': 'tool', 'ref': 'summarize'}, 'mapping_class': 'partial',
                       'confidence': 0.5, 'status': 'active'}
            binding_source = data / 'binding.json'
            binding_source.write_text(json.dumps(binding))
            binding_args = ('--file', str(binding_source), '--base-revision', '0')
            binding_target = ('--binding-id', binding['binding_id'])
            run('put', *binding_args, kind='runtime-binding', space='space:life', error='E_BINDING_CAPABILITY')
            run('put', *binding_args, kind='runtime-binding')
            binding_read = run('get', *binding_target, kind='runtime-binding')
            self.assertEqual(binding_read['record']['descriptor'], binding)
            self.assertEqual(binding_read['stale_capability_ids'], [])
            self.assertEqual(run('list', kind='runtime-binding')['bindings'][0]['mapping_class'], 'partial')
            runtime_options = ('--runtime-id', 'fixture-runtime', '--runtime-version', '1')
            preview = run('resolve', *workflow_target, *runtime_options, kind='workflow')
            self.assertEqual(preview['status'], 'unresolved')
            self.assertEqual(preview['workflow_sha256'], saved['sha256'])
            self.assertEqual([step['step_id'] for step in preview['steps']], ['summarize', 'compose'])
            self.assertFalse(preview['steps'][0]['required'])
            self.assertTrue(preview['steps'][0]['required_for_workflow'])
            self.assertEqual(preview['capabilities'][body['capability_id']]['bindings'][0]['reasons'],
                             ['mapping-class-not-accepted'])
            run('resolve', *workflow_target, *runtime_options, kind='workflow', credential=adapter, error='E_DENIED')
            run('resolve', *workflow_target, *runtime_options, kind='workflow', space='space:life', error='E_NOT_FOUND')
            for capability, name, confirmation in [(body, 'summary-exact', False), (extra, 'compose-exact', True)]:
                binding_source.write_text(json.dumps({
                    **binding, 'binding_id': f'aiap:binding:document.{name}', 'capability_id': capability['capability_id'],
                    'runtime': {'runtime_id': 'fixture-runtime', 'runtime_version': '1'},
                    'implementation': {'type': 'tool', 'ref': name},
                    'mapping_class': 'exact', 'requires_user_confirmation': confirmation,
                }))
                run('put', *binding_args, kind='runtime-binding')
            preview = run('resolve', *workflow_target, *runtime_options, kind='workflow')
            self.assertEqual(preview['status'], 'confirmation-required')
            self.assertEqual([step['status'] for step in preview['steps']], ['candidate', 'confirmation-required'])
            capability_preview = run('resolve', *target, *runtime_options)
            self.assertEqual(capability_preview['bindings'], preview['capabilities'][body['capability_id']]['bindings'])
            self.assertNotIn('agent_inventory', preview)
            inventory_file = data / 'agent-inventory.json'
            inventory_options = ('--agent-inventory', str(inventory_file))
            inventory = {
                'agent_id': 'research', 'avatar_id': avatar, 'space_ref': 'space:work',
                'runtime_id': 'fixture-runtime', 'runtime_version': '1', 'implementations': [
                    {'type': 'tool', 'ref': 'summary-exact'},
                    {'type': 'skill', 'ref': 'compose-exact'},
                ],
            }
            inventory_file.write_text(json.dumps(inventory))
            restricted = run('resolve', *workflow_target, *runtime_options, *inventory_options, kind='workflow')
            self.assertEqual(restricted['agent_inventory']['agent_id'], 'research')
            self.assertEqual(restricted['agent_inventory']['source'], 'owner-supplied')
            self.assertEqual(restricted['status'], 'unresolved')
            self.assertEqual([step['status'] for step in restricted['steps']], ['candidate', 'unresolved'])
            self.assertEqual(restricted['capabilities'][extra['capability_id']]['bindings'][0]['reasons'],
                             ['implementation-unavailable-for-agent'])
            direct = run('resolve', *target, *runtime_options, *inventory_options)
            self.assertEqual(direct['bindings'], restricted['capabilities'][body['capability_id']]['bindings'])
            selection = [{'type': 'tool', 'ref': 'compose-exact'}]
            inventory_file.write_text(json.dumps({**inventory, 'agent_id': 'writer', 'implementations': selection}))
            writer = run('resolve', *workflow_target, *runtime_options, *inventory_options, kind='workflow')
            self.assertEqual([step['status'] for step in writer['steps']], ['unresolved', 'confirmation-required'])
            self.assertNotEqual(writer['agent_inventory']['sha256'], restricted['agent_inventory']['sha256'])
            inventory_file.write_text(json.dumps({**inventory, 'implementations': []}))
            self.assertEqual(run('resolve', *target, *runtime_options, *inventory_options)['status'], 'unresolved')
            for field, value in [('avatar_id', 'avatar:other'), ('space_ref', 'space:life'),
                                 ('runtime_id', 'other-runtime'), ('runtime_version', '2')]:
                inventory_file.write_text(json.dumps({**inventory, field: value}))
                run('resolve', *target, *runtime_options, *inventory_options, error='E_AGENT_INVENTORY_SCOPE')
            inventory_file.write_text(json.dumps({**inventory, 'implementations': selection * 2}))
            run('resolve', *target, *runtime_options, *inventory_options, error='E_AGENT_INVENTORY')
            mismatched = run('resolve', *target, '--runtime-id', 'fixture-runtime', '--runtime-version', '2')
            self.assertEqual(mismatched['status'], 'unresolved')
            self.assertTrue(any(row['reasons'] == ['runtime-version-mismatch'] for row in mismatched['bindings']))
            descriptor.write_text(json.dumps({**revised, 'version': '1.2.0'}))
            run('put', *source, '--base-revision', '2')
            self.assertEqual(run('get', *workflow_target, kind='workflow')['stale_capability_ids'], [body['capability_id']])
            self.assertEqual(run('get', *binding_target, kind='runtime-binding')['stale_capability_ids'],
                             [body['capability_id']])
            stale = run('resolve', *workflow_target, *runtime_options, kind='workflow')
            self.assertEqual(stale['status'], 'blocked')
            self.assertEqual(stale['capabilities'][body['capability_id']]['reason'], 'stale-capability')
            self.assertEqual(run('put', *command, '1', kind='workflow')['revision'], 2)
            self.assertEqual(run('get', *workflow_target, kind='workflow')['stale_capability_ids'], [])
            self.assertEqual(service.db.read_bytes(), db_before)

    def test_local_session_capture_requires_explicit_input_and_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            service = Service(data, enable_semantic=False)
            service.initialize()
            owner_file = data / 'owner-credentials.json'
            owner = json.loads(owner_file.read_text())['token']
            adapter = service.issue_grant(['space:work'], 'session-capture', 'cli-test')
            adapter_file = data / 'adapter.json'
            adapter_file.write_text(json.dumps(adapter))

            def capture(raw, *options, space='space:work'):
                return subprocess.run(
                    [sys.executable, '-m', 'aiap_core', '--data-dir', directory, 'capture-session',
                     '--credential-file', str(adapter_file), '--space', space, *options],
                    input=raw, cwd=ROOT, capture_output=True, timeout=10,
                )

            excerpt = '当前任务要点\n保留原文。\n'
            preview = capture(excerpt.encode(), '--preview')
            self.assertEqual(preview.returncode, 0, preview.stdout)
            self.assertEqual(json.loads(preview.stdout), {
                'status': 'preview', 'space_ref': 'space:work', 'level': 'M1',
                'source_type': 'observed', 'characters': len(excerpt),
            })
            self.assertEqual(service.pending_proposals(owner)['proposals'], [])
            for invalid in (b'  \n', b'\xff', b'abc\x00', b'x' * 16001):
                failure = capture(invalid)
                self.assertNotEqual(failure.returncode, 0)
                self.assertEqual(failure.stdout.strip(), b'E_SESSION_EXCERPT')
            denied = capture(excerpt.encode(), '--preview', space='space:life')
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(denied.stdout.strip(), b'E_DENIED')
            bad_id = capture(excerpt.encode(), '--capture-id', 'a/path')
            self.assertNotEqual(bad_id.returncode, 0)
            self.assertEqual(bad_id.stdout.strip(), b'E_CAPTURE_ID')
            capture_options = ('--capture-id', 'fixture:same-task')
            submitted = capture(excerpt.encode(), *capture_options)
            self.assertEqual(submitted.returncode, 0, submitted.stdout)
            self.assertNotIn(excerpt.encode(), submitted.stdout)
            delta_id = json.loads(submitted.stdout)['delta_id']
            repeated = capture(excerpt.encode(), *capture_options)
            self.assertEqual(json.loads(repeated.stdout), {'delta_id': delta_id, 'status': 'proposed', 'idempotent': True})
            self.assertEqual(len(service.pending_proposals(owner)['proposals']), 1)
            changed = capture(b'Different selected text', *capture_options)
            self.assertNotEqual(changed.returncode, 0)
            self.assertEqual(changed.stdout.strip(), b'E_IDEMPOTENCY_CONFLICT')
            request = {'space_refs': ['space:work'], 'purpose': 'session-capture', 'query': '任务'}
            self.assertEqual(service.search(adapter['token'], request)['items'], [])
            service.decide(owner, delta_id, True)
            repeated = capture(excerpt.encode(), *capture_options)
            self.assertEqual(json.loads(repeated.stdout), {'delta_id': delta_id, 'status': 'accepted', 'idempotent': True})
            stored, = service.search(adapter['token'], request)['items']
            self.assertEqual(stored['content'], excerpt)
            self.assertEqual(stored['level'], 'M1')
            self.assertEqual(stored['source']['source_type'], 'observed')
            self.assertFalse(stored['source']['verified'])

    def test_local_promotion_preserves_provenance_and_rejects_stale_proposals(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            service = Service(data, enable_semantic=False)
            service.initialize()
            owner_file = data / 'owner-credentials.json'
            owner = json.loads(owner_file.read_text())['token']
            adapter_file = data / 'adapter.json'
            adapter_file.write_text(json.dumps(service.issue_grant(['space:work'], 'task', 'cli-test')))

            def run(command, *args, credential=owner_file, error=None):
                result = subprocess.run(
                    [sys.executable, '-m', 'aiap_core', '--data-dir', directory, command,
                     '--credential-file', str(credential), *args],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )
                if error:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.strip(), error)
                    return
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                return json.loads(result.stdout)

            draft = run('propose', '--local', '--space', 'space:work', '--level', 'M1',
                        '--text', 'Task fixture', '--pinned', credential=adapter_file)
            record = run('decide', '--local', '--delta-id', draft['delta_id'], '--approve')['objects'][0]
            def current():
                return run('search', '--local', '--space', 'space:work')['items'][0]
            original = current()
            self.assertEqual(original['level'], 'M1')
            target = ('--space', 'space:work', '--memory-id', record['memory_id'],
                      '--base-revision', str(record['revision']))
            reason = 'Retain for future tasks'
            run('propose-promotion', *target, '--reason', reason, credential=adapter_file, error='E_DENIED')
            run('propose-promotion', *target, '--reason', ' ', error='E_LIFECYCLE_TRANSITION')
            draft = run('propose-promotion', *target, '--reason', reason)
            competing = run('propose-promotion', *target, '--reason', 'Same baseline')
            change = run('review', '--local', '--changes', '--delta-id', draft['delta_id'])['changes'][0]
            self.assertEqual((change['current_level'], change['proposed_level'], change['transition_reason']),
                             ('M1', 'M2', reason))
            self.assertEqual(current(), original)
            with self.assertRaisesRegex(Fault, 'E_OPERATION_UNSUPPORTED'):
                service.decide(owner, draft['delta_id'], True)
            run('decide', '--local', '--delta-id', draft['delta_id'], '--approve')
            updated = current()
            self.assertEqual(updated['level'], 'M2')
            self.assertEqual(updated['revision'], original['revision'] + 1)
            for field in ('content', 'source', 'confidence', 'lifecycle', 'scope'):
                self.assertEqual(updated[field], original[field])
            self.assertTrue(updated['retention']['pinned'])
            self.assertEqual(updated['retention']['last_transition']['reason'], reason)
            run('decide', '--local', '--delta-id', competing['delta_id'], '--approve', error='E_VERSION_CONFLICT')
            events = run('audit', '--space', 'space:work', '--object-id', record['memory_id'], '--event', 'memory-promoted')
            self.assertEqual(len(events['events']), 1)
            latest_target = ('--space', 'space:work', '--memory-id', record['memory_id'],
                             '--base-revision', str(updated['revision']))
            run('propose-archive', *latest_target, '--reason', 'Project completed', credential=adapter_file, error='E_DENIED')
            archived = run('propose-archive', *latest_target, '--reason', 'Project completed')
            self.assertEqual(current(), updated)
            preview = run('review', '--local', '--changes', '--delta-id', archived['delta_id'])['changes'][0]
            self.assertEqual((preview['current_level'], preview['proposed_level']), ('M2', 'M3'))
            archived_record = run('decide', '--local', '--delta-id', archived['delta_id'], '--approve')['objects'][0]
            self.assertEqual(run('search', '--local', '--space', 'space:work')['items'], [])
            archived_memory = run('search', '--local', '--space', 'space:work', '--include-archived',
                                  credential=adapter_file)['items'][0]
            self.assertEqual(archived_memory['level'], 'M3')
            self.assertEqual(archived_memory['source'], original['source'])
            self.assertEqual(archived_memory['lifecycle'], original['lifecycle'])
            self.assertTrue(archived_memory['retention']['pinned'])
            self.assertEqual(archived_memory['retention']['demotion_count'], 1)
            reactivated = run('propose-reactivation', '--space', 'space:work', '--memory-id', archived_record['memory_id'],
                              '--base-revision', str(archived_record['revision']), '--reason', 'Current task')
            run('decide', '--local', '--delta-id', reactivated['delta_id'], '--approve')
            result = current()
            self.assertEqual(result['level'], 'M1')
            self.assertEqual(result['retention']['demotion_count'], 1)

    def test_local_proposal_update_and_confirmed_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            service = Service(data, enable_semantic=False)
            service.initialize()
            owner = data / 'owner-credentials.json'
            adapter = data / 'adapter.json'
            adapter.write_text(json.dumps(service.issue_grant(['space:work'], 'workflow', 'terminal')))

            def run(command, *options, credential=owner, error=None):
                process = subprocess.run(
                    [sys.executable, '-m', 'aiap_core', '--data-dir', directory, command,
                     '--credential-file', str(credential), *options],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )
                if error:
                    self.assertNotEqual(process.returncode, 0)
                    self.assertIn(error, process.stderr or process.stdout)
                    return
                self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
                return json.loads(process.stdout)

            run('propose', '--local', '--space', 'space:life', '--text', 'fixture',
                credential=adapter, error='E_DENIED')
            proposal_result = run('propose', '--local', '--space', 'space:work', '--text', 'fixture',
                                  '--pinned', credential=adapter)
            self.assertEqual(proposal_result['status'], 'proposed')
            self.assertEqual(run('search', '--local', '--space', 'space:work')['count'], 0)
            draft_preview = run('review', '--local', '--changes', '--delta-id', proposal_result['delta_id'])['changes'][0]
            self.assertEqual(draft_preview['operation'], 'add')
            self.assertIsNone(draft_preview['current_text'])
            self.assertEqual(draft_preview['proposed_text'], 'fixture')
            self.assertIsNone(draft_preview['current_classification'])
            self.assertEqual(draft_preview['proposed_classification']['level'], 'M2')
            self.assertFalse(draft_preview['revision_conflict'])
            run('review', '--local', '--changes', '--delta-id', proposal_result['delta_id'], credential=adapter,
                error='E_DENIED')
            run('review', '--changes', '--delta-id', proposal_result['delta_id'], error='requires --local')
            run('decide', '--local', '--delta-id', proposal_result['delta_id'], '--approve')
            self.assertEqual(run('review', '--local', '--changes', '--delta-id', proposal_result['delta_id'])['changes'], [])
            record = run('search', '--local', '--space', 'space:work')['items'][0]
            update_target = ('--space', 'space:work', '--memory-id', record['memory_id'])
            update_revision = ('--base-revision', str(record['revision']))
            run('propose', '--local', *update_target, '--text', 'missing revision', error='--base-revision')
            run('propose', *update_target, *update_revision, '--text', 'missing local', error='--local')
            run('propose', '--local', '--space', 'space:life', '--memory-id', record['memory_id'],
                *update_revision, '--text', 'outside grant', credential=adapter, error='E_DENIED')
            run('propose', '--local', '--space', 'space:life', '--memory-id', record['memory_id'],
                *update_revision, '--text', 'wrong space', error='E_NOT_FOUND')
            first = run('propose', '--local', *update_target, *update_revision, '--text', 'first edit', credential=adapter)
            second = run('propose', '--local', *update_target, *update_revision, '--text', 'second edit', credential=adapter)
            self.assertEqual(run('search', '--local', '--space', 'space:work')['items'], [record])
            run('decide', '--local', '--delta-id', first['delta_id'], '--approve')
            conflict = run('review', '--local', '--changes', '--delta-id', second['delta_id'])['changes'][0]
            self.assertEqual((conflict['current_text'], conflict['proposed_text']), ('first edit', 'second edit'))
            self.assertEqual((conflict['base_revision'], conflict['current_revision']), (record['revision'], record['revision'] + 1))
            self.assertTrue(conflict['revision_conflict'])
            run('decide', '--local', '--delta-id', second['delta_id'], '--approve', error='E_VERSION_CONFLICT')
            run('propose', '--local', *update_target, *update_revision, '--text', 'stale edit', error='E_VERSION_CONFLICT')
            edited = run('search', '--local', '--space', 'space:work')['items'][0]
            self.assertEqual(edited['content'], 'first edit')
            self.assertEqual(edited['revision'], record['revision'] + 1)
            self.assertEqual(edited['previous_revision'], record['revision'])
            self.assertEqual(edited['retention'], record['retention'])
            self.assertTrue(edited['lifecycle']['stable_preference'])
            self.assertEqual(edited['type'], record['type'])
            run('history', *update_target, credential=adapter, error='E_DENIED')
            run('history', '--space', 'space:life', '--memory-id', record['memory_id'], error='E_NOT_FOUND')
            run('history', *update_target, '--revision', str(edited['revision'] + 1), error='E_NOT_FOUND')
            history_page = run('history', *update_target, '--limit', '1')
            self.assertEqual(history_page['revisions'], [edited['revision']])
            self.assertEqual(history_page['current_revision'], edited['revision'])
            self.assertNotIn('record', history_page)
            history_tail = run('history', *update_target, '--limit', '1', '--before', str(history_page['next_before']))
            self.assertEqual(history_tail['revisions'], [record['revision']])
            self.assertIsNone(history_tail['next_before'])
            self.assertEqual(run('history', *update_target, '--revision', str(record['revision']))['record'], record)
            self.assertEqual(run('history', *update_target, '--revision', str(edited['revision']))['record'], edited)
            restore_options = ('--local', *update_target, '--base-revision', str(edited['revision']),
                               '--from-revision', str(record['revision']))
            run('propose', *restore_options, credential=adapter, error='E_DENIED')
            run('propose', *restore_options, '--text', 'ambiguous', error='not allowed with argument')
            run('propose', '--local', '--space', 'space:work', '--from-revision', '1', error='--base-revision')
            run('propose', *restore_options[:-1], str(edited['revision']), error='earlier than')
            restore = run('propose', *restore_options)
            self.assertEqual(restore['status'], 'proposed')
            self.assertEqual(run('search', '--local', '--space', 'space:work')['items'], [edited])
            run('decide', '--local', '--delta-id', restore['delta_id'], '--approve')
            run('propose', *restore_options, error='E_VERSION_CONFLICT')
            restored = run('search', '--local', '--space', 'space:work')['items'][0]
            self.assertEqual(restored['content'], record['content'])
            self.assertEqual(restored['revision'], edited['revision'] + 1)
            self.assertEqual(restored['previous_revision'], edited['revision'])
            self.assertEqual(restored['retention'], edited['retention'])
            self.assertEqual(run('history', *update_target)['revisions'],
                             [restored['revision'], edited['revision'], record['revision']])
            record = restored
            target = ('--space', 'space:work', '--memory-id', record['memory_id'])
            revision = ('--base-revision', str(record['revision']))
            run('delete', '--local', *target, *revision, error='--confirm')
            run('delete', '--confirm', *target, *revision, error='--local')
            run('delete', '--local', '--confirm', *target, *revision, credential=adapter, error='E_DENIED')
            run('delete', '--local', '--confirm', *target, '--base-revision', str(record['revision'] + 1),
                error='E_VERSION_CONFLICT')
            self.assertEqual(run('search', '--local', '--space', 'space:work')['count'], 1)
            result = run('delete', '--local', '--confirm', *target, *revision)
            self.assertTrue(result['deleted'])
            self.assertEqual(result['tombstone']['object_ref'], {'id': record['memory_id'], 'version': record['revision']})
            self.assertEqual(run('search', '--local', '--space', 'space:work')['count'], 0)
            run('history', *target, error='E_NOT_FOUND')
            run('delete', '--local', '--confirm', *target, *revision, error='E_NOT_FOUND')

    def test_local_owner_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            service = Service(data, enable_semantic=False)
            service.initialize()
            owner_file = data / 'owner-credentials.json'

            def credential(spaces, role):
                grant = service.issue_grant(spaces, 'local-review-test', 'cli-test', role=role)
                path = data / (role + '.json')
                path.write_text(json.dumps(grant))
                return grant['token'], path

            _, scoped_owner_file = credential(['space:work'], 'owner')
            adapter, adapter_file = credential(['space:work', 'space:life'], 'adapter')
            session = service.session(adapter)
            draft = proposal(session, 'space:work', 'local workflow fixture')
            work_id = service.propose(adapter, draft)['delta_id']
            mixed = proposal(session, 'space:work', 'mixed draft fixture')
            life = proposal(session, 'space:life', 'life draft fixture')
            mixed['request']['space_refs'].append('space:life')
            mixed['delta']['changes'].extend(life['delta']['changes'])
            mixed['bindings'].extend(life['bindings'])
            mixed_id = service.propose(adapter, mixed)['delta_id']

            def run(command, *options, file=owner_file, error=None):
                result = subprocess.run(
                    [sys.executable, '-m', 'aiap_core', '--data-dir', directory, command,
                     '--credential-file', str(file), *options],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )
                if error:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout.strip(), error)
                    return
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                return json.loads(result.stdout)

            run('pending', file=adapter_file, error='E_DENIED')
            run('summary', file=adapter_file, error='E_DENIED')
            run('summary', '--space', 'space:life', file=scoped_owner_file, error='E_DENIED')
            scoped_summary = run('summary', file=scoped_owner_file)['spaces']
            self.assertEqual(scoped_summary, [{'space_ref': 'space:work', 'active_memories': 0,
                                                'archived_memories': 0, 'pending_proposals': 1}])
            run('review', '--local', '--changes', '--delta-id', mixed_id, file=scoped_owner_file, error='E_NOT_FOUND')
            scoped = run('pending', '--space', 'space:work', '--limit', '1', file=scoped_owner_file)
            self.assertEqual(scoped, {'proposals': [{'delta_id': work_id, 'space_refs': ['space:work']}],
                                      'next_after': None})
            first = run('pending', '--space', 'space:work', '--limit', '1')
            second = run('pending', '--space', 'space:work', '--limit', '1', '--after', first['next_after'])
            self.assertEqual([page['proposals'][0]['delta_id'] for page in (first, second)],
                             sorted([work_id, mixed_id]))
            self.assertIsNone(second['next_after'])
            self.assertNotIn('fixture', json.dumps([first, second]))
            run('pending', '--space', 'space:life', file=scoped_owner_file, error='E_DENIED')
            self.assertEqual(run('search', '--local', '--space', 'space:work')['count'], 0)
            self.assertEqual(run('review', '--local', '--delta-id', work_id)['status'], 'proposed')
            self.assertEqual(run('decide', '--local', '--delta-id', work_id, '--approve')['status'], 'accepted')
            self.assertEqual(run('pending', file=scoped_owner_file)['proposals'], [])
            archive = proposal(session, 'space:life', 'archived summary fixture', level='M3')
            archive_id = service.propose(adapter, archive)['delta_id']
            run('decide', '--local', '--delta-id', archive_id, '--approve')
            summary = {item['space_ref']: item for item in run('summary')['spaces']}
            self.assertEqual(summary['space:general'], {'space_ref': 'space:general', 'active_memories': 0,
                                                        'archived_memories': 0, 'pending_proposals': 0})
            self.assertEqual(summary['space:work'], {'space_ref': 'space:work', 'active_memories': 1,
                                                     'archived_memories': 0, 'pending_proposals': 1})
            self.assertEqual(summary['space:life'], {'space_ref': 'space:life', 'active_memories': 0,
                                                     'archived_memories': 1, 'pending_proposals': 1})
            self.assertEqual(run('summary', '--space', 'space:work')['spaces'], [summary['space:work']])
            record = run('search', '--local', '--space', 'space:work', '--query', 'local workflow')['items'][0]
            preview = run('delete-preview', '--local', '--space', 'space:work',
                          '--memory-id', record['memory_id'], '--base-revision', str(record['revision']))
            self.assertEqual(preview['memory_id'], record['memory_id'])
            self.assertEqual(run('search', '--local', '--space', 'space:work')['count'], 1)
            context = run('context', '--space', 'space:work', '--query', 'local workflow', '--limit', '1', file=adapter_file)
            view = context['authorized_view']
            self.assertEqual(view['space_refs'], ['space:work'])
            self.assertEqual([obj['id'] for obj in view['objects']], [record['memory_id']])
            self.assertEqual(context['items'][0]['lifecycle']['context_use_count'], 0)
            unchanged = run('search', '--local', '--space', 'space:work')['items'][0]
            self.assertEqual(unchanged['revision'], record['revision'])
            self.assertIsNone(unchanged['lifecycle']['last_used_at'])
            run('context-ack', '--view-id', view['view_id'], error='E_NOT_FOUND')
            self.assertFalse(run('context-ack', '--view-id', view['view_id'], file=adapter_file)['idempotent'])
            self.assertTrue(run('context-ack', '--view-id', view['view_id'], file=adapter_file)['idempotent'])
            used = run('search', '--local', '--space', 'space:work')['items'][0]
            self.assertEqual(used['lifecycle']['context_use_count'], 1)
            self.assertEqual(used['lifecycle']['confirmed_use_count'], 0)
            target = ('--space', 'space:work', '--memory-id', used['memory_id'],
                      '--base-revision', str(used['revision']))
            run('confirm-use', *target, file=adapter_file, error='E_DENIED')
            feedback = run('confirm-use', *target, file=scoped_owner_file)
            self.assertEqual(feedback['confirmed_use_count'], 1)
            self.assertEqual(feedback['revision'], used['revision'] + 1)
            run('confirm-use', *target, file=scoped_owner_file, error='E_VERSION_CONFLICT')
            confirmed = run('search', '--local', '--space', 'space:work')['items'][0]
            self.assertEqual(confirmed['lifecycle']['context_use_count'], 1)
            self.assertEqual(confirmed['lifecycle']['confirmed_use_count'], 1)
            self.assertEqual(confirmed['content'], used['content'])
            self.assertEqual(confirmed['source'], used['source'])
            feedback_events = run('audit', '--space', 'space:work', '--event', 'memory-use-confirmed',
                                  '--object-id', record['memory_id'], file=scoped_owner_file)['events']
            self.assertEqual(len(feedback_events), 1)
            service.revoke_grant(session['auth_evidence_ref'])
            self.assertEqual(run('pending')['proposals'][0]['delta_id'], mixed_id)
            run('decide', '--local', '--delta-id', mixed_id, '--approve', error='E_IDENTITY')
            self.assertEqual(run('decide', '--local', '--delta-id', mixed_id)['status'], 'rejected')
            self.assertEqual(run('pending')['proposals'], [])

    def test_actual_process_restart(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=[sys.executable,'-m','aiap_core','--data-dir',d]
            subprocess.run(cmd+['init'],cwd=ROOT,check=True,capture_output=True,text=True)
            token=json.loads((Path(d)/'owner-credentials.json').read_text())['token']
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            def start():
                proc=subprocess.Popen(cmd+['serve','--port',str(port),'--archive-interval','0'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                line=proc.stdout.readline()
                if 'listening' not in line:
                    proc.terminate();proc.wait(timeout=5);raise AssertionError('Server did not start')
                return proc
            client=Client('http://127.0.0.1:'+str(port),token);proc=start()
            try:
                session=client.call('/v1/session');p=proposal(session,'space:work','PROCESS_PERSISTENCE');r=client.call('/v1/deltas/propose',p);client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True});avatar=session['avatar_id']
            finally:proc.terminate();proc.communicate(timeout=5)
            proc=start()
            try:
                self.assertEqual(client.call('/v1/session')['avatar_id'],avatar)
                r=client.call('/v1/search',{'space_refs':['space:work'],'purpose':'owner-maintenance','query':'PROCESS_PERSISTENCE'});self.assertEqual(r['count'],1)
            finally:proc.terminate();proc.communicate(timeout=5)
