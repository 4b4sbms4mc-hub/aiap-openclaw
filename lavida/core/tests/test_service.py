import unittest,tempfile,json,copy,threading,concurrent.futures,urllib.request,urllib.error,sqlite3
from pathlib import Path
from datetime import datetime,timezone,timedelta
from aiap_core.service import Service
from aiap_core.client import Client,proposal
from aiap_core.server import Server
from aiap_core.contracts import Fault,validate,canonical

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.now=datetime(2026,9,19,tzinfo=timezone.utc);self.s=Service(self.tmp.name,clock=lambda:self.now);self.s.initialize()
        self.owner=json.loads((Path(self.tmp.name)/'owner-credentials.json').read_text())['token']
        self.work=self.s.issue_grant(['space:work'],'work-task','test-work')['token'];self.life=self.s.issue_grant(['space:life'],'life-task','test-life')['token']
    def tearDown(self):self.tmp.cleanup()
    def draft(self,text='work fact',space='space:work',token=None,**kwargs):return proposal(self.s.session(token or self.work),space,text,**kwargs)
    def add(self,text='work fact',space='space:work',token=None,**kwargs):
        p=self.draft(text,space,token,**kwargs);t=token or self.work;r=self.s.propose(t,p);self.s.decide(self.owner,r['delta_id'],True);return p['bindings'][0]['target_object_id']
    def search(self,token=None,space='space:work',**kwargs):
        t=token or self.work;return self.s.search(t,{'space_refs':[space],'purpose':self.s.session(t)['purpose'],'query':'',**kwargs})['items']
    def fault(self,code,call):
        with self.assertRaises(Fault) as cm:call()
        self.assertEqual(cm.exception.code,code)
    def test_initial_identity_and_signature(self):
        r=self.s.core(self.owner);validate('avatar-core',r['avatar_core']);self.assertTrue(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))

    def test_local_reactivation_restarts_archive_period_without_recording_use(self):
        memory_id = self.add('Old task fixture', level='M1')
        self.now += timedelta(days=31)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)
        owner = self.s.issue_grant(['space:work'], 'review', 'owner-local', role='owner', days=30)['token']
        original, = self.search(token=owner, include_archived=True)
        self.assertEqual(self.search(token=owner), [])
        proposal_result = self.s.propose_lifecycle(owner, 'space:work', memory_id, original['revision'],
                                                   kind='reactivate', reason='Task resumed')
        self.assertEqual(self.search(token=owner), [])
        self.s.decide(owner, proposal_result['delta_id'], True, allow_lifecycle=True)
        reactivated, = self.search(token=owner)
        self.assertEqual(reactivated['level'], 'M1')
        self.assertEqual(reactivated['source'], original['source'])
        self.assertEqual(reactivated['lifecycle'], original['lifecycle'])
        self.assertEqual(reactivated['retention']['last_transition']['from'], 'M3')
        self.now += timedelta(days=29)
        self.assertEqual(self.s.archive_cycle()['archived'], 0)
        self.now += timedelta(days=1)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)

    def test_promotion_starts_full_m2_period_only_after_approval(self):
        memory_id = self.add('Project decision', level='M1')
        self.now += timedelta(days=35)
        owner = self.s.issue_grant(['space:work'], 'review', 'fixture', role='owner')['token']
        original, = self.search(token=owner)
        pending = self.s.propose_lifecycle(owner, 'space:work', memory_id, original['revision'],
                                           kind='promote', reason='Decision adopted for future projects')
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 1)
        self.now += timedelta(days=1)
        self.s.decide(owner, pending['delta_id'], True, allow_lifecycle=True)
        promoted, = self.search(token=owner)
        self.assertEqual(promoted['level'], 'M2')
        self.assertEqual(promoted['lifecycle'], original['lifecycle'])
        self.now += timedelta(days=180, microseconds=-1)
        self.assertEqual(self.s.archive_cycle()['archived'], 0)
        self.now += timedelta(microseconds=1)
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 1)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)

    def test_archive_waits_when_clock_precedes_promotion(self):
        memory_id = self.add('Long-running decision', level='M1')
        self.now += timedelta(days=200)
        owner = self.s.issue_grant(['space:work'], 'review', 'fixture', role='owner')['token']
        pending = self.s.propose_lifecycle(owner, 'space:work', memory_id, 1,
                                           kind='promote', reason='Long-term decision')
        self.s.decide(owner, pending['delta_id'], True, allow_lifecycle=True)
        self.now -= timedelta(days=1)
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 0)
        self.assertEqual(self.s.archive_cycle()['archived'], 0)
        self.now += timedelta(days=181)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)

    def test_text_correction_preserves_policy_without_aliasing_original(self):
        self.add('Original preference', pinned=True)
        original, = self.search()
        draft = self.draft('Corrected preference', old=original)
        candidate = draft['delta']['changes'][0]['candidate']
        for field in ('type', 'retention', 'lifecycle'):
            self.assertEqual(candidate[field], original[field])
        self.assertIsNot(candidate['retention'], original['retention'])
        self.assertIsNot(candidate['lifecycle']['active_task_refs'], original['lifecycle']['active_task_refs'])
        pending = self.s.propose(self.work, draft)
        self.s.decide(self.owner, pending['delta_id'], True)
        corrected, = self.search()
        self.assertEqual(corrected['retention'], original['retention'])
        self.assertTrue(corrected['lifecycle']['stable_preference'])

    def test_ordinary_edit_preserves_archived_level(self):
        ident = self.add('Task draft', level='M1')
        archive = self.s.propose_lifecycle(self.owner, 'space:work', ident, 1,
                                           kind='archive', reason='Finished')
        self.s.decide(self.owner, archive['delta_id'], True, allow_lifecycle=True)
        old, = self.search(include_archived=True)
        for level in ('M1', 'M2'):
            invalid = self.draft('Correction', old=old, level=level)
            self.fault('E_LIFECYCLE_TRANSITION', lambda: self.s.propose(self.work, invalid))
        edit = self.s.propose(self.work, self.draft('Correction', old=old))
        self.s.decide(self.owner, edit['delta_id'], True)
        self.assertEqual(self.search(), [])
        revised, = self.search(include_archived=True)
        self.assertEqual((revised['content'], revised['level']), ('Correction', 'M3'))

    def test_proposal_preflight_is_scoped_read_only_and_reports_candidates(self):
        identifier = self.add('以后请默认用中文回复。', pinned=True)
        self.add('仅其他空间可见的内容', token=self.life, space='space:life', pinned=True)
        payload = {'space_ref': 'space:work', 'purpose': 'work-task', 'text': '以后请默认用中文回复。',
                   'level': 'M2', 'memory_type': 'preference-evidence', 'trigger': 'user-request'}
        database_before = self.s.db.read_bytes()

        def preflight(**changes):
            return self.s.preflight_candidate(self.work, {**payload, **changes})

        duplicate = preflight()
        self.assertEqual((duplicate['status'], duplicate['reason']), ('duplicate', 'same-active-memory'))
        self.assertEqual(duplicate['matches'][0]['memory_id'], identifier)
        self.assertNotIn(payload['text'], json.dumps(duplicate, ensure_ascii=False))
        revised = preflight(text='以后请默认用英文回复。')
        self.assertEqual(revised['status'], 'review-revision')
        self.assertEqual(revised['matches'][0]['revision'], 1)
        targeted = preflight(text='换一套格式', target_memory_id=identifier)
        self.assertEqual(targeted['reason'], 'explicit-revision-target')
        self.assertEqual(preflight(text='仅其他空间可见的内容')['status'], 'ready-to-propose')
        self.fault('E_DENIED', lambda: preflight(space_ref='space:life'))
        self.fault('E_DENIED', lambda: preflight(purpose='life-task'))
        self.assertEqual(preflight(text='我通常用中文写周报', trigger='host-observation')['reason'],
                         'missing-source-reference')
        observed = preflight(text='我通常用中文写周报', trigger='host-observation', source_ref='event:example')
        self.assertEqual(observed['status'], 'ready-to-propose')
        self.assertFalse(observed['source_verified'])
        self.assertTrue(observed['requires_owner_confirmation'])
        self.assertEqual(preflight(text='我今天喜欢中文', trigger='host-observation',
                                   source_ref='event:example')['reason'], 'unsupported-preference-statement')
        self.assertEqual(self.s.db.read_bytes(), database_before)

    def test_proposal_preflight_pending_source_is_not_shared_between_adapters(self):
        draft = self.draft('Fixture pending task', level='M1')
        source = draft['bindings'][0]['source_refs'][0]
        pending = self.s.propose(self.work, draft)
        payload = {'space_ref': 'space:work', 'purpose': 'work-task', 'text': 'Fixture pending task',
                   'level': 'M1', 'memory_type': 'fact', 'trigger': 'agent-inference', 'source_ref': source}
        other = self.s.issue_grant(['space:work'], 'work-task', 'another-runtime')['token']
        retry = self.s.preflight_candidate(self.work, payload)
        self.assertEqual(retry['reason'], 'same-pending-source')
        self.assertEqual(retry['delta_id'], pending['delta_id'])
        self.assertEqual(self.s.preflight_candidate(self.work, {**payload, 'text': 'Changed task'})['reason'],
                         'source-reference-reused-with-different-candidate')
        self.assertEqual(self.s.preflight_candidate(other, payload)['status'], 'ready-to-propose')

    def test_checked_submission_serializes_duplicate_proposals_from_same_grant(self):
        def submit(_):
            return self.s.propose_checked(self.work, {
                'trigger': 'agent-inference', 'envelope': self.draft('Concurrent pending proposal', level='M1'),
            })

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, range(2)))
        created, = [result for result in results if result['status'] == 'proposed']
        duplicate, = [result for result in results if result['status'] == 'duplicate']
        self.assertEqual(duplicate['delta_id'], created['delta_id'])
        self.assertFalse(duplicate['submitted'])
        self.assertEqual(len(self.s.pending_proposals(self.owner)['proposals']), 1)
        self.assertEqual(self.search(), [])

    def test_owner_pending_filters_trigger_before_pagination_and_preserves_scope(self):
        legacy = self.s.propose(self.work, self.draft('Legacy task'))['delta_id']
        host = []
        for text in ('我喜欢用简洁的文字写周报。', '我一般在下午整理资料。'):
            draft = self.draft(text, pinned=True)
            result = self.s.propose_checked(self.work, {'trigger': 'host-observation', 'envelope': draft})
            self.assertEqual(result['status'], 'proposed')
            host.append(result['delta_id'])
        self.s.propose_checked(self.life, {'trigger': 'host-observation', 'envelope':
                             self.draft('我喜欢周末在家看电影。', token=self.life, space='space:life', pinned=True)})
        work_owner = self.s.issue_grant(['space:work'], 'review', 'fixture-owner', role='owner')['token']
        before = self.s.db.read_bytes()
        first = self.s.pending_proposals(work_owner, trigger='host-observation', limit=1)
        second = self.s.pending_proposals(work_owner, trigger='host-observation', limit=1, after=first['next_after'])
        self.assertEqual([entry['delta_id'] for entry in first['proposals'] + second['proposals']], sorted(host))
        self.assertIsNone(second['next_after'])
        self.assertEqual(self.s.pending_proposals(work_owner, trigger='legacy')['proposals'],
                         [{'delta_id': legacy, 'space_refs': ['space:work'], 'trigger': 'legacy'}])
        self.fault('E_DENIED', lambda: self.s.pending_proposals(self.work, trigger='host-observation'))
        review = self.s.review(work_owner, host[0], changes=True)
        self.assertEqual(review['changes'][0]['proposal_source']['runtime_ref'], 'test-work')
        self.assertTrue(review['changes'][0]['proposal_source']['reported_reference'].startswith('evidence:'))
        self.assertFalse(review['admission']['source_verified'])
        self.assertEqual(self.s.db.read_bytes(), before)

    def test_owner_approval_preview_reports_revoked_issuer_and_stale_revision(self):
        ident = self.add('Original decision')
        old, = self.search()
        item = self.s.propose(self.work, self.draft('Correction', old=old))
        delta_id = item['delta_id']
        before = self.s.db.read_bytes()
        self.assertEqual(self.s.review(self.owner, delta_id, changes=True)['approval_check'],
                         {'status': 'ready'})
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.confirm_memory_use(self.owner, 'space:work', ident, old['revision'])
        stale = self.s.review(self.owner, delta_id, changes=True)
        self.assertEqual(stale['approval_check'], {'status': 'blocked', 'code': 'E_VERSION_CONFLICT'})
        self.fault('E_VERSION_CONFLICT', lambda: self.s.decide(self.owner, delta_id, True))
        grant = self.s.session(self.work)['auth_evidence_ref']
        self.s.revoke_grant(grant)
        revoked = self.s.review(self.owner, delta_id, changes=True)
        self.assertEqual(revoked['approval_check'], {'status': 'blocked', 'code': 'E_IDENTITY'})
        self.fault('E_IDENTITY', lambda: self.s.decide(self.owner, delta_id, True))
        self.assertEqual(self.s.review(self.owner, delta_id)['status'], 'proposed')

    def test_checked_approval_blocks_duplicates_across_adapters_without_exposing_pending(self):
        other = self.s.issue_grant(['space:work'], 'work-task', 'another-runtime')['token']
        text = 'Shared candidate statement'
        first = self.s.propose_checked(self.work, {
            'trigger': 'user-request', 'envelope': self.draft(text),
        })
        second = self.s.propose_checked(other, {
            'trigger': 'user-request', 'envelope': self.draft(text, token=other),
        })
        self.assertEqual((first['status'], second['status']), ('proposed', 'proposed'))
        first_id, second_id = first['delta_id'], second['delta_id']
        self.fault('E_DENIED', lambda: self.s.review(other, first_id))

        def approve(delta_id):
            try:
                return self.s.decide(self.owner, delta_id, True)['status']
            except Fault as error:
                self.assertEqual(error.status, 409)
                return error.code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(approve, (first_id, second_id)))
        self.assertCountEqual(outcomes, ['accepted', 'E_DUPLICATE_MEMORY'])
        active, = self.search()
        blocked = (first_id, second_id)[outcomes.index('E_DUPLICATE_MEMORY')]
        review = self.s.review(self.owner, blocked, changes=True)
        self.assertEqual(review['status'], 'proposed')
        self.assertEqual(review['approval_check'], {'status': 'blocked', 'code': 'E_DUPLICATE_MEMORY'})
        self.assertEqual(review['changes'][0]['active_duplicate'],
                         {'memory_id': active['memory_id'], 'revision': active['revision']})
        self.assertEqual(self.s.decide(self.owner, blocked, False)['status'], 'rejected')

    def test_checked_revision_cannot_copy_a_different_active_record(self):
        self.add('Current decision')
        old, = self.search()
        revision = self.s.propose_checked(self.work, {
            'trigger': 'user-request', 'envelope': self.draft('Replacement text', old=old),
        })
        self.assertEqual(revision['status'], 'proposed')
        self.add('Replacement text')
        self.fault('E_DUPLICATE_MEMORY', lambda: self.s.decide(self.owner, revision['delta_id'], True))
        self.assertEqual(sorted(item['content'] for item in self.search()),
                         ['Current decision', 'Replacement text'])

    def test_checked_submission_requires_review_for_related_add_and_records_trigger(self):
        ident = self.add('以后请默认用中文回复。', pinned=True)
        envelope = self.draft('以后请默认用英文回复。', pinned=True)
        body = {'trigger': 'user-request', 'envelope': envelope}
        stopped = self.s.propose_checked(self.work, body)
        self.assertEqual(stopped['status'], 'review-revision')
        self.assertEqual(stopped['matches'][0]['memory_id'], ident)
        self.assertEqual(self.s.pending_proposals(self.owner)['proposals'], [])

        old, = self.search()
        revision = {'trigger': 'user-request', 'envelope': self.draft('以后请默认用英文回复。', old=old)}
        submitted = self.s.propose_checked(self.work, revision)
        self.assertEqual(submitted['status'], 'proposed')
        self.assertTrue(self.s.propose_checked(self.work, revision)['idempotent'])
        self.fault('E_IDEMPOTENCY_CONFLICT', lambda: self.s.propose_checked(
            self.work, {**revision, 'trigger': 'agent-inference'}))
        review = self.s.review(self.owner, submitted['delta_id'], changes=True)
        self.assertEqual(review['admission']['trigger'], 'user-request')
        self.assertFalse(review['admission']['source_verified'])
        self.assertEqual(self.search()[0]['content'], old['content'])
        self.s.decide(self.owner, submitted['delta_id'], True)
        self.assertEqual(self.search()[0]['content'], '以后请默认用英文回复。')

    def test_checked_submission_flags_ineligible_observation_and_reserved_metadata(self):
        draft = self.draft('今天临时处理这个项目', level='M1')
        body = {'trigger': 'host-observation', 'envelope': draft}
        self.fault('E_CONFIRMATION_REQUIRED', lambda: self.s.propose_checked(
            self.work, {**body, 'confirm_new': True}))
        result = self.s.propose_checked(self.work, body)
        self.assertEqual(result['reason'], 'automatic-preference-only')
        self.assertFalse(result['submitted'])
        self.assertEqual(self.s.pending_proposals(self.owner)['proposals'], [])
        draft['delta']['extensions'] = {'x-aiap-local-memory-admission': {'source_verified': True}}
        self.fault('E_OPERATION_UNSUPPORTED', lambda: self.s.propose(self.work, draft))
        self.fault('E_OPERATION_UNSUPPORTED', lambda: self.s.propose_checked(self.work, body))

    def test_offline_recall_keeps_underscored_identifiers_distinct(self):
        accepted = self.add('AIAP_ACCEPTED decision')
        self.s.propose(self.work, self.draft('AIAP_PENDING candidate'))
        body = {'space_refs': ['space:work'], 'purpose': 'work-task', 'query': 'AIAP_PENDING'}
        self.assertEqual(self.s.search(self.work, body)['items'], [])
        self.assertEqual([m['memory_id'] for m in self.s.search(
            self.work, {**body, 'query': 'AIAP_ACCEPTED 要怎么做'})['items']], [accepted])

    def test_offline_chinese_recall_and_correction(self):
        text = '签合同前，请法律顾问逐条复核。'
        ident = self.add(text)
        self.add('合同要谁复核', token=self.life, space='space:life')
        self.s.propose(self.work, self.draft('合同要谁复核'))
        body = {'space_refs': ['space:work'], 'purpose': 'work-task', 'query': '合同要谁复核'}
        self.assertNotIn(body['query'], text)
        result = self.s.search(self.work, body)
        self.assertEqual(result['retrieval'], 'scoped-offline-bm25')
        self.assertEqual([item['memory_id'] for item in result['items']], [ident])
        self.assertEqual(self.s.search(self.work, {**body, 'query': '律师审协议'})['items'], [])
        exact = self.add(body['query'])
        limited = self.s.search(self.work, {**body, 'limit': 1})
        self.assertEqual(limited['items'][0]['memory_id'], exact)
        self.assertTrue(limited['possibly_more'])
        edit = self.s.propose(self.work, self.draft('会议已经结束', old=result['items'][0]))
        self.s.decide(self.owner, edit['delta_id'], True)
        self.assertEqual([m['memory_id'] for m in self.s.search(self.work, body)['items']], [exact])

    def test_local_compact_core_keeps_one_reference_per_space(self):
        before = self.s.compact_core(self.owner)['avatar_core']
        self.assertEqual(len(before['state_index']), 3)
        self.fault('E_DENIED', lambda: self.s.compact_core(self.work))
        restricted = self.s.issue_grant(['space:work'], 'compact-view', 'test-owner', role='owner')['token']
        self.fault('E_DENIED', lambda: self.s.compact_core(restricted))
        for index in range(12):
            self.add(f'compact-private-text-{index}')
        full = self.s.core(self.owner)['avatar_core']
        compact = self.s.compact_core(self.owner)['avatar_core']
        self.assertEqual(len(compact['state_index']), 3)
        self.assertLess(len(canonical(compact)), len(canonical(before)) + 32)
        self.assertNotIn(b'compact-private-text', canonical(compact))
        self.assertEqual(compact, self.s.compact_core(self.owner)['avatar_core'])
        self.assertEqual(len(full['state_index']), 12)
        self.assertEqual(full, self.s.core(self.owner)['avatar_core'])
        work = next(ref for ref in compact['state_index'] if ref['scope']['space_ref'] == 'space:work')
        resolved = self.s.compact_core(self.owner, space='space:work', revision=compact['revision'])
        self.assertEqual(work['sha256'], resolved['sha256'])
        self.assertEqual(resolved['manifest']['entries'], full['state_index'])
        self.assertEqual(resolved['manifest']['core_revision'], work['version'])
        self.fault('E_VERSION_CONFLICT', lambda: self.s.compact_core(self.owner, space='space:work',
                                                                    revision=before['revision']))

    def test_local_profile_summary_requires_owner_and_approved_short_pinned_source(self):
        work_id = self.add('Short approved summary for work', pinned=True)
        other_id = self.add('Another approved summary in work', pinned=True)
        ordinary_id = self.add('Ordinary work memory')
        long_id = self.add('X' * 1025, pinned=True)
        proposal_result = self.s.propose(self.work, self.draft('Pending summary', pinned=True))
        pending_id = self.s.review(self.owner, proposal_result['delta_id'])['candidate']['bindings'][0]['target_object_id']
        scoped_owner = self.s.issue_grant(['space:work'], 'summary-review', 'test-owner', role='owner')['token']
        result = self.s.compact_core(self.owner, summary_ids=[work_id])['avatar_core']
        selected, = result['profile_summary']
        self.assertEqual(selected['id'], work_id)
        self.assertNotIn('Short approved summary', json.dumps(result))
        self.assertEqual(self.s.compact_core(self.owner)['avatar_core']['profile_summary'], [])
        self.assertEqual(self.s.core(self.owner)['avatar_core']['profile_summary'], [])
        read = self.s.read_profile_summary(scoped_owner, 'space:work', work_id, selected['version'])
        self.assertEqual(read, {'reference': selected, 'text': 'Short approved summary for work'})
        self.fault('E_DENIED', lambda: self.s.read_profile_summary(self.work, 'space:work', work_id, 1))
        self.fault('E_DENIED', lambda: self.s.read_profile_summary(scoped_owner, 'space:life', work_id, 1))
        self.fault('E_VERSION_CONFLICT', lambda: self.s.read_profile_summary(scoped_owner, 'space:work', work_id, 2))
        self.fault('E_SUMMARY_SOURCE', lambda: self.s.compact_core(self.owner, summary_ids=[work_id, other_id]))
        self.fault('E_SUMMARY_SOURCE', lambda: self.s.compact_core(self.owner, summary_ids=[ordinary_id]))
        self.fault('E_SUMMARY_SOURCE', lambda: self.s.compact_core(self.owner, summary_ids=[long_id]))
        self.fault('E_NOT_FOUND', lambda: self.s.compact_core(self.owner, summary_ids=[pending_id]))
        self.s.delete(self.owner, {'memory_id': work_id, 'space_ref': 'space:work', 'base_revision': 1})
        self.fault('E_NOT_FOUND', lambda: self.s.read_profile_summary(scoped_owner, 'space:work', work_id, 1))

    def test_saved_profile_summary_selection_is_scoped_and_expires_on_edit(self):
        work_id = self.add('Work source text', pinned=True)
        life_id = self.add('Life source text', space='space:life', token=self.life, pinned=True)
        limited = self.s.issue_grant(['space:work'], 'summary-selection', 'test-owner', role='owner')['token']
        self.fault('E_DENIED', lambda: self.s.set_summary_selection(self.work, 'space:work', memory_id=work_id, revision=1))
        self.fault('E_DENIED', lambda: self.s.set_summary_selection(limited, 'space:life'))
        self.fault('E_VERSION_CONFLICT', lambda: self.s.set_summary_selection(limited, 'space:work', memory_id=work_id,
                                                                             revision=2))
        self.s.set_summary_selection(limited, 'space:work', memory_id=work_id, revision=1)
        self.s.set_summary_selection(self.owner, 'space:life', memory_id=life_id, revision=1)
        file = Path(self.tmp.name) / 'profile-summary-selections.json'
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('source text', file.read_text())
        reopened = Service(self.tmp.name, clock=lambda: self.now, enable_semantic=False)
        def summary_ids(result):
            return [ref['id'] for ref in result['avatar_core']['profile_summary']]
        self.assertEqual(summary_ids(reopened.compact_core(self.owner)), [life_id, work_id])
        self.assertEqual(reopened.read_profile_summary(limited, 'space:work')['text'], 'Work source text')
        self.fault('E_DENIED', lambda: reopened.read_profile_summary(limited, 'space:life'))
        self.assertEqual(summary_ids(reopened.compact_core(self.owner, summary_ids=[work_id])), [work_id])
        self.assertEqual(reopened.core(self.owner)['avatar_core']['profile_summary'], [])
        update = self.s.propose(self.work, self.draft('Work source update', old=self.search()[0], pinned=True))
        self.s.decide(self.owner, update['delta_id'], True)
        filtered = reopened.compact_core(self.owner)
        self.assertEqual(filtered['stale_summary_spaces'], ['space:work'])
        self.assertEqual(summary_ids(filtered), [life_id])
        self.fault('E_VERSION_CONFLICT', lambda: reopened.read_profile_summary(limited, 'space:work'))
        self.assertEqual(reopened.set_summary_selection(limited, 'space:work')['selection'], None)
        self.fault('E_NOT_FOUND', lambda: reopened.read_profile_summary(limited, 'space:work'))
        self.assertNotIn('stale_summary_spaces', reopened.compact_core(self.owner))
        file.chmod(0o644)
        self.fault('E_SUMMARY_SELECTION_FILE', lambda: reopened.compact_core(self.owner))

    def test_init_no_overwrite(self):self.fault('E_ALREADY_INITIALIZED',self.s.initialize)
    def test_token_hash_only_in_database(self):
        with sqlite3.connect(self.s.db) as c:rows=str(c.execute('SELECT * FROM grants').fetchall())
        self.assertNotIn(self.owner,rows);self.assertNotIn(self.work,rows)
    def test_local_grant_inventory_pages_and_status(self):
        first = self.s.list_grants(role='adapter', limit=1)
        second = self.s.list_grants(role='adapter', after=first['next_after'], limit=1)
        self.assertIsNone(second['next_after'])
        work = self.s.grant_status(self.work)
        life = self.s.grant_status(self.life)
        by_id = {item['grant_id']: item for item in first['grants'] + second['grants']}
        self.assertEqual(list(by_id), sorted([work['grant_id'], life['grant_id']]))
        self.assertEqual(by_id[work['grant_id']], {**work, 'runtime_ref': 'test-work', 'purpose': 'work-task'})
        self.assertEqual(self.s.list_grants(role='owner')['grants'][0]['role'], 'owner')
        self.fault('E_SCHEMA', lambda: self.s.list_grants(limit=101))
        self.fault('E_SCHEMA', lambda: self.s.list_grants(role='other'))
        self.now -= timedelta(seconds=1)
        self.assertEqual({item['status'] for item in self.s.list_grants()['grants']}, {'not-yet-valid'})
        self.s.revoke_grant(life['grant_id'])
        self.now += timedelta(days=7, seconds=1)
        statuses = {item['grant_id']: item['status'] for item in self.s.list_grants(role='adapter')['grants']}
        self.assertEqual(statuses, {work['grant_id']: 'expired', life['grant_id']: 'revoked'})
        self.assertEqual(self.s.grant_status(self.work)['status'], 'expired')

    def test_local_reissue_preserves_grant_permissions(self):
        original = self.s.session(self.work)
        grant_id = original['auth_evidence_ref']
        self.now -= timedelta(seconds=1)
        self.fault('E_GRANT_NOT_REISSUABLE', lambda: self.s.reissue_grant(grant_id))
        self.now += timedelta(seconds=1)
        self.fault('E_SCHEMA', lambda: self.s.reissue_grant(grant_id, days=31))
        active = self.s.reissue_grant(grant_id, days=30)
        replacement = self.s.session(active['token'])
        for field in ('avatar_id', 'subject_ref', 'role', 'space_refs', 'purpose', 'runtime_ref', 'actions'):
            self.assertEqual(original[field], replacement[field])
        self.assertNotEqual(original['auth_evidence_ref'], replacement['auth_evidence_ref'])
        self.assertNotEqual(original['session_ref'], replacement['session_ref'])
        self.assertEqual(self.s.grant_status(self.work)['status'], 'active')
        self.now += timedelta(days=7)
        self.assertEqual(self.s.grant_status(self.work)['status'], 'expired')
        expired = self.s.reissue_grant(grant_id)
        self.assertEqual(self.s.grant_status(expired['token'])['status'], 'active')
        self.s.revoke_grant(grant_id)
        self.fault('E_GRANT_NOT_REISSUABLE', lambda: self.s.reissue_grant(grant_id))
        self.assertEqual(self.s.grant_status(active['token'])['status'], 'active')
        self.assertEqual(self.s.grant_status(expired['token'])['status'], 'active')

    def test_untrusted_token(self):self.fault('E_IDENTITY',lambda:self.s.session('x'*43))
    def test_adapter_no_full_core(self):self.fault('E_DENIED',lambda:self.s.core(self.work))
    def test_no_implicit_general(self):self.fault('E_DENIED',lambda:self.search(space='space:general'))
    def test_pending_not_searchable(self):self.s.propose(self.work,self.draft());self.assertEqual(self.search(),[])

    def test_local_audit_pagination_and_space_boundary(self):
        limited = self.s.issue_grant(['space:work'], 'audit-review', 'test-owner', role='owner')['token']
        work_id = self.add('synthetic-work-secret')
        life_id = self.add('synthetic-life-secret', space='space:life', token=self.life)
        self.s.delete(self.owner, {'memory_id': work_id, 'space_ref': 'space:work', 'base_revision': 1})
        self.now += timedelta(seconds=1)
        self.s.delete(self.owner, {'memory_id': life_id, 'space_ref': 'space:life', 'base_revision': 1})
        listing = self.s.list_audit(self.owner)['events']
        self.assertEqual(listing[0]['object_id'], life_id)
        self.assertIn('delta-accepted', {event['event'] for event in listing})
        self.assertIn('credential-issued', {event['event'] for event in listing})
        first = self.s.list_audit(self.owner, limit=2)
        second = self.s.list_audit(self.owner, before=first['next_before'], limit=2)
        self.assertEqual(first['events'] + second['events'], listing[:4])
        self.assertEqual(second['next_before'], second['events'][-1]['audit_id'])
        work_events = self.s.list_audit(limited)['events']
        self.assertEqual(work_events, self.s.list_audit(self.owner, space='space:work')['events'])
        self.assertEqual([(event['event'], event['object_id']) for event in work_events], [('memory-deleted', work_id)])
        self.fault('E_NOT_FOUND', lambda: self.s.list_audit(limited, before=listing[0]['audit_id']))
        first_delete = self.s.list_audit(self.owner, event='memory-deleted', limit=1)
        second_delete = self.s.list_audit(self.owner, event='memory-deleted', before=first_delete['next_before'])
        self.assertEqual([event['object_id'] for event in first_delete['events'] + second_delete['events']],
                         [life_id, work_id])
        self.assertEqual(self.s.list_audit(limited, object_id=life_id)['events'], [])
        self.assertEqual(self.s.list_audit(self.owner, event='memory-deleted', object_id=work_id)['events'], work_events)
        self.fault('E_NOT_FOUND', lambda: self.s.list_audit(self.owner, event='credential-issued',
                                                          before=first_delete['next_before']))
        self.fault('E_DENIED', lambda: self.s.list_audit(limited, space='space:life'))
        self.fault('E_DENIED', lambda: self.s.list_audit(self.work))
        self.assertNotIn('synthetic-', json.dumps(listing))

    def test_owner_approval_persists(self):self.add();self.assertEqual(self.search()[0]['content'],'work fact')
    def test_inferred_requires_owner(self):
        p=self.draft(source_type='inferred');r=self.s.propose(self.work,p);self.assertEqual(self.search(),[]);self.s.decide(self.owner,r['delta_id'],True);m=self.search()[0];self.assertEqual(m['source']['source_type'],'inferred');self.assertFalse(m['source']['verified'])
    def test_adapter_cannot_approve(self):
        r=self.s.propose(self.work,self.draft());self.fault('E_DENIED',lambda:self.s.decide(self.work,r['delta_id'],True))
    def test_rejection_stays_out(self):
        r=self.s.propose(self.work,self.draft());self.s.decide(self.owner,r['delta_id'],False);self.assertEqual(self.search(),[])
    def test_life_not_in_work(self):
        self.add('private pottery',space='space:life',token=self.life);self.add('public work');self.assertNotIn('pottery',json.dumps(self.search()))
    def test_scope_expansion_denied(self):self.fault('E_DENIED',lambda:self.search(space='space:life'))
    def test_wrong_purpose(self):self.fault('E_DENIED',lambda:self.s.search(self.work,{'space_refs':['space:work'],'purpose':'life-task','query':''}))
    def test_subject_forgery(self):
        p=self.draft();p['request']['authenticated_subject_ref']='aiap-id:someone-else';self.fault('E_IDENTITY',lambda:self.s.propose(self.work,p))
    def test_avatar_forgery(self):
        p=self.draft();p['delta']['avatar_id']='avatar:someone-else';self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_scope_forgery(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['scope']['owner_ref']='org:fake';self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_wrong_policy_version(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['scope']['policy_ref']['version']=9;self.fault('E_SCOPE',lambda:self.s.propose(self.work,p))
    def test_caller_confirmation_not_accepted(self):
        p=self.draft();p['bindings'][0]['confirmation_ref']='pretend-confirmed';self.fault('E_CONFIRMATION_REQUIRED',lambda:self.s.propose(self.work,p))
    def test_unknown_memory_extension_rejected(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['extensions']={'x-unknown':{'critical':True}};self.fault('E_OPERATION_UNSUPPORTED',lambda:self.s.propose(self.work,p))
    def test_unsupported_identity_delta(self):
        p=self.draft();p['delta']['changes'][0]['domain']='aiap.identity';self.fault('E_OPERATION_UNSUPPORTED',lambda:self.s.propose(self.work,p))
    def test_no_outbound_embedding_authorization(self):
        p=self.draft();p['request']['processor_refs']=['ollama'];self.fault('E_DENIED',lambda:self.s.propose(self.work,p))
    def test_duplicate_proposal_idempotent(self):
        p=self.draft();self.s.propose(self.work,p);self.assertTrue(self.s.propose(self.work,p)['idempotent'])
    def test_same_id_different_body(self):
        p=self.draft();self.s.propose(self.work,p);p['delta']['changes'][0]['candidate']['content']='changed';self.fault('E_IDEMPOTENCY_CONFLICT',lambda:self.s.propose(self.work,p))
    def test_double_approve_idempotent(self):
        p=self.draft();r=self.s.propose(self.work,p);self.s.decide(self.owner,r['delta_id'],True);self.assertTrue(self.s.decide(self.owner,r['delta_id'],True)['idempotent']);self.assertEqual(self.search()[0]['revision'],1)
    def test_stale_proposal(self):
        self.add();old=self.search()[0];a=self.draft('first',old=old);b=self.draft('second',old=old)
        self.s.propose(self.work,a);self.s.propose(self.work,b);self.s.decide(self.owner,a['delta']['delta_id'],True)
        self.fault('E_VERSION_CONFLICT',lambda:self.s.decide(self.owner,b['delta']['delta_id'],True));self.assertEqual(self.search()[0]['content'],'first')
    def test_concurrent_compare_and_swap(self):
        self.add();old=self.search()[0];drafts=[self.draft(x,old=old) for x in ['A','B']]
        for p in drafts:self.s.propose(self.work,p)
        def decide(p):
            try:return self.s.decide(self.owner,p['delta']['delta_id'],True)['status']
            except Fault as e:return e.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(decide,drafts))
        self.assertCountEqual(results,['accepted','E_VERSION_CONFLICT']);self.assertEqual(self.search()[0]['revision'],2)
    def test_multiple_changes_atomic(self):
        self.add('one');self.add('two');one,two=self.search();a=self.draft('new one',old=one);b=self.draft('new two',old=two)
        a['delta']['changes']+=b['delta']['changes'];a['bindings']+=b['bindings'];self.s.propose(self.work,a)
        c=self.draft('competing two',old=two);self.s.propose(self.work,c);self.s.decide(self.owner,c['delta']['delta_id'],True)
        self.fault('E_VERSION_CONFLICT',lambda:self.s.decide(self.owner,a['delta']['delta_id'],True));by={m['memory_id']:m for m in self.search()};self.assertEqual(by[one['memory_id']]['revision'],1)
    def test_revocation_blocks_new_read(self):
        g=self.s.session(self.work)['auth_evidence_ref'];self.s.revoke_grant(g);self.fault('E_IDENTITY',lambda:self.s.session(self.work))
    def test_revocation_blocks_pending_approval(self):
        r=self.s.propose(self.work,self.draft());self.s.revoke_grant(self.s.session(self.work)['auth_evidence_ref']);self.fault('E_IDENTITY',lambda:self.s.decide(self.owner,r['delta_id'],True))
    def test_expiry(self):self.now+=timedelta(days=8);self.fault('E_IDENTITY',lambda:self.s.session(self.work))
    def test_restart_persists_identity_and_record(self):
        self.add();av=self.s.session(self.owner)['avatar_id'];self.s=Service(self.tmp.name,clock=lambda:self.now);self.assertEqual(self.s.session(self.owner)['avatar_id'],av);self.assertEqual(len(self.search()),1)
    def test_deleted_id_cannot_resurrect(self):
        mid=self.add();self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1});self.assertEqual(self.search(),[]);self.fault('E_DENIED',lambda:self.s.propose(self.work,self.draft(memory_id=mid)))
    def test_deleted_pending_invalidated(self):
        mid=self.add();p=self.draft(old=self.search()[0]);r=self.s.propose(self.work,p);self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1});self.assertEqual(self.s.review(self.owner,r['delta_id'])['status'],'invalidated')
    def test_delete_body_removed_from_live_rows(self):
        mid=self.add('UNIQUE_DELETE_BODY');self.s.delete(self.owner,{'memory_id':mid,'space_ref':'space:work','base_revision':1})
        with sqlite3.connect(self.s.db) as c:
            allrows=''.join(str(c.execute('SELECT * FROM '+t).fetchall()) for t in ['memories','history','deltas','audit','cores','tombstones'])
        self.assertNotIn('UNIQUE_DELETE_BODY',allrows)
    def test_archive_ordinary_but_protect_pinned(self):
        ordinary_id = self.add('ordinary')
        self.add('pinned', pinned=True)
        self.now += timedelta(days=181)
        before = self.s.db.read_bytes()
        preview = self.s.archive_cycle(dry_run=True)
        self.assertEqual(preview['eligible'], 1)
        self.assertFalse(preview['possibly_more'])
        self.assertEqual(preview['candidates'], [{'memory_id': ordinary_id, 'space_ref': 'space:work',
                                                  'base_revision': 1, 'from_level': 'M2', 'to_level': 'M3',
                                                  'eligible_since': '2027-03-18T00:00:00.000000Z'}])
        self.assertEqual(self.s.db.read_bytes(), before)
        self.assertEqual(self.s.archive_cycle()['archived'], preview['eligible'])
        self.assertEqual(self.s.archive_cycle(dry_run=True)['candidates'], [])
        t=self.s.issue_grant(['space:work'],'work-task','test-work')['token'];ms=self.search(token=t,include_archived=True);self.assertEqual({m['content']:m['level'] for m in ms},{'ordinary':'M3','pinned':'M2'})
    def test_expected_use_protection_ends_after_scheduled_time(self):
        draft = self.draft(level='M1')
        scheduled = self.now + timedelta(days=35)
        draft['delta']['changes'][0]['candidate']['lifecycle']['expected_next_use'] = scheduled.isoformat()
        pending = self.s.propose(self.work, draft)
        self.s.decide(self.owner, pending['delta_id'], True)
        self.now += timedelta(days=31)
        self.assertEqual(self.s.archive_cycle()['archived'], 0)
        self.now = scheduled
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 0)
        self.now += timedelta(microseconds=1)
        candidate, = self.s.archive_cycle(dry_run=True)['candidates']
        self.assertEqual(datetime.fromisoformat(candidate['eligible_since'].replace('Z', '+00:00')), self.now)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)

    def test_approved_correction_restarts_task_archive_window(self):
        self.add('original task', level='M1')
        self.now += timedelta(days=31)
        token = self.s.issue_grant(['space:work'], 'work-task', 'fixture')['token']
        owner = self.s.issue_grant(['space:work'], 'review', 'fixture-owner', role='owner')['token']
        old, = self.search(token=token)
        draft = self.draft('corrected task', old=old, token=token, level='M1')
        pending = self.s.propose(token, draft)
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 1)
        self.s.decide(owner, pending['delta_id'], True)
        corrected, = self.search(token=token)
        self.assertIsNone(corrected['lifecycle']['last_used_at'])
        self.now += timedelta(days=30, microseconds=-1)
        self.assertEqual(self.s.archive_cycle()['archived'], 0)
        self.now += timedelta(microseconds=1)
        self.assertEqual(self.s.archive_cycle(dry_run=True)['eligible'], 1)
        self.assertEqual(self.s.archive_cycle()['archived'], 1)

    def test_recurrence_protected(self):
        p=self.draft();p['delta']['changes'][0]['candidate']['lifecycle']['recurrence_ref']='annual:review';r=self.s.propose(self.work,p);self.s.decide(self.owner,r['delta_id'],True);self.now+=timedelta(days=400);self.assertEqual(self.s.archive_cycle()['archived'],0)
    def test_search_not_counted_as_use(self):self.add();self.search();self.assertIsNone(self.search()[0]['lifecycle']['last_used_at'])
    def context(self):return self.s.search(self.work,{'space_refs':['space:work'],'purpose':'work-task','query':''},context=True)
    def test_context_ack_once(self):
        self.add();v=self.context()['authorized_view'];self.s.acknowledge(self.work,{'view_id':v['view_id']});self.assertTrue(self.s.acknowledge(self.work,{'view_id':v['view_id']})['idempotent']);self.assertEqual(self.search()[0]['lifecycle']['context_use_count'],1)
    def test_ack_requires_same_grant(self):
        self.add();v=self.context()['authorized_view'];self.fault('E_NOT_FOUND',lambda:self.s.acknowledge(self.owner,{'view_id':v['view_id']}))
    def test_expired_view(self):
        self.add();v=self.context()['authorized_view'];self.now+=timedelta(minutes=6);self.fault('E_EXPIRED',lambda:self.s.acknowledge(self.work,{'view_id':v['view_id']}))
    def test_context_no_life_leak(self):
        self.add('private!',space='space:life',token=self.life);self.add('work');v=self.context();self.assertNotIn('private!',json.dumps(v));validate('authorized-view',v['authorized_view'])
    def test_corrected_preference_review_and_level_scoped_context(self):
        original = self.add('Use method A', pinned=True)
        self.add('Finish current task', level='M1')
        old, = self.search(level='M2')
        draft = self.draft('Use method B', old=old, pinned=True, source_type='inferred')
        delta_id = self.s.propose(self.work, draft)['delta_id']
        preview, = self.s.review(self.owner, delta_id, changes=True)['changes']
        self.assertEqual(preview['current_classification']['reported_source_type'], 'explicit-user')
        self.assertEqual(preview['proposed_classification'], {
            'level': 'M2', 'type': 'preference-evidence', 'reported_source_type': 'inferred',
            'stable_preference': True, 'confidence': 0.5})
        self.assertEqual([m['content'] for m in self.search(level='M2')], ['Use method A'])
        self.s.decide(self.owner, delta_id, True)
        result = self.s.search(self.work, {'space_refs': ['space:work'], 'purpose': 'work-task',
                                          'query': '', 'level': 'M2'}, context=True)
        self.assertEqual([m['content'] for m in result['items']], ['Use method B'])
        self.assertEqual([r['id'] for r in result['authorized_view']['objects']], [original])
        self.assertEqual(self.s.memory_history(self.owner, 'space:work', original, revision=1)['record']['content'],
                         'Use method A')

    def test_update_preserves_previous_version(self):
        self.add('previous');old=self.search()[0];p=self.draft('current',old=old);self.s.propose(self.work,p);self.s.decide(self.owner,p['delta']['delta_id'],True)
        with sqlite3.connect(self.s.db) as c:prior=json.loads(c.execute('SELECT body FROM history WHERE id=?',(old['memory_id'],)).fetchone()[0])
        self.assertEqual(prior['content'],'previous');self.assertEqual(prior['revision'],1)
    def test_local_signature_detects_tamper(self):
        r=self.s.core(self.owner);r['avatar_core']['owner']['owner_ref']='attacker';self.assertFalse(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))
    def test_unknown_local_crypto_profile_rejected(self):
        r=self.s.core(self.owner);r['avatar_core']['integrity']['proofs'][0]['crypto_profile']='unknown';self.assertFalse(self.s.verify_local_core(r['avatar_core'],r['local_enrollment']))
    def test_database_core_tamper_fails(self):
        with sqlite3.connect(self.s.db) as c:
            raw=json.loads(c.execute('SELECT body FROM cores').fetchone()[0]);raw['avatar_id']='attacker';c.execute('UPDATE cores SET body=?',(json.dumps(raw),))
        self.fault('E_INTEGRITY',lambda:self.s.core(self.owner))

class HTTPTests(ServiceTests):
    # Reuse fixtures, but do not duplicate inherited service tests.
    def setUp(self):
        ServiceTests.setUp(self);self.http=Server(('127.0.0.1',0),self.s);self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start();self.base='http://127.0.0.1:'+str(self.http.server_port);self.client=Client(self.base,self.work)
    def tearDown(self):self.http.shutdown();self.http.server_close();self.thread.join();ServiceTests.tearDown(self)
    def test_http_real_save_review_approve_read(self):
        p=proposal(self.client.call('/v1/session'),'space:work','HTTP memory');r=self.client.call('/v1/deltas/propose',p)
        with self.assertRaisesRegex(RuntimeError,'403'):self.client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
        owner=Client(self.base,self.owner);self.assertEqual(owner.call('/v1/deltas/review',{'delta_id':r['delta_id']})['status'],'proposed');owner.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
        self.assertEqual(self.client.call('/v1/search',{'space_refs':['space:work'],'purpose':'work-task','query':'HTTP'})['count'],1)
    def test_http_cross_scope_denied(self):
        with self.assertRaisesRegex(RuntimeError,'403'):self.client.call('/v1/search',{'space_refs':['space:life'],'purpose':'work-task','query':''})
    def test_http_delete_preview_is_read_only_and_matches_delete(self):
        memory_id = self.add('private preview body')
        update = self.s.propose(self.work, self.draft('updated preview body', old=self.search()[0]))
        self.s.decide(self.owner, update['delta_id'], True)
        pending = self.s.propose(self.work, self.draft('pending preview body', old=self.search()[0]))
        self.context()
        path = '/v1/memories/delete/preview'
        body = {'memory_id': memory_id, 'space_ref': 'space:work', 'base_revision': 2}
        owner = Client(self.base, self.owner)
        with self.assertRaisesRegex(RuntimeError, '403 E_DENIED'):
            self.client.call(path, body)
        with self.assertRaisesRegex(RuntimeError, '409 E_VERSION_CONFLICT'):
            owner.call(path, dict(body, base_revision=1))
        preview = owner.call(path, body)
        self.assertEqual(preview['history_versions_to_remove'], 1)
        self.assertEqual(preview['proposals_to_invalidate'], 1)
        self.assertEqual(preview['views_to_invalidate'], 1)
        self.assertNotIn('preview body', json.dumps(preview))
        self.assertEqual(owner.call(path, body), preview)
        self.assertEqual(self.s.review(self.owner, pending['delta_id'])['status'], 'proposed')
        self.assertEqual(self.search()[0]['revision'], 2)
        self.assertTrue(owner.call('/v1/memories/delete', body)['deleted'])
        self.assertEqual(self.s.review(self.owner, pending['delta_id'])['status'], 'invalidated')
        with self.s.tx(read_only=True) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM history WHERE id=?',
                                                (memory_id,)).fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT invalidated FROM views').fetchone()[0], 1)
    def test_http_no_token(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(self.base+'/v1/core')
        self.assertEqual(cm.exception.code,401)
    def test_http_duplicate_json_rejected(self):
        req=urllib.request.Request(self.base+'/v1/search',data=b'{"query":"a","query":"b"}',headers={'Authorization':'Bearer '+self.work,'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code,400)
    def test_http_origin_rejected(self):
        req=urllib.request.Request(self.base+'/v1/session',headers={'Authorization':'Bearer '+self.work,'Origin':'https://example.invalid'})
        with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code,403)
    def test_http_no_store(self):
        req=urllib.request.Request(self.base+'/v1/session',headers={'Authorization':'Bearer '+self.work})
        with urllib.request.urlopen(req) as r:self.assertEqual(r.headers['Cache-Control'],'no-store')
# unittest would otherwise run every inherited method twice. Keep only HTTP tests on this class.
for name in list(ServiceTests.__dict__):
    if name.startswith('test_'):setattr(HTTPTests,name,None)
if __name__=='__main__':unittest.main()
