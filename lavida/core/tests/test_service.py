import unittest,tempfile,json,copy,threading,concurrent.futures,urllib.request,urllib.error,sqlite3,os
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
    def test_preference_evidence_groups_retellings_and_preserves_exceptions(self):
        tokens = [self.work, self.s.issue_grant(['space:work'], 'work-task', 'second-runtime')['token']]
        ids = []
        for token, text, ref in [(tokens[0], 'Release required preflight', 'event:a'),
                                 (tokens[1], 'Same release was preflighted', 'event:a'),
                                 (tokens[0], 'Reversible local experiment ran directly', 'event:b')]:
            env = self.draft(text, token=token, level='M1')
            change = env['delta']['changes'][0]
            change['candidate']['source']['source_ref'] = ref
            change['evidence'] = [{'source_ref': ref}]
            env['bindings'][0]['source_refs'] = [ref]
            delta = self.s.propose(token, env)
            self.s.decide(self.owner, delta['delta_id'], True)
            ids.append(change['candidate']['memory_id'])
        foreign = self.add('private', space='space:life', token=self.life, level='M1')
        other_level = self.add('standing preference')
        before = self.s.db.read_bytes()
        def review(token, selected):
            return self.s.review_preference_evidence(token, 'space:work', selected)
        result = review(self.owner, ids + ids[:1])
        self.assertEqual((result['record_count'], result['source_count']), (3, 2))
        self.assertEqual([len(g['observations']) for g in result['sources']], [2, 1])
        self.assertEqual(result['sources'][1]['observations'][0]['content'], 'Reversible local experiment ran directly')
        self.fault('E_DENIED', lambda: review(tokens[0], ids))
        for ident in (foreign, other_level, 'mem:absent'):
            self.fault('E_NOT_FOUND', lambda: review(self.owner, ids + [ident]))
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.set_memory_validity(self.owner, 'space:work', ids[0], 1, expires_at=self.now.isoformat())
        self.fault('E_NOT_FOUND', lambda: review(self.owner, ids))

    def test_preference_discovery_counts_sources_and_only_previews(self):
        space = 'space:work'
        def observe(text, source, token=None, sid=space):
            token = token or self.work
            env = self.draft(text, space=sid, token=token, level='M1', source_type='observed')
            change = env['delta']['changes'][0]
            change['candidate']['type'] = 'preference-evidence'
            change['candidate']['source']['source_ref'] = source
            change['evidence'] = [{'source_ref': source}]
            env['bindings'][0]['source_refs'] = [source]
            self.s.decide(self.owner, self.s.propose(token, env)['delta_id'], True)
            return change['candidate']['memory_id']
        observe('Check first', 'event:1')
        observe('Check  first', 'event:1')
        observe('Check first', 'event:life', self.life, 'space:life')
        def discover(**args):
            return self.s.preference_candidates(self.owner, space, **args)
        self.assertEqual(discover()['candidates'], [])
        other = observe('Check first', 'event:2')
        observe('Explain briefly', 'event:3')
        observe('Explain briefly', 'event:4')
        before = self.s.db.read_bytes()
        self.fault('E_DENIED', lambda: self.s.preference_candidates(self.work, space))
        page = discover(limit=1)
        item = page['candidates'][0]
        self.assertEqual((item['wording'], item['source_count'], item['record_count']), ('Check first', 2, 3))
        self.assertEqual(len(item['sample_memory_ids']), 2)
        self.assertEqual(item['sample_revisions'], dict.fromkeys(item['sample_memory_ids'], 1))
        tail = discover(after=page['next_after'], limit=1)
        self.assertEqual(tail['candidates'][0]['wording'], 'Explain briefly')
        self.assertIsNone(tail['next_after'])
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.set_memory_validity(self.owner, space, other, 1, expires_at=self.now.isoformat())
        self.assertEqual([r['wording'] for r in discover()['candidates']], ['Explain briefly'])

    def test_owner_groups_distinct_sources_for_one_preference_event(self):
        space = 'space:work'
        first = self.add('Preflight started before release', level='M1')
        second = self.add('This release skipped the final check', level='M1')
        third = self.add('Next release ran all checks', level='M1')
        fields = dict(statement='Preflight', condition='Release', runtimes=['test-work'],
                      supporting=[first, third], counterexamples=[second])
        def preview(**extra):
            return self.s.preview_preference(self.owner, space, **fields, **extra)
        separate = preview()
        refs = {obs['memory_id']: group['source_ref'] for group in separate['evidence']['sources']
                for obs in group['observations']}
        pair = [refs[first], refs[second]]
        combined = preview(same_event=[pair])
        self.assertEqual(combined['event_group_count'], 2)
        self.assertEqual(combined['evidence']['record_count'], 3)
        events = {tuple(event['source_refs']): event['roles'] for event in combined['event_groups']}
        self.assertEqual(events[tuple(sorted(pair))], ['counterexample', 'supporting'])
        self.assertEqual(combined['preview_sha256'], preview(same_event=[pair[::-1]])['preview_sha256'])
        self.assertNotEqual(separate['preview_sha256'], combined['preview_sha256'])
        self.fault('E_VERSION_CONFLICT', lambda: self.s.confirm_preference(
            self.owner, space, combined['preview_sha256'], **fields))
        for groups in ([pair, [refs[first], refs[third]]], [[refs[first], 'unknown']], [[refs[first]]],
                       [[refs[first], refs[first]]]):
            self.fault('E_SCHEMA', lambda: preview(same_event=groups))
        saved = self.s.confirm_preference(self.owner, space, combined['preview_sha256'], **fields, same_event=[pair])
        self.assertEqual(saved['event_groups'], combined['event_groups'])
        self.assertEqual({entry['source_ref'] for entry in saved['evidence_refs']}, set(refs.values()))
        rendered = self.s.recall_preferences(self.work, space, 'Release')['preferences'][0]
        self.assertNotIn('event_groups', rendered)

    def test_owner_preference_preview_is_scoped_and_read_only(self):
        observation = self.add('Dry run before releases', level='M1')
        foreign = self.add('private', space='space:life', token=self.life, level='M1')
        before = self.s.db.read_bytes()
        def preview(token, **kwargs):
            return self.s.preview_preference(token, 'space:work', statement='Run a preflight',
                condition='Production changes', exception='Try reversible local experiments directly',
                project_rule='Release policy also requires preflight', runtimes=['dsh', 'openclaw', 'dsh'], **kwargs)
        self.assertEqual(preview(self.owner)['evidence']['record_count'], 0)
        result = preview(self.owner, supporting=[observation], counterexamples=[observation])
        self.assertEqual(result['allowed_runtimes'], ['dsh', 'openclaw'])
        obs = result['evidence']['sources'][0]['observations'][0]
        self.assertEqual((obs['roles'], obs['revision']), (['supporting', 'counterexample'], 1))
        self.fault('E_DENIED', lambda: preview(self.work))
        self.fault('E_NOT_FOUND', lambda: preview(self.owner, counterexamples=[foreign]))
        self.assertEqual(self.s.db.read_bytes(), before)

    def test_owner_can_bind_evidence_revision_before_preview(self):
        space = 'space:work'
        ident = self.add('Preflight before release', level='M1')
        fields = dict(statement='Run preflight', condition='Release', runtimes=['test-work'],
                      supporting=[ident], counterexamples=[ident])
        def preview(token, pins):
            return self.s.preview_preference(token, space, evidence_revisions=pins, **fields)
        original = preview(self.owner, {ident: 1})
        self.assertEqual(original, preview(self.owner, {}))
        old = self.s.memory_for_update(self.work, space, ident, 1)
        update = self.draft('Preflight except local experiments', old=old)
        self.s.decide(self.owner, self.s.propose(self.work, update)['delta_id'], True)
        before = self.s.db.read_bytes()
        self.fault('E_VERSION_CONFLICT', lambda: preview(self.owner, {ident: 1}))
        self.fault('E_VERSION_CONFLICT', lambda: self.s.confirm_preference(
            self.owner, space, original['preview_sha256'], evidence_revisions={ident: 1}, **fields))
        self.fault('E_DENIED', lambda: preview(self.work, {ident: 1}))
        for pins in ({ident: True}, {ident: 0}, {'mem:unselected': 1}):
            self.fault('E_SCHEMA', lambda: preview(self.owner, pins))
        self.assertEqual(self.s.db.read_bytes(), before)
        updated = preview(self.owner, {ident: 2})
        self.assertNotEqual(original['preview_sha256'], updated['preview_sha256'])
        confirmed = self.s.confirm_preference(self.owner, space, updated['preview_sha256'],
                                              evidence_revisions={ident: 2}, **fields)
        self.assertEqual(confirmed['evidence_refs'][0]['revision'], 2)

    def test_confirmed_preference_is_scoped_retryable_and_withdrawable(self):
        space = 'space:work'
        other = self.s.issue_grant([space], 'work-task', 'second')['token']
        denied = self.s.issue_grant([space], 'work-task', 'unlisted')['token']
        evidence = self.add('A single release', level='M1')
        fields = dict(statement='Run a preflight', condition='Release', exception='Reversible local experiment',
                      runtimes=['test-work', 'second'], supporting=[evidence])
        pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
        def confirm(token, **edits):
            return self.s.confirm_preference(token, space, pin, **{**fields, **edits})
        def recall(token, condition='Release'):
            return self.s.recall_preferences(token, space, condition)['preferences']
        self.assertEqual(recall(self.work), [])
        self.fault('E_DENIED', lambda: confirm(self.work))
        self.fault('E_VERSION_CONFLICT', lambda: confirm(self.owner, statement='Changed'))
        stored = confirm(self.owner)
        self.assertEqual(stored, confirm(self.owner))
        self.assertEqual(recall(self.work), recall(other))
        self.assertEqual(recall(self.work)[0]['statement'], fields['statement'])
        self.assertNotIn('evidence_refs', recall(self.work)[0])
        self.assertEqual(recall(denied), [])
        self.assertEqual(recall(self.work, 'Another condition'), [])
        self.fault('E_DENIED', lambda: recall(self.life))
        key = stored['preference_id']
        self.fault('E_DENIED', lambda: self.s.withdraw_preference(self.work, space, key))
        removed = self.s.withdraw_preference(self.owner, space, key)
        self.assertEqual(removed, self.s.withdraw_preference(self.owner, space, key))
        self.assertEqual(recall(other), [])
        self.fault('E_VERSION_CONFLICT', lambda: confirm(self.owner))
        self.s.set_memory_validity(self.owner, space, evidence, 1, expires_at=self.now.isoformat())
        self.fault('E_NOT_FOUND', lambda: confirm(self.owner))

    def test_preference_history_checks_current_evidence_without_changing_recall(self):
        space = 'space:work'
        evidence = self.add('A single release', level='M1')
        fields = dict(statement='Run preflight', condition='Release', runtimes=['test-work'], supporting=[evidence])
        pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
        key = self.s.confirm_preference(self.owner, space, pin, **fields)['preference_id']
        def evidence_state():
            page = self.s.preference_history(self.owner, space, key, check_evidence=True)
            return page['preferences'][0]['evidence_status'][0]
        self.assertEqual(evidence_state()['state'], 'current')
        old = self.s.memory_for_update(self.work, space, evidence, 1)
        delta = self.s.propose(self.work, self.draft('Revised release observation', old=old))
        self.s.decide(self.owner, delta['delta_id'], True)
        self.assertEqual(evidence_state(), {'memory_id': evidence, 'confirmed_revision': 1,
                                           'current_revision': 2, 'state': 'revised'})
        self.assertEqual(self.s.recall_preferences(self.work, space, 'Release')['preferences'][0]['preference_id'], key)
        self.s.set_memory_validity(self.owner, space, evidence, 2, expires_at=self.now.isoformat())
        self.assertEqual(evidence_state()['state'], 'unavailable')
        self.assertIsNone(evidence_state()['current_revision'])

    def test_owner_review_scan_advances_through_empty_pages(self):
        space = 'space:work'
        refs = {}
        for word in ('first', 'second', 'third'):
            mid = self.add(word, level='M1')
            fields = dict(statement=word, condition='release', runtimes=['test-work'],
                          supporting=[mid], counterexamples=[mid])
            pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
            record = self.s.confirm_preference(self.owner, space, pin, **fields)
            refs[record['preference_id']] = mid
        first, second, third = sorted(refs)
        for key in (second, third):
            self.s.set_memory_validity(self.owner, space, refs[key], 1, expires_at=self.now.isoformat())
        self.s.withdraw_preference(self.owner, space, third)
        def scan(after=''):
            return self.s.list_preferences(self.owner, space, after=after, limit=1, needs_review=True)
        before = self.s.db.read_bytes()
        self.assertEqual(scan(), {'preferences': [], 'next_after': first, 'scanned': 1})
        page = scan(first)
        self.assertIsNone(page['next_after'])
        item, = page['preferences']
        self.assertEqual(item['preference_id'], second)
        self.assertEqual(item['changed_evidence'], [{'memory_id': refs[second], 'confirmed_revision': 1,
                                                    'roles': ['supporting', 'counterexample'],
                                                    'current_revision': None, 'state': 'unavailable'}])
        self.assertEqual(self.s.list_preferences(self.owner, 'space:life', needs_review=True)['scanned'], 0)
        self.fault('E_DENIED', lambda: self.s.list_preferences(self.work, space, needs_review=True))
        self.assertEqual(self.s.db.read_bytes(), before)

    def test_preference_replacement_and_turn_override(self):
        space = 'space:work'
        def confirm(**changes):
            fields = dict(statement='preflight', condition='production', runtimes=['test-work'])
            fields.update(changes)
            pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
            return self.s.confirm_preference(self.owner, space, pin, **fields)['preference_id']
        first = confirm()
        updated = confirm(statement='review preflight', replaces=first)
        self.assertEqual(confirm(statement='review preflight', replaces=first), updated)
        self.fault('E_VERSION_CONFLICT', lambda: confirm(statement='stale edit', replaces=first))
        def context(**opts):
            request = dict(space_refs=[space], purpose='work-task', query='', preference_condition='production')
            return self.s.search(self.work, {**request, **opts}, context=True)['preference_defaults']
        self.assertEqual(context(skip_preferences=True), [])
        self.assertEqual(context(level='M1'), [])
        self.assertEqual([p['preference_id'] for p in context()], [updated])
        self.fault('E_DENIED', lambda: self.s.list_preferences(self.work, space))
        page = self.s.list_preferences(self.owner, space, limit=1)
        second = self.s.list_preferences(self.owner, space, after=page['next_after'])
        records = page['preferences'] + second['preferences']
        self.assertEqual({p['status'] for p in records}, {'superseded', 'confirmed'})
        self.s.withdraw_preference(self.owner, space, updated)
        before = self.s.db.read_bytes()
        page = self.s.preference_history(self.owner, space, updated, limit=1)
        self.assertEqual([p['status'] for p in page['preferences']], ['withdrawn'])
        self.assertEqual(page['next_preference_id'], first)
        older = self.s.preference_history(self.owner, space, first)
        self.assertEqual(older['preferences'][0]['successor'], updated)
        self.assertIsNone(older['next_preference_id'])
        self.fault('E_DENIED', lambda: self.s.preference_history(self.work, space, updated))
        self.fault('E_NOT_FOUND', lambda: self.s.preference_history(self.owner, 'space:life', updated))
        self.assertEqual(self.s.db.read_bytes(), before)
        self.assertEqual(context(), [])

    def test_preference_manifest_tracks_archives_and_isolates_spaces(self):
        work = 'space:work'
        def snapshot(space):
            return self.s.preference_manifest(self.owner, space)
        initial = snapshot(work)
        life = snapshot('space:life')
        self.assertNotEqual(initial['sha256'], life['sha256'])
        fields = dict(statement='Private preference', condition='Planning', runtimes=['test-work'])
        pin = self.s.preview_preference(self.owner, work, **fields)['preview_sha256']
        self.assertEqual(snapshot(work), initial)
        key = self.s.confirm_preference(self.owner, work, pin, **fields)['preference_id']
        confirmed = snapshot(work)
        self.assertEqual(confirmed['record_count'], 1)
        self.assertFalse(confirmed['signed'])
        self.assertNotIn('Private preference', json.dumps(confirmed))
        self.assertNotIn(key, json.dumps(confirmed))
        before = self.s.db.read_bytes()
        self.assertEqual(snapshot(work), confirmed)
        self.fault('E_DENIED', lambda: self.s.preference_manifest(self.work, work))
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.withdraw_preference(self.owner, work, key)
        withdrawn = snapshot(work)
        self.assertEqual(withdrawn['record_count'], 1)
        self.assertNotEqual(confirmed['sha256'], withdrawn['sha256'])
        self.assertEqual(snapshot('space:life'), life)

    def test_signed_preference_manifest_controls_delivery(self):
        space = 'space:work'
        fields = dict(statement='Preflight', condition='Release', runtimes=['test-work'])
        pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
        pref = self.s.confirm_preference(self.owner, space, pin, **fields)
        manifest = self.s.preference_manifest(self.owner, space)
        original = self.s.core(self.owner)['avatar_core']
        ref = {'id': 'preference-manifest:' + space, 'version': 1,
               'scope': manifest['scope'], 'sha256': manifest['sha256']}
        def install(refs):
            core = copy.deepcopy(original)
            del core['integrity']
            core['extensions'].append({'namespace': 'x-aiap-local-preference-index', 'version': '1', 'critical': True})
            core['state_index'].extend(refs)
            self.s._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00')
            with self.s.tx() as c:
                c.execute('UPDATE cores SET body=?,revision=?', (canonical(core).decode(),core['revision']))
        for refs in ([], [ref, ref], [{**ref, 'id': 'preference-manifest:space:life'}]):
            install(refs)
            self.fault('E_INTEGRITY', lambda: self.s.preference_manifest(self.owner, space))
        install([ref])
        self.assertTrue(self.s.preference_manifest(self.owner, space)['signed'])
        detail = self.s.compact_core(self.owner, space=space, revision=original['revision'])
        self.assertEqual(detail['manifest']['preference_manifest'], ref)
        self.assertEqual(detail['manifest']['entries'], [])
        bundle = self.s.compact_core(self.owner)
        compact = bundle['avatar_core']
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from aiap_core.contracts import digest, unb64
        proof = compact.pop('integrity')['proofs'][0]
        key = Ed25519PublicKey.from_public_bytes(unb64(bundle['local_enrollment']['payload']['avatar_public_key']))
        key.verify(unb64(proof['signature']), b'AIAP-LOCAL-COMPACT-CORE-v1\x00' + canonical(compact))
        self.assertEqual(digest(detail['manifest']), detail['sha256'])
        entry = next(r for r in compact['state_index'] if r['scope']['space_ref'] == space)
        self.assertEqual(entry['sha256'], detail['sha256'])
        with self.s.tx() as c:
            self.s._rebuild_core(c, original['avatar_id'])
        rebuilt = self.s.preference_manifest(self.owner, space)
        self.assertEqual((rebuilt['core_revision'], rebuilt['manifest_version']), (original['revision']+1, 1))
        with self.s.tx() as c:
            c.execute("UPDATE cores SET body=json_set(body, '$.previous_revision', 42)")
        self.fault('E_INTEGRITY', lambda: self.s.preference_manifest(self.owner, space))
        install([ref])
        self.assertEqual(len(self.s.recall_preferences(self.work, space, 'Release')['preferences']), 1)
        from unittest.mock import patch
        with patch.object(self.s, '_sign_core', side_effect=OSError('unavailable')), self.assertRaises(OSError):
            self.s.withdraw_preference(self.owner, space, pref['preference_id'])
        self.assertEqual(len(self.s.recall_preferences(self.work, space, 'Release')['preferences']), 1)
        self.s.withdraw_preference(self.owner, space, pref['preference_id'])
        changed = self.s.preference_manifest(self.owner, space)
        self.assertEqual((changed['core_revision'], changed['manifest_version']), (original['revision']+1, 2))
        self.s.withdraw_preference(self.owner, space, pref['preference_id'])
        self.assertEqual(changed, self.s.preference_manifest(self.owner, space))
        newer = dict(fields, statement='New wording')
        new_pin = self.s.preview_preference(self.owner, space, **newer)['preview_sha256']
        self.s.confirm_preference(self.owner, space, new_pin, **newer)
        self.assertEqual(self.s.preference_manifest(self.owner, space)['manifest_version'], 3)
        self.assertEqual(self.s.recall_preferences(self.work, space, 'Release')['preferences'][0]['statement'], 'New wording')
        with self.s.tx() as c:
            c.execute("UPDATE meta SET value=json_set(value, '$.statement','Changed') WHERE key=?", (pref['preference_id'],))
        self.fault('E_INTEGRITY', lambda: self.s.recall_preferences(self.work, space, 'Release'))
        self.fault('E_INTEGRITY', lambda: self.s.compact_core(self.owner))
        self.fault('E_INTEGRITY', lambda: self.s.list_preferences(self.owner, space))
        self.fault('E_INTEGRITY', lambda: self.s.search(self.work, dict(space_refs=[space], purpose='work-task',
            query='', preference_condition='Release'), context=True))

    def test_preference_baseline_binds_core_spaces_and_unsigned_records(self):
        review = self.s.preview_preference_baseline
        self.fault('E_DENIED', lambda: review(self.work))
        partial = self.s.issue_grant(['space:work'], 'owner-maintenance', 'owner', role='owner')['token']
        self.fault('E_DENIED', lambda: review(partial))
        first = review(self.owner)
        db = self.s.db.read_bytes()
        self.assertEqual(review(self.owner), first)
        self.assertEqual(self.s.db.read_bytes(), db)
        fields = dict(statement='Internal example', condition='Release', runtimes=['test-work'])
        space = 'space:work'
        pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
        self.s.confirm_preference(self.owner, space, pin, **fields)
        second = review(self.owner)
        self.assertNotEqual(second['baseline_sha256'], first['baseline_sha256'])
        self.assertEqual(second['baseline']['core_revision'], first['baseline']['core_revision'])
        self.assertNotIn('Internal example', json.dumps(second))
        with self.s.tx() as c:
            c.execute("INSERT INTO meta VALUES('preference:orphan','{}')")
        self.fault('E_INTEGRITY', lambda: review(self.owner))

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'requires POSIX safe checkpoint open')
    def test_inspect_checkpoint_separates_signed_reference_kinds(self):
        from cryptography.hazmat.primitives import serialization
        from aiap_core import recovery_checkpoint as cp
        from aiap_core.contracts import b64, digest
        from aiap_core.service import stamp
        self.add()
        info = self.s.core(self.owner)
        core = info['avatar_core']
        with self.s.tx(read_only=True) as c:
            spaces = [dict(row) for row in c.execute('SELECT * FROM spaces')]
        payload = dict(profile=cp.PROFILE, checkpoint_id='recovery:test', issued_at=stamp(self.now),
                       expires_at=stamp(self.now+timedelta(hours=1)), core=core,
                       enrollment=info['local_enrollment'], spaces=spaces, tombstones=[], revocation_epoch=0)
        key = serialization.load_pem_private_key((Path(self.tmp.name)/'owner-key.pem').read_bytes(), None)
        path = Path(self.tmp.name)/'sample.json'
        def write(signature=None):
            envelope = dict(payload=payload, signature=signature or b64(key.sign(cp.DOMAIN+canonical(payload))))
            path.write_bytes(canonical(envelope))
            return digest(envelope)
        def inspect(pin):
            return cp.inspect_checkpoint_index(path, pin, self.now)
        self.assertEqual(inspect(write())['preference_manifest_count'], 0)
        core['extensions'].append({'namespace':'x-aiap-local-preference-index','version':'1','critical':True})
        manifest = self.s.preference_manifest(self.owner, 'space:work')
        ref = dict(id='preference-manifest:space:work', version=1, scope=manifest['scope'], sha256=manifest['sha256'])
        core['state_index'].append(ref)
        del core['integrity']
        self.s._sign_core(core, 'x-aiap-local-ed25519-json-v1', b'AIAP-LOCAL-CORE-v1\x00')
        pin = write()
        report = inspect(pin)
        self.assertEqual((report['memory_reference_count'], report['preference_manifest_count']), (1,1))
        self.assertFalse(report['source_currentness_verified'])
        self.fault('E_CRITICAL_EXTENSION', lambda: cp.load_checkpoint(path, pin, self.now))
        self.fault('E_CHECKPOINT_PIN', lambda: inspect('0'*64))
        self.fault('E_INTEGRITY', lambda: inspect(write('invalid')))
        self.fault('E_EXPIRED', lambda: cp.inspect_checkpoint_index(path, write(), self.now+timedelta(hours=2)))
        project = dict(avatar=core['avatar_id'], id='space:project:demo', kind='project', policy='policy:project:demo', revision=1)
        spaces.append(project)
        self.assertEqual(inspect(write())['memory_reference_count'], 1)
        spaces.append(project)
        self.fault('E_SCOPE', lambda: inspect(write()))

    def test_decision_reason_is_owner_only_and_stable_on_retry(self):
        for approve, reason in [(True, 'owner-confirmed'), (False, 'outdated')]:
            ident = self.s.propose(self.work, self.draft())['delta_id']
            self.fault('E_DENIED', lambda: self.s.decide(self.work, ident, approve, reason=reason))
            self.s.decide(self.owner, ident, approve, reason=reason)
            self.s.decide(self.owner, ident, approve, reason='duplicate')
            self.assertEqual(self.s.review(self.owner, ident)['decision_reason'], reason)
            self.assertNotIn('decision_reason', self.s.review(self.work, ident))

    def test_expiry_limits_context_and_recall_at_deadline(self):
        ident = self.add('orchard')
        expires = self.now + timedelta(seconds=1)
        self.s.set_memory_validity(self.owner, 'space:work', ident, 1, expires_at=expires.isoformat())
        query = {'space_refs': ['space:work'], 'purpose': 'work-task', 'query': 'orchard'}
        view = self.s.search(self.work, query, context=True)['authorized_view']
        self.assertEqual(self.search()[0]['memory_id'], ident)
        self.now = expires
        self.assertEqual(self.search(), [])
        self.assertEqual(self.s.list_memories(self.work, {'space_ref':'space:work','purpose':'work-task'})['items'], [])
        self.fault('E_EXPIRED', lambda: self.s.acknowledge(self.work, {'view_id':view['view_id']}))
        self.assertEqual(self.s.memory_history(self.owner, 'space:work', ident, revision=2)['record']['content'], 'orchard')

    def test_owner_can_find_and_clear_expired_memory(self):
        ids = sorted([self.add('first rule'), self.add('second rule')])
        for ident in ids:
            self.s.set_memory_validity(self.owner, 'space:work', ident, 1, expires_at=self.now.isoformat())
        query = {'space_ref': 'space:work', 'purpose': 'owner-maintenance', 'validity': 'expired', 'limit': 1}
        self.fault('E_DENIED', lambda: self.s.list_memories(self.work, {**query, 'purpose': 'work-task'}))
        page = self.s.list_memories(self.owner, query)
        self.assertEqual(page['items'][0]['memory_id'], ids[0])
        tail = self.s.list_memories(self.owner, {**query, 'after': page['next_after']})
        self.assertEqual(tail['items'][0]['memory_id'], ids[1])
        self.fault('E_CURSOR', lambda: self.s.list_memories(self.owner, {
            **query, 'after': page['next_after'], 'validity': 'current'}))

        def clear(token, version):
            return self.s.set_memory_validity(token, 'space:work', ids[0], version, clear_expiry=True)
        self.fault('E_DENIED', lambda: clear(self.work, 2))
        self.fault('E_VERSION_CONFLICT', lambda: clear(self.owner, 1))
        self.assertEqual(clear(self.owner, 2)['revision'], 3)
        before = self.s.db.read_bytes()
        self.assertEqual(clear(self.owner, 3)['revision'], 3)
        self.assertEqual(self.s.db.read_bytes(), before)
        self.assertEqual([m['memory_id'] for m in self.search()], ids[:1])
        old = self.s.memory_history(self.owner, 'space:work', ids[0], revision=2)['record']
        self.assertIn('expires_at', old['extensions']['x-aiap-memory-validity-v1'])
        events = self.s.list_audit(self.owner, event='memory-expiry-cleared')['events']
        self.assertEqual([e['object_id'] for e in events], ids[:1])

    def test_supersession_requires_current_same_space_pair(self):
        old, new = self.add('old route'), self.add('new road')
        foreign = self.add('private', space='space:life', token=self.life)
        def replace(target, revision, token=None):
            return self.s.set_memory_validity(token or self.owner, 'space:work', old, 1,
                                              successor_id=target, successor_revision=revision)
        self.fault('E_DENIED', lambda: replace(new, 1, self.work))
        self.fault('E_NOT_FOUND', lambda: replace(foreign, 1))
        self.fault('E_VERSION_CONFLICT', lambda: replace(new, 2))
        replace(new, 1)
        page = self.s.list_memories(self.owner, {'space_ref':'space:work', 'purpose':'owner-maintenance',
                                                'validity':'superseded'})
        self.assertEqual(page['items'][0]['validity']['superseded_by'], {'id':new, 'revision':1})
        self.fault('E_LIFECYCLE_TRANSITION', lambda: self.s.set_memory_validity(
            self.owner, 'space:work', old, 2, clear_expiry=True))
        self.assertEqual([m['memory_id'] for m in self.search()], [new])
        record = self.s.memory_history(self.owner, 'space:work', old, revision=2)['record']
        self.assertEqual(record['extensions']['x-aiap-memory-validity-v1']['superseded_by'],
                         {'id':new,'revision':1})
        self.fault('E_LIFECYCLE_TRANSITION', lambda: self.s.set_memory_validity(
            self.owner, 'space:work', new, 1, successor_id=old, successor_revision=2))

    def test_adapter_archive_requires_owner_decision(self):
        ident = self.add()
        body = {'space_ref': 'space:work', 'purpose': 'work-task', 'memory_id': ident,
                'base_revision': 1, 'reason': 'Project completed'}
        self.fault('E_DENIED', lambda: self.s.propose_archive(self.life, body))
        self.fault('E_DENIED', lambda: self.s.propose_lifecycle(
            self.work, 'space:work', ident, 1, kind='promote', reason='Keep'))
        pending = self.s.propose_archive(self.work, body)['delta_id']
        self.fault('E_DENIED', lambda: self.s.decide(self.work, pending, True, allow_lifecycle=True))
        self.assertEqual(len(self.search()), 1)
        self.s.decide(self.owner, pending, True, allow_lifecycle=True)
        self.assertEqual(self.search(), [])
        self.assertEqual(self.search(include_archived=True)[0]['level'], 'M3')

    def test_browse_scoped_live_pages(self):
        query = {'space_ref': 'space:work', 'purpose': 'work-task', 'limit': 1}
        def page(**options):
            return self.s.list_memories(self.work, {**query, **options})
        ids = sorted(self.add(str(i), level='M1') for i in range(3))
        self.add('private', space='space:life', token=self.life)
        before = self.s.db.read_bytes()
        first = page()
        item, = first['items']
        self.assertEqual(item['memory_id'], ids[0])
        cursor = first['next_after']
        tail = page(after=cursor, limit=5)
        self.assertEqual([i['memory_id'] for i in tail['items']], ids[1:])
        self.assertIsNone(tail['next_after'])
        self.fault('E_CURSOR', lambda: self.s.list_memories(self.life, {
            'space_ref': 'space:life', 'purpose': 'life-task', 'after': cursor}))
        self.fault('E_DENIED', lambda: page(space_ref='space:life'))
        self.fault('E_CURSOR', lambda: page(after=cursor, level='M2'))
        self.assertTrue(page(level='M1', memory_type=item['type'], updated_from=item['updated_at'])['items'])
        self.assertFalse(page(updated_before=item['updated_at'])['items'])
        self.fault('E_SCHEMA', lambda: page(updated_from='yesterday'))
        self.assertEqual(before, self.s.db.read_bytes())
        late = self.add('later', level='M1')
        archived = self.s.propose_lifecycle(self.owner, 'space:work', ids[1], 1, kind='archive', reason='Done')
        self.s.decide(self.owner, archived['delta_id'], True, allow_lifecycle=True)
        tail = page(after=cursor, limit=5)
        self.assertEqual([i['memory_id'] for i in tail['items']], sorted(i for i in [ids[2], late] if i > ids[0]))
        self.assertEqual(page(level='M3')['items'][0]['memory_id'], ids[1])

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
    def test_http_list_memories(self):
        result = self.client.call('/v1/memories/list', {'space_ref': 'space:work', 'purpose': 'work-task'})
        self.assertEqual(result, {'space_ref': 'space:work', 'items': [], 'next_after': None})

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
    def test_http_preference_condition_discovery_pages_authorized_labels(self):
        space = 'space:work'
        path = '/v1/preferences/conditions'
        body = dict(space_ref=space, purpose='work-task', after='')
        def confirm(condition, runtime='test-work', statement='Default'):
            fields = dict(statement=statement, condition=condition, runtimes=[runtime])
            pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
            return self.s.confirm_preference(self.owner, space, pin, **fields)['preference_id']
        labels = [f'Release {i:02}' for i in range(21)]
        for label in labels:
            confirm(label)
        confirm(labels[0], statement='Second default')
        confirm('Private label', runtime='other')
        self.s.withdraw_preference(self.owner, space, confirm('Archived'))
        before = self.s.db.read_bytes()
        page = self.client.call(path, body)
        self.assertEqual(page, {'space_ref': space, 'conditions': labels[:20], 'next_after': labels[19]})
        self.assertEqual(self.client.call(path, {**body, 'after': page['next_after']}),
                         {'space_ref': space, 'conditions': labels[20:], 'next_after': None})
        for edits in ({'purpose':'other'}, {'space_ref':'space:life'}):
            with self.assertRaisesRegex(RuntimeError, 'E_DENIED'):
                self.client.call(path, {**body, **edits})
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.revoke_grant(self.s.session(self.work)['auth_evidence_ref'])
        with self.assertRaisesRegex(RuntimeError, 'E_IDENTITY'):
            self.client.call(path, body)

    def test_http_preference_pages_are_grant_bound(self):
        space = 'space:work'
        for text in ['First', 'Second']:
            fields = dict(statement=text, condition='Release', runtimes=['test-work'])
            pin = self.s.preview_preference(self.owner, space, **fields)['preview_sha256']
            self.s.confirm_preference(self.owner, space, pin, **fields)
        path = '/v1/preferences/recall'
        req = dict(space_ref=space, purpose='work-task', condition='Release', limit=1)
        cursor = self.client.call(path, req)['next_after']
        another = self.s.issue_grant([space], 'work-task', 'test-work')
        with self.assertRaisesRegex(RuntimeError, 'E_CURSOR'):
            Client(self.base, another['token']).call(path, {**req, 'after':cursor})
        view = dict(space_refs=[space], purpose='work-task', query='', limit=1,
                    preference_condition='Release', preference_after=cursor, skip_preferences=True)
        skipped = self.client.call('/v1/context', view)
        self.assertEqual(skipped['preference_defaults'], [])
        self.assertNotIn('next_preference_after', skipped)
        self.s.revoke_grant(self.s.session(self.work)['auth_evidence_ref'])
        with self.assertRaisesRegex(RuntimeError, 'E_IDENTITY'):
            self.client.call(path, {**req, 'after':cursor})

    def test_http_preference_recall_binds_scope_purpose_and_live_grant(self):
        path = '/v1/preferences/recall'
        body = dict(space_ref='space:work', purpose='work-task', condition='Release', limit=1)
        before = self.s.db.read_bytes()
        self.assertEqual(self.client.call(path, body), {'space_ref': 'space:work', 'preferences': [], 'possibly_more': False})
        for edits, error in [({'space_ref':'space:life'}, 'E_DENIED'), ({'purpose':'other'}, 'E_DENIED'),
                             ({'purpose':None}, 'E_SCHEMA'), ({'limit':True}, 'E_SCHEMA'),
                             ({'runtime':'other'}, 'E_SCHEMA')]:
            with self.subTest(edits=edits), self.assertRaisesRegex(RuntimeError, error):
                self.client.call(path, {**body, **edits})
        self.assertEqual(self.s.db.read_bytes(), before)
        self.s.revoke_grant(self.s.session(self.work)['auth_evidence_ref'])
        with self.assertRaisesRegex(RuntimeError, 'E_IDENTITY'):
            self.client.call(path, body)

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
