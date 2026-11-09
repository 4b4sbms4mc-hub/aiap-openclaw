# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_recovery_guard as recovery_tests
from recovery_guard import Service, digest, restore_snapshot, canonical
from recovery_witness import WitnessReader
from recovery_highwater import DurableWitnessReader
from recovery_source_gate import SourceGate, ExperimentalGatedService, governance
from aiap_core.client import proposal
from aiap_core.contracts import Fault

CHILD = '''
import json,sys,time
from pathlib import Path
from datetime import datetime
sys.path.insert(0, sys.argv[1])
from recovery_source_gate import SourceGate,ExperimentalGatedService
print('READY',flush=True)
sys.stdin.readline()
gate=SourceGate(sys.argv[2],sys.argv[3],json.loads(sys.argv[4]),lambda:datetime.fromisoformat(sys.argv[5]))
def barrier(phase):
    if phase==sys.argv[6]:
        print('AT_BARRIER',flush=True)
        while True: time.sleep(1)
gate._event=barrier
owner=json.loads((Path(sys.argv[2])/'owner-credentials.json').read_text())['token']
ExperimentalGatedService(gate).delete(owner,{'memory_id':sys.argv[7], 'space_ref':'space:general','base_revision':int(sys.argv[8])})
print('DONE',flush=True)
'''


class SourceGateTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery_tests.RecoveryTests()
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.now = self.f.now
        self.directory = self.f.root / 'source-controls'
        self.gate = SourceGate.enroll(self.f.current, self.directory, self.f.checkpoint,
                                     self.f.pin, lambda: self.now)
        self.service = ExperimentalGatedService(self.gate)
        self.reader = WitnessReader(clock=lambda: self.now, **self.gate.trust)

    def reopen(self, source=None, control=None):
        return SourceGate(source or self.f.current, control or self.directory,
                          self.gate.trust, lambda: self.now)

    def delete(self, service=None, mid=None, revision=1):
        return (service or self.service).delete(self.f.owner,
            {'memory_id': mid or self.f.keep, 'space_ref': 'space:general', 'base_revision': revision})

    def has(self, ident, directory=None):
        records=Service(directory or self.f.current, clock=lambda: self.now).search(self.f.owner,
            {'space_refs':['space:general'],'purpose':'owner-maintenance','query':''})['items']
        return ident in {r['memory_id'] for r in records}

    def reject(self, code, callback):
        with self.assertRaises(Fault) as error: callback()
        self.assertEqual(error.exception.code, code)

    def proof(self, gate=None, reader=None):
        return (gate or self.gate).answer((reader or self.reader).challenge())

    def fail_phase(self, phase):
        def event(at):
            if at == phase: raise OSError('INJECTED_'+phase)
        return patch.object(self.gate, '_event', side_effect=event)

    def test_delete_checkpoint_and_durable_reader_to_real_isolated_restore(self):
        snapshot=self.f.root/'pre-gate-delete';shutil.copytree(self.f.current,snapshot)
        initial=self.proof()
        d=DurableWitnessReader.enroll(self.f.root/'reader',self.reader,initial,digest(self.gate.head))
        self.delete()
        pin=d.verify(self.proof(reader=d))
        checkpoint=self.directory/('checkpoint-'+pin+'.json')
        payload=json.loads(checkpoint.read_text())['payload']
        self.assertIn(self.f.keep,{r['id'] for r in payload['tombstones']})
        report=restore_snapshot(snapshot,checkpoint,pin,self.f.target,clock=lambda:self.now)
        self.assertEqual(report['restored_objects'],2)
        with Service(self.f.target).tx() as db:
            self.assertIsNone(db.execute('SELECT id FROM memories WHERE id=?',(self.f.keep,)).fetchone())
        self.assertEqual(d.head['sequence'],2)

    def test_read_and_nongovernance_operations_do_not_advance_witness(self):
        self.service.session(self.f.owner);self.service.core(self.f.owner)
        self.service.search(self.f.owner,{'space_refs':['space:general'],'purpose':'owner-maintenance','query':''},context=True)
        self.service.issue_grant(['space:general'],'memory','extra-runtime')
        draft=proposal(self.service.session(self.f.owner),'space:general','PENDING_ONLY')
        delta=self.service.propose(self.f.owner,draft)
        self.service.decide(self.f.owner,delta['delta_id'],False)
        self.assertEqual(self.gate.head['sequence'],1)
        self.reader.verify(self.proof())

    def test_approval_publishes_new_governance(self):
        draft=proposal(self.service.session(self.f.owner),'space:general','APPROVED_GATE')
        delta=self.service.propose(self.f.owner,draft)
        self.service.decide(self.f.owner,delta['delta_id'],True)
        self.assertEqual(self.gate.head['sequence'],2)
        self.assertTrue(self.has(draft['bindings'][0]['target_object_id']))

    def test_acknowledgement_publishes_changed_record(self):
        view=self.service.search(self.f.owner,{'space_refs':['space:general'],'purpose':'owner-maintenance','query':''},context=True)['authorized_view']['view_id']
        self.service.acknowledge(self.f.owner,{'view_id':view})
        self.assertEqual(self.gate.head['sequence'],2)
        self.service.acknowledge(self.f.owner,{'view_id':view})
        self.assertEqual(self.gate.head['sequence'],2)

    def test_archive_cycle_publishes_changed_records(self):
        self.now+=timedelta(days=181)
        self.assertGreater(self.service.archive_cycle()['archived'],0)
        self.assertEqual(self.gate.head['sequence'],2)
        self.reader.verify(self.proof())

    def test_revocation_publishes_epoch_even_without_core_revision_change(self):
        grant=self.service.issue_grant(['space:general'],'memory','runtime')
        before=self.gate.head
        self.service.revoke_grant(grant['grant_id'])
        after=self.gate.head
        self.assertEqual(after['sequence'],2)
        self.assertEqual(after['core_revision'],before['core_revision'])
        self.assertEqual(after['revocation_epoch'],before['revocation_epoch']+1)

    def test_pending_write_failure_prevents_source_commit(self):
        with patch.object(self.gate,'_save',side_effect=OSError('NO_PENDING_STORAGE')):
            with self.assertRaises(OSError):self.delete()
        self.assertTrue(self.has(self.f.keep))
        self.assertEqual(self.gate.head['sequence'],1)
        self.reader.verify(self.proof())

    def test_sql_failure_after_pending_rolls_back_but_remains_blocked_after_restart(self):
        with self.fail_phase('pending_saved'):
            with self.assertRaises(OSError):self.delete()
        restarted=self.reopen()
        self.assertTrue(self.has(self.f.keep))
        self.reject('E_WITNESS_UNAVAILABLE',lambda:restarted.answer(self.reader.challenge()))
        self.reject('E_WITNESS_PENDING',lambda:self.delete(ExperimentalGatedService(restarted)))
        restarted.resync()
        self.assertTrue(self.has(self.f.keep))
        self.reader.verify(self.proof(restarted))

    def test_committed_source_with_export_failure_refuses_until_resync(self):
        with self.fail_phase('source_committed'):
            with self.assertRaises(OSError):self.delete()
        self.assertFalse(self.has(self.f.keep))
        restarted=self.reopen()
        self.reject('E_WITNESS_UNAVAILABLE',lambda:restarted.answer(self.reader.challenge()))
        with self.assertRaises(TypeError):restarted.resync(checkpoint=self.f.older_checkpoint)
        restarted.resync()
        self.assertFalse(self.has(self.f.keep))
        self.assertEqual(self.reader.verify(self.proof(restarted)),restarted.head['checkpoint_sha256'])

    def test_exported_unpublished_checkpoint_is_not_automatically_activated(self):
        with self.fail_phase('checkpoint_exported'):
            with self.assertRaises(OSError):self.delete()
        self.assertGreater(len(list(self.directory.glob('checkpoint-*.json'))),1)
        restarted=self.reopen()
        self.reject('E_WITNESS_UNAVAILABLE',lambda:restarted.answer(self.reader.challenge()))
        self.assertEqual(restarted.head['sequence'],1)
        self.assertEqual(restarted.resync()['sequence'],2)

    def test_response_failure_after_head_publication_resync_is_idempotent(self):
        with self.fail_phase('head_published'):
            with self.assertRaises(OSError):self.delete()
        restarted=self.reopen()
        head=restarted.head
        self.assertEqual(head['sequence'],2)
        self.assertEqual(restarted.resync(),head)
        self.reader.verify(self.proof(restarted))

    def test_answer_refuses_while_transaction_writer_holds_gate_lock(self):
        observed=[]
        def event(phase):
            if phase in ('pending_saved','source_committed','checkpoint_exported'):
                self.reject('E_WITNESS_UNAVAILABLE',lambda:self.gate.answer(self.reader.challenge()))
                observed.append(phase)
        with patch.object(self.gate,'_event',side_effect=event):self.delete()
        self.assertEqual(observed,['pending_saved','source_committed','checkpoint_exported'])
        self.reader.verify(self.proof())

    def test_direct_production_service_bypass_detected_at_next_live_digest_check(self):
        self.delete(self.f.service)
        self.reject('E_SOURCE_DIVERGED',lambda:self.proof())
        self.reject('E_SOURCE_DIVERGED',lambda:self.service.session(self.f.owner))
        self.reject('E_SOURCE_DIVERGED',self.gate.resync)
        # Production writers still bypass the gate lock; no post-proof race guarantee.

    def test_explicit_enrollment_rejects_stale_checkpoint_and_existing_controls(self):
        other=self.f.root/'stale-controls'
        self.reject('E_SOURCE_DIVERGED',lambda:SourceGate.enroll(self.f.current,other,
            self.f.older_checkpoint,self.f.older_pin,lambda:self.now))
        self.assertFalse(other.exists())
        before=(self.directory/'gate-state.json').read_bytes()
        with self.assertRaises(FileExistsError):
            SourceGate.enroll(self.f.current,self.directory,self.f.checkpoint,self.f.pin,lambda:self.now)
        self.assertEqual((self.directory/'gate-state.json').read_bytes(),before)

    def test_missing_corrupt_state_and_trust_change_do_not_recreate_witness(self):
        wrong=dict(self.gate.trust,generation='wrong')
        self.reject('E_GATE_ENROLLMENT',lambda:SourceGate(self.f.current,self.directory,wrong,lambda:self.now))
        state=self.directory/'gate-state.json'
        saved=state.read_bytes();state.write_bytes(b'CORRUPT')
        with self.assertRaises(ValueError):self.reopen()
        state.unlink()
        with self.assertRaises(FileNotFoundError):self.reopen()
        self.assertFalse(state.exists())
        state.write_bytes(saved);state.chmod(0o600)
        self.reader.verify(self.proof(self.reopen()))

    def test_live_enrollment_change_is_rejected_even_if_core_digest_unchanged(self):
        with self.f.service.tx() as db:
            value=Service('.').meta(db,'enrollment')
            value['payload']['owner_ref']='aiap-id:unexpected'
            db.execute("UPDATE meta SET value=? WHERE key='enrollment'",(json.dumps(value),))
        self.reject('E_IDENTITY',lambda:self.proof())
        self.reject('E_IDENTITY',lambda:self.service.session(self.f.owner))

    def test_control_permissions_symlinks_and_private_key_binding(self):
        path=self.directory/'gate-state.json'
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        path.chmod(0o644)
        self.reject('E_READER_STORAGE',self.reopen)
        path.chmod(0o600)
        original=path.read_bytes()
        state=json.loads(original)
        import base64
        state['key']=base64.b64encode(bytes(32)).decode()
        path.write_bytes(canonical(state))
        self.reject('E_GATE_ENROLLMENT',self.reopen)
        saved=self.directory/'original-state.json'
        saved.write_bytes(original);saved.chmod(0o600)
        path.unlink();path.symlink_to(saved)
        self.reject('E_READER_STORAGE',self.reopen)

    def test_full_source_and_control_rollback_remains_explicit_limit(self):
        dbcopy=self.f.root/'old-core.sqlite3';shutil.copyfile(self.f.current/'core.sqlite3',dbcopy)
        old=(self.directory/'gate-state.json').read_bytes()
        self.delete();self.reader.verify(self.proof())
        shutil.copyfile(dbcopy,self.f.current/'core.sqlite3')
        (self.directory/'gate-state.json').write_bytes(old)
        restarted=self.reopen()
        fresh=WitnessReader(clock=lambda:self.now,**self.gate.trust)
        self.assertEqual(fresh.verify(self.proof(restarted,fresh)),self.f.pin)
        self.reject('E_WITNESS_ROLLBACK',lambda:self.reader.verify(self.proof(restarted)))

    def child(self,source,control,phase,mid,revision):
        p=subprocess.Popen([sys.executable,'-c',CHILD,str(Path(__file__).resolve().parents[1]),
            str(source),str(control),json.dumps(self.gate.trust),self.now.isoformat(),phase,mid,str(revision)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.stop,p)
        self.assertEqual(self.line(p),'READY')
        return p

    def line(self,p):
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=15),'child barrier timed out')
        line=p.stdout.readline().strip()
        if not line and p.poll() is not None:
            self.fail('child exited unexpectedly: '+p.stderr.read()[-600:])
        return line

    def stop(self,p):
        if p.poll() is None:p.kill()
        p.communicate(timeout=5)

    @unittest.skipUnless(os.name=='posix','requires POSIX kill/flock')
    def test_sigkill_at_each_commit_boundary_is_fail_closed_and_resyncs_real_source(self):
        # Separate equal source/control copies for each phase; all generated test data.
        original=(self.directory/'gate-state.json').read_bytes()
        for phase in ('pending_saved','source_committed','checkpoint_exported','head_published'):
            with self.subTest(phase=phase):
                source=self.f.root/('source-'+phase);control=self.f.root/('control-'+phase)
                shutil.copytree(self.f.current,source);shutil.copytree(self.directory,control)
                state=json.loads(original);state['source']=str(source.resolve())
                (control/'gate-state.json').write_bytes(canonical(state))
                p=self.child(source,control,phase,self.f.keep,1)
                p.stdin.write('GO\n');p.stdin.flush()
                self.assertEqual(self.line(p),'AT_BARRIER')
                p.kill();p.communicate(timeout=5)
                self.assertLess(p.returncode,0)
                gate=self.reopen(source,control)
                self.assertEqual(self.has(self.f.keep,source),phase=='pending_saved')
                reader=WitnessReader(clock=lambda:self.now,**self.gate.trust)
                if phase!='head_published':
                    self.reject('E_WITNESS_UNAVAILABLE',lambda:gate.answer(reader.challenge()))
                gate.resync()
                reader.verify(gate.answer(reader.challenge()))
                self.assertEqual(gate.head['sequence'],2)

    @unittest.skipUnless(os.name=='posix','requires POSIX subprocess/flock')
    def test_two_real_process_writers_serialize_without_losing_deletions(self):
        a=self.child(self.f.current,self.directory,'none',self.f.keep,1)
        b=self.child(self.f.current,self.directory,'none',self.f.stale,2)
        for p in (a,b):p.stdin.write('GO\n');p.stdin.flush()
        for p in (a,b):
            self.assertEqual(self.line(p),'DONE')
            p.communicate(timeout=5);self.assertEqual(p.returncode,0)
        gate=self.reopen()
        self.assertEqual(gate.head['sequence'],3)
        self.assertFalse(self.has(self.f.keep));self.assertFalse(self.has(self.f.stale))
        with Service(self.f.current).tx() as db:
            self.assertEqual(digest(governance(db)),gate.head['governance_sha256'])
        self.reader.verify(self.proof(gate))


if __name__=='__main__':unittest.main()
