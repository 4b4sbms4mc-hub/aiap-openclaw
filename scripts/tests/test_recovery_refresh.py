# SPDX-License-Identifier: Apache-2.0
from datetime import timedelta
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_recovery_source_gate as gate_tests
from recovery_guard import digest
from recovery_highwater import DurableWitnessReader
from recovery_witness import WitnessReader

CHILD='''
import sys,json,time
from datetime import datetime
sys.path.insert(0,sys.argv[1])
from recovery_source_gate import SourceGate
from recovery_guard import Fault
print('READY',flush=True)
sys.stdin.readline()
gate=SourceGate(sys.argv[2],sys.argv[3],json.loads(sys.argv[4]),lambda:datetime.fromisoformat(sys.argv[5]))
def barrier(phase):
    if phase==sys.argv[6]:
        print('AT_BARRIER',flush=True)
        while True:time.sleep(1)
gate._event=barrier
try:gate.refresh(1);print('DONE',flush=True)
except Fault as error:print('REJECT:'+error.code,flush=True)
'''


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.x=gate_tests.SourceGateTests();self.x.setUp()
        self.addCleanup(self.x.doCleanups)
        self.gate=self.x.gate

    def test_expired_checkpoint_renews_without_changing_identity_source_or_grants(self):
        d=DurableWitnessReader.enroll(self.x.f.root/'reader',self.x.reader,
            self.x.proof(),digest(self.gate.head))
        before=self.x.f.hashes(self.x.f.current);old=self.gate.head
        self.x.now+=timedelta(hours=2)
        self.x.reject('E_EXPIRED',lambda:self.x.proof())
        new=self.gate.refresh(1)
        self.assertEqual(new['sequence'],2)
        self.assertNotEqual(new['checkpoint_sha256'],old['checkpoint_sha256'])
        for key in ('avatar_id','enrollment_sha256','generation','core_revision',
                    'revocation_epoch','governance_sha256'):
            self.assertEqual(old[key],new[key])
        self.assertGreater(new['checkpoint_expires_at'],old['checkpoint_expires_at'])
        self.assertEqual(d.verify(self.x.proof(reader=d)),new['checkpoint_sha256'])
        self.assertEqual(self.x.f.hashes(self.x.f.current),before)

    def test_refresh_requires_current_strict_sequence(self):
        for value in (True,0,2,None,'1'):
            self.x.reject('E_WITNESS_SEQUENCE',lambda value=value:self.gate.refresh(value))
        self.gate.refresh(1)
        self.x.reject('E_WITNESS_SEQUENCE',lambda:self.gate.refresh(1))
        self.assertEqual(self.gate.head['sequence'],2)

    def test_refresh_does_not_hide_pending_source_update(self):
        with self.x.fail_phase('source_committed'):
            with self.assertRaises(OSError):self.x.delete()
        self.x.reject('E_WITNESS_PENDING',lambda:self.gate.refresh(1))
        self.gate.resync()
        self.assertFalse(self.x.has(self.x.f.keep))

    def test_missing_and_modified_selected_checkpoint_cannot_be_renewed(self):
        path=self.x.directory/('checkpoint-'+self.x.f.pin+'.json')
        raw=path.read_bytes();path.write_bytes(raw+b' ')
        self.x.reject('E_CHECKPOINT_PIN',lambda:self.gate.refresh(1))
        path.unlink()
        with self.assertRaises(FileNotFoundError):self.gate.refresh(1)
        self.assertIsNone(self.gate._load()[0]._pending)

    def test_clock_rollback_or_changed_source_cannot_be_renewed(self):
        self.x.now-=timedelta(minutes=1)
        self.x.reject('E_EXPIRED',lambda:self.gate.refresh(1))
        self.x.now=self.x.f.now
        self.x.delete(self.x.f.service)
        self.x.reject('E_SOURCE_DIVERGED',lambda:self.gate.refresh(1))
        self.assertEqual(self.gate.head['sequence'],1)

    def test_pending_persist_failure_does_not_publish_new_head(self):
        before=(self.x.directory/'gate-state.json').read_bytes()
        with patch.object(self.gate,'_save',side_effect=OSError('NO_PENDING_DISK')):
            with self.assertRaises(OSError):self.gate.refresh(1)
        self.assertEqual((self.x.directory/'gate-state.json').read_bytes(),before)
        self.x.reader.verify(self.x.proof())

    def test_refresh_failure_keeps_pending_until_resync(self):
        with self.x.fail_phase('refresh_pending_saved'):
            with self.assertRaises(OSError):self.gate.refresh(1)
        restarted=self.x.reopen()
        self.x.reject('E_WITNESS_UNAVAILABLE',lambda:self.x.proof(restarted))
        self.assertEqual(restarted.resync()['sequence'],2)
        self.x.reader.verify(self.x.proof(restarted))

    def test_source_change_after_capture_refuses_publication_and_keeps_pending(self):
        def mutate(phase):
            if phase=='checkpoint_exported':self.x.delete(self.x.f.service)
        with patch.object(self.gate,'_event',side_effect=mutate):
            self.x.reject('E_SOURCE_DIVERGED',lambda:self.gate.refresh(1))
        self.assertFalse(self.x.has(self.x.f.keep))
        self.x.reject('E_WITNESS_UNAVAILABLE',lambda:self.x.proof())
        self.gate.resync()
        self.assertEqual(self.gate.head['sequence'],2)

    def child(self,phase):
        p=subprocess.Popen([sys.executable,'-c',CHILD,str(Path(__file__).resolve().parents[1]),
            str(self.x.f.current),str(self.x.directory),json.dumps(self.gate.trust),
            self.x.now.isoformat(),phase],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.stop,p)
        self.assertEqual(self.line(p),'READY')
        return p

    def stop(self,p):
        if p.poll() is None:p.kill()
        p.communicate(timeout=5)

    def line(self,p):
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout,selectors.EVENT_READ)
            self.assertTrue(sel.select(timeout=15),'child timed out')
        return p.stdout.readline().strip()

    @unittest.skipUnless(os.name=='posix','requires POSIX kill/flock')
    def test_sigkill_pending_capture_publication_restarts_fail_closed(self):
        for phase in ('refresh_pending_saved','checkpoint_exported','head_published'):
            with self.subTest(phase=phase):
                # Restore this test's private initial controls for independent crash cases.
                if phase=='refresh_pending_saved':
                    initial=(self.x.directory/'gate-state.json').read_bytes()
                else:(self.x.directory/'gate-state.json').write_bytes(initial)
                p=self.child(phase);p.stdin.write('GO\n');p.stdin.flush()
                self.assertEqual(self.line(p),'AT_BARRIER')
                p.kill();p.communicate(timeout=5)
                restarted=self.x.reopen()
                if phase!='head_published':
                    self.x.reject('E_WITNESS_UNAVAILABLE',lambda:self.x.proof(restarted))
                self.assertEqual(restarted.resync()['sequence'],2)
                reader=WitnessReader(clock=lambda:self.x.now,**self.gate.trust)
                reader.verify(restarted.answer(reader.challenge()))

    @unittest.skipUnless(os.name=='posix','requires POSIX process/flock')
    def test_two_refreshers_using_same_expected_sequence_only_publish_once(self):
        a=self.child('none');b=self.child('none')
        for p in (a,b):p.stdin.write('GO\n');p.stdin.flush()
        results=[self.line(p) for p in (a,b)]
        self.assertCountEqual(results,['DONE','REJECT:E_WITNESS_SEQUENCE'])
        self.assertEqual(self.gate.head['sequence'],2)


if __name__=='__main__':unittest.main()
