# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_recovery_source_gate as gate_tests
from recovery_guard import Service, digest, canonical
from recovery_highwater import DurableWitnessReader
from recovery_control_review import review_control_loss


class ControlLossReviewTests(unittest.TestCase):
    def setUp(self):
        self.x=gate_tests.SourceGateTests();self.x.setUp()
        self.addCleanup(self.x.doCleanups)
        self.d=DurableWitnessReader.enroll(self.x.f.root/'independent-reader',self.x.reader,
            self.x.proof(),digest(self.x.gate.head))

    def review(self,source=None,control=None):
        return review_control_loss(source or self.x.f.current,control or self.x.directory,self.d)

    def test_missing_directory_only_reports_and_never_regenerates_keys(self):
        shutil.rmtree(self.x.directory)
        before=self.x.f.hashes(self.x.f.current)
        reader_before=self.d.db.read_bytes()
        result=self.review()
        self.assertEqual(result['status'],'manual-owner-review-required')
        self.assertEqual(result['control_condition'],'missing-directory')
        self.assertFalse(result['automatic_reenrollment'])
        self.assertFalse(result['proofs_may_resume'])
        self.assertFalse(self.x.directory.exists())
        self.assertEqual(self.x.f.hashes(self.x.f.current),before)
        self.assertEqual(self.d.db.read_bytes(),reader_before)

    def test_missing_state_or_lock_and_corruption_stay_manual_review(self):
        state=self.x.directory/'gate-state.json';saved=state.read_bytes()
        state.unlink()
        self.assertEqual(self.review()['control_condition'],'missing-gate-state.json')
        state.write_bytes(b'CORRUPT');state.chmod(0o600)
        self.assertEqual(self.review()['control_condition'],'corrupt-state-requires-owner-review')
        state.write_bytes(saved)
        (self.x.directory/'gate.lock').unlink()
        self.assertEqual(self.review()['control_condition'],'missing-gate.lock')

    def test_present_controls_are_not_automatically_declared_authenticated(self):
        result=self.review()
        self.assertEqual(result['control_condition'],'present-requires-separate-authentication')
        self.assertFalse(result['proofs_may_resume'])

    def test_report_contains_no_memory_body_tokens_or_private_key(self):
        raw=canonical(self.review())
        state=json.loads((self.x.directory/'gate-state.json').read_text())
        for value in ('KEEP_SYNTHETIC',self.x.f.owner,self.x.f.adapter['token'],state['key']):
            self.assertNotIn(value.encode(),raw)

    def test_independent_reader_higher_floor_blocks_old_source_snapshot(self):
        old=self.x.f.root/'old-source';shutil.copytree(self.x.f.current,old)
        self.x.delete()
        self.d.verify(self.x.proof(reader=self.d))
        result=self.review(source=old)
        self.assertEqual(result['status'],'blocked-source-rollback-or-divergence')
        self.assertFalse(result['proofs_may_resume'])

    def test_newer_source_is_only_review_evidence_not_currentness_proof(self):
        self.x.delete()
        result=self.review()
        self.assertEqual(result['source_relation'],'counters-newer-than-last-seen')
        self.assertEqual(result['last_seen_sequence'],1)
        self.assertFalse(result['proofs_may_resume'])

    def test_same_counters_but_changed_tombstone_manifest_blocks_review(self):
        # Core signature does not cover the tombstone table; compare full governance
        # at the same trusted counters rather than treating counters alone as authority.
        with self.x.f.service.tx() as db:db.execute('DELETE FROM tombstones')
        result=self.review()
        self.assertEqual(result['status'],'blocked-source-rollback-or-divergence')

    def test_snapshot_without_private_keys_can_be_reviewed(self):
        source=self.x.f.root/'no-keys';shutil.copytree(self.x.f.current,source)
        for name in ('owner-key.pem','avatar-key.pem','owner-credentials.json'):
            (source/name).unlink()
        self.assertEqual(self.review(source=source)['status'],'manual-owner-review-required')

    def test_bad_enrollment_and_modified_body_rejected(self):
        with self.x.f.service.tx() as db:
            db.execute("UPDATE memories SET body=replace(body,'KEEP_SYNTHETIC','MODIFIED') WHERE id=?",(self.x.f.keep,))
        self.x.reject('E_INTEGRITY',self.review)
        # An independent source snapshot cannot substitute a different identity.
        other=self.x.f.root/'other';Service(other,clock=lambda:self.x.now).initialize()
        self.x.reject('E_IDENTITY',lambda:self.review(source=other))

    def test_active_sidecar_unknown_schema_and_symlink_refused(self):
        sidecar=self.x.f.current/'core.sqlite3-wal';sidecar.write_bytes(b'ACTIVE')
        self.x.reject('E_OPERATION_UNSUPPORTED',self.review);sidecar.unlink()
        with self.x.f.service.tx() as db:db.execute('CREATE TABLE unexpected(x)')
        self.x.reject('E_OPERATION_UNSUPPORTED',self.review)
        with self.x.f.service.tx() as db:db.execute('DROP TABLE unexpected')
        db=self.x.f.current/'core.sqlite3';moved=self.x.f.current/'original.sqlite3'
        db.rename(moved);db.symlink_to(moved)
        self.x.reject('E_READER_STORAGE',self.review)

    def test_missing_reader_and_overlapping_locations_never_fallback_to_backup(self):
        self.d.db.unlink()
        with self.assertRaises(FileNotFoundError):self.review()
        self.assertFalse(self.d.db.exists())

    def test_reader_cannot_be_inside_source_or_lost_controls(self):
        reader_path=self.x.f.current/'reader';shutil.copytree(self.d.directory,reader_path)
        copied=DurableWitnessReader(reader_path,clock=lambda:self.x.now,**self.d.trust)
        self.x.reject('E_GATE_LOCATION',lambda:review_control_loss(
            self.x.f.current,self.x.directory,copied))
        self.x.reject('E_GATE_LOCATION',lambda:self.review(control=self.x.f.current/'controls'))


if __name__=='__main__':unittest.main()
