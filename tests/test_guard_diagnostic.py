import json
import sqlite3
import unittest
from unittest.mock import patch

from workrelay.attestor import verify, AttestationError
from workrelay.cli import GuardFailure, admission
from workrelay.guard_diagnostic import sanitize
from workrelay.managed_control import initialize, record_denial


class GuardDiagnosticTests(unittest.TestCase):
    config = {'model': {'providerID': 'openai', 'id': 'fixture'}, 'quota_command': '/fixture'}

    def denied(self, inventory):
        class Client:
            def request(self, method, path):
                assert (method, path) == ('GET', '/api/plugin')
                return {'data': inventory}
        with self.assertRaises(AttestationError) as raised:
            verify(self.config, Client())
        self.assertEqual(raised.exception.check_id, 'GUARD_PLUGIN_STATE')
        return raised.exception

    def test_every_collapsed_guard_branch_is_finite(self):
        entry = lambda state: {'id': 'subscription.guard', 'state': state, 'PRIVATE': 'PRIVATE'}
        cases = [({}, 'inventory_not_list'), ([None], 'entry_not_object'),
                 ([{'id': 'PRIVATE'}], 'guard_missing'),
                 ([entry({}), entry({})], 'guard_duplicate'),
                 ([entry('PRIVATE')], 'state_not_object'),
                 ([entry({})], 'status_missing'),
                 ([entry({'status': 'PRIVATE', 'message': 'PRIVATE'})], 'status_not_active')]
        for inventory, reason in cases:
            with self.subTest(reason=reason):
                diagnostic = self.denied(inventory).guard_diagnostic
                self.assertEqual(diagnostic['reason'], reason)
                self.assertNotIn('PRIVATE', json.dumps(diagnostic))

    def test_pass_and_transport_response_failures_are_not_guard_state(self):
        class Client:
            def request(self, method, path):
                return {'data': [{'id': 'subscription.guard', 'state': {'status': 'active'}}]}
        # The active predicate passes; its missing source fails at a later check.
        with self.assertRaises(AttestationError) as raised:
            verify(self.config, Client())
        self.assertEqual(raised.exception.check_id, 'GUARD_SOURCE')
        self.assertFalse(hasattr(raised.exception, 'guard_diagnostic'))

    def test_diagnostic_failure_preserves_original_denial(self):
        with patch('workrelay.guard_diagnostic.plugin_evidence', side_effect=RuntimeError('PRIVATE')):
            error = self.denied([])
        self.assertFalse(hasattr(error, 'guard_diagnostic'))

    def test_propagation_and_correlated_persistence_are_best_effort(self):
        error = self.denied([])
        with patch('workrelay.cli.subprocess.run') as run, patch('workrelay.attestor.verify', side_effect=error):
            run.return_value.returncode = 0
            with self.assertRaises(GuardFailure) as raised:
                admission(self.config, object())
        failure = raised.exception
        db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(db.close)
        initialize(db)
        for op in ('one', 'two'):
            db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity) VALUES('binding','ses_fixture',?,'queue','digest','msg_fixture','reserved','identity')", (op,))
        record_denial(db, 'binding', 'ses_fixture', 'one', failure)
        row = db.execute("SELECT phase,denial_code,attestation_check_id,guard_diagnostic FROM managed_operations WHERE operation='one'").fetchone()
        self.assertEqual(row[:3], ('denied', 'ATTESTATION_FAILED', 'GUARD_PLUGIN_STATE'))
        self.assertEqual(json.loads(row[3])['reason'], 'guard_missing')
        self.assertIsNone(db.execute("SELECT guard_diagnostic FROM managed_operations WHERE operation='two'").fetchone()[0])
        db.execute("CREATE TRIGGER reject_optional BEFORE UPDATE OF guard_diagnostic ON managed_operations BEGIN SELECT RAISE(ABORT,'PRIVATE'); END")
        record_denial(db, 'binding', 'ses_fixture', 'two', failure)
        self.assertEqual(db.execute("SELECT phase,denial_code FROM managed_operations WHERE operation='two'").fetchone(), ('denied', 'ATTESTATION_FAILED'))
        db.execute('DROP TRIGGER reject_optional')
        record_denial(db, 'binding', 'ses_fixture', 'two', failure)
        self.assertIsNone(db.execute("SELECT guard_diagnostic FROM managed_operations WHERE operation='two'").fetchone()[0], 'never backfill a previous denial with later observations')

    def test_sanitizer_ignores_secrets_and_changing_accessors(self):
        class Changing(dict):
            reads = 0
            def get(self, key, default=None):
                if key == 'reason':
                    self.reads += 1
                    return 'guard_missing' if self.reads == 1 else 'PRIVATE'
                return super().get(key, default)
        value = Changing(reason='PRIVATE', state='PRIVATE', inventory_shape='PRIVATE', token='PRIVATE', inventory_count=True)
        safe = sanitize(value)
        self.assertEqual(value.reads, 1)
        self.assertNotIn('PRIVATE', json.dumps(safe))
        self.assertIsNone(safe['inventory_count'])


if __name__ == '__main__':
    unittest.main()
