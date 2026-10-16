import copy
import sqlite3
import unittest
import tempfile
import os
import multiprocessing
from pathlib import Path
from unittest.mock import patch

from workrelay.cli import BridgeError
from workrelay.managed_control import control, reservation_owner_dead


class ManagedControlTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.sid = 'ses_existing'
        self.config = {'model': {'providerID': 'openai', 'id': 'included'}}
        self.session = {'id': self.sid, 'model': self.config['model'], 'agent': 'existing-owner',
                        'parentID': 'ses_parent', 'metadata': {'taskIntent': 'unchanged'}, 'permissions': {'ask': True}}
        self.calls = []; self.inbox = []; self.binding = 'a' * 64; self.timeout = False

    def authorize(self):
        if self.binding is None:
            raise BridgeError('revoked')
        return self.binding

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if path.endswith('/inbox'): return {'data': self.inbox}
            if '/message/' in path: return None
            return {'data': copy.deepcopy(self.session)}
        if '/prompt' in path:
            self.assertEqual(set(body), {'id', 'text', 'delivery'})
            self.assertEqual(body['delivery'], 'queue')
            result = {'id': body['id'], 'sessionID': self.sid, 'delivery': 'queue'}
            self.inbox.append(result)
            if self.timeout: raise TimeoutError()
            return {'data': result}
        self.assertEqual(path, f'/api/session/{self.sid}/interrupt?resume=false')
        self.assertIsNone(body)
        return {'interrupted': False}

    def run_control(self, op='operation', **kw):
        return control(self.db, self.config, self, self.authorize, self.sid, op, **kw)

    def posts(self): return [call for call in self.calls if call[0] == 'POST']

    @patch('workrelay.managed_control.admission')
    def test_queue_duplicate_conflict_and_identity_unchanged(self, admit):
        before = copy.deepcopy(self.session)
        result = self.run_control(text='hello')
        self.assertEqual(result['phase'], 'queued')
        self.assertEqual(self.run_control(text='hello'), result)
        self.assertEqual(len(self.posts()), 1); admit.assert_called_once()
        self.assertEqual(self.session, before)
        with self.assertRaises(BridgeError): self.run_control(text='different')
        self.binding = None
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_timeout_reconciles_exact_id_without_replay(self, admit):
        self.timeout = True
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        self.assertEqual(self.run_control(text='hello')['phase'], 'queued_observed')
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_unresolved_and_concurrent_operation_serialization(self, admit):
        # Reentrant second caller sees committed reserved operation before POST.
        def concurrent(*args):
            self.assertEqual(self.run_control(text='hello')['phase'], 'reserved')
            with self.assertRaises(BridgeError): self.run_control('other', text='other')
        admit.side_effect = concurrent
        self.run_control(text='hello')
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_financial_denial_revocation_and_owner_change_fail_closed(self, admit):
        admit.side_effect = BridgeError('financial denial')
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        self.assertEqual(self.posts(), [])
        admit.side_effect = lambda *args: self.session.update(agent='replacement')
        with self.assertRaises(BridgeError): self.run_control('change', text='hello')
        self.assertEqual(self.posts(), [])
        admit.side_effect = lambda *args: setattr(self, 'binding', None)
        with self.assertRaises(BridgeError): self.run_control('revoked', text='hello')
        self.assertEqual(self.posts(), [])

    @patch('workrelay.managed_control.admission')
    def test_interrupt_only_exact_session_no_inference(self, admit):
        self.assertEqual(self.run_control(interrupt=True)['phase'], 'interrupt_acknowledged')
        admit.assert_not_called()
        self.assertEqual(self.posts(), [('POST', '/api/session/ses_existing/interrupt?resume=false', None)])
        self.run_control(interrupt=True)
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_durable_restart_and_absent_timeout_never_replay(self, admit):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.sqlite'
            db = sqlite3.connect(path, isolation_level=None)
            self.timeout = True
            with self.assertRaises(BridgeError):
                control(db, self.config, self, self.authorize, self.sid, 'durable', text='hello')
            db.close()
            self.inbox = []
            db = sqlite3.connect(path, isolation_level=None)
            try:
                result = control(db, self.config, self, self.authorize, self.sid, 'durable', text='hello')
                self.assertEqual(result['phase'], 'uncertain')
                with self.assertRaises(BridgeError):
                    control(db, self.config, self, self.authorize, self.sid, 'new', text='hello')
                self.assertEqual(len(self.posts()), 1)
            finally: db.close()

    @patch('workrelay.cli.subprocess.run')
    def test_actual_financial_admission_denies_without_post(self, run):
        self.config['quota_command'] = '/synthetic/quota'
        run.return_value.returncode = 1
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        self.assertEqual(self.posts(), [])

    def reserve_without_send(self):
        with patch('workrelay.managed_control.admission', side_effect=SystemExit):
            with self.assertRaises(SystemExit): self.run_control(text='hello')
        self.assertEqual(self.posts(), [])

    def test_live_reused_unknown_and_legacy_owner_never_recovered(self):
        self.reserve_without_send()
        with patch('workrelay.managed_control.admission') as admit:
            # The current PID also represents the safe PID-reuse case: a live
            # occupant is never assumed to be the original owner or killed.
            self.assertEqual(self.run_control(text='hello')['phase'], 'reserved')
            for pid in [None, 0, -1]:
                self.db.execute('UPDATE managed_operations SET reservation_pid=?', (pid,))
                self.assertEqual(self.run_control(text='hello')['phase'], 'reserved')
            self.db.execute('UPDATE managed_operations SET reservation_pid=?', (os.getpid(),))
            with patch('workrelay.managed_control.os.kill', side_effect=PermissionError):
                self.assertEqual(self.run_control(text='hello')['phase'], 'reserved')
            with self.assertRaises(BridgeError): self.run_control('different', text='hello')
            admit.assert_not_called()
        self.assertEqual(self.posts(), [])

    def test_only_native_process_absence_is_death_evidence(self):
        for error in [PermissionError(), OSError('unknown'), OverflowError()]:
            with patch('workrelay.managed_control.os.kill', side_effect=error):
                self.assertFalse(reservation_owner_dead(123))
        with patch('workrelay.managed_control.os.kill', side_effect=ProcessLookupError):
            self.assertTrue(reservation_owner_dead(123))
        self.assertFalse(reservation_owner_dead(os.getpid()))

    def test_dead_owner_sending_and_uncertain_are_never_replayed(self):
        self.reserve_without_send()
        for phase in ['sending', 'uncertain']:
            self.db.execute('UPDATE managed_operations SET phase=?', (phase,))
            with patch('workrelay.managed_control.reservation_owner_dead') as probe, patch('workrelay.managed_control.admission') as admit:
                self.assertEqual(self.run_control(text='hello')['phase'], phase)
                probe.assert_not_called(); admit.assert_not_called()
            with self.assertRaises(BridgeError): self.run_control('different', text='hello')
        self.assertEqual(self.posts(), [])

    def test_actual_crash_before_admission_recovers_once_with_fresh_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.sqlite'
            def child():
                db = sqlite3.connect(path, isolation_level=None)
                with patch('workrelay.managed_control.admission', side_effect=lambda *args: os._exit(73)):
                    control(db, self.config, self, self.authorize, self.sid, 'crashed', text='hello')
            process = multiprocessing.get_context('fork').Process(target=child)
            process.start(); process.join(10)
            if process.is_alive():
                process.terminate(); process.join(); self.fail('crash fixture did not exit')
            self.assertEqual(process.exitcode, 73)
            db = sqlite3.connect(path, isolation_level=None)
            try:
                before = db.execute('SELECT message,digest,identity,reservation_pid,phase FROM managed_operations').fetchone()
                self.assertEqual(before[3], process.pid); self.assertEqual(before[4], 'reserved')
                self.assertTrue(reservation_owner_dead(process.pid))
                def concurrent(*args):
                    duplicate = sqlite3.connect(path, isolation_level=None)
                    try:
                        result = control(duplicate, self.config, self, self.authorize, self.sid, 'crashed', text='hello')
                        self.assertEqual(result['phase'], 'reserved')
                    finally: duplicate.close()
                with patch('workrelay.managed_control.admission', side_effect=concurrent) as admit:
                    result = control(db, self.config, self, self.authorize, self.sid, 'crashed', text='hello')
                    admit.assert_called_once()
                self.assertEqual(result['phase'], 'queued'); self.assertEqual(len(self.posts()), 1)
                after = db.execute('SELECT message,digest,identity,reservation_pid,phase FROM managed_operations').fetchone()
                self.assertEqual(before[:3], after[:3]); self.assertEqual(after[3], os.getpid())
                self.assertEqual(control(db, self.config, self, self.authorize, self.sid, 'crashed', text='hello')['phase'], 'queued')
                self.assertEqual(len(self.posts()), 1)
            finally: db.close()

    def test_recovered_reservation_rechecks_finances_and_identity(self):
        for mode in ['financial', 'identity', 'revocation']:
            with self.subTest(mode=mode):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                self.reserve_without_send()
                def check(*args):
                    if mode == 'financial': raise BridgeError('quota denied')
                    if mode == 'identity': self.session['agent'] = 'changed'
                    if mode == 'revocation': self.binding = None
                with patch('workrelay.managed_control.reservation_owner_dead', return_value=True), patch('workrelay.managed_control.admission', side_effect=check):
                    with self.assertRaises(BridgeError): self.run_control(text='hello')
                self.assertEqual(self.posts(), [])
                self.binding = 'a' * 64


if __name__ == '__main__': unittest.main()
