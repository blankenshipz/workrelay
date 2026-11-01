import copy
import sqlite3
import unittest
import tempfile
import os
import hashlib
import json
import contextlib
import io
import runpy
import sys
import warnings
import multiprocessing
from pathlib import Path
from unittest.mock import patch

from workrelay.cli import BridgeError, GuardFailure, CONTROL_DENIAL_CODES
from workrelay.managed_control import control, reservation_owner_dead, create_session, creation_session_id, inspect_operation, identity, resolve_operation, classified_failure, native_waits, record_denial, settle_question, reconcile_question, reconcile_operation, initialize


class ManagedControlTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.sid = 'ses_existing'
        self.config = {'model': {'providerID': 'openai', 'id': 'included'}}
        self.session = {'id': self.sid, 'model': self.config['model'], 'agent': 'existing-owner',
                        'parentID': 'ses_parent', 'metadata': {'taskIntent': 'unchanged'}, 'permissions': {'ask': True}}
        self.calls = []; self.inbox = []; self.exact_message = None; self.reconcile_during_post = None; self.binding = 'a' * 64; self.timeout = False

    def authorize(self):
        if self.binding is None:
            raise BridgeError('revoked')
        return self.binding

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if path.endswith('/inbox'): return {'data': self.inbox}
            if path.endswith('/permission') or path.endswith('/form'): return {'data': []}
            if '/message/' in path: return self.exact_message
            return {'data': copy.deepcopy(self.session)}
        if '/prompt' in path:
            self.assertEqual(set(body), {'id', 'text', 'delivery'})
            self.assertIn(body['delivery'], ('queue', 'steer'))
            result = {'id': body['id'], 'sessionID': self.sid, 'type': 'user', 'payload': {'text': body['text']}, 'delivery': body['delivery']}
            self.inbox.append(result)
            if self.reconcile_during_post:
                reconcile_operation(self.db, self.config, self, self.authorize, self.sid, self.reconcile_during_post)
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
    def test_native_shaped_queue_receipts_require_exact_user_text_before_durable_clear(self, admit):
        def uncertain(op):
            self.timeout = True
            with self.assertRaises(BridgeError): self.run_control(op, text='hello')
            self.timeout = False
            self.inbox = []
        uncertain('message-exact')
        message_id = self.db.execute("SELECT message FROM managed_operations WHERE operation='message-exact'").fetchone()[0]
        self.exact_message = {'data': {'id': message_id, 'type': 'user', 'text': 'hello'}}
        self.assertEqual(reconcile_operation(self.db, self.config, self, self.authorize, self.sid, 'message-exact')['recorded_phase'], 'message_observed')
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='message-exact'").fetchone()[0], 'message_observed')
        for index, malformed in enumerate([
            {'data': {'id': 'wrong', 'type': 'user', 'text': 'hello'}},
            {'data': {'id': None, 'type': 'assistant', 'text': 'hello'}},
            {'data': {'id': None, 'type': 'user', 'text': 'wrong'}},
            {'data': {'id': None, 'type': 'user'}},
            {'data': {'id': None, 'sessionID': 'ses_other', 'type': 'user', 'text': 'hello'}},
        ]):
            operation = 'message-bad' + str(index); uncertain(operation)
            message_id = self.db.execute('SELECT message FROM managed_operations WHERE operation=?', (operation,)).fetchone()[0]
            malformed['data']['id'] = message_id if malformed['data']['id'] is None else malformed['data']['id']
            self.exact_message = malformed
            self.assertEqual(reconcile_operation(self.db, self.config, self, self.authorize, self.sid, operation)['recorded_phase'], 'uncertain')
            self.db.execute("UPDATE managed_operations SET phase='message_observed' WHERE operation=?", (operation,))
        uncertain('inbox-exact')
        row = self.db.execute("SELECT message FROM managed_operations WHERE operation='inbox-exact'").fetchone()[0]
        self.exact_message = None
        self.inbox = [{'id': row, 'sessionID': self.sid, 'type': 'user', 'payload': {'text': 'hello'}, 'delivery': 'queue'}]
        self.assertEqual(reconcile_operation(self.db, self.config, self, self.authorize, self.sid, 'inbox-exact')['recorded_phase'], 'queued_observed')

    @patch('workrelay.managed_control.admission')
    def test_late_sender_failure_cannot_downgrade_reconciled_receipt(self, admit):
        self.reconcile_during_post = 'race-receipt'; self.timeout = True
        with self.assertRaises(BridgeError): self.run_control('race-receipt', text='hello')
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='race-receipt'").fetchone()[0], 'queued_observed')

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
        first = self.run_control(interrupt=True)
        self.assertEqual(first['phase'], 'idle_noop')
        self.assertFalse(first['cancellation_is_rollback'])
        self.assertFalse(first['queued_inputs_removed'])
        self.assertIn('may run on later resume', first['guidance'])
        admit.assert_not_called()
        self.assertEqual(self.posts(), [('POST', '/api/session/ses_existing/interrupt?resume=false', None)])
        self.assertEqual(self.run_control(interrupt=True), first)
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

    @patch('workrelay.managed_control.admission')
    def test_steer_and_inspect_use_same_native_owner_without_approval_changes(self, admit):
        original = copy.deepcopy(self.session)
        result = self.run_control(text='bounded guidance', steer=True)
        self.assertEqual(result['phase'], 'steering')
        self.assertEqual(self.posts()[0][2]['delivery'], 'steer')
        self.assertEqual(self.run_control(text='bounded guidance', steer=True), result)
        with self.assertRaises(BridgeError): self.run_control(text='bounded guidance')
        observed = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')
        self.assertEqual(observed['phase'], 'queued_observed')
        self.assertEqual(observed['task_outcome'], 'unverified')
        self.assertFalse(observed['cancellation_is_rollback'])
        self.assertEqual(self.session, original)
        self.binding = 'b' * 64
        missing = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')
        self.assertEqual(missing['code'], 'CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING')
        self.assertEqual(missing['effect'], 'not_established')

    @patch('workrelay.managed_control.admission')
    def test_inspection_exposes_exact_queue_age_without_writing_or_inference(self, admit):
        self.run_control(text='hello')
        message_id = self.db.execute("SELECT message FROM managed_operations WHERE operation='operation'").fetchone()[0]
        self.inbox = [{'id': message_id, 'sessionID': self.sid, 'type': 'user',
                       'payload': {'text': 'hello'}, 'time': {'created': 1000}}]
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        observed = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', clock_ms=6000)
        self.assertEqual(observed['phase'], 'queued_observed')
        self.assertEqual(observed['native_observation'], 'queued')
        self.assertEqual(observed['native_observed_at_ms'], 6000)
        self.assertEqual(observed['native_queued_at_ms'], 1000)
        self.assertEqual(observed['native_queue_age_ms'], 5000)
        self.assertIsNone(observed['native_materialized_at_ms'])
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        self.assertEqual(self.posts(), [('POST', f'/api/session/{self.sid}/prompt', {'id': message_id, 'text': 'hello', 'delivery': 'queue'})])
        self.assertIn('not proof the owner consumed', self.run_control(text='hello')['guidance'])

    @patch('workrelay.managed_control.admission')
    def test_inspection_materialization_and_invalid_native_clocks_are_not_invented(self, admit):
        self.run_control(text='hello')
        message_id = self.db.execute("SELECT message FROM managed_operations WHERE operation='operation'").fetchone()[0]
        self.exact_message = {'data': {'id': message_id, 'sessionID': self.sid, 'type': 'user', 'text': 'hello',
                                       'time': {'created': 5000}}}
        observed = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', clock_ms=6000)
        self.assertEqual(observed['native_observation'], 'materialized')
        self.assertEqual(observed['native_materialized_at_ms'], 5000)
        self.assertIsNone(observed['native_queue_age_ms'])
        self.exact_message = None
        self.inbox = [{'id': message_id, 'sessionID': self.sid, 'type': 'user', 'payload': {'text': 'hello'},
                       'time': {'created': 6001}}]
        future = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', clock_ms=6000)
        self.assertEqual(future['native_observation'], 'queued')
        self.assertIsNone(future['native_queued_at_ms'])
        self.assertIsNone(future['native_queue_age_ms'])
        self.inbox[0]['time'] = {'created': 'not-a-clock'}
        malformed = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', clock_ms=6000)
        self.assertIsNone(malformed['native_queued_at_ms'])
        self.assertIsNone(malformed['native_queue_age_ms'])

    @patch('workrelay.managed_control.admission')
    def test_inspection_unknown_and_receipt_only_never_claim_native_observation(self, admit):
        self.run_control(text='hello')
        self.inbox = []
        self.exact_message = None
        unknown = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', clock_ms=6000)
        self.assertEqual(unknown['native_observation'], 'unknown')
        self.assertEqual(unknown['native_observed_at_ms'], 6000)
        self.calls = []
        receipt = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
        self.assertEqual(receipt['native_observation'], 'not_run')
        self.assertIsNone(receipt['native_observed_at_ms'])
        self.assertIsNone(receipt['native_queue_age_ms'])
        self.assertEqual(self.calls, [])

    @patch('workrelay.managed_control.admission', side_effect=GuardFailure('QUOTA_DENIED'))
    def test_denied_receipt_is_not_misrepresented_as_native_queue_state(self, admit):
        with self.assertRaises(GuardFailure):
            self.run_control(text='hello')
        self.calls = []
        denied = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')
        self.assertEqual(denied['phase'], 'denied')
        self.assertEqual(denied['native_observation'], 'not_run')
        self.assertIsNone(denied['native_observed_at_ms'])
        self.assertEqual(self.calls, [])

    def test_exact_full_model_and_raw_input_bound(self):
        self.session['model'] = {**self.config['model'], 'unrecognizedRouteOverride': 'different'}
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        with self.assertRaises(BridgeError): self.run_control(text='hello' + ' ' * 16000)
        self.assertEqual(self.posts(), [])

    @patch('workrelay.managed_control.admission')
    def test_verified_sidebar_work_addition_change_and_removal_preserves_identity(self, admit):
        self.run_control(text='hello')
        original = identity(self.session, self.sid)
        for work in ({'state': 'open', 'openedAt': 1, 'openedBy': 'auto'},
                     {'state': 'open', 'suggestDoneAt': 2, 'doneAt': None},
                     {'state': 'done', 'openedBy': 'user', 'doneAt': 3}):
            self.session['metadata']['openchamber'] = {'work': work}
            self.assertEqual(identity(self.session, self.sid), original)
            self.assertEqual(inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')['phase'], 'queued_observed')
        del self.session['metadata']['openchamber']
        self.assertEqual(identity(self.session, self.sid), original)
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_protected_identity_and_unknown_ui_fields_remain_fail_closed(self, admit):
        self.run_control(text='hello')
        original = copy.deepcopy(self.session)
        changes = [('agent', 'other'), ('model', {**self.config['model'], 'variant': 'other'}),
                   ('projectID', 'other'), ('location', {'directory': '/other'}),
                   ('parentID', 'ses_other'), ('permissions', {'allow': True}),
                   ('metadata', {'taskIntent': 'changed'}),
                   ('metadata', {**original['metadata'], 'owner': 'other'}),
                   ('metadata', {**original['metadata'], 'workrelayBinding': 'other'}),
                   ('metadata', {**original['metadata'], 'openchamber': {'goal': {'id': 'other'}}}),
                   ('metadata', {**original['metadata'], 'openchamber': {'work': {'state': 'open', 'owner': 'other'}}}),
                   ('metadata', {**original['metadata'], 'openchamber': {'work': {'state': 'open', 'openedAt': 'untrusted'}}})]
        for key, value in changes:
            self.session = copy.deepcopy(original); self.session[key] = value
            with self.subTest(field=key, value_type=type(value).__name__):
                with self.assertRaises(BridgeError):
                    inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.managed_control.admission')
    def test_legacy_ui_hash_not_rewritten_or_erased(self, admit):
        self.session['metadata']['openchamber'] = {'work': {'state': 'open', 'openedAt': 1}}
        self.run_control(text='hello')
        selected = {key: self.session.get(key) for key in
                    ('id', 'parentID', 'projectID', 'agent', 'model', 'metadata', 'permissions', 'location')}
        old_hash = hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.db.execute('UPDATE managed_operations SET identity=?', (old_hash,))
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)

    @patch('workrelay.managed_control.admission')
    def test_operation_only_recovery_principal_isolation_and_collision(self, admit):
        self.run_control(text='hello')
        self.assertEqual(inspect_operation(self.db, self.config, self, self.authorize, None, 'operation')['session_id'], self.sid)
        self.binding = 'b' * 64
        with self.assertRaises(BridgeError): resolve_operation(self.db, self.authorize, 'operation')
        self.binding = 'a' * 64
        self.db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) SELECT binding,'ses_other',operation,kind,digest,message,phase,identity,reservation_pid FROM managed_operations")
        with self.assertRaises(BridgeError): resolve_operation(self.db, self.authorize, 'operation')
        self.assertEqual(resolve_operation(self.db, self.authorize, 'operation', self.sid)[1], self.sid)
        self.binding = None
        with self.assertRaises(BridgeError): resolve_operation(self.db, self.authorize, 'operation', self.sid)


    def test_denial_codes_persist_atomically_and_retry_is_read_only(self):
        original_session = copy.deepcopy(self.session)
        original_request = self.request
        for expected in ('QUOTA_DENIED', 'QUOTA_UNAVAILABLE', 'ATTESTATION_FAILED',
                         'AUTHORITY_UNAVAILABLE_OR_CHANGED', 'SESSION_READ_FAILED',
                         'MODEL_MISMATCH', 'IDENTITY_CHANGED', 'UNEXPECTED_PREPOST'):
            with self.subTest(code=expected):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                self.session = copy.deepcopy(original_session); self.binding = 'a' * 64
                self.request = original_request; self.calls = []
                def fail(*args):
                    if expected in ('QUOTA_DENIED', 'QUOTA_UNAVAILABLE', 'ATTESTATION_FAILED'):
                        raise GuardFailure(expected)
                    if expected == 'AUTHORITY_UNAVAILABLE_OR_CHANGED': self.binding = None
                    elif expected == 'SESSION_READ_FAILED':
                        self.request = lambda *args, **kwargs: (_ for _ in ()).throw(BridgeError('sensitive native body'))
                    elif expected == 'MODEL_MISMATCH': self.session['model'] = {'providerID': 'other', 'id': 'bad'}
                    elif expected == 'IDENTITY_CHANGED': self.session['agent'] = 'replacement'
                    else:
                        error = RuntimeError('Bearer do-not-persist-sensitive-token')
                        error.denial_code = 'QUOTA_DENIED'  # Untrusted attributes are ignored.
                        raise error
                with patch('workrelay.managed_control.admission', side_effect=fail), patch('workrelay.managed_control.time.time', return_value=123.456):
                    with self.assertRaises(Exception): self.run_control(text='hello')
                phase, code, timestamp = self.db.execute('SELECT phase,denial_code,denied_at_ms FROM managed_operations').fetchone()
                self.assertEqual((phase, code, timestamp), ('denied', expected, 123456))
                self.assertFalse(self.posts())
                self.binding = 'a' * 64; self.request = original_request; self.session = copy.deepcopy(original_session)
                before = self.db.execute('SELECT * FROM managed_operations').fetchall()
                with patch('workrelay.managed_control.admission') as admit:
                    retry = self.run_control(text='hello')
                    admit.assert_not_called()
                self.assertEqual(retry['denial_code'], expected)
                self.assertEqual(retry['denied_at_ms'], 123456)
                recovered = inspect_operation(self.db, self.config, self, self.authorize, None, 'operation')
                self.assertEqual(recovered['denial_code'], expected)
                classified = classified_failure(self.db, self.authorize, 'operation', self.sid, RuntimeError('native secret'))
                self.assertEqual(classified.control_details['denial_code'], expected)
                self.assertNotIn('sensitive', str(self.db.execute('SELECT * FROM managed_operations').fetchall()))
                self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)

    def test_legacy_denied_migration_no_backfill_or_current_admission(self):
        self.db.execute('CREATE TABLE managed_operations(binding TEXT,session TEXT,operation TEXT,kind TEXT,digest TEXT,message TEXT,phase TEXT,identity TEXT,reservation_pid INTEGER,PRIMARY KEY(binding,session,operation))')
        digest = hashlib.sha256(b'queue\0hello').hexdigest()
        old = (self.binding, self.sid, 'operation', 'queue', digest, 'msg_legacy', 'denied', identity(self.session, self.sid), None)
        self.db.execute('INSERT INTO managed_operations VALUES(?,?,?,?,?,?,?,?,?)', old)
        with patch('workrelay.managed_control.admission') as admit:
            retry = self.run_control(text='hello')
            self.assertEqual(retry['denial_code'], 'DENIAL_REASON_NOT_RECORDED')
            self.assertIsNone(retry['denied_at_ms']); admit.assert_not_called()
        recovered = inspect_operation(self.db, self.config, self, self.authorize, None, 'operation')
        self.assertEqual(recovered['denial_code'], 'DENIAL_REASON_NOT_RECORDED')
        self.assertEqual(self.db.execute('SELECT binding,session,operation,kind,digest,message,phase,identity,reservation_pid FROM managed_operations').fetchone(), old)
        self.assertEqual(self.db.execute('SELECT denial_code,denied_at_ms FROM managed_operations').fetchone(), (None, None))
        self.assertEqual(self.posts(), [])

    def test_atomic_denial_update_cannot_store_phase_without_code_time(self):
        self.reserve_without_send()
        self.db.execute("CREATE TRIGGER reject_diagnostic BEFORE UPDATE OF denial_code ON managed_operations BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            record_denial(self.db, self.binding, self.sid, 'operation', GuardFailure('QUOTA_DENIED'))
        self.assertEqual(self.db.execute('SELECT phase,denial_code,denied_at_ms FROM managed_operations').fetchone(), ('reserved', None, None))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE managed_operations SET denial_code='malicious-non-enum'")
        self.assertEqual(self.posts(), [])

    @patch('workrelay.managed_control.admission')
    def test_post_timeout_is_uncertain_not_prepost_denied(self, admit):
        self.timeout = True
        with self.assertRaises(BridgeError): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT phase,denial_code,denied_at_ms FROM managed_operations').fetchone(), ('uncertain', None, None))
        recovered = inspect_operation(self.db, self.config, self, self.authorize, None, 'operation')
        self.assertNotIn('denial_code', recovered)
        self.assertEqual(len(self.posts()), 1)

    @patch('workrelay.cli.subprocess.run')
    def test_admission_explicit_quota_and_attestation_codes(self, run):
        self.config['quota_command'] = '/synthetic/quota'
        for returncode, expected in ((1, 'QUOTA_DENIED'), (2, 'QUOTA_UNAVAILABLE')):
            self.db.execute('DROP TABLE IF EXISTS managed_operations')
            run.return_value.returncode = returncode
            with self.assertRaises(GuardFailure): self.run_control(text='hello')
            self.assertEqual(self.db.execute('SELECT denial_code FROM managed_operations').fetchone()[0], expected)
        self.db.execute('DROP TABLE IF EXISTS managed_operations')
        run.return_value.returncode = 0
        from workrelay.attestor import AttestationError
        with patch('workrelay.attestor.verify', side_effect=AttestationError('private details')):
            with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT denial_code FROM managed_operations').fetchone()[0], 'ATTESTATION_FAILED')
        self.assertEqual(self.posts(), [])

    def test_module_entrypoint_returns_persisted_safe_denial_json(self):
        from workrelay import cli
        with tempfile.TemporaryDirectory() as directory:
            config = {'transport': 'installed-client', 'authorized_owner': 'fixture', 'model': self.config['model']}
            original_request = self.request
            def request(method, path, body=None):
                if path == '/__managed/authorize': return {'binding_id': self.binding}
                return original_request(method, path, body)
            self.request = request
            payload = {'action': 'message', 'session_id': self.sid, 'operation_id': 'module-denial', 'text': 'hello', 'claims': {}}
            out, err = io.StringIO(), io.StringIO()
            with patch.object(cli, 'load_config', return_value=(config, None, Path(directory), Path(directory))), \
                 patch.object(cli, 'InstalledClient', return_value=self), \
                 patch('workrelay.managed_control.admission', side_effect=GuardFailure('QUOTA_DENIED')), \
                 patch('sys.argv', ['workrelay', '--config', 'synthetic-private-reference', 'managed-control', '--owner', 'fixture']), \
                 patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), warnings.catch_warnings():
                warnings.simplefilter('ignore', RuntimeWarning)
                with self.assertRaises(SystemExit) as exit:
                    runpy.run_module('workrelay.cli', run_name='__main__')
            self.assertEqual(exit.exception.code, 2)
            self.assertEqual(out.getvalue(), '')
            failure = json.loads(err.getvalue())
            self.assertEqual(failure['denial_code'], 'QUOTA_DENIED')
            self.assertEqual(failure['effect'], 'no_post_permitted')
            self.assertIsInstance(failure['denied_at_ms'], int)
            self.assertNotIn('Traceback', err.getvalue())
            self.assertEqual(self.posts(), [])


    @patch('workrelay.managed_control.admission')
    def test_receipt_only_status_survives_current_execution_model_change(self, admit):
        self.run_control(text='hello')
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        self.session['model'] = {**self.config['model'], 'variant': 'changed'}
        self.session['agent'] = 'changed-owner'
        self.calls = []
        result = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
        self.assertEqual(result['recorded_phase'], 'queued')
        self.assertEqual(result['code'], 'CONTROL_RECONCILE_EXISTING')
        self.assertEqual(result['native_observation'], 'not_run')
        self.assertFalse(result['replay_permitted'])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        # Receipt visibility does not relax write admission or reconciliation.
        admit.side_effect = GuardFailure('ATTESTATION_FAILED')
        with self.assertRaises(BridgeError):
            self.run_control('different', text='new message')
        self.assertFalse(self.posts())

    def test_receipt_unknown_is_scoped_not_authorization_or_global_absence(self):
        self.reserve_without_send()
        self.calls = []
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        for binding in ('b' * 64, 'c' * 64):
            self.binding = binding  # Other principal/server bindings see no old receipt.
            result = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
            self.assertEqual(result['code'], 'CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING')
            self.assertEqual(result['effect'], 'not_established')
            self.assertEqual(result['lookup_scope'], 'current_authenticated_binding')
            self.assertNotIn('message_id', result)
        self.binding = None
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
        self.binding = 'a' * 64
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, self.authorize, '../invalid', 'operation', receipt_only=True)
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        self.assertEqual(self.calls, [])

    def test_receipt_ambiguity_authority_change_and_stored_phases(self):
        self.reserve_without_send()
        for phase, code, effect in (
                ('reserved', 'CONTROL_NOT_SENT', 'no_post_permitted'),
                ('denied', 'CONTROL_NOT_SENT', 'no_post_permitted'),
                ('sending', 'CONTROL_UNCERTAIN', 'may_have_been_applied'),
                ('uncertain', 'CONTROL_UNCERTAIN', 'may_have_been_applied'),
                ('queued', 'CONTROL_RECONCILE_EXISTING', 'recorded_existing_operation')):
            self.db.execute('UPDATE managed_operations SET phase=?', (phase,))
            result = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
            self.assertEqual((result['code'], result['effect']), (code, effect))
            if phase == 'denied':
                self.assertEqual(result['denial_code'], 'DENIAL_REASON_NOT_RECORDED')
                self.assertIsNone(result['denied_at_ms'])
        self.db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) SELECT binding,'ses_other',operation,kind,digest,message,phase,identity,reservation_pid FROM managed_operations")
        result = inspect_operation(self.db, self.config, self, self.authorize, None, 'operation', receipt_only=True)
        self.assertEqual(result['code'], 'CONTROL_OPERATION_AMBIGUOUS_CURRENT_BINDING')
        self.assertIsNone(result['session_id'])
        self.assertNotIn('message_id', result)
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, unittest.mock.Mock(side_effect=['a' * 64, None]),
                              self.sid, 'missing', receipt_only=True)
        self.assertFalse(self.posts())

    def test_module_status_unknown_returns_finite_success_without_native_session_read(self):
        from workrelay import cli
        with tempfile.TemporaryDirectory() as directory:
            config = {'transport': 'installed-client', 'authorized_owner': 'fixture', 'model': self.config['model']}
            def request(method, path, body=None):
                self.assertEqual((method, path, body), ('GET', '/__managed/authorize', None))
                return {'binding_id': self.binding}
            self.request = request
            payload = {'action': 'inspect', 'session_id': self.sid, 'operation_id': 'missing', 'claims': {}}
            out, err = io.StringIO(), io.StringIO()
            with patch.object(cli, 'load_config', return_value=(config, None, Path(directory), Path(directory))), \
                 patch.object(cli, 'InstalledClient', return_value=self), \
                 patch('sys.argv', ['workrelay', '--config', 'fixture-reference', 'managed-control', '--owner', 'fixture']), \
                 patch('sys.stdin', io.StringIO(json.dumps(payload))), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(), 0)
            result = json.loads(out.getvalue())
            self.assertEqual(result['code'], 'CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING')
            self.assertEqual(result['effect'], 'not_established')
            self.assertEqual(err.getvalue(), '')


    def configure_catalog_route_fixture(self):
        # Reuse the existing isolated native-metadata/guard-files fixture, not
        # a live service or a provider credential. No transport script executes.
        from test_bridge import BridgeTests, FakeClient
        fixture = BridgeTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.config = copy.deepcopy(fixture.data)
        self.session['model'] = {'providerID': 'openai', 'id': 'fixture-other-model', 'variant': 'medium'}
        model = {'providerID': 'openai', 'id': 'fixture-other-model', 'modelID': 'fixture-native-model',
                 'package': '@opencode/ai/providers/openai', 'variants': [{'id': 'medium'}]}
        FakeClient.metadata['/api/model'].append(model)
        original = self.request
        def request(method, path, body=None):
            if method == 'GET' and path in FakeClient.metadata:
                return {'data': copy.deepcopy(FakeClient.metadata[path])}
            return original(method, path, body)
        self.request = request
        return FakeClient.metadata, model

    def test_exact_catalog_other_model_attests_and_retries_without_replay(self):
        metadata, model = self.configure_catalog_route_fixture()
        original = copy.deepcopy(self.session)
        result = self.run_control(text='hello')
        self.assertEqual(result['phase'], 'queued')
        self.assertEqual(self.session, original)
        self.assertNotEqual(self.session['model'], self.config['model'])
        self.assertEqual(self.run_control(text='hello'), result)
        self.assertEqual(len(self.posts()), 1)

    def test_catalog_variant_credentials_quota_and_authority_fail_closed(self):
        metadata, model = self.configure_catalog_route_fixture()
        for mode in ('variant', 'variant_key', 'model_endpoint', 'provider_key', 'quota', 'native_read'):
            with self.subTest(mode=mode):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                model['variants'] = [{'id': 'medium'}]; model.pop('settings', None)
                metadata['/api/provider/openai'].pop('settings', None)
                self.session['model']['variant'] = 'medium'
                if mode == 'variant': self.session['model']['variant'] = 'unsupported-fixture-variant'
                if mode == 'variant_key': model['variants'][0]['settings'] = {'apiKey': 'synthetic-do-not-use'}
                if mode == 'model_endpoint': model['settings'] = {'baseURL': 'https://api.openai.com/v1'}
                if mode == 'provider_key': metadata['/api/provider/openai']['settings'] = {'apiKey': 'synthetic-do-not-use'}
                original = self.request
                if mode == 'native_read':
                    def denied(method, path, body=None):
                        if path == '/api/model': raise BridgeError('native access denied')
                        return original(method, path, body)
                    self.request = denied
                try:
                    if mode == 'quota':
                        with patch('workrelay.cli.subprocess.run', return_value=type('Result', (), {'returncode': 1})()):
                            with self.assertRaises(GuardFailure): self.run_control(text='hello')
                    else:
                        with self.assertRaises(GuardFailure): self.run_control(text='hello')
                    code = self.db.execute('SELECT denial_code FROM managed_operations').fetchone()[0]
                    self.assertEqual(code, 'QUOTA_DENIED' if mode == 'quota' else 'ATTESTATION_FAILED')
                    self.assertEqual(self.posts(), [])
                finally:
                    self.request = original

    def test_catalog_model_change_during_attestation_is_denied_before_post(self):
        self.configure_catalog_route_fixture()
        original = self.request
        def change(method, path, body=None):
            result = original(method, path, body)
            if path == '/api/model': self.session['model']['variant'] = 'other'
            return result
        self.request = change
        with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT phase,denial_code FROM managed_operations').fetchone(), ('denied', 'IDENTITY_CHANGED'))
        self.assertEqual(self.posts(), [])

    def test_attestation_resolved_integration_source_is_exact_openai_oauth(self):
        metadata, _ = self.configure_catalog_route_fixture()
        provider = metadata['/api/provider/openai']
        for source in ('foreign-oauth', 'api-key-source', '', None, {'malicious': 'source'}):
            with self.subTest(source_type=type(source).__name__):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                provider['integrationID'] = source
                reads = []; original = self.request
                def read(method, path, body=None):
                    reads.append(path)
                    return original(method, path, body)
                self.request = read
                try:
                    with self.assertRaises(GuardFailure) as failure:
                        self.run_control(text='hello')
                    self.assertEqual(failure.exception.denial_code, 'ATTESTATION_FAILED')
                    self.assertEqual(self.db.execute('SELECT phase,denial_code FROM managed_operations').fetchone(),
                                     ('denied', 'ATTESTATION_FAILED'))
                    self.assertNotIn('/api/integration/openai', reads)
                    self.assertFalse(self.posts())
                finally:
                    self.request = original
        provider['integrationID'] = 'openai'
        self.db.execute('DROP TABLE IF EXISTS managed_operations')
        metadata['/api/integration/openai']['connections'][0]['method'] = 'api-key'
        with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT denial_code FROM managed_operations').fetchone()[0], 'ATTESTATION_FAILED')
        self.assertFalse(self.posts())

    def test_attestation_explicit_openai_source_passes_and_source_race_fails(self):
        metadata, _ = self.configure_catalog_route_fixture()
        metadata['/api/provider/openai']['integrationID'] = 'openai'
        self.assertEqual(self.run_control(text='hello')['phase'], 'queued')
        self.assertEqual(len(self.posts()), 1)
        self.calls = []; self.db.execute('DROP TABLE managed_operations')
        original = self.request
        def change_source(method, path, body=None):
            response = original(method, path, body)
            if path == '/api/model': metadata['/api/provider/openai']['integrationID'] = 'foreign-oauth'
            return response
        self.request = change_source
        with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT phase,denial_code FROM managed_operations').fetchone(),
                         ('denied', 'ATTESTATION_FAILED'))
        self.assertFalse(self.posts())

    def test_finite_attestation_predicates_are_atomic_durable_and_recoverable(self):
        cases = [
            ('MODEL_REF', lambda c,m,k: self.session['model'].update(variant=7)),
            ('PLUGIN_RESPONSE', lambda c,m,k: m.update({'/api/plugin': None})),
            ('GUARD_PLUGIN_STATE', lambda c,m,k: m['/api/plugin'][0]['state'].update(status='inactive')),
            ('GUARD_SOURCE', lambda c,m,k: m['/api/plugin'][0]['source'].update(type='remote')),
            ('GUARD_PIN_CONFIG', lambda c,m,k: c['guard_file_hashes'].update(entry='invalid')),
            ('GUARD_ENTRY_PIN', lambda c,m,k: c['guard_file_hashes'].update(entry='0'*64)),
            ('GUARD_IMPLEMENTATION_PIN', lambda c,m,k: c['guard_file_hashes'].update(implementation='0'*64)),
            ('GUARD_FINANCIAL_PIN', lambda c,m,k: c['guard_file_hashes'].update(financial='0'*64)),
            ('PROVIDER_RESPONSE', lambda c,m,k: m.update({'/api/provider/openai': []})),
            ('PROVIDER_INTEGRATION_SOURCE', lambda c,m,k: m['/api/provider/openai'].update(integrationID='foreign')),
            ('INTEGRATION_RESPONSE', lambda c,m,k: m.update({'/api/integration/openai': []})),
            ('OAUTH_CONNECTION', lambda c,m,k: m['/api/integration/openai']['connections'][0].update(method='api-key')),
            ('PROVIDER_OVERLAY', lambda c,m,k: m['/api/provider/openai'].update(settings={'apiKey':'synthetic-private'})),
            ('MODEL_CATALOG_RESPONSE', lambda c,m,k: m.update({'/api/model': None})),
            ('MODEL_CATALOG', lambda c,m,k: m.update({'/api/model': []})),
            ('VARIANT', lambda c,m,k: k.update(variants=[])),
            ('MODEL_OVERLAY', lambda c,m,k: k.update(headers={'authorization':'synthetic-private'})),
        ]
        for expected, mutate in cases:
            with self.subTest(check_id=expected):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                metadata, model = self.configure_catalog_route_fixture()
                mutate(self.config, metadata, model)
                with patch('workrelay.managed_control.time.time', return_value=123.456):
                    with self.assertRaises(GuardFailure): self.run_control(text='hello')
                self.assertEqual(self.db.execute('SELECT phase,denial_code,denied_at_ms,attestation_check_id FROM managed_operations').fetchone(),
                                 ('denied', 'ATTESTATION_FAILED', 123456, expected))
                before = self.db.execute('SELECT * FROM managed_operations').fetchall()
                result = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
                self.assertEqual(result['attestation_check_id'], expected)
                failure = classified_failure(self.db, self.authorize, 'operation', self.sid, RuntimeError('secret-native-error'))
                self.assertEqual(failure.control_details['attestation_check_id'], expected)
                # Return the stored failure without re-attesting or rewriting it.
                with patch('workrelay.managed_control.admission') as admit:
                    self.assertEqual(self.run_control(text='hello')['attestation_check_id'], expected)
                    admit.assert_not_called()
                self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
                self.assertNotIn('synthetic-private', str(before)); self.assertFalse(self.posts())

    def test_native_read_stage_not_mislabeled_as_pin_or_session_failure(self):
        for path, expected in [('/api/plugin','PLUGIN_READ_UNAVAILABLE'),
                               ('/api/provider/openai','PROVIDER_READ_UNAVAILABLE'),
                               ('/api/integration/openai','INTEGRATION_READ_UNAVAILABLE'),
                               ('/api/model','MODEL_CATALOG_READ_UNAVAILABLE')]:
            with self.subTest(path=path):
                self.db.execute('DROP TABLE IF EXISTS managed_operations')
                self.configure_catalog_route_fixture(); original = self.request
                def fail(method, target, body=None):
                    if target == path: raise BridgeError('Bearer private-native-message')
                    return original(method, target, body)
                self.request = fail
                try:
                    with self.assertRaises(GuardFailure): self.run_control(text='hello')
                    self.assertEqual(self.db.execute('SELECT denial_code,attestation_check_id FROM managed_operations').fetchone(),
                                     ('ATTESTATION_FAILED', expected))
                    self.assertFalse(self.posts())
                finally: self.request = original

    def test_attestation_file_unavailable_races_and_unclassified_are_safe(self):
        self.configure_catalog_route_fixture()
        with patch('workrelay.attestor.Path.read_bytes', side_effect=PermissionError('private-path')):
            with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT attestation_check_id FROM managed_operations').fetchone()[0], 'GUARD_FILE_UNAVAILABLE')
        for path, expected in [('/api/provider/openai','PROVIDER_SOURCE_CHANGED'),
                               ('/api/integration/openai','INTEGRATION_SOURCE_CHANGED')]:
            self.db.execute('DROP TABLE managed_operations')
            metadata, _ = self.configure_catalog_route_fixture(); original = self.request; count = [0]
            def race(method, target, body=None):
                response = original(method, target, body)
                if target == path:
                    count[0] += 1
                    if count[0] == 2: response['data']['changed-source-marker'] = True
                return response
            self.request = race
            try:
                with self.assertRaises(GuardFailure): self.run_control(text='hello')
                self.assertEqual(self.db.execute('SELECT attestation_check_id FROM managed_operations').fetchone()[0], expected)
            finally: self.request = original
        self.db.execute('DROP TABLE managed_operations'); self.reserve_without_send()
        error = GuardFailure('ATTESTATION_FAILED', attestation_check_id='Bearer malicious-unknown')
        record_denial(self.db, self.binding, self.sid, 'operation', error)
        self.assertIsNone(self.db.execute('SELECT attestation_check_id FROM managed_operations').fetchone()[0])
        self.assertFalse(self.posts())

    def test_attestation_detail_atomic_abort_and_secret_exception_unknown(self):
        from workrelay.attestor import AttestationError
        self.configure_catalog_route_fixture()
        with patch('workrelay.attestor.verify', side_effect=AttestationError('Bearer private-secret', check_id='not-allowlisted')):
            with self.assertRaises(GuardFailure): self.run_control(text='hello')
        self.assertEqual(self.db.execute('SELECT denial_code,attestation_check_id FROM managed_operations').fetchone(),
                         ('ATTESTATION_FAILED', 'UNCLASSIFIED'))
        self.assertNotIn('private-secret', str(self.db.execute('SELECT * FROM managed_operations').fetchall()))
        self.db.execute('DROP TABLE managed_operations'); self.reserve_without_send()
        self.db.execute("CREATE TRIGGER reject_detail BEFORE UPDATE OF attestation_check_id ON managed_operations BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            record_denial(self.db, self.binding, self.sid, 'operation',
                          GuardFailure('ATTESTATION_FAILED', attestation_check_id='MODEL_CATALOG_READ_UNAVAILABLE'))
        self.assertEqual(self.db.execute('SELECT phase,denial_code,denied_at_ms,attestation_check_id FROM managed_operations').fetchone(),
                         ('reserved', None, None, None))
        self.assertFalse(self.posts())

    def test_legacy_attestation_detail_migration_does_not_backfill(self):
        self.reserve_without_send()
        self.db.execute("UPDATE managed_operations SET phase='denied',denial_code='ATTESTATION_FAILED',denied_at_ms=1")
        # Simulate the prior application schema using an isolated supported fixture.
        self.db.execute('ALTER TABLE managed_operations DROP COLUMN attestation_check_id')
        before = self.db.execute('SELECT * FROM managed_operations').fetchone()
        result = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation', receipt_only=True)
        self.assertEqual(result['denial_code'], 'ATTESTATION_FAILED')
        self.assertIsNone(result['attestation_check_id'])
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchone()[:-1], before)
        # The immediately prior application's explicit-column writer remains
        # compatible. This is not permission to run arbitrary older writers.
        self.db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid,denial_code,denied_at_ms) SELECT binding,session,'old-writer',kind,digest,message,phase,identity,reservation_pid,denial_code,denied_at_ms FROM managed_operations")
        old = inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'old-writer', receipt_only=True)
        self.assertIsNone(old['attestation_check_id'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE managed_operations SET attestation_check_id='non-enum-private' ")


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = str(Path(self.tmp.name).resolve())
        self.config = {'directory': self.directory, 'model': {'providerID': 'openai', 'id': 'included', 'variant': 'full'}, 'agent': 'quick-builder'}
        self.db = sqlite3.connect(':memory:', isolation_level=None); self.addCleanup(self.db.close)
        self.binding = 'a' * 64; self.sessions = {}; self.calls = []; self.timeout = False

    def authorize(self):
        if self.binding is None: raise BridgeError('revoked')
        return self.binding

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == '/api/project': return getattr(self, 'project_records', [{'id': 'project', 'canonical': self.directory}])
        if path.startswith('/api/location?'):
            from urllib.parse import parse_qs, urlsplit
            directory = parse_qs(urlsplit(path).query)['location[directory]'][0]
            projects = getattr(self, 'project_records', [{'id': 'project', 'canonical': self.directory}])
            current_id = getattr(self, 'location_projects', {}).get(directory)
            if current_id is not None:
                current = next((p for p in projects if p.get('id') == current_id), None)
                if current is not None: return {'directory': directory, 'project': {**copy.deepcopy(current), 'directory': directory}}
            matches = [p for p in projects if p.get('canonical') == directory]
            if len(matches) != 1: return {'directory': directory, 'project': None}
            return {'directory': directory, 'project': {**copy.deepcopy(matches[0]), 'directory': directory}}
        if method == 'GET':
            session = self.sessions.get(path.split('/')[-1])
            return {'data': copy.deepcopy(session)} if session else None
        self.assertEqual((method, path), ('POST', '/api/session'))
        self.assertNotIn('permissions', body); self.assertNotIn('parentID', body)
        projects = getattr(self, 'project_records', [{'id': 'project', 'canonical': self.directory}])
        matches = [p for p in projects if Path(body['location']['directory']).is_relative_to(Path(p['canonical']))]
        current_id = getattr(self, 'location_projects', {}).get(body['location']['directory'])
        selected = next((p for p in matches if p.get('id') == current_id), None) if current_id else max(matches, key=lambda p: len(p['canonical']))
        self.assertIsNotNone(selected)
        self.sessions[body['id']] = {**copy.deepcopy(body), 'projectID': selected['id']}
        if self.timeout: raise TimeoutError()
        return {'data': copy.deepcopy(self.sessions[body['id']])}

    def create(self, op='create1', **kw):
        return create_session(self.db, self.config, self, self.authorize, op,
                              **{'directory': self.directory, 'title': 'Isolated check', 'project_id': 'project', **kw})

    def test_router_creation_changes_only_new_conversations(self):
        old = self.create(op='old-builder')
        self.config['agent'] = 'harness-router'
        self.config['model'] = {'providerID': 'openai', 'id': 'router-fixture', 'variant': 'medium'}
        with patch('workrelay.managed_control.admission') as admit:
            new = self.create(op='new-router')
            admit.assert_not_called()
        self.assertFalse(new['inference_started'])
        self.assertEqual(self.sessions[new['session_id']]['agent'], 'harness-router')
        self.assertEqual(self.sessions[new['session_id']]['model'], self.config['model'])
        self.assertEqual(self.sessions[old['session_id']]['agent'], 'quick-builder')
        posts = sum(method == 'POST' for method, _, _ in self.calls)
        with self.assertRaises(BridgeError):
            self.create(op='old-builder')
        self.assertEqual(sum(method == 'POST' for method, _, _ in self.calls), posts)

    def test_durable_create_duplicate_conflict_and_no_inference(self):
        with patch('workrelay.managed_control.admission') as admit:
            result = self.create()
            self.assertEqual(result['phase'], 'created'); self.assertFalse(result['inference_started'])
            self.assertEqual(self.create(), result); admit.assert_not_called()
            with self.assertRaises(BridgeError): self.create(title='Changed')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)
        session = self.sessions[result['session_id']]
        self.assertEqual(session['model'], self.config['model'])
        self.assertEqual(session['agent'], self.config['agent'])
        self.assertNotIn('permissions', session)

    def test_uncertain_create_exact_reconciliation_without_replay(self):
        self.timeout = True
        with self.assertRaises(BridgeError): self.create()
        self.assertEqual(self.create()['phase'], 'created')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)
        self.sessions.clear()
        with self.assertRaises(BridgeError): self.create()
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_workspace_project_revocation_and_identity_denied(self):
        for args in ({'directory': '/'}, {'project_id': 'other'}):
            with self.assertRaises(BridgeError): self.create(**args)
        self.assertFalse(any(m == 'POST' for m, _, _ in self.calls))
        self.binding = None
        with self.assertRaises(BridgeError): self.create('revoked')
        self.binding = 'a' * 64
        result = self.create('valid')
        self.sessions[result['session_id']]['model']['variant'] = 'wrong'
        with self.assertRaises(BridgeError): self.create('valid')

    def test_reserved_creation_not_replaced_by_parallel_caller(self):
        original = self.request
        observed = []
        def request(method, path, body=None):
            if path == '/api/project':
                observed.append(self.create())
            return original(method, path, body)
        self.request = request
        self.create()
        self.assertEqual(observed[0]['phase'], 'reserved')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_real_failure_shape_valid_project_wrong_workspace_is_definite_denial(self):
        original = self.request
        def request(method, path, body=None):
            if path == '/api/project': return [{'id': 'project', 'canonical': '/unrelated-project'}]
            return original(method, path, body)
        self.request = request
        with self.assertRaises(BridgeError) as caught: self.create()
        failure = classified_failure(self.db, self.authorize, 'create1', None, caught.exception)
        self.assertEqual(failure.control_details['code'], 'CONTROL_NOT_SENT')
        self.assertEqual(failure.control_details['reason'], 'PROJECT_WORKSPACE_MISMATCH')
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        recovered = inspect_operation(self.db, self.config, self, self.authorize, None, 'create1')
        self.assertEqual(recovered['recorded_phase'], 'denied')
        self.assertFalse(recovered['exact_session_exists'])
        self.assertEqual(recovered['effect'], 'not_applied')
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        self.assertFalse(any(m == 'POST' for m, _, _ in self.calls))

    def test_operation_only_uncertain_create_readonly_reconcile_not_absence_proof(self):
        self.timeout = True
        with self.assertRaises(BridgeError) as caught: self.create()
        failure = classified_failure(self.db, self.authorize, 'create1', None, caught.exception)
        self.assertEqual(failure.control_details['code'], 'CONTROL_UNCERTAIN')
        self.assertEqual(inspect_operation(self.db, self.config, self, self.authorize, None, 'create1')['phase'], 'created_observed')
        sid = creation_session_id(self.binding, 'create1')
        self.sessions[sid]['permissions'] = {'allow': True}
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, self.authorize, None, 'create1')
        self.sessions.clear()
        recovered = inspect_operation(self.db, self.config, self, self.authorize, None, 'create1')
        self.assertEqual(recovered['effect'], 'unknown')
        self.assertEqual(recovered['recorded_phase'], 'uncertain')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def setup_native_projects(self):
        other = Path(self.directory) / 'other-project'; other.mkdir()
        self.other = str(other)
        self.project_records = [{'id': 'project', 'canonical': self.directory}, {'id': 'other', 'canonical': self.other}]

    def native_create(self, op='native', **overrides):
        return create_session(self.db, self.config, self, self.authorize, op,
            **{'title': 'Workrelay acceptance test', 'project_id': 'other', 'authorize_native_projects': self.authorize, **overrides})

    def test_remote_shape_omitted_directory_selects_verified_native_root(self):
        self.setup_native_projects()
        result = self.native_create()
        self.assertEqual(self.sessions[result['session_id']]['location'], {'directory': self.other})
        self.assertEqual(self.sessions[result['session_id']]['model'], self.config['model'])
        self.assertFalse(result['inference_started'])
        self.assertEqual(self.native_create(), result)
        self.sessions[result['session_id']]['metadata']['openchamber'] = {'work': {'state': 'open', 'openedAt': 1}}
        self.assertEqual(self.native_create(), result)
        self.sessions[result['session_id']]['metadata']['workrelayBinding'] = 'changed'
        with self.assertRaises(BridgeError): self.native_create()
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)
        with self.assertRaises(BridgeError): self.native_create(directory=self.directory)
        with self.assertRaises(BridgeError):
            create_session(self.db, self.config, self, self.authorize, 'lower-scope', title='Lower scoped', project_id='other')

    def test_native_scope_wrong_authority_and_traversal_symlink_denied(self):
        self.setup_native_projects()
        with self.assertRaises(BridgeError): self.native_create('wrong-authority', authorize_native_projects=lambda: 'b' * 64)
        with self.assertRaises(BridgeError): self.native_create('traversal', directory=self.other + '/../other-project')
        link = Path(self.directory) / 'linked'; link.symlink_to(self.other, target_is_directory=True)
        self.config['managed_allowed_directories'] = [str(link)]
        with self.assertRaises(BridgeError): self.native_create('explicit-symlink', directory=str(link))
        self.project_records[1]['canonical'] = str(link)
        with self.assertRaises(BridgeError): self.native_create('native-symlink')
        self.assertFalse(any(m == 'POST' for m, _, _ in self.calls))

    def test_native_project_change_before_post_denied_and_old_denial_immutable(self):
        self.setup_native_projects()
        original = self.request; count = 0
        def request(method, path, body=None):
            nonlocal count
            if path == '/api/project':
                count += 1
                if count > 1: return [{'id': 'other', 'canonical': self.directory}]
            return original(method, path, body)
        self.request = request
        with self.assertRaises(BridgeError): self.native_create()
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='native'").fetchone()[0], 'denied')
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        self.request = original
        self.assertEqual(self.native_create()['phase'], 'denied')
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        self.assertFalse(any(m == 'POST' for m, _, _ in self.calls))

    def test_stale_shared_root_is_typed_denial_and_is_immutable(self):
        # project.list can expose an old ID after the native resolver has moved
        # the same canonical directory to a replacement project.
        self.project_records = [{'id': 'stale', 'canonical': self.directory}, {'id': 'current', 'canonical': self.directory}]
        original = self.request
        def request(method, path, body=None):
            if path.startswith('/api/location?'):
                return {'directory': self.directory, 'project': {'id': 'current', 'directory': self.directory, 'canonical': self.directory}}
            return original(method, path, body)
        self.request = request
        with self.assertRaises(BridgeError) as caught:
            create_session(self.db, self.config, self, self.authorize, 'stale-root', title='Fixture', project_id='stale', authorize_native_projects=self.authorize)
        failure = classified_failure(self.db, self.authorize, 'stale-root', None, caught.exception)
        self.assertEqual(failure.control_details['reason'], 'PROJECT_WORKSPACE_MISMATCH')
        self.assertEqual(self.db.execute("SELECT phase,denial_code FROM managed_operations WHERE operation='stale-root'").fetchone(), ('denied', 'CREATE_PROJECT_WORKSPACE_MISMATCH'))
        before = self.db.execute("SELECT * FROM managed_operations WHERE operation='stale-root'").fetchall()
        self.assertEqual(create_session(self.db, self.config, self, self.authorize, 'stale-root', title='Fixture', project_id='stale', authorize_native_projects=self.authorize)['phase'], 'denied')
        self.assertEqual(self.db.execute("SELECT * FROM managed_operations WHERE operation='stale-root'").fetchall(), before)
        self.assertFalse(any(method == 'POST' for method, _, _ in self.calls))

    def test_current_shared_root_succeeds_in_either_inventory_order(self):
        for index, records in enumerate((
                [{'id': 'stale', 'canonical': self.directory}, {'id': 'current', 'canonical': self.directory}],
                [{'id': 'current', 'canonical': self.directory}, {'id': 'stale', 'canonical': self.directory}])):
            with self.subTest(order=index):
                self.project_records = records
                self.location_projects = {self.directory: 'current'}
                result = create_session(self.db, self.config, self, self.authorize, 'current-tied-' + str(index), title='Fixture', project_id='current', authorize_native_projects=self.authorize)
                self.assertEqual(self.sessions[result['session_id']]['projectID'], 'current')
                self.assertEqual(sum(method == 'POST' for method, _, _ in self.calls), index + 1)

    def test_nested_current_project_is_allowed_only_when_location_agrees(self):
        nested = Path(self.directory) / 'nested'; nested.mkdir()
        self.project_records = [{'id': 'outer', 'canonical': self.directory}, {'id': 'inner', 'canonical': str(nested)}]
        result = create_session(self.db, self.config, self, self.authorize, 'nested', title='Fixture', project_id='inner', authorize_native_projects=self.authorize)
        self.assertEqual(self.sessions[result['session_id']]['projectID'], 'inner')
        self.assertEqual(self.sessions[result['session_id']]['location']['directory'], str(nested))

    def test_nested_workspace_location_is_the_attempted_directory(self):
        workspace = Path(self.directory) / 'nested-workspace'; workspace.mkdir()
        self.project_records = [{'id': 'outer', 'canonical': self.directory}]
        self.config['managed_allowed_directories'] = [str(workspace)]
        self.location_projects = {str(workspace): 'outer'}
        result = create_session(self.db, self.config, self, self.authorize, 'nested-workspace', title='Fixture', project_id='outer', directory=str(workspace), authorize_native_projects=self.authorize)
        self.assertEqual(self.sessions[result['session_id']]['location']['directory'], str(workspace))
        locations = [path for _, path, _ in self.calls if path.startswith('/api/location?')]
        self.assertTrue(locations and all(str(workspace).replace('/', '%2F') in path for path in locations))

    def test_native_uncertain_creation_not_replayed(self):
        self.setup_native_projects(); self.timeout = True
        with self.assertRaises(BridgeError): self.native_create()
        self.assertEqual(self.native_create()['phase'], 'created')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_early_denials_bind_raw_arguments_before_project_or_path_validation(self):
        self.setup_native_projects()
        cases = [('unknown-project', {'project_id': 'missing'}, {'project_id': 'other'}),
                 ('invalid-path', {'directory': self.other + '/../other-project'}, {'directory': self.other}),
                 ('missing-path', {'directory': self.other + '/not-present'}, {'directory': self.other})]
        for op, bad, corrected in cases:
            with self.subTest(op=op):
                with self.assertRaises(BridgeError): self.native_create(op, **bad)
                before = self.db.execute('SELECT * FROM managed_operations WHERE operation=?', (op,)).fetchall()
                self.assertEqual(before[0][6], 'denied')
                self.assertTrue(before[0][4].startswith('args-v2:'))
                with self.assertRaisesRegex(BridgeError, 'operation conflict'):
                    self.native_create(op, **corrected)
                self.assertEqual(self.native_create(op, **bad)['phase'], 'denied')
                observed = inspect_operation(self.db, self.config, self, self.authorize, None, op)
                self.assertEqual(observed['effect'], 'not_applied')
                self.assertEqual(self.db.execute('SELECT * FROM managed_operations WHERE operation=?', (op,)).fetchall(), before)
        self.assertFalse(any(m == 'POST' for m, _, _ in self.calls))

    def test_prevalidation_reservation_serializes_same_and_changed_arguments(self):
        self.setup_native_projects(); original = self.request; observed = []
        def request(method, path, body=None):
            if path == '/api/project' and not observed:
                observed.append(self.native_create())
                with self.assertRaisesRegex(BridgeError, 'operation conflict'):
                    self.native_create(title='Changed while validation pending')
            return original(method, path, body)
        self.request = request
        self.native_create()
        self.assertEqual(observed[0]['phase'], 'reserved')
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_actual_create_reservation_death_recovers_only_identical_attempt(self):
        self.setup_native_projects()
        path = Path(self.directory) / 'create-crash.sqlite'
        def child():
            db = sqlite3.connect(path, isolation_level=None)
            create_session(db, self.config, self, self.authorize, 'create-crashed',
                title='Bounded crash fixture', project_id='other', authorize_native_projects=lambda: os._exit(74))
        process = multiprocessing.get_context('fork').Process(target=child)
        process.start(); process.join(10)
        if process.is_alive():
            process.terminate(); process.join(); self.fail('crash fixture did not exit')
        self.assertEqual(process.exitcode, 74)
        db = sqlite3.connect(path, isolation_level=None)
        try:
            before = db.execute('SELECT digest,identity,phase,reservation_pid FROM managed_operations').fetchone()
            self.assertEqual(before[1:3], ('{}', 'reserved'))
            self.assertTrue(reservation_owner_dead(before[3]))
            with self.assertRaisesRegex(BridgeError, 'operation conflict'):
                create_session(db, self.config, self, self.authorize, 'create-crashed',
                    title='Different', project_id='other', authorize_native_projects=self.authorize)
            self.assertEqual(db.execute('SELECT digest,identity,phase,reservation_pid FROM managed_operations').fetchone(), before)
            result = create_session(db, self.config, self, self.authorize, 'create-crashed',
                title='Bounded crash fixture', project_id='other', authorize_native_projects=self.authorize)
            self.assertEqual(result['phase'], 'created')
            self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)
        finally: db.close()

    def test_malformed_or_unauthorized_request_explicitly_unbound(self):
        for bad in ({'title': 'x' * 161}, {'directory': 'x' * 4097}, {'project_id': None}):
            with self.assertRaises(BridgeError): self.create(**bad)
        self.binding = None
        with self.assertRaises(BridgeError): self.create()
        self.assertFalse(self.db.execute("SELECT 1 FROM sqlite_master WHERE name='managed_operations'").fetchone())
        self.assertEqual(self.calls, [])

    def test_legacy_create_body_digest_inspection_only_no_rebinding(self):
        result = self.create()
        self.db.execute("UPDATE managed_operations SET digest=?", ('0' * 64,))
        before = self.db.execute('SELECT * FROM managed_operations').fetchall()
        with self.assertRaisesRegex(BridgeError, 'legacy create arguments unavailable'):
            self.create()
        self.assertEqual(inspect_operation(self.db, self.config, self, self.authorize, None, 'create1')['phase'], 'created_observed')
        self.assertEqual(self.db.execute('SELECT * FROM managed_operations').fetchall(), before)
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)


class NativeWaitTests(unittest.TestCase):
    def setUp(self):
        self.binding = 'a' * 64; self.calls = []; self.after_permission = None
        self.session = {'id': 'ses_waits', 'model': {'providerID': 'other', 'id': 'read-without-inference'},
                        'agent': 'native-owner', 'metadata': {'owner': 'untouched'}, 'permissions': {'ask': True}}
        self.pending = [{'id': 'per_wait', 'sessionID': 'ses_waits', 'action': 'shell',
                         'resources': ['token=synthetic-sensitive', 'Bearer synthetic-private-token'],
                         'metadata': {'approval': True, 'secret': 'never-expose'}, 'message': 'never-expose'}]
        self.forms = []
    def authorize(self):
        if self.binding is None: raise BridgeError('revoked')
        return self.binding
    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        self.assertEqual(method, 'GET'); self.assertIsNone(body)
        if path == '/api/session/ses_waits/permission':
            if self.after_permission: self.after_permission()
            return {'data': self.pending}
        if path == '/api/session/ses_waits/form':
            return {'data': self.forms}
        if path == '/api/session/ses_waits/form/frm_question':
            return {'data': {**self.forms[0], 'state': {'status': 'pending'}}}
        self.assertEqual(path, '/api/session/ses_waits')
        return {'data': copy.deepcopy(self.session)}

    @patch('workrelay.managed_control.admission')
    def test_actionable_waits_read_only_redacted_not_permission_approval(self, admit):
        before = copy.deepcopy(self.session)
        result = native_waits(self, self.authorize, 'ses_waits')
        self.assertEqual(result['pending_permission_count'], 1)
        self.assertEqual(result['items'][0]['request_id'], 'per_wait')
        self.assertTrue(result['items'][0]['requires_explicit_human_decision'])
        self.assertFalse(result['native_permission_reply_exposed'])
        self.assertTrue(result['native_question_reply_exposed'])
        self.assertIn('approval UI', result['guidance'])
        for secret in ('synthetic-sensitive', 'synthetic-private-token', 'never-expose'):
            self.assertNotIn(secret, str(result))
        self.assertEqual(self.session, before); admit.assert_not_called()
        self.assertEqual([path for _, path, _ in self.calls],
                         ['/api/session/ses_waits', '/api/session/ses_waits/permission', '/api/session/ses_waits/form', '/api/session/ses_waits'])

    def test_bounds_other_session_duplicate_and_unknown_permissions_fail_closed(self):
        original = copy.deepcopy(self.pending)
        self.pending *= 2
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')
        self.pending = copy.deepcopy(original); self.pending[0]['sessionID'] = 'ses_other'
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')
        self.pending = copy.deepcopy(original); self.pending[0]['resources'] = [None]
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')
        self.pending = copy.deepcopy(original) * 1001
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits', limit=0)

    def test_bounded_preview_revocation_and_owner_change(self):
        self.pending += [{**self.pending[0], 'id': 'per_second'}]
        result = native_waits(self, self.authorize, 'ses_waits', limit=1)
        self.assertTrue(result['truncated']); self.assertEqual(len(result['items']), 1)
        self.after_permission = lambda: setattr(self, 'binding', None)
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')

    def test_question_wait_is_separate_from_permission_and_requires_core_provenance(self):
        self.forms = [{'id': 'frm_question', 'sessionID': 'ses_waits', 'title': 'Questions',
                       'metadata': {'kind': 'question', 'tool': {'messageID': 'msg_question', 'id': 'call_question'}},
                       'fields': [{'key': 'q0', 'title': 'Direction', 'description': 'Choose safely', 'type': 'string'}]},
                      {'id': 'frm_auth', 'sessionID': 'ses_waits', 'title': 'Questions',
                       'metadata': {'kind': 'question'}, 'fields': [{'key': 'q0', 'type': 'string'}]}]
        result = native_waits(self, self.authorize, 'ses_waits')
        self.assertEqual(result['pending_question_count'], 1)
        self.assertEqual(result['questions'][0]['form_id'], 'frm_question')
        self.assertTrue(result['questions'][0]['requires_explicit_caller_decision'])
        self.binding = 'a' * 64
        self.after_permission = lambda: self.session.update(agent='other-owner')
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')

class NativeQuestionMutationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None); self.addCleanup(self.db.close)
        self.sid = 'ses_question'; self.binding = 'a' * 64; self.posts = []; self.fail_post = False; self.form_override = False; self.message_session = None
        self.session = {'id': self.sid, 'model': {'providerID': 'openai', 'id': 'included'}, 'agent': 'owner', 'metadata': {}, 'permissions': {}}
        self.form = {'id': 'frm_question', 'sessionID': self.sid, 'title': 'Questions',
          'metadata': {'kind': 'question', 'tool': {'messageID': 'msg_question', 'id': 'call_question'}},
          'fields': [{'key': 'q0', 'type': 'string'}], 'state': {'status': 'pending'}}
    def authorize(self): return self.binding
    def request(self, method, path, body=None):
        if path == '/api/session/' + self.sid: return {'data': copy.deepcopy(self.session)}
        if path.endswith('/reply') or method == 'DELETE':
            self.posts.append((method,path,copy.deepcopy(body)))
            if self.fail_post: raise TimeoutError()
            self.form['state'] = {'status': 'cancelled'} if method == 'DELETE' else {'status': 'answered', 'answer': body['answer']}; return {}
        if path == f'/api/session/{self.sid}/form/frm_question':
            return self.form_override if self.form_override is not False else {'data': copy.deepcopy(self.form)}
        if path == f'/api/session/{self.sid}/message/msg_question': return {'data': {'id':'msg_question', **({'sessionID': self.message_session} if self.message_session is not None else {}), 'content':[{'type':'tool','id':'call_question','name':'question','executed':{},'providerState':{},'state':{'status':'running'},'time':{}}]}}
        raise AssertionError((method,path,body))
    def reserve_question(self, operation, *, cancel=False, answer=None, pid=999999):
        initialize(self.db)
        kind = 'question_cancel' if cancel else 'question_reply'
        digest = hashlib.sha256((kind + '\0' + 'frm_question' + '\0' + json.dumps(answer, sort_keys=True, separators=(',', ':'), ensure_ascii=False)).encode()).hexdigest()
        self.db.execute('INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) VALUES(?,?,?,?,?,?,?,?,?)',
                        (self.binding, self.sid, operation, kind, digest, 'frm_question', 'reserved', identity(self.session, self.sid), pid))
    @patch('workrelay.managed_control.admission')
    def test_reply_cancel_idempotency_and_conflicts(self, admit):
        result = settle_question(self.db, {}, self, self.authorize, self.sid, 'reply', 'frm_question', answer={'q0':'yes'})
        self.assertEqual(result['phase'], 'question_answered_observed'); self.assertEqual(len(self.posts), 1)
        self.assertEqual(settle_question(self.db, {}, self, self.authorize, self.sid, 'reply', 'frm_question', answer={'q0':'yes'})['phase'], result['phase'])
        self.assertEqual(len(self.posts), 1)
        for kwargs in ({'answer':{'q0':'no'}}, {'answer':None, 'cancel':True}):
            with self.assertRaises(BridgeError): settle_question(self.db, {}, self, self.authorize, self.sid, 'reply', 'frm_question', **kwargs)
        self.form['state'] = {'status':'pending'}
        self.assertEqual(settle_question(self.db, {}, self, self.authorize, self.sid, 'cancel', 'frm_question', cancel=True)['phase'], 'question_cancelled_observed')
        self.assertEqual(len(self.posts), 2)
    @patch('workrelay.managed_control.admission')
    def test_invalid_foreign_settled_or_tool_mismatch_never_posts(self, admit):
        cases = [lambda: self.form.update(sessionID='ses_other'), lambda: self.form.update(state={'status':'answered'}),
                 lambda: self.form.update(metadata={'kind':'auth','tool':{'messageID':'msg_question','id':'call_question'}}),
                 lambda: setattr(self, 'message_session', 'ses_other')]
        for index, change in enumerate(cases):
            self.form['sessionID']=self.sid; self.form['state']={'status':'pending'}; self.form['metadata']={'kind':'question','tool':{'messageID':'msg_question','id':'call_question'}}; self.message_session = None; change()
            with self.assertRaises(BridgeError): settle_question(self.db, {}, self, self.authorize, self.sid, 'bad'+str(index), 'frm_question', answer={'q0':'x'})
        self.assertEqual(self.posts, [])
    @patch('workrelay.managed_control.admission')
    def test_uncertain_post_never_replays_and_admission_denial_never_posts(self, admit):
        self.fail_post = True
        with self.assertRaises(BridgeError): settle_question(self.db, {}, self, self.authorize, self.sid, 'uncertain', 'frm_question', answer={'q0':'x'})
        self.fail_post = False
        self.assertEqual(settle_question(self.db, {}, self, self.authorize, self.sid, 'uncertain', 'frm_question', answer={'q0':'x'})['phase'], 'uncertain')
        self.assertEqual(len(self.posts), 1)
        admit.side_effect = BridgeError('denied')
        with self.assertRaises(BridgeError): settle_question(self.db, {}, self, self.authorize, self.sid, 'denied', 'frm_question', answer={'q0':'x'})
        self.assertEqual(len(self.posts), 1)

    @patch('workrelay.managed_control.admission')
    def test_reconcile_requires_exact_form_identity_and_recorded_answer(self, admit):
        self.fail_post = True
        with self.assertRaises(BridgeError):
            settle_question(self.db, {}, self, self.authorize, self.sid, 'uncertain', 'frm_question', answer={'q0':'expected'})
        self.fail_post = False
        self.form['state'] = {'status': 'answered', 'answer': {'q0': 'other'}}
        result = reconcile_question(self.db, self, self.authorize, self.sid, 'uncertain')
        self.assertEqual(result['native_form_state'], 'answered_other')
        self.assertEqual(len(self.posts), 1)
        self.form['sessionID'] = 'ses_foreign'
        with self.assertRaises(BridgeError): reconcile_question(self.db, self, self.authorize, self.sid, 'uncertain')
        self.form['sessionID'] = self.sid
        self.form_override = {'data': {}}
        with self.assertRaises(BridgeError): reconcile_question(self.db, self, self.authorize, self.sid, 'uncertain')
        self.form_override = None
        self.assertEqual(reconcile_question(self.db, self, self.authorize, self.sid, 'uncertain')['native_form_state'], 'absent')
        self.form_override = False
        self.session['agent'] = 'other-owner'
        with self.assertRaises(BridgeError): reconcile_question(self.db, self, self.authorize, self.sid, 'uncertain')

    @patch('workrelay.managed_control.admission')
    def test_exact_uncertain_question_receipt_clears_durable_block_once(self, admit):
        self.fail_post = True
        with self.assertRaises(BridgeError):
            settle_question(self.db, {}, self, self.authorize, self.sid, 'clear', 'frm_question', answer={'q0': 'yes'})
        self.fail_post = False
        self.form['state'] = {'status': 'answered', 'answer': {'q0': 'yes'}}
        self.assertEqual(reconcile_question(self.db, self, self.authorize, self.sid, 'clear')['recorded_phase'], 'question_answered_observed')
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='clear'").fetchone()[0], 'question_answered_observed')
        self.assertEqual(reconcile_question(self.db, self, self.authorize, self.sid, 'clear')['recorded_phase'], 'question_answered_observed')

    def test_generic_reconcile_cas_clears_only_exact_observed_queue_receipt(self):
        initialize(self.db)
        digest = hashlib.sha256(b'queue\0expected').hexdigest()
        self.db.execute('INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) VALUES(?,?,?,?,?,?,?,?,?)',
                        (self.binding, self.sid, 'queue-clear', 'queue', digest, 'msg_queue', 'uncertain', identity(self.session, self.sid), os.getpid()))
        observed = {'operation_id': 'queue-clear', 'session_id': self.sid, 'kind': 'queue', 'phase': 'message_observed', 'recorded_phase': 'uncertain'}
        with patch('workrelay.managed_control.inspect_operation', return_value=observed), patch('workrelay.managed_control.native_waits', return_value={'pending_question_count': 0, 'pending_permission_count': 0}):
            self.assertEqual(reconcile_operation(self.db, {}, self, self.authorize, self.sid, 'queue-clear')['recorded_phase'], 'message_observed')
            self.assertEqual(reconcile_operation(self.db, {}, self, self.authorize, self.sid, 'queue-clear')['recorded_phase'], 'message_observed')
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='queue-clear'").fetchone()[0], 'message_observed')
        self.db.execute('INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity,reservation_pid) VALUES(?,?,?,?,?,?,?,?,?)',
                        (self.binding, self.sid, 'queue-mismatch', 'queue', digest, 'msg_other', 'uncertain', identity(self.session, self.sid), os.getpid()))
        unresolved = {'operation_id': 'queue-mismatch', 'session_id': self.sid, 'kind': 'queue', 'phase': 'uncertain', 'recorded_phase': 'uncertain'}
        with patch('workrelay.managed_control.inspect_operation', return_value=unresolved), patch('workrelay.managed_control.native_waits', return_value={'pending_question_count': 0, 'pending_permission_count': 0}):
            reconcile_operation(self.db, {}, self, self.authorize, self.sid, 'queue-mismatch')
        self.assertEqual(self.db.execute("SELECT phase FROM managed_operations WHERE operation='queue-mismatch'").fetchone()[0], 'uncertain')

    @patch('workrelay.managed_control.admission')
    @patch('workrelay.managed_control.reservation_owner_dead', return_value=True)
    def test_dead_reservations_recover_reply_and_cancel_without_changing_receipt(self, dead, admit):
        self.reserve_question('crashed-reply', answer={'q0': 'yes'})
        reply = settle_question(self.db, {}, self, self.authorize, self.sid, 'crashed-reply', 'frm_question', answer={'q0': 'yes'})
        self.assertEqual(reply['phase'], 'question_answered_observed')
        self.assertEqual(len(self.posts), 1)
        self.form['state'] = {'status': 'pending'}
        self.reserve_question('crashed-cancel', cancel=True)
        cancel = settle_question(self.db, {}, self, self.authorize, self.sid, 'crashed-cancel', 'frm_question', cancel=True)
        self.assertEqual(cancel['phase'], 'question_cancelled_observed')
        self.assertEqual(len(self.posts), 2)

    @patch('workrelay.managed_control.admission')
    @patch('workrelay.managed_control.reservation_owner_dead', return_value=False)
    def test_live_or_unknown_question_reservation_blocks_without_post(self, dead, admit):
        self.reserve_question('live-reserved', answer={'q0': 'yes'}, pid=os.getpid())
        with self.assertRaises(BridgeError):
            settle_question(self.db, {}, self, self.authorize, self.sid, 'live-reserved', 'frm_question', answer={'q0': 'yes'})
        self.assertEqual(self.posts, [])


if __name__ == '__main__': unittest.main()
