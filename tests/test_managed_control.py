import copy
import sqlite3
import unittest
import tempfile
import os
import hashlib
import json
import multiprocessing
from pathlib import Path
from unittest.mock import patch

from workrelay.cli import BridgeError
from workrelay.managed_control import control, reservation_owner_dead, create_session, creation_session_id, inspect_operation, identity, resolve_operation, classified_failure, native_waits


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
            self.assertIn(body['delivery'], ('queue', 'steer'))
            result = {'id': body['id'], 'sessionID': self.sid, 'delivery': body['delivery']}
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
        with self.assertRaises(BridgeError):
            inspect_operation(self.db, self.config, self, self.authorize, self.sid, 'operation')

    def test_exact_full_model_and_raw_input_bound(self):
        self.session['model'] = {**self.config['model'], 'variant': 'different'}
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
        self.db.execute("INSERT INTO managed_operations SELECT binding,'ses_other',operation,kind,digest,message,phase,identity,reservation_pid FROM managed_operations")
        with self.assertRaises(BridgeError): resolve_operation(self.db, self.authorize, 'operation')
        self.assertEqual(resolve_operation(self.db, self.authorize, 'operation', self.sid)[1], self.sid)
        self.binding = None
        with self.assertRaises(BridgeError): resolve_operation(self.db, self.authorize, 'operation', self.sid)


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
        if method == 'GET':
            session = self.sessions.get(path.split('/')[-1])
            return {'data': copy.deepcopy(session)} if session else None
        self.assertEqual((method, path), ('POST', '/api/session'))
        self.assertNotIn('permissions', body); self.assertNotIn('parentID', body)
        projects = getattr(self, 'project_records', [{'id': 'project', 'canonical': self.directory}])
        matches = [p for p in projects if Path(body['location']['directory']).is_relative_to(Path(p['canonical']))]
        selected = max(matches, key=lambda p: len(p['canonical']))
        self.sessions[body['id']] = {**copy.deepcopy(body), 'projectID': selected['id']}
        if self.timeout: raise TimeoutError()
        return {'data': copy.deepcopy(self.sessions[body['id']])}

    def create(self, op='create1', **kw):
        return create_session(self.db, self.config, self, self.authorize, op,
                              **{'directory': self.directory, 'title': 'Isolated check', 'project_id': 'project', **kw})

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
    def authorize(self):
        if self.binding is None: raise BridgeError('revoked')
        return self.binding
    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        self.assertEqual(method, 'GET'); self.assertIsNone(body)
        if path == '/api/session/ses_waits/permission':
            if self.after_permission: self.after_permission()
            return {'data': self.pending}
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
        self.assertFalse(result['native_question_reply_exposed'])
        self.assertIn('approval UI', result['guidance'])
        for secret in ('synthetic-sensitive', 'synthetic-private-token', 'never-expose'):
            self.assertNotIn(secret, str(result))
        self.assertEqual(self.session, before); admit.assert_not_called()
        self.assertEqual([path for _, path, _ in self.calls],
                         ['/api/session/ses_waits', '/api/session/ses_waits/permission', '/api/session/ses_waits'])

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
        self.binding = 'a' * 64
        self.after_permission = lambda: self.session.update(agent='other-owner')
        with self.assertRaises(BridgeError): native_waits(self, self.authorize, 'ses_waits')


if __name__ == '__main__': unittest.main()
