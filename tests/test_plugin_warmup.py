"""GUARD_PLUGIN_STATE warm-up retry after an OpenCode service restart."""
import copy
import sqlite3
import unittest
from unittest.mock import patch

from workrelay import cli
from workrelay.cli import BridgeError, GuardFailure, admission_with_plugin_warmup
from workrelay.managed_control import control, settle_question


def plugin_state():
    return GuardFailure('ATTESTATION_FAILED', attestation_check_id='GUARD_PLUGIN_STATE')


class Recorder:
    """Client and admission double: admission outcomes are scripted in order."""
    def __init__(self, outcomes):
        self.outcomes = list(outcomes); self.events = []; self.sleeps = []

    def request(self, method, path, body=None):
        self.events.append(('request', method, path))
        return {'data': []}

    def admit(self, config, client):
        self.events.append(('admit',))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def sleep(self, seconds):
        self.events.append(('sleep', seconds)); self.sleeps.append(seconds)


class HelperTests(unittest.TestCase):
    def run_helper(self, recorder, **kw):
        return admission_with_plugin_warmup({}, recorder, admit=recorder.admit, sleep=recorder.sleep, **kw)

    def test_default_bound_is_three_retries_over_about_ten_seconds(self):
        # conftest zeroes the module default for speed; assert the shipped value.
        import importlib.util
        source = importlib.util.find_spec('workrelay.cli').loader.get_source('workrelay.cli')
        self.assertIn('PLUGIN_WARMUP_DELAYS = (1.0, 3.0, 6.0)', source)

    def test_succeeds_on_second_attempt_after_warmup(self):
        r = Recorder([plugin_state(), True]); retries = []
        self.assertTrue(self.run_helper(r, delays=(1.0, 3.0, 6.0), on_retry=retries.append))
        # Fail -> warm-up plugin load for the directory -> wait -> admit again.
        self.assertEqual(r.events, [('admit',), ('request', 'GET', '/api/plugin'), ('sleep', 1.0), ('admit',)])
        self.assertEqual(retries, [1])

    def test_gives_up_after_bound_with_original_error(self):
        first = plugin_state()
        r = Recorder([first, plugin_state(), plugin_state(), plugin_state(), True])
        with self.assertRaises(GuardFailure) as raised:
            self.run_helper(r, delays=(1.0, 3.0, 6.0))
        self.assertIs(raised.exception, first)
        self.assertEqual(r.sleeps, [1.0, 3.0, 6.0])
        self.assertEqual(sum(e == ('admit',) for e in r.events), 4)
        self.assertEqual(len(r.outcomes), 1)  # never exceeds the bound

    def test_does_not_retry_other_errors(self):
        for error in [GuardFailure('ATTESTATION_FAILED', attestation_check_id='GUARD_SOURCE'),
                      GuardFailure('ATTESTATION_FAILED', attestation_check_id='PLUGIN_READ_UNAVAILABLE'),
                      GuardFailure('ATTESTATION_FAILED'), GuardFailure('QUOTA_DENIED'),
                      GuardFailure('QUOTA_UNAVAILABLE'), BridgeError('other'), RuntimeError('other')]:
            with self.subTest(error=error):
                r = Recorder([error, True])
                with self.assertRaises(type(error)) as raised:
                    self.run_helper(r, delays=(1.0, 3.0, 6.0))
                self.assertIs(raised.exception, error)
                self.assertEqual(r.events, [('admit',)])

    def test_different_failure_after_warmup_is_the_verdict(self):
        later = GuardFailure('ATTESTATION_FAILED', attestation_check_id='GUARD_ENTRY_PIN')
        r = Recorder([plugin_state(), later])
        with self.assertRaises(GuardFailure) as raised:
            self.run_helper(r, delays=(1.0, 3.0, 6.0))
        self.assertIs(raised.exception, later)

    def test_before_retry_abort_and_warmup_failure(self):
        class Broken(Recorder):
            def request(self, method, path, body=None):
                raise BridgeError('service still starting')
        r = Broken([plugin_state(), True])
        self.assertTrue(self.run_helper(r, delays=(0.0,)))  # warm-up failure is best effort
        r = Recorder([plugin_state(), True])
        with self.assertRaises(GuardFailure) as raised:
            self.run_helper(r, delays=(0.0,), before_retry=lambda: (_ for _ in ()).throw(GuardFailure('AUTHORITY_UNAVAILABLE_OR_CHANGED')))
        self.assertEqual(raised.exception.denial_code, 'AUTHORITY_UNAVAILABLE_OR_CHANGED')
        self.assertEqual(sum(e == ('admit',) for e in r.events), 1)


class ManagedWarmupTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(self.db.close)
        self.sid = 'ses_existing'; self.binding = 'a' * 64; self.calls = []
        self.config = {'model': {'providerID': 'openai', 'id': 'included'}}
        self.session = {'id': self.sid, 'model': self.config['model'], 'agent': 'owner', 'metadata': {}}

    def authorize(self):
        return self.binding

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if method == 'GET' and path == '/api/plugin':
            return {'data': []}
        if method == 'GET':
            return None if '/message/' in path else {'data': copy.deepcopy(self.session)}
        return {'data': {'id': body['id'], 'sessionID': self.sid, 'delivery': body['delivery']}}

    def message(self, outcomes):
        outcomes = list(outcomes)
        def admit(config, client):
            self.calls.append(('ADMIT', None))
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException): raise outcome
        with patch('workrelay.managed_control.admission', side_effect=admit):
            return control(self.db, self.config, self, self.authorize, self.sid, 'op1', text='hello')

    def ledger(self):
        return self.db.execute('SELECT phase,denial_code,attestation_check_id,plugin_warmup_retries FROM managed_operations').fetchone()

    def posts(self):
        return [c for c in self.calls if c[0] == 'POST']

    def test_message_succeeds_after_warmup_with_one_post(self):
        result = self.message([plugin_state(), None])
        self.assertEqual(result['phase'], 'queued')
        self.assertEqual(len(self.posts()), 1)
        warm = self.calls.index(('GET', '/api/plugin'))
        self.assertLess(warm, self.calls.index(self.posts()[0]))
        self.assertEqual(self.ledger(), ('queued', None, None, 1))

    def test_message_gives_up_after_bound_without_post(self):
        with self.assertRaises(GuardFailure) as raised:
            self.message([plugin_state()] * 4)
        self.assertEqual(raised.exception.attestation_check_id, 'GUARD_PLUGIN_STATE')
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.ledger(), ('denied', 'ATTESTATION_FAILED', 'GUARD_PLUGIN_STATE', 3))
        self.assertEqual(sum(c[0] == 'ADMIT' for c in self.calls), 4)

    def test_message_other_denial_not_retried(self):
        with self.assertRaises(GuardFailure):
            self.message([GuardFailure('QUOTA_DENIED'), None])
        self.assertEqual(sum(c[0] == 'ADMIT' for c in self.calls), 1)
        self.assertNotIn(('GET', '/api/plugin'), self.calls)
        self.assertEqual(self.ledger(), ('denied', 'QUOTA_DENIED', None, None))

    def test_session_change_during_backoff_aborts_before_post(self):
        def admit(config, client):
            self.session['agent'] = 'replaced-owner'  # identity changes while waiting
            raise plugin_state()
        with patch('workrelay.managed_control.admission', side_effect=admit):
            with self.assertRaises(GuardFailure) as raised:
                control(self.db, self.config, self, self.authorize, self.sid, 'op1', text='hello')
        self.assertEqual(raised.exception.denial_code, 'IDENTITY_CHANGED')
        self.assertEqual(self.posts(), [])

    def test_question_reply_retries_before_post(self):
        form = {'id': 'frm_one', 'sessionID': self.sid, 'state': {'status': 'pending'}}
        outcomes = [plugin_state(), None]
        def admit(config, client):
            outcome = outcomes.pop(0)
            if outcome: raise outcome
        with patch('workrelay.managed_control.admission', side_effect=admit), \
             patch('workrelay.managed_control._question_form', return_value=False):
            with self.assertRaises(BridgeError):  # form check runs only after admission passed
                settle_question(self.db, self.config, self, self.authorize, self.sid, 'q1', 'frm_one', cancel=True)
        self.assertEqual(outcomes, [])
        self.assertEqual(self.posts(), [])
        self.assertIn(('GET', '/api/plugin'), self.calls)


if __name__ == '__main__':
    unittest.main()
