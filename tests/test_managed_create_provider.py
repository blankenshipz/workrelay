import copy
import hashlib
import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from workrelay.attestor import ANTHROPIC_PIN_PATHS
from workrelay.cli import BridgeError, GuardFailure
from workrelay import managed_control
from workrelay.managed_control import AGENT_WARMUP_DELAYS, create_body, create_session, creation_session_id

BINDING = 'a' * 64
FULL_PINS = {'anthropic': {name: 'b' * 64 for name in ANTHROPIC_PIN_PATHS}}
HAIKU = {'providerID': 'anthropic', 'id': 'claude-haiku-5-5', 'variant': 'default'}
OPUS = {'providerID': 'anthropic', 'id': 'claude-opus-5-5', 'variant': 'high'}


class ManagedCreateProviderTest(unittest.TestCase):
    """create_body route shape: supported provider, exact ref, complete pins."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = str(Path(self.tmp.name).resolve())
        self.base = {'directory': self.workspace, 'agent': 'harness-router'}

    def tearDown(self):
        self.tmp.cleanup()

    def body(self, **config):
        return create_body({**self.base, **config}, BINDING, 'op-1', self.workspace, 'demo')

    def test_openai_create_route_unchanged(self):
        model = {'providerID': 'openai', 'id': 'gpt-x'}
        body = self.body(model=model)
        self.assertEqual(body['model'], model)
        self.assertEqual(body['id'], creation_session_id(BINDING, 'op-1'))

    def test_anthropic_create_requires_complete_pinned_claude_guard(self):
        model = {'providerID': 'anthropic', 'id': 'claude-haiku-5-5', 'variant': 'low'}
        body = self.body(model=model, provider_guard_file_hashes=FULL_PINS)
        self.assertEqual(body['model'], model)
        self.assertEqual(body['location'], {'directory': self.workspace})
        partial = {'anthropic': {'subscription': 'b' * 64}}
        extra = {'anthropic': {**FULL_PINS['anthropic'], 'unexpected': 'b' * 64}}
        malformed = {'anthropic': {**FULL_PINS['anthropic'], 'paths': 'not-a-sha256'}}
        upper = {'anthropic': {**FULL_PINS['anthropic'], 'paths': 'B' * 64}}
        for missing in (None, {}, {'anthropic': {}}, {'openai': {'x': 'y'}}, partial, extra, malformed, upper,
                        {'anthropic': 'b' * 64}, ['anthropic']):
            with self.subTest(pins=missing), self.assertRaises(BridgeError):
                self.body(model=model, **({} if missing is None else {'provider_guard_file_hashes': missing}))

    def test_unsupported_or_overridden_models_denied(self):
        pins = {'provider_guard_file_hashes': FULL_PINS}
        for model in ({'providerID': 'other', 'id': 'x'}, {'providerID': 'anthropic', 'id': ''},
                      {'providerID': 'anthropic', 'id': 'claude', 'apiKey': 'k'}, {'providerID': 'anthropic'},
                      {'providerID': 'anthropic', 'id': 'claude', 'variant': ''},
                      {'providerID': 'anthropic', 'id': 'claude\n'}, {'providerID': 'anthropic', 'id': 7},
                      {'providerID': 'anthropic', 'id': 'c' * 201}, 'anthropic/claude', None):
            with self.subTest(model=model), self.assertRaises(BridgeError):
                self.body(model=model, **pins)

    def test_workspace_allowlist_still_enforced(self):
        with self.assertRaises(BridgeError):
            self.body(model={'providerID': 'anthropic', 'id': 'claude'}, managed_allowed_directories=['/nonexistent'],
                      provider_guard_file_hashes=FULL_PINS)


class CreateModelResolutionTest(unittest.TestCase):
    """Managed create stamps the target agent's configured model by default."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name).resolve()
        self.workspace = base / 'workspace'; self.workspace.mkdir()
        # Synthetic installed guard tree with real files and correct pins.
        install = base / 'install'
        entry = install / 'a' / 'b' / 'subscription-guard' / 'index.mjs'
        files = {'entry': entry, 'implementation': install / 'a' / 'b' / 'subscription-guard.mjs',
                 'financial': install / 'config' / 'guard-validation.mjs'}
        files.update({name: install / relative for name, relative in ANTHROPIC_PIN_PATHS.items()})
        for name, path in files.items():
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text('// fixture ' + name)
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.guard_files = files
        self.config = {'directory': str(self.workspace), 'agent': 'harness-router', 'model': copy.deepcopy(HAIKU),
                       'guard_entry': str(entry),
                       'guard_file_hashes': {name: digest(files[name]) for name in ('entry', 'implementation', 'financial')},
                       'provider_guard_file_hashes': {'anthropic': {name: digest(files[name]) for name in ANTHROPIC_PIN_PATHS}}}
        self.db = sqlite3.connect(':memory:', isolation_level=None); self.addCleanup(self.db.close)
        self.agent = {'id': 'harness-router', 'name': 'harness-router', 'mode': 'primary', 'hidden': False,
                      'model': copy.deepcopy(OPUS)}
        self.sessions = {}; self.calls = []
        self.answer_any_agent = False
        self.cold_agent_reads = 0  # native 404s before the location's agent registry loads
        sleeper = mock.patch.object(managed_control.time, 'sleep'); self.sleep = sleeper.start(); self.addCleanup(sleeper.stop)

    def authorize(self):
        return BINDING

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path == '/api/project':
            return [{'id': 'project', 'canonical': str(self.workspace)}]
        if method == 'GET' and path.startswith('/api/agent/'):
            parts = urlsplit(path)
            self.assertEqual(parse_qs(parts.query), {'location[directory]': [str(self.workspace)]})
            if self.cold_agent_reads > 0:
                self.cold_agent_reads -= 1
                return None  # cold location: registry not yet populated (native 404)
            if self.agent is None or (not self.answer_any_agent and parts.path != '/api/agent/' + self.agent['id']):
                return None  # native 404
            return {'location': {'directory': str(self.workspace)}, 'data': copy.deepcopy(self.agent)}
        if method == 'GET':
            session = self.sessions.get(path.split('/')[-1])
            return {'data': copy.deepcopy(session)} if session else None
        self.assertEqual((method, path), ('POST', '/api/session'))
        self.sessions[body['id']] = {**copy.deepcopy(body), 'projectID': 'project'}
        return {'data': copy.deepcopy(self.sessions[body['id']])}

    def create(self, op='create1'):
        return create_session(self.db, self.config, self, self.authorize, op,
                              directory=str(self.workspace), title='demo', project_id='project')

    def posts(self):
        return [body for method, _, body in self.calls if method == 'POST']

    def agent_reads(self):
        return [path for method, path, _ in self.calls if method == 'GET' and path.startswith('/api/agent/')]

    def assert_denied_without_post(self, op, expected=BridgeError):
        with self.assertRaises(expected) as raised:
            self.create(op)
        self.assertEqual(self.posts(), [])
        phase = self.db.execute('SELECT phase FROM managed_operations WHERE operation=?', (op,)).fetchone()[0]
        self.assertEqual(phase, 'denied')
        return raised.exception

    def test_default_uses_target_agent_configured_model_not_profile_pin(self):
        result = self.create()
        self.assertEqual(result['phase'], 'created'); self.assertFalse(result['inference_started'])
        self.assertEqual(self.sessions[result['session_id']]['model'], OPUS)
        self.assertEqual(self.posts()[0]['model'], OPUS)
        self.assertEqual(len(self.agent_reads()), 1)
        # Idempotent retry returns the receipt; it does not re-resolve or re-POST.
        self.assertEqual(self.create(), result); self.assertEqual(len(self.posts()), 1)

    def test_agent_without_model_falls_back_to_profile_model(self):
        del self.agent['model']
        result = self.create()
        self.assertEqual(self.sessions[result['session_id']]['model'], HAIKU)
        self.agent['model'] = None
        result = self.create('create2')
        self.assertEqual(self.sessions[result['session_id']]['model'], HAIKU)

    def test_explicit_profile_override_skips_agent_model(self):
        self.config['managed_create_model'] = 'profile'
        result = self.create()
        self.assertEqual(self.sessions[result['session_id']]['model'], HAIKU)
        self.assertEqual(self.agent_reads(), [])

    def test_invalid_model_policy_fails_closed(self):
        for policy in ('agent', '', None, True):
            self.config['managed_create_model'] = policy
            with self.subTest(policy=policy):
                self.assert_denied_without_post('bad-policy-' + str(policy).lower())

    def test_unavailable_or_foreign_agent_definition_never_falls_back(self):
        self.agent = None  # e.g. registry reloading (native 404)
        self.assert_denied_without_post('missing')
        self.agent = {'id': 'harness-builder', 'model': copy.deepcopy(OPUS)}
        self.assert_denied_without_post('foreign')

    def test_cold_location_agent_404_is_retried_before_post(self):
        # r31: first request for a directory boots the location and answers the
        # agent lookup 404 before plugins populate the registry.
        self.cold_agent_reads = 2
        result = self.create('cold')
        self.assertEqual(result['phase'], 'created')
        self.assertEqual(self.sessions[result['session_id']]['model'], OPUS)
        self.assertEqual(len(self.agent_reads()), 3)
        self.assertEqual(len(self.posts()), 1)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], list(AGENT_WARMUP_DELAYS[:2]))
        # Exactly one session; a retry of the same operation returns the receipt.
        self.assertEqual(self.create('cold'), result); self.assertEqual(len(self.posts()), 1)

    def test_persistent_agent_404_denies_after_bounded_retries(self):
        self.agent = None
        self.assert_denied_without_post('gone')
        self.assertEqual(len(self.agent_reads()), len(AGENT_WARMUP_DELAYS) + 1)
        self.assertEqual(self.sleep.call_count, len(AGENT_WARMUP_DELAYS))

    def test_foreign_agent_definition_is_not_retried(self):
        self.agent = {'id': 'harness-builder', 'model': copy.deepcopy(OPUS)}
        self.config['agent'] = 'harness-router'
        self.answer_any_agent = True  # 2xx carrying a different definition
        self.assert_denied_without_post('foreign-once')
        self.sleep.assert_not_called()

    def test_authority_change_during_cold_retry_aborts_without_post(self):
        self.cold_agent_reads = 10
        calls = {'n': 0}
        def authorize():
            calls['n'] += 1
            return BINDING if calls['n'] < 8 else 'other-binding'
        with self.assertRaises(BridgeError):
            create_session(self.db, self.config, self, authorize, 'authority', directory=str(self.workspace),
                           title='demo', project_id='project')
        self.assertEqual(self.posts(), [])

    def test_resolved_agent_model_gets_same_route_checks(self):
        for index, model in enumerate(({'providerID': 'other', 'id': 'x'}, {**OPUS, 'apiKey': 'k'},
                                       {'providerID': 'anthropic', 'id': ''}, 'anthropic/claude-opus-5-5#high',
                                       {'providerID': 'anthropic', 'id': 'claude', 'variant': 3})):
            self.agent['model'] = model
            with self.subTest(model=model):
                self.assert_denied_without_post(f'route-{index}')

    def test_resolved_anthropic_model_requires_pins_even_when_profile_is_openai(self):
        self.config['model'] = {'providerID': 'openai', 'id': 'gpt-x'}
        del self.config['provider_guard_file_hashes']
        self.assert_denied_without_post('no-pins')
        del self.agent['model']  # profile fallback: OpenAI route needs no Claude pins
        result = self.create('openai-fallback')
        self.assertEqual(self.sessions[result['session_id']]['model'], {'providerID': 'openai', 'id': 'gpt-x'})

    def test_mismatched_guard_files_deny_anthropic_create(self):
        self.guard_files['subscription'].write_text('// tampered')
        error = self.assert_denied_without_post('tampered-provider', GuardFailure)
        self.assertEqual((error.denial_code, error.attestation_check_id), ('ATTESTATION_FAILED', 'GUARD_IMPLEMENTATION_PIN'))
        self.guard_files['subscription'].write_text('// fixture subscription')
        self.guard_files['financial'].write_text('// tampered')
        error = self.assert_denied_without_post('tampered-guard', GuardFailure)
        self.assertEqual(error.attestation_check_id, 'GUARD_FINANCIAL_PIN')
        self.guard_files['financial'].unlink()
        error = self.assert_denied_without_post('missing-guard', GuardFailure)
        self.assertEqual(error.attestation_check_id, 'GUARD_FINANCIAL_PIN')


if __name__ == '__main__':
    unittest.main()
