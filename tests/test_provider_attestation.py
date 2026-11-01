import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import test_bridge
from workrelay.attestor import verify, AttestationError, ANTHROPIC_PIN_PATHS
from workrelay.cli import admission, load_config


class ProviderAttestationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_bridge.BridgeTests(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.config = copy.deepcopy(self.fixture.data)
        self.config['model'] = {'providerID': 'anthropic', 'id': 'claude-fixture', 'variant': 'medium'}
        root = Path(self.fixture.tmp.name)
        pins = {}
        for key, rel in ANTHROPIC_PIN_PATHS.items():
            p = root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('synthetic pinned helper')
            pins[key] = hashlib.sha256(p.read_bytes()).hexdigest()
        self.config['provider_guard_file_hashes'] = {'anthropic': pins}
        self.metadata = copy.deepcopy(test_bridge.FakeClient.metadata)
        self.metadata['/api/plugin'].append({'id': 'griffinmartin.claude-auth', 'state': {'status': 'active'},'source':{'type':'local','path':str(root / ANTHROPIC_PIN_PATHS['auth_entry'])}})
        self.metadata['/api/provider/anthropic'] = {'id': 'anthropic', 'package': '@opencode/ai/providers/anthropic'}
        self.metadata['/api/integration/anthropic'] = {'id': 'anthropic', 'methods': [{'id': 'claude-code', 'type': 'oauth'}], 'connections': [{'type': 'credential', 'method': 'oauth'}]}
        self.metadata['/api/model'].append({'id': 'claude-fixture', 'modelID': 'claude-fixture', 'providerID': 'anthropic', 'package': '@opencode/ai/providers/anthropic', 'variants': [{'id': 'medium'}]})
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path))
        self.assertEqual(method, 'GET')
        return {'data': copy.deepcopy(self.metadata[path])}

    def test_claude_uses_own_oauth_guard_without_codex_quota_or_credentials(self):
        with patch('workrelay.cli.subprocess.run', side_effect=AssertionError('Codex quota must not gate Claude')):
            admission(self.config, self)
        self.assertNotIn(('GET', '/api/provider/openai'), self.calls)
        self.assertNotIn(('GET', '/api/integration/openai'), self.calls)
        self.assertEqual(sum(path == '/api/provider/anthropic' for _, path in self.calls), 2)

    def test_anthropic_failures_block_without_native_writes(self):
        provider = self.metadata['/api/provider/anthropic']
        integration = self.metadata['/api/integration/anthropic']
        model = self.metadata['/api/model'][-1]
        cases = [
            lambda: provider.update(integrationID='openai'),
            lambda: provider.update(integrationID=None),
            lambda: provider.update(package='custom-sdk'),
            lambda: provider.update(settings=[]),
            lambda: provider.update(settings={'apiKey': 'fixture'}),
            lambda: provider.update(settings={'authToken': 'fixture'}),
            lambda: provider.update(settings={'baseURL': 'https://api.openai.com/v1'}),
            lambda: provider.update(settings={'baseURL': 'https://api.anthropic.com/v1/'}),
            lambda: provider.update(headers={'AUTHORIZATION': 'fixture'}),
            lambda: provider.update(body={'model': 'other'}),
            lambda: integration.update(connections=[{'type':'credential','method':'api-key'}, {'type':'credential','method':'oauth'}]),
            lambda: integration.update(methods=[]),
            lambda: model.update(variants=[]),
            lambda: model.update(modelID='other'),
            lambda: model.update(body={'model':'other'}),
            lambda: model['variants'][0].update(settings={'authToken':'fixture'}),
            lambda: self.config.pop('provider_guard_file_hashes'),
            lambda: self.config['provider_guard_file_hashes']['anthropic'].update(subscription='0'*64),
            lambda: self.metadata['/api/plugin'][-1].update(state={'status':'failed'}),
            lambda: self.metadata['/api/plugin'][-1].update(source={'type':'local','path':'/untrusted/entry.mjs'}),
        ]
        baseline = copy.deepcopy(self.metadata); conf = copy.deepcopy(self.config)
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                self.metadata = copy.deepcopy(baseline); self.config = copy.deepcopy(conf)
                provider = self.metadata['/api/provider/anthropic']; integration = self.metadata['/api/integration/anthropic']; model = self.metadata['/api/model'][-1]
                mutate()
                with self.assertRaises(AttestationError): verify(self.config, self)
                self.assertTrue(all(method == 'GET' for method, _ in self.calls))

    def test_selected_model_changes_during_metadata_read_fail_closed(self):
        original = self.request
        count = 0
        def changing(method, path):
            nonlocal count
            if path == '/api/model':
                count += 1
                if count == 2:self.metadata[path][-1]['variants'] = [{'id':'high'}]
            return original(method, path)
        self.request = changing
        with self.assertRaises(AttestationError) as error: verify(self.config, self)
        self.assertEqual(error.exception.check_id, 'MODEL_CATALOG')

    def test_openai_still_runs_codex_admission_and_ignores_claude_pin_requirement(self):
        config = self.fixture.data
        with patch('workrelay.cli.subprocess.run', return_value=type('Result', (), {'returncode': 1})()) as run:
            with self.assertRaises(Exception):admission(config, self)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], [config['quota_command'], '--check'])
        self.assertEqual(self.calls, [])

    def test_claude_only_configuration_does_not_require_codex_quota_command(self):
        self.config.pop('quota_command')
        self.fixture.config.write_text(json.dumps(self.config))
        loaded, _, _, _ = load_config(str(self.fixture.config))
        self.assertEqual(loaded['model']['providerID'], 'anthropic')
        with patch('workrelay.cli.subprocess.run', side_effect=AssertionError('No Codex dependency for Claude-only')):
            admission(loaded, self)

    def test_missing_codex_command_is_explicit_when_target_is_openai(self):
        from workrelay.cli import GuardFailure
        config = copy.deepcopy(self.fixture.data); config.pop('quota_command')
        with self.assertRaises(GuardFailure) as error: admission(config, self)
        self.assertEqual(error.exception.denial_code, 'QUOTA_UNAVAILABLE')
        self.assertEqual(self.calls, [])
