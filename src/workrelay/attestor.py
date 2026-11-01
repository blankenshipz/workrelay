"""Secret-free preflight for a *guarded route*, not a provider billing guarantee.

The installed subscription guard remains authoritative at each model request.
This module never resolves credentials or invokes a model.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit, unquote


ATTESTATION_CHECK_IDS = frozenset({
    'UNCLASSIFIED', 'MODEL_REF', 'PLUGIN_READ_UNAVAILABLE', 'PLUGIN_RESPONSE',
    'GUARD_PLUGIN_STATE', 'GUARD_SOURCE', 'GUARD_PIN_CONFIG',
    'GUARD_ENTRY_PIN', 'GUARD_IMPLEMENTATION_PIN', 'GUARD_FINANCIAL_PIN',
    'GUARD_FILE_UNAVAILABLE', 'PROVIDER_READ_UNAVAILABLE', 'PROVIDER_RESPONSE',
    'PROVIDER_INTEGRATION_SOURCE', 'INTEGRATION_READ_UNAVAILABLE', 'INTEGRATION_RESPONSE',
    'OAUTH_CONNECTION', 'PROVIDER_OVERLAY', 'MODEL_CATALOG_READ_UNAVAILABLE',
    'MODEL_CATALOG_RESPONSE', 'MODEL_CATALOG', 'VARIANT', 'MODEL_OVERLAY',
    'PROVIDER_SOURCE_CHANGED', 'INTEGRATION_SOURCE_CHANGED',
})


PROVIDER_PACKAGES = {
    'openai': ('@opencode/ai/providers/openai', '@opencode/ai/providers/openai/responses'),
    'anthropic': ('@opencode/ai/providers/anthropic',),
}
ANTHROPIC_PIN_PATHS = {
    'subscription': 'plugins/v2/anthropic-subscription.mjs',
    'financial_policy': 'plugins/v2/anthropic-financial-policy.mjs',
    'quota_cache': 'plugins/v2/quota-cache.mjs',
    'paths': 'plugins/v2/paths.mjs',
    'auth_entry': 'plugins/v2/claude-auth/index.mjs',
}


def check_endpoint(value, provider_id, check_id):
    check(isinstance(value, str), check_id)
    u = urlsplit(value)
    check(u.scheme == 'https' and not u.username and not u.password and not u.query and not u.fragment, check_id)
    if provider_id == 'openai':
        check(u.netloc == 'chatgpt.com' and (u.path == '/backend-api/codex' or u.path.startswith('/backend-api/codex/')), check_id)
    else:
        check(value in ('https://api.anthropic.com', 'https://api.anthropic.com/v1'), check_id)


class AttestationError(Exception):
    def __init__(self, message=None, *, check_id=None):
        self.check_id = check_id if isinstance(check_id, str) and check_id in ATTESTATION_CHECK_IDS else 'UNCLASSIFIED'
        super().__init__('guarded OAuth route unverified')


class InstalledServiceReadOnlyClient:
    """Use the installed CLI's own service authentication; no token discovery.

    This mode is preflight-only and cannot submit prompts on behalf of the adapter.
    """
    PATHS = frozenset(("/api/plugin", "/api/integration/openai", "/api/provider/openai", "/api/integration/anthropic", "/api/provider/anthropic", "/api/model"))

    def __init__(self, config):
        binary = Path(config["installed_cli"]).expanduser().resolve()
        check(binary.is_file() and os.access(binary, os.X_OK))
        self.binary = str(binary)
        self.expected_server = config["server"]
        self.assert_service()

    def command(self, *args):
        try:
            p = subprocess.run([self.binary, *args], capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            raise AttestationError("installed service unavailable") from None
        check(p.returncode == 0 and len(p.stdout) <= 2_000_000)
        return p.stdout

    def assert_service(self):
        actual = self.command("service", "status").decode("utf-8", "strict").strip()
        check(actual == self.expected_server)

    def request(self, method, path):
        check(method == "GET" and path in self.PATHS)
        self.assert_service()
        try:
            return json.loads(self.command("api", "GET", path))
        except (UnicodeDecodeError, ValueError):
            raise AttestationError("installed service response invalid") from None


def check(condition, check_id='UNCLASSIFIED'):
    if not condition:
        raise AttestationError(check_id=check_id)


def provider_evidence(error, client, stage, **values):
    try:
        from .provider_diagnostic import attach
        attach(error, client, stage, **values)
    except Exception:
        pass


def payload(client, path):
    from .cli import BridgeError
    stage = {'/api/plugin': 'PLUGIN', '/api/provider/openai': 'PROVIDER',
             '/api/integration/openai': 'INTEGRATION', '/api/provider/anthropic': 'PROVIDER',
             '/api/integration/anthropic': 'INTEGRATION', '/api/model': 'MODEL_CATALOG'}[path]
    try:
        response = client.request("GET", path)
    except (BridgeError, AttestationError, OSError, TimeoutError):
        error = AttestationError(check_id=stage + '_READ_UNAVAILABLE')
        if stage == 'PROVIDER':
            provider_evidence(error, client, 'read')
        raise error from None
    try:
        check(isinstance(response, dict) and isinstance(response.get("data"), (dict, list)), stage + '_RESPONSE')
    except AttestationError as error:
        if stage == 'PROVIDER':
            provider_evidence(error, client, 'envelope', response=response)
        raise
    return response["data"]


def verify(config, client):
    """Check route metadata and pinned local guard files; never return raw metadata."""
    ref = config.get('model')
    check(isinstance(ref, dict) and set(ref) <= {'providerID', 'id', 'variant'} and
          ref.get('providerID') in PROVIDER_PACKAGES and isinstance(ref.get('id'), str) and
          0 < len(ref['id']) <= 200 and ref['id'].isprintable() and
          ('variant' not in ref or isinstance(ref['variant'], str) and
            0 < len(ref['variant']) <= 200 and ref['variant'].isprintable()), 'MODEL_REF')
    provider_id = ref['providerID']
    packages = PROVIDER_PACKAGES[provider_id]
    guard = payload(client, '/api/plugin')
    try:
        check(isinstance(guard, list) and all(isinstance(plugin, dict) for plugin in guard), 'GUARD_PLUGIN_STATE')
        matches = [plugin for plugin in guard if plugin.get("id") == "subscription.guard"]
        check(len(matches) == 1 and isinstance(matches[0].get("state"), dict) and
              matches[0]["state"].get("status") == "active", 'GUARD_PLUGIN_STATE')
    except AttestationError as error:
        try:
            from .guard_diagnostic import plugin_evidence
            error.guard_diagnostic = plugin_evidence(guard)
        except Exception:
            pass  # A broken diagnostic must not replace the original denial.
        raise
    source = matches[0].get("source")
    check(isinstance(source, dict), 'GUARD_SOURCE')
    check(source.get("type") == "local" and isinstance(source.get("path"), str), 'GUARD_SOURCE')
    raw = source["path"]
    parsed = urlsplit(raw)
    check(parsed.scheme in ("", "file") and not parsed.netloc and not parsed.query and not parsed.fragment, 'GUARD_SOURCE')
    entry = Path(unquote(parsed.path)).resolve()
    expected = Path(config["guard_entry"]).expanduser().resolve()
    check(entry == expected and entry.name == "index.mjs" and entry.parent.name == "subscription-guard", 'GUARD_SOURCE')
    root = entry.parent.parent.parent.parent
    files = {"entry": entry, "implementation": entry.parent.parent / "subscription-guard.mjs",
             "financial": root / "config" / "guard-validation.mjs"}
    hashes = config["guard_file_hashes"]
    check(set(hashes) == set(files), 'GUARD_PIN_CONFIG')
    for name, path in files.items():
        expected_hash = hashes[name]
        check(isinstance(expected_hash, str) and bool(re.fullmatch(r"[0-9a-f]{64}", expected_hash)), 'GUARD_PIN_CONFIG')
        try:
            check(path.is_file() and path.stat().st_uid == os.getuid() and
                   hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash,
                  {'entry': 'GUARD_ENTRY_PIN', 'implementation': 'GUARD_IMPLEMENTATION_PIN',
                   'financial': 'GUARD_FINANCIAL_PIN'}[name])
        except OSError:
            raise AttestationError(check_id='GUARD_FILE_UNAVAILABLE') from None

    if provider_id == 'anthropic':
        auth_plugins = [p for p in guard if p.get('id') == 'griffinmartin.claude-auth']
        check(len(auth_plugins) == 1 and isinstance(auth_plugins[0].get('state'), dict) and auth_plugins[0]['state'].get('status') == 'active', 'OAUTH_CONNECTION')
        auth_source = auth_plugins[0].get('source')
        check(isinstance(auth_source, dict) and auth_source.get('type') == 'local' and isinstance(auth_source.get('path'), str), 'OAUTH_CONNECTION')
        auth_url = urlsplit(auth_source['path'])
        check(auth_url.scheme in ('', 'file') and not auth_url.netloc and not auth_url.query and not auth_url.fragment and Path(unquote(auth_url.path)).resolve() == (root / ANTHROPIC_PIN_PATHS['auth_entry']).resolve(), 'OAUTH_CONNECTION')
        provider_pins = config.get('provider_guard_file_hashes')
        check(isinstance(provider_pins, dict), 'GUARD_PIN_CONFIG')
        pins = provider_pins.get('anthropic')
        check(isinstance(pins, dict) and set(pins) == set(ANTHROPIC_PIN_PATHS), 'GUARD_PIN_CONFIG')
        for name, relative in ANTHROPIC_PIN_PATHS.items():
            path = root / relative
            expected_hash = pins[name]
            check(isinstance(expected_hash, str) and bool(re.fullmatch(r'[0-9a-f]{64}', expected_hash)), 'GUARD_PIN_CONFIG')
            try:
                check(path.is_file() and path.stat().st_uid == os.getuid() and hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash, 'GUARD_IMPLEMENTATION_PIN')
            except OSError:
                raise AttestationError(check_id='GUARD_FILE_UNAVAILABLE') from None

    provider_path = '/api/provider/' + provider_id
    integration_path = '/api/integration/' + provider_id
    provider = payload(client, provider_path)
    try:
        check(isinstance(provider, dict), 'PROVIDER_RESPONSE')
    except AttestationError as error:
        provider_evidence(error, client, 'provider_data', data=provider)
        raise
    # Attest the actual native credential source, never a different OAuth pool.
    check(provider.get('integrationID', provider_id) == provider_id, 'PROVIDER_INTEGRATION_SOURCE')
    integration = payload(client, integration_path)
    check(isinstance(integration, dict), 'INTEGRATION_RESPONSE')
    connections = integration.get('connections')
    check(integration.get('id') == provider_id and isinstance(connections, list) and connections and
          isinstance(connections[0], dict) and connections[0].get('type') == 'credential' and
          connections[0].get('method') == 'oauth', 'OAUTH_CONNECTION')
    if provider_id == 'anthropic':
        methods = integration.get('methods')
        check(isinstance(methods, list) and sum(isinstance(m, dict) and m.get('id') == 'claude-code' and m.get('type') == 'oauth' for m in methods) == 1, 'OAUTH_CONNECTION')
    settings = {} if provider.get('settings') is None else provider['settings']
    headers = {} if provider.get('headers') is None else provider['headers']
    check(isinstance(settings, dict) and isinstance(headers, dict), 'PROVIDER_OVERLAY')
    check(provider.get('id') == provider_id and provider.get('package') in packages and
          not any(k in settings for k in (('apiKey', 'authToken') if provider_id == 'anthropic' else ('apiKey',))) and not any(name.lower() in ('authorization', 'api-key', 'x-api-key') for name in headers), 'PROVIDER_OVERLAY')
    if provider_id == 'anthropic':
        check(provider.get('modelID', ref['id']) == ref['id'] and not (isinstance(provider.get('body'), dict) and 'model' in provider['body']), 'PROVIDER_OVERLAY')
    if 'baseURL' in settings:
        check_endpoint(settings['baseURL'], provider_id, 'PROVIDER_OVERLAY')
    models = payload(client, '/api/model')
    check(isinstance(models, list) and models and all(isinstance(m, dict) and isinstance(m.get('providerID'), str) for m in models), 'MODEL_CATALOG')
    selected = [m for m in models if m.get('providerID') == provider_id and m.get('id') == ref['id']]
    check(len(selected) == 1 and selected[0].get('package') in packages, 'MODEL_CATALOG')
    model = selected[0]
    variants = model.get('variants', [])
    check(isinstance(variants, list) and len(variants) <= 1000 and all(isinstance(v, dict) for v in variants), 'VARIANT')
    if ref.get('variant') not in (None, 'default'):
        check(sum(v.get('id') == ref['variant'] for v in variants) == 1, 'VARIANT')
    for overlay in [model, *variants]:
        if provider_id == 'anthropic':
            check(overlay.get('modelID', ref['id']) == ref['id'] and not (isinstance(overlay.get('body'), dict) and 'model' in overlay['body']), 'MODEL_OVERLAY')
        check(overlay.get('package', provider['package']) in packages, 'MODEL_OVERLAY')
        options = {} if overlay.get('settings') is None else overlay['settings']
        extra_headers = {} if overlay.get('headers') is None else overlay['headers']
        check(isinstance(options, dict) and isinstance(extra_headers, dict) and not any(k in options for k in (('apiKey', 'authToken') if provider_id == 'anthropic' else ('apiKey',))) and
              not any(name.lower() in ('authorization', 'api-key', 'x-api-key') for name in extra_headers), 'MODEL_OVERLAY')
        if 'baseURL' in options:
            check_endpoint(options['baseURL'], provider_id, 'MODEL_OVERLAY')
    if provider_id == 'anthropic':
        final_models = payload(client, '/api/model')
        check(isinstance(final_models, list) and [m for m in final_models if isinstance(m, dict) and m.get('providerID') == provider_id and m.get('id') == ref['id']] == selected, 'MODEL_CATALOG')
    check(payload(client, provider_path) == provider, 'PROVIDER_SOURCE_CHANGED')
    check(payload(client, integration_path) == integration, 'INTEGRATION_SOURCE_CHANGED')
    return True


def main(argv=None):
    import argparse
    from .cli import BridgeError, Client, InstalledClient, load_config, admission
    parser = argparse.ArgumentParser(description="Read-only guarded OAuth route preflight")
    parser.add_argument("--config", required=True)
    parser.add_argument("--installed-cli", action="store_true", help="read-only preflight via installed CLI authentication; no adapter token")
    args = parser.parse_args(argv)
    try:
        if args.installed_cli:
            p = Path(args.config).expanduser().resolve()
            if not p.is_file() or p.stat().st_uid != os.getuid() or p.stat().st_mode & 0o077:
                raise AttestationError("private configuration unavailable")
            config = json.loads(p.read_text())
            server = urlsplit(config["server"])
            check(server.scheme == "http" and server.hostname in ("127.0.0.1", "localhost", "::1") and
                  server.path in ("", "/") and not server.username and not server.password and
                  not server.query and not server.fragment)
            check(config.get("model", {}).get("providerID") in PROVIDER_PACKAGES and config["model"].get("id"))
            client = InstalledServiceReadOnlyClient(config)
        else:
            config, token, _, _ = load_config(args.config)
            config["_private_path"] = str(Path(args.config).expanduser().resolve())
            client = InstalledClient(config) if config.get("transport") == "installed-client" else Client(config, token)
        admission(config, client)
        print(json.dumps({"guarded_route": "preflight_passed", "inference": "not_attempted"}))
        return 0
    except (BridgeError, AttestationError, OSError, ValueError, KeyError):
        print(json.dumps({"error": "guarded OAuth route unverified; execution disabled"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
