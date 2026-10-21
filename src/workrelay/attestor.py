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


class AttestationError(Exception):
    pass


class InstalledServiceReadOnlyClient:
    """Use the installed CLI's own service authentication; no token discovery.

    This mode is preflight-only and cannot submit prompts on behalf of the adapter.
    """
    PATHS = frozenset(("/api/plugin", "/api/integration/openai", "/api/provider/openai", "/api/model"))

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


def check(condition):
    if not condition:
        raise AttestationError("guarded OAuth route unverified")


def payload(client, path):
    response = client.request("GET", path)
    check(isinstance(response, dict) and isinstance(response.get("data"), (dict, list)))
    return response["data"]


def verify(config, client):
    """Check route metadata and pinned local guard files; never return raw metadata."""
    ref = config.get('model')
    check(isinstance(ref, dict) and set(ref) <= {'providerID', 'id', 'variant'} and
          ref.get('providerID') == 'openai' and isinstance(ref.get('id'), str) and
          0 < len(ref['id']) <= 200 and ref['id'].isprintable() and
          ('variant' not in ref or isinstance(ref['variant'], str) and
           0 < len(ref['variant']) <= 200 and ref['variant'].isprintable()))
    guard = payload(client, "/api/plugin")
    check(isinstance(guard, list) and all(isinstance(plugin, dict) for plugin in guard))
    matches = [plugin for plugin in guard if plugin.get("id") == "subscription.guard"]
    check(len(matches) == 1 and isinstance(matches[0].get("state"), dict) and
          matches[0]["state"].get("status") == "active")
    source = matches[0].get("source")
    check(isinstance(source, dict))
    check(source.get("type") == "local" and isinstance(source.get("path"), str))
    raw = source["path"]
    parsed = urlsplit(raw)
    check(parsed.scheme in ("", "file") and not parsed.netloc and not parsed.query and not parsed.fragment)
    entry = Path(unquote(parsed.path)).resolve()
    expected = Path(config["guard_entry"]).expanduser().resolve()
    check(entry == expected and entry.name == "index.mjs" and entry.parent.name == "subscription-guard")
    root = entry.parent.parent.parent.parent
    files = {"entry": entry, "implementation": entry.parent.parent / "subscription-guard.mjs",
             "financial": root / "config" / "guard-validation.mjs"}
    hashes = config["guard_file_hashes"]
    check(set(hashes) == set(files))
    for name, path in files.items():
        expected_hash = hashes[name]
        check(isinstance(expected_hash, str) and bool(re.fullmatch(r"[0-9a-f]{64}", expected_hash)))
        try:
            check(path.is_file() and path.stat().st_uid == os.getuid() and
                  hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash)
        except OSError:
            raise AttestationError("guarded OAuth route unverified") from None

    provider = payload(client, "/api/provider/openai")
    check(isinstance(provider, dict))
    # Native ModelResolver.load resolves credentials from
    # provider.integrationID ?? selected.providerID. Attesting another active
    # OAuth integration would not attest this request's actual credential source.
    check(provider.get('integrationID', 'openai') == 'openai')
    integration = payload(client, "/api/integration/openai")
    check(isinstance(integration, dict))
    connections = integration.get("connections")
    check(integration.get("id") == "openai" and isinstance(connections, list) and len(connections) == 1 and
          isinstance(connections[0], dict) and
          connections[0].get("type") == "credential" and connections[0].get("method") == "oauth")
    settings = provider.get("settings") or {}
    headers = provider.get("headers") or {}
    check(isinstance(settings, dict) and isinstance(headers, dict))
    check(provider.get("id") == "openai" and provider.get("package") in
          ("@opencode/ai/providers/openai", "@opencode/ai/providers/openai/responses") and
          "apiKey" not in settings and
          not any(name.lower() in ("authorization", "api-key", "x-api-key")
                  for name in headers))
    base = settings.get("baseURL")
    if base is not None:
        check(isinstance(base, str))
        u = urlsplit(base)
        check(u.scheme == "https" and u.netloc == "chatgpt.com" and
              (u.path == "/backend-api/codex" or u.path.startswith("/backend-api/codex/")) and
              not u.username and not u.password and not u.query and not u.fragment)
    models = payload(client, "/api/model")
    check(isinstance(models, list) and models and all(isinstance(m, dict) and
          m.get("providerID") == "openai" for m in models))
    selected = [m for m in models if m.get("id") == config["model"]["id"]]
    check(len(selected) == 1 and selected[0].get("package") in
          ("@opencode/ai/providers/openai", "@opencode/ai/providers/openai/responses"))
    model = selected[0]
    variants = model.get('variants', [])
    check(isinstance(variants, list) and len(variants) <= 1000 and all(isinstance(v, dict) for v in variants))
    # Native ModelResolver.withVariant treats only "default" as omitted. Every
    # other variant must exist exactly once; never invent an alias/effort level.
    if ref.get('variant') not in (None, 'default'):
        check(sum(v.get('id') == ref['variant'] for v in variants) == 1)
    for overlay in [model, *variants]:
        check(overlay.get('package', provider['package']) in
              ('@opencode/ai/providers/openai', '@opencode/ai/providers/openai/responses'))
        options, extra_headers = overlay.get('settings') or {}, overlay.get('headers') or {}
        check(isinstance(options, dict) and isinstance(extra_headers, dict) and 'apiKey' not in options and
              not any(name.lower() in ('authorization', 'api-key', 'x-api-key') for name in extra_headers))
        if 'baseURL' in options:
            endpoint = urlsplit(options['baseURL'])
            check(endpoint.scheme == 'https' and endpoint.netloc == 'chatgpt.com' and
                  (endpoint.path == '/backend-api/codex' or endpoint.path.startswith('/backend-api/codex/')) and
                  not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment)
    # No cached source attestation. A source/connection change during metadata
    # reads invalidates this preflight; native request authorization still wins.
    check(payload(client, '/api/provider/openai') == provider)
    check(payload(client, '/api/integration/openai') == integration)
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
            check(config.get("model", {}).get("providerID") == "openai" and config["model"].get("id"))
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
