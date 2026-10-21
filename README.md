# Workrelay

**Keep your local OpenCode work moving while you’re away from your desk.** Send a bounded task from a remote MCP client such as ChatGPT/Dot to the OpenCode service already running on your computer; check progress or return to the conversation later. Workrelay is the small authenticated bridge between them—not a hosted coding agent and not a public OpenCode server.

Your computer and its OpenCode service must stay awake and reachable. Work continues under the existing session owner, model, native permissions, and quota/financial guards. A native permission request can pause work until you decide in OpenCode or OpenChamber; remote messages are not approvals.

## The short journey

1. **Set up once.** Keep authenticated OpenCode on loopback. Install Workrelay locally, configure its private MCP/OAuth state, and route your chosen public HTTPS hostname to the Workrelay gateway only. Never tunnel OpenCode. The [setup guide](docs/mcp-local.md) covers issuer choices, private files, reverse proxies, and exact bindings.
2. **Connect your remote client.** Add the HTTPS MCP endpoint ending in `/mcp` using its OAuth flow. For managed-server access, the operator separately enables the private capability for the exact ChatGPT client/principal and one bound OpenCode server. Other clients keep ordinary scoped access.
3. **Send one useful task.** For ordinary workspace-scoped work, call `workrelay_profile`, then `workrelay_start({key, text})` with a stable task key and a small request. Follow with `workrelay_status({key})` and `workrelay_result({key})`; use `workrelay_respond({key, feedback_key, text})` for a conversational follow-up. For the explicitly authorized managed server, discover and read first, then message the existing owner or create an idle session in a selected native project. See [managed-server tools and boundaries](docs/mcp-local.md#explicit-managed-server-supervisor).
4. **Verify, then return.** Read the visible result and check native waits. A successful turn or `idle` state is not proof your requested work is correct. If you enable MCP Events, verify the receiver actually got the signed callback and check its subscription status/expiry. Reconnect later and read current state; for an uncertain write, inspect/reconcile with the original operation ID and identical arguments—never change arguments or use a new ID until no effect is established.

## Who can use it today

Workrelay targets remote MCP clients that support authenticated Streamable HTTP and the required OAuth flow; ChatGPT/Dot is the primary target. In one user-reported remote session, the client discovered/read work, created it, sent follow-up, steered/resumed the same work, returned to inspect it, received a completion notification, and unsubscribed. This is bounded user-reported evidence—not a fresh independent acceptance of every client, model/agent visibility, native needs-input, or active cancellation. **Meta Muse is not implemented or verified**; treat it as a possible future client, not a supported integration.

## One-time setup

### Prerequisites

- A computer that remains on and reachable while work runs; authenticated OpenCode v2 on loopback. Never expose OpenCode or disable its authentication.
- Python 3.10+, Node.js 22.11+, and the configured local `codex-quota --check` entitlement/guard path. Inference uses the included ChatGPT OAuth route only; unavailable quota or unsupported/ambiguous model routes fail closed. No API-key, paid-credit, or provider fallback.
- A client with remote MCP/OAuth support. Events additionally require a real HTTPS callback receiver the client/operator can securely configure. Tool visibility alone does not establish write or event support.

### Install and connect

From a checkout, install the Python adapter and pinned Node dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-deps -e .
npm ci
```

#### Create the private bridge config

Workrelay needs a private **bridge config** before the MCP gateway can start. It is separate from the gateway's own private config described in the [installation guide](docs/mcp-local.md). Create an existing isolated workspace, an owner-only state directory, and an owner-only config file outside the checkout (config mode `0600`; state directory mode `0700`). Use the installed OpenCode loopback origin, the actual installed Node executable and `@opencode/client` service module, and the existing owner-only OpenCode `service.json` registration. Do not copy credentials from that registration or put token values in this config; the `installed-client` transport reads the existing registration through the supported client.

The required scoped-work fields are:

```json
{
  "server": "http://127.0.0.1:<OPENCODE_PORT>",
  "transport": "installed-client",
  "node_executable": "<absolute path to installed node>",
  "client_service_module": "<absolute path to @opencode/client/dist/promise/service.js>",
  "service_registration": "<absolute path to existing owner-only service.json>",
  "directory": "<absolute path to existing isolated workspace>",
  "state_dir": "<absolute path to owner-only Workrelay state directory>",
  "authorized_owner": "remote-work",
  "agent": "quick-builder",
  "model": {"providerID": "openai", "id": "<exact eligible model id from the native catalog>"},
  "quota_command": "<absolute path to installed codex-quota executable>",
  "guard_entry": "<absolute path to active subscription.guard index.mjs>",
  "guard_file_hashes": {
    "entry": "<64-character sha256 of guard_entry>",
    "implementation": "<64-character sha256 of sibling ../subscription-guard.mjs>",
    "financial": "<64-character sha256 of OpenCode project-root config/guard-validation.mjs>"
  }
}
```

This is a template, not a ready-to-run config: replace each placeholder with a path or value verified from this installation. The workspace and state directory must already exist; `server` must be an uncredentialed loopback HTTP origin. `authorized_owner` is only a local routing label, not human authentication. `agent` must be an enabled scoped builder (`quick-builder` or `builder`). Get the model ID from the authenticated native model catalog; do not invent an ID or substitute a provider. Locate the actual active `subscription.guard` entry in the installed service, review and trust all three guard files, then compute their individual SHA-256 values with `shasum -a 256`; the files are the entry, its sibling `../subscription-guard.mjs`, and the project-root `config/guard-validation.mjs`. Store those exact digests in the matching fields—never use sample or stale pins. The attestor checks that the guard is active and those installed files match; it does not read credentials or guarantee billing behavior.

After installing the Python adapter, run its read-only check with the config you just created:

```sh
workrelay-attest --config /absolute/path/to/private-bridge.json
```

`{"guarded_route":"preflight_passed","inference":"not_attempted"}` means only that this guarded route preflight passed; it does not run a task. If it fails, stop and correct the referenced setup from trusted local sources—do not weaken the guard or swap in a token/API key. This command and its exact `--config` flag are defined by the [`workrelay-attest` CLI](pyproject.toml).

Complete private issuer, gateway, and operator-controlled HTTPS/tunnel setup using the [MCP installation guide](docs/mcp-local.md); its example hostnames and configuration paths are placeholders. That guide's gateway config must point `bridge_config` at this private bridge config. Keep configuration, credentials, issuer state, ledgers, and backups private. The gateway is separate from OpenCode and should listen on loopback; the reverse proxy must preserve the configured host and route only to Workrelay. Then start the gateway from the repository root with its separate private gateway config:

```sh
node src/workrelay/mcp.mjs /absolute/path/to/private-mcp.json
```

Connect the client to `https://<your-configured-host>/mcp` through OAuth. Use only the approved `workrelay:tasks` scope and, for the pinned ChatGPT OIDC flow, its authorized `openid` addition. The private, default-off `issuer_preapprove_chatgpt` option skips only redundant consent after login; it does not bypass PKCE, CSRF, Origin, redirect/resource checks, or revocation.

Before enabling server-wide access, follow [managed-server setup](docs/mcp-local.md#explicit-managed-server-supervisor). It binds one authenticated principal/client to one canonical local server. Existing-session inference is admitted only when the session's current native model-catalog resolution and actual integration resolve to the guarded OpenAI OAuth route. Newly created sessions use the configured creation-model default. In both cases, credentials, quota, guard, identity, and native permissions remain authoritative.

## Everyday supervision

For an initial no-file check, use the ordinary workspace-scoped tools against a fresh, empty isolated workspace from the config. This request asks for text only—no file reads/writes, commands, or automatic approvals:

```text
workrelay_start({key: "first-check-001", text: "Do not read, create, or change files, and do not run commands. Reply with one sentence confirming this is a no-file supervised check and include the exact phrase: Workrelay supervised check complete."})
workrelay_status({key: "first-check-001"})
workrelay_result({key: "first-check-001"})
```

Use a fresh stable key if `first-check-001` has already been used; never change the request while reusing an existing key. The expected visible assistant response includes `Workrelay supervised check complete.` Confirm the empty workspace remains unchanged locally. If any file/command permission prompt appears, reject that exact request in OpenCode/OpenChamber—do not enable automatic approval. A successful turn or `idle` alone is not proof of the requested result.

For ordinary scoped work, keep a stable task key across status/result/follow-up calls. A task accepted into the inbox may still be queued; it is not necessarily running. `workrelay_cancel` addresses only the owned root and is not rollback.

For the opted-in managed server, start with `workrelay_server_capabilities({})` and `workrelay_server_discover({})`; read a selected session with `workrelay_server_read({session_id, include_messages:true})`. Use `workrelay_server_projects` to select a native project for an idle session, or `workrelay_server_message`/`workrelay_server_steer` to continue its existing owner. Keep each `operation_id` stable when inspecting an uncertain attempt with `workrelay_server_operation_status`. `workrelay_server_waits` is read-only: make actual permission decisions in the native OpenCode/OpenChamber UI. Messages and resume do not approve prompts or transfer ownership.

Managed Events use native `events/list`, `events/subscribe`, and `events/unsubscribe`; `workrelay_event_capabilities` describes receiver prerequisites, while subscription status exposes its expiry/renewal point. Subscriptions are leases, not permanent monitors: renew before expiry. Live SSE/state reconciliation is not historical replay and can miss intermediate transitions. An HTTP acknowledgement or `session.completed` event reports observed execution, not that you accepted or verified the requested result. Unsubscribe stops monitoring, not work or the Workrelay service. Poll/read current state if Events are unavailable, but do not count polling as Events acceptance.

## Stay safe and recover

- Keep the computer, OpenCode, Workrelay gateway, and chosen HTTPS route available for remote work; sleep, shutdown, tunnel loss, expired credentials, or subscription expiry can interrupt visibility or delivery. Workrelay does not promise always-on hosting.
- If a native permission wait appears, review that exact request in OpenCode/OpenChamber, then read waits again. There is no remote permission-reply tool.
- Interrupt targets only the named session, does not cancel descendants, remove queued text, or roll back edits. `idle_noop` is not proof an active task was stopped.
- OAuth access tokens expire after 300 seconds; refresh authorization has a fixed maximum 14-day lifetime and rotates strictly. A lost refresh response can make a retry return `invalid_grant` and revoke the refresh family; transparent retry/grace is not implemented. Reconnect through the same client/browser and fresh consent when required—do not automatically replay the old refresh token or remove/re-add the client as the default fix. The isolated renewal gate passed, but production deployment and actual ChatGPT UI behavior remain unverified; see [OAuth recovery details](docs/mcp-local.md#oauth-expiry-rotation-and-reconnect).
- Do not place secrets in prompts, command arguments, logs, or Git. Do not loosen the existing subscription guard or infer task completion from idle/succeeded status. Revoke managed access using its private capability/revocation control; disabling a tunnel is not a substitute for revoking OAuth authority.

## Evidence and further reading

The reported remote completion flow is distinct from controlled HTTPS receiver/native-transition checks and local protocol tests. ChatGPT-originated needs-input and active cancellation, broad model/agent visibility, and the complete installed remote Events journey remain unverified. A controlled receiver test, local test, or successful OAuth handshake is not proof of a real Dot/mobile round trip. See the [reviewed checkpoint notes](CHANGELOG.md), [full setup and acceptance boundaries](docs/mcp-local.md), and [public HTTPS probe checklist](docs/public-proxy-probe.md).

For local development, `npm test` runs the Node suite and `PYTHONPATH=src python3 -m unittest discover -s tests -v` runs the Python adapter suite. These are local checks, not external-client or phone acceptance. Contributions should describe the user journey and the exact evidence level; never include private deployment details or credentials.
