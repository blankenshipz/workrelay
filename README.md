# Workrelay

**Give your personal assistant the steering wheel for the work already happening on your computer.** Your assistant stays your point of contact: share a goal, let it delegate bounded work to your existing local OpenCode owner, then come back to its conversation for an update, a question, or the result. Workrelay is the authenticated control-and-events bridge between the assistant and OpenCode—not another assistant, hosted agent, remote terminal, or read-only dashboard.

For example, ask your assistant to inspect a small issue in an isolated project, make one focused change under the existing OpenCode permissions, and report the changed file and check result. If OpenCode pauses for a native permission decision, the work waits for you; a message from the assistant does not approve it. Your computer, OpenCode service, Workrelay gateway, and HTTPS route must remain available while work is running.

OpenAI describes Dots as ongoing assistants that carry goals and follow up across conversations, and documents connected apps through Plugins. Its developer docs describe authenticated MCP tools and MCP Events, including Dot use. Those docs establish the client/protocol surface—not successful Workrelay acceptance on every account or client path: [Introducing Dots](https://openai.com/index/introducing-dots/), [Dot setup and controls](https://help.openai.com/en/articles/20001530-getting-started-with-your-dot), [MCP servers](https://developers.openai.com/plugins/concepts/mcp-server), [MCP Events](https://developers.openai.com/plugins/build/mcp-events), and [OAuth authentication](https://developers.openai.com/plugins/build/auth).

## From goal to useful outcome

1. **Connect your assistant once.** Set up an authenticated remote MCP connection to Workrelay. OpenCode remains loopback-only; a user-controlled HTTPS route reaches the Workrelay gateway, not OpenCode. For managed-server access, enable the private capability bound to the exact ChatGPT principal and one local server.
2. **Give it a goal.** Describe the outcome and boundaries in the assistant conversation—for example, “In my isolated demo project, make one small documentation improvement, use only the existing project permissions, and tell me which file changed and what check you ran.”
3. **Let it supervise local work.** Workrelay passes authorized requests to an existing OpenCode owner. Ownership, the eligible current model route, included-OAuth quota and native permissions stay in force; a consequential permission wait remains for you to decide in OpenCode/OpenChamber.
4. **Return to the same conversation.** The assistant can read the visible result, follow up on your direction, and report what happened. Runtime `succeeded` or `idle` is not proof that the requested outcome is correct. Events can notify the assistant of observed state, but subscriptions expire and missed history is not replayed.

**Ready to connect your assistant? Start with the [quick setup](#quick-start).**

In one user-reported remote session, Dot discovered/read work, created it, sent a follow-up, steered/resumed the same work, returned to inspect it, received a completion notification (HTTP 200, one delivered and zero queued), and unsubscribed successfully. A reconnect/read also reportedly succeeded. These reports support that bounded journey—not broad model/agent visibility, ChatGPT-originated needs-input, active cancellation, or complete event acceptance.

## Quick start

### Prerequisites

- A computer that remains on and reachable while work runs; authenticated OpenCode v2 on loopback. Never expose OpenCode or disable its authentication.
- Python 3.10+, Node.js 22.11+, and the configured local `codex-quota --check` entitlement/guard path. Task inference uses the existing included ChatGPT/Codex subscription allowance through its OAuth route; unavailable quota or unsupported/ambiguous model routes fail closed. No API-key, paid-credit, or provider fallback.
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
  "agent": "harness-router",
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

This is a template, not a ready-to-run config: replace each placeholder with a path or value verified from this installation. The workspace and state directory must already exist; `server` must be an uncredentialed loopback HTTP origin. `authorized_owner` is only a local routing label, not human authentication. `agent` must be an enabled `harness-router` or scoped builder (`quick-builder` or `builder`). Use `harness-router` with its discovered model/variant to let the installed harness delegate, pace its enabled subscription pools, and decide when review is useful. Workrelay attests the OpenAI entry route; delegated requests remain subject to the harness's own provider, permission and financial checks. Native builders remain an explicit configuration option for installations without the harness. Changing the creation default does not retarget existing conversations. Old create retries retain their argument/model identity and may report an argument conflict after a default change; inspect the original receipt and continue its existing session instead of creating a replacement. Get the model ID from the authenticated native model catalog; do not invent an ID or substitute a provider. Locate the actual active `subscription.guard` entry in the installed service, review and trust all three guard files, then compute their individual SHA-256 values with `shasum -a 256`; the files are the entry, its sibling `../subscription-guard.mjs`, and the project-root `config/guard-validation.mjs`. Store those exact digests in the matching fields—never use sample or stale pins. The attestor checks that the guard is active and those installed files match; it does not read credentials or guarantee billing behavior.

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
- OAuth access tokens expire after 300 seconds; refresh authorization has a fixed maximum 14-day lifetime and rotates strictly. A lost refresh response can make a retry return `invalid_grant` and revoke the refresh family; transparent retry/grace is not implemented. Reconnect through the same client/browser and fresh consent when required—do not automatically replay the old refresh token or remove/re-add the client as the default fix. The reviewed OAuth change is deployed and the isolated renewal gate passed. A user-reported Dot reconnect/read succeeded, but that does not establish general ChatGPT UI renewal reliability; see [OAuth recovery details](docs/mcp-local.md#oauth-expiry-rotation-and-reconnect).
- Do not place secrets in prompts, command arguments, logs, or Git. Do not loosen the existing subscription guard or infer task completion from idle/succeeded status. Revoke managed access using its private capability/revocation control; disabling a tunnel is not a substitute for revoking OAuth authority.

## Evidence and further reading

The user-reported Dot journey covered discovery/read/create/message/follow-up/steer/resume/return, a completion notification delivered with HTTP 200 (one delivered, zero queued), and successful unsubscribe cleanup; a reconnect/read also reportedly succeeded. This is evidence for that bounded journey, not every client or model/agent visibility. ChatGPT-originated needs-input and active cancellation, and comprehensive remote event acceptance beyond the reported completion callback remain unverified. Controlled local HTTPS/native-transition checks are separate evidence, not proof of all Dot/mobile behavior. See the [reviewed checkpoint notes](CHANGELOG.md), [full setup and acceptance boundaries](docs/mcp-local.md), and [public HTTPS probe checklist](docs/public-proxy-probe.md).

For local development, `npm test` runs the Node suite and `PYTHONPATH=src python3 -m unittest discover -s tests -v` runs the Python adapter suite. These are local checks, not external-client or phone acceptance. Contributions should describe the user journey and the exact evidence level; never include private deployment details or credentials.
