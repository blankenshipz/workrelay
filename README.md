# Workrelay

**Give your personal assistant the steering wheel for the work already happening on your computer.** Your assistant stays your point of contact: share a goal, let it delegate bounded work to your existing local OpenCode owner, then come back to its conversation for an update, a question, or the result. Workrelay is the authenticated control-and-events bridge between the assistant and OpenCode—not another assistant, hosted agent, remote terminal, or read-only dashboard.

For example, ask your assistant to inspect a small issue in an isolated project, make one focused change under the existing OpenCode permissions, and report the changed file and check result. If OpenCode pauses for a native permission decision, the work waits for you; a message from the assistant does not approve it. Your computer, OpenCode service, Workrelay gateway, and HTTPS route must remain available while work is running.

## Agent quickstart (any platform)

1. **Connect** your MCP client to the gateway (`https://<host>/mcp`, OAuth) or a stdio proxy; tools come from the gateway.
2. **Set your listener once**: `workrelay_server_notify {"action":"check","scope":"agent","agent":"<YourName>"}`; if none, `{"action":"set","scope":"agent","agent":"<YourName>","url":"https://<public-443-webhook>"}` then `{"action":"test",...}`.
3. **Start work in one call**: `workrelay_server_start {"project":"<name or project_id>","agent":"<YourName>","text":"<task>"}` (add `"reuse":true` to continue your latest session; it rolls over above ~150k tokens). Retries are safe: it never starts twice.
4. **Read the reply**: `session_id`, `status`, and `queued_behind` (`"ask"`: waiting on a permission ask, with age and summary; `"busy"`: behind the current run; `null`: free).
5. **End your turn.** Do not poll; idle is not done.
6. **Act on events** POSTed to your listener: `permission_asked` (tell your human), `finished`/`failed` (call `workrelay_server_read` with `include_messages:true`), `stalled` (read, then `workrelay_server_steer` or `interrupt`).
7. **Follow up** with `workrelay_server_message` (queue) or `workrelay_server_steer` (running owner); both return `queued_behind`.
8. **Permission asks are answered only by a human operator** on the Workrelay operator page (`/operator/permissions`) or a native OpenCode UI. No agent, message or MCP tool can approve them; do not resend while `queued_behind` is `"ask"`.
9. **Native questions** (not permissions) can be answered with `workrelay_server_waits` then `workrelay_server_question_reply`, using your human's explicit choice.
10. Details: [listen for events](#progress-notifications-listen-for-events), [docs/mcp-local.md](docs/mcp-local.md).

## Progress notifications (listen for events)

**Why.** Delegated work can take minutes or hours and may stop for a human permission decision. Instead of polling, register a listener once and Workrelay POSTs one compact event when a permission ask appears, a run finishes or fails, a child fails, or a run stalls. Any platform works: anything that accepts an HTTPS POST (Grok Bot routine webhook, Slack, ntfy, an agent HTTP hook, your own endpoint).

**New agents do this by default.** The server instructions and the `workrelay_server_create`/`message`/`resume`/`notify` tool descriptions tell every agent, on first use, to run `workrelay_server_notify {action: "check", scope: "agent", agent: "<name>"}` and, if no listener is shown, to register its own.

1. **Create a listener**: a public HTTPS URL on port 443, for example a Grok Bot routine with trigger type *webhook*, a Slack incoming webhook, or `https://ntfy.sh/<long-random-topic>`.
2. **Register it under your agent name**: `workrelay_server_notify {"action": "set", "scope": "agent", "agent": "Harny", "url": "https://…", "header_name": "X-Hook-Token", "header_value": "…"}` (or `hmac_secret: "whsec_…"` for Standard Webhooks signing, `format: "slack"|"text"` for Slack/ntfy). Operators can do the same on the host with `node src/workrelay/notify-register.mjs --agent Harny`, so the secret never enters a chat.
3. **Test it**: `workrelay_server_notify {"action": "test", "scope": "agent", "agent": "Harny"}` sends a signed `workrelay.test` event; the response shows `ok` and the receiver's HTTP status.

Then pass the same `agent` on every `workrelay_server_create`/`message`/`resume` (it is remembered per session) and end your turn instead of polling; each event names the Workrelay tool to call next.

- **Event schema** (`schema_version: 1`), signature verification and what to do on each event: [docs/mcp-local.md](docs/mcp-local.md#listen-for-progress-events-any-platform).
- **Platform recipes**: Grok Bot (routine webhook, `json`, secret header), Slack (`slack`), ntfy (`text`), generic HTTPS (`json` + HMAC), Claude Code/Cursor (via a small public relay or ntfy and a hook): same link.
- **Several agents on one connection** (for example every Grok Bot agent shares OAuth client `grokbot-mcp`): each agent registers with `scope: "agent"` under its own stable name (`A-Z a-z 0-9 . _ -`, max 64) and always passes it, so events reach the right agent. `scope: "client"` is a connection-wide fallback for a single agent; operators can add a project default (`session_notify.default_targets`).
- **Stdio connectors / tool list not updating?** Tools and fields come from the gateway. A long-lived stdio proxy must forward `notifications/tools/list_changed` (or be restarted) after a gateway upgrade, or the client keeps its old cached tool list without `agent`/`notify`.

## Recover a paused conversation without duplicating work

Use `workrelay_server_waits` to distinguish a native question from a permission
request. Ordinary queued chat text cannot answer either one. For a question,
collect the user's explicit choice, then use `workrelay_server_question_reply`
with the exact session, form and stable operation IDs. An explicitly requested
question dismissal uses `workrelay_server_question_cancel`. These operations can
let the existing session continue; they never grant native tool permissions.
Permission requests still require the OpenCode/OpenChamber approval UI.

Keep `workrelay_server_operation_status` for historical receipts, including when
execution admission is unavailable. Use `workrelay_server_reconcile` for authorized
recovery: it reads native message/inbox and waits, then persists a verified local
receipt without resending work. Reconcile reports a bounded native observation:
`queued` includes a native queue timestamp and age only when that matching inbox
item supplies a valid non-future `time.created`; `materialized` may include its
native timestamp. Missing, malformed, or future clocks remain unavailable.
Receipt-only status reports `native_observation:not_run`; it cannot know queue age.
Read-only monitors use operation status and waits. Queued, consumed, executing and
idle are different observations; none proves the user's task was accepted as
complete. A failed historical idle outcome is not a failure of a currently running
execution. Unknown or uncertain delivery is never permission to replay a message or
create a replacement worker.

## Select the current project before creating a conversation

Native project inventory can retain historical IDs for the same directory.
For duplicate roots, discovery points to `workrelay_server_creation_target` with
an opaque `project_id`. The read-only helper returns the project OpenCode currently
resolves; it exposes no filesystem path and starts no work. Use its returned
handle with a new operation ID after a denied attempt. Creation checks that exact
native identity before POST; it never silently switches projects or replays a
previous denial.

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

This is a template, not a ready-to-run config: replace each placeholder with a path or value verified from this installation. The workspace and state directory must already exist; `server` must be an uncredentialed loopback HTTP origin. `authorized_owner` is only a local routing label, not human authentication. `agent` must be an enabled `harness-router` or scoped builder (`quick-builder` or `builder`). Use `harness-router` with its discovered model/variant to let the installed harness delegate, pace its enabled subscription pools, and decide when review is useful. Workrelay attests the selected supported OAuth entry route (OpenAI or Anthropic); delegated requests remain subject to the harness's own provider, permission and financial checks. Native builders remain an explicit configuration option for installations without the harness. Changing the creation default does not retarget existing conversations. Old create retries retain their argument/model identity and may report an argument conflict after a default change; inspect the original receipt and continue its existing session instead of creating a replacement. Get the model ID from the authenticated native model catalog; do not invent an ID or substitute a provider. Locate the actual active `subscription.guard` entry in the installed service, review and trust all three guard files, then compute their individual SHA-256 values with `shasum -a 256`; the files are the entry, its sibling `../subscription-guard.mjs`, and the project-root `config/guard-validation.mjs`. Store those exact digests in the matching fields—never use sample or stale pins. The attestor checks that the guard is active and those installed files match; it does not read credentials or guarantee billing behavior. OpenAI may retain several saved logins after re-authentication. Attestation follows the native selected first connection and requires that connection to be stored OAuth; it never searches later entries for an acceptable alternative. Historical connections do not by themselves block admission, and a connection change during the check invalidates it.

Existing-session message, steer and resume operations preserve the session's exact
native provider, model and effort. OpenAI and Anthropic are supported; other
providers remain denied. The same rule applies to question actions that can
resume inference. Discovery/reads are not proof of write admission.

OpenAI retains its Codex quota command and subscription financial guard. Claude
admission does not consume or check the Codex pool: it requires the active native
Claude OAuth route and pinned guard, which enforces Claude's configured policy at
every actual model request. A Claude-only configuration may omit `quota_command`.
Preflight does not resolve tokens, prove a paid-credit balance, or certify billing.

### Managed creation model

`workrelay_server_create` takes no model argument. By default
(`"managed_create_model": "agent_default"`) a new managed session is stamped with
the target `agent`'s own configured native model, read from OpenCode's
`GET /api/agent/<agent>` at the creation location (for example
`agents.harness-router.model: "anthropic/claude-opus-5-5#high"` in
`opencode.json`). The profile `model` is used only when that agent defines no
model. Set `"managed_create_model": "profile"` to explicitly force the profile
`model` for every new managed session instead. An unknown value, or an agent
definition that is unavailable (for example while OpenCode reloads its config)
or does not match the configured agent, denies the create; it never silently
falls back to the profile model. The CLI resolves the model after reserving the
operation, and the guarded transport independently re-resolves it immediately
before the native POST. A changed agent model in between denies the POST.

The resolved model must pass the same create route checks as the profile model:
an exact `{providerID, id, variant?}` reference for a supported provider
(OpenAI or Anthropic). An Anthropic-resolved create also requires the complete
`provider_guard_file_hashes.anthropic` pin set below, and the pinned guard files
must currently hash to those pins. Creation starts no inference. Every later
message, steer or resume still runs full admission/attestation against that
session's exact model. The legacy `start` command and existing sessions are
unaffected.

For Anthropic writes, additionally review and pin these installed code files under
`provider_guard_file_hashes.anthropic` (paths are relative to the OpenCode root
inferred from the existing guard entry):

| Key | File |
| --- | --- |
| `subscription` | `plugins/v2/anthropic-subscription.mjs` |
| `financial_policy` | `plugins/v2/anthropic-financial-policy.mjs` |
| `quota_cache` | `plugins/v2/quota-cache.mjs` |
| `paths` | `plugins/v2/paths.mjs` |
| `auth_entry` | `plugins/v2/claude-auth/index.mjs` |

Each value is the reviewed file's SHA-256, not a sample digest. Missing, incomplete or changed
pins fail closed, including for managed create. The active `griffinmartin.claude-auth` plugin must use that local
entry and expose the `claude-code` OAuth method. Native credential resolution and
the credential's subscription marker remain the runtime guard's responsibility;
Workrelay never reads them. Provider metadata is fetched only for the exact
session's native provider/location and revalidated against model changes. API-key,
auth-token, endpoint and model-body overrides remain prohibited.

A typed guard failure without a verified durable receipt exposes a finite
`denial_code` and `denial_stage: receipt_unverified`. It retains
`effect: not_established` and `replay_permitted: false`; it does not invent a
receipt, timestamp or delivery conclusion. Inspect the original operation and
correct the underlying route; do not replay a failed write merely because lookup
finds no receipt.

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

Before enabling server-wide access, follow [managed-server setup](docs/mcp-local.md#explicit-managed-server-supervisor). It binds one authenticated principal/client to one canonical local server. Existing-session inference is admitted only when the session's current native model-catalog resolution and actual integration resolve to the guarded OpenAI OAuth route. Newly created sessions use the target agent's configured model (see [Managed creation model](#managed-creation-model)). In both cases, credentials, quota, guard, identity, and native permissions remain authoritative.

## Everyday supervision

For an initial no-file check, use the ordinary workspace-scoped tools against a fresh, empty isolated workspace from the config. This request asks for text only—no file reads/writes, commands, or automatic approvals:

```text
workrelay_start({key: "first-check-001", text: "Do not read, create, or change files, and do not run commands. Reply with one sentence confirming this is a no-file supervised check and include the exact phrase: Workrelay supervised check complete."})
workrelay_status({key: "first-check-001"})
workrelay_result({key: "first-check-001"})
```

Use a fresh stable key if `first-check-001` has already been used; never change the request while reusing an existing key. The expected visible assistant response includes `Workrelay supervised check complete.` Confirm the empty workspace remains unchanged locally. If any file/command permission prompt appears, reject that exact request in OpenCode/OpenChamber—do not enable automatic approval. A successful turn or `idle` alone is not proof of the requested result.

For ordinary scoped work, keep a stable task key across status/result/follow-up calls. A task accepted into the inbox may still be queued; it is not necessarily running. `workrelay_cancel` addresses only the owned root and is not rollback.

For the opted-in managed server, start with `workrelay_server_capabilities({})` and `workrelay_server_discover({})`; read a selected session with `workrelay_server_read({session_id, include_messages:true})`. That opt-in read also returns a safe, historical tool-activity projection from the fetched message page: tool IDs, closed-set names, statuses, timestamps, exit codes and timeout flags only. It never includes command/input/output or provider data. `activity.scope: "this_page_only"` is historical, so a running status does not establish current activity and a completed tool does not verify task progress. Use `workrelay_server_projects` to select a native project for an idle session, or `workrelay_server_message`/`workrelay_server_steer` to continue its existing owner. Keep each `operation_id` stable when inspecting an uncertain attempt with `workrelay_server_operation_status`. `workrelay_server_waits` is read-only: make actual permission decisions in the native OpenCode/OpenChamber UI. Messages and resume do not approve prompts or transfer ownership.

Managed Events use native `events/list`, `events/subscribe`, and `events/unsubscribe`; `workrelay_event_capabilities` describes receiver prerequisites, while subscription status exposes its expiry/renewal point. Subscriptions are leases, not permanent monitors: renew before expiry. Live SSE/state reconciliation is not historical replay and can miss intermediate transitions. An HTTP acknowledgement or `session.completed` event reports observed execution, not that you accepted or verified the requested result. Unsubscribe stops monitoring, not work or the Workrelay service. Poll/read current state if Events are unavailable, but do not count polling as Events acceptance.

## Progress notifications: details

Workrelay can tell the agent (or person) that delegated work when that work needs attention, so the agent does not have to poll. This works on any agent platform: anything that accepts an HTTPS POST can receive the events. Examples are a Grok Bot routine webhook, a Slack incoming webhook, ntfy, Claude/Cursor/other agents' HTTP hooks, or your own endpoint.

- **What is sent.** One compact event when a live permission ask appears, a run finishes or fails, a child fails, or a run stalls. There are no per-step events.
- **Event format.** Every event is JSON with a stable `type` (for example `workrelay.session.finished`), `event_id`, `session_id`, `server_id`, `project_id`, `directory`, a one-line `summary`, and a `read` hint naming the Workrelay tool to call next.
- **Other formats.** `format: "slack"` sends `{text}`; `format: "text"` sends plain text for ntfy and generic receivers.
- **Register your own listener once.** Each agent calls `workrelay_server_notify` with `action: "set", scope: "agent", agent: "<its stable name>"` and its URL (or the operator runs `node src/workrelay/notify-register.mjs --agent <name>` on the Workrelay host, reading secrets only from env), then `action: "test", scope: "agent"` to receive a signed `workrelay.test` event. Every session that agent creates, messages or resumes with `agent: "<name>"` reports there from then on, even when several agents share one MCP connection. `scope: "client"` registers a connection-wide fallback.
- **Per-call targets and opt-out.** A `notify` argument on create/message/resume overrides any default; `notify: false` opts a session out.
- **Optional operator fallback.** `session_notify.default_targets`, matched by project directory glob and/or MCP OAuth client, with URL and secrets in a private `0600` secrets file or environment variables.
- **Signing.** Optional [Standard Webhooks](https://www.standardwebhooks.com) HMAC signing (`webhook-id`, `webhook-timestamp`, `webhook-signature`). An optional static secret header is also supported.
- **Checking.** `workrelay_server_notify` with `action: "check"` shows the effective target, redacted, and its source (`per_call`, `agent_default`, `client_default`, `gateway_default`). Secrets are never returned, logged or put in an event.
- **Security.** Delivery is public HTTPS only and SSRF-pinned: every DNS answer must be public, the connection is pinned to it, and redirects are never followed. Non-ask, non-completion events are rate limited. Permission asks and completion are never rate limited. Failures never affect tool calls or runs.

The 3-step setup (create a listener, register, test), the event schema, signature verification and per-platform notes for Grok Bot, Slack, ntfy, generic HTTPS and Claude Code/Cursor are in [docs/mcp-local.md](docs/mcp-local.md#listen-for-progress-events-any-platform).

## Stay safe and recover

- Keep the computer, OpenCode, Workrelay gateway, and chosen HTTPS route available for remote work; sleep, shutdown, tunnel loss, expired credentials, or subscription expiry can interrupt visibility or delivery. Workrelay does not promise always-on hosting.
- If a native permission wait appears, review that exact request in OpenCode/OpenChamber, then read waits again. There is no remote permission-reply tool.
- If `operator_approvals` is enabled, a human operator can also decide permission requests on the password-protected `/operator/permissions` page. When the public origin is not reachable from your browser, set `operator_approvals.local_listen: {"port": 49381}`. That opens a loopback-only listener which serves just that page. Tunnel to it with `ssh -N -L 49381:127.0.0.1:49381 box` and open `http://127.0.0.1:49381/operator/permissions`. See [operator approvals](docs/mcp-local.md). The same loopback listener serves a live activity view at `/operator/activity`: active sessions per project, recent tool calls and text, and approve/deny buttons for pending asks.
- With `session_notify` enabled, delegated sessions can send progress events to any webhook receiver. See [Progress notifications](#progress-notifications).
- Interrupt targets only the named session, does not cancel descendants, remove queued text, or roll back edits. `idle_noop` is not proof an active task was stopped.
- OAuth access tokens expire after 300 seconds; refresh authorization has a fixed maximum 14-day lifetime and rotates strictly. A lost refresh response can make a retry return `invalid_grant` and revoke the refresh family; transparent retry/grace is not implemented. Reconnect through the same client/browser and fresh consent when required—do not automatically replay the old refresh token or remove/re-add the client as the default fix. The reviewed OAuth change is deployed and the isolated renewal gate passed. A user-reported Dot reconnect/read succeeded, but that does not establish general ChatGPT UI renewal reliability; see [OAuth recovery details](docs/mcp-local.md#oauth-expiry-rotation-and-reconnect).
- Do not place secrets in prompts, command arguments, logs, or Git. Do not loosen the existing subscription guard or infer task completion from idle/succeeded status. Revoke managed access using its private capability/revocation control; disabling a tunnel is not a substitute for revoking OAuth authority.

## ChatGPT Dots and OpenAI clients

OpenAI describes Dots as ongoing assistants that carry goals and follow up across conversations, and documents connected apps through Plugins. Its developer docs describe authenticated MCP tools and MCP Events, including Dot use. Those docs establish the client/protocol surface—not successful Workrelay acceptance on every account or client path: [Introducing Dots](https://openai.com/index/introducing-dots/), [Dot setup and controls](https://help.openai.com/en/articles/20001530-getting-started-with-your-dot), [MCP servers](https://developers.openai.com/plugins/concepts/mcp-server), [MCP Events](https://developers.openai.com/plugins/build/mcp-events), and [OAuth authentication](https://developers.openai.com/plugins/build/auth).

## Evidence and further reading

The user-reported Dot journey covered discovery/read/create/message/follow-up/steer/resume/return, a completion notification delivered with HTTP 200 (one delivered, zero queued), and successful unsubscribe cleanup; a reconnect/read also reportedly succeeded. This is evidence for that bounded journey, not every client or model/agent visibility. ChatGPT-originated needs-input and active cancellation, and comprehensive remote event acceptance beyond the reported completion callback remain unverified. Controlled local HTTPS/native-transition checks are separate evidence, not proof of all Dot/mobile behavior. See the [reviewed checkpoint notes](CHANGELOG.md), [full setup and acceptance boundaries](docs/mcp-local.md), and [public HTTPS probe checklist](docs/public-proxy-probe.md).

For local development, `npm test` runs the Node suite and `PYTHONPATH=src python3 -m unittest discover -s tests -v` runs the Python adapter suite. These are local checks, not external-client or phone acceptance. Contributions should describe the user journey and the exact evidence level; never include private deployment details or credentials.
