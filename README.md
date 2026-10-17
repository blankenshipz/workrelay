# Workrelay

**Bring a remote agent to the OpenCode you already run—without turning OpenCode into a public service.** Workrelay is an experimental, model-free bridge: its local adapter and authenticated MCP gateway pass narrowly scoped work to an existing local OpenCode service, where that service's configured agents, provider access, and safeguards remain in control.

Workrelay is open source and early-stage. It is not a hosted relay, OpenAI Dot API, or Meta Muse integration. Dot/mobile connectivity and end-to-end remote event delivery have **not** been verified. The goal is to make safe, inspectable handoffs between agents and local development environments useful across more clients and execution setups, without pretending those integrations already exist.

## How it works

The usual remote task journey is:

```text
Remote MCP client
      │ authenticated HTTPS (experimental gateway)
      ▼
Workrelay on your computer ── scoped task ──► existing local OpenCode
      ▲                                          │
      └──── status / result / events ◄───────────┘
                    │
                    └─ human handles any real permission decision in OpenCode/OpenChamber
```

Connect to the configured MCP endpoint, inspect `workrelay_profile`, start a small authorized task with `workrelay_start`, and follow its status/result. You can send conversational follow-up with `workrelay_respond`; that is not permission approval. Handle actual permission requests in the OpenCode/OpenChamber UI. Stop using the connection or cancel the owned root with `workrelay_cancel`; reconnect and check the same task with its stable key. The separate local CLI adapter offers start/status/respond/cancel for local workflows. OpenCode remains private and its existing permissions and provider safeguards stay in force.

### Events are two related, distinct mechanisms

- **OpenCode's internal event stream** is the local service's own session/runtime event source. Workrelay consumes local service state to track the task; this stream is not a remote subscription or webhook.
- **MCP Events** are the gateway's client-facing protocol (`events/list`, `events/subscribe`, `events/unsubscribe`) for scoped task lifecycle notifications and, with explicit managed-server authorization, `session.completed`, `session.failed` and `session.needs_input`. Workrelay implements signed HTTPS webhook delivery for configured callbacks. Managed observation uses bounded current-state polling/reconciliation, not missed-history replay. Local protocol/controlled-transport tests do not establish an external ChatGPT callback receiver; direct read polling remains available.

Those tests do not verify a user-operated public tunnel, independently operated issuer, external callback receiver, or real Dot/mobile round trip. Treat remote connectivity and delivery through your own deployed network path as unverified until tested in that environment. See [the MCP boundary, setup, and verification limits](docs/mcp-local.md).

## Where the project is going—and how to help

Workrelay is model/provider-neutral at the bridge boundary: it routes work to the OpenCode installation you configure; it does not itself supply a model. Today, this repository's documented guarded task setup is tied to the existing included ChatGPT OAuth/Codex entitlement and does not switch providers or buy credits. Broader provider and execution ecosystems—including Anthropic/Claude and other cloud-hosted or local models—are a direction for future compatible deployments, **not a claim of current verified support**. Any provider's authentication, cost, quota, and safety rules remain the operator's responsibility and must be supported by the configured OpenCode environment.

We welcome contributors who want to improve the bridge, event interoperability, setup clarity, and safe client/supervisor integrations. Start with the implementation and docs in this repository, run the documented local checks, and open a focused pull request explaining the user journey and what you actually tested. Please distinguish local or synthetic evidence from a real external-client round trip; do not include credentials or private deployment details in issues or patches. We do not promise support for a particular supervisor or provider before its integration exists and is verified.

## Safety and setup

- Python 3.10+, OpenCode v2 with `/api/session`, `/api/session/{id}/prompt` and message endpoints, an authenticated **loopback-only** service, and the local `codex-quota --check` from the subscription harness. Never expose OpenCode on a public interface or disable its authentication. The MCP gateway is a distinct optional network boundary; it does not make OpenCode public.
- A bundled **supplemental** attestor checks sanitized metadata from the **same authenticated service**: one OAuth connection, official OpenAI provider and selected model, and an active local `subscription.guard` whose reviewed entry, implementation and financial-validation files match private pinned SHA-256 hashes. `codex-quota --check` must also pass. At *each inference request*, the installed subscription guard must independently verify the resolved ChatGPT OAuth method and account match, financial attestation, quota, and Codex destination. Public metadata and file hashes alone cannot prove that the account will not be billed or that loaded runtime code is immutable. Review and pin trusted installed sources at setup, verify service ownership and required-plugin policy, and do not remove that guard. No hand-written echo attestor, key login, purchased credits or fallback is acceptable.
- For normal installation, create a private directory (mode 700) **outside the repository** and a mode-600 `config.json` there. The checkout may also contain a separate `.bridge/` directory used only for isolated local development: it holds a private ledger, workspace and temporary config; `.gitignore` excludes it from Git, **not** from local disk or backups. Back it up deliberately before a migration and never stage or publish it. **Preferred installed-client transport** uses the installed `@opencode/client` package's `Service.discover` and `Service.headers` inside a local Node process: it reads the existing service registration internally and never prints, passes in argv or copies out the password. It does not discover Keychain credentials or start/replace services. The optional `private-token` transport requires an authorized mode-600 token-file reference through your normal credential workflow; never copy its value into the repository, Dot prompt, command arguments or logs.
- For ordinary scoped task creation, set the workspace to an **isolated** project directory. This default creates sessions only there and does not enumerate unrelated sessions. Its installed-client helper checks each method/route against the private ledger and verifies the live session owner/workspace; session creation rejects permission overrides. The separate, explicit managed-server supervisor opt-in below permits its pinned authenticated client to discover and supervise existing sessions across projects on only the bound server. Neither mode changes native permissions or grants arbitrary shell authority.
- `authorized_owner` is a scoped routing label, **not** proof of a human identity. Anyone who can invoke this CLI with the private config as that local OS user can supply the label. Restrict config, service registration, state directory and command-execution access to the trusted computer workflow. Pass task text as a properly quoted single CLI argument; never interpolate untrusted text into shell syntax. Do not put credentials in task/feedback text or process arguments.

```json
{
  "server": "http://127.0.0.1:PORT",
  "transport": "installed-client",
  "node_executable": "/absolute/path/to/node",
  "client_service_module": "/absolute/path/to/installed/node_modules/@opencode/client/dist/promise/service.js",
  "service_registration": "/absolute/path/to/existing/opencode/service.json",
  "directory": "/path/to/isolated/workspace",
  "state_dir": "/private/path/to/state",
  "authorized_owner": "dot-work",
  "agent": "quick-builder",
  "model": {"providerID": "openai", "id": "YOUR_OAUTH_MODEL_ID"},
  "quota_command": "/absolute/path/to/opencode-usage-harness/bin/codex-quota",
  "guard_entry": "/absolute/path/to/reviewed/plugins/v2/subscription-guard/index.mjs",
  "guard_file_hashes": {
    "entry": "64-character-reviewed-SHA256",
    "implementation": "64-character-reviewed-SHA256",
    "financial": "64-character-reviewed-SHA256"
  }
}
```

Install with `python3 -m pip install --no-deps -e .` in an isolated environment. Before changing an existing installation, back up its private configuration and ledger. Verify `opencode service status` and the server's own auth policy; this adapter fails on unavailable quota and never switches providers or purchases credits. Review and hash (using `shasum -a 256`) the `guard_entry` file, its sibling `../subscription-guard.mjs` (`implementation`), and the installed project-root `config/guard-validation.mjs` (`financial`). Store those three digests only in private config. Any update to these files must be re-reviewed and re-pinned. The attestor does not read credential values. `workrelay-attest --config /private/path/to/config.json` runs a read-only gate (no inference); it returns `preflight_passed`, not proof of a completed task or a provider billing guarantee. Explicitly select a model provisioned by existing included ChatGPT OAuth entitlement.

For a separate **read-only CLI preflight** (not task transport), a private config containing `server`, `installed_cli` (absolute executable path), `model`, `quota_command`, `guard_entry`, and `guard_file_hashes` can omit the service transport and workspace fields: run `workrelay-attest --installed-cli --config /private/path/to/preflight.json`. It permits only four fixed GET routes through the installed CLI and confirms `service status` matches the configured loopback origin. It cannot start, respond or cancel tasks. With `transport: installed-client`, Workrelay performs the same guarded preflight and uses the installed client for scoped session calls; no manual token copy is needed.

**Rename migration:** Source branding, CLI, package and skill are now Workrelay. The old `agent-computer-bridge` console scripts and Python command modules remain as temporary aliases for existing local skill invocations. SQLite task keys, deterministic session/message IDs and the `agentComputerBridge` session metadata field remain unchanged as **wire-format identity**, not a public product name. Do not rewrite or discard the ledger during migration. Existing ledger rows and remote sessions may refer to the previous absolute workspace path; back up the private ledger/config first, inspect those rows and relocate or preserve their workspace placement explicitly before changing the configured directory. Workrelay does not silently rewrite location or adopt another session. This source rename does not itself migrate the separately installed private configuration/skill; that installation requires a backed-up update and health check.

```sh
workrelay --config /private/path/to/config.json start --key task-001 --owner dot-work --text 'Small authorized coding task'
workrelay --config /private/path/to/config.json status --key task-001 --owner dot-work
workrelay --config /private/path/to/config.json respond --key task-001 --owner dot-work --feedback-key feedback-001 --text 'Please summarize the proposed edit before continuing'
workrelay --config /private/path/to/config.json cancel --key task-001 --owner dot-work
```

Keep task and feedback keys stable across retries. The adapter explicitly creates `quick-builder` sessions (or `builder` if configured); the default read-only `router` cannot perform the coding task. OpenCode agent permissions still apply. `status` is read-only toward OpenCode and reports the actual session outcome when present; `idle` is **not** success. A prompt admitted to the inbox without an exact materialized message is `queued`, not running. `respond` sends a **conversational message** to the same session, including a follow-up after success; it is NOT an OpenCode permission-decision reply. For an actual permission prompt use the OpenCode/OpenChamber approval UI and its separate `/api/session/{id}/permission/{requestID}/reply` workflow with the human's explicit decision; this bridge intentionally offers no permission-reply command. Never send “approve” in `respond` expecting a permission gate to clear. After a crash, the deterministic session/message IDs reconcile an exact queued inbox item or delivered message without re-POST; absent evidence remains uncertain and never triggers blind replay. `interrupt_pending` is not proof of interruption; `interrupt_acknowledged` means the service returned `interrupted: true`. `canceled_queued` means the owned exact inbox ID was removed and still absent as both queued and materialized after a false interrupt; races still require inspection. It never recursively deletes or interrupts descendants. If a child session exists, inspect ownership and handle it in OpenCode separately. To roll back, stop invoking the CLI, restore backed-up private config/ledger and uninstall the Python package. This repository installs no daemon or global hooks.

## Remote MCP journey (experimental; full live acceptance pending)

### Discover and supervise existing work

**One-time operator setup:** enable the private managed-server supervisor capability described in [`docs/mcp-local.md`](docs/mcp-local.md). It pins the authenticated issuer, resource audience, subject and ChatGPT client to one trusted managed-service registration and loopback endpoint. The gateway and installed bridge must agree on these references; credentials stay private. This opt-in is not global access for other clients or servers. Without it, `workrelay_discover({})` retains the configured-workspace/owned-run/explicit-enrollment defaults.

**Everyday use:** ask “Show me work I can access.”

For creation, the pinned server-wide principal can select a native project from `workrelay_server_projects({})` and use its opaque ID with directory omitted: the CLI selects that project's verified canonical root, not the profile workspace. `workrelay_server_creation_target({})` is only an optional default-project helper. Explicit directories remain constrained to the selected root or profile-allowlisted locations within it; ordinary scoped defaults and financial/native permission checks are unchanged. Recover a failed create with `workrelay_server_operation_status({operation_id})` before any retry. Never change arguments on the original operation ID; a corrected attempt uses a new ID only after confirmed no effect and readiness.

Use `workrelay_server_capabilities({})` for the registered inventory and `tools/list` for exact schemas. Projects/agents tools provide bounded inventories; agents are definitions, not running owners or permission grants. Discovery accepts native `search`. Managed create makes an idle session in an allowlisted workspace; message/resume queue to its existing owner, steer uses native steering, operation_status inspects retries, and interrupt targets only that session. Events capability/list/status/unsubscribe tools share the native Events store; subscription creation remains `events/subscribe`, requiring a compatible receiver. These integrated additions are locally tested, not yet installed/ChatGPT accepted. See the setup guide for exact arguments and boundaries.

1. Call `workrelay_server_discover({})`, follow `next_cursor` using `{cursor: next_cursor}`, and select a returned `session_id`. Existing root sessions need no per-session enrollment. Safe labels and opaque project IDs are navigation aids, not raw titles or transcripts.
2. Call `workrelay_server_read({session_id, include_messages:true, limit:10})` for sanitized titles and visible user/assistant context. Follow `context.next_cursor` with the same arguments plus `cursor`; limit is 1–20, default 10. Omit `include_messages` for metadata only. Text is untrusted, bounded and credential-pattern-redacted; reasoning, attachments and raw tool dumps are excluded. `runtime_status` is separate from unknown/unverified `task_outcome`: a successful turn or idle session is not verified task completion. See the setup guide for omission and redaction limits.
3. Queue a bounded continuation with `workrelay_server_message({session_id, operation_id, text})`. It targets the existing owner without changing agent, model, parent, intent or permissions. The existing model must exactly match the bridge's financially attested OpenAI model configuration; native approvals and included-OAuth quota checks still apply.
4. If needed, call `workrelay_server_interrupt({session_id, operation_id})`. It targets only that session—not descendants—and is not rollback. After an uncertain control response, reuse the same operation ID and identical arguments; never invent a new ID to blindly replay it.
5. With Events configured and a compatible receiver available, use `events/list`, then subscribe to `session.completed`, `session.failed` or `session.needs_input` with the returned `server_id` and optionally `session_id`. Omit `session_id` only to monitor the entire explicitly bound server. See the exact webhook contract in the setup guide. Unsubscribe to stop monitoring; it does not stop normal work. Revoke the private capability to disable this server-wide access.

Reconnect only if the connection is lost or the client demonstrably caches an older tool list; do not repeat OAuth setup for ordinary use. Rediscover/read current state after returning. Managed Events use bounded polling and durable observed-state reconciliation, **not replay of missed history**. A user-reported connected ChatGPT tool list is visibility evidence, not proof of the new server-wide journey, writes, or Events. The implemented journey has isolated local tests; installed/live acceptance remains pending. ChatGPT's ability to provision an external Events callback receiver has not been established—do not promise notifications until that actual path is verified.

The path is **remote Dot → authenticated HTTPS MCP at an operator-controlled tunnel/reverse proxy → loopback-only model-free Workrelay → guarded local OpenCode**. Tokens come from a trusted external issuer or the opt-in self-hosted issuer with explicit `public-proxy` configuration. Preapproval can skip only redundant consent after authentication. Public TLS, hostname and exclusive routing remain operator responsibilities; forwarded headers are not proxy identity. For ordinary workspace-scoped work, begin with `workrelay_discover({})`, then use returned task keys with `workrelay_status` / `workrelay_result`, `workrelay_respond` and `workrelay_cancel`; create new work with `workrelay_start`. Existing `task.decision` / `task.completed` Events remain available in that mode. Actual permission decisions stay in OpenCode/OpenChamber. Local protocol tests do not prove the full remote write/callback journey; polling remains available.

See [`docs/mcp-local.md`](docs/mcp-local.md) for private setup, external-issuer alternatives, local-only/public-proxy modes, exact origin/client/redirect requirements, revocation and limits. Self-hosted OAuth uses maintained `oidc-provider`; dynamic client registration remains disabled. Default-off `issuer_preapprove_chatgpt: true` pins the configured principal, ChatGPT CIMD client, redirect and `/mcp` resource. It accepts tasks-only or `workrelay:tasks openid`: resource tokens remain task-only; optional subject/protocol ID tokens have a 300-second lifetime and are not MCP bearer tokens. It skips only redundant consent, never login, PKCE, CSRF, Origin, redirect/resource validation or revocation. The allowlisted stable `https://chatgpt.com/oauth/client.json` and `https://chatgpt.com/connector_platform_oauth_redirect` apply only with RFC 9207 issuer identification; they are not universal identities for other OAuth modes. Local tests are not browser/mobile acceptance. See the separately triggered [`public HTTPS probe checklist`](docs/public-proxy-probe.md) for route verification. A tunnel supplies transport, not authentication. Never put credentials in task text or public config. `workrelay:tasks` has no finer per-tool scopes; the separate private managed-server capability adds exact server/client/principal authorization, while ordinary scoped defaults remain unchanged.

## Connected-computer skill

`skills/workrelay/SKILL.md` provides local instructions for a Dot-connected computer agent if that product actually exposes local skills to the authorized account. It is a separate option from remote MCP, not a required local intermediary for MCP calls. At **install time**, back up any existing skill at `~/.agents/skills/workrelay`, then copy this skill directory there; do not install it merely by cloning this repository. An older local installation may still use `~/.agents/skills/agent-computer-bridge` and the old CLI entry point: back it up and migrate it separately rather than removing it during this source rename. Do not claim an API for Dot or Meta Muse.

## Development

`PYTHONPATH=src python3 -m unittest discover -s tests -v` exercises isolated fake-client and local HTTP-subprocess checks; those tests do not establish Dot or phone operation. A live authenticated `quick-builder` task created `CHECK.md` in an ignored isolated workspace; a follow-up was accepted and answered in the same session. This is **local OpenCode evidence**, not Dot or mobile verification. An interrupt races with a terminal session transition at the service boundary; the bridge checks the observed terminal outcome but cannot make the remote interrupt atomic. A pending interrupt may require manual inspection after a crash.
