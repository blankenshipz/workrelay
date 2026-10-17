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
- **MCP Events** are the gateway's client-facing protocol (`events/list`, `events/subscribe`, `events/unsubscribe`) for scoped task lifecycle notifications and, with explicit managed-server authorization, `session.progress`, `session.needs_input`, `session.completed` and `session.failed`. Workrelay implements signed HTTPS webhook delivery for configured callbacks. Controlled live probes verified a real native permission-ask → `session.needs_input` signed HTTPS acknowledgement (unsubscribe preserved the gate; reject-only cleanup cleared it with no stale completion) and a separate financially guarded existing-session continuation → fresh-generation completion acknowledgement, with protected identity unchanged. Both exercised four native wakes, signed challenges, receiver 503/deduplicated retry, renewal and unsubscribe cleanup; see receipts `workrelay-owned-native-ask-journey-2cxff16m`, `workrelay-owned-native-completion-journey-x5eya35u`, and `workrelay-native-live-acceptance-_q6sbz3u`. These controlled journeys verify native needs-input/completion delivery to the controlled receiver, not ChatGPT-generated callback provisioning or the complete installed/ChatGPT journey. Managed observation does not replay missed history; direct read polling remains available.

That controlled receiver check does not verify a user-operated public tunnel, independently operated issuer, ChatGPT-generated callback provisioning, or real Dot/mobile round trip. Treat those paths as unverified until tested in that environment. See [the MCP boundary, setup, and verification limits](docs/mcp-local.md).

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

**One-time operator setup:** enable the private managed-server supervisor capability described in [`docs/mcp-local.md`](docs/mcp-local.md). It pins the authenticated issuer, resource audience, subject and ChatGPT client to one trusted local service registration and loopback endpoint. The gateway and installed bridge must match those bindings; credentials remain private. This grants server-wide discovery and supervision only to that principal on that one bound server. Other clients keep ordinary workspace/ownership defaults; no enrollment ID is needed for the pinned principal's eligible sessions.

**Everyday managed-server tool map** (exact schemas are returned by `tools/list`; start with `workrelay_server_capabilities({})`):

| Need | Tools | Boundary |
|---|---|---|
| Inventory | `workrelay_server_projects`, `workrelay_server_agents`, `workrelay_server_discover` | Bounded pages/cursors; agents are definitions, not running owners or permission grants. |
| Read | `workrelay_server_read`, `workrelay_server_waits` | Sanitized visible user/assistant context and native permission waits; no inference or permission reply. |
| Create/select | `workrelay_server_create`, optional `workrelay_server_creation_target` | Create an idle session in a selected native project's verified root; creation does not start inference. |
| Control/recovery | `workrelay_server_message`, `workrelay_server_resume`, `workrelay_server_steer`, `workrelay_server_operation_status`, `workrelay_server_interrupt` | Continue/steer only the existing owner; inspect an operation by its ID; interrupt only the named session. |
| Events | `workrelay_event_capabilities`, `workrelay_event_subscriptions`, `workrelay_event_subscription_status`, `workrelay_event_unsubscribe`; native `events/list`, `events/subscribe`, `events/unsubscribe` | Managed `session.progress`, `session.needs_input`, `session.completed`, `session.failed`; webhook receiver must be configured and verified separately. |

Use `workrelay_server_projects` to choose any listed native project; `workrelay_server_creation_target` is only a convenience for the configured default. Omit `directory` when creating to use the selected project's verified canonical root. An explicit directory is still constrained to that project root or an operator-allowlisted location. `workrelay_server_create` creates idle work only. `message`/`resume` queue bounded text to the existing owner; `steer` uses native steering and does not transfer owner, agent or model. The exact session model must match the private financially attested OpenAI route before inference; included-OAuth quota and native permissions remain authoritative. No arbitrary shell, blanket approval, provider/API-key fallback or competing owner is introduced.

Read with `workrelay_server_read({session_id,include_messages:true,limit:10})`; follow its context cursor for older pages. `workrelay_server_waits({session_id})` is read-only and directs a real permission decision to that exact session/request in OpenCode/OpenChamber. There is no question list/reply route, permission-reply tool, or approval-through-message. Visible conversation and runtime state are not verified task outcomes. Use `workrelay_server_operation_status({operation_id})` to recover an uncertain original write; repeat only with the same ID and identical inputs. A corrected write needs a new ID only after the original is confirmed to have had no effect.

`workrelay_server_interrupt` stops active execution only for the named test/session; it is not rollback, does not cancel descendants, and does not remove queued inputs (they may run on a later resume). `idle_noop` is not proof that anything was interrupted. Unsubscribing removes monitoring only; it does not stop the MCP service or underlying work. Reconnect after disconnection, then rediscover/read current state rather than redoing setup.

### One combined acceptance request

Run this only after the **current candidate** is installed and an isolated native test project whose model matches the guarded configuration is ready. Use one request, not separate incremental user tests:

```text
Using Workrelay's managed-server tools on the explicitly bound server only, perform one bounded acceptance on the designated isolated test project. First inspect workrelay_server_capabilities, projects, agents, and paginated discovery. Select only a designated disposable test session, or create one idle session in the designated existing project; do not create a project or touch unrelated sessions. Read bounded visible context and native waits before writing. If the project/session or required guarded model is unavailable, stop and report the prerequisite rather than changing config or policy.

Events acceptance is a required part of the combined journey, not a completed optional feature. If a real, securely configured receiver is available, call workrelay_event_capabilities, list events, and subscribe to this server and test session for progress, needs-input, completion and failure before the action. Check the returned subscription with workrelay_event_subscription_status and verify an actual callback. Never invent a callback URL or secret. If the ChatGPT test cannot configure/use a receiver, report the Events portion blocked/pending; do not count the combined journey as passed or substitute read polling for Events acceptance.

Send one small, explicit test action to the selected session using a fresh operation_id; read the visible result and runtime state, and inspect native waits. Steer only that same session if its existing owner is actively running and steering is supported; otherwise report steer as unexercised. Do not change owner, agent, model or permissions. Route any permission decision through OpenCode/OpenChamber and then reread waits. Inspect operation status after uncertainty using the original ID and identical inputs. Interrupt only this disposable session, report whether it interrupted or returned idle_noop, and do not claim rollback or cleared queued input. Unsubscribe any test subscription. Return/reconnect once, rediscover/read the same server/session, and report runtime state separately from verified task outcome. Do not imply a webhook or remote ChatGPT pass unless the receiver actually observed it.
```

The earlier installed commit is `f7090cc323c6982a21d964e791f5a167d565c680` (abbreviated `f7090cc3`); `49` was a file count, not part of the commit hash. Its local server discovery/read evidence is not proof of the current candidate's write/control/Events journey. Current-candidate targeted local gateway/SSE tests and the controlled live native transition-to-receiver probes above are evidence for their bounded paths only. The combined current-candidate installed/ChatGPT journey and ChatGPT-generated receiver path remain unverified. Managed OpenCode SSE/state reconciliation does not replay every missed transition or history. A connected tool list proves visibility only, not the combined workflow.

The path is **remote Dot → authenticated HTTPS MCP at an operator-controlled tunnel/reverse proxy → loopback-only model-free Workrelay → guarded local OpenCode**. Tokens come from a trusted external issuer or the opt-in self-hosted issuer with explicit `public-proxy` configuration. Preapproval can skip only redundant consent after authentication. Public TLS, hostname and exclusive routing remain operator responsibilities; forwarded headers are not proxy identity. For ordinary workspace-scoped work, begin with `workrelay_discover({})`, then use returned task keys with `workrelay_status` / `workrelay_result`, `workrelay_respond` and `workrelay_cancel`; create new work with `workrelay_start`. Existing `task.decision` / `task.completed` Events remain available in that mode. Actual permission decisions stay in OpenCode/OpenChamber. Local protocol tests do not prove the full remote write/callback journey; polling remains available.

See [`docs/mcp-local.md`](docs/mcp-local.md) for private setup, external-issuer alternatives, local-only/public-proxy modes, exact origin/client/redirect requirements, revocation and limits. Self-hosted OAuth uses maintained `oidc-provider`; dynamic client registration remains disabled. Default-off `issuer_preapprove_chatgpt: true` pins the configured principal, ChatGPT CIMD client, redirect and `/mcp` resource. It accepts tasks-only or `workrelay:tasks openid`: resource tokens remain task-only; optional subject/protocol ID tokens have a 300-second lifetime and are not MCP bearer tokens. It skips only redundant consent, never login, PKCE, CSRF, Origin, redirect/resource validation or revocation. The allowlisted stable `https://chatgpt.com/oauth/client.json` and `https://chatgpt.com/connector_platform_oauth_redirect` apply only with RFC 9207 issuer identification; they are not universal identities for other OAuth modes. Local tests are not browser/mobile acceptance. See the separately triggered [`public HTTPS probe checklist`](docs/public-proxy-probe.md) for route verification. A tunnel supplies transport, not authentication. Never put credentials in task text or public config. `workrelay:tasks` has no finer per-tool scopes; the separate private managed-server capability adds exact server/client/principal authorization, while ordinary scoped defaults remain unchanged.

## Connected-computer skill

`skills/workrelay/SKILL.md` provides local instructions for a Dot-connected computer agent if that product actually exposes local skills to the authorized account. It is a separate option from remote MCP, not a required local intermediary for MCP calls. At **install time**, back up any existing skill at `~/.agents/skills/workrelay`, then copy this skill directory there; do not install it merely by cloning this repository. An older local installation may still use `~/.agents/skills/agent-computer-bridge` and the old CLI entry point: back it up and migrate it separately rather than removing it during this source rename. Do not claim an API for Dot or Meta Muse.

## Development

`PYTHONPATH=src python3 -m unittest discover -s tests -v` exercises isolated fake-client and local HTTP-subprocess checks; those tests do not establish Dot or phone operation. A live authenticated `quick-builder` task created `CHECK.md` in an ignored isolated workspace; a follow-up was accepted and answered in the same session. This is **local OpenCode evidence**, not Dot or mobile verification. An interrupt races with a terminal session transition at the service boundary; the bridge checks the observed terminal outcome but cannot make the remote interrupt atomic. A pending interrupt may require manual inspection after a crash.
