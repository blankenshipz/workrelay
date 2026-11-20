# Changelog

## Unreleased

- Per-agent progress listeners for agents that share one MCP connection: `workrelay_server_notify` scope `agent` (`agent: "<stable name>"`, `[A-Za-z0-9._-]{1,64}`) stores a listener keyed by (OAuth `client_id`, agent). `workrelay_server_create`/`message`/`resume` accept an optional `agent` (remembered per session) and attach that agent's listener, falling back to the client listener, then the gateway default (`source: "agent_default"`). check/test/clear support scope `agent`; `notify-register.mjs` gains `--agent`.
- Progress notifications work with any agent platform or receiver (`session_notify`):
  - **Event schema:** `schema_version: 1`, `source`, `server_id`, `project_id`, `directory`, a one-line `summary`, and a `read` hint (`workrelay_server_read`) on every event. The schema is documented.
  - **Signing:** optional Standard Webhooks HMAC signing (`hmac_secret`: `webhook-id`, `webhook-timestamp`, `webhook-signature`). `webhook-id` is stable across retries; the timestamp and signature are fresh on each attempt.
  - **Formats:** `format: "slack"` (`{text}`, escaped) and `format: "text"` (plain text, for ntfy and generic receivers), alongside the default `json`.
  - **Gateway default targets:** `session_notify.default_targets`, matched by session directory (path or glob) and/or OAuth `client_id`. URL, header and HMAC secrets come only from a private `0600` `secrets_file` or from environment variables, are resolved at send time and never enter the config or state file. A placeholder entry with an empty URL is inert.
  - **Automatic attach and opt-out:** a matching default is attached automatically on create/message/resume. A per-call `notify` overrides it. `notify: false` or `workrelay_server_notify` `clear` opts the session out. `set` without `url` re-attaches the default.
  - **Agent awareness:** `workrelay_server_notify` `status` reports the effective target, redacted (source, default name, `url_host`, `configured`, `signed`, `format`, delivery counts), and whether a default is available. The create/message/resume descriptions tell agents to rely on events instead of polling.
- Per-session progress notifications for the delegating agent (`session_notify`, opt-in):
  - **Registering:** pass an optional `notify` to `workrelay_server_create`/`message`/`resume`, or use the new `workrelay_server_notify` tool (set, clear, status). It takes a public HTTPS webhook URL, such as a Grok Bot routine webhook trigger, an optional secret header and an optional stall threshold.
  - **Events:** `permission_asked` (permission id, child session, action, redacted preview, directory; immediate, deduped), `finished`/`failed` (once per run), `child_failed`, `stalled` (default 10 min without progress) and `unobservable`. The last three are limited to one per session per 2 minutes and coalesced. There are no per-step events.
  - **Delivery:** the SSRF-pinned transport shared with Events (public DNS answers only, no redirects). The header is stored only in a private `0600` state file and is never returned or put in a payload. Delivery runs in a background poller with concurrent delivery and longer retries for asks and completion, so failures never affect tool calls or runs.
- Loopback-only live activity view (`/operator/activity` on `operator_approvals.local_listen`):
  - Shows active sessions per project with status and a short redacted tail of tool calls and text. Pending asks get Approve once, Approve always and Deny buttons.
  - Uses the same operator session and directory-bound reply path as the permissions page. The JSON feed needs the session cookie plus a custom header; decisions need Origin plus a session-bound CSRF token. The CSP is strict and nonce-based.
  - The feed renews the operator session while the view is open, up to 2 hours; the page has a Sign out button. Per-session rate limits are applied after the session check.
  - The loopback cookies now use `Path=/operator`.
- New operator-only reader actions `session_watch` and `activity_overview`. They are never reachable from MCP tools.
- Managed create allows Anthropic routes only when the complete `provider_guard_file_hashes.anthropic` pin set is configured, and the pinned guard files currently match before the session is created. Incomplete, malformed or mismatched pins deny the create. Later writes still run full attestation.
- Managed create now stamps the target agent's own configured native model (`GET /api/agent/<agent>` at the creation location) instead of always forcing the profile `model`. The profile model is a fallback only for agents without a model, or an explicit override via `managed_create_model: "profile"`. An unavailable agent definition denies the create; there is no silent fallback. The guarded transport independently re-resolves the model before the native POST. Resolved models pass the same exact-reference, provider and pin checks.
- Read surfaces pending native permission requests across the session tree (per-session lists; the location-scoped global list is not used): `blocked_on_permission`, sanitized `pending_permissions`, `children` with running/idle/blocked status, and an `aggregate_status` that never reports a finished tree while children run or are blocked. Discover adds a compact per-session `tree` summary.
- Read/discover distinguish live permission blocks from stale requests. A stale request is one left on a stopped session: not in `/api/session/active`, and with a terminal `outcome` or `time.idle`. Stale requests are listed under `stale_permissions` (items marked `stale: true`) and in per-child and discover `stale_permission_count`. They no longer set `blocked_on_permission` or make `aggregate_status`/child status `blocked_on_permission`, so an interrupted tree reports `interrupted`. Stale requests are not notified. The operator page labels them and offers only dismissal (deny). The reader refuses `once`/`always` replies to them (`stale_session_stopped`): in OpenCode 2.0.30 such a reply resumes nothing, and `always` would still save a project-wide rule.
- Optional `harness_state_dir`: read reports the opencode-usage-harness task intent and per-check status (self-reported) for the root session; otherwise the reason states the checks are not readable by workrelay.
- Human-only permission approval page at `/operator/permissions` (`operator_approvals`), behind the operator password, single-use CSRF, Origin checks and rate limits. No MCP tool can approve. Optional deduplicated, non-blocking notification hook (`notify_command` / `notify_webhook_url`) sends summary fields only.
- After an OpenCode restart, an attestation failing only `GUARD_PLUGIN_STATE` (per-directory plugins not loaded yet) triggers a plugin load for that directory and is retried after 1 s, 3 s and 6 s before the original denial is returned. Retries happen only before any session/prompt/reply POST is permitted; other denials are never retried. Managed operations record `plugin_warmup_retries`.
- Optional `operator_approvals.local_listen: {"port": N}` (off by default; self-hosted issuer only) opens a second listener bound only to `127.0.0.1:N` with the gateway's lifetime. It serves only `/operator/permissions`, never MCP, OAuth/OIDC, interaction, metadata or JWKS routes, so an operator can reach the page with `ssh -L N:127.0.0.1:N`. It applies the same password, lockout, rate limits, single-use CSRF and 5-minute session. It requires an exact loopback Host and matching `Origin`, and rejects forwarding headers. It uses host-only, path-scoped `HttpOnly; SameSite=Strict` cookies, which are not `__Host-`/`Secure` because the origin is plain-HTTP loopback. Notifications then link to the loopback URL.
- Gateway tool-call audit log (`audit_log`): one JSON line per tool call with ids, duration and a closed status/error category only. Defaults to `<issuer_state_dir>/tool-audit.jsonl`, `0600`, with bounded rotation. Write failures never affect calls.

## 0.2.0 — 2026-11-19

### Native questions and observed delivery

- Recover only proven pre-send question reservations after a dead owner, retaining the same decision and all admission checks.

- Add explicitly authorized, exact-form question replies/dismissals with durable operation identity and no blind replay after uncertain delivery. Native permission approvals remain in the native UI.
- Expose pending questions and read-only native operation reconciliation separately from historical receipt inspection.
- Distinguish current execution and wait state from historical idle outcomes and unverified task completion.

- OAuth renewal/reconnect: documented the reviewed candidate's 300-second access-token and fixed 14-day refresh-family contract, binding checks before token consumption/replay, concurrent duplicate `invalid_grant` handling and atomic family revocation. Fresh consent using the same authorized client/browser can create a new `workrelay:tasks openid` grant after revocation; old grant tokens remain denied. Rotation is strict: lost-response/stale-token replay yields `invalid_grant` and family revocation; transparent retry/grace is not implemented. The intended recovery is explicit reconnect, not client remove/re-add.
- Evidence boundary: isolated tests used a 60-second fixture and did not alter live lifetimes, credentials, scopes or monitoring. Focused groups of 15 and 14 passed. The final unchanged-source elapsed gate passed in 223.686 seconds, covering two expiry/refresh/MCP-read cycles, restart persistence, binding preservation, concurrent refresh/replay revocation, lost-response behavior, same-client fresh-consent recovery and explicit revoke/teardown. An earlier elapsed attempt was terminated before completion and is superseded by this pass. The source candidate based on `20936c6` remains unreleased; `0.1.0` remains immutable. Production deployment and real ChatGPT UI behavior remain unverified.

- Clarify guarded inference routing: new managed sessions use the configured creation-model default; existing sessions are evaluated against their current native catalog resolution and actual pinned OpenAI OAuth integration, with credentials, quota, guard and identity rechecked. This documentation reflects reviewed source behavior but does not claim the current deployed installation or ChatGPT journey accepted the route clarification. Unsupported/ambiguous routes remain fail-closed; no universal model ID, API-key path or fallback is promised.
- Managed client pin: optional `managed_client_id` selects the OAuth client allowed to use the managed tools. It defaults to ChatGPT's CIMD client, so existing bindings are unchanged. In self-hosted mode it must exactly equal the registered `clientId`, and the capability binding `client_id` must match that pin.

## 0.1.0 — reviewed checkpoint

This is an initial reviewed checkpoint, not a claim that the full remote acceptance journey is complete. The checkpoint is based on reviewed source at `41f492326a08021cb521f9f815f8dfa6d46e4dd0`; these notes do not change runtime behavior or represent a new installation.

### Verified within the checkpoint

- A user-reported authenticated remote MCP session discovered and read sessions, inspected capabilities, created work, sent a message and follow-up, steered and resumed, returned to inspect state, and received a completion notification. The reported delivery response was HTTP 200 with one delivered and zero queued; unsubscribe also succeeded. This is bounded user-reported remote evidence, not independent proof of model/agent visibility or every control path.
- Separate controlled local native checks verified needs-input delivery and active-interrupt behavior. They are not proof of those behaviors through ChatGPT.
- Controlled HTTPS receiver checks verified signed delivery, retry/deduplication and cleanup for the exercised native transitions. They do not establish ChatGPT callback setup or the complete installed-client journey.

### Still pending or unverified

- ChatGPT-originated needs-input delivery and active cancellation remain unverified. The prepared native permission fixture was not triggered; the effective-policy application allowlist gap remains an implementation item and is not included in this checkpoint.
- Remote model/agent visibility and the complete current-installed-candidate ChatGPT journey, including its callback provisioning path, remain unverified. Do not infer them from session discovery, completion notification, local probes, or HTTP delivery status.
- Historical authorization denial and token HTTP 400 reports have unknown causes. No retroactive diagnosis or fix is claimed.

Workrelay preserves the configured included-ChatGPT OAuth route, native OpenCode permissions, session ownership, and secret protections. No API-key or paid inference fallback is introduced. See [README](README.md) and [the remote MCP setup and acceptance guide](docs/mcp-local.md) for operating boundaries and the combined acceptance workflow.
