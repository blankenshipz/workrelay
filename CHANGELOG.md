# Changelog

## Unreleased

- Clarify guarded inference routing: new managed sessions use the configured creation-model default; existing sessions are evaluated against their current native catalog resolution and actual pinned OpenAI OAuth integration, with credentials, quota, guard and identity rechecked. This documentation reflects reviewed source behavior but does not claim the current deployed installation or ChatGPT journey accepted the route clarification. Unsupported/ambiguous routes remain fail-closed; no universal model ID, API-key path or fallback is promised.

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
