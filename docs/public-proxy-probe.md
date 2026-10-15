# Separately triggered public HTTPS acceptance probe

**Do not run automatically.** Start only after the operator supplies the exact
HTTPS origin, trusted TLS terminator/route and static client ID/redirect, and
approves public exposure. Local synthetic HTTP tests cannot establish public
TLS, provenance, Dot access or webhook delivery. Never print passwords, bearer
tokens, signing keys or webhook secrets in commands, logs or screenshots.

1. Confirm the chosen hostname, DNS and valid certificate from a separate
   external client; verify TLS, hostname and certificate chain without `-k` or
   ignored verification. Confirm proxy accepts only that host, strips caller
   forwarding headers, and sends to the Workrelay loopback port only. Confirm
   the OpenCode service remains authenticated and loopback-only. Record actual
   endpoint, process/port owner and route owner without credential contents.
2. With no bearer, fetch `/.well-known/oauth-protected-resource/mcp` and the
   advertised issuer's `/.well-known/oauth-authorization-server` and `/jwks`.
   Confirm HTTPS origin, `resource=https://HOST/mcp`, exact issuer, authorization
   and token endpoints, S256 PKCE and public signing keys only. An unauthenticated
   MCP call must be rejected; forged Host, Origin, duplicate/Forwarded headers,
   missing/incorrect resource and wrong redirect/client must not mint a code.
3. In an approved browser, authorize the actual configured client using its
   exact registered HTTPS redirect, explicit human login/consent and S256 PKCE.
   Observe RFC 9207 `iss` on success **and** redirectable authorization errors.
   Exchange the code with the exact `resource` at the token endpoint. Verify
   JWT signature, issuer, subject, audience, scope and five-minute expiry, then
   invoke a harmless MCP profile/status call. Test wrong verifier and expired
   token denial. Do not substitute a synthetic user or a locally injected token.
4. If using Dot, verify the actual remote custom MCP connection and one bounded
   task: request, same-owner read-only status, human decision in local UI,
   follow-up on the same task, completion and (if enabled) signed webhook Event.
   Capture precise observed boundaries; no simulator/desktop curl is a mobile
   result. Check no paid inference fallback and keep keys outside commands.
5. Stop the route after the probe; check revocation and cleanup without changing
   unrelated sessions. If any step fails, keep public exposure disabled and
   report the exact failed boundary and next action. A passing local suite or
   public discovery alone is not release acceptance.

Official reference: https://developers.openai.com/plugins/build/auth and
https://developers.openai.com/api/docs/mcp .
