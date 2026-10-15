# Optional local OAuth issuer: local-only source mode

The existing **external OAuth issuer** remains supported. Optional
`issuer_mode: "self-hosted"` now starts only with explicit
`issuer_exposure: "local-only"`, private provisioned state and an explicit
127.0.0.1/::1 listener. It rejects public Host and caller-supplied forwarding
headers; internally it presents the configured issuer identity to the OAuth
provider for local protocol testing. This is **not** a reviewed public tunnel
mode. A reverse proxy can mask its own origin on a loopback hop, so these HTTP
checks alone cannot prove that no one has forwarded the port. Do not forward
this port or claim real browser, HTTPS or Dot/mobile verification.

`oidc-provider` 9.12.2 is pinned for a future optional issuer. Its documented
adapter interface now has private SQLite-backed IPC storage (`oidc_adapter.mjs`,
`oidc_store.py`), exercised only with synthetic records. The optional
`issuer_policy.mjs` configures an exact static client redirect,
S256 PKCE, canonical single MCP resource, 5-minute RS256 JWT access tokens,
refresh rotation, revocation endpoint and disabled dev interactions/registration.
The local gateway synthetic-credential test runs login, consent, code exchange
and an MCP tool call through HTTP simulating a validating HTTPS terminator.
It does **not** exercise a real HTTPS terminator or real ChatGPT client. Use
the verified project-local Node 22.23.3 LTS;
the global Node 22.2.0 is pre-LTS and unsupported by this library.
The integration slice does **not** establish a reviewed production OAuth server.

Source-only private setup reference: create a private 0700 state directory with
`human.json` provisioned through the local TTY command (never supply a password
in argv). Independently provision `issuer.json` mode 0600 containing a persistent
private `jwks.keys` RS256 signing JWK with `kid`, a `cookieKeys` array of private
random strings (at least 32 characters each), one `clientId`, and exact HTTPS
`redirectUris` array. Set private MCP config `issuer_mode: "self-hosted"`,
`issuer_exposure: "local-only"`, `issuer_state_dir` to that directory, `public_origin` to the intended exact
HTTPS tunnel origin, `audience` to `${public_origin}/mcp`, and `principal` to
the `human.json` account ID. The server refuses missing or permissive files.
This is a configuration format description, **not** authorization to activate
any public route or to place signing material in the repository.

Before live activation: independently review the whole issuer and interaction
boundary; verify persistent keys and private data under restart, token/client
revocation expectations, absolute proxy/Host/TLS configuration, and the real
browser and Dot/MCP flow. No real credentials have been created in this slice.
