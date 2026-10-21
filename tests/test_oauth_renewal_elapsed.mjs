// Isolated maintained-provider reproduction, NOT a production/client acceptance claim.
// Fixture alone uses 60s access TTL; no runtime config, credentials or grants read.
import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createServer, request as httpsRequest } from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes, generateKeyPairSync, createHash } from 'node:crypto';
import Provider, { errors } from 'oidc-provider';
import argon2 from 'argon2';
import { importJWK, jwtVerify } from 'jose';
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createLocalInteractions } from '../src/workrelay/issuer_interactions.mjs';
import { createUnexposedIssuerPolicy, validateRefreshBinding, loadPreapprovedChatGPTGrant, CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from '../src/workrelay/issuer_policy.mjs';

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
test('isolated OAuth real minute expiry: cycles, persistence, concurrent and lost-response rotation reproduction', { timeout: 260000 }, async t => {
  const directory = await fs.mkdtemp(fileURLToPath(new URL('.workrelay-issuer-mcp-renewal-', import.meta.url)));
  await fs.chmod(directory, 0o700);
  // Preserve fixture evidence in the private check directory's complete output;
  // generated private storage has the usual fixture teardown only after server stop.
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const pinned = process.env.WORKRELAY_TEST_PINNED_PREAPPROVAL === '1';
  const origin = 'https://issuer.renewal.test', resource = origin + '/mcp', clientId = pinned ? CHATGPT_CIMD_ID : 'isolated-renewal-client';
  const redirect = pinned ? CHATGPT_CIMD_REDIRECT : 'https://client.renewal.test/callback', principal = 'isolated-person';
  const password = randomBytes(32).toString('base64url');
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: principal,
    verifier: await argon2.hash(password, { type: argon2.argon2id }) }), { mode: 0o600 });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwks = { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' }] };
  const verifyKey = await importJWK(publicKey.export({ format: 'jwk' }), 'RS256');
  const cookieKeys = [randomBytes(32).toString('base64url')];
  const factory = process.env.WORKRELAY_TEST_ACTUAL_FACTORY === '1';
  const BaseAdapter = createIssuerAdapter(directory);
  class ObservedAdapter extends BaseAdapter {
    async consume(id) {
      try { return await super.consume(id); }
      catch (error) {
        if (this.model === 'RefreshToken') {
          const stored = await this.find(id);
          console.log(JSON.stringify({ checkpoint: 'refresh_consume_failure',
            error_class: error instanceof errors.InvalidGrant ? 'InvalidGrant' : 'StorageError',
            record_present: Boolean(stored), consumed: Boolean(stored?.consumed),
            source: 'PrivateIssuerAdapter.consume', provider: '9.12.2' }));
        }
        throw error;
      }
    }
  }
  assert.equal(!factory || pinned, true, 'factory fixture uses pinned client');
  const makeProvider = () => factory ? createUnexposedIssuerPolicy({ origin, principal, jwks, cookieKeys,
    clientId, redirectUris: [redirect], adapter: ObservedAdapter,
    clientRegistration: 'chatgpt-cimd', preapproveChatGPT: true,
    fetchClientDocument: async () => new Response(JSON.stringify({ client_id: clientId, client_name: 'Isolated ChatGPT fixture',
      redirect_uris: [redirect], token_endpoint_auth_method: 'none', token_endpoint_auth_methods_supported: ['none'], grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'], jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }), { headers: { 'content-type': 'application/json' } }),
    findAccount: async (_ctx, id) => id === principal ? { accountId: principal, claims: async () => ({ sub: principal }) } : undefined,
  }) : new Provider(origin, {
    ...(pinned ? { loadExistingGrant: ctx => loadPreapprovedChatGPTGrant(ctx, { principal, resource }) } : {}),
    adapter: ObservedAdapter, jwks, cookies: { keys: cookieKeys },
    clients: [{ client_id: clientId, redirect_uris: [redirect], token_endpoint_auth_method: 'none',
      response_types: ['code'], grant_types: ['authorization_code', 'refresh_token'] }],
    clientAuthMethods: ['none'], pkce: { required: () => true }, rotateRefreshToken: () => true,
    issueRefreshToken: (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    findAccount: async (ctx, id, source) => {
      validateRefreshBinding(ctx, id, source, { principal, clientId, resource });
      return id === principal ? { accountId: principal, claims: async () => ({ sub: principal }) } : undefined;
    },
    extraTokenClaims: async (ctx, token) => {
      if (ctx.oidc.params.resource !== resource || token.accountId !== principal || ctx.oidc.client.clientId !== clientId) throw new errors.InvalidTarget();
    },
    features: { devInteractions: { enabled: false }, registration: { enabled: false }, revocation: { enabled: true },
      resourceIndicators: { enabled: true, defaultResource: async () => { throw new errors.InvalidTarget(); },
        getResourceServerInfo: async (_ctx, target, client) => {
          if (target !== resource || client.clientId !== clientId) throw new errors.InvalidTarget();
          return { scope: 'workrelay:tasks', audience: resource, accessTokenTTL: 60, accessTokenFormat: 'jwt', jwt: { sign: { alg: 'RS256' } } };
        } } },
  });
  let provider = makeProvider();
  let interactions = createLocalInteractions({ provider, directory, origin, clientId, resource });
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'isolated-renewal-read', version: '1' });
    server.registerTool('fixture_read', { inputSchema: z.object({}).strict(), annotations: { readOnlyHint: true } },
      async () => ({ content: [{ type: 'text', text: 'ISOLATED_USEFUL_READ_OK' }] }));
    return server;
  });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost',
    '-keyout', join(directory, 'tls.key'), '-out', join(directory, 'tls.crt'), '-days', '1'], { stdio: 'ignore' });
  const tls = { key: await fs.readFile(join(directory, 'tls.key')), cert: await fs.readFile(join(directory, 'tls.crt')) };
  const serve = async (req, res) => {
    if (req.url === '/mcp') {
      try { const verified = await jwtVerify(req.headers.authorization?.slice(7) ?? '', verifyKey, { issuer: origin, audience: resource, clockTolerance: 0 });
        if (verified.payload.sub !== principal || verified.payload.scope !== 'workrelay:tasks') throw Error('denied');
      } catch { res.writeHead(401); res.end(); return; }
      let body = ''; for await (const part of req) body += part;
      const response = await handler.fetch(new Request(resource, { method: req.method, headers: { 'content-type': 'application/json',
        accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'fixture_read' }, body }));
      res.writeHead(response.status, Object.fromEntries(response.headers)); res.end(await response.text()); return;
    }
    if (!await interactions(req, res)) provider.callback()(req, res);
  };
  let server;
  async function start(port = 0) { server = createServer(tls, serve); await new Promise(resolve => server.listen(port, '127.0.0.1', resolve)); }
  await start();
  const port = server.address().port;
  const stop = () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  t.after(stop);
  let jar = new Map();
  async function request(path, { body, headers = {}, method = body ? 'POST' : 'GET', cookies = true } = {}) {
    const pathname = new URL(path, origin).pathname;
    const cookie = [...jar.values()].filter(c => pathname.startsWith(c.path)).map(c => c.pair).join('; ');
    const response = await new Promise((resolve, reject) => {
      // No pooled sockets: this fixture deliberately closes/rebinds its listener.
      const req = httpsRequest({ hostname: '127.0.0.1', port, path, method, rejectUnauthorized: false, agent: false,
        headers: { ...(cookies ? { cookie } : {}), ...headers } }, res => {
        let text = ''; res.on('data', part => { text += part; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
      }); req.on('error', error => reject(Error('isolated fixture HTTP failed: ' +
        (['ECONNRESET', 'ECONNREFUSED', 'EPIPE'].includes(error.code) ? error.code : 'OTHER')))); req.end(body?.toString());
    });
    if (cookies) for (const set of response.headers['set-cookie'] ?? []) {
      const [pair, ...attributes] = set.split(';'), name = pair.slice(0, pair.indexOf('='));
      const path = attributes.find(s => s.trim().toLowerCase().startsWith('path='))?.trim().slice(5) ?? '/';
      if (pair.endsWith('=') || attributes.some(s => s.trim().toLowerCase() === 'max-age=0')) jar.delete(name + path);
      else jar.set(name + path, { pair, path });
    }
    return response;
  }
  const token = async fields => {
    const response = await request('/token', { body: new URLSearchParams(fields), cookies: false,
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' } });
    return { status: response.status, value: JSON.parse(response.text) };
  };
  async function login({ existingBrowser = false } = {}) {
    if (!existingBrowser) jar = new Map();
    let explicitConsents = 0;
    const verifier = randomBytes(32).toString('base64url'), challenge = createHash('sha256').update(verifier).digest('base64url');
    let response = await request('/auth?' + new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirect,
      scope: pinned ? 'workrelay:tasks openid' : 'workrelay:tasks', resource, code_challenge: challenge, code_challenge_method: 'S256', state: 'fixture' }));
    for (let step = 0; step < 12; step++) {
      const location = response.headers.location;
      if (location?.startsWith(redirect)) {
        const code = new URL(location).searchParams.get('code'); assert.equal(typeof code, 'string', 'authorization code returned');
        const result = await token({ grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirect, code, code_verifier: verifier, resource });
        assert.equal(result.status, 200, 'PKCE exchange succeeds');
        if (pinned && existingBrowser) assert.equal(explicitConsents, 1, 'revoked grant requires explicit fresh human consent');
        return result.value;
      }
      if (location) { const next = new URL(location, origin); response = await request(next.pathname + next.search); continue; }
      assert.equal(response.status, 200, 'interaction form available');
      const csrf = response.text.match(/name="csrf" value="([^"]+)"/)?.[1]; assert.equal(typeof csrf, 'string', 'CSRF emitted');
      const action = response.text.match(/<form[^>]*action="([^"]+)"/)?.[1]; assert.equal(typeof action, 'string', 'form action emitted');
      const fields = { csrf, ...(response.text.includes('type="password"') ? { password } : { decision: 'approve' }) };
      if (fields.decision === 'approve') explicitConsents++;
      response = await request(new URL(action, origin).pathname, { body: new URLSearchParams(fields),
        headers: { origin, 'content-type': 'application/x-www-form-urlencoded' } });
    }
    throw Error('isolated authorization did not complete');
  }
  const refresh = (value, extra = {}) => token({ grant_type: 'refresh_token', client_id: clientId, refresh_token: value, resource, ...extra });
  async function read(value) {
    const response = await request('/mcp', { cookies: false, headers: { authorization: 'Bearer ' + value, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fixture_read', arguments: {},
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }) });
    const useful = response.text.includes('ISOLATED_USEFUL_READ_OK');
    if (!useful && response.status !== 401) {
      let code = null; try { const value = JSON.parse(response.text); if (Number.isSafeInteger(value.error?.code)) code = value.error.code; } catch {}
      console.log(JSON.stringify({ checkpoint: 'mcp_read_diagnostic', status: response.status, jsonrpc_code: code }));
    }
    return { status: response.status, useful };
  }
  let current = await login(); assert.equal((await read(current.access_token)).useful, true);
  const started = Date.now();
  // Follow-up cases can reuse the separately retained minute-expiry receipt;
  // an explicit fixture flag skips waits, never replaces elapsed acceptance.
  const cycles = process.env.WORKRELAY_TEST_REUSE_ELAPSED === '1' ? 0 : 2;
  assert.equal(!factory || cycles === 0, true, 'factory preserves production TTL; elapsed mode uses separate fixture');
  if (!cycles) console.log(JSON.stringify({ checkpoint: 'elapsed_cycles_not_rerun', source_receipt: 'oauth-refresh-fix-real-expiry-xtrixe0t' }));
  for (let cycle = 0; cycle < cycles; cycle++) {
    const claims = JSON.parse(Buffer.from(current.access_token.split('.')[1], 'base64url'));
    assert.equal(claims.exp - claims.iat, 60, 'fixture TTL only');
    await wait(Math.max(0, claims.exp * 1000 - Date.now() + 1100));
    assert.equal((await read(current.access_token)).status, 401, 'real elapsed expiry denied');
    const result = await refresh(current.refresh_token); assert.equal(result.status, 200, 'sequential renewal succeeds');
    assert.equal((await read(result.value.access_token)).useful, true); current = result.value;
    console.log(JSON.stringify({ checkpoint: 'real_expiry_cycle', cycle: cycle + 1, elapsed_ms: Date.now() - started, renewed: true, useful_read: true }));
  }
  await stop(); provider = makeProvider(); interactions = createLocalInteractions({ provider, directory, origin, clientId, resource }); await start(port);
  const persisted = await refresh(current.refresh_token); assert.equal(persisted.status, 200, 'owned issuer restart retains refresh state');
  assert.equal((await read(persisted.value.access_token)).useful, true);
  console.log(JSON.stringify({ checkpoint: 'owned_restart_persistence', refresh: 200, useful_read: true }));
  // A completed response deliberately discarded by the client represents lost delivery.
  const lostInput = persisted.value.refresh_token;
  const discarded = await refresh(lostInput); assert.equal(discarded.status, 200);
  const retry = await refresh(lostInput); assert.equal(retry.status, 400); assert.equal(retry.value.error, 'invalid_grant');
  const successor = await refresh(discarded.value.refresh_token); assert.equal(successor.status, 400, 'stale retry revokes successor grant');
  console.log(JSON.stringify({ checkpoint: 'lost_response_reproduced', stale_retry: 400, successor_after_retry: 400, native_category: 'invalid_grant' }));
  const reconnect = await login({ existingBrowser: true });
  assert.equal((await read(reconnect.access_token)).useful, true, 'same registration and browser reconnect after replay revocation');
  assert.equal((await refresh(discarded.value.refresh_token)).status, 400, 'reauthorization does not revive old token');
  console.log(JSON.stringify({ checkpoint: 'same_browser_same_client_reconnect', useful_read: true, old_refresh_denied: true }));
  const concurrentStart = await login();
  const raced = await Promise.all([refresh(concurrentStart.refresh_token), refresh(concurrentStart.refresh_token)]);
  const statuses = raced.map(r => r.status).sort(); assert.deepEqual(statuses, [200, 400], 'replay is a protocol denial, never a server error');
  assert.equal(raced.find(r => r.status === 400).value.error, 'invalid_grant');
  const raceSuccessor = raced.find(r => r.status === 200).value.refresh_token;
  assert.equal((await refresh(raceSuccessor)).status, 400, 'race revokes the successor, including any late save');
  await stop(); provider = makeProvider(); interactions = createLocalInteractions({ provider, directory, origin, clientId, resource }); await start(port);
  assert.equal((await refresh(raceSuccessor)).status, 400, 'race revocation survives restart');
  const raceRecovery = await login({ existingBrowser: true });
  assert.equal((await read(raceRecovery.access_token)).useful, true);
  console.log(JSON.stringify({ checkpoint: 'concurrent_refresh_secure_recovery', statuses, successor_denied: true, restart_denied: true, same_client_recovery_read: true }));
  const revoked = await login();
  const revoke = await request('/token/revocation', { body: new URLSearchParams({ client_id: clientId, token: revoked.refresh_token, token_type_hint: 'refresh_token' }),
    cookies: false, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(revoke.status, 200); assert.equal((await refresh(revoked.refresh_token)).status, 400);
  console.log(JSON.stringify({ checkpoint: 'explicit_revoke', refresh_denied: true }));
  const reauthorized = await login({ existingBrowser: true });
  assert.equal((await read(reauthorized.access_token)).useful, true);
  assert.equal((await refresh(revoked.refresh_token)).status, 400);
  {
    let bound = reauthorized;
    const cases = {
      client: fields => fields.set('client_id', 'wrong-client'),
      scope: fields => fields.set('scope', 'unapproved'),
      resource: fields => fields.set('resource', origin + '/wrong'),
      resource_absent: fields => fields.delete('resource'),
      resource_empty: fields => fields.set('resource', ''),
      resource_mixed: fields => fields.append('resource', origin + '/wrong'),
      resource_repeated: fields => fields.append('resource', resource),
      resource_excess: fields => { for (let i = 0; i < 8; i++) fields.append('resource', resource); },
    };
    const refreshAdapter = new BaseAdapter('RefreshToken'), grantAdapter = new BaseAdapter('Grant');
    for (const [kind, change] of Object.entries(cases)) {
      const source = await provider.RefreshToken.find(bound.refresh_token);
      assert.equal(Boolean(source), true);
      const snapshot = async () => JSON.stringify([await refreshAdapter.find(source.jti), await grantAdapter.find(source.grantId)]);
      const before = await snapshot();
      const fields = new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: bound.refresh_token, resource });
      change(fields);
      const negative = await token(fields);
      assert.equal([400, 401].includes(negative.status), true, kind + ' denied');
      assert.equal(await snapshot() === before, true, kind + ' leaves authoritative token/grant unchanged');
      const valid = await refresh(bound.refresh_token);
      assert.equal(valid.status, 200, kind + ' followed by SAME token valid refresh');
      assert.equal((await read(valid.value.access_token)).useful, true);
      bound = valid.value;
      console.log(JSON.stringify({ checkpoint: 'refresh_binding_state_preserved', kind, negative: negative.status, same_token_refresh: 200, useful_read: true }));
    }
    const normalized = await refresh(bound.refresh_token); assert.equal(normalized.status, 200);
    assert.equal((await read(normalized.value.access_token)).useful, true);
    let successorValue = normalized.value;
    const stale = await provider.RefreshToken.find(bound.refresh_token, { ignoreExpiration: true });
    assert.equal(Boolean(stale?.consumed), true, 'provider retains consumed binding fields');
    for (const [kind, change] of Object.entries(cases)) {
      const successorSource = await provider.RefreshToken.find(successorValue.refresh_token);
      const snapshot = async () => JSON.stringify([await refreshAdapter.find(stale.jti),
        await refreshAdapter.find(successorSource.jti), await grantAdapter.find(stale.grantId)]);
      const before = await snapshot();
      const fields = new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: bound.refresh_token, resource });
      change(fields);
      const negative = await token(fields);
      assert.equal([400, 401].includes(negative.status), true, 'stale ' + kind + ' denied');
      assert.equal(await snapshot() === before, true, 'stale ' + kind + ' preserves family');
      const valid = await refresh(successorValue.refresh_token);
      assert.equal(valid.status, 200, 'stale ' + kind + ' leaves successor renewable');
      assert.equal((await read(valid.value.access_token)).useful, true);
      successorValue = valid.value;
      console.log(JSON.stringify({ checkpoint: 'stale_binding_family_preserved', kind, negative: negative.status, successor_refresh: 200, useful_read: true }));
    }
    // Only a correctly bound stale replay reaches native family revocation.
    const replay = await refresh(bound.refresh_token);
    assert.equal(replay.status, 400); assert.equal(replay.value.error, 'invalid_grant');
    assert.equal((await refresh(successorValue.refresh_token)).status, 400);
    const revokedWrongResource = await refresh(revoked.refresh_token, { resource: origin + '/wrong' });
    assert.equal(revokedWrongResource.status, 400); assert.equal(revokedWrongResource.value.error, 'invalid_grant');
    console.log(JSON.stringify({ checkpoint: 'refresh_resource_replay_revocation', correctly_bound_replay: 400, successor_denied: true, revoked_wrong_resource: 400 }));
  }
});
