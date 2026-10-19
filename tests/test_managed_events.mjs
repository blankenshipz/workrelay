import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { generateKeyPairSync, createHmac } from 'node:crypto';
import { exportJWK, SignJWT } from 'jose';
import { createGateway } from '../src/workrelay/mcp.mjs';
import { createManagedReader, managedServerID } from '../src/workrelay/managed_server.mjs';
import { createEventsService } from '../src/workrelay/events.mjs';

const client = 'https://chatgpt.com/oauth/client.json', session = 'ses_existing_owner';
const secret = 'whsec_' + Buffer.alloc(32, 9).toString('base64');
const listen = s => new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
const close = s => new Promise(resolve => { s.close(resolve); s.closeAllConnections(); });
async function directory(t) { const path = await fs.mkdtemp(join(dirname(fileURLToPath(import.meta.url)), '.workrelay-managed-events-')); await fs.chmod(path, 0o700); t.after(() => fs.rm(path, { recursive: true, force: true })); return path; }
function callback(calls, status = () => 200) { return async (_url, request) => {
  const body = JSON.parse(request.body), h = request.headers;
  assert.equal(h['webhook-signature'], 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64')).update(`${h['webhook-id']}.${h['webhook-timestamp']}.${request.body}`).digest('base64'));
  calls.push(body); return { status: body.type ? 200 : status(), body: JSON.stringify({ challenge: body.challenge }) };
}; }
const subscription = (server, name = 'session.needs_input', sid = session) => ({ name, arguments: { server_id: server, ...(sid ? { session_id: sid } : {}) }, delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret } });
async function until(condition) { for (let i = 0; i < 100; i++) { if (await condition()) return; await new Promise(r => setTimeout(r, 50)); } assert.fail('bounded observation did not arrive'); }

test('managed observer reads only pinned session outcome/permission IDs and rechecks capability', async () => {
  const binding = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp', subject: 'alice', client_id: client, server: 'http://127.0.0.1:4567', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
  const expected = { issuer: binding.issuer, audience: binding.audience, principal: 'alice', managed_server: binding };
  const claims = { iss: binding.issuer, aud: binding.audience, sub: 'alice', client_id: client };
  let permissionSession = session, revokeDuring = false;
  const reader = createManagedReader(expected, () => ({ ...binding }), { canonical: p => p,
    stat: () => ({ isDirectory: () => true, isFile: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, dev: 1, ino: 1, mtimeMs: 1 }),
    loadService: async () => ({ discover: async () => ({ url: binding.server, auth: {} }), headers: () => ({}) }),
    fetcher: async (url, options) => { assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'manual');
      if (url.pathname.endsWith('/permission')) { if (revokeDuring) binding.revoked = true; return new Response(JSON.stringify({ data: [{ sessionID: permissionSession, id: 'per_decision', patterns: ['SECRET'], metadata: { token: 'SECRET' } }] })); }
      return new Response(JSON.stringify({ data: { id: session, outcome: undefined, title: 'SECRET', projectID: 'SECRET', time: { idle: 1 } } })); },
  });
  const filter = { server_id: managedServerID(binding), session_id: session };
  const result = await reader('events', filter, claims);
  assert.deepEqual(result.items, [{ session_id: session, state: 'needs_input', decisions: ['per_decision'] }]); assert.ok(!JSON.stringify(result).includes('SECRET'));
  await assert.rejects(reader('events', { ...filter, server_id: 'srv_' + 'f'.repeat(64) }, claims));
  await assert.rejects(reader('events', filter, { ...claims, client_id: 'other' }));
  permissionSession = 'ses_other'; await assert.rejects(reader('events', filter, claims)); permissionSession = session;
  revokeDuring = true; await assert.rejects(reader('events', filter, claims));
});

test('durable reconciliation, retry, restart, filters and revocation never emit transcript or idle completion', async t => {
  const dir = await directory(t), server = 'srv_' + 'a'.repeat(64), calls = []; let allowed = true, time = Date.now(), state = 'unknown', decisions = [], response = 503;
  const config = { statePath: join(dir, 'events.json'), principal: 'alice', now: () => time,
    authorize: async (principal, _task, _name, filter) => allowed && principal === 'alice' && filter?.server_id === server,
    observeManaged: async (filter, cursor) => { assert.equal(cursor, null); return { server_id: server, items: [{ session_id: filter.session_id ?? session, state, decisions, transcript: 'SECRET', prompt: 'SECRET' }], next_cursor: null }; }, transport: callback(calls, () => response) };
  let events = createEventsService(config);
  await assert.rejects(events.subscribe(subscription('srv_' + 'b'.repeat(64))));
  await events.subscribe(subscription(server)); await events.subscribe(subscription(server, 'session.failed', null)); await events.subscribe(subscription(server, 'session.completed', 'ses_other'));
  await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 0);
  state = 'needs_input'; decisions = ['per1']; await events.pollManaged(); await events.deliverDue();
  const first = calls.find(e => e.eventId); assert.equal(first.data.session_id, session); assert.equal(first.name, 'session.needs_input');
  events = createEventsService(config); response = 200; time += 1001; await events.pollManaged(); await events.deliverDue();
  const retried = calls.filter(e => e.eventId); assert.equal(retried.length, 2); assert.equal(retried[0].eventId, retried[1].eventId);
  await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 2);
  state = 'failed'; decisions = []; await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.name === 'session.failed').length, 1);
  state = 'succeeded'; await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.name === 'session.completed' && e.data.session_id === 'ses_other').length, 1);
  assert.ok(!JSON.stringify(calls).includes('SECRET')); assert.ok(!JSON.stringify(calls).includes('per1'));
  await events.unsubscribe(subscription(server, 'session.failed', null)); state = 'unknown'; await events.pollManaged(); state = 'failed'; await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.name === 'session.failed').length, 1);
  state = 'needs_input'; decisions = ['per2']; await events.pollManaged(); allowed = false; await events.deliverDue(); assert.equal(calls.filter(e => e.name === 'session.needs_input').length, 2);
  const foreign = createEventsService({ ...config, principal: 'bob' }); await assert.rejects(foreign.subscribe(subscription(server)));
});

test('server-wide pagination cursor and queued event IDs survive restart without skipping or duplicating pages', async t => {
  const dir = await directory(t), server = 'srv_' + 'd'.repeat(64), calls = [], cursors = []; let phase = 'unknown';
  const config = { statePath: join(dir, 'pages.json'), principal: 'alice', authorize: async () => true, transport: callback(calls),
    observeManaged: async (_filter, cursor) => { cursors.push(cursor); return { server_id: server, items: [{ session_id: cursor ? 'ses_page_two' : session, state: phase, decisions: [] }], next_cursor: cursor ? null : 'second-page' }; } };
  let events = createEventsService(config); await events.subscribe(subscription(server, 'session.failed', null)); await events.pollManaged();
  events = createEventsService(config); await events.pollManaged(); phase = 'failed'; await events.pollManaged(); await events.pollManaged(); await events.deliverDue();
  assert.deepEqual(cursors, [null, 'second-page', null, 'second-page']); assert.equal(new Set(calls.filter(e => e.eventId).map(e => e.eventId)).size, 2);
  await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 2);
});

test('a real pending permission projection outranks a previous terminal outcome without granting it', async t => {
  const dir = await directory(t), server = 'srv_' + 'e'.repeat(64), calls = []; let waiting = true;
  const events = createEventsService({ statePath: join(dir, 'wait.json'), principal: 'alice', authorize: async () => true, transport: callback(calls),
    observeManaged: async () => ({ server_id: server, items: [{ session_id: session, state: 'succeeded', decisions: waiting ? ['per_owned_fixture'] : [] }], next_cursor: null }) });
  await events.subscribe(subscription(server, 'session.completed')); await events.subscribe(subscription(server)); await events.pollManaged(); await events.deliverDue();
  assert.equal(calls.filter(e => e.name === 'session.completed').length, 0); assert.equal(calls.filter(e => e.name === 'session.needs_input').length, 1);
  waiting = false; await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.name === 'session.completed').length, 0);
});

test('terminal snapshots are baselines; only observed change or fresh scoped native generation emits completion', async t => {
  const dir = await directory(t), server = 'srv_' + 'f'.repeat(64), calls = [];
  const events = createEventsService({ statePath: join(dir, 'native.json'), principal: 'alice', authorize: async () => true, transport: callback(calls),
    observeManaged: async () => ({ server_id: server, items: [{ session_id: session, state: 'succeeded', decisions: [] }], next_cursor: null }) });
  await events.subscribe(subscription(server, 'session.completed')); await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 0);
  await events.noteNativeEvent({ server_id: server, session_id: session, kind: 'session.execution.succeeded', event_id: 'evt_stale', created: Date.now() - 60000 }); await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 0);
  await events.noteNativeEvent({ server_id: server, session_id: session, kind: 'session.execution.failed', event_id: 'evt_wrong_outcome', created: Date.now() }); await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 0);
  const created = Date.now(); const native = { server_id: server, session_id: session, kind: 'session.execution.succeeded', event_id: 'evt_fresh', created };
  await events.noteNativeEvent(native); await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 1); assert.equal(calls.find(e => e.eventId).timestamp, new Date(created).toISOString());
  await events.noteNativeEvent(native); await events.pollManaged(); await events.deliverDue(); assert.equal(calls.filter(e => e.eventId).length, 1);
});

test('actual authenticated MCP facade: pinned ChatGPT server/session subscriptions, reconnect dedup and authority revoke', { timeout: 30000 }, async t => {
  const dir = await directory(t), { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'fixture', alg: 'RS256', use: 'sig' }; let outcome, permissions = ['per_pending'], idle = true;
  const backend = createServer((req, res) => { res.setHeader('content-type', 'application/json');
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    assert.equal(req.method, 'GET');
    if (req.url === '/api/event') {
      res.setHeader('content-type', 'text/event-stream');
      res.write('data: {"type":"server.connected"}\n\n');
      const timer = setTimeout(() => res.end(), 15000);
      res.on('close', () => clearTimeout(timer)); return;
    }
    if (req.url === `/api/session/${session}/permission`) return res.end(JSON.stringify({ data: permissions.map(id => ({ id, sessionID: session, text: 'SECRET' })) }));
    const item = { id: session, projectID: 'private/path', title: 'SECRET', outcome, time: idle ? { idle: 1 } : {} };
    res.end(JSON.stringify(req.url.startsWith('/api/session?') ? { data: [item], cursor: {} } : { data: item }));
  }); await listen(backend); t.after(() => close(backend)); const origin = `http://127.0.0.1:${backend.address().port}`;
  const registration = join(dir, 'service.json'), module = join(dir, 'client', 'service.mjs'), capability = join(dir, 'capability.json');
  await fs.mkdir(dirname(module)); await fs.writeFile(registration, '{}', { mode: 0o600 }); await fs.writeFile(module, `export const discover=async()=>({url:${JSON.stringify(origin)},auth:{}});export const headers=()=>({});`, { mode: 0o600 });
  const reserve = createServer(); await listen(reserve); const port = reserve.address().port; await close(reserve);
  const config = { public_origin: 'https://workrelay.example', issuer: origin, jwks_uri: origin + '/jwks', audience: 'https://workrelay.example/mcp', principal: 'alice', owner: 'alice', bridge_config: '/unused-fixture', port, events_enabled: true, events_state_path: join(dir, 'events.json'), revocation_file: join(dir, 'revocations.json'), managed_supervisor_file: capability, managed_server: { server: origin, service_registration: registration, client_service_module: module } };
  const binding = { ...config.managed_server, enabled: true, revoked: false, issuer: origin, audience: config.audience, subject: 'alice', client_id: client };
  await fs.writeFile(capability, JSON.stringify(binding), { mode: 0o600 }); await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }), { mode: 0o600 });
  const calls = [], options = { testIssuer: true, invoke: async () => ({ error: 'no ordinary fixture tasks' }), eventTransport: callback(calls), eventIntervalMs: 50 };
  let gateway = createGateway(config, options); await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
  t.after(async () => { await gateway.stopEvents(); await close(gateway); });
  const post = async (method, params = {}, overrides = {}) => {
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: client, ...overrides }).setProtectedHeader({ alg: 'RS256', kid: 'fixture' }).setIssuer(origin).setAudience(config.audience).setSubject(overrides.sub ?? 'alice').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream', connection: 'close', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }) });
    return { status: response.status, body: await response.json() };
  };
  const filter = subscription(managedServerID(binding));
  assert.ok((await post('events/list')).body.result.events.some(e => e.name === 'session.needs_input'));
  assert.equal((await post('events/subscribe', filter, { client_id: 'other' })).status, 403);
  assert.equal((await post('events/subscribe', filter, { sub: 'bob' })).status, 403);
  assert.equal((await post('events/subscribe', subscription('srv_' + 'c'.repeat(64)))).status, 403);
  assert.ok((await post('events/subscribe', filter)).body.result.id);
  await until(() => calls.some(e => e.name === 'session.needs_input'));
  await gateway.stopEvents(); await close(gateway); gateway = createGateway(config, options); await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
  await new Promise(resolve => setTimeout(resolve, 400)); assert.equal(calls.filter(e => e.name === 'session.needs_input').length, 1);
  const failing = (await post('events/subscribe', subscription(managedServerID(binding), 'session.failed', null))).body.result.id; assert.ok(failing);
  permissions = []; idle = false;
  await until(async () => JSON.parse(await fs.readFile(config.events_state_path)).subscriptions[failing]?.observations[session]?.lastTerminal === null);
  outcome = 'failed'; await until(() => calls.some(e => e.name === 'session.failed'));
  assert.ok(!JSON.stringify(calls).includes('SECRET'));
  await post('events/unsubscribe', filter); binding.revoked = true; await fs.writeFile(capability, JSON.stringify(binding), { mode: 0o600 });
  assert.equal((await post('events/subscribe', filter)).status, 403);
  await until(async () => Object.keys(JSON.parse(await fs.readFile(config.events_state_path)).subscriptions).length === 0);
});
