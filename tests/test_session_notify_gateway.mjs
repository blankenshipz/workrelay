import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import { exportJWK, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { createGateway, validateConfig } from '../src/workrelay/mcp.mjs';

const client = 'https://chatgpt.com/oauth/client.json';
const root = 'ses_notifyroot000000000000001';
const child = 'ses_notifychild00000000000001';
const listen = s => new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
const close = s => new Promise(resolve => { s.close(resolve); s.closeAllConnections(); });
const HOOK = 'https://hooks.grok.example.com/routines/r1/trigger';

async function setup(t, notifyExtra = () => ({}), gatewayOptions = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-notify-gw-')); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'test', alg: 'RS256', use: 'sig' };
  const native = { active: {}, permissions: [], root: { id: root, projectID: 'project', title: 'Deploy fix', agent: 'harness-router', location: { directory: dir }, time: { created: 1, updated: 1 } } };
  const backend = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.url === '/api/project') return res.end(JSON.stringify([{ id: 'project', name: 'p', canonical: dir }]));
    if (req.url === '/api/session/active') return res.end(JSON.stringify({ data: native.active }));
    if (req.url === `/api/session/${root}`) return res.end(JSON.stringify({ data: native.root }));
    if (req.url === `/api/session/${root}/permission`) return res.end(JSON.stringify({ data: [] }));
    if (req.url === `/api/session/${child}/permission`) return res.end(JSON.stringify({ data: native.permissions }));
    if (req.url.startsWith('/api/session?') && new URL(req.url, 'http://x').searchParams.get('parentID') === root)
      return res.end(JSON.stringify({ data: native.child ? [native.child] : [], cursor: {} }));
    if (req.url.startsWith('/api/session?')) return res.end(JSON.stringify({ data: [], cursor: {} }));
    res.statusCode = 404; res.end('{}');
  });
  await listen(backend); t.after(() => close(backend));
  const origin = `http://127.0.0.1:${backend.address().port}`;
  const registration = join(dir, 'service.json'), module = join(dir, 'client', 'dist', 'service.js'), capability = join(dir, 'managed', 'capability.json');
  await fs.mkdir(dirname(module), { recursive: true }); await fs.mkdir(dirname(capability), { mode: 0o700 });
  await fs.writeFile(join(dir, 'client', 'package.json'), '{"type":"module"}');
  await fs.writeFile(registration, '{}', { mode: 0o600 });
  await fs.writeFile(module, `export const discover=async()=>({url:${JSON.stringify(origin)},auth:{}});export const headers=()=>({});`, { mode: 0o600 });
  const reserve = createServer(); await listen(reserve); const port = reserve.address().port; await close(reserve);
  const config = validateConfig({ public_origin: 'https://workrelay.test', issuer: origin, jwks_uri: origin + '/jwks', audience: 'https://workrelay.test/mcp',
    principal: 'alice', owner: 'alice', bridge_config: join(dir, 'bridge.json'), port, managed_supervisor_file: capability,
    managed_server: { server: origin, service_registration: registration, client_service_module: module },
    session_notify: { enabled: true, stall_minutes: 10, ...notifyExtra(dir) } }, { testIssuer: true });
  await fs.writeFile(capability, JSON.stringify({ ...config.managed_server, enabled: true, revoked: false, issuer: origin, audience: config.audience, subject: 'alice', client_id: client }), { mode: 0o600 });
  await fs.writeFile(config.bridge_config, JSON.stringify({ directory: dir, managed_allowed_directories: [dir] }), { mode: 0o600 });
  const invoked = [], delivered = [];
  const gateway = createGateway(config, { testIssuer: true,
    invoke: async (_config, command, input) => {
      invoked.push(input);
      if (input.action === 'create') return { operation_id: input.operation_id, session_id: root, phase: 'created' };
      return { operation_id: input.operation_id, session_id: input.session_id, phase: 'queued' };
    },
    ...gatewayOptions, notifyTransport: async (url, { body, headers }) => { delivered.push({ url, headers, event: JSON.parse(body) }); return { status: 202, body: '' }; } });
  await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve)); t.after(() => close(gateway));
  const call = async (name, args) => {
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: client }).setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(origin).setAudience(config.audience).setSubject('alice').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
    const sdk = new Client({ name: 'notify-test', version: '1' });
    try {
      await sdk.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`),
        { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
      return { result: await sdk.callTool({ name, arguments: args }), tools: (await sdk.listTools()).tools };
    } finally { await sdk.close(); }
  };
  const project = 'project_' + createHash('sha256').update('project').digest('hex');
  return { dir, call, gateway, delivered, invoked, native, project };
}

test('MCP create/message register a per-session webhook; events reach it; notify tool sets, reports and clears', async t => {
  const { dir, call, gateway, delivered, invoked, native, project } = await setup(t);
  // Invalid target: refused before any operation is attempted.
  const bad = await call('workrelay_server_create', { operation_id: 'op-bad', project_id: project, title: 'x', notify: { url: 'http://127.0.0.1/hook' } });
  assert.equal(bad.result.isError, true); assert.equal(bad.result.structuredContent.reason, 'invalid_url');
  assert.equal(invoked.length, 0);
  const tools = bad.tools.map(tool => tool.name);
  assert.ok(tools.includes('workrelay_server_notify'));
  assert.match(bad.tools.find(tool => tool.name === 'workrelay_server_create').description, /Grok Bot routine webhook/);

  const created = await call('workrelay_server_create', { operation_id: 'op-1', project_id: project, title: 'Deploy fix',
    notify: { url: HOOK, header_name: 'X-Routine-Secret', header_value: 'hook-secret-1' } });
  assert.notEqual(created.result.isError, true, JSON.stringify(created.result));
  assert.equal(created.result.structuredContent.notify.enabled, true);
  assert.equal(created.result.structuredContent.notify.url_host, 'hooks.grok.example.com');
  assert.doesNotMatch(JSON.stringify(created.result), /hook-secret-1|routines\/r1/);
  assert.ok(invoked.every(input => !('notify' in input)), 'notify never reaches the durable operation');
  const state = JSON.parse(await fs.readFile(join(dir, 'managed', 'session-notify.json'), 'utf8'));
  assert.equal(state.targets[root].header_value, 'hook-secret-1');
  assert.equal((await fs.stat(join(dir, 'managed', 'session-notify.json'))).mode & 0o777, 0o600);

  // Message arms the run; a child asks for permission -> one immediate event.
  await call('workrelay_server_message', { session_id: root, operation_id: 'op-2', text: 'Deploy it' });
  native.active = { [root]: { type: 'running' }, [child]: { type: 'running' } };
  native.child = { id: child, parentID: root, projectID: 'project', agent: 'harness-builder', location: { directory: dir }, time: { updated: 5 } };
  native.permissions = [{ id: 'per_abc', sessionID: child, action: 'shell', resources: ['docker compose --env-file ../.env up -d'] }];
  await gateway.sessionNotifier.tick();
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0].url, HOOK); assert.equal(delivered[0].headers['X-Routine-Secret'], 'hook-secret-1');
  assert.deepEqual(delivered[0].event.asks, [{ permission_id: 'per_abc', child_session_id: child, action: 'shell',
    resource_preview: ['docker compose --env-file ../.env up -d'], resources_omitted: 0, directory: dir }]);
  await gateway.sessionNotifier.tick(); assert.equal(delivered.length, 1, 'deduped');
  // Approved elsewhere; the run finishes -> completion event.
  native.permissions = []; native.active = {};
  native.child = { ...native.child, outcome: 'succeeded', time: { updated: 9, idle: 9 } };
  native.root = { ...native.root, outcome: 'succeeded', time: { created: 1, updated: 10, idle: Date.now() } };
  await gateway.sessionNotifier.tick();
  assert.equal(delivered.length, 2); assert.equal(delivered[1].event.type, 'workrelay.session.finished');
  assert.deepEqual(delivered[1].event.next, { tool: 'workrelay_server_read', arguments: { session_id: root, include_messages: true } });

  const status = await call('workrelay_server_notify', { session_id: root, action: 'status' });
  assert.equal(status.result.structuredContent.delivered, 2);
  assert.doesNotMatch(JSON.stringify(status.result), /hook-secret-1/);
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'clear', url: HOOK })).result.isError, true);
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'set', url: 'https://10.1.2.3/x' })).result.structuredContent.reason, 'invalid_url');
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'clear' })).result.structuredContent.cleared, true);
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'set', url: HOOK })).result.structuredContent.enabled, true);
  // Unknown session: denied by the managed session check, nothing registered.
  assert.equal((await call('workrelay_server_notify', { session_id: 'ses_unknown0000000000001', action: 'set', url: HOOK })).result.isError, true);
});

test('without session_notify the notify tool and argument do not exist', async () => {
  assert.throws(() => validateConfig({ public_origin: 'https://w.test', issuer: 'https://w.test', jwks_uri: 'https://w.test/jwks', audience: 'https://w.test/mcp',
    principal: 'a', owner: 'a', bridge_config: '/b', port: 1, session_notify: { enabled: true } }), /session_notify requires managed_supervisor_file/);
});

test('gateway default target: attached on create via MCP with secrets from a 0600 file; status redacted; notify:false opts out', async t => {
  let secretsFile;
  const { dir, call, gateway, delivered, native } = await setup(t, dir => {
    secretsFile = join(dir, 'secrets', 'notify.json');
    return { secrets_file: secretsFile, default_targets: [{ name: 'grokbot_harny', secret: 'grokbot_harny', directories: [dir], clients: [client] }] };
  });
  await fs.mkdir(dirname(secretsFile), { mode: 0o700 });
  await fs.writeFile(secretsFile, JSON.stringify({ version: 1, targets: { grokbot_harny: { url: HOOK, header_name: 'X-Routine-Secret', header_value: 'default-secret-1',
    hmac_secret: 'whsec_' + Buffer.from('0123456789abcdef0123456789abcdef').toString('base64') } } }), { mode: 0o600 });
  const project = 'project_' + createHash('sha256').update('project').digest('hex');
  const created = await call('workrelay_server_create', { operation_id: 'op-d1', project_id: project, title: 'Deploy fix' });
  const notify = created.result.structuredContent.notify;
  assert.equal(notify.enabled, true, JSON.stringify(created.result)); assert.equal(notify.source, 'gateway_default'); assert.equal(notify.default_target, 'grokbot_harny');
  assert.equal(notify.url_host, 'hooks.grok.example.com'); assert.equal(notify.signed, true); assert.equal(notify.configured, true);
  assert.doesNotMatch(JSON.stringify(created.result), /default-secret-1|whsec_|routines\/r1/);
  for (const name of ['workrelay_server_create', 'workrelay_server_message', 'workrelay_server_resume'])
    assert.match(created.tools.find(tool => tool.name === name).description, /do not poll or wait/);
  assert.match(created.tools.find(tool => tool.name === 'workrelay_server_notify').description, /Slack/);
  const state = await fs.readFile(join(dir, 'managed', 'session-notify.json'), 'utf8');
  assert.doesNotMatch(state, /default-secret-1|whsec_|routines/);

  await call('workrelay_server_message', { session_id: root, operation_id: 'op-d2', text: 'Deploy it' });
  native.active = { [root]: { type: 'running' } };
  await gateway.sessionNotifier.tick();
  native.active = {}; native.root = { ...native.root, outcome: 'succeeded', time: { created: 1, updated: 10, idle: Date.now() } };
  await gateway.sessionNotifier.tick();
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0].url, HOOK); assert.equal(delivered[0].headers['X-Routine-Secret'], 'default-secret-1');
  assert.match(delivered[0].headers['webhook-signature'], /^v1,/);
  assert.equal(delivered[0].event.type, 'workrelay.session.finished'); assert.equal(delivered[0].event.directory, dir);
  assert.match(delivered[0].event.server_id, /^srv_[a-f0-9]{64}$/);

  const status = (await call('workrelay_server_notify', { session_id: root, action: 'status' })).result.structuredContent;
  assert.equal(status.source, 'gateway_default'); assert.equal(status.delivered, 1);
  assert.doesNotMatch(JSON.stringify(status), /default-secret-1|whsec_|routines/);
  // Opt out per session; a later message does not re-attach the default.
  const out = await call('workrelay_server_message', { session_id: root, operation_id: 'op-d3', text: 'more', notify: false });
  assert.equal(out.result.structuredContent.notify.enabled, false); assert.equal(out.result.structuredContent.notify.opted_out, true);
  const later = await call('workrelay_server_message', { session_id: root, operation_id: 'op-d4', text: 'again' });
  assert.equal(later.result.structuredContent.notify, undefined);
  const check = (await call('workrelay_server_notify', { session_id: root, action: 'status' })).result.structuredContent;
  assert.equal(check.opted_out, true); assert.equal(check.default_available.default_target, 'grokbot_harny');
  // set without url re-attaches the default; set with target fields but no url is refused.
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'set', header_name: 'X-A', header_value: 'v' })).result.structuredContent.reason, 'url_required_with_target_fields');
  const again = (await call('workrelay_server_notify', { session_id: root, action: 'set' })).result.structuredContent;
  assert.equal(again.source, 'gateway_default'); assert.equal(again.enabled, true);
});

test('client scope: an agent registers its own listener once; it applies to every session it delegates; test action verifies it', async t => {
  const { call, gateway, delivered, native, project } = await setup(t);
  const sig = 'whsec_' + Buffer.from('client-own-secret-0123456789abcd').toString('base64');
  // Nothing registered yet: create attaches nothing, client test has nothing to send.
  assert.equal((await call('workrelay_server_notify', { action: 'check', scope: 'client' })).result.structuredContent.client_default, null);
  assert.equal((await call('workrelay_server_notify', { action: 'test', scope: 'client' })).result.structuredContent.reason, 'no_client_default');
  // Scope/field validation.
  assert.equal((await call('workrelay_server_notify', { action: 'set', url: HOOK })).result.structuredContent.reason, 'session_id_required');
  assert.equal((await call('workrelay_server_notify', { action: 'set', scope: 'client', session_id: root, url: HOOK })).result.structuredContent.reason, 'session_id_not_allowed_for_client_scope');
  assert.equal((await call('workrelay_server_notify', { action: 'set', scope: 'client', url: 'https://127.0.0.1/x' })).result.structuredContent.reason, 'invalid_url');

  const set = (await call('workrelay_server_notify', { action: 'set', scope: 'client', url: HOOK, header_name: 'X-Routine-Secret', header_value: 'client-secret-1', hmac_secret: sig })).result;
  assert.ok(!set.isError);
  assert.equal(set.structuredContent.client_id, client); assert.equal(set.structuredContent.configured, true); assert.equal(set.structuredContent.signed, true);
  assert.doesNotMatch(JSON.stringify(set), /client-secret-1|whsec_|routines\/r1/);
  const check = (await call('workrelay_server_notify', { action: 'check', scope: 'client' })).result.structuredContent;
  assert.equal(check.client_default.url_host, 'hooks.grok.example.com'); assert.equal(check.client_default.updated_by, 'mcp');

  // Test action: one signed workrelay.test event, not counted as a session delivery.
  const tested = (await call('workrelay_server_notify', { action: 'test', scope: 'client' })).result;
  assert.equal(tested.structuredContent.ok, true); assert.equal(tested.structuredContent.status, 202);
  assert.equal(delivered.length, 1); assert.equal(delivered[0].event.type, 'workrelay.test');
  assert.equal(delivered[0].headers['X-Routine-Secret'], 'client-secret-1'); assert.match(delivered[0].headers['webhook-signature'], /^v1,/);
  assert.equal((await call('workrelay_server_notify', { action: 'test', scope: 'client' })).result.structuredContent.reason, 'test_rate_limited');

  // Every session this client delegates gets it automatically (no notify argument).
  const created = (await call('workrelay_server_create', { operation_id: 'op-c1', project_id: project, title: 'Deploy fix' })).result.structuredContent;
  assert.equal(created.notify.enabled, true); assert.equal(created.notify.source, 'client_default'); assert.equal(created.notify.client_id, client);
  assert.doesNotMatch(JSON.stringify(created), /client-secret-1|whsec_|routines\/r1/);
  const status = (await call('workrelay_server_notify', { session_id: root, action: 'check' })).result.structuredContent;
  assert.equal(status.source, 'client_default');
  native.root = { ...native.root, outcome: 'succeeded', time: { created: 1, updated: 10, idle: Date.now() } };
  await gateway.sessionNotifier.tick();
  // A per-call notify still overrides.
  const override = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-c2', text: 'x', notify: { url: 'https://other.example.com/hook' } })).result.structuredContent;
  assert.equal(override.notify.source, 'per_call');
  // Clearing the client default: new sessions get nothing.
  assert.equal((await call('workrelay_server_notify', { action: 'clear', scope: 'client' })).result.structuredContent.cleared, true);
  assert.equal((await call('workrelay_server_notify', { action: 'check', scope: 'client' })).result.structuredContent.client_default, null);
});

test('agent scope: agents sharing one MCP client each get their own listener; agent is remembered per session; falls back to client', async t => {
  const { call, gateway, delivered, native, project } = await setup(t);
  const HARNY = 'https://hooks.grok.example.com/routines/harny/trigger', SCANNER = 'https://hooks.grok.example.com/routines/scanner/trigger';
  // Validation.
  assert.equal((await call('workrelay_server_notify', { action: 'set', scope: 'agent', url: HARNY })).result.structuredContent.reason, 'agent_required');
  assert.equal((await call('workrelay_server_notify', { action: 'set', scope: 'agent', agent: 'Harny', session_id: root, url: HARNY })).result.structuredContent.reason, 'session_id_not_allowed_for_agent_scope');
  assert.equal((await call('workrelay_server_notify', { action: 'set', scope: 'client', agent: 'Harny', url: HARNY })).result.structuredContent.reason, 'agent_not_allowed_for_client_scope');
  for (const bad of ['', 'Harny Bot', 'a'.repeat(65), '__proto__', 'é']) assert.equal((await call('workrelay_server_notify', { action: 'check', scope: 'agent', agent: bad })).result.isError, true, bad);
  assert.equal((await call('workrelay_server_notify', { action: 'test', scope: 'agent', agent: 'Harny' })).result.structuredContent.reason, 'no_agent_default');

  const set = (await call('workrelay_server_notify', { action: 'set', scope: 'agent', agent: 'Harny', url: HARNY, header_name: 'X-Hook-Token', header_value: 'harny-secret' })).result;
  assert.ok(!set.isError, JSON.stringify(set)); assert.equal(set.structuredContent.agent, 'Harny'); assert.equal(set.structuredContent.client_id, client);
  assert.doesNotMatch(JSON.stringify(set), /harny-secret|routines\/harny/);
  await call('workrelay_server_notify', { action: 'set', scope: 'agent', agent: 'Scanner', url: SCANNER });
  await call('workrelay_server_notify', { action: 'set', scope: 'client', url: HOOK });
  // Registering Scanner did not overwrite Harny (the r18 shared-client problem).
  const harny = (await call('workrelay_server_notify', { action: 'check', scope: 'agent', agent: 'Harny' })).result.structuredContent;
  assert.equal(harny.agent_default.secret_header, 'X-Hook-Token'); assert.equal(harny.agent_default.agent, 'Harny');
  assert.equal((await call('workrelay_server_notify', { action: 'check', scope: 'client' })).result.structuredContent.client_default.secret_header, null);
  const tested = (await call('workrelay_server_notify', { action: 'test', scope: 'agent', agent: 'Harny' })).result.structuredContent;
  assert.equal(tested.ok, true); assert.equal(tested.source, 'agent_default');
  assert.equal(delivered.at(-1).url, HARNY); assert.equal(delivered.at(-1).event.scope, 'agent'); assert.equal(delivered.at(-1).event.agent, 'Harny');

  // create with agent attaches that agent's listener; message without agent keeps it (remembered).
  const tools = (await call('workrelay_server_notify', { action: 'check', scope: 'agent', agent: 'Harny' })).tools;
  assert.match(tools.find(tool => tool.name === 'workrelay_server_create').description, /Always pass agent/);
  const created = (await call('workrelay_server_create', { operation_id: 'op-a1', project_id: project, title: 'Deploy fix', agent: 'Harny' })).result.structuredContent;
  assert.equal(created.notify.source, 'agent_default'); assert.equal(created.notify.agent, 'Harny');
  const later = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-a2', text: 'go' })).result.structuredContent;
  assert.equal(later.notify.source, 'agent_default'); assert.equal(later.notify.agent, 'Harny');
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'check' })).result.structuredContent.session_agent, 'Harny');
  native.active = { [root]: { type: 'running' }, [child]: { type: 'running' } };
  native.child = { id: child, parentID: root, projectID: 'project', agent: 'harness-builder', location: { directory: '/x' }, time: { updated: 5 } };
  native.permissions = [{ id: 'per_agent1', sessionID: child, action: 'shell', resources: ['ls'] }];
  const before = delivered.length;
  await gateway.sessionNotifier.tick();
  assert.equal(delivered.length, before + 1); assert.equal(delivered.at(-1).url, HARNY); assert.equal(delivered.at(-1).headers['X-Hook-Token'], 'harny-secret');

  // An unregistered agent name is reported and does not detach Harny.
  const typo = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-a2b', text: 'go', agent: 'harny' })).result.structuredContent;
  assert.equal(typo.notify.agent, 'Harny'); assert.equal(typo.notify.agent_listener, 'not_registered');
  // A different agent delegating the session takes it over.
  const scanner = (await call('workrelay_server_resume', { session_id: root, operation_id: 'op-a3', text: 'go', agent: 'Scanner' })).result.structuredContent;
  assert.equal(scanner.notify.agent, 'Scanner');
  // Its listener removed: falls back to the client listener on the next tick.
  assert.equal((await call('workrelay_server_notify', { action: 'clear', scope: 'agent', agent: 'Scanner' })).result.structuredContent.cleared, true);
  await gateway.sessionNotifier.tick();
  const fallback = (await call('workrelay_server_notify', { session_id: root, action: 'check' })).result.structuredContent;
  assert.equal(fallback.source, 'client_default'); assert.equal(fallback.agent, undefined);
  // Re-registered: the session's agent listener takes over again.
  await call('workrelay_server_notify', { action: 'set', scope: 'agent', agent: 'Scanner', url: SCANNER });
  await gateway.sessionNotifier.tick();
  assert.equal((await call('workrelay_server_notify', { session_id: root, action: 'check' })).result.structuredContent.agent, 'Scanner');
  // Harny is still registered.
  assert.equal((await call('workrelay_server_notify', { action: 'check', scope: 'agent', agent: 'Harny' })).result.structuredContent.agent_default.configured, true);
});
