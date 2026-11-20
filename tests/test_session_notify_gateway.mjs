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

test('MCP create/message register a per-session webhook; events reach it; notify tool sets, reports and clears', async t => {
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
    session_notify: { enabled: true, stall_minutes: 10 } }, { testIssuer: true });
  await fs.writeFile(capability, JSON.stringify({ ...config.managed_server, enabled: true, revoked: false, issuer: origin, audience: config.audience, subject: 'alice', client_id: client }), { mode: 0o600 });
  await fs.writeFile(config.bridge_config, JSON.stringify({ directory: dir, managed_allowed_directories: [dir] }), { mode: 0o600 });
  const invoked = [], delivered = [];
  const gateway = createGateway(config, { testIssuer: true,
    invoke: async (_config, command, input) => {
      invoked.push(input);
      if (input.action === 'create') return { operation_id: input.operation_id, session_id: root, phase: 'created' };
      return { operation_id: input.operation_id, session_id: input.session_id, phase: 'queued' };
    },
    notifyTransport: async (url, { body, headers }) => { delivered.push({ url, headers, event: JSON.parse(body) }); return { status: 202, body: '' }; } });
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
