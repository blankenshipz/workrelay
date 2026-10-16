import test from 'node:test';
import assert from 'node:assert/strict';
import { createManagedReader } from '../src/workrelay/managed_server.mjs';
import { createGateway } from '../src/workrelay/mcp.mjs';
import { createServer } from 'node:http';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { exportJWK, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const client = 'https://chatgpt.com/oauth/client.json';
const root = 'ses_ec3ddf9ebffe9cDFhA0VKjmkRn';
const listen = s => new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
const close = s => new Promise(resolve => { s.close(resolve); s.closeAllConnections(); });

test('managed registration read boundary is pinned, revoked, bounded and sanitized', async () => {
  const b = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp',
    subject: 'alice', client_id: client, server: 'http://127.0.0.1:12345', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
  const expected = { issuer: b.issuer, audience: b.audience, principal: b.subject, managed_server: { ...b } };
  const claims = { iss: b.issuer, aud: b.audience, sub: b.subject, client_id: client };
  let binding = { ...b }, endpoint = b.server, moved = false, calls = 0, during;
  const reader = createManagedReader(expected, () => ({ ...binding }), {
    canonical: path => moved ? '/replacement' : path,
    stat: () => ({ isFile: () => true, isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, dev: 1, ino: 1, mtimeMs: 1 }),
    loadService: async () => ({ discover: async args => { assert.equal(args.file, b.service_registration); return { url: endpoint, auth: {} }; }, headers: () => ({}) }),
    fetcher: async (url, options) => {
      calls++; assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'manual');
      const session = { id: root, projectID: '/PRIVATE/SECRET_PROJECT?token=SECRET', title: 'SECRET_TITLE', metadata: { password: 'SECRET' }, location: { directory: '/PRIVATE' }, time: { idle: 1 } };
      if (during) during();
      return new Response(JSON.stringify(url.pathname === '/api/session' ? { data: [session], cursor: { next: 'page2' } } : { data: session }));
    },
  });
  const page = await reader('discover', {}, claims);
  assert.equal(page.items[0].session_id, root); assert.equal(page.next_cursor, 'page2');
  assert.match(page.items[0].project_id, /^project_[0-9a-f]{64}$/);
  assert.equal(page.projects[0].id, page.items[0].project_id);
  assert.equal(JSON.stringify(page).includes('SECRET'), false); assert.equal(JSON.stringify(page).includes('PRIVATE'), false);
  assert.equal((await reader('read', { session_id: root }, claims)).session_id, root);
  await reader('discover', { cursor: 'page2', limit: 1 }, claims);
  const before = calls;
  for (const bad of [{ ...claims, sub: 'bob' }, { ...claims, client_id: 'other' }, { ...claims, aud: 'other' }, undefined])
    await assert.rejects(reader('discover', {}, bad));
  for (const change of [{ revoked: true }, { enabled: false }, { server: 'http://127.0.0.1:9999' }, { service_registration: '/other/service.json' }]) {
    binding = { ...b, ...change }; await assert.rejects(reader('discover', {}, claims));
  }
  binding = { ...b }; moved = true; await assert.rejects(reader('discover', {}, claims)); moved = false;
  endpoint = 'http://127.0.0.1:9999'; await assert.rejects(reader('discover', {}, claims)); endpoint = b.server;
  await assert.rejects(reader('write', {}, claims));
  await assert.rejects(reader('read', { session_id: '../root' }, claims));
  assert.equal(calls, before);
  during = () => { binding.revoked = true; }; await assert.rejects(reader('discover', {}, claims));
});

test('real MCP facade passes verified client identity to opt-in managed reads', async t => {
  const dir = await fs.mkdtemp(join(dirname(fileURLToPath(import.meta.url)), '.workrelay-head-managed-'));
  await fs.chmod(dir, 0o700); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'test', alg: 'RS256', use: 'sig' };
  let reads = 0;
  const session = { id: root, projectID: 'project', agent: 'existing-owner', parentID: 'ses_parent',
    model: { providerID: 'openai', id: 'fixture' }, metadata: { intent: 'unchanged' }, time: {} };
  const posts = [], inbox = []; let dropAck = false;
  const guardEntry = join(dir, 'runtime', 'plugins', 'subscription-guard', 'index.mjs');
  const backend = createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.method === 'POST') {
      let text = ''; for await (const chunk of req) text += chunk;
      const body = text ? JSON.parse(text) : null; posts.push({ path: req.url, body });
      if (req.url === `/api/session/${root}/interrupt?resume=false`) return res.end(JSON.stringify({ interrupted: true }));
      assert.equal(req.url, `/api/session/${root}/prompt`);
      assert.deepEqual(Object.keys(body).sort(), ['delivery', 'id', 'text']); assert.equal(body.delivery, 'queue');
      const item = { id: body.id, sessionID: root, delivery: 'queue' }; inbox.push(item);
      if (dropAck) { res.destroy(); return; }
      return res.end(JSON.stringify({ data: item }));
    }
    assert.equal(req.method, 'GET');
    if (req.url === '/api/plugin') return res.end(JSON.stringify({ data: [{ id: 'subscription.guard', state: { status: 'active' }, source: { type: 'local', path: guardEntry } }] }));
    if (req.url === '/api/integration/openai') return res.end(JSON.stringify({ data: { id: 'openai', connections: [{ type: 'credential', method: 'oauth' }] } }));
    if (req.url === '/api/provider/openai') return res.end(JSON.stringify({ data: { id: 'openai', package: '@opencode/ai/providers/openai' } }));
    if (req.url === '/api/model') return res.end(JSON.stringify({ data: [{ id: 'fixture', providerID: 'openai', package: '@opencode/ai/providers/openai' }] }));
    if (req.url === `/api/session/${root}`) return res.end(JSON.stringify({ data: session }));
    if (req.url === `/api/session/${root}/inbox`) return res.end(JSON.stringify({ data: inbox }));
    if (req.url.includes('/message/')) { res.statusCode = 404; return res.end('{}'); }
    reads++;
    res.end(JSON.stringify({ data: [{ id: root, projectID: 'project', time: {} }], cursor: {} }));
  });
  await listen(backend); t.after(() => close(backend));
  const origin = `http://127.0.0.1:${backend.address().port}`;
  const registration = join(dir, 'service.json'), module = join(dir, 'client', 'dist', 'promise', 'service.js'), capability = join(dir, 'capability.json');
  await fs.mkdir(dirname(module), { recursive: true });
  await fs.writeFile(join(dir, 'client', 'package.json'), '{"type":"module"}');
  await fs.writeFile(registration, '{}', { mode: 0o600 });
  await fs.writeFile(module, `export const discover=async()=>({url:${JSON.stringify(origin)},auth:{}});export const headers=()=>({});`, { mode: 0o600 });
  const reserve = createServer(); await listen(reserve);
  const port = reserve.address().port; await close(reserve);
  const config = { public_origin: 'https://workrelay.test', issuer: origin, jwks_uri: origin + '/jwks', audience: 'https://workrelay.test/mcp',
    principal: 'alice', owner: 'alice', bridge_config: join(dir, 'bridge.json'), port, managed_supervisor_file: capability,
    managed_server: { server: origin, service_registration: registration, client_service_module: module } };
  const binding = { ...config.managed_server, enabled: true, revoked: false, issuer: origin, audience: config.audience, subject: 'alice', client_id: client };
  await fs.writeFile(capability, JSON.stringify(binding), { mode: 0o600 });
  const quota = join(dir, 'quota');
  await fs.writeFile(quota, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  const guardFiles = { entry: guardEntry, implementation: join(dir, 'runtime', 'plugins', 'subscription-guard.mjs'), financial: join(dir, 'config', 'guard-validation.mjs') };
  const hashes = {};
  for (const [name, file] of Object.entries(guardFiles)) {
    await fs.mkdir(dirname(file), { recursive: true });
    await fs.writeFile(file, '// isolated guard fixture\n', { mode: 0o600 });
    hashes[name] = createHash('sha256').update(await fs.readFile(file)).digest('hex');
  }
  const bridge = { transport: 'installed-client', client_service_module: module, service_registration: registration,
    server: origin, node_executable: process.execPath, directory: dir, state_dir: dir, model: session.model,
    authorized_owner: 'alice', quota_command: quota, guard_entry: guardEntry, guard_file_hashes: hashes,
    managed_identity: { issuer: origin, audience: config.audience, principal: 'alice' },
    managed_server: config.managed_server, managed_supervisor_file: capability };
  await fs.writeFile(config.bridge_config, JSON.stringify(bridge), { mode: 0o600 });
  const gateway = createGateway(config, { testIssuer: true }); await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve)); t.after(() => close(gateway));
  const call = async (clientID, name = 'workrelay_server_discover', args = {}, tokenOptions = {}) => {
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: clientID }).setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(origin).setAudience(tokenOptions.audience ?? config.audience).setSubject(tokenOptions.subject ?? 'alice').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
    const sdk = new Client({ name: 'managed-test', version: '1' });
    try {
      await sdk.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.address().port}/mcp`),
        { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
      return { result: await sdk.callTool({ name, arguments: args }) };
    } finally { await sdk.close(); }
  };
  assert.equal((await call(client)).result.structuredContent.items[0].session_id, root);
  assert.equal(reads, 1);
  assert.equal((await call('other')).result.isError, true); assert.equal(reads, 1);
  await fs.writeFile(capability, JSON.stringify({ ...binding, revoked: true }));
  assert.equal((await call(client)).result.isError, true); assert.equal(reads, 1);
  await fs.writeFile(capability, JSON.stringify(binding));
  const message = { session_id: root, operation_id: 'first', text: 'isolated fixture message' };
  const sent = await call(client, 'workrelay_server_message', message);
  assert.equal(sent.result.isError, false, JSON.stringify(sent.result));
  assert.equal(sent.result.structuredContent.phase, 'queued');
  assert.equal(posts.length, 1);
  assert.equal((await call(client, 'workrelay_server_message', message)).result.structuredContent.phase, 'queued');
  assert.equal(posts.length, 1);
  const raced = await Promise.all([call(client, 'workrelay_server_message', { ...message, operation_id: 'race' }),
    call(client, 'workrelay_server_message', { ...message, operation_id: 'race' })]);
  assert.ok(raced.some(value => value.result.structuredContent?.phase === 'queued'));
  assert.equal(posts.length, 2);
  assert.equal((await call('other', 'workrelay_server_message', { ...message, operation_id: 'bad-client' })).result.isError, true);
  await fs.writeFile(quota, '#!/bin/sh\nexit 1\n');
  assert.equal((await call(client, 'workrelay_server_message', { ...message, operation_id: 'financial-denial' })).result.isError, true);
  assert.equal(posts.length, 2);
  const stopped = await call(client, 'workrelay_server_interrupt', { session_id: root, operation_id: 'stop' });
  assert.equal(stopped.result.structuredContent.phase, 'interrupt_acknowledged');
  assert.equal(posts.length, 3);
  assert.equal(posts[2].path, `/api/session/${root}/interrupt?resume=false`);
  assert.equal(session.agent, 'existing-owner'); assert.equal(session.metadata.intent, 'unchanged');
  await assert.rejects(call(client, 'workrelay_server_message', message, { audience: client }));
  await assert.rejects(call(client, 'workrelay_server_message', message, { subject: 'other' }));
  await fs.writeFile(capability, JSON.stringify({ ...binding, server: 'http://127.0.0.1:1' }));
  assert.equal((await call(client, 'workrelay_server_message', message)).result.isError, true);
  await fs.writeFile(capability, JSON.stringify({ ...binding, revoked: true }));
  assert.equal((await call(client, 'workrelay_server_interrupt', { session_id: root, operation_id: 'revoked-stop' })).result.isError, true);
  assert.equal(posts.length, 3);
  await fs.writeFile(capability, JSON.stringify(binding)); await fs.writeFile(quota, '#!/bin/sh\nexit 0\n');
  dropAck = true;
  const uncertain = { ...message, operation_id: 'lost-ack' };
  assert.equal((await call(client, 'workrelay_server_message', uncertain)).result.isError, true);
  dropAck = false;
  assert.equal((await call(client, 'workrelay_server_message', uncertain)).result.structuredContent.phase, 'queued_observed');
  assert.equal(posts.length, 4, 'lost acknowledgement reconciled from exact inbox ID without replay');
});
