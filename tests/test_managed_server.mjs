import test from 'node:test';
import assert from 'node:assert/strict';
import { createManagedReader, managedText } from '../src/workrelay/managed_server.mjs';
import { ATTESTATION_CHECK_IDS, createGateway, safeControlFailure } from '../src/workrelay/mcp.mjs';
import { catalogShape } from '../src/workrelay/mcp_observation.mjs';
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

test('control errors expose only finite code/effect/reason, never upstream text', () => {
  assert.deepEqual(safeControlFailure({ error: 'PRIVATE', code: 'CONTROL_NOT_SENT', effect: 'no_post_permitted', reason: 'PROJECT_WORKSPACE_MISMATCH', stack: 'PRIVATE' }), {
    error: 'Managed control denied or uncertain; inspect the original operation ID.', code: 'CONTROL_NOT_SENT', effect: 'no_post_permitted', reason: 'PROJECT_WORKSPACE_MISMATCH', denial_code: 'DENIAL_REASON_NOT_RECORDED', denied_at_ms: null, attestation_check_id: null });
  assert.doesNotMatch(JSON.stringify(safeControlFailure({ error: 'PRIVATE', code: 'PRIVATE', reason: 'PRIVATE', effect: 'PRIVATE' })), /PRIVATE/);
});

test('visible text preserves meaning, redacts established credentials before truncation', () => {
  const source = 'Fix navigation.\nCookie: session=hidden; second=hidden\nAuthorization: Bearer hidden\npassword="hidden words" token=hidden\nhttps://user:pass@example.test/path\n-----BEGIN PRIVATE KEY-----\nhidden\n-----END PRIVATE KEY-----\nsk-examplekey\nContinue safely.';
  const result = managedText(source);
  assert.match(result.text, /Fix navigation/); assert.match(result.text, /Continue safely/);
  assert.doesNotMatch(result.text, /hidden|user:pass|examplekey/);
  assert.equal(result.source, 'untrusted_session_text'); assert.equal(result.redacted, true);
  const long = managedText('Useful '.repeat(1000));
  assert.equal(long.text.length, 4000); assert.equal(long.omission, 'text_truncated');
  assert.equal(managedText(undefined).omission, 'text_unavailable');
});

test('managed registration read boundary is pinned, revoked, bounded and sanitized', async () => {
  const b = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp',
    subject: 'alice', client_id: client, server: 'http://127.0.0.1:12345', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
  const expected = { issuer: b.issuer, audience: b.audience, principal: b.subject, managed_server: { ...b } };
  const claims = { iss: b.issuer, aud: b.audience, sub: b.subject, client_id: client };
  let binding = { ...b }, endpoint = b.server, moved = false, calls = 0, during, foreign = false, messageRevocation = false, surfaceText, wrongSelection = false, nativeActive = {}, nativeForms = [];
  const reader = createManagedReader(expected, () => ({ ...binding }), {
    canonical: path => moved ? '/replacement' : path,
    stat: () => ({ isFile: () => true, isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, dev: 1, ino: 1, mtimeMs: 1 }),
    loadService: async () => ({ discover: async args => { assert.equal(args.file, b.service_registration); return { url: endpoint, auth: {} }; }, headers: () => ({}) }),
    fetcher: async (url, options) => {
      calls++; assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'manual');
      if (url.pathname.endsWith('/permission')) return new Response(JSON.stringify({ data: [] }));
      if (url.pathname.endsWith('/form')) return new Response(JSON.stringify({ data: nativeForms }));
      if (url.pathname === '/api/session/active') return new Response(JSON.stringify({ data: nativeActive }));
      if (url.searchParams.has('search')) assert.equal(url.searchParams.get('search'), 'release notes');
      const session = { id: root, projectID: '/PRIVATE/SECRET_PROJECT?token=SECRET', title: surfaceText ?? 'Useful project password=SECRET', metadata: { password: 'SECRET' }, location: { directory: '/PRIVATE' }, time: { idle: 1 }, outcome: 'succeeded' };
      if (during) during(session);
      if (url.pathname === '/api/event') return new Response('data: {}\n\n', { headers: { 'content-type': 'text/event-stream' } });
      if (url.pathname.endsWith('/message')) {
        assert.equal(url.pathname, `/api/session/${root}/message`);
        if (messageRevocation) binding.revoked = true;
        assert.equal(url.searchParams.get('limit'), '3');
        assert.equal(url.searchParams.has('order'), !url.searchParams.has('cursor'));
        return new Response(JSON.stringify({ data: [
          // Actual public SessionMessage.Base: id/time, no sessionID.
          { id: 'msg_user', time: { created: 1 }, ...(foreign ? { sessionID: 'ses_other' } : {}), type: 'user', text: surfaceText ?? 'Please repair navigation token=SECRET', files: [{ content: 'SECRET_FILE' }] },
          { id: 'msg_assistant', time: { created: 2 }, type: 'assistant', content: [{ type: 'text', text: surfaceText ?? 'Implemented navigation; live acceptance pending.', state: { encrypted: 'HIDDEN' } }, { type: 'reasoning', text: 'HIDDEN' }, { type: 'encrypted_reasoning', data: 'HIDDEN' }, { type: 'tool', output: 'SECRET_FILE' }] },
          { id: 'msg_system', time: { created: 3 }, type: 'system', text: 'HIDDEN' }
        ], cursor: { next: 'older' } }));
      }
      return new Response(JSON.stringify(url.pathname === '/api/session' ? { data: [session], cursor: { next: 'page2' } } : { data: { ...session, id: wrongSelection ? 'ses_other' : session.id } }));
    },
  });
  const page = await reader('discover', {}, claims);
  const opened = await reader('open_events', { signal: new AbortController().signal }, claims);
  assert.equal(opened.server_id, page.server_id); assert.match(opened.response.headers.get('content-type'), /text\/event-stream/);
  await opened.response.body.cancel();
  during = () => { binding.revoked = true; };
  await assert.rejects(reader('open_events', { signal: new AbortController().signal }, claims));
  binding = { ...b }; during = undefined;
  await reader('discover', { search: 'release notes' }, claims);
  await reader('discover', { search: 'release notes', cursor: 'page2' }, claims);
  await assert.rejects(reader('discover', { search: '\n' }, claims));
  assert.equal(page.items[0].session_id, root); assert.equal(page.next_cursor, 'page2');
  assert.match(page.items[0].project_id, /^project_[0-9a-f]{64}$/);
  assert.equal(page.projects[0].id, page.items[0].project_id);
  assert.equal(JSON.stringify(page).includes('SECRET'), false); assert.equal(JSON.stringify(page).includes('PRIVATE'), false);
  assert.equal((await reader('read', { session_id: root }, claims)).session_id, root);
  assert.equal(page.items[0].label, 'Useful project password=[REDACTED]');
  assert.equal(page.items[0].runtime_status, 'succeeded');
  assert.equal(page.items[0].task_outcome.status, 'unknown');
  during = session => { delete session.outcome; };
  const observed = await reader('events', { server_id: page.server_id, session_id: root }, claims);
  assert.equal(observed.items[0].state, 'idle', 'progress uses explicit native idle, not inferred running');
  during = undefined;
  nativeActive = { [root]: { type: 'running' } };
  assert.equal((await reader('read', { session_id: root }, claims)).runtime_status, 'running',
    'a current native drain overrides the historical last-completed outcome');
  nativeForms = [{ id: 'frm_pending', sessionID: root }];
  assert.equal((await reader('events', { server_id: page.server_id, session_id: root }, claims)).items[0].state, 'needs_input',
    'a pending form must outrank a concurrent active drain');
  nativeForms = []; nativeActive = {};
  const context = (await reader('read', { session_id: root, include_messages: true, limit: 3 }, claims)).context;
  assert.equal(context.next_cursor, 'older');
  assert.equal(context.items[0].text, 'Please repair navigation token=[REDACTED]');
  assert.equal(context.items[1].text, 'Implemented navigation; live acceptance pending.');
  assert.equal(context.items[2].omission, 'Non-user/assistant message excluded.');
  assert.deepEqual(context.visible_results.message_ids, ['msg_assistant']);
  assert.equal(context.visible_results.verification, 'unverified');
  assert.equal(context.visible_results.scope, 'this_page_only');
  assert.deepEqual(context.next_action, { tool: 'workrelay_server_read', arguments: { session_id: root, include_messages: true, limit: 3, cursor: 'older' } });
  const older = await reader('read', context.next_action.arguments, claims);
  assert.equal(Object.hasOwn(older.return_action.arguments, 'cursor'), false, 'return starts at newest state, not stale historical cursor');
  assert.equal(older.return_action.arguments.include_messages, true);
  assert.equal(older.progress.verification, 'unverified');
  const searched = await reader('discover', { search: 'release notes', limit: 1 }, claims);
  assert.deepEqual(searched.next_action.arguments, { cursor: 'page2', limit: 1, search: 'release notes' });
  assert.doesNotMatch(JSON.stringify(context), /SECRET|HIDDEN/);
  // Synthetic established formats, independently exercised through every public text surface.
  for (const credential of ['Basic dGVzdDpmaXh0dXJl', 'AKIA' + 'A'.repeat(16),
    ...['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'].map(prefix => prefix + 'SyntheticFixture123')]) {
    surfaceText = `Repair navigation ${credential} then verify results.`;
    const discovered = await reader('discover', {}, claims);
    const read = await reader('read', { session_id: root, include_messages: true, limit: 3 }, claims);
    for (const text of [discovered.items[0].label, discovered.items[0].title.text, read.label, read.title.text,
      read.context.items[0].text, read.context.items[1].text]) {
      assert.equal(text, 'Repair navigation [REDACTED] then verify results.');
    }
    assert.doesNotMatch(JSON.stringify(read), /HIDDEN|SECRET_FILE/);
    assert.equal(read.context.next_cursor, 'older');
    assert.equal(read.runtime_status, 'succeeded');
    assert.equal(read.task_outcome.status, 'unknown');
  }
  surfaceText = undefined;
  await reader('read', { session_id: root, include_messages: true, limit: 3, cursor: 'older' }, claims);
  await assert.rejects(reader('read', { session_id: root, include_messages: true, limit: 21 }, claims));
  await assert.rejects(reader('read', { session_id: root, include_messages: true, cursor: '\n' }, claims));
  foreign = true;
  await assert.rejects(reader('read', { session_id: root, include_messages: true, limit: 3 }, claims));
  foreign = false; messageRevocation = true;
  await assert.rejects(reader('read', { session_id: root, include_messages: true, limit: 3 }, claims));
  messageRevocation = false; binding = { ...b };
  wrongSelection = true;
  const beforeWrongSelection = calls;
  await assert.rejects(reader('read', { session_id: root, include_messages: true, limit: 3 }, claims));
  assert.equal(calls, beforeWrongSelection + 1, 'mismatched session metadata must prevent message request');
  wrongSelection = false;
  const beforeUnscoped = calls;
  await assert.rejects(reader('messages', { session_id: root, limit: 3 }, claims));
  assert.equal(calls, beforeUnscoped, 'message fetch requires exact session read, not a standalone action');
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
    model: { providerID: 'openai', id: 'fixture' }, metadata: { intent: 'unchanged' }, location: { directory: dir }, time: {} };
  const posts = [], inbox = [], questionMutations = []; let nativeForms = [], dropAck = false, sourceConnections = 0, activeSources = 0, maxSources = 0;
  let nativeHint = { type: 'session.updated', id: 'evt_old_fixture', created: Date.now() - 1000 };
  const nativeResponses = new Set();
  let permissionBarrier, permissionEntered, gateOnlyProgress = false;
  let permissionFailure = false, listMode = 'normal', secondPages = 0, readFailure = null;
  const guardEntry = join(dir, 'runtime', 'plugins', 'subscription-guard', 'index.mjs');
  const backend = createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/api/event') {
      sourceConnections++; activeSources++; maxSources = Math.max(maxSources, activeSources);
      assert.equal(req.method, 'GET'); assert.equal(req.headers['last-event-id'], undefined);
      res.setHeader('content-type', 'text/event-stream');
      for (let index = 0; index < 3; index++) res.write(`data: ${JSON.stringify({ ...nativeHint, data: { sessionID: root, text: 'PRIVATE_NATIVE_PAYLOAD' } })}\n\n`);
      nativeResponses.add(res);
      const end = setTimeout(() => res.end(), 15000);
      res.on('close', () => { clearTimeout(end); activeSources--; nativeResponses.delete(res); }); return;
    }
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    const reply = new RegExp(`^/api/session/${root}/form/(frm_[A-Za-z0-9_-]{1,160})/reply$`).exec(req.url);
    const cancel = new RegExp(`^/api/session/${root}/form/(frm_[A-Za-z0-9_-]{1,160})$`).exec(req.url);
    if (req.method === 'POST' && reply) {
      let text = ''; for await (const chunk of req) text += chunk;
      const body = JSON.parse(text); const form = nativeForms.find(item => item.id === reply[1]);
      assert.equal(form?.state?.status, 'pending'); assert.deepEqual(body, { answer: { q0: 'yes' } });
      form.state = { status: 'answered', answer: body.answer }; questionMutations.push({ path: req.url, body });
      return res.end(JSON.stringify({}));
    }
    if (req.method === 'DELETE' && cancel) {
      const form = nativeForms.find(item => item.id === cancel[1]); assert.equal(form?.state?.status, 'pending');
      form.state = { status: 'cancelled' }; questionMutations.push({ path: req.url, body: null });
      return res.end(JSON.stringify({}));
    }
    if (req.method === 'POST') {
      let text = ''; for await (const chunk of req) text += chunk;
      const body = text ? JSON.parse(text) : null; posts.push({ path: req.url, body });
      if (req.url === `/api/session/${root}/interrupt?resume=false`) return res.end(JSON.stringify({ interrupted: true }));
      assert.equal(req.url, `/api/session/${root}/prompt`);
      assert.deepEqual(Object.keys(body).sort(), ['delivery', 'id', 'text']); assert.equal(body.delivery, 'queue');
      const item = { id: body.id, sessionID: root, type: 'user', payload: { text: body.text }, delivery: 'queue' }; inbox.push(item);
      if (dropAck) { res.destroy(); return; }
      return res.end(JSON.stringify({ data: item }));
    }
    assert.equal(req.method, 'GET');
    if (req.url === '/api/project') return res.end(JSON.stringify([
      { id: 'project', name: 'Useful project', canonical: dir, directory: '/PRIVATE', commands: { start: 'SECRET' } },
      { id: 'empty-project', name: 'Empty project token=SECRET', canonical: '/outside-authorized-workspace' }
    ]));
    if (req.url.startsWith('/api/location?')) {
      const directory = new URL(req.url, 'http://fixture').searchParams.get('location[directory]');
      return res.end(JSON.stringify(directory === '/outside-authorized-workspace' ?
        { directory, project: { id: 'empty-project', directory, canonical: directory } } :
        { directory: dir, project: { id: 'project', directory: dir, canonical: dir } }));
    }
    if (req.url === '/api/agent') return res.end(JSON.stringify({ location: { directory: '/PRIVATE' }, data: [
      { id: 'reviewer', name: 'Review helper', description: 'Review code token=SECRET', mode: 'subagent', hidden: false, system: 'HIDDEN', request: { password: 'SECRET' }, permissions: {} }
    ] }));
    if (req.url.startsWith('/api/plugin?')) return res.end(JSON.stringify({ location: { directory: dir }, data: [{ id: 'subscription.guard', state: { status: 'active' }, source: { type: 'local', path: guardEntry } }] }));
    if (req.url.startsWith('/api/integration/openai?')) return res.end(JSON.stringify({ location: { directory: dir }, data: { id: 'openai', connections: [{ type: 'credential', method: 'oauth' }] } }));
    if (req.url.startsWith('/api/provider/openai?')) return res.end(JSON.stringify({ location: { directory: dir }, data: { id: 'openai', package: '@opencode/ai/providers/openai' } }));
    if (req.url.startsWith('/api/model?')) return res.end(JSON.stringify({ location: { directory: dir }, data: [{ id: 'fixture', providerID: 'openai', package: '@opencode/ai/providers/openai' }] }));
    if (req.url === '/api/session/active') return res.end(JSON.stringify({ data: {} }));
    if (req.url === `/api/session/${root}`) return res.end(JSON.stringify({ data: session }));
    if (req.url.startsWith(`/api/session/${root}/message?`)) {
      if (readFailure === 'denied') { res.statusCode = 403; return res.end('PRIVATE token/body'); }
      if (readFailure === 'json') return res.end('PRIVATE invalid JSON');
      return res.end(JSON.stringify({ data: [{ id: 'msg_visible', time: { created: 1 }, type: 'user', text: 'Review the release documentation.' }], cursor: {} }));
    }
    if (req.url === `/api/session/${root}/inbox`) return res.end(JSON.stringify({ data: inbox }));
    if (req.url === `/api/session/${root}/permission`) {
      if (permissionFailure) { res.statusCode = 503; return res.end('{}'); }
      const shouldGate = !gateOnlyProgress || Object.values(JSON.parse(await fs.readFile(join(dir, 'events.sqlite'), 'utf8')).subscriptions ?? {}).some(sub => sub.name === 'session.progress');
      if (shouldGate) { permissionEntered?.(); await permissionBarrier; }
      return res.end(JSON.stringify({ data: [] }));
    }
    if (req.url === `/api/session/${root}/form`) return res.end(JSON.stringify({ data: nativeForms.filter(form => form.state?.status === 'pending') }));
    const formDetail = new RegExp(`^/api/session/${root}/form/(frm_[A-Za-z0-9_-]{1,160})$`).exec(req.url);
    if (formDetail) {
      const form = nativeForms.find(item => item.id === formDetail[1]);
      if (!form) { res.statusCode = 404; return res.end('{}'); }
      return res.end(JSON.stringify({ data: form }));
    }
    const formMessage = nativeForms.find(form => req.url === `/api/session/${root}/message/${form.metadata.tool.messageID}`);
    if (formMessage) return res.end(JSON.stringify({ data: { id: formMessage.metadata.tool.messageID, content: [
      { type: 'tool', id: formMessage.metadata.tool.id, name: 'question', state: { status: 'running' } }
    ] } }));
    if (req.url.includes('/message/')) { res.statusCode = 404; return res.end('{}'); }
    if (req.url.startsWith('/api/session?')) {
      if (listMode === 'empty') return res.end(JSON.stringify({ data: [], cursor: {} }));
      if (listMode === 'partial') {
        if (new URL(req.url, 'http://fixture').searchParams.has('cursor')) {
          secondPages++; res.statusCode = 503; return res.end('{}');
        }
        return res.end(JSON.stringify({ data: [session], cursor: { next: 'fixture-page-two' } }));
      }
    }
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
  const observerDirectory = join(dir, 'observer'); await fs.mkdir(observerDirectory, { mode: 0o700 });
  config.mcp_observation = { enabled: true, directory: observerDirectory, arm_file: join(observerDirectory, 'mcp-observation.arm') };
  const armObservation = async target => fs.writeFile(config.mcp_observation.arm_file, JSON.stringify({ target, attemptId: 'b'.repeat(32), issuedAt: Date.now(), expiresAt: Date.now() + 60000 }), { mode: 0o600, flag: 'wx' });
  const gateway = createGateway(config, { testIssuer: true }); await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve)); t.after(() => close(gateway));
  const call = async (clientID, name = 'workrelay_server_discover', args = {}, tokenOptions = {}, target = gateway) => {
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: clientID }).setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(origin).setAudience(tokenOptions.audience ?? config.audience).setSubject(tokenOptions.subject ?? 'alice').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
    const sdk = new Client({ name: 'managed-test', version: '1' });
    try {
      await sdk.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${target.address().port}/mcp`),
        { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
      return { result: await sdk.callTool({ name, arguments: args }), tools: (await sdk.listTools()).tools };
    } finally { await sdk.close(); }
  };
  const nativeWaits = await call(client, 'workrelay_server_waits', { session_id: root, limit: 1 });
  assert.notEqual(nativeWaits.result.isError, true, JSON.stringify(nativeWaits.result));
  assert.equal(nativeWaits.result.structuredContent.pending_permission_count, 0);
  assert.equal(nativeWaits.result.structuredContent.inference_started, false);
  assert.equal(nativeWaits.result.structuredContent.native_permission_reply_exposed, false);
  assert.equal(nativeWaits.result.structuredContent.native_question_reply_exposed, true);
  const waitsDefinition = nativeWaits.tools.find(tool => tool.name === 'workrelay_server_waits');
  assert.equal(waitsDefinition.annotations.readOnlyHint, true);
  assert.equal(nativeWaits.tools.find(tool => tool.name === 'workrelay_server_reconcile').annotations.readOnlyHint, false);
  assert.equal(Object.hasOwn(waitsDefinition.inputSchema.properties, 'operation_id'), false);
  assert.equal((await call('other', 'workrelay_server_waits', { session_id: root })).result.isError, true);
  assert.equal((await call(client, 'workrelay_server_waits', { session_id: root, limit: 51 })).result.isError, true);
  assert.equal(posts.length, 0, 'wait reads never post or start inference');
  await armObservation('mcp-catalog');
  await assert.rejects(call(client, 'workrelay_server_capabilities', {}, { subject: 'other' }));
  await assert.rejects(fs.access(join(observerDirectory, 'mcp-observation.receipt.json')));
  assert.equal((await call(client)).result.structuredContent.items[0].session_id, root);
  const catalogReceipt = join(observerDirectory, 'mcp-observation.receipt.json');
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await fs.access(catalogReceipt).then(() => true, () => false)) break;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  const servedCatalog = JSON.parse(await fs.readFile(catalogReceipt, 'utf8'));
  assert.equal(servedCatalog.layer, 'sdk_response_before_delivery');
  assert.equal(servedCatalog.read_schema_include_messages, true);
  assert.ok(servedCatalog.known_tools.includes('workrelay_server_read'));
  assert.ok(servedCatalog.known_tools.includes('workrelay_server_creation_target'));
  assert.equal(servedCatalog.unknown_count, 0);
  await fs.rename(catalogReceipt, catalogReceipt + '.saved');
  await fs.rename(join(observerDirectory, 'mcp-observation.used'), join(observerDirectory, 'mcp-observation.used.saved'));
  assert.equal(reads, 1);
  const catalogue = await call(client, 'workrelay_server_capabilities');
  assert.deepEqual(catalogue.result.structuredContent.tools.map(tool => tool.name).sort(), catalogue.tools.map(tool => tool.name).sort());
  for (const name of ['workrelay_server_projects', 'workrelay_server_agents', 'workrelay_server_capabilities']) {
    assert.ok(catalogue.tools.some(tool => tool.name === name && tool.annotations.readOnlyHint));
    assert.equal((await call('other', name)).result.isError, true);
  }
  const projects = (await call(client, 'workrelay_server_projects', { limit: 1 })).result.structuredContent;
  assert.equal(projects.items.length, 1); assert.ok(projects.next_cursor);
  const nextProjects = (await call(client, 'workrelay_server_projects', { limit: 1, cursor: projects.next_cursor })).result.structuredContent;
  assert.equal(nextProjects.items.length, 1); assert.equal(nextProjects.next_cursor, null);
  assert.notEqual(projects.items[0].project_id, nextProjects.items[0].project_id);
  const agents = (await call(client, 'workrelay_server_agents')).result.structuredContent;
  assert.equal(agents.items[0].kind, 'agent_definition'); assert.equal(agents.items[0].execution, false);
  assert.equal(agents.items[0].label, 'Review helper');
  for (const output of [projects, nextProjects, agents, catalogue.result.structuredContent]) {
    assert.doesNotMatch(JSON.stringify(output), /SECRET|PRIVATE|HIDDEN/);
    assert.ok(catalogue.tools.some(tool => tool.name === output.next_action.tool));
    assert.notEqual((await call(client, output.next_action.tool, output.next_action.arguments)).result.isError, true);
  }
  assert.equal((await call(client, 'workrelay_server_agents', { cursor: projects.next_cursor })).result.isError, true);
  assert.equal(posts.length, 0);
  const creationTarget = (await call(client, 'workrelay_server_creation_target')).result.structuredContent;
  assert.equal(creationTarget.available, true);
  assert.equal(creationTarget.project_id, 'project_' + createHash('sha256').update('project').digest('hex'));
  assert.equal(JSON.stringify(creationTarget).includes(dir), false);
  assert.equal((await call('other', 'workrelay_server_creation_target')).result.isError, true);
  // Isolated router contract tests: the existing gateway below still exercises
  // the real guarded CLI. This separate gateway captures only router handoff.
  const handed = [];
  const revocation = join(dir, 'revocation.json');
  await fs.writeFile(revocation, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }), { mode: 0o600 });
  const integratedReserve = createServer(); await listen(integratedReserve);
  const integratedPort = integratedReserve.address().port; await close(integratedReserve);
  const delivered = [];
  const integrated = createGateway({ ...config, port: integratedPort, events_enabled: true, events_state_path: join(dir, 'events.sqlite'), revocation_file: revocation }, {
    testIssuer: true, eventIntervalMs: 50, eventReadinessTimeoutMs: 1500, eventTransport: async (_url, request) => {
      const body = JSON.parse(request.body); delivered.push(body); return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
    }, invoke: async (_config, command, payload) => {
      handed.push({ command, payload });
      if (payload.operation_id === 'predicate-success') return { phase: 'accepted', inference_started: false,
        denial_code: 'ATTESTATION_FAILED', denied_at_ms: 123, attestation_check_id: 'PRIVATE/path' };
      if (payload.operation_id === 'predicate-other-denial') return { phase: 'denied',
        denial_code: 'QUOTA_DENIED', denied_at_ms: 123, attestation_check_id: 'GUARD_SOURCE' };
      if (payload.operation_id?.startsWith('attestation-')) {
        const checks = [...ATTESTATION_CHECK_IDS, undefined, 'PRIVATE/path\nGUARD_SOURCE', { raw: 'PRIVATE' }, ['GUARD_SOURCE']];
        const index = Number(payload.operation_id.slice('attestation-'.length));
        return { ...(payload.action === 'inspect' ? {} : { error: 'PRIVATE raw exception', code: 'CONTROL_NOT_SENT' }),
          phase: 'denied', denial_code: 'ATTESTATION_FAILED', denied_at_ms: 123, attestation_check_id: checks[index] };
      }
      if (payload.action === 'waits') return { session_id: payload.session_id, pending_permission_count: 1,
        items: [{ request_id: 'per_fixture', action: 'read', resource_preview: ['sanitized fixture'], requires_explicit_human_decision: true,
          respond_via: 'native_opencode_or_openchamber_permission_ui' }], inference_started: false,
        native_permission_reply_exposed: false, native_question_reply_exposed: false };
      if (payload.action === 'inspect' && payload.operation_id === 'dot-acceptance-create-20261017-0220') return {
        phase: 'denied', recorded_phase: 'denied', kind: 'create', exact_session_exists: false, effect: 'not_applied', task_outcome: 'unverified' };
      if (payload.operation_id === 'finite-denial-error') return { error: 'PRIVATE exception', code: 'CONTROL_NOT_SENT',
        denial_code: 'QUOTA_DENIED', denied_at_ms: 123456, stack: 'PRIVATE', token: 'PRIVATE' };
      if (payload.action === 'inspect' && payload.operation_id === 'finite-denial-status') return { phase: 'denied',
        denial_code: 'AUTHORITY_UNAVAILABLE_OR_CHANGED', denied_at_ms: Number.MAX_SAFE_INTEGER };
      if (payload.action === 'inspect' && payload.operation_id === 'malicious-denial-status') return { phase: 'denied',
        denial_code: 'PRIVATE exception token=PRIVATE', denied_at_ms: 'PRIVATE' };
      if (payload.action === 'inspect' && ['ambiguous', 'missing'].includes(payload.operation_id)) return {
        code: payload.operation_id === 'missing' ? 'CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING' : 'CONTROL_OPERATION_AMBIGUOUS_CURRENT_BINDING',
        operation_id: payload.operation_id, session_id: payload.session_id ?? null, phase: 'unknown', effect: 'not_established',
        lookup_scope: 'current_authenticated_binding', native_observation: 'not_run', replay_permitted: false, task_outcome: 'unverified' };
      if (payload.action === 'inspect' && payload.operation_id === 'known-uncertain') return { phase: 'uncertain', recorded_phase: 'uncertain',
        code: 'CONTROL_UNCERTAIN', effect: 'may_have_been_applied', lookup_scope: 'current_authenticated_binding',
        native_observation: 'not_run', replay_permitted: false, task_outcome: 'unverified' };
      if (payload.action === 'create' && payload.project_id === 'empty-project' && Object.hasOwn(payload, 'directory')) return { error: 'PRIVATE workspace does not belong to selected discovered project', code: 'CONTROL_NOT_SENT', effect: 'no_post_permitted', reason: 'PROJECT_WORKSPACE_MISMATCH' };
      return { phase: 'fixture_dispatch', inference_started: false };
    }
  });
  await new Promise(resolve => integrated.listen(integratedPort, '127.0.0.1', resolve)); t.after(() => close(integrated));
  const integratedCall = (name, args = {}, who = client) => call(who, name, args, {}, integrated);
  const recovery = { operation_id: 'dot-acceptance-create-20261017-0220' };
  const recovered = (await integratedCall('workrelay_server_operation_status', recovery)).result;
  assert.equal(recovered.structuredContent.effect, 'not_applied');
  assert.equal(recovered.structuredContent.exact_session_exists, false);
  assert.equal(recovered.structuredContent.denial_code, 'DENIAL_REASON_NOT_RECORDED');
  assert.equal(recovered.structuredContent.denied_at_ms, null, 'legacy reason/time not backfilled');
  assert.equal(recovered.structuredContent.attestation_check_id, null, 'historical cause never inferred');
  assert.equal(handed.at(-1).payload.session_id, undefined);
  const diagnosticError = (await integratedCall('workrelay_server_resume', { session_id: root, operation_id: 'finite-denial-error', text: 'synthetic bounded fixture' })).result;
  assert.equal(diagnosticError.isError, true); assert.equal(diagnosticError.structuredContent.denial_code, 'QUOTA_DENIED');
  assert.equal(diagnosticError.structuredContent.denied_at_ms, 123456); assert.doesNotMatch(JSON.stringify(diagnosticError), /PRIVATE/);
  const diagnosticStatus = (await integratedCall('workrelay_server_operation_status', { operation_id: 'finite-denial-status' })).result;
  assert.equal(diagnosticStatus.structuredContent.denial_code, 'AUTHORITY_UNAVAILABLE_OR_CHANGED');
  assert.equal(diagnosticStatus.structuredContent.denied_at_ms, Number.MAX_SAFE_INTEGER);
  const maliciousStatus = (await integratedCall('workrelay_server_operation_status', { operation_id: 'malicious-denial-status' })).result;
  assert.equal(maliciousStatus.structuredContent.denial_code, 'DENIAL_REASON_NOT_RECORDED');
  assert.equal(maliciousStatus.structuredContent.denied_at_ms, null); assert.doesNotMatch(JSON.stringify(maliciousStatus), /PRIVATE/);
  for (let index = 0; index < ATTESTATION_CHECK_IDS.length + 4; index++) {
    const operation_id = 'attestation-' + index;
    const expected = ATTESTATION_CHECK_IDS[index] ?? null;
    const status = (await integratedCall('workrelay_server_operation_status', { operation_id })).result;
    const error = (await integratedCall('workrelay_server_resume', { session_id: root, operation_id, text: 'synthetic bounded fixture' })).result;
    assert.equal(error.isError, true);
    for (const result of [status, error]) {
      assert.equal(result.structuredContent.attestation_check_id, expected);
      assert.equal(result.structuredContent.denial_code, 'ATTESTATION_FAILED');
      assert.equal(result.structuredContent.denied_at_ms, 123);
      assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
    }
  }
  const successfulProjection = (await integratedCall('workrelay_server_operation_status', { operation_id: 'predicate-success' })).result;
  assert.equal(successfulProjection.structuredContent.phase, 'accepted');
  for (const key of ['denial_code', 'denied_at_ms', 'attestation_check_id']) assert.equal(successfulProjection.structuredContent[key], undefined);
  assert.doesNotMatch(JSON.stringify(successfulProjection), /PRIVATE/);
  const otherDenial = (await integratedCall('workrelay_server_operation_status', { operation_id: 'predicate-other-denial' })).result;
  assert.equal(otherDenial.structuredContent.denial_code, 'QUOTA_DENIED');
  assert.equal(otherDenial.structuredContent.attestation_check_id, null);
  const recoveryCount = handed.length;
  assert.equal((await integratedCall('workrelay_server_operation_status', recovery, 'other')).result.isError, true);
  assert.equal(handed.length, recoveryCount);
  for (const operation_id of ['missing', 'ambiguous']) {
    const rejected = (await integratedCall('workrelay_server_operation_status', { operation_id })).result;
    assert.notEqual(rejected.isError, true); assert.doesNotMatch(JSON.stringify(rejected), /PRIVATE/);
    assert.equal(rejected.structuredContent.code, operation_id === 'missing' ? 'CONTROL_OPERATION_NOT_FOUND_CURRENT_BINDING' : 'CONTROL_OPERATION_AMBIGUOUS_CURRENT_BINDING');
    assert.equal(rejected.structuredContent.lookup_scope, 'current_authenticated_binding');
    assert.equal(rejected.structuredContent.effect, 'not_established'); assert.equal(rejected.structuredContent.replay_permitted, false);
    assert.match(rejected.structuredContent.guidance, /operator/i);
  }
  const originalModel = session.model;
  session.model = { providerID: 'fixture-other', id: 'fixture-changed' };
  const unchangedPosts = posts.length;
  const historical = (await integratedCall('workrelay_server_operation_status', { operation_id: 'finite-denial-status', session_id: root })).result;
  assert.notEqual(historical.isError, true); assert.equal(historical.structuredContent.phase, 'denied');
  assert.equal(historical.structuredContent.denial_code, 'AUTHORITY_UNAVAILABLE_OR_CHANGED');
  const uncertainReceipt = (await integratedCall('workrelay_server_operation_status', { operation_id: 'known-uncertain', session_id: root })).result;
  assert.equal(uncertainReceipt.structuredContent.code, 'CONTROL_UNCERTAIN'); assert.equal(uncertainReceipt.structuredContent.effect, 'may_have_been_applied');
  assert.equal(uncertainReceipt.structuredContent.replay_permitted, false); assert.equal(uncertainReceipt.structuredContent.native_observation, 'not_run');
  assert.equal(uncertainReceipt.structuredContent.denial_code, undefined, 'uncertain is not resolved denied');
  assert.equal(posts.length, unchangedPosts, 'historical receipt reads never POST'); session.model = originalModel;
  const isolatedCount = handed.length;
  await assert.rejects(call(client, 'workrelay_server_operation_status', recovery, { subject: 'other' }, integrated));
  for (const changed of [{ ...binding, revoked: true }, { ...binding, server: 'http://127.0.0.1:1' }]) {
    await fs.writeFile(capability, JSON.stringify(changed));
    assert.equal((await integratedCall('workrelay_server_operation_status', recovery)).result.isError, true);
    assert.equal(handed.length, isolatedCount, 'revoked/wrong-server binding cannot reach receipt lookup');
  }
  await fs.writeFile(capability, JSON.stringify(binding));
  const nondefault = { operation_id: 'nondefault-native-project', project_id: 'project_' + createHash('sha256').update('empty-project').digest('hex'), title: 'Native project idle session' };
  const nativeCreate = (await integratedCall('workrelay_server_create', nondefault)).result;
  assert.notEqual(nativeCreate.isError, true);
  assert.equal(handed.at(-1).payload.project_id, 'empty-project');
  assert.equal(Object.hasOwn(handed.at(-1).payload, 'directory'), false, 'omission reaches CLI unchanged, never filled with profile default');
  assert.equal(handed.at(-1).payload.title, nondefault.title);
  const deniedCreate = (await integratedCall('workrelay_server_create', { ...nondefault, operation_id: 'explicit-bad-path', directory: '/outside-selected-project' })).result;
  assert.equal(handed.at(-1).payload.directory, '/outside-selected-project', 'explicit paths are delegated to the guarded CLI, not silently rewritten');
  assert.equal(deniedCreate.isError, true); assert.equal(deniedCreate.structuredContent.reason, 'PROJECT_WORKSPACE_MISMATCH');
  assert.equal(deniedCreate.structuredContent.effect, 'no_post_permitted'); assert.doesNotMatch(JSON.stringify(deniedCreate), /PRIVATE/);
  for (const action of ['create', 'operation_status', 'steer', 'resume']) {
    const args = action === 'create' ? { operation_id: 'new', project_id: creationTarget.project_id, title: 'Isolated creation' } :
      { session_id: root, operation_id: 'inspect', ...(['steer', 'resume'].includes(action) ? { text: 'Bounded continuation' } : {}) };
    assert.notEqual((await integratedCall(`workrelay_server_${action}`, args)).result.isError, true);
    assert.equal(handed.at(-1).command, 'managed-control');
    assert.equal(handed.at(-1).payload.action, action === 'operation_status' ? 'inspect' : action);
    assert.equal(handed.at(-1).payload.claims.sub, 'alice');
    assert.equal(handed.at(-1).payload.claims.client_id, client);
    if (action === 'create') assert.ok(['project', 'empty-project'].includes(handed.at(-1).payload.project_id));
    const count = handed.length;
    assert.equal((await integratedCall(`workrelay_server_${action}`, args, 'other')).result.isError, true);
    assert.equal(handed.length, count);
  }
  const full = await integratedCall('workrelay_server_capabilities');
  const until = async condition => { for (let attempt = 0; attempt < 150; attempt++) { if (await condition()) return; await new Promise(resolve => setTimeout(resolve, 30)); } assert.fail('bounded native-source observation missing'); };
  assert.equal(sourceConnections, 0, 'no stream before active managed subscription');
  const eventToken = await new SignJWT({ scope: 'workrelay:tasks', client_id: client }).setProtectedHeader({ alg: 'RS256', kid: 'test' })
    .setIssuer(origin).setAudience(config.audience).setSubject('alice').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
  const eventCall = async (method, params) => {
    const response = await fetch(`http://127.0.0.1:${integratedPort}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${eventToken}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }) });
    assert.equal(response.status, 200); return response.json();
  };
  const subscription = { name: 'session.failed', arguments: { server_id: full.result.structuredContent.server_id, session_id: root },
    delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret: 'whsec_' + Buffer.alloc(32, 9).toString('base64') } };
  session.outcome = 'failed';
  const subscribed = await eventCall('events/subscribe', subscription); assert.ok(subscribed.result?.id, 'subscription ACK must await live source and baseline');
  const acknowledgedState = JSON.parse(await fs.readFile(join(dir, 'events.sqlite'), 'utf8'));
  assert.ok(acknowledgedState.subscriptions[subscribed.result.id].observations[root], 'actual session baseline exists at ACK');
  assert.equal(activeSources, 1, 'source is connected at ACK');
  assert.equal(delivered.filter(event => event.name === 'session.failed').length, 0, 'stale terminal baseline is not a fresh completion');
  nativeHint = { type: 'session.execution.failed', id: 'evt_current_generation_one', created: Date.now() };
  for (const response of nativeResponses) response.end();
  await until(() => delivered.some(event => event.name === 'session.failed'));
  const firstGenerationConnections = sourceConnections;
  for (const response of nativeResponses) response.end();
  await until(() => sourceConnections > firstGenerationConnections);
  assert.equal(maxSources, 1, 'normal gateway owns only one bounded native stream');
  assert.equal(delivered.filter(event => event.name === 'session.failed').length, 1, 'duplicate native wakes reconcile the same durable observation');
  nativeHint = { type: 'session.execution.failed', id: 'evt_current_generation_two', created: Date.now() };
  for (const response of nativeResponses) response.end();
  await until(() => delivered.filter(event => event.name === 'session.failed').length === 2);
  const generations = delivered.filter(event => event.name === 'session.failed');
  assert.notEqual(generations[0].eventId, generations[1].eventId, 'same terminal state in a new native generation is a distinct durable event');
  assert.doesNotMatch(JSON.stringify(delivered), /PRIVATE_NATIVE_PAYLOAD/);
  await eventCall('events/unsubscribe', subscription);
  await until(() => activeSources === 0);
  const afterUnsubscribe = sourceConnections;
  await new Promise(resolve => setTimeout(resolve, 1100)); assert.equal(sourceConnections, afterUnsubscribe);
  let releaseBaseline, enteredBaseline;
  permissionBarrier = new Promise(resolve => { releaseBaseline = resolve; });
  const baselineEntered = new Promise(resolve => { enteredBaseline = resolve; }); permissionEntered = enteredBaseline;
  let acknowledged = false;
  const slowSubscribe = eventCall('events/subscribe', subscription).then(value => { acknowledged = true; return value; });
  await baselineEntered;
  assert.equal(acknowledged, false, 'slow actual baseline cannot ACK early');
  releaseBaseline(); permissionBarrier = undefined; permissionEntered = undefined;
  assert.ok((await slowSubscribe).result.id);
  const concurrent = await Promise.all([eventCall('events/subscribe', subscription), eventCall('events/subscribe', { ...subscription, name: 'session.completed' })]);
  assert.ok(concurrent.every(value => value.result?.id)); assert.equal(maxSources, 1);
  const stateBeforeTimeout = JSON.parse(await fs.readFile(join(dir, 'events.sqlite'), 'utf8'));
  gateOnlyProgress = true;
  permissionBarrier = new Promise(resolve => { releaseBaseline = resolve; });
  let releaseTimedOutBackend;
  permissionEntered = () => { if (!releaseTimedOutBackend) releaseTimedOutBackend = setTimeout(() => releaseBaseline(), 2000); };
  const timedOut = await eventCall('events/subscribe', { ...subscription, name: 'session.progress' });
  assert.ok(timedOut.error, 'bounded timeout must not acknowledge subscription success');
  clearTimeout(releaseTimedOutBackend); releaseBaseline(); permissionBarrier = undefined; permissionEntered = undefined; gateOnlyProgress = false;
  const stateAfterTimeout = JSON.parse(await fs.readFile(join(dir, 'events.sqlite'), 'utf8'));
  assert.deepEqual(Object.keys(stateAfterTimeout.subscriptions).sort(), Object.keys(stateBeforeTimeout.subscriptions).sort(), 'timeout removes only new subscription, preserving existing subscribers');
  const stateFile = join(dir, 'events.sqlite');
  const readSubscriptions = async () => JSON.parse(await fs.readFile(stateFile, 'utf8')).subscriptions;
  const serverwide = { ...subscription, name: 'session.progress', arguments: { server_id: subscription.arguments.server_id } };
  permissionFailure = true;
  assert.ok((await eventCall('events/subscribe', serverwide)).error, 'thrown server-wide observation cannot ACK');
  assert.deepEqual(Object.keys(await readSubscriptions()).sort(), Object.keys(stateBeforeTimeout.subscriptions).sort());
  const beforeRenewal = (await readSubscriptions())[subscribed.result.id];
  assert.ok(beforeRenewal.observations[root], 'renewal starts with stale stored observations');
  const failedRenewal = await eventCall('events/subscribe', { ...subscription, ttlMs: 60000,
    delivery: { ...subscription.delivery, secret: 'whsec_' + Buffer.alloc(32, 7).toString('base64') } });
  assert.ok(failedRenewal.error, 'stale observations cannot satisfy a fresh renewal');
  const afterRenewal = (await readSubscriptions())[subscribed.result.id];
  for (const field of ['expires', 'secret', 'verifiedUntil', 'previousSecret', 'rotationUntil', 'managedReady']) {
    assert.deepEqual(afterRenewal[field], beforeRenewal[field], `failed renewal preserves ${field}`);
  }
  permissionFailure = false; listMode = 'partial';
  assert.ok((await eventCall('events/subscribe', serverwide)).error, 'failure after first page cannot ACK');
  assert.ok(secondPages > 0, 'readiness follows pagination to the failing second page');
  assert.deepEqual(Object.keys(await readSubscriptions()).sort(), Object.keys(stateBeforeTimeout.subscriptions).sort());
  listMode = 'empty';
  const empty = await eventCall('events/subscribe', serverwide);
  assert.ok(empty.result?.id, 'valid complete empty server-wide scan is ready');
  const emptyProof = (await readSubscriptions())[empty.result.id].managedReady.observation;
  assert.equal(emptyProof.complete, true); assert.equal(emptyProof.pages, 1); assert.equal(emptyProof.items, 0);
  assert.equal(empty.result.observation, undefined, 'internal proof is not added to protocol result');
  await eventCall('events/unsubscribe', serverwide); listMode = 'normal';
  await eventCall('events/unsubscribe', subscription);
  await eventCall('events/unsubscribe', { ...subscription, name: 'session.completed' });
  await eventCall('events/subscribe', subscription);
  await until(() => sourceConnections > afterUnsubscribe);
  permissionBarrier = new Promise(resolve => { releaseBaseline = resolve; });
  const revokeEntered = new Promise(resolve => { permissionEntered = resolve; });
  const revokedAdmission = eventCall('events/subscribe', serverwide);
  await revokeEntered;
  await fs.writeFile(capability, JSON.stringify({ ...binding, revoked: true }));
  releaseBaseline(); permissionBarrier = undefined; permissionEntered = undefined;
  assert.ok((await revokedAdmission).error, 'revocation during observation cannot acknowledge a new subscription');
  await until(() => activeSources === 0);
  const afterRevocation = sourceConnections;
  await new Promise(resolve => setTimeout(resolve, 1100)); assert.equal(sourceConnections, afterRevocation);
  await integrated.stopEvents();
  await fs.writeFile(capability, JSON.stringify(binding)); delete session.outcome;
  const pendingWaits = (await integratedCall('workrelay_server_waits', { session_id: root, limit: 2 })).result;
  assert.equal(pendingWaits.structuredContent.items[0].requires_explicit_human_decision, true);
  assert.equal(handed.at(-1).payload.action, 'waits');
  assert.equal(Object.hasOwn(handed.at(-1).payload, 'operation_id'), false);
  assert.equal(handed.at(-1).payload.claims.sub, 'alice');
  assert.equal(handed.at(-1).payload.limit, 2);
  for (const step of full.result.structuredContent.journey) {
    const definition = full.tools.find(tool => tool.name === step.tool);
    assert.ok(definition, `journey stage ${step.stage} must resolve to registered tool`);
    for (const field of [...step.requires, ...Object.keys(step.arguments ?? {})]) assert.ok(Object.hasOwn(definition.inputSchema.properties, field));
    for (const field of definition.inputSchema.required ?? []) assert.ok(step.requires.includes(field) || Object.hasOwn(step.arguments ?? {}, field));
  }
  const observedFull = catalogShape({ tools: full.tools });
  assert.deepEqual(observedFull.known_tools, full.tools.map(tool => tool.name).sort());
  assert.equal(observedFull.unknown_count, 0, 'all actual registered tools, including creation_target and Events, are known');
  const withUnknown = catalogShape({ tools: [...full.tools, { name: 'PRIVATE_UNKNOWN_TOOL_VALUE' }] });
  assert.deepEqual(withUnknown.known_tools, observedFull.known_tools);
  assert.equal(withUnknown.unknown_count, 1);
  assert.equal(withUnknown.tool_count, full.tools.length + 1);
  assert.doesNotMatch(JSON.stringify(withUnknown), /PRIVATE_UNKNOWN_TOOL_VALUE/);
  assert.deepEqual(full.result.structuredContent.tools.map(tool => tool.name).sort(), full.tools.map(tool => tool.name).sort());
  for (const name of ['workrelay_event_capabilities', 'workrelay_event_subscriptions', 'workrelay_event_subscription_status', 'workrelay_event_unsubscribe']) {
    const args = ['workrelay_event_subscription_status', 'workrelay_event_unsubscribe'].includes(name) ? { subscription_id: 'sub_' + 'a'.repeat(64) } : {};
    assert.notEqual((await integratedCall(name, args)).result.isError, true);
    assert.equal((await integratedCall(name, args, 'other')).result.isError, true);
  }
  reads = 1; // Remaining legacy assertions count session-discovery calls only.
  const readArgs = { session_id: root, include_messages: true, limit: 1 };
  await armObservation('mcp-read');
  assert.equal((await call('other', 'workrelay_server_read', readArgs)).result.isError, true);
  await assert.rejects(fs.access(join(observerDirectory, 'mcp-observation.receipt.json')));
  const visible = (await call(client, 'workrelay_server_read', readArgs)).result;
  const observedRead = JSON.parse(await fs.readFile(join(observerDirectory, 'mcp-observation.receipt.json'), 'utf8'));
  assert.equal(observedRead.incoming.flag_value, true); assert.equal(observedRead.parsed.flag_value, true);
  assert.equal(observedRead.item_count, 1); assert.equal(JSON.stringify(observedRead).includes(root), false);
  await fs.rename(join(observerDirectory, 'mcp-observation.receipt.json'), join(observerDirectory, 'read.saved'));
  await fs.rename(join(observerDirectory, 'mcp-observation.used'), join(observerDirectory, 'read-used.saved'));
  await armObservation('mcp-read');
  await call(client, 'workrelay_server_read', { session_id: root });
  const omittedRead = JSON.parse(await fs.readFile(join(observerDirectory, 'mcp-observation.receipt.json'), 'utf8'));
  assert.equal(omittedRead.incoming.flag_present, false); assert.equal(omittedRead.parsed.flag_present, false);
  assert.equal(omittedRead.omission_present, true);
  assert.equal(observedRead.delivery, 'rpc_result');
  assert.equal(observedRead.native_action, 'messages');
  assert.equal(observedRead.native_stage, 'projection');
  for (const mode of ['denied', 'json']) {
    await fs.rename(join(observerDirectory, 'mcp-observation.receipt.json'), join(observerDirectory, `${mode}-previous.saved`));
    await fs.rename(join(observerDirectory, 'mcp-observation.used'), join(observerDirectory, `${mode}-previous-used.saved`));
    readFailure = mode;
    const withoutObservation = (await call(client, 'workrelay_server_read', readArgs)).result;
    await armObservation('mcp-read');
    const withObservation = (await call(client, 'workrelay_server_read', readArgs)).result;
    assert.deepEqual(withObservation, withoutObservation, 'diagnostics must not change the actual RPC tool denial/error');
    assert.equal(withObservation.isError, true);
    const failedRead = JSON.parse(await fs.readFile(join(observerDirectory, 'mcp-observation.receipt.json'), 'utf8'));
    assert.equal(failedRead.delivery, 'tool_error');
    assert.equal(failedRead.native_action, 'messages');
    assert.equal(failedRead.native_stage, mode === 'denied' ? 'native_status' : 'native_json');
    assert.equal(failedRead.native_status, mode === 'denied' ? 403 : 200);
    assert.equal(failedRead.error_type, mode === 'denied' ? 'Error' : 'SyntaxError');
    assert.doesNotMatch(JSON.stringify(failedRead), /PRIVATE|token\/body|invalid JSON/);
  }
  readFailure = null;
  assert.notEqual(visible.isError, true);
  assert.equal(visible.structuredContent.context.items[0].text, 'Review the release documentation.');
  assert.equal(visible.structuredContent.task_outcome.status, 'unknown');
  assert.equal(posts.length, 0, 'context read must never mutate');
  assert.equal((await call('other', 'workrelay_server_read', readArgs)).result.isError, true);
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
  assert.equal(stopped.result.structuredContent.queued_inputs_removed, false);
  assert.match(stopped.result.structuredContent.guidance, /may run on later resume/);
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
  const question = id => ({ id, sessionID: root, title: 'Questions',
    metadata: { kind: 'question', tool: { messageID: `msg_${id.slice(4)}`, id: `call_${id.slice(4)}` } },
    fields: [{ key: 'q0', title: 'Direction', type: 'string', required: true }], state: { status: 'pending' } });
  nativeForms = [question('frm_reply')];
  const pendingQuestions = await call(client, 'workrelay_server_waits', { session_id: root, limit: 1 });
  assert.equal(pendingQuestions.result.structuredContent.pending_question_count, 1);
  assert.equal(pendingQuestions.result.structuredContent.questions[0].form_id, 'frm_reply');
  const replyArgs = { session_id: root, operation_id: 'native-reply', form_id: 'frm_reply', answer: { q0: 'yes' } };
  const answered = await call(client, 'workrelay_server_question_reply', replyArgs);
  assert.equal(answered.result.isError, false, JSON.stringify(answered.result));
  assert.equal(answered.result.structuredContent.phase, 'question_answered_observed');
  assert.equal(questionMutations.length, 1);
  assert.equal((await call(client, 'workrelay_server_question_reply', replyArgs)).result.structuredContent.phase, 'question_answered_observed');
  assert.equal(questionMutations.length, 1, 'same stable reply receipt never posts twice');
  const reconciledQuestion = await call(client, 'workrelay_server_reconcile', { session_id: root, operation_id: 'native-reply' });
  assert.equal(reconciledQuestion.result.structuredContent.native_form_state, 'answered_recorded');
  nativeForms = [question('frm_cancel')];
  const cancelled = await call(client, 'workrelay_server_question_cancel', { session_id: root, operation_id: 'native-cancel', form_id: 'frm_cancel' });
  assert.equal(cancelled.result.isError, false, JSON.stringify(cancelled.result));
  assert.equal(cancelled.result.structuredContent.phase, 'question_cancelled_observed');
  assert.equal(questionMutations.length, 2);
  assert.equal((await call(client, 'workrelay_server_question_cancel', { session_id: root, operation_id: 'native-cancel', form_id: 'frm_cancel' })).result.structuredContent.phase, 'question_cancelled_observed');
  assert.equal(questionMutations.length, 2, 'same stable cancel receipt never posts twice');
  dropAck = true;
  const uncertain = { ...message, operation_id: 'lost-ack' };
  assert.equal((await call(client, 'workrelay_server_message', uncertain)).result.isError, true);
  dropAck = false;
  assert.equal((await call(client, 'workrelay_server_message', uncertain)).result.structuredContent.phase, 'queued_observed');
  assert.equal(posts.length, 4, 'lost acknowledgement reconciled from exact inbox ID without replay');
});
