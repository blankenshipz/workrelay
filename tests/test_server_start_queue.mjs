import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import { exportJWK, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { createGateway, validateConfig, startOperationID } from '../src/workrelay/mcp.mjs';
import { contextTokens, harnessParkedAsks } from '../src/workrelay/managed_server.mjs';

const client = 'https://chatgpt.com/oauth/client.json';
const root = 'ses_queueroot0000000000000001';
const child = 'ses_queuechild000000000000001';
const listen = s => new Promise(resolve => s.listen(0, '127.0.0.1', resolve));
const close = s => new Promise(resolve => { s.close(resolve); s.closeAllConnections(); });
const created = op => 'ses_c' + createHash('sha256').update(op).digest('hex').slice(0, 24);

async function setup(t, { notify = true, harness = false } = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-start-')); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'test', alg: 'RS256', use: 'sig' };
  const native = { active: {}, permissions: [], sessions: {}, messages: {}, children: [],
    projects: [{ id: 'project', name: 'Scanner', canonical: dir }, { id: 'other', name: 'Other', canonical: dir + '-other' }] };
  native.sessions[root] = { id: root, projectID: 'project', title: 'Deploy fix', agent: 'harness-router', location: { directory: dir }, time: { created: 1, updated: 1 } };
  const backend = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    const url = new URL(req.url, 'http://x');
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    if (url.pathname === '/api/project') return res.end(JSON.stringify(native.projects));
    if (url.pathname === '/api/session/active') return res.end(JSON.stringify({ data: native.active }));
    let m = url.pathname.match(/^\/api\/session\/(ses[A-Za-z0-9_-]+)(\/permission|\/message)?$/);
    if (m && native.failSessions?.has(m[1])) { res.statusCode = 500; return res.end('{}'); }
    if (m && native.sessions[m[1]]) {
      if (m[2] === '/permission') return res.end(JSON.stringify({ data: native.permissions.filter(item => item.sessionID === m[1]) }));
      if (m[2] === '/message') return res.end(JSON.stringify({ data: native.messages[m[1]] ?? [], cursor: {} }));
      return res.end(JSON.stringify({ data: native.sessions[m[1]] }));
    }
    if (url.pathname === '/api/session') {
      const parent = url.searchParams.get('parentID');
      return res.end(JSON.stringify({ data: parent === root ? native.children : [], cursor: {} }));
    }
    res.statusCode = 404; res.end('{}');
  });
  await listen(backend); t.after(() => close(backend));
  const origin = `http://127.0.0.1:${backend.address().port}`;
  const registration = join(dir, 'service.json'), module = join(dir, 'client', 'dist', 'service.js'), capability = join(dir, 'managed', 'capability.json');
  await fs.mkdir(dirname(module), { recursive: true }); await fs.mkdir(dirname(capability), { mode: 0o700 });
  await fs.writeFile(join(dir, 'client', 'package.json'), '{"type":"module"}');
  await fs.writeFile(registration, '{}', { mode: 0o600 });
  await fs.writeFile(module, `export const discover=async()=>({url:${JSON.stringify(origin)},auth:{}});export const headers=()=>({});`, { mode: 0o600 });
  const stateDir = join(dir, 'hstate');
  if (harness) { await fs.mkdir(join(stateDir, 'telemetry'), { recursive: true, mode: 0o700 }); await fs.chmod(stateDir, 0o700); }
  const reserve = createServer(); await listen(reserve); const port = reserve.address().port; await close(reserve);
  const config = validateConfig({ public_origin: 'https://workrelay.test', issuer: origin, jwks_uri: origin + '/jwks', audience: 'https://workrelay.test/mcp',
    principal: 'alice', owner: 'alice', bridge_config: join(dir, 'bridge.json'), port, managed_supervisor_file: capability,
    ...(harness ? { harness_state_dir: stateDir } : {}),
    managed_server: { server: origin, service_registration: registration, client_service_module: module },
    ...(notify ? { session_notify: { enabled: true, stall_minutes: 10 } } : {}) }, { testIssuer: true });
  await fs.writeFile(capability, JSON.stringify({ ...config.managed_server, enabled: true, revoked: false, issuer: origin, audience: config.audience, subject: 'alice', client_id: client }), { mode: 0o600 });
  await fs.writeFile(config.bridge_config, JSON.stringify({ directory: dir, managed_allowed_directories: [dir] }), { mode: 0o600 });
  const invoked = [];
  const receipts = new Map();
  const gateway = createGateway(config, { testIssuer: true,
    invoke: async (_config, _command, input) => {
      invoked.push(input);
      if (input.action === 'create') {
        const id = created(input.operation_id);
        const prior = receipts.get('c:' + input.operation_id);
        if (prior && prior !== JSON.stringify([input.project_id, input.title])) return { error: 'x', code: 'CONTROL_AUTHORIZATION_OR_VALIDATION_DENIED' };
        receipts.set('c:' + input.operation_id, JSON.stringify([input.project_id, input.title]));
        // Ledger semantics: a denied create stays denied; retrying the same
        // operation returns the denied receipt (exit 0) and creates nothing.
        if (native.deniedOps?.has(input.operation_id)) return { operation_id: input.operation_id, session_id: id, phase: 'denied', inference_started: false, denial_code: 'UNEXPECTED_PREPOST', denied_at_ms: 1 };
        if (native.denyCreates > 0) {
          native.denyCreates--; (native.deniedOps ??= new Set()).add(input.operation_id);
          return { error: 'x', code: 'CONTROL_NOT_SENT', effect: 'no_post_permitted', replay_permitted: false, operation_id: input.operation_id, session_id: id, phase: 'denied', denial_code: native.denyCode ?? 'UNEXPECTED_PREPOST', denied_at_ms: 1 };
        }
        if (native.reservedCreate) return { error: 'x', code: 'CONTROL_NOT_SENT', effect: 'no_post_permitted', replay_permitted: false, operation_id: input.operation_id, session_id: id, phase: 'reserved' };
        if (native.unreadableCreate) return { operation_id: input.operation_id, session_id: id, phase: 'created' };
        native.sessions[id] ??= { id, projectID: input.project_id, title: input.title, agent: 'harness-router', location: { directory: dir }, time: { created: 2, updated: 2 } };
        return { operation_id: input.operation_id, session_id: id, phase: 'created' };
      }
      if (native.failMessage) { native.failMessage = false; return { error: 'x', code: 'CONTROL_UNCERTAIN', effect: 'may_have_been_applied' }; }
      return { operation_id: input.operation_id, session_id: input.session_id, message_id: 'msg_x', phase: 'queued' };
    } });
  await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve)); t.after(() => close(gateway));
  const call = async (name, args) => {
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: client }).setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(origin).setAudience(config.audience).setSubject('alice').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
    const sdk = new Client({ name: 'start-test', version: '1' });
    try {
      await sdk.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
      return { result: await sdk.callTool({ name, arguments: args }), tools: (await sdk.listTools()).tools };
    } finally { await sdk.close(); }
  };
  return { dir, call, native, invoked, stateDir, startFile: join(dirname(capability), 'server-start.json') };
}

test('message/steer/resume report queued_behind: null when idle, busy with age, ask with redacted summary', async t => {
  const { call, native, invoked } = await setup(t);
  let out = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-1', text: 'hi' })).result.structuredContent;
  assert.equal(out.queued_behind, null); assert.equal(out.phase, 'queued');
  assert.ok(invoked.every(input => !('queued_behind' in input)));

  native.active = { [root]: { type: 'running' } };
  native.messages[root] = [{ id: 'msg_a', type: 'assistant', time: { created: Date.now() - 1000 } }, { id: 'msg_u', type: 'user', text: 'x', time: { created: Date.now() - 90_000 } }];
  out = (await call('workrelay_server_steer', { session_id: root, operation_id: 'op-2', text: 'focus' })).result.structuredContent;
  assert.equal(out.queued_behind, 'busy'); assert.ok(out.queued_age_seconds >= 89 && out.queued_age_seconds < 120, String(out.queued_age_seconds));
  assert.match(out.queued_guidance, /next supported boundary/);

  native.children = [{ id: child, parentID: root, projectID: 'project', agent: 'harness-verifier', location: { directory: '/x' }, time: { updated: 5 } }];
  native.sessions[child] = native.children[0];
  native.active = { [root]: { type: 'running' }, [child]: { type: 'running' } };
  native.permissions = [{ id: 'per_1', sessionID: child, action: 'bash', resources: ['cat ~/.env token=SUPERSECRET123 && ls'] }];
  out = (await call('workrelay_server_resume', { session_id: root, operation_id: 'op-3', text: 'go' })).result.structuredContent;
  assert.equal(out.queued_behind, 'ask');
  assert.equal(out.queued_ask.permission_id, 'per_1'); assert.equal(out.queued_ask.in_child_session, true); assert.equal(out.queued_ask.agent, 'harness-verifier');
  assert.match(out.queued_ask.summary, /^bash: cat ~\/\.env token=\[REDACTED\]/);
  assert.doesNotMatch(JSON.stringify(out), /SUPERSECRET123/);
  assert.ok(out.queued_ask.summary.length <= 120);
  assert.equal(typeof out.queued_age_seconds, 'number'); assert.match(out.queued_age_source, /gateway_first_seen/);
  assert.match(out.queued_ask.answered_by, /human operator only/);
  assert.match(out.queued_guidance, /Do not resend/);
});

test('harness park log dates a parked ask', async t => {
  const { call, native, stateDir } = await setup(t, { harness: true });
  native.active = { [root]: { type: 'running' } };
  native.permissions = [{ id: 'per_park', sessionID: root, action: 'glob', resources: ['/opt/*'] }];
  const at = new Date(Date.now() - 60_000).toISOString();
  await fs.writeFile(join(stateDir, 'telemetry', 'permission-park.jsonl'), 'garbage\n' + JSON.stringify({ at, outcome: 'parked', requestID: 'per_park', sessionID: root, pendingMs: 600_000 }) + '\n', { mode: 0o600 });
  const out = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-p', text: 'hi' })).result.structuredContent;
  assert.equal(out.queued_behind, 'ask'); assert.equal(out.queued_ask.parked, true); assert.equal(out.queued_age_source, 'harness_park_log');
  assert.ok(out.queued_age_seconds >= 659 && out.queued_age_seconds < 700, String(out.queued_age_seconds));
  assert.equal(harnessParkedAsks(stateDir, new Set(['per_none'])).size, 0);
  assert.equal(harnessParkedAsks(undefined, new Set(['per_park'])).size, 0);
});

test('contextTokens sums the newest assistant message token use', () => {
  assert.equal(contextTokens([{ type: 'user' }, { type: 'assistant', tokens: { input: 10, output: 5, reasoning: 1, cache: { read: 100, write: 4 } } }, { type: 'assistant', tokens: { input: 1 } }]), 120);
  assert.equal(contextTokens([{ type: 'user' }]), null);
  assert.equal(contextTokens(null), null);
});

test('workrelay_server_start creates and messages in one idempotent call; resolves projects by name', async t => {
  const { call, invoked, native } = await setup(t);
  const first = await call('workrelay_server_start', { project: 'scanner', agent: 'Harny', text: 'Fix the flaky test\nmore detail' });
  assert.ok(first.tools.some(tool => tool.name === 'workrelay_server_start'));
  const out = first.result.structuredContent;
  assert.notEqual(first.result.isError, true, JSON.stringify(out));
  assert.match(out.operation_id, /^start_[a-f0-9]{40}$/);
  assert.equal(out.status, 'queued'); assert.equal(out.created, true); assert.equal(out.reused, false); assert.equal(out.queued_behind, null);
  assert.equal(out.project.label, 'Scanner');
  assert.equal(out.session_id, created(out.operation_id));
  assert.deepEqual(invoked.map(input => [input.action, input.operation_id]), [['create', out.operation_id], ['message', out.operation_id + '-m']]);
  assert.equal(invoked[0].project_id, 'project'); assert.equal(invoked[0].title, 'Fix the flaky test');
  assert.equal(out.notify.agent_listener, 'not_registered');
  // Retry: same session, same operation IDs (the control layer dedupes).
  const again = (await call('workrelay_server_start', { project: 'scanner', agent: 'Harny', text: 'Fix the flaky test\nmore detail' })).result.structuredContent;
  assert.equal(again.session_id, out.session_id); assert.equal(again.operation_id, out.operation_id);
  assert.equal(invoked.length, 3); assert.deepEqual([invoked[2].action, invoked[2].operation_id], ['message', out.operation_id + '-m']);
  // Unknown and ambiguous projects.
  assert.equal((await call('workrelay_server_start', { project: 'nope', agent: 'Harny', text: 'x' })).result.structuredContent.error, 'project_not_found');
  native.projects.push({ id: 'dup', name: 'Scanner', canonical: '/elsewhere' });
  const amb = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Harny', text: 'x' })).result.structuredContent;
  assert.equal(amb.error, 'project_ambiguous'); assert.equal(amb.candidates.length, 2);
  // project_id still works when names collide.
  const byId = 'project_' + createHash('sha256').update('project').digest('hex');
  const ok = (await call('workrelay_server_start', { project: byId, agent: 'Harny', text: 'x', operation_id: 'mine-1' })).result.structuredContent;
  assert.equal(ok.operation_id, 'mine-1'); assert.equal(ok.created, true);
});

test('workrelay_server_start reuse continues the latest session and rolls over above 150k tokens', async t => {
  const { call, invoked, native } = await setup(t, { notify: false });
  const first = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'task one', reuse: true })).result.structuredContent;
  assert.equal(first.created, true);
  native.messages[first.session_id] = [{ id: 'msg_a', type: 'assistant', tokens: { input: 1000, output: 10, cache: { read: 90000 } } }];
  native.active = { [first.session_id]: { type: 'running' } };
  native.messages[first.session_id].push({ id: 'msg_u', type: 'user', time: { created: Date.now() - 5000 } });
  const second = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'task two', reuse: true })).result.structuredContent;
  assert.equal(second.session_id, first.session_id); assert.equal(second.reused, true); assert.equal(second.created, false);
  assert.equal(second.context_tokens, 91010); assert.equal(second.queued_behind, 'busy');
  assert.equal(invoked.at(-1).action, 'message'); assert.equal(invoked.filter(input => input.action === 'create').length, 1);
  // Another agent does not share it.
  const other = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Other', text: 'task two', reuse: true })).result.structuredContent;
  assert.notEqual(other.session_id, first.session_id); assert.equal(other.created, true);
  // Over the threshold: a fresh session, with the old one named.
  native.messages[first.session_id] = [{ id: 'msg_b', type: 'assistant', tokens: { input: 2000, cache: { read: 160000 } } }];
  const third = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'task three', reuse: true })).result.structuredContent;
  assert.equal(third.created, true); assert.notEqual(third.session_id, first.session_id);
  assert.deepEqual(third.rolled_over_from, { session_id: first.session_id, reason: 'context_over_150k', context_tokens: 162000 });
  const fourth = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'task four', reuse: true })).result.structuredContent;
  assert.equal(fourth.session_id, third.session_id);
  // Existing tools unchanged.
  const tools = (await call('workrelay_server_projects', {})).tools.map(tool => tool.name);
  for (const name of ['workrelay_server_create', 'workrelay_server_message', 'workrelay_server_steer', 'workrelay_server_resume']) assert.ok(tools.includes(name));
});

test('auto start operation IDs are stable per day and differ by input', () => {
  const base = { clientID: 'c', agent: 'a', projectID: 'p', text: 't', reuse: false, day: '2026-11-20' };
  assert.equal(startOperationID(base), startOperationID({ ...base }));
  assert.notEqual(startOperationID(base), startOperationID({ ...base, text: 'u' }));
  assert.notEqual(startOperationID(base), startOperationID({ ...base, reuse: true }));
  assert.notEqual(startOperationID(base), startOperationID({ ...base, day: '2026-11-21' }));
});

test('start: uncertain reuse send retries to the same session (no re-decision), replays are flagged, conflicts refused, unreadable reuse fails closed', async t => {
  const { call, invoked, native } = await setup(t, { notify: false });
  const first = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'one', reuse: true })).result.structuredContent;
  native.failMessage = true;
  const failed = await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'two', reuse: true });
  assert.equal(failed.result.isError, true); assert.equal(failed.result.structuredContent.session_id, first.session_id);
  // Meanwhile the session crosses the rollover threshold: the retry must not move to a new session.
  native.messages[first.session_id] = [{ id: 'msg_b', type: 'assistant', tokens: { input: 200000 } }];
  const creates = invoked.filter(input => input.action === 'create').length;
  const retry = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'two', reuse: true })).result.structuredContent;
  assert.equal(retry.session_id, first.session_id); assert.equal(invoked.filter(input => input.action === 'create').length, creates);
  assert.equal(retry.replayed, undefined);
  const replay = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'two', reuse: true })).result.structuredContent;
  assert.equal(replay.replayed, true); assert.equal(replay.session_id, first.session_id);
  // Explicit operation_id reused with other text: refused.
  await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'alpha', operation_id: 'fixed-1' });
  const conflict = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Scan', text: 'beta', operation_id: 'fixed-1' })).result.structuredContent;
  assert.equal(conflict.error, 'operation_id_conflict');
  // Unreadable (not gone) latest session: nothing sent, no new session.
  const latest = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Gone', text: 'x', reuse: true })).result.structuredContent;
  native.failSessions = new Set([latest.session_id]);
  const before = invoked.length;
  const unreadable = (await call('workrelay_server_start', { project: 'Scanner', agent: 'Gone', text: 'y', reuse: true })).result.structuredContent;
  assert.equal(unreadable.error, 'reuse_session_unreadable'); assert.equal(invoked.length, before);
  native.failSessions = undefined;
  assert.equal((await call('workrelay_server_start', { project: 'Scanner', agent: 'Gone', text: 'y' })).result.structuredContent.created, true);
});

test('queue state that cannot be read never blocks the send', async t => {
  const { call, native } = await setup(t);
  native.sessions[root].projectID = 'project'; native.active = 'broken';
  const out = (await call('workrelay_server_message', { session_id: root, operation_id: 'op-u', text: 'hi' })).result.structuredContent;
  assert.equal(out.phase, 'queued'); assert.equal(out.queued_behind, null); assert.equal(out.queue_state, 'unavailable');
});

test('contextTokens skips in-flight zero-usage messages', () => {
  assert.equal(contextTokens([{ type: 'assistant', tokens: { input: 0, output: 0 } }, { type: 'assistant', tokens: { input: 7 } }]), 7);
});

// r28: a denied create must never be recorded as created/latest, a retry makes a
// fresh create operation, and a gone latest session is dropped on reuse.
const readStart = async file => JSON.parse(await fs.readFile(file, 'utf8'));

test('start: denied create returns create_denied with code and hint, records nothing reusable, retry creates fresh', async t => {
  const { call, invoked, native, startFile } = await setup(t, { notify: false });
  native.denyCreates = 1;
  const denied = await call('workrelay_server_start', { project: 'Scanner', agent: 'DD', text: 'Reply with OK only.', reuse: true });
  const out = denied.result.structuredContent;
  assert.equal(denied.result.isError, true); assert.equal(out.error, 'create_denied'); assert.equal(out.denial_code, 'UNEXPECTED_PREPOST');
  assert.equal(out.stage, 'create'); assert.equal(out.created, false); assert.equal(out.create_operation_id, out.operation_id);
  assert.match(out.guidance, /no session exists/); assert.match(out.retry, /fresh create attempt/);
  assert.equal(out.session_id, undefined, 'a denied create names no session');
  assert.ok(!invoked.some(input => input.action === 'message'), 'nothing sent');
  let store = await readStart(startFile);
  assert.deepEqual(Object.values(store.latest), [], 'denied session never becomes latest');
  const [entry] = Object.values(store.ops); assert.equal(entry.session_id, null); assert.equal(entry.created, false); assert.equal(entry.create_attempt, 1);
  // Retry: a fresh create operation, then the first message.
  const retry = (await call('workrelay_server_start', { project: 'Scanner', agent: 'DD', text: 'Reply with OK only.', reuse: true })).result.structuredContent;
  assert.equal(retry.created, true, JSON.stringify(retry)); assert.equal(retry.create_operation_id, out.operation_id + '-c1');
  assert.equal(retry.session_id, created(out.operation_id + '-c1')); assert.ok(native.sessions[retry.session_id]);
  assert.deepEqual(invoked.slice(-2).map(input => [input.action, input.operation_id]), [['create', out.operation_id + '-c1'], ['message', out.operation_id + '-m']]);
  store = await readStart(startFile);
  assert.deepEqual(Object.values(store.latest).map(item => item.session_id), [retry.session_id]);
  // A later identical call is a replay of the same session; no further create.
  const creates = invoked.filter(input => input.action === 'create').length;
  const replay = (await call('workrelay_server_start', { project: 'Scanner', agent: 'DD', text: 'Reply with OK only.', reuse: true })).result.structuredContent;
  assert.equal(replay.replayed, true); assert.equal(replay.session_id, retry.session_id);
  assert.equal(invoked.filter(input => input.action === 'create').length, creates);
});

test('start: a recorded dead session (legacy created:true on a denied receipt) is replaced by one fresh create in the same call', async t => {
  const { call, invoked, native, startFile } = await setup(t, { notify: false });
  // Reproduce the live v0.4.0 state: denied create receipt, but the store says created.
  native.denyCreates = 1;
  const first = (await call('workrelay_server_start', { project: 'Scanner', agent: 'YS', text: 'hello' })).result.structuredContent;
  const op = first.operation_id, dead = created(op);
  const store = await readStart(startFile); const [opKey] = Object.keys(store.ops); const latestKey = JSON.stringify(JSON.parse(opKey).slice(0, 3));
  store.ops[opKey] = { session_id: dead, created: true, rolled_over_from: null, message: false, digest: store.ops[opKey].digest, at: 1 };
  store.latest[latestKey] = { session_id: dead, at: 1 };
  await fs.writeFile(startFile, JSON.stringify(store), { mode: 0o600 });
  const before = invoked.length;
  const out = (await call('workrelay_server_start', { project: 'Scanner', agent: 'YS', text: 'hello' })).result.structuredContent;
  assert.equal(out.created, true, JSON.stringify(out)); assert.notEqual(out.session_id, dead); assert.equal(out.create_operation_id, op + '-c1');
  assert.deepEqual(invoked.slice(before).map(input => [input.action, input.operation_id]), [['create', op], ['create', op + '-c1'], ['message', op + '-m']]);
  assert.equal((await readStart(startFile)).latest[latestKey].session_id, out.session_id);
});

test('start: reuse drops a latest entry whose session is gone (404) and starts fresh', async t => {
  const { call, native, startFile } = await setup(t, { notify: false });
  const first = (await call('workrelay_server_start', { project: 'Scanner', agent: 'R', text: 'one', reuse: true })).result.structuredContent;
  delete native.sessions[first.session_id];
  const second = (await call('workrelay_server_start', { project: 'Scanner', agent: 'R', text: 'two', reuse: true })).result.structuredContent;
  assert.equal(second.created, true, JSON.stringify(second)); assert.notEqual(second.session_id, first.session_id);
  assert.deepEqual(second.rolled_over_from, { session_id: first.session_id, reason: 'gone', context_tokens: null });
  assert.deepEqual(Object.values((await readStart(startFile)).latest).map(item => item.session_id), [second.session_id]);
});

test('start: unconfirmed or concurrently reserved creates are not recorded and never mint a fresh operation', async t => {
  const { call, invoked, native, startFile } = await setup(t, { notify: false });
  native.unreadableCreate = true;
  const unconfirmed = (await call('workrelay_server_start', { project: 'Scanner', agent: 'U', text: 'x' })).result.structuredContent;
  assert.equal(unconfirmed.error, 'create_unconfirmed'); assert.equal(unconfirmed.created, false);
  native.unreadableCreate = false; native.reservedCreate = true;
  const reserved = (await call('workrelay_server_start', { project: 'Scanner', agent: 'U', text: 'x' })).result.structuredContent;
  assert.equal(reserved.code, 'CONTROL_NOT_SENT'); assert.notEqual(reserved.error, 'create_denied');
  native.reservedCreate = false;
  let store = {}; try { store = await readStart(startFile); } catch { /* no file yet is fine */ }
  assert.deepEqual(Object.values(store.latest ?? {}), []);
  const ok = (await call('workrelay_server_start', { project: 'Scanner', agent: 'U', text: 'x' })).result.structuredContent;
  assert.equal(ok.created, true); assert.equal(ok.create_operation_id, undefined, 'same create operation reconciled');
  assert.ok(invoked.filter(input => input.action === 'create').every(input => input.operation_id === ok.operation_id));
});

test('start: persistent denial is bounded', async t => {
  const { call, native } = await setup(t, { notify: false });
  native.denyCreates = 1000; native.denyCode = 'CREATE_CAPACITY_DENIED';
  let out;
  for (let i = 0; i < 21; i++) out = (await call('workrelay_server_start', { project: 'Scanner', agent: 'B', text: 'x' })).result.structuredContent;
  assert.equal(out.error, 'create_retry_limit');
  const denied = native.deniedOps.size; assert.equal(denied, 20);
});

test('start: a lost attempt counter walks past stale denied receipts (one fresh create per call); derived suffixes are rejected', async t => {
  const { call, invoked, native, startFile } = await setup(t, { notify: false });
  native.denyCreates = 2;
  const a = (await call('workrelay_server_start', { project: 'Scanner', agent: 'L', text: 'x' })).result.structuredContent;
  const b = (await call('workrelay_server_start', { project: 'Scanner', agent: 'L', text: 'x' })).result.structuredContent;
  assert.equal(a.create_operation_id, a.operation_id); assert.equal(b.create_operation_id, a.operation_id + '-c1');
  await fs.writeFile(startFile, JSON.stringify({ version: 1, latest: {}, ops: {} }), { mode: 0o600 }); // counter lost
  const before = invoked.length;
  const ok = (await call('workrelay_server_start', { project: 'Scanner', agent: 'L', text: 'x' })).result.structuredContent;
  assert.equal(ok.created, true, JSON.stringify(ok)); assert.equal(ok.create_operation_id, a.operation_id + '-c2');
  const op = a.operation_id;
  assert.deepEqual(invoked.slice(before).map(input => input.operation_id), [op, op + '-c1', op + '-c2', op + '-m']);
  for (const bad of ['job-m', 'job-c3']) {
    const refused = await call('workrelay_server_start', { project: 'Scanner', agent: 'L', text: 'y', operation_id: bad });
    assert.equal(refused.result.isError, true, bad);
  }
});
