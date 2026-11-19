import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { EventEmitter } from 'node:events';
import { promises as fs } from 'node:fs';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { join } from 'node:path';
import argon2 from 'argon2';
import { createManagedReader, harnessTaskOutcome, HARNESS_UNREADABLE } from '../src/workrelay/managed_server.mjs';
import { createPermissionNotifier, validateNotifySettings } from '../src/workrelay/permission_notify.mjs';
import { createLocalInteractions } from '../src/workrelay/issuer_interactions.mjs';
import { validateConfig } from '../src/workrelay/mcp.mjs';

const client = 'https://chatgpt.com/oauth/client.json';
const router = 'ses_workrelay_router0000000000000001';
const builder = 'ses_builder00000000000001';
const verifier = 'ses_verifier0000000000001';
const helper = 'ses_helper000000000000001';
const b = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp',
  subject: 'alice', client_id: client, server: 'http://127.0.0.1:12345', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
const expected = { issuer: b.issuer, audience: b.audience, principal: b.subject, managed_server: { ...b } };
const claims = { iss: b.issuer, aud: b.audience, sub: b.subject, client_id: client };
const json = value => new Response(JSON.stringify(value));

async function privateDir(t, prefix) {
  const dir = await fs.mkdtemp(join(tmpdir(), prefix)); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

// Fixture native server: router (idle "succeeded") -> builder (running) and
// verifier (idle) -> helper (blocked on a permission under the verifier).
function fixture(overrides = {}) {
  const state = {
    sessions: {
      [router]: { id: router, projectID: 'p', title: 'demodirector: fixes', agent: 'harness-router', location: { directory: '/work/dd' }, time: { idle: 1 }, outcome: 'succeeded' },
      [builder]: { id: builder, parentID: router, projectID: 'p', agent: 'harness-builder', location: { directory: '/work/dd' }, time: {} },
      [verifier]: { id: verifier, parentID: router, projectID: 'p', agent: 'harness-verifier', location: { directory: '/work/dd' }, time: { idle: 1 }, outcome: 'succeeded' },
      [helper]: { id: helper, parentID: verifier, projectID: 'p', agent: 'harness-quick-builder', location: { directory: '/work/dd' }, time: {} },
    },
    active: { [builder]: { type: 'running' } },
    permissions: { [helper]: [{ id: 'per_pending1', sessionID: helper, action: 'shell',
      resources: ['cd apps/api && cat >> tests/x.py <<EOF\npassword=hunter2\nEOF ' + 'x'.repeat(400), 'grep -n foo', 'python -m pytest', 'tail -8'] }] },
    replies: [], calls: [],
    ...overrides,
  };
  const fetcher = async (url, options) => {
    state.calls.push(`${options.method} ${url.pathname}${url.search}`);
    assert.equal(options.redirect, 'manual');
    const path = url.pathname;
    if (path === '/api/session/active') return json({ data: state.active });
    if (path === '/api/session') {
      const parent = url.searchParams.get('parentID');
      const data = Object.values(state.sessions).filter(session => parent ? session.parentID === parent : true);
      return json({ data: parent && state.badChild ? [{ ...data[0], parentID: 'ses_elsewhere' }] : data, cursor: {} });
    }
    let match = /^\/api\/session\/([^/]+)\/permission\/([^/]+)\/reply$/.exec(path);
    if (match) {
      assert.equal(options.method, 'POST');
      state.replies.push({ session: match[1], permission: match[2], body: JSON.parse(options.body) });
      state.permissions[match[1]] = state.permissions[match[1]].filter(item => item.id !== match[2]);
      return json({ data: true });
    }
    match = /^\/api\/session\/([^/]+)\/permission$/.exec(path);
    if (match) return json({ data: state.permissions[match[1]] ?? [] });
    match = /^\/api\/session\/([^/]+)$/.exec(path);
    if (match && state.sessions[match[1]]) return json({ data: state.sessions[match[1]] });
    return new Response('{}', { status: 404 });
  };
  return { state, fetcher };
}

const readerFor = (fetcher, options = {}) => createManagedReader(expected, () => ({ ...b }), {
  canonical: path => path,
  stat: () => ({ isFile: () => true, isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, dev: 1, ino: 1, mtimeMs: 1 }),
  loadService: async () => ({ discover: async () => ({ url: b.server, auth: {} }), headers: () => ({}) }),
  fetcher, ...options });

test('read exposes child sessions, blocked permissions and a non-terminal aggregate status', async () => {
  const { state, fetcher } = fixture();
  const notified = [];
  const read = await readerFor(fetcher, { onPendingPermissions: items => notified.push(...items) })('read', { session_id: router }, claims);
  assert.equal(read.runtime_status, 'succeeded', 'own runtime status is unchanged');
  assert.equal(read.runtime_scope, 'this_session_only');
  assert.equal(read.aggregate_status, 'blocked_on_permission');
  assert.equal(read.blocked_on_permission, true);
  assert.equal(read.pending_permissions.count, 1);
  assert.equal(read.pending_permissions.decision, 'human_operator_only');
  const [item] = read.pending_permissions.items;
  assert.equal(item.permission_id, 'per_pending1'); assert.equal(item.session_id, helper); assert.equal(item.action, 'shell');
  assert.equal(item.resource_preview.length, 3); assert.equal(item.resources_omitted, 1);
  assert.ok(item.resource_preview[0].length <= 160, 'resource pattern is truncated');
  assert.doesNotMatch(JSON.stringify(read), /hunter2/, 'resource text is redacted');
  assert.match(item.first_seen_at, /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual(read.children.items.map(child => [child.session_id, child.agent, child.status, child.pending_permission_count, child.depth]).sort(), [
    [builder, 'harness-builder', 'running', 0, 1],
    [helper, 'harness-quick-builder', 'blocked_on_permission', 1, 2],
    [verifier, 'harness-verifier', 'succeeded', 0, 1]].sort());
  assert.equal(read.children.running_count, 1); assert.equal(read.children.blocked_count, 1);
  assert.equal(Object.hasOwn(read.children.items[0], 'pending'), false);
  assert.match(read.pending_permissions.guidance, /operator/);
  // Per-session permission routes, never the location-scoped global list.
  assert.ok(state.calls.includes(`GET /api/session/${helper}/permission`));
  assert.equal(state.calls.some(call => call.includes('/api/permission')), false);
  assert.equal(state.replies.length, 0, 'reads never reply');
  assert.deepEqual(notified.map(entry => entry.permission_id), ['per_pending1']);
  assert.equal(notified[0].resource_preview, undefined, 'notifications receive no resource text');

  state.permissions = {};
  assert.equal((await readerFor(fetcher)('read', { session_id: router }, claims)).aggregate_status, 'running', 'running child keeps the tree running');
  state.active = {};
  const done = await readerFor(fetcher)('read', { session_id: router }, claims);
  assert.equal(done.aggregate_status, 'succeeded'); assert.equal(done.blocked_on_permission, false);
  state.badChild = true;
  await assert.rejects(readerFor(fetcher)('read', { session_id: router }, claims), 'child must name the queried parent');
});

test('session_check authorizes writes without a tree walk', async () => {
  const { state, fetcher } = fixture();
  const checked = await readerFor(fetcher)('session_check', { session_id: router }, claims);
  assert.equal(checked.session_id, router);
  assert.deepEqual(state.calls, [`GET /api/session/${router}`]);
});

test('discover adds a compact tree and task summary per session', async () => {
  const { fetcher } = fixture();
  const page = await readerFor(fetcher)('discover', {}, claims);
  const item = page.items.find(entry => entry.session_id === router);
  assert.equal(item.blocked_on_permission, true);
  assert.equal(item.aggregate_status, 'blocked_on_permission');
  assert.deepEqual(item.tree, { pending_permission_count: 1, child_count: 3, running_children: 1, blocked_children: 1, truncated: false });
  assert.match(item.task_outcome.reason, /not readable by workrelay/);
  assert.equal(page.items.find(entry => entry.session_id === helper).blocked_on_permission, true);
  assert.equal(JSON.stringify(page).includes('hunter2'), false);
  assert.equal(JSON.stringify(page).includes('cat >>'), false, 'discover carries counts, not resource text');
});

test('harness task outcome is read from the dispatch registry or reported as unreadable', async t => {
  assert.match(harnessTaskOutcome(undefined, '/work/dd', router).reason, new RegExp(HARNESS_UNREADABLE));
  const dir = await privateDir(t, 'workrelay-harness-');
  await fs.mkdir(join(dir, 'dispatch-ownership'), { mode: 0o700 });
  assert.equal(harnessTaskOutcome(dir, '/work/dd', router).status, 'no_task_intent');
  const key = JSON.stringify([router, 'fixes']);
  const registry = { intents: { [key]: { rootID: router, taskId: 'fixes', revision: 2, intent: { checks: [{ id: 'api-tests', mode: 'local' }, { id: 'api-ruff', mode: 'local' }] } },
    [JSON.stringify(['ses_other', 'x'])]: { rootID: 'ses_other', taskId: 'x', revision: 1, intent: { checks: [{ id: 'SECRET_OTHER' }] } } },
    intentEvidence: { [key]: { revision: 2, checks: { 'api-tests': { status: 'passed', evidence: 'PRIVATE_EVIDENCE' } }, lastStatus: 'in_progress', lastScope: 'checkpoint' } },
    records: [{ rootID: router, taskId: 'fixes', childID: builder, state: 'running' }, { rootID: router, taskId: 'fixes', childID: verifier, state: 'completed' }] };
  const file = join(dir, 'dispatch-ownership', createHash('sha256').update('/work/dd').digest('hex') + '.json');
  await fs.writeFile(file, JSON.stringify(registry), { mode: 0o600 });
  const outcome = harnessTaskOutcome(dir, '/work/dd', router);
  assert.equal(outcome.status, 'in_progress'); assert.equal(outcome.verification, 'harness_self_reported');
  assert.deepEqual(outcome.tasks[0].checks, [{ check_id: 'api-tests', status: 'passed' }, { check_id: 'api-ruff', status: 'pending' }]);
  assert.deepEqual(outcome.tasks[0].workers, { total: 2, by_state: { running: 1, completed: 1 } });
  assert.doesNotMatch(JSON.stringify(outcome), /PRIVATE_EVIDENCE|SECRET_OTHER/);
  registry.intentEvidence[key] = { revision: 2, checks: { 'api-tests': { status: 'passed' }, 'api-ruff': { status: 'passed' } }, lastStatus: 'completed', lastScope: 'task' };
  await fs.writeFile(file, JSON.stringify(registry));
  assert.equal(harnessTaskOutcome(dir, '/work/dd', router).status, 'completed');
  registry.intentEvidence[key].revision = 1; // stale evidence for an older intent revision
  await fs.writeFile(file, JSON.stringify(registry));
  assert.equal(harnessTaskOutcome(dir, '/work/dd', router).tasks[0].checks_passed, 0);
  await fs.chmod(file, 0o666);
  assert.match(harnessTaskOutcome(dir, '/work/dd', router).reason, /unreadable or unsafe/);
  await fs.chmod(file, 0o600);
  // Wired through read: a child read walks to its root session.
  const { fetcher } = fixture();
  const read = await readerFor(fetcher, { harnessStateDir: dir })('read', { session_id: helper }, claims);
  assert.equal(read.task_outcome.source, 'harness_dispatch_registry');
  assert.equal(read.task_outcome.tasks[0].task_id, 'fixes');
});

test('operator approval actions exist only on an operator reader and are directory-bound', async () => {
  const { state, fetcher } = fixture();
  const directories = ['/work/dd'];
  for (const action of ['pending_permissions', 'permission_reply'])
    await assert.rejects(readerFor(fetcher)(action, { directories, session_id: helper, permission_id: 'per_pending1', decision: 'once' }, claims), 'MCP reader cannot approve');
  const operator = readerFor(fetcher, { operatorActions: true });
  const listing = await operator('pending_permissions', { directories }, claims);
  assert.equal(listing.items.length, 1); assert.equal(listing.items[0].directory, '/work/dd');
  assert.ok(listing.items[0].resource_preview[0].length > 160, 'operator sees a longer (still redacted) preview');
  assert.equal((await operator('pending_permissions', { directories: ['/work/other'] }, claims)).items.length, 0);
  await assert.rejects(operator('permission_reply', { directories: ['/work/other'], session_id: helper, permission_id: 'per_pending1', decision: 'once' }, claims));
  await assert.rejects(operator('permission_reply', { directories, session_id: helper, permission_id: 'per_pending1', decision: 'yes' }, claims));
  await assert.rejects(operator('pending_permissions', { directories: ['/'] }, claims));
  assert.equal(state.replies.length, 0);
  assert.deepEqual(await operator('permission_reply', { directories, session_id: helper, permission_id: 'per_pending1', decision: 'once' }, claims),
    { replied: true, session_id: helper, permission_id: 'per_pending1', decision: 'once' });
  assert.deepEqual(state.replies, [{ session: helper, permission: 'per_pending1', body: { decision: 'once' } }]);
  assert.deepEqual(await operator('permission_reply', { directories, session_id: helper, permission_id: 'per_pending1', decision: 'once' }, claims),
    { replied: false, reason: 'not_pending' });
  assert.equal(state.replies.length, 1);
});

test('notifier fires once per request with summary fields only and never throws', async () => {
  const spawned = [], posted = [];
  const notify = createPermissionNotifier({ command: ['/usr/local/bin/notify', '--x'], webhookUrl: 'https://hooks.example.test/x', approvalUrl: 'https://wr.test/operator/permissions',
    spawnImpl: (cmd, args, options) => { const child = new EventEmitter(); child.stdin = new EventEmitter(); child.stdin.end = data => spawned.push({ cmd, args, options, data: JSON.parse(data) }); return child; },
    fetchImpl: async (url, options) => { posted.push({ url, body: JSON.parse(options.body), redirect: options.redirect }); return new Response('ok'); } });
  const item = { permission_id: 'per_a', session_id: helper, action: 'shell', first_seen_at: '2026-11-19T00:00:00.000Z', resource_preview: ['SECRET'] };
  notify([item]); notify([item]); notify([{ ...item, permission_id: 'per_b' }]);
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.deepEqual(spawned.map(entry => entry.data.permission_id), ['per_a', 'per_b']);
  assert.deepEqual(spawned[0].args, ['--x']); assert.deepEqual(spawned[0].options.env, { PATH: '/usr/bin:/bin' });
  assert.deepEqual(Object.keys(spawned[0].data).sort(), ['action', 'approval_url', 'event', 'first_seen_at', 'guidance', 'permission_id', 'session_id']);
  assert.deepEqual(posted.map(entry => entry.body.permission_id), ['per_a', 'per_b']); assert.equal(posted[0].redirect, 'error');
  assert.doesNotMatch(JSON.stringify([spawned, posted]), /SECRET/);
  const failing = createPermissionNotifier({ command: ['/nope'], spawnImpl: () => { throw Error('boom'); }, fetchImpl: async () => { throw Error('boom'); }, webhookUrl: 'https://x.test' });
  assert.doesNotThrow(() => failing([item]));
  assert.equal(createPermissionNotifier({}), null);
  for (const bad of [{ enabled: false }, { enabled: true, notify_command: ['relative'] }, { enabled: true, notify_webhook_url: 'http://example.test/x' },
    { enabled: true, directories: ['/'] }, { enabled: true, poll_interval_ms: 10 }, { enabled: true, extra: 1 }])
    assert.throws(() => validateNotifySettings(bad));
  validateNotifySettings({ enabled: true, directories: ['/work/dd'], notify_command: ['/bin/true'], notify_webhook_url: 'http://127.0.0.1:9/x', poll_interval_ms: 5000 });
});

test('gateway config validates operator approvals and harness state dir', () => {
  const base = { public_origin: 'https://workrelay.test', issuer: 'https://issuer.test', jwks_uri: 'https://issuer.test/jwks', audience: 'https://workrelay.test/mcp',
    principal: 'alice', owner: 'person-1', bridge_config: '/private/bridge.json', port: 8123 };
  assert.throws(() => validateConfig({ ...base, operator_approvals: { enabled: true } }), /managed_supervisor_file/);
  assert.throws(() => validateConfig({ ...base, harness_state_dir: 'relative' }), /harness_state_dir/);
  const ok = validateConfig({ ...base, managed_supervisor_file: '/private/managed.json', harness_state_dir: '/state', operator_approvals: { enabled: true, notify_command: ['/bin/true'] } });
  assert.equal(ok.harness_state_dir, '/state');
});

test('operator page requires password, single-use CSRF and origin before any decision', async t => {
  const dir = await privateDir(t, 'workrelay-operator-');
  const password = 'correct horse battery staple';
  await fs.writeFile(join(dir, 'human.json'), JSON.stringify({ accountId: 'alice', verifier: await argon2.hash(password, { type: argon2.argon2id }) }), { mode: 0o600 });
  const origin = 'https://workrelay.test';
  const replies = [];
  let pending = [{ permission_id: 'per_pending1', session_id: helper, action: 'shell', resource_preview: ['<script>alert(1)</script> pytest'], resources_omitted: 0,
    first_seen_at: '2026-11-19T00:00:00.000Z', session_title: 'DD fixes', directory: '/work/dd', agent: 'harness-builder' }];
  const handler = createLocalInteractions({ provider: { interactionDetails: async () => { throw Error('not oauth'); }, interactionFinished: async () => {} },
    directory: dir, origin, clientId: 'cid', resource: origin + '/mcp',
    operatorApprovals: { list: async () => ({ items: pending, truncated: false }),
      reply: async input => { replies.push(input); const found = pending.some(item => item.permission_id === input.permission_id); pending = []; return { replied: found }; } } });
  const server = createServer(async (req, res) => { if (!(await handler(req, res))) { res.statusCode = 404; res.end(); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}/operator/permissions`;
  const cookies = new Map();
  const send = async (form, { originHeader = origin, jar = cookies } = {}) => {
    const response = await fetch(base, { method: form ? 'POST' : 'GET', redirect: 'manual',
      headers: { ...(form ? { 'content-type': 'application/x-www-form-urlencoded', origin: originHeader } : {}),
        cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; ') }, body: form ? new URLSearchParams(form).toString() : undefined });
    for (const set of response.headers.getSetCookie()) {
      const [pair] = set.split(';'); const [name, value] = pair.split('=');
      if (/Max-Age=0/.test(set)) jar.delete(name); else jar.set(name, value);
      assert.match(set, /Secure; HttpOnly; SameSite=Strict/);
    }
    return { status: response.status, text: await response.text(), headers: response.headers };
  };
  const tokens = text => ({ flow: /name="flow" value="([^"]+)"/.exec(text)?.[1], csrf: /name="csrf" value="([^"]+)"/.exec(text)?.[1] });
  const login = await send();
  assert.equal(login.status, 200); assert.match(login.text, /type="password"/);
  assert.match(login.headers.get('content-security-policy'), /default-src 'none'/);
  assert.doesNotMatch(login.text, /per_pending1/, 'nothing is listed before sign-in');
  let form = tokens(login.text);
  assert.equal((await send({ ...form, password: 'wrong password for operator' })).status, 403);
  assert.equal((await send({ ...form, password })).status, 403, 'login CSRF is single-use');
  form = tokens((await send()).text);
  assert.equal((await send({ ...form, password }, { originHeader: 'https://evil.test' })).status, 403, 'foreign origin denied');
  form = tokens((await send()).text);
  const listed = await send({ ...form, password });
  assert.equal(listed.status, 200);
  assert.ok(cookies.has('__Host-workrelay-operator'));
  assert.match(listed.text, /per_pending1/); assert.match(listed.text, /\/work\/dd/);
  assert.doesNotMatch(listed.text, /<script>/, 'request text is escaped');
  const page = tokens(listed.text);
  const decide = { ...page, session_id: helper, permission_id: 'per_pending1', decision: 'once' };
  assert.equal((await send(decide, { jar: new Map() })).status, 403, 'decision requires the operator session cookie');
  assert.equal(replies.length, 0);
  assert.equal((await send({ ...decide, decision: 'approve_all' })).status, 403);
  // The invalid attempt above did not consume the CSRF; the valid decision succeeds once.
  const decided = await send(decide);
  assert.equal(decided.status, 200); assert.match(decided.text, /Recorded &quot;once&quot;/);
  assert.deepEqual(replies, [{ session_id: helper, permission_id: 'per_pending1', decision: 'once' }]);
  assert.equal((await send(decide)).status, 403, 'decision CSRF is single-use');
  assert.equal(replies.length, 1);
  const refreshed = await send(tokens(decided.text));
  assert.match(refreshed.text, /No pending permission requests/);
  // Without operatorApprovals configured the route does not exist.
  const plain = createLocalInteractions({ provider: { interactionDetails: async () => ({}), interactionFinished: async () => {} }, directory: dir, origin, clientId: 'cid', resource: origin + '/mcp' });
  const res = { statusCode: 0, writeHead(code) { this.statusCode = code; }, end() {}, setHeader() {} };
  assert.equal(await plain({ url: '/operator/permissions', method: 'GET', headers: {}, socket: {} }, res), true);
  assert.equal(res.statusCode, 404);
});
