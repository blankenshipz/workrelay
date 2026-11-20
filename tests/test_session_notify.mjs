import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { createSessionNotifier, validateNotifyTarget, validateSessionNotifySettings } from '../src/workrelay/session_notify.mjs';

const S = 'ses_root000000000000000001';
const C = 'ses_child00000000000000001';
const URL_OK = 'https://hooks.grok.example.com/routines/abc/trigger';

async function privateDir(t) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-notify-')); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

function harness(t, { statePath, settings = {}, fail = false } = {}) {
  let clock = 1_000_000;
  const view = { session_id: S, title: 'fix things', directory: '/work/dd', runtime_status: 'idle', aggregate_status: 'idle', last_activity_at: 1, idle_at: null,
    running_children: 0, failed_children: [], task_outcome: 'no_task_intent', pending: [] };
  const sent = [];
  let watchFails = false;
  const notifier = createSessionNotifier({ settings, statePath, approvalUrl: 'http://127.0.0.1:49381/operator/permissions', now: () => clock,
    watch: async id => { assert.equal(id, S); if (watchFails) throw Error('down'); return structuredClone(view); },
    transport: async (url, { body, headers }) => {
      if (fail) throw Object.assign(Error('x'), { data: { reason: 'network_error' } });
      sent.push({ url, headers, event: JSON.parse(body) }); return { status: 200, body: '' };
    } });
  return { notifier, view, sent, advance: ms => { clock += ms; }, now: () => clock, setWatchFails: v => { watchFails = v; } };
}

test('notify target validation: public HTTPS only, optional secret header pair', () => {
  assert.deepEqual(validateNotifyTarget({ url: URL_OK }), { url: URL_OK });
  assert.deepEqual(validateNotifyTarget({ url: URL_OK, header_name: 'X-Routine-Secret', header_value: 's3cret', stall_minutes: 15 }),
    { url: URL_OK, header_name: 'X-Routine-Secret', header_value: 's3cret', stall_minutes: 15 });
  for (const url of ['http://hooks.grok.example.com/x', 'https://127.0.0.1/x', 'https://[::1]/x', 'https://10.0.0.5/x', 'https://localhost/x',
    'https://box.local/x', 'https://svc.internal/x', 'https://user:pw@hooks.example.com/x', 'https://hooks.example.com:8443/x',
    'https://hooks.example.com/x#frag', 'https://intranet/x', 'file:///etc/passwd', 'not a url', 'https://a.test/x', 'https://' + 'a'.repeat(2050) + '.com'])
    assert.throws(() => validateNotifyTarget({ url }), /invalid notify target/, url);
  for (const extra of [{ header_name: 'X-A' }, { header_value: 'v' }, { header_name: 'Host', header_value: 'v' }, { header_name: 'Content-Type', header_value: 'v' },
    { header_name: 'X-Workrelay-Event', header_value: 'v' }, { header_name: 'X-A', header_value: 'a\r\nInjected: 1' }, { header_name: 'bad name', header_value: 'v' },
    { header_name: 'X-A', header_value: 'v'.repeat(1025) }, { header_name: 'X-A', header_value: 'caf\u00e9\u2603' }, { stall_minutes: 0 }, { stall_minutes: 2.5 }, { other: 1 }])
    assert.throws(() => validateNotifyTarget({ url: URL_OK, ...extra }), /invalid notify target/, JSON.stringify(extra));
  validateSessionNotifySettings({ enabled: true, stall_minutes: 10, min_interval_ms: 120000, poll_interval_ms: 30000 });
  for (const bad of [{}, { enabled: false }, { enabled: true, stall_minutes: 0 }, { enabled: true, min_interval_ms: 1000 }, { enabled: true, state_file: 'rel.json' }, { enabled: true, x: 1 }])
    assert.throws(() => validateSessionNotifySettings(bad), /session_notify/, JSON.stringify(bad));
});

test('permission asks are sent immediately, once, with preview and directory; no secrets in the payload', async t => {
  const h = harness(t);
  const status = h.notifier.set(S, { url: URL_OK, header_name: 'X-Routine-Secret', header_value: 'top-secret-value' });
  assert.equal(status.url_host, 'hooks.grok.example.com'); assert.equal(status.secret_header, 'X-Routine-Secret');
  assert.ok(!JSON.stringify(status).includes('top-secret-value') && !JSON.stringify(status).includes('/routines/'));
  Object.assign(h.view, { aggregate_status: 'blocked_on_permission', runtime_status: 'running', pending: [
    { permission_id: 'per_1', session_id: C, action: 'shell', resource_preview: ['docker compose --env-file ../.env up -d'], resources_omitted: 0, directory: '/work/dd/app' }] });
  await h.notifier.tick();
  assert.equal(h.sent.length, 1);
  const { event, headers, url } = h.sent[0];
  assert.equal(url, URL_OK);
  assert.equal(headers['X-Routine-Secret'], 'top-secret-value');
  assert.equal(headers['X-Workrelay-Event'], 'workrelay.session.permission_asked');
  assert.equal(event.type, 'workrelay.session.permission_asked');
  assert.deepEqual(event.asks, [{ permission_id: 'per_1', child_session_id: C, action: 'shell', resource_preview: ['docker compose --env-file ../.env up -d'], resources_omitted: 0, directory: '/work/dd/app' }]);
  assert.equal(event.session_id, S); assert.equal(event.directory, '/work/dd'); assert.equal(event.decision, 'human_operator_only');
  assert.ok(!JSON.stringify(event).includes('top-secret-value') && !JSON.stringify(event).includes(URL_OK));
  // Same ask again: nothing. A second ask inside 2 minutes: sent anyway (asks are never rate limited).
  await h.notifier.tick(); assert.equal(h.sent.length, 1);
  h.view.pending.push({ permission_id: 'per_2', session_id: C, action: 'edit', resource_preview: ['x.py'], resources_omitted: 0, directory: '/work/dd' });
  h.advance(5000); await h.notifier.tick();
  assert.equal(h.sent.length, 2); assert.deepEqual(h.sent[1].event.asks.map(ask => ask.permission_id), ['per_2']);
});

test('completion fires once per run; a queued-but-not-started message never looks finished', async t => {
  const h = harness(t);
  h.notifier.set(S, { url: URL_OK });
  h.notifier.armed(S); // message queued; native still reports idle from before
  h.view.idle_at = h.now() - 1000;
  await h.notifier.tick(); assert.equal(h.sent.length, 0, 'not finished before it started');
  Object.assign(h.view, { aggregate_status: 'running', runtime_status: 'running', last_activity_at: 2 });
  h.advance(30000); await h.notifier.tick(); assert.equal(h.sent.length, 0, 'no per-step events');
  h.view.last_activity_at = 3; h.advance(30000); await h.notifier.tick(); assert.equal(h.sent.length, 0);
  Object.assign(h.view, { aggregate_status: 'succeeded', runtime_status: 'succeeded', idle_at: h.now() });
  h.advance(30000); await h.notifier.tick();
  assert.equal(h.sent.length, 1); assert.equal(h.sent[0].event.type, 'workrelay.session.finished'); assert.equal(h.sent[0].event.outcome, 'succeeded');
  await h.notifier.tick(); assert.equal(h.sent.length, 1, 'completion deduped');
  // Next run finished between two polls: detected via idle_at after arming.
  h.notifier.armed(S); h.advance(10000);
  Object.assign(h.view, { idle_at: h.now(), runtime_status: 'failed', aggregate_status: 'failed' });
  h.advance(20000); await h.notifier.tick();
  assert.equal(h.sent.length, 2); assert.equal(h.sent[1].event.type, 'workrelay.session.failed');
});

test('stall after N minutes, once per episode; non-ask events limited to one per 2 minutes and coalesced', async t => {
  const h = harness(t, { settings: { stall_minutes: 10 } });
  h.notifier.set(S, { url: URL_OK });
  Object.assign(h.view, { aggregate_status: 'running', runtime_status: 'running', last_activity_at: 5 });
  await h.notifier.tick();
  h.advance(9 * 60000); await h.notifier.tick(); assert.equal(h.sent.length, 0);
  h.advance(60000); await h.notifier.tick();
  assert.equal(h.sent.length, 1); assert.equal(h.sent[0].event.type, 'workrelay.session.stalled'); assert.equal(h.sent[0].event.idle_minutes, 10);
  h.advance(60000); await h.notifier.tick(); assert.equal(h.sent.length, 1, 'one stall per episode');
  // A child fails 1 minute after the stall event: deferred, then sent when the window opens.
  h.view.failed_children = [C]; h.view.last_activity_at = 6;
  h.advance(10000); await h.notifier.tick(); assert.equal(h.sent.length, 1, 'rate limited');
  h.advance(60000); await h.notifier.tick();
  assert.equal(h.sent.length, 2); assert.equal(h.sent[1].event.type, 'workrelay.session.child_failed'); assert.deepEqual(h.sent[1].event.child_session_ids, [C]);
  // Permission ask and completion bypass the limit even right after.
  h.view.pending = [{ permission_id: 'per_9', session_id: C, action: 'shell', resource_preview: [], resources_omitted: 0, directory: '/work/dd' }];
  h.view.aggregate_status = 'blocked_on_permission';
  h.advance(1000); await h.notifier.tick();
  Object.assign(h.view, { pending: [], aggregate_status: 'succeeded', runtime_status: 'succeeded' });
  h.advance(1000); await h.notifier.tick();
  assert.deepEqual(h.sent.slice(2).map(item => item.event.type), ['workrelay.session.permission_asked', 'workrelay.session.finished']);
  // Per-target stall_minutes override.
  h.notifier.set(S, { url: URL_OK, stall_minutes: 2 }); assert.equal(h.notifier.get(S).stall_minutes, 2);
});

test('delivery failures and watch failures never throw; retries are bounded', async t => {
  const h = harness(t, { fail: true });
  h.notifier.set(S, { url: URL_OK });
  h.view.pending = [{ permission_id: 'per_1', session_id: S, action: 'shell', resource_preview: [], resources_omitted: 0, directory: '/work/dd' }];
  h.view.aggregate_status = 'blocked_on_permission';
  for (let i = 0; i < 9; i++) { await h.notifier.tick(); h.advance(300000); }
  assert.equal(h.notifier.get(S).failed, 0, 'asks and completion keep retrying (10 attempts, ~25 min)');
  for (let i = 0; i < 3; i++) { await h.notifier.tick(); h.advance(300000); }
  const status = h.notifier.get(S);
  assert.equal(status.failed, 1); assert.equal(status.delivered, 0); assert.equal(status.last_delivery.ok, false); assert.equal(status.last_delivery.error, 'network_error');
  h.setWatchFails(true);
  for (let i = 0; i < 12; i++) await h.notifier.tick();
  assert.equal(h.notifier.get(S).enabled, true);
});

test('targets persist privately (0600) with dedupe state; clear and expiry remove them', async t => {
  const dir = await privateDir(t);
  const statePath = join(dir, 'session-notify.json');
  const h = harness(t, { statePath });
  h.notifier.set(S, { url: URL_OK, header_name: 'X-Routine-Secret', header_value: 'v' });
  assert.equal((await fs.stat(statePath)).mode & 0o777, 0o600);
  h.view.pending = [{ permission_id: 'per_1', session_id: S, action: 'shell', resource_preview: [], resources_omitted: 0, directory: '/work/dd' }];
  h.view.aggregate_status = 'blocked_on_permission';
  await h.notifier.tick(); assert.equal(h.sent.length, 1);
  const again = harness(t, { statePath });
  Object.assign(again.view, h.view);
  await again.notifier.tick();
  assert.equal(again.sent.length, 0, 'restart does not re-send an already notified ask');
  assert.equal(again.notifier.get(S).enabled, true);
  assert.deepEqual(again.notifier.clear(S), { session_id: S, enabled: false, cleared: true, opted_out: true });
  assert.equal(harness(t, { statePath }).notifier.get(S).enabled, false);
  const expiring = harness(t, { statePath, settings: { ttl_hours: 1 } });
  expiring.notifier.set(S, { url: URL_OK }); expiring.advance(3600001); await expiring.notifier.tick();
  assert.equal(expiring.notifier.get(S).enabled, false);
  // Non-private directory: state is not written, notifier still works in memory.
  const open = join(dir, 'open'); await fs.mkdir(open); await fs.chmod(open, 0o755);
  const loose = harness(t, { statePath: join(open, 'state.json') });
  assert.equal(loose.notifier.set(S, { url: URL_OK }).enabled, true);
  assert.deepEqual(await fs.readdir(open), []);
});

// Flexible multi-session harness for the review regressions.
function multi({ settings = {}, transportImpl } = {}) {
  let clock = 5_000_000;
  const views = {}, sent = [];
  const view = id => (views[id] ??= { session_id: id, title: 't', directory: '/work/dd', runtime_status: 'idle', aggregate_status: 'idle', root_active: false,
    tree_truncated: false, last_activity_at: 1, idle_at: null, running_children: 0, failed_children: [], task_outcome: 'no_task_intent', pending: [] });
  let onWatch;
  const notifier = createSessionNotifier({ settings, now: () => clock,
    watch: async id => { const v = structuredClone(view(id)); await onWatch?.(id); return v; },
    transport: transportImpl ?? (async (url, { body }) => { sent.push(JSON.parse(body)); return { status: 200 }; }) });
  return { notifier, view, sent, advance: ms => { clock += ms; }, now: () => clock, setOnWatch: fn => { onWatch = fn; } };
}
const ask = (id, session = C) => ({ permission_id: id, session_id: session, action: 'shell', resource_preview: ['x'], resources_omitted: 0, directory: '/work/dd' });

test('review: truncated tree still reports completion when the root and visible children are not running', async () => {
  const h = multi();
  h.notifier.set(S, { url: URL_OK });
  Object.assign(h.view(S), { aggregate_status: 'running', runtime_status: 'running', root_active: true });
  await h.notifier.tick();
  Object.assign(h.view(S), { aggregate_status: 'unknown', runtime_status: 'succeeded', root_active: false, tree_truncated: true, idle_at: h.now() });
  h.advance(30000); await h.notifier.tick();
  assert.equal(h.sent.length, 1); assert.equal(h.sent[0].type, 'workrelay.session.finished'); assert.equal(h.sent[0].tree_truncated, true);
});

test('review: a second run without re-arming (native UI, late queued message) is reported again', async () => {
  const h = multi();
  h.notifier.set(S, { url: URL_OK });
  for (const n of [1, 2]) {
    Object.assign(h.view(S), { aggregate_status: 'running', runtime_status: 'running', root_active: true, last_activity_at: n * 10 });
    h.advance(150000); await h.notifier.tick();
    Object.assign(h.view(S), { aggregate_status: 'succeeded', runtime_status: 'succeeded', root_active: false, idle_at: h.now() });
    h.advance(150000); await h.notifier.tick();
  }
  assert.deepEqual(h.sent.map(event => event.type), ['workrelay.session.finished', 'workrelay.session.finished']);
});

test('review: a run that ends before the tool returns is reported (armed with the pre-request time)', async () => {
  const h = multi();
  h.notifier.set(S, { url: URL_OK });
  const before = h.now(); h.advance(500);
  Object.assign(h.view(S), { runtime_status: 'failed', aggregate_status: 'failed', idle_at: h.now() }); // failed instantly
  h.advance(500); h.notifier.armed(S, before);
  await h.notifier.tick();
  assert.deepEqual(h.sent.map(event => event.type), ['workrelay.session.failed']);
  // Registering on an idle session that already finished earlier sends nothing.
  const g = multi();
  Object.assign(g.view(S), { runtime_status: 'succeeded', aggregate_status: 'succeeded', idle_at: g.now() - 60000 });
  g.notifier.set(S, { url: URL_OK }); await g.notifier.tick();
  assert.equal(g.sent.length, 0);
});

test('review: re-registering during a tick keeps dedupe state (no duplicate ask)', async () => {
  const h = multi();
  h.notifier.set(S, { url: URL_OK });
  Object.assign(h.view(S), { aggregate_status: 'blocked_on_permission', pending: [ask('per_1')] });
  h.setOnWatch(async () => { h.notifier.set(S, { url: URL_OK, header_name: 'X-Routine-Secret', header_value: 'v2' }); });
  await h.notifier.tick(); h.setOnWatch(undefined);
  await h.notifier.tick();
  assert.equal(h.sent.filter(event => event.type === 'workrelay.session.permission_asked').length, 1);
  assert.equal(h.notifier.get(S).secret_header, 'X-Routine-Secret');
});

test('review: a slow receiver does not hold back another session; at most 3 sends per target per tick', async () => {
  const S2 = 'ses_root000000000000000002';
  const order = []; let release;
  const gate = new Promise(resolve => { release = resolve; });
  const h = multi({ transportImpl: async (url, { body }) => {
    const event = JSON.parse(body); order.push('start:' + event.session_id);
    if (url.includes('slow')) await gate;
    order.push('end:' + event.session_id); return { status: 200 };
  } });
  h.notifier.set(S, { url: 'https://slow.example.com/h' }); h.notifier.set(S2, { url: URL_OK });
  for (const id of [S, S2]) Object.assign(h.view(id), { aggregate_status: 'blocked_on_permission', pending: [ask('per_' + id.slice(-1), id)] });
  const tick = h.notifier.tick();
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(order.includes('end:' + S2), 'fast receiver delivered while the slow one is pending');
  release(); await tick;
});

test('review: unobservable is flushed on the failure path; child failures merge; a deferred stall is dropped on progress', async () => {
  const h = multi({ settings: { stall_minutes: 1 } });
  h.notifier.set(S, { url: URL_OK });
  Object.assign(h.view(S), { aggregate_status: 'running', runtime_status: 'running', root_active: true, last_activity_at: 2 });
  await h.notifier.tick();
  h.advance(61000); await h.notifier.tick(); // stalled (opens the 2-minute window)
  h.view(S).failed_children = ['ses_c1']; h.advance(1000); await h.notifier.tick();
  h.view(S).failed_children = ['ses_c1', 'ses_c2']; h.advance(1000); await h.notifier.tick();
  h.advance(120000); await h.notifier.tick();
  const childEvents = h.sent.filter(event => event.type === 'workrelay.session.child_failed');
  assert.equal(childEvents.length, 1); assert.deepEqual(childEvents[0].child_session_ids, ['ses_c1', 'ses_c2']);
  // A stall deferred inside the window is dropped when progress resumes.
  const k = multi({ settings: { stall_minutes: 1 } });
  k.notifier.set(S, { url: URL_OK });
  Object.assign(k.view(S), { aggregate_status: 'running', runtime_status: 'running', root_active: true, last_activity_at: 2 });
  await k.notifier.tick();
  k.view(S).failed_children = ['ses_c9']; k.advance(30000); await k.notifier.tick(); // child_failed sent, window opens
  k.advance(31000); await k.notifier.tick(); // 61s without progress: stall deferred (window)
  k.view(S).last_activity_at = 3; k.advance(1000); await k.notifier.tick(); // progress: deferred stall dropped
  k.view(S).last_activity_at = 4; k.advance(58000); await k.notifier.tick();
  k.view(S).last_activity_at = 5; k.advance(40000); await k.notifier.tick(); // window open again; nothing pending
  assert.deepEqual(k.sent.map(event => event.type), ['workrelay.session.child_failed']);
  // Watch failures: the 10th failure's unobservable event is sent even though the watch keeps failing.
  const g = multi({ settings: { min_interval_ms: 30000 } });
  g.notifier.set(S, { url: URL_OK });
  g.setOnWatch(async () => { throw Error('down'); });
  for (let i = 0; i < 14; i++) { g.advance(30000); await g.notifier.tick(); }
  assert.deepEqual(g.sent.map(event => event.type), ['workrelay.session.unobservable']);
});
