import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { createEventsService } from '../src/workrelay/events.mjs';
const server = 'srv_' + 'a'.repeat(64), session = 'ses_ready_fixture';
const secret = 'whsec_' + Buffer.alloc(32, 8).toString('base64');
const params = (extra = {}) => ({ name: 'session.needs_input', arguments: { server_id: server }, delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret }, ...extra });
const page = (items = [], next_cursor = null) => ({ server_id: server, items, next_cursor });
const item = { session_id: session, state: 'needs_input', decisions: ['per_ready_fixture'] };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
async function fixture(observe) {
  const dir = await fs.mkdtemp('/private/tmp/opencode/managed-ready-test-'); await fs.chmod(dir, 0o700);
  const path = dir + '/events.json'; let authorized = true, delivered = 0;
  const events = createEventsService({ statePath: path, principal: 'ready-owner', authorize: async () => authorized,
    observeManaged: observe, transport: async (_url, request) => { const value = JSON.parse(request.body); if (!value.type) delivered++; return { status: 200, body: JSON.stringify({ challenge: value.challenge }) }; } });
  return { events, read: async () => JSON.parse(await fs.readFile(path, 'utf8')), revoke: () => { authorized = false; }, deliveries: () => delivered };
}
const options = attemptId => ({ attemptId, ready: async () => {}, timeoutMs: 4000 });

test('MGR-EVT-READY-01 empty fresh scan succeeds only after unlocked connection readiness', async () => {
  const readyGate = deferred(), entered = deferred(); let scans = 0;
  const f = await fixture(async (_filter, cursor) => { assert.equal(cursor, null); scans++; return page(); });
  let acknowledged = false;
  const operation = f.events.subscribeManagedReady(params(), { ...options('empty'), ready: async ({ subscription_id, attempt_id, signal }) => {
    assert.match(subscription_id, /^sub_/); assert.equal(attempt_id, 'empty'); assert.equal(signal.aborted, false);
    await f.events.pollManaged(); await f.events.deliverDue(); entered.resolve(); await readyGate.promise;
  } }).then(value => { acknowledged = true; return value; });
  await entered.promise; assert.equal(acknowledged, false); assert.equal(scans, 0); assert.equal(f.deliveries(), 0);
  readyGate.resolve(); const result = await operation;
  assert.deepEqual(result.observation, { attempt_id: 'empty', subscription_id: result.result.id, complete: true, pages: 1, items: 0 });
});

test('MGR-EVT-READY-01 observation throw removes only staged new subscription and never leaks outbox', async () => {
  const f = await fixture(async () => { throw Error('fixture observation failed'); });
  const existing = await f.events.subscribe(params({ name: 'session.completed' }));
  const before = (await f.read()).subscriptions[existing.id];
  await assert.rejects(f.events.subscribeManagedReady(params(), options('throw')));
  const state = await f.read(); assert.deepEqual(Object.keys(state.subscriptions), [existing.id]); assert.deepEqual(state.subscriptions[existing.id], before); assert.deepEqual(state.queue, []);
});

test('MGR-EVT-READY-01 stale renewal observations cannot prove readiness or mutate expiry/secret', async () => {
  let fail = false, reads = 0;
  const f = await fixture(async () => { reads++; if (fail) throw Error('fresh read failed'); return page([item]); });
  const old = await f.events.subscribe(params()); await f.events.pollManaged();
  const before = await f.read(); fail = true;
  await assert.rejects(f.events.subscribeManagedReady(params({ ttlMs: 100, delivery: { ...params().delivery, secret: 'whsec_' + Buffer.alloc(32, 7).toString('base64') } }), options('renew-failure')));
  assert.ok(reads >= 2); assert.deepEqual(await f.read(), before); assert.ok(before.subscriptions[old.id].observations[session]);
});

test('MGR-EVT-READY-01 partial pagination cannot commit observations or queue', async () => {
  const cursors = []; const f = await fixture(async (_filter, cursor) => { cursors.push(cursor); if (cursor === null) return page([item], 'page2'); throw Error('second page failed'); });
  await assert.rejects(f.events.subscribeManagedReady(params(), options('partial')));
  assert.deepEqual(cursors, [null, 'page2']); const state = await f.read(); assert.deepEqual(state.subscriptions, {}); assert.deepEqual(state.queue, []);
});

test('MGR-EVT-READY-01 complete pagination commits once; duplicate attempt is idempotent', async () => {
  const cursors = []; const f = await fixture(async (_filter, cursor) => { cursors.push(cursor); return cursor === null ? page([item], 'next') : page(); });
  const a = await f.events.subscribeManagedReady(params(), options('complete'));
  const b = await f.events.subscribeManagedReady(params(), options('complete'));
  assert.deepEqual(a, b); assert.deepEqual(cursors, [null, 'next']); assert.equal(a.observation.pages, 2); assert.equal(a.observation.items, 1);
  assert.equal((await f.read()).queue.length, 1); await f.events.deliverDue(); assert.equal(f.deliveries(), 1);
  await assert.rejects(f.events.subscribeManagedReady(params({ ttlMs: 500 }), options('complete')), error => error.data.reason === 'readiness_attempt_conflict');
});

test('MGR-EVT-READY-01 timeout cannot late-commit and revocation between pages rejects', async () => {
  const late = deferred(); const f = await fixture(async () => late.promise);
  await assert.rejects(f.events.subscribeManagedReady(params(), { ...options('timeout'), timeoutMs: 350 }));
  late.resolve(page([item])); await new Promise(r => setTimeout(r, 50)); assert.deepEqual((await f.read()).subscriptions, {}); assert.deepEqual((await f.read()).queue, []);
  const g = await fixture(async () => { g.revoke(); return page([item], 'next'); });
  await assert.rejects(g.events.subscribeManagedReady(params(), options('revoke'))); assert.deepEqual((await g.read()).subscriptions, {});
});

test('MGR-EVT-READY-01 concurrent duplicates serialize while preserving unrelated subscription', async () => {
  const gate = deferred(), entered = deferred(); let reads = 0;
  const f = await fixture(async () => { reads++; return page([item]); });
  const first = f.events.subscribeManagedReady(params(), { ...options('concurrent'), ready: async () => { entered.resolve(); await gate.promise; } });
  await entered.promise;
  const second = f.events.subscribeManagedReady(params(), options('concurrent'));
  const other = await f.events.subscribe(params({ name: 'session.completed' }));
  await f.events.deliverDue(); assert.equal(f.deliveries(), 0); gate.resolve();
  const [a, b] = await Promise.all([first, second]); assert.deepEqual(a, b); assert.equal(reads, 1);
  assert.ok((await f.read()).subscriptions[other.id]); assert.equal((await f.read()).queue.length, 1);
});

test('MGR-EVT-READY-01 failed connection readiness and cyclic pagination never commit', async () => {
  let scans = 0;
  const f = await fixture(async () => { scans++; return page(); });
  await assert.rejects(f.events.subscribeManagedReady(params(), { ...options('no-source'), ready: async () => { throw Error('no connection'); } }));
  assert.equal(scans, 0); assert.deepEqual((await f.read()).subscriptions, {});
  const g = await fixture(async (_filter, cursor) => page([], cursor === 'a' ? 'b' : 'a'));
  await assert.rejects(g.events.subscribeManagedReady(params(), options('cycle')));
  assert.deepEqual((await g.read()).subscriptions, {});
});

test('MGR-EVT-READY-01 successful renewal must scan afresh from NULL, not old cursor/observation', async () => {
  const cursors = []; let phase = 0;
  const f = await fixture(async (_filter, cursor) => { cursors.push(cursor); return phase === 0 ? page([item], 'old-cursor') : page(); });
  await f.events.subscribe(params()); await f.events.pollManaged(); phase = 1;
  const renewed = await f.events.subscribeManagedReady(params({ ttlMs: 60000 }), options('fresh-renewal'));
  assert.deepEqual(cursors, [null, null]); assert.equal(renewed.observation.items, 0); assert.equal(renewed.observation.complete, true);
  assert.equal((await f.read()).subscriptions[renewed.result.id].scanCursor, null);
});
