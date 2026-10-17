import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';
import { createEventsService } from '../src/workrelay/events.mjs';
import { createManagedEventTools, managedEventToolDefinitions } from '../src/workrelay/managed_event_tools.mjs';

const server = 'srv_' + 'a'.repeat(64), session = 'ses_event_tools';
const identity = { issuer: 'https://issuer.test', audience: 'https://workrelay.test/mcp', principal: 'alice', client_id: 'https://chatgpt.com/oauth/client.json' };
const claims = { iss: identity.issuer, aud: identity.audience, sub: identity.principal, client_id: identity.client_id };
const secret = 'whsec_' + Buffer.alloc(32, 27).toString('base64');
const subscription = (name = 'session.progress', sid = session) => ({ name, arguments: { server_id: server, ...(sid ? { session_id: sid } : {}) }, delivery: { mode: 'webhook', url: 'https://receiver.example/callback?token=SYNTHETIC_PRIVATE_TOKEN', secret } });
async function fixture(t) {
  const dir = await fs.mkdtemp('/private/tmp/opencode/workrelay-event-tools-'); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  let active = true, time = Date.now(), phase = 'running', response = 200; const calls = [];
  const config = { statePath: join(dir, 'events.json'), principal: 'alice', now: () => time,
    authorize: async (principal, _task, _name, filter) => active && principal === 'alice' && filter?.server_id === server,
    observeManaged: async filter => ({ server_id: server, items: [{ session_id: filter.session_id ?? session, state: phase, decisions: [], text: 'RAW_SECRET', reasoning: 'HIDDEN_REASONING', metadata: { token: 'RAW_SECRET' } }], next_cursor: null }),
    transport: async (_url, request) => {
      const h = request.headers, body = JSON.parse(request.body); calls.push({ body, headers: h });
      assert.equal(h['webhook-signature'], 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64')).update(`${h['webhook-id']}.${h['webhook-timestamp']}.${request.body}`).digest('base64'));
      return { status: body.type ? 200 : response, body: JSON.stringify({ challenge: body.challenge }) };
    } };
  const events = createEventsService(config);
  const makeTools = (service = events) => createManagedEventTools({ events: service, serverId: server, identity, authorize: async (_claims, filter) => active && filter.server_id === server });
  return { events, config, tools: makeTools(), makeTools, calls, revoke: () => { active = false; }, phase: value => { phase = value; }, response: value => { response = value; }, advance: ms => { time += ms; } };
}
function validate(schema, value) {
  if (schema.anyOf) return assert.ok(schema.anyOf.some(choice => { try { validate(choice, value); return true; } catch { return false; } }));
  if (Object.hasOwn(schema, 'const')) assert.deepEqual(value, schema.const);
  if (schema.enum) assert.ok(schema.enum.includes(value));
  const type = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
  if (schema.type) assert.ok((Array.isArray(schema.type) ? schema.type : [schema.type]).includes(type));
  if (schema.pattern) assert.match(value, new RegExp(schema.pattern));
  if (schema.type === 'object') {
    for (const key of schema.required ?? []) assert.ok(Object.hasOwn(value, key), key);
    for (const [key, data] of Object.entries(value)) { if (schema.additionalProperties === false) assert.ok(Object.hasOwn(schema.properties, key), key); if (schema.properties?.[key]) validate(schema.properties[key], data); }
  }
  if (schema.type === 'array') for (const item of value) validate(schema.items, item);
}
async function call(tools, name, input = {}, caller = claims) {
  const output = await tools.call(name, input, caller); validate(managedEventToolDefinitions.find(d => d.name === name).outputSchema, output);
  const safe = JSON.stringify(output); for (const privateValue of [secret, 'SYNTHETIC_PRIVATE_TOKEN', 'RAW_SECRET', 'HIDDEN_REASONING']) assert.equal(safe.includes(privateValue), false);
  return output;
}

test('all exported lifecycle descriptors are callable, schema-matching and use the same native subscription store', async t => {
  const f = await fixture(t);
  assert.equal(managedEventToolDefinitions.length, 4);
  const capabilities = await call(f.tools, 'workrelay_event_capabilities'); assert.equal(capabilities.server_id, server); assert.equal(capabilities.replay, false);
  assert.ok(capabilities.events.some(e => e.name === 'session.progress'));
  const optedIn = await f.events.subscribe(subscription());
  const list = await call(f.tools, 'workrelay_event_subscriptions'); assert.equal(list.subscriptions[0].id, optedIn.id); assert.equal(list.subscriptions[0].delivery_state, 'idle');
  assert.equal((await call(f.tools, 'workrelay_event_subscription_status', { subscription_id: optedIn.id })).status, 'available');
  await call(f.tools, 'workrelay_event_unsubscribe', { subscription_id: optedIn.id });
  await call(f.tools, 'workrelay_event_unsubscribe', { subscription_id: optedIn.id });
  assert.equal((await call(f.tools, 'workrelay_event_subscription_status', { subscription_id: optedIn.id })).status, 'not_found_or_unavailable');
  assert.equal((await call(f.tools, 'workrelay_event_subscriptions')).subscriptions.length, 0);
});

test('verified identity, server binding, session filtering, pagination and foreign IDs fail closed', async t => {
  const f = await fixture(t), a = await f.events.subscribe(subscription()), b = await f.events.subscribe(subscription('session.failed', 'ses_other')), broad = await f.events.subscribe(subscription('session.completed', null));
  for (const caller of [undefined, { ...claims, sub: 'bob' }, { ...claims, client_id: 'caller-owner-label' }, { ...claims, aud: 'https://other.test/mcp' }, { ...claims, iss: 'https://other-issuer.test' }]) await assert.rejects(f.tools.call('workrelay_event_subscriptions', {}, caller));
  await assert.rejects(f.tools.call('workrelay_event_subscriptions', { server_id: 'srv_' + 'b'.repeat(64) }, claims));
  await assert.rejects(f.tools.call('workrelay_event_unsubscribe', { subscription_id: a.id, owner: 'alice' }, claims));
  await assert.rejects(f.tools.call('workrelay_event_subscriptions', { limit: 51 }, claims));
  await assert.rejects(f.tools.call('workrelay_event_subscriptions', { cursor: 'arbitrary' }, claims));
  const first = await call(f.tools, 'workrelay_event_subscriptions', { limit: 1 }), second = await call(f.tools, 'workrelay_event_subscriptions', { limit: 1, cursor: first.next_cursor });
  assert.notEqual(first.subscriptions[0].id, second.subscriptions[0].id);
  const exact = await call(f.tools, 'workrelay_event_subscriptions', { session_id: session }); assert.deepEqual(exact.subscriptions.map(s => s.id), [a.id]);
  assert.equal((await call(f.tools, 'workrelay_event_subscription_status', { subscription_id: b.id, session_id: session })).subscription, null);
  await call(f.tools, 'workrelay_event_unsubscribe', { subscription_id: b.id, session_id: session }); assert.ok((await f.events.subscriptionStatus({ id: b.id, filter: { server_id: server } })).subscription);
  const foreign = createEventsService({ ...f.config, principal: 'bob', authorize: async () => true });
  assert.equal((await foreign.subscriptions({ filter: { server_id: server } })).subscriptions.length, 0);
  await foreign.unsubscribeById({ id: broad.id, filter: { server_id: server } }); assert.ok((await f.events.subscriptionStatus({ id: broad.id, filter: { server_id: server } })).subscription);
  assert.throws(() => f.makeTools(foreign));
});

test('meaningful runtime transitions, retry metadata, stable IDs and status survive refresh/restart', async t => {
  const f = await fixture(t), accepted = await f.events.subscribe(subscription());
  f.response(503); await f.events.pollManaged(); await f.events.deliverDue();
  let status = (await call(f.tools, 'workrelay_event_subscription_status', { subscription_id: accepted.id })).subscription;
  assert.equal(status.delivery_state, 'retrying'); assert.equal(status.last_http_status, 503); assert.equal(status.queued, 1); assert.equal(status.delivered, 0);
  const restarted = createEventsService(f.config), tools = f.makeTools(restarted); await restarted.subscribe(subscription());
  f.advance(1001); f.response(202); await restarted.pollManaged(); await restarted.deliverDue();
  const delivered = f.calls.filter(c => c.body.eventId); assert.equal(delivered.length, 2); assert.equal(delivered[0].body.eventId, delivered[1].body.eventId); assert.notEqual(delivered[0].headers['webhook-timestamp'], delivered[1].headers['webhook-timestamp']);
  status = (await call(tools, 'workrelay_event_subscription_status', { subscription_id: accepted.id })).subscription; assert.equal(status.delivery_state, 'idle'); assert.equal(status.delivered, 1); assert.ok(status.last_ack_at);
  await restarted.pollManaged(); await restarted.deliverDue(); assert.equal(f.calls.filter(c => c.body.eventId).length, 2);
  f.phase('idle'); await restarted.pollManaged(); await restarted.deliverDue();
  const progress = f.calls.filter(c => c.body.eventId).at(-1).body; assert.equal(progress.name, 'session.progress'); assert.equal(progress.data.state, 'idle'); assert.match(progress.data.summary, /not task completion/);
  assert.ok(!f.calls.some(c => c.body.name === 'session.completed'));
});

test('revocation races with views/delivery fail closed and subscription stop never stops ordinary work', async t => {
  const f = await fixture(t), accepted = await f.events.subscribe(subscription()); await f.events.pollManaged();
  const raced = f.makeTools({ ...f.events, subscriptions: async input => { const result = await f.events.subscriptions(input); f.revoke(); return result; } });
  await assert.rejects(raced.call('workrelay_event_subscriptions', {}, claims)); await f.events.deliverDue(); assert.equal(f.calls.filter(c => c.body.eventId).length, 0);
  await assert.rejects(f.tools.call('workrelay_event_capabilities', {}, claims));
  const g = await fixture(t), other = await g.events.subscribe(subscription('session.failed', 'ses_other')), wanted = await g.events.subscribe(subscription());
  await call(g.tools, 'workrelay_event_unsubscribe', { subscription_id: wanted.id });
  assert.ok((await call(g.tools, 'workrelay_event_subscription_status', { subscription_id: other.id })).subscription); await g.events.pollManaged(); g.phase('failed'); await g.events.pollManaged(); await g.events.deliverDue();
  assert.equal(g.calls.filter(c => c.body.name === 'session.failed').length, 1);
  const status = await f.events.subscriptionStatus({ id: accepted.id, filter: { server_id: server } }); assert.equal(status.subscription, null);
});
