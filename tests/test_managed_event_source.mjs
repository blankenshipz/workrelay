import test from 'node:test';
import assert from 'node:assert/strict';
import { createManagedEventSource } from '../src/workrelay/managed_event_source.mjs';
const server = 'srv_' + 'a'.repeat(64), session = 'ses_isolated_source';
const frame = value => `data: ${JSON.stringify(value)}\r\n\r\n`;
function response(text, chunkSize = 7) {
  const bytes = new TextEncoder().encode(text);
  return new Response(new ReadableStream({ start(controller) { for (let i = 0; i < bytes.length; i += chunkSize) controller.enqueue(bytes.slice(i, i + chunkSize)); controller.close(); } }), { headers: { 'content-type': 'text/event-stream' } });
}
test('bounded native frames wake only exact subscribed sessions and never forward payload/reasoning', async () => {
  let syncs = 0;
  const text = frame({ type: 'session.updated', properties: { info: { id: session }, text: 'PRIVATE', reasoning: 'HIDDEN' } }) + frame({ type: 'session.updated', properties: { info: { id: 'ses_unrelated' } } }) + frame({ type: 'message.part.delta', properties: { sessionID: session, text: 'TOKEN_NOISE' } }) + frame({ type: 'permission.asked', properties: { sessionID: session, patterns: ['PRIVATE'] } });
  const source = createManagedEventSource({ serverId: server, authorize: async () => true, openStream: async () => ({ server_id: server, response: response(text) }), isSubscribed: id => id === session,
    reconcile: async (...args) => { assert.equal(args.length, 0); syncs++; } });
  const result = await source.consume();
  assert.equal(result.native_events, 4); assert.equal(result.scoped_wakes, 2); assert.equal(result.reconciliations, 4); assert.equal(syncs, 4); assert.equal(result.replay, false);
  assert.ok(!JSON.stringify(result).includes('PRIVATE')); assert.ok(!JSON.stringify(result).includes('TOKEN_NOISE'));
});
test('binding, revoked authority, response type, malformed payload and backpressure fail closed', async () => {
  const config = { serverId: server, authorize: async () => true, reconcile: async () => {}, openStream: async () => ({ server_id: server, response: response('') }) };
  await assert.rejects(createManagedEventSource({ ...config, authorize: async () => false }).consume(), e => e.data.reason === 'source_authority_revoked');
  await assert.rejects(createManagedEventSource({ ...config, openStream: async () => ({ server_id: 'srv_' + 'b'.repeat(64), response: response('') }) }).consume(), e => e.data.reason === 'invalid_native_stream');
  await assert.rejects(createManagedEventSource({ ...config, openStream: async () => ({ server_id: server, response: new Response('{}') }) }).consume(), e => e.data.reason === 'invalid_native_stream');
  await assert.rejects(createManagedEventSource({ ...config, openStream: async () => ({ server_id: server, response: response('data: not json\n\n') }) }).consume(), e => e.data.reason === 'invalid_native_event');
  await assert.rejects(createManagedEventSource({ ...config, maxFrameBytes: 10, openStream: async () => ({ server_id: server, response: response(frame({ type: 'session.updated' })) }) }).consume(), e => e.data.reason === 'source_frame_too_large');
  await assert.rejects(createManagedEventSource({ ...config, maxFrames: 1, openStream: async () => ({ server_id: server, response: response(frame({}) + frame({})) }) }).consume(), e => e.data.reason === 'source_backpressure');
});
test('quiet stream stops within deadline and reconnect reconciles without claiming replay', async () => {
  let syncs = 0, cancels = 0, opens = 0;
  const source = createManagedEventSource({ serverId: server, authorize: async () => true, reconcile: async () => { syncs++; }, openStream: async ({ signal }) => {
    assert.equal(signal.aborted, false); opens++;
    return { server_id: server, response: new Response(new ReadableStream({ cancel() { cancels++; } }), { headers: { 'content-type': 'text/event-stream' } }) };
  } });
  assert.equal((await source.consume({ durationMs: 20 })).ended, 'bounded_stop');
  assert.equal((await source.consume({ durationMs: 20 })).replay, false);
  assert.equal(opens, 2); assert.equal(syncs, 4); assert.equal(cancels, 2);
});
test('authority revoked after source opens never reconciles native payload', async () => {
  let active = true, syncs = 0;
  const source = createManagedEventSource({ serverId: server, authorize: async () => active, reconcile: async () => { syncs++; active = false; }, isSubscribed: () => true,
    openStream: async () => ({ server_id: server, response: response(frame({ type: 'session.updated', properties: { sessionID: session } })) }) });
  await assert.rejects(source.consume(), e => e.data.reason === 'source_authority_revoked'); assert.equal(syncs, 1);
});

test('actual V2 type/data envelopes trigger subscribed reconciliation without forwarding data', async () => {
  let syncs = 0;
  const source = createManagedEventSource({ serverId: server, authorize: async () => true, reconcile: async () => { syncs++; }, isSubscribed: id => id === session,
    openStream: async () => ({ server_id: server, response: response(frame({ id: 'native1', type: 'session.updated', data: { sessionID: session, privateText: 'NEVER_FORWARD' } }) + frame({ id: 'native2', type: 'permission.created', data: { sessionID: session } }) + frame({ id: 'native3', type: 'session.updated', data: { id: session, outcome: 'succeeded' } })) }) });
  const result = await source.consume(); assert.equal(result.scoped_wakes, 3); assert.equal(syncs, 5); assert.ok(!JSON.stringify(result).includes('NEVER_FORWARD'));
});

test('current execution kinds carry only scoped native generation before reconciliation', async () => {
  const order = [], created = Date.now();
  const source = createManagedEventSource({ serverId: server, authorize: async () => true, reconcile: async () => { order.push('reconcile'); }, isSubscribed: id => id === session,
    onNativeEvent: async event => { assert.deepEqual(Object.keys(event).sort(), ['created', 'event_id', 'kind', 'server_id', 'session_id']); assert.equal(event.created, created); order.push(event.kind); },
    openStream: async () => ({ server_id: server, response: response(frame({ id: 'evt_begin', type: 'session.execution.started', created, data: { sessionID: session, rawPrompt: 'PRIVATE' } }) + frame({ id: 'evt_end', type: 'session.execution.succeeded', created, data: { sessionID: session } })) }) });
  const result = await source.consume(); assert.equal(result.scoped_wakes, 2); assert.equal(result.native_kinds['session.execution.succeeded'], 1);
  assert.deepEqual(order, ['reconcile', 'session.execution.started', 'reconcile', 'session.execution.succeeded', 'reconcile', 'reconcile']);
});

test('subscription readiness follows connection and initial reconciliation, never failed admission', async () => {
  const order = [];
  const config = { serverId: server, authorize: async () => true, reconcile: async () => { order.push('reconcile'); }, openStream: async () => { order.push('connected'); return { server_id: server, response: response('') }; } };
  await createManagedEventSource(config).consume({ onReady: async () => { order.push('ready'); } });
  assert.deepEqual(order, ['connected', 'reconcile', 'ready', 'reconcile']);
  let ready = false;
  await assert.rejects(createManagedEventSource({ ...config, authorize: async () => false }).consume({ onReady: () => { ready = true; } }));
  assert.equal(ready, false);
});
