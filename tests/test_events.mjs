import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { spawn, execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { createEventsService, createPinnedWebhookTransport, isPublicAddress } from '../src/workrelay/events.mjs';

const secret = 'whsec_' + Buffer.alloc(32, 17).toString('base64');
const replacement = 'whsec_' + Buffer.alloc(32, 18).toString('base64');
const subscribe = (task = 'task-1', name = 'task.decision', signingSecret = secret) => ({ name, arguments: { task_id: task }, delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret: signingSecret } });
async function fixture(t, overrides = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-events-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  let time = Date.parse('2026-10-14T00:00:00Z');
  let access = true;
  const sent = [];
  const config = { statePath: join(dir, 'state.json'), principal: 'authenticated-A', now: () => time, authorize: async (owner, task) => access && owner === 'authenticated-A' && task === 'task-1',
    transport: async (url, options) => { sent.push({ url, ...options }); const body = JSON.parse(options.body); return { status: 200, body: JSON.stringify({ challenge: body.challenge }) }; }, ...overrides };
  return { config, service: createEventsService(config), sent, advance: ms => { time += ms; }, deny: () => { access = false; } };
}
function event(eventId = 'evt_1', name = 'task.decision') { return { eventId, name, task_id: 'task-1', summary: 'Awaiting a decision' }; }
function expectSignature(call, signingSecret = secret) {
  const h = call.headers;
  const signature = 'v1,' + createHmac('sha256', Buffer.from(signingSecret.slice(6), 'base64')).update(`${h['webhook-id']}.${h['webhook-timestamp']}.${call.body}`).digest('base64');
  assert.ok(h['webhook-signature'].split(' ').includes(signature));
}

test('catalog, authenticated authorization, validation, no secret in results/errors', async t => {
  const f = await fixture(t);
  assert.deepEqual((await f.service.list()).events.map(x => x.name), ['task.decision', 'task.completed']);
  assert.throws(() => createEventsService({ ...f.config, principal: '' }), /rejected/);
  for (const params of [subscribe('foreign-task'), { ...subscribe(), name: 'unknown' }, { ...subscribe(), arguments: { task_id: 'task-1', owner: 'A' } }, { ...subscribe(), cursor: 'old' }, subscribe('task-1', 'task.decision', 'whsec_bad')]) {
    await assert.rejects(f.service.subscribe(params), e => !e.message.includes(secret));
  }
  assert.equal(f.sent.length, 0);
  const result = await f.service.subscribe(subscribe());
  assert.equal(result.cursor, null);
  assert.equal(result.truncated, false);
  assert.ok(!JSON.stringify(result).includes(secret));
  const call = f.sent[0];
  assert.equal(JSON.parse(call.body).type, 'verification');
  expectSignature(call);
  assert.equal(call.headers['X-MCP-Subscription-Id'], result.id);
  assert.equal((await fs.stat(f.config.statePath)).mode & 0o077, 0);
});

test('callback challenge failure never persists an active subscription', async t => {
  const f = await fixture(t, { transport: async () => ({ status: 200, body: '{"challenge":"wrong"}' }) });
  await assert.rejects(f.service.subscribe(subscribe()), e => e.code === -32015 && e.data.reason === 'challenge_failed');
  assert.deepEqual(await f.service.publish(event()), { eventId: 'evt_1', queued: 0 });
});

test('idempotency, cache, refresh, finite null TTL and key rotation across restart', async t => {
  const f = await fixture(t);
  const first = await f.service.subscribe({ ...subscribe(), ttlMs: 1000 });
  f.advance(100);
  const refreshed = await f.service.subscribe({ ...subscribe(), ttlMs: null });
  assert.equal(refreshed.id, first.id);
  assert.ok(Date.parse(refreshed.refreshBefore) > Date.parse(first.refreshBefore));
  assert.equal(f.sent.length, 1);
  const restarted = createEventsService(f.config);
  await restarted.subscribe(subscribe('task-1', 'task.decision', replacement));
  assert.equal(f.sent.length, 2);
  expectSignature(f.sent[1], replacement);
  expectSignature(f.sent[1], secret);
  await restarted.subscribe(subscribe('task-1', 'task.decision', replacement));
  await restarted.publish(event());
  await restarted.deliverDue();
  expectSignature(f.sent.at(-1), replacement);
  expectSignature(f.sent.at(-1), secret);
  f.advance(300001);
  await restarted.publish(event('evt_2'));
  await restarted.deliverDue();
  assert.equal(f.sent.at(-1).headers['webhook-signature'].split(' ').length, 1);
  await restarted.subscribe(subscribe('task-1', 'task.decision', replacement));
  assert.equal(JSON.parse(f.sent.at(-1).body).type, 'verification');
});

test('persisted retry preserves exact event body and ID with new signing timestamp', async t => {
  const f = await fixture(t);
  await f.service.subscribe(subscribe());
  let attempts = 0;
  const retryConfig = { ...f.config, transport: async (url, opts) => { f.sent.push({ url, ...opts }); return { status: ++attempts === 1 ? 503 : 202, body: '' }; } };
  const service = createEventsService(retryConfig);
  assert.equal((await service.publish(event())).queued, 1);
  assert.equal((await service.publish(event())).queued, 0);
  assert.equal((await service.deliverDue()).retried, 1);
  assert.equal((await service.deliverDue()).delivered, 0);
  f.advance(1001);
  assert.equal((await createEventsService(retryConfig).deliverDue()).delivered, 1);
  const [a, b] = f.sent.slice(-2);
  assert.equal(a.body, b.body);
  assert.equal(a.headers['webhook-id'], b.headers['webhook-id']);
  assert.notEqual(a.headers['webhook-timestamp'], b.headers['webhook-timestamp']);
  expectSignature(a); expectSignature(b);
  assert.equal(JSON.parse(b.body).data.task_id, 'task-1');
});

test('per-task/event/principal isolation, unsubscribe, explicit revoke, and expiry', async t => {
  const f = await fixture(t);
  await f.service.subscribe(subscribe());
  assert.equal((await f.service.publish(event('completion', 'task.completed'))).queued, 0);
  await assert.rejects(f.service.publish({ ...event(), task_id: 'other' }));
  const other = createEventsService({ ...f.config, principal: 'authenticated-B', authorize: async () => true });
  await other.unsubscribe(subscribe()); // identical arguments cannot remove A's subscription
  assert.equal((await f.service.publish(event())).queued, 1);
  assert.equal((await other.deliverDue()).delivered, 0);
  await f.service.unsubscribe(subscribe());
  await f.service.unsubscribe(subscribe());
  assert.equal((await f.service.deliverDue()).delivered, 0);
  await f.service.subscribe(subscribe());
  await f.service.publish(event('evt_2'));
  f.deny();
  assert.equal((await f.service.deliverDue()).delivered, 0);
  const g = await fixture(t);
  await g.service.subscribe({ ...subscribe(), ttlMs: 1 });
  await g.service.publish(event());
  g.advance(2);
  assert.equal((await g.service.deliverDue()).delivered, 0);
  await g.service.subscribe(subscribe());
  await g.service.publish(event('evt_2'));
  await g.service.revoke('task-1');
  assert.equal((await g.service.deliverDue()).delivered, 0);
});

test('410/413/permanent 4xx stop retries; transient failures exhaust bounded attempts', async t => {
  for (const status of [410, 413, 400, 503, 429]) {
    const f = await fixture(t);
    await f.service.subscribe(subscribe());
    let calls = 0;
    const service = createEventsService({ ...f.config, maxAttempts: 2, transport: async () => { calls++; return { status }; } });
    await service.publish(event());
    await service.deliverDue(); f.advance(1001); await service.deliverDue(); f.advance(10000); await service.deliverDue();
    assert.equal(calls, [503, 429].includes(status) ? 2 : 1);
    if (status === 410) assert.equal((await service.publish(event('evt_2'))).queued, 0);
  }
});

test('concurrent same-process services serialize subscription and queue writes', async t => {
  const f = await fixture(t);
  const services = Array.from({ length: 8 }, () => createEventsService(f.config));
  const subscriptions = await Promise.all(services.map(s => s.subscribe(subscribe())));
  assert.equal(new Set(subscriptions.map(x => x.id)).size, 1);
  assert.equal(f.sent.length, 1);
  await Promise.all(services.map((s, i) => s.publish(event(`evt_${i}`))));
  assert.equal((await f.service.deliverDue()).delivered, 8);
});

test('dispatch batches are bounded and revocation is rechecked before each send', async t => {
  const f = await fixture(t, { batchSize: 1 });
  await f.service.subscribe(subscribe());
  await f.service.publish(event('evt_1')); await f.service.publish(event('evt_2'));
  assert.equal((await f.service.deliverDue()).delivered, 1);
  assert.equal((await f.service.deliverDue()).delivered, 1);
  await f.service.publish(event('evt_3')); await f.service.publish(event('evt_4'));
  const service = createEventsService({ ...f.config, batchSize: 16, transport: async () => { f.deny(); return { status: 200 }; } });
  assert.equal((await service.deliverDue()).delivered, 1);
  assert.equal((await service.deliverDue()).delivered, 0);
});

test('public address policy rejects private, reserved, mapped, transition and documentation ranges', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.1.1', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::1', '::ffff:8.8.8.8', 'fc00::1', 'fe80::1', '2001:db8::1', '2002:0808:0808::1', '3fff::1', 'invalid']) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isPublicAddress(ip), true, ip);
});

// No sockets or real DNS: exercise production validation/pinning around fake native primitives.
function fakeRequest({ status = 200, body = '{}', onConnect = () => {} } = {}) {
  return (url, options, respond) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => {
      onConnect(url, options);
      const res = new EventEmitter(); res.statusCode = status; res.destroy = () => {};
      respond(res); res.emit('data', Buffer.from(body)); res.emit('end');
    });
    return req;
  };
}
const wire = { body: '{}', headers: {} };
test('HTTPS callback validation, every DNS answer validated, and pinned connection hostname/TLS', async () => {
  let calls = 0;
  const transport = createPinnedWebhookTransport({ resolve: async () => [{ address: '8.8.8.8', family: 4 }], request: fakeRequest({ onConnect: (url, options) => {
    calls++; assert.equal(url.hostname, 'receiver.example'); assert.equal(options.servername, 'receiver.example'); assert.equal(options.agent, false); assert.equal(options.rejectUnauthorized, true); assert.equal(options.minVersion, 'TLSv1.2');
    options.lookup(url.hostname, {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, '8.8.8.8'); assert.equal(family, 4); });
  } }) });
  for (const url of ['http://receiver.example/', 'https://user:pass@receiver.example/', 'https://receiver.example:8443/', 'https://127.0.0.1/', 'https://[::1]/', 'https://receiver.example/#x']) await assert.rejects(transport(url, wire));
  assert.equal((await transport('https://receiver.example/', wire)).status, 200);
  assert.equal(calls, 1);
  const mixed = createPinnedWebhookTransport({ resolve: async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }], request: () => assert.fail('private DNS must not connect') });
  await assert.rejects(mixed('https://receiver.example/', wire), e => e.data.reason === 'non_public_address');
});

test('DNS rebinding revalidated on each attempt; redirects/oversized response/timeout fail closed', async () => {
  let resolves = 0, calls = 0;
  const rebound = createPinnedWebhookTransport({ resolve: async () => [{ address: ++resolves === 1 ? '8.8.8.8' : '127.0.0.1', family: 4 }], request: fakeRequest({ onConnect: () => { calls++; } }) });
  await rebound('https://receiver.example/', wire);
  await assert.rejects(rebound('https://receiver.example/', wire));
  assert.equal(calls, 1);
  for (const opts of [{ status: 302 }, { body: 'x'.repeat(8193) }]) {
    const transport = createPinnedWebhookTransport({ resolve: async () => [{ address: '8.8.8.8', family: 4 }], request: fakeRequest(opts) });
    await assert.rejects(transport('https://receiver.example/', wire));
  }
  await assert.rejects(rebound('https://receiver.example/', { ...wire, body: 'x'.repeat(262145) }), e => e.data.reason === 'payload_too_large');
  let finishDNS;
  const slow = createPinnedWebhookTransport({ timeoutMs: 5, resolve: () => new Promise(resolve => { finishDNS = resolve; }), request: () => assert.fail('late DNS must not connect') });
  await assert.rejects(slow('https://receiver.example/', wire), e => e.data.reason === 'timeout');
  finishDNS([{ address: '8.8.8.8', family: 4 }]);
  await new Promise(resolve => setImmediate(resolve));
});

test('invalid event payload and nonprivate or symlinked state fail closed', async t => {
  const f = await fixture(t);
  await assert.rejects(f.service.publish({ ...event(), summary: 'x'.repeat(2001) }));
  await assert.rejects(f.service.publish({ ...event(), timestamp: 'not-date' }));
  await f.service.subscribe(subscribe());
  await fs.chmod(f.config.statePath, 0o644);
  await assert.rejects(f.service.deliverDue());
  await fs.chmod(f.config.statePath, 0o600);
  const link = f.config.statePath + '.link';
  await fs.symlink(f.config.statePath, link);
  await assert.rejects(createEventsService({ ...f.config, statePath: link }).deliverDue());
});

// Real separate Node processes share the production on-disk store/OS lock. The parent
// is an isolated fake callback protocol endpoint over IPC, not a live HTTPS/Dot receiver.
const childProgram = `
import {createEventsService,createPinnedWebhookTransport} from ${JSON.stringify(new URL('../src/workrelay/events.mjs', import.meta.url).href)};
import {EventEmitter} from 'node:events';
const options=JSON.parse(process.argv[2]); let next=0; const callbacks=new Map();
process.on('message', msg=>{ if(msg.reply){ callbacks.get(msg.reply)?.(msg.response); callbacks.delete(msg.reply); } });
let transport=(url,request)=>new Promise(resolve=>{const id=String(++next);callbacks.set(id,resolve);process.send({call:id,url,...request});});
if(options.pinned) transport=createPinnedWebhookTransport({timeoutMs:options.attemptTimeoutMs,resolve:async()=>[{address:'8.8.8.8',family:4}],request:(url,request,respond)=>{
 const req=new EventEmitter(),id=String(++next);let destroyed=false;
 req.destroy=()=>{destroyed=true;callbacks.delete(id);req.emit('error',new Error('aborted'));};
 req.end=body=>{callbacks.set(id,response=>{if(destroyed)return;const res=new EventEmitter();res.statusCode=response.status;res.destroy=()=>{};respond(res);res.emit('data',Buffer.from(response.body||''));res.emit('end');});process.send({call:id,url:String(url),headers:request.headers,body});};return req;
 }});
const service=createEventsService({statePath:process.argv[1],principal:'authenticated-A',authorize:async()=>options.allow!==false,lockTimeoutMs:options.lockTimeoutMs||30000,transport});
process.send({ready:true});
process.once('message',async()=>{try{
 if(options.op==='write'){
  await service.subscribe(${JSON.stringify(subscribe())});
  for(const id of options.events) await service.publish({name:'task.decision',task_id:'task-1',summary:'Synthetic task data',eventId:id});
 }
 if(options.op==='revoke') await service.revoke();
 else await service.deliverDue();
 process.send({done:true}); process.exit(0);
}catch(error){process.send({error:{code:error.code,reason:error.data?.reason,retryable:error.data?.retryable}});process.exit(1);}});
`;
function processClient(t, statePath, options, callback) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', childProgram, statePath, JSON.stringify(options)], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let stdout = '', stderr = '', result;
  child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
  const ready = new Promise((resolve, reject) => { child.on('message', msg => { if (msg.ready) resolve(); }); child.once('exit', () => reject(new Error('Test subprocess exited before ready: ' + stderr))); });
  child.on('message', async msg => {
    if (msg.call) { const response = await callback(msg, child); if (response && child.connected) child.send({ reply: msg.call, response }); }
    else if (msg.error) result = msg.error;
  });
  const done = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal, stdout, stderr, result })));
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return { child, ready, done, start: () => child.send({ start: true }) };
}
function fakeEndpoint(calls, delayMs = 0) {
  return async msg => {
    expectSignature(msg);
    const body = JSON.parse(msg.body); calls.push(msg);
    if (delayMs) await new Promise(resolve => setTimeout(resolve, delayMs));
    return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
  };
}
async function finish(client) { const result = await client.done; assert.equal(result.code, 0, JSON.stringify(result)); }

test('two real processes: no lost subscriptions/events or duplicate concurrent delivery', { timeout: 30000 }, async t => {
  const f = await fixture(t, { now: Date.now }); const calls = [];
  const endpoint = fakeEndpoint(calls, 25);
  const a = processClient(t, f.config.statePath, { op: 'write', events: ['a1', 'a2', 'a3', 'shared'] }, endpoint);
  const b = processClient(t, f.config.statePath, { op: 'write', events: ['b1', 'b2', 'b3', 'shared'] }, endpoint);
  await Promise.all([a.ready, b.ready]); a.start(); b.start(); await Promise.all([finish(a), finish(b)]);
  const events = calls.map(x => JSON.parse(x.body)).filter(x => x.eventId);
  assert.equal(events.length, 7); assert.equal(new Set(events.map(x => x.eventId)).size, 7);
  assert.equal(calls.length - events.length, 1); // one verified/idempotent subscription
  const state = JSON.parse(await fs.readFile(f.config.statePath));
  assert.equal(Object.keys(state.subscriptions).length, 1); assert.equal(state.seen.length, 7); assert.equal(state.queue.length, 0);
});

test('killed process releases lock and restart recovers durable claim with the same event ID', { timeout: 30000 }, async t => {
  const f = await fixture(t, { now: Date.now }); await f.service.subscribe(subscribe()); await f.service.publish(event());
  const calls = []; let observed;
  const attempted = new Promise(resolve => { observed = resolve; });
  const crashed = processClient(t, f.config.statePath, { op: 'deliver' }, async msg => { calls.push(msg); observed(); return null; });
  await crashed.ready; crashed.start(); await attempted;
  const claimed = JSON.parse(await fs.readFile(f.config.statePath));
  assert.equal(claimed.queue[0].claim.pid, crashed.child.pid); assert.equal(claimed.queue[0].attempts, 1);
  crashed.child.kill('SIGKILL'); assert.equal((await crashed.done).signal, 'SIGKILL');
  await new Promise(resolve => setTimeout(resolve, 1001));
  const restarted = processClient(t, f.config.statePath, { op: 'deliver' }, fakeEndpoint(calls));
  await restarted.ready; restarted.start(); await finish(restarted);
  assert.equal(calls.length, 2); assert.equal(calls[0].body, calls[1].body);
  assert.equal(calls[0].headers['webhook-id'], calls[1].headers['webhook-id']);
  assert.notEqual(calls[0].headers['webhook-timestamp'], calls[1].headers['webhook-timestamp']);
  assert.equal(JSON.parse(await fs.readFile(f.config.statePath)).queue.length, 0);
});

test('real-process recovery excludes revoked and expired subscriptions', { timeout: 30000 }, async t => {
  for (const action of ['revoke', 'expire', 'deny']) {
    const f = await fixture(t, { now: Date.now });
    await f.service.subscribe({ ...subscribe(), ttlMs: action === 'expire' ? 1000 : 3600000 }); await f.service.publish(event());
    let observed; const attempted = new Promise(resolve => { observed = resolve; });
    const crashed = processClient(t, f.config.statePath, { op: 'deliver' }, async () => { observed(); return null; });
    await crashed.ready; crashed.start(); await attempted; crashed.child.kill('SIGKILL'); await crashed.done;
    if (action === 'revoke') await f.service.revoke();
    if (action === 'expire') await new Promise(resolve => setTimeout(resolve, 1001));
    const calls = [];
    const restarted = processClient(t, f.config.statePath, { op: 'deliver', allow: action !== 'deny' }, fakeEndpoint(calls));
    await restarted.ready; restarted.start(); await finish(restarted); assert.equal(calls.length, 0);
    assert.equal(JSON.parse(await fs.readFile(f.config.statePath)).queue.length, 0);
  }
});

test('lock custodian crash cannot cause a stale write or simultaneous duplicate send', { timeout: 30000 }, async t => {
  const f = await fixture(t, { now: Date.now }); await f.service.subscribe(subscribe()); await f.service.publish(event());
  let observed, held;
  const attempted = new Promise(resolve => { observed = resolve; });
  const owner = processClient(t, f.config.statePath, { op: 'deliver' }, async msg => { held = msg; observed(); return null; });
  await owner.ready; owner.start(); await attempted;
  const blocked = processClient(t, f.config.statePath, { op: 'deliver', lockTimeoutMs: 100 }, () => assert.fail('contending process must not send'));
  await blocked.ready; blocked.start(); const rejected = await blocked.done;
  assert.equal(rejected.code, 1); assert.equal(rejected.result.reason, 'lock_timeout');
  const helper = Number(execFileSync('pgrep', ['-P', String(owner.child.pid)], { encoding: 'utf8' }).trim());
  assert.ok(Number.isInteger(helper) && helper > 0); process.kill(helper, 'SIGKILL');
  const calls = [];
  const concurrent = processClient(t, f.config.statePath, { op: 'write', events: ['evt_new'] }, fakeEndpoint(calls));
  await concurrent.ready; concurrent.start(); await finish(concurrent);
  assert.deepEqual(calls.map(x => JSON.parse(x.body).eventId), ['evt_new']); // live orphan claim is NOT stolen
  const revoke = processClient(t, f.config.statePath, { op: 'revoke' }, () => assert.fail('revoke must not send'));
  await revoke.ready; revoke.start(); const pending = await revoke.done;
  assert.equal(pending.code, 1); assert.equal(pending.result.reason, 'revocation_pending'); assert.equal(pending.result.retryable, true);
  owner.child.send({ reply: held.call, response: { status: 200, body: '' } });
  assert.equal((await owner.done).code, 1); // dead custodian cannot commit a stale snapshot
  const state = JSON.parse(await fs.readFile(f.config.statePath));
  assert.equal(state.seen.length, 2); assert.equal(state.queue.length, 1); assert.equal(state.queue[0].event.eventId, 'evt_1');
  const recovered = processClient(t, f.config.statePath, { op: 'deliver' }, fakeEndpoint(calls));
  await recovered.ready; recovered.start(); await finish(recovered);
  assert.deepEqual(calls.map(x => JSON.parse(x.body).eventId), ['evt_new', 'evt_1']);
});

test('real-process revoke during blocked pinned HTTPS: waits for bounded attempt, or explicit pending then retry', { timeout: 30000 }, async t => {
  for (const lockTimeoutMs of [3000, 100]) {
    const f = await fixture(t, { now: Date.now }); await f.service.subscribe(subscribe()); await f.service.publish(event());
    let observed; const attempted = new Promise(resolve => { observed = resolve; }); let sent = 0;
    const delivery = processClient(t, f.config.statePath, { op: 'deliver', pinned: true, attemptTimeoutMs: 750 }, async msg => { expectSignature(msg); sent++; observed(); return null; });
    await delivery.ready; delivery.start(); await attempted;
    const revoke = processClient(t, f.config.statePath, { op: 'revoke', lockTimeoutMs }, () => assert.fail('revoke must not send'));
    await revoke.ready; const began = Date.now(); revoke.start(); const stopped = await revoke.done;
    assert.ok(Date.now() - began < 5000, 'stop must resolve or explicitly fail within the configured bounds');
    if (lockTimeoutMs === 100) {
      assert.equal(stopped.code, 1); assert.equal(stopped.result.reason, 'revocation_pending'); assert.equal(stopped.result.retryable, true);
      assert.equal(Object.keys(JSON.parse(await fs.readFile(f.config.statePath)).subscriptions).length, 1); // NOT falsely revoked
      await finish(delivery); await f.service.revoke();
    } else { assert.equal(stopped.code, 0, JSON.stringify(stopped)); await finish(delivery); }
    const state = JSON.parse(await fs.readFile(f.config.statePath)); assert.equal(state.queue.length, 0); assert.equal(Object.keys(state.subscriptions).length, 0);
    assert.equal((await f.service.publish(event('after_stop'))).queued, 0);
    await new Promise(resolve => setTimeout(resolve, 1001));
    const laterCalls = []; const later = processClient(t, f.config.statePath, { op: 'deliver' }, fakeEndpoint(laterCalls));
    await later.ready; later.start(); await finish(later); assert.equal(laterCalls.length, 0); assert.equal(sent, 1);
  }
});

test('same-process stop cannot wait indefinitely behind an in-memory delivery queue', { timeout: 10000 }, async t => {
  const f = await fixture(t); await f.service.subscribe(subscribe()); await f.service.publish(event());
  let observed, release; const attempted = new Promise(resolve => { observed = resolve; });
  const delivery = createEventsService({ ...f.config, transport: () => new Promise(resolve => { release = resolve; observed(); }) });
  const active = delivery.deliverDue(); await attempted;
  const stop = createEventsService({ ...f.config, lockTimeoutMs: 100 });
  const began = Date.now();
  await assert.rejects(stop.revoke(), e => e.code === -32000 && e.data.reason === 'revocation_pending' && e.data.retryable);
  await assert.rejects(stop.unsubscribe(subscribe()), e => e.data.reason === 'revocation_pending');
  assert.ok(Date.now() - began < 2000);
  release({ status: 503 }); await active; await stop.revoke();
  assert.equal((await f.service.deliverDue()).delivered, 0);
});
