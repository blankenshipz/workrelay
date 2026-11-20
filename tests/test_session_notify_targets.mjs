import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { createSessionNotifier, createDefaultTargets, directoryMatcher, renderNotifyBody, signStandardWebhook,
  validateNotifyTarget, validateSessionNotifySettings } from '../src/workrelay/session_notify.mjs';

const S = 'ses_root000000000000000001';
const HOOK = 'https://hooks.grok.example.com/routines/abc/trigger';
const SECRET_URL = 'https://hooks.slack.example.com/services/T000/B000/topsecretpath';

async function privateDir(t) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-notify-targets-')); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}
async function writeSecrets(path, targets, mode = 0o600) {
  await fs.writeFile(path, JSON.stringify({ version: 1, targets }), { mode }); await fs.chmod(path, mode);
}

function harness({ statePath, settings = {}, defaults, directory = '/home/u/work/demodirector', status = 200 } = {}) {
  let clock = 1_000_000;
  const view = { session_id: S, title: 'fix things', directory, project_id: 'project_' + 'a'.repeat(64), runtime_status: 'idle', aggregate_status: 'idle',
    last_activity_at: 1, idle_at: null, running_children: 0, failed_children: [], task_outcome: 'no_task_intent', pending: [] };
  const sent = [];
  let watchCalls = 0;
  const notifier = createSessionNotifier({ settings, statePath, defaults, serverId: 'srv_' + 'b'.repeat(64), now: () => clock,
    approvalUrl: 'http://127.0.0.1:49381/operator/permissions',
    watch: async () => { watchCalls++; return structuredClone(view); },
    transport: async (url, { body, headers }) => { sent.push({ url, headers, body }); return { status: typeof status === 'function' ? status() : status, body: '' }; } });
  const run = async () => {
    notifier.armed(S, clock);
    Object.assign(view, { aggregate_status: 'running', runtime_status: 'running', last_activity_at: 2 }); await notifier.tick();
    Object.assign(view, { aggregate_status: 'idle', runtime_status: 'idle', last_activity_at: 3, idle_at: clock + 1 }); clock += 5000; await notifier.tick();
  };
  return { notifier, view, sent, run, advance: ms => { clock += ms; }, now: () => clock, watchCalls: () => watchCalls };
}

test('Standard Webhooks signature matches the reference test vector', () => {
  assert.equal(signStandardWebhook('whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', 'msg_p5jXN8AQM9LWM0D4loKWxJek', '1614265330', '{"test": 2432232314}'),
    'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
});

test('target validation: hmac_secret and format; webhook-* headers stay reserved', () => {
  assert.deepEqual(validateNotifyTarget({ url: HOOK, hmac_secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', format: 'slack' }),
    { url: HOOK, hmac_secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', format: 'slack' });
  assert.deepEqual(validateNotifyTarget({ url: HOOK, format: 'json' }), { url: HOOK });
  for (const bad of [{ hmac_secret: 'short' }, { hmac_secret: 'plain-secret-without-prefix-0123456789' }, { hmac_secret: 'whsec_' + Buffer.alloc(16).toString('base64') },
    { hmac_secret: 'whsec_' + Buffer.alloc(65).toString('base64') }, { hmac_secret: 'whsec_!!notbase64!!!!!!' }, { hmac_secret: 'whsec_AAAA' },
    { format: 'xml' }, { header_name: 'webhook-signature', header_value: 'x' }])
    assert.throws(() => validateNotifyTarget({ url: HOOK, ...bad }), /invalid notify target/, JSON.stringify(bad));
  for (const url of ['https://localhost./x', 'https://metadata.google.internal./x', 'https://hooks.example.com./x'])
    assert.throws(() => validateNotifyTarget({ url }), /invalid notify target/, url);
});

test('gateway config: default targets never carry secrets; secret refs need secrets_file', () => {
  const base = { enabled: true, secrets_file: '/s/notify.json' };
  validateSessionNotifySettings({ ...base, default_targets: [{ name: 'grokbot_harny', secret: 'grokbot_harny', directories: ['/home/u/work/demodirector', '/srv/**/app'], clients: ['grokbot-mcp'], format: 'json', stall_minutes: 5 }] });
  validateSessionNotifySettings({ enabled: true, default_targets: [{ name: 'slack', env: { url: 'SLACK_URL' }, format: 'slack' }] });
  for (const bad of [
    { ...base, default_targets: [{ name: 'a', secret: 'a', url: HOOK }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a', header_value: 'x' }] },
    { ...base, default_targets: [{ name: 'a' }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a', env: { url: 'U' } }] },
    { ...base, default_targets: [{ name: 'a', env: { header_value: 'V' } }] },
    { ...base, default_targets: [{ name: 'a', env: { url: 'bad-name' } }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a', directories: ['relative/dir'] }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a', directories: ['/a/../b'] }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a' }, { name: 'a', secret: 'b' }] },
    { ...base, default_targets: [{ name: 'a', secret: 'a', format: 'xml' }] },
    { enabled: true, default_targets: [{ name: 'a', secret: 'a' }] },
    { enabled: true, secrets_file: 'rel.json' }])
    assert.throws(() => validateSessionNotifySettings(bad), /session_notify/, JSON.stringify(bad));
});

test('directory matching: plain paths cover subdirectories, globs match whole paths', () => {
  assert.ok(directoryMatcher(['/a/b/'])('/a/b')); assert.ok(directoryMatcher(['/a/b/'])('/a/b/c')); assert.ok(directoryMatcher(['/a/*/'])('/a/x'));
  const match = directoryMatcher(['/w/demodirector', '/w/projects/*/app', '/srv/**/repo']);
  for (const yes of ['/w/demodirector', '/w/demodirector/sub/x', '/w/projects/a/app', '/srv/repo', '/srv/a/b/repo']) assert.ok(match(yes), yes);
  for (const no of ['/w/demodirector2', '/w', '/w/projects/a/b/app', '/w/projects/a/app/x', '/srv/a/repox', null]) assert.ok(!match(no), String(no));
  assert.ok(directoryMatcher(['/**'])('/anything/at/all'));
});

test('event schema: stable type, ids, session/server/project/directory, summary and read hint; formats', async () => {
  const h = harness();
  h.notifier.set(S, { url: HOOK });
  await h.run();
  assert.equal(h.sent.length, 1);
  const event = JSON.parse(h.sent[0].body);
  assert.equal(event.type, 'workrelay.session.finished'); assert.equal(event.schema_version, 1); assert.equal(event.source, 'workrelay');
  assert.match(event.event_id, /^evt_[a-f0-9]{24}$/);
  assert.equal(event.session_id, S); assert.equal(event.server_id, 'srv_' + 'b'.repeat(64)); assert.equal(event.project_id, 'project_' + 'a'.repeat(64));
  assert.equal(event.directory, '/home/u/work/demodirector'); assert.match(event.summary, /finished/);
  assert.deepEqual(event.read, { tool: 'workrelay_server_read', arguments: { session_id: S, include_messages: true } });
  assert.equal(h.sent[0].headers['Content-Type'], 'application/json');
  assert.equal(h.sent[0].headers['webhook-signature'], undefined, 'unsigned without hmac_secret');

  const slack = renderNotifyBody({ ...event, summary: 'Session "<!channel> & co" finished' }, 'slack');
  assert.deepEqual(Object.keys(JSON.parse(slack.body)), ['text']);
  assert.match(JSON.parse(slack.body).text, /&lt;!channel&gt; &amp; co/);
  assert.match(JSON.parse(slack.body).text, /workrelay_server_read/);
  const text = renderNotifyBody(event, 'text');
  assert.match(text.contentType, /^text\/plain/); assert.match(text.body, /^\[workrelay\] Session/);
});

test('signed delivery: verifiable Standard Webhooks headers; id stable across retries, timestamp fresh', async () => {
  const secret = 'whsec_' + Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');
  let code = 503;
  const h = harness({ status: () => code });
  h.notifier.set(S, { url: HOOK, hmac_secret: secret, header_name: 'X-Token', header_value: 'tok-123' });
  await h.run();
  assert.equal(h.sent.length, 1);
  const verify = ({ headers, body }) => headers['webhook-signature'] ===
    'v1,' + createHmac('sha256', Buffer.from('0123456789abcdef0123456789abcdef')).update(`${headers['webhook-id']}.${headers['webhook-timestamp']}.${body}`).digest('base64');
  assert.ok(verify(h.sent[0]));
  assert.equal(h.sent[0].headers['webhook-id'], JSON.parse(h.sent[0].body).event_id);
  assert.equal(h.sent[0].headers['X-Token'], 'tok-123');
  code = 200; h.advance(60000); await h.notifier.tick();
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[1].headers['webhook-id'], h.sent[0].headers['webhook-id']);
  assert.notEqual(h.sent[1].headers['webhook-timestamp'], h.sent[0].headers['webhook-timestamp']);
  assert.ok(verify(h.sent[1]));
  const status = h.notifier.get(S);
  assert.equal(status.signed, true); assert.equal(status.source, 'per_call');
  assert.doesNotMatch(JSON.stringify(status), /whsec_|tok-123|routines/);
});

test('gateway default: attached automatically, inert placeholder, filled secrets take effect without restart, never copied to state', async t => {
  const dir = await privateDir(t);
  const secretsFile = join(dir, 'notify.json'), statePath = join(dir, 'state.json');
  await writeSecrets(secretsFile, { grokbot_harny: { url: '', header_name: '', header_value: '' } });
  const defaults = createDefaultTargets({ secretsFile, entries: [{ name: 'grokbot_harny', secret: 'grokbot_harny', directories: ['/home/u/work/demodirector', '/home/u/work/yrdsale'] }] });
  const h = harness({ statePath, defaults });
  const attached = await h.notifier.attachDefault(S, { client_id: 'grokbot-mcp', at: h.now() });
  assert.equal(attached.enabled, true); assert.equal(attached.source, 'gateway_default'); assert.equal(attached.default_target, 'grokbot_harny');
  assert.equal(attached.configured, false); assert.equal(attached.reason, 'url_not_configured');
  await h.run();
  assert.equal(h.sent.length, 0, 'placeholder target is inert');
  assert.equal(h.notifier.get(S).last_delivery.error, 'url_not_configured');

  await writeSecrets(secretsFile, { grokbot_harny: { url: SECRET_URL, header_name: 'X-Routine-Secret', header_value: 'very-secret-value' } });
  const live = h.notifier.get(S);
  assert.equal(live.configured, true); assert.equal(live.url_host, 'hooks.slack.example.com'); assert.equal(live.secret_header, 'X-Routine-Secret');
  assert.doesNotMatch(JSON.stringify(live), /topsecretpath|very-secret-value/);
  await h.run();
  assert.equal(h.sent.length, 1); assert.equal(h.sent[0].url, SECRET_URL); assert.equal(h.sent[0].headers['X-Routine-Secret'], 'very-secret-value');
  const state = await fs.readFile(statePath, 'utf8');
  assert.doesNotMatch(state, /topsecretpath|very-secret-value/, 'secrets are resolved at send time, never persisted');
  assert.match(state, /"default_name":"grokbot_harny"/);

  // A secrets file readable by others is refused.
  await fs.chmod(secretsFile, 0o644);
  assert.equal(h.notifier.get(S).reason, 'secrets_file_not_private');
  await fs.chmod(secretsFile, 0o600);
  const link = join(dir, 'link.json'); await fs.symlink(secretsFile, link);
  assert.equal(createDefaultTargets({ secretsFile: link, entries: [{ name: 'x', secret: 'grokbot_harny' }] }).resolve('x').reason, 'secrets_file_unavailable');
});

test('gateway default: directory/client matching, per-call override, opt-out and explicit re-attach', async t => {
  const dir = await privateDir(t);
  const secretsFile = join(dir, 'notify.json');
  await writeSecrets(secretsFile, { grok: { url: HOOK } });
  const entries = [{ name: 'grok', secret: 'grok', directories: ['/home/u/work/demodirector'], clients: ['grokbot-mcp'] }];
  const defaults = createDefaultTargets({ secretsFile, entries });
  // Other client or other directory: nothing attached.
  assert.equal(await harness({ defaults }).notifier.attachDefault(S, { client_id: 'other-client' }), null);
  const elsewhere = harness({ defaults, directory: '/home/u/work/private' });
  assert.equal(await elsewhere.notifier.attachDefault(S, { client_id: 'grokbot-mcp' }), null); assert.equal(elsewhere.notifier.size(), 0);

  const h = harness({ defaults });
  await h.notifier.attachDefault(S, { client_id: 'grokbot-mcp' });
  assert.equal(h.notifier.get(S).default_target, 'grok');
  // Per-call target overrides the default; a later automatic attach keeps it.
  h.notifier.set(S, { url: 'https://other.example.com/hook', format: 'text' });
  assert.equal((await h.notifier.attachDefault(S, { client_id: 'grokbot-mcp' })).source, 'per_call');
  // Opt out: clear, then automatic attaches are skipped.
  assert.equal(h.notifier.clear(S).opted_out, true);
  assert.equal(await h.notifier.attachDefault(S, { client_id: 'grokbot-mcp' }), null);
  const status = await h.notifier.status(S, { client_id: 'grokbot-mcp' });
  assert.equal(status.opted_out, true); assert.equal(status.default_available.default_target, 'grok');
  // Explicit set without url re-attaches.
  const explicit = await h.notifier.attachDefault(S, { client_id: 'grokbot-mcp', explicit: true });
  assert.equal(explicit.source, 'gateway_default'); assert.equal(h.notifier.get(S).opted_out, undefined);
  assert.equal((await elsewhere.notifier.attachDefault(S, { client_id: 'grokbot-mcp', explicit: true })).error, 'no_default_target');

  // Env-sourced default.
  const envSig = 'whsec_' + Buffer.from('0123456789abcdef01234567').toString('base64');
  const envDefaults = createDefaultTargets({ env: { WR_URL: HOOK, WR_SIG: envSig }, entries: [{ name: 'env', env: { url: 'WR_URL', hmac_secret: 'WR_SIG' }, format: 'slack' }] });
  const resolved = envDefaults.resolve('env');
  assert.deepEqual(resolved.target, { url: HOOK, hmac_secret: envSig, format: 'slack' });
  assert.equal(createDefaultTargets({ env: {}, entries: [{ name: 'env', env: { url: 'WR_URL' } }] }).resolve('env').reason, 'url_not_configured');
});

test('review: a transient secrets-file failure retries instead of dropping the ask', async t => {
  const dir = await privateDir(t);
  const secretsFile = join(dir, 'notify.json');
  await writeSecrets(secretsFile, { grok: { url: HOOK } });
  const h = harness({ defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'grok', secret: 'grok' }] }) });
  await h.notifier.attachDefault(S, { client_id: 'c' });
  await fs.writeFile(secretsFile, '{ not json');
  Object.assign(h.view, { aggregate_status: 'blocked_on_permission', pending: [{ permission_id: 'per_1', session_id: S, action: 'shell', resource_preview: [], resources_omitted: 0, directory: '/x' }] });
  await h.notifier.tick();
  assert.equal(h.sent.length, 0); assert.match(h.notifier.get(S).last_delivery.error, /^secrets_file_/); assert.equal(h.notifier.get(S).skipped, 0);
  await writeSecrets(secretsFile, { grok: { url: HOOK } });
  h.advance(60000); await h.notifier.tick();
  assert.equal(h.sent.length, 1); assert.equal(JSON.parse(h.sent[0].body).type, 'workrelay.session.permission_asked');
});

test('review: an unmatched session never evicts a live target at max_targets', async t => {
  const dir = await privateDir(t);
  const secretsFile = join(dir, 'notify.json'); await writeSecrets(secretsFile, { grok: { url: HOOK } });
  const h = harness({ settings: { max_targets: 1 }, directory: '/elsewhere',
    defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'grok', secret: 'grok', directories: ['/home/u/work/demodirector'] }] }) });
  h.notifier.set('ses_other00000000000000001', { url: HOOK });
  assert.equal(await h.notifier.attachDefault(S, { client_id: 'c' }), null);
  assert.equal(h.notifier.get('ses_other00000000000000001').enabled, true); assert.equal(h.notifier.size(), 1);
});

test('review: attached defaults re-match against current config (narrowed or removed entries detach)', async t => {
  const dir = await privateDir(t);
  const secretsFile = join(dir, 'notify.json'), statePath = join(dir, 'state.json');
  await writeSecrets(secretsFile, { grok: { url: HOOK }, slack: { url: SECRET_URL } });
  const first = harness({ statePath, defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'grok', secret: 'grok' }] }) });
  await first.notifier.attachDefault(S, { client_id: 'c' });
  // Restart with the entry renamed: re-attached to the new matching entry.
  const renamed = harness({ statePath, defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'slack', secret: 'slack', format: 'slack' }] }) });
  assert.equal(renamed.notifier.get(S).reason, 'default_target_removed');
  await renamed.notifier.tick();
  assert.equal(renamed.notifier.get(S).default_target, 'slack');
  // Restart with the entry narrowed away from this directory: detached.
  const narrowed = harness({ statePath, defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'slack', secret: 'slack', directories: ['/nowhere'] }] }) });
  await narrowed.notifier.tick();
  assert.equal(narrowed.notifier.get(S).enabled, false);
  // A stale (removed) default does not block automatic attach of a current one.
  const statePath2 = join(dir, 'state2.json');
  await harness({ statePath: statePath2, defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'grok', secret: 'grok' }] }) }).notifier.attachDefault(S, { client_id: 'c' });
  const again = harness({ statePath: statePath2, defaults: createDefaultTargets({ secretsFile, entries: [{ name: 'slack', secret: 'slack' }] }) });
  assert.equal((await again.notifier.attachDefault(S, { client_id: 'c' })).default_target, 'slack');
});

test('review: clear/set during an in-flight delivery is honoured before the next send', async () => {
  let clock = 1_000_000, mode = 'fail', release;
  const sent = [];
  const ask = n => ({ permission_id: 'per_' + n, session_id: S, action: 'shell', resource_preview: [], resources_omitted: 0, directory: '/d' });
  const view = { session_id: S, title: 't', directory: '/d', runtime_status: 'running', aggregate_status: 'blocked_on_permission', last_activity_at: 1,
    idle_at: null, running_children: 0, failed_children: [], task_outcome: 'x', pending: [ask(1)] };
  const notifier = createSessionNotifier({ now: () => clock, watch: async () => structuredClone(view),
    transport: async url => {
      sent.push(url);
      if (mode === 'fail') return { status: 503 };
      if (mode === 'block') { mode = 'ok'; await new Promise(done => { release = done; }); }
      return { status: 200 };
    } });
  notifier.set(S, { url: HOOK });
  await notifier.tick();               // ask 1 queued, send fails -> retry later
  view.pending.push(ask(2)); clock += 1000;
  await notifier.tick();               // ask 2 queued, fails too: outbox now holds 2 events
  sent.length = 0; mode = 'block'; clock += 120000;
  const ticking = notifier.tick();     // first send blocks in flight
  while (!release) await new Promise(done => setImmediate(done));
  notifier.set(S, { url: 'https://new.example.com/hook' });
  release(); await ticking;
  assert.deepEqual(sent, [HOOK, 'https://new.example.com/hook']);
});
