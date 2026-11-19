import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, writeFile, stat, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignJWT, exportJWK } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createGateway, validateConfig, CONTROL_DENIAL_CODES, ATTESTATION_CHECK_IDS } from '../src/workrelay/mcp.mjs';
import { auditSettings, auditEntry, auditOutcome, createToolAudit, AUDIT_DEFAULT_MAX_BYTES } from '../src/workrelay/tool_audit.mjs';

const codes = { denialCodes: CONTROL_DENIAL_CODES, checkIds: ATTESTATION_CHECK_IDS };
const privateDir = async () => { const dir = await mkdtemp(join(tmpdir(), 'tool-audit-')); await chmod(dir, 0o700); return dir; };
const lines = async path => (await readFile(path, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
const FIELDS = ['client_id', 'duration_ms', 'operation_key', 'session_id', 'status', 'tool', 'ts'];

test('audit_log config: private default, explicit opt-out, bounded explicit settings', () => {
  assert.equal(auditSettings({}), null, 'no private state directory: disabled by default');
  assert.deepEqual(auditSettings({ issuer_state_dir: '/private/state' }),
    { path: '/private/state/tool-audit.jsonl', maxBytes: AUDIT_DEFAULT_MAX_BYTES, maxFiles: 3 });
  assert.equal(auditSettings({ issuer_state_dir: '/private/state', audit_log: false }), null);
  assert.deepEqual(auditSettings({ audit_log: { path: '/var/x/audit.jsonl', max_bytes: 4096, max_files: 1 } }),
    { path: '/var/x/audit.jsonl', maxBytes: 4096, maxFiles: 1 });
  for (const bad of [null, true, 'path', [], {}, { path: 'relative.jsonl' }, { path: '/a/../b.jsonl' }, { path: '/dir/' },
    { path: '/a.jsonl', max_bytes: 1 }, { path: '/a.jsonl', max_bytes: 2 ** 31 }, { path: '/a.jsonl', max_files: 0 },
    { path: '/a.jsonl', max_files: 21 }, { path: '/a.jsonl', max_files: 1.5 }, { path: '/a.jsonl', extra: true }])
    assert.throws(() => auditSettings({ audit_log: bad }), /audit log/, JSON.stringify(bad));
  const gateway = { public_origin: 'https://workrelay.example', issuer: 'https://issuer.example', jwks_uri: 'https://issuer.example/jwks',
    audience: 'https://workrelay.example/mcp', principal: 'p', owner: 'p', bridge_config: '/private/bridge', port: 1234 };
  assert.equal(validateConfig({ ...gateway, audit_log: { path: '/private/audit.jsonl' } }).audit_log.path, '/private/audit.jsonl');
  assert.throws(() => validateConfig({ ...gateway, audit_log: { path: 'audit.jsonl' } }), /audit log/);
});

test('audit entries carry only ids, duration and closed outcome; never content or secrets', () => {
  const secret = 'SECRET-PROMPT sk-live-TOKEN Bearer eyJhbGciOi';
  const ctx = { http: { authInfo: { token: 'eyJhbGciOi.raw.token', extra: { managedClaims: { client_id: 'https://chatgpt.com/oauth/client.json', sub: 'alice' } } } } };
  const input = { session_id: 'ses_abc', operation_id: 'op-1', text: secret, answer: { q: secret }, directory: '/home/secret', title: secret };
  const ok = auditEntry({ tool: 'workrelay_server_message', input, ctx, durationMs: 12.6, now: () => 0, codes,
    result: { content: [{ type: 'text', text: secret }], structuredContent: { phase: 'queued', session_id: 'ses_abc', message: secret } } });
  assert.deepEqual(ok, { ts: '1970-01-01T00:00:00.000Z', tool: 'workrelay_server_message', session_id: 'ses_abc', operation_key: 'op-1',
    client_id: 'https://chatgpt.com/oauth/client.json', duration_ms: 13, status: 'ok' });
  assert.doesNotMatch(JSON.stringify(ok), /SECRET|sk-live|eyJ|home\/secret/);

  // Create learns its session ID from the result; legacy tools use their task key.
  const created = auditEntry({ tool: 'workrelay_server_create', input: { operation_id: 'c1', title: secret, project_id: 'project_' + 'a'.repeat(64) },
    result: { structuredContent: { session_id: 'ses_workrelay_' + 'b'.repeat(32), phase: 'created' } }, durationMs: 1, codes });
  assert.equal(created.session_id, 'ses_workrelay_' + 'b'.repeat(32)); assert.equal(created.operation_key, 'c1');
  assert.equal(auditEntry({ tool: 'workrelay_start', input: { key: 'task-1', text: secret } }).operation_key, 'task-1');

  // Hostile identifiers are dropped, not escaped into the log.
  const hostile = auditEntry({ tool: 'workrelay_server_read\n{"forged":1}', input: { session_id: 'ses_x\nforged', operation_id: 'op 1' },
    ctx: { http: { authInfo: { extra: { managedClaims: { client_id: 'client with spaces' } } } } }, durationMs: -1 });
  assert.deepEqual([hostile.tool, hostile.session_id, hostile.operation_key, hostile.client_id, hostile.duration_ms], [null, null, null, null, null]);
  assert.deepEqual(Object.keys(hostile).sort(), FIELDS);

  // Closed outcome categories from structured fields only.
  assert.deepEqual(auditOutcome(undefined, true, codes), { status: 'error', error_category: 'exception' });
  assert.deepEqual(auditOutcome({ isError: true, content: [{ type: 'text', text: secret }] }, false, codes),
    { status: 'error', error_category: 'unavailable_or_denied' });
  assert.deepEqual(auditOutcome({ isError: true, structuredContent: { error: secret, code: 'CONTROL_NOT_SENT', denial_code: 'ATTESTATION_FAILED',
    attestation_check_id: 'GUARD_SOURCE', phase: 'denied' } }, false, codes),
  { status: 'error', error_category: 'denied', error_code: 'CONTROL_NOT_SENT', denial_code: 'ATTESTATION_FAILED', attestation_check_id: 'GUARD_SOURCE' });
  assert.deepEqual(auditOutcome({ isError: true, structuredContent: { error: secret, code: 'CONTROL_UNCERTAIN' } }, false, codes),
    { status: 'error', error_category: 'uncertain', error_code: 'CONTROL_UNCERTAIN' });
  assert.deepEqual(auditOutcome({ structuredContent: { phase: 'denied', denial_code: 'QUOTA_DENIED', attestation_check_id: 'GUARD_SOURCE' } }, false, codes),
    { status: 'error', error_category: 'denied', denial_code: 'QUOTA_DENIED' }, 'denied receipt is not ok; check id only for attestation');
  assert.deepEqual(auditOutcome({ isError: true, structuredContent: { code: secret, denial_code: secret, attestation_check_id: secret, error: secret } }, false, codes),
    { status: 'error', error_category: 'tool_error' });
  assert.deepEqual(auditOutcome({ isError: true, structuredContent: { error: { code: -32001, reason: 'managed_events_denied' } } }, false, codes),
    { status: 'error', error_category: 'events_denied' });
});

test('audit writer: 0600 append-only JSON lines, bounded rotation, unsafe targets skipped without throwing', async () => {
  const dir = await privateDir();
  const path = join(dir, 'audit.jsonl');
  const audit = createToolAudit({ path, maxBytes: 4096, maxFiles: 2, codes });
  for (let index = 0; index < 120; index++)
    assert.equal(audit.record({ tool: 'workrelay_server_read', input: { session_id: `ses_${index}` }, durationMs: index }), true);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const files = (await readdir(dir)).sort();
  assert.deepEqual(files, ['audit.jsonl', 'audit.jsonl.1', 'audit.jsonl.2'], 'oldest generation is discarded');
  for (const file of files) {
    const info = await stat(join(dir, file));
    assert.ok(info.size <= 4096, `${file} bounded`); assert.equal(info.mode & 0o777, 0o600);
  }
  const current = await lines(path);
  assert.equal(current.at(-1).session_id, 'ses_119'); assert.equal(current.at(-1).status, 'ok');

  // Never follow symlinks, never write foreign-permission files, never throw.
  const loose = join(dir, 'loose.jsonl'); await writeFile(loose, '', { mode: 0o644 }); await chmod(loose, 0o644);
  assert.equal(createToolAudit({ path: loose }).record({ tool: 'workrelay_server_read' }), false);
  assert.equal((await readFile(loose, 'utf8')), '');
  const target = join(dir, 'target.jsonl'); await writeFile(target, '', { mode: 0o600 });
  const link = join(dir, 'link.jsonl'); await symlink(target, link);
  assert.equal(createToolAudit({ path: link }).record({ tool: 'workrelay_server_read' }), false);
  assert.equal((await readFile(target, 'utf8')), '');
  const shared = join(dir, 'shared'); await mkdir(shared, { mode: 0o755 }); await chmod(shared, 0o755);
  assert.equal(createToolAudit({ path: join(shared, 'audit.jsonl') }).record({ tool: 'workrelay_server_read' }), false);
  assert.deepEqual(await readdir(shared), [], 'non-private directory receives nothing');
  assert.equal(createToolAudit({ path: join(dir, 'missing', 'audit.jsonl') }).record({ tool: 'workrelay_server_read' }), false);

  // The wrapper preserves results and errors exactly, whatever the audit does.
  const broken = createToolAudit({ path: join(dir, 'missing', 'audit.jsonl') });
  const value = { content: [] };
  assert.equal(await broken.wrap('workrelay_server_read', async () => value)({}, {}), value);
  const failure = new Error('handler failure');
  await assert.rejects(broken.wrap('workrelay_server_read', async () => { throw failure; })({}, {}), error => error === failure);
  const thrown = createToolAudit({ path: join(dir, 'thrown.jsonl') });
  await assert.rejects(thrown.wrap('workrelay_server_read', async () => { throw failure; })({ session_id: 'ses_t' }, {}));
  assert.deepEqual((await lines(join(dir, 'thrown.jsonl')))[0].error_category, 'exception');
});

test('gateway appends one audit line per tool call through the real MCP path; audit failure never breaks a call', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'audit-key', alg: 'RS256', use: 'sig' };
  const issuerServer = createServer((_, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise(resolve => issuerServer.listen(0, '127.0.0.1', resolve));
  const issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const dir = await privateDir();
  const secret = 'SECRET-PROMPT-TEXT do not log';
  const run = async auditLog => {
    const reserve = createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
    const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
    const config = { public_origin: 'https://workrelay.example', issuer, jwks_uri: `${issuer}/jwks`, audience: 'https://workrelay.example/mcp',
      principal: 'person-1', owner: 'person-1', bridge_config: '/nonexistent-private-config', port, audit_log: auditLog };
    const gateway = createGateway(config, { testIssuer: true, invoke: async (_config, command, input) => {
      if (command === 'cancel') throw Error('adapter exploded with ' + secret);
      if (command === 'respond') return { error: 'denied ' + secret };
      return { command, key: input.key, phase: 'running' };
    } });
    await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
    const jwt = await new SignJWT({ scope: 'workrelay:tasks', client_id: 'https://client.example/oauth.json' })
      .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' }).setIssuer(issuer).setAudience(config.audience)
      .setSubject('person-1').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const client = new Client({ name: 'audit-test', version: '1' });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { authProvider: { token: async () => jwt } }));
      const started = await client.callTool({ name: 'workrelay_start', arguments: { key: 'task-1', text: secret } });
      const denied = await client.callTool({ name: 'workrelay_respond', arguments: { key: 'task-1', feedback_key: 'fb-1', text: secret } });
      const failed = await client.callTool({ name: 'workrelay_cancel', arguments: { key: 'task-1' } });
      return { jwt, started, denied, failed };
    } finally { await client.close(); await new Promise(resolve => gateway.close(resolve)); }
  };
  try {
    const path = join(dir, 'audit.jsonl');
    const { jwt, started, denied, failed } = await run({ path });
    assert.equal(started.structuredContent.phase, 'running'); assert.equal(denied.isError, true); assert.equal(failed.isError, true);
    const raw = await readFile(path, 'utf8');
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.doesNotMatch(raw, /SECRET|exploded|denied SECRET/); assert.ok(!raw.includes(jwt) && !raw.includes(jwt.split('.')[1]));
    const entries = raw.trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(entries.map(entry => [entry.tool, entry.operation_key, entry.client_id, entry.status, entry.error_category ?? null]), [
      ['workrelay_start', 'task-1', 'https://client.example/oauth.json', 'ok', null],
      ['workrelay_respond', 'task-1', 'https://client.example/oauth.json', 'error', 'tool_error'],
      ['workrelay_cancel', 'task-1', 'https://client.example/oauth.json', 'error', 'unavailable_or_denied'],
    ]);
    for (const entry of entries) {
      assert.ok(Number.isInteger(entry.duration_ms) && entry.duration_ms >= 0);
      assert.ok(!Number.isNaN(Date.parse(entry.ts)));
      assert.deepEqual(Object.keys(entry).filter(key => !['error_category'].includes(key)).sort(), FIELDS);
    }
    // Unwritable/unsafe audit target: identical tool behaviour, nothing written.
    const shared = join(dir, 'shared'); await mkdir(shared, { mode: 0o755 }); await chmod(shared, 0o755);
    const again = await run({ path: join(shared, 'audit.jsonl') });
    assert.equal(again.started.structuredContent.phase, 'running'); assert.equal(again.denied.isError, true);
    assert.deepEqual(await readdir(shared), []);
  } finally { await new Promise(resolve => issuerServer.close(resolve)); }
});
