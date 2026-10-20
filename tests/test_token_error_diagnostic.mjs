import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { createServer, request } from 'node:https';
import { errors } from 'oidc-provider';
import { createTokenErrorDiagnostic, createUnexposedIssuerPolicy } from '../src/workrelay/issuer_policy.mjs';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';

async function fixture(t) {
  const dir = await fs.mkdtemp(fileURLToPath(new URL('.workrelay-token-error-', import.meta.url))); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const now = 1000000, attemptId = randomBytes(16).toString('hex');
  const arm = join(dir, 'token-error.arm'), receipt = join(dir, 'token-error.receipt.json');
  const data = { target: 'token-error', attemptId, issuedAt: now, expiresAt: now + 1800000 };
  return { dir, now, attemptId, arm, receipt, data,
    armWith: value => fs.writeFile(arm, JSON.stringify(value ?? data), { mode: 0o600 }),
    read: async () => JSON.parse(await fs.readFile(receipt, 'utf8')) };
}

test('token error recorder: default off, strict expiry, private arms, finite hostile values and isolation', async t => {
  const f = await fixture(t), record = createTokenErrorDiagnostic(f.dir, { now: () => f.now });
  record({ grantKind: 'refresh', errorClass: 'invalid_grant' }); await assert.rejects(fs.access(f.receipt));
  for (const data of [{ ...f.data, expiresAt: f.now }, { ...f.data, expiresAt: f.now + 1800001 },
    { ...f.data, issuedAt: f.now + 1 }, { ...f.data, extra: 'PRIVATE' }, { ...f.data, target: 'authorization-outcome' }]) {
    await f.armWith(data); record({ grantKind: 'refresh', errorClass: 'invalid_grant' }); await assert.rejects(fs.access(f.receipt));
  }
  await f.armWith(); await fs.chmod(f.arm, 0o644); record({}); await assert.rejects(fs.access(f.receipt));
  await fs.chmod(f.arm, 0o600);
  await fs.writeFile(join(f.dir, 'authorization-outcome.arm'), 'PRIVATE', { mode: 0o600 });
  record({ grantKind: 'PRIVATE\nrefresh', errorClass: { toString() { throw Error('PRIVATE'); } }, message: 'PRIVATE' });
  assert.deepEqual(await f.read(), { attemptId: f.attemptId, stage: 'token', outcome: 'grant_error', grantKind: 'other', errorClass: 'other' });
  assert.equal((await fs.stat(f.receipt)).mode & 0o777, 0o600);
  assert.equal(await fs.readFile(join(f.dir, 'authorization-outcome.arm'), 'utf8'), 'PRIVATE');
  await f.armWith(); record({ grantKind: 'authcode', errorClass: 'invalid_request' });
  assert.equal((await f.read()).grantKind, 'other', 'receipt never overwritten');
  assert.doesNotThrow(() => createTokenErrorDiagnostic('/nonexistent/diagnostic')({}));
  assert.doesNotThrow(() => record({ get errorClass() { throw Error('PRIVATE'); } }));
});

test('token error recorder: cross-process one-shot concurrency and independent directories', async t => {
  const f = await fixture(t); await f.armWith();
  const url = new URL('../src/workrelay/issuer_policy.mjs', import.meta.url).href;
  const script = `import {createTokenErrorDiagnostic} from ${JSON.stringify(url)};createTokenErrorDiagnostic(process.argv[1],{now:()=>${f.now}})({grantKind:'refresh',errorClass:'invalid_grant'});`;
  await Promise.all([1, 2, 3].map(() => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, f.dir], { stdio: 'ignore' });
    child.once('error', reject); child.once('exit', code => code === 0 ? resolve() : reject(Error('child failed')));
  })));
  assert.equal((await f.read()).errorClass, 'invalid_grant');
  assert.equal((await fs.stat(join(f.dir, 'token-error.used'))).mode & 0o777, 0o600);
  const g = await fixture(t); await g.armWith();
  createTokenErrorDiagnostic(g.dir, { now: () => g.now })({ grantKind: 'authcode', errorClass: 'invalid_client' });
  assert.equal((await g.read()).grantKind, 'authcode'); assert.notEqual((await g.read()).attemptId, (await f.read()).attemptId);
});

test('maintained provider actual token failures emit native finite grant.error; recorder failure cannot change response', async t => {
  const f = await fixture(t), outcomes = [];
  const provider = createUnexposedIssuerPolicy({ origin: 'https://issuer.example.test', principal: 'fixture-person',
    jwks: { keys: [{ ...generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')], clientId: 'fixture-client', redirectUris: ['https://client.example.test/callback'],
    adapter: createIssuerAdapter(f.dir), findAccount: async () => undefined,
    onTokenError: value => { outcomes.push(value); createTokenErrorDiagnostic(f.dir, { now: () => f.now })(value); throw Error('PRIVATE diagnostic failure'); } });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost',
    '-keyout', join(f.dir, 'tls.key'), '-out', join(f.dir, 'tls.crt'), '-days', '1'], { stdio: 'ignore' });
  const server = createServer({ key: await fs.readFile(join(f.dir, 'tls.key')), cert: await fs.readFile(join(f.dir, 'tls.crt')) }, provider.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const post = body => new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: server.address().port, path: '/token', method: 'POST', rejectUnauthorized: false,
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' } }, res => {
      let text = ''; res.on('data', chunk => { text += chunk; }); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    }); req.on('error', reject); req.end(new URLSearchParams(body).toString());
  });
  for (const [grant_type, grantKind, args] of [
    ['authorization_code', 'authcode', { code: 'synthetic-missing-code', redirect_uri: 'https://client.example.test/callback', code_verifier: 'a'.repeat(43) }],
    ['refresh_token', 'refresh', { refresh_token: 'synthetic-missing-refresh' }],
  ]) {
    const before = await post({ grant_type, client_id: 'fixture-client', ...args });
    assert.equal(before.status, 400); assert.equal(before.body.error, 'invalid_grant');
    assert.deepEqual(outcomes.at(-1), { grantKind, errorClass: 'invalid_grant' });
  }
  await f.armWith();
  const captured = await post({ grant_type: 'refresh_token', client_id: 'fixture-client', refresh_token: 'synthetic-missing-refresh' });
  assert.equal(captured.status, 400); assert.equal(captured.body.error, 'invalid_grant');
  assert.deepEqual(await f.read(), { attemptId: f.attemptId, stage: 'token', outcome: 'grant_error', grantKind: 'refresh', errorClass: 'invalid_grant' });
  provider.emit('grant.error', { oidc: { params: { grant_type: 'PRIVATE' } } }, { error: 'invalid_grant', message: 'PRIVATE' });
  assert.deepEqual(outcomes.at(-1), { grantKind: 'other', errorClass: 'other' }, 'non-native errors do not establish structured evidence');
  provider.emit('grant.error', {}, new errors.InvalidRequest('PRIVATE'));
  assert.deepEqual(outcomes.at(-1), { grantKind: 'unknown', errorClass: 'invalid_request' });
  provider.emit('grant.error', { oidc: { params: { grant_type: 'refresh_token' } } }, new errors.InvalidClientAuth('PRIVATE'));
  assert.deepEqual(outcomes.at(-1), { grantKind: 'refresh', errorClass: 'invalid_client' });
  const unknownNative = new errors.InvalidGrant('PRIVATE'); unknownNative.error = 'PRIVATE_REVOKED_OR_EXPIRED';
  provider.emit('grant.error', { oidc: { params: { grant_type: 'authorization_code' } } }, unknownNative);
  assert.deepEqual(outcomes.at(-1), { grantKind: 'authcode', errorClass: 'other' }, 'unknown native codes are never persisted');
  provider.emit('grant.error', { get oidc() { throw Error('PRIVATE'); } }, new errors.InvalidGrant('PRIVATE'));
  assert.deepEqual(outcomes.at(-1), { grantKind: 'other', errorClass: 'other' });
});
