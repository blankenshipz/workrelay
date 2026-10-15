import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { validateConfig } from '../src/workrelay/mcp.mjs';
import Provider from 'oidc-provider';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
function childCommand(directory, input) {
  const child = spawn('/usr/bin/python3', ['-m', 'workrelay.oidc_store', directory], {
    env: { PATH: '/usr/bin:/bin', PYTHONPATH: source }, stdio: ['pipe', 'pipe', 'pipe'],
  });
  let output = '', error = '';
  const finished = new Promise((resolveChild, reject) => {
    child.on('error', reject);
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { error += chunk; });
    child.on('close', code => resolveChild({ code, output, error, pid: child.pid }));
  });
  child.stdin.end(input);
  return finished;
}

test('official provider adapter shape persists records across instances, TTL, consume and revoke', async t => {
  const root = await fs.mkdtemp(join(tmpdir(), 'workrelay-oidc-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const Adapter = createIssuerAdapter(root);
  const first = new Adapter('AuthorizationCode');
  await first.upsert('code1', { uid: 'session1', grantId: 'grant1', secret: 'synthetic-private-only' }, 120);
  const second = new Adapter('AuthorizationCode');
  assert.equal((await second.find('code1')).secret, 'synthetic-private-only');
  assert.equal((await second.findByUid('session1')).grantId, 'grant1');
  await second.consume('code1');
  assert.ok((await first.find('code1')).consumed);
  await assert.rejects(first.consume('code1'), /private issuer storage unavailable/);
  await assert.rejects(first.consume('absent'), /private issuer storage unavailable/);
  await second.revokeByGrantId('grant1');
  assert.equal(await first.find('code1'), null);
  await first.upsert('code2', { exp: 0 }, 1);
  await new Promise(resolve => setTimeout(resolve, 1250));
  assert.equal(await first.find('code2'), null);
  await assert.rejects(first.consume('code2'), /private issuer storage unavailable/);
  await assert.rejects(first.upsert('large', { text: '😎'.repeat(80000) }, 30),
    /private issuer storage unavailable/);
  const valid = JSON.stringify({ model: 'AuthorizationCode', action: 'find', id: 'code2' });
  for (const input of [valid + '{}', valid + ' ', Buffer.alloc(300001, 0x61)]) {
    const result = await childCommand(root, input);
    assert.equal(result.code, 2);
    assert.equal(result.output, '');
    assert.doesNotMatch(result.error, /code2|synthetic-private-only/);
  }
  assert.equal((await fs.stat(join(root, 'issuer.sqlite'))).mode & 0o777, 0o600);
  await fs.chmod(root, 0o755);
  await assert.rejects(first.find('code2'), /private issuer storage unavailable/);
  const link = root + '-link';
  await fs.symlink(root, link);
  await assert.rejects(new (createIssuerAdapter(link))('AuthorizationCode').find('code2'),
    /private issuer storage unavailable/);
  await fs.unlink(link);
});

test('two OS processes race to consume one code: only one transaction claims it', async t => {
  const root = await fs.mkdtemp(join(tmpdir(), 'workrelay-code-race-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const Adapter = createIssuerAdapter(root);
  const code = new Adapter('AuthorizationCode');
  await code.upsert('single-use', { grantId: 'owned-grant' }, 90);
  const command = JSON.stringify({ model: 'AuthorizationCode', action: 'consume', id: 'single-use' });
  const [a, b] = await Promise.all([childCommand(root, command), childCommand(root, command)]);
  assert.notEqual(a.pid, b.pid);
  assert.deepEqual([a.code, b.code].sort(), [0, 2]);
  assert.ok((await code.find('single-use')).consumed);
});

test('two OS processes enforce persistent admission quota while pruning only expired rows', async t => {
  const root = await fs.mkdtemp(join(tmpdir(), 'workrelay-store-quota-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const Adapter = createIssuerAdapter(root);
  const live = new Adapter('AuthorizationCode');
  await live.upsert('anchor', { marker: 'live' }, 180);
  const db = join(root, 'issuer.sqlite');
  const seed = `import sqlite3,sys,time
db=sqlite3.connect(sys.argv[1]); now=int(time.time()); db.execute('BEGIN IMMEDIATE')
db.executemany('INSERT INTO records(model,id,payload,expires) VALUES(?,?,?,?)',
 [('AuthorizationCode','live-'+str(i),'{}',now+180) for i in range(4094)] +
 [('Interaction','expired-'+str(i),'{}',now-1) for i in range(300)])
db.commit(); db.close()`;
  execFileSync('/usr/bin/python3', ['-c', seed, db], { stdio: 'ignore' });
  const upsert = id => JSON.stringify({ model: 'AuthorizationCode', action: 'upsert',
    id, payload: { marker: 'admitted' }, expiresIn: 120 });
  // A legacy over-quota DB makes bounded progress even while denying writes.
  assert.equal((await childCommand(root, upsert('initial-denied'))).code, 2);
  assert.equal((await childCommand(root, upsert('second-denied'))).code, 2);
  const [a, b] = await Promise.all([childCommand(root, upsert('contender-a')),
    childCommand(root, upsert('contender-b'))]);
  assert.notEqual(a.pid, b.pid);
  assert.deepEqual([a.code, b.code].sort(), [0, 2]);
  assert.equal((await live.find('anchor')).marker, 'live');
  assert.equal((await live.find('live-4093')) !== null, true);
  const totals = execFileSync('/usr/bin/python3', ['-c', `import sqlite3,sys
db=sqlite3.connect(sys.argv[1]); print(db.execute('SELECT count(*) FROM records').fetchone()[0]);
print(db.execute('SELECT count(*) FROM records WHERE id LIKE ?', ('expired-%',)).fetchone()[0])`, db],
  { encoding: 'utf8' }).trim().split('\n').map(Number);
  assert.deepEqual(totals, [4096, 0]);
  assert.equal((await childCommand(root, upsert('restart-denied'))).code, 2);
  const winner = a.code === 0 ? 'contender-a' : 'contender-b';
  await live.destroy(winner);
  assert.equal((await childCommand(root, upsert('restart-admitted'))).code, 0);
  assert.equal((await live.find('anchor')).marker, 'live');
});

test('two OS processes share global and socket-remote authorization admission', async t => {
  if (Date.now() % 60000 > 48000)
    await new Promise(resolve => setTimeout(resolve, 60000 - Date.now() % 60000 + 200));
  const root = await fs.mkdtemp(join(tmpdir(), 'workrelay-auth-admission-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const adapter = new (createIssuerAdapter(root))('AuthorizationCode');
  await adapter.upsert('anchor', { marker: 'live' }, 180);
  const db = join(root, 'issuer.sqlite');
  execFileSync('/usr/bin/python3', ['-c', `import sqlite3,sys,time
db=sqlite3.connect(sys.argv[1]);window=int(time.time())//60
db.executemany('INSERT INTO admission VALUES(?,?,?)',
 [('global',window,31),('127.0.0.1',window,23),('::1',window,8)])
db.commit();db.close()`, db], { stdio: 'ignore' });
  const admit = id => JSON.stringify({ model: 'Issuer', action: 'admit', id });
  const [a, b] = await Promise.all([childCommand(root, admit('127.0.0.1')),
    childCommand(root, admit('::1'))]);
  assert.notEqual(a.pid, b.pid);
  assert.deepEqual([JSON.parse(a.output), JSON.parse(b.output)].sort(), [false, true]);
  assert.equal(JSON.parse((await childCommand(root, admit('127.0.0.1'))).output), false);
  assert.equal((await adapter.find('anchor')).marker, 'live');
});

test('writable ancestor, swapped private directory and SQLite sidecar symlink fail closed', async t => {
  const outer = await fs.mkdtemp(join(tmpdir(), 'workrelay-path-'));
  await fs.chmod(outer, 0o700);
  t.after(() => fs.rm(outer, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const parent = join(outer, 'parent');
  const root = join(parent, 'state');
  await fs.mkdir(parent, { mode: 0o700 });
  await fs.mkdir(root, { mode: 0o700 });
  const Code = createIssuerAdapter(root);
  const adapter = new Code('AuthorizationCode');
  await adapter.upsert('owned', { scope: 'test-only' }, 120);
  await fs.chmod(parent, 0o777);
  await assert.rejects(adapter.find('owned'), /private issuer storage unavailable/);
  await fs.chmod(parent, 0o700);
  const renamed = join(parent, 'original-state');
  await fs.rename(root, renamed);
  await fs.symlink(renamed, root);
  await assert.rejects(adapter.find('owned'), /private issuer storage unavailable/);
  await fs.unlink(root);
  await fs.rename(renamed, root);
  const target = join(parent, 'outside-target');
  await fs.writeFile(target, '', { mode: 0o600 });
  const sidecar = join(root, 'issuer.sqlite-wal');
  await fs.rm(sidecar, { force: true }); // closed fixture; replace its prior sidecar
  await fs.symlink(target, sidecar);
  await assert.rejects(adapter.find('owned'), /private issuer storage unavailable/);
  await fs.unlink(sidecar);
  assert.equal((await adapter.find('owned')).scope, 'test-only');
});

test('self-hosted mode refuses incomplete private configuration', () => {
  assert.throws(() => validateConfig({ issuer_mode: 'self-hosted', public_origin: 'https://example.test' }),
    /not safely available/);
  const external = { public_origin: 'https://example.test', issuer: 'https://issuer.example.test',
    jwks_uri: 'https://issuer.example.test/jwks', audience: 'https://example.test/mcp',
    principal: 'user', owner: 'user', bridge_config: '/private/config', port: 9000 };
  assert.equal(validateConfig(external).issuer, 'https://issuer.example.test');
});

test('maintained provider accepts private adapter and generates discovery, but is not mounted in MCP', async t => {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-provider-'));
  await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const signing = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const issuer = 'https://issuer.example.test';
  const provider = new Provider(issuer, {
    adapter: createIssuerAdapter(dir),
    jwks: { keys: [{ ...signing, kid: 'ephemeral-test-key', alg: 'RS256', use: 'sig' }] },
    cookies: { keys: [randomBytes(32).toString('base64url')] },
    clients: [{ client_id: 'known-local-test', redirect_uris: ['https://client.example.test/callback'],
      token_endpoint_auth_method: 'none', response_types: ['code'], grant_types: ['authorization_code'] }],
    features: { devInteractions: { enabled: false }, resourceIndicators: { enabled: true,
      getResourceServerInfo: async (_ctx, requested) => {
        if (requested !== 'https://resource.example.test/mcp') throw Error('invalid resource');
        return { scope: 'workrelay:tasks', audience: requested, accessTokenTTL: 300, accessTokenFormat: 'jwt' };
      } } },
    pkce: { required: () => true },
  });
  const server = createServer(provider.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/.well-known/oauth-authorization-server`);
    assert.equal(response.status, 200);
    const metadata = await response.json();
    assert.equal(metadata.issuer, issuer);
    assert.ok(metadata.code_challenge_methods_supported.includes('S256'));
    assert.equal(metadata.registration_endpoint, undefined);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
