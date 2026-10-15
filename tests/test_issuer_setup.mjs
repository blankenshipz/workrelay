import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { SignJWT, importJWK, jwtVerify, createLocalJWKSet } from 'jose';
import argon2 from 'argon2';
import { finalizeIssuerSetup, issuerReferences, rotateIssuer,
  provisionGeneratedChatGPT } from '../src/workrelay/issuer_setup.mjs';
import { CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from '../src/workrelay/issuer_policy.mjs';

async function privateFixture(prefix) {
  // The generated path must be outside the project and reject writable
  // ancestors; macOS tmpdir and the repo's .runtime are unsuitable.
  const sibling = fileURLToPath(new URL('../../', import.meta.url));
  return fs.mkdtemp(join(sibling, `.workrelay-test-${prefix}`));
}

test('generated CIMD credential stays in a separate owner-only delivery file and binds private verifier', async t => {
  const parent = await privateFixture('workrelay-generated-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const directory = join(parent, 'issuer-state');
  const delivery = join(parent, 'sync-private');
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.mkdir(delivery, { mode: 0o700 });
  const path = join(delivery, 'login.txt');
  const random = count => { assert.equal(count, 48); return Buffer.alloc(count, 0x5a); };
  const origin = 'https://relay.example.test';
  const result = await provisionGeneratedChatGPT({ directory, origin, deliveryFile: path, random });
  assert.deepEqual(result, { status: 'provisioned', path });
  assert.equal((await fs.stat(path)).mode & 0o777, 0o600);
  for (const name of ['human.json', 'issuer.json'])
    assert.equal((await fs.stat(join(directory, name))).mode & 0o777, 0o600);
  assert.deepEqual(await fs.readdir(directory), ['human.json', 'issuer.json']);
  const password = await fs.readFile(path);
  try {
    assert.equal(password.length, 64, '48 bytes of synthetic entropy encode to 64 base64url bytes');
    const human = JSON.parse(await fs.readFile(join(directory, 'human.json')));
    assert.ok(human.verifier.startsWith('$argon2id$'));
    assert.equal(await argon2.verify(human.verifier, password), true);
    const reference = issuerReferences(directory);
    assert.equal(reference.clientId, CHATGPT_CIMD_ID);
    assert.deepEqual(reference.redirectUris, [CHATGPT_CIMD_REDIRECT]);
    assert.equal(reference.audience, `${origin}/mcp`);
    assert.equal(reference.principal, human.accountId);
    const before = await Promise.all([path, join(directory, 'human.json'), join(directory, 'issuer.json')]
      .map(file => fs.readFile(file)));
    await assert.rejects(provisionGeneratedChatGPT({ directory, origin, deliveryFile: path, random }),
      /existing delivery file/);
    const after = await Promise.all([path, join(directory, 'human.json'), join(directory, 'issuer.json')]
      .map(file => fs.readFile(file)));
    assert.ok(before.every((file, index) => file.equals(after[index])), 'collision changes no private inode contents');
    const script = new URL('../src/workrelay/issuer_setup.mjs', import.meta.url).pathname;
    const refused = spawnSync(process.execPath, [script, 'init-chatgpt-cimd-generated', directory, origin, path],
      { encoding: 'utf8' });
    assert.equal(refused.status, 1, 'generated verb is recognized without a TTY but refuses existing credentials');
    assert.equal(refused.stdout, '');
    assert.equal(refused.stderr.includes(password.toString('utf8')), false);
  } finally { password.fill(0); }
});

test('generated setup rejects unsafe destinations and removes only newly created files after failure', async t => {
  const parent = await privateFixture('workrelay-generated-denial-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const directory = join(parent, 'issuer-state'), delivery = join(parent, 'sync-private');
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.mkdir(delivery, { mode: 0o700 });
  const path = join(delivery, 'login.txt');
  const input = { directory, origin: 'https://relay.example.test', deliveryFile: path,
    random: count => Buffer.alloc(count, 0x5a) };
  await assert.rejects(provisionGeneratedChatGPT({ ...input, deliveryFile: join(process.cwd(), 'login.txt') }),
    /outside the project/);
  await fs.symlink(join(parent, 'absent-target'), path);
  await assert.rejects(provisionGeneratedChatGPT(input), /existing delivery file/);
  assert.deepEqual(await fs.readdir(directory), []);
  await fs.unlink(path);
  const preexisting = join(delivery, 'preexisting.txt');
  await fs.writeFile(preexisting, 'synthetic-preexisting', { mode: 0o600 });
  await fs.link(preexisting, path);
  await assert.rejects(provisionGeneratedChatGPT(input), /existing delivery file/);
  assert.equal(await fs.readFile(preexisting, 'utf8'), 'synthetic-preexisting');
  assert.deepEqual(await fs.readdir(directory), []);
  await fs.unlink(path);
  await fs.unlink(preexisting);
  const linkedDelivery = join(parent, 'linked-delivery');
  await fs.symlink(delivery, linkedDelivery);
  await assert.rejects(provisionGeneratedChatGPT({ ...input, deliveryFile: join(linkedDelivery, 'login.txt') }),
    /private directory|unsafe directory alias/);
  await fs.unlink(linkedDelivery);
  const linkedState = join(parent, 'linked-state');
  await fs.symlink(directory, linkedState);
  await assert.rejects(provisionGeneratedChatGPT({ ...input, directory: linkedState }),
    /private directory|unsafe directory alias/);
  await fs.unlink(linkedState);
  assert.deepEqual(await fs.readdir(directory), []);
  assert.deepEqual(await fs.readdir(delivery), []);
  await fs.chmod(delivery, 0o777);
  await assert.rejects(provisionGeneratedChatGPT(input), /private directory/);
  await fs.chmod(delivery, 0o700);
  for (const failure of ['human.json', 'issuer.json']) {
    await assert.rejects(provisionGeneratedChatGPT({ ...input, beforeWrite: name => {
      if (name === failure) throw Error('synthetic write failure');
    } }), /private issuer setup unavailable/);
    assert.deepEqual(await fs.readdir(directory), []);
    assert.deepEqual(await fs.readdir(delivery), []);
  }
  await assert.rejects(provisionGeneratedChatGPT({ ...input, afterWrite: () => {
    throw Error('synthetic finalization failure');
  } }), /private issuer setup unavailable/);
  assert.deepEqual(await fs.readdir(directory), []);
  assert.deepEqual(await fs.readdir(delivery), []);
  await fs.writeFile(join(directory, 'human.json'), 'existing-partial', { mode: 0o600 });
  await assert.rejects(provisionGeneratedChatGPT(input), /existing issuer state/);
  assert.equal(await fs.readFile(join(directory, 'human.json'), 'utf8'), 'existing-partial');
  assert.deepEqual(await fs.readdir(delivery), []);
});

test('default CSPRNG provisions distinct private credentials; successful CLI prints path, never secret', async t => {
  const parent = await privateFixture('workrelay-generated-default-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const origin = 'https://relay.example.test';
  const script = new URL('../src/workrelay/issuer_setup.mjs', import.meta.url).pathname;
  const passwords = [];
  try {
    for (let index = 0; index < 2; index++) {
      const root = join(parent, `case-${index}`);
      const directory = join(root, 'state'), delivery = join(root, 'sync');
      await fs.mkdir(root, { mode: 0o700 });
      await fs.mkdir(directory, { mode: 0o700 });
      await fs.mkdir(delivery, { mode: 0o700 });
      const path = join(delivery, 'login.txt');
      const output = spawnSync(process.execPath, [script, 'init-chatgpt-cimd-generated', directory, origin, path],
        { encoding: 'utf8', timeout: 30000 });
      assert.equal(output.status, 0, 'generated CLI completes in a disposable private directory');
      const password = await fs.readFile(path);
      passwords.push(password);
      assert.equal(password.length, 64);
       assert.ok(/^[A-Za-z0-9_-]{64}$/.test(password.toString('ascii')),
         'generated password has bounded base64url format');
      assert.equal(output.stdout.includes(password.toString('ascii')), false);
      assert.equal(output.stderr.includes(password.toString('ascii')), false);
      assert.equal(output.stdout.includes(path), true, 'only destination path is reported');
      assert.equal((await fs.stat(path)).mode & 0o777, 0o600);
      assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
      assert.equal((await fs.stat(delivery)).mode & 0o777, 0o700);
      const human = JSON.parse(await fs.readFile(join(directory, 'human.json')));
      assert.ok(human.verifier.startsWith('$argon2id$'));
      assert.equal(await argon2.verify(human.verifier, password), true);
      const reference = issuerReferences(directory);
      assert.equal(reference.clientId, CHATGPT_CIMD_ID);
      assert.deepEqual(reference.redirectUris, [CHATGPT_CIMD_REDIRECT]);
      assert.equal(JSON.stringify(reference).includes(password.toString('ascii')), false);
      assert.equal(JSON.stringify(reference).includes('cookieKeys'), false);
    }
    assert.equal(passwords[0].equals(passwords[1]), false, 'independent CSPRNG credentials differ');
  } finally { for (const password of passwords) password.fill(0); }
});

test('abrupt exit between private writes leaves no enabled issuer and refuses overwrite on restart', async t => {
  const parent = await privateFixture('workrelay-generated-crash-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const moduleUrl = new URL('../src/workrelay/issuer_setup.mjs', import.meta.url).href;
  const childCode = `import { provisionGeneratedChatGPT } from ${JSON.stringify(moduleUrl)};
const [directory, origin, deliveryFile, phase] = process.argv.slice(1);
await provisionGeneratedChatGPT({ directory, origin, deliveryFile,
  beforeWrite: name => { if (name === phase) process.exit(42); } });`;
  for (const phase of ['human.json', 'issuer.json']) {
    const root = join(parent, phase), directory = join(root, 'state'), delivery = join(root, 'sync');
    await fs.mkdir(root, { mode: 0o700 });
    await fs.mkdir(directory, { mode: 0o700 });
    await fs.mkdir(delivery, { mode: 0o700 });
    const path = join(delivery, 'login.txt');
    const child = spawnSync(process.execPath,
      ['--no-warnings', '--input-type=module', '-e', childCode, directory, 'https://relay.example.test', path, phase],
      { encoding: 'utf8', timeout: 30000 });
    assert.equal(child.status, 42, `${phase} exit after previous fsynced write`);
    assert.ok(child.stdout.length === 0, 'crash fixture emitted no stdout');
    assert.ok(child.stderr.length === 0, 'crash fixture emitted no stderr');
    assert.deepEqual(await fs.readdir(directory), phase === 'human.json' ? [] : ['human.json']);
    assert.deepEqual(await fs.readdir(delivery), ['login.txt']);
    assert.equal((await fs.stat(path)).mode & 0o777, 0o600);
    assert.throws(() => issuerReferences(directory), /ENOENT/);
    await assert.rejects(provisionGeneratedChatGPT({ directory, origin: 'https://relay.example.test',
      deliveryFile: path }), /existing delivery file/);
    assert.deepEqual(await fs.readdir(directory), phase === 'human.json' ? [] : ['human.json']);
  }
});
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createUnexposedIssuerPolicy } from '../src/workrelay/issuer_policy.mjs';

test('synthetic private setup: stable signing keys, exact references, no overwrite, no interactive bypass', async t => {
  const parent = await privateFixture('workrelay-setup-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const directory = join(parent, 'state');
  await fs.mkdir(directory, { mode: 0o700 });
  const accountId = randomBytes(24).toString('base64url');
  const fixturePassword = randomBytes(24).toString('base64url');
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId,
    verifier: await argon2.hash(fixturePassword, { type: argon2.argon2id }) }), { mode: 0o600 });
  const input = { directory, accountId, origin: 'https://relay.example.test', clientId: 'one-client',
    redirectUris: ['https://client.example.test/callback'] };
  const reference = finalizeIssuerSetup(input);
  assert.deepEqual(issuerReferences(directory), reference);
  assert.equal(reference.principal, accountId);
  assert.equal(reference.audience, input.origin + '/mcp');
  assert.equal(JSON.stringify(reference).includes(fixturePassword), false);
  assert.equal(JSON.stringify(reference).includes('cookieKeys'), false);
  const path = join(directory, 'issuer.json');
  const before = await fs.readFile(path);
  const state = JSON.parse(before);
  assert.equal((await fs.stat(path)).mode & 0o777, 0o600);
  assert.equal(state.cookieKeys[0].length >= 64, true);
  assert.equal(state.jwks.keys[0].alg, 'RS256');
  assert.equal(state.jwks.keys[0].kty, 'RSA');
  const token = await new SignJWT({ scope: 'workrelay:tasks' }).setProtectedHeader({ alg: 'RS256', kid: state.jwks.keys[0].kid })
    .setIssuer(input.origin).setAudience(reference.audience).setSubject(accountId).setIssuedAt().setExpirationTime('5m')
    .sign(await importJWK(state.jwks.keys[0], 'RS256'));
  const { d, p, q, dp, dq, qi, oth, ...publicJwk } = state.jwks.keys[0];
  const decoded = await jwtVerify(token, await importJWK(publicJwk, 'RS256'),
    { issuer: input.origin, audience: reference.audience });
  assert.equal(decoded.payload.sub, accountId);
  assert.throws(() => finalizeIssuerSetup(input), /existing issuer state/);
  assert.throws(() => finalizeIssuerSetup({ ...input, clientId: 'different' }), /existing issuer state/);
  await fs.writeFile(join(directory, 'issuer.sqlite'), '', { mode: 0o600 });
  assert.throws(() => rotateIssuer({ directory }), /requires revoked session state/);
  assert.deepEqual(await fs.readFile(path), before, 'active-state refusal does not change private key');
  await fs.unlink(join(directory, 'issuer.sqlite'));
  const rotated = rotateIssuer({ directory });
  assert.equal((await fs.stat(rotated.backup)).mode & 0o777, 0o600);
  assert.deepEqual(await fs.readFile(rotated.backup), before);
  const replacement = JSON.parse(await fs.readFile(path));
  assert.equal(replacement.jwks.keys.length, 1);
  assert.equal(replacement.retiredUntil, undefined);
  assert.notEqual(replacement.jwks.keys[0].kid, state.jwks.keys[0].kid);
  assert.notEqual(replacement.cookieKeys[0], state.cookieKeys[0], 'old browser cookies cannot be decrypted');
  assert.deepEqual(issuerReferences(directory), reference, 'public references survive restart and pre-start rotation');
  const provider = createUnexposedIssuerPolicy({ origin: input.origin, principal: accountId,
    jwks: replacement.jwks, cookieKeys: replacement.cookieKeys, clientId: input.clientId,
    redirectUris: input.redirectUris, adapter: createIssuerAdapter(directory),
    findAccount: async () => undefined });
  const server = createServer(provider.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const publicSet = await (await fetch(`http://127.0.0.1:${server.address().port}/jwks`)).json();
    assert.deepEqual(publicSet.keys.map(key => key.kid), [replacement.jwks.keys[0].kid]);
    assert.ok(publicSet.keys.every(key => !key.d), 'no private key returned by provider JWKS');
    assert.notEqual(publicSet.keys[0].kid, state.jwks.keys[0].kid, 'backup key is not served');
    const verifier = createLocalJWKSet(publicSet);
    await assert.rejects(jwtVerify(token, verifier, { issuer: input.origin, audience: reference.audience }),
      /no applicable key|matching key|signature/i, 'old signed token must fail immediately after rotation');
    const newToken = await new SignJWT({ scope: 'workrelay:tasks' })
      .setProtectedHeader({ alg: 'RS256', kid: replacement.jwks.keys[0].kid })
      .setIssuer(input.origin).setAudience(reference.audience).setSubject(accountId)
      .setIssuedAt().setExpirationTime('5m')
      .sign(await importJWK(replacement.jwks.keys[0], 'RS256'));
    assert.equal((await jwtVerify(newToken, verifier, { issuer: input.origin,
      audience: reference.audience })).payload.sub, accountId);
  } finally { await new Promise(resolve => server.close(resolve)); }
  const script = new URL('../src/workrelay/issuer_setup.mjs', import.meta.url).pathname;
  const shown = spawnSync(process.execPath, [script, 'reference', directory], { encoding: 'utf8' });
  assert.equal(shown.status, 0);
  assert.deepEqual(JSON.parse(shown.stdout), reference);
  assert.doesNotMatch(shown.stdout + shown.stderr, /cookieKeys|"d"\s*:/);
  const noTty = spawnSync(process.execPath, [script, 'init', directory, input.origin,
    input.clientId, input.redirectUris[0]], { encoding: 'utf8' });
  assert.equal(noTty.status, 2);
  assert.equal(noTty.stdout, '');
  assert.doesNotMatch(noTty.stderr, new RegExp(fixturePassword));
});

test('setup rejects permissive ancestors, account mismatch, bad redirect, and existing sidecars', async t => {
  const parent = await privateFixture('workrelay-setup-path-');
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const directory = join(parent, 'state');
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'account1',
    verifier: await argon2.hash('synthetic-only-not-a-user-password', { type: argon2.argon2id }) }), { mode: 0o600 });
  const input = { directory, accountId: 'account1', origin: 'https://issuer.example.test',
    clientId: 'client1', redirectUris: ['https://client.example.test/callback'] };
  await fs.chmod(parent, 0o777);
  assert.throws(() => finalizeIssuerSetup(input), /unsafe directory ancestor/);
  await fs.chmod(parent, 0o700);
  assert.throws(() => finalizeIssuerSetup({ ...input, accountId: 'wrong' }), /human account mismatch/);
  assert.throws(() => finalizeIssuerSetup({ ...input, redirectUris: ['http://client.example.test/callback'] }), /exact HTTPS/);
  await fs.writeFile(join(directory, 'issuer.sqlite-wal'), '', { mode: 0o600 });
  assert.throws(() => finalizeIssuerSetup(input), /existing issuer state/);
  assert.equal((await fs.readdir(directory)).includes('issuer.json'), false);
});
