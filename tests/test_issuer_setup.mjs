import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { SignJWT, importJWK, jwtVerify, createLocalJWKSet } from 'jose';
import argon2 from 'argon2';
import { finalizeIssuerSetup, issuerReferences, rotateIssuer } from '../src/workrelay/issuer_setup.mjs';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createUnexposedIssuerPolicy } from '../src/workrelay/issuer_policy.mjs';

test('synthetic private setup: stable signing keys, exact references, no overwrite, no interactive bypass', async t => {
  const parent = await fs.mkdtemp(join(tmpdir(), 'workrelay-setup-'));
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
  const parent = await fs.mkdtemp(join(tmpdir(), 'workrelay-setup-path-'));
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
