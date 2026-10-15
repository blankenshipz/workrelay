import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createUnexposedIssuerPolicy } from '../src/workrelay/issuer_policy.mjs';

test('maintained issuer policy advertises S256/JWKS but refuses unregistered clients and redirects', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-issuer-policy-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const config = { origin: 'https://issuer.example.test', principal: 'person1',
    jwks: { keys: [{ ...key, kid: 'temporary-test', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')], clientId: 'approved-client',
    redirectUris: ['https://client.example.test/callback'], adapter: createIssuerAdapter(directory),
    findAccount: async () => undefined };
  for (const redirects of [['https://*.example.test/callback'], ['http://client.example.test/callback'],
    ['https://client.example.test/callback#fragment']])
    assert.throws(() => createUnexposedIssuerPolicy({ ...config, redirectUris: redirects }));
  const provider = createUnexposedIssuerPolicy(config);
  const server = createServer(provider.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const metadata = await (await fetch(base + '/.well-known/oauth-authorization-server')).json();
    assert.equal(metadata.issuer, config.origin);
    assert.ok(metadata.code_challenge_methods_supported.includes('S256'));
    assert.equal(metadata.registration_endpoint, undefined);
    const jwks = await (await fetch(base + '/jwks')).json();
    assert.equal(jwks.keys[0].kid, 'temporary-test');
    assert.equal(jwks.keys[0].d, undefined);
    const authorize = (client, redirect) => `${base}/auth?response_type=code&client_id=${encodeURIComponent(client)}` +
      `&redirect_uri=${encodeURIComponent(redirect)}&scope=workrelay%3Atasks&resource=${encodeURIComponent(config.origin + '/mcp')}` +
      '&code_challenge=' + 'a'.repeat(43) + '&code_challenge_method=S256&state=synthetic';
    const unknown = await fetch(authorize('unknown-client', config.redirectUris[0]), { redirect: 'manual' });
    assert.notEqual(unknown.status, 302);
    const offsite = await fetch(authorize(config.clientId, 'https://evil.example.test/callback'), { redirect: 'manual' });
    assert.notEqual(offsite.headers.get('location')?.startsWith('https://evil.example.test/'), true);
    const wrongResource = await fetch(authorize(config.clientId, config.redirectUris[0])
      .replace(encodeURIComponent(config.origin + '/mcp'), encodeURIComponent('https://evil.example.test/mcp')),
    { redirect: 'manual' });
    assert.doesNotMatch(wrongResource.headers.get('location') ?? '', /[?&]code=/);
    const missingResource = await fetch(authorize(config.clientId, config.redirectUris[0])
      .replace('&resource=' + encodeURIComponent(config.origin + '/mcp'), ''), { redirect: 'manual' });
    assert.doesNotMatch(missingResource.headers.get('location') ?? '', /[?&]code=/);
    assert.match(missingResource.headers.get('location') ?? '', /error=invalid_target/);
    const missingPkce = await fetch(authorize(config.clientId, config.redirectUris[0])
      .replace('&code_challenge=' + 'a'.repeat(43) + '&code_challenge_method=S256', ''),
    { redirect: 'manual' });
    assert.doesNotMatch(missingPkce.headers.get('location') ?? '', /[?&]code=/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('actual provider token route requires exact resource and configured principal', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-policy-token-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const issuer = 'https://issuer.example.test';
  const resource = `${issuer}/mcp`;
  const clientId = 'approved-client';
  const redirect = 'https://client.example.test/callback';
  const provider = createUnexposedIssuerPolicy({ origin: issuer, principal: 'person1',
    jwks: { keys: [{ ...key, kid: 'policy-test', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')], clientId,
    redirectUris: [redirect], adapter: createIssuerAdapter(directory),
    findAccount: async (_ctx, id) => ({ accountId: id, claims: async () => ({ sub: id }) }) });
  const server = createServer(provider.callback());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const tokenEndpoint = `http://127.0.0.1:${server.address().port}/token`;
    const client = await provider.Client.find(clientId);
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    async function issueCode(accountId = 'person1') {
      const grant = new provider.Grant({ accountId, clientId });
      grant.addResourceScope(resource, 'workrelay:tasks');
      const grantId = await grant.save();
      const code = new provider.AuthorizationCode({ client, accountId, grantId,
        codeChallenge: challenge, codeChallengeMethod: 'S256', redirectUri: redirect,
        resource, scope: 'workrelay:tasks', claims: {} });
      return code.save();
    }
    async function exchange(code, target, extra = {}) {
      const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
        code, redirect_uri: redirect, code_verifier: verifier, ...extra });
      if (target !== undefined) body.set('resource', target);
      const result = await fetch(tokenEndpoint, { method: 'POST', body, redirect: 'manual' });
      return { status: result.status, body: await result.json() };
    }
    for (const target of [undefined, 'https://evil.example.test/mcp']) {
      const result = await exchange(await issueCode(), target);
      assert.notEqual(result.status, 200);
      assert.equal(result.body.access_token, undefined);
    }
    const other = await exchange(await issueCode('other-person'), resource);
    assert.notEqual(other.status, 200);
    assert.equal(other.body.access_token, undefined);
    const valid = await exchange(await issueCode(), resource);
    assert.equal(valid.status, 200);
    assert.ok(valid.body.access_token);
    const [, payload] = valid.body.access_token.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    assert.equal(claims.sub, 'person1');
    assert.equal(claims.aud, resource);
    assert.ok(claims.exp - claims.iat <= 300);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
