import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import argon2 from 'argon2';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { createGateway, validateConfig } from '../src/workrelay/mcp.mjs';
import { validateNotifySettings } from '../src/workrelay/permission_notify.mjs';
import { CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from '../src/workrelay/issuer_policy.mjs';

const origin = 'https://workrelay.test';
const password = 'correct horse battery staple';

async function freePort() {
  const reserve = createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const { port } = reserve.address();
  await new Promise(resolve => reserve.close(resolve));
  return port;
}

// Raw HTTP so the test controls Host/Origin exactly like a browser behind
// `ssh -L <port>:127.0.0.1:<port>` would send them.
function call(port, { path = '/operator/permissions', method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, setHost: false,
      headers: { host: `127.0.0.1:${port}`, ...headers, ...(body !== undefined ? { 'content-length': Buffer.byteLength(body) } : {}) } }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', part => { text += part; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject); req.end(body);
  });
}

function baseConfig(directory, port) {
  return { public_origin: origin, issuer_mode: 'self-hosted', issuer_exposure: 'local-only', issuer_state_dir: directory,
    audience: origin + '/mcp', principal: 'person1', owner: 'person1', clientId: CHATGPT_CIMD_ID,
    redirectUris: [CHATGPT_CIMD_REDIRECT], clientRegistration: 'chatgpt-cimd', bridge_config: '/unused-fixture',
    managed_supervisor_file: '/unused-fixture/managed.json', port };
}

async function issuerState(t) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-operator-loopback-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await fs.writeFile(join(directory, 'issuer.json'), JSON.stringify({ version: 1, accountId: 'person1', origin,
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('hex')], clientId: CHATGPT_CIMD_ID, redirectUris: [CHATGPT_CIMD_REDIRECT],
    clientRegistration: 'chatgpt-cimd' }), { mode: 0o600 });
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'person1',
    verifier: await argon2.hash(password, { type: argon2.argon2id }) }), { mode: 0o600 });
  return directory;
}

async function start(t, config) {
  const gateway = createGateway(config);
  await new Promise(resolve => gateway.listen(config.port, '127.0.0.1', resolve));
  if (gateway.operatorServer && !gateway.operatorServer.listening)
    await new Promise(resolve => gateway.operatorServer.once('listening', resolve));
  t.after(() => new Promise(resolve => { gateway.close(resolve); gateway.closeAllConnections(); }));
  return gateway;
}

test('local_listen is an exact opt-in loopback port, off by default', () => {
  const config = baseConfig('/private/issuer', 9000);
  assert.equal(validateConfig({ ...config, operator_approvals: { enabled: true } }).operator_approvals.local_listen, undefined);
  validateConfig({ ...config, operator_approvals: { enabled: true, local_listen: { port: 9001 } } });
  for (const local_listen of [null, {}, [], { port: '9001' }, { port: 80 }, { port: 70000 }, { port: 9001, host: '0.0.0.0' }, { port: 9001.5 }])
    assert.throws(() => validateNotifySettings({ enabled: true, local_listen }), /operator_approvals/);
  assert.throws(() => validateConfig({ ...config, operator_approvals: { enabled: true, local_listen: { port: 9000 } } }), /local_listen/);
  const external = { public_origin: origin, issuer: 'https://issuer.test', jwks_uri: 'https://issuer.test/jwks', audience: origin + '/mcp',
    principal: 'person1', owner: 'person1', bridge_config: '/b', managed_supervisor_file: '/m.json', port: 9000 };
  assert.throws(() => validateConfig({ ...external, operator_approvals: { enabled: true, local_listen: { port: 9001 } } }), /local_listen/);
});

test('loopback listener serves only the password/CSRF-protected operator page', async t => {
  const directory = await issuerState(t);
  const [mainPort, operatorPort] = [await freePort(), await freePort()];
  const gateway = await start(t, validateConfig({ ...baseConfig(directory, mainPort),
    operator_approvals: { enabled: true, directories: ['/work/dd'], local_listen: { port: operatorPort } } }));
  assert.deepEqual(gateway.operatorServer.address(), { address: '127.0.0.1', family: 'IPv4', port: operatorPort });

  // Never MCP, OIDC, OAuth interaction, metadata or JWKS routes.
  for (const path of ['/mcp', '/.well-known/oauth-protected-resource/mcp', '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server', '/jwks', '/auth', '/token', '/token/revocation', '/interaction/abc',
    '/operator/permissions?x=1', '/operator/permissions/', '/operator', '/']) {
    for (const method of ['GET', 'POST']) {
      const response = await call(operatorPort, { path, method, ...(method === 'POST' ? { body: '' } : {}) });
      assert.equal(response.status, 404, `${method} ${path}`);
      assert.equal(response.headers['set-cookie'], undefined);
    }
  }
  assert.equal((await call(operatorPort, { method: 'DELETE' })).status, 405);
  // Exact loopback Host only; never forwarded identity.
  for (const headers of [{ host: 'workrelay.test' }, { host: `127.0.0.1:${mainPort}` }, { host: `evil.test:${operatorPort}` },
    { host: '127.0.0.1' }, { 'x-forwarded-for': '203.0.113.1' }, { 'x-forwarded-proto': 'https' }, { 'x-forwarded-host': 'workrelay.test' },
    { forwarded: 'for=203.0.113.1' }, { 'x-real-ip': '203.0.113.1' }])
    assert.equal((await call(operatorPort, { headers })).status, 400, JSON.stringify(headers));
  assert.equal((await call(operatorPort, { headers: { host: `localhost:${operatorPort}` } })).status, 200);

  const local = `http://127.0.0.1:${operatorPort}`;
  const jar = new Map();
  const send = async (form, { originHeader = local, cookies = jar } = {}) => {
    const body = form ? new URLSearchParams(form).toString() : undefined;
    const response = await call(operatorPort, { method: form ? 'POST' : 'GET', body,
      headers: { ...(form ? { 'content-type': 'application/x-www-form-urlencoded', origin: originHeader } : {}),
        cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join('; ') } });
    for (const set of [response.headers['set-cookie'] ?? []].flat()) {
      // Plain-HTTP loopback origin: host-only, path-scoped, HttpOnly, Strict, never __Host-/Secure.
      assert.match(set, /^workrelay-operator-(flow|session)=[^;]*; Path=\/operator\/permissions; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
      const [pair] = set.split(';'); const [name, value] = pair.split('=');
      if (/Max-Age=0/.test(set)) jar.delete(name); else jar.set(name, value);
    }
    return response;
  };
  const tokens = text => ({ flow: /name="flow" value="([^"]+)"/.exec(text)?.[1], csrf: /name="csrf" value="([^"]+)"/.exec(text)?.[1] });

  const login = await send();
  assert.equal(login.status, 200);
  assert.match(login.text, /type="password"/);
  assert.match(login.headers['content-security-policy'], /form-action 'self'/);
  let form = tokens(login.text);
  assert.equal((await send({ ...form, password: 'wrong password for operator' })).status, 403);
  assert.equal((await send({ ...form, password })).status, 403, 'login CSRF is single-use');
  for (const originHeader of [origin, 'https://evil.test', `http://127.0.0.1:${mainPort}`, 'null']) {
    form = tokens((await send()).text);
    assert.equal((await send({ ...form, password }, { originHeader })).status, 403, `origin ${originHeader} denied`);
  }
  form = tokens((await send()).text);
  assert.equal((await send({ ...form, password }, { cookies: new Map() })).status, 403, 'login requires the flow cookie');
  form = tokens((await send()).text);
  const listed = await send({ ...form, password });
  assert.equal(listed.status, 200);
  assert.ok(jar.has('workrelay-operator-session'));
  assert.match(listed.text, /Workrelay pending permissions/);
  assert.match(listed.text, /unavailable/, 'fixture has no native server; nothing is fabricated');

  // A decision still needs the operator session cookie plus a fresh single-use CSRF.
  const page = tokens(listed.text);
  const decide = { ...page, session_id: 'ses_example', permission_id: 'per_example', decision: 'once' };
  assert.equal((await send(decide, { cookies: new Map() })).status, 403);
  const session = jar.get('workrelay-operator-session');
  assert.equal((await send(decide, { cookies: new Map([['__Host-workrelay-operator', session]]) })).status, 403,
    'public-origin cookie name is not accepted on the loopback page');
  const refreshed = await send(page);
  assert.equal(refreshed.status, 200);
  assert.equal((await send(page)).status, 403, 'page CSRF is single-use');

  // The main gateway port is unchanged: same page, public-origin Secure cookies, MCP still bearer-only.
  const main = await call(mainPort);
  assert.equal(main.status, 200);
  assert.match([main.headers['set-cookie']].flat()[0], /^__Host-workrelay-flow=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Strict/);
  assert.equal((await call(mainPort, { path: '/mcp', method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 401);

  await new Promise(resolve => { gateway.close(resolve); gateway.closeAllConnections(); });
  assert.equal(gateway.operatorServer.listening, false, 'operator listener shares the gateway lifetime');
});

test('without local_listen no operator listener is opened', async t => {
  const directory = await issuerState(t);
  const [mainPort, unusedPort] = [await freePort(), await freePort()];
  const gateway = await start(t, validateConfig({ ...baseConfig(directory, mainPort), operator_approvals: { enabled: true, directories: ['/work/dd'] } }));
  assert.equal(gateway.operatorServer, undefined);
  await assert.rejects(call(unusedPort), /ECONNREFUSED/);
});
