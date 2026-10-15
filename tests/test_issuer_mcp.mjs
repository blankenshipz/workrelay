import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import argon2 from 'argon2';
import { createGateway, readPrivateConfig } from '../src/workrelay/mcp.mjs';

test('production local-only loopback gateway requires provisioned state and rejects proxy claims', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-issuer-mcp-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const reserve = createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = 'https://workrelay.example.test';
  const redirect = 'https://client.example.test/callback';
  const config = { public_origin: origin, issuer_mode: 'self-hosted', issuer_exposure: 'local-only', issuer_state_dir: directory,
    audience: origin + '/mcp', principal: 'person1', owner: 'person1', clientId: 'approved-client',
    redirectUris: [redirect],
    bridge_config: '/not-used-by-test', port };
  assert.throws(() => createGateway({ ...config, issuer_exposure: undefined }), /explicit exposure mode/);
  assert.throws(() => createGateway(config), /private issuer/);
  const password = randomBytes(32).toString('base64url'); // fixture only; never a real credential
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'person1',
    verifier: await argon2.hash(password, { type: argon2.argon2id }) }), { mode: 0o600 });
  const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const issuerSettings = {
    version: 1, accountId: 'person1', origin,
    jwks: { keys: [{ ...signingKey, kid: 'fixture', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')],
    clientId: 'approved-client', redirectUris: [redirect],
  };
  const settingsPath = join(directory, 'issuer.json');
  await fs.writeFile(settingsPath, JSON.stringify(issuerSettings), { mode: 0o600 });
  await fs.chmod(join(directory, 'issuer.json'), 0o644);
  assert.throws(() => createGateway(config), /private issuer/);
  await fs.chmod(join(directory, 'issuer.json'), 0o600);
  for (const invalid of [
    { version: 2 }, { accountId: 'other' }, { origin: 'https://different.example.test' },
    { clientId: 'different-client' }, { redirectUris: ['https://different.example.test/callback'] },
  ]) {
    await fs.writeFile(settingsPath, JSON.stringify({ ...issuerSettings, ...invalid }));
    assert.throws(() => createGateway(config), /private issuer unavailable/);
  }
  await fs.writeFile(settingsPath, JSON.stringify(issuerSettings));
  assert.throws(() => createGateway({ ...config, clientId: 'mismatched' }), /private issuer unavailable/);
  assert.throws(() => createGateway({ ...config, redirectUris: ['https://different.example.test/callback'] }),
    /private issuer unavailable/);
  const configPath = join(directory, 'mcp.json');
  await fs.writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  assert.equal(readPrivateConfig(configPath).issuer_exposure, 'local-only');
  const probe = createGateway(readPrivateConfig(configPath)); // ordinary private-file startup
  assert.throws(() => probe.listen(port, '0.0.0.0'), /loopback binding/);
  assert.throws(() => probe.listen(port, '::'), /loopback binding/);
  assert.throws(() => probe.listen(port), /loopback binding/);
  await new Promise(resolve => probe.listen(port, '::1', resolve));
  const ipv6 = await new Promise((resolve, reject) => {
    const req = httpRequest(`http://[::1]:${port}/jwks`, { headers: { host: `[::1]:${port}` } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
  assert.equal(ipv6, 200);
  await new Promise(resolve => probe.close(resolve));
  let failOnce = true;
  const gateway = createGateway(readPrivateConfig(configPath), {
    issuerTestWrap: callback => async (req, res) => {
      if (failOnce && req.url === '/jwks') { failOnce = false; throw Error('synthetic provider rejection'); }
      return callback(req, res);
    },
    invoke: async (_config, action, args) => ({ action, key: args.key }) });
  await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
  let activeGateway = gateway;
  t.after(async () => {
    if (activeGateway.listening) await new Promise(resolve => activeGateway.close(resolve));
  });
  const base = `http://127.0.0.1:${port}`;
  const jar = new Map();
  let publicMode = false;
  async function request(path, { method = 'GET', headers = {}, body, cookies = true } = {}) {
    const output = await new Promise((resolve, reject) => {
      const req = httpRequest(base + path, { method, agent: false, headers: {
        host: publicMode ? 'workrelay.example.test' : `127.0.0.1:${port}`,
        ...(cookies ? { cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; ') } : {}), ...headers,
        ...(body !== undefined ? { 'content-length': Buffer.byteLength(body.toString()) } : {}),
      } }, res => { let text = '';
        res.on('data', chunk => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
      });
      req.on('error', reject); req.end(body?.toString());
    });
    for (const set of output.headers['set-cookie'] ?? []) {
      const [name, value] = set.split(';', 1)[0].split('=');
      if (value) jar.set(name, value); else jar.delete(name);
    }
    return { response: { status: output.status, headers: { get: key => output.headers[key] } }, text: output.text };
  }
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'http' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { host: 'workrelay.example.test' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-host': 'workrelay.example.test' } })).response.status, 400);
  const duplicateHost = await new Promise((resolve, reject) => {
    const req = httpRequest(base + '/jwks', { headers: ['Host', `127.0.0.1:${port}`,
      'Host', 'workrelay.example.test'] }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
  assert.equal(duplicateHost, 400);
  assert.equal((await request('/jwks', { headers: { origin: 'https://evil.example.test' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-for': '1.2.3.4' } })).response.status, 400);
  assert.equal((await request('/token', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded', 'content-length': '16385',
  } })).response.status, 413);
  assert.equal((await request('/auth', { method: 'PUT' })).response.status, 405);
  assert.equal((await request('/not-an-issuer-route')).response.status, 404);
  assert.equal((await request('/auth?' + 'a'.repeat(4100))).response.status, 400);
  const chunked = await new Promise((resolve, reject) => {
    const req = httpRequest(base + '/token', { method: 'POST', headers: {
      host: `127.0.0.1:${port}`, 'content-type': 'application/x-www-form-urlencoded',
      'transfer-encoding': 'chunked',
    } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end('x');
  });
  assert.equal(chunked, 411);
  assert.equal((await request('/jwks')).response.status, 400, 'async provider fault must be caught');
  const jwks = await request('/jwks');
  assert.equal(jwks.response.status, 200, jwks.text);
  assert.equal(JSON.parse(jwks.text).keys[0].d, undefined);
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const auth = (client = 'approved-client', resource = origin + '/mcp') => '/auth?' + new URLSearchParams({
    response_type: 'code', client_id: client, redirect_uri: redirect,
    scope: 'workrelay:tasks', resource, code_challenge: challenge,
    code_challenge_method: 'S256', state: 'fixture-state',
  });
  assert.equal((await request(auth('other-client'))).response.status, 400);
  const wrongResource = await request(auth('approved-client', 'https://evil.example.test/mcp'));
  assert.doesNotMatch(wrongResource.response.headers.get('location') ?? '', /[?&]code=/);
  const wrongRedirect = await request(auth().replace(encodeURIComponent(redirect),
    encodeURIComponent('https://evil.example.test/callback')));
  assert.doesNotMatch(wrongRedirect.response.headers.get('location') ?? '', /evil\.example\.test/);
  const started = await request(auth());
  assert.equal(started.response.status, 303, started.text);
  let location = new URL(started.response.headers.get('location'), base);
  assert.match(location.pathname, /^\/interaction\//);
  const hidden = html => html.match(/name="csrf" value="([^"]+)"/)?.[1];
  let next = await request(location.pathname);
  assert.ok(hidden(next.text));
  const post = (path, csrf, values) => request(path, { method: 'POST', headers: {
     origin: publicMode ? origin : base, 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ csrf, ...values }) });
  assert.equal((await post(location.pathname, 'invalid', { password })).response.status, 403);
  next = await request(location.pathname);
  next = await post(location.pathname, hidden(next.text), { password });
  assert.equal(next.response.status, 303, next.text);
  location = new URL(next.response.headers.get('location'), base);
  next = await request(location.pathname + location.search);
  assert.equal(next.response.status, 303, next.text);
  location = new URL(next.response.headers.get('location'), base);
  next = await request(location.pathname);
  assert.equal(next.response.status, 200, next.text);
  next = await post(location.pathname, hidden(next.text), { decision: 'approve' });
  assert.equal(next.response.status, 303, next.text);
  location = new URL(next.response.headers.get('location'), base);
  next = await request(location.pathname + location.search);
  const callback = new URL(next.response.headers.get('location'));
  assert.equal(callback.origin, 'https://client.example.test');
  assert.equal(callback.searchParams.get('iss'), origin);
  const code = callback.searchParams.get('code');
  assert.ok(code);
  const exchange = (tokenCode, target, proof = verifier, tokenClient = 'approved-client') => request('/token', { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: tokenClient, code: tokenCode,
      redirect_uri: redirect, code_verifier: proof, ...(target ? { resource: target } : {}) }) });
  assert.notEqual((await exchange(code, undefined)).response.status, 200);
  async function freshCode({ trackPrompts = false } = {}) {
    let sawLogin = false, sawConsent = false;
    let step = await request(auth());
    for (let i = 0; i < 12; i++) {
      assert.equal(step.response.status, 303, step.text);
      const nextUrl = new URL(step.response.headers.get('location'), base);
      if (nextUrl.origin === 'https://client.example.test') {
        assert.equal(nextUrl.searchParams.get('iss'), origin);
        const issuedCode = nextUrl.searchParams.get('code');
        return trackPrompts ? { code: issuedCode, sawLogin, sawConsent } : issuedCode;
      }
      step = await request(nextUrl.pathname + nextUrl.search);
      if (step.response.status === 200 && nextUrl.pathname.startsWith('/interaction/')) {
        const isLogin = step.text.includes('name="password"');
        if (isLogin) sawLogin = true; else sawConsent = true;
        const decision = isLogin ? { password } : { decision: 'approve' };
        step = await post(nextUrl.pathname, hidden(step.text), decision);
      }
    }
    assert.fail('authorization did not complete');
  }
  assert.notEqual((await exchange(await freshCode(), 'https://evil.example.test/mcp')).response.status, 200);
  assert.notEqual((await exchange(await freshCode(), origin + '/mcp', verifier, 'other-client')).response.status, 200);
  assert.notEqual((await exchange(await freshCode(), origin + '/mcp', 'wrong')).response.status, 200);
  const exchanged = await exchange(await freshCode(), origin + '/mcp');
  assert.equal(exchanged.response.status, 200, exchanged.text);
  const token = JSON.parse(exchanged.text).access_token;
  assert.ok(token);
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  assert.equal(payload.iss, origin);
  assert.equal(payload.aud, origin + '/mcp');
  assert.equal(payload.sub, 'person1');
  const mcp = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${token}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'workrelay_status', arguments: { key: 'task1' } } }) });
  assert.equal(mcp.response.status, 200, mcp.text);
  assert.match(mcp.text, /task1/);
  // Real provider routes, not a mock admission call. Keep moderate concurrent
  // batches so process scheduling cannot masquerade as quota denial (503).
  async function hammer(path, count) {
    const statuses = [];
    for (let n = 0; n < count; n += 8) {
      const batch = await Promise.all(Array.from({ length: Math.min(8, count - n) }, () =>
        request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: 'synthetic-invalid-token', client_id: 'approved-client' }) })));
      statuses.push(...batch.map(item => item.response.status));
    }
    return statuses;
  }
  const tokenFlood = await hammer('/token', 40);
  const revokeFlood = await hammer('/token/revocation', 20);
  assert.ok(tokenFlood.includes(429), 'token exchange is admitted before provider');
  assert.ok(revokeFlood.includes(429), 'revoke is admitted before provider');
  assert.ok(tokenFlood.some(status => status !== 429) && revokeFlood.some(status => status !== 429),
    'provider gets requests within available budget');
  assert.ok([...tokenFlood, ...revokeFlood].every(status => [200, 400, 401, 403, 429].includes(status)),
    `no overload or unbounded provider exceptions: token ${tokenFlood}, revoke ${revokeFlood}`);
  const flood = [];
  for (let n = 0; n < 32; n += 4)
    flood.push(...await Promise.all(Array.from({ length: 4 }, () => request(auth()))));
  assert.ok(flood.some(item => item.response.status === 429), 'actual provider admission must return 429');
  assert.ok(flood.every(item => [303, 429].includes(item.response.status)),
    'capacity errors must not leak as provider exceptions');
  const sizes = await Promise.all(['', '-wal', '-shm'].map(async suffix =>
    (await fs.stat(join(directory, 'issuer.sqlite' + suffix)).catch(() => ({ size: 0 }))).size));
  t.diagnostic(`issuer DB/WAL/SHM bytes after HTTP flood: ${sizes.join('/')}`);
  assert.ok(sizes.reduce((sum, size) => sum + size, 0) < 96 * 1024 * 1024,
    'measure DB, WAL and SHM together');
  await new Promise(resolve => activeGateway.close(resolve));
  activeGateway = createGateway(readPrivateConfig(configPath), { invoke: async (_config, action, args) => ({ action, key: args.key }) });
  await new Promise(resolve => activeGateway.listen(port, '127.0.0.1', resolve));
  assert.equal((await request(auth())).response.status, 429, 'admission must persist across restart');
  assert.equal((await request('/token', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded' }, body: 'client_id=approved-client' })).response.status,
  429, 'token admission must persist across restart');
  assert.equal((await request('/token/revocation', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded' }, body: 'token=synthetic-invalid-token' })).response.status,
  429, 'revocation admission must persist across restart');
  assert.equal((await request('/jwks')).response.status, 200, 'rate denial is scoped to authorization');
  // Artificial storage pressure is isolated to this disposable fixture. The
  // admission path must deny rather than growing WAL on a full state database.
  execFileSync('/usr/bin/python3', ['-c', `import sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA journal_mode=WAL');
db.execute('CREATE TABLE synthetic_pressure(data BLOB)');
for i in range(50): db.execute('INSERT INTO synthetic_pressure VALUES(randomblob(1048576))');
db.commit();db.close()`, join(directory, 'issuer.sqlite')], { stdio: 'ignore' });
  const before = await Promise.all(['', '-wal', '-shm'].map(async suffix =>
    (await fs.stat(join(directory, 'issuer.sqlite' + suffix)).catch(() => ({ size: 0 }))).size));
  assert.ok(before.reduce((sum, size) => sum + size, 0) > 48 * 1024 * 1024);
  assert.equal((await request(auth())).response.status, 503, 'storage quota is fail-closed before provider');
  const after = await Promise.all(['', '-wal', '-shm'].map(async suffix =>
    (await fs.stat(join(directory, 'issuer.sqlite' + suffix)).catch(() => ({ size: 0 }))).size));
  t.diagnostic(`issuer DB/WAL/SHM bytes after pressure denial: ${after.join('/')}`);
  assert.ok(after.reduce((sum, size) => sum + size, 0) < 96 * 1024 * 1024);
  assert.equal((await request('/jwks')).response.status, 503,
    'storage pressure also blocks provider discovery before expensive work');
  await new Promise(resolve => activeGateway.close(resolve));
  // Reset only synthetic flood and injected pressure, offline. Preserve live
  // OAuth records so the CLI restart still uses the same private issuer state.
  execFileSync('/usr/bin/python3', ['-c', `import sqlite3,sys
db=sqlite3.connect(sys.argv[1]);db.execute('DROP TABLE synthetic_pressure');
db.execute('DELETE FROM admission');db.commit();db.execute('VACUUM');
db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.close()`, join(directory, 'issuer.sqlite')], { stdio: 'ignore' });
  const occupied = await new Promise(resolve => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', error => resolve(error.code !== 'ECONNREFUSED'));
  });
  assert.equal(occupied, false, 'inspect fixture port ownership before CLI startup');
  const cli = spawn(process.execPath, ['src/workrelay/mcp.mjs', configPath],
    { cwd: process.cwd(), stdio: ['ignore', 'ignore', 'pipe'] });
  cli.stderr.resume();
  t.after(() => { if (cli.exitCode === null) cli.kill('SIGTERM'); });
  let startedCli = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (cli.exitCode !== null) break;
    try { if ((await request('/jwks')).response.status === 200) { startedCli = true; break; } }
    catch { /* local listener not yet ready */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(startedCli, true, 'ordinary CLI must bind private config only on loopback');
  jar.clear(); // new synthetic browser with no prior login or consent cookie
  const cliFlow = await freshCode({ trackPrompts: true });
  assert.equal(cliFlow.sawLogin, true, 'spawned CLI must show login');
  assert.equal(cliFlow.sawConsent, true, 'spawned CLI must show explicit consent');
  const cliExchange = await exchange(cliFlow.code, origin + '/mcp');
  assert.equal(cliExchange.response.status, 200, cliExchange.text);
  const cliToken = JSON.parse(cliExchange.text).access_token;
  assert.ok(cliToken);
  const profile = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${cliToken}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'workrelay_profile', arguments: {} } }) });
  assert.equal(profile.response.status, 200, profile.text);
  assert.match(profile.text, /person1/);
  cli.kill('SIGTERM');
  if (cli.exitCode === null) await new Promise(resolve => cli.once('exit', resolve));
  // A separate operator-only opt-in; every request remains local synthetic
  // HTTP, never proof of a public TLS terminator or actual ChatGPT client.
  const publicConfig = { ...config, issuer_exposure: 'public-proxy',
    issuer_public_proxy: { origin, acknowledge_tls_terminator_and_loopback_exclusivity: true },
    revocation_file: join(directory, 'revocation.json') };
  assert.throws(() => createGateway({ ...publicConfig, issuer_public_proxy: undefined }), /public-proxy issuer requires/);
  assert.throws(() => createGateway({ ...publicConfig, revocation_file: undefined }), /public-proxy issuer requires/);
  await fs.writeFile(publicConfig.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }),
    { mode: 0o600 });
  await fs.chmod(publicConfig.revocation_file, 0o644);
  assert.throws(() => createGateway(publicConfig), /private revocation unavailable/);
  await fs.chmod(publicConfig.revocation_file, 0o600);
  const publicConfigPath = join(directory, 'mcp-public.json');
  await fs.writeFile(publicConfigPath, JSON.stringify(publicConfig), { mode: 0o600 });
  assert.equal(readPrivateConfig(publicConfigPath).issuer_exposure, 'public-proxy');
  publicMode = true;
  const publicCli = spawn(process.execPath, ['src/workrelay/mcp.mjs', publicConfigPath],
    { cwd: process.cwd(), stdio: ['ignore', 'ignore', 'pipe'] });
  publicCli.stderr.resume();
  t.after(() => { if (publicCli.exitCode === null) publicCli.kill('SIGTERM'); });
  let publicReady = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (publicCli.exitCode !== null) break;
    try { if ((await request('/jwks')).response.status === 200) { publicReady = true; break; } }
    catch { /* local listener not yet ready */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(publicReady, true, 'public-mode source CLI must only bind loopback');
  assert.equal((await request('/jwks', { headers: { host: `127.0.0.1:${port}` } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { forwarded: 'for=127.0.0.1;proto=https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { origin: 'https://wrong.example.test' } })).response.status, 400);
  const rawStatus = async requestText => new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    let output = '';
    socket.setTimeout(3000, () => { socket.destroy(); reject(Error('raw boundary timed out')); });
    socket.once('connect', () => socket.write(requestText));
    socket.on('data', chunk => {
      output += chunk;
      if (output.includes('\r\n')) { socket.destroy(); resolve(Number(/^HTTP\/1\.1 (\d+)/.exec(output)?.[1])); }
    });
    socket.once('error', reject);
  });
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nHost: workrelay.example.test\r\n\r\n'), 400);
  assert.equal(await rawStatus('POST /token HTTP/1.1\r\nHost: workrelay.example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n'), 400);
  assert.equal(await rawStatus('GET http://wrong.example.test/jwks HTTP/1.1\r\nHost: workrelay.example.test\r\n\r\n'), 400);
  const publicMetadata = await request('/.well-known/oauth-protected-resource/mcp');
  assert.equal(publicMetadata.response.status, 200);
  assert.equal(JSON.parse(publicMetadata.text).resource, origin + '/mcp');
  assert.deepEqual(JSON.parse(publicMetadata.text).authorization_servers, [origin]);
  const discovery = await request('/.well-known/oauth-authorization-server');
  assert.equal(JSON.parse(discovery.text).issuer, origin);
  assert.equal(JSON.parse(discovery.text).authorization_response_iss_parameter_supported, true);
  const rejectedResource = await request(auth('approved-client', 'https://wrong.example.test/mcp'));
  assert.doesNotMatch(rejectedResource.response.headers.get('location') ?? '', /[?&]code=/);
  const rejectedLocation = rejectedResource.response.headers.get('location');
  assert.equal(rejectedResource.response.status, 303);
  assert.ok(rejectedLocation?.startsWith(redirect));
  assert.equal(new URL(rejectedLocation).searchParams.get('iss'), origin);
  assert.notEqual((await request(auth('unregistered-client'))).response.status, 303);
  assert.doesNotMatch((await request(auth().replace(encodeURIComponent(redirect),
    encodeURIComponent('https://wrong.example.test/callback')))).response.headers.get('location') ?? '',
  /wrong\.example\.test/);
  jar.clear();
  const publicFlow = await freshCode({ trackPrompts: true });
  assert.equal(publicFlow.sawLogin, true);
  assert.equal(publicFlow.sawConsent, true);
  const publicExchange = await exchange(publicFlow.code, origin + '/mcp');
  assert.equal(publicExchange.response.status, 200, publicExchange.text);
  const publicToken = JSON.parse(publicExchange.text).access_token;
  assert.ok(publicToken);
  assert.equal((await request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} }) })).response.status, 401);
  const publicProfile = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${publicToken}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/call',
    params: { name: 'workrelay_profile', arguments: {} } }) });
  assert.equal(publicProfile.response.status, 200, publicProfile.text);
  assert.match(publicProfile.text, /person1/);
  await fs.writeFile(publicConfig.revocation_file,
    JSON.stringify({ revoked_principals: ['person1'], revoked_tokens: [] }));
  assert.equal((await request('/jwks')).response.status, 503, 'runtime revocation blocks issuer routes');
  publicCli.kill('SIGTERM');
  if (publicCli.exitCode === null) await new Promise(resolve => publicCli.once('exit', resolve));
});
