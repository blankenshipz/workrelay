import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import argon2 from 'argon2';
import { createGateway, readPrivateConfig } from '../src/workrelay/mcp.mjs';
import { CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from '../src/workrelay/issuer_policy.mjs';

test('real public-proxy gateway discovery HEAD preserves metadata and method boundaries', async t => {
  const directory = await fs.mkdtemp(join(dirname(fileURLToPath(import.meta.url)), '.workrelay-head-'));
  await fs.chmod(directory, 0o700);
  let gateway;
  const stop = async () => {
    if (gateway?.listening) await new Promise(resolve => { gateway.close(resolve); gateway.closeAllConnections(); });
  };
  t.after(async () => { await stop(); await fs.rm(directory, { recursive: true, force: true }); });
  const origin = 'https://workrelay.example.test';
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const write = (name, value) => fs.writeFile(join(directory, name), JSON.stringify(value), { mode: 0o600 });
  await write('human.json', { accountId: 'person1', verifier: await argon2.hash(randomBytes(32).toString('hex')) });
  await write('issuer.json', { version: 1, accountId: 'person1', origin,
    jwks: { keys: [{ ...key, kid: 'fixture', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('hex')], clientId: CHATGPT_CIMD_ID,
    redirectUris: [CHATGPT_CIMD_REDIRECT], clientRegistration: 'chatgpt-cimd' });
  await write('revocations.json', { revoked_principals: [], revoked_tokens: [] });
  for (const preapprove of [false, true]) {
    const reserve = createServer();
    await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
    const port = reserve.address().port;
    await new Promise(resolve => reserve.close(resolve));
    const config = { public_origin: origin, issuer_mode: 'self-hosted', issuer_exposure: 'public-proxy',
      issuer_state_dir: directory, audience: origin + '/mcp', principal: 'person1', owner: 'person1',
      clientId: CHATGPT_CIMD_ID, redirectUris: [CHATGPT_CIMD_REDIRECT], clientRegistration: 'chatgpt-cimd',
      issuer_preapprove_chatgpt: preapprove, bridge_config: '/unused-fixture', port,
      revocation_file: join(directory, 'revocations.json'), issuer_public_proxy: { origin,
        acknowledge_tls_terminator_and_loopback_exclusivity: true, require_parsed_x_forwarded_proto_https: true } };
    gateway = createGateway(config);
    await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
    const request = (path, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path, method,
        headers: { host: 'workrelay.example.test', 'x-forwarded-proto': 'https', ...headers } }, res => {
        let body = ''; res.on('data', chunk => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', reject); req.end();
    });
    for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
      const get = await request(path), head = await request(path, 'HEAD');
      assert.equal(get.status, 200); assert.equal(head.status, 200); assert.equal(head.body, '');
      assert.deepEqual(JSON.parse(get.body).scopes_supported, preapprove ? ['workrelay:tasks', 'openid'] : ['openid', 'offline_access']);
      assert.equal(Number(get.headers['content-length']), Buffer.byteLength(get.body));
      for (const name of ['content-length', 'content-type', 'cache-control', 'etag', 'vary'])
        assert.equal(head.headers[name], get.headers[name], name);
      for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) assert.equal((await request(path, method)).status, 405);
      for (const headers of [{ host: 'wrong.example.test' }, { origin: 'https://wrong.example.test' },
        { 'x-forwarded-proto': 'http' }, { forwarded: 'proto=https' }])
        assert.equal((await request(path, 'HEAD', headers)).status, 400);
    }
    assert.equal((await request('/jwks', 'HEAD')).status, 405);
    assert.equal((await request('/token', 'HEAD')).status, 405);
    assert.notEqual((await request('/mcp', 'HEAD')).status, 200);
    await stop();
  }
});

test('production local-only loopback gateway requires provisioned state and rejects proxy claims', async t => {
  // Private issuer/config reads reject writable ancestors such as macOS tmpdir.
  const directory = await fs.mkdtemp(join(dirname(fileURLToPath(import.meta.url)), '.workrelay-issuer-mcp-'));
  let probe, activeGateway, cli, publicCli, cimdCli;
  t.after(async () => {
    // One teardown owner: stop all child writers before removing private
    // SQLite/issuer files, even when an assertion aborts the test halfway.
    let stopErrors = 0;
    const children = [cimdCli, publicCli, cli].filter(Boolean);
    for (const child of children) {
      try { await stopChild(child); }
      catch { stopErrors++; child.kill('SIGKILL'); }
    }
    if (children.some(child => child.exitCode === null && child.signalCode === null))
      assert.fail('fixture child still running; refusing to remove active issuer state');
    for (const server of [activeGateway, probe]) {
      if (server?.listening) await new Promise(resolve => {
        server.close(resolve);
        server.closeAllConnections?.();
      });
    }
    await fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    await assert.rejects(fs.lstat(directory), { code: 'ENOENT' }, 'no issuer fixture remains after teardown');
    assert.equal(stopErrors, 0, 'fixture child exit must be confirmed before teardown');
  });
  await fs.chmod(directory, 0o700);
  const phase = name => process.stderr.write(`issuer fixture phase: ${name}\n`);
  phase('private setup');
  async function availablePort() {
    const reserve = createServer();
    await new Promise((resolve, reject) => {
      reserve.once('error', reject);
      reserve.listen(0, '127.0.0.1', resolve);
    });
    const selected = reserve.address().port;
    await new Promise(resolve => reserve.close(resolve));
    return selected;
  }
  let port = await availablePort();
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
  probe = createGateway(readPrivateConfig(configPath)); // ordinary private-file startup
  assert.throws(() => probe.listen(port, '0.0.0.0'), /loopback binding/);
  assert.throws(() => probe.listen(port, '::'), /loopback binding/);
  assert.throws(() => probe.listen(port), /loopback binding/);
  let bound = false;
  for (let attempt = 0; attempt < 4 && !bound; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        probe.once('error', reject);
        probe.listen(port, '::1', resolve);
      });
      bound = true;
    } catch (error) {
      if (error.code !== 'EADDRINUSE' || attempt === 3) throw error;
      // Port 0 is advisory once its reservation closes. Retry only on the
      // proven bind collision, before any test request or provider state.
      port = await availablePort();
      config.port = port;
      await fs.writeFile(configPath, JSON.stringify(config));
      probe = createGateway(readPrivateConfig(configPath));
    }
  }
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
  phase('gateway listening');
  activeGateway = gateway;
  const base = `http://127.0.0.1:${port}`;
  const jar = new Map();
  let publicMode = false;
  let parsedProxyMode = false;
  async function request(path, { method = 'GET', headers = {}, body, cookies = true, timeoutMs } = {}) {
    const output = await new Promise((resolve, reject) => {
      const req = httpRequest(base + path, { method, agent: false, headers: {
        host: publicMode ? 'workrelay.example.test' : `127.0.0.1:${port}`,
        ...(parsedProxyMode ? { 'x-forwarded-proto': 'https' } : {}),
        ...(cookies ? { cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; ') } : {}), ...headers,
        ...(body !== undefined ? { 'content-length': Buffer.byteLength(body.toString()) } : {}),
      } }, res => { let text = '';
        res.on('data', chunk => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
      });
      req.setTimeout(timeoutMs ?? 12000, () => req.destroy(Error('fixture request timeout')));
      req.on('error', reject); req.end(body?.toString());
    });
    for (const set of output.headers['set-cookie'] ?? []) {
      const [name, value] = set.split(';', 1)[0].split('=');
      if (value) jar.set(name, value); else jar.delete(name);
    }
    return { response: { status: output.status, headers: { get: key => output.headers[key] } }, text: output.text };
  }
  const safeJson = (text, label) => {
    try { return JSON.parse(text); }
    catch { assert.fail(`${label}: invalid JSON response`); }
  };
  const safeUrl = (value, relativeBase, label) => {
    if (typeof value !== 'string' || !value) assert.fail(`${label}: missing redirect URL`);
    try { return new URL(value, relativeBase); }
    catch { assert.fail(`${label}: invalid redirect URL`); }
  };
  function observeChild(child) {
    let stderrClass = 'none', processError = 'none';
    child.stderr.on('data', chunk => {
      // Classify, never print or retain raw stderr (which could include state,
      // cookie or token contents if a future provider version changes logs).
      const text = chunk.toString();
      if (/EADDRINUSE/.test(text)) stderrClass = 'address-in-use';
      else if (/issuer.*unavailable|private.*unavailable/i.test(text)) stderrClass = 'private-state-unavailable';
      else if (/Error|ERR_|failed|denied/i.test(text) &&
          !['address-in-use', 'private-state-unavailable'].includes(stderrClass)) stderrClass = 'error-other';
      else if (stderrClass === 'none') stderrClass = 'notice-only';
    });
    child.on('error', error => { processError = ['EACCES', 'ENOENT', 'EADDRINUSE'].includes(error.code) ?
      error.code : 'spawn-error-other'; });
    return () => ({ stderrClass, processError });
  }
  async function waitForGateway(child, diagnostics, label) {
    let lastStatus = 'no-response';
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && child.exitCode === null && child.signalCode === null) {
      try {
        const result = await request('/jwks', { timeoutMs: 2000 });
        lastStatus = result.response.status;
        if (lastStatus === 200) return;
      } catch { lastStatus = 'transport-unavailable'; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const { stderrClass, processError } = diagnostics();
    assert.fail(`${label} readiness failed: HTTP=${lastStatus}; exit=${child.exitCode ?? 'none'}; ` +
      `signal=${child.signalCode ?? 'none'}; stderr=${stderrClass}; process=${processError}`);
  }
  async function stopChild(child) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve, reject) => {
      const forced = setTimeout(() => child.kill('SIGKILL'), 3000);
      const deadline = setTimeout(() => reject(Error('fixture child did not exit after SIGKILL')), 5000);
      child.once('exit', () => { clearTimeout(forced); clearTimeout(deadline); resolve(); });
      child.kill('SIGTERM');
    });
  }
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'http' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'https' } })).response.status, 400,
    'local-only cannot opt into tunnel header trust');
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
  assert.equal(jwks.response.status, 200, 'JWKS discovery status');
  phase('request validation complete');
  assert.equal(safeJson(jwks.text, 'JWKS').keys[0].d, undefined);
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
  assert.equal(started.response.status, 303, 'authorization redirect status');
  let location = safeUrl(started.response.headers.get('location'), base, 'authorization');
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
  assert.equal(next.response.status, 303, 'synthetic login status');
  location = safeUrl(next.response.headers.get('location'), base, 'login');
  next = await request(location.pathname + location.search);
  assert.equal(next.response.status, 303, 'login interaction redirect status');
  location = safeUrl(next.response.headers.get('location'), base, 'interaction');
  next = await request(location.pathname);
  assert.equal(next.response.status, 200, 'consent page status');
  next = await post(location.pathname, hidden(next.text), { decision: 'approve' });
  assert.equal(next.response.status, 303, 'consent redirect status');
  location = safeUrl(next.response.headers.get('location'), base, 'consent');
  next = await request(location.pathname + location.search);
  const callback = safeUrl(next.response.headers.get('location'), undefined, 'authorization callback');
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
      assert.equal(step.response.status, 303, 'authorization step redirect status');
      const nextUrl = safeUrl(step.response.headers.get('location'), base, 'fresh authorization');
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
  assert.equal(exchanged.response.status, 200, 'synthetic token exchange status');
  const token = safeJson(exchanged.text, 'synthetic token exchange').access_token;
  assert.ok(token);
  const payload = safeJson(Buffer.from(token.split('.')[1], 'base64url').toString(), 'synthetic JWT payload');
  assert.equal(payload.iss, origin);
  assert.equal(payload.aud, origin + '/mcp');
  assert.equal(payload.sub, 'person1');
  const mcp = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${token}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: 'workrelay_status', arguments: { key: 'task1' } } }) });
  assert.equal(mcp.response.status, 200, 'synthetic MCP status');
  assert.ok(/task1/.test(mcp.text), 'synthetic MCP response includes owned task');
  phase('OAuth and MCP complete');
  async function restartGateway() {
    await new Promise(resolve => activeGateway.close(resolve));
    activeGateway = createGateway(readPrivateConfig(configPath), {
      invoke: async (_config, action, args) => ({ action, key: args.key }) });
    await new Promise((resolve, reject) => {
      activeGateway.once('error', reject);
      activeGateway.listen(port, '127.0.0.1', resolve);
    });
  }
  async function verifyPersistedAdmission(label, makeRequest, refill) {
    // Quotas are minute-windowed. A full integration suite can straddle a
    // boundary; re-exhaust the *new* window instead of treating expiry as a
    // failed durability check. Every actual same-window restart must deny.
    for (let attempt = 0; attempt < 3; attempt++) {
      const probeBefore = Math.floor(Date.now() / 60000);
      const probe = await makeRequest();
      const probeAfter = Math.floor(Date.now() / 60000);
      if (probeBefore !== probeAfter) {
        await refill();
        continue;
      }
      if (probe.response.status !== 429) {
        assert.ok((await refill()).includes(429), `${label}: must exhaust the current window`);
        continue;
      }
      await restartGateway();
      const resumedBefore = Math.floor(Date.now() / 60000);
      const resumed = await makeRequest();
      const resumedAfter = Math.floor(Date.now() / 60000);
      if (resumedBefore !== probeAfter || resumedAfter !== probeAfter) {
        await refill();
        continue;
      }
      assert.equal(resumed.response.status, 429, `${label}: quota must persist across restart`);
      return;
    }
    assert.fail(`${label}: minute window rotated during every bounded durability attempt`);
  }
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
  phase('quota flood complete');
  await verifyPersistedAdmission('token', () => request('/token', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded' }, body: 'client_id=approved-client' }),
  () => hammer('/token', 40));
  await verifyPersistedAdmission('revocation', () => request('/token/revocation', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded' }, body: 'token=synthetic-invalid-token' }),
  () => hammer('/token/revocation', 20));
  const flood = [];
  for (let n = 0; n < 64; n += 4)
    flood.push(...await Promise.all(Array.from({ length: 4 }, () => request(auth()))));
  assert.ok(flood.some(item => item.response.status === 429), 'actual provider admission must return 429');
  assert.ok(flood.every(item => [303, 429].includes(item.response.status)),
    'capacity errors must not leak as provider exceptions');
  const sizes = await Promise.all(['', '-wal', '-shm'].map(async suffix =>
    (await fs.stat(join(directory, 'issuer.sqlite' + suffix)).catch(() => ({ size: 0 }))).size));
  t.diagnostic(`issuer DB/WAL/SHM bytes after HTTP flood: ${sizes.join('/')}`);
  assert.ok(sizes.reduce((sum, size) => sum + size, 0) < 96 * 1024 * 1024,
    'measure DB, WAL and SHM together');
  await verifyPersistedAdmission('authorization', () => request(auth()), async () => {
    const statuses = [];
    for (let n = 0; n < 64; n += 4)
      statuses.push(...(await Promise.all(Array.from({ length: 4 }, () => request(auth()))))
        .map(item => item.response.status));
    return statuses;
  });
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
  phase('CLI restart preparation complete');
  cli = spawn(process.execPath, ['src/workrelay/mcp.mjs', configPath],
    { cwd: process.cwd(), stdio: ['ignore', 'ignore', 'pipe'] });
  const cliDiagnostics = observeChild(cli);
  await waitForGateway(cli, cliDiagnostics, 'ordinary local-only CLI');
  phase('CLI ready');
  jar.clear(); // new synthetic browser with no prior login or consent cookie
  const cliFlow = await freshCode({ trackPrompts: true });
  assert.equal(cliFlow.sawLogin, true, 'spawned CLI must show login');
  assert.equal(cliFlow.sawConsent, true, 'spawned CLI must show explicit consent');
  const cliExchange = await exchange(cliFlow.code, origin + '/mcp');
  assert.equal(cliExchange.response.status, 200, 'spawned CLI token exchange status');
  const cliToken = safeJson(cliExchange.text, 'spawned CLI exchange').access_token;
  assert.ok(cliToken);
  const profile = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${cliToken}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'workrelay_profile', arguments: {} } }) });
  assert.equal(profile.response.status, 200, 'spawned CLI MCP profile status');
  assert.ok(/person1/.test(profile.text), 'spawned CLI MCP profile includes synthetic principal');
  await stopChild(cli);
  // A separate operator-only opt-in; every request remains local synthetic
  // HTTP, never proof of a public TLS terminator or actual ChatGPT client.
  const publicConfig = { ...config, issuer_exposure: 'public-proxy',
    issuer_public_proxy: { origin, acknowledge_tls_terminator_and_loopback_exclusivity: true },
    issuer_origin_diagnostic: { enabled: true, arm_file: join(directory, 'origin-post.arm') },
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
  publicCli = spawn(process.execPath, ['src/workrelay/mcp.mjs', publicConfigPath],
    { cwd: process.cwd(), stdio: ['ignore', 'ignore', 'pipe'] });
  const publicDiagnostics = observeChild(publicCli);
  await waitForGateway(publicCli, publicDiagnostics, 'ordinary public-proxy CLI');
  const diagnosticArm = join(directory, 'origin-post.arm');
  const diagnosticUsed = join(directory, 'origin-post.used');
  const diagnosticReceipt = join(directory, 'origin-post.receipt.json');
  const armDiagnostic = async () => {
    const attemptId = randomBytes(16).toString('hex');
    await fs.writeFile(diagnosticArm,
      JSON.stringify({ expiresAt: Date.now() + 60000, attemptId }), { mode: 0o600, flag: 'wx' });
    return attemptId;
  };
  const diagnosticResult = async () => {
    for (let attempt = 0; attempt < 20; attempt++) {
      try { return safeJson(await fs.readFile(diagnosticReceipt, 'utf8'), 'categorical origin receipt'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail('one-shot diagnostic receipt missing');
  };
  const nullAttempt = await armDiagnostic();
  assert.equal((await request('/interaction/synthetic', { method: 'POST', headers: {
    origin: 'null', 'content-type': 'application/x-www-form-urlencoded',
  }, body: 'csrf=synthetic' })).response.status, 400);
  assert.deepEqual(await diagnosticResult(), { attemptId: nullAttempt, origin: 'null', refererOriginMatch: false,
    secFetchSite: 'absent', hostMatch: true, status: 400, stage: 'outer', rejectionClass: 'origin' });
  await fs.unlink(diagnosticUsed); await fs.unlink(diagnosticReceipt);
  const canonicalAttempt = await armDiagnostic();
  assert.equal((await request('/interaction/synthetic', { method: 'POST', headers: {
    origin, 'content-type': 'application/x-www-form-urlencoded',
  }, body: 'csrf=synthetic' })).response.status, 403);
  assert.deepEqual(await diagnosticResult(), { attemptId: canonicalAttempt, origin: 'equal', refererOriginMatch: false,
    secFetchSite: 'absent', hostMatch: true, status: 403, stage: 'interaction', rejectionClass: 'none' });
  await fs.unlink(diagnosticUsed); await fs.unlink(diagnosticReceipt);
  assert.equal((await request('/jwks', { headers: { host: `127.0.0.1:${port}` } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-for': '198.51.100.17' } })).response.status, 400,
    'public-proxy without XFF opt-in still rejects forwarding metadata');
  assert.equal((await request('/jwks', { headers: { forwarded: 'for=127.0.0.1;proto=https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { origin: 'https://wrong.example.test' } })).response.status, 400);
  const rawStatus = async requestText => new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    let output = '';
    socket.setTimeout(5000, () => { socket.destroy(); reject(Error('raw boundary timed out')); });
    socket.once('connect', () => socket.write(requestText));
    socket.on('data', chunk => {
      output += chunk;
      if (output.includes('\r\n')) { socket.destroy(); resolve(Number(/^HTTP\/1\.1 (\d+)/.exec(output)?.[1])); }
    });
    socket.once('error', reject);
  });
  const checkGatewayClass = async (headers, expected, expectedOrigin = 'absent') => {
    const id = await armDiagnostic();
    const result = await rawStatus(`POST /interaction/synthetic HTTP/${headers ? '1.1' : '1.0'}\r\n${headers}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    assert.equal(result, 400);
    const receipt = await diagnosticResult();
    assert.equal(receipt.attemptId, id);
    assert.equal(receipt.rejectionClass, expected);
    assert.equal(receipt.origin, expectedOrigin);
    assert.equal(receipt.stage, 'outer');
    await fs.unlink(diagnosticUsed); await fs.unlink(diagnosticReceipt);
  };
  await checkGatewayClass('', 'host');
  await checkGatewayClass('Host: workrelay.example.test\r\nHost: workrelay.example.test\r\n', 'host');
  await checkGatewayClass('Host: workrelay.example.test\r\nOrigin: https://wrong.example.test\r\nOrigin: https://workrelay.example.test\r\n', 'origin', 'other');
  await checkGatewayClass('Host: workrelay.example.test\r\nContent-Type: text/plain\r\nContent-Type: text/plain\r\n', 'framing');
  await checkGatewayClass('Host: workrelay.example.test\r\nX-Forwarded-For: 198.51.100.17\r\n', 'forwarding');
  await checkGatewayClass('Host: workrelay.example.test\r\nOrigin: https://wrong.example.test\r\n', 'origin', 'other');
  await checkGatewayClass('Host: workrelay.example.test\r\nOrigin: https://wrong.example.test\r\nX-Forwarded-For: 198.51.100.17\r\n', 'forwarding', 'other');
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nHost: workrelay.example.test\r\n\r\n'), 400);
  assert.equal(await rawStatus('POST /token HTTP/1.1\r\nHost: workrelay.example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n'), 400);
  assert.equal(await rawStatus('GET http://wrong.example.test/jwks HTTP/1.1\r\nHost: workrelay.example.test\r\n\r\n'), 400);
  const publicMetadata = await request('/.well-known/oauth-protected-resource/mcp');
  assert.equal(publicMetadata.response.status, 200);
  assert.equal(safeJson(publicMetadata.text, 'protected resource metadata').resource, origin + '/mcp');
  assert.deepEqual(safeJson(publicMetadata.text, 'protected resource metadata').authorization_servers, [origin]);
  const discovery = await request('/.well-known/oauth-authorization-server');
  assert.equal(safeJson(discovery.text, 'issuer discovery').issuer, origin);
  assert.equal(safeJson(discovery.text, 'issuer discovery').authorization_response_iss_parameter_supported, true);
  const rejectedResource = await request(auth('approved-client', 'https://wrong.example.test/mcp'));
  assert.doesNotMatch(rejectedResource.response.headers.get('location') ?? '', /[?&]code=/);
  const rejectedLocation = rejectedResource.response.headers.get('location');
  assert.equal(rejectedResource.response.status, 303);
  assert.ok(rejectedLocation?.startsWith(redirect));
  assert.equal(safeUrl(rejectedLocation, undefined, 'resource error').searchParams.get('iss'), origin);
  assert.notEqual((await request(auth('unregistered-client'))).response.status, 303);
  assert.doesNotMatch((await request(auth().replace(encodeURIComponent(redirect),
    encodeURIComponent('https://wrong.example.test/callback')))).response.headers.get('location') ?? '',
  /wrong\.example\.test/);
  jar.clear();
  const publicFlow = await freshCode({ trackPrompts: true });
  assert.equal(publicFlow.sawLogin, true);
  assert.equal(publicFlow.sawConsent, true);
  const publicExchange = await exchange(publicFlow.code, origin + '/mcp');
  assert.equal(publicExchange.response.status, 200, 'public-proxy token exchange status');
  const publicToken = safeJson(publicExchange.text, 'public-proxy exchange').access_token;
  assert.ok(publicToken);
  assert.equal((await request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} }) })).response.status, 401);
  const publicProfile = await request('/mcp', { method: 'POST', headers: {
    authorization: `Bearer ${publicToken}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/call',
    params: { name: 'workrelay_profile', arguments: {} } }) });
  assert.equal(publicProfile.response.status, 200, 'public-proxy MCP profile status');
  assert.ok(/person1/.test(publicProfile.text), 'public-proxy MCP profile includes synthetic principal');
  await fs.writeFile(publicConfig.revocation_file,
    JSON.stringify({ revoked_principals: ['person1'], revoked_tokens: [] }));
  assert.equal((await request('/jwks')).response.status, 503, 'runtime revocation blocks issuer routes');
  await stopChild(publicCli);
  // Offline switch of this disposable fixture; ordinary spawned CLI, real
  // oidc-provider and real SQLite adapter. Only its outgoing client-document
  // fetch is replaced with the exact official-document-shaped local fixture.
  await fs.writeFile(publicConfig.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }));
  await fs.writeFile(settingsPath, JSON.stringify({ ...issuerSettings, clientId: CHATGPT_CIMD_ID,
    redirectUris: [CHATGPT_CIMD_REDIRECT], clientRegistration: 'chatgpt-cimd' }));
  const cimdConfig = { ...publicConfig,
    issuer_public_proxy: { ...publicConfig.issuer_public_proxy,
      require_parsed_x_forwarded_proto_https: true, discard_validated_x_forwarded_for: true }, clientId: CHATGPT_CIMD_ID,
    redirectUris: [CHATGPT_CIMD_REDIRECT], clientRegistration: 'chatgpt-cimd' };
  await fs.writeFile(publicConfigPath, JSON.stringify(cimdConfig));
  const fixturePath = join(directory, 'client-document-fixture.mjs');
  const fixture = { client_id: CHATGPT_CIMD_ID, redirect_uris: [CHATGPT_CIMD_REDIRECT],
    token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    jwks_uri: 'https://chatgpt.com/oauth/jwks.json' };
  await fs.writeFile(fixturePath, `globalThis.fetch = async (url, options) => {
    if (url !== ${JSON.stringify(CHATGPT_CIMD_ID)} || !options.dispatcher || options.redirect !== 'manual')
      throw Error('synthetic outbound fetch denied');
    const response = new Response(${JSON.stringify(JSON.stringify(fixture))},
      { headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: url });
    return response;
  };`, { mode: 0o600 });
  cimdCli = spawn(process.execPath, ['--import', fixturePath, 'src/workrelay/mcp.mjs', publicConfigPath],
    { cwd: process.cwd(), stdio: ['ignore', 'ignore', 'pipe'] });
  parsedProxyMode = true;
  const cimdDiagnostics = observeChild(cimdCli);
  await waitForGateway(cimdCli, cimdDiagnostics, 'ordinary CIMD public-proxy CLI');
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-for': '198.51.100.17' } })).response.status, 200,
    'explicit public-proxy contract admits Cloudflare XFP plus XFF without trusting client identity');
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-for': '198.51.100.17, 2001:db8::1' } })).response.status, 200);
  for (const value of ['', 'unknown', '198.51.100.17,', '198.51.100.17:443', '[2001:db8::1]',
    'fe80::1%lo0', '198.51.100.17 192.0.2.1', Array(9).fill('192.0.2.1').join(','), '1'.repeat(513)]) {
    assert.equal((await request('/jwks', { headers: { 'x-forwarded-for': value } })).response.status, 400,
      'malformed or over-budget XFF rejected');
  }
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 192.0.2.1\r\nx-FoRwArDeD-fOr: 192.0.2.2\r\n\r\n'), 400);
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nX-Forwarded-For: 192.0.2.1\r\n\r\n'), 400,
    'XFF cannot substitute for required HTTPS proto');
  for (const address of ['127.0.0.1', '198.51.100.17', '2001:db8::1']) {
    const challenge = await request('/mcp', { method: 'POST', headers: {
      'x-forwarded-for': address, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 24, method: 'tools/list', params: {} }) });
    assert.equal(challenge.response.status, 401, 'forged client address never grants authorization');
    assert.ok(challenge.response.headers.get('www-authenticate')?.includes('Bearer'));
  }
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'HTTPS' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'http' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'https,https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-proto': 'https http' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-forwarded-host': 'workrelay.example.test' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { forwarded: 'proto=https' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { 'x-real-ip': '127.0.0.1' } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { host: `127.0.0.1:${port}` } })).response.status, 400);
  assert.equal((await request('/jwks', { headers: { origin: 'https://wrong.example.test' } })).response.status, 400);
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\n\r\n'), 400,
    'explicit tunnel contract requires a parsed proto header');
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nX-Forwarded-Proto: https\r\nX-fOrWaRdEd-PrOtO: https\r\n\r\n'), 400,
    'duplicates count regardless of raw header-name casing');
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nX-fOrWaRdEd-PrOtO: https\r\n\r\n'), 200);
  assert.equal(await rawStatus('GET /jwks HTTP/1.1\r\nHost: workrelay.example.test\r\nX-Forwarded-Proto:  https \r\n\r\n'), 200,
    'Node normalizes surrounding OWS before parsed-header admission');
  assert.equal(await rawStatus('POST /token HTTP/1.1\r\nHost: workrelay.example.test\r\nX-Forwarded-Proto: https\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n'), 400);
  const cimdDiscovery = safeJson((await request('/.well-known/oauth-authorization-server')).text,
    'CIMD issuer discovery');
  assert.equal(cimdDiscovery.client_id_metadata_document_supported, true);
  assert.deepEqual(cimdDiscovery.token_endpoint_auth_methods_supported, ['none']);
  assert.equal(cimdDiscovery.authorization_response_iss_parameter_supported, true);
  assert.ok(cimdDiscovery.code_challenge_methods_supported.includes('S256'));
  assert.equal((await request('/mcp', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 23, method: 'tools/list', params: {} }) })).response.status,
  401, 'parsed proto never substitutes for an OAuth bearer token');
  const cimdAuth = (client = CHATGPT_CIMD_ID, target = origin + '/mcp') =>
    auth(client, target).replace(encodeURIComponent(redirect), encodeURIComponent(CHATGPT_CIMD_REDIRECT));
  assert.notEqual((await request(cimdAuth('https://127.0.0.1/private'))).response.status, 303,
    'private-address metadata cannot be fetched');
  const cimdWrong = await request(cimdAuth(CHATGPT_CIMD_ID, 'https://wrong.example.test/mcp'));
  assert.equal(cimdWrong.response.status, 303);
  assert.equal(safeUrl(cimdWrong.response.headers.get('location'), undefined,
    'CIMD resource error').searchParams.get('iss'), origin);
  const cimdNoPkce = await request(cimdAuth().replace('&code_challenge=' + challenge + '&code_challenge_method=S256', ''));
  assert.equal(cimdNoPkce.response.status, 303);
  assert.equal(safeUrl(cimdNoPkce.response.headers.get('location'), undefined,
    'CIMD PKCE error').searchParams.get('iss'), origin);
  assert.doesNotMatch((await request(cimdAuth().replace(encodeURIComponent(CHATGPT_CIMD_REDIRECT),
    encodeURIComponent('https://wrong.example.test/redirect')))).response.headers.get('location') ?? '',
  /wrong\.example\.test/);
  jar.clear();
  let step = await request(cimdAuth());
  let sawLogin = false, sawConsent = false, cimdCode, consentAttempt;
  for (let i = 0; i < 12; i++) {
    assert.equal(step.response.status, 303, 'CIMD authorization step redirect status');
    const nextUrl = safeUrl(step.response.headers.get('location'), base, 'CIMD authorization');
    if (nextUrl.origin === 'https://chatgpt.com') {
      assert.equal(nextUrl.pathname, '/connector_platform_oauth_redirect');
      assert.equal(nextUrl.searchParams.get('iss'), origin);
      cimdCode = nextUrl.searchParams.get('code'); break;
    }
    step = await request(nextUrl.pathname + nextUrl.search);
    if (step.response.status === 200 && nextUrl.pathname.startsWith('/interaction/')) {
      const login = step.text.includes('name="password"');
      if (login) sawLogin = true; else sawConsent = true;
      if (!login) {
        consentAttempt = randomBytes(16).toString('hex');
        await fs.writeFile(diagnosticArm, JSON.stringify({ attemptId: consentAttempt,
          expiresAt: Date.now() + 60000, target: 'consent' }), { mode: 0o600, flag: 'wx' });
      }
      step = await post(nextUrl.pathname, hidden(step.text), login ? { password } : { decision: 'approve' });
      if (!login) {
        const captured = await diagnosticResult();
        assert.equal(captured.attemptId, consentAttempt);
        assert.equal(captured.consentRejection, 'none');
        assert.equal(captured.stage, 'interaction');
        assert.equal(captured.status, 303);
      }
    }
  }
  assert.ok(cimdCode && sawLogin && sawConsent, 'fresh synthetic human login and consent issue code');
  const cimdExchange = await request('/token', { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({
    grant_type: 'authorization_code', client_id: CHATGPT_CIMD_ID, code: cimdCode,
    redirect_uri: CHATGPT_CIMD_REDIRECT, code_verifier: verifier, resource: origin + '/mcp',
  }) });
  assert.equal(cimdExchange.response.status, 200, 'CIMD token exchange status');
  const cimdToken = safeJson(cimdExchange.text, 'CIMD exchange').access_token;
  assert.ok(cimdToken);
  const cimdProfile = await request('/mcp', { method: 'POST', headers: {
    'x-forwarded-for': '198.51.100.17',
    authorization: `Bearer ${cimdToken}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25',
  }, body: JSON.stringify({ jsonrpc: '2.0', id: 22, method: 'tools/call',
    params: { name: 'workrelay_profile', arguments: {} } }) });
  assert.equal(cimdProfile.response.status, 200, 'CIMD MCP profile status');
  assert.ok(/person1/.test(cimdProfile.text), 'CIMD MCP profile includes synthetic principal');
  await stopChild(cimdCli);
});
