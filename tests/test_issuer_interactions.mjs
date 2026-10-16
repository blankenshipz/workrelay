import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { createServer, request as httpsRequest } from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import argon2 from 'argon2';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createUnexposedIssuerPolicy, loadPreapprovedChatGPTGrant, createPreapprovalDiagnostic, CHATGPT_CIMD_ID, CHATGPT_CIMD_REDIRECT } from '../src/workrelay/issuer_policy.mjs';

test('preapproval denial recorder is bounded, exclusive, categorical and target-specific', async t => {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-preauth-diagnostic-'));
  await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const arm = join(dir, 'origin-post.arm'), used = join(dir, 'origin-post.used');
  const receipt = join(dir, 'origin-post.receipt.json');
  const record = createPreapprovalDiagnostic(dir);
  const attemptId = randomBytes(16).toString('hex');
  const prepare = (target, expiresAt = Date.now() + 60000) => fs.writeFile(arm,
    JSON.stringify({ target, attemptId, expiresAt }), { mode: 0o600 });
  await prepare('consent'); record('scope_other');
  assert.equal(await fs.access(used).then(() => true, () => false), false);
  await prepare('preapproval', Date.now() - 1); record('scope_other');
  assert.equal(await fs.access(used).then(() => true, () => false), false);
  await prepare('preapproval'); await fs.chmod(arm, 0o644); record('scope_other');
  assert.equal(await fs.access(used).then(() => true, () => false), false);
  await fs.chmod(arm, 0o600); record('PRIVATE_MARKER');
  assert.equal(await fs.access(used).then(() => true, () => false), false);
  await assert.rejects(loadPreapprovedChatGPTGrant({ oidc: {
    account: { accountId: 'synthetic' }, session: { accountId: 'synthetic' },
    client: { clientId: CHATGPT_CIMD_ID }, params: { client_id: CHATGPT_CIMD_ID,
      redirect_uri: CHATGPT_CIMD_REDIRECT, resource: 'https://issuer.example.test/mcp',
      scope: 'openid PRIVATE_MARKER', response_type: 'code' },
  } }, { principal: 'synthetic', resource: 'https://issuer.example.test/mcp', onDenied: record }),
  error => error.error === 'access_denied');
  assert.deepEqual(JSON.parse(await fs.readFile(receipt, 'utf8')),
    { attemptId, stage: 'preapproval', rejectionClass: 'scope_other' });
  assert.equal((await fs.stat(receipt)).mode & 0o777, 0o600);
  await prepare('preapproval'); record('account');
  assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).rejectionClass, 'scope_other');
});

test('preapproval hook rejects account and capability escalation and cannot resurrect referenced revoked grants', async () => {
  let created = 0;
  const principal = 'synthetic-account', resource = 'https://issuer.example.test/mcp';
  const context = () => ({ oidc: { account: { accountId: principal },
    session: { accountId: principal, grantIdFor: () => undefined }, client: { clientId: CHATGPT_CIMD_ID },
    params: { client_id: CHATGPT_CIMD_ID, redirect_uri: CHATGPT_CIMD_REDIRECT, resource,
      scope: 'workrelay:tasks', response_type: 'code' },
    provider: { Grant: class { constructor() { created++; } static async find() { return undefined; } } } } });
  for (const mutate of [
    c => { c.account.accountId = 'wrong'; }, c => { c.session.accountId = 'wrong'; },
    c => { c.account = undefined; }, c => { c.client.clientId = 'wrong'; },
    c => { c.params.client_id = 'wrong'; }, c => { c.params.resource += '/wrong'; },
    c => { c.params.redirect_uri = 'https://wrong.example.test'; },
    c => { c.params.scope += ' openid'; }, c => { c.params.scope = ''; },
    c => { c.params.resource = [resource, 'https://wrong.example.test']; },
    c => { c.session.grantIdFor = () => 'synthetic-revoked'; },
  ]) {
    const ctx = context(); mutate(ctx.oidc);
    await assert.rejects(loadPreapprovedChatGPTGrant(ctx, { principal, resource }),
      error => error.error === 'access_denied');
  }
  assert.equal(created, 0, 'denied requests never create a grant');
  const cases = [
    ['account', c => { c.account = undefined; }],
    ['session', c => { c.session.accountId = 'wrong'; }],
    ['client', c => { c.client.clientId = 'wrong'; }],
    ['client', c => { c.params.client_id = 'wrong'; }],
    ['redirect', c => { c.params.redirect_uri += '/wrong'; }],
    ['resource_absent', c => { delete c.params.resource; }],
    ['resource_array', c => { c.params.resource = []; }],
    ['resource_array', c => { c.params.resource = Array(1); }],
    ['resource_array', c => { c.params.resource = [resource, , resource]; }],
    ['resource_array', c => { c.params.resource = [new String(resource)]; }],
    ['resource_array', c => { c.params.resource = Array(9).fill(resource); }],
    ['resource_array', c => { c.params.resource = [resource, 'https://wrong.example.test']; }],
    ['resource_other', c => { c.params.resource += '/wrong'; }],
    ['scope_absent', c => { delete c.params.scope; }],
    ['scope_other', c => { c.params.scope = 'openid workrelay:tasks'; }],
    ['scope_other', c => { c.params.scope = 'workrelay:tasks profile'; }],
    ['response_type', c => { c.params.response_type = 'token'; }],
  ];
  for (const [expected, mutate] of cases) {
    const ctx = context(); mutate(ctx.oidc);
    const observed = [];
    await assert.rejects(loadPreapprovedChatGPTGrant(ctx, { principal, resource,
      onDenied: category => observed.push(category) }), error => error.error === 'access_denied');
    assert.deepEqual(observed, [expected]);
  }
  assert.equal(created, 0);
  for (const resourceValue of [[resource], [resource, resource]]) {
    const ctx = context(); ctx.oidc.params.resource = resourceValue;
    let saved = false, granted;
    ctx.oidc.provider.Grant = class {
      constructor(input) { assert.deepEqual(input, { accountId: principal, clientId: CHATGPT_CIMD_ID }); }
      addResourceScope(target, scope) { granted = [target, scope]; }
      async save() { saved = true; }
    };
    await loadPreapprovedChatGPTGrant(ctx, { principal, resource });
    assert.equal(saved, true);
    assert.deepEqual(granted, [resource, 'workrelay:tasks']);
  }
});
import { createLocalInteractions, createOriginDiagnostic, provisionLocalHuman } from '../src/workrelay/issuer_interactions.mjs';

test('one-shot origin diagnostic persists categories only and does not decide HTTP authorization', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-origin-diag-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const origin = 'https://issuer.example.test', hostname = 'issuer.example.test';
  const capture = createOriginDiagnostic({ directory, origin, hostname });
  const arm = join(directory, 'origin-post.arm'), receipt = join(directory, 'origin-post.receipt.json');
  const used = join(directory, 'origin-post.used');
  const run = async ({ originValue, status, stage, referer, fetchSite, host = hostname }) => {
    const attemptId = randomBytes(16).toString('hex');
    await fs.writeFile(arm, JSON.stringify({ expiresAt: Date.now() + 60000, attemptId }), { mode: 0o600, flag: 'wx' });
    const req = { method: 'POST', url: '/interaction/test',
      rawHeaders: ['Host', host, ...(originValue === undefined ? [] : ['Origin', originValue])],
      headers: { host, ...(originValue === undefined ? {} : { origin: originValue }),
        referer, 'sec-fetch-site': fetchSite, authorization: 'Bearer SYNTHETIC_PRIVATE_MARKER',
        cookie: 'SYNTHETIC_PRIVATE_MARKER' } };
    const res = new EventEmitter(); res.statusCode = status;
    const observed = capture(req, res);
    assert.ok(observed);
    if (stage === 'interaction') observed.reachedInteraction();
    res.emit('finish');
    const data = JSON.parse(await fs.readFile(receipt, 'utf8'));
    assert.equal((await fs.stat(receipt)).mode & 0o777, 0o600);
    assert.deepEqual(Object.keys(data).sort(),
      ['attemptId', 'hostMatch', 'origin', 'refererOriginMatch', 'secFetchSite', 'stage', 'status', 'rejectionClass'].sort());
    assert.equal(data.attemptId, attemptId);
    assert.equal(JSON.stringify(data).includes('SYNTHETIC_PRIVATE_MARKER'), false);
    assert.equal(JSON.stringify(data).includes('other.example.test'), false);
    assert.equal(JSON.stringify(data).includes('/interaction/test'), false);
    assert.equal(capture(req, res), null, 'one POST consumes the arm');
    await fs.unlink(used); await fs.unlink(receipt);
    const { attemptId: _attemptId, ...categories } = data;
    return categories;
  };
  assert.deepEqual(await run({ originValue: undefined, status: 400, stage: 'outer' }),
    { origin: 'absent', refererOriginMatch: false, secFetchSite: 'absent', hostMatch: true,
      status: 400, stage: 'outer', rejectionClass: 'none' });
  assert.equal((await run({ originValue: 'null', status: 400, stage: 'outer', fetchSite: 'cross-site' })).origin, 'null');
  const accepted = await run({ originValue: origin, status: 403, stage: 'interaction',
    referer: origin + '/interaction/test', fetchSite: 'same-origin' });
  assert.equal(accepted.origin, 'equal');
  assert.equal(accepted.refererOriginMatch, true);
  assert.equal(accepted.secFetchSite, 'same-origin');
  assert.equal((await run({ originValue: 'https://other.example.test', status: 400,
    stage: 'outer', host: 'other.example.test', fetchSite: 'attacker-secret' })).origin, 'other');
  await fs.writeFile(arm, JSON.stringify({ expiresAt: Date.now() + 60000,
    attemptId: randomBytes(16).toString('hex') }), { mode: 0o600 });
  await fs.chmod(arm, 0o644);
  assert.equal(capture({ method: 'POST', url: '/interaction/test', rawHeaders: [], headers: {} },
    new EventEmitter()), null, 'insecure arm fails closed');
  assert.equal(await fs.access(used).then(() => true, () => false), false);
  await fs.unlink(arm);
  await fs.writeFile(arm, JSON.stringify({ expiresAt: Date.now() - 1,
    attemptId: randomBytes(16).toString('hex') }), { mode: 0o600 });
  assert.equal(capture({ method: 'POST', url: '/interaction/test', rawHeaders: [], headers: {} },
    new EventEmitter()), null, 'expired arm does not capture');
});

test('diagnostic claim is exclusive; a failed publication or stale receipt cannot masquerade as a fresh attempt', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-origin-atomic-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const arm = join(directory, 'origin-post.arm'), used = join(directory, 'origin-post.used');
  const receipt = join(directory, 'origin-post.receipt.json');
  const request = { method: 'POST', url: '/interaction/synthetic', rawHeaders: ['Host', 'issuer.example.test'],
    headers: { host: 'issuer.example.test', cookie: 'PRIVATE_MARKER' } };
  const response = () => Object.assign(new EventEmitter(), { statusCode: 400 });
  const armAttempt = async () => {
    const id = randomBytes(16).toString('hex');
    await fs.writeFile(arm, JSON.stringify({ attemptId: id, expiresAt: Date.now() + 60000 }),
      { mode: 0o600, flag: 'wx' });
    return id;
  };
  let interrupted = false;
  const capture = createOriginDiagnostic({ directory, origin: 'https://issuer.example.test',
    hostname: 'issuer.example.test', beforePublish: () => {
      if (!interrupted) { interrupted = true; throw Error('synthetic publication interruption'); }
    } });
  const initial = await armAttempt();
  const first = response(), second = response();
  assert.ok(capture(request, first));
  assert.equal(capture(request, second), null, 'only the first simultaneous POST claims this arm');
  first.emit('finish');
  assert.equal(await fs.access(receipt).then(() => true, () => false), false,
    'interrupted temp is not published as partial JSON');
  assert.deepEqual((await fs.readdir(directory)).sort(), ['origin-post.used']);
  const retryId = await armAttempt();
  assert.notEqual(retryId, initial);
  assert.equal(capture(request, response()), null, 'used marker denies re-arm even without a receipt');
  await fs.unlink(arm); await fs.unlink(used); // simulated deliberate offline cleanup
  const successful = await armAttempt();
  const final = response(); assert.ok(capture(request, final)); final.emit('finish');
  assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).attemptId, successful);
  assert.equal((await fs.stat(receipt)).mode & 0o777, 0o600);
  await fs.unlink(used); // stale receipt still denies a re-arm after incomplete cleanup
  const later = await armAttempt();
  assert.equal(capture(request, response()), null, 'stale receipt denies new attempt');
  assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).attemptId, successful);
  assert.notEqual(later, successful);
});

test('consent-only one-shot records actual rejection branches without values; login cannot consume arm', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-consent-diagnostic-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'synthetic-account',
    verifier: '$argon2id$synthetic-unused' }), { mode: 0o600 });
  const origin = 'https://issuer.example.test', clientId = 'synthetic-client', resource = origin + '/mcp';
  let details, grantFailure = false, throwFailure = false;
  const provider = { interactionDetails: async () => details,
    Grant: class { constructor({ accountId, clientId }) { this.accountId = grantFailure ? 'wrong' : accountId; this.clientId = clientId; }
      addResourceScope() {} async save() { if (throwFailure) throw Error('PRIVATE_MARKER'); return 'synthetic-grant'; } },
    interactionFinished: async (_req, res) => { res.writeHead(303); res.end(); } };
  const capture = createOriginDiagnostic({ directory, origin, hostname: 'issuer.example.test' });
  const handler = createLocalInteractions({ provider, directory, origin, clientId, resource,
    captureConsent: (req, res) => capture(req, res, 'consent') });
  async function call(method, fields = '', headers = {}) {
    const req = Readable.from([fields]);
    Object.assign(req, { method, url: '/interaction/synthetic', socket: { remoteAddress: '127.0.0.1' },
      headers: { host: 'issuer.example.test', origin, 'content-type': 'application/x-www-form-urlencoded', ...headers } });
    req.rawHeaders = Object.entries(req.headers).flat();
    const res = new EventEmitter();
    Object.assign(res, { headers: {}, text: '', statusCode: 200,
      setHeader(name, value) { this.headers[name] = value; },
      writeHead(status, values = {}) { this.statusCode = status; Object.assign(this.headers, values); },
      end(value = '') { this.text += value; this.emit('finish'); } });
    // Same outer invocation as gateway: consent-target arm must not claim here.
    assert.equal(capture(req, res), null);
    await handler(req, res);
    return res;
  }
  for (const category of ['provider_context', 'origin', 'form', 'csrf_session_binding', 'account', 'scope', 'grant', 'caught_failure', 'none']) {
    details = { uid: 'synthetic', params: { client_id: clientId }, prompt: { name: 'consent', details: {} },
      session: { uid: 'synthetic-session', accountId: category === 'account' ? 'wrong' : 'synthetic-account' } };
    grantFailure = category === 'grant'; throwFailure = category === 'caught_failure';
    const page = await call('GET');
    const cookie = page.headers['set-cookie'].split(';')[0];
    const token = page.text.match(/name="csrf" value="([^"]+)"/)[1];
    const attemptId = randomBytes(16).toString('hex');
    await fs.writeFile(join(directory, 'origin-post.arm'), JSON.stringify({ attemptId,
      expiresAt: Date.now() + 60000, target: 'consent' }), { mode: 0o600, flag: 'wx' });
    // A login POST fails Origin but must leave this consent arm available.
    details.prompt.name = 'login';
    assert.equal((await call('POST', '', { origin: 'null' })).statusCode, 403);
    assert.equal(await fs.access(join(directory, 'origin-post.used')).then(() => true, () => false), false);
    details.prompt.name = 'consent';
    if (category === 'provider_context') details.params.client_id = 'wrong';
    if (category === 'scope') details.prompt.details = { missingOIDCScope: ['synthetic-forbidden'] };
    const body = new URLSearchParams({ csrf: category === 'csrf_session_binding' ? 'wrong' : token,
      decision: category === 'form' ? 'invalid' : 'approve' });
    const result = await call('POST', body.toString(), { cookie, origin: category === 'origin' ? 'null' : origin });
    assert.equal(result.statusCode, category === 'none' ? 303 : 403);
    const receipt = JSON.parse(await fs.readFile(join(directory, 'origin-post.receipt.json'), 'utf8'));
    assert.equal(receipt.attemptId, attemptId);
    assert.equal(receipt.consentRejection, category);
    assert.deepEqual(Object.keys(receipt).sort(), ['attemptId','origin','refererOriginMatch','secFetchSite',
      'hostMatch','status','stage','rejectionClass','consentRejection'].sort());
    assert.equal(receipt.stage, 'interaction');
    assert.equal(JSON.stringify(receipt).includes('synthetic'), false);
    assert.equal(JSON.stringify(receipt).includes('PRIVATE_MARKER'), false);
    assert.equal(capture({ method: 'POST', url: '/interaction/synthetic' }, new EventEmitter(), 'consent'), null);
    await fs.unlink(join(directory, 'origin-post.used'));
    await fs.unlink(join(directory, 'origin-post.receipt.json'));
  }
});

for (const registration of ['static', 'chatgpt-cimd', 'chatgpt-preapproved']) test(`${registration}: provisioning refuses non-TTY; actual HTTPS provider interaction requires CSRF, password and consent`, async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-interaction-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  await assert.rejects(provisionLocalHuman({ directory, accountId: 'person1' }), /local TTY/);
  // Synthetic test fixture, not a production provisioning route or password.
  const fixturePassword = randomBytes(32).toString('base64url');
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'person1',
    verifier: await argon2.hash(fixturePassword, { type: argon2.argon2id }) }), { mode: 0o600 });
  const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost',
    '-keyout', join(directory, 'tls.key'), '-out', join(directory, 'tls.crt'), '-days', '1'], { stdio: 'ignore' });
  const origin = 'https://issuer.example.test';
  const preapproveChatGPT = registration === 'chatgpt-preapproved';
  const cimd = registration !== 'static';
  const clientId = cimd ? CHATGPT_CIMD_ID : 'approved-client';
  const redirect = cimd ? CHATGPT_CIMD_REDIRECT : 'https://client.example.test/callback';
  let documentFetches = 0;
  let accountLookups = 0;
  const deniedCategories = [];
  const provider = createUnexposedIssuerPolicy({ origin, principal: 'person1',
    jwks: { keys: [{ ...privateKey, kid: 'test', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')], clientId,
    clientRegistration: cimd ? 'chatgpt-cimd' : 'static', preapproveChatGPT,
    onPreapprovalDenied: category => deniedCategories.push(category),
    ...(cimd ? { fetchClientDocument: async (id, options) => {
      assert.equal(id, CHATGPT_CIMD_ID);
      assert.equal(options.redirect, 'manual');
      assert.ok(options.dispatcher, 'maintained provider supplies restricted dispatcher');
      documentFetches++;
      // Official public metadata shape observed 2026-10-16. Only this network
      // fetch is isolated; policy validation and provider client resolution run.
      return new Response(JSON.stringify({ client_id: CHATGPT_CIMD_ID,
        redirect_uris: [CHATGPT_CIMD_REDIRECT], token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
        jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }),
        { headers: { 'content-type': 'application/json' } });
    } } : {}),
    redirectUris: [redirect], adapter: createIssuerAdapter(directory),
    findAccount: async (_ctx, id) => { accountLookups++;
      return id === 'person1' ? { accountId: id, claims: async () => ({ sub: id }) } : undefined; } });
  let handler = createLocalInteractions({ provider, directory, origin, clientId, resource: origin + '/mcp' });
  const server = createServer({ key: await fs.readFile(join(directory, 'tls.key')),
    cert: await fs.readFile(join(directory, 'tls.crt')) }, async (req, res) => {
    if (!(await handler(req, res))) provider.callback()(req, res);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `https://127.0.0.1:${server.address().port}`;
  const jar = new Map();
  async function request(path, opts = {}) {
    const pathname = new URL(path, base).pathname;
    const cookies = [...jar.values()].filter(cookie =>
      pathname === cookie.path || pathname.startsWith(cookie.path.endsWith('/') ? cookie.path : cookie.path + '/'))
      .sort((a, b) => b.path.length - a.path.length)
      .map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
    const response = await new Promise((resolve, reject) => {
      const call = httpsRequest(base + path, { method: opts.method ?? 'GET', rejectUnauthorized: false,
        headers: { cookie: cookies, ...opts.headers } }, result => {
        let text = '';
        result.on('data', chunk => { text += chunk; });
        result.on('end', () => resolve({ status: result.statusCode, headers: {
          get: key => result.headers[key], getSetCookie: () => result.headers['set-cookie'] ?? [] }, text }));
      });
      call.on('error', reject);
      call.end(opts.body?.toString());
    });
    for (const set of response.headers.getSetCookie()) {
      const [pair, ...attributes] = set.split(';');
      const split = pair.indexOf('='), name = pair.slice(0, split), value = pair.slice(split + 1);
      const attrs = new Map(attributes.map(item => {
        const [key, ...parts] = item.trim().split('='); return [key.toLowerCase(), parts.join('=')];
      }));
      const cookiePath = attrs.get('path') || pathname.slice(0, pathname.lastIndexOf('/') + 1);
      const key = name + ':' + cookiePath;
      if (!value || attrs.get('max-age') === '0') jar.delete(key);
      else jar.set(key, { name, value, path: cookiePath });
    }
    return { response, text: response.text };
  }
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const auth = `/auth?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}` +
    `&scope=workrelay%3Atasks&resource=${encodeURIComponent(origin + '/mcp')}&code_challenge=${challenge}` +
    '&code_challenge_method=S256&state=test';
  let next = await request(auth);
  assert.equal(accountLookups, 0, 'fresh no-cookie request has no authenticated account lookup');
  assert.equal(next.response.status, 303, next.text);
  let url = new URL(next.response.headers.get('location'), base);
  assert.equal(url.pathname.startsWith('/interaction/'), true);
  next = await request(url.pathname);
  assert.equal(next.response.status, 200);
  // Fetch's append-request-Origin algorithm serializes non-CORS POST Origin
  // as null with no-referrer. Same-origin preserves the strict form boundary.
  assert.equal(next.response.headers.get('referrer-policy'), 'same-origin');
  assert.equal(next.response.headers.get('content-security-policy'),
    "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  const hidden = html => html.match(/name="csrf" value="([^"]+)"/)?.[1];
  const first = hidden(next.text);
  assert.ok(first);
  for (const deniedOrigin of [undefined, 'null']) {
    const denied = await request(url.pathname, { method: 'POST', headers: {
      ...(deniedOrigin === undefined ? {} : { origin: deniedOrigin }),
      'sec-fetch-site': 'same-origin', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf: first, password: 'synthetic-never-accepted' }) });
    assert.equal(denied.response.status, 403, 'missing/null Origin is denied despite same-origin fetch-site');
  }
  assert.doesNotMatch(next.text, new RegExp(fixturePassword));
  const post = async (csrf, fields) => request(url.pathname, { method: 'POST', headers: {
    origin, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ csrf, ...fields }) });
  // Serialize successful controls from the emitted HTML, including only the
  // selected submit button. Never include the unclicked Deny button.
  const emittedForm = (html, password) => {
    const attr = tag => new Map([...tag.matchAll(/([\w-]+)="([^"]*)"/g)].map(match => [match[1], match[2]]));
    const formTag = html.match(/<form\b[^>]*>/)?.[0];
    assert.ok(formTag, 'emitted form exists');
    const form = attr(formTag);
    assert.equal(form.get('method'), 'post');
    const action = new URL(form.get('action'), origin);
    assert.equal(action.origin, origin);
    assert.equal(action.pathname, url.pathname, 'emitted action preserves interaction UID');
    const fields = new URLSearchParams();
    for (const tag of html.match(/<input\b[^>]*>/g) ?? []) {
      const input = attr(tag);
      if (input.get('type') === 'hidden') fields.append(input.get('name'), input.get('value'));
      if (input.get('type') === 'password') fields.append(input.get('name'), password);
    }
    const button = attr((html.match(/<button\b[^>]*>/g) ?? [])[0] ?? '');
    assert.equal(button.get('type'), 'submit');
    if (button.has('name')) fields.append(button.get('name'), button.get('value'));
    return { path: action.pathname, fields };
  };
  const submitForm = form => request(form.path, { method: 'POST', headers: {
    origin, referer: origin + form.path, 'sec-fetch-site': 'same-origin',
    'content-type': 'application/x-www-form-urlencoded' }, body: form.fields });
  assert.equal((await post('wrong', { password: fixturePassword })).response.status, 403);
  assert.equal((await post(first, { password: 'incorrect' })).response.status, 403);
  assert.equal((await post(first, { password: fixturePassword })).response.status, 403, 'nonce cannot be replayed');
  assert.equal((await request(url.pathname, { method: 'POST', headers: {
    origin: 'https://untrusted.example.test', 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ csrf: first, password: fixturePassword }) })).response.status, 403);
  // Failures remain locked after reconstructing the handler over the same private database.
  for (let attempt = 0; attempt < 4; attempt++) {
    next = await request(url.pathname);
    assert.equal((await post(hidden(next.text), { password: 'incorrect' })).response.status, 403);
  }
  handler = createLocalInteractions({ provider, directory, origin, clientId, resource: origin + '/mcp' });
  next = await request(url.pathname);
  assert.equal((await post(hidden(next.text), { password: fixturePassword })).response.status, 429);
  // Reset only the synthetic test's rate row to exercise the success/consent path.
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(join(directory, 'interactions.sqlite'));
  db.prepare('DELETE FROM attempts WHERE account=?').run('person1'); db.close();
  next = await request(url.pathname);
  next = await submitForm(emittedForm(next.text, fixturePassword));
  assert.equal(next.response.status, 303);
  // Resume provider authorization after login, which must prompt for consent.
  url = new URL(next.response.headers.get('location'), base);
  next = await request(url.pathname + url.search);
  assert.equal(next.response.status, 303);
  if (preapproveChatGPT) {
    const callback = new URL(next.response.headers.get('location'));
    assert.equal(callback.origin + callback.pathname, redirect, 'preapproved login goes directly to exact callback');
    assert.equal(callback.searchParams.has('code'), true);
    assert.equal(callback.searchParams.get('state'), 'test');
    assert.ok(documentFetches > 0);
    // Real provider normalization, after authentication and with its existing
    // session/grant. Duplicate scope tokens normalize to the same capability.
    const repeatedScope = await request(auth.replace('workrelay%3Atasks', 'workrelay%3Atasks%20workrelay%3Atasks'));
    assert.equal(new URL(repeatedScope.response.headers.get('location')).searchParams.has('code'), true);
    // Repeated resource parameters are retained as an array by the provider,
    // even when they name only the same server. Equivalent targets may not
    // introduce a new scope, account or audience.
    deniedCategories.length = 0;
    const repeatedResource = await request(auth + '&resource=' + encodeURIComponent(origin + '/mcp'));
    assert.equal(new URL(repeatedResource.response.headers.get('location')).searchParams.has('code'), true);
    assert.deepEqual(deniedCategories, []);
    const code = new URL(repeatedResource.response.headers.get('location')).searchParams.get('code');
    const tokenBody = new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
      redirect_uri: redirect, code, code_verifier: verifier });
    tokenBody.append('resource', origin + '/mcp');
    const duplicateTokenBody = new URLSearchParams(tokenBody);
    duplicateTokenBody.set('code', callback.searchParams.get('code'));
    duplicateTokenBody.append('resource', origin + '/mcp');
    const duplicateExchange = await request('/token', { method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded' }, body: duplicateTokenBody });
    assert.equal(duplicateExchange.response.status, 400, 'provider requires a single token resource target');
    const exchanged = await request('/token', { method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded' }, body: tokenBody });
    assert.equal(exchanged.response.status, 200, 'real repeated-resource authorization code exchanges with PKCE');
    let token;
    try { token = JSON.parse(exchanged.text).access_token; } catch { assert.fail('token response JSON invalid'); }
    assert.equal(typeof token, 'string', 'access token issued');
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    assert.equal(claims.aud, origin + '/mcp');
    assert.equal(claims.scope, 'workrelay:tasks');
    assert.equal(claims.sub, 'person1');
    for (const invalid of [
      auth.replace('workrelay%3Atasks', 'openid'),
      auth.replace(encodeURIComponent(origin + '/mcp'), encodeURIComponent('https://wrong.example.test/mcp')),
      auth.replace(encodeURIComponent(redirect), encodeURIComponent('https://wrong.example.test/callback')),
      auth.replace(clientId, 'https://wrong.example.test/client.json'),
      auth.replace(/&code_challenge=[^&]+&code_challenge_method=S256/, ''),
    ]) {
      const rejected = await request(invalid);
      const location = rejected.response.headers.get('location');
      assert.equal(location ? new URL(location, base).searchParams.has('code') : false, false,
        'out-of-policy authorization never issues a code');
      assert.ok([303, 400, 403].includes(rejected.response.status));
    }
    return;
  }
  url = new URL(next.response.headers.get('location'), base);
  next = await request(url.pathname);
  assert.equal(next.response.status, 200);
  assert.match(next.text, /Authorize/);
  assert.equal(next.response.headers.get('referrer-policy'), 'same-origin', 'consent forms use the same policy');
  assert.match(next.text, /renewable access through refresh tokens/);
  assert.match(next.text, /No self-service revoke page exists/);
  assert.match(next.text, /access tokens can remain valid for up to five minutes/);
  const consentNonce = hidden(next.text);
  assert.equal((await post(consentNonce, { decision: 'unexpected' })).response.status, 403);
  next = await request(url.pathname);
  const approveForm = emittedForm(next.text);
  const hostileForm = { ...approveForm, fields: new URLSearchParams(approveForm.fields) };
  hostileForm.fields.set('csrf', 'synthetic-wrong-csrf');
  assert.equal((await submitForm(hostileForm)).response.status, 403, 'emitted consent with hostile CSRF denied');
  next = await submitForm(approveForm);
  assert.equal(next.response.status, 303);
  assert.equal((await submitForm(approveForm)).response.status, 403, 'consent form replay denied');
  url = new URL(next.response.headers.get('location'), base);
  next = await request(url.pathname + url.search);
  assert.equal(next.response.status, 303);
  const callback = new URL(next.response.headers.get('location'));
  assert.equal(callback.origin + callback.pathname, redirect, 'exact allowlisted callback');
  assert.equal(callback.searchParams.has('code'), true, 'callback contains code, never printed');
  if (cimd) assert.ok(documentFetches > 0, 'CIMD dynamic resolution exercised, not static client fallback');
});

test('separate processes reserve at most five concurrent verifications in one private database', async t => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'workrelay-lockout-'));
  await fs.chmod(directory, 0o700);
  t.after(() => fs.rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const fixturePassword = randomBytes(32).toString('base64url');
  await fs.writeFile(join(directory, 'human.json'), JSON.stringify({ accountId: 'person1',
    verifier: await argon2.hash(fixturePassword, { type: argon2.argon2id }) }), { mode: 0o600 });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost',
    '-keyout', join(directory, 'tls.key'), '-out', join(directory, 'tls.crt'), '-days', '1'], { stdio: 'ignore' });
  const moduleUrl = new URL('../src/workrelay/issuer_interactions.mjs', import.meta.url).href;
  const worker = `import { createLocalInteractions } from ${JSON.stringify(moduleUrl)};
    import { createServer } from 'node:https';
    import { readFileSync } from 'node:fs';
    import { join } from 'node:path';
    const directory = process.argv[1];
    const provider = { interactionDetails: async req => ({ uid: req.url.split('/')[2],
      params: { client_id: 'approved-client' }, session: { uid: 'session' }, prompt: { name: 'login' } }),
      interactionFinished: async (_req, res) => { res.writeHead(303, { location: '/done' }); res.end(); } };
    const handler = createLocalInteractions({ provider, directory, origin: 'https://issuer.example.test',
      clientId: 'approved-client', resource: 'https://issuer.example.test/mcp' });
    const server = createServer({ key: readFileSync(join(directory, 'tls.key')),
      cert: readFileSync(join(directory, 'tls.crt')) }, (req, res) => handler(req, res));
    server.listen(0, '127.0.0.1', () => process.stdout.write(server.address().port + '\\n'));`;
  const children = [];
  t.after(() => { for (const child of children) child.kill(); });
  async function start() {
    const child = spawn(process.execPath, ['--input-type=module', '-e', worker, directory],
      { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    const port = await new Promise((resolve, reject) => {
      let output = '';
      child.stdout.on('data', chunk => {
        output += chunk;
        if (output.includes('\n')) resolve(Number(output.trim()));
      });
      child.once('error', reject);
      child.once('exit', code => reject(Error(`lockout worker exited ${code}`)));
    });
    assert.ok(port > 0);
    return { child, port };
  }
  async function http(port, uid, { method = 'GET', cookie = '', csrf = '' } = {}) {
    const form = new URLSearchParams({ csrf, password: 'incorrect' }).toString();
    return new Promise((resolve, reject) => {
      const req = httpsRequest(`https://127.0.0.1:${port}/interaction/${uid}`, { method,
        rejectUnauthorized: false, headers: method === 'POST' ? { origin: 'https://issuer.example.test',
          cookie, 'content-type': 'application/x-www-form-urlencoded' } : {} }, res => {
        let text = '';
        res.on('data', chunk => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, text, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
      });
      req.on('error', reject);
      req.end(method === 'POST' ? form : undefined);
    });
  }
  const workers = await Promise.all([start(), start()]);
  const forms = await Promise.all(Array.from({ length: 12 }, async (_, index) => {
    const port = workers[index % 2].port;
    const uid = `flow-${index}`;
    const get = await http(port, uid);
    assert.equal(get.status, 200);
    return { port, uid, cookie: get.cookie, csrf: get.text.match(/name="csrf" value="([^"]+)"/)?.[1] };
  }));
  const results = await Promise.all(forms.map(form => http(form.port, form.uid, { method: 'POST', ...form })));
  assert.equal(results.filter(result => result.status === 403).length, 5, 'only five requests reached password verification');
  assert.equal(results.filter(result => result.status === 429).length, 7);
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(join(directory, 'interactions.sqlite'));
  assert.equal(db.prepare('SELECT count FROM attempts WHERE account=?').get('person1').count, 5);
  assert.ok(db.prepare('SELECT COUNT(*) AS total FROM csrf').get().total <= 1,
    'consumed CSRF rows are pruned during subsequent admissions');
  db.close();
  const restarted = await start();
  const retry = await http(restarted.port, 'new-flow');
  const blocked = await http(restarted.port, 'new-flow', { method: 'POST', cookie: retry.cookie,
    csrf: retry.text.match(/name="csrf" value="([^"]+)"/)?.[1] });
  assert.equal(blocked.status, 429, 'durable lockout survives new process');
  // Sustained unauthenticated GET and malformed POST requests hit two distinct
  // OS processes sharing one SQLite admission store; neither can inflate it.
  const gets = await Promise.all(Array.from({ length: 80 }, (_, i) =>
    http(workers[i % 2].port, `flood-${i}`)));
  assert.ok(gets.filter(result => result.status === 200).length <= 27);
  assert.ok(gets.filter(result => result.status === 429 || result.status === 503).length >= 53);
  const posts = await Promise.all(Array.from({ length: 150 }, (_, i) =>
    http(workers[i % 2].port, `invalid-${i}`, { method: 'POST' })));
  assert.ok(posts.filter(result => result.status === 403).length <= 107);
  assert.ok(posts.filter(result => result.status === 429 || result.status === 503).length >= 43);
  const afterRestart = await start();
  assert.equal((await http(afterRestart.port, 'still-limited')).status, 429,
    'GET rate limit survives fresh process');
  const { DatabaseSync: SQLite } = await import('node:sqlite');
  const bounded = new SQLite(join(directory, 'interactions.sqlite'));
  assert.ok(bounded.prepare('SELECT COUNT(*) AS count FROM csrf').get().count <= 40);
  assert.ok(bounded.prepare('PRAGMA page_count').get().page_count *
    bounded.prepare('PRAGMA page_size').get().page_size <= 262144);
  bounded.prepare('UPDATE csrf SET expires=0').run();
  bounded.prepare('UPDATE admission SET expires=0').run();
  bounded.close();
  assert.equal((await http(afterRestart.port, 'after-expiry')).status, 200,
    'expired quota and nonce rows are transactionally pruned');
  const pruned = new SQLite(join(directory, 'interactions.sqlite'));
  assert.equal(pruned.prepare('SELECT COUNT(*) AS count FROM csrf').get().count, 1);
  pruned.close();
});

test('private issuer path rejects writable ancestors, symlink sidecars and swapped directory or human file', async t => {
  const parent = await fs.mkdtemp(join(tmpdir(), 'workrelay-path-'));
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const directory = join(parent, 'state');
  await fs.mkdir(directory, { mode: 0o700 });
  const origin = 'https://issuer.example.test';
  const provider = { interactionDetails: async req => ({ uid: req.url.split('/')[2],
    params: { client_id: 'approved-client' }, session: { uid: 'session' }, prompt: { name: 'login' } }),
  interactionFinished: async (_req, res) => { res.writeHead(303); res.end(); } };
  const construct = (target = directory) => createLocalInteractions({ provider, directory: target, origin, clientId: 'approved-client',
    resource: origin + '/mcp' });
  await fs.chmod(parent, 0o777);
  assert.throws(construct, /unsafe directory ancestor/);
  await fs.chmod(parent, 0o700);
  const alias = join(parent, 'state-link');
  await fs.symlink(directory, alias);
  assert.throws(() => construct(alias), /private directory required/);
  assert.throws(() => construct(`${alias}/`), /normalized absolute private directory required/);
  const sidecar = join(directory, 'interactions.sqlite-wal');
  await fs.symlink(join(parent, 'victim'), sidecar);
  assert.throws(construct, /private file required/);
  await fs.unlink(sidecar);
  await fs.writeFile(sidecar, '', { mode: 0o644 });
  await fs.chmod(sidecar, 0o644); // ensure unsafe mode even under owner-only umask
  assert.throws(construct, /private file required/);
  await fs.unlink(sidecar);
  const sqlite = join(directory, 'interactions.sqlite');
  await fs.writeFile(sqlite, '', { mode: 0o644 });
  await fs.chmod(sqlite, 0o644);
  assert.throws(construct, /private file required/);
  await fs.chmod(sqlite, 0o600);
  const handler = construct();
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-subj', '/CN=localhost',
    '-keyout', join(parent, 'tls.key'), '-out', join(parent, 'tls.crt'), '-days', '1'], { stdio: 'ignore' });
  const server = createServer({ key: await fs.readFile(join(parent, 'tls.key')),
    cert: await fs.readFile(join(parent, 'tls.crt')) }, (req, res) => handler(req, res));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const call = (method = 'GET', cookie = '', csrf = '') => new Promise((resolve, reject) => {
    const req = httpsRequest(`https://127.0.0.1:${server.address().port}/interaction/test`, {
      method, rejectUnauthorized: false, headers: method === 'POST' ? { origin,
        cookie, 'content-type': 'application/x-www-form-urlencoded' } : {} }, res => {
      let text = '';
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, text, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
    });
    req.on('error', reject);
    req.end(method === 'POST' ? new URLSearchParams({ csrf, password: 'wrong' }).toString() : undefined);
  });
  const first = await call();
  assert.equal(first.status, 200);
  const csrf = first.text.match(/name="csrf" value="([^"]+)"/)?.[1];
  await fs.symlink(join(parent, 'victim'), join(directory, 'human.json'));
  assert.equal((await call('POST', first.cookie, csrf)).status, 403, 'human symlink rejected before reading');
  await fs.unlink(join(directory, 'human.json'));
  await fs.writeFile(join(directory, 'human.json'), '{}', { mode: 0o644 });
  const second = await call();
  assert.equal((await call('POST', second.cookie, second.text.match(/name="csrf" value="([^"]+)"/)?.[1])).status,
    403, 'group/world-readable human state rejected before parsing');
  const moved = join(parent, 'state-old');
  await fs.rename(directory, moved);
  await fs.mkdir(directory, { mode: 0o700 });
  assert.equal((await call()).status, 403, 'replacement directory rejected even though private');
});
