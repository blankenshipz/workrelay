import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, request as httpsRequest } from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import argon2 from 'argon2';
import { createIssuerAdapter } from '../src/workrelay/oidc_adapter.mjs';
import { createUnexposedIssuerPolicy } from '../src/workrelay/issuer_policy.mjs';
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

test('provisioning refuses non-TTY; actual HTTPS provider interaction requires CSRF, password and consent', async t => {
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
  const clientId = 'approved-client';
  const redirect = 'https://client.example.test/callback';
  const provider = createUnexposedIssuerPolicy({ origin, principal: 'person1',
    jwks: { keys: [{ ...privateKey, kid: 'test', alg: 'RS256', use: 'sig' }] },
    cookieKeys: [randomBytes(32).toString('base64url')], clientId,
    redirectUris: [redirect], adapter: createIssuerAdapter(directory),
    findAccount: async (_ctx, id) => id === 'person1' ? { accountId: id, claims: async () => ({ sub: id }) } : undefined });
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
    const response = await new Promise((resolve, reject) => {
      const call = httpsRequest(base + path, { method: opts.method ?? 'GET', rejectUnauthorized: false,
        headers: { cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; '), ...opts.headers } }, result => {
        let text = '';
        result.on('data', chunk => { text += chunk; });
        result.on('end', () => resolve({ status: result.statusCode, headers: {
          get: key => result.headers[key], getSetCookie: () => result.headers['set-cookie'] ?? [] }, text }));
      });
      call.on('error', reject);
      call.end(opts.body?.toString());
    });
    for (const set of response.headers.getSetCookie()) {
      const [key, value] = set.split(';', 1)[0].split('=');
      if (value) jar.set(key, value); else jar.delete(key);
    }
    return { response, text: response.text };
  }
  const auth = `/auth?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}` +
    `&scope=workrelay%3Atasks&resource=${encodeURIComponent(origin + '/mcp')}&code_challenge=${'a'.repeat(43)}` +
    '&code_challenge_method=S256&state=test';
  let next = await request(auth);
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
  next = await post(hidden(next.text), { password: fixturePassword });
  assert.equal(next.response.status, 303);
  // Resume provider authorization after login, which must prompt for consent.
  url = new URL(next.response.headers.get('location'), base);
  next = await request(url.pathname + url.search);
  assert.equal(next.response.status, 303);
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
  next = await post(hidden(next.text), { decision: 'approve' });
  assert.equal(next.response.status, 303);
  url = new URL(next.response.headers.get('location'), base);
  next = await request(url.pathname + url.search);
  assert.equal(next.response.status, 303);
  assert.match(next.response.headers.get('location'), /^https:\/\/client\.example\.test\/callback\?code=/);
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
