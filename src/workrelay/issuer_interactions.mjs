// Unmounted local human interaction handler. The caller must mount this BEFORE
// provider.callback(), enforce its public-origin/proxy boundary, and serve HTTPS.
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { openSync, closeSync, readFileSync, readSync, writeFileSync, lstatSync, fstatSync, realpathSync,
  linkSync, unlinkSync, fsyncSync, constants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import argon2 from 'argon2';

const COOKIE = '__Host-workrelay-flow';
const WINDOW_MS = 300000;
const MAX_CSRF = 128;
const MAX_DB_BYTES = 262144;
const digest = value => createHash('sha256').update(value).digest('hex');
const escaped = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const allowedId = value => typeof value === 'string' && /^[A-Za-z0-9._~-]{1,128}$/.test(value);

export function privateDirectory(path) {
  if (!isAbsolute(path) || path !== resolve(path)) throw Error('normalized absolute private directory required');
  const root = lstatSync(path);
  if (!root.isDirectory() || root.uid !== process.getuid() || (root.mode & 0o077)) throw Error('private directory required');
  // SQLite only accepts a pathname, not a directory fd. Reject any ancestor
  // writable by another principal, checking both the literal and resolved
  // chain. macOS system aliases such as /var -> /private/var are root-owned.
  for (const chain of [path, realpathSync(path)]) {
    for (let node = chain; ; node = dirname(node)) {
      const stat = lstatSync(node);
      if (stat.isSymbolicLink()) {
        if (stat.uid !== 0 || node === path) throw Error('unsafe directory alias');
      } else if (!stat.isDirectory() || ![0, process.getuid()].includes(stat.uid) || (stat.mode & 0o022)) {
        throw Error('unsafe directory ancestor');
      }
      if (node === dirname(node)) break;
    }
  }
  return root;
}
function privateFile(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw Error('private file required');
  return stat;
}
function statePath(directory, name) { privateDirectory(directory); return join(directory, name); }
function sameInode(a, b) { return a.dev === b.dev && a.ino === b.ino; }
function sidecars(path) {
  for (const name of [path, `${path}-journal`, `${path}-wal`, `${path}-shm`]) {
    try { privateFile(name); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

// Explicit private one-shot diagnostic, never an authorization signal. The
// arm file is operator-created mode 0600 and expires within two minutes. A
// hard link with O_EXCL-like semantics admits at most one request across
// processes; failure to record must never change the HTTP decision.
export function createOriginDiagnostic({ directory, origin, hostname, beforePublish }) {
  privateDirectory(directory);
  const arm = join(directory, 'origin-post.arm');
  const used = join(directory, 'origin-post.used');
  const receipt = join(directory, 'origin-post.receipt.json');
  return function capture(req, res) {
    if (req.method !== 'POST' || !/^\/interaction\/[A-Za-z0-9._~-]{1,128}$/.test(req.url ?? '')) return null;
    try {
      privateDirectory(directory);
      const fd = openSync(arm, constants.O_RDONLY | constants.O_NOFOLLOW);
      let expiry, attemptId;
      try {
        const file = fstatSync(fd), link = lstatSync(arm);
        if (!file.isFile() || file.uid !== process.getuid() || file.mode & 0o077 || file.nlink !== 1 ||
            file.size > 128 || file.dev !== link.dev || file.ino !== link.ino) return null;
        const armBytes = Buffer.alloc(file.size);
        if (readSync(fd, armBytes, 0, file.size, 0) !== file.size) return null;
        ({ expiresAt: expiry, attemptId } = JSON.parse(armBytes.toString('utf8')));
      } finally { closeSync(fd); }
      const now = Date.now();
      if (!Number.isSafeInteger(expiry) || expiry <= now || expiry > now + 120000 ||
          typeof attemptId !== 'string' || !/^[a-f0-9]{32}$/.test(attemptId)) return null;
      try { lstatSync(receipt); return null; }
      catch (error) { if (error.code !== 'ENOENT') return null; }
      linkSync(arm, used); // exclusive: a second process cannot consume it
      unlinkSync(arm);
      const rawOriginCount = req.rawHeaders.filter((_, index) => index % 2 === 0)
        .filter(name => name.toLowerCase() === 'origin').length;
      const value = req.headers.origin;
      const originCategory = rawOriginCount === 0 ? 'absent' : rawOriginCount !== 1 ? 'other' :
        value === 'null' ? 'null' : value === origin ? 'equal' : 'other';
      let refererOriginMatch = false;
      try {
        const parsed = new URL(req.headers.referer);
        refererOriginMatch = parsed.origin === origin && !parsed.username && !parsed.password;
      } catch { /* absent or malformed is only a false diagnostic category */ }
      const fetchSite = req.headers['sec-fetch-site'];
      const secFetchSite = fetchSite === undefined ? 'absent' :
        ['same-origin', 'same-site', 'cross-site', 'none'].includes(fetchSite) ? fetchSite : 'other';
      const hostMatch = req.rawHeaders.filter((_, index) => index % 2 === 0)
        .filter(name => name.toLowerCase() === 'host').length === 1 && req.headers.host === hostname;
      let stage = 'outer', rejectionClass = 'none';
      res.once('finish', () => {
        let temporary, fd;
        try {
          privateDirectory(directory);
          temporary = join(directory, `origin-post.${randomBytes(16).toString('hex')}.tmp`);
          fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          writeFileSync(fd, JSON.stringify({ attemptId, origin: originCategory, refererOriginMatch,
            secFetchSite, hostMatch, status: res.statusCode, stage, rejectionClass }));
          fsyncSync(fd);
          closeSync(fd); fd = undefined;
          beforePublish?.();
          linkSync(temporary, receipt); // old receipt is never replaced
          const dirFd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
          try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
        } catch { /* never change an authentication response for diagnostic I/O */ }
        finally {
          if (fd !== undefined) try { closeSync(fd); } catch { /* ignored */ }
          if (temporary) try { unlinkSync(temporary); } catch { /* ignored */ }
        }
      });
      return { reachedInteraction() { stage = 'interaction'; }, rejectedAtGateway(reason) {
        if (['remote', 'forwarding', 'host', 'origin', 'framing', 'other'].includes(reason))
          rejectionClass = reason;
      } };
    } catch { return null; }
  };
}
function send(res, status, body = '') {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
  res.end(body);
}

// No programmatic password argument: only an interactive terminal may create
// or rotate the single human verifier. No default password or account ID.
export async function hashLocalHumanPassword(password) {
  if (!Buffer.isBuffer(password) || password.length < 16 || password.length > 256)
    throw Error('password length invalid');
  return argon2.hash(password, { type: argon2.argon2id });
}
export async function provisionLocalHuman({ directory, accountId }) {
  if (!allowedId(accountId) || !process.stdin.isTTY || !process.stdout.isTTY) throw Error('local TTY and explicit account ID required');
  const path = statePath(directory, 'human.json');
  try { privateFile(path); throw Error('credential already provisioned; remove via deliberate offline rotation'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const tty = openSync('/dev/tty', 'r+');
  const stty = (...args) => {
    const result = spawnSync('stty', args, { stdio: [tty, tty, tty] });
    if (result.status !== 0) throw Error('terminal configuration failed');
  };
  let password = Buffer.alloc(0);
  try {
    stty('-echo');
    writeFileSync(tty, 'New Workrelay password (at least 16 characters): ');
    const byte = Buffer.alloc(1);
    while (true) {
      const n = readSync(tty, byte, 0, 1, null);
      if (!n || byte[0] === 10 || byte[0] === 13) break;
      if (password.length >= 256) throw Error('password length invalid');
      password = Buffer.concat([password, byte]);
    }
  } finally { stty('echo'); writeFileSync(tty, '\n'); closeSync(tty); }
  if (password.length < 16) throw Error('password length invalid');
  let verifier;
  try { verifier = await hashLocalHumanPassword(password); }
  finally { password.fill(0); }
  // exclusive creation prevents accidental credential overwrite
  writeFileSync(path, JSON.stringify({ accountId, verifier }), { flag: 'wx', mode: 0o600 });
  privateDirectory(directory); privateFile(path);
  return accountId;
}

export function createLocalInteractions({ provider, directory, origin, clientId, resource }) {
  if (!provider?.interactionDetails || !provider?.interactionFinished ||
      new URL(origin).origin !== origin || !origin.startsWith('https://') ||
      resource !== `${origin}/mcp` || !clientId) throw Error('invalid interaction configuration');
  const root = privateDirectory(directory);
  const humanPath = statePath(directory, 'human.json');
  const dbPath = statePath(directory, 'interactions.sqlite');
  sidecars(dbPath);
  const fd = openSync(dbPath, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.uid !== process.getuid() || (opened.mode & 0o077) ||
        !sameInode(opened, privateFile(dbPath))) throw Error('unsafe private database');
  } finally { closeSync(fd); }
  const db = new DatabaseSync(dbPath, { timeout: 5000 });
  const dbIdentity = privateFile(dbPath);
  function assertState() {
    if (!sameInode(root, privateDirectory(directory))) throw Error('private directory changed');
    sidecars(dbPath);
    if (!sameInode(dbIdentity, privateFile(dbPath))) throw Error('private database changed');
  }
  assertState();
  db.exec('CREATE TABLE IF NOT EXISTS csrf (uid TEXT PRIMARY KEY, bound TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS attempts (account TEXT PRIMARY KEY, count INTEGER NOT NULL, until INTEGER NOT NULL, locked INTEGER NOT NULL)');
  db.exec('CREATE TABLE IF NOT EXISTS admission (subject TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL); PRAGMA max_page_count=64');
  assertState();
  function bounded() {
    const pages = db.prepare('PRAGMA page_count').get().page_count;
    const pageSize = db.prepare('PRAGMA page_size').get().page_size;
    return pages * pageSize <= MAX_DB_BYTES && privateFile(dbPath).size <= MAX_DB_BYTES;
  }
  function admit(req) {
    // Never trust caller-controlled X-Forwarded-For. At a loopback TLS proxy
    // every remote caller shares its proxy IP, intentionally failing closed.
    const method = req.method === 'GET' ? 'get' : 'post';
    const ip = typeof req.socket?.remoteAddress === 'string' && req.socket.remoteAddress.length <= 128
      ? req.socket.remoteAddress : 'unknown';
    const subjects = [[`${method}:global`, method === 'get' ? 80 : 300],
      [`${method}:ip:${digest(ip)}`, method === 'get' ? 40 : 120]];
    try {
      db.exec('BEGIN IMMEDIATE');
      const now = Date.now();
      db.prepare('DELETE FROM csrf WHERE expires<=? OR used=1').run(now);
      db.prepare('DELETE FROM admission WHERE expires<=?').run(now);
      db.prepare('DELETE FROM attempts WHERE until<=? AND locked<=?').run(now, now);
      const rows = subjects.map(([subject]) => db.prepare('SELECT count,expires FROM admission WHERE subject=?').get(subject));
      const pending = subjects.map(([, limit], index) => ({
        count: rows[index]?.expires > now ? rows[index].count + 1 : 1, limit }));
      if (pending.some(({ count, limit }) => count > limit)) { db.exec('COMMIT'); return 429; }
      if (method === 'get' && db.prepare('SELECT COUNT(*) AS count FROM csrf').get().count >= MAX_CSRF) {
        db.exec('COMMIT'); return 503;
      }
      if (db.prepare('SELECT COUNT(*) AS count FROM admission').get().count >= 128 || !bounded()) {
        db.exec('COMMIT'); return 503;
      }
      subjects.forEach(([subject], index) => db.prepare('INSERT INTO admission(subject,count,expires) VALUES(?,?,?) ON CONFLICT(subject) DO UPDATE SET count=excluded.count,expires=excluded.expires')
        .run(subject, pending[index].count, rows[index]?.expires > now ? rows[index].expires : now + WINDOW_MS));
      db.exec('COMMIT'); return 200;
    } catch {
      try { db.exec('ROLLBACK'); } catch { /* no transaction or storage unavailable */ }
      return 503;
    }
  }
  function readHuman() {
    assertState();
    const fd = openSync(humanPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    let text;
    try {
      const opened = fstatSync(fd);
      if (!opened.isFile() || opened.uid !== process.getuid() || (opened.mode & 0o077) ||
          !sameInode(opened, privateFile(humanPath))) throw Error('unsafe human credential');
      text = readFileSync(fd, { encoding: 'utf8' });
    } finally { closeSync(fd); }
    assertState();
    const data = JSON.parse(text);
    if (!allowedId(data.accountId) || typeof data.verifier !== 'string' || !data.verifier.startsWith('$argon2id$')) throw Error('invalid private human state');
    return data;
  }
  const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
  const sessionKey = details => JSON.stringify([details.session?.uid ?? '', details.session?.cookie ?? '', details.session?.accountId ?? '']);
  function consume(uid, details, cookie, token) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const row = db.prepare('SELECT bound,expires,used FROM csrf WHERE uid=?').get(uid);
      const bound = digest(JSON.stringify([uid, sessionKey(details), cookie, token]));
      const valid = row && !row.used && row.expires >= Date.now() && same(row.bound, bound);
      if (valid) db.prepare('UPDATE csrf SET used=1 WHERE uid=?').run(uid);
      db.exec('COMMIT'); return Boolean(valid);
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  // Reserve one password verification under a cross-process SQLite write lock.
  // Never await Argon2 before admission: concurrent requests may otherwise all
  // pass a stale lockout check. A successful login does not erase other guesses.
  function reserveAttempt(accountId) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const now = Date.now();
      const row = db.prepare('SELECT count,until,locked FROM attempts WHERE account=?').get(accountId);
      if (row?.locked > now) { db.exec('COMMIT'); return false; }
      const count = row && row.until > now ? row.count + 1 : 1;
      db.prepare('INSERT INTO attempts(account,count,until,locked) VALUES(?,?,?,?) ON CONFLICT(account) DO UPDATE SET count=excluded.count,until=excluded.until,locked=excluded.locked')
        .run(accountId, count, now + 900000, count >= 5 ? now + 900000 : 0);
      db.exec('COMMIT'); return count <= 5;
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  async function body(req) {
    if (!/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '') ||
        Number(req.headers['content-length'] ?? 0) > 2048) throw Error('invalid form');
    let text = '';
    for await (const chunk of req) { text += chunk; if (Buffer.byteLength(text) > 2048) throw Error('oversize form'); }
    const fields = new URLSearchParams(text);
    if ([...fields.keys()].some(key => fields.getAll(key).length !== 1 || !['csrf', 'password', 'decision'].includes(key))) throw Error('invalid fields');
    return fields;
  }
  return async function handle(req, res) {
    const path = req.url?.match(/^\/interaction\/([A-Za-z0-9._~-]{1,128})$/);
    if (!path) return false;
    const uid = path[1];
    if (req.method !== 'GET' && req.method !== 'POST') { send(res, 405); return true; }
    try {
      assertState();
      const admitted = admit(req);
      if (admitted !== 200) { send(res, admitted); return true; }
      // The provider binds this interaction to its own session cookies.
      const details = await provider.interactionDetails(req, res);
      if (details.uid !== uid || details.params?.client_id !== clientId ||
          !['login', 'consent'].includes(details.prompt?.name)) { send(res, 403); return true; }
      const name = details.prompt.name;
      if (req.method === 'GET') {
        const nonce = randomBytes(32).toString('base64url');
        const cookie = randomBytes(32).toString('base64url');
        try {
          db.exec('BEGIN IMMEDIATE');
          db.prepare('DELETE FROM csrf WHERE expires<=? OR used=1').run(Date.now());
          if (db.prepare('SELECT COUNT(*) AS count FROM csrf').get().count >= MAX_CSRF || !bounded()) {
            db.exec('COMMIT'); send(res, 503); return true;
          }
          db.prepare('INSERT INTO csrf(uid,bound,expires,used) VALUES(?,?,?,0) ON CONFLICT(uid) DO UPDATE SET bound=excluded.bound,expires=excluded.expires,used=0')
            .run(uid, digest(JSON.stringify([uid, sessionKey(details), cookie, nonce])), Date.now() + WINDOW_MS);
          db.exec('COMMIT');
        } catch {
          try { db.exec('ROLLBACK'); } catch { /* storage already unavailable */ }
          send(res, 503); return true;
        }
        res.setHeader('set-cookie', `${COOKIE}=${cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300`);
        const client = escaped(details.params.client_id);
        const action = escaped(`/interaction/${uid}`);
        const form = name === 'login' ? '<label>Password <input name="password" type="password" required autocomplete="current-password"></label><button type="submit">Sign in</button>'
          : '<button name="decision" value="approve" type="submit">Authorize</button><button name="decision" value="deny" type="submit">Deny</button>';
        const disclosure = name === 'consent' ? '<p>Approving allows this client to supervise your Workrelay tasks. It may receive renewable access through refresh tokens even after you close this page. No self-service revoke page exists: to revoke access, ask the local Workrelay operator to disable this client and revoke its saved grant and refresh tokens. A client holding its token may use the issuer revocation endpoint. Issued access tokens can remain valid for up to five minutes.</p>' : '';
        send(res, 200, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Workrelay ${name}</title><h1>Workrelay ${name}</h1><p>Client: ${client}</p><p>Access: ${escaped(resource)} (workrelay:tasks)</p>${disclosure}<form method="post" action="${action}"><input type="hidden" name="csrf" value="${escaped(nonce)}">${form}</form></html>`);
        return true;
      }
      if (req.headers.origin !== origin) { send(res, 403); return true; }
      const fields = await body(req);
      const cookieHeaders = (req.headers.cookie ?? '').split(';').map(s => s.trim());
      const cookies = cookieHeaders.filter(s => s.startsWith(`${COOKIE}=`));
      const cookie = cookies.length === 1 ? cookies[0].slice(COOKIE.length + 1) : '';
      if (!/^[A-Za-z0-9_-]{43}$/.test(cookie) || !/^[A-Za-z0-9_-]{43}$/.test(fields.get('csrf') ?? '') ||
          !consume(uid, details, cookie, fields.get('csrf'))) { send(res, 403); return true; }
      res.setHeader('set-cookie', `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
      if (name === 'login') {
        if (fields.has('decision') || !fields.has('password')) { send(res, 403); return true; }
        const human = readHuman();
        if (!reserveAttempt(human.accountId)) { send(res, 429); return true; }
        const password = fields.get('password');
        if (!password || Buffer.byteLength(password) > 256 || !(await argon2.verify(human.verifier, password))) {
          send(res, 403); return true;
        }
        await provider.interactionFinished(req, res, { login: { accountId: human.accountId, remember: false, amr: ['pwd'] } }, { mergeWithLastSubmission: false });
        return true;
      }
      if (fields.has('password') || !['approve', 'deny'].includes(fields.get('decision')) || !details.session?.accountId) { send(res, 403); return true; }
      const human = readHuman();
      if (details.session.accountId !== human.accountId) { send(res, 403); return true; }
      if (fields.get('decision') === 'deny') {
        await provider.interactionFinished(req, res, { error: 'access_denied' }, { mergeWithLastSubmission: false }); return true;
      }
      const missing = details.prompt.details;
      if (missing.missingOIDCScope?.length || missing.missingOIDCClaims?.length || missing.rar?.length ||
          Object.keys(missing.missingResourceScopes ?? {}).some(key => key !== resource) ||
          (missing.missingResourceScopes?.[resource] ?? []).some(scope => scope !== 'workrelay:tasks')) { send(res, 403); return true; }
      const grant = details.grantId ? await provider.Grant.find(details.grantId) :
        new provider.Grant({ accountId: human.accountId, clientId });
      if (!grant || grant.accountId !== human.accountId || grant.clientId !== clientId) { send(res, 403); return true; }
      if (missing.missingResourceScopes?.[resource]?.length) grant.addResourceScope(resource, 'workrelay:tasks');
      const grantId = await grant.save();
      await provider.interactionFinished(req, res, { consent: details.grantId ? {} : { grantId } }, { mergeWithLastSubmission: true });
      return true;
    } catch { if (!res.headersSent) send(res, 403); else res.destroy(); return true; }
  };
}

// Explicit local invocation: node issuer_interactions.mjs provision PRIVATE_DIR ACCOUNT_ID
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 5 || process.argv[2] !== 'provision') {
    console.error('Usage: node issuer_interactions.mjs provision PRIVATE_DIR ACCOUNT_ID');
    process.exitCode = 2;
  } else {
    provisionLocalHuman({ directory: process.argv[3], accountId: process.argv[4] })
      .then(() => console.log('Local human credential provisioned.'))
      .catch(() => { console.error('Provisioning failed; check TTY/private directory/account ID.'); process.exitCode = 1; });
  }
}
