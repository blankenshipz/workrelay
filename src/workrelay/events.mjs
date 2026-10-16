import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { dirname, resolve as resolvePath } from 'node:path';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import https from 'node:https';

const NAMES = ['task.decision', 'task.completed', 'session.completed', 'session.failed', 'session.needs_input', 'session.progress'];
const sessionName = name => name?.startsWith('session.');
const sessionId = value => typeof value === 'string' && /^ses[A-Za-z0-9_-]{1,160}$/.test(value);
const MAX_QUEUE = 2048;
// POSIX flock is process-owned and released by the kernel, not an age-based lease.
// This custodian is the ONLY state writer: killing it cannot permit a stale Node
// snapshot to overwrite a newer transaction. The permanent lock inode is never unlinked.
const CUSTODIAN = String.raw`
import os, sys, json, time, stat, fcntl, tempfile, subprocess
path, parent, wait = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])/1000
def emit(value):
 print(json.dumps(value, separators=(',', ':')), flush=True)
def identity(pid):
 try:
  os.kill(pid, 0)
 except ProcessLookupError:
  return 'dead'
 except OSError:
  return 'unknown'
 try:
  if sys.platform.startswith('linux'):
   with open('/proc/%d/stat' % pid) as f:
    return f.read().rsplit(')', 1)[1].split()[19]
  result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True, timeout=2)
  return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else 'unknown'
 except Exception:
  return 'unknown'
def safe(fd):
 s = os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_mode & 0o077 or s.st_uid != os.getuid() or s.st_size >= 16777216:
  raise ValueError('unsafe_state_file')
try:
 lock = os.open(path+'.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
 safe(lock)
 deadline = time.monotonic()+wait
 while True:
  try:
   fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
   break
  except BlockingIOError:
   if time.monotonic() >= deadline:
    raise ValueError('lock_timeout')
   time.sleep(.025)
 try:
  fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
  safe(fd)
  with os.fdopen(fd) as f:
   state = json.load(f)
 except FileNotFoundError:
  state = {'version':1, 'subscriptions':{}, 'queue':[], 'seen':[]}
 owner = identity(parent)
 if owner in ('dead', 'unknown'):
  raise ValueError('owner_identity_unavailable')
 live = []
 for item in state.get('queue', []):
  claim = item.get('claim')
  if claim:
   current = identity(claim['pid'])
   if current == 'unknown' or current == claim['start']:
    live.append(claim['token'])
 emit({'state':state, 'owner':owner, 'live':live})
 for line in sys.stdin:
  message = json.loads(line)
  if message.get('op') != 'save':
   raise ValueError('invalid_lock_protocol')
  data = json.dumps(message['state'], separators=(',', ':'), ensure_ascii=False).encode()
  if len(data) >= 16777216:
   raise ValueError('state_too_large')
  fd, temp = tempfile.mkstemp(prefix='.events-', dir=os.path.dirname(path))
  try:
   with os.fdopen(fd, 'wb') as f:
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
   os.replace(temp, path)
   directory = os.open(os.path.dirname(path), os.O_RDONLY)
   try:
    os.fsync(directory)
   finally:
    os.close(directory)
  finally:
   if os.path.exists(temp):
    os.unlink(temp)
  emit({'saved':True})
except Exception as e:
 reason = str(e) if isinstance(e, ValueError) and str(e) in ('lock_timeout','unsafe_state_file','owner_identity_unavailable','state_too_large') else 'state_lock_failed'
 emit({'error':reason})
 sys.exit(1)
`;

async function transaction(path, timeoutMs, fn) {
  const child = spawn('python3', ['-u', '-c', CUSTODIAN, path, String(process.pid), String(timeoutMs)], { stdio: ['pipe', 'pipe', 'ignore'] });
  const lines = [], waiters = []; let ended = false;
  const reader = createInterface({ input: child.stdout });
  reader.on('line', line => { const waiter = waiters.shift(); if (waiter) waiter.resolve(line); else lines.push(line); });
  const exited = new Promise(resolve => {
    const finish = () => { ended = true; for (const waiter of waiters.splice(0)) waiter.reject(failure('state_lock_failed', -32000)); resolve(); };
    child.once('exit', finish); child.once('error', finish);
  });
  child.stdin.on('error', () => {});
  async function receive() {
    const line = lines.length ? lines.shift() : await new Promise((resolve, reject) => { if (ended) reject(failure('state_lock_failed', -32000)); else waiters.push({ resolve, reject }); });
    let message; try { message = JSON.parse(line); } catch { throw failure('state_lock_failed', -32000); }
    if (message.error) throw failure(message.error, -32000);
    return message;
  }
  try {
    const { state, owner, live } = await receive();
    requireValue(state?.version === 1 && state.subscriptions && Array.isArray(state.queue) && Array.isArray(state.seen), 'invalid_state');
    const persist = async () => {
      if (ended) throw failure('state_lock_failed', -32000);
      child.stdin.write(JSON.stringify({ op: 'save', state }) + '\n');
      if (!(await receive()).saved) throw failure('state_lock_failed', -32000);
    };
    const result = await fn(state, persist, owner, new Set(live));
    await persist();
    return result;
  } finally { child.stdin.end(); await exited; reader.close(); }
}
function failure(reason, code = -32015) {
  return Object.assign(new Error(code === -32015 ? 'Callback endpoint rejected' : 'Event request rejected'), { code, data: { reason } });
}
function requireValue(ok, reason) { if (!ok) throw failure(reason, -32602); }
function identifier(value) { return typeof value === 'string' && /^[\w.:/-]{1,160}$/.test(value); }
function key(secret) {
  requireValue(typeof secret === 'string' && /^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret), 'invalid_secret');
  const bytes = Buffer.from(secret.slice(6), 'base64');
  requireValue(bytes.length >= 24 && bytes.length <= 64 && bytes.toString('base64') === secret.slice(6), 'invalid_secret');
  return bytes;
}
function callbackURL(value) {
  let u; try { u = new URL(value); } catch { throw failure('invalid_url'); }
  if (typeof value !== 'string' || value.length > 2048 || u.protocol !== 'https:' || u.username || u.password || u.hash || (u.port && u.port !== '443') || isIP(u.hostname) || u.hostname.startsWith('[')) throw failure('invalid_url');
  return u;
}

// Conservative public-only allowlist. IPv6 transition, mapped and special ranges fail closed.
export function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  if (isIP(address) !== 6) return false;
  const parts = address.toLowerCase().split(':');
  const a = parseInt(parts[0] || '0', 16), b = parseInt(parts[1] || '0', 16);
  return a >= 0x2000 && a < 0x4000 && a !== 0x2002 && a !== 0x3fff &&
    !(a === 0x2001 && (b < 0x200 || b === 0xdb8));
}

/** Trusted injectable DNS/HTTPS primitives are for isolated tests, NOT caller-supplied MCP input.
 * Each request resolves anew, rejects every nonpublic answer, then pins that address in the
 * actual TLS connection's lookup while retaining hostname certificate verification. No fetch,
 * redirects, proxy environment, connection pooling, or second unvalidated DNS resolution.
 */
export function createPinnedWebhookTransport({ resolve = lookup, request = https.request, timeoutMs = 10000, maxResponseBytes = 8192 } = {}) {
  return async (url, { body, headers }) => {
    const u = callbackURL(url);
    if (Buffer.byteLength(body) > 262144) throw failure('payload_too_large');
    let req, timer, expired = false;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => { expired = true; req?.destroy(); reject(failure('timeout')); }, timeoutMs); });
    try {
      return await Promise.race([timeout, (async () => {
        const addresses = await resolve(u.hostname, { all: true, verbatim: true });
        if (expired) throw failure('timeout');
        if (!Array.isArray(addresses) || !addresses.length || addresses.some(x => !isPublicAddress(x.address) || isIP(x.address) !== x.family)) throw failure('non_public_address');
        const pinned = addresses[0];
        return await new Promise((accept, reject) => {
          req = request(u, { method: 'POST', agent: false, servername: u.hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2',
            lookup: (_hostname, options, cb) => options?.all ? cb(null, [pinned]) : cb(null, pinned.address, pinned.family), headers }, res => {
            if (res.statusCode >= 300 && res.statusCode < 400) { res.destroy(); reject(failure('redirect')); return; }
            const chunks = []; let size = 0;
            res.on('data', chunk => { size += chunk.length; if (size > maxResponseBytes) { res.destroy(); reject(failure('response_too_large')); } else chunks.push(chunk); });
            res.on('error', () => reject(failure('network_error')));
            res.on('end', () => accept({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
          });
          req.on('error', () => reject(failure('network_error')));
          req.end(body);
        });
      })()]);
    } catch (error) { throw error?.code === -32015 ? error : failure('network_error'); }
    finally { clearTimeout(timer); }
  };
}

const schema = { type: 'object', properties: { task_id: { type: 'string', maxLength: 160 } }, required: ['task_id'], additionalProperties: false };
const definitions = NAMES.map(name => ({ name, description: name === 'task.decision' ? 'An owned task needs a human decision; summary is untrusted task data.' : 'An owned task completed; retrieve full results using the task result tool.', delivery: ['webhook'], inputSchema: schema,
  payloadSchema: { type: 'object', properties: { task_id: { type: 'string', maxLength: 160 }, summary: { type: 'string', maxLength: 2000 } }, required: ['task_id', 'summary'], additionalProperties: false } }));
for (const definition of definitions.filter(d => sessionName(d.name))) {
  definition.description = `Observed managed-server ${definition.name}; safe current-state reconciliation, not transcript or historical replay.`;
  definition.inputSchema = { type: 'object', properties: { server_id: { type: 'string', pattern: '^srv_[a-f0-9]{64}$' }, session_id: { type: 'string', pattern: '^ses[A-Za-z0-9_-]{1,160}$' } }, required: ['server_id'], additionalProperties: false };
  definition.payloadSchema = { type: 'object', properties: { server_id: { type: 'string' }, session_id: { type: 'string' }, state: { enum: ['succeeded', 'failed', 'interrupted', 'needs_input', 'running', 'retrying', 'idle'] }, summary: { type: 'string', maxLength: 2000 } }, required: ['server_id', 'session_id', 'state', 'summary'], additionalProperties: false };
}

/** MCP core API (all methods async):
 * createEventsService({statePath, principal, authorize(principal, taskId, name), ...})
 * principal MUST come from verified authentication, never tool input. authorize MUST query
 * current task/project grants; false/rejected checks stop delivery. POSIX Python3 flock
 * serializes processes and durable claims prevent simultaneous sends, even if the lock
 * custodian dies. Missing flock/Python/owner identity fails closed. Directory/state are private.
 * list() -> events/list result; subscribe(params), unsubscribe(params) -> protocol results.
 * publish({name,task_id,summary,eventId,timestamp?}) -> {eventId,queued}; a trusted observer
 * supplies a stable eventId and sanitized bounded summary, not raw secrets/logs/prompts.
 * deliverDue() -> counts; call periodically under EACH authenticated principal's service.
 * revoke(taskId?) -> {}; also invoke at disconnect/revocation. No polling cursor/replay.
 * No timer is started here. Integration owns scheduler/shutdown and principal enumeration.
 * Persistent queue allows retry across restarts; finite TTL, queue, dedupe and attempt bounds.
 * Event-ID dedupe lasts twice maxTtlMs (then an ID may be reused). Each dispatch handles at
 * most batchSize requests; keep scheduling until due work drains. Core restores principal
 * services from its trusted owner registry at startup; do not wait for remote reconnect.
 * Delivery is at-least-once: a crash AFTER remote receipt but BEFORE durable acknowledgement
 * may retry the SAME eventId. Receivers must dedupe that ID; exactly-once HTTP is impossible.
 * Claims recover when their process identity is proven dead/changed (never by lease age).
 * Unknown process liveness fails closed. Lock contention fails after lockTimeoutMs.
 * Stop success means durable removal: no new/retried sends for those subscriptions.
 * It cannot recall an HTTP request already sent. Stop waits for the delivery lock; a
 * timeout or surviving orphan claim returns -32000/revocation_pending (retryable), NOT
 * success. Native HTTPS attempts end within 10s; injected transports must also bound
 * attempts. A batch can hold the lock longer, so pending errors require a stop retry.
 */
export function createEventsService({ statePath, principal, authorize, observeManaged, transport = createPinnedWebhookTransport(), now = Date.now, ttlMs = 3600000, maxTtlMs = 86400000, verificationTtlMs = 300000, rotationMs = 300000, maxAttempts = 6, batchSize = 16, lockTimeoutMs = 30000 } = {}) {
  requireValue(typeof principal === 'string' && principal.length > 0 && principal.length <= 512 && typeof authorize === 'function' && typeof statePath === 'string', 'missing_authenticated_context');
  requireValue(Number.isSafeInteger(ttlMs) && ttlMs > 0 && Number.isSafeInteger(maxTtlMs) && maxTtlMs >= ttlMs && maxTtlMs <= 604800000 && verificationTtlMs > 0 && maxAttempts >= 1 && maxAttempts <= 20 && Number.isInteger(batchSize) && batchSize >= 1 && batchSize <= 64, 'invalid_configuration');
  const path = resolvePath(statePath);
  requireValue(Number.isInteger(lockTimeoutMs) && lockTimeoutMs > 0 && lockTimeoutMs <= 300000, 'invalid_lock_timeout');
  const allowed = async (owner, task, name, filter) => { try { return (await authorize(owner, task, name, filter)) === true; } catch { return false; } };
  const idFor = (name, task, url) => 'sub_' + createHash('sha256').update(JSON.stringify([principal, url, name, { task_id: task }])).digest('hex');
  async function locked(fn) {
    await fs.mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const dir = await fs.lstat(dirname(path));
    requireValue(dir.isDirectory() && !dir.isSymbolicLink() && !(dir.mode & 0o077), 'state_directory_not_private');
    return transaction(path, lockTimeoutMs, fn); // same-process contenders also get a bounded OS lock wait
  }
  function params(p, needsSecret) {
    requireValue(p && NAMES.includes(p.name) && p.arguments && p.delivery?.mode === 'webhook', 'invalid_subscription');
    let filter, task;
    if (sessionName(p.name)) {
      requireValue(typeof observeManaged === 'function' && /^srv_[a-f0-9]{64}$/.test(p.arguments.server_id) && Object.keys(p.arguments).every(k => ['server_id', 'session_id'].includes(k)) && (p.arguments.session_id === undefined || sessionId(p.arguments.session_id)), 'invalid_managed_filter');
      filter = { server_id: p.arguments.server_id, ...(p.arguments.session_id ? { session_id: p.arguments.session_id } : {}) };
      task = 'managed:' + filter.server_id + ':' + (filter.session_id ?? '*');
    } else { requireValue(Object.keys(p.arguments).length === 1 && identifier(p.arguments.task_id), 'invalid_subscription'); task = p.arguments.task_id; }
    const url = callbackURL(p.delivery.url).href;
    if (needsSecret) key(p.delivery.secret);
    requireValue(p.cursor == null, 'replay_not_supported');
    return { task, filter, url, id: idFor(p.name, task, url) };
  }
  async function signed(sub, body, eventId) {
    const timestamp = String(Math.floor(now() / 1000));
    const secrets = [sub.secret];
    if (sub.previousSecret && sub.rotationUntil > now()) secrets.push(sub.previousSecret);
    const signature = secrets.map(secret => 'v1,' + createHmac('sha256', key(secret)).update(`${eventId}.${timestamp}.${body}`).digest('base64')).join(' ');
    return transport(sub.url, { body, headers: { 'Content-Type': 'application/json', 'webhook-id': eventId, 'webhook-timestamp': timestamp, 'webhook-signature': signature, 'X-MCP-Subscription-Id': sub.id } });
  }
  function drop(state, id) { delete state.subscriptions[id]; state.queue = state.queue.filter(x => x.subscriptionId !== id); }
  async function stop(matches) {
    try {
      return await locked((state, _persist, _owner, live) => {
        const ids = new Set(Object.values(state.subscriptions).filter(matches).map(sub => sub.id));
        if (state.queue.some(item => ids.has(item.subscriptionId) && item.claim && live.has(item.claim.token))) throw failure('revocation_pending', -32000);
        for (const id of ids) drop(state, id);
        return {};
      });
    } catch (error) {
      if (error.data?.reason === 'lock_timeout' || error.data?.reason === 'revocation_pending') {
        const pending = failure('revocation_pending', -32000); pending.data.retryable = true; throw pending;
      }
      throw error;
    }
  }
  function managedFilter(filter) {
    requireValue(filter && /^srv_[a-f0-9]{64}$/.test(filter.server_id) && Object.keys(filter).every(k => ['server_id', 'session_id'].includes(k)) && (filter.session_id === undefined || sessionId(filter.session_id)), 'invalid_managed_filter');
  }
  const matchesFilter = (sub, filter) => sub.principal === principal && sub.filter?.server_id === filter.server_id && (!filter.session_id || sub.filter.session_id === filter.session_id);
  function publicSubscription(state, sub) {
    const pending = state.queue.filter(item => item.subscriptionId === sub.id);
    return { id: sub.id, name: sub.name, filter: { ...sub.filter }, status: sub.expires <= now() ? 'expired' : 'active', refresh_before: new Date(sub.expires).toISOString(),
      queued: pending.length, delivery_state: pending.some(item => item.claim) ? 'in_flight' : pending.some(item => item.attempts > 0) ? 'retrying' : pending.length ? 'queued' : 'idle',
      next_attempt_at: pending.length ? new Date(Math.min(...pending.map(item => item.due))).toISOString() : null,
      delivered: sub.delivery?.delivered ?? 0, dropped: sub.delivery?.dropped ?? 0, last_attempt_at: sub.delivery?.last_attempt_at ?? null,
      last_ack_at: sub.delivery?.last_ack_at ?? null, last_http_status: sub.delivery?.last_http_status ?? null };
  }
  return {
    principal,
    async list() { return { events: structuredClone(definitions.filter(d => !sessionName(d.name) || typeof observeManaged === 'function')) }; },
    async subscriptions({ filter, limit = 20, cursor = null }) {
      managedFilter(filter); requireValue(Number.isInteger(limit) && limit >= 1 && limit <= 50 && (cursor === null || /^sub_[a-f0-9]{64}$/.test(cursor)), 'invalid_page');
      return locked(async state => {
        const candidates = Object.values(state.subscriptions).filter(sub => matchesFilter(sub, filter) && (!cursor || sub.id > cursor)).sort((a, b) => a.id.localeCompare(b.id));
        const visible = [];
        for (const sub of candidates) if (await allowed(principal, sub.task, sub.name, sub.filter)) { visible.push(publicSubscription(state, sub)); if (visible.length > limit) break; }
        return { subscriptions: visible.slice(0, limit), next_cursor: visible.length > limit ? visible[limit - 1].id : null };
      });
    },
    async subscriptionStatus({ id, filter }) {
      managedFilter(filter); requireValue(/^sub_[a-f0-9]{64}$/.test(id), 'invalid_subscription_id');
      return locked(async state => { const sub = state.subscriptions[id]; return { subscription: sub && matchesFilter(sub, filter) && await allowed(principal, sub.task, sub.name, sub.filter) ? publicSubscription(state, sub) : null }; });
    },
    async unsubscribeById({ id, filter }) {
      managedFilter(filter); requireValue(/^sub_[a-f0-9]{64}$/.test(id), 'invalid_subscription_id');
      await stop(sub => sub.id === id && matchesFilter(sub, filter));
      return { subscription_id: id, status: 'stopped_or_absent' };
    },
    async subscribe(p) {
      const { task, filter, url, id } = params(p, true);
      requireValue(p.ttlMs == null || (Number.isSafeInteger(p.ttlMs) && p.ttlMs > 0), 'invalid_ttl');
      if (!await allowed(principal, task, p.name, filter)) throw failure('not_authorized', -32001);
      return locked(async state => {
        for (const sub of Object.values(state.subscriptions)) if (sub.expires <= now()) drop(state, sub.id);
        requireValue(Object.keys(state.subscriptions).length < 256 || state.subscriptions[id], 'subscription_limit');
        const old = state.subscriptions[id];
        const sub = { id, principal, task, name: p.name, ...(filter ? { filter, observations: old?.observations ?? {}, scanCursor: old?.scanCursor ?? null } : {}), ...(old?.delivery ? { delivery: old.delivery } : {}), url, secret: p.delivery.secret, expires: now() + Math.min(p.ttlMs ?? ttlMs, maxTtlMs), verifiedUntil: old?.verifiedUntil || 0 };
        if (old && old.secret !== sub.secret) { sub.previousSecret = old.secret; sub.rotationUntil = now() + rotationMs; }
        else if (old?.rotationUntil > now()) { sub.previousSecret = old.previousSecret; sub.rotationUntil = old.rotationUntil; }
        if (!old || old.secret !== sub.secret || old.verifiedUntil <= now()) {
          const challenge = randomBytes(32).toString('base64url');
          const response = await signed(sub, JSON.stringify({ type: 'verification', challenge }), 'msg_verification_' + randomBytes(16).toString('hex'));
          let echoed; try { echoed = JSON.parse(response.body).challenge; } catch { /* fail below */ }
          if (!Number.isInteger(response.status) || response.status < 200 || response.status >= 300 || typeof echoed !== 'string' || Buffer.byteLength(echoed) !== Buffer.byteLength(challenge) || !timingSafeEqual(Buffer.from(echoed), Buffer.from(challenge))) throw failure('challenge_failed');
          sub.verifiedUntil = now() + verificationTtlMs;
        }
        if (!await allowed(principal, task, p.name, filter)) throw failure('not_authorized', -32001);
        state.subscriptions[id] = sub;
        return { id, refreshBefore: new Date(sub.expires).toISOString(), cursor: null, truncated: false };
      });
    },
    async unsubscribe(p) { const { id } = params(p, false); return stop(sub => sub.id === id); },
    async revoke(taskId) { return stop(sub => sub.principal === principal && (!taskId || sub.task === taskId)); },
    async pollManaged() {
      if (typeof observeManaged !== 'function') return;
      return locked(async state => {
        let pages = 0;
        const subscriptions = Object.values(state.subscriptions);
        const offset = state.managedScanOffset ?? 0;
        for (let index = 0; index < subscriptions.length; index++) {
          const sub = subscriptions[(offset + index) % subscriptions.length];
          if (sub.principal !== principal || !sessionName(sub.name)) continue;
          if (sub.expires <= now() || !await allowed(principal, sub.task, sub.name, sub.filter)) { drop(state, sub.id); continue; }
          if (pages++ >= 8 || state.queue.length > MAX_QUEUE - 10) { state.managedScanOffset = (offset + index) % subscriptions.length; break; }
          let page; try { page = await observeManaged(sub.filter, sub.scanCursor); } catch { continue; }
          requireValue(page?.server_id === sub.filter.server_id && Array.isArray(page.items) && page.items.length <= 10 && (page.next_cursor === null || typeof page.next_cursor === 'string' && page.next_cursor.length <= 4096 && page.next_cursor !== sub.scanCursor), 'invalid_observation');
          if (!await allowed(principal, sub.task, sub.name, sub.filter)) { drop(state, sub.id); continue; }
          for (const item of page.items) {
            requireValue(sessionId(item.session_id) && (!sub.filter.session_id || item.session_id === sub.filter.session_id) && ['succeeded', 'failed', 'interrupted', 'needs_input', 'unknown', 'running', 'retrying', 'idle'].includes(item.state) && Array.isArray(item.decisions) && item.decisions.length <= 1000 && item.decisions.every(id => /^per[A-Za-z0-9_-]{1,160}$/.test(id)), 'invalid_observation');
            const fingerprint = createHash('sha256').update(JSON.stringify([item.state, item.state === 'needs_input' ? [...item.decisions].sort() : []])).digest('hex');
            const previous = sub.observations[item.session_id];
            if (previous?.fingerprint === fingerprint) continue;
            requireValue(previous || Object.values(state.subscriptions).reduce((sum, subscription) => sum + Object.keys(subscription.observations ?? {}).length, 0) < 8192, 'observation_limit');
            const generation = (previous?.generation ?? 0) + 1;
            sub.observations[item.session_id] = { fingerprint, generation };
            const name = item.state === 'needs_input' ? 'session.needs_input' : item.state === 'failed' ? 'session.failed' : ['succeeded', 'interrupted'].includes(item.state) ? 'session.completed' : ['running', 'retrying', 'idle'].includes(item.state) ? 'session.progress' : null;
            if (name !== sub.name) continue;
            const eventId = 'evt_' + createHash('sha256').update(JSON.stringify([principal, sub.id, item.session_id, fingerprint, generation])).digest('hex');
            state.queue.push({ subscriptionId: sub.id, event: { eventId, name, timestamp: new Date(now()).toISOString(), data: { ...sub.filter, session_id: item.session_id, state: item.state, summary: `Managed session observed ${item.state}; inspect workrelay_server_read. Runtime idle is not task completion. Native approvals remain required.` }, cursor: null }, attempts: 0, due: now() });
          }
          sub.scanCursor = page.next_cursor;
        }
      });
    },
    async publish({ name, task_id, summary, eventId, timestamp = new Date(now()).toISOString() }) {
      requireValue(NAMES.includes(name) && !sessionName(name) && identifier(task_id) && identifier(eventId) && typeof summary === 'string' && summary.length <= 2000 && typeof timestamp === 'string' && /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(timestamp) && Number.isFinite(Date.parse(timestamp)), 'invalid_event');
      if (!await allowed(principal, task_id, name)) throw failure('not_authorized', -32001);
      return locked(async state => {
        const seen = createHash('sha256').update(JSON.stringify([principal, eventId])).digest('hex');
        state.seen = state.seen.filter(entry => entry.expires > now());
        if (state.seen.some(entry => entry.id === seen)) return { eventId, queued: 0 };
        requireValue(state.seen.length < 8192, 'dedupe_limit');
        const subscriptions = Object.values(state.subscriptions).filter(s => s.principal === principal && s.task === task_id && s.name === name && s.expires > now());
        requireValue(state.queue.length + subscriptions.length <= MAX_QUEUE, 'queue_limit');
        for (const sub of subscriptions) state.queue.push({ subscriptionId: sub.id, event: { eventId, name, timestamp, data: { task_id, summary }, cursor: null }, attempts: 0, due: now() });
        state.seen.push({ id: seen, expires: now() + maxTtlMs * 2 });
        return { eventId, queued: subscriptions.length };
      });
    },
    async deliverDue() {
      return locked(async (state, persist, owner, live) => {
        const counts = { delivered: 0, retried: 0, dropped: 0 };
        for (const sub of Object.values(state.subscriptions)) if (sub.principal === principal && (sub.expires <= now() || !await allowed(sub.principal, sub.task, sub.name, sub.filter))) drop(state, sub.id);
        let sent = 0;
        const remove = item => { state.queue = state.queue.filter(x => x !== item); };
        for (const item of [...state.queue]) {
          const sub = state.subscriptions[item.subscriptionId];
          if (!sub) { remove(item); counts.dropped++; continue; }
          if (item.claim) {
            if (live.has(item.claim.token)) continue;
            delete item.claim; // only a proven dead/changed owner may be recovered
            if (item.attempts >= maxAttempts) { remove(item); counts.dropped++; continue; }
          }
          if (sub.principal !== principal || item.due > now() || sent >= batchSize) continue;
          if (sub.expires <= now() || !await allowed(sub.principal, sub.task, sub.name, sub.filter)) { drop(state, sub.id); counts.dropped++; continue; }
          if (sub.rotationUntil <= now()) { delete sub.previousSecret; delete sub.rotationUntil; }
          sent++;
          item.attempts++;
          sub.delivery ??= { delivered: 0, dropped: 0 };
          sub.delivery.last_attempt_at = new Date(now()).toISOString();
          item.claim = { pid: process.pid, start: owner, token: randomBytes(16).toString('hex') };
          await persist(); // claim and attempt count MUST reach disk before any outbound data
          if (!await allowed(sub.principal, sub.task, sub.name, sub.filter)) { drop(state, sub.id); counts.dropped++; await persist(); continue; }
          let response; try { response = await signed(sub, JSON.stringify(item.event), item.event.eventId); } catch { response = { status: 0 }; }
          delete item.claim;
          sub.delivery.last_http_status = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : null;
          if (response.status >= 200 && response.status < 300) { remove(item); counts.delivered++; sub.delivery.delivered++; sub.delivery.last_ack_at = new Date(now()).toISOString(); }
          else if (response.status === 410) { drop(state, sub.id); counts.dropped++; }
          else if (response.status === 413 || (response.status >= 400 && response.status < 500 && ![408, 429].includes(response.status)) || item.attempts >= maxAttempts) { remove(item); counts.dropped++; sub.delivery.dropped++; }
          else { item.due = now() + Math.min(1000 * 2 ** (item.attempts - 1), 300000); counts.retried++; }
          await persist(); // commit ACK/retry before claiming the next event
        }
        return counts;
      });
    },
  };
}
