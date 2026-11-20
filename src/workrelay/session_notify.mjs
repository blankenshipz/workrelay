// Per-session progress notifications to the delegating agent (e.g. a Grok Bot
// routine webhook trigger). Opt-in by gateway config (session_notify.enabled)
// and per session by the caller (workrelay_server_create/message/resume
// `notify`, or workrelay_server_notify).
//
// Events are sent ONLY for: a new live permission ask, a run finishing, a
// child failing, or a run stalling. No per-step events. Permission asks and
// completion are never rate limited; everything else is limited to one event
// per session per min_interval_ms (default 2 minutes) and coalesced.
//
// Fail safe: delivery is fire-and-forget from a background poller. Errors are
// recorded as delivery status only; they never affect a tool call or a run.
// Targets (URL + optional secret header) live in a private 0600 state file and
// are never returned by any tool, log line or event payload.
import { randomBytes } from 'node:crypto';
import { openSync, closeSync, writeSync, fsyncSync, renameSync, readFileSync, lstatSync, unlinkSync, constants } from 'node:fs';
import { dirname, basename, join } from 'node:path';
import { isIP } from 'node:net';
import { createPinnedWebhookTransport } from './events.mjs';

const SID = /^ses[A-Za-z0-9_-]{1,160}$/;
const HEADER_NAME = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
// Headers a caller may never set: framing, routing, our own event headers.
const RESERVED_HEADERS = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade',
  'te', 'trailer', 'proxy-authorization', 'proxy-connection', 'expect', 'cookie', 'user-agent']);
const MINUTE = 60000;

export function validateSessionNotifySettings(value) {
  if (value === undefined) return;
  const ints = { stall_minutes: [1, 1440], min_interval_ms: [30000, 3600000], poll_interval_ms: [5000, 600000], max_targets: [1, 1000], ttl_hours: [1, 720] };
  const ok = value && typeof value === 'object' && !Array.isArray(value) && value.enabled === true &&
    Object.keys(value).every(key => ['enabled', 'state_file', ...Object.keys(ints)].includes(key)) &&
    (value.state_file === undefined || typeof value.state_file === 'string' && value.state_file.startsWith('/') && !value.state_file.split('/').includes('..')) &&
    Object.entries(ints).every(([key, [min, max]]) => value[key] === undefined || Number.isSafeInteger(value[key]) && value[key] >= min && value[key] <= max);
  if (!ok) throw Error('invalid session_notify configuration');
}

// Caller-supplied target. Public HTTPS only (no IP literals, credentials,
// fragments or non-443 ports); the pinned transport additionally rejects any
// DNS answer that is not a public address, at send time, and never redirects.
export function validateNotifyTarget(input) {
  const fail = reason => { throw Object.assign(Error('invalid notify target'), { reason }); };
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('invalid_target');
  if (Object.keys(input).some(key => !['url', 'header_name', 'header_value', 'stall_minutes'].includes(key))) fail('unknown_field');
  let url;
  try { url = new URL(input.url); } catch { fail('invalid_url'); }
  if (typeof input.url !== 'string' || input.url.length > 2048 || url.protocol !== 'https:' || url.username || url.password || url.hash ||
      (url.port && url.port !== '443') || isIP(url.hostname) || url.hostname.startsWith('[') || !url.hostname.includes('.') ||
      /(^|\.)(localhost|local|internal|invalid|test|example|lan|home|arpa)$/i.test(url.hostname)) fail('invalid_url');
  if ((input.header_name === undefined) !== (input.header_value === undefined)) fail('header_pair_required');
  if (input.header_name !== undefined && (typeof input.header_name !== 'string' || !HEADER_NAME.test(input.header_name) ||
      RESERVED_HEADERS.has(input.header_name.toLowerCase()) || /^x-workrelay-/i.test(input.header_name) || /^webhook-/i.test(input.header_name))) fail('invalid_header_name');
  if (input.header_value !== undefined && (typeof input.header_value !== 'string' || !input.header_value.length || input.header_value.length > 1024 ||
      !/^[\x20-\x7e]+$/.test(input.header_value))) fail('invalid_header_value');
  if (input.stall_minutes !== undefined && (!Number.isSafeInteger(input.stall_minutes) || input.stall_minutes < 1 || input.stall_minutes > 1440)) fail('invalid_stall_minutes');
  return { url: url.href, ...(input.header_name ? { header_name: input.header_name, header_value: input.header_value } : {}),
    ...(input.stall_minutes ? { stall_minutes: input.stall_minutes } : {}) };
}

// Private state file: owner-only directory and file, atomic replace, no symlinks.
function loadState(path) {
  let fd;
  try {
    const dir = lstatSync(dirname(path));
    if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || dir.mode & 0o077) return {};
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const text = readFileSync(fd, 'utf8');
    const data = JSON.parse(text);
    return data?.version === 1 && data.targets && typeof data.targets === 'object' ? data.targets : {};
  } catch { return {}; }
  finally { if (fd !== undefined) closeSync(fd); }
}
function saveState(path, targets) {
  const dir = lstatSync(dirname(path));
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || dir.mode & 0o077) throw Error('notify state directory not private');
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(fd, JSON.stringify({ version: 1, targets })); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, path); } catch (error) { try { unlinkSync(temporary); } catch { /* ignored */ } throw error; }
}

const BUSY = new Set(['running', 'blocked_on_permission']);

/**
 * createSessionNotifier({ watch, settings, approvalUrl })
 * watch(session_id) -> operator-only session_watch projection (see managed_server.mjs).
 * Returns { set, clear, get, tick, start, stop }.
 */
export function createSessionNotifier({ watch, settings = {}, approvalUrl, statePath, transport = createPinnedWebhookTransport({ timeoutMs: 10000 }),
  now = Date.now, log = () => {} } = {}) {
  if (typeof watch !== 'function') throw Error('session notifier requires watch');
  const stallDefault = (settings.stall_minutes ?? 10) * MINUTE;
  const minInterval = settings.min_interval_ms ?? 2 * MINUTE;
  const maxTargets = settings.max_targets ?? 200;
  const ttl = (settings.ttl_hours ?? 72) * 60 * MINUTE;
  const targets = new Map(Object.entries(statePath ? loadState(statePath) : {}).filter(([id, t]) => SID.test(id) && typeof t?.url === 'string'));
  const persist = () => {
    if (!statePath) return;
    try { saveState(statePath, Object.fromEntries(targets)); } catch { log('session notify state not saved'); }
  };
  const publicStatus = (id, t) => t ? { session_id: id, enabled: true, url_host: new URL(t.url).host, secret_header: t.header_name ?? null,
    stall_minutes: Math.round((t.stall_ms ?? stallDefault) / MINUTE), registered_at: new Date(t.registered_at).toISOString(), expires_at: new Date(t.expires_at).toISOString(),
    delivered: t.delivered ?? 0, failed: t.failed ?? 0, last_delivery: t.last_delivery ?? null } : { session_id: id, enabled: false };

  // A target is "settled" after its finished event until new work is seen.
  const settled = t => t.finished_sent && !t.saw_work;
  function set(sessionID, rawTarget, at = now()) {
    if (!SID.test(sessionID ?? '')) throw Object.assign(Error('invalid session'), { reason: 'invalid_session' });
    const target = validateNotifyTarget(rawTarget);
    let t = targets.get(sessionID);
    if (!t && targets.size >= maxTargets) {
      // Evict a settled target first (oldest), else the oldest registration.
      const order = [...targets].sort((a, b) => Number(settled(b[1])) - Number(settled(a[1])) || a[1].registered_at - b[1].registered_at);
      targets.delete(order[0][0]);
    }
    if (!t) { t = { notified: [], saw_work: false, outbox: [], armed_at: at }; targets.set(sessionID, t); }
    // Mutate in place: a tick in progress may hold this object, and
    // re-registering must keep dedupe/run state so asks are not re-sent.
    Object.assign(t, { url: target.url, header_name: target.header_name, header_value: target.header_value,
      stall_ms: target.stall_minutes ? target.stall_minutes * MINUTE : undefined, registered_at: at, expires_at: Math.max(t.expires_at ?? 0, at + ttl) });
    if (!t.armed_at && !t.saw_work) t.armed_at = at; // a run ending after registration is reported
    persist();
    return publicStatus(sessionID, t);
  }
  function clear(sessionID) { const had = targets.delete(sessionID); if (had) persist(); return { session_id: sessionID, enabled: false, cleared: had }; }
  function get(sessionID) { return publicStatus(sessionID, targets.get(sessionID)); }

  // The delegating agent started/continued work (message/resume/steer).
  // `at` is taken BEFORE the native request, so a run that ends before the
  // tool returns still has idle_at > armed_at and is reported.
  function armed(sessionID, at = now()) {
    const t = targets.get(sessionID); if (!t) return;
    // Not yet "saw work": a queued message may not have started. Completion
    // needs an observed busy tree or a root idle transition after `at`.
    t.saw_work = false; t.armed_at = at; t.finished_sent = false; t.last_progress_at = now(); t.stall_sent = false; t.last_observed_at = 0;
    t.expires_at = Math.max(t.expires_at, now() + ttl); persist();
  }

  const IMPORTANT = new Set(['permission_asked', 'finished', 'failed']);
  function enqueue(t, sessionID, type, fields, { limited }) {
    const at = now();
    if (limited && at - (t.last_limited_at ?? 0) < minInterval) {
      // Coalesce inside the window: merge child failures, otherwise keep the newest.
      if (type === 'child_failed' && t.deferred?.type === 'child_failed')
        fields = { ...fields, child_session_ids: [...new Set([...t.deferred.fields.child_session_ids, ...fields.child_session_ids])].slice(0, 10) };
      t.deferred = { type, fields }; return;
    }
    if (limited) { t.last_limited_at = at; t.deferred = undefined; }
    const event = { type: `workrelay.session.${type}`, event_id: 'evt_' + randomBytes(12).toString('hex'), session_id: sessionID, at: new Date(at).toISOString(), ...fields };
    t.outbox = [...(t.outbox ?? []), { event, attempts: 0, next_at: at }].slice(-20);
  }
  function flushDeferred(t, sessionID) {
    if (t.deferred && now() - (t.last_limited_at ?? 0) >= minInterval) { const { type, fields } = t.deferred; enqueue(t, sessionID, type, fields, { limited: true }); }
  }

  async function deliver(sessionID, t) {
    // At most 3 sends per target per tick; targets are delivered concurrently.
    const ready = (t.outbox ?? []).filter(item => item.next_at <= now()).slice(0, 3);
    for (const item of ready) {
      item.attempts++;
      try {
        const response = await transport(t.url, { body: JSON.stringify(item.event), headers: { 'Content-Type': 'application/json',
          'User-Agent': 'workrelay-notify/1', 'X-Workrelay-Event': item.event.type, 'X-Workrelay-Event-Id': item.event.event_id,
          ...(t.header_name ? { [t.header_name]: t.header_value } : {}) } });
        const ok = response?.status >= 200 && response.status < 300;
        t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok, status: response?.status ?? null };
        if (ok || response?.status >= 400 && response.status < 500 && response.status !== 429) {
          t.outbox = t.outbox.filter(entry => entry !== item); t[ok ? 'delivered' : 'failed'] = (t[ok ? 'delivered' : 'failed'] ?? 0) + 1; continue;
        }
      } catch (error) {
        t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok: false, error: error?.data?.reason ?? 'network_error' };
      }
      // Asks and completion retry for ~25 minutes; other events 3 times.
      const important = IMPORTANT.has(item.event.type.slice('workrelay.session.'.length));
      if (item.attempts >= (important ? 10 : 3)) { t.outbox = t.outbox.filter(entry => entry !== item); t.failed = (t.failed ?? 0) + 1; }
      else item.next_at = now() + Math.min(30000 * item.attempts, 5 * MINUTE);
    }
  }

  async function observe(sessionID, t) {
    // Settled targets are checked every 2 minutes (to notice a new run started
    // elsewhere) instead of every poll.
    if (settled(t) && now() - (t.last_observed_at ?? 0) < 2 * MINUTE) return;
    t.last_observed_at = now();
    let view;
    try { view = await watch(sessionID); t.watch_failures = 0; }
    catch {
      t.watch_failures = (t.watch_failures ?? 0) + 1;
      if (t.watch_failures === 10) enqueue(t, sessionID, 'unobservable', { summary: 'Workrelay cannot observe this session (gateway binding or native server unavailable, or session removed). Use workrelay_server_read to check.' }, { limited: true });
      flushDeferred(t, sessionID);
      return;
    }
    const at = now();
    const base = { title: view.title, status: view.aggregate_status };
    // 1) New live permission asks: immediate, deduped by permission id.
    const notified = new Set(t.notified ?? []);
    const fresh = (view.pending ?? []).filter(item => !notified.has(item.permission_id));
    if (fresh.length) {
      for (const item of fresh) notified.add(item.permission_id);
      t.notified = [...notified].slice(-200);
      enqueue(t, sessionID, 'permission_asked', { ...base, directory: view.directory, asks: fresh.slice(0, 5).map(item => ({ permission_id: item.permission_id,
        child_session_id: item.session_id, action: item.action, resource_preview: item.resource_preview, resources_omitted: item.resources_omitted,
        directory: item.directory })), asks_omitted: Math.max(0, fresh.length - 5),
        decision: 'human_operator_only', ...(approvalUrl ? { approval_url: approvalUrl } : {}),
        guidance: 'A human operator must approve or deny on the Workrelay operator page; no agent tool can. Tell the human, then wait for the next event or read the session.' }, { limited: false });
    }
    // Progress bookkeeping for stall detection.
    const signature = JSON.stringify([view.last_activity_at, view.aggregate_status, view.running_children, (view.pending ?? []).length]);
    if (signature !== t.signature) {
      t.signature = signature; t.last_progress_at = at; t.stall_sent = false;
      if (t.deferred?.type === 'stalled') t.deferred = undefined; // progress resumed
    }
    const busy = BUSY.has(view.aggregate_status) || view.root_active === true || view.running_children > 0 || (view.pending ?? []).length > 0;
    if (busy) {
      // A new run (also one started outside workrelay) re-opens completion.
      if (t.finished_sent) { t.finished_sent = false; t.failed_children = []; }
      t.saw_work = true; t.expires_at = Math.max(t.expires_at, at + ttl);
    } else if (t.armed_at && Number.isSafeInteger(view.idle_at) && view.idle_at > t.armed_at) t.saw_work = true;
    // 2) Completion: the tree was busy since registration/arming and is now
    // not. A truncated tree (unknown aggregate) counts when the root is not
    // running and no visible child is running.
    if (!busy && t.saw_work && !t.finished_sent) {
      t.finished_sent = true; t.saw_work = false; t.armed_at = undefined; t.deferred = undefined;
      enqueue(t, sessionID, view.runtime_status === 'failed' ? 'failed' : 'finished', { ...base, outcome: view.runtime_status, task_outcome: view.task_outcome,
        ...((view.failed_children ?? []).length ? { failed_child_session_ids: view.failed_children.slice(0, 10) } : {}),
        ...(view.tree_truncated ? { tree_truncated: true } : {}),
        next: { tool: 'workrelay_server_read', arguments: { session_id: sessionID, include_messages: true } },
        guidance: 'Runtime completion is not verified task success; read the session for the result.' }, { limited: false });
    }
    // 3) Child failures while the run continues (rate limited, merged).
    const failed = (view.failed_children ?? []).filter(id => !(t.failed_children ?? []).includes(id));
    if (failed.length && busy) {
      t.failed_children = [...(t.failed_children ?? []), ...failed].slice(-50);
      enqueue(t, sessionID, 'child_failed', { ...base, child_session_ids: failed.slice(0, 10) }, { limited: true });
    }
    // 4) Stall: running (not waiting on a human) with no observed progress.
    const stallMs = t.stall_ms ?? stallDefault;
    if (busy && !(view.pending ?? []).length && !t.stall_sent && at - (t.last_progress_at ?? at) >= stallMs) {
      t.stall_sent = true;
      enqueue(t, sessionID, 'stalled', { ...base, idle_minutes: Math.floor((at - t.last_progress_at) / MINUTE),
        guidance: 'No observed progress. Read the session; consider steer or interrupt.' }, { limited: true });
    }
    flushDeferred(t, sessionID);
  }

  let running = false;
  async function tick() {
    if (running) return; running = true;
    try {
      const before = JSON.stringify([...targets]);
      const live = [];
      for (const [sessionID, t] of [...targets]) {
        if (t.expires_at <= now()) { targets.delete(sessionID); continue; }
        try { await observe(sessionID, t); } catch { /* never let one target stop the loop */ }
        live.push([sessionID, t]);
      }
      // One slow receiver must not delay another session's events.
      await Promise.allSettled(live.map(([sessionID, t]) => deliver(sessionID, t)));
      if (JSON.stringify([...targets]) !== before) persist();
    } finally { running = false; }
  }
  let timer;
  return { set, clear, get, armed, tick,
    size: () => targets.size,
    start() { if (!timer) { timer = setInterval(() => { void tick().catch(() => {}); }, settings.poll_interval_ms ?? 30000); timer.unref?.(); } },
    stop() { clearInterval(timer); timer = undefined; } };
}
