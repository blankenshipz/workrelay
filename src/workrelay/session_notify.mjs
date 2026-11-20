// Per-session progress notifications to the delegating agent, on any agent
// platform: a Grok Bot routine webhook, a Slack incoming webhook, ntfy, or any
// agent's HTTP hook. Opt-in by gateway config (session_notify.enabled).
// Targets come from, in order of precedence:
//  - the caller, per session (workrelay_server_create/message/resume `notify`,
//    or workrelay_server_notify scope session),
//  - the caller's own client default: each MCP client (OAuth client_id)
//    registers its listener once (workrelay_server_notify scope client, or the
//    notify-register.mjs CLI on the workrelay host) and it applies to every
//    session that client creates, messages or resumes. Stored in a private
//    0600 clients file, resolved at send time, never returned, or
//  - an optional operator fallback (session_notify.default_targets), matched by
//    session directory glob and/or OAuth client id. Its URL/header/HMAC secrets
//    live in a private 0600 secrets file or environment variables, never in the
//    gateway config, and are resolved at send time (never copied to state).
// A per-call target overrides a default; `notify: false` (or the notify tool's
// clear) opts the session out of defaults.
//
// Events are sent ONLY for: a new live permission ask, a run finishing, a
// child failing, or a run stalling. No per-step events. Permission asks and
// completion are never rate limited; everything else is limited to one event
// per session per min_interval_ms (default 2 minutes) and coalesced.
//
// Fail safe: delivery is fire-and-forget from a background poller. Errors are
// recorded as delivery status only; they never affect a tool call or a run.
// Secrets (URL path, header value, HMAC secret) are never returned by any
// tool, log line or event payload; tools see only the URL host and flags.
import { createHmac, randomBytes } from 'node:crypto';
import { openSync, closeSync, writeSync, fsyncSync, fstatSync, renameSync, readFileSync, lstatSync, unlinkSync, constants } from 'node:fs';
import { dirname, basename, join, isAbsolute, resolve as resolvePath } from 'node:path';
import { isIP } from 'node:net';
import { createPinnedWebhookTransport } from './events.mjs';

const SID = /^ses[A-Za-z0-9_-]{1,160}$/;
const HEADER_NAME = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
const TARGET_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const NOTIFY_FORMATS = ['json', 'slack', 'text'];
export const EVENT_SCHEMA_VERSION = 1;
// Headers a caller may never set: framing, routing, our own event headers.
const RESERVED_HEADERS = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade',
  'te', 'trailer', 'proxy-authorization', 'proxy-connection', 'expect', 'cookie', 'user-agent']);
const MINUTE = 60000;
const TARGET_FIELDS = ['url', 'header_name', 'header_value', 'hmac_secret', 'format', 'stall_minutes'];

const safePath = value => typeof value === 'string' && value.length <= 4096 && isAbsolute(value) && resolvePath(value) === value;

function validateDefaultTarget(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  if (!Object.keys(entry).every(key => ['name', 'secret', 'env', 'directories', 'clients', 'format', 'stall_minutes'].includes(key))) return false;
  if (typeof entry.name !== 'string' || !TARGET_NAME.test(entry.name)) return false;
  if ((entry.secret === undefined) === (entry.env === undefined)) return false; // exactly one secret source
  if (entry.secret !== undefined && (typeof entry.secret !== 'string' || !TARGET_NAME.test(entry.secret))) return false;
  if (entry.env !== undefined && (!entry.env || typeof entry.env !== 'object' || Array.isArray(entry.env) || typeof entry.env.url !== 'string' ||
      !Object.entries(entry.env).every(([key, value]) => ['url', 'header_name', 'header_value', 'hmac_secret'].includes(key) && typeof value === 'string' && ENV_NAME.test(value)))) return false;
  if (entry.directories !== undefined && (!Array.isArray(entry.directories) || !entry.directories.length || entry.directories.length > 100 ||
      !entry.directories.every(glob => typeof glob === 'string' && glob.length <= 4096 && glob.startsWith('/') && !glob.split('/').includes('..') && !glob.split('/').includes('.')))) return false;
  if (entry.clients !== undefined && (!Array.isArray(entry.clients) || !entry.clients.length || entry.clients.length > 50 ||
      !entry.clients.every(client => typeof client === 'string' && client.length >= 1 && client.length <= 512))) return false;
  if (entry.format !== undefined && !NOTIFY_FORMATS.includes(entry.format)) return false;
  if (entry.stall_minutes !== undefined && (!Number.isSafeInteger(entry.stall_minutes) || entry.stall_minutes < 1 || entry.stall_minutes > 1440)) return false;
  return true;
}

export function validateSessionNotifySettings(value) {
  if (value === undefined) return;
  const ints = { stall_minutes: [1, 1440], min_interval_ms: [30000, 3600000], poll_interval_ms: [5000, 600000], max_targets: [1, 1000], ttl_hours: [1, 720] };
  const defaults = value?.default_targets;
  const ok = value && typeof value === 'object' && !Array.isArray(value) && value.enabled === true &&
    Object.keys(value).every(key => ['enabled', 'state_file', 'secrets_file', 'clients_file', 'default_targets', ...Object.keys(ints)].includes(key)) &&
    (value.state_file === undefined || typeof value.state_file === 'string' && value.state_file.startsWith('/') && !value.state_file.split('/').includes('..')) &&
    (value.secrets_file === undefined || safePath(value.secrets_file)) && (value.clients_file === undefined || safePath(value.clients_file)) &&
    (defaults === undefined || Array.isArray(defaults) && defaults.length <= 50 && defaults.every(validateDefaultTarget) &&
      new Set(defaults.map(entry => entry.name)).size === defaults.length &&
      (value.secrets_file !== undefined || defaults.every(entry => entry.secret === undefined))) &&
    Object.entries(ints).every(([key, [min, max]]) => value[key] === undefined || Number.isSafeInteger(value[key]) && value[key] >= min && value[key] <= max);
  if (!ok) throw Error('invalid session_notify configuration');
}

// Where the notifier keeps its private files for a validated gateway config:
// the state file and the per-client defaults file (shared with the CLI).
export function sessionNotifyPaths(config) {
  const settings = config?.session_notify ?? {};
  const base = config?.managed_supervisor_file ? dirname(config.managed_supervisor_file) : null;
  return { statePath: settings.state_file ?? (base && join(base, 'session-notify.json')),
    clientsPath: settings.clients_file ?? (base && join(base, 'notify-clients.json')) };
}

// Standard Webhooks (https://www.standardwebhooks.com) HMAC-SHA256 signature:
// base64(HMAC(key, `${id}.${timestamp}.${body}`)), sent as `v1,<sig>`. The
// secret is `whsec_<base64>` (24-64 key bytes, as for MCP Events); the decoded
// bytes are the key, exactly as Standard Webhooks libraries expect.
export function signStandardWebhook(secret, id, timestamp, body) {
  const key = Buffer.from(secret.slice(6), 'base64');
  return 'v1,' + createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest('base64');
}

function validHmacSecret(secret) {
  if (typeof secret !== 'string' || !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) return false;
  const bytes = Buffer.from(secret.slice(6), 'base64');
  return bytes.length >= 24 && bytes.length <= 64 && bytes.toString('base64') === secret.slice(6);
}

// Caller-supplied target. Public HTTPS only (no IP literals, credentials,
// fragments or non-443 ports); the pinned transport additionally rejects any
// DNS answer that is not a public address, at send time, and never redirects.
export function validateNotifyTarget(input) {
  const fail = reason => { throw Object.assign(Error('invalid notify target'), { reason }); };
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('invalid_target');
  if (Object.keys(input).some(key => !TARGET_FIELDS.includes(key))) fail('unknown_field');
  let url;
  try { url = new URL(input.url); } catch { fail('invalid_url'); }
  // A trailing-dot FQDN (`localhost.`) must not slip past the name checks.
  if (url.hostname.endsWith('.')) fail('invalid_url');
  if (typeof input.url !== 'string' || input.url.length > 2048 || url.protocol !== 'https:' || url.username || url.password || url.hash ||
      (url.port && url.port !== '443') || isIP(url.hostname) || url.hostname.startsWith('[') || !url.hostname.includes('.') ||
      /(^|\.)(localhost|local|internal|invalid|test|example|lan|home|arpa)$/i.test(url.hostname)) fail('invalid_url');
  if ((input.header_name === undefined) !== (input.header_value === undefined)) fail('header_pair_required');
  if (input.header_name !== undefined && (typeof input.header_name !== 'string' || !HEADER_NAME.test(input.header_name) ||
      RESERVED_HEADERS.has(input.header_name.toLowerCase()) || /^x-workrelay-/i.test(input.header_name) || /^webhook-/i.test(input.header_name))) fail('invalid_header_name');
  if (input.header_value !== undefined && (typeof input.header_value !== 'string' || !input.header_value.length || input.header_value.length > 1024 ||
      !/^[\x20-\x7e]+$/.test(input.header_value))) fail('invalid_header_value');
  if (input.hmac_secret !== undefined && !validHmacSecret(input.hmac_secret)) fail('invalid_hmac_secret');
  if (input.format !== undefined && !NOTIFY_FORMATS.includes(input.format)) fail('invalid_format');
  if (input.stall_minutes !== undefined && (!Number.isSafeInteger(input.stall_minutes) || input.stall_minutes < 1 || input.stall_minutes > 1440)) fail('invalid_stall_minutes');
  return { url: url.href, ...(input.header_name ? { header_name: input.header_name, header_value: input.header_value } : {}),
    ...(input.hmac_secret ? { hmac_secret: input.hmac_secret } : {}), ...(input.format && input.format !== 'json' ? { format: input.format } : {}),
    ...(input.stall_minutes ? { stall_minutes: input.stall_minutes } : {}) };
}

// Private file checks shared by the state and secrets files: owner-only
// directory, regular owner-only file, no symlinks.
function privateDirectory(path) {
  const dir = lstatSync(dirname(path));
  return dir.isDirectory() && !dir.isSymbolicLink() && dir.uid === process.getuid() && !(dir.mode & 0o077);
}
function readPrivateJSON(path, maxBytes = 65536) {
  if (!privateDirectory(path)) throw Object.assign(Error('not private'), { reason: 'secrets_file_not_private' });
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.mode & 0o077 || stat.size > maxBytes) throw Object.assign(Error('not private'), { reason: 'secrets_file_not_private' });
    return JSON.parse(readFileSync(fd, 'utf8'));
  } finally { closeSync(fd); }
}

// `/a/b` matches /a/b and anything below it; globs (`*` one segment, `**` any
// depth, `?` one character) match the whole path.
export function directoryMatcher(globs) {
  const patterns = globs.map(raw => {
    const glob = raw.length > 1 ? raw.replace(/\/+$/, '') : raw; // `/a/b/` means `/a/b`
    if (!/[*?]/.test(glob)) return directory => directory === glob || directory.startsWith(glob === '/' ? '/' : glob + '/');
    let source = '';
    for (let i = 0; i < glob.length; i++) {
      if (glob.startsWith('/**', i) && (i + 3 === glob.length || glob[i + 3] === '/')) { source += '(?:/.*)?'; i += 2; }
      else if (glob.startsWith('**', i)) { source += '.*'; i += 1; }
      else if (glob[i] === '*') source += '[^/]*';
      else if (glob[i] === '?') source += '[^/]';
      else source += glob[i].replace(/[\\^$.|+()[\]{}]/g, '\\$&');
    }
    const regex = new RegExp(`^${source}$`);
    return directory => regex.test(directory);
  });
  return directory => typeof directory === 'string' && patterns.some(test => test(directory));
}

/**
 * Gateway default targets. Matching uses only config; secrets are read at
 * use time from the private secrets file or the environment, so filling the
 * secrets file takes effect without a restart and secrets never enter the
 * notifier state file.
 */
export function createDefaultTargets({ entries = [], secretsFile, env = process.env } = {}) {
  const compiled = entries.map(entry => ({ ...entry, matchDirectory: entry.directories ? directoryMatcher(entry.directories) : () => true }));
  const byName = new Map(compiled.map(entry => [entry.name, entry]));
  const clientMatches = (entry, clientID) => !entry.clients || entry.clients.includes(clientID);
  return {
    size: compiled.length,
    has: name => byName.has(name),
    // Any default that could apply to this client (directory not yet known).
    mayMatch: clientID => compiled.some(entry => clientMatches(entry, clientID)),
    match: ({ directory, client_id: clientID }) => compiled.find(entry => clientMatches(entry, clientID) && entry.matchDirectory(directory)) ?? null,
    resolve(name) {
      const entry = byName.get(name);
      if (!entry) return { reason: 'default_target_removed' };
      let raw;
      if (entry.secret !== undefined) {
        let file;
        try { file = readPrivateJSON(secretsFile); } catch (error) { return { reason: error.reason ?? 'secrets_file_unavailable' }; }
        if (file?.version !== 1 || !file.targets || typeof file.targets !== 'object' || Array.isArray(file.targets)) return { reason: 'secrets_file_invalid' };
        raw = file.targets[entry.secret];
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { reason: 'secret_entry_missing' };
      } else raw = Object.fromEntries(Object.entries(entry.env).map(([key, variable]) => [key, env[variable]]));
      // Empty values are "not set": a placeholder entry is inert.
      const fields = Object.fromEntries(Object.entries(raw).filter(([key, value]) => ['url', 'header_name', 'header_value', 'hmac_secret', 'format'].includes(key) &&
        value !== undefined && value !== null && value !== ''));
      if (!fields.url) return { reason: 'url_not_configured' };
      try { return { target: validateNotifyTarget({ ...(entry.format ? { format: entry.format } : {}), ...fields }), stall_minutes: entry.stall_minutes }; }
      catch (error) { return { reason: `secret_entry_${error.reason ?? 'invalid'}` }; }
    },
  };
}

// Redacted view of a resolved target: never the URL path, header value or HMAC secret.
export function redactTarget(target) {
  return { url_host: target ? new URL(target.url).host : null, secret_header: target?.header_name ?? null, signed: Boolean(target?.hmac_secret),
    format: target?.format ?? 'json' };
}

const CLIENT_ID = /^[\x21-\x7e]{1,512}$/;
export const validClientID = value => typeof value === 'string' && CLIENT_ID.test(value) && !['__proto__', 'constructor', 'prototype'].includes(value);
const MAX_CLIENTS = 100;

/**
 * Per-client default targets ("register your own listener once"). Keyed by the
 * authenticated OAuth client_id. Stored in a private 0600 file (owner-only
 * directory, no symlinks, atomic replace) that both the gateway and the
 * notify-register CLI write; read at use time, so CLI changes apply without a
 * restart. Secrets are never returned: callers see only redacted views.
 */
export function createClientDefaults({ file, now = Date.now } = {}) {
  // { state: 'present', entry } | { state: 'absent' } | { state: 'error', reason }
  function readAll() {
    if (!file) return { clients: new Map() };
    let data;
    try { data = readPrivateJSON(file, 524288); }
    catch (error) { return error?.code === 'ENOENT' ? { clients: new Map() } : { error: error.reason ?? 'clients_file_unavailable' }; }
    if (data?.version !== 1 || !data.clients || typeof data.clients !== 'object' || Array.isArray(data.clients)) return { error: 'clients_file_invalid' };
    return { clients: new Map(Object.entries(data.clients).filter(([id, entry]) => validClientID(id) && entry && typeof entry === 'object' && !Array.isArray(entry))) };
  }
  function lookup(clientID) {
    if (!validClientID(clientID)) return { state: 'absent' };
    const all = readAll();
    if (all.error) return { state: 'error', reason: all.error };
    const entry = all.clients.get(clientID);
    return entry ? { state: 'present', entry } : { state: 'absent' };
  }
  function resolveEntry(entry) {
    const { stall_minutes: stall, ...fields } = Object.fromEntries(Object.entries(entry).filter(([key]) => TARGET_FIELDS.includes(key)));
    try { return { target: validateNotifyTarget(fields), ...(stall ? { stall_minutes: stall } : {}) }; }
    catch (error) { return { reason: `client_default_${error.reason ?? 'invalid'}` }; }
  }
  function view(clientID, entry) {
    const resolved = resolveEntry(entry);
    return { client_id: clientID, configured: Boolean(resolved.target), ...(resolved.reason ? { reason: resolved.reason } : {}), ...redactTarget(resolved.target),
      ...(entry.stall_minutes ? { stall_minutes: entry.stall_minutes } : {}), updated_at: entry.updated_at ?? null, updated_by: entry.updated_by ?? null };
  }
  function write(clients) {
    writePrivateJSON(file, { version: 1, clients: Object.fromEntries(clients) });
  }
  const fail = reason => { throw Object.assign(Error('client default unavailable'), { reason }); };
  return {
    lookup,
    any: () => { const all = readAll(); return Boolean(all.error || all.clients.size); },
    resolve(clientID) {
      const found = lookup(clientID);
      if (found.state === 'error') return { reason: found.reason };
      if (found.state === 'absent') return { reason: 'client_default_removed' };
      return resolveEntry(found.entry);
    },
    get(clientID) { const found = lookup(clientID); return found.state === 'present' ? view(clientID, found.entry) : found.state === 'error' ? { client_id: clientID, error: found.reason } : null; },
    list() { const all = readAll(); return all.error ? { error: all.error } : { clients: [...all.clients].map(([id, entry]) => view(id, entry)) }; },
    // `by` is a non-secret label ("mcp" or "cli") recorded for operators.
    set(clientID, rawTarget, { by = 'mcp' } = {}) {
      if (!file) fail('clients_file_not_configured');
      if (!validClientID(clientID)) fail('invalid_client_id');
      const target = validateNotifyTarget(rawTarget);
      const all = readAll();
      if (all.error) fail(all.error);
      if (!all.clients.has(clientID) && all.clients.size >= MAX_CLIENTS) fail('too_many_clients');
      all.clients.set(clientID, { ...target, updated_at: new Date(now()).toISOString(), updated_by: by });
      write(all.clients);
      return view(clientID, all.clients.get(clientID));
    },
    clear(clientID) {
      if (!file) fail('clients_file_not_configured');
      const all = readAll();
      if (all.error) fail(all.error);
      const had = all.clients.delete(clientID);
      if (had) write(all.clients);
      return { client_id: clientID, cleared: had };
    },
  };
}

function writePrivateJSON(path, data) {
  if (!privateDirectory(path)) throw Object.assign(Error('directory not private'), { reason: 'directory_not_private' });
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(fd, JSON.stringify(data)); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, path); } catch (error) { try { unlinkSync(temporary); } catch { /* ignored */ } throw error; }
}

// Private state file: owner-only directory and file, atomic replace, no symlinks.
function loadState(path) {
  let fd;
  try {
    if (!privateDirectory(path)) return {};
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const text = readFileSync(fd, 'utf8');
    const data = JSON.parse(text);
    return data?.version === 1 && data.targets && typeof data.targets === 'object' ? data : {};
  } catch { return {}; }
  finally { if (fd !== undefined) closeSync(fd); }
}
function saveState(path, state) { writePrivateJSON(path, { version: 1, ...state }); }

// Human/agent readable one-line summary. Titles are untrusted session text.
function summarize(type, fields) {
  const name = `"${fields.title || 'untitled'}" (${fields.session_id})`;
  switch (type) {
    case 'permission_asked': {
      const actions = [...new Set(fields.asks.map(ask => ask.action))].join(', ');
      const count = fields.asks.length + fields.asks_omitted;
      return `Session ${name} needs human approval: ${count} permission ask${count === 1 ? '' : 's'} (${actions}). Only a human operator can approve or deny, on the Workrelay operator page.`;
    }
    case 'finished': return `Session ${name} finished (outcome: ${fields.outcome ?? 'unknown'}). Read the session for the result; runtime completion is not verified task success.`;
    case 'failed': return `Session ${name} failed. Read the session to see what happened.`;
    case 'child_failed': return `Session ${name}: ${fields.child_session_ids.length} child session${fields.child_session_ids.length === 1 ? '' : 's'} failed while the run continues.`;
    case 'stalled': return `Session ${name} has shown no progress for ${fields.idle_minutes} minutes. Read it; consider steer or interrupt.`;
    default: return `Workrelay cannot observe session ${name}.`;
  }
}
const slackEscape = text => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function renderText(event) {
  return `[workrelay] ${event.summary}` + (event.read ? `\nNext: ${event.read.tool} ${JSON.stringify(event.read.arguments)}` : '') +
    (event.approval_url ? `\nApprove: ${event.approval_url}` : '');
}
// Body + content type for a target format. json is the canonical event.
export function renderNotifyBody(event, format = 'json') {
  if (format === 'slack') return { body: JSON.stringify({ text: slackEscape(renderText(event)) }), contentType: 'application/json' };
  if (format === 'text') return { body: renderText(event), contentType: 'text/plain; charset=utf-8' };
  return { body: JSON.stringify(event), contentType: 'application/json' };
}

// One POST of an event to a resolved target. Standard Webhooks headers when
// the target has an hmac_secret: stable id (event_id), fresh timestamp and
// signature per attempt. Resolves to the HTTP status; throws on network errors.
export async function postNotifyEvent(target, event, { transport, now = Date.now }) {
  const { body, contentType } = renderNotifyBody(event, target.format);
  const timestamp = String(Math.floor(now() / 1000));
  const response = await transport(target.url, { body, headers: { 'Content-Type': contentType,
    'User-Agent': 'workrelay-notify/1', 'X-Workrelay-Event': event.type, 'X-Workrelay-Event-Id': event.event_id,
    ...(target.hmac_secret ? { 'webhook-id': event.event_id, 'webhook-timestamp': timestamp,
      'webhook-signature': signStandardWebhook(target.hmac_secret, event.event_id, timestamp, body) } : {}),
    ...(target.header_name ? { [target.header_name]: target.header_value } : {}) } });
  return response?.status ?? null;
}

// `workrelay.test`: sent only on request (notify tool action test, or the CLI)
// so a newly set up listener can be verified end to end. Receivers ignore it.
export function testNotifyEvent({ sessionID, serverId, scope, now = Date.now } = {}) {
  return { type: 'workrelay.test', schema_version: EVENT_SCHEMA_VERSION, event_id: 'evt_' + randomBytes(12).toString('hex'), source: 'workrelay',
    ...(sessionID ? { session_id: sessionID } : {}), ...(serverId ? { server_id: serverId } : {}), ...(scope ? { scope } : {}),
    at: new Date(now()).toISOString(),
    summary: 'Workrelay test event: this listener is set up correctly. No action needed.',
    guidance: 'Verification only. Do not call any tool; real events have types workrelay.session.*.' };
}

// Sends a test event and reports the outcome (no secrets).
export async function sendTestEvent(target, event, { transport, now = Date.now }) {
  try {
    const status = await postNotifyEvent(target, event, { transport, now });
    return { sent: true, ok: status >= 200 && status < 300, status, event_id: event.event_id, ...redactTarget(target) };
  } catch (error) {
    return { sent: false, ok: false, delivery_error: error?.data?.reason ?? 'network_error', event_id: event.event_id, ...redactTarget(target) };
  }
}

const BUSY = new Set(['running', 'blocked_on_permission']);

/**
 * createSessionNotifier({ watch, settings, approvalUrl, serverId, defaults, clients })
 * watch(session_id) -> operator-only session_watch projection (see managed_server.mjs).
 * clients: createClientDefaults(...) (per-client self-registered listeners).
 * defaults: createDefaultTargets(...) (optional operator fallback targets).
 */
export function createSessionNotifier({ watch, settings = {}, approvalUrl, serverId, defaults = createDefaultTargets(), clients = createClientDefaults(), statePath,
  transport = createPinnedWebhookTransport({ timeoutMs: 10000 }), now = Date.now, log = () => {} } = {}) {
  if (typeof watch !== 'function') throw Error('session notifier requires watch');
  const stallDefault = (settings.stall_minutes ?? 10) * MINUTE;
  const minInterval = settings.min_interval_ms ?? 2 * MINUTE;
  const maxTargets = settings.max_targets ?? 200;
  const ttl = (settings.ttl_hours ?? 72) * 60 * MINUTE;
  const loaded = statePath ? loadState(statePath) : {};
  const targets = new Map(Object.entries(loaded.targets ?? {}).filter(([id, t]) => SID.test(id) && t && typeof t === 'object' &&
    (typeof t.url === 'string' || typeof t.default_name === 'string' || t.default_pending === true || t.client_default === true && validClientID(t.client_id))));
  // Sessions opted out of gateway defaults -> expiry time.
  const optedOut = new Map(Object.entries(loaded.opt_out ?? {}).filter(([id, until]) => SID.test(id) && Number.isSafeInteger(until)));
  const persist = () => {
    if (!statePath) return;
    try { saveState(statePath, { targets: Object.fromEntries(targets), opt_out: Object.fromEntries(optedOut) }); } catch { log('session notify state not saved'); }
  };
  const isOptedOut = (sessionID, at = now()) => {
    const until = optedOut.get(sessionID);
    if (until !== undefined && until <= at) { optedOut.delete(sessionID); return false; }
    return until !== undefined;
  };
  // Effective delivery target: a per-call target, or a default resolved now.
  const effective = t => t.client_default ? clients.resolve(t.client_id) : t.default_name ? defaults.resolve(t.default_name) :
    t.url ? { target: { url: t.url, header_name: t.header_name, header_value: t.header_value, hmac_secret: t.hmac_secret, format: t.format } } :
    { reason: 'default_pending' };
  const sourceOf = t => t.url ? 'per_call' : t.client_default ? 'client_default' : 'gateway_default';
  // Redacted view: never the URL path, header value or HMAC secret.
  function publicStatus(id, t) {
    if (!t) return { session_id: id, enabled: false, ...(isOptedOut(id) ? { opted_out: true } : {}) };
    const resolved = t.default_pending ? { reason: 'default_pending' } : effective(t);
    const target = resolved.target;
    return { session_id: id, enabled: true, source: sourceOf(t),
      ...(t.client_default ? { client_id: t.client_id } : {}),
      ...(t.default_name ? { default_target: t.default_name } : {}), ...(t.default_pending ? { pending: true } : {}),
      configured: Boolean(target), ...(resolved.reason ? { reason: resolved.reason } : {}), ...redactTarget(target),
      stall_minutes: Math.round((t.stall_ms ?? (resolved.stall_minutes ? resolved.stall_minutes * MINUTE : stallDefault)) / MINUTE),
      registered_at: new Date(t.registered_at).toISOString(), expires_at: new Date(t.expires_at).toISOString(),
      delivered: t.delivered ?? 0, failed: t.failed ?? 0, skipped: t.skipped ?? 0, last_delivery: t.last_delivery ?? null };
  }

  // A target is "settled" after its finished event until new work is seen.
  const settled = t => t.finished_sent && !t.saw_work;
  function ensure(sessionID, at) {
    let t = targets.get(sessionID);
    if (!t && targets.size >= maxTargets) {
      // Evict a settled target first (oldest), else the oldest registration.
      const order = [...targets].sort((a, b) => Number(settled(b[1])) - Number(settled(a[1])) || a[1].registered_at - b[1].registered_at);
      targets.delete(order[0][0]);
    }
    if (!t) { t = { notified: [], saw_work: false, outbox: [], armed_at: at }; targets.set(sessionID, t); }
    if (!t.armed_at && !t.saw_work) t.armed_at = at; // a run ending after registration is reported
    t.registered_at = at; t.expires_at = Math.max(t.expires_at ?? 0, at + ttl);
    return t;
  }
  const CALL_FIELDS = ['url', 'header_name', 'header_value', 'hmac_secret', 'format', 'stall_ms', 'default_name', 'default_pending', 'client_id', 'client_default'];
  function set(sessionID, rawTarget, at = now()) {
    if (!SID.test(sessionID ?? '')) throw Object.assign(Error('invalid session'), { reason: 'invalid_session' });
    const target = validateNotifyTarget(rawTarget);
    // Mutate in place: a tick in progress may hold this object, and
    // re-registering must keep dedupe/run state so asks are not re-sent.
    const t = ensure(sessionID, at);
    for (const key of CALL_FIELDS) delete t[key];
    Object.assign(t, { url: target.url, header_name: target.header_name, header_value: target.header_value, hmac_secret: target.hmac_secret,
      format: target.format, stall_ms: target.stall_minutes ? target.stall_minutes * MINUTE : undefined });
    optedOut.delete(sessionID);
    persist();
    return publicStatus(sessionID, t);
  }
  function applyDefault(t, entry, clientID) {
    for (const key of CALL_FIELDS) delete t[key];
    // client_id is kept so the match can be re-checked against current config.
    Object.assign(t, { default_name: entry.name, client_id: clientID, stall_ms: entry.stall_minutes ? entry.stall_minutes * MINUTE : undefined });
  }
  function applyClient(t, clientID, entry) {
    for (const key of CALL_FIELDS) delete t[key];
    Object.assign(t, { client_default: true, client_id: clientID, stall_ms: entry.stall_minutes ? entry.stall_minutes * MINUTE : undefined });
  }
  // A default whose source no longer exists counts as no target (a transient
  // clients-file error does not).
  const stale = t => t?.default_name !== undefined && !defaults.has(t.default_name) || t?.client_default === true && clients.lookup(t.client_id).state === 'absent';
  const bounded = (promise, ms) => {
    let timer;
    return Promise.race([promise.catch(() => null), new Promise(done => { timer = setTimeout(() => done(null), ms); timer.unref?.(); })]).finally(() => clearTimeout(timer));
  };
  // Attach the matching gateway default. Automatic (create/message/resume):
  // never replaces an existing target and is skipped when the session opted
  // out; the directory is matched via watch now (bounded) or on the next tick.
  // Explicit (workrelay_server_notify set without url): replaces a per-call
  // target and lifts the opt-out, but only when a default matches.
  async function attachDefault(sessionID, { client_id: clientID, at = now(), explicit = false, waitMs = 4000 } = {}) {
    if (!SID.test(sessionID ?? '')) return null;
    // The caller's own registered listener comes first; no directory needed.
    const own = clients.lookup(clientID);
    if (explicit) {
      if (own.state === 'present') {
        const t = ensure(sessionID, at); applyClient(t, clientID, own.entry); optedOut.delete(sessionID); persist();
        return publicStatus(sessionID, t);
      }
      if (!defaults.size || !defaults.mayMatch(clientID)) return { error: 'no_default_target' };
      const view = await bounded(watch(sessionID), waitMs);
      if (!view) return { error: 'session_unobservable' };
      const entry = defaults.match({ directory: view.directory, client_id: clientID });
      if (!entry) return { error: 'no_default_target' };
      const t = ensure(sessionID, at); applyDefault(t, entry, clientID); optedOut.delete(sessionID); persist();
      return publicStatus(sessionID, t);
    }
    const free = () => { const t = targets.get(sessionID); if (stale(t)) { targets.delete(sessionID); persist(); return true; } return !t; };
    if (!free()) {
      const t = targets.get(sessionID);
      // An automatic target follows the delegating client's own listener;
      // a per-call target is never replaced.
      if (!t.url && own.state === 'present' && !(t.client_default && t.client_id === clientID)) { applyClient(t, clientID, own.entry); persist(); }
      return publicStatus(sessionID, t);
    }
    if (isOptedOut(sessionID, at)) return null;
    if (own.state === 'present') {
      const t = ensure(sessionID, at); applyClient(t, clientID, own.entry); persist();
      return publicStatus(sessionID, t);
    }
    if (!defaults.size || !defaults.mayMatch(clientID)) return null;
    // Match BEFORE creating an entry, so a session in an unmatched directory
    // never evicts a live target at max_targets.
    const view = await bounded(watch(sessionID), waitMs);
    if (!free()) return publicStatus(sessionID, targets.get(sessionID)); // set concurrently
    if (isOptedOut(sessionID, at)) return null;
    if (view) {
      const entry = defaults.match({ directory: view.directory, client_id: clientID });
      if (!entry) return null;
      const t = ensure(sessionID, at); applyDefault(t, entry, clientID); persist();
      return publicStatus(sessionID, t);
    }
    // Native read unavailable: resolve on a later tick, but never evict for it.
    if (targets.size >= maxTargets) return null;
    const t = ensure(sessionID, at);
    Object.assign(t, { default_pending: true, client_id: clientID });
    persist();
    return publicStatus(sessionID, t);
  }
  async function resolvePending(sessionID, t, view) {
    if (!t?.default_pending) return;
    try { view ??= await watch(sessionID); } catch { return; } // retried on the next tick
    if (!t.default_pending || targets.get(sessionID) !== t) return;
    const own = clients.lookup(t.client_id);
    const entry = own.state === 'present' ? null : defaults.match({ directory: view.directory, client_id: t.client_id });
    if (own.state === 'present') applyClient(t, t.client_id, own.entry);
    else if (entry) applyDefault(t, entry, t.client_id); else targets.delete(sessionID);
    persist();
  }
  const hasDefaults = () => defaults.size > 0 || clients.any();
  function clear(sessionID, { optOut = true } = {}) {
    const had = targets.delete(sessionID);
    const out = optOut && hasDefaults();
    if (out) optedOut.set(sessionID, now() + ttl);
    if (had || out) persist();
    return { session_id: sessionID, enabled: false, cleared: had, ...(out ? { opted_out: true } : {}) };
  }
  function get(sessionID) { return publicStatus(sessionID, targets.get(sessionID)); }
  // Status plus whether a gateway default would apply (bounded native read).
  async function status(sessionID, { client_id: clientID, waitMs = 4000 } = {}) {
    const current = get(sessionID);
    if (current.enabled) return current;
    const guidance = current.opted_out ? 'This session opted out of defaults. Call set without url to re-attach the default.' :
      'Delegating with create/message/resume attaches it automatically; or call set without url.';
    const own = clients.lookup(clientID);
    if (own.state === 'present') {
      const resolved = clients.resolve(clientID);
      return { ...current, default_available: { source: 'client_default', client_id: clientID, configured: Boolean(resolved.target),
        ...(resolved.reason ? { reason: resolved.reason } : {}), ...redactTarget(resolved.target) }, guidance };
    }
    if (!defaults.size || !defaults.mayMatch(clientID)) return current;
    const view = await bounded(watch(sessionID), waitMs);
    const entry = view && defaults.match({ directory: view.directory, client_id: clientID });
    if (!entry) return { ...current, default_available: view ? null : 'unknown' };
    const resolved = defaults.resolve(entry.name);
    return { ...current, default_available: { source: 'gateway_default', default_target: entry.name, configured: Boolean(resolved.target),
      ...(resolved.reason ? { reason: resolved.reason } : {}), ...redactTarget(resolved.target) }, guidance };
  }

  // Test event (action test): to the session's effective target, or the one a
  // delegation would attach; or (no session) to the client's own default.
  // Sent now, outside the outbox, and not counted in delivery stats.
  const lastTest = new Map();
  async function test({ session_id: sessionID, client_id: clientID } = {}) {
    const key = sessionID ? `s:${sessionID}` : `c:${clientID}`;
    if (now() - (lastTest.get(key) ?? -Infinity) < 10000) return { error: 'test_rate_limited' };
    let resolved, source;
    if (!sessionID) {
      if (clients.lookup(clientID).state !== 'present') return { error: 'no_client_default' };
      resolved = clients.resolve(clientID); source = 'client_default';
    } else {
      const t = targets.get(sessionID);
      if (t) { resolved = t.default_pending ? { reason: 'default_pending' } : effective(t); source = sourceOf(t); }
      else {
        const available = (await status(sessionID, { client_id: clientID })).default_available;
        if (!available || available === 'unknown') return { error: 'no_target' };
        source = available.source;
        resolved = source === 'client_default' ? clients.resolve(clientID) : defaults.resolve(available.default_target);
      }
    }
    if (!resolved.target) return { error: 'target_not_configured', source, ...(resolved.reason ? { reason: resolved.reason } : {}) };
    lastTest.set(key, now());
    if (lastTest.size > 1000) lastTest.delete(lastTest.keys().next().value);
    const event = testNotifyEvent({ sessionID, serverId, scope: sessionID ? 'session' : 'client', now });
    return { ...(sessionID ? { session_id: sessionID } : { client_id: clientID }), source, ...await sendTestEvent(resolved.target, event, { transport, now }) };
  }

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
  const readHint = sessionID => ({ tool: 'workrelay_server_read', arguments: { session_id: sessionID, include_messages: true } });
  function enqueue(t, sessionID, type, fields, { limited }) {
    const at = now();
    if (limited && at - (t.last_limited_at ?? 0) < minInterval) {
      // Coalesce inside the window: merge child failures, otherwise keep the newest.
      if (type === 'child_failed' && t.deferred?.type === 'child_failed')
        fields = { ...fields, child_session_ids: [...new Set([...t.deferred.fields.child_session_ids, ...fields.child_session_ids])].slice(0, 10) };
      t.deferred = { type, fields }; return;
    }
    if (limited) { t.last_limited_at = at; t.deferred = undefined; }
    const event = { type: `workrelay.session.${type}`, schema_version: EVENT_SCHEMA_VERSION, event_id: 'evt_' + randomBytes(12).toString('hex'),
      source: 'workrelay', session_id: sessionID, ...(serverId ? { server_id: serverId } : {}), project_id: t.project_id ?? null, directory: t.directory ?? null,
      at: new Date(at).toISOString(), ...fields };
    event.summary = summarize(type, event);
    event.read = readHint(sessionID);
    t.outbox = [...(t.outbox ?? []), { event, attempts: 0, next_at: at }].slice(-20);
  }
  function flushDeferred(t, sessionID) {
    if (t.deferred && now() - (t.last_limited_at ?? 0) >= minInterval) { const { type, fields } = t.deferred; enqueue(t, sessionID, type, fields, { limited: true }); }
  }

  // Reasons that mean "deliberately no receiver": drop instead of retrying.
  const INERT = new Set(['url_not_configured', 'default_target_removed', 'default_pending', 'client_default_removed']);
  async function deliver(sessionID, t) {
    const ready = (t.outbox ?? []).filter(item => item.next_at <= now());
    // At most 3 sends per target per tick; targets are delivered concurrently.
    for (const item of ready.slice(0, 3)) {
      // Re-check per send: a clear/set during an awaited send must take effect.
      if (targets.get(sessionID) !== t || !t.outbox.includes(item)) return;
      const resolved = effective(t);
      if (!resolved.target && INERT.has(resolved.reason)) {
        // Inert target (e.g. placeholder secrets): drop, never queue unbounded.
        const dropped = t.outbox.filter(entry => entry.next_at <= now());
        t.outbox = t.outbox.filter(entry => !dropped.includes(entry));
        t.skipped = (t.skipped ?? 0) + dropped.length;
        t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok: false, error: resolved.reason };
        return;
      }
      item.attempts++;
      if (!resolved.target) {
        // Transient (secrets file unreadable/invalid): retry with backoff so a
        // fixed file still delivers the ask/completion.
        t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok: false, error: resolved.reason ?? 'not_configured' };
      } else {
        try {
          const status = await postNotifyEvent(resolved.target, item.event, { transport, now });
          const ok = status >= 200 && status < 300;
          t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok, status };
          if (ok || status >= 400 && status < 500 && status !== 429) {
            t.outbox = t.outbox.filter(entry => entry !== item); t[ok ? 'delivered' : 'failed'] = (t[ok ? 'delivered' : 'failed'] ?? 0) + 1; continue;
          }
        } catch (error) {
          t.last_delivery = { at: new Date(now()).toISOString(), event: item.event.type, ok: false, error: error?.data?.reason ?? 'network_error' };
        }
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
      if (t.watch_failures === 10) enqueue(t, sessionID, 'unobservable', { title: t.title ?? null, status: 'unknown' }, { limited: true });
      flushDeferred(t, sessionID);
      return;
    }
    if (t.default_pending) { await resolvePending(sessionID, t, view); if (targets.get(sessionID) !== t || t.default_pending) return; }
    else if (!t.url) {
      // Re-check an automatic target against the current client defaults and
      // config: a newly registered client listener takes over, a removed one
      // falls back to the gateway default, and narrowed, renamed or removed
      // gateway entries re-match or detach instead of lingering.
      const own = clients.lookup(t.client_id);
      const stallOf = entry => entry.stall_minutes ? entry.stall_minutes * MINUTE : undefined;
      if (own.state === 'present') { if (!t.client_default || stallOf(own.entry) !== t.stall_ms) applyClient(t, t.client_id, own.entry); }
      else if (!(own.state === 'error' && t.client_default)) {
        const entry = defaults.match({ directory: view.directory, client_id: t.client_id });
        if (!entry) { targets.delete(sessionID); return; }
        if (t.client_default || entry.name !== t.default_name || stallOf(entry) !== t.stall_ms) applyDefault(t, entry, t.client_id);
      }
    }
    const at = now();
    t.directory = typeof view.directory === 'string' ? view.directory : null;
    t.project_id = typeof view.project_id === 'string' ? view.project_id : null;
    t.title = view.title;
    const base = { title: view.title, status: view.aggregate_status };
    // 1) New live permission asks: immediate, deduped by permission id.
    const notified = new Set(t.notified ?? []);
    const fresh = (view.pending ?? []).filter(item => !notified.has(item.permission_id));
    if (fresh.length) {
      for (const item of fresh) notified.add(item.permission_id);
      t.notified = [...notified].slice(-200);
      enqueue(t, sessionID, 'permission_asked', { ...base, asks: fresh.slice(0, 5).map(item => ({ permission_id: item.permission_id,
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
        next: readHint(sessionID),
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
      const before = JSON.stringify([[...targets], [...optedOut]]);
      for (const [id, until] of [...optedOut]) if (until <= now()) optedOut.delete(id);
      const live = [];
      for (const [sessionID, t] of [...targets]) {
        if (t.expires_at <= now()) { targets.delete(sessionID); continue; }
        try { await observe(sessionID, t); } catch { /* never let one target stop the loop */ }
        if (targets.get(sessionID) === t) live.push([sessionID, t]);
      }
      // One slow receiver must not delay another session's events.
      await Promise.allSettled(live.map(([sessionID, t]) => deliver(sessionID, t)));
      if (JSON.stringify([[...targets], [...optedOut]]) !== before) persist();
    } finally { running = false; }
  }
  let timer;
  return { set, clear, get, status, test, attachDefault, armed, tick, hasDefaults, hasGatewayDefaults: () => defaults.size > 0, clients,
    size: () => targets.size,
    start() { if (!timer) { timer = setInterval(() => { void tick().catch(() => {}); }, settings.poll_interval_ms ?? 30000); timer.unref?.(); } },
    stop() { clearInterval(timer); timer = undefined; } };
}
