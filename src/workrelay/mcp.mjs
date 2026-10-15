// Model-free MCP HTTP facade. TLS is terminated by an explicitly configured tunnel/proxy;
// this process MUST remain on loopback. There is no authorization server here.
import { createServer } from 'node:http';
import { readFileSync, statSync, lstatSync, openSync, fstatSync, readSync, writeSync, closeSync, fsyncSync, renameSync, unlinkSync, constants } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { McpServer, createMcpHandler, ProtocolError } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createEventsService } from './events.mjs';
const loopback = new Set(['127.0.0.1', '::1']);
const key = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
const grantId = z.string().regex(/^grant_[0-9a-f]{32}$/);
const text = z.string().trim().min(1).max(16000);
const MAX_REQUEST_BYTES = 100000;
const MAX_RESPONSE_BYTES = 2_000_000;
async function relayResponse(response, req, res, abort) {
  const isSSE = response.headers.get('content-type')?.toLowerCase().startsWith('text/event-stream');
  const length = response.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    res.writeHead(502).end();
    await response.body?.cancel();
    return;
  }
  let sent = 0;
  const disconnected = () => abort.abort();
  res.once('close', disconnected);
  try {
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body) for await (const chunk of response.body) {
      sent += chunk.byteLength;
      if (sent > MAX_RESPONSE_BYTES || chunk.byteLength > MAX_RESPONSE_BYTES) {
        abort.abort();
        res.destroy();
        return;
      }
      if (!res.write(chunk)) await new Promise(resolveWait => {
        const finish = () => { res.off('drain', finish); res.off('close', finish); resolveWait(); };
        res.once('drain', finish); res.once('close', finish);
      });
      if (res.destroyed) return;
    }
    if (!res.destroyed) res.end();
  } finally {
    res.off('close', disconnected);
    if (isSSE && req.destroyed) abort.abort();
  }
}

function boundedBody(req) {
  return new Promise((resolveBody, rejectBody) => {
    let bytes = 0;
    const parts = [];
    const cleanup = () => {
      clearTimeout(timer);
      req.off('data', data);
      req.off('end', end);
      req.off('error', error);
    };
    const data = chunk => {
      bytes += chunk.length;
      if (bytes > MAX_REQUEST_BYTES) {
        cleanup();
        req.resume(); // Drain without buffering so a keepalive connection cannot poison a later request.
        rejectBody(new Error('too_large'));
      } else parts.push(chunk);
    };
    const end = () => { cleanup(); resolveBody(Buffer.concat(parts)); };
    const error = () => { cleanup(); rejectBody(new Error('invalid_body')); };
    const timer = setTimeout(() => { cleanup(); req.resume(); rejectBody(new Error('body_timeout')); }, 10000);
    req.on('data', data).on('end', end).on('error', error);
  });
}
const schema = {
  profile: z.object({}).strict(),
  start: z.object({ key, text }).strict(),
  status: z.object({ key }).strict(),
  result: z.object({ key }).strict(),
  enrolled_result: z.object({ grant_id: grantId }).strict(),
  respond: z.object({ key, feedback_key: key, text }).strict(),
  cancel: z.object({ key }).strict(),
};

export function validateConfig(config, { testIssuer = false } = {}) {
  if (!config || typeof config !== 'object') throw Error('invalid MCP configuration');
  const origin = new URL(config.public_origin);
  const issuer = new URL(config.issuer);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' ||
      origin.search || origin.hash || issuer.username || issuer.password || issuer.search || issuer.hash ||
      (issuer.protocol !== 'https:' && !(testIssuer && issuer.protocol === 'http:' && loopback.has(issuer.hostname))))
    throw Error('canonical HTTPS public origin and trusted issuer required');
  if (!config.audience || typeof config.audience !== 'string' || !config.principal ||
      typeof config.principal !== 'string' || !key.safeParse(config.owner).success ||
      !config.bridge_config || typeof config.bridge_config !== 'string')
    throw Error('explicit audience, principal, owner and private bridge config required');
  if (!config.jwks_uri || typeof config.jwks_uri !== 'string') throw Error('explicit issuer JWKS URI required');
  const jwks = new URL(config.jwks_uri);
  if (jwks.protocol !== issuer.protocol || jwks.hostname !== issuer.hostname || jwks.port !== issuer.port ||
      jwks.username || jwks.password || jwks.hash) throw Error('JWKS must be same-origin with issuer');
  if (!Number.isSafeInteger(config.port) || config.port < 1 || config.port > 65535)
    throw Error('explicit loopback port required');
  if (config.events_enabled === true) {
    if (typeof config.events_state_path !== 'string' || !config.events_state_path.startsWith('/'))
      throw Error('private events state path required');
    const parent = statSync(dirname(config.events_state_path));
    if (!parent.isDirectory() || parent.uid !== process.getuid() || (parent.mode & 0o077))
      throw Error('private events directory required');
  }
  if (config.events_enabled === true && !config.revocation_file)
    throw Error('private principal revocation file required for events');
  if (config.revocation_file && (typeof config.revocation_file !== 'string' ||
      !config.revocation_file.startsWith('/'))) throw Error('private revocation file path required');
  return { ...config, public_origin: origin.origin, issuer: issuer.href.replace(/\/$/, ''), jwks_uri: jwks.href };
}

export function readPrivateConfig(path) {
  const info = statSync(path);
  if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0)
    throw Error('private MCP config permissions denied');
  return validateConfig(JSON.parse(readFileSync(path, 'utf8')));
}

function bridge(config, command, input) {
  return new Promise((done, reject) => {
    const args = ['-m', 'workrelay.cli', '--config', config.bridge_config,
      command === 'enrolled_result' ? 'enrolled-result' : command,
      ...(command === 'enrolled_result' ? ['--grant-id', input.grant_id] : ['--key', input.key]), '--owner', config.owner];
    if (command === 'respond') args.push('--feedback-key', input.feedback_key);
    if (command === 'respond' || command === 'start') args.push('--stdin-text');
    const child = spawn(config.python ?? '/usr/bin/python3', args, {
      cwd: resolve(dirname(fileURLToPath(import.meta.url)), '../..'),
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', PYTHONPATH: resolve(dirname(fileURLToPath(import.meta.url)), '..') },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '', error = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 60000);
    child.stdout.on('data', part => { output += part; if (output.length > 100000) child.kill('SIGKILL'); });
    child.stderr.on('data', part => { error += part; if (error.length > 100000) child.kill('SIGKILL'); });
    child.on('error', () => { clearTimeout(timer); reject(Error('local adapter unavailable')); });
    child.on('close', code => {
      clearTimeout(timer);
      try {
        const value = JSON.parse(code === 0 ? output : error);
        done(code === 0 ? value : { error: value.error ?? 'local adapter denied request' });
      } catch { done({ error: 'local adapter unavailable' }); }
    });
    child.stdin.end(input.text ?? '');
  });
}

function mcp(config, invoke, events) {
  const server = new McpServer({ name: 'workrelay', version: '0.1.0' },
    events ? { capabilities: { events: {} } } : {});
  for (const name of Object.keys(schema)) {
    const readOnly = ['profile', 'status', 'result', 'enrolled_result'].includes(name);
    server.registerTool(`workrelay_${name}`, {
      title: `Workrelay ${name}`,
      description: name === 'cancel' ? 'Interrupt only the owned root session; descendants are not canceled.' :
        name === 'result' ? 'Read the owned task lifecycle and evidence, not a verified final answer or transcript.' :
        name === 'enrolled_result' ? 'Read only a locally granted existing session by opaque grant ID; cannot respond, adopt or cancel it.' :
        `Operate on the single configured Workrelay workspace: ${name}.`,
      inputSchema: schema[name],
      annotations: { readOnlyHint: readOnly, destructiveHint: name === 'cancel', idempotentHint: name !== 'respond', openWorldHint: false },
    }, async input => {
      try {
        const output = name === 'profile' ? { owner: config.owner, capabilities: ['start', 'status', 'result', 'enrolled_result', 'respond', 'cancel'],
          limitation: 'Result is bounded/redacted read-only evidence; descendants remain active on cancel.' } :
          await invoke(config, name, input);
        return { content: [{ type: 'text', text: JSON.stringify(output) }], structuredContent: output,
          isError: Boolean(output.error) };
      } catch { return { isError: true, content: [{ type: 'text', text: 'local adapter unavailable' }] }; }
    });
  }
  if (events) {
    const invokeEvent = action => async params => {
      try { return await events[action](params); }
      catch (error) { throw new ProtocolError(error.code || -32603, 'Event request rejected', error.data); }
    };
    server.server.setRequestHandler('events/list', { params: z.object({ cursor: z.string().optional() }).strict() },
      invokeEvent('list'));
    const eventParams = z.object({ name: z.enum(['task.decision', 'task.completed']),
      arguments: z.object({ task_id: key }).strict(),
      delivery: z.object({ mode: z.literal('webhook'), url: z.string().url().max(2048),
        secret: z.string().max(128).optional() }).strict(),
      cursor: z.null().optional(), ttlMs: z.number().int().positive().optional().nullable() }).strict();
    server.server.setRequestHandler('events/subscribe', { params: eventParams }, invokeEvent('subscribe'));
    server.server.setRequestHandler('events/unsubscribe', { params: eventParams }, invokeEvent('unsubscribe'));
  }
  return server;
}

export function createGateway(rawConfig, options = {}) {
  const config = validateConfig(rawConfig, options);
  // Local-admin-only file. Any token hash revocation conservatively disables
  // this sole principal and its subscriptions until an explicit admin re-enable.
  // There is no verified issuer disconnect hook or token-to-subscription map.
  const active = () => {
    if (!config.revocation_file) return true; // Legacy tools-only mode; no push authorization.
    let fd;
    try {
      const parent = lstatSync(dirname(config.revocation_file));
      if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || parent.mode & 0o077) return false;
      fd = openSync(config.revocation_file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const entry = fstatSync(fd);
      if (!entry.isFile() || entry.uid !== process.getuid() || entry.mode & 0o077 || entry.size > 16384) return false;
      const bytes = Buffer.alloc(16385);
      const count = readSync(fd, bytes, 0, bytes.length, 0);
      if (count > 16384 || count !== entry.size) return false;
      const data = JSON.parse(bytes.toString('utf8', 0, count));
      if (!Array.isArray(data.revoked_principals) || !Array.isArray(data.revoked_tokens) ||
          data.revoked_principals.some(x => typeof x !== 'string') ||
          data.revoked_tokens.some(x => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x))) return false;
      return !data.revoked_principals.includes(config.principal) && data.revoked_tokens.length === 0;
    } catch { return false; }
    finally { if (fd !== undefined) closeSync(fd); }
  };
  const invoke = options.invoke ?? bridge;
  const authorized = async (_principal, task) => {
    if (!active() || !approved() || unsafeMarker || markerState() === 'pending' || !key.safeParse(task).success) return false;
    try {
      const status = await invoke(config, 'status', { key: task });
      return status?.key === task && status.owner === config.owner && status.prompt_observed === true &&
        /^ses_bridge_[a-f0-9]{32}$/.test(status.session);
    } catch { return false; }
  };
  const events = config.events_enabled === true ? createEventsService({ statePath: config.events_state_path,
    principal: config.principal, authorize: authorized,
    ...(options.eventTransport ? { transport: options.eventTransport } : {}),
    ...(options.eventLockTimeoutMs ? { lockTimeoutMs: options.eventLockTimeoutMs } : {}) }) : null;
  const marker = events ? `${config.events_state_path}.revoke` : null;
  const stamp = events ? `${config.events_state_path}.auth` : null;
  let unsafeMarker = false;
  // Approval is tied to the exact private revocation-file generation, not only
  // its current contents. A denied->re-enabled replacement after a failed
  // marker write still differs from the last approved generation on restart.
  function generation() {
    let fd;
    try {
      const dir = lstatSync(dirname(config.revocation_file));
      if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || dir.mode & 0o077) return null;
      fd = openSync(config.revocation_file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(fd, { bigint: true }), bytes = Buffer.alloc(16385);
      if (!info.isFile() || info.uid !== BigInt(process.getuid()) || info.mode & 0o077n || info.size > 16384n) return null;
      const count = readSync(fd, bytes, 0, bytes.length, 0);
      if (BigInt(count) !== info.size) return null;
      return createHash('sha256').update([info.dev, info.ino, info.ctimeNs, info.mtimeNs,
        info.size].map(String).join(':')).update(bytes.subarray(0, count)).digest('hex');
    } catch { return null; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  function approved() {
    if (!stamp) return true;
    const current = generation();
    if (!current) return false;
    let fd;
    try {
      fd = openSync(stamp, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(fd), bytes = Buffer.alloc(65);
      if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077 || info.size !== 64) return false;
      return readSync(fd, bytes, 0, 65, 0) === 64 && bytes.toString('utf8', 0, 64) === current;
    } catch { return false; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  function markerState() {
    if (!marker) return null;
    let fd;
    try {
      const dir = lstatSync(dirname(marker));
      if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || dir.mode & 0o077) return 'unsafe';
      fd = openSync(marker, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(fd), bytes = Buffer.alloc(8);
      if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077 || info.size > 8) return 'unsafe';
      const count = readSync(fd, bytes, 0, 8, 0);
      const value = bytes.toString('utf8', 0, count);
      return count === info.size && ['pending', 'clean'].includes(value) ? value : 'unsafe';
    } catch (error) { return error.code === 'ENOENT' ? null : 'unsafe'; }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  function writeMarker(value, target = marker) {
    const dir = dirname(target), info = lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || info.mode & 0o077) throw Error('unsafe marker directory');
    const temporary = `${target}.${randomBytes(12).toString('hex')}`;
    let fd;
    try {
      fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeSync(fd, value); fsyncSync(fd); closeSync(fd); fd = undefined;
      renameSync(temporary, target);
      const directory = openSync(dir, constants.O_RDONLY); try { fsyncSync(directory); } finally { closeSync(directory); }
    } finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
  }
  let cleanup;
  async function reconcile() {
    if (!events) return null;
    const revoked = !active(), state = markerState();
    if (unsafeMarker || state === 'unsafe') return 'pending';
    // First-ever empty store can be approved. Existing subscriptions without
    // a stamp (including pre-migration data) must be durably revoked first.
    if (!approved() && state === null) {
      let existing = true;
      try { lstatSync(config.events_state_path); } catch (error) { if (error.code === 'ENOENT') existing = false; }
      if (!existing && !revoked) {
        try { const value = generation(); if (!value) throw Error('generation unavailable'); writeMarker(value, stamp); }
        catch { unsafeMarker = true; return 'pending'; }
      }
    }
    if ((revoked || !approved()) && markerState() !== 'pending') {
      try { writeMarker('pending'); } catch { unsafeMarker = true; return 'pending'; }
    }
    if (markerState() === 'pending') {
      if (!cleanup) cleanup = events.revoke().then(() => {
        const value = generation(); if (!value) throw Error('generation unavailable');
        writeMarker(value, stamp); writeMarker('clean'); return true;
      })
        .catch(() => false).finally(() => { cleanup = null; });
      if (!await cleanup) return 'pending';
    }
    if (!active()) return 'revoked';
    if (markerState() === 'clean') {
      try {
        unlinkSync(marker);
        const directory = openSync(dirname(marker), constants.O_RDONLY);
        try { fsyncSync(directory); } finally { closeSync(directory); }
      } catch { unsafeMarker = true; return 'pending'; }
    }
    return null;
  }
  const handler = options.sdkHandler ?? createMcpHandler(() => mcp(config, invoke, events));
  const jwks = createRemoteJWKSet(new URL(config.jwks_uri), { timeoutDuration: 3000, cooldownDuration: 1000 });
  const metadataUrl = `${config.public_origin}/.well-known/oauth-protected-resource/mcp`;
  const resource = `${config.public_origin}/mcp`;
  const hostname = new URL(config.public_origin).host;
  const localHost = `127.0.0.1:${config.port}`;
  const metadata = JSON.stringify({ resource, authorization_servers: [config.issuer], scopes_supported: ['workrelay:tasks'],
    bearer_methods_supported: ['header'] });
  const failure = (res, code, reason) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
      ...(code === 401 || code === 403 ? { 'WWW-Authenticate': `Bearer realm="workrelay", resource_metadata="${metadataUrl}", error="${reason}"` } : {}) });
    res.end(JSON.stringify({ error: reason }));
  };
  const server = createServer(async (req, res) => {
    // Never trust forwarded identity or a caller-supplied owner. The public Host is
    // canonical; the local Host is only available to a real loopback peer.
    const remote = req.socket.remoteAddress;
    if (!loopback.has(remote) || ![hostname, localHost].includes(req.headers.host) ||
        (req.headers.host === localHost && !loopback.has(remote)) ||
        (req.headers.origin && req.headers.origin !== config.public_origin) ||
        (req.headers['x-forwarded-host'] && req.headers['x-forwarded-host'] !== hostname) ||
        (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') ||
        req.headers.forwarded || req.headers['x-forwarded-prefix']) return failure(res, 400, 'invalid_origin');
    if (req.url === '/.well-known/oauth-protected-resource/mcp' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(metadata);
    }
    if (req.url !== '/mcp' || !['GET', 'POST', 'DELETE'].includes(req.method)) return failure(res, 404, 'not_found');
    if (Number(req.headers['content-length'] ?? 0) > MAX_REQUEST_BYTES) return failure(res, 413, 'too_large');
    if (req.headers['content-encoding']) return failure(res, 415, 'unsupported_encoding');
    const bearer = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(req.headers.authorization ?? '');
    if (!bearer) return failure(res, 401, 'invalid_token');
    try {
      const { payload } = await jwtVerify(bearer[1], jwks, { issuer: config.issuer, audience: config.audience,
        algorithms: ['RS256', 'ES256'], clockTolerance: 0, requiredClaims: ['sub', 'exp', 'iat'] });
      if (payload.sub !== config.principal || !String(payload.scope ?? '').split(' ').includes('workrelay:tasks'))
        return failure(res, 403, 'insufficient_scope');
    } catch { return failure(res, 401, 'invalid_token'); }
    let parsedBody;
    if (req.method === 'POST') {
      try {
        const raw = await boundedBody(req);
        parsedBody = JSON.parse(raw.toString('utf8'));
      } catch (error) {
        return failure(res, error.message === 'too_large' ? 413 : 400,
          error.message === 'too_large' ? 'too_large' : 'invalid_body');
      }
    }
    const access = await reconcile();
    if (access === 'pending') {
      const eventRequest = /^events\//.test(parsedBody?.method ?? req.headers['mcp-method'] ?? '');
      if (eventRequest) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ jsonrpc: '2.0', id: parsedBody?.id ?? null,
          error: { code: -32000, message: 'Revocation pending', data: { reason: 'revocation_pending', retryable: true } } }));
      }
      return failure(res, 503, 'revocation_pending');
    }
    if (access === 'revoked') return failure(res, 403, 'access_revoked');
    // Official v2 HTTP entry classifies 2025 initialize and 2026-07-28 discover
    // without weakening the explicit token, Host, Origin or byte-limit boundary.
    try {
      const abort = new AbortController();
      const request = new Request(`http://${localHost}${req.url}`, { method: req.method,
        headers: req.headers, signal: abort.signal });
      const response = await handler.fetch(request, { parsedBody, authInfo: {
        token: bearer[1], clientId: config.principal, scopes: ['workrelay:tasks'],
      } });
      await relayResponse(response, req, res, abort);
    }
    catch { if (!res.headersSent) failure(res, 500, 'mcp_unavailable'); }
  });
  if (events) {
    let busy = false;
    let activeTick = Promise.resolve();
    const tick = async () => {
      if (busy) return;
      busy = true;
      try {
        if (await reconcile()) return;
        // Only inspect keys already subscribed through a verified callback; never
        // enumerate or adopt unrelated OpenCode sessions. Ledger status/result
        // independently recheck ownership and workspace on every observation.
        const file = lstatSync(config.events_state_path);
        if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
            file.mode & 0o077 || file.size > 16777216) return;
        const state = JSON.parse(readFileSync(config.events_state_path, 'utf8'));
        const activeSubscriptions = Object.values(state.subscriptions ?? {}).filter(sub =>
          sub.principal === config.principal && sub.expires > Date.now());
        const keys = [...new Set(activeSubscriptions.map(sub => sub.task))].slice(0, 256);
        for (const task of keys) {
          if (!await authorized(config.principal, task)) continue;
          const status = await invoke(config, 'status', { key: task });
          const result = await invoke(config, 'result', { key: task });
          if (result?.key !== task || result?.owner !== config.owner || result.access !== 'owned' ||
              result.session !== status.session) continue;
          const emit = async (name, detail, summary) => {
            const eventId = 'evt_' + createHash('sha256').update(JSON.stringify([
              config.principal, task, result.session, name, detail])).digest('hex');
            await events.publish({ name, task_id: task, summary, eventId });
          };
          if (result.decision_needed && result.evidence === 'OpenCode read-only observation')
            for (const decision of result.decisions ?? [])
              if (decision.kind === 'permission' && /^per[A-Za-z0-9_-]{1,160}$/.test(decision.id))
                await emit('task.decision', decision.id, 'Owned task has a pending permission decision; inspect read-only result.');
          if (result.terminal === true && result.evidence === 'OpenCode session outcome' &&
              ['succeeded', 'failed', 'interrupted'].includes(result.phase))
            await emit('task.completed', result.phase, 'Owned task reached a terminal OpenCode outcome; inspect read-only result.');
        }
        await events.deliverDue();
      } catch { /* private state or OpenCode unavailable: do not fabricate events */ }
      finally { busy = false; }
    };
    const timer = setInterval(() => { activeTick = tick(); }, options.eventIntervalMs ?? 5000);
    timer.unref();
    server.stopEvents = async () => { clearInterval(timer); await activeTick; };
    server.on('close', () => { clearInterval(timer); void handler.close?.(); });
  } else server.on('close', () => { void handler.close?.(); });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = readPrivateConfig(process.argv[2]);
    createGateway(config).listen(config.port, '127.0.0.1');
  } catch { process.stderr.write('private MCP configuration unavailable\n'); process.exitCode = 2; }
}
