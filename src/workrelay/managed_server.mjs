// Explicit managed-registration authority; no session mutation or inference routes.
import { realpathSync, lstatSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

const sid = /^ses[A-Za-z0-9_-]{1,160}$/;
const deny = () => { throw Error('managed server access unavailable'); };
export const managedServerID = binding => 'srv_' + createHash('sha256').update(JSON.stringify([binding.server, binding.service_registration, binding.client_service_module])).digest('hex');
export function checkManagedBinding(binding, claims, expected) {
  if (!binding || binding.enabled !== true || binding.revoked !== false ||
      !claims || binding.issuer !== expected.issuer || binding.audience !== expected.audience ||
      binding.subject !== expected.principal || binding.client_id !== 'https://chatgpt.com/oauth/client.json' ||
      claims.iss !== binding.issuer || claims.aud !== binding.audience ||
      claims.sub !== binding.subject || claims.client_id !== binding.client_id) deny();
  for (const key of ['server', 'service_registration', 'client_service_module'])
    if (!expected.managed_server || binding[key] !== expected.managed_server[key]) deny();
  let url;
  try { url = new URL(binding.server); } catch { deny(); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash) deny();
  for (const key of ['service_registration', 'client_service_module']) {
    const path = binding[key];
    if (typeof path !== 'string' || !path.startsWith('/') || path.includes('/../')) deny();
  }
}

function projection(session) {
  if (!session || !sid.test(session.id) || typeof session.projectID !== 'string' || session.projectID.length > 160) deny();
  // Titles, arbitrary metadata, location paths and transcript are intentionally not
  // copied. They can contain credentials or instructions. IDs are navigation only.
  const project = 'project_' + createHash('sha256').update(session.projectID).digest('hex');
  return { session_id: session.id, project_id: project,
    label: `Session ${session.id.slice(-8)}`, type: 'existing_session',
    owner: { session_id: session.id, parent_session_id: sid.test(session.parentID ?? '') ? session.parentID : null },
    status: ['succeeded', 'failed', 'interrupted'].includes(session.outcome) ? session.outcome :
      session.time?.idle ? 'idle' : 'unknown',
    actions: [{ tool: 'workrelay_server_read', arguments: { session_id: session.id } },
      { tool: 'workrelay_server_message', arguments: { session_id: session.id }, requires: ['operation_id', 'text'] },
      { tool: 'workrelay_server_interrupt', arguments: { session_id: session.id }, requires: ['operation_id'] }],
    limitation: 'Idle is not completion. Writes require matching guarded CLI configuration and financial admission. Events reconcile explicit outcomes and permission needs, never transcript/token updates.' };
}

export function createManagedReader(expected, readBinding, { loadService = path => import(pathToFileURL(path).href),
  fetcher = fetch, canonical = realpathSync, stat = lstatSync, internalAuthorize } = {}) {
  return async (action, input, claims) => {
    const binding = readBinding(); // Re-read owner-only capability every request, including revocation.
    checkManagedBinding(binding, claims, expected);
    if (canonical(binding.service_registration) !== binding.service_registration ||
        canonical(binding.client_service_module) !== binding.client_service_module) deny();
    for (const file of [binding.service_registration, binding.client_service_module]) {
      for (let parent = dirname(file); ; parent = dirname(parent)) {
        const entry = stat(parent);
        if (!entry.isDirectory() || entry.isSymbolicLink() || ![0, process.getuid()].includes(entry.uid) || entry.mode & 0o022) deny();
        if (parent === dirname(parent)) break;
      }
      const entry = stat(file);
      if (!entry.isFile() || entry.isSymbolicLink() || ![0, process.getuid()].includes(entry.uid) || entry.mode & 0o022) deny();
    }
    const registration = stat(binding.service_registration);
    if (!registration.isFile() || registration.isSymbolicLink() || registration.uid !== process.getuid() ||
        registration.mode & 0o077) deny();
    const service = await loadService(binding.client_service_module);
    const endpoint = await service.discover({ file: binding.service_registration });
    if (!endpoint?.auth || endpoint.url !== binding.server) deny();
    const bindingID = createHash('sha256').update(JSON.stringify(binding)).digest('hex');
    if (action === 'authorize') return { binding_id: bindingID, server_id: managedServerID(binding) };
    if (action === 'events' && input.server_id !== managedServerID(binding)) deny();
    let path;
    let method = 'GET', body;
    if (action === 'internal' && internalAuthorize) {
      if (!await internalAuthorize(input, bindingID, endpoint, service.headers(endpoint))) deny();
      path = input.path; method = input.method; body = input.body;
      if (JSON.stringify(readBinding()) !== JSON.stringify(binding)) deny();
      const before = stat(binding.service_registration);
      if (before.dev !== registration.dev || before.ino !== registration.ino || before.mtimeMs !== registration.mtimeMs) deny();
    } else if (action === 'read' || action === 'events' && input.session_id) {
      if (!sid.test(input.session_id ?? '')) deny();
      path = '/api/session/' + input.session_id;
    } else if (action === 'discover' || action === 'events') {
      const limit = input.limit ?? 20;
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) deny();
      const query = new URLSearchParams({ limit: String(limit) });
      if (input.cursor !== undefined) {
        if (typeof input.cursor !== 'string' || !input.cursor.length || input.cursor.length > 4096 || /[\x00-\x1f\x7f]/.test(input.cursor)) deny();
        query.set('cursor', input.cursor);
      } else query.set('order', 'desc');
      path = '/api/session?' + query;
    } else deny();
    const response = await fetcher(new URL(path, endpoint.url), { method, headers: { ...service.headers(endpoint), 'content-type': 'application/json' },
      ...(body != null ? { body: JSON.stringify(body) } : {}),
      redirect: 'manual', signal: AbortSignal.timeout(10000) });
    if (action === 'internal' && method === 'GET' && response.status === 404) { await response.body?.cancel(); return null; }
    if (!response.ok) { await response.body?.cancel(); deny(); }
    const reader = response.body.getReader(); let size = 0; const chunks = [];
    try { while (true) { const part = await reader.read(); if (part.done) break;
      size += part.value.length; if (size > 2000000) deny(); chunks.push(part.value); }
    } finally { await reader.cancel(); }
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    // Local revocation/registration replacement during network I/O must not disclose data.
    if (JSON.stringify(readBinding()) !== JSON.stringify(binding) || canonical(binding.service_registration) !== binding.service_registration) deny();
    const current = stat(binding.service_registration);
    if (current.dev !== registration.dev || current.ino !== registration.ino || current.mtimeMs !== registration.mtimeMs) deny();
    if (action === 'events') {
      const sessions = input.session_id ? [value.data] : value.data;
      if (!Array.isArray(sessions) || sessions.length > 10 || input.session_id && sessions[0]?.id !== input.session_id) deny();
      const items = [];
      for (const session of sessions) {
        if (!sid.test(session?.id ?? '')) deny();
        const permissions = await fetcher(new URL(`/api/session/${session.id}/permission`, endpoint.url), { method: 'GET', headers: service.headers(endpoint), redirect: 'manual', signal: AbortSignal.timeout(10000) });
        if (!permissions.ok) { await permissions.body?.cancel(); deny(); }
        const stream = permissions.body.getReader(); const parts = []; let bytes = 0;
        try { while (true) { const part = await stream.read(); if (part.done) break; bytes += part.value.length; if (bytes > 262144) deny(); parts.push(part.value); } } finally { await stream.cancel(); }
        const pending = JSON.parse(Buffer.concat(parts).toString('utf8')).data;
        if (!Array.isArray(pending) || pending.length > 1000 || pending.some(p => p.sessionID !== session.id || !/^per[A-Za-z0-9_-]{1,160}$/.test(p.id))) deny();
        items.push({ session_id: session.id, state: ['succeeded', 'failed', 'interrupted'].includes(session.outcome) ? session.outcome : pending.length ? 'needs_input' : 'unknown', decisions: pending.map(p => p.id).sort() });
      }
      if (JSON.stringify(readBinding()) !== JSON.stringify(binding) || canonical(binding.service_registration) !== binding.service_registration) deny();
      const after = stat(binding.service_registration);
      if (after.dev !== registration.dev || after.ino !== registration.ino || after.mtimeMs !== registration.mtimeMs) deny();
      const next = input.session_id ? null : value.cursor?.next ?? null;
      if (next !== null && (typeof next !== 'string' || next.length > 4096 || /[\x00-\x1f\x7f]/.test(next))) deny();
      return { server_id: managedServerID(binding), items, next_cursor: next };
    }
    if (action === 'internal') return value;
    if (action === 'read') {
      if (value.data?.id !== input.session_id) deny();
      return { ...projection(value.data), server_id: managedServerID(binding) };
    }
    if (!Array.isArray(value.data) || value.data.length > (input.limit ?? 20)) deny();
    const next = value.cursor?.next ?? null;
    if (next !== null && (typeof next !== 'string' || next.length > 4096 || /[\x00-\x1f\x7f]/.test(next))) deny();
    const items = value.data.map(projection);
    return { server_id: managedServerID(binding), items, projects: [...new Set(items.map(item => item.project_id))].map(id => ({ id, label: `Project ${id.slice(-8)}` })),
      next_cursor: next, access: 'managed_server_read',
      guidance: items.length ? 'Use returned session IDs and actions; continue with next_cursor.' :
        'No sessions on this page. Continue with next_cursor if present. No enrollment is required for this bound server.' };
  };
}
