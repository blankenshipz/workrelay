import test from 'node:test';
import assert from 'node:assert/strict';
import { createManagedReader } from '../src/workrelay/managed_server.mjs';

const client = 'https://chatgpt.com/oauth/client.json';
function fixture(change = {}) {
  const binding = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp',
    subject: 'alice', client_id: client, server: 'http://127.0.0.1:12345', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
  const claims = { iss: binding.issuer, aud: binding.audience, sub: binding.subject, client_id: client };
  const input = { method: 'GET', path: '/__managed/plugin-inventory', body: null,
    managed: { claims, session_id: 'ses_example', operation_id: 'inventory' } };
  const calls = [];
  if (change.revoked) binding.revoked = true;
  let sessions = 0;
  const reader = createManagedReader({ issuer: binding.issuer, audience: binding.audience, principal: binding.subject,
    managed_server: { ...binding } }, () => ({ ...binding }), {
    canonical: path => path.startsWith('/PRIVATE') && (change.alias || change.canonicalChanged && calls.includes('/api/plugin')) ? '/OTHER' : path,
    stat: path => ({ isFile: () => true, isDirectory: () => !change.notDirectory || !path.startsWith('/PRIVATE'),
      isSymbolicLink: () => !!change.symlink && path.startsWith('/PRIVATE'), uid: process.getuid(), mode: 0o600,
      dev: change.deviceChanged && path.startsWith('/PRIVATE') && calls.includes('/api/plugin') ? 2 : 1,
      ino: change.inodeChanged && path.startsWith('/PRIVATE') && calls.includes('/api/plugin') ? 2 : 1, mtimeMs: 1 }),
    loadService: async () => ({ discover: async () => ({ url: change.server ?? binding.server, auth: {} }), headers: () => ({ 'x-native-fixture': 'present' }) }),
    internalAuthorize: async request => request.method === 'GET' && request.path === '/api/session/ses_example' && request.body === null,
    fetcher: async (url, options) => {
      calls.push(url.pathname); assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'manual');
      assert.equal(options.headers['x-native-fixture'], 'present');
      if (url.pathname === '/api/plugin') {
        assert.deepEqual([...url.searchParams], [['location[directory]', '/PRIVATE/a b&c']]);
        if (change.revoke) binding.revoked = true;
        return new Response(JSON.stringify({ location: { directory: change.responseLocation ?? '/PRIVATE/a b&c' }, data: [
          { id: '/PRIVATE/token=SECRET', state: { status: 'failed', error: 'SECRET' }, source: { path: '/PRIVATE' }, params: 'SECRET' },
          { id: 'normal', state: { status: 'active' } }, { state: { status: 'failed' } } ] }));
      }
      sessions++;
      return new Response(JSON.stringify({ data: change.missing ? null : { id: 'ses_example', projectID: 'project',
        location: { directory: change.directory ?? (change.move && sessions > 1 ? '/OTHER' : '/PRIVATE/a b&c') } } }));
    },
  });
  return { reader, claims, input, calls };
}
test('internal client protocol derives encoded location, returns safe inventory, never readiness', async () => {
  const f = fixture();
  const result = await f.reader('plugin_inventory', f.input, f.claims);
  assert.deepEqual(f.calls, ['/api/session/ses_example', '/api/plugin', '/api/session/ses_example']);
  assert.equal(result.activation_readiness, 'unknown');
  assert.deepEqual(result.items.map(p => p.state), ['failed', 'active', 'failed']);
  assert.equal(result.items[2].plugin_id, null, 'native optional ID is not invented');
  assert.match(result.items[0].plugin_id, /^plugin_[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|SECRET|params|source/);
  assert.ok(Number.isFinite(Date.parse(result.observed_at)));
});
test('rejects foreign authority, missing/moved location and mid-read revocation', async () => {
  for (const change of [{ server: 'http://127.0.0.1:9999' }, { missing: true }, { move: true }, { revoke: true }, { revoked: true }, { responseLocation: '/foreign' },
    { directory: '/a/../private' }, { directory: 'relative' }, { symlink: true }, { alias: true }, { notDirectory: true },
    { canonicalChanged: true }, { deviceChanged: true }, { inodeChanged: true }]) {
    const f = fixture(change); await assert.rejects(f.reader('plugin_inventory', f.input, f.claims));
  }
  const f = fixture();
  await assert.rejects(f.reader('plugin_inventory', f.input, { ...f.claims, sub: 'other' }));
  assert.equal(f.calls.length, 0);
});
test('caller cannot select headers, query, location, another session, or write', async () => {
  for (const extra of [{ headers: {} }, { directory: '/other' }, { method: 'POST' },
    { path: '/__managed/plugin-inventory?location[directory]=/other' }, { body: {} }]) {
    const f = fixture(); await assert.rejects(f.reader('plugin_inventory', { ...f.input, ...extra }, f.claims));
    assert.equal(f.calls.length, 0);
  }
  const f = fixture();
  await assert.rejects(f.reader('plugin_inventory', { ...f.input, managed: { ...f.input.managed, session_id: 'ses_other' } }, f.claims));
  assert.equal(f.calls.length, 0);
});
