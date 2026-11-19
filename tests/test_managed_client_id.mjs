import test from 'node:test';
import assert from 'node:assert/strict';
import { checkManagedBinding, managedClientID, DEFAULT_MANAGED_CLIENT_ID } from '../src/workrelay/managed_server.mjs';
import { validateConfig } from '../src/workrelay/mcp.mjs';

const managed_server = { server: 'http://127.0.0.1:4096', service_registration: '/x/service.json', client_service_module: '/x/client/dist/promise/service.js' };
const base = { issuer: 'https://i.test', audience: 'https://i.test/mcp', principal: 'p1', managed_server };
const binding = id => ({ enabled: true, revoked: false, issuer: base.issuer, audience: base.audience, subject: 'p1', client_id: id, ...managed_server });
const claims = id => ({ iss: base.issuer, aud: base.audience, sub: 'p1', client_id: id });

test('managed client ID defaults to the upstream ChatGPT pin', () => {
  assert.equal(managedClientID({}), DEFAULT_MANAGED_CLIENT_ID);
  checkManagedBinding(binding(DEFAULT_MANAGED_CLIENT_ID), claims(DEFAULT_MANAGED_CLIENT_ID), base);
  assert.throws(() => checkManagedBinding(binding('grokbot-mcp'), claims('grokbot-mcp'), base), /unavailable/);
});

test('configured managed client ID is pinned exactly and excludes the default', () => {
  const expected = { ...base, managed_client_id: 'grokbot-mcp' };
  checkManagedBinding(binding('grokbot-mcp'), claims('grokbot-mcp'), expected);
  assert.throws(() => checkManagedBinding(binding(DEFAULT_MANAGED_CLIENT_ID), claims(DEFAULT_MANAGED_CLIENT_ID), expected), /unavailable/);
  assert.throws(() => checkManagedBinding(binding('grokbot-mcp'), claims('other'), expected), /unavailable/);
});

test('self-hosted config requires managed_client_id to equal the registered client', () => {
  const cfg = { public_origin: 'https://w.test', issuer_mode: 'self-hosted', issuer_exposure: 'local-only', issuer_state_dir: '/s',
    audience: 'https://w.test/mcp', principal: 'p1', owner: 'grokbot', clientId: 'grokbot-mcp', bridge_config: '/b', port: 9000 };
  assert.equal(validateConfig({ ...cfg, managed_client_id: 'grokbot-mcp' }).managed_client_id, 'grokbot-mcp');
  assert.throws(() => validateConfig({ ...cfg, managed_client_id: DEFAULT_MANAGED_CLIENT_ID }), /managed client ID/);
  assert.throws(() => validateConfig({ ...cfg, managed_client_id: 'bad id' }), /managed client ID/);
});
