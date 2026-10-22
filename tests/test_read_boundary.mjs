import test from 'node:test';
import assert from 'node:assert/strict';
import { createReadBoundary } from '../src/workrelay/mcp_observation.mjs';
import { createManagedReader } from '../src/workrelay/managed_server.mjs';

test('read RPC projection excludes hostile values and preserves original JSON/SSE responses', async () => {
  for (const sse of [false, true]) for (const result of [
    { result: { content: [{ text: 'PRIVATE transcript' }], structuredContent: { private: 'PRIVATE' } } },
    { result: { isError: true, content: [{ text: 'PRIVATE error' }] } },
    { error: { code: -32603, message: 'PRIVATE stack', data: { token: 'PRIVATE' } } },
    { error: { code: -99999, message: 'PRIVATE' } },
  ]) {
    let receipt;
    const boundary = createReadBoundary({ session_id: 'PRIVATE', cursor: 'PRIVATE', include_messages: true, limit: 1, PRIVATE: 'PRIVATE' }, value => { receipt = value; });
    boundary.native('PRIVATE', 'PRIVATE', 401);
    boundary.native('native_status', 'messages', 403);
    boundary.toolError(Object.assign(new TypeError('PRIVATE'), { stack: 'PRIVATE', headers: 'PRIVATE', body: 'PRIVATE' }));
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 'PRIVATE', ...result });
    const body = sse ? `event: message\ndata: ${payload}\n\n` : payload;
    const response = new Response(body, { headers: { 'content-type': sse ? 'text/event-stream' : 'application/json', authorization: 'PRIVATE' } });
    await boundary.response(response);
    assert.equal(await response.text(), body);
    assert.doesNotMatch(JSON.stringify(receipt), /PRIVATE/);
    assert.equal(receipt.native_status, 403); assert.equal(receipt.error_type, 'TypeError');
    assert.equal(receipt.delivery, result.error ? 'rpc_error' : result.result.isError ? 'tool_error' : 'rpc_result');
    assert.equal(receipt.rpc_code, result.error?.code === -32603 ? -32603 : null);
    assert.match(receipt.artifact_revision, /^[a-f0-9]{64}$/);
  }
});

test('SDK failure and observer failure are finite and non-throwing', async () => {
  let receipt;
  const boundary = createReadBoundary({}, value => { receipt = value; });
  boundary.failed({ name: 'PRIVATE', message: 'PRIVATE', stack: 'PRIVATE' });
  assert.equal(receipt.delivery, 'sdk_or_relay_threw'); assert.equal(receipt.sdk_stage, 'sdk_fetch');
  assert.equal(receipt.error_type, 'other'); assert.doesNotMatch(JSON.stringify(receipt), /PRIVATE/);
  const hostile = createReadBoundary({}, () => { throw Error('PRIVATE'); });
  hostile.failed({ get name() { throw Error('PRIVATE'); } });
  await hostile.response(new Response('PRIVATE', { headers: { 'content-type': 'text/plain' } }));
});

test('changing exception name getter is read once before finite projection', async () => {
  for (const entry of ['failed', 'toolError']) {
    let reads = 0, receipt;
    const boundary = createReadBoundary({}, value => { receipt = value; });
    const error = { get name() { return ++reads === 1 ? 'TypeError' : 'PRIVATE_SECOND_VALUE'; } };
    boundary[entry](error);
    if (entry === 'toolError') await boundary.response(Response.json({ jsonrpc: '2.0', result: { isError: true } }));
    assert.equal(reads, 1);
    assert.equal(receipt.error_type, 'TypeError');
    assert.doesNotMatch(JSON.stringify(receipt), /PRIVATE_SECOND_VALUE/);
  }
});

test('native stages retain failure location without changing results, errors or auth denials', async () => {
  const binding = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp', subject: 'fixture', client_id: 'https://chatgpt.com/oauth/client.json',
    server: 'http://127.0.0.1:12345', service_registration: '/private/service.json', client_service_module: '/private/service.mjs' };
  const expected = { issuer: binding.issuer, audience: binding.audience, principal: binding.subject, managed_server: { ...binding } };
  const claims = { iss: binding.issuer, aud: binding.audience, sub: binding.subject, client_id: binding.client_id };
  let mode = 'success', calls = 0;
  const original = new TypeError('PRIVATE fetch');
  const read = createManagedReader(expected, () => ({ ...binding }), {
    canonical: path => path,
    stat: () => ({ isFile: () => true, isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, dev: 1, ino: 1, mtimeMs: 1 }),
    loadService: async () => ({ discover: async () => ({ url: binding.server, auth: {} }), headers: () => ({ authorization: 'PRIVATE' }) }),
    fetcher: async url => {
      calls++;
      if (url.pathname.endsWith('/message')) {
        if (mode === 'fetch') throw original;
        if (mode === 'denied') return new Response('PRIVATE', { status: 403 });
        if (mode === 'json') return new Response('PRIVATE');
        if (mode === 'shape') return Response.json({ data: [{ id: 'PRIVATE' }] });
        return Response.json({ data: [{ id: 'msg_fixture', type: 'user', text: 'Visible fixture' }] });
      }
      return Response.json({ data: { id: 'ses_fixture', projectID: 'fixture', title: 'Fixture', time: { idle: 1 } } });
    },
  });
  const input = { session_id: 'ses_fixture', include_messages: true, limit: 1 };
  const baseline = await read('read', input, claims);
  const throwingObserver = () => { throw Error('PRIVATE observer'); };
  assert.deepEqual(await read('read', input, claims, throwingObserver), baseline);
  for (mode of ['success', 'fetch', 'denied', 'json', 'shape']) {
    let last;
    const observe = (stage, action, status) => { last = { stage, action, status }; };
    if (mode === 'success') assert.deepEqual(await read('read', input, claims, observe), baseline);
    else await assert.rejects(read('read', input, claims, observe), error => mode === 'fetch' ? error === original : error instanceof Error);
    assert.equal(last.action, 'messages');
    assert.equal(last.stage, { success: 'projection', fetch: 'native_fetch', denied: 'native_status', json: 'native_json', shape: 'projection' }[mode]);
    if (mode === 'denied') assert.equal(last.status, 403);
  }
  binding.revoked = true; const before = calls;
  await assert.rejects(read('read', input, claims, throwingObserver));
  assert.equal(calls, before, 'observer cannot bypass denied binding');
});
