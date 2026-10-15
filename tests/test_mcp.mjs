import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, exportJWK } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createGateway, validateConfig } from '../src/workrelay/mcp.mjs';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise(resolve => server.close(resolve));
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...await exportJWK(publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };

test('signed OAuth JWT, strict boundary, and real MCP2 client handshake/tools', async () => {
  const issuerServer = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await listen(issuerServer);
  const issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const portServer = createServer();
  await listen(portServer);
  const port = portServer.address().port;
  await close(portServer);
  const config = { public_origin: 'https://workrelay.example', issuer, jwks_uri: `${issuer}/jwks`,
    audience: 'https://workrelay.example/mcp', principal: 'person-1', owner: 'person-1',
    bridge_config: '/nonexistent-private-config', port };
  assert.throws(() => validateConfig(config), /canonical HTTPS/);
  assert.throws(() => validateConfig({ ...config, principal: '' }, { testIssuer: true }));
  let invoked = 0;
  const gateway = createGateway(config, { testIssuer: true, invoke: async (_config, command, input) => {
    invoked++;
    assert.equal(input.owner, undefined);
    if (command === 'enrolled_result') return input.grant_id === 'grant_' + 'a'.repeat(32) ?
      { grant_id: input.grant_id, access: 'enrolled_read_only', capabilities: ['read'], owner: 'person-1' } :
      { error: 'enrollment missing or revoked' };
    return { command, key: input.key, phase: 'running' };
  } });
  await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${gateway.address().port}`;
  // This test allocates port 0; request Host must match configured canonical local port.
  const url = `${base}/mcp`;
  const token = async (overrides = {}) => new SignJWT({ scope: 'workrelay:tasks', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(issuer).setAudience(config.audience).setSubject(overrides.sub ?? 'person-1')
    .setIssuedAt().setExpirationTime(overrides.exp ?? '5m').sign(privateKey);
  const request = async (jwt, headers = {}, path = '/mcp', method = 'tools/list', params = {}) => fetch(base + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${jwt}`,
      'MCP-Protocol-Version': '2025-11-25', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  try {
    const metadata = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(metadata.status, 200);
    assert.deepEqual((await metadata.json()).authorization_servers, [issuer]);
    const missing = await fetch(url, { method: 'POST' });
    assert.equal(missing.status, 401);
    assert.match(missing.headers.get('www-authenticate'), /resource_metadata=/);
    assert.equal((await request(await token({ sub: 'other' }))).status, 403);
    assert.equal((await request(await token({ scope: 'wrong' }))).status, 403);
    assert.equal((await request(await token({ exp: 1 }))).status, 401);
    const alien = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const forged = await new SignJWT({ scope: 'workrelay:tasks' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer).setAudience(config.audience).setSubject('person-1')
      .setIssuedAt().setExpirationTime('5m').sign(alien.privateKey);
    assert.equal((await request(forged)).status, 401);
    const wrongAudience = await new SignJWT({ scope: 'workrelay:tasks' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer).setAudience('different-resource').setSubject('person-1')
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    assert.equal((await request(wrongAudience)).status, 401);
    const wrongHost = await new Promise((resolve, reject) => {
      const req = httpRequest(url, { method: 'POST', headers: { Host: 'evil.example' } }, res => {
        res.resume(); res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject); req.end();
    });
    assert.equal(wrongHost, 400);
    assert.equal((await request(await token(), { Origin: 'https://evil.example' })).status, 400);
    assert.equal((await request(await token(), { 'X-Forwarded-Host': 'evil.example' })).status, 400);
    assert.equal((await request(await token(), { 'X-Forwarded-Proto': 'https' })).status, 200,
      'external issuer retains its existing forwarded-proto handling');
    assert.equal((await request(await token(), { 'X-Forwarded-Proto': 'http' })).status, 400);
    const oversizedToken = await token();
    const oversized = await new Promise((resolve, reject) => {
      const req = httpRequest(url, { method: 'POST', headers: {
        Authorization: `Bearer ${oversizedToken}`, 'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream', 'Transfer-Encoding': 'chunked',
      } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject);
      req.write('x'.repeat(60000));
      req.end('x'.repeat(60000));
    });
    assert.equal(oversized, 413);
    assert.equal(invoked, 0);
    const transport = new StreamableHTTPClientTransport(new URL(url), { authProvider: { token: async () => token() } });
    const client = new Client({ name: 'workrelay-local-test', version: '1.0.0' });
    await client.connect(transport);
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map(tool => tool.name).sort(),
      ['workrelay_cancel', 'workrelay_enrolled_result', 'workrelay_profile', 'workrelay_respond', 'workrelay_result', 'workrelay_start', 'workrelay_status']);
    assert.equal(tools.tools.find(tool => tool.name === 'workrelay_enrolled_result').annotations.readOnlyHint, true);
    const result = await client.callTool({ name: 'workrelay_status', arguments: { key: 'task1' } });
    assert.equal(result.structuredContent.key, 'task1');
    const final = await client.callTool({ name: 'workrelay_result', arguments: { key: 'task1' } });
    assert.equal(final.structuredContent.command, 'result');
    const grant = 'grant_' + 'a'.repeat(32);
    const enrolled = await client.callTool({ name: 'workrelay_enrolled_result', arguments: { grant_id: grant } });
    assert.equal(enrolled.structuredContent.access, 'enrolled_read_only');
    assert.equal(enrolled.structuredContent.grant_id, grant);
    const revoked = await client.callTool({ name: 'workrelay_enrolled_result', arguments: { grant_id: 'grant_' + 'f'.repeat(32) } });
    assert.equal(revoked.isError, true);
    assert.equal((await request(await token({ sub: 'other' }), {}, '/mcp', 'tools/call',
      { name: 'workrelay_enrolled_result', arguments: { grant_id: grant } })).status, 403);
    const forgedGrant = await client.callTool({ name: 'workrelay_enrolled_result', arguments: { grant_id: 'ses_bridge_' + 'a'.repeat(32) } });
    assert.equal(forgedGrant.isError, true);
    const extraOwner = await client.callTool({ name: 'workrelay_enrolled_result', arguments: { grant_id: grant, owner: 'other' } });
    assert.equal(extraOwner.isError, true);
    assert.equal(invoked, 4);
    const rejected = await client.callTool({ name: 'workrelay_start', arguments: { key: 'task2', text: 'hi', owner: 'other' } });
    assert.equal(rejected.isError, true);
    assert.equal(invoked, 4);
    await client.close();
  } finally { await close(gateway); await close(issuerServer); }
});

test('SDK SSE streams incrementally, aborts on client disconnect, and bounds output', async () => {
  const issuerServer = createServer((_, res) => res.end(JSON.stringify({ keys: [jwk] })));
  await listen(issuerServer);
  const reserve = createServer();
  await listen(reserve);
  const port = reserve.address().port;
  await close(reserve);
  const issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const config = { public_origin: 'https://workrelay.example', issuer, jwks_uri: `${issuer}/jwks`,
    audience: 'https://workrelay.example/mcp', principal: 'person-1', owner: 'person-1',
    bridge_config: '/nonexistent-private', port };
  let aborted = false;
  let big = false;
  const sdkHandler = { fetch: async request => big ? new Response(new ReadableStream({
    start(controller) { controller.enqueue(Buffer.alloc(2_100_000)); controller.close(); },
  }), { headers: { 'Content-Type': 'application/json' } }) : new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('data: first\n\n'));
      request.signal.addEventListener('abort', () => { aborted = true; controller.close(); });
    },
  }), { headers: { 'Content-Type': 'text/event-stream' } }) };
  const gateway = createGateway(config, { testIssuer: true, sdkHandler });
  await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve));
  const token = await new SignJWT({ scope: 'workrelay:tasks' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(issuer).setAudience(config.audience).setSubject('person-1')
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const url = `http://127.0.0.1:${port}/mcp`;
  try {
    const controller = new AbortController();
    const stream = await fetch(url, { method: 'GET', signal: controller.signal,
      headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' } });
    assert.equal(stream.status, 200);
    const reader = stream.body.getReader();
    assert.match(new TextDecoder().decode((await reader.read()).value), /data: first/);
    controller.abort();
    await new Promise(resolve => setTimeout(resolve, 25));
    assert.equal(aborted, true);
    big = true;
    await assert.rejects(async () => {
      const response = await fetch(url, { method: 'GET', headers: { Authorization: `Bearer ${token}` } });
      await response.arrayBuffer();
    });
  } finally { await close(gateway); await close(issuerServer); }
});
