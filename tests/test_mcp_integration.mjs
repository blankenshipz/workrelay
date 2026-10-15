import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, createHmac } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fork } from 'node:child_process';
import { SignJWT, exportJWK } from 'jose';
import { createGateway } from '../src/workrelay/mcp.mjs';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise(resolve => server.close(resolve));
test('authenticated 2026 discover/list/subscribe/unsubscribe; signed retry and restart', async t => {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-integration-'));
  await fs.chmod(dir, 0o700);
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'issuer-test', alg: 'RS256', use: 'sig' };
  const issuerServer = createServer((_, res) => res.end(JSON.stringify({ keys: [jwk] })));
  await listen(issuerServer);
  const issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const reserve = createServer();
  await listen(reserve);
  const port = reserve.address().port;
  await close(reserve);
  const config = { public_origin: 'https://workrelay.example', issuer, jwks_uri: issuer + '/jwks',
    audience: 'https://workrelay.example/mcp', principal: 'owner-1', owner: 'owner-1',
    bridge_config: '/nonexistent-private', port, events_enabled: true,
    events_state_path: join(dir, 'events.json'), revocation_file: join(dir, 'revocations.json') };
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }), { mode: 0o600 });
  const secret = 'whsec_' + Buffer.alloc(32, 7).toString('base64');
  const calls = [];
  let decision = 'per1', holdDelivery, deliveryEntered;
  const eventTransport = async (url, opts) => {
    assert.ok(['https://receiver.example/callback', 'https://receiver.example/bad'].includes(url));
    const signature = 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64'))
      .update(`${opts.headers['webhook-id']}.${opts.headers['webhook-timestamp']}.${opts.body}`).digest('base64');
    assert.equal(opts.headers['webhook-signature'], signature);
    calls.push(opts);
    const body = JSON.parse(opts.body);
    if (url.endsWith('/bad')) return { status: 200, body: '{"challenge":"wrong"}' };
    if (body.eventId && holdDelivery) { deliveryEntered?.(); await holdDelivery; return { status: 503, body: '' }; }
    return body.type === 'verification' ? { status: 200, body: JSON.stringify({ challenge: body.challenge }) } :
      { status: calls.filter(x => JSON.parse(x.body).eventId).length === 1 ? 503 : 202, body: '' };
  };
  const invoke = async (_config, cmd, input) => input.key === 'owned' ?
    cmd === 'status' ? { key: 'owned', owner: 'owner-1', prompt_observed: true,
      session: 'ses_bridge_' + 'a'.repeat(32), phase: 'running' } :
      { key: 'owned', owner: 'owner-1', session: 'ses_bridge_' + 'a'.repeat(32),
        decision_needed: true, decisions: [{ id: decision, kind: 'permission' }], terminal: false,
        evidence: 'OpenCode read-only observation', access: 'owned' } : { error: 'unknown task' };
  const server = createGateway(config, { testIssuer: true, invoke, eventTransport, eventIntervalMs: 40 });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  const token = async (sub = 'owner-1') => new SignJWT({ scope: 'workrelay:tasks' })
    .setProtectedHeader({ alg: 'RS256', kid: 'issuer-test' }).setIssuer(issuer)
    .setAudience(config.audience).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const post = async (method, params = {}, sub = 'owner-1') => {
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST', headers: { Authorization: `Bearer ${await token(sub)}`, 'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream', Connection: 'close', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params,
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {} } } }),
    });
    return { code: response.status, body: await response.json() };
  };
  const destination = { name: 'task.decision', arguments: { task_id: 'owned' },
    delivery: { mode: 'webhook', url: 'https://receiver.example/callback', secret } };
  const discovery = await post('server/discover');
  assert.equal(discovery.code, 200, JSON.stringify(discovery.body));
  assert.ok(discovery.body.result.supportedVersions.includes('2026-07-28'));
  assert.deepEqual(discovery.body.result.capabilities.events, {});
  const listed = await post('events/list');
  assert.deepEqual(listed.body.result.events.map(event => event.name), ['task.decision', 'task.completed']);
  assert.equal((await post('events/subscribe', destination, 'different')).code, 403);
  const denied = await post('events/subscribe', { ...destination, arguments: { task_id: 'other' } });
  assert.ok(denied.body.error);
  const accepted = await post('events/subscribe', destination);
  assert.equal(accepted.code, 200, JSON.stringify(accepted.body));
  assert.ok(accepted.body.result.id.startsWith('sub_'));
  assert.equal(calls.length, 1);
  const bad = await post('events/subscribe', { ...destination,
    delivery: { ...destination.delivery, url: 'https://receiver.example/bad' } });
  assert.equal(bad.body.error.code, -32015, JSON.stringify(bad.body));
  assert.equal(bad.body.error.data.reason, 'challenge_failed');
  await new Promise(resolve => setTimeout(resolve, 180));
  assert.equal(calls.filter(x => JSON.parse(x.body).eventId).length, 1);
  await server.stopEvents();
  await close(server);
  const restarted = createGateway(config, { testIssuer: true, invoke, eventTransport, eventIntervalMs: 40 });
  await new Promise(resolve => restarted.listen(port, '127.0.0.1', resolve));
  await new Promise(resolve => setTimeout(resolve, 1200));
  const delivered = calls.filter(x => JSON.parse(x.body).eventId);
  assert.equal(delivered.length, 2);
  assert.equal(delivered[0].headers['webhook-id'], delivered[1].headers['webhook-id']);
  assert.equal((await post('events/unsubscribe', { ...destination, delivery: { mode: 'webhook', url: destination.delivery.url } })).body.result.resultType, 'complete');
  assert.ok((await post('events/subscribe', destination)).body.result.id);
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: ['owner-1'], revoked_tokens: [] }), { mode: 0o600 });
  assert.equal((await post('events/list')).code, 403);
  assert.equal(Object.keys(JSON.parse(await fs.readFile(config.events_state_path, 'utf8')).subscriptions).length, 0);
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }));
  assert.ok((await post('events/subscribe', destination)).body.result.id);
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: ['a'.repeat(64)] }));
  assert.equal((await post('events/list')).code, 403);
  assert.equal(Object.keys(JSON.parse(await fs.readFile(config.events_state_path, 'utf8')).subscriptions).length, 0);
  await restarted.stopEvents();
  await close(restarted);
  const again = createGateway(config, { testIssuer: true, invoke, eventTransport, eventIntervalMs: 3600000 });
  await new Promise(resolve => again.listen(port, '127.0.0.1', resolve));
  assert.equal((await post('events/list')).code, 403); // restart cannot resurrect revoked delivery
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }));
  const backup = join(dir, 'revocations.backup');
  await fs.rename(config.revocation_file, backup);
  await fs.symlink(backup, config.revocation_file);
  assert.equal((await post('events/list')).body.error.code, -32000); // reject symlink even to valid private file
  await fs.unlink(config.revocation_file);
  await fs.rename(backup, config.revocation_file);
  await fs.chmod(dir, 0o755);
  assert.equal((await post('events/list')).body.error.code, -32000); // unsafe parent blocks cleanup and dispatch
  await fs.chmod(dir, 0o700);
  await again.stopEvents();
  await close(again);
  const safe = createGateway(config, { testIssuer: true, invoke, eventTransport, eventIntervalMs: 3600000 });
  await new Promise(resolve => safe.listen(port, '127.0.0.1', resolve));
  assert.equal((await post('events/list')).code, 200); // restart after repairing private state
  await safe.stopEvents();
  await close(safe);
  // Revoke while a real Events-service outbox claim is held by an in-flight
  // (injected) webhook transport; a re-enable and restart must not replay it.
  decision = 'per2';
  let releaseDelivery;
  holdDelivery = new Promise(resolve => { releaseDelivery = resolve; });
  const entered = new Promise(resolve => { deliveryEntered = resolve; });
  const blocked = createGateway(config, { testIssuer: true, invoke, eventTransport,
    eventIntervalMs: 30, eventLockTimeoutMs: 120 });
  await new Promise(resolve => blocked.listen(port, '127.0.0.1', resolve));
  assert.ok((await post('events/subscribe', destination)).body.result.id);
  await Promise.race([entered, new Promise((_, reject) => setTimeout(() => reject(Error('delivery not entered')), 3000))]);
  const before = calls.filter(x => JSON.parse(x.body).eventId).length;
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: ['owner-1'], revoked_tokens: [] }));
  const pending = await post('events/list');
  assert.equal(pending.body.error.code, -32000, JSON.stringify(pending.body));
  assert.equal(pending.body.error.data.reason, 'revocation_pending');
  assert.equal(await fs.readFile(config.events_state_path + '.revoke', 'utf8'), 'pending');
  await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }));
  assert.equal((await post('events/list')).body.error.code, -32000);
  assert.equal(calls.filter(x => JSON.parse(x.body).eventId).length, before);
  releaseDelivery(); // the already-sent callback cannot be recalled
  await blocked.stopEvents();
  await close(blocked);
  const recovered = createGateway(config, { testIssuer: true, invoke, eventTransport,
    eventIntervalMs: 3600000, eventLockTimeoutMs: 120 });
  await new Promise(resolve => recovered.listen(port, '127.0.0.1', resolve));
  assert.equal((await post('events/list')).code, 200);
  const cleaned = JSON.parse(await fs.readFile(config.events_state_path, 'utf8'));
  assert.equal(Object.keys(cleaned.subscriptions).length, 0);
  assert.equal(cleaned.queue.length, 0);
  assert.equal(calls.filter(x => JSON.parse(x.body).eventId).length, before);
  holdDelivery = undefined;
  assert.ok((await post('events/subscribe', destination)).body.result.id); // fresh opt-in required
  await recovered.stopEvents();
  await close(recovered);
  await close(issuerServer);
  await fs.rm(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
});

test('SIGKILL recovery: pending marker and failed marker write cannot revive queued events', async t => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'crash-key', alg: 'RS256', use: 'sig' };
  const issuerServer = createServer((_, res) => res.end(JSON.stringify({ keys: [jwk] })));
  await listen(issuerServer);
  const issuer = `http://127.0.0.1:${issuerServer.address().port}`;
  const root = await fs.mkdtemp(join(tmpdir(), 'workrelay-crash-'));
  await fs.chmod(root, 0o700);
  const children = new Set();
  const childFile = join(root, 'child.mjs');
  const moduleUrl = pathToFileURL(resolve('src/workrelay/mcp.mjs')).href;
  await fs.writeFile(childFile, `import { createGateway } from ${JSON.stringify(moduleUrl)};
import { readFileSync } from 'node:fs';
const { config, mode } = JSON.parse(readFileSync(0, 'utf8'));
const invoke = async (_config, command, input) => input.key === 'owned' ? command === 'status'
 ? { key:'owned', owner:'owner-1', prompt_observed:true, session:'ses_bridge_'+ 'a'.repeat(32) }
 : { key:'owned', owner:'owner-1', access:'owned', session:'ses_bridge_'+ 'a'.repeat(32), decision_needed:true,
     decisions:[{id:'per1',kind:'permission'}], terminal:false, evidence:'OpenCode read-only observation' }
 : { error:'unknown task' };
const eventTransport = async (_url, options) => {
 const body=JSON.parse(options.body);
 if (body.type==='verification') return {status:200,body:JSON.stringify({challenge:body.challenge})};
 process.send({kind:'delivery'});
 if (mode==='block') return new Promise(()=>{});
 return {status:mode==='retry' ? 503 : 200,body:''};
};
const gateway=createGateway(config,{testIssuer:true,invoke,eventTransport,eventIntervalMs:30,eventLockTimeoutMs:120});
gateway.listen(config.port,'127.0.0.1',()=>process.send({kind:'ready'}));
`, { mode: 0o600 });
  const token = await new SignJWT({ scope: 'workrelay:tasks' }).setProtectedHeader({ alg: 'RS256', kid: 'crash-key' })
    .setIssuer(issuer).setAudience('https://workrelay.example/mcp').setSubject('owner-1')
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  async function scenario(mode) {
    const dir = join(root, mode); await fs.mkdir(dir, { mode: 0o700 });
    const reserve = createServer(); await listen(reserve); const port = reserve.address().port; await close(reserve);
    const config = { public_origin: 'https://workrelay.example', issuer, jwks_uri: issuer + '/jwks',
      audience: 'https://workrelay.example/mcp', principal: 'owner-1', owner: 'owner-1',
      bridge_config: '/nonexistent-private', port, events_enabled: true,
      events_state_path: join(dir, 'events.json'), revocation_file: join(dir, 'revocations.json') };
    await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }), { mode: 0o600 });
    const received = [];
    const start = role => {
      const child = fork(childFile, [], { stdio: ['pipe', 'ignore', 'ignore', 'ipc'] });
      children.add(child);
      child.once('exit', () => children.delete(child));
      child.on('message', message => received.push(message.kind));
      child.stdin.end(JSON.stringify({ config, mode: role }));
      return child;
    };
    const wait = async kind => {
      for (let attempt = 0; attempt < 200; attempt++) {
        if (received.includes(kind)) return;
        await new Promise(resolveWait => setTimeout(resolveWait, 15));
      }
      throw Error(`child never reported ${kind}`);
    };
    const post = async (method, params = {}) => {
      const response = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Connection: 'close', 'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method },
        body: JSON.stringify({ jsonrpc:'2.0', id:1, method, params:{ ...params, _meta:{
          'io.modelcontextprotocol/protocolVersion':'2026-07-28', 'io.modelcontextprotocol/clientCapabilities':{} } } }) });
      return response.json();
    };
    const child = start(mode);
    await wait('ready');
    const secret = 'whsec_' + Buffer.alloc(32, 7).toString('base64');
    const subscribe = await post('events/subscribe', { name:'task.decision', arguments:{task_id:'owned'},
      delivery:{mode:'webhook',url:'https://receiver.example/callback',secret} });
    assert.ok(subscribe.result?.id, JSON.stringify(subscribe));
    await wait('delivery');
    if (mode === 'retry') await fs.chmod(dir, 0o500); // marker creation/fsync cannot complete
    await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals:['owner-1'], revoked_tokens:[] }));
    const pending = await post('events/list');
    assert.equal(pending.error?.code, -32000, JSON.stringify(pending));
    if (mode === 'block') assert.equal(await fs.readFile(config.events_state_path + '.revoke','utf8'),'pending');
    child.kill('SIGKILL'); await new Promise(resolveExit => child.once('exit', resolveExit));
    if (mode === 'retry') await fs.chmod(dir, 0o700);
    await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals:[], revoked_tokens:[] }));
    received.length = 0;
    const restarted = start('accept'); await wait('ready');
    const recovered = await post('events/list');
    assert.equal(recovered.result?.events?.length, 2, JSON.stringify(recovered));
    await new Promise(resolveWait => setTimeout(resolveWait, 1300));
    assert.equal(received.filter(x => x === 'delivery').length, 0, 'stale queued event delivered after re-enable');
    const state = JSON.parse(await fs.readFile(config.events_state_path, 'utf8'));
    assert.equal(Object.keys(state.subscriptions).length, 0);
    assert.equal(state.queue.length, 0);
    restarted.kill('SIGKILL'); await new Promise(resolveExit => restarted.once('exit', resolveExit));
  }
  try { await scenario('block'); await scenario('retry'); }
  finally {
    for (const child of children) child.kill('SIGKILL');
    await Promise.all([...children].map(child => new Promise(resolveExit => child.once('exit', resolveExit))));
    await close(issuerServer);
    await fs.rm(root, { recursive:true, force:true, maxRetries:8, retryDelay:100 });
  }
});
