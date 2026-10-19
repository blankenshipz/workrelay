// Explicit operator reproduction of the NORMAL createGateway subscription path.
// Synthetic local JWT issuer is labelled as such; native source and HTTPS receiver
// are real. No deployed configuration, ChatGPT records, inference or policy changes.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { generateKeyPairSync, randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { exportJWK, SignJWT } from 'jose';
import { createGateway } from './mcp.mjs';
import { managedServerID } from './managed_server.mjs';
import { createManagedEventSource } from './managed_event_source.mjs';
import { createPinnedWebhookTransport, createCallbackResolver } from './events.mjs';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function probeGatewayStartup({ serviceModule, registration, tunnelBinary, privateDirectory, fixtureFile }) {
  const fixture = JSON.parse(await fs.readFile(fixtureFile, 'utf8'));
  if (!/^ses[A-Za-z0-9_-]{1,160}$/.test(fixture.session_id) || fixture.expected_configured_effect !== 'ask' || fixture.request?.method !== 'POST' || fixture.request.path !== `/api/session/${fixture.session_id}/permission` || fixture.request.body?.action !== 'read' || fixture.request.body.resources?.length !== 1 || fixture.request.body.save?.length !== 0) throw Error('invalid owned fixture reference');
  const dir = await fs.mkdtemp(join(privateDirectory, 'normal-gateway-')); await fs.chmod(dir, 0o700);
  const service = await import(pathToFileURL(serviceModule).href), endpoint = await service.discover({ file: registration });
  if (!endpoint?.auth || new URL(endpoint.url).hostname !== '127.0.0.1') throw Error('managed source unavailable');
  const native = async (path, method = 'GET', body, signal = AbortSignal.timeout(15000)) => {
    const current = await service.discover({ file: registration }); if (!current?.auth || current.url !== endpoint.url) throw Error('source binding changed');
    return fetch(new URL(path, endpoint.url), { method, headers: { ...service.headers(current), 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}), signal, redirect: 'error' });
  };
  const pending = async () => { const response = await native(`/api/session/${fixture.session_id}/permission`); if (!response.ok) throw Error('owned fixture unavailable'); return (await response.json()).data; };
  if ((await pending()).length) throw Error('owned fixture already pending');
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'isolated-gateway', alg: 'RS256', use: 'sig' };
  const issuer = createServer((_req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ keys: [jwk] })); }); await listen(issuer);
  const issuerURL = `http://127.0.0.1:${issuer.address().port}`;
  const secret = 'whsec_' + randomBytes(32).toString('base64'), route = '/callback/' + randomBytes(24).toString('hex'); let challenges = 0, deliveries = 0;
  const receiverCounts = { arrived: 0, body_complete: 0, signed: 0, rejected: 0 };
  const receiver = createServer(async (req, res) => {
    try {
      receiverCounts.arrived++;
      if (req.method !== 'POST' || req.url !== route) { res.writeHead(404); return res.end(); }
      const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > 262144) throw Error('limit'); chunks.push(chunk); }
      receiverCounts.body_complete++;
      const body = Buffer.concat(chunks), id = req.headers['webhook-id'], time = req.headers['webhook-timestamp'], signature = req.headers['webhook-signature'];
      if (typeof id !== 'string' || typeof time !== 'string' || Math.abs(Date.now() / 1000 - Number(time)) > 60) throw Error('invalid');
      const expected = 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64')).update(`${id}.${time}.`).update(body).digest('base64');
      if (typeof signature !== 'string' || signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw Error('invalid');
      receiverCounts.signed++;
      const value = JSON.parse(body); res.setHeader('content-type', 'application/json');
      if (value.type === 'verification') { challenges++; return res.end(JSON.stringify({ challenge: value.challenge })); }
      if (value.name !== 'session.needs_input' || value.data?.session_id !== fixture.session_id) throw Error('invalid');
      deliveries++; return res.end('{}');
    } catch { receiverCounts.rejected++; res.writeHead(400); res.end(); }
  }); await listen(receiver);
  let tunnel, gateway, independent, monitorResult, permissionPromise, requestSent = false, unsubscribe;
  const stopMonitor = new AbortController();
  let requestID = 'per_gateway_lifecycle_' + randomBytes(12).toString('hex');
  const result = { auth_evidence: 'synthetic local JWT through normal gateway; NOT ChatGPT', source_evidence: 'real canonical native server', callback_challenges: 0, deliveries: 0, model_inference: false, policy_changed: false, transport_calls: [], receiver_counts: receiverCounts };
  const measuredTransport = label => async (url, request) => {
    const observation = { label, elapsed_ms: 0, dns_ms: null, first_family: null, answer_count: 0, receiver_before: { ...receiverCounts } };
    if (result.transport_calls.length < 10) result.transport_calls.push(observation);
    const resolve = createCallbackResolver(), start = Date.now();
    const transport = createPinnedWebhookTransport({ resolve: async (...args) => { const t = Date.now(); try { const answers = await resolve(...args); observation.first_family = answers[0]?.family ?? null; observation.answer_count = answers.length; return answers; } finally { observation.dns_ms = Date.now() - t; } } });
    try { const response = await transport(url, request); observation.status = response.status; return response; }
    catch (error) { observation.reason = ['timeout', 'network_error', 'non_public_address'].includes(error.data?.reason) ? error.data.reason : 'other'; observation.phase = ['dns', 'connect', 'tls', 'response'].includes(error.data?.phase) ? error.data.phase : null; throw error; }
    finally { observation.elapsed_ms = Date.now() - start; observation.receiver_after = { ...receiverCounts }; }
  };
  try {
    tunnel = spawn(tunnelBinary, ['--no-autoupdate', 'tunnel', '--url', `http://127.0.0.1:${receiver.address().port}`, '--protocol', 'http2'], { stdio: ['ignore', 'ignore', 'pipe'] });
    const origin = await new Promise((accept, reject) => {
      let text = ''; const timer = setTimeout(() => reject(Error('owned tunnel unavailable')), 30000);
      tunnel.once('error', () => { clearTimeout(timer); reject(Error('owned tunnel unavailable')); });
      tunnel.once('exit', () => { clearTimeout(timer); reject(Error('owned tunnel unavailable')); });
      tunnel.stderr.on('data', chunk => { text = (text + chunk.toString()).slice(-16384); for (const match of text.matchAll(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g)) { if (['api', 'www'].includes(new URL(match[0]).hostname.split('.')[0])) continue; clearTimeout(timer); accept(match[0]); break; } });
    });
    result.stage = 'tunnel_ready';
    const transport = measuredTransport('preflight'); let receiverReady = false;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = 'msg_preflight_' + randomBytes(12).toString('hex'), challenge = randomBytes(24).toString('hex'), time = String(Math.floor(Date.now() / 1000));
      const body = JSON.stringify({ type: 'verification', challenge });
      const signature = 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64')).update(`${id}.${time}.${body}`).digest('base64');
      try { const response = await transport(origin + route, { body, headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': time, 'webhook-signature': signature } }); if (response.status === 200 && JSON.parse(response.body).challenge === challenge) { receiverReady = true; break; } } catch {}
      await delay(1000);
    }
    if (!receiverReady) throw Error('owned public receiver unavailable');
    const preflightChallenges = challenges; result.receiver_preflight_verified = true;
    const reserve = createServer(); await listen(reserve); const port = reserve.address().port; await close(reserve);
    const config = { public_origin: 'https://isolated-gateway.invalid', issuer: issuerURL, jwks_uri: issuerURL + '/jwks', audience: 'https://isolated-gateway.invalid/mcp', principal: 'isolated-events-owner', owner: 'isolated-events-owner', bridge_config: join(dir, 'unused-bridge.json'), port,
      events_enabled: true, events_state_path: join(dir, 'events.json'), revocation_file: join(dir, 'revocation.json'), managed_supervisor_file: join(dir, 'capability.json'), managed_server: { server: endpoint.url, service_registration: registration, client_service_module: serviceModule } };
    await fs.writeFile(config.revocation_file, JSON.stringify({ revoked_principals: [], revoked_tokens: [] }), { mode: 0o600 });
    await fs.writeFile(config.managed_supervisor_file, JSON.stringify({ ...config.managed_server, enabled: true, revoked: false, issuer: config.issuer, audience: config.audience, subject: config.principal, client_id: 'https://chatgpt.com/oauth/client.json' }), { mode: 0o600 });
    const serverID = managedServerID(config.managed_server); let monitorReady;
    const ready = new Promise(resolve => { monitorReady = resolve; });
    const observer = createManagedEventSource({ serverId: serverID, authorize: async () => true, isSubscribed: id => id === fixture.session_id,
      openStream: async ({ signal }) => ({ server_id: serverID, response: await native('/api/event', 'GET', undefined, signal) }), reconcile: async () => { monitorReady(); } });
    independent = observer.consume({ signal: stopMonitor.signal, durationMs: 15000 }).then(value => { monitorResult = value; }); await ready;
    const startedAt = Date.now();
    result.stage = 'gateway_construct'; gateway = createGateway(config, { testIssuer: true, eventTransport: measuredTransport('gateway') }); await new Promise(resolve => gateway.listen(port, '127.0.0.1', resolve)); result.stage = 'gateway_listening';
    const token = await new SignJWT({ scope: 'workrelay:tasks', client_id: 'https://chatgpt.com/oauth/client.json' }).setProtectedHeader({ alg: 'RS256', kid: 'isolated-gateway' }).setIssuer(config.issuer).setAudience(config.audience).setSubject(config.principal).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const rpc = async (method, params) => {
      const response = await fetch(`http://127.0.0.1:${port}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream', connection: 'close', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }) });
      const value = await response.json(); if (!response.ok || value.error) { result.rpc_status = response.status; result.rpc_error_code = Number.isInteger(value.error?.code) ? value.error.code : null; result.rpc_error_reason = ['not_authorized', 'invalid_url', 'challenge_failed', 'network_error', 'non_public_address', 'timeout', 'revocation_pending', 'invalid_subscription'].includes(value.error?.data?.reason) ? value.error.data.reason : 'unclassified'; throw Error('normal gateway event request rejected'); } return value.result;
    };
    const destination = { name: 'session.needs_input', arguments: { server_id: serverID, session_id: fixture.session_id }, delivery: { mode: 'webhook', url: origin + route, secret } };
    result.stage = 'native_subscribe'; const accepted = await rpc('events/subscribe', destination); result.stage = 'subscribed';
    unsubscribe = () => rpc('events/unsubscribe', { ...destination, delivery: { mode: 'webhook', url: origin + route } });
    const snapshot = async () => { const state = JSON.parse(await fs.readFile(config.events_state_path, 'utf8')); const sub = state.subscriptions[accepted.id]; return { observations: Object.keys(sub?.observations ?? {}).length, queued: state.queue.filter(item => item.subscriptionId === accepted.id).length, delivered: sub?.delivery?.delivered ?? 0 }; };
    result.after_subscribe = await snapshot(); result.subscribe_elapsed_ms = Date.now() - startedAt;
    if (result.subscribe_elapsed_ms > 3200) throw Error('startup race window unavailable');
    await fs.writeFile(join(dir, 'owned-request.json'), JSON.stringify({ session_id: fixture.session_id, permission_id: requestID, phase: 'sending-once' }), { mode: 0o600, flag: 'wx' });
    requestSent = true;
    permissionPromise = native(`/api/session/${fixture.session_id}/permission`, 'POST', { ...fixture.request.body, id: requestID }).then(async response => { const value = await response.json(); result.permission_effect = ['allow', 'deny', 'ask'].includes(value.data?.effect) ? value.data.effect : 'unknown'; });
    for (let i = 0; i < 15; i++) { if ((await pending()).some(item => item.id === requestID && item.sessionID === fixture.session_id)) { result.native_pending_observed = true; break; } await delay(50); }
    result.during_fast_native_gate = await snapshot();
    if (!result.native_pending_observed || Date.now() - startedAt > 4300) throw Error('fast native gate not available');
    const rejected = await native(`/api/session/${fixture.session_id}/permission/${requestID}/reply`, 'POST', { decision: 'reject' }); if (!rejected.ok) throw Error('owned cleanup failed');
    await permissionPromise; result.native_reject_cleanup = true; result.gate_cleared_elapsed_ms = Date.now() - startedAt;
    await delay(Math.max(0, startedAt + 6800 - Date.now()));
    result.after_first_normal_tick = await snapshot();
    result.startup_deliveries = deliveries;
    result.reproduced_startup_loss = result.after_subscribe.observations === 0 && result.gate_cleared_elapsed_ms < 5000 && result.after_first_normal_tick.observations > 0 && deliveries === 0;
    // Contrast with a distinct, once-only native request AFTER the same normal
    // gateway has acquired its baseline. No restored subscription or replay.
    requestID = 'per_gateway_ready_' + randomBytes(12).toString('hex');
    await fs.writeFile(join(dir, 'owned-ready-request.json'), JSON.stringify({ session_id: fixture.session_id, permission_id: requestID, phase: 'sending-once' }), { mode: 0o600, flag: 'wx' });
    result.stage = 'post_baseline_native_gate';
    permissionPromise = native(`/api/session/${fixture.session_id}/permission`, 'POST', { ...fixture.request.body, id: requestID }).then(async response => { const value = await response.json(); result.ready_permission_effect = ['allow', 'deny', 'ask'].includes(value.data?.effect) ? value.data.effect : 'unknown'; });
    for (let i = 0; i < 100; i++) {
      const state = await snapshot();
      if (state.queued > 0) result.post_baseline_queue_observed = true;
      if (deliveries > 0) { result.post_baseline_delivery = state; break; }
      await delay(50);
    }
    const readyPending = (await pending()).some(item => item.id === requestID && item.sessionID === fixture.session_id);
    result.post_baseline_pending_preserved = readyPending;
    if (readyPending) { const rejected = await native(`/api/session/${fixture.session_id}/permission/${requestID}/reply`, 'POST', { decision: 'reject' }); if (!rejected.ok) throw Error('owned cleanup failed'); }
    await permissionPromise;
    await unsubscribe(); unsubscribe = null;
    stopMonitor.abort(); await independent;
    result.independent_native_source = { asked: monitorResult?.native_kinds?.['permission.asked'] ?? 0, replied: monitorResult?.native_kinds?.['permission.replied'] ?? 0, scoped_wakes: monitorResult?.scoped_wakes ?? 0 };
    result.callback_challenges = challenges - preflightChallenges; result.deliveries = deliveries;
    result.reproduced_startup_loss &&= result.independent_native_source.asked >= 1;
    result.owned_request_cleared = !(await pending()).some(item => item.id === requestID);
    if (!result.reproduced_startup_loss || !result.owned_request_cleared || !result.post_baseline_delivery || !result.post_baseline_pending_preserved) throw Error('normal gateway diagnosis inconclusive');
    return result;
  } catch (error) { result.callback_challenges = challenges; result.deliveries = deliveries; result.failure = ['owned tunnel unavailable', 'normal gateway event request rejected', 'startup race window unavailable', 'fast native gate not available', 'owned cleanup failed', 'normal gateway diagnosis inconclusive'].includes(error.message) ? error.message : 'local_setup_or_authority'; error.safeEvidence = result; throw error; }
  finally {
    let cleanupFailed = false;
    try { if (requestSent) { const items = await pending(); if (items.some(item => item.id === requestID && item.sessionID === fixture.session_id)) { const response = await native(`/api/session/${fixture.session_id}/permission/${requestID}/reply`, 'POST', { decision: 'reject' }); if (!response.ok) cleanupFailed = true; } } } catch { cleanupFailed = true; }
    try { await unsubscribe?.(); } catch { cleanupFailed = true; }
    stopMonitor.abort(); await independent?.catch(() => {}); if (gateway) { await gateway.stopEvents(); await close(gateway); }
    if (tunnel && tunnel.exitCode === null) tunnel.kill('SIGTERM'); await close(receiver); await close(issuer);
    if (cleanupFailed) throw Error('owned cleanup failed');
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [serviceModule, registration, tunnelBinary, privateDirectory, fixtureFile] = process.argv.slice(2);
  try { console.log(JSON.stringify(await probeGatewayStartup({ serviceModule, registration, tunnelBinary, privateDirectory, fixtureFile }))); }
  catch (error) { console.error(JSON.stringify({ result: 'inconclusive', evidence: error.safeEvidence ?? null })); process.exitCode = 1; }
}
