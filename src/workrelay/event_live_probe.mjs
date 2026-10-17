// Explicit operator-run, read-only source + isolated real HTTPS receiver probe.
// Not a test-suite import side effect. Never logs credentials, callback URLs or payloads.
import { createServer } from 'node:http';
import { spawn, execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { promises as fs } from 'node:fs';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { lookup, resolve4, resolve6 } from 'node:dns/promises';
import { createEventsService } from './events.mjs';
import { createManagedEventSource } from './managed_event_source.mjs';
import { createManagedReader } from './managed_server.mjs';
import { readManagedCapability } from './mcp.mjs';
const execFileAsync = promisify(execFile);

export async function runLiveEventsProbe({ serviceModule, registration, tunnelBinary, privateDirectory, sessionId, bridgeConfig, sourceDurationMs = 10000, permissionFixtureOnly = false, permissionFixtureKind = 'external_directory', nativeFixture, completionOnly = false } = {}) {
  if (![serviceModule, registration, tunnelBinary, privateDirectory].every(p => typeof p === 'string' && p.startsWith('/')) || !/^ses[A-Za-z0-9_-]{1,160}$/.test(sessionId)) throw Error('explicit probe references required');
  const service = await import(pathToFileURL(serviceModule).href);
  const endpoint = await service.discover({ file: registration }); // discover only; NEVER ensure/start
  const url = new URL(endpoint?.url ?? 'about:blank');
  if (!endpoint?.auth || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw Error('canonical managed service unavailable');
  const server = 'srv_' + createHash('sha256').update(JSON.stringify([endpoint.url, registration, serviceModule])).digest('hex');
  if (nativeFixture && (nativeFixture.session_id !== sessionId || nativeFixture.pending_triggered !== false || nativeFixture.request?.method !== 'POST' || nativeFixture.request.path !== `/api/session/${sessionId}/permission` || nativeFixture.request.body?.id !== nativeFixture.permission_request_id || !/^per[A-Za-z0-9_-]{1,160}$/.test(nativeFixture.permission_request_id) || nativeFixture.cleanup?.method !== 'POST' || nativeFixture.cleanup.path !== `/api/session/${sessionId}/permission/${nativeFixture.permission_request_id}/reply` || nativeFixture.cleanup.body?.decision !== 'reject' || Object.keys(nativeFixture.cleanup.body).length !== 1)) throw Error('invalid owned native fixture');
  const pythonEnv = { PATH: `${resolve(process.execPath, '..')}:/usr/local/bin:/usr/bin:/bin`, HOME: process.env.HOME, USER: process.env.USER, PYTHONPATH: resolve(fileURLToPath(new URL('..', import.meta.url))) };
  let normalReader, claims, context;
  if (bridgeConfig) {
    context = JSON.parse(execFileSync('/usr/bin/python3', ['-c', 'import json,sys;from workrelay.cli import load_config;c=load_config(sys.argv[1])[0];print(json.dumps({k:c[k] for k in ("managed_identity","managed_server","managed_supervisor_file","model")}))', bridgeConfig], { env: pythonEnv, encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] }));
    const expected = { ...context.managed_identity, managed_server: context.managed_server };
    if (context.managed_server.server !== endpoint.url || context.managed_server.service_registration !== registration || context.managed_server.client_service_module !== serviceModule) throw Error('service binding changed');
    claims = { iss: expected.issuer, aud: expected.audience, sub: expected.principal, client_id: 'https://chatgpt.com/oauth/client.json' };
    normalReader = createManagedReader(expected, () => readManagedCapability(context.managed_supervisor_file));
  }
  const current = async () => { const found = await service.discover({ file: registration }); if (!found?.auth || found.url !== endpoint.url) throw Error('service binding changed'); if (normalReader) await normalReader('authorize', {}, claims); return found; };
  const request = async (path, signal, method = 'GET', body) => { const found = await current(); return fetch(new URL(path, found.url), { method, headers: { ...service.headers(found), 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal }); };
  const secret = 'whsec_' + randomBytes(32).toString('base64'), route = '/callback/' + randomBytes(24).toString('hex');
  const seen = new Set(), kinds = {}, kindTimes = {}; let challenges = 0, applications = 0, duplicates = 0, destroyed = false, receiverRequests = 0, callbackFailure = null, tunnelConnected = false, callbackDiagnostic = null, dnsAttempts = 0, dnsReady = false, excludedProviderURLs = 0, dnsComparison = null, deliveryFaultInjected = false, triggeredPermission, adapterPending = false, adapterCleared = false;
  const receiver = createServer(async (req, res) => {
    try {
      if (req.url !== route || req.method !== 'POST') { res.writeHead(404); return res.end(); }
      receiverRequests++;
      const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > 262144) throw Error('limit'); chunks.push(chunk); }
      const body = Buffer.concat(chunks), id = req.headers['webhook-id'], signedAt = req.headers['webhook-timestamp'];
      if (typeof id !== 'string' || typeof signedAt !== 'string' || !/^\d+$/.test(signedAt) || Math.abs(Date.now() / 1000 - Number(signedAt)) > 60) throw Error('invalid');
      const signature = 'v1,' + createHmac('sha256', Buffer.from(secret.slice(6), 'base64')).update(`${id}.${signedAt}.`).update(body).digest('base64');
      const supplied = req.headers['webhook-signature'];
      if (typeof supplied !== 'string' || supplied.length !== signature.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(supplied))) throw Error('invalid');
      const value = JSON.parse(body); res.setHeader('content-type', 'application/json');
      if (value.type === 'verification') {
        if (seen.has(id) || typeof value.challenge !== 'string' || value.challenge.length > 256) throw Error('replayed_challenge');
        seen.add(id); challenges++; return res.end(JSON.stringify({ challenge: value.challenge }));
      }
      if (value.eventId !== id || value.data?.server_id !== server || value.data?.session_id !== sessionId || !['session.progress', 'session.needs_input', 'session.completed', 'session.failed'].includes(value.name)) throw Error('invalid');
      if (seen.has(id)) duplicates++; else { seen.add(id); applications++; kinds[value.name] = (kinds[value.name] ?? 0) + 1; kindTimes[value.name] = Number.isFinite(Date.parse(value.timestamp)) ? value.timestamp : null; }
      if (!deliveryFaultInjected) { deliveryFaultInjected = true; res.statusCode = 503; return res.end('{}'); } // owned receiver: real transient ACK failure, dedupe on retry
      return res.end('{}');
    } catch { res.writeHead(400); res.end(); }
  });
  await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
  let tunnel, events, sourceResult, sourceFailure, sourceTask, transitionResult; const subscriptions = [];
  const sourceStop = new AbortController();
  try {
    tunnel = spawn(tunnelBinary, ['--no-autoupdate', 'tunnel', '--url', `http://127.0.0.1:${receiver.address().port}`, '--protocol', 'http2'], { stdio: ['ignore', 'ignore', 'pipe'] });
    const origin = await new Promise((accept, reject) => {
      let text = ''; const timer = setTimeout(() => reject(Error('isolated HTTPS tunnel unavailable')), 30000);
      tunnel.once('error', () => { clearTimeout(timer); reject(Error('isolated HTTPS tunnel unavailable')); });
      tunnel.once('exit', () => { clearTimeout(timer); reject(Error('isolated HTTPS tunnel unavailable')); });
      tunnel.stderr.on('data', data => {
        text = (text + data.toString()).slice(-16384); if (/Registered tunnel connection/.test(text)) tunnelConnected = true;
        for (const match of text.matchAll(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g)) {
          if (['api', 'www'].includes(new URL(match[0]).hostname.split('.')[0])) { excludedProviderURLs++; continue; }
          clearTimeout(timer); accept(match[0]); break;
        }
      });
    });
    // A freshly allocated public hostname may not yet be visible to OS DNS. This
    // is readiness only; production transport resolves/revalidates/pins anew.
    for (let attempt = 0; attempt < 15; attempt++) {
      dnsAttempts++;
      try { if ((await lookup(new URL(origin).hostname, { all: true, verbatim: true })).length) { dnsReady = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    if (!dnsReady) {
      const hostname = new URL(origin).hostname;
      const compare = async fn => { try { return { answers: (await fn()).length, error: null }; } catch (error) { return { answers: 0, error: ['ENOTFOUND', 'ENODATA', 'ETIMEOUT', 'EAI_AGAIN', 'ESERVFAIL', 'ECONNREFUSED'].includes(error.code) ? error.code : 'OTHER_DNS_ERROR' }; } };
      dnsComparison = { configured_ipv4: await compare(() => resolve4(hostname)), configured_ipv6: await compare(() => resolve6(hostname)), public_control: await compare(() => lookup('example.com', { all: true })) };
    }
    const filter = { server_id: server, session_id: sessionId };
    events = createEventsService({ statePath: join(privateDirectory, 'probe-events.json'), principal: 'isolated-live-probe',
      authorize: async (principal, _task, _name, scope) => { await current(); return !destroyed && principal === 'isolated-live-probe' && scope?.server_id === server && scope.session_id === sessionId; },
      observeManaged: async () => {
        if (normalReader) {
          const view = await normalReader('events', { ...filter, limit: 10 }, claims);
          if (triggeredPermission) { if (view.items.some(item => item.decisions.includes(triggeredPermission))) adapterPending = true; else if (adapterPending) adapterCleared = true; }
          return view;
        }
        const response = await request(`/api/session/${sessionId}`, AbortSignal.timeout(10000)); if (!response.ok) throw Error('isolated session unavailable'); const value = (await response.json()).data;
        if (value?.id !== sessionId) throw Error('session mismatch');
        const permissions = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000)); if (!permissions.ok) throw Error('permission state unavailable'); const pending = (await permissions.json()).data;
        if (!Array.isArray(pending) || pending.length > 1000 || pending.some(p => p.sessionID !== sessionId || !/^per[A-Za-z0-9_-]{1,160}$/.test(p.id))) throw Error('permission ownership mismatch');
        const state = ['succeeded', 'failed', 'interrupted'].includes(value.outcome) ? value.outcome : pending.length ? 'needs_input' : value.time?.idle ? 'idle' : 'unknown';
        return { server_id: server, items: [{ session_id: sessionId, state, decisions: pending.map(p => p.id) }], next_cursor: null };
      } });
    for (const name of ['session.progress', 'session.needs_input', 'session.completed', 'session.failed']) {
      let accepted;
      for (let attempt = 0; attempt < 3; attempt++) { try { accepted = await events.subscribe({ name, arguments: filter, delivery: { mode: 'webhook', url: origin + route, secret } }); break; } catch (error) { callbackFailure = ['invalid_url', 'non_public_address', 'network_error', 'timeout', 'redirect', 'response_too_large', 'challenge_failed'].includes(error.data?.reason) ? error.data.reason : 'local_store_or_authority'; callbackDiagnostic = error.data?.phase && error.data?.native_code ? { phase: error.data.phase, native_code: error.data.native_code } : null; if (attempt === 2) throw Error('public callback verification unavailable'); await new Promise(r => setTimeout(r, 1500)); } }
      subscriptions.push(accepted.id);
    }
    let sourceReady; const ready = new Promise(resolve => { sourceReady = resolve; });
    const native = createManagedEventSource({ serverId: server, authorize: async () => { await current(); return !destroyed; }, isSubscribed: id => id === sessionId,
      openStream: async ({ signal }) => ({ server_id: server, response: await request('/api/event', signal) }),
      onNativeEvent: event => events.noteNativeEvent(event),
      reconcile: async () => { await events.pollManaged(); await events.deliverDue(); sourceReady(); } });
    sourceTask = native.consume({ signal: sourceStop.signal, durationMs: bridgeConfig ? 45000 : sourceDurationMs }).then(value => { sourceResult = value; }, error => { sourceFailure = error; sourceResult = error.sourceEvidence ?? null; });
    if (bridgeConfig) {
      await Promise.race([ready, sourceTask.then(() => { throw Error('native source not ready'); })]);
      const until = async check => { for (let n = 0; n < 60; n++) { if (await check()) return true; await new Promise(resolve => setTimeout(resolve, 250)); } return false; };
      const snapshot = async () => { const response = await request(`/api/session/${sessionId}`, AbortSignal.timeout(10000)); if (!response.ok) throw Error('session mismatch'); return (await response.json()).data; };
      const protectedIdentity = value => execFileSync('/usr/bin/python3', ['-c', 'import json,sys;from workrelay.managed_control import identity;s=json.load(sys.stdin);print(identity(s,s["id"]))'], { env: pythonEnv, input: JSON.stringify(value), encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
      const before = await snapshot(), fingerprint = protectedIdentity(before), baseline = kinds['session.completed'] ?? 0;
      if (before.id !== sessionId || !permissionFixtureOnly && before.outcome !== 'succeeded') throw Error('isolated session not at a safe returned boundary');
      if (nativeFixture) {
        const sameModel = execFileSync('/usr/bin/python3', ['-c', 'import json,sys;v=json.load(sys.stdin);print("yes" if v[0]==v[1] else "no")'], { env: pythonEnv, input: JSON.stringify([before.model, context.model]), encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        if (sameModel !== 'yes') throw Error('owned fixture model identity changed');
        const existing = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000));
        if (!existing.ok || (await existing.json()).data.length !== 0) throw Error('owned fixture is not at an empty permission boundary');
      }
      const operation = nativeFixture?.operation_id ?? 'events-r15-' + randomBytes(8).toString('hex');
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(operation)) throw Error('invalid owned native fixture');
      const operationStartedAt = Date.now();
      await fs.writeFile(join(privateDirectory, operation + '.json'), JSON.stringify({ session_id: sessionId, operation_id: operation, phase: 'planned' }), { mode: 0o600, flag: 'wx' });
      let guarded = { exit: 0, error: false, phase: 'not_requested' }, returned = false;
      if (!permissionFixtureOnly) {
        const instruction = 'For this isolated Workrelay Events verification, use no tools and modify no files. Write eight brief numbered sentences explaining why runtime idle is not proof of task completion. Finish with EVENT_SOURCE_RETURNED.';
        const handoff = { action: 'resume', session_id: sessionId, operation_id: operation, claims, text: instruction };
        const guardedChild = execFileAsync('/usr/bin/python3', ['-c', 'import json,subprocess,sys;from workrelay.cli import load_config;c=load_config(sys.argv[1])[0];p=subprocess.run([sys.executable,"-m","workrelay.cli","--config",sys.argv[1],"managed-control","--owner",c["authorized_owner"]],input=sys.stdin.read(),text=True,capture_output=True,timeout=35);v=json.loads(p.stdout);print(json.dumps({"exit":p.returncode,"phase":v.get("phase"),"error":bool(v.get("error"))}))', bridgeConfig], { env: pythonEnv, encoding: 'utf8', timeout: 40000, maxBuffer: 262144 });
        guardedChild.child.stdin.end(JSON.stringify(handoff)); guarded = JSON.parse((await guardedChild).stdout);
        returned = guarded.exit === 0 && !guarded.error && await until(async () => (await snapshot()).outcome === 'succeeded' && (kinds['session.completed'] ?? 0) > baseline);
      }
      transitionResult = { session_id: sessionId, operation_id: operation, continuation_attempted: !permissionFixtureOnly, guarded_phase: ['accepted', 'queued', 'delivered', 'running', 'interrupted', 'not_requested'].includes(guarded.phase) ? guarded.phase : 'classified_other', continuation_accepted: !permissionFixtureOnly && guarded.exit === 0 && !guarded.error, native_completion_after_continuation: returned, completion_baseline: baseline, permission_fixture: 'not_started' };
      transitionResult.completion_current_generation = returned && Date.parse(kindTimes['session.completed']) >= operationStartedAt;
      if (!completionOnly && (returned || permissionFixtureOnly)) {
        const permission = nativeFixture?.permission_request_id ?? 'per_workrelay_events_' + randomBytes(8).toString('hex'); let settled = false, fixtureEffect = null;
        await fs.writeFile(join(privateDirectory, operation + '.permission.json'), JSON.stringify({ session_id: sessionId, permission_id: permission, purpose: 'owned native Events fixture; reject only this request for cleanup' }), { mode: 0o600, flag: 'wx' });
        const fixtureStartedAt = Date.now(); transitionResult.fixture_started_at = new Date(fixtureStartedAt).toISOString();
        transitionResult.fixture_action = nativeFixture?.request.body.action ?? (permissionFixtureKind === 'read' ? 'read' : 'external_directory');
        const body = nativeFixture?.request.body ?? { id: permission, action: transitionResult.fixture_action, resources: [permissionFixtureKind === 'read' ? join(privateDirectory, 'owned-events-fixture.env') : privateDirectory], save: [], metadata: { purpose: 'isolated native Events observer fixture; no directory access or file read is executed' } };
        triggeredPermission = permission; transitionResult.request_send_count = 1;
        const creating = request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(25000), 'POST', body).then(async response => { settled = true; const value = await response.json(); fixtureEffect = ['allow', 'deny', 'ask'].includes(value.data?.effect) ? value.data.effect : 'unknown'; }).catch(() => { settled = true; });
        try { transitionResult.native_needs_input = await until(async () => {
          const pending = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000));
          if ((await pending.json()).data.some(item => item.id === permission && item.sessionID === sessionId)) transitionResult.native_pending_observed = true;
          await events.deliverDue(); const view = await events.subscriptions({ filter });
          transitionResult.needs_input_acknowledged = transitionResult.native_pending_observed === true && adapterPending && (kinds['session.needs_input'] ?? 0) > 0 && view.subscriptions.some(sub => sub.name === 'session.needs_input' && sub.delivered > 0);
          return transitionResult.needs_input_acknowledged || settled && fixtureEffect !== 'ask';
        }); }
        finally {
          const pendingResponse = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000)); const pending = (await pendingResponse.json()).data;
          if (transitionResult.needs_input_acknowledged && pending.some(p => p.id === permission && p.sessionID === sessionId)) {
            await events.unsubscribeById({ id: subscriptions[1], filter });
            const stillPending = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000));
            transitionResult.native_pending_survived_unsubscribe = (await stillPending.json()).data.some(item => item.id === permission && item.sessionID === sessionId);
          }
          if (pending.some(p => p.id === permission && p.sessionID === sessionId)) { const denied = await request(`/api/session/${sessionId}/permission/${permission}/reply`, AbortSignal.timeout(10000), 'POST', nativeFixture?.cleanup.body ?? { decision: 'reject', message: 'Owned Events fixture cleanup; no permission granted.' }); if (!denied.ok) throw Error('owned permission fixture cleanup failed'); transitionResult.fixture_rejected_for_cleanup = true; }
          await creating;
        }
        transitionResult.native_needs_input = (kinds['session.needs_input'] ?? 0) > 0;
        transitionResult.needs_input_current_generation = Date.parse(kindTimes['session.needs_input']) >= fixtureStartedAt - 1000;
        transitionResult.permission_fixture = 'actual native API fixture, not a model-generated permission'; transitionResult.fixture_effect_after_cleanup = fixtureEffect;
        transitionResult.owned_request_cleared = await until(async () => { const response = await request(`/api/session/${sessionId}/permission`, AbortSignal.timeout(10000)); return !(await response.json()).data.some(p => p.id === permission); });
        transitionResult.normal_adapter_pending_observed = adapterPending;
        if (adapterPending) await until(async () => adapterCleared);
        transitionResult.normal_adapter_clear_observed = adapterCleared;
      }
      transitionResult.protected_identity_unchanged = protectedIdentity(await snapshot()) === fingerprint;
      const final = await snapshot(); transitionResult.final_outcome = ['succeeded', 'failed', 'interrupted'].includes(final.outcome) ? final.outcome : 'unknown';
      sourceStop.abort();
    }
    await sourceTask; if (sourceFailure) throw sourceFailure;
    await events.pollManaged(); await events.deliverDue();
    if (deliveryFaultInjected) { await new Promise(resolve => setTimeout(resolve, 1100)); await events.deliverDue(); }
    const renewed = await events.subscribe({ name: 'session.progress', arguments: filter, delivery: { mode: 'webhook', url: origin + route, secret }, ttlMs: 60000 });
    if (renewed.id !== subscriptions[0]) throw Error('subscription renewal identity mismatch');
    const status = await events.subscriptions({ filter });
    for (const id of subscriptions) await events.unsubscribeById({ id, filter });
    if ((await events.subscriptions({ filter })).subscriptions.length !== 0) throw Error('subscription cleanup failed');
    return { source: sourceResult, event_kinds: kinds, event_times: kindTimes, transitions: transitionResult ?? null, callback_verified: challenges, application_deliveries: applications, duplicate_receipts: duplicates, transient_response_injected: deliveryFaultInjected, renewed_same_id: renewed.id === subscriptions[0],
      acknowledged: status.subscriptions.reduce((sum, item) => sum + item.delivered, 0) + (transitionResult?.native_pending_survived_unsubscribe ? 1 : 0), subscriptions_stopped: subscriptions.length, inference_started: permissionFixtureOnly ? false : bridgeConfig ? transitionResult?.native_completion_after_continuation ? true : null : false, source_mutations: Boolean(bridgeConfig), receiver: 'isolated real HTTPS Standard Webhooks receiver; NOT ChatGPT', chatgpt_verified: false };
  } catch (error) {
    sourceStop.abort(); await sourceTask;
    error.probeEvidence = { source: sourceResult ?? error.sourceEvidence ?? null, transitions: transitionResult ?? null, event_kinds: kinds, callback_verified: challenges, callback_failure: callbackFailure, callback_diagnostic: callbackDiagnostic, dns_attempts: dnsAttempts, dns_ready: dnsReady, dns_comparison: dnsComparison, excluded_provider_urls: excludedProviderURLs, receiver_requests: receiverRequests, tunnel_connected: tunnelConnected, application_deliveries: applications, duplicate_receipts: duplicates, source_mutations: bridgeConfig ? 'possible authorized isolated session only' : false, inference_started: bridgeConfig ? null : false, chatgpt_verified: false };
    throw error;
  } finally {
    sourceStop.abort(); destroyed = true; if (events) await events.revoke().catch(() => {});
    if (tunnel && tunnel.exitCode === null) tunnel.kill('SIGTERM');
    await new Promise(resolve => { receiver.close(resolve); receiver.closeAllConnections(); });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [serviceModule, registration, tunnelBinary, privateDirectory, sessionId, bridgeConfig, mode, fixtureFile] = process.argv.slice(2);
  try { const nativeFixture = mode === 'fixture-handoff' ? JSON.parse(await fs.readFile(fixtureFile, 'utf8')) : undefined; console.log(JSON.stringify(await runLiveEventsProbe({ serviceModule, registration, tunnelBinary, privateDirectory, sessionId, bridgeConfig, permissionFixtureOnly: ['fixture-only', 'fixture-read-env', 'fixture-handoff'].includes(mode), permissionFixtureKind: mode === 'fixture-read-env' ? 'read' : 'external_directory', nativeFixture, completionOnly: mode === 'completion-only' }))); }
  catch (error) {
    const safe = new Set(['explicit probe references required', 'canonical managed service unavailable', 'service binding changed', 'isolated HTTPS tunnel unavailable', 'public callback verification unavailable', 'isolated session unavailable', 'permission state unavailable', 'permission ownership mismatch', 'session mismatch', 'subscription cleanup failed']);
    const reasons = new Set(['missing_bound_source', 'source_authority_revoked', 'invalid_source_bounds', 'source_aborted', 'invalid_native_stream', 'source_frame_too_large', 'source_backpressure', 'invalid_native_event', 'native_stream_failed']);
    console.error(JSON.stringify({ result: 'failed', reason: safe.has(error.message) ? error.message : reasons.has(error.data?.reason) ? error.data.reason : 'live boundary unavailable (unclassified safe error)', evidence: error.probeEvidence ?? null })); process.exitCode = 1;
  }
}
