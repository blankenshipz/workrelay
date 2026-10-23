import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

test('actual Python client -> release transport -> native fixtures isolates selected-session guard admission', async t => {
  const project = dirname(dirname(fileURLToPath(import.meta.url)));
  const dir = await fs.mkdtemp(join(project, 'tests/.bound-attestation-'));
  await fs.chmod(dir, 0o700); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const locations = { ses_one: join(dir, 'a b&%encoded'), ses_two: join(dir, 'two') };
  for (const path of Object.values(locations)) await fs.mkdir(path);
  const files = { entry: join(dir, 'runtime/plugins/subscription-guard/index.mjs'),
    implementation: join(dir, 'runtime/plugins/subscription-guard.mjs'), financial: join(dir, 'config/guard-validation.mjs') };
  const pins = {};
  for (const [key, path] of Object.entries(files)) {
    await fs.mkdir(dirname(path), { recursive: true }); await fs.writeFile(path, '// fixture');
    pins[key] = createHash('sha256').update('// fixture').digest('hex');
  }
  let mode = 'active', posts = 0, unscoped = 0;
  const selected = [];
  const metadataLocations = [];
  const server = createServer((req, res) => {
    if (req.method !== 'GET') { posts++; res.statusCode = 405; return res.end('{}'); }
    const url = new URL(req.url, 'http://fixture');
    const location = url.searchParams.get('location[directory]');
    if (['/api/provider/openai', '/api/integration/openai', '/api/model'].includes(url.pathname)) {
      if (!location) { unscoped++; res.statusCode = 404; return res.end('PRIVATE_CANARY'); }
      metadataLocations.push([url.pathname, location]);
    }
    let value;
    if (url.pathname.startsWith('/api/session/')) {
      const id = url.pathname.split('/').at(-1);
      value = { data: locations[id] ? { id, projectID: 'project', location: { directory: locations[id] } } : null };
    } else if (url.pathname === '/api/plugin') {
      const location = url.searchParams.get('location[directory]');
      if (!location) { unscoped++; value = { data: [] }; }
      else {
        selected.push(location);
        if (mode === 'denied') { res.statusCode = 403; return res.end('PRIVATE'); }
        const guard = { id: 'subscription.guard', state: { status: mode === 'inactive' ? 'failed' : 'active' }, source: { type: 'local', path: files.entry } };
        value = { location: { directory: mode === 'wrong_location' ? locations.ses_two : location }, data:
          mode === 'missing' ? [] : mode === 'duplicate' ? [guard, guard] : mode === 'malformed' ? [null] : [guard] };
      }
    } else if (url.pathname === '/api/provider/openai') {
      if (mode === 'provider404' || mode === 'provider403') { res.statusCode = mode === 'provider404' ? 404 : 403; return res.end('PRIVATE_CANARY'); }
      if (mode === 'provider_malformed') return res.end('PRIVATE_CANARY');
      const attribution = { directory: mode === 'provider_wrong_location' ? locations.ses_two : location };
      value = mode === 'provider_null' ? null : mode === 'provider_missing' ? {} :
        mode === 'provider_scalar' ? { location: attribution, data: 'PRIVATE_CANARY' } : mode === 'provider_list' ? { location: attribution, data: [] } :
        { location: attribution, data: { id: mode === 'provider_wrong_id' ? 'foreign' : 'openai', package: location === locations.ses_two ? '@opencode/ai/providers/openai/responses' : '@opencode/ai/providers/openai' } };
    }
    else if (url.pathname === '/api/integration/openai') value = { location: { directory: location }, data: { id: 'openai', connections: [{ type: 'credential', method: 'oauth' }] } };
    else if (url.pathname === '/api/model') value = { location: { directory: location }, data: [{ id: location === locations.ses_two ? 'fixture_two' : 'fixture', providerID: 'openai', package: '@opencode/ai/providers/openai' }] };
    else { res.statusCode = 404; value = {}; }
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const registration = join(dir, 'service.json'), module = join(dir, 'service.mjs'), capability = join(dir, 'capability.json');
  await fs.writeFile(registration, '{}', { mode: 0o600 });
  await fs.writeFile(module, `export const discover=async()=>({url:${JSON.stringify(origin)},auth:{}});export const headers=()=>({});`, { mode: 0o600 });
  const client = 'https://chatgpt.com/oauth/client.json';
  const binding = { enabled: true, revoked: false, issuer: 'https://issuer.test', audience: 'https://issuer.test/mcp', subject: 'alice', client_id: client,
    server: origin, service_registration: registration, client_service_module: module };
  const base = { server: origin, service_registration: registration, client_service_module: module, managed_supervisor_file: capability,
    managed_server: { server: origin, service_registration: registration, client_service_module: module },
    managed_identity: { issuer: binding.issuer, audience: binding.audience, principal: binding.subject },
    node_executable: process.execPath, model: { providerID: 'openai', id: 'fixture' }, guard_entry: files.entry, guard_file_hashes: pins };
  const configPath = join(dir, 'bridge.json');
  await fs.writeFile(configPath, JSON.stringify(base), { mode: 0o600 });
  const run = async session => {
    const config = { ...base, model: { ...base.model, id: session === 'ses_two' ? 'fixture_two' : 'fixture' }, _fixture_diagnostic: mode.startsWith('provider'), _private_path: configPath, _supervision_authority: { managed: {
      claims: { iss: binding.issuer, aud: binding.audience, sub: binding.subject, client_id: client }, session_id: session, operation_id: 'fixture-read-only' } } };
    return new Promise((resolve, reject) => {
      const child = spawn(process.env.WORKRELAY_TEST_PYTHON || 'python3', ['-c',
        'import json,sys;from workrelay.attestor import verify,AttestationError;from workrelay.cli import InstalledClient;c=json.load(sys.stdin)\ntry:\n verify(c,InstalledClient(c));print("passed")\nexcept AttestationError as e: print(json.dumps({"check":e.check_id,"diagnostic":getattr(e,"provider_diagnostic",None)}) if c.get("_fixture_diagnostic") else e.check_id)'],
      { cwd: project, env: { ...process.env, PYTHONPATH: join(project, 'src') }, stdio: ['pipe', 'pipe', 'pipe'] });
      let out = '', err = ''; child.stdout.on('data', x => out += x); child.stderr.on('data', x => err += x);
      child.on('error', reject); child.on('exit', code => code === 0 ? resolve(out.trim()) : reject(Error('fixture subprocess exit ' + code + ': ' + err)));
      child.stdin.end(JSON.stringify(config));
    });
  };
  await fs.writeFile(capability, JSON.stringify(binding), { mode: 0o600 });
  assert.equal(await run('ses_one'), 'passed'); assert.equal(await run('ses_two'), 'passed');
  assert.deepEqual(selected, [locations.ses_one, locations.ses_two]);
  assert.deepEqual(metadataLocations, Object.values(locations).flatMap(location => ['/api/provider/openai', '/api/integration/openai', '/api/model', '/api/provider/openai', '/api/integration/openai'].map(path => [path, location])));
  for (mode of ['missing', 'inactive', 'duplicate', 'malformed']) assert.equal(await run('ses_one'), 'GUARD_PLUGIN_STATE');
  for (mode of ['denied', 'wrong_location']) assert.equal(await run('ses_one'), 'PLUGIN_READ_UNAVAILABLE');
  assert.equal(await run('ses_missing'), 'PLUGIN_READ_UNAVAILABLE');
  for (const [scenario, status, check, shape] of [
    ['provider404',404,'PROVIDER_RESPONSE','null'], ['provider_null',200,'PROVIDER_RESPONSE','null'],
    ['provider_missing',200,'PROVIDER_RESPONSE','object'], ['provider_scalar',200,'PROVIDER_RESPONSE','object'],
    ['provider_list',200,'PROVIDER_RESPONSE','object'], ['provider_malformed',200,'PROVIDER_READ_UNAVAILABLE','unknown'],
    ['provider403',403,'PROVIDER_READ_UNAVAILABLE','unknown'], ['provider_wrong_location',200,'PROVIDER_READ_UNAVAILABLE','unknown']]) {
    mode = scenario;
    const raw = await run('ses_one');
    assert.ok(!raw.includes('PRIVATE_CANARY'));
    const observed = JSON.parse(raw);
    assert.equal(observed.check, check);
    assert.equal(observed.diagnostic.http_status, status);
    assert.equal(observed.diagnostic.envelope_shape, shape);
    if (scenario === 'provider_list') assert.equal(observed.diagnostic.data_shape, 'list');
  }
  mode = 'provider_wrong_id';
  assert.equal(JSON.parse(await run('ses_one')).check, 'PROVIDER_OVERLAY');
  mode = 'active';
  await fs.writeFile(capability, JSON.stringify({ ...binding, revoked: true }));
  assert.equal(await run('ses_one'), 'PLUGIN_READ_UNAVAILABLE');
  assert.equal(unscoped, 0, 'never query or fall back to server default');
  assert.equal(posts, 0, 'no control/model/native POST');
});
