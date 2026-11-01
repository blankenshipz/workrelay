import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, realpath } from 'node:fs/promises';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

test('real transport stdin/client discovery and native HTTP path', async () => {
  // Retain synthetic files outside the candidate, under the owner-home trust
  // chain. A candidate in a sticky temporary directory is not a trusted client
  // registration location; do not weaken the production ancestor checks.
  const receipts = join(homedir(), '.workrelay-test-receipts');
  await mkdir(receipts, { recursive: true, mode: 0o700 });
  const root = await realpath(await mkdtemp(join(receipts, 'plugin-transport-fixture-')));
  const directory = root + '/workspace~*'; await mkdir(directory, { mode: 0o700 });
  const calls = [];
  const server = createServer((req, res) => {
    calls.push(req.url); assert.equal(req.method, 'GET');
    assert.equal(req.headers['x-test-native'], 'fixture');
    const url = new URL(req.url, 'http://fixture');
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(url.pathname === '/api/plugin' ?
      { location: { directory }, data: [{ id: 'fixture', state: { status: 'active' } }] } :
      { data: { id: 'ses_fixture', projectID: 'project', location: { directory } } }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const binding = { enabled: true, revoked: false, issuer: 'https://fixture.test', audience: 'https://fixture.test/mcp',
      subject: 'fixture', client_id: 'https://chatgpt.com/oauth/client.json', server: `http://127.0.0.1:${server.address().port}`,
      service_registration: root + '/service.json', client_service_module: root + '/client.mjs' };
    await writeFile(binding.service_registration, JSON.stringify({ url: binding.server }), { mode: 0o600 });
    await writeFile(binding.client_service_module, `import {readFileSync} from 'node:fs'; export const discover=async ({file})=>({...JSON.parse(readFileSync(file)),auth:{fixture:true}}); export const headers=()=>({'x-test-native':'fixture'});`, { mode: 0o600 });
    await writeFile(root + '/capability.json', JSON.stringify(binding), { mode: 0o600 });
    await writeFile(root + '/config.json', JSON.stringify({ ...binding, managed_server: binding,
      managed_identity: { issuer: binding.issuer, audience: binding.audience, principal: binding.subject },
      managed_supervisor_file: root + '/capability.json' }), { mode: 0o600 });
    const input = { method: 'GET', path: '/__managed/plugin-inventory', body: null, managed: {
      session_id: 'ses_fixture', operation_id: 'fixture', claims: { iss: binding.issuer, aud: binding.audience, sub: binding.subject, client_id: binding.client_id } } };
    const child = spawn(process.execPath, [fileURLToPath(new URL('../src/workrelay/transport.mjs', import.meta.url)), root + '/config.json'], {
      stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, NODE_NO_WARNINGS: '1' } });
    let stdout = '', stderr = '';
    child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
    child.stdin.end(JSON.stringify(input));
    const exit = await new Promise(resolve => child.on('close', resolve));
    assert.equal(exit, 0, 'transport must complete through actual stdin route'); assert.equal(stderr, '');
    const result = JSON.parse(stdout); assert.equal(result.status, 200);
    assert.equal(result.data.activation_readiness, 'unknown'); assert.equal(result.data.items[0].state, 'active');
    assert.doesNotMatch(stdout, /workspace|service.json|x-test-native/);
    assert.equal(calls.length, 3); assert.equal(new URL(calls[1], 'http://fixture').searchParams.get('location[directory]'), directory);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('managed location reads require a durable bound create body', async () => {
  const receipts = join(homedir(), '.workrelay-test-receipts'); await mkdir(receipts, { recursive: true, mode: 0o700 });
  const root = await realpath(await mkdtemp(join(receipts, 'managed-location-fixture-')));
  const directory = root + '/workspace~*'; await mkdir(directory, { mode: 0o700 });
  let locations = 0, posts = 0, nativeProject = 'current';
  const server = createServer(async (req, res) => {
    if (req.url.startsWith('/api/location?')) { locations++; res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ directory, project: { id: nativeProject, directory, canonical: directory } })); }
    if (req.url === '/api/project') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify([{ id: 'stale', canonical: directory }, { id: 'current', canonical: directory }])); }
    if (req.url === '/api/session' && req.method === 'POST') { posts++; let text = ''; for await (const chunk of req) text += chunk; return res.end(JSON.stringify({ data: { ...JSON.parse(text), projectID: nativeProject } })); }
    res.statusCode = 404; res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const binding = { enabled: true, revoked: false, issuer: 'https://fixture.test', audience: 'https://fixture.test/mcp', subject: 'fixture', client_id: 'https://chatgpt.com/oauth/client.json', server: `http://127.0.0.1:${server.address().port}`, service_registration: root + '/service.json', client_service_module: root + '/client.mjs' };
    await writeFile(binding.service_registration, JSON.stringify({ url: binding.server }), { mode: 0o600 });
    await writeFile(binding.client_service_module, `import {readFileSync} from 'node:fs'; export const discover=async ({file})=>({...JSON.parse(readFileSync(file)),auth:{fixture:true}}); export const headers=()=>({});`, { mode: 0o600 });
    await writeFile(root + '/capability.json', JSON.stringify(binding), { mode: 0o600 });
    const config = { ...binding, state_dir: root, model: { providerID: 'openai' }, agent: 'quick-builder', managed_allowed_directories: [directory], managed_server: binding, managed_identity: { issuer: binding.issuer, audience: binding.audience, principal: binding.subject }, managed_supervisor_file: root + '/capability.json' };
    await writeFile(root + '/config.json', JSON.stringify(config), { mode: 0o600 });
    const db = new DatabaseSync(join(root, 'managed-control.sqlite'));
    db.exec('CREATE TABLE managed_operations(binding TEXT,session TEXT,operation TEXT,kind TEXT,digest TEXT,message TEXT,phase TEXT,identity TEXT)');
    const bindingID = createHash('sha256').update(JSON.stringify(binding)).digest('hex');
    const sid = 'ses_location_fixture', operation = 'locationfixture';
    db.prepare('INSERT INTO managed_operations VALUES(?,?,?,?,?,?,?,?)').run(bindingID, sid, operation, 'create', 'args-v2:fixture', 'current', 'reserved', '{}');
    db.close();
    // urllib.urlencode (the Python caller) leaves ~ unescaped and escapes *;
    // the transport compares parsed values, never a JS re-encoding.
    const input = { method: 'GET', path: '/api/location?location%5Bdirectory%5D=' + encodeURIComponent(directory).replaceAll('*', '%2A'), body: null, managed: { session_id: sid, operation_id: operation, claims: { iss: binding.issuer, aud: binding.audience, sub: binding.subject, client_id: binding.client_id } } };
    const invoke = () => new Promise(resolve => {
      const child = spawn(process.execPath, [fileURLToPath(new URL('../src/workrelay/transport.mjs', import.meta.url)), root + '/config.json'], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, NODE_NO_WARNINGS: '1' } });
      let out = ''; child.stdout.on('data', chunk => { out += chunk; }); child.stdin.end(JSON.stringify(input)); child.on('close', code => resolve({ code, out }));
    });
    const denied = await invoke(); assert.equal(denied.code, 2); assert.equal(locations, 0);
    const body = { id: sid, title: 'Fixture', location: { directory }, model: config.model, agent: config.agent, metadata: { workrelayBinding: bindingID, workrelayOperation: operation } };
    const update = new DatabaseSync(join(root, 'managed-control.sqlite')); update.prepare('UPDATE managed_operations SET identity=?').run(JSON.stringify(body)); update.close();
    const allowed = await invoke(); assert.equal(allowed.code, 0); assert.equal(JSON.parse(allowed.out).data.project.id, 'current'); assert.equal(locations, 1);
    const sending = new DatabaseSync(join(root, 'managed-control.sqlite')); sending.prepare("UPDATE managed_operations SET phase='sending'").run(); sending.close();
    input.method = 'POST'; input.path = '/api/session'; input.body = body;
    const posted = await invoke(); assert.equal(posted.code, 0); assert.equal(posts, 1, 'current ID survives tied-root transport POST gate');
    nativeProject = 'stale'; const drifted = await invoke(); assert.equal(drifted.code, 2); assert.equal(posts, 1, 'location drift blocks POST'); nativeProject = 'current';
    input.method = 'GET'; input.path = '/api/location?location%5Bdirectory%5D=' + encodeURIComponent(directory).replaceAll('*', '%2A'); input.body = null;
    const denyPhase = new DatabaseSync(join(root, 'managed-control.sqlite')); denyPhase.prepare("UPDATE managed_operations SET phase='denied'").run(); denyPhase.close();
    const beforePhase = locations; const deniedAfterPhase = await invoke(); assert.equal(deniedAfterPhase.code, 2); assert.equal(locations, beforePhase);
    const reopen = new DatabaseSync(join(root, 'managed-control.sqlite')); reopen.prepare("UPDATE managed_operations SET phase='reserved'").run(); reopen.close();
    for (const bad of [`http://managed.local${input.path}`, `//managed.local${input.path}`]) {
      input.path = bad; const deniedAlias = await invoke(); assert.equal(deniedAlias.code, 2); assert.equal(locations, beforePhase);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});
