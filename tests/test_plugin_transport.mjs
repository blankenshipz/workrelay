import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, realpath } from 'node:fs/promises';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

test('real transport stdin/client discovery and native HTTP path', async () => {
  // Retain synthetic files outside the candidate, under the owner-home trust
  // chain. A candidate in a sticky temporary directory is not a trusted client
  // registration location; do not weaken the production ancestor checks.
  const receipts = join(homedir(), '.workrelay-test-receipts');
  await mkdir(receipts, { recursive: true, mode: 0o700 });
  const root = await realpath(await mkdtemp(join(receipts, 'plugin-transport-fixture-')));
  const directory = root + '/workspace'; await mkdir(directory, { mode: 0o700 });
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
