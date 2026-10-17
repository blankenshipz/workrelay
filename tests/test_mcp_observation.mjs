import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMcpObservation, catalogShape, readShape } from '../src/workrelay/mcp_observation.mjs';

test('finite observer shapes exclude hostile names, text, IDs and values', () => {
  const output = catalogShape({ tools: [{ name: 'PRIVATE_SECRET' }, { name: 'workrelay_server_read', inputSchema: { properties: { include_messages: { type: 'boolean' } } } }] });
  assert.equal(output.unknown_count, 1); assert.deepEqual(output.known_tools, ['workrelay_server_read']);
  assert.equal(output.read_schema_include_messages, true); assert.doesNotMatch(JSON.stringify(output), /PRIVATE/);
  const read = readShape({ include_messages: 'PRIVATE', session_id: 'PRIVATE', limit: 99999 }, {}, { context: { items: [{ text: 'PRIVATE' }], next_cursor: 'PRIVATE' } });
  assert.deepEqual(read.incoming, { flag_present: true, flag_value: null, limit: null });
  assert.deepEqual(read.parsed, { flag_present: false, flag_value: null, limit: null });
  assert.doesNotMatch(JSON.stringify(read), /PRIVATE/);
});

test('actual Response observation is bounded, one-shot, private and expiring', async t => {
  const dir = await fs.mkdtemp(join(dirname(fileURLToPath(import.meta.url)), '.workrelay-head-observation-'));
  await fs.chmod(dir, 0o700); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const arm = join(dir, 'mcp-observation.arm'), receipt = join(dir, 'mcp-observation.receipt.json');
  const data = { target: 'mcp-catalog', attemptId: 'a'.repeat(32), issuedAt: 100, expiresAt: 1000 };
  const observer = createMcpObservation(dir, { now: () => 200 });
  const body = { method: 'tools/list' };
  assert.deepEqual(observer.begin(body), {});
  for (const invalid of [{ ...data, expiresAt: 200 }, { ...data, issuedAt: 201 }, { ...data, expiresAt: 1800101 }, { ...data, extra: 'PRIVATE' }]) {
    await fs.writeFile(arm, JSON.stringify(invalid), { mode: 0o600 }); assert.deepEqual(observer.begin(body), {});
  }
  await fs.writeFile(arm, JSON.stringify(data), { mode: 0o600 });
  const response = () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 'PRIVATE', result: { tools: [{ name: 'workrelay_server_read', inputSchema: { properties: { include_messages: { type: 'boolean' } } } }, { name: 'PRIVATE' }] } }), { headers: { 'content-type': 'application/json' } });
  const first = observer.begin(body), second = observer.begin(body);
  const original = response();
  await Promise.all([first.response(original), second.response(response())]);
  assert.equal((await original.json()).id, 'PRIVATE', 'original SDK response remains unchanged/readable');
  const recorded = await fs.readFile(receipt, 'utf8'); assert.doesNotMatch(recorded, /PRIVATE/);
  assert.equal(JSON.parse(recorded).tool_count, 2); assert.equal((await fs.stat(receipt)).mode & 0o777, 0o600);
  await fs.writeFile(arm, JSON.stringify(data), { mode: 0o600 });
  await observer.begin(body).response(response()); assert.equal(await fs.readFile(receipt, 'utf8'), recorded);
  await fs.chmod(dir, 0o755); assert.deepEqual(observer.begin(body), {}, 'unsafe recorder never changes normal serving');
});
