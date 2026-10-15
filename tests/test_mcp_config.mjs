import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { readPrivateConfig } from '../src/workrelay/mcp.mjs';

// Use protected project-parent ancestry, outside the public candidate. System
// temp directories can have writable ancestors that production rightly rejects.
const fixtureParent = fileURLToPath(new URL('../../', import.meta.url));

test('config path requires protected ancestry and an owned regular 0600 inode', async t => {
  const root = await fs.mkdtemp(join(fixtureParent, '.workrelay-config-path-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const parent = join(root, 'private');
  await fs.mkdir(parent, { mode: 0o700 });
  const file = join(parent, 'config.json');
  const fixture = JSON.stringify({ public_origin: 'https://workrelay.example.test',
    issuer: 'https://issuer.example.test', jwks_uri: 'https://issuer.example.test/jwks',
    audience: 'https://workrelay.example.test/mcp', principal: 'person1',
    owner: 'person1', bridge_config: '/unused-fixture', port: 29450 });
  await fs.writeFile(file, fixture, { mode: 0o600 });
  assert.equal(readPrivateConfig(file).principal, 'person1');
  await fs.chmod(root, 0o777);
  assert.throws(() => readPrivateConfig(file), /private MCP config permissions denied/,
    'writable ancestor rejected even when the immediate parent is private');
  await fs.chmod(root, 0o700);
  await fs.chmod(parent, 0o777);
  assert.throws(() => readPrivateConfig(file), /private MCP config permissions denied/);
  await fs.chmod(parent, 0o700);
  await fs.chmod(file, 0o644);
  assert.throws(() => readPrivateConfig(file), /private MCP config permissions denied/);
  await fs.chmod(file, 0o600);
  const original = join(root, 'original');
  await fs.rename(parent, original);
  await fs.symlink(original, parent);
  assert.throws(() => readPrivateConfig(file), /private MCP config permissions denied/);
  await fs.unlink(parent);
  await fs.rename(original, parent);
  const safe = join(parent, 'safe.json');
  await fs.rename(file, safe);
  await fs.symlink(safe, file);
  assert.throws(() => readPrivateConfig(file), /private MCP config permissions denied/);
  await fs.unlink(file);
  await fs.rename(safe, file);
  assert.equal(readPrivateConfig(file).principal, 'person1');
});

test('two-process pathname swap cannot promote a symlink as private MCP config', async t => {
  const root = await fs.mkdtemp(join(fixtureParent, '.workrelay-config-swap-'));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const file = join(root, 'config.json');
  const good = join(root, 'good.json');
  const target = join(root, 'other.json');
  const config = { public_origin: 'https://workrelay.example.test',
    issuer: 'https://issuer.example.test', jwks_uri: 'https://issuer.example.test/jwks',
    audience: 'https://workrelay.example.test/mcp', principal: 'person1',
    owner: 'person1', bridge_config: '/unused-fixture', port: 29450 };
  await fs.writeFile(good, JSON.stringify(config), { mode: 0o600 });
  await fs.writeFile(target, JSON.stringify({ ...config, principal: 'other' }), { mode: 0o600 });
  await fs.copyFile(good, file);
  assert.equal(readPrivateConfig(file).principal, 'person1', 'safe fixture accepted before pathname race');
  const writer = `import { promises as fs } from 'node:fs';
    const [file,good,target] = process.argv.slice(1);
    for (let i=0; i<150; i++) {
      await fs.rm(file, {force:true}); await fs.symlink(target,file);
      await fs.rm(file); await fs.copyFile(good,file);
    }`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', writer, file, good, target],
    { stdio: 'ignore' });
  let succeeded = 0, denied = 0;
  while (child.exitCode === null && child.signalCode === null) {
    try { assert.equal(readPrivateConfig(file).principal, 'person1'); succeeded++; }
    catch (error) { assert.match(error.message, /private MCP config permissions denied/); denied++; }
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.equal(child.exitCode, 0);
  assert.ok(succeeded + denied > 10);
});
