import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { privateTmpdir as tmpdir } from './support/private_tmp.mjs';
import { main, parseArgs } from '../src/workrelay/notify-register.mjs';
import { createClientDefaults, createSessionNotifier } from '../src/workrelay/session_notify.mjs';

const HOOK = 'https://hooks.grok.example.com/routines/cli/trigger';
const SIG = 'whsec_' + Buffer.from('cli-secret-0123456789abcdefgh').toString('base64');

async function privateDir(t) {
  const dir = await fs.mkdtemp(join(tmpdir(), 'workrelay-notify-cli-')); await fs.chmod(dir, 0o700);
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}
const run = async (argv, env = {}, transport) => { const lines = []; const code = await main(argv, { env, out: line => lines.push(line), transport }); return { code, text: lines.join('\n') }; };

test('notify-register CLI: secrets only from env, never printed; set/show/test/list/clear', async t => {
  const dir = await privateDir(t);
  const file = join(dir, 'notify-clients.json');
  for (const bad of [['--url', HOOK], ['--header-value=x'], ['--hmac-secret', SIG]]) assert.throws(() => parseArgs(['--file', file, ...bad]), /not accepted/);
  await assert.rejects(run(['--file', file, '--client', 'agent-a', '--url-env', 'WR_URL']), /WR_URL \(url\) is not set/);
  await assert.rejects(run(['--file', file, '--client', 'agent-a', '--url-env', 'WR_URL', '--header-name', 'X-S'], { WR_URL: HOOK }), /needs both/);
  await assert.rejects(run(['--file', file, '--client', 'agent-a', '--url-env', 'WR_URL'], { WR_URL: 'https://10.0.0.1/x' }), /not registered: invalid_url/);

  const env = { WR_URL: HOOK, WR_HDR: 'X-Routine-Secret', WR_VAL: 'cli-header-secret', WR_SIG: SIG };
  const sent = [];
  const transport = async (url, { body, headers }) => { sent.push({ url, headers, body: JSON.parse(body) }); return { status: 200, body: '' }; };
  const set = await run(['--file', file, '--client', 'agent-a', '--url-env', 'WR_URL', '--header-name-env', 'WR_HDR', '--header-value-env', 'WR_VAL',
    '--hmac-secret-env', 'WR_SIG', '--format', 'json', '--stall-minutes', '15', '--test'], env, transport);
  assert.equal(set.code, 0);
  assert.doesNotMatch(set.text, /cli-header-secret|whsec_|routines\/cli/);
  assert.match(set.text, /hooks\.grok\.example\.com/); assert.match(set.text, /"updated_by": "cli"/);
  assert.equal(sent.length, 1); assert.equal(sent[0].body.type, 'workrelay.test'); assert.equal(sent[0].headers['X-Routine-Secret'], 'cli-header-secret');
  assert.ok(sent[0].headers['webhook-signature']);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);

  const shown = await run(['--file', file, '--client', 'agent-a', '--show']);
  assert.doesNotMatch(shown.text, /cli-header-secret|whsec_|routines\/cli/); assert.match(shown.text, /"stall_minutes": 15/);
  assert.match((await run(['--file', file, '--list'])).text, /agent-a/);

  // The gateway notifier picks it up without a restart.
  const notifier = createSessionNotifier({ clients: createClientDefaults({ file }), watch: async () => null, transport });
  const attached = await notifier.attachDefault('ses_cli000000000000000001', { client_id: 'agent-a' });
  assert.equal(attached.source, 'client_default'); assert.equal(attached.configured, true);

  // A failing receiver makes --test exit non-zero.
  const failing = await run(['--file', file, '--client', 'agent-a', '--test'], {}, async () => ({ status: 500, body: '' }));
  assert.equal(failing.code, 1); assert.match(failing.text, /"ok": false/);
  assert.match((await run(['--file', file, '--client', 'agent-a', '--clear'])).text, /"cleared": true/);
  await assert.rejects(run(['--file', file, '--client', 'agent-a', '--test']), /no usable client default/);
});
