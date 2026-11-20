#!/usr/bin/env node
// Register an MCP client's own progress-event listener on the Workrelay host,
// so its URL and secrets never pass through a chat transcript.
//
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json [--client ID] \
//     --url-env VAR [--header-name NAME | --header-name-env VAR] [--header-value-env VAR] \
//     [--hmac-secret-env VAR] [--format json|slack|text] [--stall-minutes N] [--test]
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json [--client ID] --show | --clear | --test
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json --list
//
// Secret values are read ONLY from the named environment variables and are
// never printed; output shows the URL host, header name and signed flag.
// --client defaults to the gateway's managed client id. --file PATH writes a
// clients file directly instead of deriving it from --config. The gateway
// reads the file at use time: no restart is needed.
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createClientDefaults, sessionNotifyPaths, testNotifyEvent, sendTestEvent, NOTIFY_FORMATS } from './session_notify.mjs';
import { createPinnedWebhookTransport } from './events.mjs';

const USAGE = 'usage: notify-register.mjs (--config MCP_JSON | --file CLIENTS_JSON) [--client ID] (--url-env VAR [--header-name NAME|--header-name-env VAR] [--header-value-env VAR] [--hmac-secret-env VAR] [--format json|slack|text] [--stall-minutes N] [--test] | --show | --clear | --test | --list)';
const FLAGS = new Set(['--show', '--clear', '--test', '--list', '--help']);
const VALUES = new Set(['--config', '--file', '--client', '--url-env', '--header-name', '--header-name-env', '--header-value-env', '--hmac-secret-env', '--format', '--stall-minutes']);
const SECRET_ARGS = new Set(['--url', '--header-value', '--hmac-secret']);

export function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (SECRET_ARGS.has(arg.split('=')[0])) throw Error(`${arg.split('=')[0]} is not accepted: pass secrets through ${arg.split('=')[0]}-env VAR (arguments are visible in ps and shell history)`);
    if (FLAGS.has(arg)) { options[arg.slice(2)] = true; continue; }
    if (!VALUES.has(arg)) throw Error(`unknown argument ${JSON.stringify(arg.slice(0, 40))}\n${USAGE}`);
    if (i + 1 >= argv.length) throw Error(`${arg} needs a value`);
    options[arg.slice(2)] = argv[++i];
  }
  return options;
}

const fromEnv = (env, variable, label) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(variable)) throw Error(`invalid environment variable name for ${label}`);
  const value = env[variable];
  if (value === undefined || value === '') throw Error(`${variable} (${label}) is not set or empty`);
  return value;
};

export async function main(argv = process.argv.slice(2), { env = process.env, out = text => process.stdout.write(text + '\n'), transport } = {}) {
  const options = parseArgs(argv);
  if (options.help) { out(USAGE); return 0; }
  let config = {};
  if (options.config) config = JSON.parse(readFileSync(options.config, 'utf8'));
  const file = options.file ?? (options.config ? sessionNotifyPaths(config).clientsPath : null);
  if (!file) throw Error(`--config or --file is required\n${USAGE}`);
  if (options.config && config.session_notify?.enabled !== true) out('warning: session_notify is not enabled in this gateway config; no events are sent until it is.');
  const clients = createClientDefaults({ file });
  const clientID = options.client ?? config.managed_client_id ?? 'workrelay-managed';
  const print = value => out(JSON.stringify(value, null, 1));
  const modes = ['show', 'clear', 'list'].filter(mode => options[mode]);
  const setting = options['url-env'] !== undefined;
  if (modes.length + (setting ? 1 : 0) > 1) throw Error(`choose one of --url-env (set), --show, --clear, --list\n${USAGE}`);
  if (!setting && ['header-name', 'header-name-env', 'header-value-env', 'hmac-secret-env', 'format', 'stall-minutes'].some(key => options[key] !== undefined))
    throw Error('target options need --url-env');

  if (options.list) { print(clients.list()); return 0; }
  if (options.show) { print(clients.get(clientID) ?? { client_id: clientID, client_default: null }); return 0; }
  if (options.clear) { print(clients.clear(clientID)); return 0; }
  if (setting) {
    const target = { url: fromEnv(env, options['url-env'], 'url') };
    const headerName = options['header-name'] ?? (options['header-name-env'] !== undefined ? fromEnv(env, options['header-name-env'], 'header name') : undefined);
    const headerValue = options['header-value-env'] !== undefined ? fromEnv(env, options['header-value-env'], 'header value') : undefined;
    if ((headerName === undefined) !== (headerValue === undefined)) throw Error('a header needs both a name and --header-value-env');
    if (headerName !== undefined) Object.assign(target, { header_name: headerName, header_value: headerValue });
    if (options['hmac-secret-env'] !== undefined) target.hmac_secret = fromEnv(env, options['hmac-secret-env'], 'hmac secret');
    if (options.format !== undefined) { if (!NOTIFY_FORMATS.includes(options.format)) throw Error('--format must be json, slack or text'); target.format = options.format; }
    if (options['stall-minutes'] !== undefined) target.stall_minutes = Number(options['stall-minutes']);
    try { print({ registered: clients.set(clientID, target, { by: 'cli' }) }); }
    catch (error) { throw Error(`not registered: ${error.reason ?? 'invalid'}`); }
  }
  if (options.test) {
    const resolved = clients.resolve(clientID);
    if (!resolved.target) throw Error(`no usable client default for ${clientID}: ${resolved.reason}`);
    const result = await sendTestEvent(resolved.target, testNotifyEvent({ scope: 'client' }),
      { transport: transport ?? createPinnedWebhookTransport({ timeoutMs: 10000 }) });
    print({ test: { client_id: clientID, ...result } });
    return result.ok ? 0 : 1;
  }
  if (!setting && !modes.length) throw Error(USAGE);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; }, error => { process.stderr.write(`notify-register: ${error.message}\n`); process.exitCode = 2; });
}
