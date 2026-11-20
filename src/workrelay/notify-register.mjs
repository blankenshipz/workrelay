#!/usr/bin/env node
// Register an agent's (or a whole MCP client's) own progress-event listener on
// the Workrelay host, so its URL and secrets never pass through a chat transcript.
// With --agent NAME the listener belongs to that agent under the client (use
// this when several agents share one MCP connection); the agent then passes
// `agent: NAME` on workrelay_server_create/message/resume.
//
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json [--client ID] [--agent NAME] \
//     --url-env VAR [--header-name NAME | --header-name-env VAR] [--header-value-env VAR] \
//     [--hmac-secret-env VAR] [--format json|slack|text] [--stall-minutes N] [--test]
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json [--client ID] [--agent NAME] --show | --clear | --test
//   node src/workrelay/notify-register.mjs --config gateway/mcp.json --list
//
// Secret values are read ONLY from the named environment variables and are
// never printed; output shows the URL host, header name and signed flag.
// --client defaults to the gateway's managed OAuth client id. --file PATH writes a
// clients file directly instead of deriving it from --config. The gateway
// reads the file at use time: no restart is needed.
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createClientDefaults, sessionNotifyPaths, testNotifyEvent, sendTestEvent, validAgentName, NOTIFY_FORMATS } from './session_notify.mjs';
import { createPinnedWebhookTransport } from './events.mjs';
import { managedClientID } from './managed_server.mjs';

const USAGE = 'usage: notify-register.mjs (--config MCP_JSON | --file CLIENTS_JSON) [--client ID] [--agent NAME] (--url-env VAR [--header-name NAME|--header-name-env VAR] [--header-value-env VAR] [--hmac-secret-env VAR] [--format json|slack|text] [--stall-minutes N] [--test] | --show | --clear | --test | --list)';
const FLAGS = new Set(['--show', '--clear', '--test', '--list', '--help']);
const VALUES = new Set(['--config', '--file', '--client', '--agent', '--url-env', '--header-name', '--header-name-env', '--header-value-env', '--hmac-secret-env', '--format', '--stall-minutes']);
const SECRET_ARGS = new Set(['--url', '--header-value', '--hmac-secret']);

export function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (SECRET_ARGS.has(arg.split('=')[0])) throw Error(`${arg.split('=')[0]} is not accepted: pass secrets through ${arg.split('=')[0]}-env VAR (arguments are visible in ps and shell history)`);
    if (FLAGS.has(arg)) { options[arg.slice(2)] = true; continue; }
    // Never echo the argument: it may be a mistyped secret.
    if (!VALUES.has(arg)) throw Error(`unknown argument #${i + 1}${arg.startsWith('--') ? '' : ' (not a --flag)'}\n${USAGE}`);
    if (i + 1 >= argv.length) throw Error(`${arg} needs a value`);
    options[arg.slice(2)] = argv[++i];
  }
  return options;
}

// Errors name the flag, never the variable name: an operator may have pasted
// the secret itself where the variable name belongs.
const fromEnv = (env, variable, flag) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(variable)) throw Error(`${flag} must name an environment variable`);
  const value = env[variable];
  if (value === undefined || value === '') throw Error(`the variable named by ${flag} is not set or empty`);
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
  // Default: the one OAuth client the gateway admits (same rule as the gateway).
  if (options.client === undefined && !options.config && !options.list) throw Error('--client is required with --file');
  const clientID = options.client ?? managedClientID(config);
  if (options.agent !== undefined && (!validAgentName(options.agent) || options.list)) throw Error('--agent must be 1-64 of A-Z a-z 0-9 . _ - (and is not used with --list)');
  const agent = options.agent;
  const who = agent !== undefined ? { client_id: clientID, agent } : { client_id: clientID };
  const print = value => out(JSON.stringify(value, null, 1));
  const modes = ['show', 'clear', 'list'].filter(mode => options[mode]);
  const setting = options['url-env'] !== undefined;
  if (modes.length + (setting ? 1 : 0) > 1) throw Error(`choose one of --url-env (set), --show, --clear, --list\n${USAGE}`);
  if (!setting && ['header-name', 'header-name-env', 'header-value-env', 'hmac-secret-env', 'format', 'stall-minutes'].some(key => options[key] !== undefined))
    throw Error('target options need --url-env');

  if (options.list) { print(clients.list()); return 0; }
  if (options.show) { print(clients.get(clientID, agent) ?? { ...who, [agent !== undefined ? 'agent_default' : 'client_default']: null }); return 0; }
  if (options.clear) { print(clients.clear(clientID, { agent })); return 0; }
  if (setting) {
    const target = { url: fromEnv(env, options['url-env'], '--url-env') };
    const headerName = options['header-name'] ?? (options['header-name-env'] !== undefined ? fromEnv(env, options['header-name-env'], '--header-name-env') : undefined);
    const headerValue = options['header-value-env'] !== undefined ? fromEnv(env, options['header-value-env'], '--header-value-env') : undefined;
    if ((headerName === undefined) !== (headerValue === undefined)) throw Error('a header needs both a name and --header-value-env');
    if (headerName !== undefined) Object.assign(target, { header_name: headerName, header_value: headerValue });
    if (options['hmac-secret-env'] !== undefined) target.hmac_secret = fromEnv(env, options['hmac-secret-env'], '--hmac-secret-env');
    if (options.format !== undefined) { if (!NOTIFY_FORMATS.includes(options.format)) throw Error('--format must be json, slack or text'); target.format = options.format; }
    if (options['stall-minutes'] !== undefined) target.stall_minutes = Number(options['stall-minutes']);
    try { print({ registered: clients.set(clientID, target, { by: 'cli', agent }) }); }
    catch (error) { throw Error(`not registered: ${error.reason ?? 'invalid'}`); }
  }
  if (options.test) {
    const resolved = clients.resolve(clientID, agent);
    if (!resolved.target) throw Error(`no usable ${agent !== undefined ? `listener for agent ${agent} of` : 'client default for'} ${clientID}: ${resolved.reason}`);
    const result = await sendTestEvent(resolved.target, testNotifyEvent({ scope: agent !== undefined ? 'agent' : 'client', agent }),
      { transport: transport ?? createPinnedWebhookTransport({ timeoutMs: 10000 }) });
    print({ test: { ...who, ...result } });
    return result.ok ? 0 : 1;
  }
  if (!setting && !modes.length) throw Error(USAGE);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().then(code => { process.exitCode = code; }, error => { process.stderr.write(`notify-register: ${error.message}\n`); process.exitCode = 2; });
}
