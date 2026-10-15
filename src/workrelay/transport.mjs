// Private in-process credential handoff from the installed @opencode/client.
// JSON body arrives via stdin; credentials and request text never enter argv.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const rootRoutes = new Set(['/api/plugin', '/api/integration/openai', '/api/provider/openai', '/api/model']);
const sessionPath = /^\/api\/session\/(ses_bridge_[0-9a-f]{32})(?:\/(prompt|message\/(msg_[0-9a-f]{32})|inbox(?:\/(msg_[0-9a-f]{32}))?|interrupt\?resume=false))?$/;
const fields = (value, expected) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...expected].sort().join(',');

function ledger(config, sid) {
  const code = `import json,sqlite3,sys
db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=3)
r=db.execute('SELECT task_key,session_id,prompt_id,workspace,phase,owner,request_hash FROM tasks WHERE session_id=?',(sys.argv[2],)).fetchone()
f=db.execute('SELECT prompt_id,request_hash FROM feedback WHERE task_key=?',(r[0],)).fetchall() if r else []
print(json.dumps({'task':r,'feedback':f}))`;
  const result = execFileSync('/usr/bin/python3', ['-c', code, `${config.state_dir}/bridge.sqlite`, sid],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 200_000, stdio: ['ignore', 'pipe', 'ignore'] });
  return JSON.parse(result);
}

async function allow(input, config, endpoint, headers) {
  const path = input.path;
  if (typeof path !== 'string' || !['GET', 'POST', 'DELETE'].includes(input.method)) return false;
  if (rootRoutes.has(path)) return input.method === 'GET' && input.body === null;
  const match = sessionPath.exec(path);
  if (path !== '/api/session' && !match) return false;
  const sid = path === '/api/session' ? input.body?.id : match[1];
  if (!/^ses_bridge_[0-9a-f]{32}$/.test(sid ?? '')) return false;
  const { task: row, feedback } = ledger(config, sid);
  if (!row || row[1] !== sid || row[3] !== config.directory || row[5] !== config.authorized_owner ||
      !/^msg_[0-9a-f]{32}$/.test(row[2])) return false;
  const [key, , mid, , phase, owner, digest] = row;
  if (path === '/api/session') {
    const body = input.body;
    return input.method === 'POST' && phase === 'reserved' &&
      fields(body, ['id', 'title', 'location', 'model', 'agent', 'metadata']) &&
      fields(body.location, ['directory']) && fields(body.model, Object.keys(config.model)) &&
      fields(body.metadata, ['agentComputerBridge', 'agentComputerBridgeOwner']) &&
      body.id === sid && body.title === `Workrelay: ${key}` &&
      body?.location?.directory === config.directory && body?.agent === (config.agent ?? 'quick-builder') &&
      JSON.stringify(body?.model) === JSON.stringify(config.model) &&
      body?.metadata?.agentComputerBridge === key && body?.metadata?.agentComputerBridgeOwner === owner;
  }
  const tail = match[2];
  const found = await fetch(new URL(`/api/session/${sid}`, endpoint.url), { headers, redirect: 'manual',
    signal: AbortSignal.timeout(5000) });
  // Exact missing-session GET is required for safe deterministic creation recovery.
  if (found.status === 404) return input.method === 'GET' && !tail && input.body === null;
  if (!found.ok) return false;
  const session = (await found.json())?.data;
  if (session?.id !== sid || session?.location?.directory !== config.directory ||
      session?.metadata?.agentComputerBridge !== key ||
      session?.metadata?.agentComputerBridgeOwner !== owner) return false;
  if (!tail) return input.method === 'GET' && input.body === null;
  if (tail === 'inbox') return input.method === 'GET' && input.body === null;
  if (tail.startsWith('message/')) return input.method === 'GET' && input.body === null &&
    (match[3] === mid || feedback.some(([id]) => id === match[3]));
  if (tail.startsWith('inbox/')) return input.method === 'DELETE' && input.body === null &&
    match[4] === mid && ['queued', 'submitting', 'interrupt_pending'].includes(phase);
  if (tail === 'interrupt?resume=false') return input.method === 'POST' && input.body === null &&
    ['running', 'queued', 'submitting', 'interrupt_pending'].includes(phase);
  if (tail === 'prompt') {
    if (input.method !== 'POST' || !fields(input.body, ['id', 'text']) ||
        !/^msg_[0-9a-f]{32}$/.test(input.body.id) || typeof input.body.text !== 'string' ||
        !input.body.text.trim() || input.body.text.length > 16000) return false;
    const hash = value => createHash('sha256').update(value).digest('hex');
    return (phase === 'submitting' && input.body.id === mid && hash(`${owner}\0${input.body.text}`) === digest) ||
      (phase === 'running' && feedback.some(([id, textHash]) => id === input.body.id &&
        hash(input.body.text) === textHash));
  }
  return false;
}

try {
  const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  const module = await import(pathToFileURL(config.client_service_module).href);
  const endpoint = await module.discover({ file: config.service_registration });
  if (!endpoint || endpoint.url !== config.server || !endpoint.auth ||
      new URL(endpoint.url).hostname !== '127.0.0.1') throw new Error('service unavailable');
  const input = JSON.parse(await new Promise((resolve, reject) => {
    let text = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { text += chunk; if (text.length > 100_000) reject(new Error('request too large')); });
    process.stdin.on('end', () => resolve(text));
    process.stdin.on('error', reject);
  }));
  const headers = { ...module.headers(endpoint), 'content-type': 'application/json' };
  if (!await allow(input, config, endpoint, headers)) throw new Error('request scope denied');
  const target = new URL(input.path, endpoint.url);
  if (target.origin !== new URL(config.server).origin) throw new Error('off-host request denied');
  const response = await fetch(target, { method: input.method, headers,
  body: input.body === null ? undefined : JSON.stringify(input.body), redirect: 'manual',
  signal: AbortSignal.timeout(15000) });
  if (response.status >= 300 && response.status < 400) throw new Error('redirect denied');
  if (response.status === 404 && input.method === 'GET') {
    process.stdout.write(JSON.stringify({ status: 404, data: null }));
  } else {
    const body = await response.text();
    if (body.length > 2_000_000) throw new Error('response too large');
    process.stdout.write(JSON.stringify({ status: response.status, data: body ? JSON.parse(body) : null }));
  }
} catch {
  // Never emit request/response bodies, transport exceptions or auth material.
  process.stderr.write('guarded local service request unavailable\n');
  process.exitCode = 2;
}
