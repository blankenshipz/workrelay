// Private in-process credential handoff from the installed @opencode/client.
// JSON body arrives via stdin; credentials and request text never enter argv.
import { readFileSync, statSync, realpathSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { createManagedReader } from './managed_server.mjs';
import { readManagedCapability } from './mcp.mjs';

const rootRoutes = new Set(['/api/plugin', '/api/integration/openai', '/api/provider/openai', '/api/model']);
const sessionPath = /^\/api\/session\/(ses_bridge_[0-9a-f]{32})(?:\/(prompt|message\/(msg_[0-9a-f]{32})|inbox(?:\/(msg_[0-9a-f]{32}))?|interrupt\?resume=false))?$/;
const resultReadPath = /^\/api\/session\/(ses_bridge_[0-9a-f]{32})\/(permission|message\?[^#]+)$/;
const fields = (value, expected) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...expected].sort().join(',');

function boundedMessageQuery(tail) {
  if (!tail.startsWith('message?')) return false;
  const raw = tail.slice('message?'.length);
  // V2 cursors are opaque strings, not assumed to be base64 or session IDs.
  // Reject ambiguous encodings/control characters, duplicate/extra fields and
  // cursor+order. Every page must retain the assistant filter and bounded limit.
  if (/%(?![0-9a-f]{2})/i.test(raw)) return false;
  const query = new URLSearchParams(raw);
  const keys = [...query.keys()];
  const expected = query.has('cursor') ? ['cursor', 'limit', 'type'] : ['limit', 'order', 'type'];
  if (keys.sort().join(',') !== expected.sort().join(',')) return false;
  const limit = query.get('limit');
  if (!/^(?:[1-9]|[1-4][0-9]|50)$/.test(limit ?? '') || query.get('type') !== 'assistant') return false;
  if (!query.has('cursor')) return query.get('order') === 'desc';
  const cursor = query.get('cursor');
  return cursor.length > 0 && cursor.length <= 4096 && !/[\x00-\x1f\x7f\ufffd]/.test(cursor);
}

async function boundedJSON(response) {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 2_000_000) throw new Error('response too large');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const body = Buffer.concat(chunks).toString('utf8');
  return body ? JSON.parse(body) : null;
}

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

function enrollment(config, grantID) {
  if (typeof grantID !== 'string' || !/^grant_[0-9a-f]{32}$/.test(grantID)) return null;
  const code = `import json,sqlite3,sys
db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=3)
r=db.execute('SELECT session_id,owner,workspace,project_id,revoked,owner_snapshot FROM supervision_grants WHERE grant_id=?',(sys.argv[2],)).fetchone()
print(json.dumps(r))`;
  return JSON.parse(execFileSync('/usr/bin/python3', ['-c', code, `${config.state_dir}/bridge.sqlite`, grantID],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 200_000, stdio: ['ignore', 'pipe', 'ignore'] }));
}

function adminAuthenticated(config, token) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 4096) return false;
  const stat = statSync(config.enrollment_admin_token_file);
  if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.size > 4096) return false;
  const expected = Buffer.from(readFileSync(config.enrollment_admin_token_file, 'utf8').trim());
  const supplied = Buffer.from(token);
  return expected.length >= 32 && expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

async function allowEnrollment(input, config, endpoint, headers) {
  if (input.method !== 'GET' || input.body !== null) return false;
  const match = /^\/api\/session\/(ses[A-Za-z0-9_-]{1,160})(?:\/(permission|message\?[^#]+))?$/.exec(input.path);
  if (!match || (match[2] && match[2] !== 'permission' && !boundedMessageQuery(match[2]))) return false;
  const sid = match[1];
  let row = null;
  if (input.local_admin_selection !== undefined || input.local_admin_token !== undefined) {
    if (input.grant_id !== undefined || match[2] || !adminAuthenticated(config, input.local_admin_token)) return false;
    const selection = input.local_admin_selection;
    if (!fields(selection, ['session_id', 'owner', 'workspace']) || selection.session_id !== sid ||
        selection.owner !== config.authorized_owner || selection.workspace !== config.directory) return false;
  } else {
    row = enrollment(config, input.grant_id);
    if (!row || row[0] !== sid || row[1] !== config.authorized_owner || row[2] !== config.directory ||
        !row[3] || row[4] !== 0 || !row[5]) return false;
  }
  const found = await fetch(new URL(`/api/session/${sid}`, endpoint.url), { headers, redirect: 'manual',
    signal: AbortSignal.timeout(5000) });
  if (!found.ok) return false;
  const session = (await boundedJSON(found))?.data;
  if (session?.id !== sid || session?.location?.directory !== config.directory || !session?.projectID) return false;
  if (row) {
    if (session.projectID !== row[3] || !isDeepStrictEqual(JSON.parse(row[5]),
        { metadata: session.metadata ?? null, parentID: session.parentID ?? null })) return false;
    // Recheck persisted revocation after the remote ownership probe.
    if (!isDeepStrictEqual(enrollment(config, input.grant_id), row)) return false;
  }
  return true;
}

async function allow(input, config, endpoint, headers) {
  const path = input.path;
  if (typeof path !== 'string' || path.length > 50_000 || /[\x00-\x1f\x7f\\#]/.test(path) ||
      !['GET', 'POST', 'DELETE'].includes(input.method)) return false;
  if (input.grant_id !== undefined || input.local_admin_selection !== undefined || input.local_admin_token !== undefined)
    return allowEnrollment(input, config, endpoint, headers);
  if (rootRoutes.has(path)) return input.method === 'GET' && input.body === null;
  const resultRead = resultReadPath.exec(path);
  if (resultRead && (input.method !== 'GET' || input.body !== null ||
      (resultRead[2] !== 'permission' && !boundedMessageQuery(resultRead[2])))) return false;
  const match = resultRead ?? sessionPath.exec(path);
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
  const session = (await boundedJSON(found))?.data;
  if (session?.id !== sid || session?.location?.directory !== config.directory ||
      session?.metadata?.agentComputerBridge !== key ||
      session?.metadata?.agentComputerBridgeOwner !== owner) return false;
  if (!tail) return input.method === 'GET' && input.body === null;
  if (resultRead) return true; // GET/body/query already checked; ownership revalidated above.
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

async function managedRequest(input, config, observe) {
  const authority = input.managed;
  if (!fields(authority, ['claims', 'session_id', 'operation_id']) ||
      !/^ses[A-Za-z0-9_-]{1,160}$/.test(authority.session_id ?? '') ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(authority.operation_id ?? '') ||
      config.server !== config.managed_server?.server ||
      config.service_registration !== config.managed_server?.service_registration ||
      config.client_service_module !== config.managed_server?.client_service_module) throw Error('managed handoff denied');
  const reader = createManagedReader({ ...config.managed_identity, managed_server: config.managed_server },
    () => readManagedCapability(config.managed_supervisor_file), {
      internalAuthorize: async (request, binding, endpoint, headers) => {
        const sid = authority.session_id;
        if (request.method === 'GET' && request.body === null) {
          if (rootRoutes.has(request.path) || request.path === '/api/project' || request.path === `/api/session/${sid}` ||
              request.path === `/api/session/${sid}/inbox` || request.path === `/api/session/${sid}/permission` ||
              request.path === `/api/session/${sid}/form`) return true;
        }
        const code = `import json,sqlite3,sys
db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=3)
r=db.execute('SELECT kind,digest,message,phase,identity FROM managed_operations WHERE binding=? AND session=? AND operation=?',sys.argv[2:5]).fetchone()
print(json.dumps(r))`;
        const row = JSON.parse(execFileSync('/usr/bin/python3', ['-c', code, `${config.state_dir}/managed-control.sqlite`, binding, sid, authority.operation_id],
          { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }));
        if (!row) return false;
        if (request.method === 'GET' && request.body === null) {
          if (request.path === `/api/session/${sid}/message/${row[2]}`) return true;
          if ((row[0] === 'question_reply' || row[0] === 'question_cancel') &&
              (request.path === `/api/session/${sid}/form/${row[2]}` || new RegExp(`^/api/session/${sid}/message/msg[A-Za-z0-9_-]{1,160}$`).test(request.path))) return true;
          return false;
        }
        if ((row[0] === 'question_reply' || row[0] === 'question_cancel')) {
          if (row[3] !== 'sending') return false;
          const reply = row[0] === 'question_reply';
          if ((reply ? request.method !== 'POST' || request.path !== `/api/session/${sid}/form/${row[2]}/reply` || !fields(request.body, ['answer']) :
              request.method !== 'DELETE' || request.path !== `/api/session/${sid}/form/${row[2]}` || request.body !== null)) return false;
          const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ?
            Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
          const decision = reply ? request.body.answer : null;
          const found = await fetch(new URL(`/api/session/${sid}`, endpoint.url), { headers, redirect: 'manual', signal: AbortSignal.timeout(5000) });
          if (!found.ok) return false;
          const session = (await boundedJSON(found))?.data;
          const hash = execFileSync('/usr/bin/python3', ['-c', 'import json,sys;from workrelay.managed_control import identity;print(identity(json.load(sys.stdin),sys.argv[1]))', sid],
            { input: JSON.stringify(session), encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
          return hash === row[4] && createHash('sha256').update(row[0] + '\0' + row[2] + '\0' + JSON.stringify(canonical(decision))).digest('hex') === row[1];
        }
        if (request.method !== 'POST' || row[3] !== 'sending') return false;
        if (row[0] === 'create') {
          const body = JSON.parse(row[4]);
          const allowed = config.managed_allowed_directories ?? [config.directory];
          const projectsResponse = await fetch(new URL('/api/project', endpoint.url), { headers, redirect: 'manual', signal: AbortSignal.timeout(5000) });
          if (!projectsResponse.ok) return false;
          const projects = await boundedJSON(projectsResponse);
          if (!Array.isArray(projects) || projects.length > 10000) return false;
          const selected = projects.filter(project => project?.id === row[2]);
          if (selected.length !== 1 || typeof selected[0].canonical !== 'string') return false;
          const root = selected[0].canonical, directory = body.location?.directory;
          if (!isAbsolute(root) || realpathSync(root) !== root || !statSync(root).isDirectory() ||
              typeof directory !== 'string' || !isAbsolute(directory) || realpathSync(directory) !== directory || !statSync(directory).isDirectory()) return false;
          const within = (parent, child) => { const rel = relative(parent, child); return !isAbsolute(rel) && rel !== '..' && !rel.startsWith('../'); };
          if (!within(root, directory)) return false;
          const candidates = projects.filter(project => typeof project?.canonical === 'string' && within(project.canonical, directory));
          candidates.sort((a, b) => b.canonical.length - a.canonical.length);
          if (candidates[0]?.id !== row[2]) return false;
          const rootHash = body.metadata?.workrelayProjectRootHash;
          const scopedNativeRoot = rootHash !== undefined && root !== '/' && directory === root &&
            rootHash === createHash('sha256').update(root).digest('hex');
          const scopedProfile = Array.isArray(allowed) && allowed.includes(directory) &&
            (rootHash === undefined || rootHash === createHash('sha256').update(root).digest('hex'));
          return request.path === '/api/session' && body.id === sid &&
            isDeepStrictEqual(request.body, body) && isDeepStrictEqual(body.model, config.model) &&
            body.agent === (config.agent ?? 'quick-builder') && (scopedNativeRoot || scopedProfile) &&
            fields(body, ['id', 'title', 'location', 'model', 'agent', 'metadata']) &&
            fields(body.location, ['directory']) && fields(body.metadata, rootHash === undefined ? ['workrelayBinding', 'workrelayOperation'] : ['workrelayBinding', 'workrelayOperation', 'workrelayProjectRootHash']) &&
            body.metadata.workrelayBinding === binding && body.metadata.workrelayOperation === authority.operation_id;
        }
        if (row[0] === 'queue' || row[0] === 'steer') {
          if (request.path !== `/api/session/${sid}/prompt` || !fields(request.body, ['id', 'text', 'delivery']) ||
              request.body.id !== row[2] || request.body.delivery !== row[0] || typeof request.body.text !== 'string' ||
              createHash('sha256').update(row[0] + '\0' + request.body.text).digest('hex') !== row[1]) return false;
        } else if (row[0] !== 'interrupt' || request.path !== `/api/session/${sid}/interrupt?resume=false` || request.body !== null) return false;
        const found = await fetch(new URL(`/api/session/${sid}`, endpoint.url), { headers, redirect: 'manual', signal: AbortSignal.timeout(5000) });
        if (!found.ok) return false;
        const session = (await boundedJSON(found))?.data;
        const hash = execFileSync('/usr/bin/python3', ['-c', 'import json,sys;from workrelay.managed_control import identity;print(identity(json.load(sys.stdin),sys.argv[1]))', sid],
          { input: JSON.stringify(session), encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        return hash === row[4];
      },
    });
  if (input.path === '/__managed/plugin-inventory') {
    return reader('plugin_inventory', input, authority.claims);
  }
  if (input.path === '/__managed/attestation-plugin') {
    return reader('attestation_plugin', input, authority.claims);
  }
  if (['/__managed/attestation-provider', '/__managed/attestation-integration', '/__managed/attestation-models'].includes(input.path)) {
    return reader('attestation_metadata', input, authority.claims, observe);
  }
  return reader(['/__managed/authorize', '/__managed/authorize-create-project'].includes(input.path) && input.method === 'GET' && input.body === null ? 'authorize' : 'internal', input, authority.claims, observe);
}

let providerDiagnostic;
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
  if (input.method === 'GET' && ['/api/provider/openai', '/__managed/attestation-provider'].includes(input.path)) providerDiagnostic = { http_status: null };
  if (input.managed !== undefined) {
    const data = await managedRequest(input, config, (stage, action, status) => {
      if (providerDiagnostic && stage === 'native_status' && ['internal', 'attestation_metadata'].includes(action) && Number.isInteger(status) && status >= 100 && status <= 599) providerDiagnostic.http_status = status;
    });
    process.stdout.write(JSON.stringify({ status: data === null ? 404 : 200, data, ...(providerDiagnostic ? { provider_diagnostic: providerDiagnostic } : {}) }));
    process.exit(0);
  }
  const headers = { ...module.headers(endpoint), 'content-type': 'application/json' };
  if (!await allow(input, config, endpoint, headers)) throw new Error('request scope denied');
  const target = new URL(input.path, endpoint.url);
  if (target.origin !== new URL(config.server).origin) throw new Error('off-host request denied');
  const response = await fetch(target, { method: input.method, headers,
  body: input.body === null ? undefined : JSON.stringify(input.body), redirect: 'manual',
  signal: AbortSignal.timeout(15000) });
  if (providerDiagnostic) providerDiagnostic.http_status = response.status;
  if (response.status >= 300 && response.status < 400) throw new Error('redirect denied');
  if (response.status === 404 && input.method === 'GET') {
    process.stdout.write(JSON.stringify({ status: 404, data: null, ...(providerDiagnostic ? { provider_diagnostic: providerDiagnostic } : {}) }));
  } else if (!response.ok) {
    // Upstream errors can include credentials/transcripts. Status is sufficient.
    await response.body?.cancel();
    process.stdout.write(JSON.stringify({ status: response.status, data: null, ...(providerDiagnostic ? { provider_diagnostic: providerDiagnostic } : {}) }));
  } else {
    process.stdout.write(JSON.stringify({ status: response.status, data: await boundedJSON(response), ...(providerDiagnostic ? { provider_diagnostic: providerDiagnostic } : {}) }));
  }
} catch {
  if (providerDiagnostic) process.stdout.write(JSON.stringify({ provider_diagnostic: providerDiagnostic }));
  // Never emit request/response bodies, transport exceptions or auth material.
  process.stderr.write('guarded local service request unavailable\n');
  process.exitCode = 2;
}
