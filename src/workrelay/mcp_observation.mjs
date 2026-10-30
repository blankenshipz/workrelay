// Opt-in finite diagnostics. Never persist arbitrary names, arguments or bodies.
import { openSync, closeSync, readFileSync, writeFileSync, lstatSync, fstatSync, linkSync, unlinkSync, fsyncSync, constants } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { privateDirectory } from './issuer_interactions.mjs';

const known = new Set([
  ...['discover', 'profile', 'start', 'status', 'result', 'enrolled_result', 'respond', 'cancel'].map(x => `workrelay_${x}`),
  ...['discover', 'read', 'projects', 'agents', 'capabilities', 'creation_target', 'create', 'operation_status', 'message', 'steer', 'resume', 'waits', 'question_reply', 'question_cancel', 'reconcile', 'interrupt'].map(x => `workrelay_server_${x}`),
  ...['capabilities', 'subscriptions', 'subscription_status', 'unsubscribe'].map(x => `workrelay_event_${x}`),
]);
const bounded = value => Number.isInteger(value) && value >= 0 && value <= 1000 ? value : null;
const artifact = createHash('sha256');
for (const file of ['mcp.mjs', 'managed_server.mjs', 'mcp_observation.mjs']) artifact.update(readFileSync(new URL(file, import.meta.url)));
const artifactRevision = artifact.digest('hex');
const statusCode = value => Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
const errorType = error => {
  try {
    const name = error?.name;
    return ['Error', 'TypeError', 'SyntaxError', 'RangeError', 'AbortError', 'TimeoutError'].includes(name) ? name : 'other';
  }
  catch { return 'other'; }
};

// This accepts no arbitrary fields from the request, exception or response.
export function createReadBoundary(incoming, publish) {
  const shape = { layer: 'read_rpc_boundary', method: 'tools/call', tool: 'workrelay_server_read',
    artifact_revision: artifactRevision, incoming: flags(incoming),
    session_present: Object.hasOwn(incoming ?? {}, 'session_id'), cursor_supplied: Object.hasOwn(incoming ?? {}, 'cursor'),
    native_stage: null, native_action: null, native_status: null, tool_stage: 'not_entered', sdk_stage: 'sdk_fetch', error_type: null };
  const emit = () => { try { publish({ ...shape }); } catch { /* diagnostic only */ } };
  return {
    native(stage, action, status) {
      if (!['binding', 'service_discovery', 'native_fetch', 'native_status', 'native_body', 'native_json', 'revalidate', 'projection'].includes(stage) || !['read', 'messages'].includes(action)) return;
      shape.native_stage = stage; shape.native_action = action;
      if (stage === 'binding') shape.native_status = null;
      if (stage === 'native_status') shape.native_status = statusCode(status);
      shape.tool_stage = 'managed_reader';
    },
    stage(stage) {
      if (stage === 'tool_serialization') shape.tool_stage = stage;
      if (['sdk_response', 'relay'].includes(stage)) shape.sdk_stage = stage;
    },
    read(parsed, output) {
      const safe = readShape({}, parsed, output);
      for (const key of ['parsed', 'context_present', 'item_count', 'cursor_present', 'omission_present']) shape[key] = safe[key];
    },
    toolError(error) { shape.error_type = errorType(error); shape.tool_stage = 'tool_failed'; },
    failed(error) { shape.error_type = errorType(error); shape.delivery = 'sdk_or_relay_threw'; emit(); },
    async response(response) {
      let reader, timer;
      shape.http_status = statusCode(response.status); shape.delivery = 'sdk_response_unobserved';
      try {
        const type = response.headers.get('content-type') ?? '';
        if (!/application\/json|text\/event-stream/.test(type)) return;
        reader = response.clone().body.getReader();
        const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(Error('expired')), 1500); });
        let size = 0; const chunks = [];
        while (true) { const part = await Promise.race([reader.read(), deadline]); if (part.done) break;
          size += part.value.length; if (size > 262144) return; chunks.push(part.value); }
        const text = Buffer.concat(chunks).toString('utf8');
        const values = type.includes('application/json') ? [JSON.parse(text)] : text.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => JSON.parse(line.slice(5)));
        for (const value of values) {
          if (value?.jsonrpc !== '2.0' || (!value.error && !value.result)) continue;
          shape.delivery = value.error ? 'rpc_error' : value.result.isError === true ? 'tool_error' : 'rpc_result';
          shape.rpc_code = [-32700, -32600, -32601, -32602, -32603, -32000].includes(value.error?.code) ? value.error.code : null;
          break;
        }
      } catch { /* Observation failure must not change the client response. */ }
      finally { clearTimeout(timer); if (reader) void reader.cancel().catch(() => {}); emit(); }
    },
  };
}
function flags(input) {
  return { flag_present: Object.hasOwn(input ?? {}, 'include_messages'),
    flag_value: typeof input?.include_messages === 'boolean' ? input.include_messages : null,
    limit: Number.isInteger(input?.limit) && input.limit >= 1 && input.limit <= 20 ? input.limit : null };
}
export function catalogShape(result) {
  if (!Array.isArray(result?.tools) || result.tools.length > 1000) return null;
  return { layer: 'sdk_response_before_delivery', tool_count: result.tools.length,
    known_tools: [...new Set(result.tools.map(tool => tool?.name).filter(name => known.has(name)))].sort(),
    unknown_count: result.tools.filter(tool => !known.has(tool?.name)).length,
    read_schema_include_messages: result.tools.some(tool => tool?.name === 'workrelay_server_read' && tool.inputSchema?.properties?.include_messages?.type === 'boolean') };
}
export function readShape(incoming, parsed, output) {
  return { layer: 'validated_tool_callback', tool: 'workrelay_server_read', incoming: flags(incoming), parsed: flags(parsed),
    context_present: !!output?.context, item_count: Array.isArray(output?.context?.items) ? bounded(output.context.items.length) : null,
    cursor_present: typeof output?.context?.next_cursor === 'string', omission_present: typeof output?.context?.omission === 'string' };
}

export function createMcpObservation(directory, { now = Date.now } = {}) {
  const armPath = join(directory, 'mcp-observation.arm');
  function arm() {
    let fd;
    try {
      privateDirectory(directory);
      fd = openSync(armPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const info = fstatSync(fd), path = lstatSync(armPath);
      if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o600 || info.nlink !== 1 || info.size > 256 || info.ino !== path.ino || info.dev !== path.dev) return;
      const data = JSON.parse(readFileSync(fd, 'utf8')), instant = now();
      if (Object.keys(data).sort().join(',') !== 'attemptId,expiresAt,issuedAt,target' || !['mcp-catalog', 'mcp-read'].includes(data.target) ||
          !/^[a-f0-9]{32}$/.test(data.attemptId) || !Number.isSafeInteger(data.issuedAt) || data.issuedAt < 0 || data.issuedAt > instant ||
          !Number.isSafeInteger(data.expiresAt) || data.expiresAt <= instant || data.expiresAt - data.issuedAt > 1800000) return;
      return data;
    } catch { /* disabled, expired or unsafe */ } finally { if (fd !== undefined) closeSync(fd); }
  }
  function publish(expected, shape) {
    let fd, temporary;
    try {
      if (!shape || JSON.stringify(arm()) !== JSON.stringify(expected)) return;
      const receipt = join(directory, 'mcp-observation.receipt.json');
      try { lstatSync(receipt); return; } catch (error) { if (error.code !== 'ENOENT') return; }
      linkSync(armPath, join(directory, 'mcp-observation.used')); unlinkSync(armPath);
      temporary = join(directory, `mcp-observation.${randomBytes(16).toString('hex')}.tmp`);
      fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(fd, JSON.stringify({ attemptId: expected.attemptId, observedAt: now(), target: expected.target, ...shape }));
      fsyncSync(fd); closeSync(fd); fd = undefined; linkSync(temporary, receipt);
      fd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW); fsyncSync(fd);
    } catch { /* Never affect normal calls. */ } finally {
      if (fd !== undefined) try { closeSync(fd); } catch { /* ignored */ }
      if (temporary) try { unlinkSync(temporary); } catch { /* ignored */ }
    }
  }
  return {
    begin(body) {
      const selected = arm();
      if (!selected) return {};
      if (selected.target === 'mcp-read' && body?.method === 'tools/call' && body.params?.name === 'workrelay_server_read') {
        const boundary = createReadBoundary(body.params.arguments, shape => publish(selected, shape));
        return { boundary, response: boundary.response,
          read: boundary.read };
      }
      if (selected.target !== 'mcp-catalog' || body?.method !== 'tools/list') return {};
      return { async response(response) {
        let reader, timer;
        try {
          if (response.status !== 200) return;
          const type = response.headers.get('content-type') ?? '';
          if (!/application\/json|text\/event-stream/.test(type)) return;
          reader = response.clone().body.getReader();
          const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(Error('expired')), 1500); });
          let size = 0; const chunks = [];
          while (true) { const part = await Promise.race([reader.read(), deadline]); if (part.done) break;
            size += part.value.length; if (size > 262144) return; chunks.push(part.value); }
          const text = Buffer.concat(chunks).toString('utf8');
          const values = type.includes('application/json') ? [JSON.parse(text)] : text.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => JSON.parse(line.slice(5)));
          for (const value of values) { const shape = catalogShape(value?.result); if (shape) { publish(selected, shape); break; } }
        } catch { /* Unsupported/oversized response is unobserved, never a failure of MCP. */ }
        finally { clearTimeout(timer); if (reader) void reader.cancel().catch(() => {}); }
      } };
    },
  };
}
