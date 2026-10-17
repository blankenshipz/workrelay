// Opt-in finite diagnostics. Never persist arbitrary names, arguments or bodies.
import { openSync, closeSync, readFileSync, writeFileSync, lstatSync, fstatSync, linkSync, unlinkSync, fsyncSync, constants } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { privateDirectory } from './issuer_interactions.mjs';

const known = new Set([
  ...['discover', 'profile', 'start', 'status', 'result', 'enrolled_result', 'respond', 'cancel'].map(x => `workrelay_${x}`),
  ...['discover', 'read', 'projects', 'agents', 'capabilities', 'creation_target', 'create', 'operation_status', 'message', 'steer', 'resume', 'waits', 'interrupt'].map(x => `workrelay_server_${x}`),
  ...['capabilities', 'subscriptions', 'subscription_status', 'unsubscribe'].map(x => `workrelay_event_${x}`),
]);
const bounded = value => Number.isInteger(value) && value >= 0 && value <= 1000 ? value : null;
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
        const incoming = flags(body.params.arguments);
        return { read(parsed, output) { try { const shape = readShape({}, parsed, output); shape.incoming = incoming; publish(selected, shape); } catch { /* ignored */ } } };
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
